# API Reference

LLM Portal exposes two sets of APIs:

1. **Portal API** — user management, authentication, admin operations
2. **Inference API** — OpenAI-compatible chat completions (proxied to backend)

All portal API endpoints require authentication (session cookie) unless noted.

## Authentication

### Session cookie

After login, the server sets an HTTP-only session cookie (default name: `llmportal`).

```bash
# Login
curl -c cookies.txt -X POST http://localhost:8081/portal/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "your-password"}'

# Use session for subsequent requests
curl -b cookies.txt http://localhost:8081/portal/api/key
```

### CSRF token

All POST requests require the `X-CSRF-Token` header, obtainable from any authenticated page (it's embedded in the JavaScript as `const CSRF = "..."`).

### API key (Bearer token)

For inference API calls:

```bash
curl http://localhost:8080/v1/chat/completions \
  -H "Authorization: Bearer aisk-username-abc123..." \
  -H "Content-Type: application/json" \
  -d '{"model": "default", "messages": [{"role": "user", "content": "Hello"}]}'
```

---

## Portal API

### Authentication endpoints

#### `POST /portal/api/login`

Sign in.

**Request:**
```json
{
  "username": "admin",
  "password": "your-password"
}
```

**Response:** `200 OK` with session cookie, or `401` with error.

```json
{"error": "invalid credentials"}
```

#### `POST /portal/api/signup`

Self-register (only when `portal.open_signup = true`).

**Request:**
```json
{
  "username": "newuser",
  "password": "secure-password"
}
```

**Response:** `200 OK` with job ID for async key provisioning, or `409` if signup is closed.

```json
{"ok": true, "job": "job_abc123"}
```

#### `POST /portal/api/logout`

End the current session.

**Response:** `200 OK`, clears cookie.

---

### User endpoints

#### `GET /portal/api/key`

Get the current user's API key.

**Response:**
```json
{
  "key": "aisk-username-abc123...",
  "masked": "aisk-username-abc1…"
}
```

#### `POST /portal/api/key/rotate`

Rotate the current user's API key. The old key is immediately invalidated.

**Response:**
```json
{"ok": true, "job": "job_def456"}
```

Poll the job for completion:
```json
{"state": "done", "result": {"key": "aisk-username-newkey..."}}
```

#### `GET /portal/api/activity`

Get the current user's recent API activity.

**Response:**
```json
{
  "lines": [
    {
      "ts": "2026-10-19T10:30:00",
      "req": "POST /v1/chat/completions",
      "type": "api",
      "status": "200",
      "dur": "145ms",
      "ip": "192.168.1.100"
    }
  ]
}
```

#### `POST /portal/api/account/password`

Change own password.

**Request:**
```json
{"password": "new-secure-password"}
```

#### `POST /portal/api/account/delete`

Delete own account (revokes key, removes user).

---

### OpenCode integration

#### `GET /portal/api/opencode-config`

Get OpenCode configuration JSON for the current user.

**Response:**
```json
{
  "name": "myllm",
  "base_url": "https://ai.example.com/v1",
  "api_key": "aisk-username-abc123...",
  "api_key_mask": "aisk-username-abc1…",
  "models": [
    {
      "name": "default",
      "display_name": "default",
      "context_window": 4096,
      "concurrent_slots": 1
    }
  ],
  "instructions": "Paste this under your opencode.json → providers section."
}
```

---

### Admin endpoints (superadmin only)

#### `GET /portal/api/admin/users`

List all users with key status.

**Response:**
```json
{
  "users": [
    {
      "username": "alice",
      "role": "user",
      "status": "active",
      "key_state": "active",
      "key_mask": "aisk-alice-abc1…",
      "created": "2026-10-19T10:00:00",
      "linked": true
    }
  ]
}
```

#### `POST /portal/api/admin/users`

Create a new user and provision an API key.

**Request:**
```json
{
  "username": "newuser",
  "password": "secure-password",
  "role": "user"
}
```

**Response:**
```json
{"ok": true, "job": "job_ghi789"}
```

#### `POST /portal/api/admin/role`

Change a user's role.

**Request:**
```json
{"username": "alice", "role": "superadmin"}
```

#### `POST /portal/api/admin/user-status`

Enable or disable a user.

**Request:**
```json
{"username": "alice", "status": "disabled"}
```

#### `POST /portal/api/admin/key/rotate`

Rotate a user's API key (admin action).

**Request:**
```json
{"username": "alice"}
```

#### `POST /portal/api/admin/key/reveal`

Get a user's full API key.

**Request:**
```json
{"username": "alice"}
```

**Response:**
```json
{"key": "aisk-alice-abc123..."}
```

#### `POST /portal/api/admin/reset-password`

Reset a user's portal password.

**Request:**
```json
{"username": "alice", "password": "new-password"}
```

#### `POST /portal/api/admin/user-delete`

Delete a user and revoke their key.

**Request:**
```json
{"username": "alice"}
```

#### `POST /portal/api/admin/import`

Import a key-only user into the portal (gives them a portal login).

**Request:**
```json
{"username": "legacy-user", "password": "their-password", "role": "user"}
```

#### `POST /portal/api/admin/signup-toggle`

Open or close self-registration.

**Request:**
```json
{"open": 1}
```

#### `GET /portal/api/admin/logs`

Read log files.

**Query parameters:**
- `kind` — `access`, `error`, `events`, `auth`, or `server`
- `n` — number of lines (10–500, default 150)
- `user` — filter by username

**Response:**
```json
{"lines": ["2026-10-19T10:30:00\tuser=alice\t..."]}
```

#### `GET /portal/api/admin/services`

Get service status and signup setting.

**Response:**
```json
{
  "services": {
    "llm-backend": "active",
    "llm-proxy": "active",
    "llm-portal": "active"
  },
  "open_signup": true
}
```

#### `GET /portal/api/admin/analytics`

Get usage analytics for the dashboard charts.

**Response:**
```json
{
  "hours": [
    {"h": "2026-10-19T08", "n": 45},
    {"h": "2026-10-19T09", "n": 120}
  ],
  "top_users": [
    {"user": "alice", "calls": 340},
    {"user": "bob", "calls": 120}
  ],
  "statuses": [
    {"code": "200", "n": 450},
    {"code": "401", "n": 5}
  ],
  "total_calls": 455,
  "peak_hour": {"h": "2026-10-19T09", "n": 120},
  "total_users": 6,
  "active_users": 5
}
```

#### `POST /portal/api/admin/create-key`

Provision an API key for a user who doesn't have one.

**Request:**
```json
{"username": "alice"}
```

---

### Job polling

Slow operations (key rotation, user deletion) run as background jobs.

#### `GET /portal/api/job/{job_id}`

**Response:**
```json
{
  "state": "done",          // or "pending", "error"
  "result": {"key": "..."}, // present when state=done
  "msg": "..."              // present when state=error
}
```

---

## Inference API (proxied)

The proxy forwards `/v1/*` to the backend and adds user attribution to logs.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v1/chat/completions` | POST | Chat completion (SSE streaming supported) |
| `/v1/completions` | POST | Text completion |
| `/v1/embeddings` | POST | Generate embeddings |
| `/v1/models` | GET | List available models |
| `/health` | GET | Backend health check |

All endpoints (except `/health` on some backends) require `Authorization: Bearer <key>`.

### Error responses

| Status | Meaning |
|--------|---------|
| `401` | Missing, invalid, or revoked API key |
| `404` | Unknown endpoint or model |
| `415` | Missing `Content-Type: application/json` |
| `429` | Rate limited (if backend enforces it) |
| `502` | Backend not responding |
| `504` | Backend timeout |
