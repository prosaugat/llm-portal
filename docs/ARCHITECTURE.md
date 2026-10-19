# Architecture

LLM Portal consists of three main components that work together:

## Components

### 1. Web Portal (`llm_portal/app.py`)

A Python HTTP server that provides:

- **Authentication** — login/signup with PBKDF2-SHA256 password hashing
- **Session management** — HTTP-only cookies with CSRF protection
- **User management** — CRUD operations, role-based access (user/superadmin)
- **API key management** — generate, reveal, rotate, disable keys
- **Admin console** — analytics charts, log viewer, system status
- **Audit logging** — every action recorded to `logs/auth/auth.log`

Listens on `127.0.0.1:8081` (loopback only — not exposed publicly).

### 2. Logging Reverse Proxy (`llm_portal/proxy.py`)

An asyncio-based reverse proxy that:

- **Routes traffic** — `/portal/*` → portal, everything else → backend
- **Attributes requests** — maps Bearer tokens to usernames via the key file
- **Logs requests** — access logs, error logs, events (with user attribution)
- **Enforces auth** (optional) — rejects requests without valid API keys
- **Injects headers** — `X-Forwarded-For` for backend visibility

Listens on `0.0.0.0:8080` (public-facing).

### 3. User CLI (`userctl.sh`)

A bash script for managing users and API keys from the command line:

- Creates/removes users and their API keys
- Rotates keys (old key immediately invalidated)
- Disables/enables access without deleting keys
- Keys hot-reload in the proxy instantly — no backend restart needed (with `enforce_auth = true`)

## Data flow

```
Client Request
     │
     ▼
┌─────────────────────────┐
│  Proxy (:8080)          │
│  1. Parse Authorization  │
│  2. Look up user by key  │──▶ data/api_keys.txt
│  3. Route:               │
│     /portal/* → Portal   │──▶ Portal (:8081)
│     else      → Backend  │──▶ Backend (:8090)
│  4. Log with attribution │──▶ logs/access/access.log
└─────────────────────────┘
```

## File storage

| File | Format | Purpose |
|------|--------|---------|
| `config.toml` | TOML | Configuration |
| `data/portal.db` | SQLite | Users, sessions, audit log |
| `data/api_keys.txt` | Plain text | API keys (source of truth) |
| `data/users.md` | Markdown | Human-readable user list |
| `logs/access/` | Text | Request logs |
| `logs/error/` | Text | Error logs |
| `logs/events/` | Text | System events |
| `logs/auth/` | Text | Authentication audit |

## Security model

### Passwords
- PBKDF2-SHA256 with 200k iterations
- Unique salt per password
- Constant-time comparison

### Sessions
- Random 256-bit tokens
- Only the SHA-256 hash is stored in the database
- HTTP-only, SameSite=Lax cookies
- 12-hour expiry (configurable)
- CSRF tokens on all POST requests

### API keys
- Format: `aisk-<username>-<32 hex chars>`
- Stored in a flat file readable only by the service user (mode 600)
- Rotation invalidates the old key immediately
- llama-server reads the file directly (native auth) or the proxy enforces it

### Rate limiting
- Login attempts limited to 8 per 10 minutes per IP
- Failed attempts logged to the audit trail

### Headers
- `Content-Security-Policy`: default-src 'self' (no external resources)
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Referrer-Policy: same-origin`

## Backend integration

The portal works with any backend by abstracting two concerns:

1. **Key storage** — keys live in `data/api_keys.txt` regardless of backend
2. **Auth enforcement** — either the backend reads the file (llama.cpp) or the proxy enforces it (Ollama/vLLM)

### Key file format

```
<username> <api-key>
```

Example:
```
alice aisk-alice-a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6
bob   aisk-bob-b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7
```

## Deployment topology

### Development (single machine)
```
Browser → Proxy :8080 → Portal :8081 + Backend :8090
```

### Production (with TLS)
```
Internet → Nginx/Caddy (TLS, :443) → Proxy :8080 → Portal + Backend
```

The proxy is designed to sit behind a TLS-terminating reverse proxy. It binds to `0.0.0.0` so it can be reached from the TLS proxy on the same host or a different host.

## Scalability notes

- The portal uses `ThreadingHTTPServer` — handles concurrent requests
- The proxy uses asyncio — handles thousands of concurrent connections
- SQLite is sufficient for thousands of users
- For heavier loads, consider replacing SQLite with PostgreSQL (not built-in)
