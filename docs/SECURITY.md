# Security Model

How LLM Portal handles authentication, sessions, and API keys.

## Overview

```
┌─────────────────────────────────────────────────┐
│                  Client                         │
│  (browser or API client)                        │
└──────────┬──────────────────────┬───────────────┘
           │                      │
     Session cookie         Bearer API key
     (portal pages)         (API requests)
           │                      │
           ▼                      ▼
┌──────────────────┐    ┌──────────────────┐
│  Portal (:8081)  │    │  Proxy (:8080)   │
│                  │    │                  │
│  • PBKDF2 hash   │    │  • Key lookup    │
│  • CSRF tokens   │    │  • Rate limit    │
│  • Rate limiting │    │  • Attribution   │
│  • Audit logging │    │  • Auth enforce  │
└──────────────────┘    └──────────────────┘
```

## Password security

- **Algorithm:** PBKDF2-HMAC-SHA256
- **Iterations:** 200,000 (configurable via `security.pbkdf2_iterations`)
- **Salt:** Unique random 16-byte salt per password
- **Storage:** Only the derived hash is stored; plaintext is never saved
- **Comparison:** Constant-time (`hmac.compare_digest`) to prevent timing attacks

### Password requirements

- Minimum 8 characters
- Enforced by the frontend strength meter and backend validation

## Session security

| Property | Value |
|----------|-------|
| Token | 256-bit random (`secrets.token_urlsafe(32)`) |
| Storage | Only SHA-256 hash in database (plaintext cookie is not stored server-side) |
| Cookie flags | `HttpOnly`, `SameSite=Lax` |
| Expiry | 12 hours (configurable via `portal.session_hours`) |
| CSRF | Double-submit token on all POST requests |

### How sessions work

1. User logs in with username/password
2. Server generates a random token, stores its SHA-256 hash in `sessions` table
3. Token is set as an HTTP-only cookie
4. Every request: cookie → hash → lookup in DB → find session + user
5. On logout or expiry: session row is deleted

### CSRF protection

- Each session gets a unique CSRF token
- The token is embedded in the page JavaScript (`const CSRF = "..."`)
- All POST requests must include `X-CSRF-Token` header
- Server compares the header token with the session's stored token (constant-time)

## Rate limiting

### Login rate limiting

Login attempts are rate-limited per IP address:

- **Default:** 8 attempts per 10-minute window
- **Scope:** Per IP, not per account (prevents brute-force from any source)
- **Reset:** Window slides; counter resets after the window expires
- **Bypass:** Restarting the portal clears all counters

Failed attempts are logged to `logs/auth/auth.log` with IP and username.

### API rate limiting (proxy)

All `/v1/*` requests are rate-limited per authenticated API key:

| Limit | Default | Returns | Config |
|-------|---------|---------|--------|
| Requests per minute | 60 | `429` + `Retry-After` | `proxy.rate_limit_rpm` |
| Concurrent streams | 5 | `429` | `proxy.rate_limit_concurrency` |
| Tokens per day | unlimited | `429` + `Retry-After: 3600` | `proxy.token_daily_quota` |

- Sliding 60-second window per key (not fixed buckets)
- Concurrency counter is released when the response finishes (including streams)
- Token quota resets daily (in-memory)
- Portal (`/portal/*`) and health (`/health`) are exempt

## API key security

### Key format

```
aisk-<username>-<32 hex characters>
```

Example: `aisk-alice-a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6`

### Key storage

- Stored in `data/api_keys.txt` with mode `0600` (owner read/write only)
- Format: `<username> <key>` (one per line)
- This file is the **source of truth** — both the portal and proxy read it
- llama-server can also read it directly (native auth)

### Key lifecycle

```
Created ──▶ Active ──▶ Rotated (old key revoked)
                │
                ├──▶ Disabled (blocked, key preserved)
                │         │
                │         └──▶ Enabled (restored)
                │
                └──▶ Deleted (key destroyed)
```

### Key rotation

- Rotating generates a new random key and **immediately invalidates** the old one
- The proxy re-reads the key file **instantly** when it changes (mtime detection)
- With `proxy.enforce_auth = true` (default): **no backend restart needed** — new keys work within milliseconds
- For llama.cpp with backend auth (`enforce_auth = false`): `userctl.sh` handles the restart

### Key revocation vs deletion

| Action | Key | User account | Portal login |
|--------|-----|-------------|--------------|
| Disable | Kept (can re-enable) | Kept | Blocked |
| Revoke | Destroyed, new one created | Kept | Works |
| Delete | Destroyed | Destroyed | Gone |

## Proxy security

### Auth enforcement

When `proxy.enforce_auth = true`:

1. Extract `Authorization: Bearer <key>` header
2. Look up key in `data/api_keys.txt`
3. If key not found → return `401 Unauthorized`
4. If key found → forward request, log with username attribution
5. If no header → return `401 Unauthorized`

### Request logging

Every request is logged with:
- Timestamp
- Username (or `anon` for no key, `unknown:<prefix>` for invalid key)
- Request method and path
- Response status code
- Response size and duration
- User agent
- Client IP (from `X-Forwarded-For` if behind a reverse proxy)

### Header handling

The proxy **strips** these hop-by-hop headers before forwarding:
- `Connection`, `Keep-Alive`, `Transfer-Encoding`
- `Proxy-Authenticate`, `Proxy-Authorization`
- `TE`, `Trailers`, `Upgrade`, `Expect`
- `X-Forwarded-For` (re-emitted with trusted chain)

## HTTP security headers

All portal responses include:

```
Content-Security-Policy: default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src 'self' data:; form-action 'self'
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: same-origin
Cache-Control: no-store
```

| Header | Effect |
|--------|--------|
| CSP | Blocks external scripts/styles/images; only same-origin + inline allowed |
| nosniff | Prevents MIME-type sniffing |
| DENY | Prevents clickjacking (page cannot be in an iframe) |
| same-origin | No referrer sent to external sites |
| no-store | Responses not cached by the browser |

## Audit logging

Every significant action is logged to `logs/auth/auth.log`:

| Action | Details logged |
|--------|---------------|
| Login success | Username, IP |
| Login failure | Username, IP, reason |
| Signup | Username, IP |
| Password change | Username, IP |
| Role change | Actor, target, old/new role |
| Key rotation | Actor, target username |
| User creation | Actor, target username, role |
| User deletion | Actor, target username |
| Account self-delete | Username, IP |
| Superadmin bootstrap | Username, IP |

## File permissions

| File | Mode | Why |
|------|------|-----|
| `data/portal.db` | `0600` | Contains password hashes |
| `data/api_keys.txt` | `0600` | Contains API keys |
| `config.toml` | `0600` | May contain internal URLs |
| `logs/` | `0755` | Readable for monitoring |
| Portal process | runs as non-root | Least privilege |

## Deployment recommendations

1. **Always use TLS** — put the portal behind Nginx/Caddy with HTTPS
2. **Bind portal to loopback** — never expose port 8081 directly
3. **Bind proxy to loopback too** if using a local TLS proxy
4. **Use strong passwords** — enforce via your organizational policy
5. **Disable open signup** after initial setup (`portal.open_signup = false`)
6. **Regular backups** — of `data/portal.db` and `data/api_keys.txt`
7. **Monitor auth logs** — watch for repeated failed login attempts
8. **Rotate keys periodically** — especially after team member offboarding
9. **Run as non-root** — create a dedicated system user
10. **Keep Python updated** — security patches for the stdlib

## Reporting vulnerabilities

If you discover a security vulnerability, please report it responsibly:
- Do **not** open a public GitHub issue
- Contact the maintainer directly
- Include steps to reproduce and potential impact
