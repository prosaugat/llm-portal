# Configuration Reference

LLM Portal is configured via `config.toml` and environment variables.

**Priority:** Environment variables > `config.toml` > built-in defaults.

## Finding your config file

The portal looks for `config.toml` in this order:
1. Path given by `LLM_PORTAL_CONFIG` environment variable
2. `./config.toml` (current directory)
3. `/etc/llm-portal/config.toml`

## `[portal]` — Web portal

| Key | Env var | Type | Default | Description |
|-----|---------|------|---------|-------------|
| `host` | `PORTAL_HOST` | string | `127.0.0.1` | Bind address |
| `port` | `PORTAL_PORT` | int | `8081` | Bind port |
| `session_hours` | `SESSION_HOURS` | int | `12` | Session lifetime |
| `open_signup` | `OPEN_SIGNUP` | bool | `true` | Allow self-registration |

## `[branding]` — Appearance

| Key | Env var | Type | Default | Description |
|-----|---------|------|---------|-------------|
| `name` | `PORTAL_NAME` | string | `LLM Portal` | Portal display name |
| `primary_color` | `PRIMARY_COLOR` | string | `#0066ff` | Primary brand color |
| `accent_color` | `ACCENT_COLOR` | string | `#FF9900` | Accent color |
| `dark_color` | — | string | `#15275D` | Background gradient color |

## `[backend]` — Inference server

| Key | Env var | Type | Default | Description |
|-----|---------|------|---------|-------------|
| `type` | `BACKEND_TYPE` | string | `llamacpp` | `llamacpp`, `ollama`, or `openai` |
| `url` | `UPSTREAM` | string | `http://127.0.0.1:8090` | Backend API URL |
| `api_domain` | `API_DOMAIN` | string | `localhost:8080` | Public domain for dashboard/OpenCode |
| `provider_name` | `PROVIDER_NAME` | string | `myllm` | OpenCode provider name |
| `model` | — | string | `default` | Default model name |
| `model_alias` | — | string | `default` | Display alias |
| `ctx_per_slot` | — | int | `4096` | Context window per slot |
| `slots` | — | int | `1` | Concurrent slots |

## `[proxy]` — Logging reverse proxy

| Key | Env var | Type | Default | Description |
|-----|---------|------|---------|-------------|
| `enabled` | — | bool | `true` | Enable the proxy |
| `host` | `PROXY_HOST` | string | `0.0.0.0` | Bind address |
| `port` | `PROXY_PORT` | int | `8080` | Bind port |
| `enforce_auth` | `PROXY_ENFORCE_AUTH` | bool | `false` | Reject requests without a valid API key at the proxy level |

### When to set `enforce_auth`

| Backend | Native auth? | `enforce_auth` |
|---------|-------------|----------------|
| llama.cpp (`AUTH=on`) | Yes | `false` (backend handles it) |
| Ollama | No | `true` (proxy must enforce) |
| vLLM / TGI | Optional | `true` (recommended) |

### Rate limiting + quotas

| Key | Env var | Type | Default | Description |
|-----|---------|------|---------|-------------|
| `rate_limit_rpm` | `RATE_LIMIT_RPM` | int | `60` | Max requests/min per key (`0` = off) |
| `rate_limit_concurrency` | `RATE_LIMIT_CONCURRENCY` | int | `5` | Max simultaneous streams per key (`0` = off) |
| `token_daily_quota` | `TOKEN_DAILY_QUOTA` | int | `0` | Max tokens/day per key (`0` = off) |

All limits return `429` with `Retry-After` and an OpenAI-compatible JSON error body.

## `[paths]` — File locations

| Key | Env var | Type | Default | Description |
|-----|---------|------|---------|-------------|
| `data_dir` | — | string | `./data` | Base data directory |
| `log_dir` | `LOG_DIR` | string | `./logs` | Log directory |
| `keys_file` | `KEY_FILE` | string | `./data/api_keys.txt` | API keys file |
| `db_file` | `PORTAL_DB` | string | `./data/portal.db` | SQLite database |
| `userctl` | `AIUSER` | string | `./userctl.sh` | User management CLI path |

Relative paths are resolved against the working directory (or `PROJ` if set).

## `[security]` — Authentication

| Key | Env var | Type | Default | Description |
|-----|---------|------|---------|-------------|
| `pbkdf2_iterations` | — | int | `200000` | Password hashing iterations |
| `session_cookie` | `SESSION_COOKIE` | string | `llmportal` | Session cookie name |
| `rate_limit_attempts` | — | int | `8` | Max login attempts per window |
| `rate_limit_window_minutes` | — | int | `10` | Rate-limit window |

## `[logging]` — Log rotation

| Key | Env var | Type | Default | Description |
|-----|---------|------|---------|-------------|
| `retention_days` | — | int | `7` | Days to keep logs |
| `rotate_time` | — | string | `00:05:00` | Daily rotation time |

## Environment variable reference

All environment variables in one place:

```bash
# Portal
export PORTAL_HOST=0.0.0.0
export PORTAL_PORT=8081
export SESSION_HOURS=24
export OPEN_SIGNUP=0

# Branding
export PORTAL_NAME="My AI Portal"
export PRIMARY_COLOR="#e74c3c"

# Backend
export BACKEND_TYPE=ollama
export UPSTREAM=http://127.0.0.1:11434
export API_DOMAIN=ai.example.com

# Proxy
export PROXY_PORT=8080
export PROXY_ENFORCE_AUTH=1

# Paths
export LOG_DIR=/var/log/llm-portal
export KEY_FILE=/etc/llm-portal/api_keys.txt
export PORTAL_DB=/var/lib/llm-portal/portal.db

# Security
export SESSION_COOKIE=myportal

# Config file location
export LLM_PORTAL_CONFIG=/etc/llm-portal/config.toml
```
