# LLM Portal

> Self-hosted web portal for managing users, API keys, and access to your LLM inference server.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen.svg)](#)
[![LLM Backend](https://img.shields.io/badge/backend-llama.cpp%20%7C%20Ollama%20%7C%20vLLM-orange.svg)](#backend-support)

Works with **llama.cpp**, **Ollama**, **vLLM**, **TGI**, or any OpenAI-compatible backend.

---

## Why LLM Portal?

Running a local LLM server is easy. **Managing who can use it** is not.

| Problem | LLM Portal solution |
|---------|-------------------|
| No user accounts on llama.cpp/Ollama | Web signup, login, password reset |
| Shared API keys = no accountability | Per-user keys with rotation & revocation |
| "Who made 10,000 calls last night?" | Per-user request attribution in logs |
| No usage visibility | Analytics dashboard with hourly charts |
| Manual key distribution | Self-service key reveal/rotate from the UI |
| OpenCode setup is tedious | One-click config generation |

## Features

- **Web signup & login** — users self-register and get their own API key
- **Admin console** — manage users, roles, keys, and view analytics with charts
- **API key management** — reveal, rotate, disable/expire keys from the UI or CLI
- **Logging reverse proxy** — per-user request attribution, access logs, error logs
- **Usage analytics** — hourly API call charts, top users, status code distribution
- **OpenCode integration** — one-click config generation for OpenCode IDE
- **Responsive UI** — glassmorphism dark theme, works on mobile
- **Zero dependencies** — pure Python stdlib, no pip install required
- **Systemd ready** — includes service units for production deployment
- **Configurable branding** — your portal name, your colors, your domain
- **Rate limiting** — login brute-force protection out of the box
- **Audit logging** — every admin action recorded with IP and timestamp

## Architecture

```
                    ┌─────────────────────────────────────┐
  Internet ────────▶│  Logging Reverse Proxy  :8080       │
                    │  (auth, rate-limit, per-user logs)  │
                    └──────────┬──────────────┬───────────┘
                               │              │
                    /portal/*  │              │  /v1/* (API)
                               ▼              ▼
                    ┌────────────────┐  ┌──────────────────┐
                    │  Web Portal    │  │  Inference Server │
                    │  :8081         │  │  :8090            │
                    │  (auth, users, │  │  llama.cpp/Ollama/│
                    │   admin UI)    │  │  vLLM/etc         │
                    └────────────────┘  └──────────────────┘
```

**Three components, one job each:**

| Component | Role | Port |
|-----------|------|------|
| **Portal** (`app.py`) | Web UI, authentication, user/key CRUD, admin console | `:8081` (loopback) |
| **Proxy** (`proxy.py`) | Routes traffic, attributes requests to users, enforces auth | `:8080` (public) |
| **CLI** (`userctl.sh`) | Scripted user/key management for automation | — |

## Quick Start

### 1. Clone & configure

```bash
git clone https://github.com/prosaugat/llm-portal.git
cd llm-portal
cp config.example.toml config.toml
# Edit config.toml — at minimum set branding.name and backend.url
```

### 2. Start the portal

```bash
# Terminal 1: web portal
python3 -m llm_portal

# Terminal 2: logging proxy (recommended)
python3 -m llm_portal proxy
```

### 3. Create the first admin

```bash
PORTAL_BOOTSTRAP_PASSWORD=changeme python3 -m llm_portal.app createsuperuser admin
```

### 4. Open the portal

Visit `http://localhost:8081/portal/` and sign in as `admin`.

### 5. Create users

From the **Admin** tab, or via CLI:

```bash
./userctl.sh add alice
./userctl.sh show alice   # get alice's API key
```

## Backend support

### llama.cpp

```toml
[backend]
type = "llamacpp"
url = "http://127.0.0.1:8090"
```

```bash
llama-server --api-key-file ./data/api_keys.txt --port 8090 -m model.gguf
```

Native auth — the backend reads the key file directly. No proxy enforcement needed.

### Ollama

```toml
[backend]
type = "ollama"
url = "http://127.0.0.1:11434"

[proxy]
enforce_auth = true   # Ollama has no native auth — proxy enforces keys
```

The proxy rejects requests without a valid API key before they reach Ollama.

### vLLM / TGI / any OpenAI-compatible server

```toml
[backend]
type = "openai"
url = "http://127.0.0.1:8000/v1"

[proxy]
enforce_auth = true
```

## Configuration

All configuration lives in `config.toml`. See [`config.example.toml`](config.example.toml) for all options.

### Key settings

| Setting | Description | Default |
|---------|-------------|---------|
| `portal.host` / `portal.port` | Web portal bind address | `127.0.0.1:8081` |
| `backend.type` | Inference backend: `llamacpp`, `ollama`, `openai` | `llamacpp` |
| `backend.url` | Backend API URL | `http://127.0.0.1:8090` |
| `proxy.enforce_auth` | Enforce API keys at the proxy | `false` |
| `branding.name` | Portal display name | `LLM Portal` |
| `branding.primary_color` | Brand color | `#0066ff` |

Full reference: [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md)

## User management CLI

```bash
./userctl.sh add alice        # create user + API key
./userctl.sh list             # list all users
./userctl.sh show alice       # print alice's full key
./userctl.sh revoke alice     # rotate alice's key (old one dies)
./userctl.sh disable alice    # block alice without deleting
./userctl.sh enable alice     # restore access
./userctl.sh remove alice     # delete alice + key
```

## API endpoints

Once running, the proxy exposes an OpenAI-compatible API:

```bash
# Chat completion
curl http://localhost:8080/v1/chat/completions \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model": "default", "messages": [{"role": "user", "content": "Hello"}]}'

# List models
curl http://localhost:8080/v1/models \
  -H "Authorization: Bearer YOUR_API_KEY"

# Health check
curl http://localhost:8080/health
```

Portal endpoints (behind auth):

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/portal/login` | Sign-in page |
| GET | `/portal/signup` | Registration page |
| GET | `/portal/dashboard` | User dashboard |
| GET | `/portal/account` | Account settings |
| GET | `/portal/admin` | Admin console (superadmin only) |
| POST | `/portal/api/login` | Authenticate |
| POST | `/portal/api/signup` | Register |
| GET | `/portal/api/key` | Get own API key |
| POST | `/portal/api/key/rotate` | Rotate own key |
| GET | `/portal/api/opencode-config` | OpenCode config JSON |
| GET | `/portal/api/admin/users` | List all users (admin) |
| GET | `/portal/api/admin/analytics` | Usage analytics (admin) |
| GET | `/portal/api/admin/logs` | Read log files (admin) |
| GET | `/portal/api/admin/services` | Service status (admin) |

## Production deployment (systemd)

```bash
# Install files
sudo mkdir -p /opt/llm-portal
sudo cp -r . /opt/llm-portal/
sudo cp config.example.toml /opt/llm-portal/config.toml
sudo nano /opt/llm-portal/config.toml

# Install service units
for f in systemd/*.service systemd/*.timer; do
  sudo sed "s|__INSTALL_DIR__|/opt/llm-portal|g" "$f" \
    | sudo tee "/etc/systemd/system/$(basename $f)" > /dev/null
done

sudo systemctl daemon-reload
sudo systemctl enable --now llm-portal llm-proxy rotate-logs.timer
```

### Behind a TLS reverse proxy

Put Nginx or Caddy in front of port 8080:

```nginx
# Nginx example
server {
    listen 443 ssl;
    server_name ai.example.com;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Host $host;
        proxy_buffering off;   # required for SSE/streaming
    }
}
```

## Documentation

| Document | What it covers |
|----------|---------------|
| [Getting Started](docs/GETTING_STARTED.md) | Step-by-step setup guide |
| [Configuration Reference](docs/CONFIGURATION.md) | Every config option + env vars |
| [Architecture](docs/ARCHITECTURE.md) | How components fit together |
| [Operations Guide](docs/OPERATIONS.md) | Day-2 ops: backups, monitoring, upgrades |
| [API Reference](docs/API_REFERENCE.md) | All portal REST endpoints |
| [Security Model](docs/SECURITY.md) | Auth, sessions, key management details |
| [Contributing](CONTRIBUTING.md) | Development setup and guidelines |

## Requirements

- Python 3.11+ (for `tomllib`; a fallback parser is included for 3.8+)
- Linux (systemd optional; macOS should work)
- **No pip dependencies** — pure standard library

## License

[MIT](LICENSE)
