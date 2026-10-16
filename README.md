# LLM Portal

A self-hosted web portal for managing users, API keys, and access to your LLM inference server.

Works with **llama.cpp**, **Ollama**, **vLLM**, **TGI**, or any OpenAI-compatible backend.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

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

## Quick Start

### 1. Clone & configure

```bash
git clone https://github.com/YOUR_USERNAME/llm-portal.git
cd llm-portal
cp config.example.toml config.toml
# Edit config.toml for your setup
```

### 2. Start the portal

```bash
# Start the web portal
python3 -m llm_portal

# In another terminal, start the proxy (optional but recommended)
python3 -m llm_portal proxy
```

### 3. Create the first admin

```bash
PORTAL_BOOTSTRAP_PASSWORD=changeme python3 -m llm_portal.app createsuperuser admin
```

### 4. Open the portal

Visit `http://localhost:8081/portal/` and sign in.

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

### Environment variables

Every config key can be overridden via environment variables. See [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md) for the full mapping.

## Backend support

### llama.cpp

```toml
[backend]
type = "llamacpp"
url = "http://127.0.0.1:8090"
```

Start llama-server with `--api-key-file` pointing to the same key file:
```bash
llama-server --api-key-file ./data/api_keys.txt --port 8090 -m model.gguf
```

### Ollama

```toml
[backend]
type = "ollama"
url = "http://127.0.0.1:11434"

[proxy]
enforce_auth = true   # Ollama has no native auth — proxy enforces keys
```

### vLLM / TGI / any OpenAI-compatible server

```toml
[backend]
type = "openai"
url = "http://127.0.0.1:8000/v1"

[proxy]
enforce_auth = true
```

## User management CLI

```bash
./userctl.sh add alice        # create user + API key
./userctl.sh list             # list all users
./userctl.sh show alice       # print alice's full key
./userctl.sh revoke alice     # rotate alice's key (old one dies)
./userctl.sh disable alice    # block alice without deleting
./userctl.sh remove alice     # delete alice + key
```

## Production deployment (systemd)

```bash
# Install files
sudo mkdir -p /opt/llm-portal
sudo cp -r . /opt/llm-portal/
sudo cp config.example.toml /opt/llm-portal/config.toml
sudo nano /opt/llm-portal/config.toml   # edit for your setup

# Install service units (replace __INSTALL_DIR__ with /opt/llm-portal)
for f in systemd/*.service systemd/*.timer; do
  sudo sed "s|__INSTALL_DIR__|/opt/llm-portal|g" "$f" \
    | sudo tee "/etc/systemd/system/$(basename $f)" > /dev/null
done

sudo systemctl daemon-reload
sudo systemctl enable --now llm-portal llm-proxy rotate-logs.timer
```

## Documentation

- [Getting Started](docs/GETTING_STARTED.md) — step-by-step setup guide
- [Configuration Reference](docs/CONFIGURATION.md) — all config options
- [Architecture](docs/ARCHITECTURE.md) — how the components fit together
- [Management Guide](docs/MANAGEMENT_GUIDE.md) — operations runbook

## Requirements

- Python 3.11+ (for `tomllib`; a fallback parser is included for older versions)
- Linux (systemd optional)
- **No pip dependencies** — pure standard library

## License

[MIT](LICENSE)
