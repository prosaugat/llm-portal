# Getting Started

This guide walks you through setting up LLM Portal from scratch.

## Prerequisites

- Python 3.11+ (recommended; 3.8+ works with the fallback TOML parser)
- An LLM inference server (llama.cpp, Ollama, vLLM, TGI, etc.)
- Linux (macOS should work; Windows is untested)

## Step 1: Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/llm-portal.git
cd llm-portal
```

## Step 2: Create your configuration

```bash
cp config.example.toml config.toml
```

Edit `config.toml`:

```toml
[portal]
host = "127.0.0.1"
port = 8081

[branding]
name = "My AI Portal"       # your portal's name
primary_color = "#0066ff"    # your brand color

[backend]
type = "llamacpp"            # or "ollama" or "openai"
url = "http://127.0.0.1:8090"
api_domain = "ai.example.com" # your public domain

[proxy]
enabled = true
port = 8080
```

## Step 3: Start your inference server

### llama.cpp

```bash
llama-server \
  --model ./models/your-model.gguf \
  --port 8090 \
  --host 127.0.0.1 \
  --api-key-file ./data/api_keys.txt \
  --ctx-size 8192
```

### Ollama

```bash
ollama serve &   # default port 11434
```

Then set `backend.url = "http://127.0.0.1:11434"` and `proxy.enforce_auth = true` in `config.toml`.

## Step 4: Start the portal

```bash
# Terminal 1: web portal
python3 -m llm_portal

# Terminal 2: logging proxy (recommended)
python3 -m llm_portal proxy
```

## Step 5: Create the first admin account

```bash
PORTAL_BOOTSTRAP_PASSWORD=your-secure-password \
  python3 -m llm_portal.app createsuperuser admin
```

## Step 6: Log in

Open `http://localhost:8081/portal/` in your browser and sign in as `admin`.

## Step 7: Create users

From the **Admin** tab in the portal:
1. Enter a username and password
2. Select a role
3. Click **Create + API key**

Or from the CLI:
```bash
./userctl.sh add alice
./userctl.sh show alice   # get alice's API key
```

## Step 8: Configure your client

### OpenCode

Visit the dashboard and click **Copy config** under the OpenCode section.

### curl

```bash
curl http://localhost:8080/v1/chat/completions \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model": "default", "messages": [{"role": "user", "content": "Hello"}]}'
```

## Production deployment

See the [systemd deployment section in the README](../README.md#production-deployment-systemd).

## Troubleshooting

| Problem | Solution |
|---------|----------|
| Portal won't start | Check `python3 -m py_compile llm_portal/app.py` |
| Can't log in | Verify the admin was created: `PORTAL_BOOTSTRAP_PASSWORD=... python3 -m llm_portal.app createsuperuser admin` |
| API returns 401 | Check the key file exists and the key matches: `./userctl.sh list` |
| Proxy can't reach backend | Verify `backend.url` in config.toml matches your server |
| Styling looks broken | Make sure the proxy is running on port 8080 and routing `/portal/*` correctly |
