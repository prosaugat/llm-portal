# Contributing to LLM Portal

Thanks for your interest in contributing!

## Development setup

```bash
git clone https://github.com/YOUR_USERNAME/llm-portal.git
cd llm-portal
cp config.example.toml config.toml

# Run the portal in development
python3 -m llm_portal

# Run tests (when available)
python3 -m pytest
```

No pip dependencies are required for the core portal.

## Project structure

```
llm-portal/
├── llm_portal/
│   ├── __init__.py        # Package version
│   ├── __main__.py        # CLI entry point
│   ├── app.py             # Web portal (HTTP server, auth, admin)
│   ├── proxy.py           # Logging reverse proxy
│   └── config.py          # Configuration loader
├── scripts/
│   ├── rotate-logs.sh     # Log rotation
│   └── log-event.sh       # Event logging helper
├── systemd/               # Service units
├── docs/                  # Documentation
├── config.example.toml    # Configuration template
└── userctl.sh             # User management CLI
```

## Coding guidelines

### Python
- Python 3.11+ target (3.8+ with fallback)
- **No third-party dependencies** — stdlib only
- Use type hints where helpful
- Keep functions focused and documented

### Shell
- `set -euo pipefail` at the top of every script
- Quote all variable expansions
- Provide usage/help text

### HTML/CSS/JS (in `app.py`)
- Inline in the Python source (single-file deployment)
- **Escaping rules in Python triple-quoted strings:**
  - `\'` in source → `'` in output (backslash consumed)
  - `\\'` in source → `\'` in output (for JavaScript)
  - `\\n` in source → `\n` in output (for JavaScript strings)
  - `\\d` in source → `\d` in output (for JavaScript regex)
- Use `&quot;` for HTML attributes inside JavaScript strings
- Always verify JS syntax: extract `<script>` blocks and run `node --check`

### Configuration
- All new settings go in `config.example.toml` with comments
- Add corresponding defaults in `llm_portal/config.py`
- Support environment variable overrides via `_ENV_MAP`

## Testing

Before submitting a PR:

1. **Python syntax**: `python3 -m py_compile llm_portal/app.py llm_portal/proxy.py llm_portal/config.py`
2. **No hardcoded paths**: `grep -r "/home/" llm_portal/` should return nothing
3. **No brand references**: `grep -ri "techkraft" llm_portal/` should return nothing
4. **JS syntax**: Extract script blocks and verify with `node --check`
5. **Manual test**: Start the portal, log in, check all pages render

## Submitting a PR

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes
4. Update documentation if needed
5. Submit a pull request with a clear description

## Reporting bugs

Open an issue with:
- Python version (`python3 --version`)
- OS and version
- Backend type (llama.cpp / Ollama / vLLM)
- Steps to reproduce
- Expected vs actual behavior
- Relevant log output
