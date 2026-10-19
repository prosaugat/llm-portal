# Changelog

All notable changes to this project will be documented in this file.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)

## [1.0.0] — 2026-10-19

### Added
- **Initial public release**
- Web portal with signup, login, dashboard, account management
- Admin console with user CRUD, role management, and system status
- Usage analytics dashboard with SVG charts (hourly API calls, top users, status codes)
- Logging reverse proxy with per-user request attribution
- API key management: generate, reveal, rotate, disable, delete
- OpenCode integration config generation
- Configurable branding (portal name, colors) via `config.toml`
- TOML configuration file with environment variable overrides
- Backend support: llama.cpp, Ollama, vLLM, and any OpenAI-compatible server
- `proxy.enforce_auth` option for backends without native auth (Ollama, vLLM)
- User management CLI (`userctl.sh`)
- Systemd service units for portal, proxy, and log rotation
- Daily log rotation with configurable retention (default 7 days)
- Rate limiting for login (8 attempts per 10 minutes)
- PBKDF2-SHA256 password hashing (200k iterations)
- CSRF protection on all POST requests
- Security headers (CSP, X-Frame-Options, nosniff, Referrer-Policy)
- Audit logging for all admin actions
- Responsive UI with dark glassmorphism theme
- Password strength meter on signup and password change forms
- Live activity feed on dashboard (15s auto-refresh)
- Admin analytics auto-refresh (30s)
- Documentation: Getting Started, Configuration, Architecture, Operations, API Reference, Security Model
- Example configs for llama.cpp, Ollama, and vLLM
- Docker Compose example
- GitHub Actions CI (syntax checks, config validation, smoke test)
- Issue templates (bug report, feature request)
- Makefile with common development tasks
- MIT License

### Security
- Session tokens stored as SHA-256 hashes only
- Constant-time password and token comparison
- HTTP-only, SameSite=Lax session cookies
- Per-IP login rate limiting
