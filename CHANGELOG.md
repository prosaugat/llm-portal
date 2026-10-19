# Changelog

All notable changes to this project will be documented in this file.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)

## [1.1.0] — 2026-10-19

### Added
- **Zero-restart user provisioning** — proxy-enforced auth (`proxy.enforce_auth = true`): new API keys work instantly without restarting the backend. The proxy detects key file changes via mtime and reloads within milliseconds.
- **Personal usage charts** — 24-hour hourly API call chart on dashboard with OK/error legend (SVG, auto-refresh 30s)
- **Getting started checklist** — 4-step onboarding guide on dashboard (create account → reveal key → first API call → copy config) with progress counter
- **Account page overhaul** — profile card with gradient avatar, usage summary (3-stat row + sparkline), active sessions list with revoke, login history with status dots
- **Active sessions management** — view all sessions, identify current device, revoke individual sessions
- **Login history** — recent 20 login attempts with IP, timestamp, and success/failure status
- **Dark/light theme toggle** — moon/sun button in header, persists via localStorage, full light theme for all components
- **Mobile hamburger menu** — slide-out navigation drawer on screens ≤640px with overlay backdrop
- **Command palette** — press `Ctrl+K` anywhere for quick navigation (Dashboard, Account, Admin, key operations, sign out) with fuzzy search
- **Skeleton loading states** — pulsing shimmer placeholders while data loads
- **Login page polish** — show/hide password toggle, loading spinner during authentication, shake animation on failed attempts
- **Password visibility toggle** — eye icon on password fields in account and login pages
- **New API endpoints**: `GET /portal/api/my-usage`, `GET /portal/api/my-sessions`, `GET /portal/api/my-logins`, `POST /portal/api/session/revoke`

### Changed
- `userctl.sh` no longer restarts the backend on key changes — keys are hot-reloaded by the proxy (when `enforce_auth = true`)
- Dashboard restructured with two-column grid: Getting Started + Usage Chart alongside API Key + OpenCode Config
- Account page expanded to 720px width with card-based layout
- Responsive breakpoints updated for mobile hamburger menu

### Fixed
- `&quot;` entity in static HTML attributes replaced with literal `"` for correct DOM parsing

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
