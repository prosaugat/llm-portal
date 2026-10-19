"""Configuration loader for LLM Portal.

Reads config.toml (or a path given by the LLM_PORTAL_CONFIG env var),
then applies environment-variable overrides on top.

Priority (highest wins):
  1. Environment variables
  2. config.toml
  3. Built-in defaults

No third-party dependencies — uses Python 3.11+ tomllib, with a
minimal fallback parser for older versions.
"""
from __future__ import annotations

import os
from typing import Any

# ---------------------------------------------------------------- defaults
DEFAULTS: dict[str, Any] = {
    "portal": {
        "host": "127.0.0.1",
        "port": 8081,
        "session_hours": 12,
        "open_signup": True,
    },
    "branding": {
        "name": "LLM Portal",
        "primary_color": "#0066ff",
        "accent_color": "#FF9900",
        "dark_color": "#15275D",
    },
    "backend": {
        "type": "llamacpp",
        "url": "http://127.0.0.1:8090",
        "api_domain": "localhost:8080",
        "provider_name": "myllm",
        "model": "default",
        "model_alias": "default",
        "ctx_per_slot": 4096,
        "slots": 1,
    },
    "proxy": {
        "enabled": True,
        "host": "0.0.0.0",
        "port": 8080,
        "enforce_auth": True,
    },
    "paths": {
        "data_dir": "./data",
        "log_dir": "./logs",
        "keys_file": "./data/api_keys.txt",
        "db_file": "./data/portal.db",
        "userctl": "./userctl.sh",
    },
    "security": {
        "pbkdf2_iterations": 200_000,
        "session_cookie": "llmportal",
        "rate_limit_attempts": 8,
        "rate_limit_window_minutes": 10,
    },
    "logging": {
        "retention_days": 7,
        "rotate_time": "00:05:00",
    },
}

# Environment-variable overrides:  ENV name  ->  (section, key, type)
_ENV_MAP: dict[str, tuple[str, str, type]] = {
    # portal
    "PORTAL_HOST":         ("portal", "host", str),
    "PORTAL_PORT":         ("portal", "port", int),
    "SESSION_HOURS":       ("portal", "session_hours", int),
    "OPEN_SIGNUP":         ("portal", "open_signup", bool),
    # branding
    "PORTAL_NAME":         ("branding", "name", str),
    "PRIMARY_COLOR":       ("branding", "primary_color", str),
    "ACCENT_COLOR":        ("branding", "accent_color", str),
    # backend
    "BACKEND_TYPE":        ("backend", "type", str),
    "UPSTREAM":            ("backend", "url", str),
    "API_DOMAIN":          ("backend", "api_domain", str),
    "PROVIDER_NAME":       ("backend", "provider_name", str),
    # proxy
    "PROXY_HOST":          ("proxy", "host", str),
    "PROXY_PORT":          ("proxy", "port", int),
    "PROXY_ENFORCE_AUTH":  ("proxy", "enforce_auth", bool),
    "PORTAL_UPSTREAM":     ("proxy", "_portal_upstream", str),  # handled in proxy
    # paths
    "LOG_DIR":             ("paths", "log_dir", str),
    "KEY_FILE":            ("paths", "keys_file", str),
    "PORTAL_DB":           ("paths", "db_file", str),
    "AIUSER":              ("paths", "userctl", str),
    "PROJ":                ("paths", "_proj", str),  # legacy base dir
    # security
    "SESSION_COOKIE":      ("security", "session_cookie", str),
}


def _parse_toml(path: str) -> dict[str, Any]:
    """Parse a TOML file. Returns {} on any failure."""
    try:
        import tomllib
        with open(path, "rb") as f:
            return tomllib.load(f)
    except ImportError:
        pass
    except (OSError, Exception):
        pass
    # Fallback: minimal TOML parser (flat tables only, good enough)
    result: dict[str, Any] = {}
    current: dict[str, Any] = result
    try:
        with open(path, "r") as f:
            for raw in f:
                line = raw.split("#", 1)[0].strip()
                if not line:
                    continue
                if line.startswith("[") and line.endswith("]"):
                    section = line[1:-1].strip()
                    current = result.setdefault(section, {})
                    continue
                if "=" not in line:
                    continue
                key, _, val = line.partition("=")
                key = key.strip()
                val = val.strip()
                # strip quotes
                if val.startswith('"') and val.endswith('"'):
                    val = val[1:-1]
                elif val.startswith("'") and val.endswith("'"):
                    val = val[1:-1]
                elif val.lower() in ("true", "false"):
                    val = val.lower() == "true"
                else:
                    try:
                        val = int(val)
                    except ValueError:
                        try:
                            val = float(val)
                        except ValueError:
                            pass
                current[key] = val
    except OSError:
        pass
    return result


def _coerce(value: str, target_type: type) -> Any:
    if target_type is bool:
        return value.lower() in ("1", "true", "yes", "on")
    try:
        return target_type(value)
    except (ValueError, TypeError):
        return value


def _deep_merge(base: dict, override: dict) -> dict:
    merged = dict(base)
    for k, v in override.items():
        if k in merged and isinstance(merged[k], dict) and isinstance(v, dict):
            merged[k] = _deep_merge(merged[k], v)
        else:
            merged[k] = v
    return merged


class Config:
    """Merged configuration with attribute-style and dict-style access."""

    def __init__(self, data: dict[str, Any]):
        self._data = data

    def __getitem__(self, section: str) -> dict:
        return self._data.get(section, {})

    def get(self, section: str, key: str, default: Any = None) -> Any:
        return self._data.get(section, {}).get(key, default)

    def section(self, name: str) -> dict:
        return dict(self._data.get(name, {}))

    @property
    def data(self) -> dict:
        return self._data


def load_config(config_path: str | None = None) -> Config:
    """Load configuration from file + environment + defaults."""
    # 1. Start with defaults
    cfg = dict(DEFAULTS)

    # 2. Merge config file
    path = config_path or os.environ.get("LLM_PORTAL_CONFIG", "")
    if not path:
        # Search common locations
        for candidate in ("config.toml", "./config.toml", "/etc/llm-portal/config.toml"):
            if os.path.isfile(candidate):
                path = candidate
                break
    if path and os.path.isfile(path):
        file_cfg = _parse_toml(path)
        if file_cfg:
            cfg = _deep_merge(cfg, file_cfg)

    # 3. Apply environment overrides
    for env_name, (section, key, typ) in _ENV_MAP.items():
        if env_name in os.environ:
            cfg.setdefault(section, {})[key] = _coerce(os.environ[env_name], typ)

    # 4. Resolve relative paths against the base directory
    base = cfg.get("paths", {}).get("_proj") or os.getcwd()
    paths = cfg.setdefault("paths", {})
    for pk in ("data_dir", "log_dir", "keys_file", "db_file"):
        val = paths.get(pk, "")
        if val and not os.path.isabs(val):
            paths[pk] = os.path.normpath(os.path.join(base, val))

    return Config(cfg)


# Module-level singleton (loaded once at import)
_config: Config | None = None


def get_config() -> Config:
    global _config
    if _config is None:
        _config = load_config()
    return _config


def set_config(cfg: Config) -> None:
    """Override the singleton (useful for testing)."""
    global _config
    _config = cfg
