#!/usr/bin/env python3
"""LLM Portal — logging reverse proxy.

Sits on the public port and forwards requests to the backend inference
server, routing /portal/* to the auth portal instead.

Logs:
  logs/access/access.log   one line per request with user attribution
                           (includes tokens=<n> when usage is parseable)
  logs/error/error.log     HTTP 4xx/5xx, auth failures, proxy errors,
                           rate-limit / quota / concurrency rejections
  logs/events/events.log   startup / shutdown / upstream-down notifications

User attribution: the Bearer token in each request (Authorization header)
is mapped to the username via the keys file (re-read on mtime change +
30 s TTL). For /portal/* requests the tkuser cookie set by the portal is
used so portal traffic is attributed to the logged-in user.

For Ollama and other backends without native auth, set proxy.enforce_auth
= true in config.toml to reject requests without a valid API key.

Rate limiting + quotas (per authenticated key, /v1/* only):
  proxy.rate_limit_rpm         max requests/min per key  (default 60,  0 = off)
  proxy.rate_limit_concurrency max simultaneous streams  (default 5,   0 = off)
  proxy.token_daily_quota      max tokens/day per key    (default 0  = off)
  Exceeding any limit returns 429 + Retry-After (OpenAI-compatible JSON).
  Token usage is parsed from response bodies (JSON + SSE) and logged.

No third-party deps: pure Python asyncio + stdlib.
"""

import asyncio
import json
import os
import re
import socket
import time
from collections import deque
from datetime import datetime, date

# ---------------------------------------------------------------- config
try:
    from .config import get_config
except ImportError:
    import sys as _sys, os as _os
    _sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
    from llm_portal.config import get_config

_cfg = get_config()

PROXY_HOST = _cfg.get("proxy", "host", "0.0.0.0")
PROXY_PORT = _cfg.get("proxy", "port", 8080)
UPSTREAM   = _cfg.get("backend", "url", "http://127.0.0.1:8090")
# /portal/* is routed to the auth-portal app instead of the backend
PORTAL_UP  = os.environ.get("PORTAL_UPSTREAM", f"127.0.0.1:{_cfg.get('portal', 'port', 8081)}")
LOG_DIR    = _cfg.get("paths", "log_dir", "./logs")
KEY_FILE   = _cfg.get("paths", "keys_file", "./data/api_keys.txt")
ENFORCE_AUTH = _cfg.get("proxy", "enforce_auth", False)
# --- rate limits / quotas (per authenticated user, /v1/* only) ---
RATE_LIMIT_RPM = int(_cfg.get("proxy", "rate_limit_rpm", 60))            # 0 = unlimited
RATE_LIMIT_CONCURRENCY = int(_cfg.get("proxy", "rate_limit_concurrency", 5))  # 0 = unlimited
TOKEN_DAILY_QUOTA = int(_cfg.get("proxy", "token_daily_quota", 0))       # 0 = unlimited

BLOCK = 65536
REQ_RE = re.compile(r"^([A-Z]+) (\S+) HTTP/1\.[01]$")
STAT_RE = re.compile(rb"^HTTP/1\.[01] (\d{3})")
# hop-by-hop headers we never forward upstream (we manage framing ourselves)
# x-forwarded-for is dropped too: we re-emit a trusted chain ourselves
DROP_HEADERS = {
    "connection", "keep-alive", "transfer-encoding", "proxy-authenticate",
    "proxy-authorization", "te", "trailers", "upgrade", "expect",
    "x-forwarded-for",
}

USER_MAP = {}
USER_MAP_TTL = 0.0
USER_MAP_MTIME = 0.0


# ---------------------------------------------------------------- logging
def _append(kind, text):
    path = os.path.join(LOG_DIR, kind, f"{kind}.log")
    try:
        with open(path, "a") as f:
            f.write(text)
    except Exception:
        pass  # never let logging kill the proxy


def log_access(user, req, status, nbytes, dur_ms, ua, ip, req_type, tokens=0):
    ts = datetime.now().isoformat(timespec="seconds")
    tok = f"\ttokens={tokens}" if tokens else ""
    _append("access",
            f"{ts}\tuser={user}\ttype={req_type}\tip={ip}\t{req}\t{status}\t{nbytes}B\t{dur_ms}ms\tua={ua!r}{tok}\n")


def log_error(user, req, msg, status=""):
    ts = datetime.now().isoformat(timespec="seconds")
    _append("error", f"{ts}\tuser={user}\tstatus={status}\trequest={req}\tmessage={msg}\n")


def log_event(msg):
    ts = datetime.now().isoformat(timespec="seconds")
    _append("events", f"{ts}\t{msg}\n")


# ---------------------------------------------------------------- user map
def load_user_map():
    m = {}
    try:
        lines = open(KEY_FILE, encoding="utf-8", errors="replace").read().splitlines()
    except Exception:
        return m
    i = 0
    while i < len(lines):
        l = lines[i].strip()
        if l.startswith("# user:"):
            name = l.split(":", 1)[1].strip()
            key = lines[i + 1].strip() if i + 1 < len(lines) else ""
            if key and not key.startswith("#"):
                m[key] = name
            i += 2
            continue
        i += 1
    return m


def _refresh_user_map(force=False):
    """Re-read key file if TTL expired or mtime changed (instant on file change)."""
    global USER_MAP, USER_MAP_TTL, USER_MAP_MTIME
    now = time.time()
    try:
        mtime = os.path.getmtime(KEY_FILE)
    except OSError:
        mtime = 0.0
    mtime_changed = mtime != USER_MAP_MTIME
    ttl_expired = now > USER_MAP_TTL
    if force or mtime_changed or ttl_expired:
        USER_MAP = load_user_map()
        USER_MAP_MTIME = mtime
        USER_MAP_TTL = now + 30
        return True
    return False


def resolve_user(auth_header):
    _refresh_user_map()
    if not auth_header or not auth_header.strip():
        return "anon"
    token = auth_header.strip().split()[-1]
    return USER_MAP.get(token, "unknown:" + token[:18] + "..")


def check_auth(auth_header, path):
    """Enforce auth for /v1/* requests when ENFORCE_AUTH is enabled.

    Returns (ok, username).  When ok=False the caller should send 401.
    Instantly picks up new keys via mtime check in _refresh_user_map().
    """
    if not ENFORCE_AUTH:
        return True, resolve_user(auth_header)
    # exempt paths: health checks + portal (own session auth) + web UI
    if path == "/health" or path.startswith("/portal") or not path.startswith("/v1/"):
        return True, resolve_user(auth_header)
    if not auth_header or not auth_header.strip():
        return False, "anon"
    token = auth_header.strip().split()[-1]
    _refresh_user_map()
    username = USER_MAP.get(token)
    if username:
        return True, username
    # unknown key — force one more read in case file just changed
    _refresh_user_map(force=True)
    username = USER_MAP.get(token)
    if username:
        return True, username
    return False, "unknown:" + token[:18] + ".."


# ------------------------------------------------------- rate limit / quota
_rate_windows = {}       # user -> deque of request timestamps (sliding 60 s)
_concurrency = {}        # user -> in-flight request count
_token_daily = {}        # user -> {"date": date_str, "tokens": int}


def check_rate_limit(user, path):
    """Sliding-window RPM check for /v1/* only. Returns (allowed, retry_after)."""
    if RATE_LIMIT_RPM <= 0 or not path.startswith("/v1/"):
        return True, 0
    now = time.time()
    win = _rate_windows.get(user)
    if win is None:
        win = _rate_windows[user] = deque()
    cutoff = now - 60
    while win and win[0] < cutoff:
        win.popleft()
    if len(win) >= RATE_LIMIT_RPM:
        retry_after = max(1, int(win[0] + 60 - now) + 1)
        return False, retry_after
    win.append(now)
    return True, 0


def acquire_slot(user, path):
    """Reserve a concurrency slot for /v1/*. Returns True if acquired (or unlimited)."""
    if RATE_LIMIT_CONCURRENCY <= 0 or not path.startswith("/v1/"):
        return True
    cur = _concurrency.get(user, 0)
    if cur >= RATE_LIMIT_CONCURRENCY:
        return False
    _concurrency[user] = cur + 1
    return True


def release_slot(user, path):
    if RATE_LIMIT_CONCURRENCY <= 0 or not path.startswith("/v1/"):
        return
    cur = _concurrency.get(user, 0)
    if cur > 0:
        _concurrency[user] = cur - 1


def check_token_quota(user):
    """Returns (allowed, used_today, quota). Resets daily."""
    if TOKEN_DAILY_QUOTA <= 0:
        return True, 0, 0
    today = date.today().isoformat()
    entry = _token_daily.get(user)
    if not entry or entry["date"] != today:
        entry = _token_daily[user] = {"date": today, "tokens": 0}
    if entry["tokens"] >= TOKEN_DAILY_QUOTA:
        return False, entry["tokens"], TOKEN_DAILY_QUOTA
    return True, entry["tokens"], TOKEN_DAILY_QUOTA


def add_tokens(user, n):
    if n <= 0:
        return
    today = date.today().isoformat()
    entry = _token_daily.get(user)
    if not entry or entry["date"] != today:
        entry = _token_daily[user] = {"date": today, "tokens": 0}
    entry["tokens"] += n


def get_token_usage(user):
    """Return (tokens_today, quota, pct) for a user."""
    today = date.today().isoformat()
    entry = _token_daily.get(user)
    used = entry["tokens"] if entry and entry["date"] == today else 0
    pct = int(used * 100 / TOKEN_DAILY_QUOTA) if TOKEN_DAILY_QUOTA > 0 else 0
    return used, TOKEN_DAILY_QUOTA, pct


# ------------------------------------------------------ portal attribution
def resolve_portal_user(headers):
    """Extract username from tkuser cookie set by the portal (fixes user=anon)."""
    cookie = headers.get("cookie", "")
    for part in cookie.split(";"):
        k, _, v = part.strip().partition("=")
        if k == "tkuser" and v:
            return v
    return "anon"


# ---------------------------------------------------------- token extraction
_USAGE_PT_RE = re.compile(rb'"prompt_tokens":\s*(\d+)')
_USAGE_CT_RE = re.compile(rb'"completion_tokens":\s*(\d+)')


def extract_usage(data):
    """Extract (prompt_tokens, completion_tokens) from a response body / SSE chunk."""
    idx = data.find(b'"usage"')
    if idx < 0:
        return 0, 0
    window = data[idx:idx + 512]
    pt_m = _USAGE_PT_RE.search(window)
    ct_m = _USAGE_CT_RE.search(window)
    pt = int(pt_m.group(1)) if pt_m else 0
    ct = int(ct_m.group(1)) if ct_m else 0
    return pt, ct


# ---------------------------------------------------------------- relay
async def _read_with_timeout(reader, timeout=900):
    return await asyncio.wait_for(reader.read(BLOCK), timeout)


async def relay_chunked(src, dst, capture_usage=False):
    """Relay a chunked body verbatim; returns bytes relayed (or (bytes, usage_buf)).

    Uses readexactly() for chunk payloads: a plain read() can return bytes
    BEYOND the current chunk (they belong to the next chunk's framing) and
    forwarding only 'remaining' used to drop them, corrupting SSE streams
    mid-generation (web-UI: "Stream resume produced no new bytes").
    """
    total = 0
    usage_buf = b""
    while True:
        size_line = await src.readline()
        if not size_line:
            break
        try:
            size = int(size_line.split(b";")[0].strip(), 16)
        except ValueError:
            size = 0
        dst.write(size_line)
        await dst.drain()
        if size == 0:
            while True:
                t = await src.readline()
                dst.write(t)
                await dst.drain()
                if capture_usage:
                    usage_buf += t
                if t in (b"\r\n", b"\n", b""):
                    break
            break
        try:
            data = await asyncio.wait_for(src.readexactly(size), 900)
            crlf = await asyncio.wait_for(src.readexactly(2), 900)
        except asyncio.IncompleteReadError as e:   # upstream closed early
            if e.partial:
                dst.write(e.partial)
                await dst.drain()
                if capture_usage:
                    usage_buf += e.partial
            break
        except asyncio.TimeoutError:
            break
        dst.write(data + crlf)
        await dst.drain()
        total += size
        if capture_usage:
            usage_buf += data
            # keep buffer bounded: usage arrives at end of stream
            if len(usage_buf) > 65536:
                usage_buf = usage_buf[-16384:]
    if capture_usage:
        return total, usage_buf
    return total


async def handle_client(client_r, client_w):
    peer = client_w.get_extra_info("peername") or ("?", 0)
    ip = str(peer[0])
    t0 = time.time()
    user, req, status, nbytes = "anon", "-", 0, 0
    ua, req_type = "", ""
    slot_held = False
    resp_tokens = 0
    try:
        client_r.sock = None
        # --- read request head ---
        lines = []
        while True:
            l = await asyncio.wait_for(client_r.readline(), 60)
            if l in (b"\r\n", b"\n", b""):
                break
            lines.append(l)
        if not lines:
            return
        first = lines[0].decode("latin1").rstrip("\r\n")
        m = REQ_RE.match(first)
        if not m:
            await _reply(client_w, 400, b"Bad Request")
            return
        method, path = m.group(1), m.group(2)
        req = f"{method} {path}"
        headers = {}
        for l in lines[1:]:
            k, _, v = l.decode("latin1").partition(":")
            headers[k.strip().lower()] = v.strip()
        auth = headers.get("authorization", "")
        ua = headers.get("user-agent", "")
        is_portal = path == "/portal" or path.startswith("/portal/")
        # --- auth enforcement for /v1/* (instant key pickup, no restart) ---
        auth_ok, user = check_auth(auth, path)
        if not auth_ok:
            status = 401
            req_type = "api"
            dur_ms = int((time.time() - t0) * 1000)
            log_access(user, f"{method} {path}", 401, 0, dur_ms, ua, ip, "api")
            log_error(user, f"{method} {path}", "invalid or missing API key", 401)
            err = json.dumps({"error": {"message": "Invalid or missing API key",
                                        "type": "invalid_request_error",
                                        "code": "invalid_api_key"}}).encode()
            await _reply(client_w, 401, err, content_type="application/json")
            return
        # --- portal attribution from tkuser cookie (fixes user=anon) ---
        if is_portal and user == "anon":
            user = resolve_portal_user(headers)
        # --- rate limit (RPM) → 429 ---
        rl_ok, retry_after = check_rate_limit(user, path)
        if not rl_ok:
            status = 429
            dur_ms = int((time.time() - t0) * 1000)
            log_access(user, f"{method} {path}", 429, 0, dur_ms, ua, ip, "api")
            log_error(user, f"{method} {path}",
                      f"rate limit exceeded ({RATE_LIMIT_RPM}/min)", 429)
            err = json.dumps({"error": {
                "message": f"Rate limit exceeded: {RATE_LIMIT_RPM} requests/min. Retry in {retry_after}s.",
                "type": "rate_limit_error", "code": "rate_limit_exceeded"}}).encode()
            await _reply(client_w, 429, err, content_type="application/json",
                         extra={"Retry-After": str(retry_after)})
            return
        # --- token daily quota → 429 ---
        tq_ok, used_today, quota = check_token_quota(user)
        if not tq_ok:
            status = 429
            dur_ms = int((time.time() - t0) * 1000)
            log_access(user, f"{method} {path}", 429, 0, dur_ms, ua, ip, "api")
            log_error(user, f"{method} {path}",
                      f"token daily quota exceeded ({used_today}/{quota})", 429)
            err = json.dumps({"error": {
                "message": f"Daily token quota exceeded: {used_today}/{quota} tokens used today.",
                "type": "rate_limit_error", "code": "token_quota_exceeded"}}).encode()
            await _reply(client_w, 429, err, content_type="application/json",
                         extra={"Retry-After": "3600"})
            return
        # --- concurrency cap ---
        if not acquire_slot(user, path):
            status = 429
            dur_ms = int((time.time() - t0) * 1000)
            log_access(user, f"{method} {path}", 429, 0, dur_ms, ua, ip, "api")
            log_error(user, f"{method} {path}",
                      f"concurrency limit reached ({RATE_LIMIT_CONCURRENCY} streams)", 429)
            err = json.dumps({"error": {
                "message": f"Concurrency limit: max {RATE_LIMIT_CONCURRENCY} simultaneous requests per key.",
                "type": "rate_limit_error", "code": "concurrency_limit_exceeded"}}).encode()
            await _reply(client_w, 429, err, content_type="application/json",
                         extra={"Retry-After": "5"})
            return
        slot_held = True
        if is_portal:
            req_type, target = "portal", PORTAL_UP
        elif path == "/health":
            req_type, target = "probe", UPSTREAM
        elif path.startswith("/v1/"):
            req_type, target = "api", UPSTREAM
        else:
            req_type, target = "web", UPSTREAM
        # --- body ---
        body = b""
        clen = int(headers.get("content-length", "0") or 0)
        if clen:
            body = await asyncio.wait_for(client_r.readexactly(clen), 120)
        # --- forward upstream (fresh connection, Connection: close) ---
        up_host, up_port = target.split(":")
        try:
            up_r, up_w = await asyncio.wait_for(
                asyncio.open_connection(up_host, int(up_port)), 15)
        except Exception as e:
            status = 502
            log_error(user, req, f"upstream connect failed ({target}): {e!r}", status)
            msg = (b"Bad Gateway: auth portal unavailable"
                   if is_portal else b"Bad Gateway: upstream unavailable")
            await _reply(client_w, 502, msg)
            return
        try:
            head = f"{method} {path} HTTP/1.1\r\n"
            for k, v in headers.items():
                if k not in DROP_HEADERS:
                    head += f"{k}: {v}\r\n"
            # trusted client chain: any upstream XFF + our direct peer
            xff = headers.get("x-forwarded-for", "")
            head += f"X-Forwarded-For: {(xff + ', ' if xff else '')}{ip}\r\n"
            head += f"Connection: close\r\nContent-Length: {len(body)}\r\n\r\n"
            up_w.write(head.encode("latin1") + body)
            await up_w.drain()
            # --- response head ---
            status_line = await asyncio.wait_for(up_r.readline(), 120)
            sm = STAT_RE.match(status_line)
            status = int(sm.group(1)) if sm else 0
            rlines = []
            while True:
                l = await asyncio.wait_for(up_r.readline(), 120)
                if l in (b"\r\n", b"\n", b""):
                    break
                rlines.append(l)
            rheaders = {}
            for l in rlines:
                k, _, v = l.decode("latin1").partition(":")
                rheaders[k.strip().lower()] = v.strip()
            chunked = rheaders.get("transfer-encoding", "").lower() == "chunked"
            rclen = int(rheaders.get("content-length", "0") or 0)
            # --- relay head to client ---
            client_w.write(status_line)
            for l in rlines:
                client_w.write(l)
            client_w.write(b"\r\n")
            await client_w.drain()
            # --- relay body ---
            usage_buf = b""
            if chunked:
                nbytes, usage_buf = await relay_chunked(up_r, client_w, capture_usage=True)
            elif rclen:
                try:
                    data = await asyncio.wait_for(up_r.readexactly(rclen), 900)
                    client_w.write(data)
                    await client_w.drain()
                    nbytes = rclen
                    usage_buf = data
                except asyncio.IncompleteReadError as e:
                    if e.partial:
                        client_w.write(e.partial)
                        await client_w.drain()
                    nbytes = len(e.partial)
                    usage_buf = e.partial or b""
                except asyncio.TimeoutError:
                    nbytes = 0
            else:
                while True:
                    data = await _read_with_timeout(up_r)
                    if not data:
                        break
                    client_w.write(data)
                    await client_w.drain()
                    nbytes += len(data)
                    usage_buf += data
            await client_w.drain()
            # --- token accounting ---
            if usage_buf:
                pt, ct = extract_usage(usage_buf)
                resp_tokens = pt + ct
                if resp_tokens:
                    add_tokens(user, resp_tokens)
            # --- log ---
            dur_ms = int((time.time() - t0) * 1000)
            log_access(user, req, status, nbytes, dur_ms, ua, ip, req_type, resp_tokens)
            if status >= 400:
                log_error(user, req, f"upstream returned {status}", status)
        finally:
            up_w.close()
            try:
                await up_w.wait_closed()
            except Exception:
                pass
    except asyncio.TimeoutError:
        status = status or 504
        log_error(user, req, "timeout while proxying", status)
        try:
            await _reply(client_w, 504, b"Gateway Timeout")
        except Exception:
            pass
    except (ConnectionResetError, BrokenPipeError):
        log_error(user, req, "client disconnected mid-request", status)
    except Exception as e:
        log_error(user, req, f"proxy error: {e!r}", status or 500)
        try:
            await _reply(client_w, 502, b"Bad Gateway")
        except Exception:
            pass
    finally:
        if slot_held:
            release_slot(user, path)
        try:
            client_w.close()
            await client_w.wait_closed()
        except Exception:
            pass


async def _reply(writer, code, body, content_type="text/plain", extra=None):
    reason = {200: "OK", 400: "Bad Request", 401: "Unauthorized",
              429: "Too Many Requests", 502: "Bad Gateway",
              504: "Gateway Timeout"}.get(code, "Error")
    hdrs = f"HTTP/1.1 {code} {reason}\r\nContent-Length: {len(body)}\r\nConnection: close\r\nContent-Type: {content_type}\r\n"
    for k, v in (extra or {}).items():
        hdrs += f"{k}: {v}\r\n"
    hdrs += "\r\n"
    writer.write(hdrs.encode("latin1") + body)
    await writer.drain()


async def main():
    log_event(f"logging proxy starting: listen {PROXY_HOST}:{PROXY_PORT} upstream {UPSTREAM} portal {PORTAL_UP} keyfile {KEY_FILE} rate_limit={RATE_LIMIT_RPM}/min concurrency={RATE_LIMIT_CONCURRENCY} token_quota={TOKEN_DAILY_QUOTA}")
    server = await asyncio.start_server(handle_client, PROXY_HOST, PROXY_PORT)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("proxy stopped")
