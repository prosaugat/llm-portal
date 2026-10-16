#!/usr/bin/env python3
"""LLM Portal — self-hosted web portal for managing LLM inference servers.

Pages (reached via the logging proxy at /portal/...):
  /portal/login     sign in
  /portal/signup    self-registration -> provisions API key
  /portal/dashboard own API key (reveal/rotate), recent API activity
  /portal/account   change password / delete account / logout
  /portal/admin     superadmin console: user CRUD, log viewer, analytics

Design:
  * Portal accounts / sessions / audit -> SQLite (configurable path), 0600
  * API keys -> key file (llama-server source of truth), mutated ONLY via
    the userctl CLI, invoked as a subprocess (flock'd)
  * Fast ops (passwords, roles) are synchronous JSON; slow ops that restart
    the model server run as background JOBS polled by the browser.

Run:
    python3 -m llm_portal.app
First superadmin:
    PORTAL_BOOTSTRAP_PASSWORD=... python3 -m llm_portal.app createsuperuser admin
"""
import fcntl
import hashlib
import hmac
import html
import http.cookies
import json
import os
import re
import secrets
import sqlite3
import subprocess
import sys
import threading
import time
from collections import deque
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

# ---------------------------------------------------------------- config
try:
    from .config import get_config
except ImportError:
    import sys as _sys, os as _os
    _sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
    from llm_portal.config import get_config
_cfg = get_config()

PROJ = _cfg.get("paths", "_proj") or os.getcwd()
HOST = _cfg.get("portal", "host", "127.0.0.1")
PORT = _cfg.get("portal", "port", 8081)
DB = _cfg.get("paths", "db_file", f"{PROJ}/data/portal.db")
LOGDIR = _cfg.get("paths", "log_dir", f"{PROJ}/logs")
KEYFILE = _cfg.get("paths", "keys_file", f"{PROJ}/data/api_keys.txt")
AIUSER = _cfg.get("paths", "userctl", f"{PROJ}/userctl.sh")
OPEN_SIGNUP_DEFAULT = _cfg.get("portal", "open_signup", True)
SESSION_SECS = _cfg.get("portal", "session_hours", 12) * 3600
AIUSER_LOCK = f"{PROJ}/.userctl.lock"
AUTHLOG = f"{LOGDIR}/auth/auth.log"
ACCESSLOG = f"{LOGDIR}/access/access.log"
COOKIE = _cfg.get("security", "session_cookie", "llmportal")

# Branding
PORTAL_NAME = _cfg.get("branding", "name", "LLM Portal")
PRIMARY_COLOR = _cfg.get("branding", "primary_color", "#0066ff")
ACCENT_COLOR = _cfg.get("branding", "accent_color", "#FF9900")
DARK_COLOR = _cfg.get("branding", "dark_color", "#15275D")

# Backend
BACKEND_TYPE = _cfg.get("backend", "type", "llamacpp")
API_DOMAIN = _cfg.get("backend", "api_domain", "localhost:8080")
PROVIDER_NAME = _cfg.get("backend", "provider_name", "myllm")
BACKEND_URL = _cfg.get("backend", "url", "http://127.0.0.1:8090")
BACKEND_ENV = os.environ.get("BACKEND_ENV_FILE", f"{PROJ}/backend.env")

U_RE = re.compile(r"^[a-z][a-z0-9_-]{0,30}$")   # same rule as userctl.sh
KEY_RE = re.compile(r"aisk-[a-z0-9_-]+-[0-9a-f]{32}")
PBKDF2_ITERS = 200_000

# ---------------------------------------------------------------- db layer
def init_db():
    os.makedirs(os.path.dirname(DB), exist_ok=True)
    conn = sqlite3.connect(DB)
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            pw TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            status TEXT NOT NULL DEFAULT 'active',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sessions(
            token_hash TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            csrf TEXT NOT NULL,
            expires_at INTEGER NOT NULL,
            created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS audit(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            username TEXT,
            action TEXT,
            ip TEXT,
            result TEXT,
            detail TEXT
        );
        CREATE TABLE IF NOT EXISTS kv(k TEXT PRIMARY KEY, v TEXT);
        """
    )
    conn.commit()
    conn.close()
    try:
        os.chmod(DB, 0o600)
    except OSError:
        pass


init_db()
CONN = sqlite3.connect(DB, check_same_thread=False)
CONN.row_factory = sqlite3.Row
DB_LOCK = threading.RLock()


def q(sql, args=(), one=False):
    with DB_LOCK:
        cur = CONN.execute(sql, args)
        rows = cur.fetchall()
        CONN.commit()
    if one:
        return rows[0] if rows else None
    return rows


def now_iso():
    return datetime.now().isoformat(timespec="seconds")


def esc(s):
    return html.escape(str(s if s is not None else ""), quote=True)


# ---------------------------------------------------------------- auth core
def hash_password(pw):
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), PBKDF2_ITERS)
    return f"pbkdf2_sha256${PBKDF2_ITERS}${salt}${dk.hex()}"


def verify_password(pw, stored):
    try:
        _, iters, salt, digest = stored.split("$")
        dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), int(iters))
        return hmac.compare_digest(dk.hex(), digest)
    except Exception:
        return False


def purge_expired_sessions():
    q("DELETE FROM sessions WHERE expires_at < ?", (int(time.time()),))


def create_session(user_id):
    token = secrets.token_urlsafe(32)
    th = hashlib.sha256(token.encode()).hexdigest()
    csrf = secrets.token_urlsafe(16)
    now = int(time.time())
    q(
        "INSERT INTO sessions(token_hash,user_id,csrf,expires_at,created_at) VALUES(?,?,?,?,?)",
        (th, user_id, csrf, now + SESSION_SECS, now),
    )
    return token, csrf


def session_user(headers):
    raw = headers.get("Cookie")
    if not raw:
        return None
    try:
        c = http.cookies.SimpleCookie()
        c.load(raw)
        morsel = c.get(COOKIE)
        if not morsel:
            return None
        token = morsel.value
    except Exception:
        return None
    th = hashlib.sha256(token.encode()).hexdigest()
    row = q(
        "SELECT s.user_id AS uid, s.csrf AS csrf, s.expires_at AS exp, "
        "u.username AS username, u.role AS role, u.status AS status "
        "FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?",
        (th,),
        one=True,
    )
    if not row:
        return None
    if row["exp"] < int(time.time()):
        q("DELETE FROM sessions WHERE token_hash = ?", (th,))
        return None
    if row["status"] != "active":
        q("DELETE FROM sessions WHERE user_id = ?", (row["uid"],))
        return None
    return {"id": row["uid"], "username": row["username"], "role": row["role"],
            "csrf": row["csrf"], "token_hash": th}


def drop_sessions_for_user(user_id):
    q("DELETE FROM sessions WHERE user_id = ?", (user_id,))


_ATTEMPTS = {}
_AT_LOCK = threading.Lock()


def rate_ok(key, maxn=8, window=600):
    now = time.time()
    with _AT_LOCK:
        dq = _ATTEMPTS.setdefault(key, deque())
        while dq and dq[0] < now - window:
            dq.popleft()
        if len(dq) >= maxn:
            return False
        dq.append(now)
        return True


def rate_clear(key):
    with _AT_LOCK:
        _ATTEMPTS.pop(key, None)


# ---------------------------------------------------------------- key file
def parse_keyfile():
    out = {}
    try:
        lines = open(KEYFILE, encoding="utf-8", errors="replace").read().splitlines()
    except OSError:
        return out
    i = 0
    while i < len(lines):
        l = lines[i].strip()
        if l.startswith("# user:"):
            name = l.split(":", 1)[1].strip()
            key = lines[i + 1].strip() if i + 1 < len(lines) else ""
            disabled = key.startswith("# DISABLED")
            if disabled:
                key = key.replace("# DISABLED ", "", 1)
            out[name] = {"key": key, "disabled": disabled}
            i += 2
            continue
        i += 1
    return out


# ---------------------------------------------------------------- userctl.sh
def run_userctl(args, timeout=300):
    """Run userctl.sh with an exclusive lock (its ops restart the model server)."""
    with open(AIUSER_LOCK, "w") as lf:
        fcntl.flock(lf, fcntl.LOCK_EX)
        p = subprocess.run([AIUSER] + args, capture_output=True, text=True,
                           timeout=timeout)
    return p.returncode, p.stdout, p.stderr


# ---------------------------------------------------------------- jobs
JOBS = {}
_JOBS_LOCK = threading.Lock()


def submit_job(kind, actor_id, fn):
    jid = secrets.token_hex(8)
    with _JOBS_LOCK:
        JOBS[jid] = {"id": jid, "kind": kind, "actor": actor_id,
                     "state": "running", "msg": "working…", "result": None,
                     "ts": time.time()}
        now = time.time()
        for k in [k for k, v in JOBS.items() if now - v["ts"] > 3600]:
            JOBS.pop(k, None)

    def runner():
        try:
            res = fn()
            ok = bool(res.get("ok"))
            with _JOBS_LOCK:
                j = JOBS[jid]
                j["state"] = "done" if ok else "error"
                j["msg"] = res.get("msg", "")
                j["result"] = res.get("result")
        except Exception as e:
            with _JOBS_LOCK:
                j = JOBS[jid]
                j["state"] = "error"
                j["msg"] = str(e)

    threading.Thread(target=runner, daemon=True).start()
    return jid


# ---------------------------------------------------------------- audit
def audit(username, action, ip, result="ok", detail=""):
    ts = now_iso()
    try:
        q("INSERT INTO audit(ts,username,action,ip,result,detail) VALUES(?,?,?,?,?,?)",
          (ts, username, action, ip, result, str(detail)[:400]))
    except Exception:
        pass
    try:
        os.makedirs(os.path.dirname(AUTHLOG), exist_ok=True)
        with open(AUTHLOG, "a") as f:
            f.write(f"{ts}\tuser={username}\taction={action}\tip={ip}\t"
                    f"result={result}\tdetail={str(detail)[:300]}\n")
    except Exception:
        pass


# ---------------------------------------------------------------- log tails
def tail_file(path, max_bytes=262144):
    try:
        with open(path, "rb") as f:
            f.seek(0, 2)
            size = f.tell()
            start = max(0, size - max_bytes)
            f.seek(start)
            data = f.read().decode("utf-8", "replace")
        lines = [l for l in data.splitlines() if l]
        if start > 0 and lines:
            lines = lines[1:]          # drop the partial first line
        return lines
    except OSError:
        return []


def own_activity(username, n=20):
    needle = f"\tuser={username}\t"
    hits = [l for l in tail_file(ACCESSLOG, 512 * 1024) if needle in l]
    out = []
    for l in hits[-n:][::-1]:
        p = l.split("\t")
        if len(p) >= 8:
            out.append({"ts": p[0], "type": p[2], "ip": p[3], "req": p[4],
                        "status": p[5], "bytes": p[6], "dur": p[7]})
    return out


LOG_FILES = {
    "access": f"{LOGDIR}/access/access.log",
    "error": f"{LOGDIR}/error/error.log",
    "events": f"{LOGDIR}/events/events.log",
    "auth": f"{LOGDIR}/auth/auth.log",
}


def read_log(kind, n=150, user_filter=""):
    lines = tail_file(LOG_FILES.get(kind, LOG_FILES["access"]), 512 * 1024)
    if user_filter:
        lines = [l for l in lines if f"user={user_filter}" in l]
    return lines[-min(n, 500):][::-1]


def services_state():
    out = {}
    for svc in _cfg.get("services", "names", ["llm-backend", "llm-proxy", "llm-portal", "rotate-logs.timer"]):
        try:
            st = subprocess.run(["systemctl", "is-active", svc],
                                capture_output=True, text=True,
                                timeout=5).stdout.strip()
        except Exception:
            st = "?"
        out[svc] = st
    return out


def kv_get(k, default=""):
    row = q("SELECT v FROM kv WHERE k=?", (k,), one=True)
    return row["v"] if row else default


def kv_set(k, v):
    q("INSERT INTO kv(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
      (k, v))


def signup_open():
    return kv_get("open_signup", "1" if OPEN_SIGNUP_DEFAULT else "0") == "1"


def count_superadmins():
    return q("SELECT COUNT(*) AS c FROM users WHERE role='superadmin' AND status='active'",
             one=True)["c"]


def valid_user(u):
    return isinstance(u, str) and U_RE.match(u) is not None


def valid_pw(p):
    return isinstance(p, str) and 8 <= len(p) <= 200


def validate_role(r):
    return r if r in ("user", "superadmin") else "user"


# ================================================================ HTML
BASE_TPL = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{TITLE}} · {{PORTAL_NAME}}</title>
<style>
:root{--bg:#080c14;--card:rgba(22,26,34,0.85);--line:rgba(36,42,53,0.7);--txt:#e6e9ef;
--mut:#8b93a3;--acc:{{PRIMARY_COLOR}};--acc2:{{PRIMARY_COLOR}};--orange:{{ACCENT_COLOR}};--dkblue:{{DARK_COLOR}};
--ok:#34d399;--err:#f87171;--warn:#fbbf24;--glass:rgba(255,255,255,0.04)}
*{box-sizing:border-box;margin:0;padding:0}
body{font:15px/1.6 system-ui,-apple-system,"Segoe UI",sans-serif;
background:var(--bg);color:var(--txt);min-height:100vh}
body::before{content:"";position:fixed;inset:0;z-index:-1;
background:
  radial-gradient(ellipse 80% 50% at 20% 10%,rgba(0,26,255,0.08),transparent),
  radial-gradient(ellipse 60% 40% at 80% 80%,rgba(255,153,0,0.05),transparent),
  radial-gradient(ellipse 50% 30% at 50% 50%,rgba(21,39,93,0.06),transparent)}

/* ── header ── */
header{display:flex;align-items:center;gap:12px;padding:10px 24px;
background:rgba(8,12,20,0.92);backdrop-filter:blur(12px);
border-bottom:1px solid var(--line);position:sticky;top:0;z-index:5}
.logo{display:flex;align-items:center;gap:8px;text-decoration:none;\ncolor:inherit;transition:opacity .2s}\n.logo:hover{opacity:.8}\n.logo-wrap{display:inline-flex;align-items:center;}\n.logo-wrap svg{height:22px}\n.logo-text{font-size:13px;font-weight:700;color:var(--acc);
background:linear-gradient(90deg,var(--acc),var(--orange));
-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.logo-wrap .logo-text{font-size:13px;font-weight:700;color:var(--acc);
background:linear-gradient(90deg,var(--acc),var(--orange));
-webkit-background-clip:text;-webkit-text-fill-color:transparent}\n.narrow .logo-wrap{margin-bottom:20px}\n.narrow .logo-wrap svg{height:28px}
.narrow .logo-wrap{margin-bottom:20px}
nav{display:flex;gap:4px}
nav a{color:var(--mut);text-decoration:none;padding:6px 12px;border-radius:8px;
font-size:13.5px;font-weight:500;transition:all .2s}
nav a:hover{color:var(--txt);background:rgba(0,102,255,0.1)}
nav a.active{color:var(--acc);background:rgba(0,102,255,0.08)}
.spacer{flex:1}.chip{font-size:12.5px;color:var(--mut);padding:4px 10px;
background:var(--glass);border-radius:20px;border:1px solid var(--line)}

/* ── main ── */
main{max-width:1100px;margin:30px auto;padding:0 20px;
animation:fadeUp .4s ease}
@keyframes fadeUp{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:none}}

/* ── cards ── */
.card{background:var(--card);backdrop-filter:blur(16px);
border:1px solid var(--line);border-radius:16px;
padding:22px 24px;margin-bottom:16px;transition:border-color .3s,box-shadow .3s}
.card:hover{border-color:rgba(0,102,255,0.25);
box-shadow:0 4px 24px rgba(0,102,255,0.06)}
.card.glass{background:rgba(15,20,32,0.7)}

/* ── stats row ── */
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:20px}
.stat{background:var(--glass);border:1px solid var(--line);border-radius:14px;
padding:16px 18px;text-align:center;transition:all .3s}
.stat:hover{border-color:rgba(0,102,255,0.3);transform:translateY(-2px)}
.stat .val{font-size:24px;font-weight:700;
background:linear-gradient(135deg,var(--acc),var(--orange));
-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.stat .lbl{font-size:12px;color:var(--mut);margin-top:4px;text-transform:uppercase;
letter-spacing:.5px}

/* ── typography ── */
h1{font-size:24px;margin:0 0 6px;font-weight:700}
h2{font-size:17px;margin:0 0 14px;font-weight:600;display:flex;align-items:center;gap:8px}
h2 .icon{font-size:18px}
.muted{color:var(--mut);font-size:13.5px}
a{color:var(--acc);text-decoration:none;transition:color .2s}
a:hover{color:var(--orange)}

/* ── forms ── */
label{display:block;margin:14px 0 5px;font-size:13px;color:var(--mut);font-weight:500}
label:first-child{margin-top:0}
input,select{width:100%;padding:10px 13px;background:rgba(10,14,24,0.8);
border:1px solid var(--line);border-radius:10px;color:var(--txt);font-size:14.5px;
transition:border-color .3s,box-shadow .3s}
input:focus,select:focus{outline:none;border-color:var(--acc);
box-shadow:0 0 0 3px rgba(0,102,255,0.15)}
input::placeholder{color:rgba(139,147,163,0.5)}

/* ── buttons ── */
.btn{display:inline-flex;align-items:center;gap:7px;padding:9px 16px;
border:1px solid var(--line);background:rgba(27,33,48,0.7);color:var(--txt);
border-radius:10px;cursor:pointer;font-size:13.5px;font-weight:500;
transition:all .25s;backdrop-filter:blur(4px)}
.btn:hover{border-color:rgba(0,102,255,0.4);background:rgba(0,102,255,0.08);
transform:translateY(-1px)}
.btn.primary{background:linear-gradient(135deg,var(--acc),var(--acc2));
border-color:transparent;color:#fff;
box-shadow:0 4px 16px rgba(0,102,255,0.25)}
.btn.primary:hover{box-shadow:0 6px 24px rgba(0,102,255,0.35);
background:linear-gradient(135deg,var(--acc),var(--acc2))}
.btn.orange{background:linear-gradient(135deg,var(--orange),#e68a00);
border-color:transparent;color:#fff;box-shadow:0 4px 16px rgba(255,153,0,0.2)}
.btn.orange:hover{box-shadow:0 6px 24px rgba(255,153,0,0.3)}
.btn.danger{background:rgba(42,21,32,0.8);border-color:#5b2437;color:#ff9aa8}
.btn.danger:hover{background:rgba(91,36,55,0.5)}
.btn.sm{padding:5px 12px;font-size:12.5px;border-radius:8px}
.btn[disabled]{opacity:.4;cursor:not-allowed;transform:none!important}

/* ── tables ── */
table{width:100%;border-collapse:collapse;font-size:13.5px}
th,td{text-align:left;padding:10px 12px;border-bottom:1px solid var(--line);vertical-align:middle}
th{color:var(--mut);font-weight:600;font-size:11.5px;text-transform:uppercase;
letter-spacing:.6px}
tr:hover td{background:rgba(0,102,255,0.03)}

/* ── badges ── */
.badge{display:inline-block;padding:3px 10px;border-radius:20px;font-size:12px;font-weight:600;
border:1px solid var(--line);transition:all .2s}
.badge.ok{color:var(--ok);border-color:rgba(52,211,153,0.3);background:rgba(52,211,153,0.08);display:inline-flex;align-items:center;gap:5px}.badge.ok::before{content:"";width:7px;height:7px;border-radius:50%;background:var(--ok);box-shadow:0 0 6px var(--ok);animation:pulse-dot 2s ease infinite}@keyframes pulse-dot{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.6;transform:scale(1.3)}}
.badge.off{color:var(--err);border-color:rgba(248,113,113,0.3);background:rgba(248,113,113,0.08);display:inline-flex;align-items:center;gap:5px}.badge.off::before{content:"";width:7px;height:7px;border-radius:50%;background:var(--err);box-shadow:0 0 6px var(--err)}
.badge.warn{color:var(--warn);border-color:rgba(251,191,36,0.3);background:rgba(251,191,36,0.08)}
.badge.role{color:var(--acc);border-color:rgba(0,102,255,0.3);background:rgba(0,102,255,0.08)}
.badge.superadmin{color:var(--orange);border-color:rgba(255,153,0,0.3);background:rgba(255,153,0,0.08)}

/* ── narrow card (login/signup) ── */
.narrow{max-width:440px;margin:8vh auto;padding:48px 36px;
background:var(--card);backdrop-filter:blur(20px);
border:1px solid var(--line);border-radius:20px;text-align:center;
box-shadow:0 8px 40px rgba(0,0,0,0.3);animation:fadeUp .5s ease}
.narrow h1{font-size:26px;margin-bottom:8px}
.narrow .subtitle{color:var(--mut);margin-bottom:24px;font-size:14px}
.narrow .logo-wrap svg{height:28px}
.narrow .logo-wrap{margin-bottom:20px}


/* ── responsive & glass ── */
@media(max-width:640px){
  nav{display:none}
  .narrow{max-width:100%!important;margin:0!important;padding:24px 16px!important}
  .card.glass{padding:14px!important}
  .grid3{grid-template-columns:1fr!important}
  .stats{grid-template-columns:repeat(3,1fr)!important}
  .stat .val{font-size:16px!important}
  table{font-size:12px}
  table th,table td{padding:6px 4px}
  .toolbar{flex-wrap:wrap;gap:6px!important}
  .toolbar input,.toolbar select,.toolbar button{min-width:0!important;flex:1 1 auto!important}
  .rowacts button{padding:4px 6px!important;font-size:11px!important}
  #searchUsers{min-width:100px!important}
}
@media(min-width:641px) and (max-width:1024px){
  .stats{grid-template-columns:repeat(3,1fr)}
}
.toolbar{display:flex;gap:8px;align-items:center;flex-wrap:wrap;padding:10px 0}
.toolbar select,.toolbar input{background:rgba(0,0,0,0.3);border:1px solid var(--line);color:inherit;border-radius:6px}
.toolbar input{padding:8px 10px}

/* ── password strength ── */
.pw-strength{margin-top:6px;height:4px;border-radius:2px;background:var(--line);overflow:hidden}
.pw-strength .bar{height:100%;width:0%;transition:all .3s;border-radius:2px}
.pw-strength .bar.weak{width:25%;background:var(--err)}
.pw-strength .bar.fair{width:50%;background:var(--warn)}
.pw-strength .bar.good{width:75%;background:#60a5fa}
.pw-strength .bar.strong{width:100%;background:var(--ok)}
.pw-strength-label{font-size:12px;margin-top:4px;font-weight:600}
.pw-strength-label.weak{color:var(--err)}
.pw-strength-label.fair{color:var(--warn)}
.pw-strength-label.good{color:#60a5fa}
.pw-strength-label.strong{color:var(--ok)}

/* ── log viewer ── */
pre.log{background:rgba(6,9,16,0.92);border:1px solid var(--line);
border-radius:10px;padding:12px 14px;overflow-x:auto;overflow-y:auto;
white-space:pre-wrap;word-break:break-word;word-wrap:break-word;
font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;
line-height:1.7;max-height:65vh;margin-top:8px;color:#c8d0e0;
scrollbar-width:thin;scrollbar-color:rgba(0,102,255,0.3) transparent}
pre.log::-webkit-scrollbar{width:8px;height:8px}
pre.log::-webkit-scrollbar-track{background:transparent}
pre.log::-webkit-scrollbar-thumb{background:rgba(0,102,255,0.3);border-radius:4px}
pre.log::-webkit-scrollbar-thumb:hover{background:rgba(0,102,255,0.5)}
pre.log .ok{color:var(--ok)}
pre.log .err{color:var(--err)}
pre.log span{white-space:pre-wrap;word-break:break-word}
@media(max-width:640px){
  pre.log{font-size:11px;padding:8px 10px;max-height:50vh}
}
.card.glass{backdrop-filter:blur(16px);transition:all .3s ease}
.card.glass:hover{border-color:rgba(0,102,255,0.3);box-shadow:0 4px 24px rgba(0,102,255,0.08)}
.user-row{transition:background .2s}
.user-row:hover{background:rgba(0,102,255,0.05)}
.user-row td{padding:10px 8px;vertical-align:middle}
.user-row td.muted{font-size:12px}
.rowacts{display:flex;gap:4px;flex-wrap:wrap}
.rowacts button{padding:4px 8px;font-size:11px}
.stat .val{transition:all .5s ease}
.stat:hover{transform:translateY(-2px)}
.stat:hover .val{transform:scale(1.05)}
.badge{padding:2px 8px;border-radius:10px;font-size:11px;font-weight:600;letter-spacing:.3px;transition:all .2s}
.badge:hover{transform:scale(1.05)}
@keyframes fadeUp{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:translateY(0)}}
.stat{animation:fadeUp .5s ease backwards;animation-delay:calc(var(--i,0) * 50ms)}
/* ── code / key ── */
code.k{display:block;background:rgba(6,9,16,0.9);border:1px solid rgba(0,102,255,0.2);
border-radius:10px;padding:12px 14px;font-family:ui-monospace,Menlo,Consolas,monospace;
font-size:13px;word-break:break-all;color:#9fe3c8;margin:8px 0;
transition:border-color .3s}
code.k:hover{border-color:rgba(0,102,255,0.5)}
.keybox{background:rgba(16,23,32,0.8);border:1px solid rgba(35,48,74,0.6);
border-radius:14px;padding:16px;margin-top:14px;
box-shadow:inset 0 1px 0 rgba(255,255,255,0.03)}
.keybox .copy-row{display:flex;gap:8px;align-items:center;margin-top:10px}

/* ── config block ── */
.config-block{background:rgba(6,9,16,0.95);border:1px solid rgba(0,102,255,0.15);
border-radius:12px;padding:18px;font-family:ui-monospace,Menlo,Consolas,monospace;
font-size:12.5px;line-height:1.7;color:#b9c2d0;overflow-x:auto;white-space:pre;
position:relative;transition:border-color .3s}
.config-block:hover{border-color:rgba(0,102,255,0.4)}
.config-block .copy-btn{position:absolute;top:8px;right:8px}

/* ── grid ── */
.grid{display:grid;gap:14px;grid-template-columns:repeat(auto-fit,minmax(240px,1fr))}
.grid2{display:grid;gap:14px;grid-template-columns:repeat(auto-fit,minmax(320px,1fr))}

/* ── misc ── */
.pre-scroll{background:rgba(6,9,16,0.8);border:1px solid var(--line);border-radius:12px;
padding:14px;max-height:400px;overflow:auto;font-size:12.5px;white-space:pre-wrap;
word-break:break-all;color:#b9c2d0;font-family:ui-monospace,Menlo,Consolas,monospace}
.tabs{display:flex;gap:6px;margin-bottom:16px;border-bottom:1px solid var(--line);padding-bottom:10px;position:relative}.tabs::after{content:"";position:absolute;bottom:-1px;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,var(--acc),var(--orange),transparent);opacity:.3}.tabs button{position:relative;overflow:hidden}.tabs button::before{content:"";position:absolute;inset:0;background:linear-gradient(135deg,rgba(0,102,255,0.1),rgba(255,153,0,0.05));opacity:0;transition:opacity .3s}.tabs button:hover::before{opacity:1}.tabs button.on::before{opacity:1}
.tabs button{background:none;border:1px solid transparent;color:var(--mut);
padding:6px 14px;border-radius:8px;cursor:pointer;font-size:13px;transition:all .2s}
.tabs button:hover{color:var(--txt);border-color:var(--line)}
.tabs button.on{background:rgba(0,102,255,0.1);border-color:rgba(0,102,255,0.3);color:var(--acc)}
.toolbar{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:14px}
.toolbar input,.toolbar select{width:auto;min-width:110px;padding:7px 10px}
#toast{position:fixed;right:20px;top:70px;z-index:99;display:flex;flex-direction:column;
gap:8px;max-width:380px;animation:fadeUp .3s ease}
.t{padding:12px 18px;border-radius:12px;font-size:14px;font-weight:500;
background:rgba(20,26,40,0.95);backdrop-filter:blur(12px);
border:1px solid rgba(44,58,85,0.5);box-shadow:0 8px 32px rgba(0,0,0,0.3);
animation:slideIn .3s ease}
.t.err{background:rgba(42,21,32,0.95);border-color:rgba(91,36,55,0.6)}
.t.ok{background:rgba(15,42,34,0.95);border-color:rgba(29,68,54,0.6)}
@keyframes slideIn{from{opacity:0;transform:translateX(20px)}to{opacity:1;transform:none}}
.ov{position:fixed;inset:0;background:rgba(0,0,0,0.7);display:flex;align-items:center;
justify-content:center;z-index:90;backdrop-filter:blur(4px)}
.ovc{background:rgba(22,26,34,0.95);border:1px solid var(--line);border-radius:18px;
padding:30px 40px;text-align:center;max-width:420px;
box-shadow:0 12px 48px rgba(0,0,0,0.4);animation:fadeUp .3s ease}
.spin{display:inline-block;width:28px;height:28px;border:3px solid rgba(51,64,92,0.5);
border-top-color:var(--acc);border-radius:50%;animation:sp 1s linear infinite;margin-bottom:14px}
@keyframes sp{to{transform:rotate(360deg)}}
.danger-zone{border:1px solid rgba(76,33,48,0.6);background:rgba(26,15,20,0.7)}
.rowacts{display:flex;gap:8px;flex-wrap:wrap}
.hidden{display:none!important}
.pulse{animation:pulse 2s ease infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.7}}
.gradient-text{background:linear-gradient(135deg,var(--acc),var(--orange));
-webkit-background-clip:text;-webkit-text-fill-color:transparent}

/* responsive */
@media(max-width:640px){
  header{padding:10px 16px}
  nav a{padding:6px 8px;font-size:12.5px}
  main{padding:0 14px;margin:20px auto}
  .narrow{margin:4vh auto;padding:32px 24px}
  .stats{grid-template-columns:repeat(2,1fr)}
}
</style>
<script>
const CSRF = "{{CSRF}}";
async function api(path, data){
  const opt = {method: data === undefined ? "GET" : "POST",
    headers: {"X-CSRF-Token": CSRF}};
  if(data !== undefined){ opt.headers["Content-Type"]="application/json";
    opt.body=JSON.stringify(data); }
  const r = await fetch(path, opt);
  let body = {}; try{ body = await r.json(); }catch(e){}
  return {ok:r.ok, status:r.status, body:body};
}
function sleep(ms){ return new Promise(r=>setTimeout(r,ms)); }
function esc(s){ return String(s==null?"":s).replace(/[&<>"']/g,
  c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c])); }
function toast(msg, isErr){
  const d=document.createElement("div");
  d.className="t "+(isErr?"err":"ok"); d.textContent=msg;
  document.getElementById("toast").appendChild(d);
  setTimeout(()=>d.remove(), isErr?7000:4000);
}
function ov(show, msg){
  const o=document.getElementById("ov");
  if(show){ document.getElementById("ovmsg").textContent=msg||"Working…";
    o.classList.remove("hidden"); }
  else o.classList.add("hidden");
}
async function runJob(id, msg){
  ov(true, msg || "Working — restarting the model server if keys changed…");
  try{
    for(let i=0;i<200;i++){
      const b = await api("/portal/api/job/"+id);
      if(b.body.state==="done") return b.body;
      if(b.body.state==="error") throw new Error(b.body.msg||"job failed");
      await sleep(1200);
    }
    throw new Error("job timed out");
  } finally { ov(false); }
}
function copyText(t){
  const done=()=>toast("copied to clipboard");
  if(navigator.clipboard && window.isSecureContext){
    navigator.clipboard.writeText(t).then(done).catch(()=>fallback(t));
  } else fallback(t);
  function fallback(x){
    const ta=document.createElement("textarea"); ta.value=x;
    document.body.appendChild(ta); ta.select();
    try{ document.execCommand("copy"); done(); }
    catch(e){ toast("copy failed — select manually", true); }
    ta.remove();
  }
}
function copyKey(btn){
  copyText(btn.parentElement.querySelector("code").textContent);
}
async function logout(){ await api("/portal/api/logout", {}); location="/portal/login"; }
function pwStrength(pw){
  let score = 0;
  if(pw.length >= 8) score++;
  if(pw.length >= 12) score++;
  if(/[a-z]/.test(pw) && /[A-Z]/.test(pw)) score++;
  if(/[0-9]/.test(pw)) score++;
  if(/[^a-zA-Z0-9]/.test(pw)) score++;
  if(score <= 1) return {cls:"weak", label:"Weak"};
  if(score === 2) return {cls:"fair", label:"Fair"};
  if(score === 3) return {cls:"good", label:"Good"};
  return {cls:"strong", label:"Strong"};
}
function updPw(inp, barId, labelId){
  const bar = document.getElementById(barId);
  const label = document.getElementById(labelId);
  if(!bar || !label) return;
  const s = pwStrength(inp.value);
  bar.className = "bar " + s.cls;
  label.className = "pw-strength-label " + s.cls;
  label.textContent = inp.value ? s.label : "";
}
</script></head>
<body>
<header>
  <a href="/" class="logo">
    <span class="logo-text" style="font-size:18px;font-weight:800;background:linear-gradient(90deg,var(--acc),var(--orange));-webkit-background-clip:text;-webkit-text-fill-color:transparent">{{PORTAL_NAME}}</span>
  </a>
  <nav>{{NAV}}</nav>
  <div class="spacer"></div>
  <span class="chip">{{USER_CHIP}}</span>
  {{LOGOUT_BTN}}
</header>
<main>{{BODY}}</main>
<div id="toast"></div>
<div id="ov" class="ov hidden"><div class="ovc">
  <div class="spin"></div><div id="ovmsg">Working…</div>
</div></div>
</body></html>"""


def page(title, body, user=None):
    if user:
        nav = ('<a href="/portal/dashboard">Dashboard</a>'
               '<a href="/portal/account">Account</a>'
               + ('<a href="/portal/admin">Admin</a>'
                  if user["role"] == "superadmin" else "")
               + '<span class="spacer"></span>')
        csrf = user["csrf"]
        chip = f'&#x1F464; {esc(user["username"])}'
        logout = '<button class="btn sm" onclick="logout()">Sign out</button>'
    else:
        nav = '<span class="spacer"></span>'
        csrf = ""
        chip = "Guest"
        logout = ""
    out = (BASE_TPL.replace("{{TITLE}}", esc(title))
                   .replace("{{PORTAL_NAME}}", esc(PORTAL_NAME))
                   .replace("{{PRIMARY_COLOR}}", PRIMARY_COLOR)
                   .replace("{{ACCENT_COLOR}}", ACCENT_COLOR)
                   .replace("{{DARK_COLOR}}", DARK_COLOR)
                   .replace("{{NAV}}", nav)
                   .replace("{{USER_CHIP}}", chip)
                   .replace("{{LOGOUT_BTN}}", logout)
                   .replace("{{CSRF}}", esc(csrf))
                   .replace("{{BODY}}", body))
    return out


def keybox_html(key, title="API key"):
    return (f'<div class="keybox"><b>{esc(title)}</b>'
            f'<code class="k">{esc(key or "(none)")}</code>'
            f'<button class="btn sm" onclick="copyKey(this)">Copy</button></div>')


# ---------------------------------------------------------------- pages
def login_page():
    body = f"""
<div class="narrow">
  <div class="logo-wrap"><span class="logo-text" style="font-size:16px;font-weight:700;background:linear-gradient(90deg,var(--acc),var(--orange));-webkit-background-clip:text;-webkit-text-fill-color:transparent">{{PORTAL_NAME}}</span></div>
  <h1>Sign in</h1>
  <p class="subtitle">Access your API keys and profile.</p>
  <form id="f">
    <label>Username</label>
    <input name="username" autocomplete="username" required autofocus placeholder="your username">
    <label>Password</label>
    <input name="password" type="password" autocomplete="current-password" required placeholder="••••••••">
    <p style="margin-top:20px"><button class="btn primary" style="width:100%">Sign in</button></p>
  </form>
  <p class="muted" style="margin-top:20px">{"No account? <a href=\"/portal/signup\">Sign up</a> to get your own API key."
                    if signup_open() else "Sign-up is currently closed — ask a superadmin."}</p>
</div>
<script>
document.getElementById("f").addEventListener("submit", async e => {{
  e.preventDefault();
  const d = Object.fromEntries(new FormData(e.target).entries());
  const r = await api("/portal/api/login", d);
  if(r.ok) location = "/portal/dashboard";
  else toast(r.body.error || ("login failed ("+r.status+")"), true);
}});
</script>"""
    return page("Sign in", body)


def signup_page():
    if not signup_open():
        body = ('<div class="narrow"><div class="logo-wrap">'
                '<img src="data:image/png;base64,' + open("tk_logo_b64.txt").read() + '" height="28"></div><h1>Sign-up closed</h1>'
                '<p class="muted">Self-registration is disabled. Ask a superadmin '
                'for an account. <a href="/portal/login">Sign in</a></p></div>')
        return page("Sign-up closed", body)
    body = """
<div class="narrow">
  <div class="logo-wrap"><span class="logo-text" style="font-size:16px;font-weight:700;background:linear-gradient(90deg,var(--acc),var(--orange));-webkit-background-clip:text;-webkit-text-fill-color:transparent">{{PORTAL_NAME}}</span></div>
  <h1>Create account</h1>
  <p class="subtitle">Get your own API key for the AI server.
  Works with /v1 endpoints and the Web UI instantly.</p>
  <form id="f">
    <label>Username (a-z, 0-9, - _)</label>
    <input name="username" pattern="[a-z][a-z0-9_-]{0,30}" required autofocus placeholder="your username">
    <label>Password</label>
    <input name="password" type="password" minlength="8" required placeholder="••••••••"
           id="signup_pw" oninput="updPw(this,'pwBar','pwLabel')">
    <div class="pw-strength"><div class="bar" id="pwBar"></div></div>
    <div class="pw-strength-label" id="pwLabel"></div>
    <label>Confirm password</label>
    <input name="confirm" type="password" minlength="8" required placeholder="••••••••">
    <p style="margin-top:20px"><button class="btn primary" style="width:100%">Sign up &amp; get API key</button></p>
  </form>
  <p class="muted" style="margin-top:20px">Already have an account? <a href="/portal/login">Sign in</a></p>
</div>
<div id="keyresult"></div>
<script>
document.getElementById("f").addEventListener("submit", async e => {
  e.preventDefault();
  const d = Object.fromEntries(new FormData(e.target).entries());
  if(d.password !== d.confirm){ toast("passwords do not match", true); return; }
  const r = await api("/portal/api/signup", d);
  if(!r.ok){ toast(r.body.error || ("signup failed ("+r.status+")"), true); return; }
  const jb = await runJob(r.body.job,
    "Creating your account and provisioning an API key (model server restart ~10-60 s)…");
  document.getElementById("keyresult").innerHTML =
    `<div class="narrow" style="margin-top:20px"><h1>Account ready &#9989;</h1>
     <p class="muted">Save this key now — you can always reveal it again after signing in.</p>
     ` + (jb.result && jb.result.key ? KEYBOX(jb.result.key) : "") + `
     <p style="margin-top:16px"><a class="btn primary" href="/portal/dashboard">Go to dashboard</a></p></div>`;
  e.target.closest("form").classList.add("hidden");
  document.querySelector(".narrow").classList.add("hidden");
  toast("account created", false);
});
function KEYBOX(k){
  return `<div class="keybox"><b>Your API key</b><code class="k">${esc(k)}</code>
          <button class="btn sm" onclick="copyKey(this)">Copy</button></div>`;
}
</script>"""
    return page("Sign up", body)


def dashboard_page(u, key_mask, created, activity):
    rows = ""
    for a in activity:
        rows += (f'<tr><td class="muted">{esc(a["ts"])}</td><td>{esc(a["req"])}</td>'
                 f'<td>{esc(a["type"])}</td>'
                 f'<td><span class="badge {"ok" if a["status"].startswith("2") else "off"}">'
                 f'{esc(a["status"])}</span></td><td class="muted">{esc(a["dur"])}</td>'
                 f'<td class="muted">{esc(a["ip"])}</td></tr>')
    if not rows:
        rows = '<tr><td colspan="6" class="muted">No API calls yet — hit /v1 with your key.</td></tr>'
    role_class = "superadmin" if u["role"] == "superadmin" else "role"
    body = """
<h1>Welcome, {{USER}} &#x1F44B;</h1>
<p class="muted">Portal account created {{CREATED}} &middot;
role <span class="badge {{ROLECLASS}}">{{ROLE}}</span></p>

<!-- Stats -->
<div class="stats">
  <div class="stat"><div class="val">{{KEYSTATUS}}</div><div class="lbl">API Key</div></div>
  <div class="stat"><div class="val">{{TOTALACT}}</div><div class="lbl">Total Calls</div></div>
  <div class="stat"><div class="val">{{APIDOMAIN}}</div><div class="lbl">API Domain</div></div>
  <div class="stat"><div class="val">{{MODEL}}</div><div class="lbl">Model</div></div>
</div>

<div class="grid2">
  <!-- API Key -->
  <div class="card">
    <h2><span class="icon">&#x1F511;</span> Your API key</h2>
    <code class="k" id="keyval">{{KEYMASK}}</code>
    <div class="rowacts">
      <button class="btn sm" id="revealBtn">&#x1F441; Reveal</button>
      <button class="btn sm" id="copyBtn">&#x1F4CB; Copy</button>
      <button class="btn sm" id="rotateBtn">&#x1F504; Rotate</button>
    </div>
    <div id="keybox"></div>
    <p class="muted" style="margin-top:10px">
      <code>Authorization: Bearer &lt;key&gt;</code> on <code>/v1/chat/completions</code> etc.
    </p>
  </div>

  <!-- OpenCode Config -->
  <div class="card glass">
    <h2><span class="icon">&#x1F916;</span> OpenCode config</h2>
    <p class="muted">Copy this JSON into your <code>opencode.json</code> to connect this AI server:</p>
    <div class="config-block" id="occonfig"><span class="pulse">Generating…</span></div>
    <div style="margin-top:10px">
      <button class="btn sm" onclick="copyOC()">&#x1F4CB; Copy config</button>
      <button class="btn sm" onclick="fetchOpenCode()">&#x1F504; Refresh</button>
    </div>
    <p class="muted" style="margin-top:10px">
      Paste into <code>~/.config/opencode/opencode.json</code> under providers → <code>llmportal</code>
    </p>
  </div>
</div>

<!-- Quick Connect -->
<div class="card">
  <h2><span class="icon">&#x26A1;</span> Quick connect</h2>
  <div class="grid2">
    <div>
      <p class="muted" style="margin-bottom:6px">API endpoint</p>
      <code class="k" style="cursor:pointer" onclick=&quot;copyText(this.textContent)&quot; title="click to copy">
        https://{{API_DOMAIN}}/v1
      </code>
    </div>
    <div>
      <p class="muted" style="margin-bottom:6px">Web UI</p>
      <a href="/" target="_blank" class="btn sm" style="display:inline-flex">
        &#x1F5A4; Open https://{{API_DOMAIN}}/
      </a>
    </div>
    <div>
      <p class="muted" style="margin-bottom:6px">Test with curl</p>
      <code class="k" style="font-size:12px;cursor:pointer" onclick=&quot;copyText(this.textContent)&quot;
            title="click to copy">curl https://{{API_DOMAIN}}/v1/models \\\n  -H "Authorization: Bearer YOUR_KEY"</code>
    </div>
  </div>
</div>

<!-- Activity -->
<div class="card">
  <h2><span class="icon">&#x1F4CA;</span> Recent API activity 
    <span class="muted" style="font-size:12px;font-weight:400">auto-refresh 15s &middot; updated <span id="actTime">—</span></span>
    <button class="btn sm" onclick="refreshAct()" style="margin-left:auto">&#x1F504;</button></h2>
  <table><thead><tr><th>Time</th><th>Request</th><th>Type</th><th>Status</th>
  <th>Duration</th><th>IP</th></tr></thead>
  <tbody id="actrows">{{ROWS}}</tbody></table>
</div>
<script>
const ocData = {};
document.getElementById("revealBtn").onclick = async () => {
  const r = await api("/portal/api/key");
  if(r.ok){ document.getElementById("keyval").textContent = r.body.key || "(none)"; }
  else toast(r.body.error || "reveal failed", true);
};
document.getElementById("copyBtn").onclick = () =>
  copyText(document.getElementById("keyval").textContent);
document.getElementById("rotateBtn").onclick = async () => {
  if(!confirm("Rotate key? The old key stops working immediately.")) return;
  const r = await api("/portal/api/key/rotate", {});
  if(!r.ok) return toast(r.body.error || "rotate failed", true);
  const jb = await runJob(r.body.job, "Rotating key (model server restart)…");
  document.getElementById("keyval").textContent = jb.result && jb.result.key ?
    jb.result.key : "(rotated)";
  document.getElementById("keybox").innerHTML =
    `<div class="keybox"><b>New key — save it now</b><code class="k">${
      esc(jb.result && jb.result.key ? jb.result.key : "")}</code>
     <button class="btn sm" onclick="copyKey(this)">Copy</button></div>`;
  toast("key rotated", false);
};
document.getElementById("copyKeyBtn")?.addEventListener("click", () =>
  copyText(document.getElementById("keyval").textContent));
async function refreshAct(){
  const r = await api("/portal/api/activity");
  if(!r.ok) return;
  const rows = (r.body.lines||[]).map(a =>
    `<tr><td class="muted">${esc(a.ts)}</td><td>${esc(a.req)}</td>
     <td>${esc(a.type)}</td>
     <td><span class="badge ${a.status.startsWith("2")?"ok":"off"}">${esc(a.status)}</span></td>
     <td class="muted">${esc(a.dur)}</td><td class="muted">${esc(a.ip)}</td></tr>`).join("");
  document.getElementById("actrows").innerHTML = rows ||
    '<tr><td colspan="6" class="muted">No API calls yet.</td></tr>';
}
async function fetchOpenCode(){
  try {
    const r = await api("/portal/api/opencode-config");
    if(!r.ok) return;
    ocData.key = r.body.api_key || "";
    ocData.model = r.body.model || "qwen3.6";
    ocData.alias = r.body.alias || "qwen3.6";
    document.getElementById("occonfig").textContent = JSON.stringify(r.body, null, 2);
  } catch(e){
    document.getElementById("occonfig").textContent = "error loading config";
  }
}
function copyOC(){
  if(ocData.key){
    copyText(JSON.stringify(ocData, null, 2));
    toast("config copied");
  } else {
    fetchOpenCode().then(()=>copyText(JSON.stringify(ocData, null, 2))).then(()=>toast("config copied"));
  }
}
window.addEventListener("load", () => fetchOpenCode());
// Auto-refresh activity feed every 15 seconds
setInterval(() => refreshAct(), 15000);
// Update activity timestamp
function updateActTime(){
  const el = document.getElementById("actTime");
  if(el) el.textContent = new Date().toLocaleTimeString();
}
setInterval(updateActTime, 15000);
updateActTime();
</script>"""
    body = (body.replace("{{USER}}", esc(u["username"]))
                .replace("{{CREATED}}", esc(created or "—"))
                .replace("{{ROLE}}", esc(u["role"]))
                .replace("{{ROLECLASS}}", role_class)
                .replace("{{KEYMASK}}", esc(key_mask))
                .replace("{{ROWS}}", rows)
                .replace("{{KEYSTATUS}}", "Active" if key_mask != "..." else "Hidden")
                .replace("{{TOTALACT}}", str(len(activity)))
                .replace("{{APIDOMAIN}}", "{{API_DOMAIN}}")
                .replace("{{MODEL}}", esc(u.get("model", _cfg.get("backend", "model", "default")))))
    return page("Dashboard", body, u)


def account_page(u, created):
    keynote = "<b>and revokes your API key</b>" if True else ""
    body = """
<div class="narrow" style="max-width:600px;margin:5vh auto">
  <div class="logo-wrap"><span class="logo-text" style="font-size:16px;font-weight:700;background:linear-gradient(90deg,var(--acc),var(--orange));-webkit-background-clip:text;-webkit-text-fill-color:transparent">{{PORTAL_NAME}}</span></div>
  <h1>Account</h1>
  <p class="subtitle">Manage your profile, password, and account status.</p>

  <div style="text-align:left;margin-bottom:20px">
    <div style="background:var(--glass);border:1px solid var(--line);border-radius:12px;padding:16px">
      <p style="margin:6px 0"><span class="muted">Username:</span> <b>{{USER}}</b></p>
      <p style="margin:6px 0"><span class="muted">Role:</span> <span class="badge {{ROLECLASS}}">{{ROLE}}</span></p>
      <p style="margin:6px 0"><span class="muted">Status:</span> <span class="badge ok">active</span></p>
      <p style="margin:6px 0"><span class="muted">Created:</span> <span class="muted">{{CREATED}}</span></p>
    </div>
    <p style="margin-top:12px"><button class="btn sm" onclick="logout()">&#x1F6AA; Sign out</button></p>
  </div>

  <div class="card" style="text-align:left">
    <h2>&#x1F511; Change password</h2>
    <form id="pwf" style="text-align:left">
      <label>Current password</label>
      <input name="old_password" type="password" autocomplete="current-password" required placeholder="••••••••">
      <label>New password (min 8)</label>
      <input name="new_password" type="password" minlength="8" required placeholder="••••••••"
             id="newpw" oninput="updPw(this,'acPwBar','acPwLabel')">
      <div class="pw-strength"><div class="bar" id="acPwBar"></div></div>
      <div class="pw-strength-label" id="acPwLabel"></div>
      <p style="margin-top:14px"><button class="btn primary">Update password</button></p>
    </form>
  </div>
</div>
<div class="card danger-zone" style="max-width:600px;margin:0 auto 20px;text-align:left">
  <h2>&#x1F6A8; Danger zone</h2>
  <p class="muted">Deleting your account removes your portal login {{KEYNOTE}}
  — this cannot be undone.</p>
  <div class="toolbar">
    <input id="delconfirm" placeholder="type your username to confirm">
    <button class="btn danger" id="delBtn">Delete my account</button>
  </div>
</div>
<script>
document.getElementById("pwf").addEventListener("submit", async e => {
  e.preventDefault();
  const d = Object.fromEntries(new FormData(e.target).entries());
  if(!d.new_password || d.new_password.length < 8) return toast("min 8 chars", true);
  const r = await api("/portal/api/password", d);
  if(r.ok){ toast("password updated", false); e.target.reset(); }
  else toast(r.body.error || "update failed", true);
});
document.getElementById("delBtn").onclick = async () => {
  const un = {{JSUSER}};
  if(document.getElementById("delconfirm").value !== un)
    return toast("type your exact username to confirm", true);
  if(!confirm("Permanently delete account "+un+" and revoke the API key?")) return;
  const r = await api("/portal/api/account/delete", {username: un});
  if(!r.ok) return toast(r.body.error || "delete failed", true);
  await runJob(r.body.job, "Deleting account and revoking key…");
  location = "/portal/login?deleted=1";
};
</script>"""
    role_class = "superadmin" if u["role"] == "superadmin" else "role"
    body = (body.replace("{{USER}}", esc(u["username"]))
                .replace("{{ROLE}}", esc(u["role"]))
                .replace("{{ROLECLASS}}", role_class)
                .replace("{{CREATED}}", esc(created or "—"))
                .replace("{{KEYNOTE}}", keynote)
                .replace("{{JSUSER}}", json.dumps(u["username"])))
    return page("Account", body, u)


def admin_page(u):
    body = """
<!-- Hero + Live Stats -->
<div class="card glass" style="padding:20px 24px;margin-bottom:16px;
  background:linear-gradient(135deg,rgba(0,26,255,0.12),rgba(255,153,0,0.06));
  border:1px solid rgba(0,102,255,0.2)">
  <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px">
    <div>
      <h1 style="margin:0;font-size:22px">Admin Console</h1>
      <p class="muted" style="margin:2px 0 0;font-size:13px">
        System overview &middot; auto-refresh 30s &middot; last update <span id="heroTime">—</span>
      </p>
    </div>
    <div style="display:flex;gap:16px;flex-wrap:wrap">
      <div class="hero-stat"><div class="hero-num" id="hCalls">0</div><div class="hero-lbl">API Calls (24h)</div></div>
      <div class="hero-stat"><div class="hero-num" id="hUsers">0</div><div class="hero-lbl">Total Users</div></div>
      <div class="hero-stat"><div class="hero-num" id="hActive">0</div><div class="hero-lbl">Active Users</div></div>
      <div class="hero-stat"><div class="hero-num" id="hPeak">0</div><div class="hero-lbl">Peak Hour</div></div>
    </div>
  </div>
</div>

<!-- Charts Row -->
<div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:14px" id="chartsRow">
  <div class="card glass">
    <h2>API Calls (last 24h)</h2>
    <div id="barChart" style="margin-top:10px"></div>
  </div>
  <div class="card glass">
    <h2>Top Users (24h)</h2>
    <div id="userBars" style="margin-top:10px"></div>
  </div>
</div>

<!-- Service Health + Activity -->
<div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:14px" id="healthRow">
  <div class="card glass">
    <h2>Service Health</h2>
    <div id="svcHealth" style="margin-top:10px"></div>
    <div style="margin-top:14px">
      <h2>Signup</h2>
      <div style="display:flex;gap:8px;align-items:center;margin-top:6px">
        <span id="suBadge" class="badge warn">checking</span>
        <button class="btn sm primary" id="suBtn">checking...</button>
      </div>
    </div>
  </div>
  <div class="card glass">
    <h2>Live Activity <span class="muted" style="font-size:11px;font-weight:400">auto 15s</span></h2>
    <div id="liveFeed" style="margin-top:8px;max-height:320px;overflow-y:auto;font-size:12px;line-height:1.8"></div>
  </div>
</div>

<!-- Tabs -->
<div class="tabs">
  <button class="btn sm on" data-t="users">Users</button>
  <button class="btn sm" data-t="logs">Logs</button>
  <button class="btn sm" data-t="system">System</button>
</div>

<!-- Users Tab -->
<div id="t-users">
  <div class="card glass" style="padding:14px 18px">
    <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap">
      <input id="searchUsers" placeholder="Search users..." style="flex:1;min-width:180px;padding:8px 12px" oninput="filterUsers()">
      <select id="filterRole" onchange="filterUsers()" style="padding:8px 10px;min-width:100px">
        <option value="all">All roles</option>
        <option value="user">user</option>
        <option value="superadmin">superadmin</option>
      </select>
      <select id="filterStatus" onchange="filterUsers()" style="padding:8px 10px;min-width:100px">
        <option value="all">All status</option>
        <option value="active">active</option>
        <option value="disabled">disabled</option>
      </select>
    </div>
  </div>

  <div class="card glass">
    <h2>Create user</h2>
    <form id="cuForm" class="grid3" style="gap:10px">
      <div><label>Username</label><input id="cu_name" pattern="[a-z][a-z0-9_-]{0,30}" required placeholder="e.g. newuser"></div>
      <div><label>Password</label><input id="cu_pass" type="password" minlength="8" required placeholder="min 8 chars" oninput="updPw(this,'cuPwBar','cuPwLabel')">
        <div class="pw-strength"><div class="bar" id="cuPwBar"></div></div>
        <div class="pw-strength-label" id="cuPwLabel"></div>
      </div>
      <div><label>Role</label><select id="cu_role"><option value="user">user</option><option value="superadmin">superadmin</option></select></div>
      <div style="display:flex;align-items:end"><button class="btn primary" style="width:100%">Create + API key</button></div>
    </form>
    <div id="createResult"></div>
  </div>

  <div class="card glass">
    <h2>All users
      <span class="muted" id="uCount"></span>
      <button class="btn sm" onclick="loadUsers()" style="margin-left:auto">Refresh</button>
    </h2>
    <div style="overflow-x:auto">
    <table id="usersTable">
      <thead><tr><th>User</th><th>Role</th><th>Status</th><th>API Key</th><th>Created</th><th>Actions</th></tr></thead>
      <tbody id="urows"><tr><td colspan="6" class="muted">Loading...</td></tr></tbody>
    </table>
    </div>
  </div>
  <div class="card glass" id="keyBoxCard" style="display:none"><h2>Key</h2><div id="keyOut"></div></div>
</div>

<!-- Logs Tab -->
<div id="t-logs" class="hidden">
  <div class="card glass">
    <div class="toolbar">
      <select id="logKind" style="padding:8px 10px">
        <option value="access">Access log</option>
        <option value="error">Error log</option>
        <option value="events">Events log</option>
        <option value="auth">Auth audit</option>
      </select>
      <input id="logUser" placeholder="filter by user">
      <input id="logN" type="number" value="150" min="10" max="500" style="width:80px;padding:8px 10px">
      <button class="btn sm primary" onclick="loadLogs()">Load</button>
      <span class="muted">newest first &middot; 7-day retention</span>
    </div>
    <pre class="log" id="logView">select a log and click Load</pre>
  </div>
</div>

<!-- System Tab -->
<div id="t-system" class="hidden">
  <div class="grid" style="grid-template-columns:repeat(auto-fit,minmax(240px,1fr))">
    <div class="card glass">
      <h2>Quick actions</h2>
      <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:8px">
        <button class="btn sm" onclick="loadSystem()">Refresh stats</button>
        <button class="btn sm" onclick="loadUsers()">Reload users</button>
        <button class="btn sm" onclick="loadAnalytics()">Reload charts</button>
      </div>
    </div>
    <div class="card glass">
      <h2>Log rotation</h2>
      <p class="muted">Logs rotate daily at 00:05, kept for 7 days.</p>
      <button class="btn sm" onclick="document.getElementById('logKind').value='events';loadLogs()">View events</button>
    </div>
  </div>
</div>

<style>
.hero-stat{text-align:center;min-width:80px}
.hero-num{font-size:28px;font-weight:800;
  background:linear-gradient(135deg,var(--acc),var(--orange));
  -webkit-background-clip:text;-webkit-text-fill-color:transparent}
.hero-lbl{font-size:11px;color:var(--mut);margin-top:2px}
.live-entry{padding:3px 0;border-bottom:1px solid var(--line);font-family:ui-monospace,Menlo,Consolas,monospace}
.live-entry .t{color:var(--mut)}
.live-entry .u{color:var(--acc);font-weight:600}
.live-entry .s{font-weight:600}
.live-entry .s.ok{color:var(--ok)}
.live-entry .s.err{color:var(--err)}
.svc-row{display:flex;align-items:center;gap:10px;padding:6px 0;border-bottom:1px solid var(--line)}
.svc-row:last-child{border-bottom:none}
.svc-dot{width:10px;height:10px;border-radius:50%;flex-shrink:0}
.svc-dot.ok{background:var(--ok);box-shadow:0 0 6px var(--ok)}
.svc-dot.err{background:var(--err);box-shadow:0 0 6px var(--err)}
.svc-dot.warn{background:var(--warn);box-shadow:0 0 6px var(--warn)}
.svc-name{flex:1;font-size:13px}
.svc-state{font-size:12px;font-weight:600}
.svc-state.ok{color:var(--ok)}
.svc-state.err{color:var(--err)}
@media(max-width:768px){
  #chartsRow{grid-template-columns:1fr!important}
  #healthRow{grid-template-columns:1fr!important}
  .hero-num{font-size:20px}
  #liveFeed{max-height:200px}
}
</style>

<script>
let SU_OPEN = false;
let allUsers = [];
let analyticsLoaded = false;

/* ── Tabs ── */
document.querySelectorAll(".tabs button").forEach(b => {
  b.onclick = () => {
    document.querySelectorAll(".tabs button").forEach(x => x.classList.remove("on"));
    b.classList.add("on");
    ["users","logs","system"].forEach(t =>
      document.getElementById("t-"+t).classList.toggle("hidden", t !== b.dataset.t));
    if(b.dataset.t === "users" && allUsers.length === 0) loadUsers();
    if(b.dataset.t === "logs") loadLogs();
    if(b.dataset.t === "system") loadSystem();
  };
});

/* ── Hero time ── */
function updateHeroTime(){
  const el = document.getElementById("heroTime");
  if(el) el.textContent = new Date().toLocaleTimeString();
}

/* ── Animated counter ── */
function animateNum(el, target, suffix){
  if(!el) return;
  const start = parseInt(el.textContent.replace(/\\D/g, "")) || 0;
  const diff = target - start;
  if(diff === 0){ el.textContent = target + (suffix||""); return; }
  const steps = 20;
  let i = 0;
  const timer = setInterval(() => {
    i++;
    const val = Math.round(start + diff * (i / steps));
    el.textContent = val + (suffix||"");
    if(i >= steps) clearInterval(timer);
  }, 25);
}

/* ── SVG Bar Chart ── */
function renderBarChart(hours){
  if(!hours || !hours.length) return;
  const w = 460, h = 160, pad = {top:10,right:10,bottom:24,left:36};
  const cw = w - pad.left - pad.right;
  const ch = h - pad.top - pad.bottom;
  const max = Math.max(...hours.map(x => x.n), 1);
  const bw = cw / hours.length;
  const svgParts = [];
  svgParts.push(`<svg viewBox="0 0 ${w} ${h}" style="width:100%;height:auto">`);
  // Grid lines
  for(let g = 0; g <= 4; g++){
    const y = pad.top + (ch / 4) * g;
    const val = Math.round(max - (max / 4) * g);
    svgParts.push(`<line x1="${pad.left}" y1="${y}" x2="${w-pad.right}" y2="${y}" stroke="rgba(255,255,255,0.06)"/>`);
    svgParts.push(`<text x="${pad.left-4}" y="${y+4}" text-anchor="end" fill="#8b93a3" font-size="9">${val}</text>`);
  }
  // Bars
  hours.forEach((d, i) => {
    const x = pad.left + i * bw;
    const bh = Math.max((d.n / max) * ch, 2);
    const y = pad.top + ch - bh;
    const barW = Math.max(bw - 2, 2);
    const hour = d.h.slice(11) + ":00";
    const isNow = i === hours.length - 1;
    svgParts.push(`<rect x="${x}" y="${y}" width="${barW}" height="${bh}" rx="2" 
      fill="${isNow ? "#FF9900" : "url(#gradBar)"}" opacity="${isNow ? 1 : 0.85}">
      <title>${hour}: ${d.n} calls</title></rect>`);
    // X labels (every 4th)
    if(i % 4 === 0 || isNow){
      svgParts.push(`<text x="${x+barW/2}" y="${h-4}" text-anchor="middle" fill="#8b93a3" font-size="8">${hour}</text>`);
    }
  });
  // Gradient def
  svgParts.push(`<defs><linearGradient id="gradBar" x1="0" y1="0" x2="0" y2="1">
    <stop offset="0%" stop-color="#0066ff"/>
    <stop offset="100%" stop-color="#001aff"/>
  </linearGradient></defs>`);
  svgParts.push("</svg>");
  document.getElementById("barChart").innerHTML = svgParts.join("");
}

/* ── SVG Horizontal Bars (Top Users) ── */
function renderUserBars(users){
  if(!users || !users.length){
    document.getElementById("userBars").innerHTML = "<p class='muted' style='font-size:13px'>No API calls yet</p>";
    return;
  }
  const max = Math.max(...users.map(x => x.calls), 1);
  const colors = ["#0066ff","#001aff","#FF9900","#34d399","#60a5fa","#f87171","#fbbf24","#a78bfa","#34d399","#fb923c"];
  const rows = users.map((u, i) => {
    const pct = Math.max((u.calls / max) * 100, 2);
    const color = colors[i % colors.length];
    return `<div style="margin-bottom:8px">
      <div style="display:flex;justify-content:space-between;font-size:12px;margin-bottom:3px">
        <span style="color:var(--txt);font-weight:500">${esc(u.user)}</span>
        <span class="muted">${u.calls}</span>
      </div>
      <div style="height:6px;background:rgba(255,255,255,0.05);border-radius:3px;overflow:hidden">
        <div style="height:100%;width:${pct}%;background:${color};border-radius:3px;
          transition:width .6s ease;box-shadow:0 0 4px ${color}40"></div>
      </div>
    </div>`;
  });
  document.getElementById("userBars").innerHTML = rows.join("");
}

/* ── Service Health ── */
const SVC_NAMES = {
  "llm-backend": "Inference Server",
  "llm-proxy": "Proxy",
  "llm-portal": "Portal",
  "rotate-logs.timer": "Log Rotation"
};
function renderSvcHealth(svc){
  const html = Object.entries(svc).map(([k, v]) => {
    const active = v === "active";
    const name = SVC_NAMES[k] || k;
    return `<div class="svc-row">
      <div class="svc-dot ${active ? "ok" : "err"}"></div>
      <div class="svc-name">${name}<div class="muted" style="font-size:11px">${esc(k)}</div></div>
      <div class="svc-state ${active ? "ok" : "err"}">${active ? "Active" : esc(v)}</div>
    </div>`;
  }).join("");
  document.getElementById("svcHealth").innerHTML = html;
}

/* ── Live Activity Feed ── */
async function loadLiveFeed(){
  try {
    const r = await api("/portal/api/admin/logs?kind=access&n=20");
    if(!r.ok) return;
    const lines = r.body.lines || [];
    const html = lines.map(l => {
      const parts = l.split("\t");
      const ts = parts[0] ? parts[0].slice(11, 19) : "";
      let user = "", path = "", status = "";
      parts.forEach(p => {
        if(p.startsWith("user=")) user = p.slice(5);
        else if(p.match(/^(GET|POST|PUT|DELETE) /)) path = p;
        else if(/^\\d{3}$/.test(p.trim())) status = p.trim();
      });
      const statusCls = status.startsWith("2") ? "ok" : "err";
      return `<div class="live-entry">
        <span class="t">${ts}</span>
        <span class="u">${esc(user)}</span>
        <span class="s ${statusCls}">${status}</span>
        <span style="color:var(--mut)">${esc(path.substring(0, 50))}</span>
      </div>`;
    });
    document.getElementById("liveFeed").innerHTML = html.join("") || "<p class='muted'>No activity</p>";
  } catch(e) {}
}

/* ── Analytics ── */
async function loadAnalytics(){
  try {
    const r = await api("/portal/api/admin/analytics");
    if(!r.ok) return;
    const d = r.body;
    animateNum(document.getElementById("hCalls"), d.total_calls || 0);
    animateNum(document.getElementById("hUsers"), d.total_users || 0);
    animateNum(document.getElementById("hActive"), d.active_users || 0);
    const peak = d.peak_hour;
    const peakEl = document.getElementById("hPeak");
    if(peakEl && peak && peak.h) peakEl.textContent = peak.h.slice(11) + ":00";
    renderBarChart(d.hours);
    renderUserBars(d.top_users);
    analyticsLoaded = true;
  } catch(e) {
    console.error("analytics error:", e);
  }
}

/* ── System / Signup ── */
async function loadSystem(){
  try {
    const r = await api("/portal/api/admin/services");
    if(!r.ok){ toast("Failed to load system info", true); return; }
    SU_OPEN = !!r.body.open_signup;
    const svc = r.body.services || {};
    renderSvcHealth(svc);
    const su = document.getElementById("suBadge");
    if(su){ su.textContent = SU_OPEN ? "OPEN" : "CLOSED"; su.className = "badge " + (SU_OPEN ? "ok" : "off"); }
    document.getElementById("suBtn").textContent = SU_OPEN ? "Close sign-up" : "Open sign-up";
    document.getElementById("suBtn").className = SU_OPEN ? "btn danger" : "btn primary";
  } catch(e) {
    console.error("loadSystem error:", e);
    toast("Error: " + e.message, true);
  }
}

/* ── Users ── */
function statusDot(s){
  return s === "active"
    ? "<span class='badge ok'>active</span>"
    : "<span class='badge off'>disabled</span>";
}
function keyBadge(u){
  if(u.key_state === "active") return "<span class='badge ok'>active</span>";
  if(u.key_state === "disabled") return "<span class='badge off'>disabled</span>";
  if(u.key_state === "missing") return "<span class='badge warn'>no key</span>";
  return "<span class='badge warn'>?</span>";
}
function filterUsers(){
  const q = document.getElementById("searchUsers").value.toLowerCase();
  const role = document.getElementById("filterRole").value;
  const status = document.getElementById("filterStatus").value;
  const filtered = allUsers.filter(u => {
    if(q && !u.username.includes(q)) return false;
    if(role !== "all" && u.role !== role) return false;
    if(status !== "all" && u.status !== status) return false;
    return true;
  });
  renderUsers(filtered);
}
function renderUsers(list){
  const rows = list.map(u => {
    if(!u.linked){
      return "<tr class='user-row'>"
        +"<td><b>"+esc(u.username)+"</b><div class='muted'>key-only (legacy)</div></td>"
        +"<td colspan='3' style='font-size:12px'>not linked — import below:<div style='margin-top:8px;display:flex;gap:6px;align-items:center;flex-wrap:wrap'>"
        +"<input id='imp_pw_"+esc(u.username)+"' type='password' placeholder='portal password' style='min-width:140px;padding:5px 8px;font-size:12px'>"
        +"<select id='imp_role_"+esc(u.username)+"' style='padding:5px 8px;font-size:12px'><option value='user'>user</option><option value='superadmin'>superadmin</option></select>"
        +"<button class='btn sm primary' onclick=&quot;importUser('"+esc(u.username)+"')&quot;>Import</button>"
        +"</div></td><td class='muted'>—</td>"
        +"<td class='rowacts'><button class='btn sm primary' onclick=&quot;importUser('"+esc(u.username)+"')&quot;>Import</button></td></tr>";
    }
    const roleSel = "<select onchange=&quot;setRole('"+esc(u.username)+"',this.value)&quot; style='padding:5px 8px;font-size:12px'>"
        +"<option value='user'"+(u.role==="user"?" selected":"")+">user</option>"
        +"<option value='superadmin'"+(u.role==="superadmin"?" selected":"")+">superadmin</option>"
        +"</select>";
    let acts = [];
    if(u.key_state !== "missing"){
      acts.push("<button class='btn sm' onclick=&quot;revealKey('"+esc(u.username)+"')&quot; title='Show key'>Show</button>");
      acts.push("<button class='btn sm' onclick=&quot;rotateKey('"+esc(u.username)+"')&quot; title='Rotate key'>Rotate</button>");
      acts.push("<button class='btn sm "+(u.status==="active"?"danger":"ok")+"' onclick=&quot;toggleStatus('"+esc(u.username)+"','"+(u.status==="active"?"disabled":"active")+"')&quot;>"+(u.status==="active"?"Disable":"Enable")+"</button>");
    } else {
      acts.push("<button class='btn sm primary' onclick=&quot;createKey('"+esc(u.username)+"')&quot; title='Provision key'>Provision</button>");
    }
    acts.push("<button class='btn sm' onclick=&quot;resetPw('"+esc(u.username)+"')&quot; title='Reset password'>Reset PW</button>");
    acts.push("<button class='btn sm danger' onclick=&quot;delUser('"+esc(u.username)+"')&quot; title='Delete user'>Delete</button>");
    return "<tr class='user-row'>"
      +"<td><b>"+esc(u.username)+"</b></td>"
      +"<td>"+roleSel+"</td>"
      +"<td>"+statusDot(u.status)+"</td>"
      +"<td>"+keyBadge(u)+" <span class='muted' style='font-size:11px'>"+esc(u.key_mask||"")+"</span></td>"
      +"<td class='muted' style='font-size:12px'>"+esc((u.created||"").slice(0,10))+"</td>"
      +"<td><div class='rowacts'>"+acts.join("")+"</div></td></tr>";
  }).join("");
  document.getElementById("urows").innerHTML = rows || "<tr><td colspan='6' class='muted'>no users</td></tr>";
  document.getElementById("uCount").textContent = "("+list.length+" shown)";
}
function showKey(title, key){
  document.getElementById("keyBoxCard").style.display = "";
  document.getElementById("keyOut").innerHTML =
    "<b>"+esc(title)+"</b><code class='k' style='cursor:pointer' onclick=&quot;copyText(this.textContent)&quot;>"+esc(key)+"</code>"
    +"<button class='btn sm' onclick=&quot;copyText(this.previousElementSibling.textContent)&quot;>Copy</button>";
}
async function loadUsers(){
  try {
    const r = await api("/portal/api/admin/users");
    if(!r.ok){ toast("Failed to load users", true); return; }
    allUsers = r.body.users || [];
    renderUsers(allUsers);
  } catch(e) {
    console.error("loadUsers error:", e);
    toast("Error: " + e.message, true);
  }
}

/* ── Logs ── */
async function loadLogs(){
  const kind = document.getElementById("logKind").value;
  const n = document.getElementById("logN").value || 150;
  const uf = document.getElementById("logUser").value.trim();
  const r = await api("/portal/api/admin/logs?kind="+encodeURIComponent(kind)+"&n="+encodeURIComponent(n)+"&user="+encodeURIComponent(uf));
  if(!r.ok){ toast(r.body.error || "cannot read log", true); return; }
  const lines = r.body.lines || [];
  const colored = lines.map((l,i) => {
    const typeClass = l.includes("result=ok") ? "ok" : l.includes("result=fail") ? "err" : "";
    return "<span style='color:#555;margin-right:12px;user-select:none'>"+String(i+1).padStart(4)+"</span><span class='"+typeClass+"'>"+esc(l)+"</span>";
  });
  document.getElementById("logView").innerHTML =
    (colored.length ? colored.join("\\n") : "(empty)") +
    "<div style='color:var(--mut);font-size:11px;margin-top:8px'>"+lines.length+" lines loaded</div>";
}

/* ── User Actions ── */
document.getElementById("cuForm").addEventListener("submit", async e => {
  e.preventDefault();
  const username = document.getElementById("cu_name").value.trim().toLowerCase();
  const password = document.getElementById("cu_pass").value;
  const role = document.getElementById("cu_role").value;
  const r = await api("/portal/api/admin/users", {username, password, role});
  if(!r.ok) return toast(r.body.error || "create failed", true);
  const jb = await runJob(r.body.job, "Creating user...");
  showKey("API key for " + username, jb.result && jb.result.key ? jb.result.key : "");
  document.getElementById("cuForm").reset();
  loadUsers();
  loadAnalytics();
  toast("user created", false);
});
async function importUser(un){
  const password = document.getElementById("imp_pw_"+un).value;
  const role = document.getElementById("imp_role_"+un).value;
  const r = await api("/portal/api/admin/import", {username:un, password, role});
  if(!r.ok) return toast(r.body.error || "import failed", true);
  toast("imported", false);
  loadUsers();
}
async function setRole(un, role){
  const r = await api("/portal/api/admin/role", {username:un, role});
  if(!r.ok){ toast(r.body.error || "role update failed", true); loadUsers(); }
  else toast("role updated", false);
}
async function toggleStatus(un, want){
  if(want==="disabled" && !confirm("Disable "+un+"?")) return;
  const r = await api("/portal/api/admin/user-status", {username:un, status:want});
  if(!r.ok) return toast(r.body.error || "status update failed", true);
  await runJob(r.body.job, (want==="disabled"?"Disabling":"Enabling")+" user...");
  toast("done", false);
  loadUsers();
  loadAnalytics();
}
async function rotateKey(un){
  if(!confirm("Rotate API key for "+un+"? Old key dies immediately.")) return;
  const r = await api("/portal/api/admin/key/rotate", {username:un});
  if(!r.ok) return toast(r.body.error || "rotate failed", true);
  const jb = await runJob(r.body.job, "Rotating key...");
  showKey("New API key for " + un, jb.result && jb.result.key ? jb.result.key : "");
  loadUsers();
}
async function revealKey(un){
  const r = await api("/portal/api/admin/key/reveal", {username:un});
  if(!r.ok) return toast(r.body.error || "reveal failed", true);
  showKey("API key for " + un, r.body.key || "");
}
async function resetPw(un){
  const pw = prompt("New portal password for "+un+" (min 8 chars):");
  if(!pw) return;
  const r = await api("/portal/api/admin/reset-password", {username:un, password:pw});
  if(!r.ok) return toast(r.body.error || "reset failed", true);
  toast("portal password reset", false);
}
async function createKey(un){
  const r = await api("/portal/api/admin/create-key", {username:un});
  if(!r.ok) return toast(r.body.error || "provision failed", true);
  const jb = await runJob(r.body.job, "Provisioning key...");
  showKey("API key for " + un, jb.result && jb.result.key ? jb.result.key : "");
  loadUsers();
}
async function delUser(un){
  const c = prompt("Type the username to confirm deletion of "+un+":");
  if(c !== un) return;
  const r = await api("/portal/api/admin/user-delete", {username:un});
  if(!r.ok) return toast(r.body.error || "delete failed", true);
  await runJob(r.body.job, "Deleting user + revoking key...");
  toast("user deleted", false);
  loadUsers();
  loadAnalytics();
}

document.getElementById("suBtn").onclick = async () => {
  const r = await api("/portal/api/admin/signup-toggle", {open: SU_OPEN ? 0 : 1});
  if(!r.ok) return toast(r.body.error || "toggle failed", true);
  toast("sign-up is now " + (r.body.open ? "OPEN" : "CLOSED"), false);
  loadSystem();
};

/* ── Init ── */
try { loadAnalytics(); } catch(e) { console.error(e); }
try { loadUsers(); } catch(e) { console.error(e); }
try { loadSystem(); } catch(e) { console.error(e); }
try { loadLiveFeed(); } catch(e) { console.error(e); }
setInterval(() => { try { loadAnalytics(); loadSystem(); } catch(e){} }, 30000);
setInterval(() => { try { loadLiveFeed(); } catch(e){} }, 15000);
setInterval(updateHeroTime, 1000);
updateHeroTime();
</script>"""
    return page("Admin", body, u)



# ================================================================ HTTP
class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "LLMPortal/1.0"

    def log_message(self, *a):   # access logging is done by the proxy
        pass

    # ---------- helpers ----------
    def _ip(self):
        xff = self.headers.get("X-Forwarded-For")
        return xff.strip() if xff else str(self.client_address[0])

    def _sec(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "same-origin")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; style-src 'unsafe-inline'; "
                         "script-src 'unsafe-inline'; img-src 'self' data:; "
                         "form-action 'self'")

    def _json(self, obj, code=200, extra=None):
        raw = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self._sec()
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(raw)

    def _html(self, s, code=200, extra=None):
        raw = s.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self._sec()
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(raw)

    def _redirect(self, loc, extra=None):
        self.send_response(302)
        self.send_header("Location", loc)
        self.send_header("Content-Length", "0")
        self._sec()
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n > 65536:
            raise ValueError("body too large")
        data = self.rfile.read(n) if n else b"{}"
        return json.loads(data or b"{}")

    def _need_auth(self, csrf=True):
        u = session_user(self.headers)
        if not u:
            self._json({"error": "unauthorized"}, 401)
            return None
        # CSRF only for state-changing (POST) calls of an authenticated session
        if csrf and self.headers.get("X-CSRF-Token", "") != u["csrf"]:
            self._json({"error": "CSRF token mismatch"}, 403)
            return None
        return u

    def _need_sa(self, csrf=True):
        u = self._need_auth(csrf=csrf)
        if u and u["role"] != "superadmin":
            self._json({"error": "superadmin only"}, 403)
            return None
        return u

    # ---------- GET ----------
    def do_GET(self):
        try:
            self.route_get()
        except (BrokenPipeError, ConnectionResetError):
            pass

    def route_get(self):
        u = urlparse(self.path)
        p = u.path.rstrip("/") or "/"
        qs = {k: v[0] for k, v in parse_qs(u.query).items()}

        if p == "/portal":
            self._redirect("/portal/dashboard" if session_user(self.headers)
                           else "/portal/login")
        elif p == "/portal/login":
            if session_user(self.headers):
                self._redirect("/portal/dashboard")
            else:
                self._html(login_page())
        elif p == "/portal/signup":
            self._html(signup_page())
        elif p == "/portal/dashboard":
            s = session_user(self.headers)
            if not s:
                self._redirect("/portal/login")
            else:
                self._html(self._dashboard(s))
        elif p == "/portal/account":
            s = session_user(self.headers)
            if not s:
                self._redirect("/portal/login")
            else:
                self._html(self._account(s))
        elif p == "/portal/admin":
            s = session_user(self.headers)
            if not s:
                self._redirect("/portal/login")
            elif s["role"] != "superadmin":
                self._html(page("Forbidden",
                                '<div class="card"><h1>403</h1>'
                                '<p class="muted">Superadmin only. '
                                '<a href="/portal/dashboard">back</a></p></div>', s))
            else:
                self._html(admin_page(s))
        # ----- JSON GETs -----
        elif p == "/portal/api/me":
            s = self._need_auth(csrf=False)
            if s:
                row = q("SELECT username,role,status,created_at FROM users WHERE id=?",
                        (s["id"],), one=True)
                k = parse_keyfile().get(s["username"], {})
                self._json({"username": row["username"], "role": row["role"],
                            "status": row["status"], "created": row["created_at"],
                            "key_mask": (k.get("key", "")[:18] + "…") if k.get("key") else ""})
        elif p == "/portal/api/key":
            s = self._need_auth(csrf=False)
            if s:
                k = parse_keyfile().get(s["username"])
                audit(s["username"], "key_view", self._ip(), "ok", "self reveal")
                self._json({"key": k["key"] if k else ""})
        elif p == "/portal/api/activity":
            s = self._need_auth(csrf=False)
            if s:
                self._json({"lines": own_activity(s["username"], 30)})
        elif p == "/portal/api/opencode-config":
            s = self._need_auth(csrf=False)
            if s:
                k = parse_keyfile().get(s["username"])
                # read model config from backend.env
                model = "qwen3.6"
                alias = "qwen3.6"
                ctx = 150000
                np = 5
                try:
                    for line in open(BACKEND_ENV):
                        line = line.strip()
                        if line.startswith("MODEL="):
                            v = line.split("=", 1)[1].strip().strip('"')
                            _m = {}  # model aliases from backend.env
                            model = _m.get(v, v)
                        elif line.startswith("ALIAS="):
                            alias = line.split("=", 1)[1].strip().strip('"')
                        elif line.startswith("CTX_PER_SLOT="):
                            ctx = int(line.split("=", 1)[1].strip())
                        elif line.startswith("NP="):
                            np = int(line.split("=", 1)[1].strip())
                except Exception:
                    pass
                config = {
                    "name": "{{PROVIDER_NAME}}",
                    "base_url": "https://{{API_DOMAIN}}/v1",
                    "api_key": k["key"] if k else "",
                    "api_key_mask": (k["key"][:18] + "…") if k and k.get("key") else "",
                    "models": [
                        {
                            "name": model,
                            "display_name": alias,
                            "context_window": ctx,
                            "concurrent_slots": np,
                        }
                    ],
                    "instructions": "Paste this under your opencode.json → providers section.",
                }
                self._json(config)
        elif p.startswith("/portal/api/job/"):
            jid = p.rsplit("/", 1)[-1]
            with _JOBS_LOCK:
                j = dict(JOBS.get(jid, {}))
            if not j:
                self._json({"state": "error", "msg": "unknown job"}, 404)
                return
            if j["actor"] == -1:     # signup job: pollable by its anonymous creator
                self._json({"state": j["state"], "msg": j["msg"],
                            "kind": j["kind"], "result": j["result"]})
                return
            s = self._need_auth(csrf=False)
            if not s:
                return
            if j["actor"] != s["id"] and s["role"] != "superadmin":
                self._json({"error": "forbidden"}, 403)
                return
            self._json({"state": j["state"], "msg": j["msg"],
                        "kind": j["kind"], "result": j["result"]})
        elif p == "/portal/api/admin/users":
            s = self._need_sa(csrf=False)
            if s:
                self._json({"users": self._merged_users()})
        elif p == "/portal/api/admin/logs":
            s = self._need_sa(csrf=False)
            if s:
                kind = qs.get("kind", "access")
                if kind not in LOG_FILES:
                    kind = "access"
                try:
                    n = max(10, min(500, int(qs.get("n", "150"))))
                except ValueError:
                    n = 150
                self._json({"lines": read_log(kind, n, qs.get("user", "").strip())})
        elif p == "/portal/api/admin/services":
            s = self._need_sa(csrf=False)
            if s:
                self._json({"services": services_state(),
                            "open_signup": signup_open()})
        elif p == "/portal/api/admin/analytics":
            s = self._need_sa(csrf=False)
            if s:
                import re as _re, time as _time
                from collections import Counter, defaultdict
                hourly = defaultdict(int)
                user_calls = Counter()
                status_codes = Counter()
                now = _time.time()
                cutoff = now - 86400
                try:
                    for line in open(ACCESSLOG, encoding="utf-8", errors="replace"):
                        parts = line.split("\t")
                        if len(parts) < 4: continue
                        ts_str = parts[0].strip()
                        try:
                            ts = _time.mktime(_time.strptime(ts_str[:19], "%Y-%m-%dT%H:%M:%S"))
                        except Exception:
                            continue
                        if ts < cutoff: continue
                        hour_key = ts_str[:13]  # YYYY-MM-DDTHH
                        hourly[hour_key] += 1
                        m = _re.search(r"user=(\S+)", line)
                        if m: user_calls[m.group(1)] += 1
                        m2 = _re.search(r"\t(\d{3})\t", line)
                        if m2: status_codes[m2.group(1)] += 1
                except FileNotFoundError:
                    pass
                # Build hourly array for last 24h
                hours = []
                for i in range(23, -1, -1):
                    t = now - i * 3600
                    key = _time.strftime("%Y-%m-%dT%H", _time.localtime(t))
                    hours.append({"h": key, "n": hourly.get(key, 0)})
                # User distribution
                users_list = [{"user": u, "calls": c} for u, c in user_calls.most_common(10)]
                # Status distribution
                status_list = [{"code": c, "n": n} for c, n in status_codes.most_common(10)]
                # User counts from DB
                total_users = q("SELECT COUNT(*) AS n FROM users", one=True)["n"]
                active_users = q("SELECT COUNT(*) AS n FROM users WHERE status='active'", one=True)["n"]
                # Total calls
                total_calls = sum(hourly.values())
                # Peak hour
                peak = max(hours, key=lambda x: x["n"]) if hours else {"h": "", "n": 0}
                self._json({
                    "hours": hours,
                    "top_users": users_list,
                    "statuses": status_list,
                    "total_calls": total_calls,
                    "peak_hour": peak,
                    "total_users": total_users,
                    "active_users": active_users,
                })
        else:
            self._json({"error": "not found"}, 404)

    # ---------- POST ----------
    def do_POST(self):
        try:
            self.route_post()
        except (BrokenPipeError, ConnectionResetError):
            pass
        except json.JSONDecodeError:
            self._json({"error": "invalid JSON body"}, 400)
        except ValueError as e:
            self._json({"error": str(e)}, 400)

    def route_post(self):
        u = urlparse(self.path)
        p = u.path.rstrip("/") or "/"
        ip = self._ip()
        body = self._body()

        # --- unauthenticated ---
        if p == "/portal/api/login":
            return self.api_login(body, ip)
        if p == "/portal/api/signup":
            return self.api_signup(body, ip)

        s = self._need_auth()
        if not s:
            return

        if p == "/portal/api/logout":
            q("DELETE FROM sessions WHERE token_hash=?", (s["token_hash"],))
            audit(s["username"], "logout", ip)
            self._json({"ok": True}, extra={"Set-Cookie":
                        f"{COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax"})
            return
        if p == "/portal/api/password":
            return self.api_password(body, s, ip)
        if p == "/portal/api/key/rotate":
            return self.api_key_rotate(body, s, ip)
        if p == "/portal/api/account/delete":
            return self.api_account_delete(body, s, ip)

        # --- superadmin ---
        if p in ("/portal/api/admin/users", "/portal/api/admin/role",
                 "/portal/api/admin/user-status", "/portal/api/admin/reset-password",
                 "/portal/api/admin/key/rotate", "/portal/api/admin/key/reveal",
                 "/portal/api/admin/user-delete", "/portal/api/admin/import",
                 "/portal/api/admin/create-key", "/portal/api/admin/signup-toggle"):
            return self.api_admin(p, body, s, ip)

        self._json({"error": "not found"}, 404)

    # ----- auth handlers -----
    def api_login(self, body, ip):
        un = str(body.get("username", "")).strip().lower()
        pw = str(body.get("password", ""))
        if not un:
            self._json({"error": "username required"}, 400)
            return
        rl = f"login:{un}:{ip}"
        if not rate_ok(rl):
            audit(un, "login", ip, "fail", "rate-limited")
            self._json({"error": "too many attempts — try again in 10 minutes"}, 429)
            return
        row = q("SELECT id,username,pw,role,status FROM users WHERE username=?",
                (un,), one=True)
        if not row:
            if un in parse_keyfile():
                audit(un, "login", ip, "fail", "not linked to portal")
                self._json({"error": "API-key user exists but has no portal login — "
                                     "ask a superadmin to import it"}, 401)
            else:
                audit(un, "login", ip, "fail", "unknown user")
                self._json({"error": "invalid username or password"}, 401)
            return
        if not verify_password(pw, row["pw"]):
            audit(un, "login", ip, "fail", "bad password")
            self._json({"error": "invalid username or password"}, 401)
            return
        if row["status"] != "active":
            audit(un, "login", ip, "fail", "account disabled")
            self._json({"error": "account disabled — contact an admin"}, 403)
            return
        rate_clear(rl)
        token, _ = create_session(row["id"])
        purge_expired_sessions()
        audit(un, "login", ip, "ok")
        self._json({"ok": True, "role": row["role"]}, extra={"Set-Cookie":
                    f"{COOKIE}={token}; Path=/; Max-Age={SESSION_SECS}; "
                    f"HttpOnly; SameSite=Lax"})

    def api_signup(self, body, ip):
        un = str(body.get("username", "")).strip().lower()
        pw = str(body.get("password", ""))
        if not valid_user(un):
            self._json({"error": "invalid username (a-z, 0-9, - _; starts with a "
                                 "letter; max 31 chars)"}, 400)
            return
        if not valid_pw(pw):
            self._json({"error": "password must be 8-200 characters"}, 400)
            return
        if not signup_open():
            audit(un, "signup", ip, "fail", "sign-up closed")
            self._json({"error": "self sign-up is closed"}, 403)
            return
        if q("SELECT 1 FROM users WHERE username=?", (un,), one=True):
            self._json({"error": "username already taken"}, 409)
            return
        if un in parse_keyfile():
            self._json({"error": "this username already has an API key — ask a "
                                 "superadmin to import it instead"}, 409)
            return
        pw_hash = hash_password(pw)

        def job():
            try:
                q("INSERT INTO users(username,pw,role,status,created_at,updated_at)"
                  " VALUES(?,?,?,?,?,?)",
                  (un, pw_hash, "user", "active", now_iso(), now_iso()))
            except sqlite3.IntegrityError:
                return {"ok": False, "msg": "username already taken"}
            rc, out, err = run_userctl(["add", un])
            if rc != 0:
                q("DELETE FROM users WHERE username=?", (un,))
                audit(un, "signup", ip, "fail", (err or out).strip()[:200])
                return {"ok": False, "msg": (err or out).strip() or "userctl failed"}
            key = (KEY_RE.search(out) or type("m", (), {"group": lambda *_: ""})()).group(0)
            audit(un, "signup", ip, "ok", "portal account + api key provisioned")
            return {"ok": True, "msg": "created", "result": {"key": key}}

        jid = submit_job("signup", -1, job)
        self._json({"ok": True, "job": jid}, 202)

    def api_password(self, body, s, ip):
        old = str(body.get("old_password", ""))
        new = str(body.get("new_password", ""))
        row = q("SELECT pw FROM users WHERE id=?", (s["id"],), one=True)
        if not verify_password(old, row["pw"]):
            audit(s["username"], "password_change", ip, "fail", "wrong current password")
            self._json({"error": "current password is wrong"}, 403)
            return
        if not valid_pw(new):
            self._json({"error": "new password must be 8-200 characters"}, 400)
            return
        q("UPDATE users SET pw=?, updated_at=? WHERE id=?",
          (hash_password(new), now_iso(), s["id"]))
        audit(s["username"], "password_change", ip, "ok")
        self._json({"ok": True})

    def api_key_rotate(self, body, s, ip):
        un = s["username"]
        keys = parse_keyfile()
        if un not in keys:
            self._json({"error": "you have no API key — contact an admin"}, 409)
            return

        def job():
            rc, out, err = run_userctl(["revoke", un])
            if rc != 0:
                audit(un, "key_rotate", ip, "fail", (err or out).strip()[:200])
                return {"ok": False, "msg": (err or out).strip() or "rotate failed"}
            key = (KEY_RE.search(out) or type("m", (), {"group": lambda *_: ""})()).group(0)
            audit(un, "key_rotate", ip, "ok", "self rotate")
            return {"ok": True, "msg": "key rotated", "result": {"key": key}}

        jid = submit_job("key_rotate", s["id"], job)
        self._json({"ok": True, "job": jid}, 202)

    def api_account_delete(self, body, s, ip):
        un = s["username"]
        if str(body.get("username", "")).strip().lower() != un:
            self._json({"error": "type your username to confirm"}, 400)
            return
        if un == str(body.get("username", "")) and s["role"] == "superadmin" \
                and count_superadmins() <= 1:
            self._json({"error": "you are the last superadmin — promote another "
                                 "one first"}, 400)
            return

        def job():
            keys = parse_keyfile()
            if un in keys:
                rc, out, err = run_userctl(["remove", un])
                if rc != 0:
                    audit(un, "account_delete", ip, "fail", (err or out).strip()[:200])
                    return {"ok": False, "msg": (err or out).strip() or "remove failed"}
            drop_sessions_for_user(s["id"])
            q("DELETE FROM users WHERE id=?", (s["id"],))
            audit(un, "account_delete", ip, "ok", "portal + api key removed")
            return {"ok": True, "msg": "account deleted"}

        jid = submit_job("account_delete", s["id"], job)
        self._json({"ok": True, "job": jid}, 202)

    # ----- superadmin handlers -----
    def _merged_users(self):
        keys = parse_keyfile()
        out = []
        linked = set()
        for r in q("SELECT username,role,status,created_at FROM users ORDER BY username"):
            k = keys.get(r["username"])
            linked.add(r["username"])
            out.append({
                "username": r["username"], "role": r["role"], "status": r["status"],
                "created": r["created_at"], "linked": True,
                "key_state": ("disabled" if k and k["disabled"]
                              else "active") if k else "missing",
                "key_mask": (k["key"][:18] + "…") if k and k["key"] else "",
            })
        for name, k in keys.items():          # legacy: key file only
            if name not in linked:
                out.append({"username": name, "role": None, "status": None,
                            "created": None, "linked": False,
                            "key_state": "disabled" if k["disabled"] else "active",
                            "key_mask": (k["key"][:18] + "…") if k["key"] else ""})
        return out

    def api_admin(self, p, body, s, ip):
        sa = self._need_sa()
        if not sa:
            return
        un = str(body.get("username", "")).strip().lower()
        actor = sa["username"]

        if p == "/portal/api/admin/signup-toggle":
            openv = "1" if str(body.get("open")) == "1" else "0"
            kv_set("open_signup", openv)
            audit(actor, "signup_toggle", ip, "ok", f"open={openv}")
            self._json({"ok": True, "open": openv == "1"})
            return

        if not valid_user(un):
            self._json({"error": "invalid username"}, 400)
            return

        if p == "/portal/api/admin/users":        # create portal user + key
            pw = str(body.get("password", ""))
            role = validate_role(body.get("role", "user"))
            if not valid_pw(pw):
                self._json({"error": "password must be 8-200 characters"}, 400)
                return
            if q("SELECT 1 FROM users WHERE username=?", (un,), one=True) or un in parse_keyfile():
                self._json({"error": "user already exists (portal or key file)"}, 409)
                return
            pw_hash = hash_password(pw)

            def job():
                try:
                    q("INSERT INTO users(username,pw,role,status,created_at,updated_at)"
                      " VALUES(?,?,?,?,?,?)",
                      (un, pw_hash, role, "active", now_iso(), now_iso()))
                except sqlite3.IntegrityError:
                    return {"ok": False, "msg": "username already taken"}
                rc, out, err = run_userctl(["add", un])
                if rc != 0:
                    q("DELETE FROM users WHERE username=?", (un,))
                    audit(actor, "user_create", ip, "fail", (err or out).strip()[:200])
                    return {"ok": False, "msg": (err or out).strip() or "userctl failed"}
                key = (KEY_RE.search(out) or type("m", (), {"group": lambda *_: ""})()).group(0)
                audit(actor, "user_create", ip, "ok", f"target={un} role={role}")
                return {"ok": True, "msg": "created", "result": {"key": key}}

            self._json({"ok": True, "job": submit_job("user_create", sa["id"], job)}, 202)
            return

        if p == "/portal/api/admin/import":       # link legacy key-only user
            pw = str(body.get("password", ""))
            role = validate_role(body.get("role", "user"))
            if not valid_pw(pw):
                self._json({"error": "password must be 8-200 characters"}, 400)
                return
            if un not in parse_keyfile():
                self._json({"error": "no API key exists for this username"}, 404)
                return
            if q("SELECT 1 FROM users WHERE username=?", (un,), one=True):
                self._json({"error": "already linked"}, 409)
                return
            key_status = "disabled" if parse_keyfile()[un]["disabled"] else "active"
            q("INSERT INTO users(username,pw,role,status,created_at,updated_at)"
              " VALUES(?,?,?,?,?,?)",
              (un, hash_password(pw), role, key_status, now_iso(), now_iso()))
            audit(actor, "user_import", ip, "ok", f"target={un} role={role}")
            self._json({"ok": True})
            return

        if p == "/portal/api/admin/role":
            role = validate_role(body.get("role", "user"))
            row = q("SELECT role FROM users WHERE username=?", (un,), one=True)
            if not row:
                self._json({"error": "no portal account for this user"}, 404)
                return
            if row["role"] == "superadmin" and role != "superadmin" \
                    and count_superadmins() <= 1:
                self._json({"error": "cannot demote the last superadmin"}, 400)
                return
            q("UPDATE users SET role=?, updated_at=? WHERE username=?",
              (role, now_iso(), un))
            drop_sessions_for_user(q("SELECT id FROM users WHERE username=?",
                                     (un,), one=True)["id"])   # force re-login
            audit(actor, "user_role", ip, "ok", f"target={un} role={role}")
            self._json({"ok": True})
            return

        if p == "/portal/api/admin/reset-password":
            pw = str(body.get("password", ""))
            if not valid_pw(pw):
                self._json({"error": "password must be 8-200 characters"}, 400)
                return
            row = q("SELECT id FROM users WHERE username=?", (un,), one=True)
            if not row:
                self._json({"error": "no portal account — import it first"}, 404)
                return
            q("UPDATE users SET pw=?, updated_at=? WHERE id=?",
              (hash_password(pw), now_iso(), row["id"]))
            drop_sessions_for_user(row["id"])
            audit(actor, "password_reset", ip, "ok", f"target={un}")
            self._json({"ok": True})
            return

        if p == "/portal/api/admin/key/reveal":
            k = parse_keyfile().get(un)
            if not k:
                self._json({"error": "no API key for this user"}, 404)
                return
            audit(actor, "key_reveal", ip, "ok", f"target={un}")
            self._json({"key": k["key"]})
            return

        if p == "/portal/api/admin/user-status":
            want = str(body.get("status", ""))
            if want not in ("active", "disabled"):
                self._json({"error": "status must be active|disabled"}, 400)
                return
            if want == "disabled" and un == actor:
                self._json({"error": "you cannot disable your own account"}, 400)
                return
            keys = parse_keyfile()
            if un not in keys and un not in {r["username"] for r in
                                             q("SELECT username FROM users")}:
                self._json({"error": "unknown user"}, 404)
                return

            def job():
                keys2 = parse_keyfile()
                if un in keys2:
                    cur = "disabled" if keys2[un]["disabled"] else "active"
                    if cur != want:
                        cmd = "disable" if want == "disabled" else "enable"
                        rc, out, err = run_userctl([cmd, un])
                        if rc != 0:
                            audit(actor, "user_status", ip, "fail",
                                  (err or out).strip()[:200])
                            return {"ok": False,
                                    "msg": (err or out).strip() or "failed"}
                q("UPDATE users SET status=?, updated_at=? WHERE username=?",
                  (want, now_iso(), un))
                if want == "disabled":
                    row = q("SELECT id FROM users WHERE username=?", (un,), one=True)
                    if row:
                        drop_sessions_for_user(row["id"])
                audit(actor, "user_status", ip, "ok", f"target={un} status={want}")
                return {"ok": True, "msg": f"{un} is now {want}"}

            self._json({"ok": True, "job": submit_job("user_status", sa["id"], job)}, 202)
            return

        if p == "/portal/api/admin/key/rotate":
            keys = parse_keyfile()
            if un not in keys:
                self._json({"error": "no API key for this user"}, 404)
                return

            def job():
                rc, out, err = run_userctl(["revoke", un])
                if rc != 0:
                    audit(actor, "key_rotate", ip, "fail", (err or out).strip()[:200])
                    return {"ok": False, "msg": (err or out).strip() or "failed"}
                key = (KEY_RE.search(out) or type("m", (), {"group": lambda *_: ""})()).group(0)
                audit(actor, "key_rotate", ip, "ok", f"target={un}")
                return {"ok": True, "msg": "rotated", "result": {"key": key}}

            self._json({"ok": True, "job": submit_job("key_rotate", sa["id"], job)}, 202)
            return

        if p == "/portal/api/admin/create-key":
            if un in parse_keyfile():
                self._json({"error": "key already exists"}, 409)
                return

            def job():
                rc, out, err = run_userctl(["add", un])
                if rc != 0:
                    audit(actor, "key_create", ip, "fail", (err or out).strip()[:200])
                    return {"ok": False, "msg": (err or out).strip() or "failed"}
                key = (KEY_RE.search(out) or type("m", (), {"group": lambda *_: ""})()).group(0)
                audit(actor, "key_create", ip, "ok", f"target={un}")
                return {"ok": True, "msg": "key provisioned", "result": {"key": key}}

            self._json({"ok": True, "job": submit_job("key_create", sa["id"], job)}, 202)
            return

        if p == "/portal/api/admin/user-delete":
            if un == actor:
                self._json({"error": "use Account → Delete my account instead"}, 400)
                return
            row = q("SELECT id,role FROM users WHERE username=?", (un,), one=True)
            in_keys = un in parse_keyfile()
            if not row and not in_keys:
                self._json({"error": "unknown user"}, 404)
                return
            if row and row["role"] == "superadmin" and count_superadmins() <= 1:
                self._json({"error": "cannot delete the last superadmin"}, 400)
                return

            def job():
                if un in parse_keyfile():
                    rc, out, err = run_userctl(["remove", un])
                    if rc != 0:
                        audit(actor, "user_delete", ip, "fail",
                              (err or out).strip()[:200])
                        return {"ok": False, "msg": (err or out).strip() or "failed"}
                if row:
                    drop_sessions_for_user(row["id"])
                    q("DELETE FROM users WHERE id=?", (row["id"],))
                audit(actor, "user_delete", ip, "ok", f"target={un}")
                return {"ok": True, "msg": "user deleted"}

            self._json({"ok": True, "job": submit_job("user_delete", sa["id"], job)}, 202)
            return

        self._json({"error": "not found"}, 404)

    # ---------- page data ----------
    def _dashboard(self, s):
        row = q("SELECT username,role,created_at FROM users WHERE id=?", (s["id"],), one=True)
        k = parse_keyfile().get(row["username"])
        mask = (k["key"][:18] + "…") if k and k["key"] else "(no API key yet)"
        # read model info from backend.env
        model = "qwen3.6"
        try:
            for line in open(BACKEND_ENV):
                line = line.strip()
                if line.startswith("MODEL="):
                    v = line.split("=", 1)[1].strip().strip('"')
                    _m = {}  # model aliases from backend.env
                    model = _m.get(v, v)
        except Exception:
            pass
        s["model"] = model
        return dashboard_page(s, mask, row["created_at"], own_activity(row["username"], 20))

    def _account(self, s):
        row = q("SELECT created_at FROM users WHERE id=?", (s["id"],), one=True)
        return account_page(s, row["created_at"] if row else "")


# ================================================================ CLI / main
def createsuperuser(name, pw):
    if not valid_user(name):
        print(f"error: invalid username '{name}'", file=sys.stderr)
        return 1
    if not valid_pw(pw):
        print("error: password must be 8-200 characters", file=sys.stderr)
        return 1
    existing = q("SELECT id,role FROM users WHERE username=?", (name,), one=True)
    if existing:
        q("UPDATE users SET pw=?, role='superadmin', status='active', updated_at=?"
          " WHERE id=?", (hash_password(pw), now_iso(), existing["id"]))
        drop_sessions_for_user(existing["id"])
        print(f"updated '{name}' -> superadmin (new password set)")
    else:
        q("INSERT INTO users(username,pw,role,status,created_at,updated_at)"
          " VALUES(?,?,?,?,?,?)",
          (name, hash_password(pw), "superadmin", "active", now_iso(), now_iso()))
        print(f"superadmin '{name}' created")
    # provision an API key too (unless one already exists)
    if name not in parse_keyfile():
        try:
            rc, out, err = run_userctl(["add", name])
            if rc == 0:
                m = KEY_RE.search(out)
                print(f"API key provisioned: {m.group(0) if m else '(see auth/api_keys.txt)'}")
            else:
                print(f"warning: could not provision API key: {(err or out).strip()}",
                      file=sys.stderr)
        except Exception as e:
            print(f"warning: userctl.sh failed: {e}", file=sys.stderr)
    audit(name, "bootstrap", "local", "ok", "createsuperuser")
    print("done.")
    return 0


def main():
    if len(sys.argv) >= 3 and sys.argv[1] == "createsuperuser":
        name = sys.argv[2]
        pw = os.environ.get("PORTAL_BOOTSTRAP_PASSWORD", "")
        if not pw:
            import getpass
            pw = getpass.getpass(f"password for superadmin '{name}': ")
            if pw != getpass.getpass("repeat: "):
                print("error: passwords do not match", file=sys.stderr)
                return 1
        return createsuperuser(name, pw)

    purge_expired_sessions()
    if not q("SELECT 1 FROM users WHERE role='superadmin' LIMIT 1", one=True):
        print("WARNING: no superadmin exists yet — create one with:\n"
              "  python3 -m llm_portal.app createsuperuser <name>", flush=True)
    os.makedirs(os.path.dirname(AUTHLOG), exist_ok=True)
    print(f"auth portal listening on http://{HOST}:{PORT}  (db={DB})", flush=True)
    srv = ThreadingHTTPServer((HOST, PORT), Handler)
    srv.daemon_threads = True
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("portal stopped")
    return 0


if __name__ == "__main__" or __package__ is None:
    sys.exit(main())
