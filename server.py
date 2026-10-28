"""tools-call-server: FastAPI backend for tools-call-collector uploads.

Ingests NDJSON batches (one JSON record per line, as appended by the plugin's
collector) into SQLite. Local-account login (admin/user roles) protects the
dashboard and stats API — regular users only see their own records; the ingest
endpoint stays open for collectors. A default admin SUPER_ADMIN / SUPER_ADMIN
is seeded on first start (empty users table) — change it after first login.

Windowed usage reports are emailed per user, plus a team aggregate (team
totals + per-person overview) to every admin with a configured mailbox:
scheduled weekly (previous ISO week) or daily (yesterday), or manually (last
7 days).
"""

import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import smtplib
import sqlite3
import sys
import threading
import time
from contextlib import asynccontextmanager, closing
from datetime import datetime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from pydantic import BaseModel
from starlette.middleware.sessions import SessionMiddleware

SERVER_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("TOOL_CALL_SERVER_DB", SERVER_DIR / "data" / "dashboard.db"))
DB_PATH.parent.mkdir(parents=True, exist_ok=True)


SESSION_MAX_AGE = 28800
try:
    SESSION_MAX_AGE = int(os.environ.get("SESSION_MAX_AGE", "28800"))
except ValueError:
    pass


def _load_session_secret():
    secret = os.environ.get("SESSION_SECRET", "")
    if secret:
        return secret
    path = SERVER_DIR / "data" / "session.secret"
    try:
        secret = path.read_text().strip() if path.exists() else ""
        if not secret:
            secret = secrets.token_urlsafe(48)
            fd = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(secret)
    except OSError:
        pass
    return secret


SESSION_SECRET = _load_session_secret()

# SMTP for report emails. No address is baked in: the admin fills the relay
# or Office 365 details in the GUI (stored in DB); env vars are fallback
# defaults and stay empty unless set. SMTP_SECURITY: starttls | ssl | none
SMTP_HOST = os.environ.get("SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "0"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
SMTP_SECURITY = os.environ.get("SMTP_SECURITY", "starttls")
# EHLO hostname passed to the relay; a fixed value avoids smtplib's
# getfqdn() DNS lookups that can hang on servers with broken reverse DNS
SMTP_EHLO_NAME = os.environ.get("SMTP_EHLO_NAME", "tools-call-server")


def get_smtp_config():
    # DB settings (admin GUI) override the env-var defaults; legacy smtp_from
    # rows (field removed) are ignored
    cfg = {"host": SMTP_HOST, "port": SMTP_PORT, "user": SMTP_USER,
           "password": SMTP_PASSWORD, "security": SMTP_SECURITY}
    with closing(connect()) as conn:
        for k, v in conn.execute("SELECT key, value FROM settings WHERE key LIKE 'smtp_%'"):
            key = k[len("smtp_"):]
            if key == "from":
                continue
            cfg[key] = int(v) if key == "port" and v.isdigit() else v
    return cfg


def set_smtp_settings(updates):
    with closing(connect()) as conn:
        for k, v in updates.items():
            conn.execute(
                "INSERT INTO settings (key, value) VALUES (?, ?)"
                " ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (f"smtp_{k}", str(v)),
            )
        conn.commit()


@asynccontextmanager
async def lifespan(app):
    seed_default_admin()
    threading.Thread(target=_report_scheduler, daemon=True).start()
    yield


app = FastAPI(title="tools-call-server", lifespan=lifespan,
              docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    max_age=SESSION_MAX_AGE,
    same_site="lax",
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    if request.url.path in ("/dashboard", "/v1/stats"):
        resp.headers["Cache-Control"] = "no-store"
    return resp

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    received_at TEXT NOT NULL,
    schema_version INTEGER,
    type TEXT,
    timestamp TEXT,
    client_id TEXT,
    user TEXT,
    session_id TEXT,
    prompt_id TEXT,
    project_dir TEXT,
    host TEXT,
    tool_name TEXT,
    status TEXT,
    input_keys TEXT,
    skill TEXT,
    skill_command TEXT,
    collector_name TEXT,
    collector_version TEXT,
    raw TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(type);
CREATE INDEX IF NOT EXISTS idx_events_tool ON events(tool_name);
CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE TABLE IF NOT EXISTS rejects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    received_at TEXT NOT NULL,
    raw TEXT NOT NULL,
    reason TEXT
);
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    email TEXT,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT
);
"""


def migrate(conn):
    """Add columns that post-date an existing database (idempotent)."""
    existing = {r[1] for r in conn.execute("PRAGMA table_info(events)")}
    if "client_id" not in existing:
        conn.execute("ALTER TABLE events ADD COLUMN client_id TEXT")
    if "user" not in existing:
        conn.execute("ALTER TABLE events ADD COLUMN user TEXT")
    ucols = {r[1] for r in conn.execute("PRAGMA table_info(users)")}
    if "email" not in ucols:
        conn.execute("ALTER TABLE users ADD COLUMN email TEXT")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_client ON events(client_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_user ON events(user)")


def connect():
    # WAL + busy_timeout: concurrent POSTs queue cleanly instead of erroring
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=10000")
    conn.executescript(SCHEMA)
    migrate(conn)
    return conn


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


INGEST_MAX_BYTES = 10_000_000


def row_from_record(record, raw):
    if not isinstance(record.get("type"), str) or not isinstance(record.get("timestamp"), str):
        raise ValueError("type and timestamp must be strings")
    collector = record.get("collector") or {}
    if not isinstance(collector, dict):
        collector = {}

    def _s(v):
        return v if isinstance(v, str) else None

    def _i(v):
        return v if isinstance(v, int) and not isinstance(v, bool) else None

    input_keys = record.get("input_keys")
    return (
        now_iso(),
        _i(record.get("schema_version")),
        _s(record.get("type")),
        _s(record.get("timestamp")),
        _s(record.get("client_id")),
        _s(record.get("user")),
        _s(record.get("session_id")),
        _s(record.get("prompt_id")),
        _s(record.get("project_dir")),
        _s(record.get("host")),
        _s(record.get("tool_name")),
        _s(record.get("status")),
        json.dumps(input_keys, ensure_ascii=False) if isinstance(input_keys, list) else None,
        _s(record.get("skill")),
        _s(record.get("skill_command")),
        _s(collector.get("name")),
        _s(collector.get("version")),
        raw,
    )


@app.get("/health")
def health():
    return {"status": "ok"}


def do_ingest(body):
    rows, rejects = [], []
    for line in body.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
            if not isinstance(record, dict):
                raise ValueError("record is not a JSON object")
            rows.append(row_from_record(record, line))
        except Exception as exc:
            rejects.append((now_iso(), line, f"{type(exc).__name__}: {exc}"))

    with closing(connect()) as conn:
        if rows:
            conn.executemany(
                "INSERT INTO events (received_at, schema_version, type, timestamp, client_id,"
                " user, session_id, prompt_id, project_dir, host, tool_name, status, input_keys, skill,"
                " skill_command, collector_name, collector_version, raw)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                rows,
            )
        if rejects:
            conn.executemany("INSERT INTO rejects (received_at, raw, reason) VALUES (?, ?, ?)", rejects)
        conn.commit()

    return {"accepted": len(rows), "rejected": len(rejects)}


@app.post("/v1/events")
async def ingest(request: Request):
    cl = request.headers.get("content-length", "")
    if cl.isdigit() and int(cl) > INGEST_MAX_BYTES:
        raise HTTPException(status_code=413, detail="body too large")
    body = (await request.body()).decode("utf-8", errors="replace")
    if not body.strip():
        raise HTTPException(status_code=400, detail="empty body")
    if len(body) > INGEST_MAX_BYTES:
        raise HTTPException(status_code=413, detail="body too large")
    return await run_in_threadpool(do_ingest, body)


@app.get("/v1/stats")
def stats(request: Request):
    user = current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="not authenticated")
    return compute_stats(None if user["role"] == "admin" else user["name"])


# ---- local accounts ----

PBKDF2_ITERATIONS = 600_000


class LoginBody(BaseModel):
    username: str
    password: str


class PasswordBody(BaseModel):
    old_password: str
    new_password: str


class NewUserBody(BaseModel):
    username: str
    password: str
    role: str = "user"


class RoleBody(BaseModel):
    role: str


class RenameBody(BaseModel):
    username: str


class ResetPasswordBody(BaseModel):
    password: str


def hash_password(password):
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt.hex()}${digest.hex()}"


def verify_password(password, stored):
    try:
        algo, iters, salt_hex, hash_hex = stored.split("$")
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), int(iters))
        return algo == "pbkdf2_sha256" and hmac.compare_digest(digest.hex(), hash_hex)
    except (ValueError, TypeError):
        return False


def get_user(username):
    with closing(connect()) as conn:
        conn.row_factory = sqlite3.Row
        return conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()


def _check_username(name):
    if not name or len(name) > 64 or any(ord(c) < 32 for c in name):
        raise HTTPException(status_code=400, detail="用户名长度需 1-64 字符且不含控制字符")


def _rename_user(old_name, new_name):
    # Rename the account and migrate its historical event records in one
    # transaction so the login identity stays linked to its data
    row = get_user(old_name)
    if not row:
        raise HTTPException(status_code=404, detail="用户不存在")
    try:
        with closing(connect()) as conn:
            conn.execute("UPDATE users SET username = ? WHERE username = ?", (new_name, old_name))
            conn.execute("UPDATE events SET user = ? WHERE user = ?", (new_name, old_name))
            conn.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="用户名已存在")
    return row


_DUMMY_HASH = None


def _dummy_hash():
    # Precomputed once: equalizes PBKDF2 cost between "unknown user" and
    # "wrong password" logins so response timing cannot enumerate usernames
    global _DUMMY_HASH
    if _DUMMY_HASH is None:
        _DUMMY_HASH = hash_password("timing-equalizer")
    return _DUMMY_HASH


def current_user(request: Request):
    # Revalidate the session against the DB on every guarded request so role
    # changes and account deletions take effect immediately
    sess = request.session.get("user")
    if not sess:
        return None
    row = get_user(sess["name"])
    if not row:
        request.session.clear()
        return None
    return {"name": row["username"], "role": row["role"]}


def require_user(request: Request):
    user = current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="not authenticated")
    return user


def require_admin(user: dict = Depends(require_user)):
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="需要管理员权限")
    return user


@app.get("/login", response_class=HTMLResponse)
def login_page():
    return LOGIN_PATH.read_text(encoding="utf-8")


@app.post("/login")
def login(body: LoginBody, request: Request):
    username = body.username.strip()
    _check_username(username)
    if len(body.password) > 1024:
        raise HTTPException(status_code=400, detail="密码过长")
    row = get_user(username)
    if not row:
        verify_password(body.password, _dummy_hash())
    if not row or not verify_password(body.password, row["password_hash"]):
        raise HTTPException(status_code=401, detail="用户名或密码错误")
    request.session["user"] = {"name": username, "role": row["role"]}
    return {"ok": True}


@app.post("/logout")
def logout(request: Request):
    request.session.clear()
    return {"ok": True}


@app.post("/me/password")
def change_my_password(body: PasswordBody, user: dict = Depends(require_user)):
    if len(body.new_password) < 8:
        raise HTTPException(status_code=400, detail="新密码至少 8 位")
    if body.new_password == body.old_password:
        raise HTTPException(status_code=400, detail="新密码不能与旧密码相同")
    row = get_user(user["name"])
    if not row or not verify_password(body.old_password, row["password_hash"]):
        raise HTTPException(status_code=400, detail="旧密码错误")
    with closing(connect()) as conn:
        conn.execute(
            "UPDATE users SET password_hash = ? WHERE username = ?",
            (hash_password(body.new_password), user["name"]),
        )
        conn.commit()
    return {"ok": True}


@app.get("/admin/users")
def admin_list_users(user: dict = Depends(require_admin)):
    with closing(connect()) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT username, role, email, created_at FROM users ORDER BY username"
        ).fetchall()
    return {"users": [dict(r) for r in rows]}


@app.post("/admin/users")
def admin_create_user(body: NewUserBody, user: dict = Depends(require_admin)):
    username = body.username.strip()
    _check_username(username)
    if len(body.password) < 8 or len(body.password) > 1024:
        raise HTTPException(status_code=400, detail="密码长度需 8-1024 位")
    if body.role not in ("admin", "user"):
        raise HTTPException(status_code=400, detail="role 必须是 admin 或 user")
    try:
        with closing(connect()) as conn:
            conn.execute(
                "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
                (username, hash_password(body.password), body.role, now_iso()),
            )
            conn.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="用户已存在")
    return {"ok": True}


@app.post("/admin/users/{username}/password")
def admin_reset_password(username: str, body: ResetPasswordBody, user: dict = Depends(require_admin)):
    if len(body.password) < 8 or len(body.password) > 1024:
        raise HTTPException(status_code=400, detail="密码长度需 8-1024 位")
    with closing(connect()) as conn:
        cur = conn.execute(
            "UPDATE users SET password_hash = ? WHERE username = ?",
            (hash_password(body.password), username),
        )
        conn.commit()
    if cur.rowcount == 0:
        raise HTTPException(status_code=404, detail="用户不存在")
    return {"ok": True}


@app.post("/admin/users/{username}/role")
def admin_set_role(username: str, body: RoleBody, user: dict = Depends(require_admin)):
    if body.role not in ("admin", "user"):
        raise HTTPException(status_code=400, detail="role 必须是 admin 或 user")
    if username == user["name"]:
        raise HTTPException(status_code=400, detail="不能修改自己的角色")
    row = get_user(username)
    if not row:
        raise HTTPException(status_code=404, detail="用户不存在")
    if body.role == "user" and row["role"] == "admin":
        with closing(connect()) as conn:
            admins = conn.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'").fetchone()[0]
        if admins <= 1:
            raise HTTPException(status_code=400, detail="不能降级最后一名管理员")
    with closing(connect()) as conn:
        cur = conn.execute("UPDATE users SET role = ? WHERE username = ?", (body.role, username))
        conn.commit()
    if cur.rowcount == 0:
        raise HTTPException(status_code=404, detail="用户不存在")
    return {"ok": True}


@app.post("/admin/users/{username}/rename")
def admin_rename_user(username: str, body: RenameBody, request: Request, user: dict = Depends(require_admin)):
    new_name = body.username.strip()
    _check_username(new_name)
    if new_name == username:
        return {"ok": True}
    row = _rename_user(username, new_name)
    if username == user["name"]:
        request.session["user"] = {"name": new_name, "role": row["role"]}
    return {"ok": True}


@app.post("/admin/users/{username}/delete")
def admin_delete_user(username: str, user: dict = Depends(require_admin)):
    if username == user["name"]:
        raise HTTPException(status_code=400, detail="不能删除自己")
    row = get_user(username)
    if not row:
        raise HTTPException(status_code=404, detail="用户不存在")
    if row["role"] == "admin":
        with closing(connect()) as conn:
            admins = conn.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'").fetchone()[0]
        if admins <= 1:
            raise HTTPException(status_code=400, detail="不能删除最后一名管理员")
    with closing(connect()) as conn:
        conn.execute("DELETE FROM users WHERE username = ?", (username,))
        conn.commit()
    return {"ok": True}


# ---- email reports ----

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def esc_html(s):
    return (str(s if s is not None else "")
            .replace("&", "\u0026amp;").replace("<", "\u0026lt;").replace(">", "\u0026gt;"))


log = logging.getLogger("uvicorn.error")


def send_html_mail(to, subject, html):
    cfg = get_smtp_config()
    port = cfg["port"] or 25
    log.info("SMTP send: to=%s host=%s port=%s security=%s ehlo=%s user=%s password_set=%s",
             to, cfg["host"], port, cfg["security"], SMTP_EHLO_NAME, cfg["user"], bool(cfg["password"]))
    if not cfg["host"] or not cfg["user"]:
        log.warning("SMTP not configured: host=%r user=%r", cfg["host"], cfg["user"])
        raise RuntimeError("SMTP 未配置：请填写服务器与账号后保存，再发送")
    msg = MIMEMultipart("alternative")
    msg["From"] = cfg["user"]
    msg["To"] = to
    msg["Subject"] = subject
    msg.attach(MIMEText(html, "html", "utf-8"))
    t0 = time.monotonic()
    try:
        if cfg["security"] == "ssl":
            s = smtplib.SMTP_SSL(cfg["host"], port, timeout=30, local_hostname=SMTP_EHLO_NAME or None)
        else:
            s = smtplib.SMTP(cfg["host"], port, timeout=30, local_hostname=SMTP_EHLO_NAME or None)
    except Exception as exc:
        log.error("SMTP connect FAILED after %.1fs: %s: %s",
                  time.monotonic() - t0, type(exc).__name__, exc)
        raise
    log.info("SMTP connected in %.1fs", time.monotonic() - t0)
    with s:
        s.set_debuglevel(1)
        s.ehlo()
        if cfg["security"] == "starttls":
            s.starttls()
            s.ehlo()
        if cfg["password"]:
            # Only authenticate when the server actually offers AUTH — relays
            # trusted by source IP don't, and a stale stored password must not
            # break those sends
            if "auth" in s.esmtp_features:
                s.login(cfg["user"], cfg["user"])
            else:
                log.info("server has no AUTH extension; skipping login")
        s.send_message(msg)
        log.info("SMTP send OK in %.1fs total", time.monotonic() - t0)


def _report_bar(n, maxn, color="#3b7ddd"):
    pct = round(n / maxn * 100) if maxn else 0
    return ('<table cellpadding="0" cellspacing="0" style="width:120px;border-collapse:collapse">'
            '<tr><td style="background:#e5e7eb;height:8px;padding:0;border-radius:4px">'
            f'<table cellpadding="0" cellspacing="0" style="width:{pct}%;border-collapse:collapse">'
            f'<tr><td style="background:{color};height:8px;padding:0;border-radius:4px;'
            'font-size:0;line-height:0">&nbsp;</td></tr></table>'
            '</td></tr></table>')


def _report_rows(rows, color):
    if not rows:
        return '<div style="color:#9ca3af;padding:8px 0">暂无数据</div>'
    maxn = max(r["n"] for r in rows) or 1
    total = sum(r["n"] for r in rows) or 1
    th = 'style="padding:8px 10px;background:#f7f8fa;color:#4b5563;border-bottom:1px solid #e5e7eb;text-align:left"'
    td = 'style="padding:8px 10px;border-bottom:1px solid #f0f1f3;vertical-align:middle"'
    h = f'<table cellpadding="0" cellspacing="0" style="width:100%;border-collapse:collapse;font-size:13px">'
    h += f'<tr><th {th}>名称</th><th {th} align="right">次数</th><th {th} align="right">占比</th><th {th}></th></tr>'
    for r in rows:
        h += (f'<tr><td {td}>{esc_html(r["name"])}</td>'
              f'<td {td} align="right" style="padding:8px 10px;border-bottom:1px solid #f0f1f3;'
              f'font-variant-numeric:tabular-nums">{r["n"]}</td>'
              f'<td {td} align="right" style="padding:8px 10px;border-bottom:1px solid #f0f1f3;color:#6b7280">'
              f'{r["n"] / total * 100:.1f}%</td>'
              f'<td {td}>{_report_bar(r["n"], maxn, color)}</td></tr>')
    return h + "</table>"


def _iso_utc(dt):
    # Local datetime -> UTC ISO string in the same format as events.timestamp,
    # so lexicographic comparison in SQL matches chronological order
    return dt.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _report_window(mode):
    """Window for a report run: UTC boundaries plus display labels.

    weekly: the previous complete ISO week (Mon 00:00 to next Mon 00:00, local)
    daily:  yesterday (local time)
    manual: the last 7 days ending now
    """
    local = datetime.now().astimezone()
    if mode == "weekly":
        end = (local - timedelta(days=local.weekday())).replace(hour=0, minute=0, second=0, microsecond=0)
        start = end - timedelta(days=7)
        iso = start.isocalendar()
        subject = f"{iso[0]}-W{iso[1]} ({start:%m-%d} ~ {end - timedelta(days=1):%m-%d})"
        meta = f"{start:%Y-%m-%d} ~ {end - timedelta(days=1):%Y-%m-%d}（7 天）"
        kind = "周报"
    elif mode == "daily":
        end = local.replace(hour=0, minute=0, second=0, microsecond=0)
        start = end - timedelta(days=1)
        subject = f"{start:%m-%d}"
        meta = f"{start:%Y-%m-%d}（1 天）"
        kind = "日报"
    else:  # manual
        end = local
        start = end - timedelta(days=7)
        subject = f"最近 7 天 ({start:%m-%d} ~ {end:%m-%d})"
        meta = f"最近 7 天（{start:%Y-%m-%d} ~ {end:%Y-%m-%d}）"
        kind = "报告"
    return {"kind": kind, "subject": subject, "meta": meta,
            "start": _iso_utc(start), "end": _iso_utc(end),
            # zero-use skills: no call within the 14 days before the window end
            "lookback_start": _iso_utc(end - timedelta(days=14))}


def _mcp_server_of(tool_name):
    # MCP tool calls are named mcp__<server>__<tool>; anything else is builtin
    if not tool_name or not tool_name.startswith("mcp__"):
        return None
    parts = tool_name.split("__", 2)
    return parts[1] if len(parts) == 3 else None


def _project_name_of(project_dir):
    return (project_dir or "").rstrip("/").split("/")[-1] or "<unknown>"


def _idle_skills(conn, flt, args, end, since):
    """Skills used before `end` but with zero calls in [since, end)."""
    ever = conn.execute(
        "SELECT skill, MAX(timestamp) AS last FROM events"
        f" WHERE type = 'skill_invoke' AND skill IS NOT NULL{flt} AND timestamp < ? GROUP BY skill",
        args + [end],
    ).fetchall()
    recent = {r[0] for r in conn.execute(
        "SELECT skill FROM events WHERE type = 'skill_invoke' AND skill IS NOT NULL"
        f"{flt} AND timestamp >= ? AND timestamp < ? GROUP BY skill",
        args + [since, end],
    )}
    return sorted(({"name": r["skill"], "last": r["last"]} for r in ever if r["skill"] not in recent),
                  key=lambda s: s["last"] or "")


def _idle_mcp(conn, flt, args, end, since):
    """MCP servers used before `end` but with zero calls in [since, end)."""
    ever = {}
    for r in conn.execute(
        "SELECT tool_name, MAX(timestamp) AS last FROM events"
        f" WHERE substr(tool_name, 1, 5) = 'mcp__'{flt} AND timestamp < ? GROUP BY tool_name",
        args + [end],
    ):
        server = _mcp_server_of(r["tool_name"])
        if server and (server not in ever or r["last"] > ever[server]):
            ever[server] = r["last"]
    recent = set()
    for r in conn.execute(
        "SELECT tool_name FROM events WHERE substr(tool_name, 1, 5) = 'mcp__'"
        f"{flt} AND timestamp >= ? AND timestamp < ? GROUP BY tool_name",
        args + [since, end],
    ):
        server = _mcp_server_of(r["tool_name"])
        if server:
            recent.add(server)
    return sorted(({"name": s, "last": t} for s, t in ever.items() if s not in recent),
                  key=lambda m: m["last"] or "")


def compute_report(user, win):
    """Windowed stats for the email reports (the dashboard keeps compute_stats).

    user=None aggregates the whole team; otherwise stats are restricted to
    that user, matching the collector's `user` field.
    """
    flt = " AND user = ?" if user else ""
    args = [user] if user else []
    w = " WHERE timestamp >= ? AND timestamp < ?" + flt
    wargs = [win["start"], win["end"]] + args
    team = user is None
    with closing(connect()) as conn:
        conn.row_factory = sqlite3.Row
        totals = conn.execute(
            "SELECT COUNT(DISTINCT session_id) AS sessions,"
            " SUM(CASE WHEN type = 'tool_call' THEN 1 ELSE 0 END) AS tool_calls,"
            " SUM(CASE WHEN type = 'skill_invoke' THEN 1 ELSE 0 END) AS skill_calls"
            f" FROM events{w}", wargs,
        ).fetchone()
        by_project = {}
        for r in conn.execute(
            f"SELECT project_dir, COUNT(DISTINCT session_id) AS n FROM events{w} GROUP BY project_dir", wargs,
        ):
            name = _project_name_of(r["project_dir"])
            by_project[name] = by_project.get(name, 0) + (r["n"] or 0)
        by_mcp = {}
        for r in conn.execute(
            "SELECT tool_name, COUNT(*) AS n FROM events"
            f"{w} AND type = 'tool_call' AND substr(tool_name, 1, 5) = 'mcp__' GROUP BY tool_name", wargs,
        ):
            server = _mcp_server_of(r["tool_name"])
            if server:
                by_mcp[server] = by_mcp.get(server, 0) + r["n"]
        by_skill = {}
        for r in conn.execute(
            f"SELECT skill, skill_command, COUNT(*) AS n FROM events"
            f"{w} AND type = 'skill_invoke' GROUP BY skill, skill_command", wargs,
        ):
            label = skill_label(r["skill"], r["skill_command"])
            by_skill[label] = by_skill.get(label, 0) + r["n"]
        by_tool = {}
        for r in conn.execute(
            "SELECT tool_name, COUNT(*) AS n FROM events"
            f"{w} AND type = 'tool_call' AND (tool_name IS NULL OR substr(tool_name, 1, 5) != 'mcp__')"
            " GROUP BY tool_name ORDER BY n DESC", wargs,
        ):
            by_tool[r["tool_name"] or "<unknown>"] = r["n"]
        zero_skills = _idle_skills(conn, flt, args, win["end"], win["lookback_start"])
        cold_mcp = _idle_mcp(conn, flt, args, win["end"], win["start"])
        per_user, idle_accounts = [], []
        if team:
            rows = conn.execute(
                "SELECT user, COUNT(DISTINCT session_id) AS sessions,"
                " SUM(CASE WHEN type = 'tool_call' THEN 1 ELSE 0 END) AS tool_calls,"
                " SUM(CASE WHEN type = 'skill_invoke' THEN 1 ELSE 0 END) AS skill_calls"
                f" FROM events{w} AND user IS NOT NULL GROUP BY user"
                " ORDER BY tool_calls DESC, sessions DESC", wargs,
            ).fetchall()
            tops = {}
            for r in conn.execute(
                "SELECT user, skill, COUNT(*) AS n FROM events"
                f"{w} AND user IS NOT NULL AND type = 'skill_invoke' AND skill IS NOT NULL"
                " GROUP BY user, skill", wargs,
            ):
                tops.setdefault(r["user"], []).append((r["skill"], r["n"]))
            per_user = [{"name": r["user"], "sessions": r["sessions"] or 0,
                         "tool_calls": r["tool_calls"] or 0, "skill_calls": r["skill_calls"] or 0,
                         "top_skills": sorted(tops.get(r["user"], []), key=lambda x: -x[1])[:3]}
                        for r in rows]
            accounts = conn.execute(
                "SELECT username FROM users WHERE email IS NOT NULL AND email != '' ORDER BY username"
            ).fetchall()
            active = {r["user"] for r in rows}
            idle_accounts = [a["username"] for a in accounts if a["username"] not in active]

    def _sorted(d):
        return [{"name": k, "n": v} for k, v in sorted(d.items(), key=lambda x: -x[1])]

    return {
        "window": win,
        "sessions": totals["sessions"] or 0,
        "tool_calls": totals["tool_calls"] or 0,
        "skill_calls": totals["skill_calls"] or 0,
        "mcp_calls": sum(by_mcp.values()),
        "users_active": len(per_user) if team else None,
        "by_project": _sorted(by_project),
        "by_mcp": _sorted(by_mcp),
        "by_skill": _sorted(by_skill),
        "by_tool": [{"name": k, "n": v} for k, v in by_tool.items()][:15],
        "zero_skills": zero_skills,
        "cold_mcp": cold_mcp,
        "per_user": per_user,
        "idle_accounts": idle_accounts,
    }


_REPORT_CARD = 'style="background:#fff;border:1px solid #e5e7eb;border-radius:10px;padding:18px;margin:0 0 18px"'
_REPORT_TTL = 'style="font-size:14px;font-weight:600;margin:0 0 12px;color:#31363c"'


def _report_kpi_cards(items):
    kpi = 'style="padding:10px 14px;background:#fff;border:1px solid #e5e7eb;border-radius:8px"'
    cells = []
    for value, label in items:
        cells.append(f'<td {kpi}><div style="font-size:22px;font-weight:600">{value}</div>'
                     f'<div style="font-size:12px;color:#6b7280">{esc_html(label)}</div></td>'
                     '<td style="width:12px">&nbsp;</td>')
    return ('<table cellpadding="0" cellspacing="0" style="width:100%;border-collapse:collapse;margin-bottom:18px"><tr>'
            + "".join(cells) + "</tr></table>")


def _report_table(headers, rows, empty_text="暂无数据"):
    # headers: [(title, numeric?)]; cells: str (escaped here) or number
    if not rows:
        return f'<div style="color:#9ca3af;padding:8px 0">{esc_html(empty_text)}</div>'
    th = 'style="padding:8px 10px;background:#f7f8fa;color:#4b5563;border-bottom:1px solid #e5e7eb;text-align:left"'
    td = 'style="padding:8px 10px;border-bottom:1px solid #f0f1f3;vertical-align:middle"'
    right = ' align="right"'
    parts = ['<table cellpadding="0" cellspacing="0" style="width:100%;border-collapse:collapse;font-size:13px"><tr>']
    for title, num in headers:
        parts.append(f"<th {th}{right if num else ''}>{esc_html(title)}</th>")
    parts.append("</tr>")
    for row in rows:
        parts.append("<tr>")
        for (_, num), cell in zip(headers, row):
            body = cell if isinstance(cell, (int, float)) else esc_html(cell)
            parts.append(f"<td {td}{right if num else ''}>{body}</td>")
        parts.append("</tr>")
    parts.append("</table>")
    return "".join(parts)


def _report_warn_card(rep):
    zero, cold = rep["zero_skills"], rep["cold_mcp"]
    n = len(zero) + len(cold)
    inner = ""
    if zero:
        inner += ('<div style="font-weight:600;margin:0 0 6px">零使用 skill（14 天内 0 次调用）</div>'
                  + _report_table([("Skill", 0), ("上次使用", 1)],
                                  [[s["name"], (s["last"] or "")[:10]] for s in zero]))
    if cold:
        inner += ('<div style="font-weight:600;margin:12px 0 6px">MCP 冷置（本窗口 0 次调用，考虑禁用以省启动开销）</div>'
                  + _report_table([("MCP server", 0), ("上次使用", 1)],
                                  [[s["name"], (s["last"] or "")[:10]] for s in cold]))
    if not inner:
        inner = '<div style="color:#1d9e75;padding:4px 0">无预警，一切正常。</div>'
    return (f"<div {_REPORT_CARD}><div {_REPORT_TTL}>该改什么（预警 {n} 条）</div>{inner}"
            '<div style="color:#9ca3af;font-size:12px;margin-top:10px">'
            "零使用/冷置仅覆盖服务端收到过调用记录的工具；从未上报过的工具不在此列。</div></div>")


def _report_bar_card(title, rows, color):
    return f"<div {_REPORT_CARD}><div {_REPORT_TTL}>{esc_html(title)}</div>{_report_rows(rows, color)}</div>"


def _team_overview_card(rep):
    rows = [[u["name"], u["sessions"], u["tool_calls"], u["skill_calls"],
             "，".join(f"{s} {n}" for s, n in u["top_skills"]) or "-"] for u in rep["per_user"]]
    body = _report_table(
        [("用户", 0), ("会话", 1), ("工具调用", 1), ("Skill 调用", 1), ("主要 Skill", 0)], rows)
    if rep["idle_accounts"]:
        body += ('<div style="color:#9ca3af;font-size:12px;margin-top:10px">本窗口无数据账号：'
                 + esc_html("、".join(rep["idle_accounts"])) + "</div>")
    return f"<div {_REPORT_CARD}><div {_REPORT_TTL}>人员概览</div>{body}</div>"


def _report_body(rep, overview=False):
    parts = [_report_warn_card(rep)]
    if overview:
        parts.append(_team_overview_card(rep))
    parts += [
        _report_bar_card("按项目分布（会话数）", rep["by_project"], "#3b7ddd"),
        _report_bar_card("MCP 调用（按 server 合并）", rep["by_mcp"], "#7f77dd"),
        _report_bar_card("Skill 调用", rep["by_skill"], "#1d9e75"),
        _report_bar_card("内置工具 Top 15", rep["by_tool"], "#3b7ddd"),
    ]
    return "".join(parts)


def _report_page(title, meta, body):
    gen = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return f"""<!doctype html><html><body style="margin:0;background:#f5f6f8;font-family:-apple-system,'Segoe UI','Microsoft YaHei',Roboto,sans-serif;font-size:14px;color:#1f2328">
<div style="max-width:900px;margin:0 auto;padding:24px">
  <div style="font-size:20px;font-weight:600;margin-bottom:4px">{title}</div>
  <div style="color:#6b7280;font-size:13px;margin-bottom:18px">窗口 {meta} · 生成于 {gen}（tools-call-server 自动统计）</div>
  {body}
  <div style="color:#9ca3af;font-size:12px">本邮件由 tools-call-server 自动发送</div>
</div></body></html>"""


def report_subject(rep, who=None):
    win = rep["window"]
    n = len(rep["zero_skills"]) + len(rep["cold_mcp"])
    if who is None:
        return f"[团队工具使用{win['kind']}] {win['subject']}（预警 {n} 条）"
    return f"[工具使用{win['kind']}] {who} · {win['subject']}（预警 {n} 条）"


def build_report_html(name, rep):
    win = rep["window"]
    title = f"工具使用{win['kind']} — {esc_html(name)} · {win['subject']}"
    meta = f"{win['meta']} · 会话 {rep['sessions']} · 工具调用 {rep['tool_calls'] + rep['skill_calls']}"
    body = _report_kpi_cards([
        (rep["sessions"], "会话数"),
        (rep["tool_calls"], "工具调用"),
        (rep["skill_calls"], "Skill 调用"),
        (rep["mcp_calls"], "MCP 调用"),
    ]) + _report_body(rep)
    return _report_page(title, meta, body)


def build_team_report_html(rep):
    win = rep["window"]
    title = f"团队工具使用{win['kind']} · {win['subject']}"
    meta = (f"{win['meta']} · 活跃用户 {rep['users_active']} · 会话 {rep['sessions']}"
            f" · 工具调用 {rep['tool_calls'] + rep['skill_calls']}")
    body = _report_kpi_cards([
        (rep["users_active"], "活跃用户"),
        (rep["sessions"], "会话数"),
        (rep["tool_calls"] + rep["skill_calls"], "工具调用"),
        (rep["skill_calls"], "Skill 调用"),
    ]) + _report_body(rep, overview=True)
    return _report_page(title, meta, body)


def _smtp_error_detail(exc):
    msg = f"{type(exc).__name__}: {exc}"
    if "5.7.139" in msg or "SmtpClientAuthentication" in msg:
        msg = ("租户已禁用 SMTP AUTH（5.7.139）：需要 IT 给发件邮箱开启 SMTP AUTH"
               "（Set-CASMailbox <邮箱> -SmtpClientAuthenticationDisabled $false），"
               "或改用公司内部 SMTP 中继（问 IT 要 relay 地址）")
    return msg


class EmailBody(BaseModel):
    email: str


@app.post("/admin/users/{username}/email")
def admin_set_email(username: str, body: EmailBody, user: dict = Depends(require_admin)):
    email = body.email.strip()
    if not EMAIL_RE.match(email) or len(email) > 254:
        raise HTTPException(status_code=400, detail="邮箱格式不正确")
    with closing(connect()) as conn:
        cur = conn.execute("UPDATE users SET email = ? WHERE username = ?", (email, username))
        conn.commit()
    if cur.rowcount == 0:
        raise HTTPException(status_code=404, detail="用户不存在")
    return {"ok": True}


def _send_user_report(username, email, win):
    rep = compute_report(username, win)
    if rep["tool_calls"] + rep["skill_calls"] == 0:
        return "skipped", "窗口内无数据"
    send_html_mail(email, report_subject(rep, who=username), build_report_html(username, rep))
    return "sent", ""


@app.post("/admin/users/{username}/send_report")
def admin_send_report(username: str, user: dict = Depends(require_admin)):
    row = get_user(username)
    if not row:
        raise HTTPException(status_code=404, detail="用户不存在")
    if not row["email"]:
        raise HTTPException(status_code=400, detail="该用户未配置邮箱")
    try:
        status, reason = _send_user_report(username, row["email"], _report_window("manual"))
    except RuntimeError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"发送失败: {_smtp_error_detail(exc)}")
    if status == "skipped":
        raise HTTPException(status_code=400, detail=reason)
    return {"ok": True}


def _send_team_report(win):
    """Team aggregate report to every admin with a configured mailbox."""
    with closing(connect()) as conn:
        conn.row_factory = sqlite3.Row
        admins = conn.execute(
            "SELECT username, email FROM users WHERE role = 'admin' AND email IS NOT NULL AND email != ''"
        ).fetchall()
    if not admins:
        return "skipped", "没有配置邮箱的管理员", []
    rep = compute_report(None, win)
    if rep["tool_calls"] + rep["skill_calls"] == 0:
        return "skipped", "全团队窗口内无数据", []
    subject = report_subject(rep)
    html = build_team_report_html(rep)
    results = []
    for a in admins:
        try:
            send_html_mail(a["email"], subject, html)
            results.append({"to": a["email"], "status": "sent", "reason": ""})
        except Exception as exc:
            results.append({"to": a["email"], "status": "failed",
                            "reason": f"{type(exc).__name__}: {exc}"})
    status = "sent" if any(r["status"] == "sent" for r in results) else "failed"
    return status, "", results


@app.post("/admin/send_team_report")
def admin_send_team_report(user: dict = Depends(require_admin)):
    status, reason, recipients = _send_team_report(_report_window("manual"))
    if status == "skipped":
        raise HTTPException(status_code=400, detail=reason)
    failed = [r for r in recipients if r["status"] == "failed"]
    if failed:
        raise HTTPException(status_code=502, detail=f"发送失败: {failed[0]['reason']}")
    return {"ok": True, "sent_to": [r["to"] for r in recipients if r["status"] == "sent"]}


def _do_send_all(win):
    # Shared by the manual bulk endpoint and the scheduler
    with closing(connect()) as conn:
        conn.row_factory = sqlite3.Row
        users = conn.execute(
            "SELECT username, email FROM users WHERE email IS NOT NULL AND email != ''"
        ).fetchall()
    results = []
    for r in users:
        try:
            status, reason = _send_user_report(r["username"], r["email"], win)
            results.append({"user": r["username"], "status": status, "reason": reason})
        except RuntimeError as exc:
            results.append({"user": r["username"], "status": "failed", "reason": str(exc)})
        except Exception as exc:
            results.append({"user": r["username"], "status": "failed",
                            "reason": f"{type(exc).__name__}: {exc}"})
    team_status, team_reason, team_recipients = _send_team_report(win)
    return {"results": results,
            "team": {"status": team_status, "reason": team_reason, "recipients": team_recipients}}


@app.post("/admin/send_all_reports")
def admin_send_all(user: dict = Depends(require_admin)):
    return _do_send_all(_report_window("manual"))


class SmtpBody(BaseModel):
    host: Optional[str] = None
    port: Optional[int] = None
    user: Optional[str] = None
    password: Optional[str] = None
    security: Optional[str] = None


class TestToBody(BaseModel):
    to: str


@app.get("/admin/smtp")
def admin_get_smtp(user: dict = Depends(require_admin)):
    cfg = get_smtp_config()
    # 密码只写不可读：只返回是否已配置
    return {"host": cfg["host"], "port": cfg["port"], "user": cfg["user"],
            "password_set": bool(cfg["password"]), "security": cfg["security"]}


@app.post("/admin/smtp")
def admin_set_smtp(body: SmtpBody, user: dict = Depends(require_admin)):
    updates = {}
    if body.host is not None:
        updates["host"] = body.host.strip()
    if body.port is not None:
        updates["port"] = body.port
    if body.user is not None:
        updates["user"] = body.user.strip()
    if body.password is not None:
        # 字段存在但为空 = 清除密码（改用免认证中继）；字段缺省 = 保持不变
        updates["password"] = body.password
    if body.security is not None:
        if body.security not in ("starttls", "ssl", "none"):
            raise HTTPException(status_code=400, detail="security 必须是 starttls/ssl/none")
        updates["security"] = body.security
    if updates:
        set_smtp_settings(updates)
    return {"ok": True}


@app.post("/admin/smtp/test")
def admin_test_smtp(body: TestToBody, user: dict = Depends(require_admin)):
    to = body.to.strip()
    if not EMAIL_RE.match(to):
        raise HTTPException(status_code=400, detail="邮箱格式不正确")
    try:
        send_html_mail(to, "tools-call-server 测试邮件",
                       '<p style="font-size:14px">SMTP 配置测试成功，报告邮件将使用此发件配置。</p>')
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"发送失败: {_smtp_error_detail(exc)}")
    return {"ok": True}


# ---- scheduled report sending ----

def get_schedule_config():
    cfg = {"mode": "off", "day": 0, "time": "09:00", "last_period": "", "last_sent": ""}
    with closing(connect()) as conn:
        for k, v in conn.execute("SELECT key, value FROM settings WHERE key LIKE 'report_%'"):
            key = k[len("report_"):]
            if key == "day":
                try:
                    cfg[key] = int(v)
                except ValueError:
                    pass
            else:
                cfg[key] = v
    return cfg


def set_schedule_settings(updates):
    with closing(connect()) as conn:
        for k, v in updates.items():
            conn.execute(
                "INSERT INTO settings (key, value) VALUES (?, ?)"
                " ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (f"report_{k}", str(v)),
            )
        conn.commit()


def _schedule_period(now, mode):
    if mode == "weekly":
        iso = now.isocalendar()
        return f"{iso[0]}-W{iso[1]}"
    return now.strftime("%Y-%m-%d")


def _scheduler_tick():
    cfg = get_schedule_config()
    if cfg["mode"] not in ("daily", "weekly"):
        return
    now = datetime.now()
    if cfg["mode"] == "weekly" and now.weekday() != cfg["day"]:
        return
    try:
        hh, mm = (cfg["time"] or "09:00").split(":")[:2]
        sched = now.replace(hour=int(hh), minute=int(mm), second=0, microsecond=0)
    except (ValueError, AttributeError):
        return
    if now < sched:
        return
    period = _schedule_period(now, cfg["mode"])
    if cfg["last_period"] == period:
        return
    outcome = _do_send_all(_report_window(cfg["mode"]))
    set_schedule_settings({"last_period": period, "last_sent": now_iso()})
    team = outcome.get("team", {})
    log.info("scheduled report run (%s): sent=%s skipped=%s failed=%s team=%s recipients=%s",
             cfg["mode"],
             len([r for r in outcome["results"] if r["status"] == "sent"]),
             len([r for r in outcome["results"] if r["status"] == "skipped"]),
             len([r for r in outcome["results"] if r["status"] == "failed"]),
             team.get("status"), len(team.get("recipients", [])))


def _report_scheduler():
    log.info("report scheduler started")
    while True:
        try:
            _scheduler_tick()
        except Exception as exc:
            log.error("report scheduler tick failed: %s: %s", type(exc).__name__, exc)
        time.sleep(60)


class ScheduleBody(BaseModel):
    mode: str
    day: Optional[int] = None
    time: Optional[str] = None


@app.get("/admin/schedule")
def admin_get_schedule(user: dict = Depends(require_admin)):
    return get_schedule_config()


@app.post("/admin/schedule")
def admin_set_schedule(body: ScheduleBody, user: dict = Depends(require_admin)):
    if body.mode not in ("off", "daily", "weekly"):
        raise HTTPException(status_code=400, detail="mode 必须是 off/daily/weekly")
    updates = {"mode": body.mode}
    if body.mode == "weekly":
        if body.day is None or not 0 <= body.day <= 6:
            raise HTTPException(status_code=400, detail="day 必须是 0-6（周一=0）")
        updates["day"] = body.day
    t = (body.time or "09:00").strip()
    if not re.match(r"^([01]?\d|2[0-3]):[0-5]\d$", t):
        raise HTTPException(status_code=400, detail="时间格式需 HH:MM")
    updates["time"] = t
    set_schedule_settings(updates)
    return {"ok": True, **get_schedule_config()}


def skill_label(skill, command):
    # None is a legitimate value (browse calls carry no skill name) —
    # render it as a readable label instead of the string "null"
    return skill or (f"<{command}>" if command else "<unidentified>")


def compute_stats(user=None):
    flt = " AND user = ?" if user else ""
    args = [user] if user else []
    where_u = " WHERE user = ?" if user else ""
    with closing(connect()) as conn:
        conn.row_factory = sqlite3.Row
        total = conn.execute(f"SELECT COUNT(*) AS n FROM events{where_u}", args).fetchone()["n"]
        by_tool = conn.execute(
            "SELECT CASE WHEN type = 'skill_invoke' THEN 'skill' ELSE tool_name END AS tool,"
            " COUNT(*) AS n FROM events WHERE type IN ('tool_call', 'skill_invoke')"
            f" AND (type = 'skill_invoke' OR tool_name IS NOT NULL){flt} GROUP BY tool ORDER BY n DESC",
            args,
        ).fetchall()
        by_skill_rows = conn.execute(
            "SELECT skill, skill_command, COUNT(*) AS n FROM events WHERE type = 'skill_invoke'"
            f"{flt} GROUP BY skill, skill_command ORDER BY n DESC",
            args,
        ).fetchall()
        by_client = conn.execute(
            f"SELECT client_id, COUNT(*) AS n FROM events{where_u} GROUP BY client_id ORDER BY n DESC",
            args,
        ).fetchall()
        by_user = conn.execute(
            f"SELECT user, COUNT(*) AS n FROM events{where_u} GROUP BY user ORDER BY n DESC",
            args,
        ).fetchall()
        tool_day_rows = conn.execute(
            "SELECT CASE WHEN type = 'skill_invoke' THEN 'skill' ELSE tool_name END AS tool,"
            " substr(timestamp, 1, 10) AS day, COUNT(*) AS n FROM events"
            " WHERE type IN ('tool_call', 'skill_invoke')"
            f" AND (type = 'skill_invoke' OR tool_name IS NOT NULL){flt} GROUP BY tool, day",
            args,
        ).fetchall()
        user_tool_rows = conn.execute(
            "SELECT user, CASE WHEN type = 'skill_invoke' THEN 'skill' ELSE tool_name END AS tool,"
            " COUNT(*) AS n FROM events"
            " WHERE type IN ('tool_call', 'skill_invoke') AND user IS NOT NULL"
            f" AND (type = 'skill_invoke' OR tool_name IS NOT NULL){flt} GROUP BY user, tool",
            args,
        ).fetchall()
        user_skill_rows = conn.execute(
            "SELECT user, skill, skill_command, COUNT(*) AS n FROM events"
            f" WHERE type = 'skill_invoke' AND user IS NOT NULL{flt} GROUP BY user, skill, skill_command",
            args,
        ).fetchall()
        by_day = conn.execute(
            f"SELECT substr(timestamp, 1, 10) AS day, COUNT(*) AS n FROM events{where_u}"
            " GROUP BY day ORDER BY day DESC LIMIT 400",
            args,
        ).fetchall()
        skill_day_rows = conn.execute(
            "SELECT skill, skill_command, substr(timestamp, 1, 10) AS day, COUNT(*) AS n FROM events"
            f" WHERE type = 'skill_invoke'{flt} GROUP BY skill, skill_command, day",
            args,
        ).fetchall()
        user_tool_day_rows = conn.execute(
            "SELECT user, CASE WHEN type = 'skill_invoke' THEN 'skill' ELSE tool_name END AS tool,"
            " substr(timestamp, 1, 10) AS day, COUNT(*) AS n FROM events"
            " WHERE type IN ('tool_call', 'skill_invoke')"
            " AND (type = 'skill_invoke' OR tool_name IS NOT NULL) AND user IS NOT NULL"
            f"{flt} GROUP BY user, tool, day",
            args,
        ).fetchall()
        user_skill_day_rows = conn.execute(
            "SELECT user, skill, skill_command, substr(timestamp, 1, 10) AS day, COUNT(*) AS n FROM events"
            " WHERE type = 'skill_invoke' AND user IS NOT NULL"
            f"{flt} GROUP BY user, skill, skill_command, day",
            args,
        ).fetchall()
        last = conn.execute(f"SELECT MAX(timestamp) AS ts FROM events{where_u}", args).fetchone()["ts"]
        tool_days, user_tools, user_skills, skill_days = {}, {}, {}, {}
        user_tool_days, user_skill_days = {}, {}
        for r in tool_day_rows:
            tool_days.setdefault(r["tool"], {})[r["day"]] = r["n"]
        for r in user_tool_rows:
            user_tools.setdefault(r["user"], {})[r["tool"]] = r["n"]
        for r in user_skill_rows:
            user_skills.setdefault(r["user"], {})[skill_label(r["skill"], r["skill_command"])] = r["n"]
        for r in skill_day_rows:
            skill_days.setdefault(skill_label(r["skill"], r["skill_command"]), {})[r["day"]] = r["n"]
        for r in user_tool_day_rows:
            user_tool_days.setdefault(r["user"], {}).setdefault(r["tool"], {})[r["day"]] = r["n"]
        for r in user_skill_day_rows:
            user_skill_days.setdefault(r["user"], {}).setdefault(
                skill_label(r["skill"], r["skill_command"]), {})[r["day"]] = r["n"]

    def _valid_day(day):
        return bool(day) and len(day) == 10 and day[4] == "-" and day[7] == "-"

    return {
        "total": total,
        "by_client": {(r["client_id"] or "<unknown>"): r["n"] for r in by_client},
        "by_user": {(r["user"] or "<unknown>"): r["n"] for r in by_user},
        "by_tool": {r["tool"]: r["n"] for r in by_tool},
        "by_skill": {skill_label(r["skill"], r["skill_command"]): r["n"] for r in by_skill_rows},
        "by_day": {r["day"]: r["n"] for r in by_day if _valid_day(r["day"])},
        "tool_days": tool_days,
        "skill_days": skill_days,
        "user_tools": user_tools,
        "user_skills": user_skills,
        "user_tool_days": user_tool_days,
        "user_skill_days": user_skill_days,
        "last_timestamp": last,
    }


DASHBOARD_PATH = Path(__file__).resolve().parent / "dashboard.html"
LOGIN_PATH = Path(__file__).resolve().parent / "login.html"
ECHARTS_PATH = Path(__file__).resolve().parent / "static" / "echarts.min.js"


@app.get("/", response_class=RedirectResponse)
def root():
    return RedirectResponse("/dashboard")


@app.get("/echarts")
def echarts_js():
    return Response(ECHARTS_PATH.read_bytes(), media_type="application/javascript")


def _json_for_script(obj):
    # Embed JSON safely inside a <script> block: escape < > & so a data value
    # like "</script>" cannot break out of the script element
    return (json.dumps(obj, ensure_ascii=False)
            .replace("<", "\\u003c").replace(">", "\\u003e")
            .replace("&", "\\u0026")
            .replace("\u2028", "\\u2028").replace("\u2029", "\\u2029"))


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    user = current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=302)
    markers = {
        "__USER__": _json_for_script(user),
        "__DATA__": _json_for_script(compute_stats(None if user["role"] == "admin" else user["name"])),
        "__GENERATED__": now_iso(),
    }
    html = DASHBOARD_PATH.read_text(encoding="utf-8")
    # Single pass: a data value containing a marker string cannot be re-substituted
    html = re.sub(r"__(?:DATA|USER|GENERATED)__", lambda m: markers[m.group()], html)
    return html


def seed_default_admin():
    """Seed the default SUPER_ADMIN account on first start (empty users table).

    Runs once: once the table is non-empty it never seeds again, so a changed
    password survives restarts. All further account management happens in the
    dashboard's user-management panel.
    """
    with closing(connect()) as conn:
        if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]:
            return
        try:
            conn.execute(
                "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
                ("SUPER_ADMIN", hash_password("SUPER_ADMIN"), "admin", now_iso()),
            )
            conn.commit()
            print(
                "已创建默认管理员 SUPER_ADMIN（密码 SUPER_ADMIN），请登录后尽快修改",
                file=sys.stderr,
            )
        except sqlite3.IntegrityError:
            pass
