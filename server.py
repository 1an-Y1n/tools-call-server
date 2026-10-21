"""tools-call-server: FastAPI backend for tools-call-collector uploads.

Ingests NDJSON batches (one JSON record per line, as appended by the plugin's
collector) into SQLite. Local-account login (admin/user roles) protects the
dashboard and stats API — regular users only see their own records; the ingest
endpoint stays open for collectors. A default admin SUPER_ADMIN / SUPER_ADMIN
is seeded on first start (empty users table) — change it after first login.
"""

import hashlib
import hmac
import json
import os
import re
import secrets
import smtplib
import sqlite3
import sys
from contextlib import asynccontextmanager, closing
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

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

# SMTP for report emails; defaults to Office 365 (Outlook). Credentials come
# from env: SMTP_USER (sender mailbox) + SMTP_PASSWORD (mailbox password or
# app password). SMTP_SECURITY: starttls (default) | ssl | none
SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.office365.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
SMTP_SECURITY = os.environ.get("SMTP_SECURITY", "starttls")


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


def send_html_mail(to, subject, html):
    cfg = get_smtp_config()
    if not cfg["host"] or not cfg["user"]:
        raise RuntimeError("SMTP 未配置：请填写服务器与账号后保存，再发送")
    msg = MIMEMultipart("alternative")
    msg["From"] = cfg["user"]
    msg["To"] = to
    msg["Subject"] = subject
    msg.attach(MIMEText(html, "html", "utf-8"))
    if cfg["security"] == "ssl":
        s = smtplib.SMTP_SSL(cfg["host"], cfg["port"], timeout=30)
    else:
        s = smtplib.SMTP(cfg["host"], cfg["port"], timeout=30)
    with s:
        s.ehlo()
        if cfg["security"] == "starttls":
            s.starttls()
            s.ehlo()
        if cfg["password"]:
            s.login(cfg["user"], cfg["user"])
        s.send_message(msg)


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


def build_report_html(name, stats):
    gen = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    tools = sorted(stats["by_tool"].items(), key=lambda x: -x[1])[:15]
    skills = sorted(stats["by_skill"].items(), key=lambda x: -x[1])[:15]
    days = sorted(stats["by_day"].items())[-30:]
    kpi = 'style="padding:10px 14px;background:#fff;border:1px solid #e5e7eb;border-radius:8px"'
    card = 'style="background:#fff;border:1px solid #e5e7eb;border-radius:10px;padding:18px;margin:0 0 18px"'
    ttl = 'style="font-size:14px;font-weight:600;margin:0 0 12px;color:#31363c"'
    clients = len([c for c in stats["by_client"] if c != "<unknown>"])
    return f"""<!doctype html><html><body style="margin:0;background:#f5f6f8;font-family:-apple-system,'Segoe UI','Microsoft YaHei',Roboto,sans-serif;font-size:14px;color:#1f2328">
<div style="max-width:900px;margin:0 auto;padding:24px">
  <div style="font-size:20px;font-weight:600;margin-bottom:4px">Agent 工具 / Skill 使用统计 — {esc_html(name)}</div>
  <div style="color:#6b7280;font-size:13px;margin-bottom:18px">生成于 {gen} · 数据范围：全部历史</div>
  <table cellpadding="0" cellspacing="0" style="width:100%;border-collapse:collapse;margin-bottom:18px"><tr>
    <td {kpi}><div style="font-size:22px;font-weight:600">{stats['total']}</div><div style="font-size:12px;color:#6b7280">总记录数</div></td>
    <td style="width:12px">&nbsp;</td>
    <td {kpi}><div style="font-size:22px;font-weight:600">{clients}</div><div style="font-size:12px;color:#6b7280">Client 数</div></td>
    <td style="width:12px">&nbsp;</td>
    <td {kpi}><div style="font-size:13px;font-weight:600;padding-top:6px">{esc_html(stats['last_timestamp'] or '-')}</div><div style="font-size:12px;color:#6b7280">最新记录时间</div></td>
  </tr></table>
  <div {card}><div {ttl}>工具调用次数（Top 15）</div>{_report_rows([{'name': t, 'n': n} for t, n in tools], '#3b7ddd')}</div>
  <div {card}><div {ttl}>Skill 调用次数（Top 15）</div>{_report_rows([{'name': s, 'n': n} for s, n in skills], '#1d9e75')}</div>
  <div {card}><div {ttl}>每日记录趋势（最近 30 天）</div>{_report_rows([{'name': d, 'n': n} for d, n in days], '#3b7ddd')}</div>
  <div style="color:#9ca3af;font-size:12px">本邮件由 tools-call-server 自动发送</div>
</div></body></html>"""


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


def _send_user_report(username, email):
    stats = compute_stats(username)
    if stats["total"] == 0:
        return "skipped", "无数据"
    send_html_mail(email, f"Agent 工具 / Skill 使用统计报告 — {username}", build_report_html(username, stats))
    return "sent", ""


@app.post("/admin/users/{username}/send_report")
def admin_send_report(username: str, user: dict = Depends(require_admin)):
    row = get_user(username)
    if not row:
        raise HTTPException(status_code=404, detail="用户不存在")
    if not row["email"]:
        raise HTTPException(status_code=400, detail="该用户未配置邮箱")
    try:
        status, reason = _send_user_report(username, row["email"])
    except RuntimeError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"发送失败: {_smtp_error_detail(exc)}")
    if status == "skipped":
        raise HTTPException(status_code=400, detail=reason)
    return {"ok": True}


@app.post("/admin/send_all_reports")
def admin_send_all(user: dict = Depends(require_admin)):
    with closing(connect()) as conn:
        conn.row_factory = sqlite3.Row
        users = conn.execute(
            "SELECT username, email FROM users WHERE email IS NOT NULL AND email != ''"
        ).fetchall()
    results = []
    for r in users:
        try:
            status, reason = _send_user_report(r["username"], r["email"])
            results.append({"user": r["username"], "status": status, "reason": reason})
        except RuntimeError as exc:
            results.append({"user": r["username"], "status": "failed", "reason": str(exc)})
        except Exception as exc:
            results.append({"user": r["username"], "status": "failed",
                            "reason": f"{type(exc).__name__}: {exc}"})
    return {"results": results}


class SmtpBody(BaseModel):
    host: str | None = None
    port: int | None = None
    user: str | None = None
    password: str | None = None
    security: str | None = None


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
