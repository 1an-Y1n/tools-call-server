"""tools-call-server: FastAPI backend for tools-call-collector uploads.

Ingests NDJSON batches (one JSON record per line, as appended by the plugin's
collector) into SQLite. Accounts are provisioned from the data itself: the
first record carrying an unseen email opens a local account whose name is that
address, and a random password is mailed there once (the admin can trigger a
resend, which always issues a new password). Local-account login protects the
dashboard and stats API — regular users only see their own records. The ingest
endpoint stays open for collectors, so it never fails because of account
provisioning. SUPER_ADMIN / SUPER_ADMIN is seeded on first start (empty users
table); two roles are enough — every admin mutation refuses to remove the last
remaining admin, which is what keeps the system manageable.

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
import queue
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


def super_admin_email():
    """The address the server sends from: SUPER_ADMIN's own mailbox.

    Keeping one source means the From header, the SMTP account and the
    account an admin maintains can never disagree.
    """
    with closing(connect()) as conn:
        row = conn.execute(
            "SELECT email FROM users WHERE username = 'SUPER_ADMIN'").fetchone()
    return (row[0] or "").strip() if row else ""


def get_smtp_config():
    # DB settings (admin GUI) override the env-var defaults; legacy smtp_from /
    # smtp_user rows (sender is derived, not configured) are ignored
    cfg = {"host": SMTP_HOST, "port": SMTP_PORT,
           "password": SMTP_PASSWORD, "security": SMTP_SECURITY}
    with closing(connect()) as conn:
        for k, v in conn.execute("SELECT key, value FROM settings WHERE key LIKE 'smtp_%'"):
            key = k[len("smtp_"):]
            if key in ("from", "user"):
                continue
            cfg[key] = int(v) if key == "port" and v.isdigit() else v
    # SMTP_USER stays as an escape hatch for deployments that must send as a
    # different mailbox (a relay-only service account, say)
    cfg["sender"] = (SMTP_USER or super_admin_email()).strip()
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


def get_setting(key, default=None):
    with closing(connect()) as conn:
        row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return row[0] if row else default


def set_setting(key, value):
    with closing(connect()) as conn:
        if value is None:
            conn.execute("DELETE FROM settings WHERE key = ?", (key,))
        else:
            conn.execute(
                "INSERT INTO settings (key, value) VALUES (?, ?)"
                " ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, str(value)),
            )
        conn.commit()


# Comma/space separated allow-list for accounts auto-created from collected
# data. Empty (the default) accepts every address. Entries are either a full
# address (name@corp.com) or a bare domain (corp.com / *@corp.com).
ALLOWLIST_KEY = "ingest_email_allowlist"


def get_email_allowlist():
    return get_setting(ALLOWLIST_KEY, "") or ""


def set_email_allowlist(raw):
    cleaned = " ".join(str(raw or "").replace(",", " ").replace(";", " ").split())
    set_setting(ALLOWLIST_KEY, cleaned or None)


def email_allowed(email):
    """Whether a collected address may get an account. Empty list = allow all."""
    patterns = get_email_allowlist().split()
    if not patterns:
        return True
    email = (email or "").lower()
    for pattern in patterns:
        p = pattern.lower().lstrip("*").lstrip("@")
        if not p:
            continue
        if "@" in p:
            if email == p:
                return True
        elif email.endswith("@" + p):
            return True
    return False


@asynccontextmanager
async def lifespan(app):
    seed_default_admin()
    threading.Thread(target=_report_scheduler, daemon=True).start()
    threading.Thread(target=_invite_worker, daemon=True).start()
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
    name TEXT,
    email TEXT,
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
    status TEXT NOT NULL DEFAULT 'active',
    must_change_password INTEGER NOT NULL DEFAULT 0,
    invite_sent_at TEXT,
    invite_error TEXT,
    last_login_at TEXT,
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
    if "name" not in existing:
        conn.execute("ALTER TABLE events ADD COLUMN name TEXT")
    if "email" not in existing:
        conn.execute("ALTER TABLE events ADD COLUMN email TEXT")
    ucols = {r[1] for r in conn.execute("PRAGMA table_info(users)")}
    if "email" not in ucols:
        conn.execute("ALTER TABLE users ADD COLUMN email TEXT")
    if "status" not in ucols:
        conn.execute("ALTER TABLE users ADD COLUMN status TEXT NOT NULL DEFAULT 'active'")
    if "must_change_password" not in ucols:
        conn.execute("ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0")
    if "invite_sent_at" not in ucols:
        conn.execute("ALTER TABLE users ADD COLUMN invite_sent_at TEXT")
    if "invite_error" not in ucols:
        conn.execute("ALTER TABLE users ADD COLUMN invite_error TEXT")
    if "last_login_at" not in ucols:
        conn.execute("ALTER TABLE users ADD COLUMN last_login_at TEXT")
    # Two roles only. Older databases may still carry the retired super_admin
    # tier; fold it back into admin.
    if conn.execute("SELECT 1 FROM users WHERE role = 'super_admin'").fetchone():
        conn.execute("UPDATE users SET role = 'admin' WHERE role = 'super_admin'")
    # Safety net: every admin mutation keeps at least one admin, so an empty
    # admin list can only come from hand-edited SQL. Recover the bootstrap
    # account (else the oldest account) rather than leave the app unmanageable.
    if not conn.execute("SELECT 1 FROM users WHERE role = 'admin'").fetchone():
        row = conn.execute(
            "SELECT username FROM users ORDER BY (username = 'SUPER_ADMIN') DESC, id LIMIT 1"
        ).fetchone()
        if row:
            conn.execute("UPDATE users SET role = 'admin' WHERE username = ?", (row[0],))
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_client ON events(client_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_user ON events(user)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_email ON events(email)")
    # the role promotion above is DML and would otherwise sit in an implicit
    # transaction that closing() rolls back — it would then be re-applied on
    # every connection, taking a write lock for each request
    conn.commit()


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

# The person a record belongs to. The collector reports the Devin account
# (name + email) whenever it can resolve it; records collected before that
# (or from a collector without a Devin login) only carry the local account
# name. Grouping by this expression keeps every aggregation consistent and
# lets old and new data live in the same table.
PERSON_SQL = "COALESCE(email, user)"

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
EMAIL_MAX_LEN = 254


def norm_email(value):
    """Canonical form of an email used as an account name / person key.

    Lower-cased and trimmed so the same person reported with different casing
    by different collectors still lands on one account. Returns None for
    anything that is not a plausible address, so malformed values fall back to
    the local account name instead of creating a junk account.
    """
    if not isinstance(value, str):
        return None
    email = value.strip().lower()
    if not email or len(email) > EMAIL_MAX_LEN or not EMAIL_RE.match(email):
        return None
    return email


def is_email(value):
    return norm_email(value) is not None


def gen_password(nbytes=12):
    # token_urlsafe(12) yields 16 URL-safe characters (~96 bits of entropy).
    return secrets.token_urlsafe(nbytes)


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
        _s(record.get("name")),
        norm_email(record.get("email")),
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


# ---------------------------------------------------------------------------
# Accounts created from collected data. The first record carrying an unseen
# email opens an account with a random password that is mailed to that address
# exactly once; the password is never stored in clear text, so any later resend
# (admin "reset") generates a fresh one.
# ---------------------------------------------------------------------------
INVITE_QUEUE = queue.Queue()
INVITE_MAX_PER_HOUR = 60
_invite_lock = threading.Lock()
_invite_sent_at = []


def _invite_rate_ok():
    cutoff = time.time() - 3600
    with _invite_lock:
        _invite_sent_at[:] = [t for t in _invite_sent_at if t > cutoff]
        return len(_invite_sent_at) < INVITE_MAX_PER_HOUR


def _note_invite_sent():
    with _invite_lock:
        _invite_sent_at.append(time.time())


def ensure_account_for_email(email):
    """Open an account for a collected email the first time it is seen.

    Returns (created, temporary_password); the password only comes back when
    this call actually created the row, so it can be mailed once.
    """
    if not email or not email_allowed(email):
        return False, None
    with closing(connect()) as conn:
        if conn.execute("SELECT 1 FROM users WHERE username = ?", (email,)).fetchone():
            return False, None
        password = gen_password()
        cur = conn.execute(
            "INSERT INTO users (username, password_hash, role, email, status,"
            " must_change_password, created_at) VALUES (?, ?, 'user', ?, 'active', 1, ?)"
            " ON CONFLICT(username) DO NOTHING",
            (email, hash_password(password), email, now_iso()),
        )
        conn.commit()
        created = cur.rowcount == 1
    return created, (password if created else None)


def queue_invite(email, password, base_url):
    # A burst of brand-new addresses must not pile plain-text passwords into an
    # unbounded queue: past the cap the account still exists, the admin can
    # resend once the backlog clears.
    if INVITE_QUEUE.qsize() >= 200:
        mark_invite(email, error="邀请队列已满，请管理员稍后重新发送")
        return
    INVITE_QUEUE.put((email, password, base_url))


def mark_invite(email, sent=False, error=None):
    with closing(connect()) as conn:
        if sent:
            conn.execute(
                "UPDATE users SET invite_sent_at = ?, invite_error = NULL WHERE username = ?",
                (now_iso(), email),
            )
        else:
            conn.execute(
                "UPDATE users SET invite_error = ? WHERE username = ?",
                (error or "发送失败", email),
            )
        conn.commit()


def invite_html(email, password, base_url):
    login_url = (base_url or "").rstrip("/") + "/login"
    return (
        '<div style="font-family:-apple-system,\'Segoe UI\',sans-serif;font-size:14px;'
        'line-height:1.7;color:#1f2328">'
        '<p>你的 Agent 工具 / Skill 使用统计账号已开通。</p>'
        '<table style="border-collapse:collapse;font-size:14px;margin:12px 0">'
        f'<tr><td style="padding:4px 12px 4px 0;color:#6b7280">登录地址</td><td>{esc_html(login_url or "见内网地址")}</td></tr>'
        f'<tr><td style="padding:4px 12px 4px 0;color:#6b7280">账号</td><td><b>{esc_html(email)}</b></td></tr>'
        f'<tr><td style="padding:4px 12px 4px 0;color:#6b7280">初始密码</td><td><code style="font-size:14px">{esc_html(password)}</code></td></tr>'
        "</table>"
        "<p>首次登录后系统会要求你修改密码。若此邮件并非你本人预期，请联系管理员。</p>"
        "</div>"
    )


def _invite_worker():
    while True:
        item = INVITE_QUEUE.get()
        if item is None:
            return
        email, password, base_url = item
        if not _invite_rate_ok():
            # still created, just not announced: the admin sees it and can
            # resend after the hourly window clears
            mark_invite(email, error="发送过于频繁，请管理员稍后重试")
            continue
        try:
            send_html_mail(email, "Agent 使用统计账号已开通", invite_html(email, password, base_url))
        except Exception as exc:
            log.warning("invite mail to %s failed: %s", email, exc)
            mark_invite(email, error=_smtp_error_detail(exc))
        else:
            _note_invite_sent()
            mark_invite(email, sent=True)


def do_ingest(body, base_url=""):
    rows, rejects, emails = [], [], set()
    for line in body.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
            if not isinstance(record, dict):
                raise ValueError("record is not a JSON object")
            row = row_from_record(record, line)
            rows.append(row)
            if row[7]:
                emails.add(row[7])
        except Exception as exc:
            rejects.append((now_iso(), line, f"{type(exc).__name__}: {exc}"))

    with closing(connect()) as conn:
        if rows:
            conn.executemany(
                "INSERT INTO events (received_at, schema_version, type, timestamp, client_id,"
                " user, name, email, session_id, prompt_id, project_dir, host, tool_name, status, input_keys, skill,"
                " skill_command, collector_name, collector_version, raw)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                rows,
            )
        if rejects:
            conn.executemany("INSERT INTO rejects (received_at, raw, reason) VALUES (?, ?, ?)", rejects)
        conn.commit()

    # after the batch is committed: open accounts for addresses never seen
    # before. Ingestion never fails because of this step.
    for email in sorted(emails):
        try:
            created, password = ensure_account_for_email(email)
        except Exception:
            log.exception("auto-provision failed for %s", email)
            continue
        if created:
            queue_invite(email, password, base_url)

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
    return await run_in_threadpool(do_ingest, body, str(request.base_url))


@app.get("/v1/stats")
def stats(request: Request):
    user = current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="not authenticated")
    if user["must_change_password"]:
        raise HTTPException(status_code=403, detail="请先修改初始密码")
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
    password: Optional[str] = None
    role: str = "user"
    email: Optional[str] = None


class RoleBody(BaseModel):
    role: str


class RenameBody(BaseModel):
    username: str


class StatusBody(BaseModel):
    status: str


class EmailBody(BaseModel):
    email: str


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
    if not name or len(name) > EMAIL_MAX_LEN or any(ord(c) < 32 for c in name):
        raise HTTPException(
            status_code=400, detail="账号长度需 1-254 字符且不含控制字符")


def normalize_username(name):
    """Account names are emails for data-backed users, so they are lower-cased.

    Admin-chosen names (SUPER_ADMIN, an operator alias) keep their casing: they
    are never matched against collected data.
    """
    raw = (name or "").strip()
    return raw.lower() if "@" in raw else raw


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
            # the person key is the email when the collector reported one, so a
            # rename has to carry those records over as well
            conn.execute("UPDATE events SET email = ? WHERE email = ?", (new_name, old_name))
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
    if not row or row["status"] != "active":
        request.session.clear()
        return None
    return {
        "name": row["username"],
        "role": row["role"],
        "email": row["email"],
        "status": row["status"],
        "must_change_password": bool(row["must_change_password"]),
    }


def require_user(request: Request):
    user = current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="not authenticated")
    return user


ROLE_RANK = {"user": 0, "admin": 1}


def require_admin(user: dict = Depends(require_user)):
    if ROLE_RANK.get(user["role"], 0) < ROLE_RANK["admin"]:
        raise HTTPException(status_code=403, detail="需要管理员权限")
    return user


def count_other_admins(username):
    with closing(connect()) as conn:
        return conn.execute(
            "SELECT COUNT(*) FROM users WHERE role = 'admin' AND username != ?", (username,)
        ).fetchone()[0]


@app.get("/login", response_class=HTMLResponse)
def login_page():
    return LOGIN_PATH.read_text(encoding="utf-8")


@app.post("/login")
def login(body: LoginBody, request: Request):
    username = normalize_username(body.username)
    _check_username(username)
    if len(body.password) > 1024:
        raise HTTPException(status_code=400, detail="密码过长")
    row = get_user(username)
    if not row:
        verify_password(body.password, _dummy_hash())
    if not row or not verify_password(body.password, row["password_hash"]):
        raise HTTPException(status_code=401, detail="账号或密码错误")
    if row["status"] != "active":
        raise HTTPException(status_code=403, detail="该账号已停用，请联系管理员")
    with closing(connect()) as conn:
        conn.execute("UPDATE users SET last_login_at = ? WHERE username = ?", (now_iso(), username))
        conn.commit()
    request.session["user"] = {"name": username, "role": row["role"]}
    return {"ok": True, "must_change_password": bool(row["must_change_password"])}


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
    if is_email(user["name"]) and body.new_password.strip().lower() == user["name"]:
        raise HTTPException(status_code=400, detail="密码不能与账号邮箱相同")
    row = get_user(user["name"])
    if not row or not verify_password(body.old_password, row["password_hash"]):
        raise HTTPException(status_code=400, detail="旧密码错误")
    with closing(connect()) as conn:
        conn.execute(
            "UPDATE users SET password_hash = ?, must_change_password = 0 WHERE username = ?",
            (hash_password(body.new_password), user["name"]),
        )
        conn.commit()
    return {"ok": True}


@app.get("/admin/users")
def admin_list_users(user: dict = Depends(require_admin)):
    with closing(connect()) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT id, username, role, email, status, must_change_password,"
            " invite_sent_at, invite_error, last_login_at, created_at"
            " FROM users ORDER BY username"
        ).fetchall()
        # one pass over events: per-person volume and last activity. The person
        # key is the collected email when there is one, otherwise the local
        # account name — the same expression every other aggregation uses.
        usage = {
            r[0]: {"event_count": r[1], "last_seen": r[2]}
            for r in conn.execute(
                f"SELECT {PERSON_SQL} AS person, COUNT(*) AS n, MAX(timestamp) AS last_seen"
                " FROM events GROUP BY person"
            )
        }
    users = []
    for r in rows:
        item = dict(r)
        item["must_change_password"] = bool(item["must_change_password"])
        stats = usage.get(r["username"]) or {}
        item["event_count"] = stats.get("event_count", 0)
        item["last_seen"] = stats.get("last_seen")
        users.append(item)
    return {"users": users}


@app.post("/admin/users")
def admin_create_user(body: NewUserBody, user: dict = Depends(require_admin)):
    username = normalize_username(body.username)
    _check_username(username)
    # Regular accounts are opened by the collector, never by hand: a manual
    # account here is always an administrator, which is also why its name does
    # not have to be an address.
    if body.role != "admin":
        raise HTTPException(
            status_code=400,
            detail="普通账号由采集数据自动创建，这里只能添加管理员")

    if is_email(username):
        # data-backed accounts are identified by their address: the login name
        # and the report recipient are the same value, by design
        email = username
    else:
        email = norm_email(body.email) if body.email else None
        if not email:
            raise HTTPException(status_code=400, detail="请为该管理员填写报告邮箱")
    if body.email and norm_email(body.email) != email:
        raise HTTPException(status_code=400, detail="账号为邮箱时，报告邮箱必须与之一致")

    generated = body.password is None
    password = gen_password() if generated else body.password
    if len(password) < 8 or len(password) > 1024:
        raise HTTPException(status_code=400, detail="密码长度需 8-1024 位")
    try:
        with closing(connect()) as conn:
            conn.execute(
                "INSERT INTO users (username, password_hash, role, email, status,"
                " must_change_password, created_at) VALUES (?, ?, ?, ?, 'active', ?, ?)",
                (username, hash_password(password), body.role, email,
                 1 if generated else 0, now_iso()),
            )
            conn.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="用户已存在")

    email_sent, email_error = False, None
    if generated:
        try:
            send_html_mail(email, "Agent 使用统计账号已开通",
                           invite_html(email, password, ""))
            mark_invite(email, sent=True)
            email_sent = True
        except Exception as exc:
            email_error = _smtp_error_detail(exc)
            mark_invite(email, error=email_error)
    return {"ok": True, "username": username, "email": email,
            "password": password if generated else None,
            "email_sent": email_sent, "email_error": email_error}


@app.post("/admin/users/{username}/password")
def admin_reset_password(username: str, user: dict = Depends(require_admin)):
    """Issue a brand-new password and mail it. The plain text is never returned.

    Used both for "forgot my password" and for re-sending after a failed
    delivery; because only the hash is stored, a resend always means a new
    password.
    """
    row = get_user(username)
    if not row:
        raise HTTPException(status_code=404, detail="用户不存在")
    password = gen_password()
    with closing(connect()) as conn:
        conn.execute(
            "UPDATE users SET password_hash = ?, must_change_password = 1,"
            " invite_sent_at = NULL, invite_error = NULL WHERE username = ?",
            (hash_password(password), username),
        )
        conn.commit()
    recipient = row["email"] or (username if is_email(username) else "")
    if not recipient:
        raise HTTPException(status_code=400, detail="该账号未配置邮箱，无法发送新密码")
    try:
        send_html_mail(recipient, "Agent 使用统计账号密码已重置",
                       invite_html(recipient, password, ""))
    except Exception as exc:
        detail = _smtp_error_detail(exc)
        mark_invite(recipient, error=detail)
        raise HTTPException(status_code=502, detail=f"密码已重置，但邮件发送失败：{detail}")
    mark_invite(recipient, sent=True)
    return {"ok": True, "email": recipient}


@app.post("/admin/users/{username}/status")
def admin_set_status(username: str, body: StatusBody, user: dict = Depends(require_admin)):
    if body.status not in ("active", "disabled"):
        raise HTTPException(status_code=400, detail="status 必须是 active 或 disabled")
    if username == user["name"]:
        raise HTTPException(status_code=400, detail="不能停用自己的账号")
    row = get_user(username)
    if not row:
        raise HTTPException(status_code=404, detail="用户不存在")
    if row["role"] == "admin" and body.status == "disabled" and count_other_admins(username) == 0:
        raise HTTPException(status_code=400, detail="至少需要保留一名可用的管理员")
    with closing(connect()) as conn:
        conn.execute("UPDATE users SET status = ? WHERE username = ?", (body.status, username))
        conn.commit()
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
    if body.role == "user":
        if count_other_admins(username) == 0:
            raise HTTPException(status_code=400, detail="至少需要保留一名管理员")
        if not is_email(username):
            raise HTTPException(
                status_code=400, detail="该账号以管理员别名登录，降级为普通用户后无法匹配采集数据")
    with closing(connect()) as conn:
        conn.execute("UPDATE users SET role = ? WHERE username = ?", (body.role, username))
        conn.commit()
    return {"ok": True}


@app.post("/admin/users/{username}/rename")
def admin_rename_user(username: str, body: RenameBody, request: Request,
                      user: dict = Depends(require_admin)):
    new_name = normalize_username(body.username)
    _check_username(new_name)
    if new_name == username:
        return {"ok": True}
    row = get_user(username)
    if not row:
        raise HTTPException(status_code=404, detail="用户不存在")
    if not is_email(new_name) and row["role"] != "admin":
        raise HTTPException(status_code=400, detail="普通用户的账号必须是邮箱")
    row = _rename_user(username, new_name)
    if is_email(new_name):
        with closing(connect()) as conn:
            conn.execute("UPDATE users SET email = ? WHERE username = ?", (new_name, new_name))
            conn.commit()
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
    if row["role"] == "admin" and count_other_admins(username) == 0:
        raise HTTPException(status_code=400, detail="至少需要保留一名管理员")
    with closing(connect()) as conn:
        conn.execute("DELETE FROM users WHERE username = ?", (username,))
        conn.commit()
    return {"ok": True}


# ---- email reports ----

def esc_html(s):
    return (str(s if s is not None else "")
            .replace("&", "\u0026amp;").replace("<", "\u0026lt;").replace(">", "\u0026gt;"))


log = logging.getLogger("uvicorn.error")


def send_html_mail(to, subject, html):
    cfg = get_smtp_config()
    port = cfg["port"] or 25
    log.info("SMTP send: to=%s host=%s port=%s security=%s ehlo=%s user=%s password_set=%s",
             to, cfg["host"], port, cfg["security"], SMTP_EHLO_NAME,
             cfg["sender"], bool(cfg["password"]))
    if not cfg["host"]:
        log.warning("SMTP not configured: host=%r", cfg["host"])
        raise RuntimeError("SMTP 未配置：请填写服务器地址后保存，再发送")
    if not cfg["sender"]:
        log.warning("SMTP sender missing: SUPER_ADMIN has no mailbox")
        raise RuntimeError(
            "SMTP 未配置：请先在用户管理中给 SUPER_ADMIN 填写邮箱（它是发件人）")
    msg = MIMEMultipart("alternative")
    msg["From"] = cfg["sender"]
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
        s.ehlo()
        if cfg["security"] == "starttls":
            s.starttls()
            s.ehlo()
        if cfg["password"]:
            # Only authenticate when the server actually offers AUTH — relays
            # trusted by source IP don't, and a stale stored password must not
            # break those sends
            if "auth" in s.esmtp_features:
                s.login(cfg["sender"], cfg["password"])
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
            "start": _iso_utc(start), "end": _iso_utc(end)}


def _mcp_server_of(tool_name):
    # MCP tool calls are named mcp__<server>__<tool>; anything else is builtin
    if not tool_name or not tool_name.startswith("mcp__"):
        return None
    parts = tool_name.split("__", 2)
    return parts[1] if len(parts) == 3 else None


def _project_name_of(project_dir):
    return (project_dir or "").rstrip("/").split("/")[-1] or "<unknown>"


def compute_report(user, win):
    """Windowed stats for the email reports (the dashboard keeps compute_stats).

    user=None aggregates the whole team; otherwise stats are restricted to
    that user, matching the collector's `user` field.
    """
    flt = f" AND {PERSON_SQL} = ?" if user else ""
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
        by_mcp, by_tool = {}, {}
        for r in conn.execute(
            f"SELECT tool_name, COUNT(*) AS n FROM events{w} AND type = 'tool_call' GROUP BY tool_name",
            wargs,
        ):
            # classify by the parsed server so malformed mcp__ names (no server
            # part) stay visible in the builtin table instead of vanishing
            # from both sections while still counting towards the KPI total
            server = _mcp_server_of(r["tool_name"])
            if server:
                by_mcp[server] = by_mcp.get(server, 0) + r["n"]
            else:
                by_tool[r["tool_name"] or "<unknown>"] = r["n"]
        by_skill = {}
        for r in conn.execute(
            f"SELECT skill, skill_command, COUNT(*) AS n FROM events"
            f"{w} AND type = 'skill_invoke' GROUP BY skill, skill_command", wargs,
        ):
            label = skill_label(r["skill"], r["skill_command"])
            by_skill[label] = by_skill.get(label, 0) + r["n"]
        per_user, idle_accounts = [], []
        if team:
            rows = conn.execute(
                f"SELECT {PERSON_SQL} AS person, COUNT(DISTINCT session_id) AS sessions,"
                " SUM(CASE WHEN type = 'tool_call' THEN 1 ELSE 0 END) AS tool_calls,"
                " SUM(CASE WHEN type = 'skill_invoke' THEN 1 ELSE 0 END) AS skill_calls"
                f" FROM events{w} AND ({PERSON_SQL}) IS NOT NULL GROUP BY person"
                " ORDER BY tool_calls DESC, sessions DESC", wargs,
            ).fetchall()
            tops = {}
            for r in conn.execute(
                f"SELECT {PERSON_SQL} AS person, skill, COUNT(*) AS n FROM events"
                f"{w} AND ({PERSON_SQL}) IS NOT NULL AND type = 'skill_invoke' AND skill IS NOT NULL"
                " GROUP BY person, skill", wargs,
            ):
                tops.setdefault(r["person"], []).append((r["skill"], r["n"]))
            # display name per person, for the report table
            display = {}
            for r in conn.execute(
                f"SELECT {PERSON_SQL} AS person, name, COUNT(*) AS n FROM events"
                f"{w} AND name IS NOT NULL GROUP BY person, name ORDER BY person, n DESC", wargs,
            ):
                display.setdefault(r["person"], r["name"])
            per_user = [{"name": r["person"], "display": display.get(r["person"]),
                         "email": r["person"] if is_email(r["person"]) else None,
                         "sessions": r["sessions"] or 0,
                         "tool_calls": r["tool_calls"] or 0, "skill_calls": r["skill_calls"] or 0,
                         "top_skills": sorted(tops.get(r["person"], []), key=lambda x: -x[1])[:3]}
                        for r in rows]
            # every known account, so accounts without a configured mailbox
            # (often the ones a manager most needs to see) are listed too
            accounts = conn.execute("SELECT username FROM users ORDER BY username").fetchall()
            active = {r["person"] for r in rows}
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
        "by_tool": _sorted(by_tool)[:15],
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


def _report_bar_card(title, rows, color):
    return f"<div {_REPORT_CARD}><div {_REPORT_TTL}>{esc_html(title)}</div>{_report_rows(rows, color)}</div>"


def _person_label(u):
    """Display name + email when the collector reported a Devin account."""
    display = u.get("display") or ""
    email = u.get("email") or ""
    if display and email:
        return f"{display} ({email})"
    if display:
        return f"{display} ({u['name']})"
    return u["name"]


def _team_overview_card(rep):
    rows = [[_person_label(u), u["sessions"], u["tool_calls"], u["skill_calls"],
             "，".join(f"{s} {n}" for s, n in u["top_skills"]) or "-"] for u in rep["per_user"]]
    body = _report_table(
        [("用户", 0), ("会话", 1), ("工具调用", 1), ("Skill 调用", 1), ("主要 Skill", 0)], rows)
    if rep["idle_accounts"]:
        body += ('<div style="color:#9ca3af;font-size:12px;margin-top:10px">本窗口无数据账号：'
                 + esc_html("、".join(rep["idle_accounts"])) + "</div>")
    return f"<div {_REPORT_CARD}><div {_REPORT_TTL}>人员概览</div>{body}</div>"


def _report_body(rep, overview=False):
    parts = []
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
    if who is None:
        return f"[团队工具使用{win['kind']}] {win['subject']}"
    return f"[工具使用{win['kind']}] {who} · {win['subject']}"


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


@app.post("/admin/users/{username}/email")
def admin_set_email(username: str, body: EmailBody, user: dict = Depends(require_admin)):
    """Report mailbox for accounts whose login name is not an email.

    Data-backed accounts use their address as both login name and mailbox, so
    changing it means renaming the account (which also moves its records).
    """
    if is_email(username):
        raise HTTPException(status_code=400,
                            detail="该账号以邮箱为登录名，请修改账号邮箱（会同步迁移历史数据）")
    email = norm_email(body.email)
    if not email:
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


def report_recipient(row):
    """Mailbox a person's reports go to. Data-backed accounts have no separate
    mailbox field: the account name is the address."""
    if not row:
        return ""
    return row["email"] or (row["username"] if is_email(row["username"]) else "")


@app.post("/admin/users/{username}/send_report")
def admin_send_report(username: str, user: dict = Depends(require_admin)):
    row = get_user(username)
    if not row:
        raise HTTPException(status_code=404, detail="用户不存在")
    recipient = report_recipient(row)
    if not recipient:
        raise HTTPException(status_code=400, detail="该账号未配置邮箱")
    try:
        status, reason = _send_user_report(username, recipient, _report_window("manual"))
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
            "SELECT username, role, email FROM users WHERE role = 'admin' ORDER BY username"
        ).fetchall()
    admins = [(a, report_recipient(a)) for a in admins]
    admins = [(a, to) for a, to in admins if to]
    if not admins:
        return "skipped", "没有配置邮箱的管理员", []
    rep = compute_report(None, win)
    if rep["tool_calls"] + rep["skill_calls"] == 0:
        return "skipped", "全团队窗口内无数据", []
    subject = report_subject(rep)
    html = build_team_report_html(rep)
    results = []
    for a, to in admins:
        try:
            send_html_mail(to, subject, html)
            results.append({"to": to, "status": "sent", "reason": ""})
        except Exception as exc:
            results.append({"to": to, "status": "failed",
                            "reason": f"{type(exc).__name__}: {exc}"})
    status = "sent" if any(r["status"] == "sent" for r in results) else "failed"
    return status, "", results


@app.post("/admin/send_team_report")
def admin_send_team_report(user: dict = Depends(require_admin)):
    try:
        status, reason, recipients = _send_team_report(_report_window("manual"))
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"发送失败: {_smtp_error_detail(exc)}")
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
            "SELECT username, role, email FROM users WHERE status = 'active' ORDER BY username"
        ).fetchall()
    results = []
    for r in users:
        recipient = report_recipient(r)
        if not recipient:
            results.append({"user": r["username"], "status": "skipped", "reason": "没有邮箱"})
            continue
        try:
            status, reason = _send_user_report(r["username"], recipient, win)
            results.append({"user": r["username"], "status": status, "reason": reason})
        except RuntimeError as exc:
            results.append({"user": r["username"], "status": "failed", "reason": str(exc)})
        except Exception as exc:
            results.append({"user": r["username"], "status": "failed",
                            "reason": f"{type(exc).__name__}: {exc}"})
    # never let a team-report error escape: the scheduler must still persist
    # last_period, or the next tick would re-send every personal report
    try:
        team_status, team_reason, team_recipients = _send_team_report(win)
        team = {"status": team_status, "reason": team_reason, "recipients": team_recipients}
    except Exception as exc:
        team = {"status": "failed", "reason": f"{type(exc).__name__}: {exc}", "recipients": []}
    return {"results": results, "team": team}


@app.post("/admin/send_all_reports")
def admin_send_all(user: dict = Depends(require_admin)):
    return _do_send_all(_report_window("manual"))


class SmtpBody(BaseModel):
    host: Optional[str] = None
    port: Optional[int] = None
    password: Optional[str] = None
    security: Optional[str] = None
    email_allowlist: Optional[str] = None


class TestToBody(BaseModel):
    to: str


@app.get("/admin/smtp")
def admin_get_smtp(user: dict = Depends(require_admin)):
    cfg = get_smtp_config()
    # 密码只写不可读：只返回是否已配置
    return {"host": cfg["host"], "port": cfg["port"], "sender": cfg["sender"],
            "password_set": bool(cfg["password"]), "security": cfg["security"],
            "email_allowlist": get_email_allowlist()}


@app.post("/admin/smtp")
def admin_set_smtp(body: SmtpBody, user: dict = Depends(require_admin)):
    updates = {}
    if body.host is not None:
        updates["host"] = body.host.strip()
    if body.port is not None:
        updates["port"] = body.port
    if body.password is not None:
        # 字段存在但为空 = 清除密码（改用免认证中继）；字段缺省 = 保持不变
        updates["password"] = body.password
    if body.security is not None:
        if body.security not in ("starttls", "ssl", "none"):
            raise HTTPException(status_code=400, detail="security 必须是 starttls/ssl/none")
        updates["security"] = body.security
    if updates:
        set_smtp_settings(updates)
    if body.email_allowlist is not None:
        set_email_allowlist(body.email_allowlist)
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
    cfg = {"daily_enabled": False, "daily_time": "09:00",
           "weekly_enabled": False, "weekly_day": 0, "weekly_time": "09:00",
           "last_daily": "", "last_weekly": "", "last_sent": ""}
    with closing(connect()) as conn:
        rows = {k: v for k, v in conn.execute("SELECT key, value FROM settings WHERE key LIKE 'report_%'")}
        _migrate_schedule_settings(conn, rows)
        for k, v in conn.execute("SELECT key, value FROM settings WHERE key LIKE 'report_%'"):
            key = k[len("report_"):]
            if key in ("daily_enabled", "weekly_enabled"):
                cfg[key] = v == "1"
            elif key == "weekly_day":
                try:
                    cfg[key] = int(v)
                except ValueError:
                    pass
            elif key in cfg:
                cfg[key] = v
    return cfg


def _migrate_schedule_settings(conn, rows):
    """Old single-mode schedule (report_mode/day/time/last_period) -> the
    split daily/weekly schedules. Runs once: the old keys are removed after
    copying, so later ticks see no legacy rows and never re-migrate."""
    mode = rows.get("report_mode")
    if mode is None:
        return
    updates = {}
    if mode == "daily":
        updates = {"daily_enabled": "1", "daily_time": rows.get("report_time", "09:00")}
    elif mode == "weekly":
        updates = {"weekly_enabled": "1", "weekly_day": rows.get("report_day", "0"),
                   "weekly_time": rows.get("report_time", "09:00")}
    if mode in ("daily", "weekly") and rows.get("report_last_period"):
        updates[f"last_{mode}"] = rows["report_last_period"]
    for k, v in updates.items():
        conn.execute(
            "INSERT INTO settings (key, value) VALUES (?, ?)"
            " ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (f"report_{k}", str(v)),
        )
    conn.execute("DELETE FROM settings WHERE key IN"
                 " ('report_mode', 'report_day', 'report_time', 'report_last_period')")
    conn.commit()


def set_schedule_settings(updates):
    with closing(connect()) as conn:
        for k, v in updates.items():
            conn.execute(
                "INSERT INTO settings (key, value) VALUES (?, ?)"
                " ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (f"report_{k}", str(v)),
            )
        conn.commit()


def _schedule_period(now, kind):
    if kind == "weekly":
        iso = now.isocalendar()
        return f"{iso[0]}-W{iso[1]}"
    return now.strftime("%Y-%m-%d")


def _scheduler_tick():
    cfg = get_schedule_config()
    now = datetime.now()
    for kind in ("daily", "weekly"):
        if not cfg[f"{kind}_enabled"]:
            continue
        # weekly fires on the configured weekday or any later day of the same
        # week, so a slot missed while the server was down is caught up instead
        # of silently skipped; last_<kind> still limits each schedule to one
        # send per period
        if kind == "weekly" and now.weekday() < cfg["weekly_day"]:
            continue
        try:
            hh, mm = (cfg[f"{kind}_time"] or "09:00").split(":")[:2]
            sched = now.replace(hour=int(hh), minute=int(mm), second=0, microsecond=0)
        except (ValueError, AttributeError):
            continue
        if now < sched:
            continue
        period = _schedule_period(now, kind)
        if cfg[f"last_{kind}"] == period:
            continue
        outcome = _do_send_all(_report_window(kind))
        set_schedule_settings({f"last_{kind}": period, "last_sent": now_iso()})
        team = outcome.get("team", {})
        log.info("scheduled %s report run: sent=%s skipped=%s failed=%s team=%s recipients=%s",
                 kind,
                 len([r for r in outcome["results"] if r["status"] == "sent"]),
                 len([r for r in outcome["results"] if r["status"] == "skipped"]),
                 len([r for r in outcome["results"] if r["status"] == "failed"]),
                 team.get("status"), len(team.get("recipients", [])))
        if team.get("status") == "skipped":
            log.warning("team report skipped: %s", team.get("reason"))
        for r in team.get("recipients", []):
            if r["status"] == "failed":
                log.warning("team report to %s failed: %s", r["to"], r["reason"])


def _report_scheduler():
    log.info("report scheduler started")
    while True:
        try:
            _scheduler_tick()
        except Exception as exc:
            log.error("report scheduler tick failed: %s: %s", type(exc).__name__, exc)
        time.sleep(60)


class ScheduleBody(BaseModel):
    daily_enabled: bool = False
    daily_time: Optional[str] = None
    weekly_enabled: bool = False
    weekly_day: Optional[int] = None
    weekly_time: Optional[str] = None


@app.get("/admin/schedule")
def admin_get_schedule(user: dict = Depends(require_admin)):
    return get_schedule_config()


@app.post("/admin/schedule")
def admin_set_schedule(body: ScheduleBody, user: dict = Depends(require_admin)):
    updates = {"daily_enabled": "1" if body.daily_enabled else "0",
               "weekly_enabled": "1" if body.weekly_enabled else "0"}
    for kind in ("daily", "weekly"):
        t = (getattr(body, f"{kind}_time") or "09:00").strip()
        if not re.match(r"^([01]?\d|2[0-3]):[0-5]\d$", t):
            raise HTTPException(status_code=400, detail="时间格式需 HH:MM")
        updates[f"{kind}_time"] = t
    if body.weekly_day is None or not 0 <= body.weekly_day <= 6:
        raise HTTPException(status_code=400, detail="day 必须是 0-6（周一=0）")
    updates["weekly_day"] = body.weekly_day
    set_schedule_settings(updates)
    return {"ok": True, **get_schedule_config()}


def skill_label(skill, command):
    # None is a legitimate value (browse calls carry no skill name) —
    # render it as a readable label instead of the string "null"
    return skill or (f"<{command}>" if command else "<unidentified>")


def _person_names(rows):
    """Map person key -> display name (the most frequently reported one)."""
    names = {}
    for r in rows:
        if r["person"] not in names:  # rows are ordered by count desc
            names[r["person"]] = r["name"]
    return names


# Hourly buckets are only shipped for the last few days — that is the only
# range where an hourly axis is finer than a daily one.
HOUR_SPAN_DAYS = 2


def compute_stats(user=None):
    flt = f" AND {PERSON_SQL} = ?" if user else ""
    args = [user] if user else []
    where_u = f" WHERE {PERSON_SQL} = ?" if user else ""
    person_not_null = f" AND ({PERSON_SQL}) IS NOT NULL"
    HOUR_CUT = (datetime.now(timezone.utc) - timedelta(days=HOUR_SPAN_DAYS)).strftime("%Y-%m-%dT%H")
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
            f"SELECT {PERSON_SQL} AS person, COUNT(*) AS n FROM events{where_u}"
            " GROUP BY person ORDER BY n DESC",
            args,
        ).fetchall()
        # display name per person (the Devin account name the collector reported)
        person_name_rows = conn.execute(
            f"SELECT {PERSON_SQL} AS person, name, COUNT(*) AS n FROM events"
            f" WHERE name IS NOT NULL{flt} GROUP BY person, name ORDER BY person, n DESC",
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
            f"SELECT {PERSON_SQL} AS person, CASE WHEN type = 'skill_invoke' THEN 'skill' ELSE tool_name END AS tool,"
            " COUNT(*) AS n FROM events"
            " WHERE type IN ('tool_call', 'skill_invoke')"
            f"{person_not_null} AND (type = 'skill_invoke' OR tool_name IS NOT NULL){flt}"
            " GROUP BY person, tool",
            args,
        ).fetchall()
        user_skill_rows = conn.execute(
            f"SELECT {PERSON_SQL} AS person, skill, skill_command, COUNT(*) AS n FROM events"
            f" WHERE type = 'skill_invoke'{person_not_null}{flt} GROUP BY person, skill, skill_command",
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
            f"SELECT {PERSON_SQL} AS person, CASE WHEN type = 'skill_invoke' THEN 'skill' ELSE tool_name END AS tool,"
            " substr(timestamp, 1, 10) AS day, COUNT(*) AS n FROM events"
            " WHERE type IN ('tool_call', 'skill_invoke')"
            f"{person_not_null} AND (type = 'skill_invoke' OR tool_name IS NOT NULL){flt}"
            " GROUP BY person, tool, day",
            args,
        ).fetchall()
        user_skill_day_rows = conn.execute(
            f"SELECT {PERSON_SQL} AS person, skill, skill_command, substr(timestamp, 1, 10) AS day,"
            " COUNT(*) AS n FROM events"
            f" WHERE type = 'skill_invoke'{person_not_null}{flt}"
            " GROUP BY person, skill, skill_command, day",
            args,
        ).fetchall()
        # Hourly buckets for the last couple of days. A one- or two-day
        # window collapses into a single daily bar, and the shape of a
        # working day is what people ask about at that range. Bounded so the
        # embedded stats payload stays small.
        where_hour = " WHERE timestamp >= ?" + (f" AND {PERSON_SQL} = ?" if user else "")
        hour_args = [HOUR_CUT] + args
        by_hour_rows = conn.execute(
            f"SELECT substr(timestamp, 1, 13) AS hour, COUNT(*) AS n FROM events{where_hour}"
            f"{person_not_null} GROUP BY hour ORDER BY hour", hour_args).fetchall()
        tool_hour_rows = conn.execute(
            "SELECT CASE WHEN type = 'skill_invoke' THEN 'skill' ELSE tool_name END AS tool,"
            " substr(timestamp, 1, 13) AS hour, COUNT(*) AS n FROM events"
            " WHERE type IN ('tool_call', 'skill_invoke')"
            " AND (type = 'skill_invoke' OR tool_name IS NOT NULL) AND timestamp >= ?"
            + (f" AND {PERSON_SQL} = ?" if user else "")
            + person_not_null + " GROUP BY tool, hour", hour_args).fetchall()
        skill_hour_rows = conn.execute(
            "SELECT skill, skill_command, substr(timestamp, 1, 13) AS hour, COUNT(*) AS n FROM events"
            " WHERE type = 'skill_invoke' AND timestamp >= ?"
            + (f" AND {PERSON_SQL} = ?" if user else "")
            + person_not_null + " GROUP BY skill, skill_command, hour", hour_args).fetchall()
        user_tool_hour_rows = conn.execute(
            f"SELECT {PERSON_SQL} AS person, CASE WHEN type = 'skill_invoke' THEN 'skill' ELSE tool_name END AS tool,"
            " substr(timestamp, 1, 13) AS hour, COUNT(*) AS n FROM events"
            " WHERE type IN ('tool_call', 'skill_invoke')"
            " AND (type = 'skill_invoke' OR tool_name IS NOT NULL) AND timestamp >= ?"
            + (f" AND {PERSON_SQL} = ?" if user else "")
            + person_not_null + " GROUP BY person, tool, hour", hour_args).fetchall()
        user_skill_hour_rows = conn.execute(
            f"SELECT {PERSON_SQL} AS person, skill, skill_command, substr(timestamp, 1, 13) AS hour,"
            " COUNT(*) AS n FROM events WHERE type = 'skill_invoke' AND timestamp >= ?"
            + (f" AND {PERSON_SQL} = ?" if user else "")
            + person_not_null + " GROUP BY person, skill, skill_command, hour", hour_args).fetchall()
        last = conn.execute(f"SELECT MAX(timestamp) AS ts FROM events{where_u}", args).fetchone()["ts"]
        tool_days, user_tools, user_skills, skill_days = {}, {}, {}, {}
        user_tool_days, user_skill_days = {}, {}
        by_skill = {}
        for r in by_skill_rows:
            # same label can come from several skill_command rows — sum them,
            # a dict comprehension would keep only the last row's count
            label = skill_label(r["skill"], r["skill_command"])
            by_skill[label] = by_skill.get(label, 0) + r["n"]
        for r in tool_day_rows:
            tool_days.setdefault(r["tool"], {})[r["day"]] = r["n"]
        for r in user_tool_rows:
            user_tools.setdefault(r["person"], {})[r["tool"]] = r["n"]
        for r in user_skill_rows:
            # same label can come from several skill_command rows — sum them,
            # a plain assignment would keep only the last row's count
            label = skill_label(r["skill"], r["skill_command"])
            per_user_skills = user_skills.setdefault(r["person"], {})
            per_user_skills[label] = per_user_skills.get(label, 0) + r["n"]
        for r in skill_day_rows:
            label = skill_label(r["skill"], r["skill_command"])
            per_label_days = skill_days.setdefault(label, {})
            per_label_days[r["day"]] = per_label_days.get(r["day"], 0) + r["n"]
        for r in user_tool_day_rows:
            user_tool_days.setdefault(r["person"], {}).setdefault(r["tool"], {})[r["day"]] = r["n"]
        for r in user_skill_day_rows:
            label = skill_label(r["skill"], r["skill_command"])
            per_label_days = user_skill_days.setdefault(r["person"], {}).setdefault(label, {})
            per_label_days[r["day"]] = per_label_days.get(r["day"], 0) + r["n"]

        by_hour = {r["hour"]: r["n"] for r in by_hour_rows}
        tool_hours, skill_hours = {}, {}
        user_tool_hours, user_skill_hours = {}, {}
        for r in tool_hour_rows:
            tool_hours.setdefault(r["tool"], {})[r["hour"]] = r["n"]
        for r in skill_hour_rows:
            label = skill_label(r["skill"], r["skill_command"])
            per_label_hours = skill_hours.setdefault(label, {})
            per_label_hours[r["hour"]] = per_label_hours.get(r["hour"], 0) + r["n"]
        for r in user_tool_hour_rows:
            per_user_hours = user_tool_hours.setdefault(r["person"], {}).setdefault(r["tool"], {})
            per_user_hours[r["hour"]] = per_user_hours.get(r["hour"], 0) + r["n"]
        for r in user_skill_hour_rows:
            label = skill_label(r["skill"], r["skill_command"])
            per_user_hours = user_skill_hours.setdefault(r["person"], {}).setdefault(label, {})
            per_user_hours[r["hour"]] = per_user_hours.get(r["hour"], 0) + r["n"]

    def _valid_day(day):
        return bool(day) and len(day) == 10 and day[4] == "-" and day[7] == "-"

    return {
        "total": total,
        "by_client": {(r["client_id"] or "<unknown>"): r["n"] for r in by_client},
        "by_user": {(r["person"] or "<unknown>"): r["n"] for r in by_user},
        "person_names": _person_names(person_name_rows),
        "by_tool": {r["tool"]: r["n"] for r in by_tool},
        "by_skill": by_skill,
        "by_day": {r["day"]: r["n"] for r in by_day if _valid_day(r["day"])},
        "tool_days": tool_days,
        "skill_days": skill_days,
        "user_tools": user_tools,
        "user_skills": user_skills,
        "user_tool_days": user_tool_days,
        "user_skill_days": user_skill_days,
        "by_hour": by_hour,
        "tool_hours": tool_hours,
        "skill_hours": skill_hours,
        "user_tool_hours": user_tool_hours,
        "user_skill_hours": user_skill_hours,
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
    if user["must_change_password"]:
        # the password was issued by someone else (invite mail, admin reset):
        # nothing else is reachable until it has been replaced
        return RedirectResponse("/login?change=1", status_code=302)
    markers = {
        "__USER__": _json_for_script(user),
        "__DATA__": _json_for_script(
            compute_stats(None if user["role"] == "admin" else user["name"])),
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
                "INSERT INTO users (username, password_hash, role, status, created_at)"
                " VALUES (?, ?, 'admin', 'active', ?)",
                ("SUPER_ADMIN", hash_password("SUPER_ADMIN"), now_iso()),
            )
            conn.commit()
            print(
                "已创建默认管理员 SUPER_ADMIN（密码 SUPER_ADMIN），请登录后尽快修改",
                file=sys.stderr,
            )
        except sqlite3.IntegrityError:
            pass
