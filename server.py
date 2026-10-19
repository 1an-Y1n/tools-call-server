"""tools-call-server: FastAPI backend for tools-call-collector uploads.

Ingests NDJSON batches (one JSON record per line, as appended by the plugin's
collector) into SQLite. No authentication: bind to localhost or put it behind
your own gateway/firewall if you expose it.
"""

import json
import os
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

SERVER_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("TOOL_CALL_SERVER_DB", SERVER_DIR / "data" / "tool-calls.db"))
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

app = FastAPI(title="tools-call-server")

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
"""


def migrate(conn):
    """Add columns that post-date an existing database (idempotent)."""
    existing = {r[1] for r in conn.execute("PRAGMA table_info(events)")}
    if "client_id" not in existing:
        conn.execute("ALTER TABLE events ADD COLUMN client_id TEXT")
    if "user" not in existing:
        conn.execute("ALTER TABLE events ADD COLUMN user TEXT")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_client ON events(client_id)")


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


def row_from_record(record, raw):
    collector = record.get("collector") or {}
    input_keys = record.get("input_keys")
    return (
        now_iso(),
        record.get("schema_version"),
        record.get("type"),
        record.get("timestamp"),
        record.get("client_id"),
        record.get("user"),
        record.get("session_id"),
        record.get("prompt_id"),
        record.get("project_dir"),
        record.get("host"),
        record.get("tool_name"),
        record.get("status"),
        json.dumps(input_keys, ensure_ascii=False) if isinstance(input_keys, list) else None,
        record.get("skill"),
        record.get("skill_command"),
        collector.get("name"),
        collector.get("version"),
        raw,
    )


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/v1/events")
async def ingest(request: Request):
    body = (await request.body()).decode("utf-8", errors="replace")
    if not body.strip():
        raise HTTPException(status_code=400, detail="empty body")

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
        except (json.JSONDecodeError, ValueError) as exc:
            rejects.append((now_iso(), line, str(exc)))

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


@app.get("/v1/stats")
def stats():
    return compute_stats()


def skill_label(skill, command):
    # None is a legitimate value (browse calls carry no skill name) —
    # render it as a readable label instead of the string "null"
    return skill or (f"<{command}>" if command else "<unidentified>")


def compute_stats():
    with closing(connect()) as conn:
        conn.row_factory = sqlite3.Row
        total = conn.execute("SELECT COUNT(*) AS n FROM events").fetchone()["n"]
        by_tool = conn.execute(
            "SELECT CASE WHEN type = 'skill_invoke' THEN 'skill' ELSE tool_name END AS tool,"
            " COUNT(*) AS n FROM events WHERE type IN ('tool_call', 'skill_invoke')"
            " AND (type = 'skill_invoke' OR tool_name IS NOT NULL) GROUP BY tool ORDER BY n DESC"
        ).fetchall()
        by_skill_rows = conn.execute(
            "SELECT skill, skill_command, COUNT(*) AS n FROM events WHERE type = 'skill_invoke'"
            " GROUP BY skill, skill_command ORDER BY n DESC"
        ).fetchall()
        by_client = conn.execute(
            "SELECT client_id, COUNT(*) AS n FROM events GROUP BY client_id ORDER BY n DESC"
        ).fetchall()
        by_user = conn.execute(
            "SELECT user, COUNT(*) AS n FROM events GROUP BY user ORDER BY n DESC"
        ).fetchall()
        tool_day_rows = conn.execute(
            "SELECT CASE WHEN type = 'skill_invoke' THEN 'skill' ELSE tool_name END AS tool,"
            " substr(timestamp, 1, 10) AS day, COUNT(*) AS n FROM events"
            " WHERE type IN ('tool_call', 'skill_invoke')"
            " AND (type = 'skill_invoke' OR tool_name IS NOT NULL) GROUP BY tool, day"
        ).fetchall()
        user_tool_rows = conn.execute(
            "SELECT user, CASE WHEN type = 'skill_invoke' THEN 'skill' ELSE tool_name END AS tool,"
            " COUNT(*) AS n FROM events"
            " WHERE type IN ('tool_call', 'skill_invoke') AND user IS NOT NULL"
            " AND (type = 'skill_invoke' OR tool_name IS NOT NULL) GROUP BY user, tool"
        ).fetchall()
        user_skill_rows = conn.execute(
            "SELECT user, skill, skill_command, COUNT(*) AS n FROM events"
            " WHERE type = 'skill_invoke' AND user IS NOT NULL GROUP BY user, skill, skill_command"
        ).fetchall()
        by_day = conn.execute(
            "SELECT substr(timestamp, 1, 10) AS day, COUNT(*) AS n FROM events"
            " GROUP BY day ORDER BY day DESC LIMIT 30"
        ).fetchall()
        skill_day_rows = conn.execute(
            "SELECT skill, skill_command, substr(timestamp, 1, 10) AS day, COUNT(*) AS n FROM events"
            " WHERE type = 'skill_invoke' GROUP BY skill, skill_command, day"
        ).fetchall()
        last = conn.execute("SELECT MAX(timestamp) AS ts FROM events").fetchone()["ts"]
        tool_days, user_tools, user_skills, skill_days = {}, {}, {}, {}
        for r in tool_day_rows:
            tool_days.setdefault(r["tool"], {})[r["day"]] = r["n"]
        for r in user_tool_rows:
            user_tools.setdefault(r["user"], {})[r["tool"]] = r["n"]
        for r in user_skill_rows:
            user_skills.setdefault(r["user"], {})[skill_label(r["skill"], r["skill_command"])] = r["n"]
        for r in skill_day_rows:
            skill_days.setdefault(skill_label(r["skill"], r["skill_command"]), {})[r["day"]] = r["n"]

    return {
        "total": total,
        "by_client": {(r["client_id"] or "<unknown>"): r["n"] for r in by_client},
        "by_user": {(r["user"] or "<unknown>"): r["n"] for r in by_user},
        "by_tool": {r["tool"]: r["n"] for r in by_tool},
        "by_skill": {skill_label(r["skill"], r["skill_command"]): r["n"] for r in by_skill_rows},
        "by_day": {r["day"]: r["n"] for r in by_day},
        "tool_days": tool_days,
        "skill_days": skill_days,
        "user_tools": user_tools,
        "user_skills": user_skills,
        "last_timestamp": last,
    }


DASHBOARD_PATH = Path(__file__).resolve().parent / "dashboard.html"
CHART_JS_PATH = Path(__file__).resolve().parent / "static" / "chart.umd.min.js"


@app.get("/", response_class=RedirectResponse)
def root():
    return RedirectResponse("/dashboard")


@app.get("/chart.js")
def chart_js():
    return Response(CHART_JS_PATH.read_bytes(), media_type="application/javascript")


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard():
    html = DASHBOARD_PATH.read_text(encoding="utf-8")
    html = html.replace("__DATA__", json.dumps(compute_stats(), ensure_ascii=False))
    html = html.replace("__GENERATED__", now_iso())
    return html
