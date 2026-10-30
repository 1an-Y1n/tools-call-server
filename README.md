# tools-call-server

FastAPI backend that ingests the NDJSON event batches uploaded by the
`tools-call-collector` plugin and stores them in SQLite. Local-account login
with admin/user roles protects the dashboard and stats API — see
[Login (local accounts)](#login-local-accounts); `/v1/events` stays open for
collectors.

## Deploy on a fresh server

```bash
# 1. Get the code
git clone <your repo> && cd tools-call-server      # or: scp -r tools-call-server/ user@server:/opt/

# 2. Python 3.8+ and dependencies (venv is the production-standard way)
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt

# 3. Run
.venv/bin/python -m uvicorn server:app --host 0.0.0.0 --port 8420

# 4. Verify
curl http://<server-ip>:8420/health
# open http://<server-ip>:8420/dashboard  → redirected to /login
# first login: SUPER_ADMIN / SUPER_ADMIN — change it via 改密码 right away
```

The SQLite database is created automatically at `<server dir>/data/dashboard.db`
on first start (override with `TOOL_CALL_SERVER_DB`). It holds the event stats
and the user accounts (including the seeded default admin).

## Run locally (development)

```bash
python3 -m uvicorn server:app --host 0.0.0.0 --port 8420
```

Environment:

| Variable | Default | Description |
| --- | --- | --- |
| `TOOL_CALL_SERVER_DB` | `<server dir>/data/dashboard.db` | SQLite database file (events/rejects + user accounts) |
| `SESSION_SECRET` | auto | Signs session cookies; auto-generated to `data/session.secret` (chmod 600) on first start |
| `SESSION_MAX_AGE` | `28800` | Session lifetime in seconds (8 h) |
| `SMTP_HOST` | — (empty) | SMTP server for report emails — the internal relay or Office 365; configured in the GUI, env is only a fallback |
| `SMTP_PORT` | — (empty) | SMTP port; falls back to 25 when unset |
| `SMTP_USER` / `SMTP_PASSWORD` | — | Sender mailbox + its password (or app password); leave empty for relays without auth |
| `SMTP_SECURITY` | `starttls` | `starttls` / `ssl` / `none` |
| `SMTP_EHLO_NAME` | `tools-call-server` | EHLO hostname sent to the relay; a fixed value avoids smtplib's getfqdn() DNS lookups that can hang on hosts with broken reverse DNS |

## Login (local accounts)

`/dashboard` and `/v1/stats` require login; `/v1/events`, `/health` and
`/echarts` stay open for collectors and probes. Two roles:

- **admin** — sees all data; manages users in the dashboard's 用户管理 panel
  (add / reset password / change role / rename / delete)
- **user** — sees only their own records, matched against the `user` field the
  collector reports. Local usernames must equal that field (e.g. the employee
  ID `A003688`), otherwise a user's view stays empty.

**Default admin**: on the first start (empty users table) the server creates
`SUPER_ADMIN` with password `SUPER_ADMIN` — no manual step, no sqlite3 CLI
needed. Log in, change that password via 改密码 (账号 tab), then manage all
further users in the GUI (用户管理 panel: add / reset password / change role).
The seed runs only while the users table is empty, so a changed password
survives restarts.

Forgot the admin password? Generate a new hash and update the row directly:

```bash
HASH=$(.venv/bin/python hash_password.py '新密码')
.venv/bin/python -c "
import sqlite3, sys
c = sqlite3.connect('data/dashboard.db')
c.execute('UPDATE users SET password_hash = ? WHERE username = ?', (sys.argv[1], 'SUPER_ADMIN'))
c.commit()
print('已重置')
" "$HASH"
```

Users change their own password in the 账号 tab. Renaming (including self)
is admin-only, done with the pencil icon next to a username in the 用户管理
panel. Passwords are stored as PBKDF2-SHA256 hashes (600k iterations,
per-user salt).

Renaming a user migrates their historical event records to the new name
(login identity and data stay linked; the password is unchanged). Deleting a
user removes only the account — their historical event records are kept.

## Email reports (Outlook)

Admins can configure each user's mailbox in the 用户管理 panel (邮箱 link),
then send the user's stats as an email per user (发报告) or to everyone
configured at once (全部发送报告 — users without data in the window are
skipped). The report is email-client-safe HTML (no JS — renders in Outlook).

**Report content** (windowed, not all-history): a header line (window ·
sessions · tool calls), KPI cards, then

- 该改什么（预警 N 条）— zero-use skills (no call in the 14 days before the
  window end, last-used date shown) and cold MCP servers (no call in the
  window, last-used date shown). These only cover tools the server has
  *seen* — the collector reports invocations, not the installed inventory,
  so a tool that was never invoked cannot be listed.
- 按项目分布（会话数）— sessions per project (project_dir basename)
- MCP 调用（按 server 合并）— MCP tool calls merged by server
  (`mcp__<server>__<tool>` → `<server>`)
- Skill 调用 — skill invocation counts
- 内置工具 Top 15 — builtin (non-MCP) tool calls

**Team aggregate report**: 发送团队报告 (and every scheduled / bulk run)
additionally sends one team report to **every admin with a configured
mailbox** — the same sections computed team-wide plus a 人员概览 table
(user → sessions / tool calls / skill calls / top skills) and a list of
known accounts with no data in the window. It is the manager's one-email
status view; each team member still receives their own personal report.

**Windows**: scheduled 每周 covers the previous complete ISO week
(Mon–Sun, server-local time, e.g. `2026-W43 (10-19 ~ 10-25)` in the
subject); scheduled 每天 covers yesterday; manual sends cover the last
7 days. The subject includes the window and the warning count
(（预警 N 条）).

The sender (SMTP) configuration lives in the 账号 tab's 邮件发送设置 card
(admin-only): server / port / security (STARTTLS default, SSL, none) /
sender mailbox, plus a 测试发送 button to verify. The sender address shown
in recipients' inboxes is the sender mailbox itself. The GUI has no
password field — the internal relay needs none; for authenticated Office
365 sending set `SMTP_PASSWORD` via env. Settings are stored in the DB and
override the `SMTP_*` environment variables (which remain as fallback
defaults). For Microsoft 365 the sender mailbox must allow SMTP AUTH — if
the tenant disables it, ask IT to enable SMTP AUTH, or use an app password
when MFA is on. Without any sender configured, the send endpoints return a
clear error.

**Internal relay deployment** (no auth): the company SMTP relay accepts
plain SMTP on port 25 from internal hosts without a password — configure
服务器 = relay address, 端口 = 25 (or leave empty, it falls back to 25),
安全方式 = 无加密, 账号 = your company mailbox (shown as sender), 密码
empty. Verify with 测试发送.

**Scheduled sending**: the 定时发送 row in the same card (admin-only)
enables automatic bulk reports — 每天 or 每周 (pick weekday) at a HH:MM
time in the server's local timezone. A background thread checks every
minute; each period (day / ISO week) is sent at most once, and a send
missed while the server was down is caught up on the next tick — for
weekly mode on any later day of the same ISO week (a week missed without
the server coming back up at all is skipped). Each run sends the per-user
reports plus the team report. The card shows the last auto-send time.

Plain HTTP is acceptable on a trusted internal network; put a TLS proxy in
front if the dashboard is reachable more widely.

## API

### `POST /v1/events`

Ingest one batch. Body: NDJSON — one JSON record per line (the same records the
plugin appends to its `events/*-calls.jsonl` files). Malformed lines are quarantined
into the `rejects` table; the rest are stored. Returns `{"accepted": N, "rejected": M}`.

The client only advances its upload cursor on a 2xx response, so a 4xx/5xx
(server error, bad request) leaves the data pending locally and the next
attempt retries.

### `GET /v1/stats`

Aggregated counts: total records, per-tool counts, per-skill counts, per-day counts.
Requires login; admins get all data, regular users get only their own records
(the dashboard's auto-refresh redirects to `/login` on a 401).

### `GET /dashboard`

HTML dashboard (light theme, ECharts served locally from `static/` — no CDN or
internet needed at view time; `GET /` redirects here). Layout: KPI cards on top
(total / clients / users / last timestamp), then tabs — 总览 (daily trend, tool
and skill counts, detail tables), Tool 分析 and Skill 分析 (daily drill-downs
filterable by 时间范围 × 用户 × tool/skill name with 7/14/30/90/180/365-day windows),
用户分析 (user × tool / user × skill stacked charts + tables; admins can pick
any user, regular users are locked to their own records), 账号 (change own
password; admins additionally get the 用户管理 panel). Data is embedded
server-side on load and refreshed via `/v1/stats` every 30 s (toggle) or on
demand. Requires login; the header shows the signed-in user with 登出.

### Admin / account endpoints

`GET /admin/users`, `POST /admin/users`, `POST /admin/users/{username}/password`,
`POST /admin/users/{username}/role`, `POST /admin/users/{username}/email`,
`POST /admin/users/{username}/send_report` (personal report, last 7 days),
`POST /admin/send_all_reports` (per-user reports + team report, last 7 days),
`POST /admin/send_team_report` (team report to all admins with a mailbox),
`GET/POST /admin/smtp`, `POST /admin/smtp/test`, `GET/POST /admin/schedule` —
admin role required. `POST /me/password` — any logged-in user.
`GET /login` / `POST /login` / `POST /logout` — open.

### `GET /health`

Liveness probe.

## Storage

Single SQLite file `data/dashboard.db` (gitignored, created on first start,
WAL mode; override with `TOOL_CALL_SERVER_DB`):

- `events` — both `tool_call` and `skill_invoke` records, split by the `type`
  column; indexed by `type`, `tool_name`, `session_id`, `timestamp`
- `rejects` — malformed upload lines
- `users` — local accounts: PBKDF2 password hashes, role, created_at
