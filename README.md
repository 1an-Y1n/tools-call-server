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

- **admin** — sees all data; manages users in the dashboard's 用户管理 tab
  (add / reset password / change role / rename / delete)
- **user** — sees only their own records, matched against the **person key**
  the collector reports (see [Who a record belongs to](#who-a-record-belongs-to)).
  Local usernames must equal that key, otherwise a user's view stays empty.

### 用户管理 tab

Admins get a dedicated 用户管理 tab (between 用户分析 and 账号). It follows the
DeepSeek Harness web UI language — hairline borders, layered radii, a dark
primary button, quiet secondary labels — and replaces the old inline table with
`prompt()`/`confirm()` prompts:

- **Overview cards** — account count, admin count, accounts with a report mailbox.
- **Table** — one row per account with avatar, role tag, report mailbox
  (falling back to the collected Devin email, marked as such), and creation time.
  Search by username/email and filter by role.
- **Row actions** — 编辑 opens a dialog for username / mailbox / role, the
  `⋯` menu offers 发送报告, 重置密码 and 删除用户.
- **Dialogs** — add, edit, reset password and a shared confirmation dialog.
  Deleting asks for an explicit acknowledgement; a role change that would drop
  the last admin is refused by the API.
- **Feedback** — a toast confirms each action; form errors stay inline in the
  dialog. No native browser dialogs are used anymore.

The backend endpoints are unchanged (`/admin/users`, `.../password`,
`.../role`, `.../rename`, `.../email`, `.../send_report`, `.../delete`).

**Access control** — the tab is hidden from regular users and the panel is
never populated for them; every `/admin/*` endpoint is guarded by
`require_admin`, so a direct API call returns 403 需要管理员权限. The role is
re-read from the database on every request, so demoting an admin takes effect
immediately.

### Who a record belongs to

Each record carries the collector's `user` field (the local account name) and,
since collector v1.11.0, the Devin account it belongs to: `name` and `email`
(read from `devin auth status`; both are null when the collector cannot resolve
a Devin login, in which case the collector records nothing at all).

The server derives one **person key** per record:

```sql
COALESCE(email, user)
```

- a record with a Devin email belongs to that email — one person, even if
  several people share the same build account;
- an older record (collected before the Devin identity, or by a collector
  without a Devin login) keeps its local account name as the key.

Every aggregation, filter and report uses that expression, so old and new
records can live in the same table. A dashboard account named
`ian_yin@sercomm.com` sees exactly the records of that Devin account; the
dashboard shows the reported display name next to the key (`Ian Yin ·
ian_yin@sercomm.com`).

**Report recipients**: the mailbox configured in the 用户管理 tab wins; when
an account has none, the server falls back to the Devin email the collector
reported for that person — the address is already known, so it does not have to
be entered twice. Renaming a user (用户管理 tab → 编辑 → 用户名) migrates both
the `user` field and the email of the matching records, so the account stays
linked to its data.

**Default admin**: on the first start (empty users table) the server creates
`SUPER_ADMIN` with password `SUPER_ADMIN` — no manual step, no sqlite3 CLI
needed. Log in, change that password via 改密码 (账号 tab), then manage all
further users in the GUI (用户管理 tab: add / reset password / change role).
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
is admin-only, done from the 编辑 dialog in the 用户管理 tab. Passwords are
stored as PBKDF2-SHA256 hashes (600k iterations, per-user salt).

Renaming a user migrates their historical event records to the new name
(login identity and data stay linked; the password is unchanged). Deleting a
user removes only the account — their historical event records are kept.

## Email reports (Outlook)

Admins can configure each user's mailbox in the 用户管理 tab (编辑 dialog →
报告邮箱), then send the user's stats as an email per user (发送报告) or to
everyone configured at once (发送报告 menu → 发送全部用户报告 — users without
data in the window are skipped). An account with no configured mailbox falls
back to the Devin email the collector reported for that person; accounts with
neither are skipped with the reason 没有邮箱. The report is email-client-safe
HTML (no JS — renders in Outlook).

**Report content** (windowed, not all-history): a header line (window ·
sessions · tool calls), KPI cards, then

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
7 days. The subject includes the window.

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

**One save button for the whole card** — the SMTP config and the send
schedule are one user-facing card, so a single 保存设置 button writes both
(`POST /admin/smtp` + `POST /admin/schedule`). The two settings live in the
same `settings` table under different key prefixes (`smtp_*` / `report_*`),
so this is purely a front-end change — the endpoints are untouched.

Only the SMTP fields the admin actually edited are submitted, so saving the
schedule never writes stale form values over a config that changed
elsewhere (a second browser tab, the API). The stored SMTP password is
write-only and is never sent back, so saving the schedule cannot clear it.
If a schedule is enabled while the server address is empty, the save
succeeds but warns that the scheduled send will fail. 测试发送 saves the SMTP
half only (it must test the values just typed in) and leaves the schedule
untouched.

**Internal relay deployment** (no auth): the company SMTP relay accepts
plain SMTP on port 25 from internal hosts without a password — configure
服务器 = relay address, 端口 = 25 (or leave empty, it falls back to 25),
安全方式 = 无加密, 账号 = your company mailbox (shown as sender), 密码
empty. Verify with 测试发送.

**Scheduled sending**: the 定时发送 rows in the same card (admin-only,
saved by the same 保存设置 button) configure two **independent** schedules —
每天 (daily, yesterday's window) and 每周 (weekly, pick weekday, previous
complete ISO week), each with its own time and enable flag, so both can run
at once (stagger the times to avoid back-to-back mails). A background thread
checks every minute; each period (day / ISO week) is sent at most once per
schedule, and a send missed while the server was down is caught up on the
next tick — for weekly mode on any later day of the same ISO week (a week
missed without the server coming back up at all is skipped). Each run sends
the per-user reports plus the team report. The card shows the last send per
schedule. A pre-existing single-mode configuration (关闭/每天/每周) is migrated
automatically on first read.

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
The user dimension uses the [person key](#who-a-record-belongs-to)
(`COALESCE(email, user)`), and the payload adds `person_names` — a map from
person key to the display name the collector reported.
Hourly buckets (`by_hour`, `tool_hours`, `skill_hours`, `user_tool_hours`,
`user_skill_hours`) are included for the last two days only — see
[时间窗口与粒度](#时间窗口与粒度).
Requires login; admins get all data, regular users get only their own records
(the dashboard's auto-refresh redirects to `/login` on a 401).

### `GET /dashboard`

HTML dashboard (light theme, ECharts served locally from `static/` — no CDN or
internet needed at view time; `GET /` redirects here). Layout: KPI cards on top
(total / clients / users / last timestamp), then tabs — 总览 (skill-centric:
the total Skill 调用趋势, the per-skill trends of the six most used skills,
and the 最常用的 Skill ranking with a sortable table; a 7/14/30/90-day/all
window switch), 调用分析 (Skill-focused drill-down — 调用趋势, 谁在用 and a
统计表 over 时间 × 用户 × 项目), 用户分析 (activity heatmap with a Skill filter, a Skill breakdown, and a
per-user overview, see [用户分析](#用户分析); admins can pick any user, regular
users are locked to their own records), 用户管理 (admin-only account management, see
[用户管理 tab](#用户管理-tab)), 账号 (change own password; admins additionally
get the SMTP and schedule cards). Data is embedded server-side on load and
refreshed via `/v1/stats` every 30 s (toggle) or on demand. Requires login; the
header shows the signed-in user with 登出.

### Analysis tabs

The four analysis tabs share one chart theme (DSH neutral-bluish surfaces,
hairline axes, one brand blue and one skill green). Reading notes:

- **The `skill` bar is not a tool.** Skill invocations are counted as one
  `skill` bucket inside the tool statistics (`CASE WHEN type = 'skill_invoke'
  THEN 'skill'`). It is drawn in the skill green and labelled as such in the
  overview and the user table, so it is never mistaken for a built-in tool.
- **Values are read from the tooltip**, not from a label on every point — 35
  permanent labels on the overview trend were unreadable.
- **Every chart states its window.** The Skill ranking used to be all-time
  while the trend above it covered 14 days; the two numbers are now on the
  same window.
- **Clicking a bar drills in.** A bar in the overview's 调用分布 chart opens
  the matching Tool / Skill analysis tab with that item selected.
- The window ranking chart dims every entry except the selected one, so the
  position of the current item is visible at a glance.

### Skill first

Skill usage is what the dashboard is about, so it leads:

- **总览** shows the total Skill 调用趋势, one line per Skill for the six most
  used Skills, and the 最常用的 Skill ranking with a sortable table. Tool
  statistics are not on this page.
- **调用分析** defaults to the Skill dimension; the 工具 switch is still there
  for the occasional tool question, but nothing about the page is built around
  it.

To keep the number of tables down, the detail tables that used to sit under
the 用户分析 charts were removed — the same 用户 × 项目 numbers live in the
调用分析 统计表, where the filters apply.

### 时间窗口与粒度

The window and the axis granularity are separate, so the chart always shows
usable resolution:

| 窗口 | 粒度 |
| --- | --- |
| 1–2 天 | 按小时 |
| 3–90 天 | 按天 |
| 半年 / 一年 / 全部 | 按周 |

Hourly buckets need the raw timestamps, so `compute_stats` ships them for the
last two days only (`by_hour`, `tool_hours`, `skill_hours`, `user_tool_hours`,
`user_skill_hours`); everything longer is derived from the daily buckets. The
embedded stats payload grows from ~40 KB to ~53 KB.

### 调用分析 and the 统计表

Tool 分析 and Skill 分析 were two near-identical pages; they are now one
**调用分析** tab. Every filter applies to the whole page: 用户, 项目 (全部 or a
specific tool/skill) and 时间窗口 (1 to 365 days). "全部项目" aggregates over
the dimension, so the trend, the metrics and the table all work with or
without a specific item.

The **统计表** at the bottom answers "任意时间 × 用户 × 项目": users down the
rows, items across the columns, with row and column totals and a per-user
trend sparkline at the end. The first column stays put while the table scrolls
sideways, and the table sits in a fixed-height scroll box with a sticky header
so a hundred-row result does not stretch the page to several thousand pixels.
Clicking a Skill bar in the overview opens this page with that Skill
selected.

**The trend chart changes shape with the filters.** With 项目 set to 全部项目
it breaks the window down into the **five most used Skills**, one coloured
line each, so the shape of each Skill's usage is visible instead of a single
aggregate line — for 全部用户 and for a single user alike. Picking a specific
项目 returns to the single line. The 谁在用 chart is hidden when a single user
is selected — it would only ever show that one person.

The period-over-period metric compares the same scope as the chart: the
previous window of the same user and item.

### 用户分析

Two charts and a table over the same 7/14/30/90-day/all window:

| 图表 | 回答 |
| --- | --- |
| 用户活跃热力图 | 谁在哪一天在忙 —— 用户 × 天，颜色越深调用越多 |
| 用户 × Skill 调用 | 每位用户的 Skill 构成绝对量 |

The heatmap has a **Skill filter**. Left at 全部 Skill it shows every call;
picking one Skill narrows it to the days that person actually used that
Skill, which answers "code-review 是谁在哪几天在跑" directly. The filter
scopes the heatmap only — the stacked chart and the table keep the full
picture.

下面是 用户概览 表：总调用 / 活跃天数 / 日均 / 主要工具 / 主要 Skill，
可排序。「主要工具」会跳过 `skill` 合成桶——它已经单独出现在「主要 Skill」
一列里。

Both charts read from the per-day buckets (`user_tool_days`,
`user_skill_days`) instead of the all-time `user_tools` / `user_skills`, so
changing the window re-scopes the page at once.

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
