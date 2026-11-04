# tools-call-server

FastAPI backend that ingests the NDJSON event batches uploaded by the
`tools-call-collector` plugin and stores them in SQLite. Accounts are opened
from the data itself: the first record carrying an unseen email creates a local
account named after that address and mails it a random password once. Login
protects the dashboard and stats API — see
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
# first login: SUPER_ADMIN / SUPER_ADMIN — change it via 账号 → 修改我的密码
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

- **admin** — sees all data; manages accounts in 用户管理, configures the mail
  settings, sends reports. Any admin can grant or revoke the role on another
  account.
- **user** — sees only their own records, matched against the **person key**
  the collector reports (see [Who a record belongs to](#who-a-record-belongs-to)).

No admin can act on its own role, delete itself or disable itself, and the API
additionally refuses to remove the last remaining admin, so a database can
never end up with no one able to manage it.

### Accounts are provisioned from the data

Normal users are never created by hand. The first record carrying an unseen
email opens an account named after that address:

- a random password (`secrets.token_urlsafe(12)`) is generated and **only its
  PBKDF2 hash is stored**;
- the plain text is mailed there **once**, from a background worker — ingestion
  never blocks on SMTP and never fails because mail is unavailable;
- `must_change_password` is set, so the first login lands on a forced
  password-change screen and `/dashboard` / `/v1/stats` stay closed until the
  password has been replaced;
- the address is trimmed and lower-cased, so `Alice@Corp.com` and
  `alice@corp.com` are one person;
- a later record for a known address never sends another mail.

The login name **is** the report mailbox — one field, so the two cannot drift
apart. Records are matched by `COALESCE(email, user)`, which for such an account
is exactly its name.

**Allow-list** (用户管理 → 邮件发送设置 → 邮箱白名单): empty by default, which
accepts every address. Entries are domains (`sercomm.com`, `*@sercomm.com`) or
full addresses. Data from an address that is not listed is still ingested — it
just does not open an account and sends no mail. This bounds who an anonymous
`/v1/events` caller can make the server mail.

**Accounts created by hand** (用户管理 → 添加管理员) are always administrators —
a regular account only ever comes from the collector, so there is nothing to
fill in for one. The name may be a non-email alias (`ops`), because an
administrator sees everything anyway and is never matched to records by
address; such an alias needs a report mailbox, an email-shaped name does not
(the address *is* the mailbox). Leaving the password empty generates one and
mails it, and the generated value is returned once so it can still be handed
over when SMTP is down.

### 用户管理 tab

Admins get a dedicated 用户管理 tab. It follows the DeepSeek Harness web UI
language — hairline borders, layered radii, a dark primary button, quiet
secondary labels:

- **Overview cards** — 账号总数, 管理员, 已停用 (with a count of undelivered
  invite mails when there are any).
- **Table** — one row per account: name (= its mailbox), 角色, 状态, 采集数据
  (record count + last activity). Search by account/mailbox, filter by role.
- **添加管理员** — the only manual account action. Regular accounts appear by
  themselves when their data first arrives.
- **邮件发送设置** — the SMTP relay (Outlook), the invite allow-list and the
  report schedule sit at the bottom of the same tab: issuing a password and
  mailing a report both depend on this one configuration, so they belong next
  to the accounts they serve.
- **Row actions** — 编辑 opens a dialog for the account name (changing it
  migrates the account's records), role and — for alias admins only — the report
  mailbox. The `⋯` menu offers 发送报告, 重置密码并发送, 停用/启用账号 and
  删除账号.
- **重置密码并发送** — generates a brand-new random password and mails it. Only
  the hash is stored, so a resend always means a new password; the admin never
  types or sees it. The account is forced to change it again on next login.
- **停用 / 启用** — a disabled account cannot log in; its data is kept. Prefer
  this over deleting for people who leave.
- **删除账号** — removes the account only; collected records are kept.

**Access control** — the tab is hidden from regular users and never populated
for them; every `/admin/*` endpoint is guarded by `require_admin` (403 需要管理员
权限 otherwise). The role is re-read from the database on every request, so
demoting an admin takes effect immediately.

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
records can live in the same table. An account created from `ian_yin@sercomm.com`
sees exactly the records of that Devin account; the dashboard shows the reported
display name next to the key (`Ian Yin · ian_yin@sercomm.com`).

**Report recipients**: the account's mailbox — `users.email`, or the account
name when that is an address (which it is for every account provisioned from
data). Renaming an account (用户管理 → 编辑 → 账号) migrates both the `user`
field and the email of its matching records, so it stays linked to its data.

**Default admin**: on the first start (empty users table) the server creates
`SUPER_ADMIN` with password `SUPER_ADMIN` as an ordinary admin — no manual
step, no sqlite3 CLI needed. Log in, change that password via 账号 → 修改我的密码,
then manage every other account in 用户管理. The seed runs only while the users
table is empty, so a changed password survives restarts.

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

Users change their own password in the 账号 tab; the first login after an invite
or an admin reset is forced through that screen. Passwords are stored as
PBKDF2-SHA256 hashes (600k iterations, per-user salt).

## Email reports (Outlook)

Every account's mailbox is its own login name, so the 用户管理 tab needs no
separate address: send the user's stats as an email per user (发送报告) or to
everyone at once (发送报告 menu → 发送全部用户报告 — accounts without data in the
window are skipped; alias admins without a mailbox are skipped with the reason
没有邮箱). The report is email-client-safe HTML (no JS — renders in Outlook).

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

The sender (SMTP) configuration lives in the 用户管理 tab's 邮件发送设置 card
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
users are locked to their own records), 用户管理 (admin-only account management —
invites, roles, disabling, password resets; see [用户管理 tab](#用户管理-tab)),
账号 (change own password — the only thing a regular user can do there). Data is embedded server-side on load and
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
trend sparkline at the end. It carries **its own 起始 / 至 date inputs**, so the
table can cover a different span than the chart above it (默认跟随趋势窗口,
「跟随趋势」把两端重置回该窗口). The range is echoed in the header and in
the hint line. The first column stays put while the table scrolls
sideways, and the table sits in a fixed-height scroll box with a sticky header
so a hundred-row result does not stretch the page to several thousand pixels.
Clicking a Skill bar in the overview opens this page with that Skill
selected.

#### 调用趋势显示逻辑

三档筛选（用户 / 项目 / 时间窗口）决定这张图的每一种形态：

| 用户 | 项目 | 图表 | 说明 |
| --- | --- | --- | --- |
| 全部用户 | 全部项目 | **单条线** | 所有用户、所有 Skill 的合计，加 7 日均线 |
| 指定用户 | 全部项目 | 多条线 | 该用户每个 Skill 一条，按调用量排序 |
| 全部用户 | 指定项目 | 多条线 | 每位用过该 Skill 的用户一条，按调用量排序 |
| 指定用户 | 指定项目 | **单条线** | 加 7 日均线 |

- **显示** 选择器控制最多画几条：前 3 / 5 / 10 / **全部**，默认 5。实际数量不足时按实际画。
  单线形态下该控件禁用并置灰。
- **鼠标悬停到一条线上会高亮它**，其余线变灰；移开自动恢复。用的是 ECharts 的
  `emphasis.focus` + `blur` 原生状态，不重绘图表。悬停图例项同样生效。
- **时间粒度自动跟随窗口**：≤2 天按小时、≤90 天按天、更长按周。所有线共用同一组桶键，因此不会错位。
- **顶部三个指标始终与当前筛选一致**：总次数、每桶均值（日/小时/周均）、使用人数。
  环比对比的是"同一用户、同一项目"的上一个等长窗口。
- **「共 N 次」是当前筛选的总量**：选了具体项目就是该项目的量，不是全部项目的量。
- 选中单个用户时，「谁在用」卡片隐藏（否则只会显示那一个人）。
- **统计表有独立的时间范围**，与趋势窗口互不影响。

The period-over-period metric compares the same scope as the chart: the
previous window of the same user and item.

### 用户分析

Two charts and a table over the same 7/14/30/90-day/all window:

| 图表 | 回答 |
| --- | --- |
| 用户活跃热力图 | 谁在哪一天在忙 —— 用户 × 天，颜色越深调用越多 |
| 用户 × Skill 调用 | 每位用户的 Skill 构成绝对量 |

热力图是**完整矩阵**：每一位用户的每一天都有一个格子，**0 次调用也参与色阶**，
落在最浅一档。所以留白不再有歧义——浅色就是"几乎没有"，深色是"用得多"。
（之前的版本直接跳过 0 值的格子，把它们留成空白，既不在色阶里也看不出是 0。）

它的 **Skill 筛选**会进一步收窄范围：选中某个 Skill 后，只有真正用过它的日子
才会离开最浅档，剩下的仍以最浅色显示，直接回答"code-review 是谁在哪几天在跑"。

筛选只作用于热力图；用户 × Skill 图和概览表保持全量口径。

下面是 用户概览 表：总调用 / 活跃天数 / 日均 / 主要工具 / 主要 Skill，
可排序。「主要工具」会跳过 `skill` 合成桶——它已经单独出现在「主要 Skill」
一列里。

Both charts read from the per-day buckets (`user_tool_days`,
`user_skill_days`) instead of the all-time `user_tools` / `user_skills`, so
changing the window re-scopes the page at once.

### Admin / account endpoints

`GET /admin/users`, `POST /admin/users`, `POST /admin/users/{username}/password`
(issue a new random password and mail it), `POST /admin/users/{username}/status`
(active/disabled), `POST /admin/users/{username}/role`,
`POST /admin/users/{username}/email` (alias admins only),
`POST /admin/users/{username}/rename` (migrates the account's records),
`POST /admin/users/{username}/delete`,
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
