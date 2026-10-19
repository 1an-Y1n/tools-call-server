# tools-call-server

FastAPI backend that ingests the NDJSON event batches uploaded by the
`tools-call-collector` plugin and stores them in SQLite. No authentication —
bind to localhost or put it behind your own gateway if you expose it.

## Deploy on a fresh server

```bash
# 1. Get the code
git clone <your repo> && cd tools-call-server      # or: scp -r tools-call-server/ user@server:/opt/

# 2. Python 3.10+ and dependencies (venv is the production-standard way)
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt

# 3. Run
.venv/bin/python -m uvicorn server:app --host 0.0.0.0 --port 8420

# 4. Verify
curl http://<server-ip>:8420/health
# open http://<server-ip>:8420/dashboard
```

The SQLite database is created automatically at `<server dir>/data/tool-calls.db`
on first start (override with `TOOL_CALL_SERVER_DB`).

## Run locally (development)

```bash
python3 -m uvicorn server:app --host 0.0.0.0 --port 8420
```

Environment:

| Variable | Default | Description |
| --- | --- | --- |
| `TOOL_CALL_SERVER_DB` | `<server dir>/data/tool-calls.db` | SQLite database file |

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

### `GET /dashboard`

HTML dashboard (dark theme, Chart.js): per-tool and per-skill daily drill-downs
(dropdowns + 7/14/30/90-day windows; only tools/skills present in the DB appear in
the dropdowns), Top 10 skills, overall skill/tool counts, daily trend, **user
dropdown** ("all users" overview capped at top 15, or a single user's tool / skill
breakdown), and summary cards (total / clients / users / last timestamp). Data is
embedded server-side on load and refreshed via `/v1/stats` every 30 s (toggle) or on
demand. Chart.js 4.4.1 is served locally from `static/` — no CDN or internet needed
at view time. `GET /` redirects here.

### `GET /health`

Liveness probe.

## Storage

Single SQLite table `events` (both `tool_call` and `skill_invoke` records, split by
the `type` column), plus `rejects` for malformed lines. Indexed by `type`,
`tool_name`, `session_id`, and `timestamp`.
>>>>>>> bd792d1 (init)
