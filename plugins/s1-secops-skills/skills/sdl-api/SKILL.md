---
name: sdl-api
author: Prithvi Moses <prithvi.moses@sentinelone.com>
description: Use whenever the user wants to read data and manage configuration through the SentinelOne Singularity Data Lake (SDL) API — run queries or manage configuration files (parsers, dashboards, alerts, lookups, datatables) on a Scalyr/SDL/XDR tenant. Trigger on "SDL", "SDL API", "Singularity Data Lake", "Scalyr", "DataSet", "xdr.us1.sentinelone.net" or any "*.sentinelone.net/api/*" URL, and on the method names "query", "powerQuery", "facetQuery", "timeseriesQuery", "numericQuery", "getFile", "putFile", "listFiles". Also trigger on tasks like "run a powerQuery", "list configuration files", "edit my parser via API", "deploy a dashboard JSON", "compute the rate of failures over time", or anything involving Log Read / Configuration Read / Configuration Write SDL keys, Bearer-token auth, or the S1-Scope header. Wraps every SDL method with a Python client and CLI.
---

# SentinelOne SDL API

Wraps the Singularity Data Lake API (query and configuration-file methods) with a pre-built Python client, a CLI runner, and a per-method reference.

The SDL API is distinct from the Management Console API. It speaks JSON over `Bearer` tokens (not `ApiToken`) and is the canonical path for querying the data lake and editing parsers/dashboards/alerts/lookups directly. Raw-log ingestion is via HEC (see the `mgmt-console-api` skill).

> **Sandbox proxy blocked?** If calls to `*.sentinelone.net` (SDL host or console host) fail with a connection or proxy error inside the Claude sandbox, use the `s1-secops-mcp` server instead. It runs locally via `node` and bypasses the sandbox proxy entirely. Setup: add it to `claude_desktop_config.json` (see `s1-secops-mcp/README.md`). The MCP server exposes `sdl_list_files`, `sdl_get_file`, `sdl_put_file`, and `sdl_delete_file` — running directly from your machine against the SDL API. Raw-log ingestion uses HEC (see `mgmt-console-api`), not this skill.

## IMPORTANT: query methods are deprecated — and LRQ is NOT available here

The query methods on this skill (`query`, `powerQuery`, `facetQuery`, `timeseriesQuery`, `numericQuery`) wrap the V1 SDL endpoints (`/api/query`, `/api/powerQuery`, etc.) at the centralized host `xdr.us1.sentinelone.net`. Those endpoints are **deprecated and sunset on 2027-02-15** (also applies to the Deep Visibility `/web/api/v2.1/dv/events/pq` endpoint).

**The LRQ API is NOT a replacement available through this skill.** LRQ runs at `POST /sdl/v2/api/queries` on the tenant's own **Management Console** host (e.g. `your-tenant.sentinelone.net`) — it is part of the Mgmt Console API surface, not the SDL API (`xdr.us1.sentinelone.net`). To run PowerQueries programmatically, use the **`mgmt-console-api`** skill which holds the LRQ runner, auth pattern, and slicing strategy.

**SDL dashboard panels do not use LRQ either.** Dashboard panel queries are executed by the SDL console's own built-in rendering engine when a user loads the dashboard in their browser. The panel JSON just stores the query string — no API call is needed. Do not attempt to test or run dashboard panel queries via LRQ.

| Task | Correct skill / path |
|------|------|
| PowerQuery programmatically (any range) | **`mgmt-console-api`** → LRQ at `POST /sdl/v2/api/queries` on console host |
| Dashboard panel queries | SDL console renders them in-browser — no API needed |
| Quick one-off stats under 24h (deprecated) | V1 methods on this skill still work until 2027-02-15 |
| `get_file` / `put_file` / `list_files` (parsers, dashboards, lookups) | **This skill** |

## Setup — configure credentials first

Drop a `credentials.json` file directly into your Cowork project folder with the keys you need:

```json
{
  "SDL_XDR_URL":          "https://xdr.us1.sentinelone.net",
  "S1_CONSOLE_API_TOKEN": "eyJ...your-token...",
  "SDL_CONFIG_WRITE_KEY": "0mXas6PD1Zvg..."
}
```

The plugin's SessionStart hook auto-discovers the file at the start of every session, so the SDL client picks it up with no preflight. To trigger a manual refresh:

```bash
bash scripts/bootstrap_creds.sh   # idempotent, returns the destination path
```

Each key type unlocks a specific set of methods (matrix below). The client picks the right key per method automatically; callers never hand-pick a token.

| Key | Methods unlocked |
|-----|-----------------|
| Log Read Access         | `query`, `numericQuery`, `facetQuery`, `timeseriesQuery`, `powerQuery` |
| Configuration Read      | All Log Read methods, plus `getFile`, `listFiles` |
| Configuration Write     | All of the above, plus `putFile` |
| `S1_CONSOLE_API_TOKEN` (mgmt-console JWT)  | All query + config methods; set `SDL_S1_SCOPE` if multi-site/account. Same JWT used by `S1Client`. (Legacy alias `SDL_CONSOLE_API_TOKEN` still recognised.) |

Environment variables (`SDL_XDR_URL`, `S1_CONSOLE_API_TOKEN`, etc.) still override the credentials file if set.

Before running anything, confirm `SDL_XDR_URL` is set and at least one key for the operation chain is present. If not, stop and ask the user to drop `credentials.json` into their Cowork project folder.

## Workflow

When the user asks for something involving the SDL API:

1. **Pick the method.** Check `references/methods.md` for the right call. For **configuration files** (`get_file`, `put_file`, `list_files`), this skill is the right tool. Raw-log ingestion is via HEC (see `mgmt-console-api`). For **queries**, use the V1 methods on this skill only for quick one-off stats under 24h; for anything programmatic or multi-day, switch to the **`mgmt-console-api`** skill and the LRQ API — LRQ is NOT available at the SDL API host (`xdr.us1.sentinelone.net`).
2. **Use the client.** `from sdl_client import SDLClient` then call the named method (`query`, `power_query`, `facet_query`, `timeseries_query`, `numeric_query`, `list_files`, `get_file`, `put_file`). The client picks the correct key, handles JSON encoding, retries 429/5xx/`error/server/backoff`, and returns parsed JSON. Note: `query` and `power_query` hit the deprecated V1 endpoints — they work until 2027-02-15 for quick lookups but should not be used for production query pipelines.
3. **For ad-hoc shots, use the CLI.** `python scripts/sdl_cli.py <method> [args]`. The CLI mirrors the client.
4. **Summarize for the user.** Don't dump raw JSON unless asked. For query results, prefer a concise table or CSV; for ingestion, confirm `bytesCharged` and the session ID; for config files, show path + version + (truncated) content.

## Schema discovery — the right way

Every SDL session must run live schema discovery for **every** data source it
will query — including the S1 internal sources `alert`, `vulnerability`,
`misconfiguration`, `asset`, `finding`, `ActivityFeed`, `Identity`, `indicator`
and every third-party source. Documented schemas drift between sessions due to
parser edits, reserved-field rewrites, and ingestion changes.

**`asset` and `ActivityFeed` — confirmed live schemas (126 and 41 fields respectively):**

- `dataSource.name='asset'` — **126 fields of rich device inventory** (OCSF class_uid 3004, category_name = 'Discovery'). Key fields: `device.agent.uuid`, `device.name`, `device.os.{name,version,type}`, `device.agent.{network_status,network_status_title,network_quarantine_enabled,is_active,is_decommissioned,is_uninstalled,scan_status,version,last_logged_in_user_name}`, `device.ip_external`, `device.hw_info.*`, `device.network_interfaces[N].*`, `severity_id`, `severity_`, `operation` (= OPERATION_UPSERT), `s1_metadata.{site_id,site_name,group_id,group_name}`. Use this for endpoint inventory panels and asset state tracking. Fields that do **not** exist: `entity.uid`, `entity_result.*`, `agent.health.online`, `agent.uuid` (use `device.agent.uuid`).
- `dataSource.name='ActivityFeed'` — **41 fields of Hyperautomation/management activity audit log** (`sca:RetentionType = 'ACTIVITY_LOG'`). Key fields: `activity_type` (numeric, NOT a string — e.g. 9207 = workflow execution event), `activity_uuid`, `primary_description`, `secondary_description`, `data.workflow_{id,name,execution_url}`, `data.{scope_id,scope_level,scope_name,site_name,user_id}`, `created_at`, `updated_at`, `account.{id,name}`, `site_id`, `context`. Useful for Hyperautomation workflow audit and compliance tracking. Not useful for threat hunting.

**The actual ingestion pipeline metrics source is `finding`** (`dataSource.category='metrics'`, `tag='ingestionHealth'`, fields: `batchCt`, `eventLatency.*`, `processor`, etc.) — do not confuse it with `asset` or `ActivityFeed`.

**Why PowerQuery is the wrong tool for this:** PowerQuery's default projection
returns `timestamp + message` only. Naive `dataSource.name='alert' | limit 1`
hides the actual fields. `| columns *` returns HTTP 500. You can probe specific
fields with `| columns f1, f2` but you have to already know what to ask for —
which defeats the purpose of discovery.

**Use the V1 `query` method instead.** It returns each match as the full event
JSON with every populated attribute keyed in an `attributes` dict. That's the
only built-in way to see what fields a source actually carries.

**Auth caveat:** the V1 `query` method requires Log Read permission. The
default credential chain is
`log_read_key → config_read_key → config_write_key → console_api_token`. If
your `credentials.json` has `SDL_CONFIG_WRITE_KEY` set but no
`SDL_LOG_READ_KEY`, the chain picks the config write key first — which does
NOT grant View Logs and returns
`HTTP 403: authorization token does not grant View logs permission`.

Force-clear the scoped keys so the chain falls through to the console JWT:

```python
from sdl_client import SDLClient
c = SDLClient()
c.keys["log_read_key"] = ""
c.keys["config_read_key"] = ""
c.keys["config_write_key"] = ""

schemas = {}
for source in all_sources_from_step1_enumeration:
    res = c.query(filter=f"dataSource.name=='{source}'", max_count=2, start_time="24h")
    matches = res.get("matches") or []
    if not matches:
        continue
    attrs = matches[0].get("attributes") or {}
    schemas[source] = sorted(attrs.keys())

import json, datetime
out = f"outputs/sdl_schemas_{datetime.date.today().isoformat()}.json"
json.dump(schemas, open(out, "w"), indent=2)
```

**Direct MCP tools bypass sandbox proxy entirely.**

The Cowork sandboxed shell blocks all outbound HTTPS to `xdr.us1.sentinelone.net`. Use the
s1-secops-mcp MCP tools instead, which run locally and bypass the proxy:

| Operation | s1-secops-mcp tool |
|---|---|
| PowerQuery | `mcp__s1-secops-mcp__powerquery_run` or `mcp__s1-secops-mcp__powerquery_schema_discover` |
| `put_file` / `get_file` / `list_files` | `mcp__s1-secops-mcp__sdl_put_file`, `mcp__s1-secops-mcp__sdl_get_file`, `mcp__s1-secops-mcp__sdl_list_files` |

All of these tools run on your local machine and make direct HTTPS calls to `xdr.us1.sentinelone.net`
without sandbox proxy interference. No fallback or workaround needed.

```python
# Example: use sdl_get_file MCP tool directly instead
import sys, subprocess, json
result = subprocess.run(["mdfind", "-name", "sdl_client.py"], capture_output=True, text=True)
sdk_dir = [p for p in result.stdout.strip().split("\n") if "ai-siem" in p][0].rsplit("/", 1)[0]
sys.path.insert(0, sdk_dir)
from sdl_client import SDLClient
c = SDLClient()
c.keys["log_read_key"] = c.keys["config_read_key"] = c.keys["config_write_key"] = ""
# SDLClient.query(...) / put_file(...) / get_file(...) here
```

A proxy error treated as an empty result produces a fabricated schema, causing every downstream panel to silently query non-existent fields.

The `attributes` dict exposes nested arrays as flattened keys like
`resources[0].name` and `vulnerabilities[0].cve.uid`. Those flattened keys are
display-only — they are NOT valid PowerQuery `columns` paths. PowerQuery
returns HTTP 500 on bracket-array indexing. For analytics over array fields,
either stay on V1 query or use `array_get(arr, 0)` inside a PowerQuery `let`.

**Trailing-underscore reserved-field rule:** Field names ending in `_`
(`severity_`, `status_`, `classification_`) are SDL's auto-rename when source
data carries a field colliding with an SDL reserved name. The underscored form
IS the canonical, queryable field. Numeric OCSF variants (`severity_id` 0-5,
`status_id`, `class_uid`) live alongside the underscored string fields.
Prefer numeric OCSF for filters; the string `severity_` is case-mixed
(`Critical` and `CRITICAL` co-exist) and will produce split columns in
`transpose`.

## Files in this skill

- `<project folder>/credentials.json` — credentials (set `SDL_XDR_URL` and the keys you need; see Setup above). Auto-discovered by the plugin's SessionStart hook.
- `scripts/bootstrap_creds.sh` — idempotent helper that copies workspace creds into the sandbox-local path. Wired to the plugin's SessionStart hook; safe to re-run manually.
- `scripts/sdl_client.py` — importable Python client (`SDLClient`). Picks the right key per method, retries with exponential backoff, exposes ergonomic method names.
- `scripts/sdl_cli.py` — CLI runner: `python scripts/sdl_cli.py power-query "dataset='accesslog' | group count() by status" --start 1h`.
- `references/methods.md` — single per-method reference (parameters, defaults, response shape, gotchas) for the SDL query and configuration-file endpoints.
- `references/auth_and_limits.md` — key matrix, console-token rules, S1-Scope, leaky-bucket CPU rate-limit model, retry guidance, daily caps.

## Using the client

```python
import sys
sys.path.insert(0, "scripts")
from sdl_client import SDLClient

c = SDLClient()

# ---- Log read ----
# PowerQuery — best general-purpose tool
res = c.power_query(
    query="dataset='accesslog' status >= 400 | group count() by status",
    start_time="1h",
)
# res = {"status": "success", "matchingEvents": ..., "columns": [...], "values": [[...], ...]}

# Raw event search
matches = list(c.iter_query(filter="error", start_time="15m", max_total=500))

# Top-N values
top_ips = c.facet_query(field="srcIp", filter="status >= 400", start_time="24h", max_count=20)

# Numeric / timeseries (1 query)
ts = c.timeseries_query(queries=[
    {"filter": "serverHost contains 'frontend'", "function": "count", "startTime": "1h", "buckets": 60}
])

# ---- Configuration files ----
# Parsers live under /logParsers/<name> — the SDL API also accepts /parsers/<name>
# but the Log Parsers UI only reads /logParsers/, so PUTs at /parsers/ are invisible
# in the console. Use /logParsers/<name> by default.
files = c.list_files()                        # {"status":"success","paths":["/foo", ...]}
parser = c.get_file("/logParsers/MyParser")   # {"status":"success","content":"...","version":7,...}
c.put_file("/logParsers/MyParser", content="// new parser body")
c.put_file("/logParsers/Stale", delete=True)
```

## Authentication

Every request sets `Authorization: Bearer <token>`. The client picks the key per method using these chains (first non-empty wins):

- `log_read`:    `log_read_key` → `config_read_key` → `config_write_key` → `console_api_token`
- `config_read`: `config_read_key` → `config_write_key` → `console_api_token`
- `config_write` (putFile): `config_write_key` → `console_api_token`

If a `console_api_token` is used and the user has access to multiple sites or accounts, set `s1_scope` (e.g. `"<account_id>:<site_id>"` for site scope, `"<account_id>"` for account scope). The client adds `S1-Scope` automatically when both conditions hold.

A 401 with `error/client/noPermission` means the token is wrong or expired. SDL keys do not expire by default, but console user tokens do.

## Rate limits and retries

The client retries automatically on HTTP 429, 5xx, and SDL `status: error/server/backoff` (which can come back inside a 200), honouring `Retry-After`. Things to know up-front:

- **Query budget is a leaky bucket of CPU seconds.** When `cpuUsageSecondsToWait` shows in a 429, back off by that many seconds. `priority: "low"` (the default) gets a more generous bucket than `"high"`. See `references/auth_and_limits.md` for the bucket model.
- **From 19 March 2026, all query methods cap at 8 queries/sec per tenant.**
- **Concurrency cap:** 12 simultaneous requests per API key (non-query). For loops, throttle in code.

For long-running ingest, use the binary truncated exponential backoff loop in `references/integration_patterns.md` rather than the client's default retries — it is designed to stop on `discardBuffer` and to slowly relax wait times after success.

## Destructive actions — confirm first

`put_file(delete=True)` and `put_file(content=...)` overwriting an existing path can wipe a parser, dashboard, alert, or lookup table. Before any `putFile` write or delete:

- Run `get_file` first to read current `version` and content. Pass that version as `expected_version` on the write to fail-fast on a concurrent edit (`error/client/versionMismatch`).
- For deletes, summarise the path and last-modified date and get explicit confirmation.
- Keep a backup in the working directory before overwriting non-trivial parsers or dashboards.

There is no undo. Configuration files are versioned but accidental deletes still take effect immediately.

## Common high-value workflows

- **Hunt with PowerQuery.** Use the **`mgmt-console-api`** skill, which holds the LRQ runner at `POST /sdl/v2/api/queries` on your console host. LRQ is NOT reachable via the SDL API (`xdr.us1.sentinelone.net`). This skill's `c.power_query()` hits the deprecated V1 endpoint and should only be used for a quick ad-hoc one-off before 2027-02-15.
- **Promote a parser/dashboard.** `get_file("/logParsers/Foo")` from staging → `put_file("/logParsers/Foo", content=..., expected_version=N)` on production. The `expected_version` guard catches concurrent edits. (Parser path is `/logParsers/` — `/parsers/` is API-accepted but not UI-visible.)
- **Audit configuration drift.** `list_files()` then `get_file()` for each path; diff against a checked-in copy.
- **Quick stats panel.** `facet_query(field="srcIp", filter="status >= 500", start_time="1h")` returns the top offenders fast.

For complex hunts and detection authoring use the `powerquery` skill for the query body, then call `c.power_query()` from this skill to execute it. For Mgmt Console resources (agents, threats, sites) use `mgmt-console-api`.


## Using s1-secops-mcp tools for direct SDL operations

If a direct bash call to sdl_client.py fails with a proxy error, use the s1-secops-mcp MCP
tools instead. They run on your local machine and bypass the sandbox proxy entirely:

- `mcp__s1-secops-mcp__sdl_get_file` for reading SDL configuration files
- `mcp__s1-secops-mcp__sdl_put_file` for deploying parsers, dashboards, alerts, lookups
- `mcp__s1-secops-mcp__sdl_list_files` for listing SDL configuration inventory
- `mcp__s1-secops-mcp__powerquery_run` for executing PowerQueries against the Singularity Data Lake

No Desktop Commander workaround is necessary when you use these tools.

This is not a credential issue. Do not widen time windows or change query logic to debug this.
