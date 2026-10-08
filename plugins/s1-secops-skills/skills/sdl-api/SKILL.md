---
name: sdl-api
author: Prithvi Moses <prithvi.moses@sentinelone.com>
description: >-
  Use whenever the user wants to read data and manage configuration through the SentinelOne Singularity Data Lake (SDL) API: run queries or manage configuration files (parsers, dashboards, alerts, lookups, datatables) on a Scalyr/SDL/XDR tenant. Trigger on "SDL", "SDL API", "Singularity Data Lake", "Scalyr", "DataSet", or any "*.sentinelone.net/sdl/api/*" URL, and on the method names "query", "powerQuery", "facetQuery", "timeseriesQuery", "numericQuery", "configFiles", "configFile", "addConfigFile", "deleteConfigFile", "getFile", "putFile", "listFiles". Also trigger on "udoId", "config file", "/sdl/v2/graphql", or a console display string of the form "/dashboards/id/{number}/{name}". Also trigger on tasks like "run a powerQuery", "list configuration files", "edit my parser via API", "deploy a dashboard JSON", "compute the rate of failures over time", or anything involving SDL Bearer-token auth or the S1-Scope header. Uses the s1-secops-mcp sdl_* tools; host-only Python client.
---
# SentinelOne SDL API

<!-- CONFIG-FILE-ADDRESSING v1 -->
> **SDL config files: address by `udoId`, and do not trust a REST listing.**
> REST `listFiles` / `getFile` **cannot see** udoId-addressed `/dashboards/` files, so `getFile`
> returns `404` on a dashboard the console is displaying and the listing under-reports (measured on
> one tenant: REST 8, GraphQL 17, console 48 files). **If a listing disagrees with what the UI
> shows, the listing is wrong until proven otherwise**, change read path before concluding the
> object is missing or the token lacks scope. Use the GraphQL `configFiles` / `configFile` surface.
> A name-addressed `addConfigFile` to `/dashboards/` **creates a duplicate** instead of updating;
> address dashboards by `udoId` with `expectedVersion`. `content` is HJSON, not JSON. `S1-Scope`
> changes which files exist as far as the caller can tell.
> Full detail: [`sdl-api/references/config-file-graphql.md`](../sdl-api/references/config-file-graphql.md)

Covers the Singularity Data Lake API (query and configuration-file methods) through the `s1-secops-mcp` MCP tools, with a per-method reference and a host-only Python client and CLI.

The SDL API lives under `<console>/sdl` on the Management Console host. It speaks JSON over `Bearer` tokens (not `ApiToken`) and is the canonical path for querying the data lake and editing parsers/dashboards/alerts/lookups directly. Raw-log ingestion is via HEC (`hec_ingest`, see "Raw log ingestion" below).

> **Primary path: the `s1-secops-mcp` MCP tools.** Config files: `sdl_list_files`, `sdl_get_file`, `sdl_put_file`, `sdl_delete_file`; dashboards: `sdl_list_dashboards`, `sdl_get_dashboard`, `sdl_create_dashboard`, `sdl_save_dashboard_layout`, `sdl_share_dashboard`, `sdl_delete_dashboard`; queries: `powerquery_run`, `powerquery_enumerate_sources`, `powerquery_schema_discover`; ingest: `hec_ingest`. The server runs on the user's machine, so it reaches `*.sentinelone.net` where the Cowork sandbox cannot. It reads credentials from environment variables or the OS keychain and masks tokens in all output. If the tools are missing, the user has not connected the server: point them to the s1-secops-mcp README (`s1-secops-mcp/README.md` in the s1-secops-skills source repo, `mcp/s1-secops-mcp/README.md` in ai-siem; not shipped inside the plugin).
>
> **`SDLClient` and `scripts/sdl_cli.py` are host-only.** They run from Claude Code or a terminal on the user's machine, with the same environment variables or keychain entries. They cannot reach the tenant from the Cowork sandbox; never treat a proxy error there as an empty result, because that is how a fabricated schema gets into every downstream panel.

## IMPORTANT: the V1 query methods are deprecated; run queries through LRQ

The query methods on the host-only Python client (`query`, `powerQuery`, `facetQuery`, `timeseriesQuery`, `numericQuery`) wrap the V1 SDL endpoints (`/api/query`, `/api/powerQuery`, etc.) under `<console>/sdl`. Those endpoints are **deprecated and sunset on 2027-02-15** (also applies to the Deep Visibility `/web/api/v2.1/dv/events/pq` endpoint).

**The replacement is the LRQ API**, `POST /sdl/v2/api/queries` on the tenant's own **Management Console** host (e.g. `your-tenant.sentinelone.net`). Run it with the `powerquery_run` MCP tool, which handles auth, the forward tag, polling, cancel, slicing (`slices` plus `merge`) and raw-event `LOG` queries. The wire details live in the `mgmt-console-api` skill (`references/lrq-api.md`).

**SDL dashboard panels are rendered in the browser.** The panel JSON stores the query string and the console executes it when a user loads the dashboard. To validate a panel before or after deploy, run its query once with `powerquery_run` at the same `scope` the dashboard uses (see the `sdl-dashboard` skill).

| Task | Correct tool / path |
|------|------|
| PowerQuery programmatically (any range) | `powerquery_run` (LRQ at `POST /sdl/v2/api/queries` on the console host) |
| Raw events with every parsed field | `powerquery_run` with `queryType: "LOG"` |
| Field schema of a source | `powerquery_schema_discover` |
| Dashboard panel validation | `powerquery_run` per panel, at the dashboard's scope |
| Quick one-off stats under 24h (deprecated) | V1 methods on the host-only client still work until 2027-02-15 |
| Config files (parsers, dashboards, lookups) | `sdl_list_files` / `sdl_get_file` / `sdl_put_file` / `sdl_delete_file`, GraphQL-backed, see below |

## STOP: config files are GraphQL, not the REST `/api/*File` endpoints

`POST /sdl/v2/graphql` is the canonical config-file surface. The legacy REST endpoints
(`/api/listFiles`, `/api/getFile`, `/api/putFile`) are **incomplete** and must not be used to
decide whether a file exists.

Measured live on `<console>`: REST `listFiles` returned **1,914** paths, GraphQL
`configFiles` returned **2,264**. The entire 350-file gap is `/dashboards/` files that carry a
`udoId`, and REST `getFile` on any of them returns `success/noSuchFile`.

**Tripwire, non-negotiable.** If a file is not found by name, or a listing count disagrees with
what the console shows, do **not** conclude the file is absent. The REST listing is incomplete by
design. Re-check with `configFiles` before reporting "not found". A count in the 1,900s when the
console says 2,200-plus means you used the wrong surface.

### The `udoId` rule

The console's Configuration Files grid displays a dashboard as:

```text
/dashboards/id/6554761743556608/AI Usage
              ^^^^^^^^^^^^^^^^ this is the udoId, NOT a path segment
```

That display string is not a path. Reading it as one returns `no file exists at path`. Pass
`6554761743556608` as `udoId`; the file's real `name` is `/dashboards/AI Usage`.

`udoId` assignment is by **namespace** (verified live): only `/dashboards/` files get one.
`/lookups/`, `/datatables/`, `/logParsers/` and `/automaticLookups` all return `udoId: null` and
are addressed by name.

| Namespace | Address by | Write by name updates in place? |
|---|---|---|
| `/dashboards/` | `udoId` | **No, it creates a duplicate** |
| `/lookups/`, `/datatables/`, `/logParsers/`, `/automaticLookups` | `name` | Yes |

### Never write a dashboard by name

`addConfigFile(name:)` **updates in place** for a name-addressed file but **creates a duplicate**
for a dashboard. Create a dashboard by name once (there is no `udoId` yet), then address it by
`udoId` forever after. Skipping this is how one tenant accumulated **152 copies** of
`/dashboards/AI Usage` and 256 surplus dashboard files overall.

`expectedVersion` is enforced on **both** address forms; a stale value is rejected with
"There are conflicting changes in the file." and the stored content is left untouched. A
`deleteConfigFile` returning `null` with no `errors` array is **success**, not failure.

## Setup: credentials live in the OS keychain or the environment

There is no credentials file. The MCP server and the host-only Python client resolve each value from environment variables first, then the OS keychain (service `sentinelone-mcp`, account `<profile>:<NAME>`, profile from `S1_PROFILE`, default `default`). The user stores them once on their machine with `s1-secops-mcp setup` and checks them with `s1-secops-mcp status`.

- `S1_CONSOLE_URL` and `S1_CONSOLE_API_TOKEN` authorise every query and config method.
- `S1_SCOPE` is the default `S1-Scope` (`<accountId>` or `<accountId>:<siteId>`) when the token spans several sites or accounts. Most tools also take a per-call `scope`.
- `S1_HEC_INGEST_URL` and `S1_HEC_TOKEN` (the SDL Log Write Key) are needed only for raw log ingest.

If a tool reports a missing credential, stop and ask the user to run `s1-secops-mcp setup` on their machine. Never ask for a token in the chat and never write one to a file.

## Workflow

When the user asks for something involving the SDL API:

1. **Pick the operation.** Check `references/methods.md` for the semantics. For **configuration files**, use the GraphQL-backed MCP tools (`sdl_list_files`, `sdl_get_file`, `sdl_put_file`, `sdl_delete_file`), never the legacy REST ones, see the STOP section above and `references/config-file-graphql.md`. Raw-log ingestion is `hec_ingest`. For **queries**, use `powerquery_run` (LRQ); the V1 query methods are deprecated.
2. **Call the MCP tool.** On the user's host only (Claude Code or a terminal), `from sdl_client import SDLClient` gives the same operations as Python methods (`config_files`, `config_file`, `put_config_file`, `delete_config_file`, plus the deprecated V1 `query`, `power_query`, `facet_query`, `timeseries_query`, `numeric_query`), and `python scripts/sdl_cli.py <method> [args]` mirrors the client.
3. **Summarize for the user.** Don't dump raw JSON unless asked. For query results, prefer a concise table or CSV; for ingestion, confirm `bytesCharged` and the session ID; for config files, show path + version + (truncated) content.

## Schema discovery: the right way

Every SDL session must run live schema discovery for **every** data source it
will query, including the S1 internal sources `alert`, `vulnerability`,
`misconfiguration`, `asset`, `finding`, `ActivityFeed`, `Identity`, `indicator`
and every third-party source. Documented schemas drift between sessions due to
parser edits, reserved-field rewrites, and ingestion changes.

**`asset` and `ActivityFeed`, confirmed live schemas (126 and 41 fields respectively):**

- `dataSource.name='asset'`: **126 fields of rich device inventory** (OCSF class_uid 3004, category_name = 'Discovery'). Key fields: `device.agent.uuid`, `device.name`, `device.os.{name,version,type}`, `device.agent.{network_status,network_status_title,network_quarantine_enabled,is_active,is_decommissioned,is_uninstalled,scan_status,version,last_logged_in_user_name}`, `device.ip_external`, `device.hw_info.*`, `device.network_interfaces[N].*`, `severity_id`, `severity_`, `operation` (= OPERATION_UPSERT), `s1_metadata.{site_id,site_name,group_id,group_name}`. Use this for endpoint inventory panels and asset state tracking. Fields that do **not** exist: `entity.uid`, `entity_result.*`, `agent.health.online`, `agent.uuid` (use `device.agent.uuid`).
- `dataSource.name='ActivityFeed'`: **41 fields of Hyperautomation/management activity audit log** (`sca:RetentionType = 'ACTIVITY_LOG'`). Key fields: `activity_type` (numeric, NOT a string, e.g. 9207 = workflow execution event), `activity_uuid`, `primary_description`, `secondary_description`, `data.workflow_{id,name,execution_url}`, `data.{scope_id,scope_level,scope_name,site_name,user_id}`, `created_at`, `updated_at`, `account.{id,name}`, `site_id`, `context`. Useful for Hyperautomation workflow audit and compliance tracking. Not useful for threat hunting.

**The actual ingestion pipeline metrics source is `finding`** (`dataSource.category='metrics'`, `tag='ingestionHealth'`, fields: `batchCt`, `eventLatency.*`, `processor`, etc.); do not confuse it with `asset` or `ActivityFeed`.

**Why PowerQuery is the wrong tool for this:** PowerQuery's default projection
returns `timestamp + message` only. Naive `dataSource.name='alert' | limit 1`
hides the actual fields. `| columns *` returns HTTP 500. You can probe specific
fields with `| columns f1, f2` but you have to already know what to ask for,
which defeats the purpose of discovery.

**Use `powerquery_schema_discover` instead.** For each source returned by
`powerquery_enumerate_sources`, call `powerquery_schema_discover` with the exact
name as `dataSourceName` (`maxEvents` up to 50, `startTime` such as `"24h"` or `"7d"`, and the
`scope` you will query at). It returns sample events as full attribute sets, so
you see what fields the source actually carries, and it drops `logVolume`
metering rows (`excludedMeteringRows` reports how many). Issue the calls for
several sources in parallel in one turn. For a bigger sample, run
`powerquery_run` with `queryType: "LOG"`, `query: "dataSource.name='<name>'"`
and an `outputFile`, then read the field names from that file.

Persist the result with the Write tool, for example
`sdl_schemas_<YYYY-MM-DD>.json` in the outputs folder (or the project's schema
cache file), shaped as `{"<source>": ["field.a", "field.b", ...]}`. Do not
write a script that loops over sources from the sandbox; it cannot reach the
tenant.

If a discovery call fails (proxy, 401/403, timeout), report the failure.
A failure treated as an empty result produces a fabricated schema, causing
every downstream panel to silently query non-existent fields.

Host-only alternative (Claude Code or a terminal on the user's machine):
`SDLClient().query(filter=f"dataSource.name=='{source}'", max_count=2, start_time="24h")`
returns each match's `attributes` dict over the deprecated V1 endpoint, and the
`mgmt-console-api` skill's `scripts/inspect_source.py` does the same over LRQ.

The `attributes` dict exposes nested arrays as flattened keys like
`resources[0].name` and `vulnerabilities[0].cve.uid`. Those flattened keys are
display-only; they are NOT valid PowerQuery `columns` paths. PowerQuery
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

## Raw log ingestion, simulating events for detection testing

Raw-log ingestion runs through the event collector (the `hec_ingest` tool; `POST {S1_HEC_INGEST_URL}/services/collector/raw` and `/event`).

**Auth is an SDL Log Write Key, carried in `S1_HEC_TOKEN`.** The Management Console API token, service user or personal, is refused: on identical requests the write key returns `HTTP 200 {"text":"Success","code":0}` and the console token returns `HTTP 400 {"text":"Missing S1-Scope header","code":5}`. Mint the key at Console > Singularity Data Lake > API Keys > Log Write Key; no API creates one. It is optional in config because only log ingest needs it.

**The ingest scope cannot be overridden.** A Log Write Key is minted for exactly one account or site and writes only there, so the key itself fixes the destination. No `S1-Scope` header is sent for log ingest, and sending one has no effect. To write elsewhere, use a key minted for that scope.

UAM alert ingest (`POST /v1/alerts` on the same host) and IOCs are a different path and still use the console API token (`S1_CONSOLE_API_TOKEN`); that client is documented with `mgmt-console-api`.

When injecting events into the data lake to validate a detection, these behaviours are confirmed live:

- **Use flat dotted keys, not nested JSON.** With `/event?isParsed=true`, nested OCSF such as `{"event":{"category":"firewall"}}` dropped `event.category` (read back null, since `event.*` is a reserved namespace). The flat key `{"event.category":"firewall"}` landed correctly. Flat dotted keys reliably populate arbitrary OCSF fields (`src.ip.address`, `dst.ip.address`, `threat.category`, ...) and even EDR-style S1QL column names (`EventType`, `TgtProcName`, `LogonResult`) as literal, queryable attributes. `dataSource.name` / `.category` / `.vendor` set via flat keys stick (e.g. `dataSource.category` stays `security`).
- **HEC data can drive all three custom-rule types.** On an AI-SIEM tenant, `events` and `correlation` STAR rules evaluate HEC-ingested data (both fired from HEC events in testing), not only EDR-agent telemetry, and `scheduled` PowerQuery rules run over the same data lake. So HEC ingest of flat-key events is a working way to end-to-end test any of the three custom detection rule types. See the Detection-as-Code playbook in `sdl-solutions`.

## Files in this skill

- `scripts/sdl_client.py`: host-only importable Python client (`SDLClient`). Reads credentials from environment variables or the OS keychain, retries with exponential backoff, exposes ergonomic method names.
- `scripts/sdl_cli.py`: host-only CLI runner: `python scripts/sdl_cli.py power-query "dataset='accesslog' | group count() by status" --start 1h`.
- `references/methods.md`: single per-method reference (parameters, defaults, response shape, gotchas) for the SDL query and configuration-file endpoints.
- `references/auth_and_limits.md`: key matrix, console-token rules, S1-Scope, leaky-bucket CPU rate-limit model, retry guidance, daily caps.

## Using the client (host only)

In Cowork and any MCP client, use the MCP tools listed at the top of this skill. The Python client below is for Claude Code or a terminal on the user's machine.

```python
import sys
sys.path.insert(0, "scripts")
from sdl_client import SDLClient

c = SDLClient()

# ---- Log read ----
# PowerQuery: best general-purpose tool
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

# ---- Configuration files (GraphQL) ----
# Parsers live under /logParsers/<name>: the SDL API also accepts /parsers/<name>
# but the Log Parsers UI only reads /logParsers/, so writes at /parsers/ are invisible
# in the console. Use /logParsers/<name> by default.
files = c.config_files()                      # [{"udoId":..., "name":"/foo", "version":7}, ...]

# Name-addressed files (/logParsers/, /lookups/, /datatables/, /automaticLookups)
parser = c.config_file(name="/logParsers/MyParser")   # {"name":..., "content":"...", "version":7, ...}
c.put_config_file(name="/logParsers/MyParser", content="// new parser body",
                  expected_version=parser["version"])
c.delete_config_file(name="/logParsers/Stale", expected_version=7)

# Dashboards are addressed by udoId: a name-addressed write creates a duplicate
dash = c.config_file(udo_id="96200328708096")
c.put_config_file(udo_id=dash["udoId"], content=new_dashboard_json,
                  expected_version=dash["version"])
```

## Authentication

Every request sets `Authorization: Bearer <token>`, and every method authenticates with `S1_CONSOLE_API_TOKEN`.

If the token has access to multiple sites or accounts, set `S1_SCOPE` (e.g. `"<account_id>:<site_id>"` for site scope, `"<account_id>"` for account scope) or pass `scope` per MCP call. The `S1-Scope` header is then added automatically.

A 401 with `error/client/noPermission` means the token is wrong or expired. SDL keys do not expire by default, but console user tokens do.

## Rate limits and retries

The MCP server and the Python client retry automatically on HTTP 429, 5xx, and SDL `status: error/server/backoff` (which can come back inside a 200), honouring `Retry-After`. Things to know up-front:

- **Query budget is a leaky bucket of CPU seconds.** When `cpuUsageSecondsToWait` shows in a 429, back off by that many seconds. `priority: "low"` (the default) gets a more generous bucket than `"high"`. See `references/auth_and_limits.md` for the bucket model.
- **From 19 March 2026, all query methods cap at 8 queries/sec per tenant.**
- **Per-IP cap, all SDL endpoints, from 10 September 2026: 60-request burst, 30 req/s refill** (was 1,600 / 800). Measured 2026-10-05 it was not yet enforced (40 req/s sustained on `/api/query`, 137 req/s bursts on `/api/listFiles`, all 200), but throttle to 30 req/s per egress IP anyway.
- **Concurrency cap:** 12 simultaneous requests per API key (non-query). This is what actually returns 429 today (`Too many concurrent requests` at 100 parallel calls). For loops, throttle in code.

For long-running ingest, use the binary truncated exponential backoff loop in `references/integration_patterns.md` rather than the client's default retries; it is designed to stop on `discardBuffer` and to slowly relax wait times after success.

## Destructive actions: confirm first

`sdl_delete_file` and `sdl_put_file` overwriting an existing file (Python: `delete_config_file(...)`, `put_config_file(content=...)`) can wipe a parser, dashboard, alert, or lookup table. Before any config-file write or delete:

- Run `sdl_get_file` first to read current `version` and content. Pass that version as `expectedVersion` on the write to fail-fast on a concurrent edit; a stale value is rejected with "There are conflicting changes in the file." on both address forms.
- Address a dashboard by `udoId`. A name-addressed write to an existing `/dashboards/` file creates a duplicate rather than updating it.
- For deletes, summarise the file name (and `udoId` for a dashboard) and get explicit confirmation. A `delete_config_file` returning `null` with no `errors` array is success.
- Keep a backup in the working directory before overwriting non-trivial parsers or dashboards.

There is no undo. Configuration files are versioned but accidental deletes still take effect immediately.

## Common high-value workflows

- **Hunt with PowerQuery.** Use `powerquery_run`, which runs LRQ at `POST /sdl/v2/api/queries` on your console host. LRQ is NOT reachable via the old SDL host (`xdr.<region>.sentinelone.net`). The host-only client's `c.power_query()` hits the deprecated V1 endpoint and should only be used for a quick ad-hoc one-off before 2027-02-15.
- **Promote a parser/dashboard.** `sdl_get_file` with `path: "/logParsers/Foo"` and the staging `scope` → `sdl_put_file` with the same path, the new content and `expectedVersion` on the production scope. The `expected_version` guard catches concurrent edits. (Parser path is `/logParsers/`, `/parsers/` is API-accepted but not UI-visible.) Promote a dashboard by `udo_id` on the target tenant, creating it by name only the first time.
- **Audit configuration drift.** `sdl_list_files`, then `sdl_get_file` by `path` for each name-addressed file and by `udoId` for each dashboard; diff against a checked-in copy.
- **Quick stats panel.** `powerquery_run` with `... | group n=count() by srcIp | sort -n | limit 20` returns the top offenders fast.

For complex hunts and detection authoring use the `powerquery` skill for the query body, then run it with `powerquery_run`. For Mgmt Console resources (agents, threats, sites) use `mgmt-console-api`.

## Why the MCP tools and not a script in the sandbox

The Cowork sandbox blocks outbound HTTPS to `*.sentinelone.net`, so `sdl_client.py` run from the sandbox fails with a proxy error. That is not a credential issue: do not widen time windows or change query logic to debug it. Use the `s1-secops-mcp` tools, which run on the user's machine:

- `sdl_get_file` for reading SDL configuration files
- `sdl_put_file` for deploying parsers, dashboards, alerts, lookups
- `sdl_list_files` for listing SDL configuration inventory
- `powerquery_run` for executing PowerQueries against the Singularity Data Lake
- `hec_ingest` for raw log ingest

## Raw log ingest (learnings)

- **Auth is the SDL Log Write Key (`S1_HEC_TOKEN`), and the key fixes the scope.** The console API token is refused, `HTTP 400 {"text":"Missing S1-Scope header","code":5}` against the write key's `HTTP 200 {"text":"Success","code":0}`. A key writes only to the account or site it was minted for; no header overrides that. See "Raw log ingestion" above.
- **Three mandatory attributes for the XDR / OCSF view:** `dataSource.name`, `dataSource.vendor`, `dataSource.category`. Set all three as query params on `POST {HEC}/services/collector/event?isParsed=true&dataSource.name=...&dataSource.vendor=...&dataSource.category=...`. With only `dataSource.name` the events land under **All Data** but are invisible under the **XDR** view (XDR-scoped dashboards and rules show nothing, while all-data API queries still return them).
- **`dataSource.category` MUST be hard-coded to `security`. Do not derive it from the event's OCSF semantics.** This attribute is the ingestion routing category that places the event in the XDR / OCSF security pipeline where detections, STAR/scheduled rules, and Singularity Threat Intelligence IOC matching run. It is NOT the OCSF event category. Setting it from the log type (e.g. `network` for a firewall, `identity` for auth logs, `cloud` for CloudTrail) lands the event under All Data only: it stays fully queryable via all-data PowerQuery, but the security pipeline never evaluates it, so XDR detections and Threat Intelligence matches silently never fire. Always send `dataSource.category=security`. The OCSF `category_uid` / `category_name` inside the event body (e.g. `4` / `Network Activity` for a firewall) is a separate field and stays true to the event; only the ingest-time `dataSource.category` query param is pinned to `security`. Confirmed failure mode (2026-07): a Palo Alto OCSF event ingested with `dataSource.category=network` was queryable under All Data but produced no Threat Intelligence match; the fix is `dataSource.category=security`.
- **Singularity Threat Intelligence IOC matching, ingest requirements:** for a HEC-ingested OCSF event to be eligible for a TI match it must (1) carry `metadata.version` with any non-empty value, this is the only "is OCSF" check the TI engine performs, it does NOT validate the full OCSF schema; (2) be ingested with `dataSource.category=security` (see above); and (3) carry the IOC value in the OCSF field the engine matches on, for an IP IOC that is `src_endpoint.ip` (also checks `dst_endpoint.ip`). A match generates a NEW event with `dataSource.name='Threat Intelligence'` and `metadata.labels[0]='s1_threat_intelligence_indicator'`; the event Name is the source data-source name. Matching is asynchronous, allow several minutes before querying for the match log.
- **Backdating:** a top-level `time` field in **epoch SECONDS** backdates the event; a nested `event.time` (ms) does NOT. `isParsed=true` indexes the JSON keys directly as top-level attributes, so the field names you ingest are the field names you query (source-agnostic, no OCSF mapping needed).
- **Query-time timestamp:** on HEC `isParsed` events `event.time` is NOT populated; the queryable event time is `timestamp` (epoch NANOSECONDS). Use `timestamp` for `newest()/oldest()`, `strftime()` hour-of-day, and time math; convert to ms with `number(ts)/1000000`.
- **⚠ Every HEC POST also writes receive-time ingest-metering rows (`tag='logVolume'`) under the same `dataSource.name`. These are NOT copies of your events.** They carry the URL-supplied `dataSource.name` / `dataSource.vendor` plus `metric` (`logBytes` / `logEvents`), `value` and `path1`, and no body fields. Back-dated and non-back-dated POSTs both produce them. Live re-test 2026-10-03: a single POST of 100 events back-dated 72h indexed exactly 100 events at the back-dated times, plus 40 `logVolume` rows at receive time whose `logEvents` values summed to 100. Earlier notes (2026-07-29, 2026-08-09) called these "shadow copies" from a platform defect; that reading is superseded. Evidence, probes and the old ticket text: [references/hec-backdated-ingest.md](references/hec-backdated-ingest.md).

  Consequences when building synthetic test data:
  - Any unfiltered `dataSource.name='X'` count over a window that spans the ingest moment includes metering rows. Exclude them with `tag != 'logVolume'` (rows with no `tag` are kept).
  - A source you deliberately left EMPTY in the live window will read as non-empty unless `logVolume` is excluded, so validate SILENT / anti-join watchdogs on the filtered count.
  - A full-text `* contains '<nonce>'` search also matches your own `queryOutcome` / `audit` rows (the logged text of queries and config writes containing the nonce). Anchor on `dataSource.name` or a body field instead.
  - Assertions: count `real = count(tag != 'logVolume')`, or tag every event and count with `<tag> = *`. Use unfiltered counts only when you specifically need what a detection over that source sees.
