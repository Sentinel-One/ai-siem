---
name: mgmt-console-api
author: Prithvi Moses <prithvi.moses@sentinelone.com>
description: Use whenever the user wants to query, update, create, or act on a SentinelOne Management Console: threats, alerts, agents, sites, accounts, groups, exclusions, RemoteOps, Deep Visibility, Hyperautomation, Unified Alert Management (UAM), Purple AI, IOCs, or any other S1 Mgmt API resource. Trigger on "console", "query/update/create console", "SentinelOne", "S1", "Singularity", "UAM", "Purple AI", "/web/api/v2.1/...", S1 agent/threat/site IDs, or asks like "list endpoints", "triage alerts", "add note to alert", "create an IOC", "isolate endpoint", "run RemoteOps", "pull DV results". For alerts the PRIMARY API is GraphQL UAM at /web/api/v2.1/unifiedalerts/graphql; REST /cloud-detection/alerts is SECONDARY (older, cloud-detection scoped, int64 IDs). Defer to Purple MCP if the user says "purple mcp" or "mcp"; this skill is the backup then. Wraps the S1 Mgmt REST API (781 ops, 113 tags, v2.1) plus UAM GraphQL and Purple AI GraphQL, with a Python client, searchable index, and reversible tests.
---

# SentinelOne Management Console API

Wraps the SentinelOne Management Console API (Swagger 2.0, spec version 2.1, 781 operations) with a pre-built Python client, a compact endpoint index, and per-tag reference files.

> **Sandbox proxy blocked?** If calls to `*.sentinelone.net` fail with a connection or proxy error inside the Claude sandbox, use the `s1-secops-mcp` server instead. It runs locally on your machine via `node` and bypasses the sandbox proxy entirely. Setup: add it to `claude_desktop_config.json` (see `s1-secops-mcp/README.md`). The MCP server exposes all the tools in this skill, `s1_api_get`, `s1_api_post`, `purple_ai_alert_summary`, `uam_list_alerts`, `uam_get_alert`, `uam_add_note`, `uam_set_status`, with schemas validated against the live API. For natural-language Purple AI queries and AI investigations, use the Purple MCP (`mcp__purple-mcp__purple_ai`) directly; those operations require a browser-session teamToken that API tokens never obtain.
>
> **Load this skill BEFORE any console/UAM *write*, not just reads.** Add-note, set-analyst-verdict, set-status, assign, and IOC-create all run through the UAM `alertTriggerActions` mutation with a specific action-id + `OrFilterSelectionInput` shape (see `references/UNIFIED_ALERTS.md`): action ids are `S1/alert/addNote` / `analystVerdictUpdate` / `statusUpdate`, and the alert is targeted by `filter:{or:[{and:[{fieldId:"id",stringEqual:{value:<id>}}]}]}`, the alert id is the FILTER, never the action `id`. Hand-rolling this GraphQL from live schema introspection is the fast path to a wrong action-id/filter and a misleading empty result. Also: `alertTriggerActions` returns a success-shaped `ActionsTriggered` even when nothing changed, always re-query (`uam_get_alert`) to confirm the write landed.

## Setup: configure credentials first

Drop a `credentials.json` file directly into your Cowork project folder with the required fields:

```json
{
  "S1_CONSOLE_URL": "https://usea1-acme.sentinelone.net",
  "S1_CONSOLE_API_TOKEN": "eyJ...your-api-token...",
  "S1_HEC_INGEST_URL": "https://ingest.us1.sentinelone.net"
}
```

`S1_CONSOLE_URL` is the tenant console URL (no trailing slash, no `/web/api/v2.1`). `S1_CONSOLE_API_TOKEN` is an API User token from Settings → Users → Service Users in the S1 console. `S1_HEC_INGEST_URL` is the SentinelOne HEC ingest host (region-specific, look up yours in [SentinelOne Endpoint URLs by Region](https://community.sentinelone.com/s/article/000004961)) and is only required if you push alerts/indicators into UAM via the UAM Alert Interface.

The plugin's SessionStart hook auto-discovers the file at the start of every session, so all S1 scripts and CLIs find it without any preflight. To trigger a manual refresh:

```bash
bash scripts/bootstrap_creds.sh   # idempotent, returns the destination path
```

Environment variables (`S1_CONSOLE_URL`, `S1_CONSOLE_API_TOKEN`, `S1_HEC_INGEST_URL`, `S1_VERIFY_TLS`) still override the credentials file if set.

Before running anything, confirm credentials resolved. If not, stop and ask the user to drop `credentials.json` into their Cowork project folder.

## Workflow

When the user asks for something involving the S1 API, follow this pattern:

1. **Find the right endpoint.**
   - If the user's ask is verb-shaped ("list / count / isolate / hunt …") and you need orientation, read `references/CAPABILITY_MAP.md` first; it's a compact per-tag summary of what verbs each resource supports.
   - For a specific multi-step task ("threat triage", "endpoint isolation", "DV hunt"), `references/WORKFLOWS.md` has ready-to-adapt recipes.
   - Otherwise go straight to `scripts/search_endpoints.py` with a keyword matching the user's intent. It now ranks results by relevance (path segment hits + verb intent + tag) and supports synonyms ("isolate" → "disconnect", "endpoint" → "agent"). Add `--only-works` to restrict to endpoints confirmed reachable on this tenant by the most recent smoke test.
2. **Read the per-tag reference.** Open `references/tags/<Tag>.md` (names match the table in `references/TAG_INDEX.md`) to see full parameter lists, descriptions, required permissions, and response codes for that group. Only read the tag file(s) relevant to the task; don't read them all.
3. **Call the endpoint.** Either use `scripts/call_endpoint.py` for one-off calls, or import `S1Client` from `scripts/s1_client.py` in a Python script for anything that needs loops, joins, or transforms. For independent GETs, prefer `c.get_many([(path, params), ...])`; it fans out in parallel over the client's pooled connection and is ~3× faster than a sequential loop.
4. **Paginate correctly.** S1 list endpoints use cursor-based pagination. The client's `paginate()` and `iter_items()` handle this automatically; prefer them over manual `skip`/`limit` math, which caps at 1000 items.
5. **Summarize the result for the user.** Don't dump raw JSON unless asked. Prefer a short prose summary plus a table or CSV/XLSX if the volume warrants.

## GET vs POST: the rule you must follow

The S1 API uses **GET for every read operation**, listing, counting, and exporting. POST is only for actions and mutations. Violating this produces HTTP 404, not a permissions error, because the path simply does not exist.

**Read (always GET):**

| Intent | Correct endpoint |
|---|---|
| List agents | `GET /web/api/v2.1/agents` |
| Count agents | `GET /web/api/v2.1/agents/count` → `{"data":{"total":N}}` |
| List threats | `GET /web/api/v2.1/threats` |
| Count threats | `GET /web/api/v2.1/threats?countOnly=true` or check `pagination.totalItems` from any list call |
| Export threats to CSV | `GET /web/api/v2.1/threats/export` (no extra params required) |
| List sites / accounts / groups | `GET /web/api/v2.1/{sites,accounts,groups}` |
| Get system info | `GET /web/api/v2.1/system/info` |

**Write / action (POST/PUT/DELETE):**

- Agent actions (isolate, reconnect, uninstall, scan): `POST /web/api/v2.1/agents/actions/<action>`
- Threat actions (mitigate, verdict, fetch-file): `POST /web/api/v2.1/threats/<action>`
- Mutations (notes, exclusions, IOCs, custom rules): POST/PUT/DELETE on the relevant resource path

**Paths that do not exist; never call these:**

These paths return HTTP 404 and have never existed in the v2.1 spec. They are plausible-sounding guesses that are consistently wrong:

| Wrong path | Why you might guess it | Correct alternative |
|---|---|---|
| `POST /web/api/v2.1/agents/ids` | "query agents by IDs" | `GET /web/api/v2.1/agents?ids=<id1>,<id2>` |
| `POST /web/api/v2.1/threats/summary` | "get a threat summary/count" | `GET /web/api/v2.1/threats?countOnly=true` |
| `POST /web/api/v2.1/export/threats` | "export threats" | `GET /web/api/v2.1/threats/export` |
| `POST /web/api/v2.1/threats/count` | "count threats via POST" | `GET /web/api/v2.1/threats?countOnly=true` |
| `POST /web/api/v2.1/agents/summary` | "agent summary" | `GET /web/api/v2.1/agents/count` + `GET /web/api/v2.1/agents` |

If you are about to call `s1_api_post` for a read/count/export operation, stop and switch to `s1_api_get`. Before any `s1_api_post` call, confirm the path exists: `python3 scripts/search_endpoints.py "<keyword>"`, if the path does not appear, it does not exist.

## Schema gotchas: confirmed on live tenant

These are fields where the obvious guess is wrong. All verified against the live tenant.

The full request-body schema gotchas for Custom Detection / STAR rules, Saved Filters, and PowerQuery Scheduled Detections (the `queryType` / `queryLang` matrix, the `isLegacy=false` listing trap, confirmed CREATE / PUT / DELETE bodies, and the enable / disable endpoints) live in [references/detection-rules.md](references/detection-rules.md). Read it before composing any POST or PUT to `/cloud-detection/rules` or `/filters`.

### Alert notes: UAM GraphQL

`deleteAlertNote` has a 30-90 second propagation window after creation before it can be deleted. The mutation uses `alertNoteId`, not `noteId`:

```graphql
mutation del($nid: ID!) {
  deleteAlertNote(alertNoteId: $nid) { data { id } }
}
```

If you call this immediately after creating a note you will get "Alert Note with ID ... does not have mgmt_note_id set". Retry with backoff; the `unified_alerts.delete_alert_note()` helper does this automatically.

## Probing a new tenant

When starting on an unfamiliar tenant, run the non-destructive smoke test once:

```text
python scripts/smoke_test_queries.py --workers 12
```

It enumerates every GET plus a curated allow-list of read-only query POSTs, records which ones return 200/403/404/etc., and writes `references/tenant_capabilities.md` and `.json`. Useful for "what's this token actually allowed to do" and as a pre-sales capability snapshot. The sweep is read-only, no writes, no agent actions, so tenant start-state and end-state are identical.

## Files in this skill

- `<project folder>/credentials.json`: credentials (set `S1_CONSOLE_URL` and `S1_CONSOLE_API_TOKEN`; see Setup above). Auto-discovered by the plugin's SessionStart hook.
- `scripts/bootstrap_creds.sh`: idempotent helper that copies workspace creds into the sandbox-local path. Wired to the plugin's SessionStart hook; safe to re-run manually.
- `scripts/s1_client.py`: importable Python client. Handles auth, pooled HTTP connections, retries on 429/5xx, pagination, parallel fan-out via `get_many()`, and optional short-TTL response caching for rarely-changing reads (accounts, sites, groups, system/info, etc.).
- `scripts/call_endpoint.py`: CLI for one-shot calls: `python scripts/call_endpoint.py GET /web/api/v2.1/agents --param limit=5`.
- `scripts/search_endpoints.py`: ranked keyword search over the endpoint index, with synonym expansion and an `--only-works` filter that restricts to endpoints confirmed reachable on this tenant.
- `scripts/smoke_test_queries.py`: non-destructive sweep of every GET + safe query POST. Writes `references/tenant_capabilities.{json,md}`. Read-only; tenant state unchanged.
- `scripts/purple_ai.py`: Purple AI natural-language wrapper over `POST /web/api/v2.1/graphql`. **Non-functional for API tokens**, `purpleLaunchQuery NATURAL_LANGUAGE` requires a browser-session teamToken that service accounts never obtain (confirmed SERVICE_ERROR 2026-05-03). Use the Purple MCP (`mcp__purple-mcp__purple_ai`) for NL queries. Kept for reference only.
- `scripts/call_purple.py`: CLI wrapper for `purple_query()`. **Non-functional for API tokens** (same teamToken constraint). Use the Purple MCP instead.
- `scripts/unified_alerts.py`: Unified Alert Management (UAM) GraphQL wrapper over `POST /web/api/v2.1/unifiedalerts/graphql`. Covers the full query + mutation surface (list/filter/group/notes/history/trigger-actions). See `references/UNIFIED_ALERTS.md`.
- `scripts/call_unified_alerts.py`: CLI for UAM: `python scripts/call_unified_alerts.py list --filter detectionProduct=EDR --first 10`, `... add-note <id> "…"`, `... set-status --scope <acct> --alert-id <id> RESOLVED`.
- `references/UNIFIED_ALERTS.md`: UAM reference: operation catalogue, schema quirks, filter patterns, action catalogue, worked recipes.
- `references/TAG_INDEX.md`: table of all 113 tags with file pointers and op counts. Start here when you don't know which tag owns an endpoint.
- `references/CAPABILITY_MAP.md`: per-tag verb-and-resource summary (L=list, G=get-one, C=count, E=export, A=action, F=filter, S=search, X=mutate) plus an "I want to…" quick lookup. Your fastest orientation when you know the verb but not the path.
- `references/WORKFLOWS.md`: ready-to-adapt multi-step recipes: threat triage, endpoint isolation, DV / PowerQuery hunt, RemoteOps, audit trail, tenant capability snapshot, etc. Each lists the endpoints you actually need and the params that matter.
- `references/tenant_capabilities.{json,md}`: auto-generated by `smoke_test_queries.py`: per-endpoint status (200/403/404/etc.) for the configured tenant. Regenerate whenever the token or tenant changes. The committed copy is a worked example from the Purple demo tenant.
- `references/endpoint_index.json`: compact machine-readable index (one entry per op). Used by `search_endpoints.py` but can be read directly if you need to filter programmatically.
- `references/tags/<Tag>.md`: per-tag reference with parameters, descriptions, and required permissions. Load only the files you need.
- `references/common_params.md`: shared query params (`skip`, `limit`, `cursor`, `sortBy`, etc.) and the pagination pattern.
- `references/POWERQUERY_RECIPES.md`: PowerQuery / SDL query recipes tested on-tenant: indicator prevalence, PowerShell outbound to public IPs, failed-login triage, storyline activity summary, UAM-indicator SDL crosscheck, endpoint heartbeat. For full PQ language reference use the dedicated `powerquery` skill.
- `references/detection-rules.md`: request-body schema gotchas for Custom Detection / STAR rules, Saved Filters, and PowerQuery Scheduled Detections (queryType / queryLang matrix, `isLegacy=false` listing trap, confirmed CREATE / PUT / DELETE bodies, enable / disable endpoints).
- `references/purple-ai.md`: Purple AI GraphQL reference (hosts, endpoints, request shapes, operation flows, Python CLI notes, domain boundary, and the confirmed API-token limitations table).
- `references/querying-logs.md`: the foolproof PowerQuery / LRQ procedure via `scripts/pq.py`, plus the UAM, UAM Alert Interface, data-source and schema discovery, baseline anomaly, CTO reporting, common-workflow, `s1-secops-mcp`, and Hyperautomation operational playbooks.
- `references/python-client.md`: full `S1Client` Python usage examples (single page, `iter_items`, parallel `get_many` fan-out, action POSTs).
- `spec/swagger_2_1.json`, the original full Swagger spec (14 MB). Use only when the per-tag reference is insufficient, e.g. to resolve a deeply nested request-body schema by `$ref`. Never read this whole file into context.
- `tests/test_ioc_lifecycle.py`: reversible CREATE → LIST → DELETE → VERIFY round-trip for Threat Intelligence IOCs. Uses a unique run-tag per invocation, scopes to a single account, and cleans up before exit. Covers the one "create content" path against the S1 detection surface.
- `tests/test_alerts_dual_api.py`: dual-API round-trip for alerts: GraphQL list/detail/addNote/notes/deleteNote plus a parallel REST `/cloud-detection/alerts` read. Demonstrates that UAM GraphQL is the PRIMARY alert surface and REST is SECONDARY, with the note mutation cleaned up before exit (handles the `mgmt_note_id` propagation delay).
- `scripts/pq.py`: foolproof PowerQuery runner over the LRQ API. Wraps launch/poll/cancel, auth flip to `Bearer`, `X-Dataset-Query-Forward-Tag` capture, exponential backoff on 5xx/429/connection errors, and a best-effort cancel. One call: `run_pq(client, "<query>", hours=24)` returns `{row_count, columns, rows, matchCount, ...}`. Also exposes `list_data_sources(client, hours=24)` for the first-response "does this data source actually exist on this tenant?" check. Use this any time a user says "query logs", "run a PQ", "search for events" via the mgmt console API.
- `scripts/inspect_source.py`: source-agnostic schema discovery. For any `dataSource.name`, samples raw events via the LRQ `LOG` queryType (or sync `/sdl/api/query` when available) and classifies every attribute the parser emits into `principal_user` / `principal_host` / `principal_ip` / `action` / `temporal` / `network` / `file` / `process` / `grouping_candidate` / `other`. Picks `prim_key` + `action_key` from whatever the source actually carries, so downstream code never hardcodes field names. Exports `discover_schema(client, source, hours, sample, extra_filter, backend, escalate)` and `pick_keys(schema)`; CLI: `python scripts/inspect_source.py --source "<name>" --window 24h`. See "Data source + schema discovery" in [references/querying-logs.md](references/querying-logs.md).
- `scripts/uam_alert_interface.py`: UAM (Unified Alert Management) Alert Interface client for pushing OCSF indicators + alerts INTO UAM via `POST /v1/indicators` and `POST /v1/alerts` on the SentinelOne HEC ingest host (e.g. `ingest.us1.sentinelone.net`, the same host used for log ingest). Handles the gzip-compressed concatenated-JSON body, `Bearer` auth (the endpoint rejects `ApiToken`), and the `S1-Scope` header. Exposes `UAMAlertInterfaceClient`, plus `build_file_indicator()`, `build_process_indicator()`, `build_network_indicator()`, and `build_alert_referencing()` payload helpers. URL defaults to `https://ingest.us1.sentinelone.net`; override via the `S1_HEC_INGEST_URL` env var or credentials.json key (former canonical `S1_UAM_ALERT_INTERFACE_URL` and legacy snake_case `uam_alert_interface_url` still honored).
- `tests/test_uam_alert_interface_single.py`: minimum-viable reversible write-side round-trip: POST one OCSF FileSystem-Activity indicator + one SecurityAlert referencing it, poll UAM GraphQL until the alert surfaces, verify the indicator is stitched in, then close the alert via bulk-ops (status=RESOLVED, analystVerdict=TRUE_POSITIVE_BENIGN). Covers the single-indicator happy path into UAM.
- `tests/test_uam_alert_interface_batch.py`: comprehensive reversible round-trip: batched POST of 3 indicators (OCSF classes 1001 FileSystem Activity, 1007 Process Activity, 4001 Network Activity) each carrying 3+ observables, referenced by a single SecurityAlert via `finding_info.related_events[]`. Verifies all 3 metadata.uids and their observable names surface in `alert.rawIndicators`, then closes the alert. Covers batching, multi-observable, and multi-indicator linkage.
- `scripts/ingestion_gateway.py` + `tests/test_ingestion_gateway_alert_with_indicator.py`: deprecated back-compat shims. The helper re-exports from `uam_alert_interface`; the test prints a pointer to the renamed file and exits non-zero.
- `scripts/build_source_report.py`: collector for the CTO report pipeline. Runs dimension probes + per-principal mix + timeline for a named data source via `scripts/pq.py` and writes `reports/<slug>_<window>/data.json`. Outputs to a per-source subfolder so multiple sources and windows coexist cleanly.
- `scripts/render_charts.py`: pure-function renderer. `data.json` in, PNG charts out under `reports/<slug>_<window>/charts/`. No tenant calls.
- `scripts/build_docx.py` / `scripts/build_pptx.py`: source-agnostic renderers that read `data.json` and emit `<Slug>_CTO_Report_<window>.docx` and `<Slug>_CTO_Deck_<window>.pptx`. Every section is gated on `dims` so dimension-sparse sources render cleanly. See "CTO report generation pipeline" in [references/querying-logs.md](references/querying-logs.md) for the full contract and renderer gotchas.
- `reports/<slug>_<window>/`: per-run artefact directory. Holds `data.json`, `charts/`, and the rendered `.docx` / `.pptx`. Treat this as the portable unit: move or archive the whole folder.

## Using the client in Python

Import `S1Client` from `scripts/s1_client.py` for anything needing loops, joins, or pagination; use `c.get_many([...])` for parallel independent GETs over pooled connections. Full worked examples (single page, `iter_items`, parallel fan-out, and an action POST) are in [references/python-client.md](references/python-client.md).

## Authentication

The API uses header auth: `Authorization: ApiToken <token>`. The client injects this automatically; do not hand-roll headers.

Token scopes are enforced server-side. Each endpoint in the per-tag references lists `Required permissions`, if a 403 comes back, the token lacks one of those scopes, and the fix is a new token (not a code change). Surface this clearly to the user.

## Rate limits and retries

The client retries automatically on 429 and 5xx with exponential backoff (max 30s), honoring `Retry-After` when present. For bulk operations across thousands of entities, prefer a single filtered action endpoint (`/agents/actions/...`) over a loop of per-ID calls, the API is designed around filter-based bulk ops.

## Destructive actions: confirm first

Many endpoints are destructive or operationally sensitive: disconnect/reconnect agent, uninstall, isolate, shutdown, decommission, script execution via RemoteOps, policy changes, user mutations, account/site deletion. Before firing any `POST`/`PUT`/`DELETE` that affects agents, policies, or tenant config, summarize exactly what will happen (endpoint, filter, estimated scope) and get explicit user confirmation. A 200 response on a wrong filter can isolate thousands of endpoints; there is no undo on many of these.

The safe pattern: run the matching `GET` with `countOnly=true` first to show the blast radius, then the mutating call.

## Purple AI: natural-language query, alert summary, and auto-investigation

Purple AI covers natural-language to PowerQuery, per-alert summaries, and auto-investigation across three GraphQL endpoints. For API-token (service-account) workflows, `purpleLaunchQuery NATURAL_LANGUAGE` and `aiInvestigation/run` are non-functional because they need a browser-session teamToken; use `mcp__purple-mcp__purple_ai` instead. `purpleAlertSummary` (via `purple_ai_alert_summary`) does work for API tokens. Full endpoint map, GraphQL request shapes, end-to-end operation flows, Python CLI notes, domain boundary, and the API-token limitations table: [references/purple-ai.md](references/purple-ai.md).

## Querying logs via the mgmt console API: the foolproof procedure

Do not hand-roll a `requests.post` for a PowerQuery; use `scripts/pq.py` (`run_pq` / `list_data_sources`), which handles Bearer auth, the `/sdl/v2/api/queries` path, the mandatory `X-Dataset-Query-Forward-Tag`, `tenant: true`, transient-error retries, and cancel-on-exit. The full playbook (surface-selection table, the 0-rows diagnostic ladder, window-scaling and slicing, LRQ response-shape gotchas, and the pre-run checklist) is in [references/querying-logs.md](references/querying-logs.md).

## UAM, UAM Alert Interface, data-source discovery, reporting, and Hyperautomation

These operational playbooks moved into [references/querying-logs.md](references/querying-logs.md). Open it when the task is one of:

- Unified Alert Management (UAM), the PRIMARY alert API: the GraphQL alerts inbox via `scripts/unified_alerts.py`, alert vs threat routing, filter shapes, and blast-radius safety. Deeper schema quirks stay in [references/UNIFIED_ALERTS.md](references/UNIFIED_ALERTS.md).
- UAM Alert Interface: pushing OCSF indicators and alerts INTO UAM via the HEC ingest host, with the multi-indicator stitching constraints and asset-linkage matrix ([references/ASSET_LINKAGE.md](references/ASSET_LINKAGE.md)).
- Data source and schema discovery: `list_data_sources` plus `inspect_source.discover_schema` / `pick_keys`, and the always-exclude-`logVolume` rule.
- Source-agnostic baseline and anomaly detection (`scripts/baseline_anomaly.py`).
- CTO report generation pipeline (`build_source_report.py`, `render_charts.py`, `build_docx.py`, `build_pptx.py`).
- Common high-value workflows, `s1-secops-mcp` direct-console usage, and the STAR / Custom Detection rule lifecycle learnings.
