# MCP Tools Reference

Full reference for the tools exposed by `s1-secops-mcp`, the one MCP server in the `sentinelone/secops-mcps` image from 1.6.0. For architecture context see [architecture.md](./architecture.md).

From 1.6.0 the image no longer bundles `purple-mcp`, the VirusTotal MCP or the Shodan MCP. Purple AI questions, VirusTotal enrichment and Shodan exposure lookups are built into `s1-secops-mcp` (`purple_ai_query`, `ti_vt_*`, `ti_shodan_*`). To add another MCP server yourself from its official source (for example VirusTotal's hosted MCP for VT Intelligence search, sandbox behaviour summaries and collections), see [connect-optional-tools.md](./connect-optional-tools.md).

---

## s1-secops-mcp

Runs on the user's machine over stdio, as a Node.js process or from the Docker image via the host launcher. Source: `mcp/s1-secops-mcp/index.js`. 40 tools are registered. The four threat-intelligence tools are listed only when their key is stored, so a client sees 36 tools with no threat-intelligence key, 38 with `VIRUSTOTAL_API_KEY` only and 40 with both `VIRUSTOTAL_API_KEY` and `SHODAN_API_KEY`. Credentials resolve per value from environment variables, then the OS keychain; there is no credentials file and no HTTP transport. Setup: [credentials.md](./credentials.md).

### Read-only mode (1.5.5 and later)

s1-secops-mcp is **read-only by default**. Every call that would change the tenant is refused before any network request, with a message that explains how to enable write (`S1_READ_ONLY=false`; launcher `install --read-write`, Windows `-ReadWrite`). Every tool stays listed in read-only mode (the threat-intelligence tools still depend on their keys, as above). While read-only, the description of each Write tool starts with `[Disabled: read-only mode, S1_READ_ONLY]`, and each Conditional tool's with `[Read-only mode, S1_READ_ONLY: write forms are refused]`. Every tool carries the MCP annotations `readOnlyHint`, `destructiveHint` and `openWorldHint`. Enabling write, accepted values and the controls that apply when write is on: [read-only.md](./read-only.md). Any other MCP server you connect yourself is not covered by this setting.

| Access | Meaning | Tools |
|---|---|---|
| Read | Always runs | `s1_api_get`, `s1_api_download`, `uam_list_alerts`, `uam_get_alert`, `uam_available_actions`, `purple_ai_alert_summary`, `purple_ai_query`, `ti_vt_lookup`, `ti_vt_relationship`, `ti_shodan_host`, `ti_shodan_dns`, `powerquery_enumerate_sources`, `powerquery_schema_discover`, `sdl_list_files`, `sdl_get_file`, `sdl_list_dashboards`, `sdl_get_dashboard`, `ha_list_workflows`, `ha_get_workflow`, `ha_export_workflow` (20) |
| Conditional | Read forms run; write forms are refused while read-only | `s1_api_post`: allowed for GraphQL documents with only `query` operations, `/dv/init-query`, `/cloud-funnel/validate-query`, graph explorer queries, `available-actions` and `/xdr/assets/tags/count`; every other POST is treated as a write. `powerquery_run`: refused when the query contains `\| savelookup` (2) |
| Write | Refused while read-only | `s1_api_put`, `s1_api_patch`, `s1_api_delete`, `uam_add_note`, `uam_set_status`, `uam_set_verdict`, `uam_assign_alert`, `uam_post_alert`, `uam_ingest_alert`, `hec_ingest`, `sdl_put_file`, `sdl_delete_file`, `sdl_create_dashboard`, `sdl_share_dashboard`, `sdl_save_dashboard_layout`, `sdl_delete_dashboard`, `ha_import_workflow`, `ha_delete_workflow` (18) |

Local file output (`outputFile`, `s1_api_download`) writes only to your machine and is allowed in read-only mode. Each tool heading below carries its access in brackets.

**Behaviour common to every tool:**

- **Redaction.** Token values are masked in every tool response and log line.
- **Large integers.** API and PowerQuery results keep integers beyond 2^53 exact: 17-19 digit ids and nanosecond timestamps come back as strings, not rounded numbers. SDL's own `sum()`, `min()` and `max()` aggregates are floats and stay numbers. Sliced merges add and compare exact integers exactly.
- **`outputFile`.** `powerquery_run`, `s1_api_get`, `s1_api_download` and `ha_export_workflow` accept an absolute `outputFile` path on the machine running the server. The full result is written there and the response carries only a summary (path, bytes, sha256, counts, plus a 5-row preview for queries), so bulk data does not pass through the model's context. The path must resolve inside `S1_OUTPUT_DIRS` (path-list; default: the home and temp directories), symlinks, dot paths and autostart folders (LaunchAgents, Windows Startup) below the root are refused, an existing file is never replaced unless `overwrite: true`, files are created mode 0600, and the path is checked before the API call. Under Docker, only the folder set with `install --output-dir` reaches your machine (mounted at the same path by the macOS/Linux launcher, at `/output` by the Windows launcher). Without it, a path inside the container is lost when the container exits, and a path on your machine is refused. From 1.5.4 the server in the image refuses both, with that advice, instead of reporting success for a file that is then lost.

### PowerQuery tools

**`powerquery_enumerate_sources`** [Read]
Lists every `dataSource.name` active in SDL over the last 24 hours (`hours` to widen, `scope` for one site). Run this at the start of every session: never assume which sources are present. Returns unique source names, vendors, and categories.

**`powerquery_run`** [Conditional: `| savelookup` is refused while read-only]
Executes a query via the SDL Long-Running Query (LRQ) API: launch, poll, cancel, and launch-429 backoff are handled. Use for threat hunting, baseline queries, custom detection rule validation, dashboard panel validation, and any SDL telemetry question. Parameters beyond `query`, `hours` / `startTime` / `endTime`, `scope` and `maxRows`:

| Parameter | Effect |
|---|---|
| `scope` | `"<accountId>"` or `"<accountId>:<siteId>"`, one account or site under the token. Sent as `tenant: false` + `accountIds` in the launch body, plus a `site.id='<siteId>'` term in the initial filter for a site (the LRQ API has no site field). This is what narrows a global or multi-account token: the `S1-Scope` header alone does not (issue #111). Unscoped, the query spans every account the token can reach. `scopeApplied` in the response says what was applied. For a leading `\| join` or `\| union` the site term goes into every subquery (lookup-table subqueries are left alone), and `\| datasource vulnerabilities` / `misconfigurations` get `\| filter siteId='<siteId>'`. Lookup tables are per scope (the same path at account and at site scope is two files), and the `S1-Scope` header, which the tool also sends, picks the copy that `\| dataset` and `\| lookup` read, on a global token too. A site scope is refused only for `\| datasource alerts`, which has no site column (use `uam_list_alerts` with `scopeType: "SITE"`). Same rules for `powerquery_enumerate_sources` and the `powerquery_schema_discover` fallback. |
| `queryType` | `"PQ"` (default) runs a PowerQuery pipeline. `"LOG"` runs a raw event search: `query` is a filter expression only (no pipes) and every parsed field of each event comes back in `matches`. Use LOG for evidence-grade exports, full-event forensic timelines and S1QL-style hunts. |
| `logLimit` | LOG only: server-side cap per query or slice (default and maximum 5000). `truncatedByServerCap: true` means the window held more events; slice it or narrow the filter. |
| `slices` | 2-15: split the window into equal time slices run in parallel. For windows over about 24 hours (30 days: about 5 s as 15 slices against 21-40 s unsliced, identical totals). |
| `merge` | With `slices` on a PQ group-by: `{"keys": [...], "sum": [...], "min": [...], "max": [...]}`. `count()` results are sums. Non-additive aggregates (`estimate_distinct`, `avg`, percentiles, `top`, `savelookup`) are refused. `keys` must list every group-by column by its exact output name; the tool does not validate them, and a wrong or missing key silently collapses rows. A trailing `\| sort` / `\| limit` is applied after the merge; any other command after the last `\| group` is refused. Without `merge`, slice rows are concatenated. With LOG, `anySliceTruncated` reports a capped slice. |
| `outputFile`, `overwrite` | Write the full result as `.csv`, `.jsonl` / `.ndjson`, or JSON (any other extension); see above. |
| `edrStrict` | Sends top-level `scheme: "edr"` so an unknown or wrongly cased EDR field fails with HTTP 400 instead of silently returning 0 rows. |
| `includeMetering` | Keep SDL ingest-metering rows (`tag='logVolume'`), which are excluded by default; the response's `effectiveQuery` shows what was sent. |

**`powerquery_schema_discover`** [Read]
Fetches sample events as full attribute sets for one `dataSourceName` (exact `dataSource.name`), with `maxEvents` (default 5, max 50), `startTime` (`"24h"`, `"7d"` or ISO) and `scope`. Use this before writing any query against a source: field names drift between sessions due to parser edits and reserved-field rewrites. Metering rows are dropped and counted in `excludedMeteringRows`. When the V1 query returns no events (an unscoped V1 query on a global or multi-account token returns none), it falls back to an LRQ LOG search with the same scope; `via` says which path answered (`v1-query` or `lrq-log`). The fallback also reports session-level fields (`account.id`, `site.id`, `serverHost`), which LOG returns under `serverInfo` for `addEvents` and agent-shipped data rather than with the event fields. Replaces the SDLClient V1 schema loop that older docs described.

### Management Console REST tools

These six tools are generic REST wrappers over the S1 Management Console API v2.1 (781 operations, 111 tags). The path always starts with `/web/api/v2.1/`.

All of them send `S1_CONSOLE_API_TOKEN`. Some endpoints refuse a token whose user spans several accounts (for example `/threat-intelligence/iocs` writes, HTTP 403 code 4030010); the error then carries a hint. Use a console API token minted at a single account or site; store it in its own keychain profile (`s1-secops-mcp setup --profile <name>`) and run a second MCP entry with `S1_PROFILE=<name>` (or make that token your default).

**`s1_api_get`** [Read]
Read any resource: agents, threats, sites, alerts, detection rules, exclusions, IOCs, accounts, groups, policies, and more. Supports all query parameters as a `params` dict. Example: `GET /web/api/v2.1/agents?limit=20&siteIds=123`. With `outputFile`, the full JSON response is written to disk and only a summary (path, bytes, sha256, item count, pagination) returns; for binary responses use `s1_api_download`.

**`s1_api_download`** [Read]
Binary GET saved to `outputFile`: RemoteOps fetch-files results, threat file fetch, CSV and other exports. Returns the file size, sha256 and content type, never the bytes. Same `outputFile` rules as above; `params` as for `s1_api_get`.

**`s1_api_post`** [Conditional: only allowlisted query POSTs run while read-only]
Create or action: create IOC, create detection rule, isolate endpoint, add exclusion, create Hyperautomation workflow, etc. Body is passed as-is: the tool does not auto-wrap in `{"data": {...}}`. Check the swagger or SKILL.md for the correct envelope per endpoint. In read-only mode only the query POSTs listed in [Read-only mode](#read-only-mode-155-and-later) run; an endpoint missing from that allowlist is treated as a write.

**`s1_api_put`** [Write]
Full-replace update: update detection rule, update policy, update exclusion. Requires all mandatory fields: omitting required fields returns 400.

**`s1_api_patch`** [Write]
Partial update: used for endpoints that support PATCH (fewer than PUT). Rare in the S1 API.

**`s1_api_delete`** [Write]
Delete with filter body: delete IOCs, detection rules, exclusions. Many S1 DELETE endpoints accept a filter body (e.g. `{"filter": {"ids": [...]}}`). Pass it as the `body` param.

Reference: `mgmt-console-api/SKILL.md` for confirmed body schemas and required fields per endpoint surface.

### UAM tools

**`uam_list_alerts`** [Read]
List UAM alerts via GraphQL. Filter with individual convenience params, not a single filter string: `status` (valid values `NEW`, `IN_PROGRESS`, `RESOLVED` only; there is no `OPEN`, which silently returns 0 results), `severity` (e.g. `CRITICAL`), `detectionProduct` (e.g. `EDR`), `searchText` (matches the alert name only; the API rejects an all-fields search), plus `startTime`/`endTime` for a time window, `first`/`after` for pagination, and `viewType` (`ALL` default, `ENDPOINT`, `IDENTITY`, `STAR`, `CUSTOM_ALERTS`, `CLOUD`, `THIRD_PARTY`, `DLP`). `scopeIds` with `scopeType` (`ACCOUNT` default, or `SITE`) lists one account or site; without it a global or multi-account token lists every account's alerts. Returns UUID-based alert objects with full context, each with `accountId` and `siteId`.

**`uam_get_alert`** [Read]
Fetch a single UAM alert by UUID. Returns full alert detail including raw indicators, assets, threat info, analyst notes, and history.

**`uam_add_note`** [Write]
Add a text note to an alert. Appears in the alert's notes history.

**`uam_available_actions`** [Read]
Ask the API which actions can be triggered on a given UAM alert. Read-only: it changes nothing. Without `scopeIds` it asks in the alert's own account, as the writes do (before 1.5.3 it used only the first 100 accounts, and an alert in account 101+ of a global token was offered nothing). Returns each action with `isDisabled` and, when disabled, a `disabledReason`. This is the authoritative way to explain a refused write, because availability is filtered by the caller's permissions AND the alert type AND the scope: `statusUpdate` is offered on a native STAR alert but not on an alert ingested via the UAM Alert Interface, and the `S1/incident/*` actions report `INCIDENT_ACTIONS_ONLY_AVAILABLE_FROM_SITE_VIEW` under ACCOUNT scope. An action missing from the list means this identity lacks what this alert needs, never that the action is impossible. Call it before concluding that a UAM write cannot be done. Optional `scopeIds` (default: every account visible to the token) and `scopeType` (`ACCOUNT`, `SITE` or `GROUP`; availability can differ between ACCOUNT and SITE).

**`uam_set_status`** [Write]
Set alert status. Valid values: `NEW`, `IN_PROGRESS`, `RESOLVED`. The analyst verdict is a separate field: set it with `uam_set_verdict`.

**`uam_set_verdict`** [Write]
Set the analyst verdict (action `S1/alert/analystVerdictUpdate`). The 20 valid values are the console's sub-verdicts, for example `TRUE_POSITIVE_MALWARE`, `TRUE_POSITIVE_BENIGN`, `FALSE_POSITIVE_BENIGN`, `FALSE_POSITIVE_USER_ERROR`, and `UNDEFINED` to clear. `TRUE_POSITIVE`, `FALSE_POSITIVE` and `SUSPICIOUS` alone are not values and are refused before any request.

**`uam_assign_alert`** [Write]
Assign an alert to a console user, or unassign it (action `S1/alert/assignUser`). Pass exactly one of `userId` (the numeric console user id, which is what the console sends), `email` (resolved to exactly one user with `GET /web/api/v2.1/users?email=`), or `unassign: true` (sends `value: null`). A service-user token can assign to a human user.

All three write tools also take optional `scopeIds` (default: the alert's own account, read from the alert) and `scopeType` (`ACCOUNT` default, `SITE` or `GROUP`).

**How the three write tools work.** Each sends the console's exact `alertTriggerActions` request (captured from a console HAR): operation `AlertTriggerActions`, `scope` set to the alert's own account, `viewType: "ALL"`, one action, filter by alert id. It then re-reads the alert and fails unless the alert shows the requested value. The result carries `outcome` (`applied`, `already_set` or `scheduled`), `verified: true`, and the `before` and `after` state. A refusal fails loudly. `errorType MISSING_PERMISSION` means the calling role lacks **Unified Alerts > *type* Alerts: Manage** for this alert type (STAR, Endpoint, Identity, Mobile or Generic); the error names the role and lists its missing Manage permissions when the token can read its own role. Measured on 2026-10-08 with a role that has no Unified Alerts Manage permission: writes on a native STAR alert succeeded (that role has the legacy STAR Rule Alerts update permissions), and writes on an alert ingested via `/v1/alerts` failed with `MISSING_PERMISSION`. Ingested alerts most likely need **Generic Alerts: Manage**. Grant it at Policies and settings > User management > Console users > Roles.

**`purple_ai_alert_summary`** [Read]
Generate a Purple AI natural-language summary for a specific UAM alert. Pass the alert's OCSF JSON (as returned by `uam_get_alert`) and receive a `{ token, summary }` result that's identical to what the Purple AI card surfaces in the console alert detail. Synchronous; no polling.

**`purple_ai_query`** [Read] (1.6.0)
Ask Purple AI a question in natural language (`purpleLaunchQuery` at `/web/api/v2.1/graphql`, synchronous, about 5 to 15 s). Uses the console API token; available whenever the console is configured, no extra key. Parameters: `question` (required, up to 4000 characters), `hours` (default 24) or `startTime` / `endTime` (ISO 8601 or epoch milliseconds) for the time range Purple scopes a generated query to. Returns `{resultType, message, summary, powerQuery {query, timeRange, viewSelector}, starRule, suggestedQuestions}`. `resultType` is `MESSAGE` for a written answer (for example "What is T1059?") or `POWER_QUERY` for a hunt question. Purple does **not** run the query: review `powerQuery.query`, then run it with `powerquery_run`. Purple can AND fields from different schema families (for example `event.type` with `winEventLog.id`), which returns nothing; split such a query by `dataSource.name`. Each call is a new conversation with no memory of earlier calls. Purple AI auto-investigation (`aiInvestigation/run`) still needs a browser session and is not exposed.

**`uam_ingest_alert`** [Write]
Ingest a synthetic alert via the UAM Alert Interface. For creating test/synthetic alerts. One round-trip: a single `POST /v1/alerts` carrying its indicator inline in `finding_info.related_events[]`. That inline copy is what populates `alert.indicators`, the field the console Indicators tab renders. Requires `S1_HEC_INGEST_URL` and `S1_CONSOLE_API_TOKEN`. Parameters: `scope` (required, `<accountId>` or `<accountId>:<siteId>`), `title` (default `MCP Test Alert`), `description`, `hostname` (default `mcp-test-host`), `filename` (default `test-payload.exe`), `sha256` (64 lowercase hex; a zeroed placeholder when omitted). `inline` is accepted for backward compatibility and ignored: indicators always ride inline.

**`uam_post_alert`** [Write]
Post a raw OCSF-formatted alert to `/v1/alerts` on the ingest host. Carry every indicator inline in `finding_info.related_events[]`.

> **Indicators cannot be ingested separately.** There is no usable `POST /v1/indicators`: it refuses the console API token and the SDL Log Write Key alike, so no credential can drive it. The two-call flow (post indicator, sleep, post alert referencing it) is gone, along with its sleep and ordering contract. The `uam_post_indicators` tool was removed for the same reason. Alert creation and IOCs are unaffected and still use `S1_CONSOLE_API_TOKEN`.
>
> Verify an ingested alert with `alert(id) { indicators { type uid title description message severity observables { name value type } } }`. `Indicator` has no `name` and no `category` field; querying either returns `Validation error ... Field 'name' in type 'Indicator' is undefined`.

### SDL tools

**`sdl_list_files`** [Read]
List configuration files on the SDL tenant (parsers, dashboards, lookups, datatables) via `POST <console>/sdl/v2/graphql`. Returns each file's `name`, `version` and `udoId`. Optional `pathPrefix` scopes the listing, e.g. `/logParsers/` or `/dashboards/`, so a caller does not have to pull all 2,264 files into context. Paged with `limit` (default 500, max 5000) and `offset` (default 0); page with `offset += limit` while `offset` is below `totalCount`.

**`sdl_get_file`** [Read]
Download the content of a single SDL configuration file. Address it by `path` for name-addressed namespaces (`/logParsers/`, `/lookups/`, `/datatables/`, `/automaticLookups`) or by `udoId` for a dashboard. The console's Configuration Files grid displays a dashboard as `/dashboards/id/<udoId>/<name>`; that is a display string, not a path. Pass the number as `udoId` and the file's real name is `/dashboards/<name>`.

**`sdl_put_file`** [Write]
Upload or update a configuration file on SDL. Used for deploying parsers and dashboards. Takes `path` or `udoId`, plus optional `expectedVersion`, which is enforced on both address forms. A path-addressed write to an existing dashboard is refused, because `addConfigFile(name:)` creates a duplicate rather than updating in place; the tool names the `udoId`s already holding that name. Create a dashboard by name once, then address it by `udoId`. Authorised by `S1_CONSOLE_API_TOKEN`.

**`sdl_delete_file`** [Write]
Delete a configuration file from SDL by `path` or `udoId`. The tool verifies removal by re-reading and returns `{status, deleted, raw}`.

**`hec_ingest`** [Write]
Ingest raw logs/events into SDL via the event collector (`/services/collector/raw` and `/event`). Applies a named parser via `?sourcetype` and lands the data for Event Search, PowerQuery, and detection rules. Posts to `S1_HEC_INGEST_URL`. Replaces the removed `sdl_upload_logs`. Used for ingesting custom telemetry or test events during parser development. Parameters: `logContent` (required; on `raw`, each line is an event), `parser` (sent as `?sourcetype=`; omit to skip parsing), `fields` (object of extra key-value query params, each becoming a field; avoid HEC-reserved names), `endpoint` (`raw` default, or `event` for structured JSON), `compress` (gzip, default true), `isParsed` (with `event`: index the JSON fields directly, no parser). `scope` is accepted and ignored.

Raw log ingest authenticates with an **SDL Log Write Key**, carried in `S1_HEC_TOKEN`. `hec_ingest` sends it as `Authorization: Bearer <key>`; the collector also accepts `Authorization: Splunk <key>`. The write key returns `HTTP 200 {"text":"Success","code":0}` and needs no `S1-Scope` header. The Management Console API token is not a reliable substitute, and its behaviour differs per console (measured 2026-10-09): on some it returns `HTTP 400 {"text":"Missing S1-Scope header","code":5}` without an `S1-Scope` header and is accepted with one (the header then decides where its events land); on others it returns `HTTP 403 {"text":"User token not allowed for this endpoint","code":4}` with or without the header. A `400 Missing S1-Scope header` means the call carried the console token without a scope header; a `403 code 4` means this console does not accept user tokens at the collector. Use the write key in both cases. Mint the key at Console > Singularity Data Lake > API Keys > Log Write Key; no API creates one. It is optional in config because only log ingest needs it.

**The ingest scope cannot be overridden.** A Log Write Key is minted for exactly one account or site and writes only there, so the key itself fixes the destination. `hec_ingest` sends no `S1-Scope` header, and with a write key sending one does not change where events land. To write elsewhere, use a key minted for that scope.

When ingesting pre-structured / OCSF JSON with `?isParsed=true` (no parser), every event MUST also include the SentinelOne source-attribution fields `dataSource.name`, `dataSource.vendor`, `dataSource.category` (set to `security`, other categories ingest but do not process correctly for custom OCSF sources), `event.type`, and `site_id`. OCSF does not define these; without them events land with a null source (no attribution, degraded console rendering, and any `dataSource.name`-based filter or detection will not match). Emit `event.type` as a FLAT dotted key (e.g. `"event.type": "DNS Activity"`); a nested `event:{...}` object is silently dropped because `event` is a HEC-reserved key.

The SDL config-file and dashboard tools take an optional `scope` argument, `"<accountId>"` or `"<accountId>:<siteId>"`, sent as the `S1-Scope` header. (`hec_ingest` is the exception: its destination comes from the Log Write Key, not from a header.) **Reads are scope-FILTERED, not merely scope-tagged**: measured live on one tenant, the same dashboard listing returned 1,515 at account scope and 7 at a single site scope. An object created at site scope is invisible to an account-scoped listing, so every "not found" is scope-relative. `scope` falls back to `S1_SCOPE` (environment or keychain) and omitting it uses the token default.

**One global token, any account or site.** A global or multi-account token can drive every account and site it is authorized for, one call at a time: pass the account or site the user named on each call (`scope` on the PowerQuery and SDL tools, `scopeIds`/`scopeType` on the UAM tools, `accountIds`/`siteIds` on the Hyperautomation and `s1_api_*` tools). Leave it out and the call covers every account the token reaches. The SDL config and dashboard tools honour the `S1-Scope` header on such a token (measured: a dashboard created at one account was not visible from another). The LRQ PowerQuery tools do not rely on the header: see `scope` under `powerquery_run`. UAM alert writes act in the alert's own account automatically.

### SDL dashboard lifecycle tools

These run on the `dashboardsV2` GraphQL surface, the one the console itself drives. It is dashboard-aware where the config-file tools above are not: it carries name, description, tabs, sharing and authorship. A dashboard's `id` here is the same value as its `udoId` in `sdl_list_files`.

**`sdl_list_dashboards`** [Read]
List dashboards visible at a scope with `{id, name, description, configType, access:{public, users, owner}}`. Prefer this over `sdl_list_files` when you need the owner or sharing state; prefer `sdl_list_files` when you need the numeric version for optimistic locking. Paged with `limit` (default 100, max 1000) and `offset` (default 0); `totalCount` always reports the full number. `namesOnly: true` returns just `{id, name}`, the cheap way to resolve a name to an id.

**`sdl_get_dashboard`** [Read]
Read one dashboard including its tabs, by `id` (preferred) or `name`. Note `tabs[].graphs`, `.parameters`, `.filters` and `.options` come back as JSON **strings**, not objects. The `version` field here is a display string and is usually empty; it is NOT the optimistic-locking token, use `sdl_get_file` for that.

**`sdl_create_dashboard`** [Write]
Create a dashboard from a complete dashboard-JSON document passed as one `config` value (a JSON string or an object). This is the preferred deploy path: it takes the whole document (`configType`, `duration`, `description`, `tabs[]`) in one call, and it validates the JSON before sending, which avoids the console editor's stub-append failure (`{graphs: []}{...}` yields `Content is invalid json / Additional text after JSON object` and leaves an empty dashboard behind). `isPublic` defaults to **true**, diverging from the raw API's false: `access.owner` is the calling identity, so with a service-account token a private dashboard is readable through the API but invisible in the console to a human at any scope, which is indistinguishable from a failed deploy. Names reject `( ) [ ] { } : , & ' % #` with only `Invalid name` as the error; letters, digits, space, `-`, `_`, `.` and `/` are accepted. `failIfNameExists: true` refuses when a dashboard of that name already exists at the scope (default false, which permits siblings; costs one extra listing call).

**`sdl_share_dashboard`** [Write]
Share or unshare a dashboard with the account or with users via `shareResource`. It is not a deployment route: to deploy a dashboard to a site, create it at the site with `sdl_create_dashboard` and `scope: "<accountId>:<siteId>"`. Note the two different scope arguments: the `scopes` array lists the share targets, while `scope` is the header for the call itself.

**`sdl_save_dashboard_layout`** [Write]
Save panel positions (layout x/y/w/h) for one tab. Layout only, matched by array index: titles, markdown and queries in the payload are ignored, and the panel count must match the tab's (the tool reads the tab first and refuses a mismatch, and warns when content changes were dropped). `graphs` is a JSON string shaped `{"graphs":[...]}`, including the wrapper key, even though the response echoes a bare array. To edit panel content or add or remove panels use `sdl_put_file` with `expectedVersion`; for a new document use `sdl_create_dashboard`.

**`sdl_delete_dashboard`** [Write]
Delete a dashboard by `id` or `name`. The mutation returns a bare boolean, so the tool re-reads afterwards and only reports success once removal is confirmed.

### Hyperautomation tools

**`ha_list_workflows`** [Read]
List Hyperautomation workflows on the tenant. Parameters: `limit` (default 50, max 200), `skip` (offset, default 0), `accountIds` (comma-separated; one account's account- and site-level workflows), `siteIds` (comma-separated; misses account-level workflows; omit both for every account the token can reach), `nameContains` (sent as `name__contains`, the only name filter the API honours; `name`, `search` and `query` are ignored and return the unfiltered page), `sortBy` (`updated_at` default, `created_at`, `name`), `sortOrder` (`desc` default, `asc`). Returns each workflow's `id`, `name`, `state`, `status`, `revisionId`, and action list.

**`ha_get_workflow`** [Read]
Fetch a single workflow by `workflowId` and optional `revisionId`. Auto-resolves `revisionId` from the list if omitted.

**`ha_import_workflow`** [Write]
Import a workflow JSON into the tenant. Requires `Hyper Automate.write` permission. Creates the workflow in draft state. Response uses `id` (not `workflowId`) and `version_id` (not `versionId`).

**`ha_export_workflow`** [Read]
Export all workflows as a ZIP archive. Pass `outputFile` (absolute path ending in `.zip`) to save the archive to disk; the response then carries only its path, size and sha256.

**`ha_delete_workflow`** [Write]
Delete one or more workflows via `DELETE /workflows/{id}` (soft, recoverable). Scope with `accountIds` or `siteIds` to match where the workflow lives. An active workflow cannot be deleted (HTTP 400): the tool deactivates it, retries once and reports `deactivatedFirst: true`. Requires Hyper Automate.write permission.

---

<a id="shodan-mcp-optional"></a><a id="threat-intelligence-which-server-to-use"></a>

### Threat-intelligence tools (1.6.0)

Built into s1-secops-mcp: our own read-only code that calls the VirusTotal API v3 and the Shodan API directly with the operator's own keys (`www.virustotal.com` and `api.shodan.io` only, GET only). No third-party MCP server or package is involved. Each tool is listed only when its key is stored: `VIRUSTOTAL_API_KEY` for the two `ti_vt_*` tools, `SHODAN_API_KEY` for the two `ti_shodan_*` tools. `s1-secops-mcp setup` (or the launcher's `setup`) prompts for both; see [credentials.md](./credentials.md). Key values are redacted from every response and error. Enrich external indicators only: RFC1918 addresses and internal hostnames are enrichment-not-applicable.

**`ti_vt_lookup`** [Read]
VirusTotal report for one indicator. Parameters: `indicator` (a file hash (MD5, SHA-1 or SHA-256), IP, domain or URL; defanged input such as `hxxp://` and `[.]` is accepted) and optional `type` (`auto` default, `file`, `hash`, `ip`, `domain`, `url`). Returns `lastAnalysisStats` (malicious, suspicious, harmless, undetected), `detections` (the engines that flagged it malicious or suspicious), `reputation`, `communityVotes`, `tags`, `lastAnalysisDate` and a `link` to the VirusTotal page, plus per type:

| Type | Extra fields |
|---|---|
| file | `sha256`, `sha1`, `md5`, `meaningfulName`, `names`, `typeDescription`, `size`, `threatLabel`, `threatCategories`, `threatNames`, `sandboxVerdicts`, `signature`, `yaraRules`, `sigmaStats`, `firstSubmission`, `lastSubmission` |
| ip | `asOwner`, `asn`, `country`, `network`, `jarm` |
| domain | `registrar`, `creationDate`, `categories`, `lastDnsRecords` |
| url | `finalUrl`, `title`, `httpResponseCode`, `redirectionChain` |

`found: false` means VirusTotal has no record of the indicator. That is not a benign verdict; report it as "no VirusTotal record".

**`ti_vt_relationship`** [Read]
One page of one VirusTotal relationship, to pivot from an indicator. Parameters: `indicator`, `relationship`, optional `type`, `limit` (1 to 40, default 10) and `cursor` (the `nextCursor` of a previous page). Items are trimmed to the fields used for pivoting (ids, names, detection counts). One relationship per call: to see contacted IPs and dropped files, make two calls.

| Indicator type | Allowed relationships |
|---|---|
| file | `contacted_domains`, `contacted_ips`, `contacted_urls`, `dropped_files`, `execution_parents`, `bundled_files`, `embedded_domains`, `embedded_ips`, `embedded_urls`, `itw_urls`, `related_threat_actors`, `similar_files`, `comments` |
| ip | `communicating_files`, `downloaded_files`, `referrer_files`, `resolutions`, `urls`, `related_threat_actors`, `historical_ssl_certificates`, `comments` |
| domain | `communicating_files`, `downloaded_files`, `referrer_files`, `resolutions`, `subdomains`, `siblings`, `urls`, `related_threat_actors`, `historical_ssl_certificates`, `comments` |
| url | `contacted_domains`, `contacted_ips`, `downloaded_files`, `communicating_files`, `redirects_to`, `redirecting_urls`, `last_serving_ip_address`, `related_threat_actors`, `comments` |

Some relationships (for example `related_threat_actors` and `similar_files`) need a premium VirusTotal key; on a free key the call returns a 403 that says so.

**VirusTotal limits.** A free key allows 4 lookups per minute and 500 per day. Each `ti_vt_lookup` and each `ti_vt_relationship` page counts as one lookup. A 429 is retried after a short wait; enrich the indicators that decide the verdict first.

**`ti_shodan_host`** [Read]
Shodan host information for one IP (`ip`, IPv4 or IPv6, defanged accepted): `org`, `isp`, `asn`, location, `os`, `hostnames`, `domains`, `tags` (for example `vpn`, `tor`, `honeypot`), `ports`, `vulns` (CVE ids Shodan associates with the host) and up to 25 services with product, version, HTTP title and TLS certificate. `found: false` means Shodan has not seen the IP, which is not a benign verdict. Does not spend query credits.

**`ti_shodan_dns`** [Read]
Resolve up to 25 `hostnames` to IP addresses, or reverse-resolve up to 25 `ips` to hostnames. Pass one list, not both. Does not spend query credits. Shodan allows about 1 request per second; a 429 is retried after a short wait.

**Not built in.** VT Intelligence search (query syntax such as `type:peexe positives:10+`), file sandbox behaviour summaries, collections (threat-actor, campaign and report objects), IOC submission or upload, Shodan device search and the Shodan CVEDB lookups. For those, connect an MCP server from its official source, for example VirusTotal's hosted MCP: see [connect-optional-tools.md](./connect-optional-tools.md).

---

## Which tool to use for what

| Task | Tool |
|---|---|
| Hunt for process/network/file events in SDL | `powerquery_run` |
| Long-window aggregate (past about 24 h) | `powerquery_run` with `slices` + `merge` |
| Every parsed field of raw events, evidence export | `powerquery_run` with `queryType: "LOG"` and `outputFile` |
| Field schema of a source | `powerquery_schema_discover` |
| Natural-language question or a draft hunt query | `purple_ai_query`, then review the query and run it with `powerquery_run` |
| List, triage or annotate alerts (notes and history included) | `uam_list_alerts`, `uam_get_alert`; writes with `uam_add_note`, `uam_set_status`, `uam_set_verdict`, `uam_assign_alert` |
| Agent inventory, vulnerabilities, misconfigurations | `s1_api_get` / `s1_api_post` (read) on the endpoints in the mgmt-console-api skill |
| Agents, threats, sites, groups, policies (REST) | `s1_api_get` / `s1_api_post` |
| Create/update/delete detection rules or exclusions | `s1_api_post` / `s1_api_put` / `s1_api_delete` |
| Create or delete IOCs | `s1_api_post` / `s1_api_delete` from an MCP entry whose token is minted at a single account or site (`S1_PROFILE`) |
| Download a fetched file, RemoteOps output, or export | `s1_api_download` |
| Deploy parser or dashboard to SDL | `sdl_put_file` |
| Ingest custom log events | `hec_ingest` |
| Import Hyperautomation workflow | `ha_import_workflow` |
| Enrich an IOC (hash, IP, domain, URL) | `ti_vt_lookup` (needs `VIRUSTOTAL_API_KEY`), or another threat-intel provider you have connected |
| Pivot on an IOC's relationships | `ti_vt_relationship`, one relationship per call |
| What an external IP exposes to the internet | `ti_shodan_host` (needs `SHODAN_API_KEY`); DNS with `ti_shodan_dns` |
| VT Intelligence search, sandbox behaviour summaries, collections | Not built in: a connected VirusTotal MCP ([connect-optional-tools.md](./connect-optional-tools.md)) |

Rows that create, update, delete, deploy, ingest, import or annotate through s1-secops-mcp need write enabled; in the default read-only mode those calls are refused. See [Read-only mode](#read-only-mode-155-and-later).
