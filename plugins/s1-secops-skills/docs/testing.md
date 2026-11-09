# Test Coverage

This document records what has been validated against a live SentinelOne tenant, including which endpoints were tested, what passed, and confirmed gotchas discovered during testing.

Tests were run against a live SentinelOne demo tenant. Specific tenant URL, site ID, and account ID are intentionally omitted; replace placeholders in `tests/*.py` with values from your own tenant before running.

Full test scripts live in `mgmt-console-api/tests/`. All lifecycle tests are reversible: they clean up after themselves.

`tools/live_learnings_check.mjs` re-checks, against a console you choose, every API behaviour the skills document as measured live on 2026-10-09 (detection-library paging and labels, UAM query shapes, Hyperautomation list/run/deactivate/delete/connections, functions, `addEvents` scoping, per-scope datatables, collector auth, the scheduled-rule toggle). It prints PASS, FAIL or INFO per check and exits 1 on any FAIL. Read-only by default; `--lab <accountId>:<siteId>` adds reversible writes in that site (objects named `zz-live-check-*`, all deleted). Credentials resolve as for the MCP server. Last run: every check passed on three consoles (42 to 44 checks each).

The Python tests are host-only: run them from a terminal or Claude Code on your machine, not from the Cowork sandbox. They read credentials from environment variables, then the OS keychain (service `sentinelone-mcp`, stored with `s1-secops-mcp setup`); there is no credentials file. The credential resolution itself is covered offline by `mgmt-console-api/tests/test_credential_resolution.py`, `test_s1_keystore.py` and their `sdl-api/tests/` twins, which run with `S1_KEYCHAIN=off` or a stubbed backend and need no tenant. The MCP server's own suite runs with `npm test` in `s1-secops-mcp/`.

---

## What was tested: at a glance

| Area | Test | Script | Reversible? | Result |
|---|---|---|---|---|
| Full API surface read-only sweep | Non-destructive sweep across all 111 tags | `scripts/smoke_test_queries.py` | N/A (read-only) | PASSED |
| Threat Intelligence IOCs | CREATE → LIST → DELETE → VERIFY | `tests/test_ioc_lifecycle.py` | Yes (single-account token required) | PASSED |
| Unified Alerts (UAM) GraphQL + REST | list → detail → addNote → deleteNote → verify; parallel REST read | `tests/test_alerts_dual_api.py` | Yes | PASSED |
| Saved filters | CREATE → LIST → UPDATE → DELETE → VERIFY | `tests/test_saved_filter_lifecycle.py` | Yes | PASSED |
| Custom Detection Rules | CREATE (disabled) → LIST → UPDATE → DELETE → VERIFY | `tests/test_custom_rule_lifecycle.py` | Yes | PASSED |
| Alert status and verdict mutations | pick alert → status round-trip → verdict round-trip → history check | `tests/test_alert_mutation_lifecycle.py` | Yes (auto-restores to starting state) | PASSED |
| Scheduled default-report tasks | CREATE → LIST → UPDATE → DELETE → VERIFY | `tests/test_scheduled_report_lifecycle.py` | Yes | PASSED |
| Alert → Indicator pivot | read alert.rawIndicators → pin to TI IOC → verify link → delete | `tests/test_alert_indicator_pivot.py` | Yes (single-account token required) | PASSED |
| UAM Alert Interface (single) | one `POST /v1/alerts` carrying 1 OCSF indicator inline → assert exactly one request was made → poll UAM → verify the indicator surfaced → close | `tests/test_uam_alert_interface_single.py` | Semi (alert closed; ingested events not hard-deletable) | PASSED |
| UAM Alert Interface (batch) | one `POST /v1/alerts` carrying 3 indicators inline (file/process/network, OCSF 1001/1007/4001) with 3+ observables each → poll UAM → verify all indicator and observable links → close | `tests/test_uam_alert_interface_batch.py` | Semi | PASSED |
| Unified Exclusions v2.1 | CREATE (EDR path, site scope) → LIST → DELETE → VERIFY | `tests/test_unified_exclusion_lifecycle.py` | Yes | PASSED |
| Hyperautomation workflow lifecycle | IMPORT (minimal manual-trigger workflow) → LIST → DELETE → VERIFY | `tests/test_hyperautomation_import_lifecycle.py` | Yes (REST DELETE, 204) | PASSED |
| Detection rule ENABLE/DISABLE | CREATE (disabled) → ENABLE → VERIFY_ON → DISABLE → VERIFY_OFF → DELETE → VERIFY (scheduled + events) | `tests/test_detection_rule_activate_lifecycle.py` | Yes (demo site; 24h window prevents real firing) | PASSED |
| XDR Graph Query | FORMAT DISCOVERY → SAVE → LIST → UPDATE → DELETE → VERIFY | `tests/test_xdr_graph_query_lifecycle.py` | Yes (skips gracefully if no saved queries exist for format template) | PASSED (skipped on demo: no saved queries) |
| STAR rules (events-type detection) | CREATE (Draft) → LIST → UPDATE → DELETE → VERIFY | `tests/test_star_rule_lifecycle.py` | Yes (Draft status, never activates) | PASSED |
| Parser lint rules (sdl-log-parser `scripts/parser_rules.py`) | per rule: deploy a bad and a good parser → HEC ingest a sample → query fields → delete (2026-10-13, 11 rules with an observable engine effect) | via MCP tools (`sdl_put_file`, `hec_ingest`, `powerquery_run`, `sdl_delete_file`) | Yes | PASSED; corrected three prior claims (v0 `constants` key, v0 same-name rename, anchored lazy prefix) |
| PowerQuery Scheduled Detection lifecycle | CREATE → GET → ENABLE → verify activating → DISABLE → GET → DELETE → verify gone | via MCP tools directly | Yes | PASSED |

---

## MCP tools validated (s1-secops-mcp)

The s1-secops-mcp tools were exercised against the live demo tenant. The 1.5.x live A/B regression covered the 35 tools of that release, both natively and in the Docker image. The five tools added in 1.6.0 (`purple_ai_query`, `ti_vt_lookup`, `ti_vt_relationship`, `ti_shodan_host`, `ti_shodan_dns`) were verified live with real keys on 2026-11-05. The seven Detection as Code and Asset Inventory tools were verified live on 2026-11-09, for 47 in total. From 1.5.5 the server is read-only by default, so re-running the write rows below needs `S1_READ_ONLY=false` ([read-only.md](./read-only.md)):

| Tool | Tested operation | Result |
|---|---|---|
| `powerquery_enumerate_sources` | List all active SDL data sources | PASSED |
| `powerquery_run` | Hunt query on EndpointSecurityWin source | PASSED |
| `powerquery_schema_discover` | Schema discovery on EndpointSecurityWin | PASSED |
| `s1_api_get` | agents, sites, accounts, threats, detection rules | PASSED |
| `s1_api_post` | Create detection rule, create exclusion, import HA workflow | PASSED |
| `s1_api_put` | Update detection rule body and description | PASSED |
| `s1_api_patch` | Covered by the A/B regression (rare in the S1 API) | PASSED |
| `s1_api_delete` | Delete detection rule, delete exclusion | PASSED |
| `s1_api_download` | Binary download saved with `outputFile` | PASSED |
| `uam_list_alerts` | List open UAM alerts | PASSED |
| `uam_get_alert` | Fetch full alert detail by UUID | PASSED |
| `uam_add_note` | Add text note to alert | PASSED |
| `uam_set_status` | Set status to NEW / IN_PROGRESS / RESOLVED | PASSED |
| `uam_set_verdict` | Set the analyst verdict (the tool verifies by re-read) | PASSED |
| `uam_assign_alert` | Assign an alert to a console user (the tool verifies by re-read) | PASSED |
| `uam_available_actions` | Read the actions offered on an alert | PASSED |
| `purple_ai_alert_summary` | Generate natural-language summary of a UAM alert | PASSED |
| `purple_ai_query` | A knowledge question (MESSAGE result) and a hunt question (POWER_QUERY result, query then run with `powerquery_run`), with the console API token | PASSED |
| `ti_vt_lookup` | Hash, IP, domain and URL reports, including defanged input and a `found:false` miss | PASSED |
| `ti_vt_relationship` | Relationship pages for a file, IP and domain; a premium-only relationship returns a 403 that says so | PASSED |
| `ti_shodan_host` | Host lookup for a public IP | PASSED |
| `ti_shodan_dns` | Forward and reverse lookups | PASSED |
| `dac_export` | Export every custom rule as YAML, listing and extracted to a folder; counts by scope and query type match a `/cloud-detection/rules` listing | PASSED |
| `dac_diff` | Diff an untouched export with a `deployments.yaml`: imports only, nothing created, updated or deleted; a missing manifest, a `..` path and a folder outside the shared one fail cleanly | PASSED |
| `dac_apply` | Apply Draft rules after a matching diff; refused in read-only mode. The bundle-hash and summary refusals are covered by unit tests (`dac-1.6.1`, `dac-1.6.2`) | PASSED |
| `asset_inventory_counts` | Totals per category and surface | PASSED |
| `asset_inventory_search` | Endpoint and Network Discovery views, with and without a `missingCoverage` `stringIn` filter; totals equal the PowerQuery `assets` datasource with `assetStatus = 'Active'` | PASSED |
| `asset_inventory_get` | One Network Discovery asset and one endpoint (agent and alert counts); an unknown id returns `NOT_FOUND` | PASSED |
| `asset_inventory_filter_values` | `missingCoverage` and `eppUnsupportedUnknown` values with counts | PASSED |
| `uam_ingest_alert` | POST one OCSF alert carrying its indicator inline | PASSED |
| `uam_post_alert` | POST OCSF alert envelope | PASSED |
| `sdl_list_files` | List `/logParsers/` and `/dashboards/` | PASSED |
| `sdl_get_file` | Download parser JSON | PASSED |
| `sdl_put_file` | Update dashboard JSON by `udoId` with `expectedVersion` | PASSED |
| `sdl_delete_file` | Delete test configuration file | PASSED |
| `sdl_list_dashboards` | List dashboards at a scope | PASSED |
| `sdl_get_dashboard` | Read one dashboard with its tabs | PASSED |
| `sdl_create_dashboard` | Create a dashboard at a scope | PASSED |
| `sdl_share_dashboard` | Share a dashboard | PASSED |
| `sdl_save_dashboard_layout` | Save panel positions for one tab | PASSED |
| `sdl_delete_dashboard` | Delete a dashboard (the tool verifies by re-read) | PASSED |
| `hec_ingest` | Ingest test events via HEC | PASSED |
| `ha_list_workflows` | List all workflows on tenant | PASSED |
| `ha_get_workflow` | Fetch single workflow | PASSED |
| `ha_import_workflow` | Import minimal manual-trigger workflow | PASSED |
| `ha_export_workflow` | Export all workflows as ZIP | PASSED |
| `ha_delete_workflow` | Delete workflow (REST DELETE) | PASSED (`DELETE /workflows/{id}?accountIds=`, 204) |

The unit suite `mcp/s1-secops-mcp/tests/ti-1.6.0.test.mjs` (part of `npm test`) covers the threat-intel tools offline: listing by key, input validation and defanging, and error mapping. No tenant or key needed.

---

## Key API findings (confirmed against live tenant)

Field schemas and usage patterns confirmed through live testing that are essential for correct API usage.

### Unified Exclusions (`/unified-exclusions`)

- POST requires 7 fields: `modeType`, `type`, `engines`, `scopeLevel`, `scopeLevelId` (camelCase), `value`, and `recommendation`
- `engines` and `interactionLevel` are mutually exclusive; only one can be set
- POST returns `data` as a list, not a single object; parse as `items[0]`
- DELETE body: `{"data": {"exclusions": [{"id": ..., "type": "path"}]}}`

### UAM Alert Interface and raw log ingest

Two paths share the ingest host and take different credentials.

- **UAM alert ingest** (`POST /v1/alerts`) uses the console JWT (`S1_CONSOLE_API_TOKEN`) as the Bearer, posted to `S1_HEC_INGEST_URL`, with the `S1-Scope` header (accountId or accountId:siteId). Unchanged.
- **Raw log ingest** over the event collector (`/services/collector/raw` and `/event`) uses an SDL Log Write Key, carried in `S1_HEC_TOKEN`, which returns `HTTP 200 {"text":"Success","code":0}`. The console API token is not a reliable substitute: on some consoles it returns `HTTP 400 {"text":"Missing S1-Scope header","code":5}` without an `S1-Scope` header and is accepted with one, on others it returns `HTTP 403 {"text":"User token not allowed for this endpoint","code":4}` either way. Use the write key in both cases. Mint the key at Console > Singularity Data Lake > API Keys > Log Write Key; no API creates one.
- **The ingest scope cannot be overridden.** A Log Write Key is minted for one account or site and writes only there. No `S1-Scope` header is sent for log ingest, and with a write key sending one does not change where events land. To write elsewhere, use a key minted for that scope.
- **Indicators cannot be ingested separately.** `POST /v1/indicators` refuses the console user token and the SDL Log Write Key alike, so no credential can drive it. Carry indicators inline in the alert, in `finding_info.related_events[]`, in a single `POST /v1/alerts`. That inline copy populates `alert.indicators`, the field the console Indicators tab renders, so the sleep and ordering contract of the old two-call flow are gone. `tests/test_uam_alert_interface_single.py` and `tests/test_uam_alert_interface_batch.py` both drive the single POST, and each asserts that exactly one request went out so a regression back to the two-call flow fails the test.
- Ingested alerts do not populate `assets[].agentUuid`; real agent linkage comes from S1 agent detections, not synthetic ingest
- The `metadata.product.name` + `metadata.product.vendor_name` envelope controls alert categorization

### Custom Detection Rules (`/cloud-detection/rules`)

- `queryType=scheduled` rules require `isLegacy=false` on GET to appear in results
- `queryType=events` (STAR rules) do not require `isLegacy=false`
- `activeResponse` is not accepted in the CREATE body for the current API version; omit it
- `queryLang` defaults to `"1.0"` for events rules; must be explicitly `"2.0"` for scheduled rules
- After ENABLE, status transitions through `"activating"` before settling on `"active"`; both are valid post-enable states
- DELETE body: top-level `{"filter": {"ids": [...], "siteIds": [...]}}` with no `"data"` wrapper
- GET with both `nameSubstring` and `queryType` is not supported; use one filter at a time
- STAR rules use `cloud-detection/rules` with `queryType=events`; there is no separate `/star-rules` endpoint

### Hyperautomation (`/hyper-automate/api/`)

- Dual base path: `/api/public/` for import/export/publish, `/api/v1/` for list/delete
- Import response uses `id` (not `workflowId`) and `version_id` (not `versionId`)
- List response shape: `{id, workflow: {id, name, state, version_id, ...}, actions: []}`; `workflow.id` == top-level `id`

#### Full lifecycle: validated end to end (2026-06-13, account scope)

| Step | Call | Result |
|---|---|---|
| IMPORT | `POST /api/public/workflow-import-export/import?accountIds=<acct>` | `201`: returns `id` + `version_id`, state `draft` |
| LIST | `GET /api/public/workflows?accountIds=<acct>` | workflow present, state `draft` |
| PUBLISH | `POST /api/v1/workflows/{id}/publish?accountIds=<acct>` | `204`: state → `inactive` (Shared Draft, visible to team) |
| DELETE | `DELETE /api/v1/workflows/{id}?accountIds=<acct>` | `204`: soft, recoverable |
| VERIFY | `GET /api/public/workflows` | workflow absent from active list |

Tested with throwaway workflow id `3085c7ef-4157-4a82-8a93-1ac0dc2c7484` (account `<accountId>`); account workflow count moved 7 → 8 (after import) → 7 (after delete).

- **Scope:** account import/publish/delete use `?accountIds=<acct>`; site-level use `?siteIds=<site>`. The v1 import path with `?_scopeId=<acct>&_scopeLevel=account` returns `403`, and a bare import with no scope returns a misleading `403` on a scoped tenant; always pass the scope query param.
- **Delete** is the REST `DELETE` above. The older `POST /workflows/archive` (and the legacy archive wrapper) return `500` on this tenant and are superseded.
- `nextCursor` returns literal string `"null"` (truthy in Python); loop by skip/limit, not cursor
- With large workflow counts, sort by `updated_at desc` and scan the top 20 to find a freshly imported workflow
- Workflows imported with a service user token are not visible to human users in the console UI

### UAM GraphQL (`/unifiedalerts/graphql`)

- Primary alert surface: multi-source (EDR, XDR, Identity, STAR, Cloud, NGFW, ingested third-party)
- Alert IDs are UUIDs, distinct from REST `/cloud-detection/alerts` which uses int64 IDs
- `addAlertNote` mutation returns a `mgmt_note_id` which is required for `deleteAlertNote` (different from the `id` on the note object)
- Alerts are created by detection engines server-side; there is no `createAlert` mutation

### Threat Intelligence IOCs

- Writes require a token minted at a single account or site: a token whose user spans several accounts gets HTTP 403 code 4030010 ("This page doesn't support multi-scopes users yet"). Store that token in its own keychain profile (`s1-secops-mcp setup --profile <name>`) and run a second MCP entry, or the tests, with `S1_PROFILE=<name>`
- DELETE body uses `{"filter": {"accountId": "...", "uuids": [...]}}`: note `accountId` (singular), not `accountIds`

### Purple AI (GraphQL)

- `purpleLaunchQuery` at `/web/api/v2.1/graphql` works with a console API token when sent in the request shape `purple_ai_query` uses. Call the tool rather than hand-rolling the GraphQL
- The result is either `MESSAGE` (a written answer) or `POWER_QUERY` (a generated query and time range). Purple AI does not run the query; run it with `powerquery_run` after reviewing it
- Each call is a new conversation, and a call takes about 5 to 15 s
- Purple AI answers questions about SDL telemetry; use REST or UAM for questions about console entities

---

## Running the full test suite

From `mgmt-console-api/` on your machine, with `S1_CONSOLE_URL` and `S1_CONSOLE_API_TOKEN` in the keychain or the environment (run the two IOC tests with `S1_PROFILE` set to a profile holding a single-account token):

```bash
# Read-only sweep (~60s)
python scripts/smoke_test_queries.py --workers 16 --timeout 10

# Reversible lifecycle tests
python tests/test_ioc_lifecycle.py                       # IOC CRUD (single-account token)
python tests/test_alerts_dual_api.py                     # UAM + REST alert surfaces
python tests/test_saved_filter_lifecycle.py              # skips if token lacks scope
python tests/test_custom_rule_lifecycle.py               # Custom Detection Rules
python tests/test_alert_mutation_lifecycle.py            # status + verdict round-trip
python tests/test_scheduled_report_lifecycle.py          # default-report tasks
python tests/test_alert_indicator_pivot.py               # alert→IOC pivot (single-account token)
python tests/test_uam_alert_interface_single.py          # 1 alert, 1 inline indicator, single POST /v1/alerts
python tests/test_uam_alert_interface_batch.py           # 1 alert, 3 inline indicators, single POST /v1/alerts
python tests/test_unified_exclusion_lifecycle.py         # EDR path exclusion CRUD
python tests/test_hyperautomation_import_lifecycle.py    # workflow IMPORT/LIST/DELETE
python tests/test_detection_rule_activate_lifecycle.py   # ENABLE/DISABLE scheduled + events
python tests/test_xdr_graph_query_lifecycle.py           # graph query CRUD (skips if no saved queries)
python tests/test_star_rule_lifecycle.py                 # STAR rule (events) CREATE/UPDATE/DELETE
```

All tests exit 0 on success. The lifecycle tests listed above accept `--keep` to skip cleanup and inspect what was created. Scope flags vary by test:

- `--site-id <id>`: `test_star_rule_lifecycle.py`, `test_detection_rule_activate_lifecycle.py`, `test_unified_exclusion_lifecycle.py`
- `--account-id <id>`: `test_hyperautomation_import_lifecycle.py`
- both: `test_uam_alert_interface_single.py`, `test_uam_alert_interface_batch.py`

The other tests take neither and use the token's default scope.

### Launcher install and config

The host launchers' `install` and `config` commands have hermetic tests: a temp HOME, a fake `docker`, no network and no keychain writes. Run them from the repo root:

```bash
sh mcp/docker/launcher-test.sh                # macOS and Linux: every case under sh, dash and bash
pwsh -NoProfile -File mcp/docker/launcher-test.ps1   # Windows launcher, PowerShell 7 on any OS
```

They cover: printed JSON is valid, carries the launcher's absolute path and holds the one `s1-secops-mcp` entry, `--with-shodan` / `-WithShodan` accepted with no effect, the removed server names exiting 78, read-only by default (no `S1_READ_ONLY` written) and `--read-write` / `-ReadWrite` writing `"S1_READ_ONLY": "false"` on the `s1-secops-mcp` entry only, plus the write NOTICE on `install`, `S1_READ_ONLY` forwarded to `docker run` only when the client sets it, `--profile`/`--output-dir`/`--claude-md`/`--image`, a fresh install, a merge that keeps other servers and settings (including a user's own purple-mcp that does not run this launcher), writes the `s1-secops-mcp` entry and drops the pre-1.6.0 `purple-mcp`, `virustotal` and `shodan` entries and older launcher entries, the `Built-in tools:` summary line, a backup identical to the previous file, idempotent re-runs, an invalid config left untouched, `--config-path`, a script piped into the shell refused without copying anything, (Linux) the fallback that prints the entry when no JSON tool exists, `--claude-code` against a stub `claude` (one user-scope entry, the write opt-out on `s1-secops-mcp` only, older entries removed only when they run this launcher, `MCP_TIMEOUT` merged into settings with a larger value and a symlinked file preserved, automatic selection inside Claude Code), (Linux) the WSL credential path against a stand-in `powershell.exe` (timeout on a hung call, concurrent reads, `setup` write and read-back, with pwsh), and, with Docker and the image present, the `initialize` handshake over a pipe and over a Unix socket, which is how Claude Code connects. On Windows, also run the `.ps1` test under Windows PowerShell 5.1 (`powershell -NoProfile -ExecutionPolicy Bypass -File mcp\docker\launcher-test.ps1`).

### Read-only mode and image checks

- **Unit tests:** `mcp/s1-secops-mcp/tests/readonly-1.5.5.test.mjs` (part of `npm test`) covers the read-only gate in `lib/access.js`. No tenant needed.
- **Image smoke tests:** `mcp/docker/smoke-test.sh <image> --expect-version 1.6.3` runs 32 checks against the distroless image. It has no shell, so in-image checks run with `--entrypoint /nodejs/bin/node`. Among them:
  - T04 to T06: no shell, no npm, no package manager, Python or git in the image;
  - T12 and T13: `tools/list` returns 43 tools with no threat-intel keys and 47 with both keys;
  - T22: the server names removed in 1.6.0 exit 78 with the update instruction;
  - T32: a write tool is refused in the default read-only mode, run with `--network none`, and the refusal says how to enable write;
  - T33: with `S1_READ_ONLY=false` the same call reaches its handler;
  - T34: a `powerquery_run` query containing `| savelookup` is refused;
  - T35 and T36: the notices and the AGPL LICENSE ship in the image.

  The full list is in [`docker/README.md`](../../../mcp/docker/README.md#build-locally).

---

## Known limitations

- **HA delete:** delete a workflow with `DELETE /api/v1/workflows/{id}?accountIds=<acct>` (204, soft/recoverable). The older `POST /workflows/archive` returns 500 on this tenant; do not use it.
- **UAM indicator ingest:** there is no separate indicator POST. `/v1/indicators` refuses the console user token and the SDL Log Write Key alike, so indicators must ride inline in the alert's `finding_info.related_events[]`. Both UAM Alert Interface tests were rewritten onto the single-call shape: each makes one `post_alerts([alert], scope=...)` call with the indicators inline, and asserts that exactly one request went out.
- **XDR graph query format:** The format is proprietary and server-validated. The test discovers it by reading an existing saved query. If no saved queries exist on the tenant, the test skips gracefully. Save one query via the XDR Graph Explorer UI to enable the test.
- **Purple AI questions:** use `purple_ai_query`, which sends `purpleLaunchQuery` in the shape that works with a console API token. Each call is a new conversation; there is no follow-up context between calls.

Full field reference per endpoint is in `mgmt-console-api/tests/README.md` and `mgmt-console-api/SKILL.md`.
