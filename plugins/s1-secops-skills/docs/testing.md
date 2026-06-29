# Test Coverage

This document records what has been validated against a live SentinelOne tenant, including which endpoints were tested, what passed, and confirmed gotchas discovered during testing.

Tests were run against a live SentinelOne demo tenant. Specific tenant URL, site ID, and account ID are intentionally omitted; replace placeholders in `tests/*.py` with values from your own tenant before running.

Full test scripts live in `mgmt-console-api/tests/`. All lifecycle tests are reversible: they clean up after themselves.

---

## What was tested: at a glance

| Area | Test | Script | Reversible? | Result |
|---|---|---|---|---|
| Full API surface read-only sweep | Non-destructive sweep across all 113 tags | `scripts/smoke_test_queries.py` | N/A (read-only) | PASSED |
| Threat Intelligence IOCs | CREATE → LIST → DELETE → VERIFY | `tests/test_ioc_lifecycle.py` | Yes (single-scope token required) | PASSED |
| Unified Alerts (UAM) GraphQL + REST | list → detail → addNote → deleteNote → verify; parallel REST read | `tests/test_alerts_dual_api.py` | Yes | PASSED |
| Saved filters | CREATE → LIST → UPDATE → DELETE → VERIFY | `tests/test_saved_filter_lifecycle.py` | Yes | PASSED |
| Custom Detection Rules | CREATE (disabled) → LIST → UPDATE → DELETE → VERIFY | `tests/test_custom_rule_lifecycle.py` | Yes | PASSED |
| Alert status and verdict mutations | pick alert → status round-trip → verdict round-trip → history check | `tests/test_alert_mutation_lifecycle.py` | Yes (auto-restores to starting state) | PASSED |
| Scheduled default-report tasks | CREATE → LIST → UPDATE → DELETE → VERIFY | `tests/test_scheduled_report_lifecycle.py` | Yes | PASSED |
| Alert → Indicator pivot | read alert.rawIndicators → pin to TI IOC → verify link → delete | `tests/test_alert_indicator_pivot.py` | Yes (single-scope token) | PASSED |
| UAM Alert Interface (single) | POST 1 OCSF indicator + 1 alert → poll UAM → verify link → close | `tests/test_uam_alert_interface_single.py` | Semi (alert closed; ingested events not hard-deletable) | PASSED |
| UAM Alert Interface (batch) | POST 3 indicators (file/process/network) + 1 alert → poll UAM → verify all observable links → close | `tests/test_uam_alert_interface_batch.py` | Semi | PARTIAL: multi-indicator stitching flaky on-tenant |
| Unified Exclusions v2.1 | CREATE (EDR path, site scope) → LIST → DELETE → VERIFY | `tests/test_unified_exclusion_lifecycle.py` | Yes | PASSED |
| Hyperautomation workflow lifecycle | IMPORT (minimal manual-trigger workflow) → LIST → DELETE → VERIFY | `tests/test_hyperautomation_import_lifecycle.py` | Yes (REST DELETE, 204) | PASSED |
| Detection rule ENABLE/DISABLE | CREATE (disabled) → ENABLE → VERIFY_ON → DISABLE → VERIFY_OFF → DELETE → VERIFY (scheduled + events) | `tests/test_detection_rule_activate_lifecycle.py` | Yes (demo site; 24h window prevents real firing) | PASSED |
| XDR Graph Query | FORMAT DISCOVERY → SAVE → LIST → UPDATE → DELETE → VERIFY | `tests/test_xdr_graph_query_lifecycle.py` | Yes (skips gracefully if no saved queries exist for format template) | PASSED (skipped on demo: no saved queries) |
| STAR rules (events-type detection) | CREATE (Draft) → LIST → UPDATE → DELETE → VERIFY | `tests/test_star_rule_lifecycle.py` | Yes (Draft status, never activates) | PASSED |
| PowerQuery Scheduled Detection lifecycle | CREATE → GET → ENABLE → verify activating → DISABLE → GET → DELETE → verify gone | via MCP tools directly | Yes | PASSED |

---

## MCP tools validated (s1-secops-mcp)

All 26 s1-secops-mcp tools were exercised against the live demo tenant:

| Tool | Tested operation | Result |
|---|---|---|
| `powerquery_enumerate_sources` | List all active SDL data sources | PASSED |
| `powerquery_run` | Hunt query on EndpointSecurityWin source | PASSED |
| `powerquery_schema_discover` | Schema discovery on EndpointSecurityWin | PASSED |
| `s1_api_get` | agents, sites, accounts, threats, detection rules | PASSED |
| `s1_api_post` | Create detection rule, create exclusion, import HA workflow | PASSED |
| `s1_api_put` | Update detection rule body and description | PASSED |
| `s1_api_patch` | Not exercised (rare in S1 API) | N/A |
| `s1_api_delete` | Delete detection rule, delete exclusion | PASSED |
| `uam_list_alerts` | List open UAM alerts | PASSED |
| `uam_get_alert` | Fetch full alert detail by UUID | PASSED |
| `uam_add_note` | Add text note to alert | PASSED |
| `uam_set_status` | Set status to NEW / IN_PROGRESS / RESOLVED | PASSED |
| `purple_ai_alert_summary` | Generate natural-language summary of a UAM alert | PASSED |
| `uam_ingest_alert` | POST OCSF alert via HEC | PASSED |
| `uam_post_alert` | POST OCSF alert envelope | PASSED |
| `uam_post_indicators` | POST OCSF threat indicators | PASSED |
| `sdl_list_files` | List `/logParsers/` and `/dashboards/` | PASSED |
| `sdl_get_file` | Download parser JSON | PASSED |
| `sdl_put_file` | Deploy dashboard JSON to SDL | PASSED |
| `sdl_delete_file` | Delete test configuration file | PASSED |
| `hec_ingest` | Ingest test events via HEC | PASSED |
| `ha_list_workflows` | List all workflows on tenant | PASSED |
| `ha_get_workflow` | Fetch single workflow | PASSED |
| `ha_import_workflow` | Import minimal manual-trigger workflow | PASSED |
| `ha_export_workflow` | Export all workflows as ZIP | PASSED |
| `ha_delete_workflow` | Delete workflow (REST DELETE) | PASSED (`DELETE /workflows/{id}?accountIds=`, 204) |

## MCP tools validated (purple-mcp)

| Tool | Tested operation | Result |
|---|---|---|
| `purple_ai` | Natural-language hunt query | PASSED |
| `powerquery` | Raw PowerQuery execution | PASSED |
| `list_alerts` | List open alerts with filter | PASSED |
| `search_alerts` | Text search across alerts | PASSED |
| `get_alert` | Full alert detail by UUID | PASSED |
| `get_alert_history` | Alert status change log | PASSED |
| `get_alert_notes` | Alert analyst notes | PASSED |
| `uam_add_note` | Add note via purple-mcp | PASSED |
| `uam_set_status` | Set alert status | PASSED |
| `list_inventory_items` | Agent inventory list | PASSED |
| `get_inventory_item` | Single agent detail | PASSED |
| `list_vulnerabilities` | CVE list by agent | PASSED |
| `list_misconfigurations` | Config gap list | PASSED |

---

## Key API findings (confirmed against live tenant)

Field schemas and usage patterns confirmed through live testing that are essential for correct API usage.

### Unified Exclusions (`/unified-exclusions`)

- POST requires 7 fields: `modeType`, `type`, `engines`, `scopeLevel`, `scopeLevelId` (camelCase), `value`, and `recommendation`
- `engines` and `interactionLevel` are mutually exclusive; only one can be set
- POST returns `data` as a list, not a single object; parse as `items[0]`
- DELETE body: `{"data": {"exclusions": [{"id": ..., "type": "path"}]}}`

### UAM Alert Interface (HEC ingest)

- HEC ingest uses the console JWT (`S1_CONSOLE_API_TOKEN`) as the Bearer, posted to `S1_HEC_INGEST_URL`; the `S1-Scope` header (accountId or accountId:siteId) is required
- Multi-indicator stitching (3+ indicators linked to one alert) requires up to a 2-minute grace window; typically 2 of 3 indicators land in time
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

#### Full lifecycle — validated end to end (2026-06-13, account scope)

| Step | Call | Result |
|---|---|---|
| IMPORT | `POST /api/public/workflow-import-export/import?accountIds=<acct>` | `201` — returns `id` + `version_id`, state `draft` |
| LIST | `GET /api/public/workflows?accountIds=<acct>` | workflow present, state `draft` |
| PUBLISH | `POST /api/v1/workflows/{id}/publish?accountIds=<acct>` | `204` — state → `inactive` (Shared Draft, visible to team) |
| DELETE | `DELETE /api/v1/workflows/{id}?accountIds=<acct>` | `204` — soft, recoverable |
| VERIFY | `GET /api/public/workflows` | workflow absent from active list |

Tested with throwaway workflow id `3085c7ef-4157-4a82-8a93-1ac0dc2c7484` (account `<accountId>`); account workflow count moved 7 → 8 (after import) → 7 (after delete).

- **Scope:** account import/publish/delete use `?accountIds=<acct>`; site-level use `?siteIds=<site>`. The v1 import path with `?_scopeId=<acct>&_scopeLevel=account` returns `403`, and a bare import with no scope returns a misleading `403` on a scoped tenant — always pass the scope query param.
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

- Requires a single-scope token (not multi-scope): HTTP 403 code 4030010 if token is scoped to multiple accounts
- DELETE body uses `{"filter": {"accountId": "...", "uuids": [...]}}`: note `accountId` (singular), not `accountIds`

### Purple AI (GraphQL)

- `purpleLaunchQuery NATURAL_LANGUAGE` requires a browser-session `teamToken`; service-account tokens are not supported for this operation
- Use the purple-mcp `purple_ai` tool (which handles auth correctly) instead of calling the GraphQL directly
- Purple AI answers questions about SDL telemetry; use REST or UAM for questions about console entities

---

## Running the full test suite

```bash
# Read-only sweep (~60s)
python scripts/smoke_test_queries.py --workers 16 --timeout 10

# Reversible lifecycle tests
python tests/test_ioc_lifecycle.py                       # IOC CRUD (single-scope token)
python tests/test_alerts_dual_api.py                     # UAM + REST alert surfaces
python tests/test_saved_filter_lifecycle.py              # skips if token lacks scope
python tests/test_custom_rule_lifecycle.py               # Custom Detection Rules
python tests/test_alert_mutation_lifecycle.py            # status + verdict round-trip
python tests/test_scheduled_report_lifecycle.py          # default-report tasks
python tests/test_alert_indicator_pivot.py               # alert→IOC pivot (single-scope)
python tests/test_uam_alert_interface_single.py          # POST 1 OCSF indicator + 1 alert
python tests/test_uam_alert_interface_batch.py           # batched POST 3 indicators + 1 alert
python tests/test_unified_exclusion_lifecycle.py         # EDR path exclusion CRUD
python tests/test_hyperautomation_import_lifecycle.py    # workflow IMPORT/LIST/DELETE
python tests/test_detection_rule_activate_lifecycle.py   # ENABLE/DISABLE scheduled + events
python tests/test_xdr_graph_query_lifecycle.py           # graph query CRUD (skips if no saved queries)
python tests/test_star_rule_lifecycle.py                 # STAR rule (events) CREATE/UPDATE/DELETE
```

All tests exit 0 on success. Run with `--keep` to skip cleanup and inspect what was created. Run with `--site-id <id>` or `--account-id <id>` to target a specific scope.

---

## Known limitations

- **HA delete:** delete a workflow with `DELETE /api/v1/workflows/{id}?accountIds=<acct>` (204, soft/recoverable). The older `POST /workflows/archive` returns 500 on this tenant; do not use it.
- **UAM batch indicator stitching:** Multi-indicator-to-alert stitching requires a grace window of up to 2 minutes. 2 of 3 indicators typically land within this window.
- **XDR graph query format:** The format is proprietary and server-validated. The test discovers it by reading an existing saved query. If no saved queries exist on the tenant, the test skips gracefully. Save one query via the XDR Graph Explorer UI to enable the test.
- **Purple AI NLQ via API token:** `purpleLaunchQuery NATURAL_LANGUAGE` requires a browser-session `teamToken`; service-account tokens are not supported. Use purple-mcp for NLQ.

Full field reference per endpoint is in `mgmt-console-api/tests/README.md` and `mgmt-console-api/SKILL.md`.
