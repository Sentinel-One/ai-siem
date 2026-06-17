# MCP Tools Reference

Full reference for all tools exposed by `s1-secops-mcp` and `purple-mcp`. For architecture context see [architecture.md](./architecture.md).

---

## s1-secops-mcp

Runs as a local Node.js process. Source: `s1-secops-mcp/index.js`. Install via `claude_desktop_config.json`: see [credentials.md](./credentials.md).

### PowerQuery tools

**`powerquery_enumerate_sources`**
Lists every `dataSource.name` active in SDL over the last 24 hours. Run this at the start of every session: never assume which sources are present. Returns unique source names, vendors, and categories.

**`powerquery_run`**
Executes a PowerQuery string via the SDL Long-Running Query (LRQ) API. Polls until results are ready. Returns tabular results. Use for threat hunting, baseline queries, custom detection rule validation, and any SDL telemetry question.

**`powerquery_schema_discover`**
Runs a V1 `query` (full-event JSON) against a specific `dataSource.name` to return field names and sample values. Use this before writing any query against a source: field names drift between sessions due to parser edits and reserved-field rewrites. Returns a dict of `{field_name: [sample_values]}`.

### Management Console REST tools

These five tools are generic REST wrappers over the S1 Management Console API v2.1 (781 operations, 113 tags). The path always starts with `/web/api/v2.1/`.

**`s1_api_get`**
Read any resource: agents, threats, sites, alerts, detection rules, exclusions, IOCs, accounts, groups, policies, and more. Supports all query parameters as a `params` dict. Example: `GET /web/api/v2.1/agents?limit=20&siteIds=123`.

**`s1_api_post`**
Create or action: create IOC, create detection rule, isolate endpoint, add exclusion, create Hyperautomation workflow, etc. Body is passed as-is: the tool does not auto-wrap in `{"data": {...}}`. Check the swagger or SKILL.md for the correct envelope per endpoint.

**`s1_api_put`**
Full-replace update: update detection rule, update policy, update exclusion. Requires all mandatory fields: omitting required fields returns 400.

**`s1_api_patch`**
Partial update: used for endpoints that support PATCH (fewer than PUT). Rare in the S1 API.

**`s1_api_delete`**
Delete with filter body: delete IOCs, detection rules, exclusions. Many S1 DELETE endpoints accept a filter body (e.g. `{"filter": {"ids": [...]}}`). Pass it as the `body` param.

Reference: `mgmt-console-api/SKILL.md` for confirmed body schemas and required fields per endpoint surface.

### UAM tools

**`uam_list_alerts`**
List UAM alerts via GraphQL. Filter with individual convenience params, not a single filter string: `status` (valid values `NEW`, `IN_PROGRESS`, `RESOLVED` only — there is no `OPEN`, which silently returns 0 results), `severity` (e.g. `CRITICAL`), `detectionProduct` (e.g. `EDR`), `searchText`, plus `startTime`/`endTime` for a time window and `first`/`after` for pagination. Returns UUID-based alert objects with full context.

**`uam_get_alert`**
Fetch a single UAM alert by UUID. Returns full alert detail including raw indicators, assets, threat info, analyst notes, and history.

**`uam_add_note`**
Add a text note to an alert. Appears in the alert's notes history.

**`uam_set_status`**
Set alert status. Valid values: `NEW`, `IN_PROGRESS`, `RESOLVED`. To mark an alert as a false positive, add a note via `uam_add_note` explaining why and set status to `RESOLVED`. Verdict (`analystVerdict`) is a separate field on the alert; this tool does not change it.

**`purple_ai_alert_summary`**
Generate a Purple AI natural-language summary for a specific UAM alert. Pass the alert's OCSF JSON (as returned by `uam_get_alert`) and receive a `{ token, summary }` result that's identical to what the Purple AI card surfaces in the console alert detail. Synchronous; no polling.

**`uam_ingest_alert`**
Ingest a synthetic alert via the UAM Alert Interface (HEC). For creating test/synthetic alerts. Requires `S1_HEC_INGEST_URL` and `S1_CONSOLE_API_TOKEN`.

**`uam_post_alert`**
Post an OCSF-formatted alert to the HEC ingest endpoint.

**`uam_post_indicators`**
Post OCSF-formatted threat intelligence indicators (file, network, process observables) to the HEC ingest endpoint.

### SDL tools

**`sdl_list_files`**
List configuration files on the SDL tenant (parsers, dashboards, lookups, datatables). Filter by path prefix, e.g. `/logParsers/` or `/dashboards/`.

**`sdl_get_file`**
Download the content of a specific SDL configuration file by path.

**`sdl_put_file`**
Upload or update a configuration file on SDL. Used for deploying parsers and dashboards. Requires `SDL_CONFIG_WRITE_KEY` or a console JWT with configuration write access.

**`sdl_delete_file`**
Delete a configuration file from SDL by path.

**`hec_ingest`**
Ingest raw logs/events into SDL via the HEC (HTTP Event Collector) endpoint. Applies a named parser via `?sourcetype` and lands the data for Event Search, PowerQuery, and detection rules. Posts to `S1_HEC_INGEST_URL` with `Authorization: Bearer <S1_CONSOLE_API_TOKEN>`; the `S1-Scope` header (accountId or accountId:siteId) is required. Replaces the removed `sdl_upload_logs`. Used for ingesting custom telemetry or test events during parser development.

### Hyperautomation tools

**`ha_list_workflows`**
List Hyperautomation workflows on the tenant. Supports scope, sort, and pagination. Returns each workflow's `id`, `name`, `state`, `status`, `revisionId`, and action list.

**`ha_get_workflow`**
Fetch a single workflow by `workflowId` and optional `revisionId`. Auto-resolves `revisionId` from the list if omitted.

**`ha_import_workflow`**
Import a workflow JSON into the tenant. Requires `Hyper Automate.write` permission. Creates the workflow in draft state. Response uses `id` (not `workflowId`) and `version_id` (not `versionId`).

**`ha_export_workflow`**
Export all workflows as a ZIP archive.

**`ha_delete_workflow`**
Delete one or more workflows via `DELETE /workflows/{id}` (soft, recoverable). Scope with `accountIds` or `siteIds` to match where the workflow lives. Requires Hyper Automate.write permission.

---

## purple-mcp

Fetched automatically from GitHub via `uvx` on first launch. Source: `github.com/Sentinel-One/purple-mcp`. No local install needed.

### Alert tools

**`list_alerts`**
List UAM alerts with rich filter support (status, severity, detection product, date range). Returns paginated alert summaries.

**`search_alerts`**
Text-search across alerts. Returns matching alerts with relevance context.

**`get_alert`**
Full alert detail: indicators, assets, threat info, agent, analyst notes, history.

**`get_alert_history`**
Audit log of all status and verdict changes for an alert.

**`get_alert_notes`**
All analyst notes added to an alert (includes MDR closure notes and analyst verdicts).

**`uam_add_note`** / **`uam_set_status`**
Alert annotation and triage (purple-mcp versions; prefer these over s1-secops-mcp equivalents for richer field access).

### Asset and inventory tools

**`list_inventory_items`** / **`search_inventory_items`** / **`get_inventory_item`**
Agent inventory: OS, version, network interfaces, groups, policy, last-seen, agent UUID. Use `get_inventory_item(agent_uuid)` to get asset criticality context during alert triage.

### Vulnerability tools

**`list_vulnerabilities`** / **`get_vulnerability`** / **`get_vulnerability_history`** / **`get_vulnerability_notes`**
CVE and patch gap data per agent. Filter by severity, exploitability, CVE ID.

### Misconfiguration tools

**`list_misconfigurations`** / **`get_misconfiguration`** / **`get_misconfiguration_history`** / **`get_misconfiguration_notes`**
Agent configuration hygiene findings (missing EDR, outdated agent, policy gaps).

### Purple AI tools

**`purple_ai`**
Natural-language query against SDL telemetry. Sends the question to the Purple AI LLM, which returns a PowerQuery string plus an English summary. Claude then executes the returned query via `powerquery_run`. Requires Purple AI tenant entitlement.

**`powerquery`**
Run a raw PowerQuery string via the SDL LRQ engine (purple-mcp version). Equivalent to s1-secops-mcp `powerquery_run`.

### Timestamp tools

**`get_timestamp_range`**
Convert human-readable time ranges ("last 7 days", "yesterday") to epoch milliseconds for use in queries.

**`iso_to_unix_timestamp`**
Convert ISO 8601 timestamps to Unix milliseconds.

---

## Which tool to use for what

| Task | Tool |
|---|---|
| Hunt for process/network/file events in SDL | `powerquery_run` or purple-mcp `powerquery` |
| Natural-language investigation query | purple-mcp `purple_ai` |
| List/triage/annotate alerts | purple-mcp alert tools (richer); s1-secops-mcp UAM tools as fallback |
| Get agent inventory, vulnerability, misconfiguration | purple-mcp |
| Agents, threats, sites, groups, policies (REST) | `s1_api_get` / `s1_api_post` |
| Create/update/delete detection rules or exclusions | `s1_api_post` / `s1_api_put` / `s1_api_delete` |
| Deploy parser or dashboard to SDL | `sdl_put_file` |
| Ingest custom log events | `hec_ingest` |
| Import Hyperautomation workflow | `ha_import_workflow` |
| Enrich IOC (IP, hash, domain, URL) | Threat-intel MCP tools (default bundle: virustotal-mcp; substitute your provider's tools if different) |
