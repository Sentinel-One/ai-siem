---
name: sdl-dashboard
author: Prithvi Moses <prithvi.moses@sentinelone.com>
description: >
  Use this skill any time the user wants to create, edit, design, generate, deploy, or debug a SentinelOne Singularity Data Lake (SDL) dashboard. Triggers include: "build me a dashboard", "create a dashboard panel", "write dashboard JSON", "add a panel to my dashboard", "deploy a dashboard to SDL", "I want a dashboard that shows...", "can you make a dashboard for...", "threat dashboard", "SOC dashboard", "network dashboard", "audit dashboard", "O365 dashboard", "hunting dashboard", or any request that involves SDL/Scalyr dashboard JSON. Also triggers when the user pastes dashboard JSON and wants help fixing, improving, or extending it. Use alongside sdl-api to deploy dashboards, and alongside powerquery to validate or compose the queries inside panels. Always use this skill when dashboards, dashboard panels, or SDL visualization is involved, even if the user just says "show me [metric] over time" in a security/SDL context.
---

# SentinelOne SDL Dashboard Skill

This skill helps you design, author, and deploy Singularity Data Lake (SDL) dashboards, from a single panel to a full multi-tab SOC dashboard. Dashboards live as configuration files in SDL and are authored as JSON (or a relaxed JavaScript-literal superset of it). You deploy them via the `sdl-api` skill's `put_file` method.

> **Sandbox proxy blocked?** If `put_file` or SDL API calls to `*.sentinelone.net` fail with a connection or proxy error inside the Claude sandbox, use the `s1-secops-mcp` server instead. It runs locally via `node` and bypasses the sandbox proxy entirely. Setup: add it to `claude_desktop_config.json` (see `s1-secops-mcp/README.md`). Use the `sdl_put_file` tool to deploy dashboards and `sdl_get_file` / `sdl_list_files` to inspect what's already deployed.

## Workflow

This workflow is mandatory for every new or modified dashboard. Steps 0, 1, and 7 are non-negotiable: pre-flight discovery, the safety pre-flight check, and the post-deploy log-evidence report. Skipping any of them produces dashboards that look fine in isolation but mislead, hang, or silently drop data.

0. **Discovery (MANDATORY for every session)**: Re-enumerate connected data sources (`| group UniqueDataSourceNames = array_agg_distinct(dataSource.name) | limit 1000`), run V1-query schema discovery on every source the dashboard will touch, and validate the discriminator field for any `event.type` you intend to count. See **Pre-authoring discovery** below. Never start a panel from a remembered schema.

   **Execution path for schema discovery via s1-secops-mcp:**

   1. **PowerQuery enumeration** (`array_agg_distinct(dataSource.name)`): run via `mcp__s1-secops-mcp__powerquery_run` directly. The s1-secops-mcp server runs locally and makes direct HTTPS calls without sandbox interference.
   2. **V1 query schema discovery** (full event JSON per source): use `mcp__s1-secops-mcp__powerquery_schema_discover` to fetch sample events from each data source and inspect their field names and types. The MCP server runs on your local machine and bypasses the sandbox proxy entirely.
1. **Understand the ask**: What data should the dashboard show? Who is the audience (SOC analyst, manager, customer POC)? What time range makes sense? What posture should each panel reflect (a panel that legitimately returns 0 needs a markdown header explaining the SOC-positive interpretation, see **Empty results are valid evidence**).
2. **Design the structure**: Choose tabs (if multi-topic), then panels per tab. Match panel type to the data shape using the guide in `references/panel-type-cheatsheet.md`. Key decisions: flows/kill-chains → `sankey`; KPI vs SLA target → `bullet`; SOC queue health → `gauge`; 3D outlier detection → `scattered_bubble`; time-based density → `heatmap`; multiple queries in one panel → tabbed table. Where one `event.type` covers multiple semantic populations (delivery-time vs click-time, scheduled vs on-demand, inbound vs outbound), build separate sections per population, not a mixed section.
3. **Write the JSON**: Use the panel type reference below and real examples in `references/community-examples.md`. Compute explicit `x`/`y`/`w`/`h` for every panel. Apply the naming-hygiene rule from **Panel naming hygiene** so titles read as SLA-grade claims.
4. **Validate queries**: Sample 3-5 events per source/event-ID to confirm field semantics. Test each panel query via the `powerquery` skill. Run the parallel load test (see **Pre-deploy validation**), acceptance thresholds: slowest panel ≤ 2s, wall-clock ≤ 5s. Run `scripts/panel_safety_check.py` against the dashboard JSON; resolve every flag before deploy.
5. **Deploy**: Use the `sdl-api` skill's GraphQL methods. First deploy only: `put_config_file(name="/dashboards/my-dashboard", content=...)`, then record the returned `udoId`. Every deploy after that: `config_file(udo_id=...)` for the current `version`, then `put_config_file(udo_id=..., content=..., expected_version=...)` as the CAS guard. A name-addressed write to an existing dashboard is refused because it duplicates. Save a backup of the prior JSON first. Sleep 3s, then re-read by `udo_id` to verify the version bumped AND grep the returned content for a canary string from your change.
6. **Iterate**: Show the user what was built, explain each panel, offer to tweak. If the dashboard hangs, follow the escalation ladder in **Pre-deploy validation**.
7. **Log-evidence report (MANDATORY)**: Run `scripts/validate_dashboard.py` against the deployed dashboard JSON to replay every panel, persist per-panel evidence (sample rows, row count, matchCount, elapsed, errors) to a JSON, and emit a markdown evidence file. Then run `scripts/render_validation_pdf.py` to render the PDF report (cover, per-tab sections, sample-data tables, empty-result appendix with SOC-meaningful interpretations). Deliver both alongside the dashboard. A dashboard delivered without an evidence report is incomplete.

   **`validate_dashboard.py` MUST be run as a background process**, at ~10s per panel, a 30-panel dashboard takes 5 minutes; a 60-panel dashboard takes 10-30 minutes. Both exceed the MCP timeout. Start it with `python3 scripts/validate_dashboard.py ... > /tmp/validate_out.txt 2>&1 &`, confirm the PID, then poll `len(json.load(open(evidence_json)))` vs the expected panel count in short separate calls. The script persists results after every panel (idempotent), so a cancelled poll never loses work. When a `stacked_bar` or `line` panel using `| transpose` returns 0 rows in validation, cross-check whether the corresponding number panel for the same source shows data, if it does, the empty result is a V1-API artefact, not a broken query. Document it in the Appendix as confirmed false-empty and do not remove the panel.

8. **Screenshot review with the user (MANDATORY).** API validation proves each panel's query returns rows; it does NOT prove the panel RENDERS. Render-only failures happen in the browser, not the API, so `validate_dashboard.py` cannot see them: a panel showing "Couldn't load content", a markdown tile showing "Untitled", a number reading "34 principals" under a title that already says principals, an empty chart, or a broken legend. After EVERY deploy, ALWAYS ask the user to open the dashboard and send screenshots of each tab, then read them, diagnose each visual defect, fix the JSON, and re-deploy, without waiting to be asked. Prompt explicitly, e.g.: "The dashboard is deployed at `/dashboards/<name>`. Please open it and send screenshots of each tab so I can catch any render-only issues and fix them automatically." Treat this as part of deployment, not optional polish. Fixes for the common render-only defects are in the **Quick triage** table.

## Pre-authoring discovery

Different tenants connect different data sources, and even the same tenant drifts between sessions as parsers are updated. Authoring a panel from a remembered schema is the single most common cause of empty-or-misleading dashboards.

### 1. Enumerate connected data sources every session

```text
| group UniqueDataSourceNames = array_agg_distinct(dataSource.name)
| limit 1000
```

If the source the dashboard is meant to cover does not appear, the dashboard cannot work. Stop and surface this to the user. Do not silently switch to a different source.

### 2. PowerQuery cannot discover a source's schema by itself

`| limit N` against a parser-emitted source returns only `timestamp + message`. PowerQuery has no `| columns *` or wildcard projection. Use the V1 query endpoint (`/api/query`, returns full event JSON) via the SDL client. Force-clear the scoped keys so auth falls through to the console JWT (which has `query` permission):

```python
from sdl_client import SDLClient
c = SDLClient()

res = c.query(filter=f"dataSource.name=='{source}'", max_count=50, start_time="7d")
attrs = sorted({k for m in res["matches"] for k in (m.get("attributes") or {}).keys()})
```

Persist `attrs` to a per-session JSON and reference it during panel authoring. Do this for every source the dashboard will query.

**SDL operations via s1-secops-mcp tools.**

All SDL operations should use the s1-secops-mcp MCP tools, which run locally and bypass the sandbox proxy:

| Operation | s1-secops-mcp tool |
|---|---|
| PowerQuery (enumeration, hunts, panel queries) | `mcp__s1-secops-mcp__powerquery_run` |
| V1 `query` (full event JSON for schema discovery) | `mcp__s1-secops-mcp__powerquery_schema_discover` |
| `put_file` / `get_file` / `list_files` (dashboard deploy) | `mcp__s1-secops-mcp__sdl_put_file`, `mcp__s1-secops-mcp__sdl_get_file`, `mcp__s1-secops-mcp__sdl_list_files` |

These tools run on your local machine and make direct HTTPS calls to the console host
without sandbox proxy interference. No fallback or workaround needed.

### 3. A field visible in `raw_data` may NOT be queryable

Parsers vary in what they extract to top-level OCSF / `unmapped.*` columns. A field plainly visible inside the `raw_data` JSON envelope may not exist as a queryable structured column. Always probe a single sample event with the V1 query to confirm a field is queryable before authoring a panel around it. Both the schema dump and a raw event are ground truth, neither alone is sufficient.

If a field is only present in `raw_data`, it can still be filtered via a full-text predicate but **cannot be grouped or aggregated** efficiently. See **Full-text predicate cost** below.

### 4. Identify the discriminator before counting

A single `event.type` value frequently bundles multiple distinct event kinds (delivery-time vs click-time, scheduled vs on-demand, inbound vs outbound, policy-event vs detection-event). The discriminator field, often named `creationMethod`, `messageType`, `triggerType`, `disposition`, etc., may or may not be promoted to the top level. Run an exploration query before authoring count panels:

```text
dataSource.name='<source>' event.type='<type>'
| group hits=count() by <candidate-discriminator>
| sort -hits
| limit 50
```

If the same `event.type` row repeats with different discriminator values, that secondary field is part of the partition key. Panels must filter on both, or split into separate sections per population. Counting "events of type X" without splitting by discriminator gives a number that conflates two semantically different things, which is the highest-cost class of dashboard bug because it looks correct.

### 4b. Null-check every grouping column before including it in a table panel

Before including any field as a grouping column in a table panel, confirm it is non-null for that specific `event.type`. A column that is null for all rows produces an empty column in the rendered table with no error. The check is one query:

```text
dataSource.name='<source>' event.type='<type>' <field>=*
| group count=count()
| limit 1
```

If this returns 0, that field is null for that event type. Remove it from the panel or replace with the correct field. **This check is mandatory for every column in every table panel, not just fields you suspect might be missing.**

Common trap: `src_endpoint.svc_name` (service name), `src_endpoint.ip`, and `app_name` may be populated for `traffic` events but null for `vpn` or `app-ctrl` events from the same source. Schema discovery on `traffic` events does not transfer to other event types.

### 5. `event.type` is not always the right partition key

Some sources emit multiple log subtypes under the same `event.type` (header logs vs body logs, policy events vs detection events). Run the same exploration query above with `event.type` PLUS a secondary discriminator before assuming `event.type` partitions the source cleanly.

---

## PowerQuery feature gaps to design around

The catalog of PowerQuery patterns that 500 or render badly inside dashboard JSON, the safe patterns to prefer, the two-pass quoted-KV parse, and the totals-plus-breakdown workaround is in [`references/powerquery-gaps.md`](references/powerquery-gaps.md). `scripts/panel_safety_check.py` scans for the failing patterns automatically.

---

## Empty results are valid evidence (but distinguish from query errors)

A query that runs successfully and returns 0 rows is a real datapoint, not a bug. Examples:

- A "policy violations blocked" panel returning 0 because the policy is in monitor-only mode.
- A "malicious URL delivered" panel returning 0 because the engine hard-blocks at a different layer.
- A "compromised account auth" panel returning 0 because no compromise occurred this window.

Rules:

1. **Never silently switch the query** to make a panel "have data." If 0 is correct, surface it.
2. **Distinguish 0-row from 0-matchCount.** A successful query with `matchCount > 0` and `rowCount = 0` means the post-pipe steps eliminated everything (often a `| filter` after `| group`). A query with `matchCount = 0` means no events matched the initial filter at all. The first hints at refining the filter; the second hints at validating coverage.
3. **In dashboards, a panel that may legitimately be 0 should have a markdown header that explains the SOC-positive interpretation.** Example: *"0 here is the desired posture; non-zero indicates a regression worth investigating."* Without this, an analyst reads a blank panel as a broken dashboard.
4. **In the evidence report (mandatory deliverable), every empty panel must include the underlying matchCount** so the reader can tell whether the source has data at all. The PDF Appendix lists every empty-result panel with its SOC-meaningful interpretation.

---

## Full-text predicate cost (when to use raw_data string matching)

When a field needed for the panel is buried inside `raw_data` rather than parsed to a structured column, the only filter is a full-text predicate against `raw_data`. Example:

```text
dataSource.name='<source>' event.type='<type>' '<json-snippet>'
```

The bare-string token is interpreted as a literal substring search across `raw_data`. It works but the cost is significant: full-text scan reads every event in the time window before applying the predicate, so cost is proportional to total events scanned, not to the matched subset. Combined with `| group` over high-cardinality dimensions, full-text predicates frequently exceed the 60s MCP timeout. Combined with `timebucket + transpose`, they almost always time out.

### Safe full-text patterns

| Use | Example | Why it works |
|---|---|---|
| Number panel: simple count | `<src> '<token>' \| group n=count() \| limit 1` | One row, no grouping; fast even at 100k+ events |
| Number panel: count with structured co-filter | `<src> '<token>' <field>='<value>' \| group n=count() \| limit 1` | Co-filter narrows scan first |
| Table panel: top-N with restrictive co-filter | `<src> '<token>' <selective-field>='<value>' \| group ... by ... \| sort \| limit 25` | Working set is small after co-filter |

### Risky full-text patterns

| Use | Why it fails |
|---|---|
| Stacked-bar timeline with full-text + transpose | Scan + bucket + group + transpose under full-text → timeout |
| Top-N grouping over the whole source under full-text | High-cardinality grouping under full-text → timeout |
| Multiple full-text tokens combined (`'<a>' '<b>' \| ...`) | Each token is a separate scan; cost compounds |

### Design rule

If a panel needs a discriminator that lives in `raw_data` only, lobby the parser team to promote it to a top-level structured field. Until then, design the panel to use full-text only where the cost is acceptable (number panels, selective tables) and replace timeline / heavy-grouping panels with structured-field equivalents.

---

## Panel naming hygiene

The single most common cause of misleading dashboards is a panel title that overstates what the underlying query measures.

| Wrong title | Why it's wrong | Correct title |
|---|---|---|
| "URL clicks" | Counts both clicks and delivery-time scans | "URL events (clicks + scans)" |
| "Phishing emails clicked" | Counts events that include a click discriminator AND those that don't | "Phishing-classified emails (events)" |
| "Allowed malicious URLs" | Counts the rewriting policy disposition, not the user's actual click | "Malicious URL events delivered (warn)" |
| "Distinct users compromised" | Counts users associated with a detection, not confirmed-compromise users | "Distinct users with detected events" |

Rule: **the panel title should be readable as an SLA / report claim.** If a CISO would feel misled reading the title without seeing the query, rename the panel.

When two semantically distinct event populations exist within the same `event.type` (delivery-time vs click-time, scheduled vs on-demand), build separate sections of the dashboard for each population, with markdown headers that explain the split. A single section that mixes both populations is almost always wrong.

---

## Dashboard JSON structure

A dashboard is a JSON object (SDL also accepts unquoted keys, JavaScript-literal format). Three top-level shapes:

### Single-tab dashboard

```json
{
  "duration": "4h",
  "description": "Optional text shown below the title",
  "graphs": [ /* array of panel objects */ ]
}
```

### Multi-tab dashboard

```json
{
  "configType": "TABBED",
  "duration": "24h",
  "description": "",
  "tabs": [
    { "tabName": "Overview", "graphs": [ /* panels */ ] },
    { "tabName": "Details",  "graphs": [ /* panels */ ] }
  ]
}
```

### Top-level properties

| Property | Description |
|---|---|
| `duration` | Default time range: `"30m"`, `"4h"`, `"1 day"`, `"7 days"` |
| `description` | Subtitle shown under the dashboard title |
| `graphs` | Array of panel objects (single-tab) |
| `tabs` | Array of `{tabName, graphs}` objects when `configType: "TABBED"` |
| `configType` | Set to `"TABBED"` for multi-tab dashboards |
| `parameters` | Array of `{name, values, defaultValue}`: creates dropdown/text filters |
| `options` | `{"layout": {"fixed": 1}}` to lock drag-and-drop |
| `teamEmails` | Array of account emails whose data is pooled |

## Panel types

Every panel is an object inside `graphs`; the `graphStyle` property picks the panel type. Every panel also needs an explicit `layout` object with `x`, `y`, `w`, `h` (omitting them can hang the renderer).

The full per-panel JSON catalog (layout helper, line/area, stacked bar, pie/donut, table, number/gauge, honeycomb, heatmap, distribution, and markdown panels) is in [`references/panel-types.md`](references/panel-types.md), with a one-line-per-panel summary in [`references/panel-type-cheatsheet.md`](references/panel-type-cheatsheet.md).

---

## Common rendering pitfalls

These are silent failures, the API accepts the JSON, the panel mounts, but
either nothing draws or the panel hangs on the spinner. Apply the fix
preemptively when authoring panels of these shapes.

| Symptom | Root cause | Fix |
|---|---|---|
| Markdown panel renders blank, no error | Wrong body field | Use `markdown:` (NOT `content:`): see Markdown panel section above |
| Markdown panel header shows "Untitled" | No `title` key on the markdown panel (S-26.1) | Add a short plain-text `title`; keep prose (no repeated `##` heading) in `markdown` |
| Number panel reads the unit twice, e.g. "34 principals" under "Active principals (24h)" | `options.suffix` duplicates a unit already in the `title` | Remove `suffix` (or drop the unit from the title); keep `{format, precision}` only |
| Category bar/line panel errors "The first column ... should have numeric value in epoch" | `graphStyle: "bar"` / `"line"` / `"area"` default to a TIME x-axis and require an epoch first column; a `(category, count)` query has a string first column | Use `graphStyle: "stacked_bar"` with `"xAxis": "grouped_data"`; keep the `(category, value)` query. `bar` alone is NOT a categorical bar chart |
| `area` chart with `query` field shows an indefinite spinner; no error in UI | `graphStyle: "area"` is built around the `plots: [...]` pattern. A query-driven multi-series chart that ends in `transpose` does not render under `area`. | Switch to `graphStyle: "stacked_bar"` (or `"line"`) with `xAxis: "time"`. The query body stays the same. |
| `plots`-based line or area panel returns "No results found" even though data clearly exists (confirmed via a number or table panel on the same source) | The `plots: [{ "filter": "...", "facet": "..." }]` filter mechanism silently ignores fields in the `unmapped.*` namespace. Any predicate like `unmapped.action='deny'` in a `filter` string inside `plots` matches 0 events regardless of actual data volume. No error is surfaced, the panel just shows empty. | Replace with a PowerQuery `stacked_bar` + `\| transpose` panel. The PowerQuery engine fully supports `unmapped.*` fields. The query body is equivalent: `<source-filter> unmapped.action in ('deny', ...) \| group count=count() by timestamp=timebucket('1h'), action=unmapped.action \| transpose action on timestamp`. |
| `Couldn't load content`: `field=[DashboardPlotQuery.plotIndex] error=[Facet for plot at index: 0 is invalid]` | `"facet": "count()"` (with parentheses) is invalid in a `plots` array. Only `"facet": "count"` (no parentheses) is accepted. The community examples in older docs show `count()`; this is wrong. | Use `"facet": "count"` (no parentheses) in every plots entry. |
| `Couldn't load content`: `"transpose" can only be used as the last command in a query` | `transpose` is the terminal command in the PQ pipeline; nothing can follow it | Remove any `\| limit N` / `\| sort` / `\| filter` placed AFTER `transpose`. If you need a limit, apply it pre-transpose via a subquery or a column-list filter |
| `Couldn't load content`: `Identifier "x-y" is ambiguous. To subtract, add spaces: "x - y". Otherwise, add backslashes: "x\-y"` | The PQ parser reads hyphenated text as a single identifier, not as subtraction | Add spaces around `-` in arithmetic: `total - min`, `max - min`, `(a - b) / (c - d)`. Same applies to all PQ panels and rule bodies. |
| `transpose <field> on timestamp` hangs the renderer when field values contain hyphens (e.g. `db-prod-01`, ISO dates, UUIDs, container names) | The renderer must parse the transposed values as column names for the chart legend. The PQ parser reads `db-prod-01` as subtraction and throws `Identifier is ambiguous`, or hangs silently. The V1 API tolerates this; the renderer does not. | **Option A**, pre-process: `\| let host_safe = replace(host_raw, '-', '_')` then transpose on `host_safe`. `replace_all` does NOT exist in SDL PowerQuery (live-verified 2026-07-29); use `replace`. If the tenant's `replace` substitutes only the first occurrence, values with multiple hyphens (`db-prod-01`) still break, so treat Option A as best-effort. **Option B (preferred for by-host charts)**: avoid transpose on hyphenated values entirely and use `"xAxis": "grouped_data"` with a grouping query. Loses time dimension but renders reliably. **Option C**: only use `transpose` on fields whose values are guaranteed free of hyphens (numeric codes, single-token labels like `Success`/`Failure`). |
| Number panel, table panel, or whole dashboard slow to load on first open | "All API queries pass" ≠ "dashboard loads fast". The browser fires all panel queries in parallel; total load time ≈ slowest single panel. Serial validation in a script wildly overestimates wall-clock load time. | Run a parallel load test before every `put_file`: see **Pre-deploy validation** section below. Acceptance thresholds: slowest single panel ≤ 2s, wall-clock ≤ 5s, zero failures. |
| `get_file` returns HTTP 404 immediately after a successful `put_file` | `put_file` is synchronous but the file propagates across replicas with eventual consistency (~2-3s). | Always `time.sleep(3)` between `put_file` and the subsequent `get_file` verification call. |
| Heatmap panel renders blank, no error, data confirmed in PowerQuery | `rangesCreation: "automatic"` requires empty-string middles in `heatmapRangeConfig`. Providing explicit numeric strings (e.g. `"10"`, `"50"`) conflicts with automatic mode and the renderer silently returns a blank panel. | Restore to `["-∞", "", "", "", "", "∞"]`. SDL auto-calculates the middle thresholds from live data. |
| Heatmap (or any panel) renders blank after a config change, but the query returns data | Stale SDL UI session state can persist across config deployments. The browser renderer caches the prior render state and does not always reload after a `put_file`. | Log out and log back in to the SDL console. This clears session state and forces a fresh render. Do not assume a config bug until you have ruled out a stale session. |
| `min(timestamp)` / `max(timestamp)` displays as a giant integer like `1.777e18` | Aggregating over `timestamp` returns raw nanoseconds. The renderer has no implicit date formatter for aggregate output. | Wrap with `simpledateformat(min(timestamp), 'yyyy-MM-dd HH:mm:ss z', '<TZ>')`. For millisecond-typed fields (e.g. `time` on `dataSource.name='asset'`), multiply by 1000000 first: `simpledateformat(max(time) * 1000000, ...)`. Functions that do NOT exist: `format_timestamp`, `formatTimestamp`, `iso8601`, `date_format`. |
| Hostname/value-list filter is slow or behaves differently in the renderer vs API | `field matches '(host-a\|host-b)'` is evaluated as a regex per event, and hyphenated literals inside alternation can interact with the parser. | Use `field in ('host-a', 'host-b', 'host-c')` for any fixed list. Faster (indexed lookup), no escaping needed, consistent across renderer and API. Fall back to `matches` only when a true regex pattern is needed. |
| "User" panels dominated by machine accounts (e.g. `host123$`, `dc-prod-01$`) | Machine accounts carry a trailing `$` and appear in the same fields as human accounts. | Add `\| filter !(field matches '.*\\$$')` after the event filter and before the group. Verify with 5-10 sample rows that no machine accounts leak through. |
| Dashboard panel times out, indefinite spinner | A subquery inside the main query forces the engine to scan-and-aggregate twice. Dashboards rerun panels on every load, so the cost compounds. | Don't gate a panel query on a subquery if you can avoid it. Hardcode top-N values via inline OR clauses, or accept the full cardinality (often small after the initial filter). If a subquery is unavoidable, prefer a `lookup` against a precomputed datatable. |
| Number panel slow on a busy index | Engine keeps scanning after the answer is computed | Always terminate number panels with `\| limit 1` after the `\| group` that reduces to one row |
| Wide range + fine `timebucket` = thousands of points per series | E.g. `timebucket("10m")` over 7d = 1,008 points × N series | Match bucket to duration: 1d → `10m`, 7d → `1h` (minimum), 30d → `1 day` minimum |
| Two or more near-identical dashboards share a name in *Configuration files* | `/dashboards/id/<udoId>/<name>` is a display string, not a path; writing to it returns `no file exists at path`. Duplicates come from `addConfigFile(name:)` creating a copy instead of updating, so every name-addressed deploy adds one. A name-addressed copy (`udoId: null`) can also coexist with udoId-addressed ones. | Resolve the name with `sdl_list_files` (`pathPrefix: "/dashboards/"`) and address every update by `udoId`. Name-addressed writes are for the first create only; `sdl_put_file` refuses the rest. Delete surplus copies by `udoId`. |
| `columns resources[0].name` or `vulnerabilities[0].cve.uid` returns HTTP 500 | PowerQuery does not accept bracket-array indexing in `columns`. The V1 query API exposes nested arrays as flattened keys (`resources[0].name`) for display, but those flattened keys are NOT valid PowerQuery field paths. | Use top-level scalar fields only (`severity_id`, `finding_info.title`, `metadata.product.name`, `class_name`, `time`). For first-element access inside a query, use `array_get(resources, 0).name` only inside `let`. For richer drill-down, switch from PowerQuery to the V1 query API (returns full event JSON); see `sdl-api` skill. |
| `\| parse "app=$val$" from message` fails with "Start quote with no matching end quote" when the raw field value is wrapped in double quotes (e.g. `app="HTTPS.BROWSER"`) | The `\| parse` format string uses `"..."` as its outer delimiter. Any `"` character embedded in the format, to match quote-wrapped KV values common in network device logs, is treated as a string terminator. No escape sequence (backslash, single-quote outer, hex) works around this. | Use a two-pass parse: pass 1 captures the entire non-whitespace token including quotes (`{regex=\\S+}`), pass 2 extracts the clean value from that token. See **Two-pass parse for quoted KV values** below. |

---

## Parameters and filters (dynamic filtering)

SDL's two dynamic-filtering mechanisms, `filters[]` for TABBED dashboards and `#VarName#` substitution for flat and TABBED dashboards, plus the UI-only `parameters[]` behavior, are documented in [`references/parameters-and-filters.md`](references/parameters-and-filters.md).

---

## Common SDL data sources and event patterns

Source-by-source field patterns and starting-point queries (S1 internal OCSF sources, EDR/XDR telemetry, third-party sources, and common panel query shapes) are in [`references/data-source-patterns.md`](references/data-source-patterns.md). Re-run live schema discovery before authoring panels; these are starting points, not a registry.

---

## Deploying a dashboard via API

Deployment via the `sdl-api` GraphQL methods (resolve the `udoId`, write with a CAS guard, verify by re-fetch with a canary grep, and handle name-vs-udoId duplicates) is documented in [`references/deployment.md`](references/deployment.md).

---

## Reference files in this skill

- `references/panel-types.md`: full per-panel JSON catalog for every `graphStyle` (moved out of this file).
- `references/panel-type-cheatsheet.md`: one-line summary of every panel type plus gotchas.
- `references/powerquery-gaps.md`: PowerQuery patterns that fail inside dashboard JSON, safe alternatives, and parse workarounds (moved out of this file).
- `references/parameters-and-filters.md`: dynamic filtering deep detail (`filters[]`, `#VarName#`, `parameters[]`) (moved out of this file).
- `references/data-source-patterns.md`: source-by-source field patterns and starting-point queries (moved out of this file).
- `references/query-performance.md`: per-query performance rules for dashboard panels (moved out of this file).
- `references/deployment.md`: deploy via API, pre-deploy validation, escalation ladder, and the pre-deploy checklist (moved out of this file).
- `references/community-examples.md`: full real-world dashboard JSON examples (console audit, threat stats, alert investigation, O365, Fortinet).
- `references/common-queries.md`: ready-to-paste PowerQuery snippets for common security use cases.
- `references/lessons-learned.md`: source-agnostic patterns and gotchas from production engagements (PowerQuery feature gaps, full-text cost, naming hygiene, discriminator handling, validation runner shape).
- `references/evidence-report-template.md`: required format for the post-deploy log-evidence report (per-panel JSON, markdown, PDF appendix).

Read the community examples before creating a new dashboard, and read `lessons-learned.md` if any of: a panel may legitimately return 0, an `event.type` covers multiple semantic populations, the panel needs a field only present in `raw_data`, or a previous version of this skill produced a 500 error on `count_if`, `sum(if())`, or mid-pipeline `| union`.

## Skill scripts (in `scripts/`)

These scripts are mandatory parts of the workflow, not optional tooling.

- `scripts/panel_safety_check.py <dashboard.json>`: pre-deploy. Scans dashboard JSON for known-bad patterns (markdown `content` vs `markdown` field, `area` + `query`, transpose-not-terminal, hyphenated arithmetic, `count_if` / `sum(if())` / mid-pipeline `| union` (union-first is allowed) / named subqueries, `\\s`/`\\d` regex escapes inside `matches`, full-text combined with timebucket+transpose, missing layout, missing `| limit` on number/table panels). Exits non-zero on any flag. Run before every `put_file`.
- `scripts/validate_dashboard.py <dashboard.json> [--start 7d] [--out <dir>]`: post-deploy. Replays every non-markdown panel against the SDL `power_query` API, persists per-panel evidence (style, query, elapsed, rowCount, matchCount, columns, sample rows, error) to a JSON keyed on `tab::title`, and emits a markdown evidence file. Idempotent, resumes cleanly, persists after each panel. Auth falls through to console JWT (force-clears scoped keys). **Always run as a background process** (`... &`); see step 7 in the Workflow section. Do not wait for it inline.
- `scripts/render_validation_pdf.py <evidence.json> [--out <pdf>]`: post-deploy. Reads the validation JSON and emits a PDF report with cover page, per-tab sections, sample-data tables (first 3 rows of N), and an Appendix listing every empty-result panel with the operator's prepared SOC-meaningful interpretation. The PDF is the leadership deliverable; the markdown evidence stays in version control.

## Log-evidence report (mandatory deliverable)

Every dashboard delivered, whether new or modified, ships with a log-evidence report. The report's purpose is to prove that each panel's query runs against live data, captures actual sample rows, and either renders data or has a documented reason for being empty. Without this report a dashboard is incomplete; do not consider the workflow done.

The minimum the report captures, per panel:

- `ok` (did the query execute), `elapsed_s`, `row_count`, `columns`, `sample_rows` (first 3 rows verbatim, this is the log evidence), `matchCount` (events scanned before grouping), `error` (first 300 chars when `ok=False`).

Verdict per panel style:

| Panel style | Pass condition |
|---|---|
| `number` | `row_count == 1` and `len(columns) == 1`; OR `row_count == 0` (acknowledged empty) |
| `donut` / `pie` | `row_count >= 1` and `len(columns) >= 2` (text + numeric); OR `row_count == 0` |
| `stacked_bar` / `bar` / `line` / `area` | `row_count >= 1` and `len(columns) >= 2`; OR `row_count == 0` |
| `table` | Always passes if `ok=True`; sample rows captured |
| `markdown` | Excluded (no query) |

The PDF report MUST include an Appendix listing every empty-result panel (`row_count == 0`) with its SOC-meaningful interpretation, sourced from the markdown header authored alongside the panel. A panel returning 0 rows without explanation is indistinguishable to the reader from a broken panel; always document the "why."

See `references/evidence-report-template.md` for the exact structure.

---

## Query performance tips

The per-query performance rules for dashboard panels (`net_rfc1918()` over hand-rolled CIDR regex, `| limit` on number and table panels, `field=*` presence checks, timebucket-vs-duration sizing, `estimate_distinct()`, and `number()` casting of string-typed numeric fields) are in [`references/query-performance.md`](references/query-performance.md).

---

## Pre-deploy validation

The browser-renderer execution path, the parallel load test with its acceptance thresholds, and the deploy-and-verify sleep window are in [`references/deployment.md`](references/deployment.md).

---

## Field semantics: verify before grouping

Two patterns cause panels to look broken silently:

**Subject vs target in Windows logon events.** For event 4624 on a domain controller, `subjectUserName` is almost always the machine account or `-`. The account that actually logged on is in `targetUserName`. A panel that groups by `subjectUserName` renders mostly empty rows.

**Same field name, different semantic per event ID.** `targetUserName` in 4624 is the human account; in 4771 (Kerberos pre-auth failure) it includes machine accounts (`host123$`). 4625 and 4740 may use `subjectUserName` depending on the failure path.

Always sample 3-5 events per event ID before authoring a grouping query:

```python
res = c.query(
    filter=f"dataSource.name=='<source>' <event-id-filter> <host-filter>",
    max_count=5, start_time="1h",
)
for m in res.get("matches") or []:
    attrs = m.get("attributes", {})
    for k in sorted(attrs.keys()):
        if any(s in k.lower() for s in ("user","subject","target","domain","logonid")):
            print(f"  {k} = {str(attrs[k])[:80]}")
```

This is the same V1-query schema-discovery pattern from the `sdl-api` skill, apply it per-event-ID, not just per-source.

---

## Escalation ladder when a deployed dashboard hangs

The step-by-step escalation ladder for a deployed dashboard that hangs (session reset, hard refresh, dev-tools network check, isolate the slow panel, halve the panel count, diff against a working dashboard, roll back) is in [`references/deployment.md`](references/deployment.md).

---

## Pre-deploy checklist

The full pre-deploy checklist (pre-authoring, JSON structure, query hygiene, naming and semantics, performance and load, deployment, and post-deploy items, with `scripts/panel_safety_check.py`-scripted items marked) is in [`references/deployment.md`](references/deployment.md).

---

## Design tips

- **Use tabs** for dashboards covering multiple topics (threat overview, policy changes, user activity). Keep each tab focused.
- **Start with number panels** at the top for KPIs, then tables and charts below.
- **Avoid breakdown graphs** in production dashboards: they can time out and can't be pre-cached. Use explicit labeled plots instead.
- **Lock layout** with `options: {"layout": {"fixed": 1}}` to prevent accidental repositioning.
- **Use `showBarsColumn: "true"`** on table panels with a count column to get inline bar charts.
- **Time range**: set `duration` to match how "fresh" the data needs to be. Use `"24h"` for security operations / alert-triage dashboards (the standard for SOC real-time views), `"7 days"` for trend and capacity dashboards. Never default to `"7 days"` for an operations dashboard, analysts lose the short-window density that makes operational dashboards useful.
- **Test queries first** with the `powerquery` skill before embedding them in dashboard JSON.
- **Use `estimate_distinct()`** for cardinality counts: exact distinct is expensive on large datasets.
- **Add a markdown panel** to each tab explaining what it covers: this helps both users and future editors understand the dashboard at a glance.

## Sandbox proxy blocked? Use Desktop Commander

Dashboard deployment uses `sdl_client.py` from the `sdl-api` skill, which
makes direct HTTPS calls to `*.sentinelone.net`. If you see `SandboxProxyBlockedError`
or `OSError: Tunnel connection failed: 403 Forbidden`, the Cowork sandbox proxy is
blocking those calls.

The fix: use s1-secops-mcp MCP tools instead. Use `sdl_put_file` and `sdl_get_file`
to deploy dashboards directly. These tools run locally and bypass the sandbox proxy entirely.
No Desktop Commander workaround is necessary.
