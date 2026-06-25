---
name: sdl-dashboard
author: Prithvi Moses <prithvi.moses@sentinelone.com>
description: >
  Use this skill any time the user wants to create, edit, design, generate, deploy, or debug a SentinelOne Singularity Data Lake (SDL) dashboard. Triggers include: "build me a dashboard", "create a dashboard panel", "write dashboard JSON", "add a panel to my dashboard", "deploy a dashboard to SDL", "I want a dashboard that shows...", "can you make a dashboard for...", "threat dashboard", "SOC dashboard", "network dashboard", "audit dashboard", "O365 dashboard", "hunting dashboard", or any request that involves SDL/Scalyr dashboard JSON. Also triggers when the user pastes dashboard JSON and wants help fixing, improving, or extending it. Use alongside sdl-api to deploy dashboards, and alongside powerquery to validate or compose the queries inside panels. Always use this skill when dashboards, dashboard panels, or SDL visualization is involved — even if the user just says "show me [metric] over time" in a security/SDL context.
---

# SentinelOne SDL Dashboard Skill

This skill helps you design, author, and deploy Singularity Data Lake (SDL) dashboards — from a single panel to a full multi-tab SOC dashboard. Dashboards live as configuration files in SDL and are authored as JSON (or a relaxed JavaScript-literal superset of it). You deploy them via the `sdl-api` skill's `put_file` method.

> **Sandbox proxy blocked?** If `put_file` or SDL API calls to `*.sentinelone.net` fail with a connection or proxy error inside the Claude sandbox, use the `s1-secops-mcp` server instead. It runs locally via `node` and bypasses the sandbox proxy entirely. Setup: add it to `claude_desktop_config.json` (see `s1-secops-mcp/README.md`). Use the `sdl_put_file` tool to deploy dashboards and `sdl_get_file` / `sdl_list_files` to inspect what's already deployed.

## Workflow

This workflow is mandatory for every new or modified dashboard. Steps 0, 1, and 7 are non-negotiable: pre-flight discovery, the safety pre-flight check, and the post-deploy log-evidence report. Skipping any of them produces dashboards that look fine in isolation but mislead, hang, or silently drop data.

0. **Discovery (MANDATORY for every session)** — Re-enumerate connected data sources (`| group UniqueDataSourceNames = array_agg_distinct(dataSource.name) | limit 1000`), run V1-query schema discovery on every source the dashboard will touch, and validate the discriminator field for any `event.type` you intend to count. See **Pre-authoring discovery** below. Never start a panel from a remembered schema.

   **Execution path for schema discovery via s1-secops-mcp:**

   1. **PowerQuery enumeration** (`array_agg_distinct(dataSource.name)`) — run via `mcp__s1-secops-mcp__powerquery_run` directly. The s1-secops-mcp server runs locally and makes direct HTTPS calls without sandbox interference.
   2. **V1 query schema discovery** (full event JSON per source) — use `mcp__s1-secops-mcp__powerquery_schema_discover` to fetch sample events from each data source and inspect their field names and types. The MCP server runs on your local machine and bypasses the sandbox proxy entirely.
1. **Understand the ask** — What data should the dashboard show? Who is the audience (SOC analyst, manager, customer POC)? What time range makes sense? What posture should each panel reflect (a panel that legitimately returns 0 needs a markdown header explaining the SOC-positive interpretation, see **Empty results are valid evidence**).
2. **Design the structure** — Choose tabs (if multi-topic), then panels per tab. Match panel type to the data shape using the guide in `references/panel-type-cheatsheet.md`. Key decisions: flows/kill-chains → `sankey`; KPI vs SLA target → `bullet`; SOC queue health → `gauge`; 3D outlier detection → `scattered_bubble`; time-based density → `heatmap`; multiple queries in one panel → tabbed table. Where one `event.type` covers multiple semantic populations (delivery-time vs click-time, scheduled vs on-demand, inbound vs outbound), build separate sections per population, not a mixed section.
3. **Write the JSON** — Use the panel type reference below and real examples in `references/community-examples.md`. Compute explicit `x`/`y`/`w`/`h` for every panel. Apply the naming-hygiene rule from **Panel naming hygiene** so titles read as SLA-grade claims.
4. **Validate queries** — Sample 3-5 events per source/event-ID to confirm field semantics. Test each panel query via the `powerquery` skill. Run the parallel load test (see **Pre-deploy validation**), acceptance thresholds: slowest panel ≤ 2s, wall-clock ≤ 5s. Run `scripts/panel_safety_check.py` against the dashboard JSON; resolve every flag before deploy.
5. **Deploy** — Use the `sdl-api` skill to `put_file` to a path like `/dashboards/my-dashboard` with `expected_version` set from a prior `get_file` (CAS guard). Save a backup of the prior JSON first. Sleep 3s, then `get_file` to verify the version bumped AND grep the returned content for a canary string from your change.
6. **Iterate** — Show the user what was built, explain each panel, offer to tweak. If the dashboard hangs, follow the escalation ladder in **Pre-deploy validation**.
7. **Log-evidence report (MANDATORY)** — Run `scripts/validate_dashboard.py` against the deployed dashboard JSON to replay every panel, persist per-panel evidence (sample rows, row count, matchCount, elapsed, errors) to a JSON, and emit a markdown evidence file. Then run `scripts/render_validation_pdf.py` to render the PDF report (cover, per-tab sections, sample-data tables, empty-result appendix with SOC-meaningful interpretations). Deliver both alongside the dashboard. A dashboard delivered without an evidence report is incomplete.

   **`validate_dashboard.py` MUST be run as a background process** — at ~10s per panel, a 30-panel dashboard takes 5 minutes; a 60-panel dashboard takes 10-30 minutes. Both exceed the MCP timeout. Start it with `python3 scripts/validate_dashboard.py ... > /tmp/validate_out.txt 2>&1 &`, confirm the PID, then poll `len(json.load(open(evidence_json)))` vs the expected panel count in short separate calls. The script persists results after every panel (idempotent), so a cancelled poll never loses work. When a `stacked_bar` or `line` panel using `| transpose` returns 0 rows in validation, cross-check whether the corresponding number panel for the same source shows data — if it does, the empty result is a V1-API artefact, not a broken query. Document it in the Appendix as confirmed false-empty and do not remove the panel.

8. **Screenshot review with the user (MANDATORY).** API validation proves each panel's query returns rows; it does NOT prove the panel RENDERS. Render-only failures happen in the browser, not the API, so `validate_dashboard.py` cannot see them: a panel showing "Couldn't load content", a markdown tile showing "Untitled", a number reading "34 principals" under a title that already says principals, an empty chart, or a broken legend. After EVERY deploy, ALWAYS ask the user to open the dashboard and send screenshots of each tab, then read them, diagnose each visual defect, fix the JSON, and re-deploy, without waiting to be asked. Prompt explicitly, e.g.: "The dashboard is deployed at /dashboards/<name>. Please open it and send screenshots of each tab so I can catch any render-only issues and fix them automatically." Treat this as part of deployment, not optional polish. Fixes for the common render-only defects are in the **Quick triage** table.

## Pre-authoring discovery

Different tenants connect different data sources, and even the same tenant drifts between sessions as parsers are updated. Authoring a panel from a remembered schema is the single most common cause of empty-or-misleading dashboards.

### 1. Enumerate connected data sources every session

```
| group UniqueDataSourceNames = array_agg_distinct(dataSource.name)
| limit 1000
```

If the source the dashboard is meant to cover does not appear, the dashboard cannot work. Stop and surface this to the user. Do not silently switch to a different source.

### 2. PowerQuery cannot discover a source's schema by itself

`| limit N` against a parser-emitted source returns only `timestamp + message`. PowerQuery has no `| columns *` or wildcard projection. Use the V1 query endpoint (`/api/query`, returns full event JSON) via the SDL client. Force-clear the scoped keys so auth falls through to the console JWT (which has `query` permission):

```python
from sdl_client import SDLClient
c = SDLClient()
c.keys["log_read_key"]    = ""
c.keys["config_read_key"] = ""
c.keys["config_write_key"] = ""

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

These tools run on your local machine and make direct HTTPS calls to `xdr.us1.sentinelone.net`
without sandbox proxy interference. No fallback or workaround needed.

### 3. A field visible in `raw_data` may NOT be queryable

Parsers vary in what they extract to top-level OCSF / `unmapped.*` columns. A field plainly visible inside the `raw_data` JSON envelope may not exist as a queryable structured column. Always probe a single sample event with the V1 query to confirm a field is queryable before authoring a panel around it. Both the schema dump and a raw event are ground truth, neither alone is sufficient.

If a field is only present in `raw_data`, it can still be filtered via a full-text predicate but **cannot be grouped or aggregated** efficiently. See **Full-text predicate cost** below.

### 4. Identify the discriminator before counting

A single `event.type` value frequently bundles multiple distinct event kinds (delivery-time vs click-time, scheduled vs on-demand, inbound vs outbound, policy-event vs detection-event). The discriminator field, often named `creationMethod`, `messageType`, `triggerType`, `disposition`, etc., may or may not be promoted to the top level. Run an exploration query before authoring count panels:

```
dataSource.name='<source>' event.type='<type>'
| group hits=count() by <candidate-discriminator>
| sort -hits
| limit 50
```

If the same `event.type` row repeats with different discriminator values, that secondary field is part of the partition key. Panels must filter on both, or split into separate sections per population. Counting "events of type X" without splitting by discriminator gives a number that conflates two semantically different things, which is the highest-cost class of dashboard bug because it looks correct.

### 4b. Null-check every grouping column before including it in a table panel

Before including any field as a grouping column in a table panel, confirm it is non-null for that specific `event.type`. A column that is null for all rows produces an empty column in the rendered table with no error. The check is one query:

```
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

The patterns below produce HTTP 500s or silent renderer failures on current SDL builds. They appear syntactically valid in language references and may even work in a developer's local PowerQuery preview, but they are not safe inside dashboard JSON. Treat them as red flags during code review. `scripts/panel_safety_check.py` scans for them automatically.

| Pattern | Failure mode |
|---|---|
| `\| let x = if(predicate, then, else)` then aggregating on `x` | 500 server error |
| `count_if(predicate)` / `countif(predicate)` aggregate functions | 500 server error |
| `sum(if(predicate, value, 0))` inside `\| group ... by ...` | 500 server error |
| `concat(field_a, ' literal ', field_b)` in `\| let` bindings | 500 server error |
| `\| union (subquery)` to add synthetic rows or merge two pipelines | 500 server error |
| `let totals = (... \| group ...)` named subquery before main pipeline | 500 server error |
| `\| parse <field> /<regex>/` with named captures and grouping in same query | 500 server error |
| `\| matches '<regex>'` with `\\s` / `\\d` escapes inside the regex literal | 500 server error |
| Anything after `\| transpose` (terminal command) | "transpose can only be used as the last command" |
| `graphStyle: "area"` panel with a `query` field (not `plots: [...]`) | Indefinite spinner, no error surfaced |
| Hyphenated arithmetic in ANY `let`, including z-scores / ratios: `(live-base)/sd`, `total-min` without spaces | "Identifier is ambiguous", the WHOLE panel fails with "Couldn't load content". Always write `(live - base) / sd` |
| `markdown` panel with `content:` field instead of `markdown:` | Renders blank tile, no error |
| `markdown` panel with NO `title` key (S-26.1) | Header renders "Untitled". Set a short plain-text `title`; prose only in `markdown` |
| Number panel `suffix` repeats the unit already in the `title` | Reads "34 principals" under title "Active principals". Put the unit in the title OR the suffix, not both |
| `graphStyle: "bar"` / `"line"` / `"area"` with a categorical (non-time) first column | "The first column of power query output should have numeric value in epoch s/ms/us/ns" error. For a category bar chart use `"stacked_bar"` with `"xAxis": "grouped_data"` and a `(category, value)` query |

### Patterns that DO work and should be preferred

| Pattern | Use case |
|---|---|
| `\| group n=count() \| limit 1` | Number panel |
| `\| group n=estimate_distinct(<field>) \| limit 1` | Cardinality number panel (HyperLogLog, fast) |
| `\| group <metric>=count() by <key1>, <key2> \| sort -<metric> \| limit N` | Top-N table |
| `\| group <metric>=count() by timestamp=timebucket('<window>'), <dim> \| transpose <dim> on timestamp` | Time-series stacked-bar / line |
| `\| group <metric>=count() by <a>, <b> \| transpose <b> on <a>` | Cross-tab / per-category × action stacked-bar |
| Long-format table: `\| group hits=count() by <category>, <action> \| sort <category>, -hits \| limit N` | When you need both dims as columns and a wide table can't be produced |
| Index-level filter (before the first pipe) | Narrow scan to relevant events; cheaper than a post-pipe `\| filter` |
| `\| filter <field> matches '<simple-regex>'` for selective dim filtering | Works with simple character classes; avoid `\\s` / `\\d` escapes |

### Two-pass parse for quoted KV values

Network device logs (FortiGate, Palo Alto, etc.) emit KV pairs where values are wrapped in double quotes: `app="HTTPS.BROWSER" appcat="Web.Client"`. The `| parse` format string is itself double-quoted, so you cannot embed a `"` to match the wrappers. The workaround is two passes:

**Pass 1** — capture the whole non-whitespace token including its surrounding quotes:
```
| parse "app=$raw_app{regex=\\S+}$" from message
```
This extracts `"HTTPS.BROWSER"` (with quotes) into `raw_app`.

**Pass 2** — extract the clean value by matching the alphanumeric content, which skips the leading `"`:
```
| parse "$app_name{regex=[A-Z0-9./_-]+}$" from raw_app
```
This produces `HTTPS.BROWSER` (no quotes) in `app_name`.

Full example for an app-ctrl panel:
```
dataSource.name='FortiGate' event.type='app-ctrl'
| parse "app=$raw_app{regex=\\S+}$" from message
| parse "appcat=$raw_cat{regex=\\S+}$" from message
| parse "$app_name{regex=[A-Z0-9./_-]+}$" from raw_app
| parse "$app_cat{regex=[A-Za-z0-9./_-]+}$" from raw_cat
| filter app_name != ''
| group Events=count() by Application=app_name, Category=app_cat
| sort -Events
| limit 20
```

**Escaping in dashboard JSON:** `\\S+` in the PowerQuery string (what the engine sees) must be written as `\\\\S+` in the JSON source because JSON applies one level of backslash-escaping before PowerQuery sees the string.

**Always invoke the `powerquery` skill before authoring parse expressions.** It references official parse documentation and gets to the correct pattern without trial-and-error.

### Workaround for "I need totals AND breakdown in one panel"

When `sum(if())`, `count_if()`, and `union` all fail, the cleanest substitute is two adjacent panels: one for totals, one for the per-action breakdown (long-format). Lay them side-by-side at half-width so they read as a single visual unit. Trying to force a single wide table with both columns generally requires one of the unsupported patterns above.

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

```
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

A dashboard is a JSON object (SDL also accepts unquoted keys — JavaScript-literal format). Three top-level shapes:

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
| `parameters` | Array of `{name, values, defaultValue}` — creates dropdown/text filters |
| `options` | `{"layout": {"fixed": 1}}` to lock drag-and-drop |
| `teamEmails` | Array of account emails whose data is pooled |

## Panel types and JSON

Every panel is an object inside `graphs`. The `graphStyle` property picks the panel type.

### Layout
Every panel **must** have explicit `x`, `y`, `w`, `h` in its `layout` object. Dashboards with many panels (observed at 18+) where `x`/`y` are omitted can hang the browser renderer indefinitely — the auto-layout pass appears to loop on collision detection when panels stack at the implicit (0,0) origin. The symptom is the browser tab becoming unresponsive before any query fires.

```json
"layout": { "w": 30, "h": 14, "x": 0, "y": 0 }
```

Use this helper to pack panels into the 60-wide grid when generating JSON:

```python
class Grid:
    def __init__(self, width=60):
        self.W = width; self.x = 0; self.y = 0; self.row_h = 0
    def place(self, w, h):
        if self.x + w > self.W:
            self.y += self.row_h; self.x = 0; self.row_h = 0
        layout = {"w": w, "h": h, "x": self.x, "y": self.y}
        self.x += w; self.row_h = max(self.row_h, h)
        return layout
    def newline(self):
        if self.x > 0:
            self.y += self.row_h; self.x = 0; self.row_h = 0
```

---

### Line / Area chart (time-series, multi-plot)

`graphStyle`: `"line"` or `"area"` (or `"stacked"` for stacked area)

Best for: event rates over time, multi-metric comparison, trend lines.

```json
{
  "title": "Threat confidence over time",
  "graphStyle": "area",
  "lineSmoothing": "straightLines",
  "yScale": "linear",
  "plots": [
    { "filter": "event.category='indicators' indicator.category='Ransomware'", "label": "Ransomware", "facet": "count" },
    { "filter": "event.category='indicators' indicator.category='Exploitation'", "label": "Exploitation", "facet": "count" }
  ]
}
```

For a **PowerQuery-driven** line chart (needed for complex grouping):
```json
{
  "title": "Login attempts over time",
  "graphStyle": "line",
  "lineSmoothing": "straightLines",
  "query": "event.login.loginIsSuccessful=false | group count() by timestamp=timebucket('1h'), endpoint.name | transpose endpoint.name on timestamp"
}
```

---

### Stacked bar chart

`graphStyle`: `"stacked_bar"` or `"bar"`

Best for: category breakdowns over time, per-group counts.

```json
{
  "title": "Threats by confidence level per day",
  "graphStyle": "stacked_bar",
  "xAxis": "time",
  "yScale": "linear",
  "query": "index='activities' activity_type in ('18','19','20') | group count=count() by timestamp=timebucket('1 day'), data.confidence_level | transpose data.confidence_level on timestamp"
}
```

For a **grouped-data X-axis** (not time):
```json
{
  "graphStyle": "stacked_bar",
  "xAxis": "grouped_data",
  "query": "event.category='indicators' | group count=count() by indicator.category | sort -count"
}
```

---

### Pie / Donut chart

`graphStyle`: `"pie"` or `"donut"`

Query **must return exactly one text column and one numeric column**.

```json
{
  "title": "Top indicator types",
  "graphStyle": "donut",
  "maxPieSlices": 10,
  "dataLabelType": "PERCENTAGE",
  "query": "event.category='indicators' | group count() by indicator.category"
}
```

---

### Table panel

`graphStyle`: `"table"` (or omit — table is the default for PowerQuery panels)

Best for: raw event lists, top-N tables, IOC lookups.

```json
{
  "title": "Outbound PowerShell connections",
  "graphStyle": "table",
  "query": "src.process.name contains 'powershell' dst.ip.address=* | let rfc1918 = not (dst.ip.address matches '((127\\..*)|(192\\.168\\..*)|(10\\..*)|(172\\.1[6-9]\\..*)|(172\\.2[0-9]\\..*)|(172\\.3[0-1]\\..*)).*') | filter rfc1918=true | group hits=count() by IP=dst.ip.address | sort -hits"
}
```

---

### Number panel (gauge)

`graphStyle`: `"number"`

Query must reduce to a single number (use `group count()`, `estimate_distinct()`, etc.).

```json
{
  "title": "Distinct active endpoints",
  "graphStyle": "number",
  "query": "| group estimate_distinct(agent.uuid) | limit 1",
  "options": {
    "format": "auto",
    "precision": "0",
    "suffix": " endpoints"
  }
}
```

> **No "millions" (or thousands) number format.** SDL number panels scale only via `format: "auto"` (which may render K/M/B); there is no explicit millions option. To force a specific unit, divide in the query and label the title: `... | group ev = count() | let Events_M = ev / 1000000 | columns Events_M | limit 1` with title `"Total Events (M)"`. Always carry the unit (GiB, events, min, count, ratio) in the title or `suffix`; a number panel renders only a bare value.

> **Options — stick to the minimal set.** Production reference dashboards only set `{format, precision, suffix}`. Fields like `backgroundColor` and `color` are documented in some places but are not consistently honoured by the renderer — at best silently ignored, at worst the panel renders blank or hangs. Do not add them until tested against the specific tenant.

With trend indicator (S-25.1.5+):
```json
{
  "graphStyle": "number",
  "trendConfig": {
    "enabled": true,
    "indicators": {
      "number": { "calculationType": "PERCENTAGE", "enabled": true },
      "arrow":  { "enabled": true },
      "upwardsMeaning": "POSITIVE"
    }
  },
  "query": "...",
  "title": "Alert volume (vs previous period)"
}
```

---

### Honeycomb panel (heat map)

`graphStyle`: `"honeycomb"`

Query must return at least one text column and one numeric column. Good for per-site or per-endpoint heatmaps.

```json
{
  "title": "File creation activity by endpoint",
  "graphStyle": "honeycomb",
  "query": "src.process.tgtFileCreationCount=* | group total=sum(src.process.tgtFileCreationCount) by site=site.id, endpoint=agent.uuid | let max=overall_max(total), min=overall_min(total) | let normalized=((total-min)/(max-min))*100 | columns Site=site, Endpoint=endpoint, Normalized=normalized",
  "honeyCombColor": { "hover": "#8ED4FB", "label": "Blue", "value": "#0998E7" },
  "honeyCombThresholds": ["0","25","50","75"],
  "honeyCombGroupBy": "Site",
  "honeyCombLinkTo": "/dash?page=Endpoints+-+Overview&params=site%3D[Site]%26endpoint%3D[Endpoint]"
}
```

---

### Heatmap panel (time OR categorical 2D matrix)

`graphStyle`: `"heatmap"`

A 2D matrix where color intensity is the aggregated value of each cell. As of S-26.x the x-axis can be **time OR a category**, and cells can carry **in-cell data labels**. Distinct from `honeycomb` (free-form hex cells). In every mode the **anchor column** (the field named after `on` in `transpose`) becomes the x-axis, and the transposed field's values become the y-axis rows.

**Two x-axis modes:**

| Mode | x-axis | Query shape | `xAxis` key |
|---|---|---|---|
| Time (classic) | timebuckets | `... \| group <m>=count() by <yCat>, timestamp=timebucket('1h') \| transpose <yCat> on timestamp` | omit (or `"time"`) |
| Categorical | a category column | `... \| group <m>=count() by <xCat>, <yCat> \| transpose <yCat> on <xCat>` | `"grouped_data"` |

**Heatmap options (live-confirmed on S-26.x, captured from what the SDL UI writes):**

| Key | Value | Effect |
|---|---|---|
| `"xAxis"` | `"grouped_data"` | Render a non-time first column as a categorical x-axis. Without it the renderer expects an epoch first column, so a category query renders blank. |
| `"showDataLabels"` | `"true"` (string, not boolean) | Print each cell's value inside the cell. Omit for color-only. |
| `"colorScheme"` | `"red"` \| `"blue"` \| `"green"` (more in the UI) | Named color ramp; `red`, `blue`, `green` confirmed to render. |
| `"colorSchemeOrder"` | `"standard"` \| `"inverted"` | Direction of the ramp; `"inverted"` flips which end is the hot color. |
| `"linkConfig"` | `{ "template": "<url>" }` | Make cells click-through to a URL, e.g. a pre-filtered Unified Alerts view. |

**Categorical heatmap example** (alerts severity x product, data labels + click-through, live-validated):
```json
{
  "title": "Alerts by severity and product",
  "graphStyle": "heatmap",
  "query": "dataSource.name='alert' severity_id=* finding_info.uid=* | group count=count() by Product=metadata.product.name, severity_id | transpose severity_id on Product",
  "xAxis": "grouped_data",
  "showDataLabels": "true",
  "colorScheme": "red",
  "colorSchemeOrder": "standard",
  "numberOfRanges": 5,
  "rangesCreation": "automatic",
  "heatmapRangeConfig": ["-∞", "", "", "", "", "∞"],
  "linkConfig": { "template": "https://<console>.sentinelone.net/incidents/unified-alerts?viewType=all" },
  "layout": { "h": 20, "w": 30, "x": 0, "y": 0 }
}
```

**Time heatmap example** (classic, x-axis = time, requires `timebucket()` and the anchor column named `timestamp`):
```json
{
  "title": "Identity Logon Activity by User [heatmap]",
  "graphStyle": "heatmap",
  "query": "dataSource.name='Identity' unmapped.type='Logon Success' user.name=* user.name != ''\n| group EventCount=count() by user_name=user.name, timestamp=timebucket('1h')\n| filter EventCount > 0\n| filter user_name in ('alice', 'bob', 'svc_adconnector', 'DC01$')\n| transpose user_name on timestamp",
  "colorScheme": "red",
  "colorSchemeOrder": "standard",
  "numberOfRanges": 5,
  "rangesCreation": "automatic",
  "heatmapRangeConfig": ["-∞", "", "", "", "", "∞"],
  "layout": { "h": 22, "w": 30, "x": 0, "y": 0 }
}
```

**Critical `heatmapRangeConfig` rule:** `rangesCreation: "automatic"` means SDL computes the threshold boundaries from the data. The `heatmapRangeConfig` array must use empty strings `""` for all middle elements. Providing explicit values (e.g. `"10"`, `"50"`) conflicts with automatic mode and causes the panel to render blank with no error. Correct form for 5 ranges: `["-∞", "", "", "", "", "∞"]` (N+1 elements for N ranges). Do not add explicit middle values unless you also change `rangesCreation` away from `"automatic"`.

**Pre-filter to top-N categories before transpose:** After `transpose`, any (category, anchor) cell with no events becomes null. To keep the heatmap readable and avoid sparse null columns, use `| filter <field> in (...)` to pin the transposed set to the most active values. Find candidates first: `| group count=count() by <field> | sort -count | limit 15 | columns <field>`.

**When to use heatmap:**
- Categorical x-axis: alerts by severity x product or asset category, detections by OS x technique, any (category x category) count matrix.
- Time x-axis: login activity per user over time (insider threat, off-hours spikes), hourly event volume across sources or endpoints, day-of-week x hour activity patterns.

---

### Distribution graph

`graphStyle`: `"distribution"`

Shows frequency distribution of a numeric field (X = value range, Y = count). Use `filter` and `facet` (not `query`).

```json
{
  "title": "Distribution of outbound destination ports",
  "graphStyle": "distribution",
  "filter": "event.network.direction='OUTGOING'",
  "facet": "src.port.number"
}
```

---

### Markdown panel

`graphStyle`: `"markdown"`

Accepts GitHub-flavored Markdown. Good for section headers, links, or explanations.

> **CRITICAL:** the body field is `markdown`, **not** `content`. A panel with
> `"content": "..."` is created successfully and renders as a **blank tile with
> no error** — the API accepts it, the UI just has nothing to display. Always
> use `"markdown": "..."`.

> **Title duplication:** the SDL UI renders the `"title"` field as a header above the panel body. Do NOT repeat the same heading inside the `"markdown"` body. A common mistake is setting `"title": "## Policy Enforcement"` (with the `##` markdown prefix) and then starting the markdown body with `## Policy Enforcement\nDescription...` — this produces the heading twice. Keep the `title` field as plain text and put only the descriptive prose (no repeated heading) inside `"markdown"`. Also: a markdown panel with NO `title` key renders an "Untitled" header in S-26.1 (observed live), so always set a short plain-text `title`.

```json
{
  "title": "About this dashboard",
  "graphStyle": "markdown",
  "markdown": "This dashboard tracks **threat activity** across all managed endpoints.\n\n[Open Event Search](/logs)"
}
```

---

## Common rendering pitfalls

These are silent failures — the API accepts the JSON, the panel mounts, but
either nothing draws or the panel hangs on the spinner. Apply the fix
preemptively when authoring panels of these shapes.

| Symptom | Root cause | Fix |
|---|---|---|
| Markdown panel renders blank, no error | Wrong body field | Use `markdown:` (NOT `content:`) — see Markdown panel section above |
| Markdown panel header shows "Untitled" | No `title` key on the markdown panel (S-26.1) | Add a short plain-text `title`; keep prose (no repeated `##` heading) in `markdown` |
| Number panel reads the unit twice, e.g. "34 principals" under "Active principals (24h)" | `options.suffix` duplicates a unit already in the `title` | Remove `suffix` (or drop the unit from the title); keep `{format, precision}` only |
| Category bar/line panel errors "The first column ... should have numeric value in epoch" | `graphStyle: "bar"` / `"line"` / `"area"` default to a TIME x-axis and require an epoch first column; a `(category, count)` query has a string first column | Use `graphStyle: "stacked_bar"` with `"xAxis": "grouped_data"`; keep the `(category, value)` query. `bar` alone is NOT a categorical bar chart |
| `area` chart with `query` field shows an indefinite spinner; no error in UI | `graphStyle: "area"` is built around the `plots: [...]` pattern. A query-driven multi-series chart that ends in `transpose` does not render under `area`. | Switch to `graphStyle: "stacked_bar"` (or `"line"`) with `xAxis: "time"`. The query body stays the same. |
| `plots`-based line or area panel returns "No results found" even though data clearly exists (confirmed via a number or table panel on the same source) | The `plots: [{ "filter": "...", "facet": "..." }]` filter mechanism silently ignores fields in the `unmapped.*` namespace. Any predicate like `unmapped.action='deny'` in a `filter` string inside `plots` matches 0 events regardless of actual data volume. No error is surfaced — the panel just shows empty. | Replace with a PowerQuery `stacked_bar` + `\| transpose` panel. The PowerQuery engine fully supports `unmapped.*` fields. The query body is equivalent: `<source-filter> unmapped.action in ('deny', ...) \| group count=count() by timestamp=timebucket('1h'), action=unmapped.action \| transpose action on timestamp`. |
| `Couldn't load content` — `field=[DashboardPlotQuery.plotIndex] error=[Facet for plot at index: 0 is invalid]` | `"facet": "count()"` (with parentheses) is invalid in a `plots` array. Only `"facet": "count"` (no parentheses) is accepted. The community examples in older docs show `count()` — this is wrong. | Use `"facet": "count"` (no parentheses) in every plots entry. |
| `Couldn't load content` — `"transpose" can only be used as the last command in a query` | `transpose` is the terminal command in the PQ pipeline; nothing can follow it | Remove any `\| limit N` / `\| sort` / `\| filter` placed AFTER `transpose`. If you need a limit, apply it pre-transpose via a subquery or a column-list filter |
| `Couldn't load content` — `Identifier "x-y" is ambiguous. To subtract, add spaces: "x - y". Otherwise, add backslashes: "x\-y"` | The PQ parser reads hyphenated text as a single identifier, not as subtraction | Add spaces around `-` in arithmetic: `total - min`, `max - min`, `(a - b) / (c - d)`. Same applies to all PQ panels and rule bodies. |
| `transpose <field> on timestamp` hangs the renderer when field values contain hyphens (e.g. `db-prod-01`, ISO dates, UUIDs, container names) | The renderer must parse the transposed values as column names for the chart legend. The PQ parser reads `db-prod-01` as subtraction and throws `Identifier is ambiguous` — or hangs silently. The V1 API tolerates this; the renderer does not. | **Option A** — pre-process: `\| let host_safe = replace_all(host_raw, '-', '_')` then transpose on `host_safe`. **Option B (preferred for by-host charts)** — avoid transpose: use `"xAxis": "grouped_data"` with a grouping query. Loses time dimension but renders reliably. **Option C** — only use `transpose` on fields whose values are guaranteed free of hyphens (numeric codes, single-token labels like `Success`/`Failure`). |
| Number panel, table panel, or whole dashboard slow to load on first open | "All API queries pass" ≠ "dashboard loads fast". The browser fires all panel queries in parallel; total load time ≈ slowest single panel. Serial validation in a script wildly overestimates wall-clock load time. | Run a parallel load test before every `put_file` — see **Pre-deploy validation** section below. Acceptance thresholds: slowest single panel ≤ 2s, wall-clock ≤ 5s, zero failures. |
| `get_file` returns HTTP 404 immediately after a successful `put_file` | `put_file` is synchronous but the file propagates across replicas with eventual consistency (~2-3s). | Always `time.sleep(3)` between `put_file` and the subsequent `get_file` verification call. |
| Heatmap panel renders blank, no error, data confirmed in PowerQuery | `rangesCreation: "automatic"` requires empty-string middles in `heatmapRangeConfig`. Providing explicit numeric strings (e.g. `"10"`, `"50"`) conflicts with automatic mode and the renderer silently returns a blank panel. | Restore to `["-∞", "", "", "", "", "∞"]`. SDL auto-calculates the middle thresholds from live data. |
| Heatmap (or any panel) renders blank after a config change, but the query returns data | Stale SDL UI session state can persist across config deployments. The browser renderer caches the prior render state and does not always reload after a `put_file`. | Log out and log back in to the SDL console. This clears session state and forces a fresh render. Do not assume a config bug until you have ruled out a stale session. |
| `min(timestamp)` / `max(timestamp)` displays as a giant integer like `1.777e18` | Aggregating over `timestamp` returns raw nanoseconds. The renderer has no implicit date formatter for aggregate output. | Wrap with `simpledateformat(min(timestamp), 'yyyy-MM-dd HH:mm:ss z', '<TZ>')`. For millisecond-typed fields (e.g. `time` on `dataSource.name='asset'`), multiply by 1000000 first: `simpledateformat(max(time) * 1000000, ...)`. Functions that do NOT exist: `format_timestamp`, `formatTimestamp`, `iso8601`, `date_format`. |
| Hostname/value-list filter is slow or behaves differently in the renderer vs API | `field matches '(host-a\|host-b)'` is evaluated as a regex per event, and hyphenated literals inside alternation can interact with the parser. | Use `field in ('host-a', 'host-b', 'host-c')` for any fixed list. Faster (indexed lookup), no escaping needed, consistent across renderer and API. Fall back to `matches` only when a true regex pattern is needed. |
| "User" panels dominated by machine accounts (e.g. `host123$`, `dc-prod-01$`) | Machine accounts carry a trailing `$` and appear in the same fields as human accounts. | Add `\| filter !(field matches '.*\\$$')` after the event filter and before the group. Verify with 5-10 sample rows that no machine accounts leak through. |
| Dashboard panel times out, indefinite spinner | A subquery inside the main query forces the engine to scan-and-aggregate twice. Dashboards rerun panels on every load, so the cost compounds. | Don't gate a panel query on a subquery if you can avoid it. Hardcode top-N values via inline OR clauses, or accept the full cardinality (often small after the initial filter). If a subquery is unavoidable, prefer a `lookup` against a precomputed datatable. |
| Number panel slow on a busy index | Engine keeps scanning after the answer is computed | Always terminate number panels with `\| limit 1` after the `\| group` that reduces to one row |
| Wide range + fine `timebucket` = thousands of points per series | E.g. `timebucket("10m")` over 7d = 1,008 points × N series | Match bucket to duration: 1d → `10m`, 7d → `1h` (minimum), 30d → `1 day` minimum |
| Two near-identical dashboards appear in *Configuration files* under `/dashboards/<name>` and `/dashboards/id/<dashboardId>/<name>` | The SDL UI's **Save** button writes to `/dashboards/id/<dashboardId>/<name>`. `put_file("/dashboards/<name>")` writes to the simpler path. Both render in the UI and both are visible to the file API; neither is access-controlled. | Pick one canonical path **before** the first deploy. Recommend the UI-native `/dashboards/id/<id>/<name>` if the dashboard already exists in the UI; otherwise `/dashboards/<name>`. Don't mix the two — each `put_file` to the alternate path creates a silent duplicate alongside the UI-saved copy. |
| `columns resources[0].name` or `vulnerabilities[0].cve.uid` returns HTTP 500 | PowerQuery does not accept bracket-array indexing in `columns`. The V1 query API exposes nested arrays as flattened keys (`resources[0].name`) for display, but those flattened keys are NOT valid PowerQuery field paths. | Use top-level scalar fields only (`severity_id`, `finding_info.title`, `metadata.product.name`, `class_name`, `time`). For first-element access inside a query, use `array_get(resources, 0).name` only inside `let`. For richer drill-down, switch from PowerQuery to the V1 query API (returns full event JSON) — see `sdl-api` skill. |
| `\| parse "app=$val$" from message` fails with "Start quote with no matching end quote" when the raw field value is wrapped in double quotes (e.g. `app="HTTPS.BROWSER"`) | The `\| parse` format string uses `"..."` as its outer delimiter. Any `"` character embedded in the format — to match quote-wrapped KV values common in network device logs — is treated as a string terminator. No escape sequence (backslash, single-quote outer, hex) works around this. | Use a two-pass parse: pass 1 captures the entire non-whitespace token including quotes (`{regex=\\S+}`), pass 2 extracts the clean value from that token. See **Two-pass parse for quoted KV values** below. |

---

## Parameters and filters (dynamic filtering)

SDL has two distinct filtering mechanisms that look similar but behave very differently depending on dashboard type.

### `filters[]` — use this in TABBED dashboards (actually works)

`filters[]` declared inside a tab object creates a live facet-based filter widget. Selecting a value from the dropdown applies that filter to **all panels in the tab** in real time. This is the correct filtering mechanism for `configType: "TABBED"` dashboards. Confirmed working.

```json
{
  "tabName": "Investigation",
  "filters": [
    { "facet": "metadata.product.name", "name": "Alert Product" },
    { "facet": "endpoint.name", "name": "Endpoint" }
  ],
  "graphs": [...]
}
```

The dropdown options are populated dynamically from live field values in the current time range. No query changes needed — SDL injects the filter automatically.

### `#VarName#` substitution — only works in FLAT (non-TABBED) dashboards

`#VarName#` query injection works **only** when the dashboard has no `configType` and no `tabs` — i.e. a flat single-view dashboard with top-level `parameters` and `graphs`. Confirmed working in `parameter_examples-v1.0.json`.

In a `configType: "TABBED"` dashboard, `#VarName#` is passed literally to the query engine, which throws `Don't understand [#] — try enclosing it in quotes`. Moving `parameters` to the top level of a TABBED dashboard does not fix this.

Flat dashboard example (the only context where `#VarName#` works):

```json
{
  "parameters": [
    {
      "name": "Specified Tag",
      "values": [
        { "label": "All", "value": "*" },
        { "label": "Log Volumes", "value": "'logVolume'" }
      ],
      "defaultValue": "*"
    }
  ],
  "graphs": [
    {
      "query": "tag=#Specified Tag# | group count=count() by serverHost",
      "title": "Count by Tag"
    }
  ]
}
```

Pre-quoting rule: if the field requires string matching, embed single quotes in the value string: `"'logVolume'"` so substitution produces `tag='logVolume'`. Use `"*"` (no inner quotes) for wildcard presence filter.

### `parameters[]` in TABBED dashboards — UI-only chrome

`parameters[]` declared inside a tab (with `facet` or `values`) renders a dropdown in the tab header but does NOT apply any filter to panel queries. It is purely decorative UI. The `filters[]` mechanism described above is the functional equivalent.

```json
{
  "parameters": [
    {
      "name": "Product",
      "label": "Alert Product",
      "values": [
        { "label": "STAR", "value": "STAR" },
        { "label": "CWS", "value": "CWS" },
        { "label": "EDR", "value": "EDR" }
      ],
      "defaultValue": "STAR"
    }
  ]
}
```

```json
{
  "parameters": [
    {
      "name": "Site",
      "label": "Site",
      "facet": "s1_detection_metadata.site_name",
      "defaultValue": "*"
    }
  ]
}
```

For user-friendly dropdown labels:
```json
{ "name": "region",
  "values": [
    { "label": "East Coast", "value": "us-east-1" },
    { "label": "West Coast", "value": "us-west-1" }
  ]
}
```

Hide a parameter from the UI (declared but not displayed):
```json
{ "name": "base_search", "options": { "display": "hidden" }, "defaultValue": "dataSource.name='MySource'" }
```

---

## Common SDL data sources and event patterns

> ⚠️ **Schemas drift between sessions and tenants.** The patterns below are
> starting points, not a registry. **Run live schema discovery (V1 query via
> `sdl-api` skill) on every source you'll query before authoring
> panels.** PowerQuery's default projection is `timestamp + message` only — it
> cannot discover schemas. Use the V1 `query` method which returns full event
> JSON.

### S1 internal SDL sources are OCSF-rich (NOT stubs)

`dataSource.name` values `alert`, `vulnerability`, `misconfiguration`, `asset`,
`Identity`, and `ActivityFeed` carry **rich OCSF events**, not metadata
stubs. The fields that *look* like they should exist based on the source name
(`alert.severity`, `alert.classification`, `vulnerability.kevAvailable`,
`misconfiguration.severity`) frequently do NOT exist — the actual queryable
fields are OCSF-namespaced.

| Source | OCSF class_uid | Severity field | Endpoint linkage | Notes |
|---|---|---|---|---|
| `alert` | 99602001 (S1 Security Alert) | `severity_id` (numeric 0-5) | `resources[].name`, `resources[].s1_metadata.site_name` (NOTE: `resources[N]` only readable via V1 query, not PowerQuery `columns`) | `finding_info.title` = alert name. `metadata.product.name` ∈ {STAR, EDR, Identity, CWS, EPP}. `class_name` = "S1 Security Alert" |
| `vulnerability` | 2002 (Vulnerability Finding) | `severity_id` + `severity_` (string, often empty) | `resource.s1_metadata.*`, `resource.uid` | `vulnerabilities[].cve.uid`, `vulnerabilities[].affected_packages[].{name,version,vendor_name}`. **No `kevAvailable` field in SDL** — KEV/EPSS metadata lives in the management console only |
| `misconfiguration` | 2003 (Compliance Finding) | `severity_id` | `resources[].s1_metadata.*` | `compliance.standards[]` (CIS_AKS, CIS_KUBERNETES, etc.), `compliance.requirements[]`, `policy.{name,uid,desc}`, `cloud.provider`, `finding_info.title` |
| `asset` | 3004 (Device Inventory) | `severity_id` + `severity_` | `device.agent.uuid`, `device.name`, `device.os.name` | 126 fields (live-confirmed). Rich endpoint inventory. Key fields: `device.agent.{uuid,version,network_status,network_status_title,is_active,is_decommissioned,is_uninstalled,network_quarantine_enabled,last_logged_in_user_name,scan_status}`, `device.os.{name,version,type}`, `device.ip_external`, `device.hw_info.*`, `device.network_interfaces[N].*`. `operation` = OPERATION_UPSERT. No `entity.uid`, no `entity_result.*`, no `agent.health.online` fields — use `device.agent.network_status` for connectivity state |
| `ActivityFeed` | n/a (Hyperautomation / mgmt activity audit) | n/a | `data.scope_id`, `site_id`, `account.id` | 41 fields (live-confirmed). Hyperautomation workflow execution audit log and management console activity log. Key fields: `activity_type` (numeric — e.g. 9207 = workflow execution event, NOT a string), `activity_uuid`, `primary_description`, `secondary_description`, `data.workflow_{id,name,execution_url}`, `data.{scope_id,scope_level,scope_name,site_name,user_id}`, `created_at`, `updated_at`, `context`. `sca:RetentionType = 'ACTIVITY_LOG'`. No `activityType` (camelCase) field. Not useful for threat hunting — use for Hyperautomation audit and compliance workflow tracking |
| `Identity` | 3002 (Authentication) | `severity_id`, `status_id` | `user.name`, `user.domain`, `src_endpoint.ip`, `dst_endpoint.hostname` | `auth_protocol` (Kerberos, NTLM), `ref_event_code` (Win Event ID like 4624), `unmapped.type` ("Logon Success"/"Logon Failure"), `type_name` ("Authentication: Logon") |
| `finding` | n/a — **NOT security findings** | n/a | n/a | `dataSource.category='metrics'`, `tag='ingestionHealth'`, `processor='ocsf-findings'`. This source is OCSF processor latency/batch metrics, not findings |

**OCSF severity_id mapping:** 0=Unknown, 1=Informational, 2=Low, 3=Medium,
4=High, 5=Critical, 6=Fatal. Filter via `severity_id >= 4` for High+Critical.

### Reserved-field rewrite (trailing underscore)

Field names ending in `_` (e.g. `severity_`, `status_`, `classification_`) are
SDL's auto-rename when source data carries a field name colliding with an SDL
reserved name. The underscored form **IS** the canonical, queryable field —
not a sparse alternate. The numeric OCSF variants (`severity_id`, `status_id`,
`class_uid`) live alongside the underscored string fields. The `severity_`
string can be case-mixed (`Critical` and `CRITICAL` both appear) — see
`powerquery/references/pitfalls.md` for handling.

### EDR / XDR telemetry (endpoint events from `dataSource.name='SentinelOne'`)
```
dataSource.category = 'security'
event.category in ('process', 'file', 'ip', 'dns', 'indicators', 'logins', 'url', 'registry')
```

`event.type='Behavioral Indicators'` carries `indicator.category`,
`indicator.name`, `agent.uuid`, `endpoint.name`, `src.process.{user,cmdline,image.path}`.

### Third-party sources
```
dataSource.vendor = 'Microsoft'        // O365, Azure AD
dataSource.name = 'FortiGate'          // field namespaces differ per event.type — validate each type separately before authoring panels
                                       // traffic:   src_endpoint.ip, dst_endpoint.ip, app_name (populated), unmapped.action, traffic.bytes_out/in
                                       // vpn:       unmapped.srcip (NOT src_endpoint.ip which is null), unmapped.action, unmapped.dstip
                                       // app-ctrl:  app_name is null (not promoted by marketplace parser); extract via two-pass parse from message field
                                       // All types: unmapped.action for the raw action string
dataSource.name = 'Okta'               // unmapped.eventType='user.session.start', status='FAILURE'/'SUCCESS', actor.user.name, src_endpoint.ip, src_endpoint.location.country
dataSource.name = 'Zscaler Internet Access'   // http_request.url.categories
metadata.product.name = 'SharePoint'
```

Re-validate every third-party source schema in Step 2b of session init —
field namespaces vary by parser version and tenant.

### Common PowerQuery patterns for panels

**Top-N table** (always add a bar column with `showBarsColumn: "true"`):
```
event.category='indicators' | group count=count() by indicator.name | sort -count | limit 20
```

**Timeline line chart** (use `timebucket` + `transpose`):
```
event.type='process' | group count=count() by timestamp=timebucket('1h'), endpoint.os | transpose endpoint.os on timestamp
```

**Single number** (estimate_distinct for cardinality):
```
| group estimate_distinct(agent.uuid)
```

**Geo enrichment**:
```
| group count=count() by country=geo_ip_country(src.ip.address) | sort -count
```

**URL deep-link in table**:
```
| let Threat_URL = format("https://your-console.sentinelone.net/incidents/threats/%s/overview", threat_id)
| columns Computer=data.computer_name, Threat_URL, Path=data.file_path
```

---

## Deploying a dashboard via API

Use the `sdl-api` skill to deploy. Dashboard config files live at paths like `/dashboards/my-dashboard-name`.

### 1. Always read existing version before put_file (CAS guard)

```python
import json, time
from sdl_client import SDLClient

client = SDLClient()
DASH_PATH = "/dashboards/soc-overview"

# Read existing version (or treat 404 as version=0 for a brand-new dashboard)
try:
    existing = client.get_file(DASH_PATH)
    cur_version = existing.get("version")
    backup_path = f"/tmp/{DASH_PATH.replace('/','_')}.{cur_version}.bak.json"
    open(backup_path, "w").write(existing.get("content") or "{}")
except Exception:
    cur_version = None
    backup_path = None

body = json.dumps(dashboard_json, indent=2)
res = client.put_file(path=DASH_PATH, content=body, expected_version=cur_version)
assert res.get("status") == "success", res
```

The `expected_version` argument is a CAS guard against concurrent writes from the SDL UI or another script.

### 2. Verify deployment by re-fetching (and grep for a canary)

```python
time.sleep(3)  # eventual-consistency window
verify = client.get_file(DASH_PATH)
deployed_content = verify.get("content", "")
assert verify.get("version") != cur_version, "version did not bump"
assert "<canary-string-from-new-section>" in deployed_content, "deploy did not include new content"
```

A `put_file` response of `{"status": "success"}` does not guarantee the new content was written, always re-fetch and grep for a canary string from the change.

### 3. Avoid duplicate dashboard paths

The SDL UI's **Save** button writes to `/dashboards/id/<dashboardId>/<name>`. The file API can write to either that path OR the simpler `/dashboards/<name>`. **Pick one canonical path before the first deploy and never mix.** Each deploy to the alternate path creates a silent duplicate alongside the UI-saved copy. Recommend `/dashboards/<name>` for hand-authored dashboards and `/dashboards/id/<id>/<name>` only for files originally saved through the UI.

### 4. Layout coordinates accumulate

Panels are placed by `layout: {w, h, x, y}`. When appending a new section to an existing dashboard, compute the next `y` as `max(existing_y + existing_h)` across the tab, not by visual estimation. Off-by-a-few errors stack panels on top of each other and the UI will not flag this as an error.

### 5. Test panels in the SDL UI before declaring done

The SDL dashboard render engine has a longer query budget than the PowerQuery MCP. A query that times out in MCP validation may still render in the UI. Conversely, a query that returns from MCP may render slowly in the UI. The final smoke test for every dashboard is: open it in the UI, watch each tab load, confirm no panel spins indefinitely.

After deploying, open in the SDL UI: **Visibility Enhanced → Dashboards** → select the dashboard by name.

---

## Reference files in this skill

- `references/panel-type-cheatsheet.md`: one-line summary of every panel type plus gotchas.
- `references/community-examples.md`: full real-world dashboard JSON examples (console audit, threat stats, alert investigation, O365, Fortinet).
- `references/common-queries.md`: ready-to-paste PowerQuery snippets for common security use cases.
- `references/lessons-learned.md`: source-agnostic patterns and gotchas from production engagements (PowerQuery feature gaps, full-text cost, naming hygiene, discriminator handling, validation runner shape).
- `references/evidence-report-template.md`: required format for the post-deploy log-evidence report (per-panel JSON, markdown, PDF appendix).

Read the community examples before creating a new dashboard, and read `lessons-learned.md` if any of: a panel may legitimately return 0, an `event.type` covers multiple semantic populations, the panel needs a field only present in `raw_data`, or a previous version of this skill produced a 500 error on `count_if`, `sum(if())`, or `| union`.

## Skill scripts (in `scripts/`)

These scripts are mandatory parts of the workflow, not optional tooling.

- `scripts/panel_safety_check.py <dashboard.json>`: pre-deploy. Scans dashboard JSON for known-bad patterns (markdown `content` vs `markdown` field, `area` + `query`, transpose-not-terminal, hyphenated arithmetic, `count_if` / `sum(if())` / `| union` / named subqueries, `\\s`/`\\d` regex escapes inside `matches`, full-text combined with timebucket+transpose, missing layout, missing `| limit` on number/table panels). Exits non-zero on any flag. Run before every `put_file`.
- `scripts/validate_dashboard.py <dashboard.json> [--start 7d] [--out <dir>]`: post-deploy. Replays every non-markdown panel against the SDL `power_query` API, persists per-panel evidence (style, query, elapsed, rowCount, matchCount, columns, sample rows, error) to a JSON keyed on `tab::title`, and emits a markdown evidence file. Idempotent, resumes cleanly, persists after each panel. Auth falls through to console JWT (force-clears scoped keys). **Always run as a background process** (`... &`) — see step 7 in the Workflow section. Do not wait for it inline.
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

Dashboard panels run their queries in the SDL console's built-in rendering engine — not via LRQ or any external API. Every panel loads when the user opens the dashboard, so slow queries directly delay the page. Apply these rules to every query you write.

### 1. Use `net_rfc1918()` — never hand-roll CIDR regex

**Slow (avoid):**
```
| let rfc1918 = not (dst.ip.address matches '((127\\..*)|(192\\.168\\..*)|(10\\..*)|(172\\.1[6-9]\\..*)|(172\\.2[0-9]\\..*)|(172\\.3[0-1]\\..*)).*')
| filter rfc1918 = true
```
**Fast:**
```
dst.ip.address = *
| let is_external = not net_rfc1918(dst.ip.address)
| filter is_external = true
```
The built-in function is evaluated natively; the regex is evaluated as a string per event.

### 2. Always add `| limit 1` to number panels

Number panels reduce to a single row. Without `| limit 1`, the engine continues scanning after finding the answer. Always terminate:
```json
"query": "dataSource.name='ActivityFeed' activity_type in (\"133\",\"134\") | group count() | limit 1"
```

### 3. Add explicit `| limit N` to every table panel

Unbounded tables force a full scan. Always cap results:
- Detail tables (time-sorted raw events): `| limit 200`
- Aggregated top-N tables: `| limit 20` or `| limit 25`
- Donut/pie panels: `| sort -count | limit 10`

### 4. Use `field=*` to drop nulls — never `field != null`

`field=*` is the correct SDL null-check predicate. It matches any event where the field is present and non-null. `field != null` is parsed as a literal comparison to the string `"null"` in the old-style filter syntax and returns wrong results or an error. Apply this anywhere you want to exclude missing values:

```
// Good — presence check
dataSource.name='alert' severity_id=*
| group count=count() by severity_id

// Bad — != null does not mean what you think in SDL filter syntax
dataSource.name='alert' severity_id != null
```

This applies in the initial filter predicate (before the first `|`) and in `| filter` commands equally.

### 5. Use `| filter count > 0` to suppress zero rows

After a `| group count=count() by ...`, SDL may produce rows with `count=0` for sparse buckets (especially after `transpose` or when grouping over a large key space). These zero rows render as empty cells in heatmaps and false entries in tables. Filter them out:

```
| group EventCount=count() by user_name=user.name, timestamp=timebucket('1h')
| filter EventCount > 0
```

Apply the same pattern to any aggregated numeric field you're visualising: `| filter bytes > 0`, `| filter value > 0`.

### 6. `| sort` must come before `| columns` — field projection is destructive

`| columns` removes every field not listed. Any `| sort` placed after `| columns` that references a field not in the projected set is operating on a non-existent field and silently fails or hangs the panel (bullet panels are especially prone to this):

```
// Wrong — severity_id is gone after | columns, sort fails silently
| group value=count(), target=..., label=... by severity_id
| columns value, target, label
| sort -severity_id          ← severity_id no longer exists

// Correct — sort while severity_id is still in scope
| group value=count(), target=..., label=... by severity_id
| sort -severity_id
| columns value, target, label
```

This affects any pipeline that projects away the sort key: bullet panels, donut panels with a custom label column, and any query that renames fields via `| columns alias=field`.

### 7. Use `event.category = *` not `event.category != ''`

`!= ''` requires evaluating the field value as a string comparison. `= *` is a cheaper is-not-null predicate:
```
dataSource.category = 'security' event.category = *
| group count=count() by timestamp=timebucket("1 day"), event.category
```

### 5. Match `timebucket` granularity to your dashboard duration

Too-fine granularity creates thousands of data points per series, slowing both query and render:

| Dashboard duration | Safe `timebucket` | Points per series |
|---|---|---|
| `1h`  | `'1m'`  | 60 |
| `4h`  | `'5m'`  | 48 |
| `24h` | `'1h'`  | 24 |
| `7d`  | `'1h'`  | 168 |
| `14d` | `'1d'`  | 14 |
| `30d` | `'1d'`  | 30 |

For a 24h dashboard, `'10m'` (144 points) can work for low-cardinality single-series panels but should not be the default — use `'1h'`. For a multi-series transpose, the data-point count compounds: `timebucket('10m')` on a 24h dashboard with a 7-series transpose = 1,008 cells per chart.

**Never use `timebucket('10m')` on a 7-day dashboard** — that's 1,008 points per series.

### 6. Push filters early — before the first pipe

The initial filter (before the first `|`) is evaluated as an index predicate. Conditions placed there are far cheaper than `| filter` commands applied after a full scan:
```
// Good — index-level filter
event.category = 'ip' event.network.direction = 'OUTGOING' dataSource.category = 'security'
| group count=count() by dst.ip.address | sort -count | limit 20

// Bad — scans all events then filters
dataSource.category = 'security'
| filter event.category = 'ip' && event.network.direction = 'OUTGOING'
| group count=count() by dst.ip.address | sort -count | limit 20
```

### 7. Use `estimate_distinct()` for cardinality — not `count(distinct …)`

`estimate_distinct()` uses HyperLogLog and is orders of magnitude faster on high-cardinality fields like `agent.uuid`, `threat_id`, `src.process.storyline.id`.

### 8. Avoid `nolimit` in dashboard panels

`nolimit` raises the row cap to 3 GB and blocks concurrent queries. It is never appropriate in a dashboard panel — always use an explicit `| limit N` instead.

### 9. Wrap string-prone numeric fields with `number()` before arithmetic

SDL/Scalyr column types are locked at first ingest. A field that *should* be numeric — `severity_id`, `traffic.bytes_in/out`, `traffic.packets_in/out`, `unmapped.duration` — can be string-typed at the index level (because a parser declared `type: "string"` for many tenant generations, or the field was first-written before the type was set). When that happens, `sum()` / `avg()` / `max()` / `>=` predicates return NaN or fail silently *even though the values are populated and visible in Event Search*.

**Failsafe pattern for every dashboard panel that does numeric work:**

```
dataSource.name='alert' severity_id=*
| let sev = number(severity_id)
| filter sev >= 4
| group hits=count() by sev
| sort sev
```

```
dataSource.name='FortiGate' unmapped.action='close'
| let bytes_out_n = number(traffic.bytes_out)
| let bytes_in_n  = number(traffic.bytes_in)
| group sessions=count(),
        bytes_out=sum(bytes_out_n),
        bytes_in=sum(bytes_in_n),
        max_session=max(bytes_out_n)
| limit 1
```

`number(x)` returns 0 for null/missing and NaN for unparseable strings. Already-numeric data is unaffected. Cost is one `let` per panel; benefit is the dashboard keeps working when a parser pushes a string-typed write or a tenant column is locked. Apply this to every numeric counter / severity / port / duration field unless this session's schema discovery proved the column type with a successful unwrapped `sum()`.

See `powerquery/references/pitfalls.md` for the full discussion of column-type lock and when the `parse "$x{regex=\\d+}$"` extraction is preferable to `number()`.

---

## Pre-deploy validation

### The browser renderer is a separate execution path

The SDL engine has three query surfaces: the V1 query API, the LRQ async API, and the in-browser dashboard renderer. The renderer has different timeouts, a stricter column-name parser, and a different concurrency model. A query that returns results instantly via the API can still hang the renderer. "All API queries pass" is necessary but not sufficient. The renderer is the only path that matters for dashboards, and it cannot be tested directly except by deploying and opening the page.

The learnings below let you predict and eliminate renderer failures before deploy.

### Parallel load test (run before every `put_file`)

The browser fires all panel queries in parallel on load. Total dashboard load time ≈ slowest single panel + small per-panel render overhead. Always run a parallel load test before deploying a new or significantly modified dashboard:

```python
import concurrent.futures, time

def run_one(panel_query):
    c = SDLClient()
    # auth setup ...
    t0 = time.time()
    try:
        res = c.power_query(query=panel_query, start_time="24h")
        return ("OK", time.time() - t0, res.get("matchingEvents") or 0)
    except Exception as e:
        return ("FAIL", time.time() - t0, str(e)[:200])

queries = [p["query"] for tab in dashboard["tabs"] for p in tab["graphs"]
           if p.get("graphStyle") != "markdown" and p.get("query")]

wall_t0 = time.time()
with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
    results = list(pool.map(run_one, queries))
wall_clock = time.time() - wall_t0

print(f"  Total serial:        {sum(r[1] for r in results):.1f}s")
print(f"  Wall-clock parallel: {wall_clock:.1f}s   <- expect this in browser")
print(f"  Slowest single:      {max(r[1] for r in results):.1f}s")
```

**Acceptance thresholds:** slowest single panel ≤ 2s, wall-clock parallel ≤ 5s, zero failures. If the slowest panel exceeds 2s, identify it and rewrite: replace `group` with `top K`, narrow the initial filter, raise the timebucket granularity, or split the dashboard.

### Deploy-and-verify: sleep before re-fetching

`put_file` returns `{"status": "success"}` synchronously, but the file propagates across replicas with eventual consistency. Calling `get_file` ~100ms after a successful PUT can return HTTP 404. Always wait:

```python
res = c.put_file(path=DASH_PATH, content=new_content, expected_version=cur_version)
assert res.get("status") == "success"

import time
time.sleep(3)            # eventual-consistency window

post = c.get_file(DASH_PATH)
assert post.get("version") != cur_version  # version bumped
```

Without the sleep, verification looks like a deploy failure even when the deploy succeeded.

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

This is the same V1-query schema-discovery pattern from the `sdl-api` skill — apply it per-event-ID, not just per-source.

---

## Escalation ladder when a deployed dashboard hangs

1. **Log out and log back in.** The SDL UI caches panel render state in the session. After a `put_file`, the browser can serve a stale render from the prior version even though the underlying config changed. A fresh login clears session state completely. Try this before any config investigation when the query is confirmed to return data.
2. **Hard refresh** (`Ctrl+Shift+R` / `Cmd+Shift+R`). Eliminates cached state from a previous broken version. Resolves ~10% of "still hung" reports.
2. **Check dev-tools network tab.** If panel queries are NOT being fired, the renderer is stuck before any HTTP call. Cause is structural (layout/options/JSON parse), not query performance. If queries ARE firing, record the slowest and move to step 3.
3. **Run the slow panel's query in isolation via the V1 API.** If it returns fast, the issue is renderer-side (column names, `transpose`, panel options). If it is slow, optimise the query.
4. **Reduce panel count by 50%.** If the dashboard now loads, the issue was concurrency or memory in the renderer. Add panels back 25% at a time until a regression isolates the offender.
5. **Diff against a working reference dashboard in the same tenant.** `list_files /dashboards/`, `get_file` on a working dashboard, compare top-level keys, panel `layout` shape, `options` keys, and `graphStyle`-specific fields. Working dashboards in the same tenant are more reliable ground truth than any external documentation, because rendering rules drift between SDL releases.
6. **Roll back.** Always keep a backup of the prior dashboard JSON before `put_file`-ing a new version. Restore via `put_file(expected_version=current)` to unblock analysts while iterating offline.

---

## Pre-deploy checklist

Run this before every `put_file`. Items marked **[scripted]** are checked automatically by `scripts/panel_safety_check.py`.

```
PRE-AUTHORING
[ ] Live data-source enumeration confirms every dataSource.name used by the dashboard exists
[ ] V1-query schema discovery run for every source; field list saved for the session
[ ] Discriminator field validated for every event.type the dashboard counts
[ ] No panel relies on a field that is only present in raw_data (or, if it does, the panel
    is a number/selective-table that won't time out under full-text)

JSON STRUCTURE (scripted)
[ ] Every panel has explicit x, y, w, h in layout                                  [scripted]
[ ] When appending to existing dashboard, next y = max(existing_y + existing_h)
[ ] No panel uses `transpose <field> on timestamp` where <field> values may contain hyphens
[ ] No `graphStyle: "area"` panel with a `query:` field (must use `plots:`)        [scripted]
[ ] Markdown panels use `markdown:` field, not `content:`                          [scripted]
[ ] No content after `| transpose` (transpose must be terminal)                    [scripted]
[ ] No hyphenated arithmetic (`x-y` without spaces)                                [scripted]

QUERY HYGIENE (scripted)
[ ] All number panels end with `| limit 1`                                         [scripted]
[ ] All table panels end with explicit `| limit N`                                 [scripted]
[ ] All time-series panels use a timebucket appropriate for duration
[ ] min/max(timestamp) columns wrapped in simpledateformat(...) with tz
[ ] Any millisecond-typed time field multiplied by 1000000 before simpledateformat
[ ] Hostname/value-list filters use `field in (...)` not `field matches '(...)'`
[ ] Numeric fields wrapped with number() before arithmetic / sum / avg
[ ] No use of count_if / sum(if(predicate, value, 0)) / | union / named subqueries [scripted]
[ ] No `\\s` / `\\d` regex escapes inside `matches '...'`                          [scripted]
[ ] No full-text predicate combined with timebucket+transpose                      [scripted]
[ ] Number panels use only {format, precision, suffix} in options

NAMING & SEMANTICS
[ ] Every panel title reads as an SLA-grade claim (no overstated counts)
[ ] Distinct event populations under the same event.type live in separate sections
    each with a markdown header explaining the split
[ ] Panels that may legitimately return 0 have a markdown header explaining the
    SOC-positive interpretation
[ ] 3-5 sample events checked to verify which field carries the user semantic per event ID
[ ] Machine-account filter applied on user-facing panels

PERFORMANCE & LOAD
[ ] Parallel load test passes: wall-clock <= 5s, slowest panel <= 2s, zero failures
[ ] All time-series panels obey the timebucket-vs-duration table

DEPLOYMENT
[ ] Backup of current dashboard JSON saved (for rollback)
[ ] put_file called with expected_version of the current deployed copy
[ ] sleep(3) before re-fetching to verify deploy
[ ] Re-fetched content greps for a canary string from the change
[ ] Path is canonical (either /dashboards/<name> OR /dashboards/id/<id>/<name>, never both)

POST-DEPLOY (MANDATORY)
[ ] scripts/validate_dashboard.py run; per-panel evidence JSON persisted
[ ] Markdown evidence file emitted alongside the JSON
[ ] scripts/render_validation_pdf.py run; PDF report delivered with the dashboard
[ ] PDF Appendix lists every empty-result panel with a SOC-meaningful interpretation
```

---

## Design tips

- **Use tabs** for dashboards covering multiple topics (threat overview, policy changes, user activity). Keep each tab focused.
- **Start with number panels** at the top for KPIs, then tables and charts below.
- **Avoid breakdown graphs** in production dashboards — they can time out and can't be pre-cached. Use explicit labeled plots instead.
- **Lock layout** with `options: {"layout": {"fixed": 1}}` to prevent accidental repositioning.
- **Use `showBarsColumn: "true"`** on table panels with a count column to get inline bar charts.
- **Time range**: set `duration` to match how "fresh" the data needs to be. Use `"24h"` for security operations / alert-triage dashboards (the standard for SOC real-time views), `"7 days"` for trend and capacity dashboards. Never default to `"7 days"` for an operations dashboard — analysts lose the short-window density that makes operational dashboards useful.
- **Test queries first** with the `powerquery` skill before embedding them in dashboard JSON.
- **Use `estimate_distinct()`** for cardinality counts — exact distinct is expensive on large datasets.
- **Add a markdown panel** to each tab explaining what it covers — this helps both users and future editors understand the dashboard at a glance.


## Sandbox proxy blocked? Use Desktop Commander

Dashboard deployment uses `sdl_client.py` from the `sdl-api` skill, which
makes direct HTTPS calls to `*.sentinelone.net`. If you see `SandboxProxyBlockedError`
or `OSError: Tunnel connection failed: 403 Forbidden`, the Cowork sandbox proxy is
blocking those calls.

The fix: use s1-secops-mcp MCP tools instead. Use `sdl_put_file` and `sdl_get_file`
to deploy dashboards directly. These tools run locally and bypass the sandbox proxy entirely.
No Desktop Commander workaround is necessary.
