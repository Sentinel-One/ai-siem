# SDL Dashboard Skill: Lessons Learned (Source-Agnostic)

This file captures patterns and gotchas discovered while building multi-tab SDL dashboards against real third-party data sources. It is intentionally written source-agnostic: every section refers to generic data-source / field / category / action concepts, not to any specific vendor or tenant.

The companion documents in this directory are tactical (cheatsheets, copy-paste queries, full examples). This file is strategic: when one of these patterns surfaces in an engagement, treat it as a hard rule, not a suggestion.

---

## 1. Pre-authoring is non-negotiable

### 1.1 Always run live data-source enumeration before authoring any panel

Different tenants have different data sources connected; even between sessions on the same tenant, the catalogue can drift. Never start a dashboard from a remembered list of `dataSource.name` values. Re-enumerate every session:

```
| group UniqueDataSourceNames = array_agg_distinct(dataSource.name)
| limit 1000
```

If the source the dashboard is meant to cover does not appear, the dashboard cannot work. Stop and surface this. Do not silently switch to a different source.

### 1.2 PowerQuery cannot discover a source's schema by itself

`| limit N` against a parser-emitted source returns only `timestamp + message`. PowerQuery has no `| columns *` or wildcard projection. To enumerate the actual queryable attributes a parser emits for a source, use the V1 query endpoint (`/api/query`, returns full event JSON) via the SDL client. Force-clear the scoped keys so auth falls through to the console JWT:

```python
c.keys["log_read_key"]    = ""
c.keys["config_read_key"] = ""
c.keys["config_write_key"] = ""

res = c.query(filter=f"dataSource.name=='{source}'", max_count=50, start_time="7d")
attrs = sorted({k for m in res["matches"] for k in (m.get("attributes") or {}).keys()})
```

### 1.3 Top-level parsed fields can be empty even when the data exists in `raw_data`

Parsers vary in what they extract to the top-level OCSF / `unmapped.*` columns. A field plainly visible inside `raw_data` (the JSON envelope) may not be queryable as a structured column. Always probe a single sample event with the V1 query to confirm a field is queryable before authoring panels around it. The schema dump and the raw event are both ground truth, neither alone is sufficient.

If a field is only present in `raw_data`, it can still be filtered via full-text predicate but cannot be grouped or aggregated efficiently. See section 4 for the cost / availability tradeoff.

### 1.4 Discriminator fields are often hidden one level deep

A single `event.type` value frequently bundles multiple distinct event kinds (delivery-time vs click-time, scheduled vs on-demand, inbound vs outbound). The discriminator field, often `creationMethod`, `messageType`, `triggerType`, etc., is what the parser uses internally and may or may not be promoted to the top level. Always identify and validate the discriminator before counting events. Counting "events of type X" without splitting by discriminator gives a number that conflates two semantically different things.

---

## 2. PowerQuery feature gaps to design around

The patterns below produce HTTP 500 errors during dashboard authoring. They appear syntactically valid in language references but are not supported in current SDL builds. Avoid them in panel queries; treat them as red flags during code review. `scripts/panel_safety_check.py` scans for these automatically.

| Pattern | Failure mode |
|---|---|
| `\| let x = if(predicate, then, else)` followed by aggregation on `x` | 500 server error |
| `count_if(predicate)` and `countif(predicate)` aggregate functions | 500 server error |
| `sum(if(predicate, value, 0))` inside `\| group ... by ...` | 500 server error |
| `concat(field_a, ' literal ', field_b)` in `\| let` bindings | 500 server error |
| `\| union (subquery)` to add synthetic rows or merge two pipelines | 500 server error |
| `let totals = (... \| group ...)` named subquery before main pipeline | 500 server error |
| `\| parse <field> /<regex>/` with named captures and grouping in same query | 500 server error |
| `\| matches '<regex>'` with `\\s` / `\\d` escapes inside the regex literal | 500 server error |
| Anything after `\| transpose` (terminal command) | "transpose can only be used as the last command" |
| `graphStyle: "area"` panel with a `query` field (not `plots: [...]`) | Indefinite spinner, no error surfaced |
| Hyphenated arithmetic: `total-min`, `max-min` without spaces | "Identifier is ambiguous" error |
| `markdown` panel with `content:` field instead of `markdown:` | Renders blank tile, no error |

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

### Workaround for "I need totals AND breakdown in one panel"

When `sum(if())`, `count_if()`, and `union` all fail, the cleanest substitute is two adjacent panels: one for the totals, one for the per-action breakdown (long-format). Lay them side-by-side at half-width so they read as a single visual unit. Trying to force a single wide table with both columns generally requires one of the unsupported patterns above.

---

## 3. Empty results are valid evidence (but distinguish from query errors)

A query that runs successfully and returns 0 rows is a real datapoint, not a bug. Examples:

- A "policy violations blocked" panel returning 0 because the policy is in monitor-only mode.
- A "malicious URL delivered" panel returning 0 because the engine hard-blocks at a different layer.
- A "compromised account auth" panel returning 0 because no compromise occurred this window.

Rules:

1. Never silently switch the query to make a panel "have data." If 0 is correct, surface it.
2. Distinguish 0-row from 0-matchCount. A successful query with `matchCount > 0` and `rowCount = 0` means the post-pipe steps eliminated everything (often a `| filter` after `| group`). A query with `matchCount = 0` means no events matched at all. Both are valid; the former hints at refining the filter, the latter at validating coverage.
3. In dashboards, a panel that may legitimately be 0 should have a markdown header that explains the SOC-positive interpretation. Otherwise the analyst reads "blank panel = broken dashboard."
4. In the evidence report, every empty panel must include the underlying matchCount so the reader can tell whether the source has data at all.

---

## 4. Full-text predicate cost (when to use raw_data string matching)

When a field needed for the panel is buried inside `raw_data` (JSON envelope) rather than parsed to a structured column, the only way to filter on it is a full-text predicate against `raw_data`. Example pattern:

```
dataSource.name='<source>' event.type='<type>' '<json-snippet>'
```

The bare-string token is interpreted as a literal substring search across `raw_data`. This works, but the cost is significant.

### Cost characteristics

- Full-text scan reads every event in the time window before applying the predicate. Cost is proportional to total events scanned, not to the matched subset.
- Combined with `| group` over high-cardinality dimensions, full-text predicates frequently exceed the 60s MCP timeout. The same query in the SDL UI may run, but in dashboards it is risky.
- Combined with `| group ... by timestamp=timebucket(...) | transpose` (timeline patterns), full-text predicates almost always time out because the engine has to scan, predicate-test, bucket, group, and transpose.

### Safe full-text patterns

| Use | Example | Why it works |
|---|---|---|
| Number panel: simple count | `<source-filter> '<token>' \| group n=count() \| limit 1` | One row, no grouping; fast even at 100k+ events |
| Number panel: count with structured co-filter | `<source-filter> '<token>' <field>='<value>' \| group n=count() \| limit 1` | Co-filter narrows scan first |
| Table panel: top-N with restrictive co-filter | `<source-filter> '<token>' <selective-field>='<value>' \| group ... by ... \| sort \| limit 25` | Working set is small after co-filter |

### Risky full-text patterns

| Use | Why it fails |
|---|---|
| Stacked-bar timeline with full-text + transpose | Scan + bucket + group + transpose under full-text → timeout |
| Top-N grouping over the whole source under full-text | High-cardinality grouping under full-text → timeout |
| Multiple full-text tokens combined | Each token is a separate scan; cost compounds |

### Design rule

If a panel needs a discriminator that lives in `raw_data` only, lobby the parser team to promote it to a top-level structured field. Until then, design the panel to use full-text only where the cost is acceptable (number panels, selective tables) and replace timeline / heavy-grouping panels with structured-field equivalents.

---

## 5. Panel naming hygiene: labels must reflect what is counted

The single most common cause of misleading dashboards is a panel title that overstates what the underlying query measures.

| Wrong title | Why it's wrong | Correct title |
|---|---|---|
| "URL clicks" | Counts both clicks and delivery-time scans | "URL events (clicks + scans)" |
| "Phishing emails clicked" | Counts events that include a click discriminator AND those that don't | "Phishing-classified emails (events)" |
| "Allowed malicious URLs" | Counts the rewriting policy disposition, not the user's actual click | "Malicious URL events delivered (warn)" |
| "Distinct users compromised" | Counts users associated with a detection, not confirmed-compromise users | "Distinct users with detected events" |

Rule: the panel title should be readable as an SLA / report claim. If a CISO would feel misled reading the title without the query, rename the panel.

When two semantically distinct event populations exist within the same `event.type` (delivery-time vs click-time, scheduled vs on-demand), build separate sections of the dashboard for each population, with markdown headers that explain the split. A single section that mixes both populations is almost always wrong.

---

## 6. Cross-source disambiguation: `event.type` is not always the right key

A single source can emit multiple log subtypes under the same `event.type` (policy events vs detection events, header logs vs body logs). Don't assume `event.type` partitions the source cleanly. Run a quick exploration query:

```
dataSource.name='<source>'
| group hits=count() by event.type, <secondary-discriminator>
| sort -hits
| limit 50
```

If the same `event.type` row repeats with different secondary-discriminator values, that secondary field is part of the partition key. Panels should filter on both.

---

## 7. Validation runner pattern (mandatory for every dashboard)

Every dashboard delivered comes with an evidence report that replays each panel's query against live data and captures the result. The skill's `scripts/validate_dashboard.py` automates this; the shape it implements is below.

### 7.1 Runner anatomy

```python
panels = []
for tab in dashboard["tabs"]:
    for g in tab["graphs"]:
        if g.get("graphStyle") != "markdown" and "query" in g:
            panels.append({"tab": tab["tabName"], "title": g["title"], "style": g["graphStyle"], "query": g["query"]})

c = SDLClient()
c.keys["log_read_key"] = ""
c.keys["config_read_key"] = ""
c.keys["config_write_key"] = ""

results = {}
for p in panels:
    t0 = time.time()
    try:
        r = c.power_query(query=p["query"], start_time=start_iso, end_time=end_iso)
        results[key] = {
            "ok": True,
            "elapsed_s": round(time.time() - t0, 2),
            "row_count": len(r.get("values") or []),
            "columns":   [c.get("name") for c in (r.get("columns") or [])],
            "sample_rows": (r.get("values") or [])[:3],
            "matchCount": (r.get("data") or {}).get("matchCount") or r.get("matchingEvents"),
        }
    except Exception as e:
        results[key] = {"ok": False, "error": str(e)[:300], "elapsed_s": round(time.time()-t0, 2)}
    json.dump(results, open(out_path, "w"), indent=2)  # persist after each panel for resumability
```

### 7.2 Run in batches

Each panel takes 1 to 4 seconds typical. Batch into chunks of about 10 per shell invocation if shell timeouts are tight. The runner is idempotent (skip keys already in `results`) so it resumes cleanly.

### 7.3 Per-panel evidence captured

For each panel, record:
- `ok`: did the query execute?
- `elapsed_s`: wall-clock time
- `row_count`: number of result rows
- `columns`: column names from the response (validates the panel-type expectation)
- `sample_rows`: first 3 rows verbatim (this is the log evidence)
- `matchCount`: events scanned before grouping (distinguishes "no data" from "filtered out")
- `error` (if failed): first 300 chars of the exception message

### 7.4 Verdict per style

| Panel style | Pass condition |
|---|---|
| `number` | `row_count == 1` and `len(columns) == 1`; OR `row_count == 0` (acknowledged empty) |
| `donut` / `pie` | `row_count >= 1` and `len(columns) >= 2` (text + numeric); OR `row_count == 0` |
| `stacked_bar` / `bar` / `line` / `area` | `row_count >= 1` and `len(columns) >= 2`; OR `row_count == 0` |
| `table` | Always passes if `ok=True`; sample rows captured |

### 7.5 Render the evidence report

The runner output (a JSON keyed on `tab::title`) feeds two artefacts:

1. A markdown evidence file for inline review and version control.
2. A PDF report for distribution. Each panel section contains: title, metadata (style / exec / rows / matchCount), verdict, the exact PowerQuery body, and either a sample-data table (first 3 rows of N) or a clear amber callout *"NO LOG EVIDENCE in window"* when `row_count == 0 AND matchCount == 0`.

The PDF must include an Appendix that lists every empty-result panel with its SOC-meaningful interpretation. A panel returning 0 rows without explanation is indistinguishable to the reader from a broken panel.

---

## 8. Deployment safety

### 8.1 Always read existing version before put_file

```python
existing = c.get_file(path)
res = c.put_file(path=path, content=body, expected_version=existing["version"])
```

The `expected_version` argument is a CAS guard against concurrent writes from the SDL UI or another script.

### 8.2 Verify deployment by re-fetching

```python
verify = c.get_file(path)
deployed_content = verify.get("content", "")
assert verify.get("version") != cur_version, "version did not bump"
assert "<canary-string-from-new-section>" in deployed_content, "deploy did not include new content"
```

A `put_file` response of `{"status": "success"}` does not guarantee the new content was written. Always re-fetch and grep for a known canary string from the change.

### 8.3 Avoid duplicate dashboard paths

The SDL UI's Save button writes to `/dashboards/id/<dashboardId>/<name>`. The file API can write to either that path OR the simpler `/dashboards/<name>`. Pick one canonical path before the first deploy and never mix. Each deploy to the alternate path creates a silent duplicate alongside the UI-saved copy. Recommend `/dashboards/<name>` for hand-authored dashboards and `/dashboards/id/<id>/<name>` only for files originally saved through the UI.

### 8.4 Layout coordinates accumulate

Panels are placed by `layout: {w, h, x, y}`. When appending a new section to an existing dashboard, compute the next `y` as `max(existing_y + existing_h)` across the tab, not by visual estimation. Off-by-a-few errors stack panels on top of each other and the UI will not flag this as an error.

### 8.5 Test panels in the SDL UI before declaring done

The SDL dashboard render engine has a longer query budget than the PowerQuery MCP. A query that times out in MCP validation may still render in the UI. Conversely, a query that returns from MCP may render slowly in the UI. The final smoke test for every dashboard is: open it in the UI, watch each tab load, confirm no panel spins indefinitely.

---

## 9. Discovery → author → validate → deploy workflow

The end-to-end engagement shape that produces clean deliverables:

1. Load every relevant skill upfront (`sdl-dashboard`, `powerquery`, `sdl-api`, plus `pdf` / `docx` for deliverables). Loading mid-task wastes turns.
2. Session init in parallel: data-source enumeration query + alert / asset triage queries + `get_timestamp_range` in a single tool-call batch.
3. Schema discovery for the target source. V1 query, dump fields to JSON, persist for the session.
4. Identify discriminator fields. Run `group by event.type, <candidate-discriminator>` to confirm cardinality and partition behaviour.
5. Author panel queries one at a time and validate each in isolation before committing them to the dashboard JSON. PQ-MCP timeouts at 60 seconds; SDL UI typically renders longer; choose the validation method per panel risk.
6. Build the dashboard JSON with explicit `layout` coordinates, markdown headers explaining each section, and a clear naming convention (events vs activities, delivery vs runtime, etc.).
7. Run `scripts/panel_safety_check.py` and resolve every flag.
8. Deploy via `put_file` with `expected_version`, then re-fetch and grep for canaries.
9. Run `scripts/validate_dashboard.py` and persist per-panel evidence to JSON + markdown.
10. Render `scripts/render_validation_pdf.py`. The PDF goes to leadership; the markdown stays in the project repo.
11. Document new gotchas back into this file. Each engagement should leave the skill better than it found it.

---

## 10. Open improvements for the dashboard skill

Items already shipped:

- A reusable `scripts/validate_dashboard.py` helper that takes a dashboard JSON path and emits a per-panel validation JSON + a markdown evidence file.
- A reusable `scripts/render_validation_pdf.py` helper that takes the validation JSON and emits a PDF with cover page, per-tab sections, sample-data tables, and an Appendix for empty-result panels.
- A `scripts/panel_safety_check.py` pre-flight checker that scans a dashboard JSON for known-bad patterns and warns before deploy.

Items still open:

- A "discriminator validation" recipe in the skill's reference docs (how to identify when one `event.type` covers multiple semantically distinct populations and the technique for splitting them in the dashboard).
- A reference snippet for "totals + breakdown in one row" that documents the limitation and the recommended two-adjacent-panel workaround when conditional aggregates are unavailable.

---

## Quick reference: minimum-viable panel skeletons

```text
# Number panel: total events
"<source-filter> | group n=count() | limit 1"

# Number panel: distinct entities
"<source-filter> | group n=estimate_distinct(<field>) | limit 1"

# Donut: top-N by category
"<source-filter> | group hits=count() by <category-field> | sort -hits | limit 10"

# Stacked-bar timeline (preferred timeline pattern)
"<source-filter> | group hits=count() by timestamp=timebucket('1h'), <action-field>
 | transpose <action-field> on timestamp"

# Stacked-bar grouped-data (cross-tab)
"<source-filter> | group hits=count() by <category-field>, <action-field>
 | transpose <action-field> on <category-field>"

# Long-format table when transpose isn't appropriate
"<source-filter> | group hits=count() by <category-field>, <action-field>
 | sort <category-field>, -hits | limit 200"

# Top-N table with bar column
"<source-filter> | group hits=count() by <key-field>
 | sort -hits | limit 25"
```

Every panel should also include a `| limit N` after `| group` (for number panels: `| limit 1`; for tables: `| limit 25` or `| limit 50`). The SDL render engine continues scanning after the answer is computed otherwise.

---

End of document. Treat this file as a living artefact: append new gotchas as they surface in subsequent engagements.

---

## 11. S1-internal SDL sources `asset` and `ActivityFeed` — corrected live schemas

**Confirmed 2026-05-01 (GRC dashboard engagement). Root cause: sandbox proxy block misread as empty source.**

**Core rule: use s1-secops-mcp tools for all SDL operations.**

| Operation | s1-secops-mcp tool |
|---|---|
| PowerQuery | `mcp__s1-secops-mcp__powerquery_run` |
| V1 `query` (full event JSON for schema discovery) | `mcp__s1-secops-mcp__powerquery_schema_discover` |
| `put_file` / `get_file` (dashboard deploy) | `mcp__s1-secops-mcp__sdl_put_file`, `mcp__s1-secops-mcp__sdl_get_file` |

These tools run locally and bypass the sandbox proxy entirely. Do not fall back to any other approach.

An earlier attempt at schema discovery in the same session ran inside the sandboxed Bash shell, which blocks all outbound HTTPS to `xdr.us1.sentinelone.net`. The V1 query calls returned a proxy error. Because the error was not recognized as a sandbox-specific block, the empty output was interpreted as the source having no useful fields, and a plausible-looking but entirely fabricated field list was deployed into the GRC dashboard panels.

The fabrication was only caught when the user asked to re-verify the schemas, at which point the operation was re-run using the s1-secops-mcp tools and returned the real data: 126 fields for `asset`, 41 fields for `ActivityFeed`.

**Prevention:** Always use s1-secops-mcp tools for SDL operations. They bypass the sandbox proxy and succeed where direct bash calls would fail.

### `dataSource.name='asset'` — 126-field rich endpoint inventory (OCSF class_uid 3004)

This is the full endpoint device inventory, not pipeline metrics. Key confirmed fields:

```
device.agent.uuid              device.name                   device.os.{name,version,type}
device.agent.network_status    device.agent.network_quarantine_enabled
device.agent.is_active         device.agent.is_decommissioned   device.agent.is_uninstalled
device.agent.scan_status       device.agent.version            device.agent.last_logged_in_user_name
device.ip_external             device.hw_info.{model_name,ram_size,cpu_type,serial_number}
device.network_interfaces[N].{ip,mac,name,subnet}
severity_id                    severity_                        operation (= OPERATION_UPSERT)
s1_metadata.{site_id,site_name,group_id,group_name}
```

Fields that do NOT exist in this source: `entity.uid`, `entity_result.*`, `agent.health.online`, `agent.uuid` (use `device.agent.uuid`).

### `dataSource.name='ActivityFeed'` — 41-field Hyperautomation/management activity audit log

This is the management console activity and Hyperautomation workflow execution log (`sca:RetentionType = 'ACTIVITY_LOG'`), not pipeline metrics. Key confirmed fields:

```
activity_type        (numeric — e.g. 9207 = workflow execution event; NOT a string)
activity_uuid        primary_description      secondary_description
data.workflow_id     data.workflow_name       data.workflow_execution_url
data.scope_id        data.scope_level         data.scope_name
data.site_name       data.user_id             data.system_user
created_at           updated_at               context
account.id           account.name             site_id
```

Useful for Hyperautomation workflow audit trails and compliance tracking. Not useful for threat hunting.

**The actual ingestion pipeline metrics source is `finding`** (fields: `batchCt`, `eventLatency.*`, `processor`, `tag`, `dataSource.category='metrics'`, `tag='ingestionHealth'`). Do not confuse it with `asset` or `ActivityFeed`.

---

## 12. Long-running scripts: always background-and-poll to avoid MCP timeout

The MCP tool call layer imposes a hard ~2-minute timeout on any `start_process` call. Two operations that exceed this in typical engagements:

- **Schema discovery across many sources** — V1 `query` calls take 5-10s each. For 15+ sources that is 2+ minutes.
- **`validate_dashboard.py` on large dashboards** — 63 panels at 8-25s each = 10-30 minutes.

**Pattern: background the process, poll the output file with fast separate calls.**

```bash
# 1. Start in background — returns immediately with PID
python3 /tmp/my_script.py > /tmp/out.txt 2>&1 &
echo "PID: $!"

# 2. Poll in a separate fast start_process call (keep each call under 90s)
python3 -c "
import json, subprocess, time
for _ in range(N):
    time.sleep(15)
    # read output file and check for completion sentinel
    r = subprocess.run(['ps','aux'], capture_output=True, text=True)
    alive = 'my_script' in r.stdout
    print(f'n={...} running={alive}', flush=True)
    if not alive: break
"
```

Key rules:
- Never put `sleep N` inside a `start_process` call where `N * iterations > 90s` — the MCP layer will time out the whole call.
- Write completion sentinels to the output file (`print("DONE: ...", flush=True)`) so polling can detect finish without relying on process exit alone.
- Use `flush=True` on every progress `print()` so the output file is readable while the script is still running.
- The output file is idempotent if the script persists results incrementally (as `validate_dashboard.py` does). A cancelled poll does not lose work.

---

## 13. Large sources: index-level filters outperform post-pipe `number()` for KPI panels

`number()` is the right defensive pattern when a field might be string-typed and you need arithmetic. However, for high-cardinality sources (tens of thousands of events in the window), `number()` forces a full scan-and-convert before the filter applies. On the `misconfiguration` source with 21k+ records this exceeded the V1 API's 30s hard timeout.

**Slow (times out on large sources):**

```
dataSource.name='misconfiguration' severity_id=*
| let sev = number(severity_id)
| filter sev >= 4
| group count()
| limit 1
```

**Fast (index-level predicate):**

```
dataSource.name='misconfiguration' severity_id >= 4
| group count()
| limit 1
```

The initial filter before the first `|` is evaluated as an index predicate. For severity_id values 1-5, string-ordered comparison (`>= 4`) is numerically correct, so this is safe without `number()`.

**Rule:** use `number()` when you need arithmetic or when severity values could be multi-digit or non-numeric. For simple threshold filters on 1-5 range fields against large sources, push the filter to the index predicate level and drop the `number()` wrapper. If the field is genuinely string-typed at index level the predicate still works correctly for single-digit ranges.

This also applies to the dashboard renderer: the V1 API has a 30s hard cap; the browser renderer has a longer budget. A KPI panel that times out in validation but uses index-level filters will almost always render in the browser.

---

## 14. `transpose` panels consistently return 0 rows via the V1 validation API — this is not a real empty result

During validation of stacked-bar panels using `| transpose <field> on timestamp`, the V1 `power_query` endpoint frequently returns 0 rows even when the underlying data exists and the KPI panels for the same source confirm thousands of matching events. This is an artefact of the deprecated V1 API's execution path, not a problem with the query or the dashboard.

**Confirmed example (2026-05-01 GRC engagement):**

- `Critical + High Alerts` number panel returned `448` events via V1 API — confirmed data exists.
- `High + Critical Alerts per Day` stacked-bar panel using `| group count=count() by timestamp=timebucket('1d'), severity_id | transpose severity_id on timestamp` returned 0 rows via the same V1 API.
- The browser renderer executed the same query without issue.

**Rule:** when `validate_dashboard.py` marks a stacked-bar or line chart panel as empty (`row_count=0`), check whether the corresponding number panel for the same source shows data. If the number panel has data and the trend panel is empty, the empty result is a V1-API artefact, not a broken query. Document it as such in the evidence report Appendix with the note: `"0 rows via deprecated V1 API — confirmed live data from corresponding KPI panel; expect correct render in browser."`

Do not remove or rewrite trend panels based on V1 validation empty results alone. The final authority is the browser renderer.

---

## 15. Third-party parser dashboards: `unmapped.*` fields and `plots`-based panels

**Confirmed 2026-05-04 (FortiGate showcase dashboard engagement).**

### 15.1 `plots` filter silently drops `unmapped.*` fields — always use stacked_bar+transpose instead

The `plots: [{ "filter": "...", "facet": "count" }]` mechanism used for `line` and `area` chart panels silently ignores any predicate that references the `unmapped.*` field namespace. A panel like:

```json
{
  "graphStyle": "line",
  "plots": [
    { "filter": "dataSource.name='FortiGate' unmapped.action='deny'", "label": "Deny", "facet": "count" },
    { "filter": "dataSource.name='FortiGate' unmapped.action='accept'", "label": "Accept", "facet": "count" }
  ]
}
```

renders as "No results found" even when PowerQuery confirms tens of thousands of matching events (confirmed: 93k deny events in a 24h window). No error is surfaced — the panel appears healthy but is completely empty.

**Root cause:** the `plots` filter path does not evaluate the `unmapped.*` field namespace. The filtering silently returns 0 matches.

**Fix:** replace any `plots`-based timeline panel that uses `unmapped.*` fields with a PowerQuery `stacked_bar` using `| transpose`:

```
dataSource.name='FortiGate' event.type='traffic' unmapped.action in ('deny', 'accept', 'close')
| group count=count() by timestamp=timebucket('1h'), action=unmapped.action
| transpose action on timestamp
```

The PowerQuery engine fully supports `unmapped.*` fields. The `stacked_bar` + transpose pattern is the safe equivalent for every case where `plots`-based line charts would use an `unmapped.*` predicate.

**Pre-authoring check:** before building any timeline panel that groups by a field in the `unmapped.*` namespace, use the PowerQuery stacked_bar pattern from the start. Never use `plots` for `unmapped.*`-based series.

### 15.2 `"facet": "count"` not `"facet": "count()"` in plots arrays

The `plots` array entries must use `"facet": "count"` (no parentheses). The error when parentheses are present:

```
Couldn't load content
field=[DashboardPlotQuery.plotIndex]
error=[Facet for plot at index: 0 is invalid]
```

Older community examples and some internal docs show `"facet": "count()"` — this is wrong and breaks every `plots`-based panel. The correct form is `"facet": "count"` for event counts, `"facet": "field_name"` for other facet targets. The SKILL.md example has been corrected to reflect this.

### 15.3 Always verify field population before using presence filters (`field=*`)

Before building a panel with a field presence filter, confirm the field is actually populated:

```
dataSource.name='FortiGate' event.type='app-ctrl' app_name=*
| group count=count()
| limit 1
```

If this returns 0, every panel using `app_name=*` as a filter will return nothing. The FortiGate marketplace parser does not populate `app_name` for `event.type='app-ctrl'` events — the field is null universally for this source. Pivot to grouping by whatever structured fields are populated (`unmapped.action`, `src_endpoint.svc_name`) and update the panel title to reflect the parser limitation.

**General rule:** run a field-population check before every panel that relies on `field=*` as a meaningful filter criterion, not just as a null-drop. A field can be present in raw event JSON but unpopulated at the structured-column level for all events.

### 15.4 Markdown panel: plain text in `title`, no heading repetition in body

The SDL UI renders the `"title"` string as the panel header. Any heading prefix (`##`) embedded in the `title` field produces raw markup in the panel header, and if the same heading also opens the `"markdown"` body, the heading appears twice.

**Wrong pattern (causes doubled heading):**
```json
{
  "title": "## Policy Enforcement Intelligence",
  "graphStyle": "markdown",
  "markdown": "## Policy Enforcement Intelligence\nAnalysis of deny and block actions..."
}
```

**Correct pattern:**
```json
{
  "title": "Policy Enforcement Intelligence",
  "graphStyle": "markdown",
  "markdown": "Analysis of deny and block actions..."
}
```

Rule: `title` is always plain text. The `markdown` body starts directly with descriptive prose, never repeating the title as a heading.

### 15.5 Operational dashboards default to `"duration": "24h"`, not `"7 days"`

Security operations dashboards (firewall visibility, threat triage, VPN health, alert queue) should default to `"duration": "24h"`. Use `"7 days"` only for trend dashboards (weekly capacity, historic comparison). Always set the correct default before the first deploy — changing it requires a re-deploy and a page reload for the user to see the new default.

### 15.6 Use ternary `?:` chaining for field-mapping in `let` — not `if()` function

When mapping a numeric code field to a human-readable label (e.g. protocol numbers to names), use ternary `?:` chaining, not `if()`:

```
| let proto = connection_info.protocol_num='6' ? 'TCP'
            : connection_info.protocol_num='17' ? 'UDP'
            : connection_info.protocol_num='1' ? 'ICMP'
            : 'Other'
```

`if(predicate, then, else)` used inside `let` followed by aggregation causes a 500 server error (see section 2). This pattern surfaces commonly when building protocol/severity/disposition mapping panels for network device dashboards.

### 15.7 `number()` wrapping for network device byte/packet fields

`traffic.bytes_in` and `traffic.bytes_out` on FortiGate events are string-typed at the index level. Arithmetic without `number()` returns NaN silently:

```
| let b_out = number(traffic.bytes_out)
| group gb_sent = sum(b_out) / 1073741824
```

Apply `number()` to byte/packet/duration fields from third-party network device parsers before using them in `sum()`, `avg()`, or division. Confirm by running a test query: if `sum(traffic.bytes_out)` returns 0 or NaN but `sum(number(traffic.bytes_out))` returns a non-zero value, the field is string-typed.

### 15.8 FortiGate marketplace parser: confirmed field layout

Schema validated against live tenant data (2026-05-04):

| Event type | Key fields |
|---|---|
| `traffic` | `unmapped.action` (deny/accept/close/pass/timeout), `src_endpoint.ip`, `dst_endpoint.ip`, `src_endpoint.location.country`, `dst_endpoint.location.country`, `dst_endpoint.port`, `connection_info.protocol_num`, `traffic.bytes_in` (string-typed), `traffic.bytes_out` (string-typed), `app_name` (populated), `src_endpoint.svc_name` |
| `vpn` | `unmapped.action` (accept/deny/ssl-login-fail/ssl-alert/tunnel-up/tunnel-down), `unmapped.srcip` (source IP — NOT `src_endpoint.ip` which is null for vpn events), `src_endpoint.svc_name` (also null for vpn) |
| `app-ctrl` | OCSF class "Security Finding". `unmapped.action` (pass/start/accept/deny/close/passthrough/ssl-login-fail), `applist` (AC policy name e.g. "Fusion_Base_AppCtrl"), `unmapped.level`. ALL of the following are NULL: `app_name`, `src_endpoint.ip`, `dst_endpoint.ip`, `dst_endpoint.port`, `finding_info.title`, `unmapped.appcat`, `unmapped.appid`, `unmapped.msg`, `src_endpoint.svc_name`. The FortiGate raw `app` field (actual app name like "YouTube") is NOT extracted by this parser — it lives in `raw_data` only and cannot be grouped. Group by `unmapped.action` + `applist` only. |
| `virus` | Presence panel only; details in `unmapped.*` |

Use `net_rfc1918(src_endpoint.ip)` to identify internal source IPs for `traffic` events. The `dst_endpoint.location.country` field is populated and usable for geo panels; filter `!(country in ('Reserved'))` to exclude RFC-1918 and loopback ranges from destination geo charts.

### 15.9 Field namespaces differ per event type — validate each event type separately

The root cause of the `unmapped.srcip` miss: schema discovery was performed against `event.type='traffic'` and the field mapping was assumed to carry across to `vpn` events. It does not. The FortiGate marketplace parser uses `src_endpoint.ip` for `traffic` events and `unmapped.srcip` for `vpn` events. `src_endpoint.ip` is null for all `vpn` events; `src_endpoint.svc_name` is null for both `vpn` and `app-ctrl` events.

**Rule: run a separate field-population check for every `event.type` you intend to query.** Do not assume OCSF field mappings are consistent across event types within the same source. A field confirmed for `traffic` may be in a completely different namespace for `vpn`, `app-ctrl`, or `virus` events from the same parser.

Minimum check before authoring any panel that uses a shared field like `src_endpoint.ip`:

```
dataSource.name='FortiGate' event.type='vpn' src_endpoint.ip=*
| group count=count()
| limit 1
```

If this returns 0, the field is not populated for that event type. Find the correct field by running schema discovery specifically against that event type.

### 15.10 PowerQuery `| parse` with quoted KV values: two-pass approach

FortiGate (and many other network device parsers) emit KV pairs where string values are wrapped in double quotes: `app="HTTPS.BROWSER" appcat="Web.Client"`. The SDL PowerQuery `| parse` format string is itself delimited by double quotes, which means you cannot embed a literal `"` in the format string to match the quote wrappers around the value.

**Confirmed workaround: two-pass parse.**

Pass 1: use `{regex=\\S+}` (non-whitespace) to capture the entire quoted value including its surrounding double quotes.

Pass 2: use `{regex=[A-Z0-9./_-]+}` (or appropriate character class) to extract just the clean value from the quoted string, skipping the leading `"`.

```
| parse "app=$raw_app{regex=\\S+}$" from message
| parse "$app_name{regex=[A-Z0-9./_-]+}$" from raw_app
```

For `app="HTTPS.BROWSER"`, `raw_app` becomes `"HTTPS.BROWSER"` and `app_name` becomes `HTTPS.BROWSER`.

**Escaping rule inside `{regex=...}` in a dashboard JSON query field:**

- The dashboard JSON stores query strings as JSON string values, so backslashes must be JSON-escaped.
- `\\S+` in the PowerQuery string (what the engine sees) requires `\\\\S+` in the JSON source.
- When using the `powerquery_run` MCP tool directly (Python string), pass `\\S+` — Python string escaping takes one step.

**Why `| parse` with embedded `"` fails:**

All attempts to embed a literal `"` in the format string (single-quoted outer, double-quoted outer, regex `/pattern/`) produce "Start quote with no matching end quote" or "Expected a quoted string". The engine treats `"` as a string delimiter regardless of quoting style. The two-pass workaround avoids this entirely.

**Invoke the PowerQuery skill before authoring parse expressions.** The skill references official documentation and reaches the correct pattern faster than ad-hoc trial-and-error.


---

## Render-only defects: validate with screenshots, not just the API

`validate_dashboard.py` proves each panel's query returns rows. It does NOT prove the panel renders: the browser, not the API, is where a markdown tile shows "Untitled", a `let`-arithmetic panel shows "Couldn't load content", a number reads its unit twice, or a chart legend breaks. Query replay is blind to all of these.

**Hard rule: after every dashboard deploy, ask the user for screenshots of each tab, read them, fix every visual defect in the JSON, and re-deploy, without being asked.** It is the final, mandatory deploy step, not optional polish.

Render-only defects seen live (S-26.1) and their fixes:

- **z-score / ratio panel shows "Couldn't load content: Identifier 'a-b' is ambiguous".** Arithmetic in a `let` needs spaces around every operator: `(live_count - baseline_avg) / baseline_stddev`. A detection-rule body copied from the console may already have spaces while a hand-written panel does not, so check both. This silently fails the entire panel, not just the expression.
- **Markdown header reads "Untitled".** Set a short plain-text `title`; a markdown panel with no `title` key renders "Untitled". Keep prose (no repeated `##` heading) in `markdown`.
- **Number reads the unit twice ("34 principals" under "Active principals").** Drop `options.suffix` when the title already names the unit; keep `{format, precision}` only.
- **Single-series `stacked_bar` with a stray legend token.** Group only by `timebucket(...)` for a clean total series (or use a `line`/`donut`), or `| transpose <dim> on timestamp` for a real per-category series. Grouping by a dimension WITHOUT transposing produces a confusing single series plus a stray legend entry.
- **Categorical bar/line panel errors "first column ... should have numeric value in epoch".** `graphStyle: "bar"`, `"line"`, and `"area"` default to a time x-axis and require an epoch first column. For a by-category bar chart use `graphStyle: "stacked_bar"` with `"xAxis": "grouped_data"` and a `(category, value)` query. Plain `bar` is not a categorical bar chart.
