# Panel Type Cheatsheet

## Complete panel type reference

| graphStyle | Panel | Query type | Notes |
|---|---|---|---|
| `line` | Line chart | PQ or `plots`-based filter+facet | Use `timebucket` + `transpose` for multi-series in PQ. Or use `plots` array (see below). |
| `area` / `stacked` | Area / stacked area | PQ or filter+facet | `stacked` = stacked area. Good for event volume over time with `transpose`. |
| `stacked_bar` / `bar` | Bar chart | PQ | Set `xAxis: "time"` for time x-axis or `xAxis: "grouped_data"` for categories. |
| `pie` | Pie chart | PQ | Exactly 1 text + 1 numeric column. `maxPieSlices` controls grouping. |
| `donut` | Donut chart | PQ | Same as pie. `totalNumberConfig: {enabled: true}` shows total in center. `dataLabelType: "VALUE"` or `"PERCENTAGE"`. |
| `number` | Single-value KPI | PQ | Single numeric value. `sparklineConfig: {enabled: true}` adds mini sparkline. `trendConfig` adds % change arrow. `options.color` overrides color. |
| `gauge` | Radial gauge | PQ | Like `number` but renders a visual arc/dial. `colorRangeConfig.ranges[]` sets color bands per numeric range. Use for SOC queue health, capacity, and backlog. |
| `bullet` | Bullet / KPI vs target | PQ | Shows actual value vs SLA target across color-coded zones. Full config below. |
| `honeycomb` | Honeycomb heatmap | PQ | Cells colored by value. Use `columns` to alias the text + numeric columns. Good for process/port density. |
| `heatmap` | 2D time heatmap | PQ | Time on x-axis, category on y-axis, color = event density. Query must use `timebucket` + `transpose`. `heatmapRangeConfig` sets bands. |
| `sankey` | Sankey flow diagram | PQ | Shows flows between nodes weighted by count. Query must return `source`, `target`, `c`. Full config below. |
| `scattered_bubble` | Bubble scatter chart | PQ | 3D scatter: x, y, bubble-size from 3 numeric columns. Optional `label` column. `scatteredBubbleConfig: {showLabel: true}`. |
| `table` (graphStyle `""`) | Table | PQ | Default for PQ panels. `showBarsColumn: "true"` adds inline bar chart. |
| `table` with tabs | Tabbed table | PQ | Add `tabbed: "true"`, `tabVariant: "tile"`, and `tabs: [{query, title}]`. Each tab has its own PQ. |
| `funnel` | Funnel chart | PQ | Shows volume drop-off across sequential stages. Query returns `stage` (text) + `value` (number) via `| union`. |
| `distribution` | Distribution histogram | filter+facet | Uses `filter` + `facet` (not `query`). Good for port/packet-size distributions. No PQ. |
| `markdown` | Text panel | none | GitHub-flavored markdown. Use `markdown:` field (NOT `content:` which renders blank). |
| `alerts_table` | Built-in alert widget | none | Uses `dataSource: "[[DataSource.ALERTS_DISTRIBUTION]]"` + `fieldId`. Not a PQ panel — pull from console widget library. |
| Filter widget | Parameter dropdown | none | NOT a `graphStyle` — declared in the tab's `parameters: []` array. Renders as a dropdown above the tab. See Filter/Parameter section below. |

---

## Choosing the right panel for your data

| Data type / question | Best panel |
|---|---|
| How many X right now? (KPI, count, rate) | `number` with `sparklineConfig` + `trendConfig` |
| Am I meeting SLA / MTTR target? | `bullet` (value vs target, color zones) |
| Is the SOC queue / capacity critical? | `gauge` (arc dial with color thresholds) |
| How is X distributed across categories? (OS, severity) | `donut` with `totalNumberConfig` |
| How does X change over time? (single series) | `line` |
| How do multiple categories change over time? | `stacked` or `stacked_bar` with `transpose` |
| Where is most activity happening? (density matrix) | `heatmap` (time x user/category) |
| Which cells are hottest? (process/port/rule density) | `honeycomb` |
| How do flows move between nodes? (login path, kill chain, process tree) | `sankey` |
| Outlier detection across 3 dimensions (x, y, size) | `scattered_bubble` |
| Ranked list with inline bar for comparison | `table` with `showBarsColumn: "true"` |
| Multiple queries in one panel with tabs | Tabbed table (`tabbed: "true"`) |
| Static description or instructions | `markdown` |
| Port/size frequency distribution | `distribution` |
| Drop-off across sequential stages (events → storylines → alerts) | `funnel` |
| Interactive dropdown to filter the whole tab | `parameters` array (Filter widget) |

---

## Bullet panel: full config

The bullet panel shows an actual value against a target (SLA) with colored range zones. Ideal for MTTR, response time, compliance scores.

**Query pattern**: return `value_column`, `sla_column`, `label_column`. The first numeric column is the actual value; the second is the target/SLA bar.

```javascript
{
  graphStyle: "bullet",
  title: "Average MTTR vs SLA by Severity",
  query: "| datasource alerts | filter status = 'RESOLVED'\n| group completion_minutes=avg(number(resolveSLOCompletion))/60 by severity\n| let slo_target = severity='CRITICAL' ? 60 : severity='HIGH' ? 120 : severity='MEDIUM' ? 180 : 300\n| columns completion_minutes, slo_target, severity",
  // Color scheme: "semantic" (green/amber/red) or "blue" (sequential)
  bulletColorScheme: "semantic",
  // coloringMode: "ranges" (color by zone), "kpiReach" (color above/below SLA), "none"
  coloringMode: "ranges",
  // colorSchemeOrder: "standard" or "inverted"
  colorSchemeOrder: "standard",
  // aboveKPIColor / belowKPIColor: "positive", "negative", "neutral"
  aboveKPIColor: "neutral",
  belowKPIColor: "negative",
  // rangesCreation: "automatic" (equal divisions) or "manual" (explicit bulletRangeConfig)
  rangesCreation: "automatic",
  numberOfRanges: 4,
  // For manual ranges: boundary strings including "0" and a high ceiling
  bulletRangeConfig: ["0", "30", "60", "120", "1000"],
  // Per-range colors (manual only, semantic scheme)
  bulletColorRangeConfig: {
    ranges: [
      { color: "var(--g-dv-semantic-positive)", range: { min: "0", max: "30" }, value: "25" },
      { color: "var(--g-dv-semantic-warning)",  range: { min: "30", max: "60" }, value: "45" },
      { color: "var(--g-dv-semantic-negative)", range: { min: "60", max: "120" }, value: "90" },
      { color: "var(--g-dv-semantic-caution)",  range: { min: "120", max: "1000" }, value: "300" }
    ]
  },
  layout: { h: 13, w: 30, x: 0, y: 0 }
}
```

**Color tokens:**
- Semantic: `var(--g-dv-semantic-positive)`, `var(--g-dv-semantic-warning)`, `var(--g-dv-semantic-negative)`, `var(--g-dv-semantic-caution)`
- Blue sequential (5-step): `var(--g-dv-sequential-default-5-step-1)` through `var(--g-dv-sequential-default-5-step-5)`

---

## Sankey panel: full config

Sankey diagrams show flows between nodes. Each row in the result is one directed edge: source node → target node, weighted by a count.

**Query pattern**: must return exactly `source`, `target`, `c` column names.

Use `array(0, 1, 2).expand()` to fan a single event row into multiple Sankey links (one per stage in the chain):

```javascript
{
  graphStyle: "sankey",
  title: "External Login Flow: Country → Process → User → Host → Result",
  query: "event.type == 'Login'\n| filter !net_private(src.endpoint.ip.address)\n| let country = geo_ip_country(src.endpoint.ip.address)\n| group c = count() by country, process=src.process.name, user=event.login.userName, host=endpoint.name, result = event.login.loginIsSuccessful ? 'Success' : 'Fail'\n// Fan each row into 4 Sankey links\n| let link = array(0, 1, 2, 3).expand()\n| let source = link==0 ? 'Inbound: '+country : link==1 ? 'Process: '+process : link==2 ? user : host\n| let target = link==0 ? 'Process: '+process : link==1 ? user : link==2 ? host : result\n| group c = sum(c) by source, target\n| columns source, target, c",
  startTime: "24h",
  // colorMatching: "automatic" (Sankey assigns colors) or "manual" (use sankeyColorMapping)
  colorMatching: "manual",
  // sankeyColorScheme: "default" or "semantic"
  sankeyColorScheme: "semantic",
  showNodeValues: "true",
  // Manual color mapping: key is "positive"/"caution"/"warning"/"negative"; value is array of node label patterns (glob * supported)
  sankeyColorMapping: [
    { key: "positive", value: ["Success", "*❌:*"] },
    { key: "caution",  value: ["Process:*"] },
    { key: "warning",  value: ["Inbound*", "Country:*"] },
    { key: "negative", value: ["Fail", "*✅:*"] }
  ],
  layout: { h: 28, w: 60, x: 0, y: 0 }
}
```

**When to use Sankey:**
- Login flow: country → process → user → host → result
- Process tree: parent → child process chains
- Network: file hash → IP → country (with TI enrichment markers)
- Kill chain: alert stage progression

---

## Bubble (scattered_bubble) panel

3D scatter chart where bubble size = volume/count. Best for outlier detection and multi-dimensional ranking.

**Query pattern**: return 3 numeric columns (x, y, size) plus optional `label` for bubble labels.

```javascript
{
  graphStyle: "scattered_bubble",
  title: "Port Scan Detection: Ports vs Destination IPs (T1046)",
  description: "Upper-right outliers = active scanners. Bubble size = total connections.",
  query: "event.network.direction = 'OUTGOING'\n| filter net_rfc1918(dst.ip.address) = true\n| group\n    tgt_port_count = estimate_distinct(dst.port.number),\n    tgt_ip_count   = estimate_distinct(dst.ip.address),\n    conn_count     = count()\n  by src.ip.address\n| filter tgt_port_count >= 2\n| sort -tgt_port_count\n| columns tgt_port_count, tgt_ip_count, conn_count, label=src.ip.address",
  scatteredBubbleConfig: { showLabel: true },
  startTime: "4 hours",
  layout: { h: 26, w: 30, x: 0, y: 0 }
}
```

**When to use bubble:**
- Port scan detection (x=distinct ports, y=distinct IPs, size=total connections)
- User behaviour: login volume vs unique hosts vs failures
- Process outliers: execution count vs unique endpoints vs file write count

---

## Heatmap panel

2D heatmap with time on x-axis and a category on y-axis. Color intensity = event density.
Distinct from `honeycomb` (which is static cells) — `heatmap` is time-series.

**Query pattern**: same as a multi-series line chart. Use `timebucket` + `transpose` to produce a time × category matrix.

```javascript
{
  graphStyle: "heatmap",
  title: "Off-Hours Activity by User (22:00–06:00)",
  query: "// Join timeseries to top-10 users\nevent.type = 'Process Creation'\n| filter !(src.process.user contains:anycase 'SYSTEM')\n| let hour = number(strftime(event.time * 1_000_000, '%H', 'UTC'))\n| filter hour >= 22 OR hour < 6\n| group EventCount = count() by User = src.process.user, timestamp = timebucket('1h')\n| transpose User on timestamp",
  startTime: "7d",
  colorScheme: "red",
  colorSchemeOrder: "standard",
  numberOfRanges: 5,
  rangesCreation: "automatic",
  // Range boundaries array: N+1 elements for N ranges. Use "-∞" / "∞" for open bounds.
  heatmapRangeConfig: ["-∞", "", "", "", "", "∞"],
  layout: { h: 14, w: 30, x: 0, y: 0 }
}
```

**When to use heatmap:**
- Off-hours process execution by user (insider threat pattern)
- Hourly event volume spikes across sources
- Day-of-week × hour activity patterns

---

## Gauge panel

Radial arc/dial with color-coded threshold bands. Shows a single value in context (good/warn/critical).
Distinct from `number` — `gauge` renders a visual arc; `number` is text only.

```javascript
{
  graphStyle: "gauge",
  title: "SOC Queue Health",
  query: "event.category = 'indicators' | group estimate_distinct(src.process.storyline.id)",
  colorRangeConfig: {
    ranges: [
      { color: "#1CAA5D", range: { min: 0,   max: 100  } },
      { color: "#E6752D", range: { min: 100, max: 500  } },
      { color: "#E0483C", range: { min: 500, max: 5000 } }
    ]
  },
  layout: { h: 10, w: 15, x: 0, y: 0 }
}
```

**When to use gauge:** SOC queue backlog, capacity utilization, SLA attainment percentage (single-number pass/fail).

---

## Tabbed table panel

A table panel where multiple sub-queries can be toggled via tabs inside the panel — without needing separate dashboard tabs.

```javascript
{
  graphStyle: "",
  title: "Process Activity",
  // Outer query is used as default/fallback
  query: "event.category=process | columns endpoint.name, src.process.name, event.type",
  tabbed: "true",
  tabVariant: "tile",
  tabs: [
    {
      title: "Process Events",
      query: "event.category=process | group count() by endpoint.name"
    },
    {
      title: "Indicator Events",
      query: "event.category=indicators | group count() by endpoint.name"
    }
  ],
  layout: { h: 25, w: 60, x: 0, y: 0 }
}
```

**When to use tabbed tables:** Side-by-side data slices in one panel (process vs file vs network events), before/after comparisons, multi-severity breakdowns.

---

## Plots-based line chart (filter+facet, no PowerQuery)

Alternative to PQ for simple time-series with multiple colored series from different filter expressions:

```javascript
{
  graphStyle: "line",
  lineSmoothing: "smoothCurves",
  plotNulls: "connected",
  title: "FortiGate: Parsed vs Ingested Rate",
  plots: [
    {
      color: "#E0483C",
      facet: "rate",
      filter: "parser='marketplace-fortinetfortigate-latest'",
      label: "Logs (parsed)"
    },
    {
      color: "#9559F7",
      facet: "sumPerSec(eventCt)",
      filter: "dataSource.name='FortiGate' serverHost='scalyr-metalog' eventCt=*",
      label: "Logs (ingest)"
    }
  ],
  layout: { h: 14, w: 60, x: 0, y: 0 }
}
```

Use this when each series comes from a different filter rather than a transpose. Good for SDL internal metrics (log rates, parser throughput).

---

## Number panel: enhanced features

```javascript
{
  graphStyle: "number",
  title: "New Unassigned Alerts",
  query: "| datasource alerts where (status in ('NEW') and !(assigneeUserId = *)) count_by assigneeUserId | group sum(count)",
  options: {
    format: "commas",       // "commas" | "short" | "bytes"
    suffix: " alerts",      // appended after the value
    color: "#E0483C"        // override number color
  },
  // Mini sparkline below the number
  sparklineConfig: { enabled: true },
  // % change vs prior period with directional arrow
  trendConfig: {
    enabled: true,
    upwardsMeaning: "NEGATIVE",   // "POSITIVE" (growth is good) or "NEGATIVE" (growth is bad)
    indicators: {
      arrow: { enabled: true },
      number: { enabled: true, calculationType: "PERCENTAGE" }
    }
  },
  // Clickthrough to console page
  chartLinkConfig: { url: "/incidents/unified-alerts?alertsTable.filters=status%3DNEW" },
  layout: { h: 10, w: 15, x: 0, y: 0 }
}
```

---

## Donut panel: enhanced features

```javascript
{
  graphStyle: "donut",
  title: "Agent Operational State",
  query: "| datasource assets from 'workstation, server' where (surfaces = 'Endpoint') count_by 'agentOperationalState' | group count=sum(count) by agentOperationalState | filter count > 0",
  maxPieSlices: 10,               // groups remaining slices into "Other"
  dataLabelType: "VALUE",         // "VALUE" | "PERCENTAGE"
  totalNumberConfig: { enabled: true },  // shows grand total in center hole
  // Row-level drill-through to console
  defaultColumnConfig: {
    linkConfig: {
      page: "[[ShellPageId.UnifiedAssets]]",
      params: [
        { key: "activeTab", value: "surface.endpoint" },
        { key: "assets-surface-endpoint.filters", value: "agentOperationalState={{assetsLabelToValue(VALUE)}}" }
      ]
    }
  },
  layout: { h: 14, w: 20, x: 0, y: 0 }
}
```

---

## Funnel panel

Shows volume drop-off across sequential pipeline stages. Ideal for detection coverage, alert lifecycle, and SOC workflow funnel.

**Query pattern**: return a `stage` (text) + `value` (number) column pair using `| union` to build each stage row. Rows must be in order (largest stage first for vertical orientation).

```javascript
{
  graphStyle: "funnel",
  title: "Threat Detection Funnel: Events → Indicators → Alerts",
  query: "| union\n(\n  event.type=*\n  | group Count=count() by Step='1 - Collected Events'\n),\n(\n  event.category=* src.process.storyline.id=*\n  | group Count=estimate_distinct(src.process.storyline.id) by Step='2 - Storylines'\n),\n(\n  event.category='indicators' indicator.name=*\n  | group Count=estimate_distinct(indicator.name) by Step='3 - Indicators'\n),\n(\n  dataSource.name='alert' finding_info.internal_uid=*\n  | group Count=estimate_distinct(finding_info.internal_uid) by Step='4 - Alerts'\n)\n| columns Step, Count",
  // orientation: "vertical" (stages stack top-to-bottom) or "horizontal" (left-to-right)
  orientation: "horizontal",
  funnelOptions: {
    colorScheme: "default",     // "default" | "semantic"
    colorSchemeOrder: "standard",
    autoScale: "true"           // scales bar widths relative to first stage
  },
  startTime: "7d",
  layout: { h: 14, w: 60, x: 0, y: 0 }
}
```

**Alert lifecycle variant** (using `datasource` UQL):
```javascript
query: "| union\n( | datasource alerts count_by severity | group Total=sum(count) | let Step='All Alerts', Count=Total ),\n( | datasource alerts where (status in ('NEW','IN_PROGRESS')) count_by status | group Open=sum(count) | let Step='Unresolved', Count=Open ),\n( | datasource alerts where (status='NEW' AND !(assigneeUserId=*)) count_by assigneeUserId | group Unassigned=sum(count) | let Step='Unassigned', Count=Unassigned )\n| columns Step, Count"
```

**When to use funnel:**
- Detection coverage: events → storylines → indicators → alerts
- Alert lifecycle: total → open → unassigned → breached SLA
- IR workflow: detected → triaged → investigated → resolved
- Funnel analysis for any multi-stage security pipeline

---

## Filter widget (tab parameters)

The "Filter" panel in the UI is implemented as a `parameters` array on the tab object, not as a `graphStyle`. Each entry renders as a dropdown or free-text input above the tab content. Queries reference the variable with `#VarName#` syntax.

```javascript
// Declare on the tab object:
{
  "parameters": [
    {
      "name": "OS",               // referenced in queries as #OS#
      "label": "Operating System",
      "facet": "endpoint.os",     // field to populate dropdown options from SDL
      "defaultValue": "*"         // "*" = All (no filter)
    },
    {
      "name": "SiteFilter",
      "label": "Site",
      "facet": "s1_detection_metadata.site_name",
      "defaultValue": "*"
    },
    {
      "name": "HiddenVar",        // internal variable — not shown to user
      "label": "Hidden Filter",
      "defaultValue": "severity_id >= 3",
      "options": { "display": "hidden" }
    }
  ],
  "graphs": [ /* panels that use #OS#, #SiteFilter#, #HiddenVar# */ ]
}
```

**Usage in a PQ panel query:**
```
endpoint.os = #OS#
| group count=count() by src.process.name
```

**Key rules:**
- Parameters are tab-scoped (not global). Each tab that needs the filter must declare its own `parameters` entry.
- `facet` populates dropdown choices from live SDL data. Omit `facet` for free-text input.
- `defaultValue: "*"` means "match all" and typically appears as "All" in the dropdown.
- Hidden parameters (`options.display: "hidden"`) are useful for injecting pre-computed filter strings or internal constants.
- Use `#VarName#` in any query string on that tab — works in PQ, UQL `datasource`, and `plots filter` expressions.

---

## Key field requirements

- **Pie/Donut**: PowerQuery must return exactly one text column and one numeric column. `| group count() by field` is the canonical pattern.
- **Number/Gauge**: Reduce to a single row. `| group estimate_distinct(field)` or `| group count()` work.
- **Honeycomb**: Use `| columns LabelCol=text_field, ValueCol=numeric_field` to set column names, then reference them in `honeyCombGroupBy` and thresholds.
- **Distribution**: Does NOT use `query`: use `filter` (search expression) and `facet` (the numeric field). The `filter` field uses the old-style SDL filter syntax — do NOT use `field != null` for null checks, as this causes `field=[filter] error=[Illegal value [null]]`. Use `field=*` instead (matches any non-null value). The `facet` field MUST be a native NUMBER field in the SDL schema — string fields (even ones that look numeric like `traffic.bytes_in`) silently return an empty panel. Confirm the field type with `| group min=min(field), max=max(field)` before using it; if min/max return NaN or STRING, the field is not numeric. The `number()` cast in the `facet` expression (e.g. `facet: "number(traffic.bytes_in)"`) does NOT work for distribution panels — SDL checks the schema-level field type at render time, before the cast runs, so a string field stays blank even after casting.
- **Sankey**: Query must output exactly `source`, `target`, `c` column names. Use `array(...).expand()` for multi-hop link expansion.
- **Scattered bubble**: First 3 numeric columns = x, y, size. Add `label` column for point labels.
- **Heatmap/multi-series line**: Must use `timebucket()` in `group by`. Timestamp column must be named `timestamp`. Use `transpose field on timestamp` for the matrix.
- **Bullet**: First numeric column = actual value; second numeric column = SLA/target. Third column = row label.
- **Tabbed table**: `tabbed: "true"` and `tabVariant: "tile"` are both required. Outer `query` is the fallback.
- **Null check — always use `field=*`, never `field != null`**: `field=*` is the SDL predicate for "field is present and non-null". `field != null` is parsed as a literal string comparison to `"null"` in old-style filter syntax and returns wrong results or a parse error. Applies in both the initial filter predicate (before the first `|`) and in `| filter` commands: `dataSource.name='alert' severity_id=*` not `severity_id != null`.
- **Zero suppression — `| filter count > 0` after group**: After `| group count=count() by ...`, SDL can produce zero-count rows for sparse key combinations (common after `transpose` or wide key spaces). These render as empty heatmap cells and spurious table rows. Always add `| filter EventCount > 0` (or `| filter value > 0`) after any group that feeds a heatmap, donut, or table panel where zero rows are meaningless.
- **`| sort` must come before `| columns`**: `| columns` removes every field not listed. A `| sort` placed after `| columns` that references a projected-away field silently fails or hangs the panel. Move `| sort` before `| columns`. Most common victim: bullet panels that sort by a severity field but project it away in the final `| columns value, target, label`.
- **`in` operator restriction**: The `in (...)` set-membership operator only works inside `| filter` commands. It does NOT work in the initial filter predicate (the part before the first `|`). Use `dataSource.name='X'\n| filter field in ('a','b','c')` — not `field in ('a','b','c') | group ...`. Violating this causes a silent parse failure that surfaces as a frontend `TypeError: e.toLowerCase is not a function`.
- **Funnel**: Query must return exactly one text column (stage label) and one numeric column (count). Use `| union` to build stages. Rows should be in stage order; rows are NOT auto-sorted. `orientation: "vertical"` stacks top-to-bottom; `"horizontal"` is left-to-right.
- **Filter widget (parameters) — UI only, no query injection**: Parameters (`parameters: []` on a tab) render a dropdown or text input in the tab header. They do NOT modify panel queries at runtime. `#VarName#` and `$name` injection into `query`/`filter` fields is NOT supported — SDL's parser sees the literal `#` or `$` and throws `Don't understand [#]`. Confirmed across `facet`-based and `values`-based parameter types; zero community examples show working query injection. Use parameters as UI chrome (e.g. a visible filter label for demos) and hardcode the actual query filter. Two sub-types: `facet` (dropdown populated from live field values) and `values` (static list of options).
- **Breakdown graphs** (`breakdownFacet` property): Very slow, not cached. Use only for exploratory work.
- **Stacked bar with time x-axis**: Set `xAxis: "time"` and `yScale: "linear"`.
- **Stacked bar with category x-axis**: Set `xAxis: "grouped_data"`.
- **`stacked_bar` vs `stacked-bar`**: The official SentinelOne community docs (article 000006455) list `"stacked-bar"` with a hyphen. All real deployed dashboard examples use `"stacked_bar"` with an underscore. Use the underscore form — it is what the current SDL frontend expects.
- **`graphStyle` empty string behavior**: When `graphStyle` is `""` and a `query` is present, SDL defaults to a table. When `graphStyle` is omitted/empty and no `query` is present (only `filter`/`facet`), it defaults to a line chart. This is why the tabbed table panel uses `graphStyle: ""`.
- **`duration` (top-level)**: Sets the default time range shown in the global time picker when the dashboard is first loaded. Accepts any time string: `"24h"`, `"1 day"`, `"30m"`, `"7d"`, `"2 weeks"`. (Source: official SDL dashboard syntax article.)
- **`startTime` on individual panels**: Pins that panel to a fixed time window, overriding the global time picker. Omit `startTime` from panels if you want them to follow the global `duration` selector. Set it only when a panel must always show a fixed window (e.g., a 30-day trend card on a dashboard with a 24h default).
- **Colors**: Use hex `"#FF0000"` in `color` (per-plot) or `valueColors` (value-based coloring in S-25.3.6+). CSS variable tokens (`var(--g-dv-semantic-*)`) work in bullet and heatmap range configs.
- **Layout grid**: Total width = 60 units. Height: ~14 units ≈ half-page height. KPI rows typically h=10, w=15 (4 across). Full-width panels use w=60.
- **Markdown**: Use `markdown:` field, NOT `content:` which renders blank. Omit the `title` field entirely on markdown panels — setting `title: ""` causes SDL to display "Untitled" in the panel header. No `title` key = no header label shown.
- **Heatmap with `rangesCreation: "automatic"`**: The `heatmapRangeConfig` array must use empty strings `""` for all middle elements — SDL auto-calculates those boundaries from live data. Providing explicit non-empty values (e.g. `"10"`, `"50"`) conflicts with automatic mode and silently produces a blank panel. Correct form: `["-∞", "", "", "", "", "∞"]`. If data density is very sparse (e.g. a 24h window with few events per cell), SDL may also fail to compute thresholds — extend to `startTime: "7d"` with `timebucket('4h')` if automatic mode remains blank on confirmed-sparse data.
- **Honeycomb required fields**: `honeycombColorScheme` (e.g. `"red"`) and `honeycombRangeConfig` (numeric threshold array e.g. `[0, 1000, 10000, 100000]`) are both required. SDL calls `.toLowerCase()` on the color scheme value at render time — if either field is absent, the frontend throws `TypeError: e.toLowerCase is not a function`.
- **Bullet `coloringMode`**: Only confirmed valid value from real examples is `"ranges"`. The value `"kpiReach"` is not confirmed and may cause a render error.
