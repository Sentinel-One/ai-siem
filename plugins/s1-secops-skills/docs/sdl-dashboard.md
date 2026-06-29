# SDL Dashboard: Panel Types and Features Reference

Complete reference for SDL dashboard JSON authoring. All entries are confirmed against a live tenant via the `panel-showcase` dashboard (`/dashboards/panel-showcase`).

**Full working example:** [`sdl-dashboard/examples/panel-showcase.json`](../skills/sdl-dashboard/examples/panel-showcase.json) — a 3-tab, 23-panel dashboard covering every supported panel type and feature. Deploy it directly with `sdl_put_file` to `/dashboards/panel-showcase`.

---

## Panel types

| graphStyle | Use case | Query shape |
|---|---|---|
| `number` | Single KPI value | `\| group count=count()` — must return a single scalar |
| `gauge` | Value vs. threshold bands | `\| group value=<scalar>` — field must be named `value` |
| `donut` | Part-of-whole distribution with center total | `\| group count=count() by label` |
| `pie` | Part-of-whole distribution, no center total | `\| group count=count() by label` |
| `stacked_bar` | Category comparison (`xAxis: "grouped_data"`) or time-series bars (`xAxis: "time"`) | `\| group count=count() by category` or `\| group count by category, timebucket() \| transpose` |
| `stacked` | Stacked area over time | `\| group count by category, timebucket() \| transpose category on timestamp` |
| `line` | Multi-series time-series line chart | `plots[]` array (not `query`) |
| `area` | Multi-series filled area chart | `plots[]` array (not `query`) |
| `heatmap` | 2D time density: category × time bucket, color = count | `\| group EventCount=count() by user, timestamp=timebucket('1h') \| transpose user on timestamp` |
| `honeycomb` | Static cell density grid, color = magnitude | `\| group value=count() by label` |
| `bullet` | KPI value vs. SLA target with color bands | `\| columns value, target, label` — all three columns required |
| `funnel` | Ordered step-down counts | `\| columns Step, Count` |
| `sankey` | Flow between two node sets | `\| columns source, target, c` |
| `scattered_bubble` | 3D outlier detection: x, y, bubble size, label | `\| columns x_col, y_col, size_col, label=field` |
| `distribution` | Histogram of a numeric field | Uses `filter` + `facet` keys, no `query` |
| `markdown` | Rich text description or section header | `markdown` key, no query |
| `""` (empty) | Table view | Standard PowerQuery, optional `showBarsColumn`, supports `tabbed` sub-tabs |

---

## Panel-level features

### number panel
```json
{
  "graphStyle": "number",
  "query": "dataSource.name='alert' | group count=count()",
  "options": { "format": "commas", "suffix": " alerts", "color": "#E0483C" },
  "sparklineConfig": { "enabled": true },
  "trendConfig": {
    "enabled": true,
    "upwardsMeaning": "NEGATIVE",
    "indicators": {
      "arrow": { "enabled": true },
      "number": { "enabled": true, "calculationType": "PERCENTAGE" }
    }
  },
  "chartLinkConfig": { "url": "/incidents/unified-alerts" }
}
```
- `options.format`: `"commas"` adds thousands separators
- `options.suffix`: appended after the value (e.g. `" alerts"`, `" GB"`)
- `options.color`: hex color for the number text
- `sparklineConfig.enabled`: shows a mini trend line below the number
- `trendConfig`: shows a % change vs. prior period with directional arrow. `upwardsMeaning: "NEGATIVE"` colors upward trends red (use for failure/threat counts)
- `chartLinkConfig.url`: makes the number clickable, opens the given console path

### gauge panel
```json
{
  "graphStyle": "gauge",
  "query": "dataSource.name='alert' | group value=count()",
  "colorRangeConfig": {
    "ranges": [
      { "color": "#1CAA5D", "range": { "min": 0, "max": 500 } },
      { "color": "#E6752D", "range": { "min": 500, "max": 2000 } },
      { "color": "#E0483C", "range": { "min": 2000, "max": 10000 } }
    ]
  }
}
```
The query result column **must** be named `value`. Color ranges define semantic zones (green/amber/red).

### donut panel
```json
{
  "graphStyle": "donut",
  "maxPieSlices": 6,
  "dataLabelType": "PERCENTAGE",
  "totalNumberConfig": { "enabled": true }
}
```
- `maxPieSlices`: caps segments, remainder grouped as "Other"
- `dataLabelType`: `"PERCENTAGE"` or `"VALUE"`
- `totalNumberConfig.enabled`: shows sum in the center hole

### pie panel
Same as donut but no `totalNumberConfig`. Use `pie` when center total is not meaningful.

### stacked_bar panel
```json
{
  "graphStyle": "stacked_bar",
  "xAxis": "grouped_data",
  "yScale": "linear"
}
```
- `xAxis: "grouped_data"`: horizontal category comparison
- `xAxis: "time"`: time-series bars. Query must use `timebucket()` + `transpose`
- `yScale`: `"linear"` or `"logarithmic"`

### line and area panels (plots array)
Both use `plots[]` instead of `query` for multi-series without PowerQuery:
```json
{
  "graphStyle": "line",
  "lineSmoothing": "smoothCurves",
  "plotNulls": "connected",
  "plots": [
    { "filter": "dataSource.name='Identity' unmapped.type='Logon Success'", "label": "Success", "facet": "rate", "color": "#1CAA5D" },
    { "filter": "dataSource.name='Identity' unmapped.type='Logon Failure'", "label": "Failure", "facet": "rate", "color": "#E0483C" }
  ]
}
```
- `lineSmoothing`: `"smoothCurves"` or `"straightLines"`
- `plotNulls: "connected"`: bridges gaps in sparse series
- `facet`: `"rate"` for events/sec, or a field name to aggregate
- `color`: per-series hex color

### heatmap panel
```json
{
  "graphStyle": "heatmap",
  "query": "... | group EventCount=count() by user_name=user.name, timestamp=timebucket('1h') | transpose user_name on timestamp",
  "colorScheme": "red",
  "colorSchemeOrder": "standard",
  "numberOfRanges": 5,
  "rangesCreation": "automatic",
  "heatmapRangeConfig": ["-∞", "", "", "", "", "∞"]
}
```
**Critical rule:** `rangesCreation: "automatic"` requires all middle elements of `heatmapRangeConfig` to be empty strings `""`. Providing explicit numeric values (e.g. `"50"`) conflicts with automatic mode and renders a blank panel with no error. The array must have N+1 elements for N ranges.

Pre-filter to a fixed user/category set before `transpose` to keep the heatmap readable and avoid sparse null columns.

### honeycomb panel
```json
{
  "graphStyle": "honeycomb",
  "query": "... | group value=count() by label=indicator.category | sort -value | limit 15",
  "honeycombColorScheme": "red",
  "honeycombRangeConfig": [0, 1000, 10000, 100000]
}
```
Static cell grid. Result columns must be `value` (numeric) and `label` (string). `honeycombRangeConfig` defines explicit threshold boundaries.

### bullet panel
```json
{
  "graphStyle": "bullet",
  "query": "... | columns value, target, label",
  "bulletColorScheme": "semantic",
  "coloringMode": "ranges",
  "colorSchemeOrder": "standard",
  "rangesCreation": "automatic",
  "numberOfRanges": 4
}
```
All three columns (`value`, `target`, `label`) are required. `coloringMode: "kpiReach"` colors the entire bar red if the KPI target is missed.

### funnel panel
```json
{
  "graphStyle": "funnel",
  "query": "| union (...) | columns Step, Count",
  "orientation": "horizontal",
  "funnelOptions": { "colorScheme": "default", "colorSchemeOrder": "standard", "autoScale": "true" }
}
```
Result must have `Step` (string label) and `Count` (numeric) columns. Use `| union` to assemble steps from separate queries.

### sankey panel
```json
{
  "graphStyle": "sankey",
  "query": "... | group c=count() by source=src.ip, target=user.domain | columns source, target, c",
  "colorMatching": "automatic",
  "sankeyColorScheme": "default",
  "showNodeValues": "true"
}
```
Result must have exactly `source`, `target`, and a numeric weight column.

### scattered_bubble panel
```json
{
  "graphStyle": "scattered_bubble",
  "query": "... | columns x_col, y_col, size_col, label=field_name",
  "scatteredBubbleConfig": { "showLabel": true }
}
```
First three numeric columns map to x, y, bubble size. Fourth column is the label. Upper-right outliers = highest x and y values.

### distribution panel
```json
{
  "graphStyle": "distribution",
  "filter": "dataSource.name='SentinelOne' event.category='ip' dst.port.number=*",
  "facet": "dst.port.number"
}
```
Uses `filter` and `facet` keys only — no `query`. The `facet` field must be numeric at the schema level. SDL auto-buckets the distribution.

### tabbed table panel
```json
{
  "graphStyle": "",
  "showBarsColumn": true,
  "tabbed": "true",
  "tabVariant": "tile",
  "query": "...",
  "tabs": [
    { "title": "Tab 1", "query": "..." },
    { "title": "Tab 2", "query": "..." }
  ]
}
```
Multiple query tabs inside a single panel widget. `tabVariant: "tile"` uses pill-style tab buttons. `showBarsColumn` toggles the inline bar column in the table.

### markdown panel
```json
{
  "graphStyle": "markdown",
  "markdown": "**Bold text**, `code`, and regular prose. Use for section headers and context."
}
```
No query. Supports standard markdown formatting.

---

## Dashboard-level features

### TABBED dashboard
```json
{
  "configType": "TABBED",
  "duration": "24h",
  "description": "Dashboard subtitle text",
  "tabs": [
    { "tabName": "Tab 1", "graphs": [...] },
    { "tabName": "Tab 2", "graphs": [...] }
  ]
}
```
- `duration`: default time window shown on load
- `description`: subtitle shown below the dashboard title

### filters[] — live tab-scoped filter widget (TABBED only)
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
Declared inside a tab object. Populates dropdown options from live field values in the current time range. Selecting a value automatically applies the filter to every panel in that tab. This is the correct interactive filtering mechanism for TABBED dashboards.

### #VarName# substitution — flat (non-TABBED) dashboards only
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
    { "query": "tag=#Specified Tag# | group count() by serverHost" }
  ]
}
```
Only works in flat dashboards (no `configType`, no `tabs`). In TABBED dashboards `#VarName#` is passed literally and throws `Don't understand [#]`. String values must embed single quotes: `"'logVolume'"` so substitution produces `tag='logVolume'`.

### Panel layout
Every panel requires explicit `layout`:
```json
"layout": { "h": 22, "w": 30, "x": 0, "y": 15 }
```
Grid is 60 units wide. `h`/`w` in grid units, `x`/`y` are top-left offsets. Panels in the same row must share the same `y` value.

---

## Confirmed working panel inventory (panel-showcase dashboard)

| Tab | Panel | graphStyle | Key features demonstrated |
|---|---|---|---|
| SOC Overview | Total Alerts | `number` | `sparklineConfig`, `options.format`, `suffix` |
| SOC Overview | Identity Logon Failures | `number` | `trendConfig`, `upwardsMeaning: "NEGATIVE"`, `options.color` |
| SOC Overview | Active EDR Endpoints | `number` | `estimate_distinct` as scalar |
| SOC Overview | Open Alert Queue | `gauge` | `colorRangeConfig` with 3 zones |
| SOC Overview | Alert Severity Distribution | `donut` | `totalNumberConfig`, `dataLabelType: "PERCENTAGE"`, computed label via `let` |
| SOC Overview | Top Alert Titles | `stacked_bar` | `xAxis: "grouped_data"` |
| SOC Overview | EDR Event Categories Over Time | `stacked_bar` | `xAxis: "time"`, `transpose` |
| SOC Overview | Indicator Category Density | `honeycomb` | `honeycombColorScheme`, `honeycombRangeConfig` |
| SOC Overview | Threat Detection Funnel | `funnel` | `\| union`, `orientation: "horizontal"`, `autoScale` |
| SOC Overview | Multi-Source Event Explorer | `""` (table) | `tabbed: "true"`, `tabVariant: "tile"`, 4 sub-tabs |
| Threat Hunting | Alert Volume vs SLA Threshold | `bullet` | `bulletColorScheme: "semantic"`, `coloringMode: "ranges"`, `rangesCreation: "automatic"` |
| Threat Hunting | Identity Auth Events Over Time | `line` | `plots[]`, `lineSmoothing`, `plotNulls: "connected"`, per-series color |
| Threat Hunting | Identity Logon Activity by User | `heatmap` | `rangesCreation: "automatic"`, `heatmapRangeConfig` empty-string middles |
| Threat Hunting | Login Flow: Source IP to User Domain | `sankey` | `colorMatching: "automatic"`, `showNodeValues` |
| Threat Hunting | Process Network Outliers | `scattered_bubble` | `scatteredBubbleConfig.showLabel`, 3D outlier pattern |
| Threat Hunting | FortiGate Inbound Traffic by Size | `stacked_bar` | Computed bucket via `let`, histogram pattern |
| Threat Hunting | EDR Event Volume Over Time | `stacked` | `transpose` multi-category area |
| Panel Features | Critical & High Alerts | `number` | `chartLinkConfig` drill-through to console |
| Panel Features | Distinct Alert Types | `gauge` | `estimate_distinct` as gauge value |
| Panel Features | Network Destination Ports | `distribution` | `filter` + `facet` (no query), numeric field |
| Panel Features | EDR Event Rate by Category | `area` | `plots[]`, 4 series, per-series color |
| Panel Features | Alerts by Product | `pie` | `maxPieSlices`, `dataLabelType: "PERCENTAGE"` |
| Panel Features | Alerts by Title | `""` (table) | `showBarsColumn: true`, `filters[]` active |
| All tabs | Tab filter widgets | — | `filters[]` with `facet` — Site, Data Source, Alert Product |

The complete JSON source for all panels above is in [`sdl-dashboard/examples/panel-showcase.json`](../skills/sdl-dashboard/examples/panel-showcase.json).
