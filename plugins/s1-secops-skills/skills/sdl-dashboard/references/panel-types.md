# SDL dashboard panel types and JSON

Full per-panel JSON catalog for every SDL dashboard `graphStyle`. This is the companion to the one-line-per-panel [`panel-type-cheatsheet.md`](panel-type-cheatsheet.md): the cheatsheet summarizes each panel, this file holds the complete JSON examples. Referenced from the Panel types section of `SKILL.md`.

## Panel types and JSON

Every panel is an object inside `graphs`. The `graphStyle` property picks the panel type.

### Layout

Every panel **must** have explicit `x`, `y`, `w`, `h` in its `layout` object. Dashboards with many panels (observed at 18+) where `x`/`y` are omitted can hang the browser renderer indefinitely, the auto-layout pass appears to loop on collision detection when panels stack at the implicit (0,0) origin. The symptom is the browser tab becoming unresponsive before any query fires.

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

`graphStyle`: `"table"` (or omit, table is the default for PowerQuery panels)

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

> **No "millions" (or thousands) number format.** SDL number panels scale only via `format: "auto"` (which may render K/M/B); there is no explicit millions option. To force a specific unit, divide in the query and label the title: `... | group ev = count() | let Events_M = ev / 1000000 | columns Events_M | limit 1` with title `"Total Events (M)"`. Always carry the unit (GiB, events, min, count, ratio) in the title or `suffix`, a number panel renders only a bare value.
>
> **Options, stick to the minimal set.** Production reference dashboards only set `{format, precision, suffix}`. Fields like `backgroundColor` and `color` are documented in some places but are not consistently honoured by the renderer, at best silently ignored, at worst the panel renders blank or hangs. Do not add them until tested against the specific tenant.

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
> no error**, the API accepts it, the UI just has nothing to display. Always
> use `"markdown": "..."`.
>
> **Title duplication:** the SDL UI renders the `"title"` field as a header above the panel body. Do NOT repeat the same heading inside the `"markdown"` body. A common mistake is setting `"title": "## Policy Enforcement"` (with the `##` markdown prefix) and then starting the markdown body with `## Policy Enforcement\nDescription...`; this produces the heading twice. Keep the `title` field as plain text and put only the descriptive prose (no repeated heading) inside `"markdown"`. Also: a markdown panel with NO `title` key renders an "Untitled" header in S-26.1 (observed live), so always set a short plain-text `title`.

```json
{
  "title": "About this dashboard",
  "graphStyle": "markdown",
  "markdown": "This dashboard tracks **threat activity** across all managed endpoints.\n\n[Open Event Search](/logs)"
}
```

---
