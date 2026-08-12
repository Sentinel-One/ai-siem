# Parameters and filters (dynamic filtering)

Deep detail on SDL dashboard dynamic filtering: `filters[]`, `#VarName#` substitution, and `parameters[]` behavior across flat and TABBED dashboards. Referenced from `SKILL.md`.

## Parameters and filters (dynamic filtering)

SDL has two distinct filtering mechanisms that look similar but behave very differently depending on dashboard type.

### `filters[]`: use this in TABBED dashboards (actually works)

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

The dropdown options are populated dynamically from live field values in the current time range. No query changes needed, SDL injects the filter automatically.

### `#VarName#` substitution: works in FLAT and TABBED dashboards; refiltering applies on Search

`#VarName#` query injection is confirmed working in flat dashboards (no `configType`, no `tabs`, top-level `parameters` and `graphs`; see `parameter_examples-v1.0.json`).

On a `configType: "TABBED"` dashboard, live visual verification (2026-07-29): a tab-level `parameters` entry renders its dropdown, a panel query using `#VarName#` renders WITHOUT error with the `defaultValue` substituted, and selecting a dropdown value re-filters the panel to exactly that value once the user presses **Search** (the dropdown does not auto-refresh the view). Test panel: `dataSource.name=#SrcName#` with facet `dataSource.name`, defaultValue `"*"`. The earlier claim that TABBED passes the literal `#` and throws `Don't understand [#]` was wrong; remember the Search-to-apply gotcha when demoing.

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

### `parameters[]` in TABBED dashboards: UI-only chrome

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
