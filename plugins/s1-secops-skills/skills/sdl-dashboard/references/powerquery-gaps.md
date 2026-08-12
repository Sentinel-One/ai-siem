# PowerQuery feature gaps to design around

PowerQuery patterns that fail or render badly inside dashboard JSON, the patterns that work instead, the two-pass quoted-KV parse, and the totals-plus-breakdown workaround. Referenced from `SKILL.md`.

## PowerQuery feature gaps to design around

The patterns below produce HTTP 500s or silent renderer failures on current SDL builds. They appear syntactically valid in language references and may even work in a developer's local PowerQuery preview, but they are not safe inside dashboard JSON. Treat them as red flags during code review. `scripts/panel_safety_check.py` scans for them automatically.

| Pattern | Failure mode |
|---|---|
| `\| let x = if(predicate, then, else)` then aggregating on `x` | 500 server error |
| `count_if(predicate)` / `countif(predicate)` aggregate functions | 500 server error |
| `sum(if(predicate, value, 0))` inside `\| group ... by ...` | 500 server error |
| `concat(field_a, ' literal ', field_b)` in `\| let` bindings | 500 server error |
| `\| union (subquery)` MID-PIPELINE (after any other command) | HTTP 400 (live-verified 2026-07-29). `union` as the FIRST command of the query, one subquery per row set, IS valid and works, including with commands after it (e.g. `\| sort`). Use union-first for funnels/synthetic rows; never mid-pipeline |
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

**Pass 1**, capture the whole non-whitespace token including its surrounding quotes:

```text
| parse "app=$raw_app{regex=\\S+}$" from message
```

This extracts `"HTTPS.BROWSER"` (with quotes) into `raw_app`.

**Pass 2**, extract the clean value by matching the alphanumeric content, which skips the leading `"`:

```text
| parse "$app_name{regex=[A-Z0-9./_-]+}$" from raw_app
```

This produces `HTTPS.BROWSER` (no quotes) in `app_name`.

Full example for an app-ctrl panel:

```text
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

When `sum(if())` and `count_if()` fail, first try a union-FIRST query (one subquery per row set; live-verified 2026-07-29). If that does not fit, the cleanest substitute is two adjacent panels: one for totals, one for the per-action breakdown (long-format). Lay them side-by-side at half-width so they read as a single visual unit. Trying to force a single wide table with both columns generally requires one of the unsupported patterns above.

---
