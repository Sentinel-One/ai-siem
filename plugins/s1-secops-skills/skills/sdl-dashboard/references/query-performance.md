# Query performance tips

Per-query performance rules for SDL dashboard panels: presence checks, limits, timebucket sizing, `number()` casting, and more. Referenced from `SKILL.md`.

## Query performance tips

Dashboard panels run their queries in the SDL console's built-in rendering engine, not via LRQ or any external API. Every panel loads when the user opens the dashboard, so slow queries directly delay the page. Apply these rules to every query you write.

### 1. Use `net_rfc1918()`: never hand-roll CIDR regex

**Slow (avoid):**

```text
| let rfc1918 = not (dst.ip.address matches '((127\\..*)|(192\\.168\\..*)|(10\\..*)|(172\\.1[6-9]\\..*)|(172\\.2[0-9]\\..*)|(172\\.3[0-1]\\..*)).*')
| filter rfc1918 = true
```

**Fast:**

```text
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

### 4. Use `field=*` to drop nulls: the canonical presence form

`field=*` is the canonical SDL presence predicate: it matches any event where the field is present and non-null. Accuracy note (live-verified 2026-07-29 via the LRQ API): `field != null` returned results identical to `field=*`; the earlier claim that it hard-errors or compares against the literal string "null" was NOT reproducible on LRQ. The console/dashboard renderer engine remains unverified for `!= null`, so `field=*` stays the REQUIRED form in all dashboard JSON, rule bodies, and examples:

```text
// Required: canonical presence check
dataSource.name='alert' severity_id=*
| group count=count() by severity_id

// Avoid: behaved identically via LRQ (2026-07-29) but unverified in the dashboard engine
dataSource.name='alert' severity_id != null
```

This applies in the initial filter predicate (before the first `|`) and in `| filter` commands equally.

### 5. Use `| filter count > 0` to suppress zero rows

After a `| group count=count() by ...`, SDL may produce rows with `count=0` for sparse buckets (especially after `transpose` or when grouping over a large key space). These zero rows render as empty cells in heatmaps and false entries in tables. Filter them out:

```text
| group EventCount=count() by user_name=user.name, timestamp=timebucket('1h')
| filter EventCount > 0
```

Apply the same pattern to any aggregated numeric field you're visualising: `| filter bytes > 0`, `| filter value > 0`.

### 6. `| sort` must come before `| columns`: field projection is destructive

`| columns` removes every field not listed. Any `| sort` placed after `| columns` that references a field not in the projected set is operating on a non-existent field and silently fails or hangs the panel (bullet panels are especially prone to this):

```text
// Wrong: severity_id is gone after | columns, sort fails silently
| group value=count(), target=..., label=... by severity_id
| columns value, target, label
| sort -severity_id          ← severity_id no longer exists

// Correct: sort while severity_id is still in scope
| group value=count(), target=..., label=... by severity_id
| sort -severity_id
| columns value, target, label
```

This affects any pipeline that projects away the sort key: bullet panels, donut panels with a custom label column, and any query that renames fields via `| columns alias=field`.

### 7. Use `event.category = *` not `event.category != ''`

`!= ''` requires evaluating the field value as a string comparison. `= *` is a cheaper is-not-null predicate:

```text
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

For a 24h dashboard, `'10m'` (144 points) can work for low-cardinality single-series panels but should not be the default; use `'1h'`. For a multi-series transpose, the data-point count compounds: `timebucket('10m')` on a 24h dashboard with a 7-series transpose = 1,008 cells per chart.

**Never use `timebucket('10m')` on a 7-day dashboard**; that's 1,008 points per series.

### 6. Push filters early: before the first pipe

The initial filter (before the first `|`) is evaluated as an index predicate. Conditions placed there are far cheaper than `| filter` commands applied after a full scan:

```text
// Good: index-level filter
event.category = 'ip' event.network.direction = 'OUTGOING' dataSource.category = 'security'
| group count=count() by dst.ip.address | sort -count | limit 20

// Bad: scans all events then filters
dataSource.category = 'security'
| filter event.category = 'ip' && event.network.direction = 'OUTGOING'
| group count=count() by dst.ip.address | sort -count | limit 20
```

### 7. Use `estimate_distinct()` for cardinality: not `count(distinct …)`

`estimate_distinct()` uses HyperLogLog and is orders of magnitude faster on high-cardinality fields like `agent.uuid`, `threat_id`, `src.process.storyline.id`.

### 8. Avoid `nolimit` in dashboard panels

`nolimit` raises the row cap to 3 GB and blocks concurrent queries. It is never appropriate in a dashboard panel; always use an explicit `| limit N` instead.

### 9. Wrap string-prone numeric fields with `number()` before arithmetic

SDL/Scalyr column types are locked at first ingest. A field that *should* be numeric, `severity_id`, `traffic.bytes_in/out`, `traffic.packets_in/out`, `unmapped.duration`, can be string-typed at the index level (because a parser declared `type: "string"` for many tenant generations, or the field was first-written before the type was set). When that happens, `sum()` / `avg()` / `max()` / `>=` predicates return NaN or fail silently *even though the values are populated and visible in Event Search*.

**Failsafe pattern for every dashboard panel that does numeric work:**

```text
dataSource.name='alert' severity_id=*
| let sev = number(severity_id)
| filter sev >= 4
| group hits=count() by sev
| sort sev
```

```text
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
