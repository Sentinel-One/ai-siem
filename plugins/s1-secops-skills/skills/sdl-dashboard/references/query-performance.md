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

## Panel cost: pick the right SOURCE before tuning the query

Tips 1-9 above make a given query cheaper. This section is about not running it against the
expensive thing in the first place, which is worth far more.

Measured on one tenant, same 24-hour window, same day:

| What the panel queries | Rows scanned | Typical wall |
|---|---:|---:|
| A datatable, `dataset 'config://datatables/<name>'` | 10^2 | effectively 0 |
| An entity datasource with `count_by` pushdown | 10^1 pre-aggregated | ~1.3 s |
| `datasource metering` | 10^2 | ~6 s |
| Raw event lake, one day | ~9x10^8 | 5-18 s |
| Raw event lake, 15-30 days | ~10^10 | does not complete |

**Before tuning a lake panel, check whether the answer already exists pre-aggregated.** Worked
example from a live board: an ingest-health Overview tab was scanning ~9x10^8 events *five times per
tab load* to compute numbers already sitting in a 13-row and a 182-row datatable written by its own
nightly job. Retargeting those panels, cold windows, alternating order, median of 3:

| Panel | Lake | Datatable |
|---|---:|---:|
| sources ingesting | 10.5 s | 3.5 s |
| events total | 5.1 s | 3.7 s |
| top sources | 7.6 s | 3.7 s |
| **three panels** | **23.2 s** | **10.9 s** |

The datatable numbers sit on a ~3.4 s launch+poll floor, so the true gain is larger than 2.1x.

### Count the scans per TAB, not per panel

A tab fires every panel at once. That Overview had five independent full-lake scans, and **two of
them were the same query differing only by `limit 15` vs `limit 10`**, one scan was pure waste.
Before shipping a tab, list its queries and look for duplicates and for anything hitting the lake
that need not.

### Split the board on "is this a right-now question?"

Anything that is not live can come from the nightly artefact. Anything genuinely live must not.
On the board above: Overview and Health read the nightly baseline datatables; the four detections
keep reading the lake, because "has this feed gone dark right now" cannot be answered from a
baseline built last night.

**Say which is which in the board.** Once the two sources coexist they will disagree by up to a
day, and a reader cannot tell from a number alone.

### Panel titles and legends are part of the query

Two defects from the same rework, both self-inflicted:

- Retargeting a panel titled "Events (24h)" at a 15-day baseline table without retitling it
  produces a confidently wrong number.
- The board's legend asserted *"Overview panels show RAW volume ... BEFORE the exclusion lists are
  applied"*. That became false the moment the queries moved, and sat there misdescribing the board.

Treat descriptive markdown as code that must change with the queries it describes.

### Show the control surface

Exclusion and allowlist tables applied invisibly cannot be audited from the board. One small table
listing them (`| dataset 'config://datatables/<exclusions>' | columns value, reason, added`) makes
the dashboard self-explaining and costs nothing.

### `count_by` pushdown and datasource-line pruning

The stock console dashboards never touch `dataset = events`. They use entity datasources and push
aggregation into the `datasource` statement, before the first pipe:

```text
| datasource assets where (surfaces = 'Endpoint') count_by 'category' | group sum(count)
```

Aggregation happens in the storage layer, so the pipeline receives pre-grouped rows. After a
pushdown always fold with `sum(count)`, never `count()`. Anti-pattern:
`| datasource assets | group count() by category`, same answer, no pushdown.

Prune on the datasource line too:

```text
| datasource assets from 'workstation, server' ...          # subcategory prune
| datasource assets type 'surface/endpoint' ...             # type prune
| datasource vulnerabilities timestamp_field lastSeenAt ... # declares the time field
```

**`timestamp_field` matters more than it looks: without it the panel's `startTime`/`endTime` cannot
prune and the query degrades to a full-entity scan.** It does not compose with every option, e.g.
`datasource metering from <x> timestamp_field <y>` returns
`400 Unsupported params: [ from, timestamp_field ]`.

### Multi-series plus an overall total, in one query

```text
| union ( <source> | group v=sum(x) by bucket, entity ),
        ( <source> | group v=sum(x) by bucket | let entity = 'TOTAL' )
| group v=sum(v) by bucket, entity
| transpose entity
```

Gives one series per entity and a TOTAL line from a single scan.

### `datasource metering`: useful, with hard limits

`metering from xdr_ingested_bytes` returns per-source ingest volume in ~6 s where the equivalent
lake scan takes 5-18 s. Before reaching for it:

- it measures **bytes**, not event counts;
- granularity is **daily** only;
- it **lags several days**, measured 5 days behind, and a 24-hour window returns **zero rows**.

Good for long-range trend and cost panels. Useless for "is this feed dark now", and the zero-row
result for a recent window looks like a broken query rather than a stale datasource.

### Perceived speed is architecture, not raw query speed

Console panel latency is not sub-second: median launch ~1.3 s, p95 ~1.9 s across 111 launches in one
capture. The boards feel fast because every panel is an independent async job rendering progressively
from `stepsCompleted`/`totalSteps`, not because any single query is quick. Do not chase a sub-second
panel query.

One caveat on copying that fan-out: it works because those are ~1-2 s pre-aggregated entity queries.
Firing many concurrent multi-hundred-million-row *lake* scans measured **slower** than running them
sequentially, three concurrent 1-day slices took 334 s with two failures, against 213 s for a
single 3-day query.

### Always tear down abandoned jobs

Killing a client does not stop the query; it keeps consuming backend capacity and starves later
panels. The console calls `removeQuery` ~0.9 times per launch. Programmatically,
`DELETE /sdl/v2/api/queries/{id}` on every exit path that is not a completion.

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
