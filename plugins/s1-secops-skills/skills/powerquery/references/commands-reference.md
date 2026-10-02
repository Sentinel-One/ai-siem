# Commands reference

In-depth documentation for every PowerQuery command. Read before writing anything non-trivial that involves `join`, `transpose`, `compare`, `top`, or subqueries.

## Table of contents

1. `filter`: add conditions
2. `columns`: project / rename / compute
3. `let`: add computed fields without dropping existing ones
4. `group`: aggregate
5. `sort`: order rows
6. `limit` / `nolimit`: size the output
7. `parse`: extract fields from text
8. `lookup` / `dataset` / `savelookup`: data tables
9. `join`: correlate subqueries
10. `union`: stack subqueries
11. `transpose`: pivot a column wider
12. `compare`: timeshift comparison
13. `top`: probabilistic top-N
14. Subqueries (`field in (…)`)

---

## 1. `filter`

```text
| filter expr
```

Keeps rows where `expr` evaluates truthy. The initial filter (everything before the first `|`) is implicit; you don't write `filter` for it. Use explicit `filter` later in the pipeline to prune based on computed or aggregated columns.

Only the initial filter supports `* contains` and `* matches`. After the first pipe, search operators must name a field.

```text
event.login.loginIsSuccessful = false
| group ct = count() by event.login.userName
| filter ct > 5
| sort -ct
```

---

## 2. `columns`

```text
| columns f1, f2                                    // select and order
| columns display = f1, "Pretty Name" = f2          // rename / quote for spaces
| columns ratio = success / (success + failure)     // compute
```

**Critical**: `columns` creates an entirely new record set. After `columns`, only the fields you listed are visible. Plan the carry-through.

Nice for ternary-based bucketing at the end of a pipeline:

```text
| columns size_bucket = (tgt.file.size < 1_000_000) ? 'Small'
                      : (tgt.file.size < 5_000_000) ? 'Medium'
                      :                                'Large'
```

For unit conversion on timestamps (e.g., promoting a seconds column into PQ's nanosecond-timestamp convention so it renders as a date):

```text
| columns create.timestamp = createSecs * 1_000_000_000
```

Any numeric field named `timestamp` or ending in `.timestamp` renders as an ISO datetime automatically.

---

## 3. `let`

```text
| let f1 = expr, "f 2" = expr2, …
```

Adds computed fields. Unlike `columns`, `let` preserves the existing record; use it when you want to add a field without losing everything else.

Cannot overwrite a field that was produced by a preceding command; *can* overwrite a field that exists in the underlying event data.

```text
src.process.name contains 'powershell' dst.ip.address = *
| let is_rfc1918 = net_rfc1918(dst.ip.address)
| filter is_rfc1918 = false
| columns endpoint.name, src.process.cmdline, dst.ip.address
```

---

## 4. `group`

```text
| group agg(x), name2 = agg2(y)
| group agg(x) by f1, "Label" = f2
```

Without `by`, returns a single row (the aggregate over all input rows). With `by`, one row per distinct combination of the `by` expressions.

Like `columns`, `group` creates a new record set, fields not named in the `group` clause are unreachable afterward.

### Aggregate function cheat-sheet

| Function | What it does |
|---|---|
| `count()` | Count rows |
| `count(cond)` | Count rows where `cond` is truthy (no `where` keyword needed) |
| `sum(x)`, `avg(x)`, `mean(x)`, `average(x)`, `min(x)`, `max(x)` | Standard |
| `median(x)`, `p10 p50 p90 p95 p99 p999`, `pct(N, x)` | Percentiles |
| `stddev(x)` | Standard deviation |
| `estimate_distinct(x)` | HyperLogLog distinct count (~1-2% error; exact for small sets). Don't use `count(distinct …)`, PQ doesn't have it. |
| `array_agg(x[, max])`, `array_agg_distinct(x[, max])` | Collect values into an array (cap recommended; the row-byte limit is real) |
| `any(x)` | Arbitrary (usually first-seen) value; handy for carrying a representative field through an aggregation |
| `any_true(x)`, `all_true(x)` | Booleans |
| `first(x)`, `last(x)` | Require `sort` before `group` |
| `newest(x)`, `oldest(x)` | Based on event timestamp; **cannot be used after `group`, `sort`, or `limit`** |
| `min_by(x, y)`, `max_by(x, y)` | Value of `x` from the row with the smallest / largest `y` |

A `where` clause applies to the LAST argument of a multi-arg function, or the sole argument otherwise:

```text
| group mean(tgt.file.size where tgt.file.path contains 'temp')
| group pct(90, tgt.file.size where tgt.file.path contains 'temp')
```

### Grouping by time

```text
| group count() by timestamp = timebucket('1h')               // hourly buckets
| group count() by timestamp = timebucket(timestamp, '5m')    // explicit form
| group count() by timestamp = timebucket('1d'), endpoint.name
```

`timebucket(unit)` is shorthand for `timebucket(timestamp, unit)`. Units: `s m h d w` shortcuts, full words (`minutes` etc.), `auto`, or a count 1-500 that divides the query span.

---

## 5. `sort`

```text
| sort expr                // ascending
| sort +expr               // explicit ascending
| sort -expr               // descending
| sort -ct, endpoint.name  // primary desc, tiebreak asc
```

If there's no `sort` after the last `group`, results are implicitly sorted ascending on the `by` keys.

---

## 6. `limit` / `nolimit`

```text
| limit           // default 10 rows
| limit 250
| nolimit         // raise cap to 3 GB; one concurrent per tenant; never in Dashboards or Alerts
```

Without `limit` or `group`, outputs are capped at 1,000 rows. The `Show All` button in the UI is equivalent to adding `| limit 100000`.

`nolimit` is a global modifier (position-independent within the query). Queries above S-24.3.3 can use it in Singularity Operations Center. Running >1 `nolimit` query at once queues the second one until the first finishes.

---

## 7. `parse`

```text
| parse "format with $field$ markers" from sourceField
| parse "$digits=digits$ seconds" from latencyStr
| parse ".*\\\\$filename{regex=[^\\\\]+}$$$" from tgt.file.path
```

Extracts fields from text. `$field$` is a placeholder; `{regex=…}` sets an explicit regex for the placeholder; `$$` at the end anchors to end-of-string; `=digits` / `=identifier` are shortcut extractors.

Performance note: most `parse` use cases are better solved by configuring a parser at ingest time. Reach for `parse` when exploring ad-hoc.

---

## 8. `lookup`, `dataset`, `savelookup`

Work with CSV / JSON lookup tables stored under Config Files (`/datatables/<name>`).

```text
| lookup osVersion from machineinfo by endpoint.name                                // join on equal names
| lookup osVersion, "Region" = region from machineinfo by endpoint.name = endpoint.name
| dataset 'config://datatables/machineinfo'                                         // use the lookup table as the pipeline source
| savelookup 'binary_outgoing_publicip'                                             // persist current results as a lookup
| savelookup 'events_per_agent', 'merge'                                            // merge into existing
```

Lookup operators:

| Operator | Meaning |
|---|---|
| `=` | Exact case-sensitive |
| `=:anycase` | Exact case-insensitive |
| `=:anyof` | Match across multiple columns (first matched condition wins) |
| `=:wildcard` | `%` = zero or more characters, `_` = exactly one; patterns are read only from the data-table value, and a `%` or `_` in the event value is matched literally |
| `=:cidr` | IPv4/IPv6 subnet membership; the data-table column is `1.2.3.0/24` style. When ranges overlap, the most specific prefix wins regardless of row order. An event value that is not an IP gives a null match with no error. A CIDR key can be combined with `=` keys in one `by` |

Limits: lookup / `savelookup` datatables can be up to 150 MB per table (operator-confirmed 2026-07-29; consistent with `detection-rules.md` and `datasource-command.md`). `savelookup` doesn't support array values.

Best practices: defer the `lookup` until after a `group`, so the lookup is performed once per group row instead of once per raw event. Don't join dynamic lookups inside an Alert.

**Confirmed on-tenant (<console>, 2026-06-01):**

- `from <table>` takes the **literal filename**. If the data table file is `sid_username.csv`, write `from sid_username.csv` (keep the extension). A bare name without the extension can miss the file. Both `/datatables/foo` and `/datatables/foo.csv` can coexist, so the name must be exact.
- **`from <table>` resolves under `/datatables/` only, never `/lookups/`.** A CSV written to `/lookups/<name>.csv` is a real config file that reads back fine over the API, but `| lookup ... from <name>.csv` returns HTTP 400 `Lookup table "<name>.csv" does not exist`. Put lookup tables in `/datatables/` (live-confirmed 2026-08-07).
- **Hyphenated table names work unquoted.** `| lookup v from my-table.csv by k = k` resolves the table (live-verified 2026-10, regression case `lk-hyphen-table-name-unquoted`); quoting (`from 'my-table.csv'`) is also accepted. In `| dataset` the path is always quoted: `| dataset 'config://datatables/my-table.csv'`.
- `by` direction is `lookupColumn = eventField`. Left of the `=` is the lookup-table key column, right is the event field or expression. Example: `by sid = winEventLog.data.event.eventData.subjectUserSid`. The same holds for `=:wildcard` and `=:cidr`; reversed, the query fails with HTTP 400 `Column "<field>" not found in table` (regression case `lk-by-table-column-on-left`).
- **Duplicate keys do not fan out.** When the table has several rows for one key, `lookup` returns the first row in file order and the event count is unchanged (regression cases `lk-dup-key-first-row-wins`, `lk-dup-key-no-row-fanout`). Deduplicate the table, or put the preferred row first.
- **`| dataset` output is an ordinary result set**: `filter`, `sort` (before or after `columns`), `limit`, `group` and `lookup` all work on it, and the path may be single- or double-quoted (regression case `lk-dataset-pipeline-commands`). `| group n=count()` over an empty table returns **no row**, not a row with 0, so treat "no row" as zero (regression case `lk-empty-table-count-no-row`).
- **`savelookup` storage format** follows the name: `savelookup 'name'` writes JSON (`{"columnNames": [...], "rows": [[...]]}`, numbers stay numbers), `savelookup 'name.csv'` writes CSV with a header row. Either way the command returns one summary row (name, columns, rows, bytes). Literal rows need no event source: `| union ( | limit 1 | columns k='a', v=1 ), ( | limit 1 | columns k='b', v=2 ) | savelookup 'name'` (live-verified 2026-10).
- `| dataset 'config://datatables/<name>'` reads a saved lookup table as the pipeline source. The leading `|` is required; without it the text is parsed as an initial filter and returns 0 rows.

**Tenant-wide enrichment without a command:** to apply a lookup automatically to every search and PowerQuery (no `| lookup` typed), use the `/automaticLookups` config file instead. See `references/automatic-lookups.md` for the schema, the "output value fields must be unique across all specs" rule, the write-time limits (200 rows, 1 MB per table, 5 MB total, 10 output fields per spec, 50 total), and a full Windows Event Logs SID-to-username worked example.

---

## 9. `join`

```text
| [inner|left|outer|sql inner|sql left|sql outer] join
    [a =] (query1),
    [b =] (query2), …
    [on key, a.x = b.y]
```

The initial `|` is mandatory, `join (…)` without a pipe is parsed as a search term. Optional names (`a =`) let you disambiguate identical field names.

Match semantics:

| Join type | Semantics | Limits |
|---|---|---|
| `inner` (default) | Left rows + first matching right row. Drop unmatched left. Null allowed as match. | Up to 10 subqueries |
| `left` | All left rows + first matching right row (null if no match). | Up to 10 subqueries |
| `outer` | All rows from both, first-match right. | Up to 10 subqueries |
| `sql inner` | All matching pairs from right (true inner join). | Exactly 2 subqueries |
| `sql left` | All left rows + all matching right rows. | Exactly 2 subqueries |
| `sql outer` | Full outer join: all rows from both, all matches. | Exactly 2 subqueries |

`on` sets the keys. Without `on`, the first row of the left is joined with the first row of the right (usually not what you want).

- `on fieldName`: same name in both queries
- `on a.x = b.y`: different names, with query aliases
- `on x, y, a.z = b.w`: multiple keys; supports the `=` form per-key

Can't match fields within the same query (`a.x = a.z` is not a legal join key). If you nest joins, inner joins can't export dotted field names, rename with `columns` before the outer join sees them.

Performance: start with the most selective (smallest-cardinality) subquery. PQ evaluates left-to-right.

---

## 10. `union`

```text
| union (query1), (query2), …                 // comma-separated branches in ONE union
```

Stacks result sets as rows. Unlike SQL union, the queries can have different columns and different types, missing columns become null. Output has no sort order (add `sort` after).

A `union` takes at most **10 subqueries**; more than 10 returns HTTP 400. Write it as a leading command, `| union (q1),(q2),...`, at the start of the query. A subquery may synthesise rows, e.g. `( | limit 1 | columns a=2, b='bar' )`, which is how you build literal rows for a `savelookup`. Do not precede `union` with a main pipeline ending in `| limit` (e.g. `<filter> | limit 1 | union (...)`); that returns HTTP 400 at any branch count. To combine more than 10 subqueries, nest: `| union ( | union (b1),...,(b10) | columns ... ), ( | union (b11),... | columns ... )`, keeping each inner union at 10 or fewer. When branches differ only by a matched literal, prefer a single scan with a `let` plus a ternary over a wide union.

Use to merge heterogeneous sources (e.g., `api_server` logs with fields `operation`/`elapsed_time` and `frontend` logs with `url`/`http_status`). Rename columns in each sub-query's `columns` to unify them:

```text
| union
    (logfile = 'api_server' | columns operation, status = status_code),
    (logfile = 'frontend'    | columns url, status = http_status)
| group count() by status
```

For EDR/XDR data with a single schema, `filter (a OR b)` is usually simpler than `union`.

---

## 11. `transpose`

```text
| transpose columnToPivot
| transpose columnToPivot on keyCol1, keyCol2
| transpose columnToPivot on keys with_totals
| transpose columnToPivot on keys limit N
```

Pivots a column into many columns, each distinct value becomes a column. Useful for "one column per category" reports and for plotting one series per entity on a line chart.

Rules:

- Must be the **last** command in the query.
- Cannot appear in a subquery.
- Max 100 new columns (most-frequent 100 win).
- `limit N` keeps only the top-N column values (by sum of the numeric row).
- `with_totals` adds a trailing total column summing across the pivoted columns.

Typical flow is `group … by <category>, <key>` then `transpose <category> on <key>`.

---

## 12. `compare`

```text
| compare [name =] timeshift('[-|+]<timespan>')
| compare previous = timeshift('-1w')
| compare next_period = timeshift(+queryspan())
```

Runs the same query over a shifted time range and attaches those numeric columns alongside, each named `<column> (<name>)`: `| group n=count() | compare prev=timeshift('-1h')` returns columns `n` and `n (prev)` (regression case `compare-column-suffix`).

Rules:

- Must be the **last** command.
- Only one `timeshift` per query.
- Shifted query has the same time-range length as the original (4-hour query + `timeshift('-1d')` → the 4 hours ending 20 hours ago).
- `queryspan()` resolves to the length of the original range.
- An unsigned span shifts **backward**: `timeshift('1h')` returns the same shifted values as `timeshift('-1h')` (regression case `compare-unsigned-shift-goes-back`). Write the sign explicitly so the intent is readable.

Pair with `sort` placed *before* `compare` if you want ordering on the primary result.

---

## 13. `top`

```text
| top K [alias =] scoring(expr) by f1, f2
```

Probabilistic top-K. Scoring functions allowed: `count()` (estimated), `sum(x)` (estimated), `min(x)` (exact), `max(x)` (exact). Adds a synthetic `rank` column; estimated results append "(estimated)" to the column name.

Limits (live-verified 2026-10, regression cases `top-*`):

- Only those four scorers. `top 5 p95(x) by k` or `top 5 estimate_distinct(x) by k` is HTTP 400 `top command only supports count/min/max/sum functions`.
- `rank` is reserved: a field already named `rank` (e.g. from `let`) makes `top` fail with HTTP 400 `'rank' is reserved for top K command results`.
- `top` is a valid subquery inner: `src.process.name in (event.type='Process Creation' | top 3 count() by src.process.name)` filters the outer query to the top 3 keys.

Use when:

- The time range is very long (hours of `group` → minutes of `top`).
- `group` is hitting intermediate-row memory limits.
- You need a fast dashboard panel and can tolerate ~few-percent error on counts.

For exact values on top entities without paying for full aggregation:

```text
| sql join
    (| top 4 s_est = sum(x) by endpoint),
    (| group s = sum(x) by endpoint)
    on endpoint
| columns endpoint, s
```

This finds exact `s` only for the top-4 endpoints, skipping the long tail.

Requires S-25.3.6+ and the Network Discovery add-on. Supported in Singularity Operations Center.

---

## 14. Subqueries: `field in (…)`

```text
field in (filter_expr | commands_that_yield_field)
| outer_commands
```

Runs the inner query first, collects one column of values, and filters the outer query to rows where `field` is in that set. Every rule below is pinned by a case in `tests/live/pq_live_cases.json` (ids `sq-*`); run `tools/pq_live_regression.py` to re-verify.

Rules (enforce them; these are where subqueries go wrong):

- The inner query **must** produce a column named the same as `field`. Use `group 1 by field` (deduplicated, cheapest), `top N count() by field`, or `columns field`. A missing or misnamed column is HTTP 400 `Explicit column(s) '<field>' must be defined for subquery, via columns or group command`.
- The inner column can be an **alias**, which is how you match one field against values of another: `src.process.name in (tgt.process.name='svchost.exe' | group 1 by src.process.name=tgt.process.name)`.
- The subquery must appear **before** any `group`, `sort`, or `limit` in the outer query (HTTP 400 `subqueries can't be used after group, sort, or limit`). The restriction is on the outer pipeline only: the inner may use `sort`, `limit` and `top` freely. `| filter field in (...)` is fine mid-pipeline as long as no `group`/`sort`/`limit` precedes it.
- **Subquery only raw, indexed fields.** The filter is applied to the stored field at scan time, whatever its position in the text. On a field created by `let` it matches nothing (0 rows, HTTP 200, no error). On a field overwritten by `let` it tests the original stored value, not the new one. For computed values use a literal `in (...)` list or a `join`.
- The inner query and the outer query are independent filters. If you also want the outer rows to have a condition (e.g., severity 5), state it outside the subquery too, `threat_level = 5 user in (threat_level = 5 | top 3 count() by user)`.
- **Empty inner:** the positive form returns nothing; the negated form `!(x in (<empty>))` returns **every** row. An allowlist subquery whose datatable is empty or whose inner filter is wrong silently excludes nothing, so check the inner returns rows before trusting a "nothing excluded" result.
- **Nulls:** `x in (subquery)` never matches an absent or null `x`, even when the inner itself yields a null key. `!(x in (subquery))` therefore keeps rows where `x` is absent; add `x=*` if those should be dropped. `join` does match null keys, so a subquery and a join are **not** equivalent when the key can be null.
- **Case-sensitive**, like the literal `in`. Use `field in:anycase (subquery)` when the inner values (often a hand-maintained datatable) differ in case from the telemetry.
- **One literal field on the left.** `any(a, b) in (subquery)` is HTTP 400 `Subquery requires a literal field name` (regression case `sq-any-on-left-rejected`); write one subquery per field and combine them with `OR`. To match two fields *together*, see "Matching two fields together" below.
- Literal rows make a self-contained inner, handy for tests and fixed lists that still need subquery semantics: `src.process.name in (| limit 1 | columns src.process.name='svchost.exe')`.

Good patterns:

```text
// Users who logged in AND ran processes
user in (action='login' | group 1 by user)
AND user in (action='process_start' | group 1 by user)
| group count() by user

// Exclude service accounts
!(user in (role='service_account' | group 1 by user))
AND threat_level > 2
| group count() by user

// Nested: events from users in departments that had security incidents
user in (
  department in (alert_type='security_incident' | group 1 by department)
  | group 1 by user
)
| group count() by action

// Top-N then pivot: only the 3 noisiest binaries
src.process.name in (event.type='Process Creation' | top 3 count() by src.process.name)
| group n=count() by src.process.name
```

A subquery also works inside a `join` branch (regression case `sq-inside-join-branch`).

**Cardinality and cost.** Inners above 5,000 unique values switch to a bloom filter automatically. An inner of roughly 9,000 unique values returned exactly the same count as a plain presence filter over the same events (regression case `sq-high-cardinality-exact`), so a large inner is not truncated. An inner `| columns` is not subject to the 1,000-row no-`group` output cap. The inner is its own scan, and LRQ `matchCount` on a subquery query **includes the inner scan** (the inner plus the outer matches), so `matchCount > 0` with 0 rows does not prove the outer matched anything. Keep the inner tightly filtered. Subqueries share the outer query's time range. Subqueries are NOT supported inside PowerQuery Alerts (the Summary service evaluates at ingest time and can't compute the inner).

### Matching two fields together (allowlisting pairs)

Two single-field subqueries are **independent**: `!(user in (<list> | group 1 by user)) !(cmd in (<list> | group 1 by cmd))` excludes a row when its `user` appears *anywhere* in the list and its `cmd` appears *anywhere* in the list, so cross pairs that were never allowlisted get excluded too. Measured: with two allowlisted (event type, process) pairs, two negated single-field subqueries excluded every one of the four combinations, while the OR-of-ANDs form below kept the cross pairs (regression cases `sq-independent-fields-cross-product`, `or-of-ands-keeps-cross-pairs`).

For a short, fixed list of pairs, write the OR of ANDs explicitly:

```text
event.type in ('Process Creation','File Creation')
!((event.type='Process Creation' && src.process.name='svchost.exe')
  || (event.type='File Creation' && src.process.name='explorer.exe'))
| group n=count() by event.type, src.process.name
```

For a list that lives in a datatable or comes from another query, correlate on both keys with `join` (§9).
