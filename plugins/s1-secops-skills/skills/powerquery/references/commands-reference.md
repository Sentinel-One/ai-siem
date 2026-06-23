# Commands reference

In-depth documentation for every PowerQuery command. Read before writing anything non-trivial that involves `join`, `transpose`, `compare`, `top`, or subqueries.

## Table of contents

1. `filter` — add conditions
2. `columns` — project / rename / compute
3. `let` — add computed fields without dropping existing ones
4. `group` — aggregate
5. `sort` — order rows
6. `limit` / `nolimit` — size the output
7. `parse` — extract fields from text
8. `lookup` / `dataset` / `savelookup` — data tables
9. `join` — correlate subqueries
10. `union` — stack subqueries
11. `transpose` — pivot a column wider
12. `compare` — timeshift comparison
13. `top` — probabilistic top-N
14. Subqueries (`field in (…)`)

---

## 1. `filter`

```
| filter expr
```

Keeps rows where `expr` evaluates truthy. The initial filter (everything before the first `|`) is implicit — you don't write `filter` for it. Use explicit `filter` later in the pipeline to prune based on computed or aggregated columns.

Only the initial filter supports `* contains` and `* matches`. After the first pipe, search operators must name a field.

```
event.login.loginIsSuccessful = false
| group ct = count() by event.login.userName
| filter ct > 5
| sort -ct
```

---

## 2. `columns`

```
| columns f1, f2                                    // select and order
| columns display = f1, "Pretty Name" = f2          // rename / quote for spaces
| columns ratio = success / (success + failure)     // compute
```

**Critical**: `columns` creates an entirely new record set. After `columns`, only the fields you listed are visible. Plan the carry-through.

Nice for ternary-based bucketing at the end of a pipeline:

```
| columns size_bucket = (tgt.file.size < 1_000_000) ? 'Small'
                      : (tgt.file.size < 5_000_000) ? 'Medium'
                      :                                'Large'
```

For unit conversion on timestamps (e.g., promoting a seconds column into PQ's nanosecond-timestamp convention so it renders as a date):

```
| columns create.timestamp = createSecs * 1_000_000_000
```

Any numeric field named `timestamp` or ending in `.timestamp` renders as an ISO datetime automatically.

---

## 3. `let`

```
| let f1 = expr, "f 2" = expr2, …
```

Adds computed fields. Unlike `columns`, `let` preserves the existing record — use it when you want to add a field without losing everything else.

Cannot overwrite a field that was produced by a preceding command; *can* overwrite a field that exists in the underlying event data.

```
src.process.name contains 'powershell' dst.ip.address = *
| let is_rfc1918 = net_rfc1918(dst.ip.address)
| filter is_rfc1918 = false
| columns endpoint.name, src.process.cmdline, dst.ip.address
```

---

## 4. `group`

```
| group agg(x), name2 = agg2(y)
| group agg(x) by f1, "Label" = f2
```

Without `by`, returns a single row (the aggregate over all input rows). With `by`, one row per distinct combination of the `by` expressions.

Like `columns`, `group` creates a new record set — fields not named in the `group` clause are unreachable afterward.

### Aggregate function cheat-sheet

| Function | What it does |
|---|---|
| `count()` | Count rows |
| `count(cond)` | Count rows where `cond` is truthy (no `where` keyword needed) |
| `sum(x)`, `avg(x)`, `mean(x)`, `average(x)`, `min(x)`, `max(x)` | Standard |
| `median(x)`, `p10 p50 p90 p95 p99 p999`, `pct(N, x)` | Percentiles |
| `stddev(x)` | Standard deviation |
| `estimate_distinct(x)` | HyperLogLog distinct count (~1-2% error; exact for small sets). Don't use `count(distinct …)` — PQ doesn't have it. |
| `array_agg(x[, max])`, `array_agg_distinct(x[, max])` | Collect values into an array (cap recommended; the row-byte limit is real) |
| `any(x)` | Arbitrary (usually first-seen) value; handy for carrying a representative field through an aggregation |
| `any_true(x)`, `all_true(x)` | Booleans |
| `first(x)`, `last(x)` | Require `sort` before `group` |
| `newest(x)`, `oldest(x)` | Based on event timestamp; **cannot be used after `group`, `sort`, or `limit`** |
| `min_by(x, y)`, `max_by(x, y)` | Value of `x` from the row with the smallest / largest `y` |

A `where` clause applies to the LAST argument of a multi-arg function, or the sole argument otherwise:

```
| group mean(tgt.file.size where tgt.file.path contains 'temp')
| group pct(90, tgt.file.size where tgt.file.path contains 'temp')
```

### Grouping by time

```
| group count() by timestamp = timebucket('1h')               // hourly buckets
| group count() by timestamp = timebucket(timestamp, '5m')    // explicit form
| group count() by timestamp = timebucket('1d'), endpoint.name
```

`timebucket(unit)` is shorthand for `timebucket(timestamp, unit)`. Units: `s m h d w` shortcuts, full words (`minutes` etc.), `auto`, or a count 1-500 that divides the query span.

---

## 5. `sort`

```
| sort expr                // ascending
| sort +expr               // explicit ascending
| sort -expr               // descending
| sort -ct, endpoint.name  // primary desc, tiebreak asc
```

If there's no `sort` after the last `group`, results are implicitly sorted ascending on the `by` keys.

---

## 6. `limit` / `nolimit`

```
| limit           // default 10 rows
| limit 250
| nolimit         // raise cap to 3 GB; one concurrent per tenant; never in Dashboards or Alerts
```

Without `limit` or `group`, outputs are capped at 1,000 rows. The `Show All` button in the UI is equivalent to adding `| limit 100000`.

`nolimit` is a global modifier (position-independent within the query). Queries above S-24.3.3 can use it in Singularity Operations Center. Running >1 `nolimit` query at once queues the second one until the first finishes.

---

## 7. `parse`

```
| parse "format with $field$ markers" from sourceField
| parse "$digits=digits$ seconds" from latencyStr
| parse ".*\\\\$filename{regex=[^\\\\]+}$$$" from tgt.file.path
```

Extracts fields from text. `$field$` is a placeholder; `{regex=…}` sets an explicit regex for the placeholder; `$$` at the end anchors to end-of-string; `=digits` / `=identifier` are shortcut extractors.

Performance note: most `parse` use cases are better solved by configuring a parser at ingest time. Reach for `parse` when exploring ad-hoc.

---

## 8. `lookup`, `dataset`, `savelookup`

Work with CSV / JSON lookup tables stored under Config Files (`/datatables/<name>`).

```
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
| `=:wildcard` | `%` = multi-char, `_` = single-char; in the data-table value |
| `=:cidr` | IPv4/IPv6 subnet membership; the data-table column is `1.2.3.0/24` style |

Limits: lookup table ≤ 400 KB, savelookup target ≤ 100,000 rows / 1.5 MB. `savelookup` doesn't support array values.

Best practices: defer the `lookup` until after a `group`, so the lookup is performed once per group row instead of once per raw event. Don't join dynamic lookups inside an Alert.

**Confirmed on-tenant (usea1-purple, 2026-06-01):**

- `from <table>` takes the **literal filename**. If the data table file is `sid_username.csv`, write `from sid_username.csv` (keep the extension). A bare name without the extension can miss the file. Both `/datatables/foo` and `/datatables/foo.csv` can coexist, so the name must be exact.
- `by` direction is `lookupColumn = eventField`. Left of the `=` is the lookup-table key column, right is the event field or expression. Example: `by sid = winEventLog.data.event.eventData.subjectUserSid`.
- `dataset 'config://datatables/<name>'` returned **0 rows** for a freshly written CSV on this tenant, both with and without the `.csv` suffix. Prefer `| lookup` to read or enrich a table. If you must dump a whole table via `dataset`, confirm it returns rows before relying on it.

**Tenant-wide enrichment without a command:** to apply a lookup automatically to every search and PowerQuery (no `| lookup` typed), use the `/automaticLookups` config file instead. See `references/automatic-lookups.md` for the schema, the "output value fields must be unique across all specs" rule, the 100-row / 5 MB / 50-column limits, and a full Windows Event Logs SID-to-username worked example.

---

## 9. `join`

```
| [inner|left|outer|sql inner|sql left|sql outer] join
    [a =] (query1),
    [b =] (query2), …
    [on key, a.x = b.y]
```

The initial `|` is mandatory — `join (…)` without a pipe is parsed as a search term. Optional names (`a =`) let you disambiguate identical field names.

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

- `on fieldName` — same name in both queries
- `on a.x = b.y` — different names, with query aliases
- `on x, y, a.z = b.w` — multiple keys; supports the `=` form per-key

Can't match fields within the same query (`a.x = a.z` is not a legal join key). If you nest joins, inner joins can't export dotted field names — rename with `columns` before the outer join sees them.

Performance: start with the most selective (smallest-cardinality) subquery. PQ evaluates left-to-right.

---

## 10. `union`

```
| union (query1), (query2), …                 // up to 10 queries
```

Stacks result sets as rows. Unlike SQL union, the queries can have different columns and different types — missing columns become null. Output has no sort order (add `sort` after).

Use to merge heterogeneous sources (e.g., `api_server` logs with fields `operation`/`elapsed_time` and `frontend` logs with `url`/`http_status`). Rename columns in each sub-query's `columns` to unify them:

```
| union
    (logfile = 'api_server' | columns operation, status = status_code),
    (logfile = 'frontend'    | columns url, status = http_status)
| group count() by status
```

For EDR/XDR data with a single schema, `filter (a OR b)` is usually simpler than `union`.

---

## 11. `transpose`

```
| transpose columnToPivot
| transpose columnToPivot on keyCol1, keyCol2
| transpose columnToPivot on keys with_totals
| transpose columnToPivot on keys limit N
```

Pivots a column into many columns — each distinct value becomes a column. Useful for "one column per category" reports and for plotting one series per entity on a line chart.

Rules:
- Must be the **last** command in the query.
- Cannot appear in a subquery.
- Max 100 new columns (most-frequent 100 win).
- `limit N` keeps only the top-N column values (by sum of the numeric row).
- `with_totals` adds a trailing total column summing across the pivoted columns.

Typical flow is `group … by <category>, <key>` then `transpose <category> on <key>`.

---

## 12. `compare`

```
| compare [name =] timeshift('[-|+]<timespan>')
| compare previous = timeshift('-1w')
| compare next_period = timeshift(+queryspan())
```

Runs the same query over a shifted time range and attaches those numeric columns (with the prefix `(<name>)`) alongside.

Rules:
- Must be the **last** command.
- Only one `timeshift` per query.
- Shifted query has the same time-range length as the original (4-hour query + `timeshift('-1d')` → the 4 hours ending 20 hours ago).
- `queryspan()` resolves to the length of the original range.

Pair with `sort` placed *before* `compare` if you want ordering on the primary result.

---

## 13. `top`

```
| top K [alias =] scoring(expr) by f1, f2
```

Probabilistic top-K. Scoring functions allowed: `count()` (estimated), `sum(x)` (estimated), `min(x)` (exact), `max(x)` (exact). Adds a synthetic `rank` column; estimated results append "(estimated)" to the column name.

Use when:
- The time range is very long (hours of `group` → minutes of `top`).
- `group` is hitting intermediate-row memory limits.
- You need a fast dashboard panel and can tolerate ~few-percent error on counts.

For exact values on top entities without paying for full aggregation:

```
| sql join
    (| top 4 s_est = sum(x) by endpoint),
    (| group s = sum(x) by endpoint)
    on endpoint
| columns endpoint, s
```

This finds exact `s` only for the top-4 endpoints, skipping the long tail.

Requires S-25.3.6+ and the Network Discovery add-on. Supported in Singularity Operations Center.

---

## 14. Subqueries — `field in (…)`

```
field in (filter_expr | commands_that_yield_field)
| outer_commands
```

Runs the inner query first, collects one column of values, and filters the outer query to rows where `field` is in that set.

Rules (enforce them — these are where subqueries go wrong):
- The inner query **must** produce a column named the same as `field`. Use `columns field` or `group 1 by field` or `top N count() by field`.
- The `in` subquery must appear **before** any `group`, `sort`, or `limit` in the outer query. After aggregation, the left side's value is computed — PQ can't push the filter in. Use `join` for post-aggregation correlation.
- The inner query and the outer query are independent filters. If you also want the outer rows to have a condition (e.g., severity 5), state it outside the subquery too — `threat_level = 5 user in (threat_level = 5 | top 3 count() by user)`.
- Empty inner result → empty outer result.

Good patterns:

```
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
```

Subqueries use bloom filters automatically when the inner yields > 5,000 unique values. Subqueries are NOT supported inside PowerQuery Alerts (the Summary service evaluates at ingest time and can't compute the inner).

### When to prefer `join`

Subqueries are for single-field membership. If a finding requires *row-level correlation* — "the same row must have `user=X` AND `cmdline=Y`" — use `join`. A subquery would treat those independently.
