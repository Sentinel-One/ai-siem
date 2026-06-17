# Pitfalls and fixes

Curated failure modes. When a PowerQuery is misbehaving, check this list before reaching for exotic explanations.

## Syntax / grammar

### `*` alone as a filter returns 500

```
*                           ← NOT a valid initial filter — HTTP 500 ("Don't understand [*]")
* | limit 5                 ← same
```

There are three distinct `*` idioms in PowerQuery. They look similar but mean different things:

**1. Field presence / attribute wildcard: `field=*`**

Means "field is present and non-null". Use as a query-opener when you want all events that have a given field, or as the starting predicate for aggregations. Confirmed working on live tenant.

```
dataSource.name=* | group count=count() by dataSource.name | sort -count | limit 10
event.type=* | limit 5
```

This is NOT an all-column text search — it checks whether a specific attribute is present.

**2. All-column text search: `* contains 'value'` or `* matches 'regex'`**

Searches ALL indexed fields across the event. Use when you need to find a specific string anywhere in the event — what users describe as "search all logs for X", "all column search", "find this text anywhere". Only valid as the **initial filter** (before the first `|`). Not valid in `| filter …` after a pipe, and not valid in Alerts.

```
dataSource.name='MySource' * contains 'evil.com'      // string in any field on a source
* contains 'suspicious_domain.com' | limit 50          // all sources, any field
* matches '\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}' | limit 20  // IP pattern anywhere
```

Much faster than `message contains 'value'` because it scans indexed fields, not a raw blob.

**3. Empty initial filter: start with `|`**

Use when you want all events with no initial predicate.

```
| limit 5                   // "all events, first 5"
| group ct=count() by event.type
```

### SQL-style `sort` direction keywords cause parse error (HTTP 500)

PowerQuery uses `-`/`+` prefix for sort direction. `desc` and `asc` are not valid keywords and cause the LRQ API to return HTTP 500 "Unable to parse the entire query".

```
| sort count desc          ← HTTP 500 — "desc" is not valid PowerQuery syntax
| sort timestamp asc       ← HTTP 500 — "asc" is not valid PowerQuery syntax
```

Fix: use `-` for descending, `+` for ascending (ascending is also the default when no prefix is given).

```
| sort -count
| sort +timestamp
| sort -hits, +endpoint.name
```

**This applies to Purple AI generated queries too.** Purple AI frequently produces `sort field desc` — always correct it to `sort -field` before running via the LRQ API or `powerquery_run`.

### `join` without a leading pipe

```
join (q1), (q2) on x         ← "join" is interpreted as a search keyword
```

Fix: `| join (q1), (q2) on x`. The same rule applies to `union`.

### `compare` or `transpose` not last

```
| compare last_week = timeshift('1w')
| sort -count                ← too late; compare must be LAST
```

Fix: move `sort` before `compare`. The display ordering is applied to the main results; the shifted column sits alongside.

### Subquery after `group` / `sort` / `limit`

```
| group count() by user
| filter user in (role='admin' | columns user)     ← invalid
```

Fix: move the subquery into the initial filter position.

```
user in (role='admin' | columns user)
| group count() by user
```

### Subquery doesn't define the filter column

```
user in (action='login')                                                     ← fails
user in (action='login' | group count() by ip)                               ← fails ("user" column not produced)
```

Fix: produce the column.

```
user in (action='login' | columns user)
user in (action='login' | group 1 by user)
user in (action='login' | top 10 count() by user)
```

### Shortcut fields as initial filter return 500

```
#cmdline contains 'python'              ← 500 on many tenants
#name = 'bash'                           ← 500
#hash = *                                ← 500
```

The docs list `#cmdline`, `#name`, `#hash`, `#ip`, `#storylineid`, `#username`, `#dns` as multi-field shortcuts. In practice, they're unreliable across tenants — in this deployment they all return 500 as initial filters. Fix: use the explicit field.

```
src.process.cmdline contains 'python'
src.process.name = 'bash'
tgt.file.sha256 = *
```

The explicit form is only a few characters longer and always works. Save shortcuts for interactive Event Search, not scripted queries.

### `parse` with the wrong argument order

```
| parse src.process.cmdline, "$bin$ $args$"       ← 500
```

Fix: the source goes at the end with `from`.

```
| parse "$bin$ $args$" from src.process.cmdline
```

### `timebucket` in `group by` without an alias — "undefined field 'timebucket'"

```
| group count=count() by timebucket('1h')     ← 500 "undefined field 'timebucket'"
```

Without an alias, PQ treats the bare name `timebucket` as a field lookup rather than a function call. Fix: always assign an alias in `group by` when using functions as keys.

```
| group count=count() by bucket=timebucket('1h') | sort +bucket
```

Same rule applies to any function used as a group key — `lower(field)`, `net_url_path(url)`, `strftime(ts, '%Y-%m-%d')`, etc. If no alias is assigned, the function name is interpreted as a field identifier.

### Non-existent functions: `formatdate`, `floor_time`, and similar

These function names do not exist in PowerQuery and return `Unknown function '<name>'`:

| Invalid | Valid replacement |
|---|---|
| `formatdate(ts)` | `strftime(ts)` or `simpledateformat(ts)` |
| `formatdate(ts, pattern)` | `strftime(ts, pattern)` |
| `formattime(ts)` | `strftime(ts)` or `simpledateformat(ts)` |
| `formattime(ts, pattern)` | `strftime(ts, pattern)` |
| `floor_time(ts, unit)` | `bucket=timebucket(unit)` in `group by` |
| `date_trunc(...)` | `timebucket(unit)` |
| `coalesce(a, b)` | bare-field ternary: `a ? a : b` (see coalesce pitfall above) |
| `ifnull(a, b)` | same |
| `if(cond, a, b)` in aggregates | `count(predicate)` or ternary in `let` |
| `percentile(x, N)` | `p50(x)` / `p95(x)` / `p99(x)` |

The valid date/time functions are: `strftime`, `simpledateformat`, `strptime`, `simpledateparse`, `timebucket`, `querystart`, `queryend`, `queryspan`. If you need a date function and aren't sure of the name, check `functions-reference.md §9` before writing the query.

### `first(x)` / `last(x)` / `percentile(x, N)` return 500

Some docs list these as aggregate functions, but they fail on many tenants. Use the reliable forms instead:

- `first(x)` → `min_by(x, timestamp)`
- `last(x)` → `max_by(x, timestamp)`
- `percentile(x, 0.95)` → `p95(x)` (also `p50`, `p99`)

### Ternary parsed as an identifier

```
cond?x:y                     ← ":" may be glued into an identifier
```

Fix: spaces around the `:`.

```
cond ? x : y
```

### `(field = *) ? a : b` inside `let` returns 500

PQ has no `coalesce()`. The intuitive way to fall back across multiple
fields breaks because `field = *` is a filter operator, not a boolean
expression usable in a computed column.

```
| let user_id = (actor.user.email_addr = *) ? actor.user.email_addr
                                            : actor.user.name        ← HTTP 500
```

Fix — bare-field truthy test (the field's null-or-truthy value drives the
ternary directly):

```
| let user_id = actor.user.email_addr
              ? actor.user.email_addr
              : (actor.user.name ? actor.user.name : src.process.user)
```

This is the working coalesce idiom. Chain ternaries to fall back across
N fields. Use the same pattern any time you'd reach for `coalesce` /
`ifnull` / `nvl` in SQL.

### `sum(if(...))` for conditional counts — use `count(predicate)` instead

```
| group critical = sum(if(severity_ in:anycase ('Critical'), 1, 0)) by host    ← invalid
```

PowerQuery does not accept `if(...)` as an aggregate body. The right idiom is
to pass a predicate directly to `count()`:

```
| group critical = count(severity_id == 5),
        high     = count(severity_id == 4),
        medium   = count(severity_id == 3),
        total    = count() by host
```

`count(<predicate>)` evaluates the predicate per row and sums the truthy ones.
Works for any boolean expression, including `in:anycase`, `contains`,
`matches`, and arithmetic comparisons.

### `severity_` (and other trailing-underscore fields) — SDL reserved-field rewrite

When a parser ingests source data carrying a field name that collides with an
SDL reserved name (`severity`, `status`, `classification`, `category`, etc.),
the field is automatically renamed by appending `_`. The underscored form
`severity_` IS the canonical, queryable field — not a sparse alternate to
`severity`.

There is no non-underscored `severity` field on alert / vulnerability /
misconfiguration / asset / Identity sources. Don't go looking for one. Same
rule applies to `status_`, `classification_`, `category_`, and any other
trailing-underscore field name encountered in raw events. The numeric OCSF
variants (`severity_id` 0-5, `status_id`, `class_uid`) live alongside the
underscored string fields and are usually the better choice for filters.

### `severity_` carries mixed casing — `transpose` produces 8 columns instead of 4

Same source pipeline, different upstream casing — values like `Critical`,
`CRITICAL`, `High`, `HIGH`, `Medium`, `MEDIUM`, `Low`, `LOW` co-exist in the
same `severity_` column.

```
| group count() by timestamp = timebucket('1h'), severity_
| transpose severity_ on timestamp                 ← produces 8 columns
```

Fix — normalise before grouping:

```
| let sev = lowercase(severity_)
| group count() by timestamp = timebucket('1h'), sev
| transpose sev on timestamp                       ← 4 clean columns
```

Or skip the string field entirely and use the numeric OCSF `severity_id` for
filters:

```
severity_id >= 4
| group count() by timestamp = timebucket('1h'), severity_id
| transpose severity_id on timestamp               ← columns are 4, 5
```

### Numeric counters indexed as string — column-type lock — wrap in `number()` as a failsafe

SDL/Scalyr indexes columns at first-write and locks the type. Once a numeric
field has been written as string (because a parser declared `type: "string"` or
the source data has been ingested untyped), the column stays string forever.
Subsequent writes — even from a parser declaring `type: "long"` — get coerced
back to string at index time. Numeric aggregation then breaks silently:

```
dataSource.name='FortiGate' unmapped.action='close'
| group sessions=count(), bytes_out=sum(traffic.bytes_out)         ← NaN, even though values are populated
| limit 1
```

The values ARE there (you can see them in Event Search), but `sum()` /
`avg()` / `max()` / `>=` predicates can't operate on a string-typed column.

**Failsafe pattern — cast at query time with `number()`:**

```
dataSource.name='FortiGate' unmapped.action='close'
| let bytes_out_n = number(traffic.bytes_out)
| let bytes_in_n  = number(traffic.bytes_in)
| group sessions=count(),
        bytes_out=sum(bytes_out_n),
        bytes_in=sum(bytes_in_n),
        max_session_bytes_out=max(bytes_out_n) | limit 1
```

`number(x)` returns 0 for null/missing and NaN for unparseable strings, so the
defensive cast is cheap and never breaks already-numeric data. Apply it
preemptively to:

| Field family | Why |
|---|---|
| `severity_id`, `status_id`, `class_uid`, `type_uid`, `category_uid` | OCSF numerics, but column-type can drift between tenants |
| `traffic.bytes_in`, `traffic.bytes_out`, `traffic.packets_in`, `traffic.packets_out`, `unmapped.duration` | FortiGate marketplace parser declared these as `string` for many tenant generations — string column lock is widespread |
| Any vendor field carrying counts or sizes | If a parser ever wrote a non-numeric token (`"-"`, `"unknown"`, blank), the column is locked string |

Same trick works for arithmetic comparisons and sorts:

```
| let sev = number(severity_id)
| filter sev >= 4
| group n=count() by sev
| sort sev
```

The previous tenant-specific workaround using `parse "$x{regex=\\d+}$"` still
works and is slightly more robust against fields like `"42 KB"` (where you
want the digits, not a NaN), but `number()` is shorter and is the
recommended default for OCSF counter fields.

### Bracket array indexing in `columns` returns HTTP 500

```
dataSource.name='alert'
| columns severity_id, resources[0].name, vulnerabilities[0].cve.uid     ← HTTP 500
```

PowerQuery does not accept `[N]` array indexing in `columns`. The V1 `query`
API (used for schema discovery) flattens nested arrays into display keys like
`resources[0].name` — those flattened keys are NOT valid PowerQuery field
paths.

Fix — for first-element access inside a query, use `array_get` in a `let`:

```
| let first_resource = array_get(resources, 0)
| let first_resource_name = first_resource.name
```

For analytics over array fields, prefer top-level scalar fields
(`severity_id`, `finding_info.title`, `metadata.product.name`, `class_name`),
or step out of PowerQuery to the V1 query API which exposes the full event
JSON.

## Escaping

### Regex backslashes eaten

```
src.process.cmdline matches "\d+"         ← only one level of escaping; often matches nothing
```

Fix: double-escape everywhere except the `$"…"` shorthand.

```
src.process.cmdline matches "\\d+"
```

Windows paths — four-ish backslashes for a literal `\`:

```
tgt.file.path matches '^C:\\\\Windows\\\\Temp\\\\[a-z]{8}\\.tmp$'
```

### Case sensitivity flip

- `contains` and `matches` default to **case-insensitive**. `contains:matchcase`, `matches:matchcase` to make them case-sensitive.
- `in` and `=` (for strings) default to **case-sensitive**. `in:anycase` to make `in` case-insensitive.

If a query "misses" something you can see in the data, check whether case was the issue. `lower(field) contains 'x'` is a pragmatic workaround when the field isn't suited to `contains:matchcase`.

## Logic

### Null fields

- `field = *` → field is present (non-null).
- `!(field = *)` → field is null / missing.
- `field = null` — only valid as a boolean test *after* the field has been computed by a preceding command (e.g., a left join or a `let`).
- `in (…)` cannot match null. If null should count as a match, use `OR !(field = *)`.

### `count(x)` doesn't count nulls; does count zero / false

`count()` counts rows. `count(expr)` counts rows where `expr` is truthy. Zero, `false`, and empty string are falsy — they DON'T count. But null is also falsy, so this matches intuition.

If you want "count of rows where `login_success = false`", write `count(login_success = false)`, not `count(login_success) - count(login_success = true)`.

### `if x = y and z = w` short-circuits — but so does `or`

`||` returns the first truthy *value*, not a boolean. `a || b` with `a = "0"` returns `"0"` (non-empty string, truthy), not a boolean `true`. If you want boolean behavior, wrap with `bool(…)`.

### `newest()` / `oldest()` after `sort` fails silently

These functions require the original timestamp ordering of events. If you `sort` (or `group`, or `limit`) before using them, they produce null or wrong results. Use them in the same `group` as the aggregation — don't aggregate in two stages.

## Performance / memory

### "Memory limits" message

```
213,408 of 37,059,484 matching events (0.576%) were omitted due to memory limits.
```

Intermediate `group` table hit 100,000 rows. Fixes in order of preference:

1. Tighten the initial filter.
2. Group on a lower-cardinality field (group by `host` instead of `(host, cmdline)`, or `net_url_path(url)` instead of full URL).
3. Pre-filter with `| filter … | group 1 by key` as a subquery to prune before the heavy group.
4. Switch to `| top K` (probabilistic).

If all else fails and you need exact numbers over a long range, `| nolimit` — but this is slow and serializes across the tenant.

### Long time range timing out

The query timeout is 5 minutes. If a 30-day query times out:

- Narrow the initial filter (almost always the biggest lever).
- Use `top` instead of `group`.
- Consider running the query over 7-day chunks and `savelookup`-ing each, then `union`-ing.

### Reaching for `message contains` on a JSON-blob source

Some data sources (O365 audit, generic webhook ingest, custom HEC sources) keep most fields inside a raw JSON `message` blob rather than as parsed top-level columns. The first instinct is to write `message contains 'value'`, but that forces a substring scan of the entire blob and falls off a performance cliff fast: queries that work at 1 day routinely time out at 7.

Fix: use the multi-field shortcut `* contains 'value'` (or `* matches 'regex'`) in the initial filter. It searches across all indexed fields, including parsed scalars from the source, and is dramatically faster than scanning a single concatenated blob.

```
// slow — single-column substring scan
dataSource.name='<source>' message contains 'value'

// fast — multi-field index search
dataSource.name='<source>' * contains 'value'
```

Same rule applies to value-anywhere lookups regardless of the source: when a user asks for "all column search", "search all fields", "search all data", or "anywhere in the event", the canonical idiom is `* contains` / `* matches` in the initial filter, not `message contains`.

Three caveats worth remembering:

- `* contains` / `* matches` only work in the **initial** filter — before the first `|`. They cannot be used in `| filter …` after a pipe, in Alerts, or after a `| group` / `| columns` that has reshaped the row.
- If the value really only lives inside a JSON blob (e.g., a deeply nested key not exposed as a parsed field), neither `* contains` nor `message contains` will surface it efficiently. Pull rows with a narrower predicate (event type, actor, time slice) and post-process the blob in Python.
- Negation against a JSON blob (e.g., "recipients NOT in `<owned_domain>`") is not expressible inline. Filter by the positive predicate, then post-process to apply the exclusion.

### High-cardinality `by`

Grouping by full URL or full command line yields one row per variant — useless for summaries and likely to hit memory limits. Prefer:

- URL path instead of full URL (`net_url_path(url.address)`).
- `src.process.name` instead of `src.process.cmdline`.
- `src.process.storyline.id` as a "session" key that groups related process lineage.

### `lookup` before `group`

A `lookup` before a `group` is evaluated per-event. Once per-group is always cheaper:

```
// ← slower
| lookup os_version from machineinfo by endpoint.name
| group count() by endpoint.name, os_version

// ← faster
| group count() by endpoint.name
| lookup os_version from machineinfo by endpoint.name
```

### `lookup` table name and `by` direction

Two ways this silently returns nothing:

- The table name in `from <table>` is the **literal filename including any extension**. If the file is `/datatables/sid_username.csv`, use `from sid_username.csv`, not `from sid_username`.
- The `by` clause is `lookupColumn = eventField` (lookup-table key column on the left, event field/expression on the right): `by sid = winEventLog.data.event.eventData.subjectUserSid`.

### `dataset 'config://datatables/...'` returns 0 rows

Reading a CSV as a pipeline source via `dataset 'config://datatables/<name>'` returned **0 rows** on a tested tenant, both with and without the `.csv` suffix, even though the table existed and `| lookup` against it worked. Prefer `| lookup` to read or enrich a data table. If you specifically need `dataset`, verify it returns rows before building on it.

### Automatic lookup deploy fails: "Output value fields are not unique"

When editing `/automaticLookups`, every output value field name must be unique across ALL `lookupSpecs`. Two specs writing the same output field (even keyed on different event fields) returns HTTP 400 `Output value fields are not unique`. Rename the outputs or consolidate to one spec. See `references/automatic-lookups.md`.

## LRQ / engine functions

### `powerquery_run` time parameters — silent fallback to full-history scan

The `powerquery_run` MCP tool exposes two time-scoping parameters:

| Parameter | Valid format | Example |
|---|---|---|
| `hours` | Positive number (decimal ok) | `hours=1`, `hours=0.5` |
| `startTime` / `endTime` | ISO-8601 UTC string | `startTime="2026-05-26T13:00:00Z"` |

**Critical:** an invalid value is silently ignored — the tool does NOT raise an error. It defaults to the last 24 hours or longer. This means:

- `startTime="10 min"` — not ISO-8601, silently ignored → full history scan
- `start_time="10m"` — wrong parameter name, silently ignored → full history scan
- `hours=0.17` — valid (≈ 10 minutes), correctly scoped

When a bare `| group count()` with no `timebucket` dimension runs against a silently-expanded window, it aggregates across ALL SDL history for that source — not just the intended window. The result looks plausible (a single number) but can be off by orders of magnitude.

**Failsafe for time-bounded aggregations:** add `by timebucket(timestamp, "<window>")` to force the engine to partition by time. Then `| sort -total | limit 1` returns only the most recent bucket:

```
dataSource.name='MySource'
| group total=count(), field_a=count(some.field)
        by timebucket(timestamp, "10m")
| sort -total
| limit 1
```

Run with `hours=1` so the scan window covers at least one complete 10-minute bucket. This enforces the time window at the query level and is not vulnerable to parameter silencing.

### `count_distinct(x)` returns HTTP 500 "Unknown function"

`count_distinct` does not exist on the LRQ/DV engine. Two replacements depending on what you need:

**Approximate (fast):** use `estimate_distinct(x)`. Returns a probabilistic HLL count. Fine for dashboards and thresholds where ±5% error is acceptable.

```
| group approx_ports = estimate_distinct(dst_endpoint.port) by src_endpoint.ip
| filter approx_ports > 100
```

**Exact (two-stage grouping):** when you need a precise count of distinct values per key, do it in two `group` passes:

```
// Stage 1 — one row per (src, port) pair
dataSource.name='Palo Alto Networks Firewall' dst_endpoint.port=*
| group count=count() by src_endpoint.ip, dst_endpoint.port

// Stage 2 — count how many distinct ports each src had
| group distinct_ports=count() by src_endpoint.ip
| filter distinct_ports > 100
| sort -distinct_ports
| limit 1000
```

Stage 1 deduplicates by grouping on the value you want to count; stage 2 counts the resulting rows per key. This gives an exact answer and runs cleanly on the LRQ engine.

---

## Deploying PQ detections

### Using Hyperautomation instead of cloud-detection/rules

Hyperautomation (HA) workflows are for SOAR-style response playbooks: conditional branching, external webhooks, multi-step actions triggered by an event. They are not the right mechanism for scheduled PowerQuery detections.

The correct API is `POST /web/api/v2.1/cloud-detection/rules` with `queryType: "scheduled"` + `queryLang: "2.0"`, and the PowerQuery goes in `data.scheduledParams.query`. HA adds unnecessary complexity, requires workarounds for LRQ poll headers, and puts detection logic in a workflow engine rather than the detection engine where it belongs.

### Always use `queryType: "scheduled"` for PowerQuery rule bodies

The combination that works for any PowerQuery (pipe-syntax) rule body is `queryType: "scheduled"` + `queryLang: "2.0"`. The other combinations fail:

| `queryType` | `queryLang` | Result |
|---|---|---|
| `scheduled` | `"2.0"` | **Correct path for PowerQuery rules.** Body goes in `data.scheduledParams.query`. |
| `events` | `"2.0"` | HTTP 400 `Don't understand [|]`. PowerQuery pipes rejected. |
| `events` | `"2.1"` | HTTP 400 `queryLang: "2.1" is not a valid choice`. |
| `events` | `"1.0"` (default) | S1QL log-search only, no pipes. |

**If `POST /cloud-detection/rules` fails with a feature-not-enabled / unlicensed response on a tenant where the body is otherwise correct, do not retry and do not silently downgrade to S1QL. Tell the user to enable the Scheduled Detections feature on their tenant and try again.** The console path is typically *Settings → Account → Detection / SDL Add-Ons → Scheduled Detections*, varies by platform version.

### `queryLang` on cloud-detection/rules is NOT the LRQ `queryType`

These are two different fields on two different APIs:

| API | Field | PowerQuery value |
|---|---|---|
| `POST /web/api/v2.1/cloud-detection/rules` | `queryLang` | `"2.0"` (with `queryType: "scheduled"`) |
| `POST /sdl/v2/api/queries` (LRQ) | `queryType` | `"PQ"` |

Do not confuse them. On the LRQ API, `queryType: "2.1"` is invalid. On cloud-detection/rules, the rule is scheduled (`queryType: "scheduled"`), the dialect is PowerQuery (`queryLang: "2.0"`), and the query body lives in `data.scheduledParams.query`, not `data.s1ql`.

---

## Alert-specific issues

### Rule silently under-counts

The 1,000-row intermediate cap in Alerts means a heavy `group` silently drops rows. Validate the filter is narrow enough that you'd never exceed 1,000 rows in a reasonable window.

### Rule uses `compare` or a subquery

Alerts don't support these. Move the correlation logic into a `join` (bounded) or rewrite as a single-pass `group`.

### Array or very wide string breaks 1 MB

`array_agg(large_string_field)` can blow the 1 MB budget even with < 100 rows. Replace with `any(…)` (one value per group) or cap the array aggressively: `array_agg(…, 20)`.

## Result-quality issues

### Always filter on `field=*` before projecting or inspecting a field

`| limit N | columns field` returns the first N events in the index regardless of whether `field` is populated — most will be null. This makes a field look absent when it isn't.

**Always add `field=*` to the initial filter** to scope to events that actually carry the field:

```
// Wrong — returns nulls because most events don't have message
dataSource.name='FortiGate' | limit 3 | columns message

// Correct — only events where message is present
dataSource.name='FortiGate' message=* | limit 3 | columns message
```

This rule applies to every field, not just `message`. Whenever you want to inspect, sample, or aggregate a field, include `field=*` in the initial filter. Confirmed on FortiGate: `message=*` surfaces the raw syslog; without it, every row returns null.

### Empty results from a correct-looking query

Before blaming the query:

1. Time range: are you sure events exist in the window?
2. Data view: `EDR` doesn't have integrated sources; `XDR` does; `All Data` adds Collector.
3. Case: are you using `contains` (ci) or `in` / `=` (cs)?
4. Field name: does the field exist on this schema? Run `dataSource.name='X' field=* | limit 1 | columns field` to confirm it's populated.

Don't keep re-running slightly rephrased versions — the Purple MCP docs warn explicitly against that. If the data isn't there, no rewrite finds it.

### Results look plausible but wrong magnitude

Common cause: grouping dropped a field you assumed was still present, or duplicate rows from a `union`. Add `columns` at the end to make the exact shape explicit, then re-inspect.
