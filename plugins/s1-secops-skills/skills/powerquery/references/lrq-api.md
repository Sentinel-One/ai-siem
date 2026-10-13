# Long Running Query (LRQ) API - the canonical PQ runner

The LRQ API is the **default** programmatic path for every PowerQuery this skill runs. It is async, survives long queries, supports cursor paging to effectively unlimited rows, and is the only endpoint that stays supported after Feb 15 2027 when `/api/powerQuery` and `/web/api/v2.1/dv/events/pq` are retired.

**You do not call this API by hand.** The `powerquery_run` MCP tool from `s1-secops-mcp` implements everything on this page: launch, forward-tag, polling, cancel, 429 backoff, `queryType: "LOG"` (`logLimit` up to 5000, `truncatedByServerCap` on a capped slice), `slices` (2-15) with `merge` (`keys` / `sum` / `min` / `max`, non-additive aggregates refused), `edrStrict` (top-level `scheme: "edr"`), and `outputFile` for bulk results. It runs on the user's machine, so it works from Cowork. This page documents the wire behaviour for debugging and for host-only Python runners (`scripts/pq.py` in `mgmt-console-api`).

## Endpoints (all on the tenant's own console host)

```text
POST   https://<console>.sentinelone.net/sdl/v2/api/queries
GET    https://<console>.sentinelone.net/sdl/v2/api/queries/{id}?lastStepSeen=N
DELETE https://<console>.sentinelone.net/sdl/v2/api/queries/{id}
```

The console host is tenant-specific (for example `your-tenant.sentinelone.net`), not a centralized URL. Do not point at `xdr.<region>.sentinelone.net` - that was the V1 SDL endpoint.

## Auth: Bearer, not ApiToken

```text
Authorization: Bearer <jwt>
```

The JWT is the **same** console service-user token used by the Mgmt API; only the prefix changes. Calling `/sdl/v2/api/queries` with `Authorization: ApiToken <jwt>` returns HTTP 500:

```text
"Header must start with Bearer, but actually starts with \"ApiTok\""
```

Service user tokens are preferred over personal user tokens: they do not expire with an SSO session and they are not shared with a person's interactive use of the console. See "Rate limits" below for what one token can do.

## Required body fields for a PQ

```json
{
  "queryType": "PQ",
  "tenant": true,
  "startTime": "2026-04-21T00:00:00Z",
  "endTime":   "2026-04-22T00:00:00Z",
  "queryPriority": "HIGH",
  "pq": {
    "query": "dataSource.name='SentinelOne' dataSource.category='security' event.type=* | group ct=count() by event.type | sort -ct | limit 50",
    "resultType": "TABLE"
  }
}
```

### Field-by-field

| Field | Required | Notes |
|---|---|---|
| `queryType` | yes | `"PQ"` for PowerQuery, `"LOG"` for log search, also `TOP_FACETS`, `FACET_VALUES`, `PLOT`, `DISTRIBUTION`. Omit and you get HTTP 400 "Query type must be specified". |
| `tenant` | conditional | `true` = query every account the token can reach: ALL of them on a global or multi-account token. Omit (and omit `accountIds`) and the query runs against a near-empty default scope and returns `matchCount=0` with 200 OK. `false` without `accountIds` returns only global-level rows. |
| `accountIds` | optional | Array of account IDs (a string is 400 "Invalid JSON"). Must pair with `tenant: false`. Passing `accountIds` with `tenant: true` (or true-by-default) returns 400 "tenant=false should be used when querying accountIds". This is how to scope a multi-account token to one account; there is no `siteIds` field, so narrow to a site with a `site.id='<siteId>'` term in the query. |
| `startTime` / `endTime` | yes | ISO-8601 with `Z`. Relative forms like `"48h"` also accepted in the launch body. |
| `queryPriority` | no | `"LOW"` / `"HIGH"`. Use `HIGH` for interactive work. |
| `pq.query` | yes (for PQ) | The PowerQuery string. |
| `pq.resultType` | yes (for PQ) | `"TABLE"` for tabular output. |
| `scheme` | no | Top level, `"edr"`. Validates field names against the EDR schema: a wrongly cased or unknown field returns HTTP 400 `Unknown EDR field: 'Endpoint.name'. Check the spelling and casing. Field names are case-sensitive.` instead of a silent `matchCount=0`. Correct casing returns the same rows as without it. Must be top level: inside `pq` it is HTTP 400 `Invalid JSON`. Platform S-26.2.6; measured 2026-10-05. |

### Response to POST

```json
{
  "id": "<queryId>",
  "stepsCompleted": 0,
  "stepsTotal": 0,
  "cpuUsage": 0,
  "data": null
}
```

**Grab the `X-Dataset-Query-Forward-Tag` response header.** It must be echoed back on every subsequent GET and DELETE - it routes the request to the shard/replica that actually holds the query state. GET/DELETE without it is rejected.

## Polling

```text
GET /sdl/v2/api/queries/{id}?lastStepSeen=<stepsCompleted>
Headers:
  Authorization: Bearer <jwt>
  X-Dataset-Query-Forward-Tag: <from POST response>
```

Done when `stepsCompleted >= stepsTotal` and `stepsTotal > 0`. **Check the POST response first:** most small queries come back already complete from the launch (measured 2026-10-05: of 348 one-day slices launched at 40 calls/s, only 9 needed a GET), so a runner that always sleeps before its first poll wastes a second per slice. `data.values` is a 2D array `[[row1col1, row1col2, ...], [row2col1, ...], ...]` whose columns are listed in `data.columns[]`.

**Poll every 1-2 seconds.** The query **expires 30 seconds after launch or 30 seconds after the last poll.** If you poll slower than that, you get a dead query and have to relaunch.

## Cancel

```text
DELETE /sdl/v2/api/queries/{id}
Headers:
  Authorization: Bearer <jwt>
  X-Dataset-Query-Forward-Tag: <from POST response>
```

Always cancel when you're done, even after a successful completion. It releases server resources and clears your per-account concurrent query budget.

## Rate limits

Measured 2026-10-05 on S-26.3.4 with **one service-user token from one egress IP**, pacing every
call (launch, poll and cancel) through a token bucket and keeping 1.5x the rate in slices in flight:

| Target rate | Achieved | 429s | Which calls |
|---|---|---|---|
| 2.5 to 20 calls/s | up to 8.6 calls/s (latency-bound) | 0 | none |
| 40 calls/s | 29.4 calls/s | 0 of 705 | none |
| 60 calls/s | 35.3 calls/s | 1 of 1,080 | launch (POST) |
| 100 calls/s | 48.7 calls/s | 17 of 1,991 | launch (POST) |
| 150 calls/s | 51.9 calls/s | 107 of 3,626 | launch (POST) |
| 120 launches at once, unthrottled | n/a | 7 of 127 launches | launch (POST) |

What that means:

- **The old "3 requests/s per user" cap is not what you hit.** One token sustained about 30 calls/s
  with zero 429s. The two-token round-robin trick is no longer needed for speed.
- **Only launches are throttled.** GET (poll) and DELETE (cancel) never returned 429. The throttle
  behaves like a cap on new or concurrent queries, not a request-rate cap.
- **Safe defaults:** a token bucket at about 25 calls/s, 15 to 20 slices in flight, retry a 429 on
  launch with exponential backoff plus jitter (0.5 s doubling, 8 tries). Do not retry a 400.
- The SDL per-IP limit published for 2026-09-10 (60 burst / 30 req/s) also covers this host; it was
  not enforced at measurement time, which is one more reason to stay at or below 30 calls/s per IP.
- Each API call (POST, GET, DELETE) counts. A slice that completes on launch costs 2 calls (POST,
  DELETE); one that runs for a few seconds adds one GET per poll.

## EDR filter - make sure you actually query EDR data

On most SentinelOne tenants, the default scope carries a mix of SentinelOne EDR telemetry and Scalyr/infra logs. If you want EDR events (Process Creation, File Creation, Module Load, etc.), prepend this to the query:

```text
dataSource.name='SentinelOne' dataSource.category='security'
```

or equivalently:

```text
i.scheme="edr"
```

Without this, an `event.type=*` aggregate on `your-tenant` over 30 days returned `matchCount=0` until the filter was added; with it, 574M events across 50 types.

## Silent `matchCount=0`: the diagnostic ladder

LRQ returning `matchCount=0` with HTTP 200 is the most common silent-failure mode. Walk these in order before widening the time range or rewriting the query.

1. **Confirm the data source string.** Call `powerquery_enumerate_sources` (host-only Python: `list_data_sources(c, hours=24)`), or run `| group ct=count() by dataSource.name | sort -ct | limit 50`) on the same tenant scope. The exact spelling, capitalization, and punctuation must match what's in the index. `'SentinelOne'` and `'sentinelone'` are different strings to the engine.

2. **Confirm the request body has the right scope.**
   - `tenant: true` is required unless `accountIds` is passed. Without either, the query runs against a near-empty default scope and silently returns zero rows.
   - `accountIds` must pair with `tenant: false`. Sending both `tenant: true` and `accountIds` returns HTTP 400.
   - **Scope goes in the body; the `S1-Scope` header is not enough.** `tenant: true` covers every account the token is authorized for: one account on an account-level token, all of them on a global or multi-account token (measured 2026-10-09: a 385-account service user returned 20 accounts in one hour). `S1-Scope` narrows an account-level token but is ignored for a multi-account one, so a "scoped" query silently answers for every account. To query one account send `tenant: false, accountIds: ["<accountId>"]`; for one site also add `site.id='<siteId>'` to the initial filter. An account the token cannot reach is HTTP 403 "Not allowed to access requested resource" (or 500 "You do not have access to this account"). The `powerquery_run`, `powerquery_enumerate_sources` and `powerquery_schema_discover` MCP tools do all of this from `scope: "<accountId>[:<siteId>]"` (s1-secops-mcp 1.5.3+) and report it as `scopeApplied`; for a leading `| join` or `| union` the site term goes into every subquery. **Keep sending `S1-Scope` anyway:** lookup tables are per scope (the same path at account and at site scope is two files), and `| dataset` / `| lookup` read the copy at the header's scope on every token. On a global token with `accountIds` and no header, the table was not found.
   - **`site.id` is stored as a string on some events and as a number on others**, so a `group ... by site.id` can show the same site twice, once as a rounded number. Filter with `site.id='<siteId>'`, which matches both forms.
   - **If a Purple MCP query returns rows for the same time window and query but LRQ returns `matchCount=0`, check the scope**: re-run with `accountIds` set to the account that carries the data. Discover account IDs via `GET /web/api/v2.1/accounts`.

3. **Check `matchCount` vs `row_count`.** `matchCount=0` means the initial filter eliminated everything (data source, scope, or filter mismatch). `matchCount > 0` with `row_count=0` means the post-filter pipeline (`| filter`, `| group` with a missing key, `| filter` after `group`) threw everything out, in which case the fix is in the pipeline, not the scope. Exception: on a query with an `in (...)` subquery, `matchCount` also counts the events the **inner** query scanned (a subquery whose inner and outer match the same events reports twice the outer count; regression case `sq-matchcount-includes-inner-scan`), so `matchCount > 0` with 0 rows can mean the outer matched nothing at all.

4. **For SentinelOne EDR data, confirm the EDR prefix.** `dataSource.name='SentinelOne' dataSource.category='security'` (or `i.scheme="edr"`) is required to surface EDR telemetry. Without it the query may match only Scalyr/infra logs.

5. **For EDR queries, relaunch with top-level `"scheme": "edr"`.** A field-name typo or wrong casing (`Endpoint.name` for `endpoint.name`) is otherwise indistinguishable from "no data": both return `matchCount=0` with HTTP 200, including when the query itself contains `i.scheme="edr"`. With the body flag the typo returns HTTP 400 `Unknown EDR field: ...` and names the field.

6. **Only after the above** widen the time range. A correct query running against an empty data source still returns zero, no matter how long the window.

## PQ functions that fail on the LRQ engine

- `count_distinct(x)` - not supported on the DV/LRQ engine. Use `estimate_distinct(x)` or drop it.
- `first(x)` / `last(x)` - flaky. Use `min_by(x, timestamp)` / `max_by(x, timestamp)`.
- `percentile(x, N)` - not real. Use `p50(x)`, `p95(x)`, `p99(x)`.
- `filter x = null` before `x` has been defined - HTTP 500. Use `filter !(x = *)` instead.

## Slicing & parallelism

For long windows, split the time range into slices, run them in parallel, then merge client-side.
On a 30-day window this is the single biggest speed-up available. `powerquery_run` does this with
`slices` and `merge`; the measurements below are why its defaults are what they are.

### Measured on S-26.3.4 (2026-10-05)

Query: `| group n=count() by dataSource.name` (and `by dataSource.vendor` for the cache-free
re-run), 30-day window, about 14.1 million events, one token, paced at 25 calls/s:

| Shape | In flight | Wall clock | Merged total vs single query |
|---|---|---|---|
| 1 x 30d | 1 | 20.9 s to 40.0 s | baseline |
| 7 x ~4.3d | 7 | 4.7 s to 5.0 s | matches (within 0.01%) |
| 15 x 2d | 15 | 4.9 s to 5.2 s | matches |
| 30 x 1d | 30 | 10.2 s | matches |

The cache-free re-run launched the 15 slices first and the single query last, so the slice timings
are not riding on cached results. Small differences in the merged totals are the window moving
while the runs execute.

- **15 x 2d with 15 in flight is the sweet spot:** 4x to 8x faster than one query.
- **Past about 15 to 20 in flight it gets slower again.** 30 slices took twice as long as 15: more
  launches hit the launch throttle and each slice still pays its fixed backend cost.
- One 1-day query over the same data typically completes in the launch call itself, so for 24 hours
  or less a single query is already fast.

### Recommended defaults

| Window | Shape | In flight | Expected wall |
|---|---|---|---|
| 24h | 1 slice | 1 | under 5 s |
| 7d | 7 x 1d | 7 | about 5 s |
| 30d | 15 x 2d | 15 | about 5 s |
| 90d | 30 x 3d, two waves of 15 | 15 | about 10 to 15 s |

Prefer `| top K` or a narrower initial filter over more slices once a single slice's own runtime
dominates.

## Merging aggregate results across slices

Aggregates don't naively concatenate - you have to re-aggregate. For a per-key count:

- `count() by k` → sum counts per k across slices
- `min(x) by k` → min of mins
- `max(x) by k` → max of maxes
- `estimate_distinct(x) by k` → NOT additive; rerun a final single-slice query on the deduped set, or accept approximation

The reference implementation (`merge_aggregate` in the runner) handles sum/min/max. For anything else, do a final aggregating pass over the union of slice outputs.

## Canonical Python runner (host only)

`powerquery_run` is the runner to use from Cowork and any MCP client. A host-only Python runner (Claude Code or a terminal, credentials from environment variables or the OS keychain) is built from these key pieces, in order of importance:

1. **RateLimiter** - token bucket with `rps` and `burst` (about 25 rps per token), acquire before every API call. One per client.
2. **LRQClient** - wraps one `requests.Session()` with `HTTPAdapter(pool_maxsize=N)` and `Authorization: Bearer <jwt>`. Exposes `launch(body)`, `poll(qid, forward_tag, last_seen)`, `cancel(qid, forward_tag)`. Auto-retries 429 with exponential backoff.
3. **run_lrq_pq(client, query, start_iso, end_iso)** - launches, captures `forward_tag` from response headers, polls every 1s, cancels on finish or failure, returns `{elapsed_s, columns, values, row_count, matchCount, ...}`.
4. **parallel_run_roundrobin(clients, query, spans, max_workers)** - binds each span to `clients[i % len(clients)]` and runs each slice's full lifecycle on its bound client. One client is enough at about 15 in flight; extra tokens only help past the launch throttle.
5. **merge_aggregate(results, key_cols, sum_cols, min_cols, max_cols)** - client-side post-aggregation.

## LOG queries are a separate primitive

For workflows that need every parsed field on every matching row (identity investigations, all-attribute hunts, evidence-grade exports), the right primitive is `queryType: "LOG"`, which has a different body shape and different failure modes from PQ. `powerquery_run` takes `queryType: "LOG"` directly (filter only in `query`, `logLimit` up to 5000, `truncatedByServerCap: true` when a slice hit the cap, combine with `slices` and `outputFile`). The host-only `scripts/pq.py` in `mgmt-console-api` runs `queryType: "PQ"` only.

### Body shape

```json
{
  "queryType": "LOG",
  "tenant": true,
  "startTime": "2026-04-01T00:00:00Z",
  "endTime":   "2026-04-02T00:00:00Z",
  "queryPriority": "HIGH",
  "log": {
    "filter": "<filter expression, no pipes>",
    "limit": 5000
  }
}
```

Two differences from PQ that bite first-time callers:

- The filter goes inside `log.filter`, not `pq.query`. The filter expression is just the initial-filter portion of a PQ (e.g., `dataSource.name='<source>' * contains 'value'`), no pipes, no commands.
- A LOG body with `pq: {query, resultType: "LOG"}` returns HTTP 400 `Unexpected value 'LOG'`. The fix is body-shape (`log: {...}` and `queryType: "LOG"`), not result-type.

### LOG-specific slicing constraints

PQ slicing concerns the LRQ deadline budget; LOG slicing concerns server-side row caps. Different failure modes:

- LOG has a server-side `log.limit` cap (typically 5000). Any slice that hits the cap **silently truncates**, returning exactly N rows where N = `log.limit`. There is no "page 2" for LOG; the missing rows are simply dropped.
- Detect cap-hit by comparing `len(matches)` to the requested `log.limit` (`powerquery_run` reports this as `truncatedByServerCap: true`). If they're equal, the slice is truncated; subdivide it (typically into 1-day chunks, or raise `slices`) and re-run each piece.
- PQ aggregations don't have this problem because they aggregate before capping. LOG cannot aggregate; the cap is on raw rows.

Standard subdivision pattern:

```python
def run_log_with_subdivision(client, filter_expr, start, end, limit=5000):
    res = run_log_query(client, filter_expr, start_time=start,
                        end_time=end, limit=limit)
    if len(res["matches"]) < limit:
        return res["matches"]                  # not capped
    # Cap hit. Subdivide and recurse.
    mid = midpoint(start, end)
    return (run_log_with_subdivision(client, filter_expr, start, mid, limit)
            + run_log_with_subdivision(client, filter_expr, mid, end, limit))
```

In practice, day-sized slices are a reasonable starting point for most M365 / identity sources; subdivide further only when a daily slice still hits the cap.

### Per-slice checkpoint pattern for long-running multi-slice jobs

Long multi-slice runs (year-long identity investigations, multi-month source profiling) lose state if the host process is killed between tool calls or sandbox sessions recycle. Without checkpointing, every retry starts from slice 0.

Pattern: each completed slice writes one JSON file under a checkpoint directory, keyed by `{slice_start}_{slice_end}.json`. On resume, skip slices whose checkpoint file already exists. Idempotent on retry, cheap on disk, and avoids re-running expensive slices.

```python
def sliced_run(client, filter_expr, slices, ckpt_dir, *,
               max_workers=3, runner=run_log_query):
    ckpt_dir = Path(ckpt_dir); ckpt_dir.mkdir(parents=True, exist_ok=True)
    todo = []
    for (s, e) in slices:
        path = ckpt_dir / f"{s}_{e}.json"
        if path.exists():
            continue                          # already done
        todo.append((s, e, path))
    # ... thread-pool over `todo`, each worker writes its slice's
    # result to its `path` on completion.
    return sorted(ckpt_dir.glob("*.json"))
```

The completed checkpoint set is the source of truth; merge with a column-union helper at the end (different slices can carry different attribute keys when parser changes land mid-window).

### Investigation-noise separator

When the LOG search predicate is an identity string (email, user id, IP), the result set interleaves real-world events from parsed sources with SDL platform-internal audit records of analysts who searched for that string previously. The audit records are themselves a finding (the subject has been investigated before), but they are not subject activity.

Cleanest separator observed: **presence of `dataSource.name`** indicates a parsed real-world event; absence indicates SDL platform-internal audit. Always partition the result set on this and report investigation-noise as a separate quantity.

```python
subject = [r for r in matches if r.get("dataSource.name")]
audit   = [r for r in matches if not r.get("dataSource.name")]
```

## Checklist before launching a programmatic PQ or LOG query

- [ ] Target the console host, not `xdr.<region>.sentinelone.net`
- [ ] `Authorization: Bearer <jwt>` (same JWT as mgmt, different prefix)
- [ ] PQ body: `queryType: "PQ"`, `tenant: true`, `pq: {query, resultType}`
- [ ] LOG body: `queryType: "LOG"`, `tenant: true`, `log: {filter, limit}` (NOT `pq: {…, resultType: "LOG"}`)
- [ ] One account on a multi-account token: `tenant: false, accountIds: ["<accountId>"]` instead of `tenant: true`; one site: also `site.id='<siteId>'` in the initial filter
- [ ] Query / filter starts with the EDR filter (for SentinelOne EDR data)
- [ ] Grab `X-Dataset-Query-Forward-Tag` from POST response, echo on every GET and DELETE
- [ ] Poll every 1-2s (query expires 30s after last poll)
- [ ] Token-bucket at about 25 calls/s per token, 15 to 20 slices in flight; retry launch 429s with backoff
- [ ] Cancel on success and on every error path
- [ ] PQ: merge slice results client-side (sum counts, min-of-mins, max-of-maxes)
- [ ] LOG: detect cap-hit (`len(matches) == log.limit`) and subdivide; checkpoint per slice for long runs
- [ ] LOG identity searches: partition on `dataSource.name` presence (subject activity vs investigation noise)
