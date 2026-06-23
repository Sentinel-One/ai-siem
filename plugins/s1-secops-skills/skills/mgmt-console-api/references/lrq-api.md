# Long Running Query (LRQ) API - the canonical PQ runner

The LRQ API is the **default** programmatic path for every PowerQuery this skill runs. It is async, survives long queries, supports cursor paging to effectively unlimited rows, and is the only endpoint that stays supported after Feb 15 2027 when `/api/powerQuery` and `/web/api/v2.1/dv/events/pq` are retired.

## Endpoints (all on the tenant's own console host)

```
POST   https://<console>.sentinelone.net/sdl/v2/api/queries
GET    https://<console>.sentinelone.net/sdl/v2/api/queries/{id}?lastStepSeen=N
DELETE https://<console>.sentinelone.net/sdl/v2/api/queries/{id}
```

The console host is tenant-specific (for example `your-tenant.sentinelone.net`), not a centralized URL. Do not point at `xdr.us1.sentinelone.net` - that was the V1 SDL endpoint.

## Auth: Bearer, not ApiToken

```
Authorization: Bearer <jwt>
```

The JWT is the **same** console service-user token used by the Mgmt API; only the prefix changes. Calling `/sdl/v2/api/queries` with `Authorization: ApiToken <jwt>` returns HTTP 500:

```
"Header must start with Bearer, but actually starts with \"ApiTok\""
```

Service user tokens are preferred over personal user tokens because the per-user rate cap of 3 rps applies to the user identity embedded in the JWT. See "Rate limits" below.

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
| `tenant` | conditional | `true` = query every account the token can reach. Omit (and omit `accountIds`) and the query runs against a near-empty default scope and returns `matchCount=0` with 200 OK. |
| `accountIds` | optional | Array of account IDs. Must pair with `tenant: false`. Passing `accountIds` with `tenant: true` (or true-by-default) returns 400 "tenant=false should be used when querying accountIds". |
| `startTime` / `endTime` | yes | ISO-8601 with `Z`. Relative forms like `"48h"` also accepted in the launch body. |
| `queryPriority` | no | `"LOW"` / `"HIGH"`. Use `HIGH` for interactive work. |
| `pq.query` | yes (for PQ) | The PowerQuery string. |
| `pq.resultType` | yes (for PQ) | `"TABLE"` for tabular output. |

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

```
GET /sdl/v2/api/queries/{id}?lastStepSeen=<stepsCompleted>
Headers:
  Authorization: Bearer <jwt>
  X-Dataset-Query-Forward-Tag: <from POST response>
```

Done when `stepsCompleted >= stepsTotal` and `stepsTotal > 0`. `data.values` is a 2D array `[[row1col1, row1col2, ...], [row2col1, ...], ...]` whose columns are listed in `data.columns[]`.

**Poll every 1-2 seconds.** The query **expires 30 seconds after launch or 30 seconds after the last poll.** If you poll slower than that, you get a dead query and have to relaunch.

## Cancel

```
DELETE /sdl/v2/api/queries/{id}
Headers:
  Authorization: Bearer <jwt>
  X-Dataset-Query-Forward-Tag: <from POST response>
```

Always cancel when you're done, even after a successful completion. It releases server resources and clears your per-account concurrent query budget.

## Rate limits

- **100 req/sec per account** (loose)
- **3 req/sec per user identity** (tight - this is what you'll hit first)

Each API call (POST, GET, DELETE) counts as one request. A single slice with 5s server runtime and 1-second polling costs roughly 1 POST + 5 GET + 1 DELETE = 7 calls. Staying under 3 rps per user means a token-bucket limiter at ~2.5 rps with 3 slices in flight is the steady-state sweet spot. Exceed it and you get HTTP 429; exponential backoff recovers but steals your wall-clock budget.

**Trick to double the budget:** create two service users with different identities (different `sub` claims in their JWTs). Each user has its own 3 rps cap. Instantiate two clients, bind each slice to one client for its full launch-poll-cancel lifecycle (the `X-Dataset-Query-Forward-Tag` is session-scoped), and round-robin slices across them. Combined budget = ~5-6 rps.

## EDR filter - make sure you actually query EDR data

On most SentinelOne tenants, the default scope carries a mix of SentinelOne EDR telemetry and Scalyr/infra logs. If you want EDR events (Process Creation, File Creation, Module Load, etc.), prepend this to the query:

```
dataSource.name='SentinelOne' dataSource.category='security'
```

or equivalently:

```
i.scheme="edr"
```

Without this, an `event.type=*` aggregate on `your-tenant` over 30 days returned `matchCount=0` until the filter was added; with it, 574M events across 50 types.

## Silent `matchCount=0`: the diagnostic ladder

LRQ returning `matchCount=0` with HTTP 200 is the most common silent-failure mode. Walk these in order before widening the time range or rewriting the query.

1. **Confirm the data source string.** Call `list_data_sources(c, hours=24)` (or run `| group ct=count() by dataSource.name | sort -ct | limit 50`) on the same tenant scope. The exact spelling, capitalization, and punctuation must match what's in the index. `'SentinelOne'` and `'sentinelone'` are different strings to the engine.

2. **Confirm the request body has the right scope.**
   - `tenant: true` is required unless `accountIds` is passed. Without either, the query runs against a near-empty default scope and silently returns zero rows.
   - `accountIds` must pair with `tenant: false`. Sending both `tenant: true` and `accountIds` returns HTTP 400.
   - `tenant: true` is **not** equivalent to "every account in the tenant" on every deployment. On multi-account tenants where an integration writes only to a sub-account or site, `tenant: true` can silently scope to a default account that doesn't carry that integration. **If a Purple MCP query returns rows for the same time window and query but LRQ returns `matchCount=0`, suspect multi-account scoping**. Re-run with explicit `accountIds` set to the account that actually carries the data. Discover candidate account IDs via `GET /web/api/v2.1/accounts`.

3. **Check `matchCount` vs `row_count`.** `matchCount=0` means the initial filter eliminated everything (data source, scope, or filter mismatch). `matchCount > 0` with `row_count=0` means the post-filter pipeline (`| filter`, `| group` with a missing key, `| filter` after `group`) threw everything out, in which case the fix is in the pipeline, not the scope.

4. **For SentinelOne EDR data, confirm the EDR prefix.** `dataSource.name='SentinelOne' dataSource.category='security'` (or `i.scheme="edr"`) is required to surface EDR telemetry. Without it the query may match only Scalyr/infra logs.

5. **Only after the above** widen the time range. A correct query running against an empty data source still returns zero, no matter how long the window.

## PQ functions that fail on the LRQ engine

- `count_distinct(x)` - not supported on the DV/LRQ engine. Use `estimate_distinct(x)` or drop it.
- `first(x)` / `last(x)` - flaky. Use `min_by(x, timestamp)` / `max_by(x, timestamp)`.
- `percentile(x, N)` - not real. Use `p50(x)`, `p95(x)`, `p99(x)`.
- `filter x = null` before `x` has been defined - HTTP 500. Use `filter !(x = *)` instead.

## Slicing & parallelism

For long windows, split the time range into slices and run them in parallel, then merge client-side.

**Two bottlenecks, in order.** At small parallelism the per-user 3 rps rate cap is the ceiling. Once you beat that (two tokens, lower rps-per-token), the new ceiling becomes the slowest slice's **server-side runtime** (each slice still takes 6 to 17 seconds on the backend depending on slice size). Adding pool width past that point doesn't help.

**Slice sizing.** Each slice costs launch + N polls + cancel against your rate budget. Fewer, larger slices beats many small ones when you are rate-capped. Once you are runtime-capped, medium slices (2-3 days) win because they parallelize cleanly without each one becoming a long tail.

### Measured on `your-tenant`

Query: `dataSource.name='SentinelOne' dataSource.category='security' event.type=* | group ct=count(), first_seen=min(timestamp), last_seen=max(timestamp) by event.type | sort -ct | limit 50`. 30-day window, 574M events aggregated.

**Single user token, 2.5 rps:**

| Shape               | Pool | Wall clock | vs serial |
|---------------------|------|------------|-----------|
| 30d serial          | 1    | 166.35s    | 1.00x     |
| 30 x 1d             | 3    | 86.96s     | 1.91x     |
| 6 x 5d              | 3    | 66.25s     | 2.51x (best 1-token) |

**Two distinct service-user JWTs, 2.5 rps each (~5 rps combined), round-robin across clients:**

| Shape               | Pool | Wall clock | vs 1-tok best | vs serial |
|---------------------|------|------------|---------------|-----------|
| 30 x 1d             | 6    | 34.77s     | 1.91x         | 4.78x     |
| 15 x 2d             | 6    | 28.56s     | 2.32x         | 5.83x (best 2-token) |
| 10 x 3d             | 6    | 28.52s     | 2.32x         | 5.83x     |

Per-slice latencies in the 2-token runs: p50 = 6-14s, p95 = 9-17s, max = 10-17s. The wall-clock floor around 28.5s is the tail of the slowest slice plus merge, not a rate-limit artefact.

### Pushing below 20s

The rate budget is no longer the bottleneck at 2 tokens. To go faster:

1. **Add a third service-user JWT** and bump pool to 9. Combined budget ~7.5 rps, backend parallelism lets 9 slices overlap. Expected wall clock: 18-22s for this workload.
2. **Use `| top K`** instead of `| group` for long-range aggregates. It is probabilistic (counts are marked estimated) but runs orders of magnitude faster on huge ranges because it doesn't keep the full per-key state.
3. **Narrow the initial filter.** `event.type in ('Process Creation','File Creation','Module Load')` instead of `event.type=*` cuts scanned volume roughly in half on this tenant and drops each slice's backend runtime proportionally.
4. **Go smaller slices, higher pool.** 30 x 1d at pool=9 with 3 tokens would likely land around the same 20s as 15 x 2d at pool=6 with 3 tokens, because the long tail dominates.

### Recommended defaults

| Window    | Shape             | Clients | Pool | Expected wall |
|-----------|-------------------|---------|------|---------------|
| 24h       | 1 slice           | 1       | 1    | <10s          |
| 7d        | 1 slice or 7x1d   | 1       | 3    | 10-20s        |
| 30d       | 15x2d or 10x3d    | 2       | 6    | 28-35s        |
| 30d fast  | 15x2d             | 3       | 9    | 18-22s        |

For anything longer than 30 days, or workloads that need aggregate accuracy across hundreds of millions of events, expect to lean on `| top K` or a narrower filter rather than raw parallelism.

## Merging aggregate results across slices

Aggregates don't naively concatenate - you have to re-aggregate. For a per-key count:

- `count() by k` → sum counts per k across slices
- `min(x) by k` → min of mins
- `max(x) by k` → max of maxes
- `estimate_distinct(x) by k` → NOT additive; rerun a final single-slice query on the deduped set, or accept approximation

The reference implementation (`merge_aggregate` in the runner) handles sum/min/max. For anything else, do a final aggregating pass over the union of slice outputs.

## Canonical Python runner

The implementation is built from these key pieces, in order of importance:

1. **RateLimiter** - token bucket with `rps` and `burst`, acquire before every API call. One per client.
2. **LRQClient** - wraps one `requests.Session()` with `HTTPAdapter(pool_maxsize=N)` and `Authorization: Bearer <jwt>`. Exposes `launch(body)`, `poll(qid, forward_tag, last_seen)`, `cancel(qid, forward_tag)`. Auto-retries 429 with exponential backoff.
3. **run_lrq_pq(client, query, start_iso, end_iso)** - launches, captures `forward_tag` from response headers, polls every 1s, cancels on finish or failure, returns `{elapsed_s, columns, values, row_count, matchCount, ...}`.
4. **parallel_run_roundrobin(clients, query, spans, max_workers)** - binds each span to `clients[i % len(clients)]` and runs each slice's full lifecycle on its bound client.
5. **merge_aggregate(results, key_cols, sum_cols, min_cols, max_cols)** - client-side post-aggregation.

## LOG queries are a separate primitive

`scripts/pq.py` runs `queryType: "PQ"` only. For workflows that need every parsed field on every matching row (identity investigations, all-attribute hunts, evidence-grade exports), the right primitive is `queryType: "LOG"`, which has a different body shape and different failure modes from PQ.

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
- Detect cap-hit by comparing `len(matches)` to the requested `log.limit`. If they're equal, the slice is truncated; subdivide it (typically into 1-day chunks) and re-run each piece.
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

- [ ] Target the console host, not `xdr.us1.sentinelone.net`
- [ ] `Authorization: Bearer <jwt>` (same JWT as mgmt, different prefix)
- [ ] PQ body: `queryType: "PQ"`, `tenant: true`, `pq: {query, resultType}`
- [ ] LOG body: `queryType: "LOG"`, `tenant: true`, `log: {filter, limit}` (NOT `pq: {…, resultType: "LOG"}`)
- [ ] Query / filter starts with the EDR filter (for SentinelOne EDR data)
- [ ] Grab `X-Dataset-Query-Forward-Tag` from POST response, echo on every GET and DELETE
- [ ] Poll every 1-2s (query expires 30s after last poll)
- [ ] Token-bucket at ~2.5 rps per user (under the 3 rps cap)
- [ ] Cancel on success and on every error path
- [ ] PQ: merge slice results client-side (sum counts, min-of-mins, max-of-maxes)
- [ ] LOG: detect cap-hit (`len(matches) == log.limit`) and subdivide; checkpoint per slice for long runs
- [ ] LOG identity searches: partition on `dataSource.name` presence (subject activity vs investigation noise)
