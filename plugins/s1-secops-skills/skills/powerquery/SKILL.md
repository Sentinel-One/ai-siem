---
name: powerquery
author: Prithvi Moses <prithvi.moses@sentinelone.com>
description: Use any time the user wants to author, debug, optimize, explain, or run a SentinelOne PowerQuery (PQ) — Deep Visibility / Event Search queries, XDR/EDR threat hunting, investigations, STAR / Custom Detection rule bodies, PowerQuery Alerts, or Singularity Data Lake dashboard panels. Trigger on PowerQuery, PQ, pq, query, Event Search, Deep Visibility, S1QL, SDL, STAR rule, Custom Detection rule, PowerQuery Alert; on queries using fields like `event.type`, `src.process.*`, `tgt.file.*`, `indicator.*`, `agent.uuid`; on pipes like `| group`, `| filter`, `| let`, `| join`, `| parse`, `| columns`, `| compare`, `| top`, `| union`, `| lookup`, `| savelookup`, `| dataset`. Also trigger when asked to hunt a TTP, IOC, behaviour, or alert pattern on a SentinelOne tenant — even casually ("find powershell reaching out to the internet", "write a detection for lsass access"). Explicitly NOT Microsoft Power Query / M / Excel and NOT Splunk SPL — this is SentinelOne's pipeline query language for security telemetry.
---

# SentinelOne PowerQuery

PowerQuery (PQ) is SentinelOne's pipeline query language for the Singularity Data Lake. It reads like `filter | command | command | …` — events that match the initial filter flow through a sequence of piped transformations (group, let, join, sort, columns, etc.).

Use this skill to write correct, efficient, runnable PowerQueries for threat hunting, investigations, detection rule bodies, and dashboards.

> **Sandbox proxy blocked?** If the LRQ API at `POST /sdl/v2/api/queries` on your console host fails with a connection or proxy error inside the Claude sandbox, use the `s1-secops-mcp` server instead. It runs locally via `node` and bypasses the sandbox proxy entirely. Setup: add it to `claude_desktop_config.json` (see `s1-secops-mcp/README.md`). The MCP server exposes `powerquery_run`, `powerquery_enumerate_sources`, and `powerquery_schema_discover` — all running through the LRQ API on your machine.

## Workflow

When the user asks you to write or investigate with a PowerQuery:

1. **Clarify the intent** if it's ambiguous (time range, data view, what the output should look like). A good PQ is scoped — not everything needs to be hunted over 30 days.
2. **Draft the query** following the grammar below. Favor `filter | group | sort | limit | columns` as the default shape — it's what most real investigations need.
3. **Run it against the tenant.** Default to the **Long Running Query (LRQ) API** at `POST /sdl/v2/api/queries` on the tenant's console URL. LRQ is the fastest, highest-limit, most reliable path for any programmatic use and supersedes both `/api/powerQuery` and the Deep Visibility `/dv/events/pq` endpoint (both deprecated; sunset Feb 15 2027). It is async, supports cursor paging to essentially unlimited rows, has a 100 req/sec per-account cap, and lets you parallelize across time slices. Reach for the Purple MCP `powerquery` tool only for a single quick exploratory check when no API client is already wired up. See "Running queries (LRQ API by default)" below and `references/lrq-api.md` for the canonical runner, body schema, auth, rate limits, and the gotchas that make it fail silently with 0 rows. If the user's request is clear and low-risk (read-only query), just run it; don't ask permission.
4. **Iterate**: if the query errors or returns obviously wrong results, read the error, fix, rerun. If the query returns nothing, that is a legitimate result, don't blindly loosen it; check the time range and filter logic first. If you ran via the Purple MCP `powerquery` tool and it **timed out** or returned a server error (common for anything past 24h or with wide initial filters), don't retry and don't shrink the range to fit the MCP budget - switch to the LRQ API path (see "Fallback" under Running queries below).
5. **Explain the result briefly** and cite any fields you're relying on. If you used a non-obvious pattern (subquery, `savelookup`, `transpose`, `compare`), explain *why* you chose it.

## The grammar in one page

```
initial-filter-expression
| command
| command
| …
```

**Initial filter** (everything before the first `|`) is the only place where `* contains "x"` and `* matches "regex"` multi-field search works. It can be empty — start the query with `|` and it is treated as "all events" (e.g., `| group ct=count() by event.type`).

**Commands** (each starts with `|`):
- `filter expr` — keep matching rows (initial filter implicit)
- `columns f1, "Renamed f2"=f2, …` — select, rename, compute output columns (creates a *new* record set — previous fields not accessible after)
- `let f = expr, …` — add computed fields without discarding existing ones
- `group agg(x), name2=agg2(y) by f1, "grouped name"=f2` — aggregate; also creates a new record set
- `sort +f1, -f2` — `-` = descending
- `limit N` — truncate (default shows 10 without it; output is capped at 1,000 rows if no `limit`/`group`)
- `parse "…$field$…" from srcField` — extract fields from unstructured text
- `lookup col, … from tableName by key=expr` — join against a CSV/JSON config data table
- `dataset 'config://datatables/<name>'` — read a lookup table as the source of the pipeline
- `datasource <name> [from <dataset>]` — read SentinelOne-managed inventory outside the event store (assets, alerts, vulnerabilities, misconfigurations, metering); the only PQ path to the Asset Inventory / AD identity attributes. See `references/datasource-command.md`
- `savelookup 'tableName'[, 'merge']` — persist current result as a reusable lookup table
- `| [inner|left|outer|sql inner|sql left|sql outer] join (q1), (q2), … on k1, a.x = b.y` — correlate subqueries (must start `| join`, not just `join`)
- `| union (q1), (q2), …` — merge heterogeneous result sets (up to 10 queries; use when `filter (…or…)` can't express it)
- `| transpose colName on keyCol, …` — pivot a column into many columns (must be LAST command)
- `| compare [name=]timeshift('-1w')` — re-run the same query shifted in time and put both in one table (must be LAST command; only one `compare` allowed)
- `| top K agg(x) by f1, f2` — probabilistic top-N (fast on huge ranges; `count()`/`sum()` are "(estimated)", `min`/`max` exact)
- `| nolimit` — raise the row cap to 3 GB (slow; one concurrent nolimit query at a time; never use in Dashboards or PowerQuery Alerts)

**Expressions** use standard operators: `=` / `==` / `!=`, `<` / `<=` / `>` / `>=`, `&&` / `||` / `!` (or `AND` / `OR` / `NOT`), ternary `a ? b : c` (put spaces around the `:`), arithmetic `+ - * / %`, and these text operators:

| Operator | Meaning |
|---|---|
| `x contains 'sub'` | substring (case-insensitive) — also `contains ('a','b','c')` for OR |
| `x contains:matchcase 'Sub'` | case-sensitive substring |
| `x matches 'regex'` | regex (case-insensitive, double-escape) — `matches ('a','b')` for OR |
| `x matches:matchcase '…'` | case-sensitive regex |
| `x in ('a','b',123,true)` | exact equals any; case-sensitive; `in:anycase` for case-insensitive; does NOT match null |
| `x = *` | field is present/non-null |
| `!(x = *)` | field is null/missing |
| `$"regex"` | shorthand for `message matches "regex"` (initial filter only) |
| `#shortcut = 'value'` | pre-defined multi-field shortcut (e.g., `#ip`, `#hash`, `#name`, `#cmdline`, `#storylineid`, `#username`) |

Strings need quotes (`'foo'` or `"foo"`); numbers and booleans don't. Underscores in numbers are OK for readability (`1_000_000`).

## BANNED functions — do not use, ever

These function names do not exist in PowerQuery. Using any of them produces `Unknown function '<name>'` (HTTP 500). Do not invent plausible-sounding names — if a function isn't in `references/functions-reference.md`, it doesn't exist.

| Do NOT write | Write this instead |
|---|---|
| `formattime(...)` | `strftime(ts)` / `strftime(ts, pattern)` |
| `formatdate(...)` | `strftime(ts)` / `simpledateformat(ts, pattern)` |
| `floor_time(...)` | `bucket=timebucket(unit)` in `group by` |
| `date_trunc(...)` | `timebucket(unit)` |
| `coalesce(a, b)` | `a ? a : b` (bare-field ternary) |
| `ifnull(a, b)` | `a ? a : b` |
| `if(cond, a, b)` inside aggregates | `count(predicate)` |
| `percentile(x, N)` | `p50(x)` / `p95(x)` / `p99(x)` |
| `first(x)` / `last(x)` | `min_by(x, timestamp)` / `max_by(x, timestamp)` |
| `sort count desc` / `sort field asc` | `sort -count` / `sort +field` — PowerQuery uses `-`/`+` prefix, NOT SQL-style `desc`/`asc`. Using `desc` or `asc` causes HTTP 500 "Unable to parse the entire query". Purple AI frequently generates this wrong — always correct before running. |
| `` `field.name` `` (backtick-quoted identifiers) | `field.name` — dotted field names are written bare, no backticks. Using backtick quoting returns HTTP 500 "Don't understand [`]". |

The only valid date/time functions are: `strftime`, `simpledateformat`, `strptime`, `simpledateparse`, `timebucket`, `querystart`, `queryend`, `queryspan`.

---

## The most important rules (learned the hard way)

These are where queries go wrong. Internalize them before writing.

1. **`*` alone is NOT a valid initial filter.** `* | limit 5` returns a 500 error ("Don't understand [*]"). There are three distinct `*` idioms — pick the right one for your intent:
   - **Field presence / attribute wildcard:** `dataSource.name=*` means "field is present/non-null". Use as a query-opener for aggregations, e.g. `dataSource.name=* | group count=count() by dataSource.name`. This is NOT an all-column search.
   - **All-column text search:** `* contains 'evil.com'` or `* matches 'regex'` in the **initial filter** (before the first `|`) searches ALL indexed fields — use when you need to find text anywhere in the event. Dramatically faster than `message contains`. Only works before the first `|`; not valid in `| filter …` after a pipe, and not valid in Alerts.
   - **Empty filter (all events):** start the query with `|`, e.g. `| group ct=count() by event.type`.
2. **Double-escape regex almost everywhere.** `src.process.cmdline matches "\\d+"`, `tgt.file.path matches '^C:\\\\Windows\\\\Temp\\\\[a-z]{8}\\.tmp$'`. The only place you don't double-escape is the `$"…"` shorthand (searches `message`).
3. **Regex lazy quantifiers (`?`) are not supported.** The SDL regex engine does not support lazy (non-greedy) quantifiers: `.*?`, `.+?`, `[^x]*?` etc. all return HTTP 500 "Dangling meta character '?'". Use a negated character class instead: `[^"]*` in place of `.*?"`, `[^ ]*` in place of `.*? `, etc.
4. **After `columns` or `group`, previous fields are gone.** These commands create an entirely new record set. If you'll need a field later, carry it through: `group ct=count(), host=any(endpoint.name) by src.process.storyline.id` — don't expect `endpoint.name` to still be addressable after that `group` unless you aggregate it.
5. **Subqueries can't go after `group`, `sort`, or `limit`.** And the subquery must itself produce the column named in the `in (...)` expression (via `columns` or `group`). `user in (action='login' | group 1 by user)` is valid; `user in (action='login')` is not.
6. **`compare` and `transpose` must be the LAST command.** Put `sort` before `compare` if you want to order the non-shifted side.
7. **`join` must start with a pipe.** `| join (…), (…) on x` — without the `|`, "join" is interpreted as a search term. Inner/left joins allow up to 10 subqueries; `sql inner` and `sql left` allow only 2.
8. **`null` behaves like false in boolean context.** `filter x = null` works after the field is defined by a prior command; before then, use `!(x = *)` for is-null and `x = *` for is-not-null.
9. **`contains` is case-insensitive by default; `in` is case-sensitive by default.** The `:matchcase` / `:anycase` suffixes reverse this.
10. **Performance: filter early, group narrow.** Push filters above the first pipe when possible. In `group`, prefer low-cardinality fields; for long ranges, consider `| top K …` instead (probabilistic but orders of magnitude faster).
11. **Alerts and Dashboards have tighter limits.** A PowerQuery Alert is capped at 1,000 rows intermediate / 1 MB RAM. Don't put `nolimit` in a dashboard panel.
12. **Shortcut fields (`#cmdline`, `#name`, `#hash`, …) don't work as initial filters on every tenant.** They're documented but return 500 on many deployments. Prefer explicit field names (`src.process.cmdline contains 'x'`) — they're as terse and always work. Save shortcuts for exploratory Event Search where you're not scripting against the API.
13. **Aggregates to prefer: `min_by` / `max_by` over `first` / `last`.** `first(x)` and `last(x)` are sometimes listed as aggregates but fail on many tenants. Use `min_by(x, timestamp)` and `max_by(x, timestamp)` — they're explicit about ordering and always work.
14. **Percentiles: use `p50`/`p95`/`p99`, not `percentile(x, N)`.** The latter isn't a real function and returns 500.
15. **Null-filter at the wrong stage: `filter x = null` before `x` is computed returns 500.** Use `filter !(x =*)` for is-null until after a `let`/`join`/`lookup` has produced `x`.
16. **Coalesce-style fallback uses bare-field truthy test, NOT `(field = *) ? a : b`.** PQ has no `coalesce()` / `ifnull()` / `nvl()`. To pick the first non-null of several fields inside a `let`, chain bare-field ternaries — they evaluate the field's truthiness directly:

    ```
    | let user_id = actor.user.email_addr
                  ? actor.user.email_addr
                  : (actor.user.name ? actor.user.name : src.process.user)
    ```

    The `(field = *) ? a : b` form (i.e. wrapping the field-presence test in parens before the ternary) **returns HTTP 500 inside `let`** on this engine — `field = *` is a filter operator, not a boolean expression usable in computed columns. Bare-field truthy is the only working coalesce idiom in PQ.
17. **`if(...)` is not a function in aggregates.** `sum(if(cond, 1, 0))` returns 500. Use `count(<predicate>)` instead — `count(severity_id == 5)` evaluates the predicate per row and sums the truthy ones. Same for any "count where X" semantic.
18. **Always filter `field=*` before projecting or inspecting any field.** `| limit N | columns field` returns the first N events regardless of whether the field is populated — most rows will be null. Add `field=*` to the initial filter to scope to events that actually carry the field:

    ```
    // Wrong — returns nulls; message may not be present on most events
    dataSource.name='FortiGate' | limit 3 | columns message

    // Correct — only events where message is present
    dataSource.name='FortiGate' message=* | limit 3 | columns message
    ```

    This applies to every field, not just `message`. Any time you want to sample, inspect, or aggregate a field, include `field=*` in the initial filter.

19. **Statistical baselining is two queries plus a client-side merge, not one inline join.** Subqueries inside a single `| join` share the parent query's time range. To compare a 24h live window against a 7d/30d baseline, run them as separate LRQs (or as separate `savelookup`+`lookup` rounds) and merge — there is no single-pass form. Pattern in `examples/behavioral-baselines.md`.

## When to delegate baselining + anomaly detection to the mgmt-console-api skill

If the user asks for any of the following, you need MORE than this skill — load `s1-secops-skills:mgmt-console-api` alongside, because the runner, the schema discovery, and the source-agnostic key picker live there:

- "Baseline behaviour on `<source>`" / "establish a baseline" / "build a 7d / 30d baseline"
- "Detect anomalies" / "find users / hosts / IPs behaving differently than usual"
- "Spot statistical outliers" / "find spikes vs typical" / "find pairs that went silent"
- Porting any moving-average + stddev / z-score / Prophet / Isolation Forest pattern
- "Run this for all sources" / source-agnostic anomaly detection

What `mgmt-console-api` adds:

- `scripts/inspect_source.py` — auto-discovers field schema for any `dataSource.name` and classifies fields into `principal_user` / `principal_host` / `principal_ip` / `action` etc. via `pick_keys(schema)` → returns `(prim_key, action_key)`. This means you don't hand-hardcode `actor.user.email_addr` for every source — the right principal field is picked from whatever the source actually carries (Okta uses email, FortiGate uses IP, SentinelOne uses process user, etc.).
- `scripts/pq.py` — `run_pq()` LRQ runner that handles auth, forward-tag, polling, slicing.
- `scripts/baseline_anomaly.py` — source-agnostic 30-day-DoW-stratified baseliner that takes a `dataSource.name`, discovers the schema, and produces anomalies. Read its source for the canonical end-to-end pattern.

Use `examples/behavioral-baselines.md` in THIS skill for the PQ building blocks (per-day slice, live slice, z-score math, silent-pair detector). Use the mgmt-console-api skill for the runner, schema discovery, and the productionised baseliner script. Don't reinvent the schema-discovery or the daily-slice runner — both already exist there.

## Running queries (LRQ API by default)

The primary execution path is the Long Running Query API. It is async (launch + poll + cancel), handles queries that would time out on any other endpoint, scales cleanly to 30-day aggregates, and is the only path that stays supported after Feb 15 2027 when both `/api/powerQuery` and `/web/api/v2.1/dv/events/pq` retire.

**Three calls, in order:**

```
POST   https://<console>.sentinelone.net/sdl/v2/api/queries          -> launch, returns {id, ...}
GET    https://<console>.sentinelone.net/sdl/v2/api/queries/{id}?lastStepSeen=N   -> poll every 1-2s
DELETE https://<console>.sentinelone.net/sdl/v2/api/queries/{id}     -> cancel when done
```

**Required body fields for a PowerQuery:**

```json
{
  "queryType": "PQ",
  "tenant": true,
  "startTime": "2026-04-21T00:00:00Z",
  "endTime":   "2026-04-22T00:00:00Z",
  "queryPriority": "HIGH",
  "pq": { "query": "<your PQ>", "resultType": "TABLE" }
}
```

**Five things that will bite you if you skip them** (full list in `references/lrq-api.md`):

1. **Auth: `Authorization: Bearer <jwt>`**, not `ApiToken`. Same JWT from the mgmt console, different prefix. Wrong prefix returns HTTP 500 "Header must start with Bearer".
2. **`queryType` is required.** Omit and you get 400 "Query type must be specified".
3. **`tenant: true` is required** unless you pass `accountIds`. Without either, the query runs against a near-empty default scope and returns `matchCount=0`.
4. **Echo `X-Dataset-Query-Forward-Tag`** from the POST response header on every poll and the cancel. GET/DELETE without it is rejected.
5. **EDR filter for SentinelOne telemetry:** prepend `dataSource.name='SentinelOne' dataSource.category='security'` (or `i.scheme="edr"`) to your query. Without it you get Scalyr / infra logs mixed with everything, and on some tenants you get only infra.

**Rate limits:** 100 req/sec per account, **3 req/sec per user** (the tight one). A user token capped at 3 rps means a token-bucket limiter at ~2.5 rps with a pool of 3 parallel slices is the sweet spot. To push further, use two distinct service user JWTs and round-robin slices across them - each user identity has its own 3 rps budget.

**Query expires 30s after launch or 30s after the last poll.** Poll every 1-2s; don't let the deadline slip.

**Sizing & parallelism.** Two bottlenecks stack: per-user rate cap first, then slowest-slice server runtime. Measured on `your-tenant` for a 30d count-by-event.type over 574M events:

- **1 token, 2.5 rps:** 30d serial 166s | 30x1d pool=3 87s | 6x5d pool=3 **66s** (best 1-token)
- **2 tokens, ~5 rps combined, round-robin:** 30x1d pool=6 35s | 15x2d pool=6 **29s** | 10x3d pool=6 **29s** (best 2-token)

Once two tokens are in play the per-user rate cap stops being the bottleneck and the slowest slice's backend runtime (p95 ~9-17s) becomes the floor. Push further by adding a third service-user JWT (pool=9, ~7.5 rps budget, expected 18-22s), swapping `| group` for `| top K` on huge ranges, or narrowing the initial filter. Defaults table and the full benchmark live in `references/lrq-api.md`.

**Canonical runner.** The full Python implementation (rate limiter, two-token round-robin, aggregate merge across slices) is documented in `references/lrq-api.md`. Read that file before writing a new runner from scratch.

**Quick one-shot exploration** (no API client wired up): the Purple MCP `mcp__purple-mcp__powerquery` tool is fine for an interactive 24h hunt. It wraps the same engine but with lower limits, tighter timeouts, and no parallelism. Pair it with `mcp__purple-mcp__get_timestamp_range(hours=24)` for ISO-8601 ranges, and `mcp__purple-mcp__purple_ai` when you need a starting-point query draft from natural language. Prefer LRQ for anything programmatic, multi-slice, over long windows, or producing results the user will use downstream.

**Fallback: when the Purple MCP `powerquery` tool times out or returns an error** (common for ranges > 24h, large aggregates, or wide initial filters), do NOT retry with a tighter time range as a first resort. Instead, re-run the same query through the LRQ API. The mgmt console API's `S1Client` already holds a valid JWT (`S1Client().api_token`); swap the prefix from `ApiToken` to `Bearer` and POST to the same tenant's `/sdl/v2/api/queries`. Canonical inline fallback:

```python
# Starting from the already-loaded S1Client used by the mgmt-console-api skill:
from sentinelone_sdl_lrq import LRQClient, run_lrq_pq, parallel_run_roundrobin, slice_window

s1 = S1Client()                                # same client the mgmt skill uses
jwt = s1.api_token                              # raw JWT - no prefix
base = s1.base_url                              # e.g. https://your-tenant.sentinelone.net
lrq = LRQClient(base, jwt, label="fallback", rps=2.5)
result = run_lrq_pq(lrq, query, start_iso, end_iso)   # launches, polls 1s, cancels
```

If the window is longer than a couple of days or the aggregate is heavy, slice it and use `parallel_run_roundrobin` with two clients built from two service-user JWTs (see `references/lrq-api.md`). The LRQ path handles anything the MCP times out on; there's no need to shrink the user's requested range to fit the MCP budget.

## Reference files — read as needed

Don't read these upfront. Read the one you need.

- `references/lrq-api.md` - the canonical Long Running Query API runner: auth, body schema, forward-tag routing, rate-limit strategy, 30-second query expiration, slicing/parallelism patterns, two-JWT round-robin to exceed the per-user rate cap. Read before writing any programmatic PQ runner, or when a query silently returns `matchCount=0`.
- `references/syntax-and-operators.md` — full operator reference, identifier rules, shortcut fields, regex dialect, date/time formats, short-circuit `||`.
- `references/commands-reference.md` — deep dive on every command (join variants, subqueries, lookup / dataset / savelookup, transpose, compare, top, nolimit). Read before writing anything non-trivial with join, transpose, or compare.
- `references/functions-reference.md` — all built-in functions: string, numeric, JSON, network, URL, aggregate, array (method chaining), geolocation, timestamp, time, string-formatting. Read when you need a function and can't remember the name.
- `references/fields-and-schema.md` — common EDR/XDR field paths (`src.process.*`, `tgt.file.*`, `event.login.*`, `dst.ip.*`, `indicator.*`, etc.) and OCSF conventions. Read when you're not sure what field holds the thing you want.
- `references/o365-fields.md`: Microsoft 365 / Exchange / Teams / SharePoint audit field shape, covering OCSF vs `unmapped.*` duality, fields that live only inside the JSON `message` blob, the discover-before-you-filter rule, send-style operations, RecordType, service-tier IP filtering, and investigation-noise separator. Read before writing any PQ against an M365 audit source.
- `references/detection-rules.md` — how to author PowerQuery Alerts / STAR / Custom Detection rule bodies, including the 1,000-row / 1 MB alert constraints and which PQ features are supported in alert context.
- `references/pitfalls.md` — curated list of common failures and their fixes (the `*`-as-filter trap, forgetting `|` before `join`, subquery position errors, memory-limit messages, `message contains` vs `* contains` on JSON-blob sources, and more).
- `references/automatic-lookups.md` — tenant-wide `/automaticLookups` enrichment that applies to every search and PowerQuery with no `| lookup` typed: config schema, the "output value fields must be unique across all specs" rule, the 100-row / 5 MB / 50-column limits, deploy-via-SDL-API flow, verified `lookup`/`dataset` gotchas, and a full Windows Event Logs SID-to-username worked example. Read when the user wants to add a lookup for SID/username (or any key) that everyone should see automatically, or asks about `/automaticLookups`.
- `references/datasource-command.md` — the `| datasource <name> [from <dataset>]` command for querying SentinelOne-managed inventory (Asset Inventory, Alerts, Vulnerabilities, Misconfigurations, Metering, SDL retention) that lives outside the event store. Covers datasource names, the `assets`/`metering` datasets, column discovery, time-series via `*_aggregated_snapshots`, and the tenant-validated specifics for asset enrichment: `from 'surface/identity'` vs sparse `from identity`, `from 'surface/endpoint'` vs sparse `from device`, single-quoting slash dataset names, empty-`riskFactors` (`"[]"`) suppression, and the `datasource ... | savelookup` pattern for building enrichment lookup tables. Read whenever the user asks about assets, identities, vulnerabilities, alerts inventory, or building an asset-enrichment lookup.

## Examples library — read when a hunt matches

- `examples/investigations.md` — ready-to-run investigation queries (PowerShell outbound, suspicious cmdline patterns, lateral movement, LOLBins, credential access, defense evasion, user-activity baselines, endpoint heartbeat, indicator prevalence). Each example includes a brief "what this finds" note and the full PQ.
- `examples/detection-library.md` — PQ bodies ready to paste into a STAR / Custom Detection / PowerQuery Alert, sized to stay within the 1,000-row/1 MB alert budget. Each entry names the MITRE technique and gives a `threshold` suggestion.
- `examples/behavioral-baselines.md` — statistical baselining recipes for any data source: per-day count slices, moving-average + stddev, z-score detection, silent-pair detection, day-of-week stratification. Read when the user asks to "baseline X behaviour", "detect anomalies in Y", "find users / hosts / IPs behaving differently than usual", or any equivalent. Source-agnostic, works on EDR, identity, network, cloud, email, or any custom log source.
- `examples/o365-email-hunting.md`: workflow recipes for the most common M365 audit hunts, covering discovery-first patterns, "did user X send mail" questions, per-day cadence, outbound external mail with recipient extraction, top recipient domains, DLP correlation, "user appears but never as actor" attribution gap, and identity-investigation-noise separation. Use whenever the hunt is against an M365 audit source.

## When to reach for join vs union vs subquery

These three blur together. Quick rules:

- **Subquery** (`field in (inner | columns field)`) — single-field "is this value in that set" filtering. Simplest and usually fastest. Use for allowlist / denylist / top-N-and-pivot patterns.
- **Join** — multi-field correlation where columns from both sides of a row must match each other (`on a.user = b.user, a.host = b.host`) *or* you need to bring extra columns from the second query into your output.
- **Union** — heterogeneous result sets that you want stacked as rows, possibly with rename/unification. Handy when the same logical event lives in two different log sources with different field names.

Prefer subqueries for exclusion/inclusion; reach for `join` when a row must "know" multiple things at once.

## Writing detection rules vs ad-hoc hunts

SentinelOne Custom Detection (STAR) rules come in three `queryType` flavors, all created at `POST /web/api/v2.1/cloud-detection/rules` with `queryLang: "2.0"`:

- **STAR single-event** (`queryType: "events"`): body is one boolean S1QL filter with NO pipes in `data.s1ql`, fires per matching event. Use for deterministic single-event signatures.
- **STAR multi-event / correlation** (`queryType: "correlation"`): `s1ql` empty, logic in `data.correlationParams` (entity + `subQueries[]` with per-query `matchesRequired` over a `timeWindow`). Use for thresholds (N of X) and A-then-B sequences.
- **Scheduled** (`queryType: "scheduled"`): a PowerQuery body (pipes allowed) in `data.scheduledParams.query`, runs on a schedule. Use for aggregation, baselines, and lookup/anti-join exclusions.

Only the **scheduled** type uses a PowerQuery body, and only it is bound by the constraints below. Single-event and correlation bodies are boolean S1QL (the same grammar as a PQ initial filter, no pipes).

A PowerQuery scheduled-rule body is more constrained than a hunt query:

- Intermediate and output tables must stay under 1,000 rows and 1 MB of RAM.
- No `nolimit`.
- No `compare`, usually no `transpose` (depends on version).
- The rule should produce one row per finding, with stable columns the detection engine can map to alert fields (e.g., `agent.uuid`, `endpoint.name`, `src.process.storyline.id`, `timestamp`).
- Keep the initial filter as specific as possible — this is what's evaluated in the summary service and is what gates cost.

For all three rule types (API shapes, the correlation `correlationParams` block, the events/correlation S1QL escaping rule), detection patterns, and a checklist, see `references/detection-rules.md` and `examples/detection-library.md`.

## A minimal but realistic example

Hunt: PowerShell that made an outbound connection to a non-RFC1918 IP in the last 24 hours, with command line.

```
src.process.name contains 'powershell' dst.ip.address = *
| let is_private = net_rfc1918(dst.ip.address)
| filter is_private = false
| group hits = count(),
        ips  = array_agg_distinct(dst.ip.address, 20),
        cmdline = any(src.process.cmdline)
  by endpoint.name, src.process.storyline.id
| sort -hits
| limit 50
```

Notice: filter early (`dst.ip.address = *` prunes events without a destination IP), `net_rfc1918` is the right way to split internal vs external (don't hand-roll CIDRs), `array_agg_distinct` caps the array so the row stays small, `any(src.process.cmdline)` grabs a representative cmdline since we're collapsing per storyline.


## PowerQuery execution via s1-secops-mcp

PowerQuery execution uses the `s1-secops-mcp` MCP tools, which bypass the Cowork sandbox
proxy entirely. Use `powerquery_run` and `powerquery_schema_discover` directly instead of
falling back to the `mgmt-console-api` skill scripts. The MCP tools run locally
on your machine and make direct HTTPS calls to `*.sentinelone.net` without proxy interference.
