# PowerQuery recipes for UAM indicators and alerts

Tested on `your-tenant` 2026-04-22 (Singularity Data Lake behind the
same console). These recipes cover the queries SecOps pre-sales most
often needs when proving UAM / XDR telemetry end-to-end: indicator
prevalence, outbound command-and-control, login-failure triage, and
storyline rollups. Each recipe states what it finds, the fields it
relies on, and the PowerQuery body. Paste into Event Search, the
PowerQuery Alerts composer, or run through the Purple MCP
`powerquery` tool.

For the PowerQuery language reference, see the `sentinelone-powerquery`
skill. The conventions below (filter early, group narrow, explicit
field names over shortcuts) match that skill's guidance.

## 1. Indicator prevalence across the fleet

What it finds: every OCSF indicator ingested in the time range, with
the most-frequently-seen indicator name and where it was seen.
Useful for "how noisy is our UAM feed" and for spotting synthetic
indicator floods from pre-sales demos.

```
event.type = 'IndicatorEvent'
| group hits = count(),
        endpoints = count_distinct(endpoint.name),
        sites = count_distinct(site.id),
        last_seen = max(timestamp)
  by indicator.name, indicator.category
| sort -hits
| limit 50
```

Notes: `indicator.name` and `indicator.category` are the OCSF-mapped
fields surfaced by the UAM ingestion path. `count_distinct` on
`endpoint.name` is cheap and more accurate than `count_distinct` on a
high-cardinality UUID field.

## 2. PowerShell reaching public IPs (outbound C2 hunt)

What it finds: PowerShell processes that opened a connection to a
non-RFC1918 IP in the time range. Classic C2 / living-off-the-land
beaconing pattern.

```
src.process.name contains 'powershell' dst.ip.address = *
| let is_private = net_rfc1918(dst.ip.address)
| filter is_private = false
| group hits = count(),
        dst_ips = array_agg_distinct(dst.ip.address, 20),
        cmdline = any(src.process.cmdline)
  by endpoint.name, src.process.storyline.id
| sort -hits
| limit 50
```

Notes: `net_rfc1918()` is the correct way to split internal vs
external -- don't hand-roll CIDRs. `array_agg_distinct(..., 20)` caps
the list so a single row stays under the row-size budget. Grouping on
`src.process.storyline.id` collapses per storyline instead of
per-event, which is usually what you want.

## 3. Failed logins by endpoint + source IP

What it finds: authentication failures bucketed by target endpoint
and source address. Good for lateral-movement / password-spray
triage; the `count_distinct(src.ip.address)` column lets you rank by
"one attacker hitting many boxes" vs "noise".

```
event.type = 'LoginEvent' event.login.loginIsSuccessful = false
| group fails = count(),
        distinct_users = count_distinct(event.login.userName),
        distinct_srcs = count_distinct(src.ip.address),
        last_fail = max(timestamp)
  by endpoint.name, src.ip.address
| sort -fails
| limit 100
```

Notes: the correct field is `event.login.loginIsSuccessful` (NOT
`event.login.isSuccessful` -- that returns null on every tenant).
Pair with `#ip = '<src>'` (the `#ip` shortcut) for single-IP
pivoting in Event Search, but keep `src.ip.address` for scripted /
API use because shortcuts 500 on some tenants.

## 4. Storyline activity summary

What it finds: per-storyline rollup of event counts, processes
launched, files touched, and destinations contacted. This is the
"what did this attack actually do" one-liner that SOC analysts want
when they open a UAM alert.

```
src.process.storyline.id = *
| group events = count(),
        procs = count_distinct(src.process.name),
        files_touched = count_distinct(tgt.file.path),
        distinct_dst_ips = count_distinct(dst.ip.address),
        first_seen = min(timestamp),
        last_seen = max(timestamp),
        endpoints = array_agg_distinct(endpoint.name, 10)
  by src.process.storyline.id
| sort -events
| limit 50
```

Notes: the explicit initial filter `src.process.storyline.id = *`
prunes events that have no storyline, which otherwise collapse into
one giant "null" bucket. `array_agg_distinct(endpoint.name, 10)`
caps the list to 10 unique endpoints per storyline, which is plenty
for triage and keeps row size small.

## 5. Find a specific indicator by name (UAM -> SDL crosscheck)

When you've ingested an indicator via `UAMAlertInterfaceClient.post_indicators`
and want to confirm it landed in the data lake (not just in the UAM
console), grep for it by name or by the `run_tag` substring your
smoke test bakes in.

```
indicator.name = *
| filter indicator.name contains 'smoke-' OR message contains 'smoke-'
| columns timestamp, indicator.name, indicator.category,
          endpoint.name, event.type, message
| sort -timestamp
| limit 100
```

Notes: `indicator.name = *` as the initial filter avoids the
bare-`*`-doesn't-work pitfall. Put the `contains`-based refinement in
a `| filter` step so the intent is obvious.

## 6. Endpoint heartbeat (are agents reporting?)

What it finds: for each endpoint, the most recent event and the gap
vs now. Useful when a pre-sales demo's test VM has gone offline and
you need to prove it before blaming the product.

```
endpoint.name = *
| group last_seen = max(timestamp), events = count()
  by endpoint.name, endpoint.uuid
| let gap_seconds = (now() - last_seen) / 1000
| sort -gap_seconds
| limit 50
```

Notes: `now()` returns a ms-epoch timestamp, so divide by 1000 to
report seconds. A gap > 3600 is worth investigating.

## Using these from Python

All four recipes run against the `powerQuery` SDL endpoint. With the
`sentinelone-sdl-api` skill's client:

```python
from sdl_client import SDLClient
c = SDLClient()  # picks up SDL_LOG_READ_KEY (or S1_CONSOLE_API_TOKEN) from credentials.json
r = c.powerQuery(
    query="src.process.name contains 'powershell' dst.ip.address = * "
          "| let is_private = net_rfc1918(dst.ip.address) "
          "| filter is_private = false "
          "| group hits = count() by endpoint.name "
          "| sort -hits | limit 50",
    startTime=int(time.time() - 3600) * 1000,
    endTime=int(time.time()) * 1000,
)
```

For natural-language query generation, use the Purple MCP
(`mcp__purple-mcp__purple_ai`). The `purple_query()` Python helper is
non-functional for API tokens (requires browser-session teamToken;
confirmed SERVICE_ERROR 2026-05-03). The Purple MCP handles both the
NL-to-PQ step and execution.

## Field reference quick-glance

For the full schema, see the `sentinelone-powerquery` skill's
`references/fields-and-schema.md`. The fields used above:

- `event.type` -- OCSF event class (`LoginEvent`, `ProcessEvent`,
  `IndicatorEvent`, `FileEvent`, etc.)
- `endpoint.name` / `endpoint.uuid` -- the agent
- `src.process.name` / `src.process.cmdline` / `src.process.storyline.id`
- `dst.ip.address` / `src.ip.address`
- `event.login.userName` / `event.login.loginIsSuccessful`
- `indicator.name` / `indicator.category`
- `tgt.file.path` / `tgt.file.sha256`
- `message` -- free-form, always searchable with `$"regex"` shorthand
  in the initial filter

## `| group` syntax reference

The `| group` pipe aggregates rows. All grouping fields must be inside
an aggregation function — bare field names after `by` are NOT valid
and return a parse error ("Field must be enclosed in a grouping function").

### Forms

```
| group function(expression), function2(expression2)
| group function(expression) by expression3, expression4, …
| group name=function(expression) by name3=expression3, name4=expression4, …
```

### Supported aggregation functions

| Function | Notes |
|---|---|
| `count()` | row count |
| `sum(x)` | sum of x |
| `avg(x)` | arithmetic mean |
| `min(x)` / `max(x)` | extremes |
| `median(x)` | 50th percentile |
| `pct(x, N)` | Nth percentile (0-100) |
| `p10(x)` / `p50(x)` / `p90(x)` / `p99(x)` / `p999(x)` | fixed percentile shortcuts |
| `stddev(x)` | standard deviation |
| `any(x)` | any non-null value of x |
| `any_true(x)` | true if any x is truthy |
| `all_true(x)` | true if all x are truthy |
| `estimate_distinct(x)` | HLL cardinality estimate |
| `first(x)` / `last(x)` | first/last by arrival order |
| `oldest(x)` / `newest(x)` | first/last by timestamp |
| `max_by(x, y)` / `min_by(x, y)` | value of x at the row where y is max/min |
| `array_agg(x, N)` | collect up to N values of x |
| `array_agg_distinct(x, N)` | collect up to N distinct values of x |

### Examples

```
| group count() by event.type
| group hits=count() by event.type
| group hits=count(), last=max(timestamp) by event.type
| group hits=count() by day=timebucket('1d'), event.type
| group endpoints=estimate_distinct(endpoint.name) by indicator.name
| group ct=count(), cmdlines=array_agg_distinct(src.process.cmdline, 10) by endpoint.name
```

### What NOT to do

```
# Wrong — bare field after by without aggregation wrapper:
| group count = count() by event.type | sort count desc   ← alias collision
| group event.type by count()                              ← reversed
```

Sort references must use the output column name (the alias you gave it):
```
| group hits=count() by event.type | sort -hits   ← correct
| group count() by event.type | sort -count       ← correct (implicit alias = function name)
```

## Common pitfalls

- `*` alone as initial filter returns 500 on this tenant. Use
  `event.type = *` or start with `|` (empty initial filter).
- Double-escape regex: `matches "\\\\.exe$"` matches `.exe`.
- `contains` with a tuple of many items sometimes 500s -- use `in (...)`
  or split into multiple `OR` clauses.
- `percentile(x, N)` is not a real function; use `p50(x)`, `p95(x)`,
  `p99(x)`.
- After `| group` or `| columns`, previous fields are gone. Carry
  anything you need forward inside the `group`/`columns` call.
