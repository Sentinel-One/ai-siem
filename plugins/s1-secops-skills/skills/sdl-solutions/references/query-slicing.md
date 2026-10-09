# Playbook: Query Slicing

Run a long-window PowerQuery fast by splitting the time range into slices, running them in
parallel through the LRQ API and merging the results client-side. Triggers: "this query is slow",
"run this over 30 / 90 days", "the query times out", "speed up my hunt / report / baseline",
"slice this query", "parallelise this query".

**Primary path: the `powerquery_run` MCP tool** from `s1-secops-mcp`, with `slices` (2-15) and a
`merge` spec. It runs on the user's machine, so it works from Cowork. The zero-dependency Python
runner `scripts/lrq_sliced.py` is the host-only equivalent (Claude Code, a terminal, or a deployer
that vendors it as is).

## Why (measured, S-26.3.4, 2026-10-05, one service-user token, one egress IP)

| 30-day `\| group n=count() by dataSource.name`, 14.1M events | Wall clock |
|---|---|
| 1 query | 21 s to 40 s |
| 7 slices in parallel | 4.7 s to 5.0 s |
| 15 slices (2 days each) in parallel | 4.9 s to 5.2 s |
| 30 slices (1 day each) in parallel | 10.2 s |

Longer and broader windows, same day, `| group ct=count()` with no source filter (s1-event-search's
own count path, cache off):

| Window | 15 slices | 1 query |
|---|---|---|
| 15 days, 6.1M events | 3.2 s | 5.5 s |
| 30 days, 13.4M events | 4.2 s | 12.4 s |
| 90 days, 43.9M events | 12.0 s | 18.1 s |

Every case completed, sliced or not. The older "15 to 30 days does not complete" figure was inferred
from row counts on a high-volume tenant and is not reproduced here; treat long windows as a cost
that grows with tenant volume, and slice whenever the aggregate merges.

Merged totals matched the single query every time. The cache-free re-run launched the slices
before the single query, so the slice timings are not riding on cached results.

The limits the runner is built around, from the same session:

- One token sustains about **30 calls/s** (launch, poll and cancel all count) with no 429s. 429s
  start near 35 calls/s and hit **only launches**; polls and cancels were never throttled. The old
  "3 requests/s per user" figure does not apply, and a second token is not needed for speed.
- Past about 15 to 20 queries in flight it gets slower again: more launches meet the throttle and
  each slice still pays a fixed backend cost.
- A query expires 30 s after launch or after its last poll. Many short queries are already
  complete in the launch response.

## Defaults

| Window | Slices | In flight | Expected |
|---|---|---|---|
| 24 h or less | 1 (no slicing) | 1 | under 5 s |
| 7 days | 7 x 1 day | 7 | about 5 s |
| 30 days | 15 x 2 days | 15 | about 5 s |
| 90 days | 30 x 3 days (Python runner) or 15 x 6 days (`powerquery_run`, max 15) | 15 | about 10 to 15 s |

Rate: token bucket at **25 calls/s per token**. Launch 429: exponential backoff from 0.5 s with
jitter, honouring `Retry-After`, up to 8 attempts. HTTP 400 is the query: fail the run, never
retry. Every query is cancelled when it finishes or fails. The host-only Python runner also splits
a slice still running after 120 s in two and re-runs it (down to 15 minutes); `powerquery_run`
does not, so raise `slices` if one slice dominates.

## Which queries can be sliced

Slicing re-aggregates per-slice results, so it is exact only for aggregates that combine:

| In the query | Across slices | `powerquery_run` `merge` | Python runner option |
|---|---|---|---|
| `count()`, `sum(x)` | add | `sum` | `--sum` |
| `min(x)` | min of mins | `min` | `--min` |
| `max(x)` | max of maxes | `max` | `--max` |
| group keys | match rows on them | `keys` | `--keys` |
| raw rows / `columns` | append | omit `merge` (rows are concatenated) | `--concat` (cap with `--limit`) |
| `estimate_distinct`, `avg`, `p50`/`p95`/`p99`, `percent_of_total`, `\| top K`, `savelookup` | **not mergeable** | refused | run unsliced, or compute from mergeable parts (`avg = sum / count`) |
| `\| limit N` inside the query | each slice keeps its own top N; the merged result can miss keys | with `merge`, a trailing `\| limit` after the last `\| group` is stripped from the slices and applied after the merge | raise N per slice, or drop it and cap with `--limit` |
| `\| sort` | per slice only | with `merge`, a trailing `\| sort` is applied after the merge | sort after the merge |
| any other command after the last `\| group` | cannot be merged | refused | run unsliced |

Both runners refuse a non-additive aggregate, so a non-additive column cannot be summed by
accident. `savelookup` is never sliced: every slice would overwrite the same table.

Time-bucketed queries (`timebucket`) slice cleanly when slice edges fall on bucket edges: slice a
30-day daily series into 15 x 2-day slices, not 7 uneven ones.

## Run it

With the MCP tool (Cowork, Claude Desktop, Claude Code, any MCP client):

```json
{
  "query": "dataSource.name='FortiGate' | group n=count(), first=min(timestamp), last=max(timestamp) by src_ip",
  "hours": 720,
  "slices": 15,
  "merge": { "keys": ["src_ip"], "sum": ["n"], "min": ["first"], "max": ["last"] },
  "outputFile": "/Users/<you>/Documents/outputs/fortigate_30d_by_src_ip.csv"
}
```

The response carries the merged rows (or, with `outputFile`, a summary plus a 5-row preview) and
per-slice stats. Add `edrStrict: true` on SentinelOne EDR queries so a mistyped field fails with
HTTP 400 instead of returning nothing. With `queryType: "LOG"`, slicing also spreads the 5000-event
server cap: `anySliceTruncated: true` means at least one slice hit the cap, so raise `slices` or
narrow the filter.

With the host-only Python runner (Claude Code or a terminal on the user's machine; it reads
`S1_CONSOLE_URL` and `S1_CONSOLE_API_TOKEN` from the environment or the OS keychain, never from a
command line):

```bash
python3 sdl-solutions/scripts/lrq_sliced.py \
  --query "dataSource.name='FortiGate' | group n=count(), first=min(timestamp), last=max(timestamp) by src_ip" \
  --days 30 --slices 15 --workers 15 \
  --keys src_ip --sum n --min first --max last --limit 100
```

Output is JSON: `columns`, `values` (merged, sorted by the first `--sum` column), `matchCount`
(summed), and `stats` (`slices`, `calls`, `launches`, `launch_429`, `splits`, `wall_s`). Add
`--edr-strict` on SentinelOne EDR queries so a mistyped field fails with HTTP 400 instead of
returning nothing; `--account-ids` scopes the query explicitly (`tenant: true` spans every
account the token can reach, all of them on a global or multi-account token).

As a library:

```python
from lrq_sliced import LRQClient, run_sliced, Merge
c = LRQClient(console_url, token)                       # 25 calls/s, shared by all slices
res = run_sliced(c, query, start, end, slices=15, workers=15,
                 merge=Merge(keys=["src_ip"], sum=["n"], min=["first"], max=["last"]))
```

## Validate

The runner itself, live on 2026-10-05: `| group n=count() by dataSource.vendor` over 30 days ran in
19.7 s as one slice and 5.3 s as 15 slices, zero launch 429s, the same 19 rows, totals 14,131,733
vs 14,131,685 (the window moved between runs).

1. Run the query unsliced once over a short window and sliced over the same window; the merged
   result must equal the unsliced one.
2. With the Python runner, check `stats.launch_429` stays near zero. If it climbs, lower
   `--workers` before lowering `--rps`: concurrency is what the throttle answers to.

## Gotchas

- **One client per token, shared by every slice.** Separate clients each get the full rate and
  together exceed it.
- **A slice is bound to the forward tag of its own launch.** Poll and cancel with that tag only.
- **Scope every slice explicitly.** `tenant: true` spans every account the token can reach, and
  the `S1-Scope` header does not narrow a multi-account token. Pass `account_ids` (Python) or a
  `scope` (MCP, 1.5.3+, which sends `tenant: false` + `accountIds` on every slice) for one
  account.
- **The SDL per-IP limit (60 burst / 30 req/s, published for 2026-09-10) covers this host too.**
  It was not enforced when measured, which is one more reason to stay at 25 calls/s.
