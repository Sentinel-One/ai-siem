# Solution: Query Slicing

Long-window PowerQueries are slow because one query is one backend execution: a 30-day aggregate
takes 20 to 40 seconds, and heavier ones time out. Query slicing splits the window into slices,
runs them in parallel through the Long Running Query (LRQ) API and merges the results on the
client. The same 30-day aggregate comes back in about 5 seconds with identical totals.

This is part of the `sdl-solutions` skill. Playbook:
[`sdl-solutions/references/query-slicing.md`](../../skills/sdl-solutions/references/query-slicing.md).
Runner: the `powerquery_run` MCP tool with `slices` (2-15) and `merge`, which works from Cowork.
A host-only Python runner, `sdl-solutions/scripts/lrq_sliced.py` (standard library only), does the
same from a terminal.

## Measured (platform S-26.3.4, 2026-10-05, one token)

| 30 days, 14.1M events | Wall clock |
|---|---|
| 1 query | 21 s to 40 s |
| 15 slices of 2 days, in parallel | about 5 s |
| 30 slices of 1 day, in parallel | 10 s |

A broad 90-day count (43.9M events, no source filter) took 12 s as 15 slices and 18 s as one query.
On this tenant no long window failed to complete; scan cost grows with tenant volume, which is why
slicing is the default for any mergeable aggregate over 24 hours.

- One token sustains about 30 calls/s; only query launches are throttled, from about 35 calls/s.
- About 15 queries in flight is the sweet spot. More is slower.

## How to ask for it

- "Count FortiGate events per source IP over the last 30 days, it keeps timing out"
- "Run this hunt over 90 days"
- "Why is my 30-day query so slow?"

The skill checks the query can be merged (counts, sums, mins and maxes can; distinct counts,
averages and percentiles cannot), picks the slice plan, runs it, and returns the merged result
with the run statistics.

## Run it yourself

Through the MCP server (any MCP client):

```json
{
  "query": "dataSource.name='FortiGate' | group n=count() by src_ip",
  "hours": 720,
  "slices": 15,
  "merge": { "keys": ["src_ip"], "sum": ["n"] }
}
```

From a terminal on your machine, with `S1_CONSOLE_URL` and `S1_CONSOLE_API_TOKEN` in the OS keychain
(`s1-secops-mcp setup`) or the environment:

```bash
python3 sdl-solutions/scripts/lrq_sliced.py \
  --query "dataSource.name='FortiGate' | group n=count() by src_ip" \
  --days 30 --keys src_ip --sum n --limit 100
```

## What can be sliced

| Aggregate | Merge |
|---|---|
| `count()`, `sum()` | add |
| `min()` / `max()` | min of mins / max of maxes |
| raw rows | append |
| `estimate_distinct`, `avg`, percentiles, `top` | not mergeable: run unsliced, or rebuild from mergeable parts (`avg = sum / count`) |

Both runners refuse a non-additive aggregate, so a distinct count is never summed by accident.
