# Query cost

Where PowerQuery time actually goes, and how to spend less of it. Every figure below is measured on
a live tenant, not inferred. Volumes are given as orders of magnitude because they are
tenant-specific; the ratios are the transferable part.

---

## 1. The cost hierarchy

Same 24-hour window, same tenant, same day:

| What you query | Rows scanned | Typical wall |
|---|---:|---:|
| A datatable, `dataset 'config://datatables/<name>'` | 10^2 | effectively 0 |
| An entity datasource with `count_by` pushdown | 10^1 pre-aggregated | ~1.3 s |
| `datasource metering` | 10^2 | ~6 s |
| Raw event lake, one day | ~9x10^8 | 5-18 s |
| Raw event lake, 15-30 days | ~10^10 | does not complete |

**Before optimising a lake query, check whether the answer already exists pre-aggregated.** A real
example: a dashboard was scanning ~9x10^8 events five times per tab load to compute numbers that
were already sitting in a 13-row datatable written by its own nightly job.

See `dashboard-performance.md` for the entity-datasource and `count_by` patterns.

---

## 2. Aggregation placement can invert the usual advice

"Filter early" is not always cheaper. A `lookup` before a `group` is evaluated **per event**; after
the `group` it is evaluated per group. Identical 1-day windows, byte-identical 15-row output:

| Shape | Wall |
|---|---:|
| `lookup` before `group`, plus `\| nolimit` | 118 s |
| `lookup` after `group`, no `\| nolimit` | 40 s |
| no `lookup` at all | 29 s |

The post-`group` form was faster **while scanning 4.8x more events**, because the join it avoided
cost more than the volume that join removed.

Two things to know before applying this:

- **After `group`, the source field no longer exists.** The join must key on the grouped alias
  (`entity_v`, not `dataSource.name`) or PQ returns `400 undefined field '<name>'`.
- **Only equivalent when the join key survives the `group` unchanged.** If the grouped alias is
  derived, a namespaced `"source / device"`, a `let` expression, the rewrite changes semantics and
  is not a mechanical substitution.

---

## 3. Window width is not a free parameter

`timebucket('1d')` is aligned to absolute UTC midnight. A window expressed as "the last N hours from
now" is not. A rolling window therefore only contains a **complete** day bucket if it reaches back
`run_hour + 24h`.

The consequence bites scheduled work: the width needed tracks the schedule. 26 h at 01:00, 39 h at
14:00. **Changing when a scheduled query runs silently changes how much it scans**, and can leave it
scanning no complete bucket at all.

Use absolute bounds instead. In Hyperautomation:

```text
startTime  {{Function.FORMATTED_DATE(Function.DELTA_NOW(24), "%Y-%m-%dT00:00:00Z")}}
endTime    {{Function.FORMATTED_DATE(Function.DATETIME_NOW(), "%Y-%m-%dT00:00:00Z")}}
```

Exactly 24 h of scan at any run hour.

---

## 4. Slice width, and why parallel can be slower

A baseline window too wide to complete has to be sliced. Measured sequentially, three sampled slices
per width, 15-day target window:

| Slice width | Slices needed | Completed | Mean per slice |
|---|---:|---:|---:|
| 1 day | 15 | 3/3 | 46 s |
| 2 day | 8 | first slice unfinished after ~20 min | n/a |

Narrower was both more reliable **and** faster overall, despite needing nearly twice the slices.

And the counter-intuitive part: **running slices concurrently made things worse.** Three concurrent
1-day slices took 334 s and two of them failed, against 213 s for a single 3-day query.

> Not a contradiction of the console dashboards, which fan many queries out in parallel very
> effectively. Those are ~1-2 s pre-aggregated entity queries. This finding is specific to
> concurrent multi-hundred-million-row scans of the event lake.

Guidance: slice narrow, run sequential, retry per slice, and give each slice a wall-clock deadline.

---

## 5. `savelookup` has its own budget

A query whose read half finishes can still die in the write:

```text
500 {"code":"internal_server_error",
     "message":"timeout prevented savelookup from completing"}
```

Re-polling never recovers this, the query is already dead server-side. **Retry means relaunch, not
re-poll.** A flow that retries the poll on 5xx will burn its whole budget achieving nothing.

---

## 6. Abandoned queries keep running

Killing a client does not stop an LRQ. It continues consuming backend capacity and starves later
queries on the same tenant. Always `DELETE /sdl/v2/api/queries/{id}` on any exit path that is not a
completion. The console does the same thing via `removeQuery`, roughly 0.9 calls per launch.

Related: **a poll-count budget is not a time budget.** Each poll can itself block for the client
timeout, so `max_polls x sleep` understates worst-case wall time badly. Scheduled work needs an
explicit wall-clock deadline.

---

## 7. Measuring honestly

These are not style points. Each one changed a conclusion that had already been drawn and written
down during the work that produced this file.

1. **Result caching will fake a speedup.** Running old-then-new once each produced an apparent 3.2x
   win. Re-measured over a fixed window, the same rewrite was **2.5x slower**. Use cold windows,
   alternate the order, take a median of at least three.
2. **A poll interval sets a measurement floor.** A 3 s first-poll sleep floors every result near 6 s.
   A 13-row datatable read and a 9x10^8-row scan both measured ~6 s until the interval dropped to
   0.4 s, at which point they separated to 3.5 s and 10.5 s.
3. **Tenant load variance can exceed the effect being measured.** The identical query measured 6.8 s
   and 18.0 s in different repetitions on the same day. A single sample is not evidence.
4. **`estimate_distinct` error is material at scale.** Measured 45,622 against a true 46,668 distinct
   (zero duplicates, verified exactly with `group count() by <key> | filter count > 1`), a 2.2 %
   undercount. Use it for magnitude only. Never to prove uniqueness or reconcile a row count.
