# PowerQuery efficiency dashboard

Monitors how well PowerQueries perform, using the data lake's own
query-audit telemetry. Nothing needs to be ingested or parsed — AI SIEM writes
this telemetry into **All Data** itself.

Organized into three tabs:

- **Overview** — five headline numbers (executions, p95 execution time, an
  error-rate gauge, bytes scanned, bytes per matched event) plus execution
  time and bytes-scanned trends.
- **Query Anatomy & Optimization** — what the matched queries are made of
  (a construct-usage donut: grouping / sorting / limiting / exclusions /
  transforms / joins), a selectivity-tier donut (good/fair/poor bytes-per-event),
  a bytes-scanned-by-origin breakdown, an origin × time heatmap of the
  heaviest scans, and a ranked worst-selectivity table.
- **Troubleshooting & Errors** — the full per-execution table (slowest
  first), a dedicated errors table, and raw stage-by-stage detail.

## The data source

All panels are scoped to `tag='queryOutcome'`. Field set, confirmed against a
live tenant:

| Field | Meaning |
|---|---|
| `lrqToken` | UUID of one query **execution** |
| `filter` | the query text as submitted, comments included |
| `queryPurpose` | which interface issued it (see coverage note) |
| `elapsedTimeMs` | wall-clock time for this stage |
| `cpuUsageMs` | CPU burned |
| `coverBytes` | bytes scanned |
| `matchCount` | events returned |
| `outcome` / `success` | `OK` \| `ERROR` / `true` \| `false` |
| `timeSpanMins`, `ageMins` | width and age of the time range queried |
| `userEmail`, `site.id`, `teamEmails` | who ran it, where |

One execution emits **several** `queryOutcome` events — one per internal stage —
all sharing the same `lrqToken`. Panels describing *an execution* group by
`lrqToken`; **Stage detail** (Troubleshooting tab) lists the stages individually.

## Identifying a PowerQuery

There is no tenant-wide stable ID for a saved PowerQuery in this telemetry, so
the `pq_id` parameter accepts either of two forms and matches on both:

```
(lrqToken=='#pq_id#' || filter contains '#pq_id#')
```

- **One execution** — paste an `lrqToken`, e.g. `94136d52-9382-4c0b-b59e-d3365c635de7`.
- **The same query across every run** — append a marker comment to the query you
  want to watch and type the marker here:

  ```
  dataSource.name='Okta' | group n=count() by user //pqid:OKTA_USER_ROLLUP
  ```

  then set `pq_id` to `pqid:OKTA_USER_ROLLUP`. Comments are stored verbatim in
  the audited `filter` field, so the marker is searchable. (Verified: the
  platform's own internal stages are already tagged this way — their stored
  `filter` ends in `//powerSummary`.)

- **Leave it empty** to see every query in the account.

Leaving `pq_id` empty matches everything because `filter contains ''` is true for
all events. The substitution is textual — don't type a quote character into the box.

## Narrowing by origin

The `purpose` parameter filters to one `queryPurpose` value (`queryPurpose=#purpose#`),
defaulting to `*` (all origins). **Gotcha:** changing the dropdown does not
auto-refresh the panels — pick a value, then press **Search**.

## Coverage caveat — read this before filing a bug

`coverBytes` and `cpuUsageMs` are populated only for search-backed origins.
Measured over 7 days on one tenant:

| `queryPurpose` | events | bytes scanned |
|---|---:|---|
| `v2_api_queries/pq` | 77 | populated |
| `Search Query Power Query` | 86 | populated |
| `Search Query` | 27 | populated |
| `Graph` | 3 | populated |
| `Power Query` (console explorer stages) | 238 | **always 0** |
| `ui_console_dashboard/pq` | 9 | **always 0** |

A zero in **Bytes scanned** for a console-explorer query is the platform, not a
broken panel. Use the **purpose** parameter to compare like with like.

Two further limits worth knowing:

- **`ERROR` events carry no error message.** `outcome='ERROR'` and
  `success=false` are recorded, but no message/exception field exists on the
  event. The Errors panel therefore shows *which* query failed, when, for whom
  and over what window — not *why*. The query text in `filter` is the lead.
- **Not every interface is audited.** Queries issued against the DataSet-style
  `POST /api/powerQuery` endpoint with a log-read key did not produce
  `queryOutcome` events during testing, while console and v2-API queries did.
  Treat this dashboard as covering console + v2-API traffic.

## Reading the Anatomy tab

**Query anatomy** classifies each matched execution by which constructs its
submitted text uses — grouping, sorting, limiting, exclusions (`!=`, `!(`,
`not`), transforms (`| let`), and joins/reshapes (`| transpose`, `| join`).
An execution can use more than one construct, so slices add up to more than
100% of executions, not 100% of a single query's characters — this product's
PowerQuery dialect has no confirmed string-length function to measure a
precise "% search text vs. % modifiers" split, so construct presence is used
as a practical proxy instead.

**Selectivity tiers** buckets executions by bytes scanned per matched event
into illustrative Good (<1KB/event) / Fair (<100KB/event) / Poor (>=100KB/event)
bands — adjust the thresholds in the `.conf` if they don't fit your tenant's
data volumes.

**Bytes scanned — origin × time** is a heatmap of origin vs. time, not
per-`lrqToken` — `lrqToken` values are opaque UUIDs, which make unreadable
heatmap row labels. For a per-execution ranking, use the **Worst selectivity**
table instead (same tab), which has an inline bar for quick comparison.

## Installing

Import the `.conf` through the console (**Dashboards → New → Import**), or via
the config API:

```bash
curl -X POST "https://<your-sdl-host>/api/createFile" \
  -H "Authorization: Bearer $CONFIG_WRITE_KEY" \
  -H "Content-Type: application/json" \
  -d "{\"path\":\"/dashboards/PowerQuery-efficiency\",\"content\":$(python3 -c 'import json;print(json.dumps(open("PowerQuery-efficiency.conf").read()))')}"
```

The dashboard's own default window is 24h; the console time picker overrides it.
