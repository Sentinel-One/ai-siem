# PowerQuery efficiency dashboard

Monitors how well a single PowerQuery performs, using the data lake's own
query-audit telemetry. Nothing needs to be ingested or parsed — AI SIEM writes
this telemetry into **All Data** itself.

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
`lrqToken`; **Stage detail** lists the stages individually.

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
broken panel. Use the **Origin** parameter to compare like with like.

Two further limits worth knowing:

- **`ERROR` events carry no error message.** `outcome='ERROR'` and
  `success=false` are recorded, but no message/exception field exists on the
  event. The Errors panel therefore shows *which* query failed, when, for whom
  and over what window — not *why*. The query text in `filter` is the lead.
- **Not every interface is audited.** Queries issued against the DataSet-style
  `POST /api/powerQuery` endpoint with a log-read key did not produce
  `queryOutcome` events during testing, while console and v2-API queries did.
  Treat this dashboard as covering console + v2-API traffic.

## Reading it

**Bytes per matched event** is the headline inefficiency signal: bytes read
divided by events returned. A high value means the query scanned a lot to
return little — usually a missing index-friendly predicate, or a time range far
wider than needed (cross-check `window_mins`). The **Worst selectivity** table
ranks executions by exactly this.

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
