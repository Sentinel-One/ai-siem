# SDL API method reference

Every method is a JSON `POST` to `{base_url}/api/<method>` unless noted. All
requests send `Authorization: Bearer <token>` and `Content-Type: application/json`. The `status` property of every
response uses a slash-delimited hierarchy; `success` prefix = OK,
`error/client` prefix = caller bug, `error/server` prefix = retry.

The rows below refer to client methods on `SDLClient` (in `scripts/sdl_client.py`)
and CLI subcommands (in `scripts/sdl_cli.py`).

---

## Ingestion (moved to HEC)

SDL raw-log ingestion (`uploadLogs`, `addEvents`) has been removed from this skill. Ingest raw logs/events via the **HEC ingest** path (HTTP Event Collector on the ingest host, with a named `parser`), which feeds Event Search, PowerQuery, and detection rules. UAM alert/indicator creation is separate and lives in `mgmt-console-api` (`uam_*`, posted to `/v1/*` on the same ingest host but a distinct API). This skill now covers queries and configuration files only.

---

## Log read (queries)

All five methods consume the CPU leaky bucket described in `auth_and_limits.md`.
`cpuUsage` is returned on success as a rate-limiting signal.

### `query` — `c.query(filter="", ...)` / `c.iter_query(...)` — CLI `query`

**DEPRECATED.** The V1 `/api/query` endpoint sunsets on 2027-02-15. For log search in new code use the LRQ API with `queryType: "LOG"` - async, cursor-paged to unlimited rows, survives long windows. See the `powerquery` skill's `references/lrq-api.md`. This method is fine for legacy one-offs until the sunset date.

Event search. Filter syntax matches the UI search bar.

Params:
- `filter` (string): search expression (e.g. `status >= 400 status < 500`). Escape `"` with `\"` when embedding in JSON.
- `startTime` / `endTime`: UI time syntax (`"1h"`, `"24h"`, `"10/27 4 PM"`) or epoch sec/ms/ns. `startTime` inclusive, `endTime` exclusive. Omit both for past 24h.
- `maxCount`: 1..5000, default 100.
- `pageMode`: `head` (oldest first) | `tail` (newest first).
- `columns`: comma-separated field allow-list to shrink response.
- `continuationToken`: page beyond maxCount; pass the token from the previous response. Pin start/end to absolute times when paging to avoid drift.
- `priority`: `low` (default, generous bucket) | `high` (stricter).
- `teamEmails` / `tenant` / `accountIds`: cross-team/multi-account (console tokens only for `tenant`/`accountIds`).

Response shape:

```json
{
  "status": "success",
  "matches": [
    {"timestamp": "nanoseconds", "message": "...", "severity": 3, "session": "...", "thread": "...", "attributes": {...}}
  ],
  "sessions": {"sessionId": {"serverHost": "...", ...}},
  "cpuUsage": 12,
  "continuationToken": "..."
}
```

`matches` is ascending by timestamp regardless of pageMode. A `continuationToken` can appear even when no more matches exist.

Use `c.iter_query(...)` to iterate across pages automatically.

---

### `powerQuery` — `c.power_query(query, ...)` — CLI `power-query`

**DEPRECATED.** The V1 `/api/powerQuery` endpoint at `xdr.us1.sentinelone.net` sunsets on 2027-02-15. New code should route PowerQueries through the **Long Running Query API** at `POST /sdl/v2/api/queries` on the tenant's own console host. LRQ is async, has higher row/rate limits, parallelizes cleanly across time slices, and is the only path that stays supported after the sunset date. Canonical runner, body schema, auth, and gotchas live in the `powerquery` skill at `references/lrq-api.md`. This method is kept here only for legacy one-offs and to round out the 10-method SDL surface.

Full pipeline query language (S1QL-style). `query` is limited to 10K chars; escape `"` with `\"`.

Times default to past 24h if both omitted.

Response:

```json
{
  "status": "success",
  "matchingEvents": 123,
  "omittedEvents": 0,
  "columns": [{"name": "col1"}, {"name": "col2"}],
  "values": [[v1, v2], [v1, v2]]
}
```

Cells may be `null`, `true`, `false`, number, string, or `{"special": "+infinity"|"-infinity"|"NaN"}`.

PQ extends with `datasource` (from S-24.2.6) to read outside Singularity, e.g. `| datasource "metering" from "reports"` for Usage Metering tables (`tenants`, `reports`, `report_name`).

#### Usage Metering reports

Usage Metering (cost / usage / MSSP chargeback) is reached through the `datasource "metering"` generator, not a dedicated REST endpoint. Source: Community article 000010750, supported from S-24.2.6.

- **Permission:** `Metering Reports - View` is required (default on C-Level and Admin roles; can be added to custom roles). Without it the query returns no data.
- **Datasets:** `tenants` (visible tenants), `reports` (available report names + metadata), and `<report_name>` for raw rows of one report (e.g. `server_endpoints`). List names via `from "reports"` before querying a specific report.
- **Run it through LRQ, not the deprecated path.** The Community doc shows `POST /sdl/api/powerQuery`, which is the V1 endpoint that sunsets 2027-02-15. The `datasource` generator works in any PQ runner, so route metering queries through the Long Running Query API (`POST /sdl/v2/api/queries`, `queryType: "PQ"`, query in `pq.query`) like every other PowerQuery in this skill.
- **Rate limit:** metering datasource calls are capped at **50 rps with a 100-request burst** (see `auth_and_limits.md`).
- **Drilldown filter:** append normal PQ to post-process the returned rows:

```
| datasource "metering" from "server_endpoints" | filter endpoint_bundle in ('Core', 'Complete')
```

Key response columns include `calculation_time`, `date`, `timestamp`, `Console_id/hostname`, `Account_scope_*`, `Site_scope_*`, `tenant_scope_*`, `tenant_id/name`, the `organization_level_{0,1,2}_*` hierarchy, `environment`, `cloud_region`, `cloud_provider`, plus report-specific fields. Full column reference and authoring help: the `powerquery` skill, `references/datasource-command.md`.

For query authoring, use the `powerquery` skill, it knows the
field taxonomy and pipe grammar.

---

### `facetQuery` — `c.facet_query(field, ...)` — CLI `facet-query`

Top-N most frequent values of `field` for events matching `filter`.

Params: `field` (required), `filter` (optional), `startTime` (required), `endTime`, `maxCount` (1..1000, default 100), `priority`.

Response:

```json
{
  "status": "success",
  "values": [{"value": "...", "count": 100}, ...],
  "matchCount": 1000,
  "cpuUsage": 12
}
```

`values` is sorted by count desc. For very large result sets, values are a sampled
subset from at least 500K matching events.

---

### `timeseriesQuery` — `c.timeseries_query(queries=[...])` — CLI `timeseries-query`

Bucketed numeric data; multi-query per request. Each entry in `queries` may
include: `filter`, `function` (`count` | `rate` | `mean(field)` | ...),
`startTime`, `endTime`, `buckets`, `createSummaries`, `onlyUseSummaries`,
`priority`, plus cross-team fields.

`createSummaries` (default `true`): create a precomputed timeseries for this
query. Backfill begins in 2–3 minutes, ~2 months/hour. Subsequent matching
queries become near-instant.

`onlyUseSummaries` (default `false`): fail over to zeros if no precomputed
series exists — guarantees fast/cheap response but may be incomplete until
backfill finishes.

Novel query budget: >100 novel (uncached) queries/hour triggers rate limits.
Using `* contains` / `* matches` to scan all fields is not optimised.

Response:

```json
{
  "status": "success",
  "results": [
    {"values": [n, n, n], "cpuUsage": 5, "foundExistingSeries": true}
  ]
}
```

`values.length == buckets`; a value is `null` if undefined (e.g. mean over an empty bucket).

---

### `numericQuery` — `c.numeric_query(...)` — CLI `numeric-query`

Effectively superseded by `timeseriesQuery` with `createSummaries=false` and
`onlyUseSummaries=false`. Keep it for two reasons:
1. Users whose role cannot call timeseriesQuery can still call this.
2. Sub-30-second bucket granularity (timeseries min is 30s).

Params: `function` (required; `count` | `rate` | aggregation), `filter`,
`startTime` (required), `endTime`, `buckets` (1..5000, default 1), `priority`.

Response: `{"status": "success", "values": [n, n, ...], "cpuUsage": 12}`.
`values.length == buckets`.

---

## Configuration files

Config files back every SDL customisation: parsers, dashboards, alerts,
lookups, datatables. Paths look like `/logParsers/Foo`, `/dashboards/Bar`,
`/alerts`, etc. Parsers specifically must use `/logParsers/<name>` —
the API also accepts `/parsers/<name>` but the Log Parsers UI reads only `/logParsers/`.

### `listFiles` — `c.list_files()` — CLI `list-files`

No params. Returns `{"status":"success","paths":["/a","/b/c","/z"]}` sorted
alphabetically.

### `getFile` — `c.get_file(path, expected_version=None, prettyprint=False)` — CLI `get-file`

Reads a single file. Response:

```json
{
  "status": "success",
  "path": "...",
  "version": 7,
  "createDate": 1700000000,
  "modDate": 1700000100,
  "content": "...",
  "stalenessSlop": 0
}
```

- If the file does not exist: `{"status":"success/noSuchFile"}`.
- If `expected_version` matches current: `{"status":"success/unchanged"}` with no `content`.

### `putFile` — `c.put_file(path, content=None, delete=False, expected_version=None, prettyprint=False)` — CLI `put-file`

Create, update, or delete. `delete=True` uses `{"deleteFile": true}` internally.

Content validation depends on file type — dashboards expect `"{graphs: []}"`
as empty, parsers/datatables expect empty string. Pass a fresh `expected_version`
from the preceding `getFile` for optimistic concurrency; a mismatch returns
`{"status":"error/client/versionMismatch"}` and no write.

Response on success: `{"status":"success"}`.

Requires Configuration Write Access key (or console token with config-write
permission). Console tokens are permitted but scope-aware — `S1-Scope` header
may be required.
