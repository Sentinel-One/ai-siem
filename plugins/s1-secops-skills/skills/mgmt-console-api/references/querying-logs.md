## Querying logs via the mgmt console API: the foolproof procedure

Every time somebody rolls their own `requests.post(...)` for a PowerQuery, one of the same six things goes wrong: wrong auth prefix, wrong endpoint path, missing `tenant: true`, missing `X-Dataset-Query-Forward-Tag`, no retry on transient 5xx, or 0 rows and the wrong debugging reflex. The fix is: do not hand-roll the call. Use the `powerquery_run` MCP tool from `s1-secops-mcp`. It runs on the user's machine, so it works from Cowork, where the sandbox cannot reach `*.sentinelone.net`. On the user's host (Claude Code or a terminal), `scripts/pq.py` is the Python equivalent; it reads credentials from environment variables or the OS keychain.

### Step 0: pick the right surface before you write a query

| The user wants… | Use | Why |
|---|---|---|
| Raw event telemetry (EDR, third-party logs, SDL data) | **`powerquery_run`** (LRQ PowerQuery; host-only Python: `scripts/pq.py`) | This is what SDL/PowerQuery is for. All `dataSource.*`, `event.*`, `src.process.*`, `tgt.file.*`, `i.scheme="edr"` filters. |
| Every parsed field of raw events (evidence export, forensic timeline) | `powerquery_run` with `queryType: "LOG"` and `outputFile` | Filter only, no pipes. Server cap 5000 events per query or slice; `truncatedByServerCap: true` means slice the window. |
| Triage/filter/note/status/verdict/assignee on an existing alert | `uam_list_alerts` / `uam_get_alert` / `uam_add_note` / `uam_set_status` / `uam_set_verdict` / `uam_assign_alert` (UAM GraphQL; host-only Python: `scripts/unified_alerts.py`) | Alerts are entities, not log events. UAM filter syntax is GraphQL `FilterInput`, NOT PowerQuery. Do not confuse the two. |
| Legacy STAR/cloud-detection alert REST shape | `s1_api_get` on `/web/api/v2.1/cloud-detection/alerts` | Only when you need `agentDetectionInfo` / `sourceProcess` etc. Otherwise UAM. |
| A console entity: threat, agent, site, policy, IOC, group | `s1_api_get` / `s1_api_post` (host-only Python: `s1_client.py`) | Not a log query. `GET /web/api/v2.1/{threats,agents,sites,...}`. |
| Natural-language hunt that can be hand-reviewed | `mcp__purple-mcp__purple_ai`, then run the returned PQ with `powerquery_run` | Purple generates PQ text; `powerquery_run` runs it. |

If the user names a vendor ("Example Source", "Zscaler", "Okta", "FortiGate") and says "query" or "search logs", that is always the PQ path, never UAM filter syntax.

### Step 1: use `powerquery_run`, not inline `requests`

```json
{
  "query": "dataSource.name = 'Example Source' | group ct = count() by event.type | sort -ct | limit 50",
  "hours": 24
}
```

That single tool call handles launch, polling, forward-tag, cancel and retry, and returns `matchCount`, `columns`, `rows` and the `effectiveQuery` it sent. Add `outputFile` (absolute path on the user's machine) when the result is large: the full result is written as `.csv`, `.jsonl` or JSON and only a summary plus a 5-row preview comes back.

Host-only Python equivalent (Claude Code or a terminal):

```python
import sys
sys.path.insert(0, "scripts")
from s1_client import S1Client
from pq import run_pq, list_data_sources, PQError

c = S1Client()

# One call. Handles launch, polling, forward-tag, cancel, retry, the lot.
res = run_pq(
    c,
    "dataSource.name = 'Example Source' "
    "| group ct = count() by event.type "
    "| sort -ct "
    "| limit 50",
    hours=24,
)
print(res["matchCount"], "events ->", res["row_count"], "rows")
for row in res["rows"]:
    print(row)
```

The tool and the helper do ALL of this for you, so there is nothing to remember:

- `Authorization: Bearer <jwt>` (flipped from the REST `ApiToken` prefix; same JWT, different scheme).
- `POST /sdl/v2/api/queries` on the tenant console host. **NOT** `/web/api/v2.1/sdl/v2/api/queries`, **NOT** `xdr.<region>.sentinelone.net`. Do not "fix" a 404 by adding `/web/api/v2.1`; that path does not exist; the fix is the shorter path.
- Captures `X-Dataset-Query-Forward-Tag` from the POST response and echoes it on every GET / DELETE (mandatory for shard routing; without it you get rejections).
- Sets `queryType: "PQ"`, `tenant: true`, `pq: {query, resultType: "TABLE"}` (omit `tenant` and you silently get `matchCount=0`).
- Polls at 1s (query expires 30s after the last poll: slower polling means you lose the query).
- Retries 5xx / 429 / connection errors with exponential backoff. Honors `Retry-After`. The DNS-cache-overflow 503s behind some egress proxies are exactly what this is for.
- Cancels on every exit path (success, deadline, failure) to release the per-account concurrent-query budget.

### Step 2: if you get 0 rows, follow the ladder, do NOT widen the window first

A query returning 0 rows has an ordered diagnostic. Burning time by widening the window first is the most common failure mode; the window is almost never the cause.

1. **Enumerate the data sources.** If your filter names a vendor / product, first confirm it exists on THIS tenant and you have the string right. Spelling, case, and punctuation matter, the filter is a literal string match. Call `powerquery_enumerate_sources` (host-only Python: `list_data_sources(c, hours=24)`).

   If "Example Source" isn't in the list, the tenant isn't ingesting it; no amount of widening the window will help. If it's there under a different spelling (`"PromptSecurity"`, `"Prompt Sec"`), use the exact string.
2. **Compare `matchCount` vs `row_count`.** `matchCount=0` means the initial filter discarded everything before any aggregation, the filter is too tight (or naming the wrong thing). `matchCount > 0` with `row_count = 0` means a post-pipe stage (`| group`, `| filter after group`) ate the rows, inspect the pipe.
3. **Only after the above come back clean**, widen the time window: in that order: 24h → 7d → 30d.

### Step 3: for large windows / heavy aggregates, slice

For ranges past 2-3 days with `event.type=*`-scale aggregates, slice the window and run slices in parallel. `powerquery_run` does this in one call: pass `slices` (2-15) and, for a group-by result, `merge` (`{"keys": [...], "sum": [...], "min": [...], "max": [...]}`). Only count, sum, min and max merge; the tool refuses `estimate_distinct`, `avg`, percentiles, `top` and `savelookup` across slices. Measured: a 30-day aggregate in about 5 s as 15 slices versus 21 to 40 s unsliced, identical totals. One token is enough (about 30 calls/s sustained). Full reference is in the `powerquery` skill at `references/lrq-api.md`; `run_pq` is the host-only single-slice primitive.

```json
{
  "query": "dataSource.name='SentinelOne' | group n = count() by event.type",
  "hours": 720,
  "slices": 15,
  "merge": { "keys": ["event.type"], "sum": ["n"] }
}
```

### Step 3a (timeseries): prefer client-side day slicing over `timebucket(...)`

`timebucket(...)` works in PQ when used as a NAMED grouping output inside `group ... by`:

```text
| group n = count() by day = timebucket('1d'), action     ← works
```

The bare positional form (no alias) and references inside `let` / `filter` are unreliable across tenant versions and have historically returned HTTP 500 `"undefined field 'timebucket'"`. Even when `timebucket` does work, a single 7d / 30d aggregate against a busy source frequently exceeds the LRQ per-call deadline (~38s observed), a 7d aggregate that finishes in 60s on the older `/api/powerQuery` endpoint will time out on LRQ.

**Default to slicing for any window > 24h.** It's faster, avoids the deadline budget, and produces the same end result. The named-form `day = timebucket('1d')` is fine inside a single 24h-or-less slice when you really do need per-hour or per-15-min buckets. For per-day rows, run one `powerquery_run` call per day as parallel tool calls in the same turn, each with its own `startTime` / `endTime`, and label each result with its day. Host-only Python equivalent:

```python
from datetime import datetime, timedelta, timezone
import concurrent.futures as cf

def slice_day(c, base, start, end):
    iso = lambda t: t.strftime("%Y-%m-%dT%H:%M:%SZ")
    return run_pq(c, base + " | group n=count() by action | sort -n",
                  start_time=iso(start), end_time=iso(end),
                  poll_deadline_s=90)

end = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
days = [(end - timedelta(days=i+1), end - timedelta(days=i)) for i in range(7)]
with cf.ThreadPoolExecutor(max_workers=7) as ex:   # one token sustains ~30 calls/s
    results = list(ex.map(lambda se: slice_day(c, base, *se), days))
```

7 daily slices run in ~20s wall-clock (vs ~2 min for a 7d aggregate) run all 7 in parallel. For hourly buckets over a 24h window use 24 slices; for 30d use 15 x 2d slices with 15 in flight (see `powerquery` skill, `references/lrq-api.md`).

### Step 3b: window-scaling playbook (performance by period)

| Window | Recommended call | Why |
|---|---|---|
| seconds to 1h | `powerquery_run` with `hours: 1` | server returns in <5s |
| 1h to 24h | `powerquery_run` with `hours: 24` | 5-30s depending on filter selectivity |
| 24h to 7d | single call OK for selective filters; for `event.type=*`-scale aggregates, `slices: 7` plus `merge` | single-call ~2 min; sliced ~20s |
| 7d to 30d | `slices: 15` plus `merge` | 30-day aggregate in about 5 s, identical totals |
| 30d+ | `slices: 15` plus `merge`, cache results with `outputFile` | long windows are a cost, not a wall |

### Step 3c: LRQ response-shape gotchas (handled by `powerquery_run` and `run_pq`)

If you ever have to read a raw LRQ response (e.g. debugging), know:

- `columns` is a list of dicts `{name, cellType, decimalPlaces}`, not a list of strings. Zipping values by `col["name"]` (not `str(col)`) is mandatory.
- `matchCount` lives inside the `data` block (`response["data"]["matchCount"]`), not at top level. Default to that path; fall back to top-level for older engines.
- `values` is an array of arrays (one per row); `powerquery_run` and `run_pq` pair it with column names for you.

### Step 4: when NOT to use `powerquery_run`

- If the user said "purple mcp", defer to `mcp__purple-mcp__powerquery` first; `powerquery_run` is the backup path when that tool times out or 5xxs.
- If the user is working with alerts as entities (listing, filtering, note, status), that's UAM GraphQL (`uam_*` tools), not PowerQuery. UAM filter syntax is `[{fieldId, stringEqual: {...}}]`; it is NOT PowerQuery `| filter` syntax. Mixing them is a common trap in screenshot-driven debugging.

### Checklist before running a PQ programmatically

- [ ] You called `powerquery_run` / `powerquery_enumerate_sources` (host-only Python: `run_pq` / `list_data_sources`), not inline `requests.post`.
- [ ] Base URL is the tenant console (e.g. `https://your-tenant.sentinelone.net`), not `xdr.<region>.sentinelone.net`.
- [ ] Endpoint path is `/sdl/v2/api/queries` (short form). If you see 404s, do NOT add `/web/api/v2.1`; that's wrong.
- [ ] If you're filtering on EDR data (`src.process.*`, `event.type=*`, `tgt.file.*`), prepend `dataSource.name='SentinelOne' dataSource.category='security'`: on mixed tenants the default scope carries Scalyr/infra logs too and wide filters silently return `matchCount=0`.
- [ ] 0 rows → ran `powerquery_enumerate_sources` and checked `matchCount` vs `row_count` BEFORE widening the window.

## Unified Alert Management (UAM): PRIMARY alert API

> **Alert API precedence, important:**
>
> 1. **PRIMARY: GraphQL UAM** at `POST /web/api/v2.1/unifiedalerts/graphql`. This is the modern, multi-source alerts inbox (EDR, XDR, Identity, STAR, Cloud, NGFW, and ingested third-party telemetry). IDs are UUIDs (e.g. `019db24c-8b6d-7451-8697-b1b2e1a270f1`). Use this for any alert listing, filtering, triage, note, status, verdict, assignment, group-by, facet, or CSV-export task.
> 2. **SECONDARY: REST** at `GET /web/api/v2.1/cloud-detection/alerts`. Older surface, scoped to cloud-detection events (STAR rule hits, EDR overflow). IDs are int64 (e.g. `2055164731151448891`). Use only when you specifically need the denormalized REST payload (`agentDetectionInfo`, `sourceProcess`, `targetProcess`, `ruleInfo`) or when UAM is unavailable. These are **parallel surfaces, not redundant**, the same alert will have different IDs in each.
> 3. **No `createAlert`.** S1 does not expose a mutation for creating alerts directly. Alerts are server-side byproducts of detection engines, create a STAR/Custom Detection rule (`POST /web/api/v2.1/cloud-detection/rules`), upload an IOC that matches live telemetry (`POST /web/api/v2.1/threat-intelligence/iocs`), or generate synthetic endpoint activity. `addAlertNote` is the closest reversible content-creation path against an existing alert.

Auth is the same `Authorization: ApiToken` header as REST; no extra credentials. Full reference in `references/UNIFIED_ALERTS.md`. The end-to-end dual-API round-trip test is `tests/test_alerts_dual_api.py`.

Use UAM whenever the user is working with *alerts* as first-class entities, triaging, filtering, adding notes, resolving, bulk-assigning, rather than the older `GET /web/api/v2.1/threats` surface.

In Cowork and any MCP client, use the `s1-secops-mcp` tools: `uam_list_alerts` (filters, paging, `scopeIds` for one account or site on a multi-account token), `uam_get_alert`, `uam_add_note`, `uam_set_status`, `uam_set_verdict`, `uam_assign_alert`, and `uam_available_actions` (read `isDisabled` / `disabledReason` before naming why an action failed). The Python wrapper and CLI below are host-only (Claude Code or a terminal on the user's machine; credentials from environment variables or the OS keychain).

```python
import sys
sys.path.insert(0, "scripts")
from s1_client import S1Client
import unified_alerts as uam

c = S1Client()

# discover: fieldIds, enum values, which views have data
cols = uam.column_metadata(c)
avail = uam.view_data_availability(c)

# triage: top 20 NEW CRITICAL EDR alerts from the last day
page = uam.list_alerts(c, filters=[
    uam.build_filter(fieldId="detectionProduct", stringEqual={"value": "EDR"}),
    uam.build_filter(fieldId="status",   stringEqual={"value": "NEW"}),
    uam.build_filter(fieldId="severity", stringEqual={"value": "CRITICAL"}),
], first=20)

# act: bulk resolve a specific list of alerts, with a note
account = uam.scope(["<account_id>"])
uam.set_alert_status(
    c, scope_input=account,
    alert_ids=["<alert1>", "<alert2>"],
    status="RESOLVED",
    note="Auto-closed: part of campaign tracked in JIRA-1234",
)
```

CLI equivalents (host-only):

```text
python scripts/call_unified_alerts.py list --filter detectionProduct=EDR --first 20
python scripts/call_unified_alerts.py facets status severity detectionProduct
python scripts/call_unified_alerts.py notes <alert-id>
python scripts/call_unified_alerts.py add-note <alert-id> "Investigating"
python scripts/call_unified_alerts.py set-status RESOLVED --scope <account-id> --alert-id <id1> <id2> --note "..."
python scripts/call_unified_alerts.py csv-export --filter severity=CRITICAL -o crit.csv
```

### UAM domain: what belongs here vs REST

UAM owns everything in the modern Alerts inbox, including alert notes, alert history, mitigation results, trigger-actions, and Cursor-paginated group-by / facet views. The older `/web/api/v2.1/threats` REST surface still exists and covers the classic endpoint-protection threat lifecycle, when the user says "alerts", "unified alerts", "alert notes", or mentions XDR / multi-source detections, route to UAM. When they say "threat", "threat group", "incident", or reference `/threats`, stay on REST.

### Important quirks (hidden by the wrapper, but mind them if writing raw GraphQL)

- The `alerts` query takes a flat `filters: [FilterInput!]` (AND-joined); mutations and `alertAvailableActions` take `filter: OrFilterSelectionInput` shaped as `{ or: [{ and: [FilterInput, ...] }, ...] }`. Mixing these up is a validation error. The wrapper exposes `build_filter(...)`, `or_filter(...)`, and `scope(...)` helpers so callers don't have to hand-assemble them.
- `updateAlertNote` and `deleteAlertNote` fail for ~30-90s after a note is freshly created (`"Alert Note with ID ... does not have mgmt_note_id set, unable to [edit|delete], try again later!"`) because the management-console backend is still propagating an internal id. The wrapper retries automatically with backoff, callers don't need to sleep.
- `aiInvestigations` has no `data` wrapper, but `alertNotes` / `alertFiltersCount` / `alertGroupByCount` / `alertAvailableActions` / `alertMitigationActionResults` / CSV exports all do. `alerts` / `alertHistory` / `alertTimeline` / `alertGroups` use connection shape (`edges`/`pageInfo`/`totalCount`).
- Full list of traps, including the `SortOrderType` enum name, `alertGroupByCount` using `limit` (not `first`), subselection requirements on `CsvResponse` / `ActionsError`, and the actual shape of `alertsViewDataAvailability`, is in `references/UNIFIED_ALERTS.md` under "Schema quirks".

### Destructive actions: blast radius

`alertTriggerActions` is the single mutation that can touch many alerts at once. Passing `filter: null` means *every alert in scope*, potentially hundreds of thousands. The safe pattern is the same as REST bulk actions:

1. Use `list_alerts(..., first=1)` with the proposed filter and read `totalCount`.
2. Show the user the exact filter + action list + count.
3. Only after explicit confirmation, call `trigger_actions(...)` or one of the `set_alert_status` / `set_analyst_verdict` / `assign_alerts` convenience wrappers (all of which constrain the filter to an explicit alert-id list by default).

## UAM Alert Interface (Unified Alert Management) -- pushing OCSF alerts INTO UAM

Everything else in this skill talks to `<tenant>.sentinelone.net/web/api/v2.1/...` (the Mgmt Console) and is read-or-mutate on pre-existing server state. The **UAM Alert Interface** (formerly "Ingestion Gateway") is a separate API family on a separate host for the write-side path: it lets you push OCSF-formatted alerts INTO UAM so they show up in the console as real alerts with attached indicators. Use it when a user asks to "create an alert", "ingest indicators", "send alerts from my pipeline", or "test alert ingestion".

**Host and wire contract:**

- Prod (US1): `https://ingest.us1.sentinelone.net`. This is the SentinelOne ingest host, shared between raw log ingest and OCSF alert ingest. Configure `S1_HEC_INGEST_URL` as an environment variable or in the OS keychain (`s1-secops-mcp setup`); the host-only Python client also takes a `--uam-url` flag.
- From Cowork or any MCP client, push the alert with the `uam_post_alert` tool (one alert per call). The Python client below is host-only.
- Auth: `Authorization: Bearer <JWT>`. NOT `ApiToken`. The mgmt-console JWT from `S1_CONSOLE_API_TOKEN` works; the endpoint rejects `ApiToken ...` with HTTP 401 `"Unsupported auth type"`. Alert creation and IOCs remain console-token operations. Only raw log ingest over the event collector (`/services/collector/raw` and `/event`) moved to the SDL Log Write Key, and that is a separate path on the same host.
- Body: concatenated JSON (one or more objects back-to-back, optionally newline-separated), gzip-compressed. `Content-Encoding: gzip` is mandatory. zstd also accepted.
- Scope: `S1-Scope: <accountId>` or `<accountId>:<siteId>[:<groupId>]` is mandatory on `/v1/alerts`.
- Success shape: `202 Accepted` with `{"details":"Success","status":202}`.

### Indicators cannot be ingested separately

There is no usable `POST /v1/indicators`. It refuses the console user token AND the SDL Log Write
Key, so no credential can drive it:

| credential | `/v1/alerts` | `/v1/indicators` |
|---|---|---|
| console API token (service user), `Bearer` | 202 Success | 403 `"User token not allowed for this endpoint"` |
| console API token (service user), `ApiToken` | 401 `Unsupported auth type` | 401 `Unsupported auth type` |
| SDL Log Write Key, `Bearer` | 401 `UNAUTHORIZED` | 401 `UNAUTHORIZED` |

The console token carries the claim `type: "user"`, and that is what `/v1/indicators` refuses. The
Log Write Key is not the alternative: it is a Scalyr-style key for the event collector, not a
Bearer JWT for the `/v1/*` family.

**Carry every indicator inline in the alert instead.** One `POST /v1/alerts`, with the indicator
content in `finding_info.related_events[]`. That inline copy is what populates `alert.indicators`,
which is what the console Indicators tab renders. The old two-call flow (post indicator, sleep
~3s, post alert referencing it by uid) is gone, along with its sleep and its ordering contract.

Per `related_events[]` entry the mapping into the `Indicator` type is:

| related_events field | renders as |
|---|---|
| `title` | `Indicator.title` |
| `desc` | `Indicator.description` |
| `message` | `Indicator.message` |
| `severity_id` | `Indicator.severity`, resolved PER indicator, independent of the alert envelope severity |
| `observables[]` | `Indicator.observables`, `type_id` mapped to the UI enum (1 HOSTNAME, 2 IP, 4 USER_NAME, 5 EMAIL, 9 PROCESS_NAME, 10 RESOURCE_UID) |

Multiple `related_events` entries give multiple indicators on one alert. The minimal enriched
entry is sufficient: inlining a whole indicator body (`device` / `actor` / `metadata.profiles`)
into the entry and adding an OCSF `evidences[]` array alongside it were both tested and changed
nothing.

`alertWithRawIndicators.rawIndicators` was the store `/v1/indicators` fed, and the UI never read
it. On this design it stays `[]`, which is expected and not a failure. Two teams have chased that
empty array as if it were a bug.

**The `Indicator` GraphQL type has these fields: `type`, `uid`, `title`, `description`,
`message`, `severity`, plus the `observables` sub-selection.** There is no `name` and no
`category`; asking for either returns
`Validation error (FieldUndefined@[alert/indicators/name]) : Field 'name' in type 'Indicator' is undefined`
before the query executes. (`indicator.name` and `indicator.category` DO exist, but they are SDL
PowerQuery fields on EDR behavioural-indicator events, an unrelated schema.)

**Endpoint:**

- `POST /v1/alerts` -- SecurityAlert wrappers, each carrying its indicators inline in `finding_info.related_events[]`. **Call with ONE alert per POST.** The wire format accepts multi-alert bodies and the gateway returns HTTP 202, but the stitcher silently drops all but one alert in a multi-alert batch; loop one at a time.

**Supported indicator classes (via builders):**

- `build_file_indicator(...)` -- OCSF class 1001 FileSystem Activity. Observables: Hostname, File Name, Hash (SHA-256/MD5), User Name, IP Address.
- `build_process_indicator(...)` -- OCSF class 1007 Process Activity. Observables: Hostname, Process Name, Resource UID (pid), User Name, IP Address, plus parent process.
- `build_network_indicator(...)` -- OCSF class 4001 Network Activity. Observables: Hostname, src/dst IP Address, URL, User Name.

**Python usage (host-only).** `post_indicators()` and `post_alert_with_indicators()` were removed from
`scripts/uam_alert_interface.py`; both drove the unreachable `/v1/indicators` endpoint, and
tombstone comments in the module record why. Build the alert with its indicators inline and send
it with `post_alerts([alert])`, one alert per call, as in the worked example at the end of this
section.

```python
import sys, time, uuid
sys.path.insert(0, "scripts")
from s1_client import S1Client
from uam_alert_interface import (
    UAMAlertInterfaceClient,
    build_file_indicator, build_process_indicator, build_network_indicator,
    build_alert_referencing,
)

mgmt = S1Client()
uam_iface = UAMAlertInterfaceClient(bearer_token=mgmt.api_token)

now_ms = int(time.time() * 1000)
ind_uid_a, ind_uid_b, alert_uid = (str(uuid.uuid4()) for _ in range(3))

ind_a = build_file_indicator(
    indicator_uid=ind_uid_a, file_name="payload.iso",
    file_sha256="0"*64, device_uid=str(uuid.uuid4()),
    device_hostname="host-1", device_ip="192.0.2.10",
    user_uid=str(uuid.uuid4()), now_ms=now_ms,
)
ind_b = build_process_indicator(
    indicator_uid=ind_uid_b, process_name="powershell.exe",
    process_pid=4242, process_cmd_line="powershell -enc ...",
    parent_process_name="explorer.exe",
    device_uid=str(uuid.uuid4()), device_hostname="host-1",
    user_uid=str(uuid.uuid4()), now_ms=now_ms,
)
alert = build_alert_referencing(
    alert_uid=alert_uid, indicators=[ind_a, ind_b], now_ms=now_ms,
    title="Ingested alert", description="...",
)

# One POST, indicators carried inline. No companion indicator POST, no
# sleep, no ordering to get wrong. For many alerts, LOOP this call -- do
# NOT pass multiple alerts to post_alerts() in one go (see constraints
# below).
uam_iface.post_alerts([alert], scope=f"{account_id}:{site_id}")
# Then poll UAM GraphQL (unified_alerts.list_alerts) to see it surface.
```

**Validation:** after ingest, find the alert via UAM GraphQL (`unified_alerts.list_alerts` filtered by name, or `get_alert(alert_id)` once you know it) and read `alert.indicators`. Do NOT validate with `get_alert_with_raw_indicators`: `rawIndicators` was fed by `/v1/indicators` and stays `[]` on this path.

**Cleanup:** ingested alerts are not hard-deletable via public API. The standard reversibility pattern is to set `status=RESOLVED` and `analystVerdict=TRUE_POSITIVE_BENIGN` via the bulk-ops mutations in `unified_alerts` so the alert exits the active SOC queue and is tagged as synthetic.

**Multi-indicator alert constraints** (empirically confirmed on a live tenant):

- **One alert per `POST /v1/alerts` call.** The wire format accepts
  concatenated JSON for N alerts in one body and the gateway returns
  HTTP 202, but the stitcher silently drops all but one of the alerts.
  Callers with many alerts MUST loop. `post_alerts` emits a
  `RuntimeWarning` when `len(alerts) > 1` to flag the hazard.
- Alerts with multiple `resources[]` entries (i.e. indicators spanning
  different `device.uid` values) are silently dropped by the stitcher.
  Return: HTTP 202 at the wire, NEVER surfaces in UAM. The builder
  collapses to a single `resources[]` entry (first indicator's device)
  to avoid this. If you truly need per-indicator assets, emit separate
  alerts.
- Each `finding_info.related_events[]` entry MUST carry `class_uid`,
  `type_uid`, `category_uid`, `activity_id`, `severity_id`, `time`,
  `message`, and enriched `observables[]` (each with `type` +
  `typeName` alongside `type_id`/`name`/`value`). `build_alert_referencing()`
  populates all of these. Omitting any of them tends to cause the
  stitcher to silently drop the alert.
- **`file.hashes` MUST be an OCSF Fingerprint array, not a dict.**
  OCSF 1.6.0 defines `file.hashes` as `Array of Fingerprint objects`:
  `[{"algorithm_id": 3, "algorithm": "SHA-256", "value": "<hex>"}, ...]`.
  Posting `{"sha256": "<hex>"}` (dict form) causes the stitcher to
  silently drop the file indicator even though POST returns 202.
  `build_file_indicator()` emits the correct array shape; custom
  payload builders must follow the same convention (algorithm_id 2=MD5,
  3=SHA-256, 4=SHA-1, 5=SHA-512).
- Ingest is asynchronous. Alerts surface in UAM within ~30-60s of the
  POST. Tests must poll with a grace window, not assert immediately.

**Single-POST worked example (the only supported path):**

```python
alert = {
    "finding_info": {
        "uid": alert_uid,
        "title": "Ingest health SILENT (feed dark)",
        "desc": "Source fell below its 7-day baseline.",
        # This entry IS the indicator. No companion POST to /v1/indicators.
        "related_events": [{
            "uid": indicator_uid,          # any uuid; nothing needs to resolve it
            "title": "Ingest volume collapsed",     # -> Indicator.title
            "desc": "Zero live events in the window.",  # -> Indicator.description
            "message": "Source volume 12 events vs baseline 4210",
            "time": now_ms,
            "severity_id": 4,              # -> Indicator.severity, per indicator
            "class_uid": 1007, "type_uid": 100701, "category_uid": 1, "activity_id": 1,
            "observables": [
                {"name": "device.hostname", "type_id": 1, "type": "string",
                 "typeName": "Hostname", "value": "host-01"},
                {"name": "dataSource.name", "type_id": 9, "type": "string",
                 "typeName": "Process Name", "value": "my-source"},
            ],
        }],
    },
    "resources": [{"uid": device_uid, "name": "host-01", "type_id": 1, "type": "host"}],
    "category_uid": 2, "category_name": "Findings",
    "class_uid": 99602001, "class_name": "S1 Security Alert",
    "type_uid": 9960200101, "type_name": "S1 Security Alert: Create",
    "activity_id": 1,
    "metadata": {"version": "1.6.0-dev",
                 "extension": {"name": "s1", "uid": "998", "version": "0.1.0"},
                 "product": {"name": "Hyperautomation", "vendor_name": "SentinelOne"},
                 "logged_time": now_ms, "modified_time": now_ms, "uid": alert_uid},
    "time": now_ms, "attack_surface_ids": [1],
    "severity_id": 4, "state_id": 1, "s1_classification_id": 1,
}
uam_iface.post_alerts([alert], scope=f"{account_id}:{site_id}")   # one alert per call
```

Verify with `alert(id) { indicators { type uid title description message severity
observables { name value type } } }`, NOT with `alertWithRawIndicators`, which stays empty on
this path. Do not add `name` or `category` to that selection set; neither exists on `Indicator`
and either one fails the whole query at validation.

`tests/test_uam_alert_interface_single.py` and `tests/test_uam_alert_interface_batch.py` both
drive the single POST above: one `post_alerts([alert], scope=...)` call with the indicators
inline, plus an assertion that exactly one request went out, so a regression back to the
indicator-then-alert sequence fails the test. The worked example on this page and those tests are
the same shape.

### Asset linkage on ingested alerts

Ingested alerts always create a synthetic `assets[]` entry derived from `resources[]`; they **never** populate `assets[].agentUuid`. That linkage to real tenant inventory is only established when the alert originates from an installed S1 agent (real detection, STAR rule hit, or Hyperautomation `sendCustomEvent`). No OCSF field combination on the ingest path (tested: `resources[].agent_list`, `device.agent_uuid`, matching real agent UUIDs, `os.type_id` hints, etc.) reconciles against inventory.

What IS controllable is the asset classification. `metadata.product.name` + `metadata.product.vendor_name` on the alert envelope drive `assets[].category` / `assets[].subcategory`:

- Defaults (`smoke-product` / `smoke-vendor`) classify as "Device / Other Device"
- `SentinelOne` / `SentinelOne` classifies as "Server / Virtual Machine"

Pass these via `build_alert_referencing(detection_product=..., detection_vendor=...)` when you want a demo alert to visually resemble an agent-generated alert. `get_alert` now defaults to `_ALERT_DETAIL_FIELDS` which includes the `assets { ... }` block; `list_alerts` / `paginate_alerts` still default to `_ALERT_CORE_FIELDS` (cheap) and accept an explicit `fields=_ALERT_DETAIL_FIELDS` override when callers want the asset join on every edge.

Full empirical matrix including per-field behaviour and probing recipes: `references/ASSET_LINKAGE.md`.

## Data source + schema discovery

Before you write queries, dashboards, or detections against an SDL data source, discover two things: (1) what sources exist on this tenant and which are actively ingesting, and (2) for a given source, what attributes the parser actually emits. Hardcoded field lists are the number-one reason queries return 0 rows on a new tenant. This workflow replaces them.

### Step 1: enumerate sources (`dataSource.name = *`)

Call `powerquery_enumerate_sources` (optionally `hours: 168` for low-volume tenants, `scope` for one site). Host-only Python equivalent:

```python
from pq import list_data_sources
sources = list_data_sources(client, hours=24, limit=200)
# -> [{"dataSource.name": "SentinelOne", "dataSource.category": "security", "ct": 18304051}, ...]
```

Host-only CLI: `python scripts/inspect_source.py --list` prints a ranked table of every source that ingested in the last 24h. If a name the user asked for isn't in the list, fuzzy-match and surface candidates rather than running a query that will return 0.

Rules of thumb:

- There can be multiple rows with the same `dataSource.name` under different `dataSource.category` values (e.g. `SentinelOne / security`, `SentinelOne / None`, `SentinelOne / telemetry`). Treat category as metadata, not part of the name.
- A source with non-zero `ct` in 24h is live. Anything else is either decommissioned, in a different time window, or scoped out of the current token.

### Step 2: discover the schema for one source

Call `powerquery_schema_discover` with the exact source name as `dataSourceName` (`maxEvents` up to 50, `startTime` such as `"24h"` or `"7d"`, optional `scope`). It returns full event attributes and drops `logVolume` metering rows, reporting how many in `excludedMeteringRows`. For a larger sample, run `powerquery_run` with `queryType: "LOG"`, `query: "dataSource.name='<name>'"`, and `outputFile`, then read the field names from the written file. Persist the field list for the session with the Write tool (for example `sdl_schemas_<YYYY-MM-DD>.json` in the outputs folder).

Host-only Python equivalent, which also classifies fields into principal / action keys:

```python
from inspect_source import discover_schema, pick_keys

schema = discover_schema(
    client, "Example Source",
    hours=24, sample=150,
    extra_filter="(tag != 'logVolume' OR !(tag = *))",  # ALWAYS exclude logVolume
    backend="auto",   # sync SDL first, LRQ LOG fallback
    escalate=True,    # 1h -> 4h -> 24h until min_events rung satisfied
)
prim_key, action_key = pick_keys(schema)
```

Host-only CLI: `python scripts/inspect_source.py --source "<name>" --window 24h`.

Key points:

- Uses the LRQ `LOG` queryType (not PowerQuery). PQ has no wildcard column projection; `| columns *` errors and `| limit N` only returns `timestamp + message`. `LOG` returns every flat attribute the parser emits under `matches[].values`, which is how the Event Search UI populates its "Event properties" panel.
- Sync SDL `/sdl/api/query` is ~30% faster than async LRQ on your-tenant. The dispatcher prefers it and falls back to LRQ LOG on HTTP 404/401/403. Force a backend with `backend="sdl"` or `backend="lrq"` if benchmarking.
- Escalating window (1h -> 4h -> 24h -> requested) keeps busy sources ~3s. Only sparse sources (audit, low-volume demos) pay the full widening cost. Override with `escalate=False` for a single-rung run at `hours=`.
- Each field is classified: `principal_user` / `principal_host` / `principal_ip` / `action` / `temporal` / `network` / `file` / `process` / `grouping_candidate` / `other`. `pick_keys(schema)` returns `(prim_key, action_key)` picked from whatever is populated, preferring `user > hostname > IP`, then shortest name, then exact-name action hits (`action`, `event.type`, `outcome`, `result`, `severity`, ...) in that priority.
- `extra_filter` is passed through verbatim and appended to the base `dataSource.name='...'` filter.

### ALWAYS exclude `tag='logVolume'` from discovery samples

SDL writes ingest-metering rows alongside real data, tagged `tag='logVolume'`, under the source's own `dataSource.name`. They have `metric`, `value`, `path1` fields and nothing else useful. If you don't exclude them, they crowd out real events in a sample window and the classifier picks `severity` as the action key because it's the only field at 100% populated. Pass:

```python
extra_filter="(tag != 'logVolume' OR !(tag = *))"
```

Both are now the default, so you rarely need to pass it:

- **PowerQuery (`scripts/pq.py` `run_pq()`, and the `s1-secops-mcp` `powerquery_run` tool):** `tag != 'logVolume'` is ANDed into the initial filter of every query. In PowerQuery `!=` already keeps rows with no `tag`, so the `OR !(tag = *)` half is redundant there: live-verified 2026-10-03 over a fixed 12h window, both forms returned 375,654, and unfiltered 383,044 minus 7,390 metering rows reconciles exactly. `include_metering=True` (MCP: `includeMetering`) opts out. Queries that mention `logVolume`, or open with `| datasource`, `| dataset`, `| join` or `| union`, are passed through unchanged.
- **Schema discovery (`inspect_source.discover_schema`, V1 / LOG backends):** the explicit `(tag != 'logVolume' OR !(tag = *))` form is applied by default, because absent-field `!=` semantics have not been verified on those backends. `include_metering=True` opts out. Passing it as `extra_filter` still works and is not doubled.

### Benchmarked results (5 sources, your-tenant, 24h ceiling)

| Source | Wall | Effective | n sampled | attrs | prim_key | action_key |
|---|---|---|---|---|---|---|
| SentinelOne | 2.9s | 1h | 150 | 333 | `src.process.eUserName` | `event.type` |
| Windows Event Logs | 3.1s | 1h | 150 | 148 | `winEventLog.data.event.eventData.subjectUserName` | `event.type` |
| FortiGate | 2.5s | 1h | 150 | 247 | `device.name` | `event.type` |
| Zscaler Internet Access | 2.5s | 1h | 150 | 47 | `None` | `action` |
| Example Source | 16.8s | 24h | 133 | 59 | `user` | `action` |

Four of five land in ~3s because busy sources satisfy the `min_events=50` threshold on the 1h rung. Only low-volume sources (demo Example Source) pay the full escalation cost (1h -> 4h -> 24h = 3 rungs). Reproduce with `python scripts/bench_5_sources.py`.

Zscaler returning `prim_key=None` is a real classifier gap: its user-ish fields are named `deviceowner` / `department` without a separator, so they don't match the `principal_user` regex. This is visible, not hidden. Operators can inspect the `other` class in the report and manually set the prim_key for downstream queries.

### Using the discovered schema in code

```python
base = f"dataSource.name = '{source}' tag != 'logVolume'"

# volume-by-action breakdown (always safe; default to count() if no action key)
if action_key:
    q = f"{base} | group n=count() by {action_key} | sort -n"
else:
    q = f"{base} | group n=count()"

# per-principal mix (skip if no principal)
if prim_key and action_key:
    q = f"{base} | group n=count() by {prim_key}, {action_key} | sort -n | limit 60"
elif prim_key:
    q = f"{base} | group n=count() by {prim_key} | sort -n | limit 25"
```

`build_source_report.py` is the reference consumer of this pattern. Read it before writing a new pipeline that needs the same keys.

## Source-agnostic baseline + anomaly detection

`scripts/baseline_anomaly.py` (host-only; it calls the tenant directly) is the productionised end-to-end pipeline for behavioural baselining and z-score anomaly detection on ANY data source. It composes the schema-discovery + key-picker + LRQ runner already in this skill, so a caller never has to hand-pick principal/action fields per source.

What it does:

1. Calls `inspect_source.discover_schema()` for the named source and `pick_keys(schema)` to choose `prim_key` (principal: user / host / IP / role) and `action_key` (event.type / activity_name / action). Honors per-source overrides if the caller knows better.
2. Runs N daily count slices (default 30) via `pq.run_pq()` over the baseline window. Daily slicing avoids the LRQ per-call deadline; `max_workers=3` is conservative; one token sustains about 30 calls/s, so up to 15 workers is safe.
3. Runs one 24h live slice.
4. Merges slices client-side. Supports two baseline strategies: pooled (all daily samples in one bucket) and DoW-stratified (one bucket per day-of-week, eliminates weekday/weekend false-positives).
5. Surfaces three anomaly classes on every run: matched-pair z-score deviations (SPIKE/DROP), silent pairs (baseline → live=0), and new-behaviour pairs (live with no baseline).

Usage:

```bash
python scripts/baseline_anomaly.py --source "<name>" --days 30 --stratify dow
python scripts/baseline_anomaly.py --source "Okta" --days 7
python scripts/baseline_anomaly.py --source "FortiGate" --days 30 --stratify dow --principal src.ip.address --action unmapped.action
```

State is checkpointed to disk per source (`baseline_anomaly_<slug>_state.json`) so the script is resumable across runs; use this when working in environments with short shell budgets.

PQ building blocks the script wraps live in the `powerquery` skill at `examples/behavioral-baselines.md`. Read that file when authoring the equivalent as a STAR / PowerQuery Alert detection rule body, the rule-body shape uses `lookup` against a pre-computed baseline table (from `savelookup`) instead of the script's two-window LRQ pattern.

### When to re-run discovery

- Before writing any query against a source you haven't touched on this tenant.
- When a previously-working query starts returning 0 rows (parser may have changed field names after a platform update).
- On tenant handover: different customers enable different parser versions, especially for XDR connectors.
- Before authoring a detection rule body (STAR / Custom Detection / PowerQuery Alert), to confirm the fields the rule references actually exist. Pass the discovered schema through to the rule author in the body of the request.

## CTO report generation pipeline

A source-agnostic pipeline for producing CTO-grade Word + PowerPoint reports on any SDL data source. Three scripts, one JSON artefact. The collector calls the tenant, so it runs on the user's host (Claude Code or a terminal); the renderers make no tenant calls. In Cowork, collect the same aggregates with parallel `powerquery_run` calls and write them to `data.json` with the Write tool, then run the renderers.

1. `scripts/build_source_report.py --source "<vendor>" --window <7d|24h|...>`. Runs dimension probes, a unified per-principal query, and a timeline aggregate against the tenant via `scripts/pq.py`, then writes `reports/<slug>_<window>/data.json`. Probes which of `user`, `src.ip.address`, `src.hostname`, `action`, `event.type` actually carry values, so the renderer can skip sections that would otherwise be empty.
2. `scripts/render_charts.py <data.json>`. Emits PNG charts into `reports/<slug>_<window>/charts/`. Pure function of the JSON, no tenant calls.
3. `scripts/build_docx.py <data.json>` and `scripts/build_pptx.py <data.json>`. Read the same JSON, emit `<Slug>_CTO_Report_<window>.docx` and `<Slug>_CTO_Deck_<window>.pptx` next to it. Every chart, section, stat card, and recommendation is gated on `data["dims"]` so a dimension-sparse source (e.g. Windows Event Logs has only `event.type`) produces a shorter but coherent report, not a broken one with empty tiles.

### Data.json contract (renderers depend on this shape)

- `source`, `slug`, `window_label`, `window_start`, `window_end`, `base_filter`.
- `dims`: boolean-per-dimension probe result.
- `summary`: derived metrics. Key fields are `total`, `intervention_rate` (only meaningful if `dims.action`), `prim_key` (name of the principal field actually used: `user`, `src.hostname`, `src.ip.address`, or null), `top_principal_key`, `top_user`, `by_action`, `rank_24h`, `n_slices`.
- `per_user_mix_top10`: the unified top-N-principals-by-action-mix result. The renderer slices this into `by_user`, `by_action_blocks`, `by_user_bypass` rather than running three separate queries. Collector does one PQ; renderer derives the rest.

### Principal key fallback

Order: `user`, then `src.hostname`, then `src.ip.address`, then none. The collector picks the first dim that returned non-null; the renderer reads `summary.prim_key` and labels stat cards and takeaways accordingly (e.g. "Dominant host" vs "Dominant user").

### Renderer gotchas (learned the hard way)

- **Never use em-dashes or en-dashes in any commentary string.** They read as AI-generated. Use commas, colons, or parentheses.
- **Stat card overflow.** Long labels (e.g. "Windows Event Log Creation") wrap through the card edge at 40pt. Use length-based font sizing: len<=7 gets 40pt, <=12 gets 28pt, <=18 gets 20pt, else 16pt.
- **Chart title "dayly" is not a word.** `f"{kind}ly"` where kind="day" is wrong. Use a lookup: `{"day": "Daily", "hour": "Hourly", "week": "Weekly", "month": "Monthly"}`.
- **X-axis label crowding on hourly charts.** A 24-slice timeline rotates 24 timestamps into each other. Sparsify with `ax.set_xticks(ticks[::step])` where `step = max(1, int(len(dates) / 10))`, BEFORE `autofmt_xdate`.
- **Single-series legend clutter.** Gate `ax.legend(...)` on `n_series > 1`. A one-series chart needs no legend; the title carries the meaning.
- **Bar data-labels overlap on dense charts.** Skip them when `len(dates) > 12`. The Y-axis scale is enough for dense timelines.
- **Adaptive title on dimensionless sources.** `title_suffix = "volume by action" if has_action else "volume"`. Don't claim action breakdown when there is none.
- **Recommendations grid leaves empty bottom cell.** With 2 cards, use a single row (not 2x2). With 1 card, full width.
- **Fallback bullets when both `action` and `top_user` are missing.** Otherwise the "CTO takeaways" section renders empty. Fall back to dominant `prim_key`, tenant rank (24h), and the data-lake story.

### Commentary generators

`_intervention_note()`, `_concentration_note()`, `_bypass_note()` in `build_docx.py` and `build_pptx.py` take metric values and return commentary strings gated on thresholds (>=40 high, >=10 moderate, else low). The thresholds are tuned for LLM-app traffic; if they feel off for a new source, edit the thresholds rather than the template strings.

### Running the whole thing

```text
# From the skill root on the user's host, with credentials in the environment or the OS keychain.
python scripts/build_source_report.py --source "<vendor>" --window <7d|24h|...>
python scripts/render_charts.py reports/<slug>_<window>/data.json
python scripts/build_docx.py    reports/<slug>_<window>/data.json
python scripts/build_pptx.py    reports/<slug>_<window>/data.json
```

The collector creates `reports/<slug>_<window>/` on first run. The `reports/` directory is `.gitignored`; this skill ships with the framework only, not sample outputs.

## Common high-value workflows

- **Unified alert triage**: `uam_list_alerts` (host-only Python: `list_alerts(...)` from `unified_alerts`) for the modern multi-source alerts inbox (EDR + XDR + Identity + cloud + third-party); use `facets`/`group-by` for volume rollups; `set_alert_status` / `set_analyst_verdict` / `assign_alerts` for triage decisions; `add_alert_note` for context.
- **Threat triage (legacy)**: `GET /threats` filtered by `createdAt__gte` + `resolved=false`; enrich with agent details from `/agents?ids=...`; output a table.
- **Endpoint isolation**: find agent IDs (`/agents` with name/IP filter), confirm count, `POST /agents/actions/disconnect` with filter.
- **Hunt across DV / PowerQuery** -- `POST /sdl/v2/api/queries` with `queryType="LOG"` (S1QL) or `queryType="PQ"` (PowerQuery), then poll `GET /sdl/v2/api/queries/{id}` echoing the `X-Dataset-Query-Forward-Tag` response header. Auth is Bearer, not ApiToken. `powerquery_run` (with `queryType: "LOG"` or the default `"PQ"`) does all of this. Legacy `/dv/init-query` + `/dv/query-status` + `/dv/events` + `/dv/events/pq` flows are deprecated (sunset 2027-02-15). See `references/WORKFLOWS.md` Section 4 for the canonical runner.
- **Natural-language hunt via Purple AI** -- Use `mcp__purple-mcp__purple_ai` (Purple MCP). The `purple_query()` Python helper and `scripts/call_purple.py` are non-functional for API tokens (`purpleLaunchQuery NATURAL_LANGUAGE` requires a browser-session teamToken, confirmed 2026-05-03). Only for SDL-telemetry questions; route entity questions to REST.
- **Site/Group inventory**: `/sites`, `/groups`, `/accounts` are the tenant-structure endpoints; many resources require filtering by `siteIds` / `accountIds`.
- **Bulk action audit**: `/activities` is the system-wide audit log; filter by `activityTypes` and `createdAt__gte`.
- **Push alerts INTO UAM** -- build one OCSF alert carrying its indicators inline in `finding_info.related_events[]`, then call `uam_post_alert` (host-only Python: `UAMAlertInterfaceClient.post_alerts([alert], scope=...)`) once per alert (loop for many). There is no separate indicator POST: `/v1/indicators` refuses every credential. See "UAM Alert Interface" above for the required fields and the multi-alert silent-drop trap. Use for pipeline integrations, synthetic-alert generation, and detection testing.
- **CTO report for a data source** (collector is host-only) -- `python scripts/build_source_report.py --source "<vendor>" --window <7d|24h>` then `scripts/render_charts.py`, `scripts/build_docx.py`, `scripts/build_pptx.py` on the resulting `reports/<slug>_<window>/data.json`. Works for any SDL data source; the renderer gates every section on `dims` so dimension-sparse sources (e.g. Windows Event Logs with only `event.type`) still produce a coherent deck. See "CTO report generation pipeline" for the data contract and renderer gotchas.

Consult the per-tag reference files for exact parameter names, the above are orientation, not copy-paste ready.

## Hyperautomation (HA): workflow management

API root (confirmed via live network capture 2026-05-03):

```text
/web/api/v2.1/hyper-automate/api/v1
```

Auth: same `Authorization: ApiToken <token>` header as all other S1 REST calls.

### Hyperautomation Endpoints

| Operation | Method | Path |
|---|---|---|
| List workflows | `GET` | `/workflows?limit=&skip=&siteIds=&sortBy=&sortOrder=` |
| Get single workflow | `GET` | `/workflows/single/{workflowId}/{revisionId}` |
| Workflow filter counts | `GET` | `/workflows/filters-count?siteIds=` |
| Delete workflow | `DELETE` | `/workflows/{id}?accountIds=<acct>` |
| Export all workflows (ZIP) | `GET` | `/workflow-import-export/export` *(confirmed on /public path)* |
| Import workflow | `POST` | `/workflow-import-export/import` *(confirmed on /public path)* |

**Important:** the single-workflow fetch requires BOTH `workflowId` AND `revisionId`. The `revisionId` is the `workflow.version_id` field returned in the list response. `GET /workflows/single/{id}` without a revision returns 404.

**Deletion is a REST `DELETE` (soft, recoverable).** `DELETE /web/api/v2.1/hyper-automate/api/v1/workflows/{id}?accountIds=<acct>` returns `204` (validated 2026-06-13: import then publish then delete then gone-from-list). Scope with `accountIds` or `siteIds` to match where the workflow lives. The older `POST /workflows/archive` and the legacy archive wrapper return HTTP 500 on this tenant; do not use them; the REST `DELETE` is the correct mechanism.

Export/import were not captured in the v1 network trace. They are confirmed working at the `/public` base path; the `/v1` equivalents have not been verified.

**⚠ Listing workflows: the page is alphabetical and capped, and the name filter 502s on spaces.**
Both bite any "does this workflow already exist?" check, and both fail SILENTLY as "not found",
which makes a deploy re-import and leave a duplicate ACTIVE copy of every flow. Tenant-validated
2026-08-09 (one redeploy produced 4 active duplicates on a 400+ workflow tenant).

| Call | Result |
| --- | --- |
| `GET /workflows?limit=200` (no filter) | first 200 **by name**; anything sorting later is invisible |
| `GET /workflows?name__contains=<value with a space>` | **HTTP 502** |
| `GET /workflows?name__contains=<single token>` | 200, correct subset |

So: filter server-side on a whitespace-free token (e.g. the deployment prefix), then match the
exact name client-side. Never scan an unfiltered capped page. And do not treat an API error as
"absent": `mgmt()`-style helpers turn a 502 into an empty result, which is exactly how a lookup
built to prevent duplicates ends up causing them. On error, log and fall back rather than
reporting not-found.

**Parked run-now executions.** A manually triggered execution can sit at `state: Running` with
`executed_actions: 0` indefinitely, and abandoned ones accumulate and hold scheduler slots (10
observed after a day of interrupted test runs, blocking new executions). Clear one with
`deactivate` → `activate` → run again, or delete the workflow. Never trigger multiple flows
concurrently. Check `GET /workflow-execution` for `Running` + `executed_actions: 0` before
debugging a flow that "will not start".

### List response shape (key fields)

Each item in `data[]`:

```jsonc
{
  "id": "<workflowUUID>",                     // top-level workflow ID
  "workflow": {
    "id": "<same UUID>",
    "version_id": "<revisionUUID>",            // pass as revisionId to single endpoint
    "name": "...",
    "state": "active|inactive|deactivated|draft",
    "status": "idle|running|...",
    "scope_level": "account|site",
    "scope_id": "<19-digit>",
    "site_name": "<name or null>",
    "created_at": "<iso>",
    "updated_at": "<iso>",
    "version_count": <int>
  },
  "actions": [
    { "id": "<uuid>", "integration_id": "<uuid or null>", "type": "<action_type>" }
  ]
}
```

Action types observed: `singularity_response_trigger`, `manual_trigger`, `http_trigger`, `scheduled_trigger`, `email_trigger`, `http_request`, `condition`, `loop`, `variable`, `delay`, `send_email`, `snippet`, `data_formation`, `wait_for_slack`, `break_loop`, `create_interaction`, `wait_for_interaction`, `llm`.

### filter-count response structure

`GET /workflows/filters-count` returns `data[]` with keys: `states`, `scope_ids`, `trigger_types`, `core_actions`, `tags`, `integrations`. Each entry has `{ count, value, title }`. Use this for summary dashboards (e.g. how many active workflows, which integrations are most used).

### MCP tools

`ha_list_workflows`, list with scope (`accountIds` or `siteIds`; neither lists every account on a multi-account token)/sort/pagination. Returns `revisionId` alongside each workflow.
`ha_get_workflow`, fetch a single workflow by `workflowId` + optional `revisionId` (auto-resolves from list if omitted).
`ha_delete_workflow`, soft-delete one or more workflows via `DELETE /workflows/{id}` (scope with accountIds/siteIds). Confirm with user before calling.
`ha_import_workflow`, create workflow from JSON. Requires Hyper Automate.write permission.
`ha_export_workflow`, export all workflows as ZIP.

### Permissions

`Hyper Automate.view`, read operations (list, get, filter-count, export).
`Hyper Automate.write`, write operations (import, delete). Confirmed: without this permission, import returns 403.

## Using s1-secops-mcp tools for direct console operations

Console operations use the `s1-secops-mcp` MCP tools, which run on the user's machine and reach
`*.sentinelone.net` where the Cowork sandbox cannot. Use `s1_api_get`, `s1_api_post`,
`s1_api_download` (binary responses), `uam_list_alerts`, `uam_get_alert`, `uam_set_status`, `uam_set_verdict`,
`uam_assign_alert`, and the other MCP tools directly. The skill's Python scripts are host-only. The server reads credentials
from environment variables or the OS keychain and masks tokens in every response; if a credential
is missing, ask the user to run `s1-secops-mcp setup` on their machine.

## STAR / Custom Detection rule lifecycle (learnings)

- **Update in place:** `PUT /web/api/v2.1/cloud-detection/rules/{id}` requires the FULL body `{data, filter}`; omitting `filter` returns HTTP 400 "filter: Missing data for required field". PUT resets the rule to the body's `status` (typically Disabled), so re-enable afterward.
- **Delete:** `DELETE /web/api/v2.1/cloud-detection/rules/{id}`, or bulk with `{"filter": {"ids": [...], "siteIds" | "accountIds": [...]}}`.
- **List:** always pass `isLegacy=false` or scheduled / PowerQuery rules are silently omitted.
- **Scheduled rules run on a pre-aggregated data layer**, so PowerQuery functions like `dataset`, `datasource`, `now`, `querystart`/`queryend`/`queryspan`, `topK`, `savelookup`, CIDR/wildcard `lookup`, `lookup` over a >10,000-row table, time-shifted `timebucket`, and `timebucket` < 30s are NOT available in a scheduled-rule body (full list in the `powerquery` skill). A detection needing any of them, e.g. an absent-pair anti-join (`left join` + `dataset`), runs as a Hyperautomation watchdog instead (see `hyperautomation`).
- **Lookup-reading rules are account-scope only.** Lookup tables / datatables are ACCOUNT-level objects, so any rule whose PQ body reads one (`| lookup ... from <table>`) can only be created with `filter.accountIds`; site-scoped creation of lookup-reading rules is invalid.
