# API test coverage — mgmt-console-api

This folder holds the **reversible lifecycle tests** that exercise the
mutating endpoints exposed by the skill against a live tenant. They
complement `scripts/smoke_test_queries.py`, which is a read-only sweep of
every GET + curated safe POSTs.

> **Rule of thumb:** smoke_test_queries proves *what reads work on this
> tenant*; the tests in this folder prove *what write paths work end-to-end
> without leaving state behind*.

---

## At a glance

| Area | How it's tested | Script | Reversible? |
|---|---|---|---|
| Every GET + safe read-only POST | Non-destructive sweep across all 113 tags | `scripts/smoke_test_queries.py` | N/A (read-only) |
| Threat Intelligence IOCs | CREATE → LIST → DELETE → VERIFY | `tests/test_ioc_lifecycle.py` | Yes (requires single-scope token) |
| Unified Alerts (UAM) GraphQL + REST | list → detail → addNote → list-notes → deleteNote → verify, plus parallel REST `/cloud-detection/alerts` read | `tests/test_alerts_dual_api.py` | Yes |
| Saved filters (REST) | CREATE → LIST → UPDATE → DELETE → VERIFY | `tests/test_saved_filter_lifecycle.py` | Yes (needs token scope) |
| Custom Detection Rules | CREATE (disabled) → LIST → UPDATE → DELETE → VERIFY | `tests/test_custom_rule_lifecycle.py` | Yes |
| Alert status + verdict mutations | pick alert → status round-trip → verdict round-trip → history check | `tests/test_alert_mutation_lifecycle.py` | Yes (auto-restores to starting state) |
| Scheduled default-report tasks | CREATE → LIST → UPDATE → DELETE → VERIFY | `tests/test_scheduled_report_lifecycle.py` | Yes |
| Alert → Indicator pivot | read alert.rawIndicators → pin to TI IOC → verify link → delete | `tests/test_alert_indicator_pivot.py` | Yes (requires single-scope token) |
| UAM Alert Interface (single) | POST /v1/indicators + /v1/alerts (1 indicator, 1 alert) → poll UAM → verify link → close | `tests/test_uam_alert_interface_single.py` | Semi (closes alert; ingested events are not hard-deletable) |
| UAM Alert Interface (batch, multi-observable) | batched POST of 3 indicators (file+process+network, OCSF 1001/1007/4001) each with 3+ observables, 1 alert referencing all 3 on a single device -> poll UAM -> assert every metadata.uid + observable surfaces in alert.rawIndicators -> close | `tests/test_uam_alert_interface_batch.py` | Semi (closes alert; ingested events are not hard-deletable). PARTIAL: multi-indicator stitching is flaky on-tenant (2 of 3 indicators typically land inside a 2-minute grace window). See "Known limitations" below. |
| Unified Exclusions v2.1 | CREATE (EDR path, site scope) → LIST → DELETE → VERIFY | `tests/test_unified_exclusion_lifecycle.py` | Yes (scoped to one site, fictional path) |
| Hyperautomation workflow lifecycle | IMPORT (minimal manual-trigger workflow) → LIST (recent 20) → DELETE → VERIFY | `tests/test_hyperautomation_import_lifecycle.py` | Yes (REST DELETE, 204; validated 2026-06-13). See gotchas below. |
| Detection rule ENABLE/DISABLE | CREATE (disabled) → ENABLE → VERIFY_ON (accepts activating) → DISABLE → VERIFY_OFF → DELETE → VERIFY (scheduled + events both exercised) | `tests/test_detection_rule_activate_lifecycle.py` | Yes (demo site; 24h window prevents real firing) |
| XDR Graph Query | FORMAT DISCOVERY → SAVE → LIST → UPDATE → DELETE → VERIFY | `tests/test_xdr_graph_query_lifecycle.py` | Yes (skips gracefully if no saved queries exist on tenant to use as format template) |
| STAR rules (events-type detection) | CREATE (Draft) → LIST → UPDATE → DELETE → VERIFY | `tests/test_star_rule_lifecycle.py` | Yes (Draft status, never activates; fictional process name in query) |

Every lifecycle test embeds a unique `run_tag` in names and filters so
parallel runs never collide and cleanup only touches what the current run
created. Test scripts accept `--keep` for manual inspection (never the
default).

---

## Tokens and scopes

Some endpoints reject **multi-scope tokens** — service-user tokens that
are assigned to more than one account simultaneously — with
`HTTP 403 code 4030010 "This page doesn't support multi-scopes users
yet"`. Confirmed today (2026-04-22) on `/web/api/v2.1/threat-intelligence/iocs`.

Add two optional token fields to your `credentials.json` (in your Cowork project folder):

```json
{
  "S1_CONSOLE_API_TOKEN": "<multi-scope or single-scope>",
  "S1_CONSOLE_API_TOKEN_SINGLE_SCOPE": "<single-account-pinned>"
}
```

Both are optional — supply whichever you have. Tests that need a
single-scope token (`test_ioc_lifecycle.py`, `test_alert_indicator_pivot.py`)
instantiate the client with `S1Client(token_kind="single_scope")`. If only
one token is configured, the client falls back to it, and the test
precheck will skip cleanly with a clear message if the endpoint rejects
the fallback.

**Which endpoints need single-scope?** The known ones today:

- `/web/api/v2.1/threat-intelligence/iocs` — all CRUD methods
- (document further here as discovered)

Per SentinelOne engineering: multi-scope support for Threat Intelligence
and related UIs/APIs is still being built out. For now, TI requires
explicit scope selection via a single-account-pinned token.

---

## 1. Full API surface — read-only smoke sweep

`scripts/smoke_test_queries.py` enumerates every `GET` in the Swagger +
a hand-curated allow-list of read-only POSTs, calls them, and records the
HTTP status + response shape.

```
python scripts/smoke_test_queries.py                                # default: skip streaming endpoints
python scripts/smoke_test_queries.py --include-slow                 # also call exports / downloads
python scripts/smoke_test_queries.py --tag Threats                  # just one tag
python scripts/smoke_test_queries.py --workers 16 --timeout 10      # tuned fan-out
python scripts/smoke_test_queries.py --batch-deadline 45            # per-batch wall-clock cap
```

Outputs:

- `references/tenant_capabilities.json`  — machine-readable per-call record
- `references/tenant_capabilities.md`    — human-readable status rollup

Performance: the default sweep (`/export` and `/download` excluded) returns
in **~60 seconds** for 300+ endpoints on the reference Purple tenant.
`--include-slow` pulls everything back in and can take several minutes
because some XDR export endpoints stream large payloads.

---

## 2. Threat Intelligence IOC lifecycle — `test_ioc_lifecycle.py`

Proves the full IOC workflow end-to-end, reversibly:

```
CREATE  POST   /web/api/v2.1/threat-intelligence/iocs
LIST    GET    /web/api/v2.1/threat-intelligence/iocs?name__contains=<run_tag>
DELETE  DELETE /web/api/v2.1/threat-intelligence/iocs   (body filter: {uuids: [...]})
VERIFY  GET    /web/api/v2.1/threat-intelligence/iocs?name__contains=<run_tag>  (expect 0)
```

Uses `token_kind="single_scope"` (see **Tokens and scopes** above). Precheck
step verifies reachability before creating any state, so a bad token on the
first call does not leak IOCs.

Safe-by-design values only: RFC 5737/2606 reserved addresses and domains
(`192.0.2.1`, `198.51.100.1`, `example.com`) plus deterministic run-tag-
derived hashes that never match real malware.

---

## 3. Alerts dual-API round-trip — `test_alerts_dual_api.py`

Demonstrates the alert-API story end-to-end: **GraphQL UAM is PRIMARY**,
REST `/cloud-detection/alerts` is **SECONDARY**, parallel surfaces with
different ID formats.

```
1. POST /web/api/v2.1/unifiedalerts/graphql  (list alerts, first=5)
2. POST /web/api/v2.1/unifiedalerts/graphql  (alert(id) detail)
3. POST /web/api/v2.1/unifiedalerts/graphql  (addAlertNote mutation)
4. POST /web/api/v2.1/unifiedalerts/graphql  (alertNotes verify)
5. GET  /web/api/v2.1/cloud-detection/alerts?limit=3   (REST surface read)
6. POST /web/api/v2.1/unifiedalerts/graphql  (deleteAlertNote w/ mgmt_note_id retry)
7. POST /web/api/v2.1/unifiedalerts/graphql  (alertNotes verify — removed)
```

Why there is no `create alert` test: SentinelOne does **not** expose a
`createAlert` mutation. Alerts are server-side byproducts of detection
engines. To prove the create/destroy pattern on the detection side, see
`test_custom_rule_lifecycle.py` (section 5 below).

---

## 4. Saved-filter lifecycle — `test_saved_filter_lifecycle.py`

Reversible CREATE → LIST → UPDATE → DELETE → VERIFY against
`/web/api/v2.1/filters`. A saved filter is a personal saved-search
definition: zero protection impact, zero detection impact, invisible to
other users.

**Permission note:** token must have "Filters — create / update / delete"
scopes. On read-only pre-sales tokens CREATE returns 403 and the test
aborts cleanly with a clear message — expected behaviour, not a bug.

---

## 5. Custom Detection Rule lifecycle — `test_custom_rule_lifecycle.py`

CREATE → LIST → UPDATE → DELETE → VERIFY on
`/web/api/v2.1/cloud-detection/rules`.

```
CREATE  POST   /web/api/v2.1/cloud-detection/rules
       body.filter: {accountIds: [<id>]}
       body.data:   {name, severity, expirationMode, queryType, status=Disabled, s1ql}
LIST    GET    /web/api/v2.1/cloud-detection/rules?name__contains=<run_tag>&accountIds=...
UPDATE  PUT    /web/api/v2.1/cloud-detection/rules/{rule_id}
DELETE  DELETE /web/api/v2.1/cloud-detection/rules  body.filter: {accountIds, ids}
VERIFY  GET    /web/api/v2.1/cloud-detection/rules?name__contains=<run_tag>
```

The rule is created with `status: "Disabled"` — the backend represents
this as `status: "Draft"` in the response (a never-activated rule). A
disabled rule never evaluates against telemetry, so zero blast radius:
no alerts generated, no SOC noise. Belt-and-braces: the s1ql body uses a
deliberately non-matching process name
(`zzz-smoke-test-does-not-exist.exe`).

Tenant-scope filter (`filter={}`) is rejected on multi-account tokens with
`"Filter args is not compatible with user scope"` — the test scopes to
the first visible account instead.

---

## 6. Alert status + verdict round-trip — `test_alert_mutation_lifecycle.py`

Proves the UAM bulk-ops mutation pattern against an existing alert,
with full restoration:

```
1. Pick most-recent alert → record {status, analystVerdict}
2. set_alert_status  (rotates NEW→IN_PROGRESS or vice versa)  → wait_for_field
3. restore status to original                                  → wait_for_field
4. set_analyst_verdict (UNDEFINED ↔ TRUE_POSITIVE_BENIGN)      → wait_for_field
5. restore verdict to original                                 → wait_for_field
6. alertHistory audit — verify transitions logged
```

Why operate on an existing alert? SentinelOne doesn't expose
`createAlert` — alerts are engine byproducts. For reversible *create*
coverage on the detection side see test #5 above (rules), #7 below
(indicators pinned to alerts via IOCs).

**Blast radius:** on a clean run the alert ends in its starting state.
The alertHistory audit log *does* record the transitions — that's
working-as-intended, every status change is auditable by design. Use
`--keep` to leave mutations applied for UI inspection, `--alert-id <id>`
to target a specific alert.

---

## 7. Scheduled default-report lifecycle — `test_scheduled_report_lifecycle.py`

CREATE → LIST → UPDATE → DELETE → VERIFY against
`/web/api/v2.1/report-tasks`.

```
CREATE POST  /web/api/v2.1/report-tasks
       body: {data: {name, scheduleType=manually, insightTypes, fromDate, toDate},
              filter: {siteIds}}
LIST   GET   /web/api/v2.1/report-tasks?name=<run_tag>
UPDATE PUT   /web/api/v2.1/report-tasks/{id}
       body: {data: {name: <new>}}         # narrower schema than POST
DELETE POST  /web/api/v2.1/reports/delete-tasks
       body: {filter: {ids: [...]}}
VERIFY GET   /web/api/v2.1/report-tasks?name=<run_tag>  (expect 0)
```

Sharp edges baked into the test:

- CREATE response is `{data: {success: true}}` — **no id returned.** Task
  is retrieved by name in the LIST step.
- DELETE uses `POST /reports/delete-tasks` (not DELETE verb), wrapper is
  `filter.ids` (not `data.ids`).
- `fromDate`/`toDate` are required even for `scheduleType=manually` — they
  define the report's content window, not the schedule.
- `siteIds` live in the top-level `filter`, NOT inside `data`.
- PUT only accepts `name` / `frequency` / `day` / `recipients` /
  `attachmentTypes`. `scheduleType`, `fromDate`, `toDate`,
  `insightTypes` are rejected on UPDATE.

The task is created as `scheduleType="manually"` so no PDF is generated
during the test window.

---

## 8. Alert → Indicator pivot — `test_alert_indicator_pivot.py`

Exercises the SOC workflow "take an indicator observed on an alert and
promote it to a tracked TI IOC":

```
1. Pick most-recent alert
2. Read alert.rawIndicators, extract a file-hash observable (MD5/SHA256)
3. CREATE an IOC for that hash, tagged to the alert:
     externalId  = <run_tag>-<alert_id>
     description = "Pinned from alert <alert_id> by API test"
4. LIST /iocs?name__contains=<run_tag> — verify linkage via externalId
5. DELETE the IOC by uuid
6. VERIFY re-query returns zero
```

Uses `token_kind="single_scope"` (same as IOC lifecycle). If the alert's
rawIndicators don't expose a usable hash, falls back to a deterministic
hash derived from the run_tag; the workflow is still proven, just with
a non-real-world hash.

---

## 9. UAM Alert Interface (single) -- `test_uam_alert_interface_single.py`

Proves the **write-side** path into UAM with the minimum viable payload:
POST one OCSF FileSystem-Activity indicator and one SecurityAlert that
references it, poll UAM GraphQL until the alert surfaces on the tenant,
verify the indicator is stitched, then close the alert
(status=RESOLVED + analystVerdict=TRUE_POSITIVE_BENIGN) so it leaves the
SOC queue.

```
1. POST https://ingest.us1.sentinelone.net/v1/indicators   (gzip + Bearer + S1-Scope)
2. POST https://ingest.us1.sentinelone.net/v1/alerts        (finding_info.related_events[].uid)
3. Poll UAM GraphQL list_alerts for name~=<run_tag> (up to 90s)
4. alert_with_raw_indicators -> verify indicator.metadata.uid in rawIndicators
5. Close alert: status -> RESOLVED + analystVerdict -> TRUE_POSITIVE_BENIGN
```

This is a **different API family** from everything else in the skill. All
other tests hit `<tenant>.sentinelone.net/web/api/v2.1/...`. The UAM
Alert Interface (formerly "Ingestion Gateway") lives on a separate host
family (e.g. `ingest.us1.sentinelone.net`). Find your region endpoint at
https://community.sentinelone.com/s/article/000004961. The interface uses its own wire contract:

- Auth header is `Bearer <JWT>`, NOT `ApiToken <JWT>`. The mgmt console
  REST scheme is rejected with HTTP 401 `"Unsupported auth type: ApiToken"`.
- `Content-Encoding: gzip` is mandatory (zstd also accepted). Uncompressed
  bodies are rejected.
- `S1-Scope: <accountId>` or `<accountId>:<siteId>[:<groupId>]` is mandatory.
- Payload is **concatenated JSON** (one or more objects back-to-back,
  optionally newline-separated), then gzip-compressed.
- Indicator must carry `metadata.profiles = ["s1/security_indicator"]`
  and a unique `metadata.uid`. The alert references indicators via
  `finding_info.related_events[].uid == indicator.metadata.uid`.

The skill ships a standalone `scripts/uam_alert_interface.py` helper
(stdlib only, no `requests`) with `UAMAlertInterfaceClient`,
`build_file_indicator`, `build_process_indicator`, `build_network_indicator`,
and `build_alert_referencing` so callers can build other payload shapes
without rewriting the wire format. Legacy names (`scripts/ingestion_gateway.py`
and `IngestionGatewayClient`) are still exported as deprecation shims.

**"Semi-reversible":** the ingested alert is not hard-deletable via
public API, but the cleanup step marks it TRUE_POSITIVE_BENIGN / RESOLVED
and names it `smoke-<timestamp>-<uuid> alert`, so it is clearly tagged as
synthetic and exits the active analyst workload. Use `--keep` to leave
it in NEW for UI inspection. Configure the host via `--uam-url` (legacy
alias `--igw-url`), the `S1_HEC_INGEST_URL` env var, or the
`S1_HEC_INGEST_URL` key in `credentials.json` (former canonical
`S1_UAM_ALERT_INTERFACE_URL` and legacy snake_case `uam_alert_interface_url`
both still honored). Default is `https://ingest.us1.sentinelone.net`.

---

## 10. UAM Alert Interface (batch, multi-observable) -- `test_uam_alert_interface_batch.py`

Comprehensive round-trip that exercises the features the single-indicator
test does not: **batching**, **multiple observables per indicator**, and
**multiple indicators linked to one alert** across all three supported
OCSF classes.

```
1. Build 3 indicators in one batch:
   - file    (OCSF class 1001) with Hostname, File Name, SHA-256, MD5, User Name, IP Address
   - process (OCSF class 1007) with Hostname, Process Name, Resource UID (pid), User Name, IP Address
   - network (OCSF class 4001) with Hostname, src IP, dst IP, URL, User Name
2. POST /v1/indicators with all 3 in one gzipped concatenated-JSON body.
3. POST /v1/alerts with one alert whose finding_info.related_events has 3
   entries (one per indicator metadata.uid).
4. Poll UAM GraphQL list_alerts for the run_tag, then wait up to 30s more
   for server-side stitching to complete.
5. Read alert.rawIndicators; assert every expected metadata.uid is present
   and the observable names for each indicator surface correctly.
6. Close alert: status -> RESOLVED + analystVerdict -> TRUE_POSITIVE_BENIGN
   (runs even if the link assertion fails, to avoid leaking NEW alerts).
```

Reserved test values are baked in: RFC 5737 IPs (`192.0.2.0/24`,
`198.51.100.0/24`) and the RFC 2606 `example.com` domain, so nothing
touches real infrastructure. Hashes are deterministic per `run_tag`.

Same wire contract, same "semi-reversible" cleanup as test #9; the only
delta is the payload shape.

**Payload constraints (empirically confirmed on `your-tenant`
2026-04-22):**

1. **Alerts that span multiple devices are silently dropped by the
   stitcher.** If `resources[]` contains more than one asset, or the
   referenced indicators target different `device.uid` values but the
   alert still declares multiple resources, the alert returns HTTP 202
   at the wire but NEVER surfaces in UAM. The builder
   `build_alert_referencing()` mitigates this by collapsing to a single
   `resources[]` entry (first indicator's device) and documenting that
   callers who truly need per-indicator assets should emit separate
   alerts. The batch test uses a single shared device for all 3
   indicators, matching the doc's worked example ("multi-stage activity
   observed on DC01").
2. **`file.hashes` must be OCSF Fingerprint array, not dict.** OCSF
   1.6.0 defines `file.hashes` as an array of Fingerprint objects
   (`[{"algorithm_id": 3, "algorithm": "SHA-256", "value": "<hex>"}, ...]`).
   Posting `{"sha256": "<hex>"}` (dict form) returns 202 at the wire
   but the stitcher silently drops the file indicator. Bug discovered
   and fixed in `build_file_indicator()` on 2026-04-22 via diagnostic
   pass 2 (trial B `sha256-dict-layout` FAILS vs trial C
   `sha256-array-layout` OK). With the array shape, all 3 indicators
   (file + process + network) stitch reliably within 2-5s.
3. **Related_events payload requirements** (beyond `uid`): the UAM
   "Alert and Indicator Ingestion" doc calls these "recommended for UI
   rendering"; in practice they look load-bearing for the stitcher on
   multi-indicator alerts. Our builder populates them by default.
4. **GraphQL `alertWithRawIndicators` rendering quirk in batch mode.**
   When multiple rawIndicators are stitched to one alert, the server
   returns the flat-key representation (`observables[N].name`/`.value`/
   `.type_id`) with shuffled VALUES on all entries except the last.
   Keys are stable; values from other fields (e.g. `account.name`,
   `metadata.product.name`) bleed into `observables[N].*` slots. Does
   NOT affect stitching -- `metadata.uid` is correct and the UI reads
   from a different code path. Programmatic consumers should assert on
   `metadata.uid` presence in `alert.rawIndicators`, not on flattened
   `observables[N].name` fields, in batch mode. The batch test treats
   per-observable assertions as informational for this reason.

---

## 11. PowerQuery scheduled detection lifecycle — inline (2026-05-03)

Proves the full lifecycle for `queryType=scheduled` rules (PowerQuery-based detections) on the demo site (`siteId=<site-id>`). No separate test script exists yet — the lifecycle was confirmed via an inline Python session. See the schema gotchas below before writing a script.

```
CREATE  POST  /web/api/v2.1/cloud-detection/rules
        data: {name, queryType="scheduled", queryLang="2.0", severity, expirationMode,
               status="Disabled", scheduledParams: {query, runIntervalMinutes, lookbackWindowMinutes, threshold}}
        filter: {siteIds: [...]}
LIST    GET   /web/api/v2.1/cloud-detection/rules?isLegacy=false&siteIds=...&name__contains=...
UPDATE  PUT   /web/api/v2.1/cloud-detection/rules/{rule_id}
        data: {name, queryType, queryLang, severity, expirationMode, status, scheduledParams}
        filter: {siteIds: [...]}     ← required by live API; swagger incorrectly marks as optional
ENABLE  PUT   /web/api/v2.1/cloud-detection/rules/enable   filter: {ids, siteIds}
DISABLE PUT   /web/api/v2.1/cloud-detection/rules/disable  filter: {ids, siteIds}
DELETE  DELETE /web/api/v2.1/cloud-detection/rules         json_body: {filter: {ids, accountIds}}
VERIFY  GET   /web/api/v2.1/cloud-detection/rules?ids=...&siteIds=...&isLegacy=false  (expect 0 hits)
```

**Critical gotchas discovered (confirmed on live tenant 2026-05-03):**

1. `isLegacy=false` is mandatory on every GET for scheduled rules. Without it the list endpoint returns 0 results even though the rules exist and are visible in the console UI. The flag selects the PowerQuery 2.0 rule schema; the legacy schema (default) does not include scheduled rules.

2. `queryLang: "2.0"` is required on POST and PUT. Omitting it or setting `"1.0"` returns HTTP 400 `"query lang must be 2.0"`.

3. PUT requires `filter.siteIds` in the body even though the swagger marks `filter` as optional. The live API returns HTTP 400 `"filter: Missing data for required field"` if omitted.

4. PUT requires all five fields in `data`: `name`, `queryType`, `severity`, `expirationMode`, `status`. Any missing field returns HTTP 400.

5. DELETE body must be passed as `json_body=` keyword argument in s1_client (not as the second positional arg, which is query params). The correct call: `client.delete(path, json_body={"filter": {...}})`.

6. VERIFY via GET (hits=0), not a second DELETE. A second DELETE on an already-deleted rule returns HTTP 400 `"Could not find rule with id: ..."` rather than `affected=0`.

7. `scheduledParams.alertPerRow` and `scheduledParams.disableStreaksLogic` are returned by the API in POST/PUT responses but are not required fields on input.

---

## What's tested by layer

**Confirmed works via lifecycle tests (reversible CRUD proven):**

- Threat Intelligence IOCs — CREATE / LIST / DELETE / VERIFY
- UAM alerts — list / detail / filter / group-by / facets / CSV export
- UAM alert notes — add / list / delete (with mgmt_note_id retry)
- UAM alert status + analystVerdict — bulk-ops filter round-trip
- REST `/cloud-detection/alerts` — read (parallel surface)
- Saved filters — CREATE / LIST / UPDATE / DELETE / VERIFY *(requires Filters scope)*
- Custom Detection Rules — CREATE (Disabled) / LIST / UPDATE / DELETE / VERIFY
- Scheduled default-report tasks — CREATE / LIST / UPDATE / DELETE / VERIFY
- Alert → IOC pinning pivot — rawIndicator read + pinned IOC CRUD
- UAM Alert Interface `/v1/indicators` + `/v1/alerts` -- push OCSF indicators + alert into UAM (single + batched 3-indicator / multi-observable across OCSF 1001/1007/4001), verify stitching, close via bulk-ops
- PowerQuery Scheduled Detections (`queryType=scheduled`) — CREATE / LIST / UPDATE / ENABLE / DISABLE / DELETE / VERIFY on demo site (2026-05-03)

**Confirmed reachable via read-only smoke sweep** (see
`references/tenant_capabilities.md` for the current tenant's full rollup):

- Accounts / Sites / Groups / Users / Service Users — full read surface
- Agents — list, filters, count, passphrase, summary, tags
- Threats — list, filters, count, timeline, notes, mitigation history, summary, search-on-endpoints
- Activities, Firewall Control, Device Control, Exclusions (v2.0 + v2.1)
- Graph Query Builder & Management (metadata, recent-queries, type-counts)
- Deep Visibility — queries, query-status, events, sessions (partial)
- Hyperautomation — workflows, executions, schedules (partial)
- Reporting — insights, reports
- RBAC — roles (read), token metadata
- Cloud / Container / Identity / Device / Function / Data-Store inventory
- Unified Alert Management GraphQL — full query + mutation surface
- Purple AI GraphQL — `purpleLaunchQuery` (undocumented but reachable)

**Untested by design — destructive or high-blast-radius:**

- Agent isolation / reconnect / uninstall / shutdown / restart
- Policy create / update / delete (tenant-wide impact)
- RemoteOps script execution (arbitrary code on endpoints)
- Account / site / group creation and deletion
- User creation / password reset / permission changes
- Threat / alert *bulk* mutations at scope=tenant
- Agent moves between sites / groups
- Upgrade / downgrade agent packages
- Firewall / device-control policy changes
- Deep-Visibility query cancellation mid-flight
- Cloud Funnel log-collection configuration changes
- Tags create/delete (reversible in theory but depends on tenant-wide taxonomy)

**Untested but eligible for future reversible coverage:**

- XDR Graph Query full cycle — `test_xdr_graph_query_lifecycle.py` exists and will run once any user saves a query via the Graph Explorer UI (provides the format template). Currently skips on tenants with no saved queries.

**Finding: no separate STAR rules endpoint.** The earlier note about a `/star-rules` endpoint family was incorrect. Confirmed against the live API (2026-05) and the swagger: no such path exists (returns 404). STAR rules are `cloud-detection/rules` with `queryType=events`. They are now covered by `test_star_rule_lifecycle.py`.

---

## 12. Unified Exclusion lifecycle (2026-05-03)

```
CREATE  POST  /web/api/v2.1/unified-exclusions
        data: {exclusionName, threatType="EDR", osType="linux",
               type="path", value=<path>, pathExclusionType="file",
               modeType="suppression", engines="suppress",
               reason="internal_testing", recommendation="NONE"}
        filter: {siteIds: [...], scopeLevel="site", scopeLevelId=<siteId>}
LIST    GET   /web/api/v2.1/unified-exclusions?siteIds=...&exclusionName__contains=...
DELETE  DELETE /web/api/v2.1/unified-exclusions
        body: {data: {exclusions: [{id: <id>, type: "path"}]}}
VERIFY  GET   (expect 0 hits)
```

**Gotchas confirmed vs. live API:**
- `modeType` and `type` are required — swagger marks them optional but API rejects without them.
- `engines` is required when `modeType=suppression`.
- `engines` and `interactionLevel` are mutually exclusive — passing both returns HTTP 400.
- `pathExclusionType` valid values: `file`, `folder`, `subfolders`. `suppress` is not valid.
- Path value goes in `value`, not `pathValue`.
- `filter.scopeLevel` is required (despite swagger). For site scope: `scopeLevel="site"` + `scopeLevelId=<siteId>` (camelCase).
- POST returns `data` as a list, not a single object — read `response["data"][0]["id"]`.

## 13. Hyperautomation workflow import lifecycle (2026-05-03)

```
IMPORT  POST  /web/api/v2.1/hyper-automate/api/public/workflow-import-export/import
        body: {data: {name, description, actions: [...]}, filter: {accountIds: [...]}}
        response: top-level "id" and "version_id" (NOT "workflowId"/"versionId")
LIST    GET   /web/api/v2.1/hyper-automate/api/public/workflows
        ?accountIds=...&limit=20&skip=0&sortBy=updated_at&sortOrder=desc
        items: {id: <uuid>, workflow: {id: same_uuid, name, state, ...}, actions: [...]}
DELETE  DELETE /web/api/v2.1/hyper-automate/api/v1/workflows/{id}?accountIds=<acct>
        -> 204 No Content (soft, recoverable delete)
```

**Gotchas confirmed vs. live API:**
- Public import response key is `id` not `workflowId`; `version_id` not `versionId`.
- `/api/public/workflows` and `/api/v1/workflows` return the same nested format: `{id, workflow: {...}, actions: []}`. The `workflow.id` == top-level `id`.
- Tenant had 1050+ workflows. `nextCursor` returns literal string `"null"` (truthy in Python) — loop by skip/limit, not cursor. Sort by `updated_at desc` and scan first 20 to find a newly imported workflow without paginating 1050 rows.
- Delete is a REST `DELETE /api/v1/workflows/{id}?accountIds=<acct>` (returns 204, soft/recoverable; validated 2026-06-13: import then publish then delete then gone-from-list). Scope with `accountIds` or `siteIds` to match where the workflow lives. The older `POST /workflows/archive` returns HTTP 500 on this tenant regardless of body shape — do not use it. The test deletes via the REST DELETE and treats a delete failure as fatal.

## 14. Detection rule ENABLE/DISABLE lifecycle (2026-05-03)

```
CREATE   POST  /web/api/v2.1/cloud-detection/rules  (see Section 11 for scheduled schema)
ENABLE   PUT   /web/api/v2.1/cloud-detection/rules/enable
         body: {filter: {ids: [<ruleId>], siteIds: [<siteId>]}}
DISABLE  PUT   /web/api/v2.1/cloud-detection/rules/disable
         body: {filter: {ids: [<ruleId>], siteIds: [<siteId>]}}
DELETE   DELETE /web/api/v2.1/cloud-detection/rules
         body: {filter: {ids: [...], accountIds: [...]}}
```

**Gotchas confirmed vs. live API:**
- After ENABLE, `status` transitions through `"activating"` before settling on `"active"`. Both are valid post-enable states — accept both in assertions.
- Tested with both `queryType=scheduled` (requires `isLegacy=false` on GET) and `queryType=events`. Both use the same enable/disable endpoints.
- Tested on demo (site <site-id>). Scheduled rule used `runIntervalMinutes=1440` and `threshold.value=9999` so it cannot fire within the test lifetime even when briefly enabled.

---

## 15. STAR rule lifecycle (2026-05-03)

STAR rules ("streaming threat assessment rules") are product marketing terminology for
real-time event detection rules. The API has no `/star-rules` path — they are
`cloud-detection/rules` with `queryType=events`. The `/star-rules` path returns 404.

```
CREATE  POST   /web/api/v2.1/cloud-detection/rules
        body: {data: {name, description, queryType="events", s1ql, severity,
                      expirationMode, status="Draft", treatAsThreat, networkQuarantine},
               filter: {siteIds: [...]}}
        response: top-level "data" object with id, queryLang="1.0", status="Draft"
LIST    GET    /web/api/v2.1/cloud-detection/rules?ids=<id>&siteIds=<id>
UPDATE  PUT    /web/api/v2.1/cloud-detection/rules/{rule_id}
        body: same shape as CREATE; all 5 required fields must be re-supplied
DELETE  DELETE /web/api/v2.1/cloud-detection/rules
        body: {filter: {ids: [...], siteIds: [...]}}   # top-level filter, no "data" wrapper
        response: {data: {affected: N}}
VERIFY  GET    ids=<id> → data=[]
```

**Gotchas confirmed vs. live API:**
- No `/star-rules` path — use `cloud-detection/rules` with `queryType=events`.
- `"activeResponse"` in the CREATE body returns HTTP 400 "Unknown field" — omit it.
- `queryLang` defaults to `"1.0"` for events rules; do not set it explicitly.
- `treatAsThreat="UNDEFINED"` is accepted on input but stored as `null` in the response.
- GET `nameSubstring` + `queryType` together returns HTTP 500 — use only one filter per
  request, or use `ids` for precise lookup after creation.
- Draft status = rule never fires even if agent telemetry matches the query.
- `isLegacy=false` is NOT required for events rules (only needed for scheduled).
- DELETE body uses top-level `filter` (no `"data"` wrapper) — same as exclusion delete.

---

## Running the full test suite

```
# 1. Read-only sweep — ~60s default, several minutes with --include-slow.
python scripts/smoke_test_queries.py --workers 16 --timeout 10

# 2. Reversible lifecycles — each ~3–15s end-to-end. Full set ~1 minute.
python tests/test_ioc_lifecycle.py                  # IOC CRUD (single-scope token)
python tests/test_alerts_dual_api.py                # UAM + REST alert surfaces
python tests/test_saved_filter_lifecycle.py         # skips cleanly if token lacks scope
python tests/test_custom_rule_lifecycle.py          # Custom Detection Rules
python tests/test_alert_mutation_lifecycle.py       # status + verdict round-trip
python tests/test_scheduled_report_lifecycle.py     # default-report tasks
python tests/test_alert_indicator_pivot.py          # alert→IOC pivot (single-scope)
python tests/test_uam_alert_interface_single.py     # POST 1 OCSF indicator + 1 alert, verify in UAM, close
python tests/test_uam_alert_interface_batch.py      # batched POST of 3 multi-observable indicators + 1 alert referencing all 3, verify in UAM, close
python tests/test_unified_exclusion_lifecycle.py    # EDR path exclusion CREATE/LIST/DELETE
python tests/test_hyperautomation_import_lifecycle.py  # workflow IMPORT/LIST/DELETE
python tests/test_detection_rule_activate_lifecycle.py  # ENABLE/DISABLE scheduled + events rules
python tests/test_xdr_graph_query_lifecycle.py      # graph query SAVE/LIST/UPDATE/DELETE (skips if no saved queries)
python tests/test_star_rule_lifecycle.py            # STAR rule (events) CREATE/LIST/UPDATE/DELETE
```

All tests exit 0 on success and non-zero on any step failure, with the
failing run_tag / IDs printed to stdout for manual cleanup if needed.
