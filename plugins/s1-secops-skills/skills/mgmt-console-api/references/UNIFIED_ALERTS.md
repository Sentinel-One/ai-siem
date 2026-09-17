# Unified Alert Management (UAM) GraphQL API

**Endpoint:** `POST /web/api/v2.1/unifiedalerts/graphql`
**Schema endpoint:** `POST /web/api/v2.1/unifiedalerts/graphql/schema`
**Auth:** same `Authorization: ApiToken <token>` header as REST; no extra permission grant required beyond the RBAC entries under "Unified Alerts".
**Skill entry points:** `scripts/unified_alerts.py` (module) and `scripts/call_unified_alerts.py` (CLI).
**Upstream docs:** <https://community.sentinelone.com/s/article/000010170>

---

## When to use this vs REST threats / alerts

Use UAM for any work on the Unified Alerts product: multi-source alert triage (EDR, XDR, Identity, STAR, Cloud, NGFW, Mimecast, Proofpoint, etc.), facet-style filtering, bulk actions, and alert notes. The v2.1 REST `/threats` endpoints cover the older "threats" surface only, for everything else that shows in the modern Alerts inbox, start here.

UAM is a single GraphQL surface (17 queries + 4 mutations). Every query and mutation is built around the same `ScopeSelectorInput`, `OrFilterSelectionInput`, and `FilterInput` types, once you have those right, the rest is just picking fields.

---

## Getting started in Python

```python
import sys
sys.path.insert(0, "scripts")
from s1_client import S1Client
import unified_alerts as uam

c = S1Client()

# 1. discover what you can query
cols = uam.column_metadata(c)          # fieldIds, enum values, filter types
avail = uam.view_data_availability(c)  # which views have data for this tenant

# 2. list alerts (flat filter list is AND; use `alerts` for this)
page = uam.list_alerts(
    c,
    filters=[
        uam.build_filter(fieldId="detectionProduct", stringEqual={"value": "EDR"}),
        uam.build_filter(fieldId="status", stringIn={"values": ["NEW", "IN_PROGRESS"]}),
    ],
    first=20,
)

# 3. paginate
for alert in uam.paginate_alerts(c, page_size=200, max_alerts=1000):
    ...

# 4. act on a set of alerts (mutations use or/and nested filter)
account = uam.scope(["<account_id>"])
uam.set_alert_status(
    c, scope_input=account, alert_ids=["<alert1>", "<alert2>"],
    status="RESOLVED", note="Closed: false positive",
)
```

---

## CLI quick reference

```bash
# list / get / notes
python3 call_unified_alerts.py list --filter detectionProduct=EDR --first 10
python3 call_unified_alerts.py list --filter 'status=NEW,IN_PROGRESS' --first 50
python3 call_unified_alerts.py get <alert-id>
python3 call_unified_alerts.py notes <alert-id>

# facets / groups
python3 call_unified_alerts.py facets status severity detectionProduct
python3 call_unified_alerts.py groups detectionProduct --first 10
python3 call_unified_alerts.py group-by severity --filter status=NEW

# mutations (blast radius scoped to explicit alert ids)
python3 call_unified_alerts.py add-note    <alert-id> "Investigating"
python3 call_unified_alerts.py update-note <note-id>  "Updated"
python3 call_unified_alerts.py delete-note <note-id>
python3 call_unified_alerts.py set-status --scope <account-id> --alert-id <id1> <id2> RESOLVED --note "..."

# exports
python3 call_unified_alerts.py csv-export --filter detectionProduct=EDR -o edr.csv
python3 call_unified_alerts.py history-csv <alert-id> -o alert_history.csv
```

Filter syntax: `fieldId=value` (stringEqual), `fieldId=v1,v2` (stringIn), `fieldId~=prefix` (stringStartsWith), `fieldId:fullText=text` (FULLTEXT).

---

## Operation surface (all tested on live tenant)

### Queries

| Name | Purpose | Wrapper | Notes |
|---|---|---|---|
| `alerts` | Primary alert list | `list_alerts`, `paginate_alerts` | Connection (edges/pageInfo/totalCount). `filters:` is `[FilterInput!]` (AND-joined). |
| `alert(id)` | Fetch one alert | `get_alert` | Returns `Alert` with all enrichment fields. |
| `alert(id) { indicators }` | The alert's rendered indicators | `get_alert_indicators` | This is what the inline `POST /v1/alerts` path populates and what the console Indicators tab renders, so it is what an ingest round-trip must be validated against. `Indicator` has `type`, `uid`, `title`, `description`, `message`, `severity`, plus the `observables { name value type }` sub-selection. No `name`, no `category`: either fails the whole query with `FieldUndefined`. |
| `alertWithRawIndicators` | Alert + raw indicator JSON | `get_alert_with_raw_indicators` | Nested shape: `{ alert { ... }, rawIndicators }`. `rawIndicators` is a SCALAR (a JSON list): sub-selecting it returns `SubselectionNotAllowed`, so request it bare. It was fed by `POST /v1/indicators`, which no credential can drive any more, so on ingested alerts it is `[]`. Read `alert.indicators` via `get_alert_indicators` instead. |
| `alertColumnMetadata` | Discover fields/enums | `column_metadata` | Tells you what you can filter, sort, group on; enum values per field. |
| `alertAvailableActions` | What can be triggered | `available_actions` | Needs `scope` + `filter` (OrFilter). No filter ⇒ returns 0. |
| `alertNotes` | List notes on an alert | `alert_notes` | `AlertNotesListResponse` wraps a bare `data` list. |
| `alertHistory` | Audit history | `alert_history` | Connection; items are `AlertHistoryItem` with `eventType`/`eventText`/`createdAt` (no id). |
| `alertTimeline` | Timeline view | `alert_timeline` | Same shape as alertHistory. |
| `alertMitigationActionResults` | Mitigation outcomes | `alert_mitigation_action_results` | `data` list wrapper. |
| `alertGroupByCount` | Facet counts | `group_by_count` | Schema marks deprecated (use alertGroups). `AlertGroupByResponse { data[] }` → `{fieldId, hasNextPage, values[{value,label,count}]}`. |
| `alertFiltersCount` | Facet counts for UI sidebar | `filters_count` | Similar `data` wrapper; `values[{value,label,count}]`. |
| `alertGroups` | Paginated group-by | `alert_groups` | Connection; node has `value`/`label`/`count`. |
| `autocompleteOptions` | Suggest values for a field | `autocomplete` | Needs `searchText` length ≥ 3; not every field supports it (e.g. `externalId` refuses). Option has `{value, count}`; no `label`. |
| `alertsViewDataAvailability` | Which views have data | `view_data_availability` | Nested: `viewDataAvailability[{viewType, dataAvailable}]`. |
| `aiInvestigations` | AI investigation status | `ai_investigations` | Returns `[AiInvestigation!]` **directly** (no `data` wrapper). |
| `alertsCsvExport` | Bulk alerts CSV | `export_alerts_csv` | `CsvResponse { data }`; returns a CSV string. |
| `alertHistoryCsvExport` | Single-alert history CSV | `export_alert_history_csv` | Same shape. |

### Mutations

| Name | Purpose | Wrapper | Notes |
|---|---|---|---|
| `addAlertNote` | Create note | `add_alert_note` | Returns the full note list for the alert (find the new one by matching text or by diffing ids before/after). |
| `updateAlertNote` | Edit note | `update_alert_note` | Fails for ~30-90s after creation with `mgmt_note_id not set`. Wrapper retries automatically. |
| `deleteAlertNote` | Remove note | `delete_alert_note` | Same eventual-consistency behaviour; wrapper retries. |
| `alertTriggerActions` | Bulk actions against a filter | `trigger_actions` + convenience wrappers (`set_alert_status`, `set_analyst_verdict`, `assign_alerts`) | Filter is `OrFilterSelectionInput` (use `or_filter(...)`). Result is a union of `ActionsTriggered \| TriggerActionsError \| TriggerActionsScheduled`. `ActionsTriggered` is not success, see below. |

### `ActionsTriggered` is an acknowledgement, not a result

A refused write returns `__typename: "ActionsTriggered"` with the alert id under
`actions[].failure[]`, identical in shape to an accepted one apart from which
sub-list the id lands in. Code that checks for an exception, or checks only the
`__typename`, reads a refusal as a success. Three callers in this repo did, and
one printed `CLEANUP ok` for an alert that never left `NEW`.

The reason is in `actions[].failure[].errorMessage`, so `trigger_actions`
selects `failure { id errorMessage __typename }`. Reduce the payload with
`action_outcome(resp)`:

```python
oc = ua.action_outcome(ua.set_alert_status(
    client, scope_input=sc, alert_ids=[alert_id], status="RESOLVED"))
if not oc["applied"]:
    raise RuntimeError("; ".join(oc["errors"]))
```

`applied` is True only when every action reported a success and no failures. A
`TriggerActionsScheduled` payload gives `applied=False`, because a bulk job has
not written anything yet and the caller has to poll.

### A refused action: ask `alertAvailableActions` for the cause

`failure[].errorMessage` names the failure, not the cause. Query
`alertAvailableActions` with a narrow filter and read `isDisabled` /
`disabledReason`. `trigger_actions(diagnose_failures=True)` (the default) does
this on any failure and attaches the result under `resp["diagnosis"]`, which
`action_outcome` folds into its error strings.

`explain_action_failure()` returns three states:

| State | Meaning |
|---|---|
| `not_offered` | This caller may not trigger it on this alert. Check the service user's UAM permissions. |
| `disabled` | Offered but disabled, with the API's own `disabledReason`. |
| `offered` | Available here, so the mutation error is the real cause. Escalate. |

**Availability is filtered by the caller's permissions AND the alert type.** One
service-user token is offered `statusUpdate` on a native STAR alert and not on
an alert ingested via `/v1/alerts`; a console user session performs the
identical mutation on either. So `not_offered` means "this identity lacks what
this alert needs", never "impossible".

Availability is also scope-sensitive: `S1/incident/*` reports
`INCIDENT_ACTIONS_ONLY_AVAILABLE_FROM_SITE_VIEW` under `ACCOUNT` scope and is
enabled under `SITE`. Re-check per scope.

The enum is not a hidden cause: an invalid value is rejected outright (`CLOSED`
raises `Invalid input for enum 'Status'`). Live enum:
`NEW | IN_PROGRESS | RESOLVED`.

### Hyperautomation native actions

`hyperautomation/references/integration-catalog.md` lists native write-back
actions with their `public_action_id`: `Set Alert Status to Resolved`,
`Resolve Alert as False Positive Benign`, `Resolve Alert as True Positive
Malware` (all against `/web/api/v2.0/threats`, the EDR **threat** family, which
is a different object from a UAM alert and decommissioned for note / verdict /
status), plus `Verdict False Positive Benign` and `Status In Progress` (against
`/web/api/v2.1/unifiedalerts/graphql`, the same endpoint and ids as above).

---

## Schema quirks you need to know

These are the traps the wrapper hides, in case you're writing GraphQL by hand.

**`OrFilterSelectionInput` vs flat `[FilterInput!]`.**
The `alerts` query takes `filters: [FilterInput!]`, a flat AND-joined list. Mutations and `alertAvailableActions` take `filter: OrFilterSelectionInput`, shaped as `{ or: [ { and: [FilterInput,...] }, ... ] }`. Passing a flat list to a mutation is a validation error; passing an or/and wrapper to `alerts` is also an error.

**`FilterInput` comparators.** One field plus one comparator per filter object. Common: `stringEqual {value}`, `stringIn {values[]}`, `stringStartsWith {value}`, `stringEndsWith {value}`, `fullText {value}`, `boolEqual {value}`, `intEqual {value}`, `intIn {values[]}`, `dateRange {from,to}`. Check `alertColumnMetadata.filterTypes` for a field before picking one, not every comparator is supported on every field.

**Connection vs `data` wrapper.** Some types use the GraphQL connection pattern (`edges { node } pageInfo totalCount`): `alerts`, `alertHistory`, `alertTimeline`, `alertGroups`. Others wrap their list under `data`: `alertNotes`, `alertMitigationActionResults`, `alertGroupByCount`, `alertFiltersCount`, `alertAvailableActions`, CSV exports. A handful return bare list/scalar: `aiInvestigations`, `alertColumnMetadata`.

**Facet value shapes.** `alertGroupByCount.data[*].values[*]` uses `{value, label, count}`. `alertFiltersCount.data[*].values[*]` uses the same. `alertGroups` nodes use `{value, label, count}` (NOT `groupValue`). `autocompleteOptions.values[*]` uses `{value, count}`; no `label`.

**`alertAvailableActions.errors` is `[ActionsError!]`.** You have to subselect at least `{ errorMessage }` on it, even if you don't care about the errors.

**`alertsViewDataAvailability` is doubly nested.** The query returns `ViewDataAvailabilityResponse` which contains `viewDataAvailability: [ViewDataAvailability!]!`. So the full path is `alertsViewDataAvailability.viewDataAvailability[*].{viewType, dataAvailable}`.

**`aiInvestigations` has no `data` wrapper.** It returns `[AiInvestigation!]` directly on the root.

**`alertHistoryItem` / `alertTimelineItem` have no `id`.** Use `createdAt + eventType + eventText` for display / dedup.

**`SortOrderType`, not `SortOrder`.** The enum name has the `Type` suffix.

**`alertGroupByCount` takes `limit`, not `first`.** The rest of the group-by / connection family uses `first` / `after`. This one is an outlier (and the schema marks it deprecated in favour of `alertGroups`).

---

## Scope and view

`ScopeSelectorInput` is `{ scopeIds: [ID!]!, scopeType: ScopeType }` where `scopeType ∈ { ACCOUNT, SITE, GROUP, GLOBAL }`. Use `uam.scope(["<id>"])` to build one.

`ViewType` (used by `alerts`, `alertsCsvExport`, `alertTriggerActions`): `ALL`, `ENDPOINT`, `IDENTITY`, `STAR`, `CUSTOM_ALERTS`, `CLOUD`, `THIRD_PARTY`. `ALL` is the default.

---

## Action catalogue

From live `alertAvailableActions` on a Singularity Platform tenant with EDR, Identity, CWS, STAR, Mimecast, Proofpoint, Vectra, Palo Alto, Netskope, Singularity Mobile, and several marketplace apps enabled. Your tenant's list will differ; always call `available_actions(...)` with a narrow filter to see what's actually live before you trigger anything.

| Action ID | Type | What it does |
|---|---|---|
| `S1/alert/analystVerdictUpdate` | ALERT | Set analystVerdict (TRUE_POSITIVE, SUSPICIOUS, FALSE_POSITIVE_USER_ERROR, etc.) |
| `S1/alert/statusUpdate` | ALERT | Set status (NEW, IN_PROGRESS, RESOLVED) |
| `S1/alert/assignUser` | ALERT | Assign to user (payload `{assignUser:{userEmail}}`) |
| `S1/alert/setTicketId` | ALERT | Attach external ticket id |
| `S1/alert/addNote` | ALERT | Add a free-text note |
| `S1/alert/eventSearch` | REFERENCE | Pivot to Event Search |
| `S1/kill` | MITIGATION | Kill matched process |
| `S1/quarantine` | MITIGATION | Quarantine |
| `S1/remediate` | MITIGATION | Remediate |
| `S1/rollback` | MITIGATION | Rollback |
| `S1/disconnectFromNetwork` | ASSET | Network-isolate host |
| `S1/addToBlocklist` | MITIGATION | Add hash to blocklist |
| `S1/addToExclusions` | MITIGATION | Add to exclusions |
| `S1/runScript` | ASSET | Run RemoteOps script |
| `S1/forensicsCollection` | ASSET | Trigger forensics collection |
| `S1/downloadDetectedFile` | DOWNLOAD | Download detected file |
| `S1/aiInvestigation/run` | AI_INVESTIGATION | Kick off AI investigation |
| `MARKETPLACE/<uuid>` | varies | Marketplace-installed apps (Virustotal, Carbon Black, etc.) |

---

## Common recipes

**Status roll-up for an account**

```python
facets = uam.filters_count(c, ["status", "severity", "detectionProduct"])
```

**EDR alerts from the last hour**

```python
import time
cutoff_ms = int((time.time() - 3600) * 1000)
edr = uam.list_alerts(c, filters=[
    uam.build_filter(fieldId="detectionProduct", stringEqual={"value": "EDR"}),
    uam.build_filter(fieldId="detectedAt", dateRange={"from": cutoff_ms}),
], first=100)
```

**Bulk resolve all `NEW` STAR alerts (mirrors the upstream docs example)**

```python
filt = uam.or_filter([
    uam.build_filter(fieldId="detectionProduct", stringEqual={"value": "STAR"}),
    uam.build_filter(fieldId="status", stringEqual={"value": "NEW"}),
])
uam.trigger_actions(
    c, scope_input=uam.scope(["<account_id>"]),
    filter_input=filt,
    actions=[
        {"id": "S1/alert/statusUpdate",
         "payload": {"status": {"value": "RESOLVED"}}},
        {"id": "S1/alert/analystVerdictUpdate",
         "payload": {"analystVerdict": {"value": "FALSE_POSITIVE_USER_ERROR"}}},
        {"id": "S1/alert/addNote",
         "payload": {"note": {"value": "auto-closed"}}},
    ],
)
```

**Add → update → delete note with eventual consistency handled**

```python
notes_before = {n["id"] for n in uam.alert_notes(c, alert_id)}
uam.add_alert_note(c, alert_id, "Investigating")
notes_after = uam.alert_notes(c, alert_id)
new_id = next(n["id"] for n in notes_after if n["id"] not in notes_before)

# These will retry for up to 120s until mgmt_note_id settles
uam.update_alert_note(c, new_id, "Contained on host-123")
uam.delete_alert_note(c, new_id)
```

**CSV for an executive one-pager**

```python
csv = uam.export_alerts_csv(c, filters=[
    uam.build_filter(fieldId="severity", stringIn={"values": ["CRITICAL", "HIGH"]}),
    uam.build_filter(fieldId="status", stringEqual={"value": "NEW"}),
], view_type="ALL")
```

---

## Known error patterns

| Error message fragment | Cause | Fix |
|---|---|---|
| `Unknown type 'SortOrder'` | Used `SortOrder`, schema is `SortOrderType`. | Use `SortOrderType`. |
| `Unknown field argument 'first'` on `alertGroupByCount` | `alertGroupByCount` takes `limit`, not `first`. | Switch to `alertGroups` or use `limit`. |
| `Subselection required for type '[ActionsError!]' of field 'errors'` | Asked for `alertAvailableActions.errors` as a scalar. | Subselect `{ errorMessage }`. |
| `Subselection required for type 'CsvResponse!'` | Requested CSV export without picking `{ data }`. | Add `{ data }`. |
| `Field doesn't support auto-complete.` | `autocompleteOptions` on unsupported field (e.g. `externalId`). | Pick a supported field (`alertName`, `assetName`, `processName`, ...) or use `autocomplete` via alert list filter. |
| `Autocomplete requires minimum 3 characters` | `searchText` too short. | Send ≥ 3 chars. |
| `Alert Note with ID ... does not have mgmt_note_id set, unable to [edit\|delete], try again later!` | Note freshly created; management-side id hasn't propagated. | Retry after 30-120s. The wrapper does this automatically. |
| No actions returned from `alertAvailableActions` | Called it with no filter or with a filter that matches nothing. | Pass a non-empty `or_filter(...)` (e.g. by alert id). |
| **0 results with no error** when filtering `status="OPEN"` | `"OPEN"` is not a valid UAM status enum value. Returns 0 results silently; no GraphQL error is raised. Confirmed on live tenant. | Use `"NEW"` instead. Valid status values are `NEW`, `IN_PROGRESS`, `RESOLVED` only. |
| `Validation error (FieldUndefined@[alert/indicators/name]) : Field 'name' in type 'Indicator' is undefined` | Selecting `name` or `category` on `Indicator`. Neither field exists, and either one fails the whole query before it executes. | Select from `type`, `uid`, `title`, `description`, `message`, `severity`, plus the `observables` sub-selection. `indicator.name` / `indicator.category` are SDL PowerQuery fields on EDR behavioural-indicator events, an unrelated schema. |
| **0 results with no error** when filtering `status="FALSE_POSITIVE"` | `"FALSE_POSITIVE"` is an `analystVerdict` value, not a `status` value. Silently returns 0 results. | To filter by analyst verdict, use `fieldId="analystVerdict"` with `stringEqual {value: "FALSE_POSITIVE_USER_ERROR"}` (or whichever verdict value). Status and analystVerdict are separate fields. |

---

## Where the schema lives

The wrapper can fetch the SDL directly:

```python
from unified_alerts import fetch_schema
raw = fetch_schema(c)        # dict; the full SDL is under raw["_raw"]
Path("uam_schema.graphql").write_text(raw["_raw"])
```

The SDL is ~225 KB and self-describing, if a field shape ever changes, grep the latest dump before guessing.

---

## Asset / entity binding on detection-rule alerts

Findings from a live events-vs-scheduled reproduction (2026-06).

- Scheduled (PowerQuery) custom rules populate the Target Asset ONLY when `data.entityMappings: [{"columnName": "<output col>"}]` is configured (UI: "Entity column mapping") referencing column(s) the query projects. Without it the alert is "Unknown Device" (`agentUuid: null`). Projecting the column is necessary but not sufficient; the `entityMappings` declaration is what binds it. Confirmed live.
- Events-type rules bind the entity from the matched event. The entity TYPE is driven by the event's OCSF `class_uid`: authentication/identity classes (e.g. `3002`) bind an **Identity** (user); endpoint classes (e.g. `1008`) bind a **Device**, reconciled via `device.agent.uuid` against agent inventory. The class is the switch, not the presence of agent fields (a real `device.agent.uuid` on an auth-class event still bound an Identity).
- **UAM ingest** (`uam_ingest_alert`) builds the asset from the event's `device` object with `agentUuid: null` and `storylineId: null`, so neither agent reconciliation nor a storyline is needed. UAM alert ingest is distinct from raw log ingest though it shares the ingest host URL.
- `storylineId` is NOT required for asset binding (a device-bound alert had `storylineId: null`).

## Ingestion paths (event collector vs UAM)

Two distinct ingest APIs share the ingest host URL. They are not connected, and they take different credentials.

- **Raw log ingest** (event collector, `/services/collector/raw` and `/event`): raw logs/events + a named `parser`; feeds Event Search, PowerQuery, and detection rules. This is the log-ingestion path (replaces the removed SDL `uploadLogs`). It authenticates with an **SDL Log Write Key** (`S1_HEC_TOKEN`), not the console API token: on identical requests the write key returns `HTTP 200 {"text":"Success","code":0}` and the console token returns `HTTP 400 {"text":"Missing S1-Scope header","code":5}`. The key is minted for one account or site at Console > Singularity Data Lake > API Keys > Log Write Key, and that fixes the ingest destination; no `S1-Scope` header is sent and sending one has no effect. For pre-structured / OCSF JSON ingested with `?isParsed=true` (no parser), each event MUST include `dataSource.name`, `dataSource.vendor`, `dataSource.category` (set to `security` for custom OCSF sources), `event.type` (as a FLAT dotted key, a nested `event:{...}` object is dropped since `event` is reserved), and `site_id`. OCSF omits these, and without them events land with a null source (no attribution; `dataSource.name`-based filters/detections miss).
- **UAM alert ingest** (`uam_ingest_alert` / `uam_post_alert`, `POST /v1/alerts`): creates UAM alerts directly and builds the alert asset from the event `device` object. Still uses the console API token (`S1_CONSOLE_API_TOKEN`), with site routing via `scope = accountId:siteId`. Indicators have no separate endpoint: `/v1/indicators` refuses the console user token and the Log Write Key alike, so carry them inline in `finding_info.related_events[]`, which is also what feeds `alert.indicators` and the console Indicators tab.
