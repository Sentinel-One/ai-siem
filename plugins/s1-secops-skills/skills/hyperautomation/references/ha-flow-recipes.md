# Hyperautomation flow recipes

Moved out of `SKILL.md` to keep it under the 500-line authoring limit. Content unchanged.

## Running an SDL LRQ from an HA flow (async launch + poll): tenant-validated 2026-06-22

**Rule: always read SDL data from an HA flow via LRQ, never the synchronous `/api/powerQuery`.** The sync endpoint returns truncated / incomplete responses for large result sets (measured ~1/5 success on a ~1 MB `dataset` read; LRQ was 5/5) and is deprecated. Use LRQ for every SDL read from a workflow, including `dataset` / lookup-table reads, regardless of size. Reference `{{Connection.protocol}}{{Connection.url}}/sdl/v2/api/queries` so the host comes from the bound "SentinelOne SDL" connection, not a hardcoded tenant.

**Datatables are scope-specific.** A table saved with `savelookup` at site scope is not visible to a read at account scope (or an LRQ scoped by `accountIds`), and vice versa. Create the lookup in the same scope the flow reads.

`POST /sdl/v2/api/queries` is ASYNC. The launch response is NOT the results: it returns `body.id`
plus `body.stepsCompleted` / `body.stepsTotal`, and `body.data` is `null` while the query is still
running. The query id is also EPHEMERAL; it expires shortly after the query finishes. So a fixed
wait fails BOTH ways: too short returns `data: null` (still running); too long returns HTTP 404
"query id not found" (the id expired, and the downstream reference then resolves to
`UnresolvedLanguageReference`). Do NOT use one long delay. Use a tight POLL LOOP that reads the moment
the query is done. Required pattern (tenant-validated 2026-06-25):

1. **Launch**: `POST {{Connection.protocol}}{{Connection.url}}/sdl/v2/api/queries` with body
   `{"queryType":"PQ","tenant":true,"startTime":...,"endTime":...,"queryPriority":"HIGH","pq":{"query":...,"resultType":"TABLE"}}`.
   Capture `body.id` AND the `X-Dataset-Query-Forward-Tag` response header (mandatory, session-scoped,
   echoed on every GET/DELETE) into local vars. Extract the header case-insensitively with JQ:
   `{{Function.JQ(launch-slug.headers, "to_entries | map(select(.key|ascii_downcase==\"x-dataset-query-forward-tag\")) | .[0].value", true)}}`.
2. **Poll loop**: a `loop` (while, capped, e.g. 60 iterations) whose FIRST inner action is the GET
   `GET {{Connection.protocol}}{{Connection.url}}/sdl/v2/api/queries/{{local_var.query_id}}?lastStepSeen=0`,
   echoing header `X-Dataset-Query-Forward-Tag: {{local_var.forward_tag}}`. Then a condition on the
   POLL body (NOT the launch body, the launch body is captured once and never updates inside the loop):
   done when `{{poll-slug.body.stepsCompleted}} = {{poll-slug.body.stepsTotal}}` (operator `equals`;
   the done-condition field is **`stepsTotal`**. Live-verified 2026-07-29 by dumping a raw LRQ poll
   body: it carries BOTH `stepsTotal` and `totalSteps` (both equal, e.g. 2), so either works and
   neither doc was wrong about the key existing; use `stepsTotal` for consistency with pq.py and the
   SDL docs). TRUE → consume results + `break_loop`. FALSE → a
   short `delay` (~5s) as the leaf of the false branch; the loop then re-iterates and re-polls.

   **Read both counters through JQ WITH DEFAULTS, and gate on `> 0`.** A bare
   `{{poll-slug.body.stepsTotal}}` ERRORS the whole run when a poll response omits the attribute
   ("Attribute totalSteps not found in Action poll-silent-pairs"), which kills a watchdog whose
   query was fine. Use `{{Function.JQ(poll-slug.body, "(.stepsCompleted // -1)", true)}}` against
   `{{Function.JQ(poll-slug.body, "(.stepsTotal // 0)", true)}}`, plus a second condition
   `stepsTotal greater_than 0`. Without the `> 0` gate a pre-assignment 0/0 first poll satisfies
   `equals` and the flow processes an EMPTY result set as complete, which for a baseline refresh
   silently writes a stub that then suppresses every detection reading it.

   **Gate the loop on a 4xx, or a killed query spins to the workflow timeout.** The backend can
   terminate a running LRQ; the poll then answers `404 {"code":"not_found"}` for the rest of the
   run. HA does NOT treat that as a failed action, its `status` is `"success"` whenever a response
   arrives whatever the code, so with the JQ defaults above the equality never matches and the loop
   iterates until the run times out (17+ iterations observed live). `continue_on_fail: false` does
   NOT help, verified live: status codes are actionable only via `retry_on_status_codes`, and
   retrying a dead token is pointless. Put a condition BETWEEN the poll and the done-check:

   ```jsonc
   {"input_value": "{{poll-slug.status_code}}", "compared_value": "400",
    "comparison_operator": "greater_than_or_equals"}
   //   true  -> an action that ENDS the run
   //   false -> the existing done-check
   ```

   `status_code` sits at the TOP level of the action output, not under `.body`. To end the run
   deliberately, reference an attribute that cannot exist (e.g.
   `{{poll-slug.body.LRQ_TERMINATED_BY_BACKEND}}`): a missing attribute is the one mechanism
   observed to fail an HA run outright, and the attribute name becomes the console error text, so
   name it descriptively. Ending in Error is also what a health-notifier flow keys on. Silent
   completion is strictly worse than a loud failure here. Verified live: the flow that had been
   spinning errored in 103s after 6 actions with the sentinel named in `error_actions`.
3. **Loop-scoped outputs are NOT visible outside the loop.** Every action that reads a poll result
   (`{{poll-slug.body...}}`), extract/read, branch, notify, break, MUST live INSIDE the loop
   (`parent_action` = the loop's export_id). An action placed after the loop that references a
   loop-internal output fails to resolve. Read from the POLL response: `poll-slug.body.data.columns`
   (array of `{name}`), `poll-slug.body.data.values` (2D array); count rows with
   `{{Function.JQ(poll-slug.body.data.values, "length", true)}}`, index with
   `{{Function.ACCESS_LIST_ITEM(Function.ACCESS_LIST_ITEM(poll-slug.body.data.values, 0), 0)}}`.
   For a `savelookup` (no results consumed) the loop body is just poll → done-check → break/delay.

**Connection requirement (do not skip):** every SDL HTTP action (launch + poll) must set
`use_authentication_data: true` and be bound to the **"SentinelOne SDL"** connection, which signs
`Authorization: Bearer <jwt>`, the auth LRQ requires. The "SentinelOne" mgmt connection signs
`ApiToken` and the SDL endpoints reject it with `HTTP 500 "Header must start with Bearer"`.
Create/verify this connection at Hyperautomation → Integrations → SentinelOne SDL → Add Connection
(Bearer token) BEFORE activating the workflow; activation otherwise fails 400 "requires configuration".

**HEC event-collector ingest is a different credential and a different connection.** A
`POST {HEC_INGEST_URL}/services/collector/event` or `/raw` action takes an **SDL Log Write Key**, not
the console token. A Hyperautomation connection passes its credential through verbatim as
`Authorization: Bearer <value>`, so bind a second Bearer connection whose key value is the Log Write
Key for the target account or site. The console token is refused with `HTTP 400 {"text":"Missing
S1-Scope header","code":5}` where the write key returns `HTTP 200 {"text":"Success","code":0}`, and
adding an `S1-Scope` header does not fix it. Send no `S1-Scope` header on collector actions: the key
is minted for one account or site and that fixes the destination. `/v1/alerts` on the same host is
the opposite case, see the UAM section below, so do not copy collector auth to it.

## Posting a UAM SecurityAlert from an HA flow that actually SURFACES

Post ONE self-contained alert to `{HEC_INGEST_URL}/v1/alerts` (Bearer + `S1-Scope` headers, using
the console API token, which alert ingest still takes). Embed the indicator inline in
`finding_info.related_events[]`: one round trip, no indicator-registration timing to get wrong.
There is no two-call alternative any more, see below. Fields the stitcher REQUIRES, or you get
HTTP 202 but a SILENT DROP (no alert appears):

- **`class_uid` = `99602001`** ("S1 Security Alert") + `class_name:"S1 Security Alert"`,
  `type_uid:9960200101`, `type_name:"S1 Security Alert: Create"`. **Generic OCSF `class_uid` 2002 is
  silently dropped, this was the actual bug.**
- Top-level **`resources`: [{uid, name, type_id:1, type:"host"}]** (the mapped asset).
- `category_uid:2`, `category_name:"Findings"`, `activity_id:1`, `severity_id`, `state_id:1`,
  `s1_classification_id:1`, `attack_surface_ids:[1]`, top-level `time` (epoch ms).
- `metadata.version:"1.6.0-dev"`, `metadata.extension:{name:"s1",uid:"998",version:"0.1.0"}`,
  `metadata.product:{name,vendor_name}`, `logged_time`, `modified_time`.
- `finding_info:{uid,title,desc,related_events:[...]}`. Each related_event needs `uid, class_uid,
  type_uid, category_uid, activity_id, severity_id, time, message` and `observables[]` (each with
  BOTH `type` AND `typeName`).

**What the related_events entry becomes in the console.** The entry IS the
indicator: `alert.indicators` in UAM GraphQL, which is what the Indicators tab renders, is
populated from `finding_info.related_events[]` with nothing sent to `/v1/indicators`. Per entry:

| related_events field | renders as |
|---|---|
| `title` | `Indicator.title` |
| `desc` | `Indicator.description` |
| `message` | `Indicator.message` |
| `severity_id` | `Indicator.severity`, resolved PER INDICATOR, independent of the alert envelope |
| `observables[]` | `Indicator.observables`, `type_id` mapped to the UI enum (1 HOSTNAME, 2 IP, 4 USER_NAME, 5 EMAIL, 9 PROCESS_NAME, 10 RESOURCE_UID) |

Add `title` and `desc`: without them the indicator renders with a null title and description.
Multiple entries give multiple indicators on one alert. Inline `device` / `actor.user` /
`metadata.profiles` on the entry, and an OCSF `evidences[]` array alongside it, were both tested
and changed nothing, so do not bother carrying them.

**Verify with the right field.** `alert(id){ indicators { type uid title description message
severity observables { name value type } } }`. NOT `alertWithRawIndicators`: `rawIndicators` is a
separate store fed only by `/v1/indicators`, so on this design it stays `[]`, which is expected and
not a failure. Two teams have now chased that empty array as if it were a bug. Do not add `name` or
`category` to that selection set: `Indicator` has neither, and either one fails the whole query with
`Validation error (FieldUndefined@[alert/indicators/name]) : Field 'name' in type 'Indicator' is undefined`.
(`indicator.name` and `indicator.category` are SDL PowerQuery fields on EDR behavioural-indicator
events, an unrelated schema.)

**Indicators cannot be ingested separately at all.** No credential drives `/v1/indicators`: the
console API token that gets `202` from `/v1/alerts` gets `403 "User token not allowed for this
endpoint"` there (it carries the claim `type: "user"`), `ApiToken` is `401` on both, and the SDL
Log Write Key is `401` on both, being a key for the event collector rather than a Bearer JWT for
`/v1/*`. If a flow still has the indicator POST with `continue_on_fail`, every run finishes
`CompletedWithErrors` with `error_actions` empty, which reads as a broken flow and is not one.
Delete the action.

Reference builder: `s1-secops-mcp/lib/uam-ingest.js` `buildSecurityAlert({inline:true})`. The alert
surfaces in UAM ~30-60s after the POST; poll `uam_list_alerts`.

- **Attribution:** for alerts a flow itself raises (e.g. the UEBA SILENT / DORMANT watchdogs), set
  `metadata.product` = `{"name":"Hyperautomation","vendor_name":"SentinelOne"}` so the alert is
  attributed to Hyperautomation in the console rather than to a generic/blank product.
