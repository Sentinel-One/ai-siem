## Detection rules and saved filters: request-body schema gotchas

### Custom Detection Rules and STAR Rules: POST /cloud-detection/rules

**STAR rules** ("streaming threat assessment rules") are the product name for real-time
detection rules that evaluate every matching event as it arrives. There is no separate
`/star-rules` API path; that path returns 404. STAR rules are `cloud-detection/rules`
with `queryType=events`, the same endpoint as all other Custom Detection Rules.

`queryType` enum (from swagger): `events`, `scheduled`, `correlation`, `uebafirstseen`.

---

#### ⚠️ LISTING DETECTION RULES: read this BEFORE calling GET /cloud-detection/rules

The list endpoint hides `queryType: "scheduled"` rules by default. **Without `isLegacy=false` in the query string, scheduled rules return 0 results even though they exist and are visible in the console UI.** This is the single most common drift between API output and console reality. There is no error, no warning, no hint, the response simply omits scheduled rules. Re-confirmed against the live API, 2026-05.

**Always pass `isLegacy=false` when listing.** The only time you can omit it is if you are 100% sure you only care about events-type STAR rules and want to filter scheduled rules out.

| Goal | Correct query | Anti-pattern (silently wrong) |
|---|---|---|
| List all detection rules | `GET /cloud-detection/rules?isLegacy=false&limit=200` | `GET /cloud-detection/rules?limit=200`: drops scheduled |
| List only scheduled detections | `GET /cloud-detection/rules?isLegacy=false&queryType=scheduled&limit=200` | `GET /cloud-detection/rules?queryType=scheduled`: returns 0 |
| List only events (STAR) rules | `GET /cloud-detection/rules?queryType=events&limit=200` | (this one is safe; events rules are not gated by `isLegacy`) |
| Search by name across all types | `GET /cloud-detection/rules?isLegacy=false&name__contains=Foo` | `GET /cloud-detection/rules?name__contains=Foo`: drops scheduled |

**Verdict-language note for analysts:** if you query without `isLegacy=false` and the response is empty, the correct statement is "no events rules came back; I haven't yet checked scheduled rules", not "this tenant has zero scheduled detections". Promoting the absence of evidence to "confirmed zero" is the failure mode this gotcha exists to prevent.

`queryType` accepts a single value or an array (comma-separated): `queryType=scheduled` or `queryType=events,scheduled` both work. The combination `queryType=<x>` + `nameSubstring=<y>` returns HTTP 500; use one filter at a time, or use `name__contains` instead of `nameSubstring` (which works with both).

---

**⚠️ Pick the right `queryType` for your rule body BEFORE composing the POST. Mismatches return HTTP 400.**

| Rule body language | Correct `queryType` | Correct `queryLang` | Field carrying the query |
|---|---|---|---|
| **PowerQuery (pipe syntax `\|`)** | **`scheduled`** | **`"2.0"`** | `data.scheduledParams.query` |
| S1QL log-search / event search | `events` | `"1.0"` (default, omit) | `data.s1ql` |
| EUEBA first-seen | `uebafirstseen` | n/a | per swagger schema |
| Correlation | `correlation` | **`"2.0"`** | `data.correlationParams` (`entity`, `matchInOrder`, `subQueries[]`) |

**Any time the rule body has the pipe character `\|` (i.e. PowerQuery), the only working path is `queryType: "scheduled"` + `queryLang: "2.0"`.** `queryType: "events"` rejects pipe syntax (HTTP 400 `Don't understand [|]`), and `queryLang: "2.1"` is not in the enum (HTTP 400 `queryLang: "2.1" is not a valid choice`). Confirmed against the live API, 2026-05.

**Correlation rules also require `queryLang: "2.0"`.** Confirmed against the live API, 2026-06: a `queryType: "correlation"` POST without `queryLang` (or with `"1.0"`) returns HTTP 400 `query lang must be 2.0`, even though the subquery bodies themselves can be boolean S1QL (e.g. `EventType = "Logon" AND LogonResult = "Fail"`). So only single-event `events` rules use 1.0; both `scheduled` and `correlation` require 2.0. `correlationParams` requires `entity` (`user`/`process`/`ip`/`endpoint`/`storyline`/`custom`/`none`) and `matchInOrder`, with 1 to 10 `subQueries[]` (each `{subQuery, matchesRequired}`); `timeWindow.windowMinutes` is one of {1,5,10,30,60,240,480,720}.

**Operational learnings, validated live (2026-07, custom detection rules + alerts):**

- **1.0 operators do not evaluate under `queryLang 2.0`.** An events rule whose body used the S1QL-1.0 operator `ContainsCIS` was accepted at create time but never fired; rewriting it to the 2.0 operator `contains:anycase` fired immediately. `scheduled` and `correlation` rules are always 2.0, so their bodies must use 2.0 operators (`contains:anycase`, `in:anycase`, etc.), not 1.0 forms (`ContainsCIS`, `In`). For `events` rules the story is more subtle: omitting `queryLang` stores `"1.0"` (live-verified 2026-07-29: a POST without `queryLang` came back `queryLang: "1.0"`), but a fleet audit found 99 of 100 live events rules carry `"2.0"` because creators set it explicitly to get the 2.0 operator set. Decide deliberately: leave it defaulted to 1.0 and write 1.0 operators, OR set `queryLang: "2.0"` explicitly and write 2.0 operators. Mixing (2.0 rule, 1.0 operator, or vice versa) stores fine and silently matches nothing. Lint rule bodies for operator/lang mismatch before deploy.
- **Alerts inherit the rule's `description`.** The generated alert carries the rule description verbatim (`ruleInfo.description` on `GET /cloud-detection/alerts`, and `description` on UAM alerts). Because the rule schema has no native MITRE/tag/custom-attribute field, embedding metadata in the description (e.g. a `[DaC] MITRE: ... | Tags: ... | Owner: ...` footer) is the way to surface MITRE/tags/owner on a custom-rule alert.
- **Alert-surface split by rule type.** `events` and `correlation` alerts appear in `GET /cloud-detection/alerts`; **scheduled** (PowerQuery) detection alerts do NOT surface there, they appear only in **UAM** (`unifiedalerts` / `uam_list_alerts`). Look for scheduled-rule alerts in UAM, not the REST alerts path. Also `sortBy=createdAt` on `/cloud-detection/alerts` returns `400 "not a valid choice"`, and a free-text `searchText` on `uam_list_alerts` can throw `Field * does not exist or not supported` (use structured filters / `viewType` instead).
- **Scheduled-rule activation latency, and PUT resets it.** After enable, a scheduled rule sits in `Activating` ("will become Active within an hour") before its first run, then runs on `runIntervalMinutes`. Every PUT/update re-enters `Activating`, so repeated re-syncs delay firing. Enable once and avoid churn when waiting for a scheduled rule to fire.

See the **PowerQuery Scheduled Detections** subsection below for the full scheduled-rule body, gotchas, and the feature-flag fallback path if the tenant has not enabled Scheduled Detections.

`expirationMode` valid values: `"Permanent"` or `"Temporary"`. `"Never"` is not valid and returns 400.

**Events (STAR) rule, confirmed CREATE body (live API, 2026-05):**

```json
{
  "data": {
    "name": "my-star-rule",
    "description": "optional",
    "severity": "Low",
    "expirationMode": "Permanent",
    "queryType": "events",
    "status": "Draft",
    "s1ql": "EventType = \"Process Creation\" AND ProcessName = \"suspicious.exe\"",
    "treatAsThreat": "UNDEFINED",
    "networkQuarantine": false
  },
  "filter": {"siteIds": ["<siteId>"]}
}
```

Events rule gotchas confirmed against live API:

- `"activeResponse"` in the body returns HTTP 400 "Unknown field": omit it.
- `queryLang` defaults to `"1.0"` for events rules; do not set it explicitly (unlike scheduled rules which require `"2.0"`).
- `treatAsThreat="UNDEFINED"` is accepted on input but stored as `null` in the response.
- `status="Draft"` creates a rule that never fires even if live telemetry matches.
- GET `nameSubstring` + `queryType` combined returns HTTP 500: use one filter at a time.
- DELETE body is top-level `{filter: {ids: [...], siteIds: [...]}}` with no `"data"` wrapper.
- `isLegacy=false` is NOT needed for events rules (only required for scheduled rules).

`status` valid values: `"Draft"`, `"Activating"`, `"Active"`, `"Disabling"`, `"Disabled"`. Use `"Disabled"` to create a non-firing rule; the API returns `"Draft"` in the response for a rule that has never been activated.

**PUT /cloud-detection/rules/{id}**, `status` is required in the PUT body even though it is read-only in practice. Omitting it returns 400 "Missing data for required field."

### Saved Filters: POST /filters

The body field for filter criteria is `filterFields`, not `filters`:

```json
{
  "data": {
    "name": "my-filter",
    "filterFields": {"infected": true, "networkStatuses": ["connected"]}
  },
  "filter": {"accountIds": ["<accountId>"]}
}
```

**PUT /filters/{id}**, does NOT accept a top-level `filter` scope wrapper. Pass only `{"data": {...}}`:

```json
{"data": {"name": "updated-name", "filterFields": {"infected": false}}}
```

### PowerQuery Scheduled Detections: POST/PUT/GET/DELETE /cloud-detection/rules

`queryType: "scheduled"` rules are PowerQuery-based detections. **This is the only path that accepts pipe-syntax PowerQuery in a detection rule body.** Events rules reject pipe syntax even with `queryLang: "2.0"`. They use a different schema from `events` and `correlation` rules and have several non-obvious requirements confirmed against the live API (2026-05).

**If the POST fails with a feature-not-enabled / not-licensed / unauthorized response on a tenant where the schema is otherwise correct, stop and tell the user to enable the Scheduled Detections feature on the tenant before retrying.** Do not silently downgrade the rule body to S1QL or re-attempt with `queryType: "events"`. The console path is typically *Settings → Account → Detection / SDL Add-Ons → Scheduled Detections* but varies by platform version, so phrase the ask in terms of capability ("please enable Scheduled Detections on this account") rather than the exact click path.

#### CREATE: POST /web/api/v2.1/cloud-detection/rules

All five `data` fields are required. `queryLang: "2.0"` is mandatory; omitting it returns HTTP 400 "query lang must be 2.0". `filter` accepts `accountIds` or `siteIds` (account-level rules cover all sites under that account):

```json
{
  "data": {
    "name": "My Scheduled Detection",
    "queryType": "scheduled",
    "queryLang": "2.0",
    "severity": "Medium",
    "expirationMode": "Permanent",
    "status": "Disabled",
    "scheduledParams": {
      "query": "dataSource.name='Proofpoint' event.type='Click' unmapped.classification='malware' | group hits=count(), first_seen=oldest(timestamp), last_seen=newest(timestamp) by clickIP | filter hits >= 1 | sort -hits | limit 100",
      "runIntervalMinutes": 60,
      "lookbackWindowMinutes": 60,
      "threshold": {"value": 0, "operator": "Greater"}
    }
  },
  "filter": {"accountIds": ["<accountId>"]}
}
```

**Scheduled-rule gotchas confirmed against live API (2026-05):**

- `disableAgentMitigation` is **not** part of the scheduled schema. Including it returns HTTP 400 `Unknown field`. Cloud-source PQ rules do not need it; mitigation actions are not supported on scheduled rules anyway.
- `treatAsThreat: "Malicious"` is for events rules with EDR telemetry. Scheduled rules accept `treatAsThreat: "UNDEFINED"` (or omit) and `networkQuarantine: false`. The verdict surfaces via the rule's `severity`, not via mitigation.
- New rules are created in `Draft` status regardless of the requested `status` in the POST. To enable, call `PUT /web/api/v2.1/cloud-detection/rules/enable` with `{"filter": {"ids": [...], "accountIds": [...]}}` after creation. The response transitions to `Activating` and then `Active` within the hour.
- The PowerQuery in `scheduledParams.query` must NOT use `nolimit`, `compare`, or subqueries. The 1,000-row intermediate cap documented in the `powerquery` skill at `references/detection-rules.md` applies.

**GET requires `isLegacy=false`**, without this query parameter, the list endpoint returns 0 results for scheduled rules even though they exist and are visible in the console UI. Always include it. **When listing all rules regardless of type (e.g. searching by name), always pass `isLegacy=false`, without it you will only see events-type rules and silently miss all scheduled rules:**

```text
GET /web/api/v2.1/cloud-detection/rules?isLegacy=false&limit=100
GET /web/api/v2.1/cloud-detection/rules?siteIds=<id>&queryType=scheduled&isLegacy=false
GET /web/api/v2.1/cloud-detection/rules?ids=<ruleId>&siteIds=<id>&isLegacy=false
```

Note: `name__contains` filter silently returns 0 for scheduled rules when `isLegacy=false` is omitted. Always pair name searches with `isLegacy=false`.

**PUT requires `filter.siteIds`** in the body even though swagger marks `filter` as optional. Also requires all five data fields (name, queryType, severity, expirationMode, status). Additional PUT gotchas confirmed 2026-05-26:

- `activeResponse` in the PUT body returns HTTP 400 "Unknown field": omit it (same as POST).
- `treatAsThreat: null` in the PUT body returns HTTP 400 "Field may not be null": use `"UNDEFINED"` even though the GET response shows `null`. The API stores it as `null` but rejects `null` as input.
- `status` must be included (e.g. `"Active"`) even though it is effectively read-only on PUT.

```json
{
  "data": {
    "name": "...", "queryType": "scheduled", "queryLang": "2.0",
    "severity": "High", "expirationMode": "Permanent", "status": "Active",
    "networkQuarantine": false, "treatAsThreat": "UNDEFINED",
    "scheduledParams": {...}
  },
  "filter": {"siteIds": ["<siteId>"]}
}
```

**ENABLE/DISABLE**, dedicated PUT endpoints. The filter takes `ids` plus an optional scope (`siteIds` or `accountIds`); `ids` alone works because rule IDs are globally unique. Do NOT include `isLegacy` in the body, it returns `400 filter: isLegacy: Unknown field` (`isLegacy` is a GET-listing param only). Tenant-validated 2026-06-16: `{"filter": {"ids": [...]}}` returned `{"affected": N}`.

```text
PUT /web/api/v2.1/cloud-detection/rules/enable   body: {"filter": {"ids": ["<ruleId>"], "siteIds": ["<siteId>"]}}
PUT /web/api/v2.1/cloud-detection/rules/disable  body: {"filter": {"ids": ["<ruleId>"], "siteIds": ["<siteId>"]}}
```

**DELETE body; use `json_body=` keyword arg in s1_client.py.** The method signature is `delete(path, params=None, json_body=None)`. Passing the filter dict positionally sends it as query params and returns HTTP 400:

```python
# Correct
client.delete("/web/api/v2.1/cloud-detection/rules",
    json_body={"filter": {"ids": [rule_id], "accountIds": [acct_id]}})

# Wrong: sends filter as query string
client.delete("/web/api/v2.1/cloud-detection/rules",
    {"filter": {"ids": [rule_id], "accountIds": [acct_id]}})
```

**Verify deletion with GET (expect 0 hits), not a second DELETE.** A second DELETE returns HTTP 400 "Could not find rule with id: ..." rather than `affected: 0`.
