# Detection rules: STAR / Custom Detection / PowerQuery Alerts

PowerQuery Alerts (and STAR / Custom Detection rules that use a PowerQuery body) have tighter limits than ad-hoc hunts. This file covers how to write detection rule bodies that are correct, cheap, and reliably fire.

## The four ways to build a detection

Three are Custom Detection (STAR) rule types, created at `POST /web/api/v2.1/cloud-detection/rules` with `queryLang: "2.0"` and listed with `isLegacy=false`. Each `queryType` puts its logic in a different field and uses a different language. The fourth, the HA watchdog, is not a rule at all: it is a Hyperautomation workflow that runs the query and raises the alert itself, and it exists for the PowerQuery a scheduled rule will not accept. Pick by what the detection needs to express.

| Type | `queryType` | Body lives in | Body language | Fires | Asset binding | Mitigation (Active Response) | Use for |
|---|---|---|---|---|---|---|---|
| **STAR single-event** | `events` | `data.s1ql` | boolean S1QL, NO pipes | per matching event, streaming at ingest | automatic, from the matched event | inline Active Response (`treatAsThreat` Suspicious/Malicious, `networkQuarantine`) or HA flow | deterministic single-event signatures (a process + cmdline, a registry write, one log line) |
| **STAR multi-event (correlation)** | `correlation` | `data.correlationParams` (`s1ql` stays `""`) | each sub-query is boolean S1QL, NO pipes | when sub-query match thresholds are met inside a time window, grouped by an entity | automatic, from the matched events; `entityMappings` optional | inline Active Response (`treatAsThreat`) or HA flow | thresholds (N of X), multi-stage chains, ordered sequences (A then B) |
| **Scheduled (PowerQuery)** | `scheduled` | `data.scheduledParams.query` (`s1ql` stays `""`) | PowerQuery, pipes allowed | on a schedule (`runIntervalMinutes`) over a lookback window | NOT automatic, set `entityMappings` on the projected columns | via HA flow off the alert (`treatAsThreat` must be `UNDEFINED`, `networkQuarantine` false; no inline Active Response) | aggregation, statistics/baselines, cross-field grouping, lookup/anti-join exclusions |
| **HA watchdog** | not a rule | a Hyperautomation workflow | full PowerQuery via the LRQ API, no evaluator restrictions | on the workflow's own `scheduled_trigger` | you compose the alert, so any field can carry the asset | any HTTP call the flow can make | a query the scheduled evaluator rejects: `datasource`, `savelookup`, `now()`, `timebucket`, unrestricted joins, results past the 1,000-row cap, or an alert whose title and description must come from the result |

Decision guide:

- The signal is one event you can describe with a boolean filter, **single-event**.
- The signal is "N occurrences" or "A then B" across several events, correlated by a user/host/IP, **correlation**.
- The signal needs `group`, `estimate_distinct`, `sum`, a `lookup` / anti-join, or any pipe, **scheduled**.
- The scheduled evaluator rejects the query, or the alert body has to be built from the result, **HA watchdog**.

Framed by intent rather than by mechanics:

| Intent | Type |
|---|---|
| A deterministic signature: this event, these fields | single-event |
| The same entity does several things close together in time | correlation |
| Retrospective, query-shaped detection over history: low-and-slow, multi-stage, patterns that only appear once aggregated | scheduled |
| The query the detection needs is valid PowerQuery but the scheduled rule refuses it | HA watchdog |

Correlation is a streaming, per-entity state machine: it groups events by an
entity, waits for the configured behaviours to accumulate, and fires. Scheduled
is a query run on a timer over a lookback window. That difference decides which
one can see your pattern at all, before any question of convenience.

The "Hard limits" below and the "Scheduled detection rule, full option set" section apply to the scheduled (PowerQuery-body) type. Single-event and correlation bodies are boolean S1QL and are not bound by the 1,000-row / 1 MB PowerQuery limits.

### Single-event (`queryType: "events"`)

Body is one boolean S1QL expression with NO pipes, in `data.s1ql`. Operators match a PowerQuery initial filter (`=`, `in`, `in:anycase`, `contains`, `matches`, `AND`/`OR`/`NOT`). The Target Asset binds automatically from the matched event.

```json
{
  "data": {
    "name": "...", "description": "... (include MITRE IDs)",
    "queryType": "events", "queryLang": "2.0",
    "severity": "High", "status": "Active", "expirationMode": "Permanent",
    "treatAsThreat": "UNDEFINED", "networkQuarantine": false,
    "s1ql": "dataSource.name = 'SentinelOne' AND event.type = 'Process Creation' AND src.process.name in ('powershell.exe','pwsh.exe') AND src.process.cmdline matches '(?i)\\s-(e|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm|encodedcomma|encodedcomman|encodedcommand)\\b'"
  },
  "filter": {"accountIds": ["<accountId>"]}
}
```

There is no `lookup` in a single-event body (no pipes). To exclude known-good accounts/hosts, hardcode an inline negative list: `AND NOT (src.process.user in:anycase ('domain\\user1','domain\\user2'))`. Tenant-validated as an events rule 2026-06-24.

### Correlation (`queryType: "correlation"`)

`s1ql` stays empty; the logic lives in `data.correlationParams`:

- `entity`: the correlation key. `user` and `ip` are tenant-confirmed built-ins; device/endpoint-style entities also exist. Set `custom` to key on an arbitrary field path, see "Custom correlation key" below.
- `matchInOrder`: `false` = sub-queries may match in any order; `true` = ordered sequence (sub-query 1, then 2, and so on).
- `timeWindow.windowMinutes`: the correlation window.
- `subQueries[]`: each `{ "matchesRequired": N, "subQuery": "<boolean S1QL, no pipes>" }`. One sub-query with `matchesRequired: N` is a threshold detection (N of the same event by entity in the window). Multiple sub-queries form a multi-stage / sequence detection.

```json
{
  "data": {
    "name": "...", "description": "... (include MITRE IDs)",
    "queryType": "correlation", "queryLang": "2.0",
    "severity": "High", "status": "Active", "expirationMode": "Permanent",
    "s1ql": "",
    "correlationParams": {
      "entity": "user",
      "matchInOrder": false,
      "timeWindow": {"windowMinutes": 60},
      "subQueries": [
        {"matchesRequired": 2, "subQuery": "event.type = 'Process Creation' and src.process.name in ('powershell.exe','pwsh.exe') and src.process.cmdline matches '(?i)\\s-enc'"}
      ]
    }
  },
  "filter": {"accountIds": ["<accountId>"]}
}
```

Tenant-validated 2026-06-24: a single-subQuery correlation (`entity:"user"`, `matchInOrder:false`, `windowMinutes:60`, `matchesRequired:2`) was accepted (created Draft, then deleted). The existing "Abnormal Spike in SSH Login Failures" rule uses two sub-queries with `matchesRequired:500` each over a 60-minute window.

#### Sizing `windowMinutes`: default to 60, and never below your ingestion lag

The window must comfortably exceed end-to-end ingestion lag, not just the
attacker's tempo. Agents and integrations buffer, networks lag, and ingestion
falls behind during bursts, so with a window of 10 minutes or less a
late-arriving event lands outside the window even though the behaviours really
did happen together, and the rule **silently fails to fire**. Nothing surfaces
this: it looks identical to "no such activity".

**Use 60 minutes as the default.** Reserve sub-hour windows for sources you know
ingest in near real time. Otherwise match the window to the threat's real tempo:
brute force unfolds in minutes, lateral movement in hours, slow exfiltration
over days. Too long is its own failure, unrelated activity drifting into one
alert.

This is the first thing to check when a correlation rule does not fire, ahead of
the query itself.

#### The cartesian-product trap: one event, many entities, many alerts

A single event can carry several values for a field the entity keys on: several
user contexts, several destination IPs, an array-valued field. The rule then
expands that event into **one entity per combination of values**, each
accumulating state independently and each able to fire its own alert.

With entity `(user, host)` and an event carrying `user: alice` and
`host: web-01, web-02, web-03`, the rule tracks three entities, not one, and can
raise three alerts for what was logically a single incident. Two multi-valued
fields holding 3 and 4 values produce 12 entities from one event.

The same thing happens through OR aliases: fields grouped as alternative
spellings of one identity, which in reality hold *different* values on the same
event, each become an entity. `real_user` and `effective_user` are related, not
aliases.

There is an internal cap on how many entities one event may map to. Above it the
system **skips entity-state updates for that event entirely**, so an over-broad
entity silently drops the events it was meant to track.

Avoid it by preferring single-valued fields for the key, keeping composites
shallow (each dimension multiplies the blast radius), and auditing OR groups so
they only contain genuine renames of the same value.

A cool-off period does **not** fix duplicate alerts of this kind: cool-off
suppresses repeats for the *same* entity, and these duplicates arrive under
different entities. The fix belongs in the entity definition.

#### Field names the validator refuses as a correlation key

Beyond syntax (a dotted identifier path, optional `[N]` index, no leading digit
or underscore, no colons, hyphens or spaces), whole categories are rejected
because they cannot work as an identity:

| Category | Why it can never fire |
|---|---|
| Per-event identifiers (event/request/correlation/transaction/span IDs, per-event UUIDs) | every event is its own entity, so nothing ever accumulates |
| Timestamps (occurred, received, created, updated) | change on every event, identify nothing |
| Free text (message, description, command line, URL, stack trace, raw payload) | enormous entity cardinality, very noisy |
| Measurements and counters (count, duration, size, ratio, score) | describe the event, do not identify its subject |
| High-entropy non-identity values (digests, signatures, tokens, nonces) | unique but name nothing stable |
| Platform-reserved (`account.id`, `account.name`, `rule.id`, `filterid`, `filterpurposeruleid`, `accountidoempurpose`, and `__` / `:` / `sca:` / `synthetic:` / `_k8s_` prefixes) | clash with platform internals |

Good keys are stable identifiers: user id or name, agent UUID, host name, source
IP, or a composite such as agent + process id. Standard identity fields pass even
when they superficially resemble a restricted category. The validator's error
message names the field and the reason, and is authoritative over this table.

#### Mitigation on a correlation rule needs its fields pinned in singleton groups

Inline Active Response runs **on the endpoint**, so the rule can only carry it
out when every matched event is guaranteed to carry the identifiers the agent
needs. With a custom entity that guarantee comes from the group layout: each
required field must sit in a group of its own. Because every event joining the
entity must supply a value for every group, a singleton group forces that field
to be present on every match, including the event that triggers the action.

| Action | Required singleton groups |
|---|---|
| Network Quarantine | `agent.uuid` alone in its own group |
| Treat as Threat | `agent.uuid` **and** a process id (`src.process.storyline.id` or `src.process.uid`), each alone |

The moment `agent.uuid` shares a group with anything else (say
`[agent.uuid, host.name]`), an event supplying only `host.name` could match with
no agent UUID, the guarantee is lost, and **both** actions become unavailable. A
pure cross-source identity such as user + host with no agent field supports
neither: those are the XDR-style rules where mitigation cannot run
deterministically, and the response belongs in a Hyperautomation flow instead.
The built-in Storyline and Process presets support both actions unconditionally.

#### Custom correlation key (`entity: "custom"`)

When no built-in entity fits, correlate on a field path of your choosing.
`entitiesAndFields` is a **list of lists, one inner list per sub-query, matched
positionally**:

```json
"correlationParams": {
  "entity": "custom",
  "entitiesAndFields": [ ["src.process.parent.storyline.id"],
                         ["tgt.process.storyline.id"] ],
  "matchInOrder": false,
  "timeWindow": {"windowMinutes": 10},
  "subQueries": [
    {"matchesRequired": 1, "subQuery": "event.type='Process Creation'"},
    {"matchesRequired": 1, "subQuery": "event.type='IP Connect'"}
  ]
}
```

Sub-query 1 is keyed on the first inner list, sub-query 2 on the second, so this
joins two different field paths that hold the same identity.

Rejections, each quoted from the API response that produced it:

| Mistake | Response |
|---|---|
| `customEntityKey` instead of `entitiesAndFields` | `correlationParams: dict_values(['customEntityKey']): Unknown field` |
| `entity: "custom"` with no key | `entities_and_fields: entitiesAndFields is required when entity is Custom` |
| a flat list of strings | `entitiesAndFields: Not a valid list` |
| an object instead of a list, per element | `entitiesAndFields: 0: Not a valid list` |
| the same path in two inner lists | `entityFields contains duplicate alias(es): '<path>'` |

The duplicate-alias rule is the surprising one: two sub-queries correlating on
the same logical identity must reference it by two **different** field paths.
Tenant-validated: the block above was accepted, created, read back with
`entitiesAndFields` intact, and deleted.

Scope note: an account-scoped token creating with `filter.tenant` returns
`User <id>:account can not create rule with higher scope None:tenant`. Pass
`filter.accountIds` instead.

### Scheduled (`queryType: "scheduled"`)

PowerQuery body (pipes allowed) in `data.scheduledParams.query`; needs `entityMappings` to bind the asset; no inline Active Response (mitigate via a Hyperautomation flow off the alert instead). Covered in full in "Deploying a rule via the API" and "Scheduled detection rule, full option set" below.

### S1QL string escaping in `events` / `correlation` bodies (validated)

The detection engine matches against a SINGLE backslash. In the raw query text you type in the console UI, write one backslash (`matches '(?i)\s-...\b'`, `in:anycase ('domain\user')`). In the JSON POST body, double each backslash (`\\s`, `\\b`, `domain\\user`) so that after JSON decoding the engine receives one. Tenant-validated 2026-06-24: a single-backslash `in:anycase ('corp\jdoe')` excluded the account, while the double-backslash form let it leak through; likewise `(?i)\s-no` matched live command lines but `(?i)\\s-no` matched nothing.

## Hard limits

- **1,000 rows maximum** on any intermediate table (including inside `group` and `join`).
- **1 MB RAM** total.
- `nolimit` is not allowed.
- Subqueries are not supported (the Summary service evaluates at ingest time and can't compute inner queries).
- `compare` isn't useful here (alerts don't do timeshift).
- Depending on platform version, `transpose` may not be supported: prefer `group` + explicit columns.
- The rule should return **one row per finding** with stable, well-named columns (the detection engine maps these to alert fields).

If you hit the 1,000-row limit on an intermediate `group`, the alert silently under-counts. This is dangerous for detections, validate the filter is selective enough before saving as a rule.

## Shape of a good rule

```text
<highly-selective-initial-filter>
| group
    count = count(),
    first_seen = oldest(timestamp),
    last_seen  = newest(timestamp),
    host       = any(endpoint.name),
    cmdline    = any(src.process.cmdline)
  by agent.uuid, src.process.storyline.id
| filter count >= 5            // the actual detection threshold
| sort -count
| limit 100
```

Why this shape:

- `group by agent.uuid, src.process.storyline.id` gives one row per (endpoint, activity cluster). That matches what the detection engine wants.
- `any(endpoint.name)` / `any(src.process.cmdline)` carry human-readable context through the group. Don't use `array_agg` in an alert body, arrays aren't supported by `savelookup` and bloat the 1 MB budget.
- `oldest(timestamp)` / `newest(timestamp)` are the canonical way to surface the detection window. They require *no* preceding `sort` / `group` / `limit` and must appear in the aggregation.
- `filter count >= N` is the threshold. Keeping the threshold inside the query (rather than tuning outside) keeps the rule self-contained.
- A final `limit` caps the emitted alert count per evaluation window: keeps you honest about alert fatigue.

## Patterns

### 1. Rare-event detection

Something that fires once per endpoint per unusual activity. Low threshold, high specificity.

```text
indicator.name = 'EventViewerTampering'
| group
    first_seen = oldest(timestamp),
    last_seen  = newest(timestamp),
    host       = any(endpoint.name),
    count      = count()
  by agent.uuid, src.process.storyline.id
| sort -count
| limit 100
```

### 2. Threshold / rate detection

"More than N of X from one entity in the window."

```text
event.login.loginIsSuccessful = false
| group
    fails     = count(),
    src_ips   = estimate_distinct(src.endpoint.ip.address),
    last_seen = newest(timestamp)
  by agent.uuid, event.login.userName
| filter fails >= 10
| sort -fails
| limit 100
```

### 3. Anomaly via combined signals

Combine filters with `and` in the initial filter, not `and` in a computed column, the initial filter is cheapest and gates what the Summary service scans.

```text
event.type = 'Process Creation'
src.process.parent.name = 'winword.exe'
src.process.name in ('powershell.exe', 'pwsh.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe', 'regsvr32.exe', 'rundll32.exe')
| group
    count      = count(),
    first_seen = oldest(timestamp),
    last_seen  = newest(timestamp),
    host       = any(endpoint.name),
    cmdline    = any(src.process.cmdline)
  by agent.uuid, src.process.storyline.id
| sort -count
| limit 100
```

### 4. Allowlist via `lookup`

When a rule would otherwise fire too broadly, exclude known-good via a config-managed data table.

```text
<filters producing candidate rows>
| lookup is_allowed = allowed from allowlist_hosts by endpoint.name
| filter is_allowed = null                   // kept rows had no allowlist entry
| group count = count(), last_seen = newest(timestamp) by agent.uuid, src.process.storyline.id
| sort -count
| limit 100
```

This uses `lookup` with a config data table (`/datatables/allowlist_hosts`). Keep the table ≤ 400 KB; prefer an opt-in allowlist, not an opt-out denylist, because the former is bounded.

### 5. Join-based correlation

`inner` / `left` joins work in alerts, bounded by the 1,000-row / 1 MB budget. Put strict filters inside each subquery; don't rely on the outer `filter` to prune.

```text
| inner join
    lsass_access = (
      indicator.name = 'CredentialDumping'
      | group last = newest(timestamp), host = any(endpoint.name)
        by agent.uuid, src.process.storyline.id
      | sort -last
      | limit 500
    ),
    powershell = (
      event.type = 'Process Creation'
      src.process.name contains 'powershell'
      | group ps_cmdline = any(src.process.cmdline)
        by agent.uuid, src.process.storyline.id
      | limit 500
    )
    on agent.uuid, src.process.storyline.id
| columns agent.uuid, host, ps_cmdline, last
| limit 100
```

## Checklist before saving a rule

- [ ] Initial filter is specific enough that you'd expect far fewer than 1,000 intermediate rows in any realistic window.
- [ ] No `nolimit`, no `compare`, no subqueries.
- [ ] The alert will bind a Target Asset (not "Unknown Device"): a scheduled rule projects the device identity and sets `entityMappings` on it (e.g. `device_host` / `device_agentid` / `device_agentuuid`); an events rule on a custom source carries `device.uid` (the numeric console agent id) + an endpoint `class_uid`. Projecting `agent.uuid` alone does NOT bind. See "Target Asset / entity binding" below.
- [ ] `group` includes `oldest(timestamp)` and `newest(timestamp)` (or a `last_seen = …` single value), so the alert has a time.
- [ ] Final `| sort -count | limit N` caps alert volume.
- [ ] Threshold (`filter count >= N`) is set to something your team will actually triage, not 1.
- [ ] Tested in Event Search over a realistic 24-hour window and produces a plausible number of rows (0-5 is good for most detections).

## Mapping fields to alert properties

When a detection rule fires, the detection engine looks for these columns to populate the alert row. Use them verbatim.

| Alert field | Column to emit |
|---|---|
| Storyline | `src.process.storyline.id` |
| Timestamp | `timestamp` (or a `.timestamp`-suffixed column like `last_seen.timestamp`) |
| Evidence | `cmdline = any(src.process.cmdline)`, `path = any(tgt.file.path)`, etc. |
| Count / severity driver | `count = count()` |

Renames are fine: the engine resolves by name, so `host = any(endpoint.name)` is fine; it just helps the analyst read the row.

### Target Asset / entity binding (scheduled rules need `entityMappings`)

A scheduled (PowerQuery) rule **binds the Target Asset via an explicit `entityMappings` config; it is not automatic.** Out of the box a scheduled-rule alert shows "Unknown Device" (`agentUuid: null`); projecting `endpoint.name` / `agent.uuid` columns is necessary but **not sufficient on its own**. The rule must also declare which result columns are the entity, via the top-level `entityMappings` array (the **"Entity column mapping"** field in the rule UI):

```json
"entityMappings": [ { "columnName": "endpoint.name" }, { "columnName": "src_ip" } ]
```

Working recipe for a scheduled rule with a mapped asset, two parts that must agree:

1. Project the entity column(s) in the query body, e.g. `| columns endpoint.name = device.hostname, src_ip = src_endpoint.ip, ...`.
2. Set `data.entityMappings` to those exact output column names: `[{ "columnName": "endpoint.name" }, { "columnName": "src_ip" }]`.

Confirmed on a live tenant: the same rule that showed "Unknown Device" with no `entityMappings` mapped the asset once `entityMappings` was configured on its `endpoint.name` / `src_ip` columns. (The earlier A/B tests showed Unknown Device only because they never set `entityMappings`.)

Other paths that bind the entity:

- **Events-type rules** (`queryType: "events"`): the entity is taken from the matched event automatically, with no `entityMappings`. The console binds a **Device** by reconciling the event's device identity against inventory. `i.scheme` is NOT required, and `account.id` / `site.id` come from the ingest scope (S1-Scope header), not the event body. Fields like `event.type` / `src.process.*` matter only if the rule's `s1ql` filters on them.
  - **Do NOT trust the cloud-detection REST `agentRealtimeInfo` block as proof of binding.** Tenant-tested 2026-06-14: an event carrying ONLY the top-level `agent.uuid` made the REST payload's `agentRealtimeInfo` resolve hostname/OS/agent-id for display, but the console alert still showed **Target Asset = "Unknown Device"**. `agentRealtimeInfo` is a uuid lookup for display; it is not the entity binding. Confirm the actual **Target Asset** via `datasource alerts` (`assetName` / `assetAgentUuid`, which matches the console) or the console UI, never the REST `agentRealtimeInfo`.
  - **Minimum to bind the Target Asset (pinned by bisection, 2026-06-14): two fields, `device.uid` + `class_uid`.** `device.uid` must carry the **numeric console agent id** (the `agentRealtimeInfo.id` / console agent id, e.g. `2497649316206445895`, NOT the agent UUID), and `class_uid` must be an endpoint class (tested with `1007`). With just those two on a custom `dataSource.name`, the events-rule alert bound the real endpoint (`assetName` corp-ws-01, OS Windows, real `assetId`); the platform resolved `assetAgentUuid` from inventory even though the event carried no uuid.
    - The console agent id must be in **`device.uid`** specifically: the same numeric id placed only in `agent.id` did NOT bind, and `endpoint.uid` was redundant.
    - `class_uid` is required: the same identity fields without any `class_uid` left the asset "Unknown Device".
    - Not needed for binding: `agent.uuid`, `device.agent.uuid`, `agent.id`, `endpoint.name`, `endpoint.uid`, `event.type`. A uuid only populates the REST `agentRealtimeInfo` display, never the Target Asset.
    - Insufficient sets tested (all "Unknown Device"): `agent.uuid`; `device.agent.uuid`; `agent.id`; `agent.uuid`+`class_uid`; `agent.uuid`+`endpoint.name`; the agent/device-id cluster (`agent.uuid`+`agent.id`+`device.agent.uuid`+`device.uid`) WITHOUT `class_uid`; the endpoint/class cluster (`endpoint.name`+`endpoint.uid`+`class_uid`+`event.type`) WITHOUT `device.uid`; `agent.id`+`class_uid`.
    - **Binding requires a REAL inventory match, you cannot fake an asset.** Tenant-tested 2026-06-14: a fabricated, non-existent console id in `device.uid` (e.g. `1234567890123456789`) + `class_uid` 1007 still fired the alert but left Target Asset "Unknown Device" (`assetAgentUuid` null). `device.uid` is reconciled against the live Asset Inventory; an id resolving to no enrolled agent does NOT create a phantom asset, it falls back to Unknown Device. Only a `device.uid` matching a real enrolled agent binds.
  - **Efficient way to test binding permutations:** one broad events rule (`s1ql: dataSource.name='<src>'`) plus `hec_ingest` `endpoint:event, isParsed:true` JSON events, one per attribute combination. The JSON keys land directly as SDL fields (dotted keys like `"device.uid"` work), no parser and no per-test propagation wait. Each distinct event produced its own alert (no dedup collapse observed). Note `src.process.cmdline` did not surface as the alert `cmdLine` column on `isParsed` events, so label/distinguish permutations by the bound entity rather than a carried tag.
  - **Practical guidance for custom / parser-enriched sources:** prefer the **scheduled (PowerQuery) rule path with `entityMappings`** on enriched columns (the validated pattern, e.g. the Cisco Meraki onboarding rules map `device_agentuuid` / `device_host`). Events-rule auto-binding on non-agent data requires emitting the full OCSF endpoint/device identity above and is more fragile.
  - **Non-device assets (Identity, cloud resource) bind too, via the unified asset id, tenant-tested 2026-06-14.** The events-rule reconciler resolves the Target Asset from a uid field on the event carrying the **unified asset id** (the `id` from `datasource assets`), plus a `class_uid`. Confirmed: `user.uid` = an AD user's unified id + `class_uid` 3002 resolved `assetName='jdoe'` (Identity / AD User); `device.uid` = a cloud resource's unified id + `class_uid` 6003 resolved `assetName='/aws/ecs/containerinsights/...'` (Governance / AWS CloudWatch Log Group). The matched inventory asset supplies the real name and category. Rules:
    - The **unified asset id is the universal reconciliation key** across device / identity / cloud. The console agent id also resolves endpoints in `device.uid`. A user identifier that is NOT the unified id (objectGUID, SID, `RANGER_AD:` form) only **types** the asset as "AD User", it does not resolve the specific identity.
    - `class_uid` is required (no class → Unknown Device), and the id must match a REAL inventory asset (fabricated → Unknown Device).
    - The legacy `cloud-detection` REST alert view is device-centric and shows these binds as no-device; confirm via `datasource alerts` (`assetName` / `assetCategory` / `assetId`), which matches the console Target Asset.
- **UAM ingest** (indicator/alert posted to `/v1/*`): asset built from the event's `device` object.

`storylineId` is NOT required for binding.

## Scheduled rules: the query shape decides what the threshold counts

The threshold does not have a fixed meaning. **The shape of the PowerQuery
decides what it is compared against**, and getting this wrong is the difference
between a rule that fires on every evaluation and one that never does:

| Query shape | Threshold type | Compared against |
|---|---|---|
| Simple filter, no `group` | `count` | total number of matching **events** |
| Contains `\| group … by …` | `tableRows` | number of **result rows** |

So `threshold > 500` on a non-aggregating filter means 500 events, while the
same threshold on a grouped query means 500 rows, which is usually a wildly
different bar. A grouped query returning one row per offending user typically
wants `tableRows > 0` with the real condition expressed as
`| filter FailureCount >= 100` inside the query.

When the query aggregates, **every sub-query inside a `join` or `union` needs its
own `| group`**.

Starting points, to be tuned rather than copied:

| Detection | Shape | Look-back | Run every |
|---|---|---|---|
| Environment-wide failed-auth volume | `count` > N | 1 hour | 5 min |
| Brute force on one account (low and slow) | `tableRows`, group by user + host | 24 hours | 1 hour |
| Password spraying (one source, many accounts) | `tableRows`, `estimate_distinct` per source IP | 1 hour | 15 min |
| Two behaviours on one host (`join`) | `tableRows`, each side grouped | 1 hour | 15 min |
| Activity absent from an allow-list (anti-join) | `tableRows`, `dataset` + null marker | 1 hour | 15 min |

### Scheduled-rule limits that are not obvious from Event Search

Anything expressible in Event Search is **not** automatically valid in a
scheduled rule:

- `| datasource` is not supported.
- `savelookup` is not supported. CSV lookups use `dataset '/datatables/<file>.csv'`, are **exact-match only** (no CIDR, no wildcard), and the file must stay valid or the rule auto-disables.
- **Lookup tables are per-account.** A global rule referencing one fails evaluation in any account missing the table, sits in *Activating* and retries each cycle, recovering once the table appears. Ensure the CSV exists in every targeted account.
- Intermediate result tables are capped (~1,000 rows in optimized mode), so results can be silently incomplete. Filter as early as possible and `limit` intermediate results.
- Alert title, description and target name **cannot** be set dynamically from the query result. The target asset comes from `entityMappings` only.
- Webhook notifications are not supported directly; route through a Hyperautomation flow.
- A subset of PowerQuery functions is unsupported in scheduled rules.

### The fourth rule type: the HA watchdog

Every limit above is a limit of the scheduled-rule *evaluator*, not of the
platform. A scheduled Hyperautomation workflow that runs the query itself and
raises the alert itself is bound by none of them. In the deployers this pattern
is called an **HA watchdog**, and it is best treated as a fourth way to build a
detection alongside `events`, `correlation` and `scheduled`: the fallback for a
PowerQuery a scheduled rule will not accept.

| Scheduled-rule limit | In an HA flow |
|---|---|
| `\| datasource` unsupported | full PowerQuery, it is an ordinary LRQ |
| `savelookup` unsupported | allowed |
| CSV lookups exact-match, per-account | any join the query language supports |
| ~1,000-row intermediate cap | the LRQ's own limits, far higher |
| Alert title/description/target not dynamic | you compose the alert body, so every field is dynamic |
| No direct webhooks | any HTTP call the flow can make |
| Threshold semantics fixed by query shape | any condition you can express |

The cost is that you own the polling, the failure handling and the alert
schema. Reach for it when a limit blocks the detection, not by default: a
scheduled rule that fits within the limits is less code to keep alive.

**The shape:**

1. `scheduled_trigger` on the cadence you want.
2. `http_request` POST `/sdl/v2/api/queries` to launch the LRQ.
3. `variable` to hold the query id and the forward tag, then a `loop`.
4. Inside the loop, `http_request` GET `/sdl/v2/api/queries/{id}`, a `condition`
   on `stepsCompleted >= stepsTotal`, a guard for a backend-terminated query, a
   `delay` before the next attempt, and `break_loop` once complete. There is no
   `status` string to test.
5. `variable` to compute the row count, then a `condition` on it. No match, exit
   quietly.
6. On a match, three actions: a `variable` holding the OCSF alert JSON, a
   `variable` wrapping it as a files-array, and an `http_request` POST to
   `/v1/alerts` on the ingest host. Indicators ride inline in
   `finding_info.related_events[]` (`/v1/indicators` is unreachable, so they
   must be in the same POST).

**Use the template, do not hand-assemble one.** The action envelope has about
twenty-five required `data` keys per `http_request` plus `state`, `client_data`
and `snippet_*` on every action; omitting any of them imports cleanly and then
fails at runtime with no error the API will show you. Ship-ready template:
`sdl-solutions/assets/ha_watchdog.workflow.template.json`. Fill in
`{{PQ_QUERY}}`, `{{ACCOUNT_ID}}`, `{{SITE_ID}}`, `{{SDL_INTEGRATION_ID}}`,
`{{HEC_URL}}`, `{{HEC_TOKEN}}` and `{{PREFIX}}`, then import. It is generated by
the SecOps deployer's own `watchdog_workflow` builder, and was validated end to
end on a live tenant: imported, activated, run, `Completed` in 10.5s across 14
actions, with the resulting UAM alert carrying the query's own result rows in
its description.

Deploying it:

| Step | Call |
|---|---|
| Import | `POST /web/api/v2.1/hyper-automate/api/public/workflow-import-export/import?accountIds=<acct>` body `{"data": <workflow>}` |
| Activate | `POST /web/api/v2.1/hyper-automate/api/v1/workflows/{wid}/{vid}/activation?accountIds=<acct>` |
| Run now | `POST /web/api/v2.1/hyper-automate/api/public/workflow-execution/manual/{wid}/{vid}?accountIds=<acct>` |
| Deactivate | `POST /web/api/v2.1/hyper-automate/api/public/workflows/{wid}/deactivate?accountIds=<acct>` |
| Delete | `DELETE /web/api/v2.1/hyper-automate/api/v1/workflows/{wid}?accountIds=<acct>` |

The `?_scopeId=&_scopeLevel=` form of import returns 403. Delete returns 400
until the workflow is deactivated.

Failure modes worth pre-empting, all paid for in live debugging:

- **There is no per-action error API.** A failed run reports only `state: Error` and `executed_actions: N` from `GET /hyper-automate/api/v1/workflow-execution`. To find the offending action, count into the flow, then reproduce that one HTTP call yourself.
- **`data.totalRows` does not exist** on the LRQ poll response. The fields are `data.matchCount` (events matched) and `data.values` (result rows). A condition on `totalRows` compares against null forever.
- **The alert POST body must be gzipped.** The proven recipe stages the alert into a variable, wraps it as `{"file":[{"name":"Alert.json","data": ...}]}`, then posts `{{Function.BASE64_DECODE_AS_BYTES(Function.COMPRESS(local_var.alertfile.file, "gzip"))}}` with `Content-Encoding: gzip`, `S1-Scope: <account>:<site>` and an explicit `Authorization: Bearer`. Alert ingest requires `S1-Scope`; without it the endpoint returns 400.
- **A fixed `delay` instead of a poll loop** races the query. The LRQ expires roughly 30 seconds after the last poll, so poll steadily and cancel when done rather than sleeping once for a guessed duration.
- **Doubly-escaped backslashes in any template value** break HA's reference validator. The flow still imports and reports success, then fails activation with "Some actions in this workflow have invalid references". Keep template values to simple `\"` escapes.

### What the alert's Indicators tab will contain

Scheduled-rule alerts are shaped differently from single-event and correlation
alerts, which matters for anything parsing them downstream:

- **Grouped query:** N+1 indicators, one generic indicator carrying the full result table plus one per result row.
- **Non-grouped query:** a single indicator carrying the event count.
- The full result is published as-is under the alert's scheduled-rule output; columns need not be renamed to OCSF names.

## Scheduled detection rule: full option set (UI ↔ API)

Every option on the rule's Overview page maps to a field in the `POST/PUT /cloud-detection/rules` body (`data` object unless noted). Confirmed against a live rule.

| UI label | API field | Notes |
|---|---|---|
| Detection name | `data.name` | |
| Description | `data.description` | |
| Severity | `data.severity` | `Critical` / `High` / `Medium` / `Low` |
| Scope | `filter.siteIds` / `accountIds` / `groupIds` / `tenant:true` | site / account / group / global |
| Expiration date | `data.expirationMode` (`Permanent`/`Temporary`) + `data.expiration` | |
| Rule type | `data.queryType` | `scheduled` for PowerQuery bodies |
| Query language | `data.queryLang` | `2.0` for scheduled PowerQuery |
| Query | `data.scheduledParams.query` | PowerQuery body (S1QL goes in `data.s1ql` for `events` rules) |
| **Entity column mapping** | **`data.entityMappings: [{ "columnName": "..." }]`** | maps result columns to the alert entity/asset; without it the alert is "Unknown Device" |
| Run every | `data.scheduledParams.runIntervalMinutes` | |
| Lookup data from the last | `data.scheduledParams.lookbackWindowMinutes` | e.g. 360 = "6 hours" |
| Threshold criteria | `data.scheduledParams.threshold.operator` | e.g. `Greater` |
| Threshold | `data.scheduledParams.threshold.value` | |
| Generate alert per row | `data.scheduledParams.alertPerRow` | bool |
| Deduplication logic | `data.scheduledParams.disableStreaksLogic` | inverse: dedup ON ⇔ `disableStreaksLogic:false` |
| Cool off period | `data.scheduledParams` cool-off settings | suppression window; only present in the payload when enabled (exact key not captured here because it was disabled) |
| Hide logic | `data.hideLogic` | bool |
| Treat as threat (Active Response) | `data.treatAsThreat` | `UNDEFINED` / `Suspicious` / `Malicious`. Scheduled rules must use `UNDEFINED`: no inline active-response on the rule itself. Drive mitigation from a Hyperautomation flow triggered by the alert instead (any alert can trigger an HA flow) |
| Network quarantine | `data.networkQuarantine` | bool; not supported on scheduled rules |

## Deploying a rule via the API

**For any PowerQuery-bodied detection rule, always deploy as `queryType: "scheduled"` with `queryLang: "2.0"`.** This is the supported PowerQuery detection path on the `cloud-detection/rules` endpoint. The other combinations do not work:

| `queryType` | `queryLang` | Result |
|---|---|---|
| `scheduled` | `"2.0"` | Correct path for PowerQuery (pipe) rules. Body goes in `data.scheduledParams.query`; accepts pipe syntax. |
| `correlation` | `"2.0"` | Multi-event correlation rules. `s1ql` stays empty; logic goes in `data.correlationParams` (`entity`, `matchInOrder`, `timeWindow.windowMinutes`, and `subQueries[]` each `{matchesRequired, subQuery}` where `subQuery` is boolean S1QL with NO pipes). Tenant-confirmed 2026-06-24. |
| `events` | `"2.0"` | Correct path for events rules. Body is a boolean S1QL filter with NO pipes, placed in `data.s1ql` (e.g. `dataSource.name='Okta' and unmapped.legacyEventType contains 'token.detect_reuse'`). The `400 Don't understand [\|]` happens only when the body contains a pipe; events bodies cannot use PowerQuery pipe syntax. Confirmed: every live events rule on this tenant (Okta, Palo Alto, Windows Event Logs, SentinelOne) uses `queryLang:"2.0"`. |
| `events` | `"2.1"` | HTTP 400 `queryLang: "2.1" is not a valid choice`; the 2.1 dialect is not in the enum. |
| `events` | `"1.0"` | Also accepted for events (legacy default), but live rules use `"2.0"`. Boolean S1QL only, no pipes. |

The query string goes inside `data.scheduledParams.query`, not in `data.s1ql`. The `s1ql` field is for `queryType: "events"` rules.

### Canonical body for a PowerQuery scheduled detection rule

```json
{
  "data": {
    "name": "Rule name",
    "description": "What it detects (include MITRE technique IDs).",
    "queryType": "scheduled",
    "queryLang": "2.0",
    "severity": "High",
    "status": "Disabled",
    "expirationMode": "Permanent",
    "scheduledParams": {
      "query": "<your PowerQuery here>",
      "runIntervalMinutes": 60,
      "lookbackWindowMinutes": 60,
      "threshold": {"value": 0, "operator": "Greater"}
    }
  },
  "filter": {"accountIds": ["<accountId>"]}
}
```

Notes on the shape:

- **Scope:** `filter` accepts `accountIds` or `siteIds`. Pick the layer the rule should fire at. Account-level rules cover all sites under the account.
- **Threshold:** the trigger threshold is the alert-firing threshold (`scheduledParams.threshold`), not the internal `| filter` inside the PowerQuery. `{value: 0, operator: "Greater"}` means "alert if the PQ returns any rows at all", combined with an internal `| filter hits >= N`, you get N as the effective threshold.
- **Run interval and lookback:** match these (e.g. 60 / 60) for non-overlapping evaluation. Setting `lookbackWindowMinutes` higher than `runIntervalMinutes` causes overlap and duplicate alerts.
- **Hard cap: `lookbackWindowMinutes / runIntervalMinutes` must be <= 96.** Above that the create returns `HTTP 400 "Validation Error"` naming NEITHER field, so it reads as a malformed body. Probed at the boundary (2026-08-09): lookback 1440 accepts cadence 15 (ratio 96.0) and rejects 14 (102.9), 12, 10 and 5; lookback 60 accepts 5 and 10. A daily-baseline rule therefore cannot evaluate more often than every 15 minutes. If a UI or config offers a faster cadence (a 5-minute "demo" option is a common trap), clamp it: raise the requested interval to `ceil(lookback / 96)` rather than letting the whole deploy fail.
- **The cadence is also the floor on any end-to-end test.** There is no run-now for a scheduled rule, so validating that one fires costs at least one interval (15 min on a daily lookback). No amount of parallelism removes it; budget for it.
- **`status`:** new rules land as `Draft` on creation regardless of the requested status. Enable separately with `PUT /web/api/v2.1/cloud-detection/rules/enable` (body `{"filter": {"ids": [...], "accountIds": [...]}}`).
- **No `disableAgentMitigation` field:** that property is not part of the scheduled-rule schema. Including it returns HTTP 400 `Unknown field`. Cloud-source PQ rules do not need it.
- **No `treatAsThreat: "Malicious"`:** scheduled rules accept `treatAsThreat: "UNDEFINED"` (or omit) and `networkQuarantine: false`. Inline (on-rule) mitigation is not supported on scheduled rules; drive mitigation from a Hyperautomation flow triggered by the alert instead.

### If creation fails with `feature not enabled` or equivalent

If `POST /web/api/v2.1/cloud-detection/rules` returns an error indicating Scheduled Detections / PowerQuery Alerts are not licensed or not turned on for the tenant, do not retry, do not silently downgrade to S1QL. **Stop and tell the user to enable the Scheduled Detections feature on the tenant before deploying.** Common surface for this in the console: *Settings → Account → Detection / SDL Add-Ons → Scheduled Detections* (exact path varies by platform version). The user needs to enable it (or have their CS/SE enable it) and then the same POST will succeed.

Do not use Hyperautomation workflows to schedule PQ detections. `cloud-detection/rules` is the correct mechanism. HA is for SOAR-style response playbooks.

### Updating and enabling a rule

```json
PUT /web/api/v2.1/cloud-detection/rules/{id}        # full-replacement update; all 5 data fields required, plus filter
PUT /web/api/v2.1/cloud-detection/rules/enable      # body: {"filter": {"ids": [...], "accountIds": [...]}}
PUT /web/api/v2.1/cloud-detection/rules/disable     # same shape
```

`GET /cloud-detection/rules?ids=...&accountIds=...&isLegacy=false` requires `isLegacy=false` for scheduled rules, without it the list call returns zero results even when the rules exist and the POST response gave you their IDs.

`isLegacy` is a GET-listing query parameter ONLY. Do NOT put it in the `enable` / `disable` PUT body: `{"filter": {"ids": [...], "isLegacy": false}}` returns `400 filter: isLegacy: Unknown field`. The enable/disable filter accepts `ids` plus an optional scope (`accountIds` / `siteIds`); `ids` alone is sufficient because rule IDs are globally unique. Tenant-validated 2026-06-16: `PUT /cloud-detection/rules/enable` with `{"filter": {"ids": [...]}}` returned `{"affected": N}`.

### Validate the rule is Active before ingesting test data (mandatory)

Enabling a rule does NOT make it evaluate immediately. After `PUT .../enable` the rule reports `statusReason: "...will become Active within an hour"` and stays inactive until the platform propagates it (up to ~60 minutes). Events rules evaluate streaming at ingest, so any test event that arrives BEFORE the rule is Active is never evaluated, and you will wrongly conclude the rule or the event attributes are broken.

Always poll the rule status until it is Active before ingesting any validation data:

```text
GET /web/api/v2.1/cloud-detection/rules?ids=<id>&accountIds=<acct>&isLegacy=false
# proceed only when data[0].status == "Active"
```

Do not ingest, do not judge a rule "not firing", and do not strip attributes to debug binding until `status == "Active"`. This check was the root cause of a false "events rules are EDR-only / the attributes are wrong" conclusion: the rule simply had not activated yet. Scheduled rules have the same activation lag, and additionally evaluate only on their `runIntervalMinutes` cadence, so allow at least one full interval after activation before judging them.

---

## Testing a rule body before deploying

1. Run it with the Purple MCP `powerquery` tool over the last 24 hours. Confirm it parses and returns 0-N rows (not an error, not thousands).
2. Confirm the threshold (`filter count >= N`) doesn't zero out the result for a known-good example, walk `N` down until you see a row, then set `N` slightly above what a benign environment would produce.
3. Run it over 7 days for baseline volume: expected row count × 7 ≈ what a week of alerting will look like.
4. If the `group`-intermediate ever exceeds 1,000 rows in a 24-hour window, tighten the initial filter.

## Lookup table size and per-device detections (validated)

- `savelookup` / `| lookup` datatables can be up to **150MB per table** (extensible by contacting SentinelOne); table size is essentially never the design blocker. Do not treat lookups as capped to a small row count.
- A `lookup` used INSIDE a scheduled `cloud-detection` rule is additionally validated for load size (on at least one tenant a ~26,800-row lookup table was rejected with "Maximum number of rows allowed is 10000"). Treat this as a soft, tenant-configurable limit: use a coarser key (hour-of-day = 24 buckets instead of hour-of-week = 168) or a volume floor to keep the rule's lookup small, or request an increase. It is not a reason to abandon a lookup-based detection.
- Name the pipeline join expression differently from the table key: `| lookup col from t by <tableKey> = <expr>` (e.g. `by devkey = dk`), not `by devkey = devkey`, which can fail the rule parser with "Expected ')'".
- Bound per-device / high-cardinality detections by doing the baseline `lookup` + `filter exp_gib > 0` per event BEFORE the `group`, so the intermediate stays within the 1,000-row alert budget.
