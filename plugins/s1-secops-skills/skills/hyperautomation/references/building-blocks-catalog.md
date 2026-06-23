# Building Blocks Catalog, Reusable SOAR Patterns

This catalog is mined from **643 active production workflows** (14,045 action steps) running on
SentinelOne tenants. Every building block here was observed in real flows, with usage counts so
you know what's load-bearing and what's a one-off.

Read this when you need to:

- **Pick the right action** for a given step (Section A, Atomic Blocks).
- **Compose multi-action idioms** like "page through a Slack list", "branch on success/fail",
  "hash-enrich an alert" (Section B, Composite Patterns).
- **Bootstrap a SOAR flow** for one of the common security use cases (Section C, Recipes).
- **Avoid the same mistakes** the corpus already paid for (Section E, Anti-patterns).

For exact field-by-field schemas, cross-reference `building-blocks.md`. For function syntax,
cross-reference `functions-reference.md`. For end-to-end JSON envelopes, cross-reference
`workflow-schema.md`.

---

## Action-type prevalence in active flows (the load-bearing 17)

| Rank | Type | Count | Class | Tag |
|------|------|------:|-------|-----|
| 1 | `http_request` | 2,699 | I/O | core or integration |
| 2 | `variable` | 2,459 | State | core |
| 3 | `condition` | 1,697 | Control | core |
| 4 | `loop` | 498 | Control | core |
| 5 | `singularity_response_trigger` | 406 | Trigger | core |
| 6 | `data_formation` | 249 | State | core |
| 7 | `send_email` | 227 | I/O | core |
| 8 | `snippet` | 194 | Composition | core |
| 9 | `break_loop` | 181 | Control | core |
| 10 | `manual_trigger` | 151 | Trigger | core |
| 11 | `wait_for_slack` | 115 | Sync | core |
| 12 | `delay` | 93 | Control | core |
| 13 | `http_trigger` | 65 | Trigger | core |
| 14 | `scheduled_trigger` | 20 | Trigger | core |
| 15 | `create_interaction` | 7 | Sync | core |
| 16 | `wait_for_interaction` | 7 | Sync | core |
| 17 | `email_trigger` | 1 | Trigger | core |

Of the 2,699 HTTP requests, **2,438 (90%) are integration-backed** (use a pre-configured
connection) and **261 (10%) are core HTTP** (raw URL, OAuth/API key in headers).

---

# Section A, Atomic Blocks

Each block lists: **purpose**, **copy-paste shape** (only the fields you actually need to think
about, the rest can be defaulted from `building-blocks.md`), **real example from the corpus**,
and **when to reach for it**.

---

## A1. Singularity Response Trigger (most common alert-driven entry point)

**Purpose**: fire a workflow when a SentinelOne alert / misconfiguration / vulnerability /
activity is created or updated.

**Real shape, high/critical EDR alert filter (most common in corpus)**:
```json
{
  "type": "singularity_response_trigger",
  "tag": "core_action",
  "data": {
    "name": "Singularity Response Trigger",
    "action_type": "singularity_response_trigger",
    "filter_groups": [{
      "condition": {
        "operator": "and",
        "conditions": [
          { "input_value": "severity", "compared_value": "[\"HIGH\",\"CRITICAL\"]", "comparison_operator": "in" },
          { "input_value": "detectionSource.product", "compared_value": "[\"EDR\"]", "comparison_operator": "in" }
        ]
      },
      "is_disabled": false,
      "run_automatically": false,
      "event_type": "alert",
      "event_subtypes": ["CREATE"]
    }]
  }
}
```

**Event-type mix in the corpus**: `alert` (406), `misconfiguration` (15), `vulnerability` (10),
`activity` (3). **Subtype mix**: `CREATE` (434), `UPDATE` (26).

**Filter-input fields most used**:
`severity`, `detectionSource.product`, `analystVerdict`, `confidenceLevel`, `status`, `name`.

**Compared-value formatting note**: when `comparison_operator` is `in`, `compared_value` must be
a **JSON-encoded string** of an array, e.g. `"[\"HIGH\",\"CRITICAL\"]"`, not a literal array.
This is how every active flow encodes it.

**Reach for it when**: you want the workflow to run automatically off the SentinelOne alerting
stream. Set `run_automatically: false` if the analyst should approve via the Singularity Response
console; set `true` for fully automated response.

---

## A2. Manual Trigger (analyst-initiated)

**Purpose**: run-on-demand. Two flavors: static (no input) and dynamic (analyst fills a form).

**Static shape (151 of 151 manual triggers in active flows use this)**:
```json
{
  "type": "manual_trigger",
  "tag": "core_action",
  "data": {
    "name": "Manual Trigger",
    "action_type": "manual_trigger",
    "trigger_type": "static",
    "dynamic_properties": null,
    "static_payload": "{}"
  }
}
```

**Dynamic shape (form-driven)**:
```json
{
  "type": "manual_trigger",
  "tag": "core_action",
  "data": {
    "name": "Manual Trigger",
    "action_type": "manual_trigger",
    "trigger_type": "dynamic",
    "dynamic_properties": {
      "Hostname": {
        "title": "Hostname",
        "description": "Endpoint to investigate",
        "index": 0,
        "type": "text",
        "validation": { "required": true, "min_length": null, "max_length": null }
      }
    },
    "static_payload": "{}"
  }
}
```
Reference: `{{manual-trigger.data.Hostname}}`.

**Reach for it when**: building an investigation playbook, a one-off remediation, or a
parameterized hunt that an analyst kicks off from the console.

---

## A3. Scheduled Trigger

**Purpose**: run on a cadence. Three patterns observed: `daily` (11), `weekly` (7), `interval`
(6 with units `hours` 3/6/12 and `minutes` 10/15).

**Daily at a fixed local time**:
```json
{
  "type": "scheduled_trigger",
  "tag": "core_action",
  "data": {
    "name": "Scheduled Trigger",
    "action_type": "scheduled_trigger",
    "schedule_method": "daily",
    "until": null,
    "max_runs": 1,
    "schedule_value": [{
      "schedule_method": "daily",
      "minute": 0,
      "hour": 8,
      "tz": "America/Los_Angeles"
    }],
    "start_at_method": "immediately",
    "start_at": null,
    "ends_on": "never"
  }
}
```

**Every N hours (interval)**:
```json
{
  "schedule_method": "interval",
  "schedule_value": [{
    "schedule_method": "interval",
    "interval_unit": "hours",
    "interval_value": 6,
    "tz": "America/Los_Angeles"
  }],
  "start_at_method": "date",
  "start_at": "2026-02-17T04:28:29.000Z",
  "ends_on": "never",
  "max_runs": 1
}
```

**Weekly on a specific day** uses `week_day` (0=Sun … 6=Sat).

**Reach for it when**: hourly/daily IOC ingest, weekly hygiene reports, periodic data-lake
queries that drop results into a ticket.

---

## A4. HTTP Trigger (Webhook)

**Purpose**: expose a public webhook URL that any external system can POST to. The console
generates a unique `url_identifier` (UUID) baked into the URL.

**Real shape**:
```json
{
  "type": "http_trigger",
  "tag": "core_action",
  "data": {
    "name": "HTTP Trigger",
    "action_type": "http_trigger",
    "url_identifier": "<auto-generated-uuid>",
    "supported_methods": { "get": true, "post": true },
    "response_status_code": 200,
    "response_body": "{\"Status\": \"OK\"}",
    "response_content_type": "application/json",
    "response_headers": {},
    "include_headers": true,
    "allow_empty_request_body": true,
    "dedup_include": null,
    "dedup_exclude": null,
    "dedup_interval_seconds": 180,
    "condition": null
  }
}
```

**De-duplication**: `dedup_interval_seconds` collapses identical webhook payloads inside a sliding
window (180s = 3 minutes is the default in active flows).

Reference incoming data: `{{http-trigger.body.<field>}}`, `{{http-trigger.query_params.<key>}}`,
`{{http-trigger.headers.<header>}}`.

**Reach for it when**: ingesting events from a third-party SIEM, ITSM, or chatops bot. Pair with
a Condition action that checks `{{http-trigger.headers.X-Auth-Token}}` to gate access.

---

## A5. Email Trigger (rare, 1 occurrence)

```json
{
  "type": "email_trigger",
  "tag": "core_action",
  "data": {
    "name": "Email Trigger",
    "action_type": "email_trigger",
    "mark_as_read": true,
    "email_method": null
  }
}
```
Reference: `{{email-trigger.subject}}`, `{{email-trigger.body}}`,
`{{email-trigger.from}}`, `{{email-trigger.attachments}}`.

**Reach for it when**: ingesting phishing reports forwarded to a mailbox, or processing low-
volume inbound email tickets. Only one active flow uses this, a strong signal that webhook-
style ingest is preferred.

---

## A6. Variable (state)

**Purpose**: assign a named value (literal, expression, or JSON object) for downstream reference.
Most-used pattern is **single-variable per action** (97 of the 100 most-named Variable actions
are simply called "Variable" with one entry).

**Single literal**:
```json
{
  "type": "variable",
  "tag": "core_action",
  "data": {
    "name": "VT Hash Found and Suspicious",
    "action_type": "variable",
    "variables": [
      { "name": "vt_verdict", "value": "suspicious", "should_use_as_output": false, "is_secret": false }
    ],
    "variables_scope": "local"
  }
}
```

**Expression (most common in corpus, `Function.DEFAULT` for safe field access)**:
```json
{
  "data": {
    "name": "Alert Hash",
    "action_type": "variable",
    "variables": [{
      "name": "alert-hash",
      "value": "{{Function.DEFAULT(Function.DEFAULT(singularity-response-trigger.data.process.file.sha256, singularity-response-trigger.data.process.file.sha1), \"no-hash\")}}",
      "should_use_as_output": false,
      "is_secret": false
    }],
    "variables_scope": "local"
  }
}
```

**Multi-variable in one action, only safe when none of the values reference each other**:
```json
{
  "data": {
    "name": "Forbidden Words",
    "variables": [
      { "name": "forbidden_words", "value": "[\"dreary\", \"quaint\", \"weak\", \"weary\"]", "is_secret": false },
      { "name": "censoring_enabled", "value": "true", "is_secret": false }
    ],
    "variables_scope": "local"
  }
}
```

`variables_scope`: `"local"` (visible only in this run) or `"global"` (persists across runs of
this workflow). Reference with `{{local_var.x}}` or `{{global_var.x}}`.

**See anti-pattern E1** for the cross-variable-reference trap.

---

## A7. Condition (branching)

**Purpose**: split control flow on a comparison. The corpus uses **`condition_type: "multi"`
universally** (1,697 of 1,697), even for single comparisons. Stick with multi.

**Operator distribution in active flows**:

| Operator | Count |
|----------|------:|
| `equals` | 1,105 |
| `not_equals` | 271 |
| `greater_than_or_equals` | 194 |
| `greater_than` | 168 |
| `contains` | 34 |
| `in` | 1 |

**Real shape**:
```json
{
  "type": "condition",
  "tag": "core_action",
  "data": {
    "name": "Alert has Hash",
    "action_type": "condition",
    "condition_type": "multi",
    "condition": null,
    "conditions": [
      { "input_value": "{{local_var.alert-hash}}", "compared_value": "no-hash", "comparison_operator": "not_equals" }
    ],
    "conditions_relationship": "and"
  }
}
```

**Multiple AND clauses**:
```json
"conditions": [
  { "input_value": "{{search-for-file-hash.status_code}}", "compared_value": "200", "comparison_operator": "equals" },
  { "input_value": "{{search-for-file-hash.body.data.attributes.last_analysis_stats.malicious}}", "compared_value": "0", "comparison_operator": "greater_than" }
],
"conditions_relationship": "and"
```

**Edge wiring**: `connected_to[].custom_handle` is `"true"` or `"false"`.

**Reach for it when**: branching on HTTP status, analyst verdict, severity, presence of a field,
result of an enrichment lookup.

---

## A8. Loop (iteration)

**Purpose**: iterate over an array (`dynamic`), run a fixed N times (`fixed`), or loop until a
`break_loop` fires (`while`).

**Dynamic loop (the only flavor seen in active flows, 498/498)**:
```json
{
  "type": "loop",
  "tag": "core_action",
  "data": {
    "name": "Iterate Users",
    "action_type": "loop",
    "loop_type": "dynamic",
    "number_of_iterations": 1,
    "object_to_iterate": "{{local_var.users}}",
    "is_parallel": false
  }
}
```

**Wiring**:

- The loop's `connected_to` entry that points at the **first inner action** must use
  `"custom_handle": "inner"`.
- Every inner action sets `"parent_action": <loop_export_id>`.
- After the inner subgraph finishes, the loop's *other* `connected_to` entry (with
  `"custom_handle": null` or omitted) points to the action that runs once after the loop ends.

**References inside the loop**: `{{loop.item}}`, `{{loop.item.field}}`,
`{{loop.index}}`. (Top-30 referenced action slugs include `iterate-column-values` 221x and
`iterate-users` 77x, both loop bodies.)

**Parallel execution**: set `is_parallel: true` for fan-out (rare in corpus, most loops are
sequential to keep API rate limits sane).

---

## A9. Break Loop

**Purpose**: terminate the enclosing loop. Always sits inside a `condition` branch.

```json
{
  "type": "break_loop",
  "tag": "core_action",
  "data": { "name": "Break Loop", "action_type": "break_loop" }
}
```

`parent_action` = the loop's `export_id`. `connected_to` = `[]` (it's a sink).

**Most common partner pattern**: pagination loops. The break fires when
`{{list-channels.body.response_metadata.next_cursor}}` is empty.

---

## A10. Delay

**Purpose**: pause N seconds / minutes / hours.

```json
{
  "type": "delay",
  "tag": "core_action",
  "data": { "name": "Delay 5 seconds", "action_type": "delay", "time_unit": "seconds", "value": 5 }
}
```

**Reach for it when**: rate-limit cooldown between API calls; letting an asynchronous backend
job (RemoteOps, scan) finish before polling its status; staging notifications.

---

## A11. Data Formation

**Purpose**: build a structured object on the fly without using a Variable. Most often used as a
scratchpad to assemble payloads from multiple sources.

**Real shape (most-cloned: "Generate UUID", 75 occurrences)**:
```json
{
  "type": "data_formation",
  "tag": "core_action",
  "data": {
    "name": "Generate UUID",
    "action_type": "data_formation",
    "data": { "uuid": "{{Function.SUBSTRING(Function.GENERATE_UUID4(), 6)}}" }
  }
}
```

Reference: `{{generate-uuid.data.uuid}}`.

Other real uses observed: `Channel Info` (build a Slack channel-config dict from alert fields),
custom note bodies, normalized event objects for SDL ingest.

---

## A12. HTTP Request (core, no integration)

**Purpose**: hit an arbitrary HTTP endpoint with full control over method, URL, headers, body,
auth, retry, SSL, proxy.

**Real shape (most generic, note `tag: "core_action"`, all integration fields null)**:
```json
{
  "type": "http_request",
  "tag": "core_action",
  "connection_id": null,
  "connection_name": null,
  "use_connection_name": false,
  "integration_id": null,
  "data": {
    "name": "Retrieve TOR Exit Nodes",
    "action_type": "http_request",
    "public_action_id": null,
    "method": "get",
    "url": "https://check.torproject.org/torbulkexitlist",
    "url_path": null,
    "url_prefix": null,
    "payload": null,
    "parameters": [],
    "retry_on_status_code": null,
    "retry_on_status_codes": [500],
    "ssl_verification": true,
    "timeout": 30,
    "headers": { "Content-Type": "application/json" },
    "use_authentication_data": false,
    "use_proxy": false,
    "redirect_follow": true,
    "continue_on_fail": false,
    "body_type": null
  }
}
```

**Method mix in active flows**: POST 1,962 (73%), GET 664, PUT 55, DELETE 13, PATCH 5.

**Top hostnames hit by core HTTP requests**: `slack.com` (Slack web API), `raw.githubusercontent.com`
(IOC list pulls), `api.virustotal.com`, `api.openai.com`, `check.torproject.org`,
`api.abuseipdb.com`, `api.dropboxapi.com`, `api.github.com`, `api.openai.com`.

**Reach for it when**: the endpoint is not behind a configured Hyperautomation integration, or
you want to inline-template the URL with `{{...}}`.

---

## A13. HTTP Request (integration-backed)

**Purpose**: same shape, but the URL, base, and authentication come from a connection
pre-configured in `Hyperautomation → Integrations`. 90% of HTTP requests in active flows.

**Real shape, SentinelOne integration (Create Device Control Rule)**:
```json
{
  "type": "http_request",
  "tag": "integration",
  "connection_id": null,
  "connection_name": "",
  "use_connection_name": false,
  "integration_id": null,
  "data": {
    "name": "Create Device Control Rule",
    "action_type": "http_request",
    "public_action_id": "fecff713-56be-4f9b-8e64-0af3d46ad8aa",
    "method": "post",
    "url": "{{Connection.protocol}}{{Connection.url}}/web/api/v2.1/device-control",
    "url_path": "/web/api/v2.1/firewall-control",
    "url_prefix": null,
    "payload": "{ \"data\": { ... }, \"filter\": { \"siteIds\": [ \"{{http-trigger.query_params.site}}\" ] } }",
    "headers": { "Content-Type": "application/json", "accept": "application/json" },
    "use_authentication_data": true,
    "ssl_verification": true,
    "timeout": 30,
    "retry_on_status_codes": [500],
    "redirect_follow": true,
    "continue_on_fail": false
  }
}
```

**Hard rule for generation**: when emitting integration actions for import, set
`connection_id: null`, `connection_name: ""`, `use_connection_name: false`,
`integration_id: null`. The console resolves them post-import from the user's connections.
**Keep `public_action_id`**, it identifies which action in the integration's catalog this is.

**Reach for it when**: hitting any of S1, M365, Slack, Okta, Jira, ServiceNow, etc. via their
official integrations.

---

## A14. Send Email

**Purpose**: SMTP-out via the platform mailer. 99% of active uses send to **a single recipient**
(`list_1`).

**Real shape (HTML body with templated alert fields)**:
```json
{
  "type": "send_email",
  "tag": "core_action",
  "data": {
    "name": "Send Email",
    "action_type": "send_email",
    "subject": "Device Control Applied",
    "to": ["{{http-trigger.query_params.email}}"],
    "cc": [],
    "bcc": [],
    "reply_to": [],
    "mime_type": "text/html",
    "body": "<!DOCTYPE html><html>... {{http-trigger.query_params.serial}} ...</html>",
    "attachments": [],
    "continue_on_fail": false
  }
}
```

`mime_type`: `"text/plain"` or `"text/html"` (HTML is more common, analyst-friendly).
Recipients in `to`/`cc`/`bcc`/`reply_to` are arrays of strings (each element can be a literal
or a `{{...}}` expression).

**Attachments use `file_name` / `file_content` (NOT `name` / `content`)**, confirmed against the
live import API on 2026-06-11:
```json
"attachments": [
  { "file_name": "report.csv", "file_content": "{{Function.BASE64_ENCODE(local_var.csv)}}" }
]
```
`file_content` is base64. Using `name`/`content` returns
`422 "Field required"` on `attachments.0.file_name` / `attachments.0.file_content`.

---

## A15. Snippet

**Purpose**: invoke a saved sub-workflow as a single action. Drives composability, e.g. one
"Variables From Column GSheet" snippet is reused across 75+ workflows.

**Real shape**:
```json
{
  "type": "snippet",
  "tag": "core_action",
  "data": { "name": "Variables From Column GSheet", "action_type": "snippet" },
  "snippet_workflow_id": null,
  "snippet_version_id": null
}
```

**Important caveat from the corpus**: when a workflow is exported, **`snippet_workflow_id` and
`snippet_version_id` come back null** (0 of 194 snippets in the corpus carried IDs). On import,
the user re-binds the snippet by name in the console UI. So when you generate a workflow that
uses a snippet, make the `name` exactly match the snippet's name on the target tenant.

---

## A16. Wait for Slack

**Purpose**: pause until an analyst clicks a Slack interactive button on a previously-posted
message, or until the timeout elapses.

**Real shape**:
```json
{
  "type": "wait_for_slack",
  "tag": "core_action",
  "data": {
    "name": "Wait for Slack",
    "action_type": "wait_for_slack",
    "message_ts": "{{ask-for-disconnect.body.ts}}",
    "time_unit": "minutes",
    "value": 1
  }
}
```

`message_ts` is the Slack message timestamp returned by the prior `chat.postMessage` HTTP
request, the wait correlates the analyst's button click back to that specific message.

**References on resume**: `{{wait-for-slack.body.actions[0].value}}` (button payload),
`{{wait-for-slack.timeout}}` (true if no click before timeout).

---

## A17. Create Interaction & Wait for Interaction (in-console approval)

**Purpose**: built-in approval gate using a Hyperautomation-native interaction (no Slack
required).

**Create**:
```json
{
  "type": "create_interaction",
  "tag": "core_action",
  "data": {
    "name": "Create Wait on User Creation",
    "action_type": "create_interaction",
    "interaction_type": "choice",
    "options": ["user-creation"],
    "form_schema": null
  }
}
```

**Wait**:
```json
{
  "type": "wait_for_interaction",
  "tag": "core_action",
  "data": {
    "name": "Wait For Interaction",
    "action_type": "wait_for_interaction",
    "identifier": "{{create-wait-on-user-creation.interaction_id}}",
    "time_unit": "hours",
    "time_value": 1,
    "expected_respondents": 1,
    "response_targets": null,
    "authentication_type": null
  }
}
```

**Reach for them when**: you want a built-in approval prompt rendered in the Hyperautomation
console. Slack is more popular in the corpus (115 wait_for_slack vs 7 wait_for_interaction).

---

# Section B, Composite Patterns (multi-action idioms)

These are the recurring sub-graphs that show up across many flows. Use them as ready-made
mini-templates.

---

## B1. Safe field access with `Function.DEFAULT` chaining

**Where**: 305 occurrences of `Function.DEFAULT` in expressions.

When a trigger field may not be present, fall back through a chain to a sentinel:

```json
{
  "name": "Alert Hash",
  "variables": [{
    "name": "alert-hash",
    "value": "{{Function.DEFAULT(Function.DEFAULT(singularity-response-trigger.data.process.file.sha256, singularity-response-trigger.data.process.file.sha1), \"no-hash\")}}"
  }]
}
```

Always pair with a Condition that branches on `{{local_var.alert-hash}} != "no-hash"` so the
"no-hash" path skips downstream enrichment.

---

## B2. Success / fail branch with status_code (canonical SOAR pattern)

**Where**: 79 conditions named "Get Response on Time", 92 named "Is File Suspicious in VT".

```
HTTP Request → Condition (status_code == 200)
  TRUE  → Variable (success_note) → HTTP (Add Note "Enriched")
  FALSE → Variable (fail_note)    → HTTP (Add Note "Enrichment failed")
```

Body of each condition:
```json
"conditions": [{ "input_value": "{{my-action.status_code}}", "compared_value": "200", "comparison_operator": "equals" }],
"conditions_relationship": "and"
```

This pattern shows up so often it's effectively the SOAR equivalent of a try/catch. Use it
after every external API call that the analyst needs receipts for.

---

## B3. Pagination loop with cursor + break

**Where**: 75 occurrences of "Set Default Cursor" / "Set Filtered Channels" / "Last Page" trio
across Slack channel-discovery flows.

```
Variable (cursor = "")
  ↓
Loop (while)
  ↓ (inner)
HTTP (List Page) using {{local_var.cursor}}
  ↓
Variable (cursor = next_cursor from response)
  ↓
Condition (cursor is empty?)
  TRUE  → Break Loop
  (NO false edge — the while loop re-runs the inner block automatically; see warning)
```

> **Confirmed 2026-06-11 (live import):** do NOT wire the condition's `FALSE` branch back to the
> top of the inner block. A `while` loop re-runs its inner subgraph automatically until a
> `break_loop` fires, so the terminating condition needs only its `TRUE → break_loop` edge; the
> `FALSE` branch is simply omitted. An explicit back-edge to an earlier action makes the importer
> reject the whole workflow with a generic `422 "Invalid workflow data"`. (Import validation
> confirmed with the edge removed; runtime iteration not separately verified.)

Most-used cursor field in the corpus:
`{{list-channels.body.response_metadata.next_cursor}}`.

> **S1 list-endpoint pagination quirks (confirmed 2026-06-11 on `/web/api/v2.1/agents`):**
> `pagination.totalItems` is populated only on the **first** page (empty cursor) and returns `0`
> on later pages — for a true total, read it on page 1 or use the length of the gathered list.
> `nextCursor` is returned **already URL-encoded** (contains `%3D`); pass it straight into the
> next request's `cursor=` (do NOT wrap it in `Function.URL_ENCODE`). An empty `cursor=` returns
> page 1 cleanly, so seeding `cursor = ""` is safe.

---

## B4. Loop + APPEND to accumulate results

**Where**: 126 occurrences of `Function.APPEND`.

Inside a dynamic loop, build up a result list:

```json
{
  "name": "Accumulate Hits",
  "variables": [{
    "name": "all_hits",
    "value": "{{Function.APPEND(local_var.all_hits, loop.item)}}"
  }]
}
```

Always seed `all_hits` with `[]` in a Variable action **before** the loop, otherwise the first
APPEND has nothing to append to.

---

## B5. JQ filter for nested response shaping

**Where**: 186 occurrences of `Function.JQ`. Per `functions-reference.md`, store the JQ
expression in a Variable first to avoid escaping pain.

```
Variable (jq_filter = ".data.matches[] | {host: .endpoint.name, count: .count}")
  ↓
Variable (filtered = "{{Function.JQ(my-pq.body, local_var.jq_filter)}}")
```

---

## B6. Add Note to Unified Alert (UAM GraphQL, observed twice in two flavors)

**Modern flavor (cleaner GraphQL)**:
```json
"payload": "{\n  \"query\": \"mutation AddAlertNote { addAlertNote(text: \\\"{{Function.HTML_ENCODE(local_var.note_body)}}\\\", alertId: \\\"{{singularity-response-trigger.data.id}}\\\") { data { alertId } } }\"\n}"
```

**Legacy flavor (alertTriggerActions wrapper, used in older flows)**:
```json
"payload": "{\n  \"query\": \"mutation AddNoteToAlert { alertTriggerActions(actions: [{ id: \\\"S1/alert/addNote\\\", payload: { note: { value: \\\"{{Function.HTML_ENCODE(local_var.note)}}\\\" } } }], filter: { or: [{ and: [{ fieldId: \\\"id\\\", stringEqual: { value: \\\"{{singularity-response-trigger.data.id}}\\\" } }] }] }) { ... on ActionsTriggered { actions { actionId success { id } failure { id } skip { id } } } } }\"\n}"
```

Always wrap the note text in `Function.HTML_ENCODE(...)`, observed 110 times. Without it, any
quote in the note body breaks the GraphQL string.

URL for both: `{{Connection.protocol}}{{Connection.url}}/web/api/v2.1/unifiedalerts/graphql`.
Method: `POST`. Headers: `{ "Content-Type": "application/json" }`.

**Prefer the modern flavor** for new flows.

---

## B7. SDL Ingest single event (xdr.us1.sentinelone.net/api/addEvents)

```json
{
  "method": "post",
  "url": "https://xdr.us1.sentinelone.net/api/addEvents",
  "payload": "{\n  \"session\": \"{{Function.GENERATE_UUID4()}}\",\n  \"events\": [{\n    \"ts\": \"{{Function.MUL(Function.DATETIME_TO_EPOCH(Function.DATETIME_NOW()), 1000000000)}}\",\n    \"sev\": 3,\n    \"attrs\": {\n      \"message\": \"Agent Data - Last Active\",\n      \"Hostname\": \"{{loop.item.computerName}}\",\n      \"LastActive\": \"{{loop.item.lastActiveDate}}\"\n    }\n  }]\n}"
}
```

`ts` must be **nanoseconds since epoch** (epoch seconds × 1,000,000,000), that's why every
active example multiplies by `1000000000`. SDL bearer token goes in the `Authorization` header
via `use_authentication_data: true` (configured in the SDL Log-Write integration).

---

## B8. PowerQuery via DV API

```json
{
  "method": "post",
  "url": "{{Connection.protocol}}xdr.us1.sentinelone.net/api/<@powerQuery@>",
  "payload": "{\n  \"query\": \"{{local_var.pq_query}}\",\n  \"startTime\": \"24h\",\n  \"endTime\": \"0h\"\n}"
}
```

Build the PQ in a Variable first (multi-line PQ in a JSON string is awful otherwise).

---

## B9. Threat Intelligence IOC create

```json
{
  "method": "post",
  "url": "{{Connection.protocol}}{{Connection.url}}/web/api/v2.1/threat-intelligence/iocs",
  "payload": "{\n  \"data\": [{\n    \"externalId\": \"AbuseIPDB\",\n    \"source\": \"https://api.abuseipdb.com/api/v2/blacklist\",\n    \"type\": \"IPV4\",\n    \"value\": \"{{loop.item}}\",\n    \"originalRiskScore\": \"90\",\n    \"method\": \"EQUALS\",\n    \"name\": \"AbuseIPDB\",\n    \"description\": \"Blacklist from AbuseIPDB\",\n    \"category\": \"threats\",\n    \"validUntil\": \"{{Function.DELTA_NOW(-24)}}\",\n    \"creationTime\": \"{{Function.DATETIME_NOW()}}\"\n  }],\n  \"filter\": { \"accountIds\": [\"<account-or-site-id>\"] }\n}"
}
```

Choose `accountIds` for global IOCs, `siteIds` for per-site. Always set `validUntil` (use
`Function.DELTA_NOW(-N)` where N is hours from now, note negative N means *N hours forward*).

---

## B10. VirusTotal hash / IP / URL lookup

```json
{
  "method": "get",
  "url": "https://www.virustotal.com/api/v3/files/{{local_var.hash}}",
  "headers": { "x-apikey": "<api-key>", "Content-Type": "application/json" }
}
```

Variants: `/api/v3/ip_addresses/{{ip}}`, `/api/v3/urls/{{Function.BASE64_ENCODE(url)}}`.
Most flows then check `body.data.attributes.last_analysis_stats.malicious > 0` in a Condition.

---

## B11. Slack post + interactive wait + branch on choice

```
HTTP (chat.postMessage with Block Kit buttons) → captures {{post.body.ts}}
  ↓
Wait for Slack (message_ts = {{post.body.ts}}, value = 30 minutes)
  ↓
Condition (timeout?)
  TRUE  → fallback path
  FALSE → Condition ({{wait-for-slack.body.actions[0].value}} == "approve") → ...
            else → ...
HTTP (chat.delete the original message, observed 83 times)
```

The `chat.delete` cleanup is a recurring polish step in mature flows.

---

## B12. OpenAI summary of tool output

```json
{
  "method": "post",
  "url": "https://api.openai.com/v1/chat/completions",
  "headers": { "Authorization": "Bearer <key>", "Content-Type": "application/json" },
  "payload": "{ \"model\": \"gpt-3.5-turbo\", \"messages\": [{ \"role\": \"user\", \"content\": \"Summarise this for a SOC analyst: {{get-a-summary-of-all-behavior-reports-for-a-file.body}}\" }] }"
}
```

Then assign `{{open-ai.body.choices[0].message.content}}` to a Variable and feed it into B6
(Add Note to Alert), observed verbatim in two production flows.

---

## B13. Generate UUID for correlation IDs

```json
{
  "type": "data_formation",
  "data": {
    "name": "Generate UUID",
    "data": { "uuid": "{{Function.SUBSTRING(Function.GENERATE_UUID4(), 6)}}" }
  }
}
```

The `SUBSTRING(..., 6)` is a corpus convention, it trims the first 5 chars to keep the ID
shorter for human-readable channel names (Slack channel-name length cap).

---

# Section C, End-to-end SOAR Recipes

Each recipe is a known-good wiring of the Section A blocks plus Section B idioms. Use as
starting templates.

---

## C1. Alert → enrich-with-VT → add-note (the workhorse, ~100 active flows)

```
Singularity Response Trigger (severity ∈ HIGH/CRITICAL, EDR)
  → Variable (alert-hash via DEFAULT chain)               [B1]
  → Condition (alert-hash != "no-hash")
       FALSE → Variable (note = "no hash") → HTTP add-note  [B6]
       TRUE  → HTTP GET virustotal.com/api/v3/files/{hash}  [B10]
                 → Condition (status == 200)                [B2]
                     TRUE  → Condition (malicious > 0)
                                TRUE  → Variable (note = "VT says malicious") → HTTP add-note
                                FALSE → Variable (note = "VT clean") → HTTP add-note
                     FALSE → Variable (note = "VT lookup failed") → HTTP add-note
```

---

## C2. Scheduled IOC ingest (TOR / AbuseIPDB / GitHub list → S1 TI)

```
Scheduled Trigger (daily 08:00)                             [A3]
  → HTTP GET <ioc-list-url>                                 [A12]
  → Variable (ioc_list = parsed lines)
  → Loop (dynamic over local_var.ioc_list)                  [A8]
       (inner) HTTP POST /threat-intelligence/iocs          [B9]
                  with value = {{loop.item}}
  → (after loop) Send Email "IOC ingest summary"            [A14]
```

---

## C3. Webhook → device-control rule + analyst email

```
HTTP Trigger (POST/GET, dedup 180s)                          [A4]
  → HTTP POST /web/api/v2.1/device-control                   [A13]
       with serial/site from {{http-trigger.query_params.*}}
  → Send Email confirmation                                  [A14]
```

This recipe matches the "Create Device Control Rule" flow exactly, a complete, working
zero-trigger-input automation.

---

## C4. Manual investigation playbook (analyst-driven hunt)

```
Manual Trigger (dynamic, Hostname text input)               [A2]
  → HTTP POST PowerQuery (filter src.endpoint.name = ...)    [B8]
  → Variable (rows = body.matches)
  → Loop over local_var.rows                                  [A8]
       (inner) Data Formation (build summary row)             [A11]
                 → Variable (results = APPEND)                [B4]
  → (after loop) Send Email with HTML table                   [A14]
```

---

## C5. Approval gate via Slack (analyst confirms a remediation)

```
Singularity Response Trigger                                  [A1]
  → HTTP POST chat.postMessage (Block Kit Approve/Deny)
  → Wait for Slack (message_ts, 30 minutes)                   [A16]
  → Condition (timeout?)
       TRUE  → Variable (note "no analyst response") → add-note → end
       FALSE → Condition (action.value == "approve")
                  TRUE  → HTTP POST /agents/<id>/disable-network → add-note "Isolated"
                  FALSE → Variable (note "Analyst denied") → add-note
  → HTTP POST chat.delete                                     [B11]
```

---

## C6. Periodic posture report (UEBA-style)

```
Scheduled Trigger (interval, every 6 hours)                   [A3]
  → HTTP POST PowerQuery (logon counts per user)              [B8]
  → Variable (rows = MAP_TABLE(columns, matches))
  → HTTP POST addEvents → SDL (one event per row)             [B7]
  → Send Email "UEBA snapshot uploaded"                       [A14]
```

This is the shape of the "UEBA - User Baselines" active flow.

---

# Section D, Decision Matrix (use case → blocks)

| Use case | Trigger | Body | Notes |
|----------|---------|------|-------|
| Auto-enrich every EDR alert | A1 | B1 + B10 + B6 | C1 |
| Daily IOC sync from OSINT | A3 | A12 + A8 + B9 | C2 |
| Build ChatOps from external system | A4 | A13 + A14 | C3 |
| Analyst-initiated hunt with form | A2 | B8 + A8 + A14 | C4 |
| Two-step approval before isolate | A1 | B11 + A13 | C5 |
| Periodic UEBA snapshot to SDL | A3 | B8 + B7 + A14 | C6 |
| Phishing inbox triage | A5 | A12 (URL defang) + B6 | rare |
| Backstop for failing API call | any | A12 + A7 (status_code) + A6 + B6 | B2 |
| Page through paginated API | any | A6 + A8 (while) + A7 + A9 | B3 |
| Free-text summary of evidence | any | B12 + B6 | adds analyst-friendly note |

---

# Section E, Anti-patterns (paid-for in production)

## E1. Multi-variable with cross-references in one Variable action

Already enshrined in `building-blocks.md` and `SKILL.md`. The corpus confirms: every multi-var
Variable action that *does* work uses **independent** values (literals, trigger fields, or
external action outputs, never another local_var defined in the same action).

## E2. Forgetting `Function.HTML_ENCODE` on note bodies

110 active flows wrap note text in `HTML_ENCODE`. Flows that don't will silently break the
moment the note contains a quote, ampersand, or angle bracket. Wrap, always.

## E3. Hard-coding site IDs in IOC create

The corpus has IOC payloads with literal `accountIds: ["<account-id>"]`, fine for
single-tenant flows, broken on transfer. Prefer:
- Pull from a Variable (set up-front from a Manual Trigger / Webhook param), or
- Pull from `singularity-response-trigger.data.scopeId` if the alert carries it.

## E4. `compared_value` shaped wrong for `in` operator

`comparison_operator: "in"` requires `compared_value` to be a **JSON-encoded string of an
array**, not a raw array. Verified: all 1 in-operator usage in the corpus uses
`"[\"HIGH\",\"CRITICAL\"]"` style. Don't write `["HIGH","CRITICAL"]` directly.

## E5. Snippet IDs missing on import

When you import a workflow that uses snippets, the `snippet_workflow_id` and
`snippet_version_id` are null. The user must re-bind in the console. **Match the snippet's
`name` to the snippet's name on the target tenant** so re-binding is one click.

## E6. Forgetting `parent_action` on inner loop steps

Every action inside a loop must set `"parent_action": <loop_export_id>`. The validator catches
this at import time, but only after the user has gone through the warning dialog. Set it as
you generate.

## E7. Dropping `retry_on_status_codes` on flaky upstreams

The active corpus uses `retry_on_status_codes: [500]` on most integration HTTP requests ,
cheap insurance against transient backend hiccups. Mirror this default for any external API
call.

## E8. Using a Service User token for import

The Hyperautomation API has no endpoint to transfer or share workflow ownership. A workflow
imported with a Service User token is invisible to humans in the UI. Always use a personal
Console User API token for `S1_CONSOLE_API_TOKEN`. (Repeated here because it's the #1 cause
of "where did my workflow go?" support tickets.)

---

# Function frequency cheat-sheet (top 30 from active flows)

Use this as a hint of which functions you'll *actually* need vs. the long-tail.

| Function | Count | One-liner |
|----------|------:|-----------|
| `DEFAULT` | 305 | safe field access / fallback chains (B1) |
| `ACCESS_LIST_ITEM` | 192 | pull index from JQ result |
| `LENGTH` | 187 | array/string length for conditions |
| `JQ` | 186 | shape JSON without nesting more actions (B5) |
| `APPEND` | 126 | accumulate inside a loop (B4) |
| `HTML_ENCODE` | 110 | quote-safe note bodies (B6, E2) |
| `FLATTEN_ARRAY` | 90 | unnest nested arrays |
| `FILTER_OBJECTS` | 83 | filter array by key=value |
| `SUBSTRING` | 79 | trim a UUID, take a prefix/suffix |
| `DATETIME_NOW` | 75 | timestamp for IOCs / SDL events |
| `STRING` | 52 | force value to string |
| `REPLACE` | 50 | swap substrings |
| `DELTA_NOW` | 33 | time math from now |
| `LOWER` | 28 | normalize case for comparisons |
| `ADD` | 26 | arithmetic |
| `REGEX_REPLACE` | 25 | sanitize / mask values |
| `GET_WORKFLOW_NAME` | 24 | self-referential metadata for notes |
| `DATETIME_TO_EPOCH` | 23 | seconds-since-epoch (× 1e9 for SDL nanos, B7) |
| `FORMATTED_DATE` | 21 | human-friendly timestamps |
| `GET_MANAGEMENT_URL` | 19 | build console deep-links |
| `DATETIME_TO_MS` | 17 | milliseconds for ts fields |
| `UNION` | 17 | merge two lists |
| `MUL` | 16 | nano-timestamps, percent math |
| `GET_EXECUTION_ID` | 15 | self-id for run-correlation notes |
| `MATCH_REGEX` | 15 | true/false on regex match |
| `EXTRACT_IPS` | 14 | pull IPs from free text |
| `REGEX_EXTRACT` | 14 | pull a substring by pattern |
| `PARSE_JSON` | 12 | string → object before access |
| `WORKFLOW_LINK` | 10 | self-link for analyst notes |
| `BASE64_DECODE_AS_BYTES` | 10 | binary handling |

Anything below count 10 is genuinely long-tail; reach for it only when nothing above will do.

---

# What's NOT in the corpus (don't invent these)

- `loop_type: "fixed"`, exists in the schema, but **0 of 498 active loops** use it. Either the
  pattern is rare or `dynamic` over a literal array is preferred. Use `dynamic`.
- `condition_type: "simple"`, also unused (0 of 1,697). Always `multi`.
- Inline OAuth flows, the corpus relies on integration connections to handle auth. Don't try
  to hand-roll OAuth in core HTTP requests; configure an integration.
- Synchronous fan-out, `is_parallel: true` on loops is rare. Default to `false` to respect
  external API rate limits.
