# Building Blocks Reference

Complete data payloads for every action type in SentinelOne Hyperautomation.

> **See also**: `building-blocks-catalog.md`, same atoms, organized by *when to reach for
> them*, with composite patterns (success/fail branch, pagination loop, hash enrichment),
> end-to-end SOAR recipes, and anti-patterns. Mined from 643 active production workflows.
> Use this file (`building-blocks.md`) for the field-by-field schema; use the catalog when
> you need to *compose* a workflow.

---

## TRIGGERS

### Manual Trigger (static — no user input)
```json
{
  "type": "manual_trigger",
  "tag": "core_action",
  "connection_id": null,
  "connection_name": null,
  "use_connection_name": false,
  "integration_id": null,
  "data": {
    "name": "Manual Trigger",
    "action_type": "manual_trigger",
    "trigger_type": "static",
    "dynamic_properties": {},
    "static_payload": "{}"
  },
  "state": "active",
  "description": null,
  "client_data": { "position": {"x": 0, "y": 0}, "dimensions": {"width": 256, "height": 100}, "collapsed": false },
  "snippet_workflow_id": null,
  "snippet_version_id": null
}
```

### Manual Trigger (dynamic — prompts user for input)
```json
{
  "type": "manual_trigger",
  "tag": "core_action",
  "connection_id": null,
  "connection_name": null,
  "use_connection_name": false,
  "integration_id": null,
  "data": {
    "name": "Manual Trigger",
    "action_type": "manual_trigger",
    "trigger_type": "dynamic",
    "dynamic_properties": {
      "AssetName": {
        "title": "",
        "description": "Enter the asset name to investigate",
        "index": 0,
        "type": "text",
        "validation": { "required": true, "min_length": null, "max_length": null }
      }
    },
    "static_payload": "{}"
  }
}
```
Input types: `"text"`, `"number"`, `"json"`, `"email"`, `"date"`, `"time"`, `"checkbox"`
Reference: `{{manual-trigger.data.AssetName}}`

### Scheduled Trigger
```json
{
  "type": "scheduled_trigger",
  "tag": "core_action",
  "data": {
    "name": "Scheduled Trigger",
    "action_type": "scheduled_trigger",
    "schedule_method": "weekly",
    "until": null,
    "max_runs": 1,
    "schedule_value": [
      {
        "schedule_method": "weekly",
        "minute": 0,
        "hour": 18,
        "tz": "Europe/Rome",
        "week_day": 2
      }
    ],
    "start_at": null,
    "start_at_method": "immediately",
    "ends_on": "never"
  }
}
```
`week_day`: 0=Sunday, 1=Monday, 2=Tuesday, 3=Wednesday, 4=Thursday, 5=Friday, 6=Saturday
`schedule_method` options: `"daily"`, `"weekly"`, `"monthly"`, `"interval"`

### HTTP Trigger (Webhook)
```json
{
  "type": "http_trigger",
  "tag": "core_action",
  "data": {
    "name": "HTTP Trigger",
    "action_type": "http_trigger",
    "url_identifier": "97ab0444-6f32-493b-b761-30970291414d",
    "supported_methods": { "get": true, "post": true },
    "response_status_code": 200,
    "response_body": "{\"Status\": \"OK\"}",
    "response_content_type": "application/json",
    "response_headers": {},
    "include_headers": true,
    "allow_empty_request_body": true
  }
}
```
Reference incoming data: `{{http-trigger.body.someField}}`

### Singularity Response Trigger
```json
{
  "type": "singularity_response_trigger",
  "tag": "core_action",
  "data": {
    "name": "Singularity Response Trigger",
    "action_type": "singularity_response_trigger",
    "filter_groups": [
      {
        "condition": {
          "operator": "and",
          "conditions": [
            {
              "input_value": "severity",
              "compared_value": "[\"HIGH\",\"CRITICAL\"]",
              "comparison_operator": "in"
            },
            {
              "input_value": "detectionSource.product",
              "compared_value": "[\"EDR\"]",
              "comparison_operator": "in"
            }
          ]
        },
        "is_disabled": false,
        "run_automatically": false,
        "event_type": "alert",
        "event_subtypes": ["CREATE"]
      }
    ]
  }
}
```

`event_type` options (count in active corpus): `"alert"` (406), `"misconfiguration"` (15),
`"vulnerability"` (10), `"activity"` (3).
`event_subtypes` options: `"CREATE"` (434), `"UPDATE"` (26).

> **`compared_value` format trap**: when `comparison_operator` is `"in"`, `compared_value` must
> be a **JSON-encoded string of an array** (e.g. `"[\"HIGH\",\"CRITICAL\"]"`), not a raw JSON
> array. Every active production flow uses this string-encoded format.
Common trigger data references:
- `{{singularity-response-trigger.data.id}}` — alert ID
- `{{singularity-response-trigger.data.name}}` — alert name
- `{{singularity-response-trigger.data.severity}}` — severity
- `{{singularity-response-trigger.data.asset.name}}` — asset/hostname
- `{{singularity-response-trigger.data.asset.agentUuid}}` — agent UUID
- `{{singularity-response-trigger.data.process.file.sha1}}` — file SHA1
- `{{singularity-response-trigger.data.process.file.sha256}}` — file SHA256
- `{{singularity-response-trigger.data.detectionSource.product}}` — product (EDR, STAR, CWS...)
- `{{singularity-response-trigger.data.externalId}}` — threat external ID
- `{{singularity-response-trigger.data.indicators[0].id}}` — first indicator ID
- `{{singularity-response-trigger.data.indicators[0].eventTime}}` — first indicator event time

### Email Trigger
```json
{
  "type": "email_trigger",
  "tag": "core_action",
  "data": {
    "name": "Email Trigger",
    "action_type": "email_trigger"
    /* connection details configured in console */
  }
}
```
Reference: `{{email-trigger.body}}`, `{{email-trigger.subject}}`

---

## CORE ACTIONS

### Variable
```json
{
  "type": "variable",
  "tag": "core_action",
  "data": {
    "name": "My Variables",
    "action_type": "variable",
    "variables": [
      {
        "name": "myVar",
        "value": "someValue or {{expression}}",
        "should_use_as_output": false,
        "is_secret": false
      },
      {
        "name": "emptyArray",
        "value": "[]",
        "should_use_as_output": false,
        "is_secret": false
      }
    ],
    "variables_scope": "local",
    "expire_in_unit": null,
    "expire_in_value": null,
    "expire_method": null,
    "workflows_acl": null
  }
}
```
`variables_scope`: `"local"` (default) or `"global"`
Reference: `{{local_var.myVar}}` or `{{global_var.myVar}}`
`should_use_as_output: true` exposes the variable as a workflow-level output (visible in the
execution detail and consumable by parent workflows).
`is_secret: true` redacts the value from the UI / execution logs (useful for tokens).
`expire_in_unit` / `expire_in_value` / `expire_method` are only used for global variables that
should TTL out; leave null for local.

> **HARD RULE — one variable per action when referencing other local variables**
>
> All entries in a single Variable action's `variables` array are evaluated simultaneously, not
> sequentially. If variable B's value references `{{local_var.A}}` and A is defined in the same
> action, A will be unresolved at evaluation time and B will silently receive an empty/null value.
>
> **Rule**: if any variable's value references a local variable defined elsewhere in the same
> workflow, give each such variable its own dedicated Variable action.
>
> ❌ **Wrong** — `fullPath` silently resolves to empty because `baseUrl` is not yet available:
> ```json
> {
>   "name": "Set Vars",
>   "action_type": "variable",
>   "variables": [
>     { "name": "baseUrl", "value": "https://api.example.com", "is_secret": false },
>     { "name": "fullPath", "value": "{{local_var.baseUrl}}/v1/alerts", "is_secret": false }
>   ],
>   "variables_scope": "local"
> }
> ```
>
> ✅ **Right** — two separate actions, each with one variable:
> ```json
> {
>   "name": "Set Base URL",
>   "action_type": "variable",
>   "variables": [
>     { "name": "baseUrl", "value": "https://api.example.com", "is_secret": false }
>   ],
>   "variables_scope": "local"
> }
> ```
> *(connected_to → next action)*
> ```json
> {
>   "name": "Set Full Path",
>   "action_type": "variable",
>   "variables": [
>     { "name": "fullPath", "value": "{{local_var.baseUrl}}/v1/alerts", "is_secret": false }
>   ],
>   "variables_scope": "local"
> }
> ```
>
> **Exception**: grouping multiple variables in a single action is fine when none of their values
> reference each other or any other `local_var` defined in this workflow (e.g., all values are
> literals, trigger fields, or external action outputs).

### Loop (dynamic — iterates over an array)
```json
{
  "type": "loop",
  "tag": "core_action",
  "data": {
    "name": "Loop Items",
    "action_type": "loop",
    "loop_type": "dynamic",
    "number_of_iterations": 5,
    "object_to_iterate": "{{local_var.myArray}}",
    "is_parallel": false
  }
}
```
Current item reference: `{{loop-items.item}}` or `{{loop-items.item.fieldName}}`
Current index: `{{loop-items.index}}`
Connect loop to first inner action using `custom_handle: "inner"`.
Actions inside the loop have `"parent_action": <loop_export_id>`.

### Loop (while — indefinite, until Break)
```json
{
  "type": "loop",
  "tag": "core_action",
  "data": {
    "name": "While Loop",
    "action_type": "loop",
    "loop_type": "while",
    "number_of_iterations": 1,
    "object_to_iterate": null,
    "is_parallel": false
  }
}
```

### Loop (fixed — runs N times)
```json
{
  "type": "loop",
  "tag": "core_action",
  "data": {
    "name": "Fixed Loop",
    "action_type": "loop",
    "loop_type": "fixed",
    "number_of_iterations": 10,
    "object_to_iterate": null,
    "is_parallel": false
  }
}
```

### Condition
See workflow-schema.md for simple vs. multi style details.
```json
{
  "type": "condition",
  "tag": "core_action",
  "data": {
    "name": "Is Success",
    "action_type": "condition",
    "condition_type": "multi",
    "condition": null,
    "conditions": [
      {
        "input_value": "{{my-action.status_code}}",
        "compared_value": "200",
        "comparison_operator": "equals"
      }
    ],
    "conditions_relationship": "and"
  }
}
```
Operators (with usage counts in active corpus):
`"equals"` (1,105), `"not_equals"` (271), `"greater_than_or_equals"` (194), `"greater_than"`
(168), `"contains"` (34), `"in"` (1), `"less_than_or_equals"` (1), `"less_than"` (1).
Also valid but unused in corpus: `"not_contains"`, `"is_empty"`, `"is_not_empty"`.

> **`condition_type` is universally `"multi"`** in active flows (1,697 of 1,697). Always emit
> multi, even for a single comparison.

> **For `comparison_operator: "in"`**, encode `compared_value` as a JSON string of an array
> (e.g. `"[\"HIGH\",\"CRITICAL\"]"`), not a raw array.

### Delay
```json
{
  "type": "delay",
  "tag": "core_action",
  "data": {
    "name": "Delay",
    "action_type": "delay",
    "time_unit": "seconds",
    "value": 20
  }
}
```
`time_unit` options: `"seconds"`, `"minutes"`, `"hours"`

### Break Loop
```json
{
  "type": "break_loop",
  "tag": "core_action",
  "data": {
    "name": "Break Loop",
    "action_type": "break_loop"
  }
}
```
Must have `"parent_action": <loop_export_id>`. `"connected_to": []`.

### Send Email
```json
{
  "type": "send_email",
  "tag": "core_action",
  "data": {
    "name": "Send Email",
    "action_type": "send_email",
    "subject": "Alert: {{singularity-response-trigger.data.name}}",
    "to": ["recipient@example.com"],
    "cc": [],
    "bcc": [],
    "reply_to": [],
    "mime_type": "text/plain",
    "body": "Alert details: {{singularity-response-trigger.data.description}}",
    "attachments": [],
    "continue_on_fail": false
  }
}
```
`mime_type`: `"text/plain"` or `"text/html"`. HTML is more common in active flows (analyst-
friendly tables, embedded SentinelOne logo banner).
For attachments, use the keys **`file_name`** and **`file_content`** (NOT `name`/`content`):
`"attachments": [{"file_name": "report.csv", "file_content": "{{local_var.csvB64}}"}]`.
`file_content` is base64-encoded — `{{Function.BASE64_ENCODE(local_var.csv)}}` for plain text, or
`{{Function.COMPRESS(...)}}` for a zip.

> **Confirmed 2026-06-11 (live import):** using `name`/`content` fails import with
> `422 "Field required"` on `attachments.0.file_name` and `attachments.0.file_content`.
> The send_email attachment object keys are `file_name` and `file_content`.

99% of active flows send to a single recipient. `to` and friends are arrays of strings; each
element can be a literal or a `{{...}}` expression.

### Data Formation
```json
{
  "type": "data_formation",
  "tag": "core_action",
  "data": {
    "name": "Generate UUID",
    "action_type": "data_formation",
    "data": {
      "uuid": "{{Function.SUBSTRING(Function.GENERATE_UUID4(), 6)}}"
    }
  }
}
```
Builds a structured object on the fly without paying for a Variable action. `data` is an
object whose values can be literals or `{{...}}` expressions; reference downstream as
`{{generate-uuid.data.uuid}}`. Real corpus uses include: building Slack channel-config dicts,
shaping note bodies, normalizing event objects before SDL ingest. **75 of 249 data_formation
actions in the corpus are exactly the "Generate UUID" template above**, copy it verbatim
when you need a correlation ID.

### HTTP Request (core — no integration)
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
    "url": "https://raw.githubusercontent.com/example/file.txt",
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
    "proxy_user": null,
    "proxy_password": null,
    "proxy_host": null,
    "proxy_port": null,
    "redirect_follow": true,
    "continue_on_fail": false,
    "body_type": null
  }
}
```
`method` (count in active corpus): `"post"` (1,962), `"get"` (664), `"put"` (55),
`"delete"` (13), `"patch"` (5).
Reference response: `{{action-slug.body}}`, `{{action-slug.status_code}}`,
`{{action-slug.headers}}`.

**Defaults observed in the active corpus** (cargo-cult these unless you have a reason not to):

- `retry_on_status_codes: [500]`: cheap insurance against transient backend hiccups.
- `timeout: 30` (seconds).
- `ssl_verification: true`.
- `redirect_follow: true`.
- `continue_on_fail: false`: let the workflow fail loudly on a bad call.
- `body_type: null` (raw payload string). Set to `"form"`/`"multipart"` if the upstream
  requires `application/x-www-form-urlencoded` or `multipart/form-data`.

### HTTP Request (integration-backed)
Same as above but:
- `"tag": "integration"`
- `"connection_id": null` (set to null for import; user configures)
- `"connection_name": ""`
- `"integration_id": null` (set to null for import)
- `"public_action_id": "<uuid>"` (from the integration's action catalog)
- URL uses `{{Connection.protocol}}{{Connection.url}}/path/to/api`

When generating workflows for import, always set `connection_id`, `connection_name`,
and `integration_id` to null/"" — these are resolved from the user's configured connections.

### URL pattern for integration-backed SentinelOne actions:
```
"url": "{{Connection.protocol}}{{Connection.url}}/web/api/v2.1/<endpoint>"
```

### Snippet
```json
{
  "type": "snippet",
  "tag": "core_action",
  "data": {
    "name": "My Snippet",
    "action_type": "snippet"
  },
  "snippet_workflow_id": null,
  "snippet_version_id": null
}
```
Snippets are reusable groups of actions. Connect using `custom_handle: "inner"`.

### Create Interaction
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
`interaction_type: "choice"` is the only flavor seen in active flows. `options` is the array
of button labels presented to the analyst in the Hyperautomation console; `form_schema` (when
non-null) defines a structured form for free-text/multi-field input.
Reference interaction URLs: `{{create-interaction.interaction_url.<option-name>}}`.
Reference interaction ID: `{{create-interaction.interaction_id}}`.

### Wait for Interaction
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
**Field name trap**: this action uses `identifier` (not `interaction_id`) and `time_value`
(not `value`). Earlier docs got this wrong; the corpus is unambiguous.
`expected_respondents: N` blocks until N analysts have responded; default to 1.

### Wait for Slack
```json
{
  "type": "wait_for_slack",
  "tag": "core_action",
  "data": {
    "name": "Wait for Slack",
    "action_type": "wait_for_slack",
    "message_ts": "{{post-alert.body.ts}}",
    "time_unit": "days",
    "value": 5
  }
}
```
Reference response: `{{wait-for-slack.body}}`, `{{wait-for-slack.timeout}}`,
`{{wait-for-slack.body.actions[0].value}}`

---

## COMMON PATTERNS

### Success/Fail branch pattern (used throughout M365 workflows)
```
Action → Condition (Is Success, checks status_code) → 
  TRUE: Variable (success note) → HTTP (add note)
  FALSE: Variable (fail note) → HTTP (add note)
```

### Add Note to Unified Alert (GraphQL mutation — most common pattern)
```json
{
  "name": "Add Note to Alert",
  "action_type": "http_request",
  "method": "post",
  "url": "{{Connection.protocol}}{{Connection.url}}/web/api/v2.1/unifiedalerts/graphql",
  "payload": "{\n  \"query\": \"mutation AddNoteToAlert($note:String!, $id:String!) { alertTriggerActions(actions:[{ id:\\\"S1/alert/addNote\\\", payload:{ note:{ value:$note }}}], filter:{ or:[{ and:[{ fieldId:\\\"id\\\", stringEqual:{ value:$id } }]}]}) { ... on ActionsTriggered { actions { actionId } } } }\",\n  \"variables\": {\n    \"id\": \"{{singularity-response-trigger.data.id}}\",\n    \"note\": \"{{local_var.note_markdown}}\"\n  }\n}"
}
```

### SDL Query (AI SIEM Singularity Data Lake)
```json
{
  "method": "post",
  "url": "{{Connection.protocol}}{{Connection.url}}/sdl/api/query",
  "payload": "{\n  \"filter\": \"dataSource.name = 'indicator' and metadata.uid = '{{singularity-response-trigger.data.indicators[0].id}}'\",\n  \"startTime\": \"{{singularity-response-trigger.data.indicators[0].eventTime}}\",\n  \"endTime\": \"{{Function.DELTA(singularity-response-trigger.data.indicators[0].eventTime,-0.1)}}\"\n}"
}
```

### PowerQuery (SDL Power Query)
```json
{
  "method": "post",
  "url": "{{Connection.protocol}}{{Connection.url}}/sdl/api/powerQuery",
  "payload": "{\n  \"query\": \"endpoint.name = '{{local_var.hostname}}' | group count() by event.type\",\n  \"startTime\": \"24h\"\n}"
}
```

### TI Ingestion (Threat Intelligence IOC)
```json
{
  "method": "post",
  "url": "{{Connection.protocol}}{{Connection.url}}/web/api/v2.1/threat-intelligence/iocs",
  "payload": "{\n  \"filter\": { \"siteIds\": [\"<your-site-id>\"] },\n  \"data\": [{\n    \"type\": \"IPV4\",\n    \"validUntil\": \"{{Function.DELTA_NOW(-72)}}\",\n    \"description\": \"TOR exit node\",\n    \"method\": \"EQUALS\",\n    \"creationTime\": \"{{Function.DATETIME_NOW()}}\",\n    \"externalId\": \"OSINT\",\n    \"value\": \"{{loop.item}}\",\n    \"originalRiskScore\": \"50\",\n    \"severity\": \"5\",\n    \"source\": \"My TI Library\",\n    \"name\": \"TOR Node Indicator\"\n  }]\n}"
}
```
