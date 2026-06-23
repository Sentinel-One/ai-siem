# Workflow JSON Schema Reference

## Top-level envelope

Every workflow JSON has exactly this structure:

```json
{
  "name": "Human-readable workflow name",
  "description": "Optional description of what the workflow does",
  "actions": [ /* array of action objects */ ]
}
```

---

## Action object structure

Every item in the `actions` array is an **action object**:

```json
{
  "action": {
    "type": "<action_type>",
    "tag": "core_action" | "integration",
    "connection_id": null | "<uuid>",
    "connection_name": null | "",
    "use_connection_name": false,
    "integration_id": null | "<uuid>",
    "data": { /* action-type-specific payload — see building-blocks.md */ },
    "state": "active",
    "description": null | "human description",
    "client_data": {
      "position": { "x": 0.0, "y": 0.0 },
      "dimensions": { "width": 256.0, "height": 76.0 },
      "collapsed": false
    },
    "snippet_workflow_id": null,
    "snippet_version_id": null
  },
  "export_id": <integer>,
  "connected_to": [
    { "target": <integer>, "custom_handle": null | "true" | "false" | "inner" }
  ],
  "parent_action": null | <integer>
}
```

---

## Key fields explained

### `export_id`
A unique integer within the workflow, used as the node ID in the graph.
Assign sequentially: 0, 1, 2, 3... starting from the LAST action (the terminal node gets 0).
The trigger typically gets the highest export_id.

### `connected_to`
Defines edges (connections) to downstream actions.
- `target`: the `export_id` of the next action
- `custom_handle`:
  - `null` — default (only one outgoing connection)
  - `"true"` / `"false"` — condition branches
  - `"inner"` — used for the body of a loop (the first action inside the loop)

### `parent_action`
- `null` — action is at the top level of the workflow
- `<integer>` — `export_id` of the loop that contains this action

### `tag`
- `"core_action"` — built-in actions (Variable, Loop, Condition, HTTP Request without integration,
  Send Email, Delay, Break Loop, Scheduled/Manual/HTTP/Email/Singularity Trigger, Snippet,
  Wait for Slack, Create Interaction, Wait for Interaction)
- `"integration"` — actions backed by a pre-configured integration connection

### `connection_id` / `connection_name` / `use_connection_name`
- For core actions: all null/false
- For integration actions: `connection_id` is the UUID of the configured connection.
  When generating for import, set `connection_id: null`, `connection_name: ""`,
  `use_connection_name: false` — the user will configure the connection after import.

### `integration_id`
- For core actions: `null`
- For integration actions: the UUID of the integration type (e.g., SentinelOne = `"ef645af9-ed60-4efd-882e-bf534442ce86"`, M365/Entra = `"73475bd9-3762-4f17-aab5-c544ec5ec31b"`)
  When generating for a new workflow, set to `null` — it will be resolved from the connection.

---

## Position / layout (client_data)

Position fields affect the visual canvas only. Use these conventions for readability:
- First action (trigger): `{ "x": 0, "y": 0 }`
- Each subsequent step: increment `y` by ~177 (height 76 + gap 101)
- Parallel branches: offset `x` by ±160–300

Standard dimensions: `{ "width": 256, "height": 76 }` for most actions.
Triggers: `{ "width": 256, "height": 100 }`.
Loop containers: wider/taller to contain children — `{ "width": 760, "height": 750 }` typical.

---

## Dynamic variable reference syntax

Reference values from previous actions using double curly braces:
```
{{action-slug.field.subfield}}
{{action-slug.body.data[0].computerName}}
{{action-slug.status_code}}
{{loop.item}}
{{loop.item.fieldName}}
{{loop.index}}
{{local_var.variableName}}
{{global_var.variableName}}
{{Function.FUNCTION_NAME(args)}}
{{Connection.protocol}}
{{Connection.url}}
```

Action slug = name field, lowercased, spaces → hyphens.
Example: `"name": "Get Agents with Active Threat"` → `get-agents-with-active-threat`

---

## Singularity Response Trigger — filter_groups structure

```json
"filter_groups": [
  {
    "condition": {
      "operator": "and",
      "conditions": [
        {
          "input_value": "detectionSource.product",
          "compared_value": "EDR",
          "comparison_operator": "equals"
        }
      ]
    },
    "is_disabled": false,
    "run_automatically": false,
    "event_type": "alert",
    "event_subtypes": ["CREATE"]
  }
]
```

Multiple filter_groups = OR logic between groups.
Conditions within a group use the `operator` field ("and" or "or").

`run_automatically: true` = workflow fires automatically on matching events.
`run_automatically: false` = workflow appears as on-demand option in alert UI.

Common `input_value` field names: `"detectionSource.product"`, `"severity"`, `"name"`,
`"status"`, `"analytics.category"`

Common `comparison_operator` values: `"equals"`, `"not_equals"`, `"contains"`,
`"not_contains"`, `"in"`, `"greater_than"`, `"greater_than_or_equals"`

For `"in"` operator, `compared_value` is a JSON array string: `"[\"HIGH\",\"CRITICAL\"]"`

---

## Condition action — two styles

### Simple condition (nested `condition` object, `condition_type: "simple"`):
```json
"condition_type": "simple",
"condition": {
  "operator": "and",
  "conditions": [
    {
      "operator": "or",
      "conditions": [
        {
          "input_value": "{{disable-user-account.status_code}}",
          "compared_value": "200",
          "comparison_operator": "equals"
        },
        {
          "input_value": "{{disable-user-account.status_code}}",
          "compared_value": "204",
          "comparison_operator": "equals"
        }
      ]
    }
  ]
},
"conditions": null
```

### Multi condition (flat `conditions` array, `condition_type: "multi"`):
```json
"condition_type": "multi",
"condition": null,
"conditions": [
  {
    "input_value": "{{local_var.alert-hash}}",
    "compared_value": "no-hash",
    "comparison_operator": "not_equals"
  }
],
"conditions_relationship": "and"
```

A condition action connects to downstream actions using `custom_handle: "true"` and `custom_handle: "false"`.
Unconnected branches (e.g., a false branch that does nothing) are simply omitted from `connected_to`.
