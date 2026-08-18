# Validation Rules

Run this checklist before outputting any workflow JSON.

---

## Structural rules

- [ ] Top-level keys are exactly: `"name"`, `"description"`, `"actions"`
- [ ] Every action has: `"action"`, `"export_id"`, `"connected_to"`, `"parent_action"`
- [ ] `export_id` values are unique integers across all actions in the workflow
- [ ] No two actions share the same `export_id`
- [ ] Every `target` in `connected_to` references a valid `export_id` in the workflow
- [ ] Every `parent_action` (when non-null) references a valid loop `export_id`

## Action type rules

- [ ] `"type"` matches `"action_type"` in the data object
- [ ] `"tag"` is `"core_action"` for built-in actions, `"integration"` for integration-backed
- [ ] `"state"` is `"active"` (not `"draft"` or `"inactive"`)
- [ ] `"snippet_workflow_id"` and `"snippet_version_id"` are `null` unless action is a snippet referencing another workflow

## Trigger rules

- [ ] Exactly one trigger action per workflow (first in execution order)
- [ ] Trigger has `"parent_action": null`
- [ ] Trigger's `connected_to` points to the first action in the flow
- [ ] `singularity_response_trigger`: `filter_groups` is a non-empty array
- [ ] `singularity_response_trigger`: each filter_group has `event_type`, `event_subtypes`, `condition`, `is_disabled`, `run_automatically`
- [ ] `manual_trigger`: `trigger_type` is `"static"` or `"dynamic"`; if dynamic, `dynamic_properties` is a non-empty object

## Loop rules

- [ ] Loop connects to its first inner action using `"custom_handle": "inner"`
- [ ] All actions inside the loop have `"parent_action": <loop_export_id>`
- [ ] Actions outside the loop have `"parent_action": null`
- [ ] `break_loop` actions inside a loop have `"connected_to": []`
- [ ] `loop_type: "dynamic"` always has a non-null `object_to_iterate`
- [ ] `loop_type: "while"` or `"fixed"` has `object_to_iterate: null`
- [ ] In a `while` loop, the terminating condition has ONLY a `"true"` → `break_loop` edge. Do NOT
  add a `"false"` back-edge to an earlier inner action, the loop re-runs the inner block on its
  own, and a manual back-edge makes import fail with `422 "Invalid workflow data"`.

## Condition rules

- [ ] Condition uses either `"condition_type": "simple"` (with nested `condition` object) or `"condition_type": "multi"` (with flat `conditions` array): not both
- [ ] For `"simple"`: `"condition"` is non-null, `"conditions"` is `null`
- [ ] For `"multi"`: `"conditions"` is a non-empty array, `"condition"` is `null`
- [ ] Condition branches use `"custom_handle": "true"` and `"custom_handle": "false"`
- [ ] A condition with only one branch (e.g., only `"true"`) is valid: the other is simply absent from `connected_to`
- [ ] **Approval / human-in-the-loop gates FAIL CLOSED.** A condition that guards a destructive action
  (block, isolate, disable) must test for the explicit approval value, e.g.
  `{{wait-for-slack.body.actions[0].value}} equals "approved"`; NEVER `not_equals "dismissed"`. On a
  Slack (or any `wait_for_interaction`) timeout the value resolves to empty, and empty is
  `!= "dismissed"`, so a fail-open `not_equals` gate would auto-run the destructive action with no
  approval. Route the destructive action off the `"true"` branch of an `equals` test only.

## Interaction form rules

Full detail in `interaction-forms.md`.

- [ ] **Every OPTIONAL form field is read through `Function.DEFAULT`.** A blank optional field is
  **absent from `response.result` entirely**, not present-and-null, and a bare reference to an
  absent attribute ERRORS the whole run ("Attribute not found in Action"). It does not resolve to
  empty. This is the same failure class as bare LRQ poll counters.

  ❌ Wrong, kills the run the first time a respondent skips the field:

  ```json
  {"name": "window_time", "value": "{{wait-for-approval.response.result.window_start_time}}"}
  ```

  ✅ Right:

  ```json
  {"name": "window_time",
   "value": "{{Function.DEFAULT(wait-for-approval.response.result.window_start_time, \"not provided\")}}"}
  ```

  Required fields are guaranteed present by form validation and may be referenced directly.
- [ ] `create_interaction` with `interaction_type: "form"` has a non-empty `form_schema`, and a
  paired `wait_for_interaction` whose `identifier` references its `interaction_id`. Activation
  rejects an unpaired Create; import does not.
- [ ] `interaction_type` is lowercase `"form"` in JSON. `"Form"` is the output display value.
- [ ] A form action carries at least one entry in `options` so the console enables **Test Action**
  (runtime does not need them, the UI does).
- [ ] Form approval gates FAIL CLOSED like any other: test `approve equals "true"` AND
  `timeout equals "false"`, never `not_equals`.

## Markdown-into-email rule

- [ ] **Never render a markdown-bearing field directly into an HTML email or Slack message.**
  Purple AI's `aiInvestigations[].result` is a full markdown report; email clients do not render
  markdown, so it arrives as one unbroken wall of `##`, `**` and `-` characters. Pass it through an
  `llm` action that emits the target format (HTML list items for email, Slack markdown for Slack),
  and keep the raw field only for the audit trail. See `autonomous-soc-template.md`.

## Import / `parent_action` rules

- [ ] **`parent_action` is for LOOP membership ONLY**: it is `null` on every node that is not inside a
  loop; flow order is expressed **strictly** via `connected_to.target`, never via `parent_action`.
  Setting `parent_action` to a previous (non-loop) node's `export_id` is the #1 cause of an import
  `422 "Invalid workflow data"` even when every field otherwise looks correct.
- [ ] `export_id` values are arbitrary unique integers: they need not be sequential or positional (a
  real export uses ids like `9, 8, 5, 6`).
- [ ] `variable` action `data` carries its full field set: `variables_scope`, `expire_*`, `global_var_*`
  (in addition to the `variables` array).
- [ ] `manual_trigger` action `data` carries `trigger_type`, `dynamic_properties`, and `static_payload`.
- [ ] Fastest way to debug a persistent `422`: round-trip a live `export?ids=all` workflow member (which
  is guaranteed valid), then bisect, swap your nodes into the known-good envelope one at a time until
  the import breaks.

## Variable rules

- [ ] Each variable in `variables` array has `"name"`, `"value"`, `"is_secret"`
- [ ] Empty array initialization: value is `"[]"` (two brackets, no spaces)
- [ ] `variables_scope` is `"local"` or `"global"`
- [ ] Dynamic references use `{{...}}` double curly braces
- [ ] **HARD RULE**: if a variable's value contains `{{local_var.*}}`, that variable must be in
  its own dedicated Variable action, a single action must never define a variable whose value
  references another `local_var` set in the same action's `variables` array. Variables in one
  action are evaluated simultaneously, not sequentially, so forward/same-action references
  silently resolve to empty.

  ❌ Wrong: `fullPath` will be empty because `baseUrl` is resolved in the same pass:

  ```json
  { "variables": [
      { "name": "baseUrl",  "value": "https://api.example.com" },
      { "name": "fullPath", "value": "{{local_var.baseUrl}}/v1/alerts" }
  ]}
  ```

  ✅ Right: split into two sequential Variable actions:

  ```json
  // Action 1
  { "variables": [{ "name": "baseUrl",  "value": "https://api.example.com" }] }
  // Action 2 (connected after Action 1)
  { "variables": [{ "name": "fullPath", "value": "{{local_var.baseUrl}}/v1/alerts" }] }
  ```

## Integration rules

- [ ] Integration-backed actions have `"tag": "integration"`
- [ ] For import-ready JSON: `connection_id: null`, `connection_name: ""`, `integration_id: null`
- [ ] Integration URLs use `{{Connection.protocol}}{{Connection.url}}/path`
- [ ] **WARN THE USER** which integrations need to be pre-configured in the console

## Function syntax rules

- [ ] All functions use `{{Function.FUNCTION_NAME(args)}}`: capital F, capital function name
- [ ] Nested functions are valid: `{{Function.STRING(Function.MUL(42, Function.DATETIME_TO_MS(Function.DATETIME_NOW())))}}`
- [ ] JQ filter strings with double quotes inside must be escaped: `\"`
- [ ] `Function.COMPRESS` requires its files array in square brackets: `[local_var.myFile]`
- [ ] `Function.BASE64_DECODE_AS_BYTES` is used (not `BASE64_DECODE`) for COMPRESS input

## Common mistakes to avoid

- ❌ Defining multiple variables that reference each other in a single Variable action; they
  resolve simultaneously, so the reference will be empty. Split them into separate actions.
  ✅ One Variable action per variable whenever `{{local_var.*}}` appears in the value.
- ❌ Using `{{loop.item}}` inside a loop: use the action's slug: `{{loop-action-name.item}}`
  ✅ e.g., `{{loop-the-list-of-ipv4.item}}` for a loop named "Loop the list of IPv4"
- ❌ Referencing an action by its `export_id`: always use the slugified `name` field
- ❌ Setting `parent_action` on actions that are outside the loop
- ❌ Using `"custom_handle": "inner"` for anything other than the loop's first inner action
- ❌ Forgetting that action slug = name lowercased, spaces→hyphens, special chars dropped
- ❌ Setting `break_loop` with `connected_to` entries: it must always be `[]`
- ❌ Having a Singularity Response Trigger with empty `filter_groups` array
- ❌ Generating `connection_id` UUIDs: always use `null` for import-ready JSON
- ❌ Using `Function.JQ` with complex expressions directly: store in Variable first
- ❌ Mixing `condition` and `conditions` in the same condition action data object
- ❌ `send_email` attachments with `name`/`content` keys: the importer requires `file_name` and
  `file_content` (import `422 "Field required"` otherwise). `file_content` is base64.
- ❌ Wiring a `while`-loop condition's `false` branch back into the loop body: omit it (see Loop rules)
