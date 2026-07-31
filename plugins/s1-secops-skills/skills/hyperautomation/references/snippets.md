# Snippets — reusable sub-workflows

A snippet is a workflow you call from other workflows. Use snippets to factor any reusable
slice of logic (isolate a device, quarantine a threat, open a ticket, poll until an investigation
completes, notify the SOC) into one versioned block that many workflows share.

## What makes a workflow a snippet

A snippet is a workflow flagged `is_snippet=true`, but **what makes it a snippet is its NODES,
not a flag in the create body.** It contains a `snippet_trigger` (its input contract) and a
`snippet_output` (its return contract) in place of an ordinary trigger. The import endpoint ignores
an explicit `is_snippet` field — include the `snippet_trigger` + `snippet_output` nodes and the
platform treats the workflow as a snippet automatically.

## Authoring a snippet

Three kinds of node:

1. **`snippet_trigger`** — the input contract. `data.action_type: "snippet_trigger"`,
   `data.name: "Snippet Input"`, and `data.dynamic_properties` declares each input:

   ```json
   "dynamic_properties": {
     "Singularity-ID": {"title": "", "description": "Alert id.", "index": 0},
     "Alert-Input":    {"title": "", "description": "Alert summary.", "index": 1}
   }
   ```

   Body actions read an input as `{{snippet-input.<Param>}}` (the slug of "Snippet Input").
   Hyphenated params are fine: `{{snippet-input.Singularity-ID}}`.

2. **Body actions** — any normal actions (`http_request`, `llm`, `condition`, `loop`,
   `send_email`, …). Same shapes as in a regular workflow.

3. **`snippet_output`** — the return contract. `data.action_type: "snippet_output"`, and
   `data.output` maps output names to values:

   ```json
   "output": {"Isolated": "{{disconnect-endpoint.status}}"}
   ```

### Authoring rules (import returns `422 "Invalid workflow data"` and names no field — check these)

- **`export_id 0` must belong to a real body action, not the `snippet_trigger`.** Assigning the
  trigger `export_id 0` fails import. Convention: body action = `0`, `snippet_trigger` = `1`,
  `snippet_output` = `2`; wire `trigger → body → output` via `connected_to.target`.
- **`snippet_output` values must be non-empty.** A bare `{{slug.}}` (trailing dot, empty field)
  imports but the snippet is invalid at runtime. Use a real `{{slug.field}}` the node actually
  emits, or a literal string (e.g. `"done"`). `send_email` does not emit a `.status` field.
- **The workflow name must not contain parentheses `()`** — import fails. Names must be unique
  among live workflows (a collision also returns `422`).
- Every node inside a loop sets `parent_action` = the loop's `export_id` (see the loop pattern
  in `autonomous-soc-template.md`).

## Calling a snippet — static

A parent workflow calls a snippet with a **`snippet_20`** node. Do NOT use type `"snippet"`, and do
NOT embed the snippet's inner actions into the parent (embedding produces an orphaned node on the
canvas):

```json
{
  "type": "snippet_20", "tag": "core_action",
  "snippet_workflow_id": "<snippet id>", "snippet_version_id": "<pinned version>",
  "data": {
    "name": "Isolate Device", "action_type": "snippet_20",
    "inputs": "{\"Singularity-ID\":\"{{singularity-response-trigger.data.id}}\"}",
    "use_latest_snippet_version": false, "is_dynamic": false,
    "dynamic_snippet_name": "Isolate Device"
  }
}
```

- `data.inputs` is a **JSON string** mapping the snippet's input-param names to mustache
  references from the parent.
- `use_latest_snippet_version: true` tracks the snippet's newest published version automatically;
  `false` pins `snippet_version_id`.
- Resolve a workflow's snippet bindings with
  `GET /workflow-actions/snippets-versions/{workflowId}/{versionId}?query={}`.

## Calling a snippet — dynamic (runtime dispatch)

Set `is_dynamic: true` and make `dynamic_snippet_name` a **mustache expression that resolves to a
snippet name at runtime**. The node dispatches to whichever snippet matches that name:

```json
"data": {
  "name": "Response", "action_type": "snippet_20",
  "inputs": "{\"Singularity-ID\":\"{{...}}\",\"Alert-Input\":\"{{...}}\"}",
  "use_latest_snippet_version": false, "is_dynamic": true,
  "dynamic_snippet_name": "{{response-decision.data}}"
}
```

An upstream LLM (or condition) emits one of several snippet names; the dynamic `snippet_20` routes
to it. For this to work, **every candidate snippet must share one input contract** (identical
`snippet_trigger` `dynamic_properties`) so the same `inputs` map satisfies any of them. This is how
an autonomous responder picks Isolate vs Quarantine vs Close-as-FP at runtime — see
`autonomous-soc-template.md`.

## Lifecycle (API)

Snippets ride the `/workflows` API. Scope every call with `siteIds=<id>` **or** `accountIds=<acct>`
to match where the snippet lives (a site snippet also appears in that account's list).

- **Create** — import a workflow that contains `snippet_trigger` + `snippet_output`:
  `POST /workflow-import-export/import?<scope>` with `{"data": <workflow>}`. (The console UI's
  own create is `POST /workflows` with an `actions_create[]` seeding those two nodes; import is
  equivalent and is what to use programmatically.)
- **Publish** — `POST /v1/workflows/{id}/publish?<scope>` (bodyless, `204`).
- **Activate** — `POST /workflows/{id}/{versionId}/activation?<scope>` with body
  `{"data": {"version_description": "", "dimensions": {"x":0,"y":0,"width":256,"height":100}}}` (`204`).
- **List** — `GET /v1/workflows?is_snippet=true&<scope>`.
- **Deactivate** — `POST /v1/workflows/{id}/{versionId}/deactivate?<scope>` (`204`). A snippet can
  carry MULTIPLE active versions; deactivate EACH version before deleting.
- **Delete (archive)** — `POST /v1/workflows/archive` with
  `{"data": {"workflow_ids": [id]}, "filter": {<scope>}}` (`200`). The filter scope must MATCH the
  object's scope: for an account-scoped snippet the filter must be `accountIds`-only — adding
  `siteIds` returns `404 "Object not found"`. A snippet still referenced by a workflow cannot be
  archived (`400 "Active workflows cannot be archived"` / reference guard); archive or unbind the
  referencing workflow first.
