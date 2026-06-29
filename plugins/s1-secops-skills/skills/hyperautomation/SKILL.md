---
name: hyperautomation
description: >
  Use this skill whenever a user wants to create, design, build, generate, write, or export a
  SentinelOne Hyperautomation workflow in JSON format. Triggers include: any mention of
  "Hyperautomation", "workflow", "automation", "SOAR", "playbook", "alert response", "trigger",
  "scheduled workflow", "webhook workflow", or any request to automate a SentinelOne-related
  security task. Also triggers when the user asks to import, export, test, validate, or submit
  a workflow to a SentinelOne console via API. Always use this skill for any task involving
  SentinelOne workflow JSON — even if phrased casually (e.g., "build me a thing that disables
  a user when an alert fires"). When in doubt about whether this skill applies, use it.
---

# SentinelOne Hyperautomation Skill

This skill enables Claude to design and generate valid SentinelOne Hyperautomation workflow
JSON, explain the logic behind workflows, and optionally submit them to a live console via API.

> **Sandbox proxy blocked?** If import/export API calls to `*.sentinelone.net` fail with a connection or proxy error inside the Claude sandbox, use the `s1-secops-mcp` server instead. It runs locally via `node` and bypasses the sandbox proxy entirely. Setup: add it to `claude_desktop_config.json` (see `s1-secops-mcp/README.md`). The MCP server exposes `ha_list_workflows`, `ha_get_workflow`, `ha_import_workflow`, and `ha_export_workflow` — all running from your machine against the Hyperautomation API.

## Minimum viable workflow JSON (smoke test)

Before building production workflows, validate your token + scope using the
smallest payload the `/import` endpoint accepts: a manual trigger with no
inputs. Use this to confirm the API path works end-to-end (import → activate)
before iterating on real action graphs.

```json
{
  "data": {
    "name": "minimal-smoke-test",
    "description": "validates the import path",
    "actions": [
      {
        "action": {
          "client_data": {
            "collapsed": false,
            "dimensions": { "height": 76.0, "width": 256.0 },
            "position": { "x": 286.0, "y": -29.0 }
          },
          "connection_id": null,
          "connection_name": null,
          "data": {
            "action_type": "manual_trigger",
            "dynamic_properties": {},
            "name": "Manual Trigger",
            "static_payload": "{}",
            "trigger_type": "dynamic"
          },
          "description": null,
          "integration_id": null,
          "tag": "core_action",
          "type": "manual_trigger",
          "use_connection_name": false
        },
        "connected_to": [],
        "export_id": 0,
        "parent_action": null
      }
    ]
  }
}
```

Notes:
- `dynamic_properties: {}` is valid — the manual-trigger node renders with no input fields.
- **Import is not complete until published: treat create/import and publish as ONE atomic step, publish in the SAME step, never as a follow-up. ALWAYS publish a newly created or imported workflow to a Shared Draft.** A workflow created or imported via the API lands as a **Private Draft owned by the API token's user** (for example, the service user), so it is invisible in the console to the human who requested it. Immediately after a successful import, publish it: `POST /hyper-automate/api/v1/workflows/{workflow_id}/publish?accountIds=<acct>` (bodyless `{}`, returns 204; state stays `inactive`, meaning shared but not running). Use `siteIds=<id>` for a site-scoped workflow. See `references/api-integration.md` section 8a. Skip this only when you are activating the workflow, since activation auto-publishes. You can only publish a draft owned by the token's user; publishing another user's private draft returns 403 "Workflow can't be published".
- Activate the imported workflow with
  `POST /workflows/{workflow_id}/{version_id}/activation?siteIds=<id>` (returns 204).
- Don't forget the scope param: see `references/api-integration.md` for the
  `siteIds=` pitfall (the wrong shape returns 403 "Insufficient permissions"
  that looks like a missing role).

## How to use this skill

When a user asks to build a workflow, follow this process:

### Step 1 — Understand the intent
Ask (or infer from context):
- What should trigger the workflow? (alert, schedule, webhook, manual, email)
- What integrations are needed? (SentinelOne, M365, Slack, VirusTotal, etc.)
- What is the desired outcome? (enrich alert, disable user, send notification, etc.)
- Should the workflow run automatically or on-demand?

### Step 2 — Warn about integrations
**CRITICAL**: Before generating JSON, identify any integration-backed actions (tag = "integration").
These require pre-configured connections in the console that CANNOT be created via API.
Always tell the user: *"This workflow uses the [X, Y, Z] integrations. Before importing, you must
configure connections for these in your Hyperautomation → Integrations section."*

Integration-backed actions have `"tag": "integration"` and a non-null `integration_id`.
Core actions (Variable, Loop, Condition, Delay, Send Email, HTTP Request without integration,
Break Loop, Snippet, Wait for Slack, Create Interaction) have `"tag": "core_action"`.

### Step 3 — Generate the JSON
Read `references/workflow-schema.md` to produce a valid workflow JSON.
Read `references/building-blocks.md` for the correct action type structures.
Read `references/functions-reference.md` for available functions and their syntax.

### Step 4 — Validate before outputting
Self-check against `references/validation-rules.md` before presenting the workflow.

### Step 5 — API submission (optional)
If the user wants to submit to a live console, read `references/api-integration.md`.

**Credentials**: The plugin's SessionStart hook auto-discovers a `credentials.json`
dropped directly into the user's Cowork project folder at the start of every session.
If the file is missing, ask the user to drop a `credentials.json` into their project folder.

Resolution priority (highest wins):

1. Environment variables `S1_CONSOLE_URL` / `S1_CONSOLE_API_TOKEN`
2. `<project folder>/credentials.json` (auto-discovered)
3. Ask the user to provide their console URL and personal Console User API token

To read credentials in Python:
```python
import json, os
from pathlib import Path
_creds = {}
for candidate in (
    Path.home() / ".claude" / "sentinelone" / "credentials.json",
    Path(os.environ.get("COWORK_WORKSPACE", "")) / ".sentinelone" / "credentials.json"
        if os.environ.get("COWORK_WORKSPACE") else None,
    Path(os.environ.get("CLAUDE_CONFIG_DIR", "")) / "sentinelone" / "credentials.json"
        if os.environ.get("CLAUDE_CONFIG_DIR") else None,
    Path.home() / ".config" / "sentinelone" / "credentials.json",
):
    if candidate and candidate.is_file():
        _creds = json.loads(candidate.read_text())
        break
S1_CONSOLE_URL  = os.environ.get("S1_CONSOLE_URL")  or _creds.get("S1_CONSOLE_URL")  or None
S1_CONSOLE_API_TOKEN = os.environ.get("S1_CONSOLE_API_TOKEN") or _creds.get("S1_CONSOLE_API_TOKEN") or None
```

Once resolved, validate them using the two-step test in `references/api-integration.md`
(system health check + token permission check). Only proceed with import/trigger/activate
after both checks pass. Always use a personal Console User API token, not a Service User
token — see `references/api-integration.md` for the reason.

### Step 6: Publish so the requester can see it (REQUIRED after any API import)
A workflow imported or created via the API is a **Private Draft owned by the token's user** and is not visible to anyone else in the console, including the person who asked for it. Treat import and publish as ONE atomic step (an import is not complete until it is a Shared Draft; publish in the same step, never a follow-up). After a successful import, ALWAYS publish it to a **Shared Draft**:
`POST /hyper-automate/api/v1/workflows/{workflow_id}/publish?accountIds=<acct>` (bodyless `{}`, returns 204). The workflow stays `inactive` (shared but not running). Use `siteIds=<id>` for a site-scoped workflow. Skip this step only when you are activating the workflow, since activation publishes automatically. See `references/api-integration.md` section 8a.

---

## Reference files — when to read each

| File | Read when... |
|------|-------------|
| `references/workflow-schema.md` | Always when generating JSON — defines the envelope and action structure |
| `references/building-blocks.md` | Need the exact shape of a specific action type (trigger, loop, condition, etc.) |
| `references/building-blocks-catalog.md` | **Picking what to use** for a given step / composing multi-action idioms / bootstrapping a SOAR recipe. Mined from 643 active production workflows. Read FIRST when designing a new workflow. |
| `references/functions-reference.md` | Using `{{Function.X()}}` syntax or PowerQuery patterns |
| `references/validation-rules.md` | Before outputting any workflow — run the checklist |
| `references/api-integration.md` | User wants to import/export/submit to a live console |

## Decision guide: pick the right pattern by use case

The catalog (`references/building-blocks-catalog.md`) names every reusable block. Use this
table to jump straight to the right starting point:

| User says... | Start with | Composite patterns to layer on |
|--------------|-----------|--------------------------------|
| "When an alert fires, do X" | A1 (Singularity Response Trigger) + recipe C1 | B1 safe-field DEFAULT chain, B2 success/fail branch, B6 add-note |
| "Every day / every N hours, do X" | A3 (Scheduled Trigger) + recipe C2 | B7 SDL ingest, B9 IOC create, B5 JQ shaping |
| "When a webhook hits, do X" | A4 (HTTP Trigger) + recipe C3 | B2 status-code branch, B11 Slack ack |
| "Let an analyst kick this off with parameters" | A2 dynamic Manual Trigger + recipe C4 | B5 JQ shaping, B4 APPEND accumulator |
| "Wait for analyst approval before remediating" | recipe C5 (Slack approval) | B11 Slack interactive, B6 add-note |
| "Periodic posture / UEBA report" | A3 + recipe C6 | B8 PowerQuery, B7 SDL ingest |
| "Page through a paginated API" | B3 (cursor + break_loop) | B4 APPEND accumulator |
| "Summarize this evidence with an LLM" | B12 (OpenAI) | B6 add-note |
| "Create a Threat Intelligence indicator" | B9 (TI IOC create) | B4 accumulator inside loop |
| "Add a note on the alert" | B6 (UAM GraphQL addAlertNote) | always wrap text in `Function.HTML_ENCODE` |

When in doubt, the load-bearing 17 atoms are:
`http_request`, `variable`, `condition`, `loop`, `singularity_response_trigger`,
`data_formation`, `send_email`, `snippet`, `break_loop`, `manual_trigger`, `wait_for_slack`,
`delay`, `http_trigger`, `scheduled_trigger`, `create_interaction`, `wait_for_interaction`,
`email_trigger`. Anything outside this set is exotic; confirm it exists before generating.

## Example workflows (in references/examples/)
Annotated real examples to use as structural references:
- `simple-linear.md` — simple trigger → action → note pattern
- `branching.md` — condition with true/false branches + success/fail notes
- `loop-pattern.md` — loop with APPEND and BREAK logic
- `integration-pattern.md` — integration-backed HTTP request with connection placeholders

---

## Quick reference — action name → slugified reference

When referencing a previous action in `{{...}}` syntax, use the kebab-case version of the
action's `name` field. Examples:
- Action named "Get Agents with Active Threat" → `{{get-agents-with-active-threat.body.data}}`
- Action named "SDL Query" → `{{sdl-query.body.matches[0].attributes.actor_user_email_addr}}`
- Action named "Singularity Response Trigger" → `{{singularity-response-trigger.data.id}}`
- Action named "Loop the list of IPv4" → `{{loop-the-list-of-ipv4.item}}`

The rule: lowercase, spaces become hyphens, special characters dropped.

---

## Integration warning template

Use this when the workflow contains integration-backed actions:

> ⚠️ **Pre-requisite integrations to configure before importing:**
> - **[Integration Name]** — used for [action name(s)]. Configure at Hyperautomation → Integrations → [Integration Name] → Add Connection.
> - *(repeat for each)*
>
> Once configured, note the connection name — you may need to update the `connection_name` field in the JSON before importing.

---

## Common mistakes to avoid

- ❌ Defining multiple variables in a single Variable action when one references another — they evaluate simultaneously and will fail with "variable not found"
  ✅ Always use one Variable action per variable when chaining references. One var → one action, always.
- ❌ Forgetting `Function.HTML_ENCODE` on note text passed to UAM GraphQL. Any quote, ampersand, or angle bracket breaks the mutation string.
  ✅ Always wrap: `\\\"{{Function.HTML_ENCODE(local_var.note)}}\\\"`.
- ❌ Encoding `compared_value` for `comparison_operator: "in"` as a raw JSON array.
  ✅ JSON-string-encode it: `"[\"HIGH\",\"CRITICAL\"]"`.
- ❌ `condition_type: "simple"`: never used in active corpus. Always emit `"multi"`.
- ❌ `wait_for_interaction` using `interaction_id` / `value` field names (older docs).
  ✅ Real fields are `identifier` / `time_value`.
- ❌ Hard-coding site IDs in TI IOC creates: breaks on tenant transfer.
  ✅ Pull from a Variable, Manual Trigger param, or `singularity-response-trigger.data.scopeId`.
- ❌ Importing with a Service User token: workflows become invisible to humans in the UI.
  ✅ Always use a personal Console User API token for `S1_CONSOLE_API_TOKEN`.
- ❌ Running an SDL PowerQuery (LRQ / `datasource` / `savelookup`) from an HTTP action bound to the **"SentinelOne"** mgmt connection. That connection signs as `Authorization: ApiToken`, but the SDL query endpoints (`POST /sdl/v2/api/queries` and `POST {sdl-host}/api/powerQuery`) require `Bearer`, so the action returns `HTTP 500 "Header must start with Bearer"`.
  ✅ Bind the **"SentinelOne SDL"** connection (Bearer by default) on the HTTP action. Notes: the ApiToken-only `/web/api/v2.1/dv/events/pq` cannot run the `datasource` command (returns 400) and is just an async wrapper over LRQ, so it is not usable for asset/inventory refresh; ## Running an SDL LRQ from an HA flow (async launch + POLL LOOP) — tenant-validated 2026-06-25

`POST /sdl/v2/api/queries` is ASYNC. The launch response is NOT the results: it returns `body.id`
plus `body.stepsCompleted` / `body.totalSteps`, and `body.data` is `null` while the query is still
running. The query id is also EPHEMERAL: it expires shortly after the query finishes. So a fixed
wait fails BOTH ways: too short returns `data: null` (still running); too long returns HTTP 404
"query id not found" (the id expired, and the downstream reference then resolves to
`UnresolvedLanguageReference`). Do NOT use one long delay. Use a tight POLL LOOP that reads the moment
the query is done. Required pattern:

1. **Launch** — `POST {{Connection.protocol}}{{Connection.url}}/sdl/v2/api/queries` with body
   `{"queryType":"PQ","tenant":true,"startTime":...,"endTime":...,"queryPriority":"HIGH","pq":{"query":...,"resultType":"TABLE"}}`.
   Capture `body.id` AND the `X-Dataset-Query-Forward-Tag` response header (mandatory, session-scoped,
   echoed on every GET/DELETE) into local vars. Extract the header case-insensitively with JQ:
   `{{Function.JQ(launch-slug.headers, "to_entries | map(select(.key|ascii_downcase==\"x-dataset-query-forward-tag\")) | .[0].value", true)}}`.
2. **Poll loop** — a `loop` (while, capped, e.g. 60 iterations) whose FIRST inner action is the GET
   `GET {{Connection.protocol}}{{Connection.url}}/sdl/v2/api/queries/{{local_var.query_id}}?lastStepSeen=0`,
   echoing header `X-Dataset-Query-Forward-Tag: {{local_var.forward_tag}}`. Then a condition on the
   POLL body (NOT the launch body, which is captured once and never updates inside the loop):
   done when `{{poll-slug.body.stepsCompleted}} = {{poll-slug.body.totalSteps}}` (operator `equals`;
   the field is **`totalSteps`**, not `stepsTotal`). TRUE goes to consume results + `break_loop`.
   FALSE goes to a short `delay` (~5s) as the leaf of the false branch; the loop then re-iterates.
3. **Loop-scoped outputs are NOT visible outside the loop.** Every action that reads a poll result
   (`{{poll-slug.body...}}`), extract/read, branch, notify, break, MUST live INSIDE the loop
   (`parent_action` = the loop's export_id). An action placed after the loop that references a
   loop-internal output fails to resolve. Read from the POLL response: `poll-slug.body.data.columns`
   (array of `{name}`), `poll-slug.body.data.values` (2D array); count rows with
   `{{Function.JQ(poll-slug.body.data.values, "length", true)}}`. For a `savelookup` (no results
   consumed) the loop body is just poll, done-check, break/delay.

## Workflow import via s1-secops-mcp

Workflow import, export, and listing use the `s1-secops-mcp` MCP server, which bypasses the
Cowork sandbox proxy entirely. Use `ha_list_workflows`, `ha_get_workflow`, `ha_import_workflow`,
and `ha_export_workflow` directly instead of falling back to the `mgmt-console-api`
skill scripts. The MCP server runs locally on your machine and makes direct HTTPS calls to
`*.sentinelone.net` without proxy interference.

### Deployment gotchas (confirmed 2026-06-11 on usea1-purple)

- **`ha_import_workflow` does not scope to a site.** It posts to `/import` with no `siteIds`, so
  on a site-scoped tenant it returns the misleading `403 "Insufficient permissions"` — not a role
  problem. For a site-scoped deploy, call the REST endpoint directly with the scope param:
  `POST /web/api/v2.1/hyper-automate/api/public/workflow-import-export/import?siteIds=<id>` with
  body `{"data": <workflow>}` (e.g. via the `mgmt-console-api` POST helper). For an
  account-level deploy use the same public endpoint with `?accountIds=<acct>`; the v1
  `/workflow-import-export/import?_scopeId=<acct>&_scopeLevel=account` path returns `403`. Same
  scope rule applies to `activation`, `deactivate`, `publish`, and `DELETE` — append
  `?siteIds=<id>` or `?accountIds=<acct>` to match where the workflow lives.
- **There is no in-place update.** Import always creates a NEW workflow. Re-importing a name that
  already exists succeeds but the console auto-appends ` (1)`, ` (2)`, … to the name. To "edit" a
  deployed workflow you must delete the old one (REST `DELETE`, see below) and re-import (or edit it
  in the UI).
- **Delete a workflow with a REST `DELETE`.** `DELETE /hyper-automate/api/v1/workflows/{id}?accountIds=<acct>`
  returns `204` (soft, recoverable delete). Validated end to end (import → publish → delete → gone
  from list). A `404 "Object not found"` on delete means the id is not under that scope (or already
  deleted); match the scope (`?accountIds=`/`?siteIds=`) to where the workflow lives.
- **Publish (share with team) without activating:** `POST /hyper-automate/api/v1/workflows/{id}/publish`
  (bodyless, scope via `?accountIds=`/`?siteIds=`, returns `204`). This transitions Private Draft to
  Shared Draft, so the flow appears in the team UI in an `inactive` (not-running) state. An imported
  draft is private to the importer until it is published or activated; use publish to hand off a
  reviewed-but-not-yet-runnable workflow, or to surface a draft for deletion.
- **Activation can fail with `400` ("requires configuration" / "invalid references")** when an
  integration-backed action has no bound connection or a placeholder is unresolved. Bind the
  connection (Hyperautomation → Integrations) and set the keys before activating, then `deactivate`
  to leave it published but not running.
