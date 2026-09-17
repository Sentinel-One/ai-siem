---
name: hyperautomation
author: Marco Rottigni <marco.rottigni@sentinelone.com>, Prithvi Moses <prithvi.moses@sentinelone.com>
description: >-
  Use this skill whenever a user wants to create, design, build, generate, write, or export
  a SentinelOne Hyperautomation workflow in JSON format. Triggers: any mention of
  "Hyperautomation", "workflow", "automation", "SOAR", "playbook", "alert response",
  "trigger", "scheduled workflow", "webhook workflow", or any request to automate a
  SentinelOne-related security task, even phrased casually ("build me a thing that disables
  a user when an alert fires"). Also triggers when the user asks to import, export, test,
  validate, or submit a workflow to a SentinelOne console via API, and for autonomous /
  auto-response SOC requests: "autonomous SOC", "SOC in a box", "auto-triage", "investigate
  and respond automatically", "auto-isolate on a critical alert", "auto-close false
  positives and escalate real threats", or letting an LLM decide isolate vs quarantine vs
  close per alert (the canonical investigate-decide-respond shape lives in
  references/autonomous-soc-template.md). When in doubt, use it.
---
# SentinelOne Hyperautomation Skill

<!-- CONFIG-FILE-ADDRESSING v1 -->
> **SDL config files: address by `udoId`, and do not trust a REST listing.**
> REST `listFiles` / `getFile` **cannot see** udoId-addressed `/dashboards/` files, so `getFile`
> returns `404` on a dashboard the console is displaying and the listing under-reports (measured on
> one tenant: REST 8, GraphQL 17, console 48 files). **If a listing disagrees with what the UI
> shows, the listing is wrong until proven otherwise**, change read path before concluding the
> object is missing or the token lacks scope. Use the GraphQL `configFiles` / `configFile` surface.
> A name-addressed `addConfigFile` to `/dashboards/` **creates a duplicate** instead of updating;
> address dashboards by `udoId` with `expectedVersion`. `content` is HJSON, not JSON. `S1-Scope`
> changes which files exist as far as the caller can tell.
> Full detail: [`sdl-api/references/config-file-graphql.md`](../sdl-api/references/config-file-graphql.md)

This skill enables Claude to design and generate valid SentinelOne Hyperautomation workflow
JSON, explain the logic behind workflows, and optionally submit them to a live console via API.

> **Sandbox proxy blocked?** If import/export API calls to `*.sentinelone.net` fail with a connection or proxy error inside the Claude sandbox, use the `s1-secops-mcp` server instead. It runs locally via `node` and bypasses the sandbox proxy entirely. Setup: add it to `claude_desktop_config.json` (see `s1-secops-mcp/README.md`). The MCP server exposes `ha_list_workflows`, `ha_get_workflow`, `ha_import_workflow`, and `ha_export_workflow`, all running from your machine against the Hyperautomation API.

## Minimum viable workflow JSON (smoke test)

Before building production workflows, validate your token + scope using the
smallest payload the `/import` endpoint accepts: a manual trigger with no
inputs. Use this to confirm the API path works end-to-end (import → activate)
before iterating on real action graphs.

> **Which of the two forms you need depends on how you are calling.** The block
> below is the **raw HTTP request body**, so it includes the `{"data": {...}}`
> envelope the `/import` endpoint requires. If you are calling through the
> `ha_import_workflow` MCP tool, pass the **bare workflow object** instead: the
> tool adds that envelope for you, and sending a wrapped payload produces
> `{"data":{"data":{...}}}` and a `422 body.data.name Field required`, which reads
> like a broken workflow rather than one extra level of nesting. Since 1.3.9 the
> tool unwraps a wrapped payload and says so in its response, but pass the bare
> object and the round trip is clean.

**Form A, raw API body** (curl, `requests`, anything hitting the endpoint directly):

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

**Form B, `ha_import_workflow` MCP tool**: the same workflow with the envelope
removed. This is the value of the `workflowJson` argument.

```json
{
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
```

Pass the scope as the tool's `accountIds` or `siteIds` argument, not in the JSON.
Form B is live-verified: it returns `201` with the new workflow `id` and
`version_id`, in state `draft`.

Notes:

- `dynamic_properties: {}` is valid: the manual-trigger node renders with no input fields.
- **Import is not complete until published: treat create/import and publish as ONE atomic step, publish in the SAME step, never as a follow-up. ALWAYS publish a newly created or imported workflow to a Shared Draft.** A workflow created or imported via the API lands as a **Private Draft owned by the API token's user** (for example, the service user), so it is invisible in the console to the human who requested it. Immediately after a successful import, publish it: `POST /hyper-automate/api/v1/workflows/{workflow_id}/publish?accountIds=<acct>` (bodyless `{}`, returns 204; state stays `inactive`, meaning shared but not running). Use `siteIds=<id>` for a site-scoped workflow. See `references/api-integration.md` section 8a. Skip this only when you are activating the workflow, since activation auto-publishes. You can only publish a draft owned by the token's user; publishing another user's private draft returns 403 "Workflow can't be published".
- Activate the imported workflow with
  `POST /workflows/{workflow_id}/{version_id}/activation?siteIds=<id>` (returns 204).
- Don't forget the scope param: see `references/api-integration.md` for the
  `siteIds=` pitfall (the wrong shape returns 403 "Insufficient permissions"
  that looks like a missing role).

## How to use this skill

When a user asks to build a workflow, follow this process:

### Step 1: Understand the intent

Ask (or infer from context):

- What should trigger the workflow? (alert, schedule, webhook, manual, email)
- What integrations are needed? (SentinelOne, M365, Slack, VirusTotal, etc.)
- What is the desired outcome? (enrich alert, disable user, send notification, etc.)
- Should the workflow run automatically or on-demand?

### Step 2: Warn about integrations

**CRITICAL**: Before generating JSON, identify any integration-backed actions (tag = "integration").
These require pre-configured connections in the console that CANNOT be *created* via API. (An EXISTING connection CAN be pre-bound programmatically: set `integration_id` = the connection's id on each `http_request` action in the import JSON with `use_authentication_data: true`, then activate via `POST .../workflows/{id}/{version_id}/activation`; no manual UI binding needed. One connection also serves actions that hit different hosts, e.g. the LRQ console host and the `/v1/alerts` ingest host, since auth is header-injected regardless of the URL, PROVIDED both endpoints take the same credential. HEC event-collector actions (`/services/collector/*`) do not: they need their own connection holding an SDL Log Write Key, see "Connection requirement" below.)
Always tell the user: *"This workflow uses the [X, Y, Z] integrations. Before importing, you must
configure connections for these in your Hyperautomation → Integrations section."*

Integration-backed actions have `"tag": "integration"` and a non-null `integration_id`.
Core actions (Variable, Loop, Condition, Delay, Send Email, HTTP Request without integration,
Break Loop, Snippet, Wait for Slack, Create Interaction, LLM) have `"tag": "core_action"`.

**Packaged vs ad-hoc integration actions.** Every built-in integration ships an action pack. A
packaged action carries `data.public_action_id` (a pack UUID) and a pre-filled `data.url_path`;
an ad-hoc action has `public_action_id: null` and a URL you write yourself. In production, 71%
of `http_request` steps (3,822 of 5,418) use a packaged action. **Prefer a packaged action when
one exists** and keep `url`, `url_path` and `public_action_id` consistent.

The action packs are not queryable: `GET /integrations/{id}` returns connection and auth metadata
only, `/integrations/{id}/actions` is 404, and there is no `GET /integrations` list endpoint (405).
So use `references/integration-catalog.md`, which records all 266 packaged actions across 45
integrations plus the ad-hoc calls, mined from a live tenant. To see what a specific console has,
enumerate with `GET /hyper-automate/api/v1/connections/scope` and resolve each distinct
`integration_id` via `GET /hyper-automate/api/v1/integrations/{id}`.

### Step 3: Generate the JSON

Read `references/workflow-schema.md` to produce a valid workflow JSON.
Read `references/building-blocks.md` for the correct action type structures.
Read `references/functions-reference.md` for available functions and their syntax.

### Step 4: Validate before outputting

Self-check against `references/validation-rules.md` before presenting the workflow.

If the workflow chains `Function.JQ` steps, builds a time window, or fails a run deliberately, also read `references/expressions-gotchas.md`. It covers the failures that only appear at runtime or activation: `Function.JQ(...,true)` returns a STRING so the next JQ cannot index it; `PARSE_JSON` rejects an already-materialised object; a `local_var` is invisible to the action that defines it; quote-bearing expressions inlined in an http_request payload fail at ACTIVATION with `invalid_references`; absolute calendar-day windows via `FORMATTED_DATE`; using `evaluate-expression` as a pre-deploy test loop; the fake-attribute throw idiom; and why retrying a poll cannot revive a dead LRQ.

### Step 5: API submission (optional)

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
token; see `references/api-integration.md` for the reason.

### Step 6: Publish so the requester can see it (REQUIRED after any API import)

A workflow imported or created via the API is a **Private Draft owned by the token's user** and is not visible to anyone else in the console, including the person who asked for it. Treat import and publish as ONE atomic step (an import is not complete until it is a Shared Draft; publish in the same step, never a follow-up). After a successful import, ALWAYS publish it to a **Shared Draft**:
`POST /hyper-automate/api/v1/workflows/{workflow_id}/publish?accountIds=<acct>` (bodyless `{}`, returns 204). The workflow stays `inactive` (shared but not running). Use `siteIds=<id>` for a site-scoped workflow. Skip this step only when you are activating the workflow, since activation publishes automatically. See `references/api-integration.md` section 8a.

- **Deactivate + delete (removal lifecycle).** To remove a workflow: if it is active, deactivate it first with `POST /hyper-automate/api/public/workflows/{workflow_id}/deactivate?siteIds=<id>` (bodyless, returns 204; no `version_id` needed), then `DELETE /hyper-automate/api/v1/workflows/{workflow_id}?siteIds=<id>` (returns 204, soft/recoverable). Deleting a still-active workflow returns `400 "Active workflows cannot be archived"`, so deactivate-then-delete is the required order. See `references/api-integration.md` sections 8 and 8b.

---

## Reference files: when to read each

| File | Read when... |
|------|-------------|
| `references/workflow-schema.md` | Always when generating JSON: defines the envelope and action structure |
| `references/building-blocks.md` | Need the exact shape of a specific action type (trigger, loop, condition, etc.) |
| `references/building-blocks-catalog.md` | **Picking what to use** for a given step / composing multi-action idioms / bootstrapping a SOAR recipe. Mined from 1,205 production workflows (17,899 action steps). Read FIRST when designing a new workflow. |
| `references/integration-catalog.md` | **Which integrations exist and what actions each one offers.** 62 built-in + 52 custom integrations resolved live, with all 266 packaged actions (`public_action_id`, method, path) plus observed ad-hoc calls. Read when the user names a third-party product ("open a Jira ticket", "block on the Palo Alto", "post to Teams") and you need the real action or endpoint shape. Also documents the integration-enumeration API. |
| `references/functions-reference.md` | Using `{{Function.X()}}` syntax or PowerQuery patterns |
| `references/validation-rules.md` | Before outputting any workflow: run the checklist |
| `references/api-integration.md` | User wants to import/export/submit to a live console |
| `references/snippets.md` | Building or calling a **snippet** (reusable sub-workflow): authoring rules, static vs dynamic `snippet_20` calls, and the snippet lifecycle API |
| `references/autonomous-soc-template.md` | Building an **autonomous SOC** / auto-response workflow: canonical alert→investigate→triage→decide→respond shape, the analyst-approved-remediation variant, the Purple AI agentic investigation calls, converting a markdown investigation report into email or Slack, the reusable response-snippet library, dynamic-snippet dispatch, and a branded SOC-email snippet example |
| `references/interaction-forms.md` | Building a **form-based interaction** (S-26.2.6+): collect structured input from a person mid-run. Product behaviour and limits, the `form_schema` shape, the response schema, and the mandatory `Function.DEFAULT` guard on optional fields |
| `references/connections.md` | Creating an integration **connection** via API (endpoint + body), cloning a connection across sites, and the integration-vs-connection binding rule |

## Decision guide: pick the right pattern by use case

The catalog (`references/building-blocks-catalog.md`) names every reusable block. Use this
table to jump straight to the right starting point:

| User says... | Start with | Composite patterns to layer on |
|--------------|-----------|--------------------------------|
| "When an alert fires, do X" | A1 (Singularity Response Trigger) + recipe C1 | B1 safe-field DEFAULT chain, B2 success/fail branch, B6 add-note |
| "Every day / every N hours, do X" | A3 (Scheduled Trigger) + recipe C2 | B7 SDL ingest, B9 IOC create, B5 JQ shaping |
| "When a webhook hits, do X" | A4 (HTTP Trigger) + recipe C3 | B2 status-code branch, B11 Slack ack |
| "Let an analyst kick this off with parameters" | A2 dynamic Manual Trigger + recipe C4 | B5 JQ shaping, B4 APPEND accumulator |
| "Wait for analyst approval before remediating" | recipe C5 (Slack approval), or `references/interaction-forms.md` for an in-console form | B11 Slack interactive, B6 add-note |
| "Ask a person for structured input mid-run" / "richer approval than yes or no" | `references/interaction-forms.md` (Create Interaction type `form` + Wait for Interaction) | guard EVERY optional field with `Function.DEFAULT`, fail-closed condition |
| "AI investigates, human approves the action" | `references/autonomous-soc-template.md` → analyst-approved remediation variant | agentic investigation, poll snippet, `llm` brief, approval form |
| "Periodic posture / UEBA report" | A3 + recipe C6 | B8 PowerQuery, B7 SDL ingest |
| "Page through a paginated API" | B3 (cursor + break_loop) | B4 APPEND accumulator |
| "Summarize this evidence with an LLM" | B12 (OpenAI) | B6 add-note |
| "Create a Threat Intelligence indicator" | B9 (TI IOC create) | B4 accumulator inside loop |
| "Add a note on the alert" | B6 (UAM GraphQL addAlertNote) | always wrap text in `Function.HTML_ENCODE` |
| "Auto-investigate and respond to alerts end to end" | `references/autonomous-soc-template.md` | reusable response snippets + dynamic `snippet_20` dispatch, poll-until-complete loop |
| "Reuse this step across several flows" / "stop copy-pasting this logic" | `references/snippets.md` (author a snippet, call it with `snippet_20`) | `use_latest_snippet_version` to auto-track edits |

**Reuse via snippets is the default for shared logic.** Whenever the same action graph would appear in more than one workflow (a response action, a notification, a poll loop), build it once as a snippet and call it with a `snippet_20` node instead of duplicating it. See `references/snippets.md`.

The 19 action types **observed in production** (1,244 workflows across 7 tenants) are:
`http_request`, `variable`, `condition`, `loop`, `singularity_response_trigger`,
`send_email`, `break_loop`, `data_formation`, `manual_trigger`, `snippet`, `delay`,
`wait_for_slack`, `http_trigger`, `scheduled_trigger`, `create_interaction`,
`wait_for_interaction`, `llm`, `email_trigger`, `snippet_20`.

This is an **observed** list, not the product's declared list, and there is no API that returns
the declared one. One known gap: the S-26.2 docs describe a **SQL action** (PostgreSQL, MySQL,
MSSQL) that appears in zero workflows in the corpus, so its JSON `type` string is unverified.
Before emitting an action type outside the 19, confirm it by building one in the console UI and
exporting the workflow to read its `type`. Do not guess the string.

> **Snippet node types.** *Calling* a snippet from a workflow uses a `snippet_20` node (not `snippet`). *Authoring* a snippet uses a `snippet_trigger` (inputs) + `snippet_output` (returns) in place of a normal trigger. See `references/snippets.md`.

## Example patterns (in references/)

Annotated real examples to use as structural references:

- `references/building-blocks-catalog.md`: patterns mined from 1,205 production workflows. Atomic node shapes (Section A), composite idioms such as condition branches with success/fail notes, loops with APPEND and BREAK logic, and integration-backed HTTP requests with connection placeholders (Section B), plus full use-case recipes (Section C) and anti-patterns (Section E).
- `references/snippets.md`: authoring and calling reusable snippets, with worked `snippet_trigger`, `snippet_output`, and `snippet_20` node shapes.
- `references/autonomous-soc-template.md`: the canonical end-to-end investigate-decide-respond workflow template, plus the analyst-approved-remediation variant and the Purple AI agentic investigation call shapes.
- `references/interaction-forms.md`: form-based interactions end to end, product behaviour plus the tenant-validated JSON layer.

---

## Quick reference: action name → slugified reference

When referencing a previous action in `{{...}}` syntax, use the kebab-case version of the
action's `name` field. Examples:

- Action named "Get Agents with Active Threat" → `{{get-agents-with-active-threat.body.data}}`
- Action named "SDL Query" → `{{sdl-query.body.matches[0].attributes.actor_user_email_addr}}`
- Action named "Singularity Response Trigger" → `{{singularity-response-trigger.data.id}}`
- Action named "Loop the list of IPv4" → `{{loop-the-list-of-ipv4.item}}`

The rule: lowercase, spaces become hyphens, special characters dropped.

> ⚠️ **Hyphens and other punctuation in a name are DROPPED, not converted to hyphens.** Only spaces
> become hyphens. So an action named "Launch CIDR-Excluded Detection" slugifies to
> `launch-cidrexcluded-detection` (the `CIDR-Excluded` hyphen is removed, merging the words), NOT
> `launch-cidr-excluded-detection`. Referencing the wrong slug fails with "Action contains invalid
> references". **Avoid hyphens/punctuation in the name of any action you reference**, use plain
> space-separated words (e.g. "Launch Detection" → `launch-detection`), or copy the exact slug the
> UI shows.

---

## Integration warning template

Use this when the workflow contains integration-backed actions:

> ⚠️ **Pre-requisite integrations to configure before importing:**
>
> - **[Integration Name]**: used for [action name(s)]. Configure at Hyperautomation → Integrations → [Integration Name] → Add Connection.
> - *(repeat for each)*
>
> Once configured, note the connection name; you may need to update the `connection_name` field in the JSON before importing.

---

## Common mistakes to avoid

- ❌ Hand-assembling a workflow JSON action by action. The action envelope has far more required
  keys than a hand-written one will carry, and a flow missing any of them imports with HTTP 200 and
  then fails at runtime, with no per-action error surface to point at the cause.
  ✅ Start from a shipped, tenant-validated template and change only the query, the payload text and
  the connection binding. See "Starting from a proven template" in `references/workflow-schema.md`.
- ❌ Renaming a `variable` action's `name` when adapting a template. Every `{{local_var.<name>}}`
  elsewhere in the flow still points at the old name. The edited flow imports cleanly, then
  activation fails with HTTP 400 "Some actions in this workflow have invalid references".
  ✅ Treat variable names as an API: change their VALUES freely, never their names. Before importing
  an edit, assert the set of variable names is unchanged and that every `local_var.X` reference
  resolves to one of them.
- ❌ Referencing an OPTIONAL interaction-form field directly. A field the respondent left blank is
  ABSENT from `response.result`, and a bare reference to an absent attribute ERRORS the whole run.
  The flow passes testing (every field filled) then dies in production on the first skipped field.
  ✅ Wrap every optional field: `{{Function.DEFAULT(wait-slug.response.result.field, "not provided")}}`.
  See `references/interaction-forms.md`.
- ❌ Rendering a markdown-bearing field (notably Purple AI's `aiInvestigations[].result`) straight
  into an HTML email or Slack message. Email clients do not render markdown, so it arrives as one
  unbroken wall of `##`, `**` and `-`.
  ✅ Convert with an `llm` action that emits the target format, keep the raw field for the audit
  trail only. See `references/autonomous-soc-template.md`.
- ❌ Putting the human-approval form BEFORE the AI investigation (asking a person which alert to
  investigate). That inverts the value of both features.
  ✅ AI investigates first, the analyst reviews the findings and approves the remediation.
- ❌ Defining multiple variables in a single Variable action when one references another; they evaluate simultaneously and will fail with "variable not found"
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
  ✅ Bind the **"SentinelOne SDL"** connection (Bearer by default) on the HTTP action. Notes: the ApiToken-only `/web/api/v2.1/dv/events/pq` cannot run the `datasource` command (returns 400) and is just an async wrapper over LRQ, so it is not usable for asset/inventory refresh; `/api/powerQuery` on the SDL host is synchronous (one call completes a `savelookup`) while `/sdl/v2/api/queries` is async. Tenant-validated 2026-06-13.
- ❌ Ingesting OCSF / structured events into AI SIEM via HEC (`/services/collector/event?isParsed=true`) without SentinelOne source-attribution fields. OCSF omits them, so events land with a null source (no attribution, degraded console rendering, and `dataSource.name`-based filters/detections miss).
  ✅ Include `dataSource.name`, `dataSource.vendor`, `dataSource.category` (set to `security`, required for AI SIEM to process custom OCSF sources), `event.type`, and `site_id`. Emit `event.type` as a FLAT dotted key (`"event.type": "..."`); a nested `event:{...}` object is dropped on ingest because `event` is a HEC-reserved key.
- ❌ **Leaving every action's `client_data.position` at `{x:0,y:0}`.** The flow runs fine but the console renders every node stacked on top of itself, unreadable. ALWAYS lay out the graph (tenant-validated 2026-07-18).
  ✅ Assign real coordinates: top-level nodes (`parent_action: null`) step DOWN the y-axis (~180px apart, x=0); a loop's child nodes (`parent_action` = the loop's `export_id`) sit INSIDE the loop container at an x offset (~210) stepping down (~180px). Give the `loop` a large `client_data.dimensions` (e.g. `{width:620,height:720}`) so it encloses its children. A one-pass layout after you build the action list is enough; see the reference `_layout(actions)` pattern:

  ```python
  def _layout(actions):
      top_y, child_y = 0, {}
      for a in actions:
          cd = a["action"].setdefault("client_data", {})
          if a.get("parent_action") is None:
              cd["position"] = {"x": 0, "y": top_y}
              if a["action"]["type"] == "loop":
                  cd["dimensions"] = {"width": 620, "height": 720}; top_y += 190 + 720
              else: top_y += 190
          else:
              y = child_y.get(a["parent_action"], 60)
              cd["position"] = {"x": 210, "y": y}; child_y[a["parent_action"]] = y + 180
  ```

- ❌ **Binding an http_request action to a CONNECTION id.** Setting `action.integration_id` to a specific connection instance's id imports + activates fine (204) but FAILS AT RUNTIME with `"Must provide connection in order..."` (activation does not validate the binding; see below). Tenant-validated 2026-07-18.
  ✅ Bind the built-in **integration (action-pack) id**, the value `discover`/list returns as the workflow action's `integration_id` (e.g. the SentinelOne SDL action-pack id). A connection created via `POST /web/api/v2.1/hyper-automate/api/v1/connections` returns a *connection* id; do NOT bind that, bind the integration id it was created under, and rely on a connection existing under that integration.
- ❌ **Trusting activation (204) as proof a flow works.** Activation validates neither connection binding nor `{{Function.JQ}}` references.
  ✅ Always run-now (or the per-action **Test Action**) after activating and confirm state `Completed` with empty `error_actions`.
- ❌ **Reading an http_request's `status` field to decide whether the call worked.** `status` is `"success"` whenever ANY response arrives, including `404`/`4xx`. A flow that branches on it treats an error body as data. Tenant-validated 2026-08-09.
  ✅ Branch on `{{action-slug.status_code}}` (top level of the action output, NOT under `.body`). `continue_on_fail` governs transport failures, not HTTP status; only `retry_on_status_codes` reacts to codes, and it cannot help with a terminal 4xx.
- ❌ **Triggering run-now on several flows concurrently.** Executions park in `Running` with `executed_actions: 0` indefinitely, and abandoned parked executions accumulate and hold scheduler slots (10 observed on one tenant after a day of killed harnesses, blocking new runs). Tenant-validated 2026-08-09.
  ✅ Serialise run-now. To clear a parked execution: `deactivate` → `activate` → run again (a full delete of the workflow also releases it). Before blaming a flow that will not start, check `workflow-execution` for `state: Running` + `executed_actions: 0`. Calibrate any "is it stuck?" timeout against measured healthy start latency: a heavy flow legitimately sat at 0 actions for ~82s before completing with 40.
- ❌ **`select((ARR | index(.field)) != null)` in `Function.JQ`.** The `| index(...)` pipe rebinds `.` to `ARR`, so `.field` then indexes the array → `Cannot index array with string "field"`.
  ✅ Bind first: `select(.field as $n | (ARR | index($n)) != null)`. And when building HTML inside a `Function.JQ` string, use SINGLE-quoted HTML attributes so the only double quotes are jq string delimiters (pre-escaping `\"` inside collides with the wrapper's single quote-escape and the platform reports "Invalid References").
- ❌ Guarding a destructive action (block, isolate, disable) with a fail-OPEN approval gate (`... not_equals "dismissed"`). A `wait_for_slack` / `wait_for_interaction` timeout yields an empty value that passes `not_equals`, so the action auto-runs with **no** approval.
  ✅ Fail CLOSED: test `... equals "approved"` and route the destructive action off the `"true"` branch only (see `references/validation-rules.md` → Condition rules).
- ❌ Setting `parent_action` to a previous (non-loop) node's `export_id` to express flow order: this returns import `422 "Invalid workflow data"` even when everything else looks correct. `parent_action` is loop-membership ONLY.
  ✅ `parent_action: null` on every node that is not inside a loop; wire flow order strictly via `connected_to.target` (see `references/validation-rules.md` → Import / `parent_action` rules).
- ❌ Writing back to an alert (note / analyst verdict / status) via the old `/web/api/v2.0/threats` REST endpoints: they are decommissioned and return HTTP 405.
  ✅ Use the Unified Alerts GraphQL API (`POST /web/api/v2.1/unifiedalerts/graphql`) for every write-back, not just notes (see `references/api-integration.md` → SentinelOne alert write-backs).

## Running an SDL LRQ from an HA flow (async launch + poll): tenant-validated 2026-06-22

Moved to a reference to keep SKILL.md under the 500-line limit. See [`references/ha-flow-recipes.md`](references/ha-flow-recipes.md).

## Posting a UAM SecurityAlert from an HA flow that actually SURFACES

Moved to a reference to keep SKILL.md under the 500-line limit. See [`references/ha-flow-recipes.md`](references/ha-flow-recipes.md).

**The credential split matters and is the usual cause of a silent failure.** The event collector needs its OWN connection carrying an SDL **Log Write Key**; the Management Console API token is refused there and returns `Missing S1-Scope header`. UAM alert ingest via `/v1/alerts` is the opposite case: it uses the console token and does require `S1-Scope`. One connection cannot serve both.

## Detection watchdog pattern (the alternate to a scheduled rule)

Some detection logic cannot run as a PowerQuery **scheduled** Custom Detection rule, because scheduled
rules run on a pre-aggregated data layer where functions like `dataset`, `datasource`, `now`,
`querystart` / `queryend` / `queryspan`, `topK`, `savelookup`, CIDR/wildcard `lookup`, `lookup` over a
>10,000-row table, time-shifted `timebucket`, and `timebucket` < 30s are unavailable (full list in the
`powerquery` skill). The classic case is enumerating **absent** rows, a pair present in a
baseline but with zero events in the live window, which needs a `left join` + `dataset` anti-join.

The **alternate is an HA watchdog**: a scheduled (or manual / run-now) workflow that

1. launches the full PowerQuery as an SDL LRQ (the LRQ runs on raw events, so `left join`, `dataset`,
   `savelookup`, wide/`timebucket`, large `lookup`, etc. all work); see "Running an SDL LRQ from an HA
   flow" above;
2. polls the LRQ to completion and reads back the result rows;
3. posts ONE OCSF SecurityAlert to UAM for the offending rows (or a summary): see "Posting a UAM
   SecurityAlert from an HA flow that actually SURFACES" above; set
   `metadata.product = {"name":"Hyperautomation","vendor_name":"SentinelOne"}` for attribution.

Deploy it active (bind the "SentinelOne SDL" Bearer connection) so the schedule runs it, and/or trigger
it immediately with run-now (`POST .../workflow-execution/manual/{workflow_id}/{version_id}`). The UEBA
**SILENT** (a reliably-active pair goes quiet) and **DORMANT** (a long-idle pair reactivates) detections
are the canonical examples. When several LRQ queries must run and they use `| nolimit`, chain them
**sequentially** (launch, poll to done, then launch the next): only one nolimit query runs per account
at a time.

## Workflow import via s1-secops-mcp

Workflow import, export, and listing use the `s1-secops-mcp` MCP server, which bypasses the
Cowork sandbox proxy entirely. Use `ha_list_workflows`, `ha_get_workflow`, `ha_import_workflow`,
and `ha_export_workflow` directly instead of falling back to the `mgmt-console-api`
skill scripts. The MCP server runs locally on your machine and makes direct HTTPS calls to
`*.sentinelone.net` without proxy interference.

### Deployment gotchas (confirmed 2026-06-11 on `<console>`)

- **`ha_import_workflow` does not scope to a site.** It posts to `/import` with no `siteIds`, so
  on a site-scoped tenant it returns the misleading `403 "Insufficient permissions"`, not a role
  problem. For a site-scoped deploy, call the REST endpoint directly with the scope param:
  `POST /web/api/v2.1/hyper-automate/api/public/workflow-import-export/import?siteIds=<id>` with
  body `{"data": <workflow>}` (e.g. via the `mgmt-console-api` POST helper). For an
  account-level deploy use the same public endpoint with `?accountIds=<acct>`; the v1
  `/workflow-import-export/import?_scopeId=<acct>&_scopeLevel=account` path returns `403`. Same
  scope rule applies to `activation`, `deactivate`, `publish`, and `DELETE`, append
  `?siteIds=<id>` or `?accountIds=<acct>` to match where the workflow lives.
- **There is no in-place update.** Import always creates a NEW workflow. Re-importing a name that
  already exists succeeds but the console auto-appends `(1)`, `(2)`, … to the name. To "edit" a
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
