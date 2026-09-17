# Common mistakes to avoid

Moved out of `SKILL.md` to keep it under the 500-line authoring limit. The content is unchanged.

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
