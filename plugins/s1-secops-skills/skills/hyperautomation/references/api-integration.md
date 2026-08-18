# API Integration Reference

## Environment Variables

Two environment variables drive all API interactions with the console:

| Variable | Contains |
|----------|----------|
| `S1_CONSOLE_URL` | Full console base URL, e.g. `https://usea1-acme.sentinelone.net` |
| `S1_CONSOLE_API_TOKEN` | Console User (personal) API token (generated in Settings → Users → API Token) |

**Always validate these before use.** Run the two-step check below, if either step fails,
stop and tell the user what went wrong before proceeding with any workflow operation.

### Step 1: Validate `S1_CONSOLE_URL` (no auth required)

```text
GET {S1_CONSOLE_URL}/web/api/v2.1/system
```

This endpoint requires no authentication and always returns `200` with `{"data": {"health": "ok"}}`
when the console is reachable. A non-200 response or a network error means `S1_CONSOLE_URL` is wrong
or the console is unreachable.

### Step 2: Validate `S1_CONSOLE_API_TOKEN` (auth + permission check)

```text
GET {S1_CONSOLE_URL}/web/api/v2.1/hyper-automate/api/public/workflows?limit=1
Authorization: ApiToken {S1_CONSOLE_API_TOKEN}
```

A `200` response confirms the token is valid and has `Hyper Automate.view` permission.
Failure responses:

- `401`: token is missing or expired
- `403`: token lacks `Hyper Automate.view` permission

```javascript
// Validation helper
async function validateCredentials(apiUrl, apiToken) {
  // Step 1: URL check
  const sysRes = await fetch(`${apiUrl}/web/api/v2.1/system`);
  if (!sysRes.ok) throw new Error(`Console unreachable (${sysRes.status}). Check S1_CONSOLE_URL.`);
  const { data: { health } } = await sysRes.json();
  if (health !== 'ok') throw new Error(`Console health: ${health}`);

  // Step 2: Token check
  const authRes = await fetch(
    `${apiUrl}/web/api/v2.1/hyper-automate/api/public/workflows?limit=1`,
    { headers: { "Authorization": `ApiToken ${apiToken}` } }
  );
  if (authRes.status === 401) throw new Error('S1_CONSOLE_API_TOKEN is invalid or expired.');
  if (authRes.status === 403) throw new Error('S1_CONSOLE_API_TOKEN lacks Hyper Automate.view permission.');
  if (!authRes.ok) throw new Error(`Token check failed (${authRes.status})`);
}
```

---

## Overview

The Hyperautomation API allows programmatic management of workflows: import, export, activate,
deactivate, trigger, list, and monitor executions.

**Base URL**: `https://<your-console-url>/web/api/v2.1/`
**Authentication**: `Authorization: ApiToken <token>` header (Console User personal API token)
**Content-Type**: `application/json` for POST requests

All POST request bodies follow the S1 envelope pattern:

```json
{ "data": { /* payload */ } }
```

All scope-filtering query params are **plural**: `accountIds`, `siteIds`, `groupIds`.

### ⚠️ Common scope-param pitfall

You will see two different scope-filter shapes in SentinelOne tutorials and
Slack snippets. Only the **plural query-string** shape works on the
Hyperautomation API. The other variants all return `HTTP 403 "Insufficient
permissions"`, a misleading error that looks like a missing role, but is
actually a wrong parameter name.

| Shape | Result |
|---|---|
| `?siteIds=<id>` (or `?accountIds=<id>`, `?groupIds=<id>`) | ✅ HTTP 200 |
| Body `{"filter": {"siteIds": ["<id>"]}}` | ✅ HTTP 200 |
| `?scopeLevel=site&scopeId=<id>` | ❌ HTTP 403 "Insufficient permissions" |
| `?site.id=<id>` / `?site_id=<id>` / `?scope_id=<id>` | ❌ HTTP 403 |
| Header `X-Scope-Site: <id>` | ❌ HTTP 403 |
| Body field `data.site_id` | ❌ HTTP 403 |

If your token has the right permissions everywhere else and only `/import` (or
another HA endpoint) returns 403, **try `?siteIds=` before assuming a role
problem**.

---

## Endpoint Reference

### 1. Import Workflow

`POST /hyper-automate/api/public/workflow-import-export/import`

**Permission**: `Hyper Automate.workflowsCreateEdit`

<!-- Section reconstructed 2026-07-29: the original text was committed corrupted (garbled
     interleaved lines) in every git revision. Rebuilt from the readable fragments,
     references/workflow-schema.md, and the tenant-validated import client in
     s1-secops-mcp/tools/hyperautomation.js. Re-validate details against a live tenant
     before treating any single field name here as authoritative. -->

**Query params** (at least one required to set scope):

| Param | Type | Description |
|-------|------|-------------|
| `accountIds` | string | Comma-separated account IDs |
| `siteIds` | string | Comma-separated site IDs |
| `groupIds` | string | Comma-separated group IDs |

**Request body**: the workflow JSON wrapped in the standard S1 envelope,
`{ "data": { <workflow object> } }` (this is what the validated import client sends).
The workflow object is the same shape `export` produces; authored-from-scratch workflows
need at minimum `name` (required, max 255 chars), `description`, and `actions`
(see workflow-schema.md). Export-produced objects also carry scope and tenant metadata:

```json
{
  "name": "Workflow Name",              // required, max 255 chars
  "description": null,
  "actions": [ /* action objects */ ],
  "scope_id": "<site_or_account_id>",
  "scope_level": "site",
  "mgmt_id": "<tenant_deployment_id>",
  "site_name": "...",
  "account_name": "...",
  "site_state": "active",
  "account_state": "active",
  "created_at": "ISO-8601",
  "updated_at": "ISO-8601",
  "created_by_user": { "id": "...", "email": "...", "name": "..." },
  "tags": [],
  "timeout": 86400,
  "daily_max_executions": 0,
  "max_concurrency": 0,
  "notify_to": [],
  "is_snippet": false,
  "dimensions": { "width": null, "height": null }
}
```

**Responses**:

- `200`: success. The response is a **flat object, NOT wrapped in `data`**.
  Do not read `response.data.id`, that returns undefined; use `response.id` and
  `response.version_id` directly at the top level.
- `422`: validation error (malformed JSON, wrong field types, etc.)

```json
{
  "id": "<workflow_id>",
  "version_id": "<version_id>",
  "name": "Workflow Name",
  "state": "...",
  "lifecycle_state": "...",
  "scope_id": "...",
  "scope_level": "...",
  "created_at": "...",
  "created_by_user": { "id": "...", "email": "...", "name": "..." },
  "version_count": 1
}
```

**Token type and ownership**: both `Authorization: ApiToken ...` and
`Authorization: Bearer ...` (JWT, `eyJ...`) schemes authenticate successfully against
`/import` and `/activation`. The practical difference is **ownership**: the imported
workflow is owned by the token's user, and there is no public endpoint to transfer
ownership. Use a personal token if a human SOC analyst needs to see or edit the imported
workflow in the UI. Use a service-user token only if the workflow is purely
automation-managed. After import, the workflow must be activated before it runs.

#### After import: retrieving the `version_id` reliably

`POST /import` returns `id` and `version_id` at the top level. Capture both
**immediately** from the response.

If you lose the response (or are activating a previously-imported workflow), the only
endpoint that returns the name plus the activation-ready `version_id` together in one
call is **`GET /workflows/versions/list/{workflow_id}`**:

```bash
curl -s -H "Authorization: ApiToken $TOKEN" \
  "$S1_CONSOLE/web/api/v2.1/hyper-automate/api/public/workflows/versions/list/$WORKFLOW_ID?siteIds=$SITE_ID" \
  | jq '[.versions[] | select(.state == "active")][0] // .versions[0]
        | {id, version_id, name, state, activated_at}'
```

Live-verified 2026-07-29: the response shape is `{"versions": [...]}` and versions are listed
**newest-first**, so `.versions[0]` can be a NEWER inactive draft rather than the running
version. Select on `state == "active"` (as above) when you want the activation-ready
`version_id`; fall back to `[0]` only for never-activated workflows.

Sample response:

```json
{
  "id": "<workflow_id>",
  "version_id": "<version_id>",
  "name": "My Workflow",
  "state": "active",           // or "draft" before activation
  "activated_at": "ISO-8601"   // null before activation
}
```

On at least some tenants, `GET /workflows/{workflow_id}` and
`GET /workflow-import-export/export/{workflow_id}` return **HTTP 404** even for
workflows that exist. Only the `/workflows/versions/list/{id}` path is guaranteed
to work for post-import retrieval.

**Notes**:

- Imported workflows are created as **Private Draft**, visible only to the owner of the token
  used for import.
- **Use a Console User (personal) token, not a Service User token.** The Hyperautomation API
  has no endpoint to change workflow ownership or share a workflow programmatically. A workflow
  imported with a Service User token would be owned by that service account and invisible to
  human users in the console UI.
- After import, the workflow must be activated before it runs.

---

### 2. Batch Import Workflows

`POST /hyper-automate/api/public/workflow-import-export/import/batch`

**Permission**: `Hyper Automate.workflowsCreateEdit`

**Query params**: same as single import (`accountIds`, `siteIds`, `groupIds`)

Accepts multiple workflow objects. Use for bulk deployments.

**Body params** (multipart/form-data):

- `file` (required): the batch import file (workflow JSON or ZIP archive)
- `filter` (required): JSON-encoded string. Send `{}` for "no filter".
  ⚠️ Sending `filter` as an **empty string** (`""`) triggers a server-side
  parse error that surfaces as **HTTP 500**, *not* HTTP 4xx. If you see a 500
  on batch import, suspect the `filter` field first.
- `body` (optional): `{ "data": {...}, "filter": {"type": "JsonPath"|"JsonSchema", "value": "..."} }`

Example:

```bash
curl -X POST "$S1_CONSOLE/web/api/v2.1/hyper-automate/api/public/workflow-import-export/import/batch?siteIds=$SITE_ID" \
  -H "Authorization: ApiToken $TOKEN" \
  -F "file=@workflows.json;type=application/json" \
  -F 'filter={};type=application/json'
```

**Responses**: `201` success, `422` validation error (missing field),
`403` (real permission check; fires only after schema validation passes;
don't trust a 500 from a malformed `filter` as evidence about permissions).

---

### 3. Export Workflow (single)

`GET /hyper-automate/api/public/workflow-import-export/export/{workflow_id}/{version_id}`

**Permission**: `Hyper Automate.workflowsExport`

Returns the full workflow JSON for re-import or inspection.

**Finding IDs**: From the console URL when viewing a workflow:
`https://<console>/hyperautomation/workflow/<workflow_id>/<version_id>`

---

### 4. Batch Export Workflows

`GET /hyper-automate/api/public/workflow-import-export/export`

**Permission**: `Hyper Automate.workflowsExport`

**Query params** (all optional, combine to filter):

| Param | Type | Description |
|-------|------|-------------|
| `workflow_ids` | string | Comma-separated workflow IDs |
| `integrations` | string | Filter by integration name |
| `trigger_types` | string | Filter by trigger type |
| `core_actions` | string | Filter by core action type |
| `states` | string | Filter by workflow state |
| `name__contains` | string | Name substring match |
| `name__eq` | string | Exact name match |
| `tags` | string | Filter by tags |
| `accountIds` | string | Scope to account(s) |
| `siteIds` | string | Scope to site(s) |
| `groupIds` | string | Scope to group(s) |

---

### 5. List Workflows

`GET /hyper-automate/api/public/workflows`

**Permission**: `Hyper Automate.view`

**Query params**:

| Param | Type | Description |
|-------|------|-------------|
| `integrations` | string | Filter by integration |
| `trigger_types` | string | Filter by trigger type |
| `core_actions` | string | Filter by action type |
| `states` | string | Filter by state (e.g. `active`, `inactive`) |
| `name__contains` | string | Name substring |
| `name__eq` | string | Exact name match |
| `description__contains` | string | Description substring |
| `is_snippet` | boolean | Filter snippets only |
| `workflow_ids` | string | Comma-separated IDs |
| `tags` | string | Filter by tag |
| `oversight` | boolean | Filter oversight workflows |
| `limit` | integer | Page size |
| `skip` | integer | Offset for pagination |
| `sortBy` | string | Field to sort by |
| `sortOrder` | string | `asc` or `desc` |
| `accountIds` | string | Scope to account(s) |
| `siteIds` | string | Scope to site(s) |
| `groupIds` | string | Scope to group(s) |

---

### 6. List Workflow Versions

`GET /hyper-automate/api/public/workflows/versions/list/{workflow_id}`

**Permission**: `Hyper Automate.view`

Returns all versions (draft, active, inactive) for a given workflow.

**Query params**: `accountIds`, `siteIds`, `groupIds` for scope.

---

### 7. Activate a Workflow Version

`POST /hyper-automate/api/public/workflows/{workflow_id}/{version_id}/activation`

**Permission**: `Hyper Automate.workflowsActivateDeactivate`

**Query params**: `accountIds`, `siteIds`, `groupIds` for scope.

**Body** (all fields optional):

```json
{
  "data": {
    "version_description": "optional version note",
    "timeout": 86400,              // seconds, default 86400 (24h)
    "daily_max_executions": 0,     // 0 = unlimited
    "max_concurrency": 0,          // 0 = unlimited
    "notify_to": ["user@example.com"],
    "time_saved": null,            // integer (minutes saved per run)
    "time_saved_unit": null,       // unit string
    "is_snippet": false,
    "dimensions": { "height": 0, "width": 0 }  // canvas dimensions (optional)
  }
}
```

**Responses**: `204` success (no body), `422` validation error.

---

### 8. Deactivate a Workflow

`POST /hyper-automate/api/public/workflows/{workflow_id}/deactivate`

**Permission**: `Hyper Automate.workflowsActivateDeactivate`

**Query params**: `version_id` (optional), `accountIds`, `siteIds`, `groupIds`. Omit `version_id`
to deactivate the currently active version (you do not need to look the version up first).

**Body**: `{ "data": null }` or empty `{}`

**Responses**: `204` success (no body), `422` validation error. Validated 2026-07-11: a bodyless
`POST .../workflows/{id}/deactivate?siteIds=<id>` with no `version_id` returned `204`.

---

### 8a. Publish a Workflow (Share with team)

`POST /hyper-automate/api/v1/workflows/{workflow_id}/publish`

Transitions a Private Draft to a Shared Draft so the workflow is visible to the team in the UI
(state becomes `inactive`, i.e. shared but not running). An imported draft is private to the
importing user until it is published or activated.

**Query params**: `accountIds` or `siteIds` (match the workflow's scope).

**Body**: none (bodyless POST; send `{}`).

**Responses**: `204` success (no body). Validated 2026-06-13.

---

### 8b. Delete a Workflow

`DELETE /hyper-automate/api/v1/workflows/{workflow_id}?accountIds=<acct>`

Soft, recoverable delete (the UI offers a "Restore workflow" action). This is the correct delete
mechanism. Validated end to end 2026-06-13 (import → publish → delete → gone from list).

**Deactivate an ACTIVE workflow before deleting it.** Deleting a running workflow returns
`400 {"detail": "Active workflows cannot be archived"}`. The correct sequence for an active
workflow is two calls: (1) deactivate it (section 8: `POST .../workflows/{id}/deactivate?siteIds=<id>`,
returns `204`), then (2) `DELETE .../workflows/{id}?siteIds=<id>` (returns `204`). Validated
2026-07-11 on two active watchdog flows: deactivate `204` then delete `204`; a direct delete of the
still-active flow first returned the 400 above.

**Query params**: `accountIds` or `siteIds`, match where the workflow lives. A `404 "Object not
found"` means the id is not under that scope (or already deleted).

**Responses**: `204` success (no body).

---

### 9. Trigger a Manual Workflow

`POST /hyper-automate/api/public/workflow-execution/manual/{workflow_id}/{version_id}`

**Permission**: `Hyper Automate.workflowsRun`

**Query params**: `accountIds`, `siteIds`, `groupIds` for scope.

**Body** (all fields optional):

```json
{
  "data": {
    "payload": "optional string payload passed to the workflow",
    "singularity_response_event_id": null,
    "singularity_response_event_type": null,
    "is_downstream_execution": false,
    "parent_execution_id": null
  }
}
```

**Responses**: `201` success (returns the execution object with `id` and `state: "Running"`), `422` validation error.

> **Run-now returns HTTP 500 on an EMPTY body.** Posting `{}` returns
> `500 {"detail":"Internal server error"}`, not a 4xx, so it reads like a server fault rather than
> a malformed request and sends you debugging the wrong thing. Send the full envelope even when
> there is no payload:
> `{"data": {"payload": "{}", "singularity_response_event_id": null,
> "singularity_response_event_type": null, "is_downstream_execution": false,
> "parent_execution_id": null}}`. Tenant-validated 2026-08-18.

> **Run-now also works on a SCHEDULED-trigger workflow (validated 2026-06-22).** Despite the name
> "manual", `POST .../workflow-execution/manual/{id}/{version_id}?accountIds=<acct>` triggers an
> active scheduled-trigger workflow immediately, no need to wait for its cron. The workflow must be
> `state: "active"` (bind connections + activate first). Verify the run via the executions endpoints
> below: poll `GET .../workflow-execution/{execution_id}` until `state` is `"Completed"`, then check
> `executed_actions` (should equal the action count) and `error_actions` (empty = clean run).
> Tenant-validated end to end: a CIDR-excluded LRQ + UAM alert flow ran via this endpoint in ~34s,
> 10/10 actions, `error_actions: []`.

---

### 10. List Workflow Executions

`GET /hyper-automate/api/public/workflow-execution`

**Permission**: `Hyper Automate.view`

**Query params**:

| Param | Type | Description |
|-------|------|-------------|
| `workflow_id` | string | Filter by specific workflow |
| `trigger_types` | string | Filter by trigger type |
| `states` | string | Filter by execution state |
| `workflow_name__contains` | string | Workflow name substring |
| `is_snippet` | boolean | Snippets only |
| `tags` | string | Filter by tag |
| `integrations` | string | Filter by integration |
| `created_at__gte` | datetime | From timestamp |
| `created_at__lt` | datetime | To timestamp |
| `limit` | integer | Page size |
| `skip` | integer | Offset for pagination |
| `sortBy` | string | Sort field |
| `sortOrder` | string | `asc` or `desc` |
| `accountIds` | string | Scope to account(s) |
| `siteIds` | string | Scope to site(s) |
| `groupIds` | string | Scope to group(s) |

---

**Response** includes `data` (array) and `pagination: { nextCursor, totalItems }`.

---

### 11. Get Execution Detail

`GET /hyper-automate/api/public/workflow-execution/{workflow_execution_id}`

**Permission**: `Hyper Automate.view`

**Response fields**:

- Required: `id`, `mgmt_id`, `scope_id`, `singularity_response_event_id`, `version_id`, `workflow_id`
- Optional: `created_at`, `duration`, `error_actions` (array), `executed_actions` (integer),
  `scope_level` (enum), `singularity_response_event_type` (enum), `state` (enum),
  `time_saved` (number), `updated_at`, `workflow_state` (enum)

---

### 12. Enable Agent PNA for Hyperautomation

`POST /agents/enable-hyper-automation-pna`

**Permission**: `Endpoints.edit` + `Hyper Automate.connectionsEdit`

Enables the Private Network Access agent integration for use in Hyperautomation connections.

---

### 13. Disable Agent PNA for Hyperautomation

`POST /agents/disable-hyper-automation-pna`

**Permission**: `Endpoints.edit` + `Hyper Automate.connectionsEdit`

---

### 14. Evaluate Expression

`POST /hyper-automate/api/public/workflow-action-expressions/{base_action_id}/evaluate-expression`

Evaluates a Hyperautomation expression string against a given context.

**Body**:

```json
{
  "data": {
    "expression": "{{action.some_field | upper}}",   // required
    "loop_context": {}                                // optional
  }
}
```

**Responses**: `200` success, `422` validation error.

---

### 15. Expression Breakdown

`POST /hyper-automate/api/public/workflow-action-expressions/{base_action_id}/expression-breakdown`

Same body as Evaluate Expression. Returns a parsed breakdown of expression components.

---

## Common Integration Flow

### Deploy a new workflow end-to-end

Uses the `S1_CONSOLE_URL` and `S1_CONSOLE_API_TOKEN` environment variables. Always call `validateCredentials()`
(defined above) before any workflow operation.

```javascript
const apiUrl   = process.env.S1_CONSOLE_URL;    // e.g. https://usea1-acme.sentinelone.net
const apiToken = process.env.S1_CONSOLE_API_TOKEN;  // Service User API token
const siteId   = process.env.SITE_ID;    // optional, scope to a specific site

const base = `${apiUrl}/web/api/v2.1/hyper-automate/api/public`;
const headers = {
  "Authorization": `ApiToken ${apiToken}`,
  "Content-Type": "application/json"
};

// 0. Validate credentials first
await validateCredentials(apiUrl, apiToken);

// 1. Import
const importRes = await fetch(`${base}/workflow-import-export/import?siteIds=${siteId}`, {
  method: "POST",
  headers,
  body: JSON.stringify({ data: workflowJson })
});
const importData = await importRes.json();
const { id: workflowId, version_id: versionId } = importData.data;

// 2. Activate
await fetch(`${base}/workflows/${workflowId}/${versionId}/activation?siteIds=${siteId}`, {
  method: "POST",
  headers,
  body: JSON.stringify({ data: {} })
});
// Note: activation returns 204 (no body)

// 3. Trigger (if manual workflow)
const triggerRes = await fetch(
  `${base}/workflow-execution/manual/${workflowId}/${versionId}?siteIds=${siteId}`,
  {
    method: "POST",
    headers,
    body: JSON.stringify({ data: { payload: "optional" } })
  }
);
// triggerRes.status === 201 on success
```

---

## Error Reference

| HTTP | Meaning | Common causes |
|------|---------|---------------|
| `200` / `201` / `204` | Success | n/a |
| `400` | Bad request | Malformed body, invalid field value |
| `401` | Unauthorized | Missing or expired API token |
| `403` | Forbidden | Token lacks required permission |
| `404` | Not found | Wrong workflow/version ID |
| `422` | Validation error | Schema mismatch, duplicate `export_id`, invalid `type` value, missing required field |

Common import `422` messages:

- `"Invalid action type"`: typo in `type` field
- `"export_id conflict"`: duplicate `export_id` values in actions array
- `"Invalid target"`: `connected_to.target` references non-existent `export_id`
- `"Missing required field"`: required field absent from data object

---

## SentinelOne alert write-backs: use the Unified Alerts GraphQL API

When a workflow writes back to the alert that triggered it, add a note, set the analyst verdict,
change status, assign an owner, or set a ticket id; use the **Unified Alerts GraphQL API**, not the
legacy REST threats endpoints. The old `POST /web/api/v2.0/threats/*` note/verdict/status paths are
**decommissioned and return HTTP 405.**

**Endpoint**: `POST {console}/web/api/v2.1/unifiedalerts/graphql`
(in an `http_request` action, target `{{Connection.protocol}}{{Connection.url}}/web/api/v2.1/unifiedalerts/graphql`).
**Payload**: a raw JSON body `{"query": "<mutation>", "variables": { ... }}`.

The **note-add** mutation shape (`addAlertNote` / `alertTriggerActions` with `S1/alert/addNote`) is
already documented in `building-blocks-catalog.md` → B6. The same `alertTriggerActions` envelope drives
the rest of the write-back actions, pass a different `id` in `actions[]`:

| Action id | Payload |
|-----------|---------|
| `S1/alert/addNote` | `{ note: { value: $note } }`: or rich: `{ formattedNote: { text: $text, plainText: $plain, type: MARKDOWN } }` |
| `S1/alert/analystVerdictUpdate` | `{ analystVerdict: { value: <ENUM> } }` |
| `S1/alert/statusUpdate` | `{ status: { value: <ENUM> } }` |
| `S1/alert/assignUser` | assign an owner to the alert |
| `S1/alert/setTicketId` | set an external ticket id |

**Gotchas (each cost a live debugging cycle):**

- **Enum values are UNQUOTED GraphQL literals**, not strings. `AnalystVerdict`:
  `FALSE_POSITIVE_BENIGN` / `TRUE_POSITIVE_MALWARE` / `UNDEFINED` / … ; `Status`:
  `NEW` / `IN_PROGRESS` / `RESOLVED`. Writing `"IN_PROGRESS"` (quoted) fails.
- **The `$id` GraphQL variable must be typed `String!`, not `ID!`**: `stringEqual.value` expects a
  `String`, so an `ID!` variable raises `VariableTypeMismatch`.
- **`ContentType` enum** for `formattedNote.type` is `HTML | MARKDOWN | PLAIN_TEXT`. `MARKDOWN` renders
  headings, bold, tables, and links in the alert Notes panel; prefer it for rich evidence notes.
- **Unknown or unavailable action ids come back as FAILURES, not silent no-ops.** The mutation returns
  HTTP 200 with the bad action under `actions[].failure` (`errorMessage: "No result returned by target
  service"`), NOT an empty `actions: []` and NOT under `skip`. Always check `actions[].failure` and
  `actions[].skip`, not just `success`: a wrong or deprecated id (e.g. `setAnalystVerdict` / `setStatus`,
  which are absent from the live catalog) fails here while the HTTP action still reports 200. Enumerate
  the valid ids for an alert first via the `alertAvailableActions` query. (Live-validated 2026-07-24.)
- Writes are **eventually consistent (~5s)**: don't read-after-write immediately and assume failure.

---

## Native integration actions vs generic `http_request`

An action is a **native integration action** when it carries `tag: "integration"` plus a
`public_action_id` (the catalog identity of a specific action inside an installed integration) and, to
render as native on the canvas, the vendor's `integration_id`.

- **Live-fetch the action catalog** rather than guessing ids or field names, then **copy the catalog
  action's `data` verbatim**, substituting only the input placeholders (catalog tokens like `<<ip>>`)
  with workflow expressions; reconstructing `data` by hand tends to drop required shape (e.g. params
  must be `{parameter_name, parameter_value}`, not `{key, value}`). NOTE: the exact catalog path is
  unconfirmed on S-26.x. `GET {base}/public-actions` returns 404 (as do `/actions` and
  `/integration-actions`); capture the current path from a browser DevTools network trace of the
  Hyperautomation > Integrations page before relying on it. (Path 404 verified live 2026-07-24.)
- **`url` / `url_path` / `payload` overrides on an integration action ARE honored**: the action then
  executes as a generic HTTP request through the bound connection. To make a node *unambiguously* a
  generic request, set `public_action_id: null`.
- **Null out `connection_id`s in exported workflow JSON for cross-tenant portability.** A hard-coded
  `connection_id` from the source tenant imports as `404 "connection not found"` in another tenant;
  leaving it `null` imports clean (the user binds the connection after import).
- **Prefer NEW API endpoints over deprecated ones** for every native action, and verify the real
  endpoint before wiring, deprecated paths can reject functions or return empty rows silently.

---

## Export-all + round-trip template

- **`GET {base}/workflow-import-export/export`** returns every workflow and is the fastest source of
  known-good templates: round-trip a member and bisect your nodes into it to debug a persistent import
  `422`. The `ids` param is NOT honored (any value, including `ids=all`, returns ALL workflows because
  the param is ignored); the real filter is **`workflow_ids=<comma-separated ids>`**, which returns only
  those workflows. A single-`workflow_ids` response is the raw `{name, description, actions, notes}` JSON
  envelope. (For the replace-in-place lifecycle, no in-place update: deactivate, delete, import,
  activate, see sections 8, 8a, and 8b above.) Param behaviour live-validated 2026-07-24.
- **Per-action execution output is NOT exposed via the API** (the per-action output endpoints 404).
  Validate a deployed workflow by triggering it and reading the resulting alert notes / downstream side
  effects, not by inspecting action outputs over the API.

---

## Console URL Formats

| Region | Pattern |
|--------|---------|
| US East 1 | `https://usea1-<tenant>.sentinelone.net` |
| EU West 1 | `https://euw1-<tenant>.sentinelone.net` |
| US East 2 | `https://usea2-<tenant>.sentinelone.net` |

**Token location**: Settings → Users → [your user] → API Token → Generate.
Use a **Console User (personal) token**. Do not use a Service User token, the Hyperautomation
API provides no endpoint to share or transfer workflow ownership, so a workflow imported with
a Service User token would be owned by that service account and invisible to human users.
