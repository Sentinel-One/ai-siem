## Purple AI: natural-language query, alert summary, and auto-investigation

> **Precedence:** if the user explicitly mentions "purple mcp" or "mcp", prefer the Purple MCP tools (`mcp__purple-mcp__purple_ai`, `mcp__purple-mcp__powerquery`, etc.); this skill is the backup path in that case. Use the wrapper below when the user has asked for the S1 console/API directly, when Purple MCP is unavailable, or when you need to script a raw GraphQL call.

### Hosts

| Host | Purpose |
|---|---|
| `<region>.sentinelone.net` | Management console: all REST and GraphQL calls use this host |
| `id.na1.sentinelone.net` | Browser session keep-alive (not relevant for API tokens) |
| `metrics-proxy-use1.na1.sentinelone.net` | Internal metrics (returned 503 in observed sessions, non-fatal) |

### Endpoints

Purple AI uses **three** GraphQL endpoints (all traffic is `POST` with JSON body). Each request carries `?opname=<OperationName>&requestId=<uuid>` as query-string params for tracing; the server only inspects the JSON body.

| Endpoint | Purpose |
|---|---|
| `POST /web/api/v2.1/graphql` | LLM dispatcher: `purpleLaunchQuery`, `purpleAlertSummary` |
| `POST /sdl/v2/graphql` | Notebook lifecycle + SDL query execution (see operation table below) |
| `POST /web/api/v2.1/unifiedalerts/graphql` | UAM: auto-investigation trigger and polling |

Auth uses the same `Authorization: ApiToken <token>` header as REST. No extra credential setup.

### SDL operation table (`POST /sdl/v2/graphql`)

| opname | Triggered by | Purpose |
|---|---|---|
| `notebooks` | Sidebar load | List My Notebooks / Shared Notebooks |
| `createNotebook` | "+ New Notebook" or starter prompt | Creates a notebook; response includes `teamToken` |
| `purpleNotebook` | Selecting a notebook | Loads full Q&A history for the notebook |
| `addPurpleInputOutputMessage` | After each LLM/query step | Persists user prompt + AI output into the notebook |
| `launchQuery` | After LLM produces a PowerQuery | Executes the PQ against the data lake |
| `pingQuery` | Repeatedly while query runs | Short-poll for status/progress/results |
| `removeQuery` | On completion or cancel | Cleans up the query and releases resources |

### Bootstrap REST calls (browser-only)

These fire on page load and when entering a notebook. Not needed for API-token workflows, but useful for debugging feature availability:

- `GET /web/api/v2.1/private/system/enabled-features?siteIds=<id>`: feature flags (`purpleNative`, `purpleConversations`, `purpleAutoInvestigations`)
- `GET /web/api/v2.1/private/rbac/user-permissions?siteIds=<id>`: current user's permission set
- `POST /web/api/v2.1/private/users/session-info`: session info

### Operations

#### purpleLaunchQuery: NL → PowerQuery (or summary/suggestions)

**Critical: this is a GraphQL `query` (not `mutation`). Variable wrapper is `request` (type `PurpleLaunchQueryRequest`). Prior implementations using `mutation` + `PurpleLaunchQueryInput` fail with HTTP 400.**

`contentType` controls what the LLM is asked to do:

| contentType | Returns |
|---|---|
| `NATURAL_LANGUAGE` | `result.powerQuery.query`: the generated PQ string |
| `QUERY_RESULTS` | `result.summary`: English summary of a previous PQ result set |
| `SUGGEST_QUESTIONS` | `result.suggestedQuestions[]`: follow-up question chips |
| `STAR_RULE`, `DETECTION_RULE` | `result.detectionRule`: generated detection logic |

```graphql
query purpleLaunchQuery($request: PurpleLaunchQueryRequest!) {
  purpleLaunchQuery(request: $request) {
    token
    resultType
    status { state error { errorType errorDetail origin } }
    stepsCompleted
    result {
      message
      summary
      maskedMetadata
      powerQuery { query viewSelector timeRange { start end } }
      suggestedQuestions { question powerQuery viewSelector timeRange { start end } }
    }
  }
}
```

Variables (`$request`):

```jsonc
{
  "request": {
    "isAsync": false,
    "contentType": "NATURAL_LANGUAGE",
    "consoleDetails": { "baseUrl": "https://<region>.sentinelone.net/", "version": "S-26.1.3#69" },
    // TOP-LEVEL inputContent required (confirmed: HTTP 400 "missing input value at $request.inputContent" without it)
    "inputContent": {
      "userInput": "<the user's question>",
      "viewSelector": "EDR",
      "displayedTimeRange": { "start": <epochMs>, "end": <epochMs> },
      "resultsPq": null, "powerQueryForResults": null, "contextId": null, "userDetails": null
    },
    "conversation": {
      "id": "<uuid>",
      "messages": [{
        "inputMessage": {
          "id": "<uuid>", "feedItemId": "<32hex>", "conversationId": "<uuid>",
          "createdAt": "<iso>", "messageType": "INPUT", "contentType": "NATURAL_LANGUAGE",
          "inputContent": {
            "userInput": "<the user's question>",
            "viewSelector": "EDR",
            "displayedTimeRange": { "start": <epochMs>, "end": <epochMs> },
            "resultsPq": null, "powerQueryForResults": null, "contextId": null, "userDetails": null
          }
        }
      }]
    }
  }
}
```

`PurpleUserDetailsRequest` schema (confirmed via live validation error, does NOT have `siteIds` or `groupIds`):

```jsonc
{
  "accountId": "<19-digit ID>",  // ID! required
  "teamToken": "<24-char>",      // ID! required, session token from Purple AI workspace
  "sessionId": "<uuid>",
  "emailAddress": "<user@...>",
  "userAgent": "<browser UA>",
  "buildDate": "<iso>",
  "buildHash": "<short hash>"
}
```

Full end-to-end flow for one user question (observed in browser session):

```text
1. purpleLaunchQuery  (NATURAL_LANGUAGE, /web/api/v2.1/graphql)
   → result.powerQuery.query  (the generated PQ string)

2. addPurpleInputOutputMessage  (/sdl/v2/graphql)
   → persists user prompt + generated PQ into the notebook

3. launchQuery  (/sdl/v2/graphql)
   → submits PQ to SDL execution engine
   → returns { token, ids, status: RUNNING }

4. pingQuery × N  (/sdl/v2/graphql, ~1 Hz)
   → polls until status = COMPLETED
   → returns columns + cells (table data)

5. purpleLaunchQuery  (QUERY_RESULTS, /web/api/v2.1/graphql)
   → result.summary  (English summary of the rows)

6. purpleLaunchQuery  (SUGGEST_QUESTIONS, /web/api/v2.1/graphql)
   → result.suggestedQuestions[]  (follow-up chips)

7. addPurpleInputOutputMessage  (/sdl/v2/graphql)
   → persists the final answer into the notebook

8. removeQuery  (/sdl/v2/graphql)
   → cleanup / releases query budget
```

Starter-prompt flow (e.g. "Find install logs" on the homepage):

```text
createNotebook → purpleLaunchQuery (NATURAL_LANGUAGE) → addPurpleInputOutputMessage
```

Note: starter prompts that return a documentation-style answer skip the `launchQuery`/`pingQuery` stage entirely.

**API-token users: use the Purple MCP.** The `purple_ai_query` MCP tool has been removed, `purpleLaunchQuery NATURAL_LANGUAGE` is confirmed non-functional for service-account API tokens (requires browser-session teamToken; returns AsimovError from LaunchQueryManager). Use `mcp__purple-mcp__purple_ai` for NL queries and `mcp__purple-mcp__powerquery` to execute the returned PQ.

#### purpleAlertSummary: per-alert natural-language summary

Separate operation (not purpleLaunchQuery). Synchronous (isAsync=false, no polling).

```graphql
query AlertSummary($request: PurpleAlertSummaryRequest!) {
  purpleAlertSummary(request: $request) {
    token
    result { summary }
  }
}
```

Variables: `request.contentType = "ALERT_ENTRY"`, `request.inputAlert = "<OCSF alert JSON as string>"`, `request.consoleDetails`, `request.userDetails`.

**MCP tool:** `purple_ai_alert_summary`, call `uam_get_alert` first to get the OCSF JSON, then pass it here.

#### aiInvestigations: auto-investigation

Two-step flow, both via the UAM GraphQL endpoint (`/web/api/v2.1/unifiedalerts/graphql`):

1. `alertTriggerActions` mutation with `id: "S1/aiInvestigation/run"`: fires investigation
2. `GetAlertAiInvestigations` query, polled every ~4s: streams `investigationStep` text, final `result` (markdown, ~16KB) + `verdict` enum

Verdict enum: `UNKNOWN`, `TRUE_POSITIVE`, `FALSE_POSITIVE`.

**API-token users: use the Purple MCP.** The `purple_ai_investigate` MCP tool has been removed, `aiInvestigation/run` via `alertTriggerActions` is confirmed non-functional for service-account API tokens (returns SERVICE_ERROR; same teamToken dependency as `purpleLaunchQuery`). Use `mcp__purple-mcp__purple_ai` for AI investigations.

### Python CLI

> **`purple_query()` and `scripts/call_purple.py` are non-functional for API tokens.** Both call `purpleLaunchQuery NATURAL_LANGUAGE`, which requires a browser-session teamToken that service accounts never have (confirmed SERVICE_ERROR 2026-05-03). Use the Purple MCP instead:
>
> ```text
> mcp__purple-mcp__purple_ai   # natural-language query → PQ → result
> mcp__purple-mcp__powerquery  # run a PQ string directly
> ```
>
> `scripts/purple_ai.py` and `scripts/call_purple.py` are kept in the skill for reference but will fail with AsimovError on any service-account token.

### Domain boundary

Purple AI answers questions about **SDL telemetry** (process/network/file events, indicators, ingested logs). It does **not** answer questions about **console entities** (alerts, threats, agents, sites, policies). Those are REST resources. Out-of-domain questions return `resultType: "MESSAGE"` with a guardrail refusal, switch to the REST path.

### Caveats and confirmed API-token limitations (live-tested 2026-05-03)

| Operation | API-token result | Notes |
|---|---|---|
| `purpleAlertSummary` (ALERT_ENTRY) | **PASS**: returns real LLM summary | Works with `userDetails: null`; no SDL dependency |
| `purpleLaunchQuery` (NATURAL_LANGUAGE) | **FAIL**: `AsimovError` from `LaunchQueryManager` | LLM layer rejects service-account requests; see below |
| `aiInvestigation/run` via `alertTriggerActions` | **FAIL**: `SERVICE_ERROR` | Same LLM-layer dependency |
| `/sdl/v2/graphql` queries (`purpleConversations`, etc.) | **FAIL**: `unauthenticated` | SDL queries require browser session cookie |
| `/sdl/v2/graphql` mutations (`createNotebook`, etc.) | **PARTIAL**: schema validation reached | Auth passes for mutations; mutation names differ from browser UI (introspection blocked) |

**Root cause of NATURAL_LANGUAGE failures:** `purpleLaunchQuery` internally routes to the same LLM workspace layer as the browser UI. That layer uses `teamToken` (obtained by browser users via `createNotebook` on `/sdl/v2/graphql`) to identify the user's Purple AI notebook. Service accounts (API tokens) never initialize a browser session, so `teamToken` is always empty and the `LaunchQueryManager` (`AsimovError`) rejects the request. This is not a schema issue, the request passes GraphQL validation (HTTP 200) and fails at the LLM dispatch layer.

`purpleAlertSummary` bypasses this because it is a self-contained summarisation operation: the full alert context is supplied inline in `inputAlert`, no SDL session or teamToken lookup is needed.

**SDL auth nuance (confirmed via live testing):** SDL query operations return `unauthenticated` for API tokens. SDL mutations reach schema validation (meaning auth succeeds), but the specific mutation names used by the browser UI (`createNotebook`, etc.) are not exposed under those names for API tokens. Introspection is blocked on the SDL endpoint.

- The GraphQL endpoint is **not a committed public API**. Field names and schema can change between console releases.
- Notebooks have a TTL: old notebooks return "Notebook is expired" and queries return no results.
- Each GraphQL request should carry a unique `requestId` UUID as a query param for tracing (`?opname=<op>&requestId=<uuid>`). The server ignores it but it aids debugging.
- Permission failures for `purpleLaunchQuery` surface as `status.state = FAILED` with `error.origin = LaunchQueryManager` (HTTP 200, not 400 or 403): not the usual "invalid query" 400 you get for schema errors.
- Do **not** auto-execute generated PQ without showing it to the user first, Purple can hallucinate fields.
- `inputContent` must appear at **both** the top level of `request` AND inside `conversation.messages[0].inputMessage.inputContent`: the server requires both (confirmed via live validation).
