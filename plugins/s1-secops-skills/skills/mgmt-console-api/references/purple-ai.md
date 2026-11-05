## Purple AI: natural-language query, alert summary, and auto-investigation

> **Primary path:** the s1-secops-mcp tools. `purple_ai_query` asks a natural-language question (synchronous `purpleLaunchQuery`, about 5 to 15 s) with the console API token and returns `{resultType, message, summary, powerQuery {query, timeRange, viewSelector}, starRule, suggestedQuestions}`. Purple does not run the query: review it, then run it with `powerquery_run`. `purple_ai_alert_summary` summarises one UAM alert. The reference below documents the raw GraphQL for debugging or scripting. From 1.6.0 the image no longer bundles purple-mcp; if the user has connected the official Purple MCP themselves and asks for it, use it.

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

**Request shape that works with a console API token (s1-secops-mcp 1.6.0, measured 2026-11-05: HTTP 200 in about 6 s, `POWER_QUERY` for a hunt question, `MESSAGE` for a knowledge question).** The same `tenantDetails` block goes in twice, at `request.tenantDetails` and at `request.inputContent.tenantDetails`, with an empty `conversation.messages` list and a fresh conversation id per call. This is what `purple_ai_query` sends (`purpleLaunchQuery` in `s1-secops-mcp/lib/s1.js` in the source repo, not shipped):

```graphql
query PurpleQuery($input: String!) {
  purpleLaunchQuery(request: {
    isAsync: false
    contentType: NATURAL_LANGUAGE
    tenantDetails: {
      userDetails: { sessionId: null emailAddress: null userAgent: "s1-secops-mcp" buildDate: null buildHash: null }
      consoleDetails: { consoleId: null tenantId: null accountId: null siteId: null baseUrl: "https://<region>.sentinelone.net" version: null }
    }
    conversation: { id: "<unique id>", messages: [], entitlements: null }
    inputContent: {
      userInput: $input
      displayedTimeRange: { start: <epochMs>, end: <epochMs> }
      viewSelector: EDR
      contentType: NATURAL_LANGUAGE
      tenantDetails: { <same block as above> }
    }
  }) {
    result { message summary powerQuery { query timeRange { start end } viewSelector } starRule suggestedQuestions { question powerQuery } }
    resultType
    status { state error { errorDetail errorType origin } }
  }
}
```

The browser sends the larger shape below (observed in a console session). It failed for API tokens in the 2026-05-03 tests; use the shape above.

Variables (`$request`), browser shape:

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

**API-token users: use `purple_ai_query`.** It sends the working request shape above and returns the answer or the generated PQ; run that PQ with `powerquery_run` after reviewing it. Purple can AND fields from different schema families (for example `event.type` with `winEventLog.id`), which returns nothing; split such a query by `dataSource.name`. Each call is a new conversation, so restate context in every question. The notebook steps (2 to 8 above) are browser-only and not needed.

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

**Not available with an API token.** `aiInvestigation/run` via `alertTriggerActions` returned `SERVICE_ERROR` for service-account API tokens (2026-05-03) and still needs a browser session; s1-secops-mcp does not expose it. Run auto-investigation from the console. For an API-token workflow, combine `purple_ai_alert_summary` with your own investigation (`uam_get_alert`, `purple_ai_query`, `powerquery_run`).

### Python CLI

> **`purple_query()` and `scripts/call_purple.py` send the older request shape**, which failed with `AsimovError` / `SERVICE_ERROR` for service-account tokens (2026-05-03). They are kept for reference. Use the `purple_ai_query` MCP tool, then `powerquery_run` to run the returned PQ.

### Domain boundary

Purple AI answers questions about **SDL telemetry** (process/network/file events, indicators, ingested logs) with a PowerQuery (`resultType: "POWER_QUERY"`), and general security questions (for example "What is T1059?") with a written answer (`resultType: "MESSAGE"`). It does **not** answer questions about **console entities** (alerts, threats, agents, sites, policies). Those are REST and UAM resources. Out-of-domain questions return `resultType: "MESSAGE"` with a guardrail refusal: switch to the REST or UAM path.

### Caveats and API-token results

| Operation | API-token result | Notes |
|---|---|---|
| `purpleAlertSummary` (ALERT_ENTRY) | **PASS**: returns real LLM summary | Works with `userDetails: null`; no SDL dependency. MCP tool `purple_ai_alert_summary` |
| `purpleLaunchQuery` (NATURAL_LANGUAGE), 1.6.0 request shape | **PASS** (2026-11-05) | `tenantDetails` at `request` and at `request.inputContent`, empty `messages`. MCP tool `purple_ai_query` |
| `purpleLaunchQuery` (NATURAL_LANGUAGE), browser request shape | **FAIL** (2026-05-03): `AsimovError` from `LaunchQueryManager` | The older shape the Python helpers still send |
| `aiInvestigation/run` via `alertTriggerActions` | **FAIL** (2026-05-03): `SERVICE_ERROR` | Needs a browser session; not exposed |
| `/sdl/v2/graphql` queries (`purpleConversations`, etc.) | **FAIL**: `unauthenticated` | SDL queries require browser session cookie |
| `/sdl/v2/graphql` mutations (`createNotebook`, etc.) | **PARTIAL**: schema validation reached | Auth passes for mutations; mutation names differ from browser UI (introspection blocked) |

**History of the NATURAL_LANGUAGE failure:** the 2026-05-03 tests sent the browser request shape, which passed GraphQL validation (HTTP 200) and then failed at the LLM dispatch layer (`LaunchQueryManager`, `AsimovError`). At the time this was attributed to the missing browser-session `teamToken`. The 1.6.0 shape, which carries `tenantDetails` in both places, succeeds with the same kind of token, which points to the request shape rather than the token type.

`purpleAlertSummary` is a self-contained summarisation operation: the full alert context is supplied inline in `inputAlert`, no SDL session lookup is needed.

**SDL auth nuance (confirmed via live testing):** SDL query operations return `unauthenticated` for API tokens. SDL mutations reach schema validation (meaning auth succeeds), but the specific mutation names used by the browser UI (`createNotebook`, etc.) are not exposed under those names for API tokens. Introspection is blocked on the SDL endpoint.

- The GraphQL endpoint is **not a committed public API**. Field names and schema can change between console releases.
- Notebooks have a TTL: old notebooks return "Notebook is expired" and queries return no results.
- Each GraphQL request should carry a unique `requestId` UUID as a query param for tracing (`?opname=<op>&requestId=<uuid>`). The server ignores it but it aids debugging.
- Permission failures for `purpleLaunchQuery` surface as `status.state = FAILED` with `error.origin = LaunchQueryManager` (HTTP 200, not 400 or 403): not the usual "invalid query" 400 you get for schema errors.
- Do **not** auto-execute generated PQ without showing it to the user first, Purple can hallucinate fields.
- In the browser shape, `inputContent` must appear at **both** the top level of `request` AND inside `conversation.messages[0].inputMessage.inputContent` (confirmed via live validation). The 1.6.0 shape sends `inputContent` once, with `messages: []`, and repeats `tenantDetails` instead.
