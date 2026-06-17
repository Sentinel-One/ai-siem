# Agents Repository (Beta)

3 endpoints.

## `DELETE /web/api/v2.1/agent-artifacts/token`
**Delete Access Token**
`operationId`: `_web_api_agent-artifacts_token_delete`

Deletes an access token for the S1 Agent Artifacts Repository

Required permissions: `Agent Artifacts.delete`

Parameters:
- `scope_level` [query, string] — Scope level to list the tokens for. Possible values: 'site', 'account'
- `scope_id` [query, integer] — Scope id to list the tokens for, example: '983604236220743370'
- `token_id` [query, integer] — token id of the token to be deleted, example: '42'

Responses: 200 Token deleted, 400 Invalid request, 401 Unauthorized, 404 Not found, 500 Internal error

## `GET /web/api/v2.1/agent-artifacts/token`
**List Access Tokens**
`operationId`: `_web_api_agent-artifacts_token_get`

Lists valid access tokens for the S1 Agent Artifacts Repository, with the option to filter by scope

Required permissions: `Agent Artifacts.listAccessTokens`

Parameters:
- `scope_level` [query, string] — Scope level to list the tokens for. Possible values: 'site', 'account', 'tenant'
- `scope_id` [query, integer] — Scope id to list the tokens for, example: '983604236220743370'
- `limit` [query, integer] — The number of tokens to return, for example: '10'. Optional
- `offset` [query, integer] — The number of tokens to skip before starting to collect the result, for example: '2'. Optional

Responses: 200 OK, 400 Invalid request, 401 Unauthorized, 500 Internal error

## `POST /web/api/v2.1/agent-artifacts/token`
**Create Access Token**
`operationId`: `_web_api_agent-artifacts_token_post`

Creates an access token for the S1 Agent Artifacts Repository, which is needed for pulling artifacts

Required permissions: `Agent Artifacts.create`

Parameters:
- `request` [body, handlers.TokenRequest] **required** — expected request body

Responses: 200 OK, 400 Invalid request, 401 Unauthorized, 500 Internal Error
