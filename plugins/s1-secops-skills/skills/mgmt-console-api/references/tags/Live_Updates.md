# Live Updates

1 endpoints.

## `GET /web/api/v2.1/content-updates-inventory`
**Get Agent Merged Updates**
`operationId`: `_web_api_content-updates-inventory_get`

Get Agent's merged updates.

Required permissions: `Endpoints.view`

Parameters:
- `skip` [query, integer] — Skip first number of items (0-1000). To iterate over more than 1000 items,  use "cursor". Example: "150".
- `limit` [query, integer] — Limit number of returned items (1-1000). Example: "10".
- `cursor` [query, string] — Cursor position returned by the last request. Use to iterate over more than 1000 items. Example: "YWdlbnRfaWQ6NTgwMjkzODE=".
- `countOnly` [query, boolean] — If true, only total number of items will be returned, without any of the actual objects.
- `skipCount` [query, boolean] — If true, total number of items will not be calculated, which speeds up execution time.
- `sortBy` [query, string] (enum: appliedAt, agentId, assetFamilyType, version, displayName) — The column to sort the results by. Example: "id".
- `sortOrder` [query, string] (enum: asc, desc) — Sort direction. Example: "asc".
- `agentId` [query, string] **required** — The ID of the Agent. Example: "225494730938493804".

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.
