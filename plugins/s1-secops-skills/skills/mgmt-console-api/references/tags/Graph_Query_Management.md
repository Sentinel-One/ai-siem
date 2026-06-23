# Graph Query Management

6 endpoints.

## `GET /web/api/v2.1/xdr/graph-explorer/query/management/query`
**Get graph query list**
`operationId`: `_web_api_xdr_graph-explorer_query_management_query_get`

Get graph query list

Required permissions: `XDR Inventory.view`

Parameters:
- `skip` [query, integer] — Skip first number of items (0-1000). To iterate over more than 1000 items,  use "cursor".
- `groupIds` [query, array] — List of Group IDs to filter by
- `sortOrder` [query, string] (enum: asc, desc) — Sort direction
- `accountIds` [query, array] — List of Account IDs to filter by
- `limit` [query, integer] — Limit number of returned items (1-1000)
- `version` [query, string] — Version
- `countOnly` [query, boolean] — If true, only total number of items will be returned, without any of the actual objects.
- `queryType` [query, string] (enum: saved, shared, suggested) — Query type
- `name__contains` [query, string] — Free-text search filter by query name
- `siteIds` [query, array] — List of Site IDs to filter by
- `cursor` [query, string] — Cursor position returned by the last request. Use to iterate over more than 1000 items.
- `skipCount` [query, boolean] — If true, total number of items will not be calculated, which speeds up execution time.
- `sortBy` [query, string] (enum: name) — The column to sort the results by.

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/xdr/graph-explorer/query/management/query`
**Save graph query**
`operationId`: `_web_api_xdr_graph-explorer_query_management_query_post`

Save graph query

Required permissions: `XDR Inventory.view`

Parameters:
- `accountIds` [query, array] — List of Account IDs to filter by
- `siteIds` [query, array] — List of Site IDs to filter by
- `groupIds` [query, array] — List of Group IDs to filter by
- `body` [body, v2_1.graph.query.schemas_QueryManagementUpdateSchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/xdr/graph-explorer/query/management/query/type-counts`
**Get graph query counts by type**
`operationId`: `_web_api_xdr_graph-explorer_query_management_query_type-counts_get`

Get graph query counts by type

Required permissions: `XDR Inventory.view`

Parameters:
- `accountIds` [query, array] — List of Account IDs to filter by
- `siteIds` [query, array] — List of Site IDs to filter by
- `groupIds` [query, array] — List of Group IDs to filter by

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `DELETE /web/api/v2.1/xdr/graph-explorer/query/management/query/{query_id}`
**Delete graph query**
`operationId`: `_web_api_xdr_graph-explorer_query_management_query_{query_id}_delete`

Delete graph query

Required permissions: `XDR Inventory.view`

Parameters:
- `accountIds` [query, array] — List of Account IDs to filter by
- `siteIds` [query, array] — List of Site IDs to filter by
- `groupIds` [query, array] — List of Group IDs to filter by
- `query_id` [path, string] **required** — Query ID

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `PUT /web/api/v2.1/xdr/graph-explorer/query/management/query/{query_id}`
**Update graph query**
`operationId`: `_web_api_xdr_graph-explorer_query_management_query_{query_id}_put`

Update graph query

Required permissions: `XDR Inventory.view`

Parameters:
- `accountIds` [query, array] — List of Account IDs to filter by
- `siteIds` [query, array] — List of Site IDs to filter by
- `groupIds` [query, array] — List of Group IDs to filter by
- `query_id` [path, string] **required** — Query ID
- `body` [body, v2_1.graph.query.schemas_QueryManagementUpdateSchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/xdr/graph-explorer/query/management/recent-queries`
**Get graph recent query list**
`operationId`: `_web_api_xdr_graph-explorer_query_management_recent-queries_get`

Get graph recent query list

Required permissions: `XDR Inventory.view`

Parameters:
- `accountIds` [query, array] — List of Account IDs to filter by
- `siteIds` [query, array] — List of Site IDs to filter by
- `limit` [query, integer] — Limit number of returned items
- `groupIds` [query, array] — List of Group IDs to filter by

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.
