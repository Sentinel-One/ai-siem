# Graph

3 endpoints.

## `POST /web/api/v2.1/xdr/graph-explorer/query/explorer`
**Query the graph based on query builder filters**
`operationId`: `_web_api_xdr_graph-explorer_query_explorer_post`

Query the graph

Required permissions: `XDR Inventory.view`

Parameters:
- `mock` [query, boolean] — Mock
- `groupIds` [query, array] — List of Group IDs to filter by
- `accountIds` [query, array] — List of Account IDs to filter by
- `limit` [query, integer] — Limit
- `continuationToken` [query, string] — Continuation token
- `siteIds` [query, array] — List of Site IDs to filter by
- `body` [body, v2_1.graph.query.schemas_QueryGraphInputSchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/xdr/graph-explorer/query/explorer/v2`
**Query the graph based on query builder filters**
`operationId`: `_web_api_xdr_graph-explorer_query_explorer_v2_post`

Query the graph

Required permissions: `XDR Inventory.view`

Parameters:
- `mock` [query, boolean] — Mock
- `groupIds` [query, array] — List of Group IDs to filter by
- `accountIds` [query, array] — List of Account IDs to filter by
- `limit` [query, integer] — Limit
- `continuationToken` [query, string] — Continuation token
- `siteIds` [query, array] — List of Site IDs to filter by
- `body` [body, v2_1.graph.query.schemas_QueryGraphInputSchemaV2] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/xdr/graph-explorer/query/subgraph`
**Query the sub graph of an asset type and id**
`operationId`: `_web_api_xdr_graph-explorer_query_subgraph_post`

Query the sub graph of an asset type and id

Required permissions: `XDR Inventory.view`

Parameters:
- `accountIds` [query, array] — List of Account IDs to filter by
- `siteIds` [query, array] — List of Site IDs to filter by
- `groupIds` [query, array] — List of Group IDs to filter by
- `body` [body, v2_1.graph.query.schemas_QuerySubGrapInputSchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.
