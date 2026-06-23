# Filters

14 endpoints.

## `GET /web/api/v2.1/filters`
**Get Filters**
`operationId`: `_web_api_filters_get`

Get the list of saved filters. See Save Filter. The response includes the ID of the filter, which you can use in other commands.

Required permissions: `Endpoints.view`

Parameters:
- `skip` [query, integer] — Skip first number of items (0-1000). To iterate over more than 1000 items,  use "cursor". Example: "150".
- `limit` [query, integer] — Limit number of returned items (1-1000). Example: "10".
- `cursor` [query, string] — Cursor position returned by the last request. Use to iterate over more than 1000 items. Example: "YWdlbnRfaWQ6NTgwMjkzODE=".
- `countOnly` [query, boolean] — If true, only total number of items will be returned, without any of the actual objects.
- `skipCount` [query, boolean] — If true, total number of items will not be calculated, which speeds up execution time.
- `sortBy` [query, string] (enum: id, name, createdAt, updatedAt) — The column to sort the results by. Example: "id".
- `sortOrder` [query, string] (enum: asc, desc) — Sort direction. Example: "asc".
- `siteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "225494730938493804,225494730938493915".
- `query` [query, string] — Text query for filter's name. Example: "MyFilter".
- `includeGlobal` [query, boolean] — [DEPRECATED] Return global filters even when specific sites are selected
- `includeParents` [query, boolean] — Return filters from parent scope levels (Default: false)
- `includeChildren` [query, boolean] — Return filters from children scope levels (Default: false)
- `ids` [query, array] — A list of Filter IDs. Example: "225494730938493804,225494730938493915".

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/filters`
**Save Filter**
`operationId`: `_web_api_filters_post`

Save a new filter to get a list of matching endpoints. When you save a filter, you can run actions on the Agents as a set of objects or create a dynamic group (automatically adds new Agents that match the filter and drops Agents if they change to not match).
For example, you can save a filter with {"data":{"filterFields":{"infected":true}}} to run kill and quarantine commands on all the Agents at once, or to create a group that holds currently infected endpoints. Best Practice: Set a scope for the new Saved Filter. Run "accounts", "sites", or "groups" to get the IDs for the scope.

Required permissions: `Endpoints.edit`

Parameters:
- `body` [body, filters.filters_NewFilterSchema] — 

Responses: 403 User is not allowed to perform this operation., 200 Filter successfully saved. Returns created object., 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/filters/csv-filter`
**Upload CSV file**
`operationId`: `_web_api_filters_csv-filter_post`

Upload CSV file

Required permissions: `Endpoints.view`

Parameters:
- `agentFilterField` [formData, string] **required** — The property of the endpoint to filter by
- `excludeHeader` [formData, boolean] **required** — Set to True to exclude the column header
- `file` [formData, file] **required** — File

Responses: 400 Invalid user input received. See error details for further i, 200 Success, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/filters/dv`
**[DEPRECATED] Get Deep Visibility Filters**
`operationId`: `_web_api_filters_dv_get`

Get saved Deep Visibility queries with full data. See Save Deep Visibility Filters.The response includes the ID of the filter, which you can use in other commands.

Required permissions: `Deep Visibility.view`

Parameters:
- `skip` [query, integer] — Skip first number of items (0-1000). To iterate over more than 1000 items,  use "cursor". Example: "150".
- `limit` [query, integer] — Limit number of returned items (1-1000). Example: "10".
- `cursor` [query, string] — Cursor position returned by the last request. Use to iterate over more than 1000 items. Example: "YWdlbnRfaWQ6NTgwMjkzODE=".
- `countOnly` [query, boolean] — If true, only total number of items will be returned, without any of the actual objects.
- `skipCount` [query, boolean] — If true, total number of items will not be calculated, which speeds up execution time.
- `sortBy` [query, string] (enum: id, name, createdAt, updatedAt) — The column to sort the results by. Example: "id".
- `sortOrder` [query, string] (enum: asc, desc) — Sort direction. Example: "asc".
- `siteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "225494730938493804,225494730938493915".
- `groupIds` [query, array] — List of Group IDs to filter by. Example: "225494730938493804,225494730938493915".
- `query` [query, string] — Text query for filter's name. Example: "MyFilter".
- `includeGlobal` [query, boolean] — [DEPRECATED] Return global filters even when specific sites are selected
- `includeParents` [query, boolean] — Return filters from parent scope levels (Default: false)
- `includeChildren` [query, boolean] — Return filters from children scope levels (Default: false)
- `ids` [query, array] — A list of Filter IDs. Example: "225494730938493804,225494730938493915".

Responses: 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/filters/dv`
**[DEPRECATED] Save Deep Visibility Filter**
`operationId`: `_web_api_filters_dv_post`

Save a Deep Visibility query with data as a filter, to get notifications of specific events sent to named recipients on a given frequency. The recipients must be Console users with permissions on the scope of the query. Notifications are sent through email: you must have an SMTP server configured in the SentinelOne solution (/settings/smtp see Set SMTP Settings).
Deep Visibility requires a Complete SKU.

Required permissions: `Deep Visibility.create`

Parameters:
- `body` [body, filters.filters_NewDeepVisibilityFilterSchema] — 

Responses: 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `DELETE /web/api/v2.1/filters/dv/{filter_id}`
**[DEPRECATED] Delete Deep Visibility Filter**
`operationId`: `_web_api_filters_dv_{filter_id}_delete`

Delete a saved Deep Visibility query.

Required permissions: `Deep Visibility.delete`

Parameters:
- `filter_id` [path, string] **required** — Filter ID. Example: "225494730938493804".

Responses: 404 Filter not found, 403 User is not allowed to perform this operation., 200 Filter successfully deleted., 401 Unauthorized access - please sign in and retry.

## `PUT /web/api/v2.1/filters/dv/{filter_id}`
**[DEPRECATED] Update Deep Visibility Filter**
`operationId`: `_web_api_filters_dv_{filter_id}_put`

Change a saved Deep Visibility filter. To get the ID and fields to change, run Get Deep Visibility Filters.

Required permissions: `Deep Visibility.edit`

Parameters:
- `filter_id` [path, string] **required** — Filter ID. Example: "225494730938493804".
- `body` [body, filters.filters_NewDeepVisibilityFilterSchema] — 

Responses: 404 Filter not found, 403 User is not allowed to perform this operation., 200 Filter successfully updated. Returns updated object., 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `DELETE /web/api/v2.1/filters/{filter_id}`
**Delete Filter**
`operationId`: `_web_api_filters_{filter_id}_delete`

Delete a saved filter.

Required permissions: `Endpoints.edit`

Parameters:
- `filter_id` [path, string] **required** — Filter ID. Example: "225494730938493804".

Responses: 404 Filter not found, 403 User is not allowed to perform this operation., 200 Filter successfully deleted., 401 Unauthorized access - please sign in and retry.

## `PUT /web/api/v2.1/filters/{filter_id}`
**Update Filter**
`operationId`: `_web_api_filters_{filter_id}_put`

Update an existing filter

Required permissions: `Endpoints.edit`

Parameters:
- `filter_id` [path, string] **required** — Filter ID. Example: "225494730938493804".
- `body` [body, filters.filters_UpdateFilterSchema] — 

Responses: 404 Filter not found, 403 User is not allowed to perform this operation., 200 Filter successfully updated. Returns updated object., 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/xdr/filters`
**Get Filters**
`operationId`: `_web_api_xdr_filters_get`

Get the list of saved filters. See Save Filter. The response includes the ID of the filter, which you can use in other commands.

Required permissions: `XDR Inventory.view`

Parameters:
- `skip` [query, integer] — Skip first number of items (0-1000). To iterate over more than 1000 items,  use "cursor".
- `sortOrder` [query, string] (enum: asc, desc) — Sort direction
- `accountIds` [query, array] — List of Account IDs to filter by
- `query` [query, string] — Text query for filter's name
- `limit` [query, integer] — Limit number of returned items (1-1000)
- `includeChildren` [query, boolean] — Return filters from children scope levels (Default: false)
- `ids` [query, array] — A list of Filter IDs
- `includeParents` [query, boolean] — Return filters from parent scope levels (Default: false)
- `countOnly` [query, boolean] — If true, only total number of items will be returned, without any of the actual objects.
- `siteIds` [query, array] — List of Site IDs to filter by
- `cursor` [query, string] — Cursor position returned by the last request. Use to iterate over more than 1000 items.
- `skipCount` [query, boolean] — If true, total number of items will not be calculated, which speeds up execution time.
- `sortBy` [query, string] (enum: id, name, createdAt, updatedAt) — The column to sort the results by.

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/xdr/filters`
**Save Filter**
`operationId`: `_web_api_xdr_filters_post`

Save a new filter to get a list of matching endpoints. When you save a filter, you can run actions on the Agents as a set of objects or create a dynamic group (automatically adds new Agents that match the filter and drops Agents if they change to not match).
For example, you can save a filter with {"data":{"filterFields":{"infected":true}}} to run kill and quarantine commands on all the Agents at once, or to create a group that holds currently infected endpoints. Best Practice: Set a scope for the new Saved Filter. Run "accounts", "sites", or "groups" to get the IDs for the scope.

Required permissions: `XDR Inventory.edit`

Parameters:
- `body` [body, v2_1.config.schemas_NewFilterSchema] — 

Responses: 403 User is not allowed to perform this operation., 200 Filter successfully saved. Returns created object., 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `DELETE /web/api/v2.1/xdr/filters/{filter_id}`
**Delete Filter**
`operationId`: `_web_api_xdr_filters_{filter_id}_delete`

Delete a saved filter.

Required permissions: `XDR Inventory.edit`

Parameters:
- `filter_id` [path, string] **required** — Filter ID

Responses: 404 Filter not found, 403 User is not allowed to perform this operation., 200 Filter successfully deleted., 401 Unauthorized access - please sign in and retry.

## `PUT /web/api/v2.1/xdr/filters/{filter_id}`
**Update Filter**
`operationId`: `_web_api_xdr_filters_{filter_id}_put`

Update an existing filter

Required permissions: `XDR Inventory.edit`

Parameters:
- `filter_id` [path, string] **required** — Filter ID
- `body` [body, v2_1.config.schemas_UpdateFilterSchema] — 

Responses: 404 Filter not found, 403 User is not allowed to perform this operation., 200 Filter successfully updated. Returns updated object., 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/xdr/private/filters/enriched`
**Filters with Metadata**
`operationId`: `_web_api_xdr_private_filters_enriched_get`

Get a list of saved endpoint filters, with enriched data. One of the fields in the response is the ID of each filter, which you will need in other commands.

Required permissions: `XDR Inventory.view`

Parameters:
- `skip` [query, integer] — Skip first number of items (0-1000). To iterate over more than 1000 items,  use "cursor".
- `sortOrder` [query, string] (enum: asc, desc) — Sort direction
- `accountIds` [query, array] — List of Account IDs to filter by
- `query` [query, string] — Text query for filter's name
- `limit` [query, integer] — Limit number of returned items (1-1000)
- `includeChildren` [query, boolean] — Return filters from children scope levels (Default: false)
- `ids` [query, array] — A list of Filter IDs
- `includeParents` [query, boolean] — Return filters from parent scope levels (Default: false)
- `countOnly` [query, boolean] — If true, only total number of items will be returned, without any of the actual objects.
- `siteIds` [query, array] — List of Site IDs to filter by
- `cursor` [query, string] — Cursor position returned by the last request. Use to iterate over more than 1000 items.
- `skipCount` [query, boolean] — If true, total number of items will not be calculated, which speeds up execution time.
- `sortBy` [query, string] (enum: id, name, createdAt, updatedAt) — The column to sort the results by.

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.
