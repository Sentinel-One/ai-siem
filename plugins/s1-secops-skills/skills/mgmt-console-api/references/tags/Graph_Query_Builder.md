# Graph Query Builder

8 endpoints.

## `GET /web/api/v2.1/xdr/assets/query/builder/metadata`
**Get Graph Query Builder Initial Metadata**
`operationId`: `_web_api_xdr_assets_query_builder_metadata_get`

Get graph query builder initial metadata

Required permissions: `XDR Inventory.view`

Parameters:
- `accountIds` [query, array] — List of Account IDs to filter by
- `siteIds` [query, array] — List of Site IDs to filter by
- `groupIds` [query, array] — List of Group IDs to filter by

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/xdr/graph-explorer/query/builder/autocomplete`
**Auto Complete**
`operationId`: `_web_api_xdr_graph-explorer_query_builder_autocomplete_get`

This api is now deprecated use /xdr/graph-explorer/query/builder/autocomplete/v2 instead.

Required permissions: `XDR Inventory.view`

Parameters:
- `ids` [query, array] — List of asset type ids
- `groupIds` [query, array] — List of Group IDs to filter by
- `accountIds` [query, array] — List of Account IDs to filter by
- `text` [query, string] — Search term text
- `version` [query, string] — Version
- `limit` [query, integer] — Limit number of returned items
- `subCategoriesIds` [query, array] — List of subCategory ids
- `key` [query, string] **required** — Search field key
- `categoryIds` [query, array] — List of category ids
- `siteIds` [query, array] — List of Site IDs to filter by

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/xdr/graph-explorer/query/builder/autocomplete/v2`
**Auto Complete**
`operationId`: `_web_api_xdr_graph-explorer_query_builder_autocomplete_v2_get`

Use this command to get values for other fields. When you send this command with input text and a field name, it returns auto-complete suggestions for the field.

Required permissions: `XDR Inventory.view`

Parameters:
- `ids` [query, array] — List of asset type ids
- `groupIds` [query, array] — List of Group IDs to filter by
- `accountIds` [query, array] — List of Account IDs to filter by
- `text` [query, string] — Search term text
- `version` [query, string] — Version
- `limit` [query, integer] — Limit number of returned items
- `subCategoriesIds` [query, array] — List of subCategory ids
- `key` [query, string] **required** — Search field key
- `categoryIds` [query, array] — List of category ids
- `siteIds` [query, array] — List of Site IDs to filter by

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/xdr/graph-explorer/query/builder/metadata`
**Get Graph Query Builder Initial Metadata**
`operationId`: `_web_api_xdr_graph-explorer_query_builder_metadata_get`

Get graph query builder initial metadata

Required permissions: `XDR Inventory.view`

Parameters:
- `accountIds` [query, array] — List of Account IDs to filter by
- `siteIds` [query, array] — List of Site IDs to filter by
- `groupIds` [query, array] — List of Group IDs to filter by

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/xdr/graph-explorer/query/builder/metadata/available-options/v2`
**Get Query Builder metadata For Requested Resource Types**
`operationId`: `_web_api_xdr_graph-explorer_query_builder_metadata_available-options_v2_get`

Get query builder metadata for requested cloud asset types

Required permissions: `XDR Inventory.view`

Parameters:
- `ids` [query, array] — List of asset type ids
- `groupIds` [query, array] — List of Group IDs to filter by
- `accountIds` [query, array] — List of Account IDs to filter by
- `version` [query, string] — Version
- `subCategoriesIds` [query, array] — List of subCategory ids
- `categoryIds` [query, array] — List of category ids
- `siteIds` [query, array] — List of Site IDs to filter by

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/xdr/graph-explorer/query/builder/metadata/available-relations`
**Get the available relations**
`operationId`: `_web_api_xdr_graph-explorer_query_builder_metadata_available-relations_get`

Get the available relations

Required permissions: `XDR Inventory.view`

Parameters:
- `accountIds` [query, array] — List of Account IDs to filter by
- `siteIds` [query, array] — List of Site IDs to filter by
- `groupIds` [query, array] — List of Group IDs to filter by

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/xdr/graph-explorer/query/builder/tag/autocomplete`
**Tag Auto Complete**
`operationId`: `_web_api_xdr_graph-explorer_query_builder_tag_autocomplete_post`

Use this command to get tag keys or values. When you send this command with input value and field name either `key` or `value`, it returns auto-complete suggestions for the field.

Required permissions: `XDR Inventory.view`

Parameters:
- `ids` [query, array] — List of asset type ids
- `groupIds` [query, array] — List of Group IDs to filter by
- `accountIds` [query, array] — List of Account IDs to filter by
- `field` [query, string] **required** (enum: key, value) — Search in keys or values
- `version` [query, string] — Version
- `value` [query, string] — Search term value
- `limit` [query, integer] — Limit number of returned items
- `subCategoriesIds` [query, array] — List of subCategory ids
- `categoryIds` [query, array] — List of category ids
- `siteIds` [query, array] — List of Site IDs to filter by

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/xdr/private/graph-services-features`
**Get all of the feature toggles for graph services.**
`operationId`: `_web_api_xdr_private_graph-services-features_get`

Get all of the feature toggles for graph services

Required permissions: `XDR Inventory.view`

Parameters:
- `accountIds` [query, array] — List of Account IDs to filter by
- `siteIds` [query, array] — List of Site IDs to filter by
- `groupIds` [query, array] — List of Group IDs to filter by

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.
