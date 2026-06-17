# Cloud Resources

2 endpoints.

## `GET /web/api/v2.1/cloudnative/cloud-rogues`
**Get cloud rogue resources**
`operationId`: `_web_api_cloudnative_cloud-rogues_get`

Returns the cloud rogue resources for given filter

Required permissions: `cloudRogues.view`

Parameters:
- `cloudProviderAccountName` [query, array] — Filter by cloud account (supports multiple values)
- `sortBy` [query, string] (enum: id, createdTime, resourceType, name, region, virtualNetworkId, imageId, osType, cloudProviderAccountName, cloudProviderAccountId, cloudProviderOrganization, cloudProviderName) — The column to sort the results by. Example: "id".
- `name__contains` [query, array] — Free-text filter by resource name (supports multiple values)
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "225494730938493804,225494730938493915".
- `virtualNetworkId__contains` [query, array] — Free-text filter by network id (supports multiple values)
- `cursor` [query, string] — Cursor position returned by the last request. Use to iterate over more than 1000 items. Example: "YWdlbnRfaWQ6NTgwMjkzODE=".
- `cloudProviderName` [query, array] — Filter by cloud provider name (supports multiple values)
- `region` [query, array] — Filter by region (supports multiple values)
- `sortOrder` [query, string] (enum: asc, desc) — Sort direction. Example: "asc".
- `imageId__contains` [query, array] — Free-text filter by image (supports multiple values)
- `osTypes` [query, array] — Included OS types
- `region__contains` [query, array] — Free-text filter by region (supports multiple values)
- `concatenatedTags__contains` [query, array] — Free-text filter by tags (supports multiple values)
- `id__contains` [query, array] — Free-text filter by id (supports multiple values)
- `siteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `skipCount` [query, boolean] — If true, total number of items will not be calculated, which speeds up execution time.
- `cloudProviderAccountId__contains` [query, array] — Free-text filter by cloud account id (supports multiple values)
- `limit` [query, integer] — Limit number of returned items (1-1000). Example: "10".
- `countOnly` [query, boolean] — If true, only total number of items will be returned, without any of the actual objects.
- `cloudProviderAccountName__contains` [query, array] — Free-text filter by cloud account (supports multiple values)
- `skip` [query, integer] — Skip first number of items (0-1000). To iterate over more than 1000 items,  use "cursor". Example: "150".

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/cloudnative/cloud-rogues/export`
**Export cloud rogue resources to csv (default) or json**
`operationId`: `_web_api_cloudnative_cloud-rogues_export_get`

Returns the results for given cloud rogues filter in a csv (default) or json format

Required permissions: `cloudRogues.view`

Parameters:
- `cloudProviderAccountName` [query, array] — Filter by cloud account (supports multiple values)
- `sortBy` [query, string] (enum: id, createdTime) — The column to sort the results by. Example: "id".
- `name__contains` [query, array] — Free-text filter by resource name (supports multiple values)
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "225494730938493804,225494730938493915".
- `virtualNetworkId__contains` [query, array] — Free-text filter by network id (supports multiple values)
- `cursor` [query, string] — Cursor position returned by the last request. Use to iterate over more than 1000 items. Example: "YWdlbnRfaWQ6NTgwMjkzODE=".
- `cloudProviderName` [query, array] — Filter by cloud provider name (supports multiple values)
- `region` [query, array] — Filter by region (supports multiple values)
- `sortOrder` [query, string] (enum: asc, desc) — Sort direction. Example: "asc".
- `imageId__contains` [query, array] — Free-text filter by image (supports multiple values)
- `osTypes` [query, array] — Included OS types
- `region__contains` [query, array] — Free-text filter by region (supports multiple values)
- `concatenatedTags__contains` [query, array] — Free-text filter by tags (supports multiple values)
- `id__contains` [query, array] — Free-text filter by id (supports multiple values)
- `siteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `skipCount` [query, boolean] — If true, total number of items will not be calculated, which speeds up execution time.
- `cloudProviderAccountId__contains` [query, array] — Free-text filter by cloud account id (supports multiple values)
- `limit` [query, integer] — Limit number of returned items (1-1000). Example: "10".
- `countOnly` [query, boolean] — If true, only total number of items will be returned, without any of the actual objects.
- `exportFormat` [query, string] (enum: csv, json) — Export format. Example: "csv".
- `cloudProviderAccountName__contains` [query, array] — Free-text filter by cloud account (supports multiple values)
- `skip` [query, integer] — Skip first number of items (0-1000). To iterate over more than 1000 items,  use "cursor". Example: "150".

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.
