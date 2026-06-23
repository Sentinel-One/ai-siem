# overview

1 endpoints.

## `POST /web/api/v2.1/xdr/assets/overview`
**Cloud Inventory resource overview**
`operationId`: `_web_api_xdr_assets_overview_post`

Get overview of a resource belonging to a category

Required permissions: `XDR Inventory.view`

Parameters:
- `accountIds` [query, array] — List of Account IDs to filter by
- `siteIds` [query, array] — List of Site IDs to filter by
- `groupIds` [query, array] — List of Group IDs to filter by
- `body` [body, v2_1.inventory.overview.schemas_InventoryOverviewJsonSchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.
