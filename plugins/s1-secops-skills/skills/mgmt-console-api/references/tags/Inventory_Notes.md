# Inventory Notes

2 endpoints.

## `DELETE /web/api/v2.1/xdr/assets/notes`
**Delete note**
`operationId`: `_web_api_xdr_assets_notes_delete`

Delete note

Required permissions: `XDR Inventory.delete`

Parameters:
- `accountIds` [query, array] — List of Account IDs to filter by
- `siteIds` [query, array] — List of Site IDs to filter by
- `groupIds` [query, array] — List of Group IDs to filter by
- `body` [body, v2_1.inventory.notes.schemas_InventoryNotesPayloadSchema] — 

Responses: 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/xdr/assets/notes`
**Create or update note against asset**
`operationId`: `_web_api_xdr_assets_notes_post`

create or update note

Required permissions: `XDR Inventory.create`

Parameters:
- `accountIds` [query, array] — List of Account IDs to filter by
- `siteIds` [query, array] — List of Site IDs to filter by
- `groupIds` [query, array] — List of Group IDs to filter by
- `body` [body, v2_1.inventory.notes.schemas_InventoryNotesPayloadSchema] — 

Responses: 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.
