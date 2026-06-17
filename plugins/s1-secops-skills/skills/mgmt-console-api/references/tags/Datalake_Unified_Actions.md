# Datalake Unified Actions

4 endpoints.

## `POST /web/api/v2.1/xdr/action-controller/fetch-surface-ids`
**Fetch surface ids in case of select all with filters**
`operationId`: `_web_api_xdr_action-controller_fetch-surface-ids_post`

Fetch surface ids in case of select all with filters

Required permissions: `XDR Inventory.view`

Parameters:
- `accountIds` [query, array] — List of Account IDs to filter by
- `siteIds` [query, array] — List of Site IDs to filter by
- `groupIds` [query, array] — List of Group IDs to filter by
- `body` [body, v2_1.action_controller.schemas_FetchSurfaceIdsRequestSchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/xdr/action-controller/fetch-unified-actions`
**Get Available Actions by Asset/Entity Type**
`operationId`: `_web_api_xdr_action-controller_fetch-unified-actions_post`

Get Available Actions by Asset/Entity Type

Required permissions: `XDR Inventory.view`

Parameters:
- `accountIds` [query, array] — List of Account IDs to filter by
- `siteIds` [query, array] — List of Site IDs to filter by
- `groupIds` [query, array] — List of Group IDs to filter by
- `body` [body, v2_1.action_controller.schemas_AffectedEntitiesSchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/xdr/action-controller/perform-unified-action`
**Perform an Action on selected assets/entities**
`operationId`: `_web_api_xdr_action-controller_perform-unified-action_post`

Perform an Action on selected assets/entities

Required permissions: `XDR Inventory.create, XDR Inventory.edit`

Parameters:
- `accountIds` [query, array] — List of Account IDs to filter by
- `siteIds` [query, array] — List of Site IDs to filter by
- `groupIds` [query, array] — List of Group IDs to filter by
- `body` [body, v2_1.action_controller.schemas_PerformActionRequestSchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/xdr/action-controller/perform-unified-action/notify`
**Internal api only to notify action was triggered without actually performing it**
`operationId`: `_web_api_xdr_action-controller_perform-unified-action_notify_post`

Internal api only to notify action was triggered without actually performing it

Required permissions: `XDR Inventory.create, XDR Inventory.edit`

Parameters:
- `accountIds` [query, array] — List of Account IDs to filter by
- `siteIds` [query, array] — List of Site IDs to filter by
- `groupIds` [query, array] — List of Group IDs to filter by
- `body` [body, v2_1.action_controller.schemas_PerformActionNotificationSchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.
