# Service Users

8 endpoints.

## `GET /web/api/v2.1/export/service-users`
**Export Service Users**
`operationId`: `_web_api_export_service-users_get`

Export Service User data to a CSV, for Service Users that match the filter.

Required permissions: `Service Users.view`

Parameters:
- `siteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "225494730938493804,225494730938493915".
- `ids` [query, array] — List of service user IDs to filter by. Example: "225494730938493804,225494730938493915".
- `query` [query, string] — Full text search for fields: full_name, email, description
- `roleIds` [query, array] — List of rbac roles to filter by. Example: "225494730938493804,225494730938493915".

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/service-users`
**Get Service Users**
`operationId`: `_web_api_service-users_get`

Get a list of service users.

Required permissions: `Service Users.view`

Parameters:
- `skip` [query, integer] — Skip first number of items (0-1000). To iterate over more than 1000 items,  use "cursor". Example: "150".
- `limit` [query, integer] — Limit number of returned items (1-1000). Example: "10".
- `cursor` [query, string] — Cursor position returned by the last request. Use to iterate over more than 1000 items. Example: "YWdlbnRfaWQ6NTgwMjkzODE=".
- `countOnly` [query, boolean] — If true, only total number of items will be returned, without any of the actual objects.
- `skipCount` [query, boolean] — If true, total number of items will not be calculated, which speeds up execution time.
- `sortBy` [query, string] (enum: id, createdAt, updatedAt, name, fullName, description, firstLogin, lastLogin, dateJoined, roleId, apiTokenCreatedAt, apiTokenExpiresAt, lastActivation, createdByName, updatedByName) — The column to sort the results by. Example: "id".
- `sortOrder` [query, string] (enum: asc, desc) — Sort direction. Example: "asc".
- `siteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "225494730938493804,225494730938493915".
- `ids` [query, array] — List of service user IDs to filter by. Example: "225494730938493804,225494730938493915".
- `query` [query, string] — Full text search for fields: full_name, email, description
- `roleIds` [query, array] — List of rbac roles to filter by. Example: "225494730938493804,225494730938493915".

Responses: 401 Unauthorized access - please sign in and retry., 200 List of service users retrieved successfully., 400 Invalid user input received. See error details for further i

## `POST /web/api/v2.1/service-users`
**Create Service User**
`operationId`: `_web_api_service-users_post`

Create a new service user.

Required permissions: `Service Users.create`

Parameters:
- `body` [body, service_users.schemas_CreateServiceUserSchema] — 

Responses: 403 Not enough permissions to create service user., 200 Service User created successfully., 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/service-users/delete-service-users`
**Bulk Delete Service Users**
`operationId`: `_web_api_service-users_delete-service-users_post`

Delete all service users that match the filter.

Required permissions: `Service Users.delete`

Parameters:
- `body` [body, service_users.schemas_BulkDeleteServiceUsersSchema] — 

Responses: 403 Insufficient permissions., 200 Service Users deleted successfully., 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `DELETE /web/api/v2.1/service-users/{service_user_id}`
**Delete Service User**
`operationId`: `_web_api_service-users_{service_user_id}_delete`

Delete a service user by ID.

Required permissions: `Service Users.delete`

Parameters:
- `service_user_id` [path, string] **required** — Service User ID. Example: "225494730938493804".

Responses: 403 Insufficient permissions., 200 Service User deleted successfully., 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/service-users/{service_user_id}`
**Get Service User**
`operationId`: `_web_api_service-users_{service_user_id}_get`

Get a specific service user by ID.

Required permissions: `Service Users.view`

Parameters:
- `service_user_id` [path, string] **required** — Service User ID. Example: "225494730938493804".

Responses: 404 Service User not found., 401 Unauthorized access - please sign in and retry., 200 Service user retrieved successfully.

## `PUT /web/api/v2.1/service-users/{service_user_id}`
**Update Service User**
`operationId`: `_web_api_service-users_{service_user_id}_put`

Change properties of the service user with the given ID.

Required permissions: `Service Users.edit`

Parameters:
- `service_user_id` [path, string] **required** — Service User ID. Example: "225494730938493804".
- `body` [body, service_users.schemas_UpdateServiceUserSchema] — 

Responses: 404 Service User not found., 403 Forbidden., 200 Service User updated successfully., 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/service-users/{service_user_id}/generate-api-token`
**Generate API Token for Service User**
`operationId`: `_web_api_service-users_{service_user_id}_generate-api-token_post`

Generate a new API token for a service user and revoke the existing API token.

Required permissions: `Service Users.edit`

Parameters:
- `service_user_id` [path, string] **required** — Service User ID. Example: "225494730938493804".
- `body` [body, service_users.schemas_GenerateServiceUserApiTokenSchema] — 

Responses: 409 API token creation conflict., 404 Service User not found., 403 Forbidden., 200 API token delivered to user., 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.
