# Sentinel Deploy

7 endpoints.

## `GET /web/api/v2.1/ranger/cred-groups`
**Get Cred groups**
`operationId`: `_web_api_ranger_cred-groups_get`

Get the data for each row in the Cred Groups table.

Required permissions: `Ranger.view`

Parameters:
- `skip` [query, integer] — Skip first number of items (0-1000). To iterate over more than 1000 items,  use "cursor". Example: "150".
- `limit` [query, integer] — Limit number of returned items (1-1000). Example: "10".
- `cursor` [query, string] — Cursor position returned by the last request. Use to iterate over more than 1000 items. Example: "YWdlbnRfaWQ6NTgwMjkzODE=".
- `countOnly` [query, boolean] — If true, only total number of items will be returned, without any of the actual objects.
- `skipCount` [query, boolean] — If true, total number of items will not be calculated, which speeds up execution time.
- `sortBy` [query, string] (enum: groupName, updatedAt, createdAt, domain, targetOs) — The column to sort the results by. Example: "id".
- `sortOrder` [query, string] (enum: asc, desc) — Sort direction. Example: "asc".
- `accountIds` [query, array] — Single Account ID to filter by. Example: "225494730938493804".
- `siteIds` [query, array] — Single Site ID to filter by. Example: "225494730938493804".
- `groupName` [query, string] — Group name being searched
- `groupNameLike` [query, string] — Group name being searched
- `ids` [query, array] — A list of ids to get
- `totalDetails__gt` [query, integer] — Get creds with total details greater than the supplied number
- `targetOs` [query, string] (enum: windows, osx_linux) — The os type for this cred group. Example: "windows".

Responses: 403 Insufficient permissions, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/ranger/cred-groups`
**Create Cred Group**
`operationId`: `_web_api_ranger_cred-groups_post`

Create a new Cred Group.

Required permissions: `Ranger.manageCredentials`

Parameters:
- `body` [body, ranger.auto_deploy_schemas_CredGroupsPostSchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/ranger/cred-groups/details`
**Get Cred group details**
`operationId`: `_web_api_ranger_cred-groups_details_get`

Get the data for each row in the Cred Groups details table.

Required permissions: `Ranger.view`

Parameters:
- `skip` [query, integer] — Skip first number of items (0-1000). To iterate over more than 1000 items,  use "cursor". Example: "150".
- `limit` [query, integer] — Limit number of returned items (1-1000). Example: "10".
- `cursor` [query, string] — Cursor position returned by the last request. Use to iterate over more than 1000 items. Example: "YWdlbnRfaWQ6NTgwMjkzODE=".
- `countOnly` [query, boolean] — If true, only total number of items will be returned, without any of the actual objects.
- `skipCount` [query, boolean] — If true, total number of items will not be calculated, which speeds up execution time.
- `sortBy` [query, string] (enum: title, type, updatedAt, createdAt, credType) — The column to sort the results by. Example: "id".
- `sortOrder` [query, string] (enum: asc, desc) — Sort direction. Example: "asc".
- `accountIds` [query, array] — Single Account ID to filter by. Example: "225494730938493804".
- `siteIds` [query, array] — Single Site ID to filter by. Example: "225494730938493804".
- `title` [query, string] — Exact filter by title
- `titleLike` [query, string] — Like filter by title
- `credTypeLike` [query, string] — The type of the cred group
- `ids` [query, array] — A list of ids to get
- `credGroupIds` [query, array] — A list of ids to get

Responses: 403 Insufficient permissions, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/ranger/cred-groups/details`
**Add cred details**
`operationId`: `_web_api_ranger_cred-groups_details_post`

Add cred details to a cred group.

Required permissions: `Ranger.manageCredentials`

Parameters:
- `body` [body, ranger.auto_deploy_schemas_CredGroupsDetailsPostSchema] — 

Responses: 404 Cred group not found., 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `DELETE /web/api/v2.1/ranger/cred-groups/details/{detail_id}`
**Delete Cred Group Detail**
`operationId`: `_web_api_ranger_cred-groups_details_{detail_id}_delete`

Delete cred group detail value.

Required permissions: `Ranger.manageCredentials`

Parameters:
- `detail_id` [path, string] **required** — Cred group detail ID. Example: "225494730938493804".

Responses: 404 Cred group not found., 200 Success, 401 Unauthorized access - please sign in and retry.

## `PUT /web/api/v2.1/ranger/cred-groups/details/{detail_id}`
**Update Cred Group Details**
`operationId`: `_web_api_ranger_cred-groups_details_{detail_id}_put`

Update cred group values.

Required permissions: `Ranger.manageCredentials`

Parameters:
- `detail_id` [path, string] **required** — Cred group detail ID. Example: "225494730938493804".
- `body` [body, ranger.auto_deploy_schemas_CredPutDetailsSchema] — 

Responses: 404 Cred group not found., 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `DELETE /web/api/v2.1/ranger/cred-groups/{cred_group_id}`
**Delete Cred Group**
`operationId`: `_web_api_ranger_cred-groups_{cred_group_id}_delete`

Delete cred group value.

Required permissions: `Ranger.manageCredentials`

Parameters:
- `cred_group_id` [path, string] **required** — Cred group ID. Example: "225494730938493804".

Responses: 404 Cred group not found., 200 Success, 401 Unauthorized access - please sign in and retry.
