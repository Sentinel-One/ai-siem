# RBAC

6 endpoints.

## `GET /web/api/v2.1/rbac/role`
**Get template for new role**
`operationId`: `_web_api_rbac_role_get`

Get the template for a new role.

Required permissions: `Roles.view`

Parameters:
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "225494730938493804,225494730938493915".
- `siteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `groupIds` [query, array] — List of Group IDs to filter by. Example: "225494730938493804,225494730938493915".
- `tenant` [query, boolean] — Indicates a tenant scope request

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/rbac/role`
**Create new role**
`operationId`: `_web_api_rbac_role_post`

Create a new role for Role-Based Access Control (RBAC).

Required permissions: `Roles.create`

Parameters:
- `body` [body, rbac.schemas_RbacCreateRoleSchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `DELETE /web/api/v2.1/rbac/role/{role_id}`
**Delete role**
`operationId`: `_web_api_rbac_role_{role_id}_delete`

With the ID of a role (see Get All Roles), you can delete a role. If there are users assigned to the role, specify the ID of their new role.

Required permissions: `Roles.delete`
Optional permissions: `Users.edit`

Parameters:
- `role_id` [path, string] **required** — Role ID. Example: "225494730938493804".
- `body` [body, rbac.schemas_RbacDeleteRoleSchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/rbac/role/{role_id}`
**Get Specific Role Definition**
`operationId`: `_web_api_rbac_role_{role_id}_get`

With the ID of a role (see Get All Roles) you can see the permissions of that role. <br>The definition of a role can change in different scopes and SKUs. For example, an Admin role with the scope access of a Site does not have Network Discovery permissions, but an IT role with the scope access of an Account with a Network Discovery license does have permissions on Network Discovery. <br>The Response shows role permissions to see views in the WebUI and to use Console features.

Required permissions: `Roles.view`

Parameters:
- `role_id` [path, string] **required** — Role ID. Example: "225494730938493804".
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "225494730938493804,225494730938493915".
- `siteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `groupIds` [query, array] — List of Group IDs to filter by. Example: "225494730938493804,225494730938493915".
- `tenant` [query, boolean] — Indicates a tenant scope request
- `name` [query, string] — Return RBAC role matching the name
- `createdAt__lt` [query, string] — Return RBAC roles created before this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__gt` [query, string] — Return RBAC roles created after this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__lte` [query, string] — Return RBAC roles created before or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__gte` [query, string] — Return RBAC roles created after or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__between` [query, string] — Return RBAC roles created within this range (inclusive). Example: "1514978764288-1514978999999".
- `updatedAt__lt` [query, string] — Return RBAC roles updated before this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `updatedAt__gt` [query, string] — Return RBAC roles updated after this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `updatedAt__lte` [query, string] — Return RBAC roles updated before or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `updatedAt__gte` [query, string] — Return RBAC roles updated after or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `updatedAt__between` [query, string] — Return RBAC roles updated within this range (inclusive). Example: "1514978764288-1514978999999".
- `query` [query, string] — Free text search on role name, and description

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `PUT /web/api/v2.1/rbac/role/{role_id}`
**Update role**
`operationId`: `_web_api_rbac_role_{role_id}_put`

With the ID of a role (see Get All Roles), you can update the permissions of users with this role.

Required permissions: `Roles.edit`

Parameters:
- `role_id` [path, string] **required** — Role ID. Example: "225494730938493804".
- `body` [body, rbac.schemas_RbacUpdateRoleSchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/rbac/roles`
**Get All Roles**
`operationId`: `_web_api_rbac_roles_get`

See roles assigned to users that match the filter, a basic description of the roles, and the number of users for each role. <br>Role-Based Access Control (RBAC) has predefined roles. (Currently, customized roles are not supported.), This command gives the ID of the role, which you can use in other commands.

Required permissions: `Roles.view`

Parameters:
- `skip` [query, integer] — Skip first number of items (0-1000). To iterate over more than 1000 items,  use "cursor". Example: "150".
- `limit` [query, integer] — Limit number of returned items (1-1000). Example: "10".
- `cursor` [query, string] — Cursor position returned by the last request. Use to iterate over more than 1000 items. Example: "YWdlbnRfaWQ6NTgwMjkzODE=".
- `countOnly` [query, boolean] — If true, only total number of items will be returned, without any of the actual objects.
- `skipCount` [query, boolean] — If true, total number of items will not be calculated, which speeds up execution time.
- `sortBy` [query, string] (enum: id, description, usersInRoles, creator, siteName, createdAt, updatedAt, updatedBy, accountName, name) — The column to sort the results by. Example: "id".
- `sortOrder` [query, string] (enum: asc, desc) — Sort direction. Example: "asc".
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "225494730938493804,225494730938493915".
- `siteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `groupIds` [query, array] — List of Group IDs to filter by. Example: "225494730938493804,225494730938493915".
- `tenant` [query, boolean] — Indicates a tenant scope request
- `name` [query, string] — Return RBAC role matching the name
- `createdAt__lt` [query, string] — Return RBAC roles created before this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__gt` [query, string] — Return RBAC roles created after this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__lte` [query, string] — Return RBAC roles created before or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__gte` [query, string] — Return RBAC roles created after or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__between` [query, string] — Return RBAC roles created within this range (inclusive). Example: "1514978764288-1514978999999".
- `updatedAt__lt` [query, string] — Return RBAC roles updated before this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `updatedAt__gt` [query, string] — Return RBAC roles updated after this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `updatedAt__lte` [query, string] — Return RBAC roles updated before or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `updatedAt__gte` [query, string] — Return RBAC roles updated after or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `updatedAt__between` [query, string] — Return RBAC roles updated within this range (inclusive). Example: "1514978764288-1514978999999".
- `query` [query, string] — Free text search on role name, and description
- `ids` [query, array] — List of ids to filter by. Example: "225494730938493804,225494730938493915".
- `tenancyIds` [query, array] — List of Tenancies IDs to filter by. Example: "225494730938493804,225494730938493915".
- `creator` [query, string] — Email of the creating user
- `creatorId` [query, string] — Id of the creating user. Example: "225494730938493804".
- `updatedBy` [query, string] — Email of the updating user
- `updatedById` [query, string] — Id of the updating user. Example: "225494730938493804".
- `createdAt` [query, string] — Created at. Example: "2018-02-27T04:49:26.257525Z".
- `updatedAt` [query, string] — Updated at. Example: "2018-02-27T04:49:26.257525Z".
- `description` [query, string] — Description
- `accountName` [query, string] — Name of the account that contains the role
- `siteName` [query, string] — Name of the site that contains the role
- `includeParents` [query, boolean] — Include parent scopes roles
- `includeChildren` [query, boolean] — Include child scopes roles
- `predefinedRole` [query, boolean] — Filter only system/custom roles

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.
