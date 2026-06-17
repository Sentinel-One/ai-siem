# Groups

10 endpoints.

## `GET /web/api/v2.1/groups`
**Get Groups**
`operationId`: `_web_api_groups_get`

Get data of groups that match the filter. Best practice: use as narrow a filter as you can. The data can be quite long for many groups. The response returns the ID of each group, which you can use in other commands.

Required permissions: `Groups.view`

Parameters:
- `skip` [query, integer] — Skip first number of items (0-1000). To iterate over more than 1000 items,  use "cursor". Example: "150".
- `limit` [query, integer] — Limit number of returned items (1-1000). Example: "10".
- `cursor` [query, string] — Cursor position returned by the last request. Use to iterate over more than 1000 items. Example: "YWdlbnRfaWQ6NTgwMjkzODE=".
- `countOnly` [query, boolean] — If true, only total number of items will be returned, without any of the actual objects.
- `skipCount` [query, boolean] — If true, total number of items will not be calculated, which speeds up execution time.
- `sortBy` [query, string] (enum: id, name, type, rank, siteId, createdAt, updatedAt, description) — The column to sort the results by. Example: "id".
- `sortOrder` [query, string] (enum: asc, desc) — Sort direction. Example: "asc".
- `siteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "225494730938493804,225494730938493915".
- `groupIds` [query, array] — List of Group IDs to filter by. Example: "225494730938493804,225494730938493915".
- `type` [query, string] (enum: static, dynamic, pinned) — Group type. Example: "static".
- `types` [query, array] — A list of Group types. Example: "static".
- `query` [query, string] — Free text search on fields name, description
- `id` [query, string] — Id. Example: "225494730938493804".
- `name` [query, string] — Name
- `description` [query, string] — The description for the Group
- `rank` [query, integer] — The rank sets the priority of a dynamic group over others. Example: "1".
- `isDefault` [query, boolean] — Is this the default group?
- `updatedAt__lt` [query, string] — Updated at lesser than. Example: "2018-02-27T04:49:26.257525Z".
- `updatedAt__gt` [query, string] — Updated at greater than. Example: "2018-02-27T04:49:26.257525Z".
- `updatedAt__lte` [query, string] — Updated at lesser or equal than. Example: "2018-02-27T04:49:26.257525Z".
- `updatedAt__gte` [query, string] — Updated at greater or equal than. Example: "2018-02-27T04:49:26.257525Z".
- `registrationToken` [query, string] — Registration token. Example: "eyJ1cmwiOiAiaHR0cHM6Ly9jb25zb2xlLnNlbnRpbmVsb25lLm5ldCIsICJzaXRlX2tleSI6ICIwNzhkYjliMWUyOTA1Y2NhIn0=".

Responses: 200 Data retrieved successfully, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/groups`
**Create Group**
`operationId`: `_web_api_groups_post`

Create a new group. You must create the Group in a Site (run "sites" to get the Site ID) for which you have permissions. If you create a dynamic Group, you must have the ID of a filter saved in the Site (run "filters?siteIds=<id from sites>").

Required permissions: `Groups.create`

Parameters:
- `body` [body, groups_PostGroupSchema] — 

Responses: 403 Insufficient permissions, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `PUT /web/api/v2.1/groups/ranks`
**Update Ranks**
`operationId`: `_web_api_groups_ranks_put`

An Agent can belong to only one Group. If the Agent matches multiple Dynamic Groups, it goes to the Group with the highest rank. The "rank" parameter has a minimum of "1". The lower the integer, the higher priority it has to collect Agents. Make sure the IDs of the groups in this command are for Dynamic groups.

Required permissions: `Groups.edit`

Parameters:
- `body` [body, groups_PutRanksSchema] — 

Responses: 403 Insufficient permissions, 204 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `DELETE /web/api/v2.1/groups/{group_id}`
**Delete Group**
`operationId`: `_web_api_groups_{group_id}_delete`

Delete a Group given by the required Group ID (run "groups"). If there are Agents in the Group, and the Group is dynamic, the next dynamic Groups will collect matching Agents, and unmatched Agents will go to the Default Group. If this is a static Group with Agents, all the Agents will go to the Default Group. (Agents always go to matching dynamic Groups. If a static Group holds Agents, there are no matching dynamic Groups.)

Required permissions: `Groups.delete`

Parameters:
- `group_id` [path, string] **required** — Group ID. Example: "225494730938493804".

Responses: 404 Group not found., 200 Success, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/groups/{group_id}`
**Get Group by ID**
`operationId`: `_web_api_groups_{group_id}_get`

Get data of a given Group. To get a Group ID, run "groups". This command responds with the ID of the Site of the Group, Group name, type (dynamic or static), and similar data. Your username must permissions for the Site.

Required permissions: `Groups.view`

Parameters:
- `group_id` [path, string] **required** — Group ID. Example: "225494730938493804".

Responses: 403 Insufficient permissions, 200 Success, 401 Unauthorized access - please sign in and retry.

## `PUT /web/api/v2.1/groups/{group_id}`
**Update Group**
`operationId`: `_web_api_groups_{group_id}_put`

Change properties of a Group specified by its ID (run "groups"). The body of the request holds all the properties of a Group. You must have access permissions on the Site. Note: iocAttributes refers to Deep Visibility. If you do not have a Complete SKU, you can remove this set.

Required permissions: `Groups.edit`

Parameters:
- `group_id` [path, string] **required** — Group ID. Example: "225494730938493804".
- `body` [body, groups_PutGroupSchema] — 

Responses: 404 Group not found., 403 Insufficient permissions., 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `PUT /web/api/v2.1/groups/{group_id}/move-agents`
**Move Agents**
`operationId`: `_web_api_groups_{group_id}_move-agents_put`

Move Agents that match the filter to a Group. The Group ID (run "groups") is required and there can be only one. This will move the matched Agents that are in the same Site as the given Group.

Required permissions: `Groups.moveToGroup`

Parameters:
- `group_id` [path, string] **required** — Group ID. Example: "225494730938493804".
- `body` [body, groups_PutAddAgentsSchema] — 

Responses: 409 Conflict, 403 Insufficient permissions, 204 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `PUT /web/api/v2.1/groups/{group_id}/regenerate-key`
**Regenerate Group Token**
`operationId`: `_web_api_groups_{group_id}_regenerate-key_put`

Get a new Group Token for a static Group. This command requires the Group ID ("groups") and you must have permissions for the Group. If you run this command on a dynamic Group, it ends in an error. If you use the API in scripts to add new endpoints with a Group Token rather than a Site Token, be aware that you must update the token value in your scripts.

Required permissions: `Groups.edit`

Parameters:
- `group_id` [path, string] **required** — Group ID. Example: "225494730938493804".

Responses: 403 No permission for regenerating a key., 404 Group not found, 200 Success, 401 Unauthorized access - please sign in and retry.

## `PUT /web/api/v2.1/groups/{group_id}/revert-policy`
**Revert Policy**
`operationId`: `_web_api_groups_{group_id}_revert-policy_put`

A Group can have a policy that is different from its Site policy. Use this command to revert the changes on the Group policy to inherit the Site policy. Your user must have permissions on the Site.

Required permissions: `Policy.edit`

Parameters:
- `group_id` [path, string] **required** — Group ID. Example: "225494730938493804".
- `body` [body, policies_schemas_RevertPolicySchema] — 

Responses: 403 Insufficient permissions, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/groups/{group_id}/token`
**Get Site registration token by ID**
`operationId`: `_web_api_groups_{group_id}_token_get`

Get the registration token of the Group of the ID.

Required permissions: `Groups.view`

Parameters:
- `group_id` [path, string] **required** — Group ID. Example: "225494730938493804".

Responses: 403 Insufficient permissions, 200 Success, 401 Unauthorized access - please sign in and retry.
