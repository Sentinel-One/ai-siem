# Config Overrides

5 endpoints.

## `DELETE /web/api/v2.1/config-override`
**Delete Config Overrides**
`operationId`: `_web_api_config-override_delete`

Delete overrides value. To get the required IDs, run "config-override".

Required permissions: `Policy Override.delete`

Parameters:
- `body` [body, config_overrides_ConfigOverrideDeleteSchema] — 

Responses: 403 Insufficient permissions, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/config-override`
**Get Config Overrides**
`operationId`: `_web_api_config-override_get`

There are different ways to override the configuration of an Agent, and the priority of changes depends on the endpoint OS and the version of the installed Agent. Use this command to see the configuration values that are changed for each Agent that matches the filter.

Required permissions: `Policy Override.view`

Parameters:
- `skip` [query, integer] — Skip first number of items (0-1000). To iterate over more than 1000 items,  use "cursor". Example: "150".
- `limit` [query, integer] — Limit number of returned items (1-1000). Example: "10".
- `cursor` [query, string] — Cursor position returned by the last request. Use to iterate over more than 1000 items. Example: "YWdlbnRfaWQ6NTgwMjkzODE=".
- `countOnly` [query, boolean] — If true, only total number of items will be returned, without any of the actual objects.
- `skipCount` [query, boolean] — If true, total number of items will not be calculated, which speeds up execution time.
- `sortBy` [query, string] (enum: id, createdAt, updatedAt, name, description, scope, osType, agentVersion, versionOption, config, agentId) — The column to sort the results by. Example: "id".
- `sortOrder` [query, string] (enum: asc, desc) — Sort direction. Example: "asc".
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "225494730938493804,225494730938493915".
- `siteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `groupIds` [query, array] — List of Group IDs to filter by. Example: "225494730938493804,225494730938493915".
- `tenant` [query, boolean] — Indicates a tenant scope request
- `ids` [query, array] — List of ids to filter by. Example: "225494730938493804,225494730938493915".
- `agentIds` [query, array] — List of Agent IDs to filter by. Example: "225494730938493804,225494730938493915".
- `createdAt__lt` [query, string] — Config Overrides created before this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__lte` [query, string] — Config Overrides created before or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__gt` [query, string] — Config Overrides created after this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__gte` [query, string] — Config Overrides created after or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__between` [query, string] — Date range for creation time (format: <from_timestamp>-<to_timestamp>, inclusive). Example: "1514978890136-1514978650130".
- `name__like` [query, string] — Match name partially (substring)
- `description__like` [query, string] — Match description partially (substring)
- `osTypes` [query, array] — Included OS types. Example: "macos".
- `agentVersions` [query, array] — Included agent versions. Example: "2.5.1.1320".
- `versionOption` [query, string] (enum: ALL, SPECIFIC) — Version option. Example: "ALL".
- `query` [query, string] — Free text search on fields name, description, agent_version, os_type, config

Responses: 400 Invalid user input received. See error details for further i, 200 Success, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/config-override`
**Create Config Override**
`operationId`: `_web_api_config-override_post`

Override the configuration of Agents that match the filter. Best practice:  Run "support-actions/config" to get the complete syntax. This command requires a Global user or Support.

Required permissions: `Policy Override.create`

Parameters:
- `body` [body, config_overrides_CreateConfigOverrideSchema] — 

Responses: 400 Invalid user input received. See error details for further i, 404 Scope not found., 403 Insufficient permissions, 200 Success, 401 Unauthorized access - please sign in and retry.

## `DELETE /web/api/v2.1/config-override/{override_id}`
**Delete Config Override**
`operationId`: `_web_api_config-override_{override_id}_delete`

Delete an override value. To get the required ID, run "config-override".

Required permissions: `Policy Override.delete`

Parameters:
- `override_id` [path, string] **required** — Config override object ID. Example: "225494730938493804".

Responses: 404 Override not found., 403 Insufficient permissions, 200 Success, 401 Unauthorized access - please sign in and retry.

## `PUT /web/api/v2.1/config-override/{override_id}`
**Update Config Override**
`operationId`: `_web_api_config-override_{override_id}_put`

Use this command to change the value of one configuration value. To get the required ID, run "config-override".

Required permissions: `Policy Override.edit`

Parameters:
- `override_id` [path, string] **required** — Config override object ID. Example: "225494730938493804".
- `body` [body, config_overrides_PutConfigOverrideSchema] — 

Responses: 404 Override not found., 403 Insufficient permissions., 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.
