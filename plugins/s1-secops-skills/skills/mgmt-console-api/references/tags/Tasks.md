# Tasks

7 endpoints.

## `GET /web/api/v2.1/tasks-configuration`
**Get Task Configuration**
`operationId`: `_web_api_tasks-configuration_get`

Get the task configuration of a scope.

Required permissions: `Upgrade Policy.view`

Parameters:
- `skip` [query, integer] — Skip first number of items (0-1000). To iterate over more than 1000 items,  use "cursor". Example: "150".
- `limit` [query, integer] — Limit number of returned items (1-1000). Example: "10".
- `cursor` [query, string] — Cursor position returned by the last request. Use to iterate over more than 1000 items. Example: "YWdlbnRfaWQ6NTgwMjkzODE=".
- `countOnly` [query, boolean] — If true, only total number of items will be returned, without any of the actual objects.
- `skipCount` [query, boolean] — If true, total number of items will not be calculated, which speeds up execution time.
- `sortBy` [query, string] (enum: scopeId, taskType, createdAt, userId) — The column to sort the results by. Example: "id".
- `sortOrder` [query, string] (enum: asc, desc) — Sort direction. Example: "asc".
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "225494730938493804,225494730938493915".
- `siteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `groupIds` [query, array] — List of Group IDs to filter by. Example: "225494730938493804,225494730938493915".
- `tenant` [query, boolean] — Indicates a tenant scope request
- `taskType` [query, string] **required** (enum: agents_upgrade, agent_version_change, auto_deploy, script_execution, cis_scan, gad, forensics_collection) — Task type. Example: "agents_upgrade".

Responses: 403 Insufficient permissions, 404 Configuration not found, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `PUT /web/api/v2.1/tasks-configuration`
**Create Task**
`operationId`: `_web_api_tasks-configuration_put`

Create a task configuration.

Required permissions: `Upgrade Policy.edit`

Parameters:
- `body` [body, tasks.schemas_PutTaskSchema] — 

Responses: 403 Operation is not allowed, 404 Configuration not found, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/tasks-configuration/explicit-subscopes`
**Get Child Scope Task Configuration**
`operationId`: `_web_api_tasks-configuration_explicit-subscopes_get`

Get the task configuration of child scopes of the given scope, if the tasks are not inherited.

Required permissions: `Upgrade Policy.view`

Parameters:
- `skip` [query, integer] — Skip first number of items (0-1000). To iterate over more than 1000 items,  use "cursor". Example: "150".
- `limit` [query, integer] — Limit number of returned items (1-1000). Example: "10".
- `cursor` [query, string] — Cursor position returned by the last request. Use to iterate over more than 1000 items. Example: "YWdlbnRfaWQ6NTgwMjkzODE=".
- `countOnly` [query, boolean] — If true, only total number of items will be returned, without any of the actual objects.
- `skipCount` [query, boolean] — If true, total number of items will not be calculated, which speeds up execution time.
- `sortBy` [query, string] (enum: scopeId, taskType, createdAt, userId) — The column to sort the results by. Example: "id".
- `sortOrder` [query, string] (enum: asc, desc) — Sort direction. Example: "asc".
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "225494730938493804,225494730938493915".
- `siteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `groupIds` [query, array] — List of Group IDs to filter by. Example: "225494730938493804,225494730938493915".
- `tenant` [query, boolean] — Indicates a tenant scope request
- `taskType` [query, string] **required** (enum: agents_upgrade, agent_version_change, auto_deploy, script_execution, cis_scan, gad, forensics_collection) — Task type. Example: "agents_upgrade".
- `query` [query, string] — Query

Responses: 403 User is not allowed in this scope, 404 Configuration not found, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/tasks-configuration/flexible`
**Get Task Configuration (Flexible MW)**
`operationId`: `_web_api_tasks-configuration_flexible_get`

Get task configuration with flexible maintenance window format. Returns policy_payload when flexible MW is configured.

Required permissions: `Upgrade Policy.view`

Parameters:
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "225494730938493804,225494730938493915".
- `siteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `groupIds` [query, array] — List of Group IDs to filter by. Example: "225494730938493804,225494730938493915".
- `tenant` [query, boolean] — Indicates a tenant scope request
- `taskType` [query, string] **required** (enum: agents_upgrade, agent_version_change, auto_deploy, script_execution, cis_scan, gad, forensics_collection) — Task type. Example: "agents_upgrade".

Responses: 403 Insufficient permissions, 404 Configuration not found, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `PUT /web/api/v2.1/tasks-configuration/flexible`
**Update Task Configuration (Flexible MW)**
`operationId`: `_web_api_tasks-configuration_flexible_put`

Update task configuration with flexible maintenance window format. Requires mw_aup_advanced_flexibility or mw_lsu_advanced_flexibility global switch.

Required permissions: `Upgrade Policy.edit`

Parameters:
- `body` [body, tasks.schemas_PutFlexibleTaskSchema] — 

Responses: 400 Invalid user input received. See error details for further i, 403 Operation is not allowed or feature not enabled, 404 Configuration not found, 200 Success, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/tasks-configuration/has-explicit-subscope`
**Has Child Scopes**
`operationId`: `_web_api_tasks-configuration_has-explicit-subscope_get`

From a given scope, see if there are scopes under it that have local, explicit tasks. The response returns True if a sub-scope has a local (not inherited) task configuration.

Required permissions: `Upgrade Policy.view`

Parameters:
- `skip` [query, integer] — Skip first number of items (0-1000). To iterate over more than 1000 items,  use "cursor". Example: "150".
- `limit` [query, integer] — Limit number of returned items (1-1000). Example: "10".
- `cursor` [query, string] — Cursor position returned by the last request. Use to iterate over more than 1000 items. Example: "YWdlbnRfaWQ6NTgwMjkzODE=".
- `countOnly` [query, boolean] — If true, only total number of items will be returned, without any of the actual objects.
- `skipCount` [query, boolean] — If true, total number of items will not be calculated, which speeds up execution time.
- `sortBy` [query, string] (enum: scopeId, taskType, createdAt, userId) — The column to sort the results by. Example: "id".
- `sortOrder` [query, string] (enum: asc, desc) — Sort direction. Example: "asc".
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "225494730938493804,225494730938493915".
- `siteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `groupIds` [query, array] — List of Group IDs to filter by. Example: "225494730938493804,225494730938493915".
- `tenant` [query, boolean] — Indicates a tenant scope request
- `taskType` [query, string] **required** (enum: agents_upgrade, agent_version_change, auto_deploy, script_execution, cis_scan, gad, forensics_collection) — Task type. Example: "agents_upgrade".

Responses: 403 User is not allowed in this scope, 404 Configuration not found, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/tasks-configuration/maintenance-windows/export_mw`
**Export Maintenance Windows as CSV**
`operationId`: `_web_api_tasks-configuration_maintenance-windows_export_mw_get`

Export all maintenance window occurrences for a specific scope as CSV. Supports both legacy (schedule_view) and flexible (policy_payload) maintenance window formats. When both schemas exist, all windows from both are included and deduplicated. Date range: policies with end dates generate up to that date; policies with no end date generate for 5 years from start date. Returns a CSV file with columns: Date, Start Time, End Time. Maximum report size: 5MB.

Required permissions: `Upgrade Policy.view`

Parameters:
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "225494730938493804,225494730938493915".
- `siteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `groupIds` [query, array] — List of Group IDs to filter by. Example: "225494730938493804,225494730938493915".
- `tenant` [query, boolean] — Indicates a tenant scope request
- `taskType` [query, string] **required** (enum: agents_upgrade, agent_version_change, auto_deploy, script_execution, cis_scan, gad, forensics_collection) — Task type. Example: "agents_upgrade".

Responses: 500 Report exceeds maximum size, 403 Insufficient permissions, 404 Configuration not found, 200 CSV file with maintenance windows, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.
