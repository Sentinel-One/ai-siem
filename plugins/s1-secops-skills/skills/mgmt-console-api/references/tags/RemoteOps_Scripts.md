# RemoteOps Scripts

16 endpoints.

## `DELETE /web/api/v2.1/remote-scripts`
**Delete Scripts**
`operationId`: `_web_api_remote-scripts_delete`

Deletes scripts that match a filter.

Required permissions: `Remote Script Orchestration.delete`

Parameters:
- `body` [body, schemas_ScriptDeleteSchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/remote-scripts`
**Get Scripts**
`operationId`: `_web_api_remote-scripts_get`

Get data of the scripts in the SentinelOne Script Library. <br>The SentinelOne Script Library, used for the Remote Script Orchestration feature, gives you a wide range of scripts to collect various forensic artifacts, parse them, and show them in formats that are easy to analyze. Use the scripts to collect information such as hardware and software inventory and configuration, running applications and processes, files and directories, network connections, and more.
Optional permissions: `Remote Script Orchestration.view, Remote Script Orchestration.delete`

Parameters:
- `skipCount` [query, boolean] — If true, total number of items will not be calculated, which speeds up execution time.
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "225494730938493804,225494730938493915".
- `groupIds` [query, array] — List of group IDs to filter by. Example: "225494730938493804,225494730938493915".
- `skip` [query, integer] — Skip first number of items (0-1000). To iterate over more than 1000 items,  use "cursor". Example: "150".
- `limit` [query, integer] — Limit number of returned items (1-1000). Example: "10".
- `siteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `isAvailableForArs` [query, boolean] — Is the script runnable in Advanced Response Scripts
- `query` [query, string] — Query
- `scriptType` [query, array] — List of the script types. Example: "artifactCollection".
- `ids` [query, array] — A list of script IDs. Example: "225494730938493804,225494730938493915".
- `sortBy` [query, string] (enum: id, createdAt, mgmtId, scopeId, scriptName, name, osTypes, createdByUserId, inputInstructions, inputExample, type, scriptType, version, scopeLevel, scopePath, subscription, isAvailableForArs) — The column to sort the results by. Example: "id".
- `cursor` [query, string] — Cursor position returned by the last request. Use to iterate over more than 1000 items. Example: "YWdlbnRfaWQ6NTgwMjkzODE=".
- `sortOrder` [query, string] (enum: asc, desc) — Sort direction. Example: "asc".
- `osTypes` [query, array] — List of the script OS types. Example: "linux".
- `countOnly` [query, boolean] — If true, only total number of items will be returned, without any of the actual objects.

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/remote-scripts`
**Upload New Script**
`operationId`: `_web_api_remote-scripts_post`

Upload a new script file. The file and various properties are required. To see the mandatory and optional parameters and their valid values, see the Body Schema or click Run On Console.

Required permissions: `Remote Script Orchestration.upload`

Parameters:
- `isScriptContentEncoded` [formData, boolean] — True if script content is encoded
- `packageMaxSize` [formData, string] — Package max size
- `inputExample` [formData, string] — Input example
- `isDuplication` [formData, boolean] — True if script/package files should be taken from an existing script specified in original_script_id
- `packageEndpointExpiration` [formData, string] (enum: None, Immediate, OnRestart, Time) — Package expiration option on endpoint. Example: "None".
- `osTypes` [formData, array] **required** — Os types. Example: "m,a,c,o,s,,,l,i,n,u,x".
- `packageRemoved` [formData, boolean] — True if package should file should not be copied, applicable only if is_duplication is true
- `scriptName` [formData, string] **required** — Script name
- `scriptType` [formData, string] **required** (enum: artifactCollection, dataCollection, action) — Script type. Example: "artifactCollection".
- `scriptRuntimeTimeoutSeconds` [formData, integer] — Script runtime timeout in seconds
- `scriptContent` [formData, string] — Content of the script file, applicable only if is_duplication is true
- `inputInstructions` [formData, string] — Input instructions
- `scopeLevel` [formData, string] **required** (enum: site, account, global) — Scope level. Example: "site".
- `consoleData` [formData, string] — Console data
- `inputRequired` [formData, boolean] **required** — Is input required
- `originalScriptId` [formData, string] — ID of script, from which the script/package files will becopied, applicable ony if is_duplication is true. Example: "225494730938493804".
- `sendActivity` [formData, boolean] — Send activity
- `scriptDescription` [formData, string] — Script description
- `packageEndpointExpirationSeconds` [formData, integer] — Package expiration time on endpoint
- `scopeId` [formData, string] — Scope ID. Example: "225494730938493804".
- `file` [formData, file] — File
- `packageFile` [formData, file] — Package file

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `PUT /web/api/v2.1/remote-scripts/edit/{script_id}`
**Update a Script**
`operationId`: `_web_api_remote-scripts_edit_{script_id}_put`

Change the properties of a given script: runtime timeout, name, and whether input is required (if true, input example and instructions are required), or script content itself. <br>This command requires the script ID, which you can get from the Get Scripts API.

Required permissions: `Remote Script Orchestration.edit`

Parameters:
- `script_id` [path, string] **required** — Script ID. Example: "225494730938493804".
- `scriptContent` [formData, string] — Filled out with a new content of a script if the script content was changedon an already previously uploaded script
- `inputInstructions` [formData, string] **required** — Input instructions
- `isScriptContentEncoded` [formData, boolean] — Is the script content base64 encoded?
- `scriptDescription` [formData, string] — Script description
- `packageRemoved` [formData, boolean] — Was package removed during edit of the script?
- `packageMaxSize` [formData, string] — Package max size
- `packageEndpointExpirationSeconds` [formData, integer] — Package expiration time on endpoint
- `consoleData` [formData, string] — Console data
- `inputExample` [formData, string] **required** — Input example
- `scriptName` [formData, string] **required** — Script name
- `inputRequired` [formData, boolean] **required** — Is input required
- `packageEndpointExpiration` [formData, string] (enum: None, Immediate, OnRestart, Time) — Package expiration option on endpoint. Example: "None".
- `scriptType` [formData, string] **required** (enum: artifactCollection, dataCollection, action) — Script type. Example: "artifactCollection".
- `osTypes` [formData, array] **required** — Os types. Example: "m,a,c,o,s,,,l,i,n,u,x".
- `sendActivity` [formData, boolean] — Send activity
- `scriptRuntimeTimeoutSeconds` [formData, integer] **required** — Script runtime timeout in seconds
- `scriptFile` [formData, file] — Script file
- `packageFile` [formData, file] — Package file

Responses: 400 Invalid user input received. See error details for further i, 404 Script not found, 200 Success, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/remote-scripts/execute`
**Run Remote Script**
`operationId`: `_web_api_remote-scripts_execute_post`

Run a remote script that was uploaded to the SentinelOne Script Library.
Optional permissions: `Remote Script Orchestration.view, Remote Script Orchestration.runArtifactCollectionScript, Remote Script Orchestration.runDataCollectionScript, Remote Script Orchestration.runActionScript`

Parameters:
- `body` [body, cloud_proxy.remote_scripts_ExecuteScriptSchema] — 

Responses: 200 Run remote script request was successful, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/remote-scripts/fetch-files`
**Get Script Results**
`operationId`: `_web_api_remote-scripts_fetch-files_post`

Get scripts results URLs. Accessible via API only

Required permissions: `Remote Script Orchestration.view`

Parameters:
- `body` [body, _FetchScriptsResultsSchema] — 

Responses: 200 Get remote script results was successful, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/remote-scripts/fetch-upload-limits`
**Get upload limit for Package**
`operationId`: `_web_api_remote-scripts_fetch-upload-limits_get`

Get upload limit for Package

Required permissions: `Remote Script Orchestration.view`

Responses: 200 Success, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/remote-scripts/guardrails/check`
**Check whether guardrail applies to an execution**
`operationId`: `_web_api_remote-scripts_guardrails_check_post`

Check whether guardrail applies to an execution

Required permissions: `Remote Script Orchestration.view`

Parameters:
- `body` [body, schemas_EncapsulatedPostGuardrailCheckSchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `DELETE /web/api/v2.1/remote-scripts/guardrails/configuration`
**Deletes a specific  guardrails configuration**
`operationId`: `_web_api_remote-scripts_guardrails_configuration_delete`

Deletes a specific  guardrails configuration

Required permissions: `Remote Script Orchestration.manageGuardrails`

Parameters:
- `body` [body, schemas_EncapsulatedDeleteGuardrailsSchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/remote-scripts/guardrails/configuration`
**Gets a guardrails configuration for a given scope**
`operationId`: `_web_api_remote-scripts_guardrails_configuration_get`

Gets a guardrails configuration for a given scope

Required permissions: `Remote Script Orchestration.view`

Parameters:
- `scopeId` [query, string] **required** — Scope ID. Example: "225494730938493804".
- `scopeLevel` [query, string] **required** (enum: account, site, group) — Scope level. Example: "account".

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/remote-scripts/guardrails/configuration`
**Updates or inserts (if record does not exist) a guardrails configuration**
`operationId`: `_web_api_remote-scripts_guardrails_configuration_post`

Updates or inserts (if record does not exist) a guardrails configuration

Required permissions: `Remote Script Orchestration.manageGuardrails`

Parameters:
- `body` [body, schemas_EncapsulatedPostGuardrailsSchema] — 

Responses: 400 Invalid user input received. See error details for further i, 200 Success, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/remote-scripts/pending-executions`
**Get paginated pending executions**
`operationId`: `_web_api_remote-scripts_pending-executions_get`

Get paginated pending executions

Required permissions: `Remote Script Orchestration.view`

Parameters:
- `skipCount` [query, boolean] — If true, total number of items will not be calculated, which speeds up execution time.
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "225494730938493804,225494730938493915".
- `groupIds` [query, array] — List of group IDs to filter by. Example: "225494730938493804,225494730938493915".
- `skip` [query, integer] — Skip first number of items (0-1000). To iterate over more than 1000 items,  use "cursor". Example: "150".
- `limit` [query, integer] — Limit number of returned items (1-1000). Example: "10".
- `siteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `sortBy` [query, string] (enum: id, createdAt, state) — The column to sort the results by. Example: "id".
- `cursor` [query, string] — Cursor position returned by the last request. Use to iterate over more than 1000 items. Example: "YWdlbnRfaWQ6NTgwMjkzODE=".
- `sortOrder` [query, string] (enum: asc, desc) — Sort direction. Example: "asc".
- `countOnly` [query, boolean] — If true, only total number of items will be returned, without any of the actual objects.

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `PUT /web/api/v2.1/remote-scripts/pending-executions/{pending_execution_id}`
**Approve/decline pending execution**
`operationId`: `_web_api_remote-scripts_pending-executions_{pending_execution_id}_put`

Approve/decline pending execution

Required permissions: `Remote Script Orchestration.reviewPendingExecutions`

Parameters:
- `pending_execution_id` [path, string] **required** — Pending execution ID. Example: "225494730938493804".
- `body` [body, schemas_ApproveDeclinePendingExecutionRequestSchema] — 

Responses: 404 Pending execution not found, 400 Invalid user input received. See error details for further i, 200 Success, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/remote-scripts/script-content`
**Get script content**
`operationId`: `_web_api_remote-scripts_script-content_get`

Get Script content by script id

Required permissions: `Remote Script Orchestration.view`

Parameters:
- `scriptId` [query, string] — Script ID. Example: "225494730938493804".

Responses: 404 Script not found, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/remote-scripts/status`
**Get Remote Scripts Tasks Status**
`operationId`: `_web_api_remote-scripts_status_get`

Get remote scripts tasks using a variety of filters. Accessible via API only<br>parent_task_id or parent_task_id__in query parameter is mandatory

Required permissions: `Task Management.view`

Parameters:
- `skip` [query, integer] — Skip first number of items (0-1000). To iterate over more than 1000 items,  use "cursor". Example: "150".
- `limit` [query, integer] — Limit number of returned items (1-1000). Example: "10".
- `cursor` [query, string] — Cursor position returned by the last request. Use to iterate over more than 1000 items. Example: "YWdlbnRfaWQ6NTgwMjkzODE=".
- `countOnly` [query, boolean] — If true, only total number of items will be returned, without any of the actual objects.
- `skipCount` [query, boolean] — If true, total number of items will not be calculated, which speeds up execution time.
- `sortBy` [query, string] (enum: id, initiatedBy, createdAt, updatedAt, status, detailedStatus, agentComputerName, parentTaskId, accountName, siteName, groupName, description) — The column to sort the results by. Example: "id".
- `sortOrder` [query, string] (enum: asc, desc) — Sort direction. Example: "asc".
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "225494730938493804,225494730938493915".
- `siteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `groupIds` [query, array] — List of Group IDs to filter by. Example: "225494730938493804,225494730938493915".
- `tenant` [query, boolean] — Indicates a tenant scope request
- `ids` [query, array] — List of IDs to filter by. Example: "225494730938493804,225494730938493915".
- `createdAt__lt` [query, string] — Created at lesser than. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__gt` [query, string] — Created at greater than. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__lte` [query, string] — Created at lesser or equal than. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__gte` [query, string] — Created at greater or equal than. Example: "2018-02-27T04:49:26.257525Z".
- `updatedAt__lt` [query, string] — Updated at lesser than. Example: "2018-02-27T04:49:26.257525Z".
- `updatedAt__gt` [query, string] — Updated at greater than. Example: "2018-02-27T04:49:26.257525Z".
- `updatedAt__lte` [query, string] — Updated at lesser or equal than. Example: "2018-02-27T04:49:26.257525Z".
- `updatedAt__gte` [query, string] — Updated at greater or equal than. Example: "2018-02-27T04:49:26.257525Z".
- `query` [query, string] — Query
- `status` [query, array] — Status in. Example: "created".
- `types` [query, array] — Type in
- `type` [query, string] — Type
- `computerName__contains` [query, array] — Free-text filter by agent computer name (supports multiple values)
- `uuid__contains` [query, array] — Free-text filter by agent UUID (supports multiple values)
- `initiatedBy__contains` [query, array] — Only include tasks from specific initiating user
- `detailedStatus__contains` [query, array] — Only include tasks with specific detailed status
- `description__contains` [query, array] — Only include tasks with specific description
- `parentTaskId__in` [query, array] — List of IDs to filter by
- `parentTaskId` [query, string] — parent task id to fetch the status by. Example: "225494730938493804".

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `PUT /web/api/v2.1/remote-scripts/{script_id}`
**Update a Script**
`operationId`: `_web_api_remote-scripts_{script_id}_put`

Change the properties of a given script: runtime timeout, name, and whether input is required (if true, input example and instructions are required). <br>This command requires the script ID, which you can get from the Get Scripts API.

Required permissions: `Remote Script Orchestration.edit`

Parameters:
- `script_id` [path, string] **required** — Script ID. Example: "225494730938493804".
- `body` [body, schemas_UpdateScript] — 

Responses: 404 Script not found, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.
