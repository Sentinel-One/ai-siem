# Remote Ops MMS

13 endpoints.

## `DELETE /web/api/v2.1/remote-ops/data-exporter/destination-profiles`
**Delete multiple Destination profiles by ID**
`operationId`: `_web_api_remote-ops_data-exporter_destination-profiles_delete`

Delete multiple Destination profiles. The profiles that are not possible to delete (e.g.non-existing or user does not have proper permissions) are skipped. IDs of successfully deleted profiles are returned in response.

Required permissions: `Remote Script Orchestration.manageDestinationCredentials`

Parameters:
- `body` [body, v2_1.data_exporter.schema_DeleteDestinationProfilesRequestSchema] — 

Responses: 200 Delete was completed or partially completed., 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/remote-ops/data-exporter/destination-profiles`
**Get available Destination profiles**
`operationId`: `_web_api_remote-ops_data-exporter_destination-profiles_get`

Get Destination profiles available for the specified scope. The profiles are inherited downwards, e.g. the profiles from parent Account and Tenant scopes are available for a Site. At most one of returned destination profiles will be marked as default for the scope. If the scope does not have default profile defined, it's inherited from the higher scope, unless inheritance was broken

Required permissions: `Remote Script Orchestration.viewDestinationCredentials`

Parameters:
- `scopeLevel` [query, string] (enum: tenant, account, site, group) — Scope level to get Destination profile configuration. Example: "tenant".
- `scopeId` [query, string] — Scope ID to get Destination profiles configuration. Example: "225494730938493804".

Responses: 403 User has insufficient permission to perform such action, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/remote-ops/data-exporter/destination-profiles`
**Create new Destination profile.**
`operationId`: `_web_api_remote-ops_data-exporter_destination-profiles_post`

Create Destination profile inside specified scope. If the created profile is requested to be default, the default profile of the specified scope is overriden.

Required permissions: `Remote Script Orchestration.manageDestinationCredentials`

Parameters:
- `body` [body, v2_1.data_exporter.schema_PostDestinationProfileRequestSchema] — 

Responses: 401 Unauthorized access - please sign in and retry., 200 Successes, 400 Invalid user input received. See error details for further i

## `POST /web/api/v2.1/remote-ops/data-exporter/destination-profiles/set-default`
**Set profile as default profile of the scope**
`operationId`: `_web_api_remote-ops_data-exporter_destination-profiles_set-default_post`

Set profile as default profile of the scope

Required permissions: `Remote Script Orchestration.manageDestinationCredentials`

Parameters:
- `body` [body, v2_1.data_exporter.schema_SetDefaultDestinationProfile] — 

Responses: 403 User has insufficient permission to perform such action, 400 Invalid user input received. See error details for further i, 200 Get Destination profile, 401 Unauthorized access - please sign in and retry.

## `DELETE /web/api/v2.1/remote-ops/data-exporter/destination-profiles/{profile_id}`
**Delete Destination profile by ID**
`operationId`: `_web_api_remote-ops_data-exporter_destination-profiles_{profile_id}_delete`

Delete Destination profile with specified ID. If the profile was used as default for a scope, the last created profile will be marked as default for that scope.

Required permissions: `Remote Script Orchestration.manageDestinationCredentials`

Parameters:
- `profile_id` [path, string] **required** — Profile ID. Example: "225494730938493804".

Responses: 403 User has insufficient permission to perform such action, 404 Destination profile is not found, 200 Destination profile is deleted, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/remote-ops/data-exporter/destination-profiles/{profile_id}`
**Get Destination profile by ID**
`operationId`: `_web_api_remote-ops_data-exporter_destination-profiles_{profile_id}_get`

Get Destination profile with specified ID

Required permissions: `Remote Script Orchestration.manageDestinationCredentials`

Parameters:
- `profile_id` [path, string] **required** — Profile ID. Example: "225494730938493804".
- `scopeLevel` [query, string] (enum: tenant, account, site, group) — Scope level to get Destination profile configuration. Example: "tenant".
- `scopeId` [query, string] — Scope ID to get Destination profiles configuration. Example: "225494730938493804".

Responses: 403 User has insufficient permission to perform such action, 404 Destination profile is not found, 200 Get Destination profile, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `PUT /web/api/v2.1/remote-ops/data-exporter/destination-profiles/{profile_id}`
**Update existing Destination profile**
`operationId`: `_web_api_remote-ops_data-exporter_destination-profiles_{profile_id}_put`

Update contents of existing Destination profile with specified ID. All the profile data should be specified, even if the values are not changed. If the updated profile is requested to be default, the default profile of its scope is modified.

Required permissions: `Remote Script Orchestration.manageDestinationCredentials`

Parameters:
- `profile_id` [path, string] **required** — Profile ID. Example: "225494730938493804".
- `body` [body, v2_1.data_exporter.schema_PutDestinationProfileRequestSchema] — 

Responses: 403 User has insufficient permission to perform such action, 404 Destination profile is not found, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/remote-ops/data-exporter/results`
**Get results sent to data exporter**
`operationId`: `_web_api_remote-ops_data-exporter_results_get`

Get results sent to data exporter
Optional permissions: `Remote Script Orchestration.view, Remote Ops Forensics.view, Remote Script Orchestration.viewDestinationResults`

Parameters:
- `taskId` [query, string] — Task id
- `maliciousGroupId` [query, string] — Threat malicious group id
- `agentId` [query, string] **required** — Id of the agent the data came from

Responses: 403 User has insufficient permission to perform such action, 200 Get Destination profile results, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/remote-ops/schedule/forensics`
**Schedule forensics for future run.**
`operationId`: `_web_api_remote-ops_schedule_forensics_post`

Schedule forensics for future run. The profile will be scheduled for execution on all endpoints matching the filter.

Required permissions: `Remote Script Orchestration.createScheduledTasks, Remote Ops Forensics.runForensicsCollection`

Parameters:
- `body` [body, v2_1.scheduling.schema_ScheduleForensicsCollectionRequestSchema] — 

Responses: 401 Unauthorized access - please sign in and retry., 200 Success, 400 Invalid user input received. See error details for further i

## `POST /web/api/v2.1/remote-ops/schedule/remote-script`
**Schedule remote script for future run.**
`operationId`: `_web_api_remote-ops_schedule_remote-script_post`

Schedule remote script for future run. The script will be scheduled for execution on all endpoints matching the filter.If appropriate, pending approval will be created for the execution.

Required permissions: `Remote Script Orchestration.createScheduledTasks`
Optional permissions: `Remote Script Orchestration.runActionScript, Remote Script Orchestration.runDataCollectionScript, Remote Script Orchestration.runArtifactCollectionScript`

Parameters:
- `body` [body, v2_1.scheduling.schema_ScheduleRemoteScriptRequestSchema] — 

Responses: 401 Unauthorized access - please sign in and retry., 200 Success, 400 Invalid user input received. See error details for further i

## `DELETE /web/api/v2.1/remote-ops/scheduled-tasks`
**Delete multiple scheduled tasks by ID**
`operationId`: `_web_api_remote-ops_scheduled-tasks_delete`

Delete multiple Scheduled tasks. The tasks that are not possible to delete (e.g.non-existing or user does not have proper permissions) are skipped. IDs of successfully deleted tasks are returned in response.

Required permissions: `Remote Script Orchestration.deleteScheduledTasks`

Parameters:
- `body` [body, v2_1.scheduling.schema_DeleteScheduledTasksRequestSchema] — 

Responses: 200 Delete was completed or partially completed., 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/remote-ops/scheduled-tasks`
**Get available Scheduled Tasks**
`operationId`: `_web_api_remote-ops_scheduled-tasks_get`

Get available Scheduled Tasks

Required permissions: `Remote Script Orchestration.viewScheduledTasks`

Parameters:
- `cursor` [query, string] — Cursor position returned by the last request. Use to iterate over more than 1000 items. Example: "YWdlbnRfaWQ6NTgwMjkzODE=".
- `scopeName__contains` [query, array] — Keyword to search in scope name
- `outputDestination` [query, array] — List of the tasks types. Example: "SentinelCloud".
- `creatorId` [query, array] — IDs of creating user of scheduled task. Example: "225494730938493804,225494730938493915".
- `createdAt__between` [query, string] — Date range for creation time
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "225494730938493804,225494730938493915".
- `type` [query, array] — List of the tasks types. Example: "action".
- `osTypes` [query, array] — List of the OS types. Example: "linux".
- `ids` [query, array] — A list of scheduled tasks ids. Example: "225494730938493804,225494730938493915".
- `description__contains` [query, array] — Keyword to search in description
- `status` [query, array] — List of the tasks status. Example: "scheduled".
- `groupIds` [query, array] — List of Group IDs to filter by. Example: "225494730938493804,225494730938493915".
- `query` [query, string] — Keyword to search in scheduled tasks profile name
- `limit` [query, integer] — Limit number of returned items (1-1000). Example: "10".
- `scheduledTime__between` [query, string] — Date range for scheduled execution time
- `targetScope` [query, array] — IDs of target scopes of scheduled task. Example: "225494730938493804,225494730938493915".
- `id__contains` [query, array] — Keyword to search in task ID
- `sortOrder` [query, string] (enum: asc, desc) — Sort direction. Example: "asc".
- `siteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `sortBy` [query, string] (enum: id, name, description, scheduledTime, type, osTypes, outputDestination, createdAt, targetScope, creator, status) — The column to sort the results by. Example: "id".
- `skip` [query, integer] — Skip first number of items (0-1000). To iterate over more than 1000 items,  use "cursor". Example: "150".
- `countOnly` [query, boolean] — If true, only total number of items will be returned, without any of the actual objects.
- `skipCount` [query, boolean] — If true, total number of items will not be calculated, which speeds up execution time.
- `name__contains` [query, array] — Keyword to search in task name

Responses: 403 User has insufficient permission to perform such action, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `PUT /web/api/v2.1/remote-ops/scheduled-tasks/{scheduled_task_id}`
**Update existing Scheduled task**
`operationId`: `_web_api_remote-ops_scheduled-tasks_{scheduled_task_id}_put`

Update existing Scheduled task

Required permissions: `Remote Script Orchestration.updateScheduledTasks`

Parameters:
- `scheduled_task_id` [path, string] **required** — Scheduled Task ID. Example: "225494730938493804".
- `body` [body, v2_1.scheduling.schema_PutScheduledTaskRequestSchema] — 

Responses: 403 User has insufficient permission to perform such action, 404 Scheduled task is not found, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.
