# RemoteOps Forensics

10 endpoints.

## `GET /web/api/v2.1/remote-ops/forensics/artifact-types`
**Get list of supported artifact types**
`operationId`: `_web_api_remote-ops_forensics_artifact-types_get`

Return a complete list of supported artifact types

Responses: 200 Successes, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/remote-ops/forensics/collection-file-url`
**Returns collection file download pre-signed url**
`operationId`: `_web_api_remote-ops_forensics_collection-file-url_get`

Returns collection file download pre-signed url
Optional permissions: `Remote Ops Forensics.view`

Parameters:
- `siteId` [query, string] **required** — Site id. Example: "225494730938493804".
- `agentId` [query, string] **required** — Agent id. Example: "225494730938493804".
- `signature` [query, string] **required** — Signature
- `signatureType` [query, string] **required** — Signature type
- `uploadedTimestamp` [query, string] **required** — Uploaded timestamp

Responses: 200 Remote Ops Forensics Collection File Found, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `DELETE /web/api/v2.1/remote-ops/forensics/collection-profiles`
**Delete Collection profiles**
`operationId`: `_web_api_remote-ops_forensics_collection-profiles_delete`

Delete multiple Forensics Collection profiles. The profiles that are not possible to delete (e.g. bundled profiles by S1, non-existing or user does not have proper permissions) are skipped. Contents of successfully deleted profiles are returned in response.

Required permissions: `Remote Ops Forensics.delete`

Parameters:
- `body` [body, v2_1.forensics.schema_DeleteProfilesRequestSchema] — 

Responses: 200 Delete was completed or partially completed., 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/remote-ops/forensics/collection-profiles`
**Get list of available Collection profiles**
`operationId`: `_web_api_remote-ops_forensics_collection-profiles_get`

Get list of available Forensics collection profiles. The list may be narrowed by specifying filter parameter. Profiles are inherited between scopes in both upward and downward directions, e.g. profiles on parent Account and Tenant scopes are returned when querying for a Site scope, and profiles on a Site scopes are returned when querying its parent Account. Bundled profiles are available regardless of requested scqpe. If scope is not specified in filter, the scopes of the requesting user are considered.

Required permissions: `Remote Ops Forensics.view`

Parameters:
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "225494730938493804,225494730938493915".
- `sortOrder` [query, string] (enum: asc, desc) — Sort direction. Example: "asc".
- `skipCount` [query, boolean] — If true, total number of items will not be calculated, which speeds up execution time.
- `autoTriggeringCompatible` [query, boolean] — Fetch auto triggering compatible profiles
- `skip` [query, integer] — Skip first number of items (0-1000). To iterate over more than 1000 items,  use "cursor". Example: "150".
- `limit` [query, integer] — Limit number of returned items (1-1000). Example: "10".
- `ids` [query, array] — A list of collection profiles IDs. Example: "225494730938493804,225494730938493915".
- `osTypes` [query, array] — Os types. Example: "linux".
- `query` [query, string] — Keyword to search in Collection profile name / description
- `countOnly` [query, boolean] — If true, only total number of items will be returned, without any of the actual objects.
- `cursor` [query, string] — Cursor position returned by the last request. Use to iterate over more than 1000 items. Example: "YWdlbnRfaWQ6NTgwMjkzODE=".
- `sortBy` [query, string] (enum: id, createdAt, mgmtId, scopeId, name, osTypes, version, scopeLevel, scopePath, creator) — The column to sort the results by. Example: "id".
- `siteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/remote-ops/forensics/collection-profiles`
**Create new Collection profile**
`operationId`: `_web_api_remote-ops_forensics_collection-profiles_post`

Create a Forensics Collection profile with provided artifacts on the specified scope. The profile name must be unique inside the scope, if the name already exists, Bad request error is returned.
Optional permissions: `Remote Ops Forensics.create, Remote Ops Forensics.upload`

Parameters:
- `body` [body, v2_1.forensics.schema_CollectionProfileRequestSchema] — 

Responses: 200 Collection profile is created, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/remote-ops/forensics/collection-profiles/{profile_id}`
**Get Collection profile by ID**
`operationId`: `_web_api_remote-ops_forensics_collection-profiles_{profile_id}_get`

Get contents of an existing Forensics Collection profile, including specification of artifacts to be collected and profile metadata.

Required permissions: `Remote Ops Forensics.view`

Parameters:
- `profile_id` [path, string] **required** — Profile ID. Example: "225494730938493804".

Responses: 403 User has insufficient permission to perform such action, 404 Collection profile was not found, 200 Collection profile content in returned, 401 Unauthorized access - please sign in and retry.

## `PUT /web/api/v2.1/remote-ops/forensics/collection-profiles/{profile_id}`
**Update Collection profile by ID**
`operationId`: `_web_api_remote-ops_forensics_collection-profiles_{profile_id}_put`

Update contents of an existing Forensics Collection profile. All the profile data should be specified, even if the values are not changed. It's not allowed to change scope of profile. The namemust be unique inside the scope, if different profile with specified name already exists, Bad requesterror is returned and no profile data is changed.

Required permissions: `Remote Ops Forensics.edit`

Parameters:
- `profile_id` [path, string] **required** — Profile ID. Example: "225494730938493804".
- `body` [body, v2_1.forensics.schema_PutCollectionProfileRequestSchema] — 

Responses: 403 User has insufficient permission to perform such action, 404 Collection profile was not found, 200 Collection profile is updated, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/remote-ops/forensics/is-collection-file`
**Check if collection file exists for given storyline**
`operationId`: `_web_api_remote-ops_forensics_is-collection-file_get`

Check if collection file exists for given storyline

Required permissions: `Remote Ops Forensics.view`

Parameters:
- `storyline` [query, string] **required** — Storyline ID
- `agentId` [query, string] **required** — Agent's ID. Example: "225494730938493804".

Responses: 404 Collection file not found, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/remote-ops/forensics/start-collection`
**Start collection of Forensics artifacts according to specified profile**
`operationId`: `_web_api_remote-ops_forensics_start-collection_post`

Start collection of Forensics artifacts according to specified profile

Required permissions: `Remote Ops Forensics.view, Remote Ops Forensics.runForensicsCollection`

Parameters:
- `body` [body, remote_ops.schemas_StartCollectionSchema] — 

Responses: 202 Forensics collection has been started, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/remote-ops/forensics/task-result`
**Return result of collection task**
`operationId`: `_web_api_remote-ops_forensics_task-result_get`

Return result of collection task

Required permissions: `Remote Ops Forensics.view`
Optional permissions: `Remote Ops Forensics.viewOutput`

Parameters:
- `taskId` [query, string] **required** — Task id. Example: "225494730938493804".

Responses: 200 Task is found and result is returned, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.
