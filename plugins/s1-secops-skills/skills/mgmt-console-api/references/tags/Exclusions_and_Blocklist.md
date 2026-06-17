# Exclusions and Blocklist

16 endpoints.

## `DELETE /web/api/v2.1/exclusions`
**Delete Exclusions**
`operationId`: `_web_api_exclusions_delete`

Every Exclusion opens a possible security hole. If you decide that an Exclusion (or multiple Exclusions) is not required, use this command to delete it. To get the ID of the Exclusion to delete, run the "exclusions" command.

Required permissions: `Exclusions.delete`

Parameters:
- `body` [body, exclusions.schemas_DeleteExclusionSchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/exclusions`
**Get Exclusions**
`operationId`: `_web_api_exclusions_get`

Get a list of all the Exclusions that match the filter. <br>Note: To filter the results for a scope: <br>* Global - Make sure "tenant" is "true" and no other scope ID is given.<br>* Account - Make sure "tenant" is "false" and at least one Account ID is given.<br>* Site - Make sure "tenant" is "false" and at least one Site ID is given.

Required permissions: `Exclusions.view`

Parameters:
- `skip` [query, integer] — Skip first number of items (0-1000). To iterate over more than 1000 items,  use "cursor". Example: "150".
- `limit` [query, integer] — Limit number of returned items (1-1000). Example: "10".
- `cursor` [query, string] — Cursor position returned by the last request. Use to iterate over more than 1000 items. Example: "YWdlbnRfaWQ6NTgwMjkzODE=".
- `countOnly` [query, boolean] — If true, only total number of items will be returned, without any of the actual objects.
- `skipCount` [query, boolean] — If true, total number of items will not be calculated, which speeds up execution time.
- `sortBy` [query, string] (enum: id, createdAt, updatedAt, mode, source, description, pathExclusionType, osType, scope, subfolders, type, userName, scopePath, value, actions, imported, applicationName, inAppInventory) — The column to sort the results by. Example: "id".
- `sortOrder` [query, string] (enum: asc, desc) — Sort direction. Example: "asc".
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "225494730938493804,225494730938493915".
- `siteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `groupIds` [query, array] — List of Group IDs to filter by. Example: "225494730938493804,225494730938493915".
- `tenant` [query, boolean] — Indicates a tenant scope request
- `ids` [query, array] — List of IDs to filter by. Example: "225494730938493804,225494730938493915".
- `unified` [query, boolean] — Unified
- `value` [query, string] — Value
- `createdAt__lt` [query, string] — Created before this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__lte` [query, string] — Created before or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__gt` [query, string] — Created after this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__gte` [query, string] — Created after or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__between` [query, string] — Date range for creation time (format: <from_timestamp>-<to_timestamp>, inclusive). Example: "1514978890136-1514978650130".
- `updatedAt__lt` [query, string] — Updated before this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `updatedAt__lte` [query, string] — Updated before or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `updatedAt__gt` [query, string] — Updated after this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `updatedAt__gte` [query, string] — Updated after or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `updatedAt__between` [query, string] — Date range for update time (format: <from_timestamp>-<to_timestamp>, inclusive). Example: "1514978890136-1514978650130".
- `query` [query, string] — A free-text search term, will match applicable attributes
- `type` [query, string] (enum: path, certificate, browser, file_type, white_hash, dv_exclusions) — Type. Example: "path".
- `osTypes` [query, array] — List of Os types to filter by. Example: "macos".
- `source` [query, array] — List sources to filter by. Example: "user".
- `userIds` [query, array] — List of user ids to filter by. Example: "225494730938493804,225494730938493915".
- `recommendations` [query, array] — List of recommendations to filter by. Example: "Not recommended".
- `value__contains` [query, array] — Free-text filter by value
- `description__contains` [query, array] — Free-text filter by description
- `user__contains` [query, array] — Free-text filter by user name
- `types` [query, array] — Type in. Example: "path".
- `modes` [query, array] — List of modes to filter by (Path exclusions only). Example: "suppress".
- `pathExclusionTypes` [query, array] — List of excluded paths in an exclusion (Path exclusions only). Example: "file".
- `includeParents` [query, boolean] — Return filters from parent scope levels (Default: false)
- `includeChildren` [query, boolean] — Return filters from children scope levels (Default: false)
- `imported` [query, array] — Filter by import status: true (imported), false (not imported), or both for multiselect
- `applicationName__contains` [query, array] — Free-text filter by application name
- `inAppInventory` [query, boolean] — Found or Not found - indicates if this exclusion is related to an application found in the scope's Application Inventory.
- `modeType` [query, string] (enum: all, suppression, agent_interoperability, binary_vault) — Mode type. Example: "all".
- `childProcess` [query, boolean] — Child process
- `threatType` [query, array] — Threat type in. Example: "EDR".
- `engines` [query, array] — Engine in. Example: "suppress".
- `interactionLevel` [query, array] — Interaction level in. Example: "disable_all_monitors".
- `conditions` [query, array] — Conditions in. Example: "white_hash".
- `exclusionName__contains` [query, array] — Exclusion name like any
- `notRecommended` [query, array] — Not recommended in. Example: "Not recommended".
- `scopePath__contains` [query, array] — Scope path like any

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/exclusions`
**Create Exclusion**
`operationId`: `_web_api_exclusions_post`

Create Exclusions to make your Agents suppress alerts and mitigation for items that you consider to be benign or which you require for interoperability.<br>IMPORTANT! Every Exclusion is a possible security hole. Do not create Exclusions unless you are sure this hash, path, certificate signer, file type, or browser is always benign.<br>Of course, if you can make the Exclusion by its hash or path, that is much more secure than excluding all detections of a specific signer, file type, or browser. We do not recommend the last types for Exclusions on production endpoints. These Exclusions might be helpful in a lab or pentester group. When you create an Exclusion, make sure you set the filter to the smallest possible scope. For example, if you can exclude security for this item on a group, do not enter values for siteIds or accountIds.<br>We recommend that you read "Not Recommended Exclusions: https://support.sentinelone.com/hc/en-us/articles/360007532894<br> and Best Practices for Exclusions: https://support.sentinelone.com/hc/en-us/articles/360008709014

Required permissions: `Exclusions.create`

Parameters:
- `body` [body, exclusions.schemas_PostExclusionSchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `PUT /web/api/v2.1/exclusions`
**Update Exclusions**
`operationId`: `_web_api_exclusions_put`

Change the properties of an Exclusion through the data fields. To get the original data, run "exclusions" with a filter to give the item you want.

Required permissions: `Exclusions.edit`

Parameters:
- `body` [body, exclusions.schemas_PutExclusionSchema] — 

Responses: 404 Exclusion not found, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/exclusions/import`
**Import Exclusions**
`operationId`: `_web_api_exclusions_import_post`

Upload a CSV file that contains exclusion entries to import to a scope in your Management

Required permissions: `Exclusions.create`

Parameters:
- `filter` [formData, string] — The details of the scope where the entities will be imported, for example:  For Global - '{"tenant":true}' For an Account - '{"accountIds": ["225494730938493804"]}' For a Site  - '{"siteIds": ["225494730938493804"]}' For a Group - '{"groupIds": ["225494730938493804"]}'
- `file` [formData, file] **required** — The input CSV file

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/exclusions/report/{report_id}`
**Get Exclusion Import Validation Report**
`operationId`: `_web_api_exclusions_report_{report_id}_get`

Get the  Validation Report generated for the import to help you fix entries that did not import successfully

Required permissions: `Exclusions.view`

Parameters:
- `report_id` [path, string] **required** — The ID of the requested Validation Report. Example: "225494730938493804".

Responses: 200 Success, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/exclusions/validate`
**Validate Exclusion Item**
`operationId`: `_web_api_exclusions_validate_post`

Check if an exclusion is on the list of SentinelOne items that are "Not Allowed" or "Not Recommended". This API returns one of the following statuses:<br> * Not Recommended: This item is not recommended by SentinelOne because it decreases security. For example, If you accidentally exclude a path that is too broad, malware can enter your environment.<br>* Not Allowed: This exclusion can harm the product and lead to unexpected functionality. From version North Pole SP3 you are prevented from creating Not Allowed exclusions.* None: This item is not on the list of SentinelOne items that are "Not Allowed" or "Not Recommended".

Required permissions: `Exclusions.create`

Parameters:
- `body` [body, exclusions.schemas_ValidateExclusionSchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/export/exclusions`
**Export Exclusions**
`operationId`: `_web_api_export_exclusions_get`

Get a csv of all the items in the Exclusions that match the filter. <br>Note: To see items from the Global Exclusion scope, make sure "tenant" is "true" and no other scope ID is given.

Required permissions: `Exclusions.view`

Parameters:
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "225494730938493804,225494730938493915".
- `siteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `groupIds` [query, array] — List of Group IDs to filter by. Example: "225494730938493804,225494730938493915".
- `tenant` [query, boolean] — Indicates a tenant scope request
- `ids` [query, array] — List of IDs to filter by. Example: "225494730938493804,225494730938493915".
- `unified` [query, boolean] — Unified
- `value` [query, string] — Value
- `createdAt__lt` [query, string] — Created before this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__lte` [query, string] — Created before or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__gt` [query, string] — Created after this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__gte` [query, string] — Created after or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__between` [query, string] — Date range for creation time (format: <from_timestamp>-<to_timestamp>, inclusive). Example: "1514978890136-1514978650130".
- `updatedAt__lt` [query, string] — Updated before this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `updatedAt__lte` [query, string] — Updated before or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `updatedAt__gt` [query, string] — Updated after this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `updatedAt__gte` [query, string] — Updated after or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `updatedAt__between` [query, string] — Date range for update time (format: <from_timestamp>-<to_timestamp>, inclusive). Example: "1514978890136-1514978650130".
- `query` [query, string] — A free-text search term, will match applicable attributes
- `type` [query, string] (enum: path, certificate, browser, file_type, white_hash, dv_exclusions) — Type. Example: "path".
- `osTypes` [query, array] — List of Os types to filter by. Example: "macos".
- `source` [query, array] — List sources to filter by. Example: "user".
- `userIds` [query, array] — List of user ids to filter by. Example: "225494730938493804,225494730938493915".
- `recommendations` [query, array] — List of recommendations to filter by. Example: "Not recommended".
- `value__contains` [query, array] — Free-text filter by value
- `description__contains` [query, array] — Free-text filter by description
- `user__contains` [query, array] — Free-text filter by user name
- `types` [query, array] — Type in. Example: "path".
- `modes` [query, array] — List of modes to filter by (Path exclusions only). Example: "suppress".
- `pathExclusionTypes` [query, array] — List of excluded paths in an exclusion (Path exclusions only). Example: "file".
- `includeParents` [query, boolean] — Return filters from parent scope levels (Default: false)
- `includeChildren` [query, boolean] — Return filters from children scope levels (Default: false)
- `imported` [query, array] — Filter by import status: true (imported), false (not imported), or both for multiselect
- `applicationName__contains` [query, array] — Free-text filter by application name
- `inAppInventory` [query, boolean] — Found or Not found - indicates if this exclusion is related to an application found in the scope's Application Inventory.
- `modeType` [query, string] (enum: all, suppression, agent_interoperability, binary_vault) — Mode type. Example: "all".
- `childProcess` [query, boolean] — Child process
- `threatType` [query, array] — Threat type in. Example: "EDR".
- `engines` [query, array] — Engine in. Example: "suppress".
- `interactionLevel` [query, array] — Interaction level in. Example: "disable_all_monitors".
- `conditions` [query, array] — Conditions in. Example: "white_hash".
- `exclusionName__contains` [query, array] — Exclusion name like any
- `notRecommended` [query, array] — Not recommended in. Example: "Not recommended".
- `scopePath__contains` [query, array] — Scope path like any

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/export/restrictions`
**Export Blocklist**
`operationId`: `_web_api_export_restrictions_get`

Get a csv of all the items in the Blocklist that match the filter. <br>Note: To see items from the Global Blocklist, make sure "tenant" is "true" and no other scope ID is given.

Required permissions: `Blacklist.view`

Parameters:
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "225494730938493804,225494730938493915".
- `siteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `groupIds` [query, array] — List of Group IDs to filter by. Example: "225494730938493804,225494730938493915".
- `tenant` [query, boolean] — Indicates a tenant scope request
- `ids` [query, array] — List of IDs to filter by. Example: "225494730938493804,225494730938493915".
- `unified` [query, boolean] — Unified
- `value` [query, string] — Value
- `createdAt__lt` [query, string] — Created before this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__lte` [query, string] — Created before or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__gt` [query, string] — Created after this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__gte` [query, string] — Created after or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__between` [query, string] — Date range for creation time (format: <from_timestamp>-<to_timestamp>, inclusive). Example: "1514978890136-1514978650130".
- `updatedAt__lt` [query, string] — Updated before this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `updatedAt__lte` [query, string] — Updated before or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `updatedAt__gt` [query, string] — Updated after this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `updatedAt__gte` [query, string] — Updated after or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `updatedAt__between` [query, string] — Date range for update time (format: <from_timestamp>-<to_timestamp>, inclusive). Example: "1514978890136-1514978650130".
- `query` [query, string] — A free-text search term, will match applicable attributes
- `type` [query, string] (enum: black_hash) — Type. Example: "black_hash".
- `osTypes` [query, array] — List of Os types to filter by. Example: "macos".
- `source` [query, array] — List sources to filter by. Example: "user".
- `userIds` [query, array] — List of user ids to filter by. Example: "225494730938493804,225494730938493915".
- `recommendations` [query, array] — List of recommendations to filter by. Example: "Not recommended".
- `value__contains` [query, array] — Free-text filter by value
- `description__contains` [query, array] — Free-text filter by description
- `user__contains` [query, array] — Free-text filter by user name
- `types` [query, array] — Type in. Example: "black_hash".
- `includeParents` [query, boolean] — Return filters from parent scope levels (Default: false)
- `includeChildren` [query, boolean] — Return filters from children scope levels (Default: false)
- `imported` [query, array] — Filter by import status: true (imported), false (not imported), or both for multiselect

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `DELETE /web/api/v2.1/restrictions`
**Delete Blocklist Item**
`operationId`: `_web_api_restrictions_delete`

Agents immediately identify files on the blocklist and block them from executing. Agents identify files on the blocklist before they look at exclusions. If there is a conflict - for example, if a hash is blocklisted from the Cloud Intelligence, and you have an exclusion to run an application that requires this hash - you can delete the hash from the Blocklist. Users with the IT role do not have permissions to run this command.

Required permissions: `Blacklist.delete`

Parameters:
- `body` [body, exclusions.schemas_DeleteRestrictionSchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/restrictions`
**Get Blocklist**
`operationId`: `_web_api_restrictions_get`

Get a list of all the items in the Blocklist that match the filter. <br>To filter the results for a scope:<br>* Global - Make sure "tenant" is "true" and no other scope ID is given.<br>* Account - Make sure "tenant" is "false" and at least one Account ID is given.<br>* Site - Make sure "tenant" is "false" and at least one Site ID is given.

Required permissions: `Blacklist.view`

Parameters:
- `skip` [query, integer] — Skip first number of items (0-1000). To iterate over more than 1000 items,  use "cursor". Example: "150".
- `limit` [query, integer] — Limit number of returned items (1-1000). Example: "10".
- `cursor` [query, string] — Cursor position returned by the last request. Use to iterate over more than 1000 items. Example: "YWdlbnRfaWQ6NTgwMjkzODE=".
- `countOnly` [query, boolean] — If true, only total number of items will be returned, without any of the actual objects.
- `skipCount` [query, boolean] — If true, total number of items will not be calculated, which speeds up execution time.
- `sortBy` [query, string] (enum: id, createdAt, updatedAt, osType, description, scope, value, userName, source, scopePath, imported) — The column to sort the results by. Example: "id".
- `sortOrder` [query, string] (enum: asc, desc) — Sort direction. Example: "asc".
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "225494730938493804,225494730938493915".
- `siteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `groupIds` [query, array] — List of Group IDs to filter by. Example: "225494730938493804,225494730938493915".
- `tenant` [query, boolean] — Indicates a tenant scope request
- `ids` [query, array] — List of IDs to filter by. Example: "225494730938493804,225494730938493915".
- `unified` [query, boolean] — Unified
- `value` [query, string] — Value
- `createdAt__lt` [query, string] — Created before this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__lte` [query, string] — Created before or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__gt` [query, string] — Created after this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__gte` [query, string] — Created after or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__between` [query, string] — Date range for creation time (format: <from_timestamp>-<to_timestamp>, inclusive). Example: "1514978890136-1514978650130".
- `updatedAt__lt` [query, string] — Updated before this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `updatedAt__lte` [query, string] — Updated before or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `updatedAt__gt` [query, string] — Updated after this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `updatedAt__gte` [query, string] — Updated after or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `updatedAt__between` [query, string] — Date range for update time (format: <from_timestamp>-<to_timestamp>, inclusive). Example: "1514978890136-1514978650130".
- `query` [query, string] — A free-text search term, will match applicable attributes
- `type` [query, string] (enum: black_hash) — Type. Example: "black_hash".
- `osTypes` [query, array] — List of Os types to filter by. Example: "macos".
- `source` [query, array] — List sources to filter by. Example: "user".
- `userIds` [query, array] — List of user ids to filter by. Example: "225494730938493804,225494730938493915".
- `recommendations` [query, array] — List of recommendations to filter by. Example: "Not recommended".
- `value__contains` [query, array] — Free-text filter by value
- `description__contains` [query, array] — Free-text filter by description
- `user__contains` [query, array] — Free-text filter by user name
- `types` [query, array] — Type in. Example: "black_hash".
- `includeParents` [query, boolean] — Return filters from parent scope levels (Default: false)
- `includeChildren` [query, boolean] — Return filters from children scope levels (Default: false)
- `imported` [query, array] — Filter by import status: true (imported), false (not imported), or both for multiselect
- `modes` [query, array] — List of modes to filter by (Path exclusions only). Example: "suppress".

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/restrictions`
**Create Blocklist Item**
`operationId`: `_web_api_restrictions_post`

Create a blocklist item for a SHA1 or SHA256 hash or both, for the scopes you enter in the filter fields. You can add the hash to multiple Groups, Sites, Accounts, and to the Global list. <br> IMPORTANT: The type must be "black_hash" - any other value will create an Exclusion rather than a Blocklist item.<br>Users with the IT role do not have permissions to run this.

Required permissions: `Blacklist.create`

Parameters:
- `body` [body, exclusions.schemas_PostRestrictionSchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `PUT /web/api/v2.1/restrictions`
**Update Blocklist Item**
`operationId`: `_web_api_restrictions_put`

Change the properties of a Blocklist item through the data fields. To get the original data, run "restrictions" with a filter to give the item you want.

Required permissions: `Blacklist.edit`

Parameters:
- `body` [body, exclusions.schemas_PutRestrictionSchema] — 

Responses: 404 Blocklist not found, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/restrictions/import`
**Import Blocklist Items**
`operationId`: `_web_api_restrictions_import_post`

Upload a CSV file that contains blocklist entries to import to a scope in your Management

Required permissions: `Blacklist.create`

Parameters:
- `filter` [formData, string] — The details of the scope where the entities will be imported, for example:  For Global - '{"tenant":true}' For an Account - '{"accountIds": ["225494730938493804"]}' For a Site  - '{"siteIds": ["225494730938493804"]}' For a Group - '{"groupIds": ["225494730938493804"]}'
- `file` [formData, file] **required** — The input CSV file

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/restrictions/report/{report_id}`
**Get Blocklist Import Validation Report**
`operationId`: `_web_api_restrictions_report_{report_id}_get`

Get the  Validation Report generated for the import to help you fix entries that did not import successfully

Required permissions: `Exclusions.view`

Parameters:
- `report_id` [path, string] **required** — The ID of the requested Validation Report. Example: "225494730938493804".

Responses: 200 Success, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/restrictions/validate`
**Validate Blocklist Item**
`operationId`: `_web_api_restrictions_validate_post`

Check if a hash is on the list of SentinelOne items that are "Not Allowed" or "Not Recommended". This API returns one of the following statuses:<br> * Not Recommended: This item is not recommended by SentinelOne because it decreases security. <br>* Not Allowed: This item can harm the product and lead to unexpected functionality. From version North Pole SP3 you are prevented from creating Not Allowed blocklist item. * None: This item is not on the list of SentinelOne items that are "Not Allowed" or "Not Recommended".

Required permissions: `Blacklist.create`

Parameters:
- `body` [body, exclusions.schemas_ValidateRestrictionSchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.
