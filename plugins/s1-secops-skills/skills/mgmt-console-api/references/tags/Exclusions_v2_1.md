# Exclusions v2.1

8 endpoints.

## `DELETE /web/api/v2.1/unified-exclusions`
**Delete Exclusions**
`operationId`: `_web_api_unified-exclusions_delete`

Required permissions: `Exclusions.delete`

Parameters:
- `body` [body, exclusions.delete_schema_UnifiedExclusionSchemaDeleteRequest] — 

Responses: 403 User is not allowed to perform this operation., 200 Exclusions successfully deleted., 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/unified-exclusions`
**Get Exclusions**
`operationId`: `_web_api_unified-exclusions_get`

Get a list of all the Exclusions that match the filter. <br>Note: To filter the results for a scope: <br>* Global - Make sure "tenant" is "true" and no other scope ID is given.<br>* Account - Make sure "tenant" is "false" and at least one Account ID is given.<br>* Site - Make sure "tenant" is "false" and at least one Site ID is given.

Required permissions: `Exclusions.view`

Parameters:
- `skip` [query, integer] — Skip first number of items (0-1000). To iterate over more than 1000 items,  use "cursor". Example: "150".
- `limit` [query, integer] — Limit number of returned items (1-1000). Example: "10".
- `cursor` [query, string] — Cursor position returned by the last request. Use to iterate over more than 1000 items. Example: "YWdlbnRfaWQ6NTgwMjkzODE=".
- `countOnly` [query, boolean] — If true, only total number of items will be returned, without any of the actual objects.
- `skipCount` [query, boolean] — If true, total number of items will not be calculated, which speeds up execution time.
- `sortBy` [query, string] (enum: id, createdAt, updatedAt, source, description, osType, scope, userName, scopePath, notRecommended, interactionLevel, childProcess, reason, user, threatType, engines, exclusionName, modeType, inAppInventory) — The column to sort the results by. Example: "id".
- `sortOrder` [query, string] (enum: asc, desc) — Sort direction. Example: "asc".
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "225494730938493804,225494730938493915".
- `siteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `groupIds` [query, array] — List of Group IDs to filter by. Example: "225494730938493804,225494730938493915".
- `tenant` [query, boolean] — Indicates a tenant scope request
- `ids` [query, array] — List of IDs to filter by. Example: "225494730938493804,225494730938493915".
- `idsNin` [query, array] — List of IDs to exclude from filter. Example: "225494730938493804,225494730938493915".
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
- `osTypes` [query, array] — List of OS types to filter by. Example: "macos".
- `source` [query, array] — List sources to filter by. Example: "user".
- `userIds` [query, array] — List of user IDs to filter by. Example: "225494730938493804,225494730938493915".
- `modeType` [query, array] — List of Exclusion Type to filter by: suppression, agent_interoperability, or binary_vault . Example: "all".
- `notRecommended` [query, array] — List of recommendations to filter by. Example: "Not recommended".
- `warnings` [query, array] — List of warnings to filter by. Example: "Not allowed".
- `pathExclusionTypes` [query, array] — List of excluded paths in an exclusion to filter by. Applies only to EDR exclusions of type path. Example: "file".
- `threatType` [query, array] — List of threat types to filter by. Example: "EDR".
- `engines` [query, array] — List of engines to filter by. Example: "suppress".
- `interactionLevel` [query, array] — List of interaction levels to filter by. Example: "disable_all_monitors".
- `includeParents` [query, boolean] — Return filters from parent scope levels (Default: false).
- `includeChildren` [query, boolean] — Return filters from children scope levels (Default: false).
- `imported` [query, boolean] — Indicates if the exclusion was imported by a bulk operation or not. You can filter by this.
- `conditions` [query, array] — List of conditions to filter by. Example: "white_hash".
- `childProcess` [query, boolean] — Indicates if the exclusion applies to child processes or not. You can filter by this.
- `inAppInventory` [query, boolean] — Indicates if the exclusion is related to an application found in the scope's Application Inventory or not. You can filter by this.
- `exclusionName__contains` [query, array] — Free-text filter by exclusion name.
- `applicationName__contains` [query, array] — Free-text filter by application name.
- `value__contains` [query, array] — Free-text filter by value.
- `podName__contains` [query, array] — Free-text filter by pod name.
- `containerName__contains` [query, array] — Free-text filter by container name.
- `namespace__contains` [query, array] — Free-text filter by namespace.
- `sha256Image__contains` [query, array] — Free-text filter by SHA-256 of an image.
- `fullImageName__contains` [query, array] — Free-text filter by full image URI.
- `labelsKey__contains` [query, array] — Free-text filter by label key.
- `labelsValue__contains` [query, array] — Free-text filter by label value.
- `cmdlineValue__contains` [query, array] — Free-text filter by nested cmdline value.
- `pathValue__contains` [query, array] — Free-text filter by nested path value.
- `description__contains` [query, array] — Free-text filter by description.
- `user__contains` [query, array] — Free-text filter by username.
- `scopePath__contains` [query, array] — Free-text filter by scope path.
- `tags` [query, string] — Filter exclusions by their assigned tags. Given in form of a JSON where each key represents a tag key, and each value represents a list of string values to filter by. To filter by unassigned tag values, use __nin suffix in the tag key. Example: "{"key1": ["value1_1", "value1_2"], "key2__nin": ["value2"]}".
- `hasTags` [query, boolean] — Include only Exclusions that have any tags assigned if True, or none if False
- `tagIds` [query, array] — List of tag IDs to filter by. Example: "225494730938493804,225494730938493915".
- `countsFor` [query, string] — comma-separated list of fields to be shown. Example: "threatType,interactionLevel".
- `tagsByGroup` [query, string] — Group exclusions by their assigned tags. Given in form of a JSON where each key represents a tag key, and each value represents a list of string values to filter by. . Example: "{"key1": ["value1_1", "value1_2"], "key2": ["value2"]}".
- `hasTagsByGroup` [query, boolean] — Include Exclusions that have any tags assigned if True, or none if False

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/unified-exclusions`
**Create Unified Exclusion**
`operationId`: `_web_api_unified-exclusions_post`

Create Exclusions to make your Agents suppress alerts and mitigation for items that you consider to be benign or which you require for interoperability.<br>IMPORTANT! Every Exclusion is a possible security hole. Do not create Exclusions unless you are sure this hash, path, certificate signer, file type, or browser is always benign.<br>Of course, if you can make the Exclusion by its hash or path, that is much more secure than excluding all detections of a specific signer, file type, or browser. We do not recommend the last types for Exclusions on production endpoints. These Exclusions might be helpful in a lab or pentester group. When you create an Exclusion, make sure you set the filter to the smallest possible scope. For example, if you can exclude security for this item on a group, do not enter values for siteIds or accountIds.<br>We recommend that you read "Not Recommended Exclusions and Best Practices for Exclusions.<br>See the Help from the Console for more details.

Required permissions: `Exclusions.create`

Parameters:
- `body` [body, object] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `PUT /web/api/v2.1/unified-exclusions`
**Update Exclusions**
`operationId`: `_web_api_unified-exclusions_put`

Change the properties of an Exclusion through the data fields. To get the original data, run "exclusions" with a filter to give the item you want.

Required permissions: `Exclusions.edit`

Parameters:
- `body` [body, object] — 

Responses: 404 Exclusion not found, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/unified-exclusions/available-actions`
**Get Exclusion Actions**
`operationId`: `_web_api_unified-exclusions_available-actions_get`

Get a list of available actions for exclusions that match the filter criteria.

Required permissions: `Exclusions.view`

Parameters:
- `skip` [query, integer] — Skip first number of items (0-1000). To iterate over more than 1000 items,  use "cursor". Example: "150".
- `limit` [query, integer] — Limit number of returned items (1-1000). Example: "10".
- `cursor` [query, string] — Cursor position returned by the last request. Use to iterate over more than 1000 items. Example: "YWdlbnRfaWQ6NTgwMjkzODE=".
- `countOnly` [query, boolean] — If true, only total number of items will be returned, without any of the actual objects.
- `skipCount` [query, boolean] — If true, total number of items will not be calculated, which speeds up execution time.
- `sortBy` [query, string] (enum: id, createdAt, updatedAt, source, description, osType, scope, userName, scopePath, notRecommended, interactionLevel, childProcess, reason, user, threatType, engines, exclusionName, modeType, inAppInventory) — The column to sort the results by. Example: "id".
- `sortOrder` [query, string] (enum: asc, desc) — Sort direction. Example: "asc".
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "225494730938493804,225494730938493915".
- `siteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `groupIds` [query, array] — List of Group IDs to filter by. Example: "225494730938493804,225494730938493915".
- `tenant` [query, boolean] — Indicates a tenant scope request
- `ids` [query, array] — List of IDs to filter by. Example: "225494730938493804,225494730938493915".
- `idsNin` [query, array] — List of IDs to exclude from filter. Example: "225494730938493804,225494730938493915".
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
- `osTypes` [query, array] — List of OS types to filter by. Example: "macos".
- `source` [query, array] — List sources to filter by. Example: "user".
- `userIds` [query, array] — List of user IDs to filter by. Example: "225494730938493804,225494730938493915".
- `modeType` [query, array] — List of Exclusion Type to filter by: suppression, agent_interoperability, or binary_vault . Example: "all".
- `notRecommended` [query, array] — List of recommendations to filter by. Example: "Not recommended".
- `warnings` [query, array] — List of warnings to filter by. Example: "Not allowed".
- `pathExclusionTypes` [query, array] — List of excluded paths in an exclusion to filter by. Applies only to EDR exclusions of type path. Example: "file".
- `threatType` [query, array] — List of threat types to filter by. Example: "EDR".
- `engines` [query, array] — List of engines to filter by. Example: "suppress".
- `interactionLevel` [query, array] — List of interaction levels to filter by. Example: "disable_all_monitors".
- `includeParents` [query, boolean] — Return filters from parent scope levels (Default: false).
- `includeChildren` [query, boolean] — Return filters from children scope levels (Default: false).
- `imported` [query, boolean] — Indicates if the exclusion was imported by a bulk operation or not. You can filter by this.
- `conditions` [query, array] — List of conditions to filter by. Example: "white_hash".
- `childProcess` [query, boolean] — Indicates if the exclusion applies to child processes or not. You can filter by this.
- `inAppInventory` [query, boolean] — Indicates if the exclusion is related to an application found in the scope's Application Inventory or not. You can filter by this.
- `exclusionName__contains` [query, array] — Free-text filter by exclusion name.
- `applicationName__contains` [query, array] — Free-text filter by application name.
- `value__contains` [query, array] — Free-text filter by value.
- `podName__contains` [query, array] — Free-text filter by pod name.
- `containerName__contains` [query, array] — Free-text filter by container name.
- `namespace__contains` [query, array] — Free-text filter by namespace.
- `sha256Image__contains` [query, array] — Free-text filter by SHA-256 of an image.
- `fullImageName__contains` [query, array] — Free-text filter by full image URI.
- `labelsKey__contains` [query, array] — Free-text filter by label key.
- `labelsValue__contains` [query, array] — Free-text filter by label value.
- `cmdlineValue__contains` [query, array] — Free-text filter by nested cmdline value.
- `pathValue__contains` [query, array] — Free-text filter by nested path value.
- `description__contains` [query, array] — Free-text filter by description.
- `user__contains` [query, array] — Free-text filter by username.
- `scopePath__contains` [query, array] — Free-text filter by scope path.
- `tags` [query, string] — Filter exclusions by their assigned tags. Given in form of a JSON where each key represents a tag key, and each value represents a list of string values to filter by. To filter by unassigned tag values, use __nin suffix in the tag key. Example: "{"key1": ["value1_1", "value1_2"], "key2__nin": ["value2"]}".
- `hasTags` [query, boolean] — Include only Exclusions that have any tags assigned if True, or none if False
- `tagIds` [query, array] — List of tag IDs to filter by. Example: "225494730938493804,225494730938493915".
- `countsFor` [query, string] — comma-separated list of fields to be shown. Example: "threatType,interactionLevel".
- `tagsByGroup` [query, string] — Group exclusions by their assigned tags. Given in form of a JSON where each key represents a tag key, and each value represents a list of string values to filter by. . Example: "{"key1": ["value1_1", "value1_2"], "key2": ["value2"]}".
- `hasTagsByGroup` [query, boolean] — Include Exclusions that have any tags assigned if True, or none if False
- `create` [query, boolean] **required** — Create
- `selectAll` [query, boolean] — When true, calculate actions for all exclusions matching filters (not just selected IDs).

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/unified-exclusions/bulk`
**Create Bulk Unified Exclusion**
`operationId`: `_web_api_unified-exclusions_bulk_post`

Create Bulk Exclusions to make your Agents suppress alerts and mitigation for items that you consider to be benign or which you require for interoperability.<br>IMPORTANT! Every Exclusion is a possible security hole. Do not create Exclusions unless you are sure this hash, path, certificate signer, file type, or browser is always benign.<br>Of course, if you can make the Exclusion by its hash or path, that is much more secure than excluding all detections of a specific signer, file type, or browser. We do not recommend the last types for Exclusions on production endpoints. These Exclusions might be helpful in a lab or pentester group. When you create an Exclusion, make sure you set the filter to the smallest possible scope. For example, if you can exclude security for this item on a group, do not enter values for siteIds or accountIds.<br>We recommend that you read "Not Recommended Exclusions and Best Practices for Exclusions.<br>See the Help from the Console for more details.

Required permissions: `Exclusions.create`

Parameters:
- `body` [body, exclusions.post_schema_PostUnifiedExclusionSchema_many] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/unified-exclusions/export`
**Export Unified Exclusions**
`operationId`: `_web_api_unified-exclusions_export_get`

Export the currently filtered exclusions to a JSON file. You can use the export file to import the exclusions to a different scope.

Required permissions: `Exclusions.view`

Parameters:
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "225494730938493804,225494730938493915".
- `siteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `groupIds` [query, array] — List of Group IDs to filter by. Example: "225494730938493804,225494730938493915".
- `tenant` [query, boolean] — Indicates a tenant scope request
- `ids` [query, array] — List of IDs to filter by. Example: "225494730938493804,225494730938493915".
- `idsNin` [query, array] — List of IDs to exclude from filter. Example: "225494730938493804,225494730938493915".
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
- `osTypes` [query, array] — List of OS types to filter by. Example: "macos".
- `source` [query, array] — List sources to filter by. Example: "user".
- `userIds` [query, array] — List of user IDs to filter by. Example: "225494730938493804,225494730938493915".
- `modeType` [query, array] — List of Exclusion Type to filter by: suppression, agent_interoperability, or binary_vault . Example: "all".
- `notRecommended` [query, array] — List of recommendations to filter by. Example: "Not recommended".
- `warnings` [query, array] — List of warnings to filter by. Example: "Not allowed".
- `pathExclusionTypes` [query, array] — List of excluded paths in an exclusion to filter by. Applies only to EDR exclusions of type path. Example: "file".
- `threatType` [query, array] — List of threat types to filter by. Example: "EDR".
- `engines` [query, array] — List of engines to filter by. Example: "suppress".
- `interactionLevel` [query, array] — List of interaction levels to filter by. Example: "disable_all_monitors".
- `includeParents` [query, boolean] — Return filters from parent scope levels (Default: false).
- `includeChildren` [query, boolean] — Return filters from children scope levels (Default: false).
- `imported` [query, boolean] — Indicates if the exclusion was imported by a bulk operation or not. You can filter by this.
- `conditions` [query, array] — List of conditions to filter by. Example: "white_hash".
- `childProcess` [query, boolean] — Indicates if the exclusion applies to child processes or not. You can filter by this.
- `inAppInventory` [query, boolean] — Indicates if the exclusion is related to an application found in the scope's Application Inventory or not. You can filter by this.
- `exclusionName__contains` [query, array] — Free-text filter by exclusion name.
- `applicationName__contains` [query, array] — Free-text filter by application name.
- `value__contains` [query, array] — Free-text filter by value.
- `podName__contains` [query, array] — Free-text filter by pod name.
- `containerName__contains` [query, array] — Free-text filter by container name.
- `namespace__contains` [query, array] — Free-text filter by namespace.
- `sha256Image__contains` [query, array] — Free-text filter by SHA-256 of an image.
- `fullImageName__contains` [query, array] — Free-text filter by full image URI.
- `labelsKey__contains` [query, array] — Free-text filter by label key.
- `labelsValue__contains` [query, array] — Free-text filter by label value.
- `cmdlineValue__contains` [query, array] — Free-text filter by nested cmdline value.
- `pathValue__contains` [query, array] — Free-text filter by nested path value.
- `description__contains` [query, array] — Free-text filter by description.
- `user__contains` [query, array] — Free-text filter by username.
- `scopePath__contains` [query, array] — Free-text filter by scope path.
- `tags` [query, string] — Filter exclusions by their assigned tags. Given in form of a JSON where each key represents a tag key, and each value represents a list of string values to filter by. To filter by unassigned tag values, use __nin suffix in the tag key. Example: "{"key1": ["value1_1", "value1_2"], "key2__nin": ["value2"]}".
- `hasTags` [query, boolean] — Include only Exclusions that have any tags assigned if True, or none if False
- `tagIds` [query, array] — List of tag IDs to filter by. Example: "225494730938493804,225494730938493915".
- `countsFor` [query, string] — comma-separated list of fields to be shown. Example: "threatType,interactionLevel".
- `tagsByGroup` [query, string] — Group exclusions by their assigned tags. Given in form of a JSON where each key represents a tag key, and each value represents a list of string values to filter by. . Example: "{"key1": ["value1_1", "value1_2"], "key2": ["value2"]}".
- `hasTagsByGroup` [query, boolean] — Include Exclusions that have any tags assigned if True, or none if False

Responses: 403 User is not allowed to perform this operation., 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/unified-exclusions/import`
**Import Unified Exclusions**
`operationId`: `_web_api_unified-exclusions_import_post`

Import exclusions to a specified scope in the Console. Use an exclusion JSON file exported from a different scope. Exported exclusion CSV files are also supported.

Required permissions: `Exclusions.create`

Parameters:
- `filter` [formData, object] **required** — Filter
- `file` [formData, file] **required** — The input JSON or CSV file

Responses: 403 User is not allowed to perform this operation., 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.
