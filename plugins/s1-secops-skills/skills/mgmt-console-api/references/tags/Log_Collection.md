# Log Collection

9 endpoints.

## `GET /web/api/v2.1/log-collection/agent-type-count`
**Get Agent type count**
`operationId`: `_web_api_log-collection_agent-type-count_get`

Get the total number of log collection rules per agent type

Required permissions: `Log Collection Rules.view`

Parameters:
- `accountIds` [query, array] — List of account IDs to filter by. Example: "225494730938493804,225494730938493915".
- `siteIds` [query, array] — List of site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `groupIds` [query, array] — List of group IDs to filter by. Example: "225494730938493804,225494730938493915".
- `tenant` [query, boolean] — Indicates a tenant scope request
- `includeParents` [query, boolean] — Return rules from parent scope levels
- `includeChildren` [query, boolean] — Return filters from children scope levels

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `DELETE /web/api/v2.1/log-collection/rules`
**Delete log collection rules**
`operationId`: `_web_api_log-collection_rules_delete`

Required permissions: `Log Collection Rules.delete`

Parameters:
- `body` [body, log_collection.schemas.delete_schema_LogCollectionRulesDeleteSchema] — 

Responses: 400 Invalid user input received. See error details for further i, 200 Success, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/log-collection/rules`
**Get Log Collection rules**
`operationId`: `_web_api_log-collection_rules_get`

Required permissions: `Log Collection Rules.view`

Parameters:
- `skip` [query, integer] — Skip first number of items (0-1000). To iterate over more than 1000 items,  use "cursor". Example: "150".
- `limit` [query, integer] — Limit number of returned items (1-1000). Example: "10".
- `cursor` [query, string] — Cursor position returned by the last request. Use to iterate over more than 1000 items. Example: "YWdlbnRfaWQ6NTgwMjkzODE=".
- `countOnly` [query, boolean] — If true, only total number of items will be returned, without any of the actual objects.
- `skipCount` [query, boolean] — If true, total number of items will not be calculated, which speeds up execution time.
- `sortBy` [query, string] (enum: id, createdAt, createdBy, updatedAt, updatedBy, scopeId, scopeLevel, name, agentType, configurationType, collectionType, state, description, enabled, parser, scopePath, collectionPath, logPrefix, excludedLogs, collectionTags, excludedTags, uuid, eventIds, collectionPathOrChannel, levels, providers, welExcludedIds) — The column to sort the results by. Example: "id".
- `sortOrder` [query, string] (enum: asc, desc) — Sort direction. Example: "asc".
- `accountIds` [query, array] — List of account IDs to filter by. Example: "225494730938493804,225494730938493915".
- `siteIds` [query, array] — List of site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `groupIds` [query, array] — List of group IDs to filter by. Example: "225494730938493804,225494730938493915".
- `tenant` [query, boolean] — Indicates a tenant scope request
- `ids` [query, array] — List of IDs to filter by. Example: "225494730938493804,225494730938493915".
- `scope` [query, string] (enum: group, site, account, tenant) — Scope. Example: "group".
- `scopes` [query, array] — List of scopes to filter by. Example: "group".
- `name` [query, string] — Name
- `names` [query, array] — List of names to filter by.
- `name__contains` [query, array] — Free-text filter by rule name (supports multiple)
- `agentType` [query, string] (enum: windows, linux, macos, k8s, k8sAndContainers) — Agent type. Example: "windows".
- `agentTypes` [query, array] — List of agent types to filter by. Example: "windows".
- `configurationType` [query, string] (enum: collectionPath, predicate) — Configuration type. Example: "collectionPath".
- `configurationTypes` [query, array] — List of configuration types to filter by. Example: "collectionPath".
- `collectionType` [query, string] (enum: applicationLog, unifiedLogging, windowsEventLog, flatFileLog) — Collection type. Example: "applicationLog".
- `collectionTypes` [query, array] — List of collection types to filter by. Example: "applicationLog".
- `state` [query, boolean] — State
- `enabled` [query, array] — Include enabled, disabled or both. Example: "True,False".
- `description__contains` [query, array] — Free-text filter by rule description (supports multiple)
- `collectionPath` [query, string] — Collection path
- `collectionPaths` [query, array] — List of collection paths to filter by.
- `collectionPath__contains` [query, array] — Free-text filter by rule collection path (supports multiple)
- `collectionTags` [query, array] — Exact match filter by collection tags (supports multiple)
- `collectionTags__contains` [query, array] — Free-text filter by rule collection tags (supports multiple)
- `excludedTags` [query, array] — Exact match filter by excluded tags (supports multiple)
- `excludedTags__contains` [query, array] — Free-text filter by rule exclued tags (supports multiple)
- `excludedLogs__contains` [query, array] — Free-text filter by rule exclued logs (supports multiple)
- `parser__contains` [query, array] — Free-text filter by rule parser (supports multiple)
- `createdBy__contains` [query, array] — Free-text filter by rule author (supports multiple)
- `updatedBy__contains` [query, array] — Free-text filter by rule last updater (supports multiple)
- `scopePath` [query, string] — Scope path
- `scopePaths` [query, array] — List of scope paths to filter by.
- `scopePath__contains` [query, array] — Free-text filter by scope path (supports multiple)
- `createdAt__between` [query, string] — Date range for creation time (format: <from_timestamp>-<to_timestamp>, inclusive). Example: "1514978890136-1514978650130".
- `updatedAt__between` [query, string] — Date range for last update time (format: <from_timestamp>-<to_timestamp>, inclusive). Example: "1514978890136-1514978650130".
- `excludedIds` [query, array] — List of IDs to exclude. Example: "225494730938493804,225494730938493915".
- `logPrefix__contains` [query, array] — Free-text filter by rule parser (supports multiple)
- `collectionPathOrChannel` [query, string] — Collection path or channel
- `collectionPathsOrChannel` [query, array] — List of collection paths to filter by.
- `collectionPathOrChannel__contains` [query, array] — Free-text filter by rule collection path or channel (supports multiple)
- `eventIds` [query, array] — Exact match filter by event Ids (supports multiple)
- `eventIds__contains` [query, array] — Free-text filter by rule eventIds (supports multiple)
- `welExcludedIds__contains` [query, array] — Free-text filter by rule exclued ids (supports multiple)
- `includeParents` [query, boolean] — Return rules from parent scope levels
- `includeChildren` [query, boolean] — Return filters from children scope levels

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/log-collection/rules`
**Create a log collection rule**
`operationId`: `_web_api_log-collection_rules_post`

Required permissions: `Log Collection Rules.create`

Parameters:
- `body` [body, log_collection.schemas.post_schema_LogCollectionRulesPostSchema] — 

Responses: 400 Invalid user input received. See error details for further i, 409 Conflict, 200 Success, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/log-collection/rules/activation`
**Change activation status of log collection rules**
`operationId`: `_web_api_log-collection_rules_activation_post`

Required permissions: `Log Collection Rules.activate`

Parameters:
- `body` [body, log_collection.schemas.post_schema_LogCollectionRulesActivationPostSchema] — 

Responses: 400 Invalid user input received. See error details for further i, 200 Success, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/log-collection/rules/export`
**Export log collection rules**
`operationId`: `_web_api_log-collection_rules_export_get`

Get a CSV file with all log collection rules according to the passed filters

Required permissions: `Log Collection Rules.view`

Parameters:
- `accountIds` [query, array] — List of account IDs to filter by. Example: "225494730938493804,225494730938493915".
- `siteIds` [query, array] — List of site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `groupIds` [query, array] — List of group IDs to filter by. Example: "225494730938493804,225494730938493915".
- `tenant` [query, boolean] — Indicates a tenant scope request
- `ids` [query, array] — List of IDs to filter by. Example: "225494730938493804,225494730938493915".
- `scope` [query, string] (enum: group, site, account, tenant) — Scope. Example: "group".
- `scopes` [query, array] — List of scopes to filter by. Example: "group".
- `name` [query, string] — Name
- `names` [query, array] — List of names to filter by.
- `name__contains` [query, array] — Free-text filter by rule name (supports multiple)
- `agentType` [query, string] (enum: windows, linux, macos, k8s, k8sAndContainers) — Agent type. Example: "windows".
- `agentTypes` [query, array] — List of agent types to filter by. Example: "windows".
- `configurationType` [query, string] (enum: collectionPath, predicate) — Configuration type. Example: "collectionPath".
- `configurationTypes` [query, array] — List of configuration types to filter by. Example: "collectionPath".
- `collectionType` [query, string] (enum: applicationLog, unifiedLogging, windowsEventLog, flatFileLog) — Collection type. Example: "applicationLog".
- `collectionTypes` [query, array] — List of collection types to filter by. Example: "applicationLog".
- `state` [query, boolean] — State
- `enabled` [query, array] — Include enabled, disabled or both. Example: "True,False".
- `description__contains` [query, array] — Free-text filter by rule description (supports multiple)
- `collectionPath` [query, string] — Collection path
- `collectionPaths` [query, array] — List of collection paths to filter by.
- `collectionPath__contains` [query, array] — Free-text filter by rule collection path (supports multiple)
- `collectionTags` [query, array] — Exact match filter by collection tags (supports multiple)
- `collectionTags__contains` [query, array] — Free-text filter by rule collection tags (supports multiple)
- `excludedTags` [query, array] — Exact match filter by excluded tags (supports multiple)
- `excludedTags__contains` [query, array] — Free-text filter by rule exclued tags (supports multiple)
- `excludedLogs__contains` [query, array] — Free-text filter by rule exclued logs (supports multiple)
- `parser__contains` [query, array] — Free-text filter by rule parser (supports multiple)
- `createdBy__contains` [query, array] — Free-text filter by rule author (supports multiple)
- `updatedBy__contains` [query, array] — Free-text filter by rule last updater (supports multiple)
- `scopePath` [query, string] — Scope path
- `scopePaths` [query, array] — List of scope paths to filter by.
- `scopePath__contains` [query, array] — Free-text filter by scope path (supports multiple)
- `createdAt__between` [query, string] — Date range for creation time (format: <from_timestamp>-<to_timestamp>, inclusive). Example: "1514978890136-1514978650130".
- `updatedAt__between` [query, string] — Date range for last update time (format: <from_timestamp>-<to_timestamp>, inclusive). Example: "1514978890136-1514978650130".
- `excludedIds` [query, array] — List of IDs to exclude. Example: "225494730938493804,225494730938493915".
- `logPrefix__contains` [query, array] — Free-text filter by rule parser (supports multiple)
- `collectionPathOrChannel` [query, string] — Collection path or channel
- `collectionPathsOrChannel` [query, array] — List of collection paths to filter by.
- `collectionPathOrChannel__contains` [query, array] — Free-text filter by rule collection path or channel (supports multiple)
- `eventIds` [query, array] — Exact match filter by event Ids (supports multiple)
- `eventIds__contains` [query, array] — Free-text filter by rule eventIds (supports multiple)
- `welExcludedIds__contains` [query, array] — Free-text filter by rule exclued ids (supports multiple)
- `includeParents` [query, boolean] — Return rules from parent scope levels
- `includeChildren` [query, boolean] — Return filters from children scope levels

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/log-collection/rules/export/{agent_type}`
**Export log collection rules**
`operationId`: `_web_api_log-collection_rules_export_{agent_type}_get`

Get a CSV file with all log collection rules according to the passed filters

Required permissions: `Log Collection Rules.view`

Parameters:
- `agent_type` [path, string] **required** — Agent type
- `accountIds` [query, array] — List of account IDs to filter by. Example: "225494730938493804,225494730938493915".
- `siteIds` [query, array] — List of site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `groupIds` [query, array] — List of group IDs to filter by. Example: "225494730938493804,225494730938493915".
- `tenant` [query, boolean] — Indicates a tenant scope request
- `ids` [query, array] — List of IDs to filter by. Example: "225494730938493804,225494730938493915".
- `scope` [query, string] (enum: group, site, account, tenant) — Scope. Example: "group".
- `scopes` [query, array] — List of scopes to filter by. Example: "group".
- `name` [query, string] — Name
- `names` [query, array] — List of names to filter by.
- `name__contains` [query, array] — Free-text filter by rule name (supports multiple)
- `agentType` [query, string] (enum: windows, linux, macos, k8s, k8sAndContainers) — Agent type. Example: "windows".
- `agentTypes` [query, array] — List of agent types to filter by. Example: "windows".
- `configurationType` [query, string] (enum: collectionPath, predicate) — Configuration type. Example: "collectionPath".
- `configurationTypes` [query, array] — List of configuration types to filter by. Example: "collectionPath".
- `collectionType` [query, string] (enum: applicationLog, unifiedLogging, windowsEventLog, flatFileLog) — Collection type. Example: "applicationLog".
- `collectionTypes` [query, array] — List of collection types to filter by. Example: "applicationLog".
- `state` [query, boolean] — State
- `enabled` [query, array] — Include enabled, disabled or both. Example: "True,False".
- `description__contains` [query, array] — Free-text filter by rule description (supports multiple)
- `collectionPath` [query, string] — Collection path
- `collectionPaths` [query, array] — List of collection paths to filter by.
- `collectionPath__contains` [query, array] — Free-text filter by rule collection path (supports multiple)
- `collectionTags` [query, array] — Exact match filter by collection tags (supports multiple)
- `collectionTags__contains` [query, array] — Free-text filter by rule collection tags (supports multiple)
- `excludedTags` [query, array] — Exact match filter by excluded tags (supports multiple)
- `excludedTags__contains` [query, array] — Free-text filter by rule exclued tags (supports multiple)
- `excludedLogs__contains` [query, array] — Free-text filter by rule exclued logs (supports multiple)
- `parser__contains` [query, array] — Free-text filter by rule parser (supports multiple)
- `createdBy__contains` [query, array] — Free-text filter by rule author (supports multiple)
- `updatedBy__contains` [query, array] — Free-text filter by rule last updater (supports multiple)
- `scopePath` [query, string] — Scope path
- `scopePaths` [query, array] — List of scope paths to filter by.
- `scopePath__contains` [query, array] — Free-text filter by scope path (supports multiple)
- `createdAt__between` [query, string] — Date range for creation time (format: <from_timestamp>-<to_timestamp>, inclusive). Example: "1514978890136-1514978650130".
- `updatedAt__between` [query, string] — Date range for last update time (format: <from_timestamp>-<to_timestamp>, inclusive). Example: "1514978890136-1514978650130".
- `excludedIds` [query, array] — List of IDs to exclude. Example: "225494730938493804,225494730938493915".
- `logPrefix__contains` [query, array] — Free-text filter by rule parser (supports multiple)
- `collectionPathOrChannel` [query, string] — Collection path or channel
- `collectionPathsOrChannel` [query, array] — List of collection paths to filter by.
- `collectionPathOrChannel__contains` [query, array] — Free-text filter by rule collection path or channel (supports multiple)
- `eventIds` [query, array] — Exact match filter by event Ids (supports multiple)
- `eventIds__contains` [query, array] — Free-text filter by rule eventIds (supports multiple)
- `welExcludedIds__contains` [query, array] — Free-text filter by rule exclued ids (supports multiple)
- `includeParents` [query, boolean] — Return rules from parent scope levels
- `includeChildren` [query, boolean] — Return filters from children scope levels

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/log-collection/rules/{agent_type}`
**Get Log Collection rules by agent type**
`operationId`: `_web_api_log-collection_rules_{agent_type}_get`

Required permissions: `Log Collection Rules.view`

Parameters:
- `agent_type` [path, string] **required** — Agent type
- `skip` [query, integer] — Skip first number of items (0-1000). To iterate over more than 1000 items,  use "cursor". Example: "150".
- `limit` [query, integer] — Limit number of returned items (1-1000). Example: "10".
- `cursor` [query, string] — Cursor position returned by the last request. Use to iterate over more than 1000 items. Example: "YWdlbnRfaWQ6NTgwMjkzODE=".
- `countOnly` [query, boolean] — If true, only total number of items will be returned, without any of the actual objects.
- `skipCount` [query, boolean] — If true, total number of items will not be calculated, which speeds up execution time.
- `sortBy` [query, string] (enum: id, createdAt, createdBy, updatedAt, updatedBy, scopeId, scopeLevel, name, agentType, configurationType, collectionType, state, description, enabled, parser, scopePath, collectionPath, logPrefix, excludedLogs, collectionTags, excludedTags, uuid, eventIds, collectionPathOrChannel, levels, providers, welExcludedIds) — The column to sort the results by. Example: "id".
- `sortOrder` [query, string] (enum: asc, desc) — Sort direction. Example: "asc".
- `accountIds` [query, array] — List of account IDs to filter by. Example: "225494730938493804,225494730938493915".
- `siteIds` [query, array] — List of site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `groupIds` [query, array] — List of group IDs to filter by. Example: "225494730938493804,225494730938493915".
- `tenant` [query, boolean] — Indicates a tenant scope request
- `ids` [query, array] — List of IDs to filter by. Example: "225494730938493804,225494730938493915".
- `scope` [query, string] (enum: group, site, account, tenant) — Scope. Example: "group".
- `scopes` [query, array] — List of scopes to filter by. Example: "group".
- `name` [query, string] — Name
- `names` [query, array] — List of names to filter by.
- `name__contains` [query, array] — Free-text filter by rule name (supports multiple)
- `agentType` [query, string] (enum: windows, linux, macos, k8s, k8sAndContainers) — Agent type. Example: "windows".
- `agentTypes` [query, array] — List of agent types to filter by. Example: "windows".
- `configurationType` [query, string] (enum: collectionPath, predicate) — Configuration type. Example: "collectionPath".
- `configurationTypes` [query, array] — List of configuration types to filter by. Example: "collectionPath".
- `collectionType` [query, string] (enum: applicationLog, unifiedLogging, windowsEventLog, flatFileLog) — Collection type. Example: "applicationLog".
- `collectionTypes` [query, array] — List of collection types to filter by. Example: "applicationLog".
- `state` [query, boolean] — State
- `enabled` [query, array] — Include enabled, disabled or both. Example: "True,False".
- `description__contains` [query, array] — Free-text filter by rule description (supports multiple)
- `collectionPath` [query, string] — Collection path
- `collectionPaths` [query, array] — List of collection paths to filter by.
- `collectionPath__contains` [query, array] — Free-text filter by rule collection path (supports multiple)
- `collectionTags` [query, array] — Exact match filter by collection tags (supports multiple)
- `collectionTags__contains` [query, array] — Free-text filter by rule collection tags (supports multiple)
- `excludedTags` [query, array] — Exact match filter by excluded tags (supports multiple)
- `excludedTags__contains` [query, array] — Free-text filter by rule exclued tags (supports multiple)
- `excludedLogs__contains` [query, array] — Free-text filter by rule exclued logs (supports multiple)
- `parser__contains` [query, array] — Free-text filter by rule parser (supports multiple)
- `createdBy__contains` [query, array] — Free-text filter by rule author (supports multiple)
- `updatedBy__contains` [query, array] — Free-text filter by rule last updater (supports multiple)
- `scopePath` [query, string] — Scope path
- `scopePaths` [query, array] — List of scope paths to filter by.
- `scopePath__contains` [query, array] — Free-text filter by scope path (supports multiple)
- `createdAt__between` [query, string] — Date range for creation time (format: <from_timestamp>-<to_timestamp>, inclusive). Example: "1514978890136-1514978650130".
- `updatedAt__between` [query, string] — Date range for last update time (format: <from_timestamp>-<to_timestamp>, inclusive). Example: "1514978890136-1514978650130".
- `excludedIds` [query, array] — List of IDs to exclude. Example: "225494730938493804,225494730938493915".
- `logPrefix__contains` [query, array] — Free-text filter by rule parser (supports multiple)
- `collectionPathOrChannel` [query, string] — Collection path or channel
- `collectionPathsOrChannel` [query, array] — List of collection paths to filter by.
- `collectionPathOrChannel__contains` [query, array] — Free-text filter by rule collection path or channel (supports multiple)
- `eventIds` [query, array] — Exact match filter by event Ids (supports multiple)
- `eventIds__contains` [query, array] — Free-text filter by rule eventIds (supports multiple)
- `welExcludedIds__contains` [query, array] — Free-text filter by rule exclued ids (supports multiple)
- `includeParents` [query, boolean] — Return rules from parent scope levels
- `includeChildren` [query, boolean] — Return filters from children scope levels

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `PUT /web/api/v2.1/log-collection/rules/{rule_id}`
**Update a log collection rule**
`operationId`: `_web_api_log-collection_rules_{rule_id}_put`

Required permissions: `Log Collection Rules.edit`

Parameters:
- `rule_id` [path, string] **required** — Rule id
- `body` [body, log_collection.schemas.post_schema_LogCollectionRulesPostSchema] — 

Responses: 400 Invalid user input received. See error details for further i, 409 Conflict, 200 Success, 401 Unauthorized access - please sign in and retry.
