# Application Risk (Deprecated)

2 endpoints.

## `GET /web/api/v2.1/installed-applications`
**[DEPRECATED] Get Applications**
`operationId`: `_web_api_installed-applications_get`

Get the applications, and their data (such as risk level), installed on endpoints with Application Risk-enabled Agents that match the filter. SentinelOne Application Risk lets you monitor applications installed on endpoints. Applications not updated with the latest patches are vulnerable to exploits. With SentinelOne Application Risk you can see all applications to be patched, on all endpoints or on a specific endpoint. The Agent takes a snapshot of the endpoint application data and checks for vulnerabilities in the SentinelOne Cloud. When the Agent detects a change to the application data, it sends a diff to the Management.<br>Application Risk requires Complete SKU. This feature is in EA. To join the EA program, contact your SentinelOne Sales Rep.

Required permissions: `Applications Page.view`

Parameters:
- `skip` [query, integer] — Skip first number of items (0-1000). To iterate over more than 1000 items,  use "cursor". Example: "150".
- `limit` [query, integer] — Limit number of returned items (1-1000). Example: "10".
- `cursor` [query, string] — Cursor position returned by the last request. Use to iterate over more than 1000 items. Example: "YWdlbnRfaWQ6NTgwMjkzODE=".
- `countOnly` [query, boolean] — If true, only total number of items will be returned, without any of the actual objects.
- `skipCount` [query, boolean] — If true, total number of items will not be calculated, which speeds up execution time.
- `sortBy` [query, string] (enum: id, installedAt, type, name, publisher, version, size, agentComputerName, riskLevel, createdAt, updatedAt) — The column to sort the results by. Example: "id".
- `sortOrder` [query, string] (enum: asc, desc) — Sort direction. Example: "asc".
- `siteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "225494730938493804,225494730938493915".
- `groupIds` [query, array] — List of Group IDs to filter by. Example: "225494730938493804,225494730938493915".
- `ids` [query, array] — Filter by application IDs. Example: "225494730938493804,225494730938493915".
- `osTypes` [query, array] — Filter by OS types. Example: "macos".
- `osTypesNin` [query, array] — Filter not by OS types. Example: "macos".
- `agentMachineTypes` [query, array] — Filter by endpoint machine types. Example: "unknown".
- `agentMachineTypesNin` [query, array] — Filter not by endpoint machine types. Example: "unknown".
- `installedAt__between` [query, string] — Filter by installation date range
- `types` [query, array] — Filter by application types. Example: "app".
- `typesNin` [query, array] — Filter not by application types. Example: "app".
- `riskLevels` [query, array] — Filter by risk. Example: "none".
- `riskLevelsNin` [query, array] — Filter not by risk. Example: "none".
- `size__between` [query, string] — Filter by application size range (bytes). Example: "1024-104856".
- `agentIsDecommissioned` [query, array] — Include active agents, decommissioned or both. Example: "True,False".
- `name__contains` [query, array] — Free-text filter by application name (supports multiple values). Example: "calc".
- `version__contains` [query, array] — Free-text filter by application version (supports multiple values). Example: "1.22.333,build".
- `publisher__contains` [query, array] — Free-text filter by application publisher (supports multiple values). Example: "Sentinel".
- `agentComputerName__contains` [query, array] — Free-text filter by computer name (supports multiple values). Example: "john-office,WIN".
- `agentUuid__contains` [query, array] — Free-text filter by agent UUID (supports multiple values). Example: "e92-01928,b055".
- `agentOsVersion__contains` [query, array] — Free-text filter by OS full name and version (supports multiple values). Example: "Service Pack 1".

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/installed-applications/cves`
**[DEPRECATED] Get CVEs**
`operationId`: `_web_api_installed-applications_cves_get`

Get known CVEs for applications that are installed on endpoints with Application Risk-enabled Agents. <br>Application Risk requires Complete SKU. This feature is in EA. To join the EA program, contact your SentinelOne Sales Rep.

Required permissions: `Applications Page.view`

Parameters:
- `skip` [query, integer] — Skip first number of items (0-1000). To iterate over more than 1000 items,  use "cursor". Example: "150".
- `limit` [query, integer] — Limit number of returned items (1-1000). Example: "10".
- `cursor` [query, string] — Cursor position returned by the last request. Use to iterate over more than 1000 items. Example: "YWdlbnRfaWQ6NTgwMjkzODE=".
- `countOnly` [query, boolean] — If true, only total number of items will be returned, without any of the actual objects.
- `skipCount` [query, boolean] — If true, total number of items will not be calculated, which speeds up execution time.
- `sortBy` [query, string] (enum: id, publishedAt, agentId, applicationId) — The column to sort the results by. Example: "id".
- `sortOrder` [query, string] (enum: asc, desc) — Sort direction. Example: "asc".
- `siteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "225494730938493804,225494730938493915".
- `groupIds` [query, array] — List of Group IDs to filter by. Example: "225494730938493804,225494730938493915".
- `ids` [query, array] — Filter by internal CVE IDs. Example: "225494730938493804,225494730938493915".
- `cveIds` [query, array] — Filter by global CVE ids. Example: "CVE-2018-3182,CVE-2018-1087".
- `applicationIds` [query, array] — Filter by application IDs. Example: "225494730938493804,225494730938493915".
- `createdAt__lt` [query, string] — Created at lesser than. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__gt` [query, string] — Created at greater than. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__lte` [query, string] — Created at lesser or equal than. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__gte` [query, string] — Created at greater or equal than. Example: "2018-02-27T04:49:26.257525Z".
- `updatedAt__lt` [query, string] — Updated at lesser than. Example: "2018-02-27T04:49:26.257525Z".
- `updatedAt__gt` [query, string] — Updated at greater than. Example: "2018-02-27T04:49:26.257525Z".
- `updatedAt__lte` [query, string] — Updated at lesser or equal than. Example: "2018-02-27T04:49:26.257525Z".
- `updatedAt__gte` [query, string] — Updated at greater or equal than. Example: "2018-02-27T04:49:26.257525Z".

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.
