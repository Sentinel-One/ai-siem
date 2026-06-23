# Application Risk

1 endpoints.

## `GET /web/api/v2.1/export/installed-applications`
**Export Applications**
`operationId`: `_web_api_export_installed-applications_get`

Export the list of applications installed on endpoints with Application Risk-enabled Agents and their properties, including the CVEs for each application that requires a patch. The CSV file is stored on the Management. Application Risk requires Complete SKU. <br>This feature is in EA. To join the EA program, contact your SentinelOne Sales Rep.

Required permissions: `Applications Page.view`

Parameters:
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
