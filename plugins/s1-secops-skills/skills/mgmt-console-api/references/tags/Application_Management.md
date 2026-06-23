# Application Management

16 endpoints.

## `GET /web/api/v2.1/application-management/inventory`
**Get Application Inventory**
`operationId`: `_web_api_application-management_inventory_get`

Get application inventory data grouped by application name and vendor.

Required permissions: `Applications Page.view`

Parameters:
- `siteIds` [query, array] — Single Site ID to filter by. Example: "225494730938493804".
- `sortOrder` [query, string] (enum: asc, desc) — Sort direction. Example: "asc".
- `accountIds` [query, array] — Single Account ID to filter by. Example: "225494730938493804".
- `cursor` [query, string] — Cursor position returned by the last request. Use to iterate over more than 1000 items. Example: "YWdlbnRfaWQ6NTgwMjkzODE=".
- `skip` [query, integer] — Skip first number of items (0-1000). To iterate over more than 1000 items,  use "cursor". Example: "150".
- `limit` [query, integer] — Limit number of returned items (1-1000). Example: "10".
- `sortBy` [query, string] (enum: applicationName, applicationVendor, applicationVersionsCount, endpointsCount) — The column to sort the results by. Example: "id".
- `endpointUuid__contains` [query, array] — Free-text filter by endpoint uuid (supports multiple values)
- `osVersions` [query, array] — Included OS versions
- `vendors` [query, array] — Included vendors. Example: "Microsoft,Apple".
- `skipCount` [query, boolean] — If true, total number of items will not be calculated, which speeds up execution time.
- `countOnly` [query, boolean] — If true, only total number of items will be returned, without any of the actual objects.
- `osVersion__contains` [query, array] — Free-text filter by os version (supports multiple values). Example: "Windows 7 ServicePack1".
- `endpointName__contains` [query, array] — Free-text filter by endpoint name (supports multiple values). Example: "Office,Test".
- `name__contains` [query, array] — Free-text filter by application name (supports multiple values). Example: "Office,Test".
- `vendor__contains` [query, array] — Free-text filter by vendor (supports multiple values). Example: "Microsoft,Apple".
- `osArchitectures` [query, array] — Included OS architectures
- `groupIds` [query, array] — Single Group ID to filter by. Example: "225494730938493804".
- `osTypes` [query, array] — Included OS types

Responses: 403 Insufficient permissions, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/application-management/inventory/applications`
**Get Endpoint Apps**
`operationId`: `_web_api_application-management_inventory_applications_get`

Get the installed applications for a specific endpoint. <BR>To get the Agent ID, run "agents".

Required permissions: `Applications Page.view`

Parameters:
- `ids` [query, array] **required** — Agent ID list. Example: "225494730938493804,225494730938493915".

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/application-management/inventory/endpoints`
**Get App Inventory Endpoints**
`operationId`: `_web_api_application-management_inventory_endpoints_get`

Get endpoint data for a specific application.

Required permissions: `Applications Page.view`

Parameters:
- `siteIds` [query, array] — Single Site ID to filter by. Example: "225494730938493804".
- `sortOrder` [query, string] (enum: asc, desc) — Sort direction. Example: "asc".
- `detectionDate__gte` [query, string] — Application detection date after or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `accountIds` [query, array] — Single Account ID to filter by. Example: "225494730938493804".
- `cursor` [query, string] — Cursor position returned by the last request. Use to iterate over more than 1000 items. Example: "YWdlbnRfaWQ6NTgwMjkzODE=".
- `skip` [query, integer] — Skip first number of items (0-1000). To iterate over more than 1000 items,  use "cursor". Example: "150".
- `limit` [query, integer] — Limit number of returned items (1-1000). Example: "10".
- `applicationName` [query, string] **required** — Name
- `sortBy` [query, string] (enum: endpointName, endpointType, osType, osVersion, accountName, siteName, groupName, version, fileSize, detectionDate, applicationInstallationDate, cpuCount, coreCount, osArch, applicationInstallationPath) — The column to sort the results by. Example: "id".
- `endpointUuid__contains` [query, array] — Free-text filter by endpoint uuid (supports multiple values)
- `osVersions` [query, array] — Included OS versions
- `detectionDate__lt` [query, string] — Application detection date before this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `applicationVendor` [query, string] **required** — Vendor
- `detectionDate__gt` [query, string] — Application detection date after this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `skipCount` [query, boolean] — If true, total number of items will not be calculated, which speeds up execution time.
- `detectionDate__between` [query, string] — Date range for application detection date(format: <from_timestamp>-<to_timestamp>, inclusive). Example: "1514978890136-1514978650130".
- `detectionDate__lte` [query, string] — Application detection date before or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `countOnly` [query, boolean] — If true, only total number of items will be returned, without any of the actual objects.
- `versions` [query, array] — Included application versions
- `endpointName__contains` [query, array] — Free-text filter by endpoint name (supports multiple values). Example: "Office,Test".
- `osArchitectures` [query, array] — Included OS architectures
- `groupIds` [query, array] — Single Group ID to filter by. Example: "225494730938493804".
- `osTypes` [query, array] — Included OS types

Responses: 403 Insufficient permissions, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/application-management/inventory/endpoints/export/csv`
**Inventory Endpoints Data Export**
`operationId`: `_web_api_application-management_inventory_endpoints_export_csv_get`

Export application inventory endpoints data to CSV.

Required permissions: `Applications Page.view`

Parameters:
- `siteIds` [query, array] — Single Site ID to filter by. Example: "225494730938493804".
- `detectionDate__gte` [query, string] — Application detection date after or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `accountIds` [query, array] — Single Account ID to filter by. Example: "225494730938493804".
- `csvDelimiter` [query, string] (enum: ,, ;) — "Optionally specify character to be used as CSV delimiter. Defaults to ",". Example: ",".
- `applicationName` [query, string] **required** — Name
- `endpointUuid__contains` [query, array] — Free-text filter by endpoint uuid (supports multiple values)
- `osVersions` [query, array] — Included OS versions
- `detectionDate__lt` [query, string] — Application detection date before this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `applicationVendor` [query, string] **required** — Vendor
- `detectionDate__gt` [query, string] — Application detection date after this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `detectionDate__between` [query, string] — Date range for application detection date(format: <from_timestamp>-<to_timestamp>, inclusive). Example: "1514978890136-1514978650130".
- `detectionDate__lte` [query, string] — Application detection date before or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `versions` [query, array] — Included application versions
- `endpointName__contains` [query, array] — Free-text filter by endpoint name (supports multiple values). Example: "Office,Test".
- `osArchitectures` [query, array] — Included OS architectures
- `groupIds` [query, array] — Single Group ID to filter by. Example: "225494730938493804".
- `osTypes` [query, array] — Included OS types

Responses: 403 Insufficient permissions, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/application-management/inventory/export/csv`
**Inventory Data Export**
`operationId`: `_web_api_application-management_inventory_export_csv_get`

Export application inventory data to CSV.

Required permissions: `Applications Page.view`

Parameters:
- `siteIds` [query, array] — Single Site ID to filter by. Example: "225494730938493804".
- `accountIds` [query, array] — Single Account ID to filter by. Example: "225494730938493804".
- `csvDelimiter` [query, string] (enum: ,, ;) — "Optionally specify character to be used as CSV delimiter. Defaults to ",". Example: ",".
- `endpointUuid__contains` [query, array] — Free-text filter by endpoint uuid (supports multiple values)
- `osVersions` [query, array] — Included OS versions
- `vendors` [query, array] — Included vendors. Example: "Microsoft,Apple".
- `osVersion__contains` [query, array] — Free-text filter by os version (supports multiple values). Example: "Windows 7 ServicePack1".
- `endpointName__contains` [query, array] — Free-text filter by endpoint name (supports multiple values). Example: "Office,Test".
- `name__contains` [query, array] — Free-text filter by application name (supports multiple values). Example: "Office,Test".
- `vendor__contains` [query, array] — Free-text filter by vendor (supports multiple values). Example: "Microsoft,Apple".
- `osArchitectures` [query, array] — Included OS architectures
- `groupIds` [query, array] — Single Group ID to filter by. Example: "225494730938493804".
- `osTypes` [query, array] — Included OS types

Responses: 403 Insufficient permissions, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/application-management/risks`
**Get CVE data**
`operationId`: `_web_api_application-management_risks_get`

Get the CVE vulnerability data for each CVE.

Required permissions: `Applications Page.viewRisks`

Parameters:
- `siteIds` [query, array] — Single Site ID to filter by. Example: "225494730938493804".
- `riskUpdatedDate__gt` [query, string] — Significant CVE updates after this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `sortOrder` [query, string] (enum: asc, desc) — Sort direction. Example: "asc".
- `detectionDate__gte` [query, string] — CVE detection date after or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `accountIds` [query, array] — Single Account ID to filter by. Example: "225494730938493804".
- `applicationNames` [query, array] — Included application names. Example: "Office 1.1,Test".
- `domain__contains` [query, array] — Free-text filter by domain (supports multiple values). Example: "mybusiness,workgroup".
- `exploitCodeMaturity` [query, array] — Included exploit code maturity values. Available for Singularity Vulnerability Management SKU. Example: "FUNCTIONAL,HIGH".
- `mitigationStatus` [query, array] — Filters by the application's mitigation status values.Available for Singularity Vulnerability Management SKU. Example: "Not mitigated,To be patched,On hold".
- `publishedDate__between` [query, string] — Date range for CVE publish date(format: <from_timestamp>-<to_timestamp>, inclusive). Example: "1514978890136-1514978650130".
- `cursor` [query, string] — Cursor position returned by the last request. Use to iterate over more than 1000 items. Example: "YWdlbnRfaWQ6NTgwMjkzODE=".
- `skip` [query, integer] — Skip first number of items (0-1000). To iterate over more than 1000 items,  use "cursor". Example: "150".
- `riskScore__between` [query, string] — Risk score (inclusive). Available for Singularity Vulnerability Management SKU. Example: "5-8.9".
- `remediationLevels` [query, array] — Included remediation level values. Available for Singularity Vulnerability Management SKU. Example: "OFFICIAL_FIX,TEMPORARY_FIX".
- `limit` [query, integer] — Limit number of returned items (1-1000). Example: "10".
- `applicationVendor__contains` [query, array] — Free-text filter by vendor (supports multiple values). Example: "Microsoft,Apple".
- `publishedDate__gte` [query, string] — CVE published date after or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `sortBy` [query, string] (enum: id, accountId, siteId, cveId, endpointName, application, applicationVendor, baseScore, severity, daysDetected, detectionDate, publishedDate, lastScanDate, lastScanResult, nvdBaseScore, riskScore, exploitCodeMaturity, remediationLevel, reportConfidence, mitigationStatus) — The column to sort the results by. Example: "id".
- `exploitedInTheWild` [query, array] — Included exploited in the wild values. Available for Singularity Vulnerability Management SKU. Example: "EXPLOITED_UNKNOWN,YES".
- `riskUpdatedDate__lt` [query, string] — Significant CVE updates before this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `severities` [query, array] — Included severities. Example: "CRITICAL,HIGH".
- `includeRemovals` [query, boolean] — Include also removed CVEs in the results
- `riskUpdatedDate__gte` [query, string] — Significant CVE updates after or at this timestamp. Recommended for fetching delta-changes. Example: "2018-02-27T04:49:26.257525Z".
- `osVersions` [query, array] — Included OS versions
- `analystVerdict` [query, array] — Include Default(not edited)/ False Positives / Added CVEs for Vulnerabilities. Example: "Default,False Positive,Added CVE".
- `domains` [query, array] — Included network domains. Example: "mybusiness,workgroup".
- `publishedDate__lt` [query, string] — CVE published date before this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `publishedDate__gt` [query, string] — CVE published date after this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `detectionDate__lt` [query, string] — CVE detection date before this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `detectionDate__gt` [query, string] — CVE detection date after this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `skipCount` [query, boolean] — If true, total number of items will not be calculated, which speeds up execution time.
- `detectionDate__lte` [query, string] — CVE detection date before or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `detectionDate__between` [query, string] — Date range for CVE detection date(format: <from_timestamp>-<to_timestamp>, inclusive). Example: "1514978890136-1514978650130".
- `publishedDate__lte` [query, string] — CVE published date before or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `reportConfidence` [query, array] — Included report confidence values. Available for Singularity Vulnerability Management SKU. Example: "REASONABLE,CONFIRMED".
- `riskUpdatedDate__between` [query, string] — Significant CVE updates within this date range(format: <from_timestamp>-<to_timestamp>, inclusive). Example: "1514978890136-1514978650130".
- `countOnly` [query, boolean] — If true, only total number of items will be returned, without any of the actual objects.
- `endpointName__contains` [query, array] — Free-text filter by endpoint name (supports multiple values). Example: "Office,Test".
- `riskUpdatedDate__lte` [query, string] — Significant CVE updates before or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `vendors` [query, array] — Included vendors. Example: "Microsoft,Apple".
- `application__contains` [query, array] — Free-text filter by application name and version (supports multiple values). Example: "Office 1.1,Test".
- `cveId__contains` [query, array] — Free-text filter by CVE id (supports multiple values). Example: "CVE-1234-5678".
- `endpointTypes` [query, array] — Included endpoint types
- `groupIds` [query, array] — Single Group ID to filter by. Example: "225494730938493804".
- `osTypes` [query, array] — Included OS types
- `lastScanResults` [query, array] — Included last scan results. Example: "Succeeded".
- `daysFromCveDetection` [query, integer] — Days from CVE detection, e.g. 12 days or more. Example: "12".

Responses: 403 Insufficient permissions, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/application-management/risks/aggregated-applications`
**Get Aggregated Applications With Risk**
`operationId`: `_web_api_application-management_risks_aggregated-applications_get`

Get data for all applications. Available with Ranger Insights license.

Required permissions: `Applications Page.viewRisks`

Parameters:
- `siteIds` [query, array] — Single Site ID to filter by. Example: "225494730938493804".
- `sortOrder` [query, string] (enum: asc, desc) — Sort direction. Example: "asc".
- `highestSeverities` [query, array] — Included highest severities. Example: "CRITICAL,HIGH".
- `detectionDate__gte` [query, string] — Application detection date after or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `applicationTypes` [query, array] — Application type. Available with Ranger Insights. Example: "A,p,p,l,i,c,a,t,i,o,n".
- `accountIds` [query, array] — Single Account ID to filter by. Example: "225494730938493804".
- `exploitCodeMaturity` [query, array] — Included exploit code maturity values. Available with Ranger Insights. Example: "Functional,High".
- `mostCommonStatuses` [query, array] — Included most common status values. Available with Ranger Insights.
- `cursor` [query, string] — Cursor position returned by the last request. Use to iterate over more than 1000 items. Example: "YWdlbnRfaWQ6NTgwMjkzODE=".
- `skip` [query, integer] — Skip first number of items (0-1000). To iterate over more than 1000 items,  use "cursor". Example: "150".
- `remediationLevels` [query, array] — Included remediation level values. Available with Ranger Insights. Example: "Official Fix,Temporary Fix".
- `limit` [query, integer] — Limit number of returned items (1-1000). Example: "10".
- `sortBy` [query, string] (enum: name, vendor, highestRiskScore, highestNvdBaseScore, highestSeverity, exploitedInTheWild, exploitCodeMaturity, remediationLevel, detectionDate, daysDetected, versionCount, cveCount, endpointCount, applicationType, mostCommonStatus) — The column to sort the results by. Example: "id".
- `exploitedInTheWild` [query, array] — Included exploited in the wild values. Available with Ranger Insights. Example: "Unknown,Yes".
- `endpointUuid__contains` [query, array] — Free-text filter by endpoint uuid (supports multiple values)
- `domains` [query, array] — Included domains.
- `detectionDate__lt` [query, string] — Application detection date before this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `vendors` [query, array] — Included vendors. Example: "Microsoft,Apple".
- `detectionDate__gt` [query, string] — Application detection date after this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `skipCount` [query, boolean] — If true, total number of items will not be calculated, which speeds up execution time.
- `detectionDate__between` [query, string] — Date range for application detection date(format: <from_timestamp>-<to_timestamp>, inclusive). Example: "1514978890136-1514978650130".
- `detectionDate__lte` [query, string] — Application detection date before or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `countOnly` [query, boolean] — If true, only total number of items will be returned, without any of the actual objects.
- `endpointName__contains` [query, array] — Free-text filter by endpoint name (supports multiple values). Example: "Office,Test".
- `cveId__contains` [query, array] — Free-text filter by CVE id (supports multiple values). Example: "CVE-1234-5678".
- `endpointTypes` [query, array] — Included endpoint types. Example: "desktop,laptop".
- `vendor__contains` [query, array] — Free-text filter by vendor (supports multiple values). Example: "Microsoft,Apple".
- `name__contains` [query, array] — Free-text filter by application name (supports multiple values). Example: "Office 1.1,Test".
- `groupIds` [query, array] — Single Group ID to filter by. Example: "225494730938493804".
- `osTypes` [query, array] — Included OS types. Example: "windows,linux".
- `daysFromDetection` [query, integer] — Days from application detection, e.g. 12 days or more. Example: "12".

Responses: 403 Insufficient permissions, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/application-management/risks/aggregated-applications/export/csv`
**Aggregated Application Risk Data Export**
`operationId`: `_web_api_application-management_risks_aggregated-applications_export_csv_get`

Export aggregated application data to CSV. Available with Ranger Insights license.

Required permissions: `Applications Page.viewRisks`

Parameters:
- `siteIds` [query, array] — Single Site ID to filter by. Example: "225494730938493804".
- `highestSeverities` [query, array] — Included highest severities. Example: "CRITICAL,HIGH".
- `detectionDate__gte` [query, string] — Application detection date after or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `applicationTypes` [query, array] — Application type. Available with Ranger Insights. Example: "A,p,p,l,i,c,a,t,i,o,n".
- `accountIds` [query, array] — Single Account ID to filter by. Example: "225494730938493804".
- `exploitCodeMaturity` [query, array] — Included exploit code maturity values. Available with Ranger Insights. Example: "Functional,High".
- `mostCommonStatuses` [query, array] — Included most common status values. Available with Ranger Insights.
- `remediationLevels` [query, array] — Included remediation level values. Available with Ranger Insights. Example: "Official Fix,Temporary Fix".
- `csvDelimiter` [query, string] (enum: ,, ;) — "Optionally specify character to be used as CSV delimiter. Defaults to ",". Example: ",".
- `exploitedInTheWild` [query, array] — Included exploited in the wild values. Available with Ranger Insights. Example: "Unknown,Yes".
- `endpointUuid__contains` [query, array] — Free-text filter by endpoint uuid (supports multiple values)
- `domains` [query, array] — Included domains.
- `detectionDate__lt` [query, string] — Application detection date before this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `vendors` [query, array] — Included vendors. Example: "Microsoft,Apple".
- `detectionDate__gt` [query, string] — Application detection date after this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `detectionDate__between` [query, string] — Date range for application detection date(format: <from_timestamp>-<to_timestamp>, inclusive). Example: "1514978890136-1514978650130".
- `detectionDate__lte` [query, string] — Application detection date before or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `endpointName__contains` [query, array] — Free-text filter by endpoint name (supports multiple values). Example: "Office,Test".
- `cveId__contains` [query, array] — Free-text filter by CVE id (supports multiple values). Example: "CVE-1234-5678".
- `endpointTypes` [query, array] — Included endpoint types. Example: "desktop,laptop".
- `vendor__contains` [query, array] — Free-text filter by vendor (supports multiple values). Example: "Microsoft,Apple".
- `name__contains` [query, array] — Free-text filter by application name (supports multiple values). Example: "Office 1.1,Test".
- `groupIds` [query, array] — Single Group ID to filter by. Example: "225494730938493804".
- `osTypes` [query, array] — Included OS types. Example: "windows,linux".
- `daysFromDetection` [query, integer] — Days from application detection, e.g. 12 days or more. Example: "12".

Responses: 403 Insufficient permissions, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/application-management/risks/applications`
**Get Applications With Risk**
`operationId`: `_web_api_application-management_risks_applications_get`

Get data for each version of all applications.

Required permissions: `Applications Page.viewRisks`

Parameters:
- `siteIds` [query, array] — Single Site ID to filter by. Example: "225494730938493804".
- `sortOrder` [query, string] (enum: asc, desc) — Sort direction. Example: "asc".
- `highestSeverities` [query, array] — Included highest severities. Example: "CRITICAL,HIGH".
- `detectionDate__gte` [query, string] — Application detection date after or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `applicationTypes` [query, array] — Application type. Available with Ranger Insights. Example: "A,p,p,l,i,c,a,t,i,o,n".
- `accountIds` [query, array] — Single Account ID to filter by. Example: "225494730938493804".
- `exploitCodeMaturity` [query, array] — Included exploit code maturity values. Available with Ranger Insights. Example: "Functional,High".
- `mostCommonStatuses` [query, array] — Included most common status values. Available with Ranger Insights.
- `cursor` [query, string] — Cursor position returned by the last request. Use to iterate over more than 1000 items. Example: "YWdlbnRfaWQ6NTgwMjkzODE=".
- `skip` [query, integer] — Skip first number of items (0-1000). To iterate over more than 1000 items,  use "cursor". Example: "150".
- `remediationLevels` [query, array] — Included remediation level values. Available with Ranger Insights. Example: "Official Fix,Temporary Fix".
- `limit` [query, integer] — Limit number of returned items (1-1000). Example: "10".
- `sortBy` [query, string] (enum: name, vendor, highestNvdBaseScore, highestSeverity, cveCount, endpointCount, detectionDate, daysDetected, highestRiskScore, exploitedInTheWild, exploitCodeMaturity, remediationLevel, mostCommonStatus, applicationType, endpointsWithoutTicket) — The column to sort the results by. Example: "id".
- `exploitedInTheWild` [query, array] — Included exploited in the wild values. Available with Ranger Insights. Example: "Unknown,Yes".
- `endpointUuid__contains` [query, array] — Free-text filter by endpoint uuid (supports multiple values)
- `domains` [query, array] — Included domains.
- `detectionDate__lt` [query, string] — Application detection date before this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `vendors` [query, array] — Included vendors. Example: "Microsoft,Apple".
- `detectionDate__gt` [query, string] — Application detection date after this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `skipCount` [query, boolean] — If true, total number of items will not be calculated, which speeds up execution time.
- `detectionDate__between` [query, string] — Date range for application detection date(format: <from_timestamp>-<to_timestamp>, inclusive). Example: "1514978890136-1514978650130".
- `detectionDate__lte` [query, string] — Application detection date before or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `countOnly` [query, boolean] — If true, only total number of items will be returned, without any of the actual objects.
- `endpointName__contains` [query, array] — Free-text filter by endpoint name (supports multiple values). Example: "Office,Test".
- `application__contains` [query, array] — Free-text filter by application name and version (supports multiple values). Example: "Office 1.1,Test".
- `cveId__contains` [query, array] — Free-text filter by CVE id (supports multiple values). Example: "CVE-1234-5678".
- `endpointTypes` [query, array] — Included endpoint types. Example: "desktop,laptop".
- `vendor__contains` [query, array] — Free-text filter by vendor (supports multiple values). Example: "Microsoft,Apple".
- `groupIds` [query, array] — Single Group ID to filter by. Example: "225494730938493804".
- `osTypes` [query, array] — Included OS types. Example: "windows,linux".
- `daysFromDetection` [query, integer] — Days from application detection, e.g. 12 days or more. Example: "12".

Responses: 403 Insufficient permissions, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/application-management/risks/applications/export/csv`
**Application Risk Data Export**
`operationId`: `_web_api_application-management_risks_applications_export_csv_get`

Export application data to CSV.

Required permissions: `Applications Page.viewRisks`

Parameters:
- `siteIds` [query, array] — Single Site ID to filter by. Example: "225494730938493804".
- `highestSeverities` [query, array] — Included highest severities. Example: "CRITICAL,HIGH".
- `detectionDate__gte` [query, string] — Application detection date after or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `applicationTypes` [query, array] — Application type. Available with Ranger Insights. Example: "A,p,p,l,i,c,a,t,i,o,n".
- `accountIds` [query, array] — Single Account ID to filter by. Example: "225494730938493804".
- `exploitCodeMaturity` [query, array] — Included exploit code maturity values. Available with Ranger Insights. Example: "Functional,High".
- `mostCommonStatuses` [query, array] — Included most common status values. Available with Ranger Insights.
- `remediationLevels` [query, array] — Included remediation level values. Available with Ranger Insights. Example: "Official Fix,Temporary Fix".
- `csvDelimiter` [query, string] (enum: ,, ;) — "Optionally specify character to be used as CSV delimiter. Defaults to ",". Example: ",".
- `exploitedInTheWild` [query, array] — Included exploited in the wild values. Available with Ranger Insights. Example: "Unknown,Yes".
- `endpointUuid__contains` [query, array] — Free-text filter by endpoint uuid (supports multiple values)
- `domains` [query, array] — Included domains.
- `detectionDate__lt` [query, string] — Application detection date before this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `vendors` [query, array] — Included vendors. Example: "Microsoft,Apple".
- `detectionDate__gt` [query, string] — Application detection date after this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `detectionDate__between` [query, string] — Date range for application detection date(format: <from_timestamp>-<to_timestamp>, inclusive). Example: "1514978890136-1514978650130".
- `detectionDate__lte` [query, string] — Application detection date before or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `endpointName__contains` [query, array] — Free-text filter by endpoint name (supports multiple values). Example: "Office,Test".
- `application__contains` [query, array] — Free-text filter by application name and version (supports multiple values). Example: "Office 1.1,Test".
- `cveId__contains` [query, array] — Free-text filter by CVE id (supports multiple values). Example: "CVE-1234-5678".
- `endpointTypes` [query, array] — Included endpoint types. Example: "desktop,laptop".
- `vendor__contains` [query, array] — Free-text filter by vendor (supports multiple values). Example: "Microsoft,Apple".
- `groupIds` [query, array] — Single Group ID to filter by. Example: "225494730938493804".
- `osTypes` [query, array] — Included OS types. Example: "windows,linux".
- `daysFromDetection` [query, integer] — Days from application detection, e.g. 12 days or more. Example: "12".

Responses: 403 Insufficient permissions, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/application-management/risks/cves`
**Get Application CVEs**
`operationId`: `_web_api_application-management_risks_cves_get`

Get CVE data for a specific application. Use applicationIds query parameter to include a single application id (required). For Ranger Insights license users, either use the applicationIds query parameter that can include multiple application IDs, or the applicationName and applicationVendors query parameters.

Required permissions: `Applications Page.viewRisks`

Parameters:
- `siteIds` [query, array] — Single Site ID to filter by. Example: "225494730938493804".
- `sortOrder` [query, string] (enum: asc, desc) — Sort direction. Example: "asc".
- `applicationIds` [query, array] — Included application versions by id. Example: "225494730938493804,225494730938493915".
- `accountIds` [query, array] — Single Account ID to filter by. Example: "225494730938493804".
- `applicationVendor` [query, string] — Application vendor
- `publishedDate__between` [query, string] — Date range for CVE publish date(format: <from_timestamp>-<to_timestamp>, inclusive). Example: "1514978890136-1514978650130".
- `cursor` [query, string] — Cursor position returned by the last request. Use to iterate over more than 1000 items. Example: "YWdlbnRfaWQ6NTgwMjkzODE=".
- `skip` [query, integer] — Skip first number of items (0-1000). To iterate over more than 1000 items,  use "cursor". Example: "150".
- `applicationName` [query, string] — Application name
- `remediationLevels` [query, array] — Included remediation level values. Available with Ranger Insights. Example: "OFFICIAL_FIX,TEMPORARY_FIX".
- `limit` [query, integer] — Limit number of returned items (1-1000). Example: "10".
- `publishedDate__gte` [query, string] — CVE published date after or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `sortBy` [query, string] (enum: cveId, severity, nvdBaseScore, publishedDate, riskScore, exploitedInTheWild, exploitCodeMaturity, remediationLevel, reportConfidence) — The column to sort the results by. Example: "id".
- `exploitedInTheWild` [query, array] — Included exploited in the wild values. Available with Ranger Insights. Example: "EXPLOITED_UNKNOWN,YES".
- `severities` [query, array] — Included severities. Example: "CRITICAL,HIGH".
- `publishedDate__lt` [query, string] — CVE published date before this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `publishedDate__gt` [query, string] — CVE published date after this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `skipCount` [query, boolean] — If true, total number of items will not be calculated, which speeds up execution time.
- `publishedDate__lte` [query, string] — CVE published date before or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `reportConfidence` [query, array] — Included report confidence values. Available with Ranger Insights. Example: "REASONABLE,CONFIRMED".
- `countOnly` [query, boolean] — If true, only total number of items will be returned, without any of the actual objects.
- `applicationVersions` [query, array] — Included application versions
- `cveId__contains` [query, array] — Free-text filter by CVE id (supports multiple values). Example: "CVE-1234-5678".
- `groupIds` [query, array] — Single Group ID to filter by. Example: "225494730938493804".
- `analystVerdict` [query, array] — Include Default(not edited)/ False Positives / Added CVEs for Vulnerabilities. Example: "Default,False Positive,Added CVE".
- `exploitCodeMaturity` [query, array] — Included exploit code maturity values. Available with Ranger Insights. Example: "FUNCTIONAL,HIGH".

Responses: 403 Insufficient permissions, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/application-management/risks/cves/export/csv`
**Application CVE Data Export**
`operationId`: `_web_api_application-management_risks_cves_export_csv_get`

Export CVE data to CSV. Use applicationIds query parameter to include a single application id (required). For Ranger Insights license users, either use the applicationIds query parameter that can include multiple application IDs, or the applicationName and applicationVendors query parameters.

Required permissions: `Applications Page.viewRisks`

Parameters:
- `siteIds` [query, array] — Single Site ID to filter by. Example: "225494730938493804".
- `applicationIds` [query, array] — Included application versions by id. Example: "225494730938493804,225494730938493915".
- `accountIds` [query, array] — Single Account ID to filter by. Example: "225494730938493804".
- `applicationVendor` [query, string] — Application vendor
- `publishedDate__between` [query, string] — Date range for CVE publish date(format: <from_timestamp>-<to_timestamp>, inclusive). Example: "1514978890136-1514978650130".
- `applicationName` [query, string] — Application name
- `remediationLevels` [query, array] — Included remediation level values. Available with Ranger Insights. Example: "OFFICIAL_FIX,TEMPORARY_FIX".
- `csvDelimiter` [query, string] (enum: ,, ;) — "Optionally specify character to be used as CSV delimiter. Defaults to ",". Example: ",".
- `publishedDate__gte` [query, string] — CVE published date after or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `exploitedInTheWild` [query, array] — Included exploited in the wild values. Available with Ranger Insights. Example: "EXPLOITED_UNKNOWN,YES".
- `severities` [query, array] — Included severities. Example: "CRITICAL,HIGH".
- `publishedDate__lt` [query, string] — CVE published date before this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `publishedDate__gt` [query, string] — CVE published date after this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `publishedDate__lte` [query, string] — CVE published date before or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `reportConfidence` [query, array] — Included report confidence values. Available with Ranger Insights. Example: "REASONABLE,CONFIRMED".
- `applicationVersions` [query, array] — Included application versions
- `cveId__contains` [query, array] — Free-text filter by CVE id (supports multiple values). Example: "CVE-1234-5678".
- `groupIds` [query, array] — Single Group ID to filter by. Example: "225494730938493804".
- `analystVerdict` [query, array] — Include Default(not edited)/ False Positives / Added CVEs for Vulnerabilities. Example: "Default,False Positive,Added CVE".
- `exploitCodeMaturity` [query, array] — Included exploit code maturity values. Available with Ranger Insights. Example: "FUNCTIONAL,HIGH".

Responses: 403 Insufficient permissions, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/application-management/risks/endpoints`
**Get Endpoints For Vulnerable App**
`operationId`: `_web_api_application-management_risks_endpoints_get`

Get a list of all endpoints installed with a specific application that contains vulnerabilities. Use applicationIds query parameter to include a single application id (required). For Ranger Insights license users, either use the applicationIds query parameter that can include multiple application IDs, or the applicationName and applicationVendors query parameters.

Required permissions: `Applications Page.viewRisks`

Parameters:
- `siteIds` [query, array] — Single Site ID to filter by. Example: "225494730938493804".
- `statusMessage__contains` [query, array] — Free-text filter by status message (supports multiple values). Available with Ranger Insights. Example: "assigned to john,top priority".
- `sortOrder` [query, string] (enum: asc, desc) — Sort direction. Example: "asc".
- `applicationIds` [query, array] — Included application versions by id. Example: "225494730938493804,225494730938493915".
- `detectionDate__gte` [query, string] — Application detection date after or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `accountIds` [query, array] — Single Account ID to filter by. Example: "225494730938493804".
- `applicationVendor` [query, string] — Application vendor
- `domain__contains` [query, array] — Free-text filter by domain (supports multiple values). Example: "mybusiness,workgroup".
- `daysToMitigation__between` [query, string] — Date range for days left to mitigation. Available with Ranger Insights when using ticket integration. Example: "1-30".
- `statuses` [query, array] — Included statuses. Available with Ranger Insights.
- `cursor` [query, string] — Cursor position returned by the last request. Use to iterate over more than 1000 items. Example: "YWdlbnRfaWQ6NTgwMjkzODE=".
- `skip` [query, integer] — Skip first number of items (0-1000). To iterate over more than 1000 items,  use "cursor". Example: "150".
- `applicationName` [query, string] — Application name
- `limit` [query, integer] — Limit number of returned items (1-1000). Example: "10".
- `sortBy` [query, string] (enum: name, osType, osVersion, endpointType, account, site, group, domain, detectionDate, daysDetected, applicationVersion, lastScanDate, lastScanResult, status, daysToMitigation) — The column to sort the results by. Example: "id".
- `endpointUuid__contains` [query, array] — Free-text filter by endpoint uuid (supports multiple values)
- `lastScanDate__lt` [query, string] — Last scan date before this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `osVersions` [query, array] — Included OS versions
- `domains` [query, array] — Included endpoint domains
- `lastScanDate__gt` [query, string] — Last scan date after this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `detectionDate__lt` [query, string] — Application detection date before this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `endpointId__contains` [query, array] — Free-text filter by endpoint id (supports multiple values)
- `detectionDate__gt` [query, string] — Application detection date after this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `skipCount` [query, boolean] — If true, total number of items will not be calculated, which speeds up execution time.
- `detectionDate__lte` [query, string] — Application detection date before or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `detectionDate__between` [query, string] — Date range for application detection date(format: <from_timestamp>-<to_timestamp>, inclusive). Example: "1514978890136-1514978650130".
- `countOnly` [query, boolean] — If true, only total number of items will be returned, without any of the actual objects.
- `applicationVersions` [query, array] — Included application versions
- `ticketId__contains` [query, array] — Free-text filter by ticket id. Available with Ranger Insights when using ticket integration. Example: "ABC-123,ABCD-100".
- `endpointName__contains` [query, array] — Free-text filter by endpoint name (supports multiple values). Example: "Office,Test".
- `lastScanDate__lte` [query, string] — Last scan date before or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `lastScanDate__between` [query, string] — Date range for last scan date(format: <from_timestamp>-<to_timestamp>, inclusive). Example: "1514978890136-1514978650130".
- `endpointTypes` [query, array] — Included endpoint types
- `groupIds` [query, array] — Single Group ID to filter by. Example: "225494730938493804".
- `osTypes` [query, array] — Included OS types
- `lastScanResults` [query, array] — Included last scan results. Example: "Succeeded".
- `daysFromDetection` [query, integer] — Days from application detection, e.g. 12 days or more. Example: "12".
- `lastScanDate__gte` [query, string] — Last scan date after or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".

Responses: 403 Insufficient permissions, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/application-management/risks/endpoints/export/csv`
**Risk Endpoint Data Export**
`operationId`: `_web_api_application-management_risks_endpoints_export_csv_get`

Export endpoint data to CSV. Use applicationIds query parameter to include a single application id (required). For Ranger Insights license users, either use the applicationIds query parameter that can include multiple application IDs, or the applicationName and applicationVendors query parameters.

Required permissions: `Applications Page.viewRisks`

Parameters:
- `siteIds` [query, array] — Single Site ID to filter by. Example: "225494730938493804".
- `statusMessage__contains` [query, array] — Free-text filter by status message (supports multiple values). Available with Ranger Insights. Example: "assigned to john,top priority".
- `applicationIds` [query, array] — Included application versions by id. Example: "225494730938493804,225494730938493915".
- `detectionDate__gte` [query, string] — Application detection date after or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `accountIds` [query, array] — Single Account ID to filter by. Example: "225494730938493804".
- `applicationVendor` [query, string] — Application vendor
- `domain__contains` [query, array] — Free-text filter by domain (supports multiple values). Example: "mybusiness,workgroup".
- `daysToMitigation__between` [query, string] — Date range for days left to mitigation. Available with Ranger Insights when using ticket integration. Example: "1-30".
- `statuses` [query, array] — Included statuses. Available with Ranger Insights.
- `applicationName` [query, string] — Application name
- `csvDelimiter` [query, string] (enum: ,, ;) — "Optionally specify character to be used as CSV delimiter. Defaults to ",". Example: ",".
- `endpointUuid__contains` [query, array] — Free-text filter by endpoint uuid (supports multiple values)
- `lastScanDate__lt` [query, string] — Last scan date before this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `osVersions` [query, array] — Included OS versions
- `domains` [query, array] — Included endpoint domains
- `lastScanDate__gt` [query, string] — Last scan date after this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `detectionDate__lt` [query, string] — Application detection date before this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `endpointId__contains` [query, array] — Free-text filter by endpoint id (supports multiple values)
- `detectionDate__gt` [query, string] — Application detection date after this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `detectionDate__between` [query, string] — Date range for application detection date(format: <from_timestamp>-<to_timestamp>, inclusive). Example: "1514978890136-1514978650130".
- `detectionDate__lte` [query, string] — Application detection date before or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `applicationVersions` [query, array] — Included application versions
- `ticketId__contains` [query, array] — Free-text filter by ticket id. Available with Ranger Insights when using ticket integration. Example: "ABC-123,ABCD-100".
- `endpointName__contains` [query, array] — Free-text filter by endpoint name (supports multiple values). Example: "Office,Test".
- `lastScanDate__lte` [query, string] — Last scan date before or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `lastScanDate__between` [query, string] — Date range for last scan date(format: <from_timestamp>-<to_timestamp>, inclusive). Example: "1514978890136-1514978650130".
- `endpointTypes` [query, array] — Included endpoint types
- `groupIds` [query, array] — Single Group ID to filter by. Example: "225494730938493804".
- `osTypes` [query, array] — Included OS types
- `lastScanResults` [query, array] — Included last scan results. Example: "Succeeded".
- `daysFromDetection` [query, integer] — Days from application detection, e.g. 12 days or more. Example: "12".
- `lastScanDate__gte` [query, string] — Last scan date after or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".

Responses: 403 Insufficient permissions, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/application-management/risks/export/csv`
**Risks Data Export**
`operationId`: `_web_api_application-management_risks_export_csv_get`

Export risks data to CSV.

Required permissions: `Applications Page.viewRisks`

Parameters:
- `siteIds` [query, array] — Single Site ID to filter by. Example: "225494730938493804".
- `riskUpdatedDate__gt` [query, string] — Significant CVE updates after this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `detectionDate__gte` [query, string] — CVE detection date after or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `accountIds` [query, array] — Single Account ID to filter by. Example: "225494730938493804".
- `applicationNames` [query, array] — Included application names. Example: "Office 1.1,Test".
- `domain__contains` [query, array] — Free-text filter by domain (supports multiple values). Example: "mybusiness,workgroup".
- `exploitCodeMaturity` [query, array] — Included exploit code maturity values. Available for Singularity Vulnerability Management SKU. Example: "FUNCTIONAL,HIGH".
- `mitigationStatus` [query, array] — Filters by the application's mitigation status values.Available for Singularity Vulnerability Management SKU. Example: "Not mitigated,To be patched,On hold".
- `publishedDate__between` [query, string] — Date range for CVE publish date(format: <from_timestamp>-<to_timestamp>, inclusive). Example: "1514978890136-1514978650130".
- `riskScore__between` [query, string] — Risk score (inclusive). Available for Singularity Vulnerability Management SKU. Example: "5-8.9".
- `remediationLevels` [query, array] — Included remediation level values. Available for Singularity Vulnerability Management SKU. Example: "OFFICIAL_FIX,TEMPORARY_FIX".
- `applicationVendor__contains` [query, array] — Free-text filter by vendor (supports multiple values). Example: "Microsoft,Apple".
- `csvDelimiter` [query, string] (enum: ,, ;) — "Optionally specify character to be used as CSV delimiter. Defaults to ",". Example: ",".
- `publishedDate__gte` [query, string] — CVE published date after or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `includeRemovals` [query, boolean] — Include also removed CVEs in the results
- `exploitedInTheWild` [query, array] — Included exploited in the wild values. Available for Singularity Vulnerability Management SKU. Example: "EXPLOITED_UNKNOWN,YES".
- `riskUpdatedDate__lt` [query, string] — Significant CVE updates before this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `severities` [query, array] — Included severities. Example: "CRITICAL,HIGH".
- `riskUpdatedDate__gte` [query, string] — Significant CVE updates after or at this timestamp. Recommended for fetching delta-changes. Example: "2018-02-27T04:49:26.257525Z".
- `osVersions` [query, array] — Included OS versions
- `analystVerdict` [query, array] — Include Default(not edited)/ False Positives / Added CVEs for Vulnerabilities. Example: "Default,False Positive,Added CVE".
- `domains` [query, array] — Included network domains. Example: "mybusiness,workgroup".
- `publishedDate__lt` [query, string] — CVE published date before this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `publishedDate__gt` [query, string] — CVE published date after this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `detectionDate__lt` [query, string] — CVE detection date before this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `detectionDate__gt` [query, string] — CVE detection date after this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `detectionDate__between` [query, string] — Date range for CVE detection date(format: <from_timestamp>-<to_timestamp>, inclusive). Example: "1514978890136-1514978650130".
- `detectionDate__lte` [query, string] — CVE detection date before or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `publishedDate__lte` [query, string] — CVE published date before or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `reportConfidence` [query, array] — Included report confidence values. Available for Singularity Vulnerability Management SKU. Example: "REASONABLE,CONFIRMED".
- `riskUpdatedDate__between` [query, string] — Significant CVE updates within this date range(format: <from_timestamp>-<to_timestamp>, inclusive). Example: "1514978890136-1514978650130".
- `endpointName__contains` [query, array] — Free-text filter by endpoint name (supports multiple values). Example: "Office,Test".
- `riskUpdatedDate__lte` [query, string] — Significant CVE updates before or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `vendors` [query, array] — Included vendors. Example: "Microsoft,Apple".
- `application__contains` [query, array] — Free-text filter by application name and version (supports multiple values). Example: "Office 1.1,Test".
- `cveId__contains` [query, array] — Free-text filter by CVE id (supports multiple values). Example: "CVE-1234-5678".
- `endpointTypes` [query, array] — Included endpoint types
- `groupIds` [query, array] — Single Group ID to filter by. Example: "225494730938493804".
- `osTypes` [query, array] — Included OS types
- `lastScanResults` [query, array] — Included last scan results. Example: "Succeeded".
- `daysFromCveDetection` [query, integer] — Days from CVE detection, e.g. 12 days or more. Example: "12".

Responses: 403 Insufficient permissions, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/application-management/scan`
**Initiate scan**
`operationId`: `_web_api_application-management_scan_post`

Initiate application vulnerability scan.

Required permissions: `Applications Page.scanVulnerabilities`

Parameters:
- `body` [body, v2_1.application_management.application_management_schemas_ScanPostSchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.
