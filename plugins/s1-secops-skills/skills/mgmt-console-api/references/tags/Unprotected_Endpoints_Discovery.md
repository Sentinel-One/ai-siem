# Unprotected Endpoints Discovery

4 endpoints.

## `GET /web/api/v2.1/rogues/report/csv`
**Export Unprotected Endpoints Discovery Data**
`operationId`: `_web_api_rogues_report_csv_get`

Export Unprotected Endpoints Discovery data to CSV. You can set filters to get only relevant data. The response sends the CSV data as text.

Required permissions: `Rogues.view`

Parameters:
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "225494730938493804,225494730938493915".
- `siteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `groupIds` [query, array] — List of Group IDs to filter by. Example: "225494730938493804,225494730938493915".
- `tenant` [query, boolean] — Indicates a tenant scope request
- `osType` [query, string] — OS type
- `osTypes` [query, array] — Included OS types
- `osName` [query, string] — Os name
- `osVersion` [query, string] — Os version
- `localIp` [query, string] — Search using local IP
- `externalIp` [query, string] — Search using external IP
- `ids` [query, array] — List of device ids. Example: "225494730938493804,225494730938493915".
- `deviceType` [query, string] — Device type. Example: "Server/Workstation/...".
- `deviceTypes` [query, array] — Device types
- `macAddress` [query, string] — A mac address to search for
- `firstSeen__lt` [query, string] — Devices first seen before this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `firstSeen__lte` [query, string] — Devices first seen before or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `firstSeen__gt` [query, string] — Devices first seen after this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `firstSeen__gte` [query, string] — Devices first seen after or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `firstSeen__between` [query, string] — Date range refor first seen(format: <from_timestamp>-<to_timestamp>, inclusive). Example: "1514978890136-1514978650130".
- `lastSeen__lt` [query, string] — Devices last seen before this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `lastSeen__lte` [query, string] — Devices last seen before or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `lastSeen__gt` [query, string] — Devices last seen after this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `lastSeen__gte` [query, string] — Devices last seen after or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `lastSeen__between` [query, string] — Date range for last seen(format: <from_timestamp>-<to_timestamp>, inclusive). Example: "1514978890136-1514978650130".
- `manufacturer` [query, string] — Manufacturer of the device or network interface
- `hostnames` [query, array] — Hostnames
- `externalIp__contains` [query, array] — Free-text filter by visible IP (supports multiple values). Example: "192.168.0.1/24,10.1".
- `localIp__contains` [query, array] — Free-text filter by IP Address (supports multiple values). Example: "192.168.0.1/24,10.1".
- `osVersion__contains` [query, array] — Free-text filter by OS full name and version (supports multiple values). Example: "Service Pack 1".
- `manufacturer__contains` [query, array] — Free-text filter by manufacturer (supports multiple values). Example: "Company".
- `macAddress__contains` [query, array] — Free-text filter by mac address (supports multiple values). Example: "aa:ee:b1".
- `hostnames__contains` [query, array] — Free-text filter by hostanem (supports multiple values). Example: "s1_host,SomeHost".
- `query` [query, string] — Query

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/rogues/settings`
**Get Unprotected Endpoints Discovery Settings**
`operationId`: `_web_api_rogues_settings_get`

Unprotected Endpoints Discovery gives full visibility of all unsecured devices connected to your network. Unprotected Endpoints Discovery scans your corporate environment to identify and manage connected devices, even those not protected by or supported by SentinelOne. Unprotected Endpoints Discovery identifies devices as:<BR> * UnSecured - End-user computer or laptop, or server, without a SentinelOne Agent.<BR> When you install Windows Agents with Unprotected Endpoints Discovery, the Agents can become scanners. Selected scanners from networks that you enable for scanning find connected devices with passive and active scan techniques. The scanners send the collected data to Unprotected Endpoints Discovery page on the Management. Unprotected Endpoints Discovery then runs fingerprinting to identify and classify unique devices and to update the Device Inventory Table in the Management Console. With port scanning, it is important that you understand the legal and ethical considerations and that you document an Unprotected Endpoints Discovery plan and implementation. See Legal Considerations and Proper Implementation in the Console Help.<BR> * minAgentsInNetworkToScan - To help you dete …

Required permissions: `Rogues.view`

Parameters:
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "225494730938493804,225494730938493915".
- `siteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".

Responses: 403 Insufficient permissions, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `PUT /web/api/v2.1/rogues/settings`
**Update Unprotected Endpoints Discovery Settings**
`operationId`: `_web_api_rogues_settings_put`

Change the Unprotected Endpoints Discovery Settings. Best Practice: Get the current settings before you change them. See: Get Unprotected Endpoints Discovery Settings.

Required permissions: `Rogues.edit`

Parameters:
- `body` [body, rogue_schemas_PutRoguesSchema] — 

Responses: 403 Insufficient permissions, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/rogues/table-view`
**Get Unprotected Endpoints Discovery Table**
`operationId`: `_web_api_rogues_table-view_get`

Get the data for each row in the Unprotected Endpoints Discovery Device Inventory Table. <BR>Best practice: Set filters. Each row is a set of parameters that quickly fills the pagination limits.

Required permissions: `Rogues.view`

Parameters:
- `skip` [query, integer] — Skip first number of items (0-1000). To iterate over more than 1000 items,  use "cursor". Example: "150".
- `limit` [query, integer] — Limit number of returned items (1-1000). Example: "10".
- `cursor` [query, string] — Cursor position returned by the last request. Use to iterate over more than 1000 items. Example: "YWdlbnRfaWQ6NTgwMjkzODE=".
- `countOnly` [query, boolean] — If true, only total number of items will be returned, without any of the actual objects.
- `skipCount` [query, boolean] — If true, total number of items will not be calculated, which speeds up execution time.
- `sortBy` [query, string] (enum: osType, osName, id, deviceType, osVersion, manufacturer, firstSeen, lastSeen, macAddress, localIp, externalIp) — The column to sort the results by. Example: "id".
- `sortOrder` [query, string] (enum: asc, desc) — Sort direction. Example: "asc".
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "225494730938493804,225494730938493915".
- `siteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `groupIds` [query, array] — List of Group IDs to filter by. Example: "225494730938493804,225494730938493915".
- `tenant` [query, boolean] — Indicates a tenant scope request
- `osType` [query, string] — OS type
- `osTypes` [query, array] — Included OS types
- `osName` [query, string] — Os name
- `osVersion` [query, string] — Os version
- `localIp` [query, string] — Search using local IP
- `externalIp` [query, string] — Search using external IP
- `ids` [query, array] — List of device ids. Example: "225494730938493804,225494730938493915".
- `deviceType` [query, string] — Device type. Example: "Server/Workstation/...".
- `deviceTypes` [query, array] — Device types
- `macAddress` [query, string] — A mac address to search for
- `firstSeen__lt` [query, string] — Devices first seen before this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `firstSeen__lte` [query, string] — Devices first seen before or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `firstSeen__gt` [query, string] — Devices first seen after this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `firstSeen__gte` [query, string] — Devices first seen after or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `firstSeen__between` [query, string] — Date range refor first seen(format: <from_timestamp>-<to_timestamp>, inclusive). Example: "1514978890136-1514978650130".
- `lastSeen__lt` [query, string] — Devices last seen before this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `lastSeen__lte` [query, string] — Devices last seen before or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `lastSeen__gt` [query, string] — Devices last seen after this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `lastSeen__gte` [query, string] — Devices last seen after or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `lastSeen__between` [query, string] — Date range for last seen(format: <from_timestamp>-<to_timestamp>, inclusive). Example: "1514978890136-1514978650130".
- `manufacturer` [query, string] — Manufacturer of the device or network interface
- `hostnames` [query, array] — Hostnames
- `externalIp__contains` [query, array] — Free-text filter by visible IP (supports multiple values). Example: "192.168.0.1/24,10.1".
- `localIp__contains` [query, array] — Free-text filter by IP Address (supports multiple values). Example: "192.168.0.1/24,10.1".
- `osVersion__contains` [query, array] — Free-text filter by OS full name and version (supports multiple values). Example: "Service Pack 1".
- `manufacturer__contains` [query, array] — Free-text filter by manufacturer (supports multiple values). Example: "Company".
- `macAddress__contains` [query, array] — Free-text filter by mac address (supports multiple values). Example: "aa:ee:b1".
- `hostnames__contains` [query, array] — Free-text filter by hostanem (supports multiple values). Example: "s1_host,SomeHost".
- `query` [query, string] — Query

Responses: 403 Insufficient permissions, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.
