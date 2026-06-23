# Network Discovery

9 endpoints.

## `POST /web/api/v2.1/ranger/device-review`
**Change Device Review in Bulk**
`operationId`: `_web_api_ranger_device-review_post`

Change the review state of more than one device.

Required permissions: `Ranger.applyDeviceReview`

Parameters:
- `body` [body, schemas_DeviceReviewSchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `PUT /web/api/v2.1/ranger/device-review/{inventory_id}`
**Change Device Review**
`operationId`: `_web_api_ranger_device-review_{inventory_id}_put`

Change the review state of one device.

Required permissions: `Ranger.applyDeviceReview`

Parameters:
- `inventory_id` [path, string] **required** — Inventory ID. Example: "225494730938493804".
- `body` [body, schemas_DeviceReviewSchemaPut] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/ranger/report/csv`
**Export Network Discovery Data**
`operationId`: `_web_api_ranger_report_csv_get`

Export Network Discovery data to csv. You can set filters to get only relevant data. The response sends the csv data as text.

Required permissions: `Ranger.view`

Parameters:
- `accountIds` [query, array] — Single Account ID to filter by. Example: "225494730938493804".
- `siteIds` [query, array] — Single Site ID to filter by. Example: "225494730938493804".
- `osType` [query, string] — OS type
- `osTypes` [query, array] — Included OS types
- `period` [query, string] (enum: latest, last12h, last24h, last3d, last7d) — Period. Example: "latest".
- `osName` [query, string] — Os name
- `osVersion` [query, string] — Os version
- `localIp` [query, string] — Search using local IP
- `externalIp` [query, string] — Search using external IP
- `networkName` [query, string] — Search using network name
- `ids` [query, array] — List of device ids. Example: "225494730938493804,225494730938493915".
- `deviceType` [query, string] — Device type. Example: "Server/Workstation/...".
- `deviceTypes` [query, array] — Device types
- `macAddress` [query, string] — A mac address to search for
- `gatewayMacAddress` [query, string] — A gateway mac address to search for
- `domains` [query, array] — Included network domains. Example: "mybusiness,workgroup".
- `siteNames` [query, array] — Included site names. Example: "Office,Test".
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
- `agentIds` [query, array] — List of agent ids. Example: "225494730938493804,225494730938493915".
- `managedState` [query, string] — Is the device managed
- `managedStates` [query, array] — Is the device managed
- `manufacturer` [query, string] — Manufacturer of the device or network interface
- `discoveryMethods` [query, array] — Discovery methods
- `knownFingerprintingData` [query, array] — Known fingerprinting data. Example: "Manufacturer".
- `hostnames` [query, array] — Hostnames
- `deviceReviews` [query, array] — The device review state
- `externalIp__contains` [query, array] — Free-text filter by visible IP (supports multiple values). Example: "192.168.0.1/24,10.1".
- `localIp__contains` [query, array] — Free-text filter by IP Address (supports multiple values). Example: "192.168.0.1/24,10.1".
- `subnetAddress__contains` [query, array] — Free-text filter by Subnet Address (supports multiple values). Example: "192.168.0.1/24,10.1".
- `osVersion__contains` [query, array] — Free-text filter by OS full name and version (supports multiple values). Example: "Service Pack 1".
- `manufacturer__contains` [query, array] — Free-text filter by manufacturer (supports multiple values). Example: "Company".
- `macAddress__contains` [query, array] — Free-text filter by mac address (supports multiple values). Example: "aa:ee:b1".
- `gatewayMacAddress__contains` [query, array] — Free-text filter by gateway mac address (supports multiple values). Example: "aa:ee:b1".
- `tcpPorts__contains` [query, array] — Free-text filter by tcp port (supports multiple values). Example: "80,24".
- `udpPorts__contains` [query, array] — Free-text filter by udp port (supports multiple values). Example: "137,2002".
- `hostnames__contains` [query, array] — Free-text filter by hostname (supports multiple values). Example: "s1_host,SomeHost".
- `networkName__contains` [query, array] — Free-text filter by network name (supports multiple values). Example: "Office".
- `deviceFunction__contains` [query, array] — Free-text filter by device function (supports multiple values). Example: "security,mobile".
- `tagName__contains` [query, array] — Free-text filter by tag name (supports multiple values). Example: "iot".
- `query` [query, string] — Query

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/ranger/settings`
**Get Network Discovery Settings**
`operationId`: `_web_api_ranger_settings_get`

Network Discovery gives full visibility of all devices connected to your network. Network Discovery scans your corporate environment to identify and manage connected devices, even those not protected by or supported by SentinelOne. Network Discovery identifies devices as:<br>* Secured - End-user computer or laptop, or server, with a SentinelOne Agent.<br>* Unsecured - Endpoint of supported hardware and OS, without an Agent.<br>* Unsupported - Hardware or software that are not compatible with the SentinelOne Agent.<br>* Unknown - Network Discovery cannot determine if the device is Unsecured or Unsupported.<br>When you install Windows Agents with Network Discovery, the Agents can become scanners. Selected scanners from networks that you enable for scanning find connected devices with passive and active scan techniques. The scanners send the collected data to Network Discovery on the Management. Network Discovery then runs fingerprinting to identify and classify unique devices and to update the Device Inventory Table in the Management Console. With port scanning, it is important that you understand the legal and ethical considerations and that you document a Network Discovery plan and …

Required permissions: `Ranger.view`

Parameters:
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "225494730938493804,225494730938493915".
- `siteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".

Responses: 403 Insufficient permissions, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `PUT /web/api/v2.1/ranger/settings`
**Update Network Discovery Settings**
`operationId`: `_web_api_ranger_settings_put`

Change the Network Discovery Settings. Best Practice: Get the current settings before you change them. See: Get Network Discovery Settings.

Required permissions: `Ranger.manageNetworkDiscoverySettings`

Parameters:
- `body` [body, schemas_PutRangerSchema] — 

Responses: 403 Insufficient permissions, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/ranger/table-view`
**Get Network Discovery Table**
`operationId`: `_web_api_ranger_table-view_get`

Get the data for each row in the Network Discovery Device Inventory Table. Best practice: Set filters. Each row is a set of parameters that quickly fills the pagination limits.

Required permissions: `Ranger.view`

Parameters:
- `skip` [query, integer] — Skip first number of items (0-1000). To iterate over more than 1000 items,  use "cursor". Example: "150".
- `limit` [query, integer] — Limit number of returned items (1-1000). Example: "10".
- `cursor` [query, string] — Cursor position returned by the last request. Use to iterate over more than 1000 items. Example: "YWdlbnRfaWQ6NTgwMjkzODE=".
- `countOnly` [query, boolean] — If true, only total number of items will be returned, without any of the actual objects.
- `skipCount` [query, boolean] — If true, total number of items will not be calculated, which speeds up execution time.
- `sortBy` [query, string] (enum: osType, osName, id, deviceType, osVersion, managedState, manufacturer, firstSeen, lastSeen, subnetAddress, gatewayMacAddress, macAddress, localIp, externalIp, archived, networkName, deviceReview, domain, hasUserLabel) — The column to sort the results by. Example: "id".
- `sortOrder` [query, string] (enum: asc, desc) — Sort direction. Example: "asc".
- `accountIds` [query, array] — Single Account ID to filter by. Example: "225494730938493804".
- `siteIds` [query, array] — Single Site ID to filter by. Example: "225494730938493804".
- `osType` [query, string] — OS type
- `osTypes` [query, array] — Included OS types
- `period` [query, string] (enum: latest, last12h, last24h, last3d, last7d) — Period. Example: "latest".
- `osName` [query, string] — Os name
- `osVersion` [query, string] — Os version
- `localIp` [query, string] — Search using local IP
- `externalIp` [query, string] — Search using external IP
- `networkName` [query, string] — Search using network name
- `ids` [query, array] — List of device ids. Example: "225494730938493804,225494730938493915".
- `deviceType` [query, string] — Device type. Example: "Server/Workstation/...".
- `deviceTypes` [query, array] — Device types
- `macAddress` [query, string] — A mac address to search for
- `gatewayMacAddress` [query, string] — A gateway mac address to search for
- `domains` [query, array] — Included network domains. Example: "mybusiness,workgroup".
- `siteNames` [query, array] — Included site names. Example: "Office,Test".
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
- `agentIds` [query, array] — List of agent ids. Example: "225494730938493804,225494730938493915".
- `managedState` [query, string] — Is the device managed
- `managedStates` [query, array] — Is the device managed
- `manufacturer` [query, string] — Manufacturer of the device or network interface
- `discoveryMethods` [query, array] — Discovery methods
- `knownFingerprintingData` [query, array] — Known fingerprinting data. Example: "Manufacturer".
- `hostnames` [query, array] — Hostnames
- `deviceReviews` [query, array] — The device review state
- `externalIp__contains` [query, array] — Free-text filter by visible IP (supports multiple values). Example: "192.168.0.1/24,10.1".
- `localIp__contains` [query, array] — Free-text filter by IP Address (supports multiple values). Example: "192.168.0.1/24,10.1".
- `subnetAddress__contains` [query, array] — Free-text filter by Subnet Address (supports multiple values). Example: "192.168.0.1/24,10.1".
- `osVersion__contains` [query, array] — Free-text filter by OS full name and version (supports multiple values). Example: "Service Pack 1".
- `manufacturer__contains` [query, array] — Free-text filter by manufacturer (supports multiple values). Example: "Company".
- `macAddress__contains` [query, array] — Free-text filter by mac address (supports multiple values). Example: "aa:ee:b1".
- `gatewayMacAddress__contains` [query, array] — Free-text filter by gateway mac address (supports multiple values). Example: "aa:ee:b1".
- `tcpPorts__contains` [query, array] — Free-text filter by tcp port (supports multiple values). Example: "80,24".
- `udpPorts__contains` [query, array] — Free-text filter by udp port (supports multiple values). Example: "137,2002".
- `hostnames__contains` [query, array] — Free-text filter by hostname (supports multiple values). Example: "s1_host,SomeHost".
- `networkName__contains` [query, array] — Free-text filter by network name (supports multiple values). Example: "Office".
- `deviceFunction__contains` [query, array] — Free-text filter by device function (supports multiple values). Example: "security,mobile".
- `tagName__contains` [query, array] — Free-text filter by tag name (supports multiple values). Example: "iot".
- `query` [query, string] — Query

Responses: 403 Insufficient permissions, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/ranger/tags`
**Change Device Tags**
`operationId`: `_web_api_ranger_tags_post`

Change the device tags.

Required permissions: `Ranger.manageDeviceTags`

Parameters:
- `body` [body, schemas_DeviceTagsSchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/ranger/{inventory_id}/json`
**JSON Raw Data**
`operationId`: `_web_api_ranger_{inventory_id}_json_get`

Get a json string with the Network Discovery data for one device, by ID in the Device Inventory Data.

Required permissions: `Ranger.view`

Parameters:
- `inventory_id` [path, string] **required** — Inventory ID. Example: "225494730938493804".

Responses: 200 Success, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/ranger/{inventory_id}/json/export`
**Export JSON Raw Data**
`operationId`: `_web_api_ranger_{inventory_id}_json_export_get`

Export the raw data for one device, by its ID in the Device Inventory Data. To get the ID, run ranger/table-view (see Get Network Discovery Table). Use this command to get data for Support.

Required permissions: `Ranger.view`

Parameters:
- `inventory_id` [path, string] **required** — Inventory ID. Example: "225494730938493804".

Responses: 404 Not found, 200 Success, 401 Unauthorized access - please sign in and retry.
