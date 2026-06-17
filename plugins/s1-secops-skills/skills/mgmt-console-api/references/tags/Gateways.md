# Gateways

3 endpoints.

## `GET /web/api/v2.1/ranger/gateways`
**Get Gateways**
`operationId`: `_web_api_ranger_gateways_get`

Get the gateways in your deployment that match the filter from a Network Discovery scan. 
Network Discovery requires a Network Discovery license.

Required permissions: `Ranger.view`

Parameters:
- `skip` [query, integer] — Skip first number of items (0-1000). To iterate over more than 1000 items,  use "cursor". Example: "150".
- `limit` [query, integer] — Limit number of returned items (1-1000). Example: "10".
- `cursor` [query, string] — Cursor position returned by the last request. Use to iterate over more than 1000 items. Example: "YWdlbnRfaWQ6NTgwMjkzODE=".
- `countOnly` [query, boolean] — If true, only total number of items will be returned, without any of the actual objects.
- `skipCount` [query, boolean] — If true, total number of items will not be calculated, which speeds up execution time.
- `sortBy` [query, string] (enum: id, ip, macAddress, externalIp, allowScan, networkName, totalAgents, agentPercentage, createdAt, numberOfAgents, numberOfRangers, expiryDate, connectedRangers) — The column to sort the results by. Example: "id".
- `sortOrder` [query, string] (enum: asc, desc) — Sort direction. Example: "asc".
- `siteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "225494730938493804,225494730938493915".
- `query` [query, string] — Free text query
- `ip` [query, string] — Search ip using a CIDR expression exact IP
- `macAddress` [query, string] — The gateway mac address
- `externalIp` [query, string] — Search external ip using a CIDR expression or exact IP
- `allowScan` [query, string] — Do we allow scanning in this network
- `ids` [query, array] — List of gateway ids. Example: "225494730938493804,225494730938493915".
- `scanOnlyLocalSubnets` [query, boolean] — Allow remote tasks form this network
- `new` [query, boolean] — True if this is network was first seen some days ago, 3 by default
- `archived` [query, boolean] — Archived network
- `numberOfAgents__lt` [query, integer] — Agent count (less than)
- `numberOfAgents__lte` [query, integer] — Agent count (less than or equal)
- `numberOfAgents__gt` [query, integer] — Agent count (more than)
- `numberOfAgents__gte` [query, integer] — Agent count (more than or equal)
- `numberOfAgents__between` [query, string] — The number of non decommissioned agents in this network. Example: "2-8".
- `numberOfRangers__lt` [query, integer] — Network Discovery count (less than)
- `numberOfRangers__lte` [query, integer] — Network Discovery count (less than or equal)
- `numberOfRangers__gt` [query, integer] — Network Discovery count (more than)
- `numberOfRangers__gte` [query, integer] — Network Discovery count (more than or equal)
- `numberOfRangers__between` [query, string] — The number of non decommissioned agents in this network. Example: "2-8".
- `agentPercentage__lt` [query, number] — Agent percentage (less than)
- `agentPercentage__lte` [query, number] — Agent percentage (less than or equal)
- `agentPercentage__gt` [query, number] — Agent percentage (more than)
- `agentPercentage__gte` [query, number] — Agent percentage (more than or equal)
- `agentPercentage__between` [query, string] — Percentage of agents of the account in this network calculated as numberOfAgents/totalAgents * 100. Example: "70-80".
- `totalAgents__lt` [query, integer] — Total agents (less than)
- `totalAgents__lte` [query, integer] — Total agents (less than or equal)
- `totalAgents__gt` [query, integer] — Total agents (more than)
- `totalAgents__gte` [query, integer] — Total agents (more than or equal)
- `totalAgents__between` [query, string] — The total of non decommissioned agents in the account. Example: "2-8".
- `connectedRangers__lt` [query, integer] — Total agents (less than)
- `connectedRangers__lte` [query, integer] — Total agents (less than or equal)
- `connectedRangers__gt` [query, integer] — Total agents (more than)
- `connectedRangers__gte` [query, integer] — Total agents (more than or equal)
- `connectedRangers__between` [query, string] — The total of non decommissioned agents in the account. Example: "2-8".
- `createdAt__lt` [query, string] — Gateway created before this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__lte` [query, string] — Gateway created before or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__gt` [query, string] — Gateway created after this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__gte` [query, string] — Gateway created after or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__between` [query, string] — Date range for creation time (format: <from_timestamp>-<to_timestamp>, inclusive). Example: "1514978890136-1514978650130".
- `updatedAt__lt` [query, string] — Gateway updated before this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `updatedAt__lte` [query, string] — Gateway updated before or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `updatedAt__gt` [query, string] — Gateway updated after this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `updatedAt__gte` [query, string] — Gateway updated after or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `updatedAt__between` [query, string] — Date range for update time (format: <from_timestamp>-<to_timestamp>, inclusive). Example: "1514978890136-1514978650130".
- `smbScan` [query, boolean] — SMB scan enabled
- `icmpScan` [query, boolean] — ICMP scan enabled
- `mdnsScan` [query, boolean] — MDNS scan enabled
- `snmpScan` [query, boolean] — SNMP scan enabled
- `rdnsScan` [query, boolean] — RDNS scan enabled
- `manufacturer` [query, string] — The gateway manufacturer obtained from the mac address
- `networkName__contains` [query, array] — Free-text filter by network name (supports multiple values). Example: "Network1".
- `externalIp__contains` [query, array] — Free-text filter by visible IP (supports multiple values). Example: "192.168.0.1/24,10.1".
- `ip__contains` [query, array] — Free-text filter by IP Address (supports multiple values). Example: "192.168.0.1/24,10.1".
- `manufacturer__contains` [query, array] — Free-text filter by manufacturer (supports multiple values). Example: "Company".
- `macAddress__contains` [query, array] — Free-text filter by mac address (supports multiple values). Example: "aa:ee:b1".
- `tcpPorts__contains` [query, array] — Free-text filter by tcp port (supports multiple values). Example: "80,24".
- `udpPorts__contains` [query, array] — Free-text filter by udp port (supports multiple values). Example: "137,2002".

Responses: 403 Insufficient permissions, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/ranger/gateways/update`
**Update Gateways**
`operationId`: `_web_api_ranger_gateways_update_post`

Change the status of filtered gateways discovered by Network Discovery. You can set the archived status, whether the network behind the gateway may be scanned by Network Discovery, and whether Network Discovery will scan only local networks.

Required permissions: `Ranger.manageDiscoveredNetworks`

Parameters:
- `body` [body, ranger.gateway_schema_PostUpdateGatewayData] — 

Responses: 403 Insufficient permissions, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `PUT /web/api/v2.1/ranger/gateways/{gateway_id}`
**Update Gateway**
`operationId`: `_web_api_ranger_gateways_{gateway_id}_put`

Change the Network Discovery scan configuration for a gateway that Network Discovery discovered

Required permissions: `Ranger.manageDiscoveredNetworks`

Parameters:
- `gateway_id` [path, string] **required** — Gateway ID. Example: "225494730938493804".
- `body` [body, ranger.gateway_schema_PutGatewayData] — 

Responses: 403 Insufficient permissions, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.
