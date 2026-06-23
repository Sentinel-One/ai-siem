# Locations

4 endpoints.

## `DELETE /web/api/v2.1/locations`
**Delete Locations**
`operationId`: `_web_api_locations_delete`

Delete location definitions of a given location. To get location IDs, run "locations".

Required permissions: `Locations.delete`

Parameters:
- `body` [body, locations.schemas_DeleteLocationsSchema] — 

Responses: 403 Insufficient permissions, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/locations`
**Get Locations**
`operationId`: `_web_api_locations_get`

Get the locations of Agents in a given scope that match the filter.  Agent locations are based on endpoint network parameters (IP, DNS, NIC, Registry Key, or SentinelOne connection set for all true, at least one true, or none true and applied to a Site, Account, or Global). Agents detect their location settings and apply Firewall Control rules that have Location Aware parameters that match the Agent location. Agents can be in multiple locations at the same time. If an Agent that supports Locations does not detect that it is in a defined location, it uses the Firewall rules assigned to the Fallback location. <br>Use this command with a filter for "hasFirewallRules" to find Locations that do not have matching Firewall Control rules. The response to this request includes the ID of the location, which you can use in other commands.<br>Firewall Control and Location Awareness require Control SKU.

Required permissions: `Locations.view`

Parameters:
- `skip` [query, integer] — Skip first number of items (0-1000). To iterate over more than 1000 items,  use "cursor". Example: "150".
- `limit` [query, integer] — Limit number of returned items (1-1000). Example: "10".
- `cursor` [query, string] — Cursor position returned by the last request. Use to iterate over more than 1000 items. Example: "YWdlbnRfaWQ6NTgwMjkzODE=".
- `countOnly` [query, boolean] — If true, only total number of items will be returned, without any of the actual objects.
- `skipCount` [query, boolean] — If true, total number of items will not be calculated, which speeds up execution time.
- `sortBy` [query, string] (enum: id, scope) — The column to sort the results by. Example: "id".
- `sortOrder` [query, string] (enum: asc, desc) — Sort direction. Example: "asc".
- `siteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "225494730938493804,225494730938493915".
- `groupIds` [query, array] — List of Group IDs to filter by. Example: "225494730938493804,225494730938493915".
- `ids` [query, array] — Filter results by location IDs. Example: "225494730938493804,225494730938493915".
- `scopes` [query, array] — Filter results by scope. Example: "site".
- `hasFirewallRules` [query, boolean] — Filter by locations with/without firewall rules associated to them
- `name__contains` [query, array] — Free-text filter by location name (supports multiple values). Example: "office".
- `description__contains` [query, array] — Free-text filter by description (supports multiple values). Example: "out of office".
- `creator__contains` [query, array] — Free-text filter by creator of the location (supports multiple values). Example: "max,mike".
- `scopeName__contains` [query, array] — Free-text filter by scope name (supports multiple values). Example: "my_group,my_site".
- `hostname__contains` [query, array] — Free-text filter by hostname (supports multiple values). Example: "sentinelone.com,localhost".
- `ipAddress__contains` [query, array] — Free-text filter by IP address (supports multiple values). Example: "29.213.22.17".
- `registryKey__contains` [query, array] — Free-text filter by registry key (supports multiple values). Example: "system\software,sentinel".

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/locations`
**Create Location**
`operationId`: `_web_api_locations_post`

Create a location that defines parameters of Agents in a scope filter. Parameters include: <br>* ipAddresses - The Agent compares the endpoint active IPv4 or IPv6 addresses to the IP addresses, ranges, and CIDRs defined for the location. <br>* dnsServers - The Agent compares the configured DNS servers of the endpoint to the DNS servers defined for the location.<br>* dnsLookup - The Agent resolves the FQDN of the endpoint to IPv4 or IPv6 addresses and compares them to the addresses configured in the location setting.<br>* networkInterfaces - The Agent determines if the endpoint is connected to the network over a wireless connection. If one connected interface is wireless, the endpoint is considered wireless.<br>* serverConnectivity - The Agent reports if it is connected to its Management.<br>* registryKeys - The Agent compares the endpoint registry keys in HKEY_LOCAL_MACHINE\SOFTWARE with the registry key of the location definition. <br>When you set a location parameter, also set the operator to ALL, NONE, or at least 1. <br>The serverConnectivity parameter takes "enabled" (true or false) and "value" (connected or disconnected). <br>The networkInterfaces parameter takes "enabled" (t …

Required permissions: `Locations.create`

Parameters:
- `body` [body, locations.schemas_NewLocationSchema] — 

Responses: 403 Insufficient permissions, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `PUT /web/api/v2.1/locations/{location_id}`
**Update Location**
`operationId`: `_web_api_locations_{location_id}_put`

Change the parameter values of a location definition. See Create Location.

Required permissions: `Locations.edit`

Parameters:
- `location_id` [path, string] **required** — Location ID. Example: "225494730938493804".
- `body` [body, locations.schemas_UpdateLocationSchema] — 

Responses: 404 Location not found, 403 Insufficient permissions, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.
