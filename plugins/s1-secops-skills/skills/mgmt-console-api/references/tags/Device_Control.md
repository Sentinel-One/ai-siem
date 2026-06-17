# Device Control

12 endpoints.

## `DELETE /web/api/v2.1/device-control`
**Delete Rules**
`operationId`: `_web_api_device-control_delete`

Delete Device Control rules that match the filter.

Required permissions: `Device Control.delete`

Parameters:
- `body` [body, device_control.schemas_RuleDeleteSchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/device-control`
**Get Device Rules**
`operationId`: `_web_api_device-control_get`

Get the Device Control rules of a specified Account, Site, Group or Global (tenant) that match the filter.

Required permissions: `Device Control.view`

Parameters:
- `skip` [query, integer] — Skip first number of items (0-1000). To iterate over more than 1000 items,  use "cursor". Example: "150".
- `limit` [query, integer] — Limit number of returned items (1-1000). Example: "10".
- `cursor` [query, string] — Cursor position returned by the last request. Use to iterate over more than 1000 items. Example: "YWdlbnRfaWQ6NTgwMjkzODE=".
- `countOnly` [query, boolean] — If true, only total number of items will be returned, without any of the actual objects.
- `skipCount` [query, boolean] — If true, total number of items will not be calculated, which speeds up execution time.
- `sortBy` [query, string] (enum: id, interface, deviceClass, ruleName, action, status, order, version) — The column to sort the results by. Example: "id".
- `sortOrder` [query, string] (enum: asc, desc) — Sort direction. Example: "asc".
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "225494730938493804,225494730938493915".
- `siteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `groupIds` [query, array] — List of Group IDs to filter by. Example: "225494730938493804,225494730938493915".
- `tenant` [query, boolean] — Indicates a tenant scope request
- `query` [query, string] — A free-text search term, will match applicable attributes.
- `scopes` [query, array] — Return only device rules in this scope. Example: "site".
- `interfaces` [query, array] — Return device rules with the filtered interface. Example: "USB".
- `deviceClasses` [query, array] — Return device rules with the filtered device class. Example: "02h".
- `serviceClasses` [query, array] — Return device rules with the filtered service class. Example: "02".
- `ruleName` [query, string] — Return device rules with the filtered rule name.
- `vendorIds` [query, array] — Return device rules with the filtered vendor id.
- `productIds` [query, array] — Return device rules with the filtered product id. Example: "02".
- `uids` [query, array] — Return device rules with the filtered uId.
- `actions` [query, array] — Return device rules with the filtered action. Example: "Allow".
- `statuses` [query, array] — Return device rules with the filtered status. Example: "Enabled".
- `createdAt__lt` [query, string] — Return device rules created before this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__gt` [query, string] — Return device rules created after this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__lte` [query, string] — Return device rules created before or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__gte` [query, string] — Return device rules created after or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__between` [query, string] — Return device rules created within this range (inclusive). Example: "1514978764288-1514978999999".
- `ids` [query, array] — List of ids to filter by. Example: "225494730938493804,225494730938493915".
- `versions` [query, array] — Return device rules with the filtered versions.
- `minorClasses` [query, array] — Return device rules with the filtered minor classes.
- `accessPermissions` [query, array] — Access permission in. Example: "Read-Only".
- `bluetoothAddresses` [query, array] — Return device rules with the filtered bluetooth addresses.
- `gattServices` [query, array] — Return device rules with the filtered GATT services.
- `manufacturerNames` [query, array] — Return device rules with the filtered manufacturer names.
- `deviceNames` [query, array] — Return device rules with the filtered device names.
- `deviceInformationServiceInfoKeys` [query, array] — Return device rules with the filtered device information service info keys.
- `deviceIds` [query, array] — Return device rules with the filtered device id. Example: "02".
- `disablePagination` [query, boolean] — If true, all rules for requested scope will be returned

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/device-control`
**Create Device Control Rule**
`operationId`: `_web_api_device-control_post`

Use this command to create a new Device Control rule. These rules allow or block devices, based on device identifiers. Rules apply to a scope: Global (tenant), Account, Site, or Group. To learn details of the fields, see https://support.sentinelone.com/hc/en-us/articles/360023338494. <br>Recommended: Before you begin, see Device Control Known Limitations: https://support.sentinelone.com/hc/en-us/articles/360021104114.<br>Device Control requires Control SKU. Linux Agents do not support Device Control.

Required permissions: `Device Control.create`

Parameters:
- `body` [body, device_control.schemas_PostDeviceSchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/device-control/configuration`
**Get Configuration**
`operationId`: `_web_api_device-control_configuration_get`

Get Device Control configuration for a given scope.<br>To filter the results for a scope:<br>* Global - Make sure "tenant" is "true" and no other scope ID is given.<br>* Account - Make sure "tenant" is "false" and at least one Account ID is given.<br>* Site - Make sure "tenant" is "false" and at least one Site ID is given.<brDevice Control requires Control SKU. It is not supported on Linux.

Required permissions: `Device Control.view`

Parameters:
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "225494730938493804,225494730938493915".
- `siteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `groupIds` [query, array] — List of Group IDs to filter by. Example: "225494730938493804,225494730938493915".
- `tenant` [query, boolean] — Indicates a tenant scope request

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `PUT /web/api/v2.1/device-control/configuration`
**Update Configuration**
`operationId`: `_web_api_device-control_configuration_put`

Use this command to change the Device Control configuration. Enter a Group ID, Site ID, Account ID, or "tenant = true". If you select only tenant, and the other scopes are empty, the change is applied to the Global policy.
Device Control requires Control SKU. It is not supported on Linux.

Required permissions: `Device Control.edit`

Parameters:
- `body` [body, device_control.schemas_PostDeviceSettingsSchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/device-control/copy-rules`
**Copy Rules**
`operationId`: `_web_api_device-control_copy-rules_post`

You can copy a set of Device Control rules to use in other Accounts, Sites, or Groups. Copy the rules from a source Group, Site, or Account to target Groups, Sites, or Accounts. <br>Define the rules to copy with the filters. To get the values for devices, run "unscoped". To get Account IDs, run "accounts". To get Site IDs, run "sites". <br>Device Control requires Control SKU. Linux Agents do not support Device Control.
Optional permissions: `Device Control.view, Device Control.create`

Parameters:
- `body` [body, device_control.schemas_CopyRuleSchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `PUT /web/api/v2.1/device-control/enable`
**Enable/Disable Rules**
`operationId`: `_web_api_device-control_enable_put`

It is best practice to disable a rule rather than delete it. Use this command to change the status of a rule between Enabled and Disabled. <br>Note: On Windows, if a USB device is already connected to an endpoint, new rules and rule changes do not affect it. USB rules will apply the next time the device connects to the endpoint. For Windows Bluetooth rules, the device and endpoint must be paired after the SentinelOne Agent that supports Bluetooth is installed or upgraded. If the endpoint and device were already paired before the Agent supported bluetooth, reboot the endpoint to activate the rule, or re-pair the endpoint and device.<br>On macOS, changes apply to devices that are already connected to an endpoint.

Required permissions: `Device Control.edit`

Parameters:
- `body` [body, device_control.schemas_EnableRuleSchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/device-control/events`
**Get Device Control Events**
`operationId`: `_web_api_device-control_events_get`

Get the data of Device Control events on Windows and macOS endpoints with Device Control-enabled Agents that match the filter.
Device Control requires Control SKU. Linux Agents do not support Device Control.

Required permissions: `Device Control.view`

Parameters:
- `skip` [query, integer] — Skip first number of items (0-1000). To iterate over more than 1000 items,  use "cursor". Example: "150".
- `limit` [query, integer] — Limit number of returned items (1-1000). Example: "10".
- `cursor` [query, string] — Cursor position returned by the last request. Use to iterate over more than 1000 items. Example: "YWdlbnRfaWQ6NTgwMjkzODE=".
- `countOnly` [query, boolean] — If true, only total number of items will be returned, without any of the actual objects.
- `skipCount` [query, boolean] — If true, total number of items will not be calculated, which speeds up execution time.
- `sortBy` [query, string] (enum: id, eventTime, eventType, agentId) — The column to sort the results by. Example: "id".
- `sortOrder` [query, string] (enum: asc, desc) — Sort direction. Example: "asc".
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "225494730938493804,225494730938493915".
- `siteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `groupIds` [query, array] — List of Group IDs to filter by. Example: "225494730938493804,225494730938493915".
- `tenant` [query, boolean] — Indicates a tenant scope request
- `query` [query, string] — A free-text search term, will match applicable attributes.
- `eventTime__gt` [query, string] — Return events generated after this time. Example: "2018-02-27T04:49:26.257525Z".
- `eventTime__lt` [query, string] — Return events generated before this time. Example: "2018-02-27T04:49:26.257525Z".
- `eventTime__gte` [query, string] — Return events generated after or at this time. Example: "2018-02-27T04:49:26.257525Z".
- `eventTime__lte` [query, string] — Return events generated before or at this time. Example: "2018-02-27T04:49:26.257525Z".
- `eventTime__between` [query, string] — Return events created within this range (inclusive). Example: "1514978764288-1514978999999".
- `ids` [query, array] — List of IDs to filter by. Example: "225494730938493804,225494730938493915".
- `eventIds` [query, array] — List of event IDs to filter by
- `interfaces` [query, array] — List of interfaces to filter by. Example: "USB".
- `deviceClasses` [query, array] — List of device classes to filter by. Example: "02h".
- `serviceClasses` [query, array] — List of service classes to filter by. Example: "02".
- `vendorIds` [query, array] — List of vendor IDs to filter by.
- `productIds` [query, array] — List of product IDs to filter by. Example: "02".
- `uids` [query, array] — List of uIds to filter by.
- `eventTypes` [query, array] — List of event types to filter by.
- `accessPermissions` [query, array] — Access permission in. Example: "Read-Only".
- `agentIds` [query, array] — List of agent Ids to filter by
- `deviceIds` [query, array] — List of device IDs to filter by

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/device-control/export`
**Export Rules**
`operationId`: `_web_api_device-control_export_get`

Export Device Control rules to a CSV file.

Required permissions: `Device Control.view`

Parameters:
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "225494730938493804,225494730938493915".
- `siteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `groupIds` [query, array] — List of Group IDs to filter by. Example: "225494730938493804,225494730938493915".
- `tenant` [query, boolean] — Indicates a tenant scope request
- `query` [query, string] — A free-text search term, will match applicable attributes.
- `scopes` [query, array] — Return only device rules in this scope. Example: "site".
- `interfaces` [query, array] — Return device rules with the filtered interface. Example: "USB".
- `deviceClasses` [query, array] — Return device rules with the filtered device class. Example: "02h".
- `serviceClasses` [query, array] — Return device rules with the filtered service class. Example: "02".
- `ruleName` [query, string] — Return device rules with the filtered rule name.
- `vendorIds` [query, array] — Return device rules with the filtered vendor id.
- `productIds` [query, array] — Return device rules with the filtered product id. Example: "02".
- `uids` [query, array] — Return device rules with the filtered uId.
- `actions` [query, array] — Return device rules with the filtered action. Example: "Allow".
- `statuses` [query, array] — Return device rules with the filtered status. Example: "Enabled".
- `createdAt__lt` [query, string] — Return device rules created before this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__gt` [query, string] — Return device rules created after this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__lte` [query, string] — Return device rules created before or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__gte` [query, string] — Return device rules created after or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__between` [query, string] — Return device rules created within this range (inclusive). Example: "1514978764288-1514978999999".
- `ids` [query, array] — List of ids to filter by. Example: "225494730938493804,225494730938493915".
- `versions` [query, array] — Return device rules with the filtered versions.
- `minorClasses` [query, array] — Return device rules with the filtered minor classes.
- `accessPermissions` [query, array] — Access permission in. Example: "Read-Only".
- `bluetoothAddresses` [query, array] — Return device rules with the filtered bluetooth addresses.
- `gattServices` [query, array] — Return device rules with the filtered GATT services.
- `manufacturerNames` [query, array] — Return device rules with the filtered manufacturer names.
- `deviceNames` [query, array] — Return device rules with the filtered device names.
- `deviceInformationServiceInfoKeys` [query, array] — Return device rules with the filtered device information service info keys.
- `deviceIds` [query, array] — Return device rules with the filtered device id. Example: "02".

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/device-control/move-rules`
**Move rules**
`operationId`: `_web_api_device-control_move-rules_post`

You can move a set of Device Control rules to other Accounts, Sites, or Groups. This command removes the rule from the source and copies to the targets. 
Define the rules to copy with the filters. To get the values for devices, run "unscoped". To get Account IDs, run "accounts". To get Site IDs, run "sites".
Device Control requires Control SKU. Linux Agents do not support Device Control.
Optional permissions: `Device Control.delete, Device Control.create, Device Control.view`

Parameters:
- `body` [body, device_control.schemas_CopyRuleSchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `PUT /web/api/v2.1/device-control/reorder`
**Reorder Rules**
`operationId`: `_web_api_device-control_reorder_put`

When an external device connects to an endpoint, the SentinelOne Agent looks at the rules based on their order in the Device Control policy, from the top to the bottom. When the Agent finds a rule that matches the device identifiers of a connected device, that rule is applied. The Agent does not continue to the lower rules in the list.
Use this command to change the order of rules for a specific scope. 
Device Control requires Control SKU. Linux Agents do not support Device Control.

Required permissions: `Device Control.edit`

Parameters:
- `body` [body, device_control.schemas_ReorderSchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `PUT /web/api/v2.1/device-control/{rule_id}`
**Update Device Rule**
`operationId`: `_web_api_device-control_{rule_id}_put`

Change the Device Control rule that matches the filter. To learn more about the fields, see https://support.sentinelone.com/hc/en-us/articles/360023338494.

Required permissions: `Device Control.edit`

Parameters:
- `rule_id` [path, string] **required** — Rule ID. Example: "225494730938493804".
- `body` [body, device_control.schemas_PutDeviceSchema] — 

Responses: 404 Device rule not found, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.
