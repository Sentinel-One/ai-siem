# Network Quarantine Control

15 endpoints.

## `DELETE /web/api/v2.1/firewall-control/{firewall_rule_category}`
**Delete Rules**
`operationId`: `_web_api_firewall-control_{firewall_rule_category}_delete`

Delete Firewall Control rules that match the filter.
Optional permissions: `Firewall Control.manageRulesAndTags, Network Quarantine Control.manageRulesAndTags`

Parameters:
- `firewall_rule_category` [path, string] **required** — To affect Network Quarantine use network-quarantine
- `body` [body, firewall_control.schemas_RuleDeleteSchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/firewall-control/{firewall_rule_category}`
**Get Firewall Rules**
`operationId`: `_web_api_firewall-control_{firewall_rule_category}_get`

Get the Firewall Control rules for a scope specified by ID (run "accounts", "sites, "groups", or set "tenant" to "true") that match the filter. <br>The response will be quite long because it includes all the rule properties, thus at least one of these filters is required: action, status, osType, name, or scope ID.
Optional permissions: `Firewall Control.view, Network Quarantine Control.view`

Parameters:
- `firewall_rule_category` [path, string] **required** — To affect Network Quarantine use network-quarantine
- `skip` [query, integer] — Skip first number of items (0-1000). To iterate over more than 1000 items,  use "cursor". Example: "150".
- `limit` [query, integer] — Limit number of returned items (1-1000). Example: "10".
- `cursor` [query, string] — Cursor position returned by the last request. Use to iterate over more than 1000 items. Example: "YWdlbnRfaWQ6NTgwMjkzODE=".
- `countOnly` [query, boolean] — If true, only total number of items will be returned, without any of the actual objects.
- `skipCount` [query, boolean] — If true, total number of items will not be calculated, which speeds up execution time.
- `sortBy` [query, string] (enum: id, name, action, status, order) — The column to sort the results by. Example: "id".
- `sortOrder` [query, string] (enum: asc, desc) — Sort direction. Example: "asc".
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "225494730938493804,225494730938493915".
- `siteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `groupIds` [query, array] — List of Group IDs to filter by. Example: "225494730938493804,225494730938493915".
- `tenant` [query, boolean] — Indicates a tenant scope request
- `query` [query, string] — Free text search on name, tag, application, protocol
- `scopes` [query, array] — Return only firewall rules in this scope. Example: "site".
- `applications` [query, array] — Return firewall rules with the filtered firewall class.
- `name` [query, string] — Return firewall rules with the filtered name.
- `protocols` [query, array] — Return firewall rules with the filtered protocols.
- `osTypes` [query, array] — Return firewall rules with the filtered os_type. Example: "macos".
- `directions` [query, array] — Return firewall rules with the filtered directions. Example: "any".
- `actions` [query, array] — Return firewall rules with the filtered action. Example: "Allow".
- `statuses` [query, array] — Return firewall rules with the filtered status. Example: "Enabled".
- `createdAt__lt` [query, string] — Return firewall rules created before this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__gt` [query, string] — Return firewall rules created after this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__lte` [query, string] — Return firewall rules created before or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__gte` [query, string] — Return firewall rules created after or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__between` [query, string] — Return firewall rules created within this range (inclusive). Example: "1514978764288-1514978999999".
- `ids` [query, array] — List of ids to filter by. Example: "225494730938493804,225494730938493915".
- `locationIds` [query, array] — Filter by associated locations. Example: "225494730938493804,225494730938493915".
- `tagIds` [query, array] — Filter by associated tags. Example: "225494730938493804,225494730938493915".
- `name__contains` [query, array] — Free-text filter by the Rule name (supports multiple values)
- `tagName__contains` [query, array] — Free-text filter by the Tag name (supports multiple values)
- `application__contains` [query, array] — Free-text filter by application (supports multiple values)
- `protocol__contains` [query, array] — Free-text filter by protocol (supports multiple values)
- `service__contains` [query, array] — Free-text filter by service (supports multiple values)
- `disablePagination` [query, boolean] — If true, all rules for requested scope will be returned

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/firewall-control/{firewall_rule_category}`
**Create Firewall Rule**
`operationId`: `_web_api_firewall-control_{firewall_rule_category}_post`

Create a Firewall Control rule for a scope specified by ID (run "accounts", "sites", "groups", or set "tenant" to "true") and specific OS, to allow or block network traffic to matching endpoints.<br>You can create one clean-up rule, with the Action of Allow or Block and with no other parameters defined explicitly. Make this the default rule at the end of your rule list. Traffic that does not match other rules first will match this rule. If you do not have a clean-up rule to match all traffic, the default Firewall Control behavior is to allow traffic that is not explicitly blocked.<br>Firewall Control requires Control SKU.
Optional permissions: `Firewall Control.manageRulesAndTags, Network Quarantine Control.manageRulesAndTags`

Parameters:
- `firewall_rule_category` [path, string] **required** — To affect Network Quarantine use network-quarantine
- `body` [body, firewall_control.schemas_PostFirewallSchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/firewall-control/{firewall_rule_category}/add-tags`
**Add Rule Tags**
`operationId`: `_web_api_firewall-control_{firewall_rule_category}_add-tags_post`

Create a Firewall Rule tag. <br>Create tags to represent Firewall policies - a set of rules in a specific order. After you create the tag, add rules to it.<br>Notes:<br>* Tags apply to a scope and cannot be linked to rules from different scopes.<br>* Tags must be 2 to 256 characters.
Optional permissions: `Firewall Control.manageRulesAndTags, Network Quarantine Control.manageRulesAndTags`

Parameters:
- `firewall_rule_category` [path, string] **required** — To affect Network Quarantine use network-quarantine
- `body` [body, firewall_control.schemas_ChangeRulesTagsSchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/firewall-control/{firewall_rule_category}/configuration`
**Get Configuration**
`operationId`: `_web_api_firewall-control_{firewall_rule_category}_configuration_get`

Get the Firewall Control configuration for a given scope.<br>To filter the results for a scope:<br>* Global - Make sure "tenant" is "true" and no other scope ID is given.<br>* Account - Make sure "tenant" is "false" and at least one Account ID is given.<br>* Site - Make sure "tenant" is "false" and at least one Site ID is given.<br>The response shows if Firewall Control is enabled for the scope, if Location Awareness is enabled, the higher scope from which this scope inherited the configuration, and whether a lower scope inherits this configuration.<br>Firewall Control requires Control SKU.
Optional permissions: `Firewall Control.view, Network Quarantine Control.view`

Parameters:
- `firewall_rule_category` [path, string] **required** — To affect Network Quarantine use network-quarantine
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "225494730938493804,225494730938493915".
- `siteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `groupIds` [query, array] — List of Group IDs to filter by. Example: "225494730938493804,225494730938493915".
- `tenant` [query, boolean] — Indicates a tenant scope request

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `PUT /web/api/v2.1/firewall-control/{firewall_rule_category}/configuration`
**Update Configuration**
`operationId`: `_web_api_firewall-control_{firewall_rule_category}_configuration_put`

Change the Firewall Control configuration for a given scope.  <br>To get the ID of a scope, run "accounts", "sites", or "groups". To change the Global configuration, leave the filters empty and set "tenant" to "true". In the Body, you can set if Firewall Control is enabled for the scope, if Location Awareness is enabled, the higher scope from which this scope inherits the configuration ("Global" or a scope ID), whether the lower scopes inherit this configuration, and whether blocked actions are reported.<br>Firewall Control requires Control SKU.
Optional permissions: `Firewall Control.modifySettings(preferencesTab), Network Quarantine Control.modifySettings(preferencesTab), Firewall Control.manageRulesAndTags, Network Quarantine Control.manageRulesAndTags`

Parameters:
- `firewall_rule_category` [path, string] **required** — To affect Network Quarantine use network-quarantine
- `body` [body, firewall_control.schemas_PostFirewallSettingsSchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/firewall-control/{firewall_rule_category}/copy-rules`
**Copy Rules**
`operationId`: `_web_api_firewall-control_{firewall_rule_category}_copy-rules_post`

Copy a set of rules to other scopes. <br>In the filter of the body, enter the properties to define the source. In the data field of the body, define the targets by ID. To get a scope ID, run 'accounts', 'sites', or 'groups'.
Optional permissions: `Firewall Control.view, Network Quarantine Control.view, Firewall Control.manageRulesAndTags, Network Quarantine Control.manageRulesAndTags`

Parameters:
- `firewall_rule_category` [path, string] **required** — To affect Network Quarantine use network-quarantine
- `body` [body, firewall_control.schemas_CopyRuleSchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `PUT /web/api/v2.1/firewall-control/{firewall_rule_category}/enable`
**Enable/Disable Rules**
`operationId`: `_web_api_firewall-control_{firewall_rule_category}_enable_put`

Change the status of a set of Firewall Control rules that match the filter to "Enabled" or "Disabled". In one request, you can set one status or the other.
Optional permissions: `Firewall Control.manageRulesAndTags, Network Quarantine Control.manageRulesAndTags`

Parameters:
- `firewall_rule_category` [path, string] **required** — To affect Network Quarantine use network-quarantine
- `body` [body, firewall_control.schemas_EnableRuleSchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/firewall-control/{firewall_rule_category}/export`
**Export Rules**
`operationId`: `_web_api_firewall-control_{firewall_rule_category}_export_get`

Export Firewall Control rules that match the filter to a JSON file from a scope specified by ID (run "accounts", "sites", "groups", or leave the scope empty and set "tenant" to "true") and import them to another scope (with the "import" command. <br>Firewall Control requires Control SKU.
Optional permissions: `Firewall Control.view, Network Quarantine Control.view`

Parameters:
- `firewall_rule_category` [path, string] **required** — To affect Network Quarantine use network-quarantine
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "225494730938493804,225494730938493915".
- `siteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `groupIds` [query, array] — List of Group IDs to filter by. Example: "225494730938493804,225494730938493915".
- `tenant` [query, boolean] — Indicates a tenant scope request
- `query` [query, string] — Free text search on name, tag, application, protocol
- `scopes` [query, array] — Return only firewall rules in this scope. Example: "site".
- `applications` [query, array] — Return firewall rules with the filtered firewall class.
- `name` [query, string] — Return firewall rules with the filtered name.
- `protocols` [query, array] — Return firewall rules with the filtered protocols.
- `osTypes` [query, array] — Return firewall rules with the filtered os_type. Example: "macos".
- `directions` [query, array] — Return firewall rules with the filtered directions. Example: "any".
- `actions` [query, array] — Return firewall rules with the filtered action. Example: "Allow".
- `statuses` [query, array] — Return firewall rules with the filtered status. Example: "Enabled".
- `createdAt__lt` [query, string] — Return firewall rules created before this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__gt` [query, string] — Return firewall rules created after this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__lte` [query, string] — Return firewall rules created before or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__gte` [query, string] — Return firewall rules created after or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__between` [query, string] — Return firewall rules created within this range (inclusive). Example: "1514978764288-1514978999999".
- `ids` [query, array] — List of ids to filter by. Example: "225494730938493804,225494730938493915".
- `locationIds` [query, array] — Filter by associated locations. Example: "225494730938493804,225494730938493915".
- `tagIds` [query, array] — Filter by associated tags. Example: "225494730938493804,225494730938493915".
- `name__contains` [query, array] — Free-text filter by the Rule name (supports multiple values)
- `tagName__contains` [query, array] — Free-text filter by the Tag name (supports multiple values)
- `application__contains` [query, array] — Free-text filter by application (supports multiple values)
- `protocol__contains` [query, array] — Free-text filter by protocol (supports multiple values)
- `service__contains` [query, array] — Free-text filter by service (supports multiple values)

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/firewall-control/{firewall_rule_category}/import`
**Import Rules**
`operationId`: `_web_api_firewall-control_{firewall_rule_category}_import_post`

Import Firewall Control rules from an exported JSON file to scopes specified by ID (run "accounts", "sites", "groups", or leave the scope empty and set "tenant" to "true").<br>Firewall Control requires Control SKU, in the target and in the source.
Optional permissions: `Firewall Control.manageRulesAndTags, Network Quarantine Control.manageRulesAndTags`

Parameters:
- `firewall_rule_category` [path, string] **required** — To affect Network Quarantine use network-quarantine
- `accountIds` [formData, array] — List of Account IDs to filter by. Example: "225494730938493804,225494730938493915".
- `siteIds` [formData, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `groupIds` [formData, array] — List of Group IDs to filter by. Example: "225494730938493804,225494730938493915".
- `tenant` [formData, boolean] — Indicates a tenant scope request
- `file` [formData, file] **required** — File

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/firewall-control/{firewall_rule_category}/move-rules`
**Move Rules**
`operationId`: `_web_api_firewall-control_{firewall_rule_category}_move-rules_post`

Remove Firewall Rules, defined with the ID of the rules (run 'firewall-control'), from scopes specified by ID (run 'accounts', 'sites', or 'groups') and add the rules to the scope IDs in the data field.<br>Firewall Control requires Control SKU.
Optional permissions: `Firewall Control.view, Network Quarantine Control.view, Firewall Control.manageRulesAndTags, Network Quarantine Control.manageRulesAndTags`

Parameters:
- `firewall_rule_category` [path, string] **required** — To affect Network Quarantine use network-quarantine
- `body` [body, firewall_control.schemas_CopyRuleSchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/firewall-control/{firewall_rule_category}/protocols`
**Get Protocols**
`operationId`: `_web_api_firewall-control_{firewall_rule_category}_protocols_get`

Get a list of protocols that can be used in Firewall Control rules.
Optional permissions: `Firewall Control.view, Network Quarantine Control.view`

Parameters:
- `firewall_rule_category` [path, string] **required** — To affect Network Quarantine use network-quarantine
- `skip` [query, integer] — Skip first number of items (0-1000). To iterate over more than 1000 items,  use "cursor". Example: "150".
- `limit` [query, integer] — Limit number of returned items (1-1000). Example: "10".
- `cursor` [query, string] — Cursor position returned by the last request. Use to iterate over more than 1000 items. Example: "YWdlbnRfaWQ6NTgwMjkzODE=".
- `countOnly` [query, boolean] — If true, only total number of items will be returned, without any of the actual objects.
- `skipCount` [query, boolean] — If true, total number of items will not be calculated, which speeds up execution time.
- `sortBy` [query, string] (enum: name) — The column to sort the results by. Example: "id".
- `sortOrder` [query, string] (enum: asc, desc) — Sort direction. Example: "asc".
- `query` [query, string] — Full text search on protocols
- `disablePagination` [query, boolean] — If true, all rules for requested scope will be returned

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/firewall-control/{firewall_rule_category}/remove-tags`
**Remove Rule Tags**
`operationId`: `_web_api_firewall-control_{firewall_rule_category}_remove-tags_post`

Remove firewall tags from rules matching the filter.<br>Tags represent Firewall policies - a set of rules in a specific order. When you remove a rule with a tag, all scopes that subscribe to the tag get the change.
Optional permissions: `Firewall Control.manageRulesAndTags, Network Quarantine Control.manageRulesAndTags`

Parameters:
- `firewall_rule_category` [path, string] **required** — To affect Network Quarantine use network-quarantine
- `body` [body, firewall_control.schemas_ChangeRulesTagsSchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `PUT /web/api/v2.1/firewall-control/{firewall_rule_category}/reorder`
**Reorder Rules**
`operationId`: `_web_api_firewall-control_{firewall_rule_category}_reorder_put`

Change the order of rules for a scope  specified by ID (run "accounts", "sites", or "groups"). <br>The Agent looks at the rules based on their order in the Firewall Control policy, from the top to the bottom. First it goes through the Group rules, then the Site rules, then the Account rules, then the Global rules. When the Agent finds a rule that matches the parameters of the traffic, that rule is applied. The Agent does not continue to the lower rules in the list. Thus, the scope and the order of the rules is important.<br>Firewall Control requires Control SKU.
Optional permissions: `Firewall Control.manageRulesAndTags, Network Quarantine Control.manageRulesAndTags`

Parameters:
- `firewall_rule_category` [path, string] **required** — To affect Network Quarantine use network-quarantine
- `body` [body, firewall_control.schemas_ReorderSchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/firewall-control/{firewall_rule_category}/set-location`
**Set Location**
`operationId`: `_web_api_firewall-control_{firewall_rule_category}_set-location_post`

Set location attributes for a Location Aware Firewall Control rule. These rules are applied by Agents only if the network parameters of the endpoint match the properties of the location definition. To get a Location ID, run "locations". <br>Firewall Control requires Control SKU.
Optional permissions: `Firewall Control.manageRulesAndTags, Network Quarantine Control.manageRulesAndTags`

Parameters:
- `firewall_rule_category` [path, string] **required** — To affect Network Quarantine use network-quarantine
- `body` [body, firewall_control.schemas_SetLocationSchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.
