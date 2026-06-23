# Custom Detection Rule

6 endpoints.

## `DELETE /web/api/v2.1/cloud-detection/rules`
**Delete Rules**
`operationId`: `_web_api_cloud-detection_rules_delete`

Deletes Custom Detection Rules that match a filter.

Required permissions: `Custom Rules.manage`

Parameters:
- `body` [body, v2_1.rules.schemas_RuleDeleteSchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/cloud-detection/rules`
**Get Rules**
`operationId`: `_web_api_cloud-detection_rules_get`

Get a list of Custom Detection Rules for a given scope. <br>Note:  You can create and see rules only for your highest available scope. For example, if your username has an access level of scope Account, you cannot see rules created for the Global scope or rules created for a specific Site.

> **⚠️ CRITICAL: pass `isLegacy=false` whenever you want to see scheduled rules.**
> The default behaviour of this endpoint is to OMIT `queryType=scheduled` rules from the response.
> No error is returned, no warning is logged — the response simply lists 0 scheduled rules.
> If you ever want to claim "this tenant has no scheduled detections", you MUST have called this endpoint with `isLegacy=false` first. Without it, the absence of evidence is meaningless.
>
> Correct invocations (re-verified 2026-05):
> - All rules: `GET /cloud-detection/rules?isLegacy=false&limit=200`
> - Only scheduled: `GET /cloud-detection/rules?isLegacy=false&queryType=scheduled&limit=200`
> - Only events: `GET /cloud-detection/rules?queryType=events&limit=200` (isLegacy not needed)
> - Name search: `GET /cloud-detection/rules?isLegacy=false&name__contains=<text>`
>
> Combining `queryType=*` with `nameSubstring=*` returns HTTP 500. Use one filter at a time, or use `name__contains` (which works alongside `queryType`).

Required permissions: `Custom Rules.view`

Parameters:
- `statuses` [query, array] — Statuses. Example: "Activating".
- `name__contains` [query, array] — Free-text filter by rule name. You can enter multiple values, separated by commas. Example: "Service Pack 1".
- `description__contains` [query, array] — Free-text filter by rule description. You can enter multiple values, separated by commas. Example: "Service Pack 1".
- `expirationMode` [query, string] (enum: Permanent, Temporary) — The expiration mode. Example: "Permanent".
- `query` [query, array] — Free-text filter by S1 query. You can enter multiple values, separated by commas. Example: "Service Pack 1".
- `severities` [query, array] — Severities. Example: "Low".
- `groupIds` [query, array] — List of Group IDs to filter by. Example: "225494730938493804,225494730938493915".
- `descriptionSubstring` [query, string] — To filter by a substring of the rule description
- `scopeLevel` [query, string] (enum: global, group, account, site) — To filter by scope, enter one or more scopes, separated by commas. Example: "global".
- `limit` [query, integer] — Limit number of returned items (1-1000). Example: "10".
- `scopeId` [query, string] — The Account, Site, or Group ID, depending on the scope. Null if the scope is Global. Example: "225494730938493804".
- `sortOrder` [query, string] (enum: asc, desc) — Sort direction. Example: "asc".
- `countOnly` [query, boolean] — If true, only total number of items will be returned, without any of the actual objects.
- `sources` [query, array] — To filter by sources associated with the rule.
- `isLegacy` [query, boolean] — If True, alertsCount will be retrieved from Star and not from UAM.
- `expired` [query, boolean] — Rule expired or not.
- `s1qlSubstring` [query, string] — To filter by a substring of the query content
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "225494730938493804,225494730938493915".
- `excludeIds` [query, array] — List of entity ids to exclude from select_all. Example: "225494730938493804,225494730938493915".
- `s1ql__contains` [query, array] — Free-text filter by S1 query. You can enter multiple values, separated by commas. Example: "Service Pack 1".
- `mitreTactics` [query, array] — To filter by sources associated with the rule.
- `creator__contains` [query, array] — Free-text filter by rule creator. You can enter multiple values, separated by commas. Example: "Service Pack 1".
- `cursor` [query, string] — Cursor position returned by the last request. Use to iterate over more than 1000 items. Example: "YWdlbnRfaWQ6NTgwMjkzODE=".
- `filterBy` [query, string] (enum: Template, Platform) — To filter by Rule type. Example: "Template".
- `activeResponse` [query, boolean] — The active response status for the rule.
- `ids` [query, array] — To filter by Rule ID, enter one or more Rule IDs, separated by commas. Example: "225494730938493804,225494730938493915".
- `attackSurfaces` [query, array] — To filter by attack surfaces associated with the rule.
- `skip` [query, integer] — Skip first number of items (0-1000). To iterate over more than 1000 items,  use "cursor". Example: "150".
- `disablePagination` [query, boolean] — If True, all rules for the requested scope will be returned.
- `reachedLimit` [query, boolean] — Rule reached limit or not.
- `scopes` [query, array] — To filter by scope, enter one or more scopes, separated by commas. Example: "global".
- `queryType` [query, array] — Enter a list of query types. Example: "events".
- `siteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `status` [query, array] — To filter by status, enter one or more statuses, separated by commas. Example: "Draft".
- `skipCount` [query, boolean] — If true, total number of items will not be calculated, which speeds up execution time.
- `platformRuleIds` [query, array] — platform rule ids. Example: "225494730938493804,225494730938493915".
- `sortBy` [query, string] (enum: id, name, status, expirationMode, expired, queryType, reachedLimit, statusReason, severity, expiration, createdAt, updatedAt, generatedAlerts, description, scopeHierarchy, scope, activeResponse, lastAlertTime, queryLang) — The column to sort the results by. Example: "id".
- `nameSubstring` [query, string] — To filter by a substring of the rule name

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/cloud-detection/rules`
**Create Rule**
`operationId`: `_web_api_cloud-detection_rules_post`

Create a Custom Detection Rule for a scope specified by ID. To get the ID, run "accounts", "sites", "groups", or set "tenant" to "true" for Global.

Required permissions: `Custom Rules.manage`
Optional permissions: `Threats.markSuspicious, Threats.markThreat, Endpoints.disconnectFromNetwork`

Parameters:
- `body` [body, v2_1.rules.schemas_PostRuleSchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `PUT /web/api/v2.1/cloud-detection/rules/disable`
**Disable Rules**
`operationId`: `_web_api_cloud-detection_rules_disable_put`

Disable Custom Detection Rules based on a filter.

Required permissions: `Custom Rules.manage`

Parameters:
- `body` [body, v2_1.rules.schemas_FilterRuleSchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `PUT /web/api/v2.1/cloud-detection/rules/enable`
**Activate Rules**
`operationId`: `_web_api_cloud-detection_rules_enable_put`

Activate Custom Detection Rules based on a filter.

Required permissions: `Custom Rules.manage`

Parameters:
- `body` [body, v2_1.rules.schemas_FilterRuleSchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `PUT /web/api/v2.1/cloud-detection/rules/{rule_id}`
**Update Rule**
`operationId`: `_web_api_cloud-detection_rules_{rule_id}_put`

Change a Custom Detection rule. <br>This command requires the rule ID. (See Get Rules).

Required permissions: `Custom Rules.manage`
Optional permissions: `Threats.markSuspicious, Threats.markThreat, Endpoints.disconnectFromNetwork`

Parameters:
- `rule_id` [path, string] **required** — The Rule ID in the URL path. Example: "225494730938493804".
- `body` [body, v2_1.rules.schemas_PostRuleSchema] — 

Responses: 404 Custom Detection rule not found, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.
