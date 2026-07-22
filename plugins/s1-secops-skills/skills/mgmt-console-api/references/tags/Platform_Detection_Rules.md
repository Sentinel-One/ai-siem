# Platform Detection Rules

12 endpoints.

## Working notes: enabling platform (managed / OOTB) rules (tenant-validated, S-26.2.2)

Platform rules are SentinelOne-managed out-of-the-box detections (`createdBy: "SentinelOne"`, ~2,000+ in the catalog), separate from custom STAR rules. Custom rules live at `/web/api/v2.1/cloud-detection/rules`; platform rules live ONLY under `/detection-library/*`. Listing `cloud-detection/rules` will NOT return platform rules.

Reading:
- List with `GET /detection-library/platform-rules`, scoped via `scopeId` + `scopeLevel` (`global|group|account|site`). For `global`, OMIT `scopeId` (otherwise 400 "a tenant scope request should not include scope id").
- The facet endpoints (`data-sources`, `surfaces`, `severities`, `statuses`) scope via `siteIds=`, not `scopeId`/`scopeLevel`.
- `hideQuery=Shown` includes the `s1ql` body in each rule (enum is `Shown`/`Hidden`, not `true`/`false`).
- `skip` is capped at 1000 ("Cannot display more than 1000 results, please refine your search"). To reach the full catalog, filter by `sources` (array). Source names are vendor-specific, e.g. `Mimecast`, `Palo Alto Networks Firewall`, `Zscaler Internet Access`, `Okta`. Not every ingested source has platform rules (Cisco Umbrella and Tenable had none on this tenant).

Enabling / disabling:
- `PUT /detection-library/platform-rules/enable`, FLAT body `{ "platformRuleIds": [<ids>], "scopeId": "<id>", "scopeLevel": "site" }`. `platformRuleIds` MUST be integers. String IDs return a misleading HTTP 500 "Server could not process the request". Response carries `data.affected`. Enable "creates a new rule and activates it" (a scoped active copy). `disable` uses the same body shape.
- The enable/disable/settings body is FLAT, NOT wrapped in `{"data": ...}` (wrapping returns 400 "scopeLevel: Missing data for required field").
- An account-scoped API user cannot enable at `global`/tenant scope (400 "can not create rule with higher scope ... tenant"). Enable at `account` or `site`.

Site-scope enable requires disabling inheritance FIRST (otherwise enable returns HTTP 500):
- `PUT /detection-library/platform-rules/settings`, FLAT body `{ "scopeId": "<site>", "scopeLevel": "site", "disableInheritance": true }`. Send ONLY `disableInheritance` plus scope. Including `core`/`autoDefault` in the same call returns 400 "cannot enable auto default when inheritance is enabled".
- Settings category toggles are `core`, `autoDefault`, `emergingThreat`, `smartDefault` (each `On`/`Off`); at least one of `core`/`autoDefault` is required when setting those, but omit them when only flipping inheritance.

Permissions: reads need `Custom Rules.view`; enable/disable/settings need `Custom Rules.manage`.
## `GET /web/api/v2.1/detection-library/data-sources`
**Get Data Sources**
`operationId`: `_web_api_detection-library_data-sources_get`

Get Data Sources valid for Managed Detection Rules

Required permissions: `Custom Rules.view`

Responses: 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/detection-library/platform-rules`
**Get Managed Detection Rules**
`operationId`: `_web_api_detection-library_platform-rules_get`

Return Managed Detection Rules for the given scope

Required permissions: `Custom Rules.view`

Parameters:
- `statuses` [query, array] — Statuses. Example: "Activating".
- `attackSurfaces` [query, array] — To filter by attack surfaces associated with the rule.
- `skip` [query, integer] — Skip first number of items (0-1000). To iterate over more than 1000 items,  use "cursor". Example: "150".
- `description__contains` [query, string] — To filter by a substring of the rule description
- `ruleNameSubstring` [query, string] — To filter by a substring of the rule name
- `s1ql__contains` [query, string] — To filter by a substring of the query content
- `excludeIds` [query, array] — List of entity ids to exclude from select_all. Example: "225494730938493804,225494730938493915".
- `scopeLevel` [query, string] (enum: global, group, account, site) — To filter by scope, enter one or more scopes, separated by commas. Example: "global".
- `limit` [query, integer] — Limit number of returned items (1-1000). Example: "10".
- `scopeId` [query, string] — The Account, Site, or Group ID, depending on the scope. Null if the scope is Global. Example: "225494730938493804".
- `mitreTactics` [query, array] — To filter by sources associated with the rule.
- `cursor` [query, string] — Cursor position returned by the last request. Use to iterate over more than 1000 items. Example: "YWdlbnRfaWQ6NTgwMjkzODE=".
- `countOnly` [query, boolean] — If true, only total number of items will be returned, without any of the actual objects.
- `sources` [query, array] — To filter by sources associated with the rule.
- `skipCount` [query, boolean] — If true, total number of items will not be calculated, which speeds up execution time.
- `platformRuleIds` [query, array] — platform rule ids. Example: "225494730938493804,225494730938493915".
- `severities` [query, array] — Severities. Example: "Low".

Responses: 404 Managed Detection Rules not found, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `PUT /web/api/v2.1/detection-library/platform-rules/disable`
**Disable a Managed Detection Rule**
`operationId`: `_web_api_detection-library_platform-rules_disable_put`

Required permissions: `Custom Rules.manage`

Parameters:
- `body` [body, v2_1.gdl.schemas_PlatformRuleSchemaWithValidation] — 

Responses: 404 Managed Detection Rule not found, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `PUT /web/api/v2.1/detection-library/platform-rules/enable`
**Enable a Managed Detection Rule**
`operationId`: `_web_api_detection-library_platform-rules_enable_put`

Enable a Managed Detection Rule creates a new rule and activates it.

Required permissions: `Custom Rules.manage`

Parameters:
- `body` [body, v2_1.gdl.schemas_PlatformRuleSchemaWithValidation] — 

Responses: 404 Managed Detection Rule not found, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/detection-library/platform-rules/settings`
**Get settings for Managed Detection Rules**
`operationId`: `_web_api_detection-library_platform-rules_settings_get`

Get settings for Managed Detection Rules for the given scope

Required permissions: `Custom Rules.view`

Parameters:
- `scopeId` [query, string] — The Account or Site ID, depending on the scope. Null if the scope is Global. Example: "225494730938493804".
- `scopeLevel` [query, string] **required** (enum: global, group, account, site) — Scope level. Example: "global".

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `PUT /web/api/v2.1/detection-library/platform-rules/settings`
**Update settings for Managed Detection Rules**
`operationId`: `_web_api_detection-library_platform-rules_settings_put`

Update settings for Managed Detection Rules

Required permissions: `Custom Rules.manage`

Parameters:
- `body` [body, v2_1.gdl.schemas_PlatformSettingsSchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/detection-library/rules`
**Get Managed Detection Rules**
`operationId`: `_web_api_detection-library_rules_get`

Return Catalog Rules for the given scope

Required permissions: `Custom Rules.view`

Parameters:
- `statuses` [query, array] — Statuses. Example: "Activating".
- `categories` [query, array] — Categories. Example: "Events".
- `customRuleIds` [query, array] — custom rule ids. Example: "225494730938493804,225494730938493915".
- `query` [query, array] — Free-text filter by All fields(name, description, query content). You can enter multiple values, separated by commas. Example: "Service Pack 1".
- `severities` [query, array] — Severities. Example: "Low".
- `siteIds` [query, string] — site scope level id. Example: "225494730938493804".
- `description__contains` [query, string] — To filter by a substring of the rule description
- `hideQuery` [query, string] (enum: Shown, Hidden) — To filter by hideQuery of the rule params. Example: "Shown".
- `limit` [query, integer] — Limit number of returned items (1-1000). Example: "10".
- `skipCount` [query, boolean] — If true, total number of items will not be calculated, which speeds up execution time.
- `sortOrder` [query, string] (enum: asc, desc) — Sort direction. Example: "asc".
- `countOnly` [query, boolean] — If true, only total number of items will be returned, without any of the actual objects.
- `sources` [query, array] — To filter by sources associated with the rule.
- `s1ql__contains` [query, string] — To filter by a substring of the query content
- `mitreTactics` [query, array] — To filter by sources associated with the rule.
- `cursor` [query, string] — Cursor position returned by the last request. Use to iterate over more than 1000 items. Example: "YWdlbnRfaWQ6NTgwMjkzODE=".
- `accountIds` [query, string] — account scope level id. Example: "225494730938493804".
- `attackSurfaces` [query, array] — To filter by attack surfaces associated with the rule.
- `skip` [query, integer] — Skip first number of items (0-1000). To iterate over more than 1000 items,  use "cursor". Example: "150".
- `name__contains` [query, string] — To filter by a substring of the rule name
- `platformRuleIds` [query, array] — platform rule ids. Example: "225494730938493804,225494730938493915".
- `sortBy` [query, string] (enum: name, status, severity, description, category, generatedAlerts, raisedIssues, lastAlertTime, attackSurfaces) — The column to sort the results by. Example: "id".

Responses: 404 Managed Detection Rules not found, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/detection-library/rules/free-text-filters`
**Free-Text Filters**
`operationId`: `_web_api_detection-library_rules_free-text-filters_get`

Get a metadata list of the available free-text filters

Required permissions: `Custom Rules.view`

Responses: 200 Success, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/detection-library/severities`
**Get Severities**
`operationId`: `_web_api_detection-library_severities_get`

Get Severities valid for Managed Detection Rules

Required permissions: `Custom Rules.view`

Responses: 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/detection-library/statuses`
**Get Statuses**
`operationId`: `_web_api_detection-library_statuses_get`

Get all rule statuses valid for Managed Detection Rules

Required permissions: `Custom Rules.view`

Responses: 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/detection-library/surfaces`
**Get Surfaces**
`operationId`: `_web_api_detection-library_surfaces_get`

Get all Surfaces valid for Managed Detection Rules

Required permissions: `Custom Rules.view`

Responses: 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/detection-library/template-rules`
**Get Template Detection Rules**
`operationId`: `_web_api_detection-library_template-rules_get`

Return Template Detection Rules for the given scope

Required permissions: `Custom Rules.view`

Parameters:
- `statuses` [query, array] — Statuses. Example: "Activating".
- `attackSurfaces` [query, array] — To filter by attack surfaces associated with the rule.
- `skip` [query, integer] — Skip first number of items (0-1000). To iterate over more than 1000 items,  use "cursor". Example: "150".
- `description__contains` [query, string] — To filter by a substring of the rule description
- `ruleNameSubstring` [query, string] — To filter by a substring of the rule name
- `s1ql__contains` [query, string] — To filter by a substring of the query content
- `excludeIds` [query, array] — List of entity ids to exclude from select_all. Example: "225494730938493804,225494730938493915".
- `scopeLevel` [query, string] (enum: global, group, account, site) — To filter by scope, enter one or more scopes, separated by commas. Example: "global".
- `limit` [query, integer] — Limit number of returned items (1-1000). Example: "10".
- `scopeId` [query, string] — The Account, Site, or Group ID, depending on the scope. Null if the scope is Global. Example: "225494730938493804".
- `mitreTactics` [query, array] — To filter by sources associated with the rule.
- `cursor` [query, string] — Cursor position returned by the last request. Use to iterate over more than 1000 items. Example: "YWdlbnRfaWQ6NTgwMjkzODE=".
- `countOnly` [query, boolean] — If true, only total number of items will be returned, without any of the actual objects.
- `sources` [query, array] — To filter by sources associated with the rule.
- `skipCount` [query, boolean] — If true, total number of items will not be calculated, which speeds up execution time.
- `platformRuleIds` [query, array] — platform rule ids. Example: "225494730938493804,225494730938493915".
- `severities` [query, array] — Severities. Example: "Low".

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.
