# Network Discovery Self Enablement

5 endpoints.

## `POST /web/api/v2.1/ranger/enable-self-management`
**Change the Self-Enablement for Accounts**
`operationId`: `_web_api_ranger_enable-self-management_post`

[DEPRECATED] Use the Update Account, Get Account, Get Sites, or the Update Site Add-ons APIs instead.

Parameters:
- `body` [body, ranger.enablement.schemas_UpdateEnablementPostSchema] — 

Responses: 404 , 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/ranger/enablement`
**Get Self Enablement**
`operationId`: `_web_api_ranger_enablement_get`

[DEPRECATED] Use the Update Account, Get Account, Get Sites, or the Update Site Add-ons APIs instead.

Parameters:
- `skip` [query, integer] — Skip first number of items (0-1000). To iterate over more than 1000 items,  use "cursor". Example: "150".
- `limit` [query, integer] — Limit number of returned items (1-1000). Example: "10".
- `cursor` [query, string] — Cursor position returned by the last request. Use to iterate over more than 1000 items. Example: "YWdlbnRfaWQ6NTgwMjkzODE=".
- `countOnly` [query, boolean] — If true, only total number of items will be returned, without any of the actual objects.
- `skipCount` [query, boolean] — If true, total number of items will not be calculated, which speeds up execution time.
- `sortBy` [query, string] (enum: siteName, activeAgents, rangerProEnabled, roguesEnabled, rangerEnabled) — The column to sort the results by. Example: "id".
- `sortOrder` [query, string] (enum: asc, desc) — Sort direction. Example: "asc".
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "225494730938493804,225494730938493915".
- `siteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `groupIds` [query, array] — List of Group IDs to filter by. Example: "225494730938493804,225494730938493915".
- `tenant` [query, boolean] — Indicates a tenant scope request
- `id` [query, string] — The enablement id. Example: "225494730938493804".
- `activeAgents` [query, integer] — The number of non-decommissioned agents in the site
- `rangerProEnabled` [query, boolean] — [DEPRECATED]. Use rangerEnabled instead. Network Discovery Pro Enabled true/false
- `rangerEnabled` [query, boolean] — Network Discovery Enabled true/false
- `roguesEnabled` [query, boolean] — Unprotected Endpoints Discovery Enabled true/false
- `activeAgents__lt` [query, integer] — Agent count (less than)
- `activeAgents__lte` [query, integer] — Agent count (less than or equal)
- `activeAgents__gt` [query, integer] — Agent count (more than)
- `activeAgents__gte` [query, integer] — Agent count (more than or equal)
- `activeAgents__between` [query, string] — Agent count (between). Example: "2-8".
- `siteName` [query, string] — The site name
- `ids` [query, array] — A list of ids to get. Example: "225494730938493804,225494730938493915".
- `siteName__contains` [query, array] — Free-text filter by site name (supports multiple values)

Responses: 404 , 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/ranger/enablement`
**Change Network Discovery or Unprotected Endpoints Discovery Features**
`operationId`: `_web_api_ranger_enablement_post`

[DEPRECATED] Use the Update Account, Get Account, Get Sites, or the Update Site Add-ons APIs instead.

Parameters:
- `body` [body, ranger.enablement.schemas_UpdateSelfEnablementFeaturesSchema] — 

Responses: 404 , 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/ranger/enablement/defaults`
**Features Configuration for New Sites**
`operationId`: `_web_api_ranger_enablement_defaults_get`

[DEPRECATED] Use the Update Account, Get Account, Get Sites, or the Update Site Add-ons APIs instead..

Parameters:
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "225494730938493804,225494730938493915".

Responses: 404 , 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/ranger/enablement/defaults`
**Change Feature Defaults for New Sites**
`operationId`: `_web_api_ranger_enablement_defaults_post`

[DEPRECATED] Use the Update Account, Get Account, Get Sites, or the Update Site Add-ons APIs instead.

Parameters:
- `body` [body, ranger.enablement.schemas_UpdateSelfEnablementFeaturesSchema] — 

Responses: 404 , 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.
