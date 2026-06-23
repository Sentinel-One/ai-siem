# Tags

5 endpoints.

## `DELETE /web/api/v2.1/tags`
**Delete Tags**
`operationId`: `_web_api_tags_delete`

Delete tags by given filter.
Optional permissions: `Firewall Control.manageRulesAndTags, Network Quarantine Control.manageRulesAndTags, Ranger.manageDeviceTags`

Parameters:
- `body` [body, tags.schemas_TagDeleteSchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/tags`
**Get Tags**
`operationId`: `_web_api_tags_get`

Get tags.
Optional permissions: `Firewall Control.view, Network Quarantine Control.view, Ranger.view`

Parameters:
- `skip` [query, integer] — Skip first number of items (0-1000). To iterate over more than 1000 items,  use "cursor". Example: "150".
- `limit` [query, integer] — Limit number of returned items (1-1000). Example: "10".
- `cursor` [query, string] — Cursor position returned by the last request. Use to iterate over more than 1000 items. Example: "YWdlbnRfaWQ6NTgwMjkzODE=".
- `countOnly` [query, boolean] — If true, only total number of items will be returned, without any of the actual objects.
- `skipCount` [query, boolean] — If true, total number of items will not be calculated, which speeds up execution time.
- `sortBy` [query, string] (enum: id, type, scope, query) — The column to sort the results by. Example: "id".
- `sortOrder` [query, string] (enum: asc, desc) — Sort direction. Example: "asc".
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "225494730938493804,225494730938493915".
- `siteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `groupIds` [query, array] — List of Group IDs to filter by. Example: "225494730938493804,225494730938493915".
- `tenant` [query, boolean] — Indicates a tenant scope request
- `ids` [query, array] — List of IDs to filter by. Example: "225494730938493804,225494730938493915".
- `query` [query, string] — Free text search on tag name
- `type` [query, array] **required** — Type in. Example: "firewall".
- `scope` [query, string] (enum: site, global, account, group) — Return tags from given scope level. Example: "site".
- `name__contains` [query, array] — Free-text filter by tag name. Example: "tag_name,tag_na".
- `onlyParents` [query, boolean] — If true returns all tags possible to inherit from parent scopes, otherwise returns all tags already inherited and tags from this scope.
- `kind` [query, string] — Returns tags of this specific kind
- `disablePagination` [query, boolean] — If true, all tags for requested filters will be returned

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/tags`
**Create Tags**
`operationId`: `_web_api_tags_post`

Add tags to create user-defined logical groups.
Optional permissions: `Firewall Control.manageRulesAndTags, Network Quarantine Control.manageRulesAndTags, Ranger.manageDeviceTags`

Parameters:
- `body` [body, tags.schemas_PostTagSchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `DELETE /web/api/v2.1/tags/{tag_id}`
**Delete Tag by ID**
`operationId`: `_web_api_tags_{tag_id}_delete`

Delete tag by ID.
Optional permissions: `Firewall Control.manageRulesAndTags, Network Quarantine Control.manageRulesAndTags, Ranger.manageDeviceTags`

Parameters:
- `tag_id` [path, string] **required** — Rule ID. Example: "225494730938493804".

Responses: 200 Success, 401 Unauthorized access - please sign in and retry.

## `PUT /web/api/v2.1/tags/{tag_id}`
**Edit Tag**
`operationId`: `_web_api_tags_{tag_id}_put`

Edit tag
Optional permissions: `Firewall Control.manageRulesAndTags, Network Quarantine Control.manageRulesAndTags, Ranger.manageDeviceTags`

Parameters:
- `tag_id` [path, string] **required** — Rule ID. Example: "225494730938493804".
- `body` [body, tags.schemas_PutTagSchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.
