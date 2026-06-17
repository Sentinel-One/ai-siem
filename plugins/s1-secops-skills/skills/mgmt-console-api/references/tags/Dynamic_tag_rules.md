# Dynamic tag rules

5 endpoints.

## `DELETE /web/api/v2.1/xdr/assets/tags/rules`
**Delete tag rules**
`operationId`: `_web_api_xdr_assets_tags_rules_delete`

Delete tag rules

Required permissions: `XDR Inventory.delete`

Parameters:
- `accountIds` [query, array] — List of Account IDs to filter by
- `siteIds` [query, array] — List of Site IDs to filter by
- `ids` [query, array] — The list of tag rule ID identifiers to be removed.
- `groupIds` [query, array] — List of Group IDs to filter by

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/xdr/assets/tags/rules`
**Get all tags rules**
`operationId`: `_web_api_xdr_assets_tags_rules_get`

Get all tags rules

Required permissions: `XDR Inventory.view`

Parameters:
- `createdByEmail` [query, array] — Filter by created by emails of the tag rules.
- `tagIds` [query, array] — The list of tag identifiers that the rule is associated with.
- `sortOrder` [query, string] (enum: asc, desc) — Sort direction
- `createdByEmail__nin` [query, array] — Negative filter by created by emails of the tag rules.
- `status` [query, string] (enum: enabled, disabled) — Status
- `name` [query, array] — Filter by names of the tag rules.
- `countOnly` [query, boolean] — If true, only total number of items will be returned, without any of the actual objects.
- `updatedByEmail__nin` [query, array] — Negative filter by updated by emails of the tag rules.
- `accountIds` [query, array] — List of Account IDs to filter by
- `limit` [query, integer] — Limit number of returned items (1-1000)
- `description` [query, array] — Filter by description of the tag rules.
- `skipCount` [query, boolean] — If true, total number of items will not be calculated, which speeds up execution time.
- `skip` [query, integer] — Skip first number of items (0-1000). To iterate over more than 1000 items,  use "cursor".
- `name__nin` [query, array] — Negative filter by names of the tag rules.
- `groupIds` [query, array] — List of Group IDs to filter by
- `description__nin` [query, array] — Negative filter by descriptions of the tag rules.
- `updatedByEmail` [query, array] — Filter by updated by emails of the tag rules.
- `siteIds` [query, array] — List of Site IDs to filter by
- `ids` [query, array] — The list of tag rule ID identifiers.
- `cursor` [query, string] — Cursor position returned by the last request. Use to iterate over more than 1000 items.
- `sortBy` [query, string] (enum: id, name, status, createdBy, createdByEmail, createdAt, updatedBy, updatedByEmail, updatedAt) — The column to sort the results by.

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/xdr/assets/tags/rules`
**Create new tag rule**
`operationId`: `_web_api_xdr_assets_tags_rules_post`

Create new tag rule

Required permissions: `XDR Inventory.create`

Parameters:
- `accountIds` [query, array] — List of Account IDs to filter by
- `siteIds` [query, array] — List of Site IDs to filter by
- `groupIds` [query, array] — List of Group IDs to filter by
- `body` [body, v2_1.inventory.tags.rules.schemas_TagRuleSchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `PUT /web/api/v2.1/xdr/assets/tags/rules`
**Update tag rule**
`operationId`: `_web_api_xdr_assets_tags_rules_put`

Update tag rule

Required permissions: `XDR Inventory.edit`

Parameters:
- `accountIds` [query, array] — List of Account IDs to filter by
- `siteIds` [query, array] — List of Site IDs to filter by
- `groupIds` [query, array] — List of Group IDs to filter by
- `body` [body, v2_1.inventory.tags.rules.schemas_TagRuleSchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/xdr/assets/tags/rules/test`
**Check how many assets this tag rule matches**
`operationId`: `_web_api_xdr_assets_tags_rules_test_post`

Check how many assets this tag rule matches

Required permissions: `XDR Inventory.view`

Parameters:
- `skip` [query, integer] — Skip first number of items (0-1000). To iterate over more than 1000 items,  use "cursor".
- `groupIds` [query, array] — List of Group IDs to filter by
- `sortOrder` [query, string] (enum: asc, desc) — Sort direction
- `accountIds` [query, array] — List of Account IDs to filter by
- `limit` [query, integer] — Limit number of returned items (1-1000)
- `countOnly` [query, boolean] — If true, only total number of items will be returned, without any of the actual objects.
- `siteIds` [query, array] — List of Site IDs to filter by
- `cursor` [query, string] — Cursor position returned by the last request. Use to iterate over more than 1000 items.
- `skipCount` [query, boolean] — If true, total number of items will not be calculated, which speeds up execution time.
- `sortBy` [query, string] (enum: s1UpdatedAt, name) — The column to sort the results by.
- `body` [body, v2_1.inventory.tags.rules.schemas_TagRuleSchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.
