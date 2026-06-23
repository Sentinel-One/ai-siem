# Tag Manager

3 endpoints.

## `DELETE /web/api/v2.1/tag-manager`
**Delete tags**
`operationId`: `_web_api_tag-manager_delete`

Delete all tags that match the filters.

Required permissions: `Tag Management.delete`

Parameters:
- `body` [body, v2_1.mgmt_tag_manager.schemas_TagsDeleteSchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/tag-manager`
**Create a new endpoint tag**
`operationId`: `_web_api_tag-manager_post`

Each tag must contain a type (endpoints) and key, Value is optional but recommended. A description is optional.

Required permissions: `Tag Management.create`

Parameters:
- `body` [body, v2_1.mgmt_tag_manager.schemas_PostTagSchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `PUT /web/api/v2.1/tag-manager/{tag_id}`
**Edit an existing tag**
`operationId`: `_web_api_tag-manager_{tag_id}_put`

Change the key, value, or description of a tag.

Required permissions: `Tag Management.edit`

Parameters:
- `tag_id` [path, string] **required** — Tag ID. You can get the ID from the Get Tag-Manager command. Example: "225494730938493804".
- `body` [body, v2_1.mgmt_tag_manager.schemas_PutTagSchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.
