# Saved Searches

3 endpoints.

## `GET /sdl/v2/api/saved-searches`
**List saved searches**
`operationId`: `_sdl_v2_api_saved-searches_get`

Retrieves all saved searches visible to the current user. Saved searches allow you to persist and quickly access frequently used search queries in Event Search. Use the `type` parameter to filter by PRIVATE (user-specific) or SHARED (visible to all users in the scope) searches.

Required permissions: `SDL Search (Previously Skylight).create, SDL Search (Previously Skylight).edit, SDL Search (Previously Skylight).delete`

Parameters:
- `type` [query, string] (enum: PRIVATE, SHARED) — Filter by search type. PRIVATE searches are visible only to you, while SHARED searches are visible to all users in your current scope. Defaults to PRIVATE if not specified.

Responses: 200 List of saved searches retrieved successfully., 401 Unauthorized. Authentication is required., 403 Forbidden. User does not have permission to manage searches.

## `PUT /sdl/v2/api/saved-searches`
**Create or update saved searches**
`operationId`: `_sdl_v2_api_saved-searches_put`

Create or update multiple saved searches in a single request. This endpoint allows you to save up to 100 searches at once. When a search with the same name already exists in the target scope, the `duplicateStrategy` parameter controls the behavior: NEW_ONLY (default) skips duplicates, REPLACE overwrites existing searches, or APPEND_SUFFIX creates new searches with numeric suffixes (e.g., 'My Search (2)'). You can change the active scope using the `S1-Scope` header to manage SHARED searches in different scopes.

Note: A `teamToken` query parameter will be automatically added to each search URL if it is not already present. This token ensures the searches are scoped correctly.

Required permissions: `SDL Search (Previously Skylight).create, SDL Search (Previously Skylight).edit, SDL Search (Previously Skylight).delete`

Parameters:
- `body` [body, v2_1.saved_searches.schemas_BatchUpsertRequest] **required** — List of saved searches to create or update, along with the duplicate handling strategy.

Responses: 200 All searches were processed successfully. This includes sear, 207 Partial success. Some searches were saved successfully, but , 400 Invalid request. The request body is malformed or contains i, 401 Authentication required. Please provide valid credentials., 403 Permission denied. You do not have the required permissions , 500 Internal server error. All searches failed to save due to a 

## `POST /sdl/v2/api/saved-searches/batch-delete`
**Delete saved searches**
`operationId`: `_sdl_v2_api_saved-searches_batch-delete_post`

Delete multiple saved searches in a single request. You can delete up to 100 searches at once by providing their names and types. Each search name must be unique within its type (PRIVATE or SHARED) and scope. Use the `S1-Scope` header to target SHARED searches in specific scopes.

Required permissions: `SDL Search (Previously Skylight).create, SDL Search (Previously Skylight).edit, SDL Search (Previously Skylight).delete`

Parameters:
- `body` [body, v2_1.saved_searches.schemas_BatchDeleteRequest] **required** — List of saved searches to delete, identified by name and type.

Responses: 200 All searches were deleted successfully., 207 Partial success. Some searches were deleted successfully, bu, 400 Invalid request. The request body is malformed or contains i, 401 Authentication required. Please provide valid credentials., 403 Permission denied. You do not have the required permissions , 500 Internal server error. All searches failed to delete due to 
