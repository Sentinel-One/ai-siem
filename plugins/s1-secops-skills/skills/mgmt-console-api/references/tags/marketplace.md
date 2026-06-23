# marketplace

9 endpoints.

## `DELETE /web/api/v2.1/singularity-marketplace/applications`
**Delete Application**
`operationId`: `_web_api_singularity-marketplace_applications_delete`

Delete application integration from your Marketplace.

Required permissions: `Singularity Marketplace.manage`

Parameters:
- `body` [body, DeleteApplicationRequest] **required** — 

Responses: 200 OK

## `GET /web/api/v2.1/singularity-marketplace/applications`
**Get Installed Applications**
`operationId`: `_web_api_singularity-marketplace_applications_get`

Get the installed Marketplace applications for a scope specified.

Required permissions: `Singularity Marketplace.view`

Parameters:
- `applicationCatalogId` [query, string] — Filter results by application catalog id. Example: "225494730938493804,225494730938493915".
- `id` [query, string] — A list of applications IDs. Example: "225494730938493804,225494730938493915".
- `name__contains` [query, string] — Free-text filter by application name (supports multiple values). Example: "Service Pack 1".
- `creator__contains` [query, string] — Free-text filter by application creator (supports multiple values). Example: "Service Pack 1".
- `query` [query, string] — Free-text filter to match name or creator.
- `accountIds` [query, string] — Filter results by account id. Example: "225494730938493804,225494730938493915".
- `siteIds` [query, string] — Filter results by site id. Example: "225494730938493804,225494730938493915".
- `cursor` [query, string] — Cursor position returned by the last request.
- `limit` [query, string] — Limit number of returned items (1-1000). Example: "10".
- `countOnly` [query, string] — If true, only the number of items will be returned.
- `disablePagination` [query, string] — If true, pagination will be disabled.
- `sortBy` [query, string] — The column to sort the results by. Example: "id".
- `sortOrder` [query, string] — Sort direction (asc/desc). Example: "asc".

Responses: 200 OK

## `POST /web/api/v2.1/singularity-marketplace/applications`
**Install Applications**
`operationId`: `_web_api_singularity-marketplace_applications_post`

Install application from the Application Catalog.

Required permissions: `Singularity Marketplace.manage`

Parameters:
- `body` [body, InstallationRequest] **required** — 

Responses: 200 OK

## `PUT /web/api/v2.1/singularity-marketplace/applications`
**Update Application Configuration**
`operationId`: `_web_api_singularity-marketplace_applications_put`

Update installed application configuration.

Required permissions: `Singularity Marketplace.manage`

Parameters:
- `body` [body, UpdateConfigurationRequest] **required** — 

Responses: 200 OK

## `GET /web/api/v2.1/singularity-marketplace/applications-catalog`
**Get Applications Catalog**
`operationId`: `_web_api_singularity-marketplace_applications-catalog_get`

Get the Marketplace Application Catalog.

Required permissions: `Singularity Marketplace.view`

Parameters:
- `id` [query, string] — Filter results by application catalog id. Example: "225494730938493804,225494730938493915".
- `category__contains` [query, string] — Free-text filter by catalog application category (supports multiple values). Example: "Service Pack 1".
- `name__contains` [query, string] — Free-text filter by catalog application name (supports multiple values). Example: "Service Pack 1".
- `description__contains` [query, string] — Free-text filter by catalog application description (supports multiple values). Example: "Service Pack 1".
- `query` [query, string] — Free-text filter to match name, description or category.
- `categoryIds` [query, string] — Filter results by application catalog category id. Example: "225494730938493804,225494730938493915".
- `cursor` [query, string] — Cursor position returned by the last request.
- `limit` [query, string] — Limit number of returned items (1-1000). Example: "10".
- `sortBy` [query, string] — The column to sort the results by. Example: "id".
- `sortOrder` [query, string] — Sort direction (asc/desc). Example: "asc".

Responses: 200 OK

## `GET /web/api/v2.1/singularity-marketplace/applications-catalog/{applicationCatalogId}/config`
**Get Configuration Fields**
`operationId`: `_web_api_singularity-marketplace_applications-catalog_{applicationCatalogId}_config_get`

Get the Configuration Fields of the Catalog Application.

Required permissions: `Singularity Marketplace.view`

Parameters:
- `applicationCatalogId` [path, string] **required** — 

Responses: 200 OK

## `GET /web/api/v2.1/singularity-marketplace/applications/{applicationId}/config`
**Get Configuration Fields For Installed Application**
`operationId`: `_web_api_singularity-marketplace_applications_{applicationId}_config_get`

Get the Catalog Application Configuration Fields.

Required permissions: `Singularity Marketplace.view`

Parameters:
- `applicationId` [path, string] **required** — 

Responses: 200 OK

## `POST /web/api/v2.1/singularity-marketplace/applications/{applicationMode}`
**Enable Or Disable Application**
`operationId`: `_web_api_singularity-marketplace_applications_{applicationMode}_post`

Use this command to enable or disable application integrations that match the filter.

Required permissions: `Singularity Marketplace.manage`

Parameters:
- `applicationMode` [path, string] **required** (enum: enable, disable) — 
- `body` [body, SwitchApplicationModeRequest] **required** — 

Responses: 200 OK

## `GET /web/api/v2.1/singularity-marketplace/applications/{id}/log`
**Get application log**
`operationId`: `_web_api_singularity-marketplace_applications_{id}_log_get`

Returns application invocation log.

Required permissions: `Singularity Marketplace.view`

Parameters:
- `id` [path, string] **required** — Application ID
- `only_errors` [query, string] — If true, only logs with error status ('Failure' or 'Retry') will be returned

Responses: 200 OK
