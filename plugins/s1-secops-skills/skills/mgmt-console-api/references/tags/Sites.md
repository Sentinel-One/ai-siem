# Sites

17 endpoints.

## `GET /web/api/v2.1/export/sites`
**Export Sites**
`operationId`: `_web_api_export_sites_get`

Export Sites data to a CSV, for Sites that match the filter.

Required permissions: `Sites.view`

Parameters:
- `siteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "225494730938493804,225494730938493915".
- `query` [query, string] — Full text search for fields: name, account_name, description. (Note: on single-account consoles account name will not be matched)
- `name` [query, string] — Name. Example: "My Site".
- `isDefault` [query, boolean] — Is default
- `healthStatus` [query, boolean] — Health status
- `siteType` [query, string] (enum: Trial, Paid) — Site type. Example: "Trial".
- `expiration` [query, string] — Expiration. Example: "2018-02-27T04:49:26.257525Z".
- `totalLicenses` [query, integer] — Total licenses
- `activeLicenses` [query, integer] — Active licenses
- `externalId` [query, string] — Id in a CRM external system
- `description` [query, string] — The description for the Site
- `createdAt` [query, string] — Timestamp of site creation. Example: "2018-02-27T04:49:26.257525Z".
- `updatedAt` [query, string] — Timestamp of last update. Example: "2018-02-27T04:49:26.257525Z".
- `state` [query, string] (enum: active, expired, deleted) — Site state. Example: "active".
- `states` [query, array] — List of states to filter
- `statesNin` [query, array] — List of states to not filter
- `suite` [query, string] (enum: Core, Control, Complete) — [DEPRECATED] Use sku instead. Example: "Core".
- `features` [query, array] — If sent return only sites that support this features. Example: "firewall-control".
- `sku` [query, string] — Sku. Example: "core".
- `module` [query, string] — Module. Example: "star,rso".
- `accountId` [query, string] — Account id. Example: "225494730938493804".
- `adminOnly` [query, boolean] — [DEPRECATED] Show sites the user has Admin privileges to
- `availableMoveSites` [query, boolean] — Only return sites the user can move agents to
- `registrationToken` [query, string] — Registration token. Example: "eyJ1cmwiOiAiaHR0cHM6Ly9jb25zb2xlLnNlbnRpbmVsb25lLm5ldCIsICJzaXRlX2tleSI6ICIwNzhkYjliMWUyOTA1Y2NhIn0=".
- `accountName__contains` [query, array] — Free-text filter by account name (supports multiple values)
- `name__contains` [query, array] — Free-text filter by site name (supports multiple values)
- `description__contains` [query, array] — Free-text filter by site description (supports multiple values)

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/site-with-admin`
**Create Site and User**
`operationId`: `_web_api_site-with-admin_post`

Create a Site and an Admin role user. This requires an Admin role with a Global scope or Account scope that has permissions over the Account to which the Site will belong. <br>You must have a license for a new Site. <br>In the body of this request, include the policy and user properties.

Required permissions: `Sites.create`

Parameters:
- `body` [body, sites_SiteDataWithUserSchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/sites`
**Get Sites**
`operationId`: `_web_api_sites_get`

Get the Sites that match the filters. <br>The response includes the IDs of Sites, which you can use in other commands.

Required permissions: `Sites.view`
Optional permissions: `Endpoints.moveToAnotherSite`

Parameters:
- `skip` [query, integer] — Skip first number of items (0-1000). To iterate over more than 1000 items,  use "cursor". Example: "150".
- `limit` [query, integer] — Limit number of returned items (1-1000). Example: "10".
- `cursor` [query, string] — Cursor position returned by the last request. Use to iterate over more than 1000 items. Example: "YWdlbnRfaWQ6NTgwMjkzODE=".
- `countOnly` [query, boolean] — If true, only total number of items will be returned, without any of the actual objects.
- `skipCount` [query, boolean] — If true, total number of items will not be calculated, which speeds up execution time.
- `sortBy` [query, string] (enum: id, name, totalLicenses, expiration, siteType, state, suite, createdAt, updatedAt, activeLicenses, accountName, sku, description, usageType) — The column to sort the results by. Example: "id".
- `sortOrder` [query, string] (enum: asc, desc) — Sort direction. Example: "asc".
- `siteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "225494730938493804,225494730938493915".
- `query` [query, string] — Full text search for fields: name, account_name, description. (Note: on single-account consoles account name will not be matched)
- `name` [query, string] — Name. Example: "My Site".
- `isDefault` [query, boolean] — Is default
- `healthStatus` [query, boolean] — Health status
- `siteType` [query, string] (enum: Trial, Paid) — Site type. Example: "Trial".
- `expiration` [query, string] — Expiration. Example: "2018-02-27T04:49:26.257525Z".
- `totalLicenses` [query, integer] — Total licenses
- `activeLicenses` [query, integer] — Active licenses
- `externalId` [query, string] — Id in a CRM external system
- `description` [query, string] — The description for the Site
- `createdAt` [query, string] — Timestamp of site creation. Example: "2018-02-27T04:49:26.257525Z".
- `updatedAt` [query, string] — Timestamp of last update. Example: "2018-02-27T04:49:26.257525Z".
- `state` [query, string] (enum: active, expired, deleted) — Site state. Example: "active".
- `states` [query, array] — List of states to filter
- `statesNin` [query, array] — List of states to not filter
- `suite` [query, string] (enum: Core, Control, Complete) — [DEPRECATED] Use sku instead. Example: "Core".
- `features` [query, array] — If sent return only sites that support this features. Example: "firewall-control".
- `sku` [query, string] — Sku. Example: "core".
- `module` [query, string] — Module. Example: "star,rso".
- `accountId` [query, string] — Account id. Example: "225494730938493804".
- `adminOnly` [query, boolean] — [DEPRECATED] Show sites the user has Admin privileges to
- `availableMoveSites` [query, boolean] — Only return sites the user can move agents to
- `registrationToken` [query, string] — Registration token. Example: "eyJ1cmwiOiAiaHR0cHM6Ly9jb25zb2xlLnNlbnRpbmVsb25lLm5ldCIsICJzaXRlX2tleSI6ICIwNzhkYjliMWUyOTA1Y2NhIn0=".
- `accountName__contains` [query, array] — Free-text filter by account name (supports multiple values)
- `name__contains` [query, array] — Free-text filter by site name (supports multiple values)
- `description__contains` [query, array] — Free-text filter by site description (supports multiple values)

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/sites`
**Create Site**
`operationId`: `_web_api_sites_post`

Create a Site. This requires an Admin role with a Global scope or Account scope that has permissions over the Account to which the Site will belong. <br>You must have a license for a new Site. <br>In the body of this request, include the policy.

Required permissions: `Sites.create`

Parameters:
- `body` [body, sites_PostSiteSchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/sites/duplicate-site`
**Create duplicate site**
`operationId`: `_web_api_sites_duplicate-site_post`

[DEPRECATED] Create duplicate site.

Required permissions: `Sites.create`

Parameters:
- `body` [body, sites_DuplicateSiteSchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `PUT /web/api/v2.1/sites/update-bulk`
**Update Sites**
`operationId`: `_web_api_sites_update-bulk_put`

Change the properties of the Sites given by IDs. <br>To get the IDs, run 'sites'.

Required permissions: `Sites.edit`

Parameters:
- `body` [body, sites_SiteBulkPutSchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `DELETE /web/api/v2.1/sites/{site_id}`
**Delete Site**
`operationId`: `_web_api_sites_{site_id}_delete`

Delete the Site of the given ID. To get the ID, run "sites". <br>You must have an Admin role with scope access that includes the Site.

Required permissions: `Sites.delete`

Parameters:
- `site_id` [path, string] **required** — Site ID. Example: "225494730938493804".

Responses: 200 Success, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/sites/{site_id}`
**Get Site by ID**
`operationId`: `_web_api_sites_{site_id}_get`

Get the data of the Site of the ID. To get the ID, run "sites". <br>The response shows the Site expiration date, SKU, licenses (total and active), token, Account name and ID, who and when it was created and changed, and its status.

Required permissions: `Sites.view`

Parameters:
- `site_id` [path, string] **required** — Site ID. Example: "225494730938493804".

Responses: 404 Site not found, 200 Success, 401 Unauthorized access - please sign in and retry.

## `PUT /web/api/v2.1/sites/{site_id}`
**Update Site**
`operationId`: `_web_api_sites_{site_id}_put`

Change the policy and properties of the Site given by ID. <br>To get the ID, run 'sites'.

Required permissions: `Sites.edit`

Parameters:
- `site_id` [path, string] **required** — Site ID. Example: "225494730938493804".
- `body` [body, sites_SitePutSchema] — 

Responses: 404 Site not found, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/sites/{site_id}/expire-now`
**Expire Site**
`operationId`: `_web_api_sites_{site_id}_expire-now_post`

Expire the Site of the given ID (run "sites" to get the ID). <br>You must have an Admin role with scope access that includes this Site.

Required permissions: `Sites.edit`

Parameters:
- `site_id` [path, string] **required** — Site ID. Example: "225494730938493804".

Responses: 404 Site not found, 200 Expire site now, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/sites/{site_id}/local-authorization`
**Get local upgrade/downgrade Site authorization**
`operationId`: `_web_api_sites_{site_id}_local-authorization_get`

Get the time when authorization of local upgrades/downgrades expires, and the number of Agents authorized for local upgrades/downgrades, in this Site.

Required permissions: `Local Upgrade/Downgrade Authorization.view`

Parameters:
- `site_id` [path, string] **required** — Site ID. Example: "225494730938493804".

Responses: 200 Success, 401 Unauthorized access - please sign in and retry.

## `PUT /web/api/v2.1/sites/{site_id}/local-authorization`
**Edit local upgrade/downgrade Site authorization**
`operationId`: `_web_api_sites_{site_id}_local-authorization_put`

Edit when authorization of local upgrades/downgrades expires. Returns the number of Agents authorized for local upgrades/downgrades, in this Site.

Required permissions: `Local Upgrade/Downgrade Authorization.edit`

Parameters:
- `site_id` [path, string] **required** — Site ID. Example: "225494730938493804".
- `body` [body, sites_PutSiteApprovalJsonSchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/sites/{site_id}/local-upgrade-approved-agents-csv`
**Get a CSV file of local upgrade/downgrade Site authorization data**
`operationId`: `_web_api_sites_{site_id}_local-upgrade-approved-agents-csv_get`

Get a CSV file containing the Agents authorized for local upgrades/downgrades, in this Site.

Required permissions: `Local Upgrade/Downgrade Authorization.view`

Parameters:
- `site_id` [path, string] **required** — Site ID. Example: "225494730938493804".

Responses: 200 Success, 401 Unauthorized access - please sign in and retry.

## `PUT /web/api/v2.1/sites/{site_id}/reactivate`
**Reactivate Site**
`operationId`: `_web_api_sites_{site_id}_reactivate_put`

Reactivate an expired Site. <br>You must have an Admin role with scope access that includes this Site, and you must have a license for the Site. <br>To get the site_id, run "sites".

Required permissions: `Sites.edit`

Parameters:
- `site_id` [path, string] **required** — Site ID. Example: "225494730938493804".
- `body` [body, sites_ReactivateSiteSchema] — 

Responses: 404 Site not found, 200 Site reactivated, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `PUT /web/api/v2.1/sites/{site_id}/regenerate-key`
**Regenerate Site Key**
`operationId`: `_web_api_sites_{site_id}_regenerate-key_put`

Regenerate the key for the given Site. <br>To get the site_id, use "sites".

Required permissions: `Sites.edit`

Parameters:
- `site_id` [path, string] **required** — Site ID. Example: "225494730938493804".

Responses: 403 No permission for regenerating a key., 404 Site not found, 200 Success, 401 Unauthorized access - please sign in and retry.

## `PUT /web/api/v2.1/sites/{site_id}/revert-policy`
**Revert Policy**
`operationId`: `_web_api_sites_{site_id}_revert-policy_put`

When a Site is created through the Console, it gets the Global policy. <br>If you change the policy and later want it set to the Global policy, use this command. <br>The site_id is required. You can get it from "sites".

Required permissions: `Policy.edit`

Parameters:
- `site_id` [path, string] **required** — Site ID. Example: "225494730938493804".
- `body` [body, policies_schemas_RevertPolicySchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/sites/{site_id}/token`
**Get Site registration token by ID**
`operationId`: `_web_api_sites_{site_id}_token_get`

Get the registration token of the Site of the ID.

Required permissions: `Sites.view`

Parameters:
- `site_id` [path, string] **required** — Site ID. Example: "225494730938493804".

Responses: 404 Site not found, 200 Success, 401 Unauthorized access - please sign in and retry.
