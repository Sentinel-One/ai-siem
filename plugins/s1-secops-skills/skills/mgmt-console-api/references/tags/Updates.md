# Updates

9 endpoints.

## `GET /web/api/v2.1/update/agent/download/{package_id}`
**Download Agent Package**
`operationId`: `_web_api_update_agent_download_{package_id}_get`

[DEPRECATED] Download an agent package by package ID.Rate limit: 2 call per minute for each different user token

Required permissions: `Packages.view`

Parameters:
- `package_id` [path, string] **required** — Package ID. Example: "225494730938493804".

Responses: 404 Package not found, 200 Success, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/update/agent/download/{site_id}/{package_id}`
**Download Package**
`operationId`: `_web_api_update_agent_download_{site_id}_{package_id}_get`

Download a package by site_id ("sites") and filename. <br>Rate limit: 2 call per minute for each user token. <br>Use this command to manually deploy Agent updates that cannot be deployed with the update-software command (see Agent Actions > Update Software) or through the Console.

Required permissions: `Packages.view`

Parameters:
- `package_id` [path, string] **required** — Package ID. Example: "225494730938493804".
- `site_id` [path, string] **required** — Site ID. Example: "225494730938493804".

Responses: 404 Package not found or bad site, 200 Success, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/update/agent/latest-packages`
**Latest Packages by OS**
`operationId`: `_web_api_update_agent_latest-packages_get`

[DEPRECATED] Use "Latest packages" API call instead ("GET /web/api/v2.1/update/agent/packages").

Required permissions: `Packages.view`

Parameters:
- `siteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "225494730938493804,225494730938493915".
- `packageType` [query, string] (enum: Agent, Ranger, AgentAndRanger) — Package type. Example: "Agent".

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `DELETE /web/api/v2.1/update/agent/packages`
**Delete Packages**
`operationId`: `_web_api_update_agent_packages_delete`

Delete Agent packages from your Management. Use the IDs from Get Latest Packages.

Required permissions: `Packages.delete`

Parameters:
- `body` [body, packages.schemas_DeletePackagesSchema] — 

Responses: 403 Insufficient permissions, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/update/agent/packages`
**Get Latest Packages**
`operationId`: `_web_api_update_agent_packages_get`

Get the Agent packages that are uploaded to your Management. <br>The response shows the data of each package, including the IDs, which you can use in other commands.

Required permissions: `Packages.view`

Parameters:
- `skip` [query, integer] — Skip first number of items (0-1000). To iterate over more than 1000 items,  use "cursor". Example: "150".
- `limit` [query, integer] — Limit number of returned items (1-1000). Example: "10".
- `cursor` [query, string] — Cursor position returned by the last request. Use to iterate over more than 1000 items. Example: "YWdlbnRfaWQ6NTgwMjkzODE=".
- `countOnly` [query, boolean] — If true, only total number of items will be returned, without any of the actual objects.
- `skipCount` [query, boolean] — If true, total number of items will not be calculated, which speeds up execution time.
- `sortBy` [query, string] (enum: id, createdAt, updatedAt, osType, platformType, fileName, fileSize, fileExtension, version, status, majorVersion, minorVersion, sha1, scopeLevel, accessLevel, packageType, rangerVersion, osArch) — The column to sort the results by. Example: "id".
- `sortOrder` [query, string] (enum: asc, desc) — Sort direction. Example: "asc".
- `fileName__contains` [query, array] — Free-text filter by file name
- `fileSize__contains` [query, array] — Free-text filter by file size
- `versionStr__contains` [query, array] — Free-text filter by version string
- `rangerVersion__contains` [query, array] — Free-text filter by Network Scanner version
- `sha1__contains` [query, array] — Free-text filter by SHA1 hash
- `siteName__contains` [query, array] — Free-text filter by site name
- `accountName__contains` [query, array] — Free-text filter by account name
- `siteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "225494730938493804,225494730938493915".
- `query` [query, string] — A free-text search term, will match applicable attributes
- `ids` [query, array] — Package ID list. Example: "225494730938493804,225494730938493915".
- `osTypes` [query, array] — Os type in. Example: "macos".
- `platformType` [query, string] (enum: macos, windows, linux_k8s, linux, sdk, windows_legacy, threat_detection_s3, threat_detection_netapp) — Platform type. Example: "macos".
- `platformTypes` [query, array] — Platform type in. Example: "macos".
- `status` [query, array] — Status in. Example: "beta".
- `osArches` [query, array] — Package OS architecture (32/64 bit), applicable to Windows packages only. Example: "64 bit".
- `fileExtension` [query, string] (enum: .msi, .exe, .deb, .rpm, .bsx, .pkg, .img, unknown, .tar, .zip, .gz, .xz) — File extension. Example: ".msi".
- `fileExtensions` [query, array] — File extension. Example: ".msi".
- `version` [query, string] — Agent version. Example: "2.5.1.1320".
- `majorVersions` [query, array] — Package major versions
- `minorVersions` [query, array] — Package minor versions
- `minorVersion` [query, string] — Package minor version
- `sha1` [query, string] — Package hash. Example: "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12".
- `rangerVersion` [query, string] — Network Scanner version. Example: "2.5.1.1320".
- `packageType` [query, string] (enum: Agent, Ranger, AgentAndRanger) — Package type. Example: "Agent".
- `packageTypes` [query, array] — Package type in. Example: "Agent".
- `osRevision` [query, string] — Agent os revision

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `PUT /web/api/v2.1/update/agent/packages/{package_id}`
**Update package**
`operationId`: `_web_api_update_agent_packages_{package_id}_put`

Update the metadata for an existing package.

Required permissions: `Packages.edit`

Parameters:
- `package_id` [path, string] **required** — Package ID. Example: "225494730938493804".
- `body` [body, packages.schemas_PutPackageSchema] — 

Responses: 404 Package not found, 403 Insufficient permissions, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/upload/agent/software`
**Upload Agent Package**
`operationId`: `_web_api_upload_agent_software_post`

If you have an On-Prem Management or you are a participant in the Beta program, you can use this command to upload an Agent package to the Management. Then you can deploy the Agent to update endpoints.

Required permissions: `Packages.edit`

Parameters:
- `siteIds` [formData, array] — List of sites to make the package available in. Applicable only if scopeLevel is set to "site". Example: "225494730938493804,225494730938493915".
- `accountIds` [formData, array] — List of accounts to make the package available in. Applicable only if scopeLevel is set to "account". Example: "225494730938493804,225494730938493915".
- `osType` [formData, string] (enum: macos, windows, linux_k8s, linux, sdk, windows_legacy, threat_detection_s3, threat_detection_netapp) — Platform type. Example: "macos".
- `platformType` [formData, string] (enum: macos, windows, linux_k8s, linux, sdk, windows_legacy, threat_detection_s3, threat_detection_netapp) — Platform type. Example: "macos".
- `version` [formData, string] — Version. Example: "2.5.1.1320".
- `status` [formData, string] **required** (enum: beta, ga, other, ea) — Status. Example: "beta".
- `minorVersion` [formData, string] — Package minor version. Example: "SP1".
- `scopeLevel` [formData, string] (enum: site, account, global) — Package scope. If "global", it will be available in all sites. Otherwise, it will only be available to the sites/accounts specified in"siteIds"/"accountIds" attribute. Example: "site".
- `file` [formData, file] **required** — File

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/upload/software`
**Upload System Package**
`operationId`: `_web_api_upload_software_post`

If you have an On-Prem Management or otherwise require a manual package upload, use this command to upload an Agent package or a Management package. Then you can deploy the update (see Deploy System Package).

Required permissions: `Packages.edit`

Parameters:
- `file` [formData, file] **required** — File

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/upload/software/deploy`
**Deploy System Package**
`operationId`: `_web_api_upload_software_deploy_post`

If you have an On-Prem Management or you are a participant in the Beta program, you can upload a Management package and then use this command to deploy the new Management. You must first upload the package (see Upload System Package).

Required permissions: `Packages.edit`

Responses: 200 Success, 401 Unauthorized access - please sign in and retry.
