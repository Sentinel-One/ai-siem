# Inventory Developer Tool

5 endpoints.

## `GET /web/api/v2.1/xdr/assets/developer-tool`
**Assets**
`operationId`: `_web_api_xdr_assets_developer-tool_get`

Get assets

Required permissions: `XDR Inventory.view`

Parameters:
- `tagsKey__contains` [query, array] — Free-text filter by tag key (supports multiple values)
- `assetCriticality__nin` [query, array] — The criticality that each asset belongs to (not in)
- `missingCoverage` [query, array] — The missing coverage for the asset
- `allTagsKeyValue` [query, array] — User and cloud tags
- `cloudProviderAccountName__nin` [query, array] — The cloud provider account name (not in)
- `tagsKey__nin` [query, array] — Tag Keys (not in)
- `cloudResourceId__contains` [query, array] — The cloud resource ID
- `cloudProviderSubscriptionId__contains` [query, array] — The cloud provider subscription ID
- `tagsKey__exists` [query, array] — Tag Keys exists
- `region` [query, array] — The region
- `tagsKeyValue__contains` [query, array] — Free-text filter by tag key value (supports multiple values)
- `cloudTagsKey__nin` [query, array] — The cloud tags key (not in)
- `tagsKey` [query, array] — Tag Keys
- `riskFactors__nin` [query, array] — The risk factors associated with the asset (not in)
- `tagsKey__nexists` [query, array] — Tag Keys not exists
- `skip` [query, integer] — Skip first number of items (0-1000). To iterate over more than 1000 items,  use "cursor".
- `cloudProviderAccountId__contains` [query, array] — The cloud provider account ID
- `imageName__contains` [query, array] — Free-text filter by the image name
- `groupIds` [query, array] — List of Group IDs to filter by
- `activeCoverage__nin` [query, array] — The active coverage for the asset (not in)
- `allTagsKeyValue__nin` [query, array] — User and cloud tags (not in)
- `region__nin` [query, array] — The region (not in)
- `allTagsKey__nin` [query, array] — User and cloud tag keys (not in)
- `cloudTagsKeyValue__nin` [query, array] — The cloud tags key value (not in)
- `surfaces` [query, array] — The Surface that each asset belongs to
- `missingCoverage__nin` [query, array] — The missing coverage for the asset (not in)
- `assetStatus__nin` [query, array] — The status of the asset (not in)
- `sortBy` [query, string] (enum: s1GroupName, s1OnboardedAccountName, cloudProviderProjectId, category, s1UpdatedAt, s1GroupId, cloudProviderAccountId, s1OnboardedScopeLevel, createdTime, subCategory, cloudProviderAccountName, s1OnboardedScopeId, cloudProviderResourceGroup, deviceReview, region, cloudProviderOrganization, s1ManagementId, name, vcsIntegrationId, assetCriticality, s1OnboardedAccountId, s1ScopePath, s1OnboardedScopePath, cloudResourceUid, s1OnboardedGroupName, cloudProviderSubscriptionId, cloudResourceId, cloudProviderOrganizationUnit, cloudProviderOrganizationUnitPath, s1OnboardedSiteName, s1ScopeId, assetStatus, assetContactEmail, s1ScopeType, assetEnvironment, resourceType, s1OnboardedGroupId, s1SiteId, s1AccountId, id, s1SiteName, infectionStatus, s1AccountName, s1ScopeLevel, s1OnboardedSiteId, cloudProviderUrlString) — The column to sort the results by.
- `region__contains` [query, array] — The geographical area where cloud resources are hosted
- `deviceReview__nin` [query, array] — The asset review (not in)
- `cloudProviderAccountName` [query, array] — The cloud provider account name
- `assetContactEmail__nin` [query, array] — Asset Contact Email (not in)
- `alertSeverity` [query, array] — The severity of the alert
- `accountIds` [query, array] — List of Account IDs to filter by
- `cloudTagsKeyValue` [query, array] — The cloud tags key value
- `resourceType__nin` [query, array] — The canonical name for the resource type (not in)
- `assetContactEmail` [query, array] — Asset Contact Email
- `riskFactors` [query, array] — The risk factors associated with the asset
- `assetEnvironment` [query, array] — The environment that the asset exists in - AWS | Azure | GCP | Active Directory
- `surfaces__nin` [query, array] — The Surface that each asset belongs to (not in)
- `id__in` [query, array] — The ID
- `cloudTagsKeyValue__contains` [query, array] — Free-text filter by cloud tag key value (supports multiple values)
- `resourceType__contains` [query, array] — The Asset Type
- `tagsKeyValue` [query, array] — Tags
- `sortOrder` [query, string] (enum: asc, desc) — Sort direction
- `cloudProviderOrganizationUnit__contains` [query, array] — The cloud provider organization unit
- `cloudProviderOrganization__contains` [query, array] — The cloud provider organization
- `countOnly` [query, boolean] — If true, only total number of items will be returned, without any of the actual objects.
- `names` [query, array] — Name
- `name__contains` [query, array] — The name
- `assetCriticality` [query, array] — The criticality that each asset belongs to
- `cloudProviderAccountId__nin` [query, array] — The cloud provider account id (not in)
- `skipCount` [query, boolean] — If true, total number of items will not be calculated, which speeds up execution time.
- `allTagsKey__nexists` [query, array] — User and cloud tag keys not exists
- `siteIds` [query, array] — List of Site IDs to filter by
- `s1UpdatedAt__between` [query, string] — The Last Seen date and time for the asset
- `resourceType` [query, array] — The canonical name for the resource type
- `assetEnvironment__nin` [query, array] — The environment that the asset exists in - AWS | Azure | GCP | Active Directory (not in)
- `names__nin` [query, array] — Name (not in)
- `cloudTagsKey` [query, array] — The cloud tags key
- `subCategory__nin` [query, array] — The sub-category that each resource belongs to (not in)
- `infectionStatus` [query, array] — The status alerts of the asset
- `activeCoverage` [query, array] — The active coverage for the asset
- `countsFor` [query, array] — The columns for which filter count would be returned for
- `csvFilterId` [query, integer] — The ID of the CSV file to filter by
- `cloudProviderAccountId` [query, array] — The cloud provider account id
- `subCategory` [query, array] — The sub-category that each resource belongs to
- `deviceReview` [query, array] — The asset review
- `allTagsKey` [query, array] — User and cloud tag keys
- `limit` [query, integer] — Limit number of returned items (1-1000)
- `id__contains` [query, array] — The ID
- `cloudProviderAccountName__contains` [query, array] — The cloud provider account name
- `assetStatus` [query, array] — The status of the asset
- `cloudTagsKey__contains` [query, array] — Free-text filter by cloud tag key (supports multiple values)
- `tagsKeyValue__nin` [query, array] — Tags (not in)
- `allTagsKey__exists` [query, array] — User and cloud tag keys exists
- `cursor` [query, string] — Cursor position returned by the last request. Use to iterate over more than 1000 items.
- `infectionStatus__nin` [query, array] — The status alerts of the asset (not in)
- `cloudProviderProjectId__contains` [query, array] — The cloud provider project ID

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/xdr/assets/developer-tool`
**Assets using POST**
`operationId`: `_web_api_xdr_assets_developer-tool_post`

POST API to get Assets

Required permissions: `XDR Inventory.view`

Parameters:
- `accountIds` [query, array] — List of Account IDs to filter by
- `siteIds` [query, array] — List of Site IDs to filter by
- `groupIds` [query, array] — List of Group IDs to filter by
- `body` [body, v2_1.inventory.developer_tool.schemas_DeveloperToolsViewInputSchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/xdr/assets/developer-tool/action`
**Perform action**
`operationId`: `_web_api_xdr_assets_developer-tool_action_post`

Perform action on selected assets

Required permissions: `XDR Inventory.create, XDR Inventory.delete`

Parameters:
- `tagsKey__contains` [query, array] — Free-text filter by tag key (supports multiple values)
- `resourceType__contains` [query, array] — The Asset Type
- `assetCriticality__nin` [query, array] — The criticality that each asset belongs to (not in)
- `infectionStatus__nin` [query, array] — The status alerts of the asset (not in)
- `tagsKeyValue` [query, array] — Tags
- `missingCoverage` [query, array] — The missing coverage for the asset
- `allTagsKeyValue` [query, array] — User and cloud tags
- `cloudProviderOrganizationUnit__contains` [query, array] — The cloud provider organization unit
- `cloudProviderAccountName__nin` [query, array] — The cloud provider account name (not in)
- `region__contains` [query, array] — The geographical area where cloud resources are hosted
- `tagsKey__nin` [query, array] — Tag Keys (not in)
- `cloudResourceId__contains` [query, array] — The cloud resource ID
- `cloudProviderSubscriptionId__contains` [query, array] — The cloud provider subscription ID
- `cloudProviderAccountId` [query, array] — The cloud provider account id
- `deviceReview__nin` [query, array] — The asset review (not in)
- `subCategory` [query, array] — The sub-category that each resource belongs to
- `cloudProviderOrganization__contains` [query, array] — The cloud provider organization
- `tagsKey__exists` [query, array] — Tag Keys exists
- `cloudProviderAccountName` [query, array] — The cloud provider account name
- `assetStatus__nin` [query, array] — The status of the asset (not in)
- `deviceReview` [query, array] — The asset review
- `assetContactEmail__nin` [query, array] — Asset Contact Email (not in)
- `allTagsKey` [query, array] — User and cloud tag keys
- `region` [query, array] — The region
- `alertSeverity` [query, array] — The severity of the alert
- `accountIds` [query, array] — List of Account IDs to filter by
- `cloudTagsKeyValue` [query, array] — The cloud tags key value
- `names` [query, array] — Name
- `tagsKeyValue__contains` [query, array] — Free-text filter by tag key value (supports multiple values)
- `cloudTagsKey__nin` [query, array] — The cloud tags key (not in)
- `tagsKey` [query, array] — Tag Keys
- `name__contains` [query, array] — The name
- `assetCriticality` [query, array] — The criticality that each asset belongs to
- `riskFactors__nin` [query, array] — The risk factors associated with the asset (not in)
- `tagsKey__nexists` [query, array] — Tag Keys not exists
- `cloudProviderAccountId__nin` [query, array] — The cloud provider account id (not in)
- `resourceType__nin` [query, array] — The canonical name for the resource type (not in)
- `csvFilterId` [query, integer] — The ID of the CSV file to filter by
- `id__contains` [query, array] — The ID
- `cloudProviderAccountId__contains` [query, array] — The cloud provider account ID
- `imageName__contains` [query, array] — Free-text filter by the image name
- `groupIds` [query, array] — List of Group IDs to filter by
- `cloudProviderAccountName__contains` [query, array] — The cloud provider account name
- `assetStatus` [query, array] — The status of the asset
- `allTagsKey__nexists` [query, array] — User and cloud tag keys not exists
- `assetContactEmail` [query, array] — Asset Contact Email
- `riskFactors` [query, array] — The risk factors associated with the asset
- `activeCoverage__nin` [query, array] — The active coverage for the asset (not in)
- `siteIds` [query, array] — List of Site IDs to filter by
- `assetEnvironment` [query, array] — The environment that the asset exists in - AWS | Azure | GCP | Active Directory
- `s1UpdatedAt__between` [query, string] — The Last Seen date and time for the asset
- `resourceType` [query, array] — The canonical name for the resource type
- `assetEnvironment__nin` [query, array] — The environment that the asset exists in - AWS | Azure | GCP | Active Directory (not in)
- `missingCoverage__nin` [query, array] — The missing coverage for the asset (not in)
- `allTagsKeyValue__nin` [query, array] — User and cloud tags (not in)
- `region__nin` [query, array] — The region (not in)
- `allTagsKey__nin` [query, array] — User and cloud tag keys (not in)
- `names__nin` [query, array] — Name (not in)
- `cloudTagsKey__contains` [query, array] — Free-text filter by cloud tag key (supports multiple values)
- `tagsKeyValue__nin` [query, array] — Tags (not in)
- `surfaces__nin` [query, array] — The Surface that each asset belongs to (not in)
- `allTagsKey__exists` [query, array] — User and cloud tag keys exists
- `cloudTagsKeyValue__nin` [query, array] — The cloud tags key value (not in)
- `cloudTagsKey` [query, array] — The cloud tags key
- `surfaces` [query, array] — The Surface that each asset belongs to
- `subCategory__nin` [query, array] — The sub-category that each resource belongs to (not in)
- `id__in` [query, array] — The ID
- `infectionStatus` [query, array] — The status alerts of the asset
- `activeCoverage` [query, array] — The active coverage for the asset
- `countsFor` [query, array] — The columns for which filter count would be returned for
- `cloudTagsKeyValue__contains` [query, array] — Free-text filter by cloud tag key value (supports multiple values)
- `cloudProviderProjectId__contains` [query, array] — The cloud provider project ID
- `body` [body, v2_1.inventory.developer_tool.schemas_DeveloperToolActionPayloadSchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/xdr/assets/developer-tool/available-actions/with-status`
**Available actions**
`operationId`: `_web_api_xdr_assets_developer-tool_available-actions_with-status_post`

Get available actions

Required permissions: `XDR Inventory.view`

Parameters:
- `tagsKey__contains` [query, array] — Free-text filter by tag key (supports multiple values)
- `resourceType__contains` [query, array] — The Asset Type
- `assetCriticality__nin` [query, array] — The criticality that each asset belongs to (not in)
- `infectionStatus__nin` [query, array] — The status alerts of the asset (not in)
- `tagsKeyValue` [query, array] — Tags
- `missingCoverage` [query, array] — The missing coverage for the asset
- `allTagsKeyValue` [query, array] — User and cloud tags
- `cloudProviderOrganizationUnit__contains` [query, array] — The cloud provider organization unit
- `cloudProviderAccountName__nin` [query, array] — The cloud provider account name (not in)
- `region__contains` [query, array] — The geographical area where cloud resources are hosted
- `tagsKey__nin` [query, array] — Tag Keys (not in)
- `cloudResourceId__contains` [query, array] — The cloud resource ID
- `cloudProviderSubscriptionId__contains` [query, array] — The cloud provider subscription ID
- `cloudProviderAccountId` [query, array] — The cloud provider account id
- `deviceReview__nin` [query, array] — The asset review (not in)
- `subCategory` [query, array] — The sub-category that each resource belongs to
- `cloudProviderOrganization__contains` [query, array] — The cloud provider organization
- `tagsKey__exists` [query, array] — Tag Keys exists
- `cloudProviderAccountName` [query, array] — The cloud provider account name
- `assetStatus__nin` [query, array] — The status of the asset (not in)
- `deviceReview` [query, array] — The asset review
- `assetContactEmail__nin` [query, array] — Asset Contact Email (not in)
- `allTagsKey` [query, array] — User and cloud tag keys
- `region` [query, array] — The region
- `alertSeverity` [query, array] — The severity of the alert
- `accountIds` [query, array] — List of Account IDs to filter by
- `cloudTagsKeyValue` [query, array] — The cloud tags key value
- `names` [query, array] — Name
- `tagsKeyValue__contains` [query, array] — Free-text filter by tag key value (supports multiple values)
- `cloudTagsKey__nin` [query, array] — The cloud tags key (not in)
- `tagsKey` [query, array] — Tag Keys
- `name__contains` [query, array] — The name
- `assetCriticality` [query, array] — The criticality that each asset belongs to
- `riskFactors__nin` [query, array] — The risk factors associated with the asset (not in)
- `tagsKey__nexists` [query, array] — Tag Keys not exists
- `cloudProviderAccountId__nin` [query, array] — The cloud provider account id (not in)
- `resourceType__nin` [query, array] — The canonical name for the resource type (not in)
- `csvFilterId` [query, integer] — The ID of the CSV file to filter by
- `id__contains` [query, array] — The ID
- `cloudProviderAccountId__contains` [query, array] — The cloud provider account ID
- `imageName__contains` [query, array] — Free-text filter by the image name
- `groupIds` [query, array] — List of Group IDs to filter by
- `cloudProviderAccountName__contains` [query, array] — The cloud provider account name
- `assetStatus` [query, array] — The status of the asset
- `allTagsKey__nexists` [query, array] — User and cloud tag keys not exists
- `assetContactEmail` [query, array] — Asset Contact Email
- `riskFactors` [query, array] — The risk factors associated with the asset
- `activeCoverage__nin` [query, array] — The active coverage for the asset (not in)
- `siteIds` [query, array] — List of Site IDs to filter by
- `assetEnvironment` [query, array] — The environment that the asset exists in - AWS | Azure | GCP | Active Directory
- `s1UpdatedAt__between` [query, string] — The Last Seen date and time for the asset
- `resourceType` [query, array] — The canonical name for the resource type
- `assetEnvironment__nin` [query, array] — The environment that the asset exists in - AWS | Azure | GCP | Active Directory (not in)
- `missingCoverage__nin` [query, array] — The missing coverage for the asset (not in)
- `allTagsKeyValue__nin` [query, array] — User and cloud tags (not in)
- `region__nin` [query, array] — The region (not in)
- `allTagsKey__nin` [query, array] — User and cloud tag keys (not in)
- `names__nin` [query, array] — Name (not in)
- `cloudTagsKey__contains` [query, array] — Free-text filter by cloud tag key (supports multiple values)
- `tagsKeyValue__nin` [query, array] — Tags (not in)
- `surfaces__nin` [query, array] — The Surface that each asset belongs to (not in)
- `allTagsKey__exists` [query, array] — User and cloud tag keys exists
- `cloudTagsKeyValue__nin` [query, array] — The cloud tags key value (not in)
- `cloudTagsKey` [query, array] — The cloud tags key
- `surfaces` [query, array] — The Surface that each asset belongs to
- `subCategory__nin` [query, array] — The sub-category that each resource belongs to (not in)
- `id__in` [query, array] — The ID
- `infectionStatus` [query, array] — The status alerts of the asset
- `activeCoverage` [query, array] — The active coverage for the asset
- `countsFor` [query, array] — The columns for which filter count would be returned for
- `cloudTagsKeyValue__contains` [query, array] — Free-text filter by cloud tag key value (supports multiple values)
- `cloudProviderProjectId__contains` [query, array] — The cloud provider project ID
- `body` [body, v2_1.inventory.schemas_AffectedResourcesSchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/xdr/assets/developer-tool/export`
**Export assets to CSV or JSON**
`operationId`: `_web_api_xdr_assets_developer-tool_export_get`

Returns the results for given inventory filter in a CSV or JSON format

Required permissions: `XDR Inventory.view`

Parameters:
- `tagsKey__contains` [query, array] — Free-text filter by tag key (supports multiple values)
- `assetCriticality__nin` [query, array] — The criticality that each asset belongs to (not in)
- `missingCoverage` [query, array] — The missing coverage for the asset
- `allTagsKeyValue` [query, array] — User and cloud tags
- `cloudProviderAccountName__nin` [query, array] — The cloud provider account name (not in)
- `tagsKey__nin` [query, array] — Tag Keys (not in)
- `cloudResourceId__contains` [query, array] — The cloud resource ID
- `cloudProviderSubscriptionId__contains` [query, array] — The cloud provider subscription ID
- `tagsKey__exists` [query, array] — Tag Keys exists
- `region` [query, array] — The region
- `tagsKeyValue__contains` [query, array] — Free-text filter by tag key value (supports multiple values)
- `cloudTagsKey__nin` [query, array] — The cloud tags key (not in)
- `tagsKey` [query, array] — Tag Keys
- `riskFactors__nin` [query, array] — The risk factors associated with the asset (not in)
- `tagsKey__nexists` [query, array] — Tag Keys not exists
- `skip` [query, integer] — Skip first number of items (0-1000). To iterate over more than 1000 items,  use "cursor".
- `cloudProviderAccountId__contains` [query, array] — The cloud provider account ID
- `imageName__contains` [query, array] — Free-text filter by the image name
- `groupIds` [query, array] — List of Group IDs to filter by
- `activeCoverage__nin` [query, array] — The active coverage for the asset (not in)
- `allTagsKeyValue__nin` [query, array] — User and cloud tags (not in)
- `region__nin` [query, array] — The region (not in)
- `allTagsKey__nin` [query, array] — User and cloud tag keys (not in)
- `cloudTagsKeyValue__nin` [query, array] — The cloud tags key value (not in)
- `surfaces` [query, array] — The Surface that each asset belongs to
- `missingCoverage__nin` [query, array] — The missing coverage for the asset (not in)
- `assetStatus__nin` [query, array] — The status of the asset (not in)
- `sortBy` [query, string] (enum: s1GroupName, s1OnboardedAccountName, cloudProviderProjectId, category, s1UpdatedAt, s1GroupId, cloudProviderAccountId, s1OnboardedScopeLevel, createdTime, subCategory, cloudProviderAccountName, s1OnboardedScopeId, cloudProviderResourceGroup, deviceReview, region, cloudProviderOrganization, s1ManagementId, name, vcsIntegrationId, assetCriticality, s1OnboardedAccountId, s1ScopePath, s1OnboardedScopePath, cloudResourceUid, s1OnboardedGroupName, cloudProviderSubscriptionId, cloudResourceId, cloudProviderOrganizationUnit, cloudProviderOrganizationUnitPath, s1OnboardedSiteName, s1ScopeId, assetStatus, assetContactEmail, s1ScopeType, assetEnvironment, resourceType, s1OnboardedGroupId, s1SiteId, s1AccountId, id, s1SiteName, infectionStatus, s1AccountName, s1ScopeLevel, s1OnboardedSiteId, cloudProviderUrlString) — The column to sort the results by.
- `region__contains` [query, array] — The geographical area where cloud resources are hosted
- `deviceReview__nin` [query, array] — The asset review (not in)
- `cloudProviderAccountName` [query, array] — The cloud provider account name
- `assetContactEmail__nin` [query, array] — Asset Contact Email (not in)
- `alertSeverity` [query, array] — The severity of the alert
- `accountIds` [query, array] — List of Account IDs to filter by
- `cloudTagsKeyValue` [query, array] — The cloud tags key value
- `resourceType__nin` [query, array] — The canonical name for the resource type (not in)
- `assetContactEmail` [query, array] — Asset Contact Email
- `riskFactors` [query, array] — The risk factors associated with the asset
- `assetEnvironment` [query, array] — The environment that the asset exists in - AWS | Azure | GCP | Active Directory
- `surfaces__nin` [query, array] — The Surface that each asset belongs to (not in)
- `id__in` [query, array] — The ID
- `cloudTagsKeyValue__contains` [query, array] — Free-text filter by cloud tag key value (supports multiple values)
- `resourceType__contains` [query, array] — The Asset Type
- `tagsKeyValue` [query, array] — Tags
- `sortOrder` [query, string] (enum: asc, desc) — Sort direction
- `cloudProviderOrganizationUnit__contains` [query, array] — The cloud provider organization unit
- `cloudProviderOrganization__contains` [query, array] — The cloud provider organization
- `countOnly` [query, boolean] — If true, only total number of items will be returned, without any of the actual objects.
- `names` [query, array] — Name
- `name__contains` [query, array] — The name
- `assetCriticality` [query, array] — The criticality that each asset belongs to
- `cloudProviderAccountId__nin` [query, array] — The cloud provider account id (not in)
- `skipCount` [query, boolean] — If true, total number of items will not be calculated, which speeds up execution time.
- `allTagsKey__nexists` [query, array] — User and cloud tag keys not exists
- `siteIds` [query, array] — List of Site IDs to filter by
- `s1UpdatedAt__between` [query, string] — The Last Seen date and time for the asset
- `resourceType` [query, array] — The canonical name for the resource type
- `assetEnvironment__nin` [query, array] — The environment that the asset exists in - AWS | Azure | GCP | Active Directory (not in)
- `names__nin` [query, array] — Name (not in)
- `cloudTagsKey` [query, array] — The cloud tags key
- `subCategory__nin` [query, array] — The sub-category that each resource belongs to (not in)
- `infectionStatus` [query, array] — The status alerts of the asset
- `activeCoverage` [query, array] — The active coverage for the asset
- `countsFor` [query, array] — The columns for which filter count would be returned for
- `csvFilterId` [query, integer] — The ID of the CSV file to filter by
- `exportFormat` [query, string] **required** (enum: csv, json) — Export format
- `cloudProviderAccountId` [query, array] — The cloud provider account id
- `subCategory` [query, array] — The sub-category that each resource belongs to
- `deviceReview` [query, array] — The asset review
- `allTagsKey` [query, array] — User and cloud tag keys
- `limit` [query, integer] — Limit number of returned items (1-1000)
- `id__contains` [query, array] — The ID
- `cloudProviderAccountName__contains` [query, array] — The cloud provider account name
- `assetStatus` [query, array] — The status of the asset
- `cloudTagsKey__contains` [query, array] — Free-text filter by cloud tag key (supports multiple values)
- `tagsKeyValue__nin` [query, array] — Tags (not in)
- `allTagsKey__exists` [query, array] — User and cloud tag keys exists
- `cursor` [query, string] — Cursor position returned by the last request. Use to iterate over more than 1000 items.
- `infectionStatus__nin` [query, array] — The status alerts of the asset (not in)
- `cloudProviderProjectId__contains` [query, array] — The cloud provider project ID

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.
