# Inventory

9 endpoints.

## `GET /web/api/v2.1/xdr/assets`
**Assets**
`operationId`: `_web_api_xdr_assets_get`

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
- `groupIds` [query, array] — List of Group IDs to filter by
- `activeCoverage__nin` [query, array] — The active coverage for the asset (not in)
- `agentConsoleConnectivity` [query, array] — The agent console connectivity
- `agentIdrConnectivity` [query, array] — The agent idr connectivity
- `allTagsKeyValue__nin` [query, array] — User and cloud tags (not in)
- `region__nin` [query, array] — The region (not in)
- `allTagsKey__nin` [query, array] — User and cloud tag keys (not in)
- `cloudTagsKeyValue__nin` [query, array] — The cloud tags key value (not in)
- `surfaces` [query, array] — The Surface that each asset belongs to
- `agentPendingActions` [query, array] — The agent pending actions
- `missingCoverage__nin` [query, array] — The missing coverage for the asset (not in)
- `assetStatus__nin` [query, array] — The status of the asset (not in)
- `sortBy` [query, string] (enum: s1GroupName, cpu, legacyIdentityPolicyName, previousOsType, previousOsVersion, agentFirewallStatus, s1UpdatedAt, cloudProviderResourceGroup, region, cloudProviderOrganization, s1ManagementId, isAdConnector, cloudProviderOrganizationUnit, agentLocationAwareness, agentDetectionState, agentCustomerIdentifier, agentDvConnectivity, agentConsoleConnectivity, agentIdrConnectivity, agentUpToDate, networkName, s1SiteId, s1SiteName, serialNumber, detectedFromSite, agentInstallerType, identityAdUserDistinguishedName, eppUnsupportedUnknown, category, s1GroupId, cloudProviderAccountName, agentLastLoggedInUser, agentK8sPod, agentDecommissioned, lastActiveDt, s1OnboardedAccountId, cloudResourceId, assetContactEmail, s1ScopeType, agentSubscribeOnDt, assetEnvironment, previousDeviceFunction, s1AccountId, adsEnabled, id, s1AccountName, agentUninstalled, s1ScopeLevel, cloudProviderUrlString, agentId, s1OnboardedAccountName, s1OnboardedScopeLevel, createdTime, isDcServer, agentOperationalState, agentNetworkStatus, name, agentVssServiceStatus, agentPendingUninstall, agentAntiTamperingStatus, assetCriticality, s1ScopePath, s1OnboardedGroupName, cloudProviderSubscriptionId, identityAdMachineDistinguishedName, cloudProviderOrganizationUnitPath, lastRebootDt, s1OnboardedSiteName, s1ScopeId, agentHasLocalConfig, agentPendingUpgrade, manufacturer, agentK8sNamespace, agentVssRollbackStatus, resourceType, agentUuid, agentOperationalStateExpirationTimeDt, infectionStatus, s1OnboardedSiteId, agentVssLastSnapshotDt, agentDvConnectivityLastUpdatedDt, cloudProviderProjectId, cloudProviderAccountId, subCategory, s1OnboardedScopeId, agentRangerStatus, deviceReview, cloudResourceUid, s1OnboardedScopePath, agentConsoleMigrationStatus, agentVssProtectionStatus, assetStatus, agentConfigurableNetworkQuarantine, agentRangerVersion, agentHealthStatus, agentFullDiskScanDt, s1OnboardedGroupId, agentAgentVersion, firstSeenDt, lastUpdateDt, agentDiskEncryption) — The column to sort the results by.
- `eppUnsupportedUnknown` [query, array] — The agent supported or unknown state
- `region__contains` [query, array] — The geographical area where cloud resources are hosted
- `category` [query, array] — The category that each resource belongs to
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
- `osFamily` [query, array] — The operating system family of the device
- `surfaces__nin` [query, array] — The Surface that each asset belongs to (not in)
- `id__in` [query, array] — The ID
- `cloudTagsKeyValue__contains` [query, array] — Free-text filter by cloud tag key value (supports multiple values)
- `resourceType__contains` [query, array] — The Asset Type
- `sortOrder` [query, string] (enum: asc, desc) — Sort direction
- `tagsKeyValue` [query, array] — Tags
- `cloudProviderOrganizationUnit__contains` [query, array] — The cloud provider organization unit
- `cloudProviderOrganization__contains` [query, array] — The cloud provider organization
- `countOnly` [query, boolean] — If true, only total number of items will be returned, without any of the actual objects.
- `agentOperationalState` [query, array] — The agent operational state
- `names` [query, array] — Name
- `name__contains` [query, array] — The name
- `assetCriticality` [query, array] — The criticality that each asset belongs to
- `agentAntiTamperingStatus` [query, array] — The agent anti tampering status
- `cloudProviderAccountId__nin` [query, array] — The cloud provider account id (not in)
- `skipCount` [query, boolean] — If true, total number of items will not be calculated, which speeds up execution time.
- `allTagsKey__nexists` [query, array] — User and cloud tag keys not exists
- `siteIds` [query, array] — List of Site IDs to filter by
- `agentVssRollbackStatus` [query, array] — The agent VSS rollback status
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
- `agentAgentVersion` [query, array] — The agent version
- `allTagsKey__exists` [query, array] — User and cloud tag keys exists
- `cursor` [query, string] — Cursor position returned by the last request. Use to iterate over more than 1000 items.
- `infectionStatus__nin` [query, array] — The status alerts of the asset (not in)
- `cloudProviderProjectId__contains` [query, array] — The cloud provider project ID

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/xdr/assets`
**Assets using POST**
`operationId`: `_web_api_xdr_assets_post`

POST API to get assets

Required permissions: `XDR Inventory.view`

Parameters:
- `accountIds` [query, array] — List of Account IDs to filter by
- `siteIds` [query, array] — List of Site IDs to filter by
- `groupIds` [query, array] — List of Group IDs to filter by
- `body` [body, v2_1.inventory.schemas_InventoryViewInputSchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/xdr/assets/action`
**Perform action**
`operationId`: `_web_api_xdr_assets_action_post`

Perform action on selected assets

Required permissions: `XDR Inventory.create, XDR Inventory.delete`

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
- `cloudProviderAccountId__contains` [query, array] — The cloud provider account ID
- `groupIds` [query, array] — List of Group IDs to filter by
- `activeCoverage__nin` [query, array] — The active coverage for the asset (not in)
- `agentConsoleConnectivity` [query, array] — The agent console connectivity
- `agentIdrConnectivity` [query, array] — The agent idr connectivity
- `allTagsKeyValue__nin` [query, array] — User and cloud tags (not in)
- `region__nin` [query, array] — The region (not in)
- `allTagsKey__nin` [query, array] — User and cloud tag keys (not in)
- `cloudTagsKeyValue__nin` [query, array] — The cloud tags key value (not in)
- `surfaces` [query, array] — The Surface that each asset belongs to
- `agentPendingActions` [query, array] — The agent pending actions
- `missingCoverage__nin` [query, array] — The missing coverage for the asset (not in)
- `assetStatus__nin` [query, array] — The status of the asset (not in)
- `eppUnsupportedUnknown` [query, array] — The agent supported or unknown state
- `region__contains` [query, array] — The geographical area where cloud resources are hosted
- `category` [query, array] — The category that each resource belongs to
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
- `osFamily` [query, array] — The operating system family of the device
- `surfaces__nin` [query, array] — The Surface that each asset belongs to (not in)
- `id__in` [query, array] — The ID
- `cloudTagsKeyValue__contains` [query, array] — Free-text filter by cloud tag key value (supports multiple values)
- `resourceType__contains` [query, array] — The Asset Type
- `tagsKeyValue` [query, array] — Tags
- `cloudProviderOrganizationUnit__contains` [query, array] — The cloud provider organization unit
- `cloudProviderOrganization__contains` [query, array] — The cloud provider organization
- `agentOperationalState` [query, array] — The agent operational state
- `names` [query, array] — Name
- `name__contains` [query, array] — The name
- `assetCriticality` [query, array] — The criticality that each asset belongs to
- `agentAntiTamperingStatus` [query, array] — The agent anti tampering status
- `cloudProviderAccountId__nin` [query, array] — The cloud provider account id (not in)
- `allTagsKey__nexists` [query, array] — User and cloud tag keys not exists
- `siteIds` [query, array] — List of Site IDs to filter by
- `agentVssRollbackStatus` [query, array] — The agent VSS rollback status
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
- `id__contains` [query, array] — The ID
- `cloudProviderAccountName__contains` [query, array] — The cloud provider account name
- `assetStatus` [query, array] — The status of the asset
- `cloudTagsKey__contains` [query, array] — Free-text filter by cloud tag key (supports multiple values)
- `tagsKeyValue__nin` [query, array] — Tags (not in)
- `agentAgentVersion` [query, array] — The agent version
- `allTagsKey__exists` [query, array] — User and cloud tag keys exists
- `infectionStatus__nin` [query, array] — The status alerts of the asset (not in)
- `cloudProviderProjectId__contains` [query, array] — The cloud provider project ID
- `body` [body, v2_1.inventory.schemas_InventoryActionPayloadSchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/xdr/assets/asset-counts`
**Get inventory counts for menu items**
`operationId`: `_web_api_xdr_assets_asset-counts_get`

Get inventory counts categories, subcategories and surfaces

Required permissions: `XDR Inventory.view`

Parameters:
- `accountIds` [query, array] — List of Account IDs to filter by
- `siteIds` [query, array] — List of Site IDs to filter by
- `groupIds` [query, array] — List of Group IDs to filter by

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/xdr/assets/available-actions/with-status`
**Available actions**
`operationId`: `_web_api_xdr_assets_available-actions_with-status_post`

Get available actions

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
- `cloudProviderAccountId__contains` [query, array] — The cloud provider account ID
- `groupIds` [query, array] — List of Group IDs to filter by
- `activeCoverage__nin` [query, array] — The active coverage for the asset (not in)
- `agentConsoleConnectivity` [query, array] — The agent console connectivity
- `agentIdrConnectivity` [query, array] — The agent idr connectivity
- `allTagsKeyValue__nin` [query, array] — User and cloud tags (not in)
- `region__nin` [query, array] — The region (not in)
- `allTagsKey__nin` [query, array] — User and cloud tag keys (not in)
- `cloudTagsKeyValue__nin` [query, array] — The cloud tags key value (not in)
- `surfaces` [query, array] — The Surface that each asset belongs to
- `agentPendingActions` [query, array] — The agent pending actions
- `missingCoverage__nin` [query, array] — The missing coverage for the asset (not in)
- `assetStatus__nin` [query, array] — The status of the asset (not in)
- `eppUnsupportedUnknown` [query, array] — The agent supported or unknown state
- `region__contains` [query, array] — The geographical area where cloud resources are hosted
- `category` [query, array] — The category that each resource belongs to
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
- `osFamily` [query, array] — The operating system family of the device
- `surfaces__nin` [query, array] — The Surface that each asset belongs to (not in)
- `id__in` [query, array] — The ID
- `cloudTagsKeyValue__contains` [query, array] — Free-text filter by cloud tag key value (supports multiple values)
- `resourceType__contains` [query, array] — The Asset Type
- `tagsKeyValue` [query, array] — Tags
- `cloudProviderOrganizationUnit__contains` [query, array] — The cloud provider organization unit
- `cloudProviderOrganization__contains` [query, array] — The cloud provider organization
- `agentOperationalState` [query, array] — The agent operational state
- `names` [query, array] — Name
- `name__contains` [query, array] — The name
- `assetCriticality` [query, array] — The criticality that each asset belongs to
- `agentAntiTamperingStatus` [query, array] — The agent anti tampering status
- `cloudProviderAccountId__nin` [query, array] — The cloud provider account id (not in)
- `allTagsKey__nexists` [query, array] — User and cloud tag keys not exists
- `siteIds` [query, array] — List of Site IDs to filter by
- `agentVssRollbackStatus` [query, array] — The agent VSS rollback status
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
- `id__contains` [query, array] — The ID
- `cloudProviderAccountName__contains` [query, array] — The cloud provider account name
- `assetStatus` [query, array] — The status of the asset
- `cloudTagsKey__contains` [query, array] — Free-text filter by cloud tag key (supports multiple values)
- `tagsKeyValue__nin` [query, array] — Tags (not in)
- `agentAgentVersion` [query, array] — The agent version
- `allTagsKey__exists` [query, array] — User and cloud tag keys exists
- `infectionStatus__nin` [query, array] — The status alerts of the asset (not in)
- `cloudProviderProjectId__contains` [query, array] — The cloud provider project ID
- `body` [body, v2_1.inventory.schemas_AffectedResourcesSchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/xdr/assets/categories`
**Categories and counts**
`operationId`: `_web_api_xdr_assets_categories_get`

Get inventory categories and their asset counts

Required permissions: `XDR Inventory.view`

Parameters:
- `accountIds` [query, array] — List of Account IDs to filter by
- `siteIds` [query, array] — List of Site IDs to filter by
- `groupIds` [query, array] — List of Group IDs to filter by

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/xdr/assets/cloud-tags/export`
**Export Cloud Tags to CSV or JSON**
`operationId`: `_web_api_xdr_assets_cloud-tags_export_get`

Returns the tags for given id in a CSV or JSON format

Required permissions: `XDR Inventory.view`

Parameters:
- `groupIds` [query, array] — List of Group IDs to filter by
- `accountIds` [query, array] — List of Account IDs to filter by
- `exportFormat` [query, string] **required** (enum: csv, json) — Export format
- `id` [query, array] — List of resource ids to filter by
- `siteIds` [query, array] — List of Site IDs to filter by

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/xdr/assets/export`
**Export assets to CSV or JSON**
`operationId`: `_web_api_xdr_assets_export_get`

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
- `groupIds` [query, array] — List of Group IDs to filter by
- `activeCoverage__nin` [query, array] — The active coverage for the asset (not in)
- `agentConsoleConnectivity` [query, array] — The agent console connectivity
- `agentIdrConnectivity` [query, array] — The agent idr connectivity
- `allTagsKeyValue__nin` [query, array] — User and cloud tags (not in)
- `region__nin` [query, array] — The region (not in)
- `allTagsKey__nin` [query, array] — User and cloud tag keys (not in)
- `cloudTagsKeyValue__nin` [query, array] — The cloud tags key value (not in)
- `surfaces` [query, array] — The Surface that each asset belongs to
- `agentPendingActions` [query, array] — The agent pending actions
- `missingCoverage__nin` [query, array] — The missing coverage for the asset (not in)
- `assetStatus__nin` [query, array] — The status of the asset (not in)
- `sortBy` [query, string] (enum: s1GroupName, cpu, legacyIdentityPolicyName, previousOsType, previousOsVersion, agentFirewallStatus, s1UpdatedAt, cloudProviderResourceGroup, region, cloudProviderOrganization, s1ManagementId, isAdConnector, cloudProviderOrganizationUnit, agentLocationAwareness, agentDetectionState, agentCustomerIdentifier, agentDvConnectivity, agentConsoleConnectivity, agentIdrConnectivity, agentUpToDate, networkName, s1SiteId, s1SiteName, serialNumber, detectedFromSite, agentInstallerType, identityAdUserDistinguishedName, eppUnsupportedUnknown, category, s1GroupId, cloudProviderAccountName, agentLastLoggedInUser, agentK8sPod, agentDecommissioned, lastActiveDt, s1OnboardedAccountId, cloudResourceId, assetContactEmail, s1ScopeType, agentSubscribeOnDt, assetEnvironment, previousDeviceFunction, s1AccountId, adsEnabled, id, s1AccountName, agentUninstalled, s1ScopeLevel, cloudProviderUrlString, agentId, s1OnboardedAccountName, s1OnboardedScopeLevel, createdTime, isDcServer, agentOperationalState, agentNetworkStatus, name, agentVssServiceStatus, agentPendingUninstall, agentAntiTamperingStatus, assetCriticality, s1ScopePath, s1OnboardedGroupName, cloudProviderSubscriptionId, identityAdMachineDistinguishedName, cloudProviderOrganizationUnitPath, lastRebootDt, s1OnboardedSiteName, s1ScopeId, agentHasLocalConfig, agentPendingUpgrade, manufacturer, agentK8sNamespace, agentVssRollbackStatus, resourceType, agentUuid, agentOperationalStateExpirationTimeDt, infectionStatus, s1OnboardedSiteId, agentVssLastSnapshotDt, agentDvConnectivityLastUpdatedDt, cloudProviderProjectId, cloudProviderAccountId, subCategory, s1OnboardedScopeId, agentRangerStatus, deviceReview, cloudResourceUid, s1OnboardedScopePath, agentConsoleMigrationStatus, agentVssProtectionStatus, assetStatus, agentConfigurableNetworkQuarantine, agentRangerVersion, agentHealthStatus, agentFullDiskScanDt, s1OnboardedGroupId, agentAgentVersion, firstSeenDt, lastUpdateDt, agentDiskEncryption) — The column to sort the results by.
- `eppUnsupportedUnknown` [query, array] — The agent supported or unknown state
- `region__contains` [query, array] — The geographical area where cloud resources are hosted
- `category` [query, array] — The category that each resource belongs to
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
- `osFamily` [query, array] — The operating system family of the device
- `surfaces__nin` [query, array] — The Surface that each asset belongs to (not in)
- `id__in` [query, array] — The ID
- `cloudTagsKeyValue__contains` [query, array] — Free-text filter by cloud tag key value (supports multiple values)
- `resourceType__contains` [query, array] — The Asset Type
- `sortOrder` [query, string] (enum: asc, desc) — Sort direction
- `tagsKeyValue` [query, array] — Tags
- `cloudProviderOrganizationUnit__contains` [query, array] — The cloud provider organization unit
- `cloudProviderOrganization__contains` [query, array] — The cloud provider organization
- `countOnly` [query, boolean] — If true, only total number of items will be returned, without any of the actual objects.
- `agentOperationalState` [query, array] — The agent operational state
- `names` [query, array] — Name
- `name__contains` [query, array] — The name
- `assetCriticality` [query, array] — The criticality that each asset belongs to
- `agentAntiTamperingStatus` [query, array] — The agent anti tampering status
- `cloudProviderAccountId__nin` [query, array] — The cloud provider account id (not in)
- `skipCount` [query, boolean] — If true, total number of items will not be calculated, which speeds up execution time.
- `allTagsKey__nexists` [query, array] — User and cloud tag keys not exists
- `siteIds` [query, array] — List of Site IDs to filter by
- `agentVssRollbackStatus` [query, array] — The agent VSS rollback status
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
- `agentAgentVersion` [query, array] — The agent version
- `allTagsKey__exists` [query, array] — User and cloud tag keys exists
- `cursor` [query, string] — Cursor position returned by the last request. Use to iterate over more than 1000 items.
- `infectionStatus__nin` [query, array] — The status alerts of the asset (not in)
- `cloudProviderProjectId__contains` [query, array] — The cloud provider project ID

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/xdr/assets/sub-categories`
**Counts per subcategory for categories**
`operationId`: `_web_api_xdr_assets_sub-categories_get`

Get asset counts per subcategory for each category

Required permissions: `XDR Inventory.view`

Parameters:
- `accountIds` [query, array] — List of Account IDs to filter by
- `siteIds` [query, array] — List of Site IDs to filter by
- `groupIds` [query, array] — List of Group IDs to filter by

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.
