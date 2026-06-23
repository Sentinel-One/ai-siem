# Inventory Tags

4 endpoints.

## `POST /web/api/v2.1/xdr/assets/fetch-tags`
**Get tags info of assets by asset id**
`operationId`: `_web_api_xdr_assets_fetch-tags_post`

Get tags info for all assets

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
- `body` [body, v2_1.inventory.unified_actions.schemas_AffectedEntitiesSchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/xdr/assets/tags`
**Fetch all Unique Tags**
`operationId`: `_web_api_xdr_assets_tags_get`

Fetch all tags removing duplicates

Required permissions: `XDR Inventory.view`

Parameters:
- `skip` [query, integer] — Skip first number of items (0-1000). To iterate over more than 1000 items,  use "cursor".
- `includeParent` [query, boolean] — Include parent
- `groupIds` [query, array] — List of Group IDs to filter by
- `sortOrder` [query, string] (enum: asc, desc) — Sort direction
- `accountIds` [query, array] — List of Account IDs to filter by
- `query` [query, string] — Query
- `source` [query, array] — The source that tag belongs to
- `limit` [query, integer] — Limit number of returned items (1-1000)
- `readOnly` [query, boolean] — Read only
- `category` [query, array] — The category that each resource belongs to
- `key__contains` [query, array] — Free-text filter by tag key
- `value__contains` [query, array] — Free-text filter by tag value
- `countOnly` [query, boolean] — If true, only total number of items will be returned, without any of the actual objects.
- `siteIds` [query, array] — List of Site IDs to filter by
- `cursor` [query, string] — Cursor position returned by the last request. Use to iterate over more than 1000 items.
- `skipCount` [query, boolean] — If true, total number of items will not be calculated, which speeds up execution time.
- `sortBy` [query, string] (enum: id, key, value, source, readOnly, reserved) — The column to sort the results by.

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/xdr/assets/tags/count`
**Get count of assets by tag id**
`operationId`: `_web_api_xdr_assets_tags_count_post`

Get asset count for given tag ids

Required permissions: `XDR Inventory.view`

Parameters:
- `accountIds` [query, array] — List of Account IDs to filter by
- `siteIds` [query, array] — List of Site IDs to filter by
- `groupIds` [query, array] — List of Group IDs to filter by
- `body` [body, v2_1.inventory.tags.schemas_InventoryTagsCountPayloadSchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/xdr/assets/tags/filters-count`
**Get asset tags filters count**
`operationId`: `_web_api_xdr_assets_tags_filters-count_get`

Get asset tags filters count

Required permissions: `XDR Inventory.view`

Parameters:
- `includeParent` [query, boolean] — Include parent
- `groupIds` [query, array] — List of Group IDs to filter by
- `accountIds` [query, array] — List of Account IDs to filter by
- `query` [query, string] — Query
- `source` [query, array] — The source that tag belongs to
- `readOnly` [query, boolean] — Read only
- `category` [query, array] — The category that each resource belongs to
- `key__contains` [query, array] — Free-text filter by tag key
- `value__contains` [query, array] — Free-text filter by tag value
- `siteIds` [query, array] — List of Site IDs to filter by

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.
