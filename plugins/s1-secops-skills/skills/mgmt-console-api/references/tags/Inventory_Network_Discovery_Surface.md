# Inventory Network Discovery Surface

4 endpoints.

## `GET /web/api/v2.1/xdr/assets/surface/networkDiscovery`
**Assets**
`operationId`: `_web_api_xdr_assets_surface_networkDiscovery_get`

Get inventory of Network Discovery surface assets

Required permissions: `XDR Inventory.view`

Parameters:
- `tagsKey__contains` [query, array] — Free-text filter by tag key (supports multiple values)
- `assetCriticality__nin` [query, array] — The criticality that each asset belongs to (not in)
- `missingCoverage` [query, array] — The missing coverage for the asset
- `allTagsKeyValue` [query, array] — User and cloud tags
- `tagsKey__nin` [query, array] — Tag Keys (not in)
- `tagsKey__exists` [query, array] — Tag Keys exists
- `memoryReadable` [query, array] — The memory of the device in human readable format
- `ipAddress__contains` [query, array] — The IP addresses
- `tagsKeyValue__contains` [query, array] — Free-text filter by tag key value (supports multiple values)
- `tagsKey` [query, array] — Tag Keys
- `riskFactors__nin` [query, array] — The risk factors associated with the asset (not in)
- `tagsKey__nexists` [query, array] — Tag Keys not exists
- `skip` [query, integer] — Skip first number of items (0-1000). To iterate over more than 1000 items,  use "cursor".
- `os` [query, array] — The operating system of the device
- `groupIds` [query, array] — List of Group IDs to filter by
- `imageName__contains` [query, array] — Free-text filter by the image name
- `subnets__contains` [query, array] — The subnets
- `rangerTagsKey` [query, array] — The ranger tags key
- `networkName__nin` [query, array] — The network name (not in)
- `activeCoverage__nin` [query, array] — The active coverage for the asset (not in)
- `allTagsKeyValue__nin` [query, array] — User and cloud tags (not in)
- `networkName` [query, array] — The network name
- `allTagsKey__nin` [query, array] — User and cloud tag keys (not in)
- `gatewayIps__contains` [query, array] — The gateway IPs
- `manufacturer__nin` [query, array] — The manufacturer of the device (not in)
- `surfaces` [query, array] — The Surface that each asset belongs to
- `osNameVersion__nin` [query, array] — The operating system name and version of the device (not in)
- `missingCoverage__nin` [query, array] — The missing coverage for the asset (not in)
- `assetStatus__nin` [query, array] — The status of the asset (not in)
- `sortBy` [query, string] (enum: s1GroupName, cpu, legacyIdentityPolicyName, previousOsType, previousOsVersion, agentFirewallStatus, s1UpdatedAt, memoryReadable, s1ManagementId, isAdConnector, os, agentLocationAwareness, agentDetectionState, agentCustomerIdentifier, agentDvConnectivity, agentConsoleConnectivity, agentIdrConnectivity, agentUpToDate, networkName, s1SiteId, s1SiteName, serialNumber, detectedFromSite, agentInstallerType, identityAdUserDistinguishedName, eppUnsupportedUnknown, category, s1GroupId, agentLastLoggedInUser, ipAddress, agentK8sPod, agentDecommissioned, lastActiveDt, s1OnboardedAccountId, assetContactEmail, s1ScopeType, agentSubscribeOnDt, assetEnvironment, previousDeviceFunction, osFamily, s1AccountId, adsEnabled, id, s1AccountName, agentUninstalled, s1ScopeLevel, memory, agentId, s1OnboardedAccountName, s1OnboardedScopeLevel, isDcServer, agentOperationalState, agentNetworkStatus, name, agentVssServiceStatus, agentPendingUninstall, agentAntiTamperingStatus, assetCriticality, osVersion, s1ScopePath, s1OnboardedGroupName, identityAdMachineDistinguishedName, lastRebootDt, s1OnboardedSiteName, s1ScopeId, agentHasLocalConfig, agentPendingUpgrade, manufacturer, agentK8sNamespace, agentVssRollbackStatus, resourceType, agentUuid, agentOperationalStateExpirationTimeDt, coreCount, infectionStatus, s1OnboardedSiteId, agentVssLastSnapshotDt, agentDvConnectivityLastUpdatedDt, subCategory, s1OnboardedScopeId, agentRangerStatus, deviceReview, s1OnboardedScopePath, agentConsoleMigrationStatus, architecture, agentVssProtectionStatus, assetStatus, agentConfigurableNetworkQuarantine, agentRangerVersion, agentHealthStatus, agentFullDiskScanDt, s1OnboardedGroupId, agentAgentVersion, firstSeenDt, domain, lastUpdateDt, agentDiskEncryption, osNameVersion) — The column to sort the results by.
- `detectedFromSite` [query, array] — The site from which the device was detected
- `eppUnsupportedUnknown` [query, array] — The agent supported or unknown state
- `category` [query, array] — The category that each resource belongs to
- `deviceReview__nin` [query, array] — The asset review (not in)
- `rangerTagKeyValue__contains` [query, array] — Free-text filter by Ranger tag key value (supports multiple values)
- `assetContactEmail__nin` [query, array] — Asset Contact Email (not in)
- `alertSeverity` [query, array] — The severity of the alert
- `accountIds` [query, array] — List of Account IDs to filter by
- `osNameVersion__contains` [query, array] — The OS names and versions
- `domain__contains` [query, array] — The domain
- `resourceType__nin` [query, array] — The canonical name for the resource type (not in)
- `gatewayMacs__contains` [query, array] — The gateway MACs
- `os__nin` [query, array] — The operating system of the device (not in)
- `manufacturer__contains` [query, array] — The manufacturer
- `assetContactEmail` [query, array] — Asset Contact Email
- `udpPorts` [query, array] — The UDP ports
- `riskFactors` [query, array] — The risk factors associated with the asset
- `assetEnvironment` [query, array] — The environment that the asset exists in - AWS | Azure | GCP | Active Directory
- `osFamily` [query, array] — The operating system family of the device
- `surfaces__nin` [query, array] — The Surface that each asset belongs to (not in)
- `rangerTagsKey__nin` [query, array] — The ranger tags key (not in)
- `id__in` [query, array] — The ID
- `resourceType__contains` [query, array] — The Asset Type
- `memoryReadable__nin` [query, array] — The memory of the device in human readable format (not in)
- `tagsKeyValue` [query, array] — Tags
- `sortOrder` [query, string] (enum: asc, desc) — Sort direction
- `rangerTagsKeyValue` [query, array] — The ranger tags key value
- `countOnly` [query, boolean] — If true, only total number of items will be returned, without any of the actual objects.
- `cursor` [query, string] — Cursor position returned by the last request. Use to iterate over more than 1000 items.
- `names` [query, array] — Name
- `macAddresses__contains` [query, array] — The MAC addresses
- `detectedFromSite__nin` [query, array] — The site from which the device was detected (not in)
- `name__contains` [query, array] — The name
- `osVersion` [query, array] — The operating system version of the device
- `assetCriticality` [query, array] — The criticality that each asset belongs to
- `firstSeenDt__between` [query, string] — The first seen date
- `lastUpdateDt__between` [query, string] — The last update date
- `skipCount` [query, boolean] — If true, total number of items will not be calculated, which speeds up execution time.
- `discoveryMethods__nin` [query, array] — The discovery methods (not in)
- `allTagsKey__nexists` [query, array] — User and cloud tag keys not exists
- `manufacturer` [query, array] — The manufacturer of the device
- `siteIds` [query, array] — List of Site IDs to filter by
- `s1UpdatedAt__between` [query, string] — The Last Seen date and time for the asset
- `resourceType` [query, array] — The canonical name for the resource type
- `assetEnvironment__nin` [query, array] — The environment that the asset exists in - AWS | Azure | GCP | Active Directory (not in)
- `names__nin` [query, array] — Name (not in)
- `coreCount` [query, array] — The number of cores
- `osVersion__nin` [query, array] — The operating system version of the device (not in)
- `subCategory__nin` [query, array] — The sub-category that each resource belongs to (not in)
- `discoveryMethods` [query, array] — The discovery methods
- `infectionStatus` [query, array] — The status alerts of the asset
- `tcpPorts` [query, array] — The TCP ports
- `activeCoverage` [query, array] — The active coverage for the asset
- `countsFor` [query, array] — The columns for which filter count would be returned for
- `coreCount__nin` [query, array] — The number of cores (not in)
- `csvFilterId` [query, integer] — The ID of the CSV file to filter by
- `rangerTagKey__contains` [query, array] — Free-text filter by Ranger tag key (supports multiple values)
- `rangerTagsKeyValue__nin` [query, array] — The ranger tags key value (not in)
- `architecture__nin` [query, array] — The architecture of the device (not in)
- `subCategory` [query, array] — The sub-category that each resource belongs to
- `osVersion__contains` [query, array] — The OS versions
- `deviceReview` [query, array] — The asset review
- `allTagsKey` [query, array] — User and cloud tag keys
- `hostnames__contains` [query, array] — The hostnames
- `limit` [query, integer] — Limit number of returned items (1-1000)
- `architecture` [query, array] — The architecture of the device
- `id__contains` [query, array] — The ID
- `internalIps__contains` [query, array] — The internal IPs
- `assetStatus` [query, array] — The status of the asset
- `eppUnsupportedUnknown__nin` [query, array] — The agent supported or unknown state (not in)
- `domain__nin` [query, array] — The domain of the device (not in)
- `tagsKeyValue__nin` [query, array] — Tags (not in)
- `allTagsKey__exists` [query, array] — User and cloud tag keys exists
- `domain` [query, array] — The domain of the device
- `osFamily__nin` [query, array] — The operating system family of the device (not in)
- `infectionStatus__nin` [query, array] — The status alerts of the asset (not in)
- `osNameVersion` [query, array] — The operating system name and version of the device

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/xdr/assets/surface/networkDiscovery/action`
**Perform action**
`operationId`: `_web_api_xdr_assets_surface_networkDiscovery_action_post`

Perform action on selected assets

Required permissions: `XDR Inventory.edit, XDR Inventory.delete`

Parameters:
- `tagsKey__contains` [query, array] — Free-text filter by tag key (supports multiple values)
- `assetCriticality__nin` [query, array] — The criticality that each asset belongs to (not in)
- `missingCoverage` [query, array] — The missing coverage for the asset
- `allTagsKeyValue` [query, array] — User and cloud tags
- `tagsKey__nin` [query, array] — Tag Keys (not in)
- `tagsKey__exists` [query, array] — Tag Keys exists
- `memoryReadable` [query, array] — The memory of the device in human readable format
- `ipAddress__contains` [query, array] — The IP addresses
- `tagsKeyValue__contains` [query, array] — Free-text filter by tag key value (supports multiple values)
- `tagsKey` [query, array] — Tag Keys
- `riskFactors__nin` [query, array] — The risk factors associated with the asset (not in)
- `tagsKey__nexists` [query, array] — Tag Keys not exists
- `os` [query, array] — The operating system of the device
- `groupIds` [query, array] — List of Group IDs to filter by
- `imageName__contains` [query, array] — Free-text filter by the image name
- `subnets__contains` [query, array] — The subnets
- `rangerTagsKey` [query, array] — The ranger tags key
- `networkName__nin` [query, array] — The network name (not in)
- `activeCoverage__nin` [query, array] — The active coverage for the asset (not in)
- `allTagsKeyValue__nin` [query, array] — User and cloud tags (not in)
- `networkName` [query, array] — The network name
- `allTagsKey__nin` [query, array] — User and cloud tag keys (not in)
- `gatewayIps__contains` [query, array] — The gateway IPs
- `manufacturer__nin` [query, array] — The manufacturer of the device (not in)
- `surfaces` [query, array] — The Surface that each asset belongs to
- `osNameVersion__nin` [query, array] — The operating system name and version of the device (not in)
- `missingCoverage__nin` [query, array] — The missing coverage for the asset (not in)
- `assetStatus__nin` [query, array] — The status of the asset (not in)
- `detectedFromSite` [query, array] — The site from which the device was detected
- `eppUnsupportedUnknown` [query, array] — The agent supported or unknown state
- `category` [query, array] — The category that each resource belongs to
- `deviceReview__nin` [query, array] — The asset review (not in)
- `rangerTagKeyValue__contains` [query, array] — Free-text filter by Ranger tag key value (supports multiple values)
- `assetContactEmail__nin` [query, array] — Asset Contact Email (not in)
- `alertSeverity` [query, array] — The severity of the alert
- `accountIds` [query, array] — List of Account IDs to filter by
- `osNameVersion__contains` [query, array] — The OS names and versions
- `domain__contains` [query, array] — The domain
- `resourceType__nin` [query, array] — The canonical name for the resource type (not in)
- `gatewayMacs__contains` [query, array] — The gateway MACs
- `os__nin` [query, array] — The operating system of the device (not in)
- `manufacturer__contains` [query, array] — The manufacturer
- `assetContactEmail` [query, array] — Asset Contact Email
- `udpPorts` [query, array] — The UDP ports
- `riskFactors` [query, array] — The risk factors associated with the asset
- `assetEnvironment` [query, array] — The environment that the asset exists in - AWS | Azure | GCP | Active Directory
- `osFamily` [query, array] — The operating system family of the device
- `surfaces__nin` [query, array] — The Surface that each asset belongs to (not in)
- `rangerTagsKey__nin` [query, array] — The ranger tags key (not in)
- `id__in` [query, array] — The ID
- `resourceType__contains` [query, array] — The Asset Type
- `memoryReadable__nin` [query, array] — The memory of the device in human readable format (not in)
- `tagsKeyValue` [query, array] — Tags
- `rangerTagsKeyValue` [query, array] — The ranger tags key value
- `names` [query, array] — Name
- `macAddresses__contains` [query, array] — The MAC addresses
- `detectedFromSite__nin` [query, array] — The site from which the device was detected (not in)
- `name__contains` [query, array] — The name
- `osVersion` [query, array] — The operating system version of the device
- `assetCriticality` [query, array] — The criticality that each asset belongs to
- `firstSeenDt__between` [query, string] — The first seen date
- `lastUpdateDt__between` [query, string] — The last update date
- `discoveryMethods__nin` [query, array] — The discovery methods (not in)
- `allTagsKey__nexists` [query, array] — User and cloud tag keys not exists
- `manufacturer` [query, array] — The manufacturer of the device
- `siteIds` [query, array] — List of Site IDs to filter by
- `s1UpdatedAt__between` [query, string] — The Last Seen date and time for the asset
- `resourceType` [query, array] — The canonical name for the resource type
- `assetEnvironment__nin` [query, array] — The environment that the asset exists in - AWS | Azure | GCP | Active Directory (not in)
- `names__nin` [query, array] — Name (not in)
- `coreCount` [query, array] — The number of cores
- `osVersion__nin` [query, array] — The operating system version of the device (not in)
- `subCategory__nin` [query, array] — The sub-category that each resource belongs to (not in)
- `discoveryMethods` [query, array] — The discovery methods
- `infectionStatus` [query, array] — The status alerts of the asset
- `tcpPorts` [query, array] — The TCP ports
- `activeCoverage` [query, array] — The active coverage for the asset
- `countsFor` [query, array] — The columns for which filter count would be returned for
- `coreCount__nin` [query, array] — The number of cores (not in)
- `csvFilterId` [query, integer] — The ID of the CSV file to filter by
- `rangerTagKey__contains` [query, array] — Free-text filter by Ranger tag key (supports multiple values)
- `rangerTagsKeyValue__nin` [query, array] — The ranger tags key value (not in)
- `architecture__nin` [query, array] — The architecture of the device (not in)
- `subCategory` [query, array] — The sub-category that each resource belongs to
- `osVersion__contains` [query, array] — The OS versions
- `deviceReview` [query, array] — The asset review
- `allTagsKey` [query, array] — User and cloud tag keys
- `hostnames__contains` [query, array] — The hostnames
- `architecture` [query, array] — The architecture of the device
- `id__contains` [query, array] — The ID
- `internalIps__contains` [query, array] — The internal IPs
- `assetStatus` [query, array] — The status of the asset
- `eppUnsupportedUnknown__nin` [query, array] — The agent supported or unknown state (not in)
- `domain__nin` [query, array] — The domain of the device (not in)
- `tagsKeyValue__nin` [query, array] — Tags (not in)
- `allTagsKey__exists` [query, array] — User and cloud tag keys exists
- `domain` [query, array] — The domain of the device
- `osFamily__nin` [query, array] — The operating system family of the device (not in)
- `infectionStatus__nin` [query, array] — The status alerts of the asset (not in)
- `osNameVersion` [query, array] — The operating system name and version of the device
- `body` [body, v2_1.inventory.surfaces.network_discovery.schemas_NetworkDiscoveryActionPayloadSchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/xdr/assets/surface/networkDiscovery/available-actions/with-status`
**Available actions**
`operationId`: `_web_api_xdr_assets_surface_networkDiscovery_available-actions_with-status_post`

Get inventory network discovery available actions

Required permissions: `XDR Inventory.view`

Parameters:
- `tagsKey__contains` [query, array] — Free-text filter by tag key (supports multiple values)
- `assetCriticality__nin` [query, array] — The criticality that each asset belongs to (not in)
- `missingCoverage` [query, array] — The missing coverage for the asset
- `allTagsKeyValue` [query, array] — User and cloud tags
- `tagsKey__nin` [query, array] — Tag Keys (not in)
- `tagsKey__exists` [query, array] — Tag Keys exists
- `memoryReadable` [query, array] — The memory of the device in human readable format
- `ipAddress__contains` [query, array] — The IP addresses
- `tagsKeyValue__contains` [query, array] — Free-text filter by tag key value (supports multiple values)
- `tagsKey` [query, array] — Tag Keys
- `riskFactors__nin` [query, array] — The risk factors associated with the asset (not in)
- `tagsKey__nexists` [query, array] — Tag Keys not exists
- `os` [query, array] — The operating system of the device
- `groupIds` [query, array] — List of Group IDs to filter by
- `imageName__contains` [query, array] — Free-text filter by the image name
- `subnets__contains` [query, array] — The subnets
- `rangerTagsKey` [query, array] — The ranger tags key
- `networkName__nin` [query, array] — The network name (not in)
- `activeCoverage__nin` [query, array] — The active coverage for the asset (not in)
- `allTagsKeyValue__nin` [query, array] — User and cloud tags (not in)
- `networkName` [query, array] — The network name
- `allTagsKey__nin` [query, array] — User and cloud tag keys (not in)
- `gatewayIps__contains` [query, array] — The gateway IPs
- `manufacturer__nin` [query, array] — The manufacturer of the device (not in)
- `surfaces` [query, array] — The Surface that each asset belongs to
- `osNameVersion__nin` [query, array] — The operating system name and version of the device (not in)
- `missingCoverage__nin` [query, array] — The missing coverage for the asset (not in)
- `assetStatus__nin` [query, array] — The status of the asset (not in)
- `detectedFromSite` [query, array] — The site from which the device was detected
- `eppUnsupportedUnknown` [query, array] — The agent supported or unknown state
- `category` [query, array] — The category that each resource belongs to
- `deviceReview__nin` [query, array] — The asset review (not in)
- `rangerTagKeyValue__contains` [query, array] — Free-text filter by Ranger tag key value (supports multiple values)
- `assetContactEmail__nin` [query, array] — Asset Contact Email (not in)
- `alertSeverity` [query, array] — The severity of the alert
- `accountIds` [query, array] — List of Account IDs to filter by
- `osNameVersion__contains` [query, array] — The OS names and versions
- `domain__contains` [query, array] — The domain
- `resourceType__nin` [query, array] — The canonical name for the resource type (not in)
- `gatewayMacs__contains` [query, array] — The gateway MACs
- `os__nin` [query, array] — The operating system of the device (not in)
- `manufacturer__contains` [query, array] — The manufacturer
- `assetContactEmail` [query, array] — Asset Contact Email
- `udpPorts` [query, array] — The UDP ports
- `riskFactors` [query, array] — The risk factors associated with the asset
- `assetEnvironment` [query, array] — The environment that the asset exists in - AWS | Azure | GCP | Active Directory
- `osFamily` [query, array] — The operating system family of the device
- `surfaces__nin` [query, array] — The Surface that each asset belongs to (not in)
- `rangerTagsKey__nin` [query, array] — The ranger tags key (not in)
- `id__in` [query, array] — The ID
- `resourceType__contains` [query, array] — The Asset Type
- `memoryReadable__nin` [query, array] — The memory of the device in human readable format (not in)
- `tagsKeyValue` [query, array] — Tags
- `rangerTagsKeyValue` [query, array] — The ranger tags key value
- `names` [query, array] — Name
- `macAddresses__contains` [query, array] — The MAC addresses
- `detectedFromSite__nin` [query, array] — The site from which the device was detected (not in)
- `name__contains` [query, array] — The name
- `osVersion` [query, array] — The operating system version of the device
- `assetCriticality` [query, array] — The criticality that each asset belongs to
- `firstSeenDt__between` [query, string] — The first seen date
- `lastUpdateDt__between` [query, string] — The last update date
- `discoveryMethods__nin` [query, array] — The discovery methods (not in)
- `allTagsKey__nexists` [query, array] — User and cloud tag keys not exists
- `manufacturer` [query, array] — The manufacturer of the device
- `siteIds` [query, array] — List of Site IDs to filter by
- `s1UpdatedAt__between` [query, string] — The Last Seen date and time for the asset
- `resourceType` [query, array] — The canonical name for the resource type
- `assetEnvironment__nin` [query, array] — The environment that the asset exists in - AWS | Azure | GCP | Active Directory (not in)
- `names__nin` [query, array] — Name (not in)
- `coreCount` [query, array] — The number of cores
- `osVersion__nin` [query, array] — The operating system version of the device (not in)
- `subCategory__nin` [query, array] — The sub-category that each resource belongs to (not in)
- `discoveryMethods` [query, array] — The discovery methods
- `infectionStatus` [query, array] — The status alerts of the asset
- `tcpPorts` [query, array] — The TCP ports
- `activeCoverage` [query, array] — The active coverage for the asset
- `countsFor` [query, array] — The columns for which filter count would be returned for
- `coreCount__nin` [query, array] — The number of cores (not in)
- `csvFilterId` [query, integer] — The ID of the CSV file to filter by
- `rangerTagKey__contains` [query, array] — Free-text filter by Ranger tag key (supports multiple values)
- `rangerTagsKeyValue__nin` [query, array] — The ranger tags key value (not in)
- `architecture__nin` [query, array] — The architecture of the device (not in)
- `subCategory` [query, array] — The sub-category that each resource belongs to
- `osVersion__contains` [query, array] — The OS versions
- `deviceReview` [query, array] — The asset review
- `allTagsKey` [query, array] — User and cloud tag keys
- `hostnames__contains` [query, array] — The hostnames
- `architecture` [query, array] — The architecture of the device
- `id__contains` [query, array] — The ID
- `internalIps__contains` [query, array] — The internal IPs
- `assetStatus` [query, array] — The status of the asset
- `eppUnsupportedUnknown__nin` [query, array] — The agent supported or unknown state (not in)
- `domain__nin` [query, array] — The domain of the device (not in)
- `tagsKeyValue__nin` [query, array] — Tags (not in)
- `allTagsKey__exists` [query, array] — User and cloud tag keys exists
- `domain` [query, array] — The domain of the device
- `osFamily__nin` [query, array] — The operating system family of the device (not in)
- `infectionStatus__nin` [query, array] — The status alerts of the asset (not in)
- `osNameVersion` [query, array] — The operating system name and version of the device
- `body` [body, v2_1.inventory.schemas_AffectedResourcesSchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/xdr/assets/surface/networkDiscovery/export`
**Export assets to CSV or JSON**
`operationId`: `_web_api_xdr_assets_surface_networkDiscovery_export_get`

Returns the results for given inventory filter in a CSV or JSON format

Required permissions: `XDR Inventory.view`

Parameters:
- `tagsKey__contains` [query, array] — Free-text filter by tag key (supports multiple values)
- `assetCriticality__nin` [query, array] — The criticality that each asset belongs to (not in)
- `missingCoverage` [query, array] — The missing coverage for the asset
- `allTagsKeyValue` [query, array] — User and cloud tags
- `tagsKey__nin` [query, array] — Tag Keys (not in)
- `tagsKey__exists` [query, array] — Tag Keys exists
- `memoryReadable` [query, array] — The memory of the device in human readable format
- `ipAddress__contains` [query, array] — The IP addresses
- `tagsKeyValue__contains` [query, array] — Free-text filter by tag key value (supports multiple values)
- `tagsKey` [query, array] — Tag Keys
- `riskFactors__nin` [query, array] — The risk factors associated with the asset (not in)
- `tagsKey__nexists` [query, array] — Tag Keys not exists
- `skip` [query, integer] — Skip first number of items (0-1000). To iterate over more than 1000 items,  use "cursor".
- `os` [query, array] — The operating system of the device
- `groupIds` [query, array] — List of Group IDs to filter by
- `imageName__contains` [query, array] — Free-text filter by the image name
- `subnets__contains` [query, array] — The subnets
- `rangerTagsKey` [query, array] — The ranger tags key
- `networkName__nin` [query, array] — The network name (not in)
- `activeCoverage__nin` [query, array] — The active coverage for the asset (not in)
- `allTagsKeyValue__nin` [query, array] — User and cloud tags (not in)
- `networkName` [query, array] — The network name
- `allTagsKey__nin` [query, array] — User and cloud tag keys (not in)
- `gatewayIps__contains` [query, array] — The gateway IPs
- `manufacturer__nin` [query, array] — The manufacturer of the device (not in)
- `surfaces` [query, array] — The Surface that each asset belongs to
- `osNameVersion__nin` [query, array] — The operating system name and version of the device (not in)
- `missingCoverage__nin` [query, array] — The missing coverage for the asset (not in)
- `assetStatus__nin` [query, array] — The status of the asset (not in)
- `sortBy` [query, string] (enum: s1GroupName, memory, detectedFromSite, previousOsType, previousOsVersion, eppUnsupportedUnknown, s1OnboardedAccountName, category, s1UpdatedAt, s1GroupId, s1OnboardedScopeLevel, subCategory, s1OnboardedScopeId, deviceReview, memoryReadable, s1ManagementId, ipAddress, name, assetCriticality, osVersion, s1ScopePath, s1OnboardedAccountId, architecture, s1OnboardedScopePath, s1OnboardedGroupName, os, s1OnboardedSiteName, s1ScopeId, assetStatus, assetContactEmail, manufacturer, s1ScopeType, assetEnvironment, previousDeviceFunction, resourceType, networkName, osFamily, s1OnboardedGroupId, s1SiteId, s1AccountId, firstSeenDt, coreCount, id, domain, s1SiteName, s1AccountName, infectionStatus, lastUpdateDt, s1ScopeLevel, s1OnboardedSiteId, osNameVersion) — The column to sort the results by.
- `detectedFromSite` [query, array] — The site from which the device was detected
- `eppUnsupportedUnknown` [query, array] — The agent supported or unknown state
- `deviceReview__nin` [query, array] — The asset review (not in)
- `rangerTagKeyValue__contains` [query, array] — Free-text filter by Ranger tag key value (supports multiple values)
- `assetContactEmail__nin` [query, array] — Asset Contact Email (not in)
- `alertSeverity` [query, array] — The severity of the alert
- `accountIds` [query, array] — List of Account IDs to filter by
- `osNameVersion__contains` [query, array] — The OS names and versions
- `domain__contains` [query, array] — The domain
- `resourceType__nin` [query, array] — The canonical name for the resource type (not in)
- `gatewayMacs__contains` [query, array] — The gateway MACs
- `os__nin` [query, array] — The operating system of the device (not in)
- `manufacturer__contains` [query, array] — The manufacturer
- `assetContactEmail` [query, array] — Asset Contact Email
- `udpPorts` [query, array] — The UDP ports
- `riskFactors` [query, array] — The risk factors associated with the asset
- `assetEnvironment` [query, array] — The environment that the asset exists in - AWS | Azure | GCP | Active Directory
- `osFamily` [query, array] — The operating system family of the device
- `surfaces__nin` [query, array] — The Surface that each asset belongs to (not in)
- `rangerTagsKey__nin` [query, array] — The ranger tags key (not in)
- `id__in` [query, array] — The ID
- `resourceType__contains` [query, array] — The Asset Type
- `memoryReadable__nin` [query, array] — The memory of the device in human readable format (not in)
- `tagsKeyValue` [query, array] — Tags
- `sortOrder` [query, string] (enum: asc, desc) — Sort direction
- `rangerTagsKeyValue` [query, array] — The ranger tags key value
- `countOnly` [query, boolean] — If true, only total number of items will be returned, without any of the actual objects.
- `cursor` [query, string] — Cursor position returned by the last request. Use to iterate over more than 1000 items.
- `names` [query, array] — Name
- `macAddresses__contains` [query, array] — The MAC addresses
- `detectedFromSite__nin` [query, array] — The site from which the device was detected (not in)
- `name__contains` [query, array] — The name
- `osVersion` [query, array] — The operating system version of the device
- `assetCriticality` [query, array] — The criticality that each asset belongs to
- `firstSeenDt__between` [query, string] — The first seen date
- `lastUpdateDt__between` [query, string] — The last update date
- `skipCount` [query, boolean] — If true, total number of items will not be calculated, which speeds up execution time.
- `discoveryMethods__nin` [query, array] — The discovery methods (not in)
- `allTagsKey__nexists` [query, array] — User and cloud tag keys not exists
- `manufacturer` [query, array] — The manufacturer of the device
- `siteIds` [query, array] — List of Site IDs to filter by
- `s1UpdatedAt__between` [query, string] — The Last Seen date and time for the asset
- `resourceType` [query, array] — The canonical name for the resource type
- `assetEnvironment__nin` [query, array] — The environment that the asset exists in - AWS | Azure | GCP | Active Directory (not in)
- `names__nin` [query, array] — Name (not in)
- `coreCount` [query, array] — The number of cores
- `osVersion__nin` [query, array] — The operating system version of the device (not in)
- `subCategory__nin` [query, array] — The sub-category that each resource belongs to (not in)
- `discoveryMethods` [query, array] — The discovery methods
- `infectionStatus` [query, array] — The status alerts of the asset
- `tcpPorts` [query, array] — The TCP ports
- `activeCoverage` [query, array] — The active coverage for the asset
- `countsFor` [query, array] — The columns for which filter count would be returned for
- `coreCount__nin` [query, array] — The number of cores (not in)
- `csvFilterId` [query, integer] — The ID of the CSV file to filter by
- `rangerTagKey__contains` [query, array] — Free-text filter by Ranger tag key (supports multiple values)
- `rangerTagsKeyValue__nin` [query, array] — The ranger tags key value (not in)
- `architecture__nin` [query, array] — The architecture of the device (not in)
- `exportFormat` [query, string] **required** (enum: csv, json) — Export format
- `subCategory` [query, array] — The sub-category that each resource belongs to
- `osVersion__contains` [query, array] — The OS versions
- `deviceReview` [query, array] — The asset review
- `allTagsKey` [query, array] — User and cloud tag keys
- `hostnames__contains` [query, array] — The hostnames
- `limit` [query, integer] — Limit number of returned items (1-1000)
- `architecture` [query, array] — The architecture of the device
- `id__contains` [query, array] — The ID
- `internalIps__contains` [query, array] — The internal IPs
- `assetStatus` [query, array] — The status of the asset
- `eppUnsupportedUnknown__nin` [query, array] — The agent supported or unknown state (not in)
- `domain__nin` [query, array] — The domain of the device (not in)
- `tagsKeyValue__nin` [query, array] — Tags (not in)
- `allTagsKey__exists` [query, array] — User and cloud tag keys exists
- `domain` [query, array] — The domain of the device
- `osFamily__nin` [query, array] — The operating system family of the device (not in)
- `infectionStatus__nin` [query, array] — The status alerts of the asset (not in)
- `osNameVersion` [query, array] — The operating system name and version of the device

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.
