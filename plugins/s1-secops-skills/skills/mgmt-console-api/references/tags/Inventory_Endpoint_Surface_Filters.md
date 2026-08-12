# Inventory Endpoint Surface Filters

3 endpoints.

## `GET /web/api/v2.1/xdr/assets/surface/endpoint/filters/autocomplete`

**Auto Complete**
`operationId`: `_web_api_xdr_assets_surface_endpoint_filters_autocomplete_get`

Use this command to get values for other fields. When you send this command with input text and a field name, it returns auto-complete suggestions for the field.

Required permissions: `XDR Inventory.view`

Parameters:

- `tagsKey__contains` [query, array]: Free-text filter by tag key (supports multiple values)
- `agentOperationalState__nin` [query, array]: The agent operational state (not in)
- `assetCriticality__nin` [query, array]: The criticality that each asset belongs to (not in)
- `legacyIdentityPolicyName` [query, array]: Legacy Identity Policy Name
- `missingCoverage` [query, array]: The missing coverage for the asset
- `allTagsKeyValue` [query, array]: User and cloud tags
- `agentConsoleMigrationStatus__nin` [query, array]: The agent console migration status (not in)
- `tagsKey__nin` [query, array]: Tag Keys (not in)
- `agentDiskMetricsFreePercentage__between` [query, string]: The agent free disk percentage on any of the disks
- `tagsKey__exists` [query, array]: Tag Keys exists
- `cpu__contains` [query, array]: The CPU
- `memoryReadable` [query, array]: The memory of the device in human readable format
- `ipAddress__contains` [query, array]: The IP addresses
- `tagsKeyValue__contains` [query, array]: Free-text filter by tag key value (supports multiple values)
- `tagsKey` [query, array]: Tag Keys
- `agentVssProtectionStatus__nin` [query, array]: The agent VSS protection status (not in)
- `riskFactors__nin` [query, array]: The risk factors associated with the asset (not in)
- `tagsKey__nexists` [query, array]: Tag Keys not exists
- `identityAdMachine__contains` [query, array]: AD machine or its groups
- `os` [query, array]: The operating system of the device
- `isAdConnector` [query, array]: Is AD Connector
- `imageName__contains` [query, array]: Free-text filter by the image name
- `agentMissingPermissions` [query, array]: The agent missing permissions
- `agentLocation__nin` [query, array]: The agent location (not in)
- `groupIds` [query, array]: List of Group IDs to filter by
- `agentDvConnectivityLastUpdatedDt__between` [query, string]: The SDL connectivity last active
- `subnets__contains` [query, array]: The subnets
- `key` [query, string] **required** (enum: resourceType__contains, id__contains, name__contains, tagsKey__contains, tagsKeyValue__contains, agentCustomerIdentifier__contains, agentLocationAwareness__contains, agentS1AgentLiveUpdatesVersion__contains, agentAgentVersion__contains, agentUuid__contains, agentLastLoggedInUser__contains, cpu__contains, serialNumber__contains, legacyIdentityPolicyName__contains, imageName__contains, domain__contains, gatewayMacs__contains, gatewayIps__contains, internalIps__contains, macAddresses__contains, ipAddress__contains, hostnames__contains, osVersion__contains, osNameVersion__contains, subnets__contains, identityAd__contains, identityAdMachine__contains, identityAdUser__contains, identityAdMachineDistinguishedName__contains, identityAdMachineMembership__contains, identityAdUserDistinguishedName__contains, identityAdUserMembership__contains): Search field key
- `agentDvConnectivity` [query, array]: The connection status between the agent and the SDL service
- `activeCoverage__nin` [query, array]: The active coverage for the asset (not in)
- `agentConsoleConnectivity` [query, array]: The agent console connectivity
- `agentIdrConnectivity` [query, array]: The agent Idr connectivity
- `allTagsKeyValue__nin` [query, array]: User and cloud tags (not in)
- `agentConfigurableNetworkQuarantine__nin` [query, array]: Whether the agent can configure network quarantine (not in)
- `allTagsKey__nin` [query, array]: User and cloud tag keys (not in)
- `gatewayIps__contains` [query, array]: The gateway IPs
- `surfaces` [query, array]: The Surface that each asset belongs to
- `agentPendingActions` [query, array]: The agent pending actions
- `osNameVersion__nin` [query, array]: The operating system name and version of the device (not in)
- `missingCoverage__nin` [query, array]: The missing coverage for the asset (not in)
- `serialNumber` [query, array]: The serial number
- `assetStatus__nin` [query, array]: The status of the asset (not in)
- `lastActiveDt__between` [query, string]: The last active date
- `identityAd__contains` [query, array]: Any AD string
- `agentInstallerType` [query, array]: The agent installer type
- `agentDiskMetricsVolumeType` [query, array]: The agent disk metrics volume type
- `legacy_identity_policy_name__contains` [query, array]: The legacy identity policy name
- `text` [query, string] **required**: Search term text
- `agentHealthStatus__nin` [query, array]: The agent health status (not in)
- `agentRangerVersion__nin` [query, array]: The agent network scanner version (not in)
- `deviceReview__nin` [query, array]: The asset review (not in)
- `assetContactEmail__nin` [query, array]: Asset Contact Email (not in)
- `agentDiskMetricsFreePercentage__lte` [query, number]: The agent free disk percentage on any of the disks
- `alertSeverity` [query, array]: The severity of the alert
- `accountIds` [query, array]: List of Account IDs to filter by
- `serialNumber__nin` [query, array]: The serial number (not in)
- `agentDecommissioned` [query, array]: Whether the agent is decommissioned
- `agentSubscribeOnDt__between` [query, string]: The agent subscribe time
- `osNameVersion__contains` [query, array]: The OS names and versions
- `domain__contains` [query, array]: The domain
- `resourceType__nin` [query, array]: The canonical name for the resource type (not in)
- `gatewayMacs__contains` [query, array]: The gateway MACs
- `agentCustomerIdentifier__contains` [query, array]: The customer identifier
- `os__nin` [query, array]: The operating system of the device (not in)
- `assetContactEmail` [query, array]: Asset Contact Email
- `riskFactors` [query, array]: The risk factors associated with the asset
- `agentFullDiskScanDt__between` [query, string]: The agent full disk scan date
- `agentAntiTamperingStatus__nin` [query, array]: The agent anti tampering status (not in)
- `assetEnvironment` [query, array]: The environment that the asset exists in - AWS | Azure | GCP | Active Directory
- `osFamily` [query, array]: The operating system family of the device
- `identityAdUser__contains` [query, array]: AD user or their groups
- `surfaces__nin` [query, array]: The Surface that each asset belongs to (not in)
- `adsEnabled` [query, array]: ADS Enabled
- `agentLocation` [query, array]: The agent location
- `agentPendingActions__nin` [query, array]: The agent pending actions (not in)
- `id__in` [query, array]: The ID
- `agentUninstalled` [query, array]: Whether the agent is uninstalled
- `resourceType__contains` [query, array]: The Asset Type
- `memoryReadable__nin` [query, array]: The memory of the device in human readable format (not in)
- `agentUuid__contains` [query, array]: The UUID
- `tagsKeyValue` [query, array]: Tags
- `isDcServer` [query, array]: Is DC Server
- `agentLocationAwareness__contains` [query, array]: The location awareness
- `identityAdUserDistinguishedName__contains` [query, array]: AD user DN
- `agentOperationalState` [query, array]: The agent operational state
- `agentNetworkStatus` [query, array]: The agent network status
- `names` [query, array]: Name
- `agentVssServiceStatus` [query, array]: The agent VSS service status
- `macAddresses__contains` [query, array]: The MAC addresses
- `agentRangerStatus__nin` [query, array]: The agent network scanner status (not in)
- `agentAgentVersion__nin` [query, array]: The agent version (not in)
- `name__contains` [query, array]: The name
- `osVersion` [query, array]: The operating system version of the device
- `agentPendingUninstall` [query, array]: Whether the agent is pending uninstall
- `agentAntiTamperingStatus` [query, array]: The agent anti tampering status
- `firstSeenDt__between` [query, string]: The first seen date
- `applicationName` [query, array]: The name of the application installed on a workstation or a server
- `assetCriticality` [query, array]: The criticality that each asset belongs to
- `agentVssServiceStatus__nin` [query, array]: The agent VSS service status (not in)
- `agentVssLastSnapshotDt__between` [query, string]: The agent VSS last snapshot date
- `agentHasLocalConfig` [query, array]: Whether the agent has local configuration
- `allTagsKey__nexists` [query, array]: User and cloud tag keys not exists
- `agentMissingPermissions__nin` [query, array]: The agent missing permissions (not in)
- `agentPendingUpgrade` [query, array]: Whether the agent is pending upgrade
- `agentVssRollbackStatus` [query, array]: The agent VSS rollback status
- `siteIds` [query, array]: List of Site IDs to filter by
- `agentInstallerType__nin` [query, array]: The agent installer type (not in)
- `s1UpdatedAt__between` [query, string]: The Last Seen date and time for the asset
- `resourceType` [query, array]: The canonical name for the resource type
- `assetEnvironment__nin` [query, array]: The environment that the asset exists in - AWS | Azure | GCP | Active Directory (not in)
- `names__nin` [query, array]: Name (not in)
- `agentUuid` [query, array]: Match by the agent UUID
- `coreCount` [query, array]: The number of cores
- `osVersion__nin` [query, array]: The operating system version of the device (not in)
- `subCategory__nin` [query, array]: The sub-category that each resource belongs to (not in)
- `infectionStatus` [query, array]: The status alerts of the asset
- `activeCoverage` [query, array]: The active coverage for the asset
- `countsFor` [query, array]: The columns for which filter count would be returned for
- `coreCount__nin` [query, array]: The number of cores (not in)
- `csvFilterId` [query, integer]: The ID of the CSV file to filter by
- `architecture__nin` [query, array]: The architecture of the device (not in)
- `identityAdMachineDistinguishedName__contains` [query, array]: AD machine DN
- `agentS1AgentLiveUpdatesVersion__contains` [query, array]: Live update ID
- `agentNetworkStatus__nin` [query, array]: The agent network status (not in)
- `subCategory` [query, array]: The sub-category that each resource belongs to
- `agentRangerStatus` [query, array]: The agent network scanner status
- `osVersion__contains` [query, array]: The OS versions
- `deviceReview` [query, array]: The asset review
- `allTagsKey` [query, array]: User and cloud tag keys
- `serialNumber__contains` [query, array]: The serial number
- `hostnames__contains` [query, array]: The hostnames
- `identityAdMachineMembership__contains` [query, array]: AD machine groups
- `limit` [query, integer]: Limit number of returned items
- `agentVssRollbackStatus__nin` [query, array]: The agent VSS rollback status (not in)
- `agentConsoleMigrationStatus` [query, array]: The agent console migration status
- `architecture` [query, array]: The architecture of the device
- `identityAdUserMembership__contains` [query, array]: AD user groups
- `agentDvConnectivity__nin` [query, array]: The connection status between the agent and the SDL service (not in)
- `agentVssProtectionStatus` [query, array]: The agent VSS protection status
- `id__contains` [query, array]: The ID
- `internalIps__contains` [query, array]: The internal IPs
- `assetStatus` [query, array]: The status of the asset
- `agentConfigurableNetworkQuarantine` [query, array]: Whether the agent can configure network quarantine
- `agentHealthStatus` [query, array]: The agent health status
- `agentRangerVersion` [query, array]: The agent network scanner version
- `agentDiskEncryption` [query, array]: The agent disk encryption
- `domain__nin` [query, array]: The domain of the device (not in)
- `agentDiskMetricsVolumeType__nin` [query, array]: The agent disk metrics volume type (not in)
- `agentLastLoggedInUser__contains` [query, array]: The last logged in user
- `tagsKeyValue__nin` [query, array]: Tags (not in)
- `agentAgentVersion` [query, array]: The agent version
- `allTagsKey__exists` [query, array]: User and cloud tag keys exists
- `agentDiskMetricsFreePercentage__gte` [query, number]: The agent free disk percentage on any of the disks
- `agentAgentVersion__contains` [query, array]: The agent version
- `domain` [query, array]: The domain of the device
- `agentVssVolumesDiffAreaFreePercentage__between` [query, string]: The agent free VSS volume percentage on any of the volumes
- `osFamily__nin` [query, array]: The operating system family of the device (not in)
- `infectionStatus__nin` [query, array]: The status alerts of the asset (not in)
- `osNameVersion` [query, array]: The operating system name and version of the device

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/xdr/assets/surface/endpoint/filters/count`

**Filter counts**
`operationId`: `_web_api_xdr_assets_surface_endpoint_filters_count_get`

Get Endpoint filter counts

Required permissions: `XDR Inventory.view`

Parameters:

- `tagsKey__contains` [query, array]: Free-text filter by tag key (supports multiple values)
- `agentOperationalState__nin` [query, array]: The agent operational state (not in)
- `assetCriticality__nin` [query, array]: The criticality that each asset belongs to (not in)
- `legacyIdentityPolicyName` [query, array]: Legacy Identity Policy Name
- `missingCoverage` [query, array]: The missing coverage for the asset
- `allTagsKeyValue` [query, array]: User and cloud tags
- `agentConsoleMigrationStatus__nin` [query, array]: The agent console migration status (not in)
- `tagsKey__nin` [query, array]: Tag Keys (not in)
- `agentDiskMetricsFreePercentage__between` [query, string]: The agent free disk percentage on any of the disks
- `tagsKey__exists` [query, array]: Tag Keys exists
- `cpu__contains` [query, array]: The CPU
- `memoryReadable` [query, array]: The memory of the device in human readable format
- `ipAddress__contains` [query, array]: The IP addresses
- `tagsKeyValue__contains` [query, array]: Free-text filter by tag key value (supports multiple values)
- `tagsKey` [query, array]: Tag Keys
- `agentVssProtectionStatus__nin` [query, array]: The agent VSS protection status (not in)
- `riskFactors__nin` [query, array]: The risk factors associated with the asset (not in)
- `tagsKey__nexists` [query, array]: Tag Keys not exists
- `identityAdMachine__contains` [query, array]: AD machine or its groups
- `os` [query, array]: The operating system of the device
- `isAdConnector` [query, array]: Is AD Connector
- `imageName__contains` [query, array]: Free-text filter by the image name
- `agentMissingPermissions` [query, array]: The agent missing permissions
- `agentLocation__nin` [query, array]: The agent location (not in)
- `groupIds` [query, array]: List of Group IDs to filter by
- `agentDvConnectivityLastUpdatedDt__between` [query, string]: The SDL connectivity last active
- `subnets__contains` [query, array]: The subnets
- `agentDvConnectivity` [query, array]: The connection status between the agent and the SDL service
- `activeCoverage__nin` [query, array]: The active coverage for the asset (not in)
- `agentConsoleConnectivity` [query, array]: The agent console connectivity
- `agentIdrConnectivity` [query, array]: The agent Idr connectivity
- `allTagsKeyValue__nin` [query, array]: User and cloud tags (not in)
- `agentConfigurableNetworkQuarantine__nin` [query, array]: Whether the agent can configure network quarantine (not in)
- `allTagsKey__nin` [query, array]: User and cloud tag keys (not in)
- `gatewayIps__contains` [query, array]: The gateway IPs
- `surfaces` [query, array]: The Surface that each asset belongs to
- `agentPendingActions` [query, array]: The agent pending actions
- `osNameVersion__nin` [query, array]: The operating system name and version of the device (not in)
- `missingCoverage__nin` [query, array]: The missing coverage for the asset (not in)
- `serialNumber` [query, array]: The serial number
- `assetStatus__nin` [query, array]: The status of the asset (not in)
- `lastActiveDt__between` [query, string]: The last active date
- `identityAd__contains` [query, array]: Any AD string
- `agentInstallerType` [query, array]: The agent installer type
- `agentDiskMetricsVolumeType` [query, array]: The agent disk metrics volume type
- `legacy_identity_policy_name__contains` [query, array]: The legacy identity policy name
- `agentHealthStatus__nin` [query, array]: The agent health status (not in)
- `agentRangerVersion__nin` [query, array]: The agent network scanner version (not in)
- `deviceReview__nin` [query, array]: The asset review (not in)
- `assetContactEmail__nin` [query, array]: Asset Contact Email (not in)
- `agentDiskMetricsFreePercentage__lte` [query, number]: The agent free disk percentage on any of the disks
- `alertSeverity` [query, array]: The severity of the alert
- `accountIds` [query, array]: List of Account IDs to filter by
- `serialNumber__nin` [query, array]: The serial number (not in)
- `agentDecommissioned` [query, array]: Whether the agent is decommissioned
- `agentSubscribeOnDt__between` [query, string]: The agent subscribe time
- `osNameVersion__contains` [query, array]: The OS names and versions
- `domain__contains` [query, array]: The domain
- `resourceType__nin` [query, array]: The canonical name for the resource type (not in)
- `gatewayMacs__contains` [query, array]: The gateway MACs
- `agentCustomerIdentifier__contains` [query, array]: The customer identifier
- `os__nin` [query, array]: The operating system of the device (not in)
- `assetContactEmail` [query, array]: Asset Contact Email
- `riskFactors` [query, array]: The risk factors associated with the asset
- `agentFullDiskScanDt__between` [query, string]: The agent full disk scan date
- `agentAntiTamperingStatus__nin` [query, array]: The agent anti tampering status (not in)
- `assetEnvironment` [query, array]: The environment that the asset exists in - AWS | Azure | GCP | Active Directory
- `osFamily` [query, array]: The operating system family of the device
- `identityAdUser__contains` [query, array]: AD user or their groups
- `surfaces__nin` [query, array]: The Surface that each asset belongs to (not in)
- `adsEnabled` [query, array]: ADS Enabled
- `agentLocation` [query, array]: The agent location
- `agentPendingActions__nin` [query, array]: The agent pending actions (not in)
- `id__in` [query, array]: The ID
- `agentUninstalled` [query, array]: Whether the agent is uninstalled
- `resourceType__contains` [query, array]: The Asset Type
- `memoryReadable__nin` [query, array]: The memory of the device in human readable format (not in)
- `agentUuid__contains` [query, array]: The UUID
- `tagsKeyValue` [query, array]: Tags
- `isDcServer` [query, array]: Is DC Server
- `agentLocationAwareness__contains` [query, array]: The location awareness
- `identityAdUserDistinguishedName__contains` [query, array]: AD user DN
- `agentOperationalState` [query, array]: The agent operational state
- `agentNetworkStatus` [query, array]: The agent network status
- `names` [query, array]: Name
- `agentVssServiceStatus` [query, array]: The agent VSS service status
- `macAddresses__contains` [query, array]: The MAC addresses
- `agentRangerStatus__nin` [query, array]: The agent network scanner status (not in)
- `agentAgentVersion__nin` [query, array]: The agent version (not in)
- `name__contains` [query, array]: The name
- `osVersion` [query, array]: The operating system version of the device
- `agentPendingUninstall` [query, array]: Whether the agent is pending uninstall
- `agentAntiTamperingStatus` [query, array]: The agent anti tampering status
- `firstSeenDt__between` [query, string]: The first seen date
- `applicationName` [query, array]: The name of the application installed on a workstation or a server
- `assetCriticality` [query, array]: The criticality that each asset belongs to
- `agentVssServiceStatus__nin` [query, array]: The agent VSS service status (not in)
- `agentVssLastSnapshotDt__between` [query, string]: The agent VSS last snapshot date
- `agentHasLocalConfig` [query, array]: Whether the agent has local configuration
- `allTagsKey__nexists` [query, array]: User and cloud tag keys not exists
- `agentMissingPermissions__nin` [query, array]: The agent missing permissions (not in)
- `agentPendingUpgrade` [query, array]: Whether the agent is pending upgrade
- `agentVssRollbackStatus` [query, array]: The agent VSS rollback status
- `siteIds` [query, array]: List of Site IDs to filter by
- `agentInstallerType__nin` [query, array]: The agent installer type (not in)
- `s1UpdatedAt__between` [query, string]: The Last Seen date and time for the asset
- `resourceType` [query, array]: The canonical name for the resource type
- `assetEnvironment__nin` [query, array]: The environment that the asset exists in - AWS | Azure | GCP | Active Directory (not in)
- `names__nin` [query, array]: Name (not in)
- `agentUuid` [query, array]: Match by the agent UUID
- `coreCount` [query, array]: The number of cores
- `osVersion__nin` [query, array]: The operating system version of the device (not in)
- `subCategory__nin` [query, array]: The sub-category that each resource belongs to (not in)
- `infectionStatus` [query, array]: The status alerts of the asset
- `activeCoverage` [query, array]: The active coverage for the asset
- `countsFor` [query, array]: The columns for which filter count would be returned for
- `coreCount__nin` [query, array]: The number of cores (not in)
- `csvFilterId` [query, integer]: The ID of the CSV file to filter by
- `architecture__nin` [query, array]: The architecture of the device (not in)
- `identityAdMachineDistinguishedName__contains` [query, array]: AD machine DN
- `agentS1AgentLiveUpdatesVersion__contains` [query, array]: Live update ID
- `agentNetworkStatus__nin` [query, array]: The agent network status (not in)
- `subCategory` [query, array]: The sub-category that each resource belongs to
- `agentRangerStatus` [query, array]: The agent network scanner status
- `osVersion__contains` [query, array]: The OS versions
- `deviceReview` [query, array]: The asset review
- `allTagsKey` [query, array]: User and cloud tag keys
- `serialNumber__contains` [query, array]: The serial number
- `hostnames__contains` [query, array]: The hostnames
- `identityAdMachineMembership__contains` [query, array]: AD machine groups
- `agentVssRollbackStatus__nin` [query, array]: The agent VSS rollback status (not in)
- `agentConsoleMigrationStatus` [query, array]: The agent console migration status
- `architecture` [query, array]: The architecture of the device
- `identityAdUserMembership__contains` [query, array]: AD user groups
- `agentDvConnectivity__nin` [query, array]: The connection status between the agent and the SDL service (not in)
- `agentVssProtectionStatus` [query, array]: The agent VSS protection status
- `id__contains` [query, array]: The ID
- `internalIps__contains` [query, array]: The internal IPs
- `assetStatus` [query, array]: The status of the asset
- `agentConfigurableNetworkQuarantine` [query, array]: Whether the agent can configure network quarantine
- `agentHealthStatus` [query, array]: The agent health status
- `agentRangerVersion` [query, array]: The agent network scanner version
- `agentDiskEncryption` [query, array]: The agent disk encryption
- `domain__nin` [query, array]: The domain of the device (not in)
- `agentDiskMetricsVolumeType__nin` [query, array]: The agent disk metrics volume type (not in)
- `agentLastLoggedInUser__contains` [query, array]: The last logged in user
- `tagsKeyValue__nin` [query, array]: Tags (not in)
- `agentAgentVersion` [query, array]: The agent version
- `allTagsKey__exists` [query, array]: User and cloud tag keys exists
- `agentDiskMetricsFreePercentage__gte` [query, number]: The agent free disk percentage on any of the disks
- `agentAgentVersion__contains` [query, array]: The agent version
- `domain` [query, array]: The domain of the device
- `agentVssVolumesDiffAreaFreePercentage__between` [query, string]: The agent free VSS volume percentage on any of the volumes
- `osFamily__nin` [query, array]: The operating system family of the device (not in)
- `infectionStatus__nin` [query, array]: The status alerts of the asset (not in)
- `osNameVersion` [query, array]: The operating system name and version of the device

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/xdr/assets/surface/endpoint/filters/free-text`

**Free text filters**
`operationId`: `_web_api_xdr_assets_surface_endpoint_filters_free-text_get`

Get Endpoint free text filters

Required permissions: `XDR Inventory.view`

Responses: 200 Success, 401 Unauthorized access - please sign in and retry.
