# Inventory Network Discovery Surface Filters

3 endpoints.

## `GET /web/api/v2.1/xdr/assets/surface/networkDiscovery/filters/autocomplete`
**Auto Complete**
`operationId`: `_web_api_xdr_assets_surface_networkDiscovery_filters_autocomplete_get`

Use this command to get values for other fields. When you send this command with input text and a field name, it returns auto-complete suggestions for the field.

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
- `key` [query, string] **required** (enum: resourceType__contains, id__contains, name__contains, tagsKey__contains, tagsKeyValue__contains, domain__contains, gatewayMacs__contains, gatewayIps__contains, internalIps__contains, macAddresses__contains, ipAddress__contains, hostnames__contains, osVersion__contains, osNameVersion__contains, subnets__contains, manufacturer__contains, tcpPorts__contains, udpPorts__contains, rangerTagsKey__contains, rangerTagsKeyValue__contains, imageName__contains) — Search field key
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
- `text` [query, string] **required** — Search term text
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
- `limit` [query, integer] — Limit number of returned items
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

## `GET /web/api/v2.1/xdr/assets/surface/networkDiscovery/filters/count`
**Filter counts**
`operationId`: `_web_api_xdr_assets_surface_networkDiscovery_filters_count_get`

Get Network Discovery filter counts

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

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/xdr/assets/surface/networkDiscovery/filters/free-text`
**Free text filters**
`operationId`: `_web_api_xdr_assets_surface_networkDiscovery_filters_free-text_get`

Get Network Discovery free text filters

Required permissions: `XDR Inventory.view`

Responses: 200 Success, 401 Unauthorized access - please sign in and retry.
