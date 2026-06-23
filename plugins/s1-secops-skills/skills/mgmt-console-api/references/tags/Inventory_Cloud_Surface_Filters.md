# Inventory Cloud Surface Filters

3 endpoints.

## `GET /web/api/v2.1/xdr/assets/surface/cloud/filters/autocomplete`
**Auto Complete**
`operationId`: `_web_api_xdr_assets_surface_cloud_filters_autocomplete_get`

Use this command to get values for other fields. When you send this command with input text and a field name, it returns auto-complete suggestions for the field.

Required permissions: `XDR Inventory.view`

Parameters:
- `tagsKey__contains` [query, array] — Free-text filter by tag key (supports multiple values)
- `assetCriticality__nin` [query, array] — The criticality that each asset belongs to (not in)
- `infectionStatus__nin` [query, array] — The status alerts of the asset (not in)
- `state__nin` [query, array] — The state of the instance (not in)
- `missingCoverage` [query, array] — The missing coverage for the asset
- `allTagsKeyValue` [query, array] — User and cloud tags
- `cloudProviderAccountName__nin` [query, array] — The cloud provider account name (not in)
- `k8sRunningOnNodes__contains` [query, array] — Running on nodes
- `tagsKey__nin` [query, array] — Tag Keys (not in)
- `cloudResourceId__contains` [query, array] — The cloud resource ID
- `cloudProviderSubscriptionId__contains` [query, array] — The cloud provider subscription ID
- `tagsKey__exists` [query, array] — Tag Keys exists
- `scanStatus__nin` [query, array] — The CDS malware scan status (not in)
- `region` [query, array] — The region
- `memoryReadable` [query, array] — The memory of the device in human readable format
- `encryptionType__nin` [query, array] — The encryption type (not in)
- `ipAddress__contains` [query, array] — The IP addresses
- `tagsKeyValue__contains` [query, array] — Free-text filter by tag key value (supports multiple values)
- `cloudTagsKey__nin` [query, array] — The cloud tags key (not in)
- `k8sRunningOnNodes` [query, array] — Running on Nodes
- `tagsKey` [query, array] — Tag Keys
- `state` [query, array] — The state of the instance
- `k8sPolicyType__contains` [query, array] — Policy Type
- `tagsKey__nexists` [query, array] — Tag Keys not exists
- `riskFactors__nin` [query, array] — The risk factors associated with the asset (not in)
- `os` [query, array] — The operating system of the device
- `cloudProviderAccountId__contains` [query, array] — The cloud provider account ID
- `imageName__contains` [query, array] — Free-text filter by the image name
- `groupIds` [query, array] — List of Group IDs to filter by
- `subnets__contains` [query, array] — The subnets
- `k8sServiceType__contains` [query, array] — Service Type
- `instanceRole__contains` [query, array] — The instance role
- `threatDetectionStatus__nin` [query, array] — Threat Detection Status (not in)
- `activeCoverage__nin` [query, array] — The active coverage for the asset (not in)
- `key` [query, string] **required** (enum: resourceType__contains, id__contains, name__contains, tagsKey__contains, tagsKeyValue__contains, agentCustomerIdentifier__contains, agentLocationAwareness__contains, agentS1AgentLiveUpdatesVersion__contains, agentAgentVersion__contains, agentUuid__contains, agentLastLoggedInUser__contains, cpu__contains, serialNumber__contains, legacyIdentityPolicyName__contains, imageName__contains, domain__contains, gatewayMacs__contains, gatewayIps__contains, internalIps__contains, macAddresses__contains, ipAddress__contains, hostnames__contains, osVersion__contains, osNameVersion__contains, subnets__contains, identityAd__contains, identityAdMachine__contains, identityAdUser__contains, identityAdMachineDistinguishedName__contains, identityAdMachineMembership__contains, identityAdUserDistinguishedName__contains, identityAdUserMembership__contains) — Search field key
- `cloudProviderProjectId__contains` [query, array] — The cloud provider project ID
- `region__nin` [query, array] — The region (not in)
- `allTagsKeyValue__nin` [query, array] — User and cloud tags (not in)
- `allTagsKey__nin` [query, array] — User and cloud tag keys (not in)
- `gatewayIps__contains` [query, array] — The gateway IPs
- `cloudTagsKeyValue__nin` [query, array] — The cloud tags key value (not in)
- `surfaces` [query, array] — The Surface that each asset belongs to
- `objectCount__nin` [query, array] — The number of objects in the bucket (not in)
- `osNameVersion__nin` [query, array] — The operating system name and version of the device (not in)
- `k8sResourceId__contains` [query, array] — Kubernetes Resource ID
- `missingCoverage__nin` [query, array] — The missing coverage for the asset (not in)
- `assetStatus__nin` [query, array] — The status of the asset (not in)
- `state__contains` [query, array] — The state
- `text` [query, string] **required** — Search term text
- `region__contains` [query, array] — The geographical area where cloud resources are hosted
- `deviceReview__nin` [query, array] — The asset review (not in)
- `threatDetectionPolicyStatus` [query, array] — Threat Detection Policy
- `cloudProviderAccountName` [query, array] — The cloud provider account name
- `assetContactEmail__nin` [query, array] — Asset Contact Email (not in)
- `k8sNode__contains` [query, array] — The Kubernetes node
- `alertSeverity` [query, array] — The severity of the alert
- `accountIds` [query, array] — List of Account IDs to filter by
- `cloudTagsKeyValue` [query, array] — The cloud tags key value
- `k8sNode__nin` [query, array] — The Kubernetes Node (not in)
- `osNameVersion__contains` [query, array] — The OS names and versions
- `domain__contains` [query, array] — The domain
- `resourceType__nin` [query, array] — The canonical name for the resource type (not in)
- `gatewayMacs__contains` [query, array] — The gateway MACs
- `os__nin` [query, array] — The operating system of the device (not in)
- `k8sCluster__nin` [query, array] — The Kubernetes Cluster (not in)
- `k8sNamespace__contains` [query, array] — Namespace Name
- `k8sResourceId` [query, array] — The Kubernetes Resource ID
- `assetContactEmail` [query, array] — Asset Contact Email
- `riskFactors` [query, array] — The risk factors associated with the asset
- `k8sLabelsUnifiedKey__contains` [query, array] — Free-text filter by Kubernetes Labels key (supports multiple values)
- `assetEnvironment` [query, array] — The environment that the asset exists in - AWS | Azure | GCP | Active Directory
- `objectCount` [query, array] — The number of objects in the bucket
- `osFamily` [query, array] — The operating system family of the device
- `surfaces__nin` [query, array] — The Surface that each asset belongs to (not in)
- `encryptionType` [query, array] — The encryption type
- `id__in` [query, array] — The ID
- `cloudTagsKeyValue__contains` [query, array] — Free-text filter by cloud tag key value (supports multiple values)
- `resourceType__contains` [query, array] — The Asset Type
- `memoryReadable__nin` [query, array] — The memory of the device in human readable format (not in)
- `k8sLabelsUnifiedKeyValue__contains` [query, array] — Free-text filter by Kubernetes Labels key value (supports multiple values)
- `tagsKeyValue` [query, array] — Tags
- `k8sCluster__contains` [query, array] — The Kubernetes cluster
- `cloudProviderOrganizationUnit__contains` [query, array] — The cloud provider organization unit
- `cloudProviderOrganization__contains` [query, array] — The cloud provider organization
- `k8sUpdateStrategy__contains` [query, array] — Update Strategy
- `names` [query, array] — Name
- `k8sCluster` [query, array] — The Kubernetes Cluster
- `macAddresses__contains` [query, array] — The MAC addresses
- `instanceType__contains` [query, array] — The instance type
- `name__contains` [query, array] — The name
- `k8sAnnotationsUnifiedKey__contains` [query, array] — Free-text filter by Kubernetes Annotations key (supports multiple values)
- `osVersion` [query, array] — The operating system version of the device
- `threatDetectionStatus__contains` [query, array] — The threat detection status
- `assetCriticality` [query, array] — The criticality that each asset belongs to
- `cloudProviderAccountId__nin` [query, array] — The cloud provider account id (not in)
- `k8sNode` [query, array] — The Kubernetes Node
- `k8sClusterId` [query, array] — The Kubernetes Cluster ID
- `allTagsKey__nexists` [query, array] — User and cloud tag keys not exists
- `virtualNetworkId__contains` [query, array] — The virtual network ID
- `instanceId__contains` [query, array] — The instance ID
- `siteIds` [query, array] — List of Site IDs to filter by
- `s1UpdatedAt__between` [query, string] — The Last Seen date and time for the asset
- `resourceType` [query, array] — The canonical name for the resource type
- `assetEnvironment__nin` [query, array] — The environment that the asset exists in - AWS | Azure | GCP | Active Directory (not in)
- `k8sVersion__nin` [query, array] — The Kubernetes Version (not in)
- `names__nin` [query, array] — Name (not in)
- `k8sDeploymentStrategy__contains` [query, array] — Deployment Strategy
- `cloudTagsKey` [query, array] — The cloud tags key
- `coreCount` [query, array] — The number of cores
- `osVersion__nin` [query, array] — The operating system version of the device (not in)
- `subCategory__nin` [query, array] — The sub-category that each resource belongs to (not in)
- `k8sVersion` [query, array] — The Kubernetes Version
- `infectionStatus` [query, array] — The status alerts of the asset
- `activeCoverage` [query, array] — The active coverage for the asset
- `countsFor` [query, array] — The columns for which filter count would be returned for
- `coreCount__nin` [query, array] — The number of cores (not in)
- `csvFilterId` [query, integer] — The ID of the CSV file to filter by
- `networkSecurityGroups__contains` [query, array] — The network security group
- `threatDetectionStatus` [query, array] — Threat Detection Status
- `architecture__nin` [query, array] — The architecture of the device (not in)
- `k8sNamespace` [query, array] — The Kubernetes Namespace Name
- `k8sType` [query, array] — The Kubernetes Type
- `cloudProviderAccountId` [query, array] — The cloud provider account id
- `isRogues` [query, array] — Whether the instance is a rogue or not
- `subCategory` [query, array] — The sub-category that each resource belongs to
- `imageId__contains` [query, array] — The image ID
- `osVersion__contains` [query, array] — The OS versions
- `deviceReview` [query, array] — The asset review
- `allTagsKey` [query, array] — User and cloud tag keys
- `hostnames__contains` [query, array] — The hostnames
- `limit` [query, integer] — Limit number of returned items
- `k8sType__nin` [query, array] — The Kubernetes Type (not in)
- `k8sServiceName__contains` [query, array] — Service Name
- `k8sAnnotationsUnifiedKeyValue__contains` [query, array] — Free-text filter by Kubernetes Annotations key value (supports multiple values)
- `scanStatus__contains` [query, array] — The CDS malware scan status
- `architecture` [query, array] — The architecture of the device
- `id__contains` [query, array] — The ID
- `cloudProviderAccountName__contains` [query, array] — The cloud provider account name
- `internalIps__contains` [query, array] — The internal IPs
- `subnetId__contains` [query, array] — The subnet ID
- `assetStatus` [query, array] — The status of the asset
- `domain__nin` [query, array] — The domain of the device (not in)
- `k8sClusterId__contains` [query, array] — Kubernetes Cluster ID
- `cloudTagsKey__contains` [query, array] — Free-text filter by cloud tag key (supports multiple values)
- `tagsKeyValue__nin` [query, array] — Tags (not in)
- `allTagsKey__exists` [query, array] — User and cloud tag keys exists
- `domain` [query, array] — The domain of the device
- `osFamily__nin` [query, array] — The operating system family of the device (not in)
- `scanStatus` [query, array] — The CDS malware scan status
- `osNameVersion` [query, array] — The operating system name and version of the device

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/xdr/assets/surface/cloud/filters/count`
**Filter counts**
`operationId`: `_web_api_xdr_assets_surface_cloud_filters_count_get`

Get filter counts

Required permissions: `XDR Inventory.view`

Parameters:
- `tagsKey__contains` [query, array] — Free-text filter by tag key (supports multiple values)
- `assetCriticality__nin` [query, array] — The criticality that each asset belongs to (not in)
- `infectionStatus__nin` [query, array] — The status alerts of the asset (not in)
- `state__nin` [query, array] — The state of the instance (not in)
- `missingCoverage` [query, array] — The missing coverage for the asset
- `allTagsKeyValue` [query, array] — User and cloud tags
- `cloudProviderAccountName__nin` [query, array] — The cloud provider account name (not in)
- `k8sRunningOnNodes__contains` [query, array] — Running on nodes
- `tagsKey__nin` [query, array] — Tag Keys (not in)
- `cloudResourceId__contains` [query, array] — The cloud resource ID
- `cloudProviderSubscriptionId__contains` [query, array] — The cloud provider subscription ID
- `tagsKey__exists` [query, array] — Tag Keys exists
- `scanStatus__nin` [query, array] — The CDS malware scan status (not in)
- `region` [query, array] — The region
- `memoryReadable` [query, array] — The memory of the device in human readable format
- `encryptionType__nin` [query, array] — The encryption type (not in)
- `ipAddress__contains` [query, array] — The IP addresses
- `tagsKeyValue__contains` [query, array] — Free-text filter by tag key value (supports multiple values)
- `cloudTagsKey__nin` [query, array] — The cloud tags key (not in)
- `k8sRunningOnNodes` [query, array] — Running on Nodes
- `tagsKey` [query, array] — Tag Keys
- `state` [query, array] — The state of the instance
- `k8sPolicyType__contains` [query, array] — Policy Type
- `tagsKey__nexists` [query, array] — Tag Keys not exists
- `riskFactors__nin` [query, array] — The risk factors associated with the asset (not in)
- `os` [query, array] — The operating system of the device
- `cloudProviderAccountId__contains` [query, array] — The cloud provider account ID
- `imageName__contains` [query, array] — Free-text filter by the image name
- `groupIds` [query, array] — List of Group IDs to filter by
- `subnets__contains` [query, array] — The subnets
- `k8sServiceType__contains` [query, array] — Service Type
- `instanceRole__contains` [query, array] — The instance role
- `threatDetectionStatus__nin` [query, array] — Threat Detection Status (not in)
- `activeCoverage__nin` [query, array] — The active coverage for the asset (not in)
- `cloudProviderProjectId__contains` [query, array] — The cloud provider project ID
- `region__nin` [query, array] — The region (not in)
- `allTagsKeyValue__nin` [query, array] — User and cloud tags (not in)
- `allTagsKey__nin` [query, array] — User and cloud tag keys (not in)
- `gatewayIps__contains` [query, array] — The gateway IPs
- `cloudTagsKeyValue__nin` [query, array] — The cloud tags key value (not in)
- `surfaces` [query, array] — The Surface that each asset belongs to
- `objectCount__nin` [query, array] — The number of objects in the bucket (not in)
- `osNameVersion__nin` [query, array] — The operating system name and version of the device (not in)
- `k8sResourceId__contains` [query, array] — Kubernetes Resource ID
- `missingCoverage__nin` [query, array] — The missing coverage for the asset (not in)
- `assetStatus__nin` [query, array] — The status of the asset (not in)
- `state__contains` [query, array] — The state
- `region__contains` [query, array] — The geographical area where cloud resources are hosted
- `deviceReview__nin` [query, array] — The asset review (not in)
- `threatDetectionPolicyStatus` [query, array] — Threat Detection Policy
- `cloudProviderAccountName` [query, array] — The cloud provider account name
- `assetContactEmail__nin` [query, array] — Asset Contact Email (not in)
- `k8sNode__contains` [query, array] — The Kubernetes node
- `alertSeverity` [query, array] — The severity of the alert
- `accountIds` [query, array] — List of Account IDs to filter by
- `cloudTagsKeyValue` [query, array] — The cloud tags key value
- `k8sNode__nin` [query, array] — The Kubernetes Node (not in)
- `osNameVersion__contains` [query, array] — The OS names and versions
- `domain__contains` [query, array] — The domain
- `resourceType__nin` [query, array] — The canonical name for the resource type (not in)
- `gatewayMacs__contains` [query, array] — The gateway MACs
- `os__nin` [query, array] — The operating system of the device (not in)
- `k8sCluster__nin` [query, array] — The Kubernetes Cluster (not in)
- `k8sNamespace__contains` [query, array] — Namespace Name
- `k8sResourceId` [query, array] — The Kubernetes Resource ID
- `assetContactEmail` [query, array] — Asset Contact Email
- `riskFactors` [query, array] — The risk factors associated with the asset
- `k8sLabelsUnifiedKey__contains` [query, array] — Free-text filter by Kubernetes Labels key (supports multiple values)
- `assetEnvironment` [query, array] — The environment that the asset exists in - AWS | Azure | GCP | Active Directory
- `objectCount` [query, array] — The number of objects in the bucket
- `osFamily` [query, array] — The operating system family of the device
- `surfaces__nin` [query, array] — The Surface that each asset belongs to (not in)
- `encryptionType` [query, array] — The encryption type
- `id__in` [query, array] — The ID
- `cloudTagsKeyValue__contains` [query, array] — Free-text filter by cloud tag key value (supports multiple values)
- `resourceType__contains` [query, array] — The Asset Type
- `memoryReadable__nin` [query, array] — The memory of the device in human readable format (not in)
- `k8sLabelsUnifiedKeyValue__contains` [query, array] — Free-text filter by Kubernetes Labels key value (supports multiple values)
- `tagsKeyValue` [query, array] — Tags
- `k8sCluster__contains` [query, array] — The Kubernetes cluster
- `cloudProviderOrganizationUnit__contains` [query, array] — The cloud provider organization unit
- `cloudProviderOrganization__contains` [query, array] — The cloud provider organization
- `k8sUpdateStrategy__contains` [query, array] — Update Strategy
- `names` [query, array] — Name
- `k8sCluster` [query, array] — The Kubernetes Cluster
- `macAddresses__contains` [query, array] — The MAC addresses
- `instanceType__contains` [query, array] — The instance type
- `name__contains` [query, array] — The name
- `k8sAnnotationsUnifiedKey__contains` [query, array] — Free-text filter by Kubernetes Annotations key (supports multiple values)
- `osVersion` [query, array] — The operating system version of the device
- `threatDetectionStatus__contains` [query, array] — The threat detection status
- `assetCriticality` [query, array] — The criticality that each asset belongs to
- `cloudProviderAccountId__nin` [query, array] — The cloud provider account id (not in)
- `k8sNode` [query, array] — The Kubernetes Node
- `k8sClusterId` [query, array] — The Kubernetes Cluster ID
- `allTagsKey__nexists` [query, array] — User and cloud tag keys not exists
- `virtualNetworkId__contains` [query, array] — The virtual network ID
- `instanceId__contains` [query, array] — The instance ID
- `siteIds` [query, array] — List of Site IDs to filter by
- `s1UpdatedAt__between` [query, string] — The Last Seen date and time for the asset
- `resourceType` [query, array] — The canonical name for the resource type
- `assetEnvironment__nin` [query, array] — The environment that the asset exists in - AWS | Azure | GCP | Active Directory (not in)
- `k8sVersion__nin` [query, array] — The Kubernetes Version (not in)
- `names__nin` [query, array] — Name (not in)
- `k8sDeploymentStrategy__contains` [query, array] — Deployment Strategy
- `cloudTagsKey` [query, array] — The cloud tags key
- `coreCount` [query, array] — The number of cores
- `osVersion__nin` [query, array] — The operating system version of the device (not in)
- `subCategory__nin` [query, array] — The sub-category that each resource belongs to (not in)
- `k8sVersion` [query, array] — The Kubernetes Version
- `infectionStatus` [query, array] — The status alerts of the asset
- `activeCoverage` [query, array] — The active coverage for the asset
- `countsFor` [query, array] — The columns for which filter count would be returned for
- `coreCount__nin` [query, array] — The number of cores (not in)
- `csvFilterId` [query, integer] — The ID of the CSV file to filter by
- `networkSecurityGroups__contains` [query, array] — The network security group
- `threatDetectionStatus` [query, array] — Threat Detection Status
- `architecture__nin` [query, array] — The architecture of the device (not in)
- `k8sNamespace` [query, array] — The Kubernetes Namespace Name
- `k8sType` [query, array] — The Kubernetes Type
- `cloudProviderAccountId` [query, array] — The cloud provider account id
- `isRogues` [query, array] — Whether the instance is a rogue or not
- `subCategory` [query, array] — The sub-category that each resource belongs to
- `imageId__contains` [query, array] — The image ID
- `osVersion__contains` [query, array] — The OS versions
- `deviceReview` [query, array] — The asset review
- `allTagsKey` [query, array] — User and cloud tag keys
- `hostnames__contains` [query, array] — The hostnames
- `k8sType__nin` [query, array] — The Kubernetes Type (not in)
- `k8sServiceName__contains` [query, array] — Service Name
- `k8sAnnotationsUnifiedKeyValue__contains` [query, array] — Free-text filter by Kubernetes Annotations key value (supports multiple values)
- `scanStatus__contains` [query, array] — The CDS malware scan status
- `architecture` [query, array] — The architecture of the device
- `id__contains` [query, array] — The ID
- `cloudProviderAccountName__contains` [query, array] — The cloud provider account name
- `internalIps__contains` [query, array] — The internal IPs
- `subnetId__contains` [query, array] — The subnet ID
- `assetStatus` [query, array] — The status of the asset
- `domain__nin` [query, array] — The domain of the device (not in)
- `k8sClusterId__contains` [query, array] — Kubernetes Cluster ID
- `cloudTagsKey__contains` [query, array] — Free-text filter by cloud tag key (supports multiple values)
- `tagsKeyValue__nin` [query, array] — Tags (not in)
- `allTagsKey__exists` [query, array] — User and cloud tag keys exists
- `domain` [query, array] — The domain of the device
- `osFamily__nin` [query, array] — The operating system family of the device (not in)
- `scanStatus` [query, array] — The CDS malware scan status
- `osNameVersion` [query, array] — The operating system name and version of the device

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/xdr/assets/surface/cloud/filters/free-text`
**Free text filters**
`operationId`: `_web_api_xdr_assets_surface_cloud_filters_free-text_get`

Get free text filters

Required permissions: `XDR Inventory.view`

Responses: 200 Success, 401 Unauthorized access - please sign in and retry.
