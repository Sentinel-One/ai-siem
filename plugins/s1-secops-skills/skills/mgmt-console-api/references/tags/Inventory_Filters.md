# Inventory Filters

4 endpoints.

## `GET /web/api/v2.1/xdr/assets/filters/autocomplete`
**Auto Complete**
`operationId`: `_web_api_xdr_assets_filters_autocomplete_get`

Use this command to get values for other fields. When you send this command with input text and a field name, it returns auto-complete suggestions for the field.

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
- `key` [query, string] **required** (enum: resourceType__contains, id__contains, name__contains, tagsKey__contains, tagsKeyValue__contains, imageName__contains) — Search field key
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
- `text` [query, string] **required** — Search term text
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
- `limit` [query, integer] — Limit number of returned items
- `id__contains` [query, array] — The ID
- `cloudProviderAccountName__contains` [query, array] — The cloud provider account name
- `assetStatus` [query, array] — The status of the asset
- `cloudTagsKey__contains` [query, array] — Free-text filter by cloud tag key (supports multiple values)
- `tagsKeyValue__nin` [query, array] — Tags (not in)
- `agentAgentVersion` [query, array] — The agent version
- `allTagsKey__exists` [query, array] — User and cloud tag keys exists
- `infectionStatus__nin` [query, array] — The status alerts of the asset (not in)
- `cloudProviderProjectId__contains` [query, array] — The cloud provider project ID

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/xdr/assets/filters/count`
**Filter counts**
`operationId`: `_web_api_xdr_assets_filters_count_get`

Get filter counts

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

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/xdr/assets/filters/csv-filter`
**Upload CSV file**
`operationId`: `_web_api_xdr_assets_filters_csv-filter_post`

Upload CSV file

Required permissions: `XDR Inventory.view`

Parameters:
- `surface` [formData, string] (enum: Cloud, Identity, Network Discovery, Endpoint) — The surface that each resource belongs to
- `category` [formData, string] (enum: All, Account, AI ML, Application Integration, Cloud Application, Code, Container, Data Analysis, Data Store, Developer Tool, Device, Function, Identity, Secrets, Server, Storage, Network, Governance, Workstation) — The category that each resource belongs to
- `excludeHeader` [formData, boolean] **required** — Set to True to exclude the column header
- `assetFilterField` [formData, string] — The property of the asset to filter by
- `file` [formData, file] **required** — File

Responses: 400 Invalid user input received. See error details for further i, 200 Success, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/xdr/assets/filters/free-text`
**Free text filters**
`operationId`: `_web_api_xdr_assets_filters_free-text_get`

Get free text filters

Required permissions: `XDR Inventory.view`

Responses: 200 Success, 401 Unauthorized access - please sign in and retry.
