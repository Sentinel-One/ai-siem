# Inventory Application Integration Filters

3 endpoints.

## `GET /web/api/v2.1/xdr/assets/application-integration/filters/autocomplete`
**Auto Complete**
`operationId`: `_web_api_xdr_assets_application-integration_filters_autocomplete_get`

Use this command to get values for other fields. When you send this command with input text and a field name, it returns auto-complete suggestions for the field.

Required permissions: `XDR Inventory.view`

Parameters:
- `tagsKey__contains` [query, array] — Free-text filter by tag key (supports multiple values)
- `resourceType__contains` [query, array] — The Asset Type
- `assetCriticality__nin` [query, array] — The criticality that each asset belongs to (not in)
- `infectionStatus__nin` [query, array] — The status alerts of the asset (not in)
- `tagsKeyValue` [query, array] — Tags
- `missingCoverage` [query, array] — The missing coverage for the asset
- `allTagsKeyValue` [query, array] — User and cloud tags
- `text` [query, string] **required** — Search term text
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
- `limit` [query, integer] — Limit number of returned items
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
- `key` [query, string] **required** (enum: resourceType__contains, cloudProviderOrganization__contains, cloudProviderOrganizationUnit__contains, cloudProviderProjectId__contains, cloudProviderSubscriptionId__contains, cloudProviderAccountName__contains, cloudProviderAccountId__contains, cloudTagsKey__contains, cloudTagsKeyValue__contains, cloudResourceId__contains, region__contains, id__contains, name__contains, tagsKey__contains, tagsKeyValue__contains, imageName__contains) — Search field key
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

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/xdr/assets/application-integration/filters/count`
**Filter counts**
`operationId`: `_web_api_xdr_assets_application-integration_filters_count_get`

Get filter counts

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

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/xdr/assets/application-integration/filters/free-text`
**Free text filters**
`operationId`: `_web_api_xdr_assets_application-integration_filters_free-text_get`

Get free text filters

Required permissions: `XDR Inventory.view`

Responses: 200 Success, 401 Unauthorized access - please sign in and retry.
