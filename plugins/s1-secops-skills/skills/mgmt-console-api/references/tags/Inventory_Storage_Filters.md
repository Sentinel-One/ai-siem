# Inventory Storage Filters

3 endpoints.

## `GET /web/api/v2.1/xdr/assets/storage/filters/autocomplete`
**Auto Complete**
`operationId`: `_web_api_xdr_assets_storage_filters_autocomplete_get`

Use this command to get values for other fields. When you send this command with input text and a field name, it returns auto-complete suggestions for the field.

Required permissions: `XDR Inventory.view`

Parameters:
- `tagsKey__contains` [query, array] — Free-text filter by tag key (supports multiple values)
- `assetCriticality__nin` [query, array] — The criticality that each asset belongs to (not in)
- `infectionStatus__nin` [query, array] — The status alerts of the asset (not in)
- `data_types__contains` [query, array] — Data types contains
- `missingCoverage` [query, array] — The missing coverage for the asset
- `allTagsKeyValue` [query, array] — User and cloud tags
- `cloudProviderAccountName__nin` [query, array] — The cloud provider account name (not in)
- `tagsKey__nin` [query, array] — Tag Keys (not in)
- `cloudResourceId__contains` [query, array] — The cloud resource ID
- `cloudProviderSubscriptionId__contains` [query, array] — The cloud provider subscription ID
- `tagsKey__exists` [query, array] — Tag Keys exists
- `scanStatus__nin` [query, array] — The CDS malware scan status (not in)
- `region` [query, array] — The region
- `encryptionType__nin` [query, array] — The encryption type (not in)
- `tagsKeyValue__contains` [query, array] — Free-text filter by tag key value (supports multiple values)
- `cloudTagsKey__nin` [query, array] — The cloud tags key (not in)
- `tagsKey` [query, array] — Tag Keys
- `riskFactors__nin` [query, array] — The risk factors associated with the asset (not in)
- `tagsKey__nexists` [query, array] — Tag Keys not exists
- `cloudProviderAccountId__contains` [query, array] — The cloud provider account ID
- `imageName__contains` [query, array] — Free-text filter by the image name
- `groupIds` [query, array] — List of Group IDs to filter by
- `key` [query, string] **required** (enum: resourceType__contains, scanStatus__contains, threatDetectionStatus__contains, cloudProviderOrganization__contains, cloudProviderOrganizationUnit__contains, cloudProviderProjectId__contains, cloudProviderSubscriptionId__contains, cloudProviderAccountName__contains, cloudProviderAccountId__contains, cloudTagsKey__contains, cloudTagsKeyValue__contains, cloudResourceId__contains, region__contains, id__contains, name__contains, tagsKey__contains, tagsKeyValue__contains, dataClassificationStatus__contains, dataTypes__contains, imageName__contains) — Search field key
- `threatDetectionStatus__nin` [query, array] — Threat Detection Status (not in)
- `activeCoverage__nin` [query, array] — The active coverage for the asset (not in)
- `data_classification_status__contains` [query, array] — Data classification status
- `allTagsKeyValue__nin` [query, array] — User and cloud tags (not in)
- `region__nin` [query, array] — The region (not in)
- `allTagsKey__nin` [query, array] — User and cloud tag keys (not in)
- `cloudTagsKeyValue__nin` [query, array] — The cloud tags key value (not in)
- `surfaces` [query, array] — The Surface that each asset belongs to
- `objectCount__nin` [query, array] — The number of objects in the bucket (not in)
- `missingCoverage__nin` [query, array] — The missing coverage for the asset (not in)
- `assetStatus__nin` [query, array] — The status of the asset (not in)
- `text` [query, string] **required** — Search term text
- `region__contains` [query, array] — The geographical area where cloud resources are hosted
- `deviceReview__nin` [query, array] — The asset review (not in)
- `threatDetectionPolicyStatus` [query, array] — Threat Detection Policy
- `cloudProviderAccountName` [query, array] — The cloud provider account name
- `assetContactEmail__nin` [query, array] — Asset Contact Email (not in)
- `alertSeverity` [query, array] — The severity of the alert
- `accountIds` [query, array] — List of Account IDs to filter by
- `cloudTagsKeyValue` [query, array] — The cloud tags key value
- `resourceType__nin` [query, array] — The canonical name for the resource type (not in)
- `assetContactEmail` [query, array] — Asset Contact Email
- `data_classification_scan_status__contains` [query, array] — Data classification scan status
- `riskFactors` [query, array] — The risk factors associated with the asset
- `assetEnvironment` [query, array] — The environment that the asset exists in - AWS | Azure | GCP | Active Directory
- `objectCount` [query, array] — The number of objects in the bucket
- `surfaces__nin` [query, array] — The Surface that each asset belongs to (not in)
- `dataTypes` [query, array] — Data Types
- `encryptionType` [query, array] — The encryption type
- `id__in` [query, array] — The ID
- `cloudTagsKeyValue__contains` [query, array] — Free-text filter by cloud tag key value (supports multiple values)
- `resourceType__contains` [query, array] — The Asset Type
- `tagsKeyValue` [query, array] — Tags
- `isPublic` [query, array] — Whether there is public access or not
- `cloudProviderOrganizationUnit__contains` [query, array] — The cloud provider organization unit
- `cloudProviderOrganization__contains` [query, array] — The cloud provider organization
- `dataClassificationScanStatus` [query, array] — Data classification scan status to exclude
- `isPublic__nin` [query, array] — Whether there is public access or not (not in)
- `dataTypes__nin` [query, array] — Data Types (not in)
- `names` [query, array] — Name
- `name__contains` [query, array] — The name
- `assetCriticality` [query, array] — The criticality that each asset belongs to
- `threatDetectionStatus__contains` [query, array] — The threat detection status
- `cloudProviderAccountId__nin` [query, array] — The cloud provider account id (not in)
- `allTagsKey__nexists` [query, array] — User and cloud tag keys not exists
- `siteIds` [query, array] — List of Site IDs to filter by
- `s1UpdatedAt__between` [query, string] — The Last Seen date and time for the asset
- `resourceType` [query, array] — The canonical name for the resource type
- `assetEnvironment__nin` [query, array] — The environment that the asset exists in - AWS | Azure | GCP | Active Directory (not in)
- `names__nin` [query, array] — Name (not in)
- `cloudTagsKey` [query, array] — The cloud tags key
- `subCategory__nin` [query, array] — The sub-category that each resource belongs to (not in)
- `infectionStatus` [query, array] — The status alerts of the asset
- `connectivityStatus` [query, array] — Connectivity
- `activeCoverage` [query, array] — The active coverage for the asset
- `countsFor` [query, array] — The columns for which filter count would be returned for
- `csvFilterId` [query, integer] — The ID of the CSV file to filter by
- `threatDetectionStatus` [query, array] — Threat Detection Status
- `dataClassificationPolicyStatus` [query, array] — Data Classification Policy
- `cloudProviderAccountId` [query, array] — The cloud provider account id
- `subCategory` [query, array] — The sub-category that each resource belongs to
- `dataClassificationStatus` [query, array] — Data Classification Status
- `deviceReview` [query, array] — The asset review
- `allTagsKey` [query, array] — User and cloud tag keys
- `limit` [query, integer] — Limit number of returned items
- `scanStatus__contains` [query, array] — The CDS malware scan status
- `id__contains` [query, array] — The ID
- `cloudProviderAccountName__contains` [query, array] — The cloud provider account name
- `scannerStatus` [query, array] — Scanner
- `assetStatus` [query, array] — The status of the asset
- `versioningEnabled` [query, array] — Whether there is versioning enabled or not
- `cloudTagsKey__contains` [query, array] — Free-text filter by cloud tag key (supports multiple values)
- `tagsKeyValue__nin` [query, array] — Tags (not in)
- `allTagsKey__exists` [query, array] — User and cloud tag keys exists
- `dataClassificationStatus__nin` [query, array] — Data Classification Status (not in)
- `scanStatus` [query, array] — The CDS malware scan status
- `cloudProviderProjectId__contains` [query, array] — The cloud provider project ID

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/xdr/assets/storage/filters/count`
**Filter counts**
`operationId`: `_web_api_xdr_assets_storage_filters_count_get`

Get filter counts

Required permissions: `XDR Inventory.view`

Parameters:
- `tagsKey__contains` [query, array] — Free-text filter by tag key (supports multiple values)
- `assetCriticality__nin` [query, array] — The criticality that each asset belongs to (not in)
- `infectionStatus__nin` [query, array] — The status alerts of the asset (not in)
- `data_types__contains` [query, array] — Data types contains
- `missingCoverage` [query, array] — The missing coverage for the asset
- `allTagsKeyValue` [query, array] — User and cloud tags
- `cloudProviderAccountName__nin` [query, array] — The cloud provider account name (not in)
- `tagsKey__nin` [query, array] — Tag Keys (not in)
- `cloudResourceId__contains` [query, array] — The cloud resource ID
- `cloudProviderSubscriptionId__contains` [query, array] — The cloud provider subscription ID
- `tagsKey__exists` [query, array] — Tag Keys exists
- `scanStatus__nin` [query, array] — The CDS malware scan status (not in)
- `region` [query, array] — The region
- `encryptionType__nin` [query, array] — The encryption type (not in)
- `tagsKeyValue__contains` [query, array] — Free-text filter by tag key value (supports multiple values)
- `cloudTagsKey__nin` [query, array] — The cloud tags key (not in)
- `tagsKey` [query, array] — Tag Keys
- `riskFactors__nin` [query, array] — The risk factors associated with the asset (not in)
- `tagsKey__nexists` [query, array] — Tag Keys not exists
- `cloudProviderAccountId__contains` [query, array] — The cloud provider account ID
- `imageName__contains` [query, array] — Free-text filter by the image name
- `groupIds` [query, array] — List of Group IDs to filter by
- `threatDetectionStatus__nin` [query, array] — Threat Detection Status (not in)
- `activeCoverage__nin` [query, array] — The active coverage for the asset (not in)
- `data_classification_status__contains` [query, array] — Data classification status
- `allTagsKeyValue__nin` [query, array] — User and cloud tags (not in)
- `region__nin` [query, array] — The region (not in)
- `allTagsKey__nin` [query, array] — User and cloud tag keys (not in)
- `cloudTagsKeyValue__nin` [query, array] — The cloud tags key value (not in)
- `surfaces` [query, array] — The Surface that each asset belongs to
- `objectCount__nin` [query, array] — The number of objects in the bucket (not in)
- `missingCoverage__nin` [query, array] — The missing coverage for the asset (not in)
- `assetStatus__nin` [query, array] — The status of the asset (not in)
- `region__contains` [query, array] — The geographical area where cloud resources are hosted
- `deviceReview__nin` [query, array] — The asset review (not in)
- `threatDetectionPolicyStatus` [query, array] — Threat Detection Policy
- `cloudProviderAccountName` [query, array] — The cloud provider account name
- `assetContactEmail__nin` [query, array] — Asset Contact Email (not in)
- `alertSeverity` [query, array] — The severity of the alert
- `accountIds` [query, array] — List of Account IDs to filter by
- `cloudTagsKeyValue` [query, array] — The cloud tags key value
- `resourceType__nin` [query, array] — The canonical name for the resource type (not in)
- `assetContactEmail` [query, array] — Asset Contact Email
- `data_classification_scan_status__contains` [query, array] — Data classification scan status
- `riskFactors` [query, array] — The risk factors associated with the asset
- `assetEnvironment` [query, array] — The environment that the asset exists in - AWS | Azure | GCP | Active Directory
- `objectCount` [query, array] — The number of objects in the bucket
- `surfaces__nin` [query, array] — The Surface that each asset belongs to (not in)
- `dataTypes` [query, array] — Data Types
- `encryptionType` [query, array] — The encryption type
- `id__in` [query, array] — The ID
- `cloudTagsKeyValue__contains` [query, array] — Free-text filter by cloud tag key value (supports multiple values)
- `resourceType__contains` [query, array] — The Asset Type
- `tagsKeyValue` [query, array] — Tags
- `isPublic` [query, array] — Whether there is public access or not
- `cloudProviderOrganizationUnit__contains` [query, array] — The cloud provider organization unit
- `cloudProviderOrganization__contains` [query, array] — The cloud provider organization
- `dataClassificationScanStatus` [query, array] — Data classification scan status to exclude
- `isPublic__nin` [query, array] — Whether there is public access or not (not in)
- `dataTypes__nin` [query, array] — Data Types (not in)
- `names` [query, array] — Name
- `name__contains` [query, array] — The name
- `assetCriticality` [query, array] — The criticality that each asset belongs to
- `threatDetectionStatus__contains` [query, array] — The threat detection status
- `cloudProviderAccountId__nin` [query, array] — The cloud provider account id (not in)
- `allTagsKey__nexists` [query, array] — User and cloud tag keys not exists
- `siteIds` [query, array] — List of Site IDs to filter by
- `s1UpdatedAt__between` [query, string] — The Last Seen date and time for the asset
- `resourceType` [query, array] — The canonical name for the resource type
- `assetEnvironment__nin` [query, array] — The environment that the asset exists in - AWS | Azure | GCP | Active Directory (not in)
- `names__nin` [query, array] — Name (not in)
- `cloudTagsKey` [query, array] — The cloud tags key
- `subCategory__nin` [query, array] — The sub-category that each resource belongs to (not in)
- `infectionStatus` [query, array] — The status alerts of the asset
- `connectivityStatus` [query, array] — Connectivity
- `activeCoverage` [query, array] — The active coverage for the asset
- `countsFor` [query, array] — The columns for which filter count would be returned for
- `csvFilterId` [query, integer] — The ID of the CSV file to filter by
- `threatDetectionStatus` [query, array] — Threat Detection Status
- `dataClassificationPolicyStatus` [query, array] — Data Classification Policy
- `cloudProviderAccountId` [query, array] — The cloud provider account id
- `subCategory` [query, array] — The sub-category that each resource belongs to
- `dataClassificationStatus` [query, array] — Data Classification Status
- `deviceReview` [query, array] — The asset review
- `allTagsKey` [query, array] — User and cloud tag keys
- `scanStatus__contains` [query, array] — The CDS malware scan status
- `id__contains` [query, array] — The ID
- `cloudProviderAccountName__contains` [query, array] — The cloud provider account name
- `scannerStatus` [query, array] — Scanner
- `assetStatus` [query, array] — The status of the asset
- `versioningEnabled` [query, array] — Whether there is versioning enabled or not
- `cloudTagsKey__contains` [query, array] — Free-text filter by cloud tag key (supports multiple values)
- `tagsKeyValue__nin` [query, array] — Tags (not in)
- `allTagsKey__exists` [query, array] — User and cloud tag keys exists
- `dataClassificationStatus__nin` [query, array] — Data Classification Status (not in)
- `scanStatus` [query, array] — The CDS malware scan status
- `cloudProviderProjectId__contains` [query, array] — The cloud provider project ID

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/xdr/assets/storage/filters/free-text`
**Free text filters**
`operationId`: `_web_api_xdr_assets_storage_filters_free-text_get`

Get free text filters

Required permissions: `XDR Inventory.view`

Responses: 200 Success, 401 Unauthorized access - please sign in and retry.
