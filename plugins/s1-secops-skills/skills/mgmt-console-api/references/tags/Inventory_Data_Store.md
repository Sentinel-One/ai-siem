# Inventory Data Store

5 endpoints.

## `GET /web/api/v2.1/xdr/assets/data-store`
**Assets**
`operationId`: `_web_api_xdr_assets_data-store_get`

Get assets

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
- `skip` [query, integer] — Skip first number of items (0-1000). To iterate over more than 1000 items,  use "cursor".
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
- `sortBy` [query, string] (enum: s1GroupName, monitoringEnabled, cnsMonitorTargetEnabled, loggingEnabled, encryptionEnabled, s1UpdatedAt, cnsVolumeGroupIdExists, cnsRetentionDays, cloudProviderResourceGroup, cnsReadReplicaSourceDbInstanceIdentifierExists, cnsHasRecurringScansEmails, replicationEnabled, region, cloudProviderOrganization, cnsAccessLevel, s1ManagementId, storageType, enabledBlobAuditingPolicy, instanceCount, enabledVulnerabilityAssessmentSetting, cloudProviderOrganizationUnit, cnsStatus, cnsSseDescriptionEnabled, s1SiteId, s1SiteName, cnsKmsKeyId, cnsMfaRequiredForDelete, category, realtimeMalwareProtectionEnabledTime, s1GroupId, threatDetectionPolicyStatus, cnsGrant, multiAzEnabled, cnsEmailAdmins, cloudProviderAccountName, engineVersion, cnsFlexibleEndIpAddress, firewallRulesEnabled, cnsValue, softDeleteEnabled, s1OnboardedAccountId, accessTier, backupRetentionPeriodDays, cloudResourceId, cnsPricingTier, assetContactEmail, immutableStorageEnabled, s1ScopeType, assetEnvironment, objectCount, s1AccountId, enabledAlertPolicy, cnsLocked, id, allowsUnencryptedObjectUploads, cnsHasOwnerOrAdminRoles, s1AccountName, backupEnabled, s1ScopeLevel, cloudProviderUrlString, cnsHasSecurityContactsEmails, highAvailabilityEnabled, geoRedundantBackupEnabled, isPublic, cnsCopyTagsToSnapshot, cnsEncryptedStorage, serverAdminLogin, s1OnboardedAccountName, s1OnboardedScopeLevel, createdTime, dataClassificationScanStatus, cnsDefenderNotificationByRoleState, cnsHasEmailConfigured, name, assetCriticality, s1ScopePath, isSynapseCreatedServer, cloudProviderSubscriptionId, s1OnboardedGroupName, engineType, cnsGetObjectAccess, lastScanDt, cloudProviderOrganizationUnitPath, s1OnboardedSiteName, s1ScopeId, resourceType, cnsEmailAdmin, cnsState, cnsExportCloudwatchLogs, cnsFlexibleStartIpAddress, cnsEndIpAddress, infectionStatus, connectivityStatus, s1OnboardedSiteId, cnsStartIpAddress, threatDetectionStatus, storageSize, backupRetentionPeriod, storageClass, dataClassificationPolicyStatus, cnsLoggingEnabled, cloudProviderProjectId, cnsIsPublic, cloudProviderAccountId, subCategory, s1OnboardedScopeId, deviceReview, dataClassificationStatus, cnsDeletionProtectionEnabled, computeMode, cloudResourceUid, s1OnboardedScopePath, cnsHasRecurringScanEnabled, policyDocument, assetStatus, scannerStatus, virtualNetworkRulesEnabled, cnsObjectVersioningEnabled, versioningEnabled, s1OnboardedGroupId, machineType, cnsAutoMinorVersionUpgrade, dataClassificationLastScanDt, scanStatus) — The column to sort the results by.
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
- `sortOrder` [query, string] (enum: asc, desc) — Sort direction
- `isPublic` [query, array] — Whether there is public access or not
- `cloudProviderOrganizationUnit__contains` [query, array] — The cloud provider organization unit
- `cloudProviderOrganization__contains` [query, array] — The cloud provider organization
- `dataClassificationScanStatus` [query, array] — Data classification scan status to exclude
- `countOnly` [query, boolean] — If true, only total number of items will be returned, without any of the actual objects.
- `isPublic__nin` [query, array] — Whether there is public access or not (not in)
- `dataTypes__nin` [query, array] — Data Types (not in)
- `names` [query, array] — Name
- `name__contains` [query, array] — The name
- `assetCriticality` [query, array] — The criticality that each asset belongs to
- `threatDetectionStatus__contains` [query, array] — The threat detection status
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
- `limit` [query, integer] — Limit number of returned items (1-1000)
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
- `cursor` [query, string] — Cursor position returned by the last request. Use to iterate over more than 1000 items.
- `scanStatus` [query, array] — The CDS malware scan status
- `cloudProviderProjectId__contains` [query, array] — The cloud provider project ID

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/xdr/assets/data-store`
**Assets using POST**
`operationId`: `_web_api_xdr_assets_data-store_post`

POST API to get Assets

Required permissions: `XDR Inventory.view`

Parameters:
- `accountIds` [query, array] — List of Account IDs to filter by
- `siteIds` [query, array] — List of Site IDs to filter by
- `groupIds` [query, array] — List of Group IDs to filter by
- `body` [body, v2_1.inventory.data_store.schemas_DataStoreViewInputSchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/xdr/assets/data-store/action`
**Perform action**
`operationId`: `_web_api_xdr_assets_data-store_action_post`

Perform action on selected assets

Required permissions: `XDR Inventory.create, XDR Inventory.delete`

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
- `body` [body, v2_1.inventory.data_store.schemas_DataStoreActionPayloadSchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/xdr/assets/data-store/available-actions/with-status`
**Available actions**
`operationId`: `_web_api_xdr_assets_data-store_available-actions_with-status_post`

Get available actions

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
- `body` [body, v2_1.inventory.schemas_AffectedResourcesSchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/xdr/assets/data-store/export`
**Export assets to CSV or JSON**
`operationId`: `_web_api_xdr_assets_data-store_export_get`

Returns the results for given inventory filter in a CSV or JSON format

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
- `skip` [query, integer] — Skip first number of items (0-1000). To iterate over more than 1000 items,  use "cursor".
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
- `sortBy` [query, string] (enum: s1GroupName, monitoringEnabled, cnsMonitorTargetEnabled, loggingEnabled, encryptionEnabled, s1UpdatedAt, cnsVolumeGroupIdExists, cnsRetentionDays, cloudProviderResourceGroup, cnsReadReplicaSourceDbInstanceIdentifierExists, cnsHasRecurringScansEmails, replicationEnabled, region, cloudProviderOrganization, cnsAccessLevel, s1ManagementId, storageType, enabledBlobAuditingPolicy, instanceCount, enabledVulnerabilityAssessmentSetting, cloudProviderOrganizationUnit, cnsStatus, cnsSseDescriptionEnabled, s1SiteId, s1SiteName, cnsKmsKeyId, cnsMfaRequiredForDelete, category, realtimeMalwareProtectionEnabledTime, s1GroupId, threatDetectionPolicyStatus, cnsGrant, multiAzEnabled, cnsEmailAdmins, cloudProviderAccountName, engineVersion, cnsFlexibleEndIpAddress, firewallRulesEnabled, cnsValue, softDeleteEnabled, s1OnboardedAccountId, accessTier, backupRetentionPeriodDays, cloudResourceId, cnsPricingTier, assetContactEmail, immutableStorageEnabled, s1ScopeType, assetEnvironment, objectCount, s1AccountId, enabledAlertPolicy, cnsLocked, id, allowsUnencryptedObjectUploads, cnsHasOwnerOrAdminRoles, s1AccountName, backupEnabled, s1ScopeLevel, cloudProviderUrlString, cnsHasSecurityContactsEmails, highAvailabilityEnabled, geoRedundantBackupEnabled, isPublic, cnsCopyTagsToSnapshot, cnsEncryptedStorage, serverAdminLogin, s1OnboardedAccountName, s1OnboardedScopeLevel, createdTime, dataClassificationScanStatus, cnsDefenderNotificationByRoleState, cnsHasEmailConfigured, name, assetCriticality, s1ScopePath, isSynapseCreatedServer, cloudProviderSubscriptionId, s1OnboardedGroupName, engineType, cnsGetObjectAccess, lastScanDt, cloudProviderOrganizationUnitPath, s1OnboardedSiteName, s1ScopeId, resourceType, cnsEmailAdmin, cnsState, cnsExportCloudwatchLogs, cnsFlexibleStartIpAddress, cnsEndIpAddress, infectionStatus, connectivityStatus, s1OnboardedSiteId, cnsStartIpAddress, threatDetectionStatus, storageSize, backupRetentionPeriod, storageClass, dataClassificationPolicyStatus, cnsLoggingEnabled, cloudProviderProjectId, cnsIsPublic, cloudProviderAccountId, subCategory, s1OnboardedScopeId, deviceReview, dataClassificationStatus, cnsDeletionProtectionEnabled, computeMode, cloudResourceUid, s1OnboardedScopePath, cnsHasRecurringScanEnabled, policyDocument, assetStatus, scannerStatus, virtualNetworkRulesEnabled, cnsObjectVersioningEnabled, versioningEnabled, s1OnboardedGroupId, machineType, cnsAutoMinorVersionUpgrade, dataClassificationLastScanDt, scanStatus) — The column to sort the results by.
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
- `sortOrder` [query, string] (enum: asc, desc) — Sort direction
- `isPublic` [query, array] — Whether there is public access or not
- `cloudProviderOrganizationUnit__contains` [query, array] — The cloud provider organization unit
- `cloudProviderOrganization__contains` [query, array] — The cloud provider organization
- `dataClassificationScanStatus` [query, array] — Data classification scan status to exclude
- `countOnly` [query, boolean] — If true, only total number of items will be returned, without any of the actual objects.
- `isPublic__nin` [query, array] — Whether there is public access or not (not in)
- `dataTypes__nin` [query, array] — Data Types (not in)
- `names` [query, array] — Name
- `name__contains` [query, array] — The name
- `assetCriticality` [query, array] — The criticality that each asset belongs to
- `threatDetectionStatus__contains` [query, array] — The threat detection status
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
- `connectivityStatus` [query, array] — Connectivity
- `activeCoverage` [query, array] — The active coverage for the asset
- `countsFor` [query, array] — The columns for which filter count would be returned for
- `csvFilterId` [query, integer] — The ID of the CSV file to filter by
- `threatDetectionStatus` [query, array] — Threat Detection Status
- `exportFormat` [query, string] **required** (enum: csv, json) — Export format
- `dataClassificationPolicyStatus` [query, array] — Data Classification Policy
- `cloudProviderAccountId` [query, array] — The cloud provider account id
- `subCategory` [query, array] — The sub-category that each resource belongs to
- `dataClassificationStatus` [query, array] — Data Classification Status
- `deviceReview` [query, array] — The asset review
- `allTagsKey` [query, array] — User and cloud tag keys
- `limit` [query, integer] — Limit number of returned items (1-1000)
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
- `cursor` [query, string] — Cursor position returned by the last request. Use to iterate over more than 1000 items.
- `scanStatus` [query, array] — The CDS malware scan status
- `cloudProviderProjectId__contains` [query, array] — The cloud provider project ID

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.
