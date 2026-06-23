# Inventory Identity

5 endpoints.

## `GET /web/api/v2.1/xdr/assets/identity`
**Assets**
`operationId`: `_web_api_xdr_assets_identity_get`

Get assets

Required permissions: `XDR Inventory.view`

Parameters:
- `tagsKey__contains` [query, array] — Free-text filter by tag key (supports multiple values)
- `assetCriticality__nin` [query, array] — The criticality that each asset belongs to (not in)
- `infectionStatus__nin` [query, array] — The status alerts of the asset (not in)
- `groupType` [query, array] — The Group Type
- `missingCoverage` [query, array] — The missing coverage for the asset
- `allTagsKeyValue` [query, array] — User and cloud tags
- `cloudProviderAccountName__nin` [query, array] — The cloud provider account name (not in)
- `objectCategory` [query, array] — The Object Category
- `cloudResourceId__contains` [query, array] — The cloud resource ID
- `cloudProviderSubscriptionId__contains` [query, array] — The cloud provider subscription ID
- `tagsKey__nin` [query, array] — Tag Keys (not in)
- `tagsKey__exists` [query, array] — Tag Keys exists
- `region` [query, array] — The region
- `userPrincipalName` [query, array] — The User Principal Name
- `tagsKeyValue__contains` [query, array] — Free-text filter by tag key value (supports multiple values)
- `cloudTagsKey__nin` [query, array] — The cloud tags key (not in)
- `tagsKey` [query, array] — Tag Keys
- `riskFactors__nin` [query, array] — The risk factors associated with the asset (not in)
- `tagsKey__nexists` [query, array] — Tag Keys not exists
- `skip` [query, integer] — Skip first number of items (0-1000). To iterate over more than 1000 items,  use "cursor".
- `cloudProviderAccountId__contains` [query, array] — The cloud provider account ID
- `imageName__contains` [query, array] — Free-text filter by the image name
- `groupIds` [query, array] — List of Group IDs to filter by
- `mail` [query, array] — The Email Address
- `onPremisesSamAccountName__contains` [query, array] — On Premises SAM Account Name
- `activeCoverage__nin` [query, array] — The active coverage for the asset (not in)
- `allTagsKeyValue__nin` [query, array] — User and cloud tags (not in)
- `region__nin` [query, array] — The region (not in)
- `allTagsKey__nin` [query, array] — User and cloud tag keys (not in)
- `samAccountName` [query, array] — The SAM Account Name
- `cloudTagsKeyValue__nin` [query, array] — The cloud tags key value (not in)
- `surfaces` [query, array] — The Surface that each asset belongs to
- `forest` [query, array] — The Forest Name
- `missingCoverage__nin` [query, array] — The missing coverage for the asset (not in)
- `assetStatus__nin` [query, array] — The status of the asset (not in)
- `sortBy` [query, string] (enum: s1GroupName, recycled, groupType, s1UpdatedAt, objectCategory, cloudProviderResourceGroup, resultantPso, region, cloudProviderOrganization, logonCount, s1ManagementId, userPrincipalName, distinguishedName, creatorSid, entraidGroupType, classification, cloudProviderOrganizationUnit, mail, accountStatus, lastLogonTime, objectSid, consistencyGuid, s1SiteId, samAccountName, onPremisesLastSyncTime, s1SiteName, forest, privileged, onPremisesSecurityIdentifier, passwordNeverExpire, category, s1GroupId, cloudProviderAccountName, deleted, securityEnabled, onPremisesSyncEnabled, officeLocation, displayName, lastModifiedTime, parentDistName, primaryGroupId, lastKnownParent, s1OnboardedAccountId, expirationTime, onPremisesDistinguishedName, cn, cloudResourceId, onPremisesUserPrincipalName, passwordLastSetTime, assetContactEmail, s1ScopeType, assetEnvironment, s1AccountId, badPasswordCount, givenName, id, s1AccountName, s1ScopeLevel, cloudProviderUrlString, forceChangePasswordNextSigninWithMfa, accountExpires, badPasswordTime, s1OnboardedAccountName, s1OnboardedScopeLevel, createdTime, jobTitle, userAccountControl, name, ageGroup, assetCriticality, s1ScopePath, s1OnboardedGroupName, cloudProviderSubscriptionId, cloudProviderOrganizationUnitPath, s1OnboardedSiteName, s1ScopeId, deletedTime, resourceType, serviceAccount, infectionStatus, objectGuid, s1OnboardedSiteId, ntSecurityDescriptor, allowedToActOnBehalfOfOtherIdentity, cloudProviderProjectId, onPremisesSamAccountName, uniqueName, lastPasswordChangeTime, cloudProviderAccountId, subCategory, s1OnboardedScopeId, onPremisesImmutableId, deviceReview, usnChanged, department, logonHours, samAccountType, principalName, visibility, cloudResourceUid, s1OnboardedScopePath, employeeType, lockOutTime, assetStatus, whenChanged, surname, s1OnboardedGroupId, forceChangePasswordNextSignin, userPasswordExpiryTimeComputed, adminCount, usnCreated, domain, onPremisesDomainName, enabled) — The column to sort the results by.
- `onPremisesUserPrincipalName__contains` [query, array] — On Premises User Principal Name
- `privileged` [query, array] — Whether the AD Entity is privileged or not
- `passwordNeverExpire` [query, array] — Whether the password never expires
- `region__contains` [query, array] — The geographical area where cloud resources are hosted
- `deviceReview__nin` [query, array] — The asset review (not in)
- `cloudProviderAccountName` [query, array] — The cloud provider account name
- `deleted` [query, array] — Whether the AD Entity is deleted or not
- `assetContactEmail__nin` [query, array] — Asset Contact Email (not in)
- `alertSeverity` [query, array] — The severity of the alert
- `mail__contains` [query, array] — The Email Address
- `cloudTagsKeyValue` [query, array] — The cloud tags key value
- `accountIds` [query, array] — List of Account IDs to filter by
- `onPremisesDistinguishedName__contains` [query, array] — 
- `domain__contains` [query, array] — The AD Domain Name
- `resourceType__nin` [query, array] — The canonical name for the resource type (not in)
- `cn` [query, array] — The LDAP Common Name
- `cn__contains` [query, array] — The LDAP Common Name
- `cn__nin` [query, array] — The LDAP Common Name (not in)
- `onPremisesDomainName__contains` [query, array] — On Premises Distinguished Name
- `lastLogonTime__between` [query, string] — The Last time of User Login
- `assetContactEmail` [query, array] — Asset Contact Email
- `riskFactors` [query, array] — The risk factors associated with the asset
- `objectClass__nin` [query, array] — The Object Class (not in)
- `assetEnvironment` [query, array] — The environment that the asset exists in - AWS | Azure | GCP | Active Directory
- `surfaces__nin` [query, array] — The Surface that each asset belongs to (not in)
- `forest__nin` [query, array] — The Forest Name (not in)
- `onPremisesSecurityIdentifier__contains` [query, array] — 
- `id__in` [query, array] — The ID
- `cloudTagsKeyValue__contains` [query, array] — Free-text filter by cloud tag key value (supports multiple values)
- `resourceType__contains` [query, array] — The Asset Type
- `tagsKeyValue` [query, array] — Tags
- `sortOrder` [query, string] (enum: asc, desc) — Sort direction
- `cloudProviderOrganizationUnit__contains` [query, array] — The cloud provider organization unit
- `cloudProviderOrganization__contains` [query, array] — The cloud provider organization
- `countOnly` [query, boolean] — If true, only total number of items will be returned, without any of the actual objects.
- `samAccountName__nin` [query, array] — The SAM Account Name (not in)
- `objectSid__contains` [query, array] — The Object SID
- `groupType__nin` [query, array] — The Group Type (not in)
- `userAccountControl` [query, array] — The User Account Control
- `names` [query, array] — Name
- `proxyAddresses__contains` [query, array] — Proxy Addresses
- `objectGuid__contains` [query, array] — The Object GUID
- `name__contains` [query, array] — The name
- `assetCriticality` [query, array] — The criticality that each asset belongs to
- `cloudProviderAccountId__nin` [query, array] — The cloud provider account id (not in)
- `lockOutTime__between` [query, string] — Lock-out Time
- `skipCount` [query, boolean] — If true, total number of items will not be calculated, which speeds up execution time.
- `allTagsKey__nexists` [query, array] — User and cloud tag keys not exists
- `servicePrincipalName__contains` [query, array] — The Service Principal Name
- `siteIds` [query, array] — List of Site IDs to filter by
- `s1UpdatedAt__between` [query, string] — The Last Seen date and time for the asset
- `resourceType` [query, array] — The canonical name for the resource type
- `assetEnvironment__nin` [query, array] — The environment that the asset exists in - AWS | Azure | GCP | Active Directory (not in)
- `names__nin` [query, array] — Name (not in)
- `cloudTagsKey` [query, array] — The cloud tags key
- `subCategory__nin` [query, array] — The sub-category that each resource belongs to (not in)
- `serviceAccount` [query, array] — The Service Account
- `infectionStatus` [query, array] — The status alerts of the asset
- `givenName__contains` [query, array] — Given Name
- `activeCoverage` [query, array] — The active coverage for the asset
- `countsFor` [query, array] — The columns for which filter count would be returned for
- `csvFilterId` [query, integer] — The ID of the CSV file to filter by
- `userPrincipalName__contains` [query, array] — The User Principal Name
- `cloudProviderAccountId` [query, array] — The cloud provider account id
- `subCategory` [query, array] — The sub-category that each resource belongs to
- `deviceReview` [query, array] — The asset review
- `allTagsKey` [query, array] — User and cloud tag keys
- `otherMails__contains` [query, array] — Other Mails
- `limit` [query, integer] — Limit number of returned items (1-1000)
- `distinguishedName__contains` [query, array] — The Distinguished Name
- `objectClass` [query, array] — The Object Class
- `forest__contains` [query, array] — The Forest Name
- `badPasswordTime__between` [query, string] — Bad Password Time
- `last_modified_time__between` [query, string] — Lock-out Time
- `displayName__contains` [query, array] — The Display Name
- `id__contains` [query, array] — The ID
- `cloudProviderAccountName__contains` [query, array] — The cloud provider account name
- `assetStatus` [query, array] — The status of the asset
- `domain__nin` [query, array] — The AD Domain Name (not in)
- `cloudTagsKey__contains` [query, array] — Free-text filter by cloud tag key (supports multiple values)
- `tagsKeyValue__nin` [query, array] — Tags (not in)
- `allTagsKey__exists` [query, array] — User and cloud tag keys exists
- `objectCategory__nin` [query, array] — The Object Category (not in)
- `userAccountControl__nin` [query, array] — The User Account Control (not in)
- `domain` [query, array] — The AD Domain Name
- `userPasswordExpiryTimeComputed__between` [query, string] — The User Password Expiry Time
- `cursor` [query, string] — Cursor position returned by the last request. Use to iterate over more than 1000 items.
- `enabled` [query, array] — Whether the Identity Group is enabled or not
- `userPrincipalName__nin` [query, array] — The User Principal Name (not in)
- `cloudProviderProjectId__contains` [query, array] — The cloud provider project ID

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/xdr/assets/identity`
**Assets using POST**
`operationId`: `_web_api_xdr_assets_identity_post`

POST API to get Assets

Required permissions: `XDR Inventory.view`

Parameters:
- `accountIds` [query, array] — List of Account IDs to filter by
- `siteIds` [query, array] — List of Site IDs to filter by
- `groupIds` [query, array] — List of Group IDs to filter by
- `body` [body, v2_1.inventory.identity.schemas_IdentityViewInputSchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/xdr/assets/identity/action`
**Perform action**
`operationId`: `_web_api_xdr_assets_identity_action_post`

Perform action on selected assets

Required permissions: `XDR Inventory.create, XDR Inventory.delete`

Parameters:
- `tagsKey__contains` [query, array] — Free-text filter by tag key (supports multiple values)
- `assetCriticality__nin` [query, array] — The criticality that each asset belongs to (not in)
- `infectionStatus__nin` [query, array] — The status alerts of the asset (not in)
- `groupType` [query, array] — The Group Type
- `missingCoverage` [query, array] — The missing coverage for the asset
- `allTagsKeyValue` [query, array] — User and cloud tags
- `cloudProviderAccountName__nin` [query, array] — The cloud provider account name (not in)
- `objectCategory` [query, array] — The Object Category
- `cloudResourceId__contains` [query, array] — The cloud resource ID
- `cloudProviderSubscriptionId__contains` [query, array] — The cloud provider subscription ID
- `tagsKey__nin` [query, array] — Tag Keys (not in)
- `tagsKey__exists` [query, array] — Tag Keys exists
- `region` [query, array] — The region
- `userPrincipalName` [query, array] — The User Principal Name
- `tagsKeyValue__contains` [query, array] — Free-text filter by tag key value (supports multiple values)
- `cloudTagsKey__nin` [query, array] — The cloud tags key (not in)
- `tagsKey` [query, array] — Tag Keys
- `riskFactors__nin` [query, array] — The risk factors associated with the asset (not in)
- `tagsKey__nexists` [query, array] — Tag Keys not exists
- `cloudProviderAccountId__contains` [query, array] — The cloud provider account ID
- `imageName__contains` [query, array] — Free-text filter by the image name
- `groupIds` [query, array] — List of Group IDs to filter by
- `mail` [query, array] — The Email Address
- `onPremisesSamAccountName__contains` [query, array] — On Premises SAM Account Name
- `activeCoverage__nin` [query, array] — The active coverage for the asset (not in)
- `allTagsKeyValue__nin` [query, array] — User and cloud tags (not in)
- `region__nin` [query, array] — The region (not in)
- `allTagsKey__nin` [query, array] — User and cloud tag keys (not in)
- `samAccountName` [query, array] — The SAM Account Name
- `cloudTagsKeyValue__nin` [query, array] — The cloud tags key value (not in)
- `surfaces` [query, array] — The Surface that each asset belongs to
- `forest` [query, array] — The Forest Name
- `missingCoverage__nin` [query, array] — The missing coverage for the asset (not in)
- `assetStatus__nin` [query, array] — The status of the asset (not in)
- `onPremisesUserPrincipalName__contains` [query, array] — On Premises User Principal Name
- `privileged` [query, array] — Whether the AD Entity is privileged or not
- `passwordNeverExpire` [query, array] — Whether the password never expires
- `region__contains` [query, array] — The geographical area where cloud resources are hosted
- `deviceReview__nin` [query, array] — The asset review (not in)
- `cloudProviderAccountName` [query, array] — The cloud provider account name
- `deleted` [query, array] — Whether the AD Entity is deleted or not
- `assetContactEmail__nin` [query, array] — Asset Contact Email (not in)
- `alertSeverity` [query, array] — The severity of the alert
- `mail__contains` [query, array] — The Email Address
- `cloudTagsKeyValue` [query, array] — The cloud tags key value
- `accountIds` [query, array] — List of Account IDs to filter by
- `onPremisesDistinguishedName__contains` [query, array] — 
- `domain__contains` [query, array] — The AD Domain Name
- `resourceType__nin` [query, array] — The canonical name for the resource type (not in)
- `cn` [query, array] — The LDAP Common Name
- `cn__contains` [query, array] — The LDAP Common Name
- `cn__nin` [query, array] — The LDAP Common Name (not in)
- `onPremisesDomainName__contains` [query, array] — On Premises Distinguished Name
- `lastLogonTime__between` [query, string] — The Last time of User Login
- `assetContactEmail` [query, array] — Asset Contact Email
- `riskFactors` [query, array] — The risk factors associated with the asset
- `objectClass__nin` [query, array] — The Object Class (not in)
- `assetEnvironment` [query, array] — The environment that the asset exists in - AWS | Azure | GCP | Active Directory
- `surfaces__nin` [query, array] — The Surface that each asset belongs to (not in)
- `forest__nin` [query, array] — The Forest Name (not in)
- `onPremisesSecurityIdentifier__contains` [query, array] — 
- `id__in` [query, array] — The ID
- `cloudTagsKeyValue__contains` [query, array] — Free-text filter by cloud tag key value (supports multiple values)
- `resourceType__contains` [query, array] — The Asset Type
- `tagsKeyValue` [query, array] — Tags
- `cloudProviderOrganizationUnit__contains` [query, array] — The cloud provider organization unit
- `cloudProviderOrganization__contains` [query, array] — The cloud provider organization
- `samAccountName__nin` [query, array] — The SAM Account Name (not in)
- `objectSid__contains` [query, array] — The Object SID
- `groupType__nin` [query, array] — The Group Type (not in)
- `userAccountControl` [query, array] — The User Account Control
- `names` [query, array] — Name
- `proxyAddresses__contains` [query, array] — Proxy Addresses
- `objectGuid__contains` [query, array] — The Object GUID
- `name__contains` [query, array] — The name
- `assetCriticality` [query, array] — The criticality that each asset belongs to
- `cloudProviderAccountId__nin` [query, array] — The cloud provider account id (not in)
- `lockOutTime__between` [query, string] — Lock-out Time
- `allTagsKey__nexists` [query, array] — User and cloud tag keys not exists
- `servicePrincipalName__contains` [query, array] — The Service Principal Name
- `siteIds` [query, array] — List of Site IDs to filter by
- `s1UpdatedAt__between` [query, string] — The Last Seen date and time for the asset
- `resourceType` [query, array] — The canonical name for the resource type
- `assetEnvironment__nin` [query, array] — The environment that the asset exists in - AWS | Azure | GCP | Active Directory (not in)
- `names__nin` [query, array] — Name (not in)
- `cloudTagsKey` [query, array] — The cloud tags key
- `subCategory__nin` [query, array] — The sub-category that each resource belongs to (not in)
- `serviceAccount` [query, array] — The Service Account
- `infectionStatus` [query, array] — The status alerts of the asset
- `givenName__contains` [query, array] — Given Name
- `activeCoverage` [query, array] — The active coverage for the asset
- `countsFor` [query, array] — The columns for which filter count would be returned for
- `csvFilterId` [query, integer] — The ID of the CSV file to filter by
- `userPrincipalName__contains` [query, array] — The User Principal Name
- `cloudProviderAccountId` [query, array] — The cloud provider account id
- `subCategory` [query, array] — The sub-category that each resource belongs to
- `deviceReview` [query, array] — The asset review
- `allTagsKey` [query, array] — User and cloud tag keys
- `otherMails__contains` [query, array] — Other Mails
- `distinguishedName__contains` [query, array] — The Distinguished Name
- `objectClass` [query, array] — The Object Class
- `forest__contains` [query, array] — The Forest Name
- `badPasswordTime__between` [query, string] — Bad Password Time
- `last_modified_time__between` [query, string] — Lock-out Time
- `displayName__contains` [query, array] — The Display Name
- `id__contains` [query, array] — The ID
- `cloudProviderAccountName__contains` [query, array] — The cloud provider account name
- `assetStatus` [query, array] — The status of the asset
- `domain__nin` [query, array] — The AD Domain Name (not in)
- `cloudTagsKey__contains` [query, array] — Free-text filter by cloud tag key (supports multiple values)
- `tagsKeyValue__nin` [query, array] — Tags (not in)
- `allTagsKey__exists` [query, array] — User and cloud tag keys exists
- `objectCategory__nin` [query, array] — The Object Category (not in)
- `userAccountControl__nin` [query, array] — The User Account Control (not in)
- `domain` [query, array] — The AD Domain Name
- `userPasswordExpiryTimeComputed__between` [query, string] — The User Password Expiry Time
- `enabled` [query, array] — Whether the Identity Group is enabled or not
- `userPrincipalName__nin` [query, array] — The User Principal Name (not in)
- `cloudProviderProjectId__contains` [query, array] — The cloud provider project ID
- `body` [body, v2_1.inventory.identity.schemas_IdentityActionPayloadSchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/xdr/assets/identity/available-actions/with-status`
**Available actions**
`operationId`: `_web_api_xdr_assets_identity_available-actions_with-status_post`

Get cloud inventory identity available-actions

Required permissions: `XDR Inventory.view`

Parameters:
- `tagsKey__contains` [query, array] — Free-text filter by tag key (supports multiple values)
- `assetCriticality__nin` [query, array] — The criticality that each asset belongs to (not in)
- `infectionStatus__nin` [query, array] — The status alerts of the asset (not in)
- `groupType` [query, array] — The Group Type
- `missingCoverage` [query, array] — The missing coverage for the asset
- `allTagsKeyValue` [query, array] — User and cloud tags
- `cloudProviderAccountName__nin` [query, array] — The cloud provider account name (not in)
- `objectCategory` [query, array] — The Object Category
- `cloudResourceId__contains` [query, array] — The cloud resource ID
- `cloudProviderSubscriptionId__contains` [query, array] — The cloud provider subscription ID
- `tagsKey__nin` [query, array] — Tag Keys (not in)
- `tagsKey__exists` [query, array] — Tag Keys exists
- `region` [query, array] — The region
- `userPrincipalName` [query, array] — The User Principal Name
- `tagsKeyValue__contains` [query, array] — Free-text filter by tag key value (supports multiple values)
- `cloudTagsKey__nin` [query, array] — The cloud tags key (not in)
- `tagsKey` [query, array] — Tag Keys
- `riskFactors__nin` [query, array] — The risk factors associated with the asset (not in)
- `tagsKey__nexists` [query, array] — Tag Keys not exists
- `cloudProviderAccountId__contains` [query, array] — The cloud provider account ID
- `imageName__contains` [query, array] — Free-text filter by the image name
- `groupIds` [query, array] — List of Group IDs to filter by
- `mail` [query, array] — The Email Address
- `onPremisesSamAccountName__contains` [query, array] — On Premises SAM Account Name
- `activeCoverage__nin` [query, array] — The active coverage for the asset (not in)
- `allTagsKeyValue__nin` [query, array] — User and cloud tags (not in)
- `region__nin` [query, array] — The region (not in)
- `allTagsKey__nin` [query, array] — User and cloud tag keys (not in)
- `samAccountName` [query, array] — The SAM Account Name
- `cloudTagsKeyValue__nin` [query, array] — The cloud tags key value (not in)
- `surfaces` [query, array] — The Surface that each asset belongs to
- `forest` [query, array] — The Forest Name
- `missingCoverage__nin` [query, array] — The missing coverage for the asset (not in)
- `assetStatus__nin` [query, array] — The status of the asset (not in)
- `onPremisesUserPrincipalName__contains` [query, array] — On Premises User Principal Name
- `privileged` [query, array] — Whether the AD Entity is privileged or not
- `passwordNeverExpire` [query, array] — Whether the password never expires
- `region__contains` [query, array] — The geographical area where cloud resources are hosted
- `deviceReview__nin` [query, array] — The asset review (not in)
- `cloudProviderAccountName` [query, array] — The cloud provider account name
- `deleted` [query, array] — Whether the AD Entity is deleted or not
- `assetContactEmail__nin` [query, array] — Asset Contact Email (not in)
- `alertSeverity` [query, array] — The severity of the alert
- `mail__contains` [query, array] — The Email Address
- `cloudTagsKeyValue` [query, array] — The cloud tags key value
- `accountIds` [query, array] — List of Account IDs to filter by
- `onPremisesDistinguishedName__contains` [query, array] — 
- `domain__contains` [query, array] — The AD Domain Name
- `resourceType__nin` [query, array] — The canonical name for the resource type (not in)
- `cn` [query, array] — The LDAP Common Name
- `cn__contains` [query, array] — The LDAP Common Name
- `cn__nin` [query, array] — The LDAP Common Name (not in)
- `onPremisesDomainName__contains` [query, array] — On Premises Distinguished Name
- `lastLogonTime__between` [query, string] — The Last time of User Login
- `assetContactEmail` [query, array] — Asset Contact Email
- `riskFactors` [query, array] — The risk factors associated with the asset
- `objectClass__nin` [query, array] — The Object Class (not in)
- `assetEnvironment` [query, array] — The environment that the asset exists in - AWS | Azure | GCP | Active Directory
- `surfaces__nin` [query, array] — The Surface that each asset belongs to (not in)
- `forest__nin` [query, array] — The Forest Name (not in)
- `onPremisesSecurityIdentifier__contains` [query, array] — 
- `id__in` [query, array] — The ID
- `cloudTagsKeyValue__contains` [query, array] — Free-text filter by cloud tag key value (supports multiple values)
- `resourceType__contains` [query, array] — The Asset Type
- `tagsKeyValue` [query, array] — Tags
- `cloudProviderOrganizationUnit__contains` [query, array] — The cloud provider organization unit
- `cloudProviderOrganization__contains` [query, array] — The cloud provider organization
- `samAccountName__nin` [query, array] — The SAM Account Name (not in)
- `objectSid__contains` [query, array] — The Object SID
- `groupType__nin` [query, array] — The Group Type (not in)
- `userAccountControl` [query, array] — The User Account Control
- `names` [query, array] — Name
- `proxyAddresses__contains` [query, array] — Proxy Addresses
- `objectGuid__contains` [query, array] — The Object GUID
- `name__contains` [query, array] — The name
- `assetCriticality` [query, array] — The criticality that each asset belongs to
- `cloudProviderAccountId__nin` [query, array] — The cloud provider account id (not in)
- `lockOutTime__between` [query, string] — Lock-out Time
- `allTagsKey__nexists` [query, array] — User and cloud tag keys not exists
- `servicePrincipalName__contains` [query, array] — The Service Principal Name
- `siteIds` [query, array] — List of Site IDs to filter by
- `s1UpdatedAt__between` [query, string] — The Last Seen date and time for the asset
- `resourceType` [query, array] — The canonical name for the resource type
- `assetEnvironment__nin` [query, array] — The environment that the asset exists in - AWS | Azure | GCP | Active Directory (not in)
- `names__nin` [query, array] — Name (not in)
- `cloudTagsKey` [query, array] — The cloud tags key
- `subCategory__nin` [query, array] — The sub-category that each resource belongs to (not in)
- `serviceAccount` [query, array] — The Service Account
- `infectionStatus` [query, array] — The status alerts of the asset
- `givenName__contains` [query, array] — Given Name
- `activeCoverage` [query, array] — The active coverage for the asset
- `countsFor` [query, array] — The columns for which filter count would be returned for
- `csvFilterId` [query, integer] — The ID of the CSV file to filter by
- `userPrincipalName__contains` [query, array] — The User Principal Name
- `cloudProviderAccountId` [query, array] — The cloud provider account id
- `subCategory` [query, array] — The sub-category that each resource belongs to
- `deviceReview` [query, array] — The asset review
- `allTagsKey` [query, array] — User and cloud tag keys
- `otherMails__contains` [query, array] — Other Mails
- `distinguishedName__contains` [query, array] — The Distinguished Name
- `objectClass` [query, array] — The Object Class
- `forest__contains` [query, array] — The Forest Name
- `badPasswordTime__between` [query, string] — Bad Password Time
- `last_modified_time__between` [query, string] — Lock-out Time
- `displayName__contains` [query, array] — The Display Name
- `id__contains` [query, array] — The ID
- `cloudProviderAccountName__contains` [query, array] — The cloud provider account name
- `assetStatus` [query, array] — The status of the asset
- `domain__nin` [query, array] — The AD Domain Name (not in)
- `cloudTagsKey__contains` [query, array] — Free-text filter by cloud tag key (supports multiple values)
- `tagsKeyValue__nin` [query, array] — Tags (not in)
- `allTagsKey__exists` [query, array] — User and cloud tag keys exists
- `objectCategory__nin` [query, array] — The Object Category (not in)
- `userAccountControl__nin` [query, array] — The User Account Control (not in)
- `domain` [query, array] — The AD Domain Name
- `userPasswordExpiryTimeComputed__between` [query, string] — The User Password Expiry Time
- `enabled` [query, array] — Whether the Identity Group is enabled or not
- `userPrincipalName__nin` [query, array] — The User Principal Name (not in)
- `cloudProviderProjectId__contains` [query, array] — The cloud provider project ID
- `body` [body, v2_1.inventory.schemas_AffectedResourcesSchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/xdr/assets/identity/export`
**Export assets to CSV or JSON**
`operationId`: `_web_api_xdr_assets_identity_export_get`

Returns the results for given inventory filter in a CSV or JSON format

Required permissions: `XDR Inventory.view`

Parameters:
- `tagsKey__contains` [query, array] — Free-text filter by tag key (supports multiple values)
- `assetCriticality__nin` [query, array] — The criticality that each asset belongs to (not in)
- `infectionStatus__nin` [query, array] — The status alerts of the asset (not in)
- `groupType` [query, array] — The Group Type
- `missingCoverage` [query, array] — The missing coverage for the asset
- `allTagsKeyValue` [query, array] — User and cloud tags
- `cloudProviderAccountName__nin` [query, array] — The cloud provider account name (not in)
- `objectCategory` [query, array] — The Object Category
- `cloudResourceId__contains` [query, array] — The cloud resource ID
- `cloudProviderSubscriptionId__contains` [query, array] — The cloud provider subscription ID
- `tagsKey__nin` [query, array] — Tag Keys (not in)
- `tagsKey__exists` [query, array] — Tag Keys exists
- `region` [query, array] — The region
- `userPrincipalName` [query, array] — The User Principal Name
- `tagsKeyValue__contains` [query, array] — Free-text filter by tag key value (supports multiple values)
- `cloudTagsKey__nin` [query, array] — The cloud tags key (not in)
- `tagsKey` [query, array] — Tag Keys
- `riskFactors__nin` [query, array] — The risk factors associated with the asset (not in)
- `tagsKey__nexists` [query, array] — Tag Keys not exists
- `skip` [query, integer] — Skip first number of items (0-1000). To iterate over more than 1000 items,  use "cursor".
- `cloudProviderAccountId__contains` [query, array] — The cloud provider account ID
- `imageName__contains` [query, array] — Free-text filter by the image name
- `groupIds` [query, array] — List of Group IDs to filter by
- `mail` [query, array] — The Email Address
- `onPremisesSamAccountName__contains` [query, array] — On Premises SAM Account Name
- `activeCoverage__nin` [query, array] — The active coverage for the asset (not in)
- `allTagsKeyValue__nin` [query, array] — User and cloud tags (not in)
- `region__nin` [query, array] — The region (not in)
- `allTagsKey__nin` [query, array] — User and cloud tag keys (not in)
- `samAccountName` [query, array] — The SAM Account Name
- `cloudTagsKeyValue__nin` [query, array] — The cloud tags key value (not in)
- `surfaces` [query, array] — The Surface that each asset belongs to
- `forest` [query, array] — The Forest Name
- `missingCoverage__nin` [query, array] — The missing coverage for the asset (not in)
- `assetStatus__nin` [query, array] — The status of the asset (not in)
- `sortBy` [query, string] (enum: s1GroupName, recycled, groupType, s1UpdatedAt, objectCategory, cloudProviderResourceGroup, resultantPso, region, cloudProviderOrganization, logonCount, s1ManagementId, userPrincipalName, distinguishedName, creatorSid, entraidGroupType, classification, cloudProviderOrganizationUnit, mail, accountStatus, lastLogonTime, objectSid, consistencyGuid, s1SiteId, samAccountName, onPremisesLastSyncTime, s1SiteName, forest, privileged, onPremisesSecurityIdentifier, passwordNeverExpire, category, s1GroupId, cloudProviderAccountName, deleted, securityEnabled, onPremisesSyncEnabled, officeLocation, displayName, lastModifiedTime, parentDistName, primaryGroupId, lastKnownParent, s1OnboardedAccountId, expirationTime, onPremisesDistinguishedName, cn, cloudResourceId, onPremisesUserPrincipalName, passwordLastSetTime, assetContactEmail, s1ScopeType, assetEnvironment, s1AccountId, badPasswordCount, givenName, id, s1AccountName, s1ScopeLevel, cloudProviderUrlString, forceChangePasswordNextSigninWithMfa, accountExpires, badPasswordTime, s1OnboardedAccountName, s1OnboardedScopeLevel, createdTime, jobTitle, userAccountControl, name, ageGroup, assetCriticality, s1ScopePath, s1OnboardedGroupName, cloudProviderSubscriptionId, cloudProviderOrganizationUnitPath, s1OnboardedSiteName, s1ScopeId, deletedTime, resourceType, serviceAccount, infectionStatus, objectGuid, s1OnboardedSiteId, ntSecurityDescriptor, allowedToActOnBehalfOfOtherIdentity, cloudProviderProjectId, onPremisesSamAccountName, uniqueName, lastPasswordChangeTime, cloudProviderAccountId, subCategory, s1OnboardedScopeId, onPremisesImmutableId, deviceReview, usnChanged, department, logonHours, samAccountType, principalName, visibility, cloudResourceUid, s1OnboardedScopePath, employeeType, lockOutTime, assetStatus, whenChanged, surname, s1OnboardedGroupId, forceChangePasswordNextSignin, userPasswordExpiryTimeComputed, adminCount, usnCreated, domain, onPremisesDomainName, enabled) — The column to sort the results by.
- `onPremisesUserPrincipalName__contains` [query, array] — On Premises User Principal Name
- `privileged` [query, array] — Whether the AD Entity is privileged or not
- `passwordNeverExpire` [query, array] — Whether the password never expires
- `region__contains` [query, array] — The geographical area where cloud resources are hosted
- `deviceReview__nin` [query, array] — The asset review (not in)
- `cloudProviderAccountName` [query, array] — The cloud provider account name
- `deleted` [query, array] — Whether the AD Entity is deleted or not
- `assetContactEmail__nin` [query, array] — Asset Contact Email (not in)
- `alertSeverity` [query, array] — The severity of the alert
- `mail__contains` [query, array] — The Email Address
- `cloudTagsKeyValue` [query, array] — The cloud tags key value
- `accountIds` [query, array] — List of Account IDs to filter by
- `onPremisesDistinguishedName__contains` [query, array] — 
- `domain__contains` [query, array] — The AD Domain Name
- `resourceType__nin` [query, array] — The canonical name for the resource type (not in)
- `cn` [query, array] — The LDAP Common Name
- `cn__contains` [query, array] — The LDAP Common Name
- `cn__nin` [query, array] — The LDAP Common Name (not in)
- `onPremisesDomainName__contains` [query, array] — On Premises Distinguished Name
- `lastLogonTime__between` [query, string] — The Last time of User Login
- `assetContactEmail` [query, array] — Asset Contact Email
- `riskFactors` [query, array] — The risk factors associated with the asset
- `objectClass__nin` [query, array] — The Object Class (not in)
- `assetEnvironment` [query, array] — The environment that the asset exists in - AWS | Azure | GCP | Active Directory
- `surfaces__nin` [query, array] — The Surface that each asset belongs to (not in)
- `forest__nin` [query, array] — The Forest Name (not in)
- `onPremisesSecurityIdentifier__contains` [query, array] — 
- `id__in` [query, array] — The ID
- `cloudTagsKeyValue__contains` [query, array] — Free-text filter by cloud tag key value (supports multiple values)
- `resourceType__contains` [query, array] — The Asset Type
- `tagsKeyValue` [query, array] — Tags
- `sortOrder` [query, string] (enum: asc, desc) — Sort direction
- `cloudProviderOrganizationUnit__contains` [query, array] — The cloud provider organization unit
- `cloudProviderOrganization__contains` [query, array] — The cloud provider organization
- `countOnly` [query, boolean] — If true, only total number of items will be returned, without any of the actual objects.
- `samAccountName__nin` [query, array] — The SAM Account Name (not in)
- `objectSid__contains` [query, array] — The Object SID
- `groupType__nin` [query, array] — The Group Type (not in)
- `userAccountControl` [query, array] — The User Account Control
- `names` [query, array] — Name
- `proxyAddresses__contains` [query, array] — Proxy Addresses
- `objectGuid__contains` [query, array] — The Object GUID
- `name__contains` [query, array] — The name
- `assetCriticality` [query, array] — The criticality that each asset belongs to
- `cloudProviderAccountId__nin` [query, array] — The cloud provider account id (not in)
- `lockOutTime__between` [query, string] — Lock-out Time
- `skipCount` [query, boolean] — If true, total number of items will not be calculated, which speeds up execution time.
- `allTagsKey__nexists` [query, array] — User and cloud tag keys not exists
- `servicePrincipalName__contains` [query, array] — The Service Principal Name
- `siteIds` [query, array] — List of Site IDs to filter by
- `s1UpdatedAt__between` [query, string] — The Last Seen date and time for the asset
- `resourceType` [query, array] — The canonical name for the resource type
- `assetEnvironment__nin` [query, array] — The environment that the asset exists in - AWS | Azure | GCP | Active Directory (not in)
- `names__nin` [query, array] — Name (not in)
- `cloudTagsKey` [query, array] — The cloud tags key
- `subCategory__nin` [query, array] — The sub-category that each resource belongs to (not in)
- `serviceAccount` [query, array] — The Service Account
- `infectionStatus` [query, array] — The status alerts of the asset
- `givenName__contains` [query, array] — Given Name
- `activeCoverage` [query, array] — The active coverage for the asset
- `countsFor` [query, array] — The columns for which filter count would be returned for
- `csvFilterId` [query, integer] — The ID of the CSV file to filter by
- `exportFormat` [query, string] **required** (enum: csv, json) — Export format
- `userPrincipalName__contains` [query, array] — The User Principal Name
- `cloudProviderAccountId` [query, array] — The cloud provider account id
- `subCategory` [query, array] — The sub-category that each resource belongs to
- `deviceReview` [query, array] — The asset review
- `allTagsKey` [query, array] — User and cloud tag keys
- `otherMails__contains` [query, array] — Other Mails
- `limit` [query, integer] — Limit number of returned items (1-1000)
- `distinguishedName__contains` [query, array] — The Distinguished Name
- `objectClass` [query, array] — The Object Class
- `forest__contains` [query, array] — The Forest Name
- `badPasswordTime__between` [query, string] — Bad Password Time
- `last_modified_time__between` [query, string] — Lock-out Time
- `displayName__contains` [query, array] — The Display Name
- `id__contains` [query, array] — The ID
- `cloudProviderAccountName__contains` [query, array] — The cloud provider account name
- `assetStatus` [query, array] — The status of the asset
- `domain__nin` [query, array] — The AD Domain Name (not in)
- `cloudTagsKey__contains` [query, array] — Free-text filter by cloud tag key (supports multiple values)
- `tagsKeyValue__nin` [query, array] — Tags (not in)
- `allTagsKey__exists` [query, array] — User and cloud tag keys exists
- `objectCategory__nin` [query, array] — The Object Category (not in)
- `userAccountControl__nin` [query, array] — The User Account Control (not in)
- `domain` [query, array] — The AD Domain Name
- `userPasswordExpiryTimeComputed__between` [query, string] — The User Password Expiry Time
- `cursor` [query, string] — Cursor position returned by the last request. Use to iterate over more than 1000 items.
- `enabled` [query, array] — Whether the Identity Group is enabled or not
- `userPrincipalName__nin` [query, array] — The User Principal Name (not in)
- `cloudProviderProjectId__contains` [query, array] — The cloud provider project ID

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.
