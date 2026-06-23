# Inventory Identity Filters

3 endpoints.

## `GET /web/api/v2.1/xdr/assets/identity/filters/autocomplete`
**Auto Complete**
`operationId`: `_web_api_xdr_assets_identity_filters_autocomplete_get`

Use this command to get values for other fields. When you send this command with input text and a field name, it returns auto-complete suggestions for the field.

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
- `key` [query, string] **required** (enum: cn__contains, displayName__contains, distinguishedName__contains, domain__contains, objectGuid__contains, objectSid__contains, servicePrincipalName__contains, forest__contains, resourceType__contains, cloudProviderOrganization__contains, cloudProviderOrganizationUnit__contains, cloudProviderProjectId__contains, cloudProviderSubscriptionId__contains, cloudProviderAccountName__contains, cloudProviderAccountId__contains, cloudTagsKey__contains, cloudTagsKeyValue__contains, cloudResourceId__contains, region__contains, id__contains, name__contains, tagsKey__contains, tagsKeyValue__contains, givenName__contains, onPremisesDistinguishedName__contains, onPremisesDomainName__contains, onPremisesSamAccountName__contains, onPremisesUserPrincipalName__contains, otherMails__contains, proxyAddresses__contains, onPremisesSecurityIdentifier__contains, mail__contains, userPrincipalName__contains, imageName__contains) — Search field key
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
- `text` [query, string] **required** — Search term text
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
- `limit` [query, integer] — Limit number of returned items
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

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/xdr/assets/identity/filters/count`
**Filter counts**
`operationId`: `_web_api_xdr_assets_identity_filters_count_get`

Get filter counts

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

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/xdr/assets/identity/filters/free-text`
**Free text filters**
`operationId`: `_web_api_xdr_assets_identity_filters_free-text_get`

Get free text filters

Required permissions: `XDR Inventory.view`

Responses: 200 Success, 401 Unauthorized access - please sign in and retry.
