# Threat Intelligence

7 endpoints.

## `DELETE /web/api/v2.1/threat-intelligence/iocs`
**Delete IOCs**
`operationId`: `_web_api_threat-intelligence_iocs_delete`

Delete an IoC from the Threat Intelligence database that matches a filter using the accountID and one other field.

Required permissions: `Threat Intelligence.manage`

Parameters:
- `body` [body, v2_1.schemas_IOCDeleteSchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/threat-intelligence/iocs`
**Get IOCs**
`operationId`: `_web_api_threat-intelligence_iocs_get`

Get the IOCs of a specified Account that match the filter.<br>Note: Using creationTime to sort results has been deprecated and should not be used. In the future, the ability to sort by creationTime will be removed. Please sort by uploadTime or updatedAt as an alternative.

Required permissions: `Threat Intelligence.view`

Parameters:
- `creator__contains` [query, array] — Free-text filter by the user uploaded the Threat Intelligence indicator (supports multiple values). Example: "admin@sentinelone.com".
- `creationTime__lt` [query, string] — Creation Time as set by the user lesser than. Example: "2021-07-13T20:33:29.007906Z".
- `creationTime__lte` [query, string] — Creation Time as set by the user lesser or equal than. Example: "2021-07-11T20:33:29.007906Z".
- `severity` [query, array] — A list of severities to filter by (0-7)
- `uploadTime__lte` [query, string] — The time at which the Threat Intelligence indicator was uploaded to SentinelOne DB lesser or equal than. Example: "2022-07-13T20:33:29.007906Z".
- `uuids` [query, array] — A list of unique Ids of the parent process of the indicator of compromise. Example: "2,c,f,f,a,e,8,7,1,1,9,7,f,2,0,d,8,6,4,f,e,8,3,6,3,e,e,e,6,6,5,1".
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "4,2,6,4,1,8,0,3,0,2,1,2,0,7,3,7,6,2".
- `name__contains` [query, array] — Free-text filter by the Indicator name (supports multiple values). Example: "foo.dll".
- `updatedAt__gt` [query, string] — The time at which the indicator was last updated in SentinelOne DB  greater than. Example: "2021-07-13T20:33:29.007906Z".
- `malwareNames__in` [query, array] — A list of malware names to filter by.
- `sortBy` [query, string] (enum: id, creationTime, uploadTime, updatedAt, source, type) — The column to sort the results by. Example: "id".
- `creationTime__gt` [query, string] — Creation Time as set by the user greater than. Example: "2021-07-12T20:33:29.007906Z".
- `threatActorTypes__in` [query, array] — List of threat actor types associated with the indicator.
- `cursor` [query, string] — Cursor position returned by the last request. Use to iterate over more than 1000 items. Example: "YWdlbnRfaWQ6NTgwMjkzODE=".
- `labels__in` [query, array] — List of labels associated with the indicator.
- `type` [query, string] (enum: DNS, IPV4, IPV6, MD5, SHA1, SHA256, URL) — The type of the Threat Intelligence indicator. Example: "IPv4".
- `threatActors__in` [query, array] — A list of threat actors to filter by
- `updatedAt__lt` [query, string] — The time at which the indicator was last updated in SentinelOne DB  lesser than. Example: "2021-07-13T20:33:29.007906Z".
- `uploadTime__gte` [query, string] — The time at which the Threat Intelligence indicator was uploaded to SentinelOne DB greater or equal than. Example: "2022-07-13T20:33:29.007906Z".
- `updatedAt__gte` [query, string] — The time at which the indicator was last updated in SentinelOne DB  greater or equal than. Example: "2021-07-13T20:33:29.007906Z".
- `batchId` [query, string] — Unique ID of the uploaded indicators batch. Example: "atmtn000000028a881bcf939dc6d92ab55443".
- `campaignNames__in` [query, array] — List of campaign names associated with the indicator.
- `uploadTime__lt` [query, string] — The time at which the Threat Intelligence indicator was uploaded to SentinelOne DB lesser than. Example: "2021-07-13T20:33:29.007906Z".
- `creationTime__gte` [query, string] — Creation Time as set by the user greater or equal than. Example: "2021-07-13T20:33:29.007906Z".
- `skipCount` [query, boolean] — If true, total number of items will not be calculated, which speeds up execution time.
- `updatedAt__lte` [query, string] — The time at which the indicator was last updated in SentinelOne DB  lesser or equal than. Example: "2021-07-13T20:33:29.007906Z".
- `limit` [query, integer] — Limit number of returned items (1-1000). Example: "10".
- `source` [query, array] — List of the sources of the identified Threat Intelligence indicator. Example: "AlienVault".
- `description__contains` [query, array] — Free-text filter by the description of the indicator (supports multiple values). Example: "Malicious-activity".
- `uploadTime__gt` [query, string] — The time at which the Threat Intelligence indicator was uploaded to SentinelOne DB greater than. Example: "2022-07-13T20:33:29.007906Z".
- `countOnly` [query, boolean] — If true, only total number of items will be returned, without any of the actual objects.
- `skip` [query, integer] — Skip first number of items (0-1000). To iterate over more than 1000 items,  use "cursor". Example: "150".
- `tenant` [query, boolean] — Indicates a tenant scope request
- `siteIds` [query, array] — List of Site IDs to filter by. Example: "4,2,6,4,1,8,0,3,0,2,1,2,0,7,3,7,6,2".
- `sortOrder` [query, string] (enum: asc, desc) — Sort direction. Example: "asc".
- `category__in` [query, string] — The categories of the Threat Intelligence indicator, e.g.  the malware type associated with the IOC
- `externalId` [query, string] — The unique identifier of the indicator as provided by the Threat Intelligence source. Example: "e277603e-1060-5ad4-9937-c26c97f1ca68".
- `value` [query, string] — The value of the Threat Intelligence indicator. Example: "175.45.176.1".

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/threat-intelligence/iocs`
**Create IOCs**
`operationId`: `_web_api_threat-intelligence_iocs_post`

Add an IoC to the Threat Intelligence database. <br>These values under data are required fields: "source", "type", "value", and "method". <br>"Type" and "method" must be in upper case.<br>The "validUntil" field is mandatory, and must contain a date, for example, 2021-03-20 09:14:47.779000. "validUntil" determines when the IOC expires.<br>If the expiration date ("validUntil") is left blank, by default it will be the upload date plus a default offset value:<br>- 14 days for IPs<br>- 90 days for URLs and domains<br>- 180 days for file hashes (SHA1, SHA256, and MD5)<br>The maximum offset values allowed are:<br>- 30 days for IPs<br>- 180 days for URLs and Domains<br>- 180 days for hashes (SHA1, SHA256, and MD5)<br>The upload date is when the API gets a request to create an IOC.<br>If the expiration date is later than the upload date plus the the maximum offset value allowed, it will be adjusted to the upload date plus the maximum offset value allowed.

Required permissions: `Threat Intelligence.manage`

Parameters:
- `body` [body, v2_1.schemas_PostThreatIntelligenceSchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/threat-intelligence/iocs/stix`
**Create IOCs from STIX bundle**
`operationId`: `_web_api_threat-intelligence_iocs_stix_post`

Add IOCs to the Threat Intelligence database from a STIX 2.1 bundle. The API will transform STIX indicators into Threat Intelligence IOCs.<br>Must be a valid STIX 2.1 bundle containing indicator objects<br>Each indicator object should have a valid STIX pattern for one of these types:<br>-File hashes: [file:hashes.MD5 = ...], [file:hashes.SHA-1 = ...], [file:hashes.SHA-256 = ...]<br>-IP addresses: [ipv4-addr:value = ...]<br>-Domains: [domain-name:value = ...]<br>-URLs: [url:value = ...]<br>If the expiration date ("validUntil") is left blank, by default it will be the upload date plus a default offset value:<br>- 14 days for IPs<br>- 90 days for URLs and domains<br>- 180 days for file hashes (SHA1, SHA256, and MD5)<br>The maximum offset values allowed are:<br>- 30 days for IPs<br>- 180 days for URLs and Domains<br>- 180 days for hashes (SHA1, SHA256, and MD5)<br>The upload date is when the API gets a request to create an IOC.<br>If the expiration date is later than the upload date plus the the maximum offset value allowed, it will be adjusted to the upload date plus the maximum offset value allowed.<br>The API will also process these optional STIX relationships if present: <br>-Threa …

Required permissions: `Threat Intelligence.manage`

Parameters:
- `body` [body, v2_1.schemas_StixPostSchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `DELETE /web/api/v2.1/threat-intelligence/user-config`
**Delete Threat Intelligence user config**
`operationId`: `_web_api_threat-intelligence_user-config_delete`

Delete Threat Intelligence user config that match the filter.

Required permissions: `Threat Intelligence.manage`

Parameters:
- `body` [body, v2_1.schemas_UserConfigFilterSchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/threat-intelligence/user-config`
**Get Threat Intelligence user config**
`operationId`: `_web_api_threat-intelligence_user-config_get`

Get the Threat Intelligence user config that match the filter.

Required permissions: `Threat Intelligence.view`

Parameters:
- `siteIds` [query, array] — List of Site IDs to filter by. Example: "4,2,6,4,1,8,0,3,0,2,1,2,0,7,3,7,6,2".
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "4,2,6,4,1,8,0,3,0,2,1,2,0,7,3,7,6,2".
- `tenant` [query, boolean] — Indicates a tenant scope request

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/threat-intelligence/user-config`
**Create Threat Intelligence user config**
`operationId`: `_web_api_threat-intelligence_user-config_post`

Create Threat Intelligence user config.

Required permissions: `Threat Intelligence.manage`

Parameters:
- `body` [body, v2_1.schemas_PostUserConfigSchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.
