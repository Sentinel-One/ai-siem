# Mobile Integration

11 endpoints.

## `GET /web/api/v2.1/mobile-integration/devices`
**Devices - Get list of devices for specific scope**
`operationId`: `_web_api_mobile-integration_devices_get`

Devices - Get list devices for specific scope

Required permissions: `Mobile Endpoints.view`

Parameters:
- `privileges__in` [query, array] — Include devices only with given privileges. Example: "none".
- `siteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `model__contains` [query, string] — Include devices by models that contain text
- `trackingId1__contains` [query, string] — Include devices by external tracking IDs that contain text
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "225494730938493804,225494730938493915".
- `osVersion__contains` [query, string] — Include devices by os version that contain text
- `countOnly` [query, boolean] — If true, only total number of items will be returned, without any of the actual objects.
- `groupIds` [query, array] — List of Group IDs to filter by. Example: "225494730938493804,225494730938493915".
- `user__contains` [query, string] — Include devices by users that contain text
- `trackingId2__contains` [query, string] — Include devices by another external tracking IDs that contain text
- `cursor` [query, string] — Cursor position returned by the last request. Use to iterate over more than 1000 items. Example: "YWdlbnRfaWQ6NTgwMjkzODE=".
- `platform__in` [query, array] — Include devices only of given platforms. Example: "android".
- `tenant` [query, boolean] — Indicates a tenant scope request
- `sortOrder` [query, string] (enum: asc, desc) — Sort direction. Example: "asc".
- `appVersion__in` [query, array] — Include devices with given app versions. Example: "2.5.1.1320".
- `healthState__in` [query, array] — Include devices only with given health state. Example: "normal".
- `skip` [query, integer] — Skip first number of items (0-1000). To iterate over more than 1000 items,  use "cursor". Example: "150".
- `skipCount` [query, boolean] — If true, total number of items will not be calculated, which speeds up execution time.
- `limit` [query, integer] — Limit number of returned items (1-1000). Example: "10".
- `sortBy` [query, string] (enum: id, appVersion, registeredOn, lastActiveOn, healthState) — The column to sort the results by. Example: "id".
- `deviceId__contains` [query, string] — Include devices by device IDs that contain text

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/mobile-integration/incidents`
**Incidents - Get list of incidents**
`operationId`: `_web_api_mobile-integration_incidents_get`

Incidents - Get list of incidents

Required permissions: `Mobile Alerts.view, Mobile Threats.view`

Parameters:
- `siteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "225494730938493804,225494730938493915".
- `countOnly` [query, boolean] — If true, only total number of items will be returned, without any of the actual objects.
- `groupIds` [query, array] — List of Group IDs to filter by. Example: "225494730938493804,225494730938493915".
- `user__contains` [query, string] — Include incidents by user email that contain text
- `deviceId__in` [query, array] — Include incidents only of given device ids. Example: "a,b,c,-,1,2,3,-,4,5,6".
- `cursor` [query, string] — Cursor position returned by the last request. Use to iterate over more than 1000 items. Example: "YWdlbnRfaWQ6NTgwMjkzODE=".
- `tenant` [query, boolean] — Indicates a tenant scope request
- `sortOrder` [query, string] (enum: asc, desc) — Sort direction. Example: "asc".
- `statusAction__in` [query, array] — Include incident only of given status actions. Example: "conditional_access".
- `incidentStatus__in` [query, array] — Include incident only of given incident statuses. Example: "unresolved".
- `severity__in` [query, array] — Include incident only of given severities. Example: "low".
- `skip` [query, integer] — Skip first number of items (0-1000). To iterate over more than 1000 items,  use "cursor". Example: "150".
- `analystVerdict__in` [query, array] — Include incident only of given analyst verdicts. Example: "true_positive".
- `skipCount` [query, boolean] — If true, total number of items will not be calculated, which speeds up execution time.
- `limit` [query, integer] — Limit number of returned items (1-1000). Example: "10".
- `status__in` [query, array] — Include incident only of given statuses. Example: "not_mitigated".
- `kind__in` [query, array] — Include incidents only of given kinds. Example: "t,h,r,e,a,t".
- `sortBy` [query, string] (enum: id, reportedTime, severity, status) — The column to sort the results by. Example: "id".
- `deviceId__contains` [query, string] — Include incidents by device IDs that contain text

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/mobile-integration/mssp-provisioning/partner`
**Provision - Get MSSP partner with admin user**
`operationId`: `_web_api_mobile-integration_mssp-provisioning_partner_get`

Gets MSSP partner with the first admin user by scope

Required permissions: `Mobile Integrations.view`

Parameters:
- `tenant` [query, boolean] — Indicates a tenant scope request
- `groupIds` [query, array] — List of Group IDs to filter by. Example: "225494730938493804,225494730938493915".
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "225494730938493804,225494730938493915".
- `siteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".

Responses: 200 MSSP partner retrieved, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/mobile-integration/mssp-provisioning/partner`
**Provision - Provision MSSP partner with admin user**
`operationId`: `_web_api_mobile-integration_mssp-provisioning_partner_post`

Provision a new MSSP partner and create an admin user for the partner account

Required permissions: `Mobile Integrations.manage`

Parameters:
- `body` [body, v2_1.provisioning.schemas_ProvisionWithUserRequestWrapper] — 

Responses: 403 403 - You do not have authorization to complete request., 401 Unauthorized access - please sign in and retry., 400 Invalid user input received. See error details for further i, 201 MSSP partner provisioned and admin user created

## `GET /web/api/v2.1/mobile-integration/provisioning/can-provision-tenant`
**Provision - Check if tenant can be provisioned**
`operationId`: `_web_api_mobile-integration_provisioning_can-provision-tenant_get`

Checks if tenant can be provisioned by scope

Required permissions: `Mobile Integrations.view`

Parameters:
- `tenant` [query, boolean] — Indicates a tenant scope request
- `groupIds` [query, array] — List of Group IDs to filter by. Example: "225494730938493804,225494730938493915".
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "225494730938493804,225494730938493915".
- `siteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".

Responses: 200 Tenant retrieved, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/mobile-integration/provisioning/partner-key`
**Provision - Get MSSP partner key**
`operationId`: `_web_api_mobile-integration_provisioning_partner-key_get`

Gets MSSP partner key by scope

Required permissions: `Mobile Integrations.view`

Parameters:
- `tenant` [query, boolean] — Indicates a tenant scope request
- `groupIds` [query, array] — List of Group IDs to filter by. Example: "225494730938493804,225494730938493915".
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "225494730938493804,225494730938493915".
- `siteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".

Responses: 200 Partner key retrieved successfully., 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/mobile-integration/provisioning/partner-key`
**Provision - Persist MSSP partner key**
`operationId`: `_web_api_mobile-integration_provisioning_partner-key_post`

Persists MSSP partner key - client ID and secret - for future customer provisioning.

Required permissions: `Mobile Integrations.manage`

Parameters:
- `body` [body, v2_1.provisioning.schemas_PartnerKeyRequestWrapper] — 

Responses: 403 403 - You do not have authorization to complete request., 401 Unauthorized access - please sign in and retry., 400 Invalid user input received. See error details for further i, 201 Partner key persisted successfully.

## `PUT /web/api/v2.1/mobile-integration/provisioning/partner-key`
**Provision - Update MSSP partner key**
`operationId`: `_web_api_mobile-integration_provisioning_partner-key_put`

Updates MSSP partner key - client ID and secret - for future customer provisioning.

Required permissions: `Mobile Integrations.manage`

Parameters:
- `body` [body, v2_1.provisioning.schemas_PartnerKeyRequestWrapper] — 

Responses: 404 404 - Partner key not found., 403 403 - You do not have authorization to complete request., 401 Unauthorized access - please sign in and retry., 400 Invalid user input received. See error details for further i, 201 Partner key updated successfully.

## `DELETE /web/api/v2.1/mobile-integration/provisioning/partner-key/{client_id}`
**Deletes MSSP partner key by client ID**
`operationId`: `_web_api_mobile-integration_provisioning_partner-key_{client_id}_delete`

Provision - Delete MSSP partner key

Required permissions: `Mobile Integrations.manage`

Parameters:
- `client_id` [path, string] **required** — Client id
- `body` [body, v2_1.provisioning.schemas_DeletePartnerKeyRequestSchema] — 

Responses: 404 Partner key not found, 204 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/mobile-integration/provisioning/tenant`
**Provision - Get tenant with users**
`operationId`: `_web_api_mobile-integration_provisioning_tenant_get`

Gets tenant with users by scope

Required permissions: `Mobile Integrations.view`

Parameters:
- `tenant` [query, boolean] — Indicates a tenant scope request
- `groupIds` [query, array] — List of Group IDs to filter by. Example: "225494730938493804,225494730938493915".
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "225494730938493804,225494730938493915".
- `siteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".

Responses: 200 Tenant retrieved, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/mobile-integration/provisioning/tenant`
**Provision - Provision tenant with admin user**
`operationId`: `_web_api_mobile-integration_provisioning_tenant_post`

Provision a new tenant and create an admin user for the tenant account

Required permissions: `Mobile Integrations.manage`

Parameters:
- `body` [body, v2_1.provisioning.schemas_ProvisionWithUserRequestWrapper] — 

Responses: 403 403 - You do not have authorization to complete request., 401 Unauthorized access - please sign in and retry., 400 Invalid user input received. See error details for further i, 201 Tenant provisioned and admin user created
