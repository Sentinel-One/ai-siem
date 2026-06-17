# VCS Integration

20 endpoints.

## `GET /web/api/v2.1/cnapp/vcs/filters/count`
**Fetch filter count**
`operationId`: `_web_api_cnapp_vcs_filters_count_get`

Fetch filter count

Parameters:
- `scopeType` [query, string] **required** — 
- `scopeIds` [query, string] **required** — 

Responses: 200 Filter count fetched successfully, 400 Bad Request, 500 Internal Server Error

## `GET /web/api/v2.1/cnapp/vcs/integration/{integrationId}/offboarding`
**Delete a VCS Integration**
`operationId`: `_web_api_cnapp_vcs_integration_{integrationId}_offboarding_get`

This API is used to off-board a VCS integration.

Parameters:
- `scopeType` [query, string] **required** — 
- `scopeIds` [query, string] **required** — 

Responses: 200 VCS offboarding app url created successfully, 400 Bad Request, 500 Internal Server Error

## `PUT /web/api/v2.1/cnapp/vcs/integration/{integrationId}/repos/disable-scan`
**Disable scanning for repositories in a VCS integration**
`operationId`: `_web_api_cnapp_vcs_integration_{integrationId}_repos_disable-scan_put`

Deactivate scanning for repositories associated with the given VCS integration.

Parameters:
- `scopeType` [query, string] **required** — 
- `scopeIds` [query, string] **required** — 
- `integrationId` [path, string] **required** — 
- `body` [body, EnableDisableRepos] **required** — 

Responses: 200 Successfully disabled repositories, 400 Bad Request, 500 Internal Server Error

## `PUT /web/api/v2.1/cnapp/vcs/integration/{integrationId}/repos/edit-tags`
**Edit tags for repositories in a VCS integration**
`operationId`: `_web_api_cnapp_vcs_integration_{integrationId}_repos_edit-tags_put`

Allows modification of tags associated with one or more repositories under a specified VCS integration. This operation supports adding, removing, or updating tags to help organize and categorize repositories effectively.

Parameters:
- `scopeType` [query, string] **required** — 
- `scopeIds` [query, string] **required** — 
- `integrationId` [path, string] **required** — 
- `body` [body, EditReposTags] **required** — 

Responses: 200 Tags updated successfully, 400 Bad Request, 500 Internal Server Error

## `PUT /web/api/v2.1/cnapp/vcs/integration/{integrationId}/repos/enable-scan`
**Enable scanning for repositories in a VCS integration**
`operationId`: `_web_api_cnapp_vcs_integration_{integrationId}_repos_enable-scan_put`

Activates scanning for repositories associated with the given VCS integration.

Parameters:
- `scopeType` [query, string] **required** — 
- `scopeIds` [query, string] **required** — 
- `integrationId` [path, string] **required** — 
- `body` [body, EnableDisableRepos] **required** — 

Responses: 200 Successfully enabled repositories, 400 Bad Request, 500 Internal Server Error

## `POST /web/api/v2.1/cnapp/vcs/integration/{integrationId}/repos/get-tags`
**Fetch repository tags**
`operationId`: `_web_api_cnapp_vcs_integration_{integrationId}_repos_get-tags_post`

This endpoint retrieves tags associated with repositories under a VCS integration.

Parameters:
- `scopeType` [query, string] **required** — 
- `scopeIds` [query, string] **required** — 
- `integrationId` [path, string] **required** — 
- `body` [body, FetchReposTags] **required** — 

Responses: 200 Repositories tags fetched successfully, 400 Bad Request, 500 Internal Server Error

## `DELETE /web/api/v2.1/cnapp/vcs/integration/{vcsIntegrationId}`
**Delete a VCS integration**
`operationId`: `_web_api_cnapp_vcs_integration_{vcsIntegrationId}_delete`

This endpoint permanently deletes a VCS integration.

Parameters:
- `scopeType` [query, string] **required** — 
- `scopeIds` [query, string] **required** — 
- `vcsIntegrationId` [path, string] **required** — 

Responses: 200 VCS integration deleted successfully, 400 Bad Request, 500 Internal Server Error

## `PUT /web/api/v2.1/cnapp/vcs/integration/{vcsIntegrationId}`
**Update a VCS integration**
`operationId`: `_web_api_cnapp_vcs_integration_{vcsIntegrationId}_put`

This endpoint allows users to update configuration details for a VCS integration.

Parameters:
- `scopeType` [query, string] **required** — 
- `scopeIds` [query, string] **required** — 
- `vcsIntegrationId` [path, string] **required** — 
- `body` [body, UpdateVCSIntegration] **required** — 

Responses: 200 VCS integration updated successfully, 400 Bad Request, 500 Internal Server Error

## `GET /web/api/v2.1/cnapp/vcs/integration/{vcsIntegrationId}/repos`
**List VCS integration repositories**
`operationId`: `_web_api_cnapp_vcs_integration_{vcsIntegrationId}_repos_get`

Fetches a list of repositories associated with the VCS integration

Parameters:
- `scopeType` [query, string] — 
- `scopeIds` [query, string] — 
- `limit` [query, string] — 
- `cursor` [query, string] — 
- `skip` [query, string] — 
- `vcsIntegrationId` [path, string] **required** — 

Responses: 200 Successfully retrieved the list of repositories, 400 Bad Request, 500 Internal Server Error

## `PUT /web/api/v2.1/cnapp/vcs/integration/{vcsIntegrationId}/repos/resync`
**Resync VCS Integration Repositories**
`operationId`: `_web_api_cnapp_vcs_integration_{vcsIntegrationId}_repos_resync_put`

Initiates a process to resynchronize repositories associated with the specified VCS integration

Parameters:
- `scopeType` [query, string] **required** — 
- `scopeIds` [query, string] **required** — 
- `vcsIntegrationId` [path, string] **required** — 

Responses: 200 Resynchronization initiated successfully, 400 Bad Request, 500 Internal Server Error

## `GET /web/api/v2.1/cnapp/vcs/integrations`
**List VCS integrations**
`operationId`: `_web_api_cnapp_vcs_integrations_get`

Fetches a list of all configured VCS integrations.

Parameters:
- `scopeType` [query, string] — 
- `scopeIds` [query, string] — 
- `limit` [query, string] — 
- `skip` [query, string] — 

Responses: 200 Successfully retrieved the list of VCS integrations, 400 Bad Request, 500 Internal Server Error

## `PUT /web/api/v2.1/cnapp/vcs/integrations/edit-tags`
**Edit tags for a VCS integration**
`operationId`: `_web_api_cnapp_vcs_integrations_edit-tags_put`

Allows modification of tags in a VCS integration. This operation supports adding, removing, or updating tags to help organize and categorize integration repositories effectively.

Parameters:
- `scopeType` [query, string] **required** — 
- `scopeIds` [query, string] **required** — 
- `body` [body, EditIntegrationsTags] **required** — 

Responses: 200 Tags updated successfully, 400 Bad Request, 500 Internal Server Error

## `POST /web/api/v2.1/cnapp/vcs/onboarding`
**Onboard a new VCS integration**
`operationId`: `_web_api_cnapp_vcs_onboarding_post`

This endpoint allows users to onboard a new VCS integration, enabling automated scanning for secrets and IaC misconfigurations.

Parameters:
- `scopeType` [query, string] **required** — 
- `scopeIds` [query, string] **required** — 
- `body` [body, VCSOnboarding] **required** — 

Responses: 200 VCS onboarding completed successfully, 400 Bad Request, 500 Internal Server Error

## `GET /web/api/v2.1/cnapp/vcs/scanner-policies`
**List VCS and CICD scanner policies**
`operationId`: `_web_api_cnapp_vcs_scanner-policies_get`

This endpoint retrieves a list of all configured scanner policies used for VCS and CICD integrations.

Parameters:
- `scopeType` [query, string] — 
- `scopeIds` [query, string] — 
- `limit` [query, string] — 
- `skip` [query, string] — 

Responses: 200 Scanner policies fetched successfully, 400 Bad Request, 500 Internal Server Error

## `POST /web/api/v2.1/cnapp/vcs/scanner-policy`
**Create a VCS and CICD scanner policy**
`operationId`: `_web_api_cnapp_vcs_scanner-policy_post`

Defines a scanning policy for a VCS integration, configuring parameters for detecting secrets, IaC misconfigurations, and vulnerabilities within repositories.

Parameters:
- `scopeType` [query, string] **required** — 
- `scopeIds` [query, string] **required** — 
- `body` [body, AddScannerPolicy] **required** — 

Responses: 200 Scanner policy created successfully, 400 Bad Request, 500 Internal Server Error

## `GET /web/api/v2.1/cnapp/vcs/scanner-policy/max-allowed-priority`
**Get max allowed priority**
`operationId`: `_web_api_cnapp_vcs_scanner-policy_max-allowed-priority_get`

This endpoint returns the maximum allowed value for the priority in scanner policies.

Parameters:
- `scopeType` [query, string] **required** — 
- `scopeIds` [query, string] **required** — 
- `targetScopeType` [query, string] **required** — 
- `targetScopeId` [query, string] **required** — 

Responses: 200 Max allowed priority fetched successfully, 400 Bad Request, 500 Internal Server Error

## `DELETE /web/api/v2.1/cnapp/vcs/scanner-policy/{policyId}`
**Delete a VCS and CICD scanner policy**
`operationId`: `_web_api_cnapp_vcs_scanner-policy_{policyId}_delete`

This endpoint deletes a scanner policy.

Parameters:
- `scopeType` [query, string] **required** — 
- `scopeIds` [query, string] **required** — 
- `policyId` [path, string] **required** — 

Responses: 200 VCS scanner policy deleted successfully, 400 Bad Request, 500 Internal Server Error

## `GET /web/api/v2.1/cnapp/vcs/scanner-policy/{policyId}`
**Get a VCS and CICD scanner policy**
`operationId`: `_web_api_cnapp_vcs_scanner-policy_{policyId}_get`

Get a VCS and CICD scanner policy

Parameters:
- `scopeType` [query, string] **required** — 
- `scopeIds` [query, string] **required** — 
- `policyId` [path, string] **required** — 

Responses: 200 This endpoint fetches detailed information for a scanner pol, 400 Bad Request, 500 Internal Server Error

## `PUT /web/api/v2.1/cnapp/vcs/scanner-policy/{policyId}`
**Update a VCS and CICD scanner policy**
`operationId`: `_web_api_cnapp_vcs_scanner-policy_{policyId}_put`

This endpoint updates an existing scanner policy. A scanner policy defines how secrets, IaC misconfigurations, and vulnerabilities should be detected and handled within a VCS integration/CICD.

Parameters:
- `scopeType` [query, string] **required** — 
- `scopeIds` [query, string] **required** — 
- `policyId` [path, string] **required** — 
- `body` [body, UpdateVCSScannerPolicy] **required** — 

Responses: 200 Scanner policy updated successfully, 400 Bad Request, 500 Internal Server Error

## `POST /web/api/v2.1/cnapp/vcs/tunnel/user`
**Register Tunnel User**
`operationId`: `_web_api_cnapp_vcs_tunnel_user_post`

This API is used to register a new tunnel user. It sets up the necessary tunnel configuration and credentials for secure access.

Parameters:
- `scopeType` [query, string] **required** — 
- `scopeIds` [query, string] **required** — 
- `body` [body, TunnelUser] **required** — 

Responses: 200 Tunnel user registered successfully, 400 Bad Request, 500 Internal Server Error
