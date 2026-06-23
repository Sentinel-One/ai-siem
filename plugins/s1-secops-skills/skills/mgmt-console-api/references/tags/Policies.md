# Policies

8 endpoints.

## `GET /web/api/v2.1/accounts/{account_id}/policy`
**Account Policy**
`operationId`: `_web_api_accounts_{account_id}_policy_get`

Get the policy for the Account given by ID. To get the ID of an Account, run "accounts". See also: Get Policy.

Required permissions: `Policy.view`

Parameters:
- `account_id` [path, string] **required** — Account ID. You can get the ID from the Get accounts command. Example: "225494730938493804".

Responses: 404 Policy not found, 200 Success, 401 Unauthorized access - please sign in and retry.

## `PUT /web/api/v2.1/accounts/{account_id}/policy`
**Update Account Policy**
`operationId`: `_web_api_accounts_{account_id}_policy_put`

Change the policy for the Account given by ID. Best practice: Get the policy of the Account before you attempt to change it. See also:  Get Policy.

Required permissions: `Policy.edit`
Optional permissions: `Remote Ops Forensics.view`

Parameters:
- `account_id` [path, string] **required** — Account ID. You can get the ID from the Get accounts command. Example: "225494730938493804".
- `body` [body, policies_TenantPolicySchema] — 

Responses: 404 Account not found, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/groups/{group_id}/policy`
**Group Policy**
`operationId`: `_web_api_groups_{group_id}_policy_get`

Get the policy of the Group given by ID. To get the ID of a Group, run "groups". See also: Get Policy.

Required permissions: `Policy.view`

Parameters:
- `group_id` [path, string] **required** — Group ID. Example: "225494730938493804".

Responses: 404 Policy not found, 200 Success, 401 Unauthorized access - please sign in and retry.

## `PUT /web/api/v2.1/groups/{group_id}/policy`
**Update Group Policy**
`operationId`: `_web_api_groups_{group_id}_policy_put`

Change the policy for the Group given by ID. Best practice: Get the policy of the Group before you attempt to change it. See also:  Get Policy.

Required permissions: `Policy.edit`
Optional permissions: `Remote Ops Forensics.view`

Parameters:
- `group_id` [path, string] **required** — Group ID. Example: "225494730938493804".
- `body` [body, policies_TenantPolicySchema] — 

Responses: 404 Group not found, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/sites/{site_id}/policy`
**Site Policy**
`operationId`: `_web_api_sites_{site_id}_policy_get`

Get the policy of the Site given by ID. To get the ID of a Site, run "sites". See also: Get Policy.

Required permissions: `Policy.view`

Parameters:
- `site_id` [path, string] **required** — Site ID. Example: "225494730938493804".

Responses: 404 Policy not found, 200 Success, 401 Unauthorized access - please sign in and retry.

## `PUT /web/api/v2.1/sites/{site_id}/policy`
**Update Site Policy**
`operationId`: `_web_api_sites_{site_id}_policy_put`

Change the policy for the Site given by ID. Best practice: Get the policy of the Site before you attempt to change it. See also:  Get Policy.

Required permissions: `Policy.edit`
Optional permissions: `Remote Ops Forensics.view`

Parameters:
- `site_id` [path, string] **required** — Site ID. Example: "225494730938493804".
- `body` [body, policies_TenantPolicySchema] — 

Responses: 404 Site not found, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/tenant/policy`
**Global Policy**
`operationId`: `_web_api_tenant_policy_get`

Get the Global policy. This is the default policy for your deployment. See also: Get Policy.

Required permissions: `Policy.view`

Responses: 404 Policy not found, 200 Success, 401 Unauthorized access - please sign in and retry.

## `PUT /web/api/v2.1/tenant/policy`
**Update Global Policy**
`operationId`: `_web_api_tenant_policy_put`

Change the policy of your deployment. Best practice: Get the Global policy before you attempt to change it. See also:  Get Policy. 
 You must be a Global Admin user to change the Global Policy.

Required permissions: `Policy.edit`
Optional permissions: `Remote Ops Forensics.view`

Parameters:
- `body` [body, policies_TenantPolicySchema] — 

Responses: 404 Policy not found, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.
