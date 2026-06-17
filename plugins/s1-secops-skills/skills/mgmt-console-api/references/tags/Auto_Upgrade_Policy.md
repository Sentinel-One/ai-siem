# Auto Upgrade Policy

13 endpoints.

## `GET /web/api/v2.1/upgrade-policy/all-policies-count`
**All Policies OS Count**
`operationId`: `_web_api_upgrade-policy_all-policies-count_get`

Get the number of all policies for each OS from the given scope and the inherited scopes

Required permissions: `Auto-Upgrade Policy.view`

Parameters:
- `scopeLevel` [query, string] **required** — Scope level, one of 'account', 'group', 'site' or 'tenant'
- `scopeId` [query, string] — Scope ID

Responses: 200 Success, 400 Bad request

## `GET /web/api/v2.1/upgrade-policy/available-packages`
**Get Available Packages**
`operationId`: `_web_api_upgrade-policy_available-packages_get`

Get Available Packages

Required permissions: `Auto-Upgrade Policy.view`

Parameters:
- `scopeLevel` [query, string] **required** — Scope level, one of 'account', 'group', 'site' or 'tenant'
- `scopeId` [query, string] — Scope ID
- `osType` [query, string] **required** — OS type, one of 'linux', 'macos' or 'windows'
- `displayName__contains` [query, string] — Partially match the name of the package, e.g. '22.1 GA'

Responses: 200 Success, 400 Bad request

## `POST /web/api/v2.1/upgrade-policy/has-policy`
**Has Policy**
`operationId`: `_web_api_upgrade-policy_has-policy_post`

Has policy

Parameters:
- `payload` [body, v2_1.models.HasPoliciesRequest] **required** — Policy payload

Responses: 200 Success, 400 Bad request

## `GET /web/api/v2.1/upgrade-policy/parent-policies`
**Get Parent Policies**
`operationId`: `_web_api_upgrade-policy_parent-policies_get`

Get paginated and ordered parent policies by a given scope

Required permissions: `Auto-Upgrade Policy.view`

Parameters:
- `scopeLevel` [query, string] **required** — Scope level, one of 'account', 'group', 'site' or 'tenant'
- `scopeId` [query, string] — Scope ID
- `osType` [query, string] **required** — OS type, one of 'linux', 'macos' or 'windows'
- `limit` [query, integer] **required** — Limit number of returned items. Should be more than 1. Example: '10'.
- `skip` [query, integer] **required** — Skip first number of items. Example: '0'.
- `sortBy` [query, string] **required** — The column to sort the results by. Example: 'priority'.
- `sortOrder` [query, string] **required** — Sort direction. Could be 'asc' or 'desc'.

Responses: 200 Success, 400 Bad request

## `GET /web/api/v2.1/upgrade-policy/policies`
**Get Policies**
`operationId`: `_web_api_upgrade-policy_policies_get`

Get paginated and ordered policies by a given scope

Required permissions: `Auto-Upgrade Policy.view`

Parameters:
- `scopeLevel` [query, string] **required** — Scope level, one of 'account', 'group', 'site' or 'tenant'
- `scopeId` [query, string] — Scope ID
- `osType` [query, string] **required** — OS type, one of 'linux', 'macos' or 'windows'
- `limit` [query, integer] **required** — Limit number of returned items. Should be more than 1. Example: '10'
- `skip` [query, integer] **required** — Skip first number of items. Example: '0'.
- `sortBy` [query, string] **required** — The column to sort the results by. Example: 'priority'.
- `sortOrder` [query, string] **required** — Sort direction. Could be 'asc' or 'desc'.

Responses: 200 Success, 400 Bad request

## `POST /web/api/v2.1/upgrade-policy/policies`
**Deactivate Policies**
`operationId`: `_web_api_upgrade-policy_policies_post`

Deactivate all policies

Required permissions: `Auto-Upgrade Policy.disableAllPolicies`

Parameters:
- `scopeLevel` [query, string] **required** — Scope level, one of 'account', 'group', 'site' or 'tenant'
- `scopeId` [query, string] — Scope ID
- `osType` [query, string] **required** — OS type, one of 'linux', 'macos' or 'windows'

Responses: 200 Success, 400 Bad request

## `GET /web/api/v2.1/upgrade-policy/policies-count`
**Policies OS Count**
`operationId`: `_web_api_upgrade-policy_policies-count_get`

Get the number of policies for each OS, for a given scope level and id

Required permissions: `Auto-Upgrade Policy.view`

Parameters:
- `scopeLevel` [query, string] **required** — Scope level, one of 'account', 'group', 'site' or 'tenant'
- `scopeId` [query, string] — Scope ID

Responses: 200 Success, 400 Bad request

## `POST /web/api/v2.1/upgrade-policy/policy`
**Create Policy**
`operationId`: `_web_api_upgrade-policy_policy_post`

Add policy

Required permissions: `Auto-Upgrade Policy.create`

Parameters:
- `payload` [body, v2_1.models.Policy] **required** — Policy payload

Responses: 200 Success, 400 Bad request

## `POST /web/api/v2.1/upgrade-policy/policy/{policyid}`
**Policy Action**
`operationId`: `_web_api_upgrade-policy_policy_{policyid}_post`

Perform action on a certain policy

Required permissions: `Auto-Upgrade Policy.policyAction`

Parameters:
- `payload` [body, v2_1.models.EndpointActionRequest] **required** — Policy payload
- `policyid` [path, string] **required** — Policy id

Responses: 200 Success, 400 Bad request

## `PUT /web/api/v2.1/upgrade-policy/policy/{policyid}`
**Update Policy**
`operationId`: `_web_api_upgrade-policy_policy_{policyid}_put`

Update existing policy

Required permissions: `Auto-Upgrade Policy.edit`

Parameters:
- `payload` [body, v2_1.models.CreatePolicyRequest] **required** — Policy payload
- `policyid` [path, string] **required** — Policy id

Responses: 200 Success, 400 Bad request

## `PUT /web/api/v2.1/upgrade-policy/policy/{policyid}/reset-retry-counter`
**Reset Policy Retry Counter**
`operationId`: `_web_api_upgrade-policy_policy_{policyid}_reset-retry-counter_put`

Reset the number of times an Agent upgrade will be retried if the original upgrade attempt fails.

Required permissions: `Auto-Upgrade Policy.edit`

Parameters:
- `policyid` [path, string] **required** — Policy ID

Responses: 200 Success, 400 Bad request

## `PUT /web/api/v2.1/upgrade-policy/reorder`
**Reorder Policies**
`operationId`: `_web_api_upgrade-policy_reorder_put`

Reorder policies

Required permissions: `Auto-Upgrade Policy.edit`

Parameters:
- `payload` [body, v2_1.models.ReorderPolicyRequest] **required** — Policy payload

Responses: 200 Success, 400 Bad request

## `PUT /web/api/v2.1/upgrade-policy/set-inheriting`
**Set Scope Inheriting**
`operationId`: `_web_api_upgrade-policy_set-inheriting_put`

Set Scope Inheriting

Required permissions: `Auto-Upgrade Policy.edit`

Parameters:
- `payload` [body, v2_1.models.ScopeInheritanceRequest] **required** — payload

Responses: 200 Success, 400 Bad request
