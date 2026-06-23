# Accounts

12 endpoints.

## `GET /web/api/v2.1/accounts`
**Get Accounts**
`operationId`: `_web_api_accounts_get`

Get the Accounts, and their data, that match the filter. This command gives the Account IDs, which other commands require. <br>Accounts are created by a Global User or by SentinelOne. Each Account contains Sites, which can inherit assets and settings. Each Account has one or more SKUs, that you assign to the Sites. To have both Core and Complete Sites in an Account, the Account must have both SKUs.

Required permissions: `Accounts.view`

Parameters:
- `skip` [query, integer] — Skip first number of items (0-1000). To iterate over more than 1000 items,  use "cursor". Example: "150".
- `limit` [query, integer] — Limit number of returned items (1-1000). Example: "10".
- `cursor` [query, string] — Cursor position returned by the last request. Use to iterate over more than 1000 items. Example: "YWdlbnRfaWQ6NTgwMjkzODE=".
- `countOnly` [query, boolean] — If true, only total number of items will be returned, without any of the actual objects.
- `skipCount` [query, boolean] — If true, total number of items will not be calculated, which speeds up execution time.
- `sortBy` [query, string] (enum: id, name, totalLicenses, expiration, accountType, state, createdAt, updatedAt, activeLicenses, activeAgents, numberOfSites, usageType, billingMode) — The column to sort the results by. Example: "id".
- `sortOrder` [query, string] (enum: asc, desc) — Sort direction. Example: "asc".
- `ids` [query, array] — A list of Account IDs. Example: "225494730938493804,225494730938493915".
- `accountIds` [query, array] — List of Account IDs to search for. Example: "225494730938493804,225494730938493915".
- `query` [query, string] — Full text search for fields: name. (Note: on single-Account Consoles, the Account name will not be matched)
- `name` [query, string] — Name. Example: "My Account".
- `isDefault` [query, boolean] — Is default
- `accountType` [query, string] (enum: Trial, Paid) — Account type. Example: "Trial".
- `expiration` [query, string] — Expiration. Example: "2018-02-27T04:49:26.257525Z".
- `totalLicenses` [query, integer] — Total licenses
- `activeLicenses` [query, integer] — Active licenses
- `sku` [query, string] — Sku. Example: "core".
- `module` [query, string] — Module. Example: "star,rso".
- `createdAt` [query, string] — Timestamp of Account creation. Example: "2018-02-27T04:49:26.257525Z".
- `updatedAt` [query, string] — Timestamp of last update. Example: "2018-02-27T04:49:26.257525Z".
- `state` [query, string] (enum: active, expired, deleted) — Account state. Example: "active".
- `states` [query, array] — Filter by state, such as active or expired.
- `statesNin` [query, array] — List of states to not filter
- `features` [query, array] — Filter the list of Accounts for those that support this feature. Example: "firewall-control".
- `usageType` [query, string] (enum: customer, mssp, ir) — Usage type. Example: "customer".
- `billingMode` [query, string] (enum: subscription, consumption) — Billing mode. Example: "subscription".
- `name__contains` [query, array] — Free-text filter by account name (supports multiple values)

Responses: 403 Insufficient permissions, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/accounts`
**Create Account**
`operationId`: `_web_api_accounts_post`

Create a new Account. This command requires Global permissions and an MSSP deployment. Consult with your SE before you run this command. An Account is a logical segment with permissions to configure features for specific Sites. Multiple Accounts can be useful for deployments with multiple Sites for third-parties (such as MSSP). Each Account has one or more SKUs, that you assign to Sites. If an Account has the Complete SKU, and you create a new Site in the Account, it will automatically have the Complete SKU. Best practice: Run "name-available" first, to make sure the name is unique in your deployment.

Required permissions: `Accounts.create`

Parameters:
- `body` [body, accounts.schemas_PostAccountSchema] — 

Responses: 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/accounts/{account_id}`
**Get Account by ID**
`operationId`: `_web_api_accounts_{account_id}_get`

Get Account data from a given Account ID. To get an Account ID, run "accounts".

Required permissions: `Accounts.view`

Parameters:
- `account_id` [path, string] **required** — Account ID. You can get the ID from the Get accounts command. Example: "225494730938493804".

Responses: 404 Account not found, 200 Success, 401 Unauthorized access - please sign in and retry.

## `PUT /web/api/v2.1/accounts/{account_id}`
**Update Account**
`operationId`: `_web_api_accounts_{account_id}_put`

Change the data of an Account. This command requires a Global user or an Account user and Admin role. Use this command to change the name, ID, SKUs and how they are distributed among Sites and Agents, and more. (See the Body sample.) Best practice:  Consult with your SentinelOne SE.

Required permissions: `Accounts.edit`

Parameters:
- `account_id` [path, string] **required** — Account ID. You can get the ID from the Get accounts command. Example: "225494730938493804".
- `body` [body, accounts.schemas_AccountPutSchema] — 

Responses: 404 Account not found, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/accounts/{account_id}/expire-now`
**Expire an Account**
`operationId`: `_web_api_accounts_{account_id}_expire-now_post`

Expire an Account immediately. The user must have Global access or Account acces with permissions for the Account. Best practice: Consult with Support before you use this command.

Required permissions: `Accounts.edit`

Parameters:
- `account_id` [path, string] **required** — Account ID. You can get the ID from the Get accounts command. Example: "225494730938493804".

Responses: 404 Account not found, 200 Expire account now, 401 Unauthorized access - please sign in and retry.

## `PUT /web/api/v2.1/accounts/{account_id}/reactivate`
**Reactivate Account**
`operationId`: `_web_api_accounts_{account_id}_reactivate_put`

Reactivate an expired Account. This command requires a Global user or Support. Consult with your SentinelOne SE.

Required permissions: `Accounts.edit`

Parameters:
- `account_id` [path, string] **required** — Account ID. You can get the ID from the Get accounts command. Example: "225494730938493804".
- `body` [body, accounts.schemas_ReactivateAccountSchema] — 

Responses: 404 Account not found, 200 Account reactivated, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `PUT /web/api/v2.1/accounts/{account_id}/revert-policy`
**Revert Policy**
`operationId`: `_web_api_accounts_{account_id}_revert-policy_put`

The policy of the Account is based on the default Global policy and is enforced by all endpoints in the Sites and Groups of the Account (if you did not change the Site or Group policies). If you change the Account policy, you can use this command to revert it to the default Global policy.

Required permissions: `Policy.edit`

Parameters:
- `account_id` [path, string] **required** — Account ID. You can get the ID from the Get accounts command. Example: "225494730938493804".
- `body` [body, policies_schemas_RevertPolicySchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/accounts/{account_id}/uninstall-password/generate`
**Generate/Regenerate Uninstall Password**
`operationId`: `_web_api_accounts_{account_id}_uninstall-password_generate_post`

You can uninstall all Agents of one Account with one command that requires a password. This command sets a new account-level uninstall password.<br>To enable this feature, submit a ticket with Support.<br>Best Practice: After you uninstall the Agents and install again, revoke the passphrase.<br>Applicable on Windows (versions 4.4+) and Linux (versions 21.7+) Agents.

Required permissions: `Endpoints.modifyUninstallPassword`

Parameters:
- `account_id` [path, string] **required** — Account ID. You can get the ID from the Get accounts command. Example: "225494730938493804".
- `body` [body, accounts.schemas_UninstallPasswordGenerateRequestSchema] — 

Responses: 403 Insufficient permissions, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/accounts/{account_id}/uninstall-password/metadata`
**Get Uninstall Password Metadata**
`operationId`: `_web_api_accounts_{account_id}_uninstall-password_metadata_get`

Get the uninstall password metadata, such as which user created and revoked it and when.

Required permissions: `Accounts.view`

Parameters:
- `account_id` [path, string] **required** — Account ID. You can get the ID from the Get accounts command. Example: "225494730938493804".

Responses: 403 Insufficient permissions, 200 Success, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/accounts/{account_id}/uninstall-password/revoke`
**Revoke Uninstall Password**
`operationId`: `_web_api_accounts_{account_id}_uninstall-password_revoke_post`

Delete the account-level uninstall password. If you do not delete it, you or another Console user can mistakenly use the Account passphrase (and uninstall all Agents) when you mean to uninstall one Agent.

Required permissions: `Endpoints.modifyUninstallPassword`

Parameters:
- `account_id` [path, string] **required** — Account ID. You can get the ID from the Get accounts command. Example: "225494730938493804".

Responses: 403 Insufficient permissions, 200 Success, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/accounts/{account_id}/uninstall-password/view`
**Get Uninstall Password**
`operationId`: `_web_api_accounts_{account_id}_uninstall-password_view_get`

Get the uninstall password to uninstall several Agents of one Account with one command.

Required permissions: `Endpoints.viewUninstallPassword`

Parameters:
- `account_id` [path, string] **required** — Account ID. You can get the ID from the Get accounts command. Example: "225494730938493804".

Responses: 403 Insufficient permissions, 200 Success, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/export/accounts`
**Export Accounts**
`operationId`: `_web_api_export_accounts_get`

Export Accounts data to a CSV, for Accounts that match the filter.

Required permissions: `Accounts.view`

Parameters:
- `ids` [query, array] — A list of Account IDs. Example: "225494730938493804,225494730938493915".
- `accountIds` [query, array] — List of Account IDs to search for. Example: "225494730938493804,225494730938493915".
- `query` [query, string] — Full text search for fields: name. (Note: on single-Account Consoles, the Account name will not be matched)
- `name` [query, string] — Name. Example: "My Account".
- `isDefault` [query, boolean] — Is default
- `accountType` [query, string] (enum: Trial, Paid) — Account type. Example: "Trial".
- `expiration` [query, string] — Expiration. Example: "2018-02-27T04:49:26.257525Z".
- `totalLicenses` [query, integer] — Total licenses
- `activeLicenses` [query, integer] — Active licenses
- `sku` [query, string] — Sku. Example: "core".
- `module` [query, string] — Module. Example: "star,rso".
- `createdAt` [query, string] — Timestamp of Account creation. Example: "2018-02-27T04:49:26.257525Z".
- `updatedAt` [query, string] — Timestamp of last update. Example: "2018-02-27T04:49:26.257525Z".
- `state` [query, string] (enum: active, expired, deleted) — Account state. Example: "active".
- `states` [query, array] — Filter by state, such as active or expired.
- `statesNin` [query, array] — List of states to not filter
- `features` [query, array] — Filter the list of Accounts for those that support this feature. Example: "firewall-control".
- `usageType` [query, string] (enum: customer, mssp, ir) — Usage type. Example: "customer".
- `billingMode` [query, string] (enum: subscription, consumption) — Billing mode. Example: "subscription".
- `name__contains` [query, array] — Free-text filter by account name (supports multiple values)

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.
