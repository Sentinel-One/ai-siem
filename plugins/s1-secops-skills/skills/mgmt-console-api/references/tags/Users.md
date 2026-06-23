# Users

41 endpoints.

## `GET /web/api/v2.1/export/users`
**Export Users**
`operationId`: `_web_api_export_users_get`

Export User data to a CSV, for Users that match the filter.

Required permissions: `Users.view`

Parameters:
- `siteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "225494730938493804,225494730938493915".
- `source` [query, string] (enum: mgmt, sso_saml, active_directory, global) — User Source. Example: "mgmt".
- `sources` [query, array] — Source in. Example: "mgmt".
- `email` [query, string] — Email. Example: "admin@sentinelone.com".
- `email__contains` [query, array] — Match email partially (substring)
- `emailReadOnly` [query, boolean] — True if email cannot be changed
- `fullName` [query, string] — Full name
- `fullName__contains` [query, array] — Match full name partially (substring)
- `fullNameReadOnly` [query, boolean] — True if full name cannot be changed
- `firstLogin` [query, string] — First login. Example: "2018-02-27T04:49:26.257525Z".
- `lastLogin` [query, string] — Last login. Example: "2018-02-27T04:49:26.257525Z".
- `dateJoined` [query, string] — Date joined. Example: "2018-02-27T04:49:26.257525Z".
- `groupsReadOnly` [query, boolean] — [DEPRECATED] True if permissions cannot be changed
- `twoFaEnabled` [query, boolean] — Two fa enabled
- `primaryTwoFaMethod` [query, string] — Primary two fa method
- `emailVerified` [query, boolean] — Return only verified/unverified users
- `query` [query, string] — Full text search for fields: full_name, email, description
- `ids` [query, array] — List of user IDs to filter by. Example: "225494730938493804,225494730938493915".
- `roleIds` [query, array] — List of rbac roles to filter by. Example: "225494730938493804,225494730938493915".
- `twoFaStatus` [query, string] — Two fa status
- `twoFaStatuses` [query, array] — Two fa status in
- `canGenerateApiToken` [query, boolean] — Can generate api token
- `hasValidApiToken` [query, boolean] — Has valid api token
- `lastActivation__lt` [query, string] — User was last active before this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `lastActivation__lte` [query, string] — User was last active before or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `lastActivation__gt` [query, string] — User was last active after this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `lastActivation__gte` [query, string] — User was last active after or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `lastActivation__between` [query, string] — Date range for when the user was last active (format: <from_timestamp>-<to_timestamp>, inclusive). Example: "1514978890136-1514978650130".
- `apiTokenExpiresAt__lt` [query, string] — API token expires before this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `apiTokenExpiresAt__lte` [query, string] — API token expires before or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `apiTokenExpiresAt__gt` [query, string] — API token expires after this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `apiTokenExpiresAt__gte` [query, string] — API token expires after or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `apiTokenExpiresAt__between` [query, string] — Date range for when the API token expires (format: <from_timestamp>-<to_timestamp>, inclusive). Example: "1514978890136-1514978650130".
- `createdAt__lt` [query, string] — User was created before this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__lte` [query, string] — User was created before or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__gt` [query, string] — User was created after this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__gte` [query, string] — User was created after or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__between` [query, string] — Date range for when the user was created (format: <from_timestamp>-<to_timestamp>, inclusive). Example: "1514978890136-1514978650130".

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/user`
**User by token**
`operationId`: `_web_api_user_get`

Get a user by token.

Required permissions: `Users.view`

Parameters:
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "225494730938493804,225494730938493915".
- `siteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `groupIds` [query, array] — List of Group IDs to filter by. Example: "225494730938493804,225494730938493915".
- `tenant` [query, boolean] — Indicates a tenant scope request

Responses: 401 Unauthorized access - please sign in and retry., 200 User retrieved correctly., 400 Invalid user input received. See error details for further i

## `GET /web/api/v2.1/users`
**List users**
`operationId`: `_web_api_users_get`

Get a list of users.

Required permissions: `Users.view`

Parameters:
- `skip` [query, integer] — Skip first number of items (0-1000). To iterate over more than 1000 items,  use "cursor". Example: "150".
- `limit` [query, integer] — Limit number of returned items (1-1000). Example: "10".
- `cursor` [query, string] — Cursor position returned by the last request. Use to iterate over more than 1000 items. Example: "YWdlbnRfaWQ6NTgwMjkzODE=".
- `countOnly` [query, boolean] — If true, only total number of items will be returned, without any of the actual objects.
- `skipCount` [query, boolean] — If true, total number of items will not be calculated, which speeds up execution time.
- `sortBy` [query, string] (enum: id, createdAt, fullName, firstLogin, lastLogin, source, email, emailVerified, dateJoined, twoFaEnabled, twoFaStatus, apiTokenCreatedAt, apiTokenExpiresAt, canGenerateApiToken) — The column to sort the results by. Example: "id".
- `sortOrder` [query, string] (enum: asc, desc) — Sort direction. Example: "asc".
- `siteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "225494730938493804,225494730938493915".
- `source` [query, string] (enum: mgmt, sso_saml, active_directory, global) — User Source. Example: "mgmt".
- `sources` [query, array] — Source in. Example: "mgmt".
- `email` [query, string] — Email. Example: "admin@sentinelone.com".
- `email__contains` [query, array] — Match email partially (substring)
- `emailReadOnly` [query, boolean] — True if email cannot be changed
- `fullName` [query, string] — Full name
- `fullName__contains` [query, array] — Match full name partially (substring)
- `fullNameReadOnly` [query, boolean] — True if full name cannot be changed
- `firstLogin` [query, string] — First login. Example: "2018-02-27T04:49:26.257525Z".
- `lastLogin` [query, string] — Last login. Example: "2018-02-27T04:49:26.257525Z".
- `dateJoined` [query, string] — Date joined. Example: "2018-02-27T04:49:26.257525Z".
- `groupsReadOnly` [query, boolean] — [DEPRECATED] True if permissions cannot be changed
- `twoFaEnabled` [query, boolean] — Two fa enabled
- `primaryTwoFaMethod` [query, string] — Primary two fa method
- `emailVerified` [query, boolean] — Return only verified/unverified users
- `query` [query, string] — Full text search for fields: full_name, email, description
- `ids` [query, array] — List of user IDs to filter by. Example: "225494730938493804,225494730938493915".
- `roleIds` [query, array] — List of rbac roles to filter by. Example: "225494730938493804,225494730938493915".
- `twoFaStatus` [query, string] — Two fa status
- `twoFaStatuses` [query, array] — Two fa status in
- `canGenerateApiToken` [query, boolean] — Can generate api token
- `hasValidApiToken` [query, boolean] — Has valid api token
- `lastActivation__lt` [query, string] — User was last active before this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `lastActivation__lte` [query, string] — User was last active before or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `lastActivation__gt` [query, string] — User was last active after this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `lastActivation__gte` [query, string] — User was last active after or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `lastActivation__between` [query, string] — Date range for when the user was last active (format: <from_timestamp>-<to_timestamp>, inclusive). Example: "1514978890136-1514978650130".
- `apiTokenExpiresAt__lt` [query, string] — API token expires before this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `apiTokenExpiresAt__lte` [query, string] — API token expires before or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `apiTokenExpiresAt__gt` [query, string] — API token expires after this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `apiTokenExpiresAt__gte` [query, string] — API token expires after or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `apiTokenExpiresAt__between` [query, string] — Date range for when the API token expires (format: <from_timestamp>-<to_timestamp>, inclusive). Example: "1514978890136-1514978650130".
- `createdAt__lt` [query, string] — User was created before this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__lte` [query, string] — User was created before or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__gt` [query, string] — User was created after this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__gte` [query, string] — User was created after or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__between` [query, string] — Date range for when the user was created (format: <from_timestamp>-<to_timestamp>, inclusive). Example: "1514978890136-1514978650130".

Responses: 401 Unauthorized access - please sign in and retry., 200 List of users retrieved successfully., 400 Invalid user input received. See error details for further i

## `POST /web/api/v2.1/users`
**Create User**
`operationId`: `_web_api_users_post`

Create a new user.

Required permissions: `Users.create`

Parameters:
- `body` [body, users.schemas_CreateUserSchema] — 

Responses: 403 Not enough permissions to create user., 200 User created successfully., 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/users/2fa/disable`
**Disable 2FA**
`operationId`: `_web_api_users_2fa_disable_post`

Disable Two-Factor Authentication for one user. This requires the ID of the user (run "users").
Optional permissions: `Users.edit`

Parameters:
- `body` [body, users.schemas_UserIdSchema] — 

Responses: 403 No permission for the action, 200 2FA successfully disabled, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/users/2fa/enable`
**Enable 2FA**
`operationId`: `_web_api_users_2fa_enable_post`

Enable two-factor authentication for a given user.
Optional permissions: `Users.edit`

Parameters:
- `body` [body, users.schemas_UserIdSchema] — 

Responses: 403 No permission for the action, 200 2FA successfully enabled, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/users/api-token-details`
**API Token Details**
`operationId`: `_web_api_users_api-token-details_post`

Get details of the API token that matches the filter.

Parameters:
- `body` [body, users.schemas_ApiTokenSchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i

## `POST /web/api/v2.1/users/auth/app`
**Auth App**
`operationId`: `_web_api_users_auth_app_post`

Authenticate a user with a third-party app, such as DUO or Google Authenticator, for deployments that require Two Factor Authentication.

Parameters:
- `body` [body, users.schemas_AuthCodeSchema] — 

Responses: 200 Authenticated, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/users/auth/elevate`
**Auth Elevate**
`operationId`: `_web_api_users_auth_elevate_post`

Elevate a session with a third-party app, such as DUO or Google Authenticator.

Parameters:
- `body` [body, users.schemas_ElevateSessionSchema] — 

Responses: 200 Elevated, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/users/auth/eula`
**Sign EULA**
`operationId`: `_web_api_users_auth_eula_post`

Mark the End User License Agreement (EULA) as signed for user scopes.

Responses: 200 Authenticated, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/users/change-password`
**Change Password**
`operationId`: `_web_api_users_change-password_post`

Change the user password.
Optional permissions: `Users.edit`

Parameters:
- `body` [body, users.schemas_ChangePasswordSchema] — 

Responses: 404 User not found, 403 Insufficient permissions, 200 Password changed, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/users/delete-2fa`
**Delete 2FA**
`operationId`: `_web_api_users_delete-2fa_post`

Delete 2FA for users.

Required permissions: `Users.edit, Users.allow2FAForOtherUsers`

Parameters:
- `body` [body, users.schemas_DeleteTfaSchema] — 

Responses: 404 User not found, 403 Insufficient permissions, 200 2FA delete completed, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/users/delete-users`
**Bulk Delete Users**
`operationId`: `_web_api_users_delete-users_post`

Delete all users that match the filter.

Required permissions: `Users.delete`

Parameters:
- `body` [body, users.schemas_BulkUsersActionSchema] — 

Responses: 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/users/enable-app`
**Enable 2FA App**
`operationId`: `_web_api_users_enable-app_post`

Enable support for the 2FA app (such as Duo or Google Authenticator) that your Console users will use to log in.

Parameters:
- `body` [body, users.schemas_EnableAppSchema] — 

Responses: 200 2FA app enabled, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/users/enroll-2fa`
**Enroll 2FA**
`operationId`: `_web_api_users_enroll-2fa_post`

Enroll users for 2FA setup.

Required permissions: `Users.edit, Users.allow2FAForOtherUsers`

Parameters:
- `body` [body, users.schemas_UserIdsSchema] — 

Responses: 404 User not found, 403 Insufficient permissions, 200 2FA enrollment completed, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/users/generate-api-token`
**Generate API Token**
`operationId`: `_web_api_users_generate-api-token_post`

Get the API token for the authenticated user.

Parameters:
- `body` [body, users.schemas_GenerateApiTokenSchema] — 

Responses: 409 API token conflict (already generated), 200 API token delivered to user, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/users/generate-iframe-token`
**Generate iFrame Token**
`operationId`: `_web_api_users_generate-iframe-token_post`

Get a new iFrame token with the provided limitations.

Required permissions: `Users.create`

Parameters:
- `body` [body, users.schemas_CreateIFrameUserSchema] — 

Responses: 403 Not enough permissions to create user., 200 User created successfully., 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/users/login`
**Login**
`operationId`: `_web_api_users_login_post`

Authenticate a user by username and password and return an authentication token. Rate limit: 1 call per second for each different IP address that communicates with the Console.

Parameters:
- `body` [body, users.schemas_LoginInputSchema] — 

Responses: 401 Login failed. May be the result of bad credentials, or a wro, 400 Invalid user input received. See error details for further i, 200 User authenticated successfully.

## `POST /web/api/v2.1/users/login-continue`
**Continue with login due to upcoming password expiration or SSO 2FA setup**
`operationId`: `_web_api_users_login-continue_post`

For SSO 2FA setup tokens, allows users to skip setting up the 2FA and proceed with their login.<br>Accepts a temporary token from SSO login flow with error code 4010035.<br><br>For password expiration tokens, allows users to decide if they want to change their soon to expire password now or later. <br>Users can also choose not to receive the notification again for this password cycle. <br>Accepts a temporary token from /users/login with error code 4010093.<br>For users eligible to be onboarded to global identity allows to decide if they want to skip and finish their login

Parameters:
- `body` [body, users.schemas_LoginContinueSchema] — 

Responses: 401 Unauthorized. <br>In password expiration flow, a temporary t, 200 Login can continue, 400 Invalid user input received. See error details for further i

## `POST /web/api/v2.1/users/login/by-api-token`
**Login by API Token**
`operationId`: `_web_api_users_login_by-api-token_post`

Log in to the API with a token. To learn more about temporary and 6-month tokens and how to generate them, see https://support.sentinelone.com/hc/en-us/articles/360004195934.

Parameters:
- `body` [body, users.schemas_LoginByApiTokenSchema] — 

Responses: 401 User authentication failed, 200 user logged in, 400 Invalid user input received. See error details for further i

## `GET /web/api/v2.1/users/login/by-token`
**Login by Token**
`operationId`: `_web_api_users_login_by-token_get`

Log in with user token.

Parameters:
- `token` [query, string] **required** — User token. Example: "bfd9070c1afa88516d3cdfd722e62fe433e42bad6bb14da27088140ad785585f8582adaccd56fb69".
- `removedSavedScope` [query, string] — Removed saved scope
- `redirectTo` [query, string] — Relative url to redirect to
- `redirectToParams` [query, string] — Query params for the redirect to, without '?' prefix

Responses: 401 User authentication failed, 200 user logged in, 400 Invalid user input received. See error details for further i

## `POST /web/api/v2.1/users/login/force-reset-password-on-login`
**Reset password on next login**
`operationId`: `_web_api_users_login_force-reset-password-on-login_post`

Force users to reset their password on next login.

Required permissions: `Users.edit`

Parameters:
- `body` [body, users.schemas_BulkUsersActionSchema] — 

Responses: 403 Insufficient permissions, 200 Users marked to reset password on next login successfully, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/users/login/send-reset-password-email`
**Prompt reset password**
`operationId`: `_web_api_users_login_send-reset-password-email_post`

Prompt reset password for users.

Required permissions: `Users.edit`

Parameters:
- `body` [body, users.schemas_BulkUsersActionSchema] — 

Responses: 403 Insufficient permissions, 200 Prompt reset password completed, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/users/login/set-password`
**Set a New Password**
`operationId`: `_web_api_users_login_set-password_post`

Sets a new password for the user. <br>Used by forced password reset and password expiration flows. <br>Accepts temporary tokens from /users/login with error codes 4010091 and 4010092.

Parameters:
- `body` [body, users.schemas_SetPasswordSchema] — 

Responses: 401 Unauthorized, 200 Password was set, 400 Invalid user input received. See error details for further i

## `GET /web/api/v2.1/users/login/sso-saml2`
**Redirect to SSO**
`operationId`: `_web_api_users_login_sso-saml2_get`

If SSO is enabled for a deployment or scope, and a user attempts to log in with name and password, this command redirects the login to SSO.

Parameters:
- `email` [query, string] — Email address of the user trying to log in. Example: "me@sentinelone.com".
- `scopeId` [query, string] — The scope the desired SSO IdP is configured on. email is irrelevant when using scope_id. If both are provided, email is ignored. Example: "225494730938493804".

Responses: 401 Not authenticated user., 302 Login redirected., 400 Invalid user input received. See error details for further i

## `POST /web/api/v2.1/users/login/sso-saml2/{scope_id}`
**Auth by SSO**
`operationId`: `_web_api_users_login_sso-saml2_{scope_id}_post`

Authenticate a Single Sign-On response over SAML v2 protocol.

Parameters:
- `scope_id` [path, string] **required** — Scope ID. Example: "225494730938493804".

Responses: 404 Site not found., 401 Not authenticated user., 302 SSO authenticated.

## `POST /web/api/v2.1/users/logout`
**Logout**
`operationId`: `_web_api_users_logout_post`

Log out the authenticated user.

Responses: 401 Unauthorized access - please sign in and retry., 200 User logged out successfully.

## `POST /web/api/v2.1/users/onboarding/send-verification-email`
**Send Verification Email**
`operationId`: `_web_api_users_onboarding_send-verification-email_post`

Send verification email to users that match the filter. Warning: Active users will be locked out of the Management Console until they verify (unless set_user_password_methods is on)their email. If your Management Console has Onboarding enabled, when you create a new user, the user gets an email invitation. If the user does not respond in time or loses the email, you can send it again. You can send the email invitation to multiple users. Your SMTP server must be correctly configured in Settings > SMTP for the Global scope. Changing the Global SMTP settings requires an Admin role with Global scope or Support.

Required permissions: `Users.edit`

Parameters:
- `body` [body, users.schemas_BulkUsersActionSchema] — 

Responses: 403 Insufficient permissions, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/users/onboarding/validate-token`
**Validate Verification Token**
`operationId`: `_web_api_users_onboarding_validate-token_get`

When a new user verifies their email, the Management gets a token.  Use this command to validate the token.

Parameters:
- `token` [query, string] **required** — Verification token
- `resetPasswordFlow` [query, boolean] — Reset password flow

Responses: 404 A user matching the input verification token wasn't found, 401 Verification failed, 400 Invalid user input received. See error details for further i, 200 Token is valid

## `POST /web/api/v2.1/users/onboarding/verify`
**Email Verification**
`operationId`: `_web_api_users_onboarding_verify_post`

When a new user verifies their email, the Management gets a token. Use this command to verify the token and set a new password.

Parameters:
- `body` [body, users.schemas_OnboardingVerificationSchema] — 

Responses: 404 A user matching the input verification token wasn't found, 401 Verification failed, 400 Invalid user input received. See error details for further i, 200 User successfully verified

## `POST /web/api/v2.1/users/request-app`
**Request 2FA App**
`operationId`: `_web_api_users_request-app_post`

Request 2FA App response.

Parameters:
- `body` [body, users.schemas_RequestAppSchema] — 

Responses: 400 Invalid user input received. See error details for further i, 200 Success, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/users/reset-2fa`
**Reset 2FA**
`operationId`: `_web_api_users_reset-2fa_post`

Reset 2FA for users.

Required permissions: `Users.edit, Users.allow2FAForOtherUsers`

Parameters:
- `body` [body, users.schemas_ResetTfaSchema] — 

Responses: 404 User not found, 403 Insufficient permissions, 200 2FA reset completed, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/users/revoke-api-token`
**Revoke API Token**
`operationId`: `_web_api_users_revoke-api-token_post`

Revoke an API token.
Optional permissions: `Users.revokeOtherUsersApiTokens`

Parameters:
- `body` [body, users.schemas_UserIdSchema] — 

Responses: 404 User not found, 403 Insufficient permissions, 200 Api token revoked, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/users/rs-auth-check`
**Check Remote Shell Permissions**
`operationId`: `_web_api_users_rs-auth-check_get`

See if the logged in user is allowed to use Remote Shell.

Required permissions: `Endpoints.remoteShell`

Responses: 403 Insufficient permissions, 200 User is allowed to use remote shell feature., 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/users/sso-saml2/re-auth`
**Redirect to SSO for re-authentication**
`operationId`: `_web_api_users_sso-saml2_re-auth_get`

Initiates re-authentication with user's identity provider.

Responses: 500 Error in SAML handler initialization., 403 User is not allowed to re-authenticate with their IDP, 302 Redirect user to their IDP for re-authentication., 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/users/tenant-admin-auth-check`
**Check Global User**
`operationId`: `_web_api_users_tenant-admin-auth-check_get`

See if logged in user is a user with the Global scope of access.

Responses: 403 Insufficient permissions, 200 User is Global., 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/users/viewer-auth-check`
**Check Viewer**
`operationId`: `_web_api_users_viewer-auth-check_get`

See if the logged in user has only viewer permissions.

Responses: 200 User is a viewer., 401 Unauthorized access - please sign in and retry.

## `DELETE /web/api/v2.1/users/{user_id}`
**Delete User**
`operationId`: `_web_api_users_{user_id}_delete`

Delete a user by ID.

Required permissions: `Users.delete`

Parameters:
- `user_id` [path, string] **required** — User ID. Example: "225494730938493804".

Responses: 403 Insufficient permissions., 200 User deleted successfully., 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/users/{user_id}`
**Get User**
`operationId`: `_web_api_users_{user_id}_get`

Get a user by ID.

Required permissions: `Users.view`

Parameters:
- `user_id` [path, string] **required** — User ID. Example: "225494730938493804".

Responses: 404 Could not retrieve user., 403 Insufficient permissions., 200 User retrieved successfully., 401 Unauthorized access - please sign in and retry.

## `PUT /web/api/v2.1/users/{user_id}`
**Update User**
`operationId`: `_web_api_users_{user_id}_put`

Change properties of the user of the given ID.
Optional permissions: `Users.edit, Users.allowGenerateApiToken`

Parameters:
- `user_id` [path, string] **required** — User ID. Example: "225494730938493804".
- `body` [body, users.schemas_UpdateUserSchema] — 

Responses: 409 User or Email already taken., 404 User not found., 403 Forbidden., 200 User updated successfully., 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/users/{user_id}/api-token-details`
**API Token by User ID**
`operationId`: `_web_api_users_{user_id}_api-token-details_get`

Get the details of the API token generated for a given user.
Optional permissions: `Users.view`

Parameters:
- `user_id` [path, string] **required** — User ID. Example: "225494730938493804".

Responses: 404 User not found, 403 Insufficient permissions, 200 Success, 401 Unauthorized access - please sign in and retry.
