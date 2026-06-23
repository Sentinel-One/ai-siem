# Settings

27 endpoints.

## `GET /web/api/v2.1/settings/active-directory`
**Get AD Settings**
`operationId`: `_web_api_settings_active-directory_get`

Get the Global Active Directory settings.

Required permissions: `Integrations.view`

Parameters:
- `siteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "225494730938493804,225494730938493915".

Responses: 403 User is not allowed in this scope, 200 Data retrieved successfully, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `PUT /web/api/v2.1/settings/active-directory`
**Set AD Settings**
`operationId`: `_web_api_settings_active-directory_put`

Update the Global Active Directory settings.

Required permissions: `Integrations.edit`

Parameters:
- `body` [body, settings_AdSettingsPutSchema] — 

Responses: 400 Invalid user input received. See error details for further i, 200 Success, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/settings/active-directory/scope-mapping`
**Get AD FQDNs**
`operationId`: `_web_api_settings_active-directory_scope-mapping_get`

Get the map of Active Directory FQDNs to user roles of the given Sites (use "sites" to get IDs) or Accounts ("accounts").

Required permissions: `Integrations.view`

Parameters:
- `siteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "225494730938493804,225494730938493915".

Responses: 403 User is not allowed in this scope, 200 Data retrieved successfully, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `PUT /web/api/v2.1/settings/active-directory/scope-mapping`
**Set AD FQDNs**
`operationId`: `_web_api_settings_active-directory_scope-mapping_put`

Update the Active Directory FQDNs of a Site or Account.

Required permissions: `Integrations.edit`

Parameters:
- `body` [body, settings_AdFqdnsPutSchema] — 

Responses: 404 Scope does not exist, 403 User is not allowed in this scope, 400 Invalid user input received. See error details for further i, 200 Success, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/settings/active-directory/test`
**Test AD Settings**
`operationId`: `_web_api_settings_active-directory_test_post`

Test Active Directory settings.

Required permissions: `Integrations.create`

Parameters:
- `body` [body, settings_AdSettingsPutSchema] — 

Responses: 404 Scope does not exist, 400 Invalid user input received. See error details for further i, 200 Data retrieved successfully, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/settings/microsoft`
**Get Microsoft Settings**
`operationId`: `_web_api_settings_microsoft_get`

[DEPRECATED] Gets the Microsoft settings of the Sites or Accounts.

Required permissions: `Integrations.view`

Parameters:
- `siteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "225494730938493804,225494730938493915".

Responses: 404 Scope does not exist, 403 User is not allowed in this scope, 200 Data retrieved successfully, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `PUT /web/api/v2.1/settings/microsoft`
**Set Microsoft Settings**
`operationId`: `_web_api_settings_microsoft_put`

[DEPRECATED] Update Microsoft settings for the given Sites or Accounts.

Required permissions: `Integrations.edit`

Parameters:
- `body` [body, settings_MicrosoftSettingsPutSchema] — 

Responses: 404 Scope does not exist, 403 User is not allowed in this scope, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/settings/microsoft/test`
**Test Microsoft Settings**
`operationId`: `_web_api_settings_microsoft_test_post`

[DEPRECATED] Test Microsoft settings.

Required permissions: `Integrations.create`

Parameters:
- `body` [body, settings_MicrosoftSettingsPutSchema] — 

Responses: 404 Scope does not exist, 200 Data retrieved successfully, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/settings/notifications`
**Get Notification Settings**
`operationId`: `_web_api_settings_notifications_get`

Get the notification settings for the given Sites (to get the IDs, run "settings") or Accounts ("accounts"). <br>The response shows every possible notification and whether it is active and if so, for email or syslog or both. It also shows the ID string for each notification, which can be used in other commands. <br>Note: Each notification also shows "sms" which is deprecated.

Required permissions: `Notifications.view`

Parameters:
- `siteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "225494730938493804,225494730938493915".

Responses: 403 User is not allowed in this scope, 200 Data retrieved successfully, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `PUT /web/api/v2.1/settings/notifications`
**Set Notification Settings**
`operationId`: `_web_api_settings_notifications_put`

Change the notifications for the given Sites (to get the IDs, run "settings") or Accounts ("accounts"). Best practice: Get the current settings (see Get Notification Settings) before you run this command.

Required permissions: `Notifications.edit`

Parameters:
- `body` [body, notifications_schemas_NotificationSettingsPutSchema] — 

Responses: 404 Scope does not exist, 403 User is not allowed in this scope, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/settings/notifications/cancel-pending-emails`
**Clear Pending Emails**
`operationId`: `_web_api_settings_notifications_cancel-pending-emails_post`

Clear (discard without sending) pending email notifications for the given Sites (to get the IDs, run "sites") or Accounts ("accounts"). <br>When you set email recipients to get notifications for activities in the system, you can set too many, or in other ways cause issues that demand that the queue be cleared.

Required permissions: `Notifications.delete`

Parameters:
- `body` [body, notifications_schemas_CancelPendingEmailNotificationsPostSchema] — 

Responses: 404 Scope does not exist, 403 User is not allowed in this scope, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/settings/recipients`
**Get Notification Recipients**
`operationId`: `_web_api_settings_recipients_get`

Get the emails that are configured to receive notifications.

Required permissions: `Notifications.view`

Parameters:
- `siteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "225494730938493804,225494730938493915".
- `name` [query, string] — Name
- `email` [query, string] — Email
- `sms` [query, string] — Sms
- `query` [query, string] — Full text search for fields: name, email, sms

Responses: 404 Scope does not exist, 403 User is not allowed in this scope, 200 Data retrieved successfully, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `PUT /web/api/v2.1/settings/recipients`
**Set Notification Recipients**
`operationId`: `_web_api_settings_recipients_put`

Set the emails of recipients to get notifications.

Required permissions: `Notifications.edit`
Optional permissions: `Notifications.create`

Parameters:
- `body` [body, settings_NotificationRecipientSettingsPutSchema] — 

Responses: 404 Scope does not exist, 403 User is not allowed in this scope, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `DELETE /web/api/v2.1/settings/recipients/{recipient_id}`
**Delete Notification Recipient**
`operationId`: `_web_api_settings_recipients_{recipient_id}_delete`

Delete a notification recipient by ID. To get the IDs of recipients, run "recipients" (see Get Notification Recipients).

Required permissions: `Notifications.delete`

Parameters:
- `recipient_id` [path, string] **required** — Recipient ID. Example: "225494730938493804".

Responses: 403 Insufficient permissions., 200 Recipient deleted successfully., 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/settings/sms`
**Get SMS Settings**
`operationId`: `_web_api_settings_sms_get`

[DEPRECATED] Gets the site's SMS settings.

Required permissions: `Integrations.view`

Parameters:
- `siteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "225494730938493804,225494730938493915".

Responses: 404 Scope does not exist, 403 User is not allowed in this scope, 200 Data retrieved successfully, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `PUT /web/api/v2.1/settings/sms`
**Set SMS Settings**
`operationId`: `_web_api_settings_sms_put`

[DEPRECATED] Set SMS settings.

Required permissions: `Integrations.edit`

Parameters:
- `body` [body, settings_SmsSettingsPutSchema] — 

Responses: 404 Scope does not exist, 403 User is not allowed in this scope, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/settings/smtp`
**Get SMTP Settings**
`operationId`: `_web_api_settings_smtp_get`

Get the SMTP server configuration of the given Sites (to get the IDs, run "sites") or Accounts ("accounts"). The SMTP integration is required to send notifications by email.

Required permissions: `Integrations.view`

Parameters:
- `siteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "225494730938493804,225494730938493915".

Responses: 404 Scope does not exist, 403 User is not allowed in this scope, 200 Data retrieved successfully, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `PUT /web/api/v2.1/settings/smtp`
**Set SMTP Settings**
`operationId`: `_web_api_settings_smtp_put`

Change the SMTP server configuration for the given Sites or Accounts. Use this command to integrate a different SMTP server, which is required to send notifications by email.

Required permissions: `Integrations.edit`

Parameters:
- `body` [body, settings_SmtpSettingsPutSchema] — 

Responses: 404 Scope does not exist, 403 User is not allowed in this scope, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/settings/smtp/test`
**Test SMTP Settings**
`operationId`: `_web_api_settings_smtp_test_post`

Test SMTP settings between the Management and the SMTP server. This integration is required if you use email notifications.

Required permissions: `Integrations.create`

Parameters:
- `body` [body, settings_SmtpSettingsTestSchema] — 

Responses: 404 Scope does not exist, 200 Data retrieved successfully, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/settings/sso`
**Get SSO Settings**
`operationId`: `_web_api_settings_sso_get`

Get the Single Sign-On configuration for the given Sites (to get the IDs, run "sites") or Accounts ("accounts").

Required permissions: `Integrations.view`

Parameters:
- `siteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "225494730938493804,225494730938493915".

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `PUT /web/api/v2.1/settings/sso`
**Set SSO Settings**
`operationId`: `_web_api_settings_sso_put`

Change the Single Sign-On configuration for the given Sites (to get the IDs, run "sites") or Accounts ("accounts"). <br>The Management supports SAML 2.0 and will integrate with SAML 2.0 compliant SSO providers. <br>SentinelOne Technical Support can help you with issues related to the provider we tested: Okta. To use a different ID provider, see the provider documentation and support. <br>For requirements and best practices of Okta integration, see https://support.sentinelone.com/hc/en-us/articles/360004195714.

Required permissions: `Integrations.edit`

Parameters:
- `body` [body, settings_SsoSettingsPutSchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/settings/sso/sp-cert`
**Get SSO Service Provider Certificate**
`operationId`: `_web_api_settings_sso_sp-cert_get`

Get the Service Provider Certificate for the Single Sign-On configuration for the given scope.

Required permissions: `Integrations.view`

Parameters:
- `siteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "225494730938493804,225494730938493915".

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/settings/sso/sp-cert/download`
**Download SSO Service Provider Certificate**
`operationId`: `_web_api_settings_sso_sp-cert_download_get`

Download the Service Provider Certificate for the Single Sign-On configuration for the given scope.

Required permissions: `Integrations.view`

Parameters:
- `siteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "225494730938493804,225494730938493915".

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/settings/sso/test`
**Test SSO Settings**
`operationId`: `_web_api_settings_sso_test_post`

Test Single Sign-On settings.

Required permissions: `Integrations.create`

Parameters:
- `body` [body, settings_SsoSettingsPutSchema] — 

Responses: 200 The url to redirect too., 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/settings/syslog`
**Get Syslog Settings**
`operationId`: `_web_api_settings_syslog_get`

Get the configuration of the syslog server integrated with the given Sites (to get the IDs, run "sites") or Accounts ("accounts").

Required permissions: `Integrations.view`

Parameters:
- `siteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "225494730938493804,225494730938493915".

Responses: 404 Scope does not exist, 403 User is not allowed in this scope, 200 Data retrieved successfully, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `PUT /web/api/v2.1/settings/syslog`
**Set Syslog Settings**
`operationId`: `_web_api_settings_syslog_put`

Change the configuration of the syslog server of the given Sites (to get the IDs, run "sites") or Accounts ("accounts"). Use this command to send notifications to a different syslog server. Best Practice: Get Syslog Settings before you run this command.

Required permissions: `Integrations.edit`

Parameters:
- `body` [body, settings_SyslogSettingsPutSchema] — 

Responses: 404 Scope does not exist, 403 User is not allowed in this scope, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/settings/syslog/test`
**Test Syslog Settings**
`operationId`: `_web_api_settings_syslog_test_post`

Test Syslog settings. The Management tests the connection to the Syslog server.

Required permissions: `Integrations.create`

Parameters:
- `body` [body, settings_SyslogSettingsPutSchema] — 

Responses: 404 Scope does not exist, 200 Data retrieved successfully, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.
