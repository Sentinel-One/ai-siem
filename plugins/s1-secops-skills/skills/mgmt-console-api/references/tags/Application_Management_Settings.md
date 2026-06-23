# Application Management Settings

2 endpoints.

## `GET /web/api/v2.1/application-management/settings`
**Get Application Management Settings**
`operationId`: `_web_api_application-management_settings_get`

Get Application Management settings.

Required permissions: `Applications Page.view`

Parameters:
- `siteIds` [query, array] — Single Site ID to filter by. Example: "225494730938493804".
- `groupIds` [query, array] — Single Group ID to filter by. Example: "225494730938493804".
- `accountIds` [query, array] — Single Account ID to filter by. Example: "225494730938493804".

Responses: 403 Insufficient permissions, 400 Invalid user input received. See error details for further i, 200 Success, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/application-management/settings`
**Update Application Management Settings**
`operationId`: `_web_api_application-management_settings_post`

Update Application Management Settings
Optional permissions: `Applications Page.scanVulnerabilities, Applications Page.changeVulnerabilitiesScanPolicy`

Parameters:
- `body` [body, v2_1.application_management.settings_filters_ApplicationManagementSettingsSchema] — 

Responses: 403 Insufficient permissions, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.
