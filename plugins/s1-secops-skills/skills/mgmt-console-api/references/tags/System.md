# System

7 endpoints.

## `GET /web/api/v2.1/system/configuration`
**Get System Config**
`operationId`: `_web_api_system_configuration_get`

Get the configuration of your SentinelOne system. <br>The response shows basic information of the deployed SKUs and licenses, 2FA, and the Management URL.

Required permissions: `Configuration.view`

Parameters:
- `siteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "225494730938493804,225494730938493915".

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `PUT /web/api/v2.1/system/configuration`
**Set System Config**
`operationId`: `_web_api_system_configuration_put`

Change the system configuration. <br>Before you run this, see Get System Config. <br>This command requires a Global Admin user or Support.

Required permissions: `Configuration.edit`
Optional permissions: `Users.allow2FAForOtherUsers`

Parameters:
- `body` [body, system_PutSystemConfiguration] — 

Responses: 403 Insufficient permissions, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/system/env`
**System Environment**
`operationId`: `_web_api_system_env_get`

Get environment details of the system

Responses: 200 Success

## `GET /web/api/v2.1/system/info`
**System Info**
`operationId`: `_web_api_system_info_get`

Get the Console build, version, patch, and release information.

Responses: 200 Success, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/system/status`
**System Status**
`operationId`: `_web_api_system_status_get`

Get an indication of the system's health status. <br>This command always returns a positive response when the Management Console and API server are up and running. In these cases, some features or capabilities might be impaired. This command does not require authentication.<br>Rate limit: 1 call per second for each IP address that communicates with the Console.

Responses: 200 Success

## `GET /web/api/v2.1/system/status/cache`
**Cache Status**
`operationId`: `_web_api_system_status_cache_get`

[DEPRECATED] Works the same way as "System Status" endpoint.<br>This command does not require authentication. <br>Rate limit: 1 call per second for each IP address that communicates with the Console.

Responses: 200 Success

## `GET /web/api/v2.1/system/status/db`
**Database Status**
`operationId`: `_web_api_system_status_db_get`

[DEPRECATED] Works the same way as "System Status" endpoint.<br>This command does not require authentication. <br>Rate limit: 1 call per second for each IP address that communicates with the Console.

Responses: 200 Success
