# Forensics

4 endpoints.

## `GET /web/api/v2.1/applications/{application_id}/forensics`
**Application Forensics**
`operationId`: `_web_api_applications_{application_id}_forensics_get`

DEPRECATED

Required permissions: `Threats.view, Applications Page.view`

Parameters:
- `application_id` [path, string] **required** — Application ID. Example: "56ee72a79c7e5c62dd36e6b1".
- `siteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "225494730938493804,225494730938493915".
- `groupIds` [query, array] — List of Group IDs to filter by. Example: "225494730938493804,225494730938493915".

Responses: 404 Not found, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/applications/{application_id}/forensics/connections`
**Application Connections**
`operationId`: `_web_api_applications_{application_id}_forensics_connections_get`

[DEPRECATED] Returns an empty array

Required permissions: `Threats.view, Applications Page.view`

Parameters:
- `application_id` [path, string] **required** — Application ID. Example: "56ee72a79c7e5c62dd36e6b1".
- `siteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "225494730938493804,225494730938493915".
- `groupIds` [query, array] — List of Group IDs to filter by. Example: "225494730938493804,225494730938493915".
- `country_code` [query, string] — Country code

Responses: 404 Not found, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/applications/{application_id}/forensics/details`
**Application Forensics - Detailed**
`operationId`: `_web_api_applications_{application_id}_forensics_details_get`

[DEPRECATED] Returns an empty array

Required permissions: `Threats.view, Applications Page.view`

Parameters:
- `application_id` [path, string] **required** — Application ID. Example: "56ee72a79c7e5c62dd36e6b1".
- `siteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "225494730938493804,225494730938493915".
- `groupIds` [query, array] — List of Group IDs to filter by. Example: "225494730938493804,225494730938493915".

Responses: 404 Not found, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/applications/{application_id}/forensics/export/{export_format}`
**Export Application**
`operationId`: `_web_api_applications_{application_id}_forensics_export_{export_format}_get`

[DEPRECATED] Returns an empty array

Required permissions: `Threats.view, Applications Page.view`

Parameters:
- `application_id` [path, string] **required** — Application ID. Example: "56ee72a79c7e5c62dd36e6b1".
- `export_format` [path, string] **required** (enum: csv, json) — Export format. Example: "csv".
- `siteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "225494730938493804,225494730938493915".
- `groupIds` [query, array] — List of Group IDs to filter by. Example: "225494730938493804,225494730938493915".

Responses: 404 Not found, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.
