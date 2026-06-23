# ISPM

6 endpoints.

## `GET /web/api/v2.1/ranger-ad/assessment-status`
**Get Assessment Status**
`operationId`: `_web_api_ranger-ad_assessment-status_get`

Use the below Cloud API to get the status of the AD Assessment status for that account

Required permissions: `AD Exposures.View`

Parameters:
- `siteIds` [query, string] — List of site IDs separated by comma
- `accountIds` [query, string] — List of account IDs separated by comma

Responses: 403 Insufficient permissions, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/ranger-ad/get-affected-objects`
**Get Affected Objects**
`operationId`: `_web_api_ranger-ad_get-affected-objects_post`

Use the below Cloud API to get all the affected objects based on the selected filters

Required permissions: `AD Exposures.View`

Parameters:
- `limit` [query, integer] — Limit number of returned items (1-1000). Example: "10".
- `skip` [query, integer] — Skip first number of items (0-1000). To iterate over more than 1000 items,  use "cursor". Example: "150".
- `accountIds` [query, string] — List of account IDs separated by comma
- `siteIds` [query, string] — List of site IDs separated by comma
- `body` [body, v2_1.public_api.schemas_GetAffectedObjectsRequestSchema] — 

Responses: 403 Insufficient permissions, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/ranger-ad/get-exposures`
**Get Exposures**
`operationId`: `_web_api_ranger-ad_get-exposures_post`

Use the below Cloud API to get all the exposures based on the selected filters

Required permissions: `AD Exposures.View`

Parameters:
- `limit` [query, integer] — Limit number of returned items (1-1000). Example: "10".
- `skip` [query, integer] — Skip first number of items (0-1000). To iterate over more than 1000 items,  use "cursor". Example: "150".
- `accountIds` [query, string] — List of account IDs separated by comma
- `siteIds` [query, string] — List of site IDs separated by comma
- `body` [body, v2_1.public_api.schemas_GetExposuresRequestSchema] — 

Responses: 403 Insufficient permissions, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/ranger-ad/set-ack-status`
**Set Acknowledged Status**
`operationId`: `_web_api_ranger-ad_set-ack-status_post`

Use the below Cloud API to set acknowledgement status

Required permissions: `AD Exposures.Ack or Unack AD Assessment`

Parameters:
- `siteIds` [query, string] — List of site IDs separated by comma
- `accountIds` [query, string] — List of account IDs separated by comma
- `body` [body, v2_1.public_api.schemas_SetAckExposuresRequestSchema] — 

Responses: 403 Insufficient permissions, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/ranger-ad/set-skipped-exposures`
**Set Skipped Exposures**
`operationId`: `_web_api_ranger-ad_set-skipped-exposures_post`

Use the below Cloud API to set the list of exposures to be skipped

Required permissions: `AD Exposure Exclusions.Edit`

Parameters:
- `siteIds` [query, string] — List of site IDs separated by comma
- `accountIds` [query, string] — List of account IDs separated by comma
- `body` [body, v2_1.public_api.schemas_SetSkippedExposuresRequestSchema] — 

Responses: 403 Insufficient permissions, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/ranger-ad/trigger-assessment`
**Trigger Assessment**
`operationId`: `_web_api_ranger-ad_trigger-assessment_post`

Use the below Cloud API to trigger ADAssessment

Required permissions: `AD Exposures.Trigger Assessment`

Parameters:
- `siteIds` [query, string] — List of site IDs separated by comma
- `accountIds` [query, string] — List of account IDs separated by comma
- `body` [body, v2_1.public_api.schemas_TriggerAssessmentRequestSchema] — 

Responses: 403 Insufficient permissions, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.
