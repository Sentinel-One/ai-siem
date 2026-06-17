# Threat Notes

4 endpoints.

## `POST /web/api/v2.1/threats/notes`
**Add Note to Multiple**
`operationId`: `_web_api_threats_notes_post`

Add a threat note to multiple threats.

Required permissions: `Threats.view`

Parameters:
- `body` [body, threats.schemas_ThreatsNoteCreateSchema] — 

Responses: 200 Threats note successfully created, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/threats/{threat_id}/notes`
**Get Threat Notes**
`operationId`: `_web_api_threats_{threat_id}_notes_get`

Get the threat notes that match the filter.

Required permissions: `Threats.view`

Parameters:
- `threat_id` [path, string] **required** — Threat ID. Example: "225494730938493804".
- `skip` [query, integer] — Skip first number of items (0-1000). To iterate over more than 1000 items,  use "cursor". Example: "150".
- `limit` [query, integer] — Limit number of returned items (1-1000). Example: "10".
- `cursor` [query, string] — Cursor position returned by the last request. Use to iterate over more than 1000 items. Example: "YWdlbnRfaWQ6NTgwMjkzODE=".
- `countOnly` [query, boolean] — If true, only total number of items will be returned, without any of the actual objects.
- `skipCount` [query, boolean] — If true, total number of items will not be calculated, which speeds up execution time.
- `sortBy` [query, string] (enum: createdAt, updatedAt) — The column to sort the results by. Example: "id".
- `sortOrder` [query, string] (enum: asc, desc) — Sort direction. Example: "asc".
- `creator__like` [query, string] — Threat Note creator name (partially or full). Example: "John".
- `creatorId` [query, string] — Threat Note creator ID. Example: "225494730938493804".

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `DELETE /web/api/v2.1/threats/{threat_id}/notes/{note_id}`
**Delete Threat Note**
`operationId`: `_web_api_threats_{threat_id}_notes_{note_id}_delete`

Delete a threat note.

Required permissions: `Threats.view`

Parameters:
- `threat_id` [path, string] **required** — Threat ID. Example: "225494730938493804".
- `note_id` [path, string] **required** — Threat Note ID. Example: "225494730938493804".

Responses: 200 Threat note successfully deleted, 401 Unauthorized access - please sign in and retry.

## `PUT /web/api/v2.1/threats/{threat_id}/notes/{note_id}`
**Update Threat Note**
`operationId`: `_web_api_threats_{threat_id}_notes_{note_id}_put`

Change the text of a threat note.

Required permissions: `Threats.view`

Parameters:
- `threat_id` [path, string] **required** — Threat ID. Example: "225494730938493804".
- `note_id` [path, string] **required** — Threat Note ID. Example: "225494730938493804".
- `body` [body, threats.schemas_PostThreatNoteDataSchema] — 

Responses: 200 Threat note successfully updated, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.
