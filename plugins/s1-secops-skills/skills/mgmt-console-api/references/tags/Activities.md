# Activities

4 endpoints.

## `GET /web/api/v2.1/activities`
**Get Activities**
`operationId`: `_web_api_activities_get`

Get the activities, and their data, that match the filters.
 We recommend that you set some values for the filters. The full list will be too large to be useful.

Required permissions: `Activity Page.view`

Parameters:
- `skip` [query, integer] — Skip first number of items (0-1000). To iterate over more than 1000 items,  use "cursor". Example: "150".
- `limit` [query, integer] — Limit number of returned items (1-1000). Example: "10".
- `cursor` [query, string] — Cursor position returned by the last request. Use to iterate over more than 1000 items. Example: "YWdlbnRfaWQ6NTgwMjkzODE=".
- `countOnly` [query, boolean] — If true, only total number of items will be returned, without any of the actual objects.
- `skipCount` [query, boolean] — If true, total number of items will not be calculated, which speeds up execution time.
- `sortBy` [query, string] (enum: id, activityType, createdAt) — The column to sort the results by. Example: "id".
- `sortOrder` [query, string] (enum: asc, desc) — Sort direction. Example: "asc".
- `siteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "225494730938493804,225494730938493915".
- `groupIds` [query, array] — List of Group IDs to filter by. Example: "225494730938493804,225494730938493915".
- `createdAt__lt` [query, string] — Get activities created before this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__gt` [query, string] — Get activities created after this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__lte` [query, string] — Get activities created before or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__gte` [query, string] — Get activities created after or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__between` [query, string] — Get activities created in this range (inclusive) of a start timestamp and an end timestamp. Example: "1514978764288-1514978999999".
- `activityTypes` [query, array] — Return only these activity codes (comma-separated list). Select a code from the drop-down, or see the id field from the Get activity types command. . Example: "52,53,71,72".
- `includeHidden` [query, boolean] — Include internal activities hidden from display. Example: "False".
- `threatIds` [query, array] — Return activities related to specified threats. Example: "225494730938493804,225494730938493915".
- `agentIds` [query, array] — Return activities related to specified agents. Example: "225494730938493804,225494730938493915".
- `ids` [query, array] — Filter activities by specific activity IDs. Example: "225494730938493804,225494730938493915".
- `activityUuids` [query, array] — Return activities by specific activity UUIDs. Example: "a2c8037c-e6df-436d-b92b-bc09a418717e,f15b308b-fab9-4c0b-b6f5-17d236a7bf55".
- `userIds` [query, array] — The user who invoked the activity (If applicable). Example: "225494730938493804,225494730938493915".
- `userEmails` [query, array] — Email of the user who invoked the activity (If applicable)
- `ruleIds` [query, array] — Return activities related to specified rules. Example: "225494730938493804,225494730938493915".
- `alertIds` [query, array] — Return activities related to specified alerts. Example: "225494730938493804,225494730938493915".
- `relatedIds` [query, array] — Return activities related to specified entities. Example: "56ee72a79c7e5c62dd36e6b1".

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/activities/types`
**Get Activity Types**
`operationId`: `_web_api_activities_types_get`

Get a list of activity types. This is useful to see valid values to filter activities in other commands.

Required permissions: `Activity Page.view`

Responses: 200 Success, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/export/activities`
**Export Activities**
`operationId`: `_web_api_export_activities_get`

Export the list of activities.

Required permissions: `Activity Page.view`

Parameters:
- `siteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "225494730938493804,225494730938493915".
- `groupIds` [query, array] — List of Group IDs to filter by. Example: "225494730938493804,225494730938493915".
- `createdAt__lt` [query, string] — Get activities created before this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__gt` [query, string] — Get activities created after this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__lte` [query, string] — Get activities created before or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__gte` [query, string] — Get activities created after or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__between` [query, string] — Get activities created in this range (inclusive) of a start timestamp and an end timestamp. Example: "1514978764288-1514978999999".
- `activityTypes` [query, array] — Return only these activity codes (comma-separated list). Select a code from the drop-down, or see the id field from the Get activity types command. . Example: "52,53,71,72".
- `includeHidden` [query, boolean] — Include internal activities hidden from display. Example: "False".
- `threatIds` [query, array] — Return activities related to specified threats. Example: "225494730938493804,225494730938493915".
- `agentIds` [query, array] — Return activities related to specified agents. Example: "225494730938493804,225494730938493915".
- `ids` [query, array] — Filter activities by specific activity IDs. Example: "225494730938493804,225494730938493915".
- `activityUuids` [query, array] — Return activities by specific activity UUIDs. Example: "a2c8037c-e6df-436d-b92b-bc09a418717e,f15b308b-fab9-4c0b-b6f5-17d236a7bf55".
- `userIds` [query, array] — The user who invoked the activity (If applicable). Example: "225494730938493804,225494730938493915".
- `userEmails` [query, array] — Email of the user who invoked the activity (If applicable)
- `ruleIds` [query, array] — Return activities related to specified rules. Example: "225494730938493804,225494730938493915".
- `alertIds` [query, array] — Return activities related to specified alerts. Example: "225494730938493804,225494730938493915".
- `relatedIds` [query, array] — Return activities related to specified entities. Example: "56ee72a79c7e5c62dd36e6b1".
- `rowsLimit` [query, integer] — Limit number of returned items (1-10000). Example: "100".

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/last-activity-as-syslog`
**Last activity as Syslog message**
`operationId`: `_web_api_last-activity-as-syslog_get`

To see examples of Syslog messages, you can get the Syslog message that corresponds to the last activity that matches the filter. This is not intended for production purposes.<br>If Syslog messages that you expected to see are not in the response, make sure you selected "Syslog" for the activity type in Console > Settings > Notifications.<br>To see your Syslog settings, run: "settings/notifications".<br>To changethe settings, run: "settings/notifications" with the changes in the body of the request.

Required permissions: `Activity Page.view`

Parameters:
- `skip` [query, integer] — Skip first number of items (0-1000). To iterate over more than 1000 items,  use "cursor". Example: "150".
- `limit` [query, integer] — Limit number of returned items (1-1000). Example: "10".
- `cursor` [query, string] — Cursor position returned by the last request. Use to iterate over more than 1000 items. Example: "YWdlbnRfaWQ6NTgwMjkzODE=".
- `countOnly` [query, boolean] — If true, only total number of items will be returned, without any of the actual objects.
- `skipCount` [query, boolean] — If true, total number of items will not be calculated, which speeds up execution time.
- `sortBy` [query, string] (enum: id, activityType, createdAt) — The column to sort the results by. Example: "id".
- `sortOrder` [query, string] (enum: asc, desc) — Sort direction. Example: "asc".
- `siteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "225494730938493804,225494730938493915".
- `groupIds` [query, array] — List of Group IDs to filter by. Example: "225494730938493804,225494730938493915".
- `createdAt__lt` [query, string] — Get activities created before this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__gt` [query, string] — Get activities created after this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__lte` [query, string] — Get activities created before or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__gte` [query, string] — Get activities created after or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__between` [query, string] — Get activities created in this range (inclusive) of a start timestamp and an end timestamp. Example: "1514978764288-1514978999999".
- `activityTypes` [query, array] — Return only these activity codes (comma-separated list). Select a code from the drop-down, or see the id field from the Get activity types command. . Example: "52,53,71,72".
- `includeHidden` [query, boolean] — Include internal activities hidden from display. Example: "False".
- `threatIds` [query, array] — Return activities related to specified threats. Example: "225494730938493804,225494730938493915".
- `agentIds` [query, array] — Return activities related to specified agents. Example: "225494730938493804,225494730938493915".
- `ids` [query, array] — Filter activities by specific activity IDs. Example: "225494730938493804,225494730938493915".
- `activityUuids` [query, array] — Return activities by specific activity UUIDs. Example: "a2c8037c-e6df-436d-b92b-bc09a418717e,f15b308b-fab9-4c0b-b6f5-17d236a7bf55".
- `userIds` [query, array] — The user who invoked the activity (If applicable). Example: "225494730938493804,225494730938493915".
- `userEmails` [query, array] — Email of the user who invoked the activity (If applicable)
- `ruleIds` [query, array] — Return activities related to specified rules. Example: "225494730938493804,225494730938493915".
- `alertIds` [query, array] — Return activities related to specified alerts. Example: "225494730938493804,225494730938493915".
- `relatedIds` [query, array] — Return activities related to specified entities. Example: "56ee72a79c7e5c62dd36e6b1".

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.
