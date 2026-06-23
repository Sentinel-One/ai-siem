# Default Reports

9 endpoints.

## `GET /web/api/v2.1/report-tasks`
**Get Default Report Tasks**
`operationId`: `_web_api_report-tasks_get`

Get the tasks that were done to generate default reports and to schedule future default reports. Default Reports require Reports permission and appropriate license. Best Practice: Use a filter. Each task includes many lines of data and can quickly fill the page limit. Use this command to get the ID of a report task to use in other commands.

Required permissions: `Reports Page.view`

Parameters:
- `skip` [query, integer] — Skip first number of items (0-1000). To iterate over more than 1000 items,  use "cursor". Example: "150".
- `limit` [query, integer] — Limit number of returned items (1-1000). Example: "10".
- `cursor` [query, string] — Cursor position returned by the last request. Use to iterate over more than 1000 items. Example: "YWdlbnRfaWQ6NTgwMjkzODE=".
- `countOnly` [query, boolean] — If true, only total number of items will be returned, without any of the actual objects.
- `skipCount` [query, boolean] — If true, total number of items will not be calculated, which speeds up execution time.
- `sortBy` [query, string] (enum: id, name, sites, frequency, day, scope, createdAt, scheduleType, status) — The column to sort the results by. Example: "id".
- `sortOrder` [query, string] (enum: asc, desc) — Sort direction. Example: "asc".
- `siteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "225494730938493804,225494730938493915".
- `id` [query, string] — Id. Example: "225494730938493804".
- `createdAt__lte` [query, string] — Created at lte. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__gte` [query, string] — Created at gte. Example: "2018-02-27T04:49:26.257525Z".
- `name` [query, string] — Name
- `scope` [query, string] (enum: group, site, account, tenant) — Scope. Example: "group".
- `frequency` [query, string] (enum: manually, weekly, monthly) — Frequency. Example: "manually".
- `day` [query, string] — Day
- `creatorId` [query, string] — Creator id. Example: "225494730938493804".
- `creatorName` [query, string] — Creator name
- `query` [query, string] — Query
- `scheduleType` [query, string] (enum: manually, scheduled) — Report type. Example: "manually".
- `ids` [query, array] — Id in. Example: "225494730938493804,225494730938493915".

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/report-tasks`
**Create Default Report Task**
`operationId`: `_web_api_report-tasks_post`

Create a task to generate a default report immediately, one time in the future, or on a schedule. Default Reports require Reports permission and appropriate license. Best Practice: Get Default Report Tasks first, to have a basis for a new task.

Required permissions: `Reports Page.create`

Parameters:
- `body` [body, reports_ReportTasksPostSchema] — 

Responses: 404 Validation errors, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `PUT /web/api/v2.1/report-tasks/{task_id}`
**Update Default Report Task**
`operationId`: `_web_api_report-tasks_{task_id}_put`

Update the default report task of the given ID. Default Reports require Reports permission and appropriate license. To get the task ID, and the data to change, run Get Default Report Tasks.

Required permissions: `Reports Page.edit`

Parameters:
- `task_id` [path, string] **required** — Task ID. Example: "225494730938493804".
- `body` [body, reports_ReportTasksPutSchema] — 

Responses: 404 Validation errors, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/reports`
**Get Default Reports**
`operationId`: `_web_api_reports_get`

Get the default reports that match the filter and the data of the reports. Default Reports require Reports permission and appropriate license. Use this command to get the ID of reports to use in other commands. Other data in the response: schedule, Insight Type, name and ID of the user who created the report, the date range, and more.

Required permissions: `Reports Page.view`

Parameters:
- `skip` [query, integer] — Skip first number of items (0-1000). To iterate over more than 1000 items,  use "cursor". Example: "150".
- `limit` [query, integer] — Limit number of returned items (1-1000). Example: "10".
- `cursor` [query, string] — Cursor position returned by the last request. Use to iterate over more than 1000 items. Example: "YWdlbnRfaWQ6NTgwMjkzODE=".
- `countOnly` [query, boolean] — If true, only total number of items will be returned, without any of the actual objects.
- `skipCount` [query, boolean] — If true, total number of items will not be calculated, which speeds up execution time.
- `sortBy` [query, string] (enum: id, name, sites, frequency, interval, scope, createdAt, scheduleType, status) — The column to sort the results by. Example: "id".
- `sortOrder` [query, string] (enum: asc, desc) — Sort direction. Example: "asc".
- `siteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "225494730938493804,225494730938493915".
- `id` [query, string] — Id. Example: "225494730938493804".
- `createdAt__lte` [query, string] — Created at lte. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__gte` [query, string] — Created at gte. Example: "2018-02-27T04:49:26.257525Z".
- `name` [query, string] — Name
- `scope` [query, string] (enum: group, site, account, tenant) — Scope. Example: "group".
- `frequency` [query, string] (enum: manually, weekly, monthly) — Frequency. Example: "manually".
- `interval` [query, string] — Interval
- `fromDate` [query, string] — From date. Example: "2018-02-27T04:49:26.257525Z".
- `toDate` [query, string] — To date. Example: "2018-02-27T04:49:26.257525Z".
- `query` [query, string] — Query
- `scheduleType` [query, string] (enum: manually, scheduled) — Report type. Example: "manually".
- `taskId` [query, string] — Task id. Example: "225494730938493804".
- `ids` [query, array] — Id in. Example: "225494730938493804,225494730938493915".

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/reports/delete-reports`
**Delete Default Reports**
`operationId`: `_web_api_reports_delete-reports_post`

Delete the default reports that match the filter. Default Reports require Reports permission and appropriate license. To delete a specific report, use its ID (see Get Default Reports).

Required permissions: `Reports Page.delete`

Parameters:
- `body` [body, reports_ReportDeleteSchema] — 

Responses: 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/reports/delete-tasks`
**Delete Default Report Tasks**
`operationId`: `_web_api_reports_delete-tasks_post`

You can schedule a default report to be generated on a routine. Default Reports require Reports permission and appropriate license. Use this command to remove a task to generate a report in the future. To get an ID to delete a specific task, see Get Default Report Tasks.

Required permissions: `Reports Page.delete`

Parameters:
- `body` [body, reports_ReportTaskDeleteSchema] — 

Responses: 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/reports/insights/types`
**Get Default Insight Reports**
`operationId`: `_web_api_reports_insights_types_get`

Get the Insight Report types for Default Reports. Default Reports require Reports permission and appropriate license. These reports show high-level and detailed information on the state of your endpoint security. Reports include statistics, trends, and summaries with easy to read and actionable information about your network. Use this command to see the predefined reports. This command does not give data for specific reports.

Required permissions: `Reports Page.view`

Parameters:
- `siteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "225494730938493804,225494730938493915".
- `groupIds` [query, array] — List of Group IDs to filter by. Example: "225494730938493804,225494730938493915".
- `forceUpdate` [query, boolean] — Force update

Responses: 404 Package not found, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/reports/{report_id}/{report_format}`
**Download Default Report**
`operationId`: `_web_api_reports_{report_id}_{report_format}_get`

When the Management generates a default report, it is uploaded to the Management Console. Default Reports require Reports permission and appropriate license. Use this command to get the report as a PDF or HTML file. To get the ID of the report, see Get Default Reports.

Required permissions: `Reports Page.view`

Parameters:
- `report_id` [path, string] **required** — Report ID. Example: "225494730938493804".
- `report_format` [path, string] **required** (enum: pdf, html) — Report format. Example: "pdf".

Responses: 404 Report not found, 200 Success, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/sentinelonerss`
**S1 RSS Feed**
`operationId`: `_web_api_sentinelonerss_get`

Get the SentinelOne RSS feed. In the SentinelOne Management Console, we show the feed contents in the Dashboard.

Responses: 404 Site not found, 200 Success, 401 Unauthorized access - please sign in and retry.
