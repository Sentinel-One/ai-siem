# Deep Visibility

9 endpoints.

**All query endpoints in this tag are deprecated and sunset on 2027-02-15.** Use the Long Running Query (LRQ) tag instead: `POST /sdl/v2/api/queries` with `queryType="LOG"` (S1QL) or `queryType="PQ"` (PowerQuery), poll `GET /sdl/v2/api/queries/{id}` echoing the `X-Dataset-Query-Forward-Tag` response header, DELETE when done. Auth is Bearer, not ApiToken. See `tags/Long_Running_Query.md` and the `sentinelone-powerquery` skill for the canonical runner. `GET /dv/fetch-file` (file download) is the only endpoint in this tag that is not deprecated.

## `POST /web/api/v2.1/dv/cancel-query`
**[DEPRECATED] Cancel Running Query**
`operationId`: `_web_api_dv_cancel-query_post`

Stop a Deep Visibility Query by queryId. The body is {"queryID":"string_ID"}. Get the ID of the Deep Visibility query or Power Query from "init-query". See "Create Query and get QueryId".<br> Deep Visibility requires Complete SKU.

Required permissions: `SDL Data.viewEdr`

Parameters:
- `body` [body, deep_visibility.deep_visibility_v2_schemas_DeepVisibilityQueryIdRequestSchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/dv/events`
**[DEPRECATED] Get Events**
`operationId`: `_web_api_dv_events_get`

Get all Deep Visibility events from a queryId. You can use this command to send a sub-query, a new query to run on these events. Get the ID from "init-query". See "Create Query and get QueryId". <br>For complete documentation, see Query Syntax in the Knowledge Base (support.sentinelone.com) or the Console Help.

Required permissions: `SDL Data.viewEdr`

Parameters:
- `skip` [query, integer] — Skip first number of items (0-1000). To iterate over more than 1000 items,  use "cursor". Example: "150".
- `limit` [query, integer] — Limit number of returned items (1-1000). Example: "10".
- `cursor` [query, string] — Cursor position returned by the last request. Should be used instead of skip. cursor currently supports sort by with createdAt, pid, processStartTime
- `subQuery` [query, string] — Create a sub query to run on the data that was already pulled
- `queryId` [query, string] **required** — QueryId obtained when creating a query under Create Query. Example: "q1xx2xx3".
- `sortBy` [query, string] — Events sorted by field. Example: "createdAt".
- `sortOrder` [query, string] (enum: asc, desc) — Event sorting order. Example: "asc".

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/dv/events/pq`
**[DEPRECATED] Create a Power Query and Get QueryId**
`operationId`: `_web_api_dv_events_pq_post`

Start a Deep Visibility Power Query, get back status and potential results (ping afterwards using the queryId if query has not finished)

Required permissions: `SDL Data.viewEdr`

Parameters:
- `body` [body, deep_visibility.deep_visibility_v2_schemas_DeepVisibilityPQRequestSchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/dv/events/pq-ping`
**[DEPRECATED] Ping a Power Query if results haven't been retrieved**
`operationId`: `_web_api_dv_events_pq-ping_get`

Ping a Deep Visibility Power Query using the queryId if results have not returned from an initial Power Query or a previous ping.<br>Use pq-ping soon after initiating a Power Query via the /web/api/v2.1/dv/events/pq endpoint. <br>It is recommended to create a script that initiates the Power Query and then pings the query every few seconds to check the status and retrieve results when they are ready. <br>If the ping is run after a significant delay, it may result in a 503 Service Unavailable response. This indicates that the results are no longer available due to cache eviction.

Required permissions: `SDL Data.viewEdr`

Parameters:
- `queryId` [query, string] — QueryId query param

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/dv/events/{event_type}`
**[DEPRECATED] Get Events By Type**
`operationId`: `_web_api_dv_events_{event_type}_get`

Get Deep Visibility results from the query that matches the given event type. Valid values for Event Type:<br> Process Exit<br> Process Modification<br> Process Creation<br> Duplicate Process Handle<br> Duplicate Thread Handle<br> Open Remote Process Handle<br> Remote Thread Creation<br> Remote Process Termination<br> Command Script<br> IP Connect<br> IP Listen<br> File Modification<br> File Creation<br> File Scan<br> File Deletion<br> File Rename<br> Pre Execution Detection<br> Login<br> Logout<br> GET<br> OPTIONS<br> POST<br> PUT<br> DELETE<br> CONNECT<br> HEAD<br> DNS Resolved<br> DNS Unresolved<br> Task Register<br> Task Update<br> Task Start<br> Task Trigger<br> Task Delete<br> Registry Key Create<br> Registry Key Rename<br> Registry Key Delete<br> Registry Key Export<br> Registry Key Security Changed<br> Registry Key Import<br> Registry Value Modified<br> Registry Value Create<br> Registry Value Delete<br> Behavioral Indicators<br> Module Load

Required permissions: `SDL Data.viewEdr`

Parameters:
- `event_type` [path, string] **required** — Event type for Autocomplete
- `skip` [query, integer] — Skip first number of items (0-1000). To iterate over more than 1000 items,  use "cursor". Example: "150".
- `limit` [query, integer] — Limit number of returned items (1-1000). Example: "10".
- `cursor` [query, string] — Cursor position returned by the last request. Should be used instead of skip. cursor currently supports sort by with createdAt, pid, processStartTime
- `subQuery` [query, string] — Create a sub query to run on the data that was already pulled
- `queryId` [query, string] **required** — QueryId obtained when creating a query under Create Query. Example: "q1xx2xx3".
- `sortBy` [query, string] — Events sorted by field. Example: "createdAt".
- `sortOrder` [query, string] (enum: asc, desc) — Event sorting order. Example: "asc".

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/dv/fetch-file`
**Download source process file**
`operationId`: `_web_api_dv_fetch-file_get`

Download the source process file associated with a Deep Visibility event.

Required permissions: `Deep Visibility.fileFetch`

Parameters:
- `downloadToken` [query, string] **required** — Download token

Responses: 404 File not found, 400 Invalid user input received. See error details for further i, 200 Success, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/dv/init-query`
**[DEPRECATED] Create Query and Get QueryId**
`operationId`: `_web_api_dv_init-query_post`

Start a Deep Visibility Query and get the queryId. You can use the queryId for other commands, such as Get Events and Get Query Status. For complete query syntax, see Query Syntax in the Knowledge Base (community.sentinelone.com) or the Console Help. Only SentinelOne Deep Visibility Query Language (S1QL 1.0) syntax is supported. SentinelOne Deep Visibility extends the ActiveEDR capabilities, with full visibility into endpoint data and threat hunting.  Its kernel-based monitoring searches across endpoints for all indicators of compromise (IOC). <br>Note: From Management version Rio (February 2022) the default of "isVerbose" is "false" instead of "true".<br>Deep Visibility requires Complete SKU.

Required permissions: `SDL Data.viewEdr`

Parameters:
- `body` [body, deep_visibility.deep_visibility_v2_schemas_DeepVisibilityApiRequestSchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/dv/process-state`
**[DEPRECATED] Get Process State**
`operationId`: `_web_api_dv_process-state_get`

Get details of all Deep Visibility processes from a queryId.To get the ID from "init-query". See "Create Query and get QueryId".

Required permissions: `SDL Data.viewEdr`

Parameters:
- `skip` [query, integer] — Skip first number of items (0-1000). To iterate over more than 1000 items,  use "cursor". Example: "150".
- `limit` [query, integer] — Limit number of returned items (1-1000). Example: "10".
- `cursor` [query, string] — Cursor position returned by the last request. Use to iterate over more than 1000 items. Example: "YWdlbnRfaWQ6NTgwMjkzODE=".
- `queryId` [query, string] **required** — QueryId obtained when creating a query under Create Query. Example: "q1xx2xx3".
- `sortBy` [query, string] — Events sorted by field. Example: "SrcProcStartTime".
- `sortOrder` [query, string] (enum: asc, desc) — Event sorting order. Example: "asc".

Responses: 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/dv/query-status`
**[DEPRECATED] Get Query Status**
`operationId`: `_web_api_dv_query-status_get`

Get that status of a Deep Visibility Query. When the status is FINISHED, you can get the results with the queryId in "Get Events".<br>Deep Visibility requires Complete SKU.<br>Rate limit: 1 call per second for each different user token. <br>responseState can return these values: EMPTY_RESULTS, EVENTS_RUNNING, FAILED, FAILED_CLIENT, FINISHED, PLANNING, PROCESS_RUNNING, QUERY_CANCEL, QUERY_EXPIRED, QUERY_NOT_FOUND, QUERY_RUNNING, RUNNING, TIMED_OUT.

Required permissions: `SDL Data.viewEdr`

Parameters:
- `queryId` [query, string] **required** — QueryId obtained when creating a query under Create Query. Example: "q1xx2xx3".

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.
