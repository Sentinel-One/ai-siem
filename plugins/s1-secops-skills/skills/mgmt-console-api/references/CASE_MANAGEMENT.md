# Case Management

A case groups related alerts into one incident with its own status, severity, analyst verdict,
assignee, case types, notes, tasks, linked IOCs and a collaboration space. Cases are opened by
hand, from an alert (the UAM `S1/incident/create` action), or automatically by creation rules.

Use the `case_*` tools in s1-secops-mcp. They cover every operation below, send the request
shapes verified on a live console, and re-read what they change. Reach for raw `s1_api_post` to
`/web/api/v2.1/cases/graphql` only for something the tools do not cover (watchers, message
search, assets), using the shapes in this file.

## Tools

| Need | Tool | Notes |
|---|---|---|
| Find cases | `case_list` | Filters: status, severity, verdict, assignee or unassigned, case types, creation rule, name words, created range, raw `filters`. Cursor paging. Without a status filter CLOSED cases are left out: pass `includeClosed: true`. |
| Read a case | `case_get` | Detail fields plus notes, tasks, IOCs and latest messages. `includeAlerts: true` reads the member alerts from UAM. |
| Which case holds this alert | `case_for_alert` | `null` when the alert is in no case. |
| Field ids, enum values, case type options, upload limits | `case_metadata` | |
| Creation rules and inheritance | `case_rules` | List, one rule (`ruleId`), `linked`, and with `includeMetadata` the matchable properties and grouping limits. |
| Open a case from alerts | `case_create` | Waits until the case is ready; lists alerts that stayed in another case. |
| Rename, retype, reassign, change status / severity / verdict of one case | `case_update` | Read-then-write; omitted fields keep their value. Cannot close (use `case_triage`). |
| Status, severity, verdict or assignee of many cases; close | `case_triage` | CLOSED needs `closingReason`. `alsoAlerts: true` applies status / verdict / assignee to the member alerts. |
| Notes | `case_add_note` | Plain text in, escaped HTML sent. |
| Tasks | `case_task` | create / update (read-then-write) / delete. |
| IOCs | `case_iocs` | link (optionally creating the Threat Intelligence IOC first) / unlink. |
| Collaboration space | `case_post_message` | Message or reply (`parentId`). |
| Alerts in a case | `case_alerts` | add / remove. |
| Rules | `case_rule_apply` | create / update / enable / disable / rank / delete. |
| Rule inheritance | `case_rules_scope` | link / unlink; needs `confirm: true`. |

Reads are allowed in read-only mode; every write tool needs write enabled (`S1_READ_ONLY=false`).

## Behaviour to know before you act

- **Case state and alert state are independent.** Closing a case, or setting its verdict, does not
  change its alerts: they keep their own status, verdict and assignee. When the user wants both,
  use `case_triage` with `alsoAlerts: true` (case CLOSED maps to alert RESOLVED; case severity is not
  applied to alerts), or the `uam_*` tools per alert.
- **An alert belongs to at most one case.** Adding an alert that is already in another case leaves
  it where it is, and the API still reports `success: true`. `case_create` and `case_alerts` re-read
  the case and list such alerts under `notAdded` with the case that holds them. Use `case_for_alert`
  before assuming an alert is free.
- **Cases are not deleted.** Close them with a reason. Test runs should tag case names and close
  the cases at the end.
- **`updateCase` replaces the whole case.** Every field is sent; an omitted `assignTo` unassigns
  the case. `case_update` reads first so this cannot happen by accident.
- **The default list leaves out CLOSED cases.** A filter on `status` that includes `CLOSED` (or
  `includeClosed: true`) brings them back.
- **List fields and detail fields differ.** `alertIds`, `assets`, `products`, `processingState`,
  `noteCount`, `taskCount`, `iocCount`, `fileCount`, `mitreAttacks`, `watchers` and the SLO fields
  are on `case(id)` only; `creationRule`, `assetCount`, `mitreTactics` and `lastModifiedAt` are on
  the `cases` list node only. Selecting a field on the wrong one fails the whole query with
  `FieldUndefined`.
- **Notes are stored as HTML.** `createNote` needs `contentHtml`; `contentPlainText` is derived from
  it (newlines collapse, and text that looked like a tag is dropped). Read `contentHtml` when the
  exact text matters.
- **Case types:** at most 5 per case. Values are stored trimmed and in sentence case
  (`"  my TYPE "` becomes `My type`); compare case-insensitively. `caseTypeOptions` lists the values
  in use, including custom ones.
- **New cases are processed asynchronously.** `processingState` goes from `CREATING_FROM_ALERTS` to
  `READY` within seconds; `case_create` waits for `READY`.

## Endpoint and request shape

`POST /web/api/v2.1/cases/graphql`, header `Authorization: ApiToken <token>` (`Bearer <token>`
also works, which is what a Hyperautomation GraphQL connection sends). Introspection is disabled
and the input type names are not published, so input objects (scope, filters, expressions) are
written as literals. Scalar variables work, including inside those literals: every id is `ID!`
(case, alert, scope, IOC, task, message ids; a `String!` there fails with `VariableTypeMismatch`),
text is `String!`, and a value inside a filter (`stringEqual: { value: $x }`) is `String!`. Pass
untrusted values as variables, for example
`query q($acct: ID!) { cases(scope: { scopeIds: [$acct], scopeType: ACCOUNT }) { totalCount } }`.
The `case_*` tools build literals with a strict escaper instead.

Scope literal: `scope: { scopeIds: ["<accountId>"], scopeType: ACCOUNT }` (or `SITE`).

Three filter shapes:

| Used by | Shape |
|---|---|
| `cases`, `creationRules` `filters` | Flat list, AND across items: `[{ fieldId: "status", stringIn: { values: ["NEW"] } }]` |
| `updateCaseStatus` / `Severity` / `AnalystVerdict`, `caseAssignment`, `changeRulesStateV2`, `deleteCreationRules` `filter` | `{ or: [{ and: [{ fieldId: "id", stringIn: { values: ["<caseId>"] } }] }] }` |
| `createCase.alertFilterSelection.alertFilters`, `addAlertsToCaseFromFilters`, `removeAlertsFromCases.alertFilters` | The same OR/AND shape, with UAM alert field ids |

Filter operators by field (from `caseColumnMetadata`): `stringEqual` / `stringIn` for ids, status,
severity, verdict, case types, creation rule; `longEqual` / `longIn` for `assigneeUserId`
(`value: null` matches unassigned); `match: { value: ["words"] }` for the FULLTEXT fields (name,
publicId, assignee and rule names; any word matches); `dateTimeRange: { start, end }` in epoch ms
for `createdAt` / `lastModifiedAt`; `isNegated: true` inverts a filter.

### Reads

```graphql
query { cases(filters: [{ fieldId: "status", stringIn: { values: ["NEW", "IN_PROGRESS"] } }],
              scope: { scopeIds: ["<accountId>"], scopeType: ACCOUNT },
              sort: { by: "createdAt", order: DESC }, first: 25) {
  totalCount pageInfo { hasNextPage endCursor }
  edges { node { id publicId name status severity analystVerdict caseTypes createdAt lastModifiedAt
                 assetCount assignee { id fullName } creationRule { id name } mitreTactics { id tacticName }
                 scope { account { id name } site { id name } } } } } }

query { case(id: "<caseId>") { id publicId name status severity analystVerdict processingState caseTypes
  assignee { id fullName email } scope { account { id } site { id } } alertIds assets products
  noteCount taskCount iocCount fileCount watchers { user { id fullName } addedAt }
  mitreAttacks { tactic { id tacticName } techniques { id techniqueName } } } }

query { caseForAlert(alertId: "<alertId>") { id publicId name status } }
query { listNotesForCase(caseId: "<id>", first: 20) { edges { node { id author { fullName } createdAt contentHtml } } pageInfo { hasNextPage } } }
query { listTasksForCase(caseId: "<id>") { id name status dueDate taskIndex assignee { id fullName } } }
query { listIoCsForCase(caseId: "<id>") { ioCId type value linkedAt } }
query { collaborationSpaceMessages(caseId: "<id>", first: 20) { edges { node { id author { fullName } contentHtml createdAt replyCount } } } }
query { searchCollaborationSpaceMessages(caseId: "<id>", query: "<words>") { edges { node { id } } } }
query { caseColumnMetadata { fieldId enumValues filterTypes sortable } caseTypeOptions }
```

### Writes

| Mutation | Arguments | Returns |
|---|---|---|
| `createCase` | `scope, name, severity, assignTo, caseTypes, alertFilterSelection: { alertFilters }` | `{ id publicId processingState }` |
| `updateCase` | `caseId, name, status, severity, analystVerdict, assignTo, caseTypes` (all of them) | Boolean |
| `updateCaseStatus` | `filter, scope, status, closingInfo: { reason, note }` (closingInfo required for CLOSED) | `{ updatedCaseIds }` |
| `updateCaseSeverity` / `updateCaseAnalystVerdict` / `caseAssignment` | `filter, scope, severity` / `analystVerdict` / `userId` | `{ updatedCaseIds }` |
| `addAlertsToCase` | `caseId, alertIds` | `{ success errors { field errorType message } }` |
| `addAlertsToCaseFromFilters` | `caseId, alertFilterSelection` | same |
| `removeAlertsFromCases` | `alertFilters, scope` | same |
| `createNote` / `updateNote` | `caseId` or `noteId`, `contentPlainText, contentHtml` | Boolean |
| `deleteNote` | `noteId` | Boolean |
| `createTask` | `caseId, name, assigneeUserId, dueDate` | `{ task { id status taskIndex } errors { … } }` |
| `updateTask` | `taskId, name, assigneeUserId, dueDate, taskIndex, status` (all of them; status `TO_DO` / `DONE`) | same |
| `deleteTask` | `taskId` | Boolean |
| `linkIoCsToCase` | `caseId, ioCs: [{ ioCId, value, type }]` (idempotent) | `{ linkedIoCIds }` |
| `unlinkIoCsFromCase` | `caseId, ioCIds` | `{ unlinkedIoCIds }` |
| `createSimpleCollaborationSpaceMessage` | `caseId, content, parentId` | `{ message { id createdAt } errors { … } }` |
| `editCollaborationSpaceMessage` | `messageId, contentPlainText, contentHtml` (both) | `{ message { id } errors { … } }` |
| `addCaseWatchers` / `removeCaseWatchers` | `caseId, userIds` | `[CaseWatcher]` (select `user { fullName } addedAt`) |
| `watchCase` / `unwatchCase` | `caseId` (the calling user) | `[CaseWatcher]` |

`ioCId` is the Threat Intelligence IOC `uuid` (create one with `POST /web/api/v2.1/threat-intelligence/iocs`,
which needs a token minted at a single account or site).

## Creation rules

Rules are evaluated in rank order (rank 1 first; only enabled rules have a rank). A matching alert
opens a case named `<alert name> - <rule name>` with the rule's severity, case scope level and
default tasks; with grouping on, later matching alerts that share the grouping property join that
case within the window. On a live console the case existed when the alert first appeared in UAM.

**Inheritance.** A scope either inherits the rules of the level above (`linked: true`) or keeps its
own (`linked: false`). While linked, every rule write is refused ("Creation rules cannot be
modified while the scope is inheriting. Unlink the scope first."). Read the state with
`creationRulesScopeConfig(scope) { linked }`; change it with
`changeRulesScopeConfig(linked: false|true, action: INHERIT, scope) { linked }`. Unlinking copies
the inherited rules into the scope; relinking makes it follow the level above again. An account
token can do this for its own account. Change it only when the user wants the scope to have its
own rules (`case_rules_scope` requires `confirm: true`).

**Expressions** are a tree of `GROUP` nodes (`condition: AND | OR`, `expressions: [...]`) and
`ITEM` nodes (`propertyName`, `operation`, `value`).

- Every node needs an `id` of **exactly six alphanumeric characters**, unique in the expression
  (`"RULCRI"`, `"bcXr5m"`). Four, five, seven or more characters, `-`, `_` and UUIDs all fail with
  only `Expression id … is invalid`. Rules from the console's library can carry seven-character ids
  (`CRE001A`) that fail the same check when sent back, so generate new ids when updating one
  (`case_rule_apply` does).
- `propertyName` is a **string** (`"ALERT_NAME"`), `operation` and `type` are enums.
- `value: { type: STRING, stringValue: "..." }` or `{ type: STRING_LIST, stringValues: [...] }`.
  Enum properties (for example `ALERT_SEVERITY`, `CLASSIFICATION`, `MITRE_TACTICS`) take one of
  their listed values as a string.
- `creationRulePropertyMetadata` lists the properties with their type, values, supported
  operations and constraints; `getGroupingMetadata` lists the grouping properties (`ASSET`,
  `ASSET_NAME`, `ACTOR_USER`, `IP_ADDRESS`, `FILE_HASH`, `CLOUD_CONTAINER`, `TICKET_ID`) and limits
  (window up to 20,160 minutes).
- Validate first: `query { validateRuleExpression(ruleExpression: {...}) { validationErrors { field errorType message ... on CreationRuleExpressionError { expId } } } }`.

`case_rule_apply` takes the short form `{ match: "all" | "any", conditions: [{ property, operation, value }] }`
and generates the ids. Raw mutations:

```graphql
mutation { createCreationRule(scope: {...}, ruleName: "...", ruleDescription: "...",
  ruleExpression: { id: "Rt0001", type: GROUP, condition: AND, expressions: [
    { id: "It0001", type: ITEM, propertyName: "ALERT_SEVERITY", operation: EQUALS, value: { type: STRING, stringValue: "CRITICAL" } } ] },
  severity: HIGH, status: true, caseScopeLevel: SITE,
  groupingConfig: { autoGroupingEnabled: true, autoGroupingProperties: [ASSET], groupingWindowMinutes: 1440 },
  defaultTasks: [{ name: "Isolate affected asset" }]) { ruleId errors { field errorType message } } }
```

`updateRule(ruleId, scope, ruleName, ruleDescription, ruleExpression, severity, groupingConfig, defaultTasks)`
replaces the rule: leaving `groupingConfig` out turns grouping off; leaving `defaultTasks` out keeps
the tasks. `changeRulesStateV2(filter, scope, enabled)`, `changeRuleRankV2(ruleId, rank, scope)`
(rank `-1` = last) and `deleteCreationRules(filter, scope) { deletedRuleIds }` complete the set.
`ruleKind` (`CUSTOM` / `LIBRARY`) is on the `creationRules` list node, not on `creationRule(id)`.

## From UAM

- The alert carries its case: `alert(id) { case { id } }` on `/unifiedalerts/graphql`.
- UAM actions that open or extend a case use the action ids `S1/incident/create` and
  `S1/incident/addToExisting` (see `UNIFIED_ALERTS.md`). They need SITE scope.

## Not covered by the tools

File attachments (`initiateFileUpload`, `listFilesForCase`, `getFileLink`) and message pinning are
not wrapped. `caseFileUploadConfig` (returned by `case_metadata`) lists the accepted MIME types and
the size limit.
