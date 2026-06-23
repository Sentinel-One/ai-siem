# Hyperautomation

13 endpoints.

## `POST /web/api/v2.1/hyper-automate/api/public/workflow-action-expressions/{base_action_id}/evaluate-expression`
**Evaluate Expression**
`operationId`: `_web_api_hyper-automate_api_public_workflow-action-expressions_{base_action_id}_evaluate-expression_post`

Parameters:
- `base_action_id` [path, string] **required** — 
- `groupIds` [query, object] — 
- `siteIds` [query, object] — 
- `accountIds` [query, object] — 
- `cicdschema` [header, object] — 
- `body` [body, S1ApiBody_ExpressionEvaluationInput_] **required** — 

Responses: 200 Successful Response, 422 Validation Error

## `POST /web/api/v2.1/hyper-automate/api/public/workflow-action-expressions/{base_action_id}/expression-breakdown`
**Expression Breakdown**
`operationId`: `_web_api_hyper-automate_api_public_workflow-action-expressions_{base_action_id}_expression-breakdown_post`

Parameters:
- `base_action_id` [path, string] **required** — 
- `groupIds` [query, object] — 
- `siteIds` [query, object] — 
- `accountIds` [query, object] — 
- `cicdschema` [header, object] — 
- `body` [body, S1ApiBody_ExpressionEvaluationInput_] **required** — 

Responses: 200 Successful Response, 422 Validation Error

## `GET /web/api/v2.1/hyper-automate/api/public/workflow-execution`
**List all workflow executions**
`operationId`: `_web_api_hyper-automate_api_public_workflow-execution_get`

Required permissions: `Hyper Automate.view`

Parameters:
- `trigger_types` [query, string] — 
- `states` [query, string] — 
- `scope_ids` [query, string] — 
- `versions_count` [query, string] — 
- `created_at__gte` [query, object] — 
- `created_at__lt` [query, object] — 
- `limit` [query, integer] — 
- `skip` [query, integer] — 
- `workflow_name__contains` [query, object] — 
- `integrations` [query, object] — 
- `workflow_id` [query, object] — 
- `is_snippet` [query, boolean] — 
- `tags` [query, string] — 
- `sortBy` [query, object] — 
- `sortOrder` [query, object] — 
- `groupIds` [query, object] — 
- `siteIds` [query, object] — 
- `accountIds` [query, object] — 
- `cicdschema` [header, object] — 

Responses: 200 Successful Response, 422 Validation Error

## `POST /web/api/v2.1/hyper-automate/api/public/workflow-execution/manual/{workflow_id}/{version_id}`
**Trigger a workflow that uses a manual trigger**
`operationId`: `_web_api_hyper-automate_api_public_workflow-execution_manual_{workflow_id}_{version_id}_post`

Required permissions: `Hyper Automate.workflowsRun`

Parameters:
- `workflow_id` [path, string] **required** — 
- `version_id` [path, string] **required** — 
- `groupIds` [query, object] — 
- `siteIds` [query, object] — 
- `accountIds` [query, object] — 
- `cicdschema` [header, object] — 
- `body` [body, S1ApiBody_WorkflowExecutionCreate_] **required** — 

Responses: 201 Successful Response, 422 Validation Error

## `GET /web/api/v2.1/hyper-automate/api/public/workflow-execution/{workflow_execution_id}`
**Get a workflow execution by its ID**
`operationId`: `_web_api_hyper-automate_api_public_workflow-execution_{workflow_execution_id}_get`

Required permissions: `Hyper Automate.view`

Parameters:
- `workflow_execution_id` [path, string] **required** — 
- `groupIds` [query, object] — 
- `siteIds` [query, object] — 
- `accountIds` [query, object] — 
- `cicdschema` [header, object] — 

Responses: 200 Successful Response, 422 Validation Error

## `GET /web/api/v2.1/hyper-automate/api/public/workflow-import-export/export`
**Batch export workflows**
`operationId`: `_web_api_hyper-automate_api_public_workflow-import-export_export_get`

Required permissions: `Hyper Automate.workflowsExport`

Parameters:
- `workflow_ids` [query, string] — 
- `integrations` [query, string] — 
- `trigger_types` [query, string] — 
- `core_actions` [query, string] — 
- `states` [query, string] — 
- `scope_ids` [query, string] — 
- `name__contains` [query, object] — 
- `description__contains` [query, object] — 
- `name__eq` [query, object] — 
- `oversight` [query, boolean] — 
- `tags` [query, string] — 
- `groupIds` [query, object] — 
- `siteIds` [query, object] — 
- `accountIds` [query, object] — 
- `cicdschema` [header, object] — 

Responses: 200 Successful Response, 422 Validation Error

## `GET /web/api/v2.1/hyper-automate/api/public/workflow-import-export/export/{workflow_id}/{version_id}`
**Export workflow**
`operationId`: `_web_api_hyper-automate_api_public_workflow-import-export_export_{workflow_id}_{version_id}_get`

Export a specific workflow version.

Required permissions: `Hyper Automate.workflowsExport`

Parameters:
- `workflow_id` [path, string] **required** — 
- `version_id` [path, string] **required** — 
- `groupIds` [query, object] — 
- `siteIds` [query, object] — 
- `accountIds` [query, object] — 
- `cicdschema` [header, object] — 

Responses: 200 Successful Response, 422 Validation Error

## `POST /web/api/v2.1/hyper-automate/api/public/workflow-import-export/import`
**Import workflow**
`operationId`: `_web_api_hyper-automate_api_public_workflow-import-export_import_post`

Import workflows that have been previously exported from Hyperautomation.

Required permissions: `Hyper Automate.workflowsCreateEdit`

Parameters:
- `groupIds` [query, object] — 
- `siteIds` [query, object] — 
- `accountIds` [query, object] — 
- `cicdschema` [header, object] — 
- `body` [body, S1ApiBody_WorkflowImportExport_] **required** — 

Responses: 200 Successful Response, 422 Validation Error

## `POST /web/api/v2.1/hyper-automate/api/public/workflow-import-export/import/batch`
**Batch import workflows**
`operationId`: `_web_api_hyper-automate_api_public_workflow-import-export_import_batch_post`

Import workflows that have been previously exported from Hyperautomation.

Required permissions: `Hyper Automate.workflowsCreateEdit`

Parameters:
- `groupIds` [query, object] — 
- `siteIds` [query, object] — 
- `accountIds` [query, object] — 
- `cicdschema` [header, object] — 
- `body` [body, Body_import_workflow_batch_web_api_v2_1_hyper_automate_api_public_workflow_import_export_import_batch_post] **required** — 

Responses: 201 Successful Response, 422 Validation Error

## `GET /web/api/v2.1/hyper-automate/api/public/workflows`
**List all workflows**
`operationId`: `_web_api_hyper-automate_api_public_workflows_get`

Required permissions: `Hyper Automate.view`

Parameters:
- `integrations` [query, string] — 
- `trigger_types` [query, string] — 
- `core_actions` [query, string] — 
- `states` [query, string] — 
- `scope_ids` [query, string] — 
- `limit` [query, integer] — 
- `skip` [query, integer] — 
- `is_snippet` [query, boolean] — 
- `name__contains` [query, object] — 
- `description__contains` [query, object] — 
- `name__eq` [query, object] — 
- `tags` [query, string] — 
- `sortBy` [query, object] — 
- `sortOrder` [query, object] — 
- `oversight` [query, boolean] — 
- `workflow_ids` [query, object] — 
- `groupIds` [query, object] — 
- `siteIds` [query, object] — 
- `accountIds` [query, object] — 
- `cicdschema` [header, object] — 

Responses: 200 Successful Response, 422 Validation Error

## `GET /web/api/v2.1/hyper-automate/api/public/workflows/versions/list/{workflow_id}`
**List workflow versions**
`operationId`: `_web_api_hyper-automate_api_public_workflows_versions_list_{workflow_id}_get`

Required permissions: `Hyper Automate.view`

Parameters:
- `workflow_id` [path, string] **required** — 
- `groupIds` [query, object] — 
- `siteIds` [query, object] — 
- `accountIds` [query, object] — 
- `cicdschema` [header, object] — 

Responses: 200 Successful Response, 422 Validation Error

## `POST /web/api/v2.1/hyper-automate/api/public/workflows/{workflow_id}/deactivate`
**Deactivate The active workflow**
`operationId`: `_web_api_hyper-automate_api_public_workflows_{workflow_id}_deactivate_post`

Required permissions: `Hyper Automate.workflowsActivateDeactivate`

Parameters:
- `workflow_id` [path, string] **required** — 
- `version_id` [query, string] — 
- `groupIds` [query, object] — 
- `siteIds` [query, object] — 
- `accountIds` [query, object] — 
- `cicdschema` [header, object] — 
- `body` [body, S1ApiBody] — 

Responses: 204 Successful Response, 422 Validation Error

## `POST /web/api/v2.1/hyper-automate/api/public/workflows/{workflow_id}/{version_id}/activation`
**Activate a workflow version**
`operationId`: `_web_api_hyper-automate_api_public_workflows_{workflow_id}_{version_id}_activation_post`

Required permissions: `Hyper Automate.workflowsActivateDeactivate`

Parameters:
- `workflow_id` [path, string] **required** — 
- `version_id` [path, string] **required** — 
- `groupIds` [query, object] — 
- `siteIds` [query, object] — 
- `accountIds` [query, object] — 
- `cicdschema` [header, object] — 
- `body` [body, S1ApiBody_WorkflowPatch_] — 

Responses: 204 Successful Response, 422 Validation Error
