# alerts

3 endpoints.

## `GET /web/api/v2.1/cloud-detection/alerts`
**Get alerts**
`operationId`: `_web_api_cloud-detection_alerts_get`

Get a list of alerts for a given scope

Required permissions: `Custom Alerts.view`

Parameters:
- `createdAt__gt` [query, string] — Created at greater than. Example: "2018-02-27T04:49:26.257525Z".
- `sourceProcessFileHashSha256__contains` [query, array] — Free-text filter by source sha255. Example: "rule1".
- `origAgentName__contains` [query, array] — Free-text filter by agent name. Example: "ilia".
- `sourceProcessCommandline__contains` [query, array] — Free-text filter by source commandline. Example: "rule1".
- `containerImageName__contains` [query, array] — Free-text filter by the endpoint container image name (supports multiple values)
- `ruleName__contains` [query, array] — Free-text filter by rule name. Example: "rule1".
- `origAgentVersion__contains` [query, array] — Free-text filter by agent OS version. Example: "7.11".
- `k8sNode__contains` [query, array] — Free-text filter by the endpoint Kubernetes node name (supports multiple values)
- `k8sNamespaceLabels__contains` [query, array] — Free-text filter by the endpoint Kubernetes namespace labels (supports multiple values)
- `analystVerdict` [query, array] — Filter threats by a analyst verdict. Example: "TRUE_POSITIVE".
- `tenant` [query, boolean] — Indicates a tenant scope request
- `containerName__contains` [query, array] — Free-text filter by the endpoint container name (supports multiple values)
- `query` [query, string] — Full text search for all fields
- `containerLabels__contains` [query, array] — Free-text filter by the endpoint container labels (supports multiple values)
- `groupIds` [query, array] — List of Group IDs to filter by. Example: "225494730938493804,225494730938493915".
- `sourceProcessName__contains` [query, array] — Free-text filter by source process name. Example: "proc1.exe".
- `createdAt__gte` [query, string] — Created at greater or equal than. Example: "2018-02-27T04:49:26.257525Z".
- `incidentStatus` [query, array] — Filter threats by a incident status. Example: "IN_PROGRESS".
- `sourceProcessStoryline__contains` [query, array] — Free-text filter by source storyline. Example: "rule1".
- `sourceProcessFileHashSha1__contains` [query, array] — Free-text filter by source sha1. Example: "rule1".
- `k8sPodLabels__contains` [query, array] — Free-text filter by the endpoint Kubernetes pod labels (supports multiple values)
- `osType` [query, array] — Included OS types
- `sourceProcessFileHashMd5__contains` [query, array] — Free-text filter by source md5. Example: "rule1".
- `limit` [query, integer] — Limit number of returned items (1-1000). Example: "10".
- `k8sNamespaceName__contains` [query, array] — Free-text filter by the endpoint Kubernetes namespace name (supports multiple values)
- `origAgentOsRevision__contains` [query, array] — Free-text filter by agent OS revision. Example: "win7".
- `sortOrder` [query, string] (enum: asc, desc) — Sort direction. Example: "asc".
- `countOnly` [query, boolean] — If true, only total number of items will be returned, without any of the actual objects.
- `severity` [query, array] — Severity. Example: "Low".
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "225494730938493804,225494730938493915".
- `reportedAt__gte` [query, string] — Reported at greater or equal than. Example: "2018-02-27T04:49:26.257525Z".
- `k8sControllerName__contains` [query, array] — Free-text filter by the endpoint Kubernetes controller name (supports multiple values)
- `origAgentUuid__contains` [query, array] — Free-text filter by agent UUID. Example: "win7".
- `createdAt__lt` [query, string] — Created at lesser than. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__lte` [query, string] — Created at lesser or equal than. Example: "2018-02-27T04:49:26.257525Z".
- `reportedAt__lte` [query, string] — Reported at lesser or equal than. Example: "2018-02-27T04:49:26.257525Z".
- `k8sCluster__contains` [query, array] — Free-text filter by the endpoint Kubernetes cluster name (supports multiple values)
- `k8sControllerLabels__contains` [query, array] — Free-text filter by the endpoint Kubernetes controller labels (supports multiple values)
- `reportedAt__lt` [query, string] — Reported at lesser than. Example: "2018-02-27T04:49:26.257525Z".
- `cursor` [query, string] — Cursor position returned by the last request. Use to iterate over more than 1000 items. Example: "YWdlbnRfaWQ6NTgwMjkzODE=".
- `ids` [query, array] — A list of Alert IDs. Example: "225494730938493804,225494730938493915".
- `skip` [query, integer] — Skip first number of items (0-1000). To iterate over more than 1000 items,  use "cursor". Example: "150".
- `disablePagination` [query, boolean] — If true, all rules for requested scope will be returned
- `machineType` [query, array] — agent machine type
- `reportedAt__gt` [query, string] — Reported at greater than. Example: "2018-02-27T04:49:26.257525Z".
- `scopes` [query, array] — Filter results by scope. Example: "global".
- `k8sPod__contains` [query, array] — Free-text filter by the endpoint Kubernetes pod name (supports multiple values)
- `siteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `sourceProcessFilePath__contains` [query, array] — Free-text filter by source file path. Example: "rule1".
- `skipCount` [query, boolean] — If true, total number of items will not be calculated, which speeds up execution time.
- `sortBy` [query, string] (enum: id, machineType, osName, incidentStatus, analystVerdict, severity, agentDetectionInfoMachineType, agentDetectionInfoName, agentDetectionInfoOsFamily, agentDetectionInfoOsName, agentDetectionInfoOsRevision, agentDetectionInfoSiteId, agentDetectionInfoUuid, agentDetectionInfoVersion, alertInfoAlertId, alertInfoAnalystVerdict, alertInfoCreatedAt, alertInfoDvEventId, alertInfoEventType, alertInfoHitType, alertInfoIncidentStatus, alertInfoReportedAt, alertInfoSource, containerInfoId, containerInfoImage, containerInfoLabels, containerInfoName, kubernetesInfoCluster, kubernetesInfoControllerKind, kubernetesInfoControllerLabels, kubernetesInfoControllerName, kubernetesInfoNamespace, kubernetesInfoNamespaceLabels, kubernetesInfoNode, kubernetesInfoPod, kubernetesInfoPodLabels, ruleInfoDescription, ruleInfoId, ruleInfoName, ruleInfoScopeLevel, ruleInfoSeverity, ruleInfoTreatAsThreat, sourceParentProcessInfoCommandline, sourceParentProcessInfoFileHashMd5, sourceParentProcessInfoFileHashSha1, sourceParentProcessInfoFileHashSha256, sourceParentProcessInfoFilePath, sourceParentProcessInfoFileSignerIdentity, sourceParentProcessInfoName, sourceParentProcessInfoPid, sourceParentProcessInfoPidStarttime, sourceParentProcessInfoStoryline, sourceParentProcessInfoIntegrityLevel, sourceParentProcessInfoSubsystem, sourceParentProcessInfoUser, sourceProcessInfoCommandline, sourceProcessInfoFileHashMd5, sourceProcessInfoFileHashSha1, sourceProcessInfoFileHashSha256, sourceProcessInfoFilePath, sourceProcessInfoFileSignerIdentity, sourceProcessInfoName, sourceProcessInfoPid, sourceProcessInfoPidStarttime, sourceProcessInfoStoryline, sourceProcessInfoIntegrityLevel, sourceProcessInfoSubsystem, sourceProcessInfoUser) — The column to sort the results by. Example: "id".

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/cloud-detection/alerts/analyst-verdict`
**Update Alert Analyst Verdict**
`operationId`: `_web_api_cloud-detection_alerts_analyst-verdict_post`

Change the verdict of an alert

Required permissions: `Custom Alerts.updateAnalystVerdict`

Parameters:
- `body` [body, v2_1.alerts.schemas_AlertsAnalystVerdictSchema] — 

Responses: 200 Threats incident successfully updated, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/cloud-detection/alerts/incident`
**Update Threat Incident**
`operationId`: `_web_api_cloud-detection_alerts_incident_post`

Update the incident details of an alert.

Required permissions: `Custom Alerts.updateIncidentStatus`

Parameters:
- `body` [body, v2_1.alerts.schemas_AlertsIncidentSchema] — 

Responses: 200 Threats incident successfully updated, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.
