# Threats

22 endpoints.

## `GET /web/api/v2.1/export/threats/{threat_id}/explore/events`
**Export Events**
`operationId`: `_web_api_export_threats_{threat_id}_explore_events_get`

Export threat events in CSV or JSON format.

Required permissions: `Threats.view`

Parameters:
- `threat_id` [path, string] **required** — Threat ID. Example: "225494730938493804".
- `eventTypes` [query, array] — Filter events by type. Example: "events".
- `eventSubTypes` [query, array] — Filter events by sub-type. Example: "PROCESSCREATION".
- `eventId` [query, string] — Filter by a specific process key and its children
- `processName__like` [query, string] — Filter by process name (substring)
- `format` [query, string] **required** (enum: json, csv) — Exported file format. Example: "json".

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/export/threats/{threat_id}/timeline`
**Export Threat Timeline**
`operationId`: `_web_api_export_threats_{threat_id}_timeline_get`

Export a threat's timeline.

Required permissions: `Threats.view`

Parameters:
- `threat_id` [path, string] **required** — Threat ID. Example: "225494730938493804".
- `siteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "225494730938493804,225494730938493915".
- `groupIds` [query, array] — List of Group IDs to filter by. Example: "225494730938493804,225494730938493915".
- `query` [query, string] — Full text search for fields: hash, primary_description, secondary_description
- `activityTypes` [query, array] — Return only these activity codes (comma-separated list). Example: "52,53,71,72".

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/threats`
**Get Threats**
`operationId`: `_web_api_threats_get`

Get data of threats that match the filter. <BR>Best Practice: Use the filters. Each threat gives a number of data lines that will quickly fill the page limit.

Required permissions: `Threats.view`

Parameters:
- `skip` [query, integer] — Skip first number of items (0-1000). To iterate over more than 1000 items,  use "cursor". Example: "150".
- `limit` [query, integer] — Limit number of returned items (1-1000). Example: "10".
- `cursor` [query, string] — Cursor position returned by the last request. Use to iterate over more than 1000 items. Example: "YWdlbnRfaWQ6NTgwMjkzODE=".
- `countOnly` [query, boolean] — If true, only total number of items will be returned, without any of the actual objects.
- `skipCount` [query, boolean] — If true, total number of items will not be calculated, which speeds up execution time.
- `sortBy` [query, string] (enum: id, createdAt, updatedAt, mitigationStatus, fileDisplayName, agentVersion, agentMachineType, siteId, siteName, agentComputerName, filePath, contentHash, collectionId, classification, createdDate, cloudAccount, cloudImage, cloudInstanceId, cloudInstanceSize, cloudLocation, cloudNetwork) — The column to sort the results by. Example: "id".
- `sortOrder` [query, string] (enum: asc, desc) — Sort direction. Example: "asc".
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "225494730938493804,225494730938493915".
- `siteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `groupIds` [query, array] — List of Group IDs to filter by. Example: "225494730938493804,225494730938493915".
- `tenant` [query, boolean] — Indicates a tenant scope request
- `createdAt__lt` [query, string] — Created at lesser than. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__gt` [query, string] — Created at greater than. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__lte` [query, string] — Created at lesser or equal than. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__gte` [query, string] — Created at greater or equal than. Example: "2018-02-27T04:49:26.257525Z".
- `updatedAt__lt` [query, string] — Updated at lesser than. Example: "2018-02-27T04:49:26.257525Z".
- `updatedAt__gt` [query, string] — Updated at greater than. Example: "2018-02-27T04:49:26.257525Z".
- `updatedAt__lte` [query, string] — Updated at lesser or equal than. Example: "2018-02-27T04:49:26.257525Z".
- `updatedAt__gte` [query, string] — Updated at greater or equal than. Example: "2018-02-27T04:49:26.257525Z".
- `contentHashes` [query, array] — List of sha1 hashes to search for. Example: "d,d,d,5,0,3,0,a,3,d,0,2,9,f,3,8,4,5,f,c,1,0,5,2,4,1,9,8,2,9,f,0,8,f,3,1,2,2,4,0".
- `displayName` [query, string] — Display name
- `mitigationStatuses` [query, array] — Filter threats by a specific status. Example: "not_mitigated".
- `mitigationStatusesNin` [query, array] — Filter threats not by a specific status. Example: "not_mitigated".
- `agentIds` [query, array] — List of Agent IDs. Example: "225494730938493804,225494730938493915".
- `storylines` [query, array] — List of Agent context to search for
- `ids` [query, array] — List of threat IDs. Example: "225494730938493804,225494730938493915".
- `collectionIds` [query, array] — List of collection IDs to search. Example: "225494730938493804,225494730938493915".
- `engines` [query, array] — Included engines. Example: "reputation".
- `enginesNin` [query, array] — Excluded engines. Example: "reputation".
- `detectionEngines` [query, array] — Included engines. Example: "reputation".
- `detectionEnginesNin` [query, array] — Excluded engines. Example: "reputation".
- `classifications` [query, array] — List of threat classifications to search
- `classificationsNin` [query, array] — List of threat classifications not to search
- `classificationSources` [query, array] — Classification sources list. Example: "Cloud".
- `classificationSourcesNin` [query, array] — Classification sources list to exclude. Example: "Cloud".
- `agentVersions` [query, array] — Include Agent versions. Example: "2.5.1.1320".
- `agentVersionsNin` [query, array] — Excluded Agent versions. Example: "2.5.1.1320".
- `agentMachineTypes` [query, array] — Include Agent machine types. Example: "unknown".
- `agentMachineTypesNin` [query, array] — Excluded Agent machine types. Example: "unknown".
- `osTypes` [query, array] — Included OS types. Example: "macos".
- `osTypesNin` [query, array] — Excluded OS types. Example: "macos".
- `osArchs` [query, array] — Included OS Architectures. Example: "32 bit".
- `osNames` [query, array] — 
- `osNamesNin` [query, array] — 
- `agentIsActive` [query, boolean] — Include Agents currently connected to the Management Console
- `initiatedBy` [query, array] — Only include threats from specific initiating sources. Example: "agent_policy,dv_command".
- `initiatedByNin` [query, array] — Exclude threats with specific initiating sources. Example: "agent_policy,dv_command".
- `confidenceLevels` [query, array] — Filter threats by a specific confidence level. Example: "malicious".
- `confidenceLevelsNin` [query, array] — Exclude threats with specific confidence level. Example: "malicious".
- `analystVerdicts` [query, array] — Filter threats by a specific analyst verdict. Example: "true_positive,suspicious".
- `analystVerdictsNin` [query, array] — Exclude threats with specific analyst verdicts. Example: "true_positive,suspicious".
- `incidentStatuses` [query, array] — Filter threats by a specific incident status. Example: "unresolved,in_progress".
- `incidentStatusesNin` [query, array] — Exclude threats with specific incident statuses. Example: "unresolved,in_progress".
- `noteExists` [query, boolean] — The threat contains at least one note
- `failedActions` [query, boolean] — At least one action failed on the threat
- `rebootRequired` [query, boolean] — A reboot is required on any endpoint for at least one action on the threat
- `pendingActions` [query, boolean] — At least one action is pending for the Agent for the threat
- `externalTicketExists` [query, boolean] — The threat contains ticket number
- `externalTicketIds` [query, array] — External ticket ID for the threat
- `mitigatedPreemptively` [query, boolean] — If the threat was detected pre-execution or post-execution
- `agentTagsData` [query, string] — Filter threats by assigned tags to the related agent. Given in form of a JSON where each key represents a tag key, and each value represents a list of string values to filter by. To filter by unassigned tag values, use __nin suffix in the tag key. Example: "{"key1": ["value1_1", "value1_2"], "key2__nin": ["value2"]}".
- `hasAgentTags` [query, boolean] — Include only Threats whose Agent is assigned any tags if True, or none if False
- `query` [query, string] — Full text search for fields: threat_details, content_hash, computer_name, file_path, uuid, detection_agent_version, realtime_agent_version, detection_agent_domain, command_line_arguments, initiated_by_username, storyline, originated_process, k8s_cluster_name, k8s_node_name, k8s_node_labels, k8s_namespace_name, k8s_namespace_labels, k8s_controller_name, k8s_controller_labels, k8s_pod_name, k8s_pod_labels, container_name, container_image_name, container_labels, external_ticket_id
- `contentHash__contains` [query, array] — Free-text filter by file content hash (supports multiple values). Example: "5f09bcff3".
- `threatDetails__contains` [query, array] — Free-text filter by threat details(supports multiple values). Example: "malware.exe,virus.exe".
- `filePath__contains` [query, array] — Free-text filter by file path (supports multiple values). Example: "\MyUser\Downloads".
- `computerName__contains` [query, array] — Free-text filter by computer name (supports multiple values). Example: "john-office,WIN".
- `uuid__contains` [query, array] — Free-text filter by Agent UUID (supports multiple values). Example: "e92-01928,b055".
- `detectionAgentVersion__contains` [query, array] — Free-text filter by Agent version at detection time (supports multiple values). Example: "1.1.1.1,2.2.".
- `realtimeAgentVersion__contains` [query, array] — Free-text filter by Agent version at current time (supports multiple values). Example: "1.1.1.1,2.2.".
- `detectionAgentDomain__contains` [query, array] — Free-text filter by Agent domain at detection time (supports multiple values). Example: "sentinel,sentinelone.com".
- `commandLineArguments__contains` [query, array] — Free-text filter by threat command line arguments (supports multiple values). Example: "/usr/sbin/,wget".
- `initiatedByUsername__contains` [query, array] — Free-text filter by the username that initiated that threat (supports multiple values). Example: "John,John Doe".
- `storyline__contains` [query, array] — Free-text filter by threat storyline (supports multiple values). Example: "0000C2E97648,0006FC73-77B4-470F-AAC7-".
- `originatedProcess__contains` [query, array] — Free-text filter by the originated process name of the threat (supports multiple values)
- `publisherName__contains` [query, array] — Free-text filter by threat's publisher name (supports multiple values). Example: "GOOGLE,Apple Inc.".
- `signerIdentity__contains` [query, array] — Free-text filter by threat's signer identity (certificate ID) (supports multiple values). Example: "3BDA323E552DB1FDC0A9DD871E8CADDA2FCBB419".
- `k8sClusterName__contains` [query, array] — Free-text filter by the endpoint Kubernetes cluster name (supports multiple values)
- `k8sNodeName__contains` [query, array] — Free-text filter by the endpoint Kubernetes node name (supports multiple values)
- `k8sNodeLabels__contains` [query, array] — Free-text filter by the endpoint Kubernetes node labels (supports multiple values)
- `k8sNamespaceName__contains` [query, array] — Free-text filter by the endpoint Kubernetes namespace name (supports multiple values)
- `k8sNamespaceLabels__contains` [query, array] — Free-text filter by the endpoint Kubernetes namespace labels (supports multiple values)
- `k8sControllerName__contains` [query, array] — Free-text filter by the endpoint Kubernetes controller name (supports multiple values)
- `k8sControllerLabels__contains` [query, array] — Free-text filter by the endpoint Kubernetes controller labels (supports multiple values)
- `k8sPodName__contains` [query, array] — Free-text filter by the endpoint Kubernetes pod name (supports multiple values)
- `k8sPodLabels__contains` [query, array] — Free-text filter by the endpoint Kubernetes pod labels (supports multiple values)
- `containerName__contains` [query, array] — Free-text filter by the endpoint container name (supports multiple values)
- `containerImageName__contains` [query, array] — Free-text filter by the endpoint container image name (supports multiple values)
- `containerLabels__contains` [query, array] — Free-text filter by the endpoint container labels (supports multiple values)
- `externalTicketId__contains` [query, array] — Free-text filter by the threat external ticket ID (supports multiple values)
- `countsFor` [query, string] — comma-separated list of fields to be shown. Example: "osTypes,machineTypes".
- `resolved` [query, boolean] — This is used for backward-compatibility with API 2.0.
- `cloudProvider` [query, array] — Agents from which cloud provider
- `cloudProviderNin` [query, array] — Exclude Agents from these cloud provider
- `awsSecurityGroups__contains` [query, array] — Free-text filter by aws securityGroups(supports multiple values)
- `cloudAccount__contains` [query, array] — Free-text filter by cloud account (supports multiple values)
- `cloudImage__contains` [query, array] — Free-text filter by cloud image (supports multiple values)
- `cloudInstanceId__contains` [query, array] — Free-text filter by cloud instance id(supports multiple values)
- `cloudInstanceSize__contains` [query, array] — Free-text filter by cloud instance size(supports multiple values)
- `cloudLocation__contains` [query, array] — Free-text filter by cloud location (supports multiple values)
- `cloudNetwork__contains` [query, array] — Free-text filter by cloud network (supports multiple values)
- `awsRole__contains` [query, array] — Free-text filter by aws role(supports multiple values)
- `awsSubnetIds__contains` [query, array] — Free-text filter by aws subnet ids (supports multiple values)
- `azureResourceGroup__contains` [query, array] — Free-text filter by azure resource group(supports multiple values)
- `gcpServiceAccount__contains` [query, array] — Free-text filter by gcp service account (supports multiple values)

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/threats/actions/container-network-connect`
**Reconnect Container**
`operationId`: `_web_api_threats_actions_container-network-connect_post`

Restore network to a container that was disconnected

Required permissions: `Endpoints.reconnectToNetwork`

Parameters:
- `body` [body, threats.schemas_ContainerNetworkQuarantineSchema] — 

Responses: 200 Reconnect command was created, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/threats/actions/container-network-disconnect`
**Disconnect Container**
`operationId`: `_web_api_threats_actions_container-network-disconnect_post`

Network quarantine a specific container

Required permissions: `Endpoints.disconnectFromNetwork`

Parameters:
- `body` [body, threats.schemas_ContainerNetworkQuarantineSchema] — 

Responses: 200 Disconnect command was created, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/threats/add-to-blacklist`
**Add to Blocklist**
`operationId`: `_web_api_threats_add-to-blacklist_post`

Add threats that have a SHA1 hash and that match the filter to the Blocklist of the target scope: Global, Account, Site, or Group.<BR> Your role must have permissions to change the Blocklist - Admin, IR Team, SOC - and your user scope access must include the Agent. The target scope is the Group, Site, or Account of the Agent.

Required permissions: `Blacklist.create`
Optional permissions: `Threats.updateAnalystVerdict`

Parameters:
- `body` [body, threats.schemas_ThreatsAddToRestrictionsWithTargetSchema] — 

Responses: 200 Hash threat added to black list, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/threats/add-to-exclusions`
**Add to Exclusions**
`operationId`: `_web_api_threats_add-to-exclusions_post`

Add a threat to exclusions. The "whitening option" is required. <BR>When you create an exclusion, you override the "malicious" verdict of the Agent for a detection. This can open holes in your security deployment. Use with caution.<BR>Best practice: Use the most specific definition of the exclusion possible and the lowest mode possible.

Required permissions: `Exclusions.create`
Optional permissions: `Threats.updateAnalystVerdict`

Parameters:
- `body` [body, threats.schemas_ThreatsAddToExclusionsWithTargetSchema] — 

Responses: 200 Added to exclusions, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/threats/analyst-verdict`
**Update Threat Analyst Verdict**
`operationId`: `_web_api_threats_analyst-verdict_post`

Change the verdict of a threat, as determined by a Console user.

Required permissions: `Threats.updateAnalystVerdict`

Parameters:
- `body` [body, threats.schemas_ThreatsAnalystVerdictSchema] — 

Responses: 200 Threats analyst verdict successfully updated, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/threats/dv-add-to-blacklist`
**Add to Blocklist (Deep Visibility)**
`operationId`: `_web_api_threats_dv-add-to-blacklist_post`

From Deep Visibility results, add a SHA1 hash to the Blocklist. Set the scope of the Blocklist: Global, Account, Site, or Group. The SHA1 and the Agent ID are required (see Deep Visibility > Get Events). Your role must have permissions to change the Blocklist - Admin, IR Team, SOC - and your user scope access must include the scope of the Agent. The target scope is the Group, Site, or Account of the Agent. <BR> Deep Visibility requires Complete SKU.

Required permissions: `Blacklist.create`

Parameters:
- `body` [body, threats.schemas_DvAddToBlackListSchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/threats/dv-mark-as-threat`
**Mark as Threat (Deep Visibility)**
`operationId`: `_web_api_threats_dv-mark-as-threat_post`

Mark an event from Deep Visibility data as a threat. (see Deep Visibility > Get Events).Your role must have permissions to Mark as Threat - Admin, IR Team, SOC. The item becomes marked as a threat and the Management adds it to the blocklist. If this threat is detected on an endpoint, the Agent blocks it immediately.

Required permissions: `Threats.markThreat`

Parameters:
- `body` [body, threats.schemas_DvMarkAsThreatSchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/threats/engines/disable`
**Disable Engines**
`operationId`: `_web_api_threats_engines_disable_post`

If your list of threats shows too many False Positives, use this command to troubleshoot the Agent Engines that return unexpected results in your deployment. Valid values:  "penetration", "dataFiles","exploits", "reputation", "executables", "preExecutionSuspicious", "preExecution", "lateralMovement", and "pup".

Required permissions: `Policy.edit`

Parameters:
- `body` [body, threats.schemas_EngineListSchema] — 

Responses: 200 Engines disabled, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/threats/export`
**Export Threats**
`operationId`: `_web_api_threats_export_get`

Export data of threats (as seen in the Console > Incidents) that match the filter. Note: Use the filter. This command exports only 20,000 items (each datum is an item).

Required permissions: `Threats.view`

Parameters:
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "225494730938493804,225494730938493915".
- `siteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `groupIds` [query, array] — List of Group IDs to filter by. Example: "225494730938493804,225494730938493915".
- `tenant` [query, boolean] — Indicates a tenant scope request
- `createdAt__lt` [query, string] — Created at lesser than. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__gt` [query, string] — Created at greater than. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__lte` [query, string] — Created at lesser or equal than. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__gte` [query, string] — Created at greater or equal than. Example: "2018-02-27T04:49:26.257525Z".
- `updatedAt__lt` [query, string] — Updated at lesser than. Example: "2018-02-27T04:49:26.257525Z".
- `updatedAt__gt` [query, string] — Updated at greater than. Example: "2018-02-27T04:49:26.257525Z".
- `updatedAt__lte` [query, string] — Updated at lesser or equal than. Example: "2018-02-27T04:49:26.257525Z".
- `updatedAt__gte` [query, string] — Updated at greater or equal than. Example: "2018-02-27T04:49:26.257525Z".
- `contentHashes` [query, array] — List of sha1 hashes to search for. Example: "d,d,d,5,0,3,0,a,3,d,0,2,9,f,3,8,4,5,f,c,1,0,5,2,4,1,9,8,2,9,f,0,8,f,3,1,2,2,4,0".
- `displayName` [query, string] — Display name
- `mitigationStatuses` [query, array] — Filter threats by a specific status. Example: "not_mitigated".
- `mitigationStatusesNin` [query, array] — Filter threats not by a specific status. Example: "not_mitigated".
- `agentIds` [query, array] — List of Agent IDs. Example: "225494730938493804,225494730938493915".
- `storylines` [query, array] — List of Agent context to search for
- `ids` [query, array] — List of threat IDs. Example: "225494730938493804,225494730938493915".
- `collectionIds` [query, array] — List of collection IDs to search. Example: "225494730938493804,225494730938493915".
- `engines` [query, array] — Included engines. Example: "reputation".
- `enginesNin` [query, array] — Excluded engines. Example: "reputation".
- `detectionEngines` [query, array] — Included engines. Example: "reputation".
- `detectionEnginesNin` [query, array] — Excluded engines. Example: "reputation".
- `classifications` [query, array] — List of threat classifications to search
- `classificationsNin` [query, array] — List of threat classifications not to search
- `classificationSources` [query, array] — Classification sources list. Example: "Cloud".
- `classificationSourcesNin` [query, array] — Classification sources list to exclude. Example: "Cloud".
- `agentVersions` [query, array] — Include Agent versions. Example: "2.5.1.1320".
- `agentVersionsNin` [query, array] — Excluded Agent versions. Example: "2.5.1.1320".
- `agentMachineTypes` [query, array] — Include Agent machine types. Example: "unknown".
- `agentMachineTypesNin` [query, array] — Excluded Agent machine types. Example: "unknown".
- `osTypes` [query, array] — Included OS types. Example: "macos".
- `osTypesNin` [query, array] — Excluded OS types. Example: "macos".
- `osArchs` [query, array] — Included OS Architectures. Example: "32 bit".
- `osNames` [query, array] — 
- `osNamesNin` [query, array] — 
- `agentIsActive` [query, boolean] — Include Agents currently connected to the Management Console
- `initiatedBy` [query, array] — Only include threats from specific initiating sources. Example: "agent_policy,dv_command".
- `initiatedByNin` [query, array] — Exclude threats with specific initiating sources. Example: "agent_policy,dv_command".
- `confidenceLevels` [query, array] — Filter threats by a specific confidence level. Example: "malicious".
- `confidenceLevelsNin` [query, array] — Exclude threats with specific confidence level. Example: "malicious".
- `analystVerdicts` [query, array] — Filter threats by a specific analyst verdict. Example: "true_positive,suspicious".
- `analystVerdictsNin` [query, array] — Exclude threats with specific analyst verdicts. Example: "true_positive,suspicious".
- `incidentStatuses` [query, array] — Filter threats by a specific incident status. Example: "unresolved,in_progress".
- `incidentStatusesNin` [query, array] — Exclude threats with specific incident statuses. Example: "unresolved,in_progress".
- `noteExists` [query, boolean] — The threat contains at least one note
- `failedActions` [query, boolean] — At least one action failed on the threat
- `rebootRequired` [query, boolean] — A reboot is required on any endpoint for at least one action on the threat
- `pendingActions` [query, boolean] — At least one action is pending for the Agent for the threat
- `externalTicketExists` [query, boolean] — The threat contains ticket number
- `externalTicketIds` [query, array] — External ticket ID for the threat
- `mitigatedPreemptively` [query, boolean] — If the threat was detected pre-execution or post-execution
- `agentTagsData` [query, string] — Filter threats by assigned tags to the related agent. Given in form of a JSON where each key represents a tag key, and each value represents a list of string values to filter by. To filter by unassigned tag values, use __nin suffix in the tag key. Example: "{"key1": ["value1_1", "value1_2"], "key2__nin": ["value2"]}".
- `hasAgentTags` [query, boolean] — Include only Threats whose Agent is assigned any tags if True, or none if False
- `query` [query, string] — Full text search for fields: threat_details, content_hash, computer_name, file_path, uuid, detection_agent_version, realtime_agent_version, detection_agent_domain, command_line_arguments, initiated_by_username, storyline, originated_process, k8s_cluster_name, k8s_node_name, k8s_node_labels, k8s_namespace_name, k8s_namespace_labels, k8s_controller_name, k8s_controller_labels, k8s_pod_name, k8s_pod_labels, container_name, container_image_name, container_labels, external_ticket_id
- `contentHash__contains` [query, array] — Free-text filter by file content hash (supports multiple values). Example: "5f09bcff3".
- `threatDetails__contains` [query, array] — Free-text filter by threat details(supports multiple values). Example: "malware.exe,virus.exe".
- `filePath__contains` [query, array] — Free-text filter by file path (supports multiple values). Example: "\MyUser\Downloads".
- `computerName__contains` [query, array] — Free-text filter by computer name (supports multiple values). Example: "john-office,WIN".
- `uuid__contains` [query, array] — Free-text filter by Agent UUID (supports multiple values). Example: "e92-01928,b055".
- `detectionAgentVersion__contains` [query, array] — Free-text filter by Agent version at detection time (supports multiple values). Example: "1.1.1.1,2.2.".
- `realtimeAgentVersion__contains` [query, array] — Free-text filter by Agent version at current time (supports multiple values). Example: "1.1.1.1,2.2.".
- `detectionAgentDomain__contains` [query, array] — Free-text filter by Agent domain at detection time (supports multiple values). Example: "sentinel,sentinelone.com".
- `commandLineArguments__contains` [query, array] — Free-text filter by threat command line arguments (supports multiple values). Example: "/usr/sbin/,wget".
- `initiatedByUsername__contains` [query, array] — Free-text filter by the username that initiated that threat (supports multiple values). Example: "John,John Doe".
- `storyline__contains` [query, array] — Free-text filter by threat storyline (supports multiple values). Example: "0000C2E97648,0006FC73-77B4-470F-AAC7-".
- `originatedProcess__contains` [query, array] — Free-text filter by the originated process name of the threat (supports multiple values)
- `publisherName__contains` [query, array] — Free-text filter by threat's publisher name (supports multiple values). Example: "GOOGLE,Apple Inc.".
- `signerIdentity__contains` [query, array] — Free-text filter by threat's signer identity (certificate ID) (supports multiple values). Example: "3BDA323E552DB1FDC0A9DD871E8CADDA2FCBB419".
- `k8sClusterName__contains` [query, array] — Free-text filter by the endpoint Kubernetes cluster name (supports multiple values)
- `k8sNodeName__contains` [query, array] — Free-text filter by the endpoint Kubernetes node name (supports multiple values)
- `k8sNodeLabels__contains` [query, array] — Free-text filter by the endpoint Kubernetes node labels (supports multiple values)
- `k8sNamespaceName__contains` [query, array] — Free-text filter by the endpoint Kubernetes namespace name (supports multiple values)
- `k8sNamespaceLabels__contains` [query, array] — Free-text filter by the endpoint Kubernetes namespace labels (supports multiple values)
- `k8sControllerName__contains` [query, array] — Free-text filter by the endpoint Kubernetes controller name (supports multiple values)
- `k8sControllerLabels__contains` [query, array] — Free-text filter by the endpoint Kubernetes controller labels (supports multiple values)
- `k8sPodName__contains` [query, array] — Free-text filter by the endpoint Kubernetes pod name (supports multiple values)
- `k8sPodLabels__contains` [query, array] — Free-text filter by the endpoint Kubernetes pod labels (supports multiple values)
- `containerName__contains` [query, array] — Free-text filter by the endpoint container name (supports multiple values)
- `containerImageName__contains` [query, array] — Free-text filter by the endpoint container image name (supports multiple values)
- `containerLabels__contains` [query, array] — Free-text filter by the endpoint container labels (supports multiple values)
- `externalTicketId__contains` [query, array] — Free-text filter by the threat external ticket ID (supports multiple values)
- `countsFor` [query, string] — comma-separated list of fields to be shown. Example: "osTypes,machineTypes".
- `resolved` [query, boolean] — This is used for backward-compatibility with API 2.0.
- `cloudProvider` [query, array] — Agents from which cloud provider
- `cloudProviderNin` [query, array] — Exclude Agents from these cloud provider
- `awsSecurityGroups__contains` [query, array] — Free-text filter by aws securityGroups(supports multiple values)
- `cloudAccount__contains` [query, array] — Free-text filter by cloud account (supports multiple values)
- `cloudImage__contains` [query, array] — Free-text filter by cloud image (supports multiple values)
- `cloudInstanceId__contains` [query, array] — Free-text filter by cloud instance id(supports multiple values)
- `cloudInstanceSize__contains` [query, array] — Free-text filter by cloud instance size(supports multiple values)
- `cloudLocation__contains` [query, array] — Free-text filter by cloud location (supports multiple values)
- `cloudNetwork__contains` [query, array] — Free-text filter by cloud network (supports multiple values)
- `awsRole__contains` [query, array] — Free-text filter by aws role(supports multiple values)
- `awsSubnetIds__contains` [query, array] — Free-text filter by aws subnet ids (supports multiple values)
- `azureResourceGroup__contains` [query, array] — Free-text filter by azure resource group(supports multiple values)
- `gcpServiceAccount__contains` [query, array] — Free-text filter by gcp service account (supports multiple values)

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/threats/external-ticket-id`
**Update Threat External Ticket ID**
`operationId`: `_web_api_threats_external-ticket-id_post`

Change the external ticket ID of a threat.

Required permissions: `Threats.updateExternalTicketId`

Parameters:
- `body` [body, threats.schemas_ThreatExternalTicketSchema] — 

Responses: 200 Threats external ticket id successfully updated, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/threats/fetch-file`
**Fetch Threat File**
`operationId`: `_web_api_threats_fetch-file_post`

Fetch a file associated with the threat that matches the filter. Your user role must have permissions to Fetch Threat File - Admin, IR Team, SOC.

Required permissions: `Threats.fetchThreatFile`

Parameters:
- `body` [body, threats.schemas_ThreatsFetchFileRequestSchema] — 

Responses: 200 Number of affected agents, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/threats/incident`
**Updated Threat Incident**
`operationId`: `_web_api_threats_incident_post`

Update the incident details of a threat.

Required permissions: `Threats.updateIncidentStatus`
Optional permissions: `Threats.updateAnalystVerdict`

Parameters:
- `body` [body, threats.schemas_ThreatsIncidentSchema] — 

Responses: 200 Threats incident successfully updated, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/threats/mitigate-alerts`
**Mitigate Alerts**
`operationId`: `_web_api_threats_mitigate-alerts_post`

Mark an alerts as a threat and run mitigation action from the Management UI.

Required permissions: `Threats.markThreat`

Parameters:
- `body` [body, threats.schemas_MitigateAlertsSchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/threats/mitigate/{action}`
**Mitigate Threats**
`operationId`: `_web_api_threats_mitigate_{action}_post`

Apply a mitigation action to a group of threats that match the filter. Valid values for mitigation: "kill", "quarantine", "remediate", "rollback-remediation", "un-quarantine","network-quarantine".<BR>Your user role must have permissions to mitigate threats - Admin, IR Team, SOC. Only threats which you have permission to mitigate are countedas "affected" in response field. <BR>Rollback is applied only on Windows. Remediate is applied only on macOS and Windows.
Optional permissions: `Threats.kill, Threats.quarantine, Threats.unquarantine, Threats.remediate, Threats.rollback, Threats.removeMacro, Threats.restoreMacro`

Parameters:
- `action` [path, string] **required** (enum: kill, remediate, rollback-remediation, quarantine, un-quarantine, None, remove_macros, restore_macros) — Mitigation action. Example: "kill".
- `body` [body, threats.schemas_ThreatsMitigateRequestSchema] — 

Responses: 200 Threat successfully mitigated, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/threats/mitigation-report/{report_id}`
**Export Mitigation Report**
`operationId`: `_web_api_threats_mitigation-report_{report_id}_get`

Export the mitigation report as a CSV file.

Required permissions: `Activity Page.view`

Parameters:
- `report_id` [path, string] **required** — Mitigation report ID. Example: "225494730938493804".

Responses: 200 Success, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/threats/{threat_id}/download-from-cloud`
**Download from cloud**
`operationId`: `_web_api_threats_{threat_id}_download-from-cloud_get`

Download threat file from cloud.

Required permissions: `Threats.view`

Parameters:
- `threat_id` [path, string] **required** — Threat ID. Example: "225494730938493804".

Responses: 200 Success, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/threats/{threat_id}/explore/events`
**Get Events**
`operationId`: `_web_api_threats_{threat_id}_explore_events_get`

Get all threat events.

Required permissions: `Threats.view`

Parameters:
- `threat_id` [path, string] **required** — Threat ID. Example: "225494730938493804".
- `skip` [query, integer] — Skip first number of items (0-1000). To iterate over more than 1000 items,  use "cursor". Example: "150".
- `limit` [query, integer] — Limit number of returned items (1-1000). Example: "10".
- `cursor` [query, string] — Cursor position returned by the last request. Use to iterate over more than 1000 items. Example: "YWdlbnRfaWQ6NTgwMjkzODE=".
- `countOnly` [query, boolean] — If true, only total number of items will be returned, without any of the actual objects.
- `skipCount` [query, boolean] — If true, total number of items will not be calculated, which speeds up execution time.
- `sortBy` [query, string] (enum: id, createdAt, eventType, fileSize, fileType, registryPath, registryId, registryClassification, pid, processName) — The column to sort the results by. Example: "id".
- `sortOrder` [query, string] (enum: asc, desc) — Sort direction. Example: "asc".
- `eventTypes` [query, array] — Filter events by type. Example: "events".
- `eventSubTypes` [query, array] — Filter events by sub-type. Example: "PROCESSCREATION".
- `eventId` [query, string] — Filter by a specific process key and its children
- `processName__like` [query, string] — Filter by process name (substring)

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/threats/{threat_id}/timeline`
**Get Threat Timeline**
`operationId`: `_web_api_threats_{threat_id}_timeline_get`

Get a threat's timeline.

Required permissions: `Threats.view`

Parameters:
- `threat_id` [path, string] **required** — Threat ID. Example: "225494730938493804".
- `skip` [query, integer] — Skip first number of items (0-1000). To iterate over more than 1000 items,  use "cursor". Example: "150".
- `limit` [query, integer] — Limit number of returned items (1-1000). Example: "10".
- `cursor` [query, string] — Cursor position returned by the last request. Use to iterate over more than 1000 items. Example: "YWdlbnRfaWQ6NTgwMjkzODE=".
- `countOnly` [query, boolean] — If true, only total number of items will be returned, without any of the actual objects.
- `skipCount` [query, boolean] — If true, total number of items will not be calculated, which speeds up execution time.
- `sortBy` [query, string] (enum: hash, activityType, primaryDescription, secondaryDescription, createdAt) — The column to sort the results by. Example: "id".
- `sortOrder` [query, string] (enum: asc, desc) — Sort direction. Example: "asc".
- `siteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "225494730938493804,225494730938493915".
- `groupIds` [query, array] — List of Group IDs to filter by. Example: "225494730938493804,225494730938493915".
- `query` [query, string] — Full text search for fields: hash, primary_description, secondary_description
- `activityTypes` [query, array] — Return only these activity codes (comma-separated list). Example: "52,53,71,72".

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/threats/{threat_id}/whitening-options`
**Exclusion Options**
`operationId`: `_web_api_threats_{threat_id}_whitening-options_get`

Get the Exclusion types that can be created from the detection data. <BR> For example, if a threat is a file with a detected SHA1 hash and pathname, the values of the whiteningOptions in the response are "path" and "file_hash". This command requires the ID of the threat, which you can get from "threats" (see Get Threats). To create an Exclusion, see Exclusions.

Required permissions: `Threats.view`

Parameters:
- `threat_id` [path, string] **required** — Threat ID. Example: "225494730938493804".

Responses: 200 Success, 401 Unauthorized access - please sign in and retry.
