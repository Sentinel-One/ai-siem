# Agents

14 endpoints.

## `GET /web/api/v2.1/agents`
**Get Agents**
`operationId`: `_web_api_agents_get`

Get the Agents, and their data, that match the filter. This command gives the Agent ID, which you can use in other commands. <BR>To save the list and data to a CSV file, use "export/agents".

Required permissions: `Endpoints.view`

Parameters:
- `skip` [query, integer] — Skip first number of items (0-1000). To iterate over more than 1000 items,  use "cursor". Example: "150".
- `limit` [query, integer] — Limit number of returned items (1-1000). Example: "10".
- `cursor` [query, string] — Cursor position returned by the last request. Use to iterate over more than 1000 items. Example: "YWdlbnRfaWQ6NTgwMjkzODE=".
- `countOnly` [query, boolean] — If true, only total number of items will be returned, without any of the actual objects.
- `skipCount` [query, boolean] — If true, total number of items will not be calculated, which speeds up execution time.
- `sortBy` [query, string] (enum: createdAt, updatedAt, id, computerName, groupId, osType, osName, uuid, scanStatus, isDecommissioned, decommissionedAt, isUninstalled, threatMitigationStatus, threatResolved, threatContentHash, threatCreatedAt, registeredAt, lastActiveDate, isActive, isPendingUninstall, activeThreats, isUpToDate, agentVersion, osArch, machineType, networkStatus, domain, mitigationMode, mitigationModeSuspicious, encryptedApplications, totalMemory, cpuCount, coreCount, externalIp, lastLoggedInUserName, groupName, networkInterfacePhysical, siteId, siteName, infected, threatRebootRequired, consoleMigrationStatus, appsVulnerabilityStatus, accountName, externalId, installerType, rangerVersion, operationalState, remoteProfilingState, networkQuarantineEnabled, firewallEnabled, locationEnabled, cloudAccount, cloudImage, cloudInstanceId, cloudInstanceSize, cloudLocation, cloudNetwork, cloudProvider, clusterName, kubernetesVersion, kubernetesType, agentNamespace, agentPodName, serialNumber, cpuId, fullDiskScanLastUpdatedAt, lastSuccessfulScanDate, ecsType, ecsVersion, ecsClusterName, ecsTaskArn, ecsTaskAvailabilityZone, ecsServiceName, ecsServiceArn, ecsTaskDefinitionFamily, ecsTaskDefinitionRevision, ecsTaskDefinitionArn, isAdConnector, activeProtection, pacFileUsage, proxyMethod, console, consoleProxyAddress, deepVisibility, deepVisibilityProxyAddress) — The column to sort the results by. Example: "id".
- `sortOrder` [query, string] (enum: asc, desc) — Sort direction. Example: "asc".
- `siteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "225494730938493804,225494730938493915".
- `groupIds` [query, array] — List of Group IDs to filter by. Example: "225494730938493804,225494730938493915".
- `filteredGroupIds` [query, array] — List of Group IDs to filter by. Example: "225494730938493804,225494730938493915".
- `filteredSiteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `registeredAt__between` [query, string] — Date range for first registration time (format: <from_timestamp>-<to_timestamp>, inclusive). Example: "1514978764288-1514978999999".
- `lastActiveDate__between` [query, string] — Date range for last active date(format: <from_timestamp>-<to_timestamp>, inclusive). Example: "1514978764288-1514978999999".
- `lastSuccessfulScanDate__between` [query, string] — Date range for last successful full disk scan(format: <from_timestamp>-<to_timestamp>, inclusive). Example: "1514978764288-1514978999999".
- `isActive` [query, array] — Include only active Agents
- `isPendingUninstall` [query, array] — Include only Agents with pending uninstall requests
- `infected` [query, boolean] — Include only Agents with at least one active threat
- `isUpToDate` [query, array] — Include only Agents with updated software
- `query` [query, string] — A free-text search term, will match applicable attributes (sub-string match). Note: Device's physical addresses will be matched if they start with the search term only (no match if they contain the term). Example: "Linux".
- `agentVersions` [query, array] — Agent versions to include. Example: "2.0.0.0,2.1.5.144".
- `agentVersionsNin` [query, array] — Agent versions not to include. Example: "2.0.0.0,2.1.5.144".
- `rangerVersions` [query, array] — Network Scanner versions to include. Example: "2.0.0.0,2.1.5.144".
- `rangerVersionsNin` [query, array] — Network Scanner versions not to include. Example: "2.0.0.0,2.1.5.144".
- `osArch` [query, string] (enum: 32 bit, 64 bit, ARM64) — OS architecture. Example: "32 bit".
- `osArches` [query, array] — OS architectures to include. Example: "32 bit,64 bit".
- `osArchesNin` [query, array] — OS architectures not to include. Example: "32 bit,64 bit".
- `osTypes` [query, array] — Included OS types. Example: "macos".
- `osTypesNin` [query, array] — Not included OS types. Example: "macos".
- `scanStatuses` [query, array] — Included scan statuses. Example: "started,aborted".
- `scanStatusesNin` [query, array] — Not included scan statuses. Example: "started,aborted".
- `machineTypes` [query, array] — Included machine types. Example: "laptop,desktop".
- `machineTypesNin` [query, array] — Not included machine types. Example: "laptop,desktop".
- `storageTypes` [query, array] — Included storage types. Example: "NetApp,Dell,S3".
- `storageTypesNin` [query, array] — Excluded storage types. Example: "NetApp,Dell,S3".
- `networkStatuses` [query, array] — Included network statuses. Example: "connected,connecting".
- `networkStatusesNin` [query, array] — Included network statuses. Example: "connected,connecting".
- `domains` [query, array] — Included network domains. Example: "mybusiness.net,workgroup".
- `domainsNin` [query, array] — Not included network domains. Example: "mybusiness.net,workgroup".
- `encryptedApplications` [query, array] — Disk encryption status
- `totalMemory__between` [query, string] — Total memory range (GB, inclusive). Example: "4-8".
- `coreCount__between` [query, string] — Possible number of CPU cores (inclusive). Example: "2-8".
- `cpuCount__between` [query, string] — Possible number of CPU cores (inclusive). Example: "2-8".
- `userActionsNeeded` [query, array] — Included pending user actions. Example: "reboot_needed,upgrade_needed".
- `missingPermissions` [query, array] — Included missing permissions. Example: "user_action_needed_bluetooth_per,user_action_needed_fda_helper".
- `userActionsNeededNin` [query, array] — Excluded pending user actions. Example: "reboot_needed,upgrade_needed".
- `missingPermissionsNin` [query, array] — Excluded missing permissions. Example: "user_action_needed_bluetooth_per,user_action_needed_fda_helper".
- `adQuery` [query, string] — An Active Directory query string. Example: "CN=Managers,DC=sentinelone,DC=com".
- `hasLocalConfiguration` [query, boolean] — Agent has a local configuration set
- `consoleMigrationStatuses` [query, array] — Migration status in. Example: "N/A".
- `consoleMigrationStatusesNin` [query, array] — Migration status nin. Example: "N/A".
- `appsVulnerabilityStatuses` [query, array] — Apps vulnerability status in. Example: "patch_required".
- `appsVulnerabilityStatusesNin` [query, array] — Apps vulnerability status nin. Example: "patch_required".
- `locationIds` [query, array] — Include only Agents reporting these locations. Example: "225494730938493804,225494730938493915".
- `locationIdsNin` [query, array] — Do not include only Agents reporting these locations. Example: "225494730938493804,225494730938493915".
- `installerTypes` [query, array] — Include only Agents installed with these package types. Example: ".msi".
- `installerTypesNin` [query, array] — Exclude Agents installed with these package types. Example: ".msi".
- `operationalStates` [query, array] — Agent operational state
- `operationalStatesNin` [query, array] — Do not include these Agent operational states
- `remoteProfilingStates` [query, array] — Agent remote profiling state
- `remoteProfilingStatesNin` [query, array] — Do not include these Agent remote profiling states
- `rangerStatuses` [query, array] — Status of Network Discovery. Example: "NotApplicable".
- `rangerStatusesNin` [query, array] — Do not include these Network Scanner Statuses. Example: "NotApplicable".
- `rangerStatus` [query, string] (enum: NotApplicable, Enabled, Disabled) — [DEPRECATED] Use rangerStatuses. Example: "NotApplicable".
- `threatRebootRequired` [query, array] — Has at least one threat with at least one mitigation action pending reboot to succeed
- `networkQuarantineEnabled` [query, array] — The agents supports Network Quarantine Control and its enabled for the agent's group
- `firewallEnabled` [query, array] — The agents supports Firewall Control and it is enabled for the agent's group
- `locationEnabled` [query, array] — The agents supports Location Awareness and it is enabled for the agent's group
- `cloudProvider` [query, array] — Agents from which cloud provider
- `cloudProviderNin` [query, array] — Exclude Agents from these cloud provider
- `tagsData` [query, string] — Filter agents by their assigned tags. Given in form of a JSON where each key represents a tag key, and each value represents a list of string values to filter by. To filter by unassigned tag values, use __nin suffix in the tag key. Example: "{"key1": ["value1_1", "value1_2"], "key2__nin": ["value2"]}".
- `hasTags` [query, boolean] — Include only Agents that have any tags assigned if True, or none if False
- `isAdConnector` [query, array] — The agents that are ADConnectors if True, or not if False
- `isHyperAutomate` [query, array] — The agents has Hyper Automate PNA enabled if True, or not if False
- `activeProtection` [query, array] — Included agent active protections. Example: "edr,idr".
- `containerizedWorkloadCounts` [query, object] — Containerized workload counts
- `hasContainerizedWorkload` [query, array] — Indicates whether the agent protects containerized workload at the moment
- `pacFileUsage` [query, array] — Include only Agents using PAC file for proxy configuration. Accepts true, false, or none (for not reported).
- `proxyMethod` [query, array] — Include only Agents using these proxy methods. Example: "None,Auto,System,User,Custom".
- `proxyMethodNin` [query, array] — Exclude Agents using these proxy methods. Example: "None,Auto,System,User,Custom".
- `console` [query, array] — Include only Agents using console proxy. Accepts true, false, or none (for not reported).
- `deepVisibility` [query, array] — Include only Agents using deep visibility proxy. Accepts true, false, or none (for not reported).
- `externalIp__contains` [query, array] — Free-text filter by visible IP (supports multiple values). Example: "205,127.0".
- `computerName__contains` [query, array] — Free-text filter by computer name (supports multiple values). Example: "john-office,WIN".
- `networkInterfaceInet__contains` [query, array] — Free-text filter by local IP (supports multiple values). Example: "192,10.0.0".
- `networkInterfacePhysical__contains` [query, array] — Free-text filter by MAC address (supports multiple values). Example: "aa:0f,:41:".
- `networkInterfaceGatewayMacAddress__contains` [query, array] — Free-text filter by Gateway MAC address (supports multiple values). Example: "aa:0f,:41:".
- `lastLoggedInUserName__contains` [query, array] — Free-text filter by username (supports multiple values). Example: "admin,johnd1".
- `osVersion__contains` [query, array] — Free-text filter by OS full name and version (supports multiple values). Example: "Service Pack 1".
- `adQuery__contains` [query, array] — Free-text filter by Active Directory string (supports multiple values). Example: "DC=sentinelone".
- `adUserName__contains` [query, array] — Free-text filter by Active Directory username string (supports multiple values). Example: "DC=sentinelone".
- `adUserMember__contains` [query, array] — Free-text filter by Active Directory user groups string (supports multiple values). Example: "DC=sentinelone".
- `adUserQuery__contains` [query, array] — Free-text filter by Active Directory computer name or its groups (supports multiple values). Example: "DC=sentinelone,John".
- `adComputerName__contains` [query, array] — Free-text filter by Active Directory computer name string (supports multiple values). Example: "DC=sentinelone".
- `adComputerMember__contains` [query, array] — Free-text filter by Active Directory computer groups string (supports multiple values). Example: "DC=sentinelone".
- `adComputerQuery__contains` [query, array] — Free-text filter by Active Directory computer name or its groups (supports multiple values). Example: "DC=sentinelone,Windows".
- `uuid__contains` [query, array] — Free-text filter by Agent UUID (supports multiple values). Example: "e92-01928,b055".
- `externalId__contains` [query, array] — Free-text filter by external ID (Customer ID). Example: "Tag#1 - monitoring,Performance machine".
- `awsRole__contains` [query, array] — Free-text filter by aws role(supports multiple values)
- `awsSecurityGroups__contains` [query, array] — Free-text filter by aws securityGroups(supports multiple values)
- `awsSubnetIds__contains` [query, array] — Free-text filter by aws subnet ids (supports multiple values)
- `agentNamespace__contains` [query, array] — Free-text filter by agent namespace (supports multiple values)
- `agentPodName__contains` [query, array] — Free-text filter by agent pod name (supports multiple values)
- `azureResourceGroup__contains` [query, array] — Free-text filter by azure resource group(supports multiple values)
- `cloudAccount__contains` [query, array] — Free-text filter by cloud account (supports multiple values)
- `cloudImage__contains` [query, array] — Free-text filter by cloud image (supports multiple values)
- `cloudInstanceId__contains` [query, array] — Free-text filter by cloud instance id(supports multiple values)
- `cloudInstanceSize__contains` [query, array] — Free-text filter by cloud instance size(supports multiple values)
- `cloudLocation__contains` [query, array] — Free-text filter by cloud location (supports multiple values)
- `cloudNetwork__contains` [query, array] — Free-text filter by cloud network (supports multiple values)
- `cloudTags__contains` [query, array] — Free-text filter by cloud tags (supports multiple values)
- `clusterName__contains` [query, array] — Free-text filter by cluster name (supports multiple values)
- `gcpServiceAccount__contains` [query, array] — Free-text filter by gcp service account (supports multiple values)
- `k8sNodeLabels__contains` [query, array] — Free-text filter by K8s node labels (supports multiple values)
- `k8sNodeName__contains` [query, array] — Free-text filter by K8s node name (supports multiple values)
- `k8sType__contains` [query, array] — Free-text filter by K8s type(supports multiple values)
- `k8sVersion__contains` [query, array] — Free-text filter by K8s version (supports multiple values)
- `liveUpdateId__contains` [query, array] — Free-text filter by live update ID (supports multiple values)
- `serialNumber__contains` [query, array] — Free-text filter by Serial Number (supports multiple values)
- `cpuId__contains` [query, array] — Free-text filter by CPU name (supports multiple values). Example: "Intel,AMD".
- `ecsType__contains` [query, array] — Free-text filter by ECS type
- `ecsVersion__contains` [query, array] — Free-text filter by ECS version
- `ecsClusterName__contains` [query, array] — Free-text filter by ECS cluster name
- `ecsTaskArn__contains` [query, array] — Free-text filter by ECS task arn
- `ecsTaskAvailabilityZone__contains` [query, array] — Free-text filter by ECS task availability zone
- `ecsServiceName__contains` [query, array] — Free-text filter by ECS service name
- `ecsServiceArn__contains` [query, array] — Free-text filter by ECS service arn
- `ecsTaskDefinitionFamily__contains` [query, array] — Free-text filter by ECS task definition family
- `ecsTaskDefinitionRevision__contains` [query, array] — Free-text filter by ECS task definition revision
- `ecsTaskDefinitionArn__contains` [query, array] — Free-text filter by ECS task definition arn
- `isDecommissioned` [query, array] — Include active, decommissioned or both. Example: "True,False".
- `isUninstalled` [query, array] — Include installed, uninstalled or both. Example: "True,False".
- `computerNameOrUuid__contains` [query, array] — Free-text filter by computer name or uuid (supports multiple values)
- `ids` [query, array] — Included Agent IDs. Example: "225494730938493804,225494730938493915".
- `idsNin` [query, array] — Excluded Agent IDs. Example: "225494730938493804,225494730938493915".
- `filterId` [query, string] — Include all Agents matching this saved filter. Example: "225494730938493804".
- `decommissionedAt__gte` [query, string] — Agents decommissioned after or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `decommissionedAt__lt` [query, string] — Agents decommissioned before this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `decommissionedAt__lte` [query, string] — Agents decommissioned before this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `decommissionedAt__gt` [query, string] — Agents decommissioned after this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `decommissionedAt__between` [query, string] — Date range for decommission time (format: <from_timestamp>-<to_timestamp>, inclusive). Example: "1514978890136-1514978650130".
- `createdAt__lt` [query, string] — Agents created before this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__lte` [query, string] — Agents created before or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__gt` [query, string] — Agents created after this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__gte` [query, string] — Agents created after or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__between` [query, string] — Date range for creation time (format: <from_timestamp>-<to_timestamp>, inclusive). Example: "1514978890136-1514978650130".
- `updatedAt__lt` [query, string] — Agents updated before this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `updatedAt__lte` [query, string] — Agents updated before or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `updatedAt__gt` [query, string] — Agents updated after this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `updatedAt__gte` [query, string] — Agents updated after or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `updatedAt__between` [query, string] — Date range for update time (format: <from_timestamp>-<to_timestamp>, inclusive). Example: "1514978890136-1514978650130".
- `computerName__like` [query, string] — Match computer name partially (substring). Example: "Lab1".
- `computerName` [query, string] — Computer name. Example: "My Office Desktop".
- `agentVersion__lt` [query, string] — Agents versions less than given version. Example: "2.5.1.1320".
- `agentVersion__lte` [query, string] — Agents versions less than or equal to given version. Example: "2.5.1.1320".
- `agentVersion__gt` [query, string] — Agents versions greater than given version. Example: "2.5.1.1320".
- `agentVersion__gte` [query, string] — Agents versions greater than or equal to given version. Example: "2.5.1.1320".
- `agentVersion__between` [query, string] — Version range for agent version (format: <from_version>-<to_version>, inclusive). Example: "2.0.0.0-2.1.5.144".
- `uuid` [query, string] — Agent's universally unique identifier. Example: "ff819e70af13be381993075eb0ce5f2f6de05be2".
- `uuids` [query, array] — A list of included UUIDs. Example: "ff819e70af13be381993075eb0ce5f2f6de05b11,ff819e70af13be381993075eb0ce5f2f6de05c22".
- `scanStatus` [query, string] (enum: none, started, aborted, finished) — Scan status. Example: "none".
- `threatMitigationStatus` [query, string] (enum: mitigated, blocked, active, suspicious, pending, suspicious_resolved) — Include only Agents that have threats with this mitigation status. Example: "mitigated".
- `threatResolved` [query, boolean] — Include only Agents with at least one resolved threat
- `threatHidden` [query, boolean] — Include only Agents with at least one hidden threat
- `threatContentHash` [query, string] — Include only Agents that have at least one threat with this content hash. Example: "cf23df2207d99a74fbe169e3eba035e633b65d94".
- `threatCreatedAt__lt` [query, string] — Agents with threats reported before this time. Example: "2018-02-27T04:49:26.257525Z".
- `threatCreatedAt__lte` [query, string] — Agents with threats reported before or at this time. Example: "2018-02-27T04:49:26.257525Z".
- `threatCreatedAt__gt` [query, string] — Agents with threats reported after this time. Example: "2018-02-27T04:49:26.257525Z".
- `threatCreatedAt__gte` [query, string] — Agents with threats reported after or at this time. Example: "2018-02-27T04:49:26.257525Z".
- `threatCreatedAt__between` [query, string] — Agents with threats reported in a date range (format: <from_timestamp>-<to_timestamp>, inclusive). Example: "1514978764288-1514978999999".
- `activeThreats` [query, integer] — Include Agents with this amount of active threats. Example: "3".
- `activeThreats__gt` [query, integer] — Include Agents with at least this amount of active threats. Example: "5".
- `mitigationMode` [query, string] (enum: detect, protect) — Agent mitigation mode policy. Example: "detect".
- `mitigationModeSuspicious` [query, string] (enum: detect, protect) — Mitigation mode policy for suspicious activity. Example: "detect".
- `registeredAt__lt` [query, string] — Agents registered before this time. Example: "2018-02-27T04:49:26.257525Z".
- `registeredAt__lte` [query, string] — Agents registered before or at this time. Example: "2018-02-27T04:49:26.257525Z".
- `registeredAt__gt` [query, string] — Agents registered after this time. Example: "2018-02-27T04:49:26.257525Z".
- `registeredAt__gte` [query, string] — Agents registered after or at this time. Example: "2018-02-27T04:49:26.257525Z".
- `lastActiveDate__lt` [query, string] — Agents last active before this time. Example: "2018-02-27T04:49:26.257525Z".
- `lastActiveDate__lte` [query, string] — Agents last active before or at this time. Example: "2018-02-27T04:49:26.257525Z".
- `lastActiveDate__gt` [query, string] — Agents last active after this time. Example: "2018-02-27T04:49:26.257525Z".
- `lastActiveDate__gte` [query, string] — Agents last active after or at this time. Example: "2018-02-27T04:49:26.257525Z".
- `lastSuccessfulScanDate__lt` [query, string] — Agents last successful full disk scan before this time. Example: "2018-02-27T04:49:26.257525Z".
- `lastSuccessfulScanDate__lte` [query, string] — Agents last successful full disk scan before or at this time. Example: "2018-02-27T04:49:26.257525Z".
- `lastSuccessfulScanDate__gt` [query, string] — Agents last successful full disk scan after this time. Example: "2018-02-27T04:49:26.257525Z".
- `lastSuccessfulScanDate__gte` [query, string] — Agents last successful full disk scan after or at this time. Example: "2018-02-27T04:49:26.257525Z".
- `coreCount__lt` [query, integer] — CPU cores (less than)
- `coreCount__lte` [query, integer] — CPU cores (less than or equal)
- `coreCount__gt` [query, integer] — CPU cores (more than)
- `coreCount__gte` [query, integer] — CPU cores (more than or equal)
- `cpuCount__lt` [query, integer] — Number of CPUs (less than)
- `cpuCount__lte` [query, integer] — Number of CPUs (less than or equal)
- `cpuCount__gt` [query, integer] — Number of CPUs (more than)
- `cpuCount__gte` [query, integer] — Number of CPUs (more than or equal)
- `totalMemory__lt` [query, integer] — Memory size (MB, less than)
- `totalMemory__lte` [query, integer] — Memory size (MB, less than or equal)
- `totalMemory__gt` [query, integer] — Memory size (MB, more than)
- `totalMemory__gte` [query, integer] — Memory size (MB, more than or equal)
- `migrationStatus` [query, string] (enum: N/A, Pending, Migrated, Failed) — Migration status. Example: "N/A".
- `gatewayIp` [query, string] — Gateway ip. Example: "192.168.0.1".
- `csvFilterId` [query, string] — The ID of the CSV file to filter by. Example: "225494730938493804".
- `rsoLevel` [query, string] (enum: none, pro, ars) — Supported Remote Script Orchestration level. Example: "none".
- `remoteOpsForensicsSupported` [query, boolean] — Include only agents that has Remote Ops Forensicsfeature supported
- `windowsOsRevision__gte` [query, integer] — Agents os revision than or equal to given version
- `windowsOsRevision__lte` [query, integer] — Agents os revision lower than or equal to given version
- `rsoLevels` [query, array] — A list of included rso_levels. Example: "pro,ars".

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/agents/applications`
**Applications**
`operationId`: `_web_api_agents_applications_get`

Get the installed applications for a specific Agent. <BR>To get the Agent ID, run "agents".

Required permissions: `Endpoints.view`

Parameters:
- `ids` [query, array] **required** — Agent ID list. Example: "225494730938493804,225494730938493915".

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/agents/count`
**Count Agents**
`operationId`: `_web_api_agents_count_get`

Get the count of Agents that match a filter. This command is useful to run before you run other commands. You will be able to manage Agent maintenance better if you know how many Agents will get a command that takes time (such as Update Software).

Required permissions: `Endpoints.view`

Parameters:
- `siteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "225494730938493804,225494730938493915".
- `groupIds` [query, array] — List of Group IDs to filter by. Example: "225494730938493804,225494730938493915".
- `filteredGroupIds` [query, array] — List of Group IDs to filter by. Example: "225494730938493804,225494730938493915".
- `filteredSiteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `registeredAt__between` [query, string] — Date range for first registration time (format: <from_timestamp>-<to_timestamp>, inclusive). Example: "1514978764288-1514978999999".
- `lastActiveDate__between` [query, string] — Date range for last active date(format: <from_timestamp>-<to_timestamp>, inclusive). Example: "1514978764288-1514978999999".
- `lastSuccessfulScanDate__between` [query, string] — Date range for last successful full disk scan(format: <from_timestamp>-<to_timestamp>, inclusive). Example: "1514978764288-1514978999999".
- `isActive` [query, array] — Include only active Agents
- `isPendingUninstall` [query, array] — Include only Agents with pending uninstall requests
- `infected` [query, boolean] — Include only Agents with at least one active threat
- `isUpToDate` [query, array] — Include only Agents with updated software
- `query` [query, string] — A free-text search term, will match applicable attributes (sub-string match). Note: Device's physical addresses will be matched if they start with the search term only (no match if they contain the term). Example: "Linux".
- `agentVersions` [query, array] — Agent versions to include. Example: "2.0.0.0,2.1.5.144".
- `agentVersionsNin` [query, array] — Agent versions not to include. Example: "2.0.0.0,2.1.5.144".
- `rangerVersions` [query, array] — Network Scanner versions to include. Example: "2.0.0.0,2.1.5.144".
- `rangerVersionsNin` [query, array] — Network Scanner versions not to include. Example: "2.0.0.0,2.1.5.144".
- `osArch` [query, string] (enum: 32 bit, 64 bit, ARM64) — OS architecture. Example: "32 bit".
- `osArches` [query, array] — OS architectures to include. Example: "32 bit,64 bit".
- `osArchesNin` [query, array] — OS architectures not to include. Example: "32 bit,64 bit".
- `osTypes` [query, array] — Included OS types. Example: "macos".
- `osTypesNin` [query, array] — Not included OS types. Example: "macos".
- `scanStatuses` [query, array] — Included scan statuses. Example: "started,aborted".
- `scanStatusesNin` [query, array] — Not included scan statuses. Example: "started,aborted".
- `machineTypes` [query, array] — Included machine types. Example: "laptop,desktop".
- `machineTypesNin` [query, array] — Not included machine types. Example: "laptop,desktop".
- `storageTypes` [query, array] — Included storage types. Example: "NetApp,Dell,S3".
- `storageTypesNin` [query, array] — Excluded storage types. Example: "NetApp,Dell,S3".
- `networkStatuses` [query, array] — Included network statuses. Example: "connected,connecting".
- `networkStatusesNin` [query, array] — Included network statuses. Example: "connected,connecting".
- `domains` [query, array] — Included network domains. Example: "mybusiness.net,workgroup".
- `domainsNin` [query, array] — Not included network domains. Example: "mybusiness.net,workgroup".
- `encryptedApplications` [query, array] — Disk encryption status
- `totalMemory__between` [query, string] — Total memory range (GB, inclusive). Example: "4-8".
- `coreCount__between` [query, string] — Possible number of CPU cores (inclusive). Example: "2-8".
- `cpuCount__between` [query, string] — Possible number of CPU cores (inclusive). Example: "2-8".
- `userActionsNeeded` [query, array] — Included pending user actions. Example: "reboot_needed,upgrade_needed".
- `missingPermissions` [query, array] — Included missing permissions. Example: "user_action_needed_bluetooth_per,user_action_needed_fda_helper".
- `userActionsNeededNin` [query, array] — Excluded pending user actions. Example: "reboot_needed,upgrade_needed".
- `missingPermissionsNin` [query, array] — Excluded missing permissions. Example: "user_action_needed_bluetooth_per,user_action_needed_fda_helper".
- `adQuery` [query, string] — An Active Directory query string. Example: "CN=Managers,DC=sentinelone,DC=com".
- `hasLocalConfiguration` [query, boolean] — Agent has a local configuration set
- `consoleMigrationStatuses` [query, array] — Migration status in. Example: "N/A".
- `consoleMigrationStatusesNin` [query, array] — Migration status nin. Example: "N/A".
- `appsVulnerabilityStatuses` [query, array] — Apps vulnerability status in. Example: "patch_required".
- `appsVulnerabilityStatusesNin` [query, array] — Apps vulnerability status nin. Example: "patch_required".
- `locationIds` [query, array] — Include only Agents reporting these locations. Example: "225494730938493804,225494730938493915".
- `locationIdsNin` [query, array] — Do not include only Agents reporting these locations. Example: "225494730938493804,225494730938493915".
- `installerTypes` [query, array] — Include only Agents installed with these package types. Example: ".msi".
- `installerTypesNin` [query, array] — Exclude Agents installed with these package types. Example: ".msi".
- `operationalStates` [query, array] — Agent operational state
- `operationalStatesNin` [query, array] — Do not include these Agent operational states
- `remoteProfilingStates` [query, array] — Agent remote profiling state
- `remoteProfilingStatesNin` [query, array] — Do not include these Agent remote profiling states
- `rangerStatuses` [query, array] — Status of Network Discovery. Example: "NotApplicable".
- `rangerStatusesNin` [query, array] — Do not include these Network Scanner Statuses. Example: "NotApplicable".
- `rangerStatus` [query, string] (enum: NotApplicable, Enabled, Disabled) — [DEPRECATED] Use rangerStatuses. Example: "NotApplicable".
- `threatRebootRequired` [query, array] — Has at least one threat with at least one mitigation action pending reboot to succeed
- `networkQuarantineEnabled` [query, array] — The agents supports Network Quarantine Control and its enabled for the agent's group
- `firewallEnabled` [query, array] — The agents supports Firewall Control and it is enabled for the agent's group
- `locationEnabled` [query, array] — The agents supports Location Awareness and it is enabled for the agent's group
- `cloudProvider` [query, array] — Agents from which cloud provider
- `cloudProviderNin` [query, array] — Exclude Agents from these cloud provider
- `tagsData` [query, string] — Filter agents by their assigned tags. Given in form of a JSON where each key represents a tag key, and each value represents a list of string values to filter by. To filter by unassigned tag values, use __nin suffix in the tag key. Example: "{"key1": ["value1_1", "value1_2"], "key2__nin": ["value2"]}".
- `hasTags` [query, boolean] — Include only Agents that have any tags assigned if True, or none if False
- `isAdConnector` [query, array] — The agents that are ADConnectors if True, or not if False
- `isHyperAutomate` [query, array] — The agents has Hyper Automate PNA enabled if True, or not if False
- `activeProtection` [query, array] — Included agent active protections. Example: "edr,idr".
- `containerizedWorkloadCounts` [query, object] — Containerized workload counts
- `hasContainerizedWorkload` [query, array] — Indicates whether the agent protects containerized workload at the moment
- `pacFileUsage` [query, array] — Include only Agents using PAC file for proxy configuration. Accepts true, false, or none (for not reported).
- `proxyMethod` [query, array] — Include only Agents using these proxy methods. Example: "None,Auto,System,User,Custom".
- `proxyMethodNin` [query, array] — Exclude Agents using these proxy methods. Example: "None,Auto,System,User,Custom".
- `console` [query, array] — Include only Agents using console proxy. Accepts true, false, or none (for not reported).
- `deepVisibility` [query, array] — Include only Agents using deep visibility proxy. Accepts true, false, or none (for not reported).
- `externalIp__contains` [query, array] — Free-text filter by visible IP (supports multiple values). Example: "205,127.0".
- `computerName__contains` [query, array] — Free-text filter by computer name (supports multiple values). Example: "john-office,WIN".
- `networkInterfaceInet__contains` [query, array] — Free-text filter by local IP (supports multiple values). Example: "192,10.0.0".
- `networkInterfacePhysical__contains` [query, array] — Free-text filter by MAC address (supports multiple values). Example: "aa:0f,:41:".
- `networkInterfaceGatewayMacAddress__contains` [query, array] — Free-text filter by Gateway MAC address (supports multiple values). Example: "aa:0f,:41:".
- `lastLoggedInUserName__contains` [query, array] — Free-text filter by username (supports multiple values). Example: "admin,johnd1".
- `osVersion__contains` [query, array] — Free-text filter by OS full name and version (supports multiple values). Example: "Service Pack 1".
- `adQuery__contains` [query, array] — Free-text filter by Active Directory string (supports multiple values). Example: "DC=sentinelone".
- `adUserName__contains` [query, array] — Free-text filter by Active Directory username string (supports multiple values). Example: "DC=sentinelone".
- `adUserMember__contains` [query, array] — Free-text filter by Active Directory user groups string (supports multiple values). Example: "DC=sentinelone".
- `adUserQuery__contains` [query, array] — Free-text filter by Active Directory computer name or its groups (supports multiple values). Example: "DC=sentinelone,John".
- `adComputerName__contains` [query, array] — Free-text filter by Active Directory computer name string (supports multiple values). Example: "DC=sentinelone".
- `adComputerMember__contains` [query, array] — Free-text filter by Active Directory computer groups string (supports multiple values). Example: "DC=sentinelone".
- `adComputerQuery__contains` [query, array] — Free-text filter by Active Directory computer name or its groups (supports multiple values). Example: "DC=sentinelone,Windows".
- `uuid__contains` [query, array] — Free-text filter by Agent UUID (supports multiple values). Example: "e92-01928,b055".
- `externalId__contains` [query, array] — Free-text filter by external ID (Customer ID). Example: "Tag#1 - monitoring,Performance machine".
- `awsRole__contains` [query, array] — Free-text filter by aws role(supports multiple values)
- `awsSecurityGroups__contains` [query, array] — Free-text filter by aws securityGroups(supports multiple values)
- `awsSubnetIds__contains` [query, array] — Free-text filter by aws subnet ids (supports multiple values)
- `agentNamespace__contains` [query, array] — Free-text filter by agent namespace (supports multiple values)
- `agentPodName__contains` [query, array] — Free-text filter by agent pod name (supports multiple values)
- `azureResourceGroup__contains` [query, array] — Free-text filter by azure resource group(supports multiple values)
- `cloudAccount__contains` [query, array] — Free-text filter by cloud account (supports multiple values)
- `cloudImage__contains` [query, array] — Free-text filter by cloud image (supports multiple values)
- `cloudInstanceId__contains` [query, array] — Free-text filter by cloud instance id(supports multiple values)
- `cloudInstanceSize__contains` [query, array] — Free-text filter by cloud instance size(supports multiple values)
- `cloudLocation__contains` [query, array] — Free-text filter by cloud location (supports multiple values)
- `cloudNetwork__contains` [query, array] — Free-text filter by cloud network (supports multiple values)
- `cloudTags__contains` [query, array] — Free-text filter by cloud tags (supports multiple values)
- `clusterName__contains` [query, array] — Free-text filter by cluster name (supports multiple values)
- `gcpServiceAccount__contains` [query, array] — Free-text filter by gcp service account (supports multiple values)
- `k8sNodeLabels__contains` [query, array] — Free-text filter by K8s node labels (supports multiple values)
- `k8sNodeName__contains` [query, array] — Free-text filter by K8s node name (supports multiple values)
- `k8sType__contains` [query, array] — Free-text filter by K8s type(supports multiple values)
- `k8sVersion__contains` [query, array] — Free-text filter by K8s version (supports multiple values)
- `liveUpdateId__contains` [query, array] — Free-text filter by live update ID (supports multiple values)
- `serialNumber__contains` [query, array] — Free-text filter by Serial Number (supports multiple values)
- `cpuId__contains` [query, array] — Free-text filter by CPU name (supports multiple values). Example: "Intel,AMD".
- `ecsType__contains` [query, array] — Free-text filter by ECS type
- `ecsVersion__contains` [query, array] — Free-text filter by ECS version
- `ecsClusterName__contains` [query, array] — Free-text filter by ECS cluster name
- `ecsTaskArn__contains` [query, array] — Free-text filter by ECS task arn
- `ecsTaskAvailabilityZone__contains` [query, array] — Free-text filter by ECS task availability zone
- `ecsServiceName__contains` [query, array] — Free-text filter by ECS service name
- `ecsServiceArn__contains` [query, array] — Free-text filter by ECS service arn
- `ecsTaskDefinitionFamily__contains` [query, array] — Free-text filter by ECS task definition family
- `ecsTaskDefinitionRevision__contains` [query, array] — Free-text filter by ECS task definition revision
- `ecsTaskDefinitionArn__contains` [query, array] — Free-text filter by ECS task definition arn
- `isDecommissioned` [query, array] — Include active, decommissioned or both. Example: "True,False".
- `isUninstalled` [query, array] — Include installed, uninstalled or both. Example: "True,False".
- `computerNameOrUuid__contains` [query, array] — Free-text filter by computer name or uuid (supports multiple values)
- `ids` [query, array] — Included Agent IDs. Example: "225494730938493804,225494730938493915".
- `idsNin` [query, array] — Excluded Agent IDs. Example: "225494730938493804,225494730938493915".
- `filterId` [query, string] — Include all Agents matching this saved filter. Example: "225494730938493804".
- `decommissionedAt__gte` [query, string] — Agents decommissioned after or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `decommissionedAt__lt` [query, string] — Agents decommissioned before this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `decommissionedAt__lte` [query, string] — Agents decommissioned before this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `decommissionedAt__gt` [query, string] — Agents decommissioned after this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `decommissionedAt__between` [query, string] — Date range for decommission time (format: <from_timestamp>-<to_timestamp>, inclusive). Example: "1514978890136-1514978650130".
- `createdAt__lt` [query, string] — Agents created before this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__lte` [query, string] — Agents created before or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__gt` [query, string] — Agents created after this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__gte` [query, string] — Agents created after or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__between` [query, string] — Date range for creation time (format: <from_timestamp>-<to_timestamp>, inclusive). Example: "1514978890136-1514978650130".
- `updatedAt__lt` [query, string] — Agents updated before this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `updatedAt__lte` [query, string] — Agents updated before or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `updatedAt__gt` [query, string] — Agents updated after this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `updatedAt__gte` [query, string] — Agents updated after or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `updatedAt__between` [query, string] — Date range for update time (format: <from_timestamp>-<to_timestamp>, inclusive). Example: "1514978890136-1514978650130".
- `computerName__like` [query, string] — Match computer name partially (substring). Example: "Lab1".
- `computerName` [query, string] — Computer name. Example: "My Office Desktop".
- `agentVersion__lt` [query, string] — Agents versions less than given version. Example: "2.5.1.1320".
- `agentVersion__lte` [query, string] — Agents versions less than or equal to given version. Example: "2.5.1.1320".
- `agentVersion__gt` [query, string] — Agents versions greater than given version. Example: "2.5.1.1320".
- `agentVersion__gte` [query, string] — Agents versions greater than or equal to given version. Example: "2.5.1.1320".
- `agentVersion__between` [query, string] — Version range for agent version (format: <from_version>-<to_version>, inclusive). Example: "2.0.0.0-2.1.5.144".
- `uuid` [query, string] — Agent's universally unique identifier. Example: "ff819e70af13be381993075eb0ce5f2f6de05be2".
- `uuids` [query, array] — A list of included UUIDs. Example: "ff819e70af13be381993075eb0ce5f2f6de05b11,ff819e70af13be381993075eb0ce5f2f6de05c22".
- `scanStatus` [query, string] (enum: none, started, aborted, finished) — Scan status. Example: "none".
- `threatMitigationStatus` [query, string] (enum: mitigated, blocked, active, suspicious, pending, suspicious_resolved) — Include only Agents that have threats with this mitigation status. Example: "mitigated".
- `threatResolved` [query, boolean] — Include only Agents with at least one resolved threat
- `threatHidden` [query, boolean] — Include only Agents with at least one hidden threat
- `threatContentHash` [query, string] — Include only Agents that have at least one threat with this content hash. Example: "cf23df2207d99a74fbe169e3eba035e633b65d94".
- `threatCreatedAt__lt` [query, string] — Agents with threats reported before this time. Example: "2018-02-27T04:49:26.257525Z".
- `threatCreatedAt__lte` [query, string] — Agents with threats reported before or at this time. Example: "2018-02-27T04:49:26.257525Z".
- `threatCreatedAt__gt` [query, string] — Agents with threats reported after this time. Example: "2018-02-27T04:49:26.257525Z".
- `threatCreatedAt__gte` [query, string] — Agents with threats reported after or at this time. Example: "2018-02-27T04:49:26.257525Z".
- `threatCreatedAt__between` [query, string] — Agents with threats reported in a date range (format: <from_timestamp>-<to_timestamp>, inclusive). Example: "1514978764288-1514978999999".
- `activeThreats` [query, integer] — Include Agents with this amount of active threats. Example: "3".
- `activeThreats__gt` [query, integer] — Include Agents with at least this amount of active threats. Example: "5".
- `mitigationMode` [query, string] (enum: detect, protect) — Agent mitigation mode policy. Example: "detect".
- `mitigationModeSuspicious` [query, string] (enum: detect, protect) — Mitigation mode policy for suspicious activity. Example: "detect".
- `registeredAt__lt` [query, string] — Agents registered before this time. Example: "2018-02-27T04:49:26.257525Z".
- `registeredAt__lte` [query, string] — Agents registered before or at this time. Example: "2018-02-27T04:49:26.257525Z".
- `registeredAt__gt` [query, string] — Agents registered after this time. Example: "2018-02-27T04:49:26.257525Z".
- `registeredAt__gte` [query, string] — Agents registered after or at this time. Example: "2018-02-27T04:49:26.257525Z".
- `lastActiveDate__lt` [query, string] — Agents last active before this time. Example: "2018-02-27T04:49:26.257525Z".
- `lastActiveDate__lte` [query, string] — Agents last active before or at this time. Example: "2018-02-27T04:49:26.257525Z".
- `lastActiveDate__gt` [query, string] — Agents last active after this time. Example: "2018-02-27T04:49:26.257525Z".
- `lastActiveDate__gte` [query, string] — Agents last active after or at this time. Example: "2018-02-27T04:49:26.257525Z".
- `lastSuccessfulScanDate__lt` [query, string] — Agents last successful full disk scan before this time. Example: "2018-02-27T04:49:26.257525Z".
- `lastSuccessfulScanDate__lte` [query, string] — Agents last successful full disk scan before or at this time. Example: "2018-02-27T04:49:26.257525Z".
- `lastSuccessfulScanDate__gt` [query, string] — Agents last successful full disk scan after this time. Example: "2018-02-27T04:49:26.257525Z".
- `lastSuccessfulScanDate__gte` [query, string] — Agents last successful full disk scan after or at this time. Example: "2018-02-27T04:49:26.257525Z".
- `coreCount__lt` [query, integer] — CPU cores (less than)
- `coreCount__lte` [query, integer] — CPU cores (less than or equal)
- `coreCount__gt` [query, integer] — CPU cores (more than)
- `coreCount__gte` [query, integer] — CPU cores (more than or equal)
- `cpuCount__lt` [query, integer] — Number of CPUs (less than)
- `cpuCount__lte` [query, integer] — Number of CPUs (less than or equal)
- `cpuCount__gt` [query, integer] — Number of CPUs (more than)
- `cpuCount__gte` [query, integer] — Number of CPUs (more than or equal)
- `totalMemory__lt` [query, integer] — Memory size (MB, less than)
- `totalMemory__lte` [query, integer] — Memory size (MB, less than or equal)
- `totalMemory__gt` [query, integer] — Memory size (MB, more than)
- `totalMemory__gte` [query, integer] — Memory size (MB, more than or equal)
- `migrationStatus` [query, string] (enum: N/A, Pending, Migrated, Failed) — Migration status. Example: "N/A".
- `gatewayIp` [query, string] — Gateway ip. Example: "192.168.0.1".
- `csvFilterId` [query, string] — The ID of the CSV file to filter by. Example: "225494730938493804".
- `rsoLevel` [query, string] (enum: none, pro, ars) — Supported Remote Script Orchestration level. Example: "none".
- `remoteOpsForensicsSupported` [query, boolean] — Include only agents that has Remote Ops Forensicsfeature supported
- `windowsOsRevision__gte` [query, integer] — Agents os revision than or equal to given version
- `windowsOsRevision__lte` [query, integer] — Agents os revision lower than or equal to given version
- `rsoLevels` [query, array] — A list of included rso_levels. Example: "pro,ars".

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/agents/disable-hyper-automation-pna`
**Disable PNA for Hyperautomation**
`operationId`: `_web_api_agents_disable-hyper-automation-pna_post`

Disable Agent PNA for Hyperautomation

Required permissions: `Endpoints.edit, Hyper Automate.connectionsEdit`

Parameters:
- `body` [body, agents.schemas_AgentsActionSchema] — 

Responses: 403 Insufficient permissions, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/agents/enable-hyper-automation-pna`
**Enable Agent PNA for Hyperautomation**
`operationId`: `_web_api_agents_enable-hyper-automation-pna_post`

Enable Agent PNA for Hyperautomation

Required permissions: `Endpoints.edit, Hyper Automate.connectionsEdit`

Parameters:
- `body` [body, agents.schemas_AgentsActionSchema] — 

Responses: 400 Invalid user input received. See error details for further i, 404 Agent not found, 403 Insufficient permissions, 200 Success, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/agents/passphrases`
**Get Passphrase**
`operationId`: `_web_api_agents_passphrases_get`

Show the passphrase for the Agents that match the filter. This is an important command. You need the passphrase for most SentinelCtl commands and for different API commands.

Required permissions: `Endpoints.showPassphrase`

Parameters:
- `skip` [query, integer] — Skip first number of items (0-1000). To iterate over more than 1000 items,  use "cursor". Example: "150".
- `limit` [query, integer] — Limit number of returned items (1-1000). Example: "10".
- `cursor` [query, string] — Cursor position returned by the last request. Use to iterate over more than 1000 items. Example: "YWdlbnRfaWQ6NTgwMjkzODE=".
- `countOnly` [query, boolean] — If true, only total number of items will be returned, without any of the actual objects.
- `skipCount` [query, boolean] — If true, total number of items will not be calculated, which speeds up execution time.
- `siteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "225494730938493804,225494730938493915".
- `groupIds` [query, array] — List of Group IDs to filter by. Example: "225494730938493804,225494730938493915".
- `filteredGroupIds` [query, array] — List of Group IDs to filter by. Example: "225494730938493804,225494730938493915".
- `filteredSiteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `registeredAt__between` [query, string] — Date range for first registration time (format: <from_timestamp>-<to_timestamp>, inclusive). Example: "1514978764288-1514978999999".
- `lastActiveDate__between` [query, string] — Date range for last active date(format: <from_timestamp>-<to_timestamp>, inclusive). Example: "1514978764288-1514978999999".
- `lastSuccessfulScanDate__between` [query, string] — Date range for last successful full disk scan(format: <from_timestamp>-<to_timestamp>, inclusive). Example: "1514978764288-1514978999999".
- `isActive` [query, array] — Include only active Agents
- `isPendingUninstall` [query, array] — Include only Agents with pending uninstall requests
- `infected` [query, boolean] — Include only Agents with at least one active threat
- `isUpToDate` [query, array] — Include only Agents with updated software
- `query` [query, string] — A free-text search term, will match applicable attributes (sub-string match). Note: Device's physical addresses will be matched if they start with the search term only (no match if they contain the term). Example: "Linux".
- `agentVersions` [query, array] — Agent versions to include. Example: "2.0.0.0,2.1.5.144".
- `agentVersionsNin` [query, array] — Agent versions not to include. Example: "2.0.0.0,2.1.5.144".
- `rangerVersions` [query, array] — Network Scanner versions to include. Example: "2.0.0.0,2.1.5.144".
- `rangerVersionsNin` [query, array] — Network Scanner versions not to include. Example: "2.0.0.0,2.1.5.144".
- `osArch` [query, string] (enum: 32 bit, 64 bit, ARM64) — OS architecture. Example: "32 bit".
- `osArches` [query, array] — OS architectures to include. Example: "32 bit,64 bit".
- `osArchesNin` [query, array] — OS architectures not to include. Example: "32 bit,64 bit".
- `osTypes` [query, array] — Included OS types. Example: "macos".
- `osTypesNin` [query, array] — Not included OS types. Example: "macos".
- `scanStatuses` [query, array] — Included scan statuses. Example: "started,aborted".
- `scanStatusesNin` [query, array] — Not included scan statuses. Example: "started,aborted".
- `machineTypes` [query, array] — Included machine types. Example: "laptop,desktop".
- `machineTypesNin` [query, array] — Not included machine types. Example: "laptop,desktop".
- `storageTypes` [query, array] — Included storage types. Example: "NetApp,Dell,S3".
- `storageTypesNin` [query, array] — Excluded storage types. Example: "NetApp,Dell,S3".
- `networkStatuses` [query, array] — Included network statuses. Example: "connected,connecting".
- `networkStatusesNin` [query, array] — Included network statuses. Example: "connected,connecting".
- `domains` [query, array] — Included network domains. Example: "mybusiness.net,workgroup".
- `domainsNin` [query, array] — Not included network domains. Example: "mybusiness.net,workgroup".
- `encryptedApplications` [query, array] — Disk encryption status
- `totalMemory__between` [query, string] — Total memory range (GB, inclusive). Example: "4-8".
- `coreCount__between` [query, string] — Possible number of CPU cores (inclusive). Example: "2-8".
- `cpuCount__between` [query, string] — Possible number of CPU cores (inclusive). Example: "2-8".
- `userActionsNeeded` [query, array] — Included pending user actions. Example: "reboot_needed,upgrade_needed".
- `missingPermissions` [query, array] — Included missing permissions. Example: "user_action_needed_bluetooth_per,user_action_needed_fda_helper".
- `userActionsNeededNin` [query, array] — Excluded pending user actions. Example: "reboot_needed,upgrade_needed".
- `missingPermissionsNin` [query, array] — Excluded missing permissions. Example: "user_action_needed_bluetooth_per,user_action_needed_fda_helper".
- `adQuery` [query, string] — An Active Directory query string. Example: "CN=Managers,DC=sentinelone,DC=com".
- `hasLocalConfiguration` [query, boolean] — Agent has a local configuration set
- `consoleMigrationStatuses` [query, array] — Migration status in. Example: "N/A".
- `consoleMigrationStatusesNin` [query, array] — Migration status nin. Example: "N/A".
- `appsVulnerabilityStatuses` [query, array] — Apps vulnerability status in. Example: "patch_required".
- `appsVulnerabilityStatusesNin` [query, array] — Apps vulnerability status nin. Example: "patch_required".
- `locationIds` [query, array] — Include only Agents reporting these locations. Example: "225494730938493804,225494730938493915".
- `locationIdsNin` [query, array] — Do not include only Agents reporting these locations. Example: "225494730938493804,225494730938493915".
- `installerTypes` [query, array] — Include only Agents installed with these package types. Example: ".msi".
- `installerTypesNin` [query, array] — Exclude Agents installed with these package types. Example: ".msi".
- `operationalStates` [query, array] — Agent operational state
- `operationalStatesNin` [query, array] — Do not include these Agent operational states
- `remoteProfilingStates` [query, array] — Agent remote profiling state
- `remoteProfilingStatesNin` [query, array] — Do not include these Agent remote profiling states
- `rangerStatuses` [query, array] — Status of Network Discovery. Example: "NotApplicable".
- `rangerStatusesNin` [query, array] — Do not include these Network Scanner Statuses. Example: "NotApplicable".
- `rangerStatus` [query, string] (enum: NotApplicable, Enabled, Disabled) — [DEPRECATED] Use rangerStatuses. Example: "NotApplicable".
- `threatRebootRequired` [query, array] — Has at least one threat with at least one mitigation action pending reboot to succeed
- `networkQuarantineEnabled` [query, array] — The agents supports Network Quarantine Control and its enabled for the agent's group
- `firewallEnabled` [query, array] — The agents supports Firewall Control and it is enabled for the agent's group
- `locationEnabled` [query, array] — The agents supports Location Awareness and it is enabled for the agent's group
- `cloudProvider` [query, array] — Agents from which cloud provider
- `cloudProviderNin` [query, array] — Exclude Agents from these cloud provider
- `tagsData` [query, string] — Filter agents by their assigned tags. Given in form of a JSON where each key represents a tag key, and each value represents a list of string values to filter by. To filter by unassigned tag values, use __nin suffix in the tag key. Example: "{"key1": ["value1_1", "value1_2"], "key2__nin": ["value2"]}".
- `hasTags` [query, boolean] — Include only Agents that have any tags assigned if True, or none if False
- `isAdConnector` [query, array] — The agents that are ADConnectors if True, or not if False
- `isHyperAutomate` [query, array] — The agents has Hyper Automate PNA enabled if True, or not if False
- `activeProtection` [query, array] — Included agent active protections. Example: "edr,idr".
- `containerizedWorkloadCounts` [query, object] — Containerized workload counts
- `hasContainerizedWorkload` [query, array] — Indicates whether the agent protects containerized workload at the moment
- `pacFileUsage` [query, array] — Include only Agents using PAC file for proxy configuration. Accepts true, false, or none (for not reported).
- `proxyMethod` [query, array] — Include only Agents using these proxy methods. Example: "None,Auto,System,User,Custom".
- `proxyMethodNin` [query, array] — Exclude Agents using these proxy methods. Example: "None,Auto,System,User,Custom".
- `console` [query, array] — Include only Agents using console proxy. Accepts true, false, or none (for not reported).
- `deepVisibility` [query, array] — Include only Agents using deep visibility proxy. Accepts true, false, or none (for not reported).
- `externalIp__contains` [query, array] — Free-text filter by visible IP (supports multiple values). Example: "205,127.0".
- `computerName__contains` [query, array] — Free-text filter by computer name (supports multiple values). Example: "john-office,WIN".
- `networkInterfaceInet__contains` [query, array] — Free-text filter by local IP (supports multiple values). Example: "192,10.0.0".
- `networkInterfacePhysical__contains` [query, array] — Free-text filter by MAC address (supports multiple values). Example: "aa:0f,:41:".
- `networkInterfaceGatewayMacAddress__contains` [query, array] — Free-text filter by Gateway MAC address (supports multiple values). Example: "aa:0f,:41:".
- `lastLoggedInUserName__contains` [query, array] — Free-text filter by username (supports multiple values). Example: "admin,johnd1".
- `osVersion__contains` [query, array] — Free-text filter by OS full name and version (supports multiple values). Example: "Service Pack 1".
- `adQuery__contains` [query, array] — Free-text filter by Active Directory string (supports multiple values). Example: "DC=sentinelone".
- `adUserName__contains` [query, array] — Free-text filter by Active Directory username string (supports multiple values). Example: "DC=sentinelone".
- `adUserMember__contains` [query, array] — Free-text filter by Active Directory user groups string (supports multiple values). Example: "DC=sentinelone".
- `adUserQuery__contains` [query, array] — Free-text filter by Active Directory computer name or its groups (supports multiple values). Example: "DC=sentinelone,John".
- `adComputerName__contains` [query, array] — Free-text filter by Active Directory computer name string (supports multiple values). Example: "DC=sentinelone".
- `adComputerMember__contains` [query, array] — Free-text filter by Active Directory computer groups string (supports multiple values). Example: "DC=sentinelone".
- `adComputerQuery__contains` [query, array] — Free-text filter by Active Directory computer name or its groups (supports multiple values). Example: "DC=sentinelone,Windows".
- `uuid__contains` [query, array] — Free-text filter by Agent UUID (supports multiple values). Example: "e92-01928,b055".
- `externalId__contains` [query, array] — Free-text filter by external ID (Customer ID). Example: "Tag#1 - monitoring,Performance machine".
- `awsRole__contains` [query, array] — Free-text filter by aws role(supports multiple values)
- `awsSecurityGroups__contains` [query, array] — Free-text filter by aws securityGroups(supports multiple values)
- `awsSubnetIds__contains` [query, array] — Free-text filter by aws subnet ids (supports multiple values)
- `agentNamespace__contains` [query, array] — Free-text filter by agent namespace (supports multiple values)
- `agentPodName__contains` [query, array] — Free-text filter by agent pod name (supports multiple values)
- `azureResourceGroup__contains` [query, array] — Free-text filter by azure resource group(supports multiple values)
- `cloudAccount__contains` [query, array] — Free-text filter by cloud account (supports multiple values)
- `cloudImage__contains` [query, array] — Free-text filter by cloud image (supports multiple values)
- `cloudInstanceId__contains` [query, array] — Free-text filter by cloud instance id(supports multiple values)
- `cloudInstanceSize__contains` [query, array] — Free-text filter by cloud instance size(supports multiple values)
- `cloudLocation__contains` [query, array] — Free-text filter by cloud location (supports multiple values)
- `cloudNetwork__contains` [query, array] — Free-text filter by cloud network (supports multiple values)
- `cloudTags__contains` [query, array] — Free-text filter by cloud tags (supports multiple values)
- `clusterName__contains` [query, array] — Free-text filter by cluster name (supports multiple values)
- `gcpServiceAccount__contains` [query, array] — Free-text filter by gcp service account (supports multiple values)
- `k8sNodeLabels__contains` [query, array] — Free-text filter by K8s node labels (supports multiple values)
- `k8sNodeName__contains` [query, array] — Free-text filter by K8s node name (supports multiple values)
- `k8sType__contains` [query, array] — Free-text filter by K8s type(supports multiple values)
- `k8sVersion__contains` [query, array] — Free-text filter by K8s version (supports multiple values)
- `liveUpdateId__contains` [query, array] — Free-text filter by live update ID (supports multiple values)
- `serialNumber__contains` [query, array] — Free-text filter by Serial Number (supports multiple values)
- `cpuId__contains` [query, array] — Free-text filter by CPU name (supports multiple values). Example: "Intel,AMD".
- `ecsType__contains` [query, array] — Free-text filter by ECS type
- `ecsVersion__contains` [query, array] — Free-text filter by ECS version
- `ecsClusterName__contains` [query, array] — Free-text filter by ECS cluster name
- `ecsTaskArn__contains` [query, array] — Free-text filter by ECS task arn
- `ecsTaskAvailabilityZone__contains` [query, array] — Free-text filter by ECS task availability zone
- `ecsServiceName__contains` [query, array] — Free-text filter by ECS service name
- `ecsServiceArn__contains` [query, array] — Free-text filter by ECS service arn
- `ecsTaskDefinitionFamily__contains` [query, array] — Free-text filter by ECS task definition family
- `ecsTaskDefinitionRevision__contains` [query, array] — Free-text filter by ECS task definition revision
- `ecsTaskDefinitionArn__contains` [query, array] — Free-text filter by ECS task definition arn
- `isDecommissioned` [query, array] — Include active, decommissioned or both. Example: "True,False".
- `isUninstalled` [query, array] — Include installed, uninstalled or both. Example: "True,False".
- `computerNameOrUuid__contains` [query, array] — Free-text filter by computer name or uuid (supports multiple values)
- `ids` [query, array] — Included Agent IDs. Example: "225494730938493804,225494730938493915".
- `idsNin` [query, array] — Excluded Agent IDs. Example: "225494730938493804,225494730938493915".
- `filterId` [query, string] — Include all Agents matching this saved filter. Example: "225494730938493804".
- `decommissionedAt__gte` [query, string] — Agents decommissioned after or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `decommissionedAt__lt` [query, string] — Agents decommissioned before this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `decommissionedAt__lte` [query, string] — Agents decommissioned before this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `decommissionedAt__gt` [query, string] — Agents decommissioned after this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `decommissionedAt__between` [query, string] — Date range for decommission time (format: <from_timestamp>-<to_timestamp>, inclusive). Example: "1514978890136-1514978650130".
- `createdAt__lt` [query, string] — Agents created before this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__lte` [query, string] — Agents created before or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__gt` [query, string] — Agents created after this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__gte` [query, string] — Agents created after or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__between` [query, string] — Date range for creation time (format: <from_timestamp>-<to_timestamp>, inclusive). Example: "1514978890136-1514978650130".
- `updatedAt__lt` [query, string] — Agents updated before this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `updatedAt__lte` [query, string] — Agents updated before or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `updatedAt__gt` [query, string] — Agents updated after this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `updatedAt__gte` [query, string] — Agents updated after or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `updatedAt__between` [query, string] — Date range for update time (format: <from_timestamp>-<to_timestamp>, inclusive). Example: "1514978890136-1514978650130".
- `computerName__like` [query, string] — Match computer name partially (substring). Example: "Lab1".
- `computerName` [query, string] — Computer name. Example: "My Office Desktop".
- `agentVersion__lt` [query, string] — Agents versions less than given version. Example: "2.5.1.1320".
- `agentVersion__lte` [query, string] — Agents versions less than or equal to given version. Example: "2.5.1.1320".
- `agentVersion__gt` [query, string] — Agents versions greater than given version. Example: "2.5.1.1320".
- `agentVersion__gte` [query, string] — Agents versions greater than or equal to given version. Example: "2.5.1.1320".
- `agentVersion__between` [query, string] — Version range for agent version (format: <from_version>-<to_version>, inclusive). Example: "2.0.0.0-2.1.5.144".
- `uuid` [query, string] — Agent's universally unique identifier. Example: "ff819e70af13be381993075eb0ce5f2f6de05be2".
- `uuids` [query, array] — A list of included UUIDs. Example: "ff819e70af13be381993075eb0ce5f2f6de05b11,ff819e70af13be381993075eb0ce5f2f6de05c22".
- `scanStatus` [query, string] (enum: none, started, aborted, finished) — Scan status. Example: "none".
- `threatMitigationStatus` [query, string] (enum: mitigated, blocked, active, suspicious, pending, suspicious_resolved) — Include only Agents that have threats with this mitigation status. Example: "mitigated".
- `threatResolved` [query, boolean] — Include only Agents with at least one resolved threat
- `threatHidden` [query, boolean] — Include only Agents with at least one hidden threat
- `threatContentHash` [query, string] — Include only Agents that have at least one threat with this content hash. Example: "cf23df2207d99a74fbe169e3eba035e633b65d94".
- `threatCreatedAt__lt` [query, string] — Agents with threats reported before this time. Example: "2018-02-27T04:49:26.257525Z".
- `threatCreatedAt__lte` [query, string] — Agents with threats reported before or at this time. Example: "2018-02-27T04:49:26.257525Z".
- `threatCreatedAt__gt` [query, string] — Agents with threats reported after this time. Example: "2018-02-27T04:49:26.257525Z".
- `threatCreatedAt__gte` [query, string] — Agents with threats reported after or at this time. Example: "2018-02-27T04:49:26.257525Z".
- `threatCreatedAt__between` [query, string] — Agents with threats reported in a date range (format: <from_timestamp>-<to_timestamp>, inclusive). Example: "1514978764288-1514978999999".
- `activeThreats` [query, integer] — Include Agents with this amount of active threats. Example: "3".
- `activeThreats__gt` [query, integer] — Include Agents with at least this amount of active threats. Example: "5".
- `mitigationMode` [query, string] (enum: detect, protect) — Agent mitigation mode policy. Example: "detect".
- `mitigationModeSuspicious` [query, string] (enum: detect, protect) — Mitigation mode policy for suspicious activity. Example: "detect".
- `registeredAt__lt` [query, string] — Agents registered before this time. Example: "2018-02-27T04:49:26.257525Z".
- `registeredAt__lte` [query, string] — Agents registered before or at this time. Example: "2018-02-27T04:49:26.257525Z".
- `registeredAt__gt` [query, string] — Agents registered after this time. Example: "2018-02-27T04:49:26.257525Z".
- `registeredAt__gte` [query, string] — Agents registered after or at this time. Example: "2018-02-27T04:49:26.257525Z".
- `lastActiveDate__lt` [query, string] — Agents last active before this time. Example: "2018-02-27T04:49:26.257525Z".
- `lastActiveDate__lte` [query, string] — Agents last active before or at this time. Example: "2018-02-27T04:49:26.257525Z".
- `lastActiveDate__gt` [query, string] — Agents last active after this time. Example: "2018-02-27T04:49:26.257525Z".
- `lastActiveDate__gte` [query, string] — Agents last active after or at this time. Example: "2018-02-27T04:49:26.257525Z".
- `lastSuccessfulScanDate__lt` [query, string] — Agents last successful full disk scan before this time. Example: "2018-02-27T04:49:26.257525Z".
- `lastSuccessfulScanDate__lte` [query, string] — Agents last successful full disk scan before or at this time. Example: "2018-02-27T04:49:26.257525Z".
- `lastSuccessfulScanDate__gt` [query, string] — Agents last successful full disk scan after this time. Example: "2018-02-27T04:49:26.257525Z".
- `lastSuccessfulScanDate__gte` [query, string] — Agents last successful full disk scan after or at this time. Example: "2018-02-27T04:49:26.257525Z".
- `coreCount__lt` [query, integer] — CPU cores (less than)
- `coreCount__lte` [query, integer] — CPU cores (less than or equal)
- `coreCount__gt` [query, integer] — CPU cores (more than)
- `coreCount__gte` [query, integer] — CPU cores (more than or equal)
- `cpuCount__lt` [query, integer] — Number of CPUs (less than)
- `cpuCount__lte` [query, integer] — Number of CPUs (less than or equal)
- `cpuCount__gt` [query, integer] — Number of CPUs (more than)
- `cpuCount__gte` [query, integer] — Number of CPUs (more than or equal)
- `totalMemory__lt` [query, integer] — Memory size (MB, less than)
- `totalMemory__lte` [query, integer] — Memory size (MB, less than or equal)
- `totalMemory__gt` [query, integer] — Memory size (MB, more than)
- `totalMemory__gte` [query, integer] — Memory size (MB, more than or equal)
- `migrationStatus` [query, string] (enum: N/A, Pending, Migrated, Failed) — Migration status. Example: "N/A".
- `gatewayIp` [query, string] — Gateway ip. Example: "192.168.0.1".
- `csvFilterId` [query, string] — The ID of the CSV file to filter by. Example: "225494730938493804".
- `rsoLevel` [query, string] (enum: none, pro, ars) — Supported Remote Script Orchestration level. Example: "none".
- `remoteOpsForensicsSupported` [query, boolean] — Include only agents that has Remote Ops Forensicsfeature supported
- `windowsOsRevision__gte` [query, integer] — Agents os revision than or equal to given version
- `windowsOsRevision__lte` [query, integer] — Agents os revision lower than or equal to given version
- `rsoLevels` [query, array] — A list of included rso_levels. Example: "pro,ars".

Responses: 403 Insufficient permissions, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/agents/processes`
**Processes**
`operationId`: `_web_api_agents_processes_get`

[OBSOLETE] Returns empty array. To get processes of an Agent, see Applications.

Required permissions: `Endpoints.view`

Parameters:
- `ids` [query, array] **required** — Agent ID list. Example: "225494730938493804,225494730938493915".

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/agents/tags`
**Get the endpoint tags that match the filters.**
`operationId`: `_web_api_agents_tags_get`

Get endpoint Tags.

Required permissions: `Endpoints.view`
Optional permissions: `Tag Management.edit`

Parameters:
- `skip` [query, integer] — Skip first number of items (0-1000). To iterate over more than 1000 items,  use "cursor". Example: "150".
- `limit` [query, integer] — Limit number of returned items (1-1000). Example: "10".
- `cursor` [query, string] — Cursor position returned by the last request. Use to iterate over more than 1000 items. Example: "YWdlbnRfaWQ6NTgwMjkzODE=".
- `countOnly` [query, boolean] — If true, only total number of items will be returned, without any of the actual objects.
- `skipCount` [query, boolean] — If true, total number of items will not be calculated, which speeds up execution time.
- `sortBy` [query, string] (enum: key, value, description, updatedAt, createdBy, updatedBy, scopePath) — The column to sort the results by. Example: "id".
- `sortOrder` [query, string] (enum: asc, desc) — Sort direction. Example: "asc".
- `siteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "225494730938493804,225494730938493915".
- `groupIds` [query, array] — List of Group IDs to filter by. Example: "225494730938493804,225494730938493915".
- `includeParents` [query, boolean] — Return tags from parent scope levels
- `includeChildren` [query, boolean] — Return tags from children scope levels
- `ids` [query, array] — List of tag IDs to filter by. Example: "225494730938493804,225494730938493915".
- `key__contains` [query, array] — Free-text filter by tag key. Example: "server".
- `query` [query, string] — Free text search on fields key, value, description
- `key` [query, string] — Tag key
- `value` [query, string] — Tag value
- `description` [query, string] — Tag description
- `scopePath` [query, string] — Scope path
- `createdBy` [query, string] — Created by
- `updatedBy` [query, string] — Updated by
- `value__contains` [query, array] — Free-text filter by tag value. Example: "server".
- `includeEndpointCounters` [query, boolean] — Include endpoint counters
- `includeExclusionCounters` [query, boolean] — Include exclusion counters
- `isDecommissioned` [query, array] — Filter endpoint counts by decommissioned status: [False] for active only, [True] for decommissioned only, [True, False] for both. Example: "True,False".
- `isUninstalled` [query, array] — Filter endpoint counts by uninstalled status: [False] for installed only, [True] for uninstalled only, [True, False] for both. Example: "True,False".

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/agents/tags/filters-count`
**Endpoint tags count by Filters**
`operationId`: `_web_api_agents_tags_filters-count_get`

Get endpoint Tags filter counts.

Required permissions: `Endpoints.view`
Optional permissions: `Tag Management.edit`

Parameters:
- `siteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "225494730938493804,225494730938493915".
- `groupIds` [query, array] — List of Group IDs to filter by. Example: "225494730938493804,225494730938493915".
- `includeParents` [query, boolean] — Return tags from parent scope levels
- `includeChildren` [query, boolean] — Return tags from children scope levels
- `ids` [query, array] — List of tag IDs to filter by. Example: "225494730938493804,225494730938493915".
- `key__contains` [query, array] — Free-text filter by tag key. Example: "server".
- `query` [query, string] — Free text search on fields key, value, description
- `key` [query, string] — Tag key
- `value` [query, string] — Tag value
- `description` [query, string] — Tag description
- `scopePath` [query, string] — Scope path
- `createdBy` [query, string] — Created by
- `updatedBy` [query, string] — Updated by
- `value__contains` [query, array] — Free-text filter by tag value. Example: "server".

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/agents/{agent_id}/local-upgrade-authorization`
**Get local upgrade/downgrade Agent authorization**
`operationId`: `_web_api_agents_{agent_id}_local-upgrade-authorization_get`

Get the time when authorization of local upgrades/downgrades expires

Required permissions: `Local Upgrade/Downgrade Authorization.view`

Parameters:
- `agent_id` [path, string] **required** — Agent ID. Example: "225494730938493804".

Responses: 200 Success, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/agents/{agent_id}/uploads/{activity_id}`
**Export Agent Logs**
`operationId`: `_web_api_agents_{agent_id}_uploads_{activity_id}_get`

Get Agent logs from Agents that match the filter. You can filter by Agent ID (run "agents" to get the ID) or by Activity ID (run "activities/types" to get the Activity ID). Send the logs to SentinelOne Support for assistance.

Required permissions: `Endpoints.view`
Optional permissions: `Endpoints.fileFetch, Endpoints.FetchLogs, Endpoints.downloadRemoteShellTranscript`

Parameters:
- `agent_id` [path, string] **required** — Agent ID. Example: "225494730938493804".
- `activity_id` [path, string] **required** — ID of activity that logs files uploaded by agent. Example: "225494730938493804".

Responses: 404 Agent or activity not found, 403 Insufficient permissions, 200 Success, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/export/agents`
**Export Agents**
`operationId`: `_web_api_export_agents_get`

Export Agent data to a CSV, for Agents that match the filter. This command exports up to 50000 items (each datum is an item).

Required permissions: `Endpoints.view`

Parameters:
- `siteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "225494730938493804,225494730938493915".
- `groupIds` [query, array] — List of Group IDs to filter by. Example: "225494730938493804,225494730938493915".
- `filteredGroupIds` [query, array] — List of Group IDs to filter by. Example: "225494730938493804,225494730938493915".
- `filteredSiteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `registeredAt__between` [query, string] — Date range for first registration time (format: <from_timestamp>-<to_timestamp>, inclusive). Example: "1514978764288-1514978999999".
- `lastActiveDate__between` [query, string] — Date range for last active date(format: <from_timestamp>-<to_timestamp>, inclusive). Example: "1514978764288-1514978999999".
- `lastSuccessfulScanDate__between` [query, string] — Date range for last successful full disk scan(format: <from_timestamp>-<to_timestamp>, inclusive). Example: "1514978764288-1514978999999".
- `isActive` [query, array] — Include only active Agents
- `isPendingUninstall` [query, array] — Include only Agents with pending uninstall requests
- `infected` [query, boolean] — Include only Agents with at least one active threat
- `isUpToDate` [query, array] — Include only Agents with updated software
- `query` [query, string] — A free-text search term, will match applicable attributes (sub-string match). Note: Device's physical addresses will be matched if they start with the search term only (no match if they contain the term). Example: "Linux".
- `agentVersions` [query, array] — Agent versions to include. Example: "2.0.0.0,2.1.5.144".
- `agentVersionsNin` [query, array] — Agent versions not to include. Example: "2.0.0.0,2.1.5.144".
- `rangerVersions` [query, array] — Network Scanner versions to include. Example: "2.0.0.0,2.1.5.144".
- `rangerVersionsNin` [query, array] — Network Scanner versions not to include. Example: "2.0.0.0,2.1.5.144".
- `osArch` [query, string] (enum: 32 bit, 64 bit, ARM64) — OS architecture. Example: "32 bit".
- `osArches` [query, array] — OS architectures to include. Example: "32 bit,64 bit".
- `osArchesNin` [query, array] — OS architectures not to include. Example: "32 bit,64 bit".
- `osTypes` [query, array] — Included OS types. Example: "macos".
- `osTypesNin` [query, array] — Not included OS types. Example: "macos".
- `scanStatuses` [query, array] — Included scan statuses. Example: "started,aborted".
- `scanStatusesNin` [query, array] — Not included scan statuses. Example: "started,aborted".
- `machineTypes` [query, array] — Included machine types. Example: "laptop,desktop".
- `machineTypesNin` [query, array] — Not included machine types. Example: "laptop,desktop".
- `storageTypes` [query, array] — Included storage types. Example: "NetApp,Dell,S3".
- `storageTypesNin` [query, array] — Excluded storage types. Example: "NetApp,Dell,S3".
- `networkStatuses` [query, array] — Included network statuses. Example: "connected,connecting".
- `networkStatusesNin` [query, array] — Included network statuses. Example: "connected,connecting".
- `domains` [query, array] — Included network domains. Example: "mybusiness.net,workgroup".
- `domainsNin` [query, array] — Not included network domains. Example: "mybusiness.net,workgroup".
- `encryptedApplications` [query, array] — Disk encryption status
- `totalMemory__between` [query, string] — Total memory range (GB, inclusive). Example: "4-8".
- `coreCount__between` [query, string] — Possible number of CPU cores (inclusive). Example: "2-8".
- `cpuCount__between` [query, string] — Possible number of CPU cores (inclusive). Example: "2-8".
- `userActionsNeeded` [query, array] — Included pending user actions. Example: "reboot_needed,upgrade_needed".
- `missingPermissions` [query, array] — Included missing permissions. Example: "user_action_needed_bluetooth_per,user_action_needed_fda_helper".
- `userActionsNeededNin` [query, array] — Excluded pending user actions. Example: "reboot_needed,upgrade_needed".
- `missingPermissionsNin` [query, array] — Excluded missing permissions. Example: "user_action_needed_bluetooth_per,user_action_needed_fda_helper".
- `adQuery` [query, string] — An Active Directory query string. Example: "CN=Managers,DC=sentinelone,DC=com".
- `hasLocalConfiguration` [query, boolean] — Agent has a local configuration set
- `consoleMigrationStatuses` [query, array] — Migration status in. Example: "N/A".
- `consoleMigrationStatusesNin` [query, array] — Migration status nin. Example: "N/A".
- `appsVulnerabilityStatuses` [query, array] — Apps vulnerability status in. Example: "patch_required".
- `appsVulnerabilityStatusesNin` [query, array] — Apps vulnerability status nin. Example: "patch_required".
- `locationIds` [query, array] — Include only Agents reporting these locations. Example: "225494730938493804,225494730938493915".
- `locationIdsNin` [query, array] — Do not include only Agents reporting these locations. Example: "225494730938493804,225494730938493915".
- `installerTypes` [query, array] — Include only Agents installed with these package types. Example: ".msi".
- `installerTypesNin` [query, array] — Exclude Agents installed with these package types. Example: ".msi".
- `operationalStates` [query, array] — Agent operational state
- `operationalStatesNin` [query, array] — Do not include these Agent operational states
- `remoteProfilingStates` [query, array] — Agent remote profiling state
- `remoteProfilingStatesNin` [query, array] — Do not include these Agent remote profiling states
- `rangerStatuses` [query, array] — Status of Network Discovery. Example: "NotApplicable".
- `rangerStatusesNin` [query, array] — Do not include these Network Scanner Statuses. Example: "NotApplicable".
- `rangerStatus` [query, string] (enum: NotApplicable, Enabled, Disabled) — [DEPRECATED] Use rangerStatuses. Example: "NotApplicable".
- `threatRebootRequired` [query, array] — Has at least one threat with at least one mitigation action pending reboot to succeed
- `networkQuarantineEnabled` [query, array] — The agents supports Network Quarantine Control and its enabled for the agent's group
- `firewallEnabled` [query, array] — The agents supports Firewall Control and it is enabled for the agent's group
- `locationEnabled` [query, array] — The agents supports Location Awareness and it is enabled for the agent's group
- `cloudProvider` [query, array] — Agents from which cloud provider
- `cloudProviderNin` [query, array] — Exclude Agents from these cloud provider
- `tagsData` [query, string] — Filter agents by their assigned tags. Given in form of a JSON where each key represents a tag key, and each value represents a list of string values to filter by. To filter by unassigned tag values, use __nin suffix in the tag key. Example: "{"key1": ["value1_1", "value1_2"], "key2__nin": ["value2"]}".
- `hasTags` [query, boolean] — Include only Agents that have any tags assigned if True, or none if False
- `isAdConnector` [query, array] — The agents that are ADConnectors if True, or not if False
- `isHyperAutomate` [query, array] — The agents has Hyper Automate PNA enabled if True, or not if False
- `activeProtection` [query, array] — Included agent active protections. Example: "edr,idr".
- `containerizedWorkloadCounts` [query, object] — Containerized workload counts
- `hasContainerizedWorkload` [query, array] — Indicates whether the agent protects containerized workload at the moment
- `pacFileUsage` [query, array] — Include only Agents using PAC file for proxy configuration. Accepts true, false, or none (for not reported).
- `proxyMethod` [query, array] — Include only Agents using these proxy methods. Example: "None,Auto,System,User,Custom".
- `proxyMethodNin` [query, array] — Exclude Agents using these proxy methods. Example: "None,Auto,System,User,Custom".
- `console` [query, array] — Include only Agents using console proxy. Accepts true, false, or none (for not reported).
- `deepVisibility` [query, array] — Include only Agents using deep visibility proxy. Accepts true, false, or none (for not reported).
- `externalIp__contains` [query, array] — Free-text filter by visible IP (supports multiple values). Example: "205,127.0".
- `computerName__contains` [query, array] — Free-text filter by computer name (supports multiple values). Example: "john-office,WIN".
- `networkInterfaceInet__contains` [query, array] — Free-text filter by local IP (supports multiple values). Example: "192,10.0.0".
- `networkInterfacePhysical__contains` [query, array] — Free-text filter by MAC address (supports multiple values). Example: "aa:0f,:41:".
- `networkInterfaceGatewayMacAddress__contains` [query, array] — Free-text filter by Gateway MAC address (supports multiple values). Example: "aa:0f,:41:".
- `lastLoggedInUserName__contains` [query, array] — Free-text filter by username (supports multiple values). Example: "admin,johnd1".
- `osVersion__contains` [query, array] — Free-text filter by OS full name and version (supports multiple values). Example: "Service Pack 1".
- `adQuery__contains` [query, array] — Free-text filter by Active Directory string (supports multiple values). Example: "DC=sentinelone".
- `adUserName__contains` [query, array] — Free-text filter by Active Directory username string (supports multiple values). Example: "DC=sentinelone".
- `adUserMember__contains` [query, array] — Free-text filter by Active Directory user groups string (supports multiple values). Example: "DC=sentinelone".
- `adUserQuery__contains` [query, array] — Free-text filter by Active Directory computer name or its groups (supports multiple values). Example: "DC=sentinelone,John".
- `adComputerName__contains` [query, array] — Free-text filter by Active Directory computer name string (supports multiple values). Example: "DC=sentinelone".
- `adComputerMember__contains` [query, array] — Free-text filter by Active Directory computer groups string (supports multiple values). Example: "DC=sentinelone".
- `adComputerQuery__contains` [query, array] — Free-text filter by Active Directory computer name or its groups (supports multiple values). Example: "DC=sentinelone,Windows".
- `uuid__contains` [query, array] — Free-text filter by Agent UUID (supports multiple values). Example: "e92-01928,b055".
- `externalId__contains` [query, array] — Free-text filter by external ID (Customer ID). Example: "Tag#1 - monitoring,Performance machine".
- `awsRole__contains` [query, array] — Free-text filter by aws role(supports multiple values)
- `awsSecurityGroups__contains` [query, array] — Free-text filter by aws securityGroups(supports multiple values)
- `awsSubnetIds__contains` [query, array] — Free-text filter by aws subnet ids (supports multiple values)
- `agentNamespace__contains` [query, array] — Free-text filter by agent namespace (supports multiple values)
- `agentPodName__contains` [query, array] — Free-text filter by agent pod name (supports multiple values)
- `azureResourceGroup__contains` [query, array] — Free-text filter by azure resource group(supports multiple values)
- `cloudAccount__contains` [query, array] — Free-text filter by cloud account (supports multiple values)
- `cloudImage__contains` [query, array] — Free-text filter by cloud image (supports multiple values)
- `cloudInstanceId__contains` [query, array] — Free-text filter by cloud instance id(supports multiple values)
- `cloudInstanceSize__contains` [query, array] — Free-text filter by cloud instance size(supports multiple values)
- `cloudLocation__contains` [query, array] — Free-text filter by cloud location (supports multiple values)
- `cloudNetwork__contains` [query, array] — Free-text filter by cloud network (supports multiple values)
- `cloudTags__contains` [query, array] — Free-text filter by cloud tags (supports multiple values)
- `clusterName__contains` [query, array] — Free-text filter by cluster name (supports multiple values)
- `gcpServiceAccount__contains` [query, array] — Free-text filter by gcp service account (supports multiple values)
- `k8sNodeLabels__contains` [query, array] — Free-text filter by K8s node labels (supports multiple values)
- `k8sNodeName__contains` [query, array] — Free-text filter by K8s node name (supports multiple values)
- `k8sType__contains` [query, array] — Free-text filter by K8s type(supports multiple values)
- `k8sVersion__contains` [query, array] — Free-text filter by K8s version (supports multiple values)
- `liveUpdateId__contains` [query, array] — Free-text filter by live update ID (supports multiple values)
- `serialNumber__contains` [query, array] — Free-text filter by Serial Number (supports multiple values)
- `cpuId__contains` [query, array] — Free-text filter by CPU name (supports multiple values). Example: "Intel,AMD".
- `ecsType__contains` [query, array] — Free-text filter by ECS type
- `ecsVersion__contains` [query, array] — Free-text filter by ECS version
- `ecsClusterName__contains` [query, array] — Free-text filter by ECS cluster name
- `ecsTaskArn__contains` [query, array] — Free-text filter by ECS task arn
- `ecsTaskAvailabilityZone__contains` [query, array] — Free-text filter by ECS task availability zone
- `ecsServiceName__contains` [query, array] — Free-text filter by ECS service name
- `ecsServiceArn__contains` [query, array] — Free-text filter by ECS service arn
- `ecsTaskDefinitionFamily__contains` [query, array] — Free-text filter by ECS task definition family
- `ecsTaskDefinitionRevision__contains` [query, array] — Free-text filter by ECS task definition revision
- `ecsTaskDefinitionArn__contains` [query, array] — Free-text filter by ECS task definition arn
- `isDecommissioned` [query, array] — Include active, decommissioned or both. Example: "True,False".
- `isUninstalled` [query, array] — Include installed, uninstalled or both. Example: "True,False".
- `computerNameOrUuid__contains` [query, array] — Free-text filter by computer name or uuid (supports multiple values)
- `ids` [query, array] — Included Agent IDs. Example: "225494730938493804,225494730938493915".
- `idsNin` [query, array] — Excluded Agent IDs. Example: "225494730938493804,225494730938493915".
- `filterId` [query, string] — Include all Agents matching this saved filter. Example: "225494730938493804".
- `decommissionedAt__gte` [query, string] — Agents decommissioned after or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `decommissionedAt__lt` [query, string] — Agents decommissioned before this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `decommissionedAt__lte` [query, string] — Agents decommissioned before this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `decommissionedAt__gt` [query, string] — Agents decommissioned after this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `decommissionedAt__between` [query, string] — Date range for decommission time (format: <from_timestamp>-<to_timestamp>, inclusive). Example: "1514978890136-1514978650130".
- `createdAt__lt` [query, string] — Agents created before this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__lte` [query, string] — Agents created before or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__gt` [query, string] — Agents created after this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__gte` [query, string] — Agents created after or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__between` [query, string] — Date range for creation time (format: <from_timestamp>-<to_timestamp>, inclusive). Example: "1514978890136-1514978650130".
- `updatedAt__lt` [query, string] — Agents updated before this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `updatedAt__lte` [query, string] — Agents updated before or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `updatedAt__gt` [query, string] — Agents updated after this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `updatedAt__gte` [query, string] — Agents updated after or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `updatedAt__between` [query, string] — Date range for update time (format: <from_timestamp>-<to_timestamp>, inclusive). Example: "1514978890136-1514978650130".
- `computerName__like` [query, string] — Match computer name partially (substring). Example: "Lab1".
- `computerName` [query, string] — Computer name. Example: "My Office Desktop".
- `agentVersion__lt` [query, string] — Agents versions less than given version. Example: "2.5.1.1320".
- `agentVersion__lte` [query, string] — Agents versions less than or equal to given version. Example: "2.5.1.1320".
- `agentVersion__gt` [query, string] — Agents versions greater than given version. Example: "2.5.1.1320".
- `agentVersion__gte` [query, string] — Agents versions greater than or equal to given version. Example: "2.5.1.1320".
- `agentVersion__between` [query, string] — Version range for agent version (format: <from_version>-<to_version>, inclusive). Example: "2.0.0.0-2.1.5.144".
- `uuid` [query, string] — Agent's universally unique identifier. Example: "ff819e70af13be381993075eb0ce5f2f6de05be2".
- `uuids` [query, array] — A list of included UUIDs. Example: "ff819e70af13be381993075eb0ce5f2f6de05b11,ff819e70af13be381993075eb0ce5f2f6de05c22".
- `scanStatus` [query, string] (enum: none, started, aborted, finished) — Scan status. Example: "none".
- `threatMitigationStatus` [query, string] (enum: mitigated, blocked, active, suspicious, pending, suspicious_resolved) — Include only Agents that have threats with this mitigation status. Example: "mitigated".
- `threatResolved` [query, boolean] — Include only Agents with at least one resolved threat
- `threatHidden` [query, boolean] — Include only Agents with at least one hidden threat
- `threatContentHash` [query, string] — Include only Agents that have at least one threat with this content hash. Example: "cf23df2207d99a74fbe169e3eba035e633b65d94".
- `threatCreatedAt__lt` [query, string] — Agents with threats reported before this time. Example: "2018-02-27T04:49:26.257525Z".
- `threatCreatedAt__lte` [query, string] — Agents with threats reported before or at this time. Example: "2018-02-27T04:49:26.257525Z".
- `threatCreatedAt__gt` [query, string] — Agents with threats reported after this time. Example: "2018-02-27T04:49:26.257525Z".
- `threatCreatedAt__gte` [query, string] — Agents with threats reported after or at this time. Example: "2018-02-27T04:49:26.257525Z".
- `threatCreatedAt__between` [query, string] — Agents with threats reported in a date range (format: <from_timestamp>-<to_timestamp>, inclusive). Example: "1514978764288-1514978999999".
- `activeThreats` [query, integer] — Include Agents with this amount of active threats. Example: "3".
- `activeThreats__gt` [query, integer] — Include Agents with at least this amount of active threats. Example: "5".
- `mitigationMode` [query, string] (enum: detect, protect) — Agent mitigation mode policy. Example: "detect".
- `mitigationModeSuspicious` [query, string] (enum: detect, protect) — Mitigation mode policy for suspicious activity. Example: "detect".
- `registeredAt__lt` [query, string] — Agents registered before this time. Example: "2018-02-27T04:49:26.257525Z".
- `registeredAt__lte` [query, string] — Agents registered before or at this time. Example: "2018-02-27T04:49:26.257525Z".
- `registeredAt__gt` [query, string] — Agents registered after this time. Example: "2018-02-27T04:49:26.257525Z".
- `registeredAt__gte` [query, string] — Agents registered after or at this time. Example: "2018-02-27T04:49:26.257525Z".
- `lastActiveDate__lt` [query, string] — Agents last active before this time. Example: "2018-02-27T04:49:26.257525Z".
- `lastActiveDate__lte` [query, string] — Agents last active before or at this time. Example: "2018-02-27T04:49:26.257525Z".
- `lastActiveDate__gt` [query, string] — Agents last active after this time. Example: "2018-02-27T04:49:26.257525Z".
- `lastActiveDate__gte` [query, string] — Agents last active after or at this time. Example: "2018-02-27T04:49:26.257525Z".
- `lastSuccessfulScanDate__lt` [query, string] — Agents last successful full disk scan before this time. Example: "2018-02-27T04:49:26.257525Z".
- `lastSuccessfulScanDate__lte` [query, string] — Agents last successful full disk scan before or at this time. Example: "2018-02-27T04:49:26.257525Z".
- `lastSuccessfulScanDate__gt` [query, string] — Agents last successful full disk scan after this time. Example: "2018-02-27T04:49:26.257525Z".
- `lastSuccessfulScanDate__gte` [query, string] — Agents last successful full disk scan after or at this time. Example: "2018-02-27T04:49:26.257525Z".
- `coreCount__lt` [query, integer] — CPU cores (less than)
- `coreCount__lte` [query, integer] — CPU cores (less than or equal)
- `coreCount__gt` [query, integer] — CPU cores (more than)
- `coreCount__gte` [query, integer] — CPU cores (more than or equal)
- `cpuCount__lt` [query, integer] — Number of CPUs (less than)
- `cpuCount__lte` [query, integer] — Number of CPUs (less than or equal)
- `cpuCount__gt` [query, integer] — Number of CPUs (more than)
- `cpuCount__gte` [query, integer] — Number of CPUs (more than or equal)
- `totalMemory__lt` [query, integer] — Memory size (MB, less than)
- `totalMemory__lte` [query, integer] — Memory size (MB, less than or equal)
- `totalMemory__gt` [query, integer] — Memory size (MB, more than)
- `totalMemory__gte` [query, integer] — Memory size (MB, more than or equal)
- `migrationStatus` [query, string] (enum: N/A, Pending, Migrated, Failed) — Migration status. Example: "N/A".
- `gatewayIp` [query, string] — Gateway ip. Example: "192.168.0.1".
- `csvFilterId` [query, string] — The ID of the CSV file to filter by. Example: "225494730938493804".
- `rsoLevel` [query, string] (enum: none, pro, ars) — Supported Remote Script Orchestration level. Example: "none".
- `remoteOpsForensicsSupported` [query, boolean] — Include only agents that has Remote Ops Forensicsfeature supported
- `windowsOsRevision__gte` [query, integer] — Agents os revision than or equal to given version
- `windowsOsRevision__lte` [query, integer] — Agents os revision lower than or equal to given version
- `rsoLevels` [query, array] — A list of included rso_levels. Example: "pro,ars".

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `GET /web/api/v2.1/export/agents-light`
**Export Agents - Light**
`operationId`: `_web_api_export_agents-light_get`

Export Agent data to a CSV, for Agents that match the filter. This command exports up to 300000 items (each datum is an item).

Required permissions: `Endpoints.view`

Parameters:
- `siteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `accountIds` [query, array] — List of Account IDs to filter by. Example: "225494730938493804,225494730938493915".
- `groupIds` [query, array] — List of Group IDs to filter by. Example: "225494730938493804,225494730938493915".
- `filteredGroupIds` [query, array] — List of Group IDs to filter by. Example: "225494730938493804,225494730938493915".
- `filteredSiteIds` [query, array] — List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".
- `registeredAt__between` [query, string] — Date range for first registration time (format: <from_timestamp>-<to_timestamp>, inclusive). Example: "1514978764288-1514978999999".
- `lastActiveDate__between` [query, string] — Date range for last active date(format: <from_timestamp>-<to_timestamp>, inclusive). Example: "1514978764288-1514978999999".
- `lastSuccessfulScanDate__between` [query, string] — Date range for last successful full disk scan(format: <from_timestamp>-<to_timestamp>, inclusive). Example: "1514978764288-1514978999999".
- `isActive` [query, array] — Include only active Agents
- `isPendingUninstall` [query, array] — Include only Agents with pending uninstall requests
- `infected` [query, boolean] — Include only Agents with at least one active threat
- `isUpToDate` [query, array] — Include only Agents with updated software
- `query` [query, string] — A free-text search term, will match applicable attributes (sub-string match). Note: Device's physical addresses will be matched if they start with the search term only (no match if they contain the term). Example: "Linux".
- `agentVersions` [query, array] — Agent versions to include. Example: "2.0.0.0,2.1.5.144".
- `agentVersionsNin` [query, array] — Agent versions not to include. Example: "2.0.0.0,2.1.5.144".
- `rangerVersions` [query, array] — Network Scanner versions to include. Example: "2.0.0.0,2.1.5.144".
- `rangerVersionsNin` [query, array] — Network Scanner versions not to include. Example: "2.0.0.0,2.1.5.144".
- `osArch` [query, string] (enum: 32 bit, 64 bit, ARM64) — OS architecture. Example: "32 bit".
- `osArches` [query, array] — OS architectures to include. Example: "32 bit,64 bit".
- `osArchesNin` [query, array] — OS architectures not to include. Example: "32 bit,64 bit".
- `osTypes` [query, array] — Included OS types. Example: "macos".
- `osTypesNin` [query, array] — Not included OS types. Example: "macos".
- `scanStatuses` [query, array] — Included scan statuses. Example: "started,aborted".
- `scanStatusesNin` [query, array] — Not included scan statuses. Example: "started,aborted".
- `machineTypes` [query, array] — Included machine types. Example: "laptop,desktop".
- `machineTypesNin` [query, array] — Not included machine types. Example: "laptop,desktop".
- `storageTypes` [query, array] — Included storage types. Example: "NetApp,Dell,S3".
- `storageTypesNin` [query, array] — Excluded storage types. Example: "NetApp,Dell,S3".
- `networkStatuses` [query, array] — Included network statuses. Example: "connected,connecting".
- `networkStatusesNin` [query, array] — Included network statuses. Example: "connected,connecting".
- `domains` [query, array] — Included network domains. Example: "mybusiness.net,workgroup".
- `domainsNin` [query, array] — Not included network domains. Example: "mybusiness.net,workgroup".
- `encryptedApplications` [query, array] — Disk encryption status
- `totalMemory__between` [query, string] — Total memory range (GB, inclusive). Example: "4-8".
- `coreCount__between` [query, string] — Possible number of CPU cores (inclusive). Example: "2-8".
- `cpuCount__between` [query, string] — Possible number of CPU cores (inclusive). Example: "2-8".
- `userActionsNeeded` [query, array] — Included pending user actions. Example: "reboot_needed,upgrade_needed".
- `missingPermissions` [query, array] — Included missing permissions. Example: "user_action_needed_bluetooth_per,user_action_needed_fda_helper".
- `userActionsNeededNin` [query, array] — Excluded pending user actions. Example: "reboot_needed,upgrade_needed".
- `missingPermissionsNin` [query, array] — Excluded missing permissions. Example: "user_action_needed_bluetooth_per,user_action_needed_fda_helper".
- `adQuery` [query, string] — An Active Directory query string. Example: "CN=Managers,DC=sentinelone,DC=com".
- `hasLocalConfiguration` [query, boolean] — Agent has a local configuration set
- `consoleMigrationStatuses` [query, array] — Migration status in. Example: "N/A".
- `consoleMigrationStatusesNin` [query, array] — Migration status nin. Example: "N/A".
- `appsVulnerabilityStatuses` [query, array] — Apps vulnerability status in. Example: "patch_required".
- `appsVulnerabilityStatusesNin` [query, array] — Apps vulnerability status nin. Example: "patch_required".
- `locationIds` [query, array] — Include only Agents reporting these locations. Example: "225494730938493804,225494730938493915".
- `locationIdsNin` [query, array] — Do not include only Agents reporting these locations. Example: "225494730938493804,225494730938493915".
- `installerTypes` [query, array] — Include only Agents installed with these package types. Example: ".msi".
- `installerTypesNin` [query, array] — Exclude Agents installed with these package types. Example: ".msi".
- `operationalStates` [query, array] — Agent operational state
- `operationalStatesNin` [query, array] — Do not include these Agent operational states
- `remoteProfilingStates` [query, array] — Agent remote profiling state
- `remoteProfilingStatesNin` [query, array] — Do not include these Agent remote profiling states
- `rangerStatuses` [query, array] — Status of Network Discovery. Example: "NotApplicable".
- `rangerStatusesNin` [query, array] — Do not include these Network Scanner Statuses. Example: "NotApplicable".
- `rangerStatus` [query, string] (enum: NotApplicable, Enabled, Disabled) — [DEPRECATED] Use rangerStatuses. Example: "NotApplicable".
- `threatRebootRequired` [query, array] — Has at least one threat with at least one mitigation action pending reboot to succeed
- `networkQuarantineEnabled` [query, array] — The agents supports Network Quarantine Control and its enabled for the agent's group
- `firewallEnabled` [query, array] — The agents supports Firewall Control and it is enabled for the agent's group
- `locationEnabled` [query, array] — The agents supports Location Awareness and it is enabled for the agent's group
- `cloudProvider` [query, array] — Agents from which cloud provider
- `cloudProviderNin` [query, array] — Exclude Agents from these cloud provider
- `tagsData` [query, string] — Filter agents by their assigned tags. Given in form of a JSON where each key represents a tag key, and each value represents a list of string values to filter by. To filter by unassigned tag values, use __nin suffix in the tag key. Example: "{"key1": ["value1_1", "value1_2"], "key2__nin": ["value2"]}".
- `hasTags` [query, boolean] — Include only Agents that have any tags assigned if True, or none if False
- `isAdConnector` [query, array] — The agents that are ADConnectors if True, or not if False
- `isHyperAutomate` [query, array] — The agents has Hyper Automate PNA enabled if True, or not if False
- `activeProtection` [query, array] — Included agent active protections. Example: "edr,idr".
- `containerizedWorkloadCounts` [query, object] — Containerized workload counts
- `hasContainerizedWorkload` [query, array] — Indicates whether the agent protects containerized workload at the moment
- `pacFileUsage` [query, array] — Include only Agents using PAC file for proxy configuration. Accepts true, false, or none (for not reported).
- `proxyMethod` [query, array] — Include only Agents using these proxy methods. Example: "None,Auto,System,User,Custom".
- `proxyMethodNin` [query, array] — Exclude Agents using these proxy methods. Example: "None,Auto,System,User,Custom".
- `console` [query, array] — Include only Agents using console proxy. Accepts true, false, or none (for not reported).
- `deepVisibility` [query, array] — Include only Agents using deep visibility proxy. Accepts true, false, or none (for not reported).
- `externalIp__contains` [query, array] — Free-text filter by visible IP (supports multiple values). Example: "205,127.0".
- `computerName__contains` [query, array] — Free-text filter by computer name (supports multiple values). Example: "john-office,WIN".
- `networkInterfaceInet__contains` [query, array] — Free-text filter by local IP (supports multiple values). Example: "192,10.0.0".
- `networkInterfacePhysical__contains` [query, array] — Free-text filter by MAC address (supports multiple values). Example: "aa:0f,:41:".
- `networkInterfaceGatewayMacAddress__contains` [query, array] — Free-text filter by Gateway MAC address (supports multiple values). Example: "aa:0f,:41:".
- `lastLoggedInUserName__contains` [query, array] — Free-text filter by username (supports multiple values). Example: "admin,johnd1".
- `osVersion__contains` [query, array] — Free-text filter by OS full name and version (supports multiple values). Example: "Service Pack 1".
- `adQuery__contains` [query, array] — Free-text filter by Active Directory string (supports multiple values). Example: "DC=sentinelone".
- `adUserName__contains` [query, array] — Free-text filter by Active Directory username string (supports multiple values). Example: "DC=sentinelone".
- `adUserMember__contains` [query, array] — Free-text filter by Active Directory user groups string (supports multiple values). Example: "DC=sentinelone".
- `adUserQuery__contains` [query, array] — Free-text filter by Active Directory computer name or its groups (supports multiple values). Example: "DC=sentinelone,John".
- `adComputerName__contains` [query, array] — Free-text filter by Active Directory computer name string (supports multiple values). Example: "DC=sentinelone".
- `adComputerMember__contains` [query, array] — Free-text filter by Active Directory computer groups string (supports multiple values). Example: "DC=sentinelone".
- `adComputerQuery__contains` [query, array] — Free-text filter by Active Directory computer name or its groups (supports multiple values). Example: "DC=sentinelone,Windows".
- `uuid__contains` [query, array] — Free-text filter by Agent UUID (supports multiple values). Example: "e92-01928,b055".
- `externalId__contains` [query, array] — Free-text filter by external ID (Customer ID). Example: "Tag#1 - monitoring,Performance machine".
- `awsRole__contains` [query, array] — Free-text filter by aws role(supports multiple values)
- `awsSecurityGroups__contains` [query, array] — Free-text filter by aws securityGroups(supports multiple values)
- `awsSubnetIds__contains` [query, array] — Free-text filter by aws subnet ids (supports multiple values)
- `agentNamespace__contains` [query, array] — Free-text filter by agent namespace (supports multiple values)
- `agentPodName__contains` [query, array] — Free-text filter by agent pod name (supports multiple values)
- `azureResourceGroup__contains` [query, array] — Free-text filter by azure resource group(supports multiple values)
- `cloudAccount__contains` [query, array] — Free-text filter by cloud account (supports multiple values)
- `cloudImage__contains` [query, array] — Free-text filter by cloud image (supports multiple values)
- `cloudInstanceId__contains` [query, array] — Free-text filter by cloud instance id(supports multiple values)
- `cloudInstanceSize__contains` [query, array] — Free-text filter by cloud instance size(supports multiple values)
- `cloudLocation__contains` [query, array] — Free-text filter by cloud location (supports multiple values)
- `cloudNetwork__contains` [query, array] — Free-text filter by cloud network (supports multiple values)
- `cloudTags__contains` [query, array] — Free-text filter by cloud tags (supports multiple values)
- `clusterName__contains` [query, array] — Free-text filter by cluster name (supports multiple values)
- `gcpServiceAccount__contains` [query, array] — Free-text filter by gcp service account (supports multiple values)
- `k8sNodeLabels__contains` [query, array] — Free-text filter by K8s node labels (supports multiple values)
- `k8sNodeName__contains` [query, array] — Free-text filter by K8s node name (supports multiple values)
- `k8sType__contains` [query, array] — Free-text filter by K8s type(supports multiple values)
- `k8sVersion__contains` [query, array] — Free-text filter by K8s version (supports multiple values)
- `liveUpdateId__contains` [query, array] — Free-text filter by live update ID (supports multiple values)
- `serialNumber__contains` [query, array] — Free-text filter by Serial Number (supports multiple values)
- `cpuId__contains` [query, array] — Free-text filter by CPU name (supports multiple values). Example: "Intel,AMD".
- `ecsType__contains` [query, array] — Free-text filter by ECS type
- `ecsVersion__contains` [query, array] — Free-text filter by ECS version
- `ecsClusterName__contains` [query, array] — Free-text filter by ECS cluster name
- `ecsTaskArn__contains` [query, array] — Free-text filter by ECS task arn
- `ecsTaskAvailabilityZone__contains` [query, array] — Free-text filter by ECS task availability zone
- `ecsServiceName__contains` [query, array] — Free-text filter by ECS service name
- `ecsServiceArn__contains` [query, array] — Free-text filter by ECS service arn
- `ecsTaskDefinitionFamily__contains` [query, array] — Free-text filter by ECS task definition family
- `ecsTaskDefinitionRevision__contains` [query, array] — Free-text filter by ECS task definition revision
- `ecsTaskDefinitionArn__contains` [query, array] — Free-text filter by ECS task definition arn
- `isDecommissioned` [query, array] — Include active, decommissioned or both. Example: "True,False".
- `isUninstalled` [query, array] — Include installed, uninstalled or both. Example: "True,False".
- `computerNameOrUuid__contains` [query, array] — Free-text filter by computer name or uuid (supports multiple values)
- `ids` [query, array] — Included Agent IDs. Example: "225494730938493804,225494730938493915".
- `idsNin` [query, array] — Excluded Agent IDs. Example: "225494730938493804,225494730938493915".
- `filterId` [query, string] — Include all Agents matching this saved filter. Example: "225494730938493804".
- `decommissionedAt__gte` [query, string] — Agents decommissioned after or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `decommissionedAt__lt` [query, string] — Agents decommissioned before this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `decommissionedAt__lte` [query, string] — Agents decommissioned before this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `decommissionedAt__gt` [query, string] — Agents decommissioned after this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `decommissionedAt__between` [query, string] — Date range for decommission time (format: <from_timestamp>-<to_timestamp>, inclusive). Example: "1514978890136-1514978650130".
- `createdAt__lt` [query, string] — Agents created before this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__lte` [query, string] — Agents created before or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__gt` [query, string] — Agents created after this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__gte` [query, string] — Agents created after or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `createdAt__between` [query, string] — Date range for creation time (format: <from_timestamp>-<to_timestamp>, inclusive). Example: "1514978890136-1514978650130".
- `updatedAt__lt` [query, string] — Agents updated before this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `updatedAt__lte` [query, string] — Agents updated before or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `updatedAt__gt` [query, string] — Agents updated after this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `updatedAt__gte` [query, string] — Agents updated after or at this timestamp. Example: "2018-02-27T04:49:26.257525Z".
- `updatedAt__between` [query, string] — Date range for update time (format: <from_timestamp>-<to_timestamp>, inclusive). Example: "1514978890136-1514978650130".
- `computerName__like` [query, string] — Match computer name partially (substring). Example: "Lab1".
- `computerName` [query, string] — Computer name. Example: "My Office Desktop".
- `agentVersion__lt` [query, string] — Agents versions less than given version. Example: "2.5.1.1320".
- `agentVersion__lte` [query, string] — Agents versions less than or equal to given version. Example: "2.5.1.1320".
- `agentVersion__gt` [query, string] — Agents versions greater than given version. Example: "2.5.1.1320".
- `agentVersion__gte` [query, string] — Agents versions greater than or equal to given version. Example: "2.5.1.1320".
- `agentVersion__between` [query, string] — Version range for agent version (format: <from_version>-<to_version>, inclusive). Example: "2.0.0.0-2.1.5.144".
- `uuid` [query, string] — Agent's universally unique identifier. Example: "ff819e70af13be381993075eb0ce5f2f6de05be2".
- `uuids` [query, array] — A list of included UUIDs. Example: "ff819e70af13be381993075eb0ce5f2f6de05b11,ff819e70af13be381993075eb0ce5f2f6de05c22".
- `scanStatus` [query, string] (enum: none, started, aborted, finished) — Scan status. Example: "none".
- `threatMitigationStatus` [query, string] (enum: mitigated, blocked, active, suspicious, pending, suspicious_resolved) — Include only Agents that have threats with this mitigation status. Example: "mitigated".
- `threatResolved` [query, boolean] — Include only Agents with at least one resolved threat
- `threatHidden` [query, boolean] — Include only Agents with at least one hidden threat
- `threatContentHash` [query, string] — Include only Agents that have at least one threat with this content hash. Example: "cf23df2207d99a74fbe169e3eba035e633b65d94".
- `threatCreatedAt__lt` [query, string] — Agents with threats reported before this time. Example: "2018-02-27T04:49:26.257525Z".
- `threatCreatedAt__lte` [query, string] — Agents with threats reported before or at this time. Example: "2018-02-27T04:49:26.257525Z".
- `threatCreatedAt__gt` [query, string] — Agents with threats reported after this time. Example: "2018-02-27T04:49:26.257525Z".
- `threatCreatedAt__gte` [query, string] — Agents with threats reported after or at this time. Example: "2018-02-27T04:49:26.257525Z".
- `threatCreatedAt__between` [query, string] — Agents with threats reported in a date range (format: <from_timestamp>-<to_timestamp>, inclusive). Example: "1514978764288-1514978999999".
- `activeThreats` [query, integer] — Include Agents with this amount of active threats. Example: "3".
- `activeThreats__gt` [query, integer] — Include Agents with at least this amount of active threats. Example: "5".
- `mitigationMode` [query, string] (enum: detect, protect) — Agent mitigation mode policy. Example: "detect".
- `mitigationModeSuspicious` [query, string] (enum: detect, protect) — Mitigation mode policy for suspicious activity. Example: "detect".
- `registeredAt__lt` [query, string] — Agents registered before this time. Example: "2018-02-27T04:49:26.257525Z".
- `registeredAt__lte` [query, string] — Agents registered before or at this time. Example: "2018-02-27T04:49:26.257525Z".
- `registeredAt__gt` [query, string] — Agents registered after this time. Example: "2018-02-27T04:49:26.257525Z".
- `registeredAt__gte` [query, string] — Agents registered after or at this time. Example: "2018-02-27T04:49:26.257525Z".
- `lastActiveDate__lt` [query, string] — Agents last active before this time. Example: "2018-02-27T04:49:26.257525Z".
- `lastActiveDate__lte` [query, string] — Agents last active before or at this time. Example: "2018-02-27T04:49:26.257525Z".
- `lastActiveDate__gt` [query, string] — Agents last active after this time. Example: "2018-02-27T04:49:26.257525Z".
- `lastActiveDate__gte` [query, string] — Agents last active after or at this time. Example: "2018-02-27T04:49:26.257525Z".
- `lastSuccessfulScanDate__lt` [query, string] — Agents last successful full disk scan before this time. Example: "2018-02-27T04:49:26.257525Z".
- `lastSuccessfulScanDate__lte` [query, string] — Agents last successful full disk scan before or at this time. Example: "2018-02-27T04:49:26.257525Z".
- `lastSuccessfulScanDate__gt` [query, string] — Agents last successful full disk scan after this time. Example: "2018-02-27T04:49:26.257525Z".
- `lastSuccessfulScanDate__gte` [query, string] — Agents last successful full disk scan after or at this time. Example: "2018-02-27T04:49:26.257525Z".
- `coreCount__lt` [query, integer] — CPU cores (less than)
- `coreCount__lte` [query, integer] — CPU cores (less than or equal)
- `coreCount__gt` [query, integer] — CPU cores (more than)
- `coreCount__gte` [query, integer] — CPU cores (more than or equal)
- `cpuCount__lt` [query, integer] — Number of CPUs (less than)
- `cpuCount__lte` [query, integer] — Number of CPUs (less than or equal)
- `cpuCount__gt` [query, integer] — Number of CPUs (more than)
- `cpuCount__gte` [query, integer] — Number of CPUs (more than or equal)
- `totalMemory__lt` [query, integer] — Memory size (MB, less than)
- `totalMemory__lte` [query, integer] — Memory size (MB, less than or equal)
- `totalMemory__gt` [query, integer] — Memory size (MB, more than)
- `totalMemory__gte` [query, integer] — Memory size (MB, more than or equal)
- `migrationStatus` [query, string] (enum: N/A, Pending, Migrated, Failed) — Migration status. Example: "N/A".
- `gatewayIp` [query, string] — Gateway ip. Example: "192.168.0.1".
- `csvFilterId` [query, string] — The ID of the CSV file to filter by. Example: "225494730938493804".
- `rsoLevel` [query, string] (enum: none, pro, ars) — Supported Remote Script Orchestration level. Example: "none".
- `remoteOpsForensicsSupported` [query, boolean] — Include only agents that has Remote Ops Forensicsfeature supported
- `windowsOsRevision__gte` [query, integer] — Agents os revision than or equal to given version
- `windowsOsRevision__lte` [query, integer] — Agents os revision lower than or equal to given version
- `rsoLevels` [query, array] — A list of included rso_levels. Example: "pro,ars".

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/export/agents-passphrases`
**Export Agents - Passphrases**
`operationId`: `_web_api_export_agents-passphrases_post`

Export Agent passphrases to a CSV, for Agents that match the filter. This command exports up to 50000 items (each datum is an item).

Required permissions: `Endpoints.showPassphrase`

Parameters:
- `body` [body, agents.schemas_ExportAgentsPassphrasesSchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.
