# Agent Actions

38 endpoints.

## `POST /web/api/v2.1/agents/actions/abort-scan`
**Abort Scan**
`operationId`: `_web_api_agents_actions_abort-scan_post`

Immediately stop a Full Disk Scan on all Agents that match the filter. See "Initiate scan" to learn more about Full Disk Scan.

Required permissions: `Endpoints.abortScan`

Parameters:
- `body` [body, agents.schemas_AgentsActionSchema] — 

Responses: 403 User has insufficient permissions to perform the requested a, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/agents/actions/approve-stateless-upgrade`
**Approve Stateless Upgrades**
`operationId`: `_web_api_agents_actions_approve-stateless-upgrade_post`

Approve stateless upgrade for agents

Required permissions: `Endpoints.uninstall`

Parameters:
- `body` [body, agents.schemas_AgentsCleaninstallerSchema] — 

Responses: 403 Insufficient permissions, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/agents/actions/approve-uninstall`
**Approve Uninstall**
`operationId`: `_web_api_agents_actions_approve-uninstall_post`

If a user tries to uninstall the SentinelOne Agent from an endpoint, an uninstall request is sent to the Management. You must approve the request. <BR>After you approve a request, users see a message that the request was approved. They can restart to complete the Agent uninstall.<BR>We recommend that you do not approve these requests until you understand the reason for the request, you agree with the request, and you have alternative security for the endpoint until you install the Agent again.<BR>This command will approve pending uninstall requests for all Agents that match the filter.

Required permissions: `Endpoints.approveUninstall`

Parameters:
- `body` [body, agents.schemas_AgentsActionSchema] — 

Responses: 403 User has insufficient permissions to perform the requested a, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/agents/actions/broadcast`
**Broadcast Message**
`operationId`: `_web_api_agents_actions_broadcast_post`

You can send a message through the Agents that users can see. <BR>This is useful for endpoints that have human users. This command is supported on Windows and macOS endpoints (not supported on Linux). The message is sent to all endpoints that match the filter. <br>Put the message in the data parameter: "data":{"message":"<your message>"} <br>The message must be 140 characters or less.

Required permissions: `Endpoints.sendMessage`

Parameters:
- `body` [body, agents.schemas_AgentsBroadcastActionSchema] — 

Responses: 403 User has insufficient permissions to perform the requested a, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/agents/actions/can-start-remote-shell`
**Can run Remote Shell**
`operationId`: `_web_api_agents_actions_can-start-remote-shell_post`

Who can run Remote Shell? Remote Shell is a powerful way to respond remotely to events on endpoints. It lets you open full shell capabilities - PowerShell on Windows and Bash on macOS and Linux. To be able to run a Remote Shell session, SentinelOne users require permissions, which are set on different levels. It can be confusing to know who has permission. Use this command to see if a username you created for someone else or the API, or your own name, has permission.<BR> If a user does not have Remote Shell permission, how can you grant it? First, you need the Control SKU. Then, the user must have a role with permission to use Remote Shell: Admin, SOC, IR Team. The IT role does not have Remote Shell permission, and the user must be responsible for the Account, Site, or Group on whose policy Remote Shell is enabled.

Required permissions: `Endpoints.remoteShell`

Parameters:
- `body` [body, agents.schemas_AgentsActionSchema] — 

Responses: 403 Insufficient permissions, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry., 200 Success

## `POST /web/api/v2.1/agents/actions/connect`
**Connect to Network**
`operationId`: `_web_api_agents_actions_connect_post`

After you run "disconnect from network" on endpoints, analyze the issue, and mitigate threats. Use this command to reconnect to the network all endpoints that match the filter. To learn more, see "Disconnect from Network".

Required permissions: `Endpoints.reconnectToNetwork`

Parameters:
- `body` [body, agents.schemas_AgentsActionSchema] — 

Responses: 403 User has insufficient permissions to perform the requested a, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/agents/actions/decommission`
**Decommission**
`operationId`: `_web_api_agents_actions_decommission_post`

If a user is scheduled for time off, or a device is scheduled for maintenance, you can decommission the Agent. This removes the Agent from the Management Console. <BR>When the Agent communicates with the Management again, the Management recommissions it and returns it to the Console. Use this command to decommission the Agents that match the filter.

Required permissions: `Endpoints.decommission`

Parameters:
- `body` [body, agents.schemas_AgentsDangerousActionSchema] — 

Responses: 403 User has insufficient permissions to perform the requested a, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/agents/actions/disable-agent`
**Disable Agent**
`operationId`: `_web_api_agents_actions_disable-agent_post`

Use this command to disable Agents that match the filter. <BR>Disabled agents run with minimal footprint and do not detect or mitigate threats, but they maintain connectivity with the Management Console. <BR>If the command returns "Insufficient permissions", make sure you have permissions for the Account, Site, or Group and a role that allows Disable Agent (Admin, IR team or IT).<BR>In the body of this command, the data parameter set is mandatory.

Required permissions: `Endpoints.disableAgent`

Parameters:
- `body` [body, agents.schemas_AgentDisableActionSchema] — 

Responses: 403 Insufficient permissions, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/agents/actions/disconnect`
**Disconnect from Network**
`operationId`: `_web_api_agents_actions_disconnect_post`

Use this command to isolate (quarantine) endpoints from the network, if the endpoints match the filter. <BR>The Agent can communicate with the Management, which lets you analyze and mitigate threats. Best practice: For Active threats that spread, apply "Disconnect from network" immediately. In the policy, you can set this is to be automatic. When the Agent detects a high-confidence malicious threat, it will mitigate the threat (on Protect) with the action set by the policy. Then the Agent will immediately quarantine the endpoint. To make Disconnect from network automatic in an Account policy, run the "accounts/{id} command (see "Update Account") with: "networkQuarantine":true.

Required permissions: `Endpoints.disconnectFromNetwork`

Parameters:
- `body` [body, agents.schemas_AgentsDangerousActionSchema] — 

Responses: 403 User has insufficient permissions to perform the requested a, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/agents/actions/enable-agent`
**Enable Agent**
`operationId`: `_web_api_agents_actions_enable-agent_post`

Use this command to enable disabled Agents that match the filter. <BR>If the command returns "Insufficient permissions", make sure you have permissions for the Account, Site, or Group and a role that allows Disable Agent (Admin, IR team or IT).<BR>In the body of this command, the data parameter set is mandatory.

Required permissions: `Endpoints.enableAgent`

Parameters:
- `body` [body, agents.schemas_AgentEnableActionSchema] — 

Responses: 403 Insufficient permissions, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/agents/actions/fetch-firewall-rules`
**Fetch Firewall Rules**
`operationId`: `_web_api_agents_actions_fetch-firewall-rules_post`

Firewall Control is disabled at the Global level. When it is first enabled, all Sites and Groups inherit the Firewall Control policy from the Global policy. Agents have Firewall Control disabled, until they connect to a Site or Group with an enabled Firewall Control policy. <BR>After Agents get Firewall Control, if you add or change a Firewall rule, you can use this command to make sure all Agents fetch the rules, (though Agents usually update their policies every few seconds). Use the filter parameter to set which Agents will fetch the rules, if you do not want all of them to attempt it.<BR>Firewall Control requires a Control SKU.

Required permissions: `Endpoints.configureFirewallLogging`

Parameters:
- `body` [body, agents.schemas_AgentFetchFirewallRulesActionSchema] — 

Responses: 403 Insufficient permissions, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/agents/actions/fetch-installed-apps`
**Get Applications**
`operationId`: `_web_api_agents_actions_fetch-installed-apps_post`

Application Risk Management is an EA feature. Contact your partner or SentinelOne SE to learn how to join the EA program.<BR> If you have this feature, you can use this command to have all Agents update the data of the applications that are installed on the endpoint. Change the filter parameter values to send this command to matching Agents only. The updated data of installed applications shows on the Console.<BR>Some filter fields are required. <BR>Best practice: Enter all fields in the body. Click in the Body sample to get a copy of the fields in the body form.

Required permissions: `Endpoints.showApplications`

Parameters:
- `body` [body, agents.schemas_AgentsDangerousActionSchema] — 

Responses: 403 Insufficient permissions, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/agents/actions/fetch-logs`
**Fetch Logs**
`operationId`: `_web_api_agents_actions_fetch-logs_post`

Get the Agent and Endpoint logs from Agents that match the filter. <BR>The Agent logs are encrypted and only Support can read them. <BR>The Endpoint logs, for operations on the computers, laptops, or servers that have the Agent installed, are readable. The Endpoint logs are available for Windows endpoints only and require Agent version 3.6 or later. After you run this command, download the fetched logs. You can download the logs from the Console GUI or collect them. <BR>On Windows: C:\ProgramData\Sentinel\logs.<BR>On macOS: Run sudo sentinelctl logreport and get the log files on the desktop.<BR>On Linux: Run sudo /opt/sentinelone/bin/sentinelctl log generate.

Required permissions: `Endpoints.FetchLogs`

Parameters:
- `body` [body, agents.schemas_AgentFetchLogsActionSchema] — 

Responses: 403 User has insufficient permissions to perform the requested a, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/agents/actions/firewall-logging`
**Fetch Firewall Logs**
`operationId`: `_web_api_agents_actions_firewall-logging_post`

Get Firewall Control events in the local log file, written in clear text, for Firewall Control events of an endpoint with Firewall Control enabled. Enable the logs for Agents that match the filter. <BR>When Firewall Logging is enabled, you can choose if blocked traffic events go only to a local log on the endpoint (reportMgmt: false, reportLog: true), or also to Console > Activity (reportMgmt: true).<BR>Allowed traffic is not logged. <BR>Each Agent with Firewall Control Event Logging enabled keeps five log files, for a total of 100 MB maximum. The logs cycle older lines to maintain the size threshold. <BR>On Windows endpoints, the Firewall Control logs are in C:\ProgramData\Sentinel\logs\. Search for log files with "visible" in the filename.<BR>On macOS, run: sudo sentinelctl log.<BR>On Linux, run: sudo /opt/sentinelone/bin/sentinelctl log generate /output_path.<BR>Make sure the Group and Site of the Agent has Firewall Control enabled. Firewall Control requires a Control SKU.

Required permissions: `Endpoints.configureFirewallLogging`

Parameters:
- `body` [body, agents.schemas_AgentFirewallLoggingActionSchema] — 

Responses: 403 Insufficient permissions, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/agents/actions/initiate-scan`
**Initiate Scan**
`operationId`: `_web_api_agents_actions_initiate-scan_post`

Use this command to run a Full Disk Scan on Agents that match the filter. <BR>Full Disk Scan finds dormant suspicious activity, threats, and compliance violations, that are then mitigated according to the policy. It scans the local file system.<BR>Full Disk Scan does not inspect drives that require user credentials (such as network drives) or external drives. <BR>Full Disk Scan does not work on hashes. It does not check each file against the blocklist. <BR>If the Static AI determines a file is suspicious, the Agent calculates its hash and sees if the hash is in the blocklist. If a file is executed, all aspects of the process are inspected, including hash-based analysis and blocklist checks. Full Disk Scan can run when the endpoint is offline, but when it is connected to the Management, it can use the most updated Cloud data to improve detection.

Required permissions: `Endpoints.initiateScan`

Parameters:
- `body` [body, agents.schemas_AgentsActionSchema] — 

Responses: 403 User has insufficient permissions to perform the requested a, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/agents/actions/local-upgrade-authorization`
**Edit local upgrade/downgrade Site authorization**
`operationId`: `_web_api_agents_actions_local-upgrade-authorization_post`

Edit when authorization of local upgrades/downgrades expires.

Required permissions: `Local Upgrade/Downgrade Authorization.edit`

Parameters:
- `body` [body, agents.schemas_AgentLocalUpgradeAuthorizationActionSchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/agents/actions/manage-tags`
**Manage endpoint tags: add, remove, override**
`operationId`: `_web_api_agents_actions_manage-tags_post`

The "add" operation adds the given tags to the endpoints (if not already present), the "remove" operation removes the given tags from endpoints (if present), and the "override" operation overrides already present tag(s) by the same key of the given tags (if multiple same-key tags are provided, they are preserved).

Required permissions: `Endpoints.manageEndpointTags`

Parameters:
- `body` [body, agents.schemas_ManageEndpointTagsSchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/agents/actions/mark-up-to-date`
**Mark as up-to-date**
`operationId`: `_web_api_agents_actions_mark-up-to-date_post`

The value of the Agent version as "up-to-date" is a useful filter for many actions. There are scenarios where the Management does not recognize a version as latest. <BR>For example, if Agents that were sent a new version with the update-software command did not yet report to their Management. <BR>You can manually mark these Agents as up-to-date. <BR>This command is not available to users with the SOC role.

Required permissions: `Endpoints.markAsUpToDate`

Parameters:
- `body` [body, agents.schemas_AgentsActionSchema] — 

Responses: 403 User has insufficient permissions to perform the requested a, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/agents/actions/move-to-console`
**Move to Console**
`operationId`: `_web_api_agents_actions_move-to-console_post`

You can move Agents between Management Consoles. This command moves Agents to a target Console, Account, and Site, given the Console URL and Site token. <BR>You must have Global permissions for the source Console and access to the Site token of the target Site. <BR>Resolve all threats on the Agents to move before you run this command. <BR>If the Agents have local configurations, the configurations are maintained. <BR>If the new Management has different blocklists, exclusions, and other assets, these are applied the next time the Agent communicates with the Management. <BR>This command works on these Agent versions: Windows 3.0 and later, macOS 3.0 and later, Linux 3.4 and later. <BR>An Agent tries to connect to the new Management Console for 3 minutes. If the Agent cannot connect (has unresolved threats or other requirements are not met), it stays in the original Management Console. <BR>To get the Site token, run the "sites" command (see Sites list) and take the "registrationToken" value.

Required permissions: `Endpoints.migrateAgent`

Parameters:
- `body` [body, agents.schemas_AgentsMoveToConsoleSchema] — 

Responses: 403 User has insufficient permissions to perform the requested a, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/agents/actions/move-to-site`
**Move between Sites**
`operationId`: `_web_api_agents_actions_move-to-site_post`

This command requires Account or Global level access. <BR>Agents are assigned to a Site when they are first installed with a Site Token. If you have the required access level, a role with permissions (the SOC role does not allow this action), and permission for both Sites, you can move Agents from one Site to a different Site. Agents will be moved to the best matching dynamic group, or to the Default group if no dynamic group matches.

Required permissions: `Endpoints.moveToAnotherSite`

Parameters:
- `body` [body, agents.schemas_AgentsMoveToSiteSchema] — 

Responses: 403 User has insufficient permissions to perform the requested a, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/agents/actions/randomize-uuid`
**Randomize UUID**
`operationId`: `_web_api_agents_actions_randomize-uuid_post`

IMPORTANT: This action will assign a new UUID to Agents that match the filter. <BR>Run it only when instructed to do so by SentinelOne Support. <BR>If you clone the Agent on a VM or VDI without the /VDI switch, you might need to run this command. It is best to ask for Support assistance. Historical threat and Deep Visibility data will be kept in the Management, but that data will be disassociated from the Agent.

Required permissions: `Endpoints.randomizeUuid`

Parameters:
- `body` [body, agents.schemas_AgentsDangerousActionSchema] — 

Responses: 403 User has insufficient permissions to perform the requested a, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/agents/actions/ranger-disable`
**Disable Network Discovery**
`operationId`: `_web_api_agents_actions_ranger-disable_post`

Disable Network Discovery from the Agents that match the filter.<BR>Singularity Network Discovery gives full visibility of all devices connected to your network. Network Discovery scans your corporate environment to identify and manage connected devices, even those not protected by or supported by SentinelOne. When Network Discovery is enabled on an Agent, the Agent adds "Scanner" to its functionality. It is the starting point for the Network Discovery scans.<BR>Best Practice: Disable Network Discovery on endpoints that are performance-sensitive and on endpoints that often connect to non-corporate networks.

Required permissions: `Endpoints.disableRanger`

Parameters:
- `body` [body, agents.schemas_AgentsActionSchema] — 

Responses: 403 Insufficient permissions, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/agents/actions/ranger-enable`
**Enable Network Discovery**
`operationId`: `_web_api_agents_actions_ranger-enable_post`

Singularity Network Discovery gives full visibility of all devices connected to your network. Network Discovery scans your corporate environment to identify and manage connected devices, even those not protected by or supported by SentinelOne. Use this command to enable Network Discovery on Agents that match the filter. The Agent adds "Scanner" to its functionality.<BR>If the given Agent cannot support Network Discovery, or if Network Discovery is already enabled, this command does nothing.<BR>Network Discovery requires a special license. Consult with your SentinelOne SE.

Required permissions: `Endpoints.enableRanger`

Parameters:
- `body` [body, agents.schemas_AgentsActionSchema] — 

Responses: 403 Insufficient permissions, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/agents/actions/reject-uninstall`
**Reject uninstall**
`operationId`: `_web_api_agents_actions_reject-uninstall_post`

Reject uninstall requests for all Agents that match the filter. To learn more about Uninstall Requests, see "Approve Uninstall".

Required permissions: `Endpoints.rejectUninstall`

Parameters:
- `body` [body, agents.schemas_AgentsActionSchema] — 

Responses: 403 User has insufficient permissions to perform the requested a, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/agents/actions/reset-local-config`
**Reset Local Config**
`operationId`: `_web_api_agents_actions_reset-local-config_post`

SentinelCtl is the CLI for Agents. It runs commands directly on one Agent at a time. You can use this command to clear the SentinelCtl changes from all Agents that match the filter. Specific SentinelCtl settings are not cleared: <BR>On Windows: proxy address and Management token.<BR>On macOC: Management server address and server site key.

Required permissions: `Endpoints.resetLocalConfiguration`

Parameters:
- `body` [body, agents.schemas_AgentsActionSchema] — 

Responses: 403 User has insufficient permissions to perform the requested a, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/agents/actions/reset-passphrase`
**Reset Passphrases**
`operationId`: `_web_api_agents_actions_reset-passphrase_post`

Initiate an Agent passphrase reset for Agents that match the filter. <BR>This action performs eligibility checks (for example: Agent online status, required capabilities, feature toggles, and cooldown period) and returns per-agent results. <BR>Historical passphrase records are kept in the Management and are associated with the Agent.

Required permissions: `Endpoints.resetPassphrase`

Parameters:
- `body` [body, agents.schemas_AgentsResetPassphrasesSchema] — 

Responses: 403 Insufficient permissions, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/agents/actions/reset-passphrase/capability`
**Reset Passphrase Capability**
`operationId`: `_web_api_agents_actions_reset-passphrase_capability_post`

Check if a passphrase reset can be initiated for Agents that match the filter. <BR>This returns per-agent eligibility, including reasons (for example: Agent offline, feature disabled, missing required capabilities, or reset cooldown not elapsed). <BR>Use this to preview the outcome before calling "Reset Passphrases".

Required permissions: `Endpoints.resetPassphrase`

Parameters:
- `body` [body, agents.schemas_AgentsResetPassphraseCapabilitySchema] — 

Responses: 403 Insufficient permissions, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/agents/actions/restart-machine`
**Restart**
`operationId`: `_web_api_agents_actions_restart-machine_post`

Use this command to restart endpoints that have an Agent installed and that fit the filter. We recommend that you use the "broadcast" command to send a message to users of endpoints before you restart their computers.

Required permissions: `Endpoints.reboot`

Parameters:
- `body` [body, agents.schemas_AgentsDangerousActionSchema] — 

Responses: 403 User has insufficient permissions to perform the requested a, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/agents/actions/set-config`
**Set Persistent Configuration Overrides**
`operationId`: `_web_api_agents_actions_set-config_post`

This command requires Global permissions or Support.<BR>The configuration of an Agent can be changed in different ways, such as through  Policy settings, Policy Override, SentinelCtl, and changes to the LocalConfig.json file. <BR>For Windows, Policy Override overwrites policy settings, and local changes (to the file and from this command) overwrite Policy Override from the Console or with policy updates from the API. <BR>For macOS, the Policy Override has the highest priority. If you run this command and then update a Group policy that affects both Windows and macOS endpoints, the settings of this command are applied to the Windows endpoints. But the macOS endpoints will apply the settings of the policy, for settings that are duplicated in both the policy and this command.<BR>When you use this command, enter the filter values to set which Agents get the change. Then use the data parameter to set the actual changes. Get the JSON settings for data from the Agent Configuration or see the Knowledge Base: https://support.sentinelone.com/hc/en-us/articles/360022158673-sentinelctl

Required permissions: `Endpoints.configuration`

Parameters:
- `body` [body, agents.schemas_AgentsSetConfigSchema] — 

Responses: 403 User has insufficient permissions to perform the requested a, 400 Invalid user input received. See error details for further i, 200 Success, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/agents/actions/set-external-id`
**Set External ID**
`operationId`: `_web_api_agents_actions_set-external-id_post`

You can add a Customer Identifier (a string) to identify each endpoint or to tag sets of endpoints. The string shows in the Endpoint Details of the Management Console. For example, you can tag endpoints based on their state, installed applications, or endpoint status. The identifier is set on all Agents that match the filter.

Required permissions: `Endpoints.setCustomerIdentifier`

Parameters:
- `body` [body, agents.schemas_AgentsUpdateExternalIdScheme] — 

Responses: 403 User has insufficient permissions to perform the requested a, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/agents/actions/shutdown`
**Shutdown**
`operationId`: `_web_api_agents_actions_shutdown_post`

You can shut down endpoints remotely for performance, maintenance, or security. <BR>This command shuts down all endpoints that match the filter. Best Practice:  If an endpoint is infected, we recommend the "disconnect" command and not the "shutdown" command. The disconnect command secures the environment from infection while you analyze the cause and best response.<BR>If the endpoint is offline, the shutdown command is not available.

Required permissions: `Endpoints.shutDown`

Parameters:
- `body` [body, agents.schemas_AgentsDangerousActionSchema] — 

Responses: 403 User has insufficient permissions to perform the requested a, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/agents/actions/start-profiling`
**Start Remote Profiling**
`operationId`: `_web_api_agents_actions_start-profiling_post`

Use this command to start remote profiling on Agents that match the filter. <BR>Remote profiling lets you collect runtime diagnostic information for Agents on containers. <BR>If the command returns "Insufficient permissions", make sure you have permissions for the Account, Site, or Group and a role that allows Start Remote Profiling (Admin or IT).

Required permissions: `Endpoints.remoteProfiling`

Parameters:
- `body` [body, agents.schemas_AgentStartProfilingActionSchema] — 

Responses: 403 Insufficient permissions, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/agents/actions/start-remote-shell`
**Start Remote Shell**
`operationId`: `_web_api_agents_actions_start-remote-shell_post`

Remote shell is an opened websocket between the browser and the Agent, with a proprietary communication protocol that requires an unreasonable effort to run from the API. We recommend that you not use this call.<BR><BR> If you do want to use this API, you must have permission through your user role (not IT or Viewer), specific Remote Shell permissions, 2FA enabled on the username with a valid code in the twoFaCode parameter, valid code in the twoFaCode parameter, and permissions for the Account, Site, or Group on whose policy Remote Shell is enabled. To make sure you have permission to start Remote Shell, use the "can-start-remote-shell" command. Best practice: Use the UUID filter to run Remote Shell on a specific endpoint. To get the UUID, run the "agents" command. <BR>In the body of this command, the data parameter set is mandatory. <BR>Remote Shell requires a Control SKU.

Required permissions: `Endpoints.remoteShell`

Parameters:
- `body` [body, agents.schemas_StartRemoteShellSchema] — 

Responses: 403 Insufficient permissions, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry., 200 Success

## `POST /web/api/v2.1/agents/actions/stop-profiling`
**Stop Remote Profiling**
`operationId`: `_web_api_agents_actions_stop-profiling_post`

Use this command to stop remote profiling on Agents that match the filter. <BR>If the command returns "Insufficient permissions", make sure you have permissions for the Account, Site, or Group and a role that allows Stop Remote Profiling (Admin or IT).

Required permissions: `Endpoints.remoteProfiling`

Parameters:
- `body` [body, agents.schemas_AgentStopProfilingActionSchema] — 

Responses: 403 Insufficient permissions, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/agents/actions/terminate-remote-shell`
**Terminate Remote Shell**
`operationId`: `_web_api_agents_actions_terminate-remote-shell_post`

Remote Shell is a powerful, full shell for Windows, macOS, and Linux. It is best practice to terminate Remote Shell sessions when they are not in use. A Remote Shell session terminates when the user closes the session, the session times out, or the session is idle longer than the idle-timeout. <BR>Use this command terminate a session immediately.

Required permissions: `Endpoints.remoteShell`

Parameters:
- `body` [body, agents.schemas_TerminateRemoteShellSchema] — 

Responses: 403 Insufficient permissions, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry., 200 Success

## `POST /web/api/v2.1/agents/actions/uninstall`
**Uninstall**
`operationId`: `_web_api_agents_actions_uninstall_post`

Use this command to uninstall Agents that match the filter. For Windows and macOS, make sure that all remnants of the Agent are removed: reboot the endpoints after uninstall. Use the "restart" command.

Required permissions: `Endpoints.uninstall`

Parameters:
- `body` [body, agents.schemas_AgentsDangerousActionSchema] — 

Responses: 403 User has insufficient permissions to perform the requested a, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/agents/actions/update-software`
**Update Software**
`operationId`: `_web_api_agents_actions_update-software_post`

Use this command to update the Agent version on endpoints that have the Agent installed and that match the filter. For a cloud-based Management, SentinelOne updates your Management Console with the latest Agent versions. For On-Prem environments, or if you need a package that is not in your Management Console, request files from SentinelOne Support. <BR>IMPORTANT: These parameters are required:<br>packageType - example: "packageType": "AgentAndRanger",osType - example: "osType": "windows",fileName - example: "fileName": "SentinelInstaller-x86_windows_32bit_v4_6_12_241.exe"<BR>Best Practice:  Upgrade your SentinelOne Agents by group or OS. Note about macOS endpoints: It is important that you upgrade the Agent before the endpoint operating system is upgraded to a version that the Agent does not support. More best practices: read the Release Notes, review the system requirements, and if you decide to not upgrade Agents yet, review the Agent Lifecycle. Make sure your deployment is in the supportable bounds.

Required permissions: `Endpoints.updateSoftware`

Parameters:
- `body` [body, agents.schemas_AgentsUpdateSoftwareActionSchema] — 

Responses: 403 User has insufficient permissions to perform the requested a, 409 The Agent is automatically upgraded according to its Upgrade, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.

## `POST /web/api/v2.1/agents/{agent_id}/actions/fetch-files`
**Fetch Files**
`operationId`: `_web_api_agents_{agent_id}_actions_fetch-files_post`

Fetch files from endpoints (up to 10 MB for each command) to analyze the root of threats (that come from files - of course, this does not help for fileless threats). Set the pathnames in the body of the request. <BR>Regular expressions and metacharacters are not allowed. Spaces are allowed.<BR>You must enter a new password, which you will use to open the archive of downloaded files. The password must be 10 or more characters with a mix of upper and lower case letters, numbers, and symbols.<BR>This command collects the file and uploads them to the Management. To get the files, download them from the Management.<BR>FedRAMP-compliant and other Managements in GovCloud require a Support ticket to enable this feature.

Required permissions: `Endpoints.fileFetch`

Parameters:
- `agent_id` [path, string] **required** — Agent ID. Example: "225494730938493804".
- `body` [body, agents.schemas_AgentFetchFilesActionSchema] — 

Responses: 404 Agent not found, 403 User has insufficient permissions to perform the requested a, 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.
