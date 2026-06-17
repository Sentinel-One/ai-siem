# Agent Support Actions

1 endpoints.

## `POST /web/api/v2.1/agents/actions/clear-remote-shell-session`
**Clear Remote Shell**
`operationId`: `_web_api_agents_actions_clear-remote-shell-session_post`

Remote Shell is a powerful way to respond remotely to events on endpoints. It lets you open full shell capabilities - PowerShell on Windows and Bash on macOS and Linux. <BR>For best practices, a Remote Shell session can be terminated in many ways: from the UI, from Agent timeouts, from endpoint or connections issues, and so on. If a shell closes at the same time that an Agent goes offline, Remote Shell status is incorrect on the Management. <BR>Use this command to clear the "open shell" flags on the Management. <BR>The IT user role does not have permissions to run this command.

Required permissions: `Endpoints.clearRemoteShellSession`

Parameters:
- `body` [body, agents.schemas_AgentsActionSchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.
