# Read-Only Mode and Write Access

**Applies to:** s1-secops-mcp 1.5.5 and later, image `sentinelone/secops-mcps:1.5.7` and later, plugin 1.3.16 and later

> **WARNING: WRITE ACCESS CHANGES YOUR SENTINELONE TENANT**
>
> When write access is enabled, an AI assistant can create, modify and delete objects in your SentinelOne console on your behalf, including alert status and verdicts, analyst notes, dashboards, parsers, lookup tables, Hyperautomation workflows and ingested data. Some of these changes cannot be undone.
>
> - Every write runs with the permissions of the user that owns the configured API token and is recorded in the server audit log (section 4).
> - The assistant may act on an incorrect interpretation of your request. Review each proposed change before you approve the tool call.
> - Enable write access only if you are authorised to make changes in the tenant, and only for as long as you need it.
> - Use a dedicated service user with the least-privileged role that covers the task. Do not use a token that belongs to a Global Admin.
>
> Read-only mode is the default and the recommended setting for investigation, hunting and reporting.

---

## 1. Default behaviour

From 1.5.5, s1-secops-mcp starts in **read-only mode**. All tools remain listed, so the assistant can explain what it would do, but any tool call that would change the tenant is refused **before a network request is made**. The refusal tells the user how to enable write access.

Read-only mode covers s1-secops-mcp only. purple-mcp, the VirusTotal MCP and the Shodan MCP expose query tools and are unaffected by this setting.

| Mode | What runs | What is refused |
|---|---|---|
| Read-only (default) | Every query and read: PowerQuery, schema discovery, Mgmt API GET, query-type POSTs on an allowlist, UAM list and get, SDL file and dashboard reads, Hyperautomation list, get and export, local file output (`outputFile`, `s1_api_download`) | Every tool or call that changes the tenant (see section 3) |
| Write enabled | Everything | Nothing beyond what the token's console role denies |

## 2. Enabling write access

Set `S1_READ_ONLY=false` for the s1-secops-mcp server, then restart the MCP client.

| Install method | How to enable write | How to return to read-only |
|---|---|---|
| Docker launcher, macOS or Linux | `s1-secops-mcp-launch.sh install --read-write` | `s1-secops-mcp-launch.sh install` |
| Docker launcher, Windows | `s1-secops-mcp-launch.ps1 install -ReadWrite` | `s1-secops-mcp-launch.ps1 install` |
| Claude Desktop extension (`.mcpb`) | Settings, Extensions, SentinelOne SecOps MCP: turn off **Read-only mode (recommended)** | Turn the setting back on |
| Node install, any MCP client | Add `"S1_READ_ONLY": "false"` to the `env` block of the `s1-secops-mcp` entry | Remove the line, or set it to `"true"` |
| Plain `docker run` | `-e S1_READ_ONLY=false` | Omit it |

Restart Claude Desktop completely (including from the system tray on Windows) after any change.

Accepted values: `false`, `0`, `no`, `off` enable write; `true`, `1`, `yes`, `on`, empty or unset keep read-only. **Any other value keeps read-only** and logs a warning, so a typo can never enable write by accident.

To check the active mode, look for the `Mode:` line in the server log at startup, or ask the assistant to call `credentials-status`, which returns a `mode` object.

## 3. What read-only mode refuses

### 3.1 Tools that always change the tenant (18)

| Area | Tools |
|---|---|
| Management Console API | `s1_api_put`, `s1_api_patch`, `s1_api_delete` |
| Unified Alert Management | `uam_add_note`, `uam_set_status`, `uam_set_verdict`, `uam_assign_alert`, `uam_post_alert`, `uam_ingest_alert` |
| Singularity Data Lake | `hec_ingest`, `sdl_put_file`, `sdl_delete_file`, `sdl_create_dashboard`, `sdl_share_dashboard`, `sdl_save_dashboard_layout`, `sdl_delete_dashboard` |
| Hyperautomation | `ha_import_workflow`, `ha_delete_workflow` |

### 3.2 Tools that depend on their arguments (2)

| Tool | Allowed in read-only mode | Refused in read-only mode |
|---|---|---|
| `s1_api_post` | GraphQL documents that contain only `query` operations; Deep Visibility query launch (`/dv/init-query`); query validation (`/cloud-funnel/validate-query`); graph explorer queries; `available-actions`; tag counts | Every other POST, including GraphQL `mutation` and any endpoint not on the allowlist. An endpoint missing from the allowlist is treated as a write. The check uses the path the request is actually sent to: a path containing a `#` fragment, `;` parameters, a backslash, whitespace, percent-encoded separators or dots, or `.` / `..` segments is treated as a write. |
| `powerquery_run` | Every query that does not write | Queries containing `\| savelookup`, which creates or overwrites a lookup table |

### 3.3 Tools that never change the tenant (15)

`s1_api_get`, `s1_api_download`, `uam_list_alerts`, `uam_get_alert`, `uam_available_actions`, `purple_ai_alert_summary`, `powerquery_enumerate_sources`, `powerquery_schema_discover`, `sdl_list_files`, `sdl_get_file`, `sdl_list_dashboards`, `sdl_get_dashboard`, `ha_list_workflows`, `ha_get_workflow`, `ha_export_workflow`.

Each tool also carries MCP annotations (`readOnlyHint`, `destructiveHint`) so clients that honour them can ask for confirmation before a write.

### 3.4 purple-mcp `savelookup`

purple-mcp's `powerquery` tool is outside this setting. A PowerQuery containing `| savelookup` sent through purple-mcp writes a lookup table even when s1-secops-mcp is read-only. If that matters in your environment, give purple-mcp a token whose role cannot write to the Data Lake.

## 4. Controls when write is enabled

| Control | Behaviour |
|---|---|
| Token required | A write is refused if no console API token is configured (`hec_ingest` uses the SDL Log Write Key instead). |
| Token expiry | If the console token is a JWT and its expiry has passed, the write is refused with a message to generate a new token. The server also warns at startup when the token expires within 7 days. |
| Audit line | Each allowed write logs one line to the server's stderr: `[s1-secops-mcp] WRITE <time> tool=<name> path=<path> ...`. The line records what and where, never request bodies, tokens or headers. Claude Desktop keeps it in the MCP server log. |
| Console audit | Alert actions (status, verdict, notes) are recorded in the console Activity log under the token's user. Singularity Data Lake objects such as dashboards record `createdBy` and `updatedBy` on the object itself. |

## 5. Relationship to console permissions

Read-only mode is a safeguard in the MCP server. **The authoritative control is the role of the token's user in the SentinelOne console.** A token whose user has a read-only role (for example Viewer) cannot change the tenant whatever `S1_READ_ONLY` says, and a token with an administrative role can change anything its role allows once write is enabled.

Recommended practice:

1. Investigation, hunting and reporting: read-only mode, token from a service user with a read-only role.
2. Content deployment (dashboards, parsers, detections, workflows) or alert triage: write enabled, token from a service user whose role covers only those actions, scoped to the account or site concerned.
3. Return to read-only mode when the change is complete.

## 6. Upgrading from 1.5.4 or earlier

Earlier versions allowed every tool to write. After upgrading, tools that change the tenant are refused until you opt in as described in section 2. Skills and workflows that deploy content (dashboards, parsers, detections, Hyperautomation workflows, alert status and notes) will report the refusal with instructions; no data is changed while read-only.

---

SentinelOne®, Singularity™ and Purple AI™ are trademarks or registered trademarks of SentinelOne, Inc. See [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md) for third-party components and services.
