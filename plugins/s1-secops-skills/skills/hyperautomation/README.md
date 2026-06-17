# hyperautomation (Claude skill)

A Claude skill for designing and generating SentinelOne Hyperautomation workflow JSON, with optional live console import via API.

## What it does

- Generates valid Hyperautomation workflow JSON from a plain-language description
- Covers all workflow trigger types: alert, schedule, webhook, manual, email
- Supports core actions (conditions, loops, variables, HTTP requests, delays) and integration-backed actions (SentinelOne, M365, Slack, VirusTotal, etc.)
- Validates the generated JSON against schema rules before presenting it
- Optionally imports, activates, and triggers workflows on a live console via the Hyperautomation API
- Warns about integrations that require pre-configuration in the console before import

## Install

This skill ships as part of the `s1-secops-skills` plugin. Install the plugin and it is included automatically.

To install individually, copy this folder into your user skills directory:

```bash
cp -r hyperautomation ~/.claude/skills/
```

## Configure

Set credentials as environment variables in `claude_desktop_config.json` inside the `s1-secops-mcp` server entry (recommended), or drop a `credentials.json` into your Cowork project folder for direct skill use:

```json
{
  "S1_CONSOLE_URL": "https://usea1-acme.sentinelone.net",
  "S1_CONSOLE_API_TOKEN": "eyJ...your-console-user-api-token...",
  "S1_HEC_INGEST_URL": "https://ingest.us1.sentinelone.net"
}
```

Use a **Console User (personal) API token**, not a Service User token. Workflows imported with a Service User token are owned by that service account and invisible to human users in the console UI.

`S1_HEC_INGEST_URL` is the SentinelOne HEC ingest host (region-specific: see [SentinelOne Endpoint URLs by Region](https://community.sentinelone.com/s/article/000004961)). It is not used by this Hyperautomation skill, but is shown here so the credentials file is consistent across all skills in this plugin (the mgmt-console skill's UAM Alert Interface uses it for OCSF alert/indicator ingest).

## Usage

Just describe the workflow in plain language:

- "Build a workflow that isolates an endpoint when a critical threat alert fires"
- "Create a scheduled workflow that runs a PowerQuery every morning and posts results to Slack"
- "Generate a Hyperautomation workflow that enriches alerts with VirusTotal lookups"

Claude will ask clarifying questions if needed, warn about any integrations that require pre-configuration, generate the workflow JSON, and optionally push it directly to your console.

## Layout

- `SKILL.md`: instructions Claude reads when the skill triggers
- `references/workflow-schema.md`: envelope and action structure
- `references/building-blocks.md`: exact shape of every action type
- `references/functions-reference.md`: `{{Function.X()}}` syntax and PowerQuery patterns
- `references/validation-rules.md`: pre-output checklist
- `references/api-integration.md`: Hyperautomation API reference (import, activate, trigger, list)

## Credit

Originally authored by **Marco Rottigni**. Integrated into the s1-secops-skills plugin with credential-resolver updates and API reference additions.
