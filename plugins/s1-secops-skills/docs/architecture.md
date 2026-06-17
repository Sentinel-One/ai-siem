# Architecture

This document explains how the three layers of the SentinelOne AI analyst stack fit together: the Claude skills, the MCP servers, and the CLAUDE.md operating instructions.

---

## The three layers

```
┌─────────────────────────────────────────────────────────────────────┐
│  CLAUDE.md : SOC Analyst persona, evidence rules, session protocol │
│  Loaded as a resource via s1-secops-mcp at session start          │
└────────────────────────────┬────────────────────────────────────────┘
                             │ instructs Claude how to investigate
                             ▼
┌─────────────────────────────────────────────────────────────────────┐
│  MCP Servers : live API access, bypasses Cowork sandbox proxy      │
│                                                                     │
│  s1-secops-mcp (this repo, Node.js, local process)               │
│    26 tools: PowerQuery, SDL API, Hyperautomation, Mgmt REST, UAM,  │
│              UAM Ingest                                              │
│                                                                     │
│  purple-mcp (Python, fetched via uvx from GitHub)                  │
│    alert triage, Purple AI NLQ, Deep Visibility, UAM, assets       │
│                                                                     │
│  threat-intel-mcp (required; use your org's approved provider)     │
│    external IOC enrichment; required for CRITICAL classification    │
│    VirusTotal shown as example: any equivalent MCP works          │
└────────────────────────────┬────────────────────────────────────────┘
                             │ tools Claude calls
                             ▼
┌─────────────────────────────────────────────────────────────────────┐
│  Skills (SKILL.md files) : procedural knowledge Claude reads       │
│  Loaded when a relevant request triggers the skill                  │
│                                                                     │
│  mgmt-console-api   SDL query, Mgmt REST, UAM, Purple  │
│  powerquery         PowerQuery authoring and execution  │
│  sdl-api            SDL log ingest, config file ops     │
│  sdl-dashboard      Dashboard JSON authoring/deploy     │
│  sdl-log-parser     Parser authoring and validation     │
│  hyperautomation    Workflow JSON authoring/import      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## How the layers interact

### CLAUDE.md

`CLAUDE.md` defines the operating persona for every session: Principal SOC Analyst. It contains:

- Mandatory session initialization protocol (enumerate SDL sources, triage alerts in parallel)
- Evidence discipline rules (no fabrication, cite sources inline, mark assumptions explicitly)
- Investigation workflow (triage, enrichment, correlation, MITRE mapping, risk scoring)
- Alert classification rules (no CRITICAL verdict without independent threat intel confirmation)
- Anomaly detection checklist (frequency, timing, geolocation, privilege, chain anomalies)

`s1-secops-mcp` exposes `CLAUDE.md` as an MCP resource (`sentinelone://soc-context`) and prompt (`soc_analyst`). Claude reads it at session start. The file lives in `plugins/s1-secops-skills/CLAUDE.md`; editing it and restarting the MCP server immediately changes Claude's operating behavior.

### s1-secops-mcp

A local Node.js process that runs outside the Cowork sandbox. Because the Cowork sandbox proxy blocks outbound HTTPS to `*.sentinelone.net` by default, all API calls go through this server instead, bypassing the sandbox proxy entirely.

It exposes 26 MCP tools across five groups:

| Group | Tools | API surface |
|---|---|---|
| PowerQuery | `powerquery_enumerate_sources`, `powerquery_run`, `powerquery_schema_discover` | SDL LRQ API |
| Mgmt Console | `s1_api_get`, `s1_api_post`, `s1_api_put`, `s1_api_patch`, `s1_api_delete` | S1 REST API v2.1 |
| UAM | `uam_list_alerts`, `uam_get_alert`, `uam_add_note`, `uam_set_status`, `uam_ingest_alert`, `uam_post_alert`, `uam_post_indicators`, `purple_ai_alert_summary` | UAM GraphQL + HEC ingest |
| SDL | `sdl_list_files`, `sdl_get_file`, `sdl_put_file`, `sdl_delete_file`, `hec_ingest` | SDL config + HEC log ingest API |
| Hyperautomation | `ha_list_workflows`, `ha_get_workflow`, `ha_import_workflow`, `ha_export_workflow`, `ha_delete_workflow` | HA public + v1 API |

Full tool reference: [mcp-tools.md](./mcp-tools.md)

### purple-mcp

A separate MCP server (Python, fetched from GitHub via `uvx`) that provides the Purple AI investigation surface. It covers:

- `purple_ai`: natural-language queries against SDL telemetry
- `powerquery`: run raw PowerQuery strings via the SDL LRQ engine
- `list_alerts`, `search_alerts`, `get_alert`, `get_alert_history`, `get_alert_notes`: UAM alert access
- `list_inventory_items`, `search_inventory_items`, `get_inventory_item`: asset inventory
- `list_vulnerabilities`, `get_vulnerability`: CVE and patch gap reporting
- `list_misconfigurations`, `get_misconfiguration`: agent config hygiene
- `uam_add_note`, `uam_set_status`: alert annotation and triage

purple-mcp is complementary to s1-secops-mcp. They share credentials but serve different roles:

| Task | Use |
|---|---|
| SDL PowerQuery hunting | Either: `powerquery_run` (s1-secops-mcp) or `powerquery` (purple-mcp) |
| Natural-language Purple AI queries | purple-mcp `purple_ai` only |
| Alert triage, notes, status | purple-mcp is preferred (richer GraphQL fields); s1-secops-mcp UAM tools as fallback |
| Management Console REST ops (agents, threats, sites, exclusions, IOCs, detection rules) | s1-secops-mcp `s1_api_*` only |
| SDL log ingest, parser/dashboard deploy | s1-secops-mcp SDL tools only |
| Hyperautomation workflow import | s1-secops-mcp HA tools only |

### Skills (SKILL.md files)

Each skill folder contains a `SKILL.md` that Claude reads when a relevant request triggers the skill. SKILL.md files encode:

- API endpoint paths and required field schemas (confirmed against live API, not just swagger)
- Non-obvious requirements, gotchas, and field-name traps discovered by testing
- Python script reference for running operations locally
- MCP tool guidance (which tool to use for which operation)

The skills are read-only procedural knowledge. They do not execute API calls directly when loaded: they instruct Claude on *how* to use the MCP tools and scripts to execute operations correctly.

---

## Authentication flow

All four API surfaces use a single service user token (`S1_CONSOLE_API_TOKEN`) plus surface-specific keys for SDL write operations.

```
S1_CONSOLE_API_TOKEN  ──► S1 Mgmt REST API    (Authorization: ApiToken <jwt>)
                      ──► SDL config ops       (Authorization: Bearer <jwt>)
                      ──► UAM GraphQL          (Authorization: ApiToken <jwt>)
                      ──► Purple AI GraphQL    (Authorization: ApiToken <jwt>)
                      ──► LRQ PowerQuery       (Authorization: Bearer <jwt>)
                      ──► HEC log ingest       (Authorization: Bearer <jwt>, host S1_HEC_INGEST_URL)

SDL_CONFIG_WRITE_KEY  ──► SDL putFile          (Authorization: Bearer <key>)
```

The console JWT (`S1_CONSOLE_API_TOKEN`) grants access to SDL config and query operations from Management version Z SP5+, and is also the Bearer used for HEC log ingest (`hec_ingest`, posted to `S1_HEC_INGEST_URL`). The dedicated `SDL_CONFIG_WRITE_KEY` is only needed for parser/dashboard deployment (`sdl_put_file`).

Credential resolution order (highest priority first):

1. Environment variables (`S1_CONSOLE_URL`, `S1_CONSOLE_API_TOKEN`, `SDL_*`)
2. `credentials.json` in the Cowork project folder (auto-discovered by the plugin's SessionStart hook)
3. `~/.config/sentinelone/credentials.json` (terminal fallback)

For the MCP servers, credentials are passed via `env` in `claude_desktop_config.json`: see [credentials.md](./credentials.md).

---

## Sandbox proxy and why MCP is needed

The Cowork sandbox runs API calls through a proxy that blocks outbound HTTPS to arbitrary domains including `*.sentinelone.net`. There are two solutions:

**Option A (recommended): s1-secops-mcp local server.** Runs as a local process on your machine, outside the sandbox. API calls go directly from your machine to SentinelOne. No allowlist changes needed.

**Option B: Network allowlist.** In Claude Desktop settings, add `*.sentinelone.net` to the allowed domains. This lets the skills' Python scripts (`s1_client.py`, `sdl_client.py`) reach the API from inside the sandbox. No MCP server needed, but requires admin configuration.

Most users should use Option A.

---

## Data flow in a typical investigation

```
User: "Investigate alert abc-123"
       │
       ▼
Claude reads CLAUDE.md instructions for investigation protocol
       │
       ├── purple-mcp: get_alert(abc-123) → alert details, notes, history
       ├── purple-mcp: get_inventory_item(agent_uuid) → asset criticality
       ├── s1-secops-mcp: s1_api_get(/threats, filter=alert) → threat context
       │
       ▼
Claude reads powerquery SKILL.md → writes hunt query
       │
       ├── s1-secops-mcp: powerquery_enumerate_sources → confirm data sources present
       └── s1-secops-mcp: powerquery_run(hunt_query) → corroborating telemetry
              │
              ▼
       IOC extracted from telemetry
              │
              ├── threat-intel-mcp: get_file_report(hash) → multi-engine verdict
              └── threat-intel-mcp: get_ip_report(ip) → threat actor attribution
              (use your org's approved threat intel MCP; VirusTotal shown as example)
                     │
                     ▼
              Claude generates SOC report (.docx) with verdict, MITRE mapping,
              IOC table, and recommendations
```

---

## Directory layout

```
ai-siem/
  .claude-plugin/marketplace.json   Marketplace catalog (lists the plugin)
  plugins/
    s1-secops-skills/               Plugin root: all 7 skills + packaging
      .claude-plugin/plugin.json    Plugin manifest
      CLAUDE.md                     SOC Analyst persona and operating instructions
      README.md                     High-level overview (this project)
      docs/                         Detailed documentation (this folder)
        architecture.md             How all layers fit together (this file)
        skills.md                   Per-skill capability reference
        mcp-tools.md                All MCP tool schemas and usage notes
        credentials.md              Credential keys, resolution order, where to find each
        testing.md                  Test coverage: what was validated, gotchas per surface
      hooks/  scripts/  dist/       SessionStart cred hook, build script, built bundles
      skills/
        mgmt-console-api/ Skill: Management Console REST + SDL + UAM + Purple AI
        powerquery/       Skill: PowerQuery authoring and execution
        sdl-api/          Skill: SDL log ingest and config file operations
        sdl-dashboard/    Skill: SDL dashboard authoring and deployment
        sdl-log-parser/   Skill: SDL log parser authoring and validation
        hyperautomation/  Skill: Hyperautomation workflow authoring and import
        sdl-solutions/    Skill: repeatable SDL solution deployment (onboarding, enrichment)
  mcp/
    s1-secops-mcp/                MCP server (Node.js): 26 tools, stdio or HTTP
    docker/                         Container build for the MCP stack
```
