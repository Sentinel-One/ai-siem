# Architecture

This document explains how the layers of the SentinelOne AI analyst stack fit together, top-down: the CLAUDE.md operating instructions that drive every session, the umbrella sdl-solutions skill that orchestrates whole-solution deploys, the primitive Claude skills, and the MCP servers that reach the live APIs.

---

## The layers

The stack runs top-down: CLAUDE.md decides what to do and invokes skills; the umbrella
`sdl-solutions` skill orchestrates the primitive skills for whole-solution work; the skills reach the
live APIs through the MCP servers.

```text
CLAUDE.md                       Main instruction layer: SOC Analyst persona, session protocol,
                                evidence rules, investigation workflow, classification gates.
                                Loaded as a resource via s1-secops-mcp at session start. Decides what
                                to do and invokes skills as needed.
       |  invokes skills
       v
sdl-solutions       Umbrella orchestrator. On a "deploy / onboard / monitor a whole
                                solution" request it runs first, collects parameters, previews,
                                then drives the primitive skills below in dependency order.
                                (Skipped when the ask is a single query, parser, or workflow.)
       |  orchestrates
       v
Primitive skills (SKILL.md)     Procedural knowledge Claude reads when a request triggers them:
  powerquery         PowerQuery authoring and execution
  sdl-dashboard      Dashboard JSON authoring and deployment
  sdl-log-parser     Parser authoring and validation
  hyperautomation    Workflow JSON authoring and import
  sdl-api            SDL log ingest and config file ops
  mgmt-console-api   Mgmt Console REST, UAM, Purple AI, HA
       |  call MCP tools, which reach the APIs
       v
MCP Servers                     Live API access, outside the Cowork sandbox proxy:
  s1-secops-mcp                PowerQuery, SDL API, Hyperautomation, Mgmt REST, UAM, UAM ingest
  purple-mcp                     alert triage, Purple AI NLQ, Deep Visibility, assets, vulnerabilities
  threat-intel-mcp               external IOC enrichment (required for CRITICAL classification)
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

`s1-secops-mcp` exposes `CLAUDE.md` as an MCP resource (`sentinelone://soc-context`) and prompt (`soc_analyst`). Claude reads it at session start. The file lives in `s1-secops-skills/CLAUDE.md`; editing it and restarting the MCP server immediately changes Claude's operating behaviour.

### s1-secops-mcp

A local Node.js process (or the Docker image, started by the host launcher) that runs on the user's machine, outside the Cowork sandbox, over stdio. Because the Cowork sandbox proxy blocks outbound HTTPS to `*.sentinelone.net` by default, all API calls go through this server. It reads credentials from environment variables, then the OS keychain, and masks token values in every tool response and log line. There is no HTTP transport and no shared team server: each user runs their own instance with their own credentials.

Bulk results do not have to pass through the model's context: `powerquery_run`, `s1_api_get`, `s1_api_download` and `ha_export_workflow` take an `outputFile` (an absolute path inside `S1_OUTPUT_DIRS`, default home and temp; files are created mode 0600 and never overwritten unless `overwrite` is true) and return a summary instead.

It exposes 35 MCP tools across five groups:

| Group | Tools | API surface |
|---|---|---|
| PowerQuery | `powerquery_enumerate_sources`, `powerquery_run` (PQ or LOG, `slices` + `merge`, `outputFile`), `powerquery_schema_discover` | SDL LRQ API |
| Mgmt Console | `s1_api_get`, `s1_api_post`, `s1_api_put`, `s1_api_patch`, `s1_api_delete`, `s1_api_download`, `uam_list_alerts`, `uam_get_alert`, `uam_add_note`, `uam_set_status`, `uam_set_verdict`, `uam_assign_alert`, `uam_available_actions`, `purple_ai_alert_summary` | S1 REST API v2.1 + UAM GraphQL |
| SDL | `sdl_list_files`, `sdl_get_file`, `sdl_put_file`, `sdl_delete_file`, `sdl_list_dashboards`, `sdl_get_dashboard`, `sdl_create_dashboard`, `sdl_share_dashboard`, `sdl_save_dashboard_layout`, `sdl_delete_dashboard`, `hec_ingest` | SDL config + dashboards + event collector |
| Hyperautomation | `ha_list_workflows`, `ha_get_workflow`, `ha_import_workflow`, `ha_export_workflow`, `ha_delete_workflow` | HA public + v1 API |
| UAM Ingest | `uam_ingest_alert`, `uam_post_alert` | UAM Alert Interface (`/v1/alerts`) |

Two credentials split the ingest surface. `hec_ingest` posts raw logs to the event collector and authenticates with an SDL Log Write Key (`S1_HEC_TOKEN`); the console API token is refused there, returning `HTTP 400 {"text":"Missing S1-Scope header","code":5}` where the write key returns `HTTP 200 {"text":"Success","code":0}`. The UAM Ingest tools post alerts to `/v1/alerts` and keep using the console API token (`S1_CONSOLE_API_TOKEN`). Indicators have no separate ingest path: they ride inside the alert, in `finding_info.related_events[]`.

Full tool reference: [mcp-tools.md](./mcp-tools.md)

### purple-mcp

A separate MCP server (Python, bundled in the `sentinelone/secops-mcps` image from a pinned git commit; a native install runs it as `s1-secops-mcp exec -- purple-mcp --mode stdio`, see [credentials.md](./credentials.md#storing-values-setup-status-forget)) that provides the Purple AI investigation surface. It covers:

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
- MCP tool guidance (which tool to use for which operation); the MCP tools are the primary path
- Host-only Python script reference for Claude Code or terminal use, where the scripts read the same environment variables or keychain entries

The skills are read-only procedural knowledge. They do not execute API calls directly when loaded: they instruct Claude on *how* to use the MCP tools (and, on the host, the scripts) to execute operations correctly.

`sdl-solutions` is the umbrella skill in this layer: for a whole-solution request (onboard a source, asset enrichment, UEBA, ingest health monitoring, or custom detection exclusions) it runs first, collects parameters, previews, and orchestrates the primitive skills in dependency order, instead of each skill being invoked independently.

---

## Authentication flow

Two credentials cover the API surfaces. The console service-user token (`S1_CONSOLE_API_TOKEN`) authorises the management, SDL and UAM surfaces. Raw log ingest to the event collector is the exception: it authorises with the SDL Log Write Key (`S1_HEC_TOKEN`).

```text
S1_CONSOLE_API_TOKEN  ──► S1 Mgmt REST API    (Authorization: ApiToken <jwt>)
                      ──► SDL config ops       (Authorization: Bearer <jwt>)
                      ──► UAM GraphQL          (Authorization: ApiToken <jwt>)
                      ──► Purple AI GraphQL    (Authorization: ApiToken <jwt>)
                      ──► LRQ PowerQuery       (Authorization: Bearer <jwt>)
                      ──► UAM alert ingest     (Authorization: Bearer <jwt>, POST /v1/alerts, S1-Scope required)

S1_HEC_TOKEN          ──► HEC log ingest       (Authorization: Bearer <write-key>, host S1_HEC_INGEST_URL, no S1-Scope)

```

`S1_CONSOLE_API_TOKEN` authorises every SDL config read, config write and log read, plus UAM alert ingest on `/v1/alerts` (which additionally requires an `S1-Scope` header) and the IOC endpoints. `hec_ingest` is the one surface it does not cover: raw log ingest to the event collector needs the SDL Log Write Key (`S1_HEC_TOKEN`) and sends no `S1-Scope` header. Passing the console token there returns `HTTP 400 {"text":"Missing S1-Scope header","code":5}` where the write key returns `HTTP 200 {"text":"Success","code":0}`. The two ingest paths are separate; do not substitute one credential for the other.

Credential resolution, per value (highest priority first):

1. Environment variables (`S1_CONSOLE_URL`, `S1_CONSOLE_API_TOKEN`, `S1_HEC_INGEST_URL`, `S1_HEC_TOKEN`, `S1_SCOPE`, `VIRUSTOTAL_API_KEY`)
2. The OS keychain: service `sentinelone-mcp`, account `<profile>:<NAME>`, profile from `S1_PROFILE` (default `default`). macOS login keychain, Linux Secret Service, Windows Credential Manager.

There is no file fallback. Values are stored with `s1-secops-mcp setup` (or the Docker launcher's `setup` mode). Under Docker, the host launcher reads the keychain and passes the values to the container over stdin, so the MCP client config carries no secrets. Details, the migration from `credentials.json`, and the limits of keychain protection: [credentials.md](./credentials.md).

---

## Sandbox proxy and why MCP is needed

The Cowork sandbox runs API calls through a proxy that blocks outbound HTTPS to arbitrary domains including `*.sentinelone.net`. The supported path is the **s1-secops-mcp local server**: it runs on your machine, outside the sandbox, so API calls go directly from your machine to SentinelOne with no allowlist change. Every skill is written to use it.

> **Note (allowlist):** an administrator can add `*.sentinelone.net` to the Claude Desktop network allowlist, which lets the skills' Python scripts reach the API from inside the sandbox. Those scripts read credentials from environment variables or the OS keychain, neither of which exists inside the sandbox, so this route still needs credentials supplied another way and is not a documented setup. Prefer the MCP server.

---

## Data flow in a typical investigation

```text
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

```text
s1-secops-skills/
  CLAUDE.md                     SOC Analyst persona and operating instructions
  README.md                     High-level overview (this project)
  docs/                         Detailed documentation (this folder)
    architecture.md             How all layers fit together (this file)
    skills.md                   Per-skill capability reference
    mcp-tools.md                All MCP tool schemas and usage notes
    credentials.md              Credential values, env + keychain resolution, setup, security model
    testing.md                  Test coverage: what was validated, gotchas per surface
  mgmt-console-api/ Skill: Management Console REST + SDL + UAM + Purple AI
  powerquery/       Skill: PowerQuery authoring and execution
  sdl-api/          Skill: SDL log ingest and config file operations
  sdl-dashboard/    Skill: SDL dashboard authoring and deployment
  sdl-log-parser/   Skill: SDL log parser authoring and validation
  hyperautomation/  Skill: Hyperautomation workflow authoring and import
  sdl-solutions/    Skill: repeatable SDL solution deployment (onboarding, enrichment)
  soc-investigator/             Skill: autonomous DFIR alert investigation and correlation
  s1-secops-mcp/              MCP server (Node.js): 35 tools, stdio
  docker/                       Image build, entrypoint, and the host keychain launchers
  s1-secops-skills-plugin/    Distributable plugin bundle (all 8 skills)
  assets/                       Screenshots and images for documentation
```
