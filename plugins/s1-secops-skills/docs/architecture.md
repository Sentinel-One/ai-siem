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
MCP Server                      Live API access, outside the Cowork sandbox proxy:
  s1-secops-mcp                 PowerQuery, SDL API, Hyperautomation, Mgmt REST, UAM, UAM ingest,
                                Purple AI questions, built-in VirusTotal and Shodan lookups
  optional (your choice)        other MCP servers from their official sources, e.g. another
                                threat-intel provider (see connect-optional-tools.md)
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

It registers 40 MCP tools across six groups. The four VirusTotal and Shodan tools are listed only when their API key is stored, so a client sees 36 tools with no threat-intel keys, 38 with VirusTotal only, and 40 with both:

| Group | Tools | API surface |
|---|---|---|
| PowerQuery | `powerquery_enumerate_sources`, `powerquery_run` (PQ or LOG, `slices` + `merge`, `outputFile`), `powerquery_schema_discover` | SDL LRQ API |
| Mgmt Console | `s1_api_get`, `s1_api_post`, `s1_api_put`, `s1_api_patch`, `s1_api_delete`, `s1_api_download`, `uam_list_alerts`, `uam_get_alert`, `uam_add_note`, `uam_set_status`, `uam_set_verdict`, `uam_assign_alert`, `uam_available_actions`, `purple_ai_alert_summary`, `purple_ai_query` | S1 REST API v2.1 + UAM GraphQL + Purple AI GraphQL |
| Threat intelligence | `ti_vt_lookup`, `ti_vt_relationship` (with `VIRUSTOTAL_API_KEY`), `ti_shodan_host`, `ti_shodan_dns` (with `SHODAN_API_KEY`) | VirusTotal API v3, Shodan API |
| SDL | `sdl_list_files`, `sdl_get_file`, `sdl_put_file`, `sdl_delete_file`, `sdl_list_dashboards`, `sdl_get_dashboard`, `sdl_create_dashboard`, `sdl_share_dashboard`, `sdl_save_dashboard_layout`, `sdl_delete_dashboard`, `hec_ingest` | SDL config + dashboards + event collector |
| Hyperautomation | `ha_list_workflows`, `ha_get_workflow`, `ha_import_workflow`, `ha_export_workflow`, `ha_delete_workflow` | HA public + v1 API |
| UAM Ingest | `uam_ingest_alert`, `uam_post_alert` | UAM Alert Interface (`/v1/alerts`) |

Two credentials split the ingest surface. `hec_ingest` posts raw logs to the event collector and authenticates with an SDL Log Write Key (`S1_HEC_TOKEN`), which returns `HTTP 200 {"text":"Success","code":0}` with no `S1-Scope` header. The console API token is not a reliable substitute there: on some consoles it returns `HTTP 400 {"text":"Missing S1-Scope header","code":5}` without an `S1-Scope` header and is accepted with one, on others it returns `HTTP 403 {"text":"User token not allowed for this endpoint","code":4}` either way. Use the write key in both cases. The UAM Ingest tools post alerts to `/v1/alerts` and keep using the console API token (`S1_CONSOLE_API_TOKEN`). Indicators have no separate ingest path: they ride inside the alert, in `finding_info.related_events[]`.

**Read-only by default (1.5.5).** One gate in the server (`lib/access.js`) classifies every tool as Read (20), Write (18) or Conditional (2: `s1_api_post`, `powerquery_run`). Unless `S1_READ_ONLY=false` is set, any call that would change the tenant is refused before a network request is made; read and query calls always run. When write is enabled, a write is still refused if no console token is configured (except `hec_ingest`) or the token is a JWT that has expired, and each allowed write logs one stderr audit line with no bodies or tokens. The console role of the token's user remains the authoritative control. Details: [read-only.md](./read-only.md); per-tool access: [mcp-tools.md](./mcp-tools.md).

Full tool reference: [mcp-tools.md](./mcp-tools.md)

### Purple AI and built-in threat intelligence

These tools are part of s1-secops-mcp, written in this repo with Node's built-in `fetch` and no dependencies. All of them are read-only.

- **`purple_ai_query`** sends a natural-language question to Purple AI (`purpleLaunchQuery` on `/web/api/v2.1/graphql`) with the console API token, so it needs no extra key and is listed whenever the console is configured. It returns `MESSAGE` (a written answer) or `POWER_QUERY` (a PowerQuery plus time range). Purple AI does not run the query: Claude reviews it and runs it with `powerquery_run`. Each call is a new conversation and takes about 5 to 15 s.
- **`ti_vt_lookup` and `ti_vt_relationship`** call the VirusTotal API with `VIRUSTOTAL_API_KEY`: a report for a hash, IP, domain or URL (defanged input accepted), and one page of a relationship such as contacted domains, resolutions or related threat actors. `found:false` means VirusTotal has no record, not that the indicator is benign. A free key allows 4 lookups a minute and 500 a day, and some relationships need a premium key.
- **`ti_shodan_host` and `ti_shodan_dns`** call the Shodan API with `SHODAN_API_KEY`: open ports, services, CVEs, owner and tags for an external IP, and forward or reverse DNS for up to 25 names or IPs. Neither spends Shodan query credits. Shodan applies only to external (non-RFC1918) addresses.

At startup the server logs which of these are on, for example `Threat intel: Purple AI on, VirusTotal on, Shodan off (no SHODAN_API_KEY)`.

### Optional MCP servers

Any other MCP server runs next to s1-secops-mcp as its own entry in the client, installed by the user from its official source and supported by its own maintainers: the VirusTotal hosted MCP for VT Intelligence search and sandbox behaviour, SentinelOne's open-source purple-mcp, or another threat-intel provider. The skills are written provider-agnostic, so they use whichever threat-intel tools are connected. s1-secops-mcp's read-only setting does not apply to those servers. Setup per client: [connect-optional-tools.md](./connect-optional-tools.md).

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

VIRUSTOTAL_API_KEY    ──► VirusTotal API v3    (optional, ti_vt_* tools)
SHODAN_API_KEY        ──► Shodan API           (optional, ti_shodan_* tools)
```

`S1_CONSOLE_API_TOKEN` authorises every SDL config read, config write and log read, plus UAM alert ingest on `/v1/alerts` (which additionally requires an `S1-Scope` header) and the IOC endpoints. `hec_ingest` is the one surface it does not reliably cover: raw log ingest to the event collector uses the SDL Log Write Key (`S1_HEC_TOKEN`) and sends no `S1-Scope` header. The console token there gets `HTTP 400 {"text":"Missing S1-Scope header","code":5}` without a scope header, and with one it is accepted on some consoles and refused on others (`HTTP 403 {"text":"User token not allowed for this endpoint","code":4}`); the write key returns `HTTP 200 {"text":"Success","code":0}`. The two ingest paths are separate; do not substitute one credential for the other.

Credential resolution, per value (highest priority first):

1. Environment variables (`S1_CONSOLE_URL`, `S1_CONSOLE_API_TOKEN`, `S1_HEC_INGEST_URL`, `S1_HEC_TOKEN`, `S1_SCOPE`, `VIRUSTOTAL_API_KEY`, `SHODAN_API_KEY`)
2. The OS keychain: service `sentinelone-mcp`, account `<profile>:<NAME>`, profile from `S1_PROFILE` (default `default`). macOS login keychain, Linux Secret Service, Windows Credential Manager.

There is no file fallback. Values are stored with `s1-secops-mcp setup` (or the Docker launcher's `setup` mode). Under Docker, the host launcher reads the keychain and passes the values to the container over stdin, so the MCP client config carries no secrets. The optional `VIRUSTOTAL_API_KEY` and `SHODAN_API_KEY` are stored by `setup` under the same service (`<profile>:<NAME>`). Details, the migration from `credentials.json`, and the limits of keychain protection: [credentials.md](./credentials.md).

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
       ├── s1-secops-mcp: uam_get_alert(abc-123) → alert details, notes, history
       ├── s1-secops-mcp: s1_api_get(/agents, uuid) → asset context
       ├── s1-secops-mcp: s1_api_get(/threats, filter=alert) → threat context
       │
       ▼
Claude reads powerquery SKILL.md → writes hunt query
       │
       ├── s1-secops-mcp: powerquery_enumerate_sources → confirm data sources present
       ├── s1-secops-mcp: purple_ai_query(question) → suggested PowerQuery (optional)
       └── s1-secops-mcp: powerquery_run(hunt_query) → corroborating telemetry
              │
              ▼
       IOC extracted from telemetry
              │
              ├── s1-secops-mcp: ti_vt_lookup(hash) → multi-engine verdict
              ├── s1-secops-mcp: ti_vt_relationship(ip, related_threat_actors) → attribution
              └── s1-secops-mcp: ti_shodan_host(ip) → exposed ports, services, host CVEs
              (or your org's approved threat-intel MCP, connected next to s1-secops-mcp)
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
  s1-secops-mcp/              MCP server (Node.js): 40 tools, stdio
  docker/                       Image build (one server, distroless), dispatcher, and the host keychain launchers
  s1-secops-skills-plugin/    Distributable plugin bundle (all 8 skills)
  assets/                       Screenshots and images for documentation
```
