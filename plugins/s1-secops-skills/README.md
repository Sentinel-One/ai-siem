# SentinelOne AI Analyst: Claude Skills

A full-stack AI analyst for SentinelOne, built as a set of Claude skills, three MCP servers, and an operating persona (CLAUDE.md). Install once and Claude can hunt threats, triage alerts, write detections, deploy dashboards, author parsers, and build automation workflows, entirely from natural language.

> **Fastest way to get started: [Docker install](./docs/docker.md).** One image bundles all three MCPs, no host-level Node, Python, or `uv` required. Pull, paste a config block, install the plugin, done.
>
> **New here?** Start with the [Zero to Hero guide](./docs/zero-to-hero.md): a 20-minute onboarding walkthrough for customers and partners new to Claude Skills.

- [Architecture overview](#architecture-overview)
- [What's included](#whats-included)
- [PrincipalSOCAnalyst Project](#principalsocanalyst-project)
  - [What it delivers](#what-it-delivers)
  - [Setting up the PrincipalSOCAnalyst project](#setting-up-the-principalsocanalyst-project)
  - [How to activate in other environments](#how-to-activate-in-other-environments)
  - [What happens in a session](#what-happens-in-a-session)
- [What you can do](#what-you-can-do)
- [Behavioural baselining + anomaly detection](#behavioural-baselining--anomaly-detection)
- [Example questions](#example-questions)
- [Installing, upgrading, and configuration](#installing-and-upgrading)
- [Team VM deployment (s1-secops-mcp)](#team-vm-deployment-s1-secops-mcp)
- [Windsurf](#windsurf)
- [Documentation](#documentation)

---

## Architecture overview

The layers work together top-down. CLAUDE.md is the main instruction layer and decides what to do; it invokes skills as needed. For a whole-solution request the `sdl-solutions` umbrella skill runs first and orchestrates the primitive skills; the skills then reach live APIs through the MCP servers.

```
CLAUDE.md                  Main instruction layer: SOC Analyst persona, session protocol,
                           evidence rules, investigation workflow, classification gates.
                           Decides what to do and invokes skills as needed.
       │  invokes skills
       ▼
sdl-solutions              Umbrella orchestrator. On a "deploy / onboard / monitor a whole
                           solution" request it runs first, collects parameters, previews,
                           then drives the primitive skills below in dependency order.
       │  orchestrates
       ▼
Primitive skills (SKILL.md)  Procedural knowledge: confirmed API schemas, field requirements, patterns
  powerquery                 PowerQuery authoring and execution
  sdl-dashboard              Dashboard JSON authoring and deployment
  sdl-log-parser             Parser authoring and validation
  hyperautomation            Workflow JSON authoring and import
  sdl-api                    SDL log ingest and config file ops
  mgmt-console-api           Mgmt Console REST + UAM + Purple AI + HA
       │  call live APIs through
       ▼
MCP Servers                Live API access, outside the Cowork sandbox proxy
  s1-secops-mcp              PowerQuery, SDL, Mgmt Console REST, UAM, Hyperautomation
  purple-mcp                 Alert triage, Purple AI NLQ, Deep Visibility, assets, vulnerabilities
  threat-intel-mcp           External IOC enrichment (required for CRITICAL classification)
```

**CLAUDE.md** is the brain: it sets the operating persona and invokes skills as the task demands. **sdl-solutions** is the umbrella skill: for whole-solution work it runs first and orchestrates the primitive skills (PowerQuery, dashboard, parser, Hyperautomation, SDL API, Mgmt Console) in order, previewing before it deploys. **Skills** encode confirmed API behaviour, including field schemas validated against live tenants, so Claude doesn't guess field names, and they reach `*.sentinelone.net` through the **MCP servers**, which bypass the Cowork sandbox proxy. For a single query, dashboard, parser, or workflow, Claude calls the matching primitive skill directly without the umbrella.

Full architecture details: [docs/architecture.md](./docs/architecture.md)

---

## What's included

The plugin bundles every skill; installing it is sufficient. No individual skill setup needed.

| Skill | What it does |
|---|---|
| mgmt-console-api | Query and act on the Management Console: threats, alerts, agents, sites, RemoteOps, Deep Visibility, Hyperautomation, Purple AI, UAM. Includes the source-agnostic behavioural baselining + anomaly detection pipeline (`baseline_anomaly.py`) |
| powerquery | Write, debug, and run PowerQuery for threat hunting, STAR detection rules, SDL dashboards, and statistical baseline / anomaly detection rule bodies |
| sdl-api | Ingest events, run queries, and manage configuration files (parsers, dashboards, lookups) via the Singularity Data Lake API |
| sdl-dashboard | Design, author, and deploy SDL dashboards: panels, tabs, parameters, and full dashboard JSON. See [docs/sdl-dashboard.md](./docs/sdl-dashboard.md) for all supported panel types |
| sdl-log-parser | Author and validate SDL log parsers for any log format, with OCSF field mapping by default |
| hyperautomation | Design and generate Hyperautomation workflow JSON, with optional live console import |
| sdl-solutions | Deploy packaged, repeatable SDL solutions into a customer site from one short prompt: data source onboarding (raw stream to OCSF + enrichment + dashboard + MITRE detections + threat-response flow) , asset enrichment of raw logs (device/user context from the Asset Inventory), UEBA behavioural anomaly detection (z-score baselining of any signal), and per-device ingest health monitoring (anomaly detection on a 7-day hour-of-day baseline: volume spike/drop, ingest lag, ingest loss, and parser drift, with a dashboard and email notifications). Orchestrates the skills above |

---

## PrincipalSOCAnalyst Project

`CLAUDE.md` at the root of this repo transforms Claude into a **Principal SOC Analyst**: a structured investigator that runs the same enrichment, correlation, and reasoning process a senior analyst would, on every alert, every time. Set it up once as a named Cowork project and every session starts fully briefed.

### What it delivers

| Outcome | How |
|---|---|
| **Reduce L1 SOC workload by 70%+** | Automated triage, mandatory threat-intel enrichment on every IOC, and verdict generation eliminate repetitive alert investigation. L1 analysts focus on exceptions, not routine. |
| **Elevate every analyst to principal grade** | Junior analysts get the same structured investigation framework, enrichment depth, and analytical reasoning that only senior staff possess today. |
| **External threat intelligence on every IOC** | Mandatory enrichment of every IP, domain, hash, and URL through the configured threat-intel MCP. The default bundle ships VirusTotal (70+ AV engines, threat-actor attribution, full infrastructure mapping); swap in any equivalent provider (Recorded Future, Mandiant Advantage, OpenCTI, MISP, etc.) and the workflow is unchanged. |
| **Mean investigation time under 5 minutes** | Investigation workflows that take 45-60 minutes manually compress to under 5 minutes. Continuous hunting catches threats between analyst shifts. |
| **Full data estate coverage** | Queries OCSF-normalised logs, non-OCSF vendor logs, and raw syslog. Discovers field schemas dynamically at session start, with no hardcoded assumptions about what sources are present. |
| **Fast-track detection creation** | Natural language detection authoring across any data source. Recommends new STAR rules and custom detections as threats are identified during investigation. |
| **Deliver the capability today** | Purple AI becomes even more powerful when orchestrated through this multi-layer architecture, combining deep enrichment, cross-source correlation, and external threat intelligence in every investigation. |
| **Federated search across the data estate** | Search, correlate, and hunt across endpoint, network, identity, and cloud log sources via MCP/API in a single session. Cross-source correlation connects signals that are invisible in any one source. |
| **Every alert arrives with business context** | Asset and identity enrichment attaches device role, criticality, and account context to each alert automatically, so the queue self-prioritises by business impact. A medium on a domain controller outranks a critical on a sandbox, with no manual lookup. |
| **New detections the same day a threat emerges** | When a new TTP or campaign breaks, its behaviour is turned into a validated, MITRE-mapped PowerQuery or STAR detection and deployed in hours, not the weeks a hand-authored rule normally takes. |
| **Onboard any new data source in minutes** | A raw, unreadable stream becomes OCSF-normalised, parsed, dashboarded, and detection-covered in a single session. Coverage stops being gated by quarters of engineering backlog. |
| **Find threats hiding in app and business logs** | Detection and investigation reach beyond traditional security telemetry into custom application and business logs, surfacing fraud and abuse that no SIEM was watching. Engineers, not only analysts, can run it. |
| **Proactive anomaly detection at machine speed** | Source-agnostic behavioural baselining flags deviations with no known signature (impossible travel, off-hours access, first-seen processes, beaconing), catching novel and insider threats between analyst shifts. |
| **Lower cost than the legacy SIEM model** | The Singularity Data Lake keeps all data hot and searchable at flat-rate, indexless economics rather than per-gigabyte ingest pricing, and the bring-your-own-AI run cost is negligible against analyst hours and SIEM licensing. |

**Key metrics:** `< 5 min` mean investigation time · `100%` IOC enrichment coverage · `Real-time` MITRE ATT&CK mapping · `70%+` L1 capacity freed · `minutes` to onboard a new source · `hours` from emerging threat to live detection

---

### Setting up the PrincipalSOCAnalyst project

**Easiest path: [Docker install](./docs/docker.md).** One image at `ghcr.io/pmoses-s1/s1-mcps` bundles all three MCPs (s1-secops-mcp, purple-mcp, virustotal-mcp), version-locked at a known good combo. No host-level Node, Python, or `uv` required. Works the same on macOS, Windows, and Linux, and on locked-down machines where IT policy blocks `npm install -g` or `pip install`.

Four steps:

1. `docker pull ghcr.io/pmoses-s1/s1-mcps:1.2.2`
2. Paste the [Docker MCP config](./docs/docker.md#step-2-configure-mcp-servers) into `claude_desktop_config.json` and replace the placeholders with your tokens and region URLs.
3. Install the [`.plugin` file](./dist/) via Cowork → Customize → Browse plugins.
4. Create a Cowork project named `PrincipalSOCAnalyst`, open it, and run `smoke test s1 skills` to verify.

Full Docker reference (prerequisites, credential keys, troubleshooting, upgrades): [docs/docker.md](./docs/docker.md)

**Prefer not to use Docker?** The MCPs also run directly via `npx` (s1-secops-mcp, virustotal) and `uvx` (purple-mcp). See [docs/installation.md](./docs/installation.md) for the host-runtime path.

**Start a session**

Open the **PrincipalSOCAnalyst** project and start a new chat. Claude reads `CLAUDE.md` automatically and immediately runs:
- Data source enumeration: discovers every log source present in your SDL
- Alert triage: pulls open alerts in parallel while enumeration runs

> **Tip:** Keep a `reports/` subfolder inside your project folder. When Claude generates a SOC report, save it there so it persists across sessions.

---

### How to activate in other environments

**Claude Code (terminal)**
```bash
cd ~/path/to/ai-siem   # any folder containing CLAUDE.md
claude                        # CLAUDE.md is read automatically on startup
```

**Any Claude session**

Copy the contents of `CLAUDE.md` into Settings → Custom Instructions (or equivalent system prompt field) of any Claude session that has the plugin installed.

---

### What happens in a session

**Session initialisation (automatic, every session)**
1. Enumerates all live `dataSource.name` values in SDL, confirming which log sources are actually present and queryable
2. Runs alert triage in parallel, pulling open/critical alerts while enumeration executes
3. For any non-OCSF source discovered, runs schema discovery before writing any query

**Investigation workflow**
- Triage and context gathering: alert details, analyst notes, MDR verdicts, asset criticality
- Threat-intel enrichment: every IP, domain, hash, and URL enriched through the configured threat-intel MCP (VirusTotal in the default bundle) before any verdict; no finding classified CRITICAL without independent TI confirmation
- Infrastructure pivoting: C2 infrastructure, threat actor attribution, SSL certificate reuse, sibling domains, dropped payloads, execution chain reconstruction
- Cross-source correlation: IOC found in any source is immediately hunted across all other connected sources
- Anomaly analysis: every query result checked for frequency, timing, geolocation, baseline, volume, new entity, privilege, and chain anomalies
- MITRE ATT&CK mapping: every finding mapped to tactic and technique; kill chain gaps identified
- Composite risk scoring: cross-source anomaly scores determine escalation priority

**Report generation**

At the end of any significant investigation, ask Claude to produce a SOC report. It generates a structured `.docx` file containing: executive summary, incident timeline, affected assets, full IOC table with threat-intel verdicts, threat actor profile, MITRE ATT&CK mapping, root cause analysis, threat-intel summary, actions taken, and recommendations.

**Example session starters**
```
Start a new investigation session
```
```
Triage today's open alerts and flag anything requiring immediate action
```
```
Investigate alert ID <id>: full enrichment, verdict, and recommended response
```
```
Hunt for lateral movement across all connected sources in the last 24 hours
```
```
Write a SOC Leader report for this investigation as a Word document
```

---

## What you can do

These skills turn Claude into a hands-on SentinelOne analyst and engineer. Once the plugin is installed and credentials are configured, you can talk to your tenant in plain English. Claude handles the API calls, query writing, and JSON authoring and explains what it found or built.

**Threat hunting and investigation**: ask Claude to hunt for specific TTPs, IOCs, or behaviours across your SDL telemetry. It writes and runs PowerQuery automatically, pages through results, and summarises findings. You can go from a vague question ("any PowerShell reaching out to the internet?") to a ranked table of suspicious endpoints in one message.

**Alert and threat management**: list open threats, triage UAM alerts, add analyst notes, change status, or isolate an endpoint, all by describing what you want. Claude maps your intent to the right Management Console API calls and confirms what it did.

**Dashboard authoring**: describe the panels you want ("a SOC overview with threat timeline, top noisy endpoints, and outbound connection breakdown") and Claude produces deployment-ready SDL dashboard JSON, with queries validated against your tenant before it deploys.

**Log parser authoring**: paste a raw log sample and Claude writes a complete SDL parser definition, maps fields to OCSF, validates it against the parser engine, ingests a test event, and confirms the fields appear correctly, end to end in one session.

**Automation and response**: describe a response workflow in natural language ("when a high-severity alert fires on a server, isolate the endpoint, create an IOC for any hash in the alert, and notify the team") and Claude generates the Hyperautomation workflow JSON ready to import.

**Data lake operations**: ingest custom telemetry, list and manage configuration files, deploy or update parsers and dashboards, and run arbitrary queries through the SDL API.

**Behavioural baselining and anomaly detection**: build per-(principal, action) statistical baselines on any data source (Okta, FortiGate, CloudTrail, SentinelOne, Mimecast, Zeek, or anything else ingested into SDL) and surface deviations automatically. The skill auto-discovers the right principal field (user, host, IP, role) and action field (event.type, activity_name, action) per source so you don't hardcode field names. See [Behavioural baselining](#behavioural-baselining--anomaly-detection) below.

---

## Behavioural baselining + anomaly detection

A source-agnostic pipeline for building behavioural baselines and surfacing statistical anomalies
(SPIKE / DROP / SILENT / NEW-BEHAVIOR) on any log source ingested into SDL, baselined per
(principal, action) with day-of-week stratification and z-scoring. Run it interactively for a hunt,
or deploy it as a persisted baseline + scheduled rule + nightly refresh + dashboard.

Full guide, including the `baseline_anomaly.py` CLI, the three production failure modes it handles,
interactive and Cowork-chat usage, and productionising as a STAR / PowerQuery Alert rule, is in
[docs/solutions/ueba-anomaly-detection.md](./docs/solutions/ueba-anomaly-detection.md). PQ building
blocks are in `powerquery/examples/behavioral-baselines.md`.

---

## Example questions

These are real questions you can ask. Claude will pick the right skill automatically.

### Threat hunting

- *"Hunt for any process that opened a connection to a non-RFC1918 IP in the last 7 days; show me top endpoints by hit count"*
- *"Write a PowerQuery that finds lsass memory reads by non-system processes"*
- *"Are there any HIFI indicators for Mimikatz or BloodHound on my tenant in the last 30 days?"*
- *"Find PowerShell scripts that encoded a Base64 command, group by endpoint"*
- *"Show me the top 20 destination IPs for outbound connections from Windows servers this week"*
- *"Write a STAR detection rule that fires when a script interpreter spawns a network tool"*

### Behavioural baselining and anomaly detection

- *"Build a 30-day behavioural baseline for Okta and show me anomalies for today"*
- *"Run a day-of-week-stratified baseline on FortiGate and surface devices with unusual traffic patterns"*
- *"Which CloudTrail roles are silent today that were active every day last week?"*
- *"Find users in Google Workspace whose activity volume today is more than 3 standard deviations from their typical day"*
- *"Detect anomalies across all my SaaS sources and rank them by composite z-score"*
- *"Establish a baseline for SentinelOne process activity per endpoint and find spikes since this morning"*
- *"Build me a STAR rule body that uses a stored baseline lookup table to detect login spikes"*

### Alert and threat management

- *"List all open threats created in the last 24 hours, sorted by confidence"*
- *"Show me unresolved UAM alerts with severity High or Critical from today"*
- *"Add a note to alert ID `abc123` saying it was reviewed and is a false positive"*
- *"Isolate endpoint `DESKTOP-XYZ` and create an IOC for its SHA1 hash `aabbcc...`"*
- *"How many threats were mitigated vs unresolved this week, broken down by site?"*
- *"Get me the details for alert ID `xyz` including any associated agent and threat info"*

### Dashboards

- *"Build me a SOC overview dashboard with: threat timeline by confidence, top 10 noisiest endpoints, failed logins over time, and outbound connection breakdown by direction"*
- *"Create a Purple AI usage dashboard showing queries by analyst and a timeline of usage"*
- *"Add a honeycomb panel to my dashboard showing file creation activity by endpoint"*
- *"Build an O365 tab for my audit dashboard with login failures by user and country"*
- *"Deploy my dashboard JSON to SDL at `/dashboards/soc-overview`"*

### Log parsers

- *"Write an SDL parser for this Palo Alto syslog sample: `<paste log>`"*
- *"I have a CEF log from CrowdStrike: create a parser with OCSF field mapping"*
- *"My FortiGate parser isn't extracting the destination IP correctly, here's the JSON: `<paste parser>`"*
- *"Validate my parser and ingest a test event to confirm the fields look right"*

### Data lake operations

- *"List all configuration files on my SDL tenant under `/dashboards/`"*
- *"Ingest this JSON array of events into SDL with the source name `custom-app`"*
- *"Run this PowerQuery against my tenant and return the results as a table: `<query>`"*
- *"Download the current version of my `/logParsers/fortinet-fortigate` parser"*

### SOC investigation and triage

- *"Start a new investigation session: enumerate live data sources and pull today's open alerts"*
- *"Triage alert ID `abc123`: get the full details, check notes and history, enrich any IOCs through the threat-intel MCP, and give me a verdict"*
- *"Enrich this file hash `aabbccdd...`: detection ratio, behavioural analysis, C2 infrastructure, and threat actor attribution"*
- *"Pivot on IP `1.2.3.4`: what malware communicates with it, what domains resolve to it, and is it associated with any APT group?"*
- *"Cross-correlate this IOC across all connected data sources: check firewall, Okta, Zeek, and CloudTrail for any trace of `1.2.3.4`"*
- *"Check endpoint `DESKTOP-XYZ` for anomalies: run the full anomaly checklist across process, network, and identity data"*
- *"Apply the MITRE ATT&CK framework to what we've found so far: what techniques are mapped and where are the detection gaps?"*
- *"Score the current investigation using the cross-source anomaly framework and tell me if we should escalate to IR"*

### Reporting

- *"Write a SOC Leader report for this investigation as a Word document: executive summary, incident timeline, IOC table with threat-intel verdicts, MITRE mapping, root cause, and recommendations"*
- *"Generate a weekly threat summary for SOC leadership covering alerts triaged, true positives confirmed, top IOCs, and any active campaigns"*
- *"Produce an IOC table for all indicators found in the last 24 hours, including threat-intel MCP verdict, detection ratio, and threat actor attribution"*
- *"Give me an executive-level summary of the firewall beaconing pattern we found: one paragraph, business risk focus, no jargon"*

### Hyperautomation workflows

- *"Build a workflow that isolates an endpoint and sends a Slack notification when a Ransomware indicator fires"*
- *"Create a scheduled workflow that runs every morning and sends a summary of overnight threats by email"*
- *"Write a webhook workflow that creates an IOC from an incoming threat intel feed payload"*
- *"Design a playbook: on a Critical alert, add a note, escalate the site status, and page the on-call analyst"*

### SDL solution deployment (sdl-solutions)

Whole solutions deployed into a customer site from one short prompt. The skill runs a short
parameter interview, previews the rendered config, then deploys and validates.

**Data source onboarding** (raw stream to OCSF, enrichment, dashboard, MITRE detections, threat-response flow). Full guide: [docs/solutions/data-source-onboarding.md](./docs/solutions/data-source-onboarding.md).

- *"Onboard the cisco_meraki logs on the Acme site"*
- *"Bring our new FortiGate firewall source into AI SIEM and build detections and a dashboard"*
- *"Set up detections and a dashboard for the Okta source on the Acme site"*
- *"Onboard our Zscaler logs end to end: OCSF parser, asset-enriched dashboard, MITRE-mapped detections, and a SOC threat-response playbook"*
- *"Onboard cisco_meraki and add the response automation that VirusTotal-checks the destination, then blocks the IOC and quarantines the source host on a malicious verdict"*

**UEBA behavioural anomaly detection** (baseline ANY signal, security or not, and flag z-score deviations: SPIKE, DROP, SILENT, NEW-BEHAVIOR). Full guide: [docs/solutions/ueba-anomaly-detection.md](./docs/solutions/ueba-anomaly-detection.md).

- *"Run a behavioural baseline on Okta and tell me what's anomalous"*
- *"Deploy UEBA anomaly detection for FortiGate on the Acme site"*
- *"Monitor the Avelios Medical app for unusual user behaviour"*

**Asset enrichment of raw logs** (device/user context from the Asset Inventory). Full guide: [docs/solutions/asset-enrichment.md](./docs/solutions/asset-enrichment.md).

- *"Deploy the asset enrichment solution for Acme on the Acme site"*
- *"Enrich the firewall logs with device and user info"*
- *"Add asset enrichment, query-time only, no parser"*

When you ask to add an enrichment, it is a single multi-select prompt: pick any of Device,
User/AD, Vulnerabilities, Misconfigurations, Open alerts, or Cloud context. Example:

- *"Add enrichment: device context and open vulnerabilities, keyed on hostname"*
- *"Enrich each event with user AD groups and privilege, and the device criticality"*

**Ingest health monitoring (per device)** (per-firewall/endpoint/server anomaly detection on a 7-day hour-of-day baseline: volume spike/drop, ingest lag, ingest loss, and parser drift, with email on every failure). Full guide: [docs/solutions/ingest-health-monitoring.md](./docs/solutions/ingest-health-monitoring.md).

- *"Deploy ingest health monitoring per device on the Acme site"*
- *"Monitor ingest per firewall and endpoint and email soc@acme.com on any failure"*
- *"Alert me when a specific firewall or endpoint stops sending logs"*

**Detection exclusions** (suppress known-good noise in a STAR rule: a single-event rule with an inline hardcoded exclusion list, or a scheduled rule with a CSV lookup anti-join plus an effectiveness dashboard; the skill asks which rule type first). Full guide: [docs/solutions/scheduled-detection-exclusions.md](./docs/solutions/scheduled-detection-exclusions.md).

- *"Exclude my engineering team from the encoded-PowerShell detection"*
- *"Stop my Akamai DNS detection from alerting on our scanner subnets and corporate domains, here's the list"*
- *"Add a single-event STAR detection for encoded PowerShell that ignores our DevOps service accounts"*

**Risk-Based Alerting (RBA)** (publish noisy observations as low-noise risk events into a `risk` index, accumulate risk per user/host object amplified by asset risk factors, and fire one high-fidelity alert when a 24h cumulative-score or 7d multi-MITRE-tactic threshold is crossed). Full guide: [docs/solutions/risk-based-alerting.md](./docs/solutions/risk-based-alerting.md).

- *"Deploy risk-based alerting for users and hosts on the Acme site"*
- *"Set up RBA: score encoded PowerShell, recon, LOLBins, and log clearing, and alert when a user accumulates enough risk across tactics"*
- *"Roll out RBA with asset-criticality risk factors and a risk leaderboard dashboard"*

For the full per-solution breakdown, outcomes, and more example prompts, see the solution skill's own README: [skills/sdl-solutions/README.md](./skills/sdl-solutions/README.md).

---

## Installing and upgrading

Two install paths, both four steps from zero to a working session:

- **[Docker (recommended, easiest)](./docs/docker.md)**: one image bundles all three MCPs, no host-level Node, Python, or `uv` required. Pinned semver tags for reproducible installs. Works on locked-down machines where IT policy blocks `npm install -g` or `pip install`.
- **[npx/uvx (host runtime)](./docs/installation.md)**: MCP servers run directly on the host via `npx` and `uvx`. Lighter on disk, slightly faster per-session startup, but requires Node 18+ and `uv` to be installable.

For a team that wants one shared `s1-secops-mcp` instance instead of an install per laptop, see **[Team VM deployment](./docs/vm-deployment.md)** (v1.1.0+).

Upgrades:

- **Docker**: bump the tag in `claude_desktop_config.json` (e.g. `:1.2.1` to `:1.2.2`) and restart Claude Desktop. The new image pulls on first launch.
- **npx/uvx**: effectively free; `npx -y` and `uvx` re-resolve the MCP servers to the latest published version on each Claude Desktop launch.
- **Plugin**: Plugin: download the new .plugin from s1-secops-skills/dist/, open Cowork → Customize → Browse plugins, upload, click Replace when prompted.


---

## Configuration

See [docs/installation.md#configuration](./docs/installation.md#configuration) for credential setup, the full key reference, and resolution order.

---

## Team VM deployment (s1-secops-mcp)

Want one shared `s1-secops-mcp` instance for the whole team instead of an install per laptop? `s1-secops-mcp` v1.1.0+ supports it natively. See the dedicated guide:

**[docs/vm-deployment.md](./docs/vm-deployment.md)**: one-line install, per-user bearer tokens, Caddy TLS, SIGHUP-reloadable rotation, audit logs.

---

## Windsurf

This repo includes Windsurf workflow files in `.windsurf/workflows/`. Each workflow is a thin pointer that directs Cascade to read the canonical `SKILL.md` and reference docs in the matching skill folder, with no duplicated content.

- `sentinelone-api.md`: Management Console API (agents, threats, alerts, sites, Purple AI, UAM).
- `powerquery.md`: PowerQuery authoring, debugging, and detection rules.
- `sdl-api.md`: Singularity Data Lake API (ingest, query, config files).
- `sdl-log-parser.md`: SDL log parser authoring with OCSF mapping.

---

## Documentation

| Doc | Contents |
|---|---|
| [docs/zero-to-hero.md](./docs/zero-to-hero.md) | Onboarding guide for customers and partners new to Claude Skills: concepts, install, first session, common workflows, troubleshooting |
| [docs/docker.md](./docs/docker.md) | **Recommended install path.** One Docker image bundles all three MCPs, no host-level Node/Python/uv. Four steps from zero to a working session, with troubleshooting and upgrade guidance |
| [docs/installation.md](./docs/installation.md) | Alternative host-runtime install via `npx`/`uvx`, plus credential config, project creation, and upgrade paths |
| [docs/vm-deployment.md](./docs/vm-deployment.md) | Team VM deployment for `s1-secops-mcp` (v1.1.0+): one-line install, per-user bearer tokens, TLS, audit logs |
| [docs/architecture.md](./docs/architecture.md) | How the three layers fit together, data flow, auth patterns, sandbox proxy explanation |
| [docs/skills.md](./docs/skills.md) | Per-skill capability reference, key scripts, and field requirements |
| [docs/mcp-tools.md](./docs/mcp-tools.md) | All s1-secops-mcp and purple-mcp tools with usage notes and which to use when |
| [docs/credentials.md](./docs/credentials.md) | Every credential key, where to find it, full `claude_desktop_config.json` reference |
| [docs/testing.md](./docs/testing.md) | Full test coverage matrix, MCP tool validation results, and confirmed API field requirements |
| [docs/sdl-dashboard.md](./docs/sdl-dashboard.md) | All supported panel types and dashboard features with confirmed JSON examples |
| [docs/solutions/data-source-onboarding.md](./docs/solutions/data-source-onboarding.md) | SDL Solutions: onboard a raw source end to end (OCSF, enrichment, dashboard, detections, threat-response flow) from one prompt |
| [docs/solutions/asset-enrichment.md](./docs/solutions/asset-enrichment.md) | SDL Solutions: enrich raw logs with device/user/vuln/alert context from the Asset Inventory, with prompt examples |
| [docs/solutions/ueba-anomaly-detection.md](./docs/solutions/ueba-anomaly-detection.md) | SDL Solutions: baseline ANY signal per (action, principal) and detect z-score anomalies (SPIKE/DROP/SILENT/NEW), deployed as a baseline lookup, scheduled rule, nightly refresh, and dashboard |
| [docs/solutions/ingest-health-monitoring.md](./docs/solutions/ingest-health-monitoring.md) | SDL Solutions: per-device ingest health (per firewall/endpoint/server) on a 7-day hour-of-day baseline: volume spike/drop, ingest lag, ingest loss, parser drift, with a dashboard and email notifications |
| [docs/solutions/scheduled-detection-exclusions.md](./docs/solutions/scheduled-detection-exclusions.md) | SDL Solutions: suppress known-good noise in a STAR Custom Detection rule, built as a single-event rule (inline hardcoded exclusion) or a scheduled rule (CSV lookup anti-join + effectiveness dashboard); asks the rule type first |
| [docs/solutions/risk-based-alerting.md](./docs/solutions/risk-based-alerting.md) | SDL Solutions: Risk-Based Alerting in SDL, publish noisy observations as risk events into a `risk` index, accumulate risk per user/host object amplified by asset risk factors, and fire one high-fidelity alert on a 24h cumulative-score or 7d multi-MITRE-tactic threshold; deploys contributors, factor table, collector flow, four incident rules, and a dashboard |
| [docs/detection-rule-types.md](./docs/detection-rule-types.md) | The three STAR / Custom Detection rule types (single-event, multi-event correlation, scheduled PowerQuery): API shapes, when to use each, S1QL backslash escaping, and why asset enrichment is the prerequisite for asset-mapped alerts |
| [docs/detection-asset-binding.md](./docs/detection-asset-binding.md) | Which event attributes make STAR detection alerts auto-populate the Target Asset (device, identity, cloud), the tested per-type binding matrix, and how the asset enrichment solution supplies them |
| [mgmt-console-api/SKILL.md](./skills/mgmt-console-api/SKILL.md) | Deep reference: confirmed field schemas and required API parameters per endpoint |
| [mgmt-console-api/tests/README.md](./skills/mgmt-console-api/tests/README.md) | Reversible lifecycle test patterns and per-test field notes |
