# SentinelOne AI Analyst: Claude Skills

A full-stack AI analyst for SentinelOne, built as a set of Claude skills, three MCP servers, and an operating persona (CLAUDE.md). Install once and Claude can hunt threats, triage alerts, write detections, deploy dashboards, author parsers, and build automation workflows, entirely from natural language.

> **Fastest way to get started: [Quick start (Docker)](#1-quick-start-docker).** One image bundles all three MCPs, no host-level Node, Python, or `uv` required. Store your tokens in the OS keychain, point the config at the launcher, install the plugin, done. See [Installation](#installation) for both install paths.
>
> **Upgrading to 1.5.0?** It is a breaking release: no `credentials.json`, no HTTP transport, and a Docker launcher instead of `docker run -e`. Follow [docs/upgrading.md](./docs/upgrading.md#14x-to-150).
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
- [Installation](#installation)
  - [1. Quick start (Docker)](#1-quick-start-docker)
  - [2. Individual MCP / plugin / skill install](#2-individual-mcp--plugin--skill-install)
- [Windsurf](#windsurf)
- [Documentation](#documentation)

---

## Architecture overview

The layers work together top-down. CLAUDE.md is the main instruction layer and decides what to do; it invokes skills as needed. For a whole-solution request the `sdl-solutions` umbrella skill runs first and orchestrates the primitive skills; the skills then reach live APIs through the MCP servers.

```text
CLAUDE.md                       Main instruction layer: SOC Analyst persona, session protocol,
                                evidence rules, investigation workflow, classification gates.
                                Decides what to do and invokes skills as needed.
       │  invokes skills
       ▼
sdl-solutions                   Umbrella orchestrator for 10 packaged solutions. On a "deploy /
                                onboard / monitor a whole solution" request it runs first, collects
                                parameters, previews, then drives the primitive skills below in
                                dependency order.
soc-investigator                Investigation orchestrator: staged DFIR triage of an alert, or an
                                alert-agnostic SWEEP for MITRE-mapped TTPs, with verdict gates.
       │  orchestrates
       ▼
Primitive skills (SKILL.md)     Procedural knowledge: confirmed API schemas, field requirements, patterns
  powerquery          PowerQuery authoring and execution
  sdl-dashboard       Dashboard JSON authoring and deployment
  sdl-log-parser      Parser authoring and validation
  hyperautomation     Workflow JSON authoring, interaction forms, and import
  sdl-api             SDL log ingest and config file ops
  mgmt-console-api    Mgmt Console REST + UAM + Purple AI + HA
       │  call live APIs through
       ▼
MCP Servers                     Live API access, outside the Cowork sandbox proxy
  s1-secops-mcp                 PowerQuery, SDL, Mgmt Console REST, UAM, Hyperautomation
  purple-mcp                      Alert triage, Purple AI NLQ, Deep Visibility, assets, vulnerabilities, VT Intelligence search
  threat-intel-mcp                External IOC enrichment and pivots (required for CRITICAL classification); shares its VirusTotal key with purple-mcp
```

**CLAUDE.md** is the brain: it sets the operating persona and invokes skills as the task demands. **sdl-solutions** is the umbrella skill: for whole-solution work it runs first and orchestrates the primitive skills (PowerQuery, dashboard, parser, Hyperautomation, SDL API, Mgmt Console) in order, previewing before it deploys. **Skills** encode confirmed API behaviour, including field schemas validated against live tenants, so Claude doesn't guess field names, and they reach `*.sentinelone.net` through the **MCP servers**, which run on your machine, outside the Cowork sandbox proxy, and read credentials from the OS keychain. For a single query, dashboard, parser, or workflow, Claude calls the matching primitive skill directly without the umbrella.

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
| hyperautomation | Design and generate Hyperautomation workflow JSON, with optional live console import. Includes interaction forms: pause a run to collect structured input from a person, then branch on their answers |
| sdl-solutions | Deploy packaged, repeatable SDL solutions into a customer site from one short prompt: data source onboarding (raw stream to OCSF + enrichment + dashboard + MITRE detections + threat-response flow) , asset enrichment of raw logs (device/user context from the Asset Inventory), UEBA behavioural anomaly detection (z-score baselining of any signal), per-device ingest health monitoring (anomaly detection on a 7-day hour-of-day baseline: volume spike/drop, ingest lag, ingest loss, and parser drift, with a dashboard and email notifications), detection exclusions, Risk-Based Alerting, Detection as Code (author rules as TOML in Git and sync them to the Custom Detection API via CI), alert noise reduction (find and quiet the sources flooding the alert queue: an ingestion-filter recommendation, an auto-resolve flow, and a noise-vs-signal dashboard), custom detections with MITRE mapping (a watchdog flow that posts the alert with ATT&CK attached, since STAR rules cannot carry it), and query slicing (long-window PowerQuery as parallel time slices, merged). Ten solutions in all. Orchestrates the skills above |
| soc-investigator | Autonomous, staged DFIR investigation of SentinelOne alerts (SHORT / MEDIUM / LONG modes), plus SWEEP, an alert-agnostic hunt of a time window for MITRE-mapped TTPs, with tool discovery, interactive intake, a previewed plan, IOC enrichment, per-endpoint PowerQuery forensics, and optional third-party correlation and anomaly detection. Carries the evidence-discipline and verdict gates from the SOC Analyst standard and the SDL hunt-and-correlation method. Authored by Joel Mora |

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

Install the stack using either path in [Installation](#installation) (the Docker quick start is the fastest). Then set up the project:

1. In Cowork, create a new project named `PrincipalSOCAnalyst` and select a folder for it.
2. Drop a copy of [`CLAUDE.md`](./CLAUDE.md) into the folder. On the Docker path this is optional (the image ships a default persona); do it when you want to customise.
3. Confirm `s1-secops-skills` appears under Personal plugins and that `s1-secops-mcp`, `purple-mcp`, and your threat-intel MCP are green under MCP Servers.

**Start a session**

Open the **PrincipalSOCAnalyst** project and start a new chat. Claude reads `CLAUDE.md` automatically and immediately runs:

- Data source enumeration: discovers every log source present in your SDL
- Alert triage: pulls open alerts in parallel while enumeration runs

> **Tip:** Keep a `reports/` subfolder inside your project folder. When Claude generates a SOC report, save it there so it persists across sessions.

---

### How to activate in other environments

**Claude Code (terminal)**

```bash
cd ~/path/to/s1-secops-skills   # any folder containing CLAUDE.md
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

```text
Start a new investigation session
```

```text
Triage today's open alerts and flag anything requiring immediate action
```

```text
Investigate alert ID <id>: full enrichment, verdict, and recommended response
```

```text
Hunt for lateral movement across all connected sources in the last 24 hours
```

```text
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

**Keep them short.** The skills carry the constraints, so you do not have to. You never need to write "put the predicate in `where (...)`", "`now()` is nanoseconds", "use chained group not `estimate_distinct`", or "validate before deploying". Those are defaults. If you find yourself typing a constraint into a prompt, that is a bug in the skill, not a habit worth keeping, so raise it.

### Threat hunting

- *"Hunt for any process that opened a connection to a non-RFC1918 IP in the last 7 days; show me top endpoints by hit count"*
- *"Write a PowerQuery that finds lsass memory reads by non-system processes"*
- *"Are there any HIFI indicators for Mimikatz or BloodHound on my tenant in the last 30 days?"*
- *"Find PowerShell scripts that encoded a Base64 command, group by endpoint"*
- *"Show me the top 20 destination IPs for outbound connections from Windows servers this week"*
- *"Write a STAR detection rule that fires when a script interpreter spawns a network tool"*
- *"Impossible travel for the last 24 hours"* (geo-velocity in km/h, computed without the `| join` that silently reports an arbitrary pair)

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

UQL and inventory, on `| datasource` rather than the event stream:

- *"Build a SOC leader alert dashboard"*
- *"Build a vulnerability management dashboard"*
- *"Add an identity tab to `SOC Leader Alert Operations`"*
- *"Fix the broken panels on `<dashboard>`"* (reaches the XDR scope trap, the visual's column contract and hyphens in transposed values on its own)
- *"This panel is blank but the query returns rows"*
- *"Show me dashboards in this account that already use `| datasource`"*
- *"Exact distinct count of assets with alerts"*
- *"UQL query for open Critical alerts older than 14 days, grouped by owner"*

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

No alert ID at all (SWEEP mode, alert-agnostic):

- *"Find the MITRE TTPs in my logs from last week"*
- *"Sweep the last 7 days, no alert ID"*
- *"What techniques are in my telemetry, and which are just our BAS agent?"*

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

**Human in the loop (interaction forms).** Pause a running workflow, hand a person a structured form, and use their submitted values in later actions. Full reference: [hyperautomation/references/interaction-forms.md](./skills/hyperautomation/references/interaction-forms.md):

- *"Before isolating the host, ask the on-call analyst for a justification and a ticket number, and only isolate if they approve"*
- *"Pause the triage flow and let an analyst classify the alert and paste any extra IOCs they found"*
- *"Email the asset owner a form asking them to confirm they own the device and describe the activity"*
- *"Collect a maintenance window and target scope from the change approver before running the remediation"*

Requires platform S-26.2.6 or later. Field types are text, number, JSON, email, date, time and checkbox; there is no file upload. In the initial release the respondent needs view permission on the origin workflow, so this is for internal responders rather than arbitrary external recipients.

**Autonomous SOC (auto-investigate and respond).** The canonical investigate-decide-respond pattern, with reusable response snippets and dynamic dispatch, lives in [hyperautomation/references/autonomous-soc-template.md](./skills/hyperautomation/references/autonomous-soc-template.md):

- *"Build an autonomous SOC workflow that investigates and responds to alerts on its own"*
- *"Auto-triage every high/critical alert, add a verdict note, open a ticket, and remediate"*
- *"On a ransomware alert, isolate the device and notify the SOC; auto-close false positives and escalate real threats"*
- *"Let an LLM pick isolate vs quarantine vs close-as-false-positive per alert"*
- *"Auto-investigate every ransomware alert with Purple AI, then email me the findings and let me approve the remediation"*

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
- *"Monitor ingest per firewall and endpoint and email <soc@acme.com> on any failure"*
- *"Alert me when a specific firewall or endpoint stops sending logs"*

**Custom detection exclusions** (suppress known-good noise in a STAR rule, all three rule types: single-event and correlation rules with an inline hardcoded exclusion list, or a scheduled rule with a CSV lookup anti-join plus an effectiveness dashboard; the skill asks which rule type first). Full guide: [docs/solutions/custom-detection-exclusions.md](./docs/solutions/custom-detection-exclusions.md).

- *"Exclude my engineering team from the encoded-PowerShell detection"*
- *"Stop my Akamai DNS detection from alerting on our scanner subnets and corporate domains, here's the list"*
- *"Add a single-event STAR detection for encoded PowerShell that ignores our DevOps service accounts"*

**Risk-Based Alerting (RBA)** (publish noisy observations as low-noise risk events into a `risk` index, accumulate risk per user/host object amplified by asset risk factors, and fire one high-fidelity alert when a 24h cumulative-score or 7d multi-MITRE-tactic threshold is crossed). Full guide: [docs/solutions/risk-based-alerting.md](./docs/solutions/risk-based-alerting.md).

- *"Deploy risk-based alerting for users and hosts on the Acme site"*
- *"Set up RBA: score encoded PowerShell, recon, LOLBins, and log clearing, and alert when a user accumulates enough risk across tactics"*
- *"Roll out RBA with asset-criticality risk factors and a risk leaderboard dashboard"*

**Detection as Code (DaC)** (scaffold a Git + CI pipeline where detection engineers author rules as TOML, a pull request triggers validation and four-eyes review, and a merge syncs the changed rules to the Custom Detection Rule API; covers single-event, correlation, and scheduled rule types, with a zero-dependency TOML-to-API sync engine and CI for GitHub, GitLab, and Azure). Full guide: [docs/solutions/detection-as-code.md](./docs/solutions/detection-as-code.md).

- *"Set up detection as code for the Acme site"*
- *"Scaffold a DaC repo with GitHub Actions and sync the example rules"*
- *"Automate our detections as code: author in TOML, validate on PR, deploy on merge"*

**Custom detections with MITRE mapping** (solution for custom detections to carry MITRE mapping: STAR rules have no MITRE field, so the detection runs as a scheduled Hyperautomation watchdog that posts the UAM alert with ATT&CK tactics and techniques attached; render from a small JSON rule spec or convert an existing scheduled rule). Full guide: [docs/solutions/custom-detection-mitre-mapping.md](./docs/solutions/custom-detection-mitre-mapping.md).

**Query slicing** (run a long-window PowerQuery as parallel time slices through the LRQ API and merge the results: a 30-day aggregate in about 5 s instead of 21 to 40 s; zero-dependency runner). Full guide: [docs/solutions/query-slicing.md](./docs/solutions/query-slicing.md).

**Alert noise reduction** (find the sources and signatures flooding the alert queue, separate ingested and already-actioned noise from real detections, recommend an ingestion-severity filter, auto-resolve already-mitigated alerts with a note, and ship a noise-vs-signal dashboard; everything discovered live, nothing hardcoded). Full guide: [docs/solutions/alert-noise-reduction.md](./docs/solutions/alert-noise-reduction.md).

- *"My alert queue is flooded, reduce the noise"*
- *"Tune our alert ingestion and auto-close the already-blocked firewall alerts"*
- *"Run an alert optimization for the Acme site"*

For the full per-solution breakdown, outcomes, and more example prompts, see the solution skill's own README: [sdl-solutions/README.md](./skills/sdl-solutions/README.md).

---

## Installation

Everything installs from one Docker image. Pick the path that matches your scope: the whole stack, or a subset.

| Path | Best for | Time |
|---|---|---|
| **[1. Quick start (Docker)](#1-quick-start-docker)** | Most users, including locked-down machines. One image, all three MCPs, Docker plus a small launcher script on the host. | ~10 min |
| **[2. Individual MCP / plugin / skill install](#2-individual-mcp--plugin--skill-install)** | You want one MCP rather than all three, one skill rather than the whole plugin, or a Node install without Docker. | ~10 min |

Credentials are identical across both paths and live in the OS keychain, never in a file or a client config. What each value is, where to get it, and how it is protected: **[docs/credentials.md](./docs/credentials.md)**. To change, check, remove or rotate a stored value, or to switch consoles with a profile, see [Changing credentials in the keychain](./docs/credentials.md#changing-credentials-in-the-keychain): re-run `setup` (Enter keeps the current value), then restart the MCP client.

---

### 1. Quick start (Docker)

One image (`sentinelone/secops-mcps`) bundles all three MCPs (`s1-secops-mcp`, `purple-mcp`, `virustotal-mcp`), version-locked together. On the host you need Docker and the launcher script, which reads your OS keychain and hands the secrets to the container over stdin. It works the same on macOS, Windows, and Linux, including machines where IT policy blocks host-level package installs.

**Step 1: Install Docker**

Docker Desktop (macOS/Windows) or Docker Engine (Linux). Start it and confirm it is running:

```bash
docker info | head -3
```

**Step 2: Install the launcher and connect Claude Desktop (one command)**

macOS or Linux, in Terminal:

```bash
mkdir -p ~/.local/bin && curl -fsSL https://raw.githubusercontent.com/Sentinel-One/ai-siem/main/mcp/docker/s1-secops-mcp-launch.sh -o ~/.local/bin/s1-secops-mcp-launch.sh && sh ~/.local/bin/s1-secops-mcp-launch.sh install
```

Windows, in PowerShell:

```powershell
$f = "$env:TEMP\s1-secops-mcp-launch.ps1"; Invoke-WebRequest https://raw.githubusercontent.com/Sentinel-One/ai-siem/main/mcp/docker/s1-secops-mcp-launch.ps1 -OutFile $f -UseBasicParsing; powershell -NoProfile -ExecutionPolicy Bypass -File $f install
```

Already cloned this repo? Run `sh mcp/docker/s1-secops-mcp-launch.sh install` from the repo root instead (Windows: `powershell -NoProfile -ExecutionPolicy Bypass -File mcp\docker\s1-secops-mcp-launch.ps1 install`).

`install` does the whole setup and is safe to re-run:

- copies the launcher to `~/.local/bin/` (Windows: `%USERPROFILE%\bin\`), outside `~/Documents`, `~/Desktop` and `~/Downloads`, where macOS stops Claude Desktop from running scripts;
- adds the three MCP servers to your Claude Desktop config with your real home path filled in, keeps every other server and setting, and saves a backup of the old file next to it;
- pulls `sentinelone/secops-mcps:1.5.3`;
- asks for your credentials if none are stored yet, and stores them in the macOS login keychain, the Linux Secret Service or Windows Credential Manager (service `sentinelone-mcp`). Nothing is typed into a file.

Where to get each value it asks for:

| Name | What it is | Where to get it |
|---|---|---|
| `S1_CONSOLE_URL` | Your console URL | e.g. `https://usea1-yourorg.sentinelone.net` |
| `S1_CONSOLE_API_TOKEN` | Mgmt Console API token | Settings → Users → Service Users → Create New Service User ([guide](https://community.sentinelone.com/s/article/000005291)) |
| `S1_HEC_INGEST_URL` | Ingest host for your region | [Endpoint URLs by Region](https://community.sentinelone.com/s/article/000004961) |
| `S1_HEC_TOKEN` | SDL Log Write Key. Optional: only raw log ingest needs it | Console → Singularity Data Lake → API Keys → Log Write Key. No API mints one |
| `S1_SCOPE` | Optional default `S1-Scope` for SDL calls, needed when the token spans several accounts or sites: `<accountId>` or `<accountId>:<siteId>` | Account and site ids from `GET /web/api/v2.1/accounts` and `/web/api/v2.1/sites` |
| `VIRUSTOTAL_API_KEY` | VirusTotal API key (free tier is fine). Serves both the VirusTotal MCP and purple-mcp's threat intelligence tools | [virustotal.com/gui/my-apikey](https://www.virustotal.com/gui/my-apikey) |

To change a value later, run `~/.local/bin/s1-secops-mcp-launch.sh setup` (Enter keeps the current value). With Node installed, `s1-secops-mcp setup` does the same and verifies each value by reading it back; `s1-secops-mcp status` shows where each value resolves from, masked. Coming from a `credentials.json`? Run `s1-secops-mcp setup --import-json /path/to/credentials.json`, check `status`, then delete the file.

> **IOC writes:** `/threat-intelligence/iocs` refuses a token whose user spans several accounts (HTTP 403, code 4030010). Use a console API token minted at a single account or site; store it in its own keychain profile (`s1-secops-mcp setup --profile <name>`) and run a second MCP entry with `S1_PROFILE=<name>` (or make that token your default).

> **On `S1_HEC_TOKEN`:** the console API token does not work for raw log ingest. The write key is bound to one account or site, and a key minted for a different scope still returns `200 Success` while discarding every event. Read an event back before trusting an ingest.

**Step 3: Restart Claude Desktop**

Quit Claude Desktop completely (macOS: Cmd+Q; Windows: also quit it from the system tray) and open it again. Claude Desktop starts the three MCPs itself, one container each, and removes them when it quits.

> **Do I start the MCPs myself, or from Docker Desktop?** No. Docker Desktop only needs to be running. The containers you see in Docker Desktop while Claude is open are the ones Claude Desktop started through the launcher; starting the image from Docker Desktop gives you a container with no credentials and no connection to Claude.

<details>
<summary>Editing the config yourself, or using another MCP client</summary>

`~/.local/bin/s1-secops-mcp-launch.sh config` prints the three entries with this machine's real path, ready to paste into `claude_desktop_config.json` (macOS: `~/Library/Application Support/Claude/`; Windows: `%APPDATA%\Claude\`, or `%LOCALAPPDATA%\Packages\Claude_<id>\LocalCache\Roaming\Claude\` for a fresh install from the claude.ai installer, which is an MSIX package and reads only that copy) or any other MCP client. Do not type the path by hand: the config is JSON, which does not expand `~`, `$HOME` or `%USERPROFILE%`, so a path such as `/Users/you/...` must be your exact home folder. On Windows, run the same with `powershell -NoProfile -ExecutionPolicy Bypass -File $HOME\bin\s1-secops-mcp-launch.ps1 config`.

`install` and `config` take the same options: `--image IMG` to pin another tag, `--profile P` for a non-default keychain profile, `--output-dir DIR` so bulk results written with `outputFile` land in a folder you can open (macOS/Linux mount it at the same path in the container; Windows mounts it at `/output`), and `--claude-md FILE` to use your own CLAUDE.md. `install --config-path FILE` writes a config somewhere other than Claude Desktop's. On Windows the options are `-Image`, `-Profile`, `-OutputDir`, `-ClaudeMd` and `-ConfigPath`.

In a hand-written entry, launcher options (`--image`, `--profile`) go **before** the server name: everything after the server name is passed to the server inside the container, which rejects an unknown argument.

</details>

> **Do not put tokens in the MCP config, and do not use `docker run -e`.** MCP client configs are plaintext, and `-e` values show in `docker inspect`. The same applies to `~/.claude.json`, `.mcp.json`, Cursor, Windsurf and Zed. See [docs/credentials.md](./docs/credentials.md#mcp-client-configs-are-not-a-secret-store).

**Step 4: Install the plugin (all eight skills)**

Download the latest `s1-secops-skills-v*.plugin` from [ai-siem `plugins/s1-secops-skills/dist/`](./dist/). In Claude Desktop: **Cowork → Customize → Browse plugins**, then upload the `.plugin` file. All eight skills install in one step.

Then create a Cowork project named `PrincipalSOCAnalyst` and select a folder for it. The Docker image ships a default CLAUDE.md, so dropping your own [`CLAUDE.md`](./CLAUDE.md) into the folder is only needed if you want to customise the persona.

**Verify (tested)**

In the `PrincipalSOCAnalyst` project, start a session and run:

```text
smoke test s1 secops skills
```

Claude checks all three MCPs, confirms each skill is loaded, and reports any missing credential or unreachable endpoint. You can also test the image straight from a terminal, no Claude Desktop required:

```bash
docker run -i --rm sentinelone/secops-mcps:1.5.3 help    # lists the three bundled servers
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"smoke","version":"0.1"}}}' \
  | ~/.local/bin/s1-secops-mcp-launch.sh s1-secops-mcp
```

The second command returns one JSON line with `serverInfo.name = "s1-secops-mcp-server"` and `version = "1.5.3"`, and stderr shows `Tools: 35 registered` plus `configured` for each surface whose values are in the keychain.

**Troubleshooting**

| Symptom | Fix |
|---|---|
| MCP shows red in Cowork → MCP Servers | Confirm Docker is running: `docker info \| head -3`. Start Docker Desktop, then restart Claude Desktop. |
| `Cannot connect to the Docker daemon` in the logs | Docker Desktop is not running. |
| `Couldn't start for Cowork and Code sessions. Error: Request timed out` (`shared-pool`) in the MCP log | On Windows, update the launcher: run the Step 2 command again. Launchers before this release held each request from Claude Desktop until it closed the connection, so the server answered only after Claude had given up (in the log, `Message from server: id=0 result` comes right after `notifications/cancelled`). If it persists with the current launcher, Claude Desktop's own readiness timeout may be involved ([anthropics/claude-code#92758](https://github.com/anthropics/claude-code/issues/92758)): restart Claude Desktop and open a new Cowork session. |
| `/bin/sh: .../s1-secops-mcp-launch.sh: Operation not permitted` in the MCP log (macOS) | The config points at a launcher under `~/Documents`, `~/Desktop` or `~/Downloads`, where macOS blocks Claude Desktop's shell from running it. Run the Step 2 command again: `install` copies the launcher to `~/.local/bin/` and rewrites the config. |
| `ENOENT`, `No such file or directory` or `spawn ... s1-secops-mcp-launch` in the MCP log | The `command` path in the config does not exist, usually a hand-typed `/Users/you/...`. Run the Step 2 command again: `install` writes your real path. |
| Windows: Settings → Developer shows "No servers added" after the config was edited | Claude Desktop from the claude.ai installer is an MSIX package that reads `%LOCALAPPDATA%\Packages\Claude_<id>\LocalCache\Roaming\Claude\`, not the `%APPDATA%\Claude\` file that **Edit config** opens. Run the Step 2 command again: `install` writes both. Or uninstall that build and install with the classic `Claude Setup.exe`, which reads `%APPDATA%\Claude\` like the rest of these docs describe (tested on Windows 11). |
| `denied` or `manifest unknown` from docker.io | Normally a typo in the image name or tag, or a proxy intercepting Docker Hub. The reference must be exactly `sentinelone/secops-mcps:1.5.3`. |
| `VIRUSTOTAL_API_KEY ... required`, or a `PURPLEMCP_*` validation error | The value is not in the keychain, or the launcher could not read it. Re-run `~/.local/bin/s1-secops-mcp-launch.sh setup`; on Linux confirm the Secret Service is unlocked. |
| `S1 Mgmt API: NOT configured` | No console token reached the server; check `s1-secops-mcp status` (or `security find-generic-password -s sentinelone-mcp -a default:S1_CONSOLE_API_TOKEN` on macOS). |
| A skill asks you to run `s1-secops-mcp setup` | A value is missing. Run it in a terminal; never paste a token into the chat. |

Per-MCP logs are at `~/Library/Logs/Claude/mcp-server-<name>.log` on macOS, and in the `logs` folder next to the config Claude Desktop reads on Windows (for an MSIX install, `%LOCALAPPDATA%\Packages\Claude_<id>\LocalCache\Roaming\Claude\logs\`). Upgrading from 1.4.x or older? See **[docs/upgrading.md](./docs/upgrading.md)**.

Full troubleshooting flowchart, hand-testing, and rollback: **[docs/docker.md](./docs/docker.md)**.

---

### 2. Individual MCP / plugin / skill install

Only want one MCP instead of all three? Run `~/.local/bin/s1-secops-mcp-launch.sh config`, keep the one `mcpServers` entry you need and drop the others (or run `install` and delete the two you do not want). Every entry runs the same image through the same launcher; the last argument is the server name (`s1-secops-mcp`, `purple-mcp`, or `virustotal-mcp`), so one server costs you one block and no extra image.

Prefer Node to Docker for `s1-secops-mcp`? Install it, store values with `s1-secops-mcp setup`, and use `{"command": "s1-secops-mcp"}` with no `env` block; it reads the keychain itself. Claude Desktop users who want the OS store without a terminal can install the optional `.mcpb` extension from `mcp/s1-secops-mcp/mcpb/`, whose token fields are marked sensitive. Details: [s1-secops-mcp/README.md](../../mcp/s1-secops-mcp/README.md).

Only want one skill instead of the whole plugin? Each skill ships as a standalone `.skill` file in [the ai-siem `dist/` folder](./dist/); upload the individual file via Cowork → Customize → Browse plugins. The eight files are listed in [docs/installation.md](./docs/installation.md#step-3-install-the-plugin).

Full walkthrough (keychain setup, config block, prerequisites, project setup, upgrading): **[docs/installation.md](./docs/installation.md)**.

---

### Upgrading

- **MCPs**: bump the pinned `--image` tag in `claude_desktop_config.json` to the current release (`1.5.3`), run `docker pull sentinelone/secops-mcps:1.5.3`, and restart Claude Desktop. Coming from 1.4.x, also move credentials into the keychain and switch to the launcher. There is no moving tag to drift onto, so an upgrade is always an explicit, reviewable edit.
- **Plugin**: download the newer `.plugin` from [the ai-siem `dist/` folder](./dist/), then Cowork → Customize → Browse plugins, upload, and click **Replace**.

Step-by-step, including what to delete from an older config: **[docs/upgrading.md](./docs/upgrading.md)**.

---

## Windsurf

This repo includes Windsurf workflow files in `.windsurf/workflows/`. Each workflow is a thin pointer that directs Cascade to read the canonical `SKILL.md` and reference docs in the matching skill folder, with no duplicated content.

- `s1-api.md`: Management Console API (agents, threats, alerts, sites, Purple AI, UAM).
- `powerquery.md`: PowerQuery authoring, debugging, and detection rules.
- `sdl-api.md`: Singularity Data Lake API (ingest, query, config files).
- `sdl-log-parser.md`: SDL log parser authoring with OCSF mapping.

---

## Documentation

| Doc | Contents |
|---|---|
| [docs/zero-to-hero.md](./docs/zero-to-hero.md) | Onboarding guide for customers and partners new to Claude Skills: concepts, install, first session, common workflows, troubleshooting |
| [docs/docker.md](./docs/docker.md) | Full Docker reference: the keychain launcher, troubleshooting flowchart, hand-testing, CLAUDE.md override, upgrades, and build-from-source. The Docker quick start lives in [Installation](#installation) |
| [docs/installation.md](./docs/installation.md) | Canonical install: keychain setup, launcher config, plugin, project creation, verification, and upgrade paths |
| [docs/upgrading.md](./docs/upgrading.md) | Version-to-version upgrade steps, including the 1.4.x to 1.5.0 breaking changes |
| [docs/architecture.md](./docs/architecture.md) | How the three layers fit together, data flow, auth patterns, sandbox proxy explanation |
| [docs/skills.md](./docs/skills.md) | Per-skill capability reference, key scripts, and field requirements |
| [docs/mcp-tools.md](./docs/mcp-tools.md) | All s1-secops-mcp and purple-mcp tools with usage notes and which to use when |
| [docs/credentials.md](./docs/credentials.md) | Every credential value, env and OS keychain resolution, `setup` / `status` / `forget`, changing and rotating stored values, migration from `credentials.json`, client-config warnings, and the security model |
| [docs/testing.md](./docs/testing.md) | Full test coverage matrix, MCP tool validation results, and confirmed API field requirements |
| [docs/sdl-dashboard.md](./docs/sdl-dashboard.md) | All supported panel types and dashboard features with confirmed JSON examples |
| [docs/solutions/data-source-onboarding.md](./docs/solutions/data-source-onboarding.md) | SDL Solutions: onboard a raw source end to end (OCSF, enrichment, dashboard, detections, threat-response flow) from one prompt |
| [docs/solutions/asset-enrichment.md](./docs/solutions/asset-enrichment.md) | SDL Solutions: enrich raw logs with device/user/vuln/alert context from the Asset Inventory, with prompt examples |
| [docs/solutions/ueba-anomaly-detection.md](./docs/solutions/ueba-anomaly-detection.md) | SDL Solutions: baseline ANY signal per (action, principal) and detect z-score anomalies (SPIKE/DROP/SILENT/NEW), deployed as a baseline lookup, scheduled rule, nightly refresh, and dashboard |
| [docs/solutions/ingest-health-monitoring.md](./docs/solutions/ingest-health-monitoring.md) | SDL Solutions: per-device ingest health (per firewall/endpoint/server) on a 7-day hour-of-day baseline: volume spike/drop, ingest lag, ingest loss, parser drift, with a dashboard and email notifications |
| [docs/solutions/custom-detection-exclusions.md](./docs/solutions/custom-detection-exclusions.md) | SDL Solutions: suppress known-good noise in a STAR Custom Detection rule, built as a single-event or correlation rule (inline hardcoded exclusion) or a scheduled rule (CSV lookup anti-join + effectiveness dashboard); asks the rule type first |
| [docs/solutions/risk-based-alerting.md](./docs/solutions/risk-based-alerting.md) | SDL Solutions: Risk-Based Alerting in SDL, publish noisy observations as risk events into a `risk` index, accumulate risk per user/host object amplified by asset risk factors, and fire one high-fidelity alert on a 24h cumulative-score or 7d multi-MITRE-tactic threshold; deploys contributors, factor table, collector flow, four incident rules, and a dashboard |
| [docs/solutions/detection-as-code.md](./docs/solutions/detection-as-code.md) | SDL Solutions: Detection as Code, scaffold a Git + CI pipeline where detection rules are authored as TOML, validated on pull request, and synced to the Custom Detection Rule API on merge; covers single-event, correlation, and scheduled rule types, with a zero-dependency TOML-to-API sync engine and CI for GitHub, GitLab, and Azure |
| [docs/solutions/alert-noise-reduction.md](./docs/solutions/alert-noise-reduction.md) | SDL Solutions: reduce alert-queue noise, find the sources and signatures flooding the queue, separate ingested and already-actioned noise from real detections, recommend an ingestion-severity filter, auto-resolve already-mitigated alerts with a note, and ship a noise-vs-signal dashboard; all product/source/signature/action values discovered live |
| [docs/detection-rule-types.md](./docs/detection-rule-types.md) | The three STAR / Custom Detection rule types (single-event, multi-event correlation, scheduled PowerQuery): API shapes, when to use each, S1QL backslash escaping, and why asset enrichment is the prerequisite for asset-mapped alerts |
| [docs/detection-asset-binding.md](./docs/detection-asset-binding.md) | Which event attributes make STAR detection alerts auto-populate the Target Asset (device, identity, cloud), the tested per-type binding matrix, and how the asset enrichment solution supplies them |
| [mgmt-console-api/SKILL.md](./skills/mgmt-console-api/SKILL.md) | Deep reference: confirmed field schemas and required API parameters per endpoint |
| [mgmt-console-api/tests/README.md](./skills/mgmt-console-api/tests/README.md) | Reversible lifecycle test patterns and per-test field notes |
