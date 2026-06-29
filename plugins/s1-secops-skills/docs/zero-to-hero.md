# Zero to Hero: Claude Skills for SentinelOne

A practical onboarding guide for customers and partners new to Claude Skills. Read this start to finish (~20 minutes) and you'll understand what skills are, why they matter, and how to get a working SentinelOne AI analyst running in a Cowork project.

This guide assumes no prior exposure to Claude Skills, MCP, or Cowork. It covers concepts, installation, and day-to-day use.

- [1. What are Claude Skills?](#1-what-are-claude-skills)
- [2. How to use the skills](#2-how-to-use-the-skills)
- [3. Install in 30 minutes](#3-install-in-30-minutes)
- [4. Your first session](#4-your-first-session)
- [5. Walkthroughs by use case](#5-walkthroughs-by-use-case)
- [6. When things don't work](#6-when-things-dont-work)
- [7. Going deeper](#7-going-deeper)

---

## 1. What are Claude Skills?

### The 30-second version

A **skill** is a folder containing a `SKILL.md` file that teaches Claude how to do a specific job correctly. The SKILL.md encodes confirmed API field names, validated procedures, gotchas, and the right tool to call for each operation. When your request matches a skill's trigger description, Claude loads that skill on demand and follows it.

You don't pick skills manually. You describe the outcome you want in plain English, and Claude routes to the right skill (or several) automatically.

### Why skills matter

Without a skill, Claude has to guess at the things every API has too many of: field names, endpoint paths, required parameters, output shapes, version-specific behaviour. Guessing produces plausible-looking but broken code, wrong field references, and hallucinated fields. Skills replace guesswork with knowledge that has been validated against a live tenant.

For SentinelOne specifically: the Management Console exposes 781 operations across 113 tags. The SDL API has its own auth model, log ingest format, and configuration filesystem. PowerQuery has reserved-field rewrites, type-locked columns, and a per-call deadline that aggregates can blow through. STAR rules have one schema; PowerQuery Alerts have another. Skills capture all of this so Claude doesn't have to rediscover it on every request.

### The three-layer mental model

Three pieces work together in every session:

```
CLAUDE.md            SOC Analyst persona, evidence rules, session protocol
       |
       v
MCP Servers          Live API access (bypasses the Cowork sandbox proxy)
  s1-secops-mcp    26 tools: PowerQuery, SDL, Mgmt REST, UAM, UAM Ingest, Hyperautomation
  purple-mcp         Alert triage, Purple AI NLQ, Deep Visibility, assets, vulns
  threat-intel-mcp   External IOC enrichment (e.g. VirusTotal)
       |
       v
Skills (SKILL.md)    Procedural knowledge: confirmed schemas, field requirements,
                     usage patterns, validated against live tenants
```

A useful analogy: **MCP servers are hands** (they touch the API), **skills are training manuals** (they say how to use the hands), and **CLAUDE.md is the job description** (it says what kind of work to do, in what order, with what discipline).

### How Claude decides which skill to load

Every skill's frontmatter has a `description` field listing trigger phrases and example requests. When you send a message, Claude scans your text against every available skill description and loads the matching ones. Triggers are deliberately broad: "hunt for PowerShell", "show me open alerts", "write a parser for this log", "build a dashboard panel" all map cleanly.

You can also be explicit. "Use the SDL log parser skill to..." or "switch to PowerQuery and..." both work, but you almost never need to. Describing the outcome is enough.

### What ships in this repo

| Skill | What it does |
|---|---|
| mgmt-console-api | Query and act on the Management Console: threats, alerts, agents, sites, RemoteOps, Deep Visibility, Hyperautomation, Purple AI, UAM. Includes the source-agnostic behavioural baselining + anomaly detection pipeline. |
| powerquery | Write, debug, and run PowerQuery for threat hunting, STAR detection rules, SDL dashboards, and statistical baseline / anomaly detection rule bodies. |
| sdl-api | Ingest events, run queries, and manage configuration files (parsers, dashboards, lookups) via the Singularity Data Lake API. |
| sdl-dashboard | Design, author, and deploy SDL dashboards: panels, tabs, parameters, and full dashboard JSON. |
| sdl-log-parser | Author and validate SDL log parsers for any log format, with OCSF field mapping by default. |
| hyperautomation | Design and generate Hyperautomation workflow JSON, with optional live console import. |
| sdl-solutions | Deploy packaged, repeatable SDL solutions from one short prompt: data source onboarding (raw stream to OCSF, enrichment, dashboard, MITRE detections, threat-response flow) , asset enrichment of raw logs, and UEBA behavioural anomaly detection (z-score baselining of any signal). Orchestrates the other six skills. |

Plus `CLAUDE.md` at the repo root, which transforms Claude into a **Principal SOC Analyst**: a structured investigator that runs the same enrichment, correlation, and reasoning process a senior analyst would, on every alert, every time.

### What this gets you (the outcomes)

| Outcome | How |
|---|---|
| Reduce L1 SOC workload by 70%+ | Automated triage, mandatory threat-intel enrichment, and verdict generation eliminate repetitive alert investigation. |
| Elevate every analyst to principal grade | Junior analysts get the same structured investigation framework as seniors. |
| External threat intelligence on every IOC | Mandatory enrichment on every IP, domain, hash, and URL before any verdict. |
| Mean investigation time under 5 minutes | 45-60 minute manual investigations compress to under 5 minutes. |
| Full data estate coverage | Queries OCSF-normalised logs, non-OCSF vendor logs, and raw syslog. Discovers field schemas dynamically per session. |
| Federated search across the data estate | Search and correlate across endpoint, network, identity, and cloud sources in a single session. |
| Every alert arrives with business context | Asset and identity enrichment auto-prioritises the queue by device criticality and account context. |
| New detections the same day a threat emerges | Emerging TTPs become validated, MITRE-mapped detections in hours, not weeks. |
| Onboard any new data source in minutes | Raw stream to OCSF-parsed, dashboarded, and detection-covered in one session. |
| Find threats hiding in app and business logs | Reaches beyond security telemetry into custom app logs, surfacing fraud no SIEM was watching. |
| Proactive anomaly detection at machine speed | Source-agnostic baselining flags signatureless deviations between analyst shifts. |
| Lower cost than the legacy SIEM model | Flat-rate, all-hot data lake economics plus negligible bring-your-own-AI run cost. |

---

## 2. How to use the skills

Your goal: ask Claude about your SentinelOne tenant in plain English and get correct, evidence-backed answers, dashboards, parsers, and workflows. You don't write any code, edit any SKILL.md files, or pick skills manually. You describe what you want and Claude routes the request.

Time to first value: about 30 minutes for the install, plus 5 minutes for your first real query.

There are three ways to interact with the skills once they're installed:

**1. Inside the Cowork project (the main path).** Open the `PrincipalSOCAnalyst` project in Claude Desktop and start a new chat. `CLAUDE.md` loads automatically, the session protocol runs (data source enumeration, alert triage in parallel), and every skill is one prompt away. This is where you'll spend almost all your time.

**2. From the terminal via Claude Code.** `cd` into the `ai-siem` repo folder and run `claude`. The CLI reads `CLAUDE.md` on startup and the same skills are available. Useful for scripting, batch jobs, and CI hooks.

**3. From any Claude session with the plugin installed.** Copy the contents of `CLAUDE.md` into Settings, Custom Instructions (or the equivalent system prompt field) of any Claude session that has the `s1-secops-skills` plugin installed. Useful when you want the SOC Analyst persona somewhere outside Cowork.

Continue to [Section 3: Install](#3-install-in-30-minutes) to set this up.

---

## 3. Install in 30 minutes

This section uses the Docker install path: a single image bundles all three MCPs, so the only host dependency is Docker. The full Docker reference is [`docs/docker.md`](./docker.md), and the npx/uvx reference is [`docs/installation.md`](./installation.md).

### Prerequisites

| Requirement | Check | Install |
|---|---|---|
| Claude desktop app | App is open | Download from [claude.com](https://claude.com) |
| Docker (Desktop on macOS/Windows, Engine on Linux) | `docker --version` | [docker.com/get-started](https://www.docker.com/get-started/) |
| SentinelOne API token | Settings, Users, Service Users | [Community guide](https://community.sentinelone.com/s/article/000005291) |
| SDL API keys | Singularity Data Lake, API Keys | [Community guide](https://community.sentinelone.com/s/article/000006763) |
| Regional endpoint URLs | n/a | [Endpoint URLs by Region](https://community.sentinelone.com/s/article/000004961) |
| Threat intel API key | e.g. [virustotal.com/gui/my-apikey](https://www.virustotal.com/gui/my-apikey) | Free tier is sufficient |

One image, multi-arch (`linux/amd64` + `linux/arm64`), so Apple Silicon and Intel both run native with no emulation. No host-level Node, Python, or `uv` to install.

### Step 1: Pull the image

```bash
docker pull ghcr.io/pmoses-s1/s1-mcps:1.2.2
```

What you got: one image (`ghcr.io/pmoses-s1/s1-mcps`) bundling all three MCPs (`s1-secops-mcp`, `purple-mcp`, `virustotal-mcp`), version-locked together at a known good combo. About 250 MB compressed, ~600 MB unpacked. Pin to a tag like `:1.2.2`; pulling `:latest` works but silently inherits upgrades on each re-pull. Confirm the dispatcher works:

```bash
docker run --rm ghcr.io/pmoses-s1/s1-mcps:1.2.2 help
```

### Step 2: Wire up the MCP servers in Claude Desktop

Edit `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows). Three entries, one per MCP, all referencing the same image:

```json
{
  "mcpServers": {
    "s1-secops-mcp": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm", "--pull=missing",
        "-e", "S1_CONSOLE_URL",
        "-e", "S1_CONSOLE_API_TOKEN",
        "-e", "S1_HEC_INGEST_URL",
        "-e", "SDL_XDR_URL",
        "-e", "SDL_LOG_READ_KEY",
        "-e", "SDL_CONFIG_WRITE_KEY",
        "-e", "SDL_CONFIG_READ_KEY",
        "ghcr.io/pmoses-s1/s1-mcps:1.2.2",
        "s1-secops-mcp"
      ],
      "env": {
        "S1_CONSOLE_URL":       "https://usea1-yourorg.sentinelone.net",
        "S1_CONSOLE_API_TOKEN": "eyJ...your-api-token...",
        "S1_HEC_INGEST_URL":    "https://ingest.us1.sentinelone.net",
        "SDL_XDR_URL":          "https://xdr.us1.sentinelone.net",
        "SDL_LOG_READ_KEY":     "your-log-read-key",
        "SDL_CONFIG_WRITE_KEY": "your-config-write-key",
        "SDL_CONFIG_READ_KEY":  "your-config-read-key"
      }
    },
    "purple-mcp": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm", "--pull=missing",
        "-e", "PURPLEMCP_CONSOLE_TOKEN",
        "-e", "PURPLEMCP_CONSOLE_BASE_URL",
        "ghcr.io/pmoses-s1/s1-mcps:1.2.2",
        "purple-mcp"
      ],
      "env": {
        "PURPLEMCP_CONSOLE_TOKEN":    "eyJ...your-api-token...",
        "PURPLEMCP_CONSOLE_BASE_URL": "https://usea1-yourorg.sentinelone.net"
      }
    },
    "virustotal": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm", "--pull=missing",
        "-e", "VIRUSTOTAL_API_KEY",
        "ghcr.io/pmoses-s1/s1-mcps:1.2.2",
        "virustotal-mcp"
      ],
      "env": {
        "VIRUSTOTAL_API_KEY": "your-virustotal-api-key"
      }
    }
  },
  "preferences": {
    "coworkScheduledTasksEnabled": true,
    "coworkWebSearchEnabled": true
  }
}
```

Things people get wrong here:

- `S1_CONSOLE_API_TOKEN` and `PURPLEMCP_CONSOLE_TOKEN` are the **same** token. One service user with read scope is enough for hunting and triage; IR Team scope or higher is needed for response actions like isolate.
- Region URLs vary. Check the [Endpoint URLs by Region](https://community.sentinelone.com/s/article/000004961) article for `S1_HEC_INGEST_URL` and `SDL_XDR_URL`.
- Replace VirusTotal with your organisation's approved threat intel MCP if different.
- `-i` is required so Claude Desktop can speak JSON-RPC over stdin; `--rm` cleans up the container when the session ends; `--pull=missing` pulls on first launch and skips the registry thereafter.
- The `-e VAR` form (no value) tells Docker to inherit each variable from the `env` block below it.

**Restart Claude Desktop after saving the file.**

### Step 3: Install the plugin

The plugin bundles all seven skills in a single file, so there's no per-skill install to manage.

1. In Claude Desktop, open the **Cowork** tab.
2. Click **Customize** in the left sidebar.
3. Click the '+' sign under **Personal plugins**.
4. Upload `s1-secops-skills-vX.Y.Z.plugin` from [`s1-secops-skills/dist/`](../s1-secops-skills/dist/).

If plugin upload fails, the same `dist/` folder has individual `.skill` files you can install one at a time by double-clicking them or by uploading via Browse plugins.

### Step 4: Create the Cowork project

Cowork projects are durable workspaces with their own folder, plugins, and CLAUDE.md. You'll do all your real work inside one.

1. In Claude Desktop, open **Cowork** and click **New Project**.
2. Name it `PrincipalSOCAnalyst`.
3. Click **Select Folder** and pick any folder on your machine. This becomes the project workspace.
4. Optionally drop a copy of [`CLAUDE.md`](https://raw.githubusercontent.com/Sentinel-One/ai-siem/main/plugins/s1-secops-skills/CLAUDE.md) into the project folder. The Docker image ships a default CLAUDE.md, so this step is optional; provide your own only to override it. To use a project-folder copy, mount the folder read-only and point `S1_CLAUDE_MD_PATH` at it in the `s1-secops-mcp` args (see [`docs/docker.md`](./docker.md#claudemd-customization)). The `s1-secops-mcp` server reads it at session start and exposes it as the `sentinelone://soc-context` resource.
5. Confirm `s1-secops-skills` appears under **Personal plugins**, and that `s1-secops-mcp`, `purple-mcp`, and your threat intel MCP appear under **MCP Servers**.

### Step 5: Verify the install

Open the **PrincipalSOCAnalyst** project and start a new session. Claude will automatically run data source enumeration and triage open alerts. Then ask:

```
smoke test s1 skills
```

Claude verifies connectivity to every MCP, confirms each skill is loaded, and reports missing credentials or unreachable endpoints. To check the version:

```
which version of s1-secops-skills is installed?
```

If anything fails, jump to [Section 6: When things don't work](#6-when-things-dont-work).

---

## 4. Your first session

### What happens when you open the project

The moment you start a chat in `PrincipalSOCAnalyst`, Claude reads `CLAUDE.md` and runs the mandatory session protocol:

1. **Enumerates live `dataSource.name` values in your SDL.** This tells Claude exactly which sources are present (S1 internal, SentinelOne EDR, plus any third-party connectors like Okta, FortiGate, CloudTrail, Mimecast).
2. **Pulls open alerts in parallel** while enumeration runs.
3. **For any non-OCSF source it discovers, runs schema discovery** before authoring any query against it.

This isn't filler. It's why the answers you get later are correct: Claude never reuses cached field names from a previous session because parsers, reserved-field rewrites, and ingestion changes can drift between sessions.

### Three first prompts to try

Pick whichever feels most useful and run it:

**Triage**
```
Triage today's open alerts and flag anything requiring immediate action.
```
Expect a ranked list with verdicts, IOCs, threat-intel enrichment, MITRE mapping, and recommended response actions.

**Hunt**
```
Hunt for any process that opened a connection to a non-RFC1918 IP in the last 7 days, show me the top endpoints by hit count.
```
Expect a PowerQuery, validated against your data sources, executed, and a ranked endpoint table summarised in chat.

**Build**
```
Build me a SOC overview dashboard with a threat timeline by confidence,
top 10 noisiest endpoints, failed logins over time, and an outbound
connection breakdown by direction. Deploy it to /dashboards/soc-overview.
```
Expect dashboard JSON authored, queries validated against your tenant, the dashboard deployed to SDL, and a confirmation back.

### How to read what Claude is doing

A few signals tell you which skill is running and what API surface is being used:

- **Tool calls named `mcp__s1-secops-mcp__*`** are the local MCP server. Names like `powerquery_run`, `s1_api_get`, `sdl_put_file`, `uam_list_alerts`, `ha_import_workflow` map cleanly to the skill they belong to.
- **Tool calls named `mcp__purple-mcp__*`** are the Python Purple MCP. Use these for alert triage, Purple AI NLQ, vulnerabilities, inventory.
- **Tool calls named `mcp__virustotal__*`** (or your equivalent) are external threat intel.
- **Skill load indicators** appear inline: Claude will mention "loading powerquery" or similar before it starts authoring a query.
- **Citations** appear in Claude's prose. Every fact ties back to a specific tool call, with no fabrication.

### What good output looks like

A correct response has three properties:

1. **Evidence-backed.** Numbers, IOCs, and verdicts cite the tool call that produced them.
2. **Calibrated language.** Claude uses "confirmed" / "consistent with" / "suggests" / "possible" deliberately, scaled to the strength of the evidence.
3. **No CRITICAL verdict without independent threat intel.** This is enforced by `CLAUDE.md`. If you see a CRITICAL classification, you'll see VirusTotal (or equivalent) corroboration alongside it.

If a response is missing any of these, push back. Claude will recheck and recalibrate.

---

## 5. Walkthroughs by use case

Each subsection has a sample prompt and what to expect. Run them in your `PrincipalSOCAnalyst` project.

### Threat hunting

Skill: `powerquery` (plus `mgmt-console-api` for execution).

```
Find PowerShell scripts that encoded a Base64 command, group by endpoint,
and rank by hit count over the last 7 days.
```

What you'll get: a PowerQuery using `event.type`, `src.process.cmdline`, and `array_agg_distinct`, validated against your sources, run, and the top-N endpoints summarised. You can ask Claude to convert it to a STAR detection rule if it looks useful.

### Alert triage

Skills: `mgmt-console-api`, plus `purple-mcp` for richer GraphQL fields.

```
Triage alert ID abc123: get full details, check notes and history, enrich
any IOCs through the threat-intel MCP, and give me a verdict.
```

What you'll get: the full alert payload, prior analyst notes, MDR verdict, asset criticality lookup, every IOC enriched through the configured threat-intel MCP (VirusTotal in the default bundle), MITRE mapping, and a calibrated verdict. If the verdict is CRITICAL or TRUE POSITIVE, you'll see the threat intel evidence inline.

### Behavioural baselining and anomaly detection

Skill: `mgmt-console-api` (the `baseline_anomaly.py` pipeline) plus `powerquery` for the rule body.

```
Build a 30-day behavioural baseline for Okta and show me anomalies for today.
Use day-of-week stratification.
```

What you'll get: schema auto-discovery to pick the right `principal_field` (e.g. `actor.user.email_addr` for Okta) and `action_field`, 30 daily slices run in parallel under the per-user 3 rps cap, a 24-hour live slice, and three anomaly classes returned: matched z-score deviations (spike or drop), silent pairs (active in baseline, zero today), and new-behaviour pairs (active today, no baseline at all).

For a recurring detection, ask Claude to productionise it as a PowerQuery Alert rule with a `| savelookup` baseline and `| lookup` join.

### Dashboard authoring

Skill: `sdl-dashboard` (plus `sdl-api` for deploy and `powerquery` for panel queries).

```
Create a Purple AI usage dashboard showing queries by analyst over time
and a timeline of usage. Deploy it to /dashboards/purple-ai-usage.
```

What you'll get: dashboard JSON with the right panel types (timeseries, table, single value), every panel query validated against your tenant before deploy, and a confirmation that the dashboard is live in SDL.

### Log parser authoring

Skill: `sdl-log-parser` (plus `sdl-api` for end-to-end validation).

```
Write an SDL parser for this Palo Alto syslog sample, with OCSF field
mapping:

  <paste raw log here>
```

What you'll get: a complete parser definition (`formats`, `patterns`, `lineGroupers`, `rewrites`, `discardAttributes`), OCSF field mapping, deploy to `/logParsers/<name>`, ingest of a test event, and a query confirming the fields appear correctly in SDL.

### Hyperautomation workflows

Skill: `hyperautomation`.

```
Build a workflow that, when a Ransomware indicator fires, isolates the
affected endpoint, creates an IOC for the SHA1 hash, and sends a Slack
notification to #soc-alerts.
```

What you'll get: workflow JSON ready to import. If you ask Claude to import it, it does so via `ha_import_workflow`. Important note: workflows imported with a service user token are invisible to human users in the console UI. To surface one quickly, ask Claude to enable then deactivate it; for a permanent fix, use a personal console user token.

### SOC reporting

```
Write a SOC Leader report for this investigation as a Word document:
executive summary, incident timeline, IOC table with VT verdicts, MITRE
mapping, root cause, and recommendations.
```

What you'll get: a structured `.docx` saved to your project folder, ready to share. If you keep a `reports/` subfolder in your project, Claude saves there by default and the report persists across sessions.

---

## 6. When things don't work

### "Skill didn't trigger"

Be more specific in your prompt. "Make a thing" is ambiguous; "build a Hyperautomation workflow that..." is unmissable. You can also be explicit: "Use the sdl-dashboard skill to..."

If a skill should have triggered and didn't, ask Claude `which skills are loaded for this session?` to confirm the plugin is wired up.

### MCP server not connecting (red dot in Cowork)

Check, in order:

1. **Docker Desktop is actually running.** Run `docker info | head -3`; you should see `Server Version: ...`. If you see `Cannot connect to the Docker daemon`, start Docker Desktop, wait for the whale icon to stop animating, and restart Claude Desktop.
2. **The image is present.** Run `docker run --rm ghcr.io/pmoses-s1/s1-mcps:1.2.2 help`. If it can't pull, you may be behind a proxy or VPN that blocks ghcr.io; run `docker login ghcr.io` if you have a token.
3. **First-launch pull took too long and timed out.** The first `docker run` downloads the image (30–90 s). Run `docker pull ghcr.io/pmoses-s1/s1-mcps:1.2.2` once manually to warm the cache, then restart Claude Desktop.
4. **Restart Claude Desktop** after any config change.
5. **Force a fresh pull** if you suspect a corrupted local image: `docker rmi ghcr.io/pmoses-s1/s1-mcps:1.2.2 && docker pull ghcr.io/pmoses-s1/s1-mcps:1.2.2`.

### 401 / 403 errors

- **Wrong region URL.** `S1_CONSOLE_URL`, `S1_HEC_INGEST_URL`, and `SDL_XDR_URL` are region-specific. Cross-check against the [Endpoint URLs by Region](https://community.sentinelone.com/s/article/000004961) article.
- **Token scope too low.** Read operations need Viewer or higher; response actions need IR Team or higher.
- **Wrong key for the operation.** `SDL_CONFIG_WRITE_KEY` does NOT grant View Logs access; using it for a query returns 403. The console JWT works for SDL config and query operations on Mgmt Z SP5+ and is the Bearer for HEC log ingest (`hec_ingest`); the dedicated `SDL_CONFIG_WRITE_KEY` is only needed for parser/dashboard `putFile`.

### Plugin upload failed

Fall back to per-skill `.skill` files in [`s1-secops-skills/dist/`](../s1-secops-skills/dist/). Double-click each `.skill` file to install, or upload one at a time via Browse plugins. The six files are: `mgmt-console-api.skill`, `powerquery.skill`, `sdl-api.skill`, `sdl-dashboard.skill`, `sdl-log-parser.skill`, `hyperautomation.skill`.

### "I imported a workflow but I can't see it in the console UI"

Workflows imported with a service user token are invisible to human users. Two ways to fix it:

- **Quickest, no token change:** ask Claude to enable the workflow and then deactivate it. That toggle surfaces it in the console UI without touching your config.
- **Permanent:** generate a personal console user token, set `S1_CONSOLE_API_TOKEN` to that token in `claude_desktop_config.json`, and re-import.

### "Claude said something I don't believe"

Push back. Tell Claude you don't believe a specific claim and ask it to recheck the underlying tool call. The session protocol forbids fabrication; if Claude can't cite the evidence, it has to retract or recalibrate. This is by design.

### Need a deeper look

Ask Claude:

```
smoke test s1 skills
```

It runs through every MCP and skill, reports what's healthy, and gives a precise error for anything that isn't.

---

## 7. Going deeper

### Read the full reference docs

| Doc | When to read it |
|---|---|
| [`docs/docker.md`](./docker.md) | Full Docker install reference: image tags, troubleshooting, upgrade, CLAUDE.md mount |
| [`docs/installation.md`](./installation.md) | npx/uvx install reference, including upgrade and credentials.json fallback |
| [`docs/architecture.md`](./architecture.md) | Data flow, auth model, sandbox proxy explanation |
| [`docs/skills.md`](./skills.md) | Per-skill capability reference |
| [`docs/mcp-tools.md`](./mcp-tools.md) | Every MCP tool with usage notes |
| [`docs/credentials.md`](./credentials.md) | Every credential key and where to find it |
| [`docs/sdl-dashboard.md`](./sdl-dashboard.md) | Every supported panel type with confirmed JSON examples |
| [`docs/testing.md`](./testing.md) | Test coverage matrix and confirmed API field requirements |
| [`mgmt-console-api/SKILL.md`](../skills/mgmt-console-api/SKILL.md) | Confirmed field schemas and required parameters per endpoint |

### Operate at scale

Once you're past first-run, the next leverage points are:

- **Schedule recurring tasks** with `coworkScheduledTasksEnabled: true` (it's already in the config snippet above). Examples: nightly behavioural baseline refresh, hourly alert digest to Slack, weekly threat summary as a `.docx`.
- **Productionise hunts as detection rules.** Anything you find useful in chat can be promoted to a recurring detection.
- **Add custom data sources.** Author a parser, deploy it, and the skills handle every other source the same way (auto-discovery means no per-source hardcoding).

### Get help

- Re-run `smoke test s1 skills` whenever something feels off.
- File issues against the repo with the smoke test output attached.
- For SentinelOne API questions, the Community articles linked throughout this guide are the canonical references.

---

You're ready. Open the `PrincipalSOCAnalyst` project, start a new chat, and ask it to triage today's alerts. Everything else builds from there.
