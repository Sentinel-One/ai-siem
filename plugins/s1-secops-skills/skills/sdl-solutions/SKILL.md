---
name: sdl-solutions
author: Prithvi Moses <prithvi.moses@sentinelone.com>
description: Deploy packaged, repeatable SentinelOne Singularity Data Lake (SDL) solutions into a customer site from one short prompt, instead of authoring a single query, parser, or workflow by hand. Use when the user wants to onboard, set up, deploy, or roll out a whole SDL solution. Catalog - (1) data source onboarding, take a raw stream already reaching the tenant and operationalise it end to end (OCSF normalisation, device/user enrichment, dashboard, MITRE-mapped detections, and a threat-response Hyperautomation flow); (2) asset enrichment of raw logs, device/user context from the Asset Inventory via savelookup tables, a parser, and a refresh flow; (3) UEBA behavioral anomaly detection over ANY security or non-security signal, baselines per (action, principal) and scores the live window with a z-score to surface SPIKE/DROP/SILENT/NEW deviations, deployed as a persisted baseline lookup plus a scheduled PowerQuery detection rule, a nightly Hyperautomation refresh, and a dashboard; (4) ingest health monitoring per device, anomaly detection on a 7-day hour-of-day seasonal baseline (refreshed daily by a Hyperautomation flow) that detects when a specific firewall, endpoint, or server spikes, drops, lags, or goes silent, plus parser drift, deployed as per-device baseline lookups, scheduled PowerQuery detections, an ingest-loss watchdog, a dashboard, and email notifications for every failure. Triggers - "onboard cisco_meraki logs", "bring a new vendor source into AI SIEM and build detections", "deploy the asset enrichment solution", "enrich the firewall logs with device and user info", "run a behavioral baseline on Okta", "deploy UEBA anomaly detection for <source>", "detect anomalies in <source> against a baseline", "flag users whose activity is off their 30-day normal", "deploy ingest health monitoring", "monitor ingest per device / per firewall / per endpoint", "alert me when a source or device stops sending logs", "detect ingest spikes, drops, or lag", "find parser drift". Orchestrates the powerquery, sdl-log-parser, sdl-dashboard, sdl-api, mgmt-console-api, and hyperautomation skills. NOT for one-off queries or standalone parser authoring.
---

# SentinelOne SDL Solutions

This skill packages repeatable SDL solutions and deploys them into a specific customer
environment from a short set of prompts. It is an orchestration layer: it does not reimplement
PowerQuery, parser, SDL API, or Hyperautomation mechanics. Instead it collects the customer
parameters, renders the solution's templates, previews the result, deploys through the
primitive skills, and validates.

Use this skill when the user wants to deploy or tailor a whole solution. For a single query,
parser, dashboard, or workflow, use the matching primitive skill directly.

## Solution catalog

| Solution | What it does | Playbook |
|---|---|---|
| Data source onboarding | Take a raw log stream already reaching the tenant and operationalise it end to end from one short prompt: locate the source, normalise it to OCSF, enrich it with device/user context, then build a dashboard, MITRE-mapped detections, and a Hyperautomation flow | `references/data-source-onboarding.md` |
| Asset enrichment | Enrich ingested raw logs with device and user context (OS, IP, agent UUID, AD groups, SID, criticality, risk factors) from the Asset Inventory, at ingest or at query time | `references/asset-enrichment.md` |
| UEBA behavioral anomaly detection | Baseline ANY security or non-security signal per (action, principal) over a chosen window and detect deviations with a z-score: SPIKE, DROP, SILENT, and NEW-BEHAVIOR. Interactive engine for investigation, or a production deploy (baseline lookup + scheduled PowerQuery rule + nightly refresh + dashboard) | `references/ueba-anomaly-detection.md` |
| Ingest health monitoring (per device) | Per-device ingest health: anomaly detection on a 7-day hour-of-day seasonal baseline refreshed daily, detecting when a specific firewall, endpoint, or server spikes, drops, lags (p95), or goes silent, plus parser drift. Deploys per-device baseline lookups, scheduled PowerQuery detections, an ingest-loss watchdog flow, a 5-tab dashboard, and an email-notification flow for every failure | `references/ingest-health-monitoring.md` |

More solutions are added under `references/<solution>.md` plus templates under `assets/`. See
"Adding a new solution" below.

## How a deployment runs (always follow this loop)

1. **Pick the solution.** If the user named it, use it. Otherwise show the catalog and ask which one.
2. **Collect parameters with simple prompts.** Ask only what the playbook needs, one compact question set, with sensible defaults pre-filled. Never start deploying before parameters are confirmed. Each playbook lists its parameters and defaults.
3. **Confirm the environment.** Resolve the target site name to a siteId (fuzzy match, console site names can contain spaces). Confirm the console/tenant. Read existing config versions before any overwrite.
4. **Render and preview.** Fill the templates in `assets/` with the parameters and show the user the final config (queries, parser, workflow) and the projected enriched record BEFORE deploying. This is a dry run.
5. **Deploy in dependency order** through the primitive skills (see each playbook for the exact order). Typical order: build lookup tables, then parser or lookup guidance, then refresh flow.
6. **Validate** with a real ingest and query, and report what populated. Use `metadata.version` as the propagation canary for parser changes.
7. **Summarize** the deployed artifacts (paths, IDs, site) and hand off the rendered config files.

Keep prompts simple and few. Prefer defaults the user can accept with one word over long forms.

## Dependencies (load as needed)

This skill orchestrates the SentinelOne primitive skills. Load the ones a playbook calls for:

- `powerquery` for `datasource` + `savelookup` queries and the LRQ runner. The `references/datasource-command.md` there is the source of truth for the assets datasource.
- `sdl-api` (or the `s1-secops-mcp` tools `sdl_put_file`, `sdl_get_file`, `hec_ingest`) to deploy config files and ingest test data.
- `sdl-log-parser` for parser authoring and the computeFields lookup pattern.
- `hyperautomation` for the scheduled refresh workflow.
- `mgmt-console-api` (or `s1-secops-mcp` `s1_api_*`) for site lookup and scoped workflow import / activate / deactivate.

## Conventions

- **Naming prefix.** Every artifact a deployment creates is prefixed with a customer or solution code so multiple deployments coexist cleanly: tables `<prefix>IdentityLookup` / `<prefix>EndpointLookup`, parser `<prefix>_enrich`, workflow `<prefix> Asset Lookups`.
- **Scope by site.** Deploy to the customer's site. Resolve the name to a siteId and pass it on every scoped call. The HA import, activation, and deactivation all require the scope parameter.
- **Empty suppression.** Inventory empties (for example `riskFactors` as the string `"[]"`) are converted to null in the savelookup so enrichment never writes an empty field.
- **Preview before deploy.** Always show rendered config and an example enriched record first.
- **Idempotence.** Read the current version of any SDL config file before overwriting, and pass it as the expected version. Hyperautomation import always creates a new workflow, so to update one, replace it rather than re-import blindly.
- **Asset mapping is built in.** Any parser or detection a solution creates must carry the minimum attributes that let an alert bind its Target Asset, so alerts are not "Unknown Device". The endpoint lookup captures `device_agentid` (the numeric console agent id); the parser stamps `device.uid` = `device_agentid` plus an endpoint `class_uid`; and scheduled detections set `entityMappings` on the device identity columns (`device_host` / `device_agentid` / `device_agentuuid`). Binding reconciles `device.uid` against the live Asset Inventory, so a real enrolled agent id is required (a fabricated id stays Unknown Device). The tested binding matrix and the minimum set live in `powerquery/references/detection-rules.md`.

## Reference files

- `references/data-source-onboarding.md` - the onboarding playbook: the one-line-prompt UX, the parser-attribute editability rule for locating a source, parser create/update to OCSF plus asset enrichment, the 5-minute propagation wait, the parallel dashboard and MITRE-mapped detection build with asset-context columns, and the Hyperautomation SOC threat-response playbook (alert-triggered, VirusTotal-gated containment) with the single deploy-location question. Read this when onboarding a new data source.
- `references/asset-enrichment.md` - the asset enrichment playbook: parameters and defaults, the deployment-mode prompt (ingest-time parser vs query-time lookup vs automatic lookup; ingest-time requires the parser deployed in AI SIEM), the savelookup table builders, the parser, the validation steps, the Hyperautomation refresh flow, and the gotchas. Read this when deploying or tailoring asset enrichment.

## Templates

`assets/` holds the parameterized templates a playbook renders. Tokens use `{{NAME}}`:

- `assets/savelookup_identity.pq` - identity lookup table builder
- `assets/savelookup_endpoint.pq` - endpoint lookup table builder
- `assets/parser.template.json` - the enrichment parser
- `assets/refresh_workflow.template.json` - the Hyperautomation refresh workflow
- `assets/onboarding_detection.template.json` - STAR scheduled PowerQuery detection-rule envelope (onboarding)
- `assets/threat_response_workflow.template.json` - Hyperautomation SOC threat-response playbook (alert trigger to VirusTotal enrich to VT-gated containment: IOC block + endpoint quarantine, then note + notify) for an onboarded source's detections
- `assets/onboarding_dashboard.template.json` - starter tabbed dashboard skeleton for an onboarded source

Common tokens: `{{PREFIX}}`, `{{IDENTITY_TABLE}}`, `{{ENDPOINT_TABLE}}`, `{{PARSER_NAME}}`,
`{{DATASOURCE_NAME}}`, `{{VENDOR}}`, `{{HOSTNAME_FIELD}}`, `{{USERNAME_FIELD}}`, `{{USERNAME_KEY}}`
(`samAccountName` or `principalName`), `{{SCHEDULE_HOUR}}`, `{{SITE_ID}}`, `{{CONSOLE_HOST}}`,
`{{ENDPOINT_CLASS_UID}}` (OCSF class for the parser's `class_uid`; default `1007`, must be an
endpoint class `1xxx` for events-rule asset auto-binding).
Onboarding tokens: `{{DETECTION_NAME}}`, `{{DETECTION_DESCRIPTION}}`, `{{MITRE_TACTIC}}`,
`{{MITRE_TECHNIQUE}}`, `{{SEVERITY}}`, `{{PQ_BODY_ENDING_WITH_COLUMNS_PROJECTION}}`,
`{{RENOTIFY_MINUTES}}`, `{{ENTITY_COL_1}}`, `{{ENTITY_COL_2}}`, `{{ENTITY_COL_3}}` (entityMappings
is capped at 3), `{{SCOPE_KEY}}` (`accountIds`/`siteIds`), `{{SCOPE_ID}}`, `{{IP_SRC_FIELD}}`,
`{{IP_DST_FIELD}}`, `{{PORT_FIELD}}`, `{{ACTION_FIELD}}`, `{{USER_FIELD}}`,
`{{SOURCE_LABEL}}`, `{{ACCOUNT_ID}}`, `{{VT_API_KEY}}`, `{{NOTIFY_WEBHOOK_URL}}`,
`{{IOC_TTL_HOURS_NEG}}`.

## Adding a new solution

1. Write `references/<solution>.md` as a self-contained playbook: parameters with defaults, render steps, deploy order through the primitives, validation, gotchas.
2. Add the rendered templates to `assets/`.
3. Add a row to the Solution catalog table above and name the new solution in this skill's frontmatter description so it triggers.
4. Keep each solution self-contained so the router can branch cleanly.
