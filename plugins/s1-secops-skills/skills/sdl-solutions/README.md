# sdl-solutions

Deploy packaged, repeatable SentinelOne Singularity Data Lake (SDL) solutions into a specific
customer site from one short prompt. This skill is an orchestration layer: it collects a few
parameters, previews the rendered config, then deploys and validates through the primitive
SentinelOne skills (`powerquery`, `sdl-api`, `sdl-log-parser`,
`sdl-dashboard`, `mgmt-console-api`, `hyperautomation`). It does
not reimplement them.

Use it for whole solutions. For a single query, parser, dashboard, or workflow, use the matching
primitive skill directly.

## Solutions

| Solution | What it does | Guide | Playbook (Claude-facing) |
|---|---|---|---|
| Data source onboarding | Take a raw stream already reaching the tenant and operationalise it end to end: OCSF normalisation, device/user enrichment, dashboard, MITRE-mapped detections, and a SOC threat-response playbook | [guide](../docs/solutions/data-source-onboarding.md) | [`references/data-source-onboarding.md`](references/data-source-onboarding.md) |
| Asset enrichment | Enrich raw logs with device, user, vulnerability, misconfiguration, alert, or cloud context from the Asset Inventory, at ingest or at query time | [guide](../docs/solutions/asset-enrichment.md) | [`references/asset-enrichment.md`](references/asset-enrichment.md) |
| UEBA behavioral anomaly detection | Baseline ANY security or non-security signal per (action, principal) and detect z-score deviations: SPIKE, DROP, SILENT, NEW-BEHAVIOR. Run interactively to investigate, or deploy a baseline lookup, a scheduled PowerQuery rule, a nightly refresh, and a dashboard | [guide](../docs/solutions/ueba-anomaly-detection.md) | [`references/ueba-anomaly-detection.md`](references/ueba-anomaly-detection.md) |
| Ingest health monitoring (per device) | Per-device ingest health (per firewall, endpoint, server) on a 7-day hour-of-day seasonal baseline rebuilt daily: volume spike/drop, ingest lag, ingest loss, and parser drift, with a dashboard and email notifications | [guide](../docs/solutions/ingest-health-monitoring.md) | [`references/ingest-health-monitoring.md`](references/ingest-health-monitoring.md) |

## Outcomes

What the solutions deliver, framed as the result rather than the mechanism:

| Outcome | How |
|---|---|
| Onboard any new data source in minutes | Data source onboarding takes a raw, unreadable stream to OCSF-normalised, parsed, dashboarded, and detection-covered in a single session. Coverage stops being gated by quarters of engineering backlog. |
| Detections and threat response ship with the source | Onboarding deploys MITRE-mapped detections and a SOC threat-response playbook alongside the new source, so a feed is protected the day it goes live, not weeks later. |
| Every alert and log arrives with business context | Asset enrichment attaches device, user, vulnerability, misconfiguration, alert, and cloud context at ingest or query time, so investigations and the alert queue prioritise by business impact with no manual lookup. |
| Catch behavioral anomalies on any signal, no per-source code | UEBA baselines per (action, principal) on any security or non-security source and scores the live window with a z-score, surfacing spikes, drops, entities that went silent, and first-seen behavior. Deploys as a persisted baseline, a scheduled rule, a nightly refresh, and a dashboard. |
| Know the moment a device stops sending or misbehaves | Ingest health monitoring baselines every firewall, endpoint, and server and detects per-device volume spikes, drops, ingest lag, silence, and parser drift, emailing on every failure so a broken collector or a drifting parser is caught in minutes, not at the next investigation. |

## Run it with one prompt

- *"Onboard the cisco_meraki logs on the Acme site"*
- *"Bring our new FortiGate firewall source into AI SIEM and build detections and a dashboard"*
- *"Deploy the asset enrichment solution for Acme on the Acme site"*
- *"Enrich the firewall logs with device and user info"*
- *"Run a behavioral baseline on Okta and tell me what's anomalous"*
- *"Deploy UEBA anomaly detection for FortiGate on the Acme site"*
- *"Deploy ingest health monitoring per device and email the SOC on any failure"*

Adding an enrichment is a single multi-select question (Device, User/AD, Vulnerabilities,
Misconfigurations, Open alerts, Cloud). Everything else is auto-derived and shown in the preview.

## How it runs

Pick the solution, collect parameters with a short prompt set (sensible defaults), confirm the
target site, preview the rendered config, deploy in dependency order, validate against live data,
and summarise the deployed artifacts. Full loop and conventions are in
[`SKILL.md`](SKILL.md) (the file Claude loads).

## Layout

- `SKILL.md` - what Claude reads: the router, the deployment loop, conventions, dependencies.
- `references/` - one self-contained playbook per solution (execution detail).
- `assets/` - parameterized templates (savelookup queries, parser, dashboard, detection, workflows) with `{{TOKEN}}` placeholders.

## Adding a new solution

Add `references/<solution>.md` (a self-contained playbook), its templates under `assets/`, a row
in the Solutions table above and in `SKILL.md`, and name the solution in the `SKILL.md` frontmatter
description so it triggers. A human guide under `docs/solutions/<solution>.md` linked from the repo
README is recommended.
