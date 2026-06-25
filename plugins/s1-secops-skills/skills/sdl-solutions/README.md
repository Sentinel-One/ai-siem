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
| Data source onboarding | Take a raw stream already reaching the tenant and operationalise it end to end: OCSF normalisation, device/user enrichment, dashboard, MITRE-mapped detections, and a SOC threat-response playbook | [guide](../../docs/solutions/data-source-onboarding.md) | [`references/data-source-onboarding.md`](references/data-source-onboarding.md) |
| Asset enrichment | Enrich raw logs with device, user, vulnerability, misconfiguration, alert, or cloud context from the Asset Inventory, at ingest or at query time | [guide](../../docs/solutions/asset-enrichment.md) | [`references/asset-enrichment.md`](references/asset-enrichment.md) |
| UEBA behavioural anomaly detection | Baseline ANY security or non-security signal per (action, principal) and detect z-score deviations: SPIKE, DROP, SILENT, NEW-BEHAVIOR. Run interactively to investigate, or deploy a baseline lookup, a scheduled PowerQuery rule, a nightly refresh, and a dashboard | [guide](../../docs/solutions/ueba-anomaly-detection.md) | [`references/ueba-anomaly-detection.md`](references/ueba-anomaly-detection.md) |
| Ingest health monitoring (per device) | Per-device ingest health (per firewall, endpoint, server) on a 7-day hour-of-day seasonal baseline rebuilt daily: volume spike/drop, ingest lag, ingest loss, and parser drift, with a dashboard and email notifications | [guide](../../docs/solutions/ingest-health-monitoring.md) | [`references/ingest-health-monitoring.md`](references/ingest-health-monitoring.md) |
| Scheduled detection exclusions | Suppress known-good noise in a scheduled detection over a third-party source by keying it against a CSV exclusion list (assets by IP/CIDR/host, or custom domains/users/values) via a lookup anti-join, with an exclusion-effectiveness dashboard | [guide](../../docs/solutions/scheduled-detection-exclusions.md) | [`references/scheduled-detection-exclusions.md`](references/scheduled-detection-exclusions.md) |
| Risk-Based Alerting (RBA) | Publish noisy-but-interesting observations as low-noise risk events into a `risk` index, accumulate risk per user/host object amplified by asset risk factors, and fire one high-fidelity alert on a 24h cumulative-score or 7d multi-MITRE-tactic threshold. Deploys contributors, a risk-factor table, a scheduled collector flow, four incident rules, and a dashboard | [guide](../../docs/solutions/risk-based-alerting.md) | [`references/risk-based-alerting.md`](references/risk-based-alerting.md) |

## Outcomes

What the solutions deliver, framed as the result rather than the mechanism:

| Outcome | How |
|---|---|
| Onboard any new data source in minutes | Data source onboarding takes a raw, unreadable stream to OCSF-normalised, parsed, dashboarded, and detection-covered in a single session. Coverage stops being gated by quarters of engineering backlog. |
| Detections and threat response ship with the source | Onboarding deploys MITRE-mapped detections and a SOC threat-response playbook alongside the new source, so a feed is protected the day it goes live, not weeks later. |
| Every alert and log arrives with business context | Asset enrichment attaches device, user, vulnerability, misconfiguration, alert, and cloud context at ingest or query time, so investigations and the alert queue prioritise by business impact with no manual lookup. |
| Catch behavioural anomalies on any signal, no per-source code | UEBA baselines per (action, principal) on any security or non-security source and scores the live window with a z-score, surfacing spikes, drops, entities that went silent, and first-seen behaviour. Deploys as a persisted baseline, a scheduled rule, a nightly refresh, and a dashboard. |
| Know the moment a device stops sending or misbehaves | Ingest health monitoring baselines every firewall, endpoint, and server and detects per-device volume spikes, drops, ingest lag, silence, and parser drift, emailing on every failure so a broken collector or a drifting parser is caught in minutes, not at the next investigation. |
| Tune out known-good noise without losing real signal | Scheduled detection exclusions let an analyst suppress an allowlisted set of assets or values from a detection with one CSV, applied at detection time via a lookup anti-join, plus a dashboard that shows exactly what each list is suppressing so an over-broad exclusion that hides a real threat is caught. |
| Alert on connected behaviour, not disconnected events | Risk-Based Alerting publishes noisy observations as risk events into a `risk` index, accumulates risk per user/host (amplified by asset criticality / privilege), and fires one high-fidelity alert only when an object crosses a cumulative-score or multi-MITRE-tactic threshold, so analysts get a contextualised story with far less alert fatigue and a proprietary internal intelligence library of interesting behaviour. |

## Run it with one prompt

- *"Onboard the cisco_meraki logs on the Acme site"*
- *"Bring our new FortiGate firewall source into AI SIEM and build detections and a dashboard"*
- *"Deploy the asset enrichment solution for Acme on the Acme site"*
- *"Enrich the firewall logs with device and user info"*
- *"Run a behavioural baseline on Okta and tell me what's anomalous"*
- *"Deploy UEBA anomaly detection for FortiGate on the Acme site"*
- *"Deploy ingest health monitoring per device and email the SOC on any failure"*
- *"Stop my Akamai DNS detection from alerting on our scanner subnets and corporate domains, here's the list"*
- *"Deploy risk-based alerting for users and hosts with asset-criticality risk factors"*

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
