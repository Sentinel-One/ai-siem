# Solution: Data source onboarding

Turn a raw log stream that is already reaching the tenant into a fully operationalised source:
normalised to OCSF, enriched with device and user context, then made useful with a dashboard,
MITRE-mapped detections, and a SOC threat-response Hyperautomation playbook. The whole thing runs
from one short prompt.

This is part of the `sdl-solutions` skill. It orchestrates the primitive skills
(`sdl-log-parser`, `powerquery`, `sdl-dashboard`,
`mgmt-console-api`, `hyperautomation`) in order and validates each stage
against live data before moving on.

## Features

- **One-prompt onboarding**: name a source and the skill locates it by its `parser` attribute, then normalises, enriches, dashboards, detects, and adds response, end to end.
- **OCSF normalisation**: sets the four mandatory attributes (`dataSource.name`/`vendor`/`category`, `metadata.version`) and maps vendor fields to verified OCSF fields (never invented).
- **Asset enrichment built in**: device/user context is joined onto every event so detections bind a real Target Asset, not "Unknown Device".
- **MITRE-mapped detections**: STAR scheduled rules for the source class, each mapped to ATT&CK, with entity mapping and severity-tuned cool-offs.
- **SOC threat-response playbook**: an alert-triggered Hyperautomation flow extracts IOCs, gates on VirusTotal, then blocks the IOC and network-quarantines the source host on a malicious verdict.
- **Operational dashboard**: volume over time, action breakdown, top talkers/users/devices, geo, and any IDS/threat signatures the source emits.
- **Validated stage by stage**: parser propagation, the normalised stream, detections, and the flow are each checked against live data before the next step.

## Run it with one prompt

Name a source and that is enough to start. Example prompts:

- *"Onboard the cisco_meraki logs on the Acme site"*
- *"Onboard Okta"*
- *"Bring our new FortiGate firewall source into AI SIEM and build detections and a dashboard"*
- *"Set up detections and a dashboard for the Zscaler source"*

The skill discovers everything else and asks only one question: where to deploy the detections and
the Hyperautomation flow (which site or account scope). It previews the parser, dashboard,
detections, and flow before deploying, and presents detections and flows for your approval.

## What it does, end to end

1. **Locate the source and check editability.** It finds the stream by its `parser` attribute (an
   un-normalised source has no `dataSource.name` yet). The source is editable in SDL when the
   `parser` attribute is present and the `message` attribute is populated, since SDL parsers operate
   on the raw text in `message`; this holds even if the data was parsed upstream. If there is no
   `parser` attribute, SDL cannot parse the events and the skill says so rather than inventing a
   parser.
2. **Create or update the parser to OCSF** and add device/user asset enrichment, reusing the asset
   enrichment solution's lookup tables.
3. **Wait for propagation** (parser activation is about 3 to 5 minutes) before building anything
   downstream, using `metadata.version` as the canary.
4. **Build a dashboard and MITRE-mapped detections in parallel** off the normalised stream, with
   asset-context columns on the alerts. Detections map the device identity (console agent id /
   hostname) as the alert entity so each alert binds a real Target Asset instead of "Unknown Device".
5. **Build a SOC threat-response playbook** tied to those detections: alert-triggered, it extracts
   the IOCs, enriches the external destination with VirusTotal, and on a malicious verdict contains
   the threat (blocks the destination IOC and network-quarantines the source endpoint), then
   documents the action on the alert and notifies the SOC. Internal-only alerts (e.g. the host-scan
   detection) route to analyst triage instead of auto-containment. Deploys scoped to the chosen site.
6. **Verify and summarise** every deployed artifact (paths, IDs, site) and an example
   normalised-and-enriched record.

## What gets deployed

An OCSF parser at `/logParsers/<source>`, the asset enrichment datatables (reused if they already
exist), a `<prefix> Overview` dashboard, a set of STAR scheduled PowerQuery detections (left as
draft unless you ask to enable them), and a SOC threat-response Hyperautomation playbook
(imported deactivated, with VirusTotal-gated containment).

## Notes and gotchas

- A source with no `dataSource.name` is not empty, it is un-normalised; find it by `parser=`.
- Parsers are account-level; they deploy at account scope even when the source ingests at a site.
- JSON-per-line bodies flatten with the dotted-prefix capture `$unmapped.=json{parse=dottedJson}$`,
  not a bare `$json{parse=json}$` (which emits no subfields).
- Network sources key enrichment on IP rather than hostname.
- The threat-response playbook binds the **SentinelOne** mgmt connection (ApiToken) for the S1
  actions (IOC block, endpoint quarantine, alert note); set the VirusTotal API key and the SOC
  webhook before activating. Containment is gated on a VirusTotal-malicious verdict, never on the
  detection alone.
- HA import needs the **Hyper Automate.write** scope and a scope on the URL: `?accountIds=<acct>`
  for an account-level import or `?siteIds=<site>` for a site; with no scope it returns a misleading
  `403`. To make an imported draft visible to the team without running it, call the publish endpoint
  (`POST /hyper-automate/api/v1/workflows/{id}/publish`, returns `204`), it becomes an inactive
  Shared Draft. Delete a workflow with `DELETE /hyper-automate/api/v1/workflows/{id}?accountIds=<acct>`
  (`204`, soft/recoverable); scope it to where the workflow lives.

## Validated reference

First live onboarding (2026-06-13): **Cisco Meraki** via `onboard cisco_meraki logs`.
The source was located by `parser='cisco_meraki-latest'` with no parser file and no
`dataSource.name` (the un-normalised gap); the parser was created and corrected to OCSF Network
Activity with a dotted-prefix JSON flatten, and device enrichment was added via an IP-keyed
endpoint lookup (proven live: a host IP resolved to its hostname, OS, and agent UUID). A
`Cisco Meraki Overview` dashboard and four MITRE-mapped STAR detections (perimeter beaconing,
host fan-out scan, high-risk port, ICMP anomaly) were deployed, and a `Meraki Threat Response`
playbook was authored for VT-gated containment.

## For engineers

The full execution detail (the editability rule, parser steps, propagation, dashboard and
detection design rules, the threat-response playbook) lives in the playbook the skill reads:
[`sdl-solutions/references/data-source-onboarding.md`](../../skills/sdl-solutions/references/data-source-onboarding.md).
