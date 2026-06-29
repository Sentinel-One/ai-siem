# Playbook: Onboard a new data source

Turn a raw log stream that is already reaching the tenant into a fully operationalised source:
normalised to OCSF, enriched with device and user context, then made useful with a dashboard,
MITRE-mapped detections, and a Hyperautomation flow. The whole thing runs from one short prompt,
for example `onboard cisco_meraki logs` or `onboard the Mimecast source`.

This is an orchestration playbook. It does not reimplement parser, PowerQuery, dashboard, STAR,
or Hyperautomation mechanics; it drives the primitive skills in order and validates each stage
against live data before moving on.

## The one-line prompt

The user names a source and that is enough to start. Examples that should run this playbook:
`onboard cisco_meraki logs`, `onboard Okta`, `onboard the new firewall source`, `bring Zscaler
into AI SIEM and build detections`. Discover everything else; ask only the single deploy-location
question at Step 4. Do not front-load a long form.

## Parameters (discover first, ask only if discovery fails)

| Parameter | How to get it | Default |
|---|---|---|
| `SOURCE` | from the prompt | required |
| `PARSER_NAME` | the `parser` attribute on the source's events (see Step 0) | discovered |
| `DATASOURCE_NAME` | the product name to tag, OCSF-style (e.g. `Cisco Meraki`) | derive from source |
| `VENDOR` | parent company (e.g. `Cisco`) | derive from source |
| `PREFIX` | short artifact-naming code | derive from source |
| `HOST_FIELD` / `USER_FIELD` / `IP_FIELD` | fields in the parsed event used to key asset enrichment | discovered from the sample |
| `SITE` / `SCOPE` | where to deploy STAR rules and the HA flow | ask at Step 4 only |

## Step 0: locate the source and decide if it is editable in SDL

The editability of a source in SDL is decided by one signal: the `parser` attribute on its events.

```
parser=* | group events=count() by parser | sort -events | limit 200
```

Then map parser to the source by pulling a sample. Because an un-normalised source has no
`dataSource.name` yet, do not search by `dataSource.name`; search by the parser:

```
parser='<PARSER_NAME>' | sort -timestamp | limit 20
```

Apply this rule before doing anything else:

| Observation | Meaning | Action |
|---|---|---|
| `parser` attribute populated AND `message` populated | A parser of that name exists in SDL at `/logParsers/<parser>` and is editable, and there is raw text in `message` for it to operate on | Proceed. This is the normal onboarding path. |
| `parser` populated but `dataSource.name` null/absent | The parser is landing the data but is not normalising it. This is the onboarding gap. | Proceed to Step 1: extend the parser to set the four mandatory attributes and OCSF. |
| no `parser` attribute | No SDL parser is bound to these events, so SDL cannot parse or modify them | Stop. Tell the user the source cannot be onboarded in SDL as-is. Do not invent a parser. |

**Only the content of the `message` attribute can be parsed.** SDL parsers operate on `message`;
field extraction, OCSF mapping, and enrichment all run off that raw text. A `parser` attribute being
present means the data is editable even if it was parsed upstream, provided `message` is populated.
If `message` is empty there is nothing to parse, even with a parser bound.

If live discovery finds nothing, ask the user to upload a raw sample of the source's logs and
proceed from the sample. Confirm the source is sending now (recent `timestamp` values), not a
stale historical trickle, before building anything on top of it.

**Prefer live data, and ask before ingesting test samples.** Validate against the live stream
wherever possible. If you need to HEC-ingest a synthetic sample to test the parser, ask the user
for permission first every time. The live stream usually makes sample ingest unnecessary: deploy
the parser, wait for activation, and the source's own events normalise.

Pull a real sample and read the field shape (key=value, CEF, JSON, syslog). This drives both the
OCSF mapping and the choice of `HOST_FIELD` / `USER_FIELD` / `IP_FIELD` for enrichment.

## Step 1: create or update the parser (OCSF + asset enrichment)

Load `sdl-log-parser`. Two hard rules from that skill apply to every parser here:
the four mandatory attributes are always present (`dataSource.category` fixed at `security`,
`dataSource.name`, `dataSource.vendor`, `metadata.version`), and every OCSF field name is verified
against `sdl-log-parser/references/ocsf-schema-documentation.md`, never invented.

1. **Check the ai-siem catalog** for an existing parser for this vendor before authoring. Most
   common sources already have one; diffing it is far less work than starting from scratch.
2. **Read the current parser** with `sdl_get_file /logParsers/<PARSER_NAME>` and note its version.
   If a marketplace parser carries a `-latest` style managed name, prefer extending it in place
   only if it is editable; if edits would be overwritten on a marketplace refresh, clone it to a
   tenant-owned name and rebind, but remember the sourcetype is set by the sender, so in-place
   extension of the bound parser is usually the only path that affects the live stream.
2a. **Parsers are account-level.** Deploy the parser at account scope even when the data ingests
   at a site. `sdl_put_file /logParsers/<name>` writes the tenant/account-level parser; there is
   no site-scoped parser file. The sourcetype label on the events binds them to the parser by name.

2b. **JSON-per-line sources: use the dotted-prefix capture, not a bare `{parse=json}`.** The
   tenant-validated way to flatten a JSON body into queryable fields is
   `format: "$unmapped.=json{parse=dottedJson}$"` (capture name is the dotted prefix `unmapped.`
   with a trailing dot, plus the explicit `=json` pattern), then rename `unmapped.*` to clean and
   OCSF fields in a `mappings` block. A non-prefix capture like `$json{parse=json}$` captures the
   raw JSON string and emits NO subfields, so every field reads null after deploy. The `mappings`
   block needs `version: 1` and ops under `transformations` (error `unsupported event mapper
   version -1` means `version:` is missing).

3. **Set the four attributes and map to OCSF.** Give the source a clean `dataSource.name` and
   `dataSource.vendor`, and map its fields to OCSF (`src_endpoint.ip`, `dst_endpoint.ip`,
   `actor.user.name`, `network_activity` class fields, etc.) so it is queryable with the same
   schema as the rest of the lake.
4. **Add asset enrichment.** Asset attributes (OS, agent UUID, criticality, AD groups, SID, risk
   factors) are not in the source telemetry. They come from the Asset Inventory through the
   PowerQuery `datasource` command, which is a query, not a REST call: see
   `powerquery/references/datasource-command.md`. Reuse the asset-enrichment solution:
   build the `assetIdentityLookup` and `assetEndpointLookup` datatables with the savelookup PQ in
   `assets/savelookup_identity.pq` and `assets/savelookup_endpoint.pq`, then add two
   `computeFields | lookup` rewrites to this source's parser keyed on the source's host and user
   fields. If the tables already exist from a prior deployment, reuse them rather than rebuilding.
   The endpoint lookup includes **`device_agentid`** (the numeric console agent id); carry it through
   so detections can bind the Target Asset. For an endpoint-class source, also stamp `device.uid` =
   `device_agentid` plus an endpoint `class_uid` in the parser `mappings` so events-type rules
   auto-bind (the tested minimum); for network/identity sources, bind via the scheduled-rule
   `entityMappings` path in Step 3 instead.
5. **Bump `metadata.version`** on every change. This is the propagation canary in Step 2.
6. **Deploy** with `sdl_put_file` passing the version you read as `expectedVersion`.
7. **Validate** by HEC re-ingesting one real sample line with `?sourcetype=<PARSER_NAME>` and
   querying it back, confirming `dataSource.name`, the OCSF fields, and the enriched `device_*` /
   `user_*` fields populate, and that empty inventory values are null rather than `"[]"`.

## Step 2: wait for propagation

Parsers apply to new events only, and a deploy takes roughly 3 to 5 minutes to activate on the
live stream (tenant-validated). Sleep about 5 minutes, then poll until the new `metadata.version`
appears on fresh events. Each subsequent parser edit incurs the same 3 to 5 minute wait, so batch
parser changes rather than deploying one field at a time:

```
dataSource.name='<DATASOURCE_NAME>' | group events=count() by metadata.version | sort -events
```

Do not build the dashboard or detections off the old, un-normalised events. Wait for the new
version to dominate, then drive everything from the normalised stream.

## Step 3: dashboard and detections (build in parallel)

Both read the now-normalised `dataSource.name='<DATASOURCE_NAME>'` data. Build them together.

### Dashboard (load `sdl-dashboard`)

A comprehensive operational view of the source. Render the relevant panels from
`assets/onboarding_dashboard.template.json` and deploy with `sdl_put_file` to
`/dashboards/<PREFIX> Overview`. Typical panel set for a network/security source:

- Ingest volume over time (`graphStyle: stacked_bar`, `xAxis: time`, bucket matched to range:
  1d to 10m, 7d to 1h, 30d to 1d). A number panel for total events, terminated with `| limit 1`.
- Allowed vs blocked / action breakdown.
- Top source and destination talkers, top ports, top applications or URL categories.
- Top users and top devices, projected through the enriched `user_*` / `device_*` fields so the
  panel carries asset context, not just IPs.
- Geo of external destinations, and any IDS/threat signatures the source emits.

Mind the tenant dashboard pitfalls in the umbrella SKILL.md and the dashboard skill: `markdown:`
not `content:` for markdown panels; `stacked_bar`/`line` not `area` for query-driven series;
nothing after `transpose`; spaces around `-` in arithmetic; `| limit 1` on number panels.

### Detections (load `mgmt-console-api` + `powerquery`)

Identify the top detections that matter for this source class and author them as STAR scheduled
rules from `assets/onboarding_detection.template.json`. Map every rule to MITRE ATT&CK in the
description. Use Purple AI to draft each PowerQuery body, then validate it parses and returns
rows against the live data before deploying.

When validating against demo or freshly seeded data, expect count/volume-threshold rules
(beaconing by repeat count, destination fan-out, large transfer) to return zero rows, because
seed data is usually low-cardinality (about one event per entity) so the threshold is never
crossed. That is not a rule defect. Lead the "returns rows" gate with attribute/category rules
(for example `threat_category='...'`), keep the count-based rules, and note they validate only
against production volume. Never lower a production threshold just to make seed data fire.
Tenant-validated 2026-06-16 on Zscaler firewall logs.

**Present detections to the user for review before deploying.** Show the rule name, severity,
MITRE mapping, and the PowerQuery body for each candidate, and wait for the user to approve (or
prune) the set before any `POST /cloud-detection/rules`. Do not auto-deploy detections.

Detection design rules that hold on this tenant:

- **Scheduled rules only for PowerQuery bodies:** `queryType: scheduled`, `queryLang: "2.0"`,
  PQ in `data.scheduledParams.query`, `treatAsThreat: "UNDEFINED"`, `networkQuarantine: false`.
  Inline active-response is not supported on scheduled rules (drive mitigation from a Hyperautomation flow off the alert); the verdict surfaces via the
  rule severity.
- **Aggregation lives inside `group`.** No `count_distinct(x)` outside a grouping function;
  simplify to `| group hits=count() by ...`.
- **The `scheduledParams.threshold` is the firing threshold**, separate from any internal
  `| filter hits >= N`. Match `runIntervalMinutes` and `lookbackWindowMinutes` (for example 60/60)
  to avoid overlap and duplicate alerts.
- **End every rule body with an explicit `| columns` projection.** After the `group` (and a
  lookup-after-group to pull enriched `device_*` / `user_*` context), project the metric, the key
  OCSF/vendor fields, and the asset-context columns: `... | lookup device_host, device_os,
  device_agentuuid, device_criticality from <table> by device_ip = src_ip | columns <metric>,
  src_ip, dst_ip, dst_port, device_host, device_os, device_agentuuid, device_criticality | sort
  -<metric>`. Without `| columns` the alert has no named output columns and the asset context is
  lost.
- **Map the asset with `entityMappings` (capped at 3).** Add a top-level `data.entityMappings`
  array mapping output columns to security entities, e.g. `[{ "columnName": "device_host" },
  { "columnName": "src_ip" }, { "columnName": "dst_ip" }]`. The API rejects a 4th entry
  (`400: entityMappings: Longer than maximum length 3`), so pick the three highest-value identity
  columns; keep extra context (e.g. `device_agentuuid`, `device_os`) in `| columns` for display.
  For the device entity, project and map the enriched **`device_agentid`** (the numeric console
  agent id) and/or `device_host` so the alert binds a real Target Asset rather than "Unknown Device".
  Binding reconciles against the live Asset Inventory, so the enriched id must belong to an enrolled
  agent. See the tested binding matrix in `powerquery/references/detection-rules.md`.
- **Set an appropriate cool-off, never 24h.** `data.coolOffSettings.renotifyMinutes` suppresses
  re-notification per entity. With streak-dedup on, a long cool-off (e.g. 1440) masks an ongoing
  threat for a day. Tie it to severity and the run cadence: High active-threat rules ~60 (re-notify
  each cycle so live C2 stays visible), Medium recon/anomaly rules ~240.
- **List with `isLegacy=false`.** Every `GET /cloud-detection/rules` must pass `isLegacy=false`
  or scheduled rules are silently omitted. Trust the POST's returned `data.id` as authoritative.
- New rules land as `Draft`/`Disabled`; enable separately with
  `PUT /cloud-detection/rules/enable` only if the user wants them live.
- If the POST reports Scheduled Detections is not enabled on the tenant, stop and tell the user
  to enable the feature; do not silently downgrade to S1QL.

Candidate detections by source class (pick what the source actually emits):

- Firewall / network: outbound to known-bad or newly-seen external IP; high-frequency BLOCK
  retries (beaconing blocked at perimeter); large outbound transfer; connection on non-standard
  port; traffic to anonymiser/Tor.
- Web proxy / content filter: first-ever access to a new domain at volume; access to a blocked
  category that succeeded; high-volume download.
- IDS/IPS: any high-severity signature; repeated signature from one source.
- Identity / SaaS: impossible travel; off-hours admin login; MFA fatigue; new mail-forwarding rule.

## Step 4: Hyperautomation flow, then ask where to deploy

Load `hyperautomation`. The primary HA deliverable is a **SOC threat-response
playbook tied to the detections you just built**, not a generic monitor. It should automate what
an analyst would actually do when one of those detections fires:

1. **Singularity Response Trigger** on the source's alerts (filter `name contains '<source/rule>'`,
   `severity in [HIGH, MEDIUM]`, event_type `alert`, subtype `CREATE`). Keep `run_automatically`
   false so the analyst approves containment in the Singularity Response console; set true for
   fully automated response.
2. **Extract IOCs** from the alert (internal `src_ip`, external `dst_ip`, `device_agentuuid`) with
   a `Function.DEFAULT` fallback chain (confirm the exact alert field paths against a real fired
   alert).
3. **Enrich** the external destination with VirusTotal (`/api/v3/ip_addresses/{{dst_ip}}`).
4. **Gate containment on threat intel.** Only on a VT-malicious verdict
   (`last_analysis_stats.malicious > 0`) take action; never contain on the detection alone (this
   mirrors the evidence-discipline rule: a detection is a hypothesis, not a verdict).
5. **Contain**: block the destination as a Threat Intelligence IOC
   (`POST /threat-intelligence/iocs`) and network-quarantine the source endpoint
   (`POST /agents/actions/disconnect` by agent UUID).
6. **Document and notify**: add a note to the alert via UAM GraphQL
   (`addAlertNote`, wrap text in `Function.HTML_ENCODE`) and post a SOC notification.
7. **Branch for internal-only alerts** (e.g. a host-scan detection with no single external IOC):
   route to analyst triage with enrichment context instead of auto-containment.

Render `assets/threat_response_workflow.template.json` for this (tokens: `{{SOURCE_LABEL}}`,
`{{ACCOUNT_ID}}`, `{{VT_API_KEY}}`, `{{NOTIFY_WEBHOOK_URL}}`, `{{IOC_TTL_HOURS_NEG}}`).

**Present the HA flow(s) to the user for review before importing**, the same as detections: show
what each flow does and its trigger, and wait for approval. Then ask **where to deploy** (which
site, or account scope) and import scoped:

- Import (account): `POST /web/api/v2.1/hyper-automate/api/public/workflow-import-export/import?accountIds=<acct>`
  with body `{ "data": <workflow> }`. For a site, use `?siteIds=<site>` instead.
- Publish in the SAME step as the import (an import is not complete until it is a Shared Draft): `POST /hyper-automate/api/v1/workflows/{id}/publish`
  (bodyless, `?accountIds=`/`?siteIds=`, returns `204`). The flow lands as an `inactive` Shared Draft.
- This response playbook calls the S1 mgmt API (IOC create, agent disconnect, alert note), so bind
  the **"SentinelOne"** mgmt connection on the integration actions, and set the VirusTotal API key
  and SOC webhook. Activation needs those bound first (a `400 "invalid references"` otherwise), so a
  freshly imported flow stays a draft for the analyst to finalise in the builder, then activate.

## Step 5: verify and summarise

Re-fetch the parser, dashboard, and rules; confirm versions and IDs; run each rule's PQ body once
against live data to confirm it parses. Summarise the deployed artifacts (paths, IDs, site) and
the example normalised-and-enriched record, then hand off the rendered files.

## Gotchas specific to onboarding

- A source with no `dataSource.name` is not "empty", it is un-normalised. Find it by `parser=`,
  not by `dataSource.name`.
- A `parser=<name>` label with no `/logParsers/<name>` file (a 404 on `sdl_get_file`) and no
  `dataSource.name` means the events were tagged with a sourcetype but never transformed. Creating
  the parser at that exact path normalises the live stream going forward, which is the core of the
  onboarding fix. The 404 is a "create me", not an error.
- Do not assume the source is editable. The `parser`-attribute rule in Step 0 is the gate.
- JSON-per-line flatten: `$unmapped.=json{parse=dottedJson}$` (dotted-prefix capture) then rename
  in `mappings`. A bare `$json{parse=json}$` emits no subfields. `mappings` needs `version: 1` and
  `transformations`.
- Parsers are account-level; deploy at account scope even when the source ingests at a site.
- Parser activation is 3 to 5 minutes per deploy. Batch parser changes; do not iterate one field
  at a time.
- Wait out parser propagation (Step 2) before building anything downstream, or panels and rules
  will be built against the wrong schema.
- Numeric counters (bytes, packets, duration) can be string-typed in SDL; wrap with `number()`
  before arithmetic or `>=` in panels and rules.
- Reuse the asset-enrichment datatables if they already exist; do not rebuild them per source.
- Capturing an ISO8601 string into the reserved `timestamp` field can silently drop the event;
  capture it under `unmapped.*` and let the ingest receive-time stand for near-real-time sources.
- Enrichment on a network source keys on IP, not hostname. Build an IP-keyed endpoint lookup
  (`assets/savelookup_endpoint_byip.pq`, which puts `device_ip` first so the join resolves and
  carries `device_agentid` / `device_assetid` for Target-Asset binding) and key the parser
  `| lookup ... by device_ip = unmapped.<client_ip>` (use the pre-rename `unmapped.*` field, since
  the `computeFields` rewrite runs before `mappings` renames). Reuse ONE generic IP-keyed table
  (for example `assetEndpointByIp`) across all network sources rather than building one per source.

## Deployed artifacts

A full deployment produces the artifacts below. Each renders from a template in `assets/` and is deployed through the matching primitive skill. The `<prefix>` is the solution/customer code.

| Artifact | Template | Deployed to | Purpose |
|---|---|---|---|
| Source parser (OCSF + enrichment) | `assets/parser.template.json` | AI SIEM parser `/logParsers/<parser-name>` | Normalise the raw stream to OCSF, set the four mandatory attributes, and stamp device/user context plus `device.uid`/`class_uid` |
| Endpoint lookup builder | `assets/savelookup_endpoint.pq` | SDL datatable `/datatables/<prefix>EndpointLookup` | Persist device context keyed by hostname for the parser `lookup` |
| Identity lookup builder | `assets/savelookup_identity.pq` | SDL datatable `/datatables/<prefix>IdentityLookup` | Persist AD/user context keyed by samAccountName for the parser `lookup` |
| IP-keyed endpoint builder | `assets/savelookup_endpoint_byip.pq` | SDL datatable `/datatables/<prefix>EndpointByIp` | Device context keyed by IP for network sources that key enrichment on client IP |
| Source dashboard | `assets/onboarding_dashboard.template.json` | `sdl_put_file /dashboards/<prefix> Overview` | Operational view: ingest volume, action breakdown, top talkers/ports/users/devices, geo, signatures |
| Source detections | `assets/onboarding_detection.template.json` | STAR rule via `POST /web/api/v2.1/cloud-detection/rules` | MITRE-mapped scheduled detections for the source class with `entityMappings` Target-Asset binding |
| Threat-response workflow | `assets/threat_response_workflow.template.json` | Hyperautomation workflow import | Alert-triggered SOC playbook: extract IOCs, VT-gate, contain, document, notify |
| Refresh workflow | `assets/refresh_workflow.template.json` | Hyperautomation workflow import | Re-run the savelookup builders on a schedule so enrichment tables stay current |
