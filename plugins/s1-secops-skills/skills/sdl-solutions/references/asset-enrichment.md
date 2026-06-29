# Playbook: Asset enrichment of raw logs

Enrich ingested events with device and user context from the Singularity Asset Inventory. A
thin source log such as `hostname=ABRAX username=adm.webb action=logon` becomes a contextualised
event carrying OS, IP, agent UUID, site, AD principal, SID, group membership, privilege flag,
asset criticality and risk factors, so an analyst can triage without leaving the event.

The asset attributes are not in event telemetry and the unified inventory REST API returns them
null on at least one tenant. The only query path to them is the PowerQuery `datasource` command
(`datasource assets from 'surface/identity'` and `'surface/endpoint'`). See
`powerquery/references/datasource-command.md`.

## Prompts (two required questions, the rest defaulted)

Adding an enrichment takes TWO short questions, what to enrich with and the deployment mode.
Everything else has a safe default, so do not ask for it unless the answer is genuinely ambiguous
or the user volunteers a change.

- **Required, multi-select, what to enrich with:** "What should each event be enriched with?" Offer
  the enrichment source catalog below and let the user pick any combination (for example Device + User,
  or Device + Vulnerabilities + Alerts).
- **Required, single-select, the deployment mode:** "How do you want the enrichment applied, ingest
  time with a parser, query-time lookup, or an automatic lookup?" Always ask this; do not assume a
  default. The three modes:
  - **Ingest time (parser)** — the context is stamped on every event at ingest by an SDL log parser.
    This **requires the parser to be deployed in AI SIEM (Singularity Data Lake)**. Once deployed the
    context is always-on and queryable like any native field, and this is the only mode that lets STAR
    detections auto-map the asset, because the parser also stamps `device.uid` / `user.uid` + `class_uid`
    from the enriched ids. Best for always-on context on a source.
  - **Lookup (query time)** — no parser; the analyst joins the lookup table at query or dashboard time
    with `| lookup`. Lean storage, nothing is written on the event, fields are chosen per query.
  - **Auto lookup (automatic lookup)** — a tenant-wide automatic lookup applied at query time, for small
    shared reference sets only (100-row / 5 MB / 50-col cap). It does NOT cover the full asset tables and
    does not apply inside dashboards, alert triggers, or parser PowerQueries.
- **Optional toggle (default: daily):** Hyperautomation refresh cadence, or none.

Auto-derived, do NOT prompt for these (state them in the preview instead):

- `PREFIX` from the customer or site code.
- `DATASOURCE_NAME` (the source being enriched) from the onboarding context; ask only if unknown.
- Event key fields: `HOSTNAME_FIELD` default `hostname`, `USERNAME_FIELD` default `username`;
  identity key `samAccountName` (switch to `principalName` only if the logs carry `DOMAIN\user`).
- Field set per source: the catalog defaults.
- Empty suppression: on.
- Site: from the active deployment; resolve the name to a siteId.

### Enrichment source catalog (all `datasource` options)

Each row is one selectable enrichment. The builder query, join key, and default fields are fixed,
so the user only picks the row(s); the playbook renders the rest.

| Pick | Builder source | Joins event by | Default enriched fields | Lookup table |
|---|---|---|---|---|
| Device context | `datasource assets from 'surface/endpoint'` | hostname | device_assetid, device_agentid, device_os, device_ip, device_agentuuid, device_lastuser, device_site, device_criticality, device_riskfactors | `{{PREFIX}}EndpointLookup` |
| User / AD context | `datasource assets from 'surface/identity'` | username (samAccountName) | user_assetid, user_principal, user_sid, user_domain, user_dn, user_groups, user_privileged, user_criticality, user_riskfactors | `{{PREFIX}}IdentityLookup` |
| Vulnerabilities | `datasource vulnerabilities` | hostname (assetName) | vuln_open_count, vuln_critical, vuln_high, vuln_max_cvss | `{{PREFIX}}VulnLookup` |
| Misconfigurations | `datasource misconfigurations` | hostname (assetName) | misconfig_count, misconfig_high | `{{PREFIX}}MisconfigLookup` |
| Open alerts | `datasource alerts` | hostname (assetName) or user | alert_open_count, alert_max_severity | `{{PREFIX}}AlertLookup` |
| Cloud resource | `datasource assets from 'surface/cloud'` | hostname or instanceId | cloud_provider, cloud_account, region, instance_type | `{{PREFIX}}CloudLookup` |

Device and User columns are tenant-validated. For Vulnerabilities, Misconfigurations, Alerts, and
Cloud, confirm the real source columns first with `| datasource <name> [from <dataset>] | limit 1`
(field names vary by tenant), then map them into the builder. The aggregate sources
(vulnerabilities, misconfigurations, alerts) group to one row per asset before savelookup:

```
| datasource vulnerabilities
| filter assetName = *
| group vuln_open_count = count(),
        vuln_critical = count(severity == 'CRITICAL'),
        vuln_high = count(severity == 'HIGH')
  by hostname = assetName
| limit 150000
| savelookup '{{PREFIX}}VulnLookup'
```

### Enrichment deployment mode (the second prompt)

| Mode (what the user picks) | Applied | Stored on event | Needs a parser in AI SIEM? | Asset auto-maps on detections? | Table size limit | Best for |
|---|---|---|---|---|---|---|
| **Ingest time (parser)** | ingest | yes, all fields | **Yes** (`/logParsers/<name>`, account scope) | **Yes** (parser stamps `device.uid`/`user.uid` + `class_uid`) | up to 150 MB per table | always-on context on a source |
| **Lookup (query time)** | query time | no | no | no (analyst joins at query time) | up to 150 MB per table | lean storage, analyst picks fields, works in dashboards |
| **Auto lookup** | query time, tenant-wide | no | no | no | 100 rows, 5 MB, 50 cols | small shared reference sets only |

**Ingest time (parser) requires the parser to be deployed in AI SIEM (Singularity Data Lake)** with
`sdl_put_file` to `/logParsers/<name>` at account scope (parsers are account-level), and it is the only
mode that puts the binding fields on the event so STAR detections auto-map the asset. Automatic lookups
do not apply inside dashboards, alert triggers, or parser PowerQueries, and the 100-row cap rules out the
full asset tables. Use ingest or query mode for the full tables; reserve auto for small sets. See
`powerquery/references/automatic-lookups.md`.

**A parser cannot query `datasource` directly: a lookup table is mandatory for parser mode.**
Tenant-validated 2026-06-14: deploying a parser whose `computeFields` used
`| datasource assets from 'surface/endpoint' | filter name = hostname | columns ...` was rejected at
`putFile` with `400 "Used unsupported commands in parser: datasource"`. A parser's PQ subset is
`columns, filter, let, lookup, parse` only; `datasource` is a pipeline source and is disallowed.
So ingest-time enrichment must go through a materialized table (`savelookup` then `| lookup`); there
is no way to read the Asset Inventory live from inside a parser. The HA refresh flow automates the
table upkeep, so this is not a manual step.

**Zero-table alternative (query time only):** `datasource` IS allowed in a normal query, so you can
join live against it with no stored table. `join` must be the FIRST command, so both sides are
subqueries:

```
| join (dataSource.name='<source>' hostname=* | columns timestamp, hostname, username),
       (| datasource assets from 'surface/endpoint'
          | filter name = * | columns hostname=name, device_os=os, device_site=s1SiteName, device_crit=assetCriticality)
  on hostname
| columns timestamp, hostname, username, device_os, device_site, device_crit
```

Tenant-validated 2026-06-14: this enriched live SentinelOne endpoint events with OS/site/criticality
straight from the asset datasource, no datatable involved. Trade-off: it re-scans the asset
datasource on every run (cost/latency) and works only in ad-hoc hunts and dashboards, NOT in parsers
or alert-trigger bodies. Prefer it when the goal is zero stored tables and enrichment is only needed
at query time; prefer parser + `| lookup` when context must be stamped on every event at ingest.

### Minimum attributes for automatic STAR-rule alert enrichment (binding the Target Asset)

Enriching context onto an event is separate from getting a detection ALERT to bind the asset (so it is
not "Unknown Device"). An events-type STAR rule binds the Target Asset automatically from a uid field on
the event, so the enrichment has to stamp the right identifier plus a class.

**Minimum: a uid field carrying the asset's identifier + a `class_uid`.** Tenant-tested 2026-06-14:

- **Universal key, any asset type:** the **unified asset id** (the `id` from `datasource assets`,
  enriched as `device_assetid` / `user_assetid`) resolves the specific asset of any type. Stamp it into
  `device.uid` (device / cloud) or `user.uid` (identity) with a `class_uid`. Confirmed: `user.uid` = a
  user's unified id + class `3002` resolved the AD User `jdoe`; `device.uid` = a cloud resource's unified
  id + class `6003` resolved an AWS CloudWatch Log Group; `device.uid` = a host's console agent id +
  class `1007` resolved the host (medicalcenter, validated end to end via this template).
- **Endpoints also accept the console agent id** (`device_agentid` = `agentId`) in `device.uid`. The
  parser template stamps `device.uid` from the first of `device_agentid` / `device_assetid`.
- **`class_uid` is required** (no class → Unknown Device): an endpoint class (1xxx, e.g. `1007`) for
  devices, an Identity class (3xxx, e.g. `3002`) for users. The resolved asset's real category comes from
  inventory, not the class.
- **A uuid / objectGUID / SID does NOT resolve.** `agent.uuid` / `device.agent.uuid` only populate the
  display; an AD objectGUID/SID only types the asset as "AD User". Only the unified asset id (or the
  console agent id for endpoints) resolves the specific named asset.
- **Real inventory match required.** A fabricated id stays "Unknown Device". Keep the lookup current (the
  refresh flow) so newly enrolled/added assets resolve.

**Two delivery paths:**

- **Parser-stamped (events rules):** the parser maps `device.uid` (or `user.uid` for an identity-centric
  source) from the enriched `*_assetid` and sets `class_uid` (`{{ENDPOINT_CLASS_UID}}`). Validated end to
  end 2026-06-14 for devices.
- **Scheduled rule + `entityMappings` (any source):** project `device_host` / `device_assetid` /
  `device_agentid` / `device_agentuuid` in `| columns` and set `entityMappings` on them. The general
  fallback that binds for network / identity / cloud sources.

Full tested binding matrix and the exact minimum: `powerquery/references/detection-rules.md`.

## Step 1: build the selected lookup tables

Build only the tables for the enrichments the user picked in the catalog (not always both). For
each selected row, run its builder through the LRQ runner (powerquery): it reads the
`datasource` and persists with `savelookup`. The shipped builders cover Device
(`assets/savelookup_endpoint.pq`) and User (`assets/savelookup_identity.pq`); render the catalog's
aggregate pattern for Vulnerabilities / Misconfigurations / Alerts / Cloud after confirming their
columns. Empty `riskFactors` (`"[]"`) is converted to null. Verify each table with a `\| lookup`
readback before continuing.

Keys: identity table keyed on `{{USERNAME_KEY}}`; endpoint and the aggregate tables keyed on
hostname. If `USERNAME_KEY` is samAccountName, note in the preview that it is not unique across AD
domains and that principalName (DOMAIN\\sam) is the multi-domain-safe key, provided the source logs
carry that form.

## Step 2: deliver the enrichment

**parser mode.** Render `assets/parser.template.json` (parser `{{PREFIX}}_enrich`, dataSource.name
`{{DATASOURCE_NAME}}`, two computeFields `\| lookup` rewrites against the two tables) and deploy
with `sdl_put_file` to `/logParsers/{{PREFIX}}_enrich`. Bump `metadata.version` on every change.
The template also includes a v1 `mappings` block that copies `device_agentid` to `device.uid` and
`device_agentuuid` to `device.agent.uuid` and sets `class_uid` = `{{ENDPOINT_CLASS_UID}}` (default
`1007`), so events-type detections on this source bind the Target Asset (see "Asset mapping on
detections" above). For a non-endpoint source set `{{ENDPOINT_CLASS_UID}}` to the source's real OCSF
class and rely on the scheduled-rule `entityMappings` path instead. Validate that `device.uid` and
`class_uid` populate on a re-ingested event before relying on auto-binding.

**query mode.** Do not deploy a parser. Give the analyst ready-to-run `\| lookup` snippets, for
example `<source query> \| lookup <fields> from {{ENDPOINT_TABLE}} by hostname = {{HOSTNAME_FIELD}}`.
Recommend lookup-after-group so the join runs once per key.

**auto mode.** Only for a small table. Add a spec to `/automaticLookups` (read current version
first, append, write back with expectedVersion). Output value field names must be unique across
all specs.

## Step 3: validate

Ingest a sample whose hostname and username exist in the tables, with the parser bound via the
HEC sourcetype, then query back:

```
hostname=<known host> username=<known user> action=logon outcome=success
```

```
dataSource.name = '{{DATASOURCE_NAME}}'
| sort -timestamp | limit 10
| columns timestamp, metadata.version, {{HOSTNAME_FIELD}}, {{USERNAME_FIELD}},
          device_assetid, device_agentid, device.uid, class_uid,
          device_os, device_ip, device_site, device_criticality, device_riskfactors,
          user_assetid, user_principal, user_sid, user_domain, user_groups, user_privileged,
          user_criticality, user_riskfactors
```

Confirm the expected fields populate and that empty values are null, not `"[]"`. For asset binding,
confirm `device.uid` (= the console agent id) and `class_uid` are populated; if so, an events-type
detection on this source will bind the Target Asset. Parser changes take a few minutes to propagate;
poll until the new `metadata.version` appears on fresh events.

## Step 4: keep the tables current (Hyperautomation)

If `SCHEDULE_HOUR` is set, render `assets/refresh_workflow.template.json` and deploy it with the
hyperautomation skill. It is a scheduled workflow with two HTTP actions that re-run
the two savelookup queries against the LRQ API, so the tables stay current and keep the empty
suppression. Deploy scoped to the site:

- Import: `POST /web/api/v2.1/hyper-automate/api/public/workflow-import-export/import?siteIds={{SITE_ID}}` with body `{ "data": <workflow> }`.
- Publish in the SAME step as the import (an import is not complete until it is a Shared Draft): `POST /hyper-automate/api/v1/workflows/{id}/publish` (bodyless, `?siteIds={{SITE_ID}}`, returns `204`); it lands as an inactive Shared Draft.
- **Bind the "SentinelOne SDL" connection (Bearer), NOT the "SentinelOne" mgmt connection.** The SDL query endpoint `/sdl/v2/api/queries` requires `Authorization: Bearer`. The mgmt connection signs as `ApiToken` and the action returns HTTP 500 "Header must start with Bearer". The "SentinelOne SDL" connection uses Bearer by default. Tenant-validated 2026-06-13.

## Gotchas

- Single-quote slash dataset names: `from 'surface/identity'`, `from 'surface/endpoint'`.
- `from identity` / `from device` are sparse; use the `surface/*` datasets for full attributes.
- samAccountName is not unique across domains; principalName is the safe key.
- The identity builder filters `objectSid = *`, so SID-less objects return null on lookup (a no-match, not suppression).
- Parsers apply to new events only; re-ingest after each change when validating.
- Automatic lookups: 100 rows / 5 MB / 50 cols combined, and not in dashboards, alert triggers, or parser PQ.
- Lookup datatables (savelookup / `| lookup`) can be up to 150 MB per table, so the `| limit` in the builder queries can be raised well beyond 1000 / 2000 when the inventory is larger. The small 100-row / 5 MB cap applies only to automatic lookups.

## Extending the enrichment

Add fields by extending the savelookup `columns` and the lookup field lists. High-value extras:
identity (serviceAccount, adminCount, groupType, objectGuid, whenChanged), endpoint
(agentVersion, agentNetworkStatus, agentIsInfected, isDcServer, osVersion, lastActiveDt),
and cross-datasource tables from `datasource vulnerabilities` / `misconfigurations` / `alerts`
keyed by assetName or user.

## Deployed artifacts

A full deployment produces the artifacts below. Each renders from a template in `assets/` and is deployed through the matching primitive skill. The `<prefix>` is the solution/customer code.

| Artifact | Template | Deployed to | Purpose |
|---|---|---|---|
| Endpoint lookup builder | `assets/savelookup_endpoint.pq` | SDL datatable `/datatables/<prefix>EndpointLookup` | Persist device context (OS, IP, agent id/uuid, site, criticality, risk factors) keyed by hostname |
| Identity lookup builder | `assets/savelookup_identity.pq` | SDL datatable `/datatables/<prefix>IdentityLookup` | Persist AD/user context (principal, SID, domain, DN, groups, privileged, criticality) keyed by samAccountName |
| IP-keyed endpoint builder | `assets/savelookup_endpoint_byip.pq` | SDL datatable `/datatables/<prefix>EndpointByIp` | Device context keyed by IP for network sources that carry no hostname |
| Enrichment parser | `assets/parser.template.json` | AI SIEM parser `/logParsers/<prefix>_enrich` | Stamp device/user context plus `device.uid`/`user.uid` and `class_uid` on every event at ingest (parser mode) |
| Refresh workflow | `assets/refresh_workflow.template.json` | Hyperautomation workflow import | Re-run the savelookup builders on a schedule so the lookup tables stay current |
