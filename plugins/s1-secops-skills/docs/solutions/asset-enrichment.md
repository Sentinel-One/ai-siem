# Solution: Asset enrichment of raw logs

Enrich ingested events with device and user context from the Singularity Asset Inventory, so a
thin source log such as `hostname=ABRAX username=adm.webb action=logon` becomes a contextualised
event carrying OS, IP, agent UUID, site, AD principal, SID, group membership, privilege, asset
criticality and risk factors. An analyst can then triage without leaving the event.

This is part of the `sdl-solutions` skill. It orchestrates the primitive skills
(`powerquery`, `sdl-api`, `sdl-log-parser`,
`hyperautomation`); it does not reimplement them.

## Features

- **Device + user context on every event**: OS, IP, agent UUID, site, AD principal, SID, group membership, privilege, asset criticality, and risk factors, sourced from the Singularity Asset Inventory.
- **Multi-select enrichment catalog**: Device, User/AD, Vulnerabilities, Misconfigurations, Open alerts, or Cloud context; pick any combination in one prompt.
- **Three deployment modes**: ingest-time (parser stamps context and enables asset auto-binding on detections), query-time (`| lookup`, no parser), or automatic lookup (small shared reference sets).
- **Asset auto-binding for detections**: stamps the unified asset id / console agent id plus a `class_uid` so STAR alerts resolve the real Target Asset.
- **Daily refresh**: a Hyperautomation flow rebuilds the `savelookup` tables so context stays current; empty inventory values are suppressed to null.
- **Source-agnostic keys**: keyed on hostname/username (`samAccountName` or the multi-domain-safe `principalName`), with IP-keyed tables for network sources.

## Run it with one prompt

The skill runs a short parameter interview, previews the rendered config, then deploys and
validates. Example prompts:

- *"Deploy the asset enrichment solution for Acme on the Acme site"*
- *"Enrich the firewall logs with device and user info"*
- *"Add asset enrichment, query-time only, no parser"*

Adding an enrichment is two short questions: what to enrich with (multi-select, from the catalog
below) and the **deployment mode** (ingest-time parser, query-time lookup, or automatic lookup, see
"Enrichment deployment mode"). Pick any combination of enrichments:

- *"Add enrichment: device context and open vulnerabilities, keyed on hostname"*
- *"Enrich each event with user AD groups and privilege, and the device criticality"*

| Enrichment | Source | Joins by | Example fields |
|---|---|---|---|
| Device context | `datasource assets from 'surface/endpoint'` | hostname | console agent id, OS, IP, agent UUID, site, criticality, risk factors |
| User / AD context | `datasource assets from 'surface/identity'` | username | principal, SID, domain, DN, groups, privileged, criticality |
| Vulnerabilities | `datasource vulnerabilities` | hostname | open count, critical, high, max CVSS |
| Misconfigurations | `datasource misconfigurations` | hostname | count, high count |
| Open alerts | `datasource alerts` | hostname or user | open count, max severity |
| Cloud resource | `datasource assets from 'surface/cloud'` | hostname / instanceId | provider, account, region, instance type |

Everything else (artifact name prefix, the source being enriched, key field names, the per-source
field set, empty-value suppression, target site) is auto-derived and shown in the preview, not
prompted.

## Enrichment deployment mode

The skill always asks which of three modes to use:

| Mode | When applied | Stored on event | Needs parser in AI SIEM | Auto-maps asset on detections | Table cap |
|---|---|---|---|---|---|
| Ingest time (parser) | at ingest | yes, all fields | yes | yes | up to 150 MB per table |
| Lookup (query time) | at query time | no | no | no | up to 150 MB per table |
| Auto lookup | at query time, tenant-wide | no | no | no | 100 rows / 5 MB / 50 cols |

Ingest-time mode requires the parser to be deployed in AI SIEM (Singularity Data Lake) and is the only
mode that stamps the binding fields onto events so STAR detections auto-populate the Target Asset.

A parser cannot read the Asset Inventory live: the `datasource` command is rejected inside a parser
(it is a query-only command), so parser mode always needs a materialized lookup table (the refresh
flow keeps it current automatically). If you want no stored table at all, enrich at query time by
joining live against `datasource assets`, for example:

```
| join (dataSource.name='<source>' hostname=* | columns timestamp, hostname, username),
       (| datasource assets from 'surface/endpoint'
          | filter name = * | columns hostname=name, device_os=os, device_site=s1SiteName, device_crit=assetCriticality)
  on hostname
```

That avoids maintaining a table, but it re-scans the inventory on every run and works only in hunts
and dashboards, not in parsers or alert triggers.

## Asset mapping on detections

So detection alerts bind a Target Asset instead of showing "Unknown Device", the enrichment captures
the asset's **unified asset id** (the `id` from the asset inventory) as well as the console agent id.
The tested minimum for an events-type STAR rule is a uid field carrying that id plus a `class_uid`:
in parser mode the parser stamps `device.uid` (the unified asset id, or the console agent id for
endpoints) plus an endpoint `class_uid`. The unified asset id is the universal key, it resolves
devices, identities (stamped in `user.uid` with an identity class), and cloud resources alike. A uuid
or AD objectGUID/SID does not resolve the specific asset. For any source type a scheduled detection can
also bind by mapping the identity columns (unified asset id, host, agent id) as its entities. Binding
is reconciled against the live Asset Inventory, so only real assets bind; a made-up id stays "Unknown
Device". Keep the refresh flow running so newly added assets resolve.

## What gets deployed

- One SDL datatable per selected enrichment, built from the `assets` datasource with `savelookup`
  (empty `riskFactors` `"[]"` is converted to null so no empty field is written).
- Parser mode: an SDL log parser with `computeFields | lookup` rewrites that join by hostname and
  username. Query mode: ready-to-run `| lookup` snippets instead.
- Optional Hyperautomation flow that re-runs the savelookup queries daily to keep tables current.

## Validation

The deployment ingests a sample whose hostname and username exist in the tables, then queries the
event back to confirm the `device_*` and `user_*` fields populate and that empty values are null,
not `"[]"`. `metadata.version` is the parser propagation canary.

## Notes and limits

- Lookup datatables can be up to 150 MB each, so the savelookup `limit` can be raised for large
  inventories. The 100-row / 5 MB cap applies only to automatic lookups.
- `samAccountName` is not unique across AD domains; use `principalName` (DOMAIN\\sam) when the logs
  carry that form.
- The Hyperautomation refresh actions must bind the **SentinelOne SDL** connection (Bearer). The
  SentinelOne mgmt connection (ApiToken) returns HTTP 500 against the SDL query endpoint.

## For engineers

The execution detail (savelookup builders, parser template, deploy order, gotchas) lives in the
playbook the skill reads: [`sdl-solutions/references/asset-enrichment.md`](../../skills/sdl-solutions/references/asset-enrichment.md).
The `datasource` command reference is
[`powerquery/references/datasource-command.md`](../../skills/powerquery/references/datasource-command.md).
