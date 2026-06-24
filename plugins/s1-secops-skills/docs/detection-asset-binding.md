# Asset binding in STAR detection alerts

How to make a SentinelOne **events-type (single-event) STAR / Custom Detection** alert automatically
populate its **Target Asset** with the real device, identity, or cloud resource, instead of showing
"Unknown Device". This is the difference between an analyst seeing `corp-ws-01 (Windows desktop)`
or `jdoe (AD User)` on the alert versus a blank "Unknown Device" they have to chase down manually.

Everything here is tenant-validated (2026-06-14). The full tested matrix lives in the
PowerQuery skill: [`powerquery/references/detection-rules.md`](../skills/powerquery/references/detection-rules.md).

**Related:** for the three rule types (single-event, multi-event correlation, scheduled) and which to
use when, see [detection-rule-types.md](./detection-rule-types.md). Asset binding on third-party and
custom sources depends on the asset identity being **enriched into the raw log first**, the raw log
does not carry the console asset id on its own, so the asset enrichment solution
([`docs/solutions/asset-enrichment.md`](./solutions/asset-enrichment.md)) is the prerequisite for
asset-mapped STAR alerts on those sources.

## How events-rule binding works

An events-type rule (`queryType: "events"`, `queryLang: "2.0"`, boolean S1QL in `data.s1ql`) binds the
Target Asset **automatically from the matched event** with no `entityMappings`. The reconciler reads an
identifier off the event and matches it against the live Asset Inventory. The matched inventory record
supplies the asset's real name and category on the alert.

Two attributes do the work:

1. **An identifier in a `uid` field** on the event (`device.uid` for device/cloud, `user.uid` for identity).
2. **A `class_uid`** so the pipeline treats the event as an asset-bearing event.

If both are present and the identifier matches a real asset, the alert binds. If not, the alert shows
"Unknown Device".

## The universal rule

**Put the asset's unified asset id (the `id` from `datasource assets`) in a `uid` field, plus a
`class_uid`.** The unified asset id is the same id space for every surface, so one key resolves devices,
identities, and cloud resources. The console agent id also works for endpoints.

| Asset type | Identifier field on the event | Identifier value (from `datasource assets`) | `class_uid` | Asset surface |
|---|---|---|---|---|
| Endpoint / device | `device.uid` | console agent id (`agentId`) **or** unified asset id (`id`) | endpoint class, e.g. `1007` | `surface/endpoint` |
| Identity (AD user, IAM role, Okta user) | `user.uid` | unified asset id (`id`) | identity class, e.g. `3002` | `surface/identity` |
| Cloud resource (S3, SNS, log group, EC2, K8s) | `device.uid` | unified asset id (`id`) | a class, e.g. `6003` | `surface/cloud` |

The asset's actual category (Device, Identity, Data Store, Application Integration, Container,
Governance, Server, etc.) is resolved from inventory; the `class_uid` you send only needs to be present
to trigger binding, it does not have to match the asset's true category.

## Attribute binding matrix

The three attribute combinations that resolved the asset, confirmed on a custom `dataSource.name` via
parser-less `isParsed` events against a live account-scoped events rule, read back from `datasource alerts`:

| Asset type | Event attributes | Resolved Target Asset |
|---|---|---|
| Endpoint / device | `device.uid` = console agent id + `class_uid` 1007 | `corp-ws-01` (Windows desktop), validated end to end |
| Identity | `user.uid` = unified asset id + `class_uid` 3002 | `jdoe` (Identity / AD User) |
| Cloud resource | `device.uid` = unified asset id + `class_uid` 6003 | `/aws/ecs/...` (Governance / AWS CloudWatch Log Group) |

## Hard rules

- **`class_uid` is required.** Without it the alert is "Unknown Device", regardless of the identifier.
- **The identifier must match a REAL inventory asset.** Binding reconciles against the live Asset
  Inventory; a made-up id stays "Unknown Device". You cannot fake an asset.
- **Use the unified asset id, not a uuid/GUID/SID.** A uuid never binds. An AD objectGUID/SID only types
  the asset as "AD User" without resolving the specific person. The unified asset id (and the console
  agent id for endpoints) is what resolves the named asset.
- **The rule must be Active before the event arrives.** Events rules evaluate streaming at ingest;
  enabling a rule reports "Activating" and can take up to ~1 hour to become Active. An event that lands
  before the rule is Active is never evaluated.
- **Confirm binding via `datasource alerts`** (`assetName` / `assetCategory` / `assetId`), which matches
  the console Target Asset. The legacy `cloud-detection` REST alert view is device-centric and shows
  identity/cloud binds as no-device, so it is not a reliable check.

## Scheduled (PowerQuery) rules

A scheduled rule (`queryType: "scheduled"`) does not auto-bind. It binds via an explicit
`data.entityMappings` array mapping result columns to entities. Project the asset identity columns in the
rule body (`| columns device_host = ..., device_assetid = ..., src_ip = ...`) and set:

```json
"entityMappings": [ { "columnName": "device_assetid" }, { "columnName": "device_host" }, { "columnName": "src_ip" } ]
```

`entityMappings` is capped at 3 columns. This path binds for any source type and is the general fallback
when the events-rule auto-bind is not suitable.

## Enrich your logs so this happens automatically

You usually do not have the asset's unified id on a raw log; the log has a hostname, username, or IP. The
**asset enrichment solution** in `sdl-solutions` adds the binding identifiers to your events
automatically:

- It builds lookup tables from `datasource assets`, keyed on hostname / username, that carry
  `device_assetid` / `user_assetid` (the unified asset id) and `device_agentid` (the console agent id).
- Its parser stamps `device.uid` (or `user.uid` for an identity source) from those enriched columns and
  sets `class_uid`, so every event on the source becomes bindable and STAR alerts auto-populate the
  Target Asset.
- A Hyperautomation refresh flow keeps the lookup tables current so newly enrolled/added assets resolve.

Full guide and prompts: [docs/solutions/asset-enrichment.md](./solutions/asset-enrichment.md). The
deployable playbook and templates are in the
[`sdl-solutions`](../skills/sdl-solutions/references/asset-enrichment.md) skill.

## References

- Tested binding matrix and the exact minimum per asset type:
  [`powerquery/references/detection-rules.md`](../skills/powerquery/references/detection-rules.md)
- Asset enrichment solution (enrich logs with the binding identifiers):
  [docs/solutions/asset-enrichment.md](./solutions/asset-enrichment.md)
- Data source onboarding (OCSF + enrichment + detections that bind assets):
  [docs/solutions/data-source-onboarding.md](./solutions/data-source-onboarding.md)
