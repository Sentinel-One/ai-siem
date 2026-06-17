# PowerQuery `datasource` command

The `datasource` command queries SentinelOne-managed data that lives **outside** the data
lake event store: Alerts, Asset Inventory, Misconfigurations, Vulnerabilities, usage Metering,
and SDL retention entitlements. It is the only PowerQuery path to the asset/identity/vuln
inventory, and it is distinct from `dataset 'config://datatables/<name>'` (which reads a saved
lookup table).

Source: SentinelOne Community article 000012487, plus behaviours validated on `usea1-purple` (2026-06-13).

```
| datasource <datasource_name>
| datasource <datasource_name> from <dataset>
```

The command is a **generator**: it starts the pipeline with `|` and supplies its own source,
so the usual "a query may not start with a bare `|` and no initial predicate" rule does not
apply here. In the Event Search UI you must select **All Data** for the `datasource` command
to be available. Results are subject to the normal memory limits, so project narrow columns
and add `| limit N`.

## datasource names

| Value | Source |
|---|---|
| `alerts` | Alerts |
| `assets` | Asset inventory |
| `misconfigurations` | Misconfigurations |
| `vulnerabilities` | Vulnerabilities |
| `metering` | Usage metering reports and tenants |
| `sdl-retention` | SDL retention entitlements |

For time-series, use the aggregated-snapshot variants instead of `compare`/`timebucket`
(see "Time series" below): `alert_aggregated_snapshots`, `vulnerability_aggregated_snapshots`,
`misconfiguration_aggregated_snapshots`.

## `from <dataset>`

Only `assets` and `metering` support multiple datasets; other datasources reject `from`.

**assets datasets:** `account`, `application-integration`, `cloud-application`, `container`,
`data-store`, `device`, `function`, `governance`, `identity`, `network`, `server`, `storage`,
`workstation`, `surface/endpoint`, `surface/cloud`, `surface/identity`, `surface/networkDiscovery`.

**metering datasets:** `tenants` (tenants you can see), `reports` (available report names),
and `<report_name>` (raw rows for one report; list names via the `reports` dataset).

## Discovering columns

Columns vary per source and per dataset. Run the command with a small `limit` to see the
available column set, then filter on those columns:

```
| datasource misconfigurations | limit 5
| datasource misconfigurations | filter environment = 'AWS'
```

## Tenant-validated specifics (read before building asset enrichment)

These cost iteration cycles if you skip them. Validated on `usea1-purple`, 2026-06-13.

- **Slash dataset names MUST be single-quoted.** `from 'surface/identity'` works; bare
  `from surface/identity` returns `400 invalid_argument "Expected a name"`.
- **`from identity` is sparse; `from 'surface/identity'` has the AD attributes.** The plain
  `identity` dataset returns only base inventory metadata (id, name, category, riskFactors,
  assetCriticality, s1Site*, etc.) with **no** directory attributes. To get `objectSid`,
  `principalName`, `samAccountName`, `distinguishedName`, `memberOf`, `member`, `privileged`,
  `adminCount`, `serviceAccount`, `domain`, `forest`, `objectGuid`, `whenChanged`, use
  `from 'surface/identity'`.
- **`from device` is sparse; `from 'surface/endpoint'` has the rich host schema.** Plain
  `device` is mostly "Unknown Device" rows with no hostname. `surface/endpoint` carries `name`
  (hostname), `os`, `osVersion`, `ipAddress`, `internalIps`, `agentUuid`, `agentVersion`,
  `agentLastReportedIp`, `agentLastLoggedInUser`, `domain`, `isDcServer`, `isAdConnector`,
  `lastActiveDt`, `applications`, plus cloud `sourceJson*` columns.
- **`assetCriticality` is null when unset; `riskFactors` is the string `"[]"` when empty.**
  To suppress empties (so downstream enrichment does not write an empty field), use a bare-field
  ternary: `| let rf = (riskFactors == '[]' ? null : riskFactors)`. The `null` literal is valid
  here and yields an unpopulated field.
- **AD objects without a SID exist.** Filter `objectSid = *` on `surface/identity` to keep only
  resolvable user/group objects; objects lacking a SID return null on later lookups.
- **The assets snapshot ignores the query time window.** It reflects current inventory state, so
  LRQ `startTime`/`endTime` (or the Event Search range) do not change the result.
- **`s1ManagementId` typing differs by dataset** (NUMBER in `from device`, STRING in
  `from 'surface/endpoint'`); cast with `number()` before arithmetic if you aggregate on it.

## Building enrichment lookup tables (`datasource` + `savelookup`)

Pipe a `datasource` query into `savelookup '<name>'` to materialise a reusable lookup table.
This is the supported way to turn inventory into an enrichment source that a parser
(`computeFields | lookup`), a dashboard, or an ad hoc hunt can read with
`| lookup ... from <name> by <tableCol> = <eventField>`. See `automatic-lookups.md` for the
query-time/automatic-lookup side, and `commands-reference.md` for `lookup`/`savelookup`.

A saved lookup datatable can be up to **150 MB per table**, so a `savelookup` builder can carry a
high `| limit` for large inventories. The much smaller 100-row / 5 MB / 50-column cap applies only
to tables registered as automatic lookups, not to explicit `| lookup` or `dataset` reads.

```
// Identity enrichment table, keyed on samAccountName, empties suppressed
| datasource assets from 'surface/identity'
| filter resourceType = 'AD User'
| filter objectSid = *
| columns username=samAccountName, user_principal=principalName, user_sid=objectSid,
          user_domain=domain, user_dn=distinguishedName, user_groups=memberOf,
          user_privileged=privileged, user_criticality=assetCriticality, _rf=riskFactors
| let user_riskfactors = (_rf == '[]' ? null : _rf)
| columns username, user_principal, user_sid, user_domain, user_dn, user_groups,
          user_privileged, user_criticality, user_riskfactors
| limit 1000
| savelookup 'assetIdentityLookup'

// Endpoint enrichment table, keyed on hostname
| datasource assets from 'surface/endpoint'
| filter name = *
| filter agentUuid = *
| columns hostname=name, device_os=os, device_ip=agentLastReportedIp,
          device_agentuuid=agentUuid, device_lastuser=agentLastLoggedInUser,
          device_site=s1SiteName, device_criticality=assetCriticality, _rf=riskFactors
| let device_riskfactors = (_rf == '[]' ? null : _rf)
| columns hostname, device_os, device_ip, device_agentuuid, device_lastuser,
          device_site, device_criticality, device_riskfactors
| limit 2000
| savelookup 'assetEndpointLookup'
```

Reading a saved table back with `| lookup` confirmed the round trip (e.g. hostname `ABRAX`
returned `device_os` "Windows 11 Pro", `device_criticality` "high"; `adm.webb` returned SID
`S-1-5-21-1068759508-3553314729-511895651-1136`, group `Domain Admins`).

> Note: a saved lookup table read via `dataset 'config://datatables/<name>'` worked for
> savelookup-created tables in testing, but `dataset` returned 0 rows for a freshly written raw
> CSV. Prefer `| lookup` to enrich. See `automatic-lookups.md`.

## Time series

Do not use `compare timeshift(queryspan())` or `timebucket(...)` on a raw `datasource` query.
Use the aggregated-snapshot datasources, which carry a `snapshotDate`:

```
| datasource alert_aggregated_snapshots
| group count=sum(findingCount) by severity, timestamp=snapshotDate
| transpose severity
```

## Example queries

```
// Count of unresolved alerts, current vs previous window
| datasource alerts | group count() | compare timeshift(queryspan())

// Assets with the most high/critical alerts
| datasource alerts
| filter severity in ('CRITICAL', 'HIGH')
| group count=count() by assetName
| sort -count | limit 100

// Active endpoints missing a protection surface
| datasource assets
| filter assetStatus = 'Active'
| columns missingCoverage
| group count() by missingCoverage

// Vulnerability count by severity
| datasource vulnerabilities
| filter product = 'Singularity Vulnerability Management'
| group count=count() by severity
| sort -count

// Available metering reports
| datasource 'metering' from 'reports'
| columns report_name, product_category, product_name, unit, description
```

## Gotchas (quick list)

- Single-quote any dataset name containing a slash: `from 'surface/identity'`.
- `from identity` / `from device` are sparse; use `from 'surface/identity'` / `from 'surface/endpoint'` for full attributes.
- Only `assets` and `metering` accept `from`; other datasources reject it.
- `riskFactors` empty is the string `"[]"`, not null. Suppress with `(field == '[]' ? null : field)`.
- The assets snapshot ignores the time range.
- No `compare`/`timebucket` on raw datasource queries; use the `*_aggregated_snapshots` variants.
- Subject to memory limits: project narrow columns and add `| limit N`.
