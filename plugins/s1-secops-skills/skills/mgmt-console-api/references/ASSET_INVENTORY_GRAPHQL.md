# Asset Inventory GraphQL

Reference for the Asset Inventory GraphQL operations behind the console's Inventory pages: counts per
surface and category, filtered asset lists, per-asset overview (criticality, tags, infection status,
alert counts per severity, agent), and facet counts. Every example on this page was run against a live
tenant as written, read-only.

Use it for:

- counts and coverage questions ("how many Network Discovery assets are missing EPP")
- the unprotected-endpoints list (Network Discovery assets with Missing Protection = EPP)
- per-asset triage context from an alert's `agentUuid`

## Endpoint, auth and tools

```text
POST https://<console>/web/api/v2.1/graphql
Authorization: ApiToken <token>
Content-Type: application/json
{"query": "<graphql document>", "variables": {...}}
```

Same console API token and `ApiToken` prefix as REST. In an MCP client use the s1-secops-mcp tools:

| Tool | Operation | Main inputs |
|---|---|---|
| `asset_inventory_counts` | `assetInventoryAssetCounts` | `scope` |
| `asset_inventory_search` | `assetInventoryAssets` | `surface`, `category`, `subCategory`, `filters`, `sort`, `fields`, `first`, `after`, `maxPages`, `outputFile`, `scope` |
| `asset_inventory_get` | `assetInventoryAssetOverview` | `resourceId` or `agentUuid`, `scope` |
| `asset_inventory_filter_values` | `assetInventoryFiltersCount` | `surface`, `filters`, `fieldIds` (required) |

All four send `query` documents only, so they run in read-only mode. Without the dedicated tools,
`s1_api_post` to `/web/api/v2.1/graphql` with the same document also runs in read-only mode (query
documents are allowed; mutations are refused).

## Errors and schema discovery

| What happens | Response |
|---|---|
| Unknown field, argument, enum or variable type in the document | HTTP 400 `invalid query`, no detail. Check spelling against this page. |
| Wrong value type (for example an ISO string where epoch ms is expected) | HTTP 200, `data: null`, `errors[].message` such as `Validation error (WrongType@[assetInventoryAssets]) ... is not a valid 'Long'` |
| Operator not supported for a field | HTTP 200 with `errors`: `Invalid filter type STRING_IN for field managed_state` |
| `first` above 1000 | HTTP 200 with `errors`: `Maximum page size is 1000` |
| Unknown `sort.by` field | HTTP 200 with `errors`: `Internal server error` |
| Asset id or agent UUID not found | HTTP 200 with `errors`: `Asset with identifier '<id>' not found` |
| Token rejected | HTTP 200 with `errors`: `HTTP fetch failed from 'uaip': 401: Unauthorized` (plus a second content-type message) |

**HTTP 200 is not success.** Always read `errors` before `data`; the tools turn a non-empty `errors`
into a tool error. A `uaip ... 401` was observed on tokens that REST also rejects (HTTP 401, code
`4010010`), so check the token with a REST read such as `GET /web/api/v2.1/accounts?limit=1` before
concluding that the token lacks asset permissions.

Introspection is disabled (`__schema` returns `introspection has been disabled`). Discover field
values with `assetInventoryFiltersCount` (`asset_inventory_filter_values`), and field names from this page.

## Operations

### `assetInventoryAssetCounts`: totals per category and surface

```graphql
query {
  assetInventoryAssetCounts(scope: {scopeType: TENANT, scopeIds: []}) {
    categories { category count subCategories { subCategory count } }
    surfaces { surface count }
  }
}
```

`scope` is optional. `category` and `surface` come back as enums (`WORKSTATION`, `NETWORK_DISCOVERY`),
`subCategory` as display labels (`Desktop`, `Laptop`). Surfaces seen: `CLOUD`, `IDENTITY`, `ENDPOINT`,
`AI_SECURITY`, `NETWORK_DISCOVERY`. These are curated view totals; see "View semantics" before comparing
them with anything else. For a Network Discovery headline use `assetInventoryAssets(surface: NETWORK_DISCOVERY)`
`totalCount`, not this operation.

### `assetInventoryAssets`: filtered, sorted, paged list

```graphql
query q($f: [AssetInventoryFilterInput!], $after: String) {
  assetInventoryAssets(
    first: 100, after: $after,
    surface: NETWORK_DISCOVERY,
    filters: $f,
    sort: {by: "lastActiveDt", order: DESC}
  ) {
    totalCount
    pageInfo { hasNextPage endCursor }
    edges { node {
      id name resourceType category subCategory osFamily assetStatus
      surfaces activeCoverage missingCoverage s1SiteId
      ipAddress internalIps macAddresses manufacturer subnets
      firstSeenDt lastActiveDt lastUpdateDt
      discoveryMethods managedState eppUnsupportedUnknown deviceReview
    } }
  }
}
```

Variables: `{"f": [{"fieldId": "missingCoverage", "stringIn": {"values": ["EPP"]}}], "after": null}`.

`internalIps` is the device's own address and `subnets` the networks it was found on. `ipAddress` is
the public address the site's traffic leaves from, usually the same for every device behind one
gateway: never report it as the device's IP. Checked on a lab network, where every Agent reported
the same external IP that Network Discovery shows as `ipAddress` for all devices there.

- Arguments: `first` (1 to 1000), `after` (cursor), `surface` (enum), `category` (enum, for example
  `WORKSTATION`, `SERVER`, `DEVICE`), `subCategory` (enum), `scope`, `filters`, `sort` (`{by, order}`,
  order `ASC` or `DESC`). `filters` is required by the document shape; pass `[]` for none.
- `totalCount` is the full match count under the filters, independent of `first`.
- Agent-backed assets also carry `agent { uuid agentVersion operationalState }`.
- Network Discovery fields (`managedState`, `eppUnsupportedUnknown`, `deviceReview`, `discoveryMethods`,
  `subnets`, `gatewayIps`) are selectable on every node and are `null` where not applicable.

### `assetInventoryAssetOverview`: one asset

```graphql
query q($u: String) {
  assetInventoryAssetOverview(agentUuid: $u) {
    id name resourceType category osFamily assetStatus s1SiteId
    assetCriticality infectionStatus riskFactors
    tags { key value }
    alertsCount { severity count }
    surfaces activeCoverage missingCoverage
    lastActiveDt firstSeenDt
    agent { uuid agentVersion operationalState }
  }
}
```

- Look up by `agentUuid` (the alert's agent UUID) or by `resourceId` (the inventory `id`); both
  return the same record. `scope` is accepted.
- `assetCriticality`: `critical`, `high`, `medium`, `low`, or `""` (console label "Unassigned").
- `tags` is a list of `{key, value}` (for example key `S1_Asset_criticality`) or `null`.
- `alertsCount` is a list of `{severity, count}` with severities `Info`, `Low`, `Medium`, `High`,
  `Critical`; `null` when the asset has no alerts.
- `infectionStatus`: `Healthy` or `Infected`. `riskFactors` is a list of labels such as
  `Unresolved Alerts`, `High Value`.

### `assetInventoryFiltersCount`: facet counts

```graphql
query {
  assetInventoryFiltersCount(
    surface: NETWORK_DISCOVERY,
    filters: [{fieldId: "missingCoverage", stringIn: {values: ["EPP"]}}],
    fieldIds: ["managedState", "eppUnsupportedUnknown", "deviceReview", "resourceType", "osFamily",
               "discoveryMethods", "s1SiteId"]
  ) { data { fieldId values { label value count } } }
}
```

One call returns counts for many fields under the same `surface`, `filters` and `scope`. Values with
zero matches under the filter can still be listed with `count: 0`. For `s1SiteId` the label and value
are the site id. Use this call to learn exact filter values before filtering.

## Filters

Variable type: `[AssetInventoryFilterInput!]`. Each entry is `{fieldId, <operator>}`; entries are ANDed.

| Operator | Shape | Behaviour |
|---|---|---|
| `match` | `{values: ["win"]}` | contains, case-insensitive (`osFamily` match `win` finds `Windows`); text fields only, see below |
| `stringEqual` | `{value: "Windows"}` | exact, case-sensitive (`windows` matches nothing) |
| `stringIn` | `{values: ["EPP"]}` | any of, exact, case-sensitive (`epp` matches nothing) |
| `dateTimeRange` | `{start: <epoch ms>, end: <epoch ms>}` | `end` optional; values are Long epoch ms, not ISO strings |

Not every field takes every operator:

| Field | Filterable with | Notes |
|---|---|---|
| `missingCoverage`, `activeCoverage`, `surfaces`, `assetStatus`, `category`, `resourceType`, `osFamily`, `deviceReview`, `discoveryMethods`, `eppUnsupportedUnknown` | `stringIn`, `stringEqual` | display values from the facet call. On the list fields (`missingCoverage`, `activeCoverage`, `surfaces`, `discoveryMethods`) `match` returns `Invalid filter type FULLTEXT` |
| `name`, `osFamily` | `match` | |
| `firstSeenDt`, `lastActiveDt` | `dateTimeRange` | |
| `managedState` | none (facet and node field only) | `stringIn`, `stringEqual` and `match` all return `Invalid filter type` |
| `s1SiteId` | none (facet and node field only) | narrow by site with `scope: {scopeType: SITE, scopeIds: ["<siteId>"]}` |

**Enum vs display value.** The `surface`, `category` and `subCategory` ARGUMENTS take enums
(`NETWORK_DISCOVERY`, `WORKSTATION`, `DEVICE`). FILTER values take display labels exactly as the
facet call returns them (`"Network Discovery"`, `"Workstation"`, `"Windows workstation"`, `"EPP"`).
Mixing the two returns HTTP 400 (enum position) or zero rows (filter value).

## Paging

- `first` up to 1000 (`Maximum page size is 1000` above that); follow `pageInfo.endCursor` as `after`
  while `hasNextPage` is true.
- Keep `surface`, `filters`, `sort` and `scope` identical on every page; the cursor encodes the sort
  position. Sort by a stable field (`lastActiveDt`, `name`) for long exports.
- `asset_inventory_search` pages for you with `maxPages`; pass `outputFile` for a full list so rows do
  not pass through the context window.

## Scope

`scope: {scopeType: TENANT | ACCOUNT | SITE | GROUP, scopeIds: ["<id>", ...]}` on all four operations.
`TENANT` takes `scopeIds: []`. Omitting `scope` returns everything the token can see. `SITE` scope is
the way to restrict to one site (the `s1SiteId` field is not filterable). TENANT, ACCOUNT and SITE were
verified live; GROUP is accepted by the tools but was not exercised.

## View semantics: why two counts for "the same" thing differ

The `surface:` argument is the curated console page view. The `surfaces` filter is the raw surface tag.
They differ, by design:

| Query shape | What it counts |
|---|---|
| `assetInventoryAssets(surface: NETWORK_DISCOVERY)` | Network Discovery page view: `assetStatus = Active` only |
| `filters: [surfaces stringIn ["Network Discovery"]]` | every record tagged Network Discovery, Active and Inactive |
| `surfaces` filter plus `assetStatus stringIn ["Active"]` | equals the `surface: NETWORK_DISCOVERY` count exactly |
| `assetInventoryAssets(surface: ENDPOINT)` | Endpoint page view: agent-backed assets only |
| `filters: [surfaces stringIn ["Endpoint"]]` | also agentless records carrying the Endpoint tag (for example `Unknown Device` records) |
| `assetInventoryAssetCounts.surfaces` | equal to the `surface:` argument for `ENDPOINT`, `CLOUD`, `IDENTITY` and `AI_SECURITY`; for `NETWORK_DISCOVERY` it was higher than the `surface:` argument on both tenants measured, so it is not the console Network Discovery number |
| `assetInventoryAssetCounts.categories` | a curated category view that can omit records: on one tenant it reported `DEVICE` 0 while `category: DEVICE` listed thousands of agentless `Unknown Device` records, and on another tenant the two also disagreed |

Rules:

- For Network Discovery and Endpoint questions use the `surface:` argument; it matches what the
  console shows.
- Never mix `assetInventoryAssetCounts` totals with filtered `totalCount` values in one table or
  ratio. Take the denominator and the numerator from the same operation and the same `surface:`.
- When a number must reconcile with PowerQuery or REST, state the view (`surface:` argument or tag
  filter, with or without `assetStatus`).

## PowerQuery and REST equivalents

The GraphQL operations, the PQ `assets` datasource and the REST `xdr/assets` endpoints read the same
inventory. They differ only in default filters.

| Question | GraphQL | PowerQuery | REST |
|---|---|---|---|
| Network Discovery, console view | `surface: NETWORK_DISCOVERY` | `\| datasource assets from 'surface/networkDiscovery' \| filter assetStatus = 'Active'` | `GET /web/api/v2.1/xdr/assets/surface/networkDiscovery?assetStatus=Active` |
| Network Discovery, all records | `surfaces` filter | same PQ without the `assetStatus` filter | same GET without `assetStatus` |
| ND console view, Missing EPP | `surface: NETWORK_DISCOVERY` plus `missingCoverage stringIn ["EPP"]` | add `missingCoverage contains 'EPP'` to the Active filter | `...networkDiscovery?assetStatus=Active&missingCoverage=EPP` |
| Endpoint surface | `surface: ENDPOINT` | `\| datasource assets from 'surface/endpoint'` | `GET /web/api/v2.1/xdr/assets/surface/endpoint` |

Each row was run back to back and returned the same count. The PQ form for the unprotected list:

```text
| datasource assets from 'surface/networkDiscovery'
| filter assetStatus = 'Active' missingCoverage contains 'EPP'
| sort id
| let ip = internalIps
| columns id, name, ip, subnets, ipAddress, resourceType, osFamily, managedState, eppUnsupportedUnknown, deviceReview, firstSeenDt, lastActiveDt
| limit 10000
```

PowerQuery rules for the `assets` datasource:

- A list query (one row per asset, no `group`) must start with `| sort id | let …` before `columns`.
  With no `let` before `columns`, the adapter runs `columns`, `sort` and `limit` itself and returns
  one page: 55 of 610 devices on one console, a different size on each run. Without a unique sort
  first, its paging skips assets that share a name: 665 of 675 on another console. With both, the
  list matched Asset Inventory GraphQL asset by asset on nine consoles. Grouped queries aggregate on
  the server and are not affected.

- Put predicates after the pipe with `| filter`. `| datasource assets ... where (<predicate>)` returns at most
  20 rows whatever the predicate, with no error.
- At very large scale, `missingCoverage` filters are slow: on a console with about 95,000 Network
  Discovery assets each such query took 184 to 208 s, against about 2 s for an `assetStatus` count.
  GraphQL answered the same counts in about a second, so use GraphQL for counts and keep PowerQuery for
  joins with telemetry.

### Which one to use

| Need | Use |
|---|---|
| Counts, coverage, facets, the console view | GraphQL. Counts and facets answer in about a second even at tens of thousands of Network Discovery assets; one `FiltersCount` call returns many breakdowns. |
| One asset's criticality, tags, infection status, alert counts | GraphQL `assetInventoryAssetOverview` (`asset_inventory_get`) |
| Joining assets with telemetry (firewall, DNS, proxy, EDR), lookups, `savelookup`, dashboards | PowerQuery `datasource assets`. Coverage filters and some groupings take minutes at large scale, so keep them out of dashboard panels. A scheduled detection rule cannot use `datasource`. |
| Asset actions, CSV export, notes | REST `xdr/assets/surface/<surface>` (`/action`, `/export`); see `references/tags/Inventory_*.md` |

## Coverage labels

`activeCoverage` and `missingCoverage` hold product labels; Missing Protection is derived from which
surfaces report the asset. Use `asset_inventory_filter_values(fieldIds: ["missingCoverage", "activeCoverage"])`
to list the labels on a tenant.

| Label | Product |
|---|---|
| `EPP` | Endpoint protection agent (Singularity Endpoint) |
| `CWS` | Cloud Workload Security agent |
| `CWS Serverless` | Cloud Workload Security for serverless |
| `ISPM` | Identity Security Posture Management |
| `IDR` | Identity detection and response |
| `Ranger Insights` | Network Discovery insights (documented; not seen live) |
| `CDS` | Cloud Data Security |
| `Data Classification` | Cloud data classification |
| `CNS KSPM` | Cloud Native Security, Kubernetes posture |
| `CNS IaC Scan` | Cloud Native Security, infrastructure-as-code scanning |
| `CNS VM Scan` | Cloud Native Security, agentless VM scanning |
| `CNS Image Scan` | Cloud Native Security, container image scanning |
| `CNS Secret Scan` | Cloud Native Security, secret scanning (documented label) |
| `CNS Secret Scanning (Daily)`, `CNS Secret Scanning (Real-Time)` | secret scanning labels seen live |
| `CNS Detect`, `CNS Remediate`, `Admission Control` | Cloud Native Security labels seen live |
| `AI Security Agent` | AI security coverage |

Surface filter labels seen live: `Cloud`, `Identity`, `Endpoint`, `AI Security`, `Network Discovery`,
`Unspecified`.

## Recipes

### Unprotected endpoints (Network Discovery, Missing EPP)

1. Headline and breakdowns in one call:
   `asset_inventory_filter_values(surface: NETWORK_DISCOVERY, filters: [{fieldId: "missingCoverage", stringIn: {values: ["EPP"]}}], fieldIds: ["resourceType", "osFamily", "eppUnsupportedUnknown", "managedState", "deviceReview", "discoveryMethods", "s1SiteId"])`.
   The denominator is `asset_inventory_search(surface: NETWORK_DISCOVERY, filters: [], first: 1).totalCount`,
   never `asset_inventory_counts`.
2. The list: `asset_inventory_search(surface: NETWORK_DISCOVERY, filters: [{fieldId: "missingCoverage", stringIn: {values: ["EPP"]}}], sort: {by: "lastActiveDt", order: DESC}, first: 1000, maxPages: <n>, outputFile: <path>)`.
3. Newly seen: add `{fieldId: "firstSeenDt", dateTimeRange: {start: <now - 7d in epoch ms>}}`.
4. Agent-capable split: `eppUnsupportedUnknown` (`Supported`, `Unknown`, `Unsupported`) is filterable;
   `managedState` (`Unsecured`, `Unknown`, `Unsupported`) is a facet only. On the tenant measured,
   Missing EPP held only `Supported` and `Unknown` devices; `Unsupported` devices carried no Missing EPP.
5. Remediation for agent-capable devices is Sentinel Deploy (`references/tags/Sentinel_Deploy.md`).

The full report playbook is `sdl-solutions/references/unprotected-endpoints.md`.

### Coverage gaps by asset type

```graphql
query {
  assetInventoryFiltersCount(surface: ENDPOINT, filters: [],
    fieldIds: ["missingCoverage", "activeCoverage", "resourceType"]) {
    data { fieldId values { label count } }
  }
}
```

Then per gap, `asset_inventory_filter_values(surface: ENDPOINT, filters: [{fieldId: "missingCoverage", stringIn: {values: ["<label>"]}}], fieldIds: ["resourceType", "osFamily"])`.
Repeat with `surface: CLOUD` or `IDENTITY` for those views. Facet counts under different filters are
comparable only within the same `surface:`.

### Per-asset triage from an alert

Take `assets[].agentUuid` from `uam_get_alert`, then `asset_inventory_get(agentUuid: "<agentUuid>")`
with the overview fields above. Report `assetCriticality` (authoritative over hostname guesses),
`tags` (including `S1_Asset_criticality`), `infectionStatus`, `riskFactors`, `alertsCount` per
severity and `agent.operationalState`. Alerts ingested through the UAM Alert Interface have no
`agentUuid` (`references/ASSET_LINKAGE.md`); look those up with `asset_inventory_search` and a `name`
`match` filter, and say that the match is by name.
