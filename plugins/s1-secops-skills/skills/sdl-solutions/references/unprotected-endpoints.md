# Playbook: Unprotected Endpoints report

Find the devices on the network that should carry the SentinelOne agent and do not, from one prompt,
and hand back a report the user can act on. An unprotected endpoint is a Network Discovery asset in
the console view (Active) whose Missing Protection includes `EPP`. Remediation is Sentinel Deploy for
devices that can take an agent, and device review or segmentation for the rest.

This solution is read-only. It deploys nothing and writes nothing to the tenant: no lookup table, no
rule, no workflow, no dashboard. The deliverable is a report Claude writes from live data (an HTML
artifact by default, `.docx` on request). Every number in it comes from a query listed in its method
appendix.

Primary data path: the Asset Inventory GraphQL tools (`asset_inventory_counts`,
`asset_inventory_filter_values`, `asset_inventory_search`). Field names, filter operators, view
semantics and error shapes: `mgmt-console-api/references/ASSET_INVENTORY_GRAPHQL.md`. Read it first.
PowerQuery is used only for the optional telemetry enrichment and as the fallback when GraphQL is refused.

## Invocation prompt (natural language)

Any of these starts it:

> "Find our unprotected endpoints."
>
> "Which devices on the network are missing the SentinelOne agent, and which of them can we deploy to?"
>
> "Unprotected endpoints report for site `<site name>`, as a Word document."

## Parameters (ask few; default the rest)

| Parameter | Default | Ask? |
|---|---|---|
| Scope | everything the token can see | only if the user names an account or site; resolve the name to an id (`GET /web/api/v2.1/sites?name__contains=<substring>`), then pass `scope: {scopeType: SITE, scopeIds: ["<siteId>"]}` (or `ACCOUNT`) on every call |
| Output | HTML artifact | `.docx` only when asked (use the `docx` skill) |
| Newly seen window | 7 days (`firstSeenDt`) | no |
| Telemetry enrichment | off | offer once at the end: "Check which of these IPs appear in firewall, DNS or proxy logs?" |
| Enrichment window | 7 days | only when enrichment is on |

Do not ask anything else. State the defaults in the report's method appendix.

## Definitions (used in every section)

- **Network Discovery view**: `asset_inventory_search(surface: NETWORK_DISCOVERY)`. This is the
  console's Network Discovery page and contains Active assets only. Never use the `surfaces` filter
  or a PowerQuery dataset without `assetStatus = 'Active'` for the headline: both include Inactive
  records.
- **Unprotected**: Network Discovery view plus `{fieldId: "missingCoverage", stringIn: {values: ["EPP"]}}`.
- **Deploy-ready**: unprotected and `{fieldId: "eppUnsupportedUnknown", stringIn: {values: ["Supported"]}}`.
  `eppUnsupportedUnknown = Unknown` is reported as its own group ("agent support unknown: review"), never
  merged into deploy-ready. Use `eppUnsupportedUnknown`, not `managedState`, because only the first is
  filterable. Facts measured live that bear on this definition: `eppUnsupportedUnknown` (`Supported`, `Unknown`,
  `Unsupported`) is filterable; `managedState` (`Unsecured`, `Unknown`, `Unsupported`) is returned as a
  facet and node field but every filter operator on it is refused (`Invalid filter type ... for field managed_state`).
  On both tenants measured, within Missing EPP, `managedState = Unsecured` and
  `eppUnsupportedUnknown = Supported` had the same count, and no asset was `Unsupported` (devices the
  agent cannot run on did not carry Missing EPP).
- **Cannot take an agent**: `eppUnsupportedUnknown = Unsupported` (network gear, printers, TVs,
  cameras, consoles, other IoT). Count them from the whole Network Discovery view (Step 1 call D) and
  report them separately so they are never counted as deployment gaps. Any that do appear under
  Missing EPP are listed in this group, not in the gap.
- **Unknown capability**: `eppUnsupportedUnknown = Unknown`. Report as its own group: these need
  identification (device review, fingerprinting) before they can be called a gap or not.

## Step 0: preflight

1. Confirm the `asset_inventory_*` tools are listed. If they are not, use `s1_api_post` to
   `/web/api/v2.1/graphql` with the same documents (query documents run in read-only mode).
2. Read-only mode is fine; nothing here writes.
3. Resolve the scope (above).

## Step 1: headline and breakdowns (four calls, run in parallel)

```text
A. asset_inventory_search(surface: NETWORK_DISCOVERY, filters: [], first: 1, scope)
     -> totalCount = Active Network Discovery assets (headline denominator)
B. asset_inventory_filter_values(surface: NETWORK_DISCOVERY, filters: [], scope,
     fieldIds: ["missingCoverage", "eppUnsupportedUnknown", "managedState", "resourceType",
                "osFamily", "discoveryMethods", "deviceReview", "s1SiteId", "subnets"])
     -> missingCoverage EPP count (headline numerator) plus whole-view breakdowns
C. asset_inventory_filter_values(surface: NETWORK_DISCOVERY, scope,
     filters: [{fieldId: "missingCoverage", stringIn: {values: ["EPP"]}}],
     fieldIds: ["eppUnsupportedUnknown", "managedState", "resourceType", "osFamily",
                "discoveryMethods", "deviceReview", "s1SiteId", "subnets"])
     -> every breakdown of the unprotected set
D. asset_inventory_filter_values(surface: NETWORK_DISCOVERY, scope,
     filters: [{fieldId: "eppUnsupportedUnknown", stringIn: {values: ["Unsupported"]}}],
     fieldIds: ["resourceType", "deviceReview", "s1SiteId"])
     -> devices that cannot take an agent, by type, review status and site
```

Optional context line: `asset_inventory_counts(scope)` for the surface totals of the whole inventory.
Show it as context only. Its Network Discovery number is not the console view and must not be the
headline denominator or appear in a ratio with A or B (see "View semantics" in the reference).

Consistency checks before writing anything:

- The `missingCoverage` `EPP` count in B equals the sum of `eppUnsupportedUnknown` counts in C.
- Every count in C is at most the `EPP` count in B.
- If either check fails, report the mismatch with both numbers; do not adjust them.

## Step 2: the list (paged)

```text
asset_inventory_search(surface: NETWORK_DISCOVERY, scope,
  filters: [{fieldId: "missingCoverage", stringIn: {values: ["EPP"]}}],
  sort: {by: "lastActiveDt", order: DESC},
  fields: ["id", "name", "ipAddress", "internalIps", "macAddresses", "manufacturer", "resourceType",
           "osFamily", "subnets", "s1SiteId", "firstSeenDt", "lastActiveDt", "discoveryMethods",
           "managedState", "eppUnsupportedUnknown", "deviceReview"],
  first: 1000, maxPages: <ceil(EPP count / 1000)>, outputFile: <path>)
```

Keep `filters`, `sort` and `scope` fixed across pages. The rows written must equal the `EPP` count from
Step 1; if not, say so in the report. Newly seen devices are the rows with `firstSeenDt` inside the
window, or one more call with `{fieldId: "firstSeenDt", dateTimeRange: {start: <now minus 7 days, epoch ms>}}`
added to the filters. Resolve `s1SiteId` to site names with `GET /web/api/v2.1/sites?siteIds=<ids>`.

## Step 3: reconciliation line

Print one line in the report body, under the headline, with the exact calls:

```text
Active Network Discovery assets: <A.totalCount> (asset_inventory_search surface NETWORK_DISCOVERY, no filters).
Missing EPP: <B missingCoverage EPP> (asset_inventory_filter_values surface NETWORK_DISCOVERY), rows listed: <Step 2 row count>.
Scope: <scope>. Run at <UTC timestamp>.
```

If the user asks how this compares with PowerQuery, the equal query is
`| datasource assets from 'surface/networkDiscovery' | filter assetStatus = 'Active' missingCoverage contains 'EPP' | group n=count()`.

## Step 4 (optional, only on request): which unprotected IPs appear in telemetry

Answers "which of these devices are talking on the network we log". Needs the schema cache
(`s1_sdl_schema_cache.json`) for the IP fields of each firewall, DNS and proxy source; discover a missing
source with `powerquery_schema_discover` first. Run one query per source, with the IP list from Step 2
(split long lists over several queries):

```text
dataSource.name = '<source>' <src_ip_field> in ('<ip1>', '<ip2>')
| group events = count(), first_seen = min(timestamp), last_seen = max(timestamp) by ip = <src_ip_field>
| sort -events
| limit 1000
```

Add the destination-side field as a second query when the source has one. Use `powerquery_run` with an
explicit window (default 7 days) and the same `scope`. Report per device: seen or not seen, source,
event count, last seen. "Not seen" means no event matched in the queried sources and window, not that
the device is idle. Never fabricate a source that the cache does not list.

## Report sections

1. **Headline.** Active Network Discovery assets; unprotected (Missing EPP); of those, deploy-ready,
   unknown capability, cannot take an agent. Then the reconciliation line.
2. **Deploy-ready list.** Table from Step 2 filtered to the deploy-ready definition: name, IP, type, OS,
   site, subnet, first seen, last active, review status. Sort by last active.
3. **Unknown capability.** Same columns; needs identification before deployment.
4. **Devices that cannot take an agent.** Counts by `resourceType`, review status and site from call D.
   State plainly that they are excluded from the deployment gap.
5. **Breakdowns.** By site, subnet, OS family, resource type and discovery method (Step 1 call C), each as
   a small table with counts.
6. **Newly seen in the last 7 days.** Unprotected devices whose `firstSeenDt` falls in the window.
7. **Review status.** `deviceReview` counts (`Not Reviewed`, `Under Analysis`, `Allowed`, `Not Trusted`)
   for the unprotected set; flag unprotected devices marked `Not Trusted`.
8. **Remediation.**
   - Deploy-ready: Sentinel Deploy from the console (Network Discovery), grouped by site so each site
     owner gets one list. API reference: `mgmt-console-api/references/tags/Sentinel_Deploy.md`. This
     playbook does not trigger deployment.
   - Unknown capability: identify (device review in the console, owner lookup), then re-run.
   - Cannot take an agent: device review (`Allowed` or `Not Trusted`), network segmentation or NAC.
9. **Telemetry appendix** (only when Step 4 ran).
10. **Method appendix.** Every call with its exact arguments, scope, window and run time; the defaults
    used; any error returned, verbatim.

## Dashboard

An optional SDL dashboard ships as `assets/unprotected_endpoints_dashboard.template.json`. Offer it
after the report, as an add-on for ongoing visibility, never instead of the report.

- **What it shows:** Active Network Discovery devices; missing EPP; missing EPP on an EPP-supported
  device type; missing EPP by device type, agent support, site, OS family and review status; all Active
  devices by managed state and discovery method; the unprotected device list.
- **How its queries are built:** every panel reads `| datasource assets from 'surface/networkDiscovery'
  | filter assetStatus = 'Active'`, so it equals the console Network Discovery view. Use `| filter`, never
  `where (...)`, on the assets adapter: `where (...)` returns at most 20 rows whatever the predicate.
- **Deploy** with `sdl_create_dashboard` at the account scope that holds the Network Discovery assets
  (`scope: "<accountId>"`). Network Discovery assets are often account-scoped, so a site-scoped dashboard
  can show none. Tell the user to set the data selector to **All Data**.
- **Size limit, measured:** with about 240 Active devices the 11 panels loaded in 4.8 s in parallel. On a
  console with about 95,000 Network Discovery assets, each panel that filters on `missingCoverage` took
  184 to 208 s per run (4 runs), too slow for a dashboard. Before offering the dashboard, read the Active
  total from Step 1. If it is in the thousands, time one `missingCoverage` panel query with `powerquery_run`
  at the target scope, and offer the dashboard only if it returns within a few seconds. Otherwise say the
  report is the supported view at that size.
- **Before handing it over:** replay every panel with `powerquery_run` at the same scope, and check the
  headline panels equal the report's GraphQL numbers.

## Errors and fallback

- GraphQL errors arrive as HTTP 200 with an `errors` array and `data: null`. Report them verbatim in
  the method appendix; never print an empty report as if the tenant had no unprotected devices.
- `HTTP fetch failed from 'uaip': 401: Unauthorized`: first check the token with
  `GET /web/api/v2.1/accounts?limit=1`. If REST also returns 401, the token is invalid; stop and ask the
  user to replace it (`s1-secops-mcp setup`). If REST works, the token is refused by the asset
  inventory service; offer the PowerQuery fallback below and say the report used it.
- PowerQuery fallback (same inventory, explicit console-view filter):

```text
| datasource assets from 'surface/networkDiscovery'
| filter assetStatus = 'Active'
| group n = count() by missingCoverage, eppUnsupportedUnknown, resourceType
| sort -n
| limit 1000
```

  and for the list:

```text
| datasource assets from 'surface/networkDiscovery'
| filter assetStatus = 'Active' missingCoverage contains 'EPP'
| columns id, name, ipAddress, resourceType, osFamily, managedState, eppUnsupportedUnknown, deviceReview, s1SiteId, firstSeenDt, lastActiveDt
| limit 5000
```

  Run with `powerquery_run` (`maxRows` 5000, `outputFile` for the list). Coverage filters on this
  dataset are slow at large scale (minutes at tens of thousands of Network Discovery assets); say so
  before running. Without `assetStatus = 'Active'` the dataset includes Inactive records and will not
  match the console.

## Gotchas

- `asset_inventory_counts` Network Discovery is not the console number; the headline comes from
  `asset_inventory_search(surface: NETWORK_DISCOVERY).totalCount`.
- Filter values are display labels and case-sensitive (`"EPP"`, not `"epp"`); arguments are enums
  (`NETWORK_DISCOVERY`). Discover values with `asset_inventory_filter_values` before filtering.
- `s1SiteId` cannot be filtered; restrict to a site with `scope`.
- Keep filters and sort fixed while paging, `first` at most 1000.
- Do not put asset names or IPs from one customer into shared files, tickets or examples outside the
  report the user asked for.
