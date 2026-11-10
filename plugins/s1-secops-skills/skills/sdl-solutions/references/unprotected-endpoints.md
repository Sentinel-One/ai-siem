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
  fields: ["id", "name", "ipAddress", "internalIps", "macAddresses", "gatewayMacs", "manufacturer",
           "resourceType", "osFamily", "subnets", "s1AccountId", "s1SiteId", "firstSeenDt", "lastActiveDt",
           "discoveryMethods", "managedState", "eppUnsupportedUnknown", "deviceReview"],
  first: 1000, maxPages: <ceil(EPP count / 1000)>, outputFile: <dir>/nd.json)
```

Keep `filters`, `sort` and `scope` fixed across pages. The rows written must equal the `EPP` count from
Step 1; if not, say so in the report. Newly seen devices are the rows with `firstSeenDt` inside the
window, or one more call with `{fieldId: "firstSeenDt", dateTimeRange: {start: <now minus 7 days, epoch ms>}}`
added to the filters. Resolve `s1SiteId` to site names with `GET /web/api/v2.1/sites?siteIds=<ids>`.

## Step 2b: agent cross-check (always run)

Network Discovery can list a device that already runs the agent as Missing EPP. The usual causes:

- the agent did not report the NIC the scanner saw (often Wi-Fi, a VLAN sub-interface, or a NIC that
  went inactive);
- the ND record has no MAC, because it came from ping, DNS or SSDP, or from a scanner on another subnet;
- the agent sits in another site while Network Discovery consolidates per site;
- VPN or virtual adapters show a different IP and MAC;
- the device was seen before its agent registered.

So every unprotected device is checked against the agent list before the report calls it a gap.

**1. Fetch every agent, to files.** Fetch whole accounts (`accountIds`, no `siteIds`) even when the
report is for one site, because an agent in a sibling site is one of the causes. Take the accounts
from the `s1AccountId` values of the Network Discovery rows. On a token that spans many accounts this
avoids paging through the whole console. The default listing leaves out decommissioned agents, so
fetch them separately.

```text
s1_api_get(path: "/web/api/v2.1/agents/count", params: {accountIds: "<ids>"})        -> live total
s1_api_get(path: "/web/api/v2.1/agents/count", params: {accountIds: "<ids>", isDecommissioned: "true"})
s1_api_get(path: "/web/api/v2.1/agents", params: {accountIds: "<ids>", limit: 1000, cursor: <next>},
           outputFile: <dir>/agents-live-<n>.json)
s1_api_get(path: "/web/api/v2.1/agents", params: {accountIds: "<ids>", limit: 1000, isDecommissioned: "true",
           cursor: <next>}, outputFile: <dir>/agents-decom-<n>.json)
```

Follow `pagination.nextCursor` until it is null. The agents loaded must equal the two counts added
together; if not, say so in the report. Do not look agents up with lists of values in
`networkInterfacePhysical__contains`, `networkInterfaceInet__contains` or `computerName__contains`.
Measured on six consoles, those lookups failed on three, and a failed lookup reads as "no match".
Paging is about 5 s per 1,000 agents: 25 pages took 2 minutes, and 241 pages (about 240,000 agents)
took 20 minutes. Above about 50,000 agents, tell the user the fetch time before starting.

**2. Run the matcher** (zero dependencies, reads the files the tools wrote):

```bash
python3 scripts/nd_agent_crosscheck.py --nd <dir>/nd.json --agents <dir>/agents-*.json \
  --out <dir>/verdicts.json
```

It prints a summary (counts per verdict, per identity flag, agents loaded) and writes one row per device
with the verdict and the matched agent's id, name, site and last active time.

**3. Matching rules.** These follow the platform's own merge order, MAC first and then IP plus hostname,
and add guards against values that repeat across devices:

| Key | Counts only when |
|---|---|
| MAC | Normalised to 12 hex digits. Globally unique unicast only (second hex digit 0, 4, 8 or c), so randomised Wi-Fi, Docker and other locally administered MACs never match. Never all zeros or a known shared VPN adapter MAC. Never a MAC that more than one ND device carries. |
| IP | The agent NIC with that IP reports the same gateway MAC as the ND record, and that gateway MAC is real and not shared (not VRRP, HSRP or the Azure virtual gateway). RFC 1918 addresses repeat across sites, so an IP alone never matches. |
| Hostname | Lower case, domain removed, at least 3 characters, not a number, IP or MAC, and not a placeholder (`Unknown ... Name`) or generic device name (`iphone`, `localhost`, `macbook-pro`). |
| IP plus hostname | Both point at the same agent. |

An agent counts as live when it is neither decommissioned nor uninstalled.

**4. Verdicts**, best first. Each device gets the best verdict over all the agents it matches; a strong
match to an offline agent outranks a hostname-only or IP-only match:

| Verdict | Meaning | In the deployment gap? |
|---|---|---|
| Likely false positive: Agent MAC matches | A live agent reports the MAC the scanner saw | No |
| Likely false positive: Agent IP and hostname match | One live agent has the IP (same gateway) and the hostname | No |
| Review: matched Agent has been offline | MAC or IP plus hostname match, but the agent has not been active for 30 days | Yes, flagged |
| Review: hostname matches an Agent | Name only; can be a stale DNS name or a renamed device | Yes, flagged |
| Review: IP matches an Agent | IP only; the address may have moved to another device | Yes, flagged |
| Unprotected: matched Agent is decommissioned or uninstalled | The device had an agent and no longer does | Yes |
| Unprotected: no Agent match | No live or dead agent matches | Yes |

Flag likely false positives whose agent is in another site: that points at per-site consolidation.

For devices with no agent match, the matcher also flags:

- **weak identity:** no MAC address, a randomised or shared MAC, no usable hostname, or seen by
  neighbour discovery only;
- **possible middlebox ghost:** at least 50 MAC-less devices behind one gateway MAC (`--ghost-threshold`).
  A firewall, NAT or virtual edge that answers scans for a whole range creates thousands of these;
- **not seen in the last 24 hours:** a leftover record waiting to age out.

As far as the data shows these are real gaps, but the same device may appear under another record, or
may not exist at all in the ghost case.

**5. Network Discovery settings** (account level; the site-level call returns 403 when Network Discovery
is configured at the account):

```text
s1_api_get(path: "/web/api/v2.1/ranger/settings", params: {accountIds: "<accountId>"})
```

Report `combineDevices` (Combine devices with the same MAC Address), `icmpScan`, `mdnsScan`, `rdnsScan`,
`snapshotPeriod` (minutes; 120 lets the backend correlate) and `scanOnlyLocalSubnets`. Some merge
switches are not exposed in the API. When the verdicts point at them, recommend a support case naming
the scope:

- for many IP-plus-hostname false positives, ask support to confirm that IP-plus-hostname merging is
  enabled for the scope;
- for agents in another site, ask about cross-scope agent awareness.

Attach the raw data of a sample device (Network Discovery, Actions, Show raw data) to the case.

## Step 2c: other inventories (always run when they hold gaps)

Network Discovery only sees the networks its scanners reach, so it cannot list a gap in a subnet with
no scanning agent, a remote site or a cloud VPC. Two other inventories report coverage gaps that do not
depend on the scanner. Measured on live consoles, IDENTITY listed AD and Entra computer objects with
Missing EPP, and CLOUD listed EC2 instances and Kubernetes nodes with Missing CWS (the cloud workload
agent).

```text
asset_inventory_filter_values(surface: IDENTITY, filters: [], fieldIds: ["missingCoverage"], scope)
asset_inventory_filter_values(surface: CLOUD, filters: [], fieldIds: ["missingCoverage"], scope)
asset_inventory_search(surface: IDENTITY, scope, filters: [{fieldId: "missingCoverage", stringIn: {values: ["EPP"]}}],
  fields: ["id", "name", "resourceType", "category", "s1SiteId", "missingCoverage"], first: 1000,
  outputFile: <dir>/identity.json)
asset_inventory_search(surface: CLOUD, scope, filters: [{fieldId: "missingCoverage", stringIn: {values: ["CWS"]}}],
  fields: ["id", "name", "resourceType", "internalIps", "macAddresses", "osFamily", "s1SiteId", "missingCoverage"],
  first: 1000, outputFile: <dir>/cloud.json)
```

Skip a surface whose counts show no `EPP` (IDENTITY) or `CWS` (CLOUD) value. Pass the files to the
matcher with `--other <dir>/identity.json <dir>/cloud.json --other-out <dir>/other.json`. These rows are
weaker than Network Discovery rows, and the matcher treats them that way:

- **AD and Entra computer objects** carry a name only, so a hostname match to a live agent is a review
  item, never a false positive.
- **Cloud interfaces** use locally administered MACs, so a cloud MAC counts only together with the same
  IP on the same agent NIC.
- **Rows that Network Discovery also lists** are flagged, so they are not counted twice.

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

1. **Headline.** Active Network Discovery assets; unprotected (Missing EPP), the console number; then the
   same number after the false-positive check, split into likely false positives, review, and
   unprotected. Then the deploy-ready, unknown capability and cannot-take-an-agent split of the
   devices that remain in the gap, and the reconciliation line. Never subtract review items from the
   gap.
2. **False-positive check** (its own section, always present, even when nothing matched):
   - **Checks run.** One row per check with what it catches and how it is decided:
     - agent MAC match;
     - agent IP and hostname on the same agent;
     - hostname only;
     - IP only;
     - matched agent offline;
     - matched agent decommissioned or uninstalled;
     - agent in another site;
     - shared and randomised MAC guard;
     - shared gateway guard;
     - weak identity (no MAC, randomised MAC, no hostname, neighbour discovery only);
     - possible middlebox ghosts;
     - records not seen in the last 24 hours;
     - Network Discovery settings.

     Take the rules from Step 2b.
   - **Results.** Devices per verdict, agents loaded against the two counts, and devices per identity
     flag.
   - **Likely false positives.** Device, IP, MAC, the matched agent's name, site and last active
     time, the match type, and "agent in another site" where it applies.
   - **Review items.** The same columns, with the reason to check each one.
   - **Settings.** The Network Discovery settings read in Step 2b, with any value that explains the
     false positives, and the support case to raise.
   - **Other inventories** (Step 2c). AD and Entra computers missing EPP, and cloud instances missing
     CWS, each with its verdict, and a flag on rows that Network Discovery also lists.
   - **Coverage limits.** What this report cannot see:
     - subnets with no scanning agent;
     - devices that only ever appear with no MAC, a randomised MAC or no hostname;
     - inventories the tenant does not hold.

     List the options in "Closing the remaining gaps" that apply to this tenant.
3. **Deploy-ready list.** From the devices still in the gap (verdict Unprotected or Review), filtered to
   the deploy-ready definition: name, IP, type, OS, account, site, subnet, public IP, first seen, last
   active, review status and verdict. Sort by last active. IP is the device's own address
   (`internalIps`); public IP (`ipAddress`) is the address the site's traffic leaves from, usually the
   same for every device behind one gateway, so never show it as the device's IP.
4. **Unknown capability.** Same columns; needs identification before deployment.
5. **Devices that cannot take an agent.** Counts by `resourceType`, review status and site from call D.
   State plainly that they are excluded from the deployment gap.
6. **Breakdowns.** By account and site, subnet, OS family, resource type and discovery method (Step 1
   call C), each as a small table with counts. Label sites with their account: site names can repeat
   across accounts. The subnet table has one row per account, site and subnet, with active devices,
   missing EPP, deploy-ready and the percentage missing; a device on several subnets counts in each.
7. **Newly seen in the last 7 days.** Unprotected devices whose `firstSeenDt` falls in the window.
8. **Review status.** `deviceReview` counts (`Not Reviewed`, `Under Analysis`, `Allowed`, `Not Trusted`)
   for the unprotected set; flag unprotected devices marked `Not Trusted`.
9. **Remediation.**
   - Deploy-ready: Sentinel Deploy from the console (Network Discovery), grouped by site so each site
     owner gets one list. API reference: `mgmt-console-api/references/tags/Sentinel_Deploy.md`. This
     playbook does not trigger deployment.
   - Unknown capability: identify (device review in the console, owner lookup), then re-run.
   - Cannot take an agent: device review (`Allowed` or `Not Trusted`), network segmentation or NAC.
   - Likely false positives: no deployment. There is no supported way to merge or delete a Network
     Discovery record by hand. Apply the setting the false-positive check points at, or raise the
     support case it names. Device review `Allowed` marks the record but does not change its
     protection state. Possible middlebox ghosts: a scan restriction for the range, or turning off the
     scan method that the edge answers (often SMB).
10. **Telemetry appendix** (only when Step 4 ran).
11. **Method appendix.** Every call with its exact arguments, scope, window and run time; the defaults
    used; any error returned, verbatim.

## Closing the remaining gaps

No single source finds every unprotected device. Network Discovery can list a device that has an agent,
and it can miss a device it never scanned. The report narrows both and says what is left. Put the
options that apply in the report's "Coverage limits" part, as recommendations, never as things the
report did.

| Option | Closes | Who does it |
|---|---|---|
| Combine devices with the same MAC Address on; snapshot interval 120 minutes | Duplicate and early records | Console admin (Network Discovery settings) |
| A scan restriction for a range a firewall or NAT edge answers, or that scan method off (often SMB) | Middlebox ghosts | Console admin |
| A scanning agent in every subnet that matters; check the Networks view for subnets that are not scanned | Devices Network Discovery never sees | Console admin |
| IP-plus-hostname merging enabled for the scope | MAC-less records of devices that have an agent | SentinelOne support case |
| Cross-scope agent awareness, where Network Discovery consolidates per site | Agents in another site | SentinelOne support case (dedicated consoles) |
| Current console and agent versions | Multi-NIC and inactive-NIC false positives | Platform owner |
| The telemetry check (Step 4) | Which gaps are active on the logged network | This skill, on request |
| An MDM Wi-Fi profile that turns off private Wi-Fi addresses on the corporate network, where the MDM supports it | Randomised MACs on managed phones and laptops | Endpoint management team |
| DHCP lease, NAC (802.1X) or CMDB data in SDL, compared by MAC and hostname with the agent list | Devices that no scanner reaches | Customer data, ingested into SDL; not built in |

## Dashboard

An optional SDL dashboard ships as `assets/unprotected_endpoints_dashboard.template.json`. Offer it
after the report, as an add-on for ongoing visibility, never instead of the report.

- **What it shows:** Active Network Discovery devices; missing EPP; missing EPP on an EPP-supported
  device type; missing EPP by device type, agent support, account and site, OS family and review
  status; missing EPP by subnet (active devices, missing EPP, deploy candidates and percentage missing
  per account, site and subnet); all Active devices by managed state and discovery method; the
  unprotected device list (up to 10,000, with internal IP, subnet and public IP); and a false-positive
  check: Missing EPP devices by cross-check verdict, by identity strength, and the likely false
  positives and review items with the matched agent.
- **How its queries are built:** every panel reads `| datasource assets from 'surface/networkDiscovery'
  | filter assetStatus = 'Active'`, so it equals the console Network Discovery view. Use `| filter`, never
  `where (...)`, on the assets adapter: `where (...)` returns at most 20 rows whatever the predicate.
  Grouped panels aggregate on the server and match Asset Inventory GraphQL exactly. The device list
  starts with `sort id` and a `let` (see the PowerQuery fallback below), and sites are labelled with
  their account, because site names can repeat across accounts.
- **The false-positive panels** run `assets/nd_agent_crosscheck.pq`, the PowerQuery form of the Step 2b
  rules, against `surface/endpoint`. Measured on five consoles (1,394 unprotected devices), they never
  cleared a device that the report kept in the gap. Two differences are by design:
  - the endpoint inventory drops decommissioned agents, so a device whose agent was removed shows as no
    match there, where the report says the agent was decommissioned;
  - an agent that the inventory marks inactive counts as not active.

  In both cases the device stays in the gap. Two smaller differences:
  - the query pairs each IP with the gateway MAC of the same Network Discovery interface, where the
    report pairs each IP with each gateway MAC of the record (Asset Inventory GraphQL does not return
    interfaces);
  - the 30-day offline limit is fixed in the query, where the report takes `--stale-days`.

  The report remains the authoritative view.
- **Deploy** with `sdl_create_dashboard` at the account scope that holds the Network Discovery assets
  (`scope: "<accountId>"`). Network Discovery assets are often account-scoped, so a site-scoped dashboard
  can show none. Tell the user to set the data selector to **All Data**.
- **Size limit, measured:** with about 240 Active devices the 11 inventory panels loaded in 4.8 s in
  parallel. The false-positive panels join two inventories: 3 s with 4 devices and 16 agents, 10 s with
  7 devices and 6,100 agents, 43 s with 538 devices and 19,000 agents, and 175 s with 832 devices and
  24,000 agents. With 2,387 devices and about 240,000 agents the panel query hit the 5-minute query
  limit, so at that size only the report runs the check. Time one of them at the target scope before
  offering the dashboard. On a
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
| sort id
| let ip = internalIps
| columns id, name, ip, subnets, ipAddress, resourceType, osFamily, managedState, eppUnsupportedUnknown, deviceReview, s1AccountName, s1SiteId, firstSeenDt, lastActiveDt
| limit 10000
```

  Keep `sort id` and the `let` in that order. A list query on the assets adapter returns a partial
  result in two cases. With no `let` before `columns`, the adapter runs `columns` and `limit` itself
  and returns one page (55 of 610 devices on one console). Without a unique sort first, its paging
  skips devices that share a name (665 of 675). With both, the list matched Asset Inventory GraphQL
  device by device. `internalIps` is the device's own address; `ipAddress` is the address the site's
  traffic leaves from, usually the same for every device behind one gateway.

  Run with `powerquery_run` (`maxRows` 10000, `outputFile` for the list). Coverage filters on this
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
