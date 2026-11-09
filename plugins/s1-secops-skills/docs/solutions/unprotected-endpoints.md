# Solution: Unprotected Endpoints Report

Find the devices on the network that should carry the SentinelOne agent and do not. Network
Discovery sees every device on the subnets it scans; this solution takes that inventory, picks out
the devices with no agent, and splits them into the ones you can deploy to now, the ones that need
identifying first, and the ones that can never take an agent. The result is a report a site owner
can act on, with Sentinel Deploy as the remediation for the deploy-ready group.

This is part of the `sdl-solutions` skill. Playbook:
[`sdl-solutions/references/unprotected-endpoints.md`](../../skills/sdl-solutions/references/unprotected-endpoints.md).
Data path: the Asset Inventory tools in `s1-secops-mcp` (`asset_inventory_search`,
`asset_inventory_filter_values`, `asset_inventory_counts`), plus `s1_api_get` for the agent list and the
Network Discovery settings. PowerQuery is the fallback, and also runs the optional telemetry check.

## Read-only

The solution deploys nothing and writes nothing to the tenant: no lookup table, rule, workflow or
dashboard unless you ask for the optional dashboard. It runs in read-only mode. The deliverable is a
report Claude writes from live data (an HTML artifact by default, `.docx` on request), and every
number in it comes from a call listed in its method appendix.

## Definitions

| Term | Meaning |
|---|---|
| Network Discovery view | The console's Network Discovery page: Active devices only. The headline count comes from this view, never from a dataset that includes Inactive records. |
| Unprotected | In the Network Discovery view, with `EPP` under Missing Protection (no SentinelOne agent). |
| Deploy-ready | Unprotected, and the device type can run the agent (`eppUnsupportedUnknown = Supported`). These are the Sentinel Deploy candidates. |
| Agent support unknown | Unprotected, and the device type is not yet classified (`eppUnsupportedUnknown = Unknown`). Identify these before calling them a gap. |
| Cannot take an agent | `eppUnsupportedUnknown = Unsupported`: network gear, printers, TVs, cameras and other IoT. Reported separately and never counted as a deployment gap. |

## False positives and the checks the report runs

Network Discovery sometimes lists a device that already runs the agent as unprotected. The usual causes:

- the agent did not report the network card the scanner saw (Wi-Fi, a VLAN, a card that went inactive);
- the Network Discovery record has no MAC address (found by ping, DNS or SSDP, or from another subnet);
- the agent is in another site while Network Discovery consolidates per site;
- a VPN or virtual adapter shows a different IP and MAC;
- the device was seen before its agent registered.

Before a device counts as a gap, the report checks it against every agent the token can see, including
decommissioned ones and agents in other sites. The agent list comes from the Management API, and
`scripts/nd_agent_crosscheck.py` does the matching.

| Check | Catches | Rule |
|---|---|---|
| Agent MAC match | An agent that reports the MAC the scanner saw | Only globally unique MACs count. Randomised Wi-Fi, Docker, all-zero and shared VPN adapter MACs never match, and neither does a MAC on more than one Network Discovery device. |
| Agent IP and hostname | A device the scanner saw on another card, or with no MAC | The IP must come from the agent card with the same gateway MAC, and the hostname must belong to the same agent. |
| Hostname only | A stale DNS name, or a renamed device | Review item, still in the gap. |
| IP only | An address that may have moved to another device | Review item, still in the gap. |
| Matched agent offline | An agent that has not reported for 30 days | Review item, still in the gap. |
| Matched agent decommissioned or uninstalled | A device that had an agent and no longer does | Stays unprotected. |
| Agent in another site | Per-site consolidation | Flagged on the false positive. |
| Shared gateway guard | VRRP, HSRP and cloud virtual gateways shared across networks | Such a gateway never qualifies an IP match. |
| Weak identity | No MAC, randomised MAC, no hostname, or neighbour discovery only | Flagged on devices with no match. |
| Possible middlebox ghost | A firewall or NAT edge answering scans for a whole range | Flagged when at least 50 MAC-less devices share one gateway. |
| Not seen in the last 24 hours | Leftover records that are waiting to age out | Flagged on devices with no match. |
| Network Discovery settings | Combine by MAC off, scan methods, snapshot interval | Read from the API and shown in the report. |

### How the check works

1. **Network Discovery list.** Every Active device with Missing EPP, from Asset Inventory, written to
   a file.
2. **Agent list.** Every agent the token can see, from the Management API, including decommissioned
   agents and agents in every site, written to files page by page. It does not look agents up by
   individual MAC or IP: on three of six consoles tested, those lookups failed and read as "no match".
3. **Match.** `scripts/nd_agent_crosscheck.py` builds keys from both lists (MAC, IP with its gateway
   MAC, hostname) with the guards in the table, pairs each device with each agent it shares a key
   with, and keeps the best verdict. The order follows the platform's own merge order: MAC first, then
   IP plus hostname.
4. **Other inventories.** AD and Entra computer objects missing EPP (IDENTITY), and cloud instances
   missing the cloud workload agent (CLOUD), are checked against the same agent list. These rows carry
   less data, so a name match there is a review item at most.
5. **Settings.** The Network Discovery settings, read from the API.

Every count in the report comes from those files and calls, and the method appendix lists each call.

The report has a **False-positive check** section with each check's results, the likely false positives
(with the matched agent, its site and when it was last active), and the review items. It also names the
setting or support case that addresses the false positives. Its headline shows the console's
unprotected count next to the count after the check, so the two can be compared.

## What no report can see, and how to close it

No single source finds every unprotected device:

- Network Discovery can list a device that has an agent (the check above handles that).
- It can miss a device entirely, when the device sits on a subnet with no scanning agent, a remote
  site or a cloud network.
- Some devices only ever appear with no MAC address, a randomised one, or no hostname, so their
  identity cannot be proven from scan data.

The report says which of these apply in its **Coverage limits** part. These options close them:

| Option | Closes | Who does it |
|---|---|---|
| Turn on Combine devices with the same MAC Address; set the snapshot interval to 120 minutes | Duplicate and early records | Console admin, Network Discovery settings |
| Add a scan restriction for a range that a firewall or NAT edge answers, or turn off the scan method it answers (often SMB) | Ghost devices | Console admin |
| Put a scanning agent in every subnet that matters, and check the Networks view for subnets not scanned | Devices Network Discovery never sees | Console admin |
| Ask SentinelOne support to enable IP-plus-hostname merging for the scope | Records with no MAC for devices that have an agent | Support case |
| Ask SentinelOne support about cross-scope agent awareness, where Network Discovery consolidates per site | Agents in another site | Support case (dedicated consoles) |
| Keep the console and agents on current versions | Multi-NIC and inactive-NIC false positives | Platform owner |
| Ask for the telemetry check | Which gaps are active on the logged network | This report, on request |
| Use an MDM Wi-Fi profile that turns off private Wi-Fi addresses on the corporate network, where the MDM supports it | Randomised MACs on managed devices | Endpoint management team |
| Bring DHCP lease, NAC (802.1X) or CMDB data into SDL and compare it with the agent list by MAC and hostname | Devices no scanner reaches | Your data; not built in |

The last option is the most complete independent source, because every device on the network gets a
DHCP lease or passes NAC whether or not a scanner reached it.

## Run it with one prompt

- *"Find our unprotected endpoints"*
- *"Which devices on the network have no SentinelOne agent, and which of them can we deploy to?"*
- *"Unprotected endpoints report for the Acme site, as a Word document"*

Claude asks for nothing else unless you name an account or site. Defaults: everything the token can
see, HTML output, a 7-day window for newly seen devices, telemetry check off.

## What the report contains

1. **Headline:** Active Network Discovery devices, unprotected devices before and after the
   false-positive check, and the split of the remaining gap into deploy-ready, agent support unknown
   and cannot take an agent, with a one-line reconciliation of the exact calls behind each number.
2. **False-positive check:** the checks above with their results, likely false positives, review
   items and Network Discovery settings.
3. **Deploy-ready list:** name, IP, type, OS, site, subnet, first seen, last active and review status,
   most recently active first.
4. **Agent support unknown:** the same columns, flagged for identification.
5. **Cannot take an agent:** counts by device type, review status and site.
6. **Breakdowns** of the unprotected set by site, subnet, OS family, device type and discovery method.
7. **Newly seen** unprotected devices in the last 7 days.
8. **Review status,** with any unprotected device marked Not Trusted called out.
9. **Remediation:** Sentinel Deploy for deploy-ready devices, grouped by site; device review for
   unknown ones; device review, segmentation or NAC for devices that cannot take an agent; the setting
   or support case for likely false positives. The solution does not trigger a deployment.
10. **Method appendix:** every call with its arguments, scope and run time, and any error verbatim.

On request, Claude also checks which unprotected IPs appear in your firewall, DNS or proxy logs, so
you can see which of these devices are active on the network you log.

## Optional dashboard

For ongoing visibility, the skill ships an SDL dashboard template
(`sdl-solutions/assets/unprotected_endpoints_dashboard.template.json`). It shows the same headline
and breakdowns, plus a list of the 1,000 most recently active unprotected devices. Every panel reads
the Active Network Discovery view, so its counts match the console. Set the data selector to
**All Data**.

The dashboard suits consoles with up to a few thousand Network Discovery devices: about 240 Active
devices loaded in under 5 seconds. On a console with about 95,000 Network Discovery assets, each
coverage panel took about 3 minutes, so at that size the report is the supported view. Claude times
one panel query at your scope before offering the dashboard.
