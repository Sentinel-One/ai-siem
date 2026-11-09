# Solution: Unprotected Endpoints Report

Find the devices on the network that should carry the SentinelOne agent and do not. Network
Discovery sees every device on the subnets it scans; this solution takes that inventory, picks out
the devices with no agent, and splits them into the ones you can deploy to now, the ones that need
identifying first, and the ones that can never take an agent. The result is a report a site owner
can act on, with Sentinel Deploy as the remediation for the deploy-ready group.

This is part of the `sdl-solutions` skill. Playbook:
[`sdl-solutions/references/unprotected-endpoints.md`](../../skills/sdl-solutions/references/unprotected-endpoints.md).
Data path: the Asset Inventory tools in `s1-secops-mcp` (`asset_inventory_search`,
`asset_inventory_filter_values`, `asset_inventory_counts`), with PowerQuery as the fallback and for
the optional telemetry check.

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

## Run it with one prompt

- *"Find our unprotected endpoints"*
- *"Which devices on the network have no SentinelOne agent, and which of them can we deploy to?"*
- *"Unprotected endpoints report for the Acme site, as a Word document"*

Claude asks for nothing else unless you name an account or site. Defaults: everything the token can
see, HTML output, a 7-day window for newly seen devices, telemetry check off.

## What the report contains

1. **Headline:** Active Network Discovery devices, unprotected devices, and the split into
   deploy-ready, agent support unknown and cannot take an agent, with a one-line reconciliation of
   the exact calls behind each number.
2. **Deploy-ready list:** name, IP, type, OS, site, subnet, first seen, last active and review status,
   most recently active first.
3. **Agent support unknown:** the same columns, flagged for identification.
4. **Cannot take an agent:** counts by device type, review status and site.
5. **Breakdowns** of the unprotected set by site, subnet, OS family, device type and discovery method.
6. **Newly seen** unprotected devices in the last 7 days.
7. **Review status,** with any unprotected device marked Not Trusted called out.
8. **Remediation:** Sentinel Deploy for deploy-ready devices, grouped by site; device review for
   unknown ones; device review, segmentation or NAC for devices that cannot take an agent. The
   solution does not trigger a deployment.
9. **Method appendix:** every call with its arguments, scope and run time, and any error verbatim.

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
