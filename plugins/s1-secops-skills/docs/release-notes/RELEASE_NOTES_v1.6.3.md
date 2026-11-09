## secops-mcps image 1.6.3

Image **1.6.3** on `docker.io/sentinelone/secops-mcps` (linux/amd64, linux/arm64) runs
`s1-secops-mcp` 1.6.3 on the same distroless base as 1.6.2. Alerts now carry the account and site
they belong to, and their history. With plugin `s1-secops-skills` 1.4.3, the unprotected endpoints report separates
Network Discovery false positives from real coverage gaps.

### Changed

- **Alert scope:** `uam_get_alert` and `uam_list_alerts` return `accountId`, `accountName`, `siteId`
  and `siteName`. `uam_get_alert` adds `detectionScope` when the alert was detected under a
  different account or site.
- **Alert history:** `uam_get_alert` returns the alert's history (status, verdict and assignment
  changes, with their text and time) next to its notes, so an MDR or analyst verdict is visible
  in one call.

### Skills (plugin 1.4.3)

- **Unprotected endpoints report, false-positive check:**
  - Network Discovery can list a device that already runs the agent as unprotected, for example
    when the agent reported a different network card, the record has no MAC, or the agent is in
    another site.
  - The report checks every unprotected device against every agent the token can see (live and
    decommissioned, every site) by MAC, by IP on the same gateway, and by hostname.
  - It reports likely false positives and review items in their own section. The headline shows the
    console count next to the count after the check, and review items stay in the gap.
- **More coverage:** AD and Entra computers missing EPP and cloud instances missing the workload
  agent are listed and checked against the same agents. A Network Discovery settings check and a
  table of options (settings, support cases, MDM, DHCP or NAC data) show how to close what no single
  source sees.
- **Dashboard template:** two new panels run the check in PowerQuery, and a third shows Missing EPP
  devices by identity strength. The report stays the authoritative view.
- **Alert triage:** follow-up queries and actions on an alert use the alert's account and site.

The distroless 1.6.x images have no OpenVEX document; `docker/vex/` covers 1.5.x images only.

### Upgrade

Install the 1.6.3 launcher, which writes the 1.6.3 image into your client config:

```bash
mkdir -p ~/.local/bin && curl -fsSL https://raw.githubusercontent.com/Sentinel-One/ai-siem/main/mcp/docker/s1-secops-mcp-launch.sh -o ~/.local/bin/s1-secops-mcp-launch.sh && sh ~/.local/bin/s1-secops-mcp-launch.sh install   # add --read-write if you use write access
```

Or keep your launcher and pin the image:
`~/.local/bin/s1-secops-mcp-launch.sh install --image sentinelone/secops-mcps:1.6.3`. Install plugin
1.4.3, then quit and reopen Claude Desktop. Credentials, profiles, output folders and read-only mode
carry over. Details, including Windows: [upgrading.md](../upgrading.md#162-to-163-plugin-143).
