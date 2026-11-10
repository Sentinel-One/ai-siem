# Upgrading

Three things move independently: the **MCP image** (or npm install), the **skills plugin**, and
your **MCP client config**. Do them in that order.

`install` copies the launcher file you run and writes that launcher's default image, so an upgrade
starts from the new launcher (downloaded) or passes the image explicitly (`--image`, Windows
`-Image`). The current release is image `1.6.3`. If you are several releases behind, read the
sections in between for what changed, then follow [1.6.2 to 1.6.3](#162-to-163-plugin-143).

- [Plugin 1.4.3 to 1.4.4](#plugin-143-to-144) (current release: image `1.6.3`, s1-secops-mcp `1.6.3`, plugin `1.4.4`)
- [1.6.2 to 1.6.3 (plugin 1.4.3)](#162-to-163-plugin-143)
- [1.6.1 to 1.6.2 (plugin 1.4.2)](#161-to-162-plugin-142)
- [1.6.0 to 1.6.1 (plugin 1.4.2)](#160-to-161-plugin-142)
- [Plugin 1.4.0 to 1.4.1](#plugin-140-to-141)
- [1.5.7 to 1.6.0](#157-to-160)
- [Launcher update for Claude Code, Linux and WSL](#launcher-update-for-claude-code-linux-and-wsl)
- [1.5.6 to 1.5.7](#156-to-157)
- [Plugin 1.3.16 to 1.3.17](#plugin-1316-to-1317)
- [1.5.5 to 1.5.6](#155-to-156)
- [1.5.4 to 1.5.5](#154-to-155)
- [1.5.3 to 1.5.4](#153-to-154)
- [1.5.0, 1.5.1 or 1.5.2 to 1.5.3](#150-151-or-152-to-153)
- [1.4.x to 1.5.0](#14x-to-150)
- [Older: 1.2.x / 1.3.x to 1.4.x](#older-12x--13x-to-14x)
- [Rolling back](#rolling-back)

---

## Plugin 1.4.3 to 1.4.4

Skills only: the image and `s1-secops-mcp` stay at `1.6.3`, so there is nothing to reinstall.
Download the new `.plugin` and replace the old one (Cowork → Customize → Browse plugins → upload →
**Replace**). What changed:

- **Unprotected endpoints dashboard 1.0.1:**
  - a new Missing EPP by subnet panel, with active devices, missing EPP, deploy candidates and the
    percentage missing for each account, site and subnet;
  - the device list shows each device's own IP and subnet, with the site's public IP in its own
    column, and returns every unprotected device, up to 10,000;
  - sites are shown with their account, so sites that share a name stay separate.

  Redeploy the dashboard from the template, or import version 1.0.1 from the Dashboard Library.
- **Unprotected endpoints report:** device lists use the device's own IP and add public IP and
  account; the subnet breakdown adds deploy-ready and the percentage missing.

---

## 1.6.2 to 1.6.3 (plugin 1.4.3)

**Alerts carry their scope and history, and the unprotected endpoints report checks for false
positives.**
Credentials, profiles, output folders, read-only mode and the CLAUDE.md override carry over.

**Changed:**

- `uam_get_alert` and `uam_list_alerts` return the alert's `accountId`, `accountName`, `siteId` and
  `siteName` as flat fields. `uam_get_alert` adds `detectionScope` when the alert was detected under
  a different account or site.
- `uam_get_alert` returns the alert's history: `history` (`createdAt`, `eventType`, `eventText`),
  `historyTotalCount`, and `historyTruncated` when there are more than 500 entries.

**Skills (plugin 1.4.3):**

- **Unprotected endpoints report:**
  - It checks every Network Discovery device with Missing EPP against every agent: live and
    decommissioned, in every site.
  - Matching is by MAC, by IP on the same gateway, and by hostname. The report shows likely false
    positives and review items in their own section, with the console count next to the count after
    the check.
  - It adds AD, Entra and cloud gap lists, a Network Discovery settings check, and the options that
    close what no source can see.
  - The matcher is `sdl-solutions/scripts/nd_agent_crosscheck.py`.
- **Dashboard template:** two new panels run the check in PowerQuery
  (`sdl-solutions/assets/nd_agent_crosscheck.pq`), and a third shows Missing EPP devices by identity
  strength.
- **Alert triage:** follow-up queries and actions on an alert use the alert's account and site as
  their scope.

**Upgrade:**

1. **Install the 1.6.3 launcher**, with your usual options (`--read-write`, `--output-dir`; Claude
   Code users add `--claude-code`). macOS or Linux:

   ```bash
   mkdir -p ~/.local/bin && curl -fsSL https://raw.githubusercontent.com/Sentinel-One/ai-siem/main/mcp/docker/s1-secops-mcp-launch.sh -o ~/.local/bin/s1-secops-mcp-launch.sh && sh ~/.local/bin/s1-secops-mcp-launch.sh install
   ```

   Windows (PowerShell, options as `-ReadWrite`, `-OutputDir`):

   ```powershell
   $f = "$env:TEMP\s1-secops-mcp-launch.ps1"; Invoke-WebRequest https://raw.githubusercontent.com/Sentinel-One/ai-siem/main/mcp/docker/s1-secops-mcp-launch.ps1 -OutFile $f -UseBasicParsing; powershell -NoProfile -ExecutionPolicy Bypass -File $f install
   ```

   To keep the launcher you have, pass the image instead:
   `~/.local/bin/s1-secops-mcp-launch.sh install --image sentinelone/secops-mcps:1.6.3` (Windows:
   `... s1-secops-mcp-launch.ps1 install -Image sentinelone/secops-mcps:1.6.3`).
2. **Install plugin `1.4.3`** (Cowork → Customize → Browse plugins → upload → **Replace**).
3. **Restart the client** (quit Claude Desktop completely and open it again, or restart Claude Code).

**Check:** `docker run --rm sentinelone/secops-mcps:1.6.3 versions` shows `image_version` `1.6.3`,
and the MCP entry in your client config names `sentinelone/secops-mcps:1.6.3`.

---

## 1.6.1 to 1.6.2 (plugin 1.4.2)

**`dac_apply` is tied to the reviewed bundle.** Credentials, profiles, output folders, read-only
mode and the CLAUDE.md override carry over.

**Changed:**

- `dac_apply` requires `expectedZipSha256`: pass `bundle.zipSha256` from the `dac_diff` you
  reviewed, together with `expectedSummary`. It rebuilds the bundle from the same input and refuses
  before sending anything when the hash differs, so a changed rule file is refused even when the
  change counts are the same. A call without it is refused with a message naming the field.
- When `dac_apply` times out, fails on the network or gets an HTTP 5xx, the error says the apply may
  have been committed and to run `dac_diff` before trying again. HTTP 429 is retried.
- `deploymentsFile` must be a `.yaml` or `.yml` file.
- `asset_inventory_search` and `asset_inventory_filter_values`: `match` works on text fields such
  as `name`; list fields such as `missingCoverage`, `activeCoverage`, `surfaces` and
  `discoveryMethods` take `stringIn`.

**Skills (plugin 1.4.2 bundle):** the Detection as Code playbook passes `expectedZipSha256` to
`dac_apply`; the PowerQuery skill shows where to add `tag != 'logVolume'` inside a subquery; the
Asset Inventory reference gives the `match` shape (`{values: [..]}`) and the fields that refuse it.

**Upgrade:**

1. **Install the 1.6.2 launcher**, with your usual options (`--read-write`, `--output-dir`; Claude
   Code users add `--claude-code`). macOS or Linux:

   ```bash
   mkdir -p ~/.local/bin && curl -fsSL https://raw.githubusercontent.com/Sentinel-One/ai-siem/main/mcp/docker/s1-secops-mcp-launch.sh -o ~/.local/bin/s1-secops-mcp-launch.sh && sh ~/.local/bin/s1-secops-mcp-launch.sh install
   ```

   Windows (PowerShell, options as `-ReadWrite`, `-OutputDir`):

   ```powershell
   $f = "$env:TEMP\s1-secops-mcp-launch.ps1"; Invoke-WebRequest https://raw.githubusercontent.com/Sentinel-One/ai-siem/main/mcp/docker/s1-secops-mcp-launch.ps1 -OutFile $f -UseBasicParsing; powershell -NoProfile -ExecutionPolicy Bypass -File $f install
   ```

   To keep the launcher you have, pass the image instead:
   `~/.local/bin/s1-secops-mcp-launch.sh install --image sentinelone/secops-mcps:1.6.2` (Windows:
   `... s1-secops-mcp-launch.ps1 install -Image sentinelone/secops-mcps:1.6.2`).
2. **Reinstall plugin `1.4.2` from the current bundle** (Cowork → Customize → Browse plugins → upload → **Replace**). It carries the skill changes above.
3. **Restart the client** (quit Claude Desktop completely and open it again, or restart Claude Code).

**Check:** `docker run --rm sentinelone/secops-mcps:1.6.2 versions` shows `image_version` `1.6.2`,
and the MCP entry in your client config names `sentinelone/secops-mcps:1.6.2`.

---

## 1.6.0 to 1.6.1 (plugin 1.4.2)

**New tools, two fixes, no breaking changes.** Credentials, profiles, output folders, read-only
mode and the CLAUDE.md override carry over. If you are on 1.5.x, read
[1.5.7 to 1.6.0](#157-to-160) first: it renames tools and removes the bundled servers.

| New tool | What it does | Read-only mode |
|---|---|---|
| `dac_export` | Exports your custom detection rules as Detection as Code YAML (ZIP or extracted folder), ready to commit | Runs (writes only to your machine) |
| `dac_diff` | Shows what a rules bundle would create, update, delete, import or retain on the console. Changes nothing | Runs |
| `dac_apply` | Applies a bundle, only when a fresh diff matches the summary you reviewed. Changes the tenant and is marked destructive | Refused until write is enabled |
| `asset_inventory_counts` | Asset Inventory totals per category and surface | Runs |
| `asset_inventory_search` | Filtered, sorted, paged asset lists on any surface; `countOnly` for an exact count | Runs |
| `asset_inventory_get` | One asset's criticality, tags, coverage and alert counts, by asset id or agent UUID | Runs |
| `asset_inventory_filter_values` | The values that exist for a field, with counts, for exact filter labels | Runs |

The client now lists 47 tools with both threat-intel keys stored, 43 with none.

**Fixed:**

- `powerquery_run`: a subquery in the initial filter works with the default metering exclusion and
  with a site `scope` (it no longer fails with HTTP 400 `Expected ")"`). The workaround of writing
  `tag != 'logVolume'` yourself or passing `includeMetering: true` is no longer needed.
- `s1_api_get` adds `isLegacy=false` only to `/cloud-detection/rules` and
  `/cloud-detection/rules/<id>`; other sub-paths such as `/rules/export-vcs` are sent as written.

**Skills (plugin 1.4.2):**

- **Detection as Code** uses the console's native engine: YAML rules plus a manifest per console,
  a console-computed diff on each pull request, apply on merge through the official SentinelOne
  `detection-as-code` reference workflow. The TOML starter (`detection-as-code-starter/`,
  `dac_lint.py`, `dac_sync.py`) is removed; to move a repository built from it, export the console
  rules with `dac_export` and follow `sdl-solutions/references/detection-as-code.md`.
- **Unprotected endpoints report:** a new read-only solution ("find our unprotected endpoints").
- Asset Inventory GraphQL reference, custom correlation entity rules, verify-and-repeat rule
  deletion, the `| filter` rule for `| datasource assets` dashboards, and asset context in
  soc-investigator triage.

**Upgrade:**

1. **Re-run `install` with the 1.6.1 image** and your usual options (add `--read-write` again if
   you use write access). macOS or Linux:
   `~/.local/bin/s1-secops-mcp-launch.sh install --image sentinelone/secops-mcps:1.6.1`. Windows:
   `powershell -NoProfile -ExecutionPolicy Bypass -File $HOME\bin\s1-secops-mcp-launch.ps1 install -Image sentinelone/secops-mcps:1.6.1`.
   Claude Code users: add `--claude-code`.
2. **Install plugin `1.4.2`** (Cowork → Customize → Browse plugins → upload → **Replace**).
3. **Restart the client** (quit Claude Desktop completely and open it again, or restart Claude Code).

**Check:** `docker run --rm sentinelone/secops-mcps:1.6.1 versions` shows `image_version` `1.6.1`,
and the server log's `Tools:` line shows 43 to 47 listed depending on the threat-intel keys you
stored.

---

## Plugin 1.4.0 to 1.4.1

Skills only: the image and `s1-secops-mcp` stay at `1.6.0`, so there is nothing to reinstall.
Download the new `.plugin` and replace the old one (Cowork → Customize → Browse plugins → upload →
**Replace**). What changed:

- **powerquery:** corrections from about 500 live queries. Lazy quantifiers, lookaheads and named
  groups work; `* contains` also works after a pipe (slower); `first()` / `last()` need an earlier
  `sort`; `| columns *` is rejected, so use `queryType: "LOG"` to see every field. More functions
  are listed as banned, with what to write instead.
- **Subqueries and the metering filter:** fixed in s1-secops-mcp 1.6.1 (see
  [1.6.0 to 1.6.1](#160-to-161-plugin-142)). On 1.6.0, write `tag != 'logVolume'` in the initial
  filter yourself or pass `includeMetering: true`. The skill's Python client
  (`mgmt-console-api/scripts/pq.py`) handles subqueries.
- **hyperautomation:**
  - `data_formation` never reached GA and is no longer generated; use a Variable action.
  - Activity triggers must be automatic: an on-demand activity trigger imports but never runs.
  - The new **Switch** action (release 26.3.6) is documented, with the fields to take from a
    console export until its full JSON is confirmed.

---

## 1.5.7 to 1.6.0

**The image now runs one MCP server, `s1-secops-mcp`.** The `purple-mcp`, `virustotal` and
`shodan` servers are no longer in the image. What they were used for is now built into
`s1-secops-mcp`, using your own keys:

| Built-in tool | What it does | Needs |
|---|---|---|
| `purple_ai_query` | Ask Purple AI a question in natural language. Returns a written answer, or a PowerQuery plus time range that Purple AI suggests but does not run (run it with `powerquery_run`). Each call is a new conversation; expect 5 to 15 s | The console token you already store; always listed |
| `ti_vt_lookup`, `ti_vt_relationship` | VirusTotal report for a hash, IP, domain or URL (defanged input accepted), and one relationship page (contacted domains, resolutions, related threat actors and so on) | `VIRUSTOTAL_API_KEY` |
| `ti_shodan_host`, `ti_shodan_dns` | Open ports, services, CVEs, owner and tags for an IP; resolve up to 25 hostnames or reverse up to 25 IPs. Neither spends query credits | `SHODAN_API_KEY` |

The image is also smaller and simpler: a distroless Node 24 base with no shell, no package manager
and no Python, running as an unprivileged user. Credentials, profiles, output folders, read-only
mode and the CLAUDE.md override carry over unchanged.

**Upgrade:**

1. **Re-run `install`** with your usual options (add `--read-write` again if you use write access).
   It installs the current launcher, writes the `s1-secops-mcp` entry with `1.6.0`, removes the old
   `purple-mcp`, `virustotal` and `shodan` entries that ran this launcher, and pulls the image.
   Servers you added yourself with other commands are kept. macOS or Linux:

   ```bash
   mkdir -p ~/.local/bin && curl -fsSL https://raw.githubusercontent.com/Sentinel-One/ai-siem/main/mcp/docker/s1-secops-mcp-launch.sh -o ~/.local/bin/s1-secops-mcp-launch.sh && sh ~/.local/bin/s1-secops-mcp-launch.sh install
   ```

   Windows (PowerShell):

   ```powershell
   $f = "$env:TEMP\s1-secops-mcp-launch.ps1"; Invoke-WebRequest https://raw.githubusercontent.com/Sentinel-One/ai-siem/main/mcp/docker/s1-secops-mcp-launch.ps1 -OutFile $f -UseBasicParsing; powershell -NoProfile -ExecutionPolicy Bypass -File $f install
   ```

   Claude Code users: add `--claude-code`. It registers `s1-secops-mcp` and removes the old
   entries only when they ran this launcher. `--with-shodan` (Windows: `-WithShodan`) is still
   accepted but does nothing.
2. **Optional: store threat-intel keys.** Your stored `VIRUSTOTAL_API_KEY` is reused as is. To add
   or change a key, run `~/.local/bin/s1-secops-mcp-launch.sh setup` (Windows:
   `powershell -NoProfile -ExecutionPolicy Bypass -File $HOME\bin\s1-secops-mcp-launch.ps1 setup`),
   which prompts for `VIRUSTOTAL_API_KEY` and `SHODAN_API_KEY`; press Enter to keep a value or skip
   it. The end of `install` shows which tools are on, for example
   `Built-in tools: Purple AI on, VirusTotal on, Shodan off (no SHODAN_API_KEY)`.
3. **Install plugin `1.4.1`** (1.4.0 or later; Cowork → Customize → Browse plugins → upload → **Replace**).
4. **Restart the client** (quit Claude Desktop completely and open it again, or restart Claude Code).

**Tool names that changed.** If you have saved prompts, scripts or runbooks that name tools from
the old servers, update them:

| Old tool (server) | Use now |
|---|---|
| `get_file_report`, `get_ip_report`, `get_domain_report`, `get_url_report` (VirusTotal MCP) | `ti_vt_lookup` |
| `get_file_relationship`, `get_ip_relationship`, `get_domain_relationship`, `get_url_relationship` (VirusTotal MCP) | `ti_vt_relationship` |
| `purple_ai` (purple-mcp) | `purple_ai_query` |
| `powerquery` (purple-mcp) | `powerquery_run` |
| `list_alerts`, `search_alerts` (purple-mcp) | `uam_list_alerts` |
| `get_alert` (purple-mcp) | `uam_get_alert` |
| `threat_intel_by_hash`, `threat_intel_by_ip`, `threat_intel_by_domain`, `threat_intel_by_url` (purple-mcp) | `ti_vt_lookup` |

The built-in VirusTotal tools cover reports and the common relationships. A free VirusTotal key
allows 4 lookups a minute and 500 a day, and some relationships (`related_threat_actors`,
`similar_files`) need a premium key. For VirusTotal features the built-in tools leave out (VT
Intelligence search, sandbox behaviour, collections), or to keep using purple-mcp's own tools, add
those servers from their official sources: [connect-optional-tools.md](./connect-optional-tools.md).

**Check:**

- The client lists `s1-secops-mcp` and no `purple-mcp`, `virustotal` or `shodan` entry from this
  launcher. An old entry left behind fails with `'<name>' was removed in 1.6.0 ... run install again`
  in its log; run `install` again.
- The server log (`~/Library/Logs/Claude/mcp-server-s1-secops-mcp.log` on macOS) shows
  `Threat intel: Purple AI on, VirusTotal on|off, Shodan on|off` and a `Tools:` line: 36 listed with
  no threat-intel keys, 38 with VirusTotal only, 40 with both.
- `docker run --rm sentinelone/secops-mcps:1.6.0 versions` shows `image_version` `1.6.0` and one
  server.

---

## Plugin 1.3.16 to 1.3.17

Skills only. The image and `s1-secops-mcp` stay at 1.5.6, and nothing in your config changes.
Install plugin `1.3.17` (Cowork → Customize → Browse plugins → upload → **Replace**).

What it adds:

- **hyperautomation:** an L1 triage template (`references/l1-triage-template.md`); `llm` actions
  take `json_schema` as a JSON string and their output is read at `.data`; branching on a strict
  output with a safe default; per-group `run_automatically`; account-scope workflow lists include
  every site's workflows, so filter before a delete-by-name; the export, patch, re-import and
  re-bind loop for editing a deployed flow; hash and scope extraction from the raw alert; if a
  console does not accept the `llm` action, contact your SentinelOne account team to enable it.
- **mgmt-console-api:** account and site licences (`references/licences.md`).
- **CLAUDE.md:** an Investigation Hygiene section.

---

## Launcher update for Claude Code, Linux and WSL

A launcher fix for Claude Code on Linux and WSL, released after 1.5.7. The current launcher includes it and installs image `1.6.1`, so following these steps today also performs the [1.5.7 to 1.6.0](#157-to-160) and [1.6.0 to 1.6.1](#160-to-161-plugin-142) upgrades. MCP clients run the installed copy in `~/.local/bin`, so a fresh download alone does not apply the fix: run `install` again.

1. Download the launcher and re-run `install` with your usual options (add `--read-write` again if you use write access):

   ```bash
   curl -fsSL https://raw.githubusercontent.com/Sentinel-One/ai-siem/main/mcp/docker/s1-secops-mcp-launch.sh -o /tmp/s1-secops-mcp-launch.sh && sh /tmp/s1-secops-mcp-launch.sh install
   ```

2. **Claude Code users** (macOS, Linux, WSL): add `--claude-code` so the server is registered with Claude Code. This also sets `MCP_TIMEOUT` to 120 s in `~/.claude/settings.json`, which applies to every MCP server in Claude Code. Then restart Claude Code.
3. **WSL users:** credentials are read from Windows Credential Manager when no Linux Secret Service is available, so values already stored by the Windows launcher or Cowork are reused. Turn on Docker Desktop's WSL integration for the distro and add your user to the `docker` group.

**Check:** `~/.local/bin/s1-secops-mcp-launch.sh status` lists your stored values, and `/mcp` in Claude Code shows `s1-secops-mcp` connected.

---

## 1.5.6 to 1.5.7

A dependency and base-image update. No configuration changes: credentials, profiles, output folders and the plugin (1.3.17) carry over.

1. Re-run `install` with the `1.5.7` image and the same options as before. `install` writes the mode you ask for, so add `--read-write` again if you use write access:

   ```bash
   ~/.local/bin/s1-secops-mcp-launch.sh install --image sentinelone/secops-mcps:1.5.7
   ```

2. Quit and reopen Claude Desktop.

Check with `docker run --rm sentinelone/secops-mcps:1.5.7 versions` (Node `v24.22.1`).

---

## 1.5.5 to 1.5.6

A security update to read-only mode in `s1-secops-mcp`. Nothing to migrate: credentials, profiles, output folders and the plugin (1.3.16) carry over.

1. Re-run `install` with the `1.5.6` image and the same options as before. `install` writes the mode you ask for, so add `--read-write` again if you use write access:

   ```bash
   ~/.local/bin/s1-secops-mcp-launch.sh install --image sentinelone/secops-mcps:1.5.6
   ```

2. Quit and reopen Claude Desktop.

Check with `docker run --rm sentinelone/secops-mcps:1.5.6 versions`.

---

## 1.5.4 to 1.5.5

**s1-secops-mcp is now read-only by default.** Every tool call that would change your tenant is refused before any network request, with a message that explains how to enable write. Read and query tools are unchanged. purple-mcp, VirusTotal and Shodan are not affected, and their pins are the same as in 1.5.4.

**What stops working until you opt in:**

| Area | Refused while read-only |
|---|---|
| Alert triage | `uam_add_note`, `uam_set_status`, `uam_set_verdict`, `uam_assign_alert` |
| Alert ingest | `uam_post_alert`, `uam_ingest_alert` |
| Content deployment | `sdl_put_file`, `sdl_delete_file`, `sdl_create_dashboard`, `sdl_share_dashboard`, `sdl_save_dashboard_layout`, `sdl_delete_dashboard`, `ha_import_workflow`, `ha_delete_workflow` |
| Log ingest | `hec_ingest` |
| Mgmt Console API | `s1_api_put`, `s1_api_patch`, `s1_api_delete`, and `s1_api_post` except allowlisted query POSTs (for example detection rule creation, IOC creation and endpoint actions are refused) |
| PowerQuery | `powerquery_run` with `\| savelookup` |

Skills that deploy content or triage alerts report the refusal and the steps to enable write. No data changes while read-only. If you only investigate, hunt and report, there is nothing to do beyond the image upgrade.

**Upgrade:**

1. Re-run the install command (macOS/Linux one-liner or the Windows one in [1.5.0, 1.5.1 or 1.5.2 to 1.5.3](#150-151-or-152-to-153)). It installs the newer launcher, rewrites your entries with the current tag and pulls the image. Pass your usual options again (`--profile P`, `--output-dir DIR`, `--claude-md FILE`).
2. **To keep write access**, add `--read-write` (Windows: `-ReadWrite`) to that command. It writes `"S1_READ_ONLY": "false"` into the `s1-secops-mcp` entry and prints a NOTICE. Without the flag, `install` prints a read-only notice.
3. Install plugin `1.3.16` (Cowork → Customize → Browse plugins → upload → **Replace**).
4. Quit and reopen Claude Desktop.

**Enable write for other install methods:**

| Install method | Enable write | Return to read-only |
|---|---|---|
| Docker launcher, macOS or Linux | `~/.local/bin/s1-secops-mcp-launch.sh install --read-write` | Run `install` without the flag |
| Docker launcher, Windows | `powershell -NoProfile -ExecutionPolicy Bypass -File $HOME\bin\s1-secops-mcp-launch.ps1 install -ReadWrite` | Run `install` without the flag |
| Claude Desktop extension (`.mcpb`) | Turn off **Read-only mode (recommended)** in the extension settings | Turn it back on |
| Node install | Add `"S1_READ_ONLY": "false"` to the `env` block of the `s1-secops-mcp` entry | Remove the line |
| Plain `docker run` | `-e S1_READ_ONLY=false` | Omit it |

Restart Claude Desktop after any change. Any value other than `false`, `0`, `no` or `off` keeps read-only. Use a token whose console role covers only the changes you intend; the role, not this setting, is the authoritative control. Full reference: [read-only.md](./read-only.md).

**Check:** the server's startup log shows a `Mode:` line; `~/.local/bin/s1-secops-mcp-launch.sh status` includes an `S1_READ_ONLY` line noting that the setting lives in the client config; `docker run --rm sentinelone/secops-mcps:1.5.6 versions` lists the bundled pins; `docker run --rm sentinelone/secops-mcps:1.5.6 notices` prints the new third-party notices.

Nothing else to migrate: credentials, profiles, output folders and the CLAUDE.md override carry over unchanged.

---

## 1.5.3 to 1.5.4

Image 1.5.4 added a fourth, **optional** MCP server, Shodan (`shodan-mcp`). From 1.6.0 that server
is gone and Shodan host and DNS lookups are built-in tools of `s1-secops-mcp`
([1.5.7 to 1.6.0](#157-to-160)), so steps 2 and 3 below now only store the key: no `shodan` entry
is written.

The bundled s1-secops-mcp moves to 1.5.4 for one fix. In the image, `outputFile` used to report
success for a path inside the container (`/tmp`, `/home/node`), and the file was lost when the
container exited. It is now refused unless a folder is shared with `install --output-dir`, and every
refusal says to run that. If you write exports, pass `--output-dir` in step 1.

1. **Pull the new tag** by re-running the install command (macOS/Linux one-liner or the Windows one in
   [1.5.0, 1.5.1 or 1.5.2 to 1.5.3](#150-151-or-152-to-153)). It installs the newer launcher,
   rewrites your entries with the current tag and pulls the image. Pass your usual options again
   (`--profile P`, `--output-dir DIR`, `--claude-md FILE`).
2. **To add Shodan, store the key:** run `~/.local/bin/s1-secops-mcp-launch.sh setup` (Windows:
   `powershell -NoProfile -ExecutionPolicy Bypass -File $HOME\bin\s1-secops-mcp-launch.ps1 setup`)
   and enter `SHODAN_API_KEY` from [account.shodan.io](https://account.shodan.io) (Account page,
   API key). Press Enter at every other prompt to keep the current values, and at the Shodan prompt
   to skip it.
3. Quit and reopen Claude Desktop. With the key stored, the built-in `ti_shodan_host` and
   `ti_shodan_dns` tools are listed.

---

<a id="150-or-151-to-152"></a>

## 1.5.0, 1.5.1 or 1.5.2 to 1.5.3

No config changes beyond the image tag, with two exceptions noted below (both from 1.5.2). What changed:

- **One global token, any account or site (1.5.3, issue #111):** with a global or multi-account
  token, `scope: "<accountId>"` or `"<accountId>:<siteId>"` on `powerquery_run`,
  `powerquery_enumerate_sources` and `powerquery_schema_discover` now narrows the query. Before
  1.5.3 the scope was sent only as an `S1-Scope` header, which the query API ignores for a
  multi-account user, so a scoped query silently answered for every account. `uam_list_alerts`
  gains `scopeIds`/`scopeType`, `ha_list_workflows` gains `accountIds` and `nameContains`,
  `ha_delete_workflow` deactivates an active workflow before deleting it, and
  `uam_available_actions` uses the alert's own account. Nothing changes for an account-level token
  (verified: same counts). If you relied on an "unscoped-looking" result from a scoped call on a
  multi-account token, expect smaller, correct numbers now.
- **Security (from 1.5.1):** the VirusTotal MCP inside the image ships `proxy-addr` 2.0.8
  (CVE-2026-90711, critical) and `@modelcontextprotocol/sdk` 1.32.1 (CVE-2026-104850, high). Neither
  was reachable in the stdio server, but both cleared image scans.
- **One console token (from 1.5.2):** the optional second token `S1_CONSOLE_API_TOKEN_SINGLE_SCOPE` and the
  `tokenKind` parameter of the `s1_api_*` tools are removed. An endpoint that refuses a token whose
  user spans several accounts (error 4030010, e.g. IOC writes) now returns a hint: use a token minted
  at a single account or site, in its own keychain profile (`s1-secops-mcp setup --profile <name>`),
  and run a second MCP entry with `S1_PROFILE=<name>`.
- **`S1_SCOPE` is `<accountId>` or `<accountId>:<siteId>` (from 1.5.2):** setup refuses a group part, which every
  SDL and PowerQuery tool rejected anyway.

Upgrade with the install command (it also installs the newer launcher, which adds `install` and
`config`). **Windows: required.** Earlier Windows launchers held each request from Claude Desktop until the
connection closed, so servers timed out in Cowork; the new launcher fixes it. macOS or Linux:

```bash
mkdir -p ~/.local/bin && curl -fsSL https://raw.githubusercontent.com/Sentinel-One/ai-siem/main/mcp/docker/s1-secops-mcp-launch.sh -o ~/.local/bin/s1-secops-mcp-launch.sh && sh ~/.local/bin/s1-secops-mcp-launch.sh install
```

Windows (PowerShell):

```powershell
$f = "$env:TEMP\s1-secops-mcp-launch.ps1"; Invoke-WebRequest https://raw.githubusercontent.com/Sentinel-One/ai-siem/main/mcp/docker/s1-secops-mcp-launch.ps1 -OutFile $f -UseBasicParsing; powershell -NoProfile -ExecutionPolicy Bypass -File $f install
```

It rewrites the `s1-secops-mcp` entry with the current tag and your real path, removes the old
`purple-mcp`, `virustotal` and `shodan` entries (from 1.6.0 those are built-in tools), keeps your
other servers, saves a backup of the old config, pulls the image and keeps your
stored credentials. If you used `S1_PROFILE`, an output folder or your own CLAUDE.md, pass them
again (`--profile P`, `--output-dir DIR`, `--claude-md FILE`). Then quit and reopen the client.

If you stored a single-scope token, it stays in the keychain but nothing reads it, and `status` and
`forget` no longer list it. Delete it by hand: macOS
`security delete-generic-password -s sentinelone-mcp -a <profile>:S1_CONSOLE_API_TOKEN_SINGLE_SCOPE`,
Linux `secret-tool clear service sentinelone-mcp username <profile>:S1_CONSOLE_API_TOKEN_SINGLE_SCOPE`,
Windows `cmdkey /delete:<profile>:S1_CONSOLE_API_TOKEN_SINGLE_SCOPE.sentinelone-mcp`. A stored
`S1_SCOPE` with a group part is refused at the next `setup`; re-enter it as `<accountId>:<siteId>`.

---

## 1.4.x to 1.5.0

1.5.0 is a breaking release. Budget ten minutes.

### Breaking changes

| Change | What breaks | What to do |
|---|---|---|
| **No `credentials.json`** | Every file location is gone: `S1_CREDS_FILE`, `COWORK_WORKSPACE`, the working-directory walk-up, `~/mnt/*`, `CLAUDE_CONFIG_DIR`, `~/.config/sentinelone`, `~/.claude/sentinelone`. The plugin's SessionStart hook (`bootstrap_creds.sh`) and both `scripts/bootstrap_creds.sh` copies are deleted. | Move the values into the OS keychain with `s1-secops-mcp setup --import-json <file>`, then delete the file. |
| **Credentials resolve from env, then the OS keychain** | Nothing reads a file any more. | `s1-secops-mcp setup` stores values (service `sentinelone-mcp`, account `<profile>:<NAME>`); `s1-secops-mcp status` shows where each resolves from. |
| **No HTTP transport** | `--transport http`, bearer tokens (`MCP_BEARER_TOKENS*`), the team VM deployment (`mcp/s1-secops-mcp/deploy/`: `install.sh`, systemd, Caddy, the bridge) and its guide are removed. The server speaks stdio only. | Each user runs their own server (Docker launcher or Node) with their own credentials. Decommission any shared VM. |
| **Docker launcher instead of `-e`** | Configs that pass tokens with `docker run -e` and an `env` block still start, but they keep tokens in plaintext and in `docker inspect`. The documented configs no longer do this. | Run the launcher's `install` (Step 2): it copies the launcher to `~/.local/bin/` (Windows: `%USERPROFILE%\bin\`) and points each server entry at that copy. |

### Step 1: move credentials into the keychain

If you used a `credentials.json`:

```bash
s1-secops-mcp setup --import-json /path/to/credentials.json
s1-secops-mcp status          # every value should read "keychain"
rm /path/to/credentials.json
```

Also delete the copies the old hook made (`~/.claude/sentinelone/credentials.json`, `~/.config/sentinelone/credentials.json`, any `.sentinelone/credentials.json` in a project) and remove the file from Cowork projects' **Add files** lists.

If your tokens were in the `env` blocks of `claude_desktop_config.json` instead, run `s1-secops-mcp setup` (or, Docker-only, the launcher's `setup`, which `install` in Step 2 runs for you) and enter the same values when prompted. Back up the config first (`cp claude_desktop_config.json claude_desktop_config.json.bak`), and delete the backup once the new setup works, because it still holds the tokens.

No Node on the machine? `s1-secops-mcp-launch.sh setup` (macOS, Linux), `s1-secops-mcp-launch.ps1 setup` (Windows), or `python3 mgmt-console-api/scripts/s1_keystore.py setup` from a skills checkout (macOS, Linux) store the same entries.

### Step 2: the launcher, the image and the config

One command installs the launcher to `~/.local/bin/`, rewrites the Docker entries in
`claude_desktop_config.json` (with a dated backup of the old file), pulls the image and runs
`setup` if no token is stored. macOS or Linux:

```bash
mkdir -p ~/.local/bin && curl -fsSL https://raw.githubusercontent.com/Sentinel-One/ai-siem/main/mcp/docker/s1-secops-mcp-launch.sh -o ~/.local/bin/s1-secops-mcp-launch.sh && sh ~/.local/bin/s1-secops-mcp-launch.sh install
```

Windows (PowerShell):

```powershell
$f = "$env:TEMP\s1-secops-mcp-launch.ps1"; Invoke-WebRequest https://raw.githubusercontent.com/Sentinel-One/ai-siem/main/mcp/docker/s1-secops-mcp-launch.ps1 -OutFile $f -UseBasicParsing; powershell -NoProfile -ExecutionPolicy Bypass -File $f install
```

The launcher has to live outside `~/Documents`, `~/Desktop` and `~/Downloads` on macOS (including a
repo clone there), because macOS blocks Claude Desktop's `/bin/sh` from running scripts in those
folders; `install` puts it in `~/.local/bin/`.

### Step 3: the plugin

Install plugin `1.3.13` (Cowork → Customize → Browse plugins → upload → **Replace**). It drops the SessionStart hook and rewrites every skill to use the MCP tools as the primary path, with the Python clients documented as host-only.

### Step 4: the config

Step 2 already wrote the `s1-secops-mcp` entry, and removed older entries that ran the launcher
under another name (including `purple-mcp`, `virustotal` and `shodan`, which are built-in tools
from 1.6.0). Open the config and delete any token still
left in other entries, then delete the `.bak-` copy `install` made once the new setup works, because
it may still hold tokens. To see the entries for this machine, or to configure another client by
hand, run `~/.local/bin/s1-secops-mcp-launch.sh config`: it prints the entry with your real path (JSON
does not expand `~` or `$HOME`, so never type the path yourself). Keep `--image` before the server
name in a hand-written entry: anything after the server name is passed to the server inside the
container, which rejects it.

Node installs: `"command": "s1-secops-mcp"` (or `node /path/to/s1-secops-mcp/index.js`) with no `env` block. Remove any `--transport http` argument and any `MCP_BEARER_TOKENS*` variable. Claude Code users: re-register without `--env` (`claude mcp add s1-secops-mcp -- s1-secops-mcp`) and remove tokens from `~/.claude.json` and project `.mcp.json` files.

Then **restart Claude Desktop**.

### Step 5: verify

```text
smoke test s1 secops skills
```

Or from a terminal:

```bash
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"smoke","version":"0.1"}}}' \
  | ~/.local/bin/s1-secops-mcp-launch.sh s1-secops-mcp
```

Expect `serverInfo.name = "s1-secops-mcp-server"`, `version = "1.6.1"`, a `Tools:` line on stderr (47 registered; 43 to 47 listed depending on the threat-intel keys you stored), and `configured` for each surface whose values you stored. Confirm no token remains in your client config:

```bash
grep -E 'eyJ|S1_CONSOLE_API_TOKEN|S1_HEC_TOKEN|VIRUSTOTAL_API_KEY' ~/Library/Application\ Support/Claude/claude_desktop_config.json || echo "clean"
```

### New in 1.5.0 worth using

- `powerquery_run` takes `queryType: "LOG"` (every parsed field per event, server cap 5000 per query or slice), `slices` (2-15) with a `merge` spec for long windows, and `outputFile` for bulk results.
- `s1_api_download` saves binary responses (RemoteOps fetch-files, threat file fetch, exports) to disk and returns size, sha256 and content type.
- `ha_export_workflow` and `s1_api_get` take `outputFile`.
- Token values are masked in all tool output and logs.

Full tool reference: [mcp-tools.md](./mcp-tools.md).

### Troubleshooting 1.5.0

| Symptom | Cause and fix |
|---|---|
| `/bin/sh: .../s1-secops-mcp-launch.sh: Operation not permitted` in the MCP log (macOS) | The config points at a launcher under `~/Documents`, `~/Desktop` or `~/Downloads`, where macOS blocks Claude Desktop's shell from running it. Run the Step 2 command again: it installs the launcher to `~/.local/bin/` and rewrites the config. |
| `ENOENT` or `No such file or directory` for the launcher in the MCP log | The `command` path was typed by hand and does not exist. Run the Step 2 command again, which writes your real path. |
| `S1 Mgmt API: NOT configured` | No value reached the server. `s1-secops-mcp status` shows what resolves; check `S1_PROFILE` if you stored values under a named profile. |
| `OS keychain unavailable: secret-tool not found` | Linux without libsecret tools. Install `libsecret-tools` / `libsecret`, or use environment variables from a secret manager. |
| D-Bus or `locked collection` errors on Linux | No unlocked Secret Service in this session (common on headless hosts and over SSH). Unlock the keyring or use environment variables. |
| `optional dependency @napi-rs/keyring is not installed` | Windows Node install: `npm install @napi-rs/keyring`, or use the Docker launcher. |
| `outputFile ... is outside the allowed output directories`, or (1.5.4+) `... refused: no output folder is shared with this container` | Under Docker, run `~/.local/bin/s1-secops-mcp-launch.sh install --output-dir <folder>` (Windows: `-OutputDir`), restart Claude Desktop, and write inside that folder. `S1_OUTPUT_DIRS` in the client config has no effect under Docker. With the Node server, write inside your home or temp directory, or set `S1_OUTPUT_DIRS`. |
| A skill asks you to run `s1-secops-mcp setup` | That is the intended behaviour when a value is missing. Do not paste tokens into the chat. |

---

## Older: 1.2.x / 1.3.x to 1.4.x

Keep this section only if you are coming from a release older than 1.4.0. Apply these changes, then continue with [1.4.x to 1.5.0](#14x-to-150) for the credential and config steps; do not stop at the 1.4.x `env`-block config.

### The plugin

The plugin was renamed from `sentinelone-skills` to `s1-secops-skills`. A plugin's name is its installed identity, so this reads as a **different plugin**: the old one will not update in place.

1. Remove the old `sentinelone-skills` plugin.
2. Install `s1-secops-skills` from the marketplace.

Confirm afterwards that the skills are the new ones, not a stale cache:

```bash
for f in /var/folders/*/*/T/claude-hostloop-plugins/*/skills/sdl-api/SKILL.md; do
  [ -f "$f" ] || continue
  printf 'stale-markers=%s  %s\n' \
    "$(grep -c 'SDL_XDR_URL\|c\.keys\[' "$f")" "${f##*hostloop-plugins/}"
done
```

`stale-markers=0` means you are on the new skills. Anything above zero is an old cache still in place.

### The config

| Change | From | To |
|---|---|---|
| Server key | `"sentinelone-mcp"` | `"s1-secops-mcp"` |
| Dispatcher argument | `sentinelone-mcp` | `s1-secops-mcp` |
| Image | `s1-mcps:1.2.x` | `sentinelone/secops-mcps:1.6.3` via the launcher |
| purple-mcp variables | `PURPLEMCP_CONSOLE_BASE_URL`, `PURPLEMCP_CONSOLE_TOKEN` | `S1_CONSOLE_URL`, `S1_CONSOLE_API_TOKEN` in the keychain. purple-mcp is no longer in the image; Purple AI questions are the built-in `purple_ai_query` tool |

Delete outright: `SDL_XDR_URL`, `SDL_CONFIG_READ_KEY`, `SDL_CONFIG_WRITE_KEY`, `SDL_LOG_READ_KEY`, `SDL_LOG_WRITE_KEY`. Nothing replaces them. The console API token authorises every SDL operation, and the SDL base is derived from `S1_CONSOLE_URL` as `<console>/sdl`.

### Scripts of your own

`SDLClient.keys` no longer exists, so this raises `AttributeError`:

```python
c = SDLClient()
c.keys["log_read_key"] = ""        # remove
c.keys["config_read_key"] = ""     # remove
c.keys["config_write_key"] = ""    # remove
```

Delete those lines. Nothing replaces them; the client uses the console token for every method. `SDLClient` also fails fast at construction when `S1_CONSOLE_API_TOKEN` is absent from both the environment and the keychain.

| Symptom | Cause and fix |
|---|---|
| `manifest unknown` / image pull fails | Tag typo, or an MCP version used as an image tag. Use the exact image tag (`1.6.1`). |
| `entrypoint: unknown command 'sentinelone-mcp'` | The dispatcher argument still says the old name. Change it to `s1-secops-mcp`. |
| Skills still mention `SDL_XDR_URL` or `c.keys[...]` | An old plugin cache. Re-check with the loop above. |
| `AttributeError: 'SDLClient' object has no attribute 'keys'` | A script still force-clears scoped keys. See above. |

Per-MCP logs: `~/Library/Logs/Claude/mcp-server-<name>.log` on macOS; on Windows, the `logs` folder next to the config Claude Desktop reads (for an MSIX install, `%LOCALAPPDATA%\Packages\Claude_<id>\LocalCache\Roaming\Claude\logs\`).

---

## Rolling back

Restore the config backup and reinstall the previous plugin:

```bash
cd ~/Library/Application\ Support/Claude
cp claude_desktop_config.json.bak claude_desktop_config.json
```

**Back to 1.6.2.** Run `~/.local/bin/s1-secops-mcp-launch.sh install --image sentinelone/secops-mcps:1.6.2` (add your usual options), reinstall plugin 1.4.2, and restart the client. `uam_get_alert` and `uam_list_alerts` then return no account or site fields, and `uam_get_alert` no history.

**Back to 1.6.1.** Run `~/.local/bin/s1-secops-mcp-launch.sh install --image sentinelone/secops-mcps:1.6.1` (add your usual options), reinstall plugin 1.4.2, and restart the client. `dac_apply` then takes `expectedSummary` only.

**Back to 1.6.0.** Run `~/.local/bin/s1-secops-mcp-launch.sh install --image sentinelone/secops-mcps:1.6.0` (add your usual options), reinstall plugin 1.4.1, and restart the client. `dac_*` and `asset_inventory_*` are not in 1.6.0.

**Back to 1.5.7.** Restore the `.bak-` config copy that `install` saved before the 1.6.0 upgrade (it still has the `purple-mcp`, `virustotal` and `shodan` entries), or run `~/.local/bin/s1-secops-mcp-launch.sh install --image sentinelone/secops-mcps:1.5.7` for the `s1-secops-mcp` entry alone. Then restart the client. The 1.6.0 launcher refuses the removed server names, so restoring those three entries also needs the 1.5.7 launcher.

**Rollback target: `1.4.10`.** `sentinelone/secops-mcps` carries `1.6.3`, `1.6.2`, `1.6.1`, `1.6.0`, `1.5.7`, `1.5.6`, `1.5.5`, `1.5.4`, `1.5.3`, `1.5.2`, `1.5.1`, `1.5.0` and `1.4.10`; tags are immutable, so `:1.4.10` is the exact earlier build. Any image before `1.5.5` has no read-only mode: every tool can write, whatever `S1_READ_ONLY` says. Note that 1.4.10 reads tokens from the config `env` block or a `credentials.json`, so rolling back puts plaintext tokens back on disk. Once you return to 1.5.x, delete the backup and run `s1-secops-mcp forget` only if you also want the keychain entries gone.
