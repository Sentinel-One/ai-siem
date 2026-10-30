# Upgrading

Three things move independently: the **MCP image** (or npm install), the **skills plugin**, and
your **MCP client config**. Do them in that order.

- [Launcher update for Claude Code, Linux and WSL](#launcher-update-for-claude-code-linux-and-wsl) (image and plugin unchanged)
- [1.5.6 to 1.5.7](#156-to-157) (current release: image `1.5.7`, s1-secops-mcp `1.5.7`, plugin `1.3.17`)
- [Plugin 1.3.16 to 1.3.17](#plugin-1316-to-1317)
- [1.5.5 to 1.5.6](#155-to-156)
- [1.5.4 to 1.5.5](#154-to-155)
- [1.5.3 to 1.5.4](#153-to-154)
- [1.5.0, 1.5.1 or 1.5.2 to 1.5.3](#150-151-or-152-to-153)
- [1.4.x to 1.5.0](#14x-to-150)
- [Older: 1.2.x / 1.3.x to 1.4.x](#older-12x--13x-to-14x)
- [Rolling back](#rolling-back)

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

The launcher script changed; the image (`1.5.7`) and the plugin (`1.3.17`) did not. MCP clients run the installed copy in `~/.local/bin`, so a fresh download alone does not apply the fix: run `install` again.

1. Download the launcher and re-run `install` with your usual options (add `--read-write` again if you use write access):

   ```bash
   curl -fsSL https://raw.githubusercontent.com/Sentinel-One/ai-siem/main/mcp/docker/s1-secops-mcp-launch.sh -o /tmp/s1-secops-mcp-launch.sh && sh /tmp/s1-secops-mcp-launch.sh install
   ```

2. **Claude Code users** (macOS, Linux, WSL): add `--claude-code` so the servers are registered with Claude Code. This also sets `MCP_TIMEOUT` to 120 s in `~/.claude/settings.json`, which applies to every MCP server in Claude Code. Then restart Claude Code.
3. **WSL users:** credentials are read from Windows Credential Manager when no Linux Secret Service is available, so values already stored by the Windows launcher or Cowork are reused. Turn on Docker Desktop's WSL integration for the distro and add your user to the `docker` group.

**Check:** `~/.local/bin/s1-secops-mcp-launch.sh status` lists your stored values, and `/mcp` in Claude Code shows the servers connected.

---

## 1.5.6 to 1.5.7

A dependency and base-image update. No configuration changes: credentials, profiles, output folders and the plugin (1.3.17) carry over.

1. Re-run your usual `install` command to pull `:1.5.7`, with the same options as before. `install` writes the mode you ask for, so add `--read-write` again if you use write access:

   ```bash
   ~/.local/bin/s1-secops-mcp-launch.sh install
   ```

2. Quit and reopen Claude Desktop.

Check with `docker run --rm sentinelone/secops-mcps:1.5.7 versions` (Node `v24.22.1`).

---

## 1.5.5 to 1.5.6

A security update to read-only mode in `s1-secops-mcp`. Nothing to migrate: credentials, profiles, output folders and the plugin (1.3.16) carry over.

1. Re-run your usual `install` command to pull `:1.5.6`, with the same options as before. `install` writes the mode you ask for, so add `--read-write` again if you use write access:

   ```bash
   ~/.local/bin/s1-secops-mcp-launch.sh install
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

1. Re-run the install command (macOS/Linux one-liner or the Windows one in [1.5.0, 1.5.1 or 1.5.2 to 1.5.3](#150-151-or-152-to-153)). It installs the newer launcher, rewrites your entries with `1.5.5` and pulls the image. Pass your usual options again (`--profile P`, `--output-dir DIR`, `--claude-md FILE`, `--with-shodan`).
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

Image 1.5.4 adds a fourth, **optional** MCP server, Shodan (`shodan-mcp`), for exposure
intelligence on external IPs and domains: open ports, services, banners, TLS/JARM and host CVEs,
plus Shodan CVEDB lookups. It complements VirusTotal, which stays the primary IOC enrichment.
Tools and credit costs: [mcp-tools.md → Shodan MCP](./mcp-tools.md#shodan-mcp-optional).

The bundled s1-secops-mcp moves to 1.5.4 for one fix. In the image, `outputFile` used to report
success for a path inside the container (`/tmp`, `/home/node`), and the file was lost when the
container exited. It is now refused unless a folder is shared with `install --output-dir`, and every
refusal says to run that. If you write exports, pass `--output-dir` in step 1.

1. **Pull the new tag** by re-running the install command (macOS/Linux one-liner or the Windows one in
   [1.5.0, 1.5.1 or 1.5.2 to 1.5.3](#150-151-or-152-to-153)). It installs the newer launcher,
   rewrites your entries with `1.5.4` and pulls the image. Pass your usual options again
   (`--profile P`, `--output-dir DIR`, `--claude-md FILE`).
2. **To add Shodan, store the key:** run `~/.local/bin/s1-secops-mcp-launch.sh setup` (Windows:
   `powershell -NoProfile -ExecutionPolicy Bypass -File $HOME\bin\s1-secops-mcp-launch.ps1 setup`)
   and enter `SHODAN_API_KEY` from [account.shodan.io](https://account.shodan.io) (Account page,
   API key). Press Enter at every other prompt to keep the current values, and at the Shodan prompt
   to skip it.
3. **Re-run `install`.** It writes the `shodan` entry only when `SHODAN_API_KEY` is stored (or with
   `--with-shodan`, Windows `-WithShodan`). Then quit and reopen Claude Desktop.

Without a Shodan key you need only step 1; the three existing entries move to `1.5.4` and no
`shodan` entry is added. A free ("oss") key reliably covers the CVEDB tools, counts and filters.
Host lookups and DNS return "Requires membership or higher" for some targets, and `shodan_search`
needs a membership or higher. Use a membership or higher key for dependable results.

Check what you have with `docker run --rm sentinelone/secops-mcps:1.5.4 versions`: it now also
lists the `shodan-mcp` pin and the Node version.

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

It rewrites the `s1-secops-mcp`, `purple-mcp` and `virustotal` entries with the current tag and your real
path, keeps your other servers, saves a backup of the old config, pulls the image and keeps your
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

Step 2 already replaced the `s1-secops-mcp`, `purple-mcp` and `virustotal` entries, and removed
older entries that ran the launcher under another name. Open the config and delete any token still
left in other entries, then delete the `.bak-` copy `install` made once the new setup works, because
it may still hold tokens. To see the entries for this machine, or to configure another client by
hand, run `~/.local/bin/s1-secops-mcp-launch.sh config`: it prints them with your real path (JSON
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

Expect `serverInfo.name = "s1-secops-mcp-server"`, `version = "1.5.7"`, `Tools: 35 registered` on stderr, and `configured` for each surface whose values you stored. Confirm no token remains in your client config:

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
| Image | `s1-mcps:1.2.x` | `sentinelone/secops-mcps:1.5.7` via the launcher |
| purple-mcp variables | `PURPLEMCP_CONSOLE_BASE_URL`, `PURPLEMCP_CONSOLE_TOKEN` | `S1_CONSOLE_URL`, `S1_CONSOLE_API_TOKEN` (the entrypoint derives the purple names) |

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
| `manifest unknown` / image pull fails | Tag typo, or an MCP version used as an image tag. Use the exact image tag (`1.5.7`). |
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

**Rollback target: `1.4.10`.** `sentinelone/secops-mcps` carries `1.5.7`, `1.5.6`, `1.5.5`, `1.5.4`, `1.5.3`, `1.5.2`, `1.5.1`, `1.5.0` and `1.4.10`; tags are immutable, so `:1.4.10` is the exact earlier build. Any image before `1.5.5` has no read-only mode: every tool can write, whatever `S1_READ_ONLY` says. Note that 1.4.10 reads tokens from the config `env` block or a `credentials.json`, so rolling back puts plaintext tokens back on disk. Once you return to 1.5.x, delete the backup and run `s1-secops-mcp forget` only if you also want the keychain entries gone.
