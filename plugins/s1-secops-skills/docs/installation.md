# Installation and Upgrade Guide

Five steps from zero to a working PrincipalSOCAnalyst session: one command that installs the launcher, connects Claude Desktop and stores credentials; a restart; the plugin; the Cowork project; verify.

The `s1-secops-mcp` server ships in one Docker image, `sentinelone/secops-mcps`. Besides PowerQuery, SDL, Mgmt Console, UAM and Hyperautomation tools, it carries Purple AI questions (`purple_ai_query`) and built-in VirusTotal and Shodan lookups (`ti_vt_*`, `ti_shodan_*`), which are listed when their API keys are stored. On the host you need Docker plus the small launcher script that reads your keychain and starts the container. The MCP client config holds no secrets.

Other MCP servers (the VirusTotal hosted MCP, SentinelOne's open-source purple-mcp, another threat-intel provider) are optional and install from their official sources: [connect-optional-tools.md](./connect-optional-tools.md).

The same steps in condensed form are in the [README Quick start (Docker)](../README.md#1-quick-start-docker). The full Docker reference (tags, troubleshooting flowchart, CLAUDE.md override, building from source) is [`docker.md`](./docker.md). Every credential, the resolution order and the security model are in [`credentials.md`](./credentials.md).

- [Prerequisites](#prerequisites)
- [Step 1: Install the launcher and store credentials](#step-1-install-the-launcher-and-store-credentials)
- [Step 2: Configure MCP servers](#step-2-configure-mcp-servers)
- [Step 3: Install the plugin](#step-3-install-the-plugin)
- [Step 4: Create the Cowork project](#step-4-create-the-cowork-project)
- [Step 5: Verify the install](#step-5-verify-the-install)
- [Upgrading](#upgrading)
- [Configuration reference](#configuration-reference)
- [Building from source](#building-from-source)

---

## Prerequisites

| Requirement | Check | Install |
|---|---|---|
| Docker (Desktop on macOS/Windows, Engine on Linux), running | `docker --version` | [docker.com/get-started](https://www.docker.com/get-started/) |
| An OS keychain | macOS: built in. Linux: `secret-tool --version` plus an unlocked Secret Service (GNOME Keyring or KeePassXC). Windows: Credential Manager, built in. | Linux: `libsecret-tools` (Debian, Ubuntu) or `libsecret` (Fedora, Arch) |
| SentinelOne API token | Settings → Users → Service Users | [Community guide](https://community.sentinelone.com/s/article/000005291) |
| SDL Log Write Key (only for raw log ingest) | Singularity Data Lake → API Keys | [Community guide](https://community.sentinelone.com/s/article/000006763) |
| VirusTotal API key (optional, built-in `ti_vt_*` tools) | [virustotal.com/gui/my-apikey](https://www.virustotal.com/gui/my-apikey) | A free key allows 4 lookups a minute and 500 a day. Some relationships (`related_threat_actors`, `similar_files`) need a premium key |
| Shodan API key (optional, built-in `ti_shodan_*` tools) | [account.shodan.io](https://account.shodan.io), Account page, API key | The two tools spend no query credits. A free key may get "Requires membership or higher" for some hosts; a membership or higher key gives dependable results |
| The launcher script | `mcp/docker/s1-secops-mcp-launch.sh` (macOS, Linux) or `mcp/docker/s1-secops-mcp-launch.ps1` (Windows) | Nothing to do: Step 1 downloads and installs it |

A headless Linux host with no D-Bus session cannot use the keychain; pass values as environment variables from a secret manager instead (see [credentials.md](./credentials.md)).

The image is multi-arch (`linux/amd64` + `linux/arm64`), so Apple Silicon runs natively without qemu. Step 1 pulls it for you.

---

<a id="step-1-store-credentials-in-the-keychain"></a>

## Step 1: Install the launcher and store credentials

One command, in a terminal on your machine. macOS or Linux:

```bash
mkdir -p ~/.local/bin && curl -fsSL https://raw.githubusercontent.com/Sentinel-One/ai-siem/main/mcp/docker/s1-secops-mcp-launch.sh -o ~/.local/bin/s1-secops-mcp-launch.sh && sh ~/.local/bin/s1-secops-mcp-launch.sh install
```

Windows (PowerShell):

```powershell
$f = "$env:TEMP\s1-secops-mcp-launch.ps1"; Invoke-WebRequest https://raw.githubusercontent.com/Sentinel-One/ai-siem/main/mcp/docker/s1-secops-mcp-launch.ps1 -OutFile $f -UseBasicParsing; powershell -NoProfile -ExecutionPolicy Bypass -File $f install
```

From a clone of this repo, `sh mcp/docker/s1-secops-mcp-launch.sh install` (Windows: `powershell -NoProfile -ExecutionPolicy Bypass -File mcp\docker\s1-secops-mcp-launch.ps1 install`) does the same.

What `install` does, in order (safe to re-run):

1. Copies the launcher to `~/.local/bin/s1-secops-mcp-launch.sh` (Windows: `%USERPROFILE%\bin\s1-secops-mcp-launch.ps1`) and clears the download quarantine flag. On macOS this keeps it out of `~/Documents`, `~/Desktop` and `~/Downloads`, where privacy protection stops Claude Desktop's `/bin/sh` from running it (`Operation not permitted` in the MCP log).
2. Adds the `s1-secops-mcp` entry to `claude_desktop_config.json` (Step 2) with the launcher's real path, keeps every other server and setting, removes older `purple-mcp`, `virustotal` and `shodan` entries that ran this launcher (servers you added yourself with other commands are kept), and saves the previous file as `claude_desktop_config.json.bak-<date>`. A config that is not valid JSON is left untouched and reported.
3. Pulls `sentinelone/secops-mcps:1.6.3`, or warns that Docker is not running.
4. If no console token is stored for the profile, runs `setup`: it prompts for each value without echo and stores it in the OS keychain under service `sentinelone-mcp`, account `default:<NAME>`.
5. Prints whether s1-secops-mcp is configured read-only (the default) or with write enabled, and which built-in tools are on, for example `Built-in tools: Purple AI on, VirusTotal on, Shodan off (no SHODAN_API_KEY)`.

> **Read-only by default (1.5.5 and later).** s1-secops-mcp refuses every tool call that would change your tenant (alert status, verdicts and notes, dashboards, parsers, lookup tables, Hyperautomation workflows, ingest) until you opt in. Investigation, hunting and reporting need nothing more. To deploy content or triage alerts from Claude, run `install` again with `--read-write` (Windows: `-ReadWrite`) and restart Claude Desktop. Read [read-only.md](./read-only.md) before you enable write.

Values: `S1_CONSOLE_URL`, `S1_CONSOLE_API_TOKEN`, `S1_HEC_INGEST_URL`, `S1_HEC_TOKEN` (SDL Log Write Key) and `S1_SCOPE`, plus the optional `VIRUSTOTAL_API_KEY` and `SHODAN_API_KEY` for the built-in threat-intel tools (press Enter to skip either). What each one is for: [credentials.md → The values](./credentials.md#the-values).

To change values later, run `~/.local/bin/s1-secops-mcp-launch.sh setup` (Windows: `powershell -NoProfile -ExecutionPolicy Bypass -File $HOME\bin\s1-secops-mcp-launch.ps1 setup`, which stores them in Credential Manager). For a non-default profile, add `--profile P` (Windows: `-Profile P`) to `install` or `setup`. If you have Node and the `s1-secops-mcp` CLI, `s1-secops-mcp setup` does the same and also verifies each value by reading it back; `s1-secops-mcp status` shows where every value resolves from, masked.

Skipped a VirusTotal or Shodan key and want it later? Run the launcher's `setup` to store it, then restart Claude Desktop. No second `install` is needed: the tools are listed as soon as the server starts with the key.

Upgrading from a `credentials.json` setup? Run `s1-secops-mcp setup --import-json /path/to/credentials.json`, check `s1-secops-mcp status`, then delete the file. See [credentials.md → Migrating](./credentials.md#migrating-from-a-credentials-file).

---

## Step 2: Configure MCP servers

### Claude Code (CLI), macOS, Linux and WSL

Run the installer in your own terminal, not through a `!` command in Claude Code, so it can prompt for the keys:

```bash
mkdir -p ~/.local/bin && curl -fsSL https://raw.githubusercontent.com/Sentinel-One/ai-siem/main/mcp/docker/s1-secops-mcp-launch.sh -o ~/.local/bin/s1-secops-mcp-launch.sh && sh ~/.local/bin/s1-secops-mcp-launch.sh install --claude-code
```

`--claude-code` registers `s1-secops-mcp` with `claude mcp add-json --scope user` instead of editing the Claude Desktop config, removes older `purple-mcp`, `virustotal` and `shodan` entries only when they run this launcher (a server of that name you installed yourself is kept), and sets `MCP_TIMEOUT` to 120 s in `~/.claude/settings.json` (a larger value is kept; the setting applies to every MCP server in Claude Code). It is chosen automatically when `install` runs inside Claude Code, in which case the Claude Desktop config is left unchanged. Add `--read-write` for write access. Restart Claude Code; `/mcp` lists `s1-secops-mcp`.

- **WSL:** without a Linux Secret Service, the launcher stores and reads keys in Windows Credential Manager through `powershell.exe`, the same items the Windows launcher and Cowork use. Turn on **Docker Desktop → Settings → Resources → WSL integration** for your distro, and add yourself to the `docker` group (`sudo usermod -aG docker $USER`, then `wsl --shutdown`).
- **Slow starts:** set `S1_LAUNCH_TRACE=/tmp/s1.trace` to log each launcher stage with timestamps (no values are logged).

### Claude Desktop

Step 1 already did this. Quit Claude Desktop completely (macOS: Cmd+Q; Windows: also quit it from the system tray) and open it again: Claude Desktop starts the MCP server itself through the launcher, in one container, and removes it when it quits. Docker Desktop only needs to be running; do not start the image from Docker Desktop, because a container started there has no credentials and no connection to Claude.

The config lives at `~/Library/Application Support/Claude/claude_desktop_config.json` on macOS and `%APPDATA%\Claude\claude_desktop_config.json` on Windows. A fresh Windows install from the claude.ai installer is an MSIX package that reads its own copy under `%LOCALAPPDATA%\Packages\Claude_<id>\LocalCache\Roaming\Claude\` instead, while **Settings → Developer → Edit config** still opens the `%APPDATA%` file. Some builds keep user data outside the package in `%LOCALAPPDATA%\Claude-Data\<package id>\claude_desktop_config.json`. `install` writes all three locations, so any of these installs picks up the server, and it warns when it finds no existing config. If the server still does not appear after a restart, open **Edit config**, note the path of the file it opens, and run `install -ConfigPath "<that path>"`. If you would rather have one file that **Edit config** also opens, uninstall the MSIX build and install with the classic `Claude Setup.exe`, which reads `%APPDATA%\Claude\`; re-run `install` afterwards (tested on Windows 11). To see what `install` wrote, or to configure another MCP client by hand, print the entry for this machine:

```bash
~/.local/bin/s1-secops-mcp-launch.sh config
```

On macOS the output looks like this, with your own home folder in place of `<home>`:

```json
{
  "mcpServers": {
    "s1-secops-mcp": {
      "command": "<home>/.local/bin/s1-secops-mcp-launch.sh",
      "args": ["--image", "sentinelone/secops-mcps:1.6.3", "s1-secops-mcp"]
    }
  }
}
```

With `--read-write` (Windows: `-ReadWrite`), the `s1-secops-mcp` entry also carries `"env": {"S1_READ_ONLY": "false"}`; see [read-only.md](./read-only.md).

Copy what the command prints, not this sample. The config is JSON, which does not expand `~`, `$HOME` or `%USERPROFILE%`, so the path has to be the exact one for your account; a hand-typed `/Users/you/...` is the most common reason a server stays red.

On Windows the entry uses the PowerShell launcher (`powershell -NoProfile -ExecutionPolicy Bypass -File $HOME\bin\s1-secops-mcp-launch.ps1 config` prints it):

```json
"s1-secops-mcp": {
  "command": "powershell.exe",
  "args": ["-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
           "<home>\\bin\\s1-secops-mcp-launch.ps1",
           "-Image", "sentinelone/secops-mcps:1.6.3", "s1-secops-mcp"]
}
```

In a hand-written entry, launcher options (`--image`, `--profile`; on Windows `-Image`, `-Profile`) go before the server name: everything after the server name is passed to the server inside the container, which rejects an unknown argument.

The launcher reads the keychain on the host and passes the values to the container over stdin, so they never appear in this file, in `docker inspect`, or in the process list. Do not add an `env` block with tokens and do not switch to `docker run -e`: both store secrets in plaintext. Background: [credentials.md → Docker](./credentials.md#docker-the-launcher-not--e).

Optional: to get `outputFile` results (bulk query exports, binary downloads, workflow ZIPs) somewhere you can open them, run `install` again with `--output-dir ~/Documents/s1-output` (Windows: `-OutputDir $HOME\Documents\s1-output`). It creates the folder and adds `S1_OUTPUT_DIR` to the `s1-secops-mcp` entry. That is a directory path, not a secret; the macOS/Linux launcher mounts it into the container at the same path, and the Windows launcher mounts it at `/output` (pass `outputFile` paths under `/output/` there).

**Notes:**

- `purple_ai_query` uses the stored console URL and token; it needs no extra key. It returns either a written answer or a PowerQuery that Purple AI suggests but does not run (run it with `powerquery_run`).
- The built-in VirusTotal tools (`ti_vt_lookup`, `ti_vt_relationship`) use the stored `VIRUSTOTAL_API_KEY`, and the Shodan tools (`ti_shodan_host`, `ti_shodan_dns`) use `SHODAN_API_KEY`. Each pair is listed only when its key is stored. Tool details: [mcp-tools.md](./mcp-tools.md).
- Region URLs vary. Look up your region in the [SentinelOne Endpoint URLs by Region](https://community.sentinelone.com/s/article/000004961) article.
- Your organisation uses a different threat-intel provider? Add that provider's MCP from its official source next to `s1-secops-mcp`: [connect-optional-tools.md](./connect-optional-tools.md). The skills are written provider-agnostic.
- Every install is pinned. There is no `:latest`, and the repository has immutable tags enabled, so `1.6.1` always means the same bytes.
- s1-secops-mcp is read-only by default. `purple_ai_query` and the built-in threat-intel tools are read-only, so they always run. Details: [read-only.md](./read-only.md).
- Third-party components, licenses and service terms: [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md), or `docker run --rm sentinelone/secops-mcps:1.6.3 notices`.

---

## Step 3: Install the plugin

The plugin bundles all eight skills in a single file. Download `s1-secops-skills-vX.Y.Z.plugin` from [ai-siem `plugins/s1-secops-skills/dist/`](../dist/).

In the Claude desktop app:

1. Open the **Cowork** tab
2. Click **Customize** in the left sidebar
3. Click **Browse plugins**
4. Upload the `.plugin` file

All eight skills install in one step. No individual skill configuration needed.

If the plugin upload fails, install individual `.skill` files from the same `dist/` folder. The eight are: `mgmt-console-api.skill`, `powerquery.skill`, `sdl-api.skill`, `sdl-dashboard.skill`, `sdl-log-parser.skill`, `hyperautomation.skill`, `sdl-solutions.skill`, `soc-investigator.skill`.

---

## Step 4: Create the Cowork project

> Create this project in Cowork, not Claude.ai chat. Open the Claude desktop app and navigate to Cowork from the sidebar.

1. Open **Cowork** and click **New Project**
2. Name it `PrincipalSOCAnalyst`
3. Click **Select Folder** and choose any folder on your machine (this becomes the project workspace)
4. Optionally drop a copy of [`CLAUDE.md`](../CLAUDE.md) from this repo into the project folder. The image ships a default persona at `/etc/sentinelone/CLAUDE.md`, so this step is only needed when you want to customise it. To point the container at your own copy, re-run `install --claude-md <path to your CLAUDE.md>` (Windows: `-ClaudeMd`), which sets `S1_CLAUDE_MD_PATH` in the `s1-secops-mcp` entry with the full path (the launchers mount it read-only), see [docker.md → CLAUDE.md customization](./docker.md#claudemd-customization).
5. Confirm `s1-secops-skills` appears under **Personal plugins**, and that `s1-secops-mcp` (plus any optional server you added) appears under **MCP Servers**

Do not put tokens in the project folder. The skills reach the tenant only through the MCP servers, which read the keychain; the Cowork sandbox itself cannot reach `*.sentinelone.net`.

---

## Step 5: Verify the install

Open the **PrincipalSOCAnalyst** project and start a new session. Claude will automatically:

- Enumerate all live `dataSource.name` values in your SDL
- Pull open alerts in parallel

Run a smoke test to confirm everything is wired up:

```text
smoke test s1 secops skills
```

Claude verifies connectivity to `s1-secops-mcp` and its built-in tools (and any optional MCP you added), confirms each skill is loaded, and reports any missing credentials or unreachable endpoints.

You can also test the image straight from a terminal, with no Claude Desktop involved:

```bash
docker run --rm sentinelone/secops-mcps:1.6.3 versions   # what is inside the image
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"smoke","version":"0.1"}}}' \
  | docker run -i --rm sentinelone/secops-mcps:1.6.3 s1-secops-mcp
```

The second command needs no credentials. It returns one JSON line with `serverInfo.name = "s1-secops-mcp-server"`, and stderr shows a `Threat intel:` line, a `Tools:` line (43 listed of 47 registered with no threat-intel keys; 45 with a VirusTotal key, 47 with both) and a `Mode:` line (`READ-ONLY` by default). The `version` it reports is the bundled MCP's own version, not the image tag.

If anything is red, check:

- `s1-secops-mcp` is listed and green under MCP Servers in the Cowork session panel. A red `purple-mcp`, `virustotal` or `shodan` entry is left over from before 1.6.0: run the [Step 1](#step-1-install-the-launcher-and-store-credentials) command again to remove it
- Docker is running: `docker info | head -3`
- On macOS, the MCP log (`~/Library/Logs/Claude/mcp-server-<name>.log`) does not show `/bin/sh: .../s1-secops-mcp-launch.sh: Operation not permitted`. If it does, the config points at a launcher under `~/Documents`, `~/Desktop` or `~/Downloads`; run the [Step 1](#step-1-install-the-launcher-and-store-credentials) command again, which installs it to `~/.local/bin/` and rewrites the config
- The MCP log does not show `ENOENT` or `No such file or directory` for the launcher. If it does, the `command` path was typed by hand and does not exist; run the Step 1 command again, which writes your real path
- The keychain holds the values: `~/.local/bin/s1-secops-mcp-launch.sh status` (or `s1-secops-mcp status`), which shows secrets as a length only
- The API token has the right scope (Viewer or higher for read; IR Team or higher for response actions)
- A tool reply that starts `s1-secops-mcp is in read-only mode (S1_READ_ONLY)` is the expected default, not a fault. Enable write only if you need it: [read-only.md](./read-only.md)

Full troubleshooting flowchart and MCP log tailing: [docker.md → Troubleshooting](./docker.md#troubleshooting).

To confirm the active plugin version: `which version of s1-secops-skills is installed?`

---

## Upgrading

**MCP server** (`s1-secops-mcp`): the config pins `1.6.3`, so restarting Claude Desktop keeps that exact image. To upgrade, run the [Step 1](#step-1-install-the-launcher-and-store-credentials) command again: it downloads the current launcher, whose default image is the current release, rewrites the entry with that tag, removes entries from older releases that ran this launcher, pulls the image and keeps your stored credentials. Pass `--read-write` (Windows: `-ReadWrite`) again if you use write access; without it the rewritten entry is read-only. To move to a specific tag instead, run `~/.local/bin/s1-secops-mcp-launch.sh install --image sentinelone/secops-mcps:<tag>`. Then restart Claude Desktop.

**Plugin**: download the new `.plugin` from [the ai-siem `dist/` folder](../dist/), open Cowork → Customize → Browse plugins, upload, click **Replace** when prompted.

**CLAUDE.md**: if you customised it, your project-folder copy stays as-is. To pick up upstream improvements, diff against the latest [`CLAUDE.md`](../CLAUDE.md) in this repo.

Moving to 1.6.0 replaces the `purple-mcp`, `virustotal` and `shodan` entries with built-in tools and renames some tools: see [upgrading.md → 1.5.7 to 1.6.0](./upgrading.md#157-to-160). Moving to 1.5.5 makes s1-secops-mcp read-only by default: see [upgrading.md → 1.5.4 to 1.5.5](./upgrading.md#154-to-155). Moving from 1.4.x to 1.5.0 is a breaking change (no `credentials.json`, no HTTP transport, Docker launcher instead of `-e`). Step-by-step instructions, including what to delete from an older config: [upgrading.md](./upgrading.md).

---

## Configuration reference

- **Credentials:** environment variables, then the OS keychain (service `sentinelone-mcp`, account `<profile>:<NAME>`). No file. Full reference: **[credentials.md](./credentials.md)**.
- **`S1_PROFILE`:** selects a keychain profile (default `default`), for example one per tenant.
- **`S1_KEYCHAIN=off`:** disables the keychain lookup (CI, containers, tests).
- **`S1_OUTPUT_DIR`** (Docker launcher) / **`S1_OUTPUT_DIRS`** (server): where `outputFile` may write. The server default is your home and temp directories. Under Docker set it with `install --output-dir`; `S1_OUTPUT_DIRS` in the client config does not reach the container. Without it, files the server writes stay inside the container and are lost when it exits, so from 1.5.4 the server in the image refuses `outputFile` and says to run `install --output-dir`.
- **`S1_CLAUDE_MD_PATH`:** points the server at a custom CLAUDE.md (both the macOS/Linux and the Windows launcher mount the host file read-only into the container).
- **`S1_KEYCHAIN_TIMEOUT`** (sh launcher, seconds, default 15) / **`S1_KEYCHAIN_TIMEOUT_MS`** (native server and Python clients, milliseconds, default 15000): how long a keychain read may wait before it is treated as unavailable.
- **`S1_MCP_IMAGE`:** the launcher's default image when no `--image` is passed (`sentinelone/secops-mcps:1.6.3`).
- **`S1_READ_ONLY`:** read-only mode for s1-secops-mcp. Unset or `true` (the default) refuses every call that changes the tenant; `false` enables write. Set it with `install --read-write` (Windows: `-ReadWrite`), the `.mcpb` extension's **Read-only mode (recommended)** setting, or `"S1_READ_ONLY": "false"` in the `env` block for a Node install. It lives in the client config, not the keychain. Full reference: [read-only.md](./read-only.md).

The two values you always need are `S1_CONSOLE_URL` and `S1_CONSOLE_API_TOKEN`, which between them authorise parser and dashboard deployment and every other SDL operation; add `S1_HEC_INGEST_URL` for alert ingest and `S1_HEC_TOKEN` for raw log ingest. `VIRUSTOTAL_API_KEY` and `SHODAN_API_KEY` are optional and turn on the built-in threat-intel tools.

---

## Building from source

Only needed when changing the skills. End users do not need this.

```bash
git clone https://github.com/Sentinel-One/ai-siem.git
cd ai-siem/plugins/s1-secops-skills

# Rebuild the plugin and the per-skill .skill files into dist/
bash scripts/build.sh         # incremental
bash scripts/build.sh --clean # clean
```

The Docker image is built and published by the maintainers; see [docker.md → Building from source](./docker.md#building-from-source) for how to review and verify it.
