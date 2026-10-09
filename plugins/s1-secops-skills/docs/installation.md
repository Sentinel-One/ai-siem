# Installation and Upgrade Guide

Five steps from zero to a working PrincipalSOCAnalyst session: one command that installs the launcher, connects Claude Desktop and stores credentials; a restart; the plugin; the Cowork project; verify.

All three MCP servers (`s1-secops-mcp`, `purple-mcp`, `virustotal-mcp`) ship in one Docker image, `sentinelone/secops-mcps`, version-locked together. On the host you need Docker plus the small launcher script that reads your keychain and starts the container. The MCP client config holds no secrets.

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
| VirusTotal API key | [virustotal.com/gui/my-apikey](https://www.virustotal.com/gui/my-apikey) | Free tier is sufficient |
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
2. Adds `s1-secops-mcp`, `purple-mcp` and `virustotal` to `claude_desktop_config.json` (Step 2) with the launcher's real path, keeps every other server and setting, removes older entries that ran the launcher under another name, and saves the previous file as `claude_desktop_config.json.bak-<date>`. A config that is not valid JSON is left untouched and reported.
3. Pulls `sentinelone/secops-mcps:1.5.3`, or warns that Docker is not running.
4. If no console token is stored for the profile, runs `setup`: it prompts for each value without echo and stores it in the OS keychain under service `sentinelone-mcp`, account `default:<NAME>`.

Values: `S1_CONSOLE_URL`, `S1_CONSOLE_API_TOKEN`, `S1_HEC_INGEST_URL`, `S1_HEC_TOKEN` (SDL Log Write Key) and `S1_SCOPE`, plus `VIRUSTOTAL_API_KEY` (used by both the VirusTotal MCP and purple-mcp's threat intelligence tools). What each one is for: [credentials.md → The values](./credentials.md#the-values).

To change values later, run `~/.local/bin/s1-secops-mcp-launch.sh setup` (Windows: `powershell -NoProfile -ExecutionPolicy Bypass -File $HOME\bin\s1-secops-mcp-launch.ps1 setup`, which stores them in Credential Manager). For a non-default profile, add `--profile P` (Windows: `-Profile P`) to `install` or `setup`. If you have Node and the `s1-secops-mcp` CLI, `s1-secops-mcp setup` does the same and also verifies each value by reading it back; `s1-secops-mcp status` shows where every value resolves from, masked.

Upgrading from a `credentials.json` setup? Run `s1-secops-mcp setup --import-json /path/to/credentials.json`, check `s1-secops-mcp status`, then delete the file. See [credentials.md → Migrating](./credentials.md#migrating-from-a-credentials-file).

---

## Step 2: Configure MCP servers

Step 1 already did this. Quit Claude Desktop completely (macOS: Cmd+Q; Windows: also quit it from the system tray) and open it again: Claude Desktop starts the three MCPs itself through the launcher, one container each, and removes them when it quits. Docker Desktop only needs to be running; do not start the image from Docker Desktop, because a container started there has no credentials and no connection to Claude.

The config lives at `~/Library/Application Support/Claude/claude_desktop_config.json` on macOS and `%APPDATA%\Claude\claude_desktop_config.json` on Windows. A fresh Windows install from the claude.ai installer is an MSIX package that reads its own copy under `%LOCALAPPDATA%\Packages\Claude_<id>\LocalCache\Roaming\Claude\` instead, while **Settings → Developer → Edit config** still opens the `%APPDATA%` file; `install` writes both, so either kind of install picks up the servers. If you would rather have one file that **Edit config** also opens, uninstall the MSIX build and install with the classic `Claude Setup.exe`, which reads `%APPDATA%\Claude\`; re-run `install` afterwards (tested on Windows 11). To see what `install` wrote, or to configure another MCP client by hand, print the entries for this machine:

```bash
~/.local/bin/s1-secops-mcp-launch.sh config
```

On macOS the output looks like this, with your own home folder in place of `<home>`:

```json
{
  "mcpServers": {
    "s1-secops-mcp": {
      "command": "<home>/.local/bin/s1-secops-mcp-launch.sh",
      "args": ["--image", "sentinelone/secops-mcps:1.5.3", "s1-secops-mcp"]
    },
    "purple-mcp": {
      "command": "<home>/.local/bin/s1-secops-mcp-launch.sh",
      "args": ["--image", "sentinelone/secops-mcps:1.5.3", "purple-mcp"]
    },
    "virustotal": {
      "command": "<home>/.local/bin/s1-secops-mcp-launch.sh",
      "args": ["--image", "sentinelone/secops-mcps:1.5.3", "virustotal-mcp"]
    }
  }
}
```

Copy what the command prints, not this sample. The config is JSON, which does not expand `~`, `$HOME` or `%USERPROFILE%`, so the path has to be the exact one for your account; a hand-typed `/Users/you/...` is the most common reason a server stays red.

On Windows the entries use the PowerShell launcher (`powershell -NoProfile -ExecutionPolicy Bypass -File $HOME\bin\s1-secops-mcp-launch.ps1 config` prints them):

```json
"s1-secops-mcp": {
  "command": "powershell.exe",
  "args": ["-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
           "<home>\\bin\\s1-secops-mcp-launch.ps1",
           "-Image", "sentinelone/secops-mcps:1.5.3", "s1-secops-mcp"]
}
```

In a hand-written entry, launcher options (`--image`, `--profile`; on Windows `-Image`, `-Profile`) go before the server name: everything after the server name is passed to the server inside the container, which rejects an unknown argument.

The launcher reads the keychain on the host and passes the values to the container over stdin, so they never appear in this file, in `docker inspect`, or in the process list. Do not add an `env` block with tokens and do not switch to `docker run -e`: both store secrets in plaintext. Background: [credentials.md → Docker](./credentials.md#docker-the-launcher-not--e).

Optional: to get `outputFile` results (bulk query exports, binary downloads, workflow ZIPs) somewhere you can open them, run `install` again with `--output-dir ~/Documents/s1-output` (Windows: `-OutputDir $HOME\Documents\s1-output`). It creates the folder and adds `S1_OUTPUT_DIR` to the `s1-secops-mcp` entry. That is a directory path, not a secret; the macOS/Linux launcher mounts it into the container at the same path, and the Windows launcher mounts it at `/output` (pass `outputFile` paths under `/output/` there).

**Notes:**

- purple-mcp reads the same `S1_CONSOLE_URL` and `S1_CONSOLE_API_TOKEN`; the image entrypoint maps them onto `PURPLEMCP_CONSOLE_BASE_URL` and `PURPLEMCP_CONSOLE_TOKEN`.
- purple-mcp also receives the stored `VIRUSTOTAL_API_KEY`, which the entrypoint maps to `PURPLEMCP_VT_API_KEY` for its threat intelligence tools. No separate setup: the one key you stored in Step 1 serves both the VirusTotal MCP and purple-mcp. Which server to use for which task: [mcp-tools.md → Threat intelligence: which server to use](./mcp-tools.md#threat-intelligence-which-server-to-use).
- Region URLs vary. Look up your region in the [SentinelOne Endpoint URLs by Region](https://community.sentinelone.com/s/article/000004961) article.
- The VirusTotal MCP shown is one example. Replace it with your organisation's approved threat intel MCP if different.
- Every install is pinned. There is no `:latest`, and the repository has immutable tags enabled, so `1.5.3` always means the same bytes.

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
5. Confirm `s1-secops-skills` appears under **Personal plugins**, and that `s1-secops-mcp`, `purple-mcp`, and your threat intel MCP appear under **MCP Servers**

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

Claude verifies connectivity to `s1-secops-mcp`, `purple-mcp`, and the threat intel MCP, confirms each skill is loaded, and reports any missing credentials or unreachable endpoints.

You can also test the image straight from a terminal, with no Claude Desktop involved:

```bash
docker run --rm sentinelone/secops-mcps:1.5.3 versions   # what is inside the image
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"smoke","version":"0.1"}}}' \
  | docker run -i --rm sentinelone/secops-mcps:1.5.3 s1-secops-mcp
```

The second command needs no credentials. It returns one JSON line with `serverInfo.name = "s1-secops-mcp-server"`, and stderr shows `Tools: 35 registered`. The `version` it reports is the bundled MCP's own version, not the image tag.

If anything is red, check:

- All three MCPs are listed and green under MCP Servers in the Cowork session panel
- Docker is running: `docker info | head -3`
- On macOS, the MCP log (`~/Library/Logs/Claude/mcp-server-<name>.log`) does not show `/bin/sh: .../s1-secops-mcp-launch.sh: Operation not permitted`. If it does, the config points at a launcher under `~/Documents`, `~/Desktop` or `~/Downloads`; run the [Step 1](#step-1-install-the-launcher-and-store-credentials) command again, which installs it to `~/.local/bin/` and rewrites the config
- The MCP log does not show `ENOENT` or `No such file or directory` for the launcher. If it does, the `command` path was typed by hand and does not exist; run the Step 1 command again, which writes your real path
- The keychain holds the values: `~/.local/bin/s1-secops-mcp-launch.sh status` (or `s1-secops-mcp status`), which shows secrets as a length only
- The API token has the right scope (Viewer or higher for read; IR Team or higher for response actions)

Full troubleshooting flowchart and per-MCP log tailing: [docker.md → Troubleshooting](./docker.md#troubleshooting).

To confirm the active plugin version: `which version of s1-secops-skills is installed?`

---

## Upgrading

**MCP servers** (`s1-secops-mcp`, `purple-mcp`, `virustotal`): the config pins `1.5.3`, so restarting Claude Desktop keeps that exact image. To upgrade, run the [Step 1](#step-1-install-the-launcher-and-store-credentials) command again: it downloads the current launcher, whose default image is the current release, rewrites the three entries with that tag, pulls the image and keeps your stored credentials. To move to a specific tag instead, run `~/.local/bin/s1-secops-mcp-launch.sh install --image sentinelone/secops-mcps:<tag>`. Then restart Claude Desktop.

**Plugin**: download the new `.plugin` from [the ai-siem `dist/` folder](../dist/), open Cowork → Customize → Browse plugins, upload, click **Replace** when prompted.

**CLAUDE.md**: if you customised it, your project-folder copy stays as-is. To pick up upstream improvements, diff against the latest [`CLAUDE.md`](../CLAUDE.md) in this repo.

Moving from 1.4.x to 1.5.0 is a breaking change (no `credentials.json`, no HTTP transport, Docker launcher instead of `-e`). Step-by-step instructions, including what to delete from an older config: [upgrading.md](./upgrading.md).

---

## Configuration reference

- **Credentials:** environment variables, then the OS keychain (service `sentinelone-mcp`, account `<profile>:<NAME>`). No file. Full reference: **[credentials.md](./credentials.md)**.
- **`S1_PROFILE`:** selects a keychain profile (default `default`), for example one per tenant.
- **`S1_KEYCHAIN=off`:** disables the keychain lookup (CI, containers, tests).
- **`S1_OUTPUT_DIR`** (Docker launcher) / **`S1_OUTPUT_DIRS`** (server): where `outputFile` may write. The server default is your home and temp directories.
- **`S1_CLAUDE_MD_PATH`:** points the server at a custom CLAUDE.md (both the macOS/Linux and the Windows launcher mount the host file read-only into the container).
- **`S1_KEYCHAIN_TIMEOUT`** (sh launcher, seconds, default 15) / **`S1_KEYCHAIN_TIMEOUT_MS`** (native server and Python clients, milliseconds, default 15000): how long a keychain read may wait before it is treated as unavailable.
- **`S1_MCP_IMAGE`:** the launcher's default image when no `--image` is passed (`sentinelone/secops-mcps:1.5.3`).

The two values you always need are `S1_CONSOLE_URL` and `S1_CONSOLE_API_TOKEN`, which between them authorise parser and dashboard deployment and every other SDL operation; add `S1_HEC_INGEST_URL` for alert ingest and `S1_HEC_TOKEN` for raw log ingest.

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
