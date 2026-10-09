# Installation and Upgrade Guide

Five steps from zero to a working PrincipalSOCAnalyst session: store credentials in the OS keychain, configure MCP servers, install the plugin, create the Cowork project, verify.

All three MCP servers (`s1-secops-mcp`, `purple-mcp`, `virustotal-mcp`) ship in one Docker image, `sentinelone/secops-mcps`, version-locked together. On the host you need Docker plus the small launcher script that reads your keychain and starts the container. The MCP client config holds no secrets.

The same steps in condensed form are in the [README Quick start (Docker)](../README.md#1-quick-start-docker). The full Docker reference (tags, troubleshooting flowchart, CLAUDE.md override, building from source) is [`docker.md`](./docker.md). Every credential, the resolution order and the security model are in [`credentials.md`](./credentials.md).

- [Prerequisites](#prerequisites)
- [Step 1: Store credentials in the keychain](#step-1-store-credentials-in-the-keychain)
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
| The launcher script | `mcp/docker/s1-secops-mcp-launch.sh` (macOS, Linux) or `mcp/docker/s1-secops-mcp-launch.ps1` (Windows) from this repo | macOS/Linux: copy it to `~/.local/bin/` (command below). Windows: put it somewhere stable such as `C:\Users\you\bin\` |

Install the macOS/Linux launcher from the repo root:

```bash
mkdir -p ~/.local/bin && cp -X mcp/docker/s1-secops-mcp-launch.sh ~/.local/bin/ && chmod 755 ~/.local/bin/s1-secops-mcp-launch.sh
```

> **macOS: keep the launcher out of `~/Documents`, `~/Desktop` and `~/Downloads`.** macOS privacy protection blocks Claude Desktop's `/bin/sh` from running a script stored in those folders; the MCP log shows `/bin/sh: .../s1-secops-mcp-launch.sh: Operation not permitted` and the server never starts. A repo clone or a browser download usually lands in one of them, which is why the command copies the script to `~/.local/bin/`. `cp -X` drops extended attributes such as the download quarantine flag.

A headless Linux host with no D-Bus session cannot use the keychain; pass values as environment variables from a secret manager instead (see [credentials.md](./credentials.md)).

The image is multi-arch (`linux/amd64` + `linux/arm64`), so Apple Silicon runs natively without qemu. Pull it once before you start:

```bash
docker pull sentinelone/secops-mcps:1.5.3
```

---

## Step 1: Store credentials in the keychain

Run the launcher's setup mode once, in a terminal on your machine. It prompts for each value without echo and stores it in the OS keychain under service `sentinelone-mcp`, account `default:<NAME>`:

```bash
~/.local/bin/s1-secops-mcp-launch.sh setup
```

On Windows, run `powershell -NoProfile -ExecutionPolicy Bypass -File C:\Users\you\bin\s1-secops-mcp-launch.ps1 setup`, which stores the values in Credential Manager. To use a non-default profile, put `--profile P` (or `-Profile P` on Windows) before `setup`.

If you have Node and the `s1-secops-mcp` CLI, `s1-secops-mcp setup` does the same and also verifies each value by reading it back; `s1-secops-mcp status` shows where every value resolves from, masked.

Values: `S1_CONSOLE_URL`, `S1_CONSOLE_API_TOKEN`, `S1_HEC_INGEST_URL`, `S1_HEC_TOKEN` (SDL Log Write Key) and `S1_SCOPE`, plus `VIRUSTOTAL_API_KEY` (used by both the VirusTotal MCP and purple-mcp's threat intelligence tools). What each one is for: [credentials.md → The values](./credentials.md#the-values).

Upgrading from a `credentials.json` setup? Run `s1-secops-mcp setup --import-json /path/to/credentials.json`, check `s1-secops-mcp status`, then delete the file. See [credentials.md → Migrating](./credentials.md#migrating-from-a-credentials-file).

---

## Step 2: Configure MCP servers

Edit `~/Library/Application Support/Claude/claude_desktop_config.json` on macOS, or `%APPDATA%\Claude\claude_desktop_config.json` on Windows. Point each server at the launcher:

```json
{
  "mcpServers": {
    "s1-secops-mcp": {
      "command": "/Users/you/.local/bin/s1-secops-mcp-launch.sh",
      "args": ["--image", "sentinelone/secops-mcps:1.5.3", "s1-secops-mcp"]
    },
    "purple-mcp": {
      "command": "/Users/you/.local/bin/s1-secops-mcp-launch.sh",
      "args": ["--image", "sentinelone/secops-mcps:1.5.3", "purple-mcp"]
    },
    "virustotal": {
      "command": "/Users/you/.local/bin/s1-secops-mcp-launch.sh",
      "args": ["--image", "sentinelone/secops-mcps:1.5.3", "virustotal-mcp"]
    }
  }
}
```

Launcher options (`--image`, `--profile`) go before the server name: everything after the server name is passed to the server inside the container, which rejects an unknown argument.

On Windows, use the PowerShell launcher (PowerShell parameters take one dash):

```json
"s1-secops-mcp": {
  "command": "powershell.exe",
  "args": ["-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
           "C:\\Users\\you\\bin\\s1-secops-mcp-launch.ps1",
           "-Image", "sentinelone/secops-mcps:1.5.3", "s1-secops-mcp"]
}
```

The launcher reads the keychain on the host and passes the values to the container over stdin, so they never appear in this file, in `docker inspect`, or in the process list. Do not add an `env` block with tokens and do not switch to `docker run -e`: both store secrets in plaintext. Background: [credentials.md → Docker](./credentials.md#docker-the-launcher-not--e).

Optional: to get `outputFile` results (bulk query exports, binary downloads, workflow ZIPs) somewhere you can open them, add `"env": {"S1_OUTPUT_DIR": "/Users/you/Documents/s1-output"}` to the `s1-secops-mcp` entry. That is a directory path, not a secret; the macOS/Linux launcher mounts it into the container at the same path, and the Windows launcher mounts it at `/output` (pass `outputFile` paths under `/output/` there).

**Notes:**

- purple-mcp reads the same `S1_CONSOLE_URL` and `S1_CONSOLE_API_TOKEN`; the image entrypoint maps them onto `PURPLEMCP_CONSOLE_BASE_URL` and `PURPLEMCP_CONSOLE_TOKEN`.
- purple-mcp also receives the stored `VIRUSTOTAL_API_KEY`, which the entrypoint maps to `PURPLEMCP_VT_API_KEY` for its threat intelligence tools. No separate setup: the one key you stored in Step 1 serves both the VirusTotal MCP and purple-mcp. Which server to use for which task: [mcp-tools.md → Threat intelligence: which server to use](./mcp-tools.md#threat-intelligence-which-server-to-use).
- Region URLs vary. Look up your region in the [SentinelOne Endpoint URLs by Region](https://community.sentinelone.com/s/article/000004961) article.
- The VirusTotal MCP shown is one example. Replace it with your organisation's approved threat intel MCP if different.
- Every install is pinned. There is no `:latest`, and the repository has immutable tags enabled, so `1.5.3` always means the same bytes.

**Restart Claude Desktop** after saving.

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
4. Optionally drop a copy of [`CLAUDE.md`](../CLAUDE.md) from this repo into the project folder. The image ships a default persona at `/etc/sentinelone/CLAUDE.md`, so this step is only needed when you want to customise it. To point the container at your own copy, set `S1_CLAUDE_MD_PATH` to its host path in the `s1-secops-mcp` entry's `env` block (the macOS/Linux and Windows launchers mount it read-only), see [docker.md → CLAUDE.md customization](./docker.md#claudemd-customization).
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
- On macOS, the MCP log (`~/Library/Logs/Claude/mcp-server-<name>.log`) does not show `/bin/sh: .../s1-secops-mcp-launch.sh: Operation not permitted`. If it does, the launcher is under `~/Documents`, `~/Desktop` or `~/Downloads`; copy it to `~/.local/bin/` (see [Prerequisites](#prerequisites)) and update `command` in the config
- The keychain holds the values: `s1-secops-mcp-launch.sh status` (or `s1-secops-mcp status`), which shows secrets as a length only
- The API token has the right scope (Viewer or higher for read; IR Team or higher for response actions)

Full troubleshooting flowchart and per-MCP log tailing: [docker.md → Troubleshooting](./docker.md#troubleshooting).

To confirm the active plugin version: `which version of s1-secops-skills is installed?`

---

## Upgrading

**MCP servers** (`s1-secops-mcp`, `purple-mcp`, `virustotal`): the config above pins `1.5.3`, so restarting Claude Desktop keeps that exact image. Upgrading means editing the `--image` tag in all three entries. To pre-pull a version before switching to it:

```bash
docker pull sentinelone/secops-mcps:1.5.3
```

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
