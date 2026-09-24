# Installation and Upgrade Guide

Four steps from zero to a working PrincipalSOCAnalyst session: configure MCP servers, install the plugin, create the Cowork project, verify.

All three MCP servers (`s1-secops-mcp`, `purple-mcp`, `virustotal-mcp`) ship in one Docker image, `sentinelone/secops-skills`, version-locked together. Docker is the only thing you need on the host. There is no git clone and no absolute path to manage. New machine: paste the config, paste the tokens, restart Claude Desktop.

The same three steps in condensed form are in the [README Quick start (Docker)](../README.md#1-quick-start-docker). The full Docker reference (tags, troubleshooting flowchart, CLAUDE.md override, building from source) is [`docker.md`](./docker.md).

- [Prerequisites](#prerequisites)
- [Step 1: Configure MCP servers](#step-1-configure-mcp-servers)
- [Step 2: Install the plugin](#step-2-install-the-plugin)
- [Step 3: Create the Cowork project](#step-3-create-the-cowork-project)
- [Step 4: Verify the install](#step-4-verify-the-install)
- [Upgrading](#upgrading)
- [Configuration reference](#configuration-reference)
- [Building from source](#building-from-source)

---

## Prerequisites

| Requirement | Check | Install |
|---|---|---|
| Docker (Desktop on macOS/Windows, Engine on Linux), running | `docker --version` | [docker.com/get-started](https://www.docker.com/get-started/) |
| SentinelOne API token | Settings → Users → Service Users | [Community guide](https://community.sentinelone.com/s/article/000005291) |
| SDL API keys | Singularity Data Lake → API Keys | [Community guide](https://community.sentinelone.com/s/article/000006763) |
| VirusTotal API key | [virustotal.com/gui/my-apikey](https://www.virustotal.com/gui/my-apikey) | Free tier is sufficient |

Nothing else is needed on the host: no Node, no Python, no `uv`. The image is multi-arch (`linux/amd64` + `linux/arm64`), so Apple Silicon runs natively without qemu.

Pull the image once before you start:

```bash
docker pull sentinelone/secops-skills:1.4.6
```

---

## Step 1: Configure MCP servers

Edit `~/Library/Application Support/Claude/claude_desktop_config.json` on macOS, or `%APPDATA%\Claude\claude_desktop_config.json` on Windows. Paste in the three MCP servers below and replace every placeholder with your real values.

All three entries run the same image with a different dispatcher argument. `--pull=missing` fetches the image only if it is not already present locally. Because `1.4.6` is an immutable tag it cannot change underneath you, so there is nothing to re-check on later launches.

```json
{
  "mcpServers": {
    "s1-secops-mcp": {
      "command": "docker",
      "args": ["run", "-i", "--rm", "--pull=missing",
               "-e", "S1_CONSOLE_URL", "-e", "S1_CONSOLE_API_TOKEN", "-e", "S1_HEC_INGEST_URL", "-e", "S1_HEC_TOKEN",
               "sentinelone/secops-skills:1.4.6", "s1-secops-mcp"],
      "env": {
        "S1_CONSOLE_URL":       "https://usea1-yourorg.sentinelone.net",
        "S1_CONSOLE_API_TOKEN": "eyJ...your-api-token...",
        "S1_HEC_INGEST_URL":    "https://ingest.us1.sentinelone.net",
        "S1_HEC_TOKEN":         "<SDL Log Write Key, optional; hec_ingest needs it>"
      }
    },
    "purple-mcp": {
      "command": "docker",
      "args": ["run", "-i", "--rm", "--pull=missing",
               "-e", "S1_CONSOLE_URL", "-e", "S1_CONSOLE_API_TOKEN",
               "sentinelone/secops-skills:1.4.6", "purple-mcp"],
      "env": {
        "S1_CONSOLE_URL":       "https://usea1-yourorg.sentinelone.net",
        "S1_CONSOLE_API_TOKEN": "eyJ...your-api-token..."
      }
    },
    "virustotal": {
      "command": "docker",
      "args": ["run", "-i", "--rm", "--pull=missing",
               "-e", "VIRUSTOTAL_API_KEY",
               "sentinelone/secops-skills:1.4.6", "virustotal-mcp"],
      "env": {
        "VIRUSTOTAL_API_KEY": "your-virustotal-key"
      }
    }
  }
}
```

Only three variable names exist. purple-mcp and virustotal use the same
canonical names as `s1-secops-mcp`, because the image entrypoint maps them onto
each server's own variables:

| You set | Derived for |
|---|---|
| `S1_CONSOLE_URL` | `PURPLEMCP_CONSOLE_BASE_URL` |
| `S1_CONSOLE_API_TOKEN` | `PURPLEMCP_CONSOLE_TOKEN` |

A server-specific variable that is already set always wins, so a configuration
that names `PURPLEMCP_*` explicitly keeps working.

**Notes:**

- Both `S1_CONSOLE_API_TOKEN` and `PURPLEMCP_CONSOLE_TOKEN` are the same Management Console API token. Generate one under Settings → Users → Service Users.
- Region URLs vary. Look up your region in the [SentinelOne Endpoint URLs by Region](https://community.sentinelone.com/s/article/000004961) article.
- The VirusTotal MCP shown is one example. Replace it with your organisation's approved threat intel MCP if different.
- Every install is pinned by default. There is no `:latest` to drift from: the tag was deleted and the repository has immutable tags enabled, so `1.4.6` always means the same bytes.

**Restart Claude Desktop** after saving.

Full credential reference: [credentials.md](./credentials.md)

---

## Step 2: Install the plugin

The plugin bundles all eight skills in a single file. Download `s1-secops-skills-vX.Y.Z.plugin` from [`s1-secops-skills-plugin/dist/`](../dist/).

In the Claude desktop app:

1. Open the **Cowork** tab
2. Click **Customize** in the left sidebar
3. Click **Browse plugins**
4. Upload the `.plugin` file

All eight skills install in one step. No individual skill configuration needed.

If the plugin upload fails, install individual `.skill` files from the same `dist/` folder. The eight are: `mgmt-console-api.skill`, `powerquery.skill`, `sdl-api.skill`, `sdl-dashboard.skill`, `sdl-log-parser.skill`, `hyperautomation.skill`, `sdl-solutions.skill`, `soc-investigator.skill`.

---

## Step 3: Create the Cowork project

> Create this project in Cowork, not Claude.ai chat. Open the Claude desktop app and navigate to Cowork from the sidebar.

1. Open **Cowork** and click **New Project**
2. Name it `PrincipalSOCAnalyst`
3. Click **Select Folder** and choose any folder on your machine (this becomes the project workspace)
4. Optionally drop a copy of [`CLAUDE.md`](../CLAUDE.md) from this repo into the project folder. The image ships a default persona at `/etc/sentinelone/CLAUDE.md`, so this step is only needed when you want to customise it. To point the container at your own copy, mount the folder read-only and set `S1_CLAUDE_MD_PATH`, see [docker.md → CLAUDE.md customization](./docker.md#claudemd-customization).
5. Confirm `s1-secops-skills` appears under **Personal plugins**, and that `s1-secops-mcp`, `purple-mcp`, and your threat intel MCP appear under **MCP Servers**

> **credentials.json:** with the config above, all credentials live in `claude_desktop_config.json` and you do not need a `credentials.json` in your project folder. The file is still supported as a fallback for direct skill usage. See [credentials.md](./credentials.md).

---

## Step 4: Verify the install

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
docker run --rm sentinelone/secops-skills:1.4.6 versions   # what is inside the image
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"smoke","version":"0.1"}}}' \
  | docker run -i --rm sentinelone/secops-skills:1.4.6 s1-secops-mcp
```

The second command returns one JSON line with `serverInfo.name = "s1-secops-mcp-server"`, and stderr shows `Tools: 32 registered`. The `version` it reports is the bundled MCP's own version, not the image tag.

If anything is red, check:

- All three MCPs are listed and green under MCP Servers in the Cowork session panel
- Docker is running: `docker info | head -3`
- The API token has the right scope (Viewer or higher for read; IR Team or higher for response actions)

Full troubleshooting flowchart and per-MCP log tailing: [docker.md → Troubleshooting](./docker.md#troubleshooting).

To confirm the active plugin version: `which version of s1-secops-skills is installed?`

---

## Upgrading

**MCP servers** (`s1-secops-mcp`, `purple-mcp`, `virustotal`): the config above pins `:1.4.6`, so restarting Claude Desktop keeps that exact image. Upgrading means editing the tag in all three entries. To pre-pull a version before switching to it:

```bash
docker pull sentinelone/secops-skills:1.4.6
```

If you pinned a version tag, bump it to the current release (`1.4.5`) and restart Claude Desktop.

**Plugin**: download the new `.plugin` from [`s1-secops-skills-plugin/dist/`](../dist/), open Cowork → Customize → Browse plugins, upload, click **Replace** when prompted.

**CLAUDE.md**: if you customised it, your project-folder copy stays as-is. To pick up upstream improvements, diff against the latest [`CLAUDE.md`](../CLAUDE.md) in this repo.

Step-by-step upgrade instructions, including what to delete from an older config: [upgrading.md](./upgrading.md).

---

## Configuration reference

**Recommended:** credentials live in `claude_desktop_config.json` as env vars on each MCP server (Step 1). No file in the project folder.

**Backwards-compatible fallback** (for direct skill usage without `s1-secops-mcp`): place a `credentials.json` in your Cowork project folder. The plugin's SessionStart hook auto-discovers it.

```bash
# macOS / Linux: create credentials.json with the keys you need.
# Full key list + resolution order: docs/credentials.md
cat > ~/Documents/Claude/Projects/PrincipalSOCAnalyst/credentials.json <<'JSON'
{
  "S1_CONSOLE_URL": "https://<your-tenant>.sentinelone.net",
  "S1_CONSOLE_API_TOKEN": "<your-mgmt-console-api-token>"
}
JSON
${EDITOR:-nano} ~/Documents/Claude/Projects/PrincipalSOCAnalyst/credentials.json
```

Resolution order (highest priority wins):

1. Environment variables in `claude_desktop_config.json` via `s1-secops-mcp` (recommended)
2. `<project folder>/credentials.json` (backwards-compatible fallback)
3. `~/.config/sentinelone/credentials.json` (terminal fallback)

Every credential key, where to get it, the two token types, and the resolution order are documented in one canonical place: **[credentials.md](./credentials.md)**. The two keys you always need are `S1_CONSOLE_URL` and `S1_CONSOLE_API_TOKEN`, which between them authorise parser and dashboard deployment and every other SDL operation; add `S1_HEC_INGEST_URL` for log and alert ingest, and `S1_CLAUDE_MD_PATH` to point at a custom CLAUDE.md.

---

## Building from source

Only needed when developing the MCP server or rebuilding the plugin. End users do not need this.

```bash
git clone https://github.com/pmoses-s1/s1-secops-skills.git
cd s1-secops-skills

# Rebuild the image from pinned sources (single-arch, host architecture)
docker/build.sh

# Rebuild the plugin
cd s1-secops-skills-plugin && bash scripts/build.sh         # incremental
cd s1-secops-skills-plugin && bash scripts/build.sh --clean # clean
```

Version pins, multi-arch builds, and publishing are covered in [docker.md → Building from source](./docker.md#building-from-source).

To point Claude Desktop at a locally built image instead of the published one, change the image reference in the Step 1 config to the tag you built, for example `secops-skills:dev`.
