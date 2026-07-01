# Installation and Upgrade Guide

Four steps from zero to a working PrincipalSOCAnalyst session: configure MCP servers, install the plugin, create the Cowork project, verify.

The MCP servers all run via package managers (`npx` and `uvx`). There is no git clone, no `npm install`, no absolute path to manage. New machine = paste the config, paste the tokens, restart Claude Desktop.

> **On a locked-down machine?** A Docker-based install path is also available: one image bundles all three MCPs, no host-level Node/Python/uv required. See [`docker.md`](./docker.md).

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
| Node.js 18+ | `node --version` | [nodejs.org](https://nodejs.org) |
| `uv` (for purple-mcp) | `uvx --version` | `curl -LsSf https://astral.sh/uv/install.sh \| sh`, then open a new terminal |
| SentinelOne API token | Settings → Users → Service Users | [Community guide](https://community.sentinelone.com/s/article/000005291) |
| SDL API keys | Singularity Data Lake → API Keys | [Community guide](https://community.sentinelone.com/s/article/000006763) |
| Regional endpoint URLs | `S1_CONSOLE_URL`, `SDL_XDR_URL`, `S1_HEC_INGEST_URL` | [SentinelOne Endpoint URLs by Region](https://community.sentinelone.com/s/article/000004961) |
| VirusTotal API key | [virustotal.com/gui/my-apikey](https://www.virustotal.com/gui/my-apikey) | Free tier is sufficient |

---

## Step 1: Configure MCP servers

Edit `~/Library/Application Support/Claude/claude_desktop_config.json` on macOS, or `%APPDATA%\Claude\claude_desktop_config.json` on Windows. Paste in the three MCP servers below and replace every placeholder with your real values.

All three servers run from public package registries: `s1-secops-mcp` and `@burtthecoder/mcp-virustotal` via `npx`, `purple-mcp` via `uvx`. First launch fetches and caches each one automatically. No prior install step.

```json
{
  "mcpServers": {
    "s1-secops-mcp": {
      "command": "npx",
      "args": ["-y", "@pmoses-s1/s1-secops-mcp"],
      "env": {
        "S1_CONSOLE_URL": "https://usea1-yourorg.sentinelone.net",
        "S1_CONSOLE_API_TOKEN": "eyJ...your-api-token...",
        "S1_HEC_INGEST_URL": "https://ingest.us1.sentinelone.net",
        "SDL_XDR_URL": "https://xdr.us1.sentinelone.net",
        "SDL_LOG_READ_KEY": "your-log-read-key",
        "SDL_CONFIG_WRITE_KEY": "your-config-write-key",
        "SDL_CONFIG_READ_KEY": "your-config-read-key"
      }
    },
    "purple-mcp": {
      "command": "uvx",
      "args": [
        "--from",
        "git+https://github.com/Sentinel-One/purple-mcp.git",
        "purple-mcp",
        "--mode",
        "stdio"
      ],
      "env": {
        "PURPLEMCP_CONSOLE_TOKEN": "eyJ...your-api-token...",
        "PURPLEMCP_CONSOLE_BASE_URL": "https://usea1-yourorg.sentinelone.net"
      }
    },
    "virustotal": {
      "command": "npx",
      "args": ["-y", "@burtthecoder/mcp-virustotal"],
      "env": {
        "VIRUSTOTAL_API_KEY": "your-virustotal-api-key"
      }
    }
  },
  "preferences": {
    "coworkScheduledTasksEnabled": true,
    "coworkWebSearchEnabled": true
  }
}
```

**Notes:**

- Both `S1_CONSOLE_API_TOKEN` and `PURPLEMCP_CONSOLE_TOKEN` are the same Management Console API token. Generate one under Settings → Users → Service Users.
- Region URLs vary. Look up your region in the [SentinelOne Endpoint URLs by Region](https://community.sentinelone.com/s/article/000004961) article.
- The VirusTotal MCP shown is one example. Replace it with your organisation's approved threat intel MCP if different.
- `npx -y` answers "yes" to the install prompt on first run, then caches. `uvx` does the same for the Python side.

**Restart Claude Desktop** after saving.

Full credential reference: [credentials.md](./credentials.md)

---

## Step 2: Install the plugin

The plugin bundles all seven skills in a single file. Download `s1-secops-skills-vX.Y.Z.plugin` from [`s1-secops-skills/dist/`](../s1-secops-skills/dist/).

In the Claude desktop app:

1. Open the **Cowork** tab
2. Click **Customize** in the left sidebar
3. Click **Browse plugins**
4. Upload the `.plugin` file

All seven skills install in one step. No individual skill configuration needed.

If the plugin upload fails, install individual `.skill` files from the same `dist/` folder. The seven are: `mgmt-console-api.skill`, `powerquery.skill`, `sdl-api.skill`, `sdl-dashboard.skill`, `sdl-log-parser.skill`, `hyperautomation.skill`, `sdl-solutions.skill`.

---

## Step 3: Create the Cowork project

> Create this project in Cowork, not Claude.ai chat. Open the Claude desktop app and navigate to Cowork from the sidebar.

1. Open **Cowork** and click **New Project**
2. Name it `PrincipalSOCAnalyst`
3. Click **Select Folder** and choose any folder on your machine (this becomes the project workspace)
4. Drop a copy of [`CLAUDE.md`](../CLAUDE.md) from this repo into the project folder. The `s1-secops-mcp` server reads it from the project folder at session start and exposes it as the `sentinelone://soc-context` resource.
5. Confirm `s1-secops-skills` appears under **Personal plugins**, and that `s1-secops-mcp`, `purple-mcp`, and your threat intel MCP appear under **MCP Servers**

If you'd rather keep CLAUDE.md outside the project folder, set `S1_CLAUDE_MD_PATH` in the `s1-secops-mcp` env block in Step 1 to its absolute path.

> **credentials.json:** With the npx config above, all credentials live in `claude_desktop_config.json` and you do not need a `credentials.json` in your project folder. The file is still supported as a fallback for direct skill usage. See [credentials.md](./credentials.md).

---

## Step 4: Verify the install

Open the **PrincipalSOCAnalyst** project and start a new session. Claude will automatically:

- Enumerate all live `dataSource.name` values in your SDL
- Pull open alerts in parallel

Run a smoke test to confirm everything is wired up:

```
smoke test s1 skills
```

Claude verifies connectivity to `s1-secops-mcp`, `purple-mcp`, and the threat intel MCP, confirms each skill is loaded, and reports any missing credentials or unreachable endpoints.

If anything is red, check:

- All three MCPs are listed and green under MCP Servers in the Cowork session panel
- The API token has the right scope (Viewer or higher for read; IR Team or higher for response actions)
- `SDL_XDR_URL` and the SDL keys match your region

To confirm the active plugin version: `which version of s1-secops-skills is installed?`

---

## Upgrading

**MCP servers** (`s1-secops-mcp`, `purple-mcp`, `virustotal`): nothing to do. `npx -y` and `uvx` re-resolve to the latest published version on each Claude Desktop launch. To force a refresh:

```bash
# npx-based
npx clear-npx-cache

# uvx-based
uvx cache clean purple-mcp
```

**Plugin**: download the new `.plugin` from [`s1-secops-skills/dist/`](../s1-secops-skills/dist/), open Cowork → Customize → Browse plugins, upload, click **Replace** when prompted.

**CLAUDE.md**: if you customised it, your project-folder copy stays as-is. To pick up upstream improvements, diff against the latest [`CLAUDE.md`](../CLAUDE.md) in this repo.

---

## Configuration reference

**Recommended:** credentials live in `claude_desktop_config.json` as env vars on each MCP server (Step 1). No file in the project folder.

**Backwards-compatible fallback** (for direct skill usage without `s1-secops-mcp`): place a `credentials.json` in your Cowork project folder. The plugin's SessionStart hook auto-discovers it.

```bash
# macOS / Linux ,  create credentials.json with the keys you need.
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

Every credential key, where to get it, the two token types, and the resolution order are documented in one canonical place: **[credentials.md](./credentials.md)**. The two keys you always need are `S1_CONSOLE_URL` and `S1_CONSOLE_API_TOKEN`; add the `SDL_*` keys for log ingest and parser/dashboard deployment, and `S1_CLAUDE_MD_PATH` to point at a custom CLAUDE.md.

---

## Building from source

Only needed when developing the MCP server or rebuilding the plugin. End users do not need this.

```bash
git clone https://github.com/Sentinel-One/ai-siem.git
cd ai-siem

# Run the MCP server from the local clone (replaces the npx command in Step 1)
node s1-secops-mcp/index.js

# Rebuild the plugin
cd s1-secops-skills && bash scripts/build.sh         # incremental
cd s1-secops-skills && bash scripts/build.sh --clean # clean
```

To point Claude Desktop at the local clone instead of the published npm package, replace the `s1-secops-mcp` block in Step 1 with:

```json
"s1-secops-mcp": {
  "command": "node",
  "args": ["/absolute/path/to/ai-siem/mcp/s1-secops-mcp/index.js"],
  "env": { "...": "..." }
}
```
