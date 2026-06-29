# Docker install (alternate)

A single Docker image bundling all three MCPs (`s1-secops-mcp`, `purple-mcp`, `virustotal-mcp`). Use this path on machines where you can install Docker but cannot install Node, Python, or `uv` directly.

The recommended path is still [npx/uvx](./installation.md). Pick this one when:

- IT policy blocks `npm install -g`, `pip install`, or arbitrary CLI binaries
- You want the three MCPs version-locked together at a known good combo
- You prefer one tool (`docker pull`) for upgrades

Image: `ghcr.io/pmoses-s1/s1-mcps`
Tags: `latest` (main), `1` / `1.2` / `1.2.2` (pinned semver, current), `sha-<short>` (any commit)

- [Prerequisites](#prerequisites)
- [Step 1: Pull the image](#step-1-pull-the-image)
- [Step 2: Configure MCP servers](#step-2-configure-mcp-servers)
- [Step 3: Install the plugin](#step-3-install-the-plugin)
- [Step 4: Create the Cowork project](#step-4-create-the-cowork-project)
- [Step 5: Verify the install](#step-5-verify-the-install)
- [Troubleshooting](#troubleshooting)
- [CLAUDE.md customization](#claudemd-customization)
- [Upgrading](#upgrading)
- [Trade-offs vs the npx path](#trade-offs-vs-the-npx-path)
- [Building from source](#building-from-source)

---

## Prerequisites

| Requirement | Check | Install |
|---|---|---|
| Docker (Desktop on macOS/Windows, Engine on Linux) | `docker --version` | [docker.com/get-started](https://www.docker.com/get-started/) |
| SentinelOne API token | Settings → Users → Service Users | [Community guide](https://community.sentinelone.com/s/article/000005291) |
| SDL API keys | Singularity Data Lake → API Keys | [Community guide](https://community.sentinelone.com/s/article/000006763) |
| Regional endpoint URLs | `S1_CONSOLE_URL`, `SDL_XDR_URL`, `S1_HEC_INGEST_URL` | [Endpoint URLs by Region](https://community.sentinelone.com/s/article/000004961) |
| VirusTotal API key | [virustotal.com/gui/my-apikey](https://www.virustotal.com/gui/my-apikey) | Free tier is sufficient |

Apple Silicon and Intel are both supported; the image is multi-arch (`linux/amd64` + `linux/arm64`) so qemu emulation is never used.

---

## Step 1: Pull the image

```bash
docker pull ghcr.io/pmoses-s1/s1-mcps:1.2.2
```

Pin to a specific tag (`:1.2.2` or `:1`). Pulling `:latest` works but you'll silently inherit upgrades whenever you re-pull, which makes incident triage harder. About 250 MB compressed, ~600 MB unpacked.

Verify the dispatcher works:

```bash
docker run --rm ghcr.io/pmoses-s1/s1-mcps:1.2.2 help
```

---

## Step 2: Configure MCP servers

Edit `~/Library/Application Support/Claude/claude_desktop_config.json` on macOS, or `%APPDATA%\Claude\claude_desktop_config.json` on Windows. Three entries (one per MCP) all reference the same image. Replace every placeholder.

```json
{
  "mcpServers": {
    "s1-secops-mcp": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm", "--pull=missing",
        "-e", "S1_CONSOLE_URL",
        "-e", "S1_CONSOLE_API_TOKEN",
        "-e", "S1_HEC_INGEST_URL",
        "-e", "SDL_XDR_URL",
        "-e", "SDL_LOG_READ_KEY",
        "-e", "SDL_CONFIG_WRITE_KEY",
        "-e", "SDL_CONFIG_READ_KEY",
        "ghcr.io/pmoses-s1/s1-mcps:1.2.2",
        "s1-secops-mcp"
      ],
      "env": {
        "S1_CONSOLE_URL":       "https://usea1-yourorg.sentinelone.net",
        "S1_CONSOLE_API_TOKEN": "eyJ...your-api-token...",
        "S1_HEC_INGEST_URL":    "https://ingest.us1.sentinelone.net",
        "SDL_XDR_URL":          "https://xdr.us1.sentinelone.net",
        "SDL_LOG_READ_KEY":     "your-log-read-key",
        "SDL_CONFIG_WRITE_KEY": "your-config-write-key",
        "SDL_CONFIG_READ_KEY":  "your-config-read-key"
      }
    },
    "purple-mcp": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm", "--pull=missing",
        "-e", "PURPLEMCP_CONSOLE_TOKEN",
        "-e", "PURPLEMCP_CONSOLE_BASE_URL",
        "ghcr.io/pmoses-s1/s1-mcps:1.2.2",
        "purple-mcp"
      ],
      "env": {
        "PURPLEMCP_CONSOLE_TOKEN":    "eyJ...your-api-token...",
        "PURPLEMCP_CONSOLE_BASE_URL": "https://usea1-yourorg.sentinelone.net"
      }
    },
    "virustotal": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm", "--pull=missing",
        "-e", "VIRUSTOTAL_API_KEY",
        "ghcr.io/pmoses-s1/s1-mcps:1.2.2",
        "virustotal-mcp"
      ],
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

- `-i` is required so Claude Desktop can speak JSON-RPC over stdin.
- `--rm` cleans up the container when the session ends; without it stopped containers accumulate.
- `--pull=missing` makes the first launch pull, subsequent launches skip the registry. Use `--pull=always` if you want to chase `:latest`.
- The `-e VAR` form (no value) tells Docker to inherit the env var from the parent process; the value comes from the `env` block. This matches how the npx config passes secrets.
- Both `S1_CONSOLE_API_TOKEN` and `PURPLEMCP_CONSOLE_TOKEN` are the same Management Console API token.

**Restart Claude Desktop** after saving.

---

## Step 3: Install the plugin

Same as the npx path: download `s1-secops-skills-vX.Y.Z.plugin` from [`s1-secops-skills/dist/`](../s1-secops-skills/dist/) and upload via Cowork → Customize → Browse plugins. Full instructions: [installation.md#step-2-install-the-plugin](./installation.md#step-2-install-the-plugin).

---

## Step 4: Create the Cowork project

Create a Cowork project named `PrincipalSOCAnalyst`, select a folder, and (optionally) drop your customised CLAUDE.md into the folder. The image ships a default CLAUDE.md so this step is optional for the Docker path. See [CLAUDE.md customization](#claudemd-customization) below if you want to override.

---

## Step 5: Verify the install

Open the **PrincipalSOCAnalyst** project and run:

```
smoke test s1 skills
```

Claude verifies connectivity to all three Docker-backed MCPs, confirms each skill is loaded, and reports any missing credentials or unreachable endpoints.

To check the image you have running:

```bash
docker run --rm ghcr.io/pmoses-s1/s1-mcps:1.2.2 help
docker image inspect ghcr.io/pmoses-s1/s1-mcps:1.2.2 \
  --format '{{index .Config.Labels "org.opencontainers.image.version"}}'
```

---

## Troubleshooting

If a server shows red in Cowork → MCP Servers, work through these in order.

### 1. Confirm Docker Desktop is actually running

```bash
docker info | head -3
```

Expected: `Server Version: ...`. If you see `Cannot connect to the Docker daemon`, start Docker Desktop, wait until the whale icon stops animating, and restart Claude Desktop.

### 2. Tail the per-MCP log files

Claude Desktop writes one log file per MCP server. Watch them while you start a new chat:

```bash
tail -F ~/Library/Logs/Claude/mcp-server-s1-secops-mcp.log
tail -F ~/Library/Logs/Claude/mcp-server-purple-mcp.log
tail -F ~/Library/Logs/Claude/mcp-server-virustotal.log
```

Common signatures:

| Log line | Meaning |
|---|---|
| `Cannot connect to the Docker daemon` | Docker Desktop is not running, see step 1 |
| `Unable to find image ... pulling from ghcr.io` | First-launch pull, normal, takes 30–90 s |
| `denied: permission_denied` from ghcr.io | Image is private or your network blocks ghcr.io. Run `docker login ghcr.io` if you have a token, or check VPN/proxy. |
| `VIRUSTOTAL_API_KEY environment variable is required` | The env value did not propagate. Re-check the `env` block in `claude_desktop_config.json` and that the `-e VAR` arg matches the key name. |
| `pydantic_core.ValidationError ... PURPLEMCP_*` | Same root cause for purple-mcp. |
| `S1 Mgmt API: NOT configured` | s1-secops-mcp boots but no console token reached it; check `S1_CONSOLE_URL` + `S1_CONSOLE_API_TOKEN` in the config. |

### 3. Run the MCP container by hand

This bypasses Claude Desktop entirely and confirms the image and credentials work end-to-end. Pass the env vars directly so the test is hermetic:

```bash
# Replace placeholders with your real values; this is a one-off test, NOT something to commit
docker run -i --rm --pull=missing \
  -e S1_CONSOLE_URL='https://usea1-yourorg.sentinelone.net' \
  -e S1_CONSOLE_API_TOKEN='eyJ...' \
  -e SDL_XDR_URL='https://xdr.us1.sentinelone.net' \
  -e SDL_LOG_READ_KEY='...' \
  -e SDL_CONFIG_READ_KEY='...' \
  ghcr.io/pmoses-s1/s1-mcps:1.2.2 s1-secops-mcp <<< '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"smoke","version":"0.1"}}}'
```

Expected: a single JSON line back on stdout with `serverInfo.name = "s1-secops-mcp-server"`. Stderr should show `Tools: 26 registered` and one of the `configured`/`NOT configured` summaries per API surface.

For a less verbose env-source pattern, put the values in a `.env` file and pass it with `--env-file`:

```bash
docker run -i --rm --pull=missing --env-file ~/.config/sentinelone/s1-mcp.env \
  ghcr.io/pmoses-s1/s1-mcps:1.2.2 s1-secops-mcp <<< '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"smoke","version":"0.1"}}}'
```

The `.env` file is plain `KEY=value` per line. Keep its mode 0600 and out of any repo.

### 4. Force a fresh pull

If you suspect a corrupted local image:

```bash
docker rmi ghcr.io/pmoses-s1/s1-mcps:1.2.2
docker pull ghcr.io/pmoses-s1/s1-mcps:1.2.2
```

### 5. Roll back to the npx path

If the Docker path is misbehaving and you want to get working again immediately, restore the npx config from the backup that was written before the swap:

```bash
ls -1t ~/Library/Application\ Support/Claude/claude_desktop_config.json.pre-docker-bak-* | head -1
# Then, copying the most recent backup back over the live config:
LATEST=$(ls -1t ~/Library/Application\ Support/Claude/claude_desktop_config.json.pre-docker-bak-* | head -1)
cp "$LATEST" ~/Library/Application\ Support/Claude/claude_desktop_config.json
```

Restart Claude Desktop. The npx-based config from before the swap takes over, no other changes needed.

---

## CLAUDE.md customization

The image bundles a default CLAUDE.md at `/etc/sentinelone/CLAUDE.md`. Most users do not need to override it.

To use your own copy, mount your Cowork project folder read-only and point the env var at it:

```json
"s1-secops-mcp": {
  "command": "docker",
  "args": [
    "run", "-i", "--rm", "--pull=missing",
    "-v", "/Users/yourname/Documents/Claude/Projects/PrincipalSOCAnalyst:/workspace:ro",
    "-e", "S1_CLAUDE_MD_PATH=/workspace/CLAUDE.md",
    "-e", "S1_CONSOLE_URL", "-e", "S1_CONSOLE_API_TOKEN",
    "-e", "S1_HEC_INGEST_URL", "-e", "SDL_XDR_URL",
    "-e", "SDL_LOG_READ_KEY",
    "-e", "SDL_CONFIG_WRITE_KEY", "-e", "SDL_CONFIG_READ_KEY",
    "ghcr.io/pmoses-s1/s1-mcps:1.2.2",
    "s1-secops-mcp"
  ],
  "env": { "...": "..." }
}
```

Only the `s1-secops-mcp` entry reads CLAUDE.md; you don't need the volume mount on the `purple-mcp` or `virustotal` entries.

---

## Upgrading

Bump the tag in your `claude_desktop_config.json` from `:1.2.2` to the new version, save, and restart Claude Desktop. The new image is pulled on first launch (`--pull=missing` ensures this).

To force a fresh pull mid-tag (e.g. `:latest` moved):

```bash
docker pull ghcr.io/pmoses-s1/s1-mcps:latest
```

To prune old image layers after a few upgrades:

```bash
docker image prune -a --filter "until=168h"
```

---

## Trade-offs vs the npx path

| Concern | npx/uvx (default) | Docker (this path) |
|---|---|---|
| Host runtime deps | Node 18+, `uv`, `npm` | Docker only |
| First-launch latency | ~1–2 s npm fetch + cache | ~1–2 s container start |
| Per-session overhead | ~50 ms | ~200–500 ms |
| Cross-host portability | Same Node version assumed | Identical bytes everywhere |
| Auto-updates | `npx -y` re-resolves on each launch | Pinned to tag; explicit `docker pull` |
| Apple Silicon | Native | Native (multi-arch image) |
| Image size on disk | ~80 MB cache total | ~600 MB unpacked |
| Logs | `~/Library/Logs/Claude/mcp-server-*.log` | Same (Claude Desktop captures container stderr) |
| Token handling | Env vars in `claude_desktop_config.json` | Same (env vars passed to `docker run`) |

If you have a choice and IT policy permits, the npx path is lighter. The Docker path is for when you don't have that choice, or when you want all three MCPs version-locked.

---

## Building from source

For maintainers who want to rebuild the image locally:

```bash
git clone https://github.com/Sentinel-One/ai-siem.git
cd ai-siem

# Single-arch build for the host architecture
docker/build.sh

# Multi-arch build + push to ghcr.io (requires `docker login ghcr.io` first)
PUSH=true docker/build.sh
```

All version pins live in [`docker/build.sh`](../../../mcp/docker/build.sh) and the matching CI workflow [`.github/workflows/main.yml`](../../../.github/workflows/main.yml). They are checked for sync at CI build time.

Maintainer reference: [`docker/README.md`](../../../mcp/docker/README.md).
