# Docker reference

The **3-step Docker quick start** (pull the image, paste the config, install the plugin, verify) lives in the [README → Quick start (Docker)](../README.md#1-quick-start-docker). That is the path to follow for a normal install.

This page is the full Docker reference for everything beyond those three steps: prerequisites, the troubleshooting flowchart, hand-testing the container with credentials, overriding CLAUDE.md, upgrading, trade-offs vs the npx path, and building the image from source.

One Docker image bundles all three MCPs (`s1-secops-mcp`, `purple-mcp`, `virustotal-mcp`) so you only need Docker on the host: no Node, Python, or `uv`. This is the recommended path for most users, and the only option on machines where IT policy blocks `npm install -g` or `pip install`.

Image: `ghcr.io/pmoses-s1/s1-mcps`
Tags: `latest` (newest published), `1` / `1.2` / `1.2.3` (pinned semver, current), `sha-<short>` (any commit). Pin an explicit version for reproducible, forensically consistent installs.

- [Prerequisites](#prerequisites)
- [Troubleshooting](#troubleshooting)
- [CLAUDE.md customization](#claudemd-customization)
- [Upgrading](#upgrading)
- [Trade-offs vs the npx path](#trade-offs-vs-the-npx-path)
- [Building from source](#building-from-source)

Credential keys and where to get each one: [credentials.md](./credentials.md).

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

The pull command, the full `claude_desktop_config.json` block, the plugin install, and the verify step are all in the [README Quick start (Docker)](../README.md#1-quick-start-docker).

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
| `Unable to find image ... pulling from ghcr.io` | First-launch pull, normal, takes 30 to 90 s |
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
  ghcr.io/pmoses-s1/s1-mcps:1.2.3 s1-secops-mcp <<< '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"smoke","version":"0.1"}}}'
```

Expected: a single JSON line back on stdout with `serverInfo.name = "sentinelone-mcp-server"`. Stderr should show `Tools: 26 registered` and one of the `configured`/`NOT configured` summaries per API surface.

For a less verbose env-source pattern, put the values in a `.env` file and pass it with `--env-file`:

```bash
docker run -i --rm --pull=missing --env-file ~/.config/sentinelone/s1-mcp.env \
  ghcr.io/pmoses-s1/s1-mcps:1.2.3 s1-secops-mcp <<< '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"smoke","version":"0.1"}}}'
```

The `.env` file is plain `KEY=value` per line. Keep its mode 0600 and out of any repo.

### 4. Force a fresh pull

If you suspect a corrupted local image:

```bash
docker rmi ghcr.io/pmoses-s1/s1-mcps:1.2.3
docker pull ghcr.io/pmoses-s1/s1-mcps:1.2.3
```

### 5. Roll back to the npx path

If the Docker path is misbehaving and you want to get working again immediately, switch that MCP entry to the [npx/uvx config](./installation.md#step-1-configure-mcp-servers) and restart Claude Desktop. If a backup of the previous config was written before the swap, restore it:

```bash
LATEST=$(ls -1t ~/Library/Application\ Support/Claude/claude_desktop_config.json.pre-docker-bak-* 2>/dev/null | head -1)
[ -n "$LATEST" ] && cp "$LATEST" ~/Library/Application\ Support/Claude/claude_desktop_config.json
```

Restart Claude Desktop. The npx-based config takes over, no other changes needed.

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
    "ghcr.io/pmoses-s1/s1-mcps:1.2.3",
    "s1-secops-mcp"
  ],
  "env": { "...": "..." }
}
```

Only the `s1-secops-mcp` entry reads CLAUDE.md; you don't need the volume mount on the `purple-mcp` or `virustotal` entries.

---

## Upgrading

Bump the tag in your `claude_desktop_config.json` (e.g. `:1.2.2` to `:1.2.3`), save, and restart Claude Desktop. The new image is pulled on first launch (`--pull=missing` ensures this).

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

| Concern | npx/uvx | Docker (this path) |
|---|---|---|
| Host runtime deps | Node 18+, `uv`, `npm` | Docker only |
| First-launch latency | ~1-2 s npm fetch + cache | ~1-2 s container start |
| Per-session overhead | ~50 ms | ~200-500 ms |
| Cross-host portability | Same Node version assumed | Identical bytes everywhere |
| Auto-updates | `npx -y` re-resolves on each launch | Pinned to tag; explicit `docker pull` |
| Apple Silicon | Native | Native (multi-arch image) |
| Image size on disk | ~80 MB cache total | ~600 MB unpacked |
| Logs | `~/Library/Logs/Claude/mcp-server-*.log` | Same (Claude Desktop captures container stderr) |
| Token handling | Env vars in `claude_desktop_config.json` | Same (env vars passed to `docker run`) |

The Docker path is the default recommendation because it needs nothing on the host but Docker and version-locks all three MCPs together. The [npx/uvx path](./installation.md) is lighter on disk and slightly faster per session when Node 18+ and `uv` are installable.

---

## Building from source

For maintainers who want to rebuild the image locally:

```bash
git clone https://github.com/Sentinel-One/ai-siem.git
cd ai-siem

# Single-arch build for the host architecture
mcp/docker/build.sh

# Multi-arch build + push to ghcr.io (requires `docker login ghcr.io` first)
PUSH=true mcp/docker/build.sh
```

All version pins live in [`mcp/docker/build.sh`](../../../mcp/docker/build.sh); keep them in sync with `mcp/docker/README.md`.

Maintainer reference (pinned versions, publishing, bumping a pin): [`mcp/docker/README.md`](../../../mcp/docker/README.md).
