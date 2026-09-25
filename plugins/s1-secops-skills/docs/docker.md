# Docker reference

The **3-step Docker quick start** (pull the image, paste the config, install the plugin), plus a verify step, lives in the [README → Quick start (Docker)](../README.md#1-quick-start-docker). That is the path to follow for a normal install.

This page is the full Docker reference for everything beyond those three steps: prerequisites, the troubleshooting flowchart, hand-testing the container with credentials, overriding CLAUDE.md, upgrading, and building the image from source.

One Docker image bundles all three MCPs (`s1-secops-mcp`, `purple-mcp`, `virustotal-mcp`) so you only need Docker on the host: no Node, Python, or `uv`. It is the only supported install path, and it works on machines where IT policy blocks host-level package installs.

Image: `sentinelone/secops-mcps`
Tags: full semver only. `1.4.6` is current; `1.4.5` is the previous release. There is no `latest`, no rolling `1` or `1.4`, and no `sha-<short>`: the repository has immutable tags enabled, so a published tag can never be repointed at different bytes. Every install is therefore pinned and reproducible by construction, and an upgrade is something you do deliberately.

From `1.4.0` the image is built entirely from pinned git sources. Nothing in the build resolves a package from the npm registry, and `npm` and `npx` are not present in the image. This matters if you are reviewing the supply chain of what runs in your environment, or running builds somewhere the npm registry is unreachable. One registry dependency does remain: purple-mcp's Python packages still come from PyPI at build time.

**The image was renamed at 1.4.8.** It is now `sentinelone/secops-mcps`. The previous name, `sentinelone/secops-skills`, carries `1.4.5` and `1.4.6` and receives no further releases. Before that, releases went to `ghcr.io/pmoses-s1/s1-mcps`, which is being made private; those tags are gone and are not recoverable.

The new repository carries `1.4.8` only. Update any config referencing either older name to `sentinelone/secops-mcps:1.4.8`.

The image version is its own counter and does not encode the versions inside it: image `1.4.6` bundles s1-secops-mcp 1.3.9. From 1.3.4 onward a version tag strictly increases and is never republished, so a pin is stable. Tags at or below `1.3.3` were republished with different contents and do not reliably identify what is inside. To know what you have, ask the image:

```bash
docker run --rm sentinelone/secops-mcps:1.4.8 versions
```

- [Prerequisites](#prerequisites)
- [Troubleshooting](#troubleshooting)
- [CLAUDE.md customization](#claudemd-customization)
- [Upgrading](#upgrading)
- [Building from source](#building-from-source)

Credential keys and where to get each one: [credentials.md](./credentials.md).

---

## Shared credentials across the bundled servers

All three servers ship in the same image and run through the same entrypoint, so
the console URL and token only need to be supplied once. The entrypoint maps the
canonical names onto each server's own variables:

| You set | Mapped to | Used by |
|---|---|---|
| `S1_CONSOLE_URL` | `PURPLEMCP_CONSOLE_BASE_URL` | purple-mcp |
| `S1_CONSOLE_API_TOKEN` | `PURPLEMCP_CONSOLE_TOKEN` | purple-mcp |

A server-specific variable that is already set always wins, so existing
configurations keep working unchanged.

This means every server entry can pass the same `-e` flags:

```json
"s1-secops-mcp": {
  "command": "docker",
  "args": ["run", "-i", "--rm", "--pull=missing",
           "-e", "S1_CONSOLE_URL", "-e", "S1_CONSOLE_API_TOKEN", "-e", "S1_HEC_INGEST_URL", "-e", "S1_HEC_TOKEN",
           "sentinelone/secops-mcps:1.4.8", "s1-secops-mcp"],
  "env": {
    "S1_CONSOLE_URL":       "https://usea1-acme.sentinelone.net",
    "S1_CONSOLE_API_TOKEN": "eyJ...",
    "S1_HEC_INGEST_URL":    "https://ingest.us1.sentinelone.net",
    "S1_HEC_TOKEN":         "<SDL Log Write Key, optional; hec_ingest needs it>"
  }
},
"purple-mcp": {
  "command": "docker",
  "args": ["run", "-i", "--rm", "--pull=missing",
           "-e", "S1_CONSOLE_URL", "-e", "S1_CONSOLE_API_TOKEN",
           "sentinelone/secops-mcps:1.4.8", "purple-mcp"],
  "env": {
    "S1_CONSOLE_URL":       "https://usea1-acme.sentinelone.net",
    "S1_CONSOLE_API_TOKEN": "eyJ..."
  }
}
```

## Prerequisites

| Requirement | Check | Install |
|---|---|---|
| Docker (Desktop on macOS/Windows, Engine on Linux) | `docker --version` | [docker.com/get-started](https://www.docker.com/get-started/) |
| SentinelOne API token | Settings → Users → Service Users | [Community guide](https://community.sentinelone.com/s/article/000005291) |
| SDL API keys | Singularity Data Lake → API Keys | [Community guide](https://community.sentinelone.com/s/article/000006763) |
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
| `Unable to find image ... pulling from docker.io` | First-launch pull, normal, takes 30 to 90 s |
| `denied` or `manifest unknown` from docker.io | The repository is public and needs no login, so this is normally a typo in the image name or tag, or a proxy intercepting Docker Hub. The image was renamed at 1.4.8: `sentinelone/secops-mcps` carries `1.4.8`, and the old `sentinelone/secops-skills` carries `1.4.5` and `1.4.6`. Check with `docker manifest inspect sentinelone/secops-mcps:1.4.8`. |
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
  sentinelone/secops-mcps:1.4.8 s1-secops-mcp <<< '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"smoke","version":"0.1"}}}'
```

Expected: a single JSON line back on stdout with `serverInfo.name = "s1-secops-mcp-server"` and `version = "1.3.9"`, the bundled MCP version, not the `1.3.6` image tag. Stderr should show `Tools: 32 registered` and one of the `configured`/`NOT configured` summaries per API surface.

### 4. Force a fresh pull

If you suspect a corrupted local image:

```bash
docker rmi sentinelone/secops-mcps:1.4.8
docker pull sentinelone/secops-mcps:1.4.8
```

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
    "sentinelone/secops-mcps:1.4.8",
    "s1-secops-mcp"
  ],
  "env": { "...": "..." }
}
```

Only the `s1-secops-mcp` entry reads CLAUDE.md; you don't need the volume mount on the `purple-mcp` or `virustotal` entries.

---

## Upgrading

Upgrading is deliberate: edit the tag in `claude_desktop_config.json` and restart Claude Desktop.

The documented config pins `:1.4.6` with `--pull=missing`, so restarting does **not** move you to a newer image, by design. An immutable tag cannot change underneath you, which is what makes a pin forensically meaningful: the bytes you validated are the bytes you keep running. The trade is that nothing upgrades on its own, so watch the releases rather than expecting a restart to do it.

Replace the tag in all three MCP entries at once. They share one image, and leaving them on different tags is the one way to get the three servers out of lockstep.

To pre-pull the new version before editing the config:

```bash
docker pull sentinelone/secops-mcps:1.4.8
```

To prune old image layers after a few upgrades:

```bash
docker image prune -a --filter "until=168h"
```

---

## Building from source

For maintainers who want to rebuild the image locally:

```bash
git clone https://github.com/pmoses-s1/s1-secops-skills.git
cd s1-secops-skills

# Single-arch build for the host architecture
docker/build.sh

# Multi-arch build + push to Docker Hub (requires `docker login docker.io` first)
PUSH=true docker/build.sh
```

All version pins live in [`docker/build.sh`](../../../mcp/docker/build.sh) and the matching CI workflow `.github/workflows/docker-publish.yml` in the upstream `s1-secops-skills` repo. They are checked for sync at CI build time.

Maintainer reference (pinned versions, publishing, bumping a pin): [`docker/README.md`](../../../mcp/docker/README.md).
