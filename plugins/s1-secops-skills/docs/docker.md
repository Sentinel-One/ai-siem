# Docker reference

The **Docker quick start** (store credentials, pull the image, point the config at the launcher, install the plugin), plus a verify step, lives in the [README → Quick start (Docker)](../README.md#1-quick-start-docker). That is the path to follow for a normal install.

This page is the full Docker reference for everything beyond those steps: the launcher, prerequisites, the troubleshooting flowchart, hand-testing the container, overriding CLAUDE.md, upgrading, and building the image from source.

One Docker image bundles all three MCPs (`s1-secops-mcp`, `purple-mcp`, `virustotal-mcp`) so you only need Docker and the launcher script on the host: no Node, Python, or `uv`. It works on machines where IT policy blocks host-level package installs.

Image: `sentinelone/secops-mcps`
Tags: full semver only. `1.5.3` is the current tag; `1.5.2`, `1.5.1`, `1.5.0` and `1.4.10` stay published as earlier ones. There is no `latest`, no rolling `1` or `1.4`, and no `sha-<short>`: the repository has immutable tags enabled, so a published tag can never be repointed at different bytes. Every install is therefore pinned and reproducible by construction, and an upgrade is something you do deliberately.

From `1.4.0` the image is built entirely from pinned git sources. Nothing in the build resolves a package from the npm registry, and `npm` and `npx` are not present in the image. This matters if you are reviewing the supply chain of what runs in your environment, or running builds somewhere the npm registry is unreachable. One registry dependency does remain: purple-mcp's Python packages still come from PyPI at build time.

The image version is its own counter and does not encode the versions inside it: image `1.5.3` bundles s1-secops-mcp 1.5.3. From 1.3.4 onward a version tag strictly increases and is never republished, so a pin is stable. Tags at or below `1.3.3` were republished with different contents and do not reliably identify what is inside. To know what you have, ask the image:

```bash
docker run --rm sentinelone/secops-mcps:1.5.3 versions
```

- [Secrets: the launcher, never `-e`](#secrets-the-launcher-never--e)
- [Prerequisites](#prerequisites)
- [Troubleshooting](#troubleshooting)
- [CLAUDE.md customization](#claudemd-customization)
- [Upgrading](#upgrading)
- [Building from source](#building-from-source)

Credential values, the keychain model and its limits: [credentials.md](./credentials.md).

---

## Secrets: the launcher, never `-e`

Values passed to `docker run` with `-e NAME=value`, or with `-e NAME` from an MCP client `env` block, are stored in the container's configuration: anyone who can reach the Docker daemon sees them with `docker inspect`, and the client config file holds them in plaintext. From 1.5.0 the documented configs do neither.

The host launcher reads each value from the OS keychain (service `sentinelone-mcp`, account `<profile>:<NAME>`) and writes them to the container's stdin; the entrypoint reads them when `S1_SECRETS_STDIN=1`, before it starts the MCP server. Nothing secret appears in the client config, `docker inspect`, or the host process list.

| Host | Launcher |
|---|---|
| macOS, Linux | [`mcp/docker/s1-secops-mcp-launch.sh`](../../../mcp/docker/s1-secops-mcp-launch.sh) |
| Windows | [`mcp/docker/s1-secops-mcp-launch.ps1`](../../../mcp/docker/s1-secops-mcp-launch.ps1) |

Usage:

```bash
s1-secops-mcp-launch.sh [--image IMG] [--profile P] <server> [server args...]   # server: s1-secops-mcp | purple-mcp | virustotal-mcp
s1-secops-mcp-launch.sh [--profile P] setup     # store values with security (macOS) or secret-tool (Linux), no echo
s1-secops-mcp-launch.sh [--profile P] status    # which values are stored (secrets shown as a length only)
s1-secops-mcp-launch.sh versions                # docker run --rm IMG versions
s1-secops-mcp-launch.sh --help
```

Install the macOS/Linux launcher to `~/.local/bin/` from the repo root:

```bash
mkdir -p ~/.local/bin && cp -X mcp/docker/s1-secops-mcp-launch.sh ~/.local/bin/ && chmod 755 ~/.local/bin/s1-secops-mcp-launch.sh
```

On macOS, do not run it from `~/Documents`, `~/Desktop` or `~/Downloads`, which is where a repo clone or a browser download usually lands. macOS privacy protection blocks Claude Desktop's `/bin/sh` from executing a script stored in those folders, and the MCP log shows `/bin/sh: .../s1-secops-mcp-launch.sh: Operation not permitted`. `cp -X` drops extended attributes such as the download quarantine flag.

Launcher options go **before** the server name; everything after the server name is passed to the server inside the container. Environment: `S1_MCP_IMAGE` (default image, `sentinelone/secops-mcps:1.5.3`), `S1_PROFILE` (keychain profile, default `default`), `S1_OUTPUT_DIR` (host directory for `outputFile`), `S1_CLAUDE_MD_PATH` (host CLAUDE.md, mounted read-only), `S1_KEYCHAIN_TIMEOUT` (keychain call timeout in **seconds**, default 15). The native Node server and the Python clients read `S1_KEYCHAIN_TIMEOUT_MS` (milliseconds, default 15000) instead; the launcher does not read the `_MS` name. The Windows launcher takes `-Image` and `-Profile`, reads `S1_MCP_IMAGE`, `S1_PROFILE`, `S1_OUTPUT_DIR` and `S1_CLAUDE_MD_PATH`, and supports `setup`, `status`, `versions`, `help` and the three server names. It has no keychain timeout: Credential Manager reads do not wait on a prompt.

Claude Desktop config:

```json
{
  "mcpServers": {
    "s1-secops-mcp":  { "command": "/Users/you/.local/bin/s1-secops-mcp-launch.sh", "args": ["s1-secops-mcp"] },
    "purple-mcp":     { "command": "/Users/you/.local/bin/s1-secops-mcp-launch.sh", "args": ["purple-mcp"] },
    "virustotal":     { "command": "/Users/you/.local/bin/s1-secops-mcp-launch.sh", "args": ["virustotal-mcp"] }
  }
}
```

Put `"--image", "sentinelone/secops-mcps:1.5.3"` in front of the server name in the args to pin explicitly (on Windows, `"-Image", "..."`). Set `S1_PROFILE` in an `env` block to use a non-default keychain profile, and `S1_OUTPUT_DIR` to a host directory to receive `outputFile` results: the macOS/Linux launcher mounts that directory into the container at the same path, so a path you pass to `outputFile` means the same thing on both sides. The Windows launcher mounts it at `/output` instead, so pass `outputFile` paths under `/output/` there. Neither variable is a secret.

All three servers ship in the same image and read the same names. The entrypoint maps the canonical names onto purple-mcp's own variables (`S1_CONSOLE_URL` → `PURPLEMCP_CONSOLE_BASE_URL`, `S1_CONSOLE_API_TOKEN` → `PURPLEMCP_CONSOLE_TOKEN`, `VIRUSTOTAL_API_KEY` → `PURPLEMCP_VT_API_KEY`); a server-specific variable that is already set wins.

The launcher sends each server only the values it uses. `purple-mcp` receives `S1_CONSOLE_URL`, `S1_CONSOLE_API_TOKEN` and the keychain's `VIRUSTOTAL_API_KEY`; the entrypoint turns the VirusTotal key into `PURPLEMCP_VT_API_KEY` for purple-mcp only and then unsets `VIRUSTOTAL_API_KEY` and `VT_API_KEY` in that container. This enables purple-mcp's threat intelligence tools (`threat_intel_by_*`, `threat_intel_search`) from the same stored key the VirusTotal MCP uses, with no separate setup. Which server to use for which enrichment task: [mcp-tools.md → Threat intelligence: which server to use](./mcp-tools.md#threat-intelligence-which-server-to-use).

A headless Linux host with no Secret Service has no keychain for the launcher to read. There, supply the values as environment variables from your secret manager instead, as described in [credentials.md](./credentials.md#resolution-order); never write them into the client config.

## Prerequisites

| Requirement | Check | Install |
|---|---|---|
| Docker (Desktop on macOS/Windows, Engine on Linux) | `docker --version` | [docker.com/get-started](https://www.docker.com/get-started/) |
| OS keychain | macOS, Windows: built in. Linux: `secret-tool --version` and an unlocked Secret Service | `libsecret-tools` (Debian, Ubuntu) or `libsecret` (Fedora, Arch) |
| SentinelOne API token | Settings → Users → Service Users | [Community guide](https://community.sentinelone.com/s/article/000005291) |
| SDL Log Write Key (raw log ingest only) | Singularity Data Lake → API Keys | [Community guide](https://community.sentinelone.com/s/article/000006763) |
| VirusTotal API key | [virustotal.com/gui/my-apikey](https://www.virustotal.com/gui/my-apikey) | Free tier is sufficient. One key serves the VirusTotal MCP and purple-mcp's threat intelligence tools; purple-mcp's `threat_intel_search` needs a premium key |

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
| `/bin/sh: .../s1-secops-mcp-launch.sh: Operation not permitted` (macOS) | The launcher is stored under `~/Documents`, `~/Desktop` or `~/Downloads`, where macOS blocks Claude Desktop's shell from running it. Copy it to `~/.local/bin/` (see [the launcher](#secrets-the-launcher-never--e)) and update `command` in the config. |
| `Unable to find image ... pulling from docker.io` | First-launch pull, normal, takes 30 to 90 s |
| `denied` or `manifest unknown` from docker.io | Normally a typo in the image name or tag, or a proxy intercepting Docker Hub. The reference must be exactly `sentinelone/secops-mcps:1.5.3`. Check with `docker manifest inspect sentinelone/secops-mcps:1.5.3`. |
| `VIRUSTOTAL_API_KEY environment variable is required` | The value is not in the keychain, or the launcher could not read it. Check with `s1-secops-mcp-launch.sh status` (or `s1-secops-mcp status`), which shows a stored secret as a length only, then re-run the launcher's `setup`. |
| `pydantic_core.ValidationError ... PURPLEMCP_*` | Same root cause for purple-mcp: `S1_CONSOLE_URL` or `S1_CONSOLE_API_TOKEN` did not reach the container. |
| `S1 Mgmt API: NOT configured` | s1-secops-mcp boots but no console token reached it; check the keychain entries for `S1_CONSOLE_URL` and `S1_CONSOLE_API_TOKEN` and the `S1_PROFILE` in use. |
| `OS keychain unavailable` / `secret-tool not found` / D-Bus errors | Linux without an unlocked Secret Service. Unlock the keyring, install libsecret tools, or use environment variables from a secret manager. |

### 3. Run the MCP container by hand

This bypasses Claude Desktop entirely and confirms the image works. The initialize handshake needs no credentials:

```bash
docker run -i --rm --pull=missing sentinelone/secops-mcps:1.5.3 s1-secops-mcp \
  <<< '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"smoke","version":"0.1"}}}'
```

Expected: a single JSON line back on stdout with `serverInfo.name = "s1-secops-mcp-server"` and the bundled MCP version (`1.5.3`). Stderr shows `Tools: 35 registered` and a `NOT configured` summary per API surface, because no credentials were supplied.

To test with your real credentials, run the launcher by hand instead of `docker run -e`, so the token never lands on a command line or in `docker inspect`:

```bash
~/.local/bin/s1-secops-mcp-launch.sh s1-secops-mcp \
  <<< '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"smoke","version":"0.1"}}}'
```

Stderr should now show `configured` for each surface whose values are in the keychain.

### 4. Force a fresh pull

If you suspect a corrupted local image:

```bash
docker rmi sentinelone/secops-mcps:1.5.3
docker pull sentinelone/secops-mcps:1.5.3
```

---

## CLAUDE.md customization

The image bundles a default CLAUDE.md at `/etc/sentinelone/CLAUDE.md`. Most users do not need to override it.

To use your own copy, the container needs to see the file and `S1_CLAUDE_MD_PATH` must point at it. A volume mount and a path are not secrets, so a plain `docker run` with them is fine as long as no token travels the same way. With either launcher (macOS/Linux or Windows), set `S1_CLAUDE_MD_PATH` to the absolute host path of your file in the `s1-secops-mcp` entry's `env` block. The launcher mounts it read-only at `/workspace/CLAUDE.md` and points the server at it; a path that is not an existing file is ignored and the bundled default is used:

```json
"s1-secops-mcp": {
  "command": "/Users/you/.local/bin/s1-secops-mcp-launch.sh",
  "args": ["s1-secops-mcp"],
  "env": {
    "S1_CLAUDE_MD_PATH": "/Users/yourname/Documents/PrincipalSOCAnalyst/CLAUDE.md"
  }
}
```

The Windows launcher does the same: it mounts the file read-only at `/workspace/CLAUDE.md` when `S1_CLAUDE_MD_PATH` names an existing file.

Confirm the override took effect by reading the `sentinelone://soc-context` resource in a new session. Only the `s1-secops-mcp` entry reads CLAUDE.md; the `purple-mcp` and `virustotal` entries need nothing.

---

## Upgrading

Upgrading is deliberate: edit the `--image` tag in `claude_desktop_config.json` (or update the launcher's default) and restart Claude Desktop.

The documented config pins `1.5.3`, so restarting does **not** move you to a newer image, by design. An immutable tag cannot change underneath you, which is what makes a pin forensically meaningful: the bytes you validated are the bytes you keep running. The trade is that nothing upgrades on its own, so watch the releases rather than expecting a restart to do it.

Replace the tag in all three MCP entries at once. They share one image, and leaving them on different tags is the one way to get the three servers out of lockstep.

To pre-pull the new version before editing the config:

```bash
docker pull sentinelone/secops-mcps:1.5.3
```

Coming from 1.4.x: the `-e`/`env` configs no longer apply. Store the values with the launcher's `setup`, switch each entry to the launcher, and remove the tokens from the config file. Full checklist: [upgrading.md](./upgrading.md).

To prune old image layers after a few upgrades:

```bash
docker image prune -a --filter "until=168h"
```

---

## Building from source

The image is built and published by the maintainers; end users never need to build it. This repo carries the exact [`Dockerfile`](../../../mcp/docker/Dockerfile), [`build.sh`](../../../mcp/docker/build.sh) and [`entrypoint.sh`](../../../mcp/docker/entrypoint.sh) used for each release, so the build is reviewable, and every version pin lives in `build.sh`.

To confirm what a published image contains, ask the image itself. It reports the exact repository and commit behind each bundled server:

```bash
docker run --rm sentinelone/secops-mcps:1.5.3 versions
```

Maintainer reference (pinned versions, publishing, bumping a pin): [`docker/README.md`](../../../mcp/docker/README.md).
