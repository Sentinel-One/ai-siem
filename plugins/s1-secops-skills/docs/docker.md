# Docker reference

The **Docker quick start** (one `install` command that sets up the launcher, the Claude Desktop config, the image and your credentials; a restart; the plugin), plus a verify step, lives in the [README → Quick start (Docker)](../README.md#1-quick-start-docker). That is the path to follow for a normal install.

This page is the full Docker reference for everything beyond those steps: the launcher, prerequisites, the troubleshooting flowchart, hand-testing the container, overriding CLAUDE.md, upgrading, and building the image from source.

One Docker image runs one MCP server, `s1-secops-mcp`, so you only need Docker and the launcher script on the host: no Node, Python, or `uv`. It works on machines where IT policy blocks host-level package installs. Purple AI questions (`purple_ai_query`) and the VirusTotal (`ti_vt_lookup`, `ti_vt_relationship`) and Shodan (`ti_shodan_host`, `ti_shodan_dns`) lookups are built-in tools of that server. The VirusTotal and Shodan tools are listed only when their API keys are stored. Other MCP servers are your choice and install from their official sources: [connect-optional-tools.md](./connect-optional-tools.md).

Image: `sentinelone/secops-mcps`
Tags: full semver only. `1.6.3` is the current tag; earlier tags stay published. There is no `latest`, no rolling `1` or `1.6`, and no `sha-<short>`: the repository has immutable tags enabled, so a published tag can never be repointed at different bytes. Every install is therefore pinned and reproducible by construction, and an upgrade is something you do deliberately.

The image is built on a distroless Node 24 base (`gcr.io/distroless/nodejs24-debian13`, pinned by digest). It contains Node and the server code and nothing else: no shell, no package manager, no npm, no Python, and no init. Nothing in the build resolves a package from any registry, because `s1-secops-mcp` has no runtime dependencies. It runs as the unprivileged `nonroot` user (uid 65532). This matters if you are reviewing the supply chain of what runs in your environment.

The image version is its own counter and does not encode the versions inside it: image `1.6.1` bundles s1-secops-mcp 1.6.1. From 1.3.4 onward a version tag strictly increases and is never republished, so a pin is stable. Tags at or below `1.3.3` were republished with different contents and do not reliably identify what is inside. To know what you have, ask the image:

```bash
docker run --rm sentinelone/secops-mcps:1.6.3 versions
```

The output includes the image version, the server version, the Node version (`node`), the base image and the list of built-in tools.

**Read-only by default.** From 1.5.5, s1-secops-mcp refuses every tool call that would change your tenant until you opt in with `install --read-write` (Windows: `-ReadWrite`). See [Read-only mode and write access](#read-only-mode-and-write-access) below and the full reference in [read-only.md](./read-only.md).

- [Secrets: the launcher, never `-e`](#secrets-the-launcher-never--e)
- [Read-only mode and write access](#read-only-mode-and-write-access)
- [Licenses, notices and attestations](#licenses-notices-and-attestations)
- [Prerequisites](#prerequisites)
- [Troubleshooting](#troubleshooting)
- [CLAUDE.md customization](#claudemd-customization)
- [Upgrading](#upgrading)
- [Building from source](#building-from-source)

Credential values, the keychain model and its limits: [credentials.md](./credentials.md).

---

## Secrets: the launcher, never `-e`

Values passed to `docker run` with `-e NAME=value`, or with `-e NAME` from an MCP client `env` block, are stored in the container's configuration: anyone who can reach the Docker daemon sees them with `docker inspect`, and the client config file holds them in plaintext. From 1.5.0 the documented configs do neither.

The host launcher reads each value from the OS keychain (service `sentinelone-mcp`, account `<profile>:<NAME>`) and writes them to the container's stdin; the server reads them when `S1_SECRETS_STDIN=1`, before it handles any MCP request. Nothing secret appears in the client config, `docker inspect`, or the host process list.

| Host | Launcher |
|---|---|
| macOS, Linux | [`mcp/docker/s1-secops-mcp-launch.sh`](../../../mcp/docker/s1-secops-mcp-launch.sh) |
| Windows | [`mcp/docker/s1-secops-mcp-launch.ps1`](../../../mcp/docker/s1-secops-mcp-launch.ps1) |

Usage:

```bash
s1-secops-mcp-launch.sh [--image IMG] [--profile P] s1-secops-mcp [server args...]
s1-secops-mcp-launch.sh [--profile P] setup     # store values with security (macOS), secret-tool (Linux) or Windows Credential Manager (WSL), no echo
s1-secops-mcp-launch.sh [--profile P] status    # which values are stored (secrets shown as a length only)
s1-secops-mcp-launch.sh versions                # docker run --rm IMG versions
s1-secops-mcp-launch.sh notices                 # third-party notices and licenses (docker run --rm IMG notices)
s1-secops-mcp-launch.sh install [options]       # copy to ~/.local/bin, write the Claude Desktop config (or register with Claude Code), pull, run setup if needed
s1-secops-mcp-launch.sh config  [options]       # print the mcpServers JSON with this launcher's real path
s1-secops-mcp-launch.sh --help
# install/config options: --image IMG  --profile P  --output-dir DIR  --claude-md FILE  --read-write  (install only: --config-path FILE, --claude-code)
```

`--with-shodan` (Windows: `-WithShodan`) is still accepted so older scripts keep working, but it does nothing: the launcher prints that Shodan is built in. Running the launcher with a server name removed in 1.6.0 (`purple-mcp`, `virustotal-mcp`, `shodan-mcp`) exits 78 with a message to run `install` again.

Install it with one command, which needs no clone (from a clone, run `sh mcp/docker/s1-secops-mcp-launch.sh install` instead):

```bash
mkdir -p ~/.local/bin && curl -fsSL https://raw.githubusercontent.com/Sentinel-One/ai-siem/main/mcp/docker/s1-secops-mcp-launch.sh -o ~/.local/bin/s1-secops-mcp-launch.sh && sh ~/.local/bin/s1-secops-mcp-launch.sh install
```

`install` copies the launcher to `~/.local/bin/` and clears extended attributes such as the download quarantine flag; adds the `s1-secops-mcp` entry to the Claude Desktop config (`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS, `${XDG_CONFIG_HOME:-~/.config}/Claude/claude_desktop_config.json` on Linux) with the real path, removes older `purple-mcp`, `virustotal`, `shodan` and `virustotal-mcp` entries that ran this launcher, and keeps every other entry (including servers you added yourself with other commands) and a dated `.bak-` copy of the old file; pulls the image; runs `setup` when no console token is stored; and ends with a `Built-in tools: Purple AI on, VirusTotal on|off ..., Shodan on|off ...` line that tells you which threat-intel tools will be listed. It merges with `osascript` (macOS) or `python3` (Linux); with neither, it prints the entries instead of editing the file. A config that is not valid JSON is never overwritten. Re-running it is safe, and it is also the upgrade path: a newer launcher pins the newer image.

The launcher must live outside `~/Documents`, `~/Desktop` and `~/Downloads` on macOS: privacy protection blocks Claude Desktop's `/bin/sh` from executing a script stored there, and the MCP log shows `/bin/sh: .../s1-secops-mcp-launch.sh: Operation not permitted`. `install` takes care of that; `config` warns when run from one of those folders.

Launcher options go **before** the server name; everything after the server name is passed to the server inside the container. Environment: `S1_MCP_IMAGE` (default image, `sentinelone/secops-mcps:1.6.3`), `S1_PROFILE` (keychain profile, default `default`), `S1_OUTPUT_DIR` (host directory for `outputFile`), `S1_CLAUDE_MD_PATH` (host CLAUDE.md, mounted read-only), `S1_READ_ONLY` (forwarded to the container only when the client config sets it), `S1_KEYCHAIN_TIMEOUT` (keychain call timeout in **seconds**, default 15). The native Node server and the Python clients read `S1_KEYCHAIN_TIMEOUT_MS` (milliseconds, default 15000) instead; the launcher does not read the `_MS` name. The Windows launcher takes `-Image` and `-Profile`, reads `S1_MCP_IMAGE`, `S1_PROFILE`, `S1_OUTPUT_DIR`, `S1_CLAUDE_MD_PATH` and `S1_READ_ONLY`, and supports `setup`, `status`, `versions`, `notices`, `help`, `install`, `config` and the `s1-secops-mcp` server name. Its `install` copies it to `%USERPROFILE%\bin\`, unblocks it, and writes `%APPDATA%\Claude\claude_desktop_config.json` plus, when Claude Desktop is the MSIX package the claude.ai installer now ships, the copy that package actually reads under `%LOCALAPPDATA%\Packages\Claude_<id>\LocalCache\Roaming\Claude\` (options `-Image`, `-Profile`, `-OutputDir`, `-ClaudeMd`, `-ReadWrite`, `-ConfigPath`). One command, no clone:

```powershell
$f = "$env:TEMP\s1-secops-mcp-launch.ps1"; Invoke-WebRequest https://raw.githubusercontent.com/Sentinel-One/ai-siem/main/mcp/docker/s1-secops-mcp-launch.ps1 -OutFile $f -UseBasicParsing; powershell -NoProfile -ExecutionPolicy Bypass -File $f install
```
 It has no keychain timeout: Credential Manager reads do not wait on a prompt.

Claude Desktop config, as `install` writes it and `config` prints it (`<home>` is your home folder; the real file holds the full path, because JSON does not expand `~` or `$HOME`):

```json
{
  "mcpServers": {
    "s1-secops-mcp": { "command": "<home>/.local/bin/s1-secops-mcp-launch.sh", "args": ["--image", "sentinelone/secops-mcps:1.6.3", "s1-secops-mcp"] }
  }
}
```

The built-in VirusTotal and Shodan tools need no entry of their own. To turn them on, run `setup`, store `VIRUSTOTAL_API_KEY` or `SHODAN_API_KEY`, and restart Claude Desktop; the server lists the tools when it starts with the key.

With `--read-write` (Windows: `-ReadWrite`), the `s1-secops-mcp` entry also carries `"env": {"S1_READ_ONLY": "false"}`. Without it, no `S1_READ_ONLY` is written and the server runs read-only.

Generate entries rather than typing them: a hand-typed path that does not exist is the most common reason a server stays red. `--profile P` adds a non-default keychain profile to each entry, and `--output-dir DIR` creates `DIR` and sets `S1_OUTPUT_DIR` on the `s1-secops-mcp` entry so it receives `outputFile` results: the macOS/Linux launcher mounts that directory into the container at the same path, so a path you pass to `outputFile` means the same thing on both sides. The Windows launcher mounts it at `/output` instead, so pass `outputFile` paths under `/output/` there. Neither variable is a secret.

The stdin preamble accepts only `S1_CONSOLE_URL`, `S1_CONSOLE_API_TOKEN`, `S1_HEC_INGEST_URL`, `S1_HEC_TOKEN`, `S1_SCOPE`, `VIRUSTOTAL_API_KEY` and `SHODAN_API_KEY`. `purple_ai_query` uses the console token, so it needs no extra key. The VirusTotal tools call `www.virustotal.com` with `VIRUSTOTAL_API_KEY`, and the Shodan tools call `api.shodan.io` with `SHODAN_API_KEY`. All of them are read-only. At startup the server log prints which are on, for example `Threat intel: Purple AI on, VirusTotal on, Shodan off (no SHODAN_API_KEY)`. Tool details: [mcp-tools.md](./mcp-tools.md).

A headless Linux host with no Secret Service has no keychain for the launcher to read. There, supply the values as environment variables from your secret manager instead, as described in [credentials.md](./credentials.md#resolution-order); never write them into the client config.

## Read-only mode and write access

From 1.5.5, s1-secops-mcp is read-only by default. Tools that change the tenant (writes through the Mgmt API, UAM triage, SDL files and dashboards, HEC ingest, Hyperautomation import and delete, and PowerQuery `| savelookup`) are refused before any network call, with a message that explains how to enable write. Read and query tools always run, including `purple_ai_query` and the built-in VirusTotal and Shodan tools, which are read-only.

| To | Run, then restart Claude Desktop |
|---|---|
| Enable write (macOS, Linux) | `~/.local/bin/s1-secops-mcp-launch.sh install --read-write` |
| Enable write (Windows) | `powershell -NoProfile -ExecutionPolicy Bypass -File $HOME\bin\s1-secops-mcp-launch.ps1 install -ReadWrite` |
| Return to read-only | Run `install` again without the flag |
| Plain `docker run` | Add `-e S1_READ_ONLY=false` |

`install --read-write` writes `"S1_READ_ONLY": "false"` into the `s1-secops-mcp` entry's `env` block and prints a NOTICE that write is enabled; without the flag it prints a read-only notice. At runtime the launcher forwards `S1_READ_ONLY` to the container only when the client config sets it, so the server default (read-only) applies otherwise. `status` shows an `S1_READ_ONLY` line stating that the setting lives in the client config, not the keychain. Pass your other options (`--profile`, `--output-dir`, `--claude-md`) again with `--read-write`.

Accepted values, refused tools, the controls that apply when write is enabled, and the recommended token roles: [read-only.md](./read-only.md).

## Licenses, notices and attestations

Print the third-party notices, licenses and service terms with either command:

```bash
docker run --rm sentinelone/secops-mcps:1.6.3 notices    # aliases: licenses, license
~/.local/bin/s1-secops-mcp-launch.sh notices             # Windows: s1-secops-mcp-launch.ps1 notices
```

In the image, [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md) is at `/usr/share/doc/secops-mcps/THIRD_PARTY_NOTICES.md` and the s1-secops-mcp license (AGPL-3.0) is at `/opt/s1-secops-mcp/LICENSE`.

From 1.5.5, each pushed image carries SLSA provenance and an SPDX SBOM attestation on its index. Docker Hub lists these as an extra `unknown/unknown` platform entry; `docker pull` ignores it. To inspect them:

```bash
docker buildx imagetools inspect sentinelone/secops-mcps:1.6.3 --format '{{ json .SBOM }}'
docker buildx imagetools inspect sentinelone/secops-mcps:1.6.3 --format '{{ json .Provenance }}'
```

## Prerequisites

| Requirement | Check | Install |
|---|---|---|
| Docker (Desktop on macOS/Windows, Engine on Linux) | `docker --version` | [docker.com/get-started](https://www.docker.com/get-started/) |
| OS keychain | macOS, Windows: built in. Linux: `secret-tool --version` and an unlocked Secret Service | `libsecret-tools` (Debian, Ubuntu) or `libsecret` (Fedora, Arch) |
| SentinelOne API token | Settings → Users → Service Users | [Community guide](https://community.sentinelone.com/s/article/000005291) |
| SDL Log Write Key (raw log ingest only) | Singularity Data Lake → API Keys | [Community guide](https://community.sentinelone.com/s/article/000006763) |
| VirusTotal API key (optional) | [virustotal.com/gui/my-apikey](https://www.virustotal.com/gui/my-apikey) | For the built-in `ti_vt_lookup` and `ti_vt_relationship` tools. A free key allows 4 lookups a minute and 500 a day; some relationships (`related_threat_actors`, `similar_files`) need a premium key, and a 403 says so |
| Shodan API key (optional) | [account.shodan.io](https://account.shodan.io), Account page, API key | For the built-in `ti_shodan_host` and `ti_shodan_dns` tools. Neither spends query credits. A free key may get "Requires membership or higher" for some hosts; a membership or higher key gives dependable results |

Apple Silicon and Intel are both supported; the image is multi-arch (`linux/amd64` + `linux/arm64`) so qemu emulation is never used.

The install command, the plugin install, and the verify step are all in the [README Quick start (Docker)](../README.md#1-quick-start-docker).

Claude Desktop starts the MCP server itself, in one container, when it opens, and removes it when it quits. Docker Desktop only has to be running; a container started from Docker Desktop has no credentials and no connection to Claude.

---

## Troubleshooting

If `s1-secops-mcp` shows red in Cowork → MCP Servers, work through these in order.

### 1. Confirm Docker Desktop is actually running

```bash
docker info | head -3
```

Expected: `Server Version: ...`. If you see `Cannot connect to the Docker daemon`, start Docker Desktop, wait until the whale icon stops animating, and restart Claude Desktop.

### 2. Tail the MCP log file

Claude Desktop writes one log file per MCP server. Watch it while you start a new chat:

```bash
tail -F ~/Library/Logs/Claude/mcp-server-s1-secops-mcp.log
```

Common signatures:

| Log line | Meaning |
|---|---|
| `Cannot connect to the Docker daemon` | Docker Desktop is not running, see step 1 |
| Claude Code: `MCP server ... connection timed out` (Linux, WSL) | Run `install --claude-code` again to get the current launcher. If it persists, set `S1_LAUNCH_TRACE=/tmp/s1.trace` before starting Claude Code and check which stage the trace reaches. |
| WSL: `The command 'docker' could not be found in this WSL 2 distro` | Docker Desktop → Settings → Resources → WSL integration: switch on the distro, Apply & restart, open a new WSL terminal |
| WSL: `permission denied while trying to connect to the docker API at unix:///var/run/docker.sock` | `sudo usermod -aG docker $USER`, then `wsl --shutdown` from Windows and open a new WSL terminal |
| WSL: `Windows Credential Manager unreachable through powershell.exe` | WSL interop is off or `powershell.exe` is not on `PATH`. Check `command -v powershell.exe`; interop is on by default (`/etc/wsl.conf`, `[interop] enabled=true`) |
| `Couldn't start for Cowork and Code sessions. Error: Request timed out` (`shared-pool`) | On Windows, run `install` again to get the current launcher. Earlier Windows launchers held each request until Claude Desktop closed stdin, so `Message from server: id=0 result` appears right after `notifications/cancelled`. Check with `mcp/docker/launcher-test.ps1`: its last case sends `initialize` with stdin held open and expects the reply within seconds (0.6 s on Windows 11). Piping one line and closing stdin does not test this, because closing stdin releases the held request. If the current launcher passes and the error persists, see [anthropics/claude-code#92758](https://github.com/anthropics/claude-code/issues/92758). |
| `/bin/sh: .../s1-secops-mcp-launch.sh: Operation not permitted` (macOS) | The config points at a launcher under `~/Documents`, `~/Desktop` or `~/Downloads`, where macOS blocks Claude Desktop's shell from running it. Run `install` again (see [the launcher](#secrets-the-launcher-never--e)): it copies the launcher to `~/.local/bin/` and rewrites the config. |
| `ENOENT`, `No such file or directory` or `spawn ... s1-secops-mcp-launch` | The `command` path in the config does not exist, usually a hand-typed `/Users/you/...`. Run `install` again, which writes the real path. |
| `Unable to find image ... pulling from docker.io` | First-launch pull, normal, takes 30 to 90 s |
| `denied` or `manifest unknown` from docker.io | Normally a typo in the image name or tag, or a proxy intercepting Docker Hub. The reference must be exactly `sentinelone/secops-mcps:1.6.3`. Check with `docker manifest inspect sentinelone/secops-mcps:1.6.3`. |
| A tool returns `s1-secops-mcp is in read-only mode (S1_READ_ONLY)` | Expected from 1.5.5 for any call that changes the tenant. To allow writes, run `install --read-write` (Windows: `-ReadWrite`) and restart Claude Desktop. See [read-only.md](./read-only.md). |
| `purple-mcp`, `virustotal` or `shodan` shows failed after upgrading; its log says `'purple-mcp' was removed in 1.6.0` (or the same for another name) | The entry is from before 1.6.0. Run `install` again: it removes the old entries and writes the `s1-secops-mcp` entry. Then restart Claude Desktop. To keep using one of those servers, install it from its official source: [connect-optional-tools.md](./connect-optional-tools.md). |
| `Threat intel: ... VirusTotal off (no VIRUSTOTAL_API_KEY)` or `Shodan off (no SHODAN_API_KEY)`, and the `ti_vt_*` or `ti_shodan_*` tools are missing | The key is not in the keychain, or the launcher could not read it. Check with `~/.local/bin/s1-secops-mcp-launch.sh status` (or `s1-secops-mcp status`), which shows a stored secret as a length only, then run the launcher's `setup` and restart Claude Desktop. |
| `Purple AI off (no console token)` | `S1_CONSOLE_URL` or `S1_CONSOLE_API_TOKEN` did not reach the container; `purple_ai_query` needs both. Same check as above. |
| `outputFile ... refused: no output folder is shared with this container`, or `... is outside the allowed output directories` | Under Docker, run `~/.local/bin/s1-secops-mcp-launch.sh install --output-dir <folder>` (Windows: `-OutputDir`), restart Claude Desktop, and write inside that folder (Windows: under `/output`). `S1_OUTPUT_DIRS` in the client config has no effect under Docker. With the Node server, write inside your home or temp directory, or set `S1_OUTPUT_DIRS`. |
| `S1 Mgmt API: NOT configured` | s1-secops-mcp boots but no console token reached it; check the keychain entries for `S1_CONSOLE_URL` and `S1_CONSOLE_API_TOKEN` and the `S1_PROFILE` in use. |
| `OS keychain unavailable` / `secret-tool not found` / D-Bus errors | Linux without an unlocked Secret Service. Unlock the keyring, install libsecret tools, or use environment variables from a secret manager. |

### 3. Run the MCP container by hand

This bypasses Claude Desktop entirely and confirms the image works. The initialize handshake needs no credentials:

```bash
docker run -i --rm --pull=missing sentinelone/secops-mcps:1.6.3 s1-secops-mcp \
  <<< '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"smoke","version":"0.1"}}}'
```

Expected: a single JSON line back on stdout with `serverInfo.name = "s1-secops-mcp-server"` and the bundled MCP version (`1.6.1`). Stderr shows a `Threat intel:` line, a `Tools:` line (43 listed of 47 registered here, because no threat-intel keys were supplied; 45 with a VirusTotal key, 47 with both keys), a `Mode:` line (read-only unless `S1_READ_ONLY=false` was passed) and a `NOT configured` summary per API surface, because no credentials were supplied.

To test with your real credentials, run the launcher by hand instead of `docker run -e`, so the token never lands on a command line or in `docker inspect`:

```bash
~/.local/bin/s1-secops-mcp-launch.sh s1-secops-mcp \
  <<< '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"smoke","version":"0.1"}}}'
```

Stderr should now show `configured` for each surface whose values are in the keychain.

The image has no shell, so `docker run --entrypoint sh` does not work. To look inside, run Node instead:

```bash
docker run --rm --entrypoint /nodejs/bin/node sentinelone/secops-mcps:1.6.3 -e 'console.log(process.version)'
```

### 4. Force a fresh pull

If you suspect a corrupted local image:

```bash
docker rmi sentinelone/secops-mcps:1.6.3
docker pull sentinelone/secops-mcps:1.6.3
```

---

## CLAUDE.md customization

The image bundles a default CLAUDE.md at `/etc/sentinelone/CLAUDE.md`. Most users do not need to override it.

To use your own copy, the container needs to see the file and `S1_CLAUDE_MD_PATH` must point at it. A volume mount and a path are not secrets, so a plain `docker run` with them is fine as long as no token travels the same way. With either launcher (macOS/Linux or Windows), re-run `install` with the file, which writes its absolute path into the `s1-secops-mcp` entry as `S1_CLAUDE_MD_PATH` (combine it with any other options you use, such as `--output-dir`):

```bash
~/.local/bin/s1-secops-mcp-launch.sh install --claude-md ~/Documents/PrincipalSOCAnalyst/CLAUDE.md
```

On Windows: `powershell -NoProfile -ExecutionPolicy Bypass -File $HOME\bin\s1-secops-mcp-launch.ps1 install -ClaudeMd $HOME\Documents\PrincipalSOCAnalyst\CLAUDE.md`. The launcher mounts the file read-only at `/workspace/CLAUDE.md` and points the server at it; a path that is not an existing file is ignored and the bundled default is used. The resulting entry:

```json
"s1-secops-mcp": {
  "command": "<home>/.local/bin/s1-secops-mcp-launch.sh",
  "args": ["--image", "sentinelone/secops-mcps:1.6.3", "s1-secops-mcp"],
  "env": {"S1_CLAUDE_MD_PATH": "<home>/Documents/PrincipalSOCAnalyst/CLAUDE.md"}
}
```

The Windows launcher does the same: it mounts the file read-only at `/workspace/CLAUDE.md` when `S1_CLAUDE_MD_PATH` names an existing file.

Confirm the override took effect by reading the `sentinelone://soc-context` resource in a new session.

---

## Upgrading

Upgrading is deliberate: run the install command again (macOS/Linux one-liner above, or the Windows one) and restart Claude Desktop. It fetches the current launcher, whose default image is the current release, rewrites the `s1-secops-mcp` entry with that tag, removes entries from older releases that ran this launcher, pulls the image, and keeps your credentials. `install` rewrites the `s1-secops-mcp` entry, so pass `--read-write` again if you use write access. To pick a specific tag, run `~/.local/bin/s1-secops-mcp-launch.sh install --image sentinelone/secops-mcps:<tag>`.

The documented config pins `1.6.1`, so restarting does **not** move you to a newer image, by design. An immutable tag cannot change underneath you, which is what makes a pin forensically meaningful: the bytes you validated are the bytes you keep running. The trade is that nothing upgrades on its own, so watch the releases rather than expecting a restart to do it.

Coming from 1.5.x: run `install` again so the old `purple-mcp`, `virustotal` and `shodan` entries are removed. Coming from 1.4.x: the `-e`/`env` configs no longer apply. Run `install`, which stores the values with `setup` and writes the `s1-secops-mcp` entry, then remove any tokens left in other entries of the config file. Full checklist: [upgrading.md](./upgrading.md).

To prune old image layers after a few upgrades:

```bash
docker image prune -a --filter "until=168h"
```

---

## Building from source

The image is built and published by the maintainers; end users never need to build it. This repo carries the exact [`Dockerfile`](../../../mcp/docker/Dockerfile), [`build.sh`](../../../mcp/docker/build.sh) and [`container-entry.mjs`](../../../mcp/docker/container-entry.mjs) used for each release, so the build is reviewable, and every version pin lives in `build.sh`.

To confirm what a published image contains, ask the image itself. It reports the repository and commit the server was built from, the Node version and the base packages removed at build time:

```bash
docker run --rm sentinelone/secops-mcps:1.6.3 versions
```

The image version and the base image digest are pinned in [`mcp/docker/build.sh`](../../../mcp/docker/build.sh). The release pipeline that publishes the image is maintained outside this repository and keeps its own copy of both pins. The server itself is copied from the working tree, so there is no source pin for it.

Maintainer reference (what is in the image, publishing, moving the base image): [`docker/README.md`](../../../mcp/docker/README.md).
