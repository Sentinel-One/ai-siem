# Claude Desktop Extension (.mcpb), optional

This folder builds `s1-secops-mcp` as a Claude Desktop Extension: a single
`.mcpb` file that a Claude Desktop user double-clicks to install. Desktop shows
a settings form for the console URL and tokens, stores the secret fields in the
operating system's secure store, and launches the server with those values as
environment variables. No terminal, no `claude_desktop_config.json` editing.

It is optional. The server, the keychain CLI and the Docker launcher work
without it.

## Which install path to use

| Path | Use it when | Where secrets live |
|---|---|---|
| **Desktop Extension** (this folder) | You use Claude Desktop only and want a GUI install with no Node or Docker setup. | Claude Desktop's secure storage (see below). |
| **Keychain CLI** (`s1-secops-mcp setup`) | You run the server with Node from Claude Code, Cowork, Claude Desktop config, or several clients that should share one set of credentials. Also the path for Purple MCP and VirusTotal via `s1-secops-mcp exec`. | OS keychain, service `sentinelone-mcp`, account `<profile>:<NAME>`. |
| **Docker launcher** | You want the pinned, scanned container image and the bundled Purple MCP and VirusTotal servers. | OS keychain, read by the launcher and handed to the container on stdin. |

The extension does not read the `sentinelone-mcp` keychain items written by
`s1-secops-mcp setup`. The two stores are separate; enter the values in the
extension settings even if they are already in the keychain.

## Build

```bash
cd s1-secops-mcp
bash mcpb/build-mcpb.sh
# output: dist/s1-secops-mcp-<version>.mcpb  (dist/ is git-ignored)
```

The script checks that `manifest.json` and `package.json` carry the same
version and that the manifest's `tools` list matches the 35 tools the server
registers, stages only `index.js`, `lib/`, `tools/`, `package.json`,
`README.md` and `CHANGELOG.md` under `server/` (plus `manifest.json`,
`CLAUDE.md` and `LICENSE` at the root), normalises file modes, and refuses to
pack anything that looks like a credential, test or data file.

Packing uses the official CLI (`@anthropic-ai/mcpb`) to run `mcpb validate`,
`mcpb pack` and `mcpb info`:

- `mcpb` on `PATH` if present (`npm install -g @anthropic-ai/mcpb`), otherwise
- the CLI inside a `node:24` container via Docker. Where `registry.npmjs.org`
  is blocked, set `MCPB_NPM_REGISTRY=https://registry.yarnpkg.com/`.
- `MCPB_PACKER=zip` forces a plain zip with no official validation.

The archive is unsigned (`mcpb info` reports "Not signed").

## Install

1. Double-click `s1-secops-mcp-<version>.mcpb` with Claude Desktop installed.
2. Follow the prompts to install and configure the extension.
3. Fill in the settings form (fields below).
4. Make sure the extension is enabled, then start a new chat. Reading the
   `sentinelone://credentials-status` resource shows which values the server
   received (secrets are never shown).

| Field | Required | Sensitive | Server variable |
|---|---|---|---|
| Console URL | yes | no | `S1_CONSOLE_URL` |
| Console API token | yes | yes | `S1_CONSOLE_API_TOKEN` |
| HEC ingest URL | no | no | `S1_HEC_INGEST_URL` |
| SDL Log Write Key | no | yes | `S1_HEC_TOKEN` |
| Default S1-Scope | no | no | `S1_SCOPE` |
| Output directory | no | no | `S1_OUTPUT_DIRS` (one directory) |
| SOC analyst CLAUDE.md | no | no | `S1_CLAUDE_MD_PATH` |

In the reference mcpb implementation (`getMcpConfigForManifest`), no launch
config is produced until both required fields are filled. Every optional field
declares `"default": ""`: an optional field with no value and no default is
left as the literal text `${user_config.<key>}` in the environment, which the
server would read as a real value. With the empty default, a blank field
reaches the server as an empty string, which it treats as unset.

## Where Claude Desktop stores the values

Per the Claude Help Center article "Getting Started with Local MCP Servers on
Claude Desktop" (FAQ, "How do I handle sensitive configuration like API
keys?"): fields marked `"sensitive": true` are encrypted with the operating
system's secure storage, which is the **Keychain on macOS**, **Credential
Manager on Windows**, and **your distribution's keychain manager on Linux**.
<https://support.claude.com/en/articles/10949351-getting-started-with-local-mcp-servers-on-claude-desktop>

In this manifest the three tokens are sensitive. The console URL, HEC URL,
scope and paths are not, so Desktop keeps them in its ordinary extension
settings.

## Why the server runs with `S1_KEYCHAIN=off`

The manifest sets `S1_KEYCHAIN=off` in the server environment. Desktop already
holds the values, and environment variables win over the keychain for every
field the user fills in, so leaving the keychain on would only matter for the
fields left blank. For those it would silently pull a `sentinelone-mcp`
keychain item written by `s1-secops-mcp setup`, possibly for a different
tenant or profile (for example a stale `S1_SCOPE` or HEC token applied to the
console named in the extension settings). With the keychain off, the Desktop
settings form is the single source of truth, and the startup log and the
credentials-status resource say so explicitly. On Windows the native keychain
backend needs `@napi-rs/keyring`, which the bundle does not ship, so the
setting also avoids a pointless backend probe there.

## Administrators

Owners and Primary Owners of Team and Enterprise organisations can control
which desktop extensions members may enable (the desktop extension allowlist),
and machine-level enterprise policy (for example `isDesktopExtensionEnabled`
set to `false`) overrides the in-app controls. If the extension is blocked,
use the keychain CLI or Docker path instead. See the same Help Center article,
sections "Enabling/disabling specific extensions on Team and Enterprise plans"
and "Enterprise Policy Controls".

## Limits

- Built for Claude Desktop's extension installer. For Claude Code, Cowork or
  any other MCP client, use the keychain CLI or Docker path.
- The bundle is unsigned (`mcpb info` reports "Not signed").
- Node 24 or later (`compatibility.runtimes.node`). Claude Desktop includes a
  built-in Node.js runtime (Help Center FAQ); Claude Desktop 2.26454.0 embeds
  Node 24.21.0. The packed server was run on Node 24.21.0 and 25.9.0.
- One set of credentials per installed extension; there is no profile switch.
  To change tenants, edit the settings.
- Output directory accepts one directory. Leaving it blank allows the home
  and temp directories, the server default.
- The `soc_analyst` prompt serves the `CLAUDE.md` bundled with the extension
  unless you pick another file. The bundled copy is a snapshot taken at build
  time.
- No VirusTotal or Purple MCP. Those are separate servers; run them with
  `s1-secops-mcp exec` or the Docker launcher.
- Desktop's secure storage protects the tokens at rest. Like any MCP server,
  the running process holds them in its environment, readable by the same
  OS user.
