# Credentials

This is the canonical credentials reference for every install path (Docker, individual MCP install, Claude Code, host-only Python scripts). It covers every value, where to get it, how it is stored, how each install path reads it, and the limits of that protection.

As of s1-secops-mcp 1.5.0 (plugin 1.3.12) there is **no credentials file**. Values come from environment variables or the OS keychain, nothing else. If you are upgrading from a release that used `credentials.json`, see [Migrating from a credentials file](#migrating-from-a-credentials-file).

---

## The values

| Name | Required for | How to get it |
|---|---|---|
| `S1_CONSOLE_URL` | Everything | Your console URL, e.g. `https://usea1-acme.sentinelone.net`. No trailing slash. |
| `S1_CONSOLE_API_TOKEN` | Mgmt Console REST, PowerQuery LRQ, UAM GraphQL, Purple AI GraphQL, SDL config operations, UAM alert ingest, IOCs | Settings → Users → Service Users → Create Service User → copy the API token. |
| `S1_HEC_INGEST_URL` | UAM alert ingest, raw log ingest | Region-specific ingest host, e.g. `https://ingest.us1.sentinelone.net`. Look up yours at [SentinelOne Endpoint URLs by Region](https://community.sentinelone.com/s/article/000004961). |
| `S1_HEC_TOKEN` | Optional. Raw log ingest over the event collector (`hec_ingest`) | The SDL Log Write Key: Console → Singularity Data Lake → API Keys → Log Write Key. No API mints one. |
| `S1_SCOPE` | Optional. Default `S1-Scope` for SDL calls when the token spans several sites or accounts | `<accountId>` or `<accountId>:<siteId>`. Most tools also take a per-call `scope`. |
| `VIRUSTOTAL_API_KEY` | The VirusTotal MCP, and purple-mcp's threat intelligence tools (`threat_intel_by_hash` / `_url` / `_domain` / `_ip`, `threat_intel_search`) | A VirusTotal API key (free tier works) from [virustotal.com](https://virustotal.com). One stored key serves both servers. `threat_intel_search` (VT Intelligence query syntax) needs a premium key. |

`S1_CONSOLE_URL` and `S1_CONSOLE_API_TOKEN` are the minimum, and between them they authorise every SDL query and configuration operation including parser and dashboard deployment.

Raw log ingest is the one path the console API token does not reliably cover. `/services/collector/raw` and `/event` take the SDL Log Write Key in `S1_HEC_TOKEN` (`Splunk` or `Bearer` prefix), which returns `HTTP 200 {"text":"Success","code":0}`. The console token's behaviour there differs per console: on some it returns `HTTP 400 {"text":"Missing S1-Scope header","code":5}` without an `S1-Scope` header and is accepted with one, on others it returns `HTTP 403 {"text":"User token not allowed for this endpoint","code":4}` either way. Use the write key in both cases. A key is minted for exactly one account or site and writes only there, so the key fixes the ingest destination; no `S1-Scope` header is sent, and sending one does not change where the key's events land. UAM alert ingest and IOCs still use `S1_CONSOLE_API_TOKEN`.

The scoped SDL keys (`SDL_CONFIG_READ_KEY`, `SDL_CONFIG_WRITE_KEY`, `SDL_LOG_READ_KEY`, `SDL_LOG_WRITE_KEY`, `SDL_XDR_URL`) are retired and are no longer read.

---

## Resolution order

Each value resolves independently, highest wins:

1. **Environment variable** of the same name. Use this for CI, a secret manager that injects variables, and the Docker launcher (which hands values to the container over stdin, see below). The MCP server, the Python clients and `s1-secops-mcp setup` (stdin and `--import-json`) accept the same aliases; the canonical name wins when both are set:

   | Canonical name | Also accepted |
   |---|---|
   | `S1_CONSOLE_URL` | `S1_BASE_URL` |
   | `S1_CONSOLE_API_TOKEN` | `S1_API_TOKEN`, `SDL_CONSOLE_API_TOKEN` |
   | `S1_HEC_INGEST_URL` | `S1_UAM_ALERT_INTERFACE_URL` |
   | `S1_SCOPE` | `SDL_S1_SCOPE` |
   | `VIRUSTOTAL_API_KEY` | `VT_API_KEY` |

   `setup` also maps `PURPLEMCP_CONSOLE_BASE_URL` and `PURPLEMCP_CONSOLE_TOKEN` from an imported purple-mcp config.
2. **OS keychain**, service `sentinelone-mcp`, account `<profile>:<NAME>`. The profile comes from `S1_PROFILE` and defaults to `default`, so the console token lives at account `default:S1_CONSOLE_API_TOKEN`.

There is no third step. The old file discovery (`S1_CREDS_FILE`, `COWORK_WORKSPACE`, the working-directory walk-up, `~/mnt/*`, `CLAUDE_CONFIG_DIR`, `~/.config/sentinelone`, `~/.claude/sentinelone`) and the SessionStart hook that copied a file into the session are gone. `S1_KEYCHAIN=off` disables the keychain step entirely, which is what CI, containers and tests use.

### Keychain backends

| Platform | Backend | Notes |
|---|---|---|
| macOS | Login keychain via `/usr/bin/security` | Nothing to install. Writes go through `security -i` on stdin, so the secret never appears in a process argument list. |
| Linux | Secret Service via `secret-tool` (libsecret) | Install `libsecret-tools` (Debian, Ubuntu) or `libsecret` (Fedora, Arch). Needs a D-Bus session and an unlocked keyring (GNOME Keyring or KeePassXC). Headless hosts without one should use environment variables. |
| Windows | Credential Manager | The Node server uses the optional `@napi-rs/keyring` package (`npm install @napi-rs/keyring`); the Python clients use the `keyring` package. |

All backends use the same service and account names, so the MCP server, the Docker launcher and the Python clients find the same entries on macOS and Linux. On Windows, see the Python `keyring` caveat under [Storing values](#storing-values-setup-status-forget).

---

## Storing values: `setup`, `status`, `forget`

Run these on your own machine, in a terminal (not inside a Claude chat). They need the `s1-secops-mcp` CLI from an npm install or a source checkout (`node mcp/s1-secops-mcp/index.js <command>` works the same way).

```bash
s1-secops-mcp setup                    # prompts for each value without echo, stores it, reads it back to verify
s1-secops-mcp setup --profile prod     # a second tenant under its own profile
s1-secops-mcp status                   # where each value comes from (env or keychain), masked
s1-secops-mcp forget --name S1_HEC_TOKEN       # remove one value
s1-secops-mcp forget --profile prod            # remove a whole profile
s1-secops-mcp exec -- purple-mcp --mode stdio  # run another MCP server with the keychain values in its environment
```

Without a terminal, `setup` reads `NAME=value` lines from stdin instead of prompting, which keeps values out of the command line and shell history. `exec` maps the values to the names the other servers read (`PURPLEMCP_CONSOLE_BASE_URL`, `PURPLEMCP_CONSOLE_TOKEN`, `PURPLEMCP_VT_API_KEY`, `VT_API_KEY`); they are visible in that child's environment to the same OS user.

To run the server against a non-default profile, set `S1_PROFILE=<name>` in the environment the server starts with (the launcher and MCP configs below accept it, and it is not a secret).

Docker-only hosts without Node can store values with the launcher: `mcp/docker/s1-secops-mcp-launch.sh setup` writes them with `security` (macOS) or `secret-tool` (Linux), and `mcp/docker/s1-secops-mcp-launch.ps1 setup` writes Windows Credential Manager entries named the way `@napi-rs/keyring` names them. Without Node, the Python helper in a skills checkout does the same job on macOS and Linux: `python3 mgmt-console-api/scripts/s1_keystore.py setup` prompts and stores, and `... s1_keystore.py status` shows sources. On Windows the Python helper goes through the `keyring` package (`pip install keyring`), whose Credential Manager target names (`sentinelone-mcp` or `<account>@sentinelone-mcp`) differ, per its source, from the `<account>.sentinelone-mcp` targets that `@napi-rs/keyring` and the PowerShell launcher use. This has not been verified on a Windows host yet, so prefer the PowerShell launcher's `setup` there.

Never paste a token into a chat with Claude, and never ask Claude to write one to a file. The skills are written to stop and ask you to run `s1-secops-mcp setup` when a value is missing.

---

## Changing credentials in the keychain

Every change below happens in a terminal on your own machine. **Restart the MCP client afterwards** (quit and reopen Claude Desktop, or start a new Claude Code session): the servers read the keychain when they start, so a running server keeps the old value until it restarts.

### Change one value, or all of them

Run `setup` again. It prompts for each value in turn, shows whether it is set (secrets as a length only), hides what you type for secrets, and **keeps the current value when you press Enter**. Type a new value only for the ones you want to change.

```bash
~/.local/bin/s1-secops-mcp-launch.sh setup                  # Docker hosts (macOS, Linux)
~/.local/bin/s1-secops-mcp-launch.sh setup --profile kbl    # the same, for another profile
s1-secops-mcp setup [--profile P]                           # Node install or source checkout
```

To be asked for one value only, name it (Node CLI only; the launcher always walks the full list):

```bash
s1-secops-mcp setup --name S1_CONSOLE_API_TOKEN
```

Without a terminal, `s1-secops-mcp setup` reads `NAME=value` lines from stdin:

```bash
printf 'S1_CONSOLE_URL=https://usea1-acme.sentinelone.net\n' | s1-secops-mcp setup
```

Use this form only for values that are not secret, or pipe a secret from a password manager's CLI. A token typed into that command line lands in your shell history; type tokens at the interactive prompt instead.

### Check what is stored

```bash
~/.local/bin/s1-secops-mcp-launch.sh status [--profile P]
s1-secops-mcp status [--profile P]      # also shows whether each value comes from the environment or the keychain
```

`status` never prints a secret: tokens and keys show as `set (N chars)`. Console and ingest URLs and `S1_SCOPE` are shown in full because they are not secrets.

### Remove values

```bash
s1-secops-mcp forget --name S1_HEC_TOKEN              # one value from the default profile
s1-secops-mcp forget --profile kbl --name S1_SCOPE    # one value from another profile
s1-secops-mcp forget --profile kbl                    # every value in that profile
```

`forget` is in the Node CLI. On a Docker-only host, remove items with the OS tools below.

### Switch consoles with profiles

Each console or tenant gets its own profile: `setup --profile kbl` stores a full set under `kbl:<NAME>` without touching `default`. Point a server at it with `S1_PROFILE`, which is not a secret and is safe in an MCP client config:

```json
"s1-secops-mcp": { "command": "s1-secops-mcp", "env": { "S1_PROFILE": "kbl" } }
```

For the Docker launcher, pass the profile before the server name instead: `"args": ["--profile", "kbl", "s1-secops-mcp"]` (Windows: `-Profile kbl`). Restart the client after changing the profile.

### Using the operating system's own tools

The items are ordinary keychain entries, so the OS tools can view and delete them. Prefer `setup` to change a value: it validates the input and reads the value back to confirm the write.

| Platform | Where to look | Item naming |
|---|---|---|
| macOS | **Keychain Access** app, login keychain, search for `SentinelOne MCP` | Name `SentinelOne MCP <profile> <NAME>`, Account `<profile>:<NAME>`, Where `sentinelone-mcp` |
| Linux | `secret-tool lookup service sentinelone-mcp username <profile>:<NAME>` to read, `secret-tool clear service sentinelone-mcp username <profile>:<NAME>` to delete, or **Seahorse** (Passwords and Keys) | Label `SentinelOne MCP <profile> <NAME>` |
| Windows | **Credential Manager** > Windows Credentials > Generic Credentials, or `cmdkey /delete:<profile>:<NAME>.sentinelone-mcp` | Generic credential `<profile>:<NAME>.sentinelone-mcp` |

On Windows, store and change values with `s1-secops-mcp-launch.ps1 setup [-Profile P]` (or `s1-secops-mcp setup` when the Node server is installed with `@napi-rs/keyring`). Both write the same Generic credentials.

### Rotate a token

1. Mint a new token for the same user in the console (Settings > Users > Service Users for a service user; My User > API Token for a personal token).
2. Store it: `s1-secops-mcp setup --name S1_CONSOLE_API_TOKEN` (or the launcher's `setup`, pressing Enter for every other value).
3. Confirm with `status` that the token length matches the new token.
4. Restart the MCP client and run one read-only call to prove the new token works.
5. Revoke the old token in the console.

If the console revokes the old token the moment it issues a new one, steps 2 to 4 have to follow straight away. For a suspected compromise, revoke first and then store the new token.

---

## Migrating from a credentials file

If you used `credentials.json` with an earlier release:

```bash
s1-secops-mcp setup --import-json /path/to/credentials.json   # copies every known key into the keychain
s1-secops-mcp status                                           # confirm each value now reads from the keychain
rm /path/to/credentials.json                                   # then delete the file
```

Also delete any copies the old SessionStart hook made (for example under `~/.claude/sentinelone/` or `~/.config/sentinelone/`), and remove the file from any Cowork project's **Add files** list. Nothing in 1.5.0 reads them.

---

## Docker: the launcher, not `-e`

Do **not** pass secrets to `docker run` with `-e`, and do not put them in a client config `env` block for a Docker command. Values passed with `-e` are stored in the container's configuration and show in `docker inspect` to anyone who can reach the Docker daemon.

Use the host launcher instead. It reads the keychain on the host and hands the values to the container over stdin (the entrypoint reads them when `S1_SECRETS_STDIN=1`), so they never appear in `docker inspect`, the process list, or the MCP client config:

| Host | Launcher |
|---|---|
| macOS, Linux | `mcp/docker/s1-secops-mcp-launch.sh [--image sentinelone/secops-mcps:1.5.3] [--profile P] <server>` |
| Windows | `mcp/docker/s1-secops-mcp-launch.ps1 [-Image sentinelone/secops-mcps:1.5.3] [-Profile P] <server>` |

`<server>` is `s1-secops-mcp`, `purple-mcp` or `virustotal-mcp`. Launcher options go before the server name; anything after it is passed to the server inside the container.

On macOS and Linux, install the launcher to `~/.local/bin/` from the repo root and point the client config at that copy:

```bash
mkdir -p ~/.local/bin && cp -X mcp/docker/s1-secops-mcp-launch.sh ~/.local/bin/ && chmod 755 ~/.local/bin/s1-secops-mcp-launch.sh
```

On macOS, a launcher stored under `~/Documents`, `~/Desktop` or `~/Downloads` does not start: macOS blocks Claude Desktop's `/bin/sh` from running scripts in those folders, and the MCP log shows `/bin/sh: .../s1-secops-mcp-launch.sh: Operation not permitted`.

Claude Desktop config (macOS, Linux):

```json
{
  "mcpServers": {
    "s1-secops-mcp":  { "command": "/Users/you/.local/bin/s1-secops-mcp-launch.sh", "args": ["s1-secops-mcp"] },
    "purple-mcp":     { "command": "/Users/you/.local/bin/s1-secops-mcp-launch.sh", "args": ["purple-mcp"] },
    "virustotal-mcp": { "command": "/Users/you/.local/bin/s1-secops-mcp-launch.sh", "args": ["virustotal-mcp"] }
  }
}
```

The config holds no secrets. Set `S1_OUTPUT_DIR` to a host directory if you want `outputFile` results written somewhere you can open: the macOS/Linux launcher mounts it into the container at the same path, and the Windows launcher mounts it at `/output`. Full Docker details are in [docker.md](./docker.md).

All three servers read the same names. `purple-mcp` uses its own variable names internally and the image entrypoint derives them (`S1_CONSOLE_URL` → `PURPLEMCP_CONSOLE_BASE_URL`, `S1_CONSOLE_API_TOKEN` → `PURPLEMCP_CONSOLE_TOKEN`, `VIRUSTOTAL_API_KEY` → `PURPLEMCP_VT_API_KEY`).

Each server receives only the values it uses: `s1-secops-mcp` gets the console, ingest and scope values; `purple-mcp` gets `S1_CONSOLE_URL`, `S1_CONSOLE_API_TOKEN` and `VIRUSTOTAL_API_KEY`; `virustotal-mcp` gets `VIRUSTOTAL_API_KEY` only. Inside the purple-mcp container the entrypoint copies the VirusTotal key to `PURPLEMCP_VT_API_KEY` and then unsets `VIRUSTOTAL_API_KEY` and `VT_API_KEY`, so purple-mcp's threat intelligence tools work from the same keychain entry with no separate setup.

---

## MCP client configs are not a secret store

An `env` block in an MCP client configuration file is plaintext on disk and is copied into backups and dotfile repos. That applies to `claude_desktop_config.json`, `~/.claude.json`, project `.mcp.json`, Cursor `mcp.json`, Windsurf and Zed. Keep tokens out of all of them.

| Client | Do this |
|---|---|
| Claude Desktop (Docker) | Point the server entry at the launcher, as above. |
| Claude Desktop (Node) | `"command": "s1-secops-mcp"` (or `node /path/to/index.js`) with no `env` block; the server reads the keychain. |
| Claude Desktop Extension | The optional `.mcpb` bundle in `mcp/s1-secops-mcp/mcpb/` declares its tokens as `user_config` with `"sensitive": true`, so Claude Desktop stores them in the OS keychain. |
| Claude Code | Register the server with no `env` (`claude mcp add s1-secops-mcp -- s1-secops-mcp`) and let it read the keychain. Use `${VAR}` expansion in `.mcp.json` only when the variable itself comes from a secret manager. |
| VS Code | Use `inputs` with `"password": true`, which VS Code keeps in its secret storage. |
| Cursor, Windsurf, Zed | No secret store for MCP env values: use the keychain (no `env` block) or the Docker launcher. |

---

## Host-only Python scripts

The Python clients in the skills (`S1Client`, `SDLClient`, `pq.py`, `lrq_sliced.py`, the tests and smoke sweeps) run only on your machine, from Claude Code or a terminal. They cannot reach `*.sentinelone.net` from the Cowork sandbox, where the `s1-secops-mcp` tools are the path. They read the same environment variables first, then the same keychain entries (Windows needs `pip install keyring`).

Quick check from a checkout:

```bash
cd s1-secops-skills/mgmt-console-api
pip install requests        # plus keyring on Windows
python scripts/s1_client.py
```

This prints the first 5 accounts and runs 4 parallel GETs to confirm auth and connectivity. A full non-destructive sweep of every readable endpoint: `python scripts/smoke_test_queries.py --workers 12` (results land in `references/tenant_capabilities.{json,md}`).

---

## Token types

The S1 API has two token types and they are not interchangeable for all operations:

| Token type | Created via | Visible in UI | Notes |
|---|---|---|---|
| Service User token | Settings → Users → Service Users | No: workflows/rules created with this token are invisible to human users in the UI | Use for programmatic API access |
| Personal Console User token | Settings → Users → My User → API Token | Yes: objects created are visible and attributed to the user | Required for Hyperautomation workflows to appear in the UI |

For most skills a service user token is correct. If you need Hyperautomation workflows to be visible and editable in the console UI, store a personal console user token under its own profile (`s1-secops-mcp setup --profile personal`) and run the server with `S1_PROFILE=personal` for that work.

**Multi-account tokens:** some endpoints reject a token whose user spans several accounts with `HTTP 403 code 4030010` ("This page doesn't support multi-scopes users yet"), including IOC writes on `/threat-intelligence/iocs`. Use a console API token minted at a single account or site; store it in its own keychain profile (`s1-secops-mcp setup --profile <name>`) and run a second MCP entry with `S1_PROFILE=<name>` (or make that token your default). The `s1_api_*` tools add this hint to the error when they see code 4030010.

---

## What the keychain protects, and what it does not

- **Protected:** secrets at rest. They are encrypted by the OS, locked with your login session, and absent from plaintext config files, dotfile repos and backups of those files. Tool output and server logs mask token values.
- **Not protected:** other processes running as your user. Any process running as the same user can read a `sentinelone-mcp` item without a prompt. This was measured on macOS for items created by `/usr/bin/security` and by Node. Malware or an untrusted tool running under your account can therefore read the tokens, exactly as it could read a file in your home directory.

So treat the tokens as you would any credential on a workstation: least-privilege service users, tokens minted at a single account or site where possible, short expiry, and rotation when a machine or account is suspected compromised (see [Rotate a token](#rotate-a-token)).
