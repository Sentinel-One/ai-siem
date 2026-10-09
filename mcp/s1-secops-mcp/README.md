# SentinelOne MCP Server

Model Context Protocol server orchestrating the SentinelOne Management Console, Singularity Data Lake, UAM Alert Interface, and Hyperautomation APIs. Pure Node.js, zero required dependencies, stdio transport (Claude Desktop, Cowork, Claude Code, and any client that launches the server as a subprocess).

Each user runs their own instance on their own machine, with their own credentials, which resolve from environment variables and then the OS keychain. There is no credentials file, no HTTP transport, and no shared team server (all three were removed in 1.5.0; see [docs/upgrading.md](../../plugins/s1-secops-skills/docs/upgrading.md#14x-to-150)).

## What this exposes

<!-- BEGIN AUTO-GENERATED TOOLS TABLE -->
**35 tools** across PowerQuery, Mgmt Console, SDL API, Hyperautomation, and UAM Ingest:

| Group | Tool | Skill |
|-------|------|-------|
| PowerQuery | `powerquery_enumerate_sources` | powerquery |
| PowerQuery | `powerquery_run` | powerquery |
| PowerQuery | `powerquery_schema_discover` | powerquery |
| Mgmt Console | `purple_ai_alert_summary` | mgmt-console-api |
| Mgmt Console | `s1_api_delete` | mgmt-console-api |
| Mgmt Console | `s1_api_download` | mgmt-console-api |
| Mgmt Console | `s1_api_get` | mgmt-console-api |
| Mgmt Console | `s1_api_patch` | mgmt-console-api |
| Mgmt Console | `s1_api_post` | mgmt-console-api |
| Mgmt Console | `s1_api_put` | mgmt-console-api |
| Mgmt Console | `uam_add_note` | mgmt-console-api |
| Mgmt Console | `uam_assign_alert` | mgmt-console-api |
| Mgmt Console | `uam_available_actions` | mgmt-console-api |
| Mgmt Console | `uam_get_alert` | mgmt-console-api |
| Mgmt Console | `uam_list_alerts` | mgmt-console-api |
| Mgmt Console | `uam_set_status` | mgmt-console-api |
| Mgmt Console | `uam_set_verdict` | mgmt-console-api |
| SDL API | `hec_ingest` | sdl-api / sdl-log-parser |
| SDL API | `sdl_create_dashboard` | sdl-api / sdl-dashboard |
| SDL API | `sdl_delete_dashboard` | sdl-api / sdl-dashboard |
| SDL API | `sdl_delete_file` | sdl-api |
| SDL API | `sdl_get_dashboard` | sdl-api / sdl-dashboard |
| SDL API | `sdl_get_file` | sdl-api / sdl-dashboard / sdl-log-parser |
| SDL API | `sdl_list_dashboards` | sdl-api / sdl-dashboard |
| SDL API | `sdl_list_files` | sdl-api / sdl-dashboard / sdl-log-parser |
| SDL API | `sdl_put_file` | sdl-api / sdl-dashboard / sdl-log-parser |
| SDL API | `sdl_save_dashboard_layout` | sdl-api / sdl-dashboard |
| SDL API | `sdl_share_dashboard` | sdl-api / sdl-dashboard |
| Hyperautomation | `ha_delete_workflow` | hyperautomation |
| Hyperautomation | `ha_export_workflow` | hyperautomation |
| Hyperautomation | `ha_get_workflow` | hyperautomation |
| Hyperautomation | `ha_import_workflow` | hyperautomation |
| Hyperautomation | `ha_list_workflows` | hyperautomation |
| UAM Ingest | `uam_ingest_alert` | mgmt-console-api (UAM Alert Interface) |
| UAM Ingest | `uam_post_alert` | mgmt-console-api (UAM Alert Interface) |
<!-- END AUTO-GENERATED TOOLS TABLE -->

Per-tool parameters and usage notes, including the 1.5.0 additions (`powerquery_run` `queryType: "LOG"`, `slices` + `merge`, `outputFile`; `s1_api_download`; `outputFile` on `s1_api_get` and `ha_export_workflow`), are in **[docs/mcp-tools.md](../../plugins/s1-secops-skills/docs/mcp-tools.md)**.

**2 resources:**

- `sentinelone://soc-context`: `CLAUDE.md`, the Principal SOC Analyst operating instructions.
- `sentinelone://credentials-status`: which credentials are configured (never their values) and which API surfaces are available.

**2 prompts:**

- `soc_analyst`: embeds `CLAUDE.md` as a system prompt; call at session start.
- `session_init`: structured init: enumerate sources + triage alerts in parallel.

## Quick install

For the end-user install paths, see the canonical **[README Installation section](../../plugins/s1-secops-skills/README.md#installation)**; every credential value, the keychain model and its limits are in **[docs/credentials.md](../../plugins/s1-secops-skills/docs/credentials.md)**. This section is the MCP-server-specific reference.

### A. Docker, through the keychain launcher (recommended)

The server runs in a container on your machine. The host launcher reads your OS keychain and passes the values to the container over stdin, so no secret appears in the client config, in `docker inspect`, or in the process list.

```bash
mkdir -p ~/.local/bin && cp -X docker/s1-secops-mcp-launch.sh ~/.local/bin/ && chmod 755 ~/.local/bin/s1-secops-mcp-launch.sh
~/.local/bin/s1-secops-mcp-launch.sh setup    # once: store values in the OS keychain
```

Point the client at the copy in `~/.local/bin/`, not at the repo checkout. On macOS, Claude Desktop's `/bin/sh` cannot run a script stored under `~/Documents`, `~/Desktop` or `~/Downloads`; the MCP log shows `/bin/sh: .../s1-secops-mcp-launch.sh: Operation not permitted`.

```json
{
  "mcpServers": {
    "s1-secops-mcp": {
      "command": "/Users/you/.local/bin/s1-secops-mcp-launch.sh",
      "args": ["--image", "sentinelone/secops-mcps:1.5.3", "s1-secops-mcp"]
    }
  }
}
```

Windows uses `mcp/docker/s1-secops-mcp-launch.ps1`. The same image serves `purple-mcp` and `virustotal-mcp`; the server-name argument, after any launcher options such as `--image`, selects which one runs. Full reference: [docs/docker.md](../../plugins/s1-secops-skills/docs/docker.md).

### B. Node

From a clone of this repo (Node 24 or later):

```bash
cd ai-siem/mcp/s1-secops-mcp
node index.js setup          # store values in the OS keychain
node index.js status         # confirm where each value resolves from
```

```json
{
  "mcpServers": {
    "s1-secops-mcp": { "command": "node", "args": ["/path/to/ai-siem/mcp/s1-secops-mcp/index.js"] }
  }
}
```

`npm link` in this folder puts the same entry point on your `PATH` as `s1-secops-mcp`, which is the name the docs use for the CLI. No `env` block: the server reads the keychain. On Windows, the keychain backend is the optional `@napi-rs/keyring` package (`npm install @napi-rs/keyring` in this folder); without it, use the Docker launcher or environment variables from a secret manager. Claude Code: `claude mcp add s1-secops-mcp -- node /path/to/ai-siem/mcp/s1-secops-mcp/index.js`.

### C. Claude Desktop Extension (`.mcpb`)

An optional extension bundle lives in [`mcpb/`](./mcpb/). It declares the tokens as `user_config` fields with `"sensitive": true`, so Claude Desktop prompts for them in its UI and stores them in the OS keychain rather than in a config file.

## Credentials

Every value, where to get it, the token types, migration from `credentials.json`, and the security limits are documented canonically in **[docs/credentials.md](../../plugins/s1-secops-skills/docs/credentials.md)**. This section adds the server-specific detail.

To change a stored value, re-run `s1-secops-mcp setup` (Enter keeps the current value) or `s1-secops-mcp setup --name <NAME>` for one value, check with `status`, remove with `forget`, and restart the MCP client, because the server reads the keychain once at start. Profiles, the OS keychain apps and token rotation: [Changing credentials in the keychain](../../plugins/s1-secops-skills/docs/credentials.md#changing-credentials-in-the-keychain).

### Resolution order (per value, highest wins)

1. **Environment variable** of the same name, or one of its aliases: `S1_BASE_URL`, `S1_API_TOKEN`, `SDL_CONSOLE_API_TOKEN`, `S1_UAM_ALERT_INTERFACE_URL`, `SDL_S1_SCOPE`, `VT_API_KEY` (full table: [Resolution order](../../plugins/s1-secops-skills/docs/credentials.md#resolution-order)). Environment values are read live on every call.
2. **OS keychain**, service `sentinelone-mcp`, account `<profile>:<NAME>`, profile from `S1_PROFILE` (default `default`). Read once, lazily, then cached for the process.

There is deliberately no file fallback. Backends: macOS login keychain via `/usr/bin/security`; Linux Secret Service via `secret-tool` (needs a D-Bus session and an unlocked collection; headless hosts use environment variables); Windows Credential Manager via the optional `@napi-rs/keyring`. `S1_KEYCHAIN=off` disables the keychain step; `S1_KEYCHAIN_BACKEND=macos|linux|native` forces a backend.

### Which value gates which tools

| Name | Required for |
|---|---|
| `S1_CONSOLE_URL` | Every Mgmt, PowerQuery, UAM, Hyperautomation and SDL tool |
| `S1_CONSOLE_API_TOKEN` | Every Mgmt, PowerQuery, UAM, Purple AI summary, Hyperautomation and SDL config-file tool, plus UAM alert ingest |
| `S1_HEC_INGEST_URL` | `uam_ingest_alert`, `uam_post_alert`, `hec_ingest` |
| `S1_HEC_TOKEN` | `hec_ingest` only: the SDL Log Write Key. The console token is not a reliable substitute at the event collector (400 `Missing S1-Scope header` without a scope header, 403 code 4 on some consoles either way); the key is minted for one account or site and fixes the destination |
| `S1_SCOPE` | Optional default `S1-Scope` for SDL calls: `<accountId>` or `<accountId>:<siteId>` |

The scoped SDL keys (`SDL_CONFIG_READ_KEY`, `SDL_CONFIG_WRITE_KEY`, `SDL_LOG_READ_KEY`, `SDL_LOG_WRITE_KEY`, `SDL_XDR_URL`) are retired and are no longer read.

IOC writes (`/threat-intelligence/iocs`) refuse a token whose user spans several accounts (HTTP 403, code 4030010), and the `s1_api_*` error says so. Use a console API token minted at a single account or site; store it in its own keychain profile (`s1-secops-mcp setup --profile <name>`) and run a second MCP entry with `S1_PROFILE=<name>` (or make that token your default).

### Redaction and output files

- Token values are masked in every tool response and every log line.
- `outputFile` (on `powerquery_run`, `s1_api_get`, `s1_api_download`, `ha_export_workflow`) writes only inside `S1_OUTPUT_DIRS` (path-list; default: home and temp directories), refuses symlinks and dot or autostart paths below the root, never replaces an existing file unless `overwrite: true`, and creates files mode 0600.

### Security limit

The keychain protects secrets at rest and keeps them out of config files and their backups. It does not isolate them from other processes running as the same user: any such process can read a `sentinelone-mcp` item without a prompt (measured on macOS for items created by `/usr/bin/security` and by Node). See [credentials.md](../../plugins/s1-secops-skills/docs/credentials.md#what-the-keychain-protects-and-what-it-does-not).

## CLI reference

```text
s1-secops-mcp                              Start the MCP server on stdio (what MCP clients launch)
s1-secops-mcp setup [--profile P] [--name N] [--import-json <path>]
                                           Prompt for each value without echo (or read NAME=value
                                           lines from stdin when there is no terminal), store it in
                                           the OS keychain, read it back to verify. --import-json
                                           copies the keys from an old credentials.json; delete the
                                           file afterwards.
s1-secops-mcp status [--profile P]         Show where each value resolves from (env or keychain), masked
s1-secops-mcp forget [--profile P] [--name N]
                                           Remove one value, or every value in the profile
s1-secops-mcp exec [--profile P] -- <command> [args...]
                                           Run another MCP server (purple-mcp, the VirusTotal MCP) with
                                           the keychain values in its environment, mapped to
                                           PURPLEMCP_CONSOLE_BASE_URL, PURPLEMCP_CONSOLE_TOKEN,
                                           PURPLEMCP_VT_API_KEY and VT_API_KEY
s1-secops-mcp --help | --version
```

Run `setup`, `status` and `forget` in a terminal on your own machine, never inside a chat. `--name` takes one of the six names in the table above, or `VIRUSTOTAL_API_KEY`. Other environment settings: `S1_PROFILE`, `S1_KEYCHAIN=off`, `S1_KEYCHAIN_BACKEND`, `S1_KEYCHAIN_TIMEOUT_MS` (keychain call timeout, default 15000), `S1_OUTPUT_DIRS`, `S1_CLAUDE_MD_PATH`.

## Tool inputs and outputs

Every tool's input schema is documented in the `tools/list` response (the `inputSchema` JSON Schema on each tool). The response shape is always:

```json
{
  "content": [
    { "type": "text", "text": "<JSON-encoded result>" }
  ],
  "isError": false
}
```

Parse `content[0].text` as JSON to get the actual data the tool returned. Tool-level errors set `isError: true` and put the error text in the same field.

### Row / page limits (measured, not enforced)

The `maxRows` (`powerquery_run`) and `first` (`uam_list_alerts`) parameters are soft client-side hints, not hard backend caps. Live-verified 2026-07-29:

- `powerquery_run` `maxRows`: default 1000, but not a ceiling. The LRQ engine returns as many rows as the query's own `| limit N` asks for. A `| limit 20000` query with `maxRows: 20000` returned 20,000 rows in a single response. For large results pass `outputFile` instead, which keeps every row on disk and returns a summary. `queryType: "LOG"` is different: the server caps it at `logLimit` (max 5000) per query or slice and reports `truncatedByServerCap`.
- `uam_list_alerts` `first`: default 20, not enforced client-side. The UAM GraphQL backend accepts larger pages: `first: 500` returned 500 alerts with `pageInfo.hasNextPage: true`. Paginate with the returned `pageInfo.endCursor` via `after` rather than requesting one unbounded page.

## Architecture

```text
s1-secops-mcp/
  index.js                    Entry: CLI (setup / status / forget / exec) or the stdio server
  lib/
    cli.js                    setup / status / forget / exec subcommands
    server-core.js            Tool registry, JSON-RPC dispatch
    stdio-transport.js        stdin/stdout JSON-RPC loop
    keystore.js               OS keychain backends (macOS security, Linux secret-tool, @napi-rs/keyring)
    credentials.js            Per-value resolution: env, then keychain
    redact.js                 Masks token values in tool output and logs
    output.js                 outputFile path checks and 0600 writes
    slicing.js                Parallel LRQ time slices and merge rules
    s1.js                     Mgmt REST + LRQ PowerQuery + Purple AI + UAM GraphQL
    sdl.js                    SDL config files, dashboards, V1 query
    hec.js                    Event collector ingest
    uam-ingest.js             UAM Alert Interface ingestion
  tools/
    powerquery.js             PowerQuery enumerate / run / schema-discover
    mgmt-console.js           S1 REST verbs, binary download, Purple AI summary, UAM
    sdl-api.js                SDL config file, dashboard and log ingestion tools
    hyperautomation.js        Hyperautomation list / get / import / export / delete
    uam-ingest.js             UAM Alert Interface ingestion tools
  mcpb/                       Optional Claude Desktop Extension bundle
  scripts/
    regen-readme-tools-table.mjs   Tools-table regenerator (no drift)
  tests/                      node --test suites
```

## Auth patterns (implemented)

| API surface | Auth header | Key |
|-------------|-------------|-----|
| S1 Mgmt REST API | `Authorization: ApiToken <jwt>` | `S1_CONSOLE_API_TOKEN` |
| LRQ PowerQuery | `Authorization: Bearer <jwt>`; scope is `tenant: false` + `accountIds` in the body plus a `site.id` term for a site (the `S1-Scope` header does not narrow event rows on a multi-account token, but it still picks which scope's copy of a lookup table is read) | Same token, different prefix |
| Purple AI GraphQL | `Authorization: ApiToken <jwt>` | `S1_CONSOLE_API_TOKEN` |
| UAM GraphQL | `Authorization: ApiToken <jwt>` | `S1_CONSOLE_API_TOKEN` |
| UAM alert ingest (`/v1/alerts`) | `Authorization: Bearer <jwt>`, `S1-Scope` required | `S1_CONSOLE_API_TOKEN` |
| Event collector log ingest | `Authorization: Bearer <write-key>` (`Splunk <write-key>` also accepted), no `S1-Scope`; the key's mint scope decides where events land | `S1_HEC_TOKEN` (the console token is not a reliable substitute: 400 `Missing S1-Scope header` without a scope header, 403 `User token not allowed for this endpoint` on some consoles either way) |
| SDL config files (`POST /sdl/v2/graphql`) | `Authorization: Bearer <jwt>`, plus an `s1-scope` header that IS honoured: listings and reads are scope-filtered (measured 113 files at account scope vs 4 at a site scope) | `S1_CONSOLE_API_TOKEN`, optional `S1_SCOPE` |

## Testing

```bash
npm test
```

The suites under `tests/` run with `S1_KEYCHAIN=off` or a stubbed keychain and need no tenant. `smoke.test.mjs` introspects `ALL_TOOLS` directly and asserts the tool set by name, which catches drift between code and the README regenerator; the stdio suite spawns the server and exercises `initialize`, `tools/list`, `resources/list`, `prompts/list`, and error handling.

The smoke suite is the source of truth for the tool count and is what `scripts/regen-readme-tools-table.mjs` derives the README table from. If the table goes stale, `npm run regen:readme -- --check` exits 1 (it is not wired into the CI workflows); `npm run regen:readme` fixes it. A new tool needs an entry in the script's `TOOL_SKILL` map first, or the script stops with `Missing TOOL_SKILL mapping`.

## Updating CLAUDE.md

The `sentinelone://soc-context` resource and `soc_analyst` prompt load `CLAUDE.md` at server startup. Resolution order:

1. `S1_CLAUDE_MD_PATH` env var (explicit absolute path).
2. `<cwd>/CLAUDE.md`: your Cowork project folder, when launched from there.
3. Same-dir / parent / grandparent of the server's `index.js`: when running from a git clone.

Without a CLAUDE.md nearby, set `S1_CLAUDE_MD_PATH` in the server entry's `env` block (a path, not a secret) to point at the one in your Cowork project folder. Restart Claude Desktop to pick up edits.

## Known client issue: omitted parameters that declare a default are rejected

On affected Claude Code / Claude Desktop builds, calling one of the tools below without
passing **every** parameter fails before the request reaches this server:

```text
MCP error -32602: Input validation error: Invalid arguments for tool powerquery_run: [
  { "code": "invalid_type", "expected": "nonoptional", "path": ["maxRows"],
    "message": "Invalid input: expected nonoptional, received undefined" } ]
```

**This is not a defect in this server, and upgrading it will not fix it.** This package
does not use zod; those are Zod v4 error codes, emitted by the host, and the error arrives
before dispatch. The host converts a tool's JSON Schema into a validator and maps a property
carrying `default` to a non-optional field, so an absent value raises an error instead of
taking the default. It validates against the schema's *output* type rather than its *input*
type. Any MCP server that declares defaults is affected.

**Workaround:** pass every parameter explicitly, including the ones you want at their
default value.

**Affected tools and parameters:**

| Tool | Parameters carrying a `default` |
|---|---|
| `ha_list_workflows` | `limit`, `skip`, `sortBy`, `sortOrder` |
| `uam_list_alerts` | `first`, `viewType` |
| `powerquery_run` | `hours`, `maxRows` |
| `powerquery_schema_discover` | `maxEvents`, `startTime` |
| `powerquery_enumerate_sources` | `hours` |
| `sdl_create_dashboard` | `isPublic` |
| `uam_ingest_alert` | `title`, `hostname`, `filename`, `inline` |

Every other tool is unaffected, and within these tools only the listed parameters are
rejected. Parameters without a default (`query`, `scope`, `startTime` on
`powerquery_run`, `status`, `severity`, `siteIds`) work when omitted.

Parameters added in 1.3.9 (`limit` and `offset` on `sdl_list_dashboards` and
`sdl_list_files`, `namesOnly` on `sdl_list_dashboards` only) and the 1.5.0 parameters (`queryType`, `logLimit`, `slices`, `merge`,
`outputFile`, `overwrite`) deliberately omit the `default` keyword and document
their defaults in the parameter description instead, so they are not affected. Reported
upstream; when the host is fixed, the defaults can go back into the schemas.

## Removed

- **1.5.0:** the Streamable HTTP transport (`--transport http`, `--host`, `--port`, `--path`), bearer-token auth (`MCP_BEARER_TOKENS`, `MCP_BEARER_TOKENS_FILE`), the audit log, the shared-VM deployment (`deploy/`: install script, systemd unit, Caddy template, stdio bridge), and every `credentials.json` location (`S1_CREDS_FILE`, `COWORK_WORKSPACE`, working-directory walk-up, `~/mnt/*`, `CLAUDE_CONFIG_DIR`, `~/.config/sentinelone`). Migrate with `s1-secops-mcp setup --import-json <file>`.
- **2026-05-03:** `purple_ai_query` and `purple_ai_investigate`. Both required a browser-session `teamToken` from `/sdl/v2/graphql` that service-account API tokens never obtain (returns `AsimovError` / `SERVICE_ERROR`). Use `mcp__purple-mcp__purple_ai` instead, which holds the right credentials.

## Version history

See [CHANGELOG.md](./CHANGELOG.md).
