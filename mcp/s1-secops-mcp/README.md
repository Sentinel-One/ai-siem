# SentinelOne MCP Server

Model Context Protocol server orchestrating the SentinelOne Management Console, Singularity Data Lake, UAM Alert Interface, and Hyperautomation APIs. Pure Node.js 18+, zero external dependencies. Supports both stdio (for Claude Desktop / Cowork / Claude Code) and Streamable HTTP (for team-shared VM deployments) transports.

- **Single-user, local:** install with `npx`, plug into Claude Desktop in 30 seconds.
- **Team, VM-hosted:** install on one Linux box, per-user bearer tokens, audit logs, SIGHUP-reloadable rotation.

See **[deploy/README.md](./deploy/README.md)** for the full deployment walkthrough across all three topologies.

## What this exposes

<!-- BEGIN AUTO-GENERATED TOOLS TABLE -->
**26 tools** across PowerQuery, Mgmt Console, SDL API, Hyperautomation, and UAM Ingest:

| Group | Tool | Skill |
|-------|------|-------|
| PowerQuery | `powerquery_enumerate_sources` | sentinelone-powerquery |
| PowerQuery | `powerquery_run` | sentinelone-powerquery |
| PowerQuery | `powerquery_schema_discover` | sentinelone-powerquery |
| Mgmt Console | `purple_ai_alert_summary` | sentinelone-mgmt-console-api |
| Mgmt Console | `s1_api_delete` | sentinelone-mgmt-console-api |
| Mgmt Console | `s1_api_get` | sentinelone-mgmt-console-api |
| Mgmt Console | `s1_api_patch` | sentinelone-mgmt-console-api |
| Mgmt Console | `s1_api_post` | sentinelone-mgmt-console-api |
| Mgmt Console | `s1_api_put` | sentinelone-mgmt-console-api |
| Mgmt Console | `uam_add_note` | sentinelone-mgmt-console-api |
| Mgmt Console | `uam_get_alert` | sentinelone-mgmt-console-api |
| Mgmt Console | `uam_list_alerts` | sentinelone-mgmt-console-api |
| Mgmt Console | `uam_set_status` | sentinelone-mgmt-console-api |
| SDL API | `sdl_delete_file` | sentinelone-sdl-api |
| SDL API | `sdl_get_file` | sentinelone-sdl-api / sdl-dashboard / sdl-log-parser |
| SDL API | `sdl_list_files` | sentinelone-sdl-api / sdl-dashboard / sdl-log-parser |
| SDL API | `sdl_put_file` | sentinelone-sdl-api / sdl-dashboard / sdl-log-parser |
| SDL API | `hec_ingest` | sentinelone-sdl-api / sdl-log-parser |
| Hyperautomation | `ha_delete_workflow` | sentinelone-hyperautomation |
| Hyperautomation | `ha_export_workflow` | sentinelone-hyperautomation |
| Hyperautomation | `ha_get_workflow` | sentinelone-hyperautomation |
| Hyperautomation | `ha_import_workflow` | sentinelone-hyperautomation |
| Hyperautomation | `ha_list_workflows` | sentinelone-hyperautomation |
| UAM Ingest | `uam_ingest_alert` | sentinelone-mgmt-console-api (UAM Alert Interface) |
| UAM Ingest | `uam_post_alert` | sentinelone-mgmt-console-api (UAM Alert Interface) |
| UAM Ingest | `uam_post_indicators` | sentinelone-mgmt-console-api (UAM Alert Interface) |
<!-- END AUTO-GENERATED TOOLS TABLE -->

**2 resources:**
- `sentinelone://soc-context` — `CLAUDE.md`, the Principal SOC Analyst operating instructions.
- `sentinelone://credentials-status` — which credentials are configured and which API surfaces are available.

**2 prompts:**
- `soc_analyst` — embeds `CLAUDE.md` as a system prompt; call at session start.
- `session_init` — structured init: enumerate sources + triage alerts in parallel.

## Quick install

Three paths, pick the one that matches your setup:

### A. Local single-user via `npx` (Claude Desktop / Claude Code / Cowork)

MCP runs as a subprocess on your machine, talking SentinelOne APIs directly. Credentials live in the Claude config `env` block.

Add this to `claude_desktop_config.json` (or `.mcp.json` for Claude Code):

```json
{
  "mcpServers": {
    "s1-secops-mcp": {
      "command": "npx",
      "args": ["-y", "@pmoses-s1/s1-secops-mcp@1.2.2"],
      "env": {
        "S1_CONSOLE_URL":       "https://usea1-yourorg.sentinelone.net",
        "S1_CONSOLE_API_TOKEN": "eyJ...",
        "S1_HEC_INGEST_URL":    "https://ingest.us1.sentinelone.net",
        "SDL_XDR_URL":          "https://xdr.us1.sentinelone.net",
        "SDL_LOG_READ_KEY":     "...",
        "SDL_CONFIG_READ_KEY":  "...",
        "SDL_CONFIG_WRITE_KEY": "..."
      }
    }
  }
}
```

Restart Claude Desktop. `npx -y` caches the package on first launch.

### B. Reproducible: install script

```bash
curl -fsSL https://raw.githubusercontent.com/Sentinel-One/ai-siem/main/mcp/s1-secops-mcp/deploy/install.sh | bash
```

Sets up a per-user npm prefix if needed, installs the package, drops a credentials skeleton at `~/.config/sentinelone/credentials.json` (mode 0600), and prints the wiring instructions for Claude Desktop.

For VM deployments, the same script in `--server` mode does everything (system user, systemd unit, initial bearer token, service start). See [deploy/README.md](./deploy/README.md).

### C. Claude Desktop connecting to a team VM (stdio bridge)

When the MCP is running as a shared service on a Linux VM (deploy topology C in [deploy/README.md](./deploy/README.md)) and you're connecting from Claude Desktop, you need a small stdio↔HTTPS shim because Claude Desktop's stable build doesn't accept `type: "http"` configs. (Claude Cowork and Claude Code do; see "[Calling the HTTP endpoint directly](#calling-the-http-endpoint-directly)" for the native `type: "http"` form.)

The bridge is a 40-line zero-dependency Node script shipped at [`deploy/bridge/s1-secops-mcp-bridge.mjs`](./deploy/bridge/s1-secops-mcp-bridge.mjs).

Each team member installs the script once:

```bash
mkdir -p ~/.local/bin
curl -fsSL https://raw.githubusercontent.com/Sentinel-One/ai-siem/main/mcp/s1-secops-mcp/deploy/bridge/s1-secops-mcp-bridge.mjs \
  -o ~/.local/bin/s1-secops-mcp-bridge.mjs
chmod +x ~/.local/bin/s1-secops-mcp-bridge.mjs
```

Then adds this block to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "s1-secops-mcp": {
      "command": "node",
      "args": ["/Users/<you>/.local/bin/s1-secops-mcp-bridge.mjs"],
      "env": {
        "MCP_URL":    "https://mcp.example.internal:8764/mcp",
        "MCP_BEARER": "<your personal bearer token>"
      }
    }
  }
}
```

Cmd+Q and reopen Claude Desktop. SentinelOne credentials live on the VM in `/etc/s1-secops-mcp/credentials.json` — only the bearer token sits in each user's local Claude config. Full setup + smoke-test instructions at [`deploy/bridge/README.md`](./deploy/bridge/README.md).

## Credentials

`S1_CONSOLE_URL` and `S1_CONSOLE_API_TOKEN` are sufficient for the PowerQuery, Mgmt Console REST, Purple AI summary, and UAM tools (16 of the 26).

`S1_HEC_INGEST_URL` is **required** for the three UAM Ingest tools (`uam_ingest_alert`, `uam_post_indicators`, `uam_post_alert`) and for `hec_ingest`. Without it those tools error at call time; the rest still work.

`SDL_*` keys gate the SDL tools as follows:

| Variable | Description | Required for |
|----------|-------------|--------------|
| `S1_CONSOLE_URL` | Console URL, e.g. `https://usea1-acme.sentinelone.net` | All Mgmt + PowerQuery tools |
| `S1_CONSOLE_API_TOKEN` | Mgmt Console API token (Settings → Users → Service Users) | All Mgmt + PowerQuery + UAM tools |
| `S1_HEC_INGEST_URL` | HEC ingest host, e.g. `https://ingest.us1.sentinelone.net` | `uam_ingest_alert`, `uam_post_indicators`, `uam_post_alert`, `hec_ingest` |
| `SDL_XDR_URL` | SDL tenant URL, e.g. `https://xdr.us1.sentinelone.net` | All `sdl_*` tools and `powerquery_schema_discover` |
| `SDL_LOG_READ_KEY` | SDL Log Read key | SDL query operations |
| `SDL_CONFIG_READ_KEY` | SDL Config Read key | `sdl_list_files`, `sdl_get_file` |
| `SDL_CONFIG_WRITE_KEY` | SDL Config Write key | `sdl_put_file`, `sdl_delete_file` |

### Credential resolution order (highest priority wins)

1. Environment variables (set in `claude_desktop_config.json` `env`, systemd `EnvironmentFile`, or your shell).
2. `S1_CREDS_FILE` — explicit path to a JSON file (recommended for VM deployments and secret-store integrations).
3. `COWORK_WORKSPACE/credentials.json`.
4. Walk-up from the current working directory looking for `credentials.json`.
5. `~/mnt/<folder>/credentials.json` (Cowork workspace mounts).
6. `$CLAUDE_CONFIG_DIR/sentinelone/credentials.json`.
7. `~/.config/sentinelone/credentials.json`.

The server logs the resolved credential source at startup so you can diagnose surprise overrides.

## Transport modes

### stdio (default)

The transport used by Claude Desktop, Claude Code, Claude Cowork, and any other client launched via `npx` / `node index.js`.

```bash
s1-secops-mcp                          # auto-discovers credentials
node index.js                            # same as above, from a local clone
```

### Streamable HTTP

```bash
s1-secops-mcp --transport http                       # 127.0.0.1:8765/mcp, no auth
s1-secops-mcp --transport http --host 0.0.0.0        # all interfaces, no auth (loud warning)
MCP_BEARER_TOKENS_FILE=/etc/s1-secops-mcp/bearer-tokens.json \
  s1-secops-mcp --transport http --host 0.0.0.0      # team mode with per-user tokens
```

Configuration via flags or environment variables:

| Flag | Env var | Default | Purpose |
|------|---------|---------|---------|
| `--transport` | `MCP_TRANSPORT` | `stdio` | `stdio` or `http`. |
| `--host` | `MCP_HTTP_HOST` | `127.0.0.1` | HTTP bind address. Use `0.0.0.0` for cross-host access. |
| `--port` | `MCP_HTTP_PORT` | `8765` | HTTP port. |
| `--path` | `MCP_HTTP_PATH` | `/mcp` | MCP endpoint path. |

In HTTP mode the server exposes:

- `POST /mcp` — accepts JSON-RPC, returns JSON-RPC. The MCP entry point.
- `GET /healthz` — returns `200 ok`. For load balancer probes; no auth.

### Team auth: bearer tokens

To enable team auth, set one of:

- `MCP_BEARER_TOKENS_FILE=/path/to/file.json` (recommended). The file is `{ "<name>": "<token>", ... }`. Names appear in audit logs; revoking a user is a one-line edit. SIGHUP reloads without restart.
- `MCP_BEARER_TOKENS="token1,token2,..."` (fallback, no per-user names).

Token rotation:

```bash
sudo vim /etc/s1-secops-mcp/bearer-tokens.json   # add/remove entries
sudo systemctl reload s1-secops-mcp              # SIGHUP, no connection drops
```

If neither env var is set, HTTP transport runs **without** authentication and the server logs a warning at startup. That's acceptable for `--host 127.0.0.1` single-user use; never use it on `0.0.0.0` in production.

### Audit log

Every authenticated HTTP request emits a structured stderr line that systemd captures via journald:

```
[audit] 2026-05-28T15:01:22.413Z | alice | tools/call | name=powerquery_run | 200 ok
[audit] 2026-05-28T15:01:34.221Z | bob   | tools/list | -                  | 200 ok
[audit] 2026-05-28T17:03:11.221Z | -     | -          | -                  | 401 unauthorized
```

## Calling the HTTP endpoint directly

You don't need an MCP client library. The HTTP transport is plain JSON-RPC 2.0 over `POST`, with bearer auth in the `Authorization` header. Any HTTP client works — `curl`, Python `requests`, Node `fetch`, Go `net/http`, etc. This is how you'd integrate from a custom script, a CI job, or a non-MCP tool that just needs to call SentinelOne via the same wrapped surface.

> **Ready-made check:** [`scripts/smoke-test-http.sh`](./scripts/smoke-test-http.sh) runs the six contract checks documented below (healthz, initialize, tools/list, tools/call, bad-bearer 401, unknown-method JSON-RPC error) and prints PASS/FAIL. Run as `MCP_HOST=<host:port> MCP_BEARER=<token> bash s1-secops-mcp/scripts/smoke-test-http.sh`. Good for new-team-member onboarding and post-rotation validation.

### Endpoint contract

| Item | Value |
|---|---|
| Method | `POST` |
| URL | `https://<host>:<port>/mcp` (path is `/mcp` by default; configurable with `--path`) |
| `Content-Type` | `application/json` |
| `Authorization` | `Bearer <token>` (one of the tokens in `MCP_BEARER_TOKENS_FILE`) |
| Body | JSON-RPC 2.0 envelope |
| Response | JSON-RPC 2.0 envelope (`result` on success, `error` on failure) |

Health probe (no auth, no JSON): `GET /healthz` returns `200 ok`.

### Initialize, then list tools, then call one (curl)

```bash
HOST=mcp.s1.internal
TOKEN='your-bearer-token-here'

# 1. initialize (required first call per spec; advertises protocol version and capabilities)
curl -s -X POST "https://$HOST/mcp" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
          "protocolVersion": "2024-11-05",
          "capabilities": {},
          "clientInfo": { "name": "my-script", "version": "1.0" }
        }
      }'
# -> {"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05","capabilities":{...},"serverInfo":{...}}}

# 2. list every tool the server exposes
curl -s -X POST "https://$HOST/mcp" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
  | jq '.result.tools | length'
# -> 26

# 3. call a tool (here: list custom detection rules with the mandatory isLegacy=false)
curl -s -X POST "https://$HOST/mcp" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
          "name": "s1_api_get",
          "arguments": {
            "path": "/web/api/v2.1/cloud-detection/rules",
            "params": { "isLegacy": false, "limit": 50 }
          }
        }
      }' \
  | jq '.result.content[0].text | fromjson | .pagination.totalItems'
```

### Python (requests)

```python
import json
import requests

URL    = "https://mcp.s1.internal/mcp"
TOKEN  = "your-bearer-token-here"
HEADERS = {
    "Authorization": f"Bearer {TOKEN}",
    "Content-Type":  "application/json",
}

def rpc(method, params=None, id=1):
    body = {"jsonrpc": "2.0", "id": id, "method": method}
    if params is not None:
        body["params"] = params
    r = requests.post(URL, headers=HEADERS, json=body, timeout=30)
    r.raise_for_status()
    return r.json()

# initialize once per session
rpc("initialize", {
    "protocolVersion": "2024-11-05",
    "capabilities": {},
    "clientInfo": {"name": "python-client", "version": "1.0"},
}, id=0)

# list tools
tools = rpc("tools/list", id=1)["result"]["tools"]
print(f"{len(tools)} tools available")

# call a tool
resp = rpc("tools/call", {
    "name": "powerquery_run",
    "arguments": {
        "query": "dataSource.name=* | group count=count() by dataSource.name | sort -count | limit 10",
        "hours": 24,
    },
}, id=2)

# Tool results live in result.content[0].text as a JSON string.
payload = json.loads(resp["result"]["content"][0]["text"])
print(json.dumps(payload, indent=2))
```

### Node (built-in fetch, Node 18+)

```javascript
const URL    = 'https://mcp.s1.internal/mcp';
const TOKEN  = process.env.MCP_BEARER;

async function rpc(method, params, id = 1) {
  const body = { jsonrpc: '2.0', id, method };
  if (params !== undefined) body.params = params;
  const res = await fetch(URL, {
    method:  'POST',
    headers: {
      'Authorization': `Bearer ${TOKEN}`,
      'Content-Type':  'application/json',
    },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}: ${await res.text()}`);
  return res.json();
}

await rpc('initialize', {
  protocolVersion: '2024-11-05',
  capabilities: {},
  clientInfo: { name: 'node-client', version: '1.0' },
}, 0);

const { result } = await rpc('tools/list', null, 1);
console.log(`${result.tools.length} tools available`);

const call = await rpc('tools/call', {
  name: 'uam_list_alerts',
  arguments: { first: 20, status: 'NEW' },
}, 2);
console.log(JSON.parse(call.result.content[0].text));
```

### JSON-RPC envelope shapes

**Success response:**

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "result": { ... method-specific payload ... }
}
```

**Error response:**

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "error": {
    "code": -32602,
    "message": "Tool not found: bad_tool_name"
  }
}
```

**Notifications** (one-way messages with no `id`, e.g. `notifications/initialized`):

```bash
curl -i -s -X POST "https://$HOST/mcp" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"notifications/initialized"}'
# -> HTTP/2 202 (no body, per JSON-RPC spec)
```

### Error codes you'll actually see

| HTTP | JSON-RPC code | Meaning |
|---|---|---|
| 200 | (none, has `result`) | Success |
| 200 | `-32601` | Method not found (e.g. typo in method name) |
| 200 | `-32602` | Invalid params (tool not found, missing required arg) |
| 200 | `-32603` | Tool handler threw — upstream S1 API error usually |
| 400 | `-32700` | Parse error (malformed JSON body) |
| 400 | `-32600` | Invalid request (e.g. JSON-RPC batch — not supported) |
| 401 | `-32001` | Missing or invalid bearer token |
| 405 | (none) | Wrong HTTP method on `/mcp` (only POST is accepted) |
| 413 | `-32600` | Body exceeds 4 MB |

### Tool inputs and outputs

Every tool's input schema is documented in the `tools/list` response (look at the `inputSchema` JSON Schema on each tool). The response shape is always:

```json
{
  "content": [
    { "type": "text", "text": "<JSON-encoded result>" }
  ],
  "isError": false
}
```

Parse `content[0].text` as JSON to get the actual data the tool returned. Tool-level errors set `isError: true` and put the error text in the same field.

## CLI reference

```
s1-secops-mcp [options]

OPTIONS
  --transport <stdio|http>    Transport. Default: stdio.
  --host <host>               HTTP bind address. Default: 127.0.0.1.
  --port <port>               HTTP port. Default: 8765.
  --path <path>               HTTP MCP endpoint path. Default: /mcp.
  -h, --help                  Show help.
  -v, --version               Show server version.
```

## Architecture

```
s1-secops-mcp/
  index.js                    Entry: flag parsing + transport selection
  lib/
    server-core.js            Tool registry, JSON-RPC dispatch (transport-agnostic)
    stdio-transport.js        stdin/stdout JSON-RPC loop
    http-transport.js         Streamable HTTP (node:http, zero deps)
    auth.js                   Bearer token allowlist with SIGHUP reload
    credentials.js            S1 + SDL credential resolution
    s1.js                     Mgmt REST + LRQ PowerQuery + Purple AI + UAM GraphQL
    sdl.js                    SDL config files + V1 query
    uam-ingest.js             HEC alert/indicator ingestion
  tools/
    powerquery.js             PowerQuery enumerate/run/schema-discover
    mgmt-console.js           S1 REST verbs + Purple AI summary + UAM
    sdl-api.js                SDL config file + log ingestion tools
    hyperautomation.js        Hyperautomation list/get/import/export/delete
    uam-ingest.js             UAM Alert Interface ingestion tools
  deploy/
    install.sh                One-shot installer (Mac and Linux)
    systemd/                  Service unit for Linux VM deployments
    caddy/                    TLS reverse proxy template
    README.md                 Deployment walkthrough
  scripts/
    regen-readme-tools-table.mjs   Tools-table regenerator (no drift)
  tests/                      Smoke + stdio + HTTP test suites (node --test)
```

## Auth patterns (implemented)

| API surface | Auth header | Key |
|-------------|-------------|-----|
| S1 Mgmt REST API | `Authorization: ApiToken <jwt>` | `S1_CONSOLE_API_TOKEN` |
| LRQ PowerQuery | `Authorization: Bearer <jwt>` | Same token, different prefix |
| Purple AI GraphQL | `Authorization: ApiToken <jwt>` | `S1_CONSOLE_API_TOKEN` |
| UAM GraphQL | `Authorization: ApiToken <jwt>` | `S1_CONSOLE_API_TOKEN` |
| UAM HEC ingest | `Authorization: Bearer <jwt>` | `S1_CONSOLE_API_TOKEN` |
| SDL config ops | `Authorization: Bearer <key>` | `SDL_CONFIG_WRITE_KEY` or console JWT |

## Testing

```bash
npm test
```

Three test suites under `tests/`:

- `smoke.test.mjs` — introspects `ALL_TOOLS` directly, no spawning. Asserts 26 tools by name; catches any drift between code and the README regenerator.
- `stdio-transport.test.mjs` — spawns the server in stdio mode, exercises `initialize`, `tools/list`, `resources/list`, `prompts/list`, and error handling.
- `http-transport.test.mjs` — spawns in HTTP mode on a random ephemeral port, exercises `/healthz`, `POST /mcp`, both auth-required and auth-optional flows, and the env-var token fallback.

The smoke suite is the source of truth for the tool count and is what `scripts/regen-readme-tools-table.mjs` derives the README table from. If the table goes stale, `npm run regen:readme -- --check` fails CI; `npm run regen:readme` fixes it.

## Updating CLAUDE.md

The `sentinelone://soc-context` resource and `soc_analyst` prompt load `CLAUDE.md` at server startup. Resolution order:

1. `S1_CLAUDE_MD_PATH` env var (explicit absolute path).
2. `<cwd>/CLAUDE.md` — your Cowork project folder, when launched from there.
3. Same-dir / parent / grandparent of the server's `index.js` — when running from a git clone.

For npx installs without a CLAUDE.md nearby, set `S1_CLAUDE_MD_PATH` in the `env` block of `claude_desktop_config.json` to point at the one in your Cowork project folder. Restart Claude Desktop to pick up edits.

## Removed tools

`purple_ai_query` and `purple_ai_investigate` were removed on 2026-05-03. Both required a browser-session `teamToken` from `/sdl/v2/graphql` that service-account API tokens never obtain (returns `AsimovError` / `SERVICE_ERROR`). Use `mcp__purple-mcp__purple_ai` instead, which holds the right credentials.

## Version history

See [CHANGELOG.md](./CHANGELOG.md).
