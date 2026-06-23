# Claude Desktop bridge for the remote MCP

A small stdio↔HTTPS proxy so Claude Desktop can talk to a team-shared `s1-secops-mcp` server running on a VM. Each team member runs the bridge on their own machine; the bridge sends bearer-authed POSTs to the shared MCP endpoint.

## Why this exists

Claude Desktop's `claude_desktop_config.json` only accepts stdio-based MCP servers in current stable builds. Adding a remote server via `type: "http"` gets rejected with "not valid MCP server configuration". The bridge wraps the remote HTTPS endpoint as a local stdio process, which Claude Desktop accepts.

Claude Cowork and Claude Code don't need this — both support `type: "http"` natively.

## What's in the box

- [`s1-secops-mcp-bridge.mjs`](./s1-secops-mcp-bridge.mjs) — the script. 40 lines, zero external dependencies. Requires Node.js 18+ (uses the built-in `fetch`).

## Install (per team member, one-time)

```bash
# Download the script
mkdir -p ~/.local/bin
curl -fsSL https://raw.githubusercontent.com/Sentinel-One/ai-siem/main/mcp/s1-secops-mcp/deploy/bridge/s1-secops-mcp-bridge.mjs \
  -o ~/.local/bin/s1-secops-mcp-bridge.mjs
chmod +x ~/.local/bin/s1-secops-mcp-bridge.mjs

# Confirm Node is on PATH
node --version   # must be 18.0.0 or newer
```

## Configure Claude Desktop

Edit `~/Library/Application Support/Claude/claude_desktop_config.json` on macOS, or `%APPDATA%\Claude\claude_desktop_config.json` on Windows. Add the `s1-secops-mcp` block:

```json
{
  "mcpServers": {
    "s1-secops-mcp": {
      "command": "node",
      "args": ["/Users/<you>/.local/bin/s1-secops-mcp-bridge.mjs"],
      "env": {
        "MCP_URL":    "https://mcp.s1.internal/mcp",
        "MCP_BEARER": "<your personal bearer token>"
      }
    }
  }
}
```

`MCP_URL` is whatever URL your team's admin gave you (it should end in `/mcp`). `MCP_BEARER` is your personal bearer token from `/etc/s1-secops-mcp/bearer-tokens.json` on the VM.

Quit Claude Desktop fully (Cmd+Q on macOS, not just close the window) and reopen. The 26 tools should appear in the tools list.

## Smoke test (without Claude Desktop)

```bash
export MCP_URL='https://mcp.s1.internal/mcp'
export MCP_BEARER='<your token>'

# initialize round trip
echo '{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"cli","version":"1"}}}' \
  | node ~/.local/bin/s1-secops-mcp-bridge.mjs

# tools/list (should return 26)
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' \
  | node ~/.local/bin/s1-secops-mcp-bridge.mjs \
  | python3 -c 'import sys,json; print(len(json.load(sys.stdin)["result"]["tools"]), "tools")'
```

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Claude Desktop log: `MCP error -32001: Request timed out` | `MCP_URL` unreachable or wrong path | `curl -sS $MCP_URL` from the same machine. Confirm the URL ends with `/mcp`. |
| `fetch error: ... UNABLE_TO_GET_ISSUER_CERT_LOCALLY` | Server is using a private CA (e.g. `tls internal`); Node doesn't read the system keychain | Use a publicly-trusted cert on the server (Let's Encrypt or ZeroSSL). See [../README.md#aws-specific-gotchas](../README.md#aws-specific-gotchas). |
| `bridge fetch error: ... ENOTFOUND` | DNS doesn't resolve `MCP_URL` host | Verify with `nslookup` or `dig`. If using an AWS public DNS, it may have changed; re-check the EC2 console. |
| 401 from upstream in the log | Wrong / revoked bearer token | Ask the admin for a fresh token; replace `MCP_BEARER`. |
| Bridge starts but Claude Desktop times out | Node version too old | `node --version` — need 18+. Built-in fetch was added in 18. |

## How it works

```
+----------------+          stdio JSON-RPC          +--------+        HTTPS POST /mcp        +------+
| Claude Desktop | <------------------------------> | bridge | <---------------------------> | VM   |
+----------------+                                  +--------+   Bearer auth, JSON in/out    +------+
```

The bridge reads one JSON-RPC message per line from stdin, POSTs it to `MCP_URL` with the `Authorization: Bearer <token>` header, and writes the JSON-RPC reply to stdout. JSON-RPC notifications (messages with no `id`) get no reply, matching the spec. Errors get translated to a JSON-RPC error envelope so Claude Desktop sees something useful instead of a hung process.

There is no session state, no buffering, and no SDK dependency — it's just stdin → fetch → stdout.

## Security notes

- The bearer token is stored in plaintext in `claude_desktop_config.json`. Treat that file as a secret on each laptop.
- Rotate bearer tokens by editing `/etc/s1-secops-mcp/bearer-tokens.json` on the VM (see [../README.md#day-2-operations](../README.md#day-2-operations)) and reissuing the new value to each team member.
- TLS verification uses Node's bundled CA store. For privately-issued certs, set `NODE_EXTRA_CA_CERTS=/path/to/root.pem` in the `env` block. Better: use a publicly-trusted cert on the server so no client-side trust is needed.
