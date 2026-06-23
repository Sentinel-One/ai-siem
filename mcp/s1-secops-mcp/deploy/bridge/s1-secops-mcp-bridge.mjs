#!/usr/bin/env node
/**
 * Tiny stdio -> HTTPS bridge for the SentinelOne MCP server running on a VM.
 *
 * Why this exists:
 *   Claude Desktop's stable claude_desktop_config.json only accepts stdio-based
 *   MCP servers; the type:"http" form is rejected. This bridge translates
 *   Claude Desktop's stdio JSON-RPC into POSTs against the MCP HTTP endpoint,
 *   so a single shared HTTPS MCP can serve a whole team's Claude Desktops.
 *
 * Required environment:
 *   MCP_URL     full HTTPS endpoint, e.g. https://mcp.s1.internal/mcp
 *   MCP_BEARER  bearer token (no "Bearer " prefix; the script adds it)
 *
 * Optional:
 *   none. Zero external dependencies. Requires Node.js 18+ for built-in fetch.
 *
 * Configure Claude Desktop:
 *   {
 *     "mcpServers": {
 *       "s1-secops-mcp": {
 *         "command": "node",
 *         "args": ["/Users/<you>/.local/bin/s1-secops-mcp-bridge.mjs"],
 *         "env": {
 *           "MCP_URL":    "https://mcp.s1.internal/mcp",
 *           "MCP_BEARER": "<your bearer token>"
 *         }
 *       }
 *     }
 *   }
 *
 * Smoke test:
 *   MCP_URL=... MCP_BEARER=... bash -c '
 *     echo "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}" \
 *     | node s1-secops-mcp-bridge.mjs'
 *   # -> JSON-RPC response with 26 tools in result.tools[]
 */

import { createInterface } from 'node:readline';

const URL    = process.env.MCP_URL    || (() => { throw new Error('MCP_URL not set'); })();
const BEARER = process.env.MCP_BEARER || (() => { throw new Error('MCP_BEARER not set'); })();

const log = (...a) => process.stderr.write('[bridge] ' + a.join(' ') + '\n');

log('starting; target', URL);

const rl = createInterface({ input: process.stdin, terminal: false });

let inFlight = 0;
let stdinClosed = false;
function maybeExit() {
  if (stdinClosed && inFlight === 0) {
    log('all requests complete, exiting');
    process.exit(0);
  }
}

rl.on('line', async (line) => {
  const raw = line.trim();
  if (!raw) return;

  let msg;
  try { msg = JSON.parse(raw); }
  catch (e) { log('bad json from stdin:', e.message); return; }

  const isNotification = msg.id === undefined;

  inFlight++;
  try {
    const res = await fetch(URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${BEARER}`,
        'Accept': 'application/json',
      },
      body: raw,
    });

    if (isNotification) return;

    const text = await res.text();
    if (!res.ok) log(`HTTP ${res.status} from upstream: ${text.slice(0, 200)}`);
    process.stdout.write(text.trimEnd() + '\n');
  } catch (e) {
    const cause = e.cause ? ` cause=${e.cause.code || e.cause.message || JSON.stringify(e.cause)}` : '';
    log('fetch error:', e.message, cause);
    if (!isNotification) {
      process.stdout.write(JSON.stringify({
        jsonrpc: '2.0',
        id: msg.id ?? null,
        error: { code: -32603, message: `bridge fetch error: ${e.message}${cause}` },
      }) + '\n');
    }
  } finally {
    inFlight--;
    maybeExit();
  }
});

rl.on('close', () => { log('stdin closed, draining...'); stdinClosed = true; maybeExit(); });
process.on('SIGINT', () => process.exit(0));
process.on('SIGTERM', () => process.exit(0));
