#!/usr/bin/env node
/**
 * SentinelOne MCP Server
 *
 * Implements the Model Context Protocol over either stdio (default) or
 * Streamable HTTP, using raw JSON-RPC 2.0 throughout. No external runtime
 * dependencies. Pure Node.js 18+.
 *
 * Exposes 26 tools across PowerQuery, Mgmt Console REST, UAM, SDL API,
 * Hyperautomation, and UAM Ingest; plus 2 resources and 2 prompts.
 *
 * Quick start:
 *   stdio (default, used by Claude Desktop / Claude Code / Cowork):
 *     node index.js
 *
 *   Streamable HTTP, bound to localhost, no auth (single-user local):
 *     node index.js --transport http
 *
 *   Streamable HTTP, bound to 0.0.0.0 with team bearer tokens:
 *     MCP_BEARER_TOKENS_FILE=/etc/s1-secops-mcp/bearer-tokens.json \
 *       node index.js --transport http --host 0.0.0.0 --port 8765
 *
 * Full configuration reference: README.md and deploy/README.md.
 */

import { dispatch, SERVER_INFO, ALL_TOOLS } from './lib/server-core.js';
import { getCreds, hasS1Creds, hasSdlCreds } from './lib/credentials.js';
import { hasHecCreds } from './lib/uam-ingest.js';
import { loadTokens, installSighupReload } from './lib/auth.js';

function log(...args) {
  process.stderr.write('[s1-secops-mcp] ' + args.join(' ') + '\n');
}

// ─── CLI flag parser ──────────────────────────────────────────────────────────

function parseArgs(argv) {
  const out = {
    transport: process.env.MCP_TRANSPORT || 'stdio',
    host:      process.env.MCP_HTTP_HOST || '127.0.0.1',
    port:      Number(process.env.MCP_HTTP_PORT) || 8765,
    path:      process.env.MCP_HTTP_PATH || '/mcp',
    help:      false,
    version:   false,
  };

  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = () => argv[++i];
    switch (a) {
      case '-h': case '--help':    out.help = true; break;
      case '-v': case '--version': out.version = true; break;
      case '--transport':          out.transport = next(); break;
      case '--host':               out.host = next(); break;
      case '--port':               out.port = Number(next()); break;
      case '--path':               out.path = next(); break;
      default:
        if (a.startsWith('--')) {
          process.stderr.write(`Unknown flag: ${a}\nRun with --help for usage.\n`);
          process.exit(2);
        }
    }
  }

  if (!['stdio', 'http'].includes(out.transport)) {
    process.stderr.write(`Invalid --transport: ${out.transport} (expected: stdio, http)\n`);
    process.exit(2);
  }
  if (out.transport === 'http' && (!out.port || out.port <= 0 || out.port > 65535)) {
    process.stderr.write(`Invalid --port: ${out.port}\n`);
    process.exit(2);
  }
  if (!out.path.startsWith('/')) {
    process.stderr.write(`Invalid --path: ${out.path} (must start with /)\n`);
    process.exit(2);
  }

  return out;
}

function printHelp() {
  process.stdout.write(`\
s1-secops-mcp ${SERVER_INFO.version}

USAGE
  s1-secops-mcp [options]

OPTIONS
  --transport <stdio|http>    Transport to use. Default: stdio.
  --host <host>               HTTP bind address. Default: 127.0.0.1.
  --port <port>               HTTP port. Default: 8765.
  --path <path>               HTTP MCP endpoint path. Default: /mcp.
  -h, --help                  Show this help.
  -v, --version               Show server version.

ENVIRONMENT
  MCP_TRANSPORT               Same as --transport.
  MCP_HTTP_HOST               Same as --host.
  MCP_HTTP_PORT               Same as --port.
  MCP_HTTP_PATH               Same as --path.

  MCP_BEARER_TOKENS_FILE      Path to a JSON file mapping {name: token} for
                              per-user authenticated HTTP access. Recommended
                              for teams. SIGHUP reloads without restart.
  MCP_BEARER_TOKENS           Comma-separated raw tokens (no per-user names).
                              Fallback when MCP_BEARER_TOKENS_FILE is not set.

  S1_CONSOLE_URL              Console URL, e.g. https://usea1-acme.sentinelone.net
  S1_CONSOLE_API_TOKEN        Mgmt Console API token. Required for most tools.
  S1_HEC_INGEST_URL           HEC ingest host. Required for uam_ingest_alert,
                              uam_post_indicators, uam_post_alert.
  SDL_XDR_URL                 SDL tenant URL.
  SDL_LOG_READ_KEY            SDL Log Read key.
  SDL_CONFIG_READ_KEY         SDL Config Read key.
  SDL_CONFIG_WRITE_KEY        SDL Config Write key. Required for sdl_put_file.
  S1_CREDS_FILE               Explicit path to a credentials.json file.
                              Highest priority for credential resolution.
  S1_CLAUDE_MD_PATH           Absolute path to CLAUDE.md for the soc_analyst
                              prompt and sentinelone://soc-context resource.

EXAMPLES
  Run as a local MCP server for Claude Desktop / Cowork:
    s1-secops-mcp

  Run as an HTTP service for personal use:
    s1-secops-mcp --transport http
    # then: curl -s http://127.0.0.1:8765/healthz

  Run as a shared team service with token auth:
    MCP_BEARER_TOKENS_FILE=/etc/s1-secops-mcp/bearer-tokens.json \\
      s1-secops-mcp --transport http --host 0.0.0.0 --port 8765
    # See deploy/README.md for the full Linux VM walkthrough.
`);
}

// ─── Main ────────────────────────────────────────────────────────────────────

async function main() {
  const opts = parseArgs(process.argv.slice(2));

  if (opts.help)    { printHelp(); process.exit(0); }
  if (opts.version) { process.stdout.write(`${SERVER_INFO.version}\n`); process.exit(0); }

  log(`Starting ${SERVER_INFO.name} v${SERVER_INFO.version} (node ${process.version})`);

  const creds = getCreds();
  log(`S1 Mgmt API:  ${hasS1Creds() ? 'configured (' + creds.S1_CONSOLE_URL + ')' : 'NOT configured'}`);
  log(`SDL API:      ${hasSdlCreds() ? 'configured (' + creds.SDL_XDR_URL + ')' : 'NOT configured'}`);
  log(`UAM Ingest:   ${hasHecCreds() ? 'configured (' + creds.S1_HEC_INGEST_URL + ')' : 'NOT configured (add S1_HEC_INGEST_URL)'}`);
  log(`Tools:        ${ALL_TOOLS.length} registered`);

  if (opts.transport === 'http') {
    try {
      loadTokens();
    } catch (e) {
      process.stderr.write(`[auth] FATAL: ${e.message}\n`);
      process.exit(1);
    }
    installSighupReload();

    const { startHttp } = await import('./lib/http-transport.js');
    await startHttp(dispatch, { port: opts.port, host: opts.host, path: opts.path });
    log('HTTP transport ready. Press Ctrl+C to stop.');
    return;
  }

  // Default: stdio
  const { startStdio } = await import('./lib/stdio-transport.js');
  await startStdio(dispatch);
}

main().catch(e => {
  process.stderr.write(`Fatal: ${e.message}\n${e.stack}\n`);
  process.exit(1);
});
