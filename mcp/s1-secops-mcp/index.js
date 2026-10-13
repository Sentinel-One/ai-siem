#!/usr/bin/env node
/**
 * SentinelOne MCP Server
 *
 * Implements the Model Context Protocol over stdio, using raw JSON-RPC 2.0.
 * No required runtime dependencies (optional: @napi-rs/keyring, used for the
 * Windows Credential Manager).
 *
 * Exposes 35 tools across PowerQuery, Mgmt Console REST, UAM, SDL API,
 * Hyperautomation, and UAM Ingest; plus 2 resources and 2 prompts.
 *
 * Credentials come from environment variables, then the OS keychain. There is
 * no file fallback. Store them once with `s1-secops-mcp setup`.
 *
 * The Streamable HTTP transport and the team VM deployment were removed in
 * 1.5.0; this server is stdio only.
 */

import { dispatch, SERVER_INFO, ALL_TOOLS } from './lib/server-core.js';
import { getCreds, hasS1Creds, hasSdlCreds, loadCredentials } from './lib/credentials.js';
import { hasHecCreds } from './lib/uam-ingest.js';
import { runCli, SUBCOMMANDS } from './lib/cli.js';
import { redact } from './lib/redact.js';

function log(...args) {
  process.stderr.write(redact('[s1-secops-mcp] ' + args.join(' ')) + '\n');
}

function printHelp() {
  process.stdout.write(`\
s1-secops-mcp ${SERVER_INFO.version}

USAGE
  s1-secops-mcp                       Run the MCP server on stdio (what MCP clients launch)
  s1-secops-mcp setup  [options]      Store credentials in the OS keychain
  s1-secops-mcp status [--profile P]  Show where each value comes from (secrets masked)
  s1-secops-mcp forget [options]      Remove stored credentials
  s1-secops-mcp exec   [--profile P] -- <command> [args...]
                                      Run another MCP server (purple-mcp, VirusTotal)
                                      with the keychain values in its environment

SETUP OPTIONS
  --profile <name>        Keychain profile (default: "default", or S1_PROFILE)
  --name <NAME>           Only this value
  --import-json <file>    Migrate an old credentials.json into the keychain,
                          then delete the file yourself

  setup prompts without echo on a terminal. Without a terminal it reads
  NAME=value lines from stdin. Secrets are never taken as arguments.

OPTIONS
  -h, --help              Show this help.
  -v, --version           Show server version.

CREDENTIALS (environment variables override the keychain, per value)
  S1_CONSOLE_URL                     Console URL, e.g. https://usea1-acme.sentinelone.net
  S1_CONSOLE_API_TOKEN               Mgmt Console API token. Required for most tools.
  S1_HEC_INGEST_URL                  HEC ingest host for uam_ingest_alert, uam_post_alert, hec_ingest
  S1_HEC_TOKEN                       SDL Log Write Key, for hec_ingest only
  S1_SCOPE                           Default S1-Scope for SDL requests
  VIRUSTOTAL_API_KEY                 Stored for the VirusTotal MCP (exec / Docker launcher)

OTHER ENVIRONMENT
  S1_PROFILE              Keychain profile to read (default "default")
  S1_KEYCHAIN=off         Do not use the OS keychain (environment variables only)
  S1_KEYCHAIN_BACKEND     Force a backend: macos | linux | native
  S1_OUTPUT_DIRS          Directories outputFile may write to (default: home and temp)
  S1_CLAUDE_MD_PATH       Absolute path to CLAUDE.md for the soc_analyst prompt

KEYCHAIN
  macOS: login keychain via /usr/bin/security. Linux: Secret Service via secret-tool
  (needs a D-Bus session and an unlocked keyring; on headless hosts use environment
  variables). Windows: Credential Manager via the optional @napi-rs/keyring package.
  Items: service "sentinelone-mcp", account "<profile>:<NAME>".
`);
}

async function main() {
  const argv = process.argv.slice(2);
  const first = argv[0];

  if (first === '-h' || first === '--help' || first === 'help') { printHelp(); process.exit(0); }
  if (first === '-v' || first === '--version') { process.stdout.write(`${SERVER_INFO.version}\n`); process.exit(0); }

  if (first && SUBCOMMANDS.has(first)) {
    process.exit(await runCli(first, argv.slice(1)));
  }

  // The HTTP transport was removed in 1.5.0. Fail loudly instead of silently
  // starting on stdio when an old config still passes --transport http.
  const transportIdx = argv.indexOf('--transport');
  if (transportIdx !== -1 && argv[transportIdx + 1] && argv[transportIdx + 1] !== 'stdio') {
    process.stderr.write('The HTTP transport was removed in 1.5.0. s1-secops-mcp runs on stdio only.\n');
    process.exit(2);
  }
  if ((process.env.MCP_TRANSPORT || 'stdio') !== 'stdio') {
    process.stderr.write('MCP_TRANSPORT is set to a non-stdio value; the HTTP transport was removed in 1.5.0.\n');
    process.exit(2);
  }
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--transport') { i++; continue; }
    process.stderr.write(`Unknown argument: ${a}\nRun with --help for usage.\n`);
    process.exit(2);
  }

  log(`Starting ${SERVER_INFO.name} v${SERVER_INFO.version} (node ${process.version})`);

  const creds = getCreds();
  const { keychain } = loadCredentials();
  log(`Credentials:  env, then keychain (${keychain.backend}${keychain.error ? ': unavailable, ' + keychain.error : ''})`);
  log(`S1 Mgmt API:  ${hasS1Creds() ? 'configured (' + creds.S1_CONSOLE_URL + ')' : 'NOT configured (run `s1-secops-mcp setup`)'}`);
  log(`SDL API:      ${hasSdlCreds() ? 'configured (' + creds.S1_CONSOLE_URL + '/sdl)' : 'NOT configured'}`);
  log(`UAM Ingest:   ${hasHecCreds() ? 'configured (' + creds.S1_HEC_INGEST_URL + ')' : 'NOT configured (S1_HEC_INGEST_URL missing)'}`);
  log(`Tools:        ${ALL_TOOLS.length} registered`);

  const { startStdio } = await import('./lib/stdio-transport.js');
  await startStdio(dispatch);
}

main().catch(e => {
  process.stderr.write(redact(`Fatal: ${e.message}\n${e.stack}`) + '\n');
  process.exit(1);
});
