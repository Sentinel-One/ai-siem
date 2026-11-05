/**
 * stdio transport: reads JSON-RPC messages from stdin (one per line),
 * dispatches via the provided dispatcher, writes responses to stdout.
 *
 * This is the default transport and the one used by Claude Desktop,
 * Claude Code, Claude Cowork, and any other client launched via the
 * `npx` / `node index.js` invocation pattern.
 *
 * Secrets preamble (S1_SECRETS_STDIN=1, 1.6.0): the host launcher
 * (docker/s1-secops-mcp-launch.sh / .ps1) writes NAME=value lines and one empty
 * line BEFORE relaying the client's JSON-RPC stream, which keeps every secret out
 * of `docker inspect` and out of every command line. Until 1.5.x a shell
 * entrypoint read them; the 1.6.0 image has no shell, so the server reads them
 * here, in order, before the first JSON-RPC line. Only known names are accepted.
 */

import { createInterface } from 'readline';
import { err as makeErr } from './server-core.js';

function log(...args) {
  process.stderr.write('[s1-secops-mcp] ' + args.join(' ') + '\n');
}

function send(obj) {
  process.stdout.write(JSON.stringify(obj) + '\n');
}

/** Names the secrets preamble may set. VT_API_KEY is an alias for VIRUSTOTAL_API_KEY. */
export const PREAMBLE_NAMES = Object.freeze([
  'S1_CONSOLE_URL', 'S1_CONSOLE_API_TOKEN', 'S1_HEC_INGEST_URL', 'S1_HEC_TOKEN', 'S1_SCOPE',
  'VIRUSTOTAL_API_KEY', 'VT_API_KEY', 'SHODAN_API_KEY',
]);

/**
 * Apply one preamble line. Returns 'end' on the blank line that closes the preamble,
 * 'jsonrpc' when the stream starts with JSON-RPC instead, or 'ok'.
 * Exported for tests.
 */
export function applyPreambleLine(line, env = process.env, { first = false } = {}) {
  let s = String(line);
  if (first) s = s.replace(/^﻿/, '');          // a Windows host may prepend a UTF-8 BOM
  s = s.replace(/\r$/, '');
  if (s === '') return 'end';
  if (s.trimStart().startsWith('{')) return 'jsonrpc';
  const i = s.indexOf('=');
  const name = i > 0 ? s.slice(0, i) : '';
  if (PREAMBLE_NAMES.includes(name)) {
    env[name] = s.slice(i + 1);
  } else {
    log('ignoring an unknown name on the secrets channel');
  }
  return 'ok';
}

/**
 * @param {Function} dispatch
 * @param {{secretsPreamble?: boolean, onReady?: Function}} [opts]
 *   secretsPreamble: read NAME=value lines up to the first empty line before any JSON-RPC.
 *   onReady: called once the preamble is read (or at once without one).
 */
export async function startStdio(dispatch, { secretsPreamble = false, onReady } = {}) {
  log('Transport: stdio');

  const rl = createInterface({ input: process.stdin, terminal: false });

  let inFlight = 0;
  let stdinClosed = false;
  let preamble = secretsPreamble;
  let firstLine = true;
  const ready = () => { try { onReady?.(); } catch (e) { log('startup report failed:', e.message); } };
  if (!preamble) ready();

  function maybeExit() {
    if (stdinClosed && inFlight === 0) {
      log('All requests complete, exiting.');
      process.exit(0);
    }
  }

  rl.on('line', async (line) => {
    if (preamble) {
      const r = applyPreambleLine(line, process.env, { first: firstLine });
      firstLine = false;
      if (r === 'ok') return;
      if (r === 'jsonrpc') {
        log('S1_SECRETS_STDIN=1 but stdin starts with JSON-RPC; send NAME=value lines and an empty line first (use docker/s1-secops-mcp-launch.sh).');
        process.exit(64);
      }
      preamble = false;                              // r === 'end'
      delete process.env.S1_SECRETS_STDIN;
      if (process.env.VT_API_KEY && !process.env.VIRUSTOTAL_API_KEY) process.env.VIRUSTOTAL_API_KEY = process.env.VT_API_KEY;
      ready();
      return;
    }

    const trimmed = line.trim();
    if (!trimmed) return;

    let msg;
    try {
      msg = JSON.parse(trimmed);
    } catch (e) {
      send(makeErr(null, -32700, `Parse error: ${e.message}`));
      return;
    }

    const isNotification = msg.id === undefined;

    inFlight++;
    try {
      const response = await dispatch(msg.method, msg.params, msg.id);
      if (response !== null && !isNotification) {
        send(response);
      }
    } catch (e) {
      log('Unhandled dispatch error:', e.message, e.stack);
      if (!isNotification) {
        send(makeErr(msg.id ?? null, -32603, `Internal error: ${e.message}`));
      }
    } finally {
      inFlight--;
      maybeExit();
    }
  });

  rl.on('close', () => {
    log('stdin closed, waiting for in-flight requests...');
    stdinClosed = true;
    maybeExit();
  });

  // Node running as PID 1 (the 1.6.0 image has no init) ignores signals that have no
  // handler, so handle both explicitly: the MCP client and `docker stop` send these.
  for (const sig of ['SIGINT', 'SIGTERM']) {
    process.on(sig, () => {
      log(`${sig} received, exiting.`);
      process.exit(0);
    });
  }
}
