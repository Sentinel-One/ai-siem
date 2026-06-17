/**
 * stdio transport: reads JSON-RPC messages from stdin (one per line),
 * dispatches via the provided dispatcher, writes responses to stdout.
 *
 * This is the default transport and the one used by Claude Desktop,
 * Claude Code, Claude Cowork, and any other client launched via the
 * `npx` / `node index.js` invocation pattern.
 */

import { createInterface } from 'readline';
import { err as makeErr } from './server-core.js';

function log(...args) {
  process.stderr.write('[s1-secops-mcp] ' + args.join(' ') + '\n');
}

function send(obj) {
  process.stdout.write(JSON.stringify(obj) + '\n');
}

export async function startStdio(dispatch) {
  log('Transport: stdio');

  const rl = createInterface({ input: process.stdin, terminal: false });

  let inFlight = 0;
  let stdinClosed = false;

  function maybeExit() {
    if (stdinClosed && inFlight === 0) {
      log('All requests complete, exiting.');
      process.exit(0);
    }
  }

  rl.on('line', async (line) => {
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

  process.on('SIGINT', () => {
    log('SIGINT received, exiting.');
    process.exit(0);
  });
}
