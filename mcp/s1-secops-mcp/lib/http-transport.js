/**
 * Streamable HTTP transport (MCP 2024-11-05 / 2025-06-18 compatible subset).
 *
 * Single endpoint:
 *   POST /mcp     accept JSON-RPC, return JSON-RPC reply (Content-Type: application/json)
 *   GET  /healthz return 200 OK (for load balancers / systemd readiness checks)
 *   Any other path / method returns 404 or 405.
 *
 * The server is stateless: it does not maintain MCP sessions or push
 * server-initiated notifications, so the spec-allowed SSE response form
 * is not used. Clients that try to GET /mcp for a server-initiated stream
 * receive 405 Method Not Allowed, which spec-compliant clients tolerate.
 *
 * Auth: if any tokens are loaded via lib/auth.js, every POST /mcp must
 * carry "Authorization: Bearer <token>". Missing/invalid token -> 401.
 *
 * Audit: every authenticated request logs to stderr (captured by journald
 * on systemd or by Docker on container runtimes):
 *   timestamp | client-name | method | params-summary | response-status
 *
 * Zero external dependencies (uses node:http).
 */

import { createServer } from 'http';
import { authenticate, isAuthConfigured, warnIfNoAuth, authSourceForLogging } from './auth.js';
import { err as makeErr } from './server-core.js';

const MAX_BODY_BYTES = 4 * 1024 * 1024; // 4 MB — well above any normal MCP call

function log(...args) {
  process.stderr.write('[s1-secops-mcp] ' + args.join(' ') + '\n');
}

function audit(line) {
  process.stderr.write(`[audit] ${line}\n`);
}

function summarizeParams(params) {
  if (!params || typeof params !== 'object') return '';
  if (params.name) return `name=${params.name}`;       // tools/call
  if (params.uri) return `uri=${params.uri}`;          // resources/read
  return '';
}

/**
 * DNS-rebinding guard for the no-auth HTTP mode.
 *
 * The Host header must match the address the server is bound to (or a loopback
 * literal when bound to loopback). A DNS-rebinding attack arrives with the
 * attacker's Host (e.g. "rebind.attacker.example:8765"), which will not match
 * the loopback bind. When bound to a wildcard address we cannot know the
 * intended FQDN, so we accept any Host and rely on the Origin check to block
 * browsers. HTTP/1.1 mandates a Host header, so a missing one is rejected.
 */
function isAllowedHost(hostHeader, bindHost, bindPort) {
  if (!hostHeader) return false;
  const wildcard = ['0.0.0.0', '::', ''].includes(String(bindHost));
  // Parse "hostname" or "hostname:port" (including IPv6 "[::1]:port").
  const m = /^(\[[^\]]+\]|[^:]+)(?::(\d+))?$/.exec(hostHeader.trim());
  if (!m) return false;
  const name = m[1].toLowerCase().replace(/^\[|\]$/g, '');
  const port = m[2];
  if (port !== undefined && Number(port) !== Number(bindPort)) return false;
  if (wildcard) return true;
  const loopback = ['127.0.0.1', '::1', 'localhost'];
  const bind = String(bindHost).toLowerCase();
  const allowed = new Set([bind, ...(loopback.includes(bind) ? loopback : [])]);
  return allowed.has(name);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        reject(new Error(`Request body exceeds ${MAX_BODY_BYTES} bytes`));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      try {
        const raw = Buffer.concat(chunks).toString('utf-8');
        resolve(raw);
      } catch (e) { reject(e); }
    });
    req.on('error', reject);
  });
}

function sendJson(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(body),
    'Cache-Control': 'no-store',
  });
  res.end(body);
}

function sendText(res, status, text) {
  res.writeHead(status, {
    'Content-Type': 'text/plain; charset=utf-8',
    'Content-Length': Buffer.byteLength(text),
    'Cache-Control': 'no-store',
  });
  res.end(text);
}

async function handleMcp(req, res, dispatch, clientIp, bindHost, bindPort) {
  // Auth check (only if any tokens are configured)
  let clientName = '-';
  if (isAuthConfigured()) {
    clientName = authenticate(req.headers['authorization']) || '';
    if (!clientName) {
      audit(`${new Date().toISOString()} | ${clientIp} | - | - | 401 unauthorized`);
      sendJson(res, 401, makeErr(null, -32001, 'Unauthorized: missing or invalid bearer token'));
      return;
    }
  } else {
    // SECURITY (no-auth mode): a configured bearer token normally blocks
    // browser-driven requests, because a web page cannot forge an Authorization
    // header. The documented no-auth loopback mode has no such gate, so a
    // malicious page — or a DNS-rebinding attack — on the operator's own
    // workstation could otherwise drive this server via cross-origin fetch()
    // and invoke every state-changing tool with the tenant API token. Per the
    // MCP Streamable HTTP spec we reject any browser Origin and validate the
    // Host header to defeat DNS rebinding. Non-browser MCP clients (stdio
    // bridge, curl, Claude Desktop) omit Origin and send a matching Host.
    const origin = req.headers['origin'];
    if (origin) {
      audit(`${new Date().toISOString()} | ${clientIp} | - | - | 403 cross-origin (${origin})`);
      sendJson(res, 403, makeErr(null, -32001, 'Cross-origin requests are not allowed'));
      return;
    }
    if (!isAllowedHost(req.headers['host'], bindHost, bindPort)) {
      audit(`${new Date().toISOString()} | ${clientIp} | - | - | 403 bad-host (${req.headers['host'] || '-'})`);
      sendJson(res, 403, makeErr(null, -32001, 'Invalid Host header'));
      return;
    }
    clientName = `anon@${clientIp}`;
  }

  // Parse JSON body
  let raw;
  try {
    raw = await readBody(req);
  } catch (e) {
    audit(`${new Date().toISOString()} | ${clientName} | - | - | 413 body-too-large`);
    sendJson(res, 413, makeErr(null, -32600, e.message));
    return;
  }

  if (!raw) {
    sendJson(res, 400, makeErr(null, -32600, 'Empty body'));
    return;
  }

  let msg;
  try {
    msg = JSON.parse(raw);
  } catch (e) {
    audit(`${new Date().toISOString()} | ${clientName} | - | - | 400 parse-error`);
    sendJson(res, 400, makeErr(null, -32700, `Parse error: ${e.message}`));
    return;
  }

  // JSON-RPC batch: out of spec for Streamable HTTP MCP; reject explicitly.
  if (Array.isArray(msg)) {
    sendJson(res, 400, makeErr(null, -32600, 'Batch requests are not supported'));
    return;
  }

  const isNotification = msg.id === undefined;
  const ts = new Date().toISOString();

  try {
    const response = await dispatch(msg.method, msg.params, msg.id);

    if (isNotification) {
      // Per JSON-RPC, notifications get no reply; per MCP Streamable HTTP, return 202.
      audit(`${ts} | ${clientName} | ${msg.method} | ${summarizeParams(msg.params)} | 202 notification`);
      res.writeHead(202);
      res.end();
      return;
    }

    if (response === null) {
      sendJson(res, 200, makeErr(msg.id ?? null, -32603, 'Internal error: empty response'));
      return;
    }

    const status = response.error ? 200 : 200; // JSON-RPC errors are 200 with error envelope
    audit(`${ts} | ${clientName} | ${msg.method} | ${summarizeParams(msg.params)} | ${response.error ? `200 jsonrpc-error (${response.error.code})` : '200 ok'}`);
    sendJson(res, status, response);

  } catch (e) {
    log('Dispatch error:', e.message, e.stack);
    audit(`${ts} | ${clientName} | ${msg.method || '-'} | ${summarizeParams(msg.params)} | 500 internal-error`);
    if (!isNotification) {
      sendJson(res, 500, makeErr(msg.id ?? null, -32603, `Internal error: ${e.message}`));
    } else {
      res.writeHead(500);
      res.end();
    }
  }
}

export async function startHttp(dispatch, { port, host, path }) {
  warnIfNoAuth(host);

  const server = createServer(async (req, res) => {
    const clientIp = req.socket.remoteAddress || '-';

    // Health check
    if (req.method === 'GET' && (req.url === '/healthz' || req.url === '/health')) {
      sendText(res, 200, 'ok\n');
      return;
    }

    // MCP endpoint
    if (req.url === path) {
      if (req.method === 'POST') {
        await handleMcp(req, res, dispatch, clientIp, host, port);
        return;
      }
      if (req.method === 'GET' || req.method === 'DELETE') {
        // Spec-allowed but not implemented (no server-push, no sessions).
        res.writeHead(405, { 'Allow': 'POST', 'Content-Type': 'text/plain' });
        res.end('Method not allowed; this server accepts POST only.\n');
        return;
      }
      res.writeHead(405, { 'Allow': 'POST', 'Content-Type': 'text/plain' });
      res.end('Method not allowed\n');
      return;
    }

    sendText(res, 404, 'Not found. The MCP endpoint is ' + path + '.\n');
  });

  server.on('error', (e) => {
    log(`HTTP server error: ${e.message}`);
    if (e.code === 'EADDRINUSE') {
      log(`Port ${port} is already in use. Pick a different --port.`);
      process.exit(1);
    }
  });

  await new Promise((resolve) => server.listen(port, host, resolve));
  const authMode = isAuthConfigured() ? authSourceForLogging() : 'NONE (warn)';
  log(`Transport: streamableHttp listening on http://${host}:${port}${path} (auth: ${authMode})`);

  // Graceful shutdown
  process.on('SIGINT', () => {
    log('SIGINT received, draining HTTP server...');
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 5000).unref();
  });
  process.on('SIGTERM', () => {
    log('SIGTERM received, draining HTTP server...');
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 5000).unref();
  });

  return server;
}
