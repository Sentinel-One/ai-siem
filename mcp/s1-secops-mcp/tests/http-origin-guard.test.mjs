/**
 * HTTP transport CSRF / DNS-rebinding guard test (finding 019eff5a).
 *
 * The documented no-auth loopback mode (`s1-secops-mcp --transport http`, no
 * bearer tokens) used to dispatch any POST /mcp regardless of Origin or Host,
 * so a browser page — or a DNS-rebinding attack — on the operator's workstation
 * could invoke every state-changing tool. After the fix, in no-auth mode:
 *   - a request carrying any Origin header is rejected 403
 *   - a request whose Host header is not the loopback bind is rejected 403
 *   - a normal non-browser request (no Origin, loopback Host) still works
 *
 * fetch() forbids setting Origin/Host, so we use the raw node:http client.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import http from 'node:http';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dir = dirname(fileURLToPath(import.meta.url));
const SERVER = resolve(__dir, '..', 'index.js');

async function waitForHealth(port, attempts = 50) {
  for (let i = 0; i < attempts; i++) {
    try {
      const r = await fetch(`http://127.0.0.1:${port}/healthz`);
      if (r.ok) return;
    } catch { /* retry */ }
    await new Promise(r => setTimeout(r, 100));
  }
  throw new Error(`Server did not become healthy on port ${port}`);
}

function spawnServer(env = {}) {
  const port = 9000 + Math.floor(Math.random() * 1000);
  const child = spawn(process.execPath, [SERVER, '--transport', 'http', '--port', String(port), '--host', '127.0.0.1'], {
    stdio: ['ignore', 'ignore', 'pipe'],
    env: { ...process.env, ...env },
  });
  let stderrBuf = '';
  child.stderr.on('data', c => { stderrBuf += c.toString('utf-8'); });
  return { child, port, getStderr: () => stderrBuf };
}

/** Raw HTTP POST so we can set the forbidden-in-fetch Origin / Host headers. */
function rawPost(port, body, headers = {}) {
  return new Promise((resolve, reject) => {
    const data = Buffer.from(body, 'utf-8');
    const req = http.request({
      hostname: '127.0.0.1',
      port,
      path: '/mcp',
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': data.length, ...headers },
    }, (res) => {
      let buf = '';
      res.on('data', c => { buf += c; });
      res.on('end', () => resolve({ status: res.statusCode, body: buf }));
    });
    req.on('error', reject);
    req.write(data);
    req.end();
  });
}

function rpc(id, method, params = {}) {
  return JSON.stringify({ jsonrpc: '2.0', id, method, params });
}

async function withServer(env, fn) {
  const { child, port, getStderr } = spawnServer(env);
  try {
    await waitForHealth(port);
    await fn(port);
  } finally {
    child.kill('SIGTERM');
    await new Promise(r => setTimeout(r, 100));
    if (!child.killed) child.kill('SIGKILL');
  }
}

test('guard(no-auth): request with an Origin header is rejected 403', async () => {
  await withServer({}, async (port) => {
    const r = await rawPost(port, rpc(1, 'tools/list'), { Origin: 'https://evil.example' });
    assert.equal(r.status, 403);
    const body = JSON.parse(r.body);
    assert.equal(body.error.code, -32001);
  });
});

test('guard(no-auth): DNS-rebind Host header is rejected 403', async () => {
  await withServer({}, async (port) => {
    const r = await rawPost(port, rpc(1, 'tools/list'), { Host: `rebind.attacker.example:${port}` });
    assert.equal(r.status, 403);
    const body = JSON.parse(r.body);
    assert.equal(body.error.code, -32001);
  });
});

test('guard(no-auth): simple text/plain cross-origin POST is rejected 403', async () => {
  // The pre-fix bypass: a "simple" cross-origin fetch with text/plain sends an
  // Origin header but no preflight. The Origin check must still catch it.
  await withServer({}, async (port) => {
    const r = await rawPost(port, rpc(1, 'tools/list'), {
      Origin: 'https://example.com',
      'Content-Type': 'text/plain',
    });
    assert.equal(r.status, 403);
  });
});

test('guard(no-auth): normal non-browser request (no Origin, loopback Host) still works', async () => {
  await withServer({}, async (port) => {
    const r = await rawPost(port, rpc(1, 'tools/list'));
    assert.equal(r.status, 200);
    const body = JSON.parse(r.body);
    assert.equal(body.result.tools.length, 26);
  });
});

test('guard(no-auth): localhost Host with matching port is allowed', async () => {
  await withServer({}, async (port) => {
    const r = await rawPost(port, rpc(1, 'tools/list'), { Host: `localhost:${port}` });
    assert.equal(r.status, 200);
  });
});

test('guard(auth): authenticated path is unaffected by Origin (proxy compatibility)', async () => {
  // When bearer auth is configured (systemd / Caddy team path), the token
  // already blocks browsers, and a reverse proxy may legitimately forward a
  // public Host/Origin. The guard is scoped to no-auth mode, so a valid token
  // with an Origin header must still succeed.
  const goodToken = 'alice-token-' + 'x'.repeat(20);
  const dir = mkdtempSync(join(tmpdir(), 'mcp-auth-'));
  const file = join(dir, 'tokens.json');
  writeFileSync(file, JSON.stringify({ alice: goodToken }), { mode: 0o600 });
  try {
    await withServer({ MCP_BEARER_TOKENS_FILE: file }, async (port) => {
      const r = await rawPost(port, rpc(1, 'tools/list'), {
        Origin: 'https://proxy.s1.internal',
        Authorization: `Bearer ${goodToken}`,
      });
      assert.equal(r.status, 200);
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
