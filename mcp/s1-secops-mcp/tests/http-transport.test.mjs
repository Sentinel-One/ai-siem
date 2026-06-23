/**
 * HTTP transport integration test.
 *
 * Spawns `node index.js --transport http` on an ephemeral port and:
 *   - confirms /healthz returns 200
 *   - confirms POST /mcp with `initialize` returns the expected envelope
 *   - confirms POST /mcp with `tools/list` returns 26 tools
 *   - confirms unknown path returns 404
 *   - confirms unknown method returns -32601
 *   - confirms with bearer auth configured:
 *       missing header  -> 401
 *       wrong token     -> 401
 *       valid token     -> 200
 *
 * Picks a random port in 9000-9999 to avoid collisions when run in CI.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
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

function rpc(id, method, params = {}) {
  return JSON.stringify({ jsonrpc: '2.0', id, method, params });
}

async function postMcp(port, body, headers = {}) {
  return fetch(`http://127.0.0.1:${port}/mcp`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...headers },
    body,
  });
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

test('http: /healthz returns 200 ok', async () => {
  await withServer({}, async (port) => {
    const r = await fetch(`http://127.0.0.1:${port}/healthz`);
    assert.equal(r.status, 200);
    assert.equal((await r.text()).trim(), 'ok');
  });
});

test('http: POST /mcp initialize returns server info', async () => {
  await withServer({}, async (port) => {
    const r = await postMcp(port, rpc(1, 'initialize', {
      protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'http-test', version: '1' },
    }));
    assert.equal(r.status, 200);
    const body = await r.json();
    assert.equal(body.id, 1);
    assert.equal(body.result.serverInfo.name, 's1-secops-mcp-server');
    assert.equal(body.result.serverInfo.version, '1.2.2');
  });
});

test('http: POST /mcp tools/list returns 26 tools', async () => {
  await withServer({}, async (port) => {
    const r = await postMcp(port, rpc(1, 'tools/list'));
    assert.equal(r.status, 200);
    const body = await r.json();
    assert.equal(body.result.tools.length, 26);
  });
});

test('http: POST /mcp unknown method returns -32601', async () => {
  await withServer({}, async (port) => {
    const r = await postMcp(port, rpc(1, 'does/not/exist'));
    const body = await r.json();
    assert.equal(body.error.code, -32601);
  });
});

test('http: GET unknown path returns 404', async () => {
  await withServer({}, async (port) => {
    const r = await fetch(`http://127.0.0.1:${port}/nope`);
    assert.equal(r.status, 404);
  });
});

test('http: GET /mcp returns 405 (POST only)', async () => {
  await withServer({}, async (port) => {
    const r = await fetch(`http://127.0.0.1:${port}/mcp`);
    assert.equal(r.status, 405);
    assert.equal(r.headers.get('allow'), 'POST');
  });
});

test('http: bad JSON body returns -32700', async () => {
  await withServer({}, async (port) => {
    const r = await postMcp(port, 'not json');
    assert.equal(r.status, 400);
    const body = await r.json();
    assert.equal(body.error.code, -32700);
  });
});

test('http+auth: missing Authorization header -> 401', async () => {
  const tokens = { alice: 'alice-token-' + 'x'.repeat(20) };
  const dir = mkdtempSync(join(tmpdir(), 'mcp-auth-'));
  const file = join(dir, 'tokens.json');
  writeFileSync(file, JSON.stringify(tokens), { mode: 0o600 });
  try {
    await withServer({ MCP_BEARER_TOKENS_FILE: file }, async (port) => {
      const r = await postMcp(port, rpc(1, 'tools/list'));
      assert.equal(r.status, 401);
      const body = await r.json();
      assert.equal(body.error.code, -32001);
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('http+auth: wrong token -> 401', async () => {
  const tokens = { alice: 'alice-token-' + 'x'.repeat(20) };
  const dir = mkdtempSync(join(tmpdir(), 'mcp-auth-'));
  const file = join(dir, 'tokens.json');
  writeFileSync(file, JSON.stringify(tokens), { mode: 0o600 });
  try {
    await withServer({ MCP_BEARER_TOKENS_FILE: file }, async (port) => {
      const r = await postMcp(port, rpc(1, 'tools/list'), { 'Authorization': 'Bearer wrong-token-' + 'x'.repeat(20) });
      assert.equal(r.status, 401);
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('http+auth: correct token -> 200', async () => {
  const goodToken = 'alice-token-' + 'x'.repeat(20);
  const tokens = { alice: goodToken };
  const dir = mkdtempSync(join(tmpdir(), 'mcp-auth-'));
  const file = join(dir, 'tokens.json');
  writeFileSync(file, JSON.stringify(tokens), { mode: 0o600 });
  try {
    await withServer({ MCP_BEARER_TOKENS_FILE: file }, async (port) => {
      const r = await postMcp(port, rpc(1, 'tools/list'), { 'Authorization': `Bearer ${goodToken}` });
      assert.equal(r.status, 200);
      const body = await r.json();
      assert.equal(body.result.tools.length, 26);
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('http+auth: env var fallback works', async () => {
  const goodToken = 'env-token-' + 'x'.repeat(20);
  await withServer({ MCP_BEARER_TOKENS: goodToken }, async (port) => {
    const r1 = await postMcp(port, rpc(1, 'tools/list'));
    assert.equal(r1.status, 401);
    const r2 = await postMcp(port, rpc(1, 'tools/list'), { 'Authorization': `Bearer ${goodToken}` });
    assert.equal(r2.status, 200);
  });
});
