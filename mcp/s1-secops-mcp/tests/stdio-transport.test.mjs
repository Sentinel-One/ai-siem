/**
 * stdio transport integration test.
 *
 * Spawns `node index.js` with default stdio transport, sends JSON-RPC
 * over stdin, reads JSON-RPC over stdout. Verifies:
 *   - initialize returns the expected protocol version and server info
 *   - tools/list returns 26 tools
 *   - resources/list returns 2 resources
 *   - prompts/list returns 2 prompts
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const __dir = dirname(fileURLToPath(import.meta.url));
const SERVER = resolve(__dir, '..', 'index.js');

function runOnce(messages, { timeoutMs = 10000 } = {}) {
  return new Promise((resolveP, rejectP) => {
    const child = spawn(process.execPath, [SERVER], {
      stdio: ['pipe', 'pipe', 'pipe'],
      env: { ...process.env, MCP_TRANSPORT: 'stdio' },
    });

    const replies = [];
    let stdoutBuf = '';
    let stderrBuf = '';

    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      rejectP(new Error(`Test timeout after ${timeoutMs}ms; stderr was: ${stderrBuf}`));
    }, timeoutMs);

    child.stdout.on('data', (chunk) => {
      stdoutBuf += chunk.toString('utf-8');
      let idx;
      while ((idx = stdoutBuf.indexOf('\n')) >= 0) {
        const line = stdoutBuf.slice(0, idx).trim();
        stdoutBuf = stdoutBuf.slice(idx + 1);
        if (!line) continue;
        try { replies.push(JSON.parse(line)); }
        catch (e) { rejectP(new Error(`Bad JSON from server: ${line}`)); return; }
        if (replies.length === messages.filter(m => m.id !== undefined).length) {
          // Got all expected replies. Close stdin so the server exits cleanly.
          child.stdin.end();
        }
      }
    });

    child.stderr.on('data', (chunk) => { stderrBuf += chunk.toString('utf-8'); });

    child.on('error', rejectP);
    child.on('exit', () => {
      clearTimeout(timer);
      resolveP({ replies, stderr: stderrBuf });
    });

    for (const msg of messages) {
      child.stdin.write(JSON.stringify(msg) + '\n');
    }
  });
}

test('stdio: initialize returns expected envelope', async () => {
  const { replies } = await runOnce([
    { jsonrpc: '2.0', id: 1, method: 'initialize', params: {
      protocolVersion: '2024-11-05',
      capabilities: {},
      clientInfo: { name: 'stdio-test', version: '1' },
    }},
  ]);
  assert.equal(replies.length, 1);
  const r = replies[0];
  assert.equal(r.jsonrpc, '2.0');
  assert.equal(r.id, 1);
  assert.ok(r.result);
  assert.equal(r.result.serverInfo.name, 's1-secops-mcp-server');
  assert.equal(r.result.serverInfo.version, '1.2.2');
  assert.ok(r.result.capabilities.tools);
});

test('stdio: tools/list returns 26 tools', async () => {
  const { replies } = await runOnce([
    { jsonrpc: '2.0', id: 1, method: 'initialize', params: {
      protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 't', version: '1' },
    }},
    { jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} },
  ]);
  const toolsReply = replies.find(r => r.id === 2);
  assert.ok(toolsReply, `no reply with id=2 in: ${JSON.stringify(replies)}`);
  assert.ok(toolsReply.result.tools);
  assert.equal(toolsReply.result.tools.length, 26);
});

test('stdio: resources/list returns 2 resources', async () => {
  const { replies } = await runOnce([
    { jsonrpc: '2.0', id: 1, method: 'initialize', params: {
      protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 't', version: '1' },
    }},
    { jsonrpc: '2.0', id: 2, method: 'resources/list', params: {} },
  ]);
  const r = replies.find(x => x.id === 2);
  assert.equal(r.result.resources.length, 2);
  const uris = r.result.resources.map(x => x.uri).sort();
  assert.deepEqual(uris, ['sentinelone://credentials-status', 'sentinelone://soc-context']);
});

test('stdio: prompts/list returns 2 prompts', async () => {
  const { replies } = await runOnce([
    { jsonrpc: '2.0', id: 1, method: 'initialize', params: {
      protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 't', version: '1' },
    }},
    { jsonrpc: '2.0', id: 2, method: 'prompts/list', params: {} },
  ]);
  const r = replies.find(x => x.id === 2);
  assert.equal(r.result.prompts.length, 2);
  const names = r.result.prompts.map(x => x.name).sort();
  assert.deepEqual(names, ['session_init', 'soc_analyst']);
});

test('stdio: unknown method returns -32601', async () => {
  const { replies } = await runOnce([
    { jsonrpc: '2.0', id: 1, method: 'initialize', params: {
      protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 't', version: '1' },
    }},
    { jsonrpc: '2.0', id: 2, method: 'does/not/exist', params: {} },
  ]);
  const r = replies.find(x => x.id === 2);
  assert.ok(r.error);
  assert.equal(r.error.code, -32601);
});
