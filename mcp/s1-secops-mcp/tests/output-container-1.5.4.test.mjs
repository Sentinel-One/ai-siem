/**
 * outputFile under the Docker image (1.5.4), from output-dir-changes.md.
 *
 *   T3: with no shared folder, a write to the container's /tmp reported success
 *       (path, bytes, sha256) and the file vanished with the container.
 *   T4: a host path was refused with "Set S1_OUTPUT_DIRS", advice that does
 *       nothing under Docker (the client config never reaches the container).
 *
 * In the image (S1_IN_CONTAINER=1) there is now no default root, and every
 * refusal tells the user to run `install --output-dir`. Outside the image the
 * old behaviour and message are unchanged. HTTP is mocked; no network.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, existsSync, readFileSync, realpathSync } from 'node:fs';
import { tmpdir, homedir } from 'node:os';
import { join } from 'node:path';

process.env.S1_CONSOLE_URL ||= 'https://tenant.sentinelone.net';
process.env.S1_CONSOLE_API_TOKEN ||= 'test-token';

const out = await import('../lib/output.js');
const { ALL_TOOLS } = await import('../lib/server-core.js');
const tool = name => ALL_TOOLS.find(x => x.name === name);

// Run fn with exactly these env values (undefined = unset), then restore.
async function withEnv(vars, fn) {
  const saved = {};
  for (const k of Object.keys(vars)) saved[k] = process.env[k];
  for (const [k, v] of Object.entries(vars)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
  try { return await fn(); } finally {
    for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
  }
}

const INSTALL_ADVICE = /install --output-dir <folder>.*Windows: -OutputDir.*restart Claude Desktop/;

function stubFetch(body) {
  const calls = [];
  const real = globalThis.fetch;
  globalThis.fetch = async (url) => {
    calls.push(String(url));
    return { ok: true, status: 200, headers: new Map([['Content-Type', 'application/json']]),
      text: async () => JSON.stringify(body), json: async () => body };
  };
  return { calls, restore: () => { globalThis.fetch = real; } };
}

test('container, no shared folder: no allowed roots at all', () => withEnv({ S1_IN_CONTAINER: '1', S1_OUTPUT_DIRS: undefined }, () => {
  assert.equal(out.inContainer(), true);
  assert.deepEqual(out.allowedRoots(), []);
}));

test('container, no shared folder: /tmp, home and any host path are refused with install advice (T3, T4)', () => withEnv({ S1_IN_CONTAINER: '1', S1_OUTPUT_DIRS: undefined }, () => {
  for (const p of [join(tmpdir(), 'inside-container.json'), join(homedir(), 'x.json'), '/Users/someone/secops/r.json']) {
    assert.throws(() => out.resolveOutputPath(p), (e) => {
      assert.match(e.message, /no output folder is shared with this container/);
      assert.match(e.message, INSTALL_ADVICE);
      assert.match(e.message, /under \/output/);
      assert.match(e.message, /S1_OUTPUT_DIRS in the client config has no effect under Docker/);
      assert.doesNotMatch(e.message, /Set S1_OUTPUT_DIRS to allow another directory/);
      return true;
    });
  }
}));

test('container, no shared folder: writeOutput creates nothing (no silent loss)', () => withEnv({ S1_IN_CONTAINER: '1', S1_OUTPUT_DIRS: undefined }, () => {
  const p = join(mkdtempSync(join(tmpdir(), 's1oc-lost-')), 'should-not-exist.json');
  assert.throws(() => out.writeOutput(p, '{"a":1}'), /no output folder is shared/);
  assert.equal(existsSync(p), false);
}));

test('container, shared folder set: inside is written, outside refused with container advice', () => {
  const root = mkdtempSync(join(tmpdir(), 's1oc-shared-'));
  const outside = mkdtempSync(join(tmpdir(), 's1oc-outside-'));
  return withEnv({ S1_IN_CONTAINER: '1', S1_OUTPUT_DIRS: root }, () => {
    assert.deepEqual(out.allowedRoots(), [realpathSync(root)]);
    const w = out.writeOutput(join(root, 'r.json'), '{"a":1}');
    assert.equal(w.bytes, 7);
    assert.equal(readFileSync(w.path, 'utf-8'), '{"a":1}');
    assert.throws(() => out.resolveOutputPath(join(outside, 'x.json')), (e) => {
      assert.match(e.message, /outside the folder shared with this container/);
      assert.match(e.message, INSTALL_ADVICE);
      return true;
    });
    // The existing safety rules still apply inside the shared folder.
    assert.throws(() => out.resolveOutputPath(join(root, '.ssh', 'authorized_keys')), /hidden \(dot\) path/);
  });
});

test('outside the image: home and temp stay the default roots, message unchanged', () => withEnv({ S1_IN_CONTAINER: undefined, S1_OUTPUT_DIRS: undefined }, () => {
  assert.equal(out.inContainer(), false);
  const roots = out.allowedRoots();
  assert.equal(roots.length, 2);
  const dir = mkdtempSync(join(tmpdir(), 's1oc-node-'));
  const w = out.writeOutput(join(dir, 'ok.json'), 'x');
  assert.equal(w.bytes, 1);
  assert.throws(() => out.resolveOutputPath('/definitely-not-a-root-s1oc/x.json'),
    /outside the allowed output directories .*Set S1_OUTPUT_DIRS to allow another directory/);
}));

test('S1_IN_CONTAINER other than "1" does not switch modes', () => withEnv({ S1_IN_CONTAINER: 'true', S1_OUTPUT_DIRS: undefined }, () => {
  assert.equal(out.inContainer(), false);
  assert.equal(out.allowedRoots().length, 2);
}));

test('s1_api_get in the container refuses outputFile BEFORE calling the API, with install advice', async () => {
  const f = stubFetch({ data: [{ id: 1 }] });
  try {
    await withEnv({ S1_IN_CONTAINER: '1', S1_OUTPUT_DIRS: undefined }, async () => {
      const p = join(tmpdir(), 's1oc-api-get.json');
      await assert.rejects(() => tool('s1_api_get').handler({ path: '/web/api/v2.1/system/status', outputFile: p }),
        (e) => { assert.match(e.message, INSTALL_ADVICE); return true; });
      assert.equal(existsSync(p), false);
      assert.equal(f.calls.length, 0, 'the API was called before the path was validated');
    });
  } finally { f.restore(); }
});

test('every outputFile tool description carries the Docker sentence', () => {
  const want = /Under the Docker launcher only the folder set with `install --output-dir` is shared with the host \(Windows: pass paths under `\/output`\); if none is set, tell the user to run it rather than writing elsewhere\./;
  const names = ['powerquery_run', 's1_api_get', 's1_api_download', 'ha_export_workflow'];
  for (const n of names) {
    const t = tool(n);
    assert.ok(t, `${n} is registered`);
    const d = t.inputSchema?.properties?.outputFile?.description || '';
    assert.match(d, want, `${n}.outputFile description`);
  }
});
