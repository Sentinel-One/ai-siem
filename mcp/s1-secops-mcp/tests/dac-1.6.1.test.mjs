/**
 * Detection as Code tools (1.6.1): lib/zip.js and tools/dac.js (dac_export, dac_diff, dac_apply).
 * HTTP is mocked; no network.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, symlinkSync, statSync, readFileSync, realpathSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { crc32 } from 'node:zlib';

process.env.S1_CONSOLE_URL ||= 'https://tenant.sentinelone.net';
process.env.S1_CONSOLE_API_TOKEN ||= 'test-token';

const zip = await import('../lib/zip.js');
const dac = await import('../tools/dac.js');
const tool = name => dac.tools.find(t => t.name === name);
dac.retryTiming.baseMs = 1;

async function withEnv(vars, fn) {
  const saved = {};
  for (const k of Object.keys(vars)) saved[k] = process.env[k];
  for (const [k, v] of Object.entries(vars)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
  try { return await fn(); } finally {
    for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
  }
}

/** Replace fetch with a queue of responders; records every call. */
function stubFetch(responders) {
  const calls = [];
  const real = globalThis.fetch;
  let i = 0;
  globalThis.fetch = async (url, opts = {}) => {
    const call = { url: new URL(String(url)), method: opts.method || 'GET', headers: opts.headers || {}, body: opts.body };
    calls.push(call);
    const r = responders[Math.min(i++, responders.length - 1)];
    return typeof r === 'function' ? r(call) : r;
  };
  return { calls, restore: () => { globalThis.fetch = real; } };
}

const json = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
const binary = buf => new Response(buf, { status: 200, headers: { 'Content-Type': 'application/zip' } });

const SUMMARY = { totalChanges: 2, totalCreates: 1, totalUpdates: 1, totalDeletes: 0, totalImports: 0, totalRetains: 0 };
const diffBody = (summary = SUMMARY, n = 1) => ({
  data: {
    summary,
    vcsRepoId: 'r1',
    creates: Array.from({ length: n }, (_, k) => ({ externalId: `c${k}`, scopeId: '1', scopeLevel: 'site' })),
    updates: [{ externalId: 'u0' }], deletes: [], imports: [], retains: [],
  },
});
const VCS = { vcsRepoId: 'r1', vcsRepoName: 'org/repo', vcsCommitId: 'abc123' };
const DEP = 'targets:\n  t:\n    scopeId: "1"\n    scopeLevel: site\ndeploy:\n  t:\n    - "rules/*.yaml"\n';
const FILES = { 'deployments.yaml': DEP, 'rules/a.yaml': 'id: a\nqueryType: events\n' };
const HASH = (await import('node:crypto')).createHash('sha256').update(zip.writeZip(dac.collectBundle({ files: FILES }).entries)).digest('hex');

/** Rename the single entry of a one-entry zip (same length), bypassing the writer's name checks. */
function zipWithName(name) {
  const placeholder = 'x'.repeat(Buffer.byteLength(name));
  const buf = zip.writeZip([{ name: placeholder, data: 'payload' }]);
  const out = Buffer.from(buf);
  const from = Buffer.from(placeholder);
  let at = out.indexOf(from);
  while (at >= 0) { Buffer.from(name).copy(out, at); at = out.indexOf(from, at + 1); }
  return out;
}

const LOCAL = 0x04034b50;
const CENTRAL = 0x02014b50;
/** Offsets of every local and central header in a writer-produced zip. */
function headers(buf) {
  const loc = []; const cen = [];
  for (let i = 0; i + 4 <= buf.length; i++) {
    const v = buf.readUInt32LE(i);
    if (v === LOCAL) loc.push(i); else if (v === CENTRAL) cen.push(i);
  }
  return { loc, cen };
}

// ─── lib/zip.js ───────────────────────────────────────────────────────────────

test('zip round trip: every entry reads back byte for byte', () => {
  const entries = [
    { name: 'deployments.yaml', data: DEP },
    { name: 'rules/nested/deep/r1.yaml', data: 'id: r1\nname: "ünïcode ✓"\n' },
    { name: 'empty.yaml', data: '' },
    { name: 'bin.dat', data: Buffer.from(Array.from({ length: 4096 }, (_, k) => (k * 31) & 0xff)) },
    { name: 'dir/', data: '' },
  ];
  const buf = zip.writeZip(entries);
  const back = zip.readZip(buf);
  assert.deepEqual(back.map(e => e.name), entries.map(e => e.name));
  for (const [k, e] of entries.entries()) {
    const want = Buffer.isBuffer(e.data) ? e.data : Buffer.from(e.data, 'utf-8');
    assert.ok(back[k].data.equals(want), `entry ${e.name} differs`);
  }
  assert.equal(back[4].directory, true);
  // Same input, same bytes (fixed timestamps).
  assert.ok(zip.writeZip(entries).equals(buf));
});

test('zip reader accepts a stored (method 0) entry', () => {
  // Build a stored zip by hand: local header + raw data + central directory + EOCD.
  const name = Buffer.from('s.txt'); const data = Buffer.from('stored bytes');
  const lh = Buffer.alloc(30); lh.writeUInt32LE(LOCAL, 0); lh.writeUInt16LE(20, 4); lh.writeUInt32LE(crc32(data) >>> 0, 14);
  lh.writeUInt32LE(data.length, 18); lh.writeUInt32LE(data.length, 22); lh.writeUInt16LE(name.length, 26);
  const ch = Buffer.alloc(46); ch.writeUInt32LE(CENTRAL, 0); ch.writeUInt16LE(20, 6); ch.writeUInt32LE(crc32(data) >>> 0, 16);
  ch.writeUInt32LE(data.length, 20); ch.writeUInt32LE(data.length, 24); ch.writeUInt16LE(name.length, 28);
  const cdOff = 30 + name.length + data.length;
  const cd = Buffer.concat([ch, name]);
  const eocd = Buffer.alloc(22); eocd.writeUInt32LE(0x06054b50, 0); eocd.writeUInt16LE(1, 8); eocd.writeUInt16LE(1, 10);
  eocd.writeUInt32LE(cd.length, 12); eocd.writeUInt32LE(cdOff, 16);
  const back = zip.readZip(Buffer.concat([lh, name, data, cd, eocd]));
  assert.equal(back[0].name, 's.txt');
  assert.ok(back[0].data.equals(data));
});

test('zip-slip: unsafe entry names are refused by the reader and the writer', () => {
  for (const bad of ['/etc/passwd', '../escape.yaml', 'rules/../../escape.yaml', 'rules\\win.yaml', 'C:/x.yaml', 'c:x.yaml', 'a//b.yaml', './a.yaml', 'a/./b.yaml', 'a/..']) {
    assert.throws(() => zip.readZip(zipWithName(bad)), /zip entry name/, `reader accepted ${bad}`);
    assert.throws(() => zip.writeZip([{ name: bad, data: 'x' }]), /zip entry name/, `writer accepted ${bad}`);
  }
});

test('zip caps: entry count and total uncompressed size are enforced before inflating', () => {
  const buf = zip.writeZip([{ name: 'a', data: 'x'.repeat(100) }, { name: 'b', data: 'y'.repeat(100) }, { name: 'c', data: 'z' }]);
  assert.throws(() => zip.readZip(buf, { maxEntries: 2 }), /3 entries, over the limit of 2/);
  assert.throws(() => zip.readZip(buf, { maxTotalBytes: 150 }), /exceeds the limit of 150 bytes/);
  assert.equal(zip.readZip(buf, { maxEntries: 3, maxTotalBytes: 201 }).length, 3);
});

test('zip reader: a header that understates the size, a bad CRC, an unsupported method and encryption are refused', () => {
  const big = zip.writeZip([{ name: 'bomb', data: Buffer.alloc(100000) }]);
  const { loc, cen } = headers(big);
  // Understated uncompressed size: inflate is bounded by the declared size.
  const lie = Buffer.from(big); lie.writeUInt32LE(10, cen[0] + 24); lie.writeUInt32LE(10, loc[0] + 22);
  assert.throws(() => zip.readZip(lie), /failed to inflate within its declared size of 10 bytes/);
  const crc = Buffer.from(big); crc.writeUInt32LE(1, cen[0] + 16);
  assert.throws(() => zip.readZip(crc), /CRC-32/);
  const method = Buffer.from(big); method.writeUInt16LE(12, cen[0] + 10);
  assert.throws(() => zip.readZip(method), /compression method 12/);
  const enc = Buffer.from(big); enc.writeUInt16LE(0x0801, cen[0] + 8);
  assert.throws(() => zip.readZip(enc), /encrypted/);
  assert.throws(() => zip.readZip(Buffer.from('not a zip at all, just text here')), /not a zip archive/);
});

// ─── bundle layout ────────────────────────────────────────────────────────────

function makeRepo() {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 's1dac-')));
  const repo = join(root, 'repo', 'detections');
  mkdirSync(join(repo, 'rules', 'nested'), { recursive: true });
  mkdirSync(join(repo, '.git'), { recursive: true });
  mkdirSync(join(root, 'repo', 'consoles'), { recursive: true });
  writeFileSync(join(repo, 'deployments.yaml'), DEP);
  writeFileSync(join(repo, 'rules', 'a.yaml'), 'id: a\n');
  writeFileSync(join(repo, 'rules', 'nested', 'b.yml'), 'id: b\n');
  writeFileSync(join(repo, 'README.md'), '# not a rule\n');
  writeFileSync(join(repo, '.git', 'c.yaml'), 'id: hidden\n');
  writeFileSync(join(root, 'outside.yaml'), 'id: outside\n');
  symlinkSync(join(root, 'outside.yaml'), join(repo, 'rules', 'link.yaml'));
  writeFileSync(join(root, 'repo', 'consoles', 'prod.yaml'), 'targets: {}\ndeploy: {}\n# prod\n');
  return { root, repo };
}

test('bundle from repoDir: deployments.yaml at the root, rules at their relative path, no hidden files or symlinks', () => {
  const { root, repo } = makeRepo();
  return withEnv({ S1_OUTPUT_DIRS: root, S1_IN_CONTAINER: undefined }, () => {
    const b = dac.collectBundle({ repoDir: repo });
    assert.deepEqual(b.entries.map(e => e.name), ['deployments.yaml', 'rules/a.yaml', 'rules/nested/b.yml']);
    assert.equal(b.entries[0].data.toString(), DEP);
    assert.deepEqual(b.ruleFiles, ['rules/a.yaml', 'rules/nested/b.yml']);
    assert.ok(b.notes.some(n => /symlink/.test(n)));
    assert.ok(b.notes.some(n => /hidden/.test(n)));
  });
});

test('bundle from repoDir with a separate deploymentsFile: stored as deployments.yaml; a root deployments.yaml is not bundled as a rule', () => {
  const { root, repo } = makeRepo();
  return withEnv({ S1_OUTPUT_DIRS: root, S1_IN_CONTAINER: undefined }, () => {
    const b = dac.collectBundle({ repoDir: repo, deploymentsFile: '../consoles/prod.yaml' });
    assert.deepEqual(b.entries.map(e => e.name), ['deployments.yaml', 'rules/a.yaml', 'rules/nested/b.yml']);
    assert.match(b.entries[0].data.toString(), /# prod/);
    assert.ok(b.notes.some(n => /Skipped deployments.yaml at the repoDir root/.test(n)));
  });
});

test('bundle from files: deployments.yaml required, only safe .yaml/.yml paths, exactly one input', () => {
  const b = dac.collectBundle({ files: { ...FILES, 'z/b.yml': 'id: b\n' } });
  assert.deepEqual(b.entries.map(e => e.name), ['deployments.yaml', 'rules/a.yaml', 'z/b.yml']);
  assert.throws(() => dac.collectBundle({ files: { 'rules/a.yaml': 'id: a' } }), /must contain "deployments.yaml"/);
  assert.throws(() => dac.collectBundle({ files: { ...FILES, 'rules/a.txt': 'x' } }), /not a .yaml or .yml/);
  assert.throws(() => dac.collectBundle({ files: { ...FILES, '../evil.yaml': 'x' } }), /zip entry name/);
  assert.throws(() => dac.collectBundle({ files: FILES, repoDir: '/tmp' }), /exactly one of/);
  assert.throws(() => dac.collectBundle({}), /exactly one of/);
});

test('repoDir outside the allowed folders, relative, or a symlink is refused before any request', async () => {
  const { root, repo } = makeRepo();
  const other = realpathSync(mkdtempSync(join(tmpdir(), 's1dac-other-')));
  const s = stubFetch([json(diffBody())]);
  try {
    await withEnv({ S1_OUTPUT_DIRS: other, S1_IN_CONTAINER: undefined }, async () => {
      await assert.rejects(tool('dac_diff').handler({ ...VCS, repoDir: repo }), /outside the allowed directories/);
    });
    await withEnv({ S1_OUTPUT_DIRS: root, S1_IN_CONTAINER: undefined }, async () => {
      await assert.rejects(tool('dac_diff').handler({ ...VCS, repoDir: 'repo/detections' }), /absolute path/);
      symlinkSync(repo, join(root, 'linked'));
      await assert.rejects(tool('dac_diff').handler({ ...VCS, repoDir: join(root, 'linked') }), /symlink/);
      await assert.rejects(tool('dac_diff').handler({ ...VCS, repoDir: join(repo, '.git') }), /hidden/);
    });
    await withEnv({ S1_OUTPUT_DIRS: undefined, S1_IN_CONTAINER: '1' }, async () => {
      await assert.rejects(tool('dac_diff').handler({ ...VCS, repoDir: repo }), /no folder is shared with this container/);
    });
    assert.equal(s.calls.length, 0);
  } finally { s.restore(); }
});

// ─── parse-vcs ────────────────────────────────────────────────────────────────

test('dac_diff sends multipart: file=detections.zip plus vcsRepoId, vcsRepoName, vcsCommitId, ApiToken auth, mode=diff', async () => {
  const s = stubFetch([json(diffBody())]);
  try {
    await tool('dac_diff').handler({ ...VCS, files: FILES });
    assert.equal(s.calls.length, 1);
    const c = s.calls[0];
    assert.equal(c.method, 'POST');
    assert.equal(c.url.origin, 'https://tenant.sentinelone.net');
    assert.equal(c.url.pathname, '/web/api/v2.1/cloud-detection/rules/parse-vcs');
    assert.equal(c.url.searchParams.get('mode'), 'diff');
    assert.equal(c.headers.Authorization, `ApiToken ${process.env.S1_CONSOLE_API_TOKEN}`);
    assert.equal(c.headers['Content-Type'], undefined, 'fetch must set the multipart boundary itself');
    assert.ok(c.body instanceof FormData);
    assert.equal(c.body.get('vcsRepoId'), 'r1');
    assert.equal(c.body.get('vcsRepoName'), 'org/repo');
    assert.equal(c.body.get('vcsCommitId'), 'abc123');
    const file = c.body.get('file');
    assert.equal(file.name, 'detections.zip');
    assert.equal(file.type, 'application/zip');
    const entries = zip.readZip(Buffer.from(await file.arrayBuffer()));
    assert.deepEqual(entries.map(e => e.name), ['deployments.yaml', 'rules/a.yaml']);
  } finally { s.restore(); }
});

test('dac_diff passes the summary through and trims change lists', async () => {
  const s = stubFetch([json(diffBody(SUMMARY, 40))]);
  try {
    const r = JSON.parse(await tool('dac_diff').handler({ ...VCS, files: FILES, maxItems: 5 }));
    assert.deepEqual(r.summary, SUMMARY);
    assert.equal(r.mode, 'diff');
    assert.equal(r.creates.length, 5);
    assert.equal(r.listCounts.creates, 40);
    assert.match(r.trimmed, /cut to 5/);
    assert.equal(r.bundle.ruleFiles, 1);
  } finally { s.restore(); }
});

test('dac_diff writes the full response to outputFile', async () => {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), 's1dac-out-')));
  const s = stubFetch([json(diffBody(SUMMARY, 40))]);
  try {
    await withEnv({ S1_OUTPUT_DIRS: dir, S1_IN_CONTAINER: undefined }, async () => {
      const p = join(dir, 'diff.json');
      const r = JSON.parse(await tool('dac_diff').handler({ ...VCS, files: FILES, maxItems: 1, outputFile: p }));
      assert.equal(r.outputFile.path, p);
      assert.equal(JSON.parse(readFileSync(p, 'utf-8')).creates.length, 40);
      assert.equal(statSync(p).mode & 0o777, 0o600);
    });
  } finally { s.restore(); }
});

test('dac_diff surfaces an API validation error verbatim', async () => {
  const body = { data: { validationErrors: { global: [], rules: [{ errors: ['network_quarantine requires entity key with singleton group [agent.uuid]'], externalId: 'x' }] } } };
  const s = stubFetch([json(body, 400)]);
  try {
    await assert.rejects(tool('dac_diff').handler({ ...VCS, files: FILES }), (e) => {
      assert.match(e.message, /HTTP 400/);
      assert.ok(e.message.includes(JSON.stringify(body)));
      return true;
    });
    assert.equal(s.calls.length, 1, 'a 400 is not retried');
  } finally { s.restore(); }
});

test('dac_diff retries an HTTP 429', async () => {
  const s = stubFetch([new Response('<html>429 Too Many Requests</html>', { status: 429 }), json(diffBody())]);
  try {
    const r = JSON.parse(await tool('dac_diff').handler({ ...VCS, files: FILES }));
    assert.deepEqual(r.summary, SUMMARY);
    assert.equal(s.calls.length, 2);
  } finally { s.restore(); }
});

test('vcsRepoId, vcsRepoName and vcsCommitId are required, with no defaults', async () => {
  const s = stubFetch([json(diffBody())]);
  try {
    for (const k of ['vcsRepoId', 'vcsRepoName', 'vcsCommitId']) {
      const args = { ...VCS, files: FILES }; delete args[k];
      await assert.rejects(tool('dac_diff').handler(args), new RegExp(`${k} is required`));
    }
    assert.equal(s.calls.length, 0);
    for (const t of ['dac_diff', 'dac_apply']) {
      for (const k of ['vcsRepoId', 'vcsRepoName', 'vcsCommitId']) assert.ok(tool(t).inputSchema.required.includes(k));
    }
    assert.ok(tool('dac_apply').inputSchema.required.includes('expectedSummary'));
  } finally { s.restore(); }
});

test('dac_apply refuses when the fresh diff summary differs, and never sends mode=apply', async () => {
  const s = stubFetch([json(diffBody({ ...SUMMARY, totalDeletes: 3, totalChanges: 5 }))]);
  try {
    await assert.rejects(tool('dac_apply').handler({ ...VCS, files: FILES, expectedSummary: SUMMARY, expectedZipSha256: HASH }), (e) => {
      assert.match(e.message, /dac_apply refused/);
      assert.match(e.message, /"expectedSummary"/);
      assert.match(e.message, /"freshSummary"/);
      assert.match(e.message, /totalDeletes/);
      return true;
    });
    assert.equal(s.calls.length, 1);
    assert.equal(s.calls[0].url.searchParams.get('mode'), 'diff');
  } finally { s.restore(); }
});

test('dac_apply refuses without an expectedSummary, before any request', async () => {
  const s = stubFetch([json(diffBody())]);
  try {
    for (const expectedSummary of [undefined, {}, { foo: 1 }, [1]]) {
      await assert.rejects(tool('dac_apply').handler({ ...VCS, files: FILES, expectedSummary }), /expectedSummary is required/);
    }
    assert.equal(s.calls.length, 0);
  } finally { s.restore(); }
});

test('dac_apply sends mode=apply with the same bundle only after a matching diff', async () => {
  const applied = { data: { summary: SUMMARY, vcsRepoId: 'r1', creates: [{ externalId: 'c0' }], updates: [], deletes: [], imports: [], retains: [] } };
  const s = stubFetch([json(diffBody()), json(applied)]);
  try {
    const r = JSON.parse(await tool('dac_apply').handler({ ...VCS, files: FILES, expectedSummary: { ...SUMMARY }, expectedZipSha256: HASH }));
    assert.equal(r.mode, 'apply');
    assert.deepEqual(r.diffSummary, SUMMARY);
    assert.deepEqual(s.calls.map(c => c.url.searchParams.get('mode')), ['diff', 'apply']);
    const a = Buffer.from(await s.calls[0].body.get('file').arrayBuffer());
    const b = Buffer.from(await s.calls[1].body.get('file').arrayBuffer());
    assert.ok(a.equals(b), 'apply must send the bundle that was diffed');
  } finally { s.restore(); }
});

test('summaryMismatches compares every total, numerically, and treats a missing total as a mismatch', () => {
  assert.deepEqual(dac.summaryMismatches(SUMMARY, { ...SUMMARY }), []);
  assert.deepEqual(dac.summaryMismatches({ ...SUMMARY, totalCreates: '1' }, SUMMARY), []);
  assert.equal(dac.summaryMismatches({ totalChanges: 2 }, SUMMARY).length, 5);
  assert.deepEqual(dac.summaryMismatches(SUMMARY, { ...SUMMARY, totalRetains: 1 }).map(m => m.field), ['totalRetains']);
});

// ─── export-vcs ───────────────────────────────────────────────────────────────

function exportPage(rules, { nextCursor = null, totalItems } = {}) {
  const summary = { exported: rules.length, limit: 500, nextCursor, ...(totalItems !== undefined ? { totalItems } : {}) };
  return zip.writeZip([
    { name: 'export-summary.json', data: JSON.stringify(summary) },
    ...rules.map(([scope, id, qt]) => ({ name: `rules/${scope}/exported-rule-${id}.yaml`, data: `id: exported-rule-${id}\nname: r${id}\nqueryLang: '2.0'\nqueryType: ${qt}\n` })),
  ]);
}

test('dac_export follows nextCursor (URL-decoded) and counts by scope and queryType', async () => {
  const p1 = exportPage([['account-1', 1, 'events'], ['account-1', 2, 'scheduled']], { nextCursor: 'eyJhIjoxfQ%3D%3D', totalItems: 3 });
  const p2 = exportPage([['site-2', 3, 'correlation']]);
  const s = stubFetch([binary(p1), binary(p2)]);
  try {
    const r = JSON.parse(await tool('dac_export').handler({ listLimit: 1 }));
    assert.equal(s.calls.length, 2);
    assert.equal(s.calls[0].url.pathname, '/web/api/v2.1/cloud-detection/rules/export-vcs');
    assert.equal(s.calls[0].url.searchParams.get('cursor'), null);
    assert.equal(s.calls[1].url.searchParams.get('cursor'), 'eyJhIjoxfQ==');
    assert.equal(s.calls[1].url.searchParams.get('isLegacy'), null);
    assert.equal(r.pages, 2);
    assert.equal(r.rules, 3);
    assert.equal(r.totalItems, 3);
    assert.equal(r.complete, true);
    assert.deepEqual(r.byScope, { 'account-1': 2, 'site-2': 1 });
    assert.deepEqual(r.byQueryType, { events: 1, scheduled: 1, correlation: 1 });
    assert.equal(r.listing.length, 1);
    assert.match(r.listingTrimmed, /2 more/);
  } finally { s.restore(); }
});

test('dac_export stops at maxPages and says the export is incomplete', async () => {
  const p1 = exportPage([['account-1', 1, 'events']], { nextCursor: 'c1', totalItems: 9 });
  const s = stubFetch([binary(p1)]);
  try {
    const r = JSON.parse(await tool('dac_export').handler({ maxPages: 1 }));
    assert.equal(s.calls.length, 1);
    assert.equal(r.complete, false);
    assert.match(r.stopReason, /maxPages/);
  } finally { s.restore(); }
});

test('dac_export extracts to outputDir (files 0600) and writes raw page ZIPs to outputFile', async () => {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), 's1dac-exp-')));
  const p1 = exportPage([['account-1', 1, 'events']], { nextCursor: 'c1', totalItems: 2 });
  const p2 = exportPage([['site-2', 2, 'scheduled']]);
  await withEnv({ S1_OUTPUT_DIRS: dir, S1_IN_CONTAINER: undefined }, async () => {
    let s = stubFetch([binary(p1), binary(p2)]);
    try {
      const r = JSON.parse(await tool('dac_export').handler({ outputDir: join(dir, 'x') }));
      assert.equal(r.filesWritten, 4);
      const f = join(dir, 'x', 'rules', 'site-2', 'exported-rule-2.yaml');
      assert.match(readFileSync(f, 'utf-8'), /queryType: scheduled/);
      assert.equal(statSync(f).mode & 0o777, 0o600);
      assert.ok(statSync(join(dir, 'x', 'export-summary-page2.json')).isFile());
    } finally { s.restore(); }
    s = stubFetch([binary(p1), binary(p2)]);
    try {
      const r = JSON.parse(await tool('dac_export').handler({ outputFile: join(dir, 'export.zip') }));
      assert.deepEqual(r.outputFiles.map(o => o.path), [join(dir, 'export.zip'), join(dir, 'export-page2.zip')]);
      assert.ok(readFileSync(join(dir, 'export.zip')).equals(p1));
    } finally { s.restore(); }
  });
});

test('dac_export refuses an archive with a zip-slip entry and writes nothing', async () => {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), 's1dac-slip-')));
  const s = stubFetch([binary(zipWithName('rules/../../../evil.yaml'))]);
  try {
    await withEnv({ S1_OUTPUT_DIRS: dir, S1_IN_CONTAINER: undefined }, async () => {
      await assert.rejects(tool('dac_export').handler({ outputDir: join(dir, 'x') }), /zip entry name/);
    });
    assert.throws(() => statSync(join(dir, 'x')));
  } finally { s.restore(); }
});

test('queryTypeOf reads only a top-level queryType line', () => {
  assert.equal(dac.queryTypeOf("id: a\nqueryType: scheduled\n"), 'scheduled');
  assert.equal(dac.queryTypeOf("queryType: 'correlation'\n"), 'correlation');
  assert.equal(dac.queryTypeOf("scheduledParams:\n  query: 'x'\n  queryType: events\n"), 'unknown');
});
