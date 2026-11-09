/**
 * Detection as Code (1.6.2): dac_apply is tied to the reviewed bundle by hash, an apply that may
 * have been committed says so, 429 on apply is retried, and deploymentsFile must be YAML.
 * HTTP is mocked; no network.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, mkdirSync, writeFileSync, realpathSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

process.env.S1_CONSOLE_URL ||= 'https://tenant.sentinelone.net';
process.env.S1_CONSOLE_API_TOKEN ||= 'test-token';

const zip = await import('../lib/zip.js');
const dac = await import('../tools/dac.js');
const tool = name => dac.tools.find(t => t.name === name);
dac.retryTiming.baseMs = 1;

function stubFetch(responders) {
  const calls = [];
  const real = globalThis.fetch;
  let i = 0;
  globalThis.fetch = async (url, opts = {}) => {
    const call = { url: new URL(String(url)), body: opts.body };
    calls.push(call);
    const r = responders[Math.min(i++, responders.length - 1)];
    return typeof r === 'function' ? r(call) : r;
  };
  return { calls, restore: () => { globalThis.fetch = real; } };
}
const json = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

const SUMMARY = { totalChanges: 1, totalCreates: 0, totalUpdates: 1, totalDeletes: 0, totalImports: 0, totalRetains: 0 };
const diffBody = () => ({ data: { summary: SUMMARY, vcsRepoId: 'r1', creates: [], updates: [{ externalId: 'a' }], deletes: [], imports: [], retains: [] } });
const applied = () => ({ data: { summary: SUMMARY, vcsRepoId: 'r1', creates: [], updates: [{ externalId: 'a' }], deletes: [], imports: [], retains: [] } });
const VCS = { vcsRepoId: 'r1', vcsRepoName: 'org/repo', vcsCommitId: 'abc123' };
const DEP = 'targets:\n  t:\n    scopeId: "1"\n    scopeLevel: site\ndeploy:\n  t:\n    - "rules/*.yaml"\n';
const FILES = { 'deployments.yaml': DEP, 'rules/a.yaml': 'id: a\nqueryType: events\nseverity: High\n' };
const hashOf = files => createHash('sha256').update(zip.writeZip(dac.collectBundle({ files }).entries)).digest('hex');
const HASH = hashOf(FILES);
const modes = s => s.calls.map(c => c.url.searchParams.get('mode'));

test('dac_diff returns the zipSha256 that dac_apply expects, and the bundle hash is stable', async () => {
  const s = stubFetch([json(diffBody())]);
  try {
    const r = JSON.parse(await tool('dac_diff').handler({ ...VCS, files: FILES }));
    assert.equal(r.bundle.zipSha256, HASH);
    assert.equal(hashOf({ ...FILES }), HASH, 'same input, same bytes');
  } finally { s.restore(); }
});

test('expectedZipSha256 is required and validated before any request', async () => {
  assert.ok(tool('dac_apply').inputSchema.required.includes('expectedZipSha256'));
  const s = stubFetch([json(diffBody())]);
  try {
    for (const expectedZipSha256 of [undefined, '', 'abc', 'z'.repeat(64), 42]) {
      await assert.rejects(tool('dac_apply').handler({ ...VCS, files: FILES, expectedSummary: SUMMARY, expectedZipSha256 }), /expectedZipSha256 is required/);
    }
    assert.equal(s.calls.length, 0);
  } finally { s.restore(); }
});

test('a changed rule with the same change counts is refused before any request', async () => {
  const edited = { ...FILES, 'rules/a.yaml': 'id: a\nqueryType: events\nseverity: Low\n' };
  const s = stubFetch([json(diffBody()), json(applied())]);
  try {
    await assert.rejects(tool('dac_apply').handler({ ...VCS, files: edited, expectedSummary: SUMMARY, expectedZipSha256: HASH }), (e) => {
      assert.match(e.message, /dac_apply refused: the bundle differs from the one that was reviewed/);
      assert.match(e.message, /Nothing was sent/);
      return true;
    });
    assert.equal(s.calls.length, 0, 'no diff and no apply were sent');
  } finally { s.restore(); }
});

test('the reviewed bundle applies, with the hash accepted in upper case', async () => {
  const s = stubFetch([json(diffBody()), json(applied())]);
  try {
    const r = JSON.parse(await tool('dac_apply').handler({ ...VCS, files: FILES, expectedSummary: SUMMARY, expectedZipSha256: HASH.toUpperCase() }));
    assert.equal(r.mode, 'apply');
    assert.equal(r.bundle.zipSha256, HASH);
    assert.deepEqual(modes(s), ['diff', 'apply']);
  } finally { s.restore(); }
});

test('an apply timeout says it may have been committed and is not retried', async () => {
  const timeout = () => { const e = new Error('The operation was aborted due to timeout'); e.name = 'TimeoutError'; throw e; };
  const s = stubFetch([json(diffBody()), timeout]);
  try {
    await assert.rejects(tool('dac_apply').handler({ ...VCS, files: FILES, expectedSummary: SUMMARY, expectedZipSha256: HASH }), (e) => {
      assert.match(e.message, /mode=apply timed out/);
      assert.match(e.message, /may have been committed/);
      assert.match(e.message, /run dac_diff/);
      return true;
    });
    assert.deepEqual(modes(s), ['diff', 'apply']);
  } finally { s.restore(); }
});

test('an apply network error says it may have been committed and is not retried', async () => {
  const s = stubFetch([json(diffBody()), () => { throw new TypeError('fetch failed'); }]);
  try {
    await assert.rejects(tool('dac_apply').handler({ ...VCS, files: FILES, expectedSummary: SUMMARY, expectedZipSha256: HASH }), /failed before a response arrived \(fetch failed\)\. The apply may have been committed/);
    assert.deepEqual(modes(s), ['diff', 'apply']);
  } finally { s.restore(); }
});

test('an apply 5xx carries the may-have-been-committed hint and is not retried; a 4xx does not', async () => {
  let s = stubFetch([json(diffBody()), json({ errors: ['boom'] }, 502)]);
  try {
    await assert.rejects(tool('dac_apply').handler({ ...VCS, files: FILES, expectedSummary: SUMMARY, expectedZipSha256: HASH }), /HTTP 502.*may have been committed/s);
    assert.deepEqual(modes(s), ['diff', 'apply']);
  } finally { s.restore(); }
  s = stubFetch([json(diffBody()), json({ errors: ['bad rule'] }, 400)]);
  try {
    await assert.rejects(tool('dac_apply').handler({ ...VCS, files: FILES, expectedSummary: SUMMARY, expectedZipSha256: HASH }), (e) => {
      assert.match(e.message, /HTTP 400/);
      assert.doesNotMatch(e.message, /may have been committed/);
      return true;
    });
  } finally { s.restore(); }
});

test('an apply HTTP 429 is retried once the console accepts it', async () => {
  const s = stubFetch([json(diffBody()), new Response('<html>429</html>', { status: 429 }), json(applied())]);
  try {
    const r = JSON.parse(await tool('dac_apply').handler({ ...VCS, files: FILES, expectedSummary: SUMMARY, expectedZipSha256: HASH }));
    assert.equal(r.mode, 'apply');
    assert.deepEqual(modes(s), ['diff', 'apply', 'apply']);
  } finally { s.restore(); }
});

test('deploymentsFile must be a .yaml or .yml file', async () => {
  const repo = realpathSync(mkdtempSync(join(tmpdir(), 'dac162-')));
  mkdirSync(join(repo, 'rules'));
  writeFileSync(join(repo, 'rules', 'a.yaml'), 'id: a\nqueryType: events\n');
  writeFileSync(join(repo, 'notes.txt'), DEP);
  writeFileSync(join(repo, 'prod.yml'), DEP);
  assert.throws(() => dac.collectBundle({ repoDir: repo, deploymentsFile: 'notes.txt' }), /deploymentsFile must be a \.yaml or \.yml file/);
  assert.throws(() => dac.collectBundle({ repoDir: repo, deploymentsFile: join(repo, 'notes.txt') }), /deploymentsFile must be a \.yaml or \.yml file/);
  const b = dac.collectBundle({ repoDir: repo, deploymentsFile: 'prod.yml' });
  assert.equal(b.entries[0].name, 'deployments.yaml');
  assert.deepEqual(b.ruleFiles, ['rules/a.yaml']);
});
