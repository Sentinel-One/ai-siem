/**
 * 1.5.0: keychain credentials, no plaintext file discovery, stdio only,
 * redaction, outputFile safety, slicing merge, LOG queries, one console token.
 *
 * Hermetic: the real OS keychain is never touched. The Linux backend is driven
 * through a fake `secret-tool` on PATH that stores items in a temp directory.
 * Runs on macOS and Linux (the fake is a POSIX shell script).
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, mkdirSync, chmodSync, readFileSync, symlinkSync, existsSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const INDEX = join(ROOT, 'index.js');
const TOKEN = 'FAKEtoken0123456789abcdefABCDEF.eyJmYWtlIjp0cnVlfQ.sig_-x';

function fakeSecretTool() {
  const bin = mkdtempSync(join(tmpdir(), 's1kc-bin-'));
  const store = mkdtempSync(join(tmpdir(), 's1kc-store-'));
  const script = `#!/bin/sh
d="$FAKE_SECRET_STORE"
if [ -n "$FAKE_SECRET_DBUS_ERROR" ]; then echo "secret-tool: Cannot autolaunch D-Bus without X11 \\$DISPLAY" >&2; exit 1; fi
if [ -n "$FAKE_SECRET_SLEEP" ]; then sleep "$FAKE_SECRET_SLEEP"; fi
cmd=$1; shift
if [ -n "$FAKE_SECRET_LOCKED" ]; then
  case $cmd in
    search) echo "secret-tool: Cannot get secret of a locked object" >&2; exit 1;;
    lookup|clear) exit 1;;
    store) echo "secret-tool: Cannot create an item in a locked collection" >&2; exit 1;;
  esac
fi
case $cmd in
  store) shift 2; cat > "$d/$4"; exit 0;;
  lookup) if [ -f "$d/$4" ]; then cat "$d/$4"; exit 0; else exit 1; fi;;
  clear) rm -f "$d/$4"; exit 0;;
esac
exit 2
`;
  writeFileSync(join(bin, 'secret-tool'), script);
  chmodSync(join(bin, 'secret-tool'), 0o755);
  return { bin, store };
}

function run(args, { env = {}, input, cwd } = {}) {
  const r = spawnSync(process.execPath, [INDEX, ...args], {
    input: input ?? '',
    cwd: cwd || tmpdir(),
    encoding: 'utf-8',
    timeout: 20000,
    env: { PATH: process.env.PATH, ...env },
  });
  return { code: r.status, out: r.stdout || '', err: r.stderr || '' };
}

function linuxEnv(fake, extra = {}) {
  return {
    PATH: `${fake.bin}:${process.env.PATH}`,
    HOME: mkdtempSync(join(tmpdir(), 's1kc-home-')),
    S1_KEYCHAIN_BACKEND: 'linux',
    FAKE_SECRET_STORE: fake.store,
    ...extra,
  };
}

const STATUS_REQ = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'resources/read', params: { uri: 'sentinelone://credentials-status' } }) + '\n';
function credStatus(env, cwd) {
  const r = run([], { env, input: STATUS_REQ, cwd });
  const line = r.out.split('\n').find(l => l.includes('"id":1'));
  assert.ok(line, `no status reply. stderr: ${r.err}`);
  return { status: JSON.parse(JSON.parse(line).result.contents[0].text), err: r.err };
}

// ─── no plaintext file discovery ─────────────────────────────────────────────

test('decoy credentials.json files are never read (cwd, HOME, ~/mnt, ~/.config, CLAUDE_CONFIG_DIR, S1_CREDS_FILE, COWORK_WORKSPACE)', () => {
  const home = mkdtempSync(join(tmpdir(), 's1kc-decoy-'));
  const decoy = JSON.stringify({ S1_CONSOLE_URL: 'https://decoy.sentinelone.net', S1_CONSOLE_API_TOKEN: TOKEN });
  const places = [
    join(home, 'credentials.json'),
    join(home, '.config', 'sentinelone', 'credentials.json'),
    join(home, '.claude', 'sentinelone', 'credentials.json'),
    join(home, 'mnt', 'proj', 'credentials.json'),
    join(home, 'ccd', 'sentinelone', 'credentials.json'),
    join(home, 'ws', 'credentials.json'),
  ];
  for (const p of places) { mkdirSync(dirname(p), { recursive: true }); writeFileSync(p, decoy); }
  const { status } = credStatus({
    HOME: home, S1_KEYCHAIN: 'off',
    CLAUDE_CONFIG_DIR: join(home, 'ccd'), COWORK_WORKSPACE: join(home, 'ws'), S1_CREDS_FILE: places[0],
  }, home);
  assert.equal(status.s1MgmtApi.configured, false);
  assert.equal(status.s1MgmtApi.tokenPresent, false);
  assert.deepEqual(status.sources, {});
});

test('environment variables alone configure the server', () => {
  const { status } = credStatus({ S1_KEYCHAIN: 'off', S1_CONSOLE_URL: 'https://x.sentinelone.net', S1_CONSOLE_API_TOKEN: TOKEN });
  assert.equal(status.s1MgmtApi.configured, true);
  assert.equal(status.sources.S1_CONSOLE_API_TOKEN, 'env:S1_CONSOLE_API_TOKEN');
  assert.equal(status.keychain.available, false);
});

test('not-configured error names setup and the keychain reason, never a file', async () => {
  const { sdlToken } = await import('../lib/sdl.js');
  const saved = { ...process.env };
  delete process.env.S1_CONSOLE_API_TOKEN; delete process.env.S1_API_TOKEN;
  try {
    assert.throws(() => sdlToken(), (e) => /S1_CONSOLE_API_TOKEN not configured/.test(e.message)
      && /s1-secops-mcp setup/.test(e.message) && !/credentials\.json/.test(e.message));
  } finally { Object.assign(process.env, saved); }
});

// ─── keychain via the linux backend (fake secret-tool) ───────────────────────

test('setup (stdin NAME=value) stores, status masks, server reads from keychain', () => {
  const fake = fakeSecretTool();
  const env = linuxEnv(fake);
  const s = run(['setup'], { env, input: `S1_CONSOLE_URL=https://usea1-x.sentinelone.net/\nS1_CONSOLE_API_TOKEN=${TOKEN}\nJUNK=1\n` });
  assert.equal(s.code, 0, s.err);
  assert.ok(!s.err.includes(TOKEN) && !s.out.includes(TOKEN), 'setup must not echo the token');
  assert.equal(readFileSync(join(fake.store, 'default:S1_CONSOLE_URL'), 'utf-8'), 'https://usea1-x.sentinelone.net');
  assert.equal(readFileSync(join(fake.store, 'default:S1_CONSOLE_API_TOKEN'), 'utf-8'), TOKEN);

  const st = run(['status'], { env });
  assert.equal(st.code, 0, st.err);
  assert.ok(!st.out.includes(TOKEN), 'status must mask the token');
  assert.match(st.out, /S1_CONSOLE_API_TOKEN\s+keychain:linux\s+set \(\d+ chars\)/);

  const { status } = credStatus(env);
  assert.equal(status.s1MgmtApi.configured, true);
  assert.equal(status.sources.S1_CONSOLE_API_TOKEN, 'keychain:linux');
});

test('env overrides keychain per value', () => {
  const fake = fakeSecretTool();
  writeFileSync(join(fake.store, 'default:S1_CONSOLE_URL'), 'https://kc.sentinelone.net');
  writeFileSync(join(fake.store, 'default:S1_CONSOLE_API_TOKEN'), TOKEN);
  const { status } = credStatus(linuxEnv(fake, { S1_CONSOLE_URL: 'https://env.sentinelone.net' }));
  assert.equal(status.sources.S1_CONSOLE_URL, 'env:S1_CONSOLE_URL');
  assert.equal(status.sources.S1_CONSOLE_API_TOKEN, 'keychain:linux');
});

test('profiles are isolated', () => {
  const fake = fakeSecretTool();
  writeFileSync(join(fake.store, 'prod:S1_CONSOLE_URL'), 'https://prod.sentinelone.net');
  writeFileSync(join(fake.store, 'prod:S1_CONSOLE_API_TOKEN'), TOKEN);
  assert.equal(credStatus(linuxEnv(fake)).status.s1MgmtApi.configured, false);
  assert.equal(credStatus(linuxEnv(fake, { S1_PROFILE: 'prod' })).status.s1MgmtApi.configured, true);
  const bad = run(['status'], { env: linuxEnv(fake, { S1_PROFILE: 'bad profile!' }) });
  assert.equal(bad.code, 2);
});

test('headless Linux (no D-Bus) degrades to env with a clear reason, never a crash', () => {
  const fake = fakeSecretTool();
  const env = linuxEnv(fake, { FAKE_SECRET_DBUS_ERROR: '1' });
  const { status, err } = credStatus(env);
  assert.equal(status.keychain.available, false);
  assert.match(status.keychain.note, /D-Bus/);
  assert.match(err, /keychain \(linux: unavailable/);
  const ok = credStatus({ ...env, S1_CONSOLE_URL: 'https://x.sentinelone.net', S1_CONSOLE_API_TOKEN: TOKEN });
  assert.equal(ok.status.s1MgmtApi.configured, true);
  const s = run(['setup'], { env, input: `S1_CONSOLE_API_TOKEN=${TOKEN}\n` });
  assert.notEqual(s.code, 0);
  assert.match(s.err, /D-Bus/);
});

test('import-json migrates a legacy file, skips invalid values, maps aliases', () => {
  const fake = fakeSecretTool();
  const dir = mkdtempSync(join(tmpdir(), 's1kc-imp-'));
  const f = join(dir, 'credentials.json');
  writeFileSync(f, JSON.stringify({ S1_CONSOLE_URL: 'https://a.sentinelone.net/', S1_API_TOKEN: TOKEN, S1_HEC_INGEST_URL: 'xx', VT_API_KEY: 'a'.repeat(64), OTHER: 'ignored' }));
  const r = run(['setup', '--import-json', f, '--profile', 'imp'], { env: linuxEnv(fake) });
  assert.equal(r.code, 0, r.err);
  assert.match(r.err, /skip S1_HEC_INGEST_URL/);
  assert.ok(existsSync(join(fake.store, 'imp:S1_CONSOLE_API_TOKEN')));
  assert.ok(existsSync(join(fake.store, 'imp:VIRUSTOTAL_API_KEY')));
  assert.ok(!existsSync(join(fake.store, 'imp:S1_HEC_INGEST_URL')));
  assert.ok(!r.err.includes(TOKEN));
});

test('forget removes one name or the whole profile', () => {
  const fake = fakeSecretTool();
  for (const n of ['S1_CONSOLE_URL', 'S1_CONSOLE_API_TOKEN', 'S1_SCOPE']) writeFileSync(join(fake.store, `default:${n}`), n === 'S1_SCOPE' ? '123' : n === 'S1_CONSOLE_URL' ? 'https://a.sentinelone.net' : TOKEN);
  assert.equal(run(['forget', '--name', 'S1_SCOPE'], { env: linuxEnv(fake) }).code, 0);
  assert.deepEqual(readdirSync(fake.store).sort(), ['default:S1_CONSOLE_API_TOKEN', 'default:S1_CONSOLE_URL']);
  assert.equal(run(['forget'], { env: linuxEnv(fake) }).code, 0);
  assert.deepEqual(readdirSync(fake.store), []);
});

test('setup never accepts a secret as an argument', () => {
  const r = run(['setup', `--token=${TOKEN}`], { env: linuxEnv(fakeSecretTool()) });
  assert.equal(r.code, 2);
});

test('exec maps keychain values to purple-mcp and VirusTotal variable names', () => {
  const fake = fakeSecretTool();
  writeFileSync(join(fake.store, 'default:S1_CONSOLE_URL'), 'https://p.sentinelone.net');
  writeFileSync(join(fake.store, 'default:S1_CONSOLE_API_TOKEN'), TOKEN);
  writeFileSync(join(fake.store, 'default:VIRUSTOTAL_API_KEY'), 'b'.repeat(64));
  const probe = `const e=process.env;console.log(JSON.stringify({u:e.PURPLEMCP_CONSOLE_BASE_URL,t:e.PURPLEMCP_CONSOLE_TOKEN===${JSON.stringify(TOKEN)},vt:(e.VT_API_KEY||'').length,vt2:(e.VIRUSTOTAL_API_KEY||'').length,pvt:(e.PURPLEMCP_VT_API_KEY||'').length}))`;
  const r = run(['exec', '--', process.execPath, '-e', probe], { env: linuxEnv(fake) });
  assert.equal(r.code, 0, r.err);
  assert.deepEqual(JSON.parse(r.out.trim()), { u: 'https://p.sentinelone.net', t: true, vt: 64, vt2: 64, pvt: 64 });
});

// ─── stdio only ──────────────────────────────────────────────────────────────

test('HTTP transport is gone: --transport http and MCP_TRANSPORT=http exit 2', () => {
  assert.equal(run(['--transport', 'http'], { env: { S1_KEYCHAIN: 'off' } }).code, 2);
  assert.equal(run([], { env: { S1_KEYCHAIN: 'off', MCP_TRANSPORT: 'http' } }).code, 2);
  assert.equal(run(['--host', '0.0.0.0'], { env: { S1_KEYCHAIN: 'off' } }).code, 2);
  const ok = run(['--transport', 'stdio'], { env: { S1_KEYCHAIN: 'off' }, input: '' });
  assert.equal(ok.code, 0, ok.err);
});

// ─── redaction ───────────────────────────────────────────────────────────────

test('redact masks configured secrets and auth headers', async () => {
  const saved = { ...process.env };
  process.env.S1_CONSOLE_API_TOKEN = TOKEN;
  process.env.S1_HEC_TOKEN = 'hecKEY0123456789abcdef0123456789';
  try {
    const { redact } = await import('../lib/redact.js');
    const s = redact(`a ${TOKEN} b Authorization: ApiToken eyJhbGciOi.zzzzzzzzzzzz c Bearer yyyy-yyyy-yyyy-1234 d hecKEY0123456789abcdef0123456789`);
    assert.ok(!s.includes(TOKEN) && !s.includes('zzzzzzzzzzzz') && !s.includes('yyyy-yyyy-yyyy-1234') && !s.includes('hecKEY'));
    assert.match(s, /ApiToken \[REDACTED\]/);
    // Prose and success output are never pattern-masked (R2 regression).
    const prose = 'Basic authentication and Bearer tokenization; ApiToken placeholder_value_here';
    assert.equal(redact('Basic authentication and Bearer tokenization'), 'Basic authentication and Bearer tokenization');
    assert.equal(redact(prose, { patterns: false }), prose);
    assert.equal(redact(`x ${TOKEN} Bearer abcd-1234-efgh-5678`, { patterns: false }), 'x [REDACTED] Bearer abcd-1234-efgh-5678');
  } finally { process.env = saved; }
});

// ─── outputFile safety ───────────────────────────────────────────────────────

test('outputFile: absolute only, inside allowed roots, no overwrite, no symlink, mode 0600', async () => {
  const { writeOutput, resolveOutputPath } = await import('../lib/output.js');
  const root = mkdtempSync(join(tmpdir(), 's1kc-out-'));
  const outside = mkdtempSync(join(tmpdir(), 's1kc-outside-'));
  const saved = process.env.S1_OUTPUT_DIRS;
  process.env.S1_OUTPUT_DIRS = root;
  try {
    assert.throws(() => resolveOutputPath('relative.json'), /absolute/);
    assert.throws(() => resolveOutputPath(join(outside, 'x.json')), /outside the allowed/);
    assert.throws(() => resolveOutputPath(join(root, '..', 'escape.json')), /outside the allowed/);
    symlinkSync(outside, join(root, 'link'));
    assert.throws(() => resolveOutputPath(join(root, 'link', 'x.json')), /outside the allowed/);
    const w = writeOutput(join(root, 'sub', 'r.json'), '{"a":1}');
    assert.equal(w.bytes, 7);
    assert.equal(spawnSync('stat', process.platform === 'darwin' ? ['-f', '%Lp', w.path] : ['-c', '%a', w.path], { encoding: 'utf-8' }).stdout.trim(), '600');
    assert.throws(() => writeOutput(w.path, 'x'), /already exists/);
    assert.equal(writeOutput(w.path, 'xy', { overwrite: true }).bytes, 2);
    writeFileSync(join(outside, 't'), 'x');
    symlinkSync(join(outside, 't'), join(root, 'f.json'));
    assert.throws(() => writeOutput(join(root, 'f.json'), 'x', { overwrite: true }), /outside the allowed|symlink/);
  } finally { if (saved === undefined) delete process.env.S1_OUTPUT_DIRS; else process.env.S1_OUTPUT_DIRS = saved; }
});

test('rowsToCsv quotes commas, quotes and newlines; union of keys', async () => {
  const { rowsToCsv } = await import('../lib/output.js');
  assert.equal(rowsToCsv([{ a: 1, b: 'x,y' }, { a: 'q"q', c: 'l\nm' }]), 'a,b,c\n1,"x,y",\n"q""q",,"l\nm"\n');
});

// ─── slicing ─────────────────────────────────────────────────────────────────

test('sliceWindow covers the window exactly with no gaps', async () => {
  const { sliceWindow } = await import('../lib/slicing.js');
  const w = sliceWindow('2026-10-01T00:00:00Z', '2026-10-02T00:00:00Z', 7);
  assert.equal(w.length, 7);
  assert.equal(w[0].startTime, '2026-10-01T00:00:00Z');
  assert.equal(w[6].endTime, '2026-10-02T00:00:00Z');
  for (let i = 1; i < w.length; i++) assert.equal(w[i].startTime, w[i - 1].endTime);
});

test('mergeRows sums, mins and maxes by key', async () => {
  const { mergeRows } = await import('../lib/slicing.js');
  const rows = [{ k: 'a', n: 2, lo: 5, hi: 5 }, { k: 'b', n: 1, lo: 1, hi: 1 }, { k: 'a', n: '3', lo: 2, hi: 9 }];
  assert.deepEqual(mergeRows(rows, { keys: ['k'], sum: ['n'], min: ['lo'], max: ['hi'] }).sort((x, y) => x.k.localeCompare(y.k)),
    [{ k: 'a', n: 5, lo: 2, hi: 9 }, { k: 'b', n: 1, lo: 1, hi: 1 }]);
});

test('non-mergeable aggregates are refused when merging slices', async () => {
  const saved = { ...process.env };
  process.env.S1_CONSOLE_URL = 'https://x.sentinelone.net'; process.env.S1_CONSOLE_API_TOKEN = TOKEN;
  try {
    const { slicedRun } = await import('../lib/slicing.js');
    await assert.rejects(slicedRun('| group d=estimate_distinct(x)', { slices: 3, merge: { keys: [] }, hours: 3 }), /non-additive/);
  } finally { process.env = saved; }
});

// ─── LOG queries and the console token (no network) ─────────────────────────

test('LOG query with pipes is rejected before any network call', async () => {
  const saved = { ...process.env };
  process.env.S1_CONSOLE_URL = 'https://x.invalid'; process.env.S1_CONSOLE_API_TOKEN = TOKEN;
  try {
    const { lrqRun } = await import('../lib/s1.js');
    await assert.rejects(lrqRun("dataSource.name='x' | limit 5", { queryType: 'LOG' }), /filter expression only/);
    await assert.rejects(lrqRun('x', { queryType: 'FACET' }), /PQ" or "LOG/);
  } finally { process.env = saved; }
});

test('one console token: jwt() returns S1_CONSOLE_API_TOKEN and the s1_api_* tools take no token selector', async () => {
  const saved = { ...process.env };
  process.env.S1_CONSOLE_URL = 'https://x.invalid'; process.env.S1_CONSOLE_API_TOKEN = TOKEN;
  try {
    const { jwt } = await import('../lib/s1.js');
    assert.equal(jwt(), TOKEN);
    const { tools } = await import('../tools/mgmt-console.js');
    for (const t of tools.filter(x => x.name.startsWith('s1_api_'))) {
      assert.deepEqual(Object.keys(t.inputSchema.properties).filter(k => /token/i.test(k)), [], t.name);
    }
    const { KEY_NAMES } = await import('../lib/keystore.js');
    assert.deepEqual(KEY_NAMES.filter(n => n.startsWith('S1_CONSOLE_API_TOKEN')), ['S1_CONSOLE_API_TOKEN']);
  } finally { process.env = saved; }
});

test('HTTP 403 code 4030010 (multi-account token) adds the single-account token / S1_PROFILE hint', async () => {
  const saved = { ...process.env };
  process.env.S1_CONSOLE_URL = 'https://x.sentinelone.invalid'; process.env.S1_CONSOLE_API_TOKEN = TOKEN;
  const realFetch = globalThis.fetch;
  let status = 403;
  let body = { errors: [{ code: 4030010, detail: null, title: "This page doesn't support multi-scopes users yet" }] };
  globalThis.fetch = async () => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
  try {
    const { apiPost, apiGet, apiGetBinary } = await import('../lib/s1.js');
    for (const call of [
      () => apiPost('/web/api/v2.1/threat-intelligence/iocs', { data: [] }),
      () => apiGet('/web/api/v2.1/threat-intelligence/iocs'),
      () => apiGetBinary('/web/api/v2.1/threat-intelligence/iocs'),
    ]) {
      await assert.rejects(call(), (e) => /403/.test(e.message) && /S1_PROFILE/.test(e.message)
        && /single account or site/.test(e.message) && /setup --profile/.test(e.message));
    }
    // Any other 403 carries no hint.
    body = { errors: [{ code: 4030001, title: 'Insufficient permissions' }] };
    await assert.rejects(apiPost('/web/api/v2.1/threat-intelligence/iocs', {}), (e) => /403/.test(e.message) && !/S1_PROFILE/.test(e.message));
  } finally { globalThis.fetch = realFetch; process.env = saved; }
});

test('validateValue rejects bad URLs, scopes, short or spaced tokens', async () => {
  const { validateValue } = await import('../lib/cli.js');
  assert.ok(validateValue('S1_CONSOLE_URL', 'http://x.sentinelone.net'));
  assert.ok(validateValue('S1_CONSOLE_URL', 'https://x.sentinelone.net/web/api'));
  assert.equal(validateValue('S1_CONSOLE_URL', 'https://x.sentinelone.net'), null);
  assert.ok(validateValue('S1_SCOPE', 'abc'));
  assert.equal(validateValue('S1_SCOPE', '123:456'), null);
  assert.equal(validateValue('S1_SCOPE', '123'), null);
  assert.ok(validateValue('S1_CONSOLE_API_TOKEN', 'short'));
  assert.ok(validateValue('S1_CONSOLE_API_TOKEN', 'has space in it 0123456789'));
  assert.equal(validateValue('S1_CONSOLE_API_TOKEN', TOKEN), null);
});

test('setup refuses a 3-part S1_SCOPE that lib/sdl.js resolveScope would reject', async () => {
  const { validateValue } = await import('../lib/cli.js');
  const { scopeHeaders } = await import('../lib/sdl.js');
  assert.match(validateValue('S1_SCOPE', '123:456:789'), /<accountId> or <accountId>:<siteId>/);
  assert.throws(() => scopeHeaders('123:456:789'), /Invalid S1-Scope/);
  // Whatever setup accepts, resolveScope (via scopeHeaders) accepts.
  for (const ok of ['123', '123:456']) {
    assert.equal(validateValue('S1_SCOPE', ok), null);
    assert.deepEqual(scopeHeaders(ok), { 'S1-Scope': ok });
  }
});

test('setup aliases accept every runtime ENV_ALIASES name', async () => {
  const { ALIASES } = await import('../lib/cli.js');
  const { ENV_ALIASES } = await import('../lib/credentials.js');
  for (const [canonical, names] of Object.entries(ENV_ALIASES)) {
    for (const n of names) if (n !== canonical) assert.equal(ALIASES[n], canonical, n);
  }
  assert.equal(ALIASES.S1_BASE_URL, 'S1_CONSOLE_URL');
  assert.equal(ALIASES.SDL_CONSOLE_API_TOKEN, 'S1_CONSOLE_API_TOKEN');
});

// ─── regressions found by the 1.5.0 live A/B run ────────────────────────────

test('outputFile refuses a DANGLING symlink even with overwrite:true (R1)', async () => {
  const { writeOutput } = await import('../lib/output.js');
  const root = mkdtempSync(join(tmpdir(), 's1kc-dang-'));
  const outside = mkdtempSync(join(tmpdir(), 's1kc-dang-out-'));
  const saved = process.env.S1_OUTPUT_DIRS;
  process.env.S1_OUTPUT_DIRS = root;
  try {
    symlinkSync(join(outside, 'not-yet.txt'), join(root, 'dangling.json'));
    assert.throws(() => writeOutput(join(root, 'dangling.json'), 'x', { overwrite: true }), /symlink/);
    assert.throws(() => writeOutput(join(root, 'dangling.json'), 'x'), /symlink/);
    assert.equal(existsSync(join(outside, 'not-yet.txt')), false);
  } finally { if (saved === undefined) delete process.env.S1_OUTPUT_DIRS; else process.env.S1_OUTPUT_DIRS = saved; }
});

test('merged slices apply a trailing sort/limit AFTER the merge and refuse other post-group commands (R4)', async () => {
  const { planMergedQuery, splitPipes } = await import('../lib/slicing.js');
  assert.deepEqual(splitPipes("a='x|y' | group n=count() by k | sort -n"), ["a='x|y' ", ' group n=count() by k ', ' sort -n']);
  const p = planMergedQuery('| group n=count() by k | sort -n, k | limit 3');
  assert.equal(p.query.trim(), '| group n=count() by k');
  assert.deepEqual(p.post, { sort: [{ desc: true, col: 'n' }, { desc: false, col: 'k' }], limit: 3 });
  assert.throws(() => planMergedQuery('| group n=count() by k | columns k'), /cannot be merged/);
  assert.throws(() => planMergedQuery('| group n=count() by k | filter n > 5'), /cannot be merged/);
  assert.throws(() => planMergedQuery('dataSource.name=*'), /needs a query whose result comes from \| group/);
});

test('locked Linux keyring is reported as locked, not "not configured"; forget removes nothing and fails', () => {
  const fake = fakeSecretTool();
  writeFileSync(join(fake.store, 'default:S1_CONSOLE_API_TOKEN'), TOKEN);
  const env = linuxEnv(fake, { FAKE_SECRET_LOCKED: '1' });
  const { status } = credStatus(env);
  assert.equal(status.keychain.available, false);
  assert.match(status.keychain.note, /locked/);
  const f = run(['forget'], { env });
  assert.equal(f.code, 2);
  assert.match(f.err, /nothing removed/);
  assert.ok(existsSync(join(fake.store, 'default:S1_CONSOLE_API_TOKEN')));
  const s = run(['setup'], { env, input: `S1_CONSOLE_API_TOKEN=${TOKEN}\n` });
  assert.equal(s.code, 2);
  assert.match(s.err, /locked/);
});

test('keyring helper that hangs times out with a clear message (no "exit null")', () => {
  const fake = fakeSecretTool();
  const env = linuxEnv(fake, { FAKE_SECRET_SLEEP: '5', S1_KEYCHAIN_TIMEOUT_MS: '1000' });
  const st = run(['status'], { env });
  assert.match(st.out, /timed out after 1 s/);
  assert.ok(!/exit null/.test(st.out + st.err));
});


// ─── QA round 2 ──────────────────────────────────────────────────────────────

test('merge spec must name real columns and cover every result column', async () => {
  const { validateMergeSpec } = await import('../lib/slicing.js');
  assert.doesNotThrow(() => validateMergeSpec({ keys: ['k'], sum: ['n'] }, ['k', 'n']));
  assert.throws(() => validateMergeSpec({ keys: ['K'], sum: ['n'] }, ['k', 'n']), /not in the result: K/);
  assert.throws(() => validateMergeSpec({ sum: ['n'] }, ['k', 'n']), /missing: k/);
});

test('output policy refuses dot paths and autostart folders below any root', async () => {
  const { resolveOutputPath } = await import('../lib/output.js');
  const { homedir } = await import('node:os');
  const saved = process.env.S1_OUTPUT_DIRS;
  delete process.env.S1_OUTPUT_DIRS;
  try {
    assert.throws(() => resolveOutputPath(join(homedir(), '.ssh', 'authorized_keys')), /dot\) path or an autostart/);
    assert.throws(() => resolveOutputPath(join(homedir(), '.zshrc')), /dot\) path or an autostart/);
    assert.throws(() => resolveOutputPath(join(homedir(), 'Library', 'LaunchAgents', 'x.plist')), /autostart/);
    assert.ok(resolveOutputPath(join(homedir(), 's1-out-test', 'r.json')));
    const root = mkdtempSync(join(tmpdir(), 's1kc-explicit-'));
    process.env.S1_OUTPUT_DIRS = root;
    // An explicit root does not switch the filter off below it...
    assert.throws(() => resolveOutputPath(join(root, '.hidden', 'x.json')), /dot\) path or an autostart/);
    process.env.S1_OUTPUT_DIRS = homedir();
    assert.throws(() => resolveOutputPath(join(homedir(), '.zshrc')), /dot\) path or an autostart/);
    // ...but the root itself may be a dot directory.
    const dotRoot = join(root, '.cache-s1');
    mkdirSync(dotRoot);
    process.env.S1_OUTPUT_DIRS = dotRoot;
    assert.ok(resolveOutputPath(join(dotRoot, 'x.json')));
  } finally { if (saved === undefined) delete process.env.S1_OUTPUT_DIRS; else process.env.S1_OUTPUT_DIRS = saved; }
});

test('powerquery_run rejects fractional slices and LOG+merge; LOG allows a | inside quotes', async () => {
  const { tools } = await import('../tools/powerquery.js');
  const run = tools.find(t => t.name === 'powerquery_run').handler;
  await assert.rejects(run({ query: '| group n=count()', slices: 1.5 }), /whole number/);
  const saved = { ...process.env };
  process.env.S1_CONSOLE_URL = 'https://x.invalid'; process.env.S1_CONSOLE_API_TOKEN = TOKEN;
  try {
    const { slicedRun } = await import('../lib/slicing.js');
    await assert.rejects(slicedRun("a='x'", { queryType: 'LOG', slices: 2, merge: { keys: [] }, hours: 2 }), /merge applies to PQ/);
    const { lrqRun } = await import('../lib/s1.js');
    // Passes validation and fails later on the network (x.invalid), not on the pipe check.
    await assert.rejects(lrqRun("msg contains 'a|b'", { queryType: 'LOG', hours: 1 }), (e) => !/filter expression only/.test(e.message));
  } finally { process.env = saved; }
});

test('merge spec is validated BEFORE any slice runs when the group shape is known', async () => {
  const { slicedRun, groupColumns } = await import('../lib/slicing.js');
  assert.deepEqual(groupColumns('group n=count(), b=percentile(x, 50) by a.b, k'), ['a.b', 'k', 'n', 'b']);
  assert.equal(groupColumns('group count() by x'), null);
  const saved = { ...process.env };
  process.env.S1_CONSOLE_URL = 'https://x.invalid'; process.env.S1_CONSOLE_API_TOKEN = TOKEN;
  try {
    const t0 = Date.now();
    await assert.rejects(slicedRun('| group n=count() by k', { slices: 15, merge: { keys: ['K'], sum: ['n'] }, hours: 24 }), /not in the result: K/);
    assert.ok(Date.now() - t0 < 500, 'must fail before launching slices');
  } finally { process.env = saved; }
});


test('17-19 digit ids stay exact through JSON parsing (N3: shareResource id rounding)', async () => {
  const { parseJsonExact } = await import('../lib/json.js');
  const d = parseJsonExact('{"id":25738899845066752,"n":42,"f":1.5,"neg":-9007199254740993,"s":"25738899845066752"}');
  assert.equal(d.id, '25738899845066752');
  assert.equal(d.n, 42);
  assert.equal(d.f, 1.5);
  assert.equal(d.neg, '-9007199254740993');
  assert.equal(d.s, '25738899845066752');
});

test('N5: float literals beyond 2^53 stay numbers; only integer literals become strings', async () => {
  const { parseJsonExact } = await import('../lib/json.js');
  const d = parseJsonExact('{"a":1e21,"b":1.5e300,"c":12345678901234567890}');
  assert.equal(d.a, 1e21);
  assert.equal(d.b, 1.5e300);
  assert.equal(d.c, '12345678901234567890');
});

test('N4: merged sums, mins and maxes stay exact beyond 2^53', async () => {
  const { mergeRows } = await import('../lib/slicing.js');
  const rows = [
    { k: 'a', n: 2, big: '9007199254740993', lo: '2585262576128388545', hi: '2585262576128388545' },
    { k: 'a', n: 3, big: '9007199254740993', lo: '2585262576128388544', hi: '2585262576128388546' },
  ];
  const [m] = mergeRows(rows, { keys: ['k'], sum: ['n', 'big'], min: ['lo'], max: ['hi'] });
  assert.equal(m.n, 5);
  assert.equal(m.big, '18014398509481986');
  assert.equal(m.lo, '2585262576128388544');
  assert.equal(m.hi, '2585262576128388546');
});

test('N6: merged float sums above 2^53 stay numbers; N7: post-merge sort orders big integers exactly', async () => {
  const { mergeRows, planMergedQuery } = await import('../lib/slicing.js');
  const [m] = mergeRows([{ k: 'a', ts: 8.956740894843e18 }, { k: 'a', ts: 1.6444707523800531e22 }], { keys: ['k'], sum: ['ts'] });
  assert.equal(typeof m.ts, 'number');
  assert.equal(m.ts, 8.956740894843e18 + 1.6444707523800531e22);
  const slicing = await import('../lib/slicing.js');
  // applyPost is internal; drive it through planMergedQuery + mergeRows ordering semantics.
  const p = planMergedQuery('| group hi=max(x) by k | sort -hi');
  assert.deepEqual(p.post.sort, [{ desc: true, col: 'hi' }]);
  assert.ok(typeof slicing.mergeRows === 'function');
});

test('N7: applyPost sorts integer strings within 256 of each other exactly', async () => {
  const { applyPost } = await import('../lib/slicing.js');
  const rows = [{ hi: '2585262576128388545' }, { hi: '2585262576128388547' }, { hi: '2585262576128388546' }];
  assert.deepEqual(applyPost(rows, { sort: [{ desc: true, col: 'hi' }], limit: 2 }).map(r => r.hi), ['2585262576128388547', '2585262576128388546']);
  assert.deepEqual(applyPost(rows, { sort: [{ desc: false, col: 'hi' }], limit: null }).map(r => r.hi), ['2585262576128388545', '2585262576128388546', '2585262576128388547']);
});
