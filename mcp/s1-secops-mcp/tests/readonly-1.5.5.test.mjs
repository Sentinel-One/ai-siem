/**
 * Read-only mode (1.5.5): S1_READ_ONLY defaults to true, fails closed, and refuses every call that
 * would change the tenant before any network request. HTTP is mocked; no network.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

process.env.S1_CONSOLE_URL ||= 'https://tenant.sentinelone.net';
process.env.S1_CONSOLE_API_TOKEN ||= 'test-token-not-a-jwt';

const access = await import('../lib/access.js');
const core = await import('../lib/server-core.js');
const { ALL_TOOLS, dispatch } = core;
const tool = name => ALL_TOOLS.find(x => x.name === name);

async function withEnv(vars, fn) {
  const saved = {};
  for (const k of Object.keys(vars)) saved[k] = process.env[k];
  for (const [k, v] of Object.entries(vars)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
  try { return await fn(); } finally {
    for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
  }
}

function stubFetch(body = { data: {} }) {
  const calls = [];
  const real = globalThis.fetch;
  globalThis.fetch = async (url, opts = {}) => {
    calls.push({ url: String(url), method: opts.method || 'GET' });
    return { ok: true, status: 200, headers: new Map([['Content-Type', 'application/json']]),
      text: async () => JSON.stringify(body), json: async () => body, arrayBuffer: async () => new ArrayBuffer(0) };
  };
  return { calls, restore: () => { globalThis.fetch = real; } };
}

const jwt = exp => ['e30', Buffer.from(JSON.stringify({ exp })).toString('base64url'), 'sig'].join('.');

// Minimal valid-looking arguments for every write tool (the gate runs before validation of the
// rest, so these only need to reach it).
const WRITE_ARGS = {
  s1_api_put: { path: '/web/api/v2.1/x', body: {} },
  s1_api_patch: { path: '/web/api/v2.1/x', body: {} },
  s1_api_delete: { path: '/web/api/v2.1/x' },
  uam_add_note: { alertId: 'a1', note: 'n' },
  uam_set_status: { alertId: 'a1', status: 'RESOLVED' },
  uam_set_verdict: { alertId: 'a1', verdict: 'FALSE_POSITIVE' },
  uam_assign_alert: { alertId: 'a1', assigneeEmail: 'x@y.z' },
  uam_post_alert: { title: 't' },
  uam_ingest_alert: { title: 't' },
  hec_ingest: { events: [{}] },
  sdl_put_file: { path: '/dashboards/x', content: '{}' },
  sdl_delete_file: { path: '/dashboards/x' },
  sdl_create_dashboard: { name: 'x', config: '{}' },
  sdl_share_dashboard: { id: '1' },
  sdl_save_dashboard_layout: { id: '1', tabName: 'T', graphs: '{}' },
  sdl_delete_dashboard: { id: '1' },
  ha_import_workflow: { workflow: {} },
  ha_delete_workflow: { workflowId: '1' },
};

test('every tool is classified, and the classification covers exactly the registered tools', () => {
  const names = ALL_TOOLS.map(t => t.name).sort();
  assert.equal(names.length, 35);
  for (const n of names) assert.notEqual(access.accessOf(n), 'unclassified', `${n} is unclassified`);
  const all = new Set([...access.WRITE_TOOLS, ...access.CONDITIONAL_TOOLS, ...access.READ_TOOLS]);
  assert.deepEqual([...all].sort(), names, 'classification lists name a tool that does not exist');
  assert.deepEqual(Object.keys(WRITE_ARGS).sort(), [...access.WRITE_TOOLS].sort());
});

test('S1_READ_ONLY: default is read-only; only explicit false values enable write; typos fail closed', () => {
  const cases = [[undefined, true], ['', true], ['true', true], ['1', true], ['YES', true],
    ['false', false], ['0', false], ['No', false], ['off', false], ['flase', true], ['rw', true]];
  for (const [v, want] of cases) {
    const saved = process.env.S1_READ_ONLY;
    if (v === undefined) delete process.env.S1_READ_ONLY; else process.env.S1_READ_ONLY = v;
    try { assert.equal(access.readOnlyMode(), want, `S1_READ_ONLY=${v}`); } finally { process.env.S1_READ_ONLY = saved; }
  }
});

test('read-only (unset): every write tool is refused before any request, with the how-to-enable text', () => withEnv({ S1_READ_ONLY: undefined }, async () => {
  const f = stubFetch();
  try {
    for (const [name, args] of Object.entries(WRITE_ARGS)) {
      await assert.rejects(() => tool(name).handler(args), (e) => {
        assert.ok(e instanceof access.ReadOnlyError, `${name}: ${e.message}`);
        assert.match(e.message, /read-only mode \(S1_READ_ONLY\)/);
        assert.match(e.message, /install --read-write/);
        return true;
      });
    }
    assert.equal(f.calls.length, 0, `a refused write reached the network: ${JSON.stringify(f.calls)}`);
  } finally { f.restore(); }
}));

test('read-only: refusal through the MCP dispatcher is an isError result, not a crash', () => withEnv({ S1_READ_ONLY: 'true' }, async () => {
  const r = await dispatch('tools/call', { name: 'sdl_delete_dashboard', arguments: { id: '1' } }, 7);
  assert.equal(r.result.isError, true);
  assert.match(r.result.content[0].text, /read-only mode/);
}));

test('read-only: read tools still run', () => withEnv({ S1_READ_ONLY: 'true' }, async () => {
  const f = stubFetch({ data: [{ id: 1 }] });
  try {
    await tool('s1_api_get').handler({ path: '/web/api/v2.1/system/status' });
    assert.equal(f.calls.length, 1);
    assert.equal(f.calls[0].method, 'GET');
  } finally { f.restore(); }
}));

test('s1_api_post read-only allowlist: GraphQL queries and listed query endpoints pass; mutations and anything else are refused', () => withEnv({ S1_READ_ONLY: 'true' }, () => {
  const read = [
    ['/web/api/v2.1/unifiedalerts/graphql', { query: 'query Q { alerts(first: 1) { totalCount } }' }],
    ['/web/api/v2.1/unifiedalerts/graphql', { query: '# comment\n  { alerts { totalCount } }' }],
    ['/web/api/v2.1/graphql', [{ query: 'query A { a }' }, { query: 'query B { b }' }]],
    ['/web/api/v2.1/dv/init-query', { query: 'EventType = "Process Creation"' }],
    ['/web/api/v2.1/cloud-funnel/validate-query', {}],
    ['/web/api/v2.1/xdr/graph-explorer/query/explorer/v2', {}],
    ['/web/api/v2.1/xdr/assets/server/available-actions/with-status', {}],
  ];
  for (const [p, b] of read) assert.equal(access.callWrites('s1_api_post', { path: p, body: b }), false, `${p} should be a read`);
  const writes = [
    ['/web/api/v2.1/unifiedalerts/graphql', { query: 'mutation M { alertTriggerActions { x } }' }],
    ['/web/api/v2.1/graphql', [{ query: 'query A { a }' }, { query: 'mutation B { b }' }]],
    // One document, two operations: operationName selects the mutation (AppSec 1.5.5 finding).
    ['/web/api/v2.1/unifiedalerts/graphql', { query: 'query A { alerts { totalCount } } mutation B { alertTriggerActions { x } }', operationName: 'B' }],
    ['/web/api/v2.1/unifiedalerts/graphql', { query: '{ a }\nsubscription S { s }' }],
    ['/web/api/v2.1/unifiedalerts/graphql', { query: 'fragment F on X { y }' }],
    ['/web/api/v2.1/unifiedalerts/graphql', {}],
    ['/web/api/v2.1/filters', { name: 'saved filter' }],
    ['/web/api/v2.1/agents/actions/initiate-scan', {}],
    ['/web/api/v2.1/cloud-detection/rules', {}],
    ['/web/api/v2.1/hyper-automate/api/public/workflow-import-export/import', {}],
  ];
  for (const [p, b] of writes) assert.equal(access.callWrites('s1_api_post', { path: p, body: b }), true, `${p} should be a write`);
}));

test('powerquery_run: savelookup is refused in read-only mode, ordinary queries are not gated', () => withEnv({ S1_READ_ONLY: 'true' }, async () => {
  assert.equal(access.callWrites('powerquery_run', { query: "dataSource.name='x' | group n=count() by a" }), false);
  assert.equal(access.callWrites('powerquery_run', { query: "dataSource.name='x' | group n=count() by a | savelookup 'mytable'" }), true);
  await assert.rejects(() => tool('powerquery_run').handler({ query: "x=* | savelookup 't'" }), /writes a lookup table/);
}));

test('write enabled: a write passes the gate and logs one audit line without the body or the token', () => withEnv({ S1_READ_ONLY: 'false', S1_CONSOLE_API_TOKEN: 'secret-token-abcdef1234567890' }, async () => {
  const lines = [];
  const real = process.stderr.write.bind(process.stderr);
  process.stderr.write = (s) => { lines.push(String(s)); return true; };
  try {
    access.gate('s1_api_put', { path: '/web/api/v2.1/x', body: { password: 'body-secret' } });
  } finally { process.stderr.write = real; }
  const audit = lines.filter(l => l.includes(' WRITE '));
  assert.equal(audit.length, 1);
  assert.match(audit[0], /tool="s1_api_put" path="\/web\/api\/v2\.1\/x"/);
  assert.ok(!audit[0].includes('body-secret'));
  assert.ok(!audit[0].includes('secret-token-abcdef1234567890'));
}));

test('token checks: an expired JWT refuses the write; a valid JWT and a non-JWT token pass', () => withEnv({ S1_READ_ONLY: 'false', S1_CONSOLE_API_TOKEN: process.env.S1_CONSOLE_API_TOKEN }, () => {
  const past = Math.floor(Date.now() / 1000) - 60, future = Math.floor(Date.now() / 1000) + 86400 * 30;
  assert.equal(access.tokenExpiry(jwt(past)).getTime(), past * 1000);
  assert.equal(access.tokenExpiry('not-a-jwt'), null);
  const quiet = (fn) => { const r = process.stderr.write; process.stderr.write = () => true; try { return fn(); } finally { process.stderr.write = r; } };
  process.env.S1_CONSOLE_API_TOKEN = jwt(past);
  assert.throws(() => quiet(() => access.gate('sdl_delete_file', { path: '/x' })), /token expired/);
  process.env.S1_CONSOLE_API_TOKEN = jwt(future);
  quiet(() => access.gate('sdl_delete_file', { path: '/x' }));
  process.env.S1_CONSOLE_API_TOKEN = 'plain-token';
  quiet(() => access.gate('sdl_delete_file', { path: '/x' }));
  delete process.env.S1_CONSOLE_API_TOKEN;
  assert.throws(() => access.gate('sdl_delete_file', { path: '/x' }), /no console API token/);
}));

test('tools/list: annotations on every tool; write tools marked disabled only in read-only mode', () => withEnv({ S1_READ_ONLY: 'true' }, async () => {
  const ro = (await dispatch('tools/list', {}, 1)).result.tools;
  assert.equal(ro.length, 35);
  for (const t of ro) {
    assert.equal(typeof t.annotations?.readOnlyHint, 'boolean', t.name);
    assert.equal(t.annotations.readOnlyHint, access.accessOf(t.name) === 'read', t.name);
    if (access.WRITE_TOOLS.has(t.name)) assert.match(t.description, /^\[Disabled: read-only mode/);
  }
  assert.equal(ro.find(t => t.name === 'sdl_delete_file').annotations.destructiveHint, true);
  process.env.S1_READ_ONLY = 'false';
  const rw = (await dispatch('tools/list', {}, 2)).result.tools;
  assert.ok(!rw.some(t => /^\[Disabled/.test(t.description)));
}));

test('mode is reported in initialize instructions and in credentials-status', () => withEnv({ S1_READ_ONLY: undefined }, async () => {
  const init = await dispatch('initialize', {}, 1);
  assert.match(init.result.instructions, /READ-ONLY mode/);
  const st = await dispatch('resources/read', { uri: 'sentinelone://credentials-status' }, 2);
  const mode = JSON.parse(st.result.contents[0].text).mode;
  assert.equal(mode.readOnly, true);
  process.env.S1_READ_ONLY = 'false';
  assert.match((await dispatch('initialize', {}, 3)).result.instructions, /WRITE IS ENABLED/);
}));

test('local outputFile writes stay allowed in read-only mode', () => {
  const root = mkdtempSync(join(tmpdir(), 's1ro-out-'));
  return withEnv({ S1_READ_ONLY: 'true', S1_OUTPUT_DIRS: root, S1_IN_CONTAINER: undefined }, async () => {
    const f = stubFetch({ data: { health: 'ok' } });
    try {
      const out = JSON.parse(await tool('s1_api_get').handler({ path: '/web/api/v2.1/system/status', outputFile: join(root, 's.json') }));
      assert.ok(out.bytesWritten > 0);
    } finally { f.restore(); }
  });
});
