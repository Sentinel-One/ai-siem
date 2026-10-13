/**
 * Regressions from the 2026-10-02 smoke-test report, live-validated 2026-10-03.
 *
 *   1. powerquery_schema_discover sampled SDL ingest-metering rows (tag='logVolume'),
 *      which share the source's dataSource.name, and reported metric/path1/tag/value
 *      as the source schema. Measured: 42-64% of rows on 4 sources of one tenant.
 *   2. sdl_create_dashboard: a tab labelled with "name" instead of "tabName" was
 *      refused by the API as "one of the tabs in dashboard has a blank name", which
 *      does not say which key it wanted. Now caught before the mutation.
 *
 * HTTP is mocked; no network.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

process.env.S1_CONSOLE_URL ||= 'https://tenant.sentinelone.net';
process.env.S1_CONSOLE_API_TOKEN ||= 'test-token';

const { ALL_TOOLS } = await import('../lib/server-core.js');
const tool = name => ALL_TOOLS.find(x => x.name === name);

function stubFetch(body) {
  const calls = [];
  const real = globalThis.fetch;
  globalThis.fetch = async (url, opts = {}) => {
    calls.push({ url: String(url), body: opts.body ? JSON.parse(opts.body) : undefined });
    return {
      ok: true,
      status: 200,
      headers: new Map([['Content-Type', 'application/json']]),
      text: async () => JSON.stringify(body),
      json: async () => body,
    };
  };
  return { calls, restore: () => { globalThis.fetch = real; } };
}

const metering = (metric, value) => ({ attributes: { 'dataSource.name': 'Netskope', tag: 'logVolume', metric, path1: metric, value } });
const event = user => ({ attributes: { 'dataSource.name': 'Netskope', 'actor.user.name': user, 'event.type': 'Malware' } });

test('schema_discover drops logVolume metering rows and reports how many', async () => {
  const s = stubFetch({ status: 'success', matches: [event('a'), metering('logBytes', 204), metering('logEvents', 1), event('b')] });
  try {
    const out = JSON.parse(await tool('powerquery_schema_discover').handler({ dataSourceName: 'Netskope', maxEvents: 5 }));
    assert.equal(out.sampleEventCount, 2);
    assert.equal(out.excludedMeteringRows, 2);
    for (const f of ['metric', 'path1', 'tag', 'value']) assert.ok(!out.confirmedFields.includes(f), `${f} leaked into schema`);
    assert.ok(out.confirmedFields.includes('actor.user.name'));
    // Over-fetches so metering rows cannot crowd out real events.
    assert.ok(s.calls[0].body.maxCount >= 5 * 10);
  } finally { s.restore(); }
});

test('schema_discover says so when the window holds only metering rows', async () => {
  const s = stubFetch({ status: 'success', matches: [metering('logBytes', 4725), metering('logEvents', 3)] });
  try {
    const out = JSON.parse(await tool('powerquery_schema_discover').handler({ dataSourceName: 'Okta' }));
    assert.equal(out.excludedMeteringRows, 2);
    assert.equal(out.confirmedFields, undefined);
    assert.match(out.message, /ingest-metering/);
  } finally { s.restore(); }
});

test('create_dashboard refuses a tab with "name" but no "tabName", before any request', async () => {
  const s = stubFetch({});
  try {
    const config = JSON.stringify({ configType: 'TABBED', tabs: [{ name: 'Overview', graphs: [] }] });
    await assert.rejects(
      tool('sdl_create_dashboard').handler({ name: 'x', config }),
      /tabs\[0\] has "name":"Overview", rename it to "tabName"/
    );
    assert.equal(s.calls.length, 0, 'mutation must not be sent');
  } finally { s.restore(); }
});

const { excludeMetering } = await import('../lib/metering.js');

test('excludeMetering: rewrite table', () => {
  const cases = [
    // [input, expected query or null for unchanged]
    ["| group n=count() by dataSource.name", "tag != 'logVolume' | group n=count() by dataSource.name"],
    ["dataSource.name='Okta' | group n=count()", "tag != 'logVolume' and (dataSource.name='Okta'\n) | group n=count()"],
    ["a='x' or b='y'", "tag != 'logVolume' and (a='x' or b='y'\n)"],
    ["cmd contains 'a|b' | limit 5", "tag != 'logVolume' and (cmd contains 'a|b'\n) | limit 5"],
    ["dataSource.name='X' tag='logVolume' | group n=count()", null],
    ["| datasource alerts | limit 5", null],
    ["| join a=(x=1), b=(y=2) on k", null],
    ["| union (a=1), (b=2)", null],
  ];
  for (const [input, want] of cases) {
    const r = excludeMetering(input);
    if (want === null) {
      assert.equal(r.applied, false, input);
      assert.equal(r.query, input);
    } else {
      assert.equal(r.applied, true, input);
      assert.equal(r.query, want);
    }
  }
});

test('powerquery_run sends the metering-excluded query unless includeMetering is true', async () => {
  for (const [args, expectApplied] of [[{}, true], [{ includeMetering: true }, false]]) {
    const sent = [];
    const real = globalThis.fetch;
    globalThis.fetch = async (url, opts = {}) => {
      if (opts.method === 'POST') sent.push(JSON.parse(opts.body).pq.query);
      const body = opts.method === 'POST'
        ? { id: 'q1' }
        : { stepsCompleted: 1, stepsTotal: 1, data: { columns: [{ name: 'n' }], values: [[1]], matchCount: 1 } };
      return { ok: true, status: 200, headers: new Map([['X-Dataset-Query-Forward-Tag', 't']]), text: async () => JSON.stringify(body), json: async () => body };
    };
    try {
      const out = JSON.parse(await tool('powerquery_run').handler({ query: "dataSource.name='Okta' | group n=count()", ...args }));
      assert.equal(out.meteringExcluded, expectApplied);
      assert.equal(sent[0].startsWith("tag != 'logVolume'"), expectApplied);
    } finally { globalThis.fetch = real; }
  }
});

test('create_dashboard tool description names tabName and the 60-column grid', () => {
  const d = JSON.stringify(tool('sdl_create_dashboard').inputSchema.properties.config.description);
  assert.match(d, /tabName/);
  assert.match(d, /60-column grid/);
});

// ─── sdl_save_dashboard_layout is layout-only, matched by index ─────────────
function stubGraphql(queue) {
  const ops = [];
  const real = globalThis.fetch;
  globalThis.fetch = async (url, opts = {}) => {
    const body = opts.body ? JSON.parse(opts.body) : {};
    ops.push(body.operationName || (body.query || '').match(/(query|mutation)\s+(\w+)/)?.[2]);
    const next = queue.shift();
    return { ok: true, status: 200, headers: new Map([['Content-Type', 'application/json']]),
      text: async () => JSON.stringify(next), json: async () => next };
  };
  return { ops, restore: () => { globalThis.fetch = real; } };
}
const panel = (t, x) => ({ title: t, graphStyle: 'markdown', markdown: t, layout: { x, y: 0, w: 30, h: 8 } });
const dash = graphs => ({ data: { getDashboardV2: { id: '1', name: 'd', tabs: [{ tabName: 'T', graphs: JSON.stringify(graphs) }] } } });

test('save_layout refuses a payload with a different panel count, before the mutation', async () => {
  for (const sent of [[panel('A', 0)], [panel('A', 0), panel('B', 30), panel('C', 0)]]) {
    const s = stubGraphql([dash([panel('A', 0), panel('B', 30)])]);
    try {
      await assert.rejects(
        tool('sdl_save_dashboard_layout').handler({ id: '1', tabName: 'T', graphs: JSON.stringify({ graphs: sent }) }),
        /has 2 panel\(s\) and the payload has \d+.*positions only/
      );
      assert.equal(s.ops.length, 1, 'only the read, no mutation');
    } finally { s.restore(); }
  }
});

test('save_layout warns that content changes are dropped', async () => {
  const s = stubGraphql([dash([panel('A', 0), panel('B', 30)]), { data: { saveDashboardLayout: { graphs: '[]', options: '{}' } } }]);
  try {
    const out = JSON.parse(await tool('sdl_save_dashboard_layout').handler({
      id: '1', tabName: 'T', graphs: JSON.stringify({ graphs: [panel('A EDITED', 30), panel('B', 0)] }),
    }));
    const w = JSON.stringify(out);
    assert.match(w, /graphs\[0\] \(title, markdown\)/);
    assert.doesNotMatch(w, /graphs\[1\]/);
  } finally { s.restore(); }
});
