/**
 * Contract tests added in 1.3.9.
 *
 * The 1.3.8 suite asserted STRUCTURE (tool count, names, description keywords) with the
 * HTTP layer mocked. Four defects lived in the space that left uncovered, so each class
 * below closes one of them:
 *
 *   A. Executable doc examples   a payload printed in a SKILL.md must survive the tool
 *                                 it is printed next to.
 *   B. Outbound wire shape       assert the body actually sent, not just that the call
 *                                 was made.
 *   C. Client-parity schema lint every tool must be callable with only its `required`
 *                                 fields, and no tool may quietly add `default`
 *                                 keywords, which the host currently rejects.
 *   D. Response budget           a list tool must stay bounded at MSSP cardinality.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

process.env.S1_CONSOLE_URL ||= 'https://tenant.sentinelone.net';
process.env.S1_CONSOLE_API_TOKEN ||= 'test-token';

const { ALL_TOOLS } = await import('../lib/server-core.js');

const tool = name => {
  const t = ALL_TOOLS.find(x => x.name === name);
  assert.ok(t, `tool ${name} not registered`);
  return t;
};

/** Stub global.fetch, recording every outbound request. */
function stubFetch(responses) {
  const calls = [];
  global.fetch = async (url, opts = {}) => {
    calls.push({ url: String(url), method: opts.method, body: opts.body ? JSON.parse(opts.body) : undefined });
    const next = responses.shift();
    if (!next) throw new Error('stubFetch: ran out of queued responses');
    return {
      ok: next.status === undefined || (next.status >= 200 && next.status < 300),
      status: next.status ?? 200,
      headers: new Map([['Content-Type', 'application/json']]),
      text: async () => (typeof next.body === 'string' ? next.body : JSON.stringify(next.body)),
      json: async () => next.body,
      arrayBuffer: async () => new TextEncoder().encode(JSON.stringify(next.body)).buffer,
    };
  };
  return calls;
}

// ─── A. Executable doc examples ──────────────────────────────────────────────
//
// The smoke-test example in hyperautomation/SKILL.md shipped wrapped in {"data": ...}
// because that is the correct raw HTTP body. ha_import_workflow adds that envelope
// itself, so copy-pasting the documented example sent {"data":{"data":...}} and the API
// answered 422. Both artifacts were individually right; nothing executed one against
// the other. This test does.

const SKILL_MD = new URL('../../hyperautomation/SKILL.md', import.meta.url);

/** Every ```json block under the smoke-test heading, in document order. */
function smokeTestExamples() {
  const md = readFileSync(SKILL_MD, 'utf8');
  const start = md.indexOf('## Minimum viable workflow JSON');
  assert.notEqual(start, -1, 'smoke-test section missing from hyperautomation/SKILL.md');
  const section = md.slice(start, md.indexOf('\n## ', start + 10));
  return [...section.matchAll(/```json\n([\s\S]*?)```/g)].map(m => JSON.parse(m[1]));
}

test('A: the SKILL.md smoke test documents both the raw-API and the MCP form', () => {
  const ex = smokeTestExamples();
  assert.equal(ex.length, 2,
    'expected exactly two examples: Form A (raw API body) and Form B (MCP argument)');
  assert.ok(ex[0].data, 'Form A must carry the {"data": ...} envelope the endpoint requires');
  assert.equal(ex[0].data.name, 'minimal-smoke-test');
  assert.equal(ex[1].data, undefined, 'Form B must be the bare workflow, no envelope');
  assert.equal(ex[1].name, 'minimal-smoke-test');
  assert.deepEqual(ex[1], ex[0].data, 'the two forms must describe the same workflow');
});

test('A: both documented forms reach the API as a single data envelope', async () => {
  for (const [i, example] of smokeTestExamples().entries()) {
    const calls = stubFetch([{ body: { id: 'wf-1', name: 'minimal-smoke-test' } }]);
    await tool('ha_import_workflow').handler({
      workflowJson: JSON.stringify(example),
      siteIds: '2056852093198736293',
    });
    const sent = calls[0].body;
    assert.equal(sent.data.name, 'minimal-smoke-test',
      `form ${i === 0 ? 'A' : 'B'}: body.data.name must be set, the 422 said "Field required"`);
    assert.equal(sent.data.data, undefined,
      `form ${i === 0 ? 'A' : 'B'}: double-wrapped payload, this is the 1.3.8 defect`);
  }
});

// ─── B. Outbound wire shape ──────────────────────────────────────────────────

test('B: a bare workflow is wrapped exactly once', async () => {
  const calls = stubFetch([{ body: { id: 'wf-2' } }]);
  const out = await tool('ha_import_workflow').handler({
    workflowJson: JSON.stringify({ name: 'bare', actions: [] }),
    accountIds: '426418030212073761',
  });
  assert.deepEqual(calls[0].body, { data: { name: 'bare', actions: [] } });
  assert.equal(JSON.parse(out).importNote, undefined, 'a bare payload must not be reported as unwrapped');
});

test('B: the unwrap is reported, not silent', async () => {
  stubFetch([{ body: { id: 'wf-3' } }]);
  const out = JSON.parse(await tool('ha_import_workflow').handler({
    workflowJson: JSON.stringify({ data: { name: 'wrapped', actions: [] } }),
    accountIds: '426418030212073761',
  }));
  assert.match(out.importNote, /unwrapped/i,
    'silently accepting both shapes teaches nobody which one is right');
});

test('B: a workflow legitimately owning a `data` key is not unwrapped', async () => {
  const calls = stubFetch([{ body: { id: 'wf-4' } }]);
  // Guard against an over-eager unwrap: top-level `name` present means this IS the
  // workflow, and its `data` member belongs to it.
  const wf = { name: 'has-own-data', data: { something: true }, actions: [] };
  await tool('ha_import_workflow').handler({
    workflowJson: JSON.stringify(wf), accountIds: '1',
  });
  assert.deepEqual(calls[0].body, { data: wf });
});

test('B: ha_export_workflow sends the scope it was given', async () => {
  const calls = stubFetch([{ body: 'PK-zip-bytes' }]);
  await tool('ha_export_workflow').handler({ siteIds: '2056852093198736293' });
  assert.match(calls[0].url, /workflow-import-export\/export\?siteIds=2056852093198736293$/);
});

test('B: an unscoped export 403 names scope as a possible cause', async () => {
  stubFetch([{ status: 403, body: 'Insufficient permissions' }]);
  await assert.rejects(
    tool('ha_export_workflow').handler({}),
    // The message must not let the reader conclude "missing role" and stop there.
    /accountIds\/siteIds/,
  );
});

// ─── C. Client-parity schema lint ────────────────────────────────────────────
//
// The host converts each inputSchema into a validator and currently maps a property
// carrying `default` to a NON-OPTIONAL field, so omitting it fails before dispatch:
// "expected nonoptional, received undefined". This server never sees the call, and
// upgrading it cannot fix it. What this repo CAN do is refuse to grow the blast radius.

const KNOWN_DEFAULT_BEARING = {
  ha_list_workflows: ['limit', 'skip', 'sortBy', 'sortOrder'],
  uam_list_alerts: ['first', 'viewType'],
  powerquery_run: ['hours', 'maxRows'],
  powerquery_schema_discover: ['maxEvents', 'startTime'],
  powerquery_enumerate_sources: ['hours'],
  sdl_create_dashboard: ['isPublic'],
  uam_ingest_alert: ['title', 'hostname', 'filename', 'inline'],
};

test('C: no tool grows new `default` keywords while the host rejects them', () => {
  const actual = {};
  for (const t of ALL_TOOLS) {
    const props = t.inputSchema?.properties ?? {};
    const withDefault = Object.keys(props).filter(k => props[k] && 'default' in props[k]);
    if (withDefault.length) actual[t.name] = withDefault.sort();
  }
  const expected = Object.fromEntries(
    Object.entries(KNOWN_DEFAULT_BEARING).map(([k, v]) => [k, [...v].sort()]),
  );
  assert.deepEqual(actual, expected,
    'A property declaring `default` is rejected by the host when omitted. Document the ' +
    'default in the description and apply it in the handler signature instead. If the ' +
    'host bug is fixed, update this allowlist deliberately.');
});

test('C: every tool is callable with only its required properties', () => {
  for (const t of ALL_TOOLS) {
    const props = t.inputSchema?.properties ?? {};
    const required = t.inputSchema?.required ?? [];
    for (const r of required) {
      assert.ok(props[r], `${t.name}: required property "${r}" is not declared`);
      assert.ok(!('default' in props[r]),
        `${t.name}: "${r}" is required AND has a default, which contradicts itself`);
    }
    for (const [name, spec] of Object.entries(props)) {
      if (required.includes(name)) continue;
      // An optional property must be genuinely omittable. A default is the one thing
      // that currently makes it not so, which the allowlist test above pins.
      assert.ok(spec && typeof spec === 'object', `${t.name}: property "${name}" is malformed`);
    }
  }
});

// ─── D. Response budget ──────────────────────────────────────────────────────
//
// sdl_list_dashboards had no limit. On an MSSP account it returned 442,581 characters
// across 17,111 lines, which no caller can read. Cardinality is a property of the
// tenant, so a mock has to supply it; nothing in CI would otherwise be big enough.

const BUDGET = 200_000; // characters. Well under a usable context budget.

const bigDashboards = n => Array.from({ length: n }, (_, i) => ({
  id: String(7000000000000000 + i),
  name: `Dashboard number ${i} with a realistically long display name`,
  description: 'x'.repeat(220),
  configType: 'DASHBOARD',
  access: { public: true, users: [], owner: `serviceuser-${i}@mgmt-11633.sentinelone.net` },
}));

test('D: sdl_list_dashboards stays bounded at MSSP cardinality', async () => {
  stubFetch([{ body: { data: { dashboardsV2: bigDashboards(1200) } } }]);
  const out = await tool('sdl_list_dashboards').handler({});
  const parsed = JSON.parse(out);
  assert.equal(parsed.totalCount, 1200, 'the full count must still be reported');
  assert.equal(parsed.returned, 100, 'default page size');
  assert.equal(parsed.hasMore, true);
  assert.equal(parsed.nextOffset, 100);
  assert.ok(out.length < BUDGET, `response was ${out.length} chars, budget is ${BUDGET}`);
});

test('D: sdl_list_dashboards pages and namesOnly shrinks the payload', async () => {
  stubFetch([{ body: { data: { dashboardsV2: bigDashboards(1200) } } }]);
  const page2 = JSON.parse(await tool('sdl_list_dashboards').handler({ offset: 100, limit: 50 }));
  assert.equal(page2.returned, 50);
  assert.equal(page2.offset, 100);
  assert.equal(page2.dashboards[0].id, String(7000000000000000 + 100));

  stubFetch([{ body: { data: { dashboardsV2: bigDashboards(1200) } } }]);
  const full = await tool('sdl_list_dashboards').handler({ limit: 100 });
  stubFetch([{ body: { data: { dashboardsV2: bigDashboards(1200) } } }]);
  const names = await tool('sdl_list_dashboards').handler({ limit: 100, namesOnly: true });
  // Measured ~4.4x on this fixture. Assert 3x so the test pins a real property rather
  // than the exact fixture, and still fails if namesOnly stops dropping fields.
  assert.ok(names.length * 3 < full.length,
    `namesOnly should be much smaller: ${names.length} vs ${full.length} chars`);
  assert.deepEqual(Object.keys(JSON.parse(names).dashboards[0]), ['id', 'name']);
});

test('D: an oversized limit is clamped, not rejected', async () => {
  stubFetch([{ body: { data: { dashboardsV2: bigDashboards(1200) } } }]);
  const parsed = JSON.parse(await tool('sdl_list_dashboards').handler({ limit: 100000 }));
  assert.equal(parsed.limit, 1000, 'clamped to the documented maximum');
  assert.equal(parsed.returned, 1000);
});

test('D: sdl_list_files is bounded too, and count stays the full total', async () => {
  const files = Array.from({ length: 2000 }, (_, i) => ({
    udoId: null, name: `/logParsers/parser-${i}`, readOnly: false, version: i + 1,
  }));
  stubFetch([{ body: { data: { configFiles: files } } }]);
  const parsed = JSON.parse(await tool('sdl_list_files').handler({}));
  assert.equal(parsed.count, 2000, 'count must remain the full post-filter total');
  assert.equal(parsed.returned, 500, 'default page size');
  assert.equal(parsed.hasMore, true);
});

test('D: sdl_list_files applies pathPrefix before paging', async () => {
  const files = [
    ...Array.from({ length: 30 }, (_, i) => ({ udoId: null, name: `/logParsers/p${i}`, readOnly: false, version: 1 })),
    ...Array.from({ length: 30 }, (_, i) => ({ udoId: String(i), name: `/dashboards/d${i}`, readOnly: false, version: 1 })),
  ];
  stubFetch([{ body: { data: { configFiles: files } } }]);
  const parsed = JSON.parse(await tool('sdl_list_files').handler({ pathPrefix: '/dashboards/' }));
  assert.equal(parsed.count, 30, 'filter first, then page');
  assert.equal(parsed.hasMore, false);
  assert.ok(parsed.files.every(f => f.name.startsWith('/dashboards/')));
});
