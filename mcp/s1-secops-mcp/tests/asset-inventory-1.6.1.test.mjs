/**
 * 1.6.1: Asset Inventory GraphQL tools (tools/asset-inventory.js).
 * HTTP is mocked; no network.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync, rmSync, realpathSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

process.env.S1_CONSOLE_URL ||= 'https://tenant.sentinelone.net';
process.env.S1_CONSOLE_API_TOKEN ||= 'test-token-not-a-jwt';

const ai = await import('../tools/asset-inventory.js');
const access = await import('../lib/access.js');

const TOOL = Object.fromEntries(ai.tools.map(t => [t.name, t]));

/** Mock fetch. Each response is { status, body } or a function (parsedRequestBody, callIndex) => { status, body }. */
function mockFetch(responses) {
  const calls = [];
  const queue = [...responses];
  const real = globalThis.fetch;
  globalThis.fetch = async (url, opts = {}) => {
    const body = opts.body ? JSON.parse(opts.body) : undefined;
    calls.push({ url: String(url), method: opts.method || 'GET', body });
    let r = queue.length > 1 ? queue.shift() : queue[0];
    if (typeof r === 'function') r = r(body, calls.length - 1);
    const status = r.status ?? 200;
    const text = typeof r.body === 'string' ? r.body : JSON.stringify(r.body ?? {});
    return { ok: status >= 200 && status < 300, status, headers: new Map(), text: async () => text };
  };
  return { calls, restore: () => { globalThis.fetch = real; } };
}

async function withMock(responses, fn) {
  const m = mockFetch(responses);
  try { return await fn(m.calls); } finally { m.restore(); }
}

const page = (ids, hasNextPage, endCursor, totalCount = 999) => ({
  body: { data: { assetInventoryAssets: { totalCount, pageInfo: { hasNextPage, endCursor }, edges: ids.map(id => ({ node: { id, name: `n-${id}` } })) } } },
});

// ─── Query builders ──────────────────────────────────────────────────────────

test('counts builder: query document, scope as a variable, omitted when unset', () => {
  const plain = ai.buildCountsQuery({});
  assert.equal(plain.query, 'query AssetInventoryCounts { assetInventoryAssetCounts { categories { category count subCategories { subCategory count } } surfaces { surface count } } }');
  assert.deepEqual(plain.variables, {});
  const scoped = ai.buildCountsQuery({ scope: { scopeType: 'account', scopeIds: ['123'] } });
  assert.match(scoped.query, /^query AssetInventoryCounts\(\$scope: AssetInventoryScopeSelectorInput\) \{ assetInventoryAssetCounts\(scope: \$scope\)/);
  assert.deepEqual(scoped.variables, { scope: { scopeType: 'ACCOUNT', scopeIds: ['123'] } });
  assert.equal(access.graphqlOperation(scoped.query), 'query');
});

test('search builder: every argument is a typed variable; unset arguments are left out', () => {
  const q = ai.buildSearchQuery({
    first: 100, after: 'CUR', surface: 'network_discovery', category: 'SERVER', subCategory: 'VIRTUAL_MACHINE',
    scope: { scopeType: 'SITE', scopeIds: ['42'] },
    filters: [{ fieldId: 'missingCoverage', stringIn: { values: ['EPP'] } }],
    sort: { by: 'lastActiveDt', order: 'desc' },
    fields: ['name', 'agent.uuid'],
  });
  assert.equal(q.operationName, 'AssetInventorySearch');
  for (const decl of ['$first: Int', '$after: String', '$surface: AssetInventorySurfaceInput', '$category: AssetInventoryCategoryInput',
    '$subCategory: AssetInventorySubCategoryInput', '$scope: AssetInventoryScopeSelectorInput',
    '$filters: [AssetInventoryFilterInput!]!', '$sort: AssetInventorySortInput']) {
    assert.ok(q.query.includes(decl), decl);
  }
  assert.ok(q.query.includes('edges { node { id name agent { uuid } } }'));
  assert.deepEqual(q.variables, {
    first: 100, after: 'CUR', surface: 'NETWORK_DISCOVERY', category: 'SERVER', subCategory: 'VIRTUAL_MACHINE',
    scope: { scopeType: 'SITE', scopeIds: ['42'] },
    filters: [{ fieldId: 'missingCoverage', stringIn: { values: ['EPP'] } }],
    sort: { by: 'lastActiveDt', order: 'DESC' },
  });

  const minimal = ai.buildSearchQuery({});
  assert.deepEqual(Object.keys(minimal.variables).sort(), ['filters', 'first']);
  for (const absent of ['$after', '$surface', '$category', '$subCategory', '$scope', '$sort']) assert.ok(!minimal.query.includes(absent), absent);
  assert.ok(minimal.query.includes(`node { ${ai.DEFAULT_SEARCH_FIELDS.join(' ')} }`));

  const count = ai.buildSearchQuery({ countOnly: true, surface: 'ENDPOINT' });
  assert.ok(count.query.includes('{ totalCount pageInfo { hasNextPage endCursor } }'));
  assert.ok(!count.query.includes('edges'));
});

test('get builder: exactly one of resourceId or agentUuid, default field set', () => {
  const q = ai.buildGetQuery({ agentUuid: 'abc-123' });
  assert.match(q.query, /^query AssetInventoryGet\(\$agentUuid: String\) \{ assetInventoryAssetOverview\(agentUuid: \$agentUuid\) \{ /);
  assert.deepEqual(q.variables, { agentUuid: 'abc-123' });
  for (const f of ['alertsCount { severity count alertIds }', 'tags { key value source readOnly }', 'agent { uuid ', 'infectionStatus', 'assetCriticality', 'riskFactors', 'surfaces']) {
    assert.ok(q.query.includes(f), f);
  }
  const r = ai.buildGetQuery({ resourceId: 'rid', scope: { scopeType: 'TENANT' } });
  assert.deepEqual(r.variables, { resourceId: 'rid', scope: { scopeType: 'TENANT', scopeIds: [] } });
  assert.throws(() => ai.buildGetQuery({}), /exactly one/);
  assert.throws(() => ai.buildGetQuery({ resourceId: 'a', agentUuid: 'b' }), /exactly one/);
});

test('filter_values builder: fieldIds required and validated, passed as a variable', () => {
  const q = ai.buildFilterValuesQuery({ fieldIds: ['missingCoverage', 'managedState', 'missingCoverage'], surface: 'NETWORK_DISCOVERY' });
  assert.match(q.query, /^query AssetInventoryFilterValues\(\$surface: AssetInventorySurfaceInput, \$filters: \[AssetInventoryFilterInput!\]!, \$fieldIds: \[String!\]!\)/);
  assert.ok(q.query.endsWith('{ data { fieldId values { label value count } } } }'));
  assert.deepEqual(q.variables.fieldIds, ['missingCoverage', 'managedState']);
  assert.throws(() => ai.buildFilterValuesQuery({}), /fieldIds is required/);
  assert.throws(() => ai.buildFilterValuesQuery({ fieldIds: [] }), /fieldIds is required/);
  assert.throws(() => ai.buildFilterValuesQuery({ fieldIds: ['ok', 'bad"id'] }), /not a plain field name/);
});

test('every built document is a read under the read-only classifier', () => {
  const docs = [
    ai.buildCountsQuery({}),
    ai.buildSearchQuery({ filters: [{ fieldId: 'name', match: { values: ['mutation'] } }] }),
    ai.buildGetQuery({ resourceId: 'x' }),
    ai.buildFilterValuesQuery({ fieldIds: ['osFamily'] }),
  ];
  for (const d of docs) {
    assert.equal(access.graphqlOperation(d.query), 'query');
    assert.equal(access.postIsRead(ai.GRAPHQL_PATH, d), true);
  }
});

// ─── Field allowlist and injection ───────────────────────────────────────────

test('fields: injection attempts are rejected before any request', () => {
  const bad = [
    'name } x: __schema { types { name } }',
    'name } x: __schema {',
    'name\n}',
    'a b',
    '__typename { x }',
    '1name',
    'name(arg: 1)',
    'agent { uuid } x: __schema',
    'agent { uuid __schema }',
    'agent.uuid }',
    'agent { diskMetrics }',
    'agent.nope',
    'notes',
  ];
  for (const f of bad) assert.throws(() => ai.buildSelection([f]), Error, JSON.stringify(f));
  assert.throws(() => ai.buildSelection('name'), /array/);
  assert.throws(() => ai.buildSelection([42]), /strings/);
});

test('fields: allowed forms build a fixed selection', () => {
  assert.equal(ai.buildSelection(['name', 'tags', 'alertsCount']), 'id name tags { key value source readOnly } alertsCount { severity count alertIds }');
  assert.equal(ai.buildSelection(['agent']), `id agent { ${ai.DEFAULT_AGENT_FIELDS.join(' ')} }`);
  assert.equal(ai.buildSelection(['agent { uuid agentVersion }', 'agent.uuid', 'agent.isInfected']), 'id agent { uuid agentVersion isInfected }');
  assert.equal(ai.buildSelection(['eppUnsupportedUnknown', 'deviceReview', 'gatewayIps']), 'id eppUnsupportedUnknown deviceReview gatewayIps');
  assert.equal(ai.buildSelection([]), ai.DEFAULT_SEARCH_FIELDS.join(' '));
});

test('sort, scope, surface and enum arguments are validated', () => {
  assert.throws(() => ai.buildSort({ by: 'name } x' }), /plain field name/);
  assert.throws(() => ai.buildSort({ by: 'name', order: 'sideways' }), /ASC or DESC/);
  assert.throws(() => ai.buildScope({ scopeType: 'PLANET', scopeIds: [] }), /scopeType/);
  assert.throws(() => ai.buildScope({ scopeType: 'SITE' }), /required/);
  assert.throws(() => ai.buildScope({ scopeType: 'SITE', scopeIds: ['1"}'] }), /valid id/);
  assert.throws(() => ai.buildSearchQuery({ surface: 'MOON' }), /surface must be one of/);
  assert.ok(ai.SURFACES.includes('AI_SECURITY'));
  assert.throws(() => ai.buildSearchQuery({ category: 'Workstation' }), /enum form/);
  assert.throws(() => ai.buildSearchQuery({ subCategory: 'VIRTUAL_MACHINE }' }), /enum form/);
  assert.throws(() => ai.buildSearchQuery({ first: 0 }), /1 to 1000/);
  assert.throws(() => ai.buildSearchQuery({ first: 1001 }), /1 to 1000/);
  assert.throws(() => ai.buildSearchQuery({ after: 5 }), /endCursor/);
});

// ─── Filters ─────────────────────────────────────────────────────────────────

test('filters: values are never written into the document', async () => {
  const evil = '"] } }]) { totalCount } x: __schema { types { name } } #';
  const filters = [
    { fieldId: 'name', match: { values: [evil] } },
    { fieldId: 'name', stringEqual: { value: evil } },
    { fieldId: 'osFamily', stringIn: { values: ['Linux', evil] } },
  ];
  const q = ai.buildSearchQuery({ filters, countOnly: true });
  assert.ok(!q.query.includes('__schema'));
  assert.ok(!q.query.includes('Linux'));
  assert.ok(!q.query.includes(evil));
  assert.deepEqual(q.variables.filters, filters);

  await withMock([page([], false, null, 0)], async (calls) => {
    await TOOL.asset_inventory_search.handler({ filters, countOnly: true });
    assert.equal(calls.length, 1);
    assert.ok(!calls[0].body.query.includes('__schema'));
    assert.deepEqual(calls[0].body.variables.filters, filters);
    assert.equal(calls[0].body.operationName, 'AssetInventorySearch');
  });
});

test('filters: operator allowlist, exactly one operator, values normalised', () => {
  assert.throws(() => ai.buildFilters({}), /array/);
  assert.throws(() => ai.buildFilters([{ fieldId: 'name' }]), /exactly one/);
  assert.throws(() => ai.buildFilters([{ fieldId: 'name', match: { values: ['a'] }, stringIn: { values: ['b'] } }]), /exactly one/);
  assert.throws(() => ai.buildFilters([{ fieldId: 'name', booleanEqual: { value: true } }]), /unknown key/);
  assert.throws(() => ai.buildFilters([{ fieldId: 'name', match: { values: ['a'] }, __proto_: 1 }]), /unknown key/);
  assert.throws(() => ai.buildFilters([{ fieldId: 'na me', match: { values: ['a'] } }]), /plain field name/);
  assert.throws(() => ai.buildFilters([{ fieldId: 'name', stringIn: { values: [] } }]), /non-empty/);
  assert.throws(() => ai.buildFilters([{ fieldId: 'name', stringIn: { values: [{}] } }]), /strings/);
  assert.throws(() => ai.buildFilters([{ fieldId: 'name', stringEqual: { value: 5 } }]), /string/);
  assert.throws(() => ai.buildFilters([{ fieldId: 'lastActiveDt', dateTimeRange: { start: 'yesterday-ish', end: 1 } }]), /epoch milliseconds/);
  // Extra keys inside an operator are dropped: only the documented shape is sent.
  assert.deepEqual(ai.buildFilters([{ fieldId: 'name', stringIn: { values: ['a', 7], extra: 'x' } }]), [{ fieldId: 'name', stringIn: { values: ['a', '7'] } }]);
  assert.deepEqual(
    ai.buildFilters([{ fieldId: 'lastActiveDt', dateTimeRange: { start: '2026-01-01T00:00:00Z', end: '1792503736633', endInclusive: true } }]),
    [{ fieldId: 'lastActiveDt', dateTimeRange: { start: Date.parse('2026-01-01T00:00:00Z'), end: 1792503736633, endInclusive: true } }],
  );
  // end is optional.
  assert.deepEqual(ai.buildFilters([{ fieldId: 'lastActiveDt', dateTimeRange: { start: 1000 } }]), [{ fieldId: 'lastActiveDt', dateTimeRange: { start: 1000 } }]);
  assert.throws(() => ai.buildFilters([{ fieldId: 'lastActiveDt', dateTimeRange: { end: 1000 } }]), /start must be epoch/);
});

// ─── Errors ──────────────────────────────────────────────────────────────────

test('HTTP 200 with errors becomes a tool error with the messages and partial data', async () => {
  await withMock([{ body: { data: null, errors: [{ message: 'Invalid filter type STRING_IN for field managed_state', extensions: { errorType: 'BAD_REQUEST', code: 4000010, service: 'uaip' } }] } }], async () => {
    await assert.rejects(TOOL.asset_inventory_search.handler({ countOnly: true }), (e) => {
      assert.match(e.message, /HTTP 200 with errors/);
      assert.match(e.message, /Invalid filter type STRING_IN for field managed_state \(BAD_REQUEST\/4000010\/uaip\)/);
      assert.doesNotMatch(e.message, /Partial data/);
      return true;
    });
  });
  await withMock([{ body: { data: { assetInventoryAssetOverview: { id: 'x', name: 'n' } }, errors: [{ message: 'alertsCount unavailable' }, { message: 'tags unavailable' }] } }], async () => {
    await assert.rejects(TOOL.asset_inventory_get.handler({ resourceId: 'x' }), (e) => {
      assert.match(e.message, /alertsCount unavailable; tags unavailable/);
      assert.match(e.message, /Partial data: \{"assetInventoryAssetOverview":\{"id":"x","name":"n"\}\}/);
      return true;
    });
  });
  await withMock([{ body: { data: null, errors: [{ message: "HTTP fetch failed from 'uaip': 401: Unauthorized" }] } }], async () => {
    await assert.rejects(TOOL.asset_inventory_counts.handler({}), /refused the token \(401\)/);
  });
  await withMock([{ body: { data: null, errors: [{ message: 'Internal server error', extensions: { errorType: 'INTERNAL' } }] } }], async () => {
    await assert.rejects(TOOL.asset_inventory_search.handler({ sort: { by: 'notSortable' } }), /Internal server error.*sort\.by field it cannot sort on \("notSortable"\)/s);
  });
});

test('HTTP 400 "invalid query" carries a field-name hint', async () => {
  await withMock([{ status: 400, body: { errors: [{ message: 'invalid query' }] } }], async () => {
    await assert.rejects(TOOL.asset_inventory_search.handler({ fields: ['notAField'] }), /400: invalid query.*does not validate/s);
  });
});

test('filter_values and counts return the inner data', async () => {
  await withMock([{ body: { data: { assetInventoryFiltersCount: { data: [{ fieldId: 'missingCoverage', values: [{ label: 'EPP', value: 'EPP', count: 3 }] }] } } } }], async (calls) => {
    const out = JSON.parse(await TOOL.asset_inventory_filter_values.handler({ fieldIds: ['missingCoverage'], surface: 'NETWORK_DISCOVERY' }));
    assert.deepEqual(out, [{ fieldId: 'missingCoverage', values: [{ label: 'EPP', value: 'EPP', count: 3 }] }]);
    assert.equal(calls[0].url, 'https://tenant.sentinelone.net/web/api/v2.1/graphql');
    assert.equal(calls[0].method, 'POST');
    assert.deepEqual(calls[0].body.variables, { surface: 'NETWORK_DISCOVERY', filters: [], fieldIds: ['missingCoverage'] });
  });
  await withMock([{ body: { data: { assetInventoryAssetCounts: { categories: [], surfaces: [{ surface: 'ENDPOINT', count: 10 }] } } } }], async () => {
    const out = JSON.parse(await TOOL.asset_inventory_counts.handler({}));
    assert.deepEqual(out.surfaces, [{ surface: 'ENDPOINT', count: 10 }]);
  });
});

// ─── Paging ──────────────────────────────────────────────────────────────────

test('paging follows endCursor and stops when hasNextPage is false', async () => {
  await withMock([page(['a', 'b'], true, 'c1', 5), page(['c', 'd'], true, 'c2', 5), page(['e'], false, null, 5)], async (calls) => {
    const out = JSON.parse(await TOOL.asset_inventory_search.handler({ first: 2, maxPages: 10 }));
    assert.equal(calls.length, 3);
    assert.equal(calls[0].body.variables.after, undefined);
    assert.equal(calls[1].body.variables.after, 'c1');
    assert.equal(calls[2].body.variables.after, 'c2');
    assert.equal(out.pagesFetched, 3);
    assert.equal(out.rowsReturned, 5);
    assert.equal(out.totalCount, 5);
    assert.equal(out.hasNextPage, false);
    assert.deepEqual(out.rows.map(r => r.id), ['a', 'b', 'c', 'd', 'e']);
  });
});

test('paging stops at maxPages and reports the cursor to continue from', async () => {
  let n = 0;
  await withMock([() => page([`id${n}`], true, `cur${++n}`)], async (calls) => {
    const out = JSON.parse(await TOOL.asset_inventory_search.handler({ first: 1, maxPages: 2 }));
    assert.equal(calls.length, 2);
    assert.equal(out.pagesFetched, 2);
    assert.equal(out.hasNextPage, true);
    assert.equal(out.endCursor, 'cur2');
  });
  await withMock([page(['x'], true, 'more')], async (calls) => {
    const out = JSON.parse(await TOOL.asset_inventory_search.handler({}));
    assert.equal(calls.length, 1, 'maxPages defaults to 1');
    assert.equal(out.hasNextPage, true);
  });
});

test('paging limits: maxPages range and the inline row cap', async () => {
  await withMock([page([], false, null)], async (calls) => {
    await assert.rejects(TOOL.asset_inventory_search.handler({ maxPages: 0 }), /maxPages/);
    await assert.rejects(TOOL.asset_inventory_search.handler({ maxPages: ai.MAX_PAGES + 1 }), /maxPages/);
    await assert.rejects(TOOL.asset_inventory_search.handler({ first: 1000, maxPages: 2 }), /outputFile/);
    await assert.rejects(TOOL.asset_inventory_search.handler({ fields: ['bad field'] }), /plain field name/);
    assert.equal(calls.length, 0, 'validation runs before any request');
  });
});

// ─── outputFile ──────────────────────────────────────────────────────────────

test('outputFile goes through the output guard and returns a summary with a 5-row preview', async () => {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), 'ai-161-')));
  const saved = process.env.S1_OUTPUT_DIRS;
  process.env.S1_OUTPUT_DIRS = dir;
  try {
    await withMock([page(['a', 'b'], true, 'c1'), page([], false, null)], async (calls) => {
      await assert.rejects(TOOL.asset_inventory_search.handler({ outputFile: 'relative.json' }), /absolute/);
      await assert.rejects(TOOL.asset_inventory_search.handler({ outputFile: join(tmpdir(), 'elsewhere', 'x.json') }), /outside the allowed output directories/);
      await assert.rejects(TOOL.asset_inventory_search.handler({ outputFile: join(dir, '.hidden', 'x.json') }), /hidden \(dot\) path/);
      const existing = join(dir, 'exists.json');
      writeFileSync(existing, '{}');
      await assert.rejects(TOOL.asset_inventory_search.handler({ outputFile: existing }), /already exists/);
      assert.equal(calls.length, 0, 'a refused path makes no request');
    });

    const ids = Array.from({ length: 8 }, (_, i) => `id${i}`);
    await withMock([page(ids.slice(0, 4), true, 'c1', 8), page(ids.slice(4), false, null, 8)], async (calls) => {
      const target = join(dir, 'assets.jsonl');
      const out = JSON.parse(await TOOL.asset_inventory_search.handler({ first: 1000, maxPages: 5, outputFile: target }));
      assert.equal(calls.length, 2);
      assert.equal(out.outputFile, target);
      assert.equal(out.rowsReturned, 8);
      assert.equal(out.preview.length, 5);
      assert.equal(out.rows, undefined);
      const lines = readFileSync(target, 'utf-8').trim().split('\n').map(l => JSON.parse(l));
      assert.deepEqual(lines.map(l => l.id), ids);
    });

    await withMock([page(['z'], false, null, 1)], async () => {
      const target = join(dir, 'assets.json');
      await TOOL.asset_inventory_search.handler({ outputFile: target });
      const full = JSON.parse(readFileSync(target, 'utf-8'));
      assert.equal(full.totalCount, 1);
      assert.deepEqual(full.rows.map(r => r.id), ['z']);
    });
  } finally {
    if (saved === undefined) delete process.env.S1_OUTPUT_DIRS; else process.env.S1_OUTPUT_DIRS = saved;
    rmSync(dir, { recursive: true, force: true });
  }
});

// ─── Tool definitions ────────────────────────────────────────────────────────

test('tool definitions: four tools, required args, view and value rules in the descriptions', () => {
  assert.deepEqual(ai.tools.map(t => t.name), ['asset_inventory_counts', 'asset_inventory_search', 'asset_inventory_get', 'asset_inventory_filter_values']);
  assert.deepEqual(TOOL.asset_inventory_filter_values.inputSchema.required, ['fieldIds']);
  const search = TOOL.asset_inventory_search.description;
  assert.match(search, /surface argument is the curated console view/);
  assert.match(search, /NETWORK_DISCOVERY returns assetStatus Active only/);
  assert.match(search, /"surfaces" filter .* raw surface tag/);
  assert.match(search, /enums \(SERVER, WORKSTATION, VIRTUAL_MACHINE/);
  assert.match(search, /display labels/);
  assert.match(search, /asset_inventory_filter_values first/);
  assert.match(search, /Do not mix asset_inventory_counts totals/);
  assert.match(TOOL.asset_inventory_counts.description, /Do not mix/);
  assert.match(TOOL.asset_inventory_counts.description, /For Network Discovery and Device numbers use asset_inventory_search totalCount/);
  assert.match(search, /case-sensitive/);
  assert.match(search, /managedState and s1SiteId can be returned but not filtered/);
  assert.match(TOOL.asset_inventory_filter_values.description, /surface argument is the curated console view/);
  for (const t of ai.tools) {
    assert.match(t.description, /Read-only\./);
    const dashes = [0x2013, 0x2014].map(c => String.fromCharCode(c));
    assert.ok(!dashes.some(d => t.description.includes(d)), `${t.name} has an en or em dash`);
  }
  assert.deepEqual(TOOL.asset_inventory_search.inputSchema.properties.surface.enum, ['ENDPOINT', 'CLOUD', 'IDENTITY', 'NETWORK_DISCOVERY', 'AI_SECURITY']);
});
