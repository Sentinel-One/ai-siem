/**
 * Issue #111 (1.5.3): one global or multi-account token, any account or site per call.
 *
 * Live-measured 2026-10-09 on a service user spanning 385 accounts:
 *   - LRQ ignored S1-Scope: scope "<A>" returned 19 accounts, "<A>:<S>" 29 pairs.
 *     tenant:false + accountIds:[A] returned A only; a site.id term narrows to a site.
 *   - Unscoped, V1 /api/query returned 0 matches for every source, so
 *     schema_discover said "No events found" on a tenant holding millions of events.
 *   - uam_available_actions resolved only the first 100 accounts and answered 0
 *     actions for an alert in account 101+.
 *   - uam_list_alerts had no scope; ha_list_workflows had no accountIds.
 *
 * HTTP is mocked; no network.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

process.env.S1_CONSOLE_URL ||= 'https://tenant.sentinelone.net';
process.env.S1_CONSOLE_API_TOKEN ||= 'test-token';
delete process.env.S1_SCOPE;
delete process.env.SDL_S1_SCOPE;

const { lrqScope, addSiteFilter, isAccountAccessRefusal } = await import('../lib/lrq-scope.js');
const { lrqRun, allAccountIds, uamListAlerts } = await import('../lib/s1.js');
const { ALL_TOOLS } = await import('../lib/server-core.js');
const { schemaWindow } = await import('../tools/powerquery.js');
const tool = name => ALL_TOOLS.find(x => x.name === name);

const A = '1000000000000000001'; // placeholder ids, not a real tenant
const S = '1000000000000000002';

function res(status, body, headers = {}) {
  const text = typeof body === 'string' ? body : JSON.stringify(body);
  return { ok: status >= 200 && status < 300, status, headers: new Map(Object.entries(headers)), text: async () => text, json: async () => JSON.parse(text) };
}

/** LRQ mock: records launch bodies; `launchReply(n, body)` may return a non-200 reply. */
function stubLrq({ launchReply, values = [[1]], columns = [{ name: 'n' }], matches } = {}) {
  const launches = [];
  const real = globalThis.fetch;
  globalThis.fetch = async (url, opts = {}) => {
    if (opts.method === 'POST' && String(url).endsWith('/sdl/v2/api/queries')) {
      const body = JSON.parse(opts.body);
      launches.push({ body, headers: opts.headers });
      const custom = launchReply?.(launches.length, body);
      if (custom) return custom;
      return res(200, { id: `q${launches.length}` }, { 'X-Dataset-Query-Forward-Tag': 't' });
    }
    if (opts.method === 'DELETE') return res(200, {});
    return res(200, { stepsCompleted: 1, stepsTotal: 1, data: matches ? { matches } : { columns, values, matchCount: values.length } });
  };
  return { launches, restore: () => { globalThis.fetch = real; } };
}

// ── lrqScope / addSiteFilter ──────────────────────────────────────────────────

test('lrqScope: unscoped stays tenant:true; an account becomes tenant:false + accountIds array', () => {
  assert.deepEqual(lrqScope(undefined).body, { tenant: true });
  assert.deepEqual(lrqScope(null).body, { tenant: true });
  const a = lrqScope(A);
  assert.deepEqual(a.body, { tenant: false, accountIds: [A] });
  assert.equal(a.siteId, null);
  const s = lrqScope(`${A}:${S}`);
  assert.deepEqual(s.body, { tenant: false, accountIds: [A] });
  assert.equal(s.siteId, S);
  assert.throws(() => lrqScope('acme'), /Invalid S1-Scope/);
});

test('lrqScope never produces tenant:false without accountIds (that returns only global-level rows)', () => {
  for (const sc of [undefined, A, `${A}:${S}`]) {
    const b = lrqScope(sc).body;
    if (b.tenant === false) assert.ok(Array.isArray(b.accountIds) && b.accountIds.length === 1);
    else assert.ok(!('accountIds' in b));
  }
});

test('addSiteFilter: leading pipe, filter with OR, LOG filter, and refusal for | join', () => {
  assert.equal(addSiteFilter('| group n=count() by account.id', S).query, `site.id='${S}' | group n=count() by account.id`);
  const or = addSiteFilter("a='1' or b='2' | limit 5", S).query;
  assert.equal(or, `site.id='${S}' and (a='1' or b='2'\n) | limit 5`);
  assert.equal(addSiteFilter("dataSource.name='Okta'", S).query, `site.id='${S}' and (dataSource.name='Okta'\n)`);
  assert.equal(addSiteFilter("x | y", null).applied, false);
  // A pipe inside quotes is not the first top-level pipe.
  assert.equal(addSiteFilter("msg contains 'a|b' | limit 1", S).query, `site.id='${S}' and (msg contains 'a|b'\n) | limit 1`);
  assert.throws(() => addSiteFilter('| x', "1' or '1"), /numeric/);
});

test('addSiteFilter: join and union get the term in every subquery; lookup-table subqueries are left alone', () => {
  const j = addSiteFilter("| join a = (dataSource.name='X' | group n=count() by k), b = (| group m=count() by k) on k | sort -n", S);
  assert.equal(j.query, `| join a = (site.id='${S}' and (dataSource.name='X'\n) | group n=count() by k), b = (site.id='${S}' | group m=count() by k) on k | sort -n`);
  assert.match(j.reason, /2 subqueries of the join/);
  const lj = addSiteFilter("| left join a = (x='1'), t = ( | dataset 'config://datatables/T' | columns k, v ) on k", S);
  assert.match(lj.query, new RegExp(`a = \\(site\\.id='${S}' and \\(x='1'\n\\)\\)`));
  assert.match(lj.query, /t = \( \| dataset 'config:\/\/datatables\/T' \| columns k, v \)/);
  assert.match(lj.reason, /1 subquery of the join \(1 left unchanged/);
  const u = addSiteFilter("| union (a='1' | group n=count()), (b='(x)' | group n=count())", S);
  assert.equal(u.query, `| union (site.id='${S}' and (a='1'\n) | group n=count()), (site.id='${S}' and (b='(x)'\n) | group n=count())`);
  const sj = addSiteFilter('| sql inner join (a=1), (b=2) on k', S);
  assert.match(sj.query, /^\| sql inner join \(site\.id=/);
  // Nested: a join inside a union subquery.
  const nest = addSiteFilter('| union (| join (a=1), (b=2) on k), (c=3)', S);
  assert.equal((nest.query.match(/site\.id=/g) || []).length, 3);
  const tables = addSiteFilter("| join a = ( | dataset 't' ), b = ( | inputlookup 'u' ) on k", S);
  assert.equal(tables.applied, false);
  assert.match(tables.reason, /S1-Scope header selects the site copy/);
});

test('lrqRun: a lookup-table read under a site scope sends the site S1-Scope header and no row filter', async () => {
  const s = stubLrq();
  try {
    const out = await lrqRun("| dataset 'config://datatables/T'", { hours: 1, scope: `${A}:${S}` });
    assert.equal(s.launches[0].headers['S1-Scope'], `${A}:${S}`);
    assert.equal(s.launches[0].body.pq.query, "| dataset 'config://datatables/T'");
    assert.equal(out.scopeApplied.siteFilter, null);
    assert.match(out.scopeApplied.siteFilterApplied, /^none: reads a lookup table/);
  } finally { s.restore(); }
});

test('addSiteFilter: | datasource uses its own site column, or refuses where there is none', () => {
  assert.equal(addSiteFilter('| datasource vulnerabilities | group n=count()', S).query, `| datasource vulnerabilities | filter siteId='${S}' | group n=count()`);
  assert.equal(addSiteFilter("| datasource misconfigurations | filter environment = 'AWS'", S).query, `| datasource misconfigurations | filter siteId='${S}' | filter environment = 'AWS'`);
  assert.throws(() => addSiteFilter('| datasource alerts | group n=count()', S), /has no site column.*uam_list_alerts/);
  assert.equal(addSiteFilter("| dataset 'config://datatables/T'", S).applied, false);
});

test('isAccountAccessRefusal matches the measured 500 body only', () => {
  assert.ok(isAccountAccessRefusal(500, '{"message":"Operation not permitted. You do not have access to this account."}'));
  assert.ok(isAccountAccessRefusal(403, '{"code":"forbidden","message":"Not allowed to access requested resource.","details":[]}'));
  assert.ok(!isAccountAccessRefusal(500, '{"message":"Don\'t understand [*]"}'));
  assert.ok(!isAccountAccessRefusal(400, 'You do not have access to this account'));
});

// ── lrqRun launch body ───────────────────────────────────────────────────────

test('lrqRun scope "<A>": tenant:false, accountIds [A], scopeApplied reported', async () => {
  const s = stubLrq();
  try {
    const out = await lrqRun('| group n=count() by account.id', { hours: 1, scope: A });
    const b = s.launches[0].body;
    assert.equal(b.tenant, false);
    assert.deepEqual(b.accountIds, [A]);
    assert.ok(!/site\.id/.test(b.pq.query));
    assert.equal(out.scopeApplied.mode, 'accountIds');
    assert.deepEqual(out.scopeApplied.accountIds, [A]);
  } finally { s.restore(); }
});

test('lrqRun scope "<A>:<S>": accountIds [A] plus a site.id term ahead of the metering predicate', async () => {
  const s = stubLrq();
  try {
    const out = await lrqRun("dataSource.name='Okta' | group n=count()", { hours: 1, scope: `${A}:${S}` });
    const b = s.launches[0].body;
    assert.deepEqual(b.accountIds, [A]);
    assert.equal(b.tenant, false);
    assert.match(b.pq.query, new RegExp(`^tag != 'logVolume' and \\(site\\.id='${S}' and \\(dataSource\\.name='Okta'`));
    assert.equal(out.scopeApplied.siteFilter, `site.id='${S}'`);
    assert.equal(out.effectiveQuery, b.pq.query);
  } finally { s.restore(); }
});

test('lrqRun LOG with a site scope puts the term in log.filter', async () => {
  const s = stubLrq({ matches: [] });
  try {
    await lrqRun("dataSource.name='Okta'", { hours: 1, scope: `${A}:${S}`, queryType: 'LOG', includeMetering: true });
    const b = s.launches[0].body;
    assert.equal(b.queryType, 'LOG');
    assert.deepEqual(b.accountIds, [A]);
    assert.equal(b.log.filter, `site.id='${S}' and (dataSource.name='Okta'\n)`);
  } finally { s.restore(); }
});

test('lrqRun unscoped: tenant:true, no accountIds, and the note says it spans every account', async () => {
  const s = stubLrq();
  try {
    const out = await lrqRun('| group n=count()', { hours: 1 });
    assert.equal(s.launches[0].body.tenant, true);
    assert.ok(!('accountIds' in s.launches[0].body));
    assert.equal(out.scopeApplied.mode, 'tenant');
    assert.match(out.scopeApplied.note, /every account/);
  } finally { s.restore(); }
});

test('lrqRun S1_SCOPE default is applied the same way as an explicit scope', async () => {
  process.env.S1_SCOPE = A;
  const s = stubLrq();
  try {
    await lrqRun('| group n=count()', { hours: 1 });
    assert.deepEqual(s.launches[0].body.accountIds, [A]);
  } finally { s.restore(); delete process.env.S1_SCOPE; }
});

test('lrqRun: a site-level token refused accountIds falls back to tenant:true and keeps the site term', async () => {
  const refuse = (n) => n === 1 ? res(500, { message: 'Operation not permitted. You do not have access to this account.' }) : null;
  const s = stubLrq({ launchReply: refuse });
  try {
    const out = await lrqRun('| group n=count()', { hours: 1, scope: `${A}:${S}` });
    assert.equal(s.launches.length, 2);
    assert.equal(s.launches[1].body.tenant, true);
    assert.ok(!('accountIds' in s.launches[1].body));
    assert.match(s.launches[1].body.pq.query, new RegExp(`site\\.id='${S}'`));
    assert.equal(out.scopeApplied.mode, 'tenant+siteFilter');
  } finally { s.restore(); }
});

test('lrqRun: an account the token cannot reach (account scope) fails loudly, never widens', async () => {
  const s = stubLrq({ launchReply: () => res(500, { message: 'You do not have access to this account.' }) });
  try {
    await assert.rejects(lrqRun('| group n=count()', { hours: 1, scope: A }), /names an account this token cannot reach/);
    assert.equal(s.launches.length, 1);
  } finally { s.restore(); }
});

test('powerquery_enumerate_sources passes scope through to the launch body', async () => {
  const s = stubLrq();
  try {
    await tool('powerquery_enumerate_sources').handler({ hours: 1, scope: A });
    assert.deepEqual(s.launches[0].body.accountIds, [A]);
  } finally { s.restore(); }
});

test('powerquery_run sliced: every slice carries accountIds', async () => {
  const s = stubLrq({ columns: [{ name: 'account.id' }, { name: 'n' }], values: [[A, 1]] });
  try {
    const out = JSON.parse(await tool('powerquery_run').handler({ query: '| group n=count() by account.id', hours: 2, slices: 2, merge: { keys: ['account.id'], sum: ['n'] }, scope: A }));
    assert.equal(s.launches.length, 2);
    for (const l of s.launches) assert.deepEqual(l.body.accountIds, [A]);
    assert.equal(out.scopeApplied.mode, 'accountIds');
  } finally { s.restore(); }
});

// ── schema_discover fallback ─────────────────────────────────────────────────

test('schema_discover falls back to an LRQ LOG search when V1 returns nothing, with the scope', async () => {
  const launches = [];
  const real = globalThis.fetch;
  globalThis.fetch = async (url, opts = {}) => {
    const u = String(url);
    if (u.endsWith('/api/query')) return res(200, { status: 'success', matches: [] });
    if (opts.method === 'POST' && u.endsWith('/sdl/v2/api/queries')) { launches.push(JSON.parse(opts.body)); return res(200, { id: 'q1' }); }
    if (opts.method === 'DELETE') return res(200, {});
    return res(200, { stepsCompleted: 1, stepsTotal: 1, data: { matches: [{ values: { 'dataSource.name': 'SentinelOne', 'src.process.name': 'x', 'account.id': A } }] } });
  };
  try {
    const out = JSON.parse(await tool('powerquery_schema_discover').handler({ dataSourceName: 'SentinelOne', maxEvents: 2, startTime: '7d', scope: A }));
    assert.equal(out.via, 'lrq-log');
    assert.ok(out.confirmedFields.includes('src.process.name'));
    assert.equal(launches[0].queryType, 'LOG');
    assert.deepEqual(launches[0].accountIds, [A]);
    assert.equal(out.scopeApplied.mode, 'accountIds');
  } finally { globalThis.fetch = real; }
});

test('schemaWindow parses relative and ISO start times', () => {
  assert.deepEqual(schemaWindow('24h'), { hours: 24 });
  assert.deepEqual(schemaWindow('7d'), { hours: 168 });
  assert.deepEqual(schemaWindow('30m'), { hours: 0.5 });
  assert.deepEqual(schemaWindow('2026-10-01T00:00:00Z'), { startTime: '2026-10-01T00:00:00Z' });
  assert.deepEqual(schemaWindow('nonsense'), { hours: 24 });
});

// ── UAM ───────────────────────────────────────────────────────────────────────

test('allAccountIds follows the cursor past the first 100 accounts', async () => {
  const real = globalThis.fetch;
  const seen = [];
  globalThis.fetch = async (url) => {
    const u = new URL(String(url));
    seen.push(u.searchParams.get('cursor'));
    const page = u.searchParams.get('cursor')
      ? { data: [{ id: '3' }], pagination: { nextCursor: null } }
      : { data: [{ id: '1' }, { id: '2' }], pagination: { nextCursor: 'c2' } };
    return res(200, page);
  };
  try {
    assert.deepEqual(await allAccountIds(), ['1', '2', '3']);
    assert.deepEqual(seen, [null, 'c2']);
  } finally { globalThis.fetch = real; }
});

test('uam_available_actions defaults to the alert\'s own account', async () => {
  const real = globalThis.fetch;
  const bodies = [];
  globalThis.fetch = async (url, opts = {}) => {
    const b = JSON.parse(opts.body);
    bodies.push(b);
    if (/AlertState/.test(b.query)) return res(200, { data: { alert: { id: 'x', realTime: { scope: { account: { id: A }, site: { id: S } } } } } });
    return res(200, { data: { alertAvailableActions: { data: [{ id: 'S1/alert/addNote', isDisabled: false }] } } });
  };
  try {
    const out = JSON.parse(await tool('uam_available_actions').handler({ alertId: 'x' }));
    const aa = bodies.find(b => /alertAvailableActions/.test(b.query));
    assert.deepEqual(aa.variables.scope, { scopeIds: [A], scopeType: 'ACCOUNT' });
    assert.deepEqual(out.enabled, ['S1/alert/addNote']);
    assert.match(out.scope.source, /alert's account/);
  } finally { globalThis.fetch = real; }
});

test('uam_list_alerts sends scope when scopeIds is given and flattens accountId/siteId', async () => {
  const real = globalThis.fetch;
  const bodies = [];
  globalThis.fetch = async (url, opts = {}) => {
    bodies.push(JSON.parse(opts.body));
    return res(200, { data: { alerts: { totalCount: 1, pageInfo: {}, edges: [{ node: { id: 'a1', realTime: { scope: { account: { id: A }, site: { id: S } } } } }] } } });
  };
  try {
    const out = JSON.parse(await tool('uam_list_alerts').handler({ first: 1, scopeIds: [A] }));
    assert.deepEqual(bodies[0].variables.scope, { scopeIds: [A], scopeType: 'ACCOUNT' });
    assert.match(bodies[0].query, /scope: \$scope/);
    assert.equal(out.alerts[0].accountId, A);
    assert.equal(out.alerts[0].siteId, S);
    assert.ok(!('realTime' in out.alerts[0]));
    // Unscoped: no scope variable at all.
    await uamListAlerts({ first: 1 });
    assert.ok(!('scope' in bodies[1].variables));
  } finally { globalThis.fetch = real; }
});

// ── Hyperautomation / dashboards ──────────────────────────────────────────────

test('ha_list_workflows passes accountIds and nameContains (as name__contains)', async () => {
  const real = globalThis.fetch;
  let url;
  globalThis.fetch = async (u) => { url = new URL(String(u)); return res(200, { data: [], totalItems: 0 }); };
  try {
    await tool('ha_list_workflows').handler({ accountIds: A, limit: 1, nameContains: 'Ingest Health' });
    assert.equal(url.searchParams.get('accountIds'), A);
    assert.equal(url.searchParams.get('name__contains'), 'Ingest Health');
    assert.equal(url.searchParams.get('name'), null);
  } finally { globalThis.fetch = real; }
});

test('ha_delete_workflow: an active workflow (400) is deactivated, then deleted', async () => {
  const real = globalThis.fetch;
  const calls = [];
  let deletes = 0;
  globalThis.fetch = async (u, opts = {}) => {
    const url = new URL(String(u));
    calls.push(`${opts.method} ${url.pathname}`);
    if (opts.method === 'DELETE') return ++deletes === 1 ? res(400, { detail: 'Workflow is active' }) : res(204, '');
    return res(204, '');
  };
  try {
    const out = JSON.parse(await tool('ha_delete_workflow').handler({ workflowIds: ['w1'], siteIds: S }));
    assert.deepEqual(out.deleted[0], { id: 'w1', status: 'deleted', deactivatedFirst: true });
    assert.deepEqual(calls, [
      'DELETE /web/api/v2.1/hyper-automate/api/v1/workflows/w1',
      'POST /web/api/v2.1/hyper-automate/api/v1/workflows/w1/deactivate',
      'DELETE /web/api/v2.1/hyper-automate/api/v1/workflows/w1',
    ]);
  } finally { globalThis.fetch = real; }
});

test('ha_delete_workflow: a 404 is reported, never retried', async () => {
  const real = globalThis.fetch;
  let n = 0;
  globalThis.fetch = async () => { n++; return res(404, { detail: 'Object not found' }); };
  try {
    const out = JSON.parse(await tool('ha_delete_workflow').handler({ workflowIds: ['w1'], siteIds: S }));
    assert.equal(out.deleted[0].status, 'error');
    assert.equal(n, 1);
  } finally { globalThis.fetch = real; }
});

test('schema_discover LRQ fallback includes session-level serverInfo fields (account.id, site.id)', async () => {
  const real = globalThis.fetch;
  globalThis.fetch = async (url, opts = {}) => {
    const u = String(url);
    if (u.endsWith('/api/query')) return res(200, { status: 'success', matches: [] });
    if (opts.method === 'POST') return res(200, { id: 'q1' });
    if (opts.method === 'DELETE') return res(200, {});
    return res(200, { stepsCompleted: 1, stepsTotal: 1, data: { matches: [{ serverInfo: { 'account.id': A, 'site.id': S, serverHost: 'h' }, values: { 'dataSource.name': 'X', 'event.type': 'y' } }] } });
  };
  try {
    const out = JSON.parse(await tool('powerquery_schema_discover').handler({ dataSourceName: 'X', maxEvents: 1, scope: A }));
    assert.equal(out.via, 'lrq-log');
    for (const f of ['account.id', 'site.id', 'serverHost', 'event.type']) assert.ok(out.confirmedFields.includes(f), f);
  } finally { globalThis.fetch = real; }
});

test('sdl_create_dashboard accepts the config as an object', async () => {
  const real = globalThis.fetch;
  const bodies = [];
  globalThis.fetch = async (u, opts = {}) => {
    bodies.push(JSON.parse(opts.body));
    return res(200, { data: { createDashboardV2: { id: 'd1', name: 'n' } } });
  };
  try {
    await tool('sdl_create_dashboard').handler({ name: 'n', config: { duration: '1h', graphs: [] }, scope: A }).catch(() => {});
    assert.ok(bodies.length >= 1, 'an object config must reach the API, not be refused before it');
  } finally { globalThis.fetch = real; }
});
