/**
 * Behavioural tests for the GraphQL config-file layer in lib/sdl.js.
 *
 * These stub global.fetch, so they need no tenant and no credentials beyond
 * the two env vars the module reads at call time. Every case here corresponds
 * to a defect found in the 1.3.2 pre-release review; they exist so those
 * defects cannot come back silently.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

process.env.S1_CONSOLE_URL ||= 'https://tenant.sentinelone.net';
process.env.S1_CONSOLE_API_TOKEN ||= 'test-token';

const { configFiles, configFile, putConfigFile, deleteConfigFile, v1Query } = await import('../lib/sdl.js');

/** Queue up canned responses; records every outbound request. */
function stubFetch(responses) {
  const calls = [];
  global.fetch = async (url, opts) => {
    calls.push({ url, body: opts.body ? JSON.parse(opts.body) : undefined, method: opts.method });
    const next = responses.shift();
    if (!next) throw new Error('stubFetch: ran out of queued responses');
    return {
      ok: next.status === undefined || (next.status >= 200 && next.status < 300),
      status: next.status ?? 200,
      headers: new Map(),
      text: async () => (typeof next.body === 'string' ? next.body : JSON.stringify(next.body)),
    };
  };
  return calls;
}

const gql = data => ({ body: { data } });

test('non-JSON 200 throws instead of reporting an empty listing', async () => {
  stubFetch([{ body: '<html>SSO interstitial</html>' }]);
  await assert.rejects(configFiles(), /expected a JSON object/);
});

test('non-JSON 200 does not let a delete report success', async () => {
  stubFetch([{ body: '<html>proxy</html>' }]);
  await assert.rejects(deleteConfigFile({ name: '/lookups/x.csv' }), /expected a JSON object/);
});

test('a non-array errors object still throws', async () => {
  stubFetch([{ body: { errors: { message: 'boom' } } }]);
  await assert.rejects(configFiles(), /boom/);
});

test('a payload with neither data nor errors throws', async () => {
  stubFetch([{ body: { extensions: {} } }]);
  await assert.rejects(configFiles(), /neither data nor errors/);
});

test('correlationId is surfaced from per-error extensions too', async () => {
  stubFetch([{ body: { errors: [{ message: 'conflict', extensions: { correlationId: 'abc123' } }] } }]);
  await assert.rejects(configFiles(), /abc123/);
});

test('mutations are NOT retried on 5xx (a retried create duplicates a dashboard)', async () => {
  const calls = stubFetch([
    // Non-empty listing so the duplicate guard passes and we reach the mutation.
    gql({ configFiles: [{ udoId: '1', name: '/dashboards/Other', version: 1 }] }),
    { status: 502, body: 'bad gateway' },
  ]);
  await assert.rejects(putConfigFile({ name: '/dashboards/New', content: '{}' }), /502/);
  const mutations = calls.filter(c => c.body?.query?.startsWith('mutation'));
  assert.equal(mutations.length, 1, 'the addConfigFile mutation must be sent exactly once');
});

test('read-only queries ARE still retried on 5xx', async () => {
  const calls = stubFetch([
    { status: 503, body: 'unavailable' },
    gql({ configFiles: [{ udoId: null, name: '/lookups/a.csv', version: 1 }] }),
  ]);
  const files = await configFiles();
  assert.equal(files.length, 1);
  assert.equal(calls.length, 2, 'the query should have been retried once');
});

test('expectedVersion is sent on name-addressed writes (server honours it)', async () => {
  const calls = stubFetch([gql({ addConfigFile: { udoId: null, name: '/logParsers/P', version: 2 } })]);
  await putConfigFile({ name: '/logParsers/P', content: 'x', expectedVersion: 1168977232 });
  const sent = calls[0].body;
  assert.match(sent.query, /\$expectedVersion: Long/, 'mutation must declare $expectedVersion');
  assert.equal(sent.variables.expectedVersion, 1168977232, 'expectedVersion must be transmitted');
});

test('expectedVersion is sent on udoId-addressed writes', async () => {
  const calls = stubFetch([gql({ addConfigFile: { udoId: '123', name: '/dashboards/D', version: 2 } })]);
  await putConfigFile({ udoId: '123', content: 'x', expectedVersion: 99 });
  assert.equal(calls[0].body.variables.expectedVersion, 99);
});

test('duplicate guard fails closed when the listing comes back empty', async () => {
  stubFetch([gql({ configFiles: [] })]);
  await assert.rejects(
    putConfigFile({ name: '/dashboards/Existing', content: '{}' }),
    /came back empty/,
  );
});

test('duplicate guard blocks a name-addressed write to an existing dashboard', async () => {
  stubFetch([gql({ configFiles: [{ udoId: '777', name: '/dashboards/Existing', version: 1 }] })]);
  await assert.rejects(
    putConfigFile({ name: '/dashboards/Existing', content: '{}' }),
    /already use that name.*777/s,
  );
});

test('duplicate guard is case- and whitespace-insensitive', async () => {
  stubFetch([gql({ configFiles: [{ udoId: '777', name: '/dashboards/Existing', version: 1 }] })]);
  await assert.rejects(
    putConfigFile({ name: '/dashboards/existing ', content: '{}' }),
    /already use that name/,
  );
});

test('a create of a genuinely new dashboard is allowed through the guard', async () => {
  stubFetch([
    gql({ configFiles: [{ udoId: '777', name: '/dashboards/Other', version: 1 }] }),
    gql({ addConfigFile: { udoId: '888', name: '/dashboards/Brand New', version: 1 } }),
  ]);
  const created = await putConfigFile({ name: '/dashboards/Brand New', content: '{}' });
  assert.equal(created.udoId, '888');
});

test('delete verifies removal and throws when the file survives', async () => {
  stubFetch([
    gql({ deleteConfigFile: null }),
    gql({ configFile: { udoId: '5', name: '/dashboards/D', version: 9, content: '{}' } }),
  ]);
  await assert.rejects(deleteConfigFile({ udoId: '5' }), /still exists after the delete mutation/);
});

test('delete reports success only once the file is gone', async () => {
  stubFetch([
    gql({ deleteConfigFile: null }),
    gql({ configFile: null }),
  ]);
  const res = await deleteConfigFile({ udoId: '5' });
  assert.equal(res.status, 'success');
  assert.deepEqual(res.deleted, { udoId: '5' });
});

test('configFile returns null (not a throw) when the server says "not found"', async () => {
  // The server signals absence as a GraphQL error. Absence is a normal lookup
  // outcome, so configFile normalises it to null; every other error propagates.
  stubFetch([{ body: { errors: [{ message: 'Config file with name /lookups/x.csv not found.' }] } }]);
  assert.equal(await configFile({ name: '/lookups/x.csv' }), null);
});

test('a deleted udoId returns null despite the generic error (listing disambiguates)', async () => {
  // Live: configFile(udoId:) on a deleted dashboard returns "Something went
  // wrong...", not "not found", and that is the same text a version conflict
  // returns. The listing is what settles it.
  stubFetch([
    { body: { errors: [{ message: 'Something went wrong. Please try again and if the issue persists contact Support.' }] } },
    gql({ configFiles: [{ udoId: '999', name: '/dashboards/Other', version: 1 }] }),
  ]);
  assert.equal(await configFile({ udoId: '5' }), null);
});

test('a generic error on a udoId that IS still present rethrows', async () => {
  stubFetch([
    { body: { errors: [{ message: 'Something went wrong. Please try again.' }] } },
    gql({ configFiles: [{ udoId: '5', name: '/dashboards/Still Here', version: 1 }] }),
  ]);
  await assert.rejects(configFile({ udoId: '5' }), /Something went wrong/);
});

test('configFile still throws on a non-"not found" error when the file exists', async () => {
  stubFetch([
    { body: { errors: [{ message: 'internal server explosion' }] } },
    gql({ configFiles: [{ udoId: null, name: '/lookups/x.csv', version: 1 }] }),
  ]);
  await assert.rejects(configFile({ name: '/lookups/x.csv' }), /internal server explosion/);
});

test('delete succeeds when the confirming read reports the file absent', async () => {
  stubFetch([
    gql({ deleteConfigFile: null }),
    { body: { errors: [{ message: 'Config file with name /lookups/x.csv not found.' }] } },
  ]);
  const res = await deleteConfigFile({ name: '/lookups/x.csv' });
  assert.equal(res.status, 'success');
});

test('delete still propagates a non-"not found" error from the confirming read', async () => {
  stubFetch([
    gql({ deleteConfigFile: null }),
    { body: { errors: [{ message: 'internal server explosion' }] } },
    gql({ configFiles: [{ udoId: null, name: '/lookups/x.csv', version: 1 }] }),
  ]);
  await assert.rejects(deleteConfigFile({ name: '/lookups/x.csv' }), /internal server explosion/);
});

test('a numeric udoId beyond the safe-integer range is rejected, not silently truncated', async () => {
  stubFetch([]);
  await assert.rejects(configFile({ udoId: 9007199254740993 }), /safe-integer range/);
});

test('no caller-supplied value is interpolated into the query document', async () => {
  const calls = stubFetch([gql({ configFile: null })]);
  await configFile({ name: '/lookups/a"}) { evil }' });
  assert.ok(!calls[0].body.query.includes('evil'), 'name must travel in variables, not the document');
  assert.equal(calls[0].body.variables.id, '/lookups/a"}) { evil }');
});

// ─── transport vs GraphQL: absence must never be inferred from a transport error ───

test('a transport 404 whose body says "not found" is NOT treated as absence', async () => {
  // The highest-value case in this file. sdlFetch builds the message as
  // "SDL API POST ... -> 404: <body>", so a 404 page or WAF block containing
  // the words "not found" used to satisfy the absence regex, and a delete
  // would then accept it as proof the file was gone.
  stubFetch([{ status: 404, body: { error: 'not found' } }]);
  await assert.rejects(configFile({ name: '/lookups/x.csv' }), /404/);
});

test('a transport 404 does not let a delete report success', async () => {
  stubFetch([
    gql({ deleteConfigFile: null }),
    { status: 404, body: 'nginx: not found' },
  ]);
  await assert.rejects(deleteConfigFile({ name: '/lookups/x.csv' }), /404/);
});

test('a listing failure during disambiguation preserves the ORIGINAL error', async () => {
  stubFetch([
    { body: { errors: [{ message: 'There are conflicting changes in the file.' }] } },
    { status: 500, body: 'listing exploded' },
    { status: 500, body: 'listing exploded' },
    { status: 500, body: 'listing exploded' },
    { status: 500, body: 'listing exploded' },
  ]);
  await assert.rejects(
    configFile({ udoId: '5' }),
    err => /conflicting changes/.test(err.message) && /absence check failed/.test(err.message),
  );
});

// ─── duplicate guard: namespace test must be case-insensitive ───

test('a case-variant /Dashboards/ path does NOT bypass the duplicate guard', async () => {
  stubFetch([gql({ configFiles: [{ udoId: '777', name: '/dashboards/AI Usage', version: 1 }] })]);
  await assert.rejects(
    putConfigFile({ name: '/Dashboards/AI Usage', content: '{}' }),
    /already use that name/,
  );
});

test('the guard still runs (and fails closed) for a case-variant path', async () => {
  stubFetch([gql({ configFiles: [] })]);
  await assert.rejects(
    putConfigFile({ name: '/DASHBOARDS/Something', content: '{}' }),
    /came back empty/,
  );
});

// ─── v1Query is a read-only POST and must keep its backoff ───

test('v1Query retries on 5xx (schema discovery is the workload that hits the QPS cap)', async () => {
  const calls = stubFetch([
    { status: 503, body: 'unavailable' },
    { body: { matches: [{ attributes: { a: 1 } }] } },
  ]);
  const res = await v1Query("dataSource.name='X'");
  assert.equal(res.matches.length, 1);
  assert.equal(calls.length, 2, 'v1Query must back off and retry, not fail on the first 503');
});

// ═══════════════════════════════════════════════════════════════════════════
// S1-Scope plumbing and the dashboardsV2 lifecycle (added 1.4.0)
//
// Live evidence these encode (<console>, 2026-08-17): the console sends
// `s1-scope` on all 23 SDL GraphQL operations, and `getConfigurationFiles`
// returned 113 files at account scope versus 4 at a site scope. A dashboard created at
// site scope is invisible to an account-scoped listing, so a dropped header is
// not a harmless default: it changes which objects appear to exist.
// ═══════════════════════════════════════════════════════════════════════════

const {
  listDashboards, getDashboard, createDashboard,
  shareDashboard, saveDashboardLayout, deleteDashboard,
} = await import('../lib/sdl.js');

/** Like stubFetch but also records outbound headers, which is the whole point here. */
function stubFetchH(responses) {
  const calls = [];
  global.fetch = async (url, opts) => {
    calls.push({ url, method: opts.method, headers: opts.headers, body: opts.body ? JSON.parse(opts.body) : undefined });
    const next = responses.shift();
    if (!next) throw new Error('stubFetchH: ran out of queued responses');
    return {
      ok: next.status === undefined || (next.status >= 200 && next.status < 300),
      status: next.status ?? 200,
      headers: new Map(),
      text: async () => (typeof next.body === 'string' ? next.body : JSON.stringify(next.body)),
    };
  };
  return calls;
}

const ACCOUNT = '2046190533732727925';
const SITE = '2547662415802335157';
const SITE_SCOPE = `${ACCOUNT}:${SITE}`;

// ─── scope header ───

test('scope is sent as the S1-Scope header', async () => {
  const calls = stubFetchH([gql({ configFiles: [] })]);
  await configFiles({ scope: SITE_SCOPE });
  assert.equal(calls[0].headers['S1-Scope'], SITE_SCOPE);
});

test('no scope means no S1-Scope header at all (not an empty one)', async () => {
  delete process.env.S1_SCOPE;
  const calls = stubFetchH([gql({ configFiles: [] })]);
  await configFiles();
  assert.ok(!('S1-Scope' in calls[0].headers), 'an empty S1-Scope must never be sent');
});

test('S1_SCOPE from credentials is the default when no scope is passed', async () => {
  process.env.S1_SCOPE = ACCOUNT;
  try {
    const calls = stubFetchH([gql({ configFiles: [] })]);
    await configFiles();
    assert.equal(calls[0].headers['S1-Scope'], ACCOUNT);
  } finally {
    delete process.env.S1_SCOPE;
  }
});

test('scope:null suppresses the credentials default', async () => {
  process.env.S1_SCOPE = ACCOUNT;
  try {
    const calls = stubFetchH([gql({ configFiles: [] })]);
    await configFiles({ scope: null });
    assert.ok(!('S1-Scope' in calls[0].headers), 'scope:null must send no header');
  } finally {
    delete process.env.S1_SCOPE;
  }
});

test('a malformed scope is rejected before any request is sent', async () => {
  const calls = stubFetchH([gql({ configFiles: [] })]);
  await assert.rejects(configFiles({ scope: 'Metacortex' }), /Invalid S1-Scope/);
  assert.equal(calls.length, 0, 'nothing may go out with a bad scope');
});

test('writes carry the scope too, not just reads', async () => {
  const calls = stubFetchH([gql({ addConfigFile: { udoId: '1', name: '/lookups/x', version: 2 } })]);
  await putConfigFile({ name: '/lookups/x', content: 'a,b', scope: SITE_SCOPE });
  assert.equal(calls[0].headers['S1-Scope'], SITE_SCOPE);
});

test('the dashboard duplicate guard checks the SAME scope as the write', async () => {
  // Guard listing at account scope while writing at site scope would let a
  // same-named site dashboard through, or block a legitimate site create.
  const calls = stubFetchH([
    gql({ configFiles: [{ udoId: '9', name: '/dashboards/Other', version: 1 }] }),
    gql({ addConfigFile: { udoId: '10', name: '/dashboards/New', version: 1 } }),
  ]);
  await putConfigFile({ name: '/dashboards/New', content: '{}', scope: SITE_SCOPE });
  assert.equal(calls[0].headers['S1-Scope'], SITE_SCOPE, 'guard listing must be scoped to the write');
  assert.equal(calls[1].headers['S1-Scope'], SITE_SCOPE);
});

test('absence disambiguation re-lists at the same scope', async () => {
  const calls = stubFetchH([
    { body: { errors: [{ message: 'Something went wrong. Please try again' }] } },
    gql({ configFiles: [] }),
  ]);
  const res = await configFile({ udoId: '6994516145065984', scope: SITE_SCOPE });
  assert.equal(res, null);
  assert.equal(calls[1].headers['S1-Scope'], SITE_SCOPE, 'a mismatched scope here reports a real file as absent');
});

// ─── createDashboard ───

test('createDashboard posts the config verbatim and returns the new id', async () => {
  const config = JSON.stringify({ configType: 'TABBED', tabs: [] });
  const calls = stubFetchH([gql({ createDashboardV2: { id: '6999396433133568', name: 'meta1 - Copy' } })]);
  const res = await createDashboard({ name: 'meta1 - Copy', config, scope: SITE_SCOPE });
  assert.equal(res.id, '6999396433133568');
  assert.equal(calls[0].body.variables.config, config);
  assert.equal(calls[0].body.variables.dashboardName, 'meta1 - Copy');
  assert.equal(calls[0].body.variables.public, true, 'isPublic defaults TRUE: a private service-user dashboard is invisible in the console');
  assert.equal(calls[0].headers['S1-Scope'], SITE_SCOPE);
});

test('createDashboard rejects the console stub-append shape before sending', async () => {
  // Live failure mode: the UI JSON editor starts from "{graphs: []}" and pasting
  // after it yields "{graphs: []}{...}" -> "Additional text after JSON object".
  const calls = stubFetchH([]);
  await assert.rejects(
    createDashboard({ name: 'x', config: '{\n  graphs: []\n}{"configType":"TABBED"}' }),
    /not valid JSON/,
  );
  assert.equal(calls.length, 0);
});

test('createDashboard throws when the mutation returns no id', async () => {
  stubFetchH([gql({ createDashboardV2: null })]);
  await assert.rejects(createDashboard({ name: 'x', config: '{}' }), /was not created/);
});

test('createDashboard permits duplicate names by default, refuses with failIfNameExists', async () => {
  stubFetchH([gql({ createDashboardV2: { id: '1', name: 'dupe' } })]);
  assert.equal((await createDashboard({ name: 'dupe', config: '{}' })).id, '1');

  stubFetchH([gql({ dashboardsV2: [{ id: '77', name: 'dupe' }] })]);
  await assert.rejects(
    createDashboard({ name: 'dupe', config: '{}', failIfNameExists: true }),
    /already exist at this scope/,
  );
});

// ─── shareDashboard ───

test('shareDashboard sends the scope target array the console sends', async () => {
  const calls = stubFetchH([gql({ shareResource: { id: 6999150597128192, name: 'meta2' } })]);
  const res = await shareDashboard({
    id: '6999150597128192',
    scopes: [{ scopeType: 'site', scopeId: SITE, operation: 'ADD' }],
  });
  assert.equal(res.status, 'success');
  assert.deepEqual(calls[0].body.variables.scopes, [{ scopeType: 'site', scopeId: SITE, operation: 'ADD' }]);
  assert.deepEqual(calls[0].body.variables.users, []);
});

test('shareDashboard defaults operation to ADD and lowercases scopeType', async () => {
  const calls = stubFetchH([gql({ shareResource: { id: 1, name: 'x' } })]);
  await shareDashboard({ id: '1', scopes: [{ scopeType: 'Site', scopeId: SITE }] });
  assert.deepEqual(calls[0].body.variables.scopes, [{ scopeType: 'site', scopeId: SITE, operation: 'ADD' }]);
});

test('shareDashboard rejects a malformed target instead of silently sharing nothing', async () => {
  const calls = stubFetchH([]);
  await assert.rejects(shareDashboard({ id: '1', scopes: [{ scopeType: 'group', scopeId: SITE }] }), /scopeType must be one of/);
  await assert.rejects(shareDashboard({ id: '1', scopes: [{ scopeType: 'site', scopeId: 'Metacortex' }] }), /must be a numeric id/);
  await assert.rejects(shareDashboard({ id: '1', scopes: [{ scopeType: 'site', scopeId: SITE, operation: 'GRANT' }] }), /must be ADD or REMOVE/);
  await assert.rejects(shareDashboard({ id: '1' }), /at least one scope or user/);
  assert.equal(calls.length, 0, 'validation must happen before the request');
});

test('shareDashboard throws when shareResource returns no id', async () => {
  stubFetchH([gql({ shareResource: null })]);
  await assert.rejects(
    shareDashboard({ id: '1', scopes: [{ scopeType: 'site', scopeId: SITE }] }),
    /nothing was shared/,
  );
});

// ─── getDashboard absence, the 1.3.2 regression class ───

test('getDashboard treats a GraphQL error as absence when the listing agrees', async () => {
  // Guards the 1.3.2 defect where absence-as-error made every successful delete
  // report failure.
  stubFetchH([
    { body: { errors: [{ message: 'Something went wrong. Please try again' }] } },
    gql({ dashboardsV2: [] }),
  ]);
  assert.equal(await getDashboard({ id: '123' }), null);
});

test('getDashboard rethrows when the listing shows the dashboard still there', async () => {
  stubFetchH([
    { body: { errors: [{ message: 'Something went wrong. Please try again' }] } },
    gql({ dashboardsV2: [{ id: '123', name: 'still here' }] }),
  ]);
  await assert.rejects(getDashboard({ id: '123' }), /Something went wrong/);
});

test('getDashboard never reads a transport failure as absence', async () => {
  stubFetchH([{ status: 404, body: '<html>not found</html>' }]);
  await assert.rejects(getDashboard({ id: '123' }), /404/);
});

// ─── deleteDashboard ───

test('deleteDashboard confirms removal by re-reading, not from the boolean', async () => {
  const calls = stubFetchH([
    gql({ deleteDashboard: true }),
    gql({ getDashboardV2: null }),
  ]);
  const res = await deleteDashboard({ id: '6999150597128192', scope: SITE_SCOPE });
  assert.equal(res.status, 'success');
  assert.equal(calls.length, 2, 'the mutation response alone is not proof');
  assert.equal(calls[1].headers['S1-Scope'], SITE_SCOPE);
});

test('deleteDashboard fails loudly when the dashboard survives a true response', async () => {
  stubFetchH([
    gql({ deleteDashboard: true }),
    gql({ getDashboardV2: { id: '1', name: 'survivor' } }),
  ]);
  await assert.rejects(deleteDashboard({ id: '1' }), /still exists after the delete mutation/);
});

// ─── saveDashboardLayout ───

test('saveDashboardLayout requires the {"graphs":[...]} wrapper', async () => {
  const calls = stubFetchH([]);
  await assert.rejects(saveDashboardLayout({ id: '1', tabName: 't', graphs: '[]' }), /graphs" array/);
  assert.equal(calls.length, 0);
});

test('saveDashboardLayout passes the wrapped graphs string and tab name through', async () => {
  const graphs = JSON.stringify({ graphs: [{ title: 'p' }] });
  const calls = stubFetchH([gql({ saveDashboardLayout: { graphs: '[{"title":"p"}]', options: '{}' } })]);
  await saveDashboardLayout({ id: '1', tabName: '2. Metacortex operations', graphs });
  assert.equal(calls[0].body.variables.graphs, graphs);
  assert.equal(calls[0].body.variables.tabName, '2. Metacortex operations');
});

// ─── listDashboards ───

test('listDashboards returns the dashboard array with access metadata', async () => {
  stubFetchH([gql({ dashboardsV2: [{ id: '1', name: 'a', access: { public: true, owner: 'p@x' } }] })]);
  const res = await listDashboards({ scope: SITE_SCOPE });
  assert.equal(res.length, 1);
  assert.equal(res[0].access.owner, 'p@x');
});

// ─── query paths are scope-sensitive too (1.3.5 gap fix) ───
// 1.3.4 shipped scope on the config-file and dashboard operations but NOT on the
// query methods, even though log reads are filtered by the same header. A hunt or
// panel-validation query run without the intended scope silently answers for the
// token default, which is the worst failure mode here: a plausible number for the
// wrong boundary.

test('v1Query sends the S1-Scope header', async () => {
  const calls = stubFetchH([{ body: { matches: [] } }]);
  await v1Query("dataSource.name='X'", { scope: SITE_SCOPE });
  assert.equal(calls[0].headers['S1-Scope'], SITE_SCOPE);
});

test('v1Query omits the header when unscoped', async () => {
  delete process.env.S1_SCOPE;
  const calls = stubFetchH([{ body: { matches: [] } }]);
  await v1Query("dataSource.name='X'");
  assert.ok(!('S1-Scope' in calls[0].headers));
});

test('v1Query rejects a malformed scope before sending', async () => {
  const calls = stubFetchH([]);
  await assert.rejects(v1Query("dataSource.name='X'", { scope: 'sitename' }), /Invalid S1-Scope/);
  assert.equal(calls.length, 0);
});

test('scopeHeaders is exported so the LRQ path cannot drift from the config path', async () => {
  const { scopeHeaders } = await import('../lib/sdl.js');
  assert.deepEqual(scopeHeaders(SITE_SCOPE), { 'S1-Scope': SITE_SCOPE });
  assert.deepEqual(scopeHeaders(null), {});
  assert.deepEqual(scopeHeaders(undefined), {});
  assert.throws(() => scopeHeaders('not-an-id'), /Invalid S1-Scope/);
});

test('isPublic defaults to true, and false is still honoured when explicit', async () => {
  // The raw API defaults public to false, which files the dashboard as private
  // and owned by the service user, making it invisible in the console to a human
  // at any scope. Indistinguishable from a failed deploy, so we default to true.
  let calls = stubFetchH([gql({ createDashboardV2: { id: '1', name: 'd' } })]);
  await createDashboard({ name: 'd', config: '{}' });
  assert.equal(calls[0].body.variables.public, true);

  calls = stubFetchH([gql({ createDashboardV2: { id: '2', name: 'p' } })]);
  await createDashboard({ name: 'p', config: '{}', isPublic: false });
  assert.equal(calls[0].body.variables.public, false, 'explicit false must still work');
});
