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
