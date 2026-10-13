/**
 * UAM alert-management lifecycle (1.5.0): uam_set_status, uam_set_verdict,
 * uam_assign_alert, plus the LRQ poll-404 relaunch.
 *
 * The write path must send the console's exact alertTriggerActions request
 * (captured from a console HAR on 2026-10-07) and prove each change by
 * re-reading the alert. HTTP is mocked by a router that keeps a fake alert's
 * state, so every assertion about "the alert changed / did not change" is
 * checked against what a re-read returns. No network.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

process.env.S1_CONSOLE_URL = 'https://mgmt.example.invalid';
process.env.S1_CONSOLE_API_TOKEN = 'tok';

const s1 = await import('../lib/s1.js');
const { ALL_TOOLS } = await import('../lib/server-core.js');
const tool = (name) => ALL_TOOLS.find((t) => t.name === name);

const ACCOUNT = '900000000000000001';
const HUMAN = '900000000000000777';

// The console's variables for a status change, from the HAR (ids replaced).
const HAR_STATUS_VARIABLES = {
  scope: { scopeIds: [ACCOUNT], scopeType: 'ACCOUNT' },
  filter: { or: [{ and: [{ fieldId: 'id', stringEqual: { value: 'alert-1' } }] }] },
  viewType: 'ALL',
  actions: [{ id: 'S1/alert/statusUpdate', payload: { status: { value: 'IN_PROGRESS' } } }],
};

/**
 * Fetch router simulating one alert. `mode` decides how alertTriggerActions
 * answers: 'success' applies the change, 'missing' fails MISSING_PERMISSION,
 * 'skip' skips, 'lie' reports success without applying, 'error' returns
 * TriggerActionsError, 'scheduled' schedules and applies, 'failure' fails
 * with SERVICE_ERROR, 'empty' returns no actions.
 */
function mockUam({ mode = 'success', product = 'smoke-product', alert: initial, users = [], roleManage = false, found = true } = {}) {
  const alert = {
    id: 'alert-1', name: 'zz-regress unit', status: 'NEW', analystVerdict: 'UNDEFINED', assignee: null,
    detectionSource: { product, vendor: 'v' },
    realTime: { scope: { account: { id: ACCOUNT }, site: { id: '5' } } },
    ...(initial || {}),
  };
  // Other suites in the same process delete these after their tests.
  process.env.S1_CONSOLE_URL = 'https://mgmt.example.invalid';
  process.env.S1_CONSOLE_API_TOKEN = 'tok';
  const calls = [];
  const real = globalThis.fetch;
  const json = (obj) => new Response(JSON.stringify(obj), { status: 200, headers: { 'Content-Type': 'application/json' } });
  globalThis.fetch = async (url, opts = {}) => {
    const u = new URL(String(url));
    const body = opts.body ? JSON.parse(opts.body) : undefined;
    const op = body?.operationName || body?.query?.match(/(query|mutation)\s+(\w+)/)?.[2];
    calls.push({ path: u.pathname, search: u.search, method: opts.method || 'GET', body, op });
    if (u.pathname === '/web/api/v2.1/user') {
      return json({ data: { id: 'svc', scopeRoles: [{ id: ACCOUNT, name: 'acct', roleId: '42', roleName: 'FULLADMIN' }] } });
    }
    if (u.pathname.startsWith('/web/api/v2.1/rbac/role/')) {
      return json({ data: { name: 'FULLADMIN', pages: [{ identifier: 'unifiedAlerts', permissions: [
        { title: 'View', value: true },
        { title: 'Manage', groupName: 'STAR Alerts', ...(roleManage ? { value: true } : {}) },
        { title: 'Manage', groupName: 'Generic Alerts', ...(roleManage ? { value: true } : {}) },
      ] }] } });
    }
    if (u.pathname === '/web/api/v2.1/users') {
      const want = u.searchParams.get('email');
      return json({ data: users.filter((x) => !want || x.email.toLowerCase().includes(want.toLowerCase())) });
    }
    if (u.pathname === '/web/api/v2.1/accounts') return json({ data: [{ id: ACCOUNT }] });
    if (op === 'AlertState' || op === 'GetAlert') {
      return json({ data: { alert: found ? structuredClone(alert) : null } });
    }
    if (op === 'GetAlertNotes') return json({ data: { alertNotes: { data: [] } } });
    if (op === 'AvailableActions') {
      return json({ data: { alertAvailableActions: { data: [{ id: 'S1/alert/addNote', isDisabled: false }] } } });
    }
    if (op === 'AlertTriggerActions') {
      const a = body.variables.actions[0];
      const p = a.payload;
      const apply = () => {
        if (p.status) alert.status = p.status.value;
        if (p.analystVerdict) alert.analystVerdict = p.analystVerdict.value;
        if (p.assignUser) {
          alert.assignee = p.assignUser.value == null ? null
            : { userId: p.assignUser.value, email: users.find((x) => x.id === p.assignUser.value)?.email ?? null, fullName: null };
        }
      };
      const triggered = (lists) => json({ data: { alertTriggerActions: { __typename: 'ActionsTriggered', actions: [{
        actionId: a.id, skip: [], failure: [], success: [], __typename: 'TriggeredAction', ...lists }] } } });
      switch (mode) {
        case 'success': apply(); return triggered({ success: [{ id: alert.id }] });
        case 'missing': return triggered({ failure: [{ id: alert.id, errorMessage: 'Missing UAM manage permissions', errorType: 'MISSING_PERMISSION' }] });
        case 'failure': return triggered({ failure: [{ id: alert.id, errorMessage: 'status transition rejected', errorType: 'SERVICE_ERROR' }] });
        case 'skip': return triggered({ skip: [{ id: alert.id }] });
        case 'lie': return triggered({ success: [{ id: alert.id }] });
        case 'empty': return json({ data: { alertTriggerActions: { __typename: 'ActionsTriggered', actions: [] } } });
        case 'error': return json({ data: { alertTriggerActions: { __typename: 'TriggerActionsError', errors: [{ errorMessage: 'too many alerts', errorPayload: { limit: 10000 } }] } } });
        case 'scheduled': apply(); return json({ data: { alertTriggerActions: { __typename: 'TriggerActionsScheduled', bulkActionTriggerId: 'b-1' } } });
        default: throw new Error(`unknown mode ${mode}`);
      }
    }
    throw new Error(`unrouted request ${u.pathname} op=${op}`);
  };
  return {
    alert,
    calls,
    mutations: () => calls.filter((c) => c.op === 'AlertTriggerActions'),
    restore: () => { globalThis.fetch = real; },
  };
}

const FAST = { verifyDelayMs: 0, verifyAttempts: 2 };

// ─── request shape identical to the console ──────────────────────────────────

test('set_status sends the console request: operationName, ?opname, document, variables and key order', async () => {
  const m = mockUam();
  try {
    const r = await s1.uamSetStatus('alert-1', 'IN_PROGRESS', FAST);
    const [mut] = m.mutations();
    assert.equal(mut.search, '?opname=AlertTriggerActions');
    assert.equal(mut.body.operationName, 'AlertTriggerActions');
    assert.equal(mut.body.query, s1.ALERT_TRIGGER_ACTIONS_MUTATION);
    assert.deepEqual(mut.body.variables, HAR_STATUS_VARIABLES);
    assert.deepEqual(Object.keys(mut.body.variables), ['scope', 'filter', 'viewType', 'actions']);
    // The console document declares $actions as non-null.
    assert.match(mut.body.query, /\$actions: \[TriggerActionInput!\]!/);
    assert.equal(r.outcome, 'applied');
    assert.equal(r.verified, true);
    assert.deepEqual([r.before.status, r.after.status], ['NEW', 'IN_PROGRESS']);
  } finally { m.restore(); }
});

test('buildAlertTriggerActionsVariables reproduces the HAR variables exactly', () => {
  const v = s1.buildAlertTriggerActionsVariables('alert-1', 'S1/alert/statusUpdate',
    { status: { value: 'IN_PROGRESS' } }, { scopeIds: [ACCOUNT], scopeType: 'ACCOUNT' });
  assert.equal(JSON.stringify(v), JSON.stringify(HAR_STATUS_VARIABLES));
});

test('full status lifecycle NEW -> IN_PROGRESS -> RESOLVED -> NEW, each verified by re-read', async () => {
  const m = mockUam();
  try {
    for (const s of ['IN_PROGRESS', 'RESOLVED', 'NEW']) {
      const r = await s1.uamSetStatus('alert-1', s, FAST);
      assert.equal(r.after.status, s);
      assert.equal(m.alert.status, s);
    }
    assert.equal(m.mutations().length, 3);
  } finally { m.restore(); }
});

test('scopeIds/scopeType override the alert account scope', async () => {
  const m = mockUam();
  try {
    await s1.uamSetStatus('alert-1', 'RESOLVED', { ...FAST, scopeIds: ['5'], scopeType: 'SITE' });
    assert.deepEqual(m.mutations()[0].body.variables.scope, { scopeIds: ['5'], scopeType: 'SITE' });
    await assert.rejects(() => s1.uamSetStatus('alert-1', 'NEW', { ...FAST, scopeIds: ['5'], scopeType: 'GLOBAL' }), /scopeType must be ACCOUNT, SITE or GROUP/);
  } finally { m.restore(); }
});

test('without realTime scope on the alert, falls back to every visible account', async () => {
  const m = mockUam({ alert: { realTime: null } });
  try {
    await s1.uamSetStatus('alert-1', 'RESOLVED', FAST);
    assert.ok(m.calls.some((c) => c.path === '/web/api/v2.1/accounts'));
    assert.deepEqual(m.mutations()[0].body.variables.scope, { scopeIds: [ACCOUNT], scopeType: 'ACCOUNT' });
  } finally { m.restore(); }
});

// ─── analyst verdict ─────────────────────────────────────────────────────────

test('set_verdict sends S1/alert/analystVerdictUpdate {analystVerdict:{value}} and verifies', async () => {
  const m = mockUam();
  try {
    const r = await s1.uamSetVerdict('alert-1', 'TRUE_POSITIVE_MALWARE', FAST);
    const a = m.mutations()[0].body.variables.actions;
    assert.deepEqual(a, [{ id: 'S1/alert/analystVerdictUpdate', payload: { analystVerdict: { value: 'TRUE_POSITIVE_MALWARE' } } }]);
    assert.deepEqual([r.before.analystVerdict, r.after.analystVerdict], ['UNDEFINED', 'TRUE_POSITIVE_MALWARE']);
  } finally { m.restore(); }
});

test('verdict enum has the 20 schema values and rejects group headers before any request', async () => {
  assert.equal(s1.UAM_ANALYST_VERDICTS.length, 20);
  const m = mockUam();
  try {
    for (const bad of ['TRUE_POSITIVE', 'FALSE_POSITIVE', 'SUSPICIOUS', 'true_positive_malware', '', undefined]) {
      await assert.rejects(() => s1.uamSetVerdict('alert-1', bad, FAST), /invalid analyst verdict/);
    }
    assert.equal(m.calls.length, 0, 'no request may be sent for an invalid verdict');
  } finally { m.restore(); }
});

test('status enum rejects CLOSED / FALSE_POSITIVE before any request', async () => {
  const m = mockUam();
  try {
    for (const bad of ['CLOSED', 'FALSE_POSITIVE', 'OPEN', 'resolved']) {
      await assert.rejects(() => s1.uamSetStatus('alert-1', bad, FAST), /invalid status/);
    }
    assert.equal(m.calls.length, 0);
  } finally { m.restore(); }
});

// ─── assignee ────────────────────────────────────────────────────────────────

test('assign by userId sends {assignUser:{value:"<id>"}} as a string and verifies assignee.userId', async () => {
  const m = mockUam();
  try {
    const r = await s1.uamAssignAlert('alert-1', { userId: HUMAN, ...FAST });
    assert.deepEqual(m.mutations()[0].body.variables.actions,
      [{ id: 'S1/alert/assignUser', payload: { assignUser: { value: HUMAN } } }]);
    assert.equal(r.after.assignee.userId, HUMAN);
    assert.equal(m.calls.filter((c) => c.path === '/web/api/v2.1/users').length, 0, 'a userId needs no lookup');
  } finally { m.restore(); }
});

test('assign by email resolves exactly one user via GET /users?email=', async () => {
  const m = mockUam({ users: [{ id: HUMAN, email: 'Analyst@Example.com' }] });
  try {
    const r = await s1.uamAssignAlert('alert-1', { email: 'analyst@example.com', ...FAST });
    const lookup = m.calls.find((c) => c.path === '/web/api/v2.1/users');
    assert.match(lookup.search, /email=analyst%40example\.com/);
    assert.equal(m.mutations()[0].body.variables.actions[0].payload.assignUser.value, HUMAN);
    assert.equal(r.after.assignee.userId, HUMAN);
  } finally { m.restore(); }
});

test('assign by email refuses zero or ambiguous matches, before the mutation', async () => {
  for (const users of [[], [{ id: '1', email: 'a@x.com' }, { id: '2', email: 'A@x.com' }]]) {
    const m = mockUam({ users });
    try {
      await assert.rejects(() => s1.uamAssignAlert('alert-1', { email: 'a@x.com', ...FAST }), /No unique console user/);
      assert.equal(m.mutations().length, 0);
    } finally { m.restore(); }
  }
});

test('unassign sends {assignUser:{value:null}} and verifies the assignee is gone', async () => {
  const m = mockUam({ alert: { assignee: { userId: HUMAN, email: 'h@x.com' } } });
  try {
    const r = await s1.uamAssignAlert('alert-1', { unassign: true, ...FAST });
    assert.deepEqual(m.mutations()[0].body.variables.actions[0].payload, { assignUser: { value: null } });
    assert.equal(r.before.assignee.userId, HUMAN);
    assert.equal(r.after.assignee, null);
  } finally { m.restore(); }
});

test('assign argument validation happens before any request', async () => {
  const m = mockUam();
  try {
    await assert.rejects(() => s1.uamAssignAlert('alert-1', { ...FAST }), /exactly one of userId, email, or unassign/);
    await assert.rejects(() => s1.uamAssignAlert('alert-1', { userId: HUMAN, unassign: true, ...FAST }), /exactly one/);
    await assert.rejects(() => s1.uamAssignAlert('alert-1', { userId: 'bob', ...FAST }), /numeric console user id/);
    assert.equal(m.calls.length, 0);
  } finally { m.restore(); }
});

// ─── refusals fail loudly and leave the alert unchanged ──────────────────────

for (const [name, run, field, initialValue] of [
  ['status', () => s1.uamSetStatus('alert-1', 'IN_PROGRESS', FAST), 'status', 'NEW'],
  ['verdict', () => s1.uamSetVerdict('alert-1', 'FALSE_POSITIVE_BENIGN', FAST), 'analystVerdict', 'UNDEFINED'],
  ['assign', () => s1.uamAssignAlert('alert-1', { userId: HUMAN, ...FAST }), 'assignee', null],
  ['unassign', () => s1.uamAssignAlert('alert-1', { unassign: true, ...FAST }), 'assignee', { userId: HUMAN, email: 'h@x.com' }],
]) {
  test(`MISSING_PERMISSION on ${name}: throws with the role permission hint, alert unchanged`, async () => {
    const m = mockUam({ mode: 'missing', alert: field === 'assignee' ? { assignee: initialValue } : {} });
    try {
      const err = await run().then(() => null, (e) => e);
      assert.ok(err, 'must throw');
      assert.match(err.message, /Missing UAM manage permissions \(errorType MISSING_PERMISSION\)/);
      assert.match(err.message, /"Unified Alerts > Generic Alerts: Manage"/);
      assert.match(err.message, /Policies and settings > User management > Console users > Roles/);
      assert.match(err.message, /role "FULLADMIN" \(id 42\) on scope "acct" lacks STAR Alerts: Manage, Generic Alerts: Manage/);
      assert.match(err.message, /A re-read shows/);
      assert.deepEqual(m.alert[field], initialValue, 'the alert must be unchanged');
    } finally { m.restore(); }
  });
}

test('MISSING_PERMISSION on a STAR alert names STAR Alerts: Manage and the legacy STAR Rule Alerts permissions', async () => {
  const m = mockUam({ mode: 'missing', product: 'STAR' });
  try {
    await assert.rejects(() => s1.uamSetStatus('alert-1', 'RESOLVED', FAST),
      /"Unified Alerts > STAR Alerts: Manage".*legacy "STAR Rule Alerts > Update Incident Status \/ Update Analyst Verdict"/);
  } finally { m.restore(); }
});

test('uamManageGroupFor maps detection products to the RBAC group', () => {
  assert.equal(s1.uamManageGroupFor('STAR'), 'STAR Alerts');
  assert.equal(s1.uamManageGroupFor('EDR'), 'Endpoint Alerts');
  assert.equal(s1.uamManageGroupFor('Singularity Identity'), 'Identity Alerts');
  assert.equal(s1.uamManageGroupFor('Mobile'), 'Mobile Alerts');
  assert.equal(s1.uamManageGroupFor('smoke-product'), 'Generic Alerts');
  assert.equal(s1.uamManageGroupFor(undefined), 'Generic Alerts');
});

test('other failure types attach the alertAvailableActions diagnosis', async () => {
  const m = mockUam({ mode: 'failure' });
  try {
    await assert.rejects(() => s1.uamSetVerdict('alert-1', 'TRUE_POSITIVE_BENIGN', FAST),
      /status transition rejected \| alertAvailableActions: analystVerdictUpdate is NOT OFFERED/);
    const avail = m.calls.find((c) => c.op === 'AvailableActions');
    assert.deepEqual(avail.body.variables.scope, { scopeIds: [ACCOUNT], scopeType: 'ACCOUNT' });
  } finally { m.restore(); }
});

test('skip when the value is already set resolves as already_set (verified)', async () => {
  const m = mockUam({ mode: 'skip', alert: { status: 'RESOLVED' } });
  try {
    const r = await s1.uamSetStatus('alert-1', 'RESOLVED', FAST);
    assert.equal(r.outcome, 'already_set');
    assert.equal(r.verified, true);
  } finally { m.restore(); }
});

test('skip that leaves a different value throws "skipped"', async () => {
  const m = mockUam({ mode: 'skip' });
  try {
    await assert.rejects(() => s1.uamSetVerdict('alert-1', 'TRUE_POSITIVE_BENIGN', FAST), /skipped .*analystVerdict is "UNDEFINED"/);
  } finally { m.restore(); }
});

test('success that the re-read does not confirm throws instead of reporting success', async () => {
  const m = mockUam({ mode: 'lie' });
  try {
    await assert.rejects(() => s1.uamAssignAlert('alert-1', { userId: HUMAN, ...FAST }), /re-read 2 time\(s\) still shows assignee=null/);
  } finally { m.restore(); }
});

test('TriggerActionsError and empty actions throw', async () => {
  let m = mockUam({ mode: 'error' });
  try {
    await assert.rejects(() => s1.uamSetStatus('alert-1', 'RESOLVED', FAST), /trigger error .*too many alerts \(limit 10000\)/);
  } finally { m.restore(); }
  m = mockUam({ mode: 'empty' });
  try {
    await assert.rejects(() => s1.uamSetStatus('alert-1', 'RESOLVED', FAST), /applied no action/);
  } finally { m.restore(); }
});

test('TriggerActionsScheduled is accepted only once the re-read shows the value', async () => {
  const m = mockUam({ mode: 'scheduled' });
  try {
    const r = await s1.uamSetStatus('alert-1', 'IN_PROGRESS', FAST);
    assert.equal(r.outcome, 'scheduled');
    assert.equal(r.after.status, 'IN_PROGRESS');
  } finally { m.restore(); }
});

test('an alert the token cannot see fails before any mutation', async () => {
  const m = mockUam({ found: false });
  try {
    await assert.rejects(() => s1.uamSetStatus('alert-1', 'RESOLVED', FAST), /was not found or is not visible/);
    assert.equal(m.mutations().length, 0);
  } finally { m.restore(); }
});

// ─── tool wiring ─────────────────────────────────────────────────────────────

test('uam_set_verdict and uam_assign_alert are registered with schema enums from the lib', () => {
  const v = tool('uam_set_verdict');
  const a = tool('uam_assign_alert');
  const s = tool('uam_set_status');
  assert.ok(v && a && s);
  assert.deepEqual(v.inputSchema.properties.verdict.enum, [...s1.UAM_ANALYST_VERDICTS]);
  assert.deepEqual(s.inputSchema.properties.status.enum, [...s1.UAM_STATUSES]);
  assert.deepEqual(v.inputSchema.required, ['alertId', 'verdict']);
  assert.deepEqual(a.inputSchema.required, ['alertId']);
  for (const t of [v, a, s]) {
    assert.deepEqual(t.inputSchema.properties.scopeType.enum, ['ACCOUNT', 'SITE', 'GROUP']);
    assert.match(t.description, /MISSING_PERMISSION/);
  }
  assert.deepEqual(tool('uam_available_actions').inputSchema.properties.scopeType.enum, ['ACCOUNT', 'SITE', 'GROUP']);
});

test('uam_assign_alert tool handler unassigns end to end', async () => {
  const m = mockUam({ alert: { assignee: { userId: HUMAN, email: 'h@x.com' } } });
  try {
    const out = JSON.parse(await tool('uam_assign_alert').handler({ alertId: 'alert-1', unassign: true }));
    assert.equal(out.verified, true);
    assert.equal(out.after.assignee, null);
  } finally { m.restore(); }
});

test('uam_set_verdict tool handler surfaces MISSING_PERMISSION as a thrown error', async () => {
  const m = mockUam({ mode: 'missing' });
  try {
    await assert.rejects(() => tool('uam_set_verdict').handler({ alertId: 'alert-1', verdict: 'FALSE_POSITIVE_USER_ERROR' }), /MISSING_PERMISSION/);
  } finally { m.restore(); }
});

// ─── LRQ: a poll 404 "Requested token ... not found" relaunches once ─────────

function mockLrq(pollPlan) {
  process.env.S1_CONSOLE_URL = 'https://mgmt.example.invalid';
  process.env.S1_CONSOLE_API_TOKEN = 'tok';
  const log = [];
  let launches = 0;
  const real = globalThis.fetch;
  globalThis.fetch = async (url, opts = {}) => {
    const u = new URL(String(url));
    const method = opts.method || 'GET';
    if (method === 'POST') {
      launches++;
      log.push(`POST q${launches}`);
      return new Response(JSON.stringify({ id: `q${launches}` }), { status: 200, headers: { 'X-Dataset-Query-Forward-Tag': `tag${launches}` } });
    }
    const qid = u.pathname.split('/').pop();
    if (method === 'DELETE') { log.push(`DELETE ${qid}`); return new Response('{}', { status: 200 }); }
    log.push(`GET ${qid} tag=${opts.headers['X-Dataset-Query-Forward-Tag']}`);
    const step = pollPlan.shift();
    if (step === 404) {
      return new Response(JSON.stringify({ code: 'not_found', message: `Requested token=${qid} not found` }), { status: 404 });
    }
    return new Response(JSON.stringify({ stepsCompleted: 1, stepsTotal: 1, data: { columns: [{ name: 'n' }], values: [[7]], matchCount: 7 } }), { status: 200 });
  };
  return { log, restore: () => { globalThis.fetch = real; } };
}

test('LRQ: one poll 404 "Requested token ... not found" relaunches the query and succeeds', async () => {
  const m = mockLrq([404, 'ok']);
  try {
    const r = await s1.lrqRun("dataSource.name='X' | group n=count()", { includeMetering: true });
    assert.deepEqual(r.rows, [{ n: 7 }]);
    assert.equal(r.queryId, 'q2');
    assert.deepEqual(m.log, ['POST q1', 'GET q1 tag=tag1', 'DELETE q1', 'POST q2', 'GET q2 tag=tag2', 'DELETE q2']);
  } finally { m.restore(); }
});

test('LRQ: a second poll 404 after the relaunch is fatal', async () => {
  const m = mockLrq([404, 404]);
  try {
    await assert.rejects(() => s1.lrqRun("dataSource.name='X' | group n=count()", { includeMetering: true }),
      /LRQ poll failed \(404\).*not found.*after one relaunch/);
    assert.equal(m.log.filter((l) => l.startsWith('POST')).length, 2, 'exactly one relaunch');
  } finally { m.restore(); }
});
