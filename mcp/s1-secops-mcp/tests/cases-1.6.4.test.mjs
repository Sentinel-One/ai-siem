/**
 * 1.6.4: Case Management tools (lib/cases.js, tools/cases.js). HTTP is mocked; no network.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

process.env.S1_CONSOLE_URL ||= 'https://tenant.sentinelone.net';
process.env.S1_CONSOLE_API_TOKEN ||= 'test-token-not-a-jwt';
process.env.S1_CASE_ALERT_RETRY_MS = '5';   // test-only: shorten the alert retry wait

const lib = await import('../lib/cases.js');
const { tools } = await import('../tools/cases.js');
const access = await import('../lib/access.js');
const TOOL = Object.fromEntries(tools.map(t => [t.name, t]));

/** Mock fetch with a router: (url, body) => response body. Records every call. */
function mock(router) {
  const calls = [];
  const real = globalThis.fetch;
  globalThis.fetch = async (url, opts = {}) => {
    const body = opts.body ? JSON.parse(opts.body) : undefined;
    calls.push({ url: String(url), method: opts.method || 'GET', body });
    const r = router(String(url), body, calls.length - 1);
    const text = JSON.stringify(r ?? {});
    return { ok: true, status: 200, headers: new Map(), text: async () => text };
  };
  return { calls, restore: () => { globalThis.fetch = real; } };
}
async function withMock(router, fn) {
  const m = mock(router);
  try { return await fn(m.calls); } finally { m.restore(); }
}
const q = (c) => c.body?.query || '';

// ─── Literal builder ─────────────────────────────────────────────────────────

test('lit: strings are JSON-escaped, so input cannot close the literal or add arguments', () => {
  const evil = '") { id } } mutation { deleteCreationRules(filter: {}) { deletedRuleIds } } #';
  const out = lib.lit(evil);
  assert.equal(JSON.parse(out), evil);
  assert.ok(out.startsWith('"') && out.endsWith('"'));
  assert.equal(lib.lit('a\nb\\c"'), '"a\\nb\\\\c\\""');
});

test('lit: enums are validated, keys must be identifiers, numbers must be finite', () => {
  assert.equal(lib.lit(lib.en('HIGH')), 'HIGH');
  assert.throws(() => lib.en('HIGH) { id }'), /invalid enum/);
  assert.throws(() => lib.en('high'), /invalid enum/);
  assert.throws(() => lib.lit({ 'a b': 1 }), /invalid input field name/);
  assert.throws(() => lib.lit(NaN), /invalid number/);
  assert.equal(lib.lit({ a: undefined, b: [1, true, null] }), '{ b: [1, true, null] }');
  assert.equal(lib.args({ x: 'y', z: undefined }), 'x: "y"');
});

test('checkId refuses anything that is not an id', () => {
  assert.equal(lib.checkId(' 01a2-b3 '), '01a2-b3');
  assert.throws(() => lib.checkId('a" b'), /id string/);
  assert.throws(() => lib.checkId(''), /id string/);
});

test('textToHtml escapes and keeps paragraphs', () => {
  assert.equal(lib.textToHtml('a <b> & "c"\n\nline1\nline2'), '<p>a &lt;b&gt; &amp; "c"</p><p>line1<br>line2</p>');
  assert.ok(lib.sameHtml('<p>a &quot;b&quot;  c</p>', '<p>a "b" c</p>'));
});

test('case types: trimmed, de-duplicated case-insensitively, at most 5', () => {
  assert.deepEqual(lib.normaliseCaseTypes(['  Incident ', 'incident', 'my   type']), ['Incident', 'my type']);
  assert.throws(() => lib.normaliseCaseTypes(['a', 'b', 'c', 'd', 'e', 'f']), /at most 5/);
  assert.ok(lib.sameCaseTypes(['Cmtest custom', 'Incident'], ['incident', ' cmTEST   custom ']));
});

// ─── Rule expressions ────────────────────────────────────────────────────────

test('expression ids are six alphanumeric characters and unique', () => {
  const ids = new Set();
  for (let i = 0; i < 500; i++) { const id = lib.expressionId(); assert.match(id, /^[A-Za-z0-9]{6}$/); ids.add(id); }
  assert.ok(ids.size > 490);
});

test('buildExpression: short form becomes a GROUP of ITEMs with generated ids', () => {
  const { expression, idMap } = lib.buildExpression({ match: 'any', conditions: [
    { property: 'alert_severity', operation: 'equals', value: 'CRITICAL' },
    { property: 'MITRE_TACTICS', operation: 'HAS', value: ['IMPACT', 'EXECUTION'] },
  ] });
  const p = lib.plainExpression(expression);
  assert.equal(p.type, 'GROUP');
  assert.equal(p.condition, 'OR');
  assert.match(p.id, /^[A-Za-z0-9]{6}$/);
  assert.deepEqual(p.expressions[0], { id: p.expressions[0].id, type: 'ITEM', propertyName: 'ALERT_SEVERITY', operation: 'EQUALS', value: { type: 'STRING', stringValue: 'CRITICAL' } });
  assert.deepEqual(p.expressions[1].value, { type: 'STRING_LIST', stringValues: ['IMPACT', 'EXECUTION'] });
  assert.deepEqual(idMap, {});
  // propertyName is written as a string literal, operation as an enum
  const l = lib.lit(expression);
  assert.match(l, /propertyName: "ALERT_SEVERITY", operation: EQUALS/);
});

test('buildExpression: invalid caller ids are replaced and mapped; valid ones kept', () => {
  const { expression, idMap } = lib.buildExpression({ id: 'root', type: 'GROUP', condition: 'AND', expressions: [
    { id: 'abc123', type: 'ITEM', propertyName: 'ALERT_NAME', operation: 'CONTAINS', value: { type: 'STRING', stringValue: 'x' } },
  ] });
  assert.match(idMap.root, /^[A-Za-z0-9]{6}$/);
  assert.equal(lib.plainExpression(expression).expressions[0].id, 'abc123');
});

test('buildExpression rejects bad node types, operations and depth', () => {
  assert.throws(() => lib.buildExpression({ type: 'NOPE' }), /GROUP or ITEM/);
  assert.throws(() => lib.buildExpression({ type: 'ITEM', propertyName: 'A', operation: 'x) {', value: 'v' }), /invalid rule operation/);
  let deep = { type: 'ITEM', propertyName: 'A', operation: 'EQUALS', value: 'v' };
  for (let i = 0; i < 10; i++) deep = { type: 'GROUP', expressions: [deep] };
  assert.throws(() => lib.buildExpression(deep), /nested too deeply/);
});

// ─── Read-only classification ────────────────────────────────────────────────

test('case reads are read tools, writes are write tools, rule scope and rule writes are destructive', () => {
  for (const n of ['case_list', 'case_get', 'case_for_alert', 'case_metadata', 'case_rules']) assert.equal(access.accessOf(n), 'read', n);
  for (const n of ['case_create', 'case_update', 'case_triage', 'case_add_note', 'case_task', 'case_iocs', 'case_post_message', 'case_alerts', 'case_rule_apply', 'case_rules_scope']) assert.equal(access.accessOf(n), 'write', n);
  assert.equal(access.annotationsFor('case_rules_scope').destructiveHint, true);
  assert.equal(access.annotationsFor('case_add_note').destructiveHint, false);
});

test('casesGraphql refuses a mutation sent as a read', async () => {
  await assert.rejects(() => lib.casesGraphql('mutation { x }', { readOnly: true }), /must be a GraphQL query/);
});

// ─── Tools against a mocked API ──────────────────────────────────────────────

const CASE = { id: 'c1', publicId: '20261123-1', name: 'Case one', status: 'IN_PROGRESS', severity: 'HIGH', analystVerdict: 'UNDEFINED', caseTypes: ['Incident'], assignee: { id: '42', fullName: 'Ana', email: 'a@x' }, scope: { account: { id: '7' }, site: { id: '8' } }, alertIds: ['a1'] };

test('case_update reads first and sends every field, so an omitted assignee is kept', async () => {
  let state = { ...CASE };
  await withMock((url, body) => {
    const s = body?.query || '';
    if (s.startsWith('mutation')) {
      assert.match(s, /updateCase\(caseId: "c1", name: "Renamed", status: IN_PROGRESS, severity: HIGH, analystVerdict: UNDEFINED, assignTo: "42", caseTypes: \["Incident"\]\)/);
      state = { ...state, name: 'Renamed' };
      return { data: { updateCase: true } };
    }
    return { data: { case: state } };
  }, async (calls) => {
    const out = JSON.parse(await TOOL.case_update.handler({ caseId: 'c1', name: 'Renamed' }));
    assert.equal(out.verified, true);
    assert.equal(out.after.name, 'Renamed');
    assert.ok(calls.every(c => c.url.endsWith('/web/api/v2.1/cases/graphql')));
  });
});

test('case_update refuses CLOSED and points to case_triage', async () => {
  await assert.rejects(() => TOOL.case_update.handler({ caseId: 'c1', status: 'CLOSED' }), /case_triage/);
});

test('case_triage CLOSED needs a reason; sends closingInfo with the case account scope', async () => {
  await assert.rejects(() => TOOL.case_triage.handler({ caseIds: ['c1'], status: 'CLOSED' }), /closingReason/);
  let state = { ...CASE };
  await withMock((url, body) => {
    const s = body?.query || '';
    if (s.startsWith('mutation')) {
      assert.match(s, /updateCaseStatus\(filter: \{ or: \[\{ and: \[\{ fieldId: "id", stringIn: \{ values: \["c1"\] \} \}\] \}\] \}, scope: \{ scopeIds: \["7"\], scopeType: ACCOUNT \}, status: CLOSED, closingInfo: \{ reason: "Done", note: "n" \}\)/);
      state = { ...state, status: 'CLOSED' };
      return { data: { updateCaseStatus: { updatedCaseIds: ['c1'] } } };
    }
    return { data: { case: state } };
  }, async () => {
    const out = JSON.parse(await TOOL.case_triage.handler({ caseIds: ['c1'], status: 'CLOSED', closingReason: 'Done', closingNote: 'n' }));
    assert.equal(out.cases[0].after.status, 'CLOSED');
    assert.match(out.note, /independent/);
    assert.equal(out.alerts, undefined);
  });
});

test('case_add_note always sends contentHtml and finds the note on re-read', async () => {
  await withMock((url, body) => {
    const s = body?.query || '';
    if (s.startsWith('mutation')) {
      assert.match(s, /createNote\(caseId: "c1", contentPlainText: "a <b>", contentHtml: "<p>a &lt;b&gt;<\/p>"\)/);
      return { data: { createNote: true } };
    }
    return { data: { listNotesForCase: { edges: [{ node: { id: 'n1', contentPlainText: 'a', contentHtml: '<p>a &lt;b&gt;</p>', createdAt: 't' } }], pageInfo: {} }, listTasksForCase: [], listIoCsForCase: [], collaborationSpaceMessages: { edges: [], pageInfo: {} } } };
  }, async () => {
    const out = JSON.parse(await TOOL.case_add_note.handler({ caseId: 'c1', note: 'a <b>' }));
    assert.equal(out.noteId, 'n1');
  });
});

test('case_alerts add reports alerts that stayed in another case', async () => {
  await withMock((url, body) => {
    const s = body?.query || '';
    if (s.includes('addAlertsToCase')) return { data: { addAlertsToCase: { success: true, errors: [] } } };
    if (s.includes('caseForAlert')) return { data: { caseForAlert: { id: 'c9', publicId: 'P9', name: 'Other' } } };
    return { data: { case: { ...CASE, processingState: 'READY', alertIds: ['a1'] } } };
  }, async () => {
    const out = JSON.parse(await TOOL.case_alerts.handler({ action: 'add', caseId: 'c1', alertIds: ['a1', 'a2'] }));
    assert.deepEqual(out.added, ['a1']);
    assert.deepEqual(out.notAdded, [{ alertId: 'a2', inCase: { id: 'c9', publicId: 'P9', name: 'Other' } }]);
  });
});

test('case_rule_apply is refused while the scope inherits its rules', async () => {
  await withMock(() => ({ data: { creationRulesScopeConfig: { linked: true } } }), async (calls) => {
    await assert.rejects(() => TOOL.case_rule_apply.handler({ action: 'delete', ruleId: 'r1', scopeIds: ['7'] }), /inherited \(linked: true\).*case_rules_scope/);
    assert.equal(calls.length, 1);
    assert.match(q(calls[0]), /^query/);
  });
});

test('case_rules_scope requires confirm: true and sends nothing without it', async () => {
  await withMock(() => ({}), async (calls) => {
    await assert.rejects(() => TOOL.case_rules_scope.handler({ linked: false, confirm: false, scopeIds: ['7'] }), /confirm: true/);
    assert.equal(calls.length, 0);
  });
});

test('GraphQL errors become tool errors', async () => {
  await withMock(() => ({ errors: [{ message: 'A case can have at most 5 case types' }] }), async () => {
    await assert.rejects(() => TOOL.case_for_alert.handler({ alertId: 'a1' }), /at most 5 case types/);
  });
});

test('case_create retries an alert that no case holds yet, and reports one it still cannot match', async () => {
  let adds = 0;
  await withMock((url, body) => {
    const s = body?.query || '';
    if (s.includes('createCase')) return { data: { createCase: { id: 'c1', publicId: 'P1', processingState: 'CREATING_FROM_ALERTS' } } };
    if (s.includes('addAlertsToCase')) { adds++; return { data: { addAlertsToCase: { success: true, errors: [] } } }; }
    if (s.includes('caseForAlert')) return { data: { caseForAlert: null } };
    return { data: { case: { ...CASE, processingState: 'READY', alertIds: adds ? ['a1'] : [] } } };
  }, async () => {
    const out = JSON.parse(await TOOL.case_create.handler({ name: 'n', alertIds: ['a1', 'a2'], severity: 'LOW', scopeIds: ['8'], scopeType: 'SITE' }));
    assert.deepEqual(out.case.alertIds, ['a1']);
    assert.deepEqual(out.notAdded, [{ alertId: 'a2', inCase: null }]);
    assert.ok(out.addRetries >= 1);
    assert.match(out.notAddedNote, /case_alerts/);
  });
});

// ─── Code review follow-ups ──────────────────────────────────────────────────

test('graphqlOperation: a # inside a string does not hide a mutation; keywords inside strings do not count', () => {
  assert.equal(access.graphqlOperation('query { cases(name: "#") { id } } mutation { updateCase(caseId:"x") }'), 'mutation');
  assert.equal(access.postIsRead('/web/api/v2.1/cases/graphql', { query: 'query { a(x:"#") } mutation { b }' }), false);
  assert.equal(access.graphqlOperation('query { cases(filters:[{fieldId:"name", match:{value:["mutation"]}}]) { id } }'), 'query');
  assert.equal(access.graphqlOperation('query { a(x: """block # mutation \\""" still string""") }'), 'query');
  assert.equal(access.graphqlOperation('query { a } # mutation in a comment'), 'query');
  assert.equal(access.graphqlOperation('query { a(x: "unterminated) }'), null);
  assert.equal(access.graphqlOperation('{ a } mutation b { c }'), 'mutation');
});

test('case_list with the word mutation in a name filter is still a read', async () => {
  await withMock(() => ({ data: { cases: { totalCount: 0, pageInfo: {}, edges: [] } } }), async (calls) => {
    const out = JSON.parse(await TOOL.case_list.handler({ name: 'mutation subscription', scopeIds: ['7'] }));
    assert.equal(out.totalCount, 0);
    assert.match(calls[0].body.query, /^query/);
  });
});

test('scopeIds must be a non-empty array; scopeType alone is refused', () => {
  assert.throws(() => lib.scopeFromArgs('12345', 'SITE'), /non-empty array/);
  assert.throws(() => lib.scopeFromArgs([], 'SITE'), /non-empty array/);
  assert.throws(() => lib.scopeFromArgs(undefined, 'SITE'), /without scopeIds/);
  assert.equal(lib.scopeFromArgs(undefined, undefined), undefined);
  assert.deepEqual(lib.scopeFromArgs(['1'], 'SITE'), { scopeIds: ['1'], scopeType: 'SITE' });
});

test('case_task update fails when the API ignores an assignee or due date change', async () => {
  await withMock((url, body) => {
    const s = body?.query || '';
    if (s.includes('listTasksForCase')) return { data: { listTasksForCase: [{ id: 't1', name: 'n', status: 'TO_DO', dueDate: null, taskIndex: 1, assignee: null }] } };
    return { data: { updateTask: { task: { id: 't1', name: 'n', status: 'TO_DO', taskIndex: 1, dueDate: null, assignee: null }, errors: [] } } };
  }, async () => {
    await assert.rejects(() => TOOL.case_task.handler({ action: 'update', caseId: 'c1', taskId: 't1', assigneeUserId: '42' }), /did not apply/);
    await assert.rejects(() => TOOL.case_task.handler({ action: 'update', caseId: 'c1', taskId: 't1', dueDate: '2026-12-01' }), /did not apply/);
  });
});

test('rule reads cover the full expression depth the builder accepts', () => {
  assert.equal((lib.RULE_EXPRESSION_FIELDS.match(/expressions \{/g) || []).length, 8);
});
