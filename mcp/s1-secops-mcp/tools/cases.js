/**
 * Case Management tools (1.6.4), over POST /web/api/v2.1/cases/graphql (lib/cases.js).
 *
 *   case_list         cases: filter, sort and page
 *   case_get          case(id) with its notes, tasks, IOCs and messages; optionally its alerts
 *   case_for_alert    the case an alert belongs to, or null
 *   case_metadata     case fields and enum values, case type options, file upload limits
 *   case_rules        creation rules: list, one rule, inheritance state, property metadata
 *   case_create       a case from alerts, waits until it is ready
 *   case_update       name, status, severity, verdict, assignee and case types of one case
 *   case_triage       status, severity, verdict or assignee of one or more cases
 *   case_add_note     a note on a case
 *   case_task         create, update or delete a case task
 *   case_iocs         link or unlink Threat Intelligence IOCs
 *   case_post_message a message (or reply) in the case's collaboration space
 *   case_alerts       add alerts to a case or remove them
 *   case_rule_apply   create, update, enable, disable, rank or delete a creation rule
 *   case_rules_scope  link an account to, or unlink it from, inherited creation rules
 *
 * Writes that change a case, a task, its alerts, its IOCs or a rule's state re-read the result and fail
 * unless it shows the change; messages and created tasks and rules return what the API created. Case state and
 * alert state are independent: no case tool changes an alert's status, verdict or assignee
 * unless case_triage is called with alsoAlerts: true.
 */

import {
  casesGraphql, payloadErrors, lit, args, en, checkId, checkEnum, scopeLit, idFilter, sleep,
  scopeFromArgs, allAccountsScope, singleAccountScope, getCase, caseScope, caseForAlert,
  resolveUserId, textToHtml, sameHtml, normaliseCaseTypes, sameCaseTypes, buildExpression, plainExpression,
  expressionFromRead, scopeForAlerts, CASE_LIST_FIELDS, CASE_DETAIL_FIELDS, RULE_DETAIL_FIELDS,
  RULE_LIST_FIELDS, CASE_STATUSES, CASE_SEVERITIES, TASK_STATUSES, MAX_CASE_TYPES,
} from '../lib/cases.js';
import {
  uamListAlerts, uamSetStatus, uamSetVerdict, uamAssignAlert, apiPost, UAM_ANALYST_VERDICTS,
} from '../lib/s1.js';

const json = (o) => JSON.stringify(o, null, 2);

const SCOPE_PROPS = {
  scopeIds: { type: 'array', items: { type: 'string' }, description: 'Optional. Account or site ids.' },
  scopeType: { type: 'string', enum: ['ACCOUNT', 'SITE'], description: 'Optional. Type of scopeIds (default ACCOUNT).' },
};
const ALERT_STATE_NOTE = 'Case state and alert state are independent: this does not change the status, verdict or assignee of the alerts in the case.';
const MAX_ALERT_WRITES = 200;
const MAX_RETRY_LOOKUPS = 50;   // retry unmatched alerts only for small batches
const MAX_LOOKUPS = 100;        // caseForAlert lookups reported per call

// ─── Reads ───────────────────────────────────────────────────────────────────

function listFilters(a) {
  const f = [];
  const many = (v) => (Array.isArray(v) ? v : v != null ? [v] : []);
  let status = many(a.status);
  if (!status.length && a.includeClosed === true) status = [...CASE_STATUSES];
  if (status.length) f.push({ fieldId: 'status', stringIn: { values: status.map(s => checkEnum(s, CASE_STATUSES, 'status').v) } });
  const sev = many(a.severity);
  if (sev.length) f.push({ fieldId: 'severity', stringIn: { values: sev.map(s => checkEnum(s, CASE_SEVERITIES, 'severity').v) } });
  if (a.analystVerdict) f.push({ fieldId: 'analystVerdict', stringEqual: { value: String(a.analystVerdict) } });
  if (a.unassigned === true) f.push({ fieldId: 'assigneeUserId', longEqual: { value: null } });
  else if (a.assigneeUserId) f.push({ fieldId: 'assigneeUserId', longEqual: { value: checkId(String(a.assigneeUserId), 'assigneeUserId') } });
  const types = many(a.caseTypes);
  if (types.length) f.push({ fieldId: 'caseTypes', stringIn: { values: types.map(String) } });
  if (a.creationRuleId) f.push({ fieldId: 'creationRuleId', stringEqual: { value: checkId(a.creationRuleId, 'creationRuleId') } });
  if (a.createdAfter || a.createdBefore) {
    const ms = (v, w) => { const n = typeof v === 'number' ? v : Date.parse(v); if (!Number.isFinite(n)) throw new Error(`${w} must be ISO-8601 or epoch ms`); return n; };
    f.push({ fieldId: 'createdAt', dateTimeRange: { start: a.createdAfter ? ms(a.createdAfter, 'createdAfter') : undefined, end: a.createdBefore ? ms(a.createdBefore, 'createdBefore') : undefined } });
  }
  if (a.name) f.push({ fieldId: 'name', match: { value: [String(a.name)] } });
  if (Array.isArray(a.filters)) f.push(...a.filters);
  return f;
}

/** Selection set for a FilterInput passed through verbatim: only plain data, enum-free. */
function rawFilterSafe(filters) {
  for (const x of filters) if (!x || typeof x !== 'object' || typeof x.fieldId !== 'string') throw new Error('each raw filter needs a fieldId');
}

async function caseList(a = {}) {
  const scope = scopeFromArgs(a.scopeIds, a.scopeType) || await allAccountsScope();
  const filters = listFilters(a);
  rawFilterSafe(filters);
  const first = Math.min(Math.max(Number(a.first) || 25, 1), 200);
  const sortBy = a.sortBy || 'createdAt';
  if (!/^[A-Za-z][A-Za-z0-9_]*$/.test(sortBy)) throw new Error('sortBy must be a case field id');
  const order = (a.sortOrder || 'DESC').toUpperCase() === 'ASC' ? 'ASC' : 'DESC';
  const doc = `query { cases(${args({
    filters: filters.length ? filters : undefined,
    scope: scopeLit(scope),
    sort: { by: sortBy, order: en(order) },
    first,
    after: a.after || undefined,
  })}) { totalCount pageInfo { hasNextPage endCursor } edges { node { ${CASE_LIST_FIELDS} } } } }`;
  const d = await casesGraphql(doc, { readOnly: true });
  const c = d.cases || {};
  return {
    totalCount: c.totalCount ?? null,
    returned: (c.edges || []).length,
    hasNextPage: !!c.pageInfo?.hasNextPage,
    endCursor: c.pageInfo?.endCursor || null,
    scope,
    cases: (c.edges || []).map(e => e.node),
  };
}

async function caseContents(caseId, n = 20) {
  const id = checkId(caseId, 'caseId');
  const d = await casesGraphql(`query {
    listNotesForCase(${args({ caseId: id, first: n })}) { edges { node { id author { id fullName } createdAt contentPlainText contentHtml } } pageInfo { hasNextPage } }
    listTasksForCase(${args({ caseId: id })}) { id name status dueDate taskIndex assignee { id fullName } }
    listIoCsForCase(${args({ caseId: id })}) { ioCId type value linkedAt }
    collaborationSpaceMessages(${args({ caseId: id, first: n })}) { edges { node { id author { id fullName } contentHtml createdAt replyCount } } pageInfo { hasNextPage } }
  }`, { readOnly: true });
  return {
    notes: (d.listNotesForCase?.edges || []).map(e => e.node),
    notesTruncated: !!d.listNotesForCase?.pageInfo?.hasNextPage,
    tasks: d.listTasksForCase || [],
    iocs: d.listIoCsForCase || [],
    messages: (d.collaborationSpaceMessages?.edges || []).map(e => e.node),
    messagesTruncated: !!d.collaborationSpaceMessages?.pageInfo?.hasNextPage,
  };
}

async function alertsByIds(ids) {
  if (!ids.length) return [];
  const out = [];
  for (let i = 0; i < ids.length; i += 100) {
    const chunk = ids.slice(i, i + 100);
    const r = await uamListAlerts({ first: chunk.length, filters: [{ fieldId: 'id', stringIn: { values: chunk } }] });
    out.push(...(r.alerts || r.edges || r.items || []));
  }
  return out;
}

// ─── Write helpers ───────────────────────────────────────────────────────────

async function verify(label, read, ok, attempts = 8, delay = 750) {
  let last;
  for (let i = 0; i < attempts; i++) {
    if (i) await sleep(delay);
    last = await read();
    if (ok(last)) return last;
  }
  throw new Error(`${label}: the change was sent but a re-read does not show it yet. Re-check with case_get. Last read: ${JSON.stringify(last).slice(0, 600)}`);
}

const CASE_STATE_FIELDS = 'id publicId name status severity analystVerdict caseTypes assignee { id fullName email } scope { account { id } site { id } } alertIds';

async function waitReady(caseId, attempts = 20) {
  let c;
  for (let i = 0; i < attempts; i++) {
    c = await getCase(caseId, 'id publicId name status severity processingState alertIds caseTypes scope { account { id name } site { id name } }');
    if (c.processingState === 'READY') return c;
    await sleep(1000);
  }
  return c;
}

/**
 * Alerts that are in no case after a create or add are retried: an alert ingested seconds earlier
 * can be visible to UAM before the case service can match it (observed: the case opened empty).
 * Alerts held by another case are not retried; they stay where they are.
 */
async function settleAlerts(caseId, ids, { attempts = 4, delayMs = Number(process.env.S1_CASE_ALERT_RETRY_MS) || 5000 } = {}) {
  let c = await waitReady(caseId, 10);
  let missing = ids.filter(x => !(c.alertIds || []).includes(x));
  let retried = 0;
  // Bounded: per-alert lookups are one request each, so large batches are reported, not retried.
  for (let i = 0; i < attempts && missing.length && missing.length <= MAX_RETRY_LOOKUPS; i++) {
    const free = (await otherCases(missing)).filter(o => !o.inCase).map(o => o.alertId);
    if (!free.length) break;
    await sleep(delayMs);
    const d = await casesGraphql(`mutation { addAlertsToCase(${args({ caseId, alertIds: free })}) { success errors { field errorType message } } }`);
    payloadErrors('addAlertsToCase', d.addAlertsToCase);
    retried++;
    await sleep(Math.min(delayMs, 1500));
    c = await waitReady(caseId, 10);
    missing = ids.filter(x => !(c.alertIds || []).includes(x));
  }
  return { c, missing, retried };
}

async function otherCases(alertIds) {
  const out = [];
  for (const a of alertIds.slice(0, MAX_LOOKUPS)) {
    const c = await caseForAlert(a).catch(() => null);
    out.push({ alertId: a, inCase: c ? { id: c.id, publicId: c.publicId, name: c.name } : null });
  }
  return out;
}

// ─── Tools ───────────────────────────────────────────────────────────────────

export const tools = [
  {
    name: 'case_list',
    description: 'List Case Management cases with filters, sort and cursor paging. Returns list fields (id, publicId, name, status, severity, analystVerdict, caseTypes, assignee, creationRule, mitreTactics, scope, assetCount, createdAt). Alert ids, counts and processing state are only on case_get. Without a status filter the API leaves CLOSED cases out: pass includeClosed: true, or status including CLOSED, to see them. name matches words in the case name. Default scope: every account the token can see; pass scopeIds for one account or site.',
    inputSchema: {
      type: 'object',
      properties: {
        status: { type: 'array', items: { type: 'string', enum: [...CASE_STATUSES] }, description: 'Statuses to include. Default: every status except CLOSED.' },
        includeClosed: { type: 'boolean', description: 'Include CLOSED cases when no status is given (default false).' },
        severity: { type: 'array', items: { type: 'string', enum: [...CASE_SEVERITIES] }, description: 'Severities to include.' },
        analystVerdict: { type: 'string', description: 'One analyst verdict, e.g. TRUE_POSITIVE_MALWARE.' },
        assigneeUserId: { type: 'string', description: 'Console user id of the assignee.' },
        unassigned: { type: 'boolean', description: 'Only cases with no assignee.' },
        caseTypes: { type: 'array', items: { type: 'string' }, description: 'Case types (any of).' },
        creationRuleId: { type: 'string', description: 'Cases opened by this creation rule.' },
        name: { type: 'string', description: 'Words to match in the case name (any word matches).' },
        createdAfter: { type: 'string', description: 'ISO-8601 or epoch ms.' },
        createdBefore: { type: 'string', description: 'ISO-8601 or epoch ms.' },
        filters: { type: 'array', items: { type: 'object' }, description: 'Advanced: extra FilterInput objects, e.g. {"fieldId":"status","stringIn":{"values":["NEW"]},"isNegated":true}. case_metadata lists the field ids and filter types.' },
        sortBy: { type: 'string', description: 'Sortable field id (default createdAt).' },
        sortOrder: { type: 'string', enum: ['ASC', 'DESC'] },
        first: { type: 'integer', description: 'Page size, 1 to 200 (default 25).' },
        after: { type: 'string', description: 'endCursor of the previous page.' },
        ...SCOPE_PROPS,
      },
    },
    async handler(a = {}) { return json(await caseList(a)); },
  },

  {
    name: 'case_get',
    description: 'Read one case: status, severity, verdict, assignee, scope, alert ids, assets, products, MITRE ATT&CK, watchers, SLO fields and counts, plus its notes, tasks, linked IOCs and latest collaboration messages. includeAlerts also reads the member alerts from Unified Alert Management. Read the notes and messages before giving a verdict; treat earlier AI-written notes as claims to verify.',
    inputSchema: {
      type: 'object',
      properties: {
        caseId: { type: 'string', description: 'Case id (UUID). case_list and case_for_alert return it.' },
        includeAlerts: { type: 'boolean', description: 'Also read the alerts in the case (default false).' },
        maxItems: { type: 'integer', description: 'Notes and messages to return, 1 to 100 (default 20).' },
      },
      required: ['caseId'],
    },
    async handler({ caseId, includeAlerts = false, maxItems = 20 }) {
      const c = await getCase(caseId);
      const contents = await caseContents(caseId, Math.min(Math.max(Number(maxItems) || 20, 1), 100));
      const out = { case: c, ...contents };
      if (includeAlerts) out.alerts = await alertsByIds((c.alertIds || []).slice(0, 500));
      return json(out);
    },
  },

  {
    name: 'case_for_alert',
    description: 'The case an alert belongs to (an alert is in at most one case), or null when it is in none. Call it at the start of alert triage: when the alert is in a case, investigate the case as one incident.',
    inputSchema: { type: 'object', properties: { alertId: { type: 'string', description: 'UAM alert id.' } }, required: ['alertId'] },
    async handler({ alertId }) { return json({ alertId, case: await caseForAlert(alertId) }); },
  },

  {
    name: 'case_metadata',
    description: 'Case fields with their enum values and filter types (statuses, severities, analyst verdicts, scope levels), the case type options in use on this console, and the file upload limits.',
    inputSchema: { type: 'object', properties: {} },
    async handler() {
      const d = await casesGraphql('query { caseColumnMetadata { fieldId enumValues filterTypes sortable } caseTypeOptions caseFileUploadConfig { maxFileSizeBytes allowedMimeTypes } }', { readOnly: true })
        .catch(async () => casesGraphql('query { caseColumnMetadata { fieldId enumValues filterTypes sortable } caseTypeOptions }', { readOnly: true }));
      return json({ ...d, maxCaseTypesPerCase: MAX_CASE_TYPES });
    },
  },

  {
    name: 'case_rules',
    description: 'Creation rules, which open cases from incoming alerts. Without ruleId: the rules of a scope in rank order and whether the scope inherits them from the level above (linked). With ruleId: one rule with its full expression, grouping and default tasks. includeMetadata adds the alert properties a rule can match (types, values, operations) and the grouping properties and limits.',
    inputSchema: {
      type: 'object',
      properties: {
        ruleId: { type: 'string' },
        enabledOnly: { type: 'boolean' },
        includeMetadata: { type: 'boolean' },
        first: { type: 'integer', description: 'Page size, 1 to 200 (default 100).' },
        ...SCOPE_PROPS,
      },
    },
    async handler(a = {}) {
      const scope = await singleAccountScope(scopeFromArgs(a.scopeIds, a.scopeType), 'case_rules');
      const sl = lit(scopeLit(scope));
      const parts = [`creationRulesScopeConfig(scope: ${sl}) { linked }`];
      if (a.ruleId) parts.push(`creationRule(${args({ id: checkId(a.ruleId, 'ruleId') })}, scope: ${sl}) { ${RULE_DETAIL_FIELDS} }`);
      else {
        parts.push(`creationRules(${args({
          filters: a.enabledOnly ? [{ fieldId: 'enabled', booleanEqual: { value: true } }] : undefined,
          first: Math.min(Math.max(Number(a.first) || 100, 1), 200),
        })}, scope: ${sl}, sort: { by: "rank", order: ASC }) { totalCount edges { node { ${RULE_LIST_FIELDS} } } }`);
      }
      if (a.includeMetadata) {
        parts.push('creationRulePropertyMetadata { propertyName propertyType values supportedOperations valueConstraints { requirement } }');
        parts.push('getGroupingMetadata { availableProperties maxGroupingWindowMinutes maxLookbackMinutes }');
      }
      const d = await casesGraphql(`query { ${parts.join(' ')} }`, { readOnly: true });
      const out = { scope, linked: d.creationRulesScopeConfig?.linked ?? null };
      if (a.ruleId) out.rule = d.creationRule || null;
      else { out.totalCount = d.creationRules?.totalCount ?? null; out.rules = (d.creationRules?.edges || []).map(e => e.node); }
      if (a.includeMetadata) { out.properties = d.creationRulePropertyMetadata; out.grouping = d.getGroupingMetadata; }
      if (out.linked) out.note = 'This scope inherits its creation rules (linked: true): they cannot be changed here until it is unlinked with case_rules_scope.';
      return json(out);
    },
  },

  // ─── Writes ───────────────────────────────────────────────────────────────

  {
    name: 'case_create',
    description: `Create a case from one or more UAM alerts and wait until it is ready. An alert can be in only one case: alerts already in another case stay there, and the result lists them under notAdded with the case that holds them. An alert ingested moments ago may not be matchable yet; the tool retries those for about 20 seconds before listing them. Default scope: the first alert's site. ${ALERT_STATE_NOTE}`,
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'Case name.' },
        alertIds: { type: 'array', items: { type: 'string' }, description: 'UAM alert ids to put in the case (1 to 500).' },
        severity: { type: 'string', enum: [...CASE_SEVERITIES] },
        assigneeUserId: { type: 'string' },
        assigneeEmail: { type: 'string' },
        caseTypes: { type: 'array', items: { type: 'string' }, description: `Up to ${MAX_CASE_TYPES}; case_metadata lists the options in use.` },
        ...SCOPE_PROPS,
      },
      required: ['name', 'alertIds', 'severity'],
    },
    async handler(a) {
      if (!a.name || !String(a.name).trim()) throw new Error('name is required');
      const ids = (a.alertIds || []).map(x => checkId(x, 'alertId'));
      if (!ids.length || ids.length > 500) throw new Error('alertIds must hold 1 to 500 alert ids');
      const scope = scopeFromArgs(a.scopeIds, a.scopeType) || await scopeForAlerts(ids);
      const assignTo = await resolveUserId({ userId: a.assigneeUserId, email: a.assigneeEmail });
      const d = await casesGraphql(`mutation { createCase(${args({
        scope: scopeLit(scope),
        name: String(a.name).trim(),
        severity: checkEnum(a.severity, CASE_SEVERITIES, 'severity'),
        assignTo,
        caseTypes: normaliseCaseTypes(a.caseTypes),
        alertFilterSelection: { alertFilters: idFilter(ids) },
      })}) { id publicId processingState } }`);
      const created = d.createCase;
      if (!created?.id) throw new Error('createCase returned no case id');
      const { c, missing, retried } = await settleAlerts(created.id, ids);
      const notAdded = missing.length ? await otherCases(missing) : [];
      return json({
        created: true, caseId: c.id, publicId: c.publicId, processingState: c.processingState, scope,
        case: c, notAdded, notAddedCount: missing.length, addRetries: retried,
        ...(notAdded.some(o => !o.inCase) ? { notAddedNote: 'Alerts in no case could not be matched yet (an alert ingested moments ago can take a little longer). Add them later with case_alerts.' } : {}),
        note: ALERT_STATE_NOTE,
      });
    },
  },

  {
    name: 'case_update',
    description: `Change one case's name, status, severity, analyst verdict, assignee or case types. Reads the case first and sends every field, so a field you leave out keeps its value (the API replaces the whole case). Closing (status CLOSED) needs a reason: use case_triage with closingReason. Verified by re-reading. ${ALERT_STATE_NOTE}`,
    inputSchema: {
      type: 'object',
      properties: {
        caseId: { type: 'string' },
        name: { type: 'string' },
        status: { type: 'string', enum: ['NEW', 'IN_PROGRESS', 'RESOLVED'] },
        severity: { type: 'string', enum: [...CASE_SEVERITIES] },
        analystVerdict: { type: 'string', description: 'e.g. TRUE_POSITIVE_MALWARE, FALSE_POSITIVE_BENIGN, UNDEFINED. case_metadata lists them.' },
        assigneeUserId: { type: 'string' },
        assigneeEmail: { type: 'string' },
        unassign: { type: 'boolean' },
        caseTypes: { type: 'array', items: { type: 'string' }, description: `Replaces the list; up to ${MAX_CASE_TYPES}.` },
      },
      required: ['caseId'],
    },
    async handler(a) {
      if (a.status === 'CLOSED') throw new Error('case_update cannot close a case: use case_triage with status CLOSED and closingReason.');
      const before = await getCase(a.caseId, CASE_STATE_FIELDS);
      if (before.status === 'CLOSED' && !a.status) throw new Error(`case ${a.caseId} is CLOSED: pass a status (NEW, IN_PROGRESS or RESOLVED) to reopen it with this update.`);
      let assignTo = before.assignee?.id ? String(before.assignee.id) : undefined;
      if (a.unassign) assignTo = undefined;
      else if (a.assigneeUserId || a.assigneeEmail) assignTo = await resolveUserId({ userId: a.assigneeUserId, email: a.assigneeEmail });
      const want = {
        name: a.name != null ? String(a.name).trim() : before.name,
        status: a.status || before.status,
        severity: a.severity || before.severity,
        analystVerdict: a.analystVerdict || before.analystVerdict || 'UNDEFINED',
        caseTypes: a.caseTypes !== undefined ? normaliseCaseTypes(a.caseTypes) : (before.caseTypes || []),
      };
      if (!want.name) throw new Error('name cannot be empty');
      const d = await casesGraphql(`mutation { updateCase(${args({
        caseId: before.id, name: want.name,
        status: checkEnum(want.status, CASE_STATUSES, 'status'),
        severity: checkEnum(want.severity, CASE_SEVERITIES, 'severity'),
        analystVerdict: en(want.analystVerdict),
        assignTo, caseTypes: want.caseTypes,
      })}) }`);
      if (d.updateCase !== true) throw new Error(`updateCase returned ${JSON.stringify(d.updateCase)}`);
      const after = await verify('case_update', () => getCase(before.id, CASE_STATE_FIELDS), (c) =>
        c.name === want.name && c.status === want.status && c.severity === want.severity
        && c.analystVerdict === want.analystVerdict && sameCaseTypes(c.caseTypes, want.caseTypes)
        && String(c.assignee?.id ?? '') === String(assignTo ?? ''));
      return json({ updated: true, verified: true, before, after, note: ALERT_STATE_NOTE });
    },
  },

  {
    name: 'case_triage',
    description: 'Set the status, severity, analyst verdict or assignee of one or more cases in one call (each field is a separate update, verified by re-reading every case). status CLOSED requires closingReason (and optionally closingNote). alsoAlerts: true also applies the status, verdict and assignee to every alert in each case (CLOSED maps to the alert status RESOLVED; severity is not applied to alerts); leave it off unless the user asked for the alerts to change too.',
    inputSchema: {
      type: 'object',
      properties: {
        caseIds: { type: 'array', items: { type: 'string' }, description: '1 to 100 case ids.' },
        status: { type: 'string', enum: [...CASE_STATUSES] },
        closingReason: { type: 'string', description: 'Required for status CLOSED.' },
        closingNote: { type: 'string' },
        severity: { type: 'string', enum: [...CASE_SEVERITIES] },
        analystVerdict: { type: 'string' },
        assigneeUserId: { type: 'string' },
        assigneeEmail: { type: 'string' },
        alsoAlerts: { type: 'boolean', description: 'Also update the member alerts (default false).' },
      },
      required: ['caseIds'],
    },
    async handler(a) {
      const ids = [...new Set((a.caseIds || []).map(x => checkId(x, 'caseId')))];
      if (!ids.length || ids.length > 100) throw new Error('caseIds must hold 1 to 100 case ids');
      if (!a.status && !a.severity && !a.analystVerdict && !a.assigneeUserId && !a.assigneeEmail) throw new Error('pass at least one of status, severity, analystVerdict, assigneeUserId or assigneeEmail');
      if (a.status === 'CLOSED' && !String(a.closingReason || '').trim()) throw new Error('status CLOSED requires closingReason');
      const userId = await resolveUserId({ userId: a.assigneeUserId, email: a.assigneeEmail });

      // Group the cases by account: each bulk update is sent with the account of its cases.
      const before = {};
      const byAccount = {};
      for (const id of ids) {
        const c = await getCase(id, CASE_STATE_FIELDS);
        before[id] = c;
        const acct = String(c.scope?.account?.id || '');
        if (!acct) throw new Error(`case ${id}: the API did not report its account`);
        (byAccount[acct] ||= []).push(id);
      }
      const ops = [];
      if (a.status) ops.push(['updateCaseStatus', { status: checkEnum(a.status, CASE_STATUSES, 'status'), closingInfo: a.status === 'CLOSED' ? { reason: String(a.closingReason).trim(), note: a.closingNote ? String(a.closingNote) : undefined } : undefined }, c => c.status === a.status]);
      if (a.severity) ops.push(['updateCaseSeverity', { severity: checkEnum(a.severity, CASE_SEVERITIES, 'severity') }, c => c.severity === a.severity]);
      if (a.analystVerdict) ops.push(['updateCaseAnalystVerdict', { analystVerdict: en(a.analystVerdict) }, c => c.analystVerdict === a.analystVerdict]);
      if (userId) ops.push(['caseAssignment', { userId }, c => String(c.assignee?.id ?? '') === userId]);

      const updated = {};
      for (const [acct, group] of Object.entries(byAccount)) {
        for (const [m, extra] of ops) {
          const d = await casesGraphql(`mutation { ${m}(${args({ filter: idFilter(group), scope: scopeLit({ scopeIds: [acct], scopeType: 'ACCOUNT' }), ...extra })}) { updatedCaseIds } }`);
          updated[m] = [...(updated[m] || []), ...(d[m]?.updatedCaseIds || [])];
        }
      }
      const after = {};
      for (const id of ids) {
        after[id] = await verify(`case_triage case ${id}`, () => getCase(id, CASE_STATE_FIELDS), (c) => ops.every(([, , ok]) => ok(c)));
      }
      const result = { verified: true, updated, cases: ids.map(id => ({ caseId: id, publicId: after[id].publicId, before: pick(before[id]), after: pick(after[id]) })) };

      if (a.alsoAlerts) {
        const alertStatus = a.status === 'CLOSED' ? 'RESOLVED' : a.status;
        const verdictOk = a.analystVerdict && UAM_ANALYST_VERDICTS.includes(a.analystVerdict);
        const alertResults = [];
        let n = 0;
        for (const id of ids) {
          for (const alertId of after[id].alertIds || []) {
            if (++n > MAX_ALERT_WRITES) { alertResults.push({ alertId, skipped: `more than ${MAX_ALERT_WRITES} alerts; update the rest with uam_set_status / uam_set_verdict` }); continue; }
            const r = { caseId: id, alertId };
            const step = async (k, fn) => { try { const x = await fn(); r[k] = x.outcome; } catch (e) { r[k] = `error: ${e.message}`; } };
            if (alertStatus) await step('status', () => uamSetStatus(alertId, alertStatus));
            if (a.analystVerdict) { if (verdictOk) await step('verdict', () => uamSetVerdict(alertId, a.analystVerdict)); else r.verdict = 'skipped: not an alert verdict'; }
            if (userId) await step('assignee', () => uamAssignAlert(alertId, { userId }));
            alertResults.push(r);
          }
        }
        result.alerts = alertResults;
        if (a.severity) result.alertSeverityNote = 'Severity was set on the cases only; alerts keep their own severity.';
      } else {
        result.note = ALERT_STATE_NOTE;
      }
      return json(result);
    },
  },

  {
    name: 'case_add_note',
    description: 'Add a note to a case. Plain text is sent as escaped HTML (blank lines become paragraphs). Notes are visible to every analyst on the case; cite the evidence and never paste secrets. Verified by re-reading the case notes.',
    inputSchema: { type: 'object', properties: { caseId: { type: 'string' }, note: { type: 'string', description: 'Note text, up to 20,000 characters.' } }, required: ['caseId', 'note'] },
    async handler({ caseId, note }) {
      const id = checkId(caseId, 'caseId');
      const text = String(note || '');
      if (!text.trim()) throw new Error('note is empty');
      if (text.length > 20000) throw new Error('note is longer than 20,000 characters');
      const html = textToHtml(text);
      const d = await casesGraphql(`mutation { createNote(${args({ caseId: id, contentPlainText: text, contentHtml: html })}) }`);
      if (d.createNote !== true) throw new Error(`createNote returned ${JSON.stringify(d.createNote)}`);
      // The API stores contentHtml as sent and derives contentPlainText from it (newlines collapse,
      // escaped angle-bracket text is dropped), so the re-read is matched on the HTML.
      const notes = await verify('case_add_note', async () => (await caseContents(id, 20)).notes,
        (ns) => ns.some(n => sameHtml(n.contentHtml, html)));
      const n = notes.find(x => sameHtml(x.contentHtml, html));
      return json({ added: true, verified: true, caseId: id, noteId: n?.id || null, createdAt: n?.createdAt || null });
    },
  },

  {
    name: 'case_task',
    description: 'Create, update or delete a case task. update reads the task first and sends every field, so a field you leave out keeps its value. Task status values: TO_DO, DONE.',
    inputSchema: {
      type: 'object',
      properties: {
        action: { type: 'string', enum: ['create', 'update', 'delete'] },
        caseId: { type: 'string', description: 'Required for create and update.' },
        taskId: { type: 'string', description: 'Required for update and delete.' },
        name: { type: 'string' },
        status: { type: 'string', enum: [...TASK_STATUSES] },
        assigneeUserId: { type: 'string' },
        assigneeEmail: { type: 'string' },
        dueDate: { type: 'string', description: 'YYYY-MM-DD.' },
      },
      required: ['action'],
    },
    async handler(a) {
      const due = a.dueDate ? String(a.dueDate) : undefined;
      if (due && !/^\d{4}-\d{2}-\d{2}$/.test(due)) throw new Error('dueDate must be YYYY-MM-DD');
      const assignee = await resolveUserId({ userId: a.assigneeUserId, email: a.assigneeEmail });
      if (a.action === 'create') {
        const caseId = checkId(a.caseId, 'caseId');
        if (!a.name || !String(a.name).trim()) throw new Error('name is required');
        const d = await casesGraphql(`mutation { createTask(${args({ caseId, name: String(a.name).trim(), assigneeUserId: assignee, dueDate: due })}) { task { id name status taskIndex dueDate } errors { field errorType message } } }`);
        payloadErrors('createTask', d.createTask);
        let task = d.createTask?.task;
        if (a.status === 'DONE' && task?.id) {
          const u = await casesGraphql(`mutation { updateTask(${args({ taskId: task.id, name: task.name, assigneeUserId: assignee, dueDate: due, taskIndex: Number(task.taskIndex) + 0.0, status: en('DONE') })}) { task { id name status taskIndex dueDate } errors { field errorType message } } }`);
          payloadErrors('updateTask', u.updateTask);
          task = u.updateTask?.task || task;
        }
        return json({ created: true, caseId, task });
      }
      if (a.action === 'update') {
        const caseId = checkId(a.caseId, 'caseId');
        const taskId = checkId(a.taskId, 'taskId');
        const d0 = await casesGraphql(`query { listTasksForCase(${args({ caseId })}) { id name status dueDate taskIndex assignee { id } } }`, { readOnly: true });
        const cur = (d0.listTasksForCase || []).find(t => t.id === taskId);
        if (!cur) throw new Error(`task ${taskId} is not on case ${caseId}`);
        const want = {
          name: a.name != null ? String(a.name).trim() : cur.name,
          status: a.status ? checkEnum(a.status, TASK_STATUSES, 'status').v : cur.status,
          assigneeUserId: assignee ?? (cur.assignee?.id ? String(cur.assignee.id) : undefined),
          dueDate: due ?? (cur.dueDate ? String(cur.dueDate).slice(0, 10) : undefined),
        };
        const d = await casesGraphql(`mutation { updateTask(${args({ taskId, name: want.name, assigneeUserId: want.assigneeUserId, dueDate: want.dueDate, taskIndex: Number(cur.taskIndex), status: en(want.status) })}) { task { id name status taskIndex dueDate assignee { id fullName } } errors { field errorType message } } }`);
        payloadErrors('updateTask', d.updateTask);
        const t = d.updateTask?.task;
        const day = (v) => (v ? String(v).slice(0, 10) : null);
        if (!t || t.status !== want.status || t.name !== want.name
          || day(t.dueDate) !== day(want.dueDate)
          || String(t.assignee?.id ?? '') !== String(want.assigneeUserId ?? '')) {
          throw new Error(`updateTask did not apply: ${JSON.stringify(t)}`);
        }
        return json({ updated: true, verified: true, before: cur, after: t });
      }
      if (a.action === 'delete') {
        const taskId = checkId(a.taskId, 'taskId');
        const d = await casesGraphql(`mutation { deleteTask(${args({ taskId })}) }`);
        if (d.deleteTask !== true) throw new Error(`deleteTask returned ${JSON.stringify(d.deleteTask)}`);
        return json({ deleted: true, taskId });
      }
      throw new Error('action must be create, update or delete');
    },
  },

  {
    name: 'case_iocs',
    description: 'Link Threat Intelligence IOCs to a case, or unlink them. link takes iocs as {ioCId, type, value}; an entry without ioCId is first created in Threat Intelligence at the case\'s account (createMissing: true, source "Case <publicId>"), which needs a token that can write IOCs at that account. Linking is idempotent. Verified by re-reading the case IOCs.',
    inputSchema: {
      type: 'object',
      properties: {
        action: { type: 'string', enum: ['link', 'unlink'] },
        caseId: { type: 'string' },
        iocs: { type: 'array', items: { type: 'object', properties: { ioCId: { type: 'string' }, type: { type: 'string', description: 'IPV4, IPV6, DNS, URL, SHA1, SHA256 or MD5.' }, value: { type: 'string' } } }, description: 'For link.' },
        ioCIds: { type: 'array', items: { type: 'string' }, description: 'For unlink.' },
        createMissing: { type: 'boolean', description: 'Create IOCs that have no ioCId (default false).' },
        validDays: { type: 'integer', description: 'Validity of created IOCs, 1 to 365 days (default 30).' },
      },
      required: ['action', 'caseId'],
    },
    async handler(a) {
      const caseId = checkId(a.caseId, 'caseId');
      if (a.action === 'unlink') {
        const ids = (a.ioCIds || []).map(x => checkId(x, 'ioCId'));
        if (!ids.length) throw new Error('ioCIds is required for unlink');
        const d = await casesGraphql(`mutation { unlinkIoCsFromCase(${args({ caseId, ioCIds: ids })}) { unlinkedIoCIds } }`);
        const now = (await caseContents(caseId, 1)).iocs;
        const still = ids.filter(x => now.some(i => i.ioCId === x));
        if (still.length) throw new Error(`unlink sent but these are still linked: ${still.join(', ')}`);
        return json({ unlinked: d.unlinkIoCsFromCase?.unlinkedIoCIds || [], verified: true, remaining: now });
      }
      if (a.action !== 'link') throw new Error('action must be link or unlink');
      const items = Array.isArray(a.iocs) ? a.iocs : [];
      if (!items.length || items.length > 100) throw new Error('iocs must hold 1 to 100 entries');
      const TYPES = ['IPV4', 'IPV6', 'DNS', 'URL', 'SHA1', 'SHA256', 'MD5'];
      for (const i of items) {
        i.type = String(i.type || '').toUpperCase();
        if (!TYPES.includes(i.type)) throw new Error(`IOC type must be one of ${TYPES.join(', ')} (got ${JSON.stringify(i.type)})`);
        if (!i.value || typeof i.value !== 'string') throw new Error('each IOC needs a value');
      }
      const missing = items.filter(i => !i.ioCId);
      const created = [];
      if (missing.length) {
        if (!a.createMissing) throw new Error(`${missing.length} IOC(s) have no ioCId: pass createMissing: true to create them in Threat Intelligence first, or pass their ioCId.`);
        const c = await getCase(caseId, 'id publicId scope { account { id } }');
        const acct = c.scope?.account?.id;
        if (!acct) throw new Error(`case ${caseId}: the API did not report its account, so IOCs cannot be created for it`);
        const days = Math.min(Math.max(Number(a.validDays) || 30, 1), 365);
        const validUntil = new Date(Date.now() + days * 86400000).toISOString();
        const res = await apiPost('/web/api/v2.1/threat-intelligence/iocs', {
          filter: { accountIds: [String(acct)] },
          data: missing.map(i => ({ type: i.type, value: i.value, method: 'EQUALS', source: `Case ${c.publicId}`, name: `Case ${c.publicId} ${i.type}`, validUntil })),
        });
        for (const r of res?.data || []) {
          const same = (a, b) => String(a ?? '').trim().toLowerCase() === String(b ?? '').trim().toLowerCase();
          const m = missing.find(i => !i.ioCId && same(i.type, r.type) && same(i.value, r.value));
          if (m) { m.ioCId = r.uuid; created.push({ ioCId: r.uuid, type: r.type, value: r.value }); }
        }
        const unresolved = missing.filter(i => !i.ioCId);
        if (unresolved.length) throw new Error(`Threat Intelligence did not return an id for: ${unresolved.map(i => `${i.type} ${i.value}`).join(', ')} (it may already exist; pass its ioCId).`);
      }
      const iocs = items.map(i => ({ ioCId: checkId(i.ioCId, 'ioCId'), value: i.value, type: i.type }));
      const d = await casesGraphql(`mutation { linkIoCsToCase(${args({ caseId, ioCs: iocs })}) { linkedIoCIds } }`);
      const now = await verify('case_iocs', async () => (await caseContents(caseId, 1)).iocs, (l) => iocs.every(i => l.some(x => x.ioCId === i.ioCId)));
      return json({ linked: d.linkIoCsToCase?.linkedIoCIds || [], created, verified: true, caseIocs: now });
    },
  },

  {
    name: 'case_post_message',
    description: 'Post a message in a case\'s collaboration space, or a reply to one (parentId). Use it for short status updates (playbook results, containment done); use case_add_note for findings that should stay on the record.',
    inputSchema: { type: 'object', properties: { caseId: { type: 'string' }, message: { type: 'string', description: 'Up to 10,000 characters.' }, parentId: { type: 'string', description: 'Message id to reply to.' } }, required: ['caseId', 'message'] },
    async handler({ caseId, message, parentId }) {
      const id = checkId(caseId, 'caseId');
      const text = String(message || '');
      if (!text.trim() || text.length > 10000) throw new Error('message must be 1 to 10,000 characters');
      const d = await casesGraphql(`mutation { createSimpleCollaborationSpaceMessage(${args({ caseId: id, content: text, parentId: parentId ? checkId(parentId, 'parentId') : undefined })}) { message { id createdAt } errors { field errorType message } } }`);
      payloadErrors('createSimpleCollaborationSpaceMessage', d.createSimpleCollaborationSpaceMessage);
      const m = d.createSimpleCollaborationSpaceMessage?.message;
      if (!m?.id) throw new Error('the message was not created (no id returned)');
      return json({ posted: true, caseId: id, messageId: m.id, createdAt: m.createdAt, parentId: parentId || null });
    },
  },

  {
    name: 'case_alerts',
    description: `Add alerts to a case or remove them from it. An alert can be in only one case: adding an alert that is already in another case does nothing (the API still reports success), so the result lists those under notAdded with the case that holds them. Verified by re-reading the case. ${ALERT_STATE_NOTE}`,
    inputSchema: {
      type: 'object',
      properties: { action: { type: 'string', enum: ['add', 'remove'] }, caseId: { type: 'string' }, alertIds: { type: 'array', items: { type: 'string' }, description: '1 to 500 UAM alert ids.' } },
      required: ['action', 'caseId', 'alertIds'],
    },
    async handler(a) {
      const caseId = checkId(a.caseId, 'caseId');
      const ids = [...new Set((a.alertIds || []).map(x => checkId(x, 'alertId')))];
      if (!ids.length || ids.length > 500) throw new Error('alertIds must hold 1 to 500 alert ids');
      if (a.action === 'add') {
        const d = await casesGraphql(`mutation { addAlertsToCase(${args({ caseId, alertIds: ids })}) { success errors { field errorType message } } }`);
        payloadErrors('addAlertsToCase', d.addAlertsToCase);
        await sleep(1000);
        const { c, missing, retried } = await settleAlerts(caseId, ids);
        const have = new Set(c.alertIds || []);
        return json({ added: ids.filter(x => have.has(x)), notAdded: missing.length ? await otherCases(missing) : [], notAddedCount: missing.length, addRetries: retried, caseAlertCount: have.size, note: ALERT_STATE_NOTE });
      }
      if (a.action === 'remove') {
        const scope = await caseScope(caseId);
        const before = await getCase(caseId, 'id alertIds');
        const notInCase = ids.filter(x => !(before.alertIds || []).includes(x));
        const toRemove = ids.filter(x => (before.alertIds || []).includes(x));
        if (!toRemove.length) throw new Error(`none of these alerts is in case ${caseId}`);
        const d = await casesGraphql(`mutation { removeAlertsFromCases(${args({ alertFilters: idFilter(toRemove), scope: scopeLit(scope) })}) { success errors { field errorType message } } }`);
        payloadErrors('removeAlertsFromCases', d.removeAlertsFromCases);
        const after = await verify('case_alerts remove', () => getCase(caseId, 'id alertIds'), (c) => toRemove.every(x => !(c.alertIds || []).includes(x)));
        return json({ removed: toRemove, notInCase, verified: true, caseAlertCount: (after.alertIds || []).length });
      }
      throw new Error('action must be add or remove');
    },
  },

  {
    name: 'case_rule_apply',
    description: 'Create, update, enable, disable, rank or delete a creation rule. A rule matches incoming alerts and opens (or groups them into) a case. Pass the expression as {match: "all"|"any", conditions: [{property, operation, value}]} (value a string, or an array for a list) or as the API tree; node ids are generated. The expression is validated before it is sent. update reads the rule and sends every field, so grouping and tasks you leave out are kept. Refused while the scope inherits its rules: case_rules shows linked, case_rules_scope unlinks. case_rules includeMetadata lists the properties, values and operations.',
    inputSchema: {
      type: 'object',
      properties: {
        action: { type: 'string', enum: ['create', 'update', 'enable', 'disable', 'rank', 'delete'] },
        ruleId: { type: 'string', description: 'Required except for create.' },
        name: { type: 'string' },
        description: { type: 'string' },
        expression: { type: 'object', description: 'Rule expression (see the tool description).' },
        severity: { type: 'string', enum: [...CASE_SEVERITIES], description: 'Severity of the cases the rule opens.' },
        enabled: { type: 'boolean', description: 'For create (default false).' },
        caseScopeLevel: { type: 'string', enum: ['SITE', 'ACCOUNT'], description: 'For create: the scope of the cases it opens (default SITE).' },
        grouping: { type: 'object', description: '{enabled, properties: [ASSET|ASSET_NAME|ACTOR_USER|IP_ADDRESS|FILE_HASH|CLOUD_CONTAINER|TICKET_ID], windowMinutes}' },
        defaultTasks: { type: 'array', items: { type: 'string' }, description: 'Task names added to every case the rule opens (replaces the list on update).' },
        rank: { type: 'integer', description: 'For rank (and after create): 1 is evaluated first, -1 moves the rule last. Only enabled rules can be ranked.' },
        ...SCOPE_PROPS,
      },
      required: ['action'],
    },
    async handler(a) {
      const scope = await singleAccountScope(scopeFromArgs(a.scopeIds, a.scopeType), 'case_rule_apply');
      const sl = scopeLit(scope);
      const cfg = await casesGraphql(`query { creationRulesScopeConfig(scope: ${lit(sl)}) { linked } }`, { readOnly: true });
      if (cfg.creationRulesScopeConfig?.linked) {
        throw new Error(`The creation rules of ${scope.scopeType.toLowerCase()} ${scope.scopeIds[0]} are inherited (linked: true) and cannot be changed here. Unlinking copies the inherited rules into this scope so it keeps its own; do it with case_rules_scope (linked: false, confirm: true) only when the user wants this scope to have its own rules.`);
      }
      const groupingLit = (g, prev) => {
        if (g === undefined) return prev ? { autoGroupingEnabled: !!prev.autoGroupingEnabled, autoGroupingProperties: (prev.autoGroupingProperties || []).map(en), groupingWindowMinutes: prev.groupingWindowMinutes ?? undefined } : undefined;
        const props = (g.properties || []).map(p => en(String(p).toUpperCase()));
        const win = g.windowMinutes != null ? Number(g.windowMinutes) : undefined;
        if (win != null && (!Number.isInteger(win) || win < 1 || win > 20160)) throw new Error('grouping.windowMinutes must be 1 to 20160');
        return { autoGroupingEnabled: g.enabled !== false && props.length > 0, autoGroupingProperties: props, groupingWindowMinutes: win };
      };
      const validate = async (expr) => {
        const v = await casesGraphql(`query { validateRuleExpression(ruleExpression: ${lit(expr)}) { validationErrors { field errorType message ... on CreationRuleExpressionError { expId } } } }`, { readOnly: true });
        const errs = v.validateRuleExpression?.validationErrors || [];
        if (errs.length) throw new Error(`rule expression is not valid: ${errs.map(e => `${e.message}${e.expId ? ` (node ${e.expId})` : ''}`).join('; ')}`);
      };
      const ruleId = a.action !== 'create' ? checkId(a.ruleId, 'ruleId') : undefined;
      const readRule = async () => (await casesGraphql(`query { creationRule(${args({ id: ruleId })}, scope: ${lit(sl)}) { ${RULE_DETAIL_FIELDS} } }`, { readOnly: true })).creationRule;

      if (a.action === 'create') {
        if (!a.name || !a.expression || !a.severity) throw new Error('create needs name, expression and severity');
        const { expression, idMap } = buildExpression(a.expression);
        await validate(expression);
        const d = await casesGraphql(`mutation { createCreationRule(${args({
          scope: sl, ruleName: String(a.name).trim(), ruleDescription: a.description ? String(a.description) : '',
          ruleExpression: expression, severity: checkEnum(a.severity, CASE_SEVERITIES, 'severity'),
          status: a.enabled === true, caseScopeLevel: en(a.caseScopeLevel === 'ACCOUNT' ? 'ACCOUNT' : 'SITE'),
          groupingConfig: groupingLit(a.grouping), defaultTasks: (a.defaultTasks || []).map(n => ({ name: String(n) })),
        })}) { ruleId errors { field errorType message ... on CreationRuleExpressionError { expId } } } }`);
        payloadErrors('createCreationRule', d.createCreationRule);
        const id = d.createCreationRule?.ruleId;
        if (!id) throw new Error('createCreationRule returned no rule id');
        if (a.enabled === true && a.rank != null) await casesGraphql(`mutation { changeRuleRankV2(${args({ ruleId: id, rank: Number(a.rank), scope: sl })}) }`);
        const rule = (await casesGraphql(`query { creationRule(${args({ id })}, scope: ${lit(sl)}) { ${RULE_DETAIL_FIELDS} } }`, { readOnly: true })).creationRule;
        return json({ created: true, ruleId: id, rule, expressionIds: idMap, expressionSent: plainExpression(expression) });
      }
      if (a.action === 'update') {
        const cur = await readRule();
        if (!cur) throw new Error(`rule ${ruleId} was not found in this scope`);
        const { expression } = buildExpression(a.expression || expressionFromRead(cur.ruleExpression));
        await validate(expression);
        const d = await casesGraphql(`mutation { updateRule(${args({
          ruleId, scope: sl,
          ruleName: a.name != null ? String(a.name).trim() : cur.name,
          ruleDescription: a.description != null ? String(a.description) : (cur.description || ''),
          ruleExpression: expression,
          severity: checkEnum(a.severity || cur.severity, CASE_SEVERITIES, 'severity'),
          groupingConfig: groupingLit(a.grouping, cur.groupingConfig),
          defaultTasks: a.defaultTasks ? a.defaultTasks.map(n => ({ name: String(n) })) : undefined,
        })}) { ruleId errors { field errorType message ... on CreationRuleExpressionError { expId } } } }`);
        payloadErrors('updateRule', d.updateRule);
        return json({ updated: true, before: cur, after: await readRule() });
      }
      if (a.action === 'enable' || a.action === 'disable') {
        const on = a.action === 'enable';
        await casesGraphql(`mutation { changeRulesStateV2(${args({ filter: idFilter([ruleId]), scope: sl, enabled: on })}) { updatedRuleIds } }`);
        const after = await verify('case_rule_apply', readRule, (r) => r && r.enabled === on);
        if (on && a.rank != null) await casesGraphql(`mutation { changeRuleRankV2(${args({ ruleId, rank: Number(a.rank), scope: sl })}) }`);
        return json({ ruleId, enabled: after.enabled, rank: (await readRule())?.rank, verified: true });
      }
      if (a.action === 'rank') {
        if (!Number.isInteger(Number(a.rank))) throw new Error('rank must be an integer (1 first, -1 last)');
        const d = await casesGraphql(`mutation { changeRuleRankV2(${args({ ruleId, rank: Number(a.rank), scope: sl })}) }`);
        return json({ ruleId, ranked: d.changeRuleRankV2 === true, rank: (await readRule())?.rank });
      }
      if (a.action === 'delete') {
        const d = await casesGraphql(`mutation { deleteCreationRules(${args({ filter: idFilter([ruleId]), scope: sl })}) { deletedRuleIds } }`);
        const gone = d.deleteCreationRules?.deletedRuleIds || [];
        if (!gone.includes(ruleId)) throw new Error(`rule ${ruleId} was not deleted (deletedRuleIds ${JSON.stringify(gone)})`);
        return json({ deleted: true, ruleId });
      }
      throw new Error('action must be create, update, enable, disable, rank or delete');
    },
  },

  {
    name: 'case_rules_scope',
    description: 'Link a scope to the creation rules of the level above it, or unlink it so it keeps its own. Unlinking (linked: false) copies the inherited rules into this scope, after which they can be changed here. Linking (linked: true) makes the scope follow the rules above it again and drops its own rules. Requires confirm: true; returns the state and rule count before and after.',
    inputSchema: {
      type: 'object',
      properties: { linked: { type: 'boolean' }, confirm: { type: 'boolean', description: 'Must be true.' }, ...SCOPE_PROPS },
      required: ['linked', 'confirm'],
    },
    async handler(a) {
      if (a.confirm !== true) throw new Error('case_rules_scope changes how this scope gets its creation rules: pass confirm: true once the user has agreed.');
      if (typeof a.linked !== 'boolean') throw new Error('linked must be true or false');
      const scope = await singleAccountScope(scopeFromArgs(a.scopeIds, a.scopeType), 'case_rules_scope');
      const sl = lit(scopeLit(scope));
      const state = async () => {
        const d = await casesGraphql(`query { creationRulesScopeConfig(scope: ${sl}) { linked } creationRules(scope: ${sl}, first: 1) { totalCount } }`, { readOnly: true });
        return { linked: d.creationRulesScopeConfig?.linked ?? null, ruleCount: d.creationRules?.totalCount ?? null };
      };
      const before = await state();
      if (before.linked === a.linked) return json({ changed: false, scope, before, note: `already ${a.linked ? 'linked' : 'unlinked'}` });
      const d = await casesGraphql(`mutation { changeRulesScopeConfig(linked: ${a.linked ? 'true' : 'false'}, action: INHERIT, scope: ${sl}) { linked } }`);
      const after = await verify('case_rules_scope', state, (s) => s.linked === a.linked);
      return json({ changed: true, scope, before, after, response: d.changeRulesScopeConfig });
    },
  },
];

function pick(c) {
  return { status: c.status, severity: c.severity, analystVerdict: c.analystVerdict, assignee: c.assignee?.fullName || c.assignee?.id || null, caseTypes: c.caseTypes };
}
