/**
 * Case Management GraphQL (1.6.4): POST /web/api/v2.1/cases/graphql, ApiToken auth.
 *
 * Arguments are written into the document as GraphQL literals, built only by lit() below:
 * strings are JSON-escaped, enum values must match ^[A-Z][A-Z0-9_]*$, object keys must be
 * identifiers and numbers must be finite. The input type names are not published and
 * introspection is disabled, so variables cannot be typed; literals are the documented shape.
 *
 * Behaviour these helpers encode (verified on a live console, 2026-11-23):
 *   - `cases` list nodes do NOT expose alertIds, taskCount, noteCount or processingState;
 *     selecting one fails validation for the whole query. Those are on `case(id)` only.
 *   - `creationRule` is on the list node; it is not on `case(id)`.
 *   - updateCase replaces the whole case and returns a Boolean: an omitted assignTo unassigns.
 *   - createNote needs contentHtml; plain text alone is refused.
 *   - An alert belongs to at most one case. addAlertsToCase reports success and does nothing
 *     for an alert that is already in another case.
 *   - Case state and alert state are independent: closing a case leaves its alerts unchanged.
 *   - Creation-rule expression node ids must be six alphanumeric characters.
 *   - Creation rules cannot be changed while the scope inherits them (linked: true).
 */

import { randomBytes } from 'node:crypto';
import { apiPost, allAccountIds, uamAlertState, uamResolveUser } from './s1.js';
import { graphqlOperation } from './access.js';

export const CASES_PATH = '/web/api/v2.1/cases/graphql';

export const CASE_STATUSES = Object.freeze(['NEW', 'IN_PROGRESS', 'RESOLVED', 'CLOSED']);
export const CASE_SEVERITIES = Object.freeze(['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']);
export const MAX_CASE_TYPES = 5;
export const TASK_STATUSES = Object.freeze(['TO_DO', 'DONE']);
export const SCOPE_TYPES = Object.freeze(['ACCOUNT', 'SITE']);

const ENUM_RX = /^[A-Z][A-Z0-9_]*$/;
const IDENT_RX = /^[A-Za-z_][A-Za-z0-9_]*$/;
const ID_RX = /^[A-Za-z0-9._:-]{1,128}$/;

// ─── Literal builder ─────────────────────────────────────────────────────────

export class Enum {
  constructor(v) {
    if (typeof v !== 'string' || !ENUM_RX.test(v)) throw new Error(`invalid enum value ${JSON.stringify(v)}`);
    this.v = v;
  }
}
export const en = (v) => new Enum(v);

/** One GraphQL input literal. Throws on anything it cannot write safely. */
export function lit(v) {
  if (v instanceof Enum) return v.v;
  if (v === null) return 'null';
  if (typeof v === 'string') return JSON.stringify(v);
  if (typeof v === 'boolean') return v ? 'true' : 'false';
  if (typeof v === 'number') {
    if (!Number.isFinite(v)) throw new Error(`invalid number ${v}`);
    return String(v);
  }
  if (Array.isArray(v)) return `[${v.map(lit).join(', ')}]`;
  if (typeof v === 'object') {
    const parts = [];
    for (const [k, x] of Object.entries(v)) {
      if (x === undefined) continue;
      if (!IDENT_RX.test(k)) throw new Error(`invalid input field name ${JSON.stringify(k)}`);
      parts.push(`${k}: ${lit(x)}`);
    }
    return `{ ${parts.join(', ')} }`;
  }
  throw new Error(`cannot write a ${typeof v} as a GraphQL literal`);
}

/** `name: literal, ...` for an argument list; undefined values are left out. */
export function args(obj) {
  return Object.entries(obj).filter(([, v]) => v !== undefined).map(([k, v]) => {
    if (!IDENT_RX.test(k)) throw new Error(`invalid argument name ${JSON.stringify(k)}`);
    return `${k}: ${lit(v)}`;
  }).join(', ');
}

export function checkId(v, what = 'id') {
  if (typeof v !== 'string' || !ID_RX.test(v.trim())) throw new Error(`${what} must be an id string (got ${JSON.stringify(v)})`);
  return v.trim();
}

export function checkEnum(v, allowed, what) {
  if (!allowed.includes(v)) throw new Error(`${what} must be one of ${allowed.join(', ')} (got ${JSON.stringify(v)})`);
  return en(v);
}

export const scopeLit = (s) => ({ scopeIds: s.scopeIds.map(String), scopeType: en(s.scopeType) });
export const idFilter = (ids) => ({ or: [{ and: [{ fieldId: 'id', stringIn: { values: ids.map(String) } }] }] });

// ─── Transport ───────────────────────────────────────────────────────────────

/**
 * Run one document against /cases/graphql. A read (readOnly: true) must be a `query`
 * document and is retried on 429/5xx; a mutation is sent once.
 */
export async function casesGraphql(document, { readOnly = false } = {}) {
  if (readOnly && graphqlOperation(document) !== 'query') {
    throw new Error('internal: a case read must be a GraphQL query document');
  }
  const data = await apiPost(CASES_PATH, { query: document }, { allowRetry: readOnly });
  if (data?.errors?.length) {
    const msgs = data.errors.map(e => e.message).filter(Boolean);
    throw new Error(`Case Management GraphQL error: ${msgs.slice(0, 3).join(' | ')}`);
  }
  return data?.data || {};
}

/** Throw when a mutation payload carries a non-empty errors list. */
export function payloadErrors(label, payload) {
  const errs = payload?.errors;
  if (Array.isArray(errs) && errs.length) {
    const s = errs.map(e => `${e.field ? e.field + ': ' : ''}${e.message || e.errorType}${e.expId ? ` (expression node ${e.expId})` : ''}`);
    throw new Error(`${label} refused: ${s.join('; ')}`);
  }
}

export const sleep = (ms) => new Promise(r => setTimeout(r, ms));

// ─── Scope ───────────────────────────────────────────────────────────────────

/** {scopeIds, scopeType} from tool arguments, or undefined when none were given. */
export function scopeFromArgs(scopeIds, scopeType) {
  if (scopeIds === undefined || scopeIds === null) {
    if (scopeType) throw new Error('scopeType was given without scopeIds: pass scopeIds (an array of account or site ids)');
    return undefined;
  }
  if (!Array.isArray(scopeIds) || !scopeIds.length) throw new Error('scopeIds must be a non-empty array of account or site ids');
  const t = scopeType || 'ACCOUNT';
  if (!SCOPE_TYPES.includes(t)) throw new Error(`scopeType must be ACCOUNT or SITE (got ${JSON.stringify(t)})`);
  return { scopeIds: scopeIds.map(s => checkId(String(s), 'scope id')), scopeType: t };
}

/** Every account the token can see: the default scope for list reads. */
export async function allAccountsScope() {
  const ids = await allAccountIds();
  if (!ids.length) throw new Error('no accounts are visible to this token');
  return { scopeIds: ids, scopeType: 'ACCOUNT' };
}

/** A single account for rule operations: the argument, or the token's only account. */
export async function singleAccountScope(scope, label) {
  if (scope) return scope;
  const ids = await allAccountIds({ max: 2 });
  if (ids.length === 1) return { scopeIds: ids, scopeType: 'ACCOUNT' };
  throw new Error(`${label}: pass scopeIds (the account the rules belong to); this token sees ${ids.length ? 'more than one account' : 'no account'}.`);
}

// ─── Case reads ──────────────────────────────────────────────────────────────

// List-node fields only (see the header): verified live.
export const CASE_LIST_FIELDS = 'id publicId name status severity analystVerdict caseScopeLevel caseTypes createdAt lastModifiedAt '
  + 'assetCount assignee { id fullName email } creationRule { id name } mitreTactics { id tacticName } '
  + 'scope { account { id name } site { id name } }';

// Detail fields, verified live.
export const CASE_DETAIL_FIELDS = 'id publicId name status severity analystVerdict processingState caseTypes '
  + 'assignee { id fullName email } scope { account { id name } site { id name } } '
  + 'alertIds assets products noteCount taskCount iocCount fileCount '
  + 'mitreAttacks { tactic { id tacticName } techniques { id techniqueName subTechniques { id subTechniqueName } } } '
  + 'watchers { user { id fullName } addedAt } sloTimeToRespond sloTimeToResolve';

export async function getCase(caseId, fields = CASE_DETAIL_FIELDS) {
  const id = checkId(caseId, 'caseId');
  const d = await casesGraphql(`query { case(${args({ id })}) { ${fields} } }`, { readOnly: true });
  if (!d.case) throw new Error(`case ${id} was not found or is not visible to this token`);
  return d.case;
}

/** The case's own account, the scope the console sends for writes on it. */
export async function caseScope(caseId) {
  const c = await getCase(caseId, 'id scope { account { id } site { id } }');
  const acct = c.scope?.account?.id;
  if (!acct) throw new Error(`case ${caseId}: the API did not report its account`);
  return { scopeIds: [String(acct)], scopeType: 'ACCOUNT' };
}

export async function caseForAlert(alertId) {
  const id = checkId(alertId, 'alertId');
  const d = await casesGraphql(
    `query { caseForAlert(${args({ alertId: id })}) { id publicId name status severity analystVerdict assignee { id fullName } } }`,
    { readOnly: true });
  return d.caseForAlert || null;
}

// ─── Users ───────────────────────────────────────────────────────────────────

/** A console user id from userId or email (the same lookup the UAM assign tool uses). */
export async function resolveUserId({ userId, email }) {
  if ((userId == null || userId === '') && !email) return undefined;
  const u = await uamResolveUser({ userId, email });
  return u.userId;
}

// ─── Notes ───────────────────────────────────────────────────────────────────

const ESC = { '&': '&amp;', '<': '&lt;', '>': '&gt;' };
/** Plain text to the HTML the console stores: escaped, paragraphs on blank lines, <br> on newlines. */
export function textToHtml(text) {
  const esc = String(text).replace(/[&<>]/g, c => ESC[c]);
  return esc.split(/\r?\n\s*\r?\n/).map(p => p.trim()).filter(Boolean)
    .map(p => `<p>${p.replace(/\r?\n/g, '<br>')}</p>`).join('') || '<p></p>';
}

/** HTML compared the way the API stores it: entities decoded, whitespace collapsed. */
export function sameHtml(a, b) {
  const n = (h) => String(h || '').replace(/&quot;/g, '"').replace(/&#0?39;|&apos;/g, "'").replace(/&nbsp;/g, ' ')
    .replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&').replace(/\s+/g, ' ').trim();
  return n(a) === n(b);
}

// ─── Case types ──────────────────────────────────────────────────────────────

/** Clean and check a case type list: trimmed, de-duplicated (case-insensitively), at most 5. */
export function normaliseCaseTypes(list) {
  if (list === undefined) return undefined;
  if (!Array.isArray(list)) throw new Error('caseTypes must be an array of strings');
  const out = [];
  const seen = new Set();
  for (const t of list) {
    if (typeof t !== 'string') throw new Error('caseTypes must be an array of strings');
    const v = t.replace(/\s+/g, ' ').trim();
    if (!v || v.length > 100) throw new Error(`invalid case type ${JSON.stringify(t)}`);
    const k = v.toLowerCase();
    if (!seen.has(k)) { seen.add(k); out.push(v); }
  }
  if (out.length > MAX_CASE_TYPES) throw new Error(`a case can have at most ${MAX_CASE_TYPES} case types (got ${out.length})`);
  return out;
}

/** Compare case type lists the way the console stores them (case-insensitive, whitespace collapsed). */
export function sameCaseTypes(a = [], b = []) {
  const n = (l) => [...new Set((l || []).map(x => String(x).replace(/\s+/g, ' ').trim().toLowerCase()))].sort().join('|');
  return n(a) === n(b);
}

// ─── Creation rules ──────────────────────────────────────────────────────────

const EXP_ID_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
export const EXP_ID_RX = /^[A-Za-z0-9]{6}$/;

/** A six-character alphanumeric expression node id (the only shape the API accepts). */
export function expressionId() {
  const b = randomBytes(6);
  let s = '';
  for (let i = 0; i < 6; i++) s += EXP_ID_CHARS[b[i] % EXP_ID_CHARS.length];
  return s;
}

const VALUE_TYPES = ['STRING', 'STRING_LIST'];
const CONDITIONS = ['AND', 'OR'];

/**
 * Turn a rule expression into a literal-ready object. Accepts either:
 *   - the API's tree { type: GROUP|ITEM, condition, expressions, propertyName, operation, value },
 *     where node ids are optional (missing or invalid ids are replaced with generated ones), or
 *   - the short form { match: 'all'|'any', conditions: [{ property, operation, value }] },
 *     where value is a string or an array of strings (STRING_LIST).
 * Returns { expression, idMap } where idMap maps a caller id to the id sent.
 */
export function buildExpression(input, idMap = {}, depth = 0) {
  if (depth > 8) throw new Error('rule expression is nested too deeply (max 8 levels)');
  if (!input || typeof input !== 'object') throw new Error('rule expression must be an object');
  const used = new Set(Object.values(idMap));
  const nodeId = (given) => {
    if (typeof given === 'string' && EXP_ID_RX.test(given) && !used.has(given)) { used.add(given); return given; }
    let id; do { id = expressionId(); } while (used.has(id));
    used.add(id);
    if (given != null) idMap[String(given)] = id;
    return id;
  };
  if (Array.isArray(input.conditions)) {
    const match = (input.match || 'all').toLowerCase();
    if (!['all', 'any'].includes(match)) throw new Error('match must be "all" or "any"');
    if (!input.conditions.length) throw new Error('conditions must not be empty');
    const tree = {
      type: 'GROUP', condition: match === 'all' ? 'AND' : 'OR',
      expressions: input.conditions.map(c => (Array.isArray(c.conditions)
        ? c
        : { type: 'ITEM', propertyName: c.property ?? c.propertyName, operation: c.operation, value: c.value })),
    };
    return buildExpression(tree, idMap, depth);
  }
  const type = String(input.type || '').toUpperCase();
  if (type === 'GROUP') {
    const condition = String(input.condition || 'AND').toUpperCase();
    if (!CONDITIONS.includes(condition)) throw new Error(`group condition must be AND or OR (got ${input.condition})`);
    if (!Array.isArray(input.expressions) || !input.expressions.length) throw new Error('a GROUP needs a non-empty expressions list');
    const id = nodeId(input.id);
    const expressions = input.expressions.map(e => buildExpression(e, idMap, depth + 1).expression);
    return { expression: { id, type: en('GROUP'), condition: en(condition), expressions }, idMap };
  }
  if (type === 'ITEM') {
    const propertyName = String(input.propertyName || '').trim().toUpperCase();
    if (!ENUM_RX.test(propertyName)) throw new Error(`invalid rule property ${JSON.stringify(input.propertyName)}`);
    const operation = String(input.operation || '').trim().toUpperCase();
    if (!ENUM_RX.test(operation)) throw new Error(`invalid rule operation ${JSON.stringify(input.operation)}`);
    let value = input.value;
    if (typeof value === 'string') value = { type: 'STRING', stringValue: value };
    else if (Array.isArray(value)) value = { type: 'STRING_LIST', stringValues: value.map(String) };
    if (!value || typeof value !== 'object') throw new Error(`rule item ${propertyName} needs a value`);
    const vt = String(value.type || (Array.isArray(value.stringValues) ? 'STRING_LIST' : 'STRING')).toUpperCase();
    if (!VALUE_TYPES.includes(vt)) throw new Error(`value type must be STRING or STRING_LIST (got ${value.type})`);
    const v = vt === 'STRING'
      ? { type: en('STRING'), stringValue: String(value.stringValue ?? '') }
      : { type: en('STRING_LIST'), stringValues: (value.stringValues || []).map(String) };
    const id = nodeId(input.id);
    // propertyName is a String in the schema, not an enum (verified live).
    return { expression: { id, type: en('ITEM'), propertyName, operation: en(operation), value: v }, idMap };
  }
  throw new Error(`expression node type must be GROUP or ITEM (got ${JSON.stringify(input.type)})`);
}

/** The literal-safe expression back to plain JSON (enums as strings), for results. */
export function plainExpression(e) {
  return JSON.parse(JSON.stringify(e, (k, v) => (v instanceof Enum ? v.v : v)));
}

const EXPR_ITEM = 'id type condition propertyName operation value { type stringValue stringValues }';
// Read as many levels as buildExpression accepts (8), so an update without a new expression
// re-sends the whole tree rather than a truncated one.
const exprLevels = (n) => (n <= 1 ? EXPR_ITEM : `${EXPR_ITEM} expressions { ${exprLevels(n - 1)} }`);
export const RULE_EXPRESSION_FIELDS = `ruleExpression { ${exprLevels(9)} }`;
export const RULE_DETAIL_FIELDS = 'id name description rank enabled severity caseScopeLevel '
  + 'groupingConfig { autoGroupingEnabled autoGroupingProperties groupingWindowMinutes } '
  + `defaultTasks { id name taskIndex } ${RULE_EXPRESSION_FIELDS}`;
export const RULE_LIST_FIELDS = 'id name rank enabled severity ruleKind caseScopeLevel createdAt';

/** Convert a rule read back from the API into an expression input (drops nulls). */
export function expressionFromRead(e) {
  if (!e) return null;
  const out = { id: e.id, type: e.type };
  if (e.type === 'GROUP') { out.condition = e.condition; out.expressions = (e.expressions || []).map(expressionFromRead); }
  else { out.propertyName = e.propertyName; out.operation = e.operation; out.value = e.value; }
  return out;
}

/** The pre-filled UAM alert scope for creating a case from alerts: the first alert's site, else its account. */
export async function scopeForAlerts(alertIds) {
  const st = await uamAlertState(alertIds[0]).catch(() => null);
  const s = st?.realTime?.scope;
  if (s?.site?.id) return { scopeIds: [String(s.site.id)], scopeType: 'SITE' };
  if (s?.account?.id) return { scopeIds: [String(s.account.id)], scopeType: 'ACCOUNT' };
  throw new Error(`could not read the scope of alert ${alertIds[0]}; pass scopeIds and scopeType`);
}
