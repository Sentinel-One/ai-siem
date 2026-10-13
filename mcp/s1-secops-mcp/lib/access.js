/**
 * Read-only mode (1.5.5): the server refuses every action that changes the tenant unless the
 * operator explicitly enables write.
 *
 *   S1_READ_ONLY unset, "true", "1", "yes", "on"   read-only (the default)
 *   S1_READ_ONLY "false", "0", "no", "off"          write enabled
 *   any other value                                 read-only, with a warning (fail closed)
 *
 * Read-only mode is a guard in this server. The authoritative control is the role of the console
 * token: a token whose service user has a read-only role cannot write whatever this setting says.
 *
 * Every tool is classified here, in one place, so a reviewer can audit the full write surface and
 * the tests can prove that no tool is unclassified. The gate runs before any network call.
 */

import { getCreds } from './credentials.js';
import { redact } from './redact.js';

export const ENV = 'S1_READ_ONLY';
export const DOCS = 'docs/read-only.md';
export const HOW_TO_ENABLE = 'To allow it, run "s1-secops-mcp-launch.sh install --read-write" '
  + '(Windows: -ReadWrite) and restart Claude Desktop; with the Node install set S1_READ_ONLY=false '
  + `in the MCP client config. See ${DOCS}.`;

// Tools that change tenant state. Classification is by effect, not by HTTP verb.
export const WRITE_TOOLS = new Set([
  's1_api_put', 's1_api_patch', 's1_api_delete',
  'uam_add_note', 'uam_set_status', 'uam_set_verdict', 'uam_assign_alert',
  'uam_post_alert', 'uam_ingest_alert', 'hec_ingest',
  'sdl_put_file', 'sdl_delete_file',
  'sdl_create_dashboard', 'sdl_share_dashboard', 'sdl_save_dashboard_layout', 'sdl_delete_dashboard',
  'ha_import_workflow', 'ha_delete_workflow',
]);

// Tools that read or write depending on arguments.
export const CONDITIONAL_TOOLS = new Set(['s1_api_post', 'powerquery_run']);

// Tools that never change tenant state. outputFile / s1_api_download write only to the local
// machine, under the existing output-folder rules, and are allowed in read-only mode.
export const READ_TOOLS = new Set([
  's1_api_get', 's1_api_download',
  'uam_list_alerts', 'uam_get_alert', 'uam_available_actions', 'purple_ai_alert_summary',
  'powerquery_enumerate_sources', 'powerquery_schema_discover',
  'sdl_list_files', 'sdl_get_file', 'sdl_list_dashboards', 'sdl_get_dashboard',
  'ha_list_workflows', 'ha_get_workflow', 'ha_export_workflow',
]);

// Edits that can overwrite or remove existing state: MCP destructiveHint.
const DESTRUCTIVE = new Set([
  's1_api_put', 's1_api_patch', 's1_api_delete', 'sdl_put_file', 'sdl_delete_file',
  'sdl_delete_dashboard', 'sdl_save_dashboard_layout', 'ha_delete_workflow',
]);

let warnedValue = null;

/** True unless S1_READ_ONLY explicitly disables read-only mode. Fails closed. */
export function readOnlyMode() {
  const raw = process.env[ENV];
  if (raw === undefined || raw === '') return true;
  const v = String(raw).trim().toLowerCase();
  if (['false', '0', 'no', 'off'].includes(v)) return false;
  if (['true', '1', 'yes', 'on'].includes(v)) return true;
  if (warnedValue !== raw) {
    warnedValue = raw;
    process.stderr.write(`[s1-secops-mcp] ${ENV}="${String(raw).slice(0, 20)}" is not true or false: staying read-only.\n`);
  }
  return true;
}

export function accessOf(name) {
  if (WRITE_TOOLS.has(name)) return 'write';
  if (CONDITIONAL_TOOLS.has(name)) return 'conditional';
  if (READ_TOOLS.has(name)) return 'read';
  return 'unclassified';
}

// ─── s1_api_post: the read-only allowlist ────────────────────────────────────
// POST is also how the console API runs queries. Only these are read-only; everything else
// (create, update, actions, imports) is treated as a write. The list is deliberately small:
// an endpoint missing from it is refused, never assumed to be a read.
const READ_POST_PATHS = [
  /\/dv\/init-query$/,                                   // Deep Visibility query launch
  /\/cloud-funnel\/validate-query$/,                     // query syntax validation
  /\/xdr\/graph-explorer\/query(\/[a-z0-9/_-]+)?$/i,     // graph explorer queries
  /\/available-actions(\/with-status)?$/,                // which actions are offered
  /\/xdr\/assets\/tags\/count$/,                         // counts
];

/**
 * Operation type of a GraphQL document, ignoring comments. Fails closed: a document that
 * contains the word `mutation` or `subscription` anywhere is classed as such, because one
 * document can hold several operations (`query a {..} mutation b {..}` with operationName "b"
 * runs the mutation). A read that merely mentions the word is refused, which is the safe error.
 */
export function graphqlOperation(query) {
  if (typeof query !== 'string') return null;
  const s = query.replace(/#[^\n]*/g, ' ').trim();
  const kw = /\b(mutation|subscription)\b/.exec(s);
  if (kw) return kw[1];
  if (s.startsWith('{') || /^query\b/.test(s)) return 'query';
  return null;                                         // unknown shape: fail closed below
}

export function postIsRead(path, body) {
  const p = String(path || '').split('?')[0].replace(/\/+$/, '');
  if (/\/graphql$/.test(p)) {
    const docs = [];
    const add = b => { if (b && typeof b === 'object') docs.push(b.query); };
    Array.isArray(body) ? body.forEach(add) : add(body);
    return docs.length > 0 && docs.every(q => graphqlOperation(q) === 'query');
  }
  return READ_POST_PATHS.some(rx => rx.test(p));
}

function pqWrites(query) {
  return /\|\s*savelookup\b/i.test(String(query || ''));
}

/** Does this specific call change tenant state? */
export function callWrites(name, args = {}) {
  const a = accessOf(name);
  if (a === 'write') return true;
  if (a === 'read') return false;
  if (name === 's1_api_post') return !postIsRead(args.path, args.body);
  if (name === 'powerquery_run') return pqWrites(args.query);
  return true;   // unclassified: treat as a write
}

// ─── Token checks ─────────────────────────────────────────────────────────────

/** Expiry of a JWT console token, or null when the token is not a JWT or has no exp. */
export function tokenExpiry(token) {
  const parts = String(token || '').split('.');
  if (parts.length !== 3) return null;
  try {
    const payload = JSON.parse(Buffer.from(parts[1].replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf-8'));
    return typeof payload.exp === 'number' ? new Date(payload.exp * 1000) : null;
  } catch { return null; }
}

export class ReadOnlyError extends Error {}

function refusalText(name, args) {
  const what = name === 'powerquery_run'
    ? 'This query writes a lookup table (| savelookup).'
    : name === 's1_api_post'
      ? `POST ${String(args.path || '').split('?')[0]} is not on the read-only allowlist, so it is treated as a change to the tenant.`
      : `${name} changes the tenant.`;
  return `s1-secops-mcp is in read-only mode (${ENV}). ${what} ${HOW_TO_ENABLE}`;
}

/**
 * Gate for one tool call. Throws before any network call when the call would write and write is
 * not enabled, or when the token is missing or expired. Logs one audit line for an allowed write.
 */
export function gate(name, args = {}) {
  if (!callWrites(name, args)) return;
  if (readOnlyMode()) throw new ReadOnlyError(refusalText(name, args));
  const token = getCreds().S1_CONSOLE_API_TOKEN;
  if (!token && name !== 'hec_ingest') {
    throw new Error(`${name} refused: no console API token is configured. Run "s1-secops-mcp-launch.sh setup".`);
  }
  const exp = tokenExpiry(token);
  if (exp && exp.getTime() <= Date.now()) {
    throw new Error(`${name} refused: the console API token expired on ${exp.toISOString()}. Generate a new token and run setup again.`);
  }
  audit(name, args);
}

/** One stderr line per allowed write: what and where, never bodies, tokens or headers. */
export function audit(name, args = {}) {
  const fields = { tool: name };
  for (const k of ['path', 'udoId', 'id', 'alertId', 'workflowId', 'name', 'scope', 'accountIds', 'siteIds']) {
    if (args[k] !== undefined && args[k] !== null && typeof args[k] !== 'object') fields[k] = String(args[k]).slice(0, 200);
  }
  if (Array.isArray(args.alertIds)) fields.alertIds = args.alertIds.length + ' alert(s)';
  const line = Object.entries(fields).map(([k, v]) => `${k}=${JSON.stringify(v)}`).join(' ');
  process.stderr.write(redact(`[s1-secops-mcp] WRITE ${new Date().toISOString()} ${line}`) + '\n');
}

/** MCP tool annotations (readOnlyHint / destructiveHint / openWorldHint). */
export function annotationsFor(name) {
  const a = accessOf(name);
  return {
    readOnlyHint: a === 'read',
    destructiveHint: DESTRUCTIVE.has(name),
    openWorldHint: true,
  };
}

/** Description shown to the client, marked when the tool is disabled by read-only mode. */
export function describe(tool) {
  const a = accessOf(tool.name);
  if (!readOnlyMode()) return tool.description;
  if (a === 'write') return `[Disabled: read-only mode, ${ENV}] ${tool.description}`;
  if (a === 'conditional') return `[Read-only mode, ${ENV}: write forms are refused] ${tool.description}`;
  return tool.description;
}

/** Startup / status summary. */
export function modeSummary() {
  const ro = readOnlyMode();
  const exp = tokenExpiry(getCreds().S1_CONSOLE_API_TOKEN);
  const days = exp ? Math.floor((exp.getTime() - Date.now()) / 86400000) : null;
  return {
    readOnly: ro,
    setting: `${ENV}=${process.env[ENV] === undefined ? '(unset)' : process.env[ENV]}`,
    writeTools: [...WRITE_TOOLS].length + [...CONDITIONAL_TOOLS].length,
    tokenExpires: exp ? exp.toISOString() : 'unknown (not a JWT or no expiry)',
    tokenExpiresInDays: days,
    note: ro
      ? `Read-only: tools that change the tenant are refused. ${HOW_TO_ENABLE}`
      : 'WRITE ENABLED: actions change your SentinelOne tenant and run as this token\'s user; every write is recorded in the server audit log.',
  };
}
