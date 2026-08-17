/**
 * SentinelOne Singularity Data Lake (SDL) API client.
 *
 * Auth: the console API token, sent as `Authorization: Bearer <token>`.
 * It covers every SDL operation, config read, config write, and log read.
 *
 * All SDL endpoints live under `<console>/sdl`, derived from S1_CONSOLE_URL.
 */

import { getCreds } from './credentials.js';

// ─── helpers ──────────────────────────────────────────────────────────────────

function sdlBase() {
  const url = (getCreds().S1_CONSOLE_URL || '').replace(/\/+$/, '');
  if (!url) throw new Error('S1_CONSOLE_URL not configured. Drop credentials.json into your project folder.');
  return `${url}/sdl`;
}

/** The SDL credential: the console API token, used for every operation. */
export function sdlToken() {
  const token = getCreds().S1_CONSOLE_API_TOKEN;
  if (!token) {
    throw new Error('S1_CONSOLE_API_TOKEN not configured. Drop credentials.json into your project folder.');
  }
  return token;
}

/**
 * Resolve the S1-Scope header value for a request.
 *
 * SDL objects (dashboards, saved searches, config files) are filed against the
 * scope the request carries, and reads are filtered by it. Verified live on
 * usea1-purple 2026-08-17, same token: `configFiles` returned 113 files at
 * account scope (20 of them dashboards) and 4 at a site scope (all 4
 * dashboards). A dashboard created at site scope is invisible to an
 * account-scoped listing, so a missing header is not a neutral default, it
 * silently changes which objects exist as far as the caller can tell.
 *
 * Precedence: explicit per-call scope, then S1_SCOPE from credentials. Passing
 * `null` is NOT the same as omitting: `null` deliberately suppresses the creds
 * default and sends no header, which is what the account-wide listing needs.
 *
 * Format: "<accountId>" for account scope, "<accountId>:<siteId>" for site
 * scope. Group scope does not exist in SDL; the console silently promotes a
 * Group selection to the Site above it.
 */
function resolveScope(scope) {
  if (scope === null) return null;
  const raw = scope !== undefined ? scope : getCreds().S1_SCOPE;
  if (raw === undefined || raw === null || raw === '') return null;
  if (typeof raw !== 'string') {
    throw new Error(`S1-Scope must be a string, got ${typeof raw}. Use "<accountId>" or "<accountId>:<siteId>".`);
  }
  const trimmed = raw.trim();
  if (!/^\d+(:\d+)?$/.test(trimmed)) {
    throw new Error(
      `Invalid S1-Scope ${JSON.stringify(trimmed)}. Expected "<accountId>" or "<accountId>:<siteId>", ` +
      'both numeric ids. Get them from GET /web/api/v2.1/accounts and /web/api/v2.1/sites.'
    );
  }
  return trimmed;
}

/** Header object carrying S1-Scope, or empty when the request is unscoped.
 *  Exported so the LRQ path in lib/s1.js scopes identically; a second
 *  implementation would drift. */
export function scopeHeaders(scope) {
  const resolved = resolveScope(scope);
  return resolved ? { 'S1-Scope': resolved } : {};
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

function retryAfterMs(res, fallback) {
  // Retry-After may be seconds OR an HTTP date; parseInt on a date yields NaN
  // and sleep(NaN) fires immediately (no backoff). Validate and cap.
  const raw = res.headers.get('Retry-After');
  const secs = Number(raw);
  if (raw && Number.isFinite(secs) && secs >= 0) return Math.min(secs * 1000, 30000);
  return fallback;
}

/**
 * Origin-pin the SDL request path, mirroring safeUrl() in lib/s1.js.
 *
 * Every current caller passes a literal, so this is defence in depth: the next
 * caller to thread a tool-supplied path through sdlFetch would otherwise be
 * able to rewrite the authority ("//evil.example/x", "@evil.example/x") and
 * send the tenant bearer token to an attacker-chosen origin.
 */
function safeSdlUrl(path) {
  if (typeof path !== 'string' || !path.startsWith('/') || path.startsWith('//')) {
    throw new Error(
      `SDL API path must be a string starting with a single "/" (got: ${JSON.stringify(path)?.slice(0, 80)})`
    );
  }
  const origin = new URL(sdlBase()).origin;
  const u = new URL(sdlBase() + path, origin);
  if (u.origin !== origin) {
    throw new Error(`SDL API path may not change the request origin (resolved to ${u.origin})`);
  }
  return u.toString();
}

async function sdlFetch(method, path, { body, extraHeaders = {}, rawBody = null, contentType = 'application/json', allowRetry = null } = {}, retries = 3) {
  const url = safeSdlUrl(path);
  const headers = {
    Authorization: `Bearer ${sdlToken()}`,
    'Content-Type': contentType,
    ...extraHeaders,
  };

  // Status-based retry is restricted to idempotent methods, mirroring lib/s1.js.
  // A 5xx received *after* the server committed a write would otherwise be
  // re-sent, and a re-sent addConfigFile(name:) against /dashboards/ creates a
  // duplicate. Callers opt in with allowRetry:true for read-only POSTs
  // (GraphQL queries). Network-layer rejections are still always retried:
  // those mean the request may never have reached the server at all.
  const methodRetryable = allowRetry !== null ? allowRetry : (method === 'GET' || method === 'HEAD');

  let delay = 500;
  for (let attempt = 0; attempt <= retries; attempt++) {
    let res;
    try {
      res = await fetch(url, {
        method,
        headers,
        body: rawBody !== null ? rawBody : (body !== undefined ? JSON.stringify(body) : undefined),
      });
    } catch (err) {
      if (attempt === retries) throw err;
      await sleep(delay);
      delay = Math.min(delay * 2, 8000);
      continue;
    }

    if (methodRetryable && (res.status === 429 || res.status >= 500) && attempt < retries) {
      await sleep(retryAfterMs(res, delay));
      delay = Math.min(delay * 2, 8000);
      continue;
    }

    const text = await res.text();
    let data;
    try { data = JSON.parse(text); } catch { data = text; }

    if (!res.ok) {
      const msg = typeof data === 'object' ? JSON.stringify(data) : text;
      throw new Error(`SDL API ${method} ${path} → ${res.status}: ${msg}`);
    }
    return data;
  }
  throw new Error(`SDL API ${method} ${path}: request failed after retries`);
}

// ─── Config file operations (GraphQL, canonical) ──────────────────────────────
//
// `POST /sdl/v2/graphql` is the canonical config-file surface. It is a strict
// superset of the legacy REST `/api/*File` endpoints:
//
//   * REST listFiles omits every udoId-addressed dashboard. Measured on a live
//     tenant: REST returned 1,914 paths, GraphQL configFiles returned 2,264.
//     The 350-file gap is entirely /dashboards/ files that carry a udoId, and
//     REST getFile on any of them returns `success/noSuchFile`.
//   * The console's Configuration Files grid renders a udoId dashboard as the
//     display string `/dashboards/id/<udoId>/<name>`. That is NOT a path. Reading
//     it as one returns "no file exists at path". Address it by udoId; its real
//     name is `/dashboards/<name>`.
//
// udoId assignment is by namespace, verified live: only `/dashboards/` files get
// a udoId. `/lookups/`, `/datatables/`, `/logParsers/` and `/automaticLookups`
// all come back with udoId `null` and are addressed by name.
//
// Write rule, verified live: addConfigFile(name:) UPDATES IN PLACE for a
// name-addressed file, but CREATES A DUPLICATE for a dashboard. Always write a
// dashboard by udoId. Skipping that rule is how one tenant accumulated 152
// copies of `/dashboards/AI Usage`.

/** Marks an error as originating from the GraphQL layer rather than the
 *  transport. Absence detection keys off this: a 404 page whose body contains
 *  "not found" must never be read as "the file does not exist". */
class SdlGraphqlError extends Error {
  constructor(message) {
    super(message);
    this.name = 'SdlGraphqlError';
    this.graphql = true;
  }
}

/**
 * POST /sdl/v2/graphql. Returns `data`; throws on the GraphQL `errors` array.
 *
 * GraphQL reports failure as HTTP 200 with an `errors` array, so the status
 * code alone never proves success. Three things this must not do, each of which
 * would resurface the exact false-negative class this module exists to remove:
 *
 *   1. Accept a non-JSON 200. sdlFetch falls back to raw text when JSON.parse
 *      fails, so a proxy interstitial or WAF page arrives as a string. Left
 *      unchecked, `payload.errors` is undefined and every caller returns its
 *      empty default: "no files", "not found", "deleted".
 *   2. Require `errors` to be an array. A bare `{errors: {...}}` object would
 *      slip through an Array.isArray gate.
 *   3. Return a payload carrying neither `data` nor `errors`.
 *
 * `readOnly` opts into status-based retry; only pass it for queries.
 * `scope` sets the S1-Scope header; see resolveScope for precedence.
 */
async function sdlGraphql(opname, query, variables, { readOnly = false, scope } = {}) {
  const body = { query };
  if (variables) body.variables = variables;
  const payload = await sdlFetch(
    'POST',
    `/v2/graphql?opname=${encodeURIComponent(opname)}`,
    { body, allowRetry: readOnly, extraHeaders: scopeHeaders(scope) }
  );

  if (typeof payload !== 'object' || payload === null) {
    throw new Error(
      `SDL GraphQL ${opname}: expected a JSON object, got ${typeof payload}. ` +
      'This usually means a proxy or auth interstitial answered instead of the API. ' +
      `First 200 chars: ${String(payload).slice(0, 200)}`
    );
  }
  if (payload.errors) {
    const errs = Array.isArray(payload.errors) ? payload.errors : [payload.errors];
    const correlationId = payload.extensions?.correlationId ?? errs[0]?.extensions?.correlationId;
    const msg = errs[0]?.message || 'unknown GraphQL error';
    throw new SdlGraphqlError(`SDL GraphQL ${opname} → ${msg}${correlationId ? ` (correlationId=${correlationId})` : ''}`);
  }
  if (!('data' in payload)) {
    throw new SdlGraphqlError(`SDL GraphQL ${opname}: response carried neither data nor errors.`);
  }
  return payload.data;
}

/** udoIds are 16 digits, within ~1.4x of Number.MAX_SAFE_INTEGER. A caller that
 *  sends one as a JSON number has already lost precision before we stringify. */
function assertSafeUdoId(udoId) {
  if (typeof udoId === 'number' && !Number.isSafeInteger(udoId)) {
    throw new Error(
      `udoId ${udoId} exceeds the JS safe-integer range and has already lost precision. Pass it as a string.`
    );
  }
  return String(udoId);
}

const CONFIG_FIELDS = 'udoId name readOnly version';

/** SDL config names are case-insensitive and tolerate stray whitespace, so the
 *  absence check and the duplicate guard must normalise identically. */
function normaliseName(n) {
  return String(n ?? '').trim().toLowerCase();
}
function matchesName(file, name) {
  return normaliseName(file?.name) === normaliseName(name);
}

/** Every config file visible at `scope`, including udoId-addressed dashboards.
 *  This listing IS scope-filtered: a site-scoped dashboard does not appear in an
 *  account-scoped listing and vice versa. */
export async function configFiles({ scope } = {}) {
  const data = await sdlGraphql(
    'getConfigurationFiles',
    `query getConfigurationFiles { configFiles { ${CONFIG_FIELDS} } }`,
    undefined,
    { readOnly: true, scope }
  );
  return data?.configFiles ?? [];
}

/**
 * Read one config file by name (plain files) or udoId (dashboards).
 * Returns null when the file does not exist.
 *
 * Absence is a normal outcome of a lookup, but the server reports it as a
 * GraphQL error, and the message differs by address form (verified live):
 *
 *   by name : "Config file with name /x/y not found."   <- explicit
 *   by udoId: "Something went wrong. Please try again..." <- generic, and the
 *             SAME text a version conflict returns, so it cannot be trusted
 *             on message alone.
 *
 * So the explicit form is normalised directly, and the ambiguous one is
 * disambiguated against the file listing: absent from configFiles means the
 * file is genuinely gone, otherwise the error was real and is rethrown. The
 * extra listing only happens on the error path.
 */
export async function configFile({ name, udoId, scope }) {
  if (!name && !udoId) throw new Error('configFile requires either name or udoId');
  // Validate before the try: an invalid udoId is a caller bug, not a signal
  // that the file is absent, and must never be swallowed by the absence path.
  const safeUdoId = udoId ? assertSafeUdoId(udoId) : null;
  try {
    const data = safeUdoId
      ? await sdlGraphql('configFile', `query f($udoId: ID!) { configFile(udoId: $udoId) { ${CONFIG_FIELDS} content } }`, { udoId: safeUdoId }, { readOnly: true, scope })
      : await sdlGraphql('configFile', `query f($id: ID!) { configFile(id: $id) { ${CONFIG_FIELDS} content } }`, { id: name }, { readOnly: true, scope });
    return data?.configFile ?? null;
  } catch (err) {
    // Only a GraphQL-layer error can mean "absent". A transport failure whose
    // body happens to contain the words "not found" (a 404 page, a WAF block)
    // must never be read as absence: that is how a delete gets confirmed
    // against a file that was never checked.
    if (!err.graphql) throw err;
    if (/config file with (name|id) .* not found/i.test(err.message)) return null;

    // The udoId form returns a generic message that a version conflict also
    // returns, so settle it against the listing. If the listing itself fails,
    // surface the ORIGINAL error with the listing failure attached rather than
    // replacing it.
    // Same scope as the failed lookup. Disambiguating against a DIFFERENT
    // scope's listing would report a site-scoped file as absent purely because
    // the listing was taken at account scope, which is the exact false-negative
    // class this branch exists to remove.
    let all;
    try {
      all = await configFiles({ scope });
    } catch (listErr) {
      err.message += ` (absence check failed: ${listErr.message})`;
      throw err;
    }
    const present = udoId
      ? all.some(f => String(f.udoId) === String(udoId))
      : all.some(f => matchesName(f, name));
    if (!present) return null;
    throw err;
  }
}

/**
 * Create or update a config file.
 *   - udoId given  → updates that file in place; pass expectedVersion to lock.
 *   - name given   → updates in place for plain files, but CREATES A DUPLICATE
 *                    for /dashboards/. Never write a dashboard by name.
 */
export async function putConfigFile({ name, udoId, content, expectedVersion, scope }) {
  if (!name && !udoId) throw new Error('putConfigFile requires either name or udoId');
  // Creating a dashboard must go by name (no udoId exists yet); only an
  // *existing* dashboard is at risk of being duplicated by a name-addressed
  // write. So refuse only when a file of that name already exists.
  if (!udoId && normaliseName(name).startsWith('/dashboards/')) {
    // Scoped to match the write. An account-scoped listing would not see a
    // same-named site-scoped dashboard, so the guard has to look where the
    // write is going, not where the token defaults.
    const all = await configFiles({ scope });
    // An empty listing means the check could not run, not that the name is
    // free. Failing open here would silently disable the guard.
    if (!all.length) {
      throw new Error(
        `Refusing to write "${name}" by name: the configFiles listing came back empty, so the ` +
        'duplicate check could not run. Retry, or pass an explicit udoId.'
      );
    }
    const existing = all.filter(f => matchesName(f, name));
    if (existing.length) {
      const ids = existing.map(f => f.udoId).filter(Boolean).join(', ');
      throw new Error(
        `Refusing to write "${name}" by name: ${existing.length} dashboard(s) already use that name, ` +
        'and a name-addressed write to /dashboards/ creates another duplicate rather than updating. ' +
        `Pass one of these udoIds instead: ${ids || '(none, file has no udoId)'}.`
      );
    }
  }
  // expectedVersion is honoured on BOTH address forms. Verified live 2026-08-07:
  // a stale expectedVersion on a name-addressed /datatables/ write was rejected
  // with "There are conflicting changes in the file." and the content was left
  // untouched. Omitting it here would silently downgrade every parser, lookup,
  // datatable and /automaticLookups write to last-write-wins.
  const data = udoId
    ? await sdlGraphql('addConfigFile',
        `mutation f($udoId: ID, $content: String!, $expectedVersion: Long) { addConfigFile(udoId: $udoId, content: $content, expectedVersion: $expectedVersion) { ${CONFIG_FIELDS} } }`,
        { udoId: assertSafeUdoId(udoId), content, expectedVersion }, { scope })
    : await sdlGraphql('addConfigFile',
        `mutation f($name: String, $content: String!, $expectedVersion: Long) { addConfigFile(name: $name, content: $content, expectedVersion: $expectedVersion) { ${CONFIG_FIELDS} } }`,
        { name, content, expectedVersion }, { scope });
  return data?.addConfigFile ?? null;
}

/**
 * Delete a config file. Dashboards delete by udoId, plain files by name.
 * A null return with no errors array is SUCCESS; the deleted object is not
 * echoed back. Treating that null as a failure is the classic mistake here.
 */
export async function deleteConfigFile({ name, udoId, expectedVersion, scope }) {
  if (!name && !udoId) throw new Error('deleteConfigFile requires either name or udoId');
  const raw = udoId
    ? await sdlGraphql('deleteConfigFile',
        'mutation f($udoId: ID, $expectedVersion: Long) { deleteConfigFile(udoId: $udoId, expectedVersion: $expectedVersion) { udoId } }',
        { udoId: assertSafeUdoId(udoId), expectedVersion }, { scope })
    : await sdlGraphql('deleteConfigFile',
        'mutation f($id: ID, $expectedVersion: Long) { deleteConfigFile(id: $id, expectedVersion: $expectedVersion) { udoId } }',
        { id: name, expectedVersion }, { scope });

  // The mutation returns null on success and does not echo the deleted object,
  // so its response cannot distinguish "deleted" from "matched nothing". Confirm
  // by re-reading. This is the house rule established by uamSetStatus in
  // lib/s1.js: never treat a mutation response as proof, re-get and verify.
  const still = await configFile({ name, udoId, scope });
  if (still) {
    throw new Error(
      `deleteConfigFile: ${udoId ? `udoId ${udoId}` : name} still exists after the delete mutation ` +
      `(version ${still.version}). The mutation reported no errors but nothing was removed.`
    );
  }
  return { status: 'success', deleted: udoId ? { udoId: String(udoId) } : { name }, raw: raw?.deleteConfigFile ?? null };
}

// The legacy REST config-file endpoints (/api/listFiles, /api/getFile,
// /api/putFile) are not wrapped here. They cannot see or modify a
// udoId-addressed dashboard, so their listing is unsafe for any "does this file
// exist" decision. The GraphQL operations above cover every namespace,
// including parsers, lookups, datatables and /automaticLookups.

// ─── Dashboard lifecycle (dashboardsV2, GraphQL) ──────────────────────────────
//
// A SECOND, HIGHER-LEVEL SURFACE on the same `POST /sdl/v2/graphql` endpoint.
// This is what the console itself drives; captured from live console traffic on
// usea1-purple 2026-08-17 (280 requests, 23 operations).
//
// Relationship to the config-file layer above:
//
//   dashboardsV2       dashboard-aware: name, description, tabs, access/sharing,
//                      createdBy/updatedBy, isBuiltIn/isEditable. Create takes
//                      the whole dashboard JSON as one `config` string.
//   configFiles        the raw file underneath, addressed by udoId. Same object,
//                      no sharing or authorship metadata, `content` is the JSON.
//
// The `id` in dashboardsV2 IS the `udoId` in configFiles. Verified: dashboard
// "meta1" is id 6999000578736128 in getDashboardV2 and udoId 6999000578736128
// / name "/dashboards/meta1" in configFile.
//
// WHY THIS EXISTS: creating a dashboard through addConfigFile(name:) files it at
// the request's scope but gives no way to share it elsewhere, and the console's
// own create path is createDashboardV2. Site-level lifecycle needs both this and
// shareResource, which is the ONLY operation that takes an explicit scope target
// rather than inferring one from the request header.
//
// VERSION FIELDS DIFFER, do not cross them. getDashboardV2 returns
// `version: ""` (a display string, empty in practice); configFile returns
// `version: 215771284` (the numeric CAS token). Only the configFile value is
// valid as expectedVersion.

const DASHBOARD_SUMMARY_FIELDS = 'id name description configType access { public users owner }';

/** Every dashboard visible at `scope`, with sharing metadata. Prefer this over
 *  configFiles({pathPrefix:'/dashboards/'}) when you need owner or access. */
export async function listDashboards({ scope } = {}) {
  const data = await sdlGraphql(
    'GetDashboardNames',
    `query GetDashboardNames { dashboardsV2 { ${DASHBOARD_SUMMARY_FIELDS} } }`,
    undefined,
    { readOnly: true, scope }
  );
  return data?.dashboardsV2 ?? [];
}

/**
 * Read one dashboard by id (preferred) or name, including its tabs.
 * Returns null when it does not exist at `scope`.
 *
 * `tabs[].graphs` / `.parameters` / `.filters` / `.options` come back as JSON
 * STRINGS, not objects; the console parses them client-side. Callers that want
 * structure must JSON.parse each one.
 *
 * ABSENCE HANDLING mirrors configFile deliberately. The live capture only shows
 * a successful read, so it is not established whether a missing dashboard comes
 * back as `data.getDashboardV2 = null` or as a GraphQL error. Both are treated
 * as absence, disambiguated against the dashboard listing. Assuming only the
 * null form is what broke every `sdl_delete_file` in 1.3.2: the confirming
 * re-read threw on precisely the success path. A transport-layer error is still
 * rethrown, so a proxy page containing "not found" can never be read as absence.
 */
export async function getDashboard({ id, name, scope }) {
  if (!id && !name) throw new Error('getDashboard requires either id or name');
  const safeId = id ? assertSafeUdoId(id) : undefined;
  try {
    const data = await sdlGraphql(
      'GetDashboardConfigV2',
      `query GetDashboardConfigV2($id: ID, $dashboardName: String) {
         getDashboardV2(id: $id, dashboardName: $dashboardName, resolveParameters: true) {
           id name description configType duration isBuiltIn isEditable version
           access { public users owner }
           tabs { tabName parameters graphs filters options }
           createdAt createdBy updatedAt updatedBy
         }
       }`,
      { id: safeId, dashboardName: name },
      { readOnly: true, scope }
    );
    return data?.getDashboardV2 ?? null;
  } catch (err) {
    if (!err.graphql) throw err;
    let all;
    try {
      all = await listDashboards({ scope });
    } catch (listErr) {
      err.message += ` (absence check failed: ${listErr.message})`;
      throw err;
    }
    const present = safeId
      ? all.some(d => String(d.id) === safeId)
      : all.some(d => normaliseName(d.name) === normaliseName(name));
    if (!present) return null;
    throw err;
  }
}

/**
 * Create a dashboard from a full dashboard-JSON config, at `scope`.
 *
 * This is the console's own create path and it accepts the complete dashboard
 * document (configType, duration, description, tabs[]) as ONE string. That is
 * the important difference from the UI's "new dashboard then paste JSON" flow,
 * which starts from a `{graphs: []}` stub: pasting after the stub instead of
 * replacing it produces `{graphs: []}{...}` and the server rejects it with
 * "Content is invalid json" / "Additional text after JSON object". Going
 * through this function cannot hit that class of error.
 *
 * `isPublic` DEFAULTS TO TRUE, unlike the raw API, which defaults it to false.
 * `access.owner` is set to the calling identity; with a service-account token that
 * is `serviceuser-<uuid>@mgmt-<n>.sentinelone.net`, not a person. A private
 * service-user dashboard is readable through the API and INVISIBLE in the console
 * to the human operator, at any scope, which is indistinguishable from a failed
 * deploy. Verified live: the same config at the same scope became visible purely
 * by recreating it with public true. Pass `isPublic: false` deliberately if the
 * dashboard really should be private to the service account.
 *
 * Names reject punctuation and answer only "Invalid name". Accepted: letters,
 * digits, space, `-`, `_`, `.`, `/`. Rejected: `( ) [ ] { } : , & ' % #`.
 *
 * DUPLICATE NAMES ARE ALLOWED HERE, unlike putConfigFile. The console itself
 * creates "<name> - Copy" siblings, and shareResource addresses dashboards by
 * id, so duplicate names are not the footgun they are for name-addressed
 * config-file writes. Set `failIfNameExists` to opt into the stricter
 * behaviour; it costs one extra listing call.
 */
export async function createDashboard({ name, config, isPublic = true, scope, failIfNameExists = false }) {
  if (!name || typeof name !== 'string') throw new Error('createDashboard requires a name');
  if (typeof config !== 'string' || !config.trim()) {
    throw new Error('createDashboard requires config as a JSON string (the full dashboard document).');
  }
  // Fail before the mutation rather than filing a broken dashboard the console
  // then renders as an empty shell.
  try {
    JSON.parse(config);
  } catch (e) {
    throw new Error(
      `createDashboard: config is not valid JSON (${e.message}). ` +
      'If this came from the console\'s JSON editor, check for a leading "{graphs: []}" stub: ' +
      'the new document must REPLACE it, not follow it.'
    );
  }

  if (failIfNameExists) {
    const existing = (await listDashboards({ scope })).filter(d => normaliseName(d.name) === normaliseName(name));
    if (existing.length) {
      throw new Error(
        `createDashboard: ${existing.length} dashboard(s) named "${name}" already exist at this scope ` +
        `(ids: ${existing.map(d => d.id).join(', ')}). Pass failIfNameExists:false to create a sibling anyway.`
      );
    }
  }

  const data = await sdlGraphql(
    'CreateDashboard',
    `mutation CreateDashboard($dashboardName: String!, $config: String, $public: Boolean) {
       createDashboardV2(dashboardName: $dashboardName, config: $config, public: $public) { id name }
     }`,
    { dashboardName: name, config, public: isPublic },
    { scope }
  );
  const created = data?.createDashboardV2 ?? null;
  if (!created?.id) {
    throw new SdlGraphqlError('createDashboard: mutation returned no id, so the dashboard was not created.');
  }
  return created;
}

/**
 * Share a dashboard to scopes and/or users. THE ONLY OPERATION THAT TAKES AN
 * EXPLICIT SCOPE TARGET; everything else infers scope from the S1-Scope header.
 *
 * `scopes` entries are {scopeType, scopeId, operation}:
 *   scopeType  'site' | 'account' | 'global'
 *   scopeId    the numeric id from /web/api/v2.1/sites or /accounts
 *   operation  'ADD' | 'REMOVE'
 *
 * `scope` (the option, not the array) is still the header for the CALL, i.e.
 * where you are standing when you share. It is independent of the targets.
 */
const VALID_SCOPE_TYPES = new Set(['site', 'account', 'global']);
const VALID_SCOPE_OPS = new Set(['ADD', 'REMOVE']);

export async function shareDashboard({ id, scopes = [], users = [], scope }) {
  if (!id) throw new Error('shareDashboard requires the dashboard id');
  if (!Array.isArray(scopes) || !Array.isArray(users)) {
    throw new Error('shareDashboard: scopes and users must both be arrays.');
  }
  if (!scopes.length && !users.length) {
    throw new Error('shareDashboard: pass at least one scope or user, otherwise the call is a no-op.');
  }
  // Validate up front: the server accepts a malformed entry and silently shares
  // nothing, which reads as success.
  const normalisedScopes = scopes.map((s, i) => {
    const type = String(s?.scopeType ?? '').toLowerCase();
    const op = String(s?.operation ?? 'ADD').toUpperCase();
    if (!VALID_SCOPE_TYPES.has(type)) {
      throw new Error(`shareDashboard: scopes[${i}].scopeType must be one of ${[...VALID_SCOPE_TYPES].join(', ')} (got ${JSON.stringify(s?.scopeType)}).`);
    }
    if (!VALID_SCOPE_OPS.has(op)) {
      throw new Error(`shareDashboard: scopes[${i}].operation must be ADD or REMOVE (got ${JSON.stringify(s?.operation)}).`);
    }
    if (type !== 'global' && !/^\d+$/.test(String(s?.scopeId ?? ''))) {
      throw new Error(`shareDashboard: scopes[${i}].scopeId must be a numeric id for scopeType "${type}" (got ${JSON.stringify(s?.scopeId)}).`);
    }
    return { scopeType: type, scopeId: String(s.scopeId), operation: op };
  });

  const data = await sdlGraphql(
    'ShareDashboard',
    `mutation ShareDashboard($id: ID!, $users: [UserSharingCommand], $scopes: [ScopeSharingCommand]) {
       shareResource(id: $id, users: $users, scopes: $scopes) { id name }
     }`,
    { id: assertSafeUdoId(id), users, scopes: normalisedScopes },
    { scope }
  );
  const shared = data?.shareResource ?? null;
  if (!shared?.id) {
    throw new SdlGraphqlError('shareDashboard: shareResource returned no id, so nothing was shared.');
  }
  return { status: 'success', dashboard: { id: String(shared.id), name: shared.name }, scopes: normalisedScopes, users };
}

/**
 * Replace the panel layout of ONE tab. `graphs` is a JSON string shaped
 * `{"graphs":[...]}` (note the wrapper key; the response echoes a bare array).
 * Use this for incremental panel edits; use createDashboard for a whole document.
 */
export async function saveDashboardLayout({ id, name, tabName, graphs, options, scope }) {
  if (!id && !name) throw new Error('saveDashboardLayout requires either id or name');
  if (typeof graphs !== 'string' || !graphs.trim()) {
    throw new Error('saveDashboardLayout requires graphs as a JSON string, shaped {"graphs":[...]}.');
  }
  try {
    const parsed = JSON.parse(graphs);
    if (!parsed || !Array.isArray(parsed.graphs)) {
      throw new Error('missing the top-level "graphs" array');
    }
  } catch (e) {
    throw new Error(`saveDashboardLayout: graphs is not a valid {"graphs":[...]} JSON string (${e.message}).`);
  }
  const data = await sdlGraphql(
    'SaveDashboardLayout',
    `mutation SaveDashboardLayout($id: ID, $dashboardName: String, $graphs: String, $options: String, $tabName: String) {
       saveDashboardLayout(id: $id, dashboardName: $dashboardName, graphs: $graphs, options: $options, tabName: $tabName) { graphs options }
     }`,
    { id: id ? assertSafeUdoId(id) : undefined, dashboardName: name, graphs, options, tabName },
    { scope }
  );
  return data?.saveDashboardLayout ?? null;
}

/**
 * Delete a dashboard by id or name. `deleteDashboard` returns a bare boolean,
 * so per the house rule the removal is confirmed by re-reading rather than
 * trusted from the mutation response.
 */
export async function deleteDashboard({ id, name, scope }) {
  if (!id && !name) throw new Error('deleteDashboard requires either id or name');
  const data = await sdlGraphql(
    'DeleteDashboard',
    'mutation DeleteDashboard($id: ID, $dashboardName: String) { deleteDashboard(id: $id, dashboardName: $dashboardName) }',
    { id: id ? assertSafeUdoId(id) : undefined, dashboardName: name },
    { scope }
  );
  const reported = data?.deleteDashboard;

  const still = await getDashboard({ id, name, scope });
  if (still) {
    throw new Error(
      `deleteDashboard: ${id ? `id ${id}` : name} still exists after the delete mutation ` +
      `(mutation returned ${JSON.stringify(reported)}). Nothing was removed.`
    );
  }
  return { status: 'success', deleted: id ? { id: String(id) } : { name }, raw: reported ?? null };
}

// ─── V1 Query (schema discovery) ─────────────────────────────────────────────
// Deprecated Feb 15 2027 but still the only way to get full event JSON per-event.
// Use for schema discovery; use LRQ for hunting.

/** POST /api/query: retrieve raw event JSON for schema discovery.
 *  Returns { matches: [{ timestamp, message, attributes }] }. */
export async function v1Query(filter, { maxCount = 5, startTime = '24h', endTime, scope } = {}) {
  const body = {
    queryType: 'log',
    filter,
    maxCount,
    startTime,
  };
  if (endTime) body.endTime = endTime;
  // Read-only POST: opt back into status retry. Schema discovery iterates this
  // once per data source, which is the workload that trips the SDL QPS cap.
  return sdlFetch('POST', '/api/query', { body, allowRetry: true, extraHeaders: scopeHeaders(scope) });
}
