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
 */
async function sdlGraphql(opname, query, variables, { readOnly = false } = {}) {
  const body = { query };
  if (variables) body.variables = variables;
  const payload = await sdlFetch(
    'POST',
    `/v2/graphql?opname=${encodeURIComponent(opname)}`,
    { body, allowRetry: readOnly }
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

/** Every config file on the tenant, including udoId-addressed dashboards. */
export async function configFiles() {
  const data = await sdlGraphql(
    'getConfigurationFiles',
    `query getConfigurationFiles { configFiles { ${CONFIG_FIELDS} } }`,
    undefined,
    { readOnly: true }
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
export async function configFile({ name, udoId }) {
  if (!name && !udoId) throw new Error('configFile requires either name or udoId');
  // Validate before the try: an invalid udoId is a caller bug, not a signal
  // that the file is absent, and must never be swallowed by the absence path.
  const safeUdoId = udoId ? assertSafeUdoId(udoId) : null;
  try {
    const data = safeUdoId
      ? await sdlGraphql('configFile', `query f($udoId: ID!) { configFile(udoId: $udoId) { ${CONFIG_FIELDS} content } }`, { udoId: safeUdoId }, { readOnly: true })
      : await sdlGraphql('configFile', `query f($id: ID!) { configFile(id: $id) { ${CONFIG_FIELDS} content } }`, { id: name }, { readOnly: true });
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
    let all;
    try {
      all = await configFiles();
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
export async function putConfigFile({ name, udoId, content, expectedVersion }) {
  if (!name && !udoId) throw new Error('putConfigFile requires either name or udoId');
  // Creating a dashboard must go by name (no udoId exists yet); only an
  // *existing* dashboard is at risk of being duplicated by a name-addressed
  // write. So refuse only when a file of that name already exists.
  if (!udoId && normaliseName(name).startsWith('/dashboards/')) {
    const all = await configFiles();
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
        { udoId: assertSafeUdoId(udoId), content, expectedVersion })
    : await sdlGraphql('addConfigFile',
        `mutation f($name: String, $content: String!, $expectedVersion: Long) { addConfigFile(name: $name, content: $content, expectedVersion: $expectedVersion) { ${CONFIG_FIELDS} } }`,
        { name, content, expectedVersion });
  return data?.addConfigFile ?? null;
}

/**
 * Delete a config file. Dashboards delete by udoId, plain files by name.
 * A null return with no errors array is SUCCESS; the deleted object is not
 * echoed back. Treating that null as a failure is the classic mistake here.
 */
export async function deleteConfigFile({ name, udoId, expectedVersion }) {
  if (!name && !udoId) throw new Error('deleteConfigFile requires either name or udoId');
  const raw = udoId
    ? await sdlGraphql('deleteConfigFile',
        'mutation f($udoId: ID, $expectedVersion: Long) { deleteConfigFile(udoId: $udoId, expectedVersion: $expectedVersion) { udoId } }',
        { udoId: assertSafeUdoId(udoId), expectedVersion })
    : await sdlGraphql('deleteConfigFile',
        'mutation f($id: ID, $expectedVersion: Long) { deleteConfigFile(id: $id, expectedVersion: $expectedVersion) { udoId } }',
        { id: name, expectedVersion });

  // The mutation returns null on success and does not echo the deleted object,
  // so its response cannot distinguish "deleted" from "matched nothing". Confirm
  // by re-reading. This is the house rule established by uamSetStatus in
  // lib/s1.js: never treat a mutation response as proof, re-get and verify.
  const still = await configFile({ name, udoId });
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

// ─── V1 Query (schema discovery) ─────────────────────────────────────────────
// Deprecated Feb 15 2027 but still the only way to get full event JSON per-event.
// Use for schema discovery; use LRQ for hunting.

/** POST /api/query: retrieve raw event JSON for schema discovery.
 *  Returns { matches: [{ timestamp, message, attributes }] }. */
export async function v1Query(filter, { maxCount = 5, startTime = '24h', endTime } = {}) {
  const body = {
    queryType: 'log',
    filter,
    maxCount,
    startTime,
  };
  if (endTime) body.endTime = endTime;
  // Read-only POST: opt back into status retry. Schema discovery iterates this
  // once per data source, which is the workload that trips the SDL QPS cap.
  return sdlFetch('POST', '/api/query', { body, allowRetry: true });
}
