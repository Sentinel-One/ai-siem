/**
 * SentinelOne client: Mgmt Console REST API, LRQ PowerQuery, Purple AI, UAM GraphQL.
 *
 * Auth patterns:
 *   Mgmt REST API   → Authorization: ApiToken <jwt>
 *   LRQ             → Authorization: Bearer  <jwt>   (same token, different prefix)
 *   Purple AI       → Authorization: ApiToken <jwt>   (POST /web/api/v2.1/graphql)
 *   UAM GraphQL     → Authorization: ApiToken <jwt>   (POST /web/api/v2.1/unifiedalerts/graphql)
 */

import { getCreds, setupHint } from './credentials.js';
import { parseJsonExact } from './json.js';
import { scopeHeaders } from './sdl.js';
import { excludeMetering, firstTopLevelPipe } from './metering.js';

// ─── helpers ──────────────────────────────────────────────────────────────────

export function base() {
  const url = getCreds().S1_CONSOLE_URL.replace(/\/+$/, '');
  if (!url) throw new Error('S1_CONSOLE_URL not configured. ' + setupHint());
  return url;
}

/** The console token (S1_CONSOLE_API_TOKEN). */
export function jwt() {
  const tok = getCreds().S1_CONSOLE_API_TOKEN;
  if (!tok) throw new Error('S1_CONSOLE_API_TOKEN not configured. ' + setupHint());
  return tok;
}

/**
 * Some endpoints (e.g. POST/DELETE /web/api/v2.1/threat-intelligence/iocs)
 * refuse a token whose user spans several accounts with HTTP 403, code
 * 4030010 "This page doesn't support multi-scopes users yet".
 */
export const MULTI_SCOPE_HINT =
  'Hint: error 4030010 means this endpoint refuses a token whose user spans several accounts. ' +
  'Use a console API token minted at a single account or site; store it in its own keychain profile ' +
  '(`s1-secops-mcp setup --profile <name>`) and run a second MCP entry with `S1_PROFILE=<name>` ' +
  '(or make that token your default).';

/** True when a parsed error body carries errors[].code 4030010. */
export function isMultiScopeError(data) {
  return !!(data && typeof data === 'object' && Array.isArray(data.errors) &&
    data.errors.some((e) => Number(e?.code) === 4030010));
}

/**
 * Build a validated absolute URL for an S1 Mgmt API call.
 *
 * SECURITY: `path` frequently originates from an LLM tool call
 * (s1_api_get/post/put/delete/patch) and must never be able to change the
 * request authority. Bare string concatenation (`${base()}${path}`) let a
 * path like "@evil.example/x", ".evil.example/x", or "//evil.example/x"
 * rewrite the host and send the tenant ApiToken to an attacker-chosen origin.
 * We therefore (1) require a leading single "/" and (2) pin the resolved
 * origin to the configured console. Any deviation throws before doFetch runs.
 */
function safeUrl(path) {
  if (typeof path !== 'string' || !path.startsWith('/') || path.startsWith('//')) {
    throw new Error(
      `S1 API path must be a string starting with a single "/" (got: ${JSON.stringify(path)?.slice(0, 80)})`
    );
  }
  const origin = new URL(base()).origin;
  const u = new URL(path, origin);
  if (u.origin !== origin) {
    throw new Error(`S1 API path may not change the request origin (resolved to ${u.origin})`);
  }
  return u;
}

async function doFetch(url, opts, retries = 3, { allowRetry = null } = {}) {
  // Status-based retry is restricted to idempotent methods (GET/HEAD) unless the
  // caller opts in: a 5xx received after the server committed a write would
  // otherwise be re-POSTed (duplicate rules/notes/ingestion). Fixed 2026-07-29,
  // mirroring the same fix in scripts/s1_client.py.
  const method = (opts.method || 'GET').toUpperCase();
  const methodRetryable = allowRetry !== null ? allowRetry : (method === 'GET' || method === 'HEAD');
  let delay = 500;
  for (let attempt = 0; attempt <= retries; attempt++) {
    let res;
    try {
      res = await fetch(url, opts);
    } catch (err) {
      if (attempt === retries) throw err;
      await sleep(delay);
      delay = Math.min(delay * 2, 8000);
      continue;
    }

    // Retry on 429 / 5xx (idempotent methods, or explicit opt-in, only)
    if ((res.status === 429 || res.status >= 500) && attempt < retries && methodRetryable) {
      // Retry-After may be missing or an HTTP date. Number(null) is 0, so a
      // missing header must not be treated as "wait 0ms": only honor the
      // header when the raw value is present and parses to a finite number.
      const raRaw = res.headers.get('Retry-After');
      const ra = Number(raRaw);
      const wait = raRaw && Number.isFinite(ra) && ra >= 0 ? Math.min(ra * 1000, 30000) : delay;
      await sleep(wait);
      delay = Math.min(delay * 2, 8000);
      continue;
    }

    const text = await res.text();
    let data;
    try { data = parseJsonExact(text); } catch { data = text; }

    if (!res.ok) {
      const msg = typeof data === 'object' ? (data?.errors?.[0]?.detail || data?.errors?.[0]?.message || JSON.stringify(data)) : text;
      const hint = res.status === 403 && isMultiScopeError(data) ? ` ${MULTI_SCOPE_HINT}` : '';
      throw new Error(`S1 API ${opts.method || 'GET'} ${url} → ${res.status}: ${msg}${hint}`);
    }
    return data;
  }
}

function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}

// ─── Mgmt REST API ────────────────────────────────────────────────────────────

/** GET /web/api/v2.1/<path> */
export async function apiGet(path, params = {}) {
  const u = safeUrl(path);
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null) u.searchParams.set(k, String(v));
  }
  return doFetch(u.toString(), {
    method: 'GET',
    headers: {
      Authorization: `ApiToken ${jwt()}`,
      'Content-Type': 'application/json',
    },
  });
}

/** POST /web/api/v2.1/<path>.
 *  Pass { allowRetry: true } ONLY for read-only POSTs (GraphQL queries, Purple AI
 *  launches, validate endpoints); mutating POSTs must not auto-retry on 5xx. */
export async function apiPost(path, body = {}, { allowRetry = false } = {}) {
  return doFetch(safeUrl(path).toString(), {
    method: 'POST',
    headers: {
      Authorization: `ApiToken ${jwt()}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(body),
  }, 3, { allowRetry });
}

/** PUT /web/api/v2.1/<path> */
export async function apiPut(path, body = {}) {
  return doFetch(safeUrl(path).toString(), {
    method: 'PUT',
    headers: {
      Authorization: `ApiToken ${jwt()}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(body),
  });
}

/** DELETE /web/api/v2.1/<path> */
export async function apiDelete(path, body = {}) {
  return doFetch(safeUrl(path).toString(), {
    method: 'DELETE',
    headers: {
      Authorization: `ApiToken ${jwt()}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(body),
  });
}

/** PATCH /web/api/v2.1/<path> */
export async function apiPatch(path, body = {}) {
  return doFetch(safeUrl(path).toString(), {
    method: 'PATCH',
    headers: {
      Authorization: `ApiToken ${jwt()}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(body),
  });
}

const DOWNLOAD_TIMEOUT_MS = Math.max(1000, Number(process.env.S1_DOWNLOAD_TIMEOUT_MS) || 10 * 60 * 1000);
const DOWNLOAD_MAX_BYTES = Math.max(1, Number(process.env.S1_DOWNLOAD_MAX_BYTES) || 1024 * 1024 * 1024);

/**
 * GET a binary resource (file fetch, export ZIP, etc). Returns
 * { buffer, contentType, contentDisposition, status }. Same origin pinning as
 * every other call; GET is retried on 429/5xx.
 */
export async function apiGetBinary(path, params = {}) {
  const u = safeUrl(path);
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null) u.searchParams.set(k, String(v));
  }
  let delay = 500;
  for (let attempt = 0; attempt <= 3; attempt++) {
    let res;
    try {
      res = await fetch(u.toString(), {
        method: 'GET',
        headers: { Authorization: `ApiToken ${jwt()}` },
        signal: AbortSignal.timeout(DOWNLOAD_TIMEOUT_MS),
      });
    } catch (e) {
      if (e?.name === 'TimeoutError') throw new Error(`S1 API GET ${u.pathname} timed out after ${DOWNLOAD_TIMEOUT_MS / 1000} s`);
      if (attempt === 3) throw e;
      await sleep(delay); delay = Math.min(delay * 2, 8000); continue;
    }
    if ((res.status === 429 || res.status >= 500) && attempt < 3) {
      await sleep(delay); delay = Math.min(delay * 2, 8000); continue;
    }
    if (!res.ok) {
      const text = await res.text().catch(() => '');
      let parsed = null;
      try { parsed = JSON.parse(text); } catch { /* not JSON */ }
      const hint = res.status === 403 && isMultiScopeError(parsed) ? ` ${MULTI_SCOPE_HINT}` : '';
      throw new Error(`S1 API GET ${u.pathname} → ${res.status}: ${text.slice(0, 500)}${hint}`);
    }
    const declared = Number(res.headers.get('Content-Length'));
    if (Number.isFinite(declared) && declared > DOWNLOAD_MAX_BYTES) {
      await res.body?.cancel().catch(() => {});
      throw new Error(`S1 API GET ${u.pathname}: response is ${declared} bytes, over the ${DOWNLOAD_MAX_BYTES}-byte limit (S1_DOWNLOAD_MAX_BYTES)`);
    }
    // Read with a running cap so a server that omits Content-Length cannot
    // exhaust memory.
    const chunks = [];
    let total = 0;
    for await (const chunk of res.body) {
      total += chunk.length;
      if (total > DOWNLOAD_MAX_BYTES) throw new Error(`S1 API GET ${u.pathname}: response exceeded the ${DOWNLOAD_MAX_BYTES}-byte limit (S1_DOWNLOAD_MAX_BYTES)`);
      chunks.push(Buffer.from(chunk));
    }
    const buffer = Buffer.concat(chunks, total);
    return {
      buffer,
      status: res.status,
      contentType: res.headers.get('Content-Type') || '',
      contentDisposition: res.headers.get('Content-Disposition') || '',
    };
  }
}

// ─── LRQ PowerQuery ───────────────────────────────────────────────────────────
// POST <console>/sdl/v2/api/queries with Bearer auth (same JWT, different prefix)
// Must echo X-Dataset-Query-Forward-Tag on every subsequent GET/DELETE.
// Poll every 1s; query expires 30s after last poll. Always cancel after use.

/** Resolve the LRQ time window. Each bound defaults INDEPENDENTLY, per the tool schema.
 *  Bug fixed 2026-07-29: the old `if (!startTime || !endTime)` overwrote BOTH bounds
 *  whenever either was missing, so a call with only startTime silently ran over the
 *  last `hours` instead of the requested window (plausible-but-wrong results).
 *  Demonstrated live: startTime-only for a 7.4-day window returned 12,880 events
 *  (== the 24h control, 12,875) vs 73,099 for the true pinned window. */
export function resolveLrqWindow({ startTime, endTime, hours = 24 } = {}) {
  const iso = (d) => d.toISOString().replace(/\.\d+Z$/, 'Z');
  if (!endTime) endTime = iso(new Date());
  if (!startTime) startTime = iso(new Date(new Date(endTime) - hours * 3600 * 1000));
  return { startTime, endTime };
}

/** matchCount lives inside the data block on current engines; top-level is a legacy
 *  fallback. Fixed 2026-07-29: reading only result.matchCount returned null on every
 *  live call, breaking the 0-rows-vs-0-matches triage. */
export function pickMatchCount(result) {
  const d = (result && result.data) || {};
  return d.matchCount ?? (result && result.matchCount) ?? null;
}

/** Run a full LRQ PowerQuery lifecycle. Returns { columns, rows, rowCount, matchCount }. */
export async function lrqRun(query, { startTime, endTime, hours = 24, maxRows = 5000, scope, includeMetering = false, edrStrict = false, queryType = 'PQ', logLimit = 5000 } = {}) {
  const b = base();
  const tok = jwt();
  if (!['PQ', 'LOG'].includes(queryType)) throw new Error(`queryType must be "PQ" or "LOG" (got ${queryType})`);
  const isLog = queryType === 'LOG';
  if (isLog && firstTopLevelPipe(String(query)) !== -1) {
    throw new Error('queryType "LOG" takes a filter expression only (no pipes or commands), e.g. dataSource.name=\'X\' * contains \'evil.com\'. Use queryType "PQ" for pipelines.');
  }

  // Exclude SDL ingest-metering rows (tag='logVolume') unless asked not to; see lib/metering.js.
  // Not with edrStrict: scheme=edr validates every field against the EDR schema,
  // `tag` is not an EDR field (HTTP 400 "Unknown EDR field 'tag'"), and EDR
  // events carry no metering rows anyway.
  const metering = includeMetering
    ? { query, applied: false, reason: 'includeMetering=true' }
    : (edrStrict && !isLog)
      ? { query, applied: false, reason: 'edrStrict=true: EDR events have no metering rows, and tag is not an EDR field' }
      : excludeMetering(query);
  query = metering.query;

  ({ startTime, endTime } = resolveLrqWindow({ startTime, endTime, hours }));

  const launchUrl = `${b}/sdl/v2/api/queries`;
  const launchBody = isLog
    ? {
        queryType: 'LOG', tenant: true, startTime, endTime, queryPriority: 'HIGH',
        // log.limit is the server-side row cap (typically max 5000). A result that
        // returns exactly this many rows was truncated; there is no page 2.
        log: { filter: query, limit: Math.max(1, Math.min(Number(logLimit) || 5000, 5000)) },
      }
    : {
        queryType: 'PQ', tenant: true, startTime, endTime, queryPriority: 'HIGH',
        pq: { query, resultType: 'TABLE' },
      };
  // Top-level scheme=edr (platform S-26.2.6): an unknown or wrongly cased EDR field is
  // HTTP 400 "Unknown EDR field" instead of a silent matchCount=0. It must be top level;
  // inside pq it is HTTP 400 "Invalid JSON". Correct fields return the same rows.
  if (edrStrict && !isLog) launchBody.scheme = 'edr';

  // S1-Scope applies to log reads exactly as it does to config reads: an LRQ
  // run without the intended scope silently answers for the token default.
  const scopeHdrs = scopeHeaders(scope);

  // Launch. A launch only creates a read-only query, so retrying a 429/5xx is
  // safe; measured limits put 429s on launches only (never polls or cancels).
  async function launch() {
    let launchRes;
    let backoff = 1000;
    for (let attempt = 0; ; attempt++) {
      launchRes = await fetch(launchUrl, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${tok}`,
          'Content-Type': 'application/json',
          ...scopeHdrs,
        },
        body: JSON.stringify(launchBody),
      });
      // Not a plain 500: SDL answers some invalid queries (e.g. `field == null`)
      // with HTTP 500, and retrying those only turns a 0.5 s error into 18 s.
      if ([429, 502, 503, 504].includes(launchRes.status) && attempt < 4) {
        await launchRes.text().catch(() => '');
        await sleep(backoff + Math.floor(Math.random() * 250));
        backoff = Math.min(backoff * 2, 8000);
        continue;
      }
      break;
    }

    if (!launchRes.ok) {
      const body = await launchRes.text();
      throw new Error(`LRQ launch failed (${launchRes.status}): ${body}`);
    }

    const forwardTag = launchRes.headers.get('X-Dataset-Query-Forward-Tag');
    const launched = parseJsonExact(await launchRes.text());
    const id = launched.id;
    if (!id) throw new Error(`LRQ launch returned no id: ${JSON.stringify(launched)}`);
    return {
      queryId: id,
      pollHeaders: {
        Authorization: `Bearer ${tok}`,
        'Content-Type': 'application/json',
        ...scopeHdrs,
        ...(forwardTag ? { 'X-Dataset-Query-Forward-Tag': forwardTag } : {}),
      },
    };
  }

  const cancel = async (id, headers) => {
    try {
      await fetch(`${b}/sdl/v2/api/queries/${id}`, { method: 'DELETE', headers });
    } catch { /* best effort */ }
  };

  let { queryId, pollHeaders } = await launch();

  // Poll until done (30s expiry, poll every 1s)
  let lastStepSeen = 0;
  let result = null;
  let pollDelay = 1000;
  let relaunched = false;
  const deadline = Date.now() + 5 * 60 * 1000; // 5 min hard timeout

  try {
    while (Date.now() < deadline) {
      await sleep(pollDelay);
      const pollUrl = `${b}/sdl/v2/api/queries/${queryId}?lastStepSeen=${lastStepSeen}`;
      let pollRes;
      try {
        pollRes = await fetch(pollUrl, { method: 'GET', headers: pollHeaders });
      } catch (err) {
        // Transient network error; keep polling
        continue;
      }

      if (!pollRes.ok) {
        const body = await pollRes.text().catch(() => '');
        // A transient 429/5xx on a single poll must not cancel a running
        // query: keep polling (doubling the interval up to 5s, still well
        // under the 30s poll-expiry window) until the 5-minute deadline.
        if (pollRes.status === 429 || pollRes.status >= 500) {
          pollDelay = Math.min(pollDelay * 2, 5000);
          continue;
        }
        // A 404 "Requested token=... not found" means the backend lost the
        // query (observed live in three A/B regression runs, 2026-10-07/08;
        // relaunching the same query succeeded 3/3). The query is read-only,
        // so relaunch it once and poll the new id. A second 404 is fatal.
        if (pollRes.status === 404 && !relaunched && /not found/i.test(body)) {
          relaunched = true;
          await cancel(queryId, pollHeaders);
          ({ queryId, pollHeaders } = await launch());
          lastStepSeen = 0;
          pollDelay = 1000;
          continue;
        }
        // Other 4xx responses are permanent and remain fatal.
        throw new Error(`LRQ poll failed (${pollRes.status}): ${body}${relaunched ? ' (after one relaunch)' : ''}`);
      }
      pollDelay = 1000; // healthy poll: restore the normal interval

      // Exact parse: PQ results can carry ids and nanosecond timestamps beyond 2^53.
      const state = parseJsonExact(await pollRes.text());
      lastStepSeen = state.stepsCompleted ?? lastStepSeen;

      const done = state.stepsTotal > 0 && state.stepsCompleted >= state.stepsTotal;
      if (done) {
        result = state;
        break;
      }
    }
  } finally {
    // Always cancel to release quota
    await cancel(queryId, pollHeaders);
  }

  if (!result) throw new Error('LRQ timed out after 5 minutes');

  const data = result.data || {};

  if (isLog) {
    const all = data.matches || [];
    const cap = launchBody.log.limit;
    return {
      queryType: 'LOG',
      matches: all.slice(0, maxRows),
      rowCount: Math.min(all.length, maxRows),
      totalRows: all.length,
      logLimit: cap,
      // Exactly `limit` rows means the server cap truncated the window.
      truncatedByServerCap: all.length >= cap,
      estimatedMatchCount: data.estimatedMatchCount ?? null,
      matchCount: pickMatchCount(result),
      queryId,
      startTime, endTime,
      meteringExcluded: metering.applied,
      ...(metering.applied ? { effectiveQuery: query } : { meteringNote: metering.reason }),
    };
  }
  const columns = data.columns || [];
  const rawRows = data.values || [];

  // Cap rows
  // Confirmed: LRQ API returns columns as descriptor objects {name, cellType, ...}, not strings.
  // Must use col.name (not col itself) as the row key, col.toString() produces "[object Object]".
  const rows = rawRows.slice(0, maxRows).map(r => {
    const obj = {};
    columns.forEach((col, i) => { obj[col.name ?? col] = r[i]; });
    return obj;
  });

  return {
    columns,
    rows,
    rowCount: rows.length,
    totalRows: rawRows.length,
    matchCount: pickMatchCount(result),
    queryId,
    meteringExcluded: metering.applied,
    ...(metering.applied ? { effectiveQuery: query } : { meteringNote: metering.reason }),
  };
}

// ─── Purple AI ────────────────────────────────────────────────────────────────
// Reverse-engineered from live network traffic on usea1-acme.sentinelone.net.
//
// Endpoints:
//   Purple AI LLM  → POST /web/api/v2.1/graphql       (ApiToken auth)
//   SDL/History    → POST <base>/sdl/v2/graphql        (Bearer auth, same token)
//
// The dead exports purpleAiQuery and purpleAiInvestigate were deleted
// 2026-07-31. Their MCP tools were removed 2026-05-03: purpleLaunchQuery
// NATURAL_LANGUAGE and aiInvestigation/run both require a browser-session
// teamToken that service-account API tokens never obtain (AsimovError /
// SERVICE_ERROR). purpleAlertSummary (ALERT_ENTRY) has no such limitation.

/**
 * Get a Purple AI natural-language summary for a specific UAM alert.
 *
 * Calls purpleAlertSummary (separate operation from purpleLaunchQuery).
 * The inputAlert must be the OCSF-serialised alert JSON string.
 * Returns { token, summary }
 */
export async function purpleAlertSummary(alertOcsfJson, { userDetails = null } = {}) {
  const consoleUrl = `${base()}/`;

  const gqlBody = {
    operationName: 'AlertSummary',
    variables: {
      request: {
        isAsync: false,
        contentType: 'ALERT_ENTRY',
        inputAlert: typeof alertOcsfJson === 'string' ? alertOcsfJson : JSON.stringify(alertOcsfJson),
        userDetails: userDetails || {
          teamToken: '',
          accountId:   '',
          userAgent:   's1-secops-mcp/1.0',
          buildDate:   new Date().toISOString(),
          buildHash:   '',
          emailAddress: '',
        },
        consoleDetails: {
          baseUrl: consoleUrl,
          version: 'S-26.1.3#69',
        },
      },
    },
    query: `
      query AlertSummary($request: PurpleAlertSummaryRequest!) {
        purpleAlertSummary(request: $request) {
          token
          result { summary }
        }
      }
    `,
  };

  const data = await apiPost('/web/api/v2.1/graphql', gqlBody, { allowRetry: true }); // read-only summary
  if (data.errors?.length) throw new Error(`Purple AI AlertSummary error: ${data.errors[0].message}`);

  const pas = data?.data?.purpleAlertSummary || {};
  return {
    token:   pas.token || null,
    summary: pas.result?.summary || null,
  };
}

// ─── UAM GraphQL ─────────────────────────────────────────────────────────────

/** Execute a raw UAM GraphQL operation. */
export async function uamGraphql(query, variables = {}, operationName, { readOnly = false, opname = false } = {}) {
  const body = { operationName, variables, query };
  if (!operationName) delete body.operationName;
  // opname=true appends ?opname=<operationName>, as the console does on every
  // UAM call (HAR 2026-10-07). The server does not require it; it only labels
  // the request.
  const path = '/web/api/v2.1/unifiedalerts/graphql'
    + (opname && operationName ? `?opname=${encodeURIComponent(operationName)}` : '');
  // readOnly=true (list/get queries) re-enables 429/5xx retry, which is safe
  // for GraphQL reads; mutations (addNote, alertTriggerActions) must not auto-retry.
  const data = await apiPost(path, body, { allowRetry: readOnly });
  if (data.errors?.length) {
    throw new Error(`UAM GraphQL error: ${data.errors[0].message}`);
  }
  return data.data;
}

/**
 * List UAM alerts using the correct `filters: [FilterInput!]` schema.
 *
 * IMPORTANT: The `alerts` query takes `filters: [FilterInput!]` (flat AND-joined list).
 * Do NOT pass `filter: String` or `OrFilterSelectionInput`: those belong to mutations only.
 *
 * Each FilterInput is: { fieldId, <comparator>: <value> }
 * Valid comparators (confirmed via introspection):
 *   stringEqual, stringIn, booleanEqual, booleanIn,
 *   intEqual, intIn, intRange,
 *   longEqual, longIn, longRange,
 *   dateTimeRange, match (fulltext)
 * For dates: dateTimeRange: { start: <epoch_ms>, end: <epoch_ms> }
 *   NOT dateRange, NOT date_range, NOT { from, to }
 *
 * Purple MCP bug: its search_alerts sends date_range (snake_case) → UAM rejects.
 * Use this function instead for time-scoped searches.
 */
export async function uamListAlerts({
  first = 20,
  after = null,
  viewType = 'ALL',
  // Convenience: status / severity / detectionProduct strings → auto-built FilterInputs
  status = null,           // e.g. 'OPEN', 'IN_PROGRESS'
  severity = null,         // e.g. 'CRITICAL', 'HIGH'
  detectionProduct = null, // e.g. 'EDR', 'STAR'
  searchText = null,       // fullText search across all fields
  // Time range: specify either ISO strings OR epoch ms; both become dateRange { from, to }
  startTime = null,        // ISO string "2026-05-03T07:32:00Z" or epoch ms number
  endTime = null,          // ISO string or epoch ms; defaults to now when startTime is set
  // Raw FilterInput list: overrides all convenience params above when provided
  filters = null,
} = {}) {

  // Build filters array
  let builtFilters = filters;
  if (!builtFilters) {
    builtFilters = [];

    if (status) {
      builtFilters.push({ fieldId: 'status', stringEqual: { value: status } });
    }
    if (severity) {
      builtFilters.push({ fieldId: 'severity', stringEqual: { value: severity } });
    }
    if (detectionProduct) {
      builtFilters.push({ fieldId: 'detectionProduct', stringEqual: { value: detectionProduct } });
    }
    if (searchText) {
      builtFilters.push({ fieldId: 'alertName', match: { value: [searchText] } }); // fieldId '*' is rejected live; alertName verified 2026-10-08
    }
    if (startTime !== null) {
      // Convert ISO string to epoch ms if needed
      const fromMs = typeof startTime === 'number' ? startTime : new Date(startTime).getTime();
      const toMs = endTime
        ? (typeof endTime === 'number' ? endTime : new Date(endTime).getTime())
        : Date.now();
      // Correct FilterInput field: dateTimeRange { start, end }, NOT dateRange, NOT date_range
      builtFilters.push({ fieldId: 'detectedAt', dateTimeRange: { start: fromMs, end: toMs } });
    }
  }

  const variables = {
    first,
    ...(after ? { after } : {}),
    ...(builtFilters.length ? { filters: builtFilters } : {}),
    viewType,
  };

  const query = `
    query ListAlerts($first: Int, $after: String, $filters: [FilterInput!], $viewType: ViewType) {
      alerts(first: $first, after: $after, filters: $filters, viewType: $viewType) {
        pageInfo { hasNextPage endCursor }
        totalCount
        edges {
          node {
            id
            severity
            status
            createdAt
            updatedAt
            detectedAt
            name
            description
            externalId
            storylineId
            noteExists
            confidenceLevel
            primaryIndicatorType
            assignee { fullName email }
          }
        }
      }
    }
  `;
  const data = await uamGraphql(query, variables, undefined, { readOnly: true });
  const edges = data?.alerts?.edges || [];
  return {
    alerts: edges.map(e => e.node),
    totalCount: data?.alerts?.totalCount ?? null,
    pageInfo: data?.alerts?.pageInfo || {},
  };
}

/**
 * Get a single UAM alert with notes.
 * Fetches alert detail and notes in parallel (history is a separate paginated connection).
 * Confirmed field list via __type introspection on UnifiedAlertDetail and AlertNote.
 */
export async function uamGetAlert(alertId) {
  const [alertData, notesData] = await Promise.all([
    uamGraphql(`
      query GetAlert($id: ID!) {
        alert(id: $id) {
          id severity status createdAt updatedAt detectedAt
          name description externalId storylineId noteExists
          confidenceLevel primaryIndicatorType analystVerdict result ticketId
          assignee { userId fullName email }
          detectionSource { product vendor }
        }
      }
    `, { id: alertId }, undefined, { readOnly: true }),
    uamGraphql(`
      query GetAlertNotes($id: ID!) {
        alertNotes(alertId: $id) {
          data { id text type createdAt updatedAt author { fullName email } }
        }
      }
    `, { id: alertId }, undefined, { readOnly: true }),
  ]);
  const alert = alertData?.alert || null;
  if (alert) {
    alert.notes = notesData?.alertNotes?.data || [];
  }
  return alert;
}

/**
 * Add an analyst note to a UAM alert.
 * Confirmed mutation signature: addAlertNote(alertId: ID!, text: String!, type: ContentType)
 * Returns AlertNotesListResponse.data (all notes for the alert after adding).
 */
export async function uamAddNote(alertId, noteText) {
  const query = `
    mutation AddNote($alertId: ID!, $text: String!) {
      addAlertNote(alertId: $alertId, text: $text, type: PLAIN_TEXT) {
        data { id text type createdAt updatedAt author { fullName email } }
      }
    }
  `;
  const data = await uamGraphql(query, { alertId, text: noteText });
  const notes = data?.addAlertNote?.data || [];
  // Fixed 2026-07-29: do not assume list ordering (newest-last was unverified).
  // Prefer the note whose text matches what we just posted; tiebreak/fallback on
  // the newest createdAt.
  const pool = notes.filter(n => n?.text === noteText);
  const candidates = pool.length ? pool : notes;
  return candidates.reduce((best, n) => {
    if (!best) return n;
    return new Date(n?.createdAt || 0) >= new Date(best?.createdAt || 0) ? n : best;
  }, null);
}

/**
 * What actions does the API say this caller may trigger on this alert?
 *
 * The authoritative capability answer, and the thing to consult before
 * explaining any refused action. Returns the raw list, each entry carrying
 * `{id, title, type, isDisabled, disabledReason}`.
 *
 * `alertAvailableActions` needs a non-null `scope`, unlike alertTriggerActions,
 * so account ids are resolved first. Availability is scope-sensitive (measured:
 * the S1/incident/* actions report
 * INCIDENT_ACTIONS_ONLY_AVAILABLE_FROM_SITE_VIEW under ACCOUNT scope and are
 * enabled under SITE), so pass `scope` explicitly when you care about a
 * site-scoped action.
 */
export async function uamAvailableActions(alertId, scope) {
  let resolved = scope;
  if (!resolved) {
    const accts = await apiGet('/web/api/v2.1/accounts', { limit: 100 });
    const ids = (accts?.data || []).map((a) => a.id).filter(Boolean);
    if (!ids.length) throw new Error('no accounts visible to this token');
    resolved = { scopeIds: ids, scopeType: 'ACCOUNT' };
  }
  const query = `
    query AvailableActions($scope: ScopeSelectorInput!, $filter: OrFilterSelectionInput) {
      alertAvailableActions(scope: $scope, filter: $filter) {
        data { id title type isDisabled disabledReason }
        errors { errorMessage }
      }
    }
  `;
  const variables = {
    scope: resolved,
    filter: { or: [{ and: [{ fieldId: 'id', stringEqual: { value: alertId } }] }] },
  };
  const data = await uamGraphql(query, variables, undefined, { readOnly: true });
  return data?.alertAvailableActions?.data || [];
}

// ─── UAM alert management: status, analyst verdict, assignee ────────────────
//
// Every write goes through alertTriggerActions exactly as the console sends it
// (captured from a console HAR on 2026-10-07, S-26.3.x): operationName
// "AlertTriggerActions", ?opname= on the URL, variables
// {scope: {scopeIds:[<alert's account id>], scopeType:"ACCOUNT"},
//  filter: {or:[{and:[{fieldId:"id", stringEqual:{value:<alertId>}}]}]},
//  viewType: "ALL", actions: [{id, payload}]}, one action per call.
//
// ActionsTriggered is an acknowledgement, not a result: a refused write comes
// back with the alert id under actions[].failure[] and the same __typename.
// So every write here (1) reads the alert first (state + scope), (2) inspects
// success/skip/failure, and (3) re-reads the alert until the field shows the
// requested value, failing loudly if it never does.

/** Status enum (introspected 2026-10-08: enum Status). */
export const UAM_STATUSES = Object.freeze(['NEW', 'IN_PROGRESS', 'RESOLVED']);

/**
 * AnalystVerdict enum (introspected 2026-10-08; identical to the
 * S1/alert/analystVerdictUpdate tree the console renders from
 * alertAvailableActions). TRUE_POSITIVE and FALSE_POSITIVE are tree group
 * headers in the console, not values, and SUSPICIOUS does not exist.
 */
export const UAM_ANALYST_VERDICTS = Object.freeze([
  'UNDEFINED',
  'TRUE_POSITIVE_MALWARE',
  'TRUE_POSITIVE_UNAUTHORIZED_ACCESS',
  'TRUE_POSITIVE_DATA_EXFILTRATION',
  'TRUE_POSITIVE_INSIDER_THREAT',
  'TRUE_POSITIVE_PHISHING_ATTACK',
  'TRUE_POSITIVE_ADVANCED_PERSISTENT_THREAT',
  'TRUE_POSITIVE_DENIAL_OF_SERVICE',
  'TRUE_POSITIVE_RANSOMWARE',
  'TRUE_POSITIVE_POLICY_VIOLATION',
  'TRUE_POSITIVE_BENIGN_BUT_SUSPICIOUS',
  'TRUE_POSITIVE_BENIGN',
  'TRUE_POSITIVE_UNDEFINED',
  'TRUE_POSITIVE_EXPLOITATION_TOOLS',
  'TRUE_POSITIVE_PUA_ADWARE',
  'FALSE_POSITIVE_BENIGN',
  'FALSE_POSITIVE_BENIGN_BUT_SUSPICIOUS',
  'FALSE_POSITIVE_SYSTEM_ERROR',
  'FALSE_POSITIVE_USER_ERROR',
  'FALSE_POSITIVE_UNDEFINED',
]);

export const UAM_ACTIONS = Object.freeze({
  status: 'S1/alert/statusUpdate',
  verdict: 'S1/alert/analystVerdictUpdate',
  assign: 'S1/alert/assignUser',
});

/** The console's alertTriggerActions document, verbatim (HAR 2026-10-07). */
export const ALERT_TRIGGER_ACTIONS_MUTATION = `fragment TriggeredActionSkipDetail on TriggeredActionSkipDetail {
  id
  __typename
}

fragment TriggeredActionFailureDetail on TriggeredActionFailureDetail {
  id
  errorMessage
  errorType
  __typename
}

fragment TriggeredActionSuccessDetail on TriggeredActionSuccessDetail {
  id
  __typename
}

fragment ActionsTriggered on ActionsTriggered {
  actions {
    actionId
    skip {
      ...TriggeredActionSkipDetail
      __typename
    }
    failure {
      ...TriggeredActionFailureDetail
      __typename
    }
    success {
      ...TriggeredActionSuccessDetail
      __typename
    }
    __typename
  }
  __typename
}

fragment ActionsErrorLimitPayload on ActionsErrorLimitPayload {
  limit
  __typename
}

fragment ActionsErrorPayload on ActionsErrorPayload {
  ...ActionsErrorLimitPayload
  __typename
}

fragment TriggerActionsError on TriggerActionsError {
  errors {
    errorMessage
    errorPayload {
      ...ActionsErrorPayload
      __typename
    }
    __typename
  }
  __typename
}

fragment TriggerActionsScheduled on TriggerActionsScheduled {
  bulkActionTriggerId
  __typename
}

mutation AlertTriggerActions($scope: ScopeSelectorInput, $filter: OrFilterSelectionInput, $actions: [TriggerActionInput!]!, $viewType: ViewType) {
  alertTriggerActions(
    filter: $filter
    scope: $scope
    actions: $actions
    viewType: $viewType
  ) {
    ...ActionsTriggered
    ...TriggerActionsError
    ...TriggerActionsScheduled
    __typename
  }
}`;

/**
 * Variables for one alertTriggerActions call, in the console's key order:
 * scope, filter, viewType, actions. Exported so tests and the lifecycle
 * script can compare them with the HAR.
 */
export function buildAlertTriggerActionsVariables(alertId, actionId, payload, scope) {
  return {
    scope,
    filter: { or: [{ and: [{ fieldId: 'id', stringEqual: { value: alertId } }] }] },
    viewType: 'ALL',
    actions: [{ id: actionId, payload }],
  };
}

/** The fields the write path reads and verifies, plus the alert's own scope. */
export async function uamAlertState(alertId) {
  const data = await uamGraphql(`
    query AlertState($id: ID!) {
      alert(id: $id) {
        id name status analystVerdict
        assignee { userId email fullName }
        detectionSource { product vendor }
        realTime { scope { account { id } site { id } } }
      }
    }
  `, { id: alertId }, 'AlertState', { readOnly: true });
  return data?.alert || null;
}

async function allAccountsScope() {
  const accts = await apiGet('/web/api/v2.1/accounts', { limit: 100 });
  const ids = (accts?.data || []).map((a) => a.id).filter(Boolean);
  if (!ids.length) throw new Error('no accounts visible to this token');
  return { scopeIds: ids, scopeType: 'ACCOUNT' };
}

/**
 * Which "Unified Alerts > <group>: Manage" permission an alert type needs.
 * STAR is certain (console RBAC: "STAR Alerts: Manage = Run actions on custom
 * rule alerts"); the others follow the same RBAC table by detection product.
 */
export function uamManageGroupFor(product) {
  const p = String(product || '');
  if (/^STAR$/i.test(p)) return 'STAR Alerts';
  if (/^EDR$|endpoint/i.test(p)) return 'Endpoint Alerts';
  if (/identity|ranger/i.test(p)) return 'Identity Alerts';
  if (/mobile/i.test(p)) return 'Mobile Alerts';
  return 'Generic Alerts';
}

/**
 * Best effort: read the calling user's role and list the Unified Alerts
 * Manage permissions it lacks. Needs Roles/Users view; returns '' if not.
 */
async function uamRoleDiagnosis(accountId) {
  try {
    const me = (await apiGet('/web/api/v2.1/user'))?.data || {};
    const roles = (me.scopeRoles || []).filter((r) => !accountId || String(r.id) === String(accountId));
    const parts = [];
    for (const r of roles.length ? roles : (me.scopeRoles || [])) {
      if (!r.roleId) continue;
      const role = (await apiGet(`/web/api/v2.1/rbac/role/${encodeURIComponent(r.roleId)}`, { accountIds: r.id }))?.data;
      const page = (role?.pages || []).find((p) => p.identifier === 'unifiedAlerts');
      if (!page) continue;
      const missing = (page.permissions || [])
        .filter((p) => p.title === 'Manage' && p.value !== true)
        .map((p) => `${p.groupName || 'Unified Alerts'}: Manage`);
      parts.push(`role "${r.roleName || role.name}" (id ${r.roleId}) on scope "${r.name || r.id}" ` +
        (missing.length ? `lacks ${missing.join(', ')}` : 'has every Unified Alerts Manage permission'));
    }
    return parts.length ? ` Role check: ${parts.join('; ')}.` : '';
  } catch {
    return '';
  }
}

/** Ask alertAvailableActions why a non-permission failure happened. */
async function uamAvailabilityHint(alertId, actionId, scope) {
  try {
    const avail = await uamAvailableActions(alertId, scope);
    const ids = avail.map((a) => a.id);
    const short = actionId.split('/').pop();
    if (!ids.includes(actionId)) {
      return ` | alertAvailableActions: ${short} is NOT OFFERED to this caller for this alert `
        + `(available: ${ids.join(', ') || 'none'}). Availability is filtered by the caller's `
        + 'permissions and the alert type: check the service user\'s UAM permissions.';
    }
    const a = avail.find((x) => x.id === actionId);
    return a?.isDisabled
      ? ` | alertAvailableActions: offered but DISABLED (${a.disabledReason || 'no reason given'}).`
      : ` | alertAvailableActions: ${short} IS available here, so the refusal is not `
        + 'availability. Escalate as a genuine permission or state problem.';
  } catch (e) {
    return ` | could not query alertAvailableActions to diagnose: ${e.message}`;
  }
}

const pickState = (a) => a && ({
  status: a.status ?? null,
  analystVerdict: a.analystVerdict ?? null,
  assignee: a.assignee ? { userId: a.assignee.userId ?? null, email: a.assignee.email ?? null } : null,
});

/**
 * Run one alertTriggerActions action on one alert and verify it took effect.
 *
 * @param {string} alertId
 * @param {string} actionId   e.g. 'S1/alert/statusUpdate'
 * @param {object} payload    TriggerPayloadInput, e.g. {status:{value:'RESOLVED'}}
 * @param {object} o
 * @param {string} o.label    caller name for messages, e.g. 'uamSetStatus'
 * @param {string} o.field    human field name, e.g. 'status'
 * @param {(alert:object)=>boolean} o.isApplied  true when the re-read shows the requested value
 * @param {string} o.wanted   requested value, for messages
 * @param {object} [o.scope]  ScopeSelectorInput override; default = the alert's account
 * @param {number} [o.verifyAttempts=8] re-reads before giving up
 * @param {number} [o.verifyDelayMs=1000] delay between re-reads
 */
export async function uamTriggerAlertAction(alertId, actionId, payload, {
  label, field, isApplied, wanted, scope, verifyAttempts = 8, verifyDelayMs = 1000,
} = {}) {
  if (typeof alertId !== 'string' || !alertId.trim()) throw new Error(`${label}: alertId is required`);

  const before = await uamAlertState(alertId);
  if (!before) {
    throw new Error(`${label}: alert ${alertId} was not found or is not visible to this token (alert(id) returned null).`);
  }
  const accountId = before.realTime?.scope?.account?.id || null;
  const effectiveScope = scope || (accountId ? { scopeIds: [String(accountId)], scopeType: 'ACCOUNT' } : await allAccountsScope());
  const variables = buildAlertTriggerActionsVariables(alertId, actionId, payload, effectiveScope);

  const data = await uamGraphql(ALERT_TRIGGER_ACTIONS_MUTATION, variables, 'AlertTriggerActions', { opname: true });
  const result = data?.alertTriggerActions || null;
  const typename = result?.__typename;

  if (typename === 'TriggerActionsError' || result?.errors?.length) {
    const e = result?.errors?.[0] || {};
    const limit = e.errorPayload?.limit;
    throw new Error(`${label} trigger error for alert ${alertId}: ${e.errorMessage || 'unknown error'}${limit != null ? ` (limit ${limit})` : ''}`);
  }

  let outcome = 'applied';
  if (typename === 'TriggerActionsScheduled' || result?.bulkActionTriggerId) {
    outcome = 'scheduled'; // asynchronous bulk job; the re-read below decides
  } else {
    const action = result?.actions?.[0];
    if (!action) {
      // Empty actions array: the backend applied nothing (e.g. the filter matched
      // no alert). Same silent-success class as skip-without-success; fail loudly.
      throw new Error(
        `${label} applied no action for alert ${alertId}: the backend returned an empty actions list. ` +
        'Verify the alert id, then re-check with uam_get_alert.'
      );
    }
    if (action.failure?.length) {
      const f = action.failure[0];
      if (f.errorType === 'MISSING_PERMISSION') {
        // Verified live 2026-10-08: "Missing UAM manage permissions". The role
        // lacks "Unified Alerts > <alert type>: Manage" (custom roles created
        // before those permissions existed do not have them). Not a tool fault.
        const group = uamManageGroupFor(before.detectionSource?.product);
        const roleCheck = await uamRoleDiagnosis(accountId);
        const now = await uamAlertState(alertId).catch(() => null);
        const unchanged = now
          ? `A re-read shows ${field} is ${JSON.stringify(pickState(now)[field] ?? null)} (was ${JSON.stringify(pickState(before)[field] ?? null)} before the call).`
          : `${field} was ${JSON.stringify(pickState(before)[field] ?? null)} before the call (re-read failed).`;
        throw new Error(
          `${label} failed for alert ${alertId}: ${f.errorMessage || 'missing permission'} (errorType MISSING_PERMISSION). ` +
          `The calling user's role needs "Unified Alerts > ${group}: Manage" for this alert type ` +
          `(detectionSource.product=${before.detectionSource?.product ?? 'unknown'})` +
          (group === 'STAR Alerts'
            ? ' or the legacy "STAR Rule Alerts > Update Incident Status / Update Analyst Verdict"'
            : '') +
          '. Grant it in the console at ' +
          'Policies and settings > User management > Console users > Roles > <the role> > Unified Alerts ' +
          '(for a service user, edit the role shown on its Service users row), or use a token whose role has it.' +
          `${roleCheck} ${unchanged}`
        );
      }
      const hint = await uamAvailabilityHint(alertId, actionId, effectiveScope);
      throw new Error(`${label} failed for alert ${alertId}: ${f.errorMessage || f.errorType || 'unknown error'}${hint}`);
    }
    if (!(action.success?.length)) {
      // skip with no success: the backend did not apply it. Usually a no-op
      // (the value was already set); the re-read below tells the two apart.
      outcome = action.skip?.length ? 'skipped' : 'unknown';
    }
  }

  // Verify by re-reading the alert.
  let after = null;
  for (let i = 0; i < Math.max(1, verifyAttempts); i++) {
    if (i > 0 || outcome !== 'skipped') await sleep(i === 0 ? Math.min(verifyDelayMs, 250) : verifyDelayMs);
    after = await uamAlertState(alertId);
    if (after && isApplied(after)) {
      return {
        alertId,
        actionId,
        requested: wanted,
        outcome: outcome === 'skipped' || outcome === 'unknown' ? 'already_set' : outcome,
        verified: true,
        before: pickState(before),
        after: pickState(after),
        scope: effectiveScope,
        response: result,
      };
    }
    if (outcome === 'skipped' || outcome === 'unknown') break; // nothing is coming
  }
  if (outcome === 'skipped' || outcome === 'unknown') {
    throw new Error(
      `${label} skipped for alert ${alertId}: the backend did not apply the ${field} update ` +
      `(requested ${JSON.stringify(wanted)}, ${field} is ${JSON.stringify(pickState(after || before)[field] ?? null)}). ` +
      'Verify the alert id and that the change is valid, then re-check with uam_get_alert.'
    );
  }
  throw new Error(
    `${label}: the backend reported ${outcome} for alert ${alertId} but a re-read ${Math.max(1, verifyAttempts)} time(s) ` +
    `still shows ${field}=${JSON.stringify(pickState(after || before)[field] ?? null)} (requested ${JSON.stringify(wanted)}). ` +
    'Re-check with uam_get_alert; the change may be delayed or silently rejected.'
  );
}

function scopeFromArgs(scopeIds, scopeType) {
  if (!Array.isArray(scopeIds) || !scopeIds.length) return undefined;
  const t = scopeType || 'ACCOUNT';
  if (!['ACCOUNT', 'SITE', 'GROUP'].includes(t)) throw new Error(`scopeType must be ACCOUNT, SITE or GROUP (got ${JSON.stringify(t)})`);
  return { scopeIds: scopeIds.map(String), scopeType: t };
}

/**
 * Update the status of a UAM alert (NEW | IN_PROGRESS | RESOLVED), the same
 * request the console sends, verified by re-reading the alert.
 * FALSE_POSITIVE is not a status; it is an analyst verdict (uamSetVerdict).
 */
export async function uamSetStatus(alertId, status, { scopeIds, scopeType, ...opts } = {}) {
  if (!UAM_STATUSES.includes(status)) {
    throw new Error(`uamSetStatus: invalid status ${JSON.stringify(status)}. Valid: ${UAM_STATUSES.join(', ')}. ` +
      '(FALSE_POSITIVE etc. are analyst verdicts: use uam_set_verdict.)');
  }
  return uamTriggerAlertAction(alertId, UAM_ACTIONS.status, { status: { value: status } }, {
    label: 'uamSetStatus', field: 'status', wanted: status,
    isApplied: (a) => a.status === status,
    scope: scopeFromArgs(scopeIds, scopeType), ...opts,
  });
}

/** Set the analyst verdict of a UAM alert, verified by re-reading the alert. */
export async function uamSetVerdict(alertId, verdict, { scopeIds, scopeType, ...opts } = {}) {
  if (!UAM_ANALYST_VERDICTS.includes(verdict)) {
    throw new Error(`uamSetVerdict: invalid analyst verdict ${JSON.stringify(verdict)}. Valid: ${UAM_ANALYST_VERDICTS.join(', ')}. ` +
      'TRUE_POSITIVE and FALSE_POSITIVE alone are console group headers, not values; pick a sub-verdict.');
  }
  return uamTriggerAlertAction(alertId, UAM_ACTIONS.verdict, { analystVerdict: { value: verdict } }, {
    label: 'uamSetVerdict', field: 'analystVerdict', wanted: verdict,
    isApplied: (a) => a.analystVerdict === verdict,
    scope: scopeFromArgs(scopeIds, scopeType), ...opts,
  });
}

/**
 * Resolve a console user for assignment. The console sends the numeric user id
 * (AssignUserInput.value: Long, sent as a string). An email is looked up with
 * GET /web/api/v2.1/users?email= and must match exactly one user.
 */
export async function uamResolveUser({ userId, email } = {}) {
  if (userId != null && userId !== '') {
    const id = String(userId).trim();
    if (!/^\d{1,20}$/.test(id)) throw new Error(`userId must be a numeric console user id (got ${JSON.stringify(userId)})`);
    return { userId: id, email: email || null };
  }
  if (!email || typeof email !== 'string' || !email.includes('@')) {
    throw new Error('Pass userId (numeric console user id) or email of the user to assign.');
  }
  const res = await apiGet('/web/api/v2.1/users', { email: email.trim(), limit: 10 });
  const matches = (res?.data || []).filter((u) => String(u.email || '').toLowerCase() === email.trim().toLowerCase());
  if (matches.length !== 1) {
    throw new Error(
      `No unique console user with email ${email} is visible to this token (found ${matches.length}). ` +
      'Pass userId instead (GET /web/api/v2.1/users lists ids).'
    );
  }
  return { userId: String(matches[0].id), email: matches[0].email };
}

/**
 * Assign a UAM alert to a console user, or unassign it (unassign: true sends
 * {assignUser:{value:null}}, which the schema documents as "user will be
 * unassigned"). Verified by re-reading the alert's assignee.
 */
export async function uamAssignAlert(alertId, { userId, email, unassign = false, scopeIds, scopeType, ...opts } = {}) {
  const given = [userId != null && userId !== '', !!email, unassign === true].filter(Boolean).length;
  if (given !== 1) throw new Error('uamAssignAlert: pass exactly one of userId, email, or unassign: true.');
  let user = null;
  if (!unassign) user = await uamResolveUser({ userId, email });
  const value = unassign ? null : user.userId;
  return uamTriggerAlertAction(alertId, UAM_ACTIONS.assign, { assignUser: { value } }, {
    label: 'uamAssignAlert', field: 'assignee', wanted: unassign ? null : (user.email || user.userId),
    isApplied: (a) => (unassign ? a.assignee == null || a.assignee.userId == null : String(a.assignee?.userId ?? '') === user.userId),
    scope: scopeFromArgs(scopeIds, scopeType), ...opts,
  });
}
