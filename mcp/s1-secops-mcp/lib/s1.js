/**
 * SentinelOne client: Mgmt Console REST API, LRQ PowerQuery, Purple AI, UAM GraphQL.
 *
 * Auth patterns:
 *   Mgmt REST API   → Authorization: ApiToken <jwt>
 *   LRQ             → Authorization: Bearer  <jwt>   (same token, different prefix)
 *   Purple AI       → Authorization: ApiToken <jwt>   (POST /web/api/v2.1/graphql)
 *   UAM GraphQL     → Authorization: ApiToken <jwt>   (POST /web/api/v2.1/unifiedalerts/graphql)
 */

import { getCreds } from './credentials.js';

// ─── helpers ──────────────────────────────────────────────────────────────────

function base() {
  const url = getCreds().S1_CONSOLE_URL.replace(/\/+$/, '');
  if (!url) throw new Error('S1_CONSOLE_URL not configured. Drop credentials.json into your project folder.');
  return url;
}

function jwt() {
  const tok = getCreds().S1_CONSOLE_API_TOKEN;
  if (!tok) throw new Error('S1_CONSOLE_API_TOKEN not configured. Drop credentials.json into your project folder.');
  return tok;
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
    try { data = JSON.parse(text); } catch { data = text; }

    if (!res.ok) {
      const msg = typeof data === 'object' ? (data?.errors?.[0]?.detail || data?.errors?.[0]?.message || JSON.stringify(data)) : text;
      throw new Error(`S1 API ${opts.method || 'GET'} ${url} → ${res.status}: ${msg}`);
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
export async function lrqRun(query, { startTime, endTime, hours = 24, maxRows = 5000 } = {}) {
  const b = base();
  const tok = jwt();

  ({ startTime, endTime } = resolveLrqWindow({ startTime, endTime, hours }));

  const launchUrl = `${b}/sdl/v2/api/queries`;
  const launchBody = {
    queryType: 'PQ',
    tenant: true,
    startTime,
    endTime,
    queryPriority: 'HIGH',
    pq: { query, resultType: 'TABLE' },
  };

  // Launch
  const launchRes = await fetch(launchUrl, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${tok}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(launchBody),
  });

  if (!launchRes.ok) {
    const body = await launchRes.text();
    throw new Error(`LRQ launch failed (${launchRes.status}): ${body}`);
  }

  const forwardTag = launchRes.headers.get('X-Dataset-Query-Forward-Tag');
  const launched = await launchRes.json();
  const queryId = launched.id;
  if (!queryId) throw new Error(`LRQ launch returned no id: ${JSON.stringify(launched)}`);

  const pollHeaders = {
    Authorization: `Bearer ${tok}`,
    'Content-Type': 'application/json',
    ...(forwardTag ? { 'X-Dataset-Query-Forward-Tag': forwardTag } : {}),
  };

  // Poll until done (30s expiry, poll every 1s)
  let lastStepSeen = 0;
  let result = null;
  let pollDelay = 1000;
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
        // Other 4xx responses are permanent and remain fatal.
        if (pollRes.status === 429 || pollRes.status >= 500) {
          pollDelay = Math.min(pollDelay * 2, 5000);
          continue;
        }
        throw new Error(`LRQ poll failed (${pollRes.status}): ${body}`);
      }
      pollDelay = 1000; // healthy poll: restore the normal interval

      const state = await pollRes.json();
      lastStepSeen = state.stepsCompleted ?? lastStepSeen;

      const done = state.stepsTotal > 0 && state.stepsCompleted >= state.stepsTotal;
      if (done) {
        result = state;
        break;
      }
    }
  } finally {
    // Always cancel to release quota
    try {
      await fetch(`${b}/sdl/v2/api/queries/${queryId}`, {
        method: 'DELETE',
        headers: pollHeaders,
      });
    } catch { /* best effort */ }
  }

  if (!result) throw new Error('LRQ timed out after 5 minutes');

  const data = result.data || {};
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
export async function uamGraphql(query, variables = {}, operationName, { readOnly = false } = {}) {
  const body = { query, variables };
  if (operationName) body.operationName = operationName;
  // readOnly=true (list/get queries) re-enables 429/5xx retry, which is safe
  // for GraphQL reads; mutations (addNote, setStatus) must not auto-retry.
  const data = await apiPost('/web/api/v2.1/unifiedalerts/graphql', body, { allowRetry: readOnly });
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
      builtFilters.push({ fieldId: '*', match: { value: [searchText] } });
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
          confidenceLevel primaryIndicatorType analystVerdict result
          assignee { fullName email }
          detectionSource { product vendor }
        }
      }
    `, { id: alertId }),
    uamGraphql(`
      query GetAlertNotes($id: ID!) {
        alertNotes(alertId: $id) {
          data { id text type createdAt updatedAt author { fullName email } }
        }
      }
    `, { id: alertId }),
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
 * Update the status of a UAM alert via alertTriggerActions.
 * Valid status values (confirmed via Status enum introspection): NEW | IN_PROGRESS | RESOLVED
 * Note: FALSE_POSITIVE is not a status; it is an analystVerdict value.
 * To mark false positive: there is no dedicated tool. POST the raw
 * alertTriggerActions mutation with the S1/alert/analystVerdictUpdate action
 * via s1_api_post to /web/api/v2.1/unifiedalerts/graphql.
 *
 * The mutation result is verified: a __typename-only selection previously
 * reported success even when the backend skipped or failed the action
 * (observed live: status stayed unchanged). Fixed 2026-07-31.
 */
export async function uamSetStatus(alertId, status) {
  const query = `
    mutation SetStatus($filter: OrFilterSelectionInput, $actions: [TriggerActionInput!]) {
      alertTriggerActions(filter: $filter, actions: $actions) {
        ... on ActionsTriggered {
          actions { actionId skip { id } failure { id errorMessage errorType } success { id } }
        }
        ... on TriggerActionsError {
          errors { errorMessage }
        }
      }
    }
  `;
  const variables = {
    filter: {
      or: [{ and: [{ fieldId: 'id', stringEqual: { value: alertId } }] }],
    },
    actions: [{ id: 'S1/alert/statusUpdate', payload: { status: { value: status } } }],
  };
  const data = await uamGraphql(query, variables);
  const result = data?.alertTriggerActions || null;
  if (result?.errors?.length) {
    throw new Error(`uamSetStatus trigger error: ${result.errors[0].errorMessage}`);
  }
  const action = result?.actions?.[0];
  if (!action) {
    // Empty actions array: the backend applied nothing (e.g. the filter matched
    // no alert). Same silent-success class as skip-without-success; fail loudly.
    throw new Error(
      `uamSetStatus applied no action for alert ${alertId}: the backend returned an empty actions list. ` +
      'Verify the alert id, then re-check with uam_get_alert.'
    );
  }
  if (action.failure?.length) {
    const f = action.failure[0];
    throw new Error(`uamSetStatus failed for alert ${alertId}: ${f.errorMessage || f.errorType || 'unknown error'}`);
  }
  if (!(action.success?.length) && action.skip?.length) {
    throw new Error(
      `uamSetStatus skipped for alert ${alertId}: the backend did not apply the status update. ` +
      'Verify the alert id and that the transition is valid, then re-check with uam_get_alert.'
    );
  }
  return result;
}
