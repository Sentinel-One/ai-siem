/**
 * SentinelOne client — Mgmt Console REST API, LRQ PowerQuery, Purple AI, UAM GraphQL.
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

async function doFetch(url, opts, retries = 3) {
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

    // Retry on 429 / 5xx
    if ((res.status === 429 || res.status >= 500) && attempt < retries) {
      const retryAfter = res.headers.get('Retry-After');
      const wait = retryAfter ? parseInt(retryAfter, 10) * 1000 : delay;
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

/** POST /web/api/v2.1/<path> */
export async function apiPost(path, body = {}) {
  return doFetch(safeUrl(path).toString(), {
    method: 'POST',
    headers: {
      Authorization: `ApiToken ${jwt()}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(body),
  });
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

/** Run a full LRQ PowerQuery lifecycle. Returns { columns, rows, rowCount, matchCount }. */
export async function lrqRun(query, { startTime, endTime, hours = 24, maxRows = 5000 } = {}) {
  const b = base();
  const tok = jwt();

  // Resolve time range
  if (!startTime || !endTime) {
    const now = new Date();
    endTime = now.toISOString().replace(/\.\d+Z$/, 'Z');
    startTime = new Date(now - hours * 3600 * 1000).toISOString().replace(/\.\d+Z$/, 'Z');
  }

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
  const deadline = Date.now() + 5 * 60 * 1000; // 5 min hard timeout

  try {
    while (Date.now() < deadline) {
      await sleep(1000);
      const pollUrl = `${b}/sdl/v2/api/queries/${queryId}?lastStepSeen=${lastStepSeen}`;
      let pollRes;
      try {
        pollRes = await fetch(pollUrl, { method: 'GET', headers: pollHeaders });
      } catch (err) {
        // Transient network error; keep polling
        continue;
      }

      if (!pollRes.ok) {
        const body = await pollRes.text();
        throw new Error(`LRQ poll failed (${pollRes.status}): ${body}`);
      }

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
  // Must use col.name (not col itself) as the row key — col.toString() produces "[object Object]".
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
    matchCount: result.matchCount ?? null,
    queryId,
  };
}

// ─── Purple AI ────────────────────────────────────────────────────────────────
// Reverse-engineered from live network traffic on usea1-acme.sentinelone.net.
//
// IMPORTANT: purpleLaunchQuery is a GraphQL QUERY (not mutation).
// Variable wrapper is `request` (type PurpleLaunchQueryRequest), NOT `input`.
// The prior implementation used mutation + PurpleLaunchQueryInput — both wrong,
// causing HTTP 400 "invalid query" at the middleware layer.
//
// Endpoints:
//   Purple AI LLM  → POST /web/api/v2.1/graphql       (ApiToken auth)
//   SDL/History    → POST <base>/sdl/v2/graphql        (Bearer auth, same token)

function randomHex(len = 32) {
  return Array.from({ length: len }, () => Math.floor(Math.random() * 16).toString(16)).join('');
}

/**
 * Run a Purple AI natural-language query.
 *
 * Flow:
 *   1. purpleLaunchQuery (contentType=NATURAL_LANGUAGE) → PowerQuery string
 *   2. Return the generated PowerQuery + token for downstream SDL execution.
 *
 * Returns { powerQuery, viewSelector, timeRange, token, status, resultType }
 */
export async function purpleAiQuery(userInput, { viewSelector = 'EDR', hours = 24 } = {}) {
  const now = Date.now();
  const startMs = now - hours * 3600 * 1000;
  const conversationId = randomHex(32);
  const feedItemId     = randomHex(32);
  const msgId          = randomHex(32);
  const consoleUrl     = `${base()}/`;

  // Confirmed correct shape from live API validation (2026-05-03):
  // - operation type is `query` not `mutation`
  // - variable name is `request` not `input`
  // - type is `PurpleLaunchQueryRequest` not `PurpleLaunchQueryInput`
  // - inputContent MUST appear at the top level of `request` (confirmed: HTTP 400
  //   "missing input value at $request.inputContent" when omitted)
  // - PurpleUserDetailsRequest schema (confirmed from live validation error):
  //   { accountId: ID!, teamToken: ID!, sessionId, emailAddress, userAgent, buildDate, buildHash }
  //   Does NOT have siteIds or groupIds.
  const inputContentPayload = {
    userInput,
    viewSelector,
    displayedTimeRange: { start: startMs, end: now },
    resultsPq: null,
    powerQueryForResults: null,
    additionalFieldsForPq: null,
    contextId: null,
    userDetails: null,
  };

  const gqlBody = {
    operationName: 'purpleLaunchQuery',
    variables: {
      request: {
        isAsync: false,
        contentType: 'NATURAL_LANGUAGE',
        consoleDetails: {
          baseUrl: consoleUrl,
          version: 'S-26.1.3#69',
        },
        // Top-level inputContent required by PurpleLaunchQueryRequest schema.
        inputContent: inputContentPayload,
        conversation: {
          id: conversationId,
          messages: [
            {
              inputMessage: {
                id: msgId,
                feedItemId,
                conversationId,
                createdAt: new Date(now).toISOString(),
                messageType: 'INPUT',
                contentType: 'NATURAL_LANGUAGE',
                inputContent: inputContentPayload,
              },
            },
          ],
        },
      },
    },
    query: `
      query purpleLaunchQuery($request: PurpleLaunchQueryRequest!) {
        purpleLaunchQuery(request: $request) {
          token
          resultType
          status { state error { errorType errorDetail origin } }
          stepsCompleted
          result {
            message
            summary
            maskedMetadata
            powerQuery {
              query
              viewSelector
              timeRange { start end }
            }
            suggestedQuestions {
              question
              powerQuery
              viewSelector
              timeRange { start end }
            }
          }
        }
      }
    `,
  };

  const data = await apiPost('/web/api/v2.1/graphql', gqlBody);

  if (data.errors?.length) {
    throw new Error(`Purple AI GraphQL error: ${data.errors[0].message}`);
  }

  const plq = data?.data?.purpleLaunchQuery || {};
  const state = plq?.status?.state;
  if (state && state !== 'COMPLETED') {
    const err = plq?.status?.error || {};
    const detail = err.errorDetail || '';
    const origin = err.origin || '';
    // AsimovError from LaunchQueryManager = LLM workspace layer rejected the request.
    // Root cause: purpleLaunchQuery NATURAL_LANGUAGE requires a browser-session teamToken
    // (obtained from /sdl/v2/graphql) that service-account API tokens never have.
    // purpleAlertSummary (ALERT_ENTRY) does not have this limitation and works fine.
    if (detail.includes('AsimovError') || origin === 'LaunchQueryManager') {
      throw new Error(
        'Purple AI NL query failed: the LLM workspace layer (LaunchQueryManager) rejected this ' +
        'service-account request. purpleLaunchQuery NATURAL_LANGUAGE requires a browser-session ' +
        'teamToken that API-token service accounts do not have. Use purple_ai_alert_summary ' +
        '(ALERT_ENTRY) instead, or run the query interactively in the Purple AI browser console.'
      );
    }
    throw new Error(`Purple AI state: ${state}${detail ? ` (${origin}: ${detail})` : ''}`);
  }

  const r = plq.result || {};
  return {
    token:       plq.token || null,
    resultType:  plq.resultType || null,
    status:      plq.status || null,
    powerQuery:  r.powerQuery?.query || null,
    viewSelector: r.powerQuery?.viewSelector || viewSelector,
    timeRange:   r.powerQuery?.timeRange || { start: startMs, end: now },
    summary:     r.summary || null,
    message:     r.message || null,
    suggestedQuestions: r.suggestedQuestions || [],
    maskedMetadata: r.maskedMetadata || null,
  };
}

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

  const data = await apiPost('/web/api/v2.1/graphql', gqlBody);
  if (data.errors?.length) throw new Error(`Purple AI AlertSummary error: ${data.errors[0].message}`);

  const pas = data?.data?.purpleAlertSummary || {};
  return {
    token:   pas.token || null,
    summary: pas.result?.summary || null,
  };
}

/**
 * Trigger and poll Purple AI auto-investigation on a UAM alert.
 *
 * Step 1: alertTriggerActions with id="S1/aiInvestigation/run"
 * Step 2: poll aiInvestigations until status=COMPLETED or FAILED
 *
 * Returns { verdict, markdown, investigationSteps[], alertId }
 */
export async function purpleAiInvestigate(alertId, { scopeId, scopeType = 'ACCOUNT', timeoutMs = 5 * 60 * 1000 } = {}) {
  // Resolve account scope from user profile if not provided
  let resolvedScopeId = scopeId;
  if (!resolvedScopeId) {
    const userInfo = await doFetch(`${base()}/web/api/v2.1/user`, {
      method: 'GET',
      headers: { Authorization: `ApiToken ${jwt()}`, 'Content-Type': 'application/json' },
    });
    resolvedScopeId = userInfo?.data?.scopeRoles?.[0]?.id || userInfo?.data?.id;
    if (!resolvedScopeId) throw new Error('Could not resolve account scopeId for aiInvestigation. Pass scopeId explicitly.');
  }

  const scope = { scopeIds: [resolvedScopeId], scopeType };

  // Step 1: Trigger investigation
  const triggerBody = {
    operationName: 'AlertTriggerActions',
    variables: {
      scope,
      filter: { or: [{ and: [{ fieldId: 'id', stringEqual: { value: alertId } }] }] },
      viewType: 'ALL',
      actions: [{
        id: 'S1/aiInvestigation/run',
        payload: {
          aiInvestigation: {
            buildDate:      new Date().toISOString(),
            buildHash:      '',
            consoleVersion: 'S-26.1.3#69',
            scope,
            tenantId:       resolvedScopeId,
            userAgent:      's1-secops-mcp/1.0',
            sessionId:      randomHex(32),
            userTime:       new Date().toISOString(),
          },
        },
      }],
    },
    query: `
      mutation AlertTriggerActions($scope: ScopeSelectorInput, $filter: OrFilterSelectionInput, $actions: [TriggerActionInput!]!, $viewType: ViewType) {
        alertTriggerActions(filter: $filter scope: $scope actions: $actions viewType: $viewType) {
          ... on ActionsTriggered {
            actions { actionId skip { id } failure { id errorMessage errorType } success { id } }
          }
          ... on TriggerActionsError {
            errors { errorMessage }
          }
        }
      }
    `,
  };

  const triggerRes = await uamGraphql(triggerBody.query, triggerBody.variables, 'AlertTriggerActions');
  const triggerData = triggerRes?.alertTriggerActions;
  if (triggerData?.errors?.length) {
    throw new Error(`aiInvestigation trigger error: ${triggerData.errors[0].errorMessage}`);
  }
  const triggered = triggerData?.actions?.[0];
  if (triggered?.failure?.length) {
    const f = triggered.failure[0];
    // SERVICE_ERROR without errorMessage = LLM-layer rejection (same root cause as
    // purpleLaunchQuery AsimovError). aiInvestigation/run requires a browser-session
    // workspace; API-token service accounts are rejected at the service layer.
    if (f.errorType === 'SERVICE_ERROR' && !f.errorMessage) {
      throw new Error(
        'aiInvestigation SERVICE_ERROR: the AI investigation service rejected this service-account ' +
        'request. Like purpleLaunchQuery, this feature requires an active browser-session workspace. ' +
        'Trigger the investigation interactively from the Purple AI card in the alert detail panel.'
      );
    }
    throw new Error(`aiInvestigation trigger failure: ${f.errorMessage || f.errorType}`);
  }

  // Step 2: Poll GetAlertAiInvestigations
  const pollQuery = `
    query GetAlertAiInvestigations($alertIds: [ID!]!, $scope: ScopeSelectorInput) {
      aiInvestigations(alertIds: $alertIds, scope: $scope) {
        alertId status purpleAiStatus investigationStep verdict timestamp result restrictionReason
      }
    }
  `;

  const deadline = Date.now() + timeoutMs;
  const steps = [];
  let lastStep = null;

  while (Date.now() < deadline) {
    await sleep(4000);
    const pollRes = await uamGraphql(pollQuery, { alertIds: [alertId], scope }, 'GetAlertAiInvestigations');
    const inv = pollRes?.aiInvestigations?.[0];
    if (!inv) continue;

    const step = inv.investigationStep;
    if (step && step !== lastStep) {
      steps.push(step);
      lastStep = step;
    }

    if (inv.status === 'COMPLETED') {
      return {
        alertId:             inv.alertId,
        verdict:             inv.verdict,
        markdown:            inv.result,
        investigationSteps:  steps,
        timestamp:           inv.timestamp,
      };
    }
    if (inv.status === 'FAILED') {
      throw new Error(`aiInvestigation FAILED: ${inv.restrictionReason || 'unknown reason'}`);
    }
  }

  throw new Error(`aiInvestigation timed out after ${timeoutMs / 1000}s`);
}

// ─── UAM GraphQL ─────────────────────────────────────────────────────────────

/** Execute a raw UAM GraphQL operation. */
export async function uamGraphql(query, variables = {}, operationName) {
  const body = { query, variables };
  if (operationName) body.operationName = operationName;
  const data = await apiPost('/web/api/v2.1/unifiedalerts/graphql', body);
  if (data.errors?.length) {
    throw new Error(`UAM GraphQL error: ${data.errors[0].message}`);
  }
  return data.data;
}

/**
 * List UAM alerts using the correct `filters: [FilterInput!]` schema.
 *
 * IMPORTANT: The `alerts` query takes `filters: [FilterInput!]` (flat AND-joined list).
 * Do NOT pass `filter: String` or `OrFilterSelectionInput` — those belong to mutations only.
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
  // Time range — specify either ISO strings OR epoch ms; both become dateRange { from, to }
  startTime = null,        // ISO string "2026-05-03T07:32:00Z" or epoch ms number
  endTime = null,          // ISO string or epoch ms; defaults to now when startTime is set
  // Raw FilterInput list — overrides all convenience params above when provided
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
      // Correct FilterInput field: dateTimeRange { start, end } — NOT dateRange, NOT date_range
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
  const data = await uamGraphql(query, variables);
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
  // Return the most recently added note (last in the list)
  return notes.length > 0 ? notes[notes.length - 1] : null;
}

/**
 * Update the status of a UAM alert via alertTriggerActions.
 * Valid status values (confirmed via Status enum introspection): NEW | IN_PROGRESS | RESOLVED
 * Note: FALSE_POSITIVE is not a status — it is an analystVerdict value.
 * To mark false positive: use uam_set_analyst_verdict with a FALSE_POSITIVE_* value instead.
 */
export async function uamSetStatus(alertId, status) {
  const query = `
    mutation SetStatus($filter: OrFilterSelectionInput, $actions: [TriggerActionInput!]) {
      alertTriggerActions(filter: $filter, actions: $actions) {
        __typename
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
  return data?.alertTriggerActions || null;
}
