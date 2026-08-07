/**
 * Regression tests for the 2026-07-31 code-review fixes.
 *
 * 1. Retry-After backoff: a MISSING Retry-After header must fall back to the
 *    exponential delay. Number(null) is 0, so the old code slept 0ms and
 *    hammered the backend on every 429 without the header. Numeric headers
 *    keep their exact prior behavior (seconds, capped at 30s).
 *
 * 2. uamSetStatus result verification: the alertTriggerActions mutation used
 *    to select only __typename, so a failed or skipped action still returned
 *    as success (observed live: status unchanged after a "successful" call).
 *    It must throw when the response carries a failure entry, or a skip with
 *    no success.
 *
 * 3. normalizeS1ApiGetParams: an inline ?isLegacy= already present in the
 *    path must be honored; appending a conflicting isLegacy=false query param
 *    contradicts the caller. Mirrors _maybe_inject_islegacy in the Python
 *    twin (mgmt-console-api/scripts/s1_client.py).
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

// ─── Retry-After backoff (mocked fetch, no network) ──────────────────────────

test('doFetch: 429 with MISSING Retry-After waits the exponential delay, not 0ms', async () => {
  process.env.S1_CONSOLE_URL = 'https://mgmt.example.invalid';
  process.env.S1_CONSOLE_API_TOKEN = 'tok';
  const callTimes = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = async () => {
    callTimes.push(Date.now());
    if (callTimes.length === 1) return new Response('slow down', { status: 429 }); // no Retry-After header
    return new Response(JSON.stringify({ data: { ok: true } }), { status: 200, headers: { 'Content-Type': 'application/json' } });
  };
  try {
    const { apiGet } = await import('../lib/s1.js');
    const r = await apiGet('/web/api/v2.1/agents');
    assert.deepEqual(r, { data: { ok: true } });
    assert.equal(callTimes.length, 2, 'GET should retry once after the 429');
    const gap = callTimes[1] - callTimes[0];
    // First exponential delay is 500ms; the old bug slept Number(null) === 0ms.
    assert.ok(gap >= 400, `retry after missing Retry-After must back off ~500ms, got ${gap}ms`);
  } finally {
    globalThis.fetch = realFetch;
    delete process.env.S1_CONSOLE_URL; delete process.env.S1_CONSOLE_API_TOKEN;
  }
});

test('doFetch: numeric Retry-After header keeps its prior behavior (0 -> immediate retry)', async () => {
  process.env.S1_CONSOLE_URL = 'https://mgmt.example.invalid';
  process.env.S1_CONSOLE_API_TOKEN = 'tok';
  const callTimes = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = async () => {
    callTimes.push(Date.now());
    if (callTimes.length === 1) {
      return new Response('slow down', { status: 429, headers: { 'Retry-After': '0' } });
    }
    return new Response(JSON.stringify({ data: { ok: true } }), { status: 200, headers: { 'Content-Type': 'application/json' } });
  };
  try {
    const { apiGet } = await import('../lib/s1.js');
    await apiGet('/web/api/v2.1/agents');
    assert.equal(callTimes.length, 2);
    const gap = callTimes[1] - callTimes[0];
    assert.ok(gap < 400, `Retry-After: 0 must retry immediately as before, got ${gap}ms`);
  } finally {
    globalThis.fetch = realFetch;
    delete process.env.S1_CONSOLE_URL; delete process.env.S1_CONSOLE_API_TOKEN;
  }
});

// ─── uamSetStatus result verification (mocked fetch, no network) ─────────────

function gqlResponse(alertTriggerActions) {
  return new Response(JSON.stringify({ data: { alertTriggerActions } }), {
    status: 200, headers: { 'Content-Type': 'application/json' },
  });
}

test('uamSetStatus: throws when the response contains a failure entry', async () => {
  process.env.S1_CONSOLE_URL = 'https://mgmt.example.invalid';
  process.env.S1_CONSOLE_API_TOKEN = 'tok';
  const realFetch = globalThis.fetch;
  globalThis.fetch = async () => gqlResponse({
    actions: [{
      actionId: 'S1/alert/statusUpdate',
      skip: [],
      failure: [{ id: 'alert-1', errorMessage: 'status transition rejected', errorType: 'SERVICE_ERROR' }],
      success: [],
    }],
  });
  try {
    const { uamSetStatus } = await import('../lib/s1.js');
    await assert.rejects(
      () => uamSetStatus('alert-1', 'RESOLVED'),
      /status transition rejected/,
      'a failure entry must surface as a thrown error, not silent success',
    );
  } finally {
    globalThis.fetch = realFetch;
    delete process.env.S1_CONSOLE_URL; delete process.env.S1_CONSOLE_API_TOKEN;
  }
});

test('uamSetStatus: throws when the action is skipped with no success', async () => {
  process.env.S1_CONSOLE_URL = 'https://mgmt.example.invalid';
  process.env.S1_CONSOLE_API_TOKEN = 'tok';
  const realFetch = globalThis.fetch;
  globalThis.fetch = async () => gqlResponse({
    actions: [{ actionId: 'S1/alert/statusUpdate', skip: [{ id: 'alert-1' }], failure: [], success: [] }],
  });
  try {
    const { uamSetStatus } = await import('../lib/s1.js');
    await assert.rejects(() => uamSetStatus('alert-1', 'RESOLVED'), /skipped/);
  } finally {
    globalThis.fetch = realFetch;
    delete process.env.S1_CONSOLE_URL; delete process.env.S1_CONSOLE_API_TOKEN;
  }
});

test('uamSetStatus: throws when the backend returns an empty actions array', async () => {
  // Found by the 2026-07-31 A/B probe pass: an ActionsTriggered response with
  // actions: [] means nothing was applied (e.g. filter matched no alert), and
  // the guard must not resolve silently.
  process.env.S1_CONSOLE_URL = 'https://mgmt.example.invalid';
  process.env.S1_CONSOLE_API_TOKEN = 'tok';
  const realFetch = globalThis.fetch;
  globalThis.fetch = async () => gqlResponse({ actions: [] });
  try {
    const { uamSetStatus } = await import('../lib/s1.js');
    await assert.rejects(() => uamSetStatus('alert-1', 'RESOLVED'), /applied no action/);
  } finally {
    globalThis.fetch = realFetch;
    delete process.env.S1_CONSOLE_URL; delete process.env.S1_CONSOLE_API_TOKEN;
  }
});

test('uamSetStatus: resolves when the action reports success', async () => {
  process.env.S1_CONSOLE_URL = 'https://mgmt.example.invalid';
  process.env.S1_CONSOLE_API_TOKEN = 'tok';
  const realFetch = globalThis.fetch;
  globalThis.fetch = async () => gqlResponse({
    actions: [{ actionId: 'S1/alert/statusUpdate', skip: [], failure: [], success: [{ id: 'alert-1' }] }],
  });
  try {
    const { uamSetStatus } = await import('../lib/s1.js');
    const r = await uamSetStatus('alert-1', 'IN_PROGRESS');
    assert.equal(r.actions[0].success[0].id, 'alert-1');
  } finally {
    globalThis.fetch = realFetch;
    delete process.env.S1_CONSOLE_URL; delete process.env.S1_CONSOLE_API_TOKEN;
  }
});

// ─── normalizeS1ApiGetParams inline ?isLegacy= override ──────────────────────

test('normalizeS1ApiGetParams: inline ?isLegacy=true in the path is honored', async () => {
  const { normalizeS1ApiGetParams } = await import('../tools/mgmt-console.js');

  // 1. Inline isLegacy=true must NOT be contradicted by an injected param
  const a = normalizeS1ApiGetParams('/web/api/v2.1/cloud-detection/rules?isLegacy=true', {});
  assert.equal(a.isLegacy, undefined, 'inline ?isLegacy=true must suppress injection');

  // 2. Inline snake_case is_legacy also counts
  const b = normalizeS1ApiGetParams('/web/api/v2.1/cloud-detection/rules?limit=5&is_legacy=false', {});
  assert.equal(b.isLegacy, undefined, 'inline &is_legacy= must suppress injection');

  // 3. Case-insensitive match, mirroring the Python twin's re.IGNORECASE
  const c = normalizeS1ApiGetParams('/web/api/v2.1/cloud-detection/rules?ISLEGACY=true', {});
  assert.equal(c.isLegacy, undefined, 'inline override must match case-insensitively');

  // 4. No inline override -> still injected (the original guard is intact)
  const d = normalizeS1ApiGetParams('/web/api/v2.1/cloud-detection/rules', {});
  assert.equal(d.isLegacy, false, 'plain path must still get isLegacy=false injected');
});
