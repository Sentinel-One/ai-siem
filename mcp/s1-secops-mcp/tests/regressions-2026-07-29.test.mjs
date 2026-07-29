/**
 * Regression tests for the 2026-07-29 defect-review fixes.
 *
 * 1. resolveLrqWindow: each time bound must default INDEPENDENTLY.
 *    The original bug overwrote BOTH bounds when either was missing, so a
 *    startTime-only call silently ran over the last `hours` window.
 *    Live A/B (prod tenant, read-only): startTime-only for a 7.4-day window
 *    returned 12,880 events == the 24h control (12,875), vs 73,099 for the
 *    correctly pinned window.
 *
 * 2. pickMatchCount: matchCount lives at data.matchCount on current LRQ
 *    engines. Reading only the top level returned null on all 22 live calls.
 *
 * 3. keyCandidates + sdlFetch: a 401/403 from a wrong-scoped SDL key must
 *    advance to the next candidate key instead of failing the request.
 *    (SDL_CONFIG_WRITE_KEY does not grant View Logs on /api/query.)
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { resolveLrqWindow, pickMatchCount } from '../lib/s1.js';
import { keyCandidates } from '../lib/sdl.js';

// ─── resolveLrqWindow ─────────────────────────────────────────────────────────

test('resolveLrqWindow: both bounds omitted → endTime≈now, startTime = endTime - hours', () => {
  const before = Date.now();
  const { startTime, endTime } = resolveLrqWindow({ hours: 24 });
  const after = Date.now();
  const end = new Date(endTime).getTime();
  const start = new Date(startTime).getTime();
  assert.ok(end >= before - 2000 && end <= after + 2000, 'endTime should be ~now');
  assert.equal(end - start, 24 * 3600 * 1000, 'window should be exactly `hours` wide');
});

test('resolveLrqWindow: startTime-only must be PRESERVED (the 2026-07-29 bug)', () => {
  const { startTime, endTime } = resolveLrqWindow({ startTime: '2026-07-22T00:00:00Z' });
  assert.equal(startTime, '2026-07-22T00:00:00Z',
    'caller-supplied startTime must never be overwritten');
  assert.ok(new Date(endTime).getTime() > new Date('2026-07-28T00:00:00Z').getTime(),
    'endTime should default to now, not to startTime + hours');
});

test('resolveLrqWindow: endTime-only → startTime = endTime - hours', () => {
  const { startTime, endTime } = resolveLrqWindow({ endTime: '2026-07-29T00:00:00Z', hours: 48 });
  assert.equal(endTime, '2026-07-29T00:00:00Z');
  assert.equal(startTime, '2026-07-27T00:00:00Z');
});

test('resolveLrqWindow: both provided → untouched', () => {
  const { startTime, endTime } = resolveLrqWindow({
    startTime: '2026-07-01T00:00:00Z',
    endTime: '2026-07-15T12:34:56Z',
  });
  assert.equal(startTime, '2026-07-01T00:00:00Z');
  assert.equal(endTime, '2026-07-15T12:34:56Z');
});

// ─── pickMatchCount ───────────────────────────────────────────────────────────

test('pickMatchCount: reads data.matchCount (current engines)', () => {
  assert.equal(pickMatchCount({ data: { matchCount: 42 } }), 42);
});

test('pickMatchCount: data.matchCount of 0 is a real value, not "missing"', () => {
  assert.equal(pickMatchCount({ data: { matchCount: 0 }, matchCount: 99 }), 0);
});

test('pickMatchCount: falls back to top level (legacy engines)', () => {
  assert.equal(pickMatchCount({ matchCount: 7, data: {} }), 7);
});

test('pickMatchCount: null when absent everywhere', () => {
  assert.equal(pickMatchCount({ data: {} }), null);
  assert.equal(pickMatchCount({}), null);
});

// ─── keyCandidates ────────────────────────────────────────────────────────────

test('keyCandidates: log_read skips unconfigured keys, keeps scope order, ends at console JWT', () => {
  process.env.SDL_LOG_READ_KEY = '';
  process.env.SDL_CONFIG_READ_KEY = 'cfg-read';
  process.env.SDL_CONFIG_WRITE_KEY = 'cfg-write';
  process.env.S1_CONSOLE_API_TOKEN = 'console-jwt';
  try {
    assert.deepEqual(keyCandidates('log_read'), ['cfg-read', 'cfg-write', 'console-jwt']);
  } finally {
    delete process.env.SDL_LOG_READ_KEY;
    delete process.env.SDL_CONFIG_READ_KEY;
    delete process.env.SDL_CONFIG_WRITE_KEY;
    delete process.env.S1_CONSOLE_API_TOKEN;
  }
});

test('keyCandidates: returns ALL configured candidates so 403s can fall through', () => {
  process.env.SDL_LOG_READ_KEY = 'log-read';
  process.env.SDL_CONFIG_READ_KEY = 'cfg-read';
  process.env.SDL_CONFIG_WRITE_KEY = '';
  process.env.S1_CONSOLE_API_TOKEN = 'console-jwt';
  try {
    const c = keyCandidates('log_read');
    assert.ok(c.length > 1, 'must expose the full chain, not just the first key');
    assert.equal(c[0], 'log-read');
    assert.equal(c[c.length - 1], 'console-jwt');
  } finally {
    delete process.env.SDL_LOG_READ_KEY;
    delete process.env.SDL_CONFIG_READ_KEY;
    delete process.env.SDL_CONFIG_WRITE_KEY;
    delete process.env.S1_CONSOLE_API_TOKEN;
  }
});

// ─── hecIngest Content-Type per endpoint (mocked fetch, no network) ──────────
// /event takes HEC JSON envelopes and must be application/json or the envelope
// (including per-event "time" backdating) is indexed as opaque text at receive
// time. Live-verified 2026-07-29: with the fix, a {"time": <epoch>} envelope
// posted via hec_ingest indexed at exactly the backdated timestamp.

test('hecIngest: /event posts application/json, /raw posts text/plain', async () => {
  process.env.S1_HEC_INGEST_URL = 'https://ingest.example.invalid';
  process.env.S1_CONSOLE_API_TOKEN = 'tok';
  const seen = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url, opts) => {
    seen.push({ url, contentType: opts.headers['Content-Type'] });
    return new Response(JSON.stringify({ text: 'Success', code: 0 }), {
      status: 200, headers: { 'Content-Type': 'application/json' },
    });
  };
  try {
    const { hecIngest } = await import('../lib/hec.js');
    await hecIngest('{"time":123,"event":"x"}', { scope: 'a', endpoint: 'event' });
    await hecIngest('plain line', { scope: 'a', endpoint: 'raw' });
    assert.equal(seen[0].contentType, 'application/json');
    assert.equal(seen[1].contentType, 'text/plain');
  } finally {
    globalThis.fetch = realFetch;
    delete process.env.S1_HEC_INGEST_URL;
    delete process.env.S1_CONSOLE_API_TOKEN;
  }
});

// ─── doFetch write-retry semantics (mocked fetch, no network) ────────────────
// A 5xx after a mutating POST may land after the server committed; auto-retry
// would double-write. GET (idempotent) still retries; POST does not unless the
// caller opts in for a read-only POST (GraphQL query, Purple launch).

test('apiGet retries on 500 (idempotent)', async () => {
  process.env.S1_CONSOLE_URL = 'https://mgmt.example.invalid';
  process.env.S1_CONSOLE_API_TOKEN = 'tok';
  let calls = 0;
  const realFetch = globalThis.fetch;
  globalThis.fetch = async () => {
    calls++;
    if (calls === 1) return new Response('err', { status: 500 });
    return new Response(JSON.stringify({ data: { ok: true } }), { status: 200, headers: { 'Content-Type': 'application/json' } });
  };
  try {
    const { apiGet } = await import('../lib/s1.js');
    const r = await apiGet('/web/api/v2.1/agents');
    assert.equal(calls, 2, 'GET should retry once then succeed');
    assert.deepEqual(r, { data: { ok: true } });
  } finally {
    globalThis.fetch = realFetch;
    delete process.env.S1_CONSOLE_URL; delete process.env.S1_CONSOLE_API_TOKEN;
  }
});

test('apiPost does NOT retry a mutating POST on 500 (no double-write)', async () => {
  process.env.S1_CONSOLE_URL = 'https://mgmt.example.invalid';
  process.env.S1_CONSOLE_API_TOKEN = 'tok';
  let calls = 0;
  const realFetch = globalThis.fetch;
  globalThis.fetch = async () => { calls++; return new Response('boom', { status: 500 }); };
  try {
    const { apiPost } = await import('../lib/s1.js');
    await assert.rejects(() => apiPost('/web/api/v2.1/cloud-detection/rules', { data: {} }));
    assert.equal(calls, 1, 'mutating POST must be attempted exactly once');
  } finally {
    globalThis.fetch = realFetch;
    delete process.env.S1_CONSOLE_URL; delete process.env.S1_CONSOLE_API_TOKEN;
  }
});

test('apiPost with allowRetry:true retries a read-only POST on 500', async () => {
  process.env.S1_CONSOLE_URL = 'https://mgmt.example.invalid';
  process.env.S1_CONSOLE_API_TOKEN = 'tok';
  let calls = 0;
  const realFetch = globalThis.fetch;
  globalThis.fetch = async () => {
    calls++;
    if (calls === 1) return new Response('err', { status: 503 });
    return new Response(JSON.stringify({ data: {} }), { status: 200, headers: { 'Content-Type': 'application/json' } });
  };
  try {
    const { apiPost } = await import('../lib/s1.js');
    await apiPost('/web/api/v2.1/graphql', { query: '{x}' }, { allowRetry: true });
    assert.equal(calls, 2, 'opted-in read-only POST should retry');
  } finally {
    globalThis.fetch = realFetch;
    delete process.env.S1_CONSOLE_URL; delete process.env.S1_CONSOLE_API_TOKEN;
  }
});

// ─── sdlFetch 403 fallthrough (mocked fetch, no network) ─────────────────────

test('sdlFetch: 403 on first key falls through to the console JWT', async (t) => {
  process.env.SDL_XDR_URL = 'https://xdr.example.invalid';
  process.env.SDL_LOG_READ_KEY = '';
  process.env.SDL_CONFIG_READ_KEY = 'wrong-scope-key';
  process.env.SDL_CONFIG_WRITE_KEY = '';
  process.env.S1_CONSOLE_API_TOKEN = 'console-jwt';

  const seenTokens = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url, opts) => {
    const auth = opts.headers.Authorization;
    seenTokens.push(auth);
    if (auth === 'Bearer wrong-scope-key') {
      return new Response(
        JSON.stringify({ message: 'authorization token does not grant View logs permission' }),
        { status: 403, headers: { 'Content-Type': 'application/json' } },
      );
    }
    return new Response(JSON.stringify({ matches: [] }), {
      status: 200, headers: { 'Content-Type': 'application/json' },
    });
  };

  try {
    const { v1Query } = await import('../lib/sdl.js');
    const res = await v1Query("dataSource.name=='x'", { maxCount: 1 });
    assert.deepEqual(res, { matches: [] });
    assert.deepEqual(seenTokens, ['Bearer wrong-scope-key', 'Bearer console-jwt'],
      'must try the wrong-scoped key, get 403, then fall through to the console JWT');
  } finally {
    globalThis.fetch = realFetch;
    delete process.env.SDL_XDR_URL;
    delete process.env.SDL_LOG_READ_KEY;
    delete process.env.SDL_CONFIG_READ_KEY;
    delete process.env.SDL_CONFIG_WRITE_KEY;
    delete process.env.S1_CONSOLE_API_TOKEN;
  }
});
