/**
 * SSRF / API-token exfiltration regression test (finding 019eff58).
 *
 * Verifies that the s1_api_* client (lib/s1.js) can no longer be steered into
 * changing the request authority via an attacker-supplied `path`. A path like
 * "@evil.example/x", ".evil.example/x", "//evil.example/x", or "/\evil/x" used
 * to redirect the authenticated request — and the tenant ApiToken — off-host.
 * After the safeUrl() fix, every one of these must throw BEFORE fetch runs, and
 * a benign path must still resolve to the configured console origin with the
 * ApiToken attached.
 */

// Credentials must be present before importing s1.js (getCreds reads env live).
process.env.S1_CONSOLE_URL = 'https://usea1-acme.sentinelone.net';
process.env.S1_CONSOLE_API_TOKEN = 'test-token-xxxxxxxxxxxxxxxxxxxx';

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { apiGet, apiPost, apiPut, apiDelete, apiPatch } from '../lib/s1.js';

const CONSOLE_ORIGIN = 'https://usea1-acme.sentinelone.net';

// Malicious paths that must never reach fetch().
const MALICIOUS = [
  '@evil.example/web/api/v2.1/threats',   // userinfo trick -> host becomes evil.example
  '.evil.example/web/api/v2.1/threats',   // dot-suffix -> host becomes ...net.evil.example
  '//evil.example/x',                     // protocol-relative -> authority = evil.example
  'https://evil.example/x',               // absolute URL, wrong scheme/host
  '/\\evil.example/x',                    // backslash normalises to // in WHATWG URL
  'evil.example/x',                       // no leading slash at all
  '',                                     // empty
];

function stubFetch() {
  const calls = [];
  global.fetch = async (url, opts) => {
    calls.push({ url: String(url), opts });
    return {
      ok: true,
      status: 200,
      headers: { get: () => null },
      text: async () => JSON.stringify({ ok: true }),
    };
  };
  return calls;
}

test('ssrf: benign path resolves to console origin with ApiToken attached', async () => {
  const calls = stubFetch();
  await apiGet('/web/api/v2.1/agents', { limit: 5 });
  assert.equal(calls.length, 1);
  const u = new URL(calls[0].url);
  assert.equal(u.origin, CONSOLE_ORIGIN);
  assert.equal(u.pathname, '/web/api/v2.1/agents');
  assert.equal(u.searchParams.get('limit'), '5');
  assert.equal(calls[0].opts.headers.Authorization, 'ApiToken test-token-xxxxxxxxxxxxxxxxxxxx');
});

test('ssrf: apiGet rejects every host-redirect path and never calls fetch', async () => {
  for (const bad of MALICIOUS) {
    const calls = stubFetch();
    await assert.rejects(
      () => apiGet(bad),
      /must be a string starting with|may not change the request origin/,
      `apiGet should reject path ${JSON.stringify(bad)}`,
    );
    assert.equal(calls.length, 0, `fetch must NOT run for path ${JSON.stringify(bad)}`);
  }
});

test('ssrf: apiPost/apiPut/apiDelete/apiPatch all reject host-redirect paths', async () => {
  const verbs = [
    ['apiPost', (p) => apiPost(p, {})],
    ['apiPut', (p) => apiPut(p, {})],
    ['apiDelete', (p) => apiDelete(p, {})],
    ['apiPatch', (p) => apiPatch(p, {})],
  ];
  for (const [name, fn] of verbs) {
    const calls = stubFetch();
    await assert.rejects(() => fn('@evil.example/x'), /path/, `${name} should reject @evil path`);
    assert.equal(calls.length, 0, `${name}: fetch must not run for @evil path`);
  }
});

test('ssrf: origin-pinning backstops paths that pass the leading-slash check', async () => {
  const calls = stubFetch();
  // "//evil" is caught up front by the single-leading-slash rule.
  await assert.rejects(() => apiPost('//evil.example/x', {}), /must be a string starting with a single/);
  // "/\evil" passes the leading-slash rule (starts with one "/") but WHATWG URL
  // normalises the backslash to "/", yielding a foreign authority — the origin
  // check is what stops it. This proves the two layers are both load-bearing.
  await assert.rejects(() => apiPost('/\\evil.example/x', {}), /may not change the request origin/);
  assert.equal(calls.length, 0);
});
