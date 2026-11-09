/**
 * Regression tests for 1.6.1.
 *
 *   1. firstTopLevelPipe splits at the first `|` outside quotes and at
 *      parenthesis depth 0, matching `_first_top_level_pipe` in
 *      mgmt-console-api/scripts/pq.py. A subquery in the initial filter
 *      (`f in (a | group 1 by f) | group n=count()`) keeps its own pipe, so
 *      excludeMetering and addSiteFilter send balanced parentheses. Splitting at
 *      the inner pipe gets HTTP 400 `Expected ")"` from the LRQ API.
 *   2. The LOG queryType guard rejects any unquoted pipe, including one inside
 *      parentheses.
 *   3. normalizeS1ApiGetParams injects isLegacy=false on the rule listing and
 *      the single-rule form only. /rules/export-vcs rejects the parameter with
 *      HTTP 400 `isLegacy: Unknown field`.
 *
 * No network.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

process.env.S1_CONSOLE_URL ||= 'https://tenant.sentinelone.net';
process.env.S1_CONSOLE_API_TOKEN ||= 'test-token';

const { firstTopLevelPipe, hasUnquotedPipe, excludeMetering } = await import('../lib/metering.js');
const { addSiteFilter } = await import('../lib/lrq-scope.js');
const { lrqRun } = await import('../lib/s1.js');
const { normalizeS1ApiGetParams } = await import('../tools/mgmt-console.js');

const SITE = '2175066823985525506';
const balanced = (s) => {
  let depth = 0, quote = null;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (quote) { if (c === '\\') { i++; continue; } if (c === quote) quote = null; continue; }
    if (c === "'" || c === '"') { quote = c; continue; }
    if (c === '(') depth++;
    else if (c === ')') { depth--; if (depth < 0) return false; }
  }
  return depth === 0 && quote === null;
};

// ─── 1. depth-aware split (ports of the pq.py cases) ─────────────────────────

test('subquery in the initial filter: split after the subquery, metering ANDed, parentheses balanced', () => {
  const q = "f in (a='x' | group 1 by f) | group n=count()";
  assert.equal(firstTopLevelPipe(q), q.indexOf(') |') + 2);
  const r = excludeMetering(q);
  assert.equal(r.applied, true);
  assert.equal(r.query, "tag != 'logVolume' and (f in (a='x' | group 1 by f)\n) | group n=count()");
  assert.ok(balanced(r.query), r.query);
});

test('quoted pipe is not a split point', () => {
  const q = "cmd contains 'a|b' and x=\"c|d\" | limit 5";
  assert.equal(firstTopLevelPipe(q), q.indexOf(' | limit') + 1);
});

test('escaped quote inside a string does not end the string', () => {
  const q = "cmd contains 'it\\'s | here' | limit 1";
  assert.equal(firstTopLevelPipe(q), q.indexOf(' | limit') + 1);
});

test('subquery in a later stage is left untouched', () => {
  const q = 'a=1 | filter b in (c=2 | group 1 by b) | limit 3';
  assert.equal(firstTopLevelPipe(q), q.indexOf(' | filter') + 1);
  const r = excludeMetering(q);
  assert.equal(r.applied, true);
  assert.equal(r.query, "tag != 'logVolume' and (a=1\n) | filter b in (c=2 | group 1 by b) | limit 3");
  assert.ok(balanced(r.query), r.query);
});

test('no top-level pipe returns -1', () => {
  assert.equal(firstTopLevelPipe('a=1 and (b=2 or c=3)'), -1);
});

test('ignoreParens finds a pipe inside parentheses; hasUnquotedPipe agrees', () => {
  const q = 'a in (b | group 1 by a)';
  assert.equal(firstTopLevelPipe(q), -1);
  assert.equal(firstTopLevelPipe(q, { ignoreParens: true }), q.indexOf('|'));
  assert.equal(hasUnquotedPipe(q), true);
  assert.equal(hasUnquotedPipe("cmd contains 'a|b'"), false);
  assert.equal(hasUnquotedPipe('a=1'), false);
});

// ─── 2. site scope uses the same split ───────────────────────────────────────

test('addSiteFilter: subquery in the initial filter keeps the site term outside it, parentheses balanced', () => {
  const q = "event.type='Process Creation' src.process.name in (event.type='Process Creation' src.process.name='svchost.exe' | group 1 by src.process.name) | group n=count()";
  const r = addSiteFilter(q, SITE);
  assert.equal(r.applied, true);
  assert.equal(
    r.query,
    `site.id='${SITE}' and (event.type='Process Creation' src.process.name in (event.type='Process Creation' src.process.name='svchost.exe' | group 1 by src.process.name)\n) | group n=count()`,
  );
  assert.ok(balanced(r.query), r.query);
  // The site term precedes the opening parenthesis of the caller's filter, so it is
  // not inside the subquery.
  assert.ok(r.query.startsWith(`site.id='${SITE}' and (`));
  assert.equal(r.query.split(`site.id='${SITE}'`).length - 1, 1);
});

test('site scope then metering: both terms outside the subquery, parentheses balanced', () => {
  const q = "f in (a='x' | group 1 by f) | group n=count()";
  const site = addSiteFilter(q, SITE);
  const both = excludeMetering(site.query);
  assert.equal(both.applied, true);
  assert.ok(balanced(both.query), both.query);
  assert.match(both.query, /^tag != 'logVolume' and \(site\.id='\d+' and \(f in \(a='x' \| group 1 by f\)\n\)\n\) \| group n=count\(\)$/);
});

test('| join and | union are unchanged by the depth-aware split', () => {
  const join = '| join a=(x=1 | group n=count() by k), b=(y=2 | group m=count() by k) on k | limit 5';
  assert.deepEqual(excludeMetering(join), { query: join, applied: false, reason: 'query opens with | join, which does not scan the event stream directly' });
  const sj = addSiteFilter(join, SITE);
  assert.equal(sj.applied, true);
  assert.equal(sj.query, `| join a=(site.id='${SITE}' and (x=1\n) | group n=count() by k), b=(site.id='${SITE}' and (y=2\n) | group m=count() by k) on k | limit 5`);
  assert.ok(balanced(sj.query));

  const union = '| union (x=1 | group n=count()), (y=2 | group n=count())';
  assert.equal(excludeMetering(union).applied, false);
  const su = addSiteFilter(union, SITE);
  assert.equal(su.query, `| union (site.id='${SITE}' and (x=1\n) | group n=count()), (site.id='${SITE}' and (y=2\n) | group n=count())`);
  assert.ok(balanced(su.query));
});

// ─── 3. LOG guard is unchanged ────────────────────────────────────────────────

test('LOG queryType still rejects a pipe inside parentheses, before any HTTP call', async () => {
  const real = globalThis.fetch;
  let called = 0;
  globalThis.fetch = async () => { called++; throw new Error('no network in this test'); };
  try {
    await assert.rejects(
      lrqRun('a in (b | group 1 by a)', { queryType: 'LOG' }),
      /queryType "LOG" takes a filter expression only/,
    );
    await assert.rejects(
      lrqRun('a=1 | limit 5', { queryType: 'LOG' }),
      /queryType "LOG" takes a filter expression only/,
    );
  } finally {
    globalThis.fetch = real;
  }
  assert.equal(called, 0);
});

// ─── 4. isLegacy guard: listing and single-rule form only ────────────────────

test('isLegacy=false is injected only for the rule listing and the single-rule form', () => {
  const P = '/web/api/v2.1/cloud-detection/';
  const inject = ['rules', 'rules/', 'rules?x=1', 'rules/123', 'rules/123/', 'rules/123?expanded=true'];
  for (const p of inject) {
    assert.equal(normalizeS1ApiGetParams(P + p, {}).isLegacy, false, `${p} must inject`);
  }
  const skip = ['rules/export-vcs', 'rules/export-vcs?cursor=abc', 'rules/parse-vcs', 'rules/parse-vcs?mode=diff', 'rules/enable', 'rules/disable', 'rules-export', 'ruleset', 'alerts'];
  for (const p of skip) {
    assert.equal(normalizeS1ApiGetParams(P + p, {}).isLegacy, undefined, `${p} must not inject`);
  }
});

test('an explicit isLegacy is respected', () => {
  const p = '/web/api/v2.1/cloud-detection/rules';
  assert.equal(normalizeS1ApiGetParams(p, { isLegacy: true }).isLegacy, true);
  assert.equal(normalizeS1ApiGetParams(p, { isLegacy: false }).isLegacy, false);
  const snake = normalizeS1ApiGetParams(p, { is_legacy: true });
  assert.equal(snake.isLegacy, undefined);
  assert.equal(snake.is_legacy, true);
  assert.deepEqual(normalizeS1ApiGetParams(`${p}?isLegacy=true`, { limit: 5 }), { limit: 5 });
});
