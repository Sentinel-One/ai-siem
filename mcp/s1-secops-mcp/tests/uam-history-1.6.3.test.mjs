/**
 * UAM alert history (1.6.3): uam_get_alert returns the alertHistory connection as a flat
 * history array, follows endCursor up to ALERT_HISTORY_MAX_PAGES pages, and says when it
 * stopped early. HTTP is mocked; no network.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

process.env.S1_CONSOLE_URL = 'https://mgmt.example.invalid';
process.env.S1_CONSOLE_API_TOKEN = 'tok';

const s1 = await import('../lib/s1.js');
const { ALL_TOOLS } = await import('../lib/server-core.js');
const tool = (name) => ALL_TOOLS.find((t) => t.name === name);

const item = (i) => ({ createdAt: `2026-11-0${(i % 9) + 1}T00:00:00Z`, eventType: 'STATUS', eventText: `change ${i}` });

function mock({ pages, alert = { id: 'a1' } }) {
  const calls = [];
  const real = globalThis.fetch;
  const json = (obj) => new Response(JSON.stringify(obj), { status: 200, headers: { 'Content-Type': 'application/json' } });
  globalThis.fetch = async (url, opts = {}) => {
    const body = opts.body ? JSON.parse(opts.body) : {};
    const op = body.query?.match(/(query|mutation)\s+(\w+)/)?.[2];
    calls.push({ op, variables: body.variables });
    if (op === 'GetAlert') return json({ data: { alert } });
    if (op === 'GetAlertNotes') return json({ data: { alertNotes: { data: [] } } });
    if (op === 'GetAlertHistory') {
      const n = calls.filter((c) => c.op === 'GetAlertHistory').length - 1;
      const page = pages[n] || { items: [], hasNextPage: false };
      return json({ data: { alertHistory: {
        edges: page.items.map((node) => ({ node })),
        pageInfo: { hasNextPage: page.hasNextPage, endCursor: page.hasNextPage ? `c${n + 1}` : null },
        totalCount: page.total ?? null,
      } } });
    }
    return json({ data: {} });
  };
  return { calls, restore: () => { globalThis.fetch = real; } };
}

test('uam_get_alert returns history entries with their type, text and time', async () => {
  const m = mock({ pages: [{ items: [item(1), item(2)], hasNextPage: false, total: 2 }] });
  try {
    const r = JSON.parse(await tool('uam_get_alert').handler({ alertId: 'a1' }));
    assert.deepEqual(r.history, [item(1), item(2)]);
    assert.equal(r.historyTotalCount, 2);
    assert.equal(r.historyTruncated, false);
    const h = m.calls.filter((c) => c.op === 'GetAlertHistory');
    assert.equal(h.length, 1);
    assert.deepEqual(h[0].variables, { id: 'a1', first: s1.ALERT_HISTORY_PAGE, after: null });
  } finally { m.restore(); }
});

test('history follows endCursor across pages', async () => {
  const m = mock({ pages: [
    { items: [item(1)], hasNextPage: true, total: 3 },
    { items: [item(2)], hasNextPage: true, total: 3 },
    { items: [item(3)], hasNextPage: false, total: 3 },
  ] });
  try {
    const r = await s1.uamGetAlert('a1');
    assert.equal(r.history.length, 3);
    assert.equal(r.historyTruncated, false);
    assert.deepEqual(m.calls.filter((c) => c.op === 'GetAlertHistory').map((c) => c.variables.after), [null, 'c1', 'c2']);
  } finally { m.restore(); }
});

test('history stops at the page cap and says it was truncated', async () => {
  const pages = Array.from({ length: s1.ALERT_HISTORY_MAX_PAGES + 2 }, (_, i) => ({ items: [item(i)], hasNextPage: true, total: 999 }));
  const m = mock({ pages });
  try {
    const r = await s1.uamGetAlert('a1');
    assert.equal(m.calls.filter((c) => c.op === 'GetAlertHistory').length, s1.ALERT_HISTORY_MAX_PAGES);
    assert.equal(r.history.length, s1.ALERT_HISTORY_MAX_PAGES);
    assert.equal(r.historyTotalCount, 999);
    assert.equal(r.historyTruncated, true);
  } finally { m.restore(); }
});

test('an alert with no history gives an empty array, and a missing alert stays null', async () => {
  let m = mock({ pages: [{ items: [], hasNextPage: false, total: 0 }] });
  try {
    const r = await s1.uamGetAlert('a1');
    assert.deepEqual([r.history, r.historyTotalCount, r.historyTruncated], [[], 0, false]);
  } finally { m.restore(); }
  m = mock({ pages: [], alert: null });
  try { assert.equal(await s1.uamGetAlert('nope'), null); } finally { m.restore(); }
});

test('the tool description names the history fields', () => {
  const d = tool('uam_get_alert').description;
  for (const k of ['history', 'historyTotalCount', 'historyTruncated']) assert.ok(d.includes(k), k);
});
