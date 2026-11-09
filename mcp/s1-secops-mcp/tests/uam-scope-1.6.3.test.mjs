/**
 * UAM alert scope (1.6.3): uam_get_alert and uam_list_alerts return the alert's account and
 * site (id and name) as flat fields, and uam_get_alert adds detectionScope when the alert was
 * detected under a different account or site. HTTP is mocked; no network.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

process.env.S1_CONSOLE_URL = 'https://mgmt.example.invalid';
process.env.S1_CONSOLE_API_TOKEN = 'tok';

const s1 = await import('../lib/s1.js');
const { ALL_TOOLS } = await import('../lib/server-core.js');
const tool = (name) => ALL_TOOLS.find((t) => t.name === name);

const ACC = { id: '900000000000000001', name: 'Account One' };
const SITE = { id: '900000000000000005', name: 'Site Five' };
const OTHER = { id: '900000000000000009', name: 'Site Nine' };
const SCOPE_KEYS = ['accountId', 'accountName', 'siteId', 'siteName'];

function mock({ alert, list = [] }) {
  process.env.S1_CONSOLE_URL = 'https://mgmt.example.invalid';
  process.env.S1_CONSOLE_API_TOKEN = 'tok';
  const calls = [];
  const real = globalThis.fetch;
  const json = (obj) => new Response(JSON.stringify(obj), { status: 200, headers: { 'Content-Type': 'application/json' } });
  globalThis.fetch = async (url, opts = {}) => {
    const body = opts.body ? JSON.parse(opts.body) : {};
    const op = body.query?.match(/(query|mutation)\s+(\w+)/)?.[2];
    calls.push({ op, query: body.query, variables: body.variables });
    if (op === 'GetAlert') return json({ data: { alert: alert === undefined ? null : structuredClone(alert) } });
    if (op === 'GetAlertNotes') return json({ data: { alertNotes: { data: [{ id: 'n1', text: 'hello' }] } } });
    if (op === 'ListAlerts') {
      return json({ data: { alerts: { totalCount: list.length, pageInfo: { hasNextPage: false, endCursor: null },
        edges: list.map((node) => ({ node: structuredClone(node) })) } } });
    }
    return json({ data: {} });
  };
  return { calls, restore: () => { globalThis.fetch = real; } };
}

const scopeOf = (account, site) => ({ scope: { account, site } });
const detectedIn = (account, site) => ({ scope: { accountId: account.id, accountName: account.name, siteId: site.id, siteName: site.name } });

test('GetAlert selects the current and the detection-time scope with names', async () => {
  const m = mock({ alert: { id: 'a1', realTime: scopeOf(ACC, SITE), detectionTime: detectedIn(ACC, SITE) } });
  try {
    await s1.uamGetAlert('a1');
    const q = m.calls.find((c) => c.op === 'GetAlert').query.replace(/\s+/g, ' ');
    assert.match(q, /realTime \{ scope \{ account \{ id name \} site \{ id name \} \} \}/);
    assert.match(q, /detectionTime \{ scope \{ accountId accountName siteId siteName \} \}/);
  } finally { m.restore(); }
});

test('uam_get_alert returns flat account and site fields and notes, no nested scope objects', async () => {
  const m = mock({ alert: { id: 'a1', name: 'x', realTime: scopeOf(ACC, SITE), detectionTime: detectedIn(ACC, SITE) } });
  try {
    const r = JSON.parse(await tool('uam_get_alert').handler({ alertId: 'a1' }));
    assert.deepEqual(SCOPE_KEYS.map((k) => r[k]), [ACC.id, ACC.name, SITE.id, SITE.name]);
    assert.equal(r.realTime, undefined);
    assert.equal(r.detectionTime, undefined);
    assert.equal(r.detectionScope, undefined, 'same scope at detection: no detectionScope');
    assert.equal(r.notes.length, 1);
    assert.equal(r.name, 'x');
  } finally { m.restore(); }
});

test('uam_get_alert adds detectionScope when the alert moved site', async () => {
  const m = mock({ alert: { id: 'a1', realTime: scopeOf(ACC, SITE), detectionTime: detectedIn(ACC, OTHER) } });
  try {
    const r = JSON.parse(await tool('uam_get_alert').handler({ alertId: 'a1' }));
    assert.equal(r.siteId, SITE.id, 'top level is where the alert is now');
    assert.deepEqual(r.detectionScope, { accountId: ACC.id, accountName: ACC.name, siteId: OTHER.id, siteName: OTHER.name });
  } finally { m.restore(); }
});

test('uam_get_alert with no scope in the response gives nulls, and a missing alert stays null', async () => {
  let m = mock({ alert: { id: 'a1' } });
  try {
    const r = JSON.parse(await tool('uam_get_alert').handler({ alertId: 'a1' }));
    assert.deepEqual(SCOPE_KEYS.map((k) => r[k]), [null, null, null, null]);
    assert.equal(r.detectionScope, undefined);
  } finally { m.restore(); }
  m = mock({ alert: null });
  try {
    assert.equal(await s1.uamGetAlert('missing'), null);
  } finally { m.restore(); }
});

test('uam_list_alerts selects names and returns flat account and site fields per alert', async () => {
  const m = mock({ list: [
    { id: 'l1', realTime: scopeOf(ACC, SITE) },
    { id: 'l2', realTime: scopeOf(ACC, OTHER) },
  ] });
  try {
    const r = JSON.parse(await tool('uam_list_alerts').handler({ first: 2 }));
    const q = m.calls.find((c) => c.op === 'ListAlerts').query.replace(/\s+/g, ' ');
    assert.match(q, /realTime \{ scope \{ account \{ id name \} site \{ id name \} \} \}/);
    assert.deepEqual(r.alerts.map((a) => SCOPE_KEYS.map((k) => a[k])), [
      [ACC.id, ACC.name, SITE.id, SITE.name],
      [ACC.id, ACC.name, OTHER.id, OTHER.name],
    ]);
    assert.ok(r.alerts.every((a) => a.realTime === undefined && a.detectionScope === undefined));
  } finally { m.restore(); }
});

test('the tool descriptions name the scope fields', () => {
  for (const t of ['uam_get_alert', 'uam_list_alerts']) {
    for (const k of SCOPE_KEYS) assert.ok(tool(t).description.includes(k), `${t} description names ${k}`);
  }
  assert.match(tool('uam_get_alert').description, /detectionScope/);
});
