/**
 * 1.6.0: built-in threat intelligence (ti_vt_*, ti_shodan_*) and purple_ai_query.
 * HTTP is mocked; no network. Keys are fake.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

process.env.S1_CONSOLE_URL ||= 'https://tenant.sentinelone.net';
process.env.S1_CONSOLE_API_TOKEN ||= 'test-token-not-a-jwt';
process.env.S1_TI_RETRY_WAIT_MS = '0';

const ti = await import('../lib/ti.js');
const access = await import('../lib/access.js');
const { ALL_TOOLS, dispatch, toolDefs } = await import('../lib/server-core.js');

const VT_KEY = 'vt-test-key-0123456789abcdef';
const SHODAN_KEY = 'shodan-test-key-0123456789';

async function withEnv(vars, fn) {
  const saved = {};
  for (const k of Object.keys(vars)) saved[k] = process.env[k];
  for (const [k, v] of Object.entries(vars)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
  try { return await fn(); } finally {
    for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
  }
}

/** Mock fetch with a queue of { status, body, headers }. Records each call. */
function mockFetch(responses) {
  const calls = [];
  const queue = [...responses];
  const real = globalThis.fetch;
  globalThis.fetch = async (url, opts = {}) => {
    calls.push({ url: String(url), method: opts.method || 'GET', headers: opts.headers || {}, body: opts.body });
    const r = queue.length > 1 ? queue.shift() : queue[0];
    const status = r.status ?? 200;
    const text = typeof r.body === 'string' ? r.body : JSON.stringify(r.body ?? {});
    return { ok: status >= 200 && status < 300, status, headers: new Map(Object.entries(r.headers || {})), text: async () => text };
  };
  return { calls, restore: () => { globalThis.fetch = real; } };
}

const callTool = async (name, args) => {
  const r = await dispatch('tools/call', { name, arguments: args }, 1);
  return { isError: r.result.isError, text: r.result.content[0].text };
};

// ─── Indicators ──────────────────────────────────────────────────────────────

test('classifyIndicator: hashes, IPs, domains, URLs and defanged input', () => {
  const md5 = 'D41D8CD98F00B204E9800998ECF8427E';
  assert.deepEqual(ti.classifyIndicator(md5), { type: 'file', value: md5.toLowerCase(), id: md5.toLowerCase() });
  assert.equal(ti.classifyIndicator('a'.repeat(40)).type, 'file');
  assert.equal(ti.classifyIndicator('b'.repeat(64)).type, 'file');
  assert.equal(ti.classifyIndicator('8.8.8.8').type, 'ip');
  assert.equal(ti.classifyIndicator('2001:4860:4860::8888').type, 'ip');
  assert.equal(ti.classifyIndicator('Evil.Example.COM.').value, 'evil.example.com');
  assert.equal(ti.classifyIndicator('evil[.]example[.]com').value, 'evil.example.com');
  const u = ti.classifyIndicator('hxxps://evil[.]example/path?a=1');
  assert.equal(u.type, 'url');
  assert.equal(u.value, 'https://evil.example/path?a=1');
  assert.equal(u.id, Buffer.from('https://evil.example/path?a=1').toString('base64url').replace(/=+$/, ''));
  assert.ok(!u.id.includes('='));
});

test('classifyIndicator: explicit types are enforced and junk is refused', () => {
  assert.throws(() => ti.classifyIndicator('8.8.8.8', 'file'), /hash/);
  assert.throws(() => ti.classifyIndicator('not a thing'), /could not tell/);
  assert.throws(() => ti.classifyIndicator('ftp://x.example/a', 'url'), /http or https/);
  assert.throws(() => ti.classifyIndicator('999.1.1.1', 'ip'), /IPv4 or IPv6/);
  assert.throws(() => ti.classifyIndicator('-bad-.example', 'domain'), /domain/);
  assert.throws(() => ti.classifyIndicator(''), /required/);
  assert.throws(() => ti.classifyIndicator('x', 'nonsense'), /type must be/);
  assert.equal(ti.classifyIndicator('a'.repeat(32), 'hash').type, 'file');
});

// ─── Listing, classification ─────────────────────────────────────────────────

test('ti_* tools are listed only when their key is set; purple_ai_query is always listed', async () => {
  const names = () => toolDefs().map(t => t.name);
  await withEnv({ VIRUSTOTAL_API_KEY: undefined, VT_API_KEY: undefined, SHODAN_API_KEY: undefined }, () => {
    const n = names();
    assert.ok(n.includes('purple_ai_query'));
    for (const t of ['ti_vt_lookup', 'ti_vt_relationship', 'ti_shodan_host', 'ti_shodan_dns']) assert.ok(!n.includes(t), t);
  });
  await withEnv({ VIRUSTOTAL_API_KEY: VT_KEY, SHODAN_API_KEY: undefined }, () => {
    const n = names();
    assert.ok(n.includes('ti_vt_lookup') && n.includes('ti_vt_relationship'));
    assert.ok(!n.includes('ti_shodan_host'));
  });
  await withEnv({ VIRUSTOTAL_API_KEY: undefined, VT_API_KEY: VT_KEY, SHODAN_API_KEY: SHODAN_KEY }, () => {
    const n = names();
    assert.ok(n.includes('ti_vt_lookup'), 'VT_API_KEY alias works');
    assert.ok(n.includes('ti_shodan_host') && n.includes('ti_shodan_dns'));
  });
});

test('every new tool is classified read and works in read-only mode', async () => {
  for (const n of ['purple_ai_query', 'ti_vt_lookup', 'ti_vt_relationship', 'ti_shodan_host', 'ti_shodan_dns']) {
    assert.ok(ALL_TOOLS.find(t => t.name === n), `${n} registered`);
    assert.equal(access.accessOf(n), 'read', n);
    assert.equal(access.annotationsFor(n).readOnlyHint, true, n);
  }
  await withEnv({ S1_READ_ONLY: 'true', VIRUSTOTAL_API_KEY: VT_KEY }, async () => {
    const m = mockFetch([{ status: 404, body: { error: { code: 'NotFoundError', message: 'x' } } }]);
    try {
      const r = await callTool('ti_vt_lookup', { indicator: '8.8.8.8' });
      assert.equal(r.isError, false, r.text);
    } finally { m.restore(); }
  });
});

// ─── VirusTotal ──────────────────────────────────────────────────────────────

const VT_FILE = {
  data: {
    id: 'b'.repeat(64), type: 'file',
    attributes: {
      sha256: 'b'.repeat(64), md5: 'c'.repeat(32), meaningful_name: 'evil.exe', names: ['evil.exe', 'x.exe'],
      type_description: 'Win32 EXE', size: 1234, reputation: -50, tags: ['peexe'],
      last_analysis_date: 1790000000, total_votes: { harmless: 0, malicious: 3 },
      last_analysis_stats: { malicious: 40, suspicious: 1, harmless: 0, undetected: 20 },
      last_analysis_results: {
        EngA: { category: 'malicious', result: 'Trojan.X' },
        EngB: { category: 'undetected', result: null },
        EngC: { category: 'suspicious', result: 'Heur' },
      },
      popular_threat_classification: { suggested_threat_label: 'trojan.x/y', popular_threat_category: [{ value: 'trojan' }], popular_threat_name: [{ value: 'x' }] },
      sandbox_verdicts: { Zenbox: { category: 'malicious', malware_names: ['X'] } },
      crowdsourced_yara_results: [{ rule_name: 'R1' }],
    },
  },
};

test('ti_vt_lookup: pinned origin, x-apikey header, trimmed file summary', async () => {
  await withEnv({ VIRUSTOTAL_API_KEY: VT_KEY }, async () => {
    const m = mockFetch([{ body: VT_FILE }]);
    try {
      const r = await ti.vtLookup('B'.repeat(64));
      assert.equal(m.calls.length, 1);
      const u = new URL(m.calls[0].url);
      assert.equal(u.origin, 'https://www.virustotal.com');
      assert.equal(u.pathname, `/api/v3/files/${'b'.repeat(64)}`);
      assert.equal(m.calls[0].method, 'GET');
      assert.equal(m.calls[0].headers['x-apikey'], VT_KEY);
      assert.equal(r.found, true);
      assert.equal(r.lastAnalysisStats.malicious, 40);
      assert.deepEqual(r.detections.map(d => d.engine), ['EngA', 'EngC']);
      assert.equal(r.threatLabel, 'trojan.x/y');
      assert.equal(r.meaningfulName, 'evil.exe');
      assert.deepEqual(r.yaraRules, ['R1']);
      assert.equal(r.lastAnalysisDate, new Date(1790000000 * 1000).toISOString());
      assert.match(r.link, /^https:\/\/www\.virustotal\.com\/gui\/file\//);
      assert.ok(!('last_analysis_results' in r), 'raw engine table is not returned');
    } finally { m.restore(); }
  });
});

test('ti_vt_lookup: URL id, IP and domain paths', async () => {
  await withEnv({ VIRUSTOTAL_API_KEY: VT_KEY }, async () => {
    const m = mockFetch([{ body: { data: { attributes: { as_owner: 'Google', country: 'US', last_analysis_stats: { malicious: 0 } } } } }]);
    try {
      const ip = await ti.vtLookup('8.8.8.8');
      assert.equal(new URL(m.calls[0].url).pathname, '/api/v3/ip_addresses/8.8.8.8');
      assert.equal(ip.asOwner, 'Google');
      await ti.vtLookup('example.com');
      assert.equal(new URL(m.calls[1].url).pathname, '/api/v3/domains/example.com');
      await ti.vtLookup('https://example.com/a b');
      const id = Buffer.from('https://example.com/a b').toString('base64url');
      assert.equal(new URL(m.calls[2].url).pathname, `/api/v3/urls/${id}`);
    } finally { m.restore(); }
  });
});

test('ti_vt_lookup: 404 is found:false (not benign); 429 retries then explains the quota; 401 says the key was rejected', async () => {
  await withEnv({ VIRUSTOTAL_API_KEY: VT_KEY }, async () => {
    let m = mockFetch([{ status: 404, body: { error: { code: 'NotFoundError', message: 'nope' } } }]);
    try {
      const r = await ti.vtLookup('8.8.4.4');
      assert.equal(r.found, false);
      assert.match(r.note, /not a benign verdict/);
    } finally { m.restore(); }
    m = mockFetch([{ status: 429, body: { error: { code: 'QuotaExceededError', message: 'Quota exceeded' } } }]);
    try {
      await assert.rejects(ti.vtLookup('8.8.4.4'), /429.*4 lookups per minute/);
      assert.equal(m.calls.length, 3, 'two retries');
    } finally { m.restore(); }
    m = mockFetch([{ status: 401, body: { error: { code: 'WrongCredentialsError', message: 'Wrong API key' } } }]);
    try {
      await assert.rejects(ti.vtLookup('8.8.4.4'), /401.*rejected/);
      assert.equal(m.calls.length, 1, '401 is not retried');
    } finally { m.restore(); }
  });
});

test('ti_vt_relationship: allowlist per type, limit clamp, trimmed items, cursor', async () => {
  await withEnv({ VIRUSTOTAL_API_KEY: VT_KEY }, async () => {
    await assert.rejects(ti.vtRelationship('8.8.8.8', 'dropped_files'), /not available for a ip/);
    const m = mockFetch([{ body: {
      data: [
        { type: 'resolution', id: 'r1', attributes: { date: 1790000000, host_name: 'evil.example', ip_address: '1.2.3.4', host_name_last_analysis_stats: { malicious: 5 } } },
        { type: 'collection', id: 'threat-actor--x', attributes: { name: 'APT-X', alt_names: ['X1'], collection_type: 'threat-actor', description: 'd'.repeat(1000) } },
      ],
      meta: { cursor: 'NEXT', count: 99 },
    } }]);
    try {
      const r = await ti.vtRelationship('1.2.3.4', 'resolutions', { limit: 500 });
      const u = new URL(m.calls[0].url);
      assert.equal(u.pathname, '/api/v3/ip_addresses/1.2.3.4/resolutions');
      assert.equal(u.searchParams.get('limit'), '40');
      assert.equal(r.count, 2);
      assert.equal(r.total, 99);
      assert.equal(r.nextCursor, 'NEXT');
      assert.equal(r.items[0].hostName, 'evil.example');
      assert.equal(r.items[0].hostDetections, 5);
      assert.equal(r.items[1].name, 'APT-X');
      assert.equal(r.items[1].description.length, 400);
      await ti.vtRelationship('1.2.3.4', 'resolutions', { cursor: 'NEXT' });
      assert.equal(new URL(m.calls[1].url).searchParams.get('cursor'), 'NEXT');
    } finally { m.restore(); }
  });
});

// ─── Shodan ──────────────────────────────────────────────────────────────────

test('ti_shodan_host: key in query only, summary, 404 is found:false', async () => {
  await withEnv({ SHODAN_API_KEY: SHODAN_KEY }, async () => {
    const m = mockFetch([{ body: {
      ip_str: '1.2.3.4', org: 'ExampleNet', asn: 'AS1', country_name: 'X', ports: [22, 443], vulns: ['CVE-2024-0002', 'CVE-2024-0001'],
      tags: ['vpn'], hostnames: ['h.example'],
      data: [{ port: 443, transport: 'tcp', product: 'nginx', _shodan: { module: 'https' }, http: { title: 'Login', server: 'nginx' }, ssl: { cert: { subject: { CN: 'h.example' }, issuer: { CN: 'CA' } } } }],
    } }]);
    try {
      const r = await ti.shodanHost('1[.]2[.]3[.]4');
      const u = new URL(m.calls[0].url);
      assert.equal(u.origin, 'https://api.shodan.io');
      assert.equal(u.pathname, '/shodan/host/1.2.3.4');
      assert.equal(u.searchParams.get('key'), SHODAN_KEY);
      assert.deepEqual(r.vulns, ['CVE-2024-0001', 'CVE-2024-0002']);
      assert.equal(r.vulnCount, 2);
      assert.equal(r.services[0].module, 'https');
      assert.equal(r.services[0].http.title, 'Login');
      assert.equal(r.services[0].tls.subject, 'h.example');
    } finally { m.restore(); }
    const m2 = mockFetch([{ status: 404, body: { error: 'No information available for that IP.' } }]);
    try { assert.equal((await ti.shodanHost('1.2.3.5')).found, false); } finally { m2.restore(); }
    await assert.rejects(ti.shodanHost('not-an-ip'), /valid IPv4 or IPv6/);
  });
});

test('Shodan errors never carry the key: not in the message, and redacted if echoed in a body', async () => {
  await withEnv({ SHODAN_API_KEY: SHODAN_KEY }, async () => {
    const m = mockFetch([{ status: 500, body: { error: `upstream failure for key=${SHODAN_KEY}` } }]);
    try {
      const r = await callTool('ti_shodan_host', { ip: '1.2.3.4' });
      assert.equal(r.isError, true);
      assert.ok(!r.text.includes(SHODAN_KEY), r.text);
      assert.match(r.text, /Shodan GET \/shodan\/host\/1\.2\.3\.4 → 500/);
      assert.ok(!r.text.includes('?key='), 'query string is never in the message');
    } finally { m.restore(); }
  });
});

test('ti_shodan_dns: resolve or reverse, validation', async () => {
  await withEnv({ SHODAN_API_KEY: SHODAN_KEY }, async () => {
    await assert.rejects(ti.shodanDns({}), /either hostnames or ips/);
    await assert.rejects(ti.shodanDns({ hostnames: ['a.example'], ips: ['1.1.1.1'] }), /either hostnames or ips/);
    await assert.rejects(ti.shodanDns({ hostnames: ['bad host'] }), /not a valid hostname/);
    const m = mockFetch([{ body: { 'a.example': '1.2.3.4' } }]);
    try {
      const r = await ti.shodanDns({ hostnames: ['A.example'] });
      const u = new URL(m.calls[0].url);
      assert.equal(u.pathname, '/dns/resolve');
      assert.equal(u.searchParams.get('hostnames'), 'a.example');
      assert.deepEqual(r, { mode: 'resolve', results: { 'a.example': '1.2.3.4' } });
      await ti.shodanDns({ ips: ['8.8.8.8'] });
      assert.equal(new URL(m.calls[1].url).pathname, '/dns/reverse');
    } finally { m.restore(); }
  });
});

test('a ti_* call without its key fails with a setup hint', async () => {
  await withEnv({ VIRUSTOTAL_API_KEY: undefined, VT_API_KEY: undefined }, async () => {
    const r = await callTool('ti_vt_lookup', { indicator: '8.8.8.8' });
    assert.equal(r.isError, true);
    assert.match(r.text, /VIRUSTOTAL_API_KEY is not configured/);
  });
});

// ─── purple_ai_query ─────────────────────────────────────────────────────────

test('purple_ai_query: request shape (tenantDetails twice, variable input), parsed result, read-only allowed', async () => {
  await withEnv({ S1_READ_ONLY: 'true' }, async () => {
    const m = mockFetch([{ body: { data: { purpleLaunchQuery: {
      resultType: 'POWER_QUERY',
      status: { state: 'COMPLETED', error: null },
      result: { message: null, summary: 's', powerQuery: { query: '| filter( x == 1 )', timeRange: { start: 1, end: 2 }, viewSelector: 'EDR' }, suggestedQuestions: [{ question: 'q2', powerQuery: null }] },
    } } } }]);
    try {
      const r = await callTool('purple_ai_query', { question: 'Show PowerShell "quotes" process creation', hours: 48 });
      assert.equal(r.isError, false, r.text);
      const out = JSON.parse(r.text);
      assert.equal(out.resultType, 'POWER_QUERY');
      assert.equal(out.powerQuery.query, '| filter( x == 1 )');
      assert.equal(out.suggestedQuestions.length, 1);
      const call = m.calls[0];
      assert.equal(new URL(call.url).pathname, '/web/api/v2.1/graphql');
      assert.equal(call.method, 'POST');
      const body = JSON.parse(call.body);
      assert.equal(body.variables.input, 'Show PowerShell "quotes" process creation');
      assert.equal((body.query.match(/tenantDetails:/g) || []).length, 2);
      assert.match(body.query, /baseUrl: "https:\/\/tenant\.sentinelone\.net"/);
      assert.match(body.query, /isAsync: false/);
      assert.ok(!body.query.includes('quotes'), 'the question travels as a variable, never inside the document');
      const [, s, e] = body.query.match(/displayedTimeRange: \{ start: (\d+), end: (\d+) \}/);
      assert.equal(Number(e) - Number(s), 48 * 3600 * 1000);
    } finally { m.restore(); }
  });
});

test('purple_ai_query: a Purple error status and GraphQL errors fail loudly; input is validated', async () => {
  let m = mockFetch([{ body: { data: { purpleLaunchQuery: { resultType: null, status: { state: 'FAILED', error: { errorType: 'UNKNOWN', errorDetail: 'boom' } }, result: null } } } }]);
  try {
    const r = await callTool('purple_ai_query', { question: 'x' });
    assert.equal(r.isError, true);
    assert.match(r.text, /UNKNOWN: boom.*Rephrase/);
  } finally { m.restore(); }
  m = mockFetch([{ body: { errors: [{ message: 'Not authorized' }] } }]);
  try {
    const r = await callTool('purple_ai_query', { question: 'x' });
    assert.match(r.text, /Purple AI error: Not authorized/);
  } finally { m.restore(); }
  const r1 = await callTool('purple_ai_query', { question: '   ' });
  assert.match(r1.text, /question is required/);
  const r2 = await callTool('purple_ai_query', { question: 'x', hours: -1 });
  assert.match(r2.text, /hours must be a positive number/);
  const r3 = await callTool('purple_ai_query', { question: 'x', startTime: '2026-11-02T00:00:00Z', endTime: '2026-11-01T00:00:00Z' });
  assert.match(r3.text, /startTime must be before endTime/);
});
