/**
 * Live HEC ingest test — posts only, no polling.
 * Outputs the alert titles to poll for via uam_list_alerts.
 *
 * Run from the s1-secops-mcp directory:
 *   node tests/test_uam_ingest.mjs
 */
import { ingestAlert, ingestAlertInline } from '../lib/uam-ingest.js';
import { apiGet } from '../lib/s1.js';

const r = await apiGet('/web/api/v2.1/accounts', { limit: 1 });
const acct = r.data?.[0];
if (!acct) { console.error('No accounts found'); process.exit(1); }
console.log(`Account: ${acct.name} (${acct.id})`);

const scope = acct.id;
const ts = new Date().toISOString().slice(0, 16).replace('T', ' ');

// ── Test 1: two-call mode ────────────────────────────────────────────────────
const titleA = `MCP Test [two-call] ${ts}`;
console.log(`\n[1] Two-call mode — title: "${titleA}"`);
const resA = await ingestAlert({
  scope, title: titleA,
  description: 'Automated live test — two-call mode.',
  hostname: 'mcp-test-two-call', filename: 'test-two-call.exe',
});
console.log('  indicator_uid :', resA.indicator_uid);
console.log('  alert_uid     :', resA.alert_uid);
console.log('  indicator HEC :', resA.indicator_response?.status, JSON.stringify(resA.indicator_response?.body));
console.log('  alert HEC     :', resA.alert_response?.status,     JSON.stringify(resA.alert_response?.body));

// ── Test 2: inline mode ──────────────────────────────────────────────────────
const titleB = `MCP Test [inline] ${ts}`;
console.log(`\n[2] Inline mode — title: "${titleB}"`);
const resB = await ingestAlertInline({
  scope, title: titleB,
  description: 'Automated live test — inline mode.',
  hostname: 'mcp-test-inline', filename: 'test-inline.exe',
});
console.log('  indicator_uid :', resB.indicator_uid);
console.log('  alert_uid     :', resB.alert_uid);
console.log('  alert HEC     :', resB.alert_response?.status, JSON.stringify(resB.alert_response?.body));

console.log('\nDone. Now poll UAM with uam_list_alerts — allow 30-60s for alerts to surface.');
console.log(`POLL_TITLE_A=${titleA}`);
console.log(`POLL_TITLE_B=${titleB}`);
