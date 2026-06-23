/**
 * Smoke test: introspect ALL_TOOLS without spawning the server.
 *
 * This is the canonical source-of-truth check for the tool count.
 * If the README, header comment, or any doc says a different number,
 * one of them is wrong, not this test.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ALL_TOOLS, TOOL_DEFS, SERVER_INFO } from '../lib/server-core.js';

const EXPECTED_TOOLS = [
  // PowerQuery (3)
  'powerquery_enumerate_sources',
  'powerquery_run',
  'powerquery_schema_discover',
  // Mgmt Console (10)
  's1_api_get',
  's1_api_post',
  's1_api_put',
  's1_api_delete',
  's1_api_patch',
  'purple_ai_alert_summary',
  'uam_list_alerts',
  'uam_get_alert',
  'uam_add_note',
  'uam_set_status',
  // SDL API (5)
  'sdl_list_files',
  'sdl_get_file',
  'sdl_put_file',
  'sdl_delete_file',
  'hec_ingest',
  // Hyperautomation (5)
  'ha_list_workflows',
  'ha_get_workflow',
  'ha_delete_workflow',
  'ha_import_workflow',
  'ha_export_workflow',
  // UAM Ingest (3)
  'uam_ingest_alert',
  'uam_post_indicators',
  'uam_post_alert',
];

test('server version is current', () => {
  assert.equal(SERVER_INFO.version, '1.2.2');
});

test('ALL_TOOLS exposes exactly 26 tools', () => {
  assert.equal(ALL_TOOLS.length, 26, `expected 26, got ${ALL_TOOLS.length}`);
});

test('every expected tool is registered, no extras', () => {
  const actualNames = ALL_TOOLS.map(t => t.name).sort();
  const expectedNames = [...EXPECTED_TOOLS].sort();
  assert.deepEqual(actualNames, expectedNames);
});

test('every tool has name, description, inputSchema, handler', () => {
  for (const t of ALL_TOOLS) {
    assert.ok(typeof t.name === 'string' && t.name.length > 0, `tool missing name: ${JSON.stringify(t)}`);
    assert.ok(typeof t.description === 'string' && t.description.length > 0, `tool ${t.name} missing description`);
    assert.ok(t.inputSchema && typeof t.inputSchema === 'object', `tool ${t.name} missing inputSchema`);
    assert.equal(t.inputSchema.type, 'object', `tool ${t.name} inputSchema.type must be 'object'`);
    assert.ok(typeof t.handler === 'function', `tool ${t.name} missing handler`);
  }
});

test('TOOL_DEFS matches ALL_TOOLS shape and excludes handlers', () => {
  assert.equal(TOOL_DEFS.length, ALL_TOOLS.length);
  for (const def of TOOL_DEFS) {
    assert.ok(def.name);
    assert.ok(def.description);
    assert.ok(def.inputSchema);
    assert.equal(def.handler, undefined, `TOOL_DEFS leaked handler for ${def.name}`);
  }
});

test('no removed tools sneak back in', () => {
  // These were removed 2026-05-03 because the underlying API requires a
  // browser-session teamToken that service-account API tokens never obtain.
  const removed = ['purple_ai_query', 'purple_ai_investigate'];
  const names = new Set(ALL_TOOLS.map(t => t.name));
  for (const r of removed) {
    assert.ok(!names.has(r), `removed tool reintroduced: ${r}`);
  }
});

test('s1_api_get description warns about isLegacy=false on /cloud-detection/rules', () => {
  const tool = ALL_TOOLS.find(t => t.name === 's1_api_get');
  assert.ok(tool, 's1_api_get tool missing');
  // The tool description that models see in the JSON schema must loudly
  // flag the requirement, so even if the handler guard is bypassed Claude
  // sees it in the tool list.
  assert.match(tool.description, /isLegacy=false/i, 's1_api_get description must mention isLegacy=false');
  assert.match(tool.description, /cloud-detection\/rules/i, 's1_api_get description must mention /cloud-detection/rules');
});

test('normalizeS1ApiGetParams auto-injects isLegacy=false on /cloud-detection/rules', async () => {
  // Regression guard: without isLegacy=false the S1 API silently omits
  // queryType="scheduled" PowerQuery rules and the caller gets a
  // misleadingly-empty response. This was a repeated production failure
  // before the auto-injection was added — do NOT remove this guard.
  const { normalizeS1ApiGetParams } = await import('../tools/mgmt-console.js');

  // 1. Missing isLegacy → injected as false
  const a = normalizeS1ApiGetParams('/web/api/v2.1/cloud-detection/rules', { limit: 5 });
  assert.equal(a.isLegacy, false, 'missing isLegacy must be injected as false');

  // 2. Explicit isLegacy=true preserved (caller knows what they're doing)
  const b = normalizeS1ApiGetParams('/web/api/v2.1/cloud-detection/rules', { isLegacy: true, limit: 5 });
  assert.equal(b.isLegacy, true, 'explicit isLegacy=true must be preserved');

  // 3. Explicit isLegacy=false preserved
  const c = normalizeS1ApiGetParams('/web/api/v2.1/cloud-detection/rules', { isLegacy: false, limit: 5 });
  assert.equal(c.isLegacy, false, 'explicit isLegacy=false must be preserved');

  // 4. snake_case is_legacy also satisfies the guard
  const d = normalizeS1ApiGetParams('/web/api/v2.1/cloud-detection/rules', { is_legacy: false });
  assert.equal(d.isLegacy, undefined, 'snake_case is_legacy must short-circuit the inject');
  assert.equal(d.is_legacy, false);

  // 5. Sub-paths under cloud-detection/rules (e.g. /enable, /{id}) also get guarded
  const e = normalizeS1ApiGetParams('/web/api/v2.1/cloud-detection/rules/2484136149984408477', {});
  assert.equal(e.isLegacy, false, 'rule-detail path must also be guarded');

  // 6. Unrelated paths must NOT have isLegacy added
  const f = normalizeS1ApiGetParams('/web/api/v2.1/agents', {});
  assert.equal(f.isLegacy, undefined, 'unrelated paths must not have isLegacy injected');
  const g = normalizeS1ApiGetParams('/web/api/v2.1/threats', { limit: 10 });
  assert.equal(g.isLegacy, undefined);

  // 7. Defensive: undefined / null params still produce a valid object
  const h = normalizeS1ApiGetParams('/web/api/v2.1/cloud-detection/rules', undefined);
  assert.equal(h.isLegacy, false);
});
