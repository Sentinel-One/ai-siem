#!/usr/bin/env node
/**
 * Regenerate the "What this exposes" tools table in s1-secops-mcp/README.md
 * directly from the live ALL_TOOLS array in server-core.js.
 *
 * This is the guard against the drift that produced the original
 * 19-vs-21-vs-26 confusion: if the table doesn't match the registered
 * tools, the build fails (when run via `npm run regen:readme -- --check`).
 *
 * Usage:
 *   node scripts/regen-readme-tools-table.mjs           Rewrite README in place.
 *   node scripts/regen-readme-tools-table.mjs --check   Exit 1 if table is stale.
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ALL_TOOLS } from '../lib/server-core.js';

const __dir = dirname(fileURLToPath(import.meta.url));
const README = resolve(__dir, '..', 'README.md');

// Map each tool to its origin module + originating skill name(s).
// This is the only hand-maintained mapping; updating it is part of adding a
// new tool's row to the README.
const TOOL_SKILL = {
  // PowerQuery
  powerquery_enumerate_sources:  'sentinelone-powerquery',
  powerquery_run:                'sentinelone-powerquery',
  powerquery_schema_discover:    'sentinelone-powerquery',
  // Mgmt Console
  s1_api_get:                    'sentinelone-mgmt-console-api',
  s1_api_post:                   'sentinelone-mgmt-console-api',
  s1_api_put:                    'sentinelone-mgmt-console-api',
  s1_api_delete:                 'sentinelone-mgmt-console-api',
  s1_api_patch:                  'sentinelone-mgmt-console-api',
  purple_ai_alert_summary:       'sentinelone-mgmt-console-api',
  uam_list_alerts:               'sentinelone-mgmt-console-api',
  uam_get_alert:                 'sentinelone-mgmt-console-api',
  uam_add_note:                  'sentinelone-mgmt-console-api',
  uam_set_status:                'sentinelone-mgmt-console-api',
  // SDL API
  sdl_list_files:                'sentinelone-sdl-api / sdl-dashboard / sdl-log-parser',
  sdl_get_file:                  'sentinelone-sdl-api / sdl-dashboard / sdl-log-parser',
  sdl_put_file:                  'sentinelone-sdl-api / sdl-dashboard / sdl-log-parser',
  sdl_delete_file:               'sentinelone-sdl-api',
  hec_ingest:                    'sentinelone-sdl-api / sdl-log-parser',
  // Hyperautomation
  ha_list_workflows:             'sentinelone-hyperautomation',
  ha_get_workflow:               'sentinelone-hyperautomation',
  ha_delete_workflow:           'sentinelone-hyperautomation',
  ha_import_workflow:            'sentinelone-hyperautomation',
  ha_export_workflow:            'sentinelone-hyperautomation',
  // UAM Ingest
  uam_ingest_alert:              'sentinelone-mgmt-console-api (UAM Alert Interface)',
  uam_post_indicators:           'sentinelone-mgmt-console-api (UAM Alert Interface)',
  uam_post_alert:                'sentinelone-mgmt-console-api (UAM Alert Interface)',
};

const GROUPS = [
  { label: 'PowerQuery',       prefix: 'powerquery_' },
  { label: 'Mgmt Console',     test: n => /^(s1_api_|purple_ai_|uam_(list|get|add|set))/.test(n) },
  { label: 'SDL API',          prefix: 'sdl_' },
  { label: 'Hyperautomation',  prefix: 'ha_' },
  { label: 'UAM Ingest',       test: n => /^(uam_ingest_|uam_post_)/.test(n) },
];

function groupOf(name) {
  for (const g of GROUPS) {
    if (g.prefix && name.startsWith(g.prefix)) return g.label;
    if (g.test && g.test(name)) return g.label;
  }
  return '???';
}

// Build the new table block. The leading "**N tools**" header is regenerated
// too so the count and the table can't drift apart.
function buildTable() {
  const sorted = [...ALL_TOOLS]
    .map(t => t.name)
    .sort((a, b) => {
      const ga = GROUPS.findIndex(g => groupOf(a) === g.label);
      const gb = GROUPS.findIndex(g => groupOf(b) === g.label);
      if (ga !== gb) return ga - gb;
      return a.localeCompare(b);
    });

  const lines = [];
  lines.push(`**${ALL_TOOLS.length} tools** across PowerQuery, Mgmt Console, SDL API, Hyperautomation, and UAM Ingest:`);
  lines.push('');
  lines.push('| Group | Tool | Skill |');
  lines.push('|-------|------|-------|');
  for (const name of sorted) {
    const group = groupOf(name);
    const skill = TOOL_SKILL[name] || '';
    if (!skill) {
      throw new Error(`Missing TOOL_SKILL mapping for "${name}". Update scripts/regen-readme-tools-table.mjs.`);
    }
    lines.push(`| ${group} | \`${name}\` | ${skill} |`);
  }
  return lines.join('\n');
}

const START = '<!-- BEGIN AUTO-GENERATED TOOLS TABLE -->';
const END   = '<!-- END AUTO-GENERATED TOOLS TABLE -->';

function spliceTable(readme, table) {
  const start = readme.indexOf(START);
  const end   = readme.indexOf(END);
  if (start < 0 || end < 0 || end < start) {
    throw new Error(
      `README is missing the BEGIN/END auto-generated markers:\n  ${START}\n  ${END}\n` +
      `Add both to README.md around the tools table block before running this script.`
    );
  }
  const head = readme.slice(0, start + START.length);
  const tail = readme.slice(end);
  return head + '\n' + table + '\n' + tail;
}

const args = process.argv.slice(2);
const checkOnly = args.includes('--check');

const before = readFileSync(README, 'utf-8');
const table = buildTable();
const after = spliceTable(before, table);

if (checkOnly) {
  if (before !== after) {
    process.stderr.write('README tools table is out of sync with ALL_TOOLS.\n');
    process.stderr.write('Run `npm run regen:readme` to fix.\n');
    process.exit(1);
  }
  process.stdout.write('README tools table is in sync.\n');
} else {
  if (before === after) {
    process.stdout.write('No changes; README tools table already in sync.\n');
  } else {
    writeFileSync(README, after);
    process.stdout.write(`Updated README tools table (${ALL_TOOLS.length} tools).\n`);
  }
}
