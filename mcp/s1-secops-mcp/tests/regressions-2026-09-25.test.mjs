/**
 * Regression test for the 2026-09-25 fix.
 *
 * contracts-1.3.9.test.mjs resolves the hyperautomation SKILL.md through a
 * relative URL computed from the test file's own location. That path pointed
 * at mcp/hyperautomation/SKILL.md, a directory that has never existed in this
 * repo; the real file lives at
 * plugins/s1-secops-skills/skills/hyperautomation/SKILL.md. Because no CI
 * workflow runs `npm test` inside mcp/s1-secops-mcp, both contract tests that
 * depend on this path (the doc-example count and the wire-shape check) failed
 * with ENOENT for anyone who ran the suite locally, from the day the tests
 * were added.
 *
 * This test pins the path itself so a future rename or restructure of either
 * the tests directory or the plugins skills tree fails loudly here instead of
 * silently reintroducing the ENOENT.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';

test('the hyperautomation SKILL.md the contract tests read actually exists', () => {
  const skillMd = new URL(
    '../../../plugins/s1-secops-skills/skills/hyperautomation/SKILL.md',
    import.meta.url,
  );
  assert.ok(
    existsSync(skillMd),
    `expected a file at ${skillMd.pathname}, the contract tests read this path relative to ` +
      'their own location and silently ENOENT if it drifts',
  );
});

test('the smoke-test section the contract tests parse is still present', () => {
  const skillMd = new URL(
    '../../../plugins/s1-secops-skills/skills/hyperautomation/SKILL.md',
    import.meta.url,
  );
  const md = readFileSync(skillMd, 'utf8');
  assert.notEqual(
    md.indexOf('## Minimum viable workflow JSON'),
    -1,
    'the smoke-test heading contracts-1.3.9.test.mjs slices on is missing',
  );
});
