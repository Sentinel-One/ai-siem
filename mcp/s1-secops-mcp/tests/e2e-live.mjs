/**
 * Live end-to-end check. NOT part of `npm test`, and never run in CI.
 *
 * Spawns the server over real stdio JSON-RPC, so every assertion exercises
 * protocol -> handler -> live API rather than a mock. Unit and contract tests
 * cannot catch a payload the API rejects, a scope the endpoint ignores, or a
 * response whose size depends on tenant cardinality; this can.
 *
 * Run against a NON-PRODUCTION tenant. Writes are confined to the site given in
 * E2E_SITE_ID and every object created is deleted again before exit.
 *
 *   export S1_CONSOLE_URL=https://<console>.sentinelone.net
 *   export S1_CONSOLE_API_TOKEN=<token>
 *   export E2E_SITE_ID=<scratch site id>        # required, receives the writes
 *   export E2E_ACCOUNT_ID=<account id>          # optional, read-only checks
 *   node tests/e2e-live.mjs
 *
 * Set E2E_SERVER to an installed package's index.js to verify what was actually
 * published rather than the working tree. This is the isolation check in step 5 of
 * docs/release-process.md, and it is the only way to catch a packaging fault such as
 * a file missing from the "files" allowlist, which no working-tree run can see.
 *
 *   npm i --prefix /tmp/verify @pmoses-s1/s1-secops-mcp@<version>
 *   E2E_SERVER=/tmp/verify/node_modules/@pmoses-s1/s1-secops-mcp/index.js \
 *     node tests/e2e-live.mjs
 *
 * Exit code is 0 only when every check passes.
 */
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const SERVER = process.env.E2E_SERVER
  ? resolve(process.env.E2E_SERVER)
  : resolve(dirname(fileURLToPath(import.meta.url)), '..', 'index.js');

// E2E_SERVER_CMD runs an arbitrary command as the server instead of `node <path>`,
// so the container can be tested as shipped rather than the source it was built from.
// The image is what users actually run, and a build can differ from its inputs.
//   E2E_SERVER_CMD='docker run -i --rm -e S1_CONSOLE_URL -e S1_CONSOLE_API_TOKEN \
//     ghcr.io/pmoses-s1/s1-mcps:<tag> s1-secops-mcp'
const SERVER_CMD = process.env.E2E_SERVER_CMD;
const SITE = process.env.E2E_SITE_ID;
const ACCOUNT = process.env.E2E_ACCOUNT_ID;

for (const v of ['S1_CONSOLE_URL', 'S1_CONSOLE_API_TOKEN', 'E2E_SITE_ID']) {
  if (!process.env[v]) {
    console.error(`missing ${v}. See the header of this file.`);
    process.exit(2);
  }
}

const child = SERVER_CMD
  ? spawn('/bin/sh', ['-c', SERVER_CMD], {
      stdio: ['pipe', 'pipe', 'pipe'],
      env: { ...process.env, MCP_TRANSPORT: 'stdio' },
    })
  : spawn(process.execPath, [SERVER], {
      stdio: ['pipe', 'pipe', 'pipe'],
      env: { ...process.env, MCP_TRANSPORT: 'stdio' },
    });
console.log(SERVER_CMD ? `server: ${SERVER_CMD}` : `server: node ${SERVER}`);
let stderr = '';
child.stderr.on('data', c => { stderr += c.toString(); });

const pending = new Map();
let buf = '';
child.stdout.on('data', chunk => {
  buf += chunk.toString();
  let i;
  while ((i = buf.indexOf('\n')) >= 0) {
    const line = buf.slice(0, i).trim();
    buf = buf.slice(i + 1);
    if (!line) continue;
    let msg; try { msg = JSON.parse(line); } catch { continue; }
    const r = pending.get(msg.id);
    if (r) { pending.delete(msg.id); r(msg); }
  }
});

let nextId = 1;
const rpc = (method, params) => new Promise((res, rej) => {
  const id = nextId++;
  pending.set(id, res);
  child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n');
  setTimeout(() => { if (pending.has(id)) { pending.delete(id); rej(new Error(`${method} timed out`)); } }, 120000);
});

const call = async (name, args) => {
  const r = await rpc('tools/call', { name, arguments: args });
  if (r.error) return { error: r.error };
  const text = r.result?.content?.[0]?.text ?? '';
  try { return { parsed: JSON.parse(text), text }; } catch { return { text }; }
};

let pass = 0, fail = 0;
const ok = (cond, label, detail = '') => {
  if (cond) { pass++; console.log(`  PASS  ${label}${detail ? '  ' + detail : ''}`); }
  else { fail++; console.log(`  FAIL  ${label}${detail ? '  ' + detail : ''}`); }
};
const section = s => console.log(`\n${s}`);

/** Smallest workflow the import endpoint accepts: a manual trigger, no inputs. */
const wf = name => ({
  name,
  description: 'e2e live check, deleted at end of run',
  actions: [{
    action: {
      client_data: { collapsed: false, dimensions: { height: 76.0, width: 256.0 }, position: { x: 286.0, y: -29.0 } },
      connection_id: null, connection_name: null,
      data: { action_type: 'manual_trigger', dynamic_properties: {}, name: 'Manual Trigger', static_payload: '{}', trigger_type: 'dynamic' },
      description: null, integration_id: null, tag: 'core_action', type: 'manual_trigger', use_connection_name: false,
    },
    connected_to: [], export_id: 0, parent_action: null,
  }],
});

const created = [];
const PKG = JSON.parse((await import('node:fs')).readFileSync(new URL('../package.json', import.meta.url), 'utf8'));

try {
  section('1. protocol');
  const init = await rpc('initialize', {
    protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'e2e', version: PKG.version },
  });
  ok(init.result?.serverInfo?.version === PKG.version, 'server version matches package.json', init.result?.serverInfo?.version);
  const tools = await rpc('tools/list', {});
  ok(tools.result?.tools?.length > 0, 'tools/list returns tools', String(tools.result?.tools?.length));

  // Control for the client-side defaults defect: over raw JSON-RPC the server
  // applies its own defaults, which is how we know the rejection seen in some
  // hosts happens in the host and not here.
  section('2. omitted default-bearing parameters');
  const pq = await call('powerquery_run', { query: '| group ct=count() by dataSource.name | sort -ct | limit 3' });
  ok(!pq.error, 'powerquery_run succeeds with hours and maxRows omitted',
    pq.error ? JSON.stringify(pq.error).slice(0, 120) : 'server applied its defaults');

  section('3. ha_import_workflow envelope handling');
  const stamp = Date.now();
  const bare = await call('ha_import_workflow', { siteIds: SITE, workflowJson: JSON.stringify(wf(`e2e-bare-${stamp}`)) });
  ok(!!bare.parsed?.id, 'bare workflow imports', bare.parsed?.id || JSON.stringify(bare).slice(0, 160));
  ok(bare.parsed?.importNote === undefined, 'bare payload is not reported as unwrapped');
  if (bare.parsed?.id) created.push(bare.parsed.id);

  // The raw-API body shape. The tool adds the envelope itself, so this arrives
  // double-wrapped and must be unwrapped rather than 422'd.
  const wrapped = await call('ha_import_workflow', { siteIds: SITE, workflowJson: JSON.stringify({ data: wf(`e2e-wrapped-${stamp}`) }) });
  ok(!!wrapped.parsed?.id, 'data-wrapped workflow imports', wrapped.parsed?.id || JSON.stringify(wrapped).slice(0, 160));
  ok(/unwrapped/i.test(wrapped.parsed?.importNote || ''), 'the unwrap is reported, not silent');
  if (wrapped.parsed?.id) created.push(wrapped.parsed.id);

  section('4. ha_export_workflow scope');
  const exp = await call('ha_export_workflow', { siteIds: SITE });
  ok(exp.parsed?.sizeBytes > 0, 'site-scoped export returns a ZIP', `${exp.parsed?.sizeBytes} bytes`);
  if (ACCOUNT) {
    const expAcct = await call('ha_export_workflow', { accountIds: ACCOUNT });
    ok(expAcct.parsed?.sizeBytes > 0, 'account-scoped export returns a ZIP', `${expAcct.parsed?.sizeBytes} bytes`);
  }

  section('5. list-tool pagination');
  const d1 = await call('sdl_list_dashboards', {});
  ok(d1.parsed?.returned <= 100, 'default page is at most 100', `returned=${d1.parsed?.returned} of ${d1.parsed?.totalCount}`);
  ok(d1.text.length < 200000, 'response under the 200k budget', `${d1.text.length} chars`);

  const a = await call('sdl_list_dashboards', { limit: 5, offset: 0 });
  const b = await call('sdl_list_dashboards', { limit: 5, offset: 5 });
  const both = await call('sdl_list_dashboards', { limit: 10, offset: 0 });
  // Page on name: a dashboard created the old, name-addressed way has a null id,
  // so comparing ids would compare null to null and prove nothing.
  const na = (a.parsed?.dashboards || []).map(d => d.name);
  const nb = (b.parsed?.dashboards || []).map(d => d.name);
  ok(na.length && na.every(n => !nb.includes(n)), 'offset advances the window with no overlap');
  ok(JSON.stringify((both.parsed?.dashboards || []).map(d => d.name)) === JSON.stringify([...na, ...nb]),
    'consecutive pages concatenate to one larger page, nothing skipped or duplicated');

  const names = await call('sdl_list_dashboards', { limit: 50, namesOnly: true });
  const full = await call('sdl_list_dashboards', { limit: 50 });
  ok(names.text.length < full.text.length, 'namesOnly is smaller', `${names.text.length} vs ${full.text.length} chars`);

  const f = await call('sdl_list_files', { pathPrefix: '/logParsers/', limit: 10 });
  ok(f.parsed?.returned <= 10, 'sdl_list_files page size honoured', `returned=${f.parsed?.returned} count=${f.parsed?.count}`);
  ok((f.parsed?.files || []).every(x => x.name.startsWith('/logParsers/')), 'pathPrefix applied before paging');
} catch (e) {
  fail++;
  console.log(`\n  FAIL  harness error: ${e.message}`);
} finally {
  section('cleanup');
  if (!created.length) console.log('  nothing to remove');
  for (const id of created) {
    const del = await call('ha_delete_workflow', { workflowIds: [id], siteIds: SITE });
    ok(del.parsed?.deleted?.[0]?.status === 'deleted', `deleted ${id}`);
  }
  console.log(`\n${fail === 0 ? 'ALL PASS' : 'FAILURES'}: ${pass} passed, ${fail} failed`);
  if (fail && stderr.trim()) console.log(`\nserver stderr:\n${stderr.trim().split('\n').slice(0, 15).join('\n')}`);
  child.kill('SIGKILL');
  process.exit(fail === 0 ? 0 : 1);
}
