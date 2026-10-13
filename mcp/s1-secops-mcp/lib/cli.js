/**
 * Credential CLI: setup, status, forget, exec.
 *
 *   s1-secops-mcp setup  [--profile P] [--name NAME] [--import-json FILE]
 *   s1-secops-mcp status [--profile P]
 *   s1-secops-mcp forget [--profile P] [--name NAME]
 *   s1-secops-mcp exec   [--profile P] -- <command> [args...]
 *
 * Secrets are never accepted as command-line arguments. Interactive setup
 * prompts without echo (TTY raw mode). Non-interactive setup reads NAME=value
 * lines from stdin, which keeps values out of argv and shell history.
 */

import { readFileSync } from 'fs';
import { spawn } from 'child_process';
import { constants as osConstants } from 'os';
import {
  KEY_NAMES, SECRET_NAMES, detectBackend, readSecret, writeSecret, deleteSecret, currentProfile,
} from './keystore.js';
import { loadCredentials, ENV_ALIASES } from './credentials.js';

// Alternate names accepted by `setup --import-json` and stdin setup. Built from
// the server's ENV_ALIASES so setup and runtime accept the same names, plus the
// purple-mcp names a migrated config file may carry.
export const ALIASES = {
  ...Object.fromEntries(
    Object.entries(ENV_ALIASES).flatMap(([canonical, names]) =>
      names.filter(n => n !== canonical).map(n => [n, canonical]))),
  PURPLEMCP_CONSOLE_TOKEN: 'S1_CONSOLE_API_TOKEN',
  PURPLEMCP_CONSOLE_BASE_URL: 'S1_CONSOLE_URL',
};

function err(msg) { process.stderr.write(msg + '\n'); }

function parseFlags(argv) {
  const out = { profile: null, name: null, importJson: null, rest: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--') { out.rest = argv.slice(i + 1); break; }
    if (a === '--profile') out.profile = argv[++i];
    else if (a === '--name') out.name = argv[++i];
    else if (a === '--import-json') out.importJson = argv[++i];
    else throw new Error(`Unknown option: ${a}`);
  }
  if (out.profile) process.env.S1_PROFILE = out.profile;
  if (out.name && !KEY_NAMES.includes(out.name)) throw new Error(`--name must be one of ${KEY_NAMES.join(', ')}`);
  return out;
}

/** Validate a value before it is stored. Returns an error string or null. */
export function validateValue(name, value) {
  if (!value) return 'empty';
  if (/[\r\n]/.test(value)) return 'contains a newline';
  if (/^(S1_CONSOLE_URL|S1_HEC_INGEST_URL)$/.test(name)) {
    if (!/^https:\/\/[A-Za-z0-9.-]+(:\d+)?\/?$/.test(value)) return 'must be an https:// origin, e.g. https://usea1-acme.sentinelone.net';
  }
  // Same shape lib/sdl.js resolveScope accepts; a group part would break every SDL call.
  if (name === 'S1_SCOPE' && !/^\d+(:\d+)?$/.test(value)) return 'must be <accountId> or <accountId>:<siteId>';
  if (SECRET_NAMES.has(name) && /\s/.test(value)) return 'contains whitespace';
  if (SECRET_NAMES.has(name) && value.length < 16) return 'is too short to be a real token';
  return null;
}

function normaliseValue(name, v) {
  v = String(v).trim();
  if (/URL$/.test(name)) v = v.replace(/\/+$/, '');
  return v;
}

/** Prompt on the TTY. hidden=true echoes nothing. Resolves to the typed string. */
function prompt(question, { hidden }) {
  return new Promise((resolve, reject) => {
    const stdin = process.stdin;
    process.stderr.write(question);
    stdin.setRawMode(true);
    stdin.resume();
    stdin.setEncoding('utf8');
    let buf = '';
    const cleanup = () => { stdin.removeListener('data', onData); stdin.setRawMode(false); stdin.pause(); };
    function onData(chunk) {
      for (const c of chunk) {
        if (c === '\r' || c === '\n') { cleanup(); process.stderr.write('\n'); resolve(buf); return; }
        if (c === '\u0003' || c === '\u0004') { cleanup(); process.stderr.write('\n'); reject(new Error('cancelled')); return; }
        if (c === '\u007f' || c === '\b') { if (buf) { buf = buf.slice(0, -1); if (!hidden) process.stderr.write('\b \b'); } continue; }
        if (c === '\u0015') { buf = ''; continue; }
        if (c < ' ') continue;
        buf += c;
        if (!hidden) process.stderr.write(c);
      }
    }
    stdin.on('data', onData);
  });
}

function readStdin() {
  try { return readFileSync(0, 'utf-8'); } catch { return ''; }
}

function parsePairs(text) {
  const out = {};
  for (const line of text.split(/\r?\n/)) {
    const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/);
    if (!m) continue;
    const name = ALIASES[m[1]] || m[1];
    if (KEY_NAMES.includes(name) && m[2]) out[name] = m[2];
  }
  return out;
}

function storeAll(pairs, profile) {
  let stored = 0;
  let failed = 0;
  for (const [name, raw] of Object.entries(pairs)) {
    const value = normaliseValue(name, raw);
    const problem = validateValue(name, value);
    if (problem) { err(`  skip ${name}: ${problem}`); failed++; continue; }
    try {
      writeSecret(name, value, profile);
      err(`  stored ${name}${SECRET_NAMES.has(name) ? ` (${value.length} chars)` : ` = ${value}`}`);
      stored++;
    } catch (e) { err(`  FAILED ${name}: ${e.message}`); failed++; }
  }
  return { stored, failed };
}

async function cmdSetup(flags) {
  const b = detectBackend();
  if (!b.available) { err(`OS keychain unavailable: ${b.reason}`); return 2; }
  const profile = currentProfile();
  // Preflight: a backend can be installed but unusable (no D-Bus session, locked
  // keyring). Fail once with the reason instead of once per value.
  try { readSecret('S1_CONSOLE_URL', profile); }
  catch (e) { err(`OS keychain unavailable: ${e.message}`); return 2; }
  err(`Keychain backend: ${b.name}. Profile: ${profile}. Service: sentinelone-mcp.`);

  if (flags.importJson) {
    let data;
    try { data = JSON.parse(readFileSync(flags.importJson, 'utf-8')); }
    catch (e) { err(`Cannot read ${flags.importJson}: ${e.message}`); return 2; }
    const pairs = {};
    for (const [k, v] of Object.entries(data || {})) {
      const name = ALIASES[k] || k;
      if (KEY_NAMES.includes(name) && typeof v === 'string' && v) pairs[name] = v;
    }
    if (flags.name) for (const k of Object.keys(pairs)) if (k !== flags.name) delete pairs[k];
    err(`Importing ${Object.keys(pairs).length} value(s) from ${flags.importJson}:`);
    const r = storeAll(pairs, profile);
    err(`Done: ${r.stored} stored, ${r.failed} skipped or failed. Check with \`s1-secops-mcp status\`, then delete ${flags.importJson}.`);
    return r.failed && !r.stored ? 1 : 0;
  }

  if (!process.stdin.isTTY) {
    const pairs = parsePairs(readStdin());
    if (flags.name) for (const k of Object.keys(pairs)) if (k !== flags.name) delete pairs[k];
    if (!Object.keys(pairs).length) { err('No NAME=value lines on stdin. Run setup in a terminal to be prompted.'); return 2; }
    const r = storeAll(pairs, profile);
    return r.failed ? 1 : 0;
  }

  const names = flags.name ? [flags.name] : KEY_NAMES;
  err('Press Enter to keep the current value. Secret values are not echoed.');
  const pairs = {};
  for (const name of names) {
    let current = null;
    try { current = readSecret(name, profile); } catch { /* shown as unset */ }
    const label = current ? (SECRET_NAMES.has(name) ? `set, ${current.length} chars` : current) : 'not set';
    const optional = !['S1_CONSOLE_URL', 'S1_CONSOLE_API_TOKEN'].includes(name) ? ', optional' : '';
    let v;
    try { v = await prompt(`${name} [${label}${optional}]: `, { hidden: SECRET_NAMES.has(name) }); }
    catch { err('Cancelled. Nothing further stored.'); return 130; }
    if (v.trim()) pairs[name] = v;
  }
  const r = storeAll(pairs, profile);
  err(`Done: ${r.stored} stored, ${r.failed} skipped or failed.`);
  return r.failed ? 1 : 0;
}

function cmdStatus() {
  const { values, sources, keychain } = loadCredentials({ refresh: true });
  const profile = currentProfile();
  const lines = [`Profile: ${profile}`, `Keychain backend: ${keychain.backend}${keychain.error ? ` (unavailable: ${keychain.error})` : ''}`, ''];
  for (const name of KEY_NAMES) {
    const v = values[name];
    const shown = !v ? '-' : SECRET_NAMES.has(name) ? `set (${v.length} chars)` : v;
    const src = sources[name] || (keychain.error ? 'keychain unavailable' : 'unset');
    lines.push(`${name.padEnd(34)} ${src.padEnd(26)} ${shown}`);
  }
  const ready = values.S1_CONSOLE_URL && values.S1_CONSOLE_API_TOKEN;
  let footer;
  if (ready) footer = 'Ready: console URL and API token are configured.';
  else if (keychain.error && !/S1_KEYCHAIN=off/.test(keychain.error)) footer = `NOT ready: the OS keychain cannot be read (${keychain.error}). Fix that, or pass S1_CONSOLE_URL and S1_CONSOLE_API_TOKEN as environment variables.`;
  else if (keychain.error) footer = 'NOT ready: the keychain is disabled (S1_KEYCHAIN=off), so pass S1_CONSOLE_URL and S1_CONSOLE_API_TOKEN as environment variables.';
  else footer = 'NOT ready: S1_CONSOLE_URL and S1_CONSOLE_API_TOKEN are required. Run `s1-secops-mcp setup`.';
  lines.push('', footer);
  process.stdout.write(lines.join('\n') + '\n');
  return ready ? 0 : (keychain.error && !/S1_KEYCHAIN=off/.test(keychain.error)) ? 2 : 1;
}

function cmdForget(flags) {
  const b = detectBackend();
  if (!b.available) { err(`OS keychain unavailable: ${b.reason}`); return 2; }
  const profile = currentProfile();
  try { readSecret('S1_CONSOLE_URL', profile); }
  catch (e) { err(`OS keychain unavailable, nothing removed: ${e.message}`); return 2; }
  let removed = 0;
  for (const name of flags.name ? [flags.name] : KEY_NAMES) {
    try { if (deleteSecret(name, profile)) { removed++; err(`  removed ${name}`); } }
    catch (e) { err(`  FAILED ${name}: ${e.message}`); return 1; }
  }
  err(`Removed ${removed} item(s) from profile ${profile}.`);
  return 0;
}

/**
 * Run another MCP server (purple-mcp, the VirusTotal MCP, anything) with the
 * keychain values in its environment, mapped to the names those servers read.
 * The values are visible in that child's environment to the same OS user
 * (ps eww, /proc/<pid>/environ); they are never on the command line.
 */
async function cmdExec(flags) {
  if (!flags.rest.length) { err('Usage: s1-secops-mcp exec [--profile P] -- <command> [args...]'); return 2; }
  const { values } = loadCredentials({ refresh: true });
  const env = { ...process.env };
  for (const [k, v] of Object.entries(values)) if (!env[k]) env[k] = v;
  if (values.S1_CONSOLE_URL && !env.PURPLEMCP_CONSOLE_BASE_URL) env.PURPLEMCP_CONSOLE_BASE_URL = values.S1_CONSOLE_URL.replace(/\/+$/, '');
  if (values.S1_CONSOLE_API_TOKEN && !env.PURPLEMCP_CONSOLE_TOKEN) env.PURPLEMCP_CONSOLE_TOKEN = values.S1_CONSOLE_API_TOKEN;
  if (values.VIRUSTOTAL_API_KEY && !env.VT_API_KEY) env.VT_API_KEY = values.VIRUSTOTAL_API_KEY;
  if (values.VIRUSTOTAL_API_KEY && !env.PURPLEMCP_VT_API_KEY) env.PURPLEMCP_VT_API_KEY = values.VIRUSTOTAL_API_KEY;
  const child = spawn(flags.rest[0], flags.rest.slice(1), { stdio: 'inherit', env });
  for (const sig of ['SIGINT', 'SIGTERM', 'SIGHUP']) process.on(sig, () => child.kill(sig));
  return await new Promise((resolve) => {
    child.on('error', (e) => { err(`exec failed: ${e.message}`); resolve(127); });
    child.on('exit', (code, signal) => resolve(code ?? (signal ? 128 + (osConstants.signals[signal] || 0) : 1)));
  });
}

export const SUBCOMMANDS = new Set(['setup', 'status', 'forget', 'exec']);

export async function runCli(cmd, argv) {
  let flags;
  try { flags = parseFlags(argv); currentProfile(); }
  catch (e) { err(e.message); return 2; }
  if (cmd === 'setup') return cmdSetup(flags);
  if (cmd === 'status') return cmdStatus(flags);
  if (cmd === 'forget') return cmdForget(flags);
  if (cmd === 'exec') return cmdExec(flags);
  err(`Unknown command ${cmd}`);
  return 2;
}
