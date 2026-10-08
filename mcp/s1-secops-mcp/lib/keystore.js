/**
 * OS keychain access for SentinelOne credentials. Zero required dependencies.
 *
 * Backends (picked per platform, overridable with S1_KEYCHAIN_BACKEND):
 *   macos   /usr/bin/security (login keychain). Reads with find-generic-password -w,
 *           writes through `security -i` on stdin so the secret is never in argv.
 *   linux   secret-tool (libsecret / Secret Service over D-Bus). Writes on stdin.
 *           Needs a D-Bus session and an unlocked collection; headless hosts
 *           without one get a clear "keychain unavailable" error, never a file.
 *   native  @napi-rs/keyring (optional dependency). The default on Windows
 *           (Credential Manager); also usable on macOS/Linux when forced.
 *
 * Item naming (identical across backends so the Docker launcher, the MCP and
 * the Python clients all find the same entries):
 *   service  = "sentinelone-mcp"
 *   account  = "<profile>:<NAME>"   (Linux attribute name: "username", which is
 *              what secret-tool, Python keyring and keyring-rs all use; an
 *              "account" attribute is invisible to the libraries)
 *
 * Disable entirely with S1_KEYCHAIN=off (CI, containers, tests).
 *
 * Security note: the keychain protects secrets at rest (encrypted, locked with
 * the user session, absent from backups of plaintext config). It does NOT
 * isolate them from other processes running as the same user: an item created
 * by /usr/bin/security can be read by anything that can run /usr/bin/security.
 */

import { execFileSync, spawnSync } from 'child_process';
import { existsSync } from 'fs';
import { createRequire } from 'module';
import { delimiter, join } from 'path';

export const SERVICE = 'sentinelone-mcp';

/** Every name the keychain may hold, in setup order. */
export const KEY_NAMES = [
  'S1_CONSOLE_URL',
  'S1_CONSOLE_API_TOKEN',
  'S1_HEC_INGEST_URL',
  'S1_HEC_TOKEN',
  'S1_SCOPE',
  'VIRUSTOTAL_API_KEY',
];

/** Names whose values are secrets (masked in status, prompted without echo). */
export const SECRET_NAMES = new Set([
  'S1_CONSOLE_API_TOKEN',
  'S1_HEC_TOKEN',
  'VIRUSTOTAL_API_KEY',
]);

export class KeychainUnavailableError extends Error {
  constructor(message) { super(message); this.name = 'KeychainUnavailableError'; }
}

export function currentProfile() {
  const p = (process.env.S1_PROFILE || 'default').trim();
  if (!/^[A-Za-z0-9_.-]{1,64}$/.test(p)) {
    throw new Error(`Invalid S1_PROFILE "${p}": use letters, digits, dot, dash or underscore.`);
  }
  return p;
}

export function accountFor(name, profile = currentProfile()) {
  return `${profile}:${name}`;
}

function onPath(bin) {
  for (const dir of (process.env.PATH || '').split(delimiter)) {
    if (dir && existsSync(join(dir, bin))) return true;
  }
  return false;
}

let _native; // undefined = not tried, null = unavailable
function loadNative() {
  if (_native !== undefined) return _native;
  try {
    const require = createRequire(import.meta.url);
    _native = require('@napi-rs/keyring');
  } catch {
    _native = null;
  }
  return _native;
}

/**
 * Returns { name, available, reason }. Never throws.
 */
export function detectBackend() {
  if ((process.env.S1_KEYCHAIN || '').toLowerCase() === 'off') {
    return { name: 'none', available: false, reason: 'disabled by S1_KEYCHAIN=off' };
  }
  const forced = (process.env.S1_KEYCHAIN_BACKEND || '').toLowerCase();
  const plat = process.platform;
  const want = forced || (plat === 'darwin' ? 'macos' : plat === 'linux' ? 'linux' : plat === 'win32' ? 'native' : 'none');

  if (want === 'macos') {
    if (plat === 'darwin' && existsSync('/usr/bin/security')) return { name: 'macos', available: true };
    return { name: 'macos', available: false, reason: '/usr/bin/security not found (macOS only)' };
  }
  if (want === 'linux') {
    if (onPath('secret-tool')) return { name: 'linux', available: true };
    return {
      name: 'linux', available: false,
      reason: 'secret-tool not found. Install libsecret-tools (Debian/Ubuntu) or libsecret (Fedora/Arch), ' +
              'or pass credentials as environment variables.',
    };
  }
  if (want === 'native') {
    if (loadNative()) return { name: 'native', available: true };
    return {
      name: 'native', available: false,
      reason: 'optional dependency @napi-rs/keyring is not installed (npm install @napi-rs/keyring), ' +
              'or pass credentials as environment variables.',
    };
  }
  return { name: 'none', available: false, reason: `no keychain backend for platform ${plat}` };
}

function requireBackend() {
  const b = detectBackend();
  if (!b.available) throw new KeychainUnavailableError(`OS keychain unavailable: ${b.reason}`);
  return b.name;
}

// ─── macOS ────────────────────────────────────────────────────────────────────

const MAC_NOT_FOUND = 44; // errSecItemNotFound exit status from `security`

function macRead(account) {
  try {
    const out = execFileSync('/usr/bin/security',
      ['find-generic-password', '-s', SERVICE, '-a', account, '-w'],
      { stdio: ['ignore', 'pipe', 'pipe'], timeout: 15000, encoding: 'utf-8' });
    return out.replace(/\r?\n$/, '');
  } catch (e) {
    if (e.status === MAC_NOT_FOUND) return null;
    if (e.code === 'ETIMEDOUT' || (e.signal && e.status === null)) {
      throw new KeychainUnavailableError('macOS keychain read timed out after 15 s (keychain locked, or waiting on an access prompt?). Unlock it, or pass credentials as environment variables.');
    }
    const msg = String(e.stderr || e.message || '').trim();
    throw new KeychainUnavailableError(`macOS keychain read failed: ${msg || 'exit ' + e.status}`);
  }
}

/** `security -i` tokenises like a shell; reject characters we cannot quote safely. */
function macQuote(v, what) {
  if (/["\\\r\n]/.test(v)) {
    throw new Error(`${what} contains a quote, backslash or newline, which the macOS keychain CLI cannot take safely.`);
  }
  return `"${v}"`;
}

function macWrite(account, value, label) {
  const cmd = `add-generic-password -U -s ${macQuote(SERVICE, 'service')} -a ${macQuote(account, 'account')} ` +
              `-l ${macQuote(label, 'label')} -w ${macQuote(value, 'value')}\n`;
  const r = spawnSync('/usr/bin/security', ['-i'], { input: cmd, encoding: 'utf-8', timeout: 15000 });
  const f = spawnFailure(r, '/usr/bin/security', 'write');
  if (f) throw f;
  if (r.status !== 0 || /error|could not/i.test(r.stderr || '')) {
    throw new KeychainUnavailableError(`macOS keychain write failed: ${(r.stderr || '').trim() || 'exit ' + r.status}`);
  }
}

function macDelete(account) {
  const r = spawnSync('/usr/bin/security', ['delete-generic-password', '-s', SERVICE, '-a', account],
    { encoding: 'utf-8', timeout: 15000 });
  const f = spawnFailure(r, '/usr/bin/security', 'delete');
  if (f) throw f;
  if (r.status === 0) return true;
  if (r.status === MAC_NOT_FOUND) return false;
  throw new KeychainUnavailableError(`macOS keychain delete failed: ${(r.stderr || '').trim()}`);
}

// ─── Linux (libsecret) ────────────────────────────────────────────────────────

function linuxError(stderr, status, op) {
  const s = String(stderr || '').trim();
  if (/D-Bus|DBUS|autolaunch|org\.freedesktop\.secrets|locked collection|No such secret collection|ServiceUnknown/i.test(s)) {
    return new KeychainUnavailableError(
      `Linux keyring unavailable (${op}): ${s}. secret-tool needs a D-Bus session with an unlocked ` +
      'Secret Service (gnome-keyring or KeePassXC). On a headless host pass credentials as environment variables instead.');
  }
  return new KeychainUnavailableError(`Linux keyring ${op} failed: ${s || 'exit ' + status}`);
}

const SPAWN_TIMEOUT_MS = Math.max(1000, Number(process.env.S1_KEYCHAIN_TIMEOUT_MS) || 15000);

/** Map a spawnSync failure that never produced an exit status (timeout, missing binary). */
function spawnFailure(r, tool, op) {
  if (!r.error) return null;
  if (r.error.code === 'ETIMEDOUT') {
    return new KeychainUnavailableError(`${tool} ${op} timed out after ${SPAWN_TIMEOUT_MS / 1000} s (keyring locked, or waiting on an unlock prompt?). Unlock the keyring, or pass credentials as environment variables.`);
  }
  if (r.error.code === 'ENOENT') return new KeychainUnavailableError(`${tool} not found`);
  return new KeychainUnavailableError(`${tool} ${op} failed: ${r.error.message}`);
}

function secretTool(args, op, input) {
  const r = spawnSync('secret-tool', args, { encoding: 'utf-8', timeout: SPAWN_TIMEOUT_MS, ...(input !== undefined ? { input } : {}) });
  const f = spawnFailure(r, 'secret-tool', op);
  if (f) throw f;
  return r;
}

// `secret-tool lookup` on a LOCKED collection exits 1 with empty stderr, exactly
// like "not found", so a locked keyring would read as "not configured" and send
// the user to `setup`. `search` does say so ("Cannot get secret of a locked
// object"). Probed once per process, only when a lookup came back empty.
let _linuxLocked;
function linuxLocked() {
  if (_linuxLocked !== undefined) return _linuxLocked;
  const r = secretTool(['search', '--all', 'service', SERVICE], 'probe');
  _linuxLocked = /locked/i.test(String(r.stderr || ''));
  return _linuxLocked;
}
const LOCKED_MSG = 'Linux keyring is locked. Unlock it (log in to the desktop session, or `gnome-keyring-daemon --unlock`), or pass credentials as environment variables.';

function linuxRead(account) {
  const r = secretTool(['lookup', 'service', SERVICE, 'username', account], 'read');
  if (r.status === 0) return r.stdout.replace(/\r?\n$/, '');
  if (r.status === 1 && !String(r.stderr || '').trim()) {
    if (linuxLocked()) throw new KeychainUnavailableError(LOCKED_MSG);
    return null; // not found
  }
  throw linuxError(r.stderr, r.status, 'read');
}

function linuxWrite(account, value, label) {
  const r = secretTool(['store', '--label', label, 'service', SERVICE, 'username', account], 'write', value);
  if (r.status !== 0) throw linuxError(r.stderr, r.status, 'write');
}

function linuxDelete(account) {
  // linuxRead throws on a locked keyring, so forget can never report "removed 0"
  // while the items are still there.
  const existed = linuxRead(account) !== null;
  const r = secretTool(['clear', 'service', SERVICE, 'username', account], 'delete');
  if (r.status !== 0 && String(r.stderr || '').trim()) throw linuxError(r.stderr, r.status, 'delete');
  if (existed && linuxRead(account) !== null) throw new KeychainUnavailableError(`Linux keyring delete did not remove ${account}`);
  return existed;
}

// ─── native (@napi-rs/keyring) ────────────────────────────────────────────────

function nativeErr(e, op) {
  return new KeychainUnavailableError(`OS keychain ${op} failed (@napi-rs/keyring): ${e && e.message ? e.message : e}`);
}

function nativeRead(account) {
  try { return new (loadNative().Entry)(SERVICE, account).getPassword() ?? null; }
  catch (e) { throw nativeErr(e, 'read'); }
}
function nativeWrite(account, value) {
  try { new (loadNative().Entry)(SERVICE, account).setPassword(value); }
  catch (e) { throw nativeErr(e, 'write'); }
}
function nativeDelete(account) {
  try { return !!new (loadNative().Entry)(SERVICE, account).deletePassword(); }
  catch (e) { throw nativeErr(e, 'delete'); }
}

// ─── public API ───────────────────────────────────────────────────────────────

function checkName(name) {
  if (!KEY_NAMES.includes(name)) throw new Error(`Unknown credential name "${name}". Valid: ${KEY_NAMES.join(', ')}`);
}

/** Read one value. Returns string or null when absent. Throws KeychainUnavailableError. */
export function readSecret(name, profile = currentProfile()) {
  checkName(name);
  const backend = requireBackend();
  const acct = accountFor(name, profile);
  if (backend === 'macos') return macRead(acct);
  if (backend === 'linux') return linuxRead(acct);
  return nativeRead(acct);
}

/** Store one value, then read it back to prove the write landed. */
export function writeSecret(name, value, profile = currentProfile()) {
  checkName(name);
  if (typeof value !== 'string' || !value.length) throw new Error(`Empty value for ${name}`);
  const backend = requireBackend();
  const acct = accountFor(name, profile);
  const label = `SentinelOne MCP ${profile} ${name}`;
  if (backend === 'macos') macWrite(acct, value, label);
  else if (backend === 'linux') linuxWrite(acct, value, label);
  else nativeWrite(acct, value);
  const back = readSecret(name, profile);
  if (back !== value) throw new KeychainUnavailableError(`Keychain write for ${name} did not read back correctly.`);
  return true;
}

/** Delete one value. Returns true if something was removed. */
export function deleteSecret(name, profile = currentProfile()) {
  checkName(name);
  const backend = requireBackend();
  const acct = accountFor(name, profile);
  if (backend === 'macos') return macDelete(acct);
  if (backend === 'linux') return linuxDelete(acct);
  return nativeDelete(acct);
}

/**
 * Read every name that is not already supplied by `skip` (e.g. env).
 * Never throws: returns { values, backend, error }.
 */
export function readAll(skip = new Set(), profile) {
  const b = detectBackend();
  const values = {};
  if (!b.available) return { values, backend: b.name, error: b.reason };
  let prof;
  try { prof = profile || currentProfile(); } catch (e) { return { values, backend: b.name, error: e.message }; }
  for (const name of KEY_NAMES) {
    if (skip.has(name)) continue;
    try {
      const v = readSecret(name, prof);
      if (v) values[name] = v;
    } catch (e) {
      return { values, backend: b.name, error: e.message };
    }
  }
  return { values, backend: b.name, error: null };
}
