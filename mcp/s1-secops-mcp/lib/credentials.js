/**
 * Credential loader.
 *
 * Resolution order (highest wins), per value:
 *   1. Environment variables (secret-manager injection, CI, the Docker launcher)
 *   2. OS keychain, profile S1_PROFILE (default "default"); see lib/keystore.js
 *
 * There is deliberately NO file fallback. Plaintext credentials.json discovery
 * (S1_CREDS_FILE, COWORK_WORKSPACE, cwd walk-up, ~/mnt/*, CLAUDE_CONFIG_DIR,
 * ~/.config/sentinelone) was removed in 1.5.0. Store values once with
 * `s1-secops-mcp setup`; migrate an old file with
 * `s1-secops-mcp setup --import-json <path>` and then delete the file.
 */

import { readAll, KEY_NAMES, SECRET_NAMES } from './keystore.js';

// Same alias lists as the Python clients (mgmt-console-api/scripts/s1_keystore.py),
// so one environment works for both. lib/cli.js derives its setup aliases from this.
export const ENV_ALIASES = {
  S1_CONSOLE_URL: ['S1_CONSOLE_URL', 'S1_BASE_URL'],
  S1_CONSOLE_API_TOKEN: ['S1_CONSOLE_API_TOKEN', 'S1_API_TOKEN', 'SDL_CONSOLE_API_TOKEN'],
  S1_HEC_INGEST_URL: ['S1_HEC_INGEST_URL', 'S1_UAM_ALERT_INTERFACE_URL'],
  S1_SCOPE: ['S1_SCOPE', 'SDL_S1_SCOPE'],
  VIRUSTOTAL_API_KEY: ['VIRUSTOTAL_API_KEY', 'VT_API_KEY'],
};

function fromEnv(name) {
  for (const k of ENV_ALIASES[name] || [name]) {
    const v = process.env[k];
    if (v) return { value: v, source: `env:${k}` };
  }
  return null;
}

// Keychain values are read once (lazily) and cached; environment variables are
// read live on every call so they always win and tests can set them at runtime.
let _kc = null;

function keychainValues({ refresh = false } = {}) {
  if (_kc && !refresh) return _kc;
  const inEnv = new Set(KEY_NAMES.filter(n => fromEnv(n)));
  _kc = readAll(inEnv);
  return _kc;
}

/** Merged view with per-value provenance. Exported for the status command. */
export function loadCredentials({ refresh = false } = {}) {
  const kc = keychainValues({ refresh });
  const values = {};
  const sources = {};
  for (const name of KEY_NAMES) {
    const hit = fromEnv(name);
    if (hit) { values[name] = hit.value; sources[name] = hit.source; continue; }
    if (kc.values[name]) { values[name] = kc.values[name]; sources[name] = `keychain:${kc.backend}`; }
  }
  return { values, sources, keychain: { backend: kc.backend, error: kc.error } };
}

/**
 * Returns merged credentials. Shape unchanged from earlier releases so every
 * caller keeps working.
 */
export function getCreds() {
  const { values } = loadCredentials();
  const e = (k) => values[k] || '';
  return {
    S1_CONSOLE_URL:       e('S1_CONSOLE_URL'),
    S1_CONSOLE_API_TOKEN: e('S1_CONSOLE_API_TOKEN'),
    S1_HEC_INGEST_URL:    e('S1_HEC_INGEST_URL'),
    // SDL Log Write Key, used ONLY for log ingest over the event collector.
    // A different credential from the console token: some consoles refuse a
    // console user token at the collector, and the key is minted for one account or site
    // (Console > Singularity Data Lake > API Keys > Log Write Key).
    S1_HEC_TOKEN:         e('S1_HEC_TOKEN'),
    // Default S1-Scope for SDL requests: "<accountId>" or "<accountId>:<siteId>".
    S1_SCOPE:             e('S1_SCOPE'),
  };
}

/** Values that must never appear in output (for lib/redact.js). */
export function secretValues() {
  const { values } = loadCredentials();
  return Object.entries(values)
    .filter(([k, v]) => SECRET_NAMES.has(k) && v && v.length >= 8)
    .map(([, v]) => v);
}

/** One-line hint appended to "not configured" errors. */
export function setupHint() {
  const { keychain } = loadCredentials();
  const kc = keychain.error ? ` (OS keychain: ${keychain.error})` : '';
  return `Store it in the OS keychain with \`s1-secops-mcp setup\`, or pass it as an environment variable${kc}.`;
}

/** True if minimum required credentials for S1 Mgmt API are present. */
export function hasS1Creds() {
  const c = getCreds();
  return !!(c.S1_CONSOLE_URL && c.S1_CONSOLE_API_TOKEN);
}

/** True if minimum required credentials for SDL are present.
 *  SDL lives under <console>/sdl and uses the console API token. */
export function hasSdlCreds() {
  const c = getCreds();
  return !!(c.S1_CONSOLE_URL && c.S1_CONSOLE_API_TOKEN);
}
