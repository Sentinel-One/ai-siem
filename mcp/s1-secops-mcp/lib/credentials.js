/**
 * Credential loader — zero dependencies, synchronous.
 *
 * Resolution order (highest wins):
 *   1. Environment variables
 *   2. S1_CREDS_FILE (explicit absolute path; recommended for team / VM deployments)
 *   3. COWORK_WORKSPACE/credentials.json
 *   4. Walk-up from cwd looking for credentials.json
 *   5. ~/mnt/<any-folder>/credentials.json (Cowork workspace mounts)
 *   6. CLAUDE_CONFIG_DIR/sentinelone/credentials.json
 *   7. ~/.config/sentinelone/credentials.json
 */

import { readFileSync, existsSync, readdirSync } from 'fs';
import { join, dirname } from 'path';
import { homedir } from 'os';

const CRED_FILENAMES = [
  'credentials.json',
  '.sentinelone/credentials.json',
  '.claude/sentinelone/credentials.json',
];

const MNT_SKIP = new Set(['.claude', '.auto-memory', '.remote-plugins', 'outputs', 'uploads']);

function tryLoad(dir) {
  for (const rel of CRED_FILENAMES) {
    const p = join(dir, rel);
    if (existsSync(p)) {
      try { return JSON.parse(readFileSync(p, 'utf-8')); } catch { /* bad JSON */ }
    }
  }
  return null;
}

function discoverCredentials() {
  // 1. S1_CREDS_FILE — explicit absolute path. Useful for VM deployments and
  //    secret-store integrations (Vault / Doppler / 1Password / sealed-secrets)
  //    that render a credentials file to a known path at boot.
  const credsFile = process.env.S1_CREDS_FILE;
  if (credsFile && existsSync(credsFile)) {
    try { return JSON.parse(readFileSync(credsFile, 'utf-8')); }
    catch (e) {
      process.stderr.write(`[credentials] S1_CREDS_FILE set but unreadable: ${e.message}\n`);
    }
  }

  // 2. COWORK_WORKSPACE env override
  const ws = process.env.COWORK_WORKSPACE;
  if (ws) {
    const found = tryLoad(ws);
    if (found) return found;
  }

  // 2. Walk up from cwd
  let dir;
  try { dir = process.cwd(); } catch { dir = '/'; }
  for (let i = 0; i < 20; i++) {
    const found = tryLoad(dir);
    if (found) return found;
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }

  // 3. ~/mnt/* scan (Cowork workspace mounts)
  const homeMnt = join(homedir(), 'mnt');
  if (existsSync(homeMnt)) {
    try {
      const entries = readdirSync(homeMnt, { withFileTypes: true });
      for (const e of entries) {
        if (!e.isDirectory() || MNT_SKIP.has(e.name)) continue;
        const found = tryLoad(join(homeMnt, e.name));
        if (found) return found;
      }
    } catch { /* skip */ }
  }

  // 4. CLAUDE_CONFIG_DIR plugin creds
  const ccDir = process.env.CLAUDE_CONFIG_DIR;
  if (ccDir) {
    const p = join(ccDir, 'sentinelone', 'credentials.json');
    if (existsSync(p)) {
      try { return JSON.parse(readFileSync(p, 'utf-8')); } catch { /* bad JSON */ }
    }
  }

  // 5. ~/.config/sentinelone/credentials.json
  const configPath = join(homedir(), '.config', 'sentinelone', 'credentials.json');
  if (existsSync(configPath)) {
    try { return JSON.parse(readFileSync(configPath, 'utf-8')); } catch { /* bad JSON */ }
  }

  return {};
}

// Load once at module init
const _file = discoverCredentials();

/**
 * Returns merged credentials. Environment variables take precedence over file values.
 */
export function getCreds() {
  const e = (key) => process.env[key] || _file[key] || '';
  return {
    S1_CONSOLE_URL:       e('S1_CONSOLE_URL'),
    S1_CONSOLE_API_TOKEN: e('S1_CONSOLE_API_TOKEN') || e('S1_API_TOKEN'),
    S1_HEC_INGEST_URL:    e('S1_HEC_INGEST_URL'),
    SDL_XDR_URL:          e('SDL_XDR_URL') || e('SDL_BASE_URL'),
    SDL_CONFIG_WRITE_KEY: e('SDL_CONFIG_WRITE_KEY'),
    SDL_CONFIG_READ_KEY:  e('SDL_CONFIG_READ_KEY'),
    SDL_LOG_READ_KEY:     e('SDL_LOG_READ_KEY'),
    VT_API_KEY:           e('VT_API_KEY'),
  };
}

/** True if minimum required credentials for S1 Mgmt API are present. */
export function hasS1Creds() {
  const c = getCreds();
  return !!(c.S1_CONSOLE_URL && c.S1_CONSOLE_API_TOKEN);
}

/** True if minimum required credentials for SDL are present. */
export function hasSdlCreds() {
  const c = getCreds();
  return !!(c.SDL_XDR_URL && (c.SDL_CONFIG_WRITE_KEY || c.S1_CONSOLE_API_TOKEN));
}
