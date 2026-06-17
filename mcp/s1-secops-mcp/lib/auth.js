/**
 * Bearer token auth loader for HTTP transport.
 *
 * Sources (highest wins):
 *   1. MCP_BEARER_TOKENS_FILE — path to JSON: { "<name>": "<token>", ... }
 *      Allows per-user tokens with stable names for audit logs.
 *      File mode is enforced via the install script (0600 recommended).
 *   2. MCP_BEARER_TOKENS — comma-separated raw tokens (no per-user names).
 *      Names default to "token-1", "token-2", etc.
 *
 * If neither is set, HTTP transport runs with NO authentication. The server
 * logs a loud warning at startup. Suitable only for stdio-style local-only
 * deployments where the bind address is 127.0.0.1 and no other process can
 * reach the port.
 *
 * SIGHUP reloads the token store without restarting the server, so rotation
 * is "edit file, kill -HUP <pid>" with zero downtime.
 *
 * Zero dependencies. Synchronous load, async reload via SIGHUP.
 */

import { readFileSync, existsSync, statSync } from 'fs';

let _tokens = new Map();   // token -> name
let _loadedFrom = null;
let _warnedNoAuth = false;

function parseFileTokens(path) {
  const raw = readFileSync(path, 'utf-8');
  const obj = JSON.parse(raw);
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) {
    throw new Error('MCP_BEARER_TOKENS_FILE must contain a JSON object of {name: token}');
  }
  const m = new Map();
  for (const [name, token] of Object.entries(obj)) {
    if (typeof token !== 'string' || token.length < 16) {
      throw new Error(`Token for "${name}" must be a string of at least 16 chars`);
    }
    m.set(token, name);
  }
  return m;
}

function parseEnvTokens(raw) {
  const m = new Map();
  const parts = raw.split(',').map(s => s.trim()).filter(Boolean);
  parts.forEach((token, i) => {
    if (token.length < 16) {
      throw new Error(`Token #${i + 1} in MCP_BEARER_TOKENS must be at least 16 chars`);
    }
    m.set(token, `token-${i + 1}`);
  });
  return m;
}

function logModeForPath(path) {
  try {
    const s = statSync(path);
    const mode = (s.mode & 0o777).toString(8);
    if ((s.mode & 0o077) !== 0) {
      process.stderr.write(
        `[auth] WARNING: ${path} mode is ${mode}; recommended 0600. ` +
        `Run: chmod 600 ${path}\n`
      );
    }
    return mode;
  } catch { return null; }
}

export function loadTokens() {
  const filePath = process.env.MCP_BEARER_TOKENS_FILE;
  const envRaw   = process.env.MCP_BEARER_TOKENS;

  if (filePath) {
    if (!existsSync(filePath)) {
      throw new Error(`MCP_BEARER_TOKENS_FILE points at non-existent path: ${filePath}`);
    }
    _tokens = parseFileTokens(filePath);
    _loadedFrom = `file:${filePath}`;
    const mode = logModeForPath(filePath);
    process.stderr.write(
      `[auth] Loaded ${_tokens.size} bearer token(s) from ${filePath} (mode ${mode || 'unknown'})\n`
    );
    return _tokens.size;
  }

  if (envRaw) {
    _tokens = parseEnvTokens(envRaw);
    _loadedFrom = 'env:MCP_BEARER_TOKENS';
    process.stderr.write(
      `[auth] Loaded ${_tokens.size} bearer token(s) from MCP_BEARER_TOKENS env var\n`
    );
    return _tokens.size;
  }

  _tokens = new Map();
  _loadedFrom = null;
  return 0;
}

/**
 * Returns true if any token store is configured. When false, HTTP transport
 * must either (a) refuse to start, or (b) start with a loud warning,
 * depending on caller policy.
 */
export function isAuthConfigured() {
  return _tokens.size > 0;
}

/**
 * Validates an Authorization header value and returns the matched token name
 * (for audit logging), or null if the header is missing/invalid.
 *
 * Accepts:  "Bearer <token>"
 * Rejects:  empty, malformed, unknown token.
 */
export function authenticate(authHeader) {
  if (!authHeader || typeof authHeader !== 'string') return null;
  const m = authHeader.match(/^Bearer\s+(.+)$/i);
  if (!m) return null;
  const token = m[1].trim();
  return _tokens.get(token) || null;
}

/**
 * Warn once if HTTP transport is enabled with no auth. Caller invokes this
 * at startup.
 */
export function warnIfNoAuth(host) {
  if (!isAuthConfigured() && !_warnedNoAuth) {
    _warnedNoAuth = true;
    const reachable = host !== '127.0.0.1' && host !== 'localhost';
    process.stderr.write(
      `[auth] WARNING: HTTP transport is running with NO authentication.\n` +
      (reachable
        ? `[auth] WARNING: bound to ${host} (reachable from other hosts). ` +
          `Set MCP_BEARER_TOKENS_FILE or MCP_BEARER_TOKENS, or bind to 127.0.0.1.\n`
        : `[auth] (Bound to ${host}; OK for purely local single-user use, ` +
          `not OK for team / VM deployments.)\n`)
    );
  }
}

export function authSourceForLogging() {
  return _loadedFrom;
}

/**
 * Install a SIGHUP handler that reloads tokens from the same source.
 * Returns nothing; intended to be called once at startup.
 */
export function installSighupReload() {
  process.on('SIGHUP', () => {
    try {
      const n = loadTokens();
      process.stderr.write(`[auth] SIGHUP: reloaded, ${n} token(s) active\n`);
    } catch (e) {
      process.stderr.write(`[auth] SIGHUP: reload FAILED, keeping previous tokens: ${e.message}\n`);
    }
  });
}
