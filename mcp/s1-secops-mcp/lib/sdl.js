/**
 * SentinelOne Singularity Data Lake (SDL) API client.
 *
 * Auth routing (mirrors the Python SDLClient behavior):
 *   putFile             → config_write_key
 *   getFile / listFiles → config_write_key || config_read_key || console_api_token
 *   V1 query methods    → config_write_key || config_read_key || log_read_key || console_api_token
 *
 * All SDL endpoints live at SDL_XDR_URL (e.g. https://xdr.us1.sentinelone.net).
 * The Authorization header is: Bearer <key>
 * For the console JWT used with SDL, the same Bearer prefix applies.
 */

import { getCreds } from './credentials.js';

// ─── helpers ──────────────────────────────────────────────────────────────────

function xdrBase() {
  const url = getCreds().SDL_XDR_URL.replace(/\/+$/, '');
  if (!url) throw new Error('SDL_XDR_URL not configured. Drop credentials.json into your project folder.');
  return url;
}

export function keyCandidates(chain) {
  const c = getCreds();
  const chains = {
    config_write:      [c.SDL_CONFIG_WRITE_KEY, c.S1_CONSOLE_API_TOKEN],
    config_read:       [c.SDL_CONFIG_WRITE_KEY, c.SDL_CONFIG_READ_KEY, c.S1_CONSOLE_API_TOKEN],
    // Confirmed: SDL_CONFIG_WRITE_KEY does NOT grant "View logs" permission on /api/query.
    // SDL_LOG_READ_KEY must be first in chain for V1 query to succeed.
    log_read:          [c.SDL_LOG_READ_KEY, c.SDL_CONFIG_READ_KEY, c.SDL_CONFIG_WRITE_KEY, c.S1_CONSOLE_API_TOKEN],
  };
  const candidates = (chains[chain] || chains.config_read).filter(k => k);
  if (!candidates.length) throw new Error(`No SDL credential available for chain "${chain}". Drop credentials.json into your project folder.`);
  return candidates;
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

function retryAfterMs(res, fallback) {
  // Retry-After may be seconds OR an HTTP date; parseInt on a date yields NaN
  // and sleep(NaN) fires immediately (no backoff). Validate and cap.
  const raw = res.headers.get('Retry-After');
  const secs = Number(raw);
  if (raw && Number.isFinite(secs) && secs >= 0) return Math.min(secs * 1000, 30000);
  return fallback;
}

async function sdlFetch(method, path, { body, chain = 'config_read', extraHeaders = {}, rawBody = null, contentType = 'application/json' } = {}, retries = 3) {
  const url = `${xdrBase()}${path}`;
  // Fixed 2026-07-29: previously only the first CONFIGURED key was tried and a
  // 401/403 was fatal, even when a later key in the chain (e.g. the console JWT)
  // would have worked. Now auth failures advance to the next candidate key.
  const candidates = keyCandidates(chain);
  let lastAuthError = null;

  for (const token of candidates) {
    const headers = {
      Authorization: `Bearer ${token}`,
      'Content-Type': contentType,
      ...extraHeaders,
    };

    let delay = 500;
    let authFailed = false;
    for (let attempt = 0; attempt <= retries; attempt++) {
      let res;
      try {
        res = await fetch(url, {
          method,
          headers,
          body: rawBody !== null ? rawBody : (body !== undefined ? JSON.stringify(body) : undefined),
        });
      } catch (err) {
        if (attempt === retries) throw err;
        await sleep(delay);
        delay = Math.min(delay * 2, 8000);
        continue;
      }

      if ((res.status === 429 || res.status >= 500) && attempt < retries) {
        await sleep(retryAfterMs(res, delay));
        delay = Math.min(delay * 2, 8000);
        continue;
      }

      const text = await res.text();
      let data;
      try { data = JSON.parse(text); } catch { data = text; }

      if (res.status === 401 || res.status === 403) {
        // Wrong-scoped key — fall through to the next candidate in the chain.
        const msg = typeof data === 'object' ? JSON.stringify(data) : text;
        lastAuthError = new Error(`SDL API ${method} ${path} → ${res.status}: ${msg}`);
        authFailed = true;
        break;
      }

      if (!res.ok) {
        const msg = typeof data === 'object' ? JSON.stringify(data) : text;
        throw new Error(`SDL API ${method} ${path} → ${res.status}: ${msg}`);
      }
      return data;
    }
    if (!authFailed) break; // retries exhausted on non-auth errors
  }
  throw lastAuthError || new Error(`SDL API ${method} ${path}: request failed after retries`);
}

// ─── Config file operations ───────────────────────────────────────────────────

/** POST /api/listFiles — list every configuration file path on the SDL tenant. */
export async function listFiles() {
  return sdlFetch('POST', '/api/listFiles', { body: {}, chain: 'config_read' });
}

/** POST /api/getFile — read a configuration file by path.
 *  Returns { path, content, version, ...status }. */
export async function getFile(path) {
  return sdlFetch('POST', '/api/getFile', {
    body: { path, prettyprint: true },
    chain: 'config_read',
  });
}

/** POST /api/putFile — create or update a configuration file.
 *  Pass expectedVersion (from a prior getFile) to enable optimistic locking. */
export async function putFile(path, content, expectedVersion) {
  const body = { path, content };
  if (expectedVersion !== undefined && expectedVersion !== null) {
    body.expectedVersion = expectedVersion;
  }
  return sdlFetch('POST', '/api/putFile', { body, chain: 'config_write' });
}

/** POST /api/putFile with deleteFile:true — delete a config file. */
export async function deleteFile(path, expectedVersion) {
  const body = { path, deleteFile: true };
  if (expectedVersion !== undefined) body.expectedVersion = expectedVersion;
  return sdlFetch('POST', '/api/putFile', { body, chain: 'config_write' });
}

// ─── V1 Query (schema discovery) ─────────────────────────────────────────────
// Deprecated Feb 15 2027 but still the only way to get full event JSON per-event.
// Use for schema discovery; use LRQ for hunting.

/** POST /api/query — retrieve raw event JSON for schema discovery.
 *  Returns { matches: [{ timestamp, message, attributes }] }. */
export async function v1Query(filter, { maxCount = 5, startTime = '24h', endTime } = {}) {
  const body = {
    queryType: 'log',
    filter,
    maxCount,
    startTime,
  };
  if (endTime) body.endTime = endTime;
  return sdlFetch('POST', '/api/query', { body, chain: 'log_read' });
}
