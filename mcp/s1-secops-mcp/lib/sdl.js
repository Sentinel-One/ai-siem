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

function pickKey(chain) {
  const c = getCreds();
  const chains = {
    config_write:      [c.SDL_CONFIG_WRITE_KEY],
    config_read:       [c.SDL_CONFIG_WRITE_KEY, c.SDL_CONFIG_READ_KEY, c.S1_CONSOLE_API_TOKEN],
    // Confirmed: SDL_CONFIG_WRITE_KEY does NOT grant "View logs" permission on /api/query.
    // SDL_LOG_READ_KEY must be first in chain for V1 query to succeed.
    log_read:          [c.SDL_LOG_READ_KEY, c.SDL_CONFIG_READ_KEY, c.SDL_CONFIG_WRITE_KEY, c.S1_CONSOLE_API_TOKEN],
  };
  const candidates = chains[chain] || chains.config_read;
  const key = candidates.find(k => k);
  if (!key) throw new Error(`No SDL credential available for chain "${chain}". Drop credentials.json into your project folder.`);
  return key;
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

async function sdlFetch(method, path, { body, chain = 'config_read', extraHeaders = {}, rawBody = null, contentType = 'application/json' } = {}, retries = 3) {
  const url = `${xdrBase()}${path}`;
  const token = pickKey(chain);
  const headers = {
    Authorization: `Bearer ${token}`,
    'Content-Type': contentType,
    ...extraHeaders,
  };

  let delay = 500;
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
      const retryAfter = res.headers.get('Retry-After');
      await sleep(retryAfter ? parseInt(retryAfter, 10) * 1000 : delay);
      delay = Math.min(delay * 2, 8000);
      continue;
    }

    const text = await res.text();
    let data;
    try { data = JSON.parse(text); } catch { data = text; }

    if (!res.ok) {
      const msg = typeof data === 'object' ? JSON.stringify(data) : text;
      throw new Error(`SDL API ${method} ${path} → ${res.status}: ${msg}`);
    }
    return data;
  }
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
