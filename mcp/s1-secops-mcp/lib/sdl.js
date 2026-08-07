/**
 * SentinelOne Singularity Data Lake (SDL) API client.
 *
 * Auth: the console API token, sent as `Authorization: Bearer <token>`.
 * It covers every SDL operation, config read, config write, and log read.
 *
 * All SDL endpoints live under `<console>/sdl`, derived from S1_CONSOLE_URL.
 */

import { getCreds } from './credentials.js';

// ─── helpers ──────────────────────────────────────────────────────────────────

function sdlBase() {
  const url = (getCreds().S1_CONSOLE_URL || '').replace(/\/+$/, '');
  if (!url) throw new Error('S1_CONSOLE_URL not configured. Drop credentials.json into your project folder.');
  return `${url}/sdl`;
}

/** The SDL credential: the console API token, used for every operation. */
export function sdlToken() {
  const token = getCreds().S1_CONSOLE_API_TOKEN;
  if (!token) {
    throw new Error('S1_CONSOLE_API_TOKEN not configured. Drop credentials.json into your project folder.');
  }
  return token;
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

async function sdlFetch(method, path, { body, extraHeaders = {}, rawBody = null, contentType = 'application/json' } = {}, retries = 3) {
  const url = `${sdlBase()}${path}`;
  const headers = {
    Authorization: `Bearer ${sdlToken()}`,
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
      await sleep(retryAfterMs(res, delay));
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
  throw new Error(`SDL API ${method} ${path}: request failed after retries`);
}

// ─── Config file operations ───────────────────────────────────────────────────

/** POST /api/listFiles: list every configuration file path on the SDL tenant. */
export async function listFiles() {
  return sdlFetch('POST', '/api/listFiles', { body: {} });
}

/** POST /api/getFile: read a configuration file by path.
 *  Returns { path, content, version, ...status }. */
export async function getFile(path) {
  return sdlFetch('POST', '/api/getFile', {
    body: { path, prettyprint: true },
  });
}

/** POST /api/putFile: create or update a configuration file.
 *  Pass expectedVersion (from a prior getFile) to enable optimistic locking. */
export async function putFile(path, content, expectedVersion) {
  const body = { path, content };
  if (expectedVersion !== undefined && expectedVersion !== null) {
    body.expectedVersion = expectedVersion;
  }
  return sdlFetch('POST', '/api/putFile', { body });
}

/** POST /api/putFile with deleteFile:true deletes a config file. */
export async function deleteFile(path, expectedVersion) {
  const body = { path, deleteFile: true };
  if (expectedVersion !== undefined) body.expectedVersion = expectedVersion;
  return sdlFetch('POST', '/api/putFile', { body });
}

// ─── V1 Query (schema discovery) ─────────────────────────────────────────────
// Deprecated Feb 15 2027 but still the only way to get full event JSON per-event.
// Use for schema discovery; use LRQ for hunting.

/** POST /api/query: retrieve raw event JSON for schema discovery.
 *  Returns { matches: [{ timestamp, message, attributes }] }. */
export async function v1Query(filter, { maxCount = 5, startTime = '24h', endTime } = {}) {
  const body = {
    queryType: 'log',
    filter,
    maxCount,
    startTime,
  };
  if (endTime) body.endTime = endTime;
  return sdlFetch('POST', '/api/query', { body });
}
