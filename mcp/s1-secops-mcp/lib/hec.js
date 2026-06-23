/**
 * HEC (HTTP Event Collector) raw-log ingestion into the SentinelOne AI SIEM
 * Singularity Data Lake. This is the SDL log-ingestion path and the replacement
 * for the removed SDL `uploadLogs`. It is NOT UAM ingest: the `uam_*` tools post
 * OCSF indicators/alerts to /v1/* on the same ingest host, but that is a separate
 * API and is not connected to HEC.
 *
 * Source of truth: S-26.1 User Guide, "Singularity Data Lake > Data Ingestion >
 * Additional Integrations > HTTP Event Collector (HEC)", p.4723-4726.
 *   Host      : S1_HEC_INGEST_URL (e.g. https://ingest.us1.sentinelone.net)
 *   Endpoints : /services/collector/raw   (raw text — recommended for logs)
 *               /services/collector/event (structured JSON)
 *   Auth      : Authorization: Bearer <S1_CONSOLE_API_TOKEN> (the same Management Console API token the other tools use)
 *   Scope     : S1-Scope header is REQUIRED (accountId or accountId:siteId). Without it HEC returns 400 "Missing S1-Scope header".
 *   Parser    : ?sourcetype=<parserName> query param. Other query params become fields in the UI.
 *   Pre-parsed: /event with ?isParsed=true indexes already-structured JSON fields directly, with no SDL parser.
 *   Compress  : optional "Content-Encoding: gzip" (or zstd) — recommended, lowers egress cost.
 *   Limits    : 10 MB uncompressed per request, 1000 requests/sec, 2 GB/sec per account.
 */

import { gzipSync } from 'zlib';
import { getCreds } from './credentials.js';

const MAX_UNCOMPRESSED = 10 * 1024 * 1024; // 10 MB per HEC docs

function hecBase() {
  const url = (getCreds().S1_HEC_INGEST_URL || '').replace(/\/+$/, '');
  if (!url) {
    throw new Error(
      'S1_HEC_INGEST_URL not configured. Add it to credentials.json ' +
      '(e.g. "S1_HEC_INGEST_URL": "https://ingest.us1.sentinelone.net"). ' +
      'Find the regional ingest URL at https://community.sentinelone.com/s/article/000004961'
    );
  }
  return url;
}

function hecToken() {
  const tok = getCreds().S1_CONSOLE_API_TOKEN;
  if (!tok) {
    throw new Error('S1_CONSOLE_API_TOKEN not configured. HEC uses the same Management Console API token as the Bearer.');
  }
  return tok;
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

/**
 * Ingest raw logs/events into SDL via the HEC endpoint.
 *
 * @param {string} logContent  Raw text. For /raw, newline-separated lines become separate events.
 * @param {object} [opts]
 * @param {string} [opts.parser]    Parser name -> ?sourcetype=
 * @param {object} [opts.fields]    Extra {key: value} pairs -> query params, each becomes a UI field.
 *                              Avoid HEC-reserved keys (event, time, host, source, sourcetype, index, fields):
 *                              HEC interprets those, they are not stored as custom fields. Use `parser` (not a field) to set sourcetype. (S-26.1 HEC docs, p.4708.)
 * @param {string} opts.scope       REQUIRED. accountId or "accountId:siteId" -> S1-Scope header. HEC returns 400 "Missing S1-Scope header" without it.
 * @param {('raw'|'event')} [opts.endpoint='raw']
 * @param {boolean} [opts.compress=true]  gzip the body (Content-Encoding: gzip)
 * @param {boolean} [opts.isParsed=false] /event only: set ?isParsed=true to index already-structured JSON fields without an SDL parser.
 * @returns {Promise<{status:number, endpoint:string, url:string, body:any}>}
 */
export async function hecIngest(logContent, { parser, fields = {}, scope, endpoint = 'raw', compress = true, isParsed = false } = {}) {
  if (typeof logContent !== 'string' || logContent.length === 0) {
    throw new Error('hecIngest: logContent must be a non-empty string.');
  }
  if (endpoint !== 'raw' && endpoint !== 'event') {
    throw new Error("hecIngest: endpoint must be 'raw' or 'event'.");
  }
  if (!scope || typeof scope !== 'string') {
    throw new Error('hecIngest: scope is required. HEC rejects requests without an S1-Scope header (400 "Missing S1-Scope header"). Pass an accountId or "accountId:siteId".');
  }

  const qs = new URLSearchParams();
  if (parser) qs.set('sourcetype', parser);
  for (const [k, v] of Object.entries(fields || {})) qs.set(k, String(v));
  if (isParsed) qs.set('isParsed', 'true');
  const query = qs.toString();
  const url = `${hecBase()}/services/collector/${endpoint}${query ? `?${query}` : ''}`;

  const rawBuf = Buffer.from(logContent, 'utf-8');
  if (rawBuf.length > MAX_UNCOMPRESSED) {
    throw new Error(
      `hecIngest: payload is ${rawBuf.length} bytes, over the 10 MB uncompressed HEC limit. ` +
      'Split into smaller batches.'
    );
  }
  const body = compress ? gzipSync(rawBuf) : rawBuf;

  const headers = {
    Authorization: `Bearer ${hecToken()}`,
    'Content-Type': 'text/plain',
  };
  if (compress) headers['Content-Encoding'] = 'gzip';
  headers['S1-Scope'] = scope;

  let delay = 1000;
  let lastErr;
  for (let attempt = 0; attempt <= 3; attempt++) {
    let res;
    try {
      res = await fetch(url, { method: 'POST', headers, body });
    } catch (err) {
      lastErr = err;
      if (attempt === 3) throw err;
      await sleep(delay);
      delay = Math.min(delay * 2, 8000);
      continue;
    }

    if ((res.status === 429 || res.status >= 500) && attempt < 3) {
      const retryAfter = res.headers.get('Retry-After');
      await sleep(retryAfter ? parseInt(retryAfter, 10) * 1000 : delay);
      delay = Math.min(delay * 2, 8000);
      continue;
    }

    const text = await res.text();
    let data;
    try { data = JSON.parse(text); } catch { data = text; }

    if (!res.ok) {
      throw new Error(`HEC POST /services/collector/${endpoint} -> ${res.status}: ${JSON.stringify(data)}`);
    }
    return { status: res.status, endpoint, url, body: data };
  }
  throw lastErr;
}
