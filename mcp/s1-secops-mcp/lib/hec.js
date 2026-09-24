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
 *   Endpoints : /services/collector/raw   (raw text, recommended for logs)
 *               /services/collector/event (structured JSON)
 *   Auth      : Authorization: Bearer <S1_HEC_TOKEN>, an SDL Log Write Key. NOT the
 *               Management Console API token: the collector refuses a user token.
 *               Mint one at Console > Singularity Data Lake > API Keys > Log Write Key;
 *               no API creates one.
 *   Scope     : NONE. A Log Write Key is minted for one account or site and writes only
 *               there, so the key itself fixes the destination and the S1-Scope header is
 *               neither required nor honoured. Measured on a live tenant: the write key
 *               returns 200 with no S1-Scope header at all, while the console token on the
 *               same request returns 400 "Missing S1-Scope header". To write somewhere
 *               else, use a key minted for that scope.
 *   Parser    : ?sourcetype=<parserName> query param. Other query params become fields in the UI.
 *   Pre-parsed: /event with ?isParsed=true indexes already-structured JSON fields directly, with no SDL parser.
 *   Compress  : optional "Content-Encoding: gzip" (or zstd), recommended, lowers egress cost.
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
  const tok = getCreds().S1_HEC_TOKEN;
  if (!tok) {
    throw new Error(
      'S1_HEC_TOKEN not configured. Log ingest needs an SDL Log Write Key, not the ' +
      'Management Console API token: the event collector refuses a user token. ' +
      'Mint one at Console > Singularity Data Lake > API Keys > Log Write Key ' +
      '(no API creates one) and set S1_HEC_TOKEN. The key is scoped to one account or ' +
      'site and writes only there.'
    );
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
 * @param {string} [opts.scope]     IGNORED, accepted only so existing callers do not break.
 *                              The S1-Scope header is not sent: the Log Write Key already
 *                              determines the destination and the collector does not honour
 *                              an override. Passing one has no effect.
 * @param {('raw'|'event')} [opts.endpoint='raw']
 *                              For 'event', logContent must be newline-separated HEC JSON envelopes:
 *                              {"time": <epoch seconds>, "event": <string|object>, "fields": {...}}.
 *                              The body is passed through verbatim and Content-Type is application/json,
 *                              so per-event "time" BACKDATES the event (live-verified 2026-07-29; with the
 *                              old text/plain Content-Type the envelope was indexed as opaque text at
 *                              receive time and "time" was ignored).
 * @param {boolean} [opts.compress=true]  gzip the body (Content-Encoding: gzip)
 * @param {boolean} [opts.isParsed=false] /event only: set ?isParsed=true to index already-structured JSON fields without an SDL parser.
 * @returns {Promise<{status:number, endpoint:string, url:string, body:any}>}
 */
export async function hecIngest(logContent, { parser, fields = {}, scope, endpoint = 'raw', compress = true, isParsed = false } = {}) {
  void scope; // accepted and deliberately unused; see the param doc above.
  if (typeof logContent !== 'string' || logContent.length === 0) {
    throw new Error('hecIngest: logContent must be a non-empty string.');
  }
  if (endpoint !== 'raw' && endpoint !== 'event') {
    throw new Error("hecIngest: endpoint must be 'raw' or 'event'.");
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
    // /event takes HEC JSON envelopes and must be application/json, or the
    // envelope (including per-event "time") is treated as opaque text and the
    // event is indexed at receive time. /raw is plain text. Fixed 2026-07-29.
    'Content-Type': endpoint === 'event' ? 'application/json' : 'text/plain',
  };
  if (compress) headers['Content-Encoding'] = 'gzip';
  // No S1-Scope. The Log Write Key fixes the destination; sending a scope does not
  // move the events and an empty one is a different request to none at all.

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

    // 429 means the request was rejected before processing: safe to retry.
    // 5xx after a raw-log POST is ambiguous (the events may already be
    // committed) and HEC has no idempotency key, so retrying risks duplicate
    // events inflating SDL counts. Fixed 2026-07-29: no automatic 5xx retry.
    if (res.status === 429 && attempt < 3) {
      // Retry-After may be missing or an HTTP date. Number(null) is 0, so a
      // missing header must fall back to the exponential delay, not sleep 0ms.
      const raRaw = res.headers.get('Retry-After');
      const ra = Number(raRaw);
      await sleep(raRaw && Number.isFinite(ra) && ra >= 0 ? Math.min(ra * 1000, 30000) : delay);
      delay = Math.min(delay * 2, 8000);
      continue;
    }

    const text = await res.text();
    let data;
    try { data = JSON.parse(text); } catch { data = text; }

    if (!res.ok) {
      throw new Error(`HEC POST /services/collector/${endpoint} -> ${res.status}: ${JSON.stringify(data)}`);
    }

    // The collector is Splunk-HEC-compatible: it reports the per-batch outcome
    // in the BODY, not the status line. A rejected batch still answers 200.
    // Measured on a live tenant: an SDL Log Write Key returns
    // {"text":"Success","code":0}; a Management Console token returns
    // {"text":"Missing S1-Scope header","code":5}, also with HTTP 200. A key
    // minted for a different account or site likewise returns success and then
    // discards every event, which is the case that looks healthy and is not.
    // Without this check a caller reports a successful ingest of data that was
    // dropped, and the follow-up investigation is misdirected at the parser or
    // the detection rule.
    if (data && typeof data === 'object' && data.code !== undefined && Number(data.code) !== 0) {
      throw new Error(
        `HEC POST /services/collector/${endpoint} -> ${res.status} but the collector rejected the batch: ` +
        `code=${data.code} text=${JSON.stringify(data.text ?? null)}. ` +
        `No events were ingested. Check that S1_HEC_TOKEN is an SDL Log Write Key ` +
        `minted for the intended account or site.`
      );
    }

    return { status: res.status, endpoint, url, body: data };
  }
  throw lastErr;
}
