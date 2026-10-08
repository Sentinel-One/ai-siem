/**
 * UAM Alert Interface client: pushes OCSF indicators and SecurityAlerts
 * INTO Unified Alert Management via the SentinelOne HEC ingest host.
 *
 * This is a SEPARATE API surface from the Mgmt Console:
 *   Host  : S1_HEC_INGEST_URL (e.g. https://ingest.us1.sentinelone.net)
 *   Auth  : Authorization: Bearer <jwt>  (NOT "ApiToken", endpoint rejects ApiToken)
 *   Body  : concatenated JSON, gzip-compressed, Content-Encoding: gzip
 *   Scope : S1-Scope: <accountId>[:<siteId>[:<groupId>]]  (mandatory)
 *
 * Endpoints:
 *   POST /v1/alerts     , OCSF SecurityAlert (ONE per call, see below)
 *
 * INDICATORS ARE NOT SEPARATELY INGESTIBLE. There is no usable POST
 * /v1/indicators any more: the endpoint refuses the console user token AND the
 * SDL Log Write Key, so no credential can drive it. Every indicator now rides
 * inside the alert, in finding_info.related_events[], and the Indicators tab in
 * the console is fed from there. This removed the sleep, the ordering contract
 * and a whole class of silent drop, so the single POST is simpler as well as
 * being the only thing that works.
 *
 * Critical constraints (empirically confirmed on a live tenant):
 *   - ONE alert per POST /v1/alerts. Multi-alert bodies return HTTP 202 but the
 *     stitcher silently drops all but one. Loop callers for multiple alerts.
 *   - file.hashes MUST be OCSF Fingerprint array [{algorithm_id, algorithm, value}],
 *     NOT a plain dict. Dict form causes silent drop even on HTTP 202.
 *   - finding_info.related_events[] entries MUST carry class_uid, type_uid,
 *     category_uid, activity_id, severity_id, time, message, and observables[]
 *     each with both type and typeName alongside type_id/name/value.
 */

import { gzipSync } from 'zlib';
import { randomUUID } from 'crypto';
import { getCreds, setupHint } from './credentials.js';

// ─── helpers ──────────────────────────────────────────────────────────────────

function hecBase() {
  const url = (getCreds().S1_HEC_INGEST_URL || '').replace(/\/+$/, '');
  if (!url) {
    throw new Error(
      'S1_HEC_INGEST_URL not configured (e.g. https://ingest.us1.sentinelone.net). ' +
      setupHint() + ' ' +
      'Find the correct URL for your region at: ' +
      'https://community.sentinelone.com/s/article/000004961'
    );
  }
  return url;
}

function bearerJwt() {
  const tok = getCreds().S1_CONSOLE_API_TOKEN;
  if (!tok) throw new Error('S1_CONSOLE_API_TOKEN not configured. ' + setupHint());
  return tok;
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

/**
 * POST one or more OCSF objects to a HEC ingest endpoint.
 * Body is concatenated JSON (newline-separated), gzip-compressed.
 * Auth is Bearer (not ApiToken).
 */
async function hecPost(path, payloads, scope, retries = 3) {
  const url = `${hecBase()}${path}`;
  const items = Array.isArray(payloads) ? payloads : [payloads];
  const body = items.map(p => JSON.stringify(p)).join('\n');
  const compressed = gzipSync(Buffer.from(body, 'utf-8'));

  let delay = 1000;
  let lastErr;
  for (let attempt = 0; attempt <= retries; attempt++) {
    let res;
    try {
      res = await fetch(url, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${bearerJwt()}`,
          'Content-Type': 'application/json',
          'Content-Encoding': 'gzip',
          'S1-Scope': scope,
        },
        body: compressed,
      });
    } catch (err) {
      lastErr = err;
      if (attempt === retries) throw err;
      await sleep(delay);
      delay = Math.min(delay * 2, 8000);
      continue;
    }

    // Retry is acceptable here despite POST semantics: UAM alert/indicator
    // payloads carry metadata.uid, which the stitcher dedupes on, so a re-POST
    // after an ambiguous 5xx does not double-ingest. (2026-07-29 review note.)
    if ((res.status === 429 || res.status >= 500) && attempt < retries) {
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
      throw new Error(`HEC POST ${path} -> ${res.status}: ${JSON.stringify(data)}`);
    }
    return { status: res.status, body: data };
  }
  throw lastErr;
}

// ─── OCSF payload builders ────────────────────────────────────────────────────

/**
 * Build an OCSF FileSystem Activity indicator (class_uid 1001).
 *
 * Shape matches the confirmed-working Python build_file_indicator() in
 * mgmt-console-api/scripts/uam_alert_interface.py (tested
 * on usea1-acme 2026-04-22). Key points:
 *   - metadata.version "1.6.0-dev" (not "1.6.0")
 *   - metadata.extensions array (not "extension" singular)
 *   - metadata.product omits vendor_name (just name)
 *   - type_uid set directly on the indicator (class_uid*100 + activity_id)
 *   - device carries name + hostname + type_id:1
 *   - actor.user carries type:"System" + type_id:3
 *   - attack_surface_id:1 (singular, at top level)
 *   - severity_id:2 (not 3)
 *   - file.hashes MUST be Fingerprint array [{algorithm_id,algorithm,value}]
 *
 * Returns a complete indicator object ready to POST to /v1/indicators.
 */
export function buildFileIndicator({
  indicatorUid,
  filename = 'test-payload.exe',
  sha256,
  hostname = 'mcp-test-host',
  deviceUid,
  userUid,
  nowMs,
} = {}) {
  const ts = nowMs || Date.now();
  const iUid = indicatorUid || randomUUID();
  const dUid = deviceUid || randomUUID();
  const uUid = userUid || randomUUID();
  const sha  = sha256 || '0'.repeat(64);
  const activityId = 1;
  const classUid   = 1001;

  return {
    message: `File ${filename} action_${activityId}`,
    time: ts,
    device: {
      uid: dUid,
      name: hostname,
      hostname,
      type_id: 1,
    },
    metadata: {
      version: '1.6.0-dev',
      product: { name: 'smoke-product' },
      extensions: [{ name: 's1', uid: '998', version: '0.1.0' }],
      profiles: ['s1/security_indicator'],
      uid: iUid,
    },
    type_uid: classUid * 100 + activityId,
    activity_id: activityId,
    class_uid: classUid,
    category_uid: 1,
    observables: [
      { type_id: 7, type: 'File Name', typeName: 'File Name', name: 'file.name', value: filename },
      { type_id: 1, type: 'Hostname',  typeName: 'Hostname',  name: 'device.hostname', value: hostname },
      { type_id: 8, type: 'Hash',      typeName: 'Hash',      name: 'file.hashes.sha256', value: sha },
    ],
    actor: {
      user: {
        name: 'smoke-user',
        type: 'System',
        uid: uUid,
        type_id: 3,
      },
    },
    severity_id: 2,
    attack_surface_id: 1,
    // OCSF Fingerprint array: dict form causes silent stitcher drop even on HTTP 202
    file: {
      name: filename,
      type_id: 1,
      hashes: [{ algorithm_id: 3, algorithm: 'SHA-256', value: sha }],
    },
  };
}

/**
 * Build an OCSF SecurityAlert (class_uid 2002) referencing one indicator.
 *
 * Returns a complete alert object ready to POST to /v1/alerts (one at a time).
 *
 * @param {boolean} [inline=true]
 *   The only supported value is true, and it is the default. related_events[] embeds the
 *   full indicator context (file, device, actor) inline and everything ships in one
 *   /v1/alerts call.
 *
 *   Passing false used to emit reference-only entries for the stitcher to resolve against
 *   a prior /v1/indicators POST. That POST is no longer possible, so a reference-only
 *   alert now resolves to nothing: it is accepted with HTTP 202 and shows an empty
 *   Indicators tab. The parameter is still accepted so old callers do not crash, but it
 *   is forced to true and a warning is emitted.
 */
export function buildSecurityAlert({
  alertUid,
  indicator,
  title = 'MCP Test Alert',
  description = 'Synthetic test alert created by s1-secops-mcp uam_ingest_alert.',
  detectionProduct = 'smoke-product',
  detectionVendor = 'smoke-vendor',
  inline = true,
  nowMs,
} = {}) {
  const ts = nowMs || Date.now();
  const uid = indicator.metadata.uid;

  // related_events[] entry: shape matches Python build_alert_referencing().
  // type_uid comes from the indicator's own type_uid field (set by buildFileIndicator).
  // inline=true embeds file/device/actor so the alert is fully self-contained;
  // inline=false is reference-only and relies on the stitcher resolving metadata.uid.
  const relatedEvent = {
    message:      indicator.message || '',
    time:         ts,
    uid,
    severity_id:  indicator.severity_id || 2,
    observables:  (indicator.observables || []).map(o => ({
      ...o,
      typeName: o.typeName || o.type,
    })),
    class_uid:    indicator.class_uid,
    type_uid:     indicator.type_uid,
    category_uid: indicator.category_uid,
    activity_id:  indicator.activity_id || 1,
    ...(inline ? {
      file:   indicator.file,
      device: indicator.device,
      actor:  indicator.actor,
    } : {}),
  };

  const aUid = alertUid || randomUUID();
  const dev  = indicator.device || {};

  return {
    finding_info: {
      uid:            aUid,
      title,
      desc:           description,
      related_events: [relatedEvent],
    },
    // Single resources[] entry keyed on first indicator's device.
    // type_id:1 + type:"host" matches the Python reference implementation.
    resources: [{
      uid:     dev.uid   || 'unknown',
      name:    dev.hostname || dev.name || 'unknown',
      type_id: 1,
      type:    'host',
    }],
    category_uid:        2,
    category_name:       'Findings',
    // S1-specific extension class: NOT the generic OCSF 2002.
    // Using 2002 causes silent drop; 99602001 is what the stitcher expects.
    class_uid:           99602001,
    class_name:          'S1 Security Alert',
    type_uid:            9960200101,
    type_name:           'S1 Security Alert: Create',
    activity_id:         1,
    metadata: {
      version:       '1.6.0-dev',
      extension:     { name: 's1', uid: '998', version: '0.1.0' },
      product:       { name: detectionProduct, vendor_name: detectionVendor },
      logged_time:   ts,
      modified_time: ts,
    },
    time:                ts,
    attack_surface_ids:  [1],
    severity_id:         2,
    state_id:            1,
    s1_classification_id: 1,
  };
}

// ─── High-level end-to-end helpers ────────────────────────────────────────────

/* ingestAlert(), the two-step indicator-then-alert flow, was REMOVED.
 *
 * It posted the indicator to /v1/indicators, slept ~3s for the stitcher, then
 * posted an alert referencing it by uid. That path no longer works: the
 * indicators endpoint refuses both the console user token and the SDL Log Write
 * Key, so there is no credential that can drive it. Indicators are now carried
 * inline in the alert body instead, which is what ingestAlertInline() below
 * does, and which never needed the sleep or the sequencing in the first place.
 *
 * Deliberately deleted rather than left throwing: a function that can only fail
 * invites callers to keep a code path alive for it.
 */


/**
 * Create a synthetic test alert in UAM in a single /v1/alerts POST.
 *
 * Differs from ingestAlert() in two ways:
 *   - No separate /v1/indicators POST (no HEC indicator call at all).
 *   - No sleep: the indicator data is embedded inline inside the alert's
 *     finding_info.related_events[] entry (file, device, actor fields included),
 *     so the stitcher does not need to resolve a uid from a prior indicator POST.
 *
 * Trade-off: the alert's Indicators tab in UAM may show less detail than in the
 * two-call flow (stitcher reconciliation vs inline embedding). Use two-call mode
 * when deep indicator stitching is required; use inline mode for rapid testing or
 * when a single round-trip is preferred.
 */
export async function ingestAlertInline({
  scope,
  title = 'MCP Test Alert',
  description = 'Synthetic test alert created by s1-secops-mcp uam_ingest_alert (inline mode).',
  hostname = 'mcp-test-host',
  filename = 'test-payload.exe',
  sha256,
} = {}) {
  if (!scope) throw new Error('scope is required (accountId or "accountId:siteId").');

  const nowMs = Date.now();
  const indicatorUid = randomUUID();
  const alertUid = randomUUID();

  const indicator = buildFileIndicator({
    indicatorUid,
    filename,
    sha256,
    hostname,
    nowMs,
  });

  const alert = buildSecurityAlert({
    alertUid,
    indicator,
    title,
    description,
    inline: true,
    nowMs,
  });

  const alertResp = await hecPost('/v1/alerts', alert, scope);

  return {
    indicator_uid: indicatorUid,
    alert_uid: alertUid,
    alert_response: alertResp,
    mode: 'inline',
    next_step: `Allow 30-60s then call uam_list_alerts to find the alert by title "${title}". Use uam_get_alert with the returned ID for full details.`,
  };
}

// ─── Low-level raw-payload helpers ────────────────────────────────────────────

/* postIndicators() was REMOVED along with the /v1/indicators path it wrapped.
 * See the note above ingestAlertInline(). Indicators ride inside the alert.
 */


/**
 * POST a single raw OCSF SecurityAlert to /v1/alerts.
 * ONE alert per call: the stitcher silently drops all but one in multi-alert POSTs.
 */
export async function postAlert({ scope, alert }) {
  if (!scope) throw new Error('scope is required.');
  if (Array.isArray(alert)) {
    throw new Error(
      'postAlert() accepts a single alert object, not an array. ' +
      'The HEC stitcher silently drops all but one alert in multi-alert POSTs. ' +
      'Loop this call for multiple alerts.'
    );
  }
  return hecPost('/v1/alerts', alert, scope);
}

/** True if UAM ingest credentials are configured.
 *
 *  UAM alert ingest posts OCSF to /v1/alerts on the ingest host and authenticates
 *  with the CONSOLE token, not the Log Write Key: alert creation and IOCs are
 *  user-token operations. Only raw log ingest over the event collector uses
 *  S1_HEC_TOKEN, and that is checked separately in hec.js. Conflating the two is
 *  what made this function demand the wrong credential.
 */
export function hasHecCreds() {
  const c = getCreds();
  return !!(c.S1_HEC_INGEST_URL && c.S1_CONSOLE_API_TOKEN);
}
