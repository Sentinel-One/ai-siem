/**
 * UAM Alert Interface client — pushes OCSF indicators and SecurityAlerts
 * INTO Unified Alert Management via the SentinelOne HEC ingest host.
 *
 * This is a SEPARATE API surface from the Mgmt Console:
 *   Host  : S1_HEC_INGEST_URL (e.g. https://ingest.us1.sentinelone.net)
 *   Auth  : Authorization: Bearer <jwt>  (NOT "ApiToken" — endpoint rejects ApiToken)
 *   Body  : concatenated JSON, gzip-compressed, Content-Encoding: gzip
 *   Scope : S1-Scope: <accountId>[:<siteId>[:<groupId>]]  (mandatory)
 *
 * Endpoints:
 *   POST /v1/indicators  — OCSF behavioral indicators (batch: N per call)
 *   POST /v1/alerts      — OCSF SecurityAlert         (ONE per call — see below)
 *
 * Critical constraints (empirically confirmed on your-tenant 2026-04-22):
 *   - ONE alert per POST /v1/alerts. Multi-alert bodies return HTTP 202 but the
 *     stitcher silently drops all but one. Loop callers for multiple alerts.
 *   - Sleep ~3s between POST /v1/indicators and POST /v1/alerts. If the alert
 *     lands before the indicator's metadata.uid is registered the stitcher silently
 *     drops the alert (still HTTP 202). ingestAlert() enforces the sleep.
 *   - file.hashes MUST be OCSF Fingerprint array [{algorithm_id, algorithm, value}],
 *     NOT a plain dict. Dict form causes silent drop even on HTTP 202.
 *   - finding_info.related_events[] entries MUST carry class_uid, type_uid,
 *     category_uid, activity_id, severity_id, time, message, and observables[]
 *     each with both type and typeName alongside type_id/name/value.
 */

import { gzipSync } from 'zlib';
import { randomUUID } from 'crypto';
import { getCreds } from './credentials.js';

// ─── helpers ──────────────────────────────────────────────────────────────────

function hecBase() {
  const url = (getCreds().S1_HEC_INGEST_URL || '').replace(/\/+$/, '');
  if (!url) {
    throw new Error(
      'S1_HEC_INGEST_URL not configured. Add it to credentials.json ' +
      '(e.g. "S1_HEC_INGEST_URL": "https://ingest.us1.sentinelone.net"). ' +
      'Find the correct URL for your region at: ' +
      'https://community.sentinelone.com/s/article/000004961'
    );
  }
  return url;
}

function bearerJwt() {
  const tok = getCreds().S1_CONSOLE_API_TOKEN;
  if (!tok) throw new Error('S1_CONSOLE_API_TOKEN not configured.');
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
 * sentinelone-mgmt-console-api/scripts/uam_alert_interface.py (tested
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
    // OCSF Fingerprint array — dict form causes silent stitcher drop even on HTTP 202
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
 * @param {boolean} [inline=false]
 *   false (default): related_events[] contains only the reference fields (uid, class_uid,
 *     type_uid, etc.) and observables. The stitcher resolves the full indicator from a
 *     prior /v1/indicators POST via metadata.uid. Use with ingestAlert() (two-call flow).
 *   true: related_events[] embeds the full indicator context (file, device, actor) inline.
 *     No separate /v1/indicators POST is required — everything ships in one /v1/alerts call.
 *     Use with ingestAlertInline() (single-call flow).
 */
export function buildSecurityAlert({
  alertUid,
  indicator,
  title = 'MCP Test Alert',
  description = 'Synthetic test alert created by s1-secops-mcp uam_ingest_alert.',
  detectionProduct = 'smoke-product',
  detectionVendor = 'smoke-vendor',
  inline = false,
  nowMs,
} = {}) {
  const ts = nowMs || Date.now();
  const uid = indicator.metadata.uid;

  // related_events[] entry — shape matches Python build_alert_referencing().
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
    // S1-specific extension class — NOT the generic OCSF 2002.
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

/**
 * Create a synthetic test alert in UAM end-to-end.
 *
 * Builds an OCSF FileSystem Activity indicator and a SecurityAlert,
 * POSTs them to the HEC ingest host with the required 3s sleep in between,
 * and returns the UIDs and HTTP responses.
 *
 * The alert typically surfaces in UAM within 30-60s. Search by title or
 * poll uam_list_alerts.
 *
 * @param {object} opts
 * @param {string} opts.scope           accountId or "accountId:siteId" (mandatory)
 * @param {string} [opts.title]         Alert name shown in UAM (default: "MCP Test Alert")
 * @param {string} [opts.description]   Alert description
 * @param {string} [opts.hostname]      Hostname for the indicator device
 * @param {string} [opts.filename]      Filename for the FileSystem indicator
 * @param {string} [opts.sha256]        SHA-256 hash (64 hex chars); random if omitted
 * @param {number} [opts.sleepMs=3000]  Sleep between indicator POST and alert POST
 */
export async function ingestAlert({
  scope,
  title = 'MCP Test Alert',
  description = 'Synthetic test alert created by s1-secops-mcp uam_ingest_alert.',
  hostname = 'mcp-test-host',
  filename = 'test-payload.exe',
  sha256,
  sleepMs = 3000,
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

  const indicatorResp = await hecPost('/v1/indicators', [indicator], scope);

  // Wait for the stitcher to register the indicator uid before posting the alert.
  // Reducing below ~2s has been observed to cause silent drops on loaded tenants.
  await sleep(sleepMs);

  const alert = buildSecurityAlert({
    alertUid,
    indicator,
    title,
    description,
    nowMs,
  });

  const alertResp = await hecPost('/v1/alerts', alert, scope);

  return {
    indicator_uid: indicatorUid,
    alert_uid: alertUid,
    indicator_response: indicatorResp,
    alert_response: alertResp,
    next_step: `Allow 30-60s then call uam_list_alerts to find the alert by title "${title}". Use uam_get_alert with the returned ID for full details.`,
  };
}

/**
 * Create a synthetic test alert in UAM in a single /v1/alerts POST.
 *
 * Differs from ingestAlert() in two ways:
 *   - No separate /v1/indicators POST (no HEC indicator call at all).
 *   - No sleep — the indicator data is embedded inline inside the alert's
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

/**
 * POST raw OCSF indicators to /v1/indicators.
 * Caller is responsible for correct OCSF shape.
 */
export async function postIndicators({ scope, indicators }) {
  if (!scope) throw new Error('scope is required.');
  const items = Array.isArray(indicators) ? indicators : [indicators];
  return hecPost('/v1/indicators', items, scope);
}

/**
 * POST a single raw OCSF SecurityAlert to /v1/alerts.
 * ONE alert per call — the stitcher silently drops all but one in multi-alert POSTs.
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

/** True if HEC ingest credentials are configured. */
export function hasHecCreds() {
  const c = getCreds();
  return !!(c.S1_HEC_INGEST_URL && c.S1_CONSOLE_API_TOKEN);
}
