/**
 * UAM Alert Interface tools — push OCSF indicators + alerts INTO UAM
 * via the SentinelOne HEC ingest host (ingest.us1.sentinelone.net).
 *
 * Tools:
 *   uam_ingest_alert      End-to-end: build + POST one FileSystem indicator + one SecurityAlert
 *   uam_post_indicators   Low-level: POST raw OCSF indicators to /v1/indicators
 *   uam_post_alert        Low-level: POST a single raw OCSF SecurityAlert to /v1/alerts
 *
 * These tools require S1_HEC_INGEST_URL in credentials.json in addition to
 * S1_CONSOLE_API_TOKEN (same token, Bearer prefix instead of ApiToken).
 */

import { ingestAlert, ingestAlertInline, postIndicators, postAlert } from '../lib/uam-ingest.js';

export const tools = [

  // ─── uam_ingest_alert ─────────────────────────────────────────────────────
  {
    name: 'uam_ingest_alert',
    description: `Create a synthetic test alert in Unified Alert Management (UAM) via the SentinelOne HEC ingest API. Supports two modes controlled by the "inline" parameter:

Two-call mode (inline=false, default): POST indicator to /v1/indicators, sleep 3s, POST SecurityAlert to /v1/alerts referencing the indicator uid. The stitcher resolves the full indicator into alert.rawIndicators. Best for testing deep indicator stitching and the Indicators tab in UAM.

Inline mode (inline=true): POST a single SecurityAlert to /v1/alerts with the indicator's file/device/actor fields embedded inside finding_info.related_events[]. No separate indicator POST, no sleep — one round-trip. Best for rapid alert creation or when a single call is preferred.

Both modes return indicator_uid and alert_uid. The alert surfaces in UAM within 30-60s. Requires S1_HEC_INGEST_URL in credentials.json.`,
    inputSchema: {
      type: 'object',
      properties: {
        scope: {
          type: 'string',
          description: 'Mandatory. accountId or "accountId:siteId" (colon-separated). Find the accountId via s1_api_get /web/api/v2.1/accounts?limit=1.',
        },
        title: {
          type: 'string',
          description: 'Alert name shown in UAM. Default: "MCP Test Alert".',
          default: 'MCP Test Alert',
        },
        description: {
          type: 'string',
          description: 'Alert description body. Default: generic synthetic alert text.',
        },
        hostname: {
          type: 'string',
          description: 'Hostname to use for the synthetic indicator device. Default: "mcp-test-host".',
          default: 'mcp-test-host',
        },
        filename: {
          type: 'string',
          description: 'Filename for the OCSF FileSystem Activity indicator. Default: "test-payload.exe".',
          default: 'test-payload.exe',
        },
        sha256: {
          type: 'string',
          description: 'SHA-256 hash (64 lowercase hex chars). If omitted, a zeroed placeholder hash is used.',
        },
        sleep_ms: {
          type: 'number',
          description: 'Two-call mode only. Milliseconds to sleep between the indicator POST and the alert POST. Default 3000. Do not go below 2000 on loaded tenants.',
          default: 3000,
        },
        inline: {
          type: 'boolean',
          description: 'When true, embed indicator data (file, device, actor, observables) directly inside the alert\'s finding_info.related_events[] and POST only to /v1/alerts — no separate /v1/indicators call, no sleep. When false (default), use the two-call flow: POST indicator first, sleep, then POST alert.',
          default: false,
        },
      },
      required: ['scope'],
    },
    async handler({ scope, title, description, hostname, filename, sha256, sleep_ms = 3000, inline = false }) {
      const result = inline
        ? await ingestAlertInline({ scope, title, description, hostname, filename, sha256 })
        : await ingestAlert({ scope, title, description, hostname, filename, sha256, sleepMs: sleep_ms });
      return JSON.stringify(result, null, 2);
    },
  },

  // ─── uam_post_indicators ──────────────────────────────────────────────────
  {
    name: 'uam_post_indicators',
    description: `POST one or more raw OCSF behavioral indicators to /v1/indicators on the SentinelOne HEC ingest host. Batching is supported — pass multiple indicators in the array and they are sent in a single gzip-compressed request. Each indicator must carry metadata.profiles=["s1/security_indicator"] and a unique metadata.uid (used as the join key when an alert references it). After posting, wait at least 3s before posting a SecurityAlert that references these indicator uids (use uam_post_alert or uam_ingest_alert which enforce the sleep). Requires S1_HEC_INGEST_URL in credentials.json.`,
    inputSchema: {
      type: 'object',
      properties: {
        scope: {
          type: 'string',
          description: 'accountId or "accountId:siteId". Mandatory.',
        },
        indicators: {
          type: 'array',
          description: 'Array of OCSF indicator objects. Each must have metadata.uid, metadata.profiles=["s1/security_indicator"], class_uid, and observables[]. file.hashes must be a Fingerprint array [{algorithm_id, algorithm, value}], not a plain dict.',
          items: { type: 'object', additionalProperties: true },
        },
      },
      required: ['scope', 'indicators'],
    },
    async handler({ scope, indicators }) {
      const result = await postIndicators({ scope, indicators });
      return JSON.stringify(result, null, 2);
    },
  },

  // ─── uam_post_alert ───────────────────────────────────────────────────────
  {
    name: 'uam_post_alert',
    description: `POST a single raw OCSF SecurityAlert to /v1/alerts on the SentinelOne HEC ingest host. IMPORTANT: one alert per call. The HEC stitcher silently drops all but one alert in a multi-alert POST body (HTTP 202 still returned), so this tool rejects arrays. To send multiple alerts, loop this call. Always post indicator(s) first via uam_post_indicators and sleep at least 3s before calling this — posting an alert before its indicator uids are registered causes a silent drop. Requires S1_HEC_INGEST_URL in credentials.json.`,
    inputSchema: {
      type: 'object',
      properties: {
        scope: {
          type: 'string',
          description: 'accountId or "accountId:siteId". Mandatory.',
        },
        alert: {
          type: 'object',
          description: 'Single OCSF SecurityAlert object (class_uid 2002). Must have metadata.uid, finding_info.related_events[] each referencing a previously-posted indicator via uid. Each related_events entry needs class_uid, type_uid, category_uid, activity_id, severity_id, time, message, and observables[] with type+typeName.',
          additionalProperties: true,
        },
      },
      required: ['scope', 'alert'],
    },
    async handler({ scope, alert }) {
      const result = await postAlert({ scope, alert });
      return JSON.stringify(result, null, 2);
    },
  },
];
