/**
 * UAM Alert Interface tools: push OCSF indicators + alerts INTO UAM
 * via the SentinelOne HEC ingest host (ingest.us1.sentinelone.net).
 *
 * Tools:
 *   uam_ingest_alert      End-to-end: build + POST one SecurityAlert carrying its indicator inline
 *   uam_post_alert        Low-level: POST a single raw OCSF SecurityAlert to /v1/alerts
 *
 * uam_post_indicators WAS REMOVED. Indicators can no longer be ingested on their
 * own: /v1/indicators refuses the console user token and the SDL Log Write Key
 * alike, so no credential can drive it. They are carried inside the alert, in
 * finding_info.related_events[], which is also what the console Indicators tab
 * reads. A tool that can only ever return 403 is worse than no tool, because it
 * reads as a supported path.
 *
 * These tools require S1_HEC_INGEST_URL plus S1_CONSOLE_API_TOKEN. Alert creation
 * and IOCs remain user-token operations; only raw LOG ingest over the event
 * collector uses S1_HEC_TOKEN.
 */

import { ingestAlertInline, postAlert } from '../lib/uam-ingest.js';

export const tools = [

  // ─── uam_ingest_alert ─────────────────────────────────────────────────────
  {
    name: 'uam_ingest_alert',
    description: `Create a synthetic test alert in Unified Alert Management (UAM) via the SentinelOne ingest API.

ONE round-trip: a single SecurityAlert POSTed to /v1/alerts with its indicator embedded in finding_info.related_events[]. No sleep, no stitcher race, no ordering contract. That inline copy is what populates alert.indicators, the field the console Indicators tab renders.

There is no longer a two-call alternative. Posting indicators separately to /v1/indicators is refused for every credential type: the console user token and the SDL Log Write Key both fail, so nothing can drive that endpoint. The old flow also wrote alert.rawIndicators, a separate store the UI never read. The inline parameter is still accepted so existing callers do not break, but it is forced to true.

Returns indicator_uid and alert_uid. The alert surfaces in UAM within 30-60s. Verify with alert(id){indicators{...}}; alertWithRawIndicators stays empty by design. Requires S1_HEC_INGEST_URL and S1_CONSOLE_API_TOKEN.`,
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
        inline: {
          type: 'boolean',
          description: 'Accepted for backward compatibility and ignored: the value is always true. Indicators ride inside the alert because there is no working way to post them separately. Passing false returns a note saying so rather than silently doing something different.',
          default: true,
        },
      },
      required: ['scope'],
    },
    async handler({ scope, title, description, hostname, filename, sha256, inline = true }) {
      const result = await ingestAlertInline({ scope, title, description, hostname, filename, sha256 });
      // Say so rather than quietly substituting a different behaviour. A caller
      // that asked for the two-call flow is working from a stale assumption and
      // needs to know the request was not honoured as written.
      if (inline === false) {
        result.note =
          'inline:false was ignored. Indicators cannot be posted separately any more: ' +
          '/v1/indicators refuses both the console token and the SDL Log Write Key. ' +
          'The indicator was embedded in the alert instead, which is what the ' +
          'console Indicators tab reads.';
      }
      return JSON.stringify(result, null, 2);
    },
  },

  // ─── uam_post_alert ───────────────────────────────────────────────────────
  {
    name: 'uam_post_alert',
    description: `POST a single raw OCSF SecurityAlert to /v1/alerts on the SentinelOne HEC ingest host. IMPORTANT: one alert per call. The HEC stitcher silently drops all but one alert in a multi-alert POST body (HTTP 202 still returned), so this tool rejects arrays. To send multiple alerts, loop this call. Carry the indicator INLINE in finding_info.related_events[] (uid, title, desc, message, time, severity_id, class_uid, type_uid, category_uid, activity_id, and observables[] with type + typeName). That alone populates alert.indicators, which is what the UAM Indicators tab renders; no /v1/indicators call is needed and none should be made, because that endpoint returns 403 "User token not allowed for this endpoint" for a service-user token while /v1/alerts accepts the same credential. Requires S1_HEC_INGEST_URL (environment or keychain, see s1-secops-mcp setup).`,
    inputSchema: {
      type: 'object',
      properties: {
        scope: {
          type: 'string',
          description: 'accountId or "accountId:siteId". Mandatory.',
        },
        alert: {
          type: 'object',
          description: 'Single OCSF SecurityAlert object. class_uid MUST be 99602001 (S1 Security Alert extension class) with type_uid 9960200101; the generic OCSF 2002 is silently dropped by the stitcher even though HEC returns HTTP 202. Needs finding_info.uid and finding_info.title, exactly one resources[] entry (several devices are silently dropped), and finding_info.related_events[] carrying each indicator INLINE (there is no separate indicator POST to reference). Each related_events entry needs class_uid, type_uid, category_uid, activity_id, severity_id, time, message, and observables[] with type + typeName alongside type_id/name/value; title and desc render as the indicator title and description. file.hashes must be an OCSF Fingerprint array, not a dict.',
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
