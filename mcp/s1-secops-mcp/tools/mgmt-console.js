/**
 * Management Console API tools — sentinelone-mgmt-console-api skill
 *
 * Tools:
 *   s1_api_get              Generic GET against S1 Mgmt Console REST API
 *   s1_api_post             Generic POST against S1 Mgmt Console REST API
 *   s1_api_put              Generic PUT against S1 Mgmt Console REST API
 *   s1_api_delete           Generic DELETE against S1 Mgmt Console REST API
 *   s1_api_patch            Generic PATCH against S1 Mgmt Console REST API
 *   purple_ai_alert_summary Get a Purple AI natural-language summary for a specific UAM alert
 *   uam_list_alerts         List/search UAM alerts via GraphQL
 *   uam_get_alert           Get full alert details (notes, history)
 *   uam_add_note            Add analyst note to an alert
 *   uam_set_status          Update alert status (NEW, IN_PROGRESS, RESOLVED)
 *
 * REMOVED (2026-05-03 — confirmed non-functional for API tokens):
 *   purple_ai_query         — requires browser-session teamToken from /sdl/v2/graphql that
 *                             API-token service accounts never obtain. Use Purple MCP instead.
 *   purple_ai_investigate   — same root cause (SERVICE_ERROR). Use Purple MCP instead.
 */

import { apiGet, apiPost, apiPut, apiDelete, apiPatch, purpleAlertSummary, uamListAlerts, uamGetAlert, uamAddNote, uamSetStatus } from '../lib/s1.js';

/**
 * Defensive normalization for GET /cloud-detection/rules calls.
 *
 * Without `isLegacy=false`, the S1 API silently omits queryType="scheduled"
 * PowerQuery rules from the response — no error, no warning, the response
 * just lies by omission. Promoting "empty response" to "tenant has zero
 * scheduled detections" without isLegacy=false is the failure mode this
 * guard exists to prevent. Exported for unit testing.
 */
export function normalizeS1ApiGetParams(path, params) {
  const p = { ...(params || {}) };
  if (
    typeof path === 'string' &&
    /\/cloud-detection\/rules(\/|\?|$)/.test(path) &&
    p.isLegacy === undefined &&
    p.is_legacy === undefined
  ) {
    p.isLegacy = false;
  }
  return p;
}

export const tools = [
  // ─── s1_api_get ───────────────────────────────────────────────────────────
  {
    name: 's1_api_get',
    description: `Generic GET request to the SentinelOne Management Console REST API (v2.1). Use for ALL read operations: listing, counting, and exporting. The S1 API uses GET for every read — listing, counting, and exporting are always GET, never POST. The path should start with /web/api/v2.1/. Returns raw JSON response. For paginated endpoints, use the cursor or skip/limit params. Count examples: path="/web/api/v2.1/agents/count" returns {"data":{"total":N}}; path="/web/api/v2.1/threats" params={"countOnly":true} returns pagination.totalItems. Export example: path="/web/api/v2.1/threats/export" (no extra params). Get agents by IDs: path="/web/api/v2.1/agents" params={"ids":"<id1>,<id2>"} (comma-separated query param).

⚠️ CLOUD-DETECTION RULES — MANDATORY isLegacy=false: For ANY GET on /cloud-detection/rules (listing, name search, queryType filter, scope filter) you MUST pass params.isLegacy=false. Without it the API silently omits queryType="scheduled" PowerQuery rules and returns only events-type rules — there is no error, no warning, the response just lies by omission. This handler auto-injects isLegacy=false when it sees a /cloud-detection/rules path and the caller forgot it, but always pass it explicitly so it shows up in audit logs. Promoting "empty response" to "tenant has zero scheduled detections" without isLegacy=false is the failure mode this guard exists to prevent.`,
    inputSchema: {
      type: 'object',
      properties: {
        path: {
          type: 'string',
          description: 'API path starting with /web/api/v2.1/, e.g. "/web/api/v2.1/agents".',
        },
        params: {
          type: 'object',
          description: 'Query string parameters as key-value pairs, e.g. {"limit": 20, "sortBy": "createdAt"}. For /cloud-detection/rules listings ALWAYS include {"isLegacy": false}; the handler auto-injects it as a safety net but explicit is better.',
          additionalProperties: true,
        },
      },
      required: ['path'],
    },
    async handler({ path, params = {} }) {
      // Safety net: /cloud-detection/rules silently hides scheduled
      // PowerQuery rules unless isLegacy=false is passed.
      const normalized = normalizeS1ApiGetParams(path, params);
      const result = await apiGet(path, normalized);
      return JSON.stringify(result, null, 2);
    },
  },

  // ─── s1_api_post ──────────────────────────────────────────────────────────
  {
    name: 's1_api_post',
    description: `Generic POST request to the SentinelOne Management Console REST API (v2.1). Use ONLY for write and action operations: create IOC, isolate agent, add exclusion, create custom detection rule, trigger RemoteOps, etc. The path should start with /web/api/v2.1/. NEVER use POST for listing, counting, or exporting — all reads are GET. POST to a read path returns HTTP 404 because the path does not exist in the API (e.g. POST /agents/ids, POST /threats/summary, POST /export/threats are all wrong). Before calling, verify the path exists with: python3 scripts/search_endpoints.py "<keyword>". The body is NOT auto-wrapped — pass the complete envelope, e.g. {"data": {...}, "filter": {...}}.`,
    inputSchema: {
      type: 'object',
      properties: {
        path: {
          type: 'string',
          description: 'API path starting with /web/api/v2.1/, e.g. "/web/api/v2.1/threats/mark-as-threats".',
        },
        body: {
          type: 'object',
          description: 'Request body as JSON. For most S1 endpoints use the {"data": {...}, "filter": {...}} envelope. Pass the complete body.',
          additionalProperties: true,
        },
      },
      required: ['path', 'body'],
    },
    async handler({ path, body }) {
      const result = await apiPost(path, body);
      return JSON.stringify(result, null, 2);
    },
  },

  // ─── s1_api_put ───────────────────────────────────────────────────────────
  {
    name: 's1_api_put',
    description: `Generic PUT request to the SentinelOne Management Console REST API (v2.1). Use for full-replacement updates: update agent policies, replace exclusion rules, set system configuration, update firewall/device control rules, update group settings, etc. The path should start with /web/api/v2.1/. The body replaces the resource in full — include all required fields, not just the changed ones. Consult the swagger reference at references/tags/ in the sentinelone-mgmt-console-api skill before calling. Examples: path="/web/api/v2.1/accounts/{id}/policy" body={"data":{...policy fields...}}, path="/web/api/v2.1/system/configuration" body={"data":{...}}.`,
    inputSchema: {
      type: 'object',
      properties: {
        path: {
          type: 'string',
          description: 'API path starting with /web/api/v2.1/, e.g. "/web/api/v2.1/accounts/123/policy".',
        },
        body: {
          type: 'object',
          description: 'Full replacement body as JSON. Most S1 PUT endpoints use {"data": {...}} envelope. Include all required fields for the resource.',
          additionalProperties: true,
        },
      },
      required: ['path', 'body'],
    },
    async handler({ path, body }) {
      const result = await apiPut(path, body);
      return JSON.stringify(result, null, 2);
    },
  },

  // ─── s1_api_delete ────────────────────────────────────────────────────────
  {
    name: 's1_api_delete',
    description: `Generic DELETE request to the SentinelOne Management Console REST API (v2.1). Use for delete operations: delete IOCs (DELETE /web/api/v2.1/threat-intelligence/iocs), delete unified exclusions, delete custom detection rules, delete remote scripts, delete firewall/device control rules, delete tags, etc. The path should start with /web/api/v2.1/. Many S1 DELETE endpoints accept a filter body (e.g. IOCDeleteSchema uses accountId + one other field) — pass it as the body param. Some accept query params only (body can be omitted). Consult the swagger reference at references/tags/ in the sentinelone-mgmt-console-api skill for the exact filter schema before calling. WARNING: deletions are irreversible. Confirm the target ID/filter before executing.`,
    inputSchema: {
      type: 'object',
      properties: {
        path: {
          type: 'string',
          description: 'API path starting with /web/api/v2.1/, e.g. "/web/api/v2.1/threat-intelligence/iocs".',
        },
        body: {
          type: 'object',
          description: 'Optional request body as JSON. Required for filter-based deletes (e.g. IOC delete requires {"filter": {"accountId": "...", "uuids": [...]}}). Omit for ID-in-path deletes.',
          additionalProperties: true,
        },
      },
      required: ['path'],
    },
    async handler({ path, body = {} }) {
      const result = await apiDelete(path, body);
      return JSON.stringify(result, null, 2);
    },
  },

  // ─── s1_api_patch ─────────────────────────────────────────────────────────
  {
    name: 's1_api_patch',
    description: `Generic PATCH request to the SentinelOne Management Console REST API (v2.1). Use for partial updates where only specific fields need to change without replacing the full resource. Less common in the S1 API than PUT, but used by some endpoints for partial config updates and field-level changes. The path should start with /web/api/v2.1/. Pass only the fields to change in the body. Consult the swagger reference at references/tags/ in the sentinelone-mgmt-console-api skill to confirm whether a given endpoint expects PUT (full replace) or PATCH (partial update).`,
    inputSchema: {
      type: 'object',
      properties: {
        path: {
          type: 'string',
          description: 'API path starting with /web/api/v2.1/.',
        },
        body: {
          type: 'object',
          description: 'Partial update body as JSON. Include only the fields to change.',
          additionalProperties: true,
        },
      },
      required: ['path', 'body'],
    },
    async handler({ path, body }) {
      const result = await apiPatch(path, body);
      return JSON.stringify(result, null, 2);
    },
  },

  // ─── purple_ai_alert_summary ──────────────────────────────────────────────
  {
    name: 'purple_ai_alert_summary',
    description: `Get a Purple AI natural-language summary for a specific UAM alert. Calls purpleAlertSummary (operation AlertSummary) at /web/api/v2.1/graphql with the full OCSF alert JSON. This is what populates the "Purple AI" card in the alert detail panel. Synchronous (no polling required). Returns { token, summary }. Use uam_get_alert first to retrieve the raw alert data, then pass its OCSF JSON here.`,
    inputSchema: {
      type: 'object',
      properties: {
        alertJson: {
          type: 'string',
          description: 'The full alert as a JSON string (OCSF format, as returned by uam_get_alert or the GetAlert GraphQL query). Pass the entire alert object serialised to a string.',
        },
      },
      required: ['alertJson'],
    },
    async handler({ alertJson }) {
      const result = await purpleAlertSummary(alertJson);
      return JSON.stringify(result, null, 2);
    },
  },

  // ─── uam_list_alerts ──────────────────────────────────────────────────────
  {
    name: 'uam_list_alerts',
    description: `List UAM (Unified Alert Management) alerts via GraphQL. The PRIMARY alert API in S1 — covers all alert types (EDR, STAR, cloud, identity, third-party). Uses the correct FilterInput schema: dateTimeRange { start, end } for time windows (epoch ms). USE THIS instead of Purple MCP search_alerts for time-scoped searches — the Purple MCP sends date_range (snake_case) which UAM rejects; this tool uses dateTimeRange (the actual schema field). Convenience params (status, severity, startTime, endTime) build FilterInputs automatically. For deeper analysis, follow up with uam_get_alert.`,
    inputSchema: {
      type: 'object',
      properties: {
        first: {
          type: 'number',
          description: 'Number of alerts to fetch (default 20, max 100).',
          default: 20,
        },
        after: {
          type: 'string',
          description: 'Pagination cursor from a prior call\'s pageInfo.endCursor. Omit for first page.',
        },
        viewType: {
          type: 'string',
          description: 'Alert view scope.',
          enum: ['ALL', 'ENDPOINT', 'IDENTITY', 'STAR', 'CUSTOM_ALERTS', 'CLOUD', 'THIRD_PARTY'],
          default: 'ALL',
        },
        status: {
          type: 'string',
          description: 'Filter by status. Uses stringEqual FilterInput. Valid values (confirmed against live tenant): "NEW", "IN_PROGRESS", "RESOLVED". "OPEN" is NOT a valid value and silently returns 0 results. "FALSE_POSITIVE" is an analystVerdict field, not a status — use uam_set_status to set analystVerdict separately.',
        },
        severity: {
          type: 'string',
          description: 'Filter by severity. Uses stringEqual FilterInput. e.g. "CRITICAL", "HIGH", "MEDIUM", "LOW".',
        },
        detectionProduct: {
          type: 'string',
          description: 'Filter by detection product. e.g. "EDR", "STAR", "CLOUD".',
        },
        searchText: {
          type: 'string',
          description: 'Full-text search across alert fields.',
        },
        startTime: {
          type: 'string',
          description: 'Start of time window. ISO-8601 string ("2026-05-03T07:32:00Z") or epoch milliseconds as string. Builds a dateTimeRange FilterInput on detectedAt using { start, end } — the actual UAM schema fields confirmed by introspection.',
        },
        endTime: {
          type: 'string',
          description: 'End of time window. ISO-8601 string or epoch ms. Defaults to now when startTime is provided.',
        },
      },
      required: [],
    },
    async handler({ first = 20, after, viewType = 'ALL', status, severity, detectionProduct, searchText, startTime, endTime } = {}) {
      // Convert string epoch ms to numbers if needed
      const parseTime = (v) => {
        if (!v) return null;
        const n = Number(v);
        return isNaN(n) ? v : n; // if numeric string, use as epoch ms; otherwise pass as ISO
      };
      const result = await uamListAlerts({
        first, after, viewType,
        status: status || null,
        severity: severity || null,
        detectionProduct: detectionProduct || null,
        searchText: searchText || null,
        startTime: parseTime(startTime),
        endTime: parseTime(endTime),
      });
      return JSON.stringify(result, null, 2);
    },
  },

  // ─── uam_get_alert ────────────────────────────────────────────────────────
  {
    name: 'uam_get_alert',
    description: `Get full details for a specific UAM alert including analyst notes. ALWAYS call this before making a verdict — notes may contain MDR verdicts (False Positive / Benign / Resolved) that take precedence over detection engine severity. Returns alert fields plus a notes array from alertNotes query.`,
    inputSchema: {
      type: 'object',
      properties: {
        alertId: {
          type: 'string',
          description: 'The UAM alert ID (string UUID, from uam_list_alerts results).',
        },
      },
      required: ['alertId'],
    },
    async handler({ alertId }) {
      const result = await uamGetAlert(alertId);
      return JSON.stringify(result, null, 2);
    },
  },

  // ─── uam_add_note ─────────────────────────────────────────────────────────
  {
    name: 'uam_add_note',
    description: `Add an analyst note to a UAM alert. Use to document investigation findings, intermediate verdicts, IOC enrichment results, or escalation decisions. Notes are visible to all analysts and MDR. Best practice: include a timestamp-like prefix and cite the evidence inline (e.g. "VT: 12/72 malicious on hash abc123; cross-correlated with FortiGate BLOCK events on same dst IP").`,
    inputSchema: {
      type: 'object',
      properties: {
        alertId: {
          type: 'string',
          description: 'The UAM alert ID.',
        },
        note: {
          type: 'string',
          description: 'Note text. Cite evidence inline. Avoid vague statements — be specific about what queries were run, what IOCs were checked, and what the results were.',
        },
      },
      required: ['alertId', 'note'],
    },
    async handler({ alertId, note }) {
      const result = await uamAddNote(alertId, note);
      return JSON.stringify(result, null, 2);
    },
  },

  // ─── uam_set_status ───────────────────────────────────────────────────────
  {
    name: 'uam_set_status',
    description: `Update the status of a UAM alert. Valid values: NEW (reopen), IN_PROGRESS (actively investigating), RESOLVED (threat contained and remediated). Note: FALSE_POSITIVE is NOT a status value on this API — it is an analystVerdict. To mark an alert as a false positive, add a note explaining why and set status to RESOLVED. Always add a note via uam_add_note before closing an alert.`,
    inputSchema: {
      type: 'object',
      properties: {
        alertId: {
          type: 'string',
          description: 'The UAM alert ID.',
        },
        status: {
          type: 'string',
          description: 'New status. Must be one of the confirmed enum values.',
          enum: ['NEW', 'IN_PROGRESS', 'RESOLVED'],
        },
      },
      required: ['alertId', 'status'],
    },
    async handler({ alertId, status }) {
      const result = await uamSetStatus(alertId, status);
      return JSON.stringify(result, null, 2);
    },
  },
];
