/**
 * Management Console API tools: mgmt-console-api skill
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
 *   uam_set_status          Update alert status (NEW, IN_PROGRESS, RESOLVED), verified
 *   uam_set_verdict         Set the analyst verdict, verified
 *   uam_assign_alert        Assign an alert to a console user, or unassign it, verified
 *   uam_available_actions   What actions this alert allows (isDisabled + reason)
 *
 * The three write tools send the console's exact alertTriggerActions request
 * (HAR 2026-10-07) and re-read the alert to prove the change.
 *
 * REMOVED (2026-05-03: confirmed non-functional for API tokens):
 *   purple_ai_query        : requires browser-session teamToken from /sdl/v2/graphql that
 *                             API-token service accounts never obtain. Use Purple MCP instead.
 *   purple_ai_investigate  : same root cause (SERVICE_ERROR). Use Purple MCP instead.
 */

import { writeOutput, resolveOutputPath } from '../lib/output.js';
import {
  apiGet, apiGetBinary, apiPost, apiPut, apiDelete, apiPatch, purpleAlertSummary,
  uamListAlerts, uamGetAlert, uamAddNote, uamSetStatus, uamSetVerdict, uamAssignAlert, uamAvailableActions, alertScope,
  UAM_STATUSES, UAM_ANALYST_VERDICTS,
} from '../lib/s1.js';

// Optional scope override shared by the UAM write tools. Default: the alert's
// own account, read from the alert, which is what the console sends.
const UAM_WRITE_SCOPE_PROPS = {
  scopeIds: {
    type: 'array',
    items: { type: 'string' },
    description: 'Optional. Scope ids for the write. Default: the alert\'s own account (read from the alert), exactly what the console sends.',
  },
  scopeType: {
    type: 'string',
    enum: ['ACCOUNT', 'SITE', 'GROUP'],
    description: 'Optional. Scope type for scopeIds (default ACCOUNT).',
  },
};
const UAM_WRITE_RESULT_NOTE = 'Sends the same alertTriggerActions request as the console (scope = the alert\'s account, viewType ALL, one action, filter by alert id), then re-reads the alert and fails unless it shows the requested value. Returns {outcome: applied|already_set|scheduled, verified, before, after}. A refusal fails loudly: errorType MISSING_PERMISSION means the role lacks "Unified Alerts > <alert type> Alerts: Manage" (STAR, Endpoint, Identity, Mobile or Generic), and the error names the role and the missing permissions when the token can read its own role. Measured 2026-10-08 with a role lacking every Unified Alerts Manage permission: writes on a native STAR alert succeeded (the role has the legacy STAR Rule Alerts update permissions) and writes on a /v1/alerts-ingested alert failed MISSING_PERMISSION, so ingested alerts most likely need Generic Alerts: Manage.';

/**
 * Defensive normalization for GET /cloud-detection/rules calls.
 *
 * Without `isLegacy=false`, the S1 API silently omits queryType="scheduled"
 * PowerQuery rules from the response: no error, no warning, the response
 * just lies by omission. Promoting "empty response" to "tenant has zero
 * scheduled detections" without isLegacy=false is the failure mode this
 * guard exists to prevent. Exported for unit testing.
 */
export function normalizeS1ApiGetParams(path, params) {
  const p = { ...(params || {}) };
  if (
    typeof path === 'string' &&
    /\/cloud-detection\/rules(\/|\?|$)/.test(path) &&
    // Respect an explicit inline override in the path query string, e.g.
    // /cloud-detection/rules?isLegacy=true; do not append a conflicting
    // isLegacy=false. Mirrors _maybe_inject_islegacy in
    // mgmt-console-api/scripts/s1_client.py.
    !/[?&]is_?legacy=/i.test(path) &&
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
    description: `Generic GET request to the SentinelOne Management Console REST API (v2.1). Use for ALL read operations: listing, counting, and exporting. The S1 API uses GET for every read: listing, counting, and exporting are always GET, never POST. The path should start with /web/api/v2.1/. Returns raw JSON response. For paginated endpoints, use the cursor or skip/limit params. Count examples: path="/web/api/v2.1/agents/count" returns {"data":{"total":N}}; path="/web/api/v2.1/threats" params={"countOnly":true} returns pagination.totalItems. Export example: path="/web/api/v2.1/threats/export" (no extra params). Get agents by IDs: path="/web/api/v2.1/agents" params={"ids":"<id1>,<id2>"} (comma-separated query param).

⚠️ CLOUD-DETECTION RULES, MANDATORY isLegacy=false: For ANY GET on /cloud-detection/rules (listing, name search, queryType filter, scope filter) you MUST pass params.isLegacy=false. Without it the API silently omits queryType="scheduled" PowerQuery rules and returns only events-type rules; there is no error, no warning, the response just lies by omission. This handler auto-injects isLegacy=false when it sees a /cloud-detection/rules path and the caller forgot it, but always pass it explicitly so it shows up in audit logs. Promoting "empty response" to "tenant has zero scheduled detections" without isLegacy=false is the failure mode this guard exists to prevent.`,
    inputSchema: {
      type: 'object',
      properties: {
        path: {
          type: 'string',
          pattern: '^/web/api/v2\\.1/',
          description: 'API path starting with /web/api/v2.1/, e.g. "/web/api/v2.1/agents".',
        },
        params: {
          type: 'object',
          description: 'Query string parameters as key-value pairs, e.g. {"limit": 20, "sortBy": "createdAt"}. For /cloud-detection/rules listings ALWAYS include {"isLegacy": false}; the handler auto-injects it as a safety net but explicit is better.',
          additionalProperties: true,
        },
        outputFile: {
          type: 'string',
          description: 'Optional absolute path on the machine running this MCP server. The full JSON response is written there and only a summary (path, bytes, sha256, item count, pagination) is returned. Must be inside S1_OUTPUT_DIRS (default: home and temp). For binary responses use s1_api_download.',
        },
        overwrite: { type: 'boolean', description: 'Allow outputFile to replace an existing file.' },
      },
      required: ['path'],
    },
    async handler({ path, params = {}, outputFile, overwrite }) {
      // Safety net: /cloud-detection/rules silently hides scheduled
      // PowerQuery rules unless isLegacy=false is passed.
      if (outputFile) resolveOutputPath(outputFile, { overwrite: overwrite === true });
      const normalized = normalizeS1ApiGetParams(path, params);
      const result = await apiGet(path, normalized);
      if (outputFile) {
        const out = writeOutput(outputFile, JSON.stringify(result, null, 2), { overwrite: overwrite === true });
        const items = Array.isArray(result?.data) ? result.data.length : undefined;
        return JSON.stringify({ outputFile: out.path, bytesWritten: out.bytes, sha256: out.sha256, items, pagination: result?.pagination }, null, 2);
      }
      return JSON.stringify(result, null, 2);
    },
  },

  // ─── s1_api_post ──────────────────────────────────────────────────────────
  {
    name: 's1_api_post',
    description: `Generic POST request to the SentinelOne Management Console REST API (v2.1). Use ONLY for write and action operations: create IOC, isolate agent, add exclusion, create custom detection rule, trigger RemoteOps, etc. The path should start with /web/api/v2.1/. NEVER use POST for listing, counting, or exporting; all reads are GET. POST to a read path returns HTTP 404 because the path does not exist in the API (e.g. POST /agents/ids, POST /threats/summary, POST /export/threats are all wrong). Before calling, verify the path exists with: python3 scripts/search_endpoints.py "<keyword>". The body is NOT auto-wrapped; pass the complete envelope, e.g. {"data": {...}, "filter": {...}}. IOC writes (/threat-intelligence/iocs) refuse a token whose user spans several accounts (HTTP 403, code 4030010): run them from an MCP entry whose token was minted at a single account or site (a separate keychain profile selected with S1_PROFILE).`,
    inputSchema: {
      type: 'object',
      properties: {
        path: {
          type: 'string',
          pattern: '^/web/api/v2\\.1/',
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
      // GraphQL returns HTTP 200 with errors[] when the operation failed. With no
      // usable data that is a failure, so surface it as one (isError) rather than
      // a success the caller has to inspect.
      if (result && Array.isArray(result.errors) && result.errors.length) {
        const d = result.data;
        const noData = d === null || d === undefined || (typeof d === 'object' && Object.values(d).every(v => v === null));
        if (noData) throw new Error(`GraphQL errors from ${path}: ${JSON.stringify(result.errors).slice(0, 2000)}`);
      }
      return JSON.stringify(result, null, 2);
    },
  },

  // ─── s1_api_put ───────────────────────────────────────────────────────────
  {
    name: 's1_api_put',
    description: `Generic PUT request to the SentinelOne Management Console REST API (v2.1). Use for full-replacement updates: update agent policies, replace exclusion rules, set system configuration, update firewall/device control rules, update group settings, etc. The path should start with /web/api/v2.1/. The body replaces the resource in full; include all required fields, not just the changed ones. Consult the swagger reference at references/tags/ in the mgmt-console-api skill before calling. Examples: path="/web/api/v2.1/accounts/{id}/policy" body={"data":{...policy fields...}}, path="/web/api/v2.1/system/configuration" body={"data":{...}}.`,
    inputSchema: {
      type: 'object',
      properties: {
        path: {
          type: 'string',
          pattern: '^/web/api/v2\\.1/',
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
    description: `Generic DELETE request to the SentinelOne Management Console REST API (v2.1). Use for delete operations: delete IOCs (DELETE /web/api/v2.1/threat-intelligence/iocs), delete unified exclusions, delete custom detection rules, delete remote scripts, delete firewall/device control rules, delete tags, etc. The path should start with /web/api/v2.1/. Many S1 DELETE endpoints accept a filter body (e.g. IOCDeleteSchema uses accountId + one other field); pass it as the body param. Some accept query params only (body can be omitted). Consult the swagger reference at references/tags/ in the mgmt-console-api skill for the exact filter schema before calling. WARNING: deletions are irreversible. Confirm the target ID/filter before executing.`,
    inputSchema: {
      type: 'object',
      properties: {
        path: {
          type: 'string',
          pattern: '^/web/api/v2\\.1/',
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
    description: `Generic PATCH request to the SentinelOne Management Console REST API (v2.1). Use for partial updates where only specific fields need to change without replacing the full resource. Less common in the S1 API than PUT, but used by some endpoints for partial config updates and field-level changes. The path should start with /web/api/v2.1/. Pass only the fields to change in the body. Consult the swagger reference at references/tags/ in the mgmt-console-api skill to confirm whether a given endpoint expects PUT (full replace) or PATCH (partial update).`,
    inputSchema: {
      type: 'object',
      properties: {
        path: {
          type: 'string',
          pattern: '^/web/api/v2\\.1/',
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

  // ─── s1_api_download ──────────────────────────────────────────────────────
  {
    name: 's1_api_download',
    description: `Download a BINARY response from the Management Console REST API (v2.1) and save it to a file on the machine running this MCP server. Use for anything the JSON tools cannot carry: RemoteOps fetched files (/web/api/v2.1/remote-scripts/fetch-files), threat file fetch (/web/api/v2.1/threats/fetch-file), exports that return CSV or ZIP, download-from-cloud links. Returns path, size, sha256 and content type only; the bytes never enter the context window. GET only, same origin pinning as s1_api_get.`,
    inputSchema: {
      type: 'object',
      properties: {
        path: {
          type: 'string',
          pattern: '^/web/api/v2\\.1/',
          description: 'API path starting with /web/api/v2.1/.',
        },
        params: {
          type: 'object',
          description: 'Query string parameters.',
          additionalProperties: true,
        },
        outputFile: {
          type: 'string',
          description: 'Absolute path to write. Must be inside S1_OUTPUT_DIRS (default: home and temp). Created mode 0600.',
        },
        overwrite: { type: 'boolean', description: 'Allow replacing an existing file.' },
      },
      required: ['path', 'outputFile'],
    },
    async handler({ path, params = {}, outputFile, overwrite }) {
      resolveOutputPath(outputFile, { overwrite: overwrite === true });
      const r = await apiGetBinary(path, params);
      const out = writeOutput(outputFile, r.buffer, { overwrite: overwrite === true });
      return JSON.stringify({
        outputFile: out.path, bytesWritten: out.bytes, sha256: out.sha256,
        contentType: r.contentType, contentDisposition: r.contentDisposition || undefined,
      }, null, 2);
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
    description: `List UAM (Unified Alert Management) alerts via GraphQL. The PRIMARY alert API in S1, covers all alert types (EDR, STAR, cloud, identity, third-party). Uses the correct FilterInput schema: dateTimeRange { start, end } for time windows (epoch ms). USE THIS instead of Purple MCP search_alerts for time-scoped searches; the Purple MCP sends date_range (snake_case) which UAM rejects; this tool uses dateTimeRange (the actual schema field). Convenience params (status, severity, startTime, endTime) build FilterInputs automatically. SCOPE: with a global or multi-account token an unscoped listing spans every account; pass scopeIds (and scopeType SITE for sites) for the account or site the user named. Each alert carries accountId and siteId. For deeper analysis, follow up with uam_get_alert.`,
    inputSchema: {
      type: 'object',
      properties: {
        first: {
          type: 'number',
          description: 'Number of alerts to fetch per page (default 20). Not enforced client-side; the UAM GraphQL backend accepts larger pages (live-verified 2026-07-29: first=500 returned 500 with hasNextPage=true). Use the returned pageInfo.endCursor with `after` to paginate rather than requesting an unbounded page.',
          default: 20,
        },
        after: {
          type: 'string',
          description: 'Pagination cursor from a prior call\'s pageInfo.endCursor. Omit for first page.',
        },
        viewType: {
          type: 'string',
          description: 'Alert view scope.',
          enum: ['ALL', 'ENDPOINT', 'IDENTITY', 'STAR', 'CUSTOM_ALERTS', 'CLOUD', 'THIRD_PARTY', 'DLP'],
          default: 'ALL',
        },
        status: {
          type: 'string',
          description: 'Filter by status. Uses stringEqual FilterInput. Valid values (confirmed against live tenant): "NEW", "IN_PROGRESS", "RESOLVED". "OPEN" is NOT a valid value and silently returns 0 results. "FALSE_POSITIVE" is an analystVerdict field, not a status; uam_set_status cannot set it. Set the analyst verdict with uam_set_verdict.',
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
          description: 'Match against the alert name (UAM fieldId alertName). The API rejects an all-fields search.',
        },
        startTime: {
          type: 'string',
          description: 'Start of time window. ISO-8601 string ("2026-05-03T07:32:00Z") or epoch milliseconds as string. Builds a dateTimeRange FilterInput on detectedAt using { start, end }, the actual UAM schema fields confirmed by introspection.',
        },
        endTime: {
          type: 'string',
          description: 'End of time window. ISO-8601 string or epoch ms. Defaults to now when startTime is provided.',
        },
        scopeIds: {
          type: 'array',
          items: { type: 'string' },
          description: 'Optional. Account (or site) ids to list alerts for. A global or multi-account token lists alerts from EVERY account it can reach when this is omitted; pass the account the user named. Each alert in the response carries accountId and siteId.',
        },
        scopeType: {
          type: 'string',
          enum: ['ACCOUNT', 'SITE'],
          description: 'Optional. Scope type for scopeIds (default ACCOUNT).',
        },
      },
      required: [],
    },
    async handler({ first = 20, after, viewType = 'ALL', status, severity, detectionProduct, searchText, startTime, endTime, scopeIds, scopeType } = {}) {
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
        scope: scopeIds?.length ? { scopeIds: scopeIds.map(String), scopeType: scopeType || 'ACCOUNT' } : null,
      });
      return JSON.stringify(result, null, 2);
    },
  },

  // ─── uam_get_alert ────────────────────────────────────────────────────────
  {
    name: 'uam_get_alert',
    description: `Get full details for a specific UAM alert including analyst notes. ALWAYS call this before making a verdict; notes may contain MDR verdicts (False Positive / Benign / Resolved) that take precedence over detection engine severity. Returns alert fields plus a notes array from alertNotes query.`,
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
          description: 'Note text. Cite evidence inline. Avoid vague statements, be specific about what queries were run, what IOCs were checked, and what the results were.',
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
    description: `Update the status of a UAM alert. Valid values: NEW (reopen), IN_PROGRESS (actively investigating), RESOLVED (closed). FALSE_POSITIVE is NOT a status; it is an analyst verdict, set with uam_set_verdict. Always add a note via uam_add_note before closing an alert. ${UAM_WRITE_RESULT_NOTE}`,
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
          enum: [...UAM_STATUSES],
        },
        ...UAM_WRITE_SCOPE_PROPS,
      },
      required: ['alertId', 'status'],
    },
    async handler({ alertId, status, scopeIds, scopeType }) {
      const result = await uamSetStatus(alertId, status, { scopeIds, scopeType });
      return JSON.stringify(result, null, 2);
    },
  },

  // ─── uam_set_verdict ──────────────────────────────────────────────────────
  {
    name: 'uam_set_verdict',
    description: `Set the analyst verdict of a UAM alert (action S1/alert/analystVerdictUpdate). Values are the console's sub-verdicts, e.g. TRUE_POSITIVE_MALWARE, TRUE_POSITIVE_BENIGN, FALSE_POSITIVE_BENIGN, FALSE_POSITIVE_USER_ERROR, or UNDEFINED to clear. "TRUE_POSITIVE", "FALSE_POSITIVE" and "SUSPICIOUS" alone are NOT valid values and are refused before any request. Status is separate: closing an alert also needs uam_set_status RESOLVED. Record the evidence with uam_add_note first. ${UAM_WRITE_RESULT_NOTE}`,
    inputSchema: {
      type: 'object',
      properties: {
        alertId: {
          type: 'string',
          description: 'The UAM alert ID.',
        },
        verdict: {
          type: 'string',
          description: 'Analyst verdict (enum AnalystVerdict, introspected live).',
          enum: [...UAM_ANALYST_VERDICTS],
        },
        ...UAM_WRITE_SCOPE_PROPS,
      },
      required: ['alertId', 'verdict'],
    },
    async handler({ alertId, verdict, scopeIds, scopeType }) {
      const result = await uamSetVerdict(alertId, verdict, { scopeIds, scopeType });
      return JSON.stringify(result, null, 2);
    },
  },

  // ─── uam_assign_alert ─────────────────────────────────────────────────────
  {
    name: 'uam_assign_alert',
    description: `Assign a UAM alert to a console user, or unassign it (action S1/alert/assignUser). Pass exactly one of: userId (numeric console user id, what the console sends), email (resolved to one user via GET /web/api/v2.1/users?email=), or unassign: true (sends value null). A service-user token can assign the alert to a human console user. ${UAM_WRITE_RESULT_NOTE}`,
    inputSchema: {
      type: 'object',
      properties: {
        alertId: {
          type: 'string',
          description: 'The UAM alert ID.',
        },
        userId: {
          type: 'string',
          pattern: '^[0-9]{1,20}$',
          description: 'Numeric console user id (from GET /web/api/v2.1/users or an alert\'s assignee.userId).',
        },
        email: {
          type: 'string',
          description: 'Email of the console user; must match exactly one user visible to the token.',
        },
        unassign: {
          type: 'boolean',
          description: 'true to remove the current assignee.',
        },
        ...UAM_WRITE_SCOPE_PROPS,
      },
      required: ['alertId'],
    },
    async handler({ alertId, userId, email, unassign, scopeIds, scopeType }) {
      const result = await uamAssignAlert(alertId, { userId, email, unassign: unassign === true, scopeIds, scopeType });
      return JSON.stringify(result, null, 2);
    },
  },

  // ─── uam_available_actions ────────────────────────────────────────────────
  {
    name: 'uam_available_actions',
    description: `Ask the API which actions can be triggered on a UAM alert, with isDisabled and disabledReason per action. This is the authoritative capability answer and the ONLY correct way to explain a refused write. Availability is filtered by the caller's permissions AND the alert type: one service-user token is offered S1/alert/statusUpdate on a native STAR alert and not on an alert ingested via the UAM Alert Interface (/v1/alerts), where only S1/alert/addNote and S1/alert/eventSearch are listed, while a console user session performs the identical mutation on either. So an action missing here means this identity lacks the permission for this alert type, not that it is impossible: check the service user's UAM permissions. Call this before concluding anything about permissions, and before a bulk write you cannot undo. Availability is also scope-sensitive: the S1/incident/* actions report INCIDENT_ACTIONS_ONLY_AVAILABLE_FROM_SITE_VIEW under ACCOUNT scope and are enabled under SITE, so pass scopeIds/scopeType when you care about a site-scoped action. Read-only.`,
    inputSchema: {
      type: 'object',
      properties: {
        alertId: {
          type: 'string',
          description: 'The UAM alert ID to check.',
        },
        scopeIds: {
          type: 'array',
          items: { type: 'string' },
          description: 'Optional. Account or site ids for the scope. Defaults to the alert\'s own account (read from the alert, as the writes do), or every account visible to the token when the alert carries none.',
        },
        scopeType: {
          type: 'string',
          description: 'Optional. Scope type for scopeIds. Availability differs between ACCOUNT and SITE for some actions. GLOBAL is not a ScopeType (the API rejects it).',
          enum: ['ACCOUNT', 'SITE', 'GROUP'],
        },
      },
      required: ['alertId'],
    },
    async handler({ alertId, scopeIds, scopeType }) {
      const scope = scopeIds?.length
        ? { scopeIds, scopeType: scopeType || 'ACCOUNT' }
        : await alertScope(alertId);
      const actions = await uamAvailableActions(alertId, scope);
      return JSON.stringify(
        {
          alertId,
          scope: scopeIds?.length ? scope : { ...scope, source: scope.scopeIds.length === 1 ? 'the alert\'s account' : 'every account visible to the token' },
          enabled: actions.filter((a) => !a.isDisabled).map((a) => a.id),
          disabled: actions
            .filter((a) => a.isDisabled)
            .map((a) => ({ id: a.id, reason: a.disabledReason })),
          actions,
        },
        null,
        2
      );
    },
  },
];
