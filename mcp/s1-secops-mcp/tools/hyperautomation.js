/**
 * Hyperautomation tools: hyperautomation skill
 *
 * Tools:
 *   ha_list_workflows     List Hyperautomation workflows (with scope/state/sort filters)
 *   ha_get_workflow       Get a single workflow by ID (+ optional revisionId)
 *   ha_delete_workflow    Delete (soft, recoverable) a workflow via REST DELETE
 *   ha_import_workflow    Import (create) a workflow from JSON (account- or site-scoped)
 *   ha_export_workflow    Export all workflows as a ZIP archive
 *
 * API root (confirmed via live network capture 2026-05-03):
 *   /web/api/v2.1/hyper-automate/api/v1
 *
 * Single-workflow fetch requires BOTH workflowId AND revisionId:
 *   GET /workflows/single/{workflowId}/{revisionId}
 * The revisionId is workflow.version_id in the list response.
 *
 * Deletion is a soft, recoverable HTTP DELETE (validated 2026-06-13):
 *   DELETE /workflows/{id}?accountIds=<acct>   (or ?siteIds=<site>)
 * The older POST /workflows/archive returns 500 on this tenant: do not use it.
 *
 * Import scope: the public import endpoint accepts ?accountIds=<acct> or
 * ?siteIds=<site>; with no scope it returns a misleading 403 on a scoped tenant.
 */

import { apiGet, apiPost, apiDelete } from '../lib/s1.js';

// Confirmed base path from live network monitor (2026-05-03).
const HA_BASE = '/web/api/v2.1/hyper-automate/api/v1';

// Export/import confirmed on /public path during backtest; not re-captured under /v1.
const HA_PUBLIC = '/web/api/v2.1/hyper-automate/api/public';

export const tools = [
  // ─── ha_list_workflows ────────────────────────────────────────────────────
  {
    name: 'ha_list_workflows',
    description: `List SentinelOne Hyperautomation workflows. Returns workflow ID, version_id (revisionId for ha_get_workflow), name, state, status, trigger types, action types, scope, and timestamps. Supports filtering by siteId, state, and sorting. Use siteIds to scope to a specific site. State values: active, inactive, deactivated, draft. Requires Hyper Automate.view permission.`,
    inputSchema: {
      type: 'object',
      properties: {
        limit: {
          type: 'number',
          description: 'Max workflows per page (default 50, max 200).',
          default: 50,
        },
        skip: {
          type: 'number',
          description: 'Offset for pagination (default 0).',
          default: 0,
        },
        siteIds: {
          type: 'string',
          description: 'Comma-separated site IDs to scope results to (e.g. "<site-id-1>,<site-id-2>"). Omit for all accessible scopes.',
        },
        sortBy: {
          type: 'string',
          description: 'Sort field. Default: updated_at.',
          enum: ['updated_at', 'created_at', 'name'],
          default: 'updated_at',
        },
        sortOrder: {
          type: 'string',
          description: 'Sort direction.',
          enum: ['asc', 'desc'],
          default: 'desc',
        },
      },
      required: [],
    },
    async handler({ limit = 50, skip = 0, siteIds, sortBy = 'updated_at', sortOrder = 'desc' } = {}) {
      const params = {
        limit: Math.min(limit, 200),
        skip,
        sortBy,
        sortOrder,
      };
      if (siteIds) params.siteIds = siteIds;
      const result = await apiGet(`${HA_BASE}/workflows`, params);
      // Summarise for readability: include key fields the LLM needs for follow-up calls.
      const items = (result?.data || []).map(item => ({
        id:          item.id,
        revisionId:  item.workflow?.version_id,     // needed for ha_get_workflow
        name:        item.workflow?.name,
        state:       item.workflow?.state,           // active | inactive | deactivated | draft
        status:      item.workflow?.status,          // idle | running | etc.
        scopeLevel:  item.workflow?.scope_level,     // account | site
        scopeId:     item.workflow?.scope_id,
        siteName:    item.workflow?.site_name,
        createdAt:   item.workflow?.created_at,
        updatedAt:   item.workflow?.updated_at,
        versionCount: item.workflow?.version_count,
        triggerTypes: [...new Set((item.actions || [])
          .filter(a => a.type?.endsWith('_trigger'))
          .map(a => a.type))],
        actionTypes:  [...new Set((item.actions || [])
          .filter(a => !a.type?.endsWith('_trigger'))
          .map(a => a.type))],
        integrationIds: [...new Set((item.actions || [])
          .filter(a => a.integration_id)
          .map(a => a.integration_id))],
      }));
      return JSON.stringify({
        workflows: items,
        totalItems: result?.pagination?.totalItems ?? null,
        skip,
        limit: params.limit,
      }, null, 2);
    },
  },

  // ─── ha_get_workflow ──────────────────────────────────────────────────────
  {
    name: 'ha_get_workflow',
    description: `Get a single Hyperautomation workflow by workflowId and revisionId. The revisionId (= workflow.version_id) is returned by ha_list_workflows; always pass both IDs for a direct fetch. If revisionId is omitted, the tool will scan the first page of workflows to find the current revision, which is slower. Returns the full workflow object including trigger configuration, action steps, integration dependencies, scope, and version metadata.`,
    inputSchema: {
      type: 'object',
      properties: {
        workflowId: {
          type: 'string',
          description: 'Hyperautomation workflow UUID (from ha_list_workflows).',
        },
        revisionId: {
          type: 'string',
          description: 'Workflow version/revision UUID (= workflow.version_id from ha_list_workflows). Provide this to avoid an extra list call.',
        },
      },
      required: ['workflowId'],
    },
    async handler({ workflowId, revisionId }) {
      let resolvedRevisionId = revisionId;

      // If revisionId not supplied, resolve it from the list endpoint.
      if (!resolvedRevisionId) {
        // The list endpoint does not support filtering by workflowId, so we scan
        // up to 200 workflows sorted by updated_at desc (most recently touched first).
        // Confirmed: GET /workflows/single/{id} alone returns 404; revisionId is required.
        const listResult = await apiGet(`${HA_BASE}/workflows`, {
          limit: 200,
          skip: 0,
          sortBy: 'updated_at',
          sortOrder: 'desc',
        });
        const found = (listResult?.data || []).find(item => item.id === workflowId);
        if (!found) {
          return JSON.stringify({
            error: `Workflow ${workflowId} not found in the first 200 results. ` +
              'Provide revisionId directly (from ha_list_workflows) for an exact fetch.',
          });
        }
        resolvedRevisionId = found.workflow?.version_id;
      }

      // Confirmed endpoint: GET /workflows/single/{workflowId}/{revisionId}
      const result = await apiGet(`${HA_BASE}/workflows/single/${workflowId}/${resolvedRevisionId}`);
      return JSON.stringify(result, null, 2);
    },
  },

  // ─── ha_delete_workflow ───────────────────────────────────────────────────
  {
    name: 'ha_delete_workflow',
    description: `Delete one or more Hyperautomation workflows. Uses the REST DELETE /hyper-automate/api/v1/workflows/{id} endpoint (validated 2026-06-13), a soft, recoverable delete (the console offers a "Restore workflow" action), equivalent to clicking Delete in the Hyperautomation UI. Scope the call to where the workflow lives with accountIds (account-scoped workflow) or siteIds (site-scoped); a 404 "Object not found" means the id is not under that scope or is already deleted. Requires Hyper Automate.write permission. NOTE: do NOT use the older POST /workflows/archive path; it returns 500 on this tenant.`,
    inputSchema: {
      type: 'object',
      properties: {
        workflowIds: {
          type: 'array',
          items: { type: 'string' },
          description: 'One or more workflow UUIDs to delete (from ha_list_workflows).',
        },
        accountIds: {
          type: 'string',
          description: 'Account scope for an account-level workflow (e.g. "1234567890123456789"). Provide this OR siteIds.',
        },
        siteIds: {
          type: 'string',
          description: 'Site scope for a site-level workflow. Provide this OR accountIds.',
        },
      },
      required: ['workflowIds'],
    },
    async handler({ workflowIds, accountIds, siteIds } = {}) {
      if (!Array.isArray(workflowIds) || workflowIds.length === 0) {
        return JSON.stringify({ error: 'workflowIds must be a non-empty array of UUIDs.' });
      }
      if (!accountIds && !siteIds) {
        return JSON.stringify({ error: 'Provide accountIds or siteIds to scope the delete to where the workflow lives (a workflow created at a site must be deleted with siteIds; an account-scoped one with accountIds).' });
      }
      const scope = accountIds
        ? `accountIds=${encodeURIComponent(accountIds)}`
        : `siteIds=${encodeURIComponent(siteIds)}`;
      const results = [];
      for (const id of workflowIds) {
        try {
          // DELETE returns 204 No Content on success.
          await apiDelete(`${HA_BASE}/workflows/${encodeURIComponent(id)}?${scope}`);
          results.push({ id, status: 'deleted' });
        } catch (e) {
          results.push({ id, status: 'error', error: e.message });
        }
      }
      return JSON.stringify({ deleted: results }, null, 2);
    },
  },

  // ─── ha_import_workflow ───────────────────────────────────────────────────
  {
    name: 'ha_import_workflow',
    description: `Import a Hyperautomation workflow JSON into the SentinelOne console. Scope the import with accountIds (account-level) or siteIds (site-level); on a scoped tenant a bare import with no scope returns a misleading 403 "Insufficient permissions". The workflow JSON must follow the Hyperautomation schema (use the hyperautomation skill to generate valid JSON). Integration-backed actions (type=http_request with an integration_id) require pre-configured connections in Hyperautomation > Integrations before the workflow will run, and an imported flow lands as a private draft until published (publish endpoint) or activated. Returns the created workflow ID on success. Requires Hyper Automate.write permission.`,
    inputSchema: {
      type: 'object',
      properties: {
        workflowJson: {
          type: 'string',
          description: 'The workflow object as a JSON string: {"name": ..., "description": ..., "actions": [...]}. Pass the BARE workflow, not the {"data": {...}} request envelope; this tool adds the envelope itself. A data-wrapped payload is unwrapped automatically and noted in the response, because the raw-API examples in the hyperautomation skill show the on-the-wire body, which already includes that envelope. Generate the workflow using the hyperautomation skill.',
        },
        accountIds: {
          type: 'string',
          description: 'Account scope for an account-level import (e.g. "1234567890123456789"). Provide this OR siteIds.',
        },
        siteIds: {
          type: 'string',
          description: 'Site scope for a site-level import. Provide this OR accountIds.',
        },
      },
      required: ['workflowJson'],
    },
    async handler({ workflowJson, accountIds, siteIds }) {
      let parsed;
      try {
        parsed = JSON.parse(workflowJson);
      } catch (e) {
        return JSON.stringify({ error: `Invalid JSON: ${e.message}` });
      }
      // Accept the wire-shaped payload as well as the bare workflow.
      //
      // The import endpoint's body is {"data": {...}} and the skill's raw-API examples
      // show it that way, correctly. This tool supplies that envelope, so pasting a
      // documented example sent {"data":{"data":{...}}} and the API answered 422
      // `body.data.name Field required`, which reads like a schema problem in the
      // workflow rather than one extra level of nesting.
      //
      // Unwrap only when it is unambiguous: a `data` object present AND no top-level
      // `name`. A bare workflow legitimately carrying its own `data` key keeps it.
      let unwrapped = false;
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)
          && parsed.data && typeof parsed.data === 'object' && !Array.isArray(parsed.data)
          && parsed.name === undefined) {
        parsed = parsed.data;
        unwrapped = true;
        process.stderr.write(
          '[ha_import_workflow] payload arrived wrapped in {"data": ...}; unwrapped before sending. ' +
          'Pass the bare workflow object to this tool; the "data" envelope is for raw API calls.\n');
      }
      // Public import endpoint. Append the scope query param: account-level imports use
      // ?accountIds=, site-level use ?siteIds=. A bare import (no scope) returns a misleading
      // 403 on a scoped tenant (validated 2026-06-13).
      let qs = '';
      if (accountIds) qs = `?accountIds=${encodeURIComponent(accountIds)}`;
      else if (siteIds) qs = `?siteIds=${encodeURIComponent(siteIds)}`;
      const result = await apiPost(`${HA_PUBLIC}/workflow-import-export/import${qs}`, { data: parsed });
      if (unwrapped) {
        return JSON.stringify({
          importNote: 'The payload arrived wrapped in {"data": ...} and was unwrapped before sending. ' +
                      'That envelope belongs to raw API calls; pass the bare workflow object to this tool.',
          ...result,
        }, null, 2);
      }
      return JSON.stringify(result, null, 2);
    },
  },

  // ─── ha_export_workflow ───────────────────────────────────────────────────
  {
    name: 'ha_export_workflow',
    description: `Export Hyperautomation workflows as a ZIP archive. Returns metadata about the ZIP (size, content-type) plus the first 200 bytes of the base64-encoded content. NOTE: there is no per-workflow filter; the API returns every workflow in scope. Use ha_get_workflow to read a specific workflow's JSON definition instead. Scope with accountIds or siteIds: on a scoped tenant an unscoped call can return a 403 "Insufficient permissions" that is really a scoping problem, the same misleading failure ha_import_workflow documents. Requires Hyper Automate.view permission.`,
    inputSchema: {
      type: 'object',
      properties: {
        accountIds: {
          type: 'string',
          description: 'Account scope for an account-level export (e.g. "1234567890123456789"). Provide this OR siteIds. Omit to use the token default.',
        },
        siteIds: {
          type: 'string',
          description: 'Site scope for a site-level export. Provide this OR accountIds.',
        },
      },
      required: [],
    },
    async handler({ accountIds, siteIds } = {}) {
      // Export path confirmed working during backtest at /public path.
      // GET returns binary ZIP of ALL workflows; POST returns 405.
      // Per-workflow filter is not supported by this API version.
      const { getCreds } = await import('../lib/credentials.js');
      const creds = getCreds();
      const base = creds.S1_CONSOLE_URL.replace(/\/+$/, '');
      const tok  = creds.S1_CONSOLE_API_TOKEN;
      let qs = '';
      if (accountIds) qs = `?accountIds=${encodeURIComponent(accountIds)}`;
      else if (siteIds) qs = `?siteIds=${encodeURIComponent(siteIds)}`;
      const url  = `${base}${HA_PUBLIC}/workflow-import-export/export${qs}`;

      const res = await fetch(url, {
        method: 'GET',
        headers: { Authorization: `ApiToken ${tok}` },
      });
      if (!res.ok) {
        const text = await res.text();
        // A 403 here has two causes and the message does not distinguish them, so name
        // both rather than letting the reader assume it is only about roles.
        const hint = res.status === 403 && !qs
          ? '. Two possible causes: the token lacks Hyper Automate.view, OR this is a' +
            ' scoped tenant and the call needs accountIds/siteIds. Retry with a scope' +
            ' before concluding it is a permission problem.'
          : '';
        throw new Error(`ha_export_workflow → ${res.status}: ${text}${hint}`);
      }
      const buf    = await res.arrayBuffer();
      const base64 = Buffer.from(buf).toString('base64');
      return JSON.stringify({
        note: 'Export returns all workflows as a binary ZIP. Per-workflow filtering is not supported. METADATA ONLY: this tool does not return or persist the ZIP content; use the console UI or a direct API call with file output if you need the archive itself.',
        contentType: res.headers.get('Content-Type') || 'application/zip',
        sizeBytes: buf.byteLength,
        base64Preview: base64.slice(0, 200) + '… [truncated]',
      }, null, 2);
    },
  },
];
