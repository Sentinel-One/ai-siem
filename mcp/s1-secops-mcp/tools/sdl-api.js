/**
 * SDL API tools: sdl-api, sdl-dashboard, sdl-log-parser skills
 *
 * Config-file tools (raw SDL config layer):
 *   sdl_list_files            List every config file visible at a scope
 *   sdl_get_file              Get file content and version, by path or udoId
 *   sdl_put_file              Deploy or update a config file (optimistic locking)
 *   sdl_delete_file           Delete a config file
 *
 * Dashboard lifecycle tools (dashboardsV2, the console's own surface):
 *   sdl_list_dashboards       List dashboards with owner and sharing metadata
 *   sdl_get_dashboard         Read one dashboard including its tabs
 *   sdl_create_dashboard      Create from a full dashboard-JSON config
 *   sdl_share_dashboard       Share to a site / account / global scope
 *   sdl_save_dashboard_layout Replace the panel layout of one tab
 *   sdl_delete_dashboard      Delete a dashboard
 *
 * Ingest:
 *   hec_ingest                Ingest raw logs/events into SDL via HEC
 *
 * Everything except hec_ingest runs on `POST /sdl/v2/graphql`. The legacy REST
 * `/sdl/api/*File` endpoints are NOT used: they silently omit every
 * udoId-addressed dashboard (1,914 vs 2,264 files on a live tenant) and return
 * `success/noSuchFile` for any of them.
 */

import {
  configFiles, configFile, putConfigFile, deleteConfigFile,
  listDashboards, getDashboard, createDashboard, shareDashboard,
  saveDashboardLayout, deleteDashboard,
} from '../lib/sdl.js';
import { hecIngest } from '../lib/hec.js';

const UDOID_NOTE =
  'Dashboards are addressed by udoId, everything else by path. The console shows a dashboard as ' +
  '"/dashboards/id/<udoId>/<name>" in its Configuration Files grid; that display string is NOT a path, ' +
  'the number in it is the udoId and the real path is "/dashboards/<name>". ' +
  'udoId assignment is by namespace: only /dashboards/ files have one, /lookups/, /datatables/, ' +
  '/logParsers/ and /automaticLookups are all name-addressed with udoId null.';

const SCOPE_NOTE =
  'SDL config objects are filed against the scope of the request and reads are FILTERED by it, so this ' +
  'argument changes which objects exist as far as the caller can tell. Verified live: the same listing ' +
  'returned 113 files at account scope and 4 at a site scope. Format "<accountId>" for account scope or ' +
  '"<accountId>:<siteId>" for site scope; ids come from GET /web/api/v2.1/accounts and /sites. Omit to ' +
  'use S1_SCOPE from credentials.json, or the token default when that is unset. If an object you expect ' +
  'is missing, re-check at the scope it was created in before concluding it is gone.';

/** Shared scope property for every tool schema. */
const scopeProp = {
  type: 'string',
  description: `Optional S1-Scope, e.g. "2046190533732727925:2547662415802335157". ${SCOPE_NOTE}`,
};

export const tools = [
  // ─── sdl_list_files ───────────────────────────────────────────────────────
  {
    name: 'sdl_list_files',
    description: `List every configuration file visible at the given scope via the GraphQL configFiles query: /logParsers/, /dashboards/, /alerts/, /lookups/, /datatables/, /automaticLookups. Returns {udoId, name, readOnly, version} per file. ${UDOID_NOTE} Use this to discover what is deployed, and to resolve a dashboard name to the udoId that sdl_get_file/sdl_put_file need. THIS LISTING IS SCOPE-FILTERED: ${SCOPE_NOTE} Never conclude a file is absent from a listing produced any other way; the legacy REST listing omits ~350 dashboards.`,
    inputSchema: {
      type: 'object',
      properties: {
        pathPrefix: {
          type: 'string',
          description: 'Optional filter, e.g. "/dashboards/" or "/logParsers/". Applied client-side to the full listing.',
        },
        scope: scopeProp,
      },
      required: [],
    },
    async handler({ pathPrefix, scope } = {}) {
      let files = await configFiles({ scope });
      if (pathPrefix) files = files.filter(f => (f.name || '').startsWith(pathPrefix));
      return JSON.stringify({ count: files.length, scope: scope ?? null, files }, null, 2);
    },
  },

  // ─── sdl_get_file ─────────────────────────────────────────────────────────
  {
    name: 'sdl_get_file',
    description: `Get the content and current version of a SDL configuration file. Pass "path" for name-addressed files (parsers, lookups, datatables, alerts, /automaticLookups) or "udoId" for a dashboard. ${UDOID_NOTE} Read this before sdl_put_file and pass the returned version as expectedVersion so the write is optimistically locked. If a lookup by path returns nothing, the file is probably udoId-addressed: list it with sdl_list_files and retry with its udoId rather than reporting it as missing.`,
    inputSchema: {
      type: 'object',
      properties: {
        path: {
          type: 'string',
          description: 'Full SDL config path, e.g. "/logParsers/FortiGate" or "/lookups/assets.csv".',
        },
        udoId: {
          type: 'string',
          description: 'Dashboard udoId, e.g. "3559330396332032". Get it from sdl_list_files. Required for /dashboards/ files.',
        },
        scope: scopeProp,
      },
      required: [],
    },
    async handler({ path, udoId, scope }) {
      const result = await configFile({ name: path, udoId, scope });
      if (!result) {
        return JSON.stringify({
          status: 'notFound',
          scope: scope ?? null,
          hint: 'No file at that address AT THIS SCOPE. Two things to check: (1) if this is a dashboard it is udoId-addressed, run sdl_list_files with pathPrefix "/dashboards/" and retry with its udoId; (2) the file may exist at a different scope, a site-scoped dashboard is invisible from account scope, so retry with the scope it was created in.',
        }, null, 2);
      }
      return JSON.stringify(result, null, 2);
    },
  },

  // ─── sdl_put_file ─────────────────────────────────────────────────────────
  {
    name: 'sdl_put_file',
    description: `Create or update a SDL configuration file. To create, pass "path". To update, pass the file's current address plus expectedVersion from sdl_get_file. ${UDOID_NOTE} CRITICAL for dashboards: update by udoId, never by path. A path-addressed write to /dashboards/ does not update, it creates a duplicate file sharing the name; that is how one tenant accumulated 152 copies of "/dashboards/AI Usage". This tool refuses path-addressed writes to /dashboards/ on an existing file for that reason. Name-addressed writes to every other namespace update in place normally.`,
    inputSchema: {
      type: 'object',
      properties: {
        path: {
          type: 'string',
          description: 'Full SDL config path, e.g. "/logParsers/MyParser". Use for creates, and for updates to non-dashboard files.',
        },
        udoId: {
          type: 'string',
          description: 'Dashboard udoId. REQUIRED to update an existing dashboard; a path-addressed dashboard write duplicates instead of updating.',
        },
        content: {
          type: 'string',
          description: 'File content as a string. For dashboards: valid dashboard JSON. For parsers: augmented-JSON parser definition. For lookups: CSV or JSON.',
        },
        expectedVersion: {
          type: 'number',
          description: 'Current file version from sdl_get_file, for optimistic locking. Enforced on BOTH address forms, path and udoId: a stale value is rejected and nothing is written. Omit only when creating a new file.',
        },
        scope: scopeProp,
      },
      required: ['content'],
    },
    async handler({ path, udoId, content, expectedVersion, scope }) {
      const result = await putConfigFile({ name: path, udoId, content, expectedVersion, scope });
      return JSON.stringify(result, null, 2);
    },
  },

  // ─── sdl_delete_file ──────────────────────────────────────────────────────
  {
    name: 'sdl_delete_file',
    description: `Delete a SDL configuration file (parser, dashboard, alert, lookup, datatable). Deletion is permanent. Pass "udoId" for dashboards, "path" for everything else. ${UDOID_NOTE} Always read the file with sdl_get_file first to confirm the address and to get expectedVersion.`,
    inputSchema: {
      type: 'object',
      properties: {
        path: {
          type: 'string',
          description: 'Full SDL config path to delete (non-dashboard files).',
        },
        udoId: {
          type: 'string',
          description: 'Dashboard udoId to delete. Required for /dashboards/ files.',
        },
        expectedVersion: {
          type: 'number',
          description: 'Current file version for optimistic locking (from sdl_get_file). Strongly recommended.',
        },
        scope: scopeProp,
      },
      required: [],
    },
    async handler({ path, udoId, expectedVersion, scope }) {
      const result = await deleteConfigFile({ name: path, udoId, expectedVersion, scope });
      return JSON.stringify(result, null, 2);
    },
  },

  // ─── sdl_list_dashboards ──────────────────────────────────────────────────
  {
    name: 'sdl_list_dashboards',
    description: `List dashboards visible at the given scope via the GraphQL dashboardsV2 query, returning {id, name, description, configType, access:{public, users, owner}} each. Prefer this over sdl_list_files when you need the owner or the sharing state; use sdl_list_files when you need the config-file version for optimistic locking. The "id" here IS the "udoId" in sdl_list_files, they address the same object. ${SCOPE_NOTE}`,
    inputSchema: {
      type: 'object',
      properties: { scope: scopeProp },
      required: [],
    },
    async handler({ scope } = {}) {
      const dashboards = await listDashboards({ scope });
      return JSON.stringify({ count: dashboards.length, scope: scope ?? null, dashboards }, null, 2);
    },
  },

  // ─── sdl_get_dashboard ────────────────────────────────────────────────────
  {
    name: 'sdl_get_dashboard',
    description: `Read one dashboard including its tabs, description, duration, sharing and authorship, via getDashboardV2. Address by id (preferred) or name. NOTE tabs[].graphs, .parameters, .filters and .options come back as JSON STRINGS, not objects; parse each one to inspect panels. The "version" field here is a display string and is usually empty; it is NOT the optimistic-locking token, use sdl_get_file for the numeric version. Returns status notFound when the dashboard does not exist at this scope. ${SCOPE_NOTE}`,
    inputSchema: {
      type: 'object',
      properties: {
        id: { type: 'string', description: 'Dashboard id, e.g. "6994516145065984". Same value as udoId in sdl_list_files.' },
        name: { type: 'string', description: 'Dashboard display name, e.g. "Metacortex Site". Use when you do not have the id; ambiguous if duplicates exist.' },
        scope: scopeProp,
      },
      required: [],
    },
    async handler({ id, name, scope }) {
      const result = await getDashboard({ id, name, scope });
      if (!result) {
        return JSON.stringify({
          status: 'notFound',
          scope: scope ?? null,
          hint: 'No dashboard at that address AT THIS SCOPE. A site-scoped dashboard is invisible from account scope and vice versa; retry with the scope it was created in, or run sdl_list_dashboards at that scope to confirm.',
        }, null, 2);
      }
      return JSON.stringify(result, null, 2);
    },
  },

  // ─── sdl_create_dashboard ─────────────────────────────────────────────────
  {
    name: 'sdl_create_dashboard',
    description: `Create a dashboard from a complete dashboard-JSON document via createDashboardV2, filed at the given scope. THIS IS THE PREFERRED WAY TO DEPLOY A NEW DASHBOARD: it accepts the whole document (configType, duration, description, tabs[]) in one call, unlike sdl_put_file which writes the raw config file. It also avoids the console's stub-append trap, where creating an empty dashboard in the UI and pasting JSON after the existing "{graphs: []}" stub yields "Content is invalid json / Additional text after JSON object" and leaves an empty dashboard behind. To deploy to a SITE, either pass scope as "<accountId>:<siteId>" here, or create at account scope and then use sdl_share_dashboard. Duplicate names ARE allowed (the console itself makes "<name> - Copy" siblings); set failIfNameExists to refuse instead. Names reject punctuation with only "Invalid name" as the error: accepted are letters, digits, space, hyphen, underscore, dot and slash; rejected are ( ) [ ] { } : , & ' % #. ${SCOPE_NOTE}`,
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'Dashboard display name, e.g. "Metacortex Site Replica".' },
        config: { type: 'string', description: 'The full dashboard JSON document as a string: {"configType":"TABBED","duration":"24h","description":"...","tabs":[...]}. Validated as JSON before the mutation is sent.' },
        isPublic: { type: 'boolean', default: true, description: 'Share with all users in scope (the console\'s "Public" badge). DEFAULTS TO TRUE, unlike the raw API. access.owner is the calling identity, so with a service-account token a private dashboard is readable via API but INVISIBLE in the console to the human operator at any scope, which looks exactly like a failed deploy. Set false only if the dashboard should stay private to the service account.' },
        failIfNameExists: { type: 'boolean', description: 'Refuse if a dashboard of this name already exists at this scope. Default false, which permits siblings. Costs one extra listing call.' },
        scope: scopeProp,
      },
      required: ['name', 'config'],
    },
    async handler({ name, config, isPublic, failIfNameExists, scope }) {
      const result = await createDashboard({ name, config, isPublic, failIfNameExists, scope });
      return JSON.stringify({ status: 'created', scope: scope ?? null, dashboard: result }, null, 2);
    },
  },

  // ─── sdl_share_dashboard ──────────────────────────────────────────────────
  {
    name: 'sdl_share_dashboard',
    description: 'Share (or unshare) a dashboard to one or more scopes and/or users via the shareResource mutation. THIS IS THE ONLY SDL OPERATION THAT TAKES AN EXPLICIT SCOPE TARGET; every other operation infers scope from the request header. Use it to push an account-scoped dashboard down to a specific site without recreating it, which is how site-level deployment is done when the calling token sits at account scope. Note the two different scope arguments: the "scopes" array is WHERE THE DASHBOARD GOES, while "scope" is the header for this call, i.e. where you are standing when you share.',
    inputSchema: {
      type: 'object',
      properties: {
        id: { type: 'string', description: 'Dashboard id from sdl_list_dashboards or sdl_create_dashboard.' },
        scopes: {
          type: 'array',
          description: 'Share targets. Each entry is {scopeType, scopeId, operation}: scopeType is "site" | "account" | "global"; scopeId is the numeric id from GET /web/api/v2.1/sites or /accounts (not required for global); operation is "ADD" or "REMOVE" (default ADD). Example: [{"scopeType":"site","scopeId":"2547662415802335157","operation":"ADD"}].',
          items: {
            type: 'object',
            properties: {
              scopeType: { type: 'string', enum: ['site', 'account', 'global'] },
              scopeId: { type: 'string' },
              operation: { type: 'string', enum: ['ADD', 'REMOVE'] },
            },
            required: ['scopeType'],
          },
        },
        users: { type: 'array', description: 'Optional user share targets, same command shape as the console sends. Pass [] when sharing only to scopes.', items: { type: 'object' } },
        scope: scopeProp,
      },
      required: ['id'],
    },
    async handler({ id, scopes, users, scope }) {
      const result = await shareDashboard({ id, scopes, users, scope });
      return JSON.stringify(result, null, 2);
    },
  },

  // ─── sdl_save_dashboard_layout ────────────────────────────────────────────
  {
    name: 'sdl_save_dashboard_layout',
    description: 'Replace the panel layout of ONE tab of a dashboard via saveDashboardLayout. Use for incremental panel edits (repositioning, adding or removing a panel on a single tab); use sdl_create_dashboard for a whole new document, or sdl_put_file with expectedVersion to rewrite an existing dashboard\'s full config. The graphs argument is a JSON string shaped {"graphs":[...]} including the wrapper key, even though the response echoes a bare array.',
    inputSchema: {
      type: 'object',
      properties: {
        id: { type: 'string', description: 'Dashboard id.' },
        name: { type: 'string', description: 'Dashboard display name, as an alternative to id.' },
        tabName: { type: 'string', description: 'Exact tab name to replace, e.g. "2. Metacortex operations". Must match an existing tab.' },
        graphs: { type: 'string', description: 'JSON string shaped {"graphs":[{panel},...]}. Validated before sending; the top-level "graphs" array is required.' },
        options: { type: 'string', description: 'Optional tab options as a JSON string, e.g. "{}".' },
        scope: scopeProp,
      },
      required: ['graphs', 'tabName'],
    },
    async handler({ id, name, tabName, graphs, options, scope }) {
      const result = await saveDashboardLayout({ id, name, tabName, graphs, options, scope });
      return JSON.stringify(result, null, 2);
    },
  },

  // ─── sdl_delete_dashboard ─────────────────────────────────────────────────
  {
    name: 'sdl_delete_dashboard',
    description: `Delete a dashboard by id or name via the deleteDashboard mutation. Deletion is permanent. The mutation returns a bare boolean, so this tool re-reads the dashboard afterwards and only reports success once it is confirmed gone. Equivalent to sdl_delete_file by udoId; prefer this one when you are working through the dashboard surface. ${SCOPE_NOTE}`,
    inputSchema: {
      type: 'object',
      properties: {
        id: { type: 'string', description: 'Dashboard id to delete.' },
        name: { type: 'string', description: 'Dashboard name to delete, as an alternative to id. Ambiguous if duplicates exist; prefer id.' },
        scope: scopeProp,
      },
      required: [],
    },
    async handler({ id, name, scope }) {
      const result = await deleteDashboard({ id, name, scope });
      return JSON.stringify(result, null, 2);
    },
  },

  // ─── hec_ingest ─────────────────────────────────────────────────────────────
  {
    name: 'hec_ingest',
    description: `Ingest raw logs/events into the SentinelOne AI SIEM Singularity Data Lake via the HEC (HTTP Event Collector) endpoint. Applies a named parser via ?sourcetype and lands the data in the Data Lake for Event Search, PowerQuery, and detection rules. Replaces the removed sdl_upload_logs. NOT UAM ingest (the uam_* tools post OCSF indicators/alerts to /v1/* on the same host but a separate API). Per S-26.1 HEC docs: POST {S1_HEC_INGEST_URL}/services/collector/raw, Authorization: Bearer <S1_CONSOLE_API_TOKEN>, query params become fields, gzip recommended, 10 MB uncompressed per request.`,
    inputSchema: {
      type: 'object',
      properties: {
        logContent: { type: 'string', description: 'Raw log text. For the /raw endpoint, newline-separated lines become separate events.' },
        parser: { type: 'string', description: 'Parser name, sent as the ?sourcetype= query param. Omit to skip parsing (structured JSON on /event auto-parses).' },
        fields: { type: 'object', description: 'Extra key-value pairs sent as query params; each key becomes a field in the UI, e.g. {"server":"dev","region":"ap1"}. Avoid HEC-reserved names (event, time, host, source, sourcetype, index, fields) as keys; use the parser arg to set sourcetype.' },
        scope: { type: 'string', description: 'REQUIRED. accountId or "accountId:siteId" sent as the S1-Scope header; HEC rejects requests without it (400 "Missing S1-Scope header").' },
        endpoint: { type: 'string', enum: ['raw','event'], description: "HEC endpoint: 'raw' (default, raw text) or 'event' (structured JSON)." },
        compress: { type: 'boolean', description: 'gzip the body (Content-Encoding: gzip). Default true.' },
        isParsed: { type: 'boolean', description: 'For /event with structured JSON: set ?isParsed=true so SDL indexes the JSON fields directly, with no SDL parser. Confirmed working.' },
      },
      required: ['logContent', 'scope'],
    },
    async handler({ logContent, parser, fields, scope, endpoint, compress, isParsed }) {
      const result = await hecIngest(logContent, { parser, fields, scope, endpoint, compress, isParsed });
      return JSON.stringify(result, null, 2);
    },
  },
];
