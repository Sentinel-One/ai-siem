/**
 * SDL API tools: sdl-api, sdl-dashboard, sdl-log-parser skills
 *
 * Tools:
 *   sdl_list_files     List every config file on the SDL tenant (GraphQL configFiles)
 *   sdl_get_file       Get file content and version, by path or udoId
 *   sdl_put_file       Deploy or update a config file (with optimistic locking)
 *   sdl_delete_file    Delete a config file
 *   hec_ingest         Ingest raw logs/events into SDL via the HEC endpoint (replaces uploadLogs)
 *
 * All four config-file tools run on `POST /sdl/v2/graphql`. The legacy REST
 * `/sdl/api/*File` endpoints are NOT used: they silently omit every
 * udoId-addressed dashboard (1,914 vs 2,264 files on a live tenant) and return
 * `success/noSuchFile` for any of them.
 */

import { configFiles, configFile, putConfigFile, deleteConfigFile } from '../lib/sdl.js';
import { hecIngest } from '../lib/hec.js';

const UDOID_NOTE =
  'Dashboards are addressed by udoId, everything else by path. The console shows a dashboard as ' +
  '"/dashboards/id/<udoId>/<name>" in its Configuration Files grid; that display string is NOT a path, ' +
  'the number in it is the udoId and the real path is "/dashboards/<name>". ' +
  'udoId assignment is by namespace: only /dashboards/ files have one, /lookups/, /datatables/, ' +
  '/logParsers/ and /automaticLookups are all name-addressed with udoId null.';

export const tools = [
  // ─── sdl_list_files ───────────────────────────────────────────────────────
  {
    name: 'sdl_list_files',
    description: `List every configuration file on the SDL tenant via the GraphQL configFiles query: /logParsers/, /dashboards/, /alerts/, /lookups/, /datatables/, /automaticLookups. Returns {udoId, name, readOnly, version} per file. ${UDOID_NOTE} Use this to discover what is deployed, and to resolve a dashboard name to the udoId that sdl_get_file/sdl_put_file need. Never conclude a file is absent from a listing produced any other way; the legacy REST listing omits ~350 dashboards.`,
    inputSchema: {
      type: 'object',
      properties: {
        pathPrefix: {
          type: 'string',
          description: 'Optional filter, e.g. "/dashboards/" or "/logParsers/". Applied client-side to the full listing.',
        },
      },
      required: [],
    },
    async handler({ pathPrefix } = {}) {
      let files = await configFiles();
      if (pathPrefix) files = files.filter(f => (f.name || '').startsWith(pathPrefix));
      return JSON.stringify({ count: files.length, files }, null, 2);
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
      },
      required: [],
    },
    async handler({ path, udoId }) {
      const result = await configFile({ name: path, udoId });
      if (!result) {
        return JSON.stringify({
          status: 'notFound',
          hint: 'No file at that address. If this is a dashboard, it is udoId-addressed: run sdl_list_files with pathPrefix "/dashboards/" and retry with its udoId.',
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
      },
      required: ['content'],
    },
    async handler({ path, udoId, content, expectedVersion }) {
      const result = await putConfigFile({ name: path, udoId, content, expectedVersion });
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
      },
      required: [],
    },
    async handler({ path, udoId, expectedVersion }) {
      const result = await deleteConfigFile({ name: path, udoId, expectedVersion });
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
