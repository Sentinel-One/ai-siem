/**
 * SDL API tools — sentinelone-sdl-api, sentinelone-sdl-dashboard, sentinelone-sdl-log-parser skills
 *
 * Tools:
 *   sdl_list_files     List all config files on the SDL tenant
 *   sdl_get_file       Get file content and version (parsers, dashboards, alerts, lookups)
 *   sdl_put_file       Deploy or update a config file (with optimistic locking)
 *   sdl_delete_file    Delete a config file
 *   hec_ingest         Ingest raw logs/events into SDL via the HEC endpoint (replaces uploadLogs)
 */

import { listFiles, getFile, putFile, deleteFile } from '../lib/sdl.js';
import { hecIngest } from '../lib/hec.js';

export const tools = [
  // ─── sdl_list_files ───────────────────────────────────────────────────────
  {
    name: 'sdl_list_files',
    description: `List all configuration files stored in the SDL tenant. Returns all paths organized by type: /logParsers/, /dashboards/, /alerts/, /lookups/, /datatables/. Use this to discover what parsers and dashboards are already deployed, or to find a file path before calling sdl_get_file or sdl_put_file.`,
    inputSchema: {
      type: 'object',
      properties: {},
      required: [],
    },
    async handler() {
      const result = await listFiles();
      return JSON.stringify(result, null, 2);
    },
  },

  // ─── sdl_get_file ─────────────────────────────────────────────────────────
  {
    name: 'sdl_get_file',
    description: `Get the content and current version number of a SDL configuration file. Use before sdl_put_file to read the current version for optimistic locking (pass the returned version as expectedVersion). Supports any file type: parsers (/logParsers/<name>), dashboards (/dashboards/<name>), alerts (/alerts/<name>), lookups (/lookups/<name>), datatables (/datatables/<name>). Always read before overwriting — this prevents concurrent-edit conflicts.`,
    inputSchema: {
      type: 'object',
      properties: {
        path: {
          type: 'string',
          description: 'Full SDL config path, e.g. "/logParsers/FortiGate" or "/dashboards/SOC-Overview". Get the path from sdl_list_files.',
        },
      },
      required: ['path'],
    },
    async handler({ path }) {
      const result = await getFile(path);
      return JSON.stringify(result, null, 2);
    },
  },

  // ─── sdl_put_file ─────────────────────────────────────────────────────────
  {
    name: 'sdl_put_file',
    description: `Deploy or update a SDL configuration file. Always call sdl_get_file first to obtain the current expectedVersion — this prevents overwriting concurrent edits. If creating a new file, omit expectedVersion. File type conventions: parsers go to /logParsers/<name>, dashboards to /dashboards/<name>, alerts to /alerts/<name>, lookups to /lookups/<name>. Requires Configuration Write key (SDL_CONFIG_WRITE_KEY) or a console JWT that has config write permissions.`,
    inputSchema: {
      type: 'object',
      properties: {
        path: {
          type: 'string',
          description: 'Full SDL config path, e.g. "/logParsers/MyParser" or "/dashboards/SOC-Ops".',
        },
        content: {
          type: 'string',
          description: 'File content as a string. For dashboards: valid dashboard JSON. For parsers: augmented-JSON parser definition. For lookups: CSV or JSON.',
        },
        expectedVersion: {
          type: 'number',
          description: 'Current file version from sdl_get_file. Required for updates to enable optimistic locking. Omit only when creating a new file.',
        },
      },
      required: ['path', 'content'],
    },
    async handler({ path, content, expectedVersion }) {
      const result = await putFile(path, content, expectedVersion);
      return JSON.stringify(result, null, 2);
    },
  },

  // ─── sdl_delete_file ──────────────────────────────────────────────────────
  {
    name: 'sdl_delete_file',
    description: `Delete a SDL configuration file (parser, dashboard, alert, lookup, datatable). Use with caution — deletion is permanent. Always read the file with sdl_get_file first to confirm you have the right path and version.`,
    inputSchema: {
      type: 'object',
      properties: {
        path: {
          type: 'string',
          description: 'Full SDL config path to delete.',
        },
        expectedVersion: {
          type: 'number',
          description: 'Current file version for optimistic locking (from sdl_get_file). Strongly recommended.',
        },
      },
      required: ['path'],
    },
    async handler({ path, expectedVersion }) {
      const result = await deleteFile(path, expectedVersion);
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
