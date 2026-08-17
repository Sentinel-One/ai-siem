/**
 * PowerQuery tools: powerquery skill
 *
 * Tools:
 *   powerquery_run            Run a PowerQuery via the LRQ API
 *   powerquery_schema_discover Discover field schema for a data source via V1 query
 *   powerquery_enumerate_sources List all data sources active in SDL (session init)
 */

import { lrqRun } from '../lib/s1.js';
import { v1Query } from '../lib/sdl.js';

export const tools = [
  // ─── powerquery_enumerate_sources ─────────────────────────────────────────
  {
    name: 'powerquery_enumerate_sources',
    description: `MANDATORY SESSION INIT: Run the standard data-source enumeration query to discover every dataSource.name, dataSource.vendor, and dataSource.category active in this SDL tenant. Always call this at the start of every session before writing any hunt queries. Results are environment-specific and can change between sessions as integrations are added or removed. Never assume sources from a prior session.`,
    inputSchema: {
      type: 'object',
      properties: {
        hours: {
          type: 'number',
          description: 'Lookback window in hours (default 24). Increase to 168 (7d) if the last 24h had low volume.',
          default: 24,
        },
        scope: {
          type: 'string',
          description: 'Optional S1-Scope, "<accountId>" or "<accountId>:<siteId>". LOG READS ARE SCOPE-FILTERED just like config reads, so this changes which events the query can see. Use it to hunt within one site, and to validate a site-scoped dashboard panel against the same boundary the dashboard will see. Omit to use S1_SCOPE from credentials.json, or the token default when that is unset.',
        },
      },
      required: [],
    },
    async handler({ hours = 24, scope } = {}) {
      const query = `| group UniqueDataSourceNames = array_agg_distinct(dataSource.name),
        UniqueVendors = array_agg_distinct(dataSource.vendor),
        UniqueCategories = array_agg_distinct(dataSource.category)
| limit 1000`;
      const result = await lrqRun(query, { hours, scope });
      return JSON.stringify(result, null, 2);
    },
  },

  // ─── powerquery_run ────────────────────────────────────────────────────────
  {
    name: 'powerquery_run',
    description: `Run a SentinelOne PowerQuery against the Singularity Data Lake using the LRQ API. The LRQ API is async; this tool handles the full launch-poll-cancel lifecycle and returns results. Use for threat hunting, telemetry analysis, dashboard panel validation, and STAR rule testing. Auth: Bearer <jwt> (same token as mgmt API). Time range defaults to last 24 hours if startTime/endTime are omitted.`,
    inputSchema: {
      type: 'object',
      properties: {
        query: {
          type: 'string',
          description: 'The PowerQuery string. Use pipe-separated commands: | filter | group | sort | limit | columns. Three distinct wildcard idioms; use the right one: (1) FIELD PRESENCE / ATTRIBUTE WILDCARD: field=* means "field is present/non-null", e.g. dataSource.name=* | group count=count() by dataSource.name; use this as a query-opener or whenever you need "all events that have this field". (2) ALL-COLUMN TEXT SEARCH: * contains \'value\' or * matches \'regex\' in the initial filter (before the first |) searches ALL indexed fields; use when the user asks to find text anywhere in the event, e.g. dataSource.name=\'MySource\' * contains \'evil.com\'. Dramatically faster than message contains. (3) EMPTY FILTER (all events): start with | and no initial predicate, e.g. | group ct=count() by event.type. Do NOT use bare * alone as the initial filter; that causes HTTP 500 ("Don\'t understand [*]"). Beyond filtering, | datasource <name> [from <dataset>] reads SentinelOne-managed inventory (assets, alerts, vulnerabilities, misconfigurations, metering; e.g. | datasource assets from \'surface/identity\') and | savelookup \'<name>\' persists the result as a reusable lookup table (see references/datasource-command.md in powerquery).',
        },
        startTime: {
          type: 'string',
          description: 'ISO-8601 UTC start time, e.g. "2026-04-20T00:00:00Z". If omitted, defaults to (now - hours) ago.',
        },
        endTime: {
          type: 'string',
          description: 'ISO-8601 UTC end time, e.g. "2026-04-21T00:00:00Z". If omitted, defaults to now.',
        },
        hours: {
          type: 'number',
          description: 'Lookback window in hours when startTime/endTime are not specified (default 24).',
          default: 24,
        },
        maxRows: {
          type: 'number',
          description: 'Client-side cap on rows returned (default 1000). Not a hard backend limit: the LRQ engine returns as many rows as the query\'s own `| limit N` asks for (live-verified 2026-07-29: a `| limit 20000` query returned 20,000 rows in one response). Raise this to match a large `| limit`; the real ceiling is LRQ response size, not a fixed 5000.',
          default: 1000,
        },
        scope: {
          type: 'string',
          description: 'Optional S1-Scope, "<accountId>" or "<accountId>:<siteId>". LOG READS ARE SCOPE-FILTERED just like config reads, so this changes which events the query can see. Use it to hunt within one site, and to validate a site-scoped dashboard panel against the same boundary the dashboard will see. Omit to use S1_SCOPE from credentials.json, or the token default when that is unset.',
        },
      },
      required: ['query'],
    },
    async handler({ query, startTime, endTime, hours = 24, maxRows = 1000, scope }) {
      const result = await lrqRun(query, { startTime, endTime, hours, maxRows, scope });
      return JSON.stringify(result, null, 2);
    },
  },

  // ─── powerquery_schema_discover ────────────────────────────────────────────
  {
    name: 'powerquery_schema_discover',
    description: `Discover the field schema for a specific SDL data source by fetching raw event JSON via the V1 query endpoint. PowerQuery's default projection only returns timestamp+message; V1 query returns full event attributes so you can see what field names are actually present. Use this before authoring any hunt query or dashboard panel against a non-OCSF source. The V1 endpoint is deprecated (sunset Feb 2027) but is still the only way to get full event JSON per-source. Auth tries each configured SDL key in scope order and falls through to the console JWT on 401/403.`,
    inputSchema: {
      type: 'object',
      properties: {
        dataSourceName: {
          type: 'string',
          description: 'Exact dataSource.name value (case-sensitive, as returned by powerquery_enumerate_sources).',
        },
        maxEvents: {
          type: 'number',
          description: 'Number of sample events to retrieve (default 5, max 50).',
          default: 5,
        },
        startTime: {
          type: 'string',
          description: 'Lookback string or ISO date, e.g. "24h", "7d", or "2026-04-20T00:00:00Z" (default "24h").',
          default: '24h',
        },
        scope: {
          type: 'string',
          description: 'Optional S1-Scope, "<accountId>" or "<accountId>:<siteId>". Schema discovery is scope-filtered: a source present at one site may be absent at another, so discover at the scope you will query.',
        },
      },
      required: ['dataSourceName'],
    },
    async handler({ dataSourceName, maxEvents = 5, startTime = '24h', scope }) {
      // Escape backslashes first, then single quotes, to keep tenant-defined
      // source names from breaking (or altering) the V1 filter expression.
      // Quote-only escaping let a trailing backslash neutralise the added
      // escape (e.g. name\' -> \\' which re-opens the string).
      const safeName = String(dataSourceName).replace(/\\/g, '\\\\').replace(/'/g, "\\'");
      const filter = `dataSource.name=='${safeName}'`;
      const result = await v1Query(filter, { maxCount: Math.min(maxEvents, 50), startTime, scope });

      const matches = result.matches || [];
      if (matches.length === 0) {
        return JSON.stringify({ dataSourceName, message: 'No events found in the specified time range. Try a longer startTime like "7d".', result }, null, 2);
      }

      // Extract field names from first event
      const firstAttrs = matches[0]?.attributes || {};
      const allFields = new Set();
      matches.forEach(m => Object.keys(m?.attributes || {}).forEach(k => allFields.add(k)));

      return JSON.stringify({
        dataSourceName,
        sampleEventCount: matches.length,
        confirmedFields: Array.from(allFields).sort(),
        firstEventAttributes: firstAttrs,
        allSampleAttributes: matches.map(m => m.attributes),
      }, null, 2);
    },
  },
];
