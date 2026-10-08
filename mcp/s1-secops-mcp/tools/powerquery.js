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
import { slicedRun, MAX_SLICES } from '../lib/slicing.js';
import { writeOutput, serialiseRows, resolveOutputPath } from '../lib/output.js';

const OUTPUT_FILE_DESC = 'Optional absolute path on the machine running this MCP server. When set, the FULL result is written there (.csv, .jsonl/.ndjson, or JSON for any other extension) and the response carries only a summary plus a 5-row preview, so bulk results do not pass through the context window. Must be inside S1_OUTPUT_DIRS (default: home and temp directories). Refuses to overwrite unless overwrite is true. Files are created mode 0600.';

/** Write a result to outputFile and return a compact summary instead of the rows. */
function persist(result, rows, outputFile, overwrite) {
  const out = writeOutput(outputFile, serialiseRows(outputFile, rows, result), { overwrite: overwrite === true });
  const { rows: _r, matches: _m, ...rest } = result;
  return { ...rest, outputFile: out.path, bytesWritten: out.bytes, sha256: out.sha256, rowsWritten: rows.length, preview: rows.slice(0, 5) };
}

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
          description: 'Optional S1-Scope, "<accountId>" or "<accountId>:<siteId>". LOG READS ARE SCOPE-FILTERED just like config reads, so this changes which events the query can see. Use it to hunt within one site, and to validate a site-scoped dashboard panel against the same boundary the dashboard will see. Omit to use the configured S1_SCOPE, or the token default when that is unset.',
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
    description: `Run a SentinelOne PowerQuery against the Singularity Data Lake using the LRQ API. The LRQ API is async; this tool handles the full launch-poll-cancel lifecycle and returns results. Use for threat hunting, telemetry analysis, dashboard panel validation, and STAR rule testing. Auth: Bearer <jwt> (same token as mgmt API). Time range defaults to last 24 hours if startTime/endTime are omitted. SDL INGEST-METERING ROWS ARE EXCLUDED BY DEFAULT: every ingest writes receive-time accounting rows (tag='logVolume', fields metric/value/path1) under the source's own dataSource.name, which inflate per-source counts and make a silent source look live. The tool ANDs \`tag != 'logVolume'\` into the initial filter (rows with no tag are kept) and returns effectiveQuery. It is not added when the query mentions logVolume, or opens with | datasource, | dataset, | join or | union. Set includeMetering true to send the query unchanged, e.g. for ingest-volume or licence analysis. The console's XDR view already hides these rows; All Data does not. NUMBERS: integers beyond 2^53 (17-19 digit ids, nanosecond timestamps) are returned as exact strings, not rounded numbers; aggregates such as sum(), min() and max() come back from SDL as floats and stay numbers.`,
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
          description: 'Optional S1-Scope, "<accountId>" or "<accountId>:<siteId>". LOG READS ARE SCOPE-FILTERED just like config reads, so this changes which events the query can see. Use it to hunt within one site, and to validate a site-scoped dashboard panel against the same boundary the dashboard will see. Omit to use the configured S1_SCOPE, or the token default when that is unset.',
        },
        queryType: {
          type: 'string',
          enum: ['PQ', 'LOG'],
          description: 'PQ (default): a PowerQuery pipeline. LOG: raw event search; `query` is a filter expression only (no pipes), e.g. dataSource.name=\'Okta\' * contains \'jdoe\', and the response carries every parsed field per event in `matches`. Use LOG for evidence-grade exports, full-event forensic timelines and S1QL-style hunts (the Deep Visibility replacement). The server caps LOG at logLimit rows (max 5000); truncatedByServerCap=true means the window held more, so slice it.',
        },
        logLimit: {
          type: 'number',
          description: 'LOG only: server-side row cap per query or slice (default and max 5000).',
        },
        slices: {
          type: 'number',
          description: `Split the window into N equal time slices (2-${MAX_SLICES}) run in parallel, then combine. Use for windows over ~24h, where one query is slow or times out (30 days: ~5 s as 15 slices vs 21-40 s unsliced, identical totals). For PQ group-by results also pass merge; without merge the slice rows are concatenated. Only mergeable aggregates (count, sum, min, max) may be merged; estimate_distinct, avg, percentiles, top and savelookup are refused.`,
        },
        merge: {
          type: 'object',
          description: 'With slices on a PQ aggregate: how to combine rows across slices. keys = group-by columns; sum = columns to add (count() results are sums); min / max = columns to take the min / max of. Example: {"keys":["dataSource.name"],"sum":["count"]}.',
          properties: {
            keys: { type: 'array', items: { type: 'string' } },
            sum: { type: 'array', items: { type: 'string' } },
            min: { type: 'array', items: { type: 'string' } },
            max: { type: 'array', items: { type: 'string' } },
          },
        },
        outputFile: { type: 'string', description: OUTPUT_FILE_DESC },
        overwrite: { type: 'boolean', description: 'Allow outputFile to replace an existing file.' },
        includeMetering: {
          type: 'boolean',
          description: 'Send the query unchanged, including SDL ingest-metering rows (tag=\'logVolume\'). Omit, or false, to exclude them (the normal case). Set true only for ingest-volume, data-usage or licence questions.',
        },
        edrStrict: {
          type: 'boolean',
          description: 'For SentinelOne EDR queries: send scheme=edr so an unknown or wrongly cased field (e.g. Endpoint.name) fails with HTTP 400 "Unknown EDR field" instead of silently returning 0 rows. Correct fields return the same rows. A 400 here means fix the field name, not retry. Leave unset for non-EDR sources.',
        },
      },
      required: ['query'],
    },
    async handler({ query, startTime, endTime, hours = 24, maxRows = 1000, scope, includeMetering, edrStrict, queryType = 'PQ', logLimit, slices, merge, outputFile, overwrite }) {
      const common = { startTime, endTime, hours, scope, includeMetering: includeMetering === true, edrStrict: edrStrict === true, queryType, logLimit };
      const n = slices === undefined || slices === null ? 1 : Number(slices);
      if (!Number.isInteger(n) || n < 1 || n > MAX_SLICES) throw new Error(`slices must be a whole number between 1 and ${MAX_SLICES}`);
      if (merge && n < 2) throw new Error('merge only applies with slices >= 2');
      // Validate the output path BEFORE running the query, so a refused path costs nothing.
      if (outputFile) resolveOutputPath(outputFile, { overwrite: overwrite === true });

      let result;
      let rows;
      if (n > 1) {
        result = await slicedRun(query, { ...common, slices: n, merge });
        rows = result.rows;
      } else {
        // With outputFile, keep every row the engine returned; maxRows caps the inline response only.
        result = await lrqRun(query, { ...common, maxRows: outputFile ? Number.MAX_SAFE_INTEGER : maxRows });
        rows = queryType === 'LOG' ? result.matches : result.rows;
      }

      if (outputFile) return JSON.stringify(persist(result, rows, outputFile, overwrite), null, 2);

      // Inline response: apply the maxRows cap (sliced results are uncapped internally).
      if (n > 1 && rows.length > maxRows) {
        result = { ...result, rows: rows.slice(0, maxRows), rowCount: maxRows, rowsTruncatedInline: true,
          note: `${rows.length} rows; showing the first ${maxRows}. Pass outputFile to keep them all.` };
      }
      return JSON.stringify(result, null, 2);
    },
  },

  // ─── powerquery_schema_discover ────────────────────────────────────────────
  {
    name: 'powerquery_schema_discover',
    description: `Discover the field schema for a specific SDL data source by fetching raw event JSON via the V1 query endpoint. PowerQuery's default projection only returns timestamp+message; V1 query returns full event attributes so you can see what field names are actually present. Use this before authoring any hunt query or dashboard panel against a non-OCSF source. The V1 endpoint is deprecated (sunset Feb 2027) but is still the only way to get full event JSON per-source. SDL ingest-metering rows (tag='logVolume', fields metric/path1/value) share the source's dataSource.name and are excluded from the sample; excludedMeteringRows reports how many were dropped. Auth tries each configured SDL key in scope order and falls through to the console JWT on 401/403.`,
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
      const wanted = Math.max(1, Math.min(maxEvents, 50));
      // Over-fetch, then drop SDL ingest-metering rows (tag='logVolume': metric,
      // path1, value) client-side. They share the source's dataSource.name, so an
      // unfiltered sample can be partly or wholly metering and report a schema the
      // source does not have. Measured 2026-10-03: 42-64% of rows on 4 sources.
      // Done client-side so no V1 filter syntax is assumed.
      const result = await v1Query(filter, { maxCount: Math.min(wanted * 10, 500), startTime, scope });

      const all = result.matches || [];
      const isMetering = m => m?.attributes?.tag === 'logVolume';
      const excludedMeteringRows = all.filter(isMetering).length;
      const matches = all.filter(m => !isMetering(m)).slice(0, wanted);
      if (matches.length === 0) {
        const message = excludedMeteringRows > 0
          ? `Only ingest-metering rows (tag='logVolume') were found for this source in the window (${excludedMeteringRows} excluded), so no event schema could be sampled. Try a longer startTime like "7d".`
          : 'No events found in the specified time range. Try a longer startTime like "7d".';
        return JSON.stringify({ dataSourceName, message, excludedMeteringRows }, null, 2);
      }

      // Extract field names from first event
      const firstAttrs = matches[0]?.attributes || {};
      const allFields = new Set();
      matches.forEach(m => Object.keys(m?.attributes || {}).forEach(k => allFields.add(k)));

      return JSON.stringify({
        dataSourceName,
        sampleEventCount: matches.length,
        excludedMeteringRows,
        confirmedFields: Array.from(allFields).sort(),
        firstEventAttributes: firstAttrs,
        allSampleAttributes: matches.map(m => m.attributes),
      }, null, 2);
    },
  },
];
