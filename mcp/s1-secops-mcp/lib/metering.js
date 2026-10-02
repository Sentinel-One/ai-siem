/**
 * Default exclusion of SDL ingest-metering rows from PowerQuery.
 *
 * Every HEC/collector ingest writes receive-time accounting rows under the
 * source's own dataSource.name: tag='logVolume', metric logBytes|logEvents,
 * value, path1, and no event fields. Unfiltered per-source counts, baselines,
 * schema samples and "is this source silent?" checks all include them. The
 * console's XDR view hides them (its preFilter is dataSource.category='security',
 * which metering rows lack); the API and the All Data view do not.
 *
 * Live-verified 2026-10-03 over a fixed 12h window: unfiltered 383,044, metering
 * 7,390, `tag != 'logVolume'` 375,654, which reconciles exactly. Rows with no
 * `tag` are KEPT by `!=`, so the older `(tag != 'logVolume' OR !(tag = *))` form
 * is redundant (same 375,654) and costs an extra predicate.
 *
 * The predicate goes into the INITIAL filter (before the first pipe), the stage
 * that is evaluated during the scan, which is the cheapest place to drop rows.
 */

export const METERING_PREDICATE = "tag != 'logVolume'";

// Queries that open with one of these commands do not scan the event stream
// directly (inventory, config tables, multi-branch queries), so a leading
// predicate would be wrong or rejected. They are passed through unchanged.
const PASSTHROUGH_COMMANDS = new Set(['datasource', 'dataset', 'join', 'union', 'inputlookup', 'lookup', 'savelookup']);

/** Index of the first `|` that is outside single or double quotes, or -1. */
function firstTopLevelPipe(q) {
  let quote = null;
  for (let i = 0; i < q.length; i++) {
    const c = q[i];
    if (quote) {
      if (c === '\\') { i++; continue; }
      if (c === quote) quote = null;
    } else if (c === "'" || c === '"') {
      quote = c;
    } else if (c === '|') {
      return i;
    }
  }
  return -1;
}

/**
 * Return { query, applied, reason }. `query` is the text to send.
 * Never throws; anything it cannot classify safely is passed through.
 */
export function excludeMetering(query) {
  const q = String(query ?? '');
  if (/logVolume/i.test(q)) {
    return { query: q, applied: false, reason: 'query references logVolume explicitly' };
  }
  const pipe = firstTopLevelPipe(q);
  const initial = (pipe === -1 ? q : q.slice(0, pipe)).trim();
  const rest = pipe === -1 ? '' : q.slice(pipe);

  if (!initial) {
    const cmd = (rest.match(/^\|\s*([A-Za-z_]+)/) || [])[1]?.toLowerCase();
    if (!cmd) return { query: q, applied: false, reason: 'empty query' };
    if (PASSTHROUGH_COMMANDS.has(cmd)) {
      return { query: q, applied: false, reason: `query opens with | ${cmd}, which does not scan the event stream directly` };
    }
    return { query: `${METERING_PREDICATE} ${rest}`, applied: true, reason: 'added as the initial filter' };
  }
  // Parenthesise the caller's filter so a top-level OR keeps its meaning. The
  // closing paren goes on its own line so a trailing // comment cannot eat it.
  return {
    query: `${METERING_PREDICATE} and (${initial}\n)${rest ? ` ${rest}` : ''}`,
    applied: true,
    reason: 'ANDed into the initial filter',
  };
}
