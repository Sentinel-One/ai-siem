/**
 * Parallel time slicing for long-window LRQ queries, with client-side merge.
 *
 * Measured (S-26.3.4): one token sustains ~30 launches/s; a 30-day aggregate
 * took 21-40 s as one query and ~5 s as 15 slices with identical totals. Launch
 * 429s are retried inside lrqRun. At most `concurrency` slices run at once.
 *
 * Merge rules (only mergeable aggregates may be sliced):
 *   keys  group-by columns; rows with equal keys are combined
 *   sum   summed (count() results are sums)
 *   min   min of mins
 *   max   max of maxes
 * Not additive (run unsliced instead): estimate_distinct, avg, percentiles,
 * top, and anything after | sort/| limit. savelookup must never be sliced:
 * every slice would overwrite the same table.
 */

import { lrqRun, resolveLrqWindow } from './s1.js';

export const MAX_SLICES = 15;

export function sliceWindow(startTime, endTime, n) {
  const s = new Date(startTime).getTime();
  const e = new Date(endTime).getTime();
  if (!Number.isFinite(s) || !Number.isFinite(e) || e <= s) throw new Error('slicing needs a valid window with endTime after startTime');
  const iso = (t) => new Date(t).toISOString().replace(/\.\d+Z$/, 'Z');
  const out = [];
  for (let i = 0; i < n; i++) {
    const a = s + Math.floor(((e - s) * i) / n);
    const b = i === n - 1 ? e : s + Math.floor(((e - s) * (i + 1)) / n);
    out.push({ startTime: iso(a), endTime: iso(b) });
  }
  return out;
}

async function pool(items, limit, fn) {
  const results = new Array(items.length);
  let next = 0;
  async function worker() {
    while (next < items.length) {
      const i = next++;
      results[i] = await fn(items[i], i);
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return results;
}

/** Combine rows per the merge spec. Exported for unit tests. */
// Exact arithmetic for merges. Values beyond 2^53 arrive as integer strings
// (lib/json.js); BigInt keeps sums, mins and maxes exact. Results that fit a
// safe integer go back to numbers so ordinary counts look unchanged.
const isIntStr = (v) => typeof v === 'string' && /^-?\d+$/.test(v);
const isNum = (v) => typeof v === 'number' && !Number.isNaN(v);
const usable = (v) => isNum(v) || isIntStr(v);
// Exact = an integer string or a SAFE integer. A double above 2^53 (SDL sum()
// returns floats) is not exact and must stay on the float path.
const exact = (v) => isIntStr(v) || Number.isSafeInteger(v);
function fromBig(b) {
  const n = Number(b);
  return Number.isSafeInteger(n) ? n : b.toString();
}
function addExact(a, b) {
  if (!usable(a)) return b;
  if (exact(a) && exact(b)) return fromBig(BigInt(a) + BigInt(b));
  return Number(a) + Number(b);
}
function cmpExact(a, b) {
  if (exact(a) && exact(b)) { const x = BigInt(a); const y = BigInt(b); return x < y ? -1 : x > y ? 1 : 0; }
  return Number(a) - Number(b);
}

export function mergeRows(rows, { keys = [], sum = [], min = [], max = [] } = {}) {
  const out = new Map();
  const norm = (v) => (isNum(v) ? v : isIntStr(v) ? fromBig(BigInt(v)) : (v === null || v === undefined || v === '' ? null : (Number.isNaN(Number(v)) ? null : Number(v))));
  for (const r of rows) {
    const k = JSON.stringify(keys.map(c => r[c] ?? null));
    const cur = out.get(k);
    if (!cur) { out.set(k, { ...r }); continue; }
    for (const c of sum) { const v = norm(r[c]); if (v !== null) cur[c] = addExact(norm(cur[c]), v); }
    for (const c of min) { const v = norm(r[c]); if (v !== null) { const p = norm(cur[c]); cur[c] = p === null ? v : (cmpExact(v, p) < 0 ? v : p); } }
    for (const c of max) { const v = norm(r[c]); if (v !== null) { const p = norm(cur[c]); cur[c] = p === null ? v : (cmpExact(v, p) > 0 ? v : p); } }
  }
  return [...out.values()];
}

/**
 * A merge spec must name real columns, and every result column must be either a
 * key or an aggregated column: otherwise rows silently collapse (a misspelled key
 * merged everything into one row). Exported for tests.
 */
export function validateMergeSpec(merge, colNames) {
  const { keys = [], sum = [], min = [], max = [] } = merge || {};
  const named = [...keys, ...sum, ...min, ...max];
  const unknown = named.filter(c => !colNames.includes(c));
  if (unknown.length) throw new Error(`merge names column(s) not in the result: ${unknown.join(', ')}. Result columns: ${colNames.join(', ')}`);
  const unaccounted = colNames.filter(c => !named.includes(c));
  if (unaccounted.length) throw new Error(`merge must list every result column as a key or in sum/min/max; missing: ${unaccounted.join(', ')}`);
}

const NON_MERGEABLE = /\b(estimate_distinct|count_distinct|avg|median|percentile|p\d{2}|stddev|savelookup)\s*\(|\|\s*(top|savelookup)\b/i;

/** Split a PQ string on top-level pipes (outside quotes). Exported for tests. */
export function splitPipes(q) {
  const parts = [];
  let quote = null;
  let cur = '';
  for (let i = 0; i < q.length; i++) {
    const c = q[i];
    if (quote) {
      cur += c;
      if (c === '\\' && i + 1 < q.length) { cur += q[++i]; continue; }
      if (c === quote) quote = null;
    } else if (c === "'" || c === '"') { quote = c; cur += c; }
    else if (c === '|') { parts.push(cur); cur = ''; }
    else cur += c;
  }
  parts.push(cur);
  return parts;
}

/**
 * For a merged sliced run, a trailing `| sort` / `| limit` must apply to the
 * MERGED rows, not to each slice (per-slice top-N then merge gives wrong
 * answers: verified live, a 7d top-3 came back as 4 rows with a wrong count).
 * Strip them from the query, return them to re-apply after the merge. Any other
 * command after the last `| group` cannot be merged and is refused.
 * Exported for tests.
 */
export function planMergedQuery(query) {
  const parts = splitPipes(query);
  let lastGroup = -1;
  parts.forEach((p, i) => { if (i > 0 && /^\s*group\b/i.test(p)) lastGroup = i; });
  if (lastGroup === -1) throw new Error('merge needs a query whose result comes from | group ... by ...; for raw rows omit merge (slices are concatenated).');
  const post = { sort: null, limit: null };
  for (let i = lastGroup + 1; i < parts.length; i++) {
    const p = parts[i].trim();
    let m;
    if ((m = p.match(/^sort\s+(.+)$/i))) post.sort = m[1].split(',').map(s => s.trim()).filter(Boolean).map(s => ({ desc: s.startsWith('-'), col: s.replace(/^[-+]/, '').trim() }));
    else if ((m = p.match(/^limit\s+(\d+)$/i))) post.limit = Number(m[1]);
    else throw new Error(`| ${p.split(/\s/)[0]} after the last | group cannot be merged across slices. Only | sort and | limit are allowed there (they are applied after the merge); run anything else unsliced.`);
  }
  return { query: parts.slice(0, lastGroup + 1).join('|'), post, expectedCols: groupColumns(parts[lastGroup]) };
}

/** Split on commas outside parentheses and quotes. */
function splitTopLevelCommas(s) {
  const out = []; let depth = 0; let quote = null; let cur = '';
  for (const c of s) {
    if (quote) { cur += c; if (c === quote) quote = null; continue; }
    if (c === "'" || c === '"') { quote = c; cur += c; continue; }
    if (c === '(') depth++;
    if (c === ')') depth--;
    if (c === ',' && depth === 0) { out.push(cur); cur = ''; continue; }
    cur += c;
  }
  out.push(cur);
  return out.map(x => x.trim()).filter(Boolean);
}

/**
 * Result columns of `group a=count(), b=sum(x) by k1, k2`: [a, b, k1, k2].
 * Null when the shape is not recognised (then validation waits for the result).
 */
export function groupColumns(groupPart) {
  const m = String(groupPart).trim().match(/^group\s+(.+?)(?:\s+by\s+(.+))?$/is);
  if (!m) return null;
  const aggs = splitTopLevelCommas(m[1]);
  const names = [];
  for (const a of aggs) {
    const am = a.match(/^([A-Za-z_][\w.]*)\s*=/);
    if (!am) return null;
    names.push(am[1]);
  }
  const keys = m[2] ? splitTopLevelCommas(m[2]) : [];
  if (keys.some(k => !/^[A-Za-z_][\w.]*$/.test(k))) return null;
  return [...keys, ...names]; // LRQ lists group-by keys first, then aggregates
}

export function applyPost(rows, post) {
  let out = rows;
  if (post.sort) {
    out = [...out].sort((a, b) => {
      for (const { col, desc } of post.sort) {
        const x = a[col]; const y = b[col];
        if (x === y) continue;
        if (x === null || x === undefined) return 1;
        if (y === null || y === undefined) return -1;
        const nx = Number(x); const ny = Number(y);
        const cmp = exact(x) && exact(y) ? cmpExact(x, y)
          : Number.isFinite(nx) && Number.isFinite(ny) ? nx - ny : String(x).localeCompare(String(y));
        if (cmp) return desc ? -cmp : cmp;
      }
      return 0;
    });
  }
  if (post.limit !== null) out = out.slice(0, post.limit);
  return out;
}

export async function slicedRun(query, opts) {
  const { slices, merge, concurrency = MAX_SLICES, queryType = 'PQ' } = opts;
  const n = Math.max(1, Math.min(Number(slices) || 1, MAX_SLICES));
  const { startTime, endTime } = resolveLrqWindow(opts);
  if (queryType === 'PQ' && merge && NON_MERGEABLE.test(query)) {
    throw new Error('This query uses a non-additive aggregate or savelookup, which cannot be merged across slices. Run it unsliced, or slice the parts (avg = sum of sums / sum of counts).');
  }
  if (queryType === 'LOG' && merge) throw new Error('merge applies to PQ group-by results only; LOG slices are concatenated raw events.');
  let post = null;
  if (queryType === 'PQ' && merge) {
    let expectedCols;
    ({ query, post, expectedCols } = planMergedQuery(query));
    // Validate the merge spec BEFORE launching any slice when the group shape is
    // recognisable; the post-run check below stays as the backstop.
    if (expectedCols) validateMergeSpec(merge, expectedCols);
  }
  const windows = sliceWindow(startTime, endTime, n);
  const t0 = Date.now();
  const parts = await pool(windows, Math.min(concurrency, MAX_SLICES), async (w) => {
    const r = await lrqRun(query, { ...opts, startTime: w.startTime, endTime: w.endTime, maxRows: Number.MAX_SAFE_INTEGER });
    return { window: w, r };
  });
  const elapsedMs = Date.now() - t0;

  const sliceSummary = parts.map(({ window, r }) => ({
    ...window,
    rows: r.totalRows,
    matchCount: r.matchCount,
    ...(queryType === 'LOG' ? { truncatedByServerCap: r.truncatedByServerCap } : {}),
  }));

  if (queryType === 'LOG') {
    const matches = parts.flatMap(p => p.r.matches);
    return {
      queryType: 'LOG', sliced: true, slices: n, startTime, endTime, elapsedMs,
      rows: matches, totalRows: matches.length,
      anySliceTruncated: sliceSummary.some(s => s.truncatedByServerCap),
      sliceSummary,
    };
  }

  const allRows = parts.flatMap(p => p.r.rows);
  const columns = parts.find(p => p.r.columns?.length)?.r.columns || [];
  if (merge && columns.length) validateMergeSpec(merge, columns.map(c => c.name ?? c));
  const rows = merge ? applyPost(mergeRows(allRows, merge), post) : allRows;
  return {
    sliced: true, slices: n, startTime, endTime, elapsedMs,
    merged: !!merge, mergeSpec: merge || null,
    ...(post && (post.sort || post.limit !== null) ? { appliedAfterMerge: { sort: post.sort, limit: post.limit }, slicedQuery: query } : {}),
    note: merge ? undefined : 'Rows from every slice are concatenated, not merged. Pass merge {keys,sum,min,max} to combine group-by results across slices.',
    columns, rows, totalRows: rows.length,
    matchCount: parts.reduce((a, p) => a + (Number(p.r.matchCount) || 0), 0),
    effectiveQuery: parts[0]?.r.effectiveQuery,
    meteringExcluded: parts[0]?.r.meteringExcluded,
    sliceSummary,
  };
}
