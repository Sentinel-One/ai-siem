/**
 * How an LRQ (POST /sdl/v2/api/queries) is scoped to an account or a site.
 *
 * Issue #111, measured live 2026-10-09 on S-26.3 with three tokens:
 *
 *   - The LRQ API ignores the S1-Scope header for a user that spans several
 *     accounts (a global or multi-account service user). `tenant: true` runs
 *     across every authorized account, so a scoped query silently answered for
 *     all of them: scope "<A>" returned 19 accounts, scope "<A>:<S>" 29
 *     account:site pairs.
 *   - `tenant: false, accountIds: ["<A>"]` returns account A only, on a
 *     global token and on an account-level token alike. On the account-level
 *     token it matches `tenant: true` + S1-Scope exactly (184 = 184).
 *   - There is no `siteIds` body field (HTTP 400 "Invalid JSON"). A
 *     `site.id='<S>'` term in the query reproduces S1-Scope "<A>:<S>" exactly on
 *     the account-level token (106 = 106) and narrows the global token too.
 *   - `accountIds` must be an array (a string is 400 "Invalid JSON"), must pair
 *     with `tenant: false` (true or omitted is 400), and `tenant: false` without
 *     `accountIds` returns only global-level rows (account "1"). Never send that.
 *   - An account the token cannot reach is HTTP 500 "You do not have access to
 *     this account", which is a clear refusal, not a silent empty result.
 */

import { resolveScope } from './sdl.js';
import { firstTopLevelPipe, PASSTHROUGH_COMMANDS } from './metering.js';

/**
 * Resolve the effective scope (explicit, else S1_SCOPE, else none) into the
 * LRQ launch-body fields. Returns
 *   { resolved, accountId, siteId, body }
 * where `body` is merged into the launch body: { tenant: true } when unscoped,
 * { tenant: false, accountIds: [accountId] } when scoped.
 */
export function lrqScope(scope) {
  const resolved = resolveScope(scope);
  if (!resolved) return { resolved: null, accountId: null, siteId: null, body: { tenant: true } };
  const [accountId, siteId = null] = resolved.split(':');
  return { resolved, accountId, siteId, body: { tenant: false, accountIds: [accountId] } };
}

// `| [sql] [inner|left|outer] join (q1), (q2) on k` and `| union (q1), (q2)`.
const SUBQUERY_CMD = /^\|\s*(?:(?:sql\s+)?(?:inner|left|outer)\s+)?(join|union)\b/i;
// `| datasource <name>` reads SentinelOne-managed inventory, whose rows carry the
// site under their own column, not site.id. Measured 2026-10-09 against the
// S1-Scope ground truth on an account-level token: vulnerabilities 481 = 481,
// misconfigurations 662 = 662. `alerts` has no site column at all.
export const DATASOURCE_SITE_FIELD = Object.freeze({ vulnerabilities: 'siteId', misconfigurations: 'siteId' });
// A lookup table written at account scope and at account:site scope is two files.
// Measured 2026-10-09, on an account-level and on a global token: the LRQ reads the
// copy named by the S1-Scope header (account copy with "<A>", site copy with "<A>:<S>"),
// and with accountIds but no header the global token found no table at all.
const LOOKUP_NOTE = 'reads a lookup table: no row filter applies, and the S1-Scope header selects the site copy of the table';

/** Index just past the parenthesis that closes the one at `open`, quote-aware, or -1. */
function closingParen(q, open) {
  let depth = 0, quote = null;
  for (let i = open; i < q.length; i++) {
    const c = q[i];
    if (quote) { if (c === '\\') { i++; continue; } if (c === quote) quote = null; continue; }
    if (c === "'" || c === '"') { quote = c; continue; }
    if (c === '(') depth++;
    else if (c === ')') { depth--; if (depth === 0) return i + 1; }
  }
  return -1;
}

/** Narrow every subquery of a leading | join / | union. Subqueries that read a lookup
 *  table (| dataset, | inputlookup) are left alone: a table has no site. */
function siteFilterSubqueries(q, siteId) {
  const m = SUBQUERY_CMD.exec(q);
  let out = q.slice(0, m[0].length);
  let i = m[0].length, n = 0;
  const skipped = [];
  let quote = null;
  for (; i < q.length; i++) {
    const c = q[i];
    if (quote) { out += c; if (c === '\\') { out += q[++i] ?? ''; continue; } if (c === quote) quote = null; continue; }
    if (c === "'" || c === '"') { quote = c; out += c; continue; }
    if (c === '|') break; // end of the join/union command; the rest of the pipeline follows
    if (c === '(') {
      const end = closingParen(q, i);
      if (end === -1) throw new Error('Unbalanced parentheses in the join/union subqueries; cannot apply the site scope.');
      const inner = q.slice(i + 1, end - 1);
      const sub = addSiteFilter(inner, siteId, { nested: true });
      if (sub.applied) n++; else skipped.push(sub.reason);
      out += `(${sub.query})`;
      i = end - 1;
      continue;
    }
    out += c;
  }
  if (!n) return { query: out + q.slice(i), applied: false, reason: LOOKUP_NOTE };
  return { query: out + q.slice(i), applied: true, reason: `added to ${n} subquer${n === 1 ? 'y' : 'ies'} of the ${m[1].toLowerCase()}${skipped.length ? ` (${skipped.length} left unchanged: ${skipped.join('; ')})` : ''}` };
}

/**
 * Narrow a query to one site; the LRQ API has no site field. Returns
 * { query, applied, reason }.
 *   - Event queries: `site.id='<siteId>'` is ANDed into the initial filter.
 *   - A leading | join or | union: the term is added to every subquery.
 *   - | datasource vulnerabilities / misconfigurations: `| filter siteId='<siteId>'`
 *     is inserted after the datasource command.
 *   - | dataset / | inputlookup: unchanged (applied: false); the S1-Scope header,
 *     which lrqRun always sends, selects the site's copy of the table.
 * Throws only where no correct narrowing exists (| datasource alerts and other
 * inventories without a site column), because silently answering for the whole
 * account is the failure this module exists to prevent.
 */
export function addSiteFilter(query, siteId, { nested = false } = {}) {
  const q = String(query ?? '');
  if (!siteId) return { query: q, applied: false, reason: 'no site in scope' };
  if (!/^\d+$/.test(String(siteId))) throw new Error(`site id must be numeric, got ${JSON.stringify(siteId)}`);
  const term = `site.id='${siteId}'`;
  const lead = q.trimStart();
  if (SUBQUERY_CMD.test(lead)) return siteFilterSubqueries(lead, siteId);
  const pipe = firstTopLevelPipe(q);
  const initial = (pipe === -1 ? q : q.slice(0, pipe)).trim();
  const rest = pipe === -1 ? '' : q.slice(pipe);
  if (!initial) {
    const cmd = (rest.match(/^\|\s*([A-Za-z_]+)/) || [])[1]?.toLowerCase();
    if (cmd === 'datasource') {
      const dm = /^\|\s*datasource\s+['"]?([A-Za-z_]+)['"]?(\s+from\s+(?:'[^']*'|"[^"]*"|\S+))?/i.exec(rest);
      const field = dm && DATASOURCE_SITE_FIELD[dm[1].toLowerCase()];
      if (!field) {
        if (nested) return { query: q, applied: false, reason: `| datasource ${dm?.[1] ?? ''} has no site column` };
        throw new Error(
          `| datasource ${dm?.[1] ?? ''} has no site column, so a site scope cannot narrow it. ` +
          'For alerts use uam_list_alerts with scopeIds and scopeType "SITE"; otherwise pass scope as "<accountId>" only.'
        );
      }
      const after = dm[0].length;
      return { query: `${rest.slice(0, after)} | filter ${field}='${siteId}'${rest.slice(after)}`, applied: true, reason: `| filter ${field} added after | datasource ${dm[1]}` };
    }
    if (cmd && PASSTHROUGH_COMMANDS.has(cmd)) {
      // | dataset / | inputlookup read a lookup table. Its rows have no site, but the
      // table itself is per scope, and the S1-Scope header (always sent) picks the copy.
      return { query: q, applied: false, reason: nested ? `| ${cmd} reads a lookup table` : LOOKUP_NOTE };
    }
    return { query: rest ? `${term} ${rest}` : term, applied: true, reason: 'added as the initial filter' };
  }
  // Parenthesise the caller's filter so a top-level OR keeps its meaning; the
  // closing paren sits on its own line so a trailing // comment cannot eat it.
  return { query: `${term} and (${initial}\n)${rest ? ` ${rest}` : ''}`, applied: true, reason: 'ANDed into the initial filter' };
}

/** True for the launch refusal a token gets for an account it cannot reach.
 *  Measured 2026-10-09: HTTP 500 "You do not have access to this account" with
 *  accountIds alone, HTTP 403 "Not allowed to access requested resource" when the
 *  S1-Scope header names it too (which lrqRun sends). */
export function isAccountAccessRefusal(status, body) {
  const b = String(body || '');
  return (status === 500 && /do not have access to this account/i.test(b))
    || (status === 403 && /(do not have access to this account|not allowed to access requested resource)/i.test(b));
}
