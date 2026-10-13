/**
 * Redaction for anything the server writes to stderr or returns to the client.
 *
 * Two passes:
 *   1. Exact configured secret values (console token, HEC token, VT key)
 *      are replaced wherever they appear. Always on.
 *   2. Authorization-style patterns ("ApiToken <x>", "Bearer <x>", "Splunk <x>",
 *      "Basic <x>") are masked even when the value is not a configured one,
 *      e.g. a token echoed back inside an upstream error body. Only for errors
 *      and logs: on successful tool output it would corrupt legitimate content
 *      (a parser that mentions "Bearer tokenization", a dashboard note saying
 *      "Basic authentication"), and a read-edit-write cycle would persist the
 *      damage. Callers pass { patterns: false } for success output.
 */

import { secretValues } from './credentials.js';

// Token-shaped values only: at least 16 characters of token alphabet, so prose
// such as "Bearer tokenization" or "Basic authentication" is left alone.
const AUTH_PATTERN = /\b(ApiToken|Bearer|Splunk|Basic)(\s+)(?=[A-Za-z0-9._~+/=-]*[0-9._~+/=-])[A-Za-z0-9._~+/=-]{16,}/g;

export function redact(text, { patterns = true } = {}) {
  if (text === null || text === undefined) return text;
  let s = String(text);
  let secrets = [];
  try { secrets = secretValues(); } catch { /* never let redaction throw */ }
  for (const v of secrets) {
    if (v && s.includes(v)) s = s.split(v).join('[REDACTED]');
  }
  if (!patterns) return s;
  return s.replace(AUTH_PATTERN, (_m, scheme, ws) => `${scheme}${ws}[REDACTED]`);
}
