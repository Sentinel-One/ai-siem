/**
 * JSON.parse that keeps integers beyond Number.MAX_SAFE_INTEGER exact.
 *
 * SentinelOne APIs return some 17-19 digit ids as JSON numbers (for example
 * SDL shareResource's dashboard id). Plain JSON.parse rounds them, so
 * 25738899845066752 came back as 25738899845066750 and a follow-up get or
 * delete addressed a dashboard that does not exist (verified live 2026-10-08).
 * Unsafe integers are returned as their exact source text (a string), which is
 * how every id is used anyway. Uses the reviver `context.source` argument
 * (JSON.parse source text access, Node >= 21); on older runtimes it degrades
 * to plain JSON.parse.
 */
export function parseJsonExact(text) {
  return JSON.parse(text, (_key, value, context) => {
    // Only integer LITERALS: 1e21 or 1.5e300 are floats in the source and stay numbers.
    if (typeof value === 'number' && Number.isInteger(value) && !Number.isSafeInteger(value)
        && context && typeof context.source === 'string' && /^-?\d+$/.test(context.source)) {
      return context.source;
    }
    return value;
  });
}
