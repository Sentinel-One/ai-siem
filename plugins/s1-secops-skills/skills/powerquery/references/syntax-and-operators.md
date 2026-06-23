# Syntax and operators

Full reference for PowerQuery expression syntax. Read when the query needs anything beyond straightforward filtering and grouping.

## Table of contents

1. Boolean / arithmetic operators
2. Text operators — `contains`, `matches`, `in`, `=`, wildcards
3. Shortcut fields (`#ip`, `#hash`, etc.)
4. Identifier rules and escaping
5. Regex dialect and escaping levels
6. Date / time expressions
7. Short-circuit OR behavior
8. Type coercion rules

---

## 1. Boolean and arithmetic operators

| Operator | Form |
|---|---|
| AND | `a b`, `a and b`, `a AND b`, `a && b` |
| OR | `a or b`, `a OR b`, `a || b` |
| NOT | `not a`, `NOT a`, `!a` |
| Arithmetic | `+ - * / %` (modulo), unary `-x` |
| Comparison | `< <= > >= == != =` (= is synonym for ==) |
| Ternary | `cond ? then : else` (put spaces around the `:` — it can be parsed as an identifier character otherwise) |

Parentheses work as expected: `a AND (b OR c)`.

---

## 2. Text operators

### `contains` — substring search

```
src.process.cmdline contains 'powershell'
src.process.cmdline contains ('powershell', 'pwsh', 'cmd')     // OR of multiple
src.process.cmdline contains:matchcase 'PowerShell'            // case-sensitive
```

Case-insensitive by default. Cannot be used on numeric values. The OR form is much faster than chaining `contains … OR contains …`.

### `matches` — regex

```
src.process.cmdline matches '\\w+\\.exe'
src.process.cmdline matches ('regex1', 'regex2')               // OR of multiple
src.process.cmdline matches:matchcase 'CaseSensitive'
```

Case-insensitive by default. Regex has a 1,000-byte ceiling. Double-escape special characters (`\\d`, `\\s`, `\\\\` for a literal backslash). See §5 for escaping levels.

### `in` — exact equals any of

```
event.login.type in ('NETWORK', 'NETWORK_CLEAR_TEXT', 'CACHED_REMOTE_INTERACTIVE')
severity in (3, 4, 5)                    // numbers / booleans unquoted
event.login.type in:anycase ('network')  // case-insensitive variant
```

Default is case-sensitive (opposite of `contains`). Cannot match null. Quote strings; leave numbers and booleans bare.

### Equality and inequality

```
endpoint.name = 'DC-1'                   // exact equal (case-sensitive for strings)
indicator.name != 'RawVolumeAccess'
indicator.name !=*                       // never valid; use !(x=*) for is-null
```

### Wildcards

There are three distinct `*` idioms — they look similar but mean different things:

```
// 1. FIELD PRESENCE / ATTRIBUTE WILDCARD
dataSource.name = *                      // "field is present/non-null" — use as query opener or filter
indicator.category = *                   // same pattern; works for any field
!(indicator.category = *)               // field is null / missing

// 2. ALL-COLUMN TEXT SEARCH (initial filter only)
* contains 'evil.com'                    // find text in ANY indexed field — initial filter only
* matches 'regex'                        // regex across all indexed fields — initial filter only
$"regex"                                 // shorthand for message matches "regex" (initial filter only)

// 3. EMPTY INITIAL FILTER (all events)
| group ct=count() by event.type         // start with | — no initial predicate means all events
```

Key facts about `*`:
- `*` by itself is NOT a valid filter. `*` alone returns HTTP 500 ("Don't understand [*]"). Never use `*` as the only initial token.
- **`field = *`** (attribute wildcard) checks whether a specific field is present/non-null. Use `dataSource.name=*` as a query-opener for aggregations over all events that have that field. Confirmed working on live tenant.
- **`* contains` / `* matches`** (all-column search) searches across ALL indexed fields. Only works in the **initial filter** (before the first `|`). Not valid in `| filter …` after a pipe, not in Alerts, not in dashboards. Much faster than `message contains` on JSON-blob sources.
- These two idioms are NOT interchangeable: `dataSource.name=*` checks a specific field for null; `* contains 'value'` searches all fields for a substring.

### Phrasebook: natural-language asks to canonical operator

When a user describes the search in English, the phrasing usually maps to one of a few PQ idioms. Reach for the canonical form on the first draft instead of guessing field names or scanning the raw `message` blob.

| User asks for | Canonical PQ |
|---|---|
| "all column search" / "search all fields" / "search everything for X" / "anywhere in the event" / "wherever it appears" | `* contains 'value'` (initial filter only) |
| "regex across every field" / "pattern match anywhere" | `* matches 'regex'` (initial filter only) |
| "query all events for a source" / "aggregate over all logs" / "group by field across everything" | `dataSource.name=* \| group count=count() by dataSource.name` — field presence as opener |
| "is this field set" / "rows where X is populated" | `field = *` |
| "field is missing / null / empty" | `!(field = *)` |
| "field equals one of these values" (case-sensitive) | `field in ('a','b','c')` |
| "field equals one of these values" (case-insensitive) | `field in:anycase ('a','b','c')` |
| "find the substring, case doesn't matter" | `field contains 'value'` |
| "find the substring, exact case" | `field contains:matchcase 'Value'` |
| "OR over several substrings on one field" | `field contains ('a','b','c')` |
| "all events" / "no filter" | start the query with `|` (empty initial filter); never use `*` alone |

Three common mistakes the phrasebook prevents:

- "Search all data" sounds like a scope instruction (every site, all time) but is almost always a field-coverage instruction (every column). Map to `* contains`, not to a wider time range or `tenant=true` request body.
- Reaching for `message contains 'value'` for value-anywhere lookups is a performance cliff on JSON-blob sources. `* contains 'value'` indexes across parsed fields and is dramatically faster. See `references/pitfalls.md` → "Reaching for `message contains` on a JSON-blob source".
- Confusing `field=*` (attribute wildcard / field-is-present check) with `* contains 'value'` (all-column text search). They are different operators: `dataSource.name=*` is a null check on one field; `* contains 'value'` searches all fields for a substring.

---

## 3. Shortcut fields

Preceded by `#`, these search across multiple related fields at once. Only valid for *field names*, not command names.

| Shortcut | Matches |
|---|---|
| `#cmdline` | All process command-line fields |
| `#dns` | All DNS request/response fields |
| `#filepath` | All file path fields |
| `#hash` | Any MD5, SHA1, or SHA256 field |
| `#ip` | All IP address fields (src / dst / endpoint / etc.) |
| `#md5` | All MD5 fields |
| `#name` | All process name fields |
| `#sha1` | All SHA1 fields |
| `#sha256` | All SHA256 fields |
| `#storylineid` | All storyline ID fields (src, tgt, src.parent, tgt.parent, osSrc, etc.) |
| `#uid` | All UID fields |
| `#username` | All process user fields |

```
#hash = '44d88612fea8a8f36de82e1278abb02f'         // find an IOC hash anywhere
#ip = '198.51.100.7'                                 // any IP match
#storylineid = 'F5BA787CED1FF38A' | limit 100
```

Shortcuts work in EDR and XDR data views. They are not supported for command names (so `| group … by #name` is invalid).

---

## 4. Identifier rules

- Identifiers can contain `.`, `-`, `_`, and `:`. A hyphen is OK inside a name (`k8s-controller`) but will be read as subtraction if separated by spaces.
- Colons inside a ternary need spaces: `cond ? a : b` (without spaces the `:` can be mistaken for part of an identifier).
- To escape other punctuation in a field name, precede with a backslash: `field\#name`.
- Strings use single or double quotes; escape embedded quotes with backslash: `"with \"nested\" quotes"`.
- Numbers can include underscores for readability: `1_000_000`, `1_048_576`.
- Comments start with `//` and run to end of line: `let x = 1  // this is a comment`.

---

## 5. Regex dialect and escaping levels

The engine uses `java.util.regex` semantics (also compatible with Python `re`). Some operations are unavailable:

- **Lookaheads and lookbehinds are NOT supported** (performance reasons).
- **Named capture groups are NOT supported.** Use positional groups and `\1`, `\2` (in agent parsers) or `$1`, `$2` (in SDL parsers).
- Default is case-insensitive. Append `:matchcase` for case-sensitive.
- Max regex length: 1,000 bytes.

### Escaping levels

Double-escaping is the norm because the string literal passes through two parsers (one for the PQ string, one for the regex engine).

| Intent | In `$"regex"` shorthand | In `field matches "regex"` |
|---|---|---|
| Digit | `\d` | `\\d` |
| Literal backslash | `\\` | `\\\\` |
| Literal dot | `\.` | `\\.` |
| Windows path `C:\Windows\Temp\xxxx.tmp` | n/a (shorthand is for message field) | `^C:\\\\Windows\\\\Temp\\\\[a-z]{8}\\.tmp$` |

Rule of thumb: *if you're using `matches` against a field, double every backslash*. The only place single-escaping works is the `$"…"` shorthand (which only searches the `message` field).

In some edge cases (parser Redaction Rules, some nested contexts), you'll see four backslashes (`\\\\`). Test escaping in-console before committing to it.

### Character classes, quantifiers, and anchors

Standard PCRE-style: `\d \w \s \D \W \S`, `[a-z] [^a-z]`, `+ * ? {n} {n,m} {n,}`, `^ $`, `|` for alternation, `(…)` for groups.

---

## 6. Date / time expressions (Search view)

When specifying a time range in Event Search (and implicitly for PowerQuery time pickers), these formats are accepted:

- Relative: `4 hours`, `3d`, `1w`, `5m`, `30s`. Abbreviations: `s sec secs second seconds / m min mins minute minutes / h hr hrs hour hours / d day days`.
- Absolute: `10:30 AM`, `14:30`, `March 3`, `4 Mar 2023`, `2022-10-11T10:45:00+0800` (ISO), `Monday UTC`, `1346261004000` (ms since epoch).
- Time-span shortcut: `From=3d To=+16h` means "16-hour window starting 3 days ago".
- Start is inclusive; End is exclusive. Leave End empty to mean "now".

When calling the Purple MCP `powerquery` tool, pass ISO-8601 with an explicit offset: `2026-04-19T06:00:00Z` or `2026-04-19T06:00:00-04:00`. Use the `get_timestamp_range` helper to build a range relative to now.

---

## 7. Short-circuit OR returns the first truthy value

`||` and `OR` don't return booleans; they return the first truthy operand. Falsy values: `null`, `0`, `false`, `""`, `NaN`. Everything else is truthy (including `"0"` and `"false"` — those are non-empty strings).

```
| let first_name = preferred_name || legal_name || 'Unknown'
```

This is handy for coalescing. It's also a gotcha if you expected a boolean — use `bool()` to force a boolean.

---

## 8. Type coercion rules

The engine works with booleans, 64-bit floats, UTF-8 strings, and null.

- **Arithmetic**: yields `NaN` unless both inputs are numbers. Exception: `+` with at least one string argument converts the other to string and concatenates.
- **Comparison**: numbers compare numerically, strings compare lexicographically, booleans compare with `false < true`, two nulls are equal. Mixed types produce undefined results — coerce explicitly with `number(x)` or `string(x)`.
- **Boolean context**: `null`, `0`, `""` → false. Everything else → true. Use `bool()` to be explicit.

In `group` and `let`, a reference to a field not present in an event yields `null` (not an error).
