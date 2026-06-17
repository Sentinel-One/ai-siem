# SDL Parser Syntax — Full Reference

SDL parsers are **augmented JSON**: unquoted keys are allowed, string values can span lines, and `//` / `/* */` comments are supported. The file is stored at `/logParsers/<NAME>` on the SDL tenant and applied by name at HEC ingest (`parser: <NAME>` header).

## Table of contents

1. [Top-level keys](#top-level-keys)
2. [Formats](#formats)
3. [Field-matcher syntax](#field-matcher-syntax)
4. [Patterns](#patterns)
5. [Attributes (tagging)](#attributes-tagging)
6. [Line groupers (multi-line)](#line-groupers-multi-line)
7. [Rewrites](#rewrites)
8. [Special fields: timestamp, severity, message](#special-fields-timestamp-severity-message)
9. [Discard, halt, repeat, skipNumericConversion, intermittentTimestamps](#behavior-flags)
10. [Associations (correlate non-adjacent lines)](#associations)
11. [Aliases](#aliases)
12. [Parse limits](#parse-limits)

---

## Top-level keys

```js
{
  timezone: "UTC",
  attributes: { vendor: "FortiNet", dataset: "fortigate" },
  patterns:  { ts: "\\d{4}-\\d{2}-\\d{2}T[0-9:.]+Z" },
  lineGroupers: [ { start: "^\\[", continueThrough: "^\\s+at " } ],
  formats: [ /* see below */ ],
  mappings: { mappings: [ /* see references/mappers.md */ ] },
  aliasTo: "otherParser"   // short-circuit: everything else ignored
}
```

- `timezone` applies when the parsed timestamp itself has no offset. Prefer IANA names (`America/New_York`) so DST is respected; avoid `EST` / `PST` which are fixed offsets.
- `attributes` at the top level apply to every event this parser produces.
- `aliasTo` is mutually exclusive with the rest — it re-points this name to another parser file. Aliases cannot chain.

## Formats

`formats` is a list; each item can be a raw string (shorthand for `{ format: "..." }`) or a full object:

```js
{
  id: "tcp-body",
  attributes: { protocol: "tcp" },
  format: ".*proto=TCP $src$:$spt$ -> $dst$:$dpt$",
  discard: false,
  halt: true,
  repeat: false
}
```

Formats are tried in declaration order against the **whole line**. A format that doesn't match simply doesn't apply; a format that matches merges its captures into the event. When `halt: true`, matching stops after the first match.

> **The parser only sees `message`.** Ingest-time attributes added by collectors, relays, or HEC ingest (`app_id`, `cluster`, `region`, custom enrichments, etc.) are NOT visible to format strings, format-level `discard:` filters, or `rewrites` regex inputs. They ARE visible to `mappings` predicates and `mappings` op `from:` paths, since mappings run after parsing. If you need to gate a format on a vendor or app sentinel, encode it in the message body or use a `format: "..."` that anchors on a string the message contains. Don't try to read those attributes from inside the format engine.

> **There is NO `from:` directive on `format` entries.** Only the keys listed in the example object above (`id`, `attributes`, `format`, `discard`, `halt`, `repeat`, plus `rewrites`) are honored. A spurious `from: "<somefield>"` next to `format:` is silently ignored, and the format is run against the raw line — which, combined with a greedy regex like `[\s\S]+`, can clobber every captured field with the entire log message on every event. The `from:` key only exists inside `mappings` ops (`{rename: {from, to}}`, `{copy: {from, to}}`, etc.). If you want a format-like rewrite to operate against a specific captured field, you have two real options: (1) a `rewrites` entry on the same format with `input: "<fieldname>"`, or (2) a follow-up `mappings` op that reads from that field.

### Fragment formats

A format that starts with `.*` matches *anywhere* in the line, not just the start. This is the "line fragment" idiom used to share captures across related event variants. Combined with `halt: true` it's how you build "first match wins" logic.

### Anchoring fragment captures (regex behavior)

When a fragment format pulls a token out of the middle of a line, the prefix's regex must commit the engine to the right position. Three related rules:

1. **The literal anchor must live INSIDE the prefix's regex, not as separate format-string text.** A pattern like `$_pre{regex=[\s\S]*}$/actuator/health$_suf{regex=[\s\S]*}$` (greedy `[\s\S]*` followed by literal `/actuator/health` between the two field markers) does NOT match. The format engine commits each captured field's regex independently and does not backtrack the previous field once a literal-text gap has been crossed. The working form puts the literal inside the regex of the prefix itself: `$_pre{regex=[\s\S]*\/actuator\/health}$$_suf{regex=[\s\S]*}$`. Phase-10-style IOC formats do this with anchors like `[\s\S]*X-Forwarded-For=[\[]?` baked into the prefix regex.

2. **`[\s\S]*ANCHOR` is greedy and lands on the LAST occurrence of `ANCHOR`.** That is correct when the desired token always follows the rightmost anchor on the line — Phase-5-style Dropwizard formats (`[\s\S]*\[dw-[0-9]+ - `) work because `[dw-N - ` is unique to the request-line bracket. It fails when the anchor is too generic: `[\s\S]*\[` followed by a capture of `UT-[0-9]+` will fail on any line where a later `[` exists (e.g. `[#033[36mClassName#033[0;39m]` ANSI brackets), because greedy match commits to the last `[` and `UT-` does not follow there. Fix: make the anchor multi-character and discriminating (`[\s\S]*\[UT-` so only the bracket that actually opens a UT- token is matched), accepting that the discriminating literal is consumed by the anchor and your capture holds only the trailing portion (`$user_task_id_num{regex=[0-9]+}$`).

3. **DO NOT use `[\s\S]*?` lazy quantifier at the start of a prefix regex.** Same family as the documented `.*?` orphaned-`?` trap, but no error: the format silently matches almost nothing (tenant-validated 2026-05-13, `[\s\S]*?` prefixes hit 365 of ~190K events when greedy + literal anchor hit close to all). The SDL regex engine does not backtrack the lazy quantifier across field boundaries to find a position where the next field's regex matches. Always use greedy `[\s\S]*` plus a discriminating literal anchor (rule 2 above). If you actually need first-match-on-line semantics, encode it with a literal that only appears once per line (e.g. `[\s\S]*\"merchant_transaction_id\":\"` to anchor on a unique JSON key), do not reach for `*?`.

## Field-matcher syntax

Inside a format string, `$name=pattern{opt1}{opt2}$` captures a named field. All parts except `$name$` are optional:

```
$fieldName  = patternName  {parse=json}  {regex=\\d+}  {attrWhitelist=foo.*}  {timezone=UTC}  $
```

- **`patternName`** — a name from `patterns:`, or a predefined pattern: `digits`, `number`, `alphanumeric`, `identifier`, `quotable`, `quotableNoEscape`, `quoteOrSpace`, `quoteOrSpaceNoEscape`, `json` (brace-matched with nesting support).
- **`{regex=...}`** — inline regex. Metacharacters **must be double-escaped** (augmented JSON eats one backslash): `\\d`, `\\s`, `\\.`, `\\\\`.
- **`{parse=directive}`** — apply a sub-parser to the captured value. See `parse-directives.md`.
- **`{attrWhitelist=rx}` / `{attrBlacklist=rx}`** — after a sub-parse, filter which generated subfields are kept.
- **`{timezone=...}`** — field-level override when the field is `timestamp`.

### Default pattern quirks

A `$field$` followed by a **space** with no explicit pattern defaults to the `quotable` pattern (stops at whitespace, honors embedded quotes). A `$field$` followed by **`\"`** enables backslash-escape handling in the capture. Adjacent `$a$$b$` with no delimiter is invalid unless `$a$` has a pattern or regex that bounds it.

### Reserved field names

- `message` — the raw event text. Cannot be captured into from a format. Can be dropped with `discardAttributes: ["message"]`.
- `timestamp` — parsed as the event time (see *Special fields*).
- `severity` — mapped to 0–6 (see *Special fields*).
- `parser` — filled in by the ingest pipeline.
- `host` / `serverHost` — set from the `server-host` upload header.

### Escaping literals

- Literal `$`: `\$$` (backslash, dollar, terminator).
- Literal single space: `\\ ` (backslash-space); a bare space matches `\s+`.
- Literal backslash: `\\\\`.

## Patterns

Named regex fragments. Define once, reuse in many formats:

```js
patterns: {
  ts:      "\\d{4}-\\d{2}-\\d{2}T[0-9:.]+Z",
  ipv4:    "\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}",
  ipv46:   "(\\d{1,3}(\\.\\d{1,3}){3}|[0-9a-f:]+)"
},
formats: [
  "$timestamp=ts$ $src=ipv46$ -> $dst=ipv46$"
]
```

The predefined patterns (no need to declare):

| Name | Matches |
|---|---|
| `digits` | `\d+` |
| `number` | integer or float, signed |
| `alphanumeric` | `[A-Za-z0-9]+` |
| `identifier` | `[A-Za-z_][A-Za-z0-9_.-]*` |
| `quotable` | bare token, or balanced double-quoted string with `\"` escape |
| `quotableNoEscape` | same but `\` is literal |
| `quoteOrSpace` | value up to next space or matching quote |
| `quoteOrSpaceNoEscape` | same, no escape handling |
| `json` | brace-matched JSON object with nesting |

## Attributes (tagging)

```js
attributes: { vendor: "FortiNet", dataset: "fortigate" }
```

Constant key/value pairs attached to every matching event. Can live at the top level (applies to all formats in this parser) or on an individual format (applies only when that format matches). Use for vendor/product tagging, tenant stamps, and dataset routing.

### Per-format override

A format's `attributes:` block **overrides** the top-level attributes for events that match that format. This is the idiomatic way to produce multiple OCSF classes from one parser (e.g., Abnormal Security's parser emits `class_uid: 2001` for email events and `class_uid: 3002` for authentication events from the same parser) — set the common attributes at top level, then let each format override `class_uid`, `activity_id`, `severity_id`, and `activity_name`.

The 4 mandatory attributes (`dataSource.category` hardcoded to `"security"`, `dataSource.name`, `dataSource.vendor`, `metadata.version`) should live at the parser-root `attributes:` block, not per-format. OCSF subtype fields (`activity_id`, `activity_name`, per-subtype `severity_id`) should live per-format. Per-format `attributes:` override parser-root `attributes:`, which is the mechanism for one parser fanning out to multiple OCSF classes (e.g. Windows Event 4624 → Authentication, 4720 → Account Change). `metadata.version` may also be overridden per-event from inside a `mappings.constant` op when the source carries its own schema version.

### `class_uid` string vs integer

OCSF defines these as integers. Many ai-siem catalog parsers emit them as strings (`"class_uid": "4001"`). Both survive ingest. Prefer integers in new work — integer form keeps PowerQuery filters simple (`class_uid = 4001` rather than `class_uid = '4001'`).

## Line groupers (multi-line)

Combine adjacent lines into one logical event *before* formats run. Max 100,000 chars per joined event.

```js
lineGroupers: [
  {
    start: "^\\[\\d+-\\d+-\\d+ ",     // required: the "new event starts here" regex
    continueThrough: "^\\s+at "        // OR continuePast / haltBefore / haltWith
  }
]
```

| Continuation mode | Behavior |
|---|---|
| `continueThrough` | Keep accumulating while following lines match the pattern (e.g., stack traces indented). |
| `continuePast` | Accumulate matches, then one more line (e.g., `\`-terminated continuation). |
| `haltBefore` | Stop *before* the next line matching the pattern (new-message marker). |
| `haltWith` | Stop *at and including* the line matching the pattern (e.g., statement `;` terminator). |

## Rewrites

Applied *after* formats extract fields. Array on a format object:

```js
rewrites: [
  { input: "message", match: "password=[^& ]*", replacement: "password=[REDACTED]", replaceAll: true },
  { input: "rawTs",   match: "^(\\d+)-(\\d+)-(\\d+)T(.*)$", replacement: "$1/$2/$3 $4", output: "timestamp" },
  { input: "message", match: "user=(\\w+)", replacement: "$1", output: "user", outputIfNoMatch: false },

  // Time between two timestamps (seconds):
  { action: "timeDelta", startTime: "connStart", endTime: "connEnd", output: "durationSec" },

  // PowerQuery-driven enrichment (S-24.4.5+):
  { action: "computeFields",
    expression: "| lookup city_code from geo_table by src_ip | let risk_score = if(severity >= 5, 10, 1)" }
]
```

Notes:
- `$1..$n` reference regex capture groups.
- `replaceAll: true` replaces every match, not just the first.
- `outputIfNoMatch: false` suppresses the output field when the regex doesn't match (default is to copy `input` verbatim).
- `timeDelta` doesn't yet support a per-rule `timezone` — set it at parser level or inline in the source timestamp.
- `computeFields` can read from lookup tables, add/overwrite fields, and drop events via `discard: { filter: "..." }` on the format. Supported PQ subset: `columns`, `filter`, `let`, `lookup`, `parse` plus most Array/Geolocation/Network/Numeric/String/Time/Timestamp functions. Excluded array functions: `array_agg`, `array_agg_distinct`, `array_from_json`, `array_to_json`, `extract_matches`, `extract_matches_matchcase`.

## Special fields: timestamp, severity, message

**`timestamp`** — the event time. SDL recognizes most common forms. Timezone precedence: a parsed `timezone` field > `{timezone=...}` option on the `$timestamp$` matcher > parser-level `timezone` > GMT. Prefer UTC at the source.

**`severity`** — mapped to an internal integer + label:

| String | Int | Label |
|---|---|---|
| `fatal` | 6 | Critical |
| `error` | 5 | Critical |
| `warn` | 4 | High |
| `info` | 3 | Medium |
| `fine` | 2 | Low |
| `finer` | 1 | Info |
| `finest` | 0 | No severity |

Missing → `info` (3).

**`message`** — raw event text, reserved. Cannot be captured into. Rewrite rules can modify a portion (a rule whose regex matches the entire value is silently ignored). Drop it via `discardAttributes: ["message"]` — highly recommended for JSON-parsed logs to reduce storage.

## Behavior flags

- `discard: true` on a format — drop events matching the format. Discarded events don't count toward log volume.
- `discard: { filter: "keep = false" }` (S-24.4.5+) — conditional drop driven by a `computeFields` rewrite that sets a boolean field.
- `halt: true` — after this format matches, stop trying further formats on the same line.
- `repeat: true` — keep re-applying this format at the position after the last match (required for key/value catch-alls).
- `skipNumericConversion: true` — preserve string values that look numeric (e.g., postal code `00187`). Per-format flag.
- `intermittentTimestamps: true` — parser-level; for logs that emit a timestamp only when the clock rolls over. Lines without a timestamp inherit the most recent one instead of the ingest time.

## `discardAttributes` — placement matters

`discardAttributes: ["field1", "field2", ...]` accepts a list of field names to drop from the final event. There are TWO valid placements with different scopes:

**Per-format (preferred for format-capture scratch fields).** Place `discardAttributes` as a sibling key to `format:` inside an individual format object:

```js
formats: [
  {
    format: "$_pre{regex=[\\s\\S]*\\[dw-[0-9]+ - }$$http_method{regex=[A-Z]+}$ $_tail{regex=[\\s\\S]*}$",
    discardAttributes: ["_pre", "_tail"]
  }
]
```

This is the form the built-in `json` parser uses: `formats: [ { format: "$json{parse=json}$", repeat: true, discardAttributes: ["message"] } ]`. Reliably drops any field the format itself captured into a `$name$` marker.

**Parser-root (for fields produced by `{parse=json}` / `{parse=dottedJson}` flat expansion).** Place `discardAttributes` as a top-level key on the parser object:

```js
{
  timezone: "UTC",
  attributes: { ... },
  discardAttributes: ["flipkart_not_secure", "upstream_addr", "pipe"],
  formats: [ ... ]
}
```

Use this for vendor-noise keys that show up at the event root because a `{parse=json}` directive flattened them out of the source body. Parser-root scope does NOT reliably drop fields created by named-capture markers inside format strings — those leak through on this tenant despite being listed at the root. The fix is to move them into the per-format `discardAttributes` of the format that creates them. Tenant-validated 2026-05-13.

**Neither scope drops `{parse=gron}` outputs at the event root.** Gron-expanded keys (`host`, `facility`, `sndr` directly on the root) require `mappings.drop` or `mappings.drop_tree`. Tenant-validated May 2026.

## Associations

Join non-adjacent lines that share a correlation key (e.g., request-start + request-end). Possibly deprecated — check with Support before relying on it. Association state is purged ~60 seconds after first sighting.

```js
{
  format: "started req $requestId$",
  association: { tag: "req", keys: ["requestId"], store: ["src"] }
},
{
  format: "ended req $requestId$",
  association: { tag: "req", keys: ["requestId"], fetch: ["src"] }
}
```

## Aliases

```js
{ aliasTo: "json" }
```

Mutually exclusive with everything else. Aliases cannot chain (target must be a real parser).

## Parse limits

- Per-event parse limit: **just under 50,000 characters.** Oversize events are truncated *before* parsing.
- Per-joined event via line groupers: **100,000 characters.**
- HEC ingest enforces per-request and per-day size limits (see the HEC tooling for current caps).
