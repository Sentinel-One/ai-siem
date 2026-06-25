# `{parse=...}` Sub-parser Directives

A `{parse=X}` directive inside a field matcher runs a secondary parser on the captured value, generating additional fields prefixed with the parent field name. Use `{attrWhitelist=rx}` / `{attrBlacklist=rx}` to filter which generated subfields are kept.

> **NOT a valid directive: `{parse=keyValue}`.** It returns `400: Syntax error: Unknown parser "keyValue"`. The `keyValue` built-in parser exists, but it is only usable as a root-level `aliasTo: "keyValue"` (a one-line alias parser). To extract key=value pairs INSIDE a format string, use the repeating idiom `".*$_=identifier$=$_=quoteOrSpace$"` with `repeat: true` — see SKILL.md decision-tree step 5 and `examples/03-key-value.json`. The leading `.*` is mandatory; without it the format anchors at position 0 of the message and captures nothing on any line that doesn't start with a bare `identifier=`. Tenant-validated 2026-05-26 on FortiGate syslog. **None of the other built-ins** (`accessLog`, `cloudfront`, `json`, `dottedJson`, `dottedEscapedJson`, `elb-access`, `heroku-logplex`, `leveldbLog`, `mysqlGeneralQueryLog`, `mysqlSlowQueryLog`, `postgresLog`, `redshift`, `s3_bucket_access`, `spot_instance_data`, `systemLog`) are accepted as `{parse=...}` directives either — they're root-level parsers only. The valid `{parse=X}` set is the one documented below (URI variants, JSON variants, key=value list, time/byte/syslog parsers).

> **Subfield naming convention (per SDL KB 000006743):** generated fields are named `<parentFieldName><CapitalizedFirstLetterOfKey><restOfKey>`, with the source key's first letter uppercased and concatenated to the parent field name. There is NO underscore, dot, or `Query_` separator between prefix and key. Examples for a field captured as `uri`:
> - `uriPath` (the parsed URL path component, from `{parse=uri}`)
> - `uriFoo` for query param `foo` (from `{parse=uri}` or `{parse=uriAttributes}` on `?foo=...`)
> - `uriBusinessProfile` for query param `businessProfile`
> - For a field captured as `details`: `detailsApple`, `detailsBanana`, etc.
>
> Likewise for `{parse=json}` / `{parse=dottedJson}`: a field captured as `details` parsing `{"foo":"hello"}` generates `detailsFoo` (camelCase) or `details.foo` (dotted), not `details_foo`. Verify the exact field name with a sample query if you are unsure — the obvious-looking `<prefix>_<key>` form does NOT exist on this engine.

> **`attrWhitelist` / `attrBlacklist` scope** — these only filter the SUBFIELDS produced by the `{parse=...}` directive, not top-level fields you captured by name in the format string. To drop a top-level field you named explicitly, use `discardAttributes: ["fieldname"]` at the parser root, NOT a blacklist on the parse directive. Catalog parsers like `cisco_firewall-latest` show liberal use of blacklists to drop noisy nested arrays (`{attrBlacklist=(targetResources)}`, `{attrBlacklist=(threatsInfoMap|messageParts)}`); the same authors use `discardAttributes: ["message"]` separately to drop the raw event body.

> **Pipe vs parenthesized list syntax for `attrBlacklist=`** — both work in the wild:
> - Parenthesized: `{attrBlacklist=(field1|field2|field3)}` — common in Microsoft Eventhub parsers.
> - Bare list: `{attrBlacklist=field1|field2|field3}` — common in FortiGate / Cisco parsers.
> - Single field: `{attrBlacklist=tranip}` — no delimiters needed.
> Pick one style per parser for consistency.

## URI and URL-like values

| Directive | Behaviour |
|---|---|
| `uri` | Split a URL into `Path` plus each query parameter as its own field (subfield naming above). |
| `uriMultivalue` | Same but duplicate query keys become comma-joined strings instead of overwriting. |
| `uriAttributes` | URL-encoded `k=v&k=v` string with no path. Generates one subfield per key, named `<prefix><CapitalizedKey>`. |
| `urlAttributes` | Alias of `uriAttributes`. |
| `uriAttributesMultivalue` / `urlAttributesMultivalue` | Multivalue variants. |

> **Parent capture is consumed, not preserved.** When `{parse=uri}` or `{parse=uriAttributes}` runs, the parent field's captured value disappears from the event after parsing on at least some current tenants (validated April 2026 against a Singularity Data Lake tenant with relative URLs). Only the generated subfields remain. If you need the raw URL/query string in addition to the parsed pieces, capture it twice: once with the parse directive, once into a sibling scratch field that you keep, and `rename` the scratch one to your preferred OCSF target in `mappings`. Equivalent workaround: split path and query in the format string itself (`$path{regex=[^? ]+}$\??$qs{regex=[^ ]*}{parse=uriAttributes}$`) so the path stays as a top-level field.

> **Relative URLs and `{parse=uri}`.** `{parse=uri}` is documented as splitting a "URL" into path + query, and works correctly for absolute URLs (`http://host/path?foo=bar`). For relative URLs (`/path?foo=bar`), behaviour on tested tenants is to emit `<prefix>Path` only and silently drop the query subfields. Prefer `{parse=uriAttributes}` on the query-string portion (split manually with regex), which reliably emits `<prefix><CapitalizedKey>` siblings regardless of whether a scheme/host is present.

## JSON bodies

| Directive | Flattening |
|---|---|
| `json` | CamelCase: `{"a":{"b":1}}` → `ab=1`. |
| `dottedJson` | Dotted: `{"a":{"b":1}}` → `a.b=1`. |
| `gron` | Like `dottedJson` but emits empty-prefix keys when captured into an empty name. Used by the PARSER_TEMPLATE "capture everything into `unmapped.*` then mappings" pattern. |
| `escapedJson` | Strip one backslash-escape layer before parsing. |
| `dottedEscapedJson` | Dotted + one-layer unescape. |
| `urlEncodedJson` | URL-decode first. |
| `dottedUrlEncodedJson` | Dotted + URL-decode. |
| `base64EncodedJson` | Base64-decode first. |
| `dottedBase64EncodedJson` | Dotted + base64. |

> **No hex / base16 decoder exists.** The directives cover base64 and URL decoding, but there is no `{parse=hex}` / `{parse=base16}`, and the PowerQuery subset available to `computeFields` has no position-aware hex-to-string function either. Hex-encoded payloads, e.g. auditd `proctitle` and NUL-separated hex command lines, cannot be decoded to ASCII inside a parser. Source the readable value from a plaintext field if one exists (auditd's `EXECVE` arg vector is plain ASCII), or decode downstream at query / Hyperautomation time. Tenant-validated 2026-06-01.

### The gron-capture idiom

```js
formats: [
  { format: "$unmapped.{parse=gron}$",
    rewrites: [ { input: "unmapped.timestamp", output: "timestamp",
                  match: ".*", replace: "$0" } ] }
],
mappings: {
  version: 1,
  mappings: [{
    predicate: "true",
    transformations: [
      { rename: { from: "unmapped.source.ip", to: "src_endpoint.ip" } },
      { rename: { from: "unmapped.action",    to: "activity_name" } }
      // ...all renames/copies/casts/constants here
    ]
  }]
}
```

This is how the community PARSER_TEMPLATE captures the entire event into `unmapped.*` and does every OCSF mapping in one place.

**Dotted source keys are flat, not nested.** When a source JSON key literally contains a dot (e.g. `"user.email": "alice@example.com"`), gron flattens it into `unmapped.user.email` as a FLAT field name. In mappings, reference it with the literal path — `from: "unmapped.user.email"` — and do NOT escape the dots. `from: "unmapped.user\\.email"` will NOT match on current tenants (tenant-validated April 2026). This contradicts the escape-the-dots guidance in the upstream PARSER_TEMPLATE.conf in ai-siem; prefer the tenant-validated form.

**gron DOES expand arrays — into `[N]`-indexed attributes, not lossy strings. Index with `[N]`, never `.N.`** This corrects the common misconception (including elsewhere in this skill) that "gron drops arrays" or "flattens arrays to a lossy string." gron emits one queryable attribute per array leaf, using bracket-index notation:

```
"signInEventTypes":["nonInteractiveUser"]          -> unmapped.signInEventTypes[0] = "nonInteractiveUser"
"additionalDetails":[{"key":"UserType","value":"Member"}]
                                                   -> unmapped.additionalDetails[0].key   = "UserType"
                                                      unmapped.additionalDetails[0].value = "Member"
"targetResources":[{"id":"x","modifiedProperties":[{"displayName":"d","newValue":"n"}]}]
                                                   -> unmapped.targetResources[0].id = "x"
                                                      unmapped.targetResources[0].modifiedProperties[0].displayName = "d"
                                                      unmapped.targetResources[0].modifiedProperties[0].newValue    = "n"
```

The trap that makes it *look* like arrays were dropped: querying with dot-index (`unmapped.targetResources.0.id`) returns null. The actual key uses brackets (`unmapped.targetResources[0].id`). Tenant-validated 2026-06-22 (Microsoft Entra ID sign-in + directory-audit logs, deeply nested arrays).

Choose the capture per goal:
- **gron / dottedJson** -> every array element becomes its own `[N]`-indexed attribute. Use this when you want each leaf queryable / mappable (this is almost always what "extract all fields" means).
- **strictDottedJson / strict\*** -> the array is preserved as one JSON value (consumable by PowerQuery `array_from_json()` / `array_get()`), NOT split into per-element attributes.

Scalar and nested-object flattening is identical across gron, dottedJson, and the strict variants; they differ ONLY in array handling.

**Querying `[N]` attributes: they are stored but a raw PowerQuery `columns`/`filter` clause cannot type the `[`.** `| columns unmapped.x[0].y` fails to parse ("Unable to parse the entire query"); backticks fail ("Don't understand [`]"); double-quotes turn the name into a string literal. The fields ARE present and queryable through the Event Search field picker and the V1 query / `powerquery_schema_discover` endpoint — so do not conclude extraction failed just because `columns` rejects the name. To confirm `[N]` fields during validation, use `powerquery_schema_discover` (returns full event JSON) rather than a `columns` projection. Tenant-validated 2026-06-22.

See `references/ai-siem-catalog.md` §"Useful reference parsers by shape" for the canonical example, and `examples/08-gron-capture-template.json` for a ready-to-use scaffold.

### Strict variants (keep arrays as one parseable JSON value)

Non-strict `gron`/`dottedJson` expand arrays into per-element `[N]`-indexed attributes (see the gron-array note above) — great when you want each leaf queryable, but you then cannot run PowerQuery array functions over the array as a whole. If you instead want the array preserved as a single JSON value that `array_from_json()` / `array_get()` can consume, use the `strict*` variant:

- `strictJson`, `strictDottedJson`
- `strictEscapedJson`, `strictDottedEscapedJson`
- `strictUrlEncodedJson`, `strictDottedUrlEncodedJson`
- `strictBase64EncodedJson`, `strictDottedBase64EncodedJson`

Non-array behaviour is identical to the non-strict variant.

**Single-element arrays in non-strict mode become a bracket-wrapped string, not an indexable field.** A source field like `"user": ["a@b.com"]` parsed with non-strict `dottedJson` lands as the literal string `unmapped.user = "[a@b.com]"` (brackets kept, inner quotes stripped). Indexing it as `unmapped.user.0` returns null, so a `copy` or `rename` from `unmapped.user.0` is a silent no-op. If you only need the scalar (not the array), strip the brackets in a `computeFields` rewrite before the `mappings` block: `| let user = (unmapped.user == null ? null : replace(unmapped.user, '[][]', ''))`. The `[][]` regex class matches either bracket without escaping. If you need the value as a real array, use `strictDottedJson` with `array_get(...)` / `array_from_json(...)` instead. Tenant-validated 2026-06-16 on Zscaler firewall logs.

## Language-flavored dictionaries

| Directive | Syntax |
|---|---|
| `pythonDict` | `{'key': 'value', ...}` (single quotes, Python literals). |
| `rubyHash` | `{:key=>value, ...}` (Ruby hash rockets and symbols). |
| `dict` | Permissive catch-all for loose dict notation. |

## Key/value and separated values

| Directive | Behaviour |
|---|---|
| `commaKeyValues` | `key=value, key=value, ...`. |
| `commaSeparatedValues` | Positional; rename columns via a `mappings` section on the format. |
| `pipeSeparatedValues` | Same but pipe-delimited. Ideal for CEF headers. |

### Positional value example

```js
formats: [
  { format: "$csv=.*{parse=commaSeparatedValues}$",
    mappings: { positions: ["timestamp","host","action","user"] } }
]
```

## SQL normalization

| Directive | Behaviour |
|---|---|
| `sqlToSignature` | Replace string / numeric literals with `?` so similar queries aggregate. |
| `sqlWithDoubleQuotesToSignature` | Same, but preserves `"..."` as identifiers (Postgres-style). |

Useful on `mysqlGeneralQueryLog`, `postgresLog` and any slow-query stream.

## Syslog priority

`syslogPriority` decodes a numeric PRI value like `134` into three fields: `facility`, `rawSeverity`, and scaled `severity`. Most useful as `{parse=syslogPriority}` on the `<PRI>` capture from a line start.

## Date/time conversion

| Directive | Input | Output |
|---|---|---|
| `dateTimeSeconds` | Textual datetime | epoch seconds |
| `dateTimeMs` | Textual datetime | epoch milliseconds |
| `dateTimeNs` | Textual datetime | epoch nanoseconds |
| `hoursMinutesSeconds` | `hh:mm:ss[.sss]` | total seconds (float) |

## Numeric durations and sizes

Accept optional unit suffixes and normalize to a base unit:

| Directive | Base unit | Recognized suffixes |
|---|---|---|
| `seconds` | seconds | `s`, `ms`, `min`, `m`, `h`, `d` |
| `milliseconds` | milliseconds | same set |
| `bytes` | bytes | `b`, `kb`, `mb`, `gb`, `tb` |
| `kb`, `mb`, `gb` | the named unit | same |

## Subfield filtering

After a structural parse, the generated subfields may explode your schema. Filter them:

```
$payload{parse=dottedJson}{attrWhitelist=user\\.(id|email|name)}$
```

Only subfields matching the regex are kept. `attrBlacklist` is the inverse.

## When to pick which

- Embedded JSON → `json` (camel) vs `dottedJson` (dotted) based on downstream query preference. Add `strict*` if you need arrays.
- CEF / LEEF extension → `commaKeyValues` for LEEF, space-separated key=value catch-all for CEF.
- HTTP access log request line → `uri`.
- Firewall-like positional pipes → `pipeSeparatedValues` + `mappings.positions`.
- SQL log bodies → `sqlToSignature`.
- Unix/Java timing → `dateTimeMs` or `dateTimeNs` as appropriate.
