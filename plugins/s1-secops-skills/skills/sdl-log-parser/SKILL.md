---
name: sdl-log-parser
author: Prithvi Moses <prithvi.moses@sentinelone.com>
description: Use whenever the user wants to author, edit, debug, validate, or explain a SentinelOne Singularity Data Lake (SDL) log parser — the augmented-JSON files at /logParsers/ that extract fields from raw log text before ingestion. Trigger on "SDL parser", "Skylight parser", "log parser", "parser editor", "write a parser", "test parser", or any pasted raw log the user wants turned into structured fields. Also trigger on parser-DSL keywords like `formats:`, `patterns:`, `lineGroupers:`, `rewrites:`, `discardAttributes:`, `aliasTo:`, `{parse=...}`, `{regex=...}`. Especially trigger when the user pastes a raw log (CEF, syslog, JSON, key=value, multi-line, CSV) and asks to extract fields, normalize timestamps, or drop noise. If the project is SDL/Singularity/Scalyr and the user says "parse this log", use this skill. Always validates end-to-end via putFile → HEC ingest (parser applied) → query. NOT for PowerQuery (use powerquery), NOT for plain ingest without a parser (use sdl-api).
---

# SentinelOne SDL Log Parser Authoring

This skill turns raw log samples into deployed, validated SDL parser definitions. A parser is an *augmented-JSON* file at `/logParsers/<name>` on the SDL tenant that extracts fields from each ingested line. The parser editor and the `Test Parser` button in the console run the parser client-side in JavaScript; this skill mirrors that workflow programmatically and finishes by ingesting a sample through the deployed parser to confirm the actual ingest path works.

> **Sandbox proxy blocked?** If `putFile` or HEC ingest calls to `*.sentinelone.net` fail with a connection or proxy error inside the Claude sandbox, use the `s1-secops-mcp` server instead. It runs locally via `node` and bypasses the sandbox proxy entirely. Setup: add it to `claude_desktop_config.json` (see `s1-secops-mcp/README.md`). Use `sdl_put_file` to deploy the parser and `hec_ingest` to run the ingest validation step — both execute from your machine, not the sandbox.

## Two hard rules (every parser, every time)

These two rules apply to every parser you write or edit, regardless of source, regardless of whether you're starting from scratch or copying from the catalog. Violating either produces a non-conformant parser even if extraction works.

**Rule 1: The 4 mandatory attributes are always present.**

```js
attributes: {
  "dataSource.category": "security",   // hardcoded constant, never any other value
  "dataSource.name":     "Corelight",  // specific product/service name
  "dataSource.vendor":   "Corelight",  // parent vendor / company name
  "metadata.version":    "1.0.0"       // semver; bump on substantive parser changes
}
```

`dataSource.category` is fixed at `"security"`. Not `application`, not `network`, not `system`, not `audit`. The catalog has parsers that violate this; you do not.

`metadata.version` is mandatory and follows semver (`MAJOR.MINOR.PATCH`, with optional pre-release suffix like `-rc1` or `-beta1`). **Increment it on every build.** Patch bump for fixes, minor for additive changes, major for breaking schema changes. It can also be set inside `mappings` via a `constant` op when the source itself carries a vendor schema version you'd rather propagate per-event:

```js
{ constant: { field: "metadata.version", value: "<your-current-version>" } }
```

A `constant` in `mappings` overrides the parser-root `attributes:` value when it fires, which is useful when one parser handles multiple vendor schema versions and you want each event tagged with the right one.

**Rule 2: Every OCSF field name comes from `references/ocsf-schema-documentation.md`.**

Before emitting any OCSF dotted path (`src_endpoint.ip`, `actor.user.name`, `metadata.product.vendor_name`, etc.), grep `references/ocsf-schema-documentation.md` for the exact string. Do not invent field names. Do not copy from a catalog parser without verifying. Do not rely on memory. The reference is the single source of truth for the ~25,759 documented OCSF field names across the 7 categories.

The rest of this skill assumes both rules are upheld. If either is unclear for a given parser, stop and resolve before continuing.

## Critical pitfalls (read before authoring)

These are the DSL traps that cost the most iteration cycles when authoring parsers on the current S1 tenant. They are repeated in the long gotcha list below with more context, but if you're about to write a new parser, internalize these first. Items 1-9 are tenant-validated as of 2026-05-26; items 10-12 as of 2026-06-22.

1. **Key=value catch-all REQUIRES leading `.*`**. The canonical form is `".*$_=identifier$=$_=quoteOrSpace$"` with `repeat: true`. Without the `.*` the format anchors at position 0 of the message and fires zero times on any line starting with a syslog priority `<NNN>`, a CEF header, an XML envelope, or a timestamp — i.e. virtually every real log source. The leading `.*` lets the engine scan forward to the first `key=value` pair and then `repeat: true` walks the rest. This is the same pattern the built-in `keyValue` parser uses. Also: **`{parse=keyValue}` is NOT a valid sub-parser directive**; built-in parsers like `keyValue` are only usable via root-level `aliasTo:`.
2. **v1 mappings are FIRST-MATCH-WINS**, which means **renames must be duplicated into every per-subtype block** alongside the constants. A catch-all `predicate: "true"` rename block placed at the end NEVER fires for events that matched an earlier per-subtype block — only the truly-unmatched events get those renames. If you have per-subtype `constant` blocks for OCSF class/activity fan-out (e.g. `subtype=='forward'` → `activity_id=6`), you must put the full rename list inside EACH of those blocks. Verbose but correct.
3. **v0 `constants:` block is REJECTED on the current tenant.** `putFile` returns `400: Syntax error at position -1: Assertion failed: Expected a field` whenever a v0 mapping body contains a `constants:` array. v0 `renames:` and `copies:` work fine; only `constants:` fails. Practical impact: prefer **v1** (`{ constant: { field, value } }`) for any new parser that needs OCSF class fan-out. Stay on v0 only when extending an existing v0 parser that doesn't add new constants.
4. **Same-name rename silently NULLS the field.** Writing `{ rename: { from: "action", to: "action" } }` to "keep" a captured raw field under its own name actually deletes the value. The KV catch-all already extracts raw vendor field names directly into the event — to "keep" one, OMIT the rename. Only write a rename when the target name is genuinely different from the source.
5. **Unquoted numerics from `quoteOrSpace` are auto-typed as NUMBER columns.** A FortiGate `srcport=44321 sentbyte=8421` line going through the KV catch-all produces `srcport: 44321` (number), `sentbyte: 8421` (number) — queryable with `avg()` / `sum()` / `> N` without `number()` wrapping. Quoted values stay as strings even if they look numeric (`level="6"` → string). Caveat: SDL column type-locking still applies, so wrap numerics with `number()` in dashboard panels and STAR rule bodies if the column has ever been written as string in this tenant's history.

Two related queryability rules (not DSL traps, but they matter for any consumer of the parser):

6. **The raw `message` field is preserved on every event regardless of parser activity.** SDL never lets a parser overwrite `message`; the raw event body always survives. So `parse "field=$x$" from message` queries continue to work alongside the typed columns the parser produces. This is the backward-compat escape hatch during a parser rollout.
7. **When two ingest paths produce OCSF for the same source, the schema can drift.** A common case: upstream collector (Observo etc.) flattens `type=traffic, subtype=forward` to just `event.type='forward'` while the downstream parser keeps both fields populated. Consumers (dashboards, STAR rules, hunts) should write subtype filters as `(event.subtype='forward' OR event.type='forward')` until the rollout fully converges.
8. **Trailing `.*` at the END of a format string suffers the leading-`.*`-strip too.** A field marker like `$process.cmd_line{regex=.*}$` placed at the end of a format string captures the EMPTY STRING. The SDL stripping rule applies whether `.*` starts the regex or IS the entire regex. Use `[\\s\\S]+` (one-or-more) or `[\\s\\S]*` (zero-or-more) for "everything that remains on the line" semantics — those forms don't begin with `.` and survive intact.
9. **Regex alternation matches in DECLARATION ORDER, not longest-leftmost.** `regex=CRON|CROND` is a bug — `CRON` matches the prefix of `CROND` and leaves `D` dangling. Put longer alternatives first: `regex=CROND|CRON|crond|cron`. Applies to named patterns, inline `{regex=...}`, and any other alternation. When alternatives share a prefix, sort by length descending.
10. **gron expands arrays into `[N]`-indexed attributes; index with `[N]`, NOT `.N.`** Do not believe "gron drops arrays." `$unmapped.{parse=gron}$` emits one queryable attribute per array leaf: `unmapped.signInEventTypes[0]`, `unmapped.additionalDetails[0].key`, `unmapped.targetResources[0].modifiedProperties[0].newValue`. The trap that makes arrays look dropped is querying with dot-index (`unmapped.targetResources.0.id` → null); the real key is bracket-indexed (`unmapped.targetResources[0].id`). gron/dottedJson = each element its own attribute (use for "extract every field"); `strict*` = array kept as one JSON value for `array_from_json()`. Scalar/object flattening is identical across all three. Caveat: a raw PowerQuery `columns`/`filter` clause can't type the `[`, so validate `[N]` fields with `powerquery_schema_discover`, not a `columns` projection. To lift a whole array subtree to OCSF, `rename_tree { from: "unmapped.targetResources[0].modifiedProperties", to: "entity.data" }`. Tenant-validated 2026-06-22 (Microsoft Entra ID). See `references/parse-directives.md`.
11. **`copy` first-of-N treats an empty string `""` as "exists" and lets it win.** `copy {from: ["userId","servicePrincipalId"]}` where `userId` is `""` copies the empty string, not the fallback — silently breaking identity-coalesce (e.g. service-principal / managed-identity sign-ins whose `userPrincipalName`/`userId` are empty but `servicePrincipalName`/`servicePrincipalId` hold the identity). Fix by dropping empty strings upstream (the collector/Lua serializer should omit `""` values), or `drop` the empty source before the `copy`. Tenant-validated 2026-06-22.
12. **On a LIVE source, a "still broken" event is usually pre-propagation, not a parser bug.** Parser activation is ~3-5 min and a continuously-ingesting source keeps producing events through the OLD version during that window; SDL never re-parses historical events. Bump `metadata.version` every deploy and confirm via `| group count() by metadata.version` (or `powerquery_schema_discover`) which version parsed a given event before chasing a "bug." Related: if the parser sets event time from a log field, events are stamped at the log's own time, so widen validation query windows (`24h`/`7d`) or filter by a nonce field instead of time, or you get zero rows and a false negative.

## When to use this skill

Use this skill when the user wants to turn raw log text into structured SDL events. Common triggers:

- "Write a parser for this <vendor> log."
- "Why isn't `<field>` showing up after ingest?"
- A pasted log line — CEF, syslog, JSON-per-line, key=value, multi-line, vendor-specific.
- Edits to an existing parser ("add a rewrite that masks the password", "tag every event with `dataset=fortinet`").
- Migration ("alias the new parser to the old one").

Do **not** use this skill for PowerQuery authoring (use `powerquery`) or for plain-text ingestion that does not need a parser (use `sdl-api` directly).

## Workflow

Follow this loop. Skipping steps 1 (catalog check) and 5 (end-to-end validation) are the two most common reasons a parser goes live with surprises, so do not skip them.

1. **Check the ai-siem catalog first.** Before writing anything, search <https://github.com/Sentinel-One/ai-siem/tree/main/parsers> for the vendor/product. The repo has ~150 community + marketplace parsers; most common sources (Cloudflare, FortiGate, Palo Alto, Corelight, AWS RDS, Okta, Abnormal, Juniper, pfSense, Cisco ASA, etc.) are already there. If a parser exists, download it and diff against the user's requirements — far less work than authoring from scratch. See `references/ai-siem-catalog.md` for the recipe and a map of template parsers by shape.
2. **Inspect the sample.** Read every line the user pasted. Look for: leading priority/timestamp/host (syslog framing), the body shape (CEF | JSON | key=value | positional CSV | freeform), any obvious sub-structures (`uri=...`, embedded JSON, base64), and whether multiple physical lines belong to one logical event (stack traces, MySQL slow queries, Postgres SQL).
3. **Decide on strategy.** See *Strategy decision tree* below. Most logs are one of: alias an existing built-in, single line format with `$field$` markers, repeating key/value catch-all, JSON parser with `discardAttributes`, line-grouper for multi-line, or a mapper for OCSF-style restructuring.
4. **Draft the parser.** Use the templates in `examples/` as starting points, or (from step 1) a catalog parser as a base. Always start minimal — extract the *outer* frame first (timestamp + host + body), then add fragment formats or `{parse=...}` directives to crack the body open.
5. **Validate end-to-end.** Use the `sdl-api` skill to deploy the parser, ingest the sample, and query for the extracted fields. See *Validation* below for the exact recipe. **Do not call this skill done before this step succeeds.**
6. **Iterate.** If a field is missing or wrong, identify which format/rewrite was responsible, edit, redeploy, re-ingest with a fresh `Nonce`, re-query.
7. **Hand off.** Show the user the final parser file (path + version), the sample they gave, and the parsed fields the query returned.

## Required default attributes on every parser (MANDATORY)

**Four attributes are MANDATORY on the top-level `attributes:` block of every parser**, regardless of source. These are non-negotiable:

```js
"dataSource.category": "security",    // ALWAYS hardcoded to "security": fixed constant, never change
"dataSource.name":     "Corelight",   // specific product/service name (example value)
"dataSource.vendor":   "Corelight",   // parent vendor / company name (example value)
"metadata.version":    "1.0.0"        // semver; required on every parser
```

These four are required by the downstream SDL pipeline (Marketplace routing, parser catalog, content-pack grouping). Omitting any of them produces a non-conformant parser even when field extraction is correct.

**`dataSource.category` MUST always be hardcoded to `"security"`.** This is not a taxonomy pick, it is a fixed constant. Never substitute another value (`application`, `network`, `system`, `audit`) regardless of the source type. Empirical audit of the ai-siem catalog (2026-04) shows ~17% of community parsers violate this rule with values like `application`, `network`, `system`, `audit`. Fix on copy.

`dataSource.vendor` is the parent company (`Cisco` for Umbrella, `Microsoft` for Azure AD). `dataSource.name` is the specific product (`Cisco Umbrella`, `Azure AD`). For single-product vendors both can be the same string (`Corelight` / `Corelight`).

`metadata.version` is semver (`MAJOR.MINOR.PATCH` with optional `-rcN` / `-betaN` suffix). **Always increment on a new build** so content-pack tooling can detect drift. Patch for fixes, minor for additive changes, major for breaking schema changes. May also be emitted from inside `mappings` via:

```js
{ constant: { field: "metadata.version", value: "<your-current-version>" } }
```

A `mappings.constant` overrides the parser-root `attributes:` value when its predicate fires. This is the right pattern when one parser handles multiple vendor schema versions and you want each event labeled with the schema-version it actually came from.

**Catalog-parser audit step.** When you start from a catalog parser, the very first edits you make are to confirm all four fields are present, that `dataSource.category` is `"security"`, and that `metadata.version` exists and reflects the change you're about to make. About 1/3 of the community parsers in `Sentinel-One/ai-siem` are missing `dataSource.category` outright; many that include it use a non-security value. Fix before doing anything else.

## Default output schema: OCSF (mandatory reference)

Unless the user explicitly asks for vendor-native names, **emit OCSF-shaped events**. This means:

- Name captured fields with their OCSF dotted paths (e.g. `src_endpoint.ip`, `dst_endpoint.port`, `connection_info.protocol_num`, `app_name`, `actor.user.name`).
- Tag every event with the class metadata on `attributes`: `class_uid`, `class_name`, `category_uid`, `category_name`, and `metadata.product.vendor_name` / `metadata.product.name` / `metadata.log_provider`, all IN ADDITION TO the four mandatory attributes above.
- Put the per-event subtype (`activity_id` + `activity_name`) on the **format**, not the top-level attributes, because one parser often handles multiple subtypes (SESSION_CREATE vs SESSION_CLOSE).

**OCSF mapping MUST always be done using `references/ocsf-schema-documentation.md`.** This file is the authoritative SentinelOne community-documented OCSF field catalog (7 categories, 96 articles, ~25,759 field entries across every event class). Before emitting any OCSF field name, grep this file for the exact dotted path. Do **not** invent field names, do **not** copy from memory, do **not** trust catalog parsers to have the right name (many community parsers in ai-siem use vendor-native or stale OCSF names that need correcting). Workflow:

1. Pick the OCSF class (see Quick picker below).
2. Open `references/ocsf-schema-documentation.md` and grep for the class number / category to find the field block.
3. Copy the dotted path verbatim into your parser.
4. If unsure between two candidate fields, confirm with the user rather than guessing.

`references/ocsf-mapping.md` covers the two authoring idioms (capture-directly-into-dotted vs capture-vendor-then-rename) and the most common class-specific tables (Network Activity, Authentication, File Activity).

Why this matters: downstream PowerQuery hunts, STAR rules, dashboards, and Marketplace integrations assume OCSF. Vendor-native names force every consumer to learn each source format and break portability. A wrong dotted path (`source.ip` instead of `src_endpoint.ip`, `dst.port` instead of `dst_endpoint.port`) is silently wrong: it ingests, but every downstream consumer fails to match.

Quick picker (use this to find the class number, then look up fields in `ocsf-schema-documentation.md`):

- Network firewall / NAT / flow → `4001` Network Activity
- HTTP / web / proxy → `4002` HTTP Activity
- DNS → `4003` DNS Activity
- DHCP → `4004` DHCP Activity
- RDP / SSH session → `4005` RDP Activity
- TLS / SSL handshake → `4006` SSH Activity (TLS uses connection_info under 4001/4002)
- Email → `4009` Email Activity
- Authentication → `3002` Authentication
- Account change → `3001` Account Change
- API activity → `6003` API Activity
- File system ops → `1001` File System Activity
- Kernel ops → `1003` Kernel Activity
- Memory ops → `1004` Memory Activity
- Module ops → `1005` Module Activity
- Process ops → `1007` Process Activity
- Registry ops → `201001` (Windows Registry)
- Detection finding → `2004` Detection Finding
- Compliance finding → `2003` Compliance Finding
- Vulnerability finding → `2002` Vulnerability Finding
- Inventory / device → `5001` Device Inventory Info
- Email / file finding → `2007` (Email Finding) / `2006` (File Hosting Finding)

When the source could reasonably belong to multiple classes (proxy logs, EDR alerts), confirm with the user rather than picking silently.

## Top-level parser structure

A parser file is augmented JSON (unquoted keys allowed, `//` and `/* */` comments allowed). Top-level keys:

```js
{
  timezone: "UTC",                                  // fallback for timestamp parsing
  attributes: {
    // REQUIRED defaults on every parser
    "metadata.version":    "1.0.0",
    "dataSource.category": "security",    // always "security" — hardcoded, never change
    "dataSource.name":     "Juniper SRX",
    "dataSource.vendor":   "Juniper",
    // OCSF class metadata + vendor product metadata
    "metadata.product.vendor_name": "Juniper",
    "metadata.product.name":        "SRX",
    "metadata.log_provider":        "rt_flow",
    "class_uid":      4001,
    "class_name":     "Network Activity",
    "category_uid":   4,
    "category_name":  "Network Activity"
  },
  patterns:   { tsPattern: "\\w+\\s+\\d+\\s+[0-9:]+" },  // named regex shortcuts
  lineGroupers: [ { start: "...", continueThrough: "..." } ],  // multi-line glue
  formats: [
    {
      id: "happy-path",
      attributes: { activity_id: 1, activity_name: "Open" },  // per-subtype tagging
      format: "$time=tsPattern$ $src_endpoint.hostname$ $body$",
      discard: false,
      halt: true,                                   // stop after first match
      repeat: false                                 // re-apply until no progress
    }
  ],
  // Advanced (not always present):
  mappings: { mappings: [ /* rename vendor-native fields to OCSF dotted names */ ] }
}
```

`formats` is the primary engine. Everything else either feeds into it (patterns, lineGroupers) or runs after it (rewrites, mappings, discardAttributes).

## Field-matcher syntax inside a format string

```
$fieldName=patternName{parse=...}{regex=...}{attrWhitelist=...}{attrBlacklist=...}{timezone=...}$
```

Rules that bite people often:

- `$field$` alone uses the `quotable` pattern by default, which stops at whitespace or quote boundaries.
- `$field{regex=\\d+}$` inlines a regex — backslash metacharacters double-escape (`\\d` not `\d`).
- Two adjacent `$a$$b$` with no delimiter between them require a pattern or regex on `$a$` so it knows when to stop.
- `message` is reserved — it's the raw event text. You cannot capture into `message` from a format. You *can* `discardAttributes: ["message"]` to drop it.
- A literal `$` in the log requires `\$$` (escape the dollar, then close the field).
- Any space in the format matches `\s+`. To match a single literal space use `\\ ` (backslash-space).

For the full directive list see `references/syntax.md` and `references/parse-directives.md`.

## Canonical reference parsers by input shape

When you've identified the shape of the source log, jump straight to the canonical catalog parser for that shape and start from it. These are battle-tested in production:

| Input shape | Canonical parser | What to learn from it |
|---|---|---|
| Pure JSON-per-line (flat or nested) | `community/abnormal_security_logs-latest/` | `${parse=gron}$` capture, then mappings to OCSF |
| JSON with envelope (`<ts> <host> <json>`) | `community/json_generic-latest/` (or `examples/02-json-with-envelope.json`) | `dottedJson` on the body |
| JSON, nested, multi-class | `sentinelone/marketplace-cloudflare-latest/` | gron + format IDs + enum cast + tree ops, all in v1 mappings |
| Already-OCSF JSON | `community/okta_ocsf_logs-latest/` | Pass-through with light renames |
| CEF over syslog | `community/generic_access_logs-latest/` (or `examples/01-cef-over-syslog.json`) | Pipe-delimited header + KV extension |
| LEEF over syslog | `community/leef_template_logs-latest/` | Multi-format header + KV body |
| Pure key=value freeform | `sentinelone/marketplace-fortinetfortigate-latest/` | `repeat: true` catch-all, attrBlacklist, observables array |
| Key=value with record-type fan-out to many OCSF classes | `examples/12-linux-auditd-ocsf.json` | ` type=`-anchored record-type capture (avoids the `nametype=` collision), KV catch-all, v1 first-match-wins mappings fanning one source to Process 1007 / File 1001 / Auth 3002 / Finding 2004 / Network 4001, EXECVE arg-vector → `process.cmd_line` via `computeFields` `replace()` |
| Positional CSV (100+ columns) | `sentinelone/marketplace-paloaltonetworksfirewall-latest/` | `commaSeparatedvalues`, `skipNumericConversion`, `attr[N]` indexed access in v1 mappings |
| Positional space-delimited | `sentinelone/marketplace-awsvpcflowlogs-latest/` | `intermittentTimestamps`, fixed columns |
| Pipe-delimited (non-CEF) | `sentinelone/marketplace-zscalerinternetaccess-latest/` | `pipeSeparatedValues` parse directive |
| Multi-line stack / SQL | `community/sql_database_logs-latest/` and `sentinelone/marketplace-awsrdslogs-latest/` | `lineGroupers` start/continueThrough, format-id sentinels for sub-shapes |
| Windows Event XML | `community/microsoft_windows_eventlog-latest/` | XML with `\\t` / `\\n` escapes, per-EventID sub-parsers (4624, 4625, 4720, 4728, 1102) |
| HTTP access logs | `community/apache_http_logs-latest/` | Built-in `accessLog` alias-or-extend |
| pfSense / iptables freeform firewall | `community/pfsense_firewall_logs-latest/` | Frame → subtype → protocol cascade with `discard: true` for IPv6 |
| Rewrites-only legacy style | `community/okta_logs-latest/` | Minimal-diff edits when you can't migrate to mappings |
| Gron-capture + everything-in-mappings | `community/PARSER_TEMPLATE/` (and `examples/08-gron-capture-template.json`) | The most general scaffold; use when you want all transformations in one block |

When in doubt, `marketplace-cloudflare-latest/` is the most complete reference for "modern v1 parser doing everything right" (gron, format IDs, enum cast, tree ops, OCSF tagging). Start there if you're not sure.

## Strategy decision tree

Apply in order — first match wins:

1. **Is there a parser in the ai-siem catalog?** Search `Sentinel-One/ai-siem` for the vendor/product name. If so, start from that parser (see `references/ai-siem-catalog.md` for the fetch recipe and per-shape template map). On copy, immediately audit and fix:
   - The **4 mandatory attributes** (`dataSource.category` hardcoded to `"security"`, `dataSource.name`, `dataSource.vendor`, `metadata.version`). About 1/3 of community parsers miss `dataSource.category` outright; many that include it use `application`/`network`/`system`/`audit` instead of `"security"`. Force them to `"security"`. Add `metadata.version` if missing, bump it if you're changing the parser.
   - All OCSF field names against `references/ocsf-schema-documentation.md`. Catalog parsers frequently use vendor-native names (`source_ip`, `dst_port`) where OCSF dotted paths (`src_endpoint.ip`, `dst_endpoint.port`) are required. Rewrite via `mappings.rename` or change the capture name directly.
   - Stale tenant-specific attributes (e.g. hardcoded `site.id`).
   - `class_uid` should be an integer, not a string.
   - Bump `metadata.version`.
2. **Is there a built-in parser?** Web access logs → `accessLog`. Pure JSON-per-line → `json` or `dottedJson`. Syslog → `systemLog`. Key=value pairs → `keyValue`. Heroku logplex → `heroku-logplex`. MySQL/Postgres → their dedicated parsers. CloudFront/ELB/S3/Redshift → AWS parsers. See `references/builtin-parsers.md`. If a built-in fits, recommend it and (optionally) just author an alias parser: `{ aliasTo: "json" }`.
3. **Is the log JSON-per-line but with a vendor envelope?** Use one format that captures the envelope and applies `{parse=json}` (or `dottedJson`/`escapedJson`/`urlEncodedJson`/`base64EncodedJson`) on the embedded body. Add `discardAttributes: ["message"]` to save storage.
4. **Is the whole line an OCSF/JSON blob you want flattened?** Use the gron-capture-then-mappings idiom: `format: "$unmapped.{parse=gron}$"` at the top, then rename/copy/cast everything in a `mappings` block. See `examples/08-gron-capture-template.json` and the `community/PARSER_TEMPLATE/` reference.
5. **Is the body a sequence of `key=value` pairs?** Use the two-format key/value idiom. The repeating catch-all format MUST be exactly `".*$_=identifier$=$_=quoteOrSpace$"` (with the leading `.*`) and have `repeat: true`. Without the `.*` the format only anchors at position 0 of the message and fires zero times on any line that starts with a syslog priority `<NNN>`, a CEF header, an XML envelope, or anything else that isn't bare `identifier=`. The `_` field name means "use the captured token as the field name". `{parse=keyValue}` is NOT a valid sub-parser directive — it returns `Unknown parser "keyValue"`. The `keyValue` built-in can only be referenced via `aliasTo: "keyValue"` at the parser root (one-line alias parser), not via `{parse=...}`. Canonical references: built-in `keyValue` parser; `examples/03-key-value.json`; `sentinelone/marketplace-fortinetfortigate-latest/` (FortiGate syslog, key=value with quoted strings).
6. **Is it CEF or LEEF?** Treat the header as a positional pipe-delimited line, then apply key/value catch-all to the extension. See `examples/01-cef-over-syslog.json`.
7. **Is it positional / CSV / TSV?** Use `commaSeparatedValues` / `commaSeparatedvalues` or `pipeSeparatedValues` parse directives with `skipNumericConversion: true`, and name the columns in a `mappings` block by positional index (`attr[N]`). Palo Alto Networks Firewall in ai-siem is the canonical reference.
8. **Does the source emit multiple distinct event shapes** (e.g. MySQL error vs MySQL general vs Postgres from one RDS stream)? Give each `format` an `id:` and fan mapping entries out with `predicate: "<id>='true'"`. See the AWS RDS marketplace parser.
9. **Are events multi-line?** Add a `lineGroupers` block with `start` + one of `continueThrough` / `continuePast` / `haltBefore` / `haltWith`. Then write formats against the joined event. **Beware** HEC ingest newline splitting (see ingest-path gotchas). Canonical multi-line examples: `parsers/community/sql_database_logs-latest/` (Postgres SQL) and `parsers/sentinelone/marketplace-awsrdslogs-latest/` (RDS mysql/postgres mixed stream).
10. **Is the source Windows Event Log XML?** Use the per-EventID sub-parser idiom from `parsers/community/microsoft_windows_eventlog-latest/`: a `lineGroupers` block joins multi-line XML, then one format per EventID (4624, 4625, 4720, 4728, 1102, etc.) extracts EventID-specific fields. Remember the `\\t` / `\\n` double-escape gotcha. Class fan-out: 4624/4625 → `class_uid: 3002` Authentication, 4720/4728 → `class_uid: 3001` Account Change, 1102 → `class_uid: 6004` Web Resources Activity (or whatever fits).
11. **Do you need to restructure to OCSF or another schema?** Use `mappings` (gron-style mappers). See `references/mappers.md` for the two equivalent syntaxes (v1 singular / v0 marketplace). For new parsers prefer v1; only stay on v0 when extending an existing v0 parser. **Always look up dotted paths in `references/ocsf-schema-documentation.md` before emitting them.**
12. **None of the above?** Hand-write a line format. Look for stable delimiters and use named patterns when delimiters are insufficient (e.g., a timestamp containing spaces). Drop events you never want (`discard: true` on the format) rather than letting them fall through to a looser format.

## Common gotchas (memorize)

- **Double-escape every regex metacharacter.** `\\d`, `\\s`, `\\.`, `\\\\`. The augmented-JSON layer eats one backslash before the regex engine sees it.
- **`severity` is a RESERVED field coerced to 0–6 integer.** The ingest pipeline maps `info`/`warn`/`error` strings to 0–6 using its own vocabulary. OCSF labels like `"Informational"` / `"Medium"` collide and get rewritten. For the OCSF string, emit `severity_name` (or any non-colliding name); for the integer, emit `severity_id` directly (int, 0–6). Tenant-validated April 2026.
- **gron-captured dotted keys are FLAT, not nested.** A source JSON key like `"user.email": "alice"` becomes `unmapped.user.email` as a single flat field — mappings must reference it with `from: "unmapped.user.email"` (no escaping). `from: "unmapped.user\\.email"` does NOT match on current tenants, contrary to the escape-the-dots pattern in ai-siem's PARSER_TEMPLATE.conf.
- **Saved parsers apply only to newly ingested events.** Historical logs are not re-parsed. So during iteration you must re-ingest the sample after every parser edit.
- **A `parser=<name>`-tagged source with NO `/logParsers/<name>` file ingests raw (passthrough).** If events carry `parser='auditd'` but `dataSource.name` / `class_uid` are null, the named parser file does not exist yet: the collector tags the events but SDL has nothing to apply. Deploy `/logParsers/<name>` and NEW events get parsed. After deploy, the parser's root `attributes` (e.g. `dataSource.name`) are the canary that the parser is RUNNING AT ALL — if they are still null on fresh events the parser has not propagated yet (not a format bug); if they are populated but a captured field is null, that IS a format/mapping bug. `metadata.version` is the canary for WHICH version is live: bump it on every deploy so you can tell from the live stream when a specific change has propagated (poll `| group c=count() by metadata.version` until the new version appears). Propagation observed at ~3-5 min on this tenant. Tenant-validated 2026-06-01.
- **`halt: true` stops the format engine after a match.** Use it for mutually exclusive formats (e.g., TCP vs UDP variants in pfSense). Without it, all matching formats merge their captures.
- **`repeat: true` reapplies the same format from where it left off.** Required for the key/value catch-all idiom, otherwise only the first pair is captured.
- **`discardAttributes` MUST be per-format for scratch fields, NOT parser-root.** A `discardAttributes: [...]` block at the parser root does NOT reliably drop fields created by named captures inside a format string (`$_xxx{regex=...}$` scratch markers leak through to the event). Put `discardAttributes: ["_pre", "_tail", ...]` ON THE FORMAT OBJECT itself, alongside `format:`. The built-in `json` parser shows the shape: `formats: [ { format: "$json{parse=json}$", repeat: true, discardAttributes: ["message"] } ]`. Parser-root scope only works for fields produced by `{parse=json}` / `{parse=dottedJson}` flat expansion (vendor noise keys like `flipkart_not_secure`), not for format captures. Tenant-validated 2026-05-13.
- **There is NO `from:` directive on a `format` entry.** Only `id`, `attributes`, `format`, `discard`, `halt`, `repeat`, and `rewrites` are honored. A `from: "<somefield>"` next to `format:` is silently ignored, and the format then runs against the raw line; a greedy regex like `[\s\S]+` will clobber every targeted field with the entire log message on every event. The `from:` key only exists in `mappings` ops (`{rename: {from, to}}`, `{copy: {from, to}}`). To run a format-like rewrite against a specific captured field, use `rewrites:` on the same format with `input: "<fieldname>"`, or do the work in a `mappings` op.
- **The parser only sees the `message` field.** Ingest-time attributes (`app_id`, `cluster`, `region`, custom enrichments from collectors / HEC ingest) are NOT visible to format strings, format-level `discard:` filters, or `rewrites` regex inputs. They ARE visible to `mappings` predicates and `mappings` op `from:` paths since mappings run after parsing. Encode any sentinel you need to gate a format on into the message body or anchor on a string the message itself contains.
- **v1 `mappings` is FIRST-MATCH-WINS.** Mapping entries are tried in declaration order; only the first entry whose `predicate` matches an event runs. A `predicate: "true"` catch-all therefore MUST go LAST in the list — placed first, it shadows every per-app/per-class entry below it (renames don't apply, class constants stay generic). Pattern: most specific predicates first, generic catch-all last. If two predicates would both fire on the same event and you want both effects, fold their transformations into a single entry. Tenant-validated April 2026.
- **Fragment-format anchors must live INSIDE the prefix's regex, not as separate format-string text.** The format `$_pre{regex=[\s\S]*}$/actuator/health$_suf{regex=[\s\S]*}$` (greedy `[\s\S]*` followed by literal text in the format string between the field markers) does NOT match — the engine commits each field's regex independently and won't backtrack across literal-text gaps. Working form: `$_pre{regex=[\s\S]*\/actuator\/health}$$_suf{regex=[\s\S]*}$` (literal anchor inside the prefix's regex). Same shape as Phase-10 IOC formats (`[\s\S]*X-Forwarded-For=[\[]?` baked into the prefix).
- **Greedy `[\s\S]*ANCHOR` lands on the LAST occurrence of `ANCHOR`.** That is the right behaviour when the captured token follows the rightmost anchor on the line (Dropwizard `[\s\S]*\[dw-[0-9]+ - ` is unique to the request-line bracket). It fails when the anchor is too generic: `[\s\S]*\[` followed by a `UT-[0-9]+` capture fails on any line whose last `[` is something else (e.g. `[#033[36m...]` ANSI brackets). Two fixes: (a) make the anchor multi-character and discriminating (`[\s\S]*\[UT-`), accepting that the literal is consumed by the anchor and your capture holds only the trailing portion (`$user_task_id_num{regex=[0-9]+}$`); or (b) use a lazy quantifier (`[\s\S]*?`) plus a discriminating literal when the FIRST occurrence is the right one.
- **Greedy `[\\s\\S]*<anchor>` collides with COMPOUND field names that contain the anchor as a substring.** Anchoring a record-type capture on bare `type=` (`$_pre{regex=[\\s\\S]*type=}$$rectype{regex=[A-Z0-9_]+}$`) silently mis-fires on auditd PATH records because `nametype=NORMAL` (and `objtype=`) contain `type=` — the greedy match lands on the LAST `type=` (the one inside `nametype=`), captures `NORMAL`, and the rest of the format then fails. Fix: widen the anchor with the delimiter that precedes the REAL token, e.g. ` type=` with a leading space (`$_pre{regex=[\\s\\S]* type=}$`), since the real record-type follows a space (`audispd: type=PATH`) whereas `nametype=`/`objtype=` are preceded by a letter. General rule: when your anchor is a short substring that also appears inside longer field names, disambiguate it with a neighbouring delimiter. Tenant-validated 2026-06-01 on a Linux auditd parser: bare `type=` parsed SYSCALL/EXECVE/PROCTITLE but dropped every PATH record; ` type=` fixed all record types.
- **Per-event parse limit is just under 50,000 chars.** Long events get truncated *before* parsing.
- **Line groupers max 100,000 chars per joined event.** Above that, the grouper still emits but truncated.
- **`intermittentTimestamps: true`** is required for logs (like MySQL general query log) that emit a timestamp only on the second they roll over. Without it, every line missing a timestamp gets the ingest time.
- **Regex alternation cannot wrap a `$...$` token.** `($a$|$b$)` is invalid. Use multiple line fragments instead.
- **SDL regex engine does NOT support lookarounds.** `(?=...)`, `(?!...)`, `(?<=...)`, `(?<!...)` all fail silently. Use explicit token delimiters or split into multiple formats.
- **SDL strips the leading `.*` from a regex before passing it to the Java engine.** This means using `.*?` (non-greedy) at the start of a regex produces an orphaned `?` which the engine rejects as "Dangling meta character '?' near index 0". Use plain `.*` and rely on normal greedy matching. If you need non-greedy behaviour, restructure the capture into two segments (see below).
- **Trailing `.*` at the END of a format string is also stripped (same root cause as leading `.*`).** A format ending in `$_body{regex=.*}$` or `$process.cmd_line{regex=.*}$` (the field marker is the last thing on the line, regex is exactly `.*`) silently captures the EMPTY STRING instead of "everything to end of line". The SDL leading-`.*`-strip rule applies regardless of whether the `.*` is the entire regex or merely starts it; with the `.*` stripped, the regex becomes empty and the field defaults to a zero-length capture. Tenant-validated 2026-05-26 on a linuxLogsParser sudo format: `COMMAND=$process.cmd_line{regex=.*}$` captured `""` (empty), whereas the same format with `regex=[\\s\\S]+` captured the full command-line including embedded spaces. Use `[\\s\\S]+` (one or more, including newlines) or `[\\s\\S]*` (zero or more, including newlines) at any field marker where you want "everything that remains on the line" semantics. Both forms avoid the leading-`.*` strip and survive intact.
- **Regex alternation matches in DECLARATION ORDER, not longest-leftmost.** `regex=CRON|CROND` is a bug: `CRON` is tried first and matches the literal prefix of `CROND`, leaving `D` to fail against the next literal in the format string. The fix is to put the LONGER alternative FIRST: `regex=CROND|CRON|crond|cron`. This applies anywhere alternation appears (named patterns, inline `{regex=...}`, regex in rewrites). Tenant-validated 2026-05-26: linuxLogsParser cron_cmd format with `CRON|CROND` matched zero CROND events; same format with `CROND|CRON` matched every cron variant. General rule: when alternatives share a prefix, sort by length descending.
- **`[\s\S]*?` (lazy) at the start of a prefix regex silently matches almost nothing — same family of bugs as `.*?`, but no error.** A fragment format like `$_pre{regex=[\s\S]*?}$$field{regex=PATTERN}$$_suf{regex=[\s\S]*}$` will fire on a tiny fraction of events instead of the expected matches, because the SDL regex engine does not backtrack across field boundaries when the prefix is lazy. The fix is the same shape as the multi-char-anchor rule: use greedy `[\s\S]*` plus a discriminating literal anchor inside the prefix regex itself (e.g. `[\s\S]*\"merchant_transaction_id\":\"` to anchor on a JSON key before capturing a CL transaction id). Tenant-validated 2026-05-13. If you actually need first-match semantics, anchor on a literal that only appears once per line (e.g. `\[log\.`, `\"url\":\"`), do not reach for `*?`.
- **Two-segment sequential capture pattern for JSON values inside a raw string.** When a log line is a raw JSON string (with `\"` escaping) and you need to extract a field value, use a two-segment format with a `$$` transition. First segment grabs everything up to and including the opening quote of the value into a scratch field; second segment captures the value up to the closing quote. Example for extracting `severity_name` before SDL coerces it: `$_ps{regex=.*\\\"severity\\\":\\\"}$$severity_name{regex=[^\\\"]*}$`. The `$$` boundary: the first `$` closes seg 1, the second `$` opens seg 2. The scratch field (`_ps`) must be in the format's OWN `discardAttributes: ["_ps"]` array (per-format, alongside `format:`) — parser-root `discardAttributes` does not reliably drop format-capture scratch fields on this tenant. This pattern works for any quoted string value in a JSON-encoded log line.
- **`$pri{parse=syslogPriority}$` can cause silent event drops on some tenants.** If you suspect priority parsing is the culprit, capture the priority as a plain field (`$pri{regex=\\d+}$`) and skip the parse directive.
- **Indexed positional access `attr[N]` only works in `mappings.version: 1`.** v0 mappings reject `attr[0]`/`attr[1]` syntax. If the source is positional CSV (Palo Alto Firewall is the canonical case), use v1. Reference: `parsers/sentinelone/marketplace-paloaltonetworksfirewall-latest/`.
- **`{parse=gron}` flattens nested JSON to dotted keys, but the keys themselves contain dots.** A source `{"Resource": {"Id": 5}}` becomes the single flat field `unmapped.Resource.Id` (one key with two dots), not a nested object. To rename it use `from: "unmapped.Resource.Id"` (no escapes). To rename a whole subtree use `rename_tree: { from: "unmapped.Resource", to: "resource" }` and the engine walks the dotted-prefix subtree. Reference: `parsers/sentinelone/marketplace-cloudflare-latest/`.
- **`attrBlacklist={field1,field2}` only filters subfields produced by a `{parse=...}` directive.** It does NOT filter top-level captured fields you named explicitly in the format string. To drop a top-level field use `discardAttributes: ["fieldname"]` at the parser root. Reference: `parsers/sentinelone/marketplace-fortinetfortigate-latest/`.
- **`{parse=...}` subfield naming is `<prefix><CapitalizedFirstLetterOfKey><restOfKey>`** (per SDL KB 000006743). Field `details` parsing `?apple=w&banana=x` yields `detailsApple` and `detailsBanana`, NOT `details_apple` / `detailsQuery_apple` / `details.apple`. Same convention for `{parse=json}` (camelCase): `details` parsing `{"foo":"hello"}` produces `detailsFoo`, not `details_foo`. Confirm the exact field name with a sample query if unsure — every "obvious" alternative spelling fails silently.
- **`{parse=uri}` and `{parse=uriAttributes}` consume the parent capture instead of preserving it.** After parsing, the original captured value is gone from the event; only the generated subfields remain (validated against current tenant April 2026). If you also need the raw URL/query string, capture it twice: once with the parse directive, once into a sibling scratch field, and `rename` the scratch one in `mappings`. Or split path/query directly in the format: `$path{regex=[^? ]+}$\??$qs{regex=[^ ]*}{parse=uriAttributes}$`.
- **`{parse=uri}` on relative URLs (no scheme/host) silently drops the query subfields on tested tenants.** It still emits `<prefix>Path`, but `<prefix><Key>` siblings for query parameters never materialize. Use `{parse=uriAttributes}` on the query-string portion (split manually with regex) instead — it works regardless of whether the URL is absolute.
- **`skipNumericConversion: true` is required when columns contain numeric strings you want preserved as strings.** Without it, `commaSeparatedvalues` and `pipeSeparatedValues` parse will coerce `"00123"` → `123` (loses leading zeros), `"0xDEADBEEF"` → `3735928559`, and `"1.0"` → `1`. Set `skipNumericConversion: true` on the format whenever any column is an opaque ID or a hex/octal string. Canonical: Palo Alto Firewall.
- **`intermittentTimestamps: true` is the only fix for sources where only the first record on each second has a timestamp.** Common with MySQL general query log, AWS RDS, sometimes VPC flow logs. Without it, every line that lacks a timestamp gets the ingest timestamp, not the inferred one. Reference: `parsers/sentinelone/marketplace-awsvpcflowlogs-latest/` and `parsers/community/sql_database_logs-latest/`.
- **`enum` cast in v1 mappings without `enum_default` leaves unmapped values UNCHANGED, not null.** If you want unknowns to map to a known sentinel, set `enum_default: <value>` on the cast. Cloudflare uses `enum_default: 99` ("Unknown") consistently — copy that pattern.
- **`severity_id` is an integer 0–6 reserved by ingest, just like `severity`.** Setting `severity_id: 999` silently fails. Use `severity` for the normalized integer (preferred), `severity_name` for the OCSF label string. Do not emit BOTH `severity` and `severity_id` from the same parser.
- **Rewrites run during format parsing; mappings run after all formats.** A field renamed in `mappings.rename` cannot be referenced by a `rewrites:` block on a later format on the same line because `rewrites:` runs per-format during capture. If you need a derived field from a renamed one, do the derivation inside `mappings` (use `copy` then `cast`, or `replace`).
- **Mixing `mappings.version: 0` and `mappings.version: 1` syntax in the same block is a hard error.** The engine rejects with "expected list got object" or "unsupported event mapper version -1". Pick one version per parser and stick to it.
- **Windows Event Log XML payloads ship with double-escaped tabs/newlines.** A parser for Windows EventLog in the catalog (`parsers/community/microsoft_windows_eventlog-latest/`) deals with `\\t` and `\\n` literals embedded inside XML strings; capturing them needs `\\\\t` / `\\\\n` (four backslashes) at the augmented-JSON layer.
- **Some catalog parsers ship without `dataSource.category` at all (~33% of community).** When you copy from `Sentinel-One/ai-siem`, audit the top-level `attributes:` block. If `dataSource.category` is missing, add it as `"security"`. If present with another value, change it to `"security"`. Same audit for `dataSource.name` and `dataSource.vendor`.
- **`$_=identifier$=$_=quoteOrSpace$` repeating idiom REQUIRES a leading `.*` AND `repeat: true`.** This is the canonical built-in `keyValue` parser shape and it is documented in the public KB as `".*$_=identifier$=$_=quoteOrSpace$"`. Without the leading `.*`, the format anchors at position 0 of the message and fires zero times on any line that doesn't start with an identifier — including every syslog log (`<189>date=...`), CEF (`CEF:0|...`), Windows Event (`<Event xmlns=...>`), or anything with a leading timestamp/priority. The format extracts **nothing** in that case, silently. The `.*` lets the engine scan forward to the first `key=` and then `repeat: true` walks the remaining pairs from there. Tenant-validated 2026-05-26 on FortiGate syslog (`<189>date=2026-05-25 time=18:07:18 devname="..." ...`): without `.*` zero fields captured; with `.*` all 30+ key=value pairs captured. The `keyValue` built-in parser uses exactly this shape (see `examples/03-key-value.json`). If you also need a separate static-prefix capture (e.g. to extract a syslog priority), put it in a SIBLING format that runs before the catch-all — each format runs against the full original `message` independently, so the prefix format and the `.*`-anchored KV format don't compete.
- **Conditional class assignment (one parser, multiple OCSF classes) is best done by stamping `class_uid`/`class_name` on each `format`'s `attributes:` block, not on the parser root.** The root attributes are baseline; per-format attributes override. Reference for fan-out via format-id sentinel + mapping predicates: `parsers/sentinelone/marketplace-awsrdslogs-latest/`.
- **Same-name `rename` in v1 mappings silently NULLS the field.** Writing `{ rename: { from: "action", to: "action" } }` to "keep" a captured raw field under its own name actually deletes the value. The KV catch-all extracts `action` (or any other raw vendor field) directly into the event under its native name — if you want to keep it, OMIT the rename. Only write a rename when the target name is different from the source. Tenant-validated 2026-05-26: identical FortiGate `action="perf-stats"` event returned `action=null` with the self-rename present, `action="perf-stats"` after removing the self-rename. This bites you when "promoting" raw fields that the catch-all already captures.
- **`raw_data` JSON blob is duplicate storage.** Many upstream Observo / collector extractions leave the entire raw event in a `raw_data` field alongside the typed-OCSF fields they extract. If your parser is also extracting those same fields via KV catch-all or named captures, the `raw_data` field is redundant and storage-wasteful. Either `discardAttributes: ["raw_data"]` at parser root or strip upstream. Don't store the same key=value pair three times (typed + unmapped + raw_data) — this was the Netskope anti-pattern. Audit on copy.
- **Unquoted numerics captured by `quoteOrSpace` are auto-typed as NUMBER columns.** No explicit cast required. A FortiGate `srcport=44321 dstport=443 sentbyte=8421` line going through `.*$_=identifier$=$_=quoteOrSpace$` produces `srcport: 44321` (number), `dstport: 443` (number), `sentbyte: 8421` (number) — all queryable with `avg()`, `sum()`, `> 100`, etc. without `number()` wrapping. The auto-inference fires when the captured token is purely numeric AND unquoted in the source. Quoted values (`level="notice"`) stay as strings even if they look numeric. Tenant-validated 2026-05-26 on FortiGate. Caveat: SDL's column type-locking still applies — if a column was ingested as string earlier, new numeric writes coerce back to string and `avg()` returns NaN. The CLAUDE.md project rule "wrap with `number()` before arithmetic" is still the bulletproof pattern for dashboard panels and STAR rule bodies, especially for counter columns (`traffic.bytes_*`, `traffic.packets_*`, `duration`).
- **`message` field is reserved and preserved on every event regardless of parser activity.** SDL never lets a parser overwrite `message`; the raw event body always survives. Practical consequence: dashboards and PowerQuery hunts that use `parse "fieldname=$x$ " from message` continue to work even after a parser renames the typed columns (`srcip` → `src_endpoint.ip`). This is the backward-compat escape hatch during parser rollout — old events still parse via message-text extraction, new events parse via typed columns. To migrate a dashboard from parse-from-message to typed columns without losing coverage on legacy events, use `(typed_field == * OR raw_field == *)` or `coalesce(typed_field, raw_field)` patterns. Tenant-validated 2026-05-26 on FortiGate dashboard rewrite: panels that switched to `src_endpoint.ip` continued returning the same row counts because the upstream Observo path was already producing typed src_endpoint.ip too; panels using `tls.sni` only show fortigateParser-tagged events because Observo didn't extract SNI.
- **When two ingest paths produce OCSF from the same source, they may flatten `event.type` / `event.subtype` differently.** Common pattern: upstream Observo collector flattens FortiGate `type=traffic subtype=forward` into a single `event.type='forward'` (drops the parent type). The downstream parser keeps both: `event.type='traffic', event.subtype='forward'`. Same source, two schema shapes coexisting on different events. Dashboards and hunts that filter on subtype must use OR: `(event.subtype='forward' OR event.type='forward')` — this matches both legacy and parser-tagged events. The rule: every time you migrate a downstream consumer to typed OCSF columns, audit each subtype filter for backward compat with the upstream shape during the rollover window.
- **`parser='<name>'` field may only be tagged for very recent events.** Some tenants are configured to stamp the `parser` field only on events ingested in the last N minutes (e.g., last 30 minutes). Queries filtering on `parser='myparser'` against a 24h window return only that recent slice, not 24h of data. For broad coverage validation, filter on `dataSource.name` + `metadata.version` (which IS retained per-event) instead, and use `parser=` only for isolating a specific recent ingest test. Tenant-validated 2026-05-26.

### Ingest-path gotchas (discovered empirically via live validation)

These are quirks of the ingest pipeline itself, not the parser DSL. They bite you at validation time even when the parser JSON is syntactically perfect.

- **HEC ingest splits on `\n` BEFORE the parser runs.** Multi-line events (stack traces, MySQL slow queries) get chopped up and `lineGroupers` cannot re-fold them. Workarounds:
  1. Fold multi-line events client-side into a single line with a sentinel character (e.g. `\x1e`), then have your parser split on that sentinel.
  2. Send each logical event as a single HEC event so newlines inside the event body are preserved.
- **The `server-host` upload header is unreliable for isolating a test.** SDL sometimes overrides the header to the literal source name, and if the parser extracts a `host` field from the log itself that wins too. Do NOT filter your validation query by `host='parser-test-<uuid>'` alone. Safer: filter by `parser='claude_test_<name>'` and `_bytes > 0`, and use a unique nonce in the payload to double-check isolation.
- **`{parse=dottedJson}` prefixes subfields when the field has a non-empty name.** `$payload{parse=dottedJson}$` on `{"user":"alice"}` yields `payload.user = "alice"`. If you want top-level fields, capture into an empty name: `${parse=dottedJson}$`. Same applies to `json`, `escapedJson`, `urlEncodedJson`, `base64EncodedJson`.
- **`getFile` on a missing config path raises HTTP 404**, it does not return `success=false` with `noSuchFile`. Wrap existence checks in a try/except when scripting cleanup.

### `mappings` block gotchas

Two syntaxes coexist on live tenants and both work. You must commit to one per parser — mixing them in the same mappings block produces confusing "expected list got object" errors.

**v1 (singular, preferred for new parsers, tenant-validated April 2026):**

- **`mappings.version: 1` is mandatory.** Without it the tenant returns `unsupported event mapper version -1`.
- **Each transformation is `{<op>: {...body}}`**, where the op name is the **outer key** (e.g. `{rename: {from, to}}`). The public-doc form `{op: "rename", from: ..., to: ...}` is rejected.
- **`rename.from` is a single string**, not a list. Use `copy` (which does accept a list) if you need "first of N".
- **`cast` uses `type:`**, not `to:`. Example: `{cast: {field: "x", type: "int"}}`.
- **`cast` overwrites the source field.** There is no `output:` parameter — `copy` first, then `cast` the copy.
- **Predicates use `==`** (double equals).

**v0 (plural-grouped, used by most S1 Marketplace parsers — AWS RDS, Corelight, Cloudflare, FortiGate):**

- **`mappings.version: 0`**. Same block, different body shape.
- **Ops are plural arrays on the mapping entry**: `renames: [...]`, `copies: [...]`, `constants: [...]`. No `transformations:` wrapper.
- **Every op entry uses `inputs: [list]` + `output:` + `type:`** — even `rename`. `type: "string"` is the safe default.
- **Predicates use `=`** (single equals) in v0, both on the mapping entry and inside `constants`.
- **WARNING: v0 `constants:` block is rejected on the current S1 tenant.** `putFile` returns `400: Syntax error at position -1: Assertion failed: Expected a field` when a `constants:` array is present, even with the documented body shape `[{output, value, type}]`. v0 `renames:` and `copies:` work fine; only `constants:` fails. Tenant-validated 2026-05-26: identical mapping block with `constants` removed deploys cleanly, with `constants` present is rejected. If you need conditional `class_uid` / `activity_id` fan-out from one parser to multiple OCSF classes, use **v1** — the v1 `{ constant: { field, value } }` op works reliably. This means: prefer v1 for any new parser that needs OCSF class fan-out. Stay on v0 only if you're extending an existing v0 parser that doesn't add new constants.

If you inherit a marketplace parser, keep it on v0 rather than rewriting (unless you need to add `constants` — then migrate to v1). For new parsers, pick v1. See `references/mappers.md` for the full side-by-side.

**`constant` / `constants` op** (both versions) is the workhorse for conditional OCSF class/activity assignment — give it a `predicate` and it only fires when matched, so you can fan one vendor-native state code (`conn_state`, `action`, etc.) out into `activity_id` + `activity_name` + `type_uid` triples.

**Inline `predicate:` on individual `constant` ops is the cleanest escape hatch from first-match-wins in v1.** When you want a long list of unconditional renames/copies AND a handful of conditional `constant` writes (severity bucketing, OCSF enum derivation from a vendor string, action/status/disposition fan-out), DO NOT split them across multiple top-level mapping entries — only the first matching entry fires. Instead, put EVERYTHING in one `predicate: "true"` entry and attach a `predicate:` field directly to each conditional `constant` op:

```js
mappings: {
  version: 1,
  mappings: [{
    predicate: "true",
    transformations: [
      // ... unconditional renames / copies / casts ...
      { copy: { from: "raw_severity", to: "vendor.severity_raw" } },

      // Conditional constants — predicate lives ON THE OP, not the mapping entry.
      { constant: { field: "severity_id", value: 1, predicate: "vendor.severity_raw >= 0 && vendor.severity_raw <= 3"  } },
      { constant: { field: "severity_id", value: 3, predicate: "vendor.severity_raw >= 4 && vendor.severity_raw <= 6"  } },
      { constant: { field: "severity_id", value: 4, predicate: "vendor.severity_raw >= 7 && vendor.severity_raw <= 8"  } },
      { constant: { field: "severity_id", value: 5, predicate: "vendor.severity_raw >= 9 && vendor.severity_raw <= 10" } },

      { constant: { field: "action",    value: "Allowed", predicate: "raw_action == 'alert' || raw_action == 'allow'" } },
      { constant: { field: "action_id", value: 1,         predicate: "raw_action == 'alert' || raw_action == 'allow'" } },
      // ... etc ...
    ]
  }]
}
```

This pattern preserves first-match-wins semantics at the mapping-entry level (which can't be worked around) while still letting you express N independent conditional writes without duplicating the rename list across N per-subtype blocks. Use it whenever you have a flat schema (one event shape, many conditional derivations) — severity bucketing, action/status/disposition fan-out from a vendor enum, HTTP-status → OCSF status_id, and so on. The alternative — splitting into per-subtype top-level mapping entries — only makes sense when the per-subtype rename lists are genuinely different (different OCSF classes per event subtype). Tenant-validated May 2026 on a CEF source with ~20 conditional ops: all fired from a single `predicate: "true"` mapping entry; the same logic split across multiple top-level entries produced zero hits on every conditional write because only the first entry ran. See `examples/11-*-cef-ocsf.json` for the runnable reference.

**Predicate type-mismatch silently fails on captured numerics.** The KV catch-all auto-types unquoted values as NUMBER (pitfall #5 in *Critical pitfalls*). That means a predicate like `raw_severity == '5'` — quoted string — never matches a `raw_severity` captured as integer 5. Use bare numerics in predicates for numeric fields (`raw_severity >= 4`, `http_response.code < 400`) and quoted strings only for actually-string fields (`raw_action == 'alert'`, format-id sentinels `mySqlErrorLog == 'true'`). When in doubt, run a quick query on a recent parsed event and check `cellType` in the response — STRING vs NUMBER — before writing the predicate. A string predicate against a numeric field silently drops every dependent op; the only symptom is the target field being null on every event, which can take several deploy/iterate cycles to localize. Tenant-validated May 2026.

**OCSF `severity_id` is an enum `{0,1,2,3,4,5,6,99}`, NOT a vendor passthrough.** Many sources (CEF 0-10, syslog 0-7, custom 0-100) ship a wider-range numeric severity. Renaming the raw value directly into `severity_id` produces invalid OCSF (e.g. `severity_id=10` when a vendor uses 0-10) AND semantically false detections (vendor "5 out of 10" means Medium for that vendor, but `severity_id=5` is OCSF "Critical" — every routine event suddenly looks Critical to downstream consumers). Always bucket via per-op predicates and preserve the raw value under a vendor namespace (`vendor.severity_raw`, `cef.severity`) for source fidelity. Reference bucketing for a 0-10 scale: `0-3 → 1 Informational, 4-6 → 3 Medium, 7-8 → 4 High, 9-10 → 5 Critical`. For 0-7 syslog: `0-1 → 5 Critical, 2-3 → 4 High, 4 → 3 Medium, 5-7 → 1 Informational`. Same `severity` (no suffix) is RESERVED and coerced to 0-6 by ingest, so emit `severity_id` (the integer) and optionally `severity_name` (a label string) — never both `severity` and `severity_id` from the same parser. Tenant-validated May 2026: a parser that passed CEF 0-10 directly into `severity_id` emitted invalid OCSF values (`severity_id=10`) AND tagged the bulk of routine traffic as Critical; the bucketed replacement produced semantically correct severity_ids for the same input stream.

**Format-id-as-sentinel predicate**: `format: { id: "mySqlErrorLog", ... }` auto-sets a boolean-string field `mySqlErrorLog='true'` on events that matched that format. Use `predicate: "mySqlErrorLog='true'"` (v0) or `"mySqlErrorLog == 'true'"` (v1) to fan mapping entries out to sub-shapes. Quote the `'true'` — it's a string, not a bare boolean.

**`mappings.version: 1` uses FIRST-MATCH-WINS, not all-match.** The first mapping block whose predicate matches consumes the event — no subsequent blocks run. This is the single most important structural constraint when using v1. Consequences:
- A `predicate: "true"` unconditional block placed FIRST will fire on every event and prevent all per-app conditional blocks from ever executing. Always place the catch-all at the END.
- `drop` / `drop_tree` transformations cannot be factored into a standalone unconditional block at the start and shared across per-app blocks. They must be duplicated into each per-app block. Verbose but correct.
- **`rename` ops have the SAME problem as `drop`.** If you have a catch-all rename block at the end (typed-OCSF migration: srcip → src_endpoint.ip, devname → device.name, etc.) AND per-subtype `constant` blocks earlier (for activity_id fan-out), the catch-all rename NEVER fires for events that matched a per-subtype block — only the catch-all events get renamed. The per-subtype events keep raw vendor field names. To make the parser produce typed OCSF on ALL events, you MUST duplicate the rename list into every per-subtype block alongside its constants. Tenant-validated 2026-05-26 on FortiGate v1.1.0: with renames only in catch-all, event.subtype='forward' events had activity_id=6 from the constant block but src_endpoint.ip=null because the rename never ran; with renames duplicated into the per-subtype block, all fields populated. Pattern: each per-subtype block = its own constants + the full rename list. Verbose but correct.
- v0 mappings DO run all matching blocks (marketplace parsers like Cloudflare and FortiGate rely on this: an unconditional first block handles common renames, then conditional blocks handle sub-types). If you need multiple pass-through effects, consider whether v0 is a better fit — but note v0 lacks `drop`/`drop_tree` AND v0's `constants:` is currently rejected on this tenant (see WARNING above), so v0 is only viable if you don't need either.

**`discardAttributes` MUST be placed per-format, not at parser root, for scratch fields created by format captures.** The parser-root `discardAttributes: [...]` block does NOT reliably drop fields that named-capture markers `$_xxx{...}$` produced inside a format string. Scratch fields like `_dw_pre`, `_dw_tail`, `_lc_pre`, `_lc_suf`, etc. leak through to the final event despite being listed at the root. The reliable form is to put `discardAttributes: ["_dw_pre", "_dw_tail", ...]` ON THE FORMAT OBJECT ITSELF, as a sibling key to `format:`. This matches the built-in `json` parser's shape: `formats: [ { format: "$json{parse=json}$", repeat: true, discardAttributes: ["message"] } ]`. Tenant-validated 2026-05-13. Parser-root `discardAttributes` can still be used for noise fields produced by `{parse=json}` / `{parse=dottedJson}` flat-expansion of vendor JSON keys (e.g. `flipkart_not_secure`, `upstream_addr`) — those are not format captures and do get dropped from the root.

**`discardAttributes` also does NOT remove fields produced by `{parse=gron}` at the top level.** If `{parse=gron}` extracts `host`, `facility`, `sndr`, etc. directly to the event root, adding them to `discardAttributes` (root OR per-format) has zero effect. Use `mappings.drop` / `mappings.drop_tree` for those instead (see the next two gotchas). Tenant-validated May 2026.

**`attrBlacklist` on a bare `{parse=gron}` format cannot drop top-level fields.** The `attrBlacklist` directive only filters subfields when a NAMED PREFIX is in use — e.g. `$payload{parse=gron}{attrBlacklist=debug}$` drops `payload.debug`. Without a named prefix (`${parse=gron}{attrBlacklist=host,sndr}$`), the blacklist is ignored for top-level keys because there is no prefix namespace to filter within. This means `{parse=gron}` with `attrBlacklist` cannot be used to suppress noise fields at the root level. Tenant-validated May 2026.

**The correct mechanism for dropping top-level gron-produced fields is `mappings.drop` / `mappings.drop_tree`.** Add `{ drop: { field: "host" } }` (scalars) and `{ drop_tree: { field: "object" } }` (subtrees) in the `transformations` of every applicable mapping block. Because v1 is first-match-wins, these drop ops must be duplicated into each per-app block AND in the catch-all block — there is no shortcut.

### `computeFields` gotchas

- **Use PowerQuery ternary `a ? b : c`**, not `if(a, b, c)`. The latter returns `Unknown function 'if'`.
- **Use `==` for equality**, not `=`.
- **Cannot reference dashed field names.** `protocol-id` is parsed as subtraction. Rename via `mappings` first, or do the translation entirely in the mappings block.
- **Place the rewrite on the format that captures the source field.** If a repeating key/value sub-format is what produces the field, the rewrite belongs on the sub-format — not on the frame format above it.
- **The `replace` MAPPER op is a runtime no-op on this tenant; use a `computeFields` + PowerQuery `replace()` rewrite instead.** Two traps with `{ replace: {...} }` in a `mappings` block: (1) the regex key is `regexp`, NOT `pattern` — `pattern` returns `400: Missing required key 'regexp'` on `putFile` (the `mappers.md` example showing `pattern` is wrong); (2) even with the correct `regexp` key the op silently does NOT transform the value at ingest (validated on both a dotted target `process.cmd_line` and a flat scratch field, 2026-06-01). The working substitute is a `computeFields` rewrite calling the PowerQuery `replace(field, regex, replacement)` string function. PowerQuery string literals are SINGLE-quoted, so a regex containing double-quotes needs no escaping inside the expression: `expression: "| let _cmdline = replace(_cmdline, 'a[0-9]+=\"([^\"]*)\"', '$1')"`. Capture into a FLAT scratch field (computeFields and `replace` address flat names cleanly; dotted paths are unreliable), then `rename` the scratch field to the dotted OCSF target in `mappings`. This is how the auditd parser turns an EXECVE arg vector `a0="cp" a1="/x" a2="/y"` into a readable `process.cmd_line` = `cp /x /y`.
- **There is NO hex / base16 decode primitive anywhere in the DSL or in `computeFields`.** The `{parse=...}` directives offer `base64EncodedJson` / `urlEncodedJson` but no hex; the PowerQuery subset available to `computeFields` has no position-aware hex decoder either. auditd `proctitle` (and individual hex-encoded `EXECVE` args) are NUL-separated hex and cannot be turned into ASCII in-parser. Source the readable command line from the EXECVE arg vector instead (auditd stores those as plain ASCII), and leave the hex `proctitle` as-is. Do not burn iterations trying `replace`/regex to hex-decode.

### Interaction between `halt: true` and repeat formats

- **`halt: true` stops ALL further format matching on that line** — including repeating key/value catch-alls. If you have a two-format pattern (frame + repeating extractor), do NOT put `halt: true` on the frame format; the extractor will never fire.

## Validation (mandatory)

Always validate against the live tenant via the `sdl-api` skill. Do not rely solely on the syntactic plausibility of the JSON — the only authoritative test is "did the field actually appear in a query after ingest." This is what the in-console `Test Parser` button approximates client-side; doing it through the API exercises the real ingest pipeline.

```python
import sys, os, time, uuid, json
_sdl_scripts = os.environ.get("SDL_API_SCRIPTS") or os.path.normpath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "sdl-api", "scripts")
)
sys.path.insert(0, _sdl_scripts)
from sdl_client import SDLClient

c = SDLClient()
PARSER_NAME = "claude_test_<descriptive_name>"   # use a claude_test_ prefix so cleanup is easy
parser_body = open("/path/to/draft.json").read()
sample = open("/path/to/sample.log").read()

# 1. Deploy
c.put_file(f"/logParsers/{PARSER_NAME}", content=parser_body)

# 2. Ingest a sample with a unique nonce + host so we can isolate it
host_tag = f"parser-test-{uuid.uuid4().hex[:8]}"
hec_ingest(content=sample, parser=PARSER_NAME, server_host=host_tag)  # HEC ingest applies the parser; replaces the removed uploadLogs

# 3. Wait briefly, then query back
time.sleep(8)  # ingest-to-search latency
res = c.power_query(
    query=f"host='{host_tag}' | columns timestamp, message, <expected_fields>",
    start_time="5m",
)
print(json.dumps(res, indent=2))
```

A successful validation means: (a) `putFile` returned `success`, (b) HEC ingest returned `success`, (c) the `power_query` returned at least as many rows as you ingested, (d) the expected fields are populated and not null.

If a field is missing, do NOT just retry — diagnose. Common causes: wrong escape level on a regex, a delimiter that didn't match (the format silently fails to apply), `halt: true` on an earlier format catching the line first, or `discardAttributes` dropping the field by mistake.

### Cleanup

After validation, decide with the user whether to keep, rename, or delete the parser. For throwaway tests:

```python
c.put_file(f"/logParsers/{PARSER_NAME}", delete=True)
```

For something the user wants to keep, rename to a non-`claude_test_` name (`get_file` → `put_file` new name → delete old).

## Bundled references

When a question goes deeper than this file, read the relevant reference. Each is a focused deep-dive — load only what you need.

- `references/ai-siem-catalog.md` — **Check this first** before writing a new parser. Map of the public S1 parser repo (~150 parsers across community + marketplace), per-shape template recommendations, style-variance cheat sheet, and the fetch recipe.
- `references/ocsf-mapping.md` — **Then start here** for any new parser. OCSF class quick-pick (4001/4002/3002/1001/etc.), field-to-dotted-path mapping tables for Network Activity, Authentication, and File Activity, and the two authoring idioms: capture directly into dotted names vs capture vendor-native then rename via a `mappings` block. Also covers boolean/enum normalization (`YES`/`NO`/`UNKNOWN` → `tls.is_encrypted`). Points at `ocsf-schema-documentation.md` for authoritative field names.
- `references/ocsf-schema-documentation.md` — **Authoritative OCSF field catalog** — the full SentinelOne community-documented schema: 7 categories × 96 articles × ~25,759 field entries across every OCSF event class (System Activity, Findings, IAM, Network Activity, Discovery, Application Activity, Unified Alert Management). Grep this file for any OCSF field name you're about to emit — don't invent names. Always check this before choosing a dotted path, especially for classes beyond Network/Auth/File.
- `references/syntax.md` — Full augmented-JSON parser syntax: formats, patterns, attributes, lineGroupers, rewrites (including `computeFields` and `timeDelta`), special fields (timestamp/severity/message), discard, halt, repeat, association, intermittentTimestamps, skipNumericConversion. Read when authoring anything beyond a simple line format.
- `references/parse-directives.md` — Every `{parse=...}` sub-parser (json/dottedJson/escaped/urlEncoded/base64Encoded variants, strict variants for arrays, uri/uriMultivalue/uriAttributes, commaKeyValues, commaSeparated/pipeSeparated, sqlToSignature, syslogPriority, dateTime{Seconds,Ms,Ns}, hoursMinutesSeconds, seconds/milliseconds, bytes/kb/mb/gb, plus per-directive `attrWhitelist`/`attrBlacklist` rules). Read whenever the body of a field is itself structured.
- `references/builtin-parsers.md` — Catalog of all 16 built-in parsers (`accessLog`, `cloudfront`, `json`, `dottedJson`, `dottedEscapedJson`, `elb-access`, `heroku-logplex`, `keyValue`, `leveldbLog`, `mysqlGeneralQueryLog`, `mysqlSlowQueryLog`, `postgresLog`, `redshift`, `s3_bucket_access`, `spot_instance_data`, `systemLog`) and when to alias vs override. Read first when sizing up a new log source — you may not need to write a parser at all.
- `references/mappers.md` — `mappings` block (gron-style transformations: `cast`, `copy`, `copy_tree`, `drop`, `drop_tree`, `hash`, `reduce_array`, `rename`, `rename_tree`, `replace`, `zip`), array index syntax, predicate semantics. Read when restructuring events to OCSF or another target schema.
- `references/testing-workflow.md` — Detailed validation recipe with the `sdl-api` skill, including how to scope queries with a unique host tag, how to interpret common error responses, and how to clean up.

## Bundled examples

Annotated, runnable parser definitions. Copy and adapt rather than starting from scratch.

- `examples/01-cef-over-syslog.json` — Syslog-framed CEF (`<PRI>timestamp host CEF:0|...|...|key=value`). Demonstrates: `syslogPriority` parse, named timestamp pattern, positional pipe-delimited CEF header, key/value catch-all on the extension.
- `examples/02-json-with-envelope.json` — `<timestamp> <host> {"...json..."}`. Demonstrates: timestamp + host extraction, `{parse=dottedJson}` on the body, `discardAttributes: ["message"]`.
- `examples/03-key-value.json` — Pure `key=value` lines. Demonstrates: the `$_=identifier$=$_=quoteOrSpace$` repeating idiom and a leading static prefix.
- `examples/04-multiline-stack.json` — Java/Python stack traces. Demonstrates: `lineGroupers` with `continueThrough`, attribute tagging.
- `examples/05-rewrite-and-mask.json` — Single line format plus `rewrites` to mask `password=...` values and compute a derived field via `computeFields`.
- `examples/06-alias.json` — One-line alias parser (`{ aliasTo: "json" }`) for the case where a built-in already does the job.
- `examples/07-juniper-srx-rtflow-ocsf.json` — Juniper SRX RT_FLOW_SESSION_CREATE (structured-data syslog, RFC 5424-ish). Demonstrates: the **vendor-native capture + `mappings.rename` to OCSF** idiom end-to-end (source-address → `src_endpoint.ip`, nat-source-address → `connection_info.src_translated.ip`, etc.), repeating key/value catch-all on the structured-data body, `computeFields` for protocol-id → `connection_info.protocol_name` and encrypted YES/NO → `tls.is_encrypted`, Network Activity 4001 class tagging.
- `examples/08-gron-capture-template.json` — The PARSER_TEMPLATE shape lifted from `ai-siem`: capture the entire event with `$unmapped.{parse=gron}$`, then do every rename/copy/cast/constant in a single v1 `mappings` block. Ideal scaffold for JSON-shaped sources when you want all OCSF work in one place.
- `examples/12-linux-auditd-ocsf.json` — Linux auditd over syslog (`<pri> ts audispd: type=<REC> msg=audit(<epoch>:<id>): k=v ...`). Demonstrates: a ` type=`-anchored record-type + audit-event-id capture (with the leading space that avoids the `nametype=` collision), the KV catch-all, v1 first-match-wins `mappings` fanning the record type out to OCSF classes (SYSCALL/EXECVE/PROCTITLE → Process 1007, PATH/CWD → File 1001, USER_*/CRED_* → Authentication 3002, ANOM_*/AVC/SECCOMP → Detection Finding 2004, SOCKADDR → Network 4001), per-op `predicate` status/severity derivation, and cleaning the EXECVE arg vector into a readable `process.cmd_line` via a `computeFields` PowerQuery `replace()` (the `replace` mapper op is a no-op and there is no hex decode for `proctitle`).
- `examples/README.md` — When to pick which template.

## Summary of the contract you're holding

When a user pastes a log and asks you to parse it, you owe them: (1) a parser file written against the SDL augmented-JSON DSL, (2) proof it actually extracts the right fields when ingested through the live SDL pipeline (not just the editor preview), (3) a clean handoff (final path, fields, sample query). The bundled references and examples exist so you don't have to hold the entire DSL in your head — load them as needed and reach for the templates first.


## Parser deployment via s1-secops-mcp

Parser deployment and validation use the `s1-secops-mcp` MCP tools, which bypass the
Cowork sandbox proxy entirely. Use `sdl_put_file`, `sdl_get_file`, `sdl_list_files`,
and `hec_ingest` directly instead of falling back to the `sdl-api`
skill scripts. The MCP tools run locally on your machine and make direct HTTPS calls
to `*.sentinelone.net` without proxy interference.


## Per-app sentinel pattern (multi-tenant / multi-service parsers)

Use this pattern when a single parser handles events from many distinct services or applications, each needing its own OCSF class assignment.

### Pattern overview

1. **Extract a discriminator field** (e.g. `app_name` from a raw JSON `app_id` key) using a two-segment capture format.
2. **Create one format-id sentinel per service**: `{ id: "my_app", format: "$_scratch{regex=.*\"app_id\":\"my-app-id\"}$" }`. This sets `my_app='true'` on matching events.
3. **List all sentinel field names in `discardAttributes`** so they don't appear in the output event.
4. **Add one v1 mappings block per sentinel** with the OCSF constants and any drop ops. Because v1 is first-match-wins, drops cannot be factored into a shared block — duplicate them in every block including the catch-all.
5. **End with a `predicate: "true"` catch-all** that applies drops but assigns no class. Place it last or it will consume every event.

### How to add a new service

1. Confirm the new service's discriminator value (e.g. sample a few raw events via PowerQuery).
2. Check whether it already fires an existing sentinel (e.g. a shared type field that already has a sentinel). If yes, no new entry needed.
3. Add the sentinel ID to `discardAttributes`.
4. Add a format entry before the catch-all sentinels.
5. Add a mapping block before `predicate: "true"` with the right OCSF constants and all noise drops.
6. Bump `metadata.version` (minor bump for new service; patch for fixes).
7. Deploy via `sdl_put_file` with the current `expectedVersion` from `sdl_get_file`.
8. Wait ~3 min for propagation, then verify on a short window (5 min): `dataSource.name = 'MySource' | group count=count(), has_class=count(class_uid) by app_name | filter app_name = 'my-new-service'`.

### Periodic audit query

Run this periodically to catch new services that have accumulated in the catch-all:

```
dataSource.name = 'MySource' app_name = *
| group count=count(), has_class=count(class_uid) by app_name
| filter has_class == 0
| sort -count
```

Any `app_name` with `has_class == 0` and meaningful volume is a candidate for a new sentinel.

## Onboarding learnings (tenant-validated 2026-06-13, usea1-purple)

These came out of onboarding Cisco Meraki via the `sdl-solutions` onboarding playbook.

- **JSON-per-line flatten needs a dotted-prefix capture.** `format: "$unmapped.=json{parse=dottedJson}$"`
  flattens the body into `unmapped.*` queryable fields. A non-prefix capture name like
  `$json{parse=json}$` captures the raw JSON string and emits NO subfields, so every field reads
  null after deploy and only the parser-root `attributes` (e.g. `dataSource.name`) apply. This is
  already shown in `examples/02-json-with-envelope.json`; reach for it first for any JSON source.
- **`mappings` requires `version: 1` and `transformations`.** The error
  `Got unsupported event mapper version -1` on `putFile` means the `mappings` block is missing
  `version`. Ops go inside `transformations: [...]`, each as `{ <op>: {...} }`.
- **Parsers are account-level.** Deploy at account scope even when the data ingests at a site.
  There is no site-scoped `/logParsers/` file; the sourcetype label binds events to the parser.
- **Activation latency is 3 to 5 minutes per deploy** on this tenant, not seconds. Batch parser
  edits and wait out the window before validating, rather than iterating one field at a time.
- **A `parser=<name>` label with no `/logParsers/<name>` file and no `dataSource.name`** means the
  events were tagged with a sourcetype but never transformed (e.g. a marketplace `*-latest` label
  with no editable file). Creating the parser at that exact path normalises the live stream. The
  initial `sdl_get_file` 404 is a "create me", not an error.
- **Network-source enrichment keys on IP.** Build an IP-keyed endpoint lookup
  (`datasource assets from 'surface/endpoint'`, keyed on `agentLastReportedIp`) and join in the
  `computeFields` rewrite `by device_ip = unmapped.src_ip` using the pre-rename `unmapped.*` field,
  since the rewrite runs before `mappings` renames.
