# Log Mappers (`mappings` block)

Mappers run *after* the parser emits an event and restructure it in place. They're the mechanism for conforming events to OCSF, ECS, or any other target schema without authoring a custom ingest pipeline.

> **Two equivalent syntaxes are in the wild.** Both work on current tenants. Pick one and stick to it within a parser — do not mix.
>
> - **`version: 1` / singular-op** — tenant-validated April 2026, used by the `PARSER_TEMPLATE` and by parsers authored against the latest mapper engine. Each transformation is `{<op_name>: {...body}}`. Predicates use `==`. This is what you should prefer for new parsers — see §"Block shape (v1, preferred)".
> - **`version: 0` / plural-grouped** — used by most S1 Marketplace parsers (AWS RDS, Corelight, Cloudflare, Fortinet). Operations are plural arrays at the top level of each mapping entry: `renames: [...], copies: [...], constants: [...]`. Predicates use `=`. See §"Block shape (v0, marketplace)".
>
> If one syntax fails validation, the engine error message will tell you (`unsupported event mapper version -1` means `version:` is missing; predicate parse errors usually flag the equality operator). When adapting a catalog parser, check the version at the top of the `mappings` block and keep the matching syntax.

## Block shape (v1, preferred)

```js
mappings: {
  version: 1,                                // REQUIRED. Without it the tenant returns
                                             // "unsupported event mapper version -1".
  mappings: [
    {
      predicate: "metadata.event_code == 'RT_FLOW_SESSION_CREATE'",  // first match wins; see "Notes that bite people" below
      transformations: [
        // Each transformation is { <op_name>: { ...body... } }.
        // op_name is the OUTER key — NOT an `op:` field.
        { rename:   { from: "source-address",        to: "src_endpoint.ip" } },
        { cast:     { field: "src_endpoint.port",    type: "int" } },
        { drop:     { field: "debug" } },
        { constant: { value: 4001,  field: "class_uid" } },
        { constant: { value: "Open", field: "activity_name",
                      predicate: "conn_state == 'S1'" } }
      ]
    }
  ]
}
```

Notes that bite people:

- **First-match-wins.** Mapping entries are tried in declaration order; only the first entry whose `predicate` matches an event runs its `transformations`. A `predicate: "true"` catch-all therefore MUST go last in the list, otherwise it shadows every entry below it and they silently never fire (renames don't apply, per-class constants stay overridden by the catch-all). When you want a default-then-overrides pattern, structure the entries as: most specific predicates first, generic catch-all last. If two predicates are equally specific and both should fire on the same event, fold their transformations into a single entry. Validated against tenant April 2026.
- `version: 1` at the top of the block is mandatory.
- Each transformation's op is the **outer key**. Public docs sometimes show `{op: "rename", from: ..., to: ...}` — that is wrong. Use `{rename: {...}}`.
- `from` on `rename` is a **single string**, not a list. If you need "first of N matches", use `copy` first (which does accept a list) then `rename`/`drop`.
- `cast` takes `type: "..."`, not `to: "..."`. So `{cast: {field: "x", type: "int"}}`.
- `cast` does NOT honor an `output:` key — it overwrites the source field. To cast into a different field, `copy` first, then `cast` the copy.
- Predicate uses `==` (double-equals), not `=`.
- `rename` silently no-ops when the source field is absent, which is the idiom that lets a single catch-all entry hold renames for several different vendor-native key sets (e.g. `verb` → `http_request.http_method` for app A, `method` → `http_request.http_method` for app B). Each rename only fires on events that actually carry that source key.

## Block shape (v0, marketplace)

Most S1 Marketplace parsers (AWS RDS, Corelight, Cloudflare, Fortinet FortiGate) use the older "plural-grouped" syntax. If you are starting from one of those, keep this shape rather than rewriting:

```js
mappings: {
  version: 0,                                      // NOT 1 — must match the body shape below.
  mappings: [
    {
      predicate: "true",                           // unconditional
      copies: [
        { inputs: ["ts"],  output: "time",                  type: "string" },
        { inputs: ["uid"], output: "uuid",                  type: "string" }
      ],
      renames: [
        { inputs: ["id.orig_h"], output: "src_endpoint.ip", type: "string" },
        { inputs: ["id.resp_p"], output: "dst_endpoint.port", type: "string" }
      ],
      constants: [
        { value: 4,       field: "activity_id",   predicate: "conn_state = 'S0'" },
        { value: "Fail",  field: "activity_name", predicate: "conn_state = 'S0'" },
        { value: 400104,  field: "type_uid",      predicate: "conn_state = 'S0'" }
      ]
    }
  ]
}
```

Differences from v1:

- Top-level ops are **plural arrays**: `copies`, `renames`, `constants` (not `transformations`).
- Each op entry has `inputs: [list]` (even for `rename` — always a list in v0) + `output: "..."` + `type: "..."`.
- Predicate inside a constant uses `=` (single equals). Engine-level predicates (the outer `predicate:` on the mapping entry) also accept `=` in v0.
- `type:` on copies/renames is a soft coerce — `"string"` is the universal safe choice when in doubt.
- No `transformations` wrapper. The ops are direct keys on the mapping entry.

**When to use v0:** when you are copying a marketplace parser and want a minimal diff. **When to use v1:** for all new parsers, because `transformations` keeps ordering explicit and makes fan-out patterns (`cast` after `copy`, multiple `constant` with different predicates) easier to read.

### Format-id-as-sentinel predicate pattern (both versions)

When a single parser produces several distinct event shapes (e.g. AWS RDS emits MySQL error, MySQL general, Postgres), give each format an `id:` and fan mapping entries out by asserting on that id in the predicate. The format id is auto-set as a boolean field on the event when that format matches:

```js
formats: [
  { id: "mySqlErrorLog",   format: "...", halt: true, attributes: {...} },
  { id: "mySqlGeneralLog", format: "...", halt: true, attributes: {...} },
  { id: "postgresqlLog",   format: "...", halt: true, attributes: {...} }
],
mappings: {
  version: 0,
  mappings: [
    { predicate: "mySqlErrorLog='true'",   constants: [ /* MySQL error defaults */ ] },
    { predicate: "mySqlGeneralLog='true'", copies:    [ /* general-log mapping */ ] },
    { predicate: "postgresqlLog='true'",   copies:    [ /* postgres mapping */ ] }
  ]
}
```

In v1 the same pattern works with `predicate: "mySqlErrorLog == 'true'"`. The sentinel is a string `'true'` (quoted), not a bare boolean.

## Prereqs for the data shape

The event must already be in a gron-friendly form (dotted keys, flat or sparingly nested). You get this automatically when you:

- capture with `{parse=json}` / `{parse=dottedJson}` / `{parse=gron}`, or
- capture individual fields into dotted names (`$src_endpoint.ip$`) in your `formats`.

SKU: Ops Center only; not available on FedRAMP or self-hosted at time of writing.

## Gron-style field references

- `a.b`, `a.b.c` — nested object fields.
- `a.b[1]` — array element by index.
- `a.b[-1]` — **append** to array.
- `a.b[x]` — **labeled index**; appends once, then later operations referencing `[x]` target the same slot.
- `a.b[*]` — **wildcard**; apply the operation to every element.

## Operations (tenant-validated shapes)

### `rename` — rename a field

```js
{ rename: { from: "source-address", to: "src_endpoint.ip" } }
```

- `from` is a **single string** (vendor-native field name; dashes OK).
- `to` is the target path.
- If `from` doesn't exist on the event, the transformation silently no-ops.

### `copy` — copy a field (supports first-of-N)

```js
{ copy: { from: ["client.ip", "source.ip"], to: "actor.session.terminal.ip",
          default: "unknown" } }
```

- `from` is a **list**; first existing key wins.
- `default` optional — used when no source hits.

### `cast` — convert a field's type or enum

```js
// Primitive
{ cast: { field: "src_endpoint.port", type: "int" } }

// Enum
{ cast: { field: "connection_info.protocol_name",
          type: "enum",
          enum: { "6": "TCP", "17": "UDP", "1": "ICMP" } } }

// Range
{ cast: { field: "severity.id",
          type: "range",
          range: [
            { lt: 2, value: "low" },
            { lt: 4, value: "medium" },
            { lt: 6, value: "high" },
            { value: "critical" }
          ] } }

// Timestamps
{ cast: { field: "ts", type: "iso8601TimestampToEpochSec" } }
{ cast: { field: "ts", type: "datetime",
          format: "yyyy-MM-dd HH:mm:ss", units: "ms" } }
```

Primitive `type`: `bool`, `int`, `float`, `string`.

Semantic `type`: `iso8601TimestampToEpochSec`, `iso8601DateToEpochSec`, `epochSecToIso8601Timestamp`, `datetime`, `range`, `enum`.

**`cast` overwrites the source field.** There is no `output:` parameter. If you need the casted value in a different field, do:

```js
{ copy: { from: "connection_info.protocol_num", to: "connection_info.protocol_name" } },
{ cast: { field: "connection_info.protocol_name", type: "enum",
          enum: { "6": "TCP", "17": "UDP", "1": "ICMP" } } }
```

### `constant` — set a field to a constant value (optionally conditional)

```js
// v1 (singular):
{ constant: { value: 4001, field: "class_uid" } }

// Conditional — only fires when the predicate matches.
{ constant: { value: "Fail",  field: "activity_name",
              predicate: "conn_state == 'S0'" } }
{ constant: { value: 400104, field: "type_uid",
              predicate: "conn_state == 'S0'" } }
```

In v0 `constants: [...]` these look like `{ value: ..., field: ..., predicate: "..." }` with single-equals predicates. The op is indispensable for OCSF class/activity/type assignment: the same parser typically emits a dozen `constant` transformations, each gated on a vendor-native state code (`conn_state`, `event_type`, `action`, etc.) and each writing a different OCSF enum triple (`activity_id` + `activity_name` + `type_uid`).

Think of `constant` as "add a field that the source didn't have, possibly because the raw event contained a code we want to translate." Unlike `cast {type: "enum"}`, `constant` can assign multiple target fields (one per transformation) from the same source condition, which is the common OCSF need.

### `drop` — remove a scalar field

```js
{ drop: { field: "debug" } }
```

### `drop_tree` — remove an object/array subtree

```js
{ drop_tree: { field: "raw_internals" } }
```

### `copy_tree` — copy a subtree

```js
{ copy_tree: { from: "headers", to: "http_request.headers" } }
```

Object-to-object is additive; type mismatches replace. Empty-string `from: ""` copies the event root.

### `rename_tree` — rename a subtree

Same shape as `rename`, but operates on an object subtree. Additive when types match, replacing otherwise.

### `hash` — hash a string field

```js
{ hash: { field: "actor.session.terminal.ip", to: "actor.session.terminal.ip_sha256",
          algo: "sha256" } }
```

Algorithms: `sha1`, `sha256`. Output is lowercase hex with no `0x` prefix.

### `reduce_array` — collapse an array

```js
// Params array → dict
{ reduce_array: { field: "tags", kind: "params", key: "name",
                  to: "labels" } }

// Join strings
{ reduce_array: { field: "roles", kind: "string_concat", separator: ",",
                  to: "actor.user.groups_str" } }

// First matching regex
{ reduce_array: { field: "headers", kind: "find", regexp: "^Authorization: ",
                  to: "http.auth_header" } }

// Boolean collapse
{ reduce_array: { field: "flags", kind: "boolean_or", to: "any_flag_set" } }
```

### `replace` — regex replace on a field value

```js
{ replace: { field: "path", regexp: "/\\d+/", replacement: "/<id>/" } }
```

Supports `$1`…`$n` backreferences. Unchanged if no match.

> **Two confirmed traps (tenant-validated 2026-06-01).**
> 1. The regex key is **`regexp`**, NOT `pattern`. A `pattern` key returns `400: Missing required key 'regexp'` on `putFile`. (`reduce_array { kind: "find", regexp: ... }` uses the same `regexp` key — be consistent.)
> 2. Even with the correct `regexp` key, the `replace` mapper op was observed to be a **runtime no-op** on this tenant — it passes schema validation and deploys, but the field value is unchanged at ingest (tested on both a dotted target like `process.cmd_line` and a flat scratch field). If your `replace` "succeeds" but the data is untransformed, this is why. The working substitute is a **`computeFields` rewrite** on the format that captures the field, calling the PowerQuery `replace(field, regex, replacement)` string function (PowerQuery string literals are single-quoted, so a double-quote inside the regex needs no escaping): `expression: "| let _cmdline = replace(_cmdline, 'a[0-9]+=\"([^\"]*)\"', '$1')"`. Capture into a flat scratch field, clean it with computeFields, then `rename` it to the dotted OCSF target. See `examples/12-linux-auditd-ocsf.json` (EXECVE arg vector → `process.cmd_line`).

### `zip` — interleave arrays

```js
{ zip: { from: ["keys", "values"], to: "pairs" } }
```

## Idiomatic patterns

### Vendor-native → OCSF rename block (Network Activity 4001)

```js
mappings: {
  version: 1,
  mappings: [
    {
      predicate: "metadata.event_code == 'RT_FLOW_SESSION_CREATE'",
      transformations: [
        { rename: { from: "source-address",            to: "src_endpoint.ip" } },
        { rename: { from: "source-port",               to: "src_endpoint.port" } },
        { rename: { from: "destination-address",       to: "dst_endpoint.ip" } },
        { rename: { from: "destination-port",          to: "dst_endpoint.port" } },
        { rename: { from: "nat-source-address",        to: "connection_info.src_translated.ip" } },
        { rename: { from: "protocol-id",               to: "connection_info.protocol_num" } },
        { rename: { from: "policy-name",               to: "policy.name" } },
        { rename: { from: "application",               to: "app_name" } },
        { rename: { from: "username",                  to: "actor.user.name" } },
        { cast:   { field: "src_endpoint.port",        type: "int" } },
        { cast:   { field: "dst_endpoint.port",        type: "int" } },
        // Protocol num → name WITHOUT overwriting the num:
        { copy:   { from: "connection_info.protocol_num",
                    to:   "connection_info.protocol_name" } },
        { cast:   { field: "connection_info.protocol_num",  type: "int" } },
        { cast:   { field: "connection_info.protocol_name", type: "enum",
                    enum: { "6": "TCP", "17": "UDP", "1": "ICMP" } } }
      ]
    }
  ]
}
```

### Collapse a tag array into an object

Given `tags = [{"name":"env","value":"prod"},{"name":"team","value":"sec"}]`:

```js
{ reduce_array: { field: "tags", kind: "params", key: "name", to: "labels" } }
```

Result: `labels = { env: "prod", team: "sec" }`.

### Hash an IP for PII-sensitive pipelines

```js
{ copy:   { from: "client.ip", to: "actor.session.terminal.ip" } },
{ hash:   { field: "actor.session.terminal.ip",
            to:    "actor.session.terminal.ip_sha256",
            algo:  "sha256" } },
{ drop:   { field: "actor.session.terminal.ip" } }
```

### Indexed positional access for CSV / pipe-delimited columns (v1 only)

When the source is a positional CSV captured with `{parse=commaSeparatedvalues}` or `{parse=pipeSeparatedValues}`, the parser deposits columns under the synthetic prefix `attr` indexed by position. Use this in a v1 mappings block:

```js
mappings: {
  version: 1,
  mappings: [
    {
      predicate: "true",
      transformations: [
        { rename: { from: "attr[0]",  to: "raw.receive_time" } },
        { rename: { from: "attr[1]",  to: "raw.serial" } },
        { rename: { from: "attr[7]",  to: "src_endpoint.ip" } },
        { rename: { from: "attr[8]",  to: "dst_endpoint.ip" } },
        { rename: { from: "attr[24]", to: "src_endpoint.port" } },
        { cast:   { field: "src_endpoint.port", type: "int" } }
      ]
    }
  ]
}
```

**Indexed access is v1-only.** A `mappings.version: 0` block rejects `attr[0]` syntax. Canonical example: `parsers/sentinelone/marketplace-paloaltonetworksfirewall-latest/` (731 indexed transformations across 14 formats).

### Building observable arrays (v1)

OCSF events optionally carry an `observables: [...]` array of `{name, type_id, type, value}` records summarizing the IPs/users/domains/files seen in the event. Construct it via labeled-index `copy`:

```js
{ copy: { from: "src_endpoint.ip", to: "observables[srcip].value" } },
{ constant: { value: "Source IP",  field: "observables[srcip].name" } },
{ constant: { value: 2,            field: "observables[srcip].type_id" } },
{ constant: { value: "IP Address", field: "observables[srcip].type" } },

{ copy: { from: "dst_endpoint.ip", to: "observables[dstip].value" } },
{ constant: { value: "Destination IP", field: "observables[dstip].name" } },
{ constant: { value: 2,                field: "observables[dstip].type_id" } },
{ constant: { value: "IP Address",     field: "observables[dstip].type" } }
```

Each `[srcip]` / `[dstip]` is a labeled index — referenced multiple times within the same mapping entry, the engine appends once and then targets that same array slot. Produces a clean array of dicts rather than separately-named scalars. Reference: `parsers/sentinelone/marketplace-fortinetfortigate-latest/` and `parsers/sentinelone/marketplace-cloudflare-latest/`.

### Tree operations on gron-flattened JSON

Source `{"Resource": {"Id": "abc", "Type": "user"}}` after `${parse=gron}$` becomes two flat keys: `unmapped.Resource.Id` and `unmapped.Resource.Type`. To rename the whole subtree at once:

```js
{ rename_tree: { from: "unmapped.Resource", to: "resource" } }
```

The engine walks every key with that dotted prefix and renames all of them. **Do NOT escape the dots inside the subtree path** (`from: "unmapped\\.Resource"` does not match — even though the published `PARSER_TEMPLATE.conf` shows escaped dots; that template is stale on current tenants). The dots in flat-gron keys are literal parts of the key string, not navigation operators. Reference: `parsers/sentinelone/marketplace-cloudflare-latest/`.

### Enum cast with default sentinel (v1)

`cast: { type: "enum", enum: {...} }` does not have a fallback by default — unmapped source values pass through unchanged. To map every unknown to a sentinel (so downstream queries can group "known" vs "unknown"), set `enum_default`:

```js
{ cast: { field: "action_id", type: "enum",
          enum: { "1": "Allow", "2": "Block", "3": "Drop", "4": "Quarantine" },
          enum_default: 99 } }
```

Cloudflare uses `enum_default: 99` (the OCSF "Unknown" sentinel) consistently — copy that pattern. Reference: `parsers/sentinelone/marketplace-cloudflare-latest/`.

### Conditional class assignment via per-format `attributes:`

When one parser handles multiple OCSF classes (Windows Event Log emits Authentication for 4624/4625 but Account Change for 4720/4728), put the class metadata on each format rather than at parser root:

```js
formats: [
  { id: "evt4624", format: "...", halt: true,
    attributes: { class_uid: 3002, class_name: "Authentication",
                  category_uid: 3, category_name: "Identity & Access Management",
                  activity_id: 1, activity_name: "Logon" } },
  { id: "evt4625", format: "...", halt: true,
    attributes: { class_uid: 3002, class_name: "Authentication",
                  activity_id: 2, activity_name: "Logoff" } },
  { id: "evt4720", format: "...", halt: true,
    attributes: { class_uid: 3001, class_name: "Account Change",
                  activity_id: 1, activity_name: "Create" } }
]
```

Per-format `attributes:` override parser-root `attributes:`, so you can set sane defaults at root and let formats specialize. Look up every dotted name and class number in `references/ocsf-schema-documentation.md`. Reference: `parsers/community/microsoft_windows_eventlog-latest/` (5 sub-EventID directories).
