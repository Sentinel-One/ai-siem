# OCSF Field Mapping (Default Naming Convention)

The Open Cybersecurity Schema Framework (OCSF) is the schema this skill emits **by default**. Every parser should produce OCSF-shaped events unless the user explicitly asks for vendor-native names.

**Why default to OCSF:** Downstream PowerQuery hunts, dashboards, STAR rules, and Marketplace integrations all assume OCSF. Vendor-native names force every consumer to learn each source format and break portability across vendors.

> ## NON-NEGOTIABLE: ALL OCSF mapping uses `ocsf-schema-documentation.md`
>
> Before emitting any OCSF dotted path in a parser, **grep `references/ocsf-schema-documentation.md` for the exact string**. That file is the single source of truth for the ~25,759 documented OCSF field names. Do not invent. Do not copy from a catalog parser without verifying. Do not rely on memory or on the tables in this document — they are summaries for common cases, not the catalog.
>
> The two reasons people drift from this rule:
> 1. "I'm sure it's `source.ip`." It is not. It is `src_endpoint.ip`. Many vendors use `source.ip` natively. OCSF does not. Always grep.
> 2. "The catalog parser uses `attacker_ip`, so I'll keep it." Catalog parsers are full of vendor-native names. Replace them with the OCSF dotted path from the schema reference, then map via `mappings.rename`.

## Authoritative field list — `ocsf-schema-documentation.md`

Before inventing any OCSF field name, look it up in `references/ocsf-schema-documentation.md`. That file is the complete SentinelOne community-documented OCSF schema (7 categories × 96 articles × ~25,759 field entries) and is the canonical source of truth for field names and casing:

- `## System Activity` — File System (1001), Kernel Extension (1002), Kernel (1003), Memory (1004), Module (1005), Scheduled Job (1006), Process Activity (1007)
- `## Findings` — Security Finding (2001), Vulnerabilities, Misconfigurations
- `## Identity & Access Management` — Account Change (3001), Authentication (3002), Authorize Session (3003), Entity Management (3004), User Access Management (3005), Group Management (3006)
- `## Network Activity` — Network (4001), HTTP (4002), DNS (4003), DHCP (4004), RDP (4005), SMB (4006), SSH (4007), FTP (4008), Email (4009), Network File (4010), Email File (4011), Email URL (4012)
- `## Discovery` — Device Inventory Info (5001), Device Config State (5002)
- `## Application Activity` — Web Resources (6001), Application Lifecycle (6002), API (6003), Web Resource Access (6004)
- `## Unified Alert Management`

**How to use it:**
1. Identify the class from the quick-pick table below (or from the section headers in `ocsf-schema-documentation.md`).
2. Grep the relevant section of that file for the OCSF concept you want (e.g., `src_endpoint`, `actor.user.email`, `file.hashes`). Each article lists every dotted field at that level — copy the name verbatim.
3. Use the tables lower in THIS file only as a shortcut for the most common classes. For anything beyond Network/Auth/File, consult `ocsf-schema-documentation.md` first.

Field names in OCSF are lowercase dotted-path, e.g. `actor.user.email_addr`, `src_endpoint.ip`, `file.hashes[].value`. Arrays use `[]`. Enums pair as `<field>_id` (integer) + `<field>` (string) — emit both.

## Mechanics in an SDL parser

You have two choices for emitting OCSF names — pick based on parser complexity:

### Option A — Capture directly into OCSF dotted names
For simple line formats, name the captures with the OCSF dotted path:

```js
formats: [
  "$src_endpoint.ip$:$src_endpoint.port$ -> $dst_endpoint.ip$:$dst_endpoint.port$"
]
```

SDL allows `.` and `_` in field names. Dotted names show up as nested objects in queries. Use this for clean, single-line formats.

### Option B — Capture vendor-native, then `mappings` block to rename
For multi-format or complex parsers, capture vendor-native names first (matches the source log's terminology, easier to reason about during authoring), then use a `mappings` block (see `mappers.md`) to rename to OCSF in one place. This is the cleanest pattern for repeated patterns and CEF/LEEF/structured-syslog where dozens of fields need renaming.

Often a hybrid is best: capture the framing (timestamp, host, log-type) directly with OCSF names, and use `mappings.rename` for the long tail of vendor-specific fields inside the body.

## Required attributes on every parser

Tag every event with:
1. The four pipeline-required defaults (`metadata.version`, `dataSource.category`, `dataSource.name`, `dataSource.vendor`).
2. The OCSF class metadata (`class_uid`, `class_name`, `category_uid`, `category_name`).
3. Vendor/product metadata (`metadata.product.*`, `metadata.log_provider`).

```js
attributes: {
  // required pipeline defaults
  "metadata.version":    "1.0.0",
  "dataSource.category": "network",
  "dataSource.name":     "Juniper SRX",
  "dataSource.vendor":   "Juniper",
  // product metadata
  "metadata.product.vendor_name": "Juniper",
  "metadata.product.name":        "SRX",
  "metadata.log_provider":        "rt_flow_session_create",
  // OCSF class
  "class_uid":     4001,
  "class_name":    "Network Activity",
  "category_uid":  4,
  "category_name": "Network Activity"
}
```

`activity_id` belongs on the *format* (per-event-subtype) since SESSION_CREATE vs SESSION_CLOSE map to different activities.

**`dataSource.category` taxonomy:** `security`, `network`, `application`, `identity`, `endpoint`, `cloud`, `iot`, `ot`. Pick the one that best describes the source's primary purpose.

## OCSF class quick-pick

| Source | Class | UID |
|---|---|---|
| Firewall connection allow/deny, NAT, flow start/end | Network Activity | 4001 |
| HTTP / web access logs | HTTP Activity | 4002 |
| DNS queries | DNS Activity | 4003 |
| TLS handshake records | TLS Activity | 4006 |
| Authentication / login events | Authentication | 3002 |
| File create/read/write/delete | File Activity | 1001 |
| Process create/terminate | Process Activity | 1007 |
| Account creation / role change | Account Change | 3001 |
| Group/role membership changes | Group Management | 3006 |
| API activity (cloud, K8s) | API Activity | 6003 |

`class_uid = category_uid * 1000 + N`. The integer UIDs go on `attributes` so STAR rules can filter cheaply (`class_uid = 4001` is much faster than `class_name = 'Network Activity'`).

## Network Activity (4001) — the canonical mapping

This is the most common class. Map this way unless the source has a better-fitting class:

| Vendor field (typical) | OCSF dotted name |
|---|---|
| source-address, src, sip, srcip | `src_endpoint.ip` |
| source-port, spt, sport | `src_endpoint.port` |
| destination-address, dst, dip, dstip | `dst_endpoint.ip` |
| destination-port, dpt, dport | `dst_endpoint.port` |
| protocol-id (numeric) | `connection_info.protocol_num` |
| proto, protocol (string) | `connection_info.protocol_name` |
| nat-source-address, postNATSourceIP | `src_endpoint.intermediate_ips` *(or `connection_info.src_translated.ip`)* |
| nat-source-port | `connection_info.src_translated.port` |
| nat-destination-address | `connection_info.dst_translated.ip` |
| nat-destination-port | `connection_info.dst_translated.port` |
| src-nat-rule-name | `connection_info.src_translated.policy_name` |
| dst-nat-rule-name | `connection_info.dst_translated.policy_name` |
| policy-name, rule, ruleName | `policy.name` |
| source-zone-name, srczone | `src_endpoint.zone` |
| destination-zone-name, dstzone | `dst_endpoint.zone` |
| session-id-32, session_id, sessionid | `connection_info.session.uid` |
| packet-incoming-interface, ifname | `src_endpoint.interface_name` |
| application, app | `app_name` |
| nested-application | `app.profile` *(custom subfield, OCSF allows extension)* |
| encrypted (YES/NO/UNKNOWN) | `tls.is_encrypted` *(map YES→true, NO→false)* |
| username, user | `actor.user.name` |
| roles | `actor.user.groups` |
| action (allow/deny) | `disposition` *(allowed=Allowed, deny=Blocked)* |
| bytes-sent, bytes_in | `traffic.bytes_in` |
| bytes-received, bytes_out | `traffic.bytes_out` |
| packets-sent | `traffic.packets_in` |
| packets-received | `traffic.packets_out` |
| start-time, sessionStart | `start_time` |
| end-time, sessionEnd | `end_time` |
| reason, reason-code | `status_detail` |

Per-format `activity_id`:

| Source event | activity_id |
|---|---|
| SESSION_CREATE / connection started / new flow | 1 |
| SESSION_CLOSE / connection ended / flow expired | 2 |
| SESSION_DENY / connection blocked | 3 |
| reset / RST | 4 |

## Authentication (3002) — common mapping

| Vendor field | OCSF dotted name |
|---|---|
| user, username, principal | `actor.user.name` |
| user_id, uid, sid | `actor.user.uid` |
| email, mail | `actor.user.email_addr` |
| groups, roles | `actor.user.groups` |
| src_ip, source_ip, client_ip | `src_endpoint.ip` |
| user_agent, ua | `http_request.user_agent` |
| auth_method, mechanism | `auth_protocol` |
| mfa, second_factor | `mfa` |
| result, status (success/failed) | `status` *(Success / Failure)* |
| failure_reason | `status_detail` |
| session_id | `session.uid` |
| logon_type | `logon_type_id` |

`activity_id`: 1 = Logon, 2 = Logoff, 3 = Authentication Ticket, 4 = Service Ticket Request, 5 = Service Ticket Renew, 6 = Preauth.

## File Activity (1001) — common mapping

| Vendor field | OCSF dotted name |
|---|---|
| file, filename, file_path | `file.path` |
| file_name | `file.name` |
| sha256, hash | `file.hashes[].value` (algorithm 'SHA-256') |
| file_size, size | `file.size` |
| user, owner | `actor.user.name` |
| process_name | `actor.process.name` |
| process_id, pid | `actor.process.pid` |

`activity_id`: 1 Create, 2 Read, 3 Update, 4 Delete, 5 Rename, 6 Set attributes, 7 Set security, 8 Get attributes, 9 Get security, 10 Encrypt, 11 Decrypt, 12 Mount, 13 Unmount, 14 Open.

## Boolean and enum normalization tips

Logs commonly carry `YES`/`NO`/`UNKNOWN` or `0`/`1` strings. Normalize via a `computeFields` rewrite or a `mappings` block.

### Option 1 — `computeFields` (ternary syntax, `==` for equality)

```js
rewrites: [
  { action: "computeFields",
    expression: "| let tls.is_encrypted = encrypted == 'YES' ? true : (encrypted == 'NO' ? false : null)" }
]
```

Notes (**tenant-validated, April 2026**):

- **Use ternary `a ? b : c`**. Nested `if(cond, a, b)` calls are rejected: `Unknown function 'if'`.
- **Use `==` for equality**, not `=`.
- **computeFields cannot reference dashed field names** like `protocol-id` — the `-` is parsed as subtraction, and backtick/backslash escaping is rejected. Rename the field to a dot/underscore name via `mappings` first, then use computeFields on the renamed field. Or skip computeFields and do the whole enum-translation in the mappings block (see Option 2).
- Place the computeFields rewrite on the format that *captures* the source field. If the source field is captured by a repeating sub-format (e.g. a key/value extractor), put the rewrite on THAT format, not on the frame format — the frame's rewrites run before the sub-format has populated the field.

### Option 2 — `mappings` block (recommended for clean dashed-field cases)

```js
mappings: {
  version: 1,                           // required
  mappings: [{
    transformations: [
      // cast overwrites the source — copy first if you need to preserve it
      { copy: { from: "encrypted", to: "tls.is_encrypted" } },
      { cast: { field: "tls.is_encrypted", type: "enum",
                enum: { "YES": true, "NO": false } } },
      { drop: { field: "encrypted" } }
    ]
  }]
}
```

See `references/mappers.md` for the full authoritative mapper syntax (it differs from some public docs).

## Confirm with the user when class is ambiguous

If the source could reasonably belong to multiple OCSF classes (e.g., a proxy log is HTTP Activity 4002 *or* Network Activity 4001 depending on what fields you keep), surface the choice rather than picking silently. Once chosen, stick with it for the whole parser — mixed classes break downstream filters.
