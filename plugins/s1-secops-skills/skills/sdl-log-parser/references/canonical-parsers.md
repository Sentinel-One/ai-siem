# Canonical reference parsers by input shape

Moved out of `SKILL.md` to keep it under the 500-line authoring limit. Content unchanged.

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
| Key=value with record-type fan-out to many OCSF classes | `examples/12-linux-auditd-ocsf.json` | `type=`-anchored record-type capture (avoids the `nametype=` collision), KV catch-all, v1 first-match-wins mappings fanning one source to Process 1007 / File 1001 / Auth 3002 / Finding 2004 / Network 4001, EXECVE arg-vector → `process.cmd_line` via `computeFields` `replace()` |
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
