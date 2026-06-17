# Example parsers: pick your starting point

Each template targets a specific log shape. Copy the closest match, rename, edit, and validate via the `sdl-api` skill (see `../references/testing-workflow.md`).

| File | Use when |
|---|---|
| `01-cef-over-syslog.json` | Syslog-framed CEF or LEEF (appliance firewalls, NGFWs, many SIEM gateways). |
| `02-json-with-envelope.json` | Each line is a JSON object preceded by a `<timestamp> <host>` prefix. |
| `03-key-value.json` | Freeform `key=value` pairs with an optional bracketed timestamp. |
| `04-multiline-stack.json` | Application logs where exceptions span many lines. |
| `05-rewrite-and-mask.json` | You need to mask secrets or compute derived fields (`computeFields`). |
| `06-alias.json` | A built-in already handles the format: just expose it under a friendlier name. |
| `07-juniper-srx-rtflow-ocsf.json` | RFC 5424 structured-data syslog (Juniper SRX RT_FLOW, but pattern generalizes). Shows the recommended **vendor-native capture + `mappings.rename` → OCSF** idiom, plus `computeFields` for enum normalization. |
| `08-gron-capture-template.json` | JSON-per-line sources where you want all OCSF logic in one `mappings` block. Lifted from the `ai-siem` community PARSER_TEMPLATE: single `$unmapped.{parse=gron}$` capture, then every rename/copy/cast/constant in v1 mappings. |
| `09-aws-cloudtrail-assumerole-ocsf.json` | AWS CloudTrail `sts:AssumeRole` records → OCSF **Authentication (3002)**. Shows the dottedJson-capture idiom (preserves arrays as JSON-string, unlike gron which drops them), the full `user.*` / `session.*` / `api.*` / `cloud.*` / `tls.*` fan-out, and how to surface array payloads (`resources[]`) as a queryable JSON blob + a scalar `resource_uid`. |
| `10-linux-pam-session-ocsf.json` | Linux `pam_unix` session open/close over RFC 3164 syslog (e.g. `/var/log/auth.log`, journald-forwarded). Target line: `<86>Apr 19 19:36:10 ad-pve-2 CRON[2292341]: pam_unix(cron:session): session closed for user root`. Emits OCSF **Authentication (3002)** with branch-driven `activity_id` (1 Logon / 2 Logoff) via predicate-gated `constant` ops on `unmapped.pam_action`. Covers sshd, sudo, login, su, cron, systemd-logind: any pam_unix producer. |
| `11-akamai-siem-cef-ocsf.json` | Akamai SIEM CEF (bare, no syslog frame) → OCSF **HTTP Activity (4002)**. Reference example for the **inline-predicate-on-`constant`-op** pattern that sidesteps v1 mappings' first-match-wins constraint: 21 conditional `constant` ops (severity_id bucketing, action/status/disposition_id fan-out from a vendor string, status from HTTP response code) all fire from a single `predicate: "true"` mapping entry. Also demonstrates OCSF `severity_id` bucketing of a CEF 0-10 raw scale (NEVER passthrough), dual-emit fields for back-compat (`http_request.url.text` + `.url_string`), and a vendor gotcha (`app=h2` carries HTTP version, not `ver=`). Lifted from a production parser, tenant-validated 2026-05-27. |

All files are augmented-JSON; unquoted keys and `//` comments are legal. Keep the comments while iterating, strip them for production if your team prefers pure JSON.
