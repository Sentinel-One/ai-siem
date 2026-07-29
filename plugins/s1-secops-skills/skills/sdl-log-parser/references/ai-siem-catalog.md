# ai-siem Parser Catalog — Always Check First

Before writing a parser from scratch, check the **`Sentinel-One/ai-siem`** GitHub repo. It is the canonical open catalog of community + marketplace SDL parsers maintained by S1 and partners, and a large fraction of the sources a prospect will ask about already have a working parser there.

- Repo root: <https://github.com/Sentinel-One/ai-siem>
- Parsers tree: <https://github.com/Sentinel-One/ai-siem/tree/main/parsers>
- File extension: every parser is a single `.conf` file in augmented-JSON (same format as `/logParsers/<name>` on the tenant).

## Workflow

**Step 0** of authoring any parser:

1. Search ai-siem for the vendor or product name (e.g. "juniper", "okta", "fortigate", "palo alto", "corelight", "abnormal").
2. If a parser exists, download it. It becomes your starting point.
3. Diff what the user asked for against what the catalog parser emits. Audit the **4 mandatory attributes** (`dataSource.category` hardcoded to `"security"`, `dataSource.name`, `dataSource.vendor`, `metadata.version`) and add or correct any that are missing or wrong. Shift to OCSF field names if the parser uses vendor-native — every emitted dotted path must come from `references/ocsf-schema-documentation.md`, not from the catalog parser. **Always increment `metadata.version`** to mark this build as different from upstream (patch for fixes, minor for additive changes, major for breaking schema changes).
4. Validate end-to-end via `sentinelone-sdl-api` (the usual loop).

Only write from scratch when no catalog parser matches.

## Repo layout (as of 2026-04)

Two buckets:

- `parsers/marketplace/<name>-latest/` — supported, version-tagged parsers shipped in the S1 Marketplace (cloudflare, fortinet fortigate, aws rds, corelight-conn, palo alto networks firewall, and ~60 others).
- `parsers/community/<name>-<version>/` — community-contributed, less polished, more varied in style (abnormal_security_logs, juniper_networks_logs, okta_ocsf_logs, cisco_asa, pfsense_firewall, etc.).

Each folder typically contains:

- The `.conf` parser file.
- A `samples/` directory with raw log lines (use these as your validation input — real vendor samples are hard to synthesize correctly).
- Sometimes a `README.md` with field mapping or known-issues.

## Useful reference parsers by shape

When you need a template for a specific log shape, start from one of these:

- **JSON-per-line, dottedJson envelope** — `community/json_generic/`. Two-line parser, pure `${parse=dottedJson}$ repeat:true`.
- **JSON with nested KV body** — `community/json_nested_kv/`. Outer JSON then repeating KV sub-format against a nested `message` field.
- **CEF over syslog** — `community/generic_access/` header + KV extension cascade.
- **LEEF** — `community/leef_template/`. Timestamp prefix + repeating KV patterns.
- **Positional CSV with complex mapping** — `marketplace/palo_alto_networks_firewall-latest/`. Uses `{parse=commaSeparatedvalues}` + `skipNumericConversion: true` + `attr[N]` positional indexing in mappings.
- **Multi-format progressive extraction** — `community/pfsense_firewall/`. Frame → subtype → protocol-specific cascade; uses `discard: true` to drop IPv6 and a final-format rewrite for computed fields.
- **Multiple per-format OCSF class tagging** — `community/abnormal_security_logs/` and `community/juniper_networks_logs/`. Each format has its own `attributes: { class_uid, ... }` so one parser emits multiple OCSF classes.
- **Gron-capture + mappings template** — `community/PARSER_TEMPLATE/`. The "capture everything via `$unmapped.{parse=gron}$`, then rename/copy/cast in mappings" idiom. Great scaffold when the source is JSON-ish and you want all rewrites in one block.
- **Format-id sentinel for mapping fan-out** — `marketplace/awsrdslogs-latest/`. Names each format (`id: "mySqlErrorLog"`, `id: "mySqlGeneralLog"`, `id: "postgresqlLog"`) and then fans mapping predicates out via `predicate: "mySqlErrorLog='true'"` — elegant way to apply different OCSF class rules to different sub-shapes of the same source.
- **Plural-grouped mapping syntax** — `marketplace/corelight-conn-latest/` and `marketplace/awsrdslogs-latest/`. `renames: [...], copies: [...], constants: [...]` arrays inside a single mapping entry (see `mappers.md` §"Two equivalent syntaxes").
- **Rewrite-first legacy style (pre-mappings)** — `community/okta_ocsf_logs/`. Pure `rewrites:` on the format (no `mappings` block). Still works — useful when you need a minimal diff from a published parser.

## Style variance to expect (and tolerate)

The repo predates the current mapper engine, and not every author hand-converges on the same style. When copying from the catalog:

- **Two mapping syntaxes coexist.** Older parsers use `version: 0` with plural grouped arrays (`renames`, `copies`, `constants`). Newer tenant-validated parsers use `version: 1` with `transformations: [{<op>: {...}}]`. Both work. Pick one and stick to it within a parser — do not mix.
- **`class_uid` as string vs integer.** Both appear. String form (`"4001"`) is tolerated by the ingest pipeline, integer (`4001`) is the OCSF spec. Prefer integers in new work.
- **Predicate equality `=` vs `==`.** Marketplace parsers use `=`. Tenant `computeFields` and the newer `version:1` mappings style use `==`. If one fails validation, try the other — the engine error message will tell you. (See `mappers.md` for the split.)
- **Required default attributes often missing.** The catalog predates the current four-attribute requirement (`metadata.version`, `dataSource.category/name/vendor`). Add them to the top-level `attributes:` block on every parser you ship, even when copying verbatim from the catalog.

## Quick recipe for downloading a parser

The repo is public, so `curl` + the GitHub raw URL works without auth:

```bash
# Find the folder you want:
#   https://github.com/Sentinel-One/ai-siem/tree/main/parsers/<bucket>/<name>-<version>/
# Then raw-download the .conf:

curl -sSL \
  https://raw.githubusercontent.com/Sentinel-One/ai-siem/main/parsers/community/juniper_networks_logs-latest/juniper_networks_logs.conf \
  -o juniper_networks_logs.conf
```

If you are inside Cowork without network access to github raw, use `WebFetch` against the github.com tree URL and extract filenames from the rendered listing, then fetch individual `raw.githubusercontent.com` URLs.

## When the catalog is wrong

Common issues in catalog parsers that you should fix before shipping. Empirical audit (April 2026) of all 171 parsers in `Sentinel-One/ai-siem`:

1. **Missing one or more of the 4 mandatory attributes** (`dataSource.category`, `dataSource.name`, `dataSource.vendor`, `metadata.version`). About 33% of community parsers (50/152) have no `dataSource.category` at all. Of the ones that do include it, ~17% use values other than `"security"` (`application`, `network`, `system`, `audit`). Many community parsers also lack `metadata.version`. All marketplace parsers (19/19) have all four set. **Audit on copy:**
   - `dataSource.category` must be hardcoded to the literal string `"security"`. Force it.
   - `dataSource.name` and `dataSource.vendor` must be present and accurate to the product/vendor.
   - `metadata.version` must be present and follow semver. **Always increment on a new build.** May also be set inside `mappings` via `{ constant: { field: "metadata.version", value: "<your-current-version>" } }` if you need to propagate the source schema version per-event.
2. **Emitting vendor-native field names instead of OCSF.** Most community parsers ship vendor-native (`source_ip`, `dst_port`, `proto`, `bytes_in`). Add a `mappings` block that renames them, or update capture names directly. **Always look up dotted paths in `references/ocsf-schema-documentation.md` rather than guessing.**
3. **Stray `class_uid` as a string** (`"4001"`). Change to integer (`4001`). Both forms ingest, but downstream consumers and OCSF spec want integer.
4. **Using deprecated `rewrites:` on the format for what should be `mappings`.** Modern parsers do field renames/casts/copies in `mappings`. Prefer `mappings` for anything that runs after field capture. Leave `rewrites:` for timestamp normalization (the one thing it still does well).
5. **Hard-coded tenant-specific attributes** like `"site.id": "..."` (seen in pfSense and a few community parsers). Strip these before shipping to a different tenant.
6. **Predicates that match a vendor-native field after that field has already been renamed to OCSF.** Order matters inside `transformations: [...]` — predicates evaluate against the field NAME at the time the predicate runs, so a predicate referencing `source_ip` after a `rename` to `src_endpoint.ip` always evaluates to false.
7. **Mixed `mappings.version: 0` and `mappings.version: 1` syntaxes inside one parser.** Hard error. Pick one. New parsers prefer v1.
8. **Indexed positional access (`attr[0]`, `attr[1]`) used inside a `mappings.version: 0` block.** Rejected. Indexed access only works in v1. If the source is positional CSV, the mapping block must be v1.
9. **No `enum_default` on `cast: { type: "enum" }` in v1 mappings.** Without it, unmapped source values pass through unchanged instead of falling back to a sentinel. Cloudflare uses `enum_default: 99` consistently — copy that pattern.

## How the corpus splits

Quantitative breakdown of the 171 parsers (community 152 + marketplace 19), audited April 2026:

- **Has `mappings` block:** ~10% of community parsers, 100% of marketplace parsers.
- **Mapping version:** of parsers with mappings, marketplace splits ~60% v0 / 40% v1; community is overwhelmingly v0 or rewrites-only legacy.
- **Has `lineGroupers`:** rare. Examples: `axonius_asset_logs-latest`, `jruby_application_logs-latest`, `sql_database_logs-latest`, `microsoft_windows_eventlog-latest`, `marketplace-awsrdslogs-latest`, `marketplace-cloudflare-latest`, `marketplace-zscalerinternetaccess-latest`.
- **Has `samples/`:** none of the marketplace parsers; very few of the community parsers. Real-life validation samples are something you typically supply yourself.
- **`dataSource.category` correct (`"security"`):** 100% of marketplace, ~55% of community.
- **OCSF class fan-out via per-format `attributes:`:** `community/abnormal_security_logs-latest/`, `community/juniper_networks_logs-latest`, `marketplace-cloudflare-latest`, `marketplace-paloaltonetworksfirewall-latest`.
- **Format-id sentinel + predicate fan-out:** `marketplace-awsrdslogs-latest` is the textbook example.

## Vendor → parser-folder index

When you have a source in mind, look here first. Each line is `<vendor/product>: <folder1>, <folder2>, ...`. Pick the marketplace one if available; otherwise pick the most recently-edited or most complete community one.

**AWS:** `aws_cloudwatch_logs-latest`, `aws_elasticloadbalancer_logs-latest`, `aws_guardduty_logs-latest`, `aws_route53-latest`, `aws_vpc_dns_logs-latest`, `aws_waf-latest`, `vpc_logs-latest`, `marketplace-awsrdslogs-latest`, `marketplace-awsvpcflowlogs-latest`.

**Akamai:** `akamai_cdn-latest`, `akamai_dns-latest`, `akamai_general-latest`, `akamai_sitedefender-latest`.

**Microsoft / Azure:** `azure_logs-latest`, `microsoft_365_collaboration-latest`, `microsoft_365_defender-latest`, `microsoft_365_mgmt_api_logs-latest`, `microsoft_activedirectory_logs-latest`, `microsoft_azure_ad_logs-latest`, `microsoft_eventhub_azure_signin_logs-latest`, `microsoft_eventhub_defender_email_logs-latest`, `microsoft_eventhub_defender_emailforcloud_logs-latest`, `microsoft_windows_eventlog-latest`, `windows_dhcp_logs-latest`, `windows_event_log_logs-latest`, `windows_EventLog-pipeParseCommands-v0.1`.

**Cisco:** `cisco_asa_logs-latest`, `cisco_combo_logs-latest`, `cisco_duo-latest`, `cisco_firewall-latest`, `cisco_fmc_logs-latest`, `cisco_ios_logs-latest`, `cisco_ironport-latest`, `cisco_isa3000_logs-latest`, `cisco_ise_logs-latest`, `cisco_logs-latest`, `cisco_meraki-latest`, `cisco_meraki_flow_logs-latest`, `cisco_meraki_logs-latest`, `cisco_networks_logs-latest`, `cisco_umbrella-latest`, `cisco_umbrella_logs-latest`, `meraki_logs-latest`, `marketplace-ciscofirepowerthreatdefense-latest`, `marketplace-ciscofirewallthreatdefense-latest`.

**Palo Alto:** `paloalto_alternate_logs-latest`, `paloalto_logs-latest`, `paloalto_vpn_logs-latest`, `marketplace-paloaltonetworksfirewall-latest`, `marketplace-paloaltonetworksprismaaccess-latest`. (The marketplace Firewall parser is canonical for positional CSV.)

**Fortinet:** `fortigate_logs-latest`, `fortimanager_logs-latest`, `fortinet_fortigate_candidate_logs-latest`, `fortinet_logs-latest`, `marketplace-fortinetfortigate-latest`, `marketplace-fortinetfortimanager-latest`. (Marketplace Fortigate is canonical for KV freeform.)

**Cloudflare:** `cloudflare_general_logs-latest`, `cloudflare_inc_waf-lastest`, `cloudflare_logs-latest`, `cloudflare_waf_logs-latest`, `marketplace-cloudflare-latest`. (Marketplace is canonical for "modern v1 doing everything right.")

**Zscaler:** `zscaler_dns_firewall-latest`, `zscaler_firewall_logs-latest`, `zscaler_logs-latest`, `zscaler_zia_logs-latest`, `marketplace-zscalerinternetaccess-latest`, `marketplace-zscalerprivateaccessjson-latest`.

**Corelight / Zeek:** `marketplace-corelight-conn-latest`, `marketplace-corelight-http-latest`, `marketplace-corelight-ssl-latest`, `marketplace-corelight-tunnel-latest`. (All v0 plural-grouped mappings.)

**Okta:** `okta_logs-latest` (rewrites-only legacy), `okta_ocsf_logs-latest` (already-OCSF passthrough).

**Juniper:** `juniper_logs-latest`, `juniper_networks_logs-latest`. (See `examples/07-juniper-srx-rtflow-ocsf.json` in this skill.)

**F5:** `f5_networks_logs-latest`, `f5_vpn-latest`.

**Check Point:** `marketplace-checkpointfirewall-latest`.

**Infoblox:** `marketplace-infobloxddi-latest`.

**Crowdstrike:** `crowdstrike_endpoint-latest`, `crowdstrike_logs-latest`.

**Identity / Auth:** `cisco_duo-latest`, `cyberark_conjur-latest`, `cyberark_pas_logs-latest`, `hypr_auth-latest`, `linux_auth-latest`, `okta_logs-latest`, `okta_ocsf_logs-latest`, `pingfederate-latest`, `pingone_mfa-latest`, `pingprotect-latest`, `rsa_adaptive-latest`, `singularityidentity_singularityidentity_logs-latest`, `tailscale_tailscale_logs-latest`, `teleport_logs-latest`.

**Email security:** `mimecast_mimecast_logs-latest`, `proofpoint_logs-latest`, `proofpoint_proofpoint_logs-latest`, `mail_server_logs-latest`, `microsoft_eventhub_defender_email_logs-latest`, `spam_detection_logs-latest`, `abnormal_security_logs-latest`.

**SaaS / collaboration:** `github_audit-latest`, `google_workspace_logs-latest`, `microsoft_365_collaboration-latest`.

**Backup / data protection:** `cohesity_backup-latest`, `rubrik_backup_logs-latest`, `veeam_backup-latest`.

**WAF / proxy:** `cloudflare_*_waf*`, `imperva_sonar-latest`, `imperva_waf_logs-latest`, `incapsula_incapsula_logs-latest`, `aws_waf-latest`, `barracuda_firewall_logs_latest`, `forcepoint_forcepoint_logs-latest`, `haproxy_loadbalancer_logs-latest`, `nginx_error_logs-latest`, `nginx_kvlog_logs-latest`, `squid_proxy_logs-latest`.

**EDR / NDR / threat:** `crowdstrike_*`, `darktrace_darktrace_logs-latest`, `extrahop_extrahop_logs-latest`, `kaspersky_anti_targeted_attack-latest`, `kaspersky_security_center`, `jamf_protect-latest`, `stamus_networks-latest`, `vectra_ai_logs-latest`, `wiz_cloud-latest`, `wiz_cloud_security_logs-latest`.

**Network / firewall (other):** `aruba_clearpass_logs-latest`, `citrix_netscaler_logs-latest`, `extreme_networks_logs-latest`, `pfsense_firewall_logs-latest`, `sonicwall_firewall_logs-latest`, `ubiquiti_unifi_logs-latest`, `ufw_firewall_logs-latest`, `watchguard_firewall_logs-latest`.

**DNS / DHCP:** `aws_route53-latest`, `aws_vpc_dns_logs-latest`, `dhcp_logs-latest`, `dns_general_logs-latest`, `dns_ocsf_logs-latest`, `google_cloud_dns_logs-latest`, `isc_bind-latest`, `isc_dhcp-latest`, `windows_dhcp_logs-latest`, `zscaler_dns_firewall-latest`.

**Generic / utility:** `apache_http_logs-latest`, `generic_access_logs-latest`, `iis_w3c-latest`, `json_generic_logs-latest`, `json_nested_kv_logs-latest`, `leef_template_logs-latest`, `linux_system_logs-latest`, `sample_test_logs-latest`, `syslog_space_delimited_logs-latest`. **These are the most useful as starting templates** when no vendor-specific parser fits.

**SAP / database / app:** `sap_logs-latest`, `sql_database_logs-latest`, `confluent_kafka_logs-latest`, `jruby_application_logs-latest`, `microservice_tracing_logs-latest`, `vcenter_logs-latest`, `vmware_vcenter_logs-latest`.

**Misc:** `agent_metrics_logs-latest`, `armis_armis_logs-latest`, `axonius_asset_logs-latest`, `axway_sftp-latest`, `beyondtrust_passwordsafe_logs-latest`, `beyondtrust_privilegemgmtwindows_logs-latest`, `buildkite_ci_logs-latest`, `harness_ci-latest`, `hashicorp_hcp_vault_logs-latest`, `inngate_gateway_logs-latest`, `log4shell_detection_logs-latest`, `manageengine_*`, `manch_siem_logs-latest`, `netskope_*`, `securelink_logs-latest`.
