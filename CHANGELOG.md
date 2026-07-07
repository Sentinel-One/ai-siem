# Changelog

All notable changes to the AI-SIEM repository will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added - soc-investigator skill + sdl-solutions: Alert noise reduction (s1-secops-skills v1.2.6)

- New **soc-investigator** skill: autonomous, staged DFIR investigation of SentinelOne alerts (SHORT/MEDIUM/LONG modes) with tool discovery, interactive intake, IOC enrichment, per-endpoint PowerQuery forensics, and optional third-party correlation and anomaly detection. Carries the evidence-discipline and verdict gates from the SOC Analyst standard and the SDL threat-hunt-and-correlation method (`references/evidence-and-verdict-discipline.md`, `references/correlation-and-hunt-methodology.md`). Authored by Joel Mora.
- New `sdl-solutions` solution **Alert noise reduction**: find the sources and signatures flooding the alert queue, separate ingested and already-actioned noise from real detections, recommend an ingestion-severity filter, auto-resolve already-mitigated alerts with a note, and ship a noise-vs-signal dashboard. Adds `references/alert-noise-reduction.md`, `assets/alertnoise_dashboard.template.json`, `assets/alertnoise_autoresolve_ha.template.json`, and `docs/solutions/alert-noise-reduction.md`.
- Plugin version bumped to **1.2.6** (`.claude-plugin/plugin.json`, marketplace entry) and rebuilt bundles in `dist/`.

### Added - sdl-solutions: Detection as Code (s1-secops-skills v1.2.5)

- New `sdl-solutions` solution **Detection as Code (DaC)**: stand up a Git + CI pipeline where detection engineers author rules as TOML, a pull request triggers validation and four-eyes review, and a merge syncs the changed rules to the SentinelOne Custom Detection Rule API. Supports all three rule types (single-event `events`, multi-event `correlation`, and scheduled PowerQuery). Adds `references/detection-as-code.md`, the `assets/detection-as-code-starter/` repo scaffold (a zero-dependency `dac_sync.py` TOML-to-API validate/convert/idempotent-sync engine, `dac_lint.py`, `rule.schema.json`, working TOML examples per rule type, `.github/workflows/{lint,sync}.yml`, `CODEOWNERS`, and GitLab/Azure CI equivalents), and `docs/solutions/detection-as-code.md`.
- `mgmt-console-api`: corrected the Custom Detection Rule type table, `queryType: "correlation"` requires `queryLang: "2.0"` (confirmed live; without it the POST returns HTTP 400 `query lang must be 2.0`). Only single-event `events` rules use 1.0.
- Plugin version bumped to **1.2.5** (`.claude-plugin/plugin.json`, marketplace entry) and rebuilt bundles in `dist/`.

### Added - sdl-solutions: scheduled detection exclusions (s1-secops-skills v1.2.2)

- New `sdl-solutions` solution **scheduled detection exclusions**: suppress known-good noise in a scheduled detection over a third-party source by keying it against a CSV exclusion list (assets by IP/CIDR/host, or custom domains/users/values) loaded as an SDL lookup and applied with a lookup anti-join, plus an exclusion-effectiveness dashboard. CIDR/wildcard matches (which the STAR rule validator rejects) run via a Hyperautomation flow that posts a self-contained OCSF S1 SecurityAlert (`class_uid 99602001`) to UAM. Adds `references/scheduled-detection-exclusions.md`, six `assets/exclusion_*` templates, and `docs/solutions/scheduled-detection-exclusions.md`.
- All `sdl-solutions` playbooks now end with a standardized **Deployed artifacts** table (template, deploy target, purpose) in place of the old per-deployment "Reference deployment" notes.
- Plugin version bumped to **1.2.2** (`.claude-plugin/plugin.json`, marketplace entry) and rebuilt bundles in `dist/`.

### Added - plugins/ and mcp/ (SentinelOne SecOps skills + MCP server)

- `plugins/s1-secops-skills/` - a Claude plugin bundling seven SentinelOne SecOps skills (powerquery, mgmt-console-api, sdl-api, sdl-dashboard, sdl-log-parser, sdl-solutions, hyperautomation), with built `.plugin`/`.skill` bundles in `dist/` for one-step install.
- `mcp/sentinelone-mcp/` - the SentinelOne MCP server (Node.js) plus `mcp/docker/` container build.
- Root `.claude-plugin/marketplace.json` registers the repo as an installable plugin marketplace.
- Contributed content is licensed under the repository's AGPL-3.0.

### Changed - pipelines/ reorganization

The `pipelines/` directory has been restructured around ingestion mode rather
than contributor provenance. New layout:

- `pipelines/push/syslog/<vendor>/<product>/`
- `pipelines/push/hec/<vendor>/<product>/`
- `pipelines/pull/api/<vendor>/<product>/`
- `pipelines/pull/object_store/<vendor>/<product>/`
- `pipelines/community/transform_ocsf/<vendor>/<product>/`

`metadata.yaml` for pipelines now includes `ingest_mode` and `auth_type` fields.
The new schema applies to new pipelines added after this release; existing
entries in `transform_ocsf/` will be backfilled in a follow-up. See
`pipelines/community/README.md` for the full schema and naming conventions.

### Removed - orphan PAN-OS serializer

`pipelines/community/serializers/Palo Alto Networks/serializer.lua` has been
removed. It is functionally subsumed by
`pipelines/community/transform_ocsf/paloalto_logs/`, which is signed off with
100% required-field coverage and produces the same OCSF class (Network
Activity, `class_uid=4001`) for a broader range of log types. The now-empty
`pipelines/community/serializers/` umbrella has been removed alongside it.

### Removed - F-graded `palo_alto_networks_firewall` transform

`pipelines/community/transform_ocsf/palo_alto_networks_firewall/` has been
removed. It was graded F (`analyzer_limit`, 0% required-field coverage), used
a non-standard `class_uid=99602001` (SentinelOne Security Alert Extended) that
diverged from the rest of the PAN-OS cluster (`class_uid=4001` Network
Activity), and had no matching upstream parser in `parsers/community/` (its
`source_name` lacked the `-latest` versioning suffix used by every other
PAN-OS entry). The three remaining PAN-OS transforms (`paloalto_logs/`,
`paloalto_alternate_logs/`, `paloalto_vpn_logs/`) are unaffected.

### Documented - PAN-OS transform variant binding

The three remaining PAN-OS OCSF transforms in
`pipelines/community/transform_ocsf/` now declare in their `metadata.yaml`
`purpose` field which upstream parser in `parsers/community/` they bind to
and the field-name convention each expects, so users can choose between them
without reading the Lua. No serializer logic changes.

### Changed - migrated 91 community pipelines into push/pull/ taxonomy

The empty scaffolding under `pipelines/push/{syslog,hec}/` and
`pipelines/pull/{api,object_store}/` introduced in this release is now
populated. 91 community pipelines have moved out of
`pipelines/community/transform_ocsf/` and into ingest-mode-first paths:

- 57 entries → `pipelines/push/syslog/<vendor>/<product>/`
- 29 entries → `pipelines/pull/api/<vendor>/<product>/`
- 5 entries → `pipelines/pull/object_store/<vendor>/<product>/`

The bucket is determined by each entry's `ingest_mode` field. Git history is
preserved on every entry (`git mv`). No serializer logic, metadata content,
or pipeline JSON content changed; every change is a directory rename.

15 entries remain in `pipelines/community/transform_ocsf/` as platform-
agnostic OCSF overlays for generic / template / unknown-vendor data
(`agent_metrics_logs`, `generic_access_logs`, `json_generic_logs`,
`sample_test_logs`, etc.).
### Removed - 16 `transform_ocsf/` entries with first-party ingestion paths

Removed 16 directories from `pipelines/community/transform_ocsf/` for vendors
whose log streams are typically delivered to AI SIEM via first-party or
vendor-native ingestion paths in supported deployments, rather than via
community-contributed Observo transforms:

- `aws_guardduty_logs/`, `aws_waf/`
- `azure_ad/`, `azure_platform/`
- `cisco_duo/`
- `darktrace_darktrace_logs/`
- `microsoft_defender_for_cloud/`, `microsoft_entra_logs/`,
  `microsoft_eventhub_azure_signin_logs/`,
  `microsoft_eventhub_defender_email_logs/`,
  `microsoft_eventhub_defender_emailforcloud_logs/`
- `netskope/`
- `proofpoint/`
- `snyk/`
- `tenable_vulnerability_management_audit_logging/`
- `wiz_cloud_security_logs/`

Each removed entry was previously signed_off and functional; this is a scope
refinement, not a quality fix. The community pipelines directory is intended
for vendors that require contributor-authored parsing and OCSF mapping; users
who specifically need a community transform for one of these vendors can
recover it from git history.
### Removed - 7 broken-legacy `transform_ocsf/` entries

The following directories have been removed from
`pipelines/community/transform_ocsf/`:

- `aws_cloudtrail/`
- `aws_guardduty/`
- `darktrace/`
- `gcp_audit_logs/`
- `microsoft_365/`
- `okta/`
- `wiz_issue/`

Each shares the broken-legacy fingerprint already established by
`palo_alto_networks_firewall/` in the previous release: sub-passing grade
(D or F), `verdict: analyzer_limit`, `class_uid: null`, 0% required-field
coverage, no matching upstream parser in `parsers/community/`, `source_name`
without the `-latest` versioning suffix used by every working entry, and
long-form Python-port style code (632–1720 lines). Each removed entry has
at least one working alternative covering the same vendor cluster
(e.g. `aws_guardduty_logs/`, `darktrace_darktrace_logs/`, `okta_logs/`,
`microsoft_365_mgmt_api_logs/`, `wiz_cloud_security_logs/`).

## [1.3.0] - 2025-10-28

### Added
- Added metadata.yaml files for all workflow components
  - AI SIEM workflows for detection enrichment (by Patryk Kostek)
  - Abnormal Security audit log ingestion workflow (by Patryk Kostek)
- Added comprehensive metadata.yaml for monitors directory
- Added `search_type` field to all detection metadata files (powerquery | star_rule | watchlist_alert)
- Added Monitors Installation Guide section to main README

### Changed
- Updated all 8 detection metadata.yaml files with accurate descriptions based on actual detection logic
  - AzureAD-Entra: Impossible travel, MFA disabled logins, account changes
  - O365: File access rates and excessive logons
  - Fortinet FortiGate: Virus detection in firewall logs
  - Hello World: HTTP 5xx error rate monitoring
  - SQL Security: SQL Server Event ID monitoring
  - Volume Alerts: Log volume drop detection
  - XSOAR Trigger: Lateral movement detection
  - Zscaler: DLP engine threat detection
- Consolidated monitors README content into main README
- Updated repository layout descriptions with accurate component counts

### Removed
- Removed duplicate monitors/README.md file

## [1.2.0] - 2025-10-27

### Added
- Three new AI SIEM workflow components (by Patryk Kostek)
  - [AI SIEM] Add Event Data to Detection Note
  - [AI SIEM] Get Data Source Resources
  - Abnormal Security - Audit Log Ingestor

## [1.1.0] - 2025-10-22

### Changed
- Fixed Fortigate typo in directory names and metadata (was: Fortigagte)

### Added
- Pipelines section to README documentation

## [1.0.2] - 2025-10-08

### Added
- AWS CloudTrail dashboard examples
  - aws-cloudTrail-trends.conf
  - aws-cloudTrail-services-breakdown.conf

## [1.0.1] - 2025-09-14

### Added
- Pipelines directory structure for Observo Transformations
- Updated main branch as default branch

## [1.0.0] - 2025-09-12

### Added
- SECURITY.md file with security policy and vulnerability reporting guidelines
- CHANGELOG.md initial file
- .gitignore configuration
- Monitor files restored:
  - log_gen.py - Log generation for testing
  - maxmind.py - GeoIP enrichment
  - powerquerymonitor.py - PowerQuery monitoring

### Changed
- Set main branch as default (previously master)
- Updated README with repository structure

### Removed
- Removed updated_parsers.zip from parsers/community
- Removed .DS_Store files

## [0.9.0] - 2025-08-26

### Initial Release
- Initial repository structure with 255+ components
- 79 dashboards with metadata
- 8 detection rules with configurations
- 165 parsers (148 community, 17 SentinelOne official)
- 3 Python monitoring scripts
- Workflow templates for automated responses
- Complete metadata.yaml requirements for all component types
- GNU AGPL-3.0 License
