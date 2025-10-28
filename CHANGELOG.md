# Changelog

All notable changes to the AI-SIEM repository will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
