# Community Hyperautomation & Response Workflows

This directory contains **community-contributed** response playbooks and Hyperautomation workflows for the SentinelOne Singularity Platform.

## Documentation Standard

All workflows follow a consistent structure:

- **Vendor-based organization** (e.g. `VirusTotal/`, `Entra ID/`, `Okta/`, `Cloudflare/`)
- Each workflow lives in its own dedicated subfolder (ideally kebab-case with optional version suffix, e.g. `virus-total-enrichment/` or `virus-total-enrichment-v1.0/`)
- **Required contents per workflow folder**:
  - `workflow.json` — **Executable workflow definition** (must remain unchanged for direct import into SentinelOne HyperAutomation)
  - `README.md` — Purpose, Mermaid diagram, use case, dependencies, and testing notes
  - `metadata.yaml` — Standardized machine-readable metadata
  - `examples/` (optional) — Sample payloads or test data

This structure improves readability, maintainability, and collaboration while preserving full import compatibility.

### Visualization Standard

All workflow diagrams are created with **[Mermaid.js](https://github.com/mermaid-js/mermaid)** — text-based, version-controlled diagrams that render natively in GitHub.

**Credit**: Thank you to the entire **mermaid-js community** and maintainers for this powerful standard.

### Metadata Fields Guidance

The `metadata.yaml` includes:
- `purpose`
- `trigger_type`
- `integration_dependency`
- `human_in_the_loop`
- `tags`
- `version`
- `last_updated`

**Optional fields** (only populate when relevant):
- `mitre_attack_mapping` — Use **only** for threat detection/response workflows. Leave blank or omit for operational, enrichment, compliance, vulnerability management, or efficiency automations.
- `data_sources`, `kill_chain_phase`

See `TEMPLATE/metadata.yaml` for the full schema and examples.

## Folder Structure Overview

- `community/` — Community-contributed or customized workflows (this directory)
- `vendor/` — Official templates provided by SentinelOne or other vendors (coming soon — will be added in parallel)

## Contribution Guidelines

- Follow the existing naming patterns from the root repository
- Include a clear Mermaid flowchart (or sequence diagram) in each `README.md`
- Keep `workflow.json` untouched for import compatibility
- Extend `metadata.yaml` with relevant tags (e.g., `hyperautomation`, `enrichment`, `operational`, `compliance`)
- Submit via PR with logical commits

See the root [CONTRIBUTING.md](../../CONTRIBUTING.md) for full details.

## Current Workflows

- **VirusTotal** → VirusTotal hash enrichment with risk scoring and detailed alert notes
- **Entra ID** → Identity context enrichment from Microsoft Graph
- **Abnormal Security**, **Cloudflare**, **Fortinet**, **M365**, **Okta**, **Slack** — additional workflows in progress

This library aims to become a living, visually documented resource for SentinelOne Hyperautomation — covering threat response **and** operational/ efficiency use cases.
