# Community Hyperautomation & Response Workflows

This directory contains community-contributed response playbooks and Hyperautomation workflows for the SentinelOne Singularity Platform.

## Documentation Standard

All workflows follow a consistent structure:

- **Vendor-based organization** (e.g., `VirusTotal/`, `Entra-ID/`, `Okta/`)
- Each workflow lives in its own versioned subfolder (e.g., `virus-total-enrichment-v1.0/`)
- Contents per workflow folder:
  - `workflow.json` — Executable workflow definition (unchanged from original)
  - `README.md` — Purpose, Mermaid diagram, use case, and dependencies
  - `metadata.yaml` — Standardized metadata (purpose, trigger_type, integrations, tags, version, etc.)
  - `examples/` (optional) — Sample payloads or test data

This structure improves readability, maintainability, and collaboration as the library grows — especially for complex agentic/Hyperautomation patterns.

### Visualization Standard

All workflow diagrams are created with **[Mermaid.js](https://github.com/mermaid-js/mermaid)** — a popular open-source diagramming and charting tool.

**Credit**: Thank you to the entire **mermaid-js community** and maintainers for this powerful, text-based visualization standard. It enables version-controlled diagrams that render natively in GitHub, Obsidian, and other Markdown viewers.

Learn more: [mermaid-js GitHub Repository](https://github.com/mermaid-js/mermaid)

## Contribution Guidelines

- Follow the existing naming patterns from the root repository
- Include a clear Mermaid flowchart (or sequence diagram) in each `README.md`
- Extend `metadata.yaml` with relevant tags (e.g., `hyperautomation`, `enrichment`, `mermaid`)
- Submit via PR with logical commits

See the root [CONTRIBUTING.md](../..//CONTRIBUTING.md) (or the one we'll propose) for full details.

## Current Workflows

- **VirusTotal** → VirusTotal hash enrichment with risk scoring and detailed alert notes
- **Entra ID** → Identity context enrichment from Microsoft Graph
- ... (add more as you migrate)

This library aims to become a living, visually documented resource for SentinelOne Hyperautomation and response automation.