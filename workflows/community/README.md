# Community Hyperautomation & Response Workflows

This directory contains community-contributed Hyperautomation workflows and response playbooks for the SentinelOne Singularity Platform (and integrated tools).

## Current Documentation Standard

Every workflow follows this structure:

- **Vendor-based organization** (e.g. `M365/`, `Okta/`, `Cloudflare/`)
- Each individual action lives in its own subfolder named after the JSON file (without extension)
- Required files per action:
  - `*.json` — The executable workflow definition (unchanged — required for import into HyperAutomation)
  - `metadata.yaml` — Machine-readable summary
  - `readme.md` — Technical documentation with **detailed JSON-aligned Mermaid diagram**

## Example Structure
```bash
M365/
├── [M365] Disable User/
│   ├── [M365] Disable User.json
│   ├── metadata.yaml
│   └── readme.md
```
