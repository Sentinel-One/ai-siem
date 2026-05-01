# AI-SIEM Repository – A SentinelOne GitHub Forge Project

> A community‑driven, SentinelOne‑assisted library of **parsers, dashboards, detections & response playbooks** that supercharge the Singularity Platform.

---

## Important Note 

Sentinel-One AI-SIEM repository is a community-driven, open source project designed to streamline the deployment and use of the SentinelOne's AI SIEM. While not a formal SentinelOne product, Sentinel-One AI-SIEM repository is maintained by SentinelOne and supported in partnership with the open source developer community.

## Why this repository exists  
* Unite scattered content and eliminate “hunt‑the‑snippet” time for engineers and customers.  
* Enforce automated quality gates so every artifact is production‑ready.  
* Foster an open ecosystem where field teams, partners, and customers co‑create knowledge objects.

---

## Repository layout
```
ai-siem/                # AI SIEM core structure (260+ components)
  ├── dashboards/      # Visualizations (79 dashboards with metadata)
  │   └── community/   # Community-contributed dashboards
  ├── detections/      # Detection rules (8 detections with metadata)
  │   └── community/   # Community-contributed detection rules
  ├── monitors/        # Python monitoring scripts for Dataset Agent (log_gen, maxmind, powerquery)
  ├── pipelines/       # Observo pipeline templates
  │   ├── push/        # Vendor pushes to us (syslog/CEF/LEEF/KV or direct HEC)
  │   │   ├── syslog/<vendor>/<product>/
  │   │   └── hec/<vendor>/<product>/
  │   ├── pull/        # We fetch from the vendor (REST API or object store)
  │   │   ├── api/<vendor>/<product>/
  │   │   └── object_store/<vendor>/<product>/
  │   └── community/
  │       └── transform_ocsf/<vendor>/<product>/  # OCSF normalization overlays
  ├── parsers/         # Parsing logic and configurations (165 parsers)
  │   ├── community/   # 148 community parsers (*.conf + metadata)
  │   └── sentinelone/ # 17 official marketplace parsers (*.conf + metadata)
  └── workflows/       # Automated playbooks and responses
      ├── community/   # Community-developed HyperAutomation Workflows
      ├── docs-guides/ # Detailed documentation guides on importing/configuring HA Workflows
      └── vendor/      # HyperAutomation Workflows developed by S1 Staff + Partner vendors
```

---

## Quick start
1. **Clone** the repo and select the folder that matches your use‑case.  
2. **Import** dashboards (`*.conf`) or rules (`*.conf`) into your Singularity console.  
3. **Choose** between community parsers or official SentinelOne marketplace parsers.  
4. **Deploy** parsers using the included metadata.yaml for proper configuration.  
5. *(Optional)* run `make install` or `make validate` to lint and prep local changes.


---

## Contribution guide ##
1. Fork the repo and create a feature branch.  
2. Name files `vendor-usecase-vX.Y.<ext>` (e.g., `zscaler_http_access-v1.0.s1ql`) and add a matching `metadata.yaml`.  
3. Include or update sample logs under `tests/fixtures`.  
4. Open a Pull Request – CI will run secret scanning and CodeReview.  
5. At least one owner review is required before merge.


---

## Automation & quality gates
| Stage        | What it does                                                                        |
|--------------|-------------------------------------------------------------------------------------|
| Security     | Secret scanning & CodeQL                                                            |
| Release      | Semantic‑release tags `vX.Y.Z` and publishes artifacts to GitHub Releases & S3      |

---

## Community recognition
Quarterly awards for **Top Contributor**, **Most Interesting Use‑Case**, and **Best Dashboard** keep momentum high. All merged PRs count toward the public leaderboard—watch the PartnerOne newsletter for shout‑outs!

---

## Roadmap & KPIs
* **MVP v1.0** public launch at OneCon.  
* ≥ 200 GitHub ⭐ stars, 30 external PRs, and 40 % tenant adoption within the first 12 months.  
* Continuous sprint cadence with KPI reviews every quarter.

---

## License
Released under the **GNU Affero General Public License v3.0 (AGPL-3.0)** – ensuring that all modifications and network use remain open source. See the [LICENSE](LICENSE) file for details.

---

## Monitors Installation Guide

### Dataset Agent Integration
The monitors directory contains Python scripts for use with the Dataset Agent:
- **log_gen.py** - Generate test logs for various vendor formats (Cisco, Windows DNS)
- **maxmind.py** - MaxMind GeoIP enrichment for IP addresses
- **powerquerymonitor.py** - PowerQuery monitoring capabilities

### Installation Steps
1. Copy monitor files to Dataset Agent directory:
   ```bash
   cp monitors/*.py /usr/share/scalyr-agent-2/py/scalyr_agent/builtin_monitors/
   ```

2. Configure the agent by editing `/etc/scalyr-agent-2/agent.log`:
   ```json
   monitors: [
     {
       "module": "scalyr_agent.builtin_monitors.log_gen",
       "logs": "/tmp/logs/*",
       "type_array": "['cisco', 'windows_dns']",
       "parser": "json",
       "time_pattern": "(?P<date>(\\d+ \\w+ \\d+|\\d+\\/\\d+\\/\\d+)) (?P<time>(\\d{2}:\\d{2}:\\d{2}\\.\\d{3}|\\d+:\\d+:\\d+ \\w+))",
       "sampling_rate": ".2"
     }
   ]
   ```

3. Start the Dataset Agent:
   ```bash
   scalyr-agent-2 start
   ```

---

## Pipelines

The `pipelines/` directory holds Observo pipeline templates for SentinelOne
AI SIEM, organized by ingest mode:

- `pipelines/push/{syslog,hec}/<vendor>/<product>/` — vendor pushes events to us
- `pipelines/pull/{api,object_store}/<vendor>/<product>/` — we fetch from the vendor
- `pipelines/community/transform_ocsf/<vendor>/<product>/` — OCSF normalization
  overlays that run on top of upstream-ingested data

The full directory taxonomy, required `metadata.yaml` fields, and naming
conventions are documented in [`pipelines/community/README.md`](pipelines/community/README.md).

### Installing a community pipeline

1. Navigate to the relevant `pipelines/{push,pull}/<mode>/<vendor>/<product>/`
   or `pipelines/community/transform_ocsf/<vendor>/<product>/` directory.
2. Import the JSON template into your Observo instance, or apply the Lua
   serializer to the appropriate transform stage.
3. Update authentication credentials per the `metadata.yaml` `dependencies`
   block.
4. Configure the SentinelOne AI SIEM HEC destination:
   - **HEC token** — replace the placeholder in the import.
   - **Endpoint URL** — verify regional endpoint
     (default `https://ingest.us1.sentinelone.net`).
5. Deploy and activate.

---

## Workflows / Hyperautomation

Community response playbooks and Hyperautomation workflows are located in [`workflows/community/`](workflows/community/).

We have introduced a standardized documentation approach:
- Vendor-first folder structure with per-workflow subfolders
- Consistent `metadata.yaml`
- **Mermaid.js** diagrams for clear visualization of logic, decisions, and orchestration steps

**Credit to Mermaid.js**: All diagrams are powered by the open-source **[mermaid-js/mermaid](https://github.com/mermaid-js/mermaid)** project. Huge thanks to the mermaid-js community and maintainers for making version-controlled, beautiful workflow documentation possible directly in Markdown.

See [`workflows/community/README.md`](workflows/community/README.md) for the full documentation standard and examples.

---

## Getting help
Open an issue. Office hours TBD based on requests.


```yaml
## Metadata requirements per configuration type:

# Workflows
# File: metadata.yaml
metadata_details:
  purpose: "Describe the outcome, integrations, and components that need to be preconfigured"
  trigger_type: "alert | manual"
  integration_dependency: "Describe the 3rd party integrations needed to run this activity. Mention if licensing or additional features are required."
  expected_actions_per_run: "Total number of steps in the workflow"
  human_in_the_loop: "yes | no – Does the workflow require human interaction?"
  required_products: "List SentinelOne products required (e.g., EDR, CWS, CNS, Vulnerability Management)"
  tags: "Optional tagging"
  version: "v1.0"

# Dashboards
# File: metadata.yaml
metadata_details:
  data_dependencies: "Specify datasource.name or OCSF field"
  required_fields: "Any additional fields needed beyond the extracted set"
  description: "What is the visualization helping to inform?"
  usecase_type: "Operational | Security | Compliance"
  usecase_action: "Formfill | Dashboard | Report | Trending and Analysis"
  tags: "Optional tagging"
  version: "v1.0"

# Detections
# File: metadata.yaml
metadata_details:
  purpose: "Detects a specific action from a SentinelOne component or third-party integration"
  mitre_tactic_technique: "Provide the MITRE Tactic and Technique (if known)"
  datasource: "Name of the dataSource.name field"
  search_type: "powerquery | star_rule | watchlist_alert"
  usecase_plus: "Explain how combining this data with others enhances detection"
  severity: "Information | Low | Medium | High"
  expected_alert_scenario: "What alert behavior should users expect?"
  performance_impact: "Describe the impact on system performance or security operations"
  tags: "Optional tagging"
  version: "v1.0"

# Parsers
# File: metadata.yaml
metadata_details:
  purpose: "Describe what the parser does and how it processes data"
  datasource_vendor: "AWS | Microsoft | GCP | Azure | other"
  dataSource: "Specify the value for dataSource.name"
  format: "gron | json | xml | raw | syslog"
  ingestion_method: "streaming | syslog | HEC | Agent Ingest"
  sample_record: "Example log or event that the parser handles"
  dependency_summary: "Dependencies required for this parser to function properly"
  performance_impact: "Any performance impact or caveats"
  tags: "Optional tagging"
  version: "v1.0"

# Monitors
# File: metadata.yaml
metadata_details:
  data_dependencies: "Relevant OCSF or custom fields used for triggering"
  monitor_type: "Threshold | Anomaly | Heartbeat | Availability"
  trigger_frequency: "Polling interval or triggering condition"
  expected_behavior: "Describe the action or alert that should result"
  tags: "Optional tagging"
  version: "v1.0"

# Pipelines
# File: metadata.yaml
# Schema applies to new pipelines; existing entries will be backfilled in a follow-up.
# Top-level `grade:` block is produced by the automated grader — do not hand-author.
metadata_details:
  vendor: "<canonical_vendor_key>"      # lowercase, underscored
  product: "<canonical_product_key>"    # lowercase, underscored
  ingest_mode: "HEC | Syslog | API Call | Other - {Explain, e.g. websocket, object store}"
  auth_type: "N/A | HEC Token | OAuth | API Key & Secret | Bearer Token | Basic | mTLS | IAM Role | Other - {Explain}"
  syslog_format: "CEF | LEEF | RFC5424 | RFC3164 | Vendor KV"   # optional, push/syslog/ only
  purpose: "What the pipeline ingests/transforms and into which OCSF classes"
  source_template: "Source template name as it appears in the pipeline manager"
  source_vendor: "Vendor display name"
  destination_template: "SentinelOne AI SIEM"
  destination_type: "SPLUNK_HEC_LOGS"
  transform_templates: "Description of OCSF / Lua serializer logic"
  input_schema: "Expected input record fields"
  output_schema: "Resulting OCSF event shape"
  scheduling: "Polling interval / event-driven / N/A"
  retry_behavior: "Backoff and failure handling"
  dependencies: "Auth credentials, IAM, queues, etc."
  performance_impact: "Throughput and tuning notes"
  tags: "Optional tagging"
  version: "v1.0"
```
