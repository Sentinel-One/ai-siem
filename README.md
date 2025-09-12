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
ai-siem/                # AI SIEM core structure (255+ components)
  ├── dashboards/      # Visualizations (79 dashboards with metadata)
  │   └── community/   # Community-contributed dashboards
  ├── detections/      # Detection rules (8 detections with metadata)
  │   └── community/   # Community-contributed detection rules
  ├── monitors/        # Monitoring scripts (3 Python monitors)
  ├── parsers/         # Parsing logic and configurations (165 parsers)
  │   ├── community/   # 148 community parsers (*.conf + metadata)
  │   └── sentinelone/ # 17 official marketplace parsers (*.conf + metadata)
  └── workflows/       # Automated playbooks and responses (ready for content)
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
```
