# s1Community – SentinelOne Community Forge

> A community‑driven, SentinelOne‑assisted library of **parsers, dashboards, detections & response playbooks** that supercharge the Singularity Platform.

---

## Why this repository exists  
* Unite scattered content and eliminate “hunt‑the‑snippet” time for engineers and customers.  
* Enforce automated quality gates so every artifact is production‑ready.  
* Foster an open ecosystem where field teams, partners, and customers co‑create knowledge objects.

---

## Repository layout
```
aisiem/                # AI SIEM core structure
  ├── dashboards/      # Visualizations (*.json + metadata)
  ├── detections/      # Detection rules (*.conf + metadata)
  ├── monitors/        # Monitors for saving/updating objects 
  ├── parsers/         # Parsing logic and configurations (*.json + metadata)
  ├── workflows/       # Automated playbooks and responses (*.json + metadata)
```

---

## Quick start
1. **Clone** the repo and select the folder that matches your use‑case.  
2. **Import** dashboards (`*.json`) or rules (`*.conf`) into your Singularity console.  
3. **Automate** actions by deploying playbooks in **responses/** with HyperAutomation.  
3a. *(Optional)* run `make install` or `make validate` to lint and prep local changes.


---

## Contribution guide
1. Fork the repo and create a feature branch.  
2. Name files `vendor-usecase-vX.Y.<ext>` (e.g., `zscaler_http_access-v1.0.s1ql`) and add a matching `metadata.yaml`.  
3. Run `yamllint` & `s1ql-lint`; ensure all tests pass.  
4. Include or update sample logs under `tests/fixtures`.  
5. Open a Pull Request – CI will run lint, replay tests, secret scanning and CodeQL.  
6. At least one **CODEOWNER** review is required before merge.

Detailed steps live in **docs/CONTRIBUTING.md**.

---

## Automation & quality gates
| Stage        | What it does                                                                        |
|--------------|-------------------------------------------------------------------------------------|
| Static lint  | `yamllint` + `s1ql‑lint`                                                            |
| Replay test  | Replays sample logs against a disposable tenant; ensures low noise (≤ 0.1% FP rate across test data) |
| Security     | Secret scanning & CodeQL                                                            |
| Release      | Semantic‑release tags `vX.Y.Z` and publishes artifacts to GitHub Releases & S3      |

---

## Community recognition
Quarterly awards for **Top Contributor**, **Most Interesting Use‑Case**, and **Best Dashboard** keep momentum high. All merged PRs count toward the public leaderboard—watch the PartnerOne newsletter for shout‑outs!

---

## Roadmap & KPIs
* **MVP v1.0** public launch at OneCon.  
* ≥ 200 GitHub ⭐ stars, 30 external PRs, and 40 % tenant adoption within the first 12 months.  
* Continuous sprint cadence with KPI reviews every quarter.

---

## License
Released under the **Apache 2.0** license – use, modify, and distribute with attribution.

---

## Getting help
Open an issue or join the `#ai-siem-community` Slack channel. Office hours every <x days @ 09:00 EST>.


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
  format: "json | xml | raw | syslog"
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
