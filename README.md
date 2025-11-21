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
  ├── pipelines/       # Observo Pipeline Templates for data transformation (5 pipelines)
  │   └── community/   # AWS S3, Cisco Duo, Netskope, Okta, ProofPoint
  ├── parsers/         # Parsing logic and configurations (165 parsers)
  │   ├── community/   # 148 community parsers (*.conf + metadata)
  │   └── sentinelone/ # 17 official marketplace parsers (*.conf + metadata)
  └── workflows/       # Automated playbooks and responses (3 workflows with metadata)
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

## Pipelines Installation Guide

### Observo Pipeline Integration
The pipelines directory contains pre-configured Observo pipeline templates for ingesting and transforming data from various sources:

#### Available Pipeline Templates
1. **AWS S3 CloudTrail** (`aws_s3_cloudtrail/`)
   - Ingests CloudTrail logs from S3 buckets via SQS/SNS
   - Transforms to OCSF format with extensive field mapping
   - **Required credentials:**
     - `auth.assume_role`: `arn:aws:iam::<your_accountid>:role/<role you created>`
     - `auth.external_id`: Your external ID for role assumption

2. **Cisco Duo Logs** (`cisco_duo_logs/`)
   - Collects authentication, administrator, and telephony logs
   - Supports checkpointing for incremental data collection
   - **Required credentials:**
     - `DUO_API_HOST`: `<your_host>.duosecurity.com`
     - `DUO_INTEGRATION_KEY`: Your integration key
     - `DUO_SECRET_KEY`: Your secret key

3. **Netskope Alerts** (`netskope_alerts/`)
   - Ingests Netskope security alerts
   - Transforms to OCSF format

4. **Okta Log Collector** (`okta_log_collector/`)
   - Collects Okta identity and access management logs
   - Supports incremental log collection

5. **ProofPoint Logs** (`proofpoint_log/`)
   - Ingests ProofPoint email security logs
   - OCSF transformation included

### Pipeline Installation Steps
1. Import the JSON configuration file into your Observo instance
2. Update authentication credentials with your specific values
3. Configure the SentinelOne AI SIEM destination endpoint
4. Deploy and activate the pipeline

### Configuration Requirements
All pipelines require:
- **SentinelOne HEC Token**: Replace `********` with your actual token
- **Endpoint URL**: Verify the correct region endpoint (default: `https://ingest.us1.sentinelone.net`)
- **Source-specific credentials**: See individual pipeline requirements above

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
```
