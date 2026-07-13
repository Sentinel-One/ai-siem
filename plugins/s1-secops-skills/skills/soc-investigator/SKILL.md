---
name: soc-investigator
author: Joel Mora <joelm@sentinelone.com>
description: Autonomous DFIR investigation for Claude Cowork. Interrogates user for alert context, executes SHORT/MEDIUM/LONG investigation modes on SentinelOne alerts, then optionally expands to third-party data sources (M365, Entra, Sharepoint, etc.) for deep correlation and anomaly detection.
compatibility: Requires powerquery, mgmt-console-api, sdl-api, sdl-log-parser, hyperautomation, sdl-dashboard, purple MCP (VirusTotal/threat intel). Works with Claude Cowork.
metadata:
  author: Joel Mora <joelm@sentinelone.com>
  version: "1.1"
  tags:
    - dfir
    - event-correlation
    - threat-intelligence
    - third-party-correlation
    - mitre-mapping
    - investigation-reporting
---

# SOC Investigator - Iterative DFIR with Third-Party Expansion

Autonomous investigation orchestrator with user intake, three investigation modes (SHORT/MEDIUM/LONG) focused on SentinelOne alerts, then optional iterative deep-dive into third-party data sources for correlation and anomaly detection.

---

## Evidence discipline and verdict gates (non-negotiable)

Inherited from the Purple SOC Analyst operating standard and the SDL threat-hunt-and-correlation method, these apply to every mode and phase below. Full detail in `references/evidence-and-verdict-discipline.md` and `references/correlation-and-hunt-methodology.md`; the essentials:

- Reconcile to ground truth. An alert, an offence, or a rule "firing" is a lead, not a finding. A claim becomes a finding only when traceable to specific raw log lines or a tool result from this session. If raw evidence is absent, say "unconfirmed"; never upgrade a lead to a conclusion.
- No fabrication. Every count, IOC total, affected-asset number, hostname, CVE, or actor name must come from a query or tool call run this session. If you do not have it, run the query or say so. Empty, null, zero, and tool-error results are findings; report them, do not smooth over them.
- Enrich before you decide. Every external IP, domain, URL, or hash is enriched through the threat-intel MCP (VirusTotal by default) before any verdict, then pivoted for related infrastructure and actors. Internal, RFC1918, or no-external-indicator events are enrichment-N/A; state that, never fabricate a lookup.
- Verdict gate. No finding is CRITICAL or TRUE POSITIVE on a detection-engine severity alone. Require at least one of: a threat-intel malicious verdict; MDR or analyst confirmation (check `get_alert_notes` and `get_alert_history` first, an MDR False Positive or Benign verdict takes precedence); or the same IOC or behaviour corroborated across 2+ independent sources. Otherwise the ceiling is SUSPICIOUS - Pending Confirmation.
- Mark assumptions. Prefix any inference needed to proceed with "Assumption:" and state what would falsify it.
- Calibrated confidence. Use confirmed, consistent with, suggests, possible, or no evidence of, matched to evidence weight. "No evidence of" is a real, valuable result; record negatives explicitly.
- Session init first. Enumerate `dataSource.name` live and discover each source's schema before querying it; never assume a field namespace. Reuse the project schema cache if present.
- Apply the anomaly checklist to every log result: frequency, timing, geolocation, baseline deviation, volume, new entity, privilege, chain.
- Hold findings until the end and do not over-correlate: a shared time window is not causation; assert a link only when an entity or artifact bridges the clusters. Map every finding to MITRE ATT&CK and lead each conclusion with verdict, confidence, and evidence count.

---

## Stage 0: Tool Discovery

**Before anything else**, verify that the required skills and tools are available in this session. Check the `available_skills` list in your context for each of the following:

```text
Required skills for full investigation capability:

  Core (SentinelOne telemetry & console)
  ├── mgmt-console-api   - alert fetch, IOC lookup, agent/threat queries
  ├── powerquery          - Deep Visibility / SDL PowerQuery execution
  ├── sdl-api             - SDL file and log management
  │   └── sdl-log-parser  - log parser authoring/validation
  ├── sdl-dashboard       - SDL dashboard creation
  └── hyperautomation     - workflow/SOAR automation

  Threat Intelligence
  └── purple MCP (VirusTotal)         - IOC enrichment
```

For each skill, mark it as **✓ available** or **✗ missing**.

Display the result to the user before proceeding:

```text
=== Tool Discovery ===

Core skills:
  ✓ mgmt-console-api
  ✓ powerquery
  ✗ sdl-api             [MISSING - SDL correlation unavailable]
  ✗ sdl-log-parser      [MISSING - depends on sdl-api]
  ✓ sdl-dashboard
  ✓ hyperautomation

Threat intelligence:
  ✓ purple MCP (VirusTotal)

Impact of missing skills:
  - LONG mode SDL correlation will be skipped
  - Log parser validation unavailable

Proceed with available tools? [YES | CANCEL]
```

If all required skills for the chosen mode are present, proceed automatically (no user confirmation needed unless approval gates are enabled). If critical skills are missing for the requested mode, warn the user and let them choose to continue or cancel.

---

## Stage 1: User Intake Form (Interactive)

After tool discovery, ask the user:

```text
=== SOC Investigator Intake ===

1. ALERT SOURCE
   What alerts do you want to investigate?
   a) Alert ID(s): [comma-separated list, e.g., "alert_001, alert_002"]
   b) Time range query: [e.g., "last 48 hours, threat level HIGH"]
   c) SIEM/JSON paste: [paste alert JSON array]
   → Cowork fetches from SentinelOne console or accepts raw JSON

2. INVESTIGATION SCOPE (SentinelOne focus first)
   Choose investigation depth:

   🔍 SHORT (5 min, ~2k tokens)
      - SentinelOne alert data only
      - Entity extraction (users, endpoints, IPs, hashes)
      - Draft timeline & MITRE
      - Output: JSON + summary.md

   🔎 MEDIUM (15 min, ~8k tokens)
      - SentinelOne: Alert data + IOC enrichment
      - One PowerQuery per endpoint (process tree + network)
      - VirusTotal + S1 IOC API lookups
      - Enriched timeline with threat intel context
      - Output: JSON + report.md + timeline.csv
      - Then: "Want to dig into third-party sources?"

   🔬 LONG (45 min, ~30k tokens)
      - SentinelOne: Everything in MEDIUM, plus:
      - 4 deep PowerQueries per alert (process, files, network, registry)
      - SDL threat intelligence correlation
      - Full MITRE refinement with evidence
      - Output: JSON + full_report.md + visualizations
      - Then: "Deep-dive third-party interrogation?"

   → Select: [SHORT | MEDIUM | LONG]

3. APPROVAL GATES (optional)
   Do you want approval prompts at each phase?
   [YES | NO (proceed automatically)]

4. OUTPUT LOCATION
   Where to save results?
   → Default: ./investigation_<timestamp>/
```

---

## Stage 2: Investigation Plan

Once intake is complete, **generate and display the full investigation plan before executing a single query**. This gives the user a clear map of what will happen.

The plan is derived from their intake answers (mode, alert source, approval gates). Show it as a numbered checklist. Example for MEDIUM mode with approval gates ON:

```text
=== Investigation Plan ===
Mode: MEDIUM | Alerts: last 48h HIGH | Approval gates: ON
Output: ./investigation_2025-06-16T10-00-00/

  PHASE 1 - Alert Ingest & Entity Extraction          [~2 min]
    1.1  Fetch alerts via mgmt-console-api
    1.2  Extract entities (users, endpoints, IPs, hashes)
    1.3  Build draft timeline (chronological alert order)
    1.4  Infer MITRE tactics/techniques from alert types
    → Output: entities.json, timeline_draft.csv, mitre_draft.json, summary.md
    → APPROVAL GATE

  PHASE 2 - IOC Enrichment                            [~5 min]
    2.1  Batch IOC lookups: VirusTotal (purple MCP) + S1 IOC API
    2.2  Sample top 20 IOCs by frequency if >20 total
    → Output: threat_intel.json
    → APPROVAL GATE

  PHASE 3 - Endpoint Process Context                  [~5 min]
    3.1  One PowerQuery per unique endpoint (process tree)
    3.2  One PowerQuery per unique endpoint (network behavior)
    → Output: powerquery_results.jsonl

  PHASE 4 - Enriched Analysis & Reporting             [~3 min]
    4.1  Merge alert + IOC + process context into enriched timeline
    4.2  Refine MITRE with IOC evidence
    → Output: timeline_enriched.json, report.md, timeline.csv
    → APPROVAL GATE + THIRD-PARTY OPTION

  [OPTIONAL] THIRD-PARTY INVESTIGATION
    → Triggered if user selects "dig into third-party sources"
    → Discover available data sources (M365, Entra, AWS, etc.)
    → Correlate entities, detect anomalies, user-driven deep-dive

Total estimated time: ~15 min (core) + 15 min if third-party selected

Proceed? [YES | MODIFY | CANCEL]
```

For LONG mode, include all 7 phases in the plan. For SHORT mode, show only Phase 1.
Always show the optional third-party block at the bottom so the user knows it's available.

If approval gates are OFF, omit the `→ APPROVAL GATE` lines from the plan.

After the user confirms, begin Phase 1 immediately.

---

## Workflow: SHORT Mode (5 min)

**Goal**: Fast triage. What happened at a glance.

### Phase 1: Alert Ingest & Entity Extraction (5 min)

#### 1.1 Fetch alerts
```text
Use: mgmt-console-api
Query: GET /threats (filtered by user input)
Output: alerts.jsonl
```

#### 1.2 Single-pass entity extraction
```json
{
  "alerts_processed": 42,
  "entities": {
    "users": [{"user": "john.doe", "alert_count": 5, "first_seen": "2025-06-16T10:00:00Z"}],
    "endpoints": [{"agentId": "...", "agentName": "DESKTOP-ABC123", "alert_count": 12}],
    "ips": [{"ip": "192.168.1.100", "type": "src", "alert_count": 5}],
    "iocs": [{"value": "hash_abc123...", "type": "hash", "alert_count": 3}]
  }
}
```

#### 1.3 Draft timeline (alert order, not forensic)
```text
- 2025-06-16 10:00 | HIGH   | DESKTOP-ABC123 | john.doe   | Suspicious Process Execution (powershell)
- 2025-06-16 10:05 | MEDIUM | DESKTOP-ABC123 | john.doe   | Registry Modification (persistence)
- 2025-06-16 10:10 | HIGH   | DESKTOP-XYZ789 | jane.smith | File Download (executable)
```

#### 1.4 Draft MITRE (simple inference from alert type)
```json
{
  "tactics": ["Execution", "Persistence"],
  "techniques": [
    {"id": "T1059", "name": "Command and Scripting Interpreter", "confidence": 0.8},
    {"id": "T1112", "name": "Modify Registry", "confidence": 0.7}
  ]
}
```

**Output files**:
- `entities.json` - extracted entities
- `timeline_draft.csv` - simple chronological alert list
- `mitre_draft.json` - inferred tactics/techniques
- `summary.md` - 1-page overview for quick review

**Approval gate** (if enabled):
```text
✓ SHORT investigation complete.
  - 42 alerts processed
  - 7 unique users, 5 endpoints, 12 IPs, 8 IOCs extracted
  - Draft timeline and MITRE mapping ready
  Ready to proceed? [YES | MODIFY INPUT | CANCEL]
```

---

## Workflow: MEDIUM Mode (15 min)

**Goal**: Contextual investigation. Understand what the IOCs are and what the process chain looked like.

Includes SHORT, plus:

### Phase 2: IOC Enrichment (5 min)

#### 2.1 Batch IOC lookups
```text
Use: Purple MCP (VirusTotal) + mgmt-console-api (S1 IOC API)

For each IOC in entities.json:
  - VirusTotal: GET /files/{hash}, /domains/{domain}, /ip_addresses/{ip}
    Extract: detections, verdict, prevalence, last_analysis_date
  - S1 IOC API: GET /iocs (match by hash/domain/ip)
    Extract: verdict, threat_type, confidence
```

#### 2.2 Sample if >20 IOCs
```text
If IOC count > 20:
  Sort by alert_count (descending)
  Lookup only top 20 IOCs
  Note in output: "Sampled 20/52 IOCs by frequency"
```

**Output**: `threat_intel.json`

### Phase 3: Endpoint Process Context (5 min)

#### 3.1 One PowerQuery per unique endpoint
```text
Use: powerquery skill

Query A: Process tree for user during alert window
  src.process.user = '<user_from_alert>'
  AND event.timestamp >= '<alert_time - 4h>'
  | columns ts=event.timestamp, pid=src.process.pid,
    cmd=src.process.commandline, user=src.process.user,
    parent=src.process.parent.commandline
  | sort -ts
  | limit 100

Query B: Network behavior for same user
  src.process.user = '<user_from_alert>'
  AND event.type in ('dns_request', 'network_connect')
  AND event.timestamp >= '<alert_time - 4h>'
  | columns ts=event.timestamp, action=event.type,
    process=src.process.commandline, domain=network.dns.domain,
    dstIp=tgt.ip.address, dstPort=tgt.port
  | sort -ts
  | limit 100
```

**Store results**: `powerquery_results.jsonl` (one result per query)

### Phase 4: Enriched Analysis (3 min)

**4.1 Merge alert + IOC + process context** into `timeline_enriched.json`

**4.2 Refine MITRE with IOC context** - add evidence chains and confidence scores

**Output files**:
- `threat_intel.json` - IOC lookups
- `powerquery_results.jsonl` - process/network queries
- `timeline_enriched.json` - merged context
- `report.md` - formatted investigation report (1-2 pages)
- `timeline.csv` - timeline for import to Excel/Splunk

**Approval gate + Third-Party Option** (if enabled):
```text
✓ MEDIUM investigation complete.
  - 8 IOCs looked up (3 malicious, 2 suspicious, 3 clean)
  - 5 endpoints queried (process trees + network behavior)
  - Enriched timeline with IOC context ready

Next steps:
  [1] Review findings and stop here
  [2] Dig into third-party sources (M365, Entra, Sharepoint, etc.)
  [3] Cancel and refine input

Choose: [1 | 2 | 3]
```

---

## Workflow: LONG Mode (45 min)

**Goal**: Exhaustive investigation. Every lead followed, full forensic timeline, visualizations.

Includes MEDIUM, plus:

### Phase 5: Deep Forensic Queries (25 min, PARALLEL)

#### 5.1 For each endpoint in alerts, run 4 deep PowerQueries
```text
Per endpoint:

Query A: Full process execution tree (parent, siblings, children)
  agent.uuid = '<agentId>'
  AND event.timestamp >= '<alert_time - 24h>'
  | columns ts, pid, ppid, cmd, user, cmdline_hash
  | limit 500

Query B: File operations (writes, moves, deletes, renames)
  agent.uuid = '<agentId>'
  AND event.type in ('file_write', 'file_move', 'file_delete', 'file_rename')
  AND event.timestamp >= '<alert_time - 24h>'
  | columns ts, action, path, sha256, size
  | limit 500

Query C: Registry operations (if Windows)
  agent.uuid = '<agentId>'
  AND event.type = 'registry_operation'
  AND event.timestamp >= '<alert_time - 24h>'
  | columns ts, operation, registry_path, registry_value
  | limit 500

Query D: Full network behavior
  agent.uuid = '<agentId>'
  AND event.type in ('dns_request', 'network_connect', 'http_request', 'tls_handshake')
  AND event.timestamp >= '<alert_time - 24h>'
  | columns ts, event_type, process, src_ip, dst_ip, dst_port, domain, url
  | limit 500
```

**Run in parallel** across all endpoints. Store results: `powerquery_results.jsonl`

### Phase 6: Threat Intelligence Deep-Dive (10 min, PARALLEL)

#### 6.1 SDL threat intelligence correlation
```text
Use: powerquery skill

For each IOC in entities.json:
  indicator.hash = '<hash>' OR indicator.domain = '<domain>' OR indicator.ip = '<ip>'
  AND event.timestamp >= '<alert_time - 7d>'
  | group threat_count=count() by agent.uuid, indicator.threat_type, indicator.source
  | sort -threat_count
  | limit 100
```

**Goal**: Find other endpoints/users that encountered same IOCs (lateral spread, supply chain).

#### 6.2 Expand IOC lookups (all IOCs, not sampled)
VirusTotal: Full report for all hashes, domains, IPs + S1 IOC API: All IOCs

**Store results**: `threat_intel_complete.json`

### Phase 7: Forensic Analysis & Synthesis (5 min)

**7.1 Build forensic timeline** - merge raw alerts + PowerQuery results + IOC hits + SDL correlations

**7.2 Refine MITRE with full forensic evidence** - add confidence scores and evidence chains

**Output files**:
- `full_report.md` - comprehensive investigation report
- `timeline_forensic.csv` - full timeline for SIEM/Excel import
- All JSON outputs from earlier phases

**Approval gate + Third-Party Option** (if enabled):
```text
✓ LONG investigation complete.
  - 42 alerts processed
  - 12 endpoints deep-queried (4 queries each = 48 queries)
  - 8 IOCs fully enriched (VirusTotal + SDL correlation)
  - Cross-tenant IOC correlation identified (7 other incidents)
  - Full forensic timeline with visualizations ready

Next steps:
  [1] Review findings and stop here
  [2] Deep-dive third-party interrogation (M365, Entra, Sharepoint, etc.)
  [3] Cancel and refine input

Choose: [1 | 2 | 3]
```

---

## Workflow: THIRD-PARTY INVESTIGATION (Optional, Iterative)

**Triggered by**: User selects option [2] from MEDIUM or LONG approval gate

**Goal**: Correlate extracted entities (users, IPs, domains) across third-party data sources and detect anomalies.

### Phase 1: Discover Available Data Sources (2 min)

#### 1.1 Query all available data sources
```text
Use: powerquery skill

dataSource.name = *
| group ct=count() by dataSource.name
| sort -ct
| limit 50
```

#### 1.2 Ask user which sources to investigate
```text
Available data sources detected:
  ✓ Microsoft 365 (1.2M events)
  ✓ Entra ID (567K events)
  ✓ SharePoint Online (234K events)
  ✓ Exchange Online (456K events)
  ...

Which sources are relevant to this incident?
  [Select all that apply, or "all"]
```

### Phase 2: Schema Exploration (3 min per source)

For each selected source:
- Query A: list all activities (`| group ct=count() by activity_name | sort -ct | limit 30`)
- Query B: sample 10 events to see available fields

Ask user which activities/fields to focus on before running correlation queries.

### Phase 3: Entity Correlation (5 min per source)

For each user, IP, and domain in `entities.json`, run targeted queries against the selected sources.

**Output**: `third_party_correlation.json`

### Phase 4: Anomaly Detection (5 min per source)

For each user + activity combination, run timeseries analysis:
```text
| let hour = timebucket('1h')
| group ct=count() by hour
| sort +hour
```

Compare incident period against 7-day baseline. Flag spikes > 2σ and never-before-seen patterns.

**Output**: Append `anomalies` block to `third_party_correlation.json`

### Phase 5: Deep Interrogation (Optional, user-driven)

Surface significant findings, let the user choose which to deep-dive with targeted queries. Repeat until user is satisfied.

**Output**: `deep_dive_<selection>.json` per chosen finding

### Phase 6: Final Third-Party Report (2 min)

Synthesize all findings into `third_party_report.md`.

**Output files**:
- `third_party_correlation.json` - full correlation matrix
- `anomalies.json` - timeseries spikes
- `deep_dive_*.json` - user-selected deep-dives
- `third_party_report.md` - synthesis

---

## Token Optimization Summary

| Phase | Duration | Tokens | Content |
|-------|----------|--------|---------|
| SHORT | 5 min | ~2k | Alerts + entity extraction |
| MEDIUM | 15 min | ~8k | SHORT + IOC + 1 PQ per endpoint |
| LONG | 45 min | ~28k | MEDIUM + 4 PQ per endpoint + SDL |
| Third-Party (opt-in) | 15 min | ~10k | Source discovery + entity correlation + anomaly detection |

**Key optimizations**:
- Batch operations (all IOCs at once, all endpoints in parallel)
- Structured outputs (JSON, no prose)
- IOC sampling in MEDIUM (top 20 by frequency)
- Third-party is **opt-in** - user decides scope creep
- Deep-dive interrogation is user-driven (ask before diving)

---

## Output Structure

```text
investigation_<timestamp>/
├── INTAKE.txt                      # User intake responses
├── entities.json                   # Extracted entities
├── timeline_draft.csv              # Alert timeline (SHORT+)
├── mitre_draft.json                # Draft MITRE (SHORT+)
├── summary.md                      # Summary (SHORT)
├── threat_intel.json               # IOC lookups (MEDIUM+)
├── powerquery_results.jsonl        # PQ outputs (MEDIUM+)
├── timeline_enriched.json          # Merged context (MEDIUM+)
├── report.md                       # Investigation report (MEDIUM)
├── timeline.csv                    # Timeline export (MEDIUM)
├── threat_intel_complete.json      # Full IOC + SDL (LONG)
├── full_report.md                  # Full report (LONG)
├── timeline_forensic.csv           # Full timeline (LONG)
├── datasources_available.json      # Available third-party sources
├── schema_*.json                   # Schema for each source explored
├── sample_*.jsonl                  # Sample events per source
├── third_party_correlation.json    # Entity correlation + anomalies
├── deep_dive_*.json                # User-selected deep-dives
└── third_party_report.md           # Third-party synthesis
```

---

## Usage Flow

1. **Trigger**: User starts with `/soc-investigator`
2. **Tool Discovery**: Verify required skills are available; warn on missing ones
3. **Intake**: Answer questions (alerts, mode, approvals)
4. **Investigation Plan**: Display full phase-by-phase plan; user confirms before execution begins
5. **Investigation**: Run SHORT/MEDIUM/LONG
6. **Approval + Expansion Choice**: Review findings, choose to dig into third-party or stop
7. **Third-Party (optional)**: Discover sources, correlate entities, detect anomalies
8. **Deep-Dive (optional)**: User-driven interrogation of specific findings
9. **Output**: All files saved to `investigation_<timestamp>/`
10. **Review**: User reviews outputs for containment/hunting/reporting
