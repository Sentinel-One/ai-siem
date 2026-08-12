# SOC Investigator: Investigation Mode Run Instructions

Phase-by-phase run instructions for the SHORT, MEDIUM, and LONG investigation modes. `SKILL.md` loads this file once the operator has chosen a mode in Stage 1. Run the phases for the selected mode in order. The evidence-discipline, verdict-gate, and query-appendix rules stated in `SKILL.md` apply to every phase here. Each mode is cumulative: MEDIUM includes SHORT, and LONG includes MEDIUM.

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
