---
name: soc-investigator
author: Joel Mora <joelm@sentinelone.com>
description: >-
  Autonomous DFIR investigation orchestrator for SentinelOne alerts in Claude Cowork. Use
  whenever the user wants to investigate, triage, or work a SentinelOne alert or incident:
  "investigate this alert", "triage this alert id", "is this a true positive", "run a DFIR
  investigation", or any request for alert investigation, incident response, or a forensic
  deep-dive on a SentinelOne tenant. Interrogates the user for alert context, then executes
  SHORT (quick triage), MEDIUM (correlation sweep), or LONG (full forensic timeline)
  investigation modes with threat-intel enrichment, MITRE ATT&CK mapping, and strict verdict
  gates. Optionally expands to third-party data sources (M365, Entra ID, Okta, SharePoint,
  firewalls) for cross-source correlation and anomaly detection. Produces a calibrated
  verdict (true positive, false positive, or suspicious) plus a structured investigation
  report with a mandatory query appendix. Trigger on "investigate", "triage", "DFIR",
  "alert investigation", "incident response".
---

# SOC Investigator - Iterative DFIR with Third-Party Expansion

Autonomous investigation orchestrator with user intake, three investigation modes (SHORT/MEDIUM/LONG) focused on SentinelOne alerts, then optional iterative deep-dive into third-party data sources for correlation and anomaly detection.

Compatibility: requires the `powerquery`, `mgmt-console-api`, `sdl-api`, `sdl-log-parser`, `hyperautomation`, and `sdl-dashboard` skills, plus the purple MCP (VirusTotal / threat intel). Works with Claude Cowork.

---

## Evidence discipline and verdict gates (non-negotiable)

Inherited from the Purple SOC Analyst operating standard and the SDL threat-hunt-and-correlation method, these apply to every mode and phase below. Full detail in `references/evidence-and-verdict-discipline.md` and `references/correlation-and-hunt-methodology.md`; the essentials:

- Reconcile to ground truth. An alert, an offence, or a rule "firing" is a lead, not a finding. A claim becomes a finding only when traceable to specific raw log lines or a tool result from this session. If raw evidence is absent, say "unconfirmed"; never upgrade a lead to a conclusion.
- No fabrication. Every count, IOC total, affected-asset number, hostname, CVE, or actor name must come from a query or tool call run this session. If you do not have it, run the query or say so. Empty, null, zero, and tool-error results are findings; report them, do not smooth over them.
- Enrich before you decide, when third-party enrichment is enabled. External IPs, domains, URLs, and hashes are enriched through the configured threat-intel MCP (VirusTotal by default) before any verdict, then pivoted for related infrastructure and actors. Because this sends indicators to a third-party service, it is opt-in: if the user asks for SentinelOne-only / local analysis, or no threat-intel MCP is configured, skip external enrichment, say so, and cap the verdict at SUSPICIOUS - Pending Confirmation (per the verdict gate below). Internal, RFC1918, or no-external-indicator events are enrichment-N/A; state that, never fabricate a lookup.
- Verdict gate. No finding is CRITICAL or TRUE POSITIVE on a detection-engine severity alone. Require at least one of: a threat-intel malicious verdict; MDR or analyst confirmation (check `get_alert_notes` and `get_alert_history` first, an MDR False Positive or Benign verdict takes precedence); or the same IOC or behaviour corroborated across 2+ independent sources. Otherwise the ceiling is SUSPICIOUS - Pending Confirmation.
- Mark assumptions. Prefix any inference needed to proceed with "Assumption:" and state what would falsify it.
- Calibrated confidence. Use confirmed, consistent with, suggests, possible, or no evidence of, matched to evidence weight. "No evidence of" is a real, valuable result; record negatives explicitly.
- Session init first. Enumerate `dataSource.name` live and discover each source's schema before querying it; never assume a field namespace. Reuse the project schema cache if present.
- Apply the anomaly checklist to every log result: frequency, timing, geolocation, baseline deviation, volume, new entity, privilege, chain.
- Hold findings until the end and do not over-correlate: a shared time window is not causation; assert a link only when an entity or artifact bridges the clusters. Map every finding to MITRE ATT&CK and lead each conclusion with verdict, confidence, and evidence count.
- Query appendix, mandatory in every report. Always append an appendix listing every PowerQuery run during the investigation, each with its evidence (see the "Query appendix" section below). Never present a query result without also showing the query and a raw-telemetry excerpt.

---

## Query appendix (mandatory in every report)

Every report this skill produces (summary.md, report.md, full_report.md, third_party_report.md, and any exported .docx / .pdf) MUST end with an appendix that documents all PowerQueries used, with evidence. This is non-negotiable and applies to all modes (SHORT / MEDIUM / LONG) and to the third-party phase.

For each PowerQuery run during the investigation, in execution order, record:

- Purpose: one line on what the query was checking.
- Query: the exact PowerQuery text, verbatim, as executed.
- Scope: the data source(s), the time window (start to end, UTC), and the tenant.
- Result: the match / row count returned.
- Evidence: a short raw-telemetry excerpt (a few representative rows) that supports the finding. For negative results, state "0 rows / empty" explicitly, an empty result is a finding, not an omission.

Rules:

- Include every query actually executed, including ones that returned nothing or errored. Do not curate down to only the "interesting" ones.
- Never write a count, IOC total, affected-asset number, or named entity in the body without a corresponding query and evidence in the appendix that produces it. A peer must be able to copy each query into their console and reproduce the result.
- Keep evidence excerpts trimmed to the probative columns; do not paste hundreds of rows. A handful of representative rows plus the total count is sufficient.
- The appendix documents PowerQueries. Alert-API, console-API, and threat-intel-MCP calls are cited inline in the body per the evidence-discipline rules above.

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

After the user confirms, begin Phase 1 immediately, following the phase-by-phase run instructions for the chosen mode in `references/investigation-modes.md`.

---

## Investigation modes

The skill runs one of three cumulative SentinelOne-focused modes, chosen at intake. The summary below sizes each mode; the full phase-by-phase run instructions (fetch steps, example JSON, and PowerQuery templates) live in `references/investigation-modes.md`. Read the chosen mode's phases there before executing, and follow them in order.

| Mode | Duration | Tokens | What it does |
|------|----------|--------|--------------|
| SHORT | ~5 min | ~2k | SentinelOne alert data only: fetch alerts, extract entities (users, endpoints, IPs, hashes), draft timeline, infer MITRE. Output: entities.json, timeline_draft.csv, mitre_draft.json, summary.md. |
| MEDIUM | ~15 min | ~8k | SHORT plus IOC enrichment (VirusTotal + S1 IOC API) and one PowerQuery per endpoint (process tree + network). Output: threat_intel.json, powerquery_results.jsonl, timeline_enriched.json, report.md, timeline.csv. |
| LONG | ~45 min | ~30k | MEDIUM plus four deep PowerQueries per endpoint (process, files, registry, network), SDL threat-intel correlation, and full MITRE refinement. Output: threat_intel_complete.json, full_report.md, timeline_forensic.csv. |

After MEDIUM or LONG completes, the operator may expand into third-party sources. That optional, iterative playbook (source discovery, entity correlation, anomaly detection, deep interrogation) is documented in `references/third-party-playbook.md`; run it only when the operator selects the third-party option at a MEDIUM or LONG approval gate.

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

## Output structure

All phases write their artifacts into a single `investigation_<timestamp>/` directory (INTAKE.txt, entities.json, the per-mode timelines, reports, IOC and PowerQuery outputs, and the third-party correlation files). The full annotated file tree is in `references/output-structure.md`.

---

## Usage Flow

1. **Trigger**: User starts with `/soc-investigator`
2. **Tool Discovery**: Verify required skills are available; warn on missing ones
3. **Intake**: Answer questions (alerts, mode, approvals)
4. **Investigation Plan**: Display full phase-by-phase plan; user confirms before execution begins
5. **Investigation**: Run SHORT/MEDIUM/LONG per the phase instructions in `references/investigation-modes.md`
6. **Approval + Expansion Choice**: Review findings, choose to dig into third-party or stop
7. **Third-Party (optional)**: Discover sources, correlate entities, detect anomalies (see `references/third-party-playbook.md`)
8. **Deep-Dive (optional)**: User-driven interrogation of specific findings
9. **Output**: All files saved to `investigation_<timestamp>/`
10. **Review**: User reviews outputs for containment/hunting/reporting
