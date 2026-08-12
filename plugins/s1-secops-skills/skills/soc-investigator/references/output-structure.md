# SOC Investigator: Output Structure

Reference file tree for the investigation output directory produced across the SHORT, MEDIUM, LONG, and third-party phases. Files are written under `investigation_<timestamp>/`.

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
