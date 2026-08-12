# SOC Investigator: Third-Party Investigation Playbook

Optional iterative deep-dive into third-party data sources (M365, Entra ID, Okta, SharePoint, firewalls, and any other source ingesting into SDL) for cross-source entity correlation and anomaly detection. `SKILL.md` loads this file only when the operator selects the third-party option at a MEDIUM or LONG approval gate. The evidence-discipline, verdict-gate, and query-appendix rules stated in `SKILL.md` apply throughout.

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
