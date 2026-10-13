# detections/

Detection rules and alerts, written as PowerQuery, STAR rules or watchlist
alerts.

```
detections/
├── community/<name>-latest/   # community-contributed detections
└── vendor/<name>/             # detections contributed on behalf of a vendor
```

Each detection directory holds the rule (`*.conf`) and a `metadata.yaml`.

**Required `metadata.yaml` fields:** `mitre_tactic_technique` (ATT&CK
mapping), `search_type` (powerquery | star_rule | watchlist_alert), `severity`
(Information | Low | Medium | High). Also describe the expected alert
scenario so reviewers can validate it.

See [CONTRIBUTING.md](../CONTRIBUTING.md).
