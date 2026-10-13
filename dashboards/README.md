# dashboards/

Dashboard definitions (`*.conf` and `*.json`) for the Singularity console.

```
dashboards/
└── community/<name>-latest/   # dashboard file(s) + metadata.yaml
```

**Naming:** `<vendor-or-topic>-latest/`, or `-vX.Y` for pinned versions.

**Required `metadata.yaml` fields:** `data_dependencies` (the `datasource.name`
or OCSF fields the panels need), `usecase_type` (Operational | Security |
Compliance), `usecase_action` (Formfill | Dashboard | Report | Trending and
Analysis).

Before you commit an export, remove tenant IDs, customer names and any
credentials. See [CONTRIBUTING.md](../CONTRIBUTING.md).
