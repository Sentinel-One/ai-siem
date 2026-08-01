# UEBA behavioural anomaly detection

The **s1-ueba-deployer is the source of truth** for this solution. The full documentation lives at
[`docs/solutions/ueba-anomaly-detection.md`](../../../docs/solutions/ueba-anomaly-detection.md), mirrored
from the deployer.

Read that document for: the security use-case selector (intent to data sources to detections to
scoring method); the detection set, which is the ten behavioural classes (SPIKE, DROP, SILENT,
NEW-BEHAVIOR, OFF-HOURS, FAN-OUT, RATIO, VELOCITY, PEER-GROUP, DORMANT), plus two location detections
(GEO-NEW, IMPOSSIBLE-TRAVEL) when a location field is set, plus Risk-Based Alerting (RBA); the Robust
vs Standard method; every exact deployed PowerQuery; what gets deployed in production; the composite
action key; source matching by `dataSource.name` or `serverHost`; the staggered per-baseline refresh
and daily failure-notifier flows; and the dashboard All Data vs XDR scope. GEO-NEW, IMPOSSIBLE-TRAVEL,
and RBA are shipped, not roadmap.

Deployment scope: the STAR detection rule (`assets/ueba_detection.template.json`) reads the persisted
baseline datatable (`{{BASELINE_TABLE}}`), and lookup tables / datatables are ACCOUNT-level objects,
so the rule can only be created at account scope (`filter.accountIds`); site-scoped creation of
lookup-reading rules is invalid.

This solution is part of the `sentinelone-sdl-solutions` skill; it orchestrates the primitive skills
(`sentinelone-mgmt-console-api`, `sentinelone-powerquery`, `sentinelone-hyperautomation`,
`sentinelone-sdl-dashboard`) rather than reimplementing them.
