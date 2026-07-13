# UEBA behavioural anomaly detection

The full solution documentation lives at [`docs/solutions/ueba-anomaly-detection.md`](../../../docs/solutions/ueba-anomaly-detection.md).

Read that document for: the security use-case selector (intent to data sources to detections to
scoring method), the ten detections (SPIKE, DROP, SILENT, NEW-BEHAVIOR, OFF-HOURS, FAN-OUT, RATIO,
VELOCITY, PEER-GROUP, DORMANT) with security examples and logic, the Robust vs Standard method, every exact
deployed PowerQuery, what gets deployed in production mode, the Tier 2/3 roadmap, and the interactive
`baseline_anomaly.py` pipeline.

This solution is part of the `sdl-solutions` skill; it orchestrates the primitive skills
(`mgmt-console-api`, `powerquery`, `hyperautomation`,
`sdl-dashboard`) rather than reimplementing them.
