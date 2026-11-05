# Alert 1770000000000000002 - FIN-WKS-0042

**SUSPICIOUS - Pending Confirmation, single weak signal.** I am not opening a P1 on this yet.

## Why the ceiling is Pending Confirmation

A detection is a hypothesis, not a conclusion. The CRITICAL label is the Behavioural AI
engine's view of the threat class, and the verdict gate requires at least one of a
threat-intel malicious verdict, an MDR or analyst confirmation, or the same indicator
corroborated across two independent sources. None is present:

- External enrichment is opt-in and you declined it for this tenant, so it was skipped
  and no indicator left SentinelOne. That is a deliberate gap, recorded, not an oversight.
- The notes and history returned by `uam_get_alert` are both empty. No MDR verdict exists.
- One engine firing once is not multi-source corroboration.

Asset criticality (a finance workstation) raises the priority of the next collection step.
It is not a substitute for a confirmation gate, and it cannot lift the verdict on its own.

## Query appendix

- **Purpose:** confirm whether the behaviour recurs on FIN-WKS-0042.
  **Scope:** SentinelOne EDR, 24h to the alert time, UTC.
  **Result:** 0 rows / empty.
  **Evidence:** empty result set; recorded as a finding, not dropped.
