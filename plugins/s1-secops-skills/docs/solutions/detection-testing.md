# Solution: Detection Testing

Prove that a detection works before it goes live, and record which results came from simulated data
and which from real data. It covers SentinelOne EDR detections on Windows, Linux and macOS, Cloud
Workload Security detections on Linux servers and cloud workloads, and SIEM detections over
third-party sources in the Singularity Data Lake. It applies to new custom rules, converted rules
(Sigma rules or KQL hunts converted to PowerQuery) and tuning changes to existing rules.

This is part of the `sdl-solutions` skill. Playbook:
[`sdl-solutions/references/detection-testing.md`](../../skills/sdl-solutions/references/detection-testing.md).

## Run it with one prompt

- *"Test these three detections before we enable them"*
- *"Convert these Sigma rules to PowerQuery and prove they work"*
- *"A/B my tuned PowerShell rule against the current one"*
- *"Is any of these already covered by a platform rule?"*

## The steps

| Step | Data | Changes the tenant | Proves |
| --- | --- | --- | --- |
| 1. Platform coverage | Rule metadata | No | Whether a platform rule or an existing custom rule already covers the behaviour |
| 2. Real-data validation | Real data | No | The body runs, its fields are populated, the expected volume |
| 3. Query proof | Tagged synthetic events | Test events | The logic matches positives and ignores near misses |
| 4. Alert proof | Tagged synthetic events | Temporary rules, deleted after | The rule deploys, activates and raises a UAM alert |
| 5. Real telemetry | Harmless lookalikes on a test endpoint | Test endpoint activity | The agent records what the rule reads |
| 6. Native versus custom | Real telemetry | No | What the platform raised on its own |
| 7. A/B | The same synthetic and real data | Optional shadow rules | Which rule to keep |
| 8. Evidence | All of the above | No | A reviewer can rerun every result |

## What you need

- s1-secops-mcp with write enabled for steps 3, 4 and 5 ([read-only.md](../read-only.md)). Steps 1, 2
  and 6 and the A/B query are read only.
- An SDL Log Write Key for the test account or site, and a console token that can create, enable and
  delete Custom Detection rules there.
- For real telemetry: a Windows test endpoint (with RemoteOps rights) or a Linux VM with the agent
  installed on the host. On macOS, Lima provides an Ubuntu VM in minutes.

## What you get

For every detection, a verdict and the evidence behind it, labelled as simulated, real telemetry or
real data, with the queries, rule ids and alert ids a reviewer needs to rerun it, and a list of what
was not covered. Temporary rules and RemoteOps scripts are deleted and read back at the end.

## Pair it with

- [Detection as Code](./detection-as-code.md) to keep the proven rules in Git.
- [Custom detections with MITRE mapping](./custom-detection-mitre-mapping.md) when the alert should
  carry ATT&CK tactics and techniques.
- [Custom detection exclusions](./custom-detection-exclusions.md) and
  [Alert noise reduction](./alert-noise-reduction.md), whose tuning changes run the playbook's
  regression check.
