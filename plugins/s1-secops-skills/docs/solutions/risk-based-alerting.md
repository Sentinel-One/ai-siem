# Solution: Risk-Based Alerting (RBA)

Implement the Risk-Based Alerting (RBA) paradigm in SentinelOne. Instead of alerting on every noisy-but-interesting
observation, each one is published as a low-noise **risk event** into a dedicated risk index. Risk
accumulates per **risk object** (a user or a host), amplified by **risk factors** (asset criticality,
privileged, watchlist). A single high-fidelity alert fires only when a risk object crosses a
cumulative-score or distinct-MITRE-tactic threshold, so the analyst sees a contextualised story (a
timeline of connected behaviour across tactics) rather than a flood of disconnected alerts.

This is part of the `sentinelone-sdl-solutions` skill. It orchestrates the primitive skills
(`sentinelone-powerquery` for the contributor and incident queries, `sentinelone-sdl-api` for the
risk index and the factor table, `sentinelone-hyperautomation` for the collector flow,
`sentinelone-mgmt-console-api` for the incident rules, `sentinelone-sdl-dashboard` for the
dashboard); it does not reimplement them.

Every mechanic here is tenant-validated end to end (2026-06-25), including a real fired alert.

## How it maps to SentinelOne

| RBA concept | SentinelOne |
|---|---|
| Risk index | `dataSource.name='risk'`, populated via SDL HTTP ingest |
| Risk Analysis adaptive response | Risk collector: a scheduled Hyperautomation flow that runs contributors and publishes risk events |
| Risk object (user / system) | `risk_object` + `risk_object_type` |
| Threat object | `threat_object` + `threat_object_type` |
| Risk factors (multipliers) | A factor table sourced from the Asset Inventory; `risk_score = base_score * multiplier` |
| Risk incident rule | A STAR scheduled PowerQuery rule over the risk index |
| Notable + timeline | The incident alert plus the dashboard's per-object contributing-events timeline |
| Risk Factor Editor | The `{{PREFIX}}RiskFactors.csv` factor table |

## What gets deployed

| Artifact | Where | Purpose |
|---|---|---|
| Risk index | `dataSource.name='risk'` | Append-only store of risk events, written via HEC (HTTP Event Collector), SentinelOne's HTTP ingest endpoint |
| Risk-factor table | `/datatables/<prefix>RiskFactors.csv` | Per-object score multipliers (analyst-editable) |
| Risk collector | Hyperautomation (scheduled) | Runs contributors, applies factors, publishes risk events |
| Incident rules (4) | `/cloud-detection/rules` (scheduled) | User + host, each a 24h cumulative-score rule and a 7d multi-tactic rule |
| RBA dashboard | `/dashboards/<prefix>-RBA` | Leaderboard, score over time, MITRE / contributor / threat-object breakdowns, timeline |
| Response flow (optional) | Hyperautomation (alert-triggered) | VirusTotal-gated containment off an RBA incident alert |

## How it works

Contributors are noisy-but-interesting behaviours (encoded PowerShell, recon bursts, LOLBin downloads,
log clearing, shadow-copy deletion, credential-access indicators) that are too common to alert on
individually. The collector runs each contributor on a schedule, scores it (`base_score`), amplifies
by the object's risk factor, tags it with MITRE tactic/technique and a threat object, and publishes it
as a risk event. The incident rules read the risk index and fire one alert per object when:

- **24h cumulative score** crosses a threshold (default user >= 50, host >= 40), catching fast, high-intensity attacks; or
- **7d distinct MITRE tactics** crosses a threshold (default user >= 4, host >= 3), catching low-and-slow campaigns.

## Run it with one prompt

- *"Deploy risk-based alerting on the Acme site"*
- *"Set up RBA: score encoded PowerShell, recon, LOLBins, log clearing, and credential access, and alert when a user accumulates enough risk"*
- *"Roll out RBA for users and hosts with asset-criticality risk factors"*

You only have to confirm scope and (optionally) the contributor set, thresholds, and risk-object
types. Everything else has a default. The skill previews the rendered config before deploying.

## Deploying the collector (important)

The collector is a Hyperautomation flow whose two HTTP actions need the **"SentinelOne SDL" (Bearer)**
connection, which cannot be bound through the API. The skill therefore deploys it as a **Shared
Draft**, then **prompts you to bind the connection in the console**, and only **activates** it after
you confirm. Once active it runs on its schedule (set it hourly for production); you can also run it
on demand to test.

## Tuning

`NT AUTHORITY\SYSTEM` and software-update tooling generate the most observations and will dominate the
leaderboard with benign noise. Factor those accounts down (multiplier < 1) or drop them from
contributors. RBA is a system you cultivate: adjust base scores, factors, and thresholds so genuinely
high-risk objects rise and benign noise stays below the line.

## Validated

Validated on `Okta`-style EDR telemetry (2026-06-25): risk index stood up via the ingest endpoint; a real contributor
produced well-formed risk events; a privileged user's risk factor amplified base 15 to 30; the
collector flow ran end to end (6/6 actions, ~2.9s) and published clean risk events; and the user
24h-cumulative incident rule fired a real HIGH UAM alert on an object at score 60 against a threshold
of 50.

Full execution detail is in the Claude-facing playbook,
[`skills/sdl-solutions/references/risk-based-alerting.md`](../../skills/sdl-solutions/references/risk-based-alerting.md).
For the detection-rule mechanics see [detection-rule-types.md](../detection-rule-types.md) and
[detection-asset-binding.md](../detection-asset-binding.md).
