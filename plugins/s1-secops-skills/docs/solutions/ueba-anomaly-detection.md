# Solution: UEBA behavioural anomaly detection

Take ANY signal already reaching the tenant, security or not, and detect behavioural anomalies
against a baseline the source builds from its own history. The solution baselines per
`(action, principal)` pair, scores the live window with a z-score, and surfaces four classes of
deviation: SPIKE, DROP, SILENT (a pair that went quiet), and NEW-BEHAVIOR (a pair never seen in the
baseline). It is source-agnostic: the principal and action fields are picked from whatever the
source carries, so EDR, identity, firewall, cloud audit, SaaS, email, healthcare, and custom apps
all work without per-source code.

This is part of the `sentinelone-sdl-solutions` skill. It orchestrates the primitive skills
(`sentinelone-mgmt-console-api` for the engine and detection rule, `sentinelone-powerquery` for the
baseline queries, `sentinelone-hyperautomation` for the nightly refresh, `sentinelone-sdl-dashboard`
for the dashboard); it does not reimplement them.

## Features

- **Source-agnostic**: baselines ANY security or non-security signal; the principal and action fields are auto-picked from the source schema, so EDR, identity, firewall, cloud, SaaS, email, and custom apps work with no per-source code.
- **Four deviation classes**: SPIKE, DROP, SILENT (a normally-active pair went quiet), and NEW-BEHAVIOR (a first-seen pair).
- **Per (action, principal) z-score baseline**: mean and standard deviation over a 7/30/90-day window, day-of-week stratified to remove weekday/weekend false positives.
- **Two ways to run**: an interactive on-demand report for hunts and tuning, or a production deploy (baseline lookup + scheduled PowerQuery rule + nightly refresh + dashboard).
- **Tiered alerting**: hard/soft z thresholds route page vs triage vs dashboard-only; SILENT and NEW-BEHAVIOR are routed separately with their own floors.
- **Asset-bound alerts**: the scheduled rule maps the principal entity so anomalies are attributable to a real user/host.

## Run it with one prompt

- *"Run a behavioural baseline on Okta and tell me what's anomalous"*
- *"Deploy UEBA anomaly detection for FortiGate on the Acme site"*
- *"Baseline our Google Workspace audit logs and flag spikes"*
- *"Monitor the Avelios Medical app for unusual user behaviour"*
- *"Find users whose activity today is way off their 30-day normal"*
- *"Deploy UEBA anomaly detection for Okta on the Acme site, 7-day pooled baseline, z >= 3, with a nightly refresh and dashboard"* (fully specified: spells out the optional parameters so the skill skips the questions)

**Short or detailed, both work.** You only have to name the source (and, for production, the site).
Everything else has a default: 30-day day-of-week baseline, z >= 3 hard / 2 soft, top-500 pairs,
02:00 UTC refresh, Medium severity. The skill collects anything missing in one short question set
and previews the rendered config before deploying, so a one-line prompt triggers the same full
build; spelling out the parameters just skips the questions and overrides defaults.

**Two steps are intentionally not zero-touch.** The detection rule deploys **Disabled** (enable it
after a quick review), and the nightly refresh flow imports as a **draft** that needs the
"SentinelOne SDL" (Bearer) connection bound before it is activated. The skill does both on request;
it does not silently enable a detection or run a flow without the connection in place.

## Two ways to run it

| Mode | What you get | Use when |
|---|---|---|
| Interactive / on-demand | A SPIKE/DROP/SILENT/NEW report for a source, computed now from a 7 or 30-day baseline | A hunt, an investigation, or tuning thresholds before deploying |
| Production / always-on | A persisted baseline lookup, a scheduled z-score detection rule, a nightly baseline refresh, and a UEBA dashboard | Continuous monitoring of a source |

## How it works

For each `(action, principal)` pair the solution counts events per day across the baseline window,
computes the mean and standard deviation, then scores the live 24h window with
`z = (live - mean) / stddev`. The detection cadence matches the baseline unit (daily baseline, 24h
live window, daily rule). Four signal classes come out:

| Class | Meaning | Typical routing |
|---|---|---|
| SPIKE | live volume far above normal (`z >= hard`) | auto-alert |
| DROP | live volume far below normal (`z <= -hard`) | auto-alert / triage |
| SILENT | a normally-active pair with zero events now | separate lower-urgency rule, with a floor |
| NEW-BEHAVIOR | a pair active now with no baseline | baseline-curation queue, not an outright alert |

## What you choose

| Choice | Default | Notes |
|---|---|---|
| Source | (required) | any `dataSource.name`, security or not |
| Strategy | `dow` | `pooled` (one bucket per pair) or day-of-week stratified (removes weekday/weekend false positives) |
| Baseline window | 30 days | 7 quick/noisy, 30 the sweet spot, 90 for monthly seasonality |
| Z threshold | hard 3.0 / soft 2.0 | tier alerting: page vs triage vs dashboard-only |

Principal and action fields, the noise filter, the lookup table name, the top-K cap, and the live
window are auto-derived from schema discovery and shown in the preview, not prompted.

## What gets deployed (production mode)

| Artifact | Where | Purpose |
|---|---|---|
| Baseline lookup table | `<prefix><source>Baseline` (datatable) | mean + stddev per pair, joined by the rule and dashboard |
| Detection rule | `/web/api/v2.1/cloud-detection/rules` (scheduled PowerQuery) | joins the lookup, computes z, alerts on `|z| >= hard`, binds the principal |
| Refresh workflow | Hyperautomation (nightly) | rebuilds the baseline lookup over the trailing window |
| Dashboard | `/dashboards/<prefix> <source> Anomalies` | anomaly count, new-behaviour, volume over time, top SPIKE/DROP and new-behaviour tables |

## The baseline_anomaly.py pipeline (interactive / CLI)

The interactive mode is a source-agnostic pipeline at
`sentinelone-mgmt-console-api/scripts/baseline_anomaly.py`. For any `dataSource.name` it:

1. **Auto-discovers the schema** via `inspect_source.discover_schema()` and picks `principal_field` (user / host / IP / role) and `action_field` (event.type / activity_name / action) from what the source actually carries, with no per-source hardcoding.
2. **Slices the baseline window into N daily LRQ queries** (default 30 days), running 3 in parallel under the per-user 3 rps cap. Each slice produces (action, principal, count) rows for that day. Daily slicing avoids the LRQ per-call deadline that single 7d/30d aggregates routinely exceed.
3. **Runs one 24h live slice** in the same shape.
4. **Merges client-side** with one of two strategies: `pooled` (all daily samples in one bucket per pair; simple, but flags weekend silence as anomalous) or `dow` (a separate bucket per pair per day-of-week; removes the weekday/weekend false positive cleanly, and is the production tier).
5. **Surfaces three anomaly classes** every run: matched z-score deviations (SPIKE/DROP), silent pairs (active in baseline, zero live), and new-behaviour pairs (live, no baseline at all; routed to a separate triage queue).

CLI:

```bash
# Auto-discover principal/action, 30-day DoW-stratified baseline, default Z=2.0
python sentinelone-mgmt-console-api/scripts/baseline_anomaly.py --source "Okta"

# Network source: auto-discover picks device.name + event.type
python sentinelone-mgmt-console-api/scripts/baseline_anomaly.py --source "FortiGate" --days 14

# Override fields if you know better
python sentinelone-mgmt-console-api/scripts/baseline_anomaly.py --source "Zscaler Internet Access" \
    --principal src.ip.address --action unmapped.action

# Pooled (no DoW stratification) and a tighter threshold
python sentinelone-mgmt-console-api/scripts/baseline_anomaly.py --source "CloudTrail" \
    --stratify pooled --z 3.0
```

State is checkpointed to `<plugin>/baselines/baseline_anomaly_<slug>_state.json` so the script is
resumable across short shell budgets; final results land in `baseline_anomaly_<slug>_result.json`.

In a Cowork chat session, just ask (the PowerQuery skill delegates to mgmt-console-api automatically):

```
Build a 30-day behavioural baseline for Okta and show me anomalies for today.
Find users behaving differently from their typical pattern across all SaaS sources.
Run anomaly detection on FortiGate: which devices have unusual traffic today vs the last two weeks?
Which CloudTrail roles are silent today that were active every day last week?
```

## Why this matters

Three production failure modes a basic moving-average baseline misses, and this pipeline catches:

- **Silent pairs are dropped by the basic two-side join.** A critical account active every weekday and silent today never enters the join output. The pipeline walks the baseline keys explicitly to surface them.
- **Pooled baselines flag every weekend.** A 30-day pooled baseline with 22 weekday + 8 weekend samples produces a high stddev, so on a Sunday every weekday-only pair looks anomalous. Day-of-week stratification makes the comparison apples-to-apples.
- **One-size-fits-all principal field does not work.** Okta uses `actor.user.email_addr`, CloudTrail uses `actor.user.name` (role), FortiGate uses `device.name` or `src.ip.address`, SentinelOne uses `src.process.user`. The schema-discovery step picks the right one per source.

## Productionising as a STAR / PowerQuery Alert rule

For a recurring detection rather than ad-hoc, the production pattern persists the baseline and reads it at detection time:

1. Schedule a Hyperautomation workflow nightly to run the daily slices and write the DoW-stratified baseline to a config-managed lookup table via `| savelookup '<source>_baseline_dow', 'merge'`.
2. Author a PowerQuery Alert / scheduled rule body that runs the live query, joins the baseline table via `| lookup`, and filters on `(live_count - avg) / sd >= 3.0 OR <= -3.0`.
3. Tier the threshold: `|z| >= 3.0` for auto-page, `|z| >= 2.0` for analyst review queue, with separate paths for silent and new-behaviour pairs.

Full PQ building blocks and the rule-body shape are in
`sentinelone-powerquery/examples/behavioral-baselines.md`.

## Validated

Validated on `Okta` (2026-06-18): a 7-day baseline lookup `uebaOktaBaseline`
(172 pairs, n_days up to 8) was built by a single `savelookup` LRQ that completed server-side even
after the interactive wrapper reported a 30s poll timeout. Detection scored live traffic against it
and returned a robust SPIKE (`john.doe@example.com` / Other, z 7.08), identical to the engine, plus
a new-behaviour cluster around a first-seen identity that logged in, hit the admin app, and minted an
API token. Source-agnostic key-picking confirmed on Okta (security), Google Workspace (SaaS), and
Avelios Medical (custom healthcare). For windows too large for one query, the engine slices per day
over LRQ and merges client-side.
