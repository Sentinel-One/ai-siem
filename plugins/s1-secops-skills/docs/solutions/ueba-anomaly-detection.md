# Solution: UEBA behavioural anomaly detection

Take ANY signal already reaching the tenant, security or not, and detect behavioural anomalies
against a baseline the source builds from its own history. The solution baselines per
`(action, principal)` pair and surfaces nine classes of deviation across a core set (SPIKE, DROP,
SILENT, NEW-BEHAVIOR) and an advanced set (OFF-HOURS, FAN-OUT, RATIO, VELOCITY, DORMANT). It is
source-agnostic: the principal and action fields are picked from whatever the source carries, so
EDR, identity, firewall, cloud audit, SaaS, email, healthcare, and custom apps all work without
per-source code.

You do not pick detections from a flat list of statistics. You start from a security use case, and
the solution maps that intent to the right detections, the data those detections need, and the right
scoring formula. Everything stays editable.

This is part of the `sentinelone-sdl-solutions` skill. It orchestrates the primitive skills
(`sentinelone-mgmt-console-api` for the engine and detection rules, `sentinelone-powerquery` for the
baseline queries, `sentinelone-hyperautomation` for the watchdog and nightly refresh flows,
`sentinelone-sdl-dashboard` for the dashboard); it does not reimplement them.

## Features

- **Source-agnostic**: baselines ANY security or non-security signal; the principal and action fields are auto-picked from the source schema, so EDR, identity, firewall, cloud, SaaS, email, and custom apps work with no per-source code.
- **Ten detections**: four core (SPIKE, DROP, SILENT, NEW-BEHAVIOR) plus six advanced analytics (OFF-HOURS, FAN-OUT, RATIO, VELOCITY, PEER-GROUP, DORMANT).
- **Use-case driven**: choose what you are defending against; the solution pre-selects the detections, the data they need, and the scoring method.
- **Two scoring methods**: Robust (percentile p95/p05, the default, resists bursty and skewed volume) and Standard (z-score on mean and standard deviation). The method is a config knob, not a separate detection.
- **Per (action, principal) baseline**: mean, standard deviation, median, p95, and p05 over a 7/30/90-day window, computed in one pass. Optional day-of-week stratification removes weekday/weekend false positives.
- **Two ways to run**: an interactive on-demand report for hunts and tuning, or a production deploy (baseline lookups + scheduled rules + watchdog flows + nightly refresh + dashboard).
- **Asset-bound alerts**: scheduled rules map the principal entity so every anomaly is attributable to a real user or host.

## Start from the security use case

A use case tells you two things at once: which detections catch it, and which data you must already
be ingesting. A detection can only run if its source carries the one field it keys on, so the sound
order to reason in is:

**intent (use case) -> data sources required -> detections those sources can feed -> scoring method.**

Data sources are a prerequisite, not a consequence. The solution enforces this: selecting a use case
sets the detections and the method, and per-detection schema checks flag any analytic whose required
field the chosen source does not carry, so the chain is verified at deploy time rather than assumed.

| Use case | Defends against | Data sources needed | Detections | Method |
|---|---|---|---|---|
| Account takeover | Compromised credentials | Identity / auth (Okta, Entra ID, Active Directory, Duo, Ping): user principal, sign-in / action field, event timestamp | OFF-HOURS, DORMANT, VELOCITY, SPIKE | Robust |
| Brute force | Password spray / stuffing | Auth source with a success / failure outcome field (IdP, VPN, RADIUS, OS security logs) | RATIO, VELOCITY, SPIKE | Robust |
| Insider threat / data exfiltration | Staging and theft | Activity with an object / target field to count breadth (file path, bucket, host, repo): DLP, cloud storage, file / SaaS audit | FAN-OUT, PEER-GROUP, SPIKE, OFF-HOURS | Robust |
| Lateral movement | East-west spread | Telemetry with a destination host / IP field (EDR network events, firewall, multi-host auth) | FAN-OUT, PEER-GROUP, NEW-BEHAVIOR, SPIKE | Robust |
| Privilege abuse | Misuse of granted rights | Admin / audit events with an action field (cloud control plane, IAM audit, directory admin actions) | NEW-BEHAVIOR, OFF-HOURS, SPIKE | Robust |
| Service / feed health | Broken pipeline / disabled integration | Any high-volume machine or service source (log feed, service account, integration) | SILENT, DROP | Standard (stable, roughly-normal volume) |
| All | Everything | Any source | All ten | Robust |
| Custom | Anything | Any source | Manual (all ten) | Your choice |

Keep all ten detections available rather than trimming to a shortlist. Coverage across the use
cases above needs them all: a brute-force use case needs RATIO, an insider-threat use case needs
FAN-OUT. The use case, not a reduced catalog, is what keeps the choice simple, it hides the
statistics behind intent. Robust is the default method for every human-behaviour use case because
security volume is skewed; Standard fits the service / feed-health case where a machine source emits
stable, roughly-normal volume.

## Detection catalog

Each detection baselines per `(action, principal)` pair (FAN-OUT baselines per principal), then
compares the live 24h window to that baseline. The security example is what fires it; the logic is
how it decides.

| Detection | Security example (when it fires) | Logic | MITRE | Mechanism |
|---|---|---|---|---|
| SPIKE | An account's activity jumps far above its norm | 24h count vs baseline; fire on `> p95` (Robust) or `z >= Z` (Standard) | T1078 | scheduled detection |
| DROP | Activity falls off a cliff but is not zero | 24h count vs baseline; fire on `< p05` (Robust) or `z <= -Z` (Standard) | T1078 | scheduled detection |
| SILENT | A reliable feed or service account goes completely quiet | anti-join: a baseline-active pair with zero live events | T1078 | Hyperautomation watchdog |
| NEW-BEHAVIOR | An account does something it has never done | active in 24h with no baseline entry | T1204 | scheduled detection |
| OFF-HOURS | A 9-to-5 account signs in at 3am or over the weekend | per-(action, principal, hour) baseline; fire when the quiet-window count beats its own off-hours p95 | T1078 | scheduled detection |
| FAN-OUT | A user who normally hits 5 hosts a day suddenly hits 500 | daily `estimate_distinct(target)` per principal vs baseline | T1021 / T1046 / T1039 | scheduled detection |
| RATIO | Failed attempts spike inside otherwise-normal volume | daily `fails/total` per pair vs baseline | T1110 | scheduled detection |
| VELOCITY | A burst that a daily average hides (stuffing, mass export in minutes) | peak hourly count per pair vs baseline | T1110.003 / T1048 | scheduled detection |
| PEER-GROUP | One account does far more of an action than everyone else doing it, invisible to a self-baseline (e.g. a service account always high) | per-action population cohort of per-principal daily volume; fire when 24h count exceeds the cohort p95 by a multiple (default 3x). No identity/HR attributes needed | T1078 / T1021 | scheduled detection |
| DORMANT | An account idle 60 days suddenly authenticates | last-seen per pair, anti-join vs live-active with age over N days | T1078 | Hyperautomation watchdog |

SILENT and DORMANT run as Hyperautomation watchdogs, not scheduled rules, because the scheduled-rule
engine cannot enumerate zero-event pairs and rejects `left join` / `dataset`. Each watchdog runs the
anti-join as an LRQ and posts one uniform OCSF alert per run.

## Optional: ISPM-sourced peer groups

By default PEER-GROUP's cohort is the population that performs an action. Optionally the peer group can
instead be a real directory group, sourced from the ISPM Asset Inventory `Member Of`, and used to build
the baseline. Read identity assets with `| datasource assets from 'surface/identity'`: `userPrincipalName`
is the reliable join key (present on every user; `samAccountName` for AD, `emailAddress` is sparse), and
`memberOf` is a stringified JSON array of group display names (e.g. `["U.S. Sales","Sales and Marketing",
"Mark 8 Project Team",...]`).

Use a lookup, not raw-log enrichment: snapshot the inventory to a datatable with `savelookup`, then
`lookup` it at detection time and refresh it on the nightly baseline job (enrichment needs a pipeline
stage plus a re-ingest and is only as fresh as the pipeline). Define a named group by substring
(`memberOf contains:anycase('Sales')`), no JSON parsing required; or explode the array into one
`(principal, group)` row each to baseline every group automatically.

```
# 1. members of a named group, snapshot from ISPM assets
| datasource assets from 'surface/identity'
| filter userPrincipalName = * AND memberOf contains:anycase('Sales')
| columns principal_key = userPrincipalName
| savelookup '<prefix>SalesPeers'

# 2. per-group baseline (cohort = the group's members), keyed by principal
dataSource.name='<src>' <principal>=* <action>=*
| group day_count = count() by day=timebucket('1d'), principal_v=<principal>
| lookup principal_key = principal_key from <prefix>SalesPeers by principal_v = principal_key
| group pp_avg = avg(day_count) by principal_v
| group peer_avg=avg(pp_avg), peer_stddev=stddev(pp_avg), peer_p95=p95(pp_avg), n=count()
| savelookup '<prefix>SalesPeerBaseline'
```

The detection then looks up the user's group-cohort stats and fires on `live_count > peer_p95 * mult`,
the same shape as the population cohort. The source's principal must resolve to `userPrincipalName`
(Okta/Entra emit UPN/email; AD event logs may emit `samAccountName`, key the lookup on that instead).


## Choosing the scoring method

SPIKE, DROP, and the advanced volume detections score the live window against the baseline. Two
methods are available, chosen once per deployment:

| Method | Baseline stat | Fires when (SPIKE / DROP) | Best for |
|---|---|---|---|
| Robust (default) | `median`, `p95`, `pct(5, x)` | live `> p95` / live `< p05` | bursty or skewed volume, most real security data |
| Standard | `avg`, `stddev` | `z >= Z` / `z <= -Z` | stable, roughly-normal volume (machine and service feeds) |

Robust is the default because a single busy day inflates the standard deviation, so a z-score lets
real anomalies score low and quiet pairs score high. Percentiles resist that outlier pull. The
baseline stores both sets of statistics in the same pass, so switching method needs no rebuild. Day-
of-week stratification is a separate, orthogonal option that buckets each pair per weekday to remove
the weekend false positive; it applies under either method.

## Run it with one prompt

- *"Deploy UEBA for account takeover on Okta"* (use case drives the detections and method)
- *"Run a behavioural baseline on Okta and tell me what's anomalous"*
- *"Set up brute-force detection on our VPN logs"*
- *"Watch our file audit source for data exfiltration behaviour"*
- *"Baseline our Google Workspace audit logs and flag spikes"*
- *"Deploy UEBA for Okta on the Acme site, 30-day baseline, Robust method, with a nightly refresh and dashboard"* (fully specified: skips the questions)

**Short or detailed, both work.** You only have to name the source (and, for production, the site).
Everything else has a default: 30-day baseline, Robust method, top-500 pairs, 02:00 UTC refresh,
Medium/High severities per detection. The skill collects anything missing in one short question set
and previews the rendered config before deploying.

**Two steps are intentionally not zero-touch.** Scheduled rules deploy **Disabled** (enable after a
quick review), and the watchdog and refresh flows import needing the "SentinelOne SDL" (Bearer)
connection bound before activation. The skill does both on request; it does not silently enable a
detection or run a flow without the connection in place.

## Two ways to run it

| Mode | What you get | Use when |
|---|---|---|
| Interactive / on-demand | A report for a source, computed now from a 7 or 30-day baseline | A hunt, an investigation, or tuning thresholds before deploying |
| Production / always-on | Persisted baseline lookups, scheduled detection rules, watchdog flows, a nightly refresh, and a dashboard | Continuous monitoring of a source |

## What you choose

| Choice | Default | Notes |
|---|---|---|
| Source | (required) | any `dataSource.name`, security or not |
| Use case | (drives the rest) | pre-selects detections + method + the data needed |
| Detections | per use case | any subset of the ten; Custom exposes the full manual matrix |
| Scoring method | Robust | Robust (percentile) or Standard (z-score) |
| Baseline window | 30 days | 7 quick/noisy, 30 the sweet spot, 90 for monthly seasonality |
| Z threshold (Standard) | 3.0 | only used when method is Standard |

Fields each detection keys on are auto-derived from schema discovery and shown in the preview, one
click default, one field to override, never a raw query:

- FAN-OUT: the fan-out field to count breadth on (e.g. `dst.ip.address`, `tgt.file.path`).
- RATIO: the failure predicate (e.g. `outcome = 'FAILURE'`).
- OFF-HOURS: the quiet window (default 00:00 to 05:00 UTC).
- DORMANT: the dormancy threshold in days (default 30).

## What gets deployed (production mode)

| Artifact | Where | Purpose |
|---|---|---|
| Core baseline lookup | `<prefix><source>Baseline` (datatable) | mean, stddev, median, p95, p05 per pair; joined by SPIKE, DROP, NEW-BEHAVIOR, and the SILENT watchdog |
| Advanced baseline lookups | `<prefix><source>Baseline{OffHours,Fanout,Ratio,Velocity,Dormant}` | one per advanced detection selected |
| Scheduled rules | `/web/api/v2.1/cloud-detection/rules` (scheduled PowerQuery, queryLang 2.0) | SPIKE, DROP, NEW-BEHAVIOR, OFF-HOURS, FAN-OUT, RATIO, VELOCITY; join the lookup, score, bind the principal entity |
| Watchdog flows | Hyperautomation | SILENT and DORMANT anti-join LRQ, each posting one OCSF alert per run |
| Refresh workflow | Hyperautomation (nightly) | rebuilds every baseline lookup over the trailing window |
| Dashboard | `/dashboards/<prefix> <source> Anomalies` | anomaly count, volume over time, top SPIKE/DROP, silent pairs, busiest principals |

Each advanced baseline lookup must finish before its rule deploys, the rule validator rejects a rule
whose lookup table does not yet exist, so the deploy builds the table (polling up to 300s) and then
creates the rule.

## Per-analytic reference (exact deployed queries)

Tokens: `<src>` data source, `<pr>` principal field, `<ac>` action field,
`<prefix><src>Baseline` the core lookup name, `<fanout_field>` and `<failure_predicate>` the two
overridable inputs. Robust variants are shown; the Standard variant swaps the final `filter` to the
z-score form noted under each. `| nolimit` appears only on the baseline savelookup (it raises the
LRQ scan cap), never in a rule body.

### Core baseline (feeds SPIKE, DROP, NEW-BEHAVIOR, SILENT)

```
dataSource.name = '<src>' | nolimit | filter <pr> = * AND <ac> = * | group day_count = count() by day = timebucket('1d'), action_v = <ac>, principal_v = <pr> | group baseline_avg = avg(day_count), baseline_stddev = stddev(day_count), baseline_med = median(day_count), baseline_p95 = p95(day_count), baseline_p05 = pct(5, day_count), n_days = count() by action_v, principal_v | filter n_days >= 2 AND baseline_stddev > 0 | sort -baseline_avg | limit 500 | savelookup '<prefix><src>Baseline'
```

### SPIKE (Robust: `filter live_count > baseline_p95`; Standard: `filter z >= Z`)

```
dataSource.name = '<src>' | filter <pr> = * AND <ac> = * | group live_count = count() by action_v = <ac>, principal_v = <pr> | lookup baseline_avg = baseline_avg, baseline_stddev = baseline_stddev, baseline_p95 = baseline_p95, baseline_p05 = baseline_p05, n_days = n_days from <prefix><src>Baseline by action_v = action_v, principal_v = principal_v | filter baseline_avg = * | let z = (live_count - baseline_avg) / baseline_stddev | filter live_count > baseline_p95 | let direction = 'SPIKE' | sort -z | columns principal_v, action_v, live_count, baseline_avg, baseline_stddev, z, direction | limit 100
```

### DROP (Robust: `filter live_count < baseline_p05`; Standard: `filter z <= -Z`)

```
dataSource.name = '<src>' | filter <pr> = * AND <ac> = * | group live_count = count() by action_v = <ac>, principal_v = <pr> | lookup baseline_avg = baseline_avg, baseline_stddev = baseline_stddev, baseline_p95 = baseline_p95, baseline_p05 = baseline_p05, n_days = n_days from <prefix><src>Baseline by action_v = action_v, principal_v = principal_v | filter baseline_avg = * | let z = (live_count - baseline_avg) / baseline_stddev | filter live_count < baseline_p05 | let direction = 'DROP' | sort z | columns principal_v, action_v, live_count, baseline_avg, baseline_stddev, z, direction | limit 100
```

### NEW-BEHAVIOR (active now, no baseline entry)

```
dataSource.name = '<src>' | filter <pr> = * AND <ac> = * | group live_count = count() by action_v = <ac>, principal_v = <pr> | lookup baseline_avg = baseline_avg from <prefix><src>Baseline by action_v = action_v, principal_v = principal_v | filter !(baseline_avg = *) | sort -live_count | columns principal_v, action_v, live_count | limit 100
```

### SILENT anti-join (Hyperautomation watchdog)

```
| left join a = ( | dataset 'config://datatables/<prefix><src>Baseline' | columns action_v, principal_v, baseline_avg, baseline_stddev ), b = ( dataSource.name='<src>' <pr>=* <ac>=* | group live_count=count() by action_v=<ac>, principal_v=<pr> ) on a.action_v = b.action_v, a.principal_v = b.principal_v | let lc = number(live_count) | let z = (lc - baseline_avg) / baseline_stddev | filter baseline_avg >= 5 | filter lc == 0 | filter z <= -2.5 | let direction = 'SILENT' | sort z | columns principal_v, action_v, baseline_avg, baseline_stddev, z, direction | limit 200
```

### OFF-HOURS baseline + rule (Robust: `filter live_oh > oh_p95`; Standard: `filter z >= Z`)

```
dataSource.name = '<src>' | nolimit | filter <pr> = * AND <ac> = * | let hod = strftime(event.time, '%H') | filter hod >= '00' AND hod < '05' | group day_count = count() by day = timebucket('1d'), action_v = <ac>, principal_v = <pr> | group oh_avg = avg(day_count), oh_stddev = stddev(day_count), oh_p95 = p95(day_count), n_days = count() by action_v, principal_v | filter n_days >= 2 | sort -oh_avg | limit 500 | savelookup '<prefix><src>BaselineOffHours'
```
```
dataSource.name = '<src>' | filter <pr> = * AND <ac> = * | let hod = strftime(event.time, '%H') | filter hod >= '00' AND hod < '05' | group live_oh = count() by action_v = <ac>, principal_v = <pr> | lookup oh_avg = oh_avg, oh_stddev = oh_stddev, oh_p95 = oh_p95 from <prefix><src>BaselineOffHours by action_v = action_v, principal_v = principal_v | filter oh_avg = * | let sd = number(oh_stddev) | let z = (live_oh - oh_avg) / sd | filter live_oh > oh_p95 | let direction = 'OFF-HOURS' | sort -live_oh | columns principal_v, action_v, live_oh, oh_avg, oh_p95, z, direction | limit 100
```

### FAN-OUT baseline + rule (Robust: `filter live_distinct > fo_p95`; Standard: `filter z >= Z`)

```
dataSource.name = '<src>' | nolimit | filter <pr> = * AND <fanout_field> = * | group d = estimate_distinct(<fanout_field>) by day = timebucket('1d'), principal_v = <pr> | group fo_avg = avg(d), fo_stddev = stddev(d), fo_p95 = p95(d), n_days = count() by principal_v | filter n_days >= 2 | sort -fo_avg | limit 500 | savelookup '<prefix><src>BaselineFanout'
```
```
dataSource.name = '<src>' | filter <pr> = * AND <fanout_field> = * | group live_distinct = estimate_distinct(<fanout_field>) by principal_v = <pr> | lookup fo_avg = fo_avg, fo_stddev = fo_stddev, fo_p95 = fo_p95 from <prefix><src>BaselineFanout by principal_v = principal_v | filter fo_avg = * | let sd = number(fo_stddev) | let z = (live_distinct - fo_avg) / sd | filter live_distinct > fo_p95 | let direction = 'FAN-OUT' | sort -live_distinct | columns principal_v, live_distinct, fo_avg, fo_p95, z, direction | limit 100
```

### RATIO baseline + rule (Robust: `filter live_r > rt_p95`; Standard: `filter z >= Z`)

```
dataSource.name = '<src>' | nolimit | filter <pr> = * AND <ac> = * | group total = count(), fails = count(<failure_predicate>) by day = timebucket('1d'), action_v = <ac>, principal_v = <pr> | filter total >= 5 | let r = fails / total | group rt_avg = avg(r), rt_stddev = stddev(r), rt_p95 = p95(r), n_days = count() by action_v, principal_v | filter n_days >= 2 | sort -rt_avg | limit 500 | savelookup '<prefix><src>BaselineRatio'
```
```
dataSource.name = '<src>' | filter <pr> = * AND <ac> = * | group total = count(), fails = count(<failure_predicate>) by action_v = <ac>, principal_v = <pr> | filter total >= 5 | let live_r = fails / total | lookup rt_avg = rt_avg, rt_stddev = rt_stddev, rt_p95 = rt_p95 from <prefix><src>BaselineRatio by action_v = action_v, principal_v = principal_v | filter rt_avg = * | let sd = number(rt_stddev) | let z = (live_r - rt_avg) / sd | filter live_r > rt_p95 | let direction = 'RATIO' | sort -live_r | columns principal_v, action_v, total, fails, live_r, rt_avg, rt_p95, z, direction | limit 100
```

### VELOCITY baseline + rule (Robust: `filter live_peak > vel_p95`; Standard: `filter z >= Z`)

```
dataSource.name = '<src>' | nolimit | filter <pr> = * AND <ac> = * | group h = count() by day = timebucket('1d'), hour = timebucket('1h'), action_v = <ac>, principal_v = <pr> | group peak = max(h) by day, action_v, principal_v | group vel_avg = avg(peak), vel_stddev = stddev(peak), vel_p95 = p95(peak), n_days = count() by action_v, principal_v | filter n_days >= 2 | sort -vel_avg | limit 500 | savelookup '<prefix><src>BaselineVelocity'
```
```
dataSource.name = '<src>' | filter <pr> = * AND <ac> = * | group live_h = count() by hour = timebucket('1h'), action_v = <ac>, principal_v = <pr> | group live_peak = max(live_h) by action_v, principal_v | lookup vel_avg = vel_avg, vel_stddev = vel_stddev, vel_p95 = vel_p95 from <prefix><src>BaselineVelocity by action_v = action_v, principal_v = principal_v | filter vel_avg = * | let sd = number(vel_stddev) | let z = (live_peak - vel_avg) / sd | filter live_peak > vel_p95 | let direction = 'VELOCITY' | sort -live_peak | columns principal_v, action_v, live_peak, vel_avg, vel_p95, z, direction | limit 100
```

### DORMANT baseline + anti-join (Hyperautomation watchdog)

```
dataSource.name = '<src>' | nolimit | filter <pr> = * AND <ac> = * | group last_ms = newest(event.time), total = count() by action_v = <ac>, principal_v = <pr> | filter total >= 5 | sort -last_ms | limit 500 | savelookup '<prefix><src>BaselineDormant'
```
```
| left join a = ( | dataset 'config://datatables/<prefix><src>BaselineDormant' | columns action_v, principal_v, last_ms ), b = ( dataSource.name='<src>' <pr>=* <ac>=* | group live_count=count() by action_v=<ac>, principal_v=<pr> ) on a.action_v = b.action_v, a.principal_v = b.principal_v | let lc = number(live_count) | let last_n = number(last_ms) | let age_days = ({{Function.DATETIME_TO_MS(Function.DATETIME_NOW())}} - last_n) / 86400000 | filter lc > 0 | filter age_days >= 30 | let direction = 'DORMANT' | sort -age_days | columns principal_v, action_v, last_ms, age_days, direction | limit 200
```

The DORMANT watchdog injects the current epoch-ms as `{{Function.DATETIME_TO_MS(Function.DATETIME_NOW())}}`
from the Hyperautomation flow, so no PowerQuery `now()` is required.

## Beyond volume: what needs more data (Tier 2 / Tier 3)

These detections are valuable but need signals a single source does not always carry. The path is
clear once the data is present:

- **Peer-group baselining**: shipped as the PEER-GROUP detection (population cohort per action). An optional identity-attribute mode, the group taken from the ISPM Asset Inventory `Member Of`, is documented above under "Optional: ISPM-sourced peer groups".
- **Geo-velocity / impossible travel**: two authentications from distant geographies inside a short window. Needs geo-IP (country or lat/long) on the auth event; runs as a Hyperautomation LRQ join, like the SILENT watchdog.
- **Privilege / scope-change detection**: first-time admin action, new group or role membership. Needs IAM / audit events (role assignment, group add) in the lake.
- **Sequence / risk-combo detection**: high-risk action chains (MFA disable, then password change, then mass download) by one principal in a window. Needs sessionization or ordered-event correlation, best expressed as a Hyperautomation flow.
- **Risk-based alerting**: instead of each detection firing independently, publish a per-signal risk score, accumulate per entity over a rolling window with decay, and raise one high-confidence alert when the cumulative score crosses a threshold. Needs a risk-event stream and the accumulation layer. This is the natural consolidation step and the biggest lever on alert fatigue.

## The baseline_anomaly.py pipeline (interactive / CLI)

The interactive mode is a source-agnostic pipeline at
`sentinelone-mgmt-console-api/scripts/baseline_anomaly.py`. For any `dataSource.name` it:

1. **Auto-discovers the schema** via `inspect_source.discover_schema()` and picks `principal_field` (user / host / IP / role) and `action_field` (event.type / activity_name / action) from what the source actually carries, with no per-source hardcoding.
2. **Slices the baseline window into N daily LRQ queries** (default 30 days), running 3 in parallel under the per-user 3 rps cap. Daily slicing avoids the LRQ per-call deadline that single 7d/30d aggregates routinely exceed.
3. **Runs one 24h live slice** in the same shape.
4. **Merges client-side** with one of two strategies: `pooled` (all daily samples in one bucket per pair) or `dow` (a separate bucket per pair per day-of-week, which removes the weekday/weekend false positive and is the production tier).
5. **Surfaces the anomaly classes** every run: matched deviations (SPIKE/DROP), silent pairs, and new-behaviour pairs.

CLI:

```bash
# Auto-discover principal/action, 30-day DoW-stratified baseline
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

## Why this matters

Failure modes a basic moving-average baseline misses, and this solution catches:

- **Silent pairs are dropped by a basic two-side join.** A critical account active every weekday and silent today never enters the join output. The SILENT watchdog walks the baseline keys explicitly to surface them.
- **A single busy day breaks the z-score.** One spike inflates the standard deviation, so real anomalies score low and quiet pairs score high. The Robust method scores against percentiles instead, which resist the outlier.
- **Pooled baselines flag every weekend.** A pooled baseline with 22 weekday and 8 weekend samples produces a high stddev, so on a Sunday every weekday-only pair looks anomalous. Day-of-week stratification makes the comparison apples-to-apples.
- **One-size-fits-all fields do not work.** Okta uses `actor.user.email_addr`, CloudTrail uses `actor.user.name` (role), FortiGate uses `device.name` or `src.ip.address`. Schema discovery picks the right principal, action, fan-out, and failure fields per source.

## Implementation notes

- Scheduled rules run PowerQuery 2.0 and support `estimate_distinct(x)`, `count(<predicate>)` as a conditional count, `max(x)`, `median(x)`, `p95(x)`, `pct(N, x)`, `newest(ts)`, and `strftime(event.time, '%H')` as an hour-of-day group key. `percentile(x, N)` returns HTTP 500, use `p95` / `p10` / etc.
- Cast the standard deviation with `number()` before dividing in the z computation. SDL columns can be type-locked to string, and `number()` returns 0 for null and avoids NaN.
- SILENT and DORMANT cannot be scheduled rules (the engine rejects `left join` / `dataset`); they run as Hyperautomation anti-join watchdogs that post one stitched OCSF alert.
- The scoring method is a config knob, not a detection: the baseline stores `median`, `p95`, and `pct(5, x)` alongside `avg` and `stddev` in one pass, so switching method needs no rebuild.
- Each advanced detection uses its own suffixed baseline table, and that savelookup must finish before the rule deploys (poll up to 300s).

## Detection gotchas (validated)

- **DROP / SILENT use a rolling 24h window** (`lookbackWindowMinutes=1440`): the low/zero pair's normal history must sit entirely older than 24h, or activity from the last day inside the window masks the drop/silence. A midnight-to-now test window hides this; test over a true rolling 24h.
- **Constant-count pairs are excluded from the baseline** (`filter baseline_stddev > 0`): a pair whose daily counts never vary gets no baseline row, so SPIKE / DROP / SILENT cannot score it. Real data has day-to-day variance; synthetic test data must add it.
