# Solution: UEBA behavioural anomaly detection

Take ANY signal already reaching the tenant, security or not, and detect behavioural anomalies
against a baseline the source builds from its own history. The solution baselines per
`(action, principal)` pair and surfaces ten classes of deviation across a core set (SPIKE, DROP,
SILENT, NEW-BEHAVIOR) and an advanced set (OFF-HOURS, FAN-OUT, RATIO, VELOCITY, PEER-GROUP, DORMANT). It is
source-agnostic: the principal and action fields are picked from whatever the source carries, so
EDR, identity, firewall, cloud audit, SaaS, email, healthcare, and custom apps all work without
per-source code.

You do not pick detections from a flat list of statistics. You start from a security use case, and
the solution maps that intent to the right detections, the data those detections need, and the right
scoring formula. Everything stays editable.

**No AI is involved, and there is nothing to bring your own of.** This deploys native SentinelOne
capabilities only: Singularity Data Lake baseline lookup tables, scheduled detection rules, Hyperautomation watchdog and refresh flows, and an SDL dashboard. The deployer (the interactive
Docker UI) is a thin configuration layer that builds those
artifacts and creates them through the documented SentinelOne management and SDL APIs. There is no
model, no LLM, and no bring-your-own-AI to wire up. If you can reach your console with an API token,
you can deploy.

## Features

- **Source-agnostic**: baselines ANY security or non-security signal; the source is identified by `dataSource.name` or `serverHost` (some sources are only findable by one), and the principal and action fields are auto-picked from the source schema, so EDR, identity, firewall, cloud, SaaS, email, and custom apps work with no per-source code. The action can be a **composite key** (2-3 fields combined) for higher-fidelity pairs.
- **Ten detections**: four core (SPIKE, DROP, SILENT, NEW-BEHAVIOR) plus six advanced analytics (OFF-HOURS, FAN-OUT, RATIO, VELOCITY, PEER-GROUP, DORMANT), plus two optional location-based (geo) detections (GEO-NEW, IMPOSSIBLE-TRAVEL) when a location field is set.
- **Risk-Based Alerting (RBA)**: consolidates alerts into one cumulative risk score per entity (user or host) over the alert stream, scored by an editable, MITRE-tagged RiskWeights table with an optional critical-asset multiplier watchlist; fires one alert per entity over a threshold. The biggest lever on alert fatigue.
- **Use-case driven**: choose what you are defending against; the solution pre-selects the detections, the data they need, and the scoring method.
- **Two scoring methods**: Robust (percentile p95/p05, the default, resists bursty and skewed volume) and Standard (z-score on mean and standard deviation). The method is a config knob, not a separate detection.
- **Per (action, principal) baseline**: mean, standard deviation, median, p95, and p05 over a 7/30/90-day window, computed in one pass. Optional day-of-week stratification removes weekday/weekend false positives.
- **How you deploy**: an interactive Docker UI drives one deploy engine (no AI); a full deploy is baseline lookups + scheduled rules + watchdog flows + nightly refresh + dashboard.
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
| Account takeover (geo) | Compromised credentials with a location signal | Identity / auth as above, plus a location field (IP, ISO country, or `lat,lon`) | GEO-NEW, IMPOSSIBLE-TRAVEL, OFF-HOURS, SPIKE | Robust |
| Brute force | Password spray / stuffing | Auth source with a success / failure outcome field (IdP, VPN, RADIUS, OS security logs) | RATIO, VELOCITY, SPIKE | Robust |
| Insider threat / data exfiltration | Staging and theft | Activity with an object / target field to count breadth (file path, bucket, host, repo): DLP, cloud storage, file / SaaS audit | FAN-OUT, PEER-GROUP, SPIKE, OFF-HOURS | Robust |
| Lateral movement | East-west spread | Telemetry with a destination host / IP field (EDR network events, firewall, multi-host auth) | FAN-OUT, PEER-GROUP, NEW-BEHAVIOR, SPIKE | Robust |
| Privilege abuse | Misuse of granted rights | Admin / audit events with an action field (cloud control plane, IAM audit, directory admin actions) | NEW-BEHAVIOR, OFF-HOURS, SPIKE | Robust |
| Service / feed health | Broken pipeline / disabled integration | Any high-volume machine or service source (log feed, service account, integration) | SILENT, DROP | Standard (stable, roughly-normal volume) |
| Custom | Anything | Any source | Manual, the full matrix (all ten behavioural detections, the two geo detections, and RBA) | Your choice |

Keep all ten detections available rather than trimming to a shortlist. Coverage across the use
cases above needs them all: a brute-force use case needs RATIO, an insider-threat use case needs
FAN-OUT. The use case, not a reduced catalog, is what keeps the choice simple, it hides the
statistics behind intent. Robust is the default method for every human-behaviour use case because
security volume is skewed; Standard fits the service / feed-health case where a machine source emits
stable, roughly-normal volume.

The two geo detections layer onto any use case once a location field is set (the "Account takeover
(geo)" preset selects them directly). RBA is cross-cutting rather than tied to one threat: it
consolidates whatever detections you deploy into a per-entity risk score, and is included in the All
preset and selectable under Custom.

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
| PEER-GROUP | One account does far more of an action than everyone else doing it, invisible to a self-baseline (e.g. a service account always high) | per-action population cohort of per-principal daily volume; fire when 24h count exceeds the cohort p95 by a multiple (default 3x). By default no identity or HR attributes are used; if ISPM is configured, the peer group can optionally be sourced from the SentinelOne Asset Inventory Member Of (directory group membership) | T1078 / T1021 | scheduled detection |
| DORMANT | An account idle 60 days suddenly authenticates | last-seen per pair, anti-join vs live-active with age over N days | T1078 | Hyperautomation watchdog |
| GEO-NEW | A user who only ever signs in from the US authenticates from a brand-new country | per-principal usual-location baseline (ISO country via `geo_ip_country_iso`, or the location field directly); fire when a live location has no baseline row (first-seen geography) | T1078 | scheduled detection |
| IMPOSSIBLE-TRAVEL | The same credential appears in two distant places too close together in time | self-join per principal over the window; `geo_distance(geo_ip_location(ipA), geo_ip_location(ipB)) / hours` exceeds a km/h threshold (default 900), above a minimum hop distance (default 100 km) | T1078 / T1021 | Hyperautomation watchdog |
| RBA | Alert fatigue: many independent alerts, no single view of which entity is actually risky | scores the alert stream against an editable RiskWeights table (title-substring match to a base score, single-scan nested ternary), sums per entity as `weighted risk = sum(distinct alert-type scores) x max asset multiplier`, fires over a threshold | n/a (consolidation) | Hyperautomation watchdog |

GEO-NEW and IMPOSSIBLE-TRAVEL are optional and appear only when a **location field** is set. GEO-NEW is a
scheduled detection over its own usual-location baseline. IMPOSSIBLE-TRAVEL, like SILENT and DORMANT, runs
as a Hyperautomation watchdog because the self-join it needs is unavailable in the scheduled engine; it
requires coordinates, so it is offered only in IP or coordinate mode. Its guards, `geo_is_point()` on both
points, a minimum-distance floor (which also discards the `geo_distance` `-1` unresolved sentinel), and
optional proxy/Tor exclusion, keep private/unknown IPs and VPN egress from producing false hops.

SILENT and DORMANT run as Hyperautomation watchdogs, not scheduled rules, because the scheduled-detection
engine runs over an aggregated data layer, where operators like `left join` and `dataset` are not
available. Those operators are what enumerate the absent / zero-event pairs (a pair present in the
baseline but with no events in the live window) by anti-joining the live counts against the baseline
table. So each watchdog runs the anti-join as a full LRQ instead and posts one uniform OCSF alert per run.

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

## How you run it

Two entry points share one deploy engine, and neither uses AI:

- **Interactive UI**: run the container, open the local page, connect with your console URL and API
  token, pick a source, pick a security use case (or All), and click Enable. Each artifact deploys
  with a live progress log. See the user guide in the s1-ueba-deployer repository for a screenshot walkthrough.
- **Headless CLI / CI**: `deploy_cli.py` (and the bundled GitHub Actions workflow) run the same deploy
  engine non-interactively from a parameter file or environment variables, for repeatable or
  pipeline-driven rollouts.

You only have to name the source (and, for a site deploy, the site). Everything else has a default:
30-day baseline, Robust method, top-500 pairs, hourly cadence, Medium/High severities per detection.
A use case preselects the right detections; `all` deploys the full set at once (the ten behavioural
detections, plus the two location detections when a location field is set, plus RBA); `custom` lets
you pick by hand.

**Two steps are intentionally not zero-touch.** Scheduled detections deploy **Disabled** so you can
review before enabling, and the watchdog and refresh flows import needing the "SentinelOne SDL"
(Bearer) connection bound before activation. The deployer does both when you provide the connection;
it does not silently enable a detection or run a flow without the connection in place.

## What you choose

| Choice | Default | Notes |
|---|---|---|
| Source | (required) | any source, matched by `dataSource.name` or `serverHost`, security or not |
| Use case | (drives the rest) | pre-selects detections + method + the data needed |
| Detections | per use case | any subset of the ten behavioural detections, the two location detections, and RBA; Custom exposes the full manual matrix |
| Scoring method | Robust | Robust (percentile) or Standard (z-score) |
| Baseline window | 30 days | 7 quick/noisy, 30 the sweet spot, 90 for monthly seasonality |
| Z threshold (Standard) | 3.0 | only used when method is Standard |

Fields each detection keys on are auto-derived from schema discovery and shown in the preview, one
click default, one field to override, never a raw query:

- FAN-OUT: the fan-out field to count breadth on (e.g. `dst.ip.address`, `tgt.file.path`).
- RATIO: the failure predicate (e.g. `outcome = 'FAILURE'`).
- OFF-HOURS: the quiet window (default 00:00 to 05:00 UTC).
- DORMANT: the dormancy threshold in days (default 30).
- Location (geo): the field carrying an IP, ISO country, or `lat,lon`; unlocks GEO-NEW and IMPOSSIBLE-TRAVEL.
- Composite action: optionally combine 2-3 action fields into one higher-fidelity `(principal, action)` key.
- RBA: the editable risk-score table (per alert-title match), the alert threshold (default 6), and an optional critical-asset multiplier watchlist.

## What gets deployed (production mode)

| Artifact | Where | Purpose |
|---|---|---|
| Core baseline lookup | `<prefix><source>Baseline` (datatable) | mean, stddev, median, p95, p05 per pair; joined by SPIKE, DROP, NEW-BEHAVIOR, and the SILENT watchdog |
| Advanced baseline lookups | `<prefix><source>Baseline{OffHours,Fanout,Ratio,Velocity,Peer,Dormant}`, plus `<prefix><source>GeoBaseline` when a location field is set | one per advanced detection selected |
| Scheduled rules | `/web/api/v2.1/cloud-detection/rules` (scheduled PowerQuery/S1QL, queryLang 2.0) | SPIKE, DROP, NEW-BEHAVIOR, OFF-HOURS, FAN-OUT, RATIO, VELOCITY, PEER-GROUP, and GEO-NEW (when geo is set); join the lookup, score, bind the principal entity |
| Watchdog flows | Hyperautomation | SILENT, DORMANT, IMPOSSIBLE-TRAVEL (when geo is set), and RBA; anti-join / self-join / alert-stream LRQ, each posting one OCSF alert per run |
| Refresh workflow | Hyperautomation (nightly) | rebuilds every baseline lookup over the trailing window |
| RiskWeights + AssetWatchlist | `<prefix><source>{RiskWeights,AssetWatchlist}` (datatables) | RBA base scores per alert-title match, and the optional critical-asset multiplier watchlist |
| Dashboard | `/dashboards/<prefix> <source> Anomalies` | tabbed review: Overview, Deployed, one tab per detection, plus a Location tab (when geo is set) and a Risk (RBA) tab |

Each advanced baseline lookup must finish before its rule deploys, the rule validator rejects a rule
whose lookup table does not yet exist, so the deploy builds the table (polling up to 300s) and then
creates the rule.

### Dashboard data-source scope (All Data vs XDR)

The review dashboard mixes two kinds of panel. Most detection tabs read source telemetry, which is XDR-attributed, so they render under either scope. The **Risk (RBA)** tab reads the SentinelOne alert stream and the RiskWeights/AssetWatchlist config datatables, and the **SILENT** watchdog tab (plus, for ingest-health, the **Devices** tab) reads a datatable via `| dataset`. Both the alert stream and config datatables live in the native store, not the XDR view, so those tabs return no data under the **XDR** scope. Select the **All Data** source (top-left) to view the full dashboard; each affected tab carries an in-panel reminder, and the dashboard description repeats it.

## Per-analytic reference (exact deployed queries)

Tokens: `<src>` data source, `<pr>` principal field, `<ac>` action field, `<ip>` the location field
(geo detections), `<prefix><src>Baseline` the core lookup name, `<fanout_field>` and
`<failure_predicate>` the two overridable inputs. Robust variants are shown; the Standard variant
swaps the final `filter` to the z-score form noted under each. `| nolimit` appears only on the
baseline savelookup (it raises the LRQ scan cap), never in a rule body.

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

### PEER-GROUP baseline + rule (Robust: `filter live_count > peer_p95 * 3`; Standard: `filter z >= Z`)

The cohort is per action: the baseline averages each principal's daily volume, then takes the mean, stddev, and p95 across all principals doing that action. The rule flags a principal doing far more of the action than the cohort.

```
dataSource.name = '<src>' | nolimit | filter <pr> = * AND <ac> = * | group day_count = count() by day = timebucket('1d'), action_v = <ac>, principal_v = <pr> | group pp_avg = avg(day_count) by action_v, principal_v | group peer_avg = avg(pp_avg), peer_stddev = stddev(pp_avg), peer_p95 = p95(pp_avg), n_principals = count() by action_v | filter n_principals >= 3 | sort -peer_p95 | limit 500 | savelookup '<prefix><src>BaselinePeer'
```
```
dataSource.name = '<src>' | filter <pr> = * AND <ac> = * | group live_count = count() by action_v = <ac>, principal_v = <pr> | lookup peer_avg = peer_avg, peer_stddev = peer_stddev, peer_p95 = peer_p95, n_principals = n_principals from <prefix><src>BaselinePeer by action_v = action_v | filter peer_avg = * | let sd = number(peer_stddev) | let z = (live_count - peer_avg) / sd | filter live_count > peer_p95 * 3 | let direction = 'PEER-GROUP' | sort -live_count | columns principal_v, action_v, live_count, peer_avg, peer_p95, n_principals, z, direction | limit 100
```

### GEO-NEW baseline + rule (first-seen geography; requires a location field)

The baseline records every location a principal has been seen from; the rule flags a principal active now from a location with no baseline entry. In `ip` mode the location is normalised in-query to an ISO country via `geo_ip_country_iso`; `country` / `coord` modes substitute the location expression.

```
dataSource.name = '<src>' | nolimit | filter <pr> = * AND <ip> = * | let loc_v = geo_ip_country_iso(<ip>) | filter loc_v = * AND loc_v != 'null' AND loc_v != 'null,null' | group loc_count = count() by principal_v = <pr>, loc_v | sort -loc_count | limit 5000 | savelookup '<prefix><src>GeoBaseline'
```
```
dataSource.name = '<src>' | filter <pr> = * AND <ip> = * | let loc_v = geo_ip_country_iso(<ip>) | filter loc_v = * AND loc_v != 'null' AND loc_v != 'null,null' | group live_count = count() by principal_v = <pr>, loc_v | lookup loc_count = loc_count from <prefix><src>GeoBaseline by principal_v = principal_v, loc_v = loc_v | filter !(loc_count = *) | let direction = 'GEO-NEW' | sort -live_count | columns principal_v, loc_v, live_count, direction | limit 100
```

### IMPOSSIBLE-TRAVEL self-join (Hyperautomation watchdog; requires an IP or coordinate location field)

A self-join per principal over the window: for each pair of events, compute the great-circle distance and the elapsed hours, then flag any hop faster than the km/h threshold (default 900) above a minimum distance (default 100 km).

```
| join a = ( dataSource.name = '<src>' <pr>=* <ip>=* | let pa = geo_ip_location(<ip>) | filter geo_is_point(pa) | columns principal_a = <pr>, ta = timestamp, pa ), b = ( dataSource.name = '<src>' <pr>=* <ip>=* | let pb = geo_ip_location(<ip>) | filter geo_is_point(pb) | columns principal_b = <pr>, tb = timestamp, pb ) on a.principal_a = b.principal_b | filter tb > ta | let km = geo_distance(pa, pb, 'kilometer') | filter km > 100 | let hours = number(tb - ta) / 3600000000000 | filter hours > 0 | let kmh = km / hours | filter kmh > 900 | group max_kmh = max(kmh), max_km = max(km), hops = count() by principal_v = principal_a | sort -max_kmh | columns principal_v, max_kmh, max_km, hops | limit 200
```

### RBA per-entity scoring (Hyperautomation watchdog over the alert stream)

RBA scores the SentinelOne alert stream against the editable `<prefix><src>RiskWeights` table in a single scan: one nested-ternary branch per RiskWeights row maps an alert-title substring to a base score (the branches below are the pre-seeded UEBA detections). Scores accumulate per entity (`resources[*].name`, a user or host); the watchdog fires one alert per entity at or above the threshold (default 6). With an asset watchlist, `asset_mult` becomes `max(multiplier)` over matching `<prefix><src>AssetWatchlist` branches and `weighted_risk = base_risk * asset_mult`.

```
dataSource.name='alert' class_uid=99602001 | let mt = (finding_info.title contains:anycase("anomaly SPIKE") ? 'anomaly SPIKE' : (finding_info.title contains:anycase("anomaly DROP") ? 'anomaly DROP' : (finding_info.title contains:anycase("NEW-BEHAVIOR") ? 'NEW-BEHAVIOR' : (finding_info.title contains:anycase("OFF-HOURS") ? 'OFF-HOURS' : (finding_info.title contains:anycase("FAN-OUT") ? 'FAN-OUT' : (finding_info.title contains:anycase("failure-RATIO") ? 'failure-RATIO' : (finding_info.title contains:anycase("VELOCITY burst") ? 'VELOCITY burst' : (finding_info.title contains:anycase("PEER-GROUP") ? 'PEER-GROUP' : (finding_info.title contains:anycase("GEO-NEW") ? 'GEO-NEW' : (finding_info.title contains:anycase("anomaly SILENT") ? 'anomaly SILENT' : (finding_info.title contains:anycase("anomaly DORMANT") ? 'anomaly DORMANT' : (finding_info.title contains:anycase("IMPOSSIBLE-TRAVEL") ? 'IMPOSSIBLE-TRAVEL' : '')))))))))))) | let sc = (finding_info.title contains:anycase("anomaly SPIKE") ? number(4) : (finding_info.title contains:anycase("anomaly DROP") ? number(2) : (finding_info.title contains:anycase("NEW-BEHAVIOR") ? number(1) : (finding_info.title contains:anycase("OFF-HOURS") ? number(2) : (finding_info.title contains:anycase("FAN-OUT") ? number(4) : (finding_info.title contains:anycase("failure-RATIO") ? number(4) : (finding_info.title contains:anycase("VELOCITY burst") ? number(4) : (finding_info.title contains:anycase("PEER-GROUP") ? number(2) : (finding_info.title contains:anycase("GEO-NEW") ? number(3) : (finding_info.title contains:anycase("anomaly SILENT") ? number(2) : (finding_info.title contains:anycase("anomaly DORMANT") ? number(2) : (finding_info.title contains:anycase("IMPOSSIBLE-TRAVEL") ? number(5) : number(0))))))))))))) | filter sc > 0 | group th = count() by entity = resources[*].name, mt, sc | group base_risk = sum(sc), types = count(), alerts = sum(th) by entity | let asset_mult = number(1) | let weighted_risk = base_risk * asset_mult | filter weighted_risk >= 6 | sort -weighted_risk | columns entity, weighted_risk, base_risk, asset_mult, types, alerts | limit 200
```

### RBA per-alert scoring (dashboard "Calculated risk per alert")

```
dataSource.name='alert' class_uid=99602001 | let sc = (finding_info.title contains:anycase("anomaly SPIKE") ? number(4) : (finding_info.title contains:anycase("anomaly DROP") ? number(2) : (finding_info.title contains:anycase("NEW-BEHAVIOR") ? number(1) : (finding_info.title contains:anycase("OFF-HOURS") ? number(2) : (finding_info.title contains:anycase("FAN-OUT") ? number(4) : (finding_info.title contains:anycase("failure-RATIO") ? number(4) : (finding_info.title contains:anycase("VELOCITY burst") ? number(4) : (finding_info.title contains:anycase("PEER-GROUP") ? number(2) : (finding_info.title contains:anycase("GEO-NEW") ? number(3) : (finding_info.title contains:anycase("anomaly SILENT") ? number(2) : (finding_info.title contains:anycase("anomaly DORMANT") ? number(2) : (finding_info.title contains:anycase("IMPOSSIBLE-TRAVEL") ? number(5) : number(0))))))))))))) | filter sc > 0 | group hits = count() by title = finding_info.title, base_score = sc | let alert_risk = hits * base_score | sort -alert_risk | columns title, base_score, hits, alert_risk | limit 100
```

## Beyond volume: what needs more data (Tier 2 / Tier 3)

These detections are valuable but need signals a single source does not always carry. The path is
clear once the data is present:

- **Peer-group baselining**: compare a user to their department, role, or site peers, not just their own history. Needs a peer/role attribute per principal (identity or asset-inventory enrichment joined onto the event), then the same test keyed on the cohort mean.
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

- Scheduled rules run PowerQuery/S1QL 2.0 and support `estimate_distinct(x)`, `count(<predicate>)` as a conditional count, `max(x)`, `median(x)`, `p95(x)`, `pct(N, x)`, `newest(ts)`, and `strftime(event.time, '%H')` as an hour-of-day group key. `percentile(x, N)` returns HTTP 500, use `p95` / `p10` / etc.
- Cast the standard deviation with `number()` before dividing in the z computation. SDL columns can be type-locked to string, and `number()` returns 0 for null and avoids NaN.
- SILENT and DORMANT cannot be scheduled rules (the scheduled engine runs on an aggregated data layer, without `left join` / `dataset`); they run as Hyperautomation anti-join watchdogs that post one stitched OCSF alert.
- The scoring method is a config knob, not a detection: the baseline stores `median`, `p95`, and `pct(5, x)` alongside `avg` and `stddev` in one pass, so switching method needs no rebuild.
- Each advanced detection uses its own suffixed baseline table, and that savelookup must finish before the rule deploys (poll up to 300s).
