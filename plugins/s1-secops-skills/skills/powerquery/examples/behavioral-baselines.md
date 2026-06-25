# Behavioural baselining — statistical anomaly detection in PowerQuery

Recipes for building per-(principal, action) behavioural baselines and
detecting deviations from them. Source-agnostic — works on EDR, identity,
network, cloud, email, or any custom log source ingested into SDL.

For the runner, the source schema discovery, and the productionised
end-to-end script, use `mgmt-console-api`'s
`scripts/baseline_anomaly.py`. This document is the PQ building blocks.

## The pattern in one paragraph

For each `(principal, action)` pair, count how many events occurred per
day across a baseline window (e.g. 7 or 30 days). Compute moving-average
and standard deviation per pair. At detection time, count the same pairs
in a live window (e.g. last 24h). Compute `z = (live - avg) / stddev`.
Flag any pair where `|z|` exceeds a threshold (typically 2.0). Three
extensions improve precision: stratify the baseline by day-of-week,
detect pairs that went *silent* in the live window, and flag pairs
seen in live but never in the baseline window (new behaviour).

## Picking principal and action fields by source category

The "principal" is whoever the events are attributed to — user, host,
IP, role, account. The "action" is what they did — event type, API
call, command, status. Both vary per source. Pick from what the source
actually carries — schema discovery via `inspect_source.discover_schema()`
in the mgmt-console-api skill picks these for you. Common defaults:

| Source category | Typical principal | Typical action | Coalesce-style fallback |
|---|---|---|---|
| Identity (Okta, Azure AD) | `actor.user.email_addr` | `event.type` or `activity_name` | `actor.user.email_addr ? actor.user.email_addr : actor.user.name` |
| Email security (Mimecast) | `actor.user.email_addr` | `event.type` | same |
| Cloud audit (CloudTrail, GCP, M365) | `actor.user.name` (role / account) | `event.type` | `actor.user.email_addr ? actor.user.email_addr : actor.user.name` |
| SaaS productivity (Google Workspace, M365) | `actor.user.email_addr` | `event.type` | same |
| EDR (SentinelOne, Windows Event Logs) | `src.process.user` + `endpoint.name` | `event.type` | `actor.user.name ? actor.user.name : src.process.user` |
| Firewall / NDR (FortiGate, PAN, Zeek, Suricata) | `src.ip.address` or `device.name` | `unmapped.action` or `event.type` | `actor.user.name ? actor.user.name : src.ip.address` |
| Web proxy (Zscaler, Cloudflare) | `actor.user.email_addr` or `src.ip.address` | category / action | source-specific |
| AI security (Example Source, etc.) | `user` | `action` | source-specific (run schema discovery) |

When in doubt, run `python scripts/inspect_source.py --source "<name>" --window 24h`
from the mgmt-console-api skill. It returns `prim_key` and `action_key`
based on what the source actually populates.

## Building block 1 — per-day count slice

Run this once per baseline day. Each call produces one row per
`(action, principal)` pair seen on that day, with `day_count`. Replace
the bracketed placeholders.

```
dataSource.name = '<source>'
| let action = <action_field> ? <action_field> : <action_fallback>
| let principal = <principal_field> ? <principal_field> : <principal_fallback>
| filter action = * AND principal = *
| group day_count = count() by action, principal
| sort -day_count
| limit 5000
```

Set `startTime` / `endTime` on the LRQ call to a single 24h window.
For a 7-day baseline run this 7 times; for 30-day, 30 times. Run up to
3 in parallel — per-user 3 req/sec rate cap is the binding constraint.
See `references/lrq-api.md` in this skill for the slicing strategy.

**Why slice rather than aggregate inside the query:** a single 7d (let
alone 30d) aggregate frequently exceeds the LRQ per-call deadline on
busy data sources. Daily slicing keeps every call comfortably under
the budget AND makes the per-day counts available for the
client-side merge that follows.

## Building block 2 — live count

Same shape, single 24h window ending at the detection moment.

```
dataSource.name = '<source>'
| let action = <action_field> ? <action_field> : <action_fallback>
| let principal = <principal_field> ? <principal_field> : <principal_fallback>
| filter action = * AND principal = *
| group live_count = count() by action, principal
| sort -live_count
| limit 5000
```

## Building block 3 — pooled baseline merge (Python pseudocode)

After collecting daily slices, compute mean + stddev per pair across
all observed days. Pairs with fewer than 2 active days are dropped
(stddev undefined). Pairs with stddev=0 (perfectly stable) are also
dropped — every deviation is anomalous, but `z = ∞` isn't a useful
threshold.

```python
from collections import defaultdict
from statistics import mean, stdev

per_day = defaultdict(list)   # (action, principal) -> [count for each active day]
for daily_slice in baseline_slices:
    for r in daily_slice["rows"]:
        per_day[(r["action"], r["principal"])].append(r["day_count"])

baseline = {}
for key, counts in per_day.items():
    if len(counts) < 2: continue
    sd = stdev(counts)
    if sd <= 0: continue
    baseline[key] = {"avg": mean(counts), "sd": sd, "n_days": len(counts)}
```

Then for each live pair:

```python
Z_THRESHOLD = 2.0
anomalies = []
for r in live_rows:
    key = (r["action"], r["principal"])
    if key not in baseline:
        continue   # see new-behaviour detector below
    b = baseline[key]
    z = (r["live_count"] - b["avg"]) / b["sd"]
    if abs(z) >= Z_THRESHOLD:
        anomalies.append({**r, **b, "z_score": z,
                          "direction": "SPIKE" if z > 0 else "DROP"})
```

## Building block 4 — silent-pair detector

A pair active in baseline but with zero events in live is a silence
signal. The basic z-score formula handles this naturally: `(0 - avg) / sd`
is negative; if `avg/sd >= 2`, the pair is statistically silent. But the
join in block 3 silently drops missing pairs — so you need an explicit
walk over the baseline keys.

```python
silent = []
for key, b in baseline.items():
    if (key[0], key[1]) in {(r["action"], r["principal"]) for r in live_rows}:
        continue
    z = (0 - b["avg"]) / b["sd"]
    if abs(z) >= Z_THRESHOLD:
        silent.append({"action": key[0], "principal": key[1],
                       "live_count": 0, **b, "z_score": z,
                       "direction": "SILENT"})
```

In SOC terms: a critical user account that was active every weekday
but has zero events today — that's exactly the kind of insider-threat
or account-takeover signal Method 1 should surface, and the bare
two-side join misses it.

## Building block 5 — new-behaviour detector

A pair seen in live but with no baseline is "first observed in 7d/30d"
— could be a brand-new user, a fresh role being audited, a recon scan,
or a real attacker. Surface separately from z-score anomalies.

```python
new_behaviour = []
baseline_keys = set(baseline.keys())
for r in live_rows:
    key = (r["action"], r["principal"])
    if key not in baseline_keys:
        new_behaviour.append(r)
```

## Day-of-week stratification (production tier)

The pooled baseline pools weekday and weekend samples together — its
stddev reflects both, which means a Sunday with reduced activity gets
flagged as anomalous against a baseline averaged across 5 weekdays + 2
weekends. To eliminate the weekday/weekend false-positive, compute the
baseline per day-of-week.

```python
from datetime import datetime, timezone

# Group daily counts by (action, principal, day_of_week)
per_pair_dow = defaultdict(lambda: defaultdict(list))
sampled_dows = defaultdict(int)   # dow -> number of days of this dow in baseline window

for slice_label, daily_slice in baseline_slices:
    # slice_label encodes the day's date — extract the dow
    day_start = parse_iso_date(slice_label)
    dow = day_start.weekday()   # 0=Mon..6=Sun
    sampled_dows[dow] += 1
    for r in daily_slice["rows"]:
        key = (r["action"], r["principal"])
        per_pair_dow[key][dow].append(r["day_count"])

# Compute baseline per (pair, dow) — pad inactive sampled days with zeros
baseline_dow = {}
for key, by_dow in per_pair_dow.items():
    for dow, counts in by_dow.items():
        n_active = len(counts)
        n_sampled = sampled_dows[dow]
        full = counts + [0] * max(0, n_sampled - n_active)
        if len(full) < 2: continue
        sd = stdev(full)
        if sd <= 0: continue
        baseline_dow[(key[0], key[1], dow)] = {"avg": mean(full), "sd": sd,
                                               "n_active": n_active,
                                               "n_sampled": n_sampled}

# At detection time, the live window has its own day-of-week —
# only compare against the matching DoW baseline cell
live_dow = parse_iso_date(live_window_start).weekday()
for r in live_rows:
    key = (r["action"], r["principal"], live_dow)
    if key not in baseline_dow:
        # No DoW-specific baseline — emerging behaviour on this DoW
        continue
    b = baseline_dow[key]
    z = (r["live_count"] - b["avg"]) / b["sd"]
    ...
```

The padding step matters: if a (pair, DoW) cell had counts on 4 of 4
sampled Sundays and zero on the other 0 sampled Sundays, the avg is
`mean([c1, c2, c3, c4])`. If it had counts on 2 of 4 Sundays and zero
on 2, the avg is `mean([c1, c2, 0, 0])` — a tighter, more honest
representation. Without padding, the 2-of-4 case would look as
"reliably active" as the 4-of-4 case, which is wrong.

## Choosing a baseline window length

| Window | Sample size | Strength | Weakness |
|---|---|---|---|
| 7 days | 7 samples | Quick to compute, freshest signal | Stddev is noisy; bimodal weekday/weekend distributions look like normal variance |
| 30 days | 30 samples | Stable stddev; surfaces weekend false-positives clearly enough to motivate DoW stratification | Slower to compute (30 LRQ slices); slow-moving drift may be missed |
| 30 days + DoW stratification | up to 30 / 7 ≈ 4-5 per DoW cell | Right tool — eliminates the weekday/weekend false-positive cleanly | Cells with `n_sampled <= 1` per DoW have no usable baseline; those pairs need to fall through to the new-behaviour detector |
| 90 days | ~90 samples per DoW cell when stratified | Captures monthly seasonality and quarter-end spikes | More LRQ cost; baseline-write cadence becomes a job; consider `savelookup` and an incremental update path instead of full re-compute |

For most SOC use cases, 30 days + DoW stratification is the production
sweet spot. Run nightly via a Hyperautomation workflow, write the
stratified baseline to a config-managed lookup table via `savelookup`,
and reference it in a STAR / PowerQuery Alert rule body.

## Tier the threshold

Don't ship a single `|z| >= 2.0` everywhere. Different signal classes
deserve different routing:

| Tier | Z threshold | Detector | Routing |
|---|---|---|---|
| Hard alert | `|z| >= 3.0` | Pooled or DoW-stratified, whichever is in production | Auto-page; high precision, low recall |
| Soft alert / triage | `|z| >= 2.0` (DoW-stratified) | DoW-stratified preferred so weekend silences don't ping the queue | Tag for analyst review |
| Trend tuning | `|z| >= 1.0` | Pooled baseline | Analyst dashboard only — don't make this a rule |
| Silent-pair detector | `|z| >= 2.5` and `baseline_avg > <floor>` | DoW-stratified silent path | Separate rule; tune `<floor>` per source so noise pairs don't dominate |
| New-behaviour detector | n/a | New-behaviour detector | Separate rule; route to baseline-curation queue rather than alerting outright |

## Productionising as a STAR / PowerQuery Alert rule

The end-to-end production shape with persisted baselines:

1. **Schedule** a Hyperautomation workflow nightly (or every N hours) that:
   - Runs the per-day count slices for the previous N days
   - Computes baseline per (pair, DoW) client-side
   - Writes the baseline rows to a lookup table via `| savelookup '<source>_baseline_dow', 'merge'`
   - Lookup tables are capped at 400 KB — for high-cardinality sources, persist only the top-K pairs by baseline_avg

2. **Author the detection rule** as a PowerQuery Alert (`queryLang: "2.0"`,
   `queryType: "scheduled"`):

```
dataSource.name = '<source>'
| let action = <action_field> ? <action_field> : <action_fallback>
| let principal = <principal_field> ? <principal_field> : <principal_fallback>
| filter action = * AND principal = *
| group live_count = count() by action, principal
| lookup avg=baseline_avg, sd=baseline_stddev from <source>_baseline_dow by action, principal
| filter avg = *
| let z = (live_count - avg) / sd
| filter z >= 3.0 OR z <= -3.0
| sort -z
| limit 100
```

   For DoW stratification, include `dow = day_of_week(timestamp)` in the
   group-by AND in the lookup join key. The lookup table from step 1 must
   be keyed on `(action, principal, dow)` not just `(action, principal)`.

3. **Set rule constraints** — for `queryType: "scheduled"`,
   `treatAsThreat: "UNDEFINED"` and `networkQuarantine: false` are
   required. Use the alert severity field, not mitigation actions, to
   surface the verdict.

## Summary: when to reach for which tool in this skill family

| User asks for... | Use |
|---|---|
| "Write a baseline detection PQ" | This file (building blocks 1-5) — paste the placeholders into PQ templates |
| "Run a 30-day baseline for `<source>` end-to-end" | `mgmt-console-api` skill, `scripts/baseline_anomaly.py` |
| "What field should I baseline on?" | `mgmt-console-api`, `scripts/inspect_source.py --source "<name>"` |
| "Why does my baseline flag every Sunday?" | DoW stratification — section above |
| "Author this as a STAR rule body" | `references/detection-rules.md` in this skill, plus the lookup pattern in section "Productionising" |
