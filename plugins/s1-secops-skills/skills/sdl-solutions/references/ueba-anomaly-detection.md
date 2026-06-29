# Playbook: UEBA behavioural anomaly detection

Take ANY signal already reaching the tenant, security or non-security, and detect behavioural
anomalies against a baseline the source builds from its own history. The solution baselines
per `(action, principal)` pair, scores the live window with a z-score, and surfaces four classes
of deviation: SPIKE, DROP, SILENT (a pair that went quiet), and NEW-BEHAVIOR (a pair with no
baseline). It is source-agnostic: the principal and action fields are picked from whatever the
source actually carries, so EDR, identity, firewall, cloud audit, SaaS, email, healthcare, or a
custom app all work without per-source code.

This playbook orchestrates primitives that already exist; it does not reimplement them:

- The engine is `mgmt-console-api` `scripts/baseline_anomaly.py`, a resumable,
  source-agnostic baseline + z-score detector (schema discovery, daily slicing, pooled or
  day-of-week strategy, SPIKE/DROP/SILENT/NEW output, checkpointed state).
- The PowerQuery building blocks (per-day count, live count, pooled and DoW merges, silent and
  new-behaviour detectors, the productionised lookup pattern) are in `powerquery`
  `examples/behavioral-baselines.md`. Read it before authoring any baseline query by hand.
- Field selection is `mgmt-console-api` `scripts/inspect_source.py` (`pick_keys`).

## What "anomaly detection over a specified baseline" means here

For each `(action, principal)` pair, count events per day across a baseline window (default 30
days). Compute mean and standard deviation per pair. At detection time, count the same pairs over
a live window of the same unit length (24h) and compute `z = (live - mean) / stddev`. Flag pairs
where `|z|` crosses a threshold. The detection cadence MUST match the baseline unit: the baseline
is per-day counts, so the live window and the rule interval are both 24h. This is the single most
common mistake, an hourly rule against a daily baseline compares one hour to a full day.

## Two ways to run it

1. **Interactive / on-demand (investigate now).** Run `baseline_anomaly.py` against a source and
   read the SPIKE/DROP/SILENT/NEW report. Use for a hunt, an investigation, a one-off "is anything
   off on `<source>` today", or to choose thresholds before productionising. This is the most
   accurate path: it does zero-padded day-of-week stddev that a single server-side query cannot.
2. **Production (always-on).** Persist the baseline as a lookup table, deploy a scheduled
   PowerQuery detection rule that joins it and alerts on `|z|`, schedule a nightly Hyperautomation
   refresh of the baseline, and deploy a UEBA dashboard. Use when the source should be monitored
   continuously. The four artifacts are the templates in `assets/`.

Ask the user which they want if it is not obvious. "Run a baseline on `<source>`" is interactive;
"deploy UEBA / monitor `<source>` for anomalies" is production.

## Prompts (one compact set, everything else defaulted)

- **Required: the source.** `dataSource.name` to baseline. If the user did not name it, enumerate
  sources and ask. Works on any source, security or not.
- **Optional, single-select: baseline strategy (default `dow`).** `pooled` (one bucket per pair) or
  `dow` (one bucket per pair per day-of-week, removes the weekday/weekend false positive). For the
  production lookup, `pooled` is the clean server-side form; `dow` is best via the engine.
- **Optional: baseline window (default 30 days).** 7 quick and noisy, 30 the production sweet spot,
  90 captures monthly seasonality at higher query cost.
- **Optional: z threshold (default hard 3.0, soft 2.0).** Tier it: hard `|z|>=3.0` auto-alert,
  soft `|z|>=2.0` triage, silent path `|z|>=2.5` with a baseline-average floor, new-behaviour routed
  to a curation queue rather than alerted outright.
- **Production only, optional: site, schedule hour, severity, prefix.** Resolve the site name to a
  siteId. Default refresh 02:00 UTC, severity Medium, prefix a short solution/customer code.

Auto-derived, do NOT prompt (state in the preview): principal and action fields (schema discovery,
overridable), the noise filter (for example `(tag != 'logVolume' OR !(tag = *))` on sources that
carry volume-accounting rows like Google Workspace), the baseline table name
`{{PREFIX}}{{SOURCE_SLUG}}Baseline`, top-K cap (default 500), and the live window (24h).

## Parameters and tokens

| Token | Meaning | Default |
|---|---|---|
| `{{PREFIX}}` | solution / customer code prefix | `ueba` |
| `{{SOURCE}}` | `dataSource.name` to baseline | (required) |
| `{{SOURCE_SLUG}}` | source name slugged for the table | derived |
| `{{PRINCIPAL}}` | principal field (user / host / IP / role) | schema discovery |
| `{{ACTION}}` | action field (event type / activity / status) | schema discovery |
| `{{NOISE_FILTER}}` | filter to drop accounting noise | `` (or logVolume filter) |
| `{{BASELINE_TABLE}}` | lookup table name | `{{PREFIX}}{{SOURCE_SLUG}}Baseline` |
| `{{BASELINE_DAYS}}` / `{{BASELINE_HOURS}}` | baseline window | 30 / 720 |
| `{{STRATIFY}}` | `pooled` or `dow` | `dow` (engine) / `pooled` (lookup) |
| `{{Z_HARD}}` / `{{Z_SOFT}}` | z thresholds | 3.0 / 2.0 |
| `{{TOPK}}` | top pairs kept in the lookup | 500 |
| `{{LIVE_LABEL}}` | live window label | `24h` |
| `{{SCHEDULE_HOUR}}` | nightly refresh hour UTC | 2 |
| `{{SEVERITY}}` | rule severity | Medium |
| `{{RENOTIFY_MINUTES}}` | per-entity re-alert suppression | 1440 |
| `{{SCOPE_KEY}}` / `{{SCOPE_ID}}` | `accountIds`/`siteIds` + id | site |
| `{{SITE_ID}}` | site for HA import | (resolved) |
| `{{MITRE_TACTIC}}` / `{{MITRE_TECHNIQUE}}` | optional ATT&CK tag | source-dependent |

## Step 1: pick principal and action

If the user did not pass them, discover the schema and let `pick_keys` choose:

```
python scripts/inspect_source.py --source "{{SOURCE}}"
```

It returns `prim_key` (principal) and `action_key` from what the source populates. Confirmed picks
from tenant validation: Okta -> `actor.user.email_addr` / `activity_name`; Google Workspace ->
`actor.user.email_addr` / `event.type` (drop `logVolume`); Avelios Medical (custom healthcare) ->
`actorUsername` / `event_type`; FortiGate -> `device.name` / `event.type`. The caller can override
either with `--principal` / `--action`. Show the picked fields in the preview before running.

## Step 2 (interactive): run the engine

```
python scripts/baseline_anomaly.py --source "{{SOURCE}}" --days {{BASELINE_DAYS}} --stratify {{STRATIFY}} --z {{Z_HARD}}
# resumable: re-invoke until "all phases complete"; then:
python scripts/baseline_anomaly.py --source "{{SOURCE}}" report --z {{Z_HARD}}
```

State and results checkpoint to `baselines/baseline_anomaly_<slug>_state.json` and `_result.json`,
so the run survives short shell budgets. Report the three classes back to the user: matched
SPIKE/DROP (by `|z|`), silent pairs, and new-behaviour pairs. This is the path to use for an
investigation or to tune thresholds before deploying a rule.

## Step 3 (production): build the baseline lookup

Render `assets/ueba_baseline_savelookup.pq` and run it through the LRQ runner over the baseline
window. It computes the pooled per-pair mean and stddev server-side in one query and persists
`{{BASELINE_TABLE}}`. Verify with a readback before deploying the rule:

```
dataSource.name='{{SOURCE}}' {{NOISE_FILTER}} | filter {{PRINCIPAL}}=* AND {{ACTION}}=* | group live_count=count() by action_v={{ACTION}}, principal_v={{PRINCIPAL}} | lookup baseline_avg=baseline_avg from {{BASELINE_TABLE}} by action_v=action_v, principal_v=principal_v | filter baseline_avg=* | limit 5
```

LRQ note: this builder runs as one Long-Range Query (LRQ), executed server-side. An interactive
client such as the `powerquery_run` wrapper may stop polling after ~30s and report a timeout, but
the LRQ keeps running and the savelookup still persists. Validated 2026-06-18: the 7-day Okta build
wrote the table (172 pairs, n_days up to 8) AFTER the wrapper timed out, and the detection then
scored live traffic against that 7-day baseline. The nightly refresh workflow only launches this
LRQ, so 7 to 30-day windows build fine. Split only when a single windowed query exceeds the LRQ max
runtime on a very busy or high-cardinality source: run per-day LRQ slices and merge client-side via
`baseline_anomaly.py` (the engine does exactly this, 3 slices in parallel under the per-user 3 rps
cap). Do not just widen this savelookup in that case; per-day slicing is the scalable path.

## Step 4 (production): deploy the detection rule

Render `assets/ueba_detection.template.json` and POST to `/web/api/v2.1/cloud-detection/rules`,
scoped via `filter.{{SCOPE_KEY}}`. The body counts the live window per pair, joins
`{{BASELINE_TABLE}}`, computes `z`, and keeps `|z| >= {{Z_HARD}}`. `runIntervalMinutes` and
`lookbackWindowMinutes` are 1440 so the live unit matches the daily baseline. `entityMappings`
binds `principal_v`. The rule lands Disabled; validate the body by running it first, then enable
with `PUT /web/api/v2.1/cloud-detection/rules/enable`. List with `isLegacy=false` or scheduled
PowerQuery rules are silently omitted.

Two companion variants (same body, one filter change), deploy as separate rules if the user wants
them, route differently per `behavioral-baselines.md`:

- **Silent pairs:** swap the live group for a baseline-keyed walk; flag pairs with `live_count = 0`
  and `baseline_avg` above a per-source floor (`|z|>=2.5`). Route to a separate, lower-urgency rule.
- **New-behaviour:** keep `| filter !(baseline_avg = *)` after the lookup. Route to a
  baseline-curation queue rather than alerting outright.

## Step 5 (production): refresh + dashboard

- **Refresh.** Render `assets/ueba_refresh_workflow.template.json` and import with the
  hyperautomation primitive, scoped `?siteIds={{SITE_ID}}`. It rebuilds `{{BASELINE_TABLE}}` nightly
  over the trailing window. Bind the "SentinelOne SDL" connection (Bearer), not the "SentinelOne"
  mgmt connection (ApiToken signing returns 500 "Header must start with Bearer" on the SDL query
  endpoint). Imported flows land as a PRIVATE DRAFT owned by the API user (invisible in the console);
  publish in the SAME step as the import, an import is not complete until it is a Shared Draft:
  `POST /web/api/v2.1/hyper-automate/api/v1/workflows/{id}/publish?siteIds={{SITE_ID}}` (bodyless `{}`,
  returns 204), then bind/activate to run.
- **Dashboard.** Render `assets/ueba_dashboard.template.json` and `sdl_put_file` to
  `/dashboards/{{PREFIX}} {{SOURCE}} Anomalies`. Panels join the same lookup and show anomaly count,
  new-behaviour count, active principals, volume over time, the top SPIKE/DROP table, and the
  new-behaviour table.

## Step 6: validate and summarise

Run the rendered detection body over the live window and confirm it returns the expected
SPIKE/DROP rows; read back the lookup table; confirm the rule exists (GET with `isLegacy=false`),
the workflow imported, and the dashboard is present. Summarise the deployed artifacts (table name,
rule id, workflow id, dashboard path, site) and the top anomalies found on the first run.

## Gotchas

- **Cadence must match the baseline unit.** Daily baseline, 24h live window, 1440-minute rule
  interval. An hourly rule against a daily baseline is the classic false-positive generator.
- **`stddev = 0` and `n_days < 2` are dropped.** A perfectly flat pair has infinite z; a one-day
  pair has no stddev. Both fall through to the new-behaviour path, not the z path.
- **DoW stddev.** The server-side savelookup computes stddev over active days only. The engine
  zero-pads inactive sampled days, which is more honest (a pair active 2 of 4 Sundays is not as
  "reliable" as 4 of 4). Use the engine when DoW accuracy matters.
- **Noise filter.** Sources that emit volume-accounting rows (Google Workspace `tag='logVolume'`)
  must filter them or the principal/action come back null. Set `{{NOISE_FILTER}}` accordingly.
- **Lookup cap.** Datatables are up to 150 MB; the `{{TOPK}}` cap keeps high-cardinality sources
  bounded. Persist the top pairs by baseline_avg. Automatic-lookup caps (100 rows) do NOT apply here.
- **Sparse / intermittent sources.** A source that reports only some days (validated: Avelios
  Medical reported 2 of 7 days) yields few pairs with `n_days >= 2`; most behaviour shows up as
  new-behaviour. That is correct, not a failure; report it as such.
- **Low-cardinality sources.** A source driven by one service account (validated: Google Workspace,
  one `authorize` principal) produces a thin baseline. Still valid, just few pairs to score.

## Deployed artifacts

A full deployment produces the artifacts below. Each renders from a template in `assets/` and is deployed through the matching primitive skill. The `<prefix>` is the solution/customer code.

| Artifact | Template | Deployed to | Purpose |
|---|---|---|---|
| Baseline lookup builder | `assets/ueba_baseline_savelookup.pq` | SDL datatable `/datatables/<prefix><source>Baseline` | Compute per-pair mean and stddev over the baseline window and persist the top pairs for live z-scoring |
| UEBA detection rule | `assets/ueba_detection.template.json` | STAR rule via `POST /web/api/v2.1/cloud-detection/rules` | Score the 24h live window per pair against the baseline, alert on `|z| >= z_hard`, bind `principal_v` via `entityMappings` |
| Baseline refresh workflow | `assets/ueba_refresh_workflow.template.json` | Hyperautomation workflow import | Rebuild the baseline table nightly over the trailing window (Bearer SDL connection) |
| UEBA dashboard | `assets/ueba_dashboard.template.json` | `sdl_put_file /dashboards/<prefix> <source> Anomalies` | Anomaly count, new-behaviour count, active principals, volume over time, top SPIKE/DROP and new-behaviour tables |
