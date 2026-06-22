# Playbook: Ingest Health Monitoring (per device)

Deploy ingest health for an SDL tenant at per-device granularity (per firewall, endpoint, server):
anomaly detection on a 7-day hour-of-day seasonal baseline refreshed daily, plus dashboard,
detections, and email on every failure. Triggers: "deploy ingest health", "monitor ingest per
device/firewall/endpoint", "ingest loss/lag", "parser drift". Orchestration only; drives powerquery,
sdl-dashboard, hyperautomation, sdl-api, mgmt-console-api. Full queries + deploy record: `SOLUTION.md`.

## Model

Per-device z-score vs the device's 7-day hour-of-day seasonal baseline, refreshed daily by an HA
flow: `z = (current_hour - expected_for_hour_of_day) / device_sigma`. Spike z>=+3, drop z<=-3.

Device identity coalesce (one key for all source types, falls back to source):
`device = device.name ? ... : endpoint.name ? ... : agent.uuid ? ... : src_endpoint.hostname ? ... :
hostname ? ... : dataSource.name`.

Two tenant-level savelookup tables:
- `ingestHealthBaseline` key `srckey`=`source||device||hour-of-day`: `exp_gib, exp_ev`.
- `ingestHealthSourceStats` key `devkey`=`source||device`: `sig_gib, sig_ev, mean_*, active_hours, total_*, first/last_seen`.

Hour-of-day (24 buckets) keeps the per-device lookup tables small. A device floor (baseline
`exp_ev >= 5`; stats `active_hours >= 24 and mean_ev >= 5`) drops transient hosts so monitoring
targets real, continuously-present devices.

## Parameters (ask few; default rest)

| Param | Default |
|---|---|
| granularity | per device, hour-of-day (`simpledateformat(ts,'HH','GMT')`) |
| window / refresh | 7d / daily 02:00 UTC |
| sensitivity | 3 sigma |
| lag SLA | p95 > 15 min |
| device floor | exp_ev>=5 (baseline); active_hours>=24 and mean_ev>=5 (stats) |
| silence / continuity | hourly / active_hours >= round(0.9*window_h) |
| parser drift | ratio >= 0.05 |
| notify email | ask (required) |
| site/scope | ask at deploy |

## Deploy order

1. Baseline: `flows/ha_flow_1_baseline_builder.json` (2 per-device savelookups/7d, daily). Bind
   "SentinelOne SDL" (Bearer). Seed once before anything reads the tables.
2. Detections: POST `detections/*` to `/cloud-detection/rules` (`scheduled`, `queryLang 2.0`),
   scope siteIds/accountIds. Spike/drop/lag are per device and restrict to baselined devices via a
   per-event lookup before the group. Land Disabled; enable via `PUT /cloud-detection/rules/enable`.
   Lookback 60 (= 1h). Parser drift is per parser.
3. Ingest loss: per device via `flows/ha_flow_3_ingest_loss_watchdog.json` (anti-join; the
   scheduled engine rejects `left join`).
4. Notifier: `flows/ha_flow_2_alert_notifier.json` (trigger `name contains 'Ingest Health'` ->
   send_email). Core actions only; activate directly.
5. Dashboard: put_file `dashboard/*` -> `/dashboards/Ingest Health Monitoring` (Devices tab included).

## Gotchas (tenant-validated)

- Lookup datatables: 150MB storage limit (extensible via S1), NOT a small row cap. A scheduled-rule
  `lookup` is additionally validated for load size; keep it small with hour-of-day + a device floor,
  or request an increase. Name the join expression differently from the table key (`by devkey = dk`,
  not `by devkey = devkey`) or the rule parser errors "Expected ')'".
- Work in `group`: `avg, stddev, p10/p90/p95/p99/p999, pct(N,x), median, sum, count, max_by,
  oldest/newest, overall_max/min`; also `format, simpledateformat, number, sqrt`.
- `replace_all()` absent (use `replace`). `count(field=*)` errors -> `sum((field?1:0))`.
- No transpose on `dataSource.name`/`device` (spaces); use honeycomb / single-series / grouped_data.
- A second `group` cannot reference a field renamed in the first; after `by source = dataSource.name`
  use `by source`.
- Per-device detections: restrict to baselined devices with a per-event lookup BEFORE the group so
  the intermediate stays bounded on high-cardinality sources (e.g. thousands of syslog hosts).
- HA interval trigger: each `schedule_value` entry needs `schedule_method:"interval"` + unit/value.
- `sca:ingestTime` epoch sec, `timestamp` ns; lag = `(sca:ingestTime - timestamp/1e9)/60`.

## Register in skill

Add this as `references/ingest-health-monitoring.md`, tokenized templates in `assets/`
(`{{NOTIFY_EMAIL}} {{ACCOUNT_ID}} {{SITE_ID}} {{CONSOLE_HOST}} {{WINDOW_H}} {{Z}} {{LAG_SLA}}
{{FLOOR_HR}} {{STAT_HRS}} {{STAT_EV}} {{CONTINUITY_H}} {{DRIFT}} {{START_AT}}`), a catalog row, and
trigger terms in the frontmatter.


## Tested vs not tested

Tested live (LRQ) before deploy:

- All baseline/stats builder queries and the per-device spike, drop, lag, loss and parser-drift
  bodies (parse and return bounded rows); the device coalesce; `avg`/`stddev`/percentiles;
  `savelookup` writes; the lookup-before-group bounding; and the dashboard panel queries.
- Detection-rule deploy (POST/PUT accepted; rules created Disabled then enabled).

Not fully tested (needs the console or a live cycle):

- End-to-end HA flow execution and email delivery: the Baseline Builder and Watchdog flows need the
  "SentinelOne SDL" (Bearer) connection bound and activation in the console; confirm the Watchdog's
  `totalRows` response path on one real run.
- Detection alerts firing on the next evaluation (rules go Active within ~1 hour, then run on the
  interval) and the Alert Notifier emailing.
- Dashboard rendering at very wide time windows: heavy full-scan volume/parser panels can hit
  renderer fetch timeouts over multi-day ranges, which is why the default window is 4h.
- `| dataset` reads do not render in the XDR dashboard UI; device-count KPIs use a live floored
  count instead. `| lookup` against the tables renders fine.

## Recommendations

- Bind the SDL connection and activate the two savelookup flows first; the baseline must exist
  before detections or dashboard panels resolve.
- Keep the detection lookback equal to the baseline bucket (60 min for hour-of-day) so z-scores
  compare like windows.
- Use a 14-30 day baseline window in production for a stronger seasonal profile
  (`DELTA_NOW(336|720)`); 7 days is the floor.
- Tune the device floor (`exp_ev` / `active_hours` / `mean_ev`) to the fleet: raise it on noisy,
  high-cardinality syslog estates; lower it to monitor smaller devices.
- Keep the dashboard default window short (4h-24h) and widen with the time picker for
  investigation; for always-on wide views consider the pre-aggregated logVolume metric stream
  instead of per-event byte sums.
- Tie each rule's cool-off to its severity and run cadence; review the New/Unbaselined-Source rule
  before enabling.

## Deployed artifacts

A full deployment produces the artifacts below. Each renders from a template in `assets/` and is deployed through the matching primitive skill. The `<prefix>` is the solution/customer code.

| Artifact | Template | Deployed to | Purpose |
|---|---|---|---|
| Baseline Builder workflow | `assets/ingesthealth_baseline_builder.workflow.template.json` | Hyperautomation workflow import | Rebuild the `ingestHealthBaseline` and `ingestHealthSourceStats` datatables daily from a 7-day hour-of-day window (Bearer SDL connection) |
| Ingest health detections | `assets/ingesthealth_detections.template.json` | STAR rule via `POST /web/api/v2.1/cloud-detection/rules` | Per-device Volume Spike, Volume Drop, Ingest Lag and per-parser Parser Drift scheduled rules vs the seasonal baseline |
| Ingest Loss Watchdog workflow | `assets/ingesthealth_watchdog.workflow.template.json` | Hyperautomation workflow import | Hourly per-device anti-join that emails when a baselined device stops sending logs |
| Ingest health dashboard | `assets/ingesthealth_dashboard.template.json` | `sdl_put_file /dashboards/Ingest Health Monitoring` | Five-tab view: Overview, Devices, Volume & Sources, Latency & Lag, Parser Health |
| Alert Notifier workflow | `assets/ingesthealth_alert_notifier.workflow.template.json` | Hyperautomation workflow import | Alert-triggered email on any "Ingest Health" detection |
