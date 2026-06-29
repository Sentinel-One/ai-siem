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

## Granularity: source vs device

Monitoring is **source level by default** (one logical device = the source name, which suits sources with no real
device identity). A source is monitored **per device only if it is listed in the `ingestHealthDeviceLevel` lookup**
(`source, device_field, reason`). `device_field` names the field that identifies the device for that source
(`device.name`, `endpoint.name`, `agent.uuid`, `src_endpoint.hostname`, `hostname`, or `auto` to use the generic
coalesce). Device for a device-level source = the configured field (falling back to the coalesce, then the source);
for every other source `device = dataSource.name`. The same conditional logic runs in the builder, the detections,
and the watchdog, so one set of baseline tables serves both levels and every alert carries a `level` column.

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

## Source exclusions (maintainable lookup, no hardcoding)

Which sources are monitored is controlled by ONE editable CSV lookup, not by hardcoded
`dataSource.name != '...'` clauses scattered across queries. Every query body (both savelookups, all
detection rules, the watchdog live subquery, and every dashboard panel) carries the same anti-join
right after its opener:

```
<opener> | lookup ih_excl_n = reason from ingestHealthExclusions.csv by value =:anycase dataSource.name
         | lookup ih_excl_v = reason from ingestHealthExclusions.csv by value =:anycase dataSource.vendor
         | filter (ih_excl_n = null and ih_excl_v = null)
```

The table `/datatables/ingestHealthExclusions.csv` (template `assets/ingesthealth_exclusions.csv.template`)
has three columns: `value` (the `dataSource.name` OR `dataSource.vendor` string to stop monitoring),
`match_type` (`name` or `vendor`, advisory only), and `reason` (free text). To exclude a source add one
row (`Zscaler,vendor,decommissioned`); to resume, delete the row. No query edits, no redeploy. An empty
table (header only) excludes nothing.

Mechanics:
- The anti-join tests `value` against BOTH `dataSource.name` and `dataSource.vendor`, so `match_type` is
  documentation only: a row matches if its value equals either field (case-insensitive via `=:anycase`).
- This is the right place to drop the platform's own internal streams, which a vendor filter misses.
  `dataSource.vendor != 'SentinelOne'` KEEPS null-vendor rows, so `alert, indicator, asset, ActivityFeed,
  misconfiguration, finding, risk` and the native `SentinelOne` EDR leak back in; list them by NAME in the
  CSV. The shipped template pre-populates those internal streams; keep or trim per tenant.
- Scheduled detection rules accept the anti-join (`lookup ... by value =:anycase ... | filter excl = null`);
  `=` and `=:anycase` are the supported operators.
- CSV gotcha: a value containing a comma needs double-quotes; spaces do not (`Microsoft O365` is one value).
  `sdl_get_file` reflows the CSV for display, that is cosmetic; the stored table parses correctly.
- Create the CSV BEFORE deploying anything that references it, or `lookup ... from ingestHealthExclusions.csv`
  errors "file not found".

## Deploy order

1. Config lookups (FIRST, every query references them): put_file `assets/ingesthealth_exclusions.csv.template`
   -> `/datatables/ingestHealthExclusions.csv` (sources to stop monitoring) AND
   `assets/ingesthealth_devicelevel.csv.template` -> `/datatables/ingestHealthDeviceLevel.csv` (sources to
   monitor per device; absent = source level). Edit either later to change scope/granularity without
   touching any query.
2. Baseline: `flows/ha_flow_1_baseline_builder.json` (2 per-device savelookups/7d, daily). Bind
   "SentinelOne SDL" (Bearer). Seed once before anything reads the tables.
3. Detections: POST the unified rules in `assets/ingesthealth_detections.template.json` to
   `/cloud-detection/rules` (`scheduled`, `queryLang 2.0`), scope siteIds/accountIds. One Spike, one Drop,
   one Lag, each handles both levels via the conditional device logic and tags every alert with a `level`
   column. Land Disabled; enable via `PUT /cloud-detection/rules/enable`. Lookback 60 (= 1h). Parser Drift
   ships separately in `assets/ingesthealth_detections_parser_drift_optional.template.json` and is OPTIONAL:
   it is environment-specific, do NOT deploy by default, tune the drift_ratio threshold first.
4. Ingest loss: per device via `assets/ingesthealth_watchdog.workflow.template.json` (anti-join LRQ in a
   POLL LOOP; the scheduled engine rejects `left join`, so this runs as an HA LRQ, not a STAR rule).
5. Notifier: `assets/ingesthealth_alert_notifier.workflow.template.json` (trigger `name contains 'Ingest
   Health'` -> send_email). Core actions only; activate directly.
6. Dashboard: put_file `assets/ingesthealth_dashboard.template.json` -> `/dashboards/Ingest Health Monitoring`.
7. Publish + test E2E with run-now + prompt the user: publish each imported flow to a Shared Draft so it
   is visible (`POST .../workflows/{id}/publish?siteIds=<id>`, see Gotchas), bind "SentinelOne SDL"
   (Bearer), activate the flows, then
   `POST .../workflow-execution/manual/{id}/{version}?accountIds=<acct>` each flow and poll
   `GET .../workflow-execution/{exec_id}` to `Completed` with `error_actions:[]`. Confirm the tables wrote
   (`| dataset 'config://datatables/ingestHealthBaseline' | group count()`), the dashboard renders, and a
   detection alert is present. Always prompt the user to run this E2E check after a deploy.

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
- Import is not complete until published: treat `ha_import_workflow` and publish as ONE atomic step (publish in the SAME step as the import, never a follow-up). ALWAYS publish every imported HA flow immediately, or the user cannot see it. `ha_import_workflow`
  lands the flow as a PRIVATE DRAFT owned by the API token's user (invisible in the console to the human
  who asked). Right after each import: `POST /web/api/v2.1/hyper-automate/api/v1/workflows/{id}/publish?siteIds=<id>`
  (bodyless `{}`, returns 204) -> Shared Draft, visible. Use `accountIds=<acct>` for account-scoped flows.
  The flow stays inactive (shared but not running) until the connection is bound and it is activated;
  activation auto-publishes, so this explicit publish is only skippable when you activate in the same pass.
- HA interval trigger: each `schedule_value` entry needs `schedule_method:"interval"` + unit/value.
- `sca:ingestTime` epoch sec, `timestamp` ns; lag = `(sca:ingestTime - timestamp/1e9)/60`.
- HA LRQ is async AND the query id is ephemeral. Every flow LRQ (`POST /sdl/v2/api/queries`, both
  savelookups and the watchdog anti-join) must launch -> capture `body.id` + `X-Dataset-Query-Forward-Tag`
  -> POLL LOOP {poll(GET) -> `stepsCompleted = totalSteps`? break : delay ~5s, cap ~60}. The field is
  `totalSteps` (NOT `stepsTotal`). A long fixed wait 404s (id expired); reading `body.data` off the launch
  is always null. Actions that consume a poll result must live INSIDE the loop (loop-scoped outputs are
  not visible after the loop). See the hyperautomation skill's "Running an SDL LRQ from an HA flow".
- Source scoping is via the `ingestHealthExclusions.csv` lookup (see "Source exclusions" above), not
  hardcoded filters. For that list, remember `dataSource.vendor != 'SentinelOne'` KEEPS null-vendor rows,
  so the platform's own internal streams (`alert, indicator, asset, ActivityFeed, misconfiguration,
  finding, risk`) and the native `SentinelOne` EDR leak past a vendor filter; exclude them by NAME in the CSV.

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
  "SentinelOne SDL" (Bearer) connection bound and activation in the console; the Watchdog counts poll
  result rows via `Function.JQ(poll-slug.body.data.values, "length", true)` (the raw LRQ response has no
  `totalRows` field). Validated 2026-06-25 end to end via run-now: both flows Completed, `error_actions:[]`.
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
  high-cardinality syslog estates; lower it to monitor smaller devices. The defaults (`active_hours>=24`,
  watchdog continuity `>=151`) assume a mature, continuously-present fleet; when the monitored scope is
  new or low-volume (e.g. a freshly onboarded third-party source) `ingestHealthSourceStats` can come back
  EMPTY until the source accumulates history, and the z-score/lag detections won't fire until it fills.
  The daily Baseline Builder fills it over time; lower the floors to start monitoring sooner.
- Keep the dashboard default window short (4h-24h) and widen with the time picker for
  investigation; for always-on wide views consider the pre-aggregated logVolume metric stream
  instead of per-event byte sums.
- Tie each rule's cool-off to its severity and run cadence; review the New/Unbaselined-Source rule
  before enabling.

## Deployed artifacts

A full deployment produces the artifacts below. Each renders from a template in `assets/` and is deployed through the matching primitive skill. The `<prefix>` is the solution/customer code.

| Artifact | Template | Deployed to | Purpose |
|---|---|---|---|
| Source exclusions lookup | `assets/ingesthealth_exclusions.csv.template` | `sdl_put_file /datatables/ingestHealthExclusions.csv` | Editable allowlist of sources to STOP monitoring (by `dataSource.name` or `dataSource.vendor`); every query anti-joins it. Deploy FIRST. |
| Device-level config lookup | `assets/ingesthealth_devicelevel.csv.template` | `sdl_put_file /datatables/ingestHealthDeviceLevel.csv` | Opt-in list of sources to monitor per device (`source, device_field, reason`); absent = source level. Deploy FIRST. |
| Baseline Builder workflow | `assets/ingesthealth_baseline_builder.workflow.template.json` | Hyperautomation workflow import | Rebuild the `ingestHealthBaseline` and `ingestHealthSourceStats` datatables daily from a 7-day hour-of-day window (Bearer SDL connection) |
| Ingest health detections (unified) | `assets/ingesthealth_detections.template.json` | STAR rule via `POST /web/api/v2.1/cloud-detection/rules` | Unified Volume Spike, Volume Drop, Ingest Lag scheduled rules vs the seasonal baseline; each handles both levels and tags alerts with a `level` column |
| Parser Drift (OPTIONAL) | `assets/ingesthealth_detections_parser_drift_optional.template.json` | STAR rule via `POST /web/api/v2.1/cloud-detection/rules` | Per-parser drift detector. Environment-specific, ships Disabled, do NOT deploy by default; tune `drift_ratio` first |
| Ingest Loss Watchdog workflow | `assets/ingesthealth_watchdog.workflow.template.json` | Hyperautomation workflow import | Hourly per-device anti-join that emails when a baselined device stops sending logs |
| Ingest health dashboard | `assets/ingesthealth_dashboard.template.json` | `sdl_put_file /dashboards/Ingest Health Monitoring` | Five-tab view: Overview, Devices, Volume & Sources, Latency & Lag, Parser Health |
| Alert Notifier workflow | `assets/ingesthealth_alert_notifier.workflow.template.json` | Hyperautomation workflow import | Alert-triggered email on any "Ingest Health" detection |
