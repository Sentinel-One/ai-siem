# Solution: Ingest health monitoring (per device)

Monitor the health of everything sending into the Singularity Data Lake, at the level of the
individual device, not just the source. Every sending device, each firewall, endpoint, and server,
is identified and baselined against its own normal behaviour, then watched with statistical anomaly
detection on a 7-day hour-of-day seasonal baseline that is rebuilt daily. When a specific device
spikes, drops, lags, or goes silent, or a parser stops normalising, a detection fires and an email
goes out.

This is part of the `sentinelone-sdl-solutions` skill. It orchestrates the primitive skills
(`sentinelone-powerquery` for the baseline and detection bodies, `sentinelone-mgmt-console-api` for
the scheduled rules, `sentinelone-hyperautomation` for the baseline-builder, notifier, and watchdog
flows, `sentinelone-sdl-dashboard` for the dashboard); it does not reimplement them.

## Features

- **Per-device granularity**: a universal device key resolves each firewall (`device.name`), endpoint (`endpoint.name` / `agent.uuid`), and syslog/host sender (`hostname`), falling back to the source name.
- **Seasonal anomaly detection, not static thresholds**: per-device z-score against the device's own 7-day hour-of-day baseline (spike `z >= +3`, drop `z <= -3`), so it does not false-alarm on normal daily rhythm; the baseline is rebuilt daily by a Hyperautomation flow.
- **Every failure scenario covered**: per-device volume spike, volume drop, ingest lag (p95 over SLA), ingest loss (a continuously-active device went silent), and parser drift.
- **Email on every failure**: one alert-triggered notifier flow for all detections, plus a per-device ingest-loss watchdog.
- **Comprehensive dashboard**: 5 tabs (Overview, Devices, Volume & Sources, Latency & Lag, Parser Health) using number, line, bar, donut, table, and honeycomb panels.
- **Cost-aware**: `sca:bytesToCharge` drives volume and a chargeback view; validated cost, clock-skew, coverage-gap, and quota-trend extensions are included.
- **Bounded and safe at scale**: a device floor plus a per-event baseline lookup keep high-cardinality sources within the detection-rule budget; lookup datatables can be up to 150MB (extensible via SentinelOne).

## Run it with one prompt

The whole solution deploys from a single prompt:

> *"Deploy the ingest health monitoring solution per device to the Acme site and email soc@acme.com on every failure."*

That one prompt seeds the two baseline tables, creates and enables the per-device detections (volume spike/drop, ingest lag, parser drift), imports the Baseline Builder, Alert Notifier, and Ingest Loss Watchdog flows, and deploys the dashboard, previewing each step before it runs and asking only for the site and the notify address.

More targeted prompts:

- *"Deploy ingest health monitoring per device on the Acme site"*
- *"Monitor ingest per firewall and endpoint and email soc@acme.com on any failure"*
- *"Alert me when a specific firewall or endpoint stops sending logs"*
- *"Which devices are spiking, dropping, or over the ingest lag SLA right now?"*
- *"Find parser drift, where a parser stopped normalising"*

## How it works

The sending device differs by source, so one universal key resolves all of them and falls back to
the source name when a source has no device field:

```
device = device.name ? ... : endpoint.name ? ... : agent.uuid ? ... : src_endpoint.hostname ? ... : hostname ? ... : dataSource.name
```

For each `(source, device)` the solution records the expected hourly volume per hour-of-day over the
baseline window, plus the device's mean and standard deviation, then scores the live hour with
`z = (current - expected_for_this_hour_of_day) / device_sigma`. Hour-of-day (24 buckets) keeps the
per-device lookup tables small; a device floor drops transient long-tail hosts so monitoring targets
real, continuously-present devices. Five signal classes come out:

| Class | Meaning | Granularity |
|---|---|---|
| Volume SPIKE | live volume far above the device's baseline (`z >= +3`) | per device |
| Volume DROP | live volume far below baseline (`z <= -3`), partial collection loss | per device |
| Ingest LOSS | a continuously-active device produced zero events this window | per device (Watchdog flow) |
| Ingest LAG | a device's end-to-end latency p95 exceeds the SLA | per device |
| Parser DRIFT | a parser that normally normalises now emits unparsed events | per parser |

## What you choose

| Choice | Default | Notes |
|---|---|---|
| Scope | all sources | every `dataSource.name`; device resolved per event |
| Baseline window / refresh | 7 days / daily 02:00 UTC | 14-30 days gives a stronger seasonal profile; 7 is the floor |
| Granularity | per device, hour-of-day | the seasonal key |
| Sensitivity | 3 sigma | spike `z >= 3`, drop `z <= -3` |
| Lag SLA | p95 > 15 min | per-device latency threshold |
| Device floor | exp_ev >= 5 (baseline); active_hours >= 24 and mean_ev >= 5 (stats) | drops transient hosts |
| Parser drift | >= 5% unparsed on a normalising parser | per parser |
| Notify email | (required) | recipient for all failure scenarios |

The device coalesce, the lookup table names, the per-event lookup that bounds high-cardinality
sources, and the dashboard window are auto-applied and shown in the preview, not prompted.

## What gets deployed

| Artifact | Where | Purpose |
|---|---|---|
| `ingestHealthBaseline` | datatable (per source+device+hour-of-day) | expected GiB and event count, joined by the rules and dashboard |
| `ingestHealthSourceStats` | datatable (per source+device) | mean and stddev of hourly volume + liveness |
| Detection rules | `/web/api/v2.1/cloud-detection/rules` (scheduled PowerQuery) | per-device volume spike, drop, and lag, plus per-parser drift; restricted to baselined devices |
| Baseline Builder | Hyperautomation (daily) | rebuilds both tables over the trailing window |
| Ingest Loss Watchdog | Hyperautomation (hourly) | per-device anti-join to find a device that went silent, emails on a hit |
| Alert Notifier | Hyperautomation (alert-triggered) | emails on any "Ingest Health" detection alert |
| Dashboard | `/dashboards/Ingest Health Monitoring` | 5 tabs: Overview, Devices, Volume & Sources, Latency & Lag, Parser Health |

## Validated

Validated end to end against a live SDL tenant: per-device baseline and stats tables built over a
7-day window via `savelookup`; the per-device spike, drop, lag, and ingest-loss bodies all parse and
return bounded rows; the per-event baseline lookup before the group keeps high-cardinality sources
(thousands of transient syslog hosts) within the scheduled-rule budget; `avg`/`stddev`/percentiles
and the device coalesce confirmed; detections deployed and enabled. Console-only steps remain: bind
the "SentinelOne SDL" connection on the Baseline Builder and Watchdog flows and activate them, then
the rules go Active within ~1 hour and the Alert Notifier emails. Lookup datatables are limited by
size (150MB, extensible via SentinelOne), not a small row count; hour-of-day plus the device floor
keep the rule lookups compact.
