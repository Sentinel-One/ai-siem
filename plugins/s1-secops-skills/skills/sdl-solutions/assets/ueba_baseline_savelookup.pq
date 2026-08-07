// UEBA behavioral baseline builder for the ueba-anomaly-detection solution.
// Source-agnostic: works on ANY dataSource.name (security or non-security) once
// {{PRINCIPAL}} and {{ACTION}} are picked by schema discovery (inspect_source.py).
//
// Computes a per-(action, principal) POOLED baseline server-side in one query:
//   stage 1: count events per DAY per (action, principal)   -> day_count
//   stage 1b: DROP the partial first and last calendar-day buckets (day > window-start
//     bucket AND day < window-end bucket, via overall_min/overall_max of day). The edge
//     buckets cover only part of a day, so including them dragged baseline_avg down and
//     inflated baseline_stddev. Filter pattern live-validated read-only 2026-07-29.
//   stage 2: collapse to mean + stddev across FULL days     -> baseline_avg, baseline_stddev
// then persists the result as the lookup table {{BASELINE_TABLE}} that the
// detection rule and dashboard join against.
//
// Pairs with < 2 active days (stddev undefined) are dropped: with under 2 days of
// history the pair is genuinely "new" and belongs in the NEW-BEHAVIOR panel. Pairs
// with FLAT history (stddev 0, e.g. a service account or scheduled job emitting the
// same count every day) are KEPT and marked is_constant = 1: a perfectly regular
// pair is the strongest baseline there is, and dropping it (the pre-2026-08 design)
// misclassified a spike on it as new-behavior and never flagged a silence. The
// detection rule and dashboard score any deviation from a constant as sentinel
// z = 999 (above) / -999 (below), and an exact match as 0, so no division by the
// zero stddev ever happens (see ueba_detection.template.json). Ported from the
// proven fix in mgmt-console-api/scripts/baseline_anomaly.py
// (2026-07-29); build query shape live-validated read-only on 'Okta' 2026-08-01.
// Top {{TOPK}} pairs by baseline_avg are kept so the table stays under the
// 150 MB datatable cap on high-cardinality sources.
//
// Run through the powerquery LRQ runner over the baseline window
// (startTime = now - {{BASELINE_HOURS}}h, endTime = now).
//
// Runs as ONE Long-Range Query (LRQ), executed server-side. An interactive client (for
// example the powerquery_run MCP wrapper) may stop polling after ~30s and report a timeout,
// but the LRQ keeps running and the savelookup still persists. Tenant-validated 2026-06-18 on
// 'Okta': the 7-day build wrote the table (172 pairs) AFTER the wrapper reported a timeout. That
// run counted n_days up to 8 because the partial first/last calendar-day buckets were still
// included; with the edge-bucket exclusion above, a 168h window yields at most 6 to 7 FULL
// interior days, so expect n_days <= 7. The nightly refresh workflow only launches this LRQ, so 7 to 30-day windows build
// fine. Split ONLY if a single windowed query exceeds the LRQ max runtime on a very busy /
// high-cardinality source: run per-day LRQ slices and merge client-side with
// scripts/baseline_anomaly.py (3 slices in parallel, under the per-user 3 rps cap). Do not just
// widen this savelookup in that case.
//
// {{NOISE_FILTER}} drops volume-accounting noise on sources that carry it,
// e.g. "(tag != 'logVolume' OR !(tag = *))" for Google Workspace; leave empty otherwise.
//
// DoW note: for day-of-week stratification add  dow = strftime(timestamp, '%a')
// to BOTH group-by clauses and key the table on (action_v, principal_v, dow).
// The server-side stddev is then over active days only; for the zero-padded DoW
// stddev (the most accurate form) run scripts/baseline_anomaly.py --stratify dow.

dataSource.name = '{{SOURCE}}' {{NOISE_FILTER}}
| filter {{PRINCIPAL}} = * AND {{ACTION}} = *
| group day_count = count() by day = timebucket('1d'), action_v = {{ACTION}}, principal_v = {{PRINCIPAL}}
| let dmin = overall_min(day), dmax = overall_max(day)
| filter day > dmin AND day < dmax
| group baseline_avg = avg(day_count), baseline_stddev = stddev(day_count), n_days = count() by action_v, principal_v
| filter n_days >= 2
| let is_constant = (baseline_stddev > 0 ? 0 : 1)
| sort -baseline_avg
| limit {{TOPK}}
| savelookup '{{BASELINE_TABLE}}'
