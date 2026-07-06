# Solution: custom detection exclusions

Suppress known-good noise in a SentinelOne Custom Detection (STAR) rule without losing real signal.
It works for all three rule types, and the exclusion mechanic follows the rule type:

- **Single-event** (`queryType: events`) and **correlation** (`queryType: correlation`) rules have
  boolean S1QL bodies with no pipes, so the exclusion is an inline hardcoded negative list
  (`AND NOT (<field> in:anycase (...))`) written into the rule itself; correlation appends it to the
  relevant sub-query.
- **Scheduled** (`queryType: scheduled`) rules have a PowerQuery body, so beyond the inline option
  they support a CSV lookup anti-join (`| lookup ... | filter excl = null`) that keeps the exclusion
  list in an editable SDL lookup table managed independently of the rule, plus an effectiveness
  dashboard. This lookup-managed path is the key advantage of the scheduled type.

For a scheduled rule the analyst supplies a CSV of assets (hosts, IPs, CIDRs) or a custom list of
values (domains, users, URLs, rule IDs); the solution loads it as an SDL lookup table and the
detection omits any matching row with the anti-join. The exclusion is applied at the detection
itself, so excluded activity never creates an alert, and a dashboard shows exactly what each list is
suppressing.

This is the third-party-log and custom-detection counterpart to Unified Exclusions Management. UEM
excludes EDR and Identity engine alerts in the console; it does not cover detections you author over
third-party SDL sources or EDR. This solution standardises that pattern across all three rule types.

This is part of the `sdl-solutions` skill. It orchestrates the primitive skills
(`powerquery` for the anti-join query, `mgmt-console-api` for the STAR rule,
`sdl-dashboard` for the dashboard, `hyperautomation` for the CIDR/wildcard
variant and the optional list refresh); it does not reimplement them.

## Features

- **Works for all three rule types**: inline hardcoded negative list for single-event and
  correlation rules; a CSV lookup anti-join (managed outside the rule) plus an effectiveness
  dashboard for scheduled rules. The skill asks which rule type first.
- **One CSV, applied at detection time** (scheduled): the analyst supplies an allowlist (assets or custom values); the rule omits matches with `| lookup ... | filter excl = null`, so excluded activity never alerts.
- **Assets or custom values**: match by IP/subnet (`=:cidr`), hostname/value (`=:anycase`), prefix or suffix pattern (`=:wildcard`), or exact token (`=`); chain an asset list AND a value list in one rule.
- **Effectiveness dashboard**: total candidate detections vs excluded vs net, exclusion rate, excluded over time, and the top suppressed values, so an over-broad exclusion hiding a real threat is visible. Excluded is the exact inverse of the anti-join, so excluded + kept = total by construction.
- **Static or source-of-truth lists**: a CSV the analyst attaches, or a list built from the Asset Inventory (for example every asset tagged `scanner`) with an optional nightly refresh workflow.
- **CIDR and wildcard via Hyperautomation**: STAR scheduled rules accept `=` and `=:anycase`; `=:cidr` and `=:wildcard` run as a Hyperautomation flow that queries the SDL and posts a UAM alert with the offender mapped as indicator and asset.

## Run it with one prompt

- *"Stop my Akamai DNS failed-lookup detection from alerting on our scanner subnets and corporate domains, here's the list"*
- *"Exclude these allowlisted hosts/domains from the `<source>` detection"* (attach the CSV)
- *"Build a `<source>` detection that ignores anything from assets tagged `scanner`"*

## What it deploys

For a single-event or correlation rule, just the STAR rule with the inline exclusion (no lookup, no
dashboard). For a scheduled rule: a lookup table (the exclusion list), a scheduled PowerQuery STAR
rule wrapped with the anti-join, an exclusion-effectiveness dashboard, and (for CIDR/wildcard
matches) a Hyperautomation detection flow that posts the alert to UAM. An optional refresh workflow
rebuilds a source-of-truth list nightly. The full artifact table, the config questions, and the
operator/deploy caveats are in the Claude-facing playbook `references/custom-detection-exclusions.md`.
