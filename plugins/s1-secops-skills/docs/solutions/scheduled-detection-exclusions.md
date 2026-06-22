# Solution: scheduled detection exclusions

Suppress known-good noise in a scheduled detection over a third-party SDL source (firewall, DNS,
proxy, cloud audit, SaaS) without losing real signal. The analyst supplies a CSV of assets (hosts,
IPs, CIDRs) or a custom list of values (domains, users, URLs, rule IDs); the solution loads it as an
SDL lookup table and the detection omits any matching row with a lookup anti-join. The exclusion is
applied at the detection itself, so excluded activity never creates an alert, and a dashboard shows
exactly what each list is suppressing.

This is the third-party-log counterpart to Unified Exclusions Management. UEM excludes EDR and
Identity engine alerts in the console; it does not cover detections you author over third-party SDL
sources. This solution standardises that pattern: one CSV, one lookup, one anti-join filter.

This is part of the `sentinelone-sdl-solutions` skill. It orchestrates the primitive skills
(`sentinelone-powerquery` for the anti-join query, `sentinelone-mgmt-console-api` for the scheduled
STAR rule, `sentinelone-sdl-dashboard` for the dashboard, `sentinelone-hyperautomation` for the
CIDR/wildcard variant and the optional list refresh); it does not reimplement them.

## Features

- **One CSV, applied at detection time**: the analyst supplies an allowlist (assets or custom values); the rule omits matches with `| lookup ... | filter excl = null`, so excluded activity never alerts.
- **Assets or custom values**: match by IP/subnet (`=:cidr`), hostname/value (`=:anycase`), prefix or suffix pattern (`=:wildcard`), or exact token (`=`); chain an asset list AND a value list in one rule.
- **Effectiveness dashboard**: total candidate detections vs excluded vs net, exclusion rate, excluded over time, and the top suppressed values, so an over-broad exclusion hiding a real threat is visible. Excluded is the exact inverse of the anti-join, so excluded + kept = total by construction.
- **Static or source-of-truth lists**: a CSV the analyst attaches, or a list built from the Asset Inventory (for example every asset tagged `scanner`) with an optional nightly refresh workflow.
- **CIDR and wildcard via Hyperautomation**: STAR scheduled rules accept `=` and `=:anycase`; `=:cidr` and `=:wildcard` run as a Hyperautomation flow that queries the SDL and posts a UAM alert with the offender mapped as indicator and asset.

## Run it with one prompt

- *"Stop my Akamai DNS failed-lookup detection from alerting on our scanner subnets and corporate domains, here's the list"*
- *"Exclude these allowlisted hosts/domains from the `<source>` detection"* (attach the CSV)
- *"Build a `<source>` detection that ignores anything from assets tagged `scanner`"*

## What it deploys

A lookup table (the exclusion list), a scheduled PowerQuery STAR rule wrapped with the anti-join,
an exclusion-effectiveness dashboard, and (for CIDR/wildcard matches) a Hyperautomation detection
flow that posts the alert to UAM. An optional refresh workflow rebuilds a source-of-truth list
nightly. The full artifact table, the config questions, and the operator/deploy caveats are in the
Claude-facing playbook `references/scheduled-detection-exclusions.md`.
