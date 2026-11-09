# Solution: Detection as Code (DaC)

Manage SentinelOne Custom Detection rules from Git with the console's native Detection as Code
API. Each rule is a YAML file, one manifest per console says which scopes receive which files, a
pull request shows exactly what the console will change, and a merge applies it. Every change is
reviewed, versioned and traceable to a commit.

This is part of the `sdl-solutions` skill. CI runs the official SentinelOne `detection-as-code`
reference repository (GitHub Actions); Claude uses the s1-secops-mcp tools `dac_export`,
`dac_diff` and `dac_apply` (1.6.1 or later) to bootstrap the repository and review changes.

## Features

- **Native engine.** The console computes and applies the change set
  (`/cloud-detection/rules/parse-vcs`); nothing is converted or synced by a local script.
- **Start from what you run.** `dac_export` downloads every rule the token can see as YAML;
  committed unchanged, those files import the live rules instead of duplicating them.
- **Reviewed diffs.** `dac_diff` (read-only) and the reference workflow's PR comment list every
  create, update, import, retain and delete before anything changes.
- **Apply on merge.** The reference GitHub Actions workflow applies on push to `main`; GitLab CI
  and Azure Pipelines run the same script in CLI mode. `dac_apply` serves repositories without
  CI and only applies a change set whose summary matches the one reviewed.
- **All three rule types.** Events, correlation (including custom entities) and scheduled
  PowerQuery rules, with Active Response, cool-off, hidden logic and entity mappings.
- **Controlled removal.** Removing a file retains the rule as a normal console rule by default;
  deleting it takes `deletePolicy: Delete` and a second merge.

## Requirements

DaC enabled on the tenant; Endpoint Security Complete or Core; a service user whose scope covers
every target, with Custom Rules manage (plus Perform Advanced Actions for hidden logic). Only
`queryLang: "2.0"` rules can be managed as code. DaC-managed rules are edited only in Git.

## Run it with one prompt

- *"Set up detection as code for the `<site>` site"*
- *"Put our existing custom rules under Git and deploy them on merge"*
- *"Show me what this rules branch would change in the console"*

## What it produces

A rules repository in the reference layout (`consoles/<console>.yaml`, `detections/...`),
seeded from the console export or from the templates in `assets/dac-native/`, a reviewed
`dac_diff`, and CI wired to apply on merge. The prerequisites, manifest rules, delete flow and
troubleshooting table are in the Claude-facing playbook `references/detection-as-code.md`.
