# Solution: Detection as Code (DaC)

Stand up a Detection-as-Code pipeline for a SentinelOne tenant. Detection engineers author rules
as text files in Git, a pull request triggers automated validation and four-eyes review, and a
merge to the main branch syncs the changed rules to the SentinelOne Custom Detection Rule API.
Every change is version-controlled, auditable, and reversible, and rules are easy to read, diff,
and reuse across environments.

Unlike the other solutions in this skill, which deploy SDL artifacts (parsers, lookups,
dashboards, workflows) into the tenant, DaC sets up a Git + CI workflow that lives outside the
tenant and pushes detection rules in.

This is part of the `sdl-solutions` skill. It orchestrates the primitive skills
(`mgmt-console-api` for the Custom Detection Rule API and site resolution,
`powerquery` for scheduled-rule bodies, `sdl-dashboard` for the optional
effectiveness view); it does not reimplement them.

## Why TOML

Rules are authored in TOML because it is readable and diff-friendly, which makes review under a
four-eyes process fast. The SentinelOne API consumes JSON, so the sync engine converts each TOML
rule to the exact API envelope at lint and sync time. You get readable source and a correct
payload without maintaining two formats. JSON and YAML rule files are also accepted.

## Features

- **Three rule types, one format.** Single-event STAR rules (`events`), multi-event correlation
  rules (`correlation`), and scheduled PowerQuery detections (`scheduled`), all authored as TOML
  and converted to the Custom Detection API JSON.
- **Validation before production.** A lint step parses every rule and applies the confirmed API
  constraints locally (enums, required fields, the run-interval/lookback relationship, and the
  common "pipe syntax in an events rule" mistake), so a bad rule fails the pull request, not the
  console.
- **Idempotent sync on merge.** Only the rules changed in the merged PR are pushed; the engine
  creates a new rule or updates an existing one by name, so re-running never duplicates.
- **CI for three platforms.** Ready-to-use lint-on-PR and sync-on-merge automation for GitHub
  Actions, GitLab CI, and Azure Pipelines. The logic lives once in `dac_sync.py`; CI just calls it.
- **Safe by default.** Rules are authored and synced as `Draft`; activation is a deliberate,
  separate step, so a merge never silently arms a live, mitigating rule. Scheduled rules cannot
  mitigate (the converter enforces it).
- **Audit and rollback.** Each sync writes a `deployed_rules.json` manifest; `--rollback` deletes
  exactly the rules it deployed.
- **Zero dependencies.** The engine reads TOML via the stdlib on Python 3.11+ and ships a built-in
  fallback otherwise; HTTP uses the standard library. No `pip install` required on a runner.

## Run it with one prompt

- *"Set up detection as code for the Acme site"*
- *"Scaffold a DaC repo and sync the example rules"*
- *"Automate our detections as code with GitHub Actions"*
- *"Build the detection-as-code pipeline for GitLab and sync to <site>"*

## What it deploys

A starter Git repository: per-target-system rule folders with working TOML examples of all three
rule types, the `dac_sync.py` validate/convert/sync engine plus a local lint wrapper, a
`rule.schema.json` for editor validation, a CODEOWNERS file, and CI for GitHub, GitLab, and Azure.
Then, on the tenant: the converted rules created via the Custom Detection Rule API (as Draft),
verified with an `isLegacy=false` listing. The full scaffold contents, the manual repo-control
checklist (branch protection, RBAC, CODEOWNERS), the rule format reference, and the confirmed API
gotchas are in the Claude-facing playbook `references/detection-as-code.md`.
