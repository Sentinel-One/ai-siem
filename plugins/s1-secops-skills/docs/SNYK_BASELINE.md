# Snyk baseline: s1-secops-skills

Local Snyk run, 2026-11-05, org `github-forge`, Snyk CLI. This is the starting point the
warn-only `Snyk` workflow reports against; it is not a statement that these are all exploitable.
Triage each finding (fix, or suppress with a reason), then set `SNYK_ENFORCE: "true"` in
`.github/workflows/snyk.yml`.

## Snyk Code (SAST)

Open issues: **69** (2 error, 11 warning, 56 note).

### Error level

| Rule | Location | Finding |
|---|---|---|
| HardcodedNonCryptoSecret | `tools/live_learnings_check.mjs:195` | Avoid hardcoding values that are meant to be secret. Found a hardcoded string used in here. |
| Ssrf | `sdl-solutions/assets/rba_console/server.py:119` | Unsanitized input from the HTTP request body flows into urllib.request.urlopen, where it is used as an URL to  |

### Warning and note level (counts by rule)

| Level | Rule | Count |
|---|---|---|
| warning | Ssrf | 7 |
| warning | DOMXSS | 3 |
| warning | IndirectCommandInjection | 1 |
| note | PT | 41 |
| note | test | 15 |

## Snyk Open Source (SCA)

| Package | Version | Findings | Fixed in |
|---|---|---|---|

## Not covered

Snyk Container (the Dockerfile image) and Snyk IaC were not run.
