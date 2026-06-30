# Detection as Code for SentinelOne

A starter repository for managing SentinelOne Custom Detection rules as code. Detection
engineers author rules as TOML files, open a pull request, and on merge the changed rules
sync automatically to the SentinelOne Custom Detection Rule API. Every change is reviewed,
versioned, and auditable.

## Why TOML

Rules are authored in TOML because it is readable, diff-friendly, and easy to review under a
four-eyes process. The SentinelOne API consumes JSON, so `scripts/dac_sync.py` converts each
TOML rule to the exact API envelope at lint and sync time. You get readable source files and
a correct API payload without maintaining two formats by hand. JSON and YAML rule files are
also accepted if you prefer them or are migrating an existing library.

## Repository layout

```
detection-as-code/
├── detections/
│   ├── endpoint/      # one .toml per rule, grouped by target system
│   ├── identity/
│   └── cloud/
├── scripts/
│   ├── dac_sync.py    # validate + convert + idempotent sync (the engine CI calls)
│   └── dac_lint.py    # local-only validation wrapper / pre-commit hook
├── rule.schema.json   # JSON Schema for editor validation of the TOML model
├── .github/
│   ├── workflows/     # lint.yml (on PR) and sync.yml (on merge)
│   └── CODEOWNERS
└── ci/
    ├── gitlab/.gitlab-ci.yml
    └── azure/azure-pipelines.yml
```

Folder names under `detections/` are organisational only; the sync engine walks the whole tree.

## The three rule types

| Type | `query_type` | Body | Fires | Mitigation |
|---|---|---|---|---|
| Single event (STAR) | `events` | boolean S1QL in `s1ql` | per matching event, real time | yes (`treat_as_threat`, `network_quarantine`) |
| Correlation | `correlation` | `[correlation]` with `[[correlation.subqueries]]` | when subqueries match within the window | yes |
| Scheduled | `scheduled` | piped PowerQuery in `[scheduled].query` | on an interval over a lookback window | no (verdict via severity) |

See the examples under `detections/`. Each is authored as `status = "Draft"` so it never fires
until a human reviews it and flips it to `Active`.

## Workflow

1. A detection engineer creates a branch and adds or edits a `.toml` rule, ideally testing the
   query first in a lower environment.
2. They open a pull request. `lint` runs and CODEOWNERS requests review.
3. After approval, the PR merges to `main`.
4. `sync` runs on the merge and pushes only the changed rules to SentinelOne (create or update).
5. Rules are maintained by editing the files; history and rollback come from Git.

## Local use

```bash
# Validate every rule (no network):
python3 scripts/dac_lint.py

# See the exact JSON that would be sent, without deploying:
python3 scripts/dac_sync.py --dry-run detections

# Deploy everything to a site (one-off, from a trusted host):
export S1_CONSOLE_URL="https://your-tenant.sentinelone.net"
export S1_CONSOLE_API_TOKEN="****"
python3 scripts/dac_sync.py --sync --site "your-site"

# Roll back a previous deploy:
python3 scripts/dac_sync.py --rollback deployed_rules.json
```

No dependencies are required. Python 3.11+ reads TOML via the stdlib; the script also ships a
built-in TOML fallback, so it runs even on older interpreters with nothing installed. HTTP uses
the standard library (no `requests`). YAML rule files are the only thing that need an extra
package (`pip install pyyaml`); TOML and JSON work out of the box.

## Setting up the controls (one-time)

1. **Branch protection** on `main`: require a pull request, require approvals, and require the
   `lint` check to pass.
2. **CODEOWNERS**: edit `.github/CODEOWNERS` with your real teams so reviews are auto-requested.
3. **Secrets**: store the API token as `S1_CONSOLE_API_TOKEN` and the console URL as
   `S1_CONSOLE_URL` in your CI secret store (GitHub Actions secrets, GitLab CI/CD variables,
   or Azure pipeline variables). Never commit a token.
4. **Runner reachability**: if your console is not reachable from cloud-hosted runners, point
   the workflows at a self-hosted runner that can reach `*.sentinelone.net`.

## How the API mapping works (and the rules it enforces)

`dac_sync.py` applies every confirmed Custom Detection API constraint so a bad rule fails in CI,
not in production:

- `events` rules take boolean S1QL only. A pipe `|` in an events body is rejected with a clear
  error that points you to a scheduled rule.
- `scheduled` rules force `queryLang = "2.0"`, set `treatAsThreat = "UNDEFINED"` and
  `networkQuarantine = false` (scheduled rules cannot mitigate), and check that
  `run_interval_minutes` is valid for the `lookback_window_minutes` you chose.
- `correlation` rules require `entity`, `match_in_order`, and 1 to 10 subqueries.
- Listing existing rules always passes `isLegacy=false`, so scheduled rules are never missed
  during the create-or-update lookup.
- New rules are created in `Draft`; activation is a deliberate, separate step.
