# Playbook: Detection as Code (DaC)

Stand up a Detection-as-Code pipeline for a SentinelOne tenant: detection engineers author
rules as text files in Git, a pull request triggers automated validation and review, and a
merge to the main branch syncs the changed rules to the SentinelOne Custom Detection Rule API.
The whole thing runs from one short prompt, for example `set up detection as code for the
<site> site` or `scaffold a DaC repo and sync the example rules`.

This is an orchestration playbook. It does not reimplement the Custom Detection API, PowerQuery,
or S1QL mechanics; it scaffolds a starter repository from `assets/detection-as-code-starter/`,
renders it for the customer, and drives the sync engine and the Mgmt Console API to validate and
deploy. Unlike the other solutions in this skill (which deploy SDL artifacts INTO the tenant),
DaC sets up a Git + CI workflow that lives OUTSIDE the tenant and pushes detection rules in.

## What DaC gives you (from the source blog, mapped to this playbook)

A Detection Engineer creates a detection rule, pushes it to a branch, opens a pull request that
triggers automated validation and review, and on merge an automation pushes the rule to the SIEM.
Alerts are then monitored and rules refined, a continuous improvement loop. The benefits: version
history and audit on every change, easy backup and restore, a four-eyes review gate, and
text-based rules that are easy to read, diff, and reuse across environments.

The blog's steps map directly onto this playbook:

| Blog step | This playbook |
|---|---|
| Step 1: prepare a standardized template | The TOML rule templates in `assets/detection-as-code-starter/detections/` plus `rule.schema.json` |
| Step 2: prepare the repository (structure, branch protection, CODEOWNERS, RBAC) | Step 3 below + the scaffolded `.github/CODEOWNERS` and the branch-protection checklist |
| Step 3: prepare automation (linting + SIEM synchronization) | The `dac_sync.py` engine + CI workflows for GitHub, GitLab, and Azure |
| Afterword: monitor and refine | Step 7 below |

The blog uses a single JSON file as its example but notes that engineers prefer TOML for
readability and extensibility. This playbook standardizes on TOML authoring and converts to the
API's JSON at sync time, so you get both.

## The one-line prompt

The user asks to set up DaC and that is enough to start. Examples that should run this playbook:
`set up detection as code`, `scaffold a DaC repo for <site>`, `automate our detections as code`,
`build the detection-as-code pipeline and sync the examples to <site>`. Discover the rest; ask
only the few questions in Step 1.

## Parameters (ask once, with defaults pre-filled)

| Parameter | How to get it | Default |
|---|---|---|
| `SITE` / `SCOPE` | the tenant site (or account) rules deploy to | ask; resolve name to siteId |
| `CI_PLATFORM` | GitHub Actions, GitLab CI, or Azure Pipelines | GitHub Actions |
| `REPO_TARGET` | where the scaffold is written (a new folder, or push to a Git remote) | a local folder the user names |
| `RULE_TYPES` | which of events / scheduled / correlation to seed examples for | all three |
| `ACTIVATE` | whether synced rules go live or stay Draft | Draft (never auto-activate) |

Keep it to one compact question set. Never deploy before parameters are confirmed.

## Step 0: confirm prerequisites

The source blog lists three prerequisites; confirm them before scaffolding:

1. **A Git repository** on any platform (GitHub, GitLab, Azure Repos). Basic Git knowledge is
   assumed. The scaffold is platform-neutral; only the CI file differs.
2. **An automation engine.** This playbook ships ready-to-use CI for GitHub Actions, GitLab CI,
   and Azure Pipelines. Any of them, or a SOAR/cron runner calling `dac_sync.py`, works.
3. **A SentinelOne API token** with Custom Detection Rule create/update permission, stored as a
   CI secret (`S1_CONSOLE_API_TOKEN`), never committed. Generate it from Settings, Users,
   Service Users. The console URL goes in `S1_CONSOLE_URL`.

Confirm the tenant has the **Scheduled Detections** capability if scheduled rules are in scope
(check the site licenses for Singularity Data Lake + Scheduled Detections). If
not, scheduled-rule syncs return a feature-not-enabled error: surface that to the user rather
than downgrading the rule.

## Step 1: collect parameters and resolve the site

Ask the compact parameter set. Resolve the site name to a siteId with the Mgmt Console API
(`GET /web/api/v2.1/sites?name=<name>`); console site names can contain spaces, so prefer an
exact-name match and fall back to the closest. Capture the `accountId` too, some deployments
scope at account level. Confirm the console/tenant before writing anything.

## Step 2: scaffold the repository from the starter

Copy `assets/detection-as-code-starter/` to the user's `REPO_TARGET` and render it:

```
detection-as-code/
├── detections/{endpoint,identity,cloud}/   # one rule per .toml, grouped by target system
├── scripts/dac_sync.py                      # validate + convert + idempotent sync (CI calls this)
├── scripts/dac_lint.py                      # local-only validation / pre-commit hook
├── rule.schema.json                         # editor validation for the TOML model
├── .github/workflows/{lint,sync}.yml        # GitHub Actions (primary)
├── .github/CODEOWNERS                        # review accountability
├── ci/gitlab/.gitlab-ci.yml                  # GitLab equivalent
└── ci/azure/azure-pipelines.yml              # Azure DevOps equivalent
```

Render tokens:

- In every example rule's `[scope]`, set `site = "<SITE>"` (or `site_ids` / `account_ids`).
- In `.github/CODEOWNERS`, replace `@your-org/...` with the customer's real teams.
- Keep only the CI file for `CI_PLATFORM` at the repo root (move the others, or leave them under
  `ci/` as references). For GitHub, the workflows already sit at `.github/workflows/`.
- Trim the seeded example rules to the `RULE_TYPES` requested.

The folder names under `detections/` are organisational only; the sync engine walks the whole
tree. A per-target-system layout (endpoint / identity / cloud) matches the blog's recommendation.

## Step 3: set up the repository controls (the manual, one-time part)

These are the blog's Step 2 controls. They need repo-admin access and are configured in the Git
platform UI, not by the sync engine:

1. **Branch protection on `main`:** require a pull request before merging, require approvals
   (this is the four-eyes gate), and require the `lint` check to pass. On GitHub this needs the
   repo to be in a Team or Enterprise org.
2. **Role-based access (RBAC):** assign collaborators the least-privilege role they need (read /
   triage / write / maintain / admin on GitHub; equivalents elsewhere). Roles are
   org-specific, do not prescribe a one-size-fits-all mapping.
3. **CODEOWNERS:** the scaffolded `.github/CODEOWNERS` auto-requests review from the right team
   on every PR. Protect the file itself by listing `/.github/CODEOWNERS` and `/.github/` under
   owners so it cannot be changed unreviewed.

Walk the user through these in their platform; they cannot be set via the detection API. Provide
the exact click-path for their platform if asked (GitHub: Settings, Branches / Rules; Settings,
Collaborators and teams).

## Step 4: wire the automation

The scaffold ships two automations, matching the blog (linting + SIEM synchronization), for all
three CI platforms. The logic lives once in `scripts/dac_sync.py`; CI just calls it.

1. **Lint on pull request.** Runs `dac_sync.py --lint` on changed rule files. It parses the
   TOML/JSON/YAML, converts each rule to the API envelope, and enforces every API constraint
   locally (enums, required fields, the run-interval/lookback relationship, the pipe-in-events
   guard). Bad rules fail the PR check, never production. Require this check in branch protection.
2. **Sync on merge.** Runs `dac_sync.py --sync --changed-only` on push to `main`. It computes
   the rules changed in the merged range (`BASE_SHA..HEAD_SHA`), converts them, and performs an
   idempotent create-or-update against the Custom Detection API. It writes `deployed_rules.json`
   as an audit/rollback manifest, uploaded as a CI artifact.

Set the CI secrets: `S1_CONSOLE_API_TOKEN` (secret) and `S1_CONSOLE_URL` (secret or variable).
If the console is not reachable from cloud-hosted runners, point the workflow at a self-hosted
runner that can reach `*.sentinelone.net` (the blog uses a self-hosted runner for exactly this).

## Step 5: the rule format (author in TOML, deploy as JSON)

Rules are authored in TOML and converted to the Custom Detection API JSON at sync time. Three
rule types are supported; the converter applies the confirmed API rules so a mistake fails in
lint, not in the console.

| Type | `query_type` | Body field | Fires | Mitigation | API specifics the converter enforces |
|---|---|---|---|---|---|
| Single event (STAR) | `events` | `s1ql` (boolean S1QL) | per event, real time | yes | rejects a pipe `|` (that is PowerQuery); `queryLang` left at 1.0 |
| Correlation | `correlation` | `[correlation]` + `[[correlation.subqueries]]` | when subqueries match in window | yes | requires `entity`, `match_in_order`, 1 to 10 subqueries; `window_minutes` in {1,5,10,30,60,240,480,720}; converter sets `queryLang` 2.0 (the API requires it) |
| Scheduled | `scheduled` | `[scheduled].query` (PowerQuery) | on interval over lookback | no | forces `queryLang` 2.0, `treatAsThreat` UNDEFINED, `networkQuarantine` false; checks run-interval vs lookback |

Every example seeds with `status = "Draft"` so it never fires until reviewed. Mitigation fields
(`treat_as_threat = "Malicious"`, `network_quarantine = true`) are only valid on `events` and
`correlation` rules; the converter rejects them on scheduled rules.

The full field reference is `rule.schema.json` (editors with TOML schema support validate as you
type). The three seed files under `detections/` are working examples of each type.

## Step 6: validate and deploy (dry run first)

Always preview before deploying:

1. **Lint** locally or in CI: `python3 scripts/dac_sync.py --lint detections`.
2. **Dry run** to see the exact JSON that will be sent, with no API call:
   `python3 scripts/dac_sync.py --dry-run detections`. Show the user the rendered envelopes.
3. **Deploy.** In production this is the on-merge CI job. For the initial bootstrap (or a wiring
   test), run it directly from a host that can reach the console:
   `S1_CONSOLE_URL=... S1_CONSOLE_API_TOKEN=... python3 scripts/dac_sync.py --sync --site "<SITE>"`.
   New rules are created in `Draft`; activation is deliberate and separate.
4. **Verify** with the Mgmt Console API, always passing `isLegacy=false` so scheduled rules are
   not silently omitted: `GET /web/api/v2.1/cloud-detection/rules?isLegacy=false&name__contains=<name>`.
5. **Re-run** the sync to prove idempotency: the second run updates in place (PUT), it does not
   create duplicates.

To roll back, `python3 scripts/dac_sync.py --rollback deployed_rules.json` deletes exactly the
rules in the manifest.

## Step 7: monitor and refine (the continuous loop)

The blog leaves monitoring and tuning as environment-dependent. Close the loop with the rest of
this skill and the Mgmt Console API:

- Triage the alerts the rules generate (UAM: `uam_list_alerts`, or `GET /cloud-detection/alerts`).
- For noisy rules, open a PR that adds an exclusion (see the `scheduled-detection-exclusions`
  playbook) or tightens the query, review, merge, and the sync updates the live rule.
- Track effectiveness over time with an SDL dashboard (the `sdl-dashboard` skill).
- Optionally schedule a recurring drift check that lists live rules (`isLegacy=false`) and diffs
  them against the repo, so a console-side manual edit is caught and reconciled back into Git.

## Deploy / sync gotchas (confirmed against the live API)

- **Listing always needs `isLegacy=false`.** Without it the API silently omits scheduled
  PowerQuery rules, so the create-or-update lookup would wrongly think a rule is new and create a
  duplicate. The sync engine always passes it.
- **Events rules reject pipe syntax.** A PowerQuery body in an `events` rule returns HTTP 400.
  Piped PowerQuery belongs in a `scheduled` rule (`queryLang` 2.0). The linter catches this.
- **Scheduled rules cannot mitigate.** `treatAsThreat` must be `UNDEFINED` and
  `networkQuarantine` false; the verdict surfaces via severity. The converter enforces this.
- **Correlation rules require `queryLang` 2.0.** Confirmed live: omitting it returns HTTP 400
  "query lang must be 2.0", even though the subquery bodies can be boolean S1QL. Only single-event
  `events` rules use 1.0. The converter sets 2.0 for both scheduled and correlation rules.
- **`run_interval_minutes` depends on `lookback_window_minutes`:** min 1 for lookback < 60, 5 up
  to 360, 15 up to 10080, 60 up to 43200. The linter checks the relationship.
- **New rules are created in `Draft`** regardless of the requested status; activation is a
  separate step. Keep it that way so a merge never silently arms a live, mitigating rule.
- **`queryLang` 2.1 is not valid** (only 1.0 and 2.0). Do not copy older bundles that use 2.1.
- The blog's curl example keys idempotency off the error string "There is already a rule with
  same name in the scope". The engine instead looks the rule up by name (`isLegacy=false`) and
  PUTs, which is more robust than string-matching an error message.

## Dependencies (load as needed)

- `mgmt-console-api` (or the `s1-secops-mcp` `s1_api_*` tools) for site resolution,
  the Custom Detection Rule API, and verification listing. The Custom Detection Rule schema and
  every gotcha above are confirmed there.
- `powerquery` to author or validate the PowerQuery body of a scheduled rule, and
  S1QL for events/correlation rules.
- `sdl-dashboard` for the optional effectiveness dashboard in Step 7.

## Assets

`assets/detection-as-code-starter/` is the whole scaffold rendered into the user's repo:

- `scripts/dac_sync.py` - the validate + convert + idempotent-sync engine (zero dependencies on
  Python 3.11+; ships a built-in TOML fallback for older interpreters). The one place the logic
  lives, so a laptop run and a CI run behave identically.
- `scripts/dac_lint.py` - local-only validation wrapper, suitable as a pre-commit hook.
- `rule.schema.json` - JSON Schema of the TOML rule model for editor validation.
- `detections/endpoint/example_encoded_powershell.toml` - single-event (events) example.
- `detections/identity/example_correlation_brute_then_success.toml` - correlation example.
- `detections/cloud/example_scheduled_firewall_c2.toml` - scheduled PowerQuery example.
- `.github/workflows/lint.yml` and `sync.yml` - GitHub Actions (lint on PR, sync on merge).
- `.github/CODEOWNERS` - review accountability template.
- `ci/gitlab/.gitlab-ci.yml`, `ci/azure/azure-pipelines.yml` - the same two automations on the
  other platforms.
- `.gitignore` - keeps tokens and run manifests out of version control.
- `README.md` - the starter repo's own readme for the detection-engineering team.
