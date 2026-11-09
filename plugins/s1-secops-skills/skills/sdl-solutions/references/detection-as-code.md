# Playbook: Detection as Code (native)

Manage SentinelOne Custom Detection rules from Git with the console's native Detection as Code
(DaC) API. Detection engineers keep each rule as a YAML file, one manifest per console says which
scopes receive which files, a pull request shows the exact diff the console will apply, and a
merge to the main branch applies it. The console tracks every DaC-managed rule by its repository
id, so a merge creates, updates, imports, retains or deletes rules as one reviewed change set.

This is an orchestration playbook. The DaC engine runs in the console
(`POST /web/api/v2.1/cloud-detection/rules/parse-vcs`); CI runs it through the official
SentinelOne `detection-as-code` reference repository (GitHub Actions, MIT licence); and the
s1-secops-mcp tools `dac_export`, `dac_diff` and `dac_apply` drive the same API from Claude for
bootstrap, review and repositories without CI. The endpoint contract (multipart bundle, diff
response, export ZIP) is in the `mgmt-console-api` skill's `references/detection-rules.md`,
section "Detection as Code endpoints".

## Invocation prompt (natural language)

Any of these is enough to start; discover the rest and ask only the questions under Parameters:

> "Set up detection as code for the `<site>` site."
>
> "Put our existing custom rules under Git and deploy them on merge."
>
> "Show me what this rules branch would change in the console before we merge."

## Parameters (ask once, with defaults pre-filled)

| Parameter | How to get it | Default |
|---|---|---|
| `CONSOLE` | the console URL the rules deploy to | the console the MCP server is configured for |
| `TARGETS` | the scopes rules deploy to: global, account `<accountId>`, or site `<siteId>` | one site; resolve the name with `GET /web/api/v2.1/sites?name=<name>` |
| `BOOTSTRAP` | start from the rules already in the console, or from the templates | export the existing rules |
| `CI_PLATFORM` | GitHub Actions, GitLab CI or Azure Pipelines | GitHub Actions (the reference workflow) |
| `VCS_REPO` | the repository id and name CI will send | the CI platform's numeric repository id and `<owner>/<repo>` |

Confirm the console and every target scope before any `dac_diff`. Nothing in this playbook writes
to the tenant until a reviewed change set is applied.

## Step 0: prerequisites

1. **DaC is enabled on the tenant.** Enablement is per tenant. A `dac_diff` that returns HTTP 200
   confirms it. If `parse-vcs` is refused as unavailable, report the response verbatim and ask
   the user to have DaC enabled.
2. **Licence:** Endpoint Security Complete or Endpoint Security Core.
3. **A service user for CI** (Policies and settings, User management, Service users), with:
   - a scope that covers every target in every manifest (a global target needs a global token);
   - a role with **Custom Rules** manage;
   - **Perform Advanced Actions**, when any rule sets `hideLogic: true`;
   - **Endpoints: Disconnect from network** and **Endpoint Threats: Mark suspicious / Mark threat**,
     when any rule sets `networkQuarantine: true` or `treatAsThreat: Suspicious|Malicious`.

   The token is stored as a CI secret, never committed.
4. **s1-secops-mcp 1.6.1 or later** for `dac_export`, `dac_diff` and `dac_apply`.

## Step 1: bootstrap from the console (`dac_export`)

Start from what the console already runs, so the first merge adopts those rules instead of
duplicating them.

1. Run `dac_export` with `outputDir` (extracts the files) or `outputFile` (keeps the ZIP).
   It follows `nextCursor` (500 rules per page) up to `maxPages`, and exports every scope the
   token can see. Output layout:
   - `export-summary.json`: `exported`, `limit`, `nextCursor` (percent-encoded; `dac_export`
     decodes it), and `totalItems` (on the first page only);
   - `rules/<scopeLevel>-<scopeId>/exported-rule-<ruleId>.yaml`, one file per rule.
2. Each exported file carries `id: exported-rule-<ruleId>` and `importCustomRuleId: <ruleId>`.
   **Keep both unchanged.** On the first diff the rule is listed under `imports`, and the apply
   brings the live rule under DaC management instead of creating a second one.
3. Commit each file **exactly as exported**. The import is checked against the live rule: a
   changed field fails the diff with `importCustomRuleId '<ruleId>': imported YAML does not match
   the live rule (drifted fields: <field>)`. Make edits in a later pull request, after the
   import has been applied.
4. Export immediately before the import pull request. A file whose rule has since been deleted
   fails with `importCustomRuleId '<ruleId>' does not reference an active rule`.
5. Only `queryLang: "2.0"` rules can be managed as code. A 1.0 rule fails the diff with
   `Only SYQL (queryLang 2.0) rules are supported`; rewrite it in 2.0 operators first (see the
   `powerquery` skill's `references/detection-rules.md`).
6. Each `rules/<scopeLevel>-<scopeId>/` folder becomes one target in the manifest (Step 2).

`s1_api_download` on `/web/api/v2.1/cloud-detection/rules/export-vcs` (with `cursor` for later
pages) returns the same ZIP when the `dac_*` tools are not available.

## Step 2: repository layout and manifest

Use the reference repository's layout so its workflow and script run unchanged:

```text
<rules-repo>/
├── consoles/<console>.yaml          # one manifest per console (bundled as deployments.yaml)
├── detections/                      # rules root: deploy globs are relative to this folder
│   ├── events/<rule-id>.yaml
│   ├── correlation/<rule-id>.yaml
│   ├── scheduled/<rule-id>.yaml
│   └── shared/<rule-id>.yaml        # e.g. rules deployed at account scope
├── detection-as-code.py             # from the reference repository
├── requirements.txt                 # from the reference repository
└── .github/workflows/detection-as-code.yaml
```

Templates: `assets/dac-native/deployments.template.yaml` (single-scope and multi-scope),
`assets/dac-native/rules/events.template.yaml`,
`assets/dac-native/rules/correlation-custom-entity.template.yaml` and
`assets/dac-native/rules/scheduled-entity-mapping.template.yaml`. All three rule templates pass
`dac_diff` once their placeholders are filled. `assets/dac-native/README.md` covers CI.

**Manifest rules** (`consoles/<console>.yaml`):

- `targets.<name>.scopeLevel` is `global`, `account` or `site`. `account` and `site` take a
  `scopeId` written as a quoted string; `global` takes none.
- `deploy.<name>` is a list of globs, relative to the rules root, naming the files that target
  receives. In a glob, `*` also matches subfolders.
- Child scopes inherit parent-scope rules: a rule deployed to an account applies to every site
  under it. Match each rule file from one target only.
- One manifest per console. Two manifests pointing at the same console would each delete the
  other's rules (the reference script refuses that layout).
- `mgmtUri` and `tokenSecret` are read by the reference script and workflow; the `dac_*` tools
  read only `targets` and `deploy`. The API accepts the manifest with or without them.

**Rule file fields:**

| Field | Notes |
|---|---|
| `id` | The key that ties the file to its console rule. Unique in the repository (a duplicate fails the diff: `Duplicate external_id '<id>' found in 2 files`). Changing it creates a new rule. |
| `name` | Must be unique in the tenant. `dac_diff` does not check names against rules outside DaC, so search before merging: `s1_api_get /web/api/v2.1/cloud-detection/rules` with `isLegacy=false` and `name__contains`. |
| `description`, `severity`, `status` | `severity`: Low, Medium, High, Critical. `status`: Draft, Active, Disabled. |
| `expirationMode`, `expiration` | `Permanent`, or `Temporary` with an ISO 8601 `expiration`. |
| `queryType`, `queryLang` | `events`, `correlation` or `scheduled`; `queryLang` is always `"2.0"`. |
| `s1ql` / `correlationParams` / `scheduledParams` | One, matching `queryType`. |
| `treatAsThreat`, `networkQuarantine` | Inline Active Response for `events` and `correlation` rules only. Scheduled rules keep `UNDEFINED` and `false`. |
| `coolOffSettings.renotifyMinutes` | Alert cool-off. |
| `hideLogic` | Hides the query from console users without Perform Advanced Actions. |
| `entityMappings` | `[{columnName, identifierType}]`, at most 3. |
| `deletePolicy` | `Retain` (default) or `Delete`; see Step 5. |
| `importCustomRuleId` | Adopts an existing console rule; see Step 1. |

**Correlation rules with a custom entity:** `entity: Custom` with `entitiesAndFields` as a list
of groups (OR inside a group, AND across groups), `timeWindow.windowMinutes` set to one of 10, 30,
60, 240, 480 or 720 (always set it; 60 for new rules), and 2 to 10 sub-queries. Network Quarantine needs `agent.uuid` as its own group; Treat as Threat also
needs `src.process.storyline.id` or `src.process.uid` as its own group. The full rule set
(built-in entity field sets, field-name pattern, reserved names, the 2,000,000-entity limit) is in
the `powerquery` skill's `references/detection-rules.md`.

**`entityMappings.identifierType`** is one of `agent.uuid`, `cloud_resource_id`,
`distinguished_name`, `hostname`, `mac_addresses`, `object_guid`, `object_sid`,
`serial_number`, `user_principal_name`. Any other value fails the diff (HTTP 400, code 4000010,
`... ValidationError - {'entityMappings': {0: {'identifierType': ['Must be one of: ...']}}}`).
An entry may also carry `columnName` alone.

**What the diff enforces for custom-entity correlation rules:**

- Reserved entity fields are rejected: `[["account.id"]]` fails with code 4000010,
  `entitiesAndFields[0][0] "account.id" rejected by denylist ...`.
- Active Response needs singleton groups: `networkQuarantine: true` without an `["agent.uuid"]`
  group fails with `network_quarantine requires entity key with singleton group [agent.uuid]`;
  `treatAsThreat` other than `UNDEFINED` fails with `treat_as_threat requires entity key with
  singleton groups [agent.uuid] and ([src.process.storyline.id] or [src.process.uid])`.

## Step 3: `dac_diff` is the pull-request gate

Run `dac_diff` on every branch before review, and show the user the summary and the lists.

- **Input:** either `files` (a map of bundle path to file text: `deployments.yaml` plus every rule
  path the deploy globs match) or `repoDir` (the rules root) with `deploymentsFile` (the console
  manifest, bundled as `deployments.yaml`). `vcsRepoId`, `vcsRepoName` and `vcsCommitId` are
  required. `maxItems` trims the change lists in the reply and `outputFile` saves the full
  response.
- **Repository identity:** pass the same `vcsRepoId` and `vcsRepoName` that CI sends for this
  repository (on GitHub, `GITHUB_REPOSITORY_ID` and `<owner>/<repo>`), and the branch head SHA as
  `vcsCommitId`. Ownership of managed rules is keyed on `vcsRepoId`:
  - same `vcsRepoId`, same files: `totalChanges` 0;
  - the same files under a different `vcsRepoId`: HTTP 400 with a global
    `External ID '<id>' is already claimed by another repository for scope site (id: ...)` and,
    per rule, `There is already a rule with same name in the scope`;
  - an empty bundle under a different `vcsRepoId`: all totals 0, and the owning repository's
    rules are untouched.

  Never improvise a repository id: a wrong one cannot take over or remove another repository's
  rules, and with that repository's files it fails the diff.
- **Output:** `summary` (`totalChanges`, `totalCreates`, `totalUpdates`, `totalDeletes`,
  `totalImports`, `totalRetains`) and the lists `creates`, `updates`, `deletes`, `imports`,
  `retains`. Each item carries `externalId` (the rule `id`), `scopeLevel`, `scopeId` and
  `ruleData` (the normalised rule, for example `entity: Custom` comes back as `custom`).
- **A diff writes nothing.** Rule counts before and after a diff are identical.
- **A failed diff is HTTP 400 in one of two shapes.** Parse and schema problems (bad enum value,
  denylisted entity field) come back as `errors[]` with `code` 4000010 and a detail starting
  `Failed to parse rule files: <path>: ...`. Semantic problems come back as
  `data.validationErrors`: `global` (repository-level, such as duplicate ids or ownership) and
  `rules`, each with `externalId`, `filePath`, `scopeLevel`, `scopeId` and `errors[]`. Report
  every message; do not fix and resubmit silently.
- `scopeId` arrives as a JSON number larger than 2^53. Compare scopes against the manifest, not
  against a value a standard JSON parser has rounded.

A diff is read-only, so `dac_diff` runs in read-only mode.

## Step 4: apply on merge, in CI

CI owns the apply. Point the repository at the official reference workflow:

- **GitHub Actions:** copy `detection-as-code.py`, `requirements.txt` and
  `.github/workflows/detection-as-code.yaml` from the reference repository (not shipped in this
  skill). On a pull request it
  validates the repository, runs `diff` per console and posts the summary as a PR comment and a
  check run. On a push to `main` it runs `apply` per console. Add one Actions secret per console,
  named as that manifest's `tokenSecret`.
- **GitLab CI and Azure Pipelines:** run the same script in CLI mode. Snippets with the required
  environment variables are in `assets/dac-native/README.md`.
- **Protect the main branch:** pull request required, at least one approval, the diff check
  required, no direct or force pushes, forking disabled, and secret management limited to the
  owners. A merge to main changes the console.

The apply summary must equal the reviewed diff summary: same counts, same ids in each list.

**`dac_apply`** is for repositories without CI only. Pass it two values from the reviewed
`dac_diff`: `expectedZipSha256` (`bundle.zipSha256`) and `expectedSummary` (`summary`). It refuses
before sending anything if the rebuilt bundle hashes differently, then re-runs the diff and refuses
unless the fresh summary equals `expectedSummary`, then applies. If an apply times out or fails
without an answer, it may have been committed: run `dac_diff` before calling `dac_apply` again.
It is refused in read-only mode. Confirm with the user before calling it, then verify with a rule
search (`isLegacy=false`). Scheduled rules sit in `Activating` for up to an hour before their
first run.

## Step 5: change, retain and delete

| Intent | Change in Git | Result in the console |
|---|---|---|
| Create | Add a rule file matched by a deploy glob | Rule created and DaC-managed |
| Update | Edit the file | Rule updated |
| Import | Add the exported file with `importCustomRuleId` (Step 1) | Existing rule becomes DaC-managed |
| Retain | Remove the file (or its glob) with the default `deletePolicy: Retain` | Rule stays and becomes a normal console rule again |
| Delete | Merge `deletePolicy: Delete` in the file, **then** remove the file in a second merge | Rule deleted |

A delete always takes two merges: the console must have recorded `deletePolicy: Delete` before
the file disappears, otherwise the removal is a Retain. In diff terms: the merge that sets
`deletePolicy: Delete` reports an update (`totalUpdates`); the merge that removes the file
reports the delete (`totalDeletes`), and a Draft rule is gone as soon as it applies. Removing a
file that still has `Retain` reports `totalRetains`.

DaC-managed rules list with `"source": "DAC"` and `"editable": false`. They cannot be edited on
the Detections page, and `PUT /web/api/v2.1/cloud-detection/rules/{id}` returns HTTP 400
`Detection-as-Code managed rules cannot be edited.` Change them in Git. A retained rule loses
`source` and is `editable: true` again, back under normal console management.

Deleting rules through the rule API instead (for example after a Retain) uses
`DELETE /web/api/v2.1/cloud-detection/rules` with `{"filter": {"ids": [...]}}`. Its `affected`
count includes rules that were only disabled because they were still activating: re-list with
`isLegacy=false` and repeat the delete for the ids that remain until none do (see the
`mgmt-console-api` skill's `references/detection-rules.md`).

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `Only SYQL (queryLang 2.0) rules are supported` (often with `Cool Off is not supported for S1QL 1.0 rules`) | A `queryLang: "1.0"` rule | Rewrite with 2.0 operators and set `queryLang: "2.0"` |
| `Duplicate external_id '<id>' found in 2 files` | Two files share an `id` | Give each file a unique `id` |
| `imported YAML does not match the live rule (drifted fields: ...)` | The import file was edited before the import | Commit the exported file unchanged; edit after the import is applied |
| `importCustomRuleId '<ruleId>' does not reference an active rule` | The rule was deleted since the export | Re-export, or drop the file |
| Diff passes, but the name already exists in the tenant | The diff does not check names against non-DaC rules | Rename, or import the existing rule instead of creating a new one |
| Code 4000010 `identifierType: ['Must be one of: ...']` | `entityMappings` value outside the enum | Use a value from the `identifierType` list in Step 2 |
| Code 4000010 `... rejected by denylist` | A reserved field (such as `account.id`) in `entitiesAndFields` | Key the entity on a stable, non-reserved field |
| `network_quarantine requires entity key with singleton group [agent.uuid]` (or the `treat_as_threat` form) | Active Response without its singleton entity groups | Add `["agent.uuid"]` (and `["src.process.uid"]` or `["src.process.storyline.id"]`) as their own groups, or turn the response off |
| `External ID '<id>' is already claimed by another repository` | The diff ran under a different `vcsRepoId` than the owning repository | Use the owning repository's `vcsRepoId` (the one CI sends) |
| `Detection-as-Code managed rules cannot be edited.` on `PUT`, or a read-only rule on the Detections page | The rule is DaC-managed (`source: DAC`, `editable: false`) | Change it in Git |
| A rule removed from Git is still in the console | `deletePolicy` was `Retain` | Merge `deletePolicy: Delete` first, then remove the file |
| HTTP 401 or 403 from the diff | The token's scope does not cover a target, or the role lacks Custom Rules manage | Fix the service user's scope or role |
| HTTP 429 with an nginx HTML body and no `Retry-After` | `parse-vcs` calls back to back | The `dac_*` tools retry with backoff from 2 s; in CI or scripts, back off and run one diff at a time |
| `s1_api_get` on `export-vcs` returns `isLegacy: Unknown field` | s1-secops-mcp older than 1.6.1 injects `isLegacy` | Use `dac_export`, or `s1_api_download` for the ZIP |

## Dependencies (load as needed)

- `mgmt-console-api`: the DaC endpoint contract, rule listing (`isLegacy=false`), site resolution,
  and the rule delete loop (`references/detection-rules.md`).
- `powerquery`: rule bodies, and the correlation and custom-entity rules
  (`references/detection-rules.md`).

## Assets

`assets/dac-native/`:

- `deployments.template.yaml`: the console manifest, single-scope with a multi-scope alternative.
- `rules/events.template.yaml`: a streaming events rule.
- `rules/correlation-custom-entity.template.yaml`: a correlation rule keyed on a custom entity
  (`agent.uuid` AND `src.process.uid`, 60-minute window).
- `rules/scheduled-entity-mapping.template.yaml`: a scheduled PowerQuery rule with
  `entityMappings`.
- `README.md`: how the templates map into the reference repository, and CLI-mode CI for GitLab
  and Azure Pipelines.
