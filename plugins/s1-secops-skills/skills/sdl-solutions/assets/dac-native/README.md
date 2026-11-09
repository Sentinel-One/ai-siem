# Detection as Code templates (native)

Templates for a SentinelOne Detection as Code repository. The console's DaC API does the work
(`POST /web/api/v2.1/cloud-detection/rules/parse-vcs?mode=diff|apply`); CI runs it through the
official SentinelOne `detection-as-code` reference repository on GitHub
(`Sentinel-One/detection-as-code`), which ships `detection-as-code.py`, `requirements.txt` and a
GitHub Actions workflow. The playbook is `references/detection-as-code.md` in the sdl-solutions
skill.

## Where each template goes

| Template | Copy to |
|---|---|
| `deployments.template.yaml` | `consoles/<console>.yaml` |
| `rules/events.template.yaml` | `detections/events/<rule-id>.yaml` |
| `rules/correlation-custom-entity.template.yaml` | `detections/correlation/<rule-id>.yaml` |
| `rules/scheduled-entity-mapping.template.yaml` | `detections/scheduled/<rule-id>.yaml` |

Replace every `<placeholder>`. Each rule's `id` must be unique in the repository and its `name`
unique in the tenant. Adopt existing console rules by exporting them (`dac_export`, or
`GET /web/api/v2.1/cloud-detection/rules/export-vcs`) and committing the exported files
unchanged.

## GitHub Actions

Use the reference repository as is (its files are not shipped here): copy `detection-as-code.py`,
`requirements.txt` and `.github/workflows/detection-as-code.yaml` next to `consoles/` and
`detections/`, and add one
Actions secret per console, named as that manifest's `tokenSecret`. Pull requests get a diff
comment and a check run per console; a push to `main` applies.

## CLI mode (GitLab CI, Azure Pipelines, a laptop)

Outside GitHub Actions the script prints its results instead of posting PR comments. It needs
Python 3 and the hash-pinned packages from the reference `requirements.txt`.

```bash
pip install --no-deps --require-hashes --only-binary=:all: -r requirements.txt
python detection-as-code.py validate                                         # repository checks, no API call
python detection-as-code.py diff  --deployments-file consoles/<console>.yaml # writes nothing
python detection-as-code.py apply --deployments-file consoles/<console>.yaml # changes the console
```

Environment for `diff` and `apply`:

| Variable | Value |
|---|---|
| `API_TOKEN` | the service-user API token for that console (a CI secret) |
| `GITHUB_REPOSITORY` | the repository name, `<group>/<repo>`; sent as `vcsRepoName` |
| `GITHUB_REPOSITORY_ID` | a stable numeric repository id; sent as `vcsRepoId` |
| `HEAD_SHA` | the commit being diffed or applied; sent as `vcsCommitId` |
| `MGMT_URI` | optional; overrides `mgmtUri` from the manifest |

Keep `GITHUB_REPOSITORY_ID` and `GITHUB_REPOSITORY` fixed for the life of the repository: the
console records which repository owns each rule it manages. Use the same values when running
`dac_diff` from Claude.

### GitLab CI

```yaml
# .gitlab-ci.yml
stages: [diff, apply]

.dac:
  image: python:3.12-slim
  variables:
    GITHUB_REPOSITORY: $CI_PROJECT_PATH
    GITHUB_REPOSITORY_ID: $CI_PROJECT_ID
    HEAD_SHA: $CI_COMMIT_SHA
  before_script:
    - "pip install --disable-pip-version-check --no-deps --require-hashes --only-binary=:all: -r requirements.txt"

dac-diff:
  extends: .dac
  stage: diff
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  script:
    - python detection-as-code.py validate
    - API_TOKEN="$DAC_API_TOKEN" python detection-as-code.py diff --deployments-file consoles/<console>.yaml

dac-apply:
  extends: .dac
  stage: apply
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
  script:
    - API_TOKEN="$DAC_API_TOKEN" python detection-as-code.py apply --deployments-file consoles/<console>.yaml
```

Store `DAC_API_TOKEN` as a masked, protected CI/CD variable, and protect the default branch
(merge request approval required, no direct pushes).

### Azure Pipelines

```yaml
# azure-pipelines.yml
trigger:
  branches:
    include: [main]
pr:
  branches:
    include: [main]

pool:
  vmImage: ubuntu-latest

variables:
  - group: dac-secrets            # holds DAC_API_TOKEN as a secret variable

steps:
  - task: UsePythonVersion@0
    inputs:
      versionSpec: "3.12"
  - script: "pip install --disable-pip-version-check --no-deps --require-hashes --only-binary=:all: -r requirements.txt"
    displayName: Install dependencies
  - script: python detection-as-code.py validate
    displayName: Validate repository
  - script: python detection-as-code.py diff --deployments-file consoles/<console>.yaml
    displayName: Diff
    condition: eq(variables['Build.Reason'], 'PullRequest')
    env:
      API_TOKEN: $(DAC_API_TOKEN)
      GITHUB_REPOSITORY: $(Build.Repository.Name)
      GITHUB_REPOSITORY_ID: <stable-numeric-repository-id>
      HEAD_SHA: $(Build.SourceVersion)
  - script: python detection-as-code.py apply --deployments-file consoles/<console>.yaml
    displayName: Apply
    condition: and(succeeded(), eq(variables['Build.SourceBranch'], 'refs/heads/main'), ne(variables['Build.Reason'], 'PullRequest'))
    env:
      API_TOKEN: $(DAC_API_TOKEN)
      GITHUB_REPOSITORY: $(Build.Repository.Name)
      GITHUB_REPOSITORY_ID: <stable-numeric-repository-id>
      HEAD_SHA: $(Build.SourceVersion)
```

Azure repository ids are GUIDs, so set `GITHUB_REPOSITORY_ID` to a fixed numeric value of your
choice and never change it. Secret variables are not exposed to scripts unless mapped in `env`,
as above. Require a pull request with approval and the Diff step on the main branch.
