# Contributing to AI-SIEM

Thanks for helping build the library. Contributions of parsers, dashboards,
detections and workflows are all welcome.

## Before you start

- Search existing issues and pull requests to avoid duplicating work.
- For anything larger than a single component, open an issue first so we can
  agree on the approach.
- By contributing you agree your work is released under the repository's
  [AGPL-3.0 license](LICENSE).
- Report security problems privately, following [SECURITY.md](SECURITY.md).
- Participation is governed by our [Code of Conduct](CODE_OF_CONDUCT.md).
- Contributors are celebrated in [CONTRIBUTORS.md](CONTRIBUTORS.md)—you will be added when your first PR merges.

## Where things go

| Type | Location |
| ---- | -------- |
| Parser | `parsers/community/<vendor>_<product>-latest/` |
| Dashboard | `dashboards/community/<name>-latest/` |
| Detection | `detections/community/<name>-latest/` |
| Workflow / playbook | `workflows/community/<vendor>/<name>/` |
| Pipeline transform | `pipelines/` (see the README in that tree) |
| Monitor script | `monitors/` |

Every component directory contains its definition file plus a
**`metadata.yaml`** (use the `.yaml` extension, not `.yml`). Naming follows
`vendor-usecase-vX.Y.<ext>`, for example `zscaler_http_access-v1.0.conf`.

## Required metadata

- **Parsers:** `datasource_vendor`, `dataSource`, `format`
  (gron | json | xml | raw | syslog), `ingestion_method`
- **Dashboards:** `data_dependencies`, `usecase_type`, `usecase_action`
- **Detections:** `mitre_tactic_technique`, `search_type`, `severity`

Parsers should map to OCSF; start from `parsers/sentinelone/PARSER_TEMPLATE.conf`
and include sample logs under `tests/fixtures/`.

## Never include

- real credentials, tokens, customer names, hostnames, IPs or tenant IDs
  (sanitize sample logs and exported JSON before committing)
- compiled binaries or archives

## Pull requests

1. Fork and branch from `main`.
2. Keep each PR focused on one component or one concern.
3. Fill in the PR template, including how you tested the change.
4. Automated secret scanning must pass, and at least one code owner must
   approve before merge.
5. Add a line under **Unreleased** in [CHANGELOG.md](CHANGELOG.md) for
   user-visible changes.

## Python changes (`monitors/`)

Edit `requirements.in`, then regenerate the hash-locked file:

```bash
pip-compile --generate-hashes --output-file requirements.txt requirements.in
```
