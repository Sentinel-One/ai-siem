# sdl-api (Claude skill)

A Claude skill wrapping the SentinelOne **Singularity Data Lake (SDL) API** for query and configuration-file management on a Scalyr/SDL/XDR tenant. Covers the SDL query methods (`query`, `numericQuery`, `facetQuery`, `timeseriesQuery`, `powerQuery`) and the GraphQL configuration-file operations (`configFiles`, `configFile`, `addConfigFile`, `deleteConfigFile`) with a Python client, a CLI, and per-method reference docs. Raw-log ingestion has moved to the HEC path (see `mgmt-console-api`).

## Install

Copy this folder into your user skills directory:

```bash
cp -r sdl-api ~/.claude/skills/
```

In Cowork/Claude Code, the path is:

```text
/sessions/<session>/mnt/.claude/skills/sdl-api/
```

## Configure

Two values, and only two. The SDL API lives under `<console>/sdl` on the Management
Console host, so the console URL and the console API token are all it needs.

### With s1-secops-mcp (recommended)

Set them as environment variables in `claude_desktop_config.json` inside the
`s1-secops-mcp` server entry. No `credentials.json` file is needed:

```json
"env": {
  "S1_CONSOLE_URL":       "https://usea1-acme.sentinelone.net",
  "S1_CONSOLE_API_TOKEN": "eyJ...your-token..."
}
```

### Without s1-secops-mcp (direct skill use)

Drop a `credentials.json` into your Cowork project folder. The plugin's SessionStart
hook auto-discovers it; run `bash scripts/bootstrap_creds.sh` to refresh manually:

```json
{
  "S1_CONSOLE_URL":       "https://usea1-acme.sentinelone.net",
  "S1_CONSOLE_API_TOKEN": "eyJ...your-token..."
}
```

Generate the token in the S1 Console → Settings → Users → My User → **API Token**.

### Fields

| Field | Required | Purpose |
|---|---|---|
| `S1_CONSOLE_URL` | yes | Console host. The client derives the SDL base as `<console>/sdl`. |
| `S1_CONSOLE_API_TOKEN` | yes | Authorises every query and config method. Sent as `Authorization: Bearer`. |
| `SDL_S1_SCOPE` | only when multi-scope | Set when the token spans multiple sites or accounts. Format `<accountId>:<siteId>` for site scope, `<accountId>` for account scope. |

One token covers all of it: the query methods and the GraphQL configuration-file
operations. The scoped SDL keys are retired.

When using `s1-secops-mcp`, environment variables set in `claude_desktop_config.json` take priority. When using skills directly, environment variables set in your shell override the credentials file.

## Quick test

```bash
pip install requests
cd ~/.claude/skills/sdl-api
python tests/smoke_test.py
```

The smoke test exercises the query and configuration methods end-to-end: runs `query` / `facetQuery` / `numericQuery` / `timeseriesQuery` / `powerQuery`, then `configFiles` + `configFile` by udoId + a full `put_config_file` create→update→stale-version→delete round-trip on a throwaway `/lookups/sdl_skill_smoke_…` path. Reports a per-method pass/fail line.

## CLI

```bash
python scripts/sdl_cli.py config-files --prefix /dashboards/
python scripts/sdl_cli.py config-file --name /logParsers/MyParser
python scripts/sdl_cli.py config-file --udo-id 6554761743556608   # dashboards

python scripts/sdl_cli.py power-query "dataset='accesslog' | group count() by status" --start 1h
python scripts/sdl_cli.py query "tag='ingestionFailure'" --start 1h --max 20
python scripts/sdl_cli.py facet-query srcIp --filter "status >= 400" --start 1h
python scripts/sdl_cli.py numeric-query --function count --start 1h --buckets 30
python scripts/sdl_cli.py timeseries-query --function count --filter "*" --start 1h --buckets 60

python scripts/sdl_cli.py put-config-file --name /datatables/MyTable --content-file ./table.csv
python scripts/sdl_cli.py delete-config-file --name /datatables/Stale
```

The CLI subcommands are `config-files`, `config-file`, `put-config-file`, `delete-config-file`, `query`, `power-query`, `facet-query`, `numeric-query`, and `timeseries-query`. The legacy `list-files` / `get-file` / `put-file` subcommands remain but use the incomplete REST surface; prefer the `config-*` set.

**Log/event ingestion is not part of this CLI.** The former `upload-logs` and `add-events` subcommands were removed when ingestion moved to the HEC endpoint. To ingest raw logs or events, use the `hec_ingest` tool in `s1-secops-mcp` (posts to `S1_HEC_INGEST_URL` and applies a named parser via `sourcetype`).

## Python

```python
import sys; sys.path.insert(0, "scripts")
from sdl_client import SDLClient

c = SDLClient()

# Pipeline query (preferred general-purpose tool)
r = c.power_query("status >= 100 status <= 599 | group count() by status", start_time="24h")

# Stream every raw match across continuation tokens
for m in c.iter_query(filter="tag='ingestionFailure'", start_time="24h", max_total=500):
    ...

# Configuration files (GraphQL: the complete surface)
files  = c.config_files()                     # every file, including udoId-addressed dashboards
parser = c.config_file(name="/logParsers/MyParser")
c.put_config_file(name="/logParsers/MyParser", content="// parser body",
                  expected_version=parser["version"])

# Dashboards are addressed by udoId on update; a name-addressed write duplicates them.
dash = [f for f in files if f["name"] == "/dashboards/SOC Overview"][0]
c.put_config_file(udo_id=dash["udoId"], content=body, expected_version=dash["version"])
```

The client picks the right key per method automatically, retries on 429/5xx/`error/server/backoff` with exponential backoff honouring `Retry-After`, and returns parsed JSON. Errors surface as `SDLAPIError` with `.status` and `.body`.

## Layout

- `SKILL.md`: instructions Claude reads when the skill triggers
- `scripts/bootstrap_creds.sh`: idempotent helper to copy workspace creds into the sandbox-local path
- `scripts/sdl_client.py`: `SDLClient` (console token, `Bearer` auth, retries, `iter_query` pagination, GraphQL config-file operations)
- `scripts/sdl_cli.py`: shell CLI covering every method
- `references/methods.md`: per-method reference (params, defaults, response shape, field requirements)
- `references/auth_and_limits.md`: key matrix, console-token + S1-Scope rules, CPU leaky-bucket model, daily caps, 2026-03-19 8 QPS cap
- `references/integration_patterns.md`: ingestion moved to HEC (pointer)
- `tests/smoke_test.py`: end-to-end test that hits every method

## Why this is separate from `mgmt-console-api`

The SDL API is a different surface: JSON over `Bearer` (not `ApiToken`), a different URL namespace (`/api/...` not `/web/api/v2.1/...`), and its own key system. It's the path for running PowerQueries against SDL and editing parsers/dashboards/alerts/lookups programmatically. Raw-log ingestion is via HEC (see `mgmt-console-api`). For agents, threats, sites, Mgmt Console resources: use `mgmt-console-api`. For authoring PQ query bodies: use `powerquery`.
