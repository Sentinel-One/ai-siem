# sdl-api (Claude skill)

A Claude skill wrapping the SentinelOne **Singularity Data Lake (SDL) API** for ingest, query, and configuration file management on a Scalyr/SDL/XDR tenant. Covers all 10 SDL methods with a Python client, a CLI, and per-method reference docs.

## Install

Copy this folder into your user skills directory:

```bash
cp -r sdl-api ~/.claude/skills/
```

In Cowork/Claude Code, the path is:

```
/sessions/<session>/mnt/.claude/skills/sdl-api/
```

## Configure

### With s1-secops-mcp (recommended)

Set credentials as environment variables in `claude_desktop_config.json` inside the `s1-secops-mcp` server entry. No `credentials.json` file is needed:

```json
"env": {
  "SDL_XDR_URL":          "https://xdr.us1.sentinelone.net",
  "S1_CONSOLE_API_TOKEN": "eyJ...your-token...",
  "SDL_LOG_READ_KEY":     "0tzj...",
  "SDL_CONFIG_READ_KEY":  "0MQTx...",
  "SDL_CONFIG_WRITE_KEY": "0mXas6PD..."
}
```

### Without s1-secops-mcp (direct skill use)

The SDL API has four scoped key types plus (optionally) the same management-console API token used by `mgmt-console-api` (`S1_CONSOLE_API_TOKEN`). Drop a `credentials.json` into your Cowork project folder with the keys you need (see the **Credentials** section of `mcp/s1-secops-mcp/README.md` for all available keys). The plugin's SessionStart hook auto-discovers it; run `bash scripts/bootstrap_creds.sh` to refresh manually:

```json
{
  "SDL_XDR_URL":          "https://xdr.us1.sentinelone.net",
  "S1_CONSOLE_API_TOKEN": "eyJ...your-token...",
  "SDL_LOG_READ_KEY":     "0tzj/CPYT...",
  "SDL_CONFIG_READ_KEY":  "0MQTxgj...",
  "SDL_CONFIG_WRITE_KEY": "0mXas6PD..."
}
```

| Key | Methods unlocked |
|-----|-----------------|
| Log Read Access    | `query`, `numericQuery`, `facetQuery`, `timeseriesQuery`, `powerQuery` |
| Configuration Read | Log Read + `getFile`, `listFiles` |
| Configuration Write| Everything above + `putFile` |
| Console user token | All query + config methods. |

Generate SDL keys in SDL Console → your-user menu → **API Keys**. Scope-specific (a site-scoped key only sees that site).

### Which fields do I need?

- **`base_url`**: always required.
- **SDL keys**: fill in only the ones that match what you want the skill to do. Running queries? `log_read_key`. Reading parsers/dashboards? `config_read_key`. Editing/deleting them? `config_write_key`. If you only ever need to query, you can skip the others.
- **`S1_CONSOLE_API_TOKEN`**: optional alternative to SDL keys. The same management-console JWT used by `mgmt-console-api` works for every SDL method. Useful if you already have a console token and don't want to generate a second set of keys. Leave blank if you're using the scoped SDL keys. (Legacy alias `SDL_CONSOLE_API_TOKEN` is still recognised but emits a deprecation warning.)
- **`SDL_S1_SCOPE`**: only relevant when `S1_CONSOLE_API_TOKEN` is set **and** that user has access to multiple sites or accounts. Format: `<accountId>:<siteId>` for site scope, `<accountId>` for account scope. Ignored when SDL keys are used.

The client picks the narrowest matching key per method (principle of least privilege). If you fill in all 4 SDL keys, each config field maps to one method group:

| Key | Primary method(s) in the client |
|---|---|
| `log_read_key`     | `query`, `numericQuery`, `facetQuery`, `timeseriesQuery`, `powerQuery` |
| `config_read_key`  | `listFiles`, `getFile` |
| `config_write_key` | `putFile` |

`console_api_token` is only used as a fallback for any of the above when the matching SDL key is blank.

When using `s1-secops-mcp`, environment variables set in `claude_desktop_config.json` take priority. When using skills directly, environment variables set in your shell override the credentials file.

## Quick test

```bash
pip install requests
cd ~/.claude/skills/sdl-api
python tests/smoke_test.py
```

The smoke test exercises the query and configuration methods end-to-end: runs `query` / `facetQuery` / `numericQuery` / `timeseriesQuery` / `powerQuery`, then `listFiles` + `getFile` + a full `putFile` create→update→delete round-trip on a throwaway `/lookups/sdl_skill_smoke_…` path. Reports a per-method pass/fail line.

## CLI

```bash
python scripts/sdl_cli.py list-files
python scripts/sdl_cli.py get-file /logParsers/MyParser

python scripts/sdl_cli.py power-query "dataset='accesslog' | group count() by status" --start 1h
python scripts/sdl_cli.py query "tag='ingestionFailure'" --start 1h --max 20
python scripts/sdl_cli.py facet-query srcIp --filter "status >= 400" --start 1h
python scripts/sdl_cli.py numeric-query --function count --start 1h --buckets 30
python scripts/sdl_cli.py timeseries-query --function count --filter "*" --start 1h --buckets 60

python scripts/sdl_cli.py put-file /lookups/MyTable --content-file ./table.json
python scripts/sdl_cli.py put-file /lookups/Stale --delete
```

The CLI subcommands are `list-files`, `get-file`, `put-file`, `query`, `power-query`, `facet-query`, `numeric-query`, and `timeseries-query`.

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

# Configuration files
paths  = c.list_files()["paths"]
parser = c.get_file("/parsers/MyParser")
c.put_file("/parsers/MyParser", content="// parser body", expected_version=parser["version"])
```

The client picks the right key per method automatically, retries on 429/5xx/`error/server/backoff` with exponential backoff honouring `Retry-After`, and returns parsed JSON. Errors surface as `SDLAPIError` with `.status` and `.body`.

## Layout

- `SKILL.md`: instructions Claude reads when the skill triggers
- `<project folder>/credentials.json`: credentials (set `SDL_XDR_URL` and the keys you need); auto-discovered by the plugin's SessionStart hook
- `scripts/bootstrap_creds.sh`: idempotent helper to copy workspace creds into the sandbox-local path
- `scripts/sdl_client.py`: `SDLClient` (auto key selection across 3 scoped keys + console token, `Bearer` auth, retries, `iter_query` pagination)
- `scripts/sdl_cli.py`: shell CLI covering every method
- `references/methods.md`: per-method reference (params, defaults, response shape, field requirements)
- `references/auth_and_limits.md`: key matrix, console-token + S1-Scope rules, CPU leaky-bucket model, daily caps, 2026-03-19 8 QPS cap
- `references/integration_patterns.md`: ingestion moved to HEC (pointer)
- `tests/smoke_test.py`: end-to-end test that hits every method

## Why this is separate from `mgmt-console-api`

The SDL API is a different surface: JSON over `Bearer` (not `ApiToken`), a different URL namespace (`/api/...` not `/web/api/v2.1/...`), and its own key system. It's the path for running PowerQueries against SDL and editing parsers/dashboards/alerts/lookups programmatically. Raw-log ingestion is via HEC (see `mgmt-console-api`). For agents, threats, sites, Mgmt Console resources: use `mgmt-console-api`. For authoring PQ query bodies: use `powerquery`.
