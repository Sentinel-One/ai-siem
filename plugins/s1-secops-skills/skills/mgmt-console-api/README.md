# mgmt-console-api (Claude skill)

A Claude skill wrapping the SentinelOne Management Console API (Swagger 2.1, 781 operations, 113 tags) plus two GraphQL surfaces: **Unified Alert Management** (modern multi-source alert triage and bulk actions) and **Purple AI** (natural-language SDL queries).

## Install

Copy this folder into your user skills directory:

```bash
cp -r mgmt-console-api ~/.claude/skills/
```

In Cowork/Claude Code, the path is:

```
/sessions/<session>/mnt/.claude/skills/mgmt-console-api/
```

## Configure

### With s1-secops-mcp (recommended)

Set credentials as environment variables in `claude_desktop_config.json` inside the `s1-secops-mcp` server entry. No `credentials.json` file is needed:

```json
"env": {
  "S1_CONSOLE_URL":       "https://usea1-acme.sentinelone.net",
  "S1_CONSOLE_API_TOKEN": "eyJ...your-api-token...",
  "S1_HEC_INGEST_URL":    "https://ingest.us1.sentinelone.net"
}
```

### Without s1-secops-mcp (direct skill use)

Drop a `credentials.json` file into your Cowork project folder (see the **Credentials** section of `mcp/s1-secops-mcp/README.md` for all available keys). The plugin's SessionStart hook auto-discovers it. To trigger a manual refresh: `bash scripts/bootstrap_creds.sh`.

```json
{
  "S1_CONSOLE_URL": "https://usea1-acme.sentinelone.net",
  "S1_CONSOLE_API_TOKEN": "eyJ...your-api-token...",
  "S1_HEC_INGEST_URL": "https://ingest.us1.sentinelone.net"
}
```

Create the API token in the S1 console: Settings → Users → Service Users → Generate API Token. Scope it to the minimum permissions needed.

`S1_HEC_INGEST_URL` is the SentinelOne HEC ingest host, used by the UAM Alert Interface for OCSF alert/indicator ingest (and for log ingest via HEC). It is region-specific; look up your region's URL in [SentinelOne Endpoint URLs by Region](https://community.sentinelone.com/s/article/000004961). Only required if you push alerts/indicators into UAM via `UAMAlertInterfaceClient`; the read-side UAM GraphQL works without it.

## Quick test

```bash
pip install requests
cd ~/.claude/skills/mgmt-console-api
python scripts/s1_client.py
```

Should print the first 5 accounts, then fan out 4 parallel GETs.

## Probe a new tenant (non-destructive)

```bash
python scripts/smoke_test_queries.py --workers 12
```

Enumerates every GET plus a curated allow-list of read-only query POSTs, writes `references/tenant_capabilities.{json,md}`. Read-only: no writes, no agent actions. After the sweep you can filter searches to only confirmed-working endpoints:

```bash
python scripts/search_endpoints.py "threats" --only-works
```

## Orientation

- `references/CAPABILITY_MAP.md`: per-tag verb+resource summary ("I want to…" lookup).
- `references/WORKFLOWS.md`: ready-to-adapt multi-step recipes.
- `references/TAG_INDEX.md`: full 113-tag directory with per-tag reference files.

Unified Alert Management:

```bash
python scripts/call_unified_alerts.py list --filter detectionProduct=EDR --first 10
python scripts/call_unified_alerts.py facets status severity detectionProduct
```

Purple AI natural-language query (requires tenant entitlement for Purple AI):

```bash
python scripts/call_purple.py "show powershell.exe outbound connections in the last 24h, top 10"
```

Purple AI answers questions about SDL telemetry (process/network/file events, indicators, ingested logs). It does *not* answer questions about console entities (alerts, threats, agents): those go through the REST endpoints or Unified Alert Management.

## Layout

- `SKILL.md`: instructions Claude reads when the skill triggers
- `<project folder>/credentials.json` (optional): credentials for direct skill use; auto-discovered by the plugin's SessionStart hook
- `scripts/bootstrap_creds.sh`: idempotent helper to copy workspace creds into the sandbox-local path
- `scripts/s1_client.py`: REST client (auth, pooled HTTP, retries, cursor pagination, parallel `get_many()`, optional cache)
- `scripts/call_endpoint.py`: REST CLI wrapper
- `scripts/search_endpoints.py`: ranked keyword search over the endpoint index (verb-aware, `--only-works` filter)
- `scripts/smoke_test_queries.py`: non-destructive sweep of every GET + safe query POST
- `scripts/purple_ai.py`: Purple AI GraphQL wrapper (`purple_query()`, `PurpleAIError`)
- `scripts/call_purple.py`: Purple AI CLI wrapper
- `scripts/unified_alerts.py`: Unified Alert Management GraphQL wrapper (queries, mutations, triage helpers)
- `scripts/call_unified_alerts.py`: UAM CLI wrapper
- `references/`: endpoint index + per-tag reference docs; `UNIFIED_ALERTS.md` covers the GraphQL UAM surface
- `spec/`: the original Swagger JSON
