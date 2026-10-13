# mgmt-console-api (Claude skill)

A Claude skill wrapping the SentinelOne Management Console API (Swagger 2.1, 781 operations, 111 tags) plus two GraphQL surfaces: **Unified Alert Management** (modern multi-source alert triage and bulk actions) and **Purple AI** (natural-language SDL queries).

## Install

Copy this folder into your user skills directory:

```bash
cp -r mgmt-console-api ~/.claude/skills/
```

In Cowork/Claude Code, the path is:

```text
/sessions/<session>/mnt/.claude/skills/mgmt-console-api/
```

## Configure

The skill's primary path is the `s1-secops-mcp` MCP server (see the s1-secops-mcp README: `s1-secops-mcp/README.md` in the s1-secops-skills source repo, `mcp/s1-secops-mcp/README.md` in ai-siem; not shipped in the plugin). It runs on your machine and is the only path that works from Cowork, whose sandbox cannot reach `*.sentinelone.net`.

Credentials live in environment variables or the OS keychain, never in a file and never in an MCP client config `env` block (those are plaintext). Store them once on your machine:

```bash
s1-secops-mcp setup     # prompts without echo, stores in the OS keychain, verifies read-back
s1-secops-mcp status    # shows the source of each value, masked
```

Create the API token in the S1 console: Settings → Users → Service Users → Generate API Token. Scope it to the minimum permissions needed.

`S1_HEC_INGEST_URL` is the SentinelOne ingest host, used by the UAM Alert Interface for OCSF alert ingest (and for log ingest via HEC). It is region-specific; look up your region's URL in [SentinelOne Endpoint URLs by Region](https://community.sentinelone.com/s/article/000004961). Only required if you push alerts into UAM (`uam_post_alert`); the read-side UAM GraphQL works without it.

The Python scripts under `scripts/` are host-only (Claude Code or a terminal). They read the same environment variables or keychain entries as the MCP server.

## Quick test (host only)

```bash
pip install requests          # add keyring on Windows for Credential Manager reads
cd ~/.claude/skills/mgmt-console-api
python scripts/s1_client.py
```

Should print the first 5 accounts, then fan out 4 parallel GETs.

## Probe a new tenant (non-destructive, host only)

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

Unified Alert Management (MCP tools `uam_list_alerts`, `uam_get_alert`, `uam_add_note`, `uam_set_status`, `uam_set_verdict`, `uam_assign_alert`, `uam_available_actions`; host-only CLI below):

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
- `scripts/s1_client.py`: host-only REST client (auth, pooled HTTP, retries, cursor pagination, parallel `get_many()`, optional cache)
- `scripts/call_endpoint.py`: REST CLI wrapper
- `scripts/search_endpoints.py`: ranked keyword search over the endpoint index (verb-aware, `--only-works` filter)
- `scripts/smoke_test_queries.py`: non-destructive sweep of every GET + safe query POST
- `scripts/purple_ai.py`: Purple AI GraphQL wrapper (`purple_query()`, `PurpleAIError`)
- `scripts/call_purple.py`: Purple AI CLI wrapper
- `scripts/unified_alerts.py`: Unified Alert Management GraphQL wrapper (queries, mutations, triage helpers)
- `scripts/call_unified_alerts.py`: UAM CLI wrapper
- `references/`: endpoint index + per-tag reference docs; `UNIFIED_ALERTS.md` covers the GraphQL UAM surface
- `spec/`: the original Swagger JSON
