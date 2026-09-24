# Credentials

This is the canonical credentials reference for both install paths (the Docker quick start and the individual MCP install). It covers every key, where to find each one, the two token types, and the resolution order. The ready-to-paste `claude_desktop_config.json` block lives with each install path: follow your path in the [README Installation section](../README.md#installation) and fill in the keys documented here.

---

## credentials.json keys

```json
{
  "S1_CONSOLE_URL":       "https://usea1-yourorg.sentinelone.net",
  "S1_CONSOLE_API_TOKEN": "eyJ...your-api-token...",
  "S1_HEC_INGEST_URL":    "https://ingest.us1.sentinelone.net",
  "S1_HEC_TOKEN":         "<SDL Log Write Key, optional; hec_ingest needs it>"
}
```

| Key | Required for | How to get it |
|---|---|---|
| `S1_CONSOLE_URL` | Everything | Your console URL, e.g. `https://usea1-acme.sentinelone.net`. No trailing slash. |
| `S1_CONSOLE_API_TOKEN` | Mgmt Console REST, PowerQuery LRQ, UAM GraphQL, Purple AI GraphQL, SDL config ops (Management Z SP5+), UAM alert ingest, IOCs | Settings → Users → Service Users → Create Service User → copy the API token. |
| `S1_HEC_INGEST_URL` | UAM alert ingest, raw log ingest | Region-specific ingest host, e.g. `https://ingest.us1.sentinelone.net`. Look up yours at [SentinelOne Endpoint URLs by Region](https://community.sentinelone.com/s/article/000004961). |
| `S1_HEC_TOKEN` | Optional. **Raw log ingest over the event collector now needs it**, because the collector no longer accepts the console API token. Nothing else uses it. | Console → Singularity Data Lake → API Keys → Log Write Key. No API mints one. |

`S1_CONSOLE_URL` and `S1_CONSOLE_API_TOKEN` are the minimum required, and between them they authorise every SDL query and configuration operation including parser and dashboard deployment. Add `S1_HEC_INGEST_URL` only when you need log or alert ingest.

Raw log ingest is the one path the console API token does not cover. `/services/collector/raw` and `/event` take an SDL Log Write Key in `S1_HEC_TOKEN`: on identical requests the write key returns `HTTP 200 {"text":"Success","code":0}` and the console token returns `HTTP 400 {"text":"Missing S1-Scope header","code":5}`. A key is minted for exactly one account or site and writes only there, so the key fixes the ingest destination; no `S1-Scope` header is sent and sending one has no effect. To write elsewhere, use a key minted for that scope. UAM alert ingest and IOCs are unaffected and still use `S1_CONSOLE_API_TOKEN`.

The scoped SDL keys (`SDL_CONFIG_READ_KEY`, `SDL_CONFIG_WRITE_KEY`, `SDL_LOG_READ_KEY`, `SDL_LOG_WRITE_KEY`, `SDL_XDR_URL`) are retired and are no longer read.

```python
```

---

## Token types

The S1 API has two token types and they are not interchangeable for all operations:

| Token type | Created via | Visible in UI | Notes |
|---|---|---|---|
| Service User token | Settings → Users → Service Users | No: workflows/rules created with this token are invisible to human users in the UI | Use for programmatic API access |
| Personal Console User token | Settings → Users → My User → API Token | Yes: objects created are visible and attributed to the user | Required for Hyperautomation workflows to appear in the UI |

For most skills, a service user token is correct. If you need Hyperautomation workflows to be visible and editable in the console UI, use a personal console user token.

**Multi-scope tokens:** Some endpoints reject service user tokens scoped to more than one account with `HTTP 403 code 4030010`. Affected endpoints include `/threat-intelligence/iocs`. Use a single-scope token for those operations by adding:

```json
{
  "S1_CONSOLE_API_TOKEN_SINGLE_SCOPE": "eyJ...your-single-scope-token..."
}
```

The skills auto-detect and fall back to this key when the primary token is rejected.

---

## Resolution order

Credentials are resolved in this priority order (highest wins):

1. Environment variables (`S1_CONSOLE_URL`, `S1_CONSOLE_API_TOKEN`, `S1_HEC_INGEST_URL`, `S1_HEC_TOKEN`)
2. `credentials.json` in the Cowork project folder (auto-discovered by the plugin's SessionStart hook, and by s1-secops-mcp walking up the directory tree)
3. `~/.config/sentinelone/credentials.json` (fallback for terminal/Claude Code sessions)

---

## Setting up credentials.json (Cowork)

The full key list and resolution order are in the tables above. For the file-based fallback (direct skill use without `s1-secops-mcp`), create `credentials.json` in your Cowork project folder with the keys you need:

```bash
# macOS / Linux
PROJECT_DIR=~/Documents/Claude/Projects/MyProject
cat > "$PROJECT_DIR/credentials.json" <<'JSON'
{
  "S1_CONSOLE_URL": "https://<your-tenant>.sentinelone.net",
  "S1_CONSOLE_API_TOKEN": "<your-mgmt-console-api-token>"
}
JSON
${EDITOR:-nano} "$PROJECT_DIR/credentials.json"
```

Add `S1_HEC_INGEST_URL` alongside these if you need alert or log ingest, plus `S1_HEC_TOKEN` if that includes raw log ingest (full list in the [keys table](#credentialsjson-keys) above).

When creating the project in Cowork, add `credentials.json` and `CLAUDE.md` under **Add files** so Claude has access to both in every session.

---

## Configuring the MCP servers

The MCP servers receive these credentials as environment variables in `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows). The ready-to-paste config block differs by install path, so copy it from the path you are following rather than duplicating it here:

- **Docker (recommended):** [README → Quick start (Docker), Step 2](../README.md#1-quick-start-docker), or the full walkthrough at [docs/installation.md → Step 1: Configure MCP servers](./installation.md#step-1-configure-mcp-servers)

Whichever block you paste, fill in the same keys from the tables above.

**All three MCPs take the same four variable names.** You never set a server-specific variable. `purple-mcp` uses its own names internally, and the image entrypoint derives them:

| You set | Derived for purple-mcp |
|---|---|
| `S1_CONSOLE_URL` | `PURPLEMCP_CONSOLE_BASE_URL` |
| `S1_CONSOLE_API_TOKEN` | `PURPLEMCP_CONSOLE_TOKEN` |

A server-specific variable that is already set always wins, so an older config naming `PURPLEMCP_*` explicitly keeps working.

Two more things apply to every path:

> **Threat intel MCP:** Replace `virustotal` with your organisation's approved threat intelligence MCP if different. Any MCP that provides file hash, IP, domain, and URL lookup tools works. The CLAUDE.md operating instructions require multi-source confirmation before a TRUE POSITIVE or CRITICAL verdict: they do not mandate a specific provider.

**Host prerequisites:**

- Docker running on the host (`docker --version`). All three MCPs ship in `sentinelone/secops-skills`, so nothing else is required.
- A VirusTotal API key (free tier is fine) from [virustotal.com](https://virustotal.com), passed as `VIRUSTOTAL_API_KEY`.

Restart Claude Desktop after editing the config. All servers then appear under connected MCP tools.

---

## Verifying credentials work

After setup, run the quick test:

```bash
cd s1-secops-skills/mgmt-console-api
pip install requests
python scripts/s1_client.py
```

This prints the first 5 accounts and runs 4 parallel GETs to confirm auth and connectivity.

To run a full non-destructive sweep of every readable endpoint:

```bash
python scripts/smoke_test_queries.py --workers 12
```

Results land in `references/tenant_capabilities.{json,md}`.
