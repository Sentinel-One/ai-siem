# Credentials

All skills and MCP servers read from a single `credentials.json` file. This document covers every key, where to find each one, and how to configure the MCP servers.

---

## credentials.json keys

```json
{
  "S1_CONSOLE_URL":       "https://usea1-yourorg.sentinelone.net",
  "S1_CONSOLE_API_TOKEN": "eyJ...your-api-token...",
  "S1_HEC_INGEST_URL":    "https://ingest.us1.sentinelone.net",
  "SDL_XDR_URL":          "https://xdr.us1.sentinelone.net",
  "SDL_LOG_READ_KEY":     "0tzj...",
  "SDL_CONFIG_WRITE_KEY": "0mXas6...",
  "SDL_CONFIG_READ_KEY":  "0MQTx..."
}
```

| Key | Required for | How to get it |
|---|---|---|
| `S1_CONSOLE_URL` | Everything | Your console URL, e.g. `https://usea1-acme.sentinelone.net`. No trailing slash. |
| `S1_CONSOLE_API_TOKEN` | Mgmt Console REST, PowerQuery LRQ, UAM GraphQL, Purple AI GraphQL, SDL config ops (Management Z SP5+) | Settings → Users → Service Users → Create Service User → copy the API token. |
| `S1_HEC_INGEST_URL` | UAM alert/indicator ingest, SDL log ingest | Region-specific HEC host, e.g. `https://ingest.us1.sentinelone.net`. Look up yours at [SentinelOne Endpoint URLs by Region](https://community.sentinelone.com/s/article/000004961). |
| `SDL_XDR_URL` | SDL API operations (list/get/put config files, PowerQuery via SDL client) | Your SDL tenant URL, e.g. `https://xdr.us1.sentinelone.net`. Region-specific; same reference as above. |
| `SDL_LOG_READ_KEY` | SDL V1 query via SDL client (fallback) | Same location, Log Read Access. |
| `SDL_CONFIG_WRITE_KEY` | `sdl_put_file` (parser/dashboard deploy) | Singularity Data Lake → API Keys → Configuration Access Keys → New Key (Config Write). |
| `SDL_CONFIG_READ_KEY` | `sdl_list_files`, `sdl_get_file` | Same location, Config Read Access. |

`S1_CONSOLE_URL` and `S1_CONSOLE_API_TOKEN` are the minimum required for most operations. Add the SDL keys only when you need log ingest or parser/dashboard deployment.

**Important:** `SDL_CONFIG_WRITE_KEY` does NOT grant log read access. If your SDL queries return 403, force-clear the scoped keys so auth falls through to the console JWT:

```python
c.keys["log_read_key"] = ""
c.keys["config_read_key"] = ""
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

1. Environment variables (`S1_CONSOLE_URL`, `S1_CONSOLE_API_TOKEN`, `SDL_*`)
2. `credentials.json` in the Cowork project folder (auto-discovered by the plugin's SessionStart hook, and by s1-secops-mcp walking up the directory tree)
3. `~/.config/sentinelone/credentials.json` (fallback for terminal/Claude Code sessions)

---

## Setting up credentials.json (Cowork)

The full key list and resolution order are documented in the MCP server configuration: see the **Credentials** section of `mcp/s1-secops-mcp/README.md`. For the file-based fallback, create `credentials.json` in your Cowork project folder with the keys you need:

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

Add any `SDL_*` keys you need alongside these (full list in `mcp/s1-secops-mcp/README.md`).

When creating the project in Cowork, add `credentials.json` and `CLAUDE.md` under **Add files** so Claude has access to both in every session.

---

## Setting up claude_desktop_config.json (MCP servers)

The MCP servers receive credentials via environment variables set in `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows).

```json
{
  "mcpServers": {
    "s1-secops-mcp": {
      "command": "npx",
      "args": ["-y", "@pmoses-s1/s1-secops-mcp"],
      "env": {
        "S1_CONSOLE_URL":       "https://usea1-yourorg.sentinelone.net",
        "S1_CONSOLE_API_TOKEN": "eyJ...your-api-token...",
        "S1_HEC_INGEST_URL":    "https://ingest.us1.sentinelone.net",
        "SDL_XDR_URL":          "https://xdr.us1.sentinelone.net",
        "SDL_LOG_READ_KEY":     "0tzj...",
        "SDL_CONFIG_WRITE_KEY": "0mXas6...",
        "SDL_CONFIG_READ_KEY":  "0MQTx..."
      }
    },
    "purple-mcp": {
      "command": "uvx",
      "args": [
        "--from", "git+https://github.com/Sentinel-One/purple-mcp.git",
        "purple-mcp", "--mode", "stdio"
      ],
      "env": {
        "PURPLEMCP_CONSOLE_BASE_URL": "https://usea1-yourorg.sentinelone.net",
        "PURPLEMCP_CONSOLE_TOKEN":    "eyJ...your-api-token..."
      }
    },
    "virustotal": {
      "command": "npx",
      "args": ["-y", "@burtthecoder/mcp-virustotal"],
      "env": {
        "VIRUSTOTAL_API_KEY": "your-virustotal-api-key"
      }
    }
  }
}
```

> **Threat intel MCP:** Replace `virustotal` with your organisation's approved threat intelligence MCP if different. Any MCP that provides file hash, IP, domain, and URL lookup tools works. The CLAUDE.md operating instructions require multi-source confirmation before a TRUE POSITIVE or CRITICAL verdict: they do not mandate a specific provider.

**Prerequisites:**
- Node.js 18+ for `s1-secops-mcp` and `@burtthecoder/mcp-virustotal` via `npx` (`node --version`)
- `uv` for `purple-mcp`: `curl -LsSf https://astral.sh/uv/install.sh | sh`, then open a new terminal and run `uvx --version`
- A VirusTotal API key (free tier is fine) from [virustotal.com](https://virustotal.com)

Restart Claude Desktop after editing the config. All servers appear under connected MCP tools.

---

## Verifying credentials work

After setup, run the quick test:

```bash
cd plugins/s1-secops-skills/skills/mgmt-console-api
pip install requests
python scripts/s1_client.py
```

This prints the first 5 accounts and runs 4 parallel GETs to confirm auth and connectivity.

To run a full non-destructive sweep of every readable endpoint:

```bash
python scripts/smoke_test_queries.py --workers 12
```

Results land in `references/tenant_capabilities.{json,md}`.
