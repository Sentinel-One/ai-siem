# Team VM deployment (s1-secops-mcp)

Run one shared `s1-secops-mcp` instance on a Linux VM. Team members all connect to the same instance, the underlying SentinelOne service-user token lives in one place, and each person gets their own bearer token for audit and revocation.

Supported from `s1-secops-mcp` v1.1.0 onward. Does not replace the per-laptop [`npx`/`uvx`](./installation.md) or [Docker](./docker.md) paths; it's a third option for teams.

- [When to use this](#when-to-use-this)
- [Prerequisites](#prerequisites)
- [One-line install](#one-line-install)
- [Fill in credentials](#fill-in-credentials)
- [TLS in front (Caddy)](#tls-in-front-caddy)
- [Adding and revoking team members](#adding-and-revoking-team-members)
- [Client config (per team member)](#client-config-per-team-member)
- [Verifying end-to-end](#verifying-end-to-end)
- [Day-2 operations](#day-2-operations)
- [Audit log](#audit-log)
- [Troubleshooting](#troubleshooting)
- [Full reference](#full-reference)

---

## When to use this

Pick this path when:

- More than one person needs to use `s1-secops-mcp` against the same SentinelOne tenant.
- You'd rather not hand out the underlying S1 service-user token + SDL keys to N laptops.
- You want per-user audit (who ran which tool, when) and easy revocation.

If you're a single user on your own Mac or Linux machine, the [npx/uvx](./installation.md) or [Docker](./docker.md) paths are simpler.

The other two MCPs (`purple-mcp`, `virustotal`) still install per-laptop in this topology; only `s1-secops-mcp` runs server-side. That keeps the threat-intel and Purple AI flows scoped to the analyst's session.

## Prerequisites

| Requirement | Notes |
|---|---|
| Linux VM with systemd | Ubuntu 22.04 LTS, Debian 12, Rocky/Alma 9, or any equivalent systemd distro |
| Node.js 18+ | Installer errors out with apt/dnf hints if missing |
| Reachable from team laptops | Tailscale, VPN, or a private DNS name |
| One SentinelOne service-user token | Settings → Users → Service Users on the S1 console |
| TLS plan | Recommended: Caddy (template provided). Acceptable: nginx, Tailscale TLS, internal CA |

## One-line install

On the target VM:

```bash
curl -fsSL https://raw.githubusercontent.com/Sentinel-One/ai-siem/main/mcp/s1-secops-mcp/deploy/install.sh | sudo bash -s -- --server
```

This single command:

1. Creates the `mcp` system user (no shell, no home interactive).
2. Installs `@pmoses-s1/s1-secops-mcp` globally via npm.
3. Drops `/etc/s1-secops-mcp/credentials.json` (placeholder, mode 0600).
4. Generates an initial admin bearer token, writes it to `/etc/s1-secops-mcp/bearer-tokens.json`, and prints it to stdout once.
5. Installs and starts a hardened systemd unit listening on `127.0.0.1:8765/mcp`.

Verify with:

```bash
sudo systemctl status s1-secops-mcp
curl -s http://127.0.0.1:8765/healthz   # -> ok
```

## Fill in credentials

The installer drops a placeholder. Edit it with your real values:

```bash
sudo vim /etc/s1-secops-mcp/credentials.json
```

```json
{
  "S1_CONSOLE_URL":       "https://usea1-yourorg.sentinelone.net",
  "S1_CONSOLE_API_TOKEN": "eyJ...",
  "S1_HEC_INGEST_URL":    "https://ingest.us1.sentinelone.net",
  "SDL_XDR_URL":          "https://xdr.us1.sentinelone.net",
  "SDL_LOG_READ_KEY":     "...",
  "SDL_CONFIG_READ_KEY":  "...",
  "SDL_CONFIG_WRITE_KEY": "..."
}
```

Apply without restart (full restart needed for credentials):

```bash
sudo systemctl restart s1-secops-mcp
```

`S1_CONSOLE_URL` + `S1_CONSOLE_API_TOKEN` are enough for most tools. `S1_HEC_INGEST_URL` is required only for `uam_ingest_alert`, `uam_post_indicators`, `uam_post_alert`. `SDL_*` keys gate the SDL tools per the table in [the MCP README](../../../mcp/s1-secops-mcp/README.md#credentials).

## TLS in front (Caddy)

The MCP binds to `127.0.0.1` only. Put Caddy in front for HTTPS + a second-layer bearer check.

```bash
sudo apt install -y caddy
sudo cp /usr/lib/node_modules/@pmoses-s1/s1-secops-mcp/deploy/caddy/Caddyfile.example /etc/caddy/Caddyfile
sudo vim /etc/caddy/Caddyfile   # change mcp.s1.internal to your DNS / Tailscale name
sudo systemctl reload caddy
```

Default Caddyfile uses `tls internal` (Caddy's built-in CA, suitable for private networks; distribute Caddy's root cert to clients). For a publicly resolvable hostname swap to `tls <your-email>` for Let's Encrypt. For an internal PKI use `tls /path/cert.pem /path/key.pem`. nginx equivalent is in the same example file.

## Adding and revoking team members

Each person gets their own random bearer token. Names appear in the audit log; revocation removes the line and reloads.

```bash
sudo bash -c 'cat > /etc/s1-secops-mcp/bearer-tokens.json' <<EOF
{
  "admin":  "$(openssl rand -hex 32)",
  "alice":  "$(openssl rand -hex 32)",
  "bob":    "$(openssl rand -hex 32)",
  "claire": "$(openssl rand -hex 32)"
}
EOF
sudo chmod 600 /etc/s1-secops-mcp/bearer-tokens.json
sudo chown mcp:mcp /etc/s1-secops-mcp/bearer-tokens.json
sudo systemctl reload s1-secops-mcp   # SIGHUP, zero downtime
```

Hand each person their token over a secure channel (1Password, Signal, etc.).

To revoke: delete the entry and reload. To rotate one token: generate a new value, replace the entry, reload, distribute.

## Client config (per team member)

Pick the path that matches your client. The only thing each user needs from their admin is their personal bearer token and the MCP URL.

| Client | Transport | Setup needed |
|---|---|---|
| **Claude Code** | Direct HTTP | Config block only, no install |
| **Claude Cowork** | Direct HTTP | Config block only, no install |
| **Claude Desktop** | stdio bridge (Desktop rejects `type: "http"`) | 3-step bridge install + config block |

Config file locations:

| Client | Path |
|---|---|
| Claude Code | `~/.claude.json` (or workspace `.mcp.json`) |
| Claude Cowork | Settings → MCPs in the app |
| Claude Desktop (macOS) | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Claude Desktop (Windows) | `%APPDATA%\Claude\claude_desktop_config.json` |

`purple-mcp` and `virustotal` stay per-laptop in every case. Only `s1-secops-mcp` is served from the VM.

### Path A — Claude Code / Cowork (direct HTTP, no bridge)

Paste this into the config file. Replace `<THEIR_PERSONAL_TOKEN>` with the bearer token the admin handed over, and `mcp.s1.internal` with whatever DNS/Tailscale name the admin gave.

```json
{
  "mcpServers": {
    "s1-secops-mcp": {
      "type": "http",
      "url": "https://mcp.s1.internal/mcp",
      "headers": {
        "Authorization": "Bearer <THEIR_PERSONAL_TOKEN>"
      }
    },
    "purple-mcp": {
      "command": "uvx",
      "args": ["--from", "git+https://github.com/Sentinel-One/purple-mcp.git", "purple-mcp", "--mode", "stdio"],
      "env": {
        "PURPLEMCP_CONSOLE_TOKEN":    "...",
        "PURPLEMCP_CONSOLE_BASE_URL": "..."
      }
    },
    "virustotal": {
      "command": "npx",
      "args": ["-y", "@burtthecoder/mcp-virustotal"],
      "env": {
        "VIRUSTOTAL_API_KEY": "..."
      }
    }
  }
}
```

Restart the client. Done.

### Path B — Claude Desktop (stdio bridge required)

Claude Desktop's stable build rejects `type: "http"` with "not valid MCP server configuration", so you have to run a small stdio↔HTTPS shim locally. The bridge is a 40-line zero-dep Node script shipped at [`s1-secops-mcp/deploy/bridge/s1-secops-mcp-bridge.mjs`](../../../mcp/s1-secops-mcp/deploy/bridge/s1-secops-mcp-bridge.mjs).

**Step 1 — Install the bridge (one-time, per Mac):**

```bash
mkdir -p ~/.local/bin
curl -fsSL https://raw.githubusercontent.com/Sentinel-One/ai-siem/main/mcp/s1-secops-mcp/deploy/bridge/s1-secops-mcp-bridge.mjs \
  -o ~/.local/bin/s1-secops-mcp-bridge.mjs
chmod +x ~/.local/bin/s1-secops-mcp-bridge.mjs
```

Verify the file exists and is executable:

```bash
ls -l ~/.local/bin/s1-secops-mcp-bridge.mjs
# -rwxr-xr-x ... s1-secops-mcp-bridge.mjs
```

The bridge has no dependencies beyond Node 18+ (`node --version` to confirm).

**Step 2 — Add the config block:**

Open `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows) and paste:

```json
{
  "mcpServers": {
    "s1-secops-mcp": {
      "command": "node",
      "args": ["/Users/<you>/.local/bin/s1-secops-mcp-bridge.mjs"],
      "env": {
        "MCP_URL":    "https://mcp.s1.internal:8764/mcp",
        "MCP_BEARER": "<your personal bearer token>"
      }
    },
    "purple-mcp": {
      "command": "uvx",
      "args": ["--from", "git+https://github.com/Sentinel-One/purple-mcp.git", "purple-mcp", "--mode", "stdio"],
      "env": {
        "PURPLEMCP_CONSOLE_TOKEN":    "...",
        "PURPLEMCP_CONSOLE_BASE_URL": "..."
      }
    },
    "virustotal": {
      "command": "npx",
      "args": ["-y", "@burtthecoder/mcp-virustotal"],
      "env": {
        "VIRUSTOTAL_API_KEY": "..."
      }
    }
  }
}
```

Three placeholders to fill in:

| Placeholder | Where it comes from |
|---|---|
| `<you>` | Your macOS short username. `whoami` prints it. The full path must be absolute — `~` does not expand inside this field. |
| `MCP_URL` | The URL your admin gave. Must end in `/mcp`. Include the port if the admin's reverse proxy uses a non-standard one (e.g. `https://mcp.s1.internal:8764/mcp`). |
| `MCP_BEARER` | Your personal bearer token from `/etc/s1-secops-mcp/bearer-tokens.json` on the VM. The admin pastes the value for your name. |

**Step 3 — Restart Claude Desktop:**

Cmd+Q and reopen. The 26 s1-secops-mcp tools appear in the tool list within a few seconds.

**Smoke test if it doesn't connect:**

```bash
MCP_HOST='mcp.s1.internal:8764' \
MCP_BEARER='<your token>' \
  bash s1-secops-mcp/scripts/smoke-test-http.sh
```

All six checks should print PASS. Any FAIL points at the specific layer that's broken (TLS, bearer, backend, tool count). Full troubleshooting reference: [`s1-secops-mcp/deploy/bridge/README.md`](../../../mcp/s1-secops-mcp/deploy/bridge/README.md).

## Verifying end-to-end

From any team member's machine, replacing `$TOKEN` with their bearer token:

```bash
curl -s -X POST https://mcp.s1.internal/mcp \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' | jq '.result.tools | length'
# -> 26
```

`200 ok` with 26 tools listed = green path. `401` = bearer wrong or not in `/etc/s1-secops-mcp/bearer-tokens.json`. `502` from Caddy = MCP backend down (check `systemctl status s1-secops-mcp`).

## Day-2 operations

### Add a team member

```bash
sudo vim /etc/s1-secops-mcp/bearer-tokens.json   # add {"name": "<32 hex>"}
sudo systemctl reload s1-secops-mcp              # SIGHUP, no drops
```

### Revoke access

```bash
sudo vim /etc/s1-secops-mcp/bearer-tokens.json   # remove the entry
sudo systemctl reload s1-secops-mcp
```

### Rotate the SentinelOne service-user token

```bash
sudo vim /etc/s1-secops-mcp/credentials.json     # paste new S1_CONSOLE_API_TOKEN
sudo systemctl restart s1-secops-mcp             # full restart needed for creds
```

### Upgrade the MCP server

```bash
sudo npm install -g @pmoses-s1/s1-secops-mcp@<new-version>
sudo systemctl restart s1-secops-mcp
```

## Audit log

Every authenticated request logs to stderr, captured by journald:

```
[audit] 2026-05-28T15:01:22.413Z | alice | tools/call | name=powerquery_run | 200 ok
[audit] 2026-05-28T16:42:55.108Z | bob   | tools/list | -                  | 200 ok
[audit] 2026-05-28T17:03:11.221Z | -     | -          | -                  | 401 unauthorized
```

Quick filters:

```bash
# everything alice did in the last hour
sudo journalctl -u s1-secops-mcp --since="1 hour ago" | grep '\[audit\].*| alice |'

# all unauthorized attempts today
sudo journalctl -u s1-secops-mcp --since=today | grep '\[audit\].*401'

# all tool calls (not just listings)
sudo journalctl -u s1-secops-mcp -f | grep 'tools/call'
```

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `Connection refused` on `127.0.0.1:8765` | Service not running | `sudo systemctl status s1-secops-mcp` then `journalctl -u s1-secops-mcp -n 50`. |
| 401 on every request | No bearer header, or wrong token | Confirm `Authorization: Bearer <token>` is sent. Confirm the token is in `/etc/s1-secops-mcp/bearer-tokens.json`. |
| `connect ECONNREFUSED` to `*.sentinelone.net` | S1 creds missing, or VM has no outbound | `curl -v https://$YOUR_CONSOLE_URL`. Check `/etc/s1-secops-mcp/credentials.json`. |
| `502 Bad Gateway` from Caddy | Backend died between Caddy reload and proxy attempt | `systemctl status s1-secops-mcp` and check journal. |
| Tools/list returns `0` tools | Wrong tag installed, or import error | `s1-secops-mcp --version` (must be 1.1.0+), then `journalctl -u s1-secops-mcp -n 100`. |

## Full reference

The canonical deploy guide lives alongside the MCP source so it stays in lock-step with the code:

**[`s1-secops-mcp/deploy/README.md`](../../../mcp/s1-secops-mcp/deploy/README.md)** — all three topologies (single-user local stdio, single-user HTTP, team VM-hosted), full alternative-deployment notes (Docker, supergateway), and the underlying systemd / Caddy templates.

This page (`docs/vm-deployment.md`) is the on-ramp; the deploy README is the manual.
