# Deployment guide

Three supported topologies, in order of complexity.

| Topology | Who runs it | Transport | Auth | Use this when |
|---|---|---|---|---|
| **A. Single user, local** | One human | stdio | none | You use Claude Desktop / Claude Code / Claude Cowork on your own Mac or Linux laptop. |
| **B. Single user, HTTP** | One human | Streamable HTTP, `127.0.0.1` only | none | You want one server you can curl, or have a non-Claude client that speaks Streamable HTTP. |
| **C. Team, VM-hosted** | Many humans | Streamable HTTP, behind TLS | per-user bearer tokens | You want N team members to share one server with one set of SentinelOne credentials, with per-user audit and revocation. |

## A. Single user, local (stdio)

`curl -fsSL https://raw.githubusercontent.com/Sentinel-One/ai-siem/main/mcp/s1-secops-mcp/deploy/install.sh | bash`

That runs `install.sh --user`, which:
1. Confirms Node 18+ is present (errors out with install hints if not).
2. Sets up a per-user npm prefix at `~/.npm-global` if one isn't configured.
3. Installs `@pmoses-s1/s1-secops-mcp` globally for your user.
4. Writes a credentials skeleton to `~/.config/sentinelone/credentials.json` (mode 0600).
5. Prints the next steps.

Then edit `~/.config/sentinelone/credentials.json` with your real values:

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

Add the server to Claude Desktop (`~/Library/Application Support/Claude/claude_desktop_config.json` on Mac, or `%APPDATA%\Claude\claude_desktop_config.json` on Windows):

```json
{
  "mcpServers": {
    "s1-secops-mcp": {
      "command": "s1-secops-mcp"
    }
  }
}
```

Or, equivalently, by package name without the install:

```json
{
  "mcpServers": {
    "s1-secops-mcp": {
      "command": "npx",
      "args": ["-y", "@pmoses-s1/s1-secops-mcp@1.2.2"]
    }
  }
}
```

Restart Claude Desktop. The server picks credentials up from `~/.config/sentinelone/credentials.json` automatically.

## B. Single user, HTTP

Same `install.sh --user`, then start the server in HTTP mode:

```bash
s1-secops-mcp --transport http
```

It binds to `127.0.0.1:8765` and runs with no auth (which is fine when the bind address is loopback and you're the only user on the box). Hit it with curl:

```bash
curl -s http://127.0.0.1:8765/healthz
# -> ok

curl -s -X POST http://127.0.0.1:8765/mcp \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | jq '.result.tools | length'
# -> 26
```

In Claude Cowork or any MCP client that supports remote HTTP servers, add it:

```json
{
  "mcpServers": {
    "s1-secops-mcp": {
      "type": "http",
      "url": "http://127.0.0.1:8765/mcp"
    }
  }
}
```

## C. Team, VM-hosted (recommended for shared deployments)

This is the topology to use when more than one person should have access to the same SentinelOne tenant through MCP, without distributing the underlying S1 service-user token.

### What you'll end up with

- One Linux VM, reachable on your private network (or via Tailscale, WireGuard, etc.).
- One `mcp` system user owning `/etc/s1-secops-mcp/`.
- One `credentials.json` containing the S1 service-user token + SDL keys. Mode 0600, never copied off the box.
- One `bearer-tokens.json` listing per-user tokens, one per team member: `{"alice": "...", "bob": "...", "claire": "..."}`. Mode 0600. SIGHUP-reloadable.
- One systemd service running the MCP on `127.0.0.1:8765` with auth enforced.
- Caddy in front terminating TLS and forwarding to the backend.

Team members connect from their Claude clients with their own bearer token. Audit log identifies them by name. Revocation is one file edit + `systemctl reload`.

### Step-by-step

1. **Provision the VM.** Anything that runs systemd is fine: Ubuntu 22.04 LTS, Debian 12, Rocky/Alma 9, etc.

2. **Install Node 18+.** Pick one:
   ```bash
   # Ubuntu / Debian
   curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
   sudo apt install -y nodejs
   ```
   ```bash
   # Rocky / Alma
   curl -fsSL https://rpm.nodesource.com/setup_20.x | sudo bash -
   sudo dnf install -y nodejs
   ```

3. **Run the installer in server mode:**
   ```bash
   curl -fsSL https://raw.githubusercontent.com/Sentinel-One/ai-siem/main/mcp/s1-secops-mcp/deploy/install.sh | sudo bash -s -- --server
   ```
   It creates the `mcp` user, drops `/etc/s1-secops-mcp/credentials.json` (placeholder) and `/etc/s1-secops-mcp/bearer-tokens.json` (one freshly-generated admin token, printed once to stdout), installs the systemd unit, and starts the service.

4. **Fill in real SentinelOne credentials:**
   ```bash
   sudo vim /etc/s1-secops-mcp/credentials.json
   sudo systemctl reload s1-secops-mcp
   curl -s http://127.0.0.1:8765/healthz   # -> ok
   ```

5. **Put TLS in front with Caddy** (the recommended option):
   ```bash
   sudo apt install -y caddy
   sudo cp /usr/lib/node_modules/@pmoses-s1/s1-secops-mcp/deploy/caddy/Caddyfile.example /etc/caddy/Caddyfile
   sudo vim /etc/caddy/Caddyfile   # change mcp.s1.internal to your DNS name
   sudo systemctl reload caddy
   ```
   Default Caddyfile uses `tls internal` which signs with Caddy's own CA. Distribute `/var/lib/caddy/.local/share/caddy/pki/authorities/local/root.crt` to your team for trust, or use `tls <your-email>` with a publicly resolvable hostname for Let's Encrypt.

6. **Add team members.** Generate a token per person and append to the file:
   ```bash
   sudo bash -c 'cat > /etc/s1-secops-mcp/bearer-tokens.json' <<EOF
   {
     "admin": "$(openssl rand -hex 32)",
     "alice": "$(openssl rand -hex 32)",
     "bob":   "$(openssl rand -hex 32)",
     "claire":"$(openssl rand -hex 32)"
   }
   EOF
   sudo chmod 600 /etc/s1-secops-mcp/bearer-tokens.json
   sudo chown mcp:mcp /etc/s1-secops-mcp/bearer-tokens.json
   sudo systemctl reload s1-secops-mcp   # SIGHUP, no downtime
   ```
   Hand each person their token over a secure channel (1Password, Signal, etc.).

7. **Connect from a Claude client.** Each user adds the server to their config with their personal token:
   ```json
   {
     "mcpServers": {
       "s1-secops-mcp": {
         "type": "http",
         "url": "https://mcp.s1.internal/mcp",
         "headers": {
           "Authorization": "Bearer <THEIR_PERSONAL_TOKEN>"
         }
       }
     }
   }
   ```

8. **Verify end-to-end.** From a team member's machine:
   ```bash
   curl -s -X POST https://mcp.s1.internal/mcp \
     -H "Authorization: Bearer $TOKEN" \
     -H 'Content-Type: application/json' \
     -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | jq '.result.tools | length'
   # -> 26
   ```

9. **Watch the audit log.** Every authenticated request is logged with the bearer name, method, and param summary:
   ```bash
   sudo journalctl -u s1-secops-mcp -f | grep '\[audit\]'
   # [audit] 2026-05-28T15:01:22.413Z | alice | tools/call | name=powerquery_run | 200 ok
   # [audit] 2026-05-28T15:01:34.221Z | bob   | tools/list | -                  | 200 ok
   ```

## Day-2 operations

### Adding a team member

```bash
sudo vim /etc/s1-secops-mcp/bearer-tokens.json   # add new {"name": "token"}
sudo systemctl reload s1-secops-mcp              # SIGHUP, no downtime
```

### Revoking access

```bash
sudo vim /etc/s1-secops-mcp/bearer-tokens.json   # remove the entry
sudo systemctl reload s1-secops-mcp
```

### Rotating the SentinelOne service-user token

```bash
sudo vim /etc/s1-secops-mcp/credentials.json     # paste new S1_CONSOLE_API_TOKEN
sudo systemctl restart s1-secops-mcp             # full restart needed for creds
```

### Upgrading the MCP server

```bash
sudo npm install -g @pmoses-s1/s1-secops-mcp@<new-version>
sudo systemctl restart s1-secops-mcp
```

### Reading the audit log

The structured audit lines look like:

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

### Health and readiness

`GET /healthz` returns `200 ok` whenever the server is accepting connections. Use it for load balancer probes and for `systemctl-aware` orchestrators:

```bash
curl -s http://127.0.0.1:8765/healthz   # behind the proxy
curl -s https://mcp.s1.internal/healthz # in front of the proxy
```

## Connecting Claude Desktop to a remote MCP

Claude Desktop's `claude_desktop_config.json` only accepts stdio-based MCP servers in current stable builds; the `type: "http"` form gets rejected with "not valid MCP server configuration" on load. To connect Claude Desktop to your VM's HTTPS endpoint, use the bridge script shipped in this repo at [`bridge/s1-secops-mcp-bridge.mjs`](./bridge/s1-secops-mcp-bridge.mjs) — a 40-line zero-dependency Node script that translates Claude Desktop's stdio into POST requests against the MCP HTTP endpoint.

Each team member drops the script anywhere on their machine (typically `~/.local/bin/s1-secops-mcp-bridge.mjs`) and points Claude Desktop at it:

```json
{
  "mcpServers": {
    "s1-secops-mcp": {
      "command": "node",
      "args": ["/Users/<you>/.local/bin/s1-secops-mcp-bridge.mjs"],
      "env": {
        "MCP_URL":    "https://mcp.s1.internal/mcp",
        "MCP_BEARER": "<your personal bearer token>"
      }
    }
  }
}
```

Then Cmd+Q and reopen Claude Desktop. See [`bridge/README.md`](./bridge/README.md) for install, smoke-test, and troubleshooting steps. Claude Cowork users can keep using the native `type: "http"` config (it supports remote HTTP MCPs in current builds) — only Claude Desktop needs the bridge.

## AWS-specific gotchas

Five things that bit during real deployment to an EC2 instance. None are blockers, but knowing them up front saves hours.

### EC2 public DNS is unstable without an Elastic IP

Stopping and starting an instance assigns a new public IPv4 address and a new public DNS name (`ec2-<new-ip>.<region>.compute.amazonaws.com`). Every ACME-issued cert, every `claude_desktop_config.json`, and every Caddyfile that referenced the old hostname breaks. Allocate an Elastic IP in EC2 → Elastic IPs → Allocate → Associate before issuing certs. Free while attached to a running instance.

The instance's `*.compute.internal` DNS name (e.g. `ip-172-31-7-227.ap-southeast-2.compute.internal`) is the VPC-internal name and is **not** reachable from outside the VPC. It can't be used for ACME validation or for clients on the public internet.

### Let's Encrypt refuses `*.amazonaws.com` by policy

If you try to issue a cert for the EC2 public DNS, LE returns:

```
HTTP 400 urn:ietf:params:acme:error:rejectedIdentifier
The ACME server refuses to issue a certificate for this domain name, because it is forbidden by policy
```

Caddy auto-falls back to **ZeroSSL** (also free, also publicly trusted, no policy block on `amazonaws.com`). Use the email-shorthand form `tls <email>` and Caddy handles the fallback transparently. The right end state is a cert with `issuer=ZeroSSL ECC DV SSL CA 2` — verify with:

```bash
echo | openssl s_client -connect $HOST:8764 -servername $HOST 2>/dev/null \
  | grep -E "^(issuer=|verify return code)"
```

For long-term peace of mind, use a real domain instead (Route 53 A record pointing at the Elastic IP) — both LE and ZeroSSL issue without restriction and the hostname survives instance replacement.

### Caddyfile: don't mix `tls` shorthand with `issuer acme` block

```caddyfile
# WRONG — Caddy errors: "cannot mix issuer subdirective with other issuer-specific subdirectives"
tls prithvi@example.com {
    issuer acme {
        disable_http_challenge
    }
}
```

The shorthand `tls <email>` implicitly configures an ACME issuer. Combining it with an explicit `issuer acme { ... }` block conflicts. Pick one form:

```caddyfile
# Form 1: shorthand (requires port 80 open for HTTP-01)
tls prithvi@example.com

# Form 2: explicit block (gives you knobs like disable_http_challenge)
tls {
    issuer acme {
        email prithvi@example.com
        disable_http_challenge
    }
}
```

### `tls internal` produces a Caddy CA cert, not a public one

If you see ACME succeed in milliseconds rather than ~10-30 seconds, look at the cert: it was likely issued by Caddy's local CA, not by an external ACME server. The give-aways are an instant log line and `no OCSP server specified in certificate` warnings (public CAs always embed OCSP URLs). `tls internal` is fine for private-network deployments with cert distribution to clients, but doesn't help when you want public trust.

### systemd hardening that breaks Node V8 JIT

The hardened service file we ship omits two systemd directives that would otherwise be useful:

- `MemoryDenyWriteExecute=true`
- `LockPersonality=true`

Both block the W+X memory mappings V8 needs to JIT JavaScript. Adding them causes the service to silently SIGTRAP at startup with `Result: core-dump` and ~5 MB peak memory — no useful log output. If you customize the unit, leave both off.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `Connection refused` on `127.0.0.1:8765` | Service not running | `sudo systemctl status s1-secops-mcp`; check `journalctl -u s1-secops-mcp -n 50`. |
| 401 on every request | No bearer token, or wrong one | Confirm `Authorization: Bearer <token>` is set; confirm the token is in `/etc/s1-secops-mcp/bearer-tokens.json`. |
| `tools/call` returns `Error: connect ECONNREFUSED` to `*.sentinelone.net` | S1 creds missing or VM has no outbound to console | `curl -v https://$YOUR_CONSOLE_URL`; check `/etc/s1-secops-mcp/credentials.json`. |
| Service starts but `Tools: 0 registered` | Code/import error | `journalctl -u s1-secops-mcp -n 100` for the import stack trace. |
| `502 Bad Gateway` from Caddy | Backend died between Caddy reload and proxy attempt | `systemctl status s1-secops-mcp`. |

## Alternative deployments

These are supported but not first-class:

- **Docker / docker-compose.** Not shipped in this version. The single-file Node binary doesn't need it. If you want a container, the install is `FROM node:20-alpine` + `RUN npm install -g @pmoses-s1/s1-secops-mcp@1.2.2` + `CMD ["s1-secops-mcp", "--transport", "http", "--host", "0.0.0.0"]`. Mount creds at `/etc/s1-secops-mcp/credentials.json` and tokens at `/etc/s1-secops-mcp/bearer-tokens.json`.

- **External bridge (`supergateway`, `mcp-proxy`).** Pre-1.1.0 deployments used these to wrap the stdio-only server. They still work; this server's native HTTP mode is functionally equivalent and removes the extra process. Prefer native unless you have a specific reason.

- **No-auth HTTP on a non-loopback bind.** Possible (set `--host 0.0.0.0` and omit `MCP_BEARER_TOKENS*`) but the server logs a loud warning at startup. Only use if the network itself is trusted (e.g. a Tailscale-only LAN where every node is authenticated upstream).
