# Connect optional MCP servers

`s1-secops-mcp` covers what the skills need on its own: PowerQuery, SDL, the Management Console, UAM, Hyperautomation, Purple AI questions (`purple_ai_query`), and built-in VirusTotal (`ti_vt_lookup`, `ti_vt_relationship`) and Shodan (`ti_shodan_host`, `ti_shodan_dns`) lookups. You do not need any other MCP server.

This page is for when you want more: a provider's full MCP feature set, or the threat-intel provider your organisation already uses. Every server below is your choice, installed from its official source and run next to `s1-secops-mcp` as its own entry in your MCP client. None of them ships in the `sentinelone/secops-mcps` image.

> **Support and terms.** Servers installed from other sources are supported by their own maintainers, not by SentinelOne. Read each provider's terms before you connect it, in particular any commercial-use limits on free API keys.

- [Which server for what](#which-server-for-what)
- [VirusTotal official hosted MCP](#virustotal-official-hosted-mcp)
- [SentinelOne purple-mcp (open source)](#sentinelone-purple-mcp-open-source)
- [Shodan](#shodan)
- [Other threat-intel providers](#other-threat-intel-providers)
- [Other MCP clients](#other-mcp-clients)

---

## Which server for what

| You want | Use |
|---|---|
| A VirusTotal report or relationship page for an IOC | Built-in `ti_vt_lookup` / `ti_vt_relationship` (needs `VIRUSTOTAL_API_KEY`) |
| VT Intelligence search, sandbox behaviour summaries, collections, or other VirusTotal features the built-in tools leave out | [VirusTotal official hosted MCP](#virustotal-official-hosted-mcp) |
| Open ports, services and CVEs for an external IP, or DNS lookups | Built-in `ti_shodan_host` / `ti_shodan_dns` (needs `SHODAN_API_KEY`) |
| A Purple AI question, a PowerQuery, alert reads | Built-in `purple_ai_query`, `powerquery_run`, `uam_list_alerts`, `uam_get_alert` |
| purple-mcp's own tool set (for example its inventory, vulnerability and misconfiguration tools) | [SentinelOne purple-mcp](#sentinelone-purple-mcp-open-source) |
| Your organisation's threat-intel provider | That provider's MCP, see [Other threat-intel providers](#other-threat-intel-providers) |

To store or change the keys for the built-in tools, run the launcher's `setup` (or `s1-secops-mcp setup`) and restart the client. See [credentials.md](./credentials.md#the-values).

---

## VirusTotal official hosted MCP

VirusTotal runs a hosted MCP server at:

```text
https://ai.virustotal.com/mcp
```

You sign in with OAuth using a VirusTotal AI account. No API key is stored on your machine. Calls use that account's quota. The server is remote, so it cannot read local files: pass hashes, IPs, domains and URLs, not file paths.

### Claude Code

```bash
claude mcp add --transport http virustotal https://ai.virustotal.com/mcp
```

Then run `/mcp` inside Claude Code, select `virustotal`, and complete the sign-in in your browser.

VirusTotal also publishes its own Claude Code plugin; see VirusTotal's documentation for it.

### Claude Desktop and Cowork

1. Open **Settings → Connectors**.
2. Choose **Add custom connector**.
3. Enter the URL `https://ai.virustotal.com/mcp` and save.
4. Sign in with your VirusTotal AI account when prompted.

The connector is then available in Claude Desktop chats and in Cowork sessions.

---

## SentinelOne purple-mcp (open source)

SentinelOne's purple-mcp is open source at [github.com/Sentinel-One/purple-mcp](https://github.com/Sentinel-One/purple-mcp). It is optional: `s1-secops-mcp` already covers PowerQuery, alerts and Purple AI questions. Add it if you want its own tool set.

**What it needs:**

- [`uv`](https://docs.astral.sh/uv/) on the host, which provides `uvx`.
- `PURPLEMCP_CONSOLE_BASE_URL`: your console URL, for example `https://usea1-yourorg.sentinelone.net`.
- `PURPLEMCP_CONSOLE_TOKEN`: a service-user API token with **Account or Site scope** (not Global). purple-mcp is read-only.

The command it runs:

```bash
uvx --from git+https://github.com/Sentinel-One/purple-mcp.git purple-mcp --mode=stdio
```

### Keep the token out of the config file

MCP client configs are plaintext ([credentials.md](./credentials.md#mcp-client-configs-are-not-a-secret-store)). If you have the Node install of `s1-secops-mcp` ([s1-secops-mcp/README.md](../../../mcp/s1-secops-mcp/README.md)), let it start purple-mcp with the values from your OS keychain:

```bash
s1-secops-mcp exec -- uvx --from git+https://github.com/Sentinel-One/purple-mcp.git purple-mcp --mode=stdio
```

`exec` maps the stored `S1_CONSOLE_URL` and `S1_CONSOLE_API_TOKEN` to `PURPLEMCP_CONSOLE_BASE_URL` and `PURPLEMCP_CONSOLE_TOKEN` in purple-mcp's environment, so nothing secret goes into the config. If your default token is Global scope, store an Account- or Site-scoped token under its own profile (`s1-secops-mcp setup --profile purple`) and run `s1-secops-mcp exec --profile purple -- ...`.

The Docker launcher has no `exec` mode. Without the Node CLI, the token has to go in the client config's `env` block, in plaintext; if you accept that, use a dedicated read-only service user for it.

### Claude Code

```bash
claude mcp add --scope user purple-mcp -- s1-secops-mcp exec -- uvx --from git+https://github.com/Sentinel-One/purple-mcp.git purple-mcp --mode=stdio
```

Restart Claude Code; `/mcp` lists `purple-mcp`. The `s1-secops-mcp` launcher's `install --claude-code` leaves a `purple-mcp` entry like this alone, because it does not run the launcher.

### Claude Desktop and Cowork

Add an entry to `claude_desktop_config.json` (macOS: `~/Library/Application Support/Claude/`; Windows: `%APPDATA%\Claude\`, or the MSIX location described in [installation.md](./installation.md#claude-desktop)), next to the `s1-secops-mcp` entry:

```json
"purple-mcp": {
  "command": "s1-secops-mcp",
  "args": ["exec", "--", "uvx", "--from", "git+https://github.com/Sentinel-One/purple-mcp.git", "purple-mcp", "--mode=stdio"]
}
```

If Claude Desktop cannot find `s1-secops-mcp` or `uvx`, use their full paths (`which s1-secops-mcp`, `which uvx`), because Claude Desktop does not read your shell's `PATH`. Quit Claude Desktop completely and open it again. Local servers in this file also appear in Cowork sessions.

Re-running the launcher's `install` keeps this entry: it removes only entries that run the launcher.

---

## Shodan

There is no official Shodan MCP server. The built-in `ti_shodan_host` and `ti_shodan_dns` tools cover host and DNS lookups with your own `SHODAN_API_KEY`, and neither spends query credits.

Community-built Shodan MCP servers exist. If you install one, you do so at your own discretion and risk: review its code, where it sends your key, and what it can do (for example, paid search queries or scans) before you connect it.

---

## Other threat-intel providers

Any provider's MCP works next to `s1-secops-mcp`. The skills and CLAUDE.md are written provider-agnostic: they ask for a file, IP, domain or URL lookup and a malicious or benign verdict, and use whichever threat-intel tools are connected. Examples:

- **Google Threat Intelligence:** Google publishes an MCP server in [google/mcp-security](https://github.com/google/mcp-security).
- **Recorded Future, MISP** and others: use the provider's own MCP server and follow its install instructions.

Follow the provider's instructions for each client. For a local (stdio) server that needs an API key, prefer a setup that keeps the key out of the client config (the provider's own sign-in, or a secret manager that injects the variable).

---

## Other MCP clients

The same servers work in other MCP clients (for example VS Code, Cursor, Windsurf or Zed): add the hosted VirusTotal URL as a remote HTTP server, or a local server with its command and arguments as shown above. Each client has its own config format; check its documentation. The rule from [credentials.md](./credentials.md#mcp-client-configs-are-not-a-secret-store) applies everywhere: do not put tokens or API keys in a client config file.
