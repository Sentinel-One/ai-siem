## s1-secops-skills plugin 1.3.12, image 1.5.2

Docker bundle image **1.5.2**, published to **`docker.io/sentinelone/secops-mcps`** (linux/amd64
and linux/arm64). It bundles `s1-secops-mcp` 1.5.2, the VirusTotal fork at `97ca2b8` and the
purple-mcp fork at `1390b8c`. These notes cover everything since image 1.4.10 and plugin 1.3.11,
including images 1.5.0 and 1.5.1.

### Upgrade

Coming from 1.4.x this is a **breaking** release: no `credentials.json`, no HTTP transport, and
a host launcher instead of `docker run -e`. Budget ten minutes and follow
[docs/upgrading.md](../upgrading.md#14x-to-150). In short:

```bash
# 1. Store your values in the OS keychain once (prompts without echo).
~/.local/bin/s1-secops-mcp-launch.sh setup
# 2. Pull and check the image.
docker pull sentinelone/secops-mcps:1.5.2
docker run --rm sentinelone/secops-mcps:1.5.2 versions
```

3. Point all three MCP entries in `claude_desktop_config.json` at the launcher
   (`"command": "<home>/.local/bin/s1-secops-mcp-launch.sh"`, `"args": ["s1-secops-mcp"]`,
   `["purple-mcp"]`, `["virustotal-mcp"]`), remove every token from the config, and restart Claude
   Desktop. Install the launcher outside `~/Documents`, `~/Desktop` and `~/Downloads` (macOS
   blocks it there).
4. Install or update the plugin to 1.3.12.
5. Delete any old `credentials.json` and its copies.

Coming from 1.5.0 or 1.5.1: pull `:1.5.2` and replace the launcher; see
[docs/upgrading.md](../upgrading.md#150-or-151-to-152) for the two small changes below.

### What is new

Measured on a live S-26.3.4 tenant on 2026-10-07 and 2026-10-08, A/B against MCP 1.4.0 and
image 1.4.10, natively and in the image.

- **Credentials live in the OS keychain.** macOS Keychain, Linux Secret Service (`secret-tool`)
  and Windows Credential Manager, service `sentinelone-mcp`, one item per value, with named
  profiles (`S1_PROFILE`) for several consoles. `s1-secops-mcp setup | status | forget | exec`
  manage them; `status` never prints a secret. Environment variables still override.
- **No secret in Docker metadata.** The launchers read the keychain and pass values to the
  container over stdin. Secret hits in `docker inspect` and `ps eww` went from 3 to 0 per server.
  The MCP client config holds no token.
- **purple-mcp threat intelligence** works from the same keychain VirusTotal key. The VirusTotal
  MCP stays the primary enrichment and pivot server (docs/mcp-tools.md says which to use when).
- **UAM alert management matches the console:** `uam_set_status`, the new `uam_set_verdict` and
  `uam_assign_alert` send the console's own request, then re-read the alert to prove the change. A
  refusal names the missing role permission ("Unified Alerts > ... Alerts: Manage").
- **PowerQuery at scale:** `powerquery_run` gains `queryType: "LOG"` (raw events), `slices` (2 to
  15 parallel time slices) with an exact `merge`, and `outputFile` (CSV, JSONL, JSON). Ids and
  nanosecond timestamps beyond 2^53 come back exact.
- **Files out:** `outputFile` on `s1_api_get` and `ha_export_workflow`, and the new
  `s1_api_download` for binary downloads, restricted to `S1_OUTPUT_DIRS`, mode 0600.
- **One console token (1.5.2).** The optional `S1_CONSOLE_API_TOKEN_SINGLE_SCOPE` and the
  `tokenKind` parameter are removed. IOC writes work with the regular token of a user scoped to
  one account (verified live). Error 4030010 now explains how to use a single-account token through
  a second keychain profile.
- **`S1_SCOPE` (1.5.2)** is `<accountId>` or `<accountId>:<siteId>`; setup no longer accepts a
  group part that the SDL and PowerQuery tools would reject.
- **Plugin 1.3.12** is smaller: each skill's maintainer `tests/` and `evals/` stay out of the
  package, apart from the lifecycle tests the skills tell you to run. Dashboard deploys default to
  `sdl_create_dashboard` (public, deployable to a site), and the docs were re-synced with the code.

### Removed

`credentials.json` and its discovery chain, the plugin's SessionStart credential hook, the HTTP
transport and bearer tokens, the shared team-VM deployment, `S1_CONSOLE_API_TOKEN_SINGLE_SCOPE`
and `tokenKind`, sharing a dashboard to a site (`sdl_share_dashboard` takes `scopeType: account`;
create the dashboard at the site instead).

### Security

- **Plaintext credentials are gone.** Tokens and keys live in the OS keychain, one item per value,
  and are never written to disk in clear text.
- **`credentials.json` is no longer loaded.** The server, the Python clients and the plugin's
  session hook used to search several folders for a plaintext credentials file, so any stray copy
  could be picked up. That code is removed. Import an existing file once with
  `s1-secops-mcp setup --import-json`, then delete it and any copies.
- **No secrets in client configs or Docker metadata.** The launcher passes values to the container
  over stdin, so they no longer appear in `claude_desktop_config.json`, `docker inspect` or the
  process list. Tool output and logs mask configured secrets.
- VirusTotal fork `97ca2b8`: `proxy-addr` 2.0.8 (CVE-2026-90711, critical) and
  `@modelcontextprotocol/sdk` 1.32.1 (CVE-2026-104850, high). Neither was reachable in the stdio
  server; both are fixed so scans come back clean.
- Docker Scout on the 1.5.2 image, both architectures: 0 critical, 3 high, all in Debian 13
  packages with no fixed version yet (expat 2, zlib 1); nothing with an available fix.
- Smoke test and the full live regression suite pass on both architectures.

### Rollback

Pin `:1.5.1`, `:1.5.0` or `:1.4.10` (all immutable). 1.4.10 reads tokens from the config `env`
block or a `credentials.json`, so rolling back to it puts plaintext tokens back on disk.
