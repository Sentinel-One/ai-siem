## secops-mcps image 1.6.0

Image **1.6.0** on `docker.io/sentinelone/secops-mcps` (linux/amd64, linux/arm64) runs a single MCP
server, `s1-secops-mcp` 1.6.0, on a distroless base. Purple AI questions and VirusTotal and Shodan
lookups are now built-in tools of that server, and the image contains no third-party MCP server.
The plugin moves to `s1-secops-skills` 1.4.0.

### New

- **`purple_ai_query`:** ask Purple AI a question in natural language with the console API token
  you already store. It returns a written answer, or a PowerQuery and time range to review and run
  with `powerquery_run`.
- **`ti_vt_lookup`, `ti_vt_relationship`:** VirusTotal reports for hashes, IPs, domains and URLs,
  and the common relationship pivots (contacted infrastructure, resolutions, communicating files,
  related threat actors). Listed when `VIRUSTOTAL_API_KEY` is stored.
- **`ti_shodan_host`, `ti_shodan_dns`:** Shodan host exposure (ports, services, CVEs, owner, tags)
  and DNS resolution. Listed when `SHODAN_API_KEY` is stored. Neither spends query credits.
- All five tools are read-only and call each service directly under your own key.

### Changed

- **One server.** `install` writes the `s1-secops-mcp` entry and removes the older `purple-mcp`,
  `virustotal` and `shodan` entries that ran the launcher. Servers you added with other commands
  are kept. Other MCP servers, such as VirusTotal's official hosted MCP or SentinelOne's
  open-source purple-mcp, can be added from their official sources:
  [connect-optional-tools.md](../connect-optional-tools.md).
- **Smaller image with a smaller attack surface.** Base `gcr.io/distroless/nodejs24-debian13`
  (Node.js 24.22.2), with no shell, package manager, npm or Python, running as an unprivileged user.
  12 packages, 224 MB. Docker Scout reports 0 critical, 0 high and 0 medium findings; the 7 low
  findings are disputed glibc entries with no fix.
- `setup` prompts for `SHODAN_API_KEY` as well as `VIRUSTOTAL_API_KEY`.
- `--with-shodan` (Windows: `-WithShodan`) is still accepted and has no effect.

### Upgrade

```bash
~/.local/bin/s1-secops-mcp-launch.sh install              # add --read-write if you use write access
```

Windows: `powershell -NoProfile -ExecutionPolicy Bypass -File "$env:USERPROFILE\bin\s1-secops-mcp-launch.ps1" install`
(add `-ReadWrite` if you use write access). Install plugin 1.4.0, then quit and reopen Claude
Desktop. Credentials, profiles, output folders and read-only mode carry over. If saved prompts or
runbooks name tools from the removed servers, see the rename table in
[upgrading.md](../upgrading.md#157-to-160).

### Verify

```bash
docker run --rm sentinelone/secops-mcps:1.6.0 versions
docker buildx imagetools inspect sentinelone/secops-mcps:1.6.0 --format '{{ json .SBOM }}'
```

### Components

| Component | Version |
|---|---|
| Image `sentinelone/secops-mcps` | 1.6.0 |
| s1-secops-mcp | 1.6.0 |
| Node.js | 24.22.2 (distroless nodejs24-debian13) |
| Plugin `s1-secops-skills` | 1.4.0 |
