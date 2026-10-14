## secops-mcps image 1.5.6

Image **1.5.6** on `docker.io/sentinelone/secops-mcps` (linux/amd64, linux/arm64) is a security
update to read-only mode in `s1-secops-mcp` 1.5.6 and is recommended for all users. The plugin
stays at `s1-secops-skills` 1.3.16, and the purple-mcp, VirusTotal and Shodan pins are unchanged.

### Security

- **Read-only checks follow the request URL.** `s1_api_post` now decides read or write from the
  exact path the request is sent to. Paths whose written form and resolved form could differ are
  treated as writes and refused in read-only mode before any network call: `#` fragments, `;`
  parameters, backslashes, whitespace, percent-encoded `#`, `;`, `/`, `\` or `.`, and `.` or `..`
  segments.
- **Stricter paths for all Management API tools.** A `#` or `\` in an API path is rejected for
  every Management API tool, read or write.

### Upgrade

```bash
~/.local/bin/s1-secops-mcp-launch.sh install              # add --read-write if you use write access
```

Windows: `powershell -NoProfile -ExecutionPolicy Bypass -File "$env:USERPROFILE\bin\s1-secops-mcp-launch.ps1" install`
(add `-ReadWrite` if you use write access). Then quit and reopen Claude Desktop. Credentials,
profiles, output folders and the 1.3.16 plugin carry over. Details:
[upgrading.md](../upgrading.md#155-to-156).

### Verify

```bash
docker run --rm sentinelone/secops-mcps:1.5.6 versions
docker buildx imagetools inspect sentinelone/secops-mcps:1.5.6 --format '{{ json .SBOM }}'
```

### Components

| Component | Version |
|---|---|
| Image `sentinelone/secops-mcps` | 1.5.6 |
| s1-secops-mcp | 1.5.6 |
| purple-mcp, VirusTotal MCP, Shodan MCP | unchanged pins |
| Plugin `s1-secops-skills` | 1.3.16 (unchanged) |
