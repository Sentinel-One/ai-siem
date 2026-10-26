## secops-mcps image 1.5.7

Image **1.5.7** on `docker.io/sentinelone/secops-mcps` (linux/amd64, linux/arm64) is a security
maintenance release that updates the base image and the bundled MCP dependencies. It is
recommended for all users. `s1-secops-mcp` moves to 1.5.7 with no change in behaviour, and the
plugin stays at `s1-secops-skills` 1.3.17.

### Security

- **Base image:** Node.js 24.22.1 (`node:24-trixie-slim`, pinned by digest).
- **purple-mcp:** updated certifi, fastmcp, OpenTelemetry and setuptools.
- **VirusTotal and Shodan MCPs:** updated zod, follow-redirects, undici, body-parser, fast-uri,
  hono and ip-address.
- **Result:** Docker Scout reports no fixable vulnerabilities and no critical findings.

### Upgrade

```bash
~/.local/bin/s1-secops-mcp-launch.sh install              # add --read-write if you use write access
```

Windows: `powershell -NoProfile -ExecutionPolicy Bypass -File "$env:USERPROFILE\bin\s1-secops-mcp-launch.ps1" install`
(add `-ReadWrite` if you use write access). Then quit and reopen Claude Desktop. Credentials,
profiles, output folders and the 1.3.17 plugin carry over. Details:
[upgrading.md](../upgrading.md#156-to-157).

### Verify

```bash
docker run --rm sentinelone/secops-mcps:1.5.7 versions
docker buildx imagetools inspect sentinelone/secops-mcps:1.5.7 --format '{{ json .SBOM }}'
```

### Components

| Component | Version |
|---|---|
| Image `sentinelone/secops-mcps` | 1.5.7 |
| s1-secops-mcp | 1.5.7 |
| Node.js | 24.22.1 |
| VirusTotal MCP, Shodan MCP | updated dependency pins |
| purple-mcp | unchanged pin, updated dependencies |
| Plugin `s1-secops-skills` | 1.3.17 (unchanged) |
