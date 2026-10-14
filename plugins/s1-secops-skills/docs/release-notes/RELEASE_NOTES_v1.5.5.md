## secops-mcps image 1.5.5

Image **1.5.5** on `docker.io/sentinelone/secops-mcps` (linux/amd64, linux/arm64) introduces
**read-only mode by default** for `s1-secops-mcp`, adds third-party notices to the image, and
publishes SLSA provenance and an SPDX SBOM with every image. Ships with `s1-secops-mcp` 1.5.5 and
plugin `s1-secops-skills` 1.3.16.

> **Action required if Claude deploys content or triages alerts for you**
>
> `s1-secops-mcp` now starts in read-only mode. Tools that change your SentinelOne tenant (alert
> notes, status, verdicts and assignment; dashboards, parsers and lookup tables; Hyperautomation
> import and delete; HEC and UAM ingest; Management API writes) return a clear message with the
> steps to enable write. To keep write access, re-run the install with `--read-write`
> (Windows: `-ReadWrite`) and restart Claude Desktop:
>
> ```bash
> ~/.local/bin/s1-secops-mcp-launch.sh install --read-write
> ```
>
> Investigation, hunting and reporting need no change. See [read-only.md](../read-only.md).

### Read-only mode

- **Setting:** `S1_READ_ONLY`. Read-only when unset or `true`; write enabled with `false`. Any
  unrecognised value keeps read-only mode.
- **Available in read-only mode:** PowerQuery, schema discovery, Management API reads, query-type
  POSTs (GraphQL queries, Deep Visibility, query validation, graph explorer), UAM list and get, Data
  Lake file and dashboard reads, Hyperautomation list, get and export, and local file output.
- **Requires write mode:** the 18 tools that change tenant state, other `s1_api_post` calls, and
  PowerQuery `| savelookup`. Full list in [read-only.md](../read-only.md).
- **Client visibility:** every tool stays listed, write tools are labelled while read-only, and all
  tools carry the MCP annotations `readOnlyHint`, `destructiveHint` and `openWorldHint`.
- **Scope:** applies to `s1-secops-mcp`. purple-mcp, VirusTotal and Shodan are unchanged.

### When write is enabled

- Writes require a configured console API token and are declined if the token has expired. The
  server warns at startup when the token expires within 7 days.
- Each write is recorded in the server audit log
  (`[s1-secops-mcp] WRITE <time> tool=<name> path=...`), without request bodies or credentials.
- The startup log shows the active mode, and `credentials-status` reports it.
- Use a least-privilege service user; the token's console role remains the governing control.

| Install method | Enable write | Return to read-only |
|---|---|---|
| Docker launcher, macOS or Linux | `s1-secops-mcp-launch.sh install --read-write` | `s1-secops-mcp-launch.sh install` |
| Docker launcher, Windows | `s1-secops-mcp-launch.ps1 install -ReadWrite` | `s1-secops-mcp-launch.ps1 install` |
| Claude Desktop extension (`.mcpb`) | Turn off **Read-only mode (recommended)** | Turn it back on |
| Node install | `"S1_READ_ONLY": "false"` in the server's `env` block | Remove the line |
| `docker run` | `-e S1_READ_ONLY=false` | Omit it |

Restart Claude Desktop after any change.

### Third-party notices

- [THIRD_PARTY_NOTICES.md](../../THIRD_PARTY_NOTICES.md) lists each bundled component, its
  license, and the terms that apply to the VirusTotal and Shodan services. It is included in the
  image at `/usr/share/doc/secops-mcps/THIRD_PARTY_NOTICES.md`.
- The `s1-secops-mcp` license (AGPL-3.0) is included at `/opt/s1-secops-mcp/LICENSE`.
- New `notices` command: `docker run --rm sentinelone/secops-mcps:1.5.5 notices`, or
  `s1-secops-mcp-launch.sh notices`.

### Supply-chain attestations

Each image is published with SLSA provenance and an SPDX SBOM attached to its index. Docker Hub
lists the attestations as an `unknown/unknown` platform entry; pulls are unaffected.

### Plugin 1.3.16

Install `s1-secops-skills-v1.3.16.plugin` (Cowork → Customize → Browse plugins → upload →
**Replace**).

- All eight skills support read-only mode: they check the mode before multi-step deployments,
  explain how to enable write when needed, and offer the artifact as a local file.
- powerquery: rounding with `floor(x * 10 + 0.5) / 10`, and unique field names across `let` stages.
- sdl-dashboard: minimum table height, vendor field-coverage checks, and a cross-vendor
  "blocked" match (`block`, `deny`, `drop`, `reject`).
- sdl-solutions: detections are validated by their UAM alert and an `Active` rule status; new
  field-coverage step when onboarding a source.

### Upgrade

```bash
docker pull sentinelone/secops-mcps:1.5.5
~/.local/bin/s1-secops-mcp-launch.sh install [--read-write] [--profile P] [--output-dir DIR] [--with-shodan]
```

Then install plugin 1.3.16 and restart Claude Desktop. Credentials, profiles, output folders and
CLAUDE.md overrides carry over. Details: [upgrading.md](../upgrading.md#154-to-155).

### Verify

```bash
docker run --rm sentinelone/secops-mcps:1.5.5 versions
docker run --rm sentinelone/secops-mcps:1.5.5 notices
docker buildx imagetools inspect sentinelone/secops-mcps:1.5.5 --format '{{ json .SBOM }}'
docker buildx imagetools inspect sentinelone/secops-mcps:1.5.5 --format '{{ json .Provenance }}'
```

### Components

| Component | Version |
|---|---|
| Image `sentinelone/secops-mcps` | 1.5.5 |
| s1-secops-mcp | 1.5.5 |
| purple-mcp, VirusTotal MCP, Shodan MCP | unchanged pins |
| Plugin `s1-secops-skills` | 1.3.16 |
