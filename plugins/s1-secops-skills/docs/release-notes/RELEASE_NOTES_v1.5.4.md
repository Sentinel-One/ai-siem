## secops-mcps image 1.5.4

> **Draft for review.** Not yet tagged or published.

Image **1.5.4** on `docker.io/sentinelone/secops-mcps` (linux/amd64, linux/arm64) adds a fourth,
**optional** MCP server: Shodan. `s1-secops-mcp` moves to 1.5.4 for one fix (below). The
VirusTotal and purple-mcp forks are unchanged.

### Fixed: `outputFile` under Docker (s1-secops-mcp 1.5.4)

- **Before:** with no output folder shared, a write to the container's `/tmp` or `/home/node`
  reported success, and the file was lost when the container exited. A host path was refused with
  "Set S1_OUTPUT_DIRS", which does nothing under Docker.
- **Now:** the server in the image allows only the folder shared with
  `install --output-dir`. Without it, `outputFile` is refused before any API call, and the
  message says to run `~/.local/bin/s1-secops-mcp-launch.sh install --output-dir <folder>`
  (Windows: `-OutputDir`) and restart Claude Desktop. The four `outputFile` tool descriptions, the
  `mgmt-console-api` and `powerquery` skills, and the troubleshooting tables in README, docker.md
  and upgrading.md say the same. The Node install is unchanged.
- **If you export results**, re-run `install` with `--output-dir <folder>`.
- **Plugin 1.3.15** carries the skill text change; the image does not carry the skills. Install
  `s1-secops-skills-v1.3.15.plugin` (Cowork → Customize → Browse plugins → upload → **Replace**).

### Upgrade

Re-run the launcher's `install` to pull `:1.5.4` and rewrite your entries, then restart Claude
Desktop. To add Shodan, run the launcher's `setup` and store `SHODAN_API_KEY`, run `install` again,
and restart. Without a Shodan key, nothing else changes.

```bash
docker pull sentinelone/secops-mcps:1.5.4
docker run --rm sentinelone/secops-mcps:1.5.4 versions
```

Full steps: [upgrading.md → 1.5.3 to 1.5.4](../upgrading.md#153-to-154).

### Shodan MCP (optional)

Exposure intelligence for external IPs and domains: open ports, services, banners, TLS/JARM and host
CVEs, plus CVE and CPE lookups in Shodan's CVEDB. It complements VirusTotal reputation; VirusTotal
remains the primary IOC enrichment MCP. Shodan applies only to external (non-RFC1918) IPs and
domains.

- **Server:** `shodan-mcp` (dispatcher alias `shodan`), Claude Desktop entry `shodan`.
- **Source:** a maintained fork (repo in `mcp/docker/build.sh`) of
  [`w0h1v/mcp-shodan`](https://github.com/w0h1v/mcp-shodan) (npm `@burtthecoder/mcp-shodan`
  v1.0.34, upstream commit `08bf8ee`, MIT), pinned at `1b34db4`. Vendored like the
  VirusTotal fork: compiled `build/` and production `node_modules/` committed, no npm in the image.
- **Credential:** `SHODAN_API_KEY`, optional, from [account.shodan.io](https://account.shodan.io)
  (Account page, API key). Stored in the OS keychain by the launcher's `setup` (press Enter to
  skip) and passed over stdin like the other values. The server refuses to start without a key.
- **Install:** the launcher's `install` writes the `shodan` entry only when `SHODAN_API_KEY` is
  stored, or with `--with-shodan` (Windows: `-WithShodan`).
- **Read-only:** 11 tools, all marked `readOnlyHint`. No scan, alert or monitor tools, so it never
  starts an active scan or spends scan credits.

| Tool | Cost |
|---|---|
| `ip_lookup` | No query credits |
| `shodan_search` | 1 query credit when the query uses filters, plus 1 per page past the first (page max 10) |
| `shodan_count`, `dns_lookup`, `reverse_dns_lookup`, `api_info`, `search_filters` | Free |
| `domain_info` | 1 query credit per lookup (page max 10) |
| `cve_lookup`, `cpe_lookup`, `cves_by_product` | Free (CVEDB; `cve_lookup` uses no key) |

A free ("oss") key reliably covers the CVEDB tools, `shodan_count`, `search_filters` and
`api_info`. Host lookups and DNS return "Requires membership or higher" for some targets.
`shodan_search` needs a membership or higher, and `domain_info` is billed at 1 query credit. Use a
membership or higher key for dependable results. Every Shodan API plan is limited to 1 request per second. Tool reference: [mcp-tools.md → Shodan MCP](../mcp-tools.md#shodan-mcp-optional).

### Security

- **Fork patches** (in the fork's `FORK_NOTES.md`): `page` capped at 10 on `shodan_search` and
  `domain_info`; axios redirects disabled (`maxRedirects: 0`); the API key (`key=` query parameter)
  redacted from every error string; dotenv removed, so no `.env` is loaded. Dead code is stripped
  from the vendored tree: the `mcp-proxy` CLI and the `pipenet` tunnel library it imports, plus
  its Koa closure (26 packages the stdio server never loads).
- **Supply chain at vendoring:** `npm audit` (all and production) 0 vulnerabilities; `osv-scanner`
  on the lockfile, no issues; `gitleaks` over the fork history, no leaks; upstream `npm test` pass
  on Node v24.21.0. The vendoring script now runs with lifecycle scripts disabled and fails on any
  HIGH or CRITICAL audit finding.
- **stdio only:** the entrypoint unsets `MCP_TRANSPORT`, `MCP_HOST`, `MCP_PORT` and `MCP_ENDPOINT`
  before starting Shodan, so upstream's unauthenticated HTTP transport cannot be enabled.
- **Key isolation:** `SHODAN_API_KEY` reaches only the Shodan server; it is unset for the others.
- **Network:** `api.shodan.io` and `cvedb.shodan.io` only.
- **Base image:** `node:24-trixie-slim`, now pinned by digest in both stages. Node major 24 is
  asserted at build time, and the Node version is recorded in `versions.json` (`node`) with the
  `shodan-mcp` pin.

- **libexpat1 2.9.0-1 from Debian forky (temporary):** trixie's expat 2.8.3-1~deb13u1 carries
  CVE-2026-77214 (heap over-read) and CVE-2026-93990 (UTF-16 surrogates), both HIGH, with no trixie
  fix yet. The image installs the forky build for that one package at an exact version, refuses to
  build if apt would pull anything else from forky, and removes the forky source afterwards. Only
  `python3.13` (pyexpat) links it. Drop the block once trixie-security ships a fix.
- **Unused Debian packages removed:**
  - The util-linux family, `perl-base`, `libsystemd0`, `libudev1`, `apt` and `libapt-pkg7.0` are purged in the final root step. Each either carried a HIGH CVE with no trixie fix or existed only to support one that did, and nothing in the image loads any of them.
  - The list comes from the shared-library closure of every runtime.
  - The build re-checks node, the purple-mcp imports, the shell tools, bash and tini afterwards.
  - The image has no package manager at runtime, which matches the npm deletion.
- **VEX:** `docker/vex/secops-mcps.openvex.json` records:
  - the five expat CVEs as fixed in 2.9.0-1;
  - zlib CVE-2026-85091 as not affected, because trixie's 1.3.1 predates the vulnerable code;
  - Python CVE-2026-19445 and CVE-2026-19553 as not in the execute path. The first is server-side TLS only, which nothing here runs. For the second, httpcore always passes `server_hostname`.
- **Image scans (local linux/arm64 build, HIGH/CRITICAL):**
  - Trivy 0.69.3: 34 findings across 11 packages, down from 69 across 22 in 1.5.3. 0 CRITICAL and 0 fixable.
  - Docker Scout: 3 HIGH (two expat and one zlib, all covered by the VEX), compared with 9 HIGH in the `node:24-trixie-slim` base. The "no fixable critical or high" policy passes.
  - Shodan adds no finding, and nothing under `/opt/mcp-shodan` is flagged.
  - A CycloneDX SBOM is kept with the evidence.

### Testing

- `docker/smoke-test.sh` adds T22 to T27:
  - `shodan-mcp` `tools/list` returns 11 tools;
  - `MCP_TRANSPORT=httpStream` still speaks stdio;
  - no key gives exit 78 with a hint;
  - `/opt/mcp-shodan` has no `.git`, `.env`, `src` or stripped tunnel code;
  - the Shodan key reaches only `shodan-mcp`;
  - `versions.json` records the pin and Node 24.

  `help` now lists four servers.
- The fork adds `tests/s1-hardening.test.mjs`, 7 unit tests with axios mocked, covering:
  - the page cap;
  - `maxRedirects: 0` on every HTTP helper, with the key sent only to `api.shodan.io`;
  - key redaction in thrown errors and on stderr;
  - no dotenv import, and a `.env` in the working directory being ignored.

  With upstream's suite that is 41 tests, all passing.
- `docker/launcher-test.sh` and `launcher-test.ps1` cover the optional entry: absent with no key
  stored, present with `--with-shodan` / `-WithShodan`.

### Maintainers

The vendoring script is generalised to `scripts/vendor-node-fork.sh <dir>` (runs inside a `node:24`
container); `scripts/vendor-vt-fork.sh` remains as a wrapper. Refresh steps:
[docker/README.md → Refresh the Shodan fork against upstream](../../../../mcp/docker/README.md#refresh-the-shodan-fork-against-upstream).

### Rollback

Pin `:1.5.3`. Image 1.5.3 has no Shodan server, so remove the `shodan` entry from the config.
