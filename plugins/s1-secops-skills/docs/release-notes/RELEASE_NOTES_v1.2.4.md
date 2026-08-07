## s1-secops-mcp 1.2.4

Hardening release. All fixes verified by an old-vs-new A/B harness (16/16
probes) and a 56/56 unit suite. Tool count unchanged at 26.

Versioning: npm package **1.2.4** (from 1.2.3). Docker bundle image **1.2.5**
(from 1.2.4), pinning `S1_MCP_VERSION=1.2.4`.

### Fixed

- Missing `Retry-After` header no longer produces zero-delay retry storms in
  `lib/s1.js`, `lib/hec.js`, and `lib/uam-ingest.js`; exponential backoff
  applies, header honored only when present and valid, capped at 30s.
- `uam_set_status` verifies the mutation result and throws on failure entries,
  skip-without-success, or an empty actions list instead of reporting silent
  success.
- LRQ polling tolerates transient 429/5xx poll responses with backoff until
  the 5-minute deadline; other 4xx remain fatal.
  `SDL_CONFIG_READ_KEY`).
- HTTP transport returns a proper 413 for oversized bodies (was a connection
  reset) and exits non-zero on any listen failure so systemd restarts apply.
- `powerquery_schema_discover` escapes backslashes as well as quotes in the
  V1 filter.
- `s1_api_get` honors an inline `?isLegacy=` already present in the path.

### Changed

- `config_read` SDL key chain order now exactly mirrors the Python client.
- Removed unused `purpleAiQuery` / `purpleAiInvestigate` exports and stale
  references to a nonexistent `uam_set_analyst_verdict` tool.
- Bridge: 120s upstream timeout, notification bodies drained, `URL` global no
  longer shadowed.
- Docker entrypoint passes extra arguments through to the selected server.
- Installer sets `umask 077` before writing token/credential files;
  credential rotation guidance corrected to `systemctl restart`.

### Tests

- New `tests/regressions-2026-07-31.test.mjs`; `npm test` now runs both
  regression suites and reads the expected version from package.json.
