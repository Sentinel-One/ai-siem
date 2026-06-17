# Changelog

## 1.2.2 - 2026-06-13

### Changed
- **Renamed `ha_archive_workflow` to `ha_delete_workflow`.** The old tool hit `POST /hyper-automate/api/v1/workflows/archive`, which returns HTTP 500 on this tenant. The replacement uses the validated `DELETE /hyper-automate/api/v1/workflows/{id}` endpoint (a soft, recoverable delete equivalent to clicking Delete in the Hyperautomation UI). Scope the call with `accountIds` or `siteIds`; a 404 "Object not found" means the id is not under that scope or is already deleted. Updated `README.md`, the tools-table regenerator, and the smoke test in lockstep.
- **`powerquery_run` description now documents the `datasource` and `savelookup` capabilities** (querying SentinelOne-managed inventory such as assets/alerts/vulnerabilities/misconfigurations, and persisting a result as a reusable lookup table), pointing at the new `sentinelone-powerquery/references/datasource-command.md`.

### Notes
- Tool count unchanged at 26 (the Hyperautomation tool was renamed, not added or removed).
- `SERVER_INFO.version` bumped in lockstep with `package.json` (the drift that forced the 1.2.0 -> 1.2.1 re-release).

## 1.2.1 - 2026-06-11

Supersedes 1.2.0, which was deprecated on npm. The 1.2.0 build shipped with a stale internal `SERVER_INFO.version` of `1.1.0` despite a `1.2.0` package version, so the server announced the wrong version on `initialize`. 1.2.1 is identical in features and corrects the reported runtime version. The content below is unchanged from the 1.2.0 work.

### Added
- **`hec_ingest` tool** — raw-log/event ingestion into the Singularity Data Lake via the HEC (HTTP Event Collector) endpoint (`/services/collector/raw` and `/services/collector/event`). Supports `parser` (-> `?sourcetype=`), custom `fields` (query params), **required** `scope` (S1-Scope header), gzip compression, and `isParsed` (-> `?isParsed=true`, indexes already-structured JSON with no SDL parser). Replaces the removed `sdl_upload_logs`. Validated live across the full HEC matrix (both endpoints, gzip on/off, parser field extraction, multi-line, batched, reserved-field handling, scope enforcement, isParsed). Grounded in the S-26.1 HEC docs (p.4723-4726).

### Removed
- **`sdl_upload_logs` tool** plus the underlying SDL `uploadLogs`/`addEvents` library functions and `SDL_LOG_WRITE_KEY` plumbing. SDL raw-log ingestion moves to the HEC path (`hec_ingest`). The `sentinelone-sdl-api` skill is now query + configuration only; the `sentinelone-sdl-log-parser` validation loop uses HEC ingest.

### Changed
- Tool count unchanged at 26 (removed `sdl_upload_logs`, added `hec_ingest`).
- Skill docs corrected: scheduled detection rules bind the Target Asset via `entityMappings` ("Entity column mapping"); the full scheduled-rule option set (UI <-> API) is catalogued in `sentinelone-powerquery/references/detection-rules.md`.


## 1.1.0 — 2026-05-28 (rebuilt 2026-05-31)

### Fixed (rebuild)
- **`s1_api_get` now auto-injects `isLegacy=false` for `/cloud-detection/rules` listings.** Without `isLegacy=false` the S1 API silently omits `queryType="scheduled"` PowerQuery rules from the response — no error, no warning, the response just lies by omission. The handler now guards against this when the caller forgets, and the tool description loudly flags the requirement. This eliminates the "I see zero scheduled detections" failure mode that was producing wrong verdicts when listing Custom Detection rules. Same `1.1.0` version per the rebuild request.

### Added
- **Streamable HTTP transport.** New `--transport http` mode (default stays `stdio`). Single-endpoint POST `/mcp` per the MCP 2024-11-05 spec, plus `/healthz` for load balancer probes. Implementation is pure `node:http`, no new dependencies.
- **Per-user bearer token auth.** New `MCP_BEARER_TOKENS_FILE` env var pointing at a `{ "<name>": "<token>" }` JSON file gives each team member a stable name in audit logs and supports rotation. SIGHUP reloads tokens without dropping connections. `MCP_BEARER_TOKENS` env var (comma-separated raw tokens) is a fallback for small or quick-test setups.
- **Audit logging.** Every authenticated HTTP request emits `[audit] <ts> | <name> | <method> | <param-summary> | <status>` to stderr; systemd captures it via journald.
- **`S1_CREDS_FILE` credential resolver.** Highest-priority explicit path for credentials, useful for VM deployments and secret-store integrations (Vault, Doppler, 1Password Connect, sealed-secrets).
- **Deploy artifacts** under `deploy/`:
  - `install.sh` — one-shot installer for Mac and Linux. `--user` mode for individuals, `--server` mode for Linux VMs (creates `mcp` system user, generates an initial bearer token, installs systemd unit, starts the service).
  - `systemd/s1-secops-mcp.service` — hardened unit with `NoNewPrivileges`, `ProtectSystem=strict`, `MemoryDenyWriteExecute`, SIGHUP-as-reload.
  - `caddy/Caddyfile.example` — TLS reverse proxy template with bearer header gate and streaming-friendly flush.
  - `README.md` — full topology guide (single-user local, single-user HTTP, team VM-hosted) with day-2 operations.
- **Test suite.** Three new files under `tests/`, runnable via `npm test`:
  - `smoke.test.mjs` — source-of-truth tool inventory (26 tools by name).
  - `stdio-transport.test.mjs` — JSON-RPC round trip via spawned stdio process.
  - `http-transport.test.mjs` — HTTP transport end-to-end, bearer auth happy/sad paths.
- **README auto-regenerator** at `scripts/regen-readme-tools-table.mjs`. `npm run regen:readme` keeps the README table in sync with `ALL_TOOLS`. `npm run regen:readme -- --check` fails when stale (suitable for CI).

### Fixed
- **README tool table.** Previous count was 19; actual is 26. Auto-generated now.
- **Header comment in `index.js`.** Previously said 21; updated to 26.
- **`purple_ai_query`** removed from the documentation. The tool itself was removed 2026-05-03 because the underlying API requires a browser-session `teamToken` that service-account API tokens never obtain. The README, `index.js`, and `docs/mcp-tools.md` no longer reference it.
- **`uam_set_status` documentation.** Doc previously said valid status values include `CLOSED`. The source enum is `NEW`, `IN_PROGRESS`, `RESOLVED`; doc now matches.

### Changed
- **Refactored** dispatch out of `index.js` into `lib/server-core.js` so both transports use one code path. `lib/stdio-transport.js` is the extracted stdio loop; `lib/http-transport.js` is new.
- **package.json**:
  - `version` 1.0.0 → 1.1.0
  - new scripts: `start:http`, `test`, `regen:readme`
  - new files included in the npm tarball: `deploy/`, `scripts/`, `CHANGELOG.md`

### Compatibility
- Default invocation is unchanged: `npx -y @pmoses-s1/s1-secops-mcp` still produces a stdio MCP server with identical behavior to 1.0.0.
- Existing `claude_desktop_config.json` and `.mcp.json` configs work without modification.
- The 26 tools, 2 resources, and 2 prompts are unchanged from the late-1.0.0 line; only the documentation now matches reality.

## 1.0.0 — 2026-05-07

Initial public release.
- 19 tools across PowerQuery, S1 Mgmt REST, UAM, SDL API, Hyperautomation.
- stdio transport only.
- Credentials via env vars or auto-discovered `credentials.json`.
