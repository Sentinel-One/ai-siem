# Changelog

## 1.2.4 - 2026-07-31

Hardening release from the 2026-07-31 code review. Tool count unchanged at 26.

### Fixed
- **Missing `Retry-After` header no longer sleeps 0ms before retrying.** `Number(null)` is 0, so `lib/s1.js`, `lib/hec.js`, and `lib/uam-ingest.js` treated an absent header as "wait 0ms" and hammered the backend. All three now use the validated pattern from `lib/sdl.js`: honor the header only when present and parseable as a finite number of seconds (capped at 30s), otherwise fall back to the exponential delay. Numeric headers behave exactly as before.
- **`uam_set_status` no longer reports silent success.** The `alertTriggerActions` mutation selected only `__typename`, so a skipped or failed action still returned as if it worked (observed live: status unchanged after a "successful" call). The selection now mirrors the full `actions { success failure skip }` shape and the client throws when the backend reports a failure entry, skips the action without a success, or returns an empty actions list (nothing applied, e.g. the filter matched no alert). `uam_add_note` was audited for the same pattern; it already verifies via the returned note list.
- **LRQ polling tolerates transient poll errors.** A single 429/5xx poll response used to throw and cancel the running query. Transient statuses now keep polling (interval doubles up to 5s) until the existing 5-minute deadline; other 4xx responses remain fatal.
- **`hasSdlCreds()` recognizes read-only key deployments.** It required `SDL_CONFIG_WRITE_KEY` or the console token; tenants configured with only `SDL_LOG_READ_KEY` / `SDL_CONFIG_READ_KEY` were reported as unconfigured. All chain keys now count.
- **HTTP transport: oversized bodies get their 413.** The request was destroyed before the response was written, so clients saw a connection reset instead of the 413 JSON error. The server now stops reading, sends the 413, then drops the connection after the response is flushed.
- **HTTP transport exits nonzero on any listen-time server error** (EACCES, EADDRNOTAVAIL, ...), not only EADDRINUSE, so systemd/Docker restart policies see the failure.
- **`powerquery_schema_discover` escapes backslashes before quotes** in the data-source name; quote-only escaping let a trailing backslash re-open the V1 filter string.
- **`s1_api_get` honors an inline `?isLegacy=` already present in the path** instead of appending a conflicting `isLegacy=false` query param, matching `_maybe_inject_islegacy` in the Python twin.
- **SDL `config_read` key chain reordered to least-privilege first** (config_read, config_write, console JWT), matching the Python `SDLClient` the header claims to mirror.

### Changed
- **Removed dead exports `purpleAiQuery` and `purpleAiInvestigate`** from `lib/s1.js`; their MCP tools were removed 2026-05-03 (browser-session teamToken requirement) and nothing referenced the library functions. Corrected stale doc text that pointed at a nonexistent `uam_set_analyst_verdict` tool: the analyst verdict is set via a raw `alertTriggerActions` mutation with the `analystVerdictUpdate` action through `s1_api_post`.
- **Deploy docs: credentials.json changes require `systemctl restart`.** SIGHUP reload only re-reads bearer tokens; the installer output and systemd unit comment said reload was enough. `deploy/install.sh` also sets `umask 077` so token/credential files are never world-readable at creation (the explicit `chmod 600` lines remain).
- **Claude Desktop bridge hardening:** 120s fetch timeout (`AbortSignal.timeout`), notification responses are drained so keep-alive sockets are released, and the URL constant no longer shadows the global `URL` constructor.
- **Docker entrypoint passes extra args through** to the selected server binary (e.g. `s1-secops-mcp --transport http`); no-args behavior is unchanged.
- **`const status = response.error ? 200 : 200`** simplified; JSON-RPC errors still return HTTP 200 with an error envelope.

### Tests
- New `tests/regressions-2026-07-31.test.mjs` (mocked fetch, no network): missing `Retry-After` uses the exponential delay, `uamSetStatus` throws on failure/skip results, inline `?isLegacy=` is honored. Both regression suites are now part of `npm test`.
- Transport and smoke tests read the expected version from `package.json` instead of a hardcoded string.

## 1.2.3 - 2026-07-29

Correctness release from the 2026-07-29 defect review. Fixes two bugs that produced plausible-but-wrong query results, hardens the SDL auth chain and HTTP retry paths, corrects the HEC `/event` content type, and adds a regression suite. Tool count unchanged at 26. (The Docker bundle image moved to 1.2.4 pinning `S1_MCP_VERSION=1.2.3`; the image tag stays ahead of the npm tag as it has since the split.)

### Fixed
- **`powerquery_run` no longer collapses a caller-supplied time window.** The old code overwrote BOTH `startTime` and `endTime` with the last-`hours` default whenever either was missing, so a startTime-only call silently ran over the last 24 hours. Each bound now defaults independently. Live A/B: a startTime-only 7.4-day query returned 73,755 events on the fixed server vs 12,911 (the 24h control) on the old one.
- **`powerquery_run` now reports `matchCount`.** It was read from the top level of the LRQ response and came back `null` on every call; it lives inside the `data` block on current engines.
- **SDL auth chain falls through on 401/403.** `lib/sdl.js` treated an auth failure on the first configured key as fatal even when a later key (e.g. the console JWT) would work. It now advances through the chain and raises only when exhausted.
- **HEC `/event` ingestion uses `application/json`,** so per-event `time` backdating is honored instead of the envelope being indexed as opaque text at receive time.

### Changed
- **Write requests no longer auto-retry on 5xx.** Retry is restricted to idempotent methods (GET/HEAD); read-only POSTs (GraphQL queries, Purple AI launches) opt back in via `allowRetry`. HEC raw ingest no longer retries 5xx (no idempotency key); UAM ingest still retries because `metadata.uid` dedupes.
- **`Retry-After` parsing hardened:** an HTTP-date value no longer collapses to `sleep(NaN)`; waits are validated and capped at 30s.
- **`uam_add_note` returns the correct note** (matches by text, tiebreaks on newest `createdAt`) instead of assuming newest-last ordering.
- **`uam_post_alert` schema help corrected** to require `class_uid 99602001` (the S1 Security Alert extension class); generic OCSF `2002` is silently dropped by the stitcher.
- **`ha_export_workflow` no longer implies it returns the archive** (metadata only).
- **`powerquery_schema_discover` escapes single quotes** in the data-source name before building the V1 filter.

### Tests
- New `tests/regressions-2026-07-29.test.mjs` (mocked fetch, no network): independent time-bound defaults, `matchCount` extraction, SDL 401/403 fall-through, HEC per-endpoint content type, write-vs-read retry semantics.

## 1.2.2 - 2026-06-13

### Changed
- **Renamed `ha_archive_workflow` to `ha_delete_workflow`.** The old tool hit `POST /hyper-automate/api/v1/workflows/archive`, which returns HTTP 500 on this tenant. The replacement uses the validated `DELETE /hyper-automate/api/v1/workflows/{id}` endpoint (a soft, recoverable delete equivalent to clicking Delete in the Hyperautomation UI). Scope the call with `accountIds` or `siteIds`; a 404 "Object not found" means the id is not under that scope or is already deleted. Updated `README.md`, the tools-table regenerator, and the smoke test in lockstep.
- **`powerquery_run` description now documents the `datasource` and `savelookup` capabilities** (querying SentinelOne-managed inventory such as assets/alerts/vulnerabilities/misconfigurations, and persisting a result as a reusable lookup table), pointing at the new `powerquery/references/datasource-command.md`.

### Notes
- Tool count unchanged at 26 (the Hyperautomation tool was renamed, not added or removed).
- `SERVER_INFO.version` bumped in lockstep with `package.json` (the drift that forced the 1.2.0 -> 1.2.1 re-release).

## 1.2.1 - 2026-06-11

Supersedes 1.2.0, which was deprecated on npm. The 1.2.0 build shipped with a stale internal `SERVER_INFO.version` of `1.1.0` despite a `1.2.0` package version, so the server announced the wrong version on `initialize`. 1.2.1 is identical in features and corrects the reported runtime version. The content below is unchanged from the 1.2.0 work.

### Added
- **`hec_ingest` tool**: raw-log/event ingestion into the Singularity Data Lake via the HEC (HTTP Event Collector) endpoint (`/services/collector/raw` and `/services/collector/event`). Supports `parser` (-> `?sourcetype=`), custom `fields` (query params), **required** `scope` (S1-Scope header), gzip compression, and `isParsed` (-> `?isParsed=true`, indexes already-structured JSON with no SDL parser). Replaces the removed `sdl_upload_logs`. Validated live across the full HEC matrix (both endpoints, gzip on/off, parser field extraction, multi-line, batched, reserved-field handling, scope enforcement, isParsed). Grounded in the S-26.1 HEC docs (p.4723-4726).

### Removed
- **`sdl_upload_logs` tool** plus the underlying SDL `uploadLogs`/`addEvents` library functions and `SDL_LOG_WRITE_KEY` plumbing. SDL raw-log ingestion moves to the HEC path (`hec_ingest`). The `sdl-api` skill is now query + configuration only; the `sdl-log-parser` validation loop uses HEC ingest.

### Changed
- Tool count unchanged at 26 (removed `sdl_upload_logs`, added `hec_ingest`).
- Skill docs corrected: scheduled detection rules bind the Target Asset via `entityMappings` ("Entity column mapping"); the full scheduled-rule option set (UI <-> API) is catalogued in `powerquery/references/detection-rules.md`.


## 1.1.0 - 2026-05-28 (rebuilt 2026-05-31)

### Fixed (rebuild)
- **`s1_api_get` now auto-injects `isLegacy=false` for `/cloud-detection/rules` listings.** Without `isLegacy=false` the S1 API silently omits `queryType="scheduled"` PowerQuery rules from the response; no error, no warning, the response just lies by omission. The handler now guards against this when the caller forgets, and the tool description loudly flags the requirement. This eliminates the "I see zero scheduled detections" failure mode that was producing wrong verdicts when listing Custom Detection rules. Same `1.1.0` version per the rebuild request.

### Added
- **Streamable HTTP transport.** New `--transport http` mode (default stays `stdio`). Single-endpoint POST `/mcp` per the MCP 2024-11-05 spec, plus `/healthz` for load balancer probes. Implementation is pure `node:http`, no new dependencies.
- **Per-user bearer token auth.** New `MCP_BEARER_TOKENS_FILE` env var pointing at a `{ "<name>": "<token>" }` JSON file gives each team member a stable name in audit logs and supports rotation. SIGHUP reloads tokens without dropping connections. `MCP_BEARER_TOKENS` env var (comma-separated raw tokens) is a fallback for small or quick-test setups.
- **Audit logging.** Every authenticated HTTP request emits `[audit] <ts> | <name> | <method> | <param-summary> | <status>` to stderr; systemd captures it via journald.
- **`S1_CREDS_FILE` credential resolver.** Highest-priority explicit path for credentials, useful for VM deployments and secret-store integrations (Vault, Doppler, 1Password Connect, sealed-secrets).
- **Deploy artifacts** under `deploy/`:
  - `install.sh`: one-shot installer for Mac and Linux. `--user` mode for individuals, `--server` mode for Linux VMs (creates `mcp` system user, generates an initial bearer token, installs systemd unit, starts the service).
  - `systemd/s1-secops-mcp.service`: hardened unit with `NoNewPrivileges`, `ProtectSystem=strict`, `MemoryDenyWriteExecute`, SIGHUP-as-reload.
  - `caddy/Caddyfile.example`: TLS reverse proxy template with bearer header gate and streaming-friendly flush.
  - `README.md`: full topology guide (single-user local, single-user HTTP, team VM-hosted) with day-2 operations.
- **Test suite.** Three new files under `tests/`, runnable via `npm test`:
  - `smoke.test.mjs`: source-of-truth tool inventory (26 tools by name).
  - `stdio-transport.test.mjs`: JSON-RPC round trip via spawned stdio process.
  - `http-transport.test.mjs`: HTTP transport end-to-end, bearer auth happy/sad paths.
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
- Default invocation is unchanged: `npx -y @pmoses-s1/s1-secops-mcp` still produces a stdio MCP server with identical behaviour to 1.0.0.
- Existing `claude_desktop_config.json` and `.mcp.json` configs work without modification.
- The 26 tools, 2 resources, and 2 prompts are unchanged from the late-1.0.0 line; only the documentation now matches reality.

## 1.0.0 - 2026-05-07

Initial public release.
- 19 tools across PowerQuery, S1 Mgmt REST, UAM, SDL API, Hyperautomation.
- stdio transport only.
- Credentials via env vars or auto-discovered `credentials.json`.
