## s1-secops-mcp 1.2.1

Supersedes 1.2.0, which was deprecated on npm. The 1.2.0 build shipped with a
stale internal `SERVER_INFO.version` of `1.1.0` despite a `1.2.0` package
version, so the server announced the wrong version on `initialize`. 1.2.1 is
feature-identical to 1.2.0 and corrects the reported runtime version.

### Added
- **`hec_ingest` tool**: raw-log / event ingestion into the Singularity Data Lake
  via the HEC endpoint (`/services/collector/raw` and `/services/collector/event`).
  Supports `parser` (`?sourcetype=`), custom `fields`, a required `scope`
  (S1-Scope header), gzip compression, and `isParsed` (`?isParsed=true`).
  Replaces the removed `sdl_upload_logs`. Validated live across the full HEC
  matrix. Grounded in the S-26.1 HEC docs (p.4723-4726).
- **Standalone Docker MCP server**: a single multi-arch image,
  `ghcr.io/pmoses-s1/s1-mcps`, bundling all three MCPs (`s1-secops-mcp`,
  `purple-mcp`, `virustotal-mcp`) with no Node, Python, or npm install required.
  An alternative to the npx/uvx path for locked-down machines. Built and
  published via the `.github/workflows/docker-publish.yml` CI workflow, with the
  image pinned at 1.2.1. End-user guide in `docs/docker.md`.

### Removed
- **`sdl_upload_logs` tool** plus the underlying SDL `uploadLogs` / `addEvents`
  functions and `SDL_LOG_WRITE_KEY` plumbing. SDL raw-log ingestion moves to
  `hec_ingest`; the `sdl-api` skill is now query + configuration only.

### Changed
- Tool count unchanged at 26 (removed `sdl_upload_logs`, added `hec_ingest`).
- Skill docs corrected: scheduled detection rules bind the Target Asset via
  `entityMappings` ("Entity column mapping"); the full scheduled-rule option set
  is catalogued in `powerquery/references/detection-rules.md`.

### Compatibility
- Default stdio invocation (`npx -y @pmoses-s1/s1-secops-mcp`) is unchanged.
- Existing `claude_desktop_config.json` and `.mcp.json` configs work without
  modification.
