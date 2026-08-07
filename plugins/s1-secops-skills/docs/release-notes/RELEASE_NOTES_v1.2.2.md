## s1-secops-mcp 1.2.2

Renames the Hyperautomation workflow-removal tool to use a validated delete
endpoint, documents the PowerQuery `datasource` / `savelookup` capability on the
`powerquery_run` tool, and bumps the bundled MCP and the Docker image to 1.2.2.
Tool count is unchanged at 26.

### Changed
- **Renamed `ha_archive_workflow` to `ha_delete_workflow`.** The old tool called
  `POST /hyper-automate/api/v1/workflows/archive`, which returns HTTP 500 on this
  tenant. The replacement uses the validated `DELETE /hyper-automate/api/v1/workflows/{id}`
  endpoint, a soft, recoverable delete equivalent to clicking Delete in the
  Hyperautomation UI. Scope the call with `accountIds` or `siteIds`; a 404
  "Object not found" means the id is not under that scope or is already deleted.
  `README.md`, the tools-table regenerator, and the smoke test were updated in lockstep.
- **`powerquery_run` description now documents `datasource` and `savelookup`.**
  The query parameter help explains `| datasource <name> [from <dataset>]` for
  reading SentinelOne-managed inventory (assets, alerts, vulnerabilities,
  misconfigurations, metering) and `| savelookup '<name>'` for persisting a
  result as a reusable lookup table, pointing at the new
  `powerquery/references/datasource-command.md`.

### Fixed
- `SERVER_INFO.version` is bumped to 1.2.2 in lockstep with the package version,
  the drift that previously forced the 1.2.0 to 1.2.1 re-release.

### Docker
- The bundled image `ghcr.io/pmoses-s1/s1-mcps` is published at 1.2.2 (tags
  `:1.2.2`, `:1.2`, `:1`, and `:latest`), with the pinned `s1-secops-mcp`
  inside the image at 1.2.2. The image `IMAGE_VERSION`, the `S1_MCP_VERSION`
  pin in `docker/build.sh`, and the `.github/workflows/docker-publish.yml` env
  block were all moved to 1.2.2 (the CI pin-sync check keeps them aligned).

### Compatibility
- Default stdio invocation (`npx -y @pmoses-s1/s1-secops-mcp`) is unchanged.
- Existing `claude_desktop_config.json` and `.mcp.json` configs work without modification.
- Any script or workflow that called `ha_archive_workflow` must switch to
  `ha_delete_workflow` (same arguments, plus an explicit scope).
- Long-running MCP processes (a VM systemd service, or an open Claude session)
  keep serving the previous version until restarted; upgrade with
  `npm install -g @pmoses-s1/s1-secops-mcp@1.3.1` and restart, or repull the
  Docker image.
