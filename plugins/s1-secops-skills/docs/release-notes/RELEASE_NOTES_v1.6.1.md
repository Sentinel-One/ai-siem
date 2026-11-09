## secops-mcps image 1.6.1

Image **1.6.1** on `docker.io/sentinelone/secops-mcps` (linux/amd64, linux/arm64) runs
`s1-secops-mcp` 1.6.1 on the same distroless base as 1.6.0. It adds Detection as Code and Asset
Inventory tools and fixes two query-handling issues. The plugin moves to `s1-secops-skills` 1.4.2.

### New

- **`dac_export`, `dac_diff`, `dac_apply`:** work with the console's native Detection as Code
  engine. `dac_export` exports your custom detection rules as YAML, ready to commit. `dac_diff`
  shows what a rules bundle would create, update, delete, import or retain, and changes nothing.
  `dac_apply` applies a bundle only when a fresh diff matches the summary you reviewed.
- **`asset_inventory_counts`, `asset_inventory_search`, `asset_inventory_get`,
  `asset_inventory_filter_values`:** read the Asset Inventory: totals, filtered and paged asset
  lists on any surface (Network Discovery returns the same Active view as the console page), one
  asset's criticality, tags, coverage and alert counts, and the values that exist for a field.
- 47 tools in all: 43 with no threat-intel keys, 47 with both keys.

### Fixed

- **Subqueries in `powerquery_run`:** a subquery in the initial filter works with the default
  metering exclusion and with a site `scope`. It no longer fails with HTTP 400 `Expected ")"`.
- **`s1_api_get` on detection rules:** `isLegacy=false` is added only to the rule listing and the
  single-rule path, so `/cloud-detection/rules/export-vcs` and other sub-paths work as sent.

### Read-only mode

`dac_export`, `dac_diff` and the four `asset_inventory_*` tools are reads and run in the default
read-only mode. `dac_apply` changes the tenant and is refused until write is enabled
([read-only.md](../read-only.md)).

### Skills (plugin 1.4.2)

- **Detection as Code** uses the native engine only: YAML rules and a manifest per console, a
  console-computed diff on every pull request, apply on merge through the official SentinelOne
  `detection-as-code` reference workflow. The TOML starter is removed.
- **Unprotected endpoints report:** a new read-only solution that lists Network Discovery devices
  with no SentinelOne agent and the Sentinel Deploy remediation for each group.
- Asset Inventory GraphQL reference, custom correlation entity rules, verify-and-repeat rule
  deletion, and asset context in soc-investigator triage.

### Upgrade

```bash
~/.local/bin/s1-secops-mcp-launch.sh install --image sentinelone/secops-mcps:1.6.1   # add --read-write if you use write access
```

Windows: `powershell -NoProfile -ExecutionPolicy Bypass -File "$env:USERPROFILE\bin\s1-secops-mcp-launch.ps1" install -Image sentinelone/secops-mcps:1.6.1`
(add `-ReadWrite` if you use write access). Install plugin 1.4.2, then quit and reopen Claude
Desktop. Credentials, profiles, output folders and read-only mode carry over. Details:
[upgrading.md](../upgrading.md#160-to-161-plugin-142).

### Verify

```bash
docker run --rm sentinelone/secops-mcps:1.6.1 versions
docker buildx imagetools inspect sentinelone/secops-mcps:1.6.1 --format '{{ json .SBOM }}'
```

### Components

| Component | Version |
|---|---|
| Image `sentinelone/secops-mcps` | 1.6.1 |
| s1-secops-mcp | 1.6.1 |
| Node.js | 24.22.2 (distroless nodejs24-debian13) |
| Plugin `s1-secops-skills` | 1.4.2 |
