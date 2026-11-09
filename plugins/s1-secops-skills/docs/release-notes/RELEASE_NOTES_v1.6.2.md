## secops-mcps image 1.6.2

Image **1.6.2** on `docker.io/sentinelone/secops-mcps` (linux/amd64, linux/arm64) runs
`s1-secops-mcp` 1.6.2 on the same distroless base as 1.6.1. It ties `dac_apply` to the bundle you
reviewed and hardens the Detection as Code tools. The plugin stays `s1-secops-skills` 1.4.2; reinstall the current bundle for the skill changes below.

### Changed

- **`dac_apply` requires `expectedZipSha256`:** pass `bundle.zipSha256` from the `dac_diff` you
  reviewed, together with `expectedSummary`. The bundle is rebuilt from the same input and must
  hash to that value before anything is sent, so a changed rule file is refused even when the change
  counts are the same.
- **An apply that may have been committed says so:** a timeout, network error or HTTP 5xx on
  `dac_apply` is not retried, and the error tells you to run `dac_diff` before trying again.
  HTTP 429 is retried, on the basis that the console refuses before processing.
- **`deploymentsFile` must be a `.yaml` or `.yml` file.**
- **Asset Inventory filters:** `match` is a case-insensitive contains for text fields such as
  `name`. List fields (`missingCoverage`, `activeCoverage`, `surfaces`, `discoveryMethods`) take
  `stringIn`; the tool descriptions say so.

### Skills (plugin 1.4.2 bundle)

- Detection as Code playbook: `dac_apply` takes `expectedSummary` and `expectedZipSha256` from the
  reviewed `dac_diff`.
- PowerQuery: the automatic `tag != 'logVolume'` predicate sits outside a subquery in the initial
  filter; write it inside the subquery when the subquery ranks or counts by source.
- Asset Inventory GraphQL reference: the `match` shape is `{values: [..]}`, and the list fields
  refuse it with `Invalid filter type FULLTEXT`.
- Unprotected endpoints: a user guide in `docs/solutions/unprotected-endpoints.md`.

The distroless 1.6.x images have no OpenVEX document; `docker/vex/` covers 1.5.x images only.

### Upgrade

Install the 1.6.2 launcher, which writes the 1.6.2 image into your client config:

```bash
mkdir -p ~/.local/bin && curl -fsSL https://raw.githubusercontent.com/Sentinel-One/ai-siem/main/mcp/docker/s1-secops-mcp-launch.sh -o ~/.local/bin/s1-secops-mcp-launch.sh && sh ~/.local/bin/s1-secops-mcp-launch.sh install   # add --read-write if you use write access
```

Or keep your launcher and pin the image:
`~/.local/bin/s1-secops-mcp-launch.sh install --image sentinelone/secops-mcps:1.6.2`. Reinstall plugin
1.4.2 from the current bundle, then quit and reopen Claude Desktop. Credentials, profiles, output folders and read-only mode
carry over. Details, including Windows: [upgrading.md](../upgrading.md#161-to-162-plugin-142).
