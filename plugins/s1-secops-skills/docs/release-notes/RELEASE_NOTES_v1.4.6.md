## s1-secops-skills 1.4.6

Docker bundle image **1.4.6** on Docker Hub: `docker.io/sentinelone/secops-skills`.
Bundles `s1-secops-mcp` 1.3.9, a pandas-free `purple-mcp` fork, and a vendored
`virustotal-mcp` fork. Multi-arch: `linux/amd64`, `linux/arm64`.

## Action required

Repoint all three MCPs in `claude_desktop_config.json`:

```json
"sentinelone/secops-skills:1.4.6"
```

```bash
docker pull sentinelone/secops-skills:1.4.6
```

Restart Claude Desktop.

Earlier GHCR tags were deleted and cannot be recovered. Docker Hub carries
`1.4.5` and `1.4.6` only.

## What changed

- Registry moved from GHCR to Docker Hub.
- `purple-mcp` no longer pulls pandas.
- `virustotal-mcp` vendored from a pinned fork. All servers build from pinned git sources.
- VM deployment path retired. Docker only. `docs/vm-deployment.md` removed in this sync.

## Provenance

No `v1.4.6` git tag. Both workflows are disabled, so a tag push publishes
nothing. This image was built and pushed manually from `a72ae9f`, before the
commits that pinned 1.4.6. Those later commits are documentation, CI
configuration, and tests only.

Confirm what you are running:

```bash
docker run --rm sentinelone/secops-skills:1.4.6 versions
```

- amd64 `sha256:02e136ec56466ce7a9e4b7ba80ceb09f45f0b392afda9fbd0bba2fdd25ffa510`
- arm64 `sha256:ada3a946df16cd41db0216f88c9510af2d06ed952febe61679419826ee079210`

Tagging resumes at the next CI-built release.

## Notes

Write surface verified end to end on a live tenant at this version.

- A `200 Success` from HEC does not confirm ingest. The SDL Log Write Key is
  bound to one account or site, and a wrong-scoped key returns success while
  discarding events. Read an event back.
- Do not verify ingest with a unique-string search. SDL indexes query audit
  logs, so the search matches its own query text. Use field presence, for
  example `myField=*`.
