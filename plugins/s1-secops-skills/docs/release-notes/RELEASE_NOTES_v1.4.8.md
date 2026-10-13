## s1-secops-skills 1.4.8

Docker bundle image **1.4.8**, published to **`docker.io/sentinelone/secops-mcps`**.
Bundles `s1-secops-mcp` 1.3.9, a pandas-free `purple-mcp` fork, and a vendored
`virustotal-mcp` fork. Multi-arch: `linux/amd64`, `linux/arm64`.

**The image was renamed.** `sentinelone/secops-skills` receives no further
releases and is scheduled for deletion.

## Action required

Repoint all three MCPs in `claude_desktop_config.json`:

```json
"sentinelone/secops-mcps:1.4.8"
```

```bash
docker pull sentinelone/secops-mcps:1.4.8
```

Restart Claude Desktop.

| Repository | Carries | Status |
|---|---|---|
| `sentinelone/secops-mcps` | `1.4.8` | current |
| `sentinelone/secops-skills` | `1.4.5`, `1.4.6` | scheduled for deletion, do not rely on it |
| `ghcr.io/pmoses-s1/s1-mcps` | earlier tags | scheduled for deletion, do not rely on it |

Treat `1.4.8` as the only image you can count on. There is no rollback target.

## Fixed

Both of these shipped in source before 1.4.6 was cut but were not in that image.
This is the first image to carry them.

- **`hec_ingest` no longer reports a rejected batch as a successful ingest.** The
  event collector returns its per-batch outcome in the response body, not the
  status line, so a Log Write Key minted for the wrong account or site answered
  `HTTP 200 {"text":"Success","code":0}`-shaped output while discarding every
  event. The client now fails on a non-zero `code` and names the code and text.
- **An empty bearer-token file no longer disables authentication.** A token file
  of `{}` produced zero tokens, which made `isAuthConfigured()` false and dropped
  the HTTP transport onto its no-auth path. A `SIGHUP` reload that would take an
  authenticated server to zero tokens is now refused. Reachable only under
  `--transport http`; the stdio install was never exposed.

## Provenance

Tagged `s1-mcps-v1.4.8` on the exact commit the image was built from, so the
tag, the commit and the image's `vcs_ref` all read `aa234e0`. Both CI workflows
remain disabled, so this image was built and pushed by hand.

Confirm what you are running:

```bash
docker run --rm sentinelone/secops-mcps:1.4.8 versions
```

Tags are immutable and never republished, so `--pull=missing` remains correct
against a pinned tag. There is no `:latest`.
