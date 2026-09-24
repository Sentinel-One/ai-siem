## s1-secops-skills 1.4.6

Docker bundle image **1.4.6**, published to **Docker Hub** at
`docker.io/sentinelone/secops-skills`. Bundles `s1-secops-mcp` **1.3.9**, a
pandas-free `purple-mcp` fork, and a vendored `virustotal-mcp` fork. Multi-arch:
`linux/amd64` and `linux/arm64`.

The image tag versions the container, not the servers inside it. The three
numbers differ on purpose and always have.

The registry move is the headline. Everything else follows from it.

---

## Action required: repoint your Docker config

The image is no longer on GHCR. Update the image reference for all three MCPs in
`claude_desktop_config.json`:

```json
"sentinelone/secops-skills:1.4.6"
```

Then pull it and restart Claude Desktop.

```bash
docker pull sentinelone/secops-skills:1.4.6
```

**Earlier tags are gone.** Releases before 1.4.5 went to
`ghcr.io/pmoses-s1/s1-mcps`, which is being made private. Those tags were
deleted and cannot be recovered. Docker Hub carries `1.4.5` and `1.4.6` only. If
you need an older image, you need a copy you already pulled. Run
`docker image ls` to see what survived on the machine.

Version tags stay immutable and are never republished, so `--pull=missing`
remains correct against a pinned tag.

---

## Provenance: read this before you trust the tag

**There is no `v1.4.6` git tag, on purpose.** This release was built and pushed
by hand, outside CI. The repository state does not cleanly match the published
bytes, and that is worth writing down rather than leaving for someone to trip
over later.

Both GitHub Actions workflows are disabled. Actions billing is unresolved.
Publishing now targets Docker Hub, and the `DOCKERHUB_USERNAME` and
`DOCKERHUB_TOKEN` repo secrets do not exist yet. `docker-publish.yml` fires on
`push: tags: ["v*"]`. Push a release tag today and it publishes nothing, silently.
A tag would promise a CI-built artifact that was never built.

Here is what the published image reports:

```
image_version: 1.4.6
vcs_ref:       a72ae9f
build_date:    2026-09-24T07:35:45+05:30
```

`a72ae9f` is the 1.4.5 image-hardening commit. The commit that defines this
release is `ae9e0e4`, "Move to Docker Hub, pin 1.4.6, drop the VM deployment
path". It landed at 10:33, about three hours after the image was built. So these
commits sit in the repository but not in the image:

| Commit | Not in the 1.4.6 image |
|---|---|
| `ae9e0e4` | Move to Docker Hub, pin 1.4.6, drop the VM deployment path |
| `d238bfa` | Fix T17 silently skipping on py<3.12 |
| `2fdd03c` | Fix maintainer docs the repoint pass could not see |
| `b4aabd5` | Staleness audit: CI registry fix, 11 stale docs |
| `2f61ce7` | Disable both workflows and say so in the files |
| `47497cd` | Quick start: lead with the Docker prerequisite |

All six are documentation, CI configuration, and test fixes. None of them touch
runtime behaviour of the bundled servers, which is why the image is still good
to run. Just do not read the tip of `main` as a description of what you have
running.

The image is real and in active use. Ask it what it is rather than inferring
from the tag:

```bash
docker run --rm sentinelone/secops-skills:1.4.6 versions
```

Published manifest digests:

- `linux/amd64` `sha256:02e136ec56466ce7a9e4b7ba80ceb09f45f0b392afda9fbd0bba2fdd25ffa510`
- `linux/arm64` `sha256:ada3a946df16cd41db0216f88c9510af2d06ed952febe61679419826ee079210`

The next release closes this gap. Once billing is restored and the Docker Hub
secrets are in place, it gets cut through a full end-to-end CI build and
publish, then tagged. `1.4.6` will not be republished. Tags are immutable.

---

## What changed

**Registry moved to Docker Hub.** `docker.io/sentinelone/secops-skills` replaces
`ghcr.io/pmoses-s1/s1-mcps`.

**purple-mcp no longer pulls pandas.** The bundled fork drops the dependency. It
was the single largest contributor to image size and dragged a native toolchain
into the build.

**virustotal-mcp is vendored from a pinned fork** instead of installed from npm.
Every bundled server now builds from a pinned git source, so `versions` reports
the exact repo and commit behind each one. The `npm` field reports `false`.

**The VM deployment path is retired.** Docker on the laptop is the supported
install. `docs/vm-deployment.md` is removed in this sync.

---

## Verified against a live tenant

The write surface was exercised end to end on a demo account on `usea1-purple`
at this image version. Passing: SDL config file create, read, update and delete.
Optimistic locking in both directions, including correct rejection of a stale
`expectedVersion` with no partial write. Dashboard `udoId` addressing and the
duplicate-name guard. Log parser create and delete. HEC raw ingest round trip.
UAM add-note and status update. Hyperautomation workflow import and delete. STAR
scheduled rule create and delete.

### Two gotchas that cost us time

**A `200 Success` from HEC does not mean the data reached your tenant.** The SDL
Log Write Key is bound to one account or site. A key minted for a different
scope authenticates cleanly, returns `{"text":"Success","code":0}`, and discards
every event. A revoked or malformed key returns 401. The wrong-scope case is the
one that looks healthy, which is what makes it expensive. Read an event back
before you call an ingest working.

**Do not verify ingest with a unique-string text search.** SDL indexes query
audit logs, so `* contains 'MY_MARKER'` matches its own query text. The hit count
then grows on every run, which reads exactly like successful ingest. Verify by
field presence instead, for example `myField=*`.
