## s1-secops-skills 1.4.6

Docker bundle image **1.4.6**, published to **Docker Hub** at
`docker.io/sentinelone/secops-skills`. Bundles `s1-secops-mcp` **1.3.9**, a
pandas-free `purple-mcp` fork, and a vendored `virustotal-mcp` fork. Multi-arch:
`linux/amd64` and `linux/arm64`.

The image tag versions the container, not the servers inside it.

---

## Action required: repoint your Docker config

The image is no longer on GHCR. Update the image reference for all three MCPs in
`claude_desktop_config.json`:

```json
"sentinelone/secops-skills:1.4.6"
```

Then pull and restart Claude Desktop.

```bash
docker pull sentinelone/secops-skills:1.4.6
```

**Earlier tags are gone.** Releases before 1.4.5 were published to
`ghcr.io/pmoses-s1/s1-mcps`, which is being made private. Those tags were
deleted and cannot be recovered. Docker Hub carries `1.4.5` and `1.4.6` only.
For anything older, use a copy already pulled locally (`docker image ls`).

Tags are immutable and never republished, so `--pull=missing` remains correct
against a pinned tag.

---

## Provenance

**No `v1.4.6` git tag.** Both workflows are disabled, so a tag push publishes
nothing and reports no failure. This image was built and pushed manually.

The image reports `vcs_ref: a72ae9f`, the 1.4.5 hardening commit, built roughly
three hours before `ae9e0e4` pinned 1.4.6. Six later commits are in the
repository but not in the image. All are documentation, CI configuration, and
test fixes, with no runtime change.

Confirm what is running from the image rather than from `main`:

```bash
docker run --rm sentinelone/secops-skills:1.4.6 versions
```

Digests:

- amd64 `sha256:02e136ec56466ce7a9e4b7ba80ceb09f45f0b392afda9fbd0bba2fdd25ffa510`
- arm64 `sha256:ada3a946df16cd41db0216f88c9510af2d06ed952febe61679419826ee079210`

Tagging resumes at the next CI-built release.

---

## What changed

**Registry moved to Docker Hub.** `docker.io/sentinelone/secops-skills` replaces
`ghcr.io/pmoses-s1/s1-mcps`.

**purple-mcp no longer pulls pandas.** The bundled fork drops the dependency,
previously the largest contributor to image size and the reason a native
toolchain was required at build time.

**virustotal-mcp is vendored from a pinned fork** rather than installed from
npm. Every bundled server now builds from a pinned git source, so `versions`
reports the exact repo and commit behind each. The `npm` field reports `false`.

**The VM deployment path is retired.** Docker on the laptop is the supported
install. `docs/vm-deployment.md` is removed in this sync.

---

## Verified against a live tenant

The write surface was exercised end to end on a demo account on `usea1-purple`
at this image version. Passing: SDL config file create, read, update and delete;
optimistic locking in both directions, including rejection of a stale
`expectedVersion` with no partial write; dashboard `udoId` addressing and the
duplicate-name guard; log parser create and delete; HEC raw ingest round trip;
UAM add-note and status update; Hyperautomation workflow import and delete; STAR
scheduled rule create and delete.

### Two failure modes worth knowing

**A `200 Success` from HEC does not confirm the data reached your tenant.** The
SDL Log Write Key is bound to one account or site. A key minted for a different
scope authenticates, returns `{"text":"Success","code":0}`, and discards every
event. A revoked or malformed key returns 401, so the wrong-scope case is the
one that appears healthy. Read an event back before treating an ingest as
successful.

**Do not verify ingest with a unique-string text search.** SDL indexes query
audit logs, so `* contains 'MY_MARKER'` matches its own query text and the hit
count grows on each run, resembling successful ingest. Verify by field presence,
for example `myField=*`.
