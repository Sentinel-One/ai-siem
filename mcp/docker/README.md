# Docker image: SentinelOne SecOps MCP

One image, one MCP server: `s1-secops-mcp`, on a distroless Node 24 base. Purple AI questions (`purple_ai_query`), VirusTotal lookups (`ti_vt_lookup`, `ti_vt_relationship`) and Shodan lookups (`ti_shodan_host`, `ti_shodan_dns`) are built-in tools of that server, written in this repo and calling each service with the user's own keys. End users need only Docker: no Node, no Python, no `uv`, no `npm install`. This is the documented install path; see [`docs/installation.md`](../../plugins/s1-secops-skills/docs/installation.md).

End-user reference: [`docs/docker.md`](../../plugins/s1-secops-skills/docs/docker.md). This file is for image maintainers. Other MCP servers are never shipped in this image; users add them from their official sources ([`docs/connect-optional-tools.md`](../../plugins/s1-secops-skills/docs/connect-optional-tools.md)).

## What is in the image

The base is `gcr.io/distroless/nodejs24-debian13`, pinned by digest (Node v24.22.2 at the current pin). It holds Node, glibc, libstdc++, CA certificates and tzdata, and nothing else:

- **No shell, no package manager, no npm, no Python, no init.** A future `RUN npm install ...` or shell-form `RUN` fails at build time. Every `RUN` in the Dockerfile uses the exec form.
- **No registry resolution.** `s1-secops-mcp` declares no runtime dependencies (its one optional dependency, the Windows keychain binding, is unused in a container), so the `COPY`'d source is the install.
- **Four unused base packages are removed at build time:** `libssl3t64`, `zlib1g`, `libzstd1` and `libgomp1`. The official Node binary compiles in its own OpenSSL and zlib, so nothing loads them, and they carried the base image's only scanner findings. The build step deletes their files and dpkg records, then `__image_verify` proves crypto, TLS and zlib still work and that none of the removed libraries is mapped.
- **Runs as `nonroot`** (uid/gid 65532, home `/home/nonroot`). Nothing writes inside the container; the server reads its code from `/opt` and speaks JSON-RPC over stdio. Node handles SIGINT and SIGTERM itself, so no init is needed.

Docker Scout, 2026-11-05: 12 packages, 0 critical, 0 high, 0 medium, 7 low (old disputed glibc entries with no fix). Image size: 224 MB.

[`docker/vex/secops-mcps.openvex.json`](vex/secops-mcps.openvex.json) holds the VEX statements for earlier 1.5.x images; pass it with `docker scout cves --vex-location docker/vex` or `trivy image --vex docker/vex/secops-mcps.openvex.json` when scanning those tags.

## Layout

```text
docker/
├── Dockerfile                 # one stage, distroless Node 24 base pinned by digest, exec-form RUN only
├── container-entry.mjs        # dispatcher (ENTRYPOINT): s1-secops-mcp | versions | notices | help
├── s1-secops-mcp-launch.sh    # host launcher (macOS, Linux, WSL): keychain -> container stdin
├── s1-secops-mcp-launch.ps1   # host launcher (Windows): Credential Manager -> container stdin
├── launcher-test.sh           # hermetic tests for the launcher's install/config (macOS, Linux)
├── launcher-test.ps1          # the same for the Windows launcher (pwsh or Windows PowerShell)
├── build.sh                   # local + push build wrapper; owns BASE_IMAGE and IMAGE_VERSION
├── smoke-test.sh              # image smoke test (32 checks; probes with --entrypoint /nodejs/bin/node)
├── Dockerfile.dockerignore    # build-context exclusions; BuildKit reads <Dockerfile>.dockerignore, patterns are repo-root relative
├── vex/                       # OpenVEX statements for earlier images
└── README.md                  # this file
```

Inside the image:

```text
/opt/s1-secops-mcp/                    the server, from this repo
/usr/local/lib/s1-secops/entry.mjs     dispatcher (docker/container-entry.mjs)
/etc/sentinelone/CLAUDE.md             default SOC analyst persona
/etc/sentinelone/versions.json         what is actually inside this image
/usr/share/doc/secops-mcps/THIRD_PARTY_NOTICES.md
```

The dispatcher accepts `s1-secops-mcp` (alias `s1`), `versions`, `notices` (aliases `licenses`, `license`) and `help`. An unknown command exits 64. The server names removed in 1.6.0 (`purple-mcp`, `virustotal-mcp`, `shodan-mcp` and their aliases) exit 78 with one line telling the user to run the launcher's `install` again, so an MCP client still configured for an old entry logs a clear instruction.

## The stdin secrets contract

When `S1_SECRETS_STDIN=1`, the server itself (`s1-secops-mcp/lib/stdio-transport.js`) reads `NAME=value` lines up to the first empty line before it handles any JSON-RPC. It accepts only `S1_CONSOLE_URL`, `S1_CONSOLE_API_TOKEN`, `S1_HEC_INGEST_URL`, `S1_HEC_TOKEN`, `S1_SCOPE`, `VIRUSTOTAL_API_KEY` (alias `VT_API_KEY`) and `SHODAN_API_KEY`, and ignores any other name with a warning that does not echo it. The empty line is mandatory. A stream that starts with JSON-RPC while the preamble is expected is refused with exit 64. The image sets `S1_KEYCHAIN=off`.

The host launchers write exactly this preamble, so secrets never appear on a command line, in the MCP client config, or in `docker inspect`.

## Publishing rules

The image is published to `sentinelone/secops-mcps`. Tags are semver only. There is deliberately no `:latest`: the tag was deleted and the repository has immutable tags enabled, so a published tag can never be repointed at different bytes. Images are built and published by the maintainers' release pipeline. Pushes made with `PUSH=true docker/build.sh` also attach BuildKit provenance and an SBOM to the image index.

## Verify before you run

- **Pull by digest, not just by tag.** Tags are immutable, but a digest is the strongest pin: `docker pull sentinelone/secops-mcps@sha256:<digest>`. Find the digest with `docker buildx imagetools inspect sentinelone/secops-mcps:1.6.0`.
- **Check where it came from.** The image labels record the source repository and commit: `docker inspect --format '{{json .Config.Labels}}' sentinelone/secops-mcps:1.6.0` (see `org.opencontainers.image.source` and `org.opencontainers.image.revision`).
- **Inspect the provenance and SBOM** attached to the index: `docker buildx imagetools inspect sentinelone/secops-mcps:1.6.0 --format '{{ json .Provenance }}'` and `--format '{{ json .SBOM }}'`. Images published before this was enabled do not carry them.
- **Report a problem privately.** See [SECURITY.md](../../SECURITY.md); do not open a public issue for a vulnerability.

## Pins

Two values are pinned: the image version and the base image digest. Both live in `docker/build.sh`. The release pipeline that publishes the image is maintained outside this repository and keeps its own copy of both, so a change to either is made in both places.

| What | Source | Current pin |
|---|---|---|
| Image version (`IMAGE_VERSION`) | this repo | `1.6.1` |
| Base image (`BASE_IMAGE`) | `gcr.io/distroless/nodejs24-debian13` | pinned by index digest; `build.sh` rejects anything that is not `gcr.io/distroless/nodejs24-*@sha256:...`, and the setup step asserts Node major 24 |
| `s1-secops-mcp` | local `COPY` from this repo | whatever commit you build |

**`s1-secops-mcp` has no pin** because it is not fetched. Its source is in this repo and the Dockerfile `COPY`s it path by path, mirroring the `files` allowlist in `s1-secops-mcp/package.json`. `S1_MCP_VERSION` in `build.sh` is a **label** for the image, and the setup step fails the build if it differs from the `version` in `package.json`.

The package directory can also contain a git-ignored `data/` tree that holds only untracked local exports. The Dockerfile never names it, and `docker/Dockerfile.dockerignore` excludes it from the build context as well. Builds use the repo root as context (`docker/build.sh` and CI both pass `.` with `-f docker/Dockerfile`), so BuildKit reads `docker/Dockerfile.dockerignore`, whose patterns are relative to the repo root. Smoke test T09 asserts `data/` never reaches the image.

`IMAGE_VERSION` is the version tag the image is published under. It is its own counter, independent of the server version inside: bump it whenever anything that changes the image bytes changes, which is the server source, the Dockerfile, the dispatcher, the bundled `CLAUDE.md`, or the base image pin.

<!-- sync:literal: the version below is history, the tag that was republished -->
**Two rules, both enforced in CI.** It must strictly increase, and a published value is never reused. `s1-mcps:1.3.3` shipped npm 1.3.3, then 1.3.7, then 1.3.8, and the image version once moved backwards from 1.3.7 to 1.3.3. Anyone running `--pull=missing` against an unchanged tag string keeps a months-old build indefinitely with nothing to signal it. Deleting a tag from the registry does not make it reusable, because someone already pulled it.

Because the number does not encode what is inside, verify rather than infer:

```bash
docker run --rm sentinelone/secops-mcps:1.6.1 versions
```

`versions.json` records `image_version`, `node`, `base`, the one entry under `servers`, the `builtin_tools`, the `removed_base_packages`, and `shell: false`, `npm: false`.

## Build locally

```bash
# Single-arch (matches your machine), tags sentinelone/secops-mcps:<IMAGE_VERSION>
docker/build.sh

# Full smoke suite, exit code is the failure count. T17 checks the registry
# manifest: it skips on a local reference (no slash) and fails on a Docker Hub
# reference that is not pushed yet. Before the push, test a local tag:
#   docker tag sentinelone/secops-mcps:1.6.1 secops-mcps:1.6.1-local
docker/smoke-test.sh secops-mcps:1.6.1-local --expect-version 1.6.1   # T17 skipped
# After the push, the registry reference runs T17 too:
docker/smoke-test.sh sentinelone/secops-mcps:1.6.1 --expect-version 1.6.1

# Or spot-check by hand:
docker run -i --rm sentinelone/secops-mcps:1.6.1 help      # the server and its built-in tools
docker run -i --rm sentinelone/secops-mcps:1.6.1 versions
docker run --rm sentinelone/secops-mcps:1.6.1 notices      # third-party notices and licenses
```

There is no shell to debug with. Run Node instead:

```bash
docker run --rm --entrypoint /nodejs/bin/node sentinelone/secops-mcps:1.6.1 \
  -e 'console.log(process.version, require("fs").readdirSync("/opt/s1-secops-mcp"))'
```

What the smoke suite asserts, by group:

- T02 to T06: `help` describes the server and its built-in tools; an unknown command exits 64; the image has no shell, no npm, npx or corepack, and no package manager, Python or git.
- T07 to T09: `versions.json` carries the expected `image_version`, one server, no shell or npm, Node 24; no `data/` tree and no removed server ships.
- T10 and T11: runs as non-root, and every shipped file is readable by that user.
- T12 to T14: `tools/list` returns 43 tools with no threat-intel keys and 47 with both keys, and works with `--network none`.
- T15 and T16: CLAUDE.md ships and is served as an MCP resource.
- T18 to T21: the stdin preamble configures the server and never appears in `docker inspect` or on stdout; JSON-RPC first is refused with exit 64; `--transport http` is refused; `S1_KEYCHAIN=off` is baked in.
- T22 and T23: removed server names exit 78 with the update instruction; SIGTERM stops the container promptly.
- T30 to T37: `outputFile` advice and acceptance, the read-only default (a write tool and a `| savelookup` query are refused, `S1_READ_ONLY=false` lifts it), notices and the AGPL LICENSE ship, and an `s1_api_post` path with a fragment is refused in read-only mode. See [`docs/read-only.md`](../../plugins/s1-secops-skills/docs/read-only.md).
- T17: the registry manifest is readable (remote references only).

## Licenses and attestations

- [`THIRD_PARTY_NOTICES.md`](../../plugins/s1-secops-skills/THIRD_PARTY_NOTICES.md) is copied into the image at `/usr/share/doc/secops-mcps/THIRD_PARTY_NOTICES.md`, and the repo `LICENSE` (AGPL-3.0) at `/opt/s1-secops-mcp/LICENSE`. `notices` prints them, including the terms of the VirusTotal and Shodan services the built-in tools call.
- `docker/build.sh` and the CI workflow build with `--provenance=mode=max --sbom=true`, so a pushed image carries SLSA provenance and an SPDX SBOM attestation on its index. Docker Hub lists the attestation manifests as an extra `unknown/unknown` platform; pulls ignore it. Build arguments appear in the provenance, which is public, so never pass a secret as a `--build-arg`.

```bash
docker buildx imagetools inspect sentinelone/secops-mcps:1.6.1 --format '{{ json .SBOM }}'
docker buildx imagetools inspect sentinelone/secops-mcps:1.6.1 --format '{{ json .Provenance }}'
```

## Push manually

```bash
# Multi-arch (linux/amd64 + linux/arm64) and push to Docker Hub
PUSH=true docker/build.sh

# Override registry/tag
PUSH=true REGISTRY=docker.io/your-org TAG=dev docker/build.sh
```

You need `docker login docker.io` first, with a Docker Hub access token that has read/write/delete.

On a slow or unreliable link, push with `skopeo copy --all --retry-times 20` from an OCI archive rather than `docker push`. Docker Hub expires a blob upload session 30 minutes after it starts, so a large layer on a slow connection fails with `broken pipe` just before finishing. Completed blobs are retained, so re-running resumes rather than restarting.

## Move the base image to a newer build

```bash
docker buildx imagetools inspect gcr.io/distroless/nodejs24-debian13:latest   # copy the index digest
# Edit docker/build.sh: BASE_IMAGE default
# Make the same change in the release pipeline's copy (maintained outside this repository)
# Bump IMAGE_VERSION in docker/build.sh
docker/build.sh                                            # verify locally (setup asserts Node 24)
docker/smoke-test.sh secops-mcps:<version>-local --expect-version <version>
git push                                                   # no build, by design
git tag -a s1-mcps-v<version> -m "..." && git push origin s1-mcps-v<version>
```

If a newer base build adds a package to the base, check whether Node loads it before keeping it; `UNUSED_PACKAGES` in `container-entry.mjs` lists the ones removed and `__image_verify` proves Node still works without them.

**Only a release tag builds an image.** A push to `main` does not, however much
it changes: pushing and releasing are separate acts. That is a deliberate cost
control, because the arm64 half of a multi-arch build is emulated on the amd64
runner and a slow build burns a private repo's metered minutes. Use
`[skip ci]` on a commit if you want to skip even the PR check.

There is no `s1-secops-mcp` pin to bump: edit the source in `s1-secops-mcp/`, bump the `version` in its `package.json`, and set `S1_MCP_VERSION` to match (the build checks the two agree).

<!-- Anchors kept for links in older release notes: the forks they described are gone. -->
<a id="refresh-the-shodan-fork-against-upstream"></a>
<a id="refresh-the-virustotal-fork-against-upstream"></a>

## Why one server?

One server means one client entry, one container per client session, and one codebase to review, patch and scan. The threat-intel tools need only an HTTPS call with the user's key, which Node's built-in `fetch` covers with no dependencies, so carrying third-party MCP servers and their dependency trees in the image bought little and cost a large attack surface (1.5.7 was 868 MB with 397 packages). Users who want a provider's full MCP feature set install that provider's own server, at their choice and under the provider's support ([`docs/connect-optional-tools.md`](../../plugins/s1-secops-skills/docs/connect-optional-tools.md)).
