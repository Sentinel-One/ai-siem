# Docker image: SentinelOne Claude Skills MCP Stack

Single image bundling all three MCPs (`s1-secops-mcp`, `purple-mcp`, `virustotal-mcp`) so end users only need Docker installed. No Node, no Python, no `uv`, no `npm install`. This is the documented install path; see [`docs/installation.md`](../../plugins/s1-secops-skills/docs/installation.md).

End-user reference: [`docs/docker.md`](../../plugins/s1-secops-skills/docs/docker.md). This file is for image maintainers.

## No npm

Every server in this image comes from a pinned git source. Nothing in the build resolves a package from the npm registry, and the `npm` and `npx` binaries are deleted from the final image. That last part is the load-bearing one: it turns "we do not use the npm registry" from a convention someone has to remember into a property of the image. A future `RUN npm install ...` fails at build time rather than quietly reintroducing a registry dependency.

Node itself is untouched. It is what runs the two JavaScript servers.

One registry does remain: **purple-mcp's Python dependencies still resolve from PyPI** during the fetch stage. The server itself is pinned to a git commit, but its dependency tree is not vendored. Removing that too means vendoring wheels the same way the VirusTotal fork vendors `node_modules`; it has not been done.

## Layout

```bash
docker/
├── Dockerfile                 # 2-stage, multi-arch, all 3 MCPs from pinned git sources
├── entrypoint.sh              # dispatcher: argv[1] selects which MCP to run; reads secrets from stdin when S1_SECRETS_STDIN=1
├── s1-secops-mcp-launch.sh    # host launcher (macOS, Linux): keychain -> container stdin
├── s1-secops-mcp-launch.ps1   # host launcher (Windows): Credential Manager -> container stdin
├── build.sh                   # local + push build wrapper
├── smoke-test.sh              # image smoke test (tool count, stdin secrets, docker inspect, stdio only)
├── Dockerfile.dockerignore    # build-context exclusions; BuildKit reads <Dockerfile>.dockerignore, patterns are repo-root relative
└── README.md                  # this file
```

The stdin secret contract: when `S1_SECRETS_STDIN=1`, the entrypoint reads `NAME=value` lines up to the first empty line before it starts the server, exports only the known names (`S1_CONSOLE_URL`, `S1_CONSOLE_API_TOKEN`, `S1_HEC_INGEST_URL`, `S1_HEC_TOKEN`, `S1_SCOPE`, `VIRUSTOTAL_API_KEY`, `VT_API_KEY`, `PURPLEMCP_CONSOLE_BASE_URL`, `PURPLEMCP_CONSOLE_TOKEN`, `PURPLEMCP_VT_API_KEY`) and ignores any other name with a warning that does not echo it. The empty line is mandatory: without it the entrypoint keeps consuming the JSON-RPC stream. The image sets `S1_KEYCHAIN=off`.

The Dockerfile is two stages. The **fetch** stage holds everything needing git or network; the **runtime** stage copies the results, so neither `git` nor any clone metadata ships in the published image.

The image is published to `sentinelone/secops-mcps`. Tags are semver only. There is deliberately no `:latest`: the tag was deleted and the repository has immutable tags enabled, so a published tag can never be repointed at different bytes. Images are built and published by the maintainers' release pipeline.

## Pinned sources

All three MCPs are pinned at build time. The pins live in two places that must stay in sync:

1. `docker/build.sh` for local builds and manual pushes
2. `.github/workflows/docker-publish.yml` env block for CI builds

When bumping a pin, edit both. They are checked via `grep` in CI; a mismatch fails the build.

| What | Source | Current pin |
|---|---|---|
| Image version (`IMAGE_VERSION`) | this repo | `1.5.2` |
| `s1-secops-mcp` | local `COPY` from this repo | whatever commit you build |
| `virustotal-mcp` | git, maintained fork (repo in `build.sh`) | `97ca2b8` (vendored fork of `w0h1v/mcp-virustotal` v1.0.28; proxy-addr 2.0.8, MCP SDK 1.32.1) |
| `purple-mcp` | git, maintained fork (repo in `build.sh`) | `1390b8c` (fork of `Sentinel-One/purple-mcp` v0.7.0, pandas made optional) |

**`s1-secops-mcp` has no pin** because it is not fetched. Its source is in this repo and the Dockerfile `COPY`s it, so the image always carries the commit being built. This is possible only because the package declares zero `dependencies` and zero `devDependencies`: there is nothing to resolve, so the source *is* the install. `S1_MCP_VERSION` in `build.sh` is now purely a **label** for the image, and CI asserts it equals the `version` in `s1-secops-mcp/package.json` so it cannot drift into a lie.

Two consequences of that switch, both handled in the workflow: a commit under `s1-secops-mcp/` now changes the image (so it is in the build-trigger path list and the `IMAGE_VERSION` bump guard), and the Dockerfile `COPY`s path by path rather than copying the directory. The directory can also contain a git-ignored `data/` tree that holds only untracked local exports and is referenced by no code. The Dockerfile never names it, and `docker/Dockerfile.dockerignore` excludes it from the build context as well. Builds use the repo root as context (`docker/build.sh` and CI both pass `.` with `-f docker/Dockerfile`), so Docker reads `<context>/.dockerignore` or, with BuildKit, `docker/Dockerfile.dockerignore`; this repo uses the second, and its patterns are relative to the repo root. Smoke test T09 asserts `data/` never reaches the image.

**`virustotal-mcp` needs a vendored fork.** Upstream `w0h1v/mcp-virustotal` publishes only to npm: `main` is `build/index.js`, `build/` is not committed, and the build runs under `prepublishOnly` rather than `prepare`. npm runs `prepare` on git installs, so installing upstream from git fetches TypeScript, compiles nothing, and installs a bin pointing at a missing file. The fork fixes this by committing its compiled `build/` and its production `node_modules/`, which is what lets this image install it with `git clone` alone. The maintainers produce that state with a vendoring script that prints the SHA to pin. The Dockerfile asserts both `build/index.js` and `node_modules/` are present and fails the build with a pointer to that script if not, rather than shipping a container that dies on its first JSON-RPC call.

`VT_MCP_REF` must be a full 40-character SHA. A branch name would look fine and silently un-pin every subsequent build, so `build.sh` and CI both reject anything else.

`purple-mcp` is pinned to a commit on our fork rather than a floating `main`, per upstream's security guidance. The fork sits on the `v0.7.0` release commit plus one change: upstream imports pandas at module scope for `SDLTableResultData.to_df()`, a method no MCP tool calls, so every install carried pandas and numpy (~141 MB) for a code path the server never runs. The fork makes it an optional `dataframe` extra, changing no behaviour. An upstream PR is open; repin to `Sentinel-One/purple-mcp` once it merges. When a newer release ships, repin here, in `docker/build.sh`, and in the workflow env block.

`IMAGE_VERSION` is the version tag the image is published under. It is its own counter, independent of the MCP versions inside: bump it whenever anything that changes the image bytes changes, which is the Dockerfile, the dispatcher, the bundled `CLAUDE.md`, the `s1-secops-mcp` source now that it is `COPY`'d, or any pin above.

<!-- sync:literal: the version below is history, the tag that was republished -->
**Two rules, both enforced in CI.** It must strictly increase, and a published value is never reused. `s1-mcps:1.3.3` shipped npm 1.3.3, then 1.3.7, then 1.3.8, and the image version once moved backwards from 1.3.7 to 1.3.3. Anyone running `--pull=missing` against an unchanged tag string keeps a months-old build indefinitely with nothing to signal it. Deleting a tag from the registry does not make it reusable, because someone already pulled it.

Because the number does not encode what is inside, verify rather than infer:

```bash
docker run --rm sentinelone/secops-mcps:1.5.2 versions
```

## Build locally

```bash
# Single-arch (matches your machine), tags sentinelone/secops-mcps:<IMAGE_VERSION>
docker/build.sh

# Full smoke suite: 25 assertions (T17 skips on a local image reference), exit code is the failure count.
docker/smoke-test.sh sentinelone/secops-mcps:1.5.2 --expect-version 1.5.2

# Or spot-check by hand:
docker run -i --rm sentinelone/secops-mcps:1.5.2 help
docker run -i --rm sentinelone/secops-mcps:1.5.2 versions

# There should be no npm in here. This must print "absent".
docker run --rm --entrypoint sh sentinelone/secops-mcps:1.5.2 -c 'command -v npm || echo absent'
```

The dispatcher accepts `s1-secops-mcp`, `purple-mcp`, `virustotal-mcp`, `versions`, or `help`.

## Push manually

```bash
# Multi-arch (linux/amd64 + linux/arm64) and push to Docker Hub
PUSH=true docker/build.sh

# Override registry/tag
PUSH=true REGISTRY=docker.io/your-org TAG=dev docker/build.sh
```

You need `docker login docker.io` first, with a Docker Hub access token that has read/write/delete.

On a slow or unreliable link, push with `skopeo copy --all --retry-times 20` from an OCI archive rather than `docker push`. Docker Hub expires a blob upload session 30 minutes after it starts, so a large layer on a slow connection fails with `broken pipe` just before finishing. Completed blobs are retained, so re-running resumes rather than restarting.

## Bump a pin

```bash
# Edit docker/build.sh: change VT_MCP_REF or PURPLE_MCP_REF
# Edit .github/workflows/docker-publish.yml: same change in env block
# Bump IMAGE_VERSION in docker/build.sh
# Then:
docker/build.sh                                            # verify locally
git push                                                   # no build, by design
git tag -a s1-mcps-v1.5.2 -m "..." && git push origin s1-mcps-v1.5.2
```

**Only a release tag builds an image.** A push to `main` does not, however much
it changes: pushing and releasing are separate acts. That is a deliberate cost
control, because the arm64 half of a multi-arch build is emulated on the amd64
runner and a slow build burns a private repo's metered minutes. Use
`[skip ci]` on a commit if you want to skip even the PR check.

There is no `s1-secops-mcp` pin to bump: edit the source in `s1-secops-mcp/`, bump the `version` in its `package.json`, and set `S1_MCP_VERSION` to match (CI checks the two agree).

## Refresh the VirusTotal fork against upstream

```bash
git clone https://github.com/<your-org>/mcp-virustotal.git ~/src/mcp-virustotal
cd ~/src/mcp-virustotal
git remote add upstream https://github.com/w0h1v/mcp-virustotal.git
git fetch upstream && git merge upstream/main     # resolve any conflict in build/ by rebuilding

cd -                                              # back to s1-secops-skills
scripts/vendor-vt-fork.sh ~/src/mcp-virustotal    # rebuild, prune, commit
```

The script prints the commit SHA to put in `docker/build.sh` and the workflow env block. Merge conflicts will land in `build/` and `node_modules/` because those are committed artefacts; take either side and let the script's rebuild produce the correct content.

Upstream is `w0h1v/mcp-virustotal`. It is widely referenced as `BurtTheCoder/mcp-virustotal`, which is the same repository under a former account name; GitHub redirects it. Use the `w0h1v` form so the remote does not depend on a redirect.

The vendored tree was checked for portability before pinning: zero native `.node` addons and zero packages declaring `os`/`cpu` constraints, so one vendoring run on any platform is valid for both published architectures. Re-check that after a dependency bump, since a new transitive dep with a native component would silently make the fork host-specific.

## Why one image with three entrypoints?

Three entries in `claude_desktop_config.json` (one per MCP) all reference the same image and tag, so a single `docker pull` covers all three MCPs and the versions stay in lockstep. A "router" MCP that exposes all bundled tools through one process was rejected because the MCP spec has no tool-namespacing convention; tool name collisions across `s1-secops-mcp` and `purple-mcp` would force ad-hoc renaming.

## Why install pip-style for purple-mcp instead of via uv?

`uv tool install` puts the binary at a path that depends on internal layout decisions and varies by uv version. A simple `python3 -m venv /opt/purple-mcp && pip install` gives a deterministic binary location at `/opt/purple-mcp/bin/purple-mcp` and the venv is fully self-contained. End users who run `purple-mcp` outside the container start it with `s1-secops-mcp exec -- purple-mcp --mode stdio`, which hands it the keychain values; see [`docs/credentials.md`](../../plugins/s1-secops-skills/docs/credentials.md#storing-values-setup-status-forget).

The venv is created in the fetch stage at the same absolute path it occupies at runtime, then copied wholesale. Same path and same base image means the paths baked into the venv stay valid, and the runtime stage needs only `python3` (no `pip`, no `python3-venv`).

## Why vendor node_modules rather than build from a lockfile?

A multi-stage build running `npm ci` from a committed lockfile would also give a reproducible tree, and would keep the fork small. It would not remove the npm registry from the build path: `npm ci` still downloads every tarball. Committing the resolved tree moves that fetch to a maintainer's machine, once, at vendoring time, which is what makes the image buildable without registry access at all.

The costs are real and worth stating: the fork is tens of megabytes larger, dependency updates are a manual re-run of the vendoring script rather than a Dependabot bump, and `node_modules` in version control is a thing most reviewers will flinch at. Committed artefacts also guarantee merge conflicts when syncing with upstream. If registry-free builds stop being a requirement, `npm ci --omit=dev` in the fetch stage is the smaller design.
