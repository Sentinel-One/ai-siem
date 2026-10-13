#!/usr/bin/env bash
#
# Build (and optionally push) the SentinelOne Claude Skills MCP Stack image.
#
# Usage:
#   docker/build.sh                   # local single-arch build, tag secops-mcps:<version>
#   PUSH=true docker/build.sh         # multi-arch build + push to Docker Hub
#   TAG=dev docker/build.sh           # override tag
#   VT_MCP_REF=<sha> docker/build.sh  # override a pin (also SHODAN_MCP_REF, NODE_IMAGE)
#
# All pins live in the "Pinned MCP sources" block below. Bump them there, and
# in any release pipeline that keeps its own copy of the pins (such a pipeline
# is maintained outside this repository), then re-run.
# Every source is git; the image contains no npm.
#
set -euo pipefail

# ── Pinned MCP sources ───────────────────────────────────────────────────────
#
# Every MCP now comes from a pinned git source. Nothing here resolves a package
# from the npm registry, and the image has no npm binary to do so with.
#
# s1-secops-mcp is COPY'd from this working tree, so its "pin" is whatever
# commit you are building. S1_MCP_VERSION below is therefore a LABEL, not an
# install target: keep it equal to the version in s1-secops-mcp/package.json so
# the image label does not lie about what it carries.
S1_MCP_VERSION="${S1_MCP_VERSION:-1.5.5}"

# virustotal-mcp: our fork of w0h1v/mcp-virustotal. The fork exists
# because upstream publishes only to npm: it has a `prepublishOnly` build and
# no `prepare`, so a git install of upstream fetches TypeScript source with no
# build/ and yields a binary that cannot start. The fork commits its compiled
# build/ and its production node_modules/, which is what lets this image skip
# npm entirely. See scripts/vendor-vt-fork.sh.
#
# Must be a FULL 40-character commit SHA: the Dockerfile fetches the object by
# id, and a branch name would silently un-pin the build.
VT_MCP_REPO="${VT_MCP_REPO:-https://github.com/pmoses-s1/mcp-virustotal.git}"
VT_MCP_REF="${VT_MCP_REF:-97ca2b8fa696a798d8689aff13d9cb57cbd9067e}"

# purple-mcp: our fork of Sentinel-One/purple-mcp at the v0.7.0 release commit,
# plus one change. Upstream requires pandas, but imports it in exactly one place
# for SDLTableResultData.to_df(), which no MCP tool calls: the SDL tools render
# results straight from `values`. That made every install carry pandas and numpy
# (~141 MB) for a code path the server never executes. The fork makes pandas an
# optional `dataframe` extra, changing no behaviour. Upstream PR pending; repin
# to Sentinel-One once it merges.
PURPLE_MCP_REPO="${PURPLE_MCP_REPO:-https://github.com/pmoses-s1/purple-mcp.git}"
PURPLE_MCP_REF="${PURPLE_MCP_REF:-1390b8c00a8af847605739248b0b4514713298c4}"

# shodan-mcp (optional server): our fork of w0h1v/mcp-shodan, vendored exactly
# like the VirusTotal fork (same npm-only upstream, same missing `prepare`).
# The fork also carries four small hardening patches, listed in its
# FORK_NOTES.md: page cap, no redirects, API-key redaction, no dotenv.
# See scripts/vendor-node-fork.sh. Full 40-character SHA, same rule as VT.
SHODAN_MCP_REPO="${SHODAN_MCP_REPO:-https://github.com/pmoses-s1/mcp-shodan.git}"
SHODAN_MCP_REF="${SHODAN_MCP_REF:-1b34db42dcefef781ffd0aad273e065700dcddc8}"

# ── Base image ───────────────────────────────────────────────────────────────
# Node 24 LTS, pinned by digest so a rebuild cannot silently pick up different
# bytes. The Dockerfile asserts the major version is 24. To move to a newer
# Node 24 patch: `docker buildx imagetools inspect node:24-trixie-slim`, copy
# the index digest here and into any release pipeline that keeps its own copy.
# Resolved 2026-10-13: Node v24.21.0.
NODE_IMAGE="${NODE_IMAGE:-node:24-trixie-slim@sha256:173f125896c3b47ddf056734c7ea789d04595a6a08769a8f78e0df642781fb66}"

# Fail before a 4-minute build rather than after it.
for _pin in VT_MCP_REF SHODAN_MCP_REF; do
  if ! echo "${!_pin}" | grep -qE '^[0-9a-f]{40}$'; then
    echo "error: ${_pin} must be a full 40-char commit SHA, got '${!_pin}'." >&2
    echo "Vendor the fork with scripts/vendor-node-fork.sh, push it, then set" >&2
    echo "${_pin} here and in any release pipeline that keeps its own copy." >&2
    exit 1
  fi
done
case "${NODE_IMAGE}" in
  node:24-*@sha256:*) ;;
  *) echo "error: NODE_IMAGE must be a node:24 tag pinned by digest, got '${NODE_IMAGE}'." >&2; exit 1 ;;
esac

# ── Image version ────────────────────────────────────────────────────────────
# The version of THIS image. Its own counter, independent of the MCP pins above:
# bump it when anything that changes the image bytes changes, which is the
# Dockerfile, the dispatcher, the bundled CLAUDE.md, or any pin above.
#
# TWO RULES, both enforced in CI: it must strictly increase, and a published
# value is never reused. Rationale and the incident behind it: docker/README.md.
#
# Because the number does not encode what is inside, verify rather than infer:
#   docker run --rm <image> versions
# (That replaces the old `--entrypoint npm <image> ls -g --depth=0`. There is
# no npm in the image any more, so that command now fails with "not found".)
IMAGE_VERSION="${IMAGE_VERSION:-1.5.5}"

# ── Image identity ───────────────────────────────────────────────────────────
REGISTRY="${REGISTRY:-docker.io/sentinelone}"
IMAGE_NAME="${IMAGE_NAME:-secops-mcps}"
TAG="${TAG:-${IMAGE_VERSION}}"

# ── Build options ────────────────────────────────────────────────────────────
PLATFORMS="${PLATFORMS:-linux/amd64,linux/arm64}"
PUSH="${PUSH:-false}"

# ── Setup ────────────────────────────────────────────────────────────────────
REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
VCS_REF="$(git rev-parse --short HEAD)"

echo "Image:         ${REGISTRY}/${IMAGE_NAME}:${TAG}"
echo "Image version: ${IMAGE_VERSION}"
echo "Platforms:     ${PLATFORMS}"
echo "MCP sources (all git, no npm registry):"
echo "  s1-secops-mcp:   local source @ ${VCS_REF} (labelled ${S1_MCP_VERSION})"
echo "  virustotal-mcp:  ${VT_MCP_REPO}@${VT_MCP_REF}"
echo "  purple-mcp:      ${PURPLE_MCP_REPO}@${PURPLE_MCP_REF}"
echo "  shodan-mcp:      ${SHODAN_MCP_REPO}@${SHODAN_MCP_REF}"
echo "Base image:    ${NODE_IMAGE}"
echo "Build date: ${BUILD_DATE}"
echo "VCS ref:    ${VCS_REF}"
echo

# Ensure the buildx builder exists (idempotent).
#
# `--driver-opt network=host` is required, not cosmetic. The docker-container
# driver runs BuildKit in its own network namespace with its own resolver, and
# on a machine behind a split-horizon or proxied DNS (a corporate VPN, for
# instance) that resolver cannot see the names the host can. The failure is
# well disguised: the build gets as far as `apt-get update`, then reports
# "Temporary failure resolving 'deb.debian.org'" and "Unable to locate package
# python3", which reads as a broken base image or a bad package list rather
# than as DNS. Sharing the host network namespace makes the builder resolve
# exactly what the host resolves.
#
# This does not affect the default `docker` driver used for plain `docker
# build`, which is why single-arch builds can succeed on a machine where this
# multi-arch path fails.
BUILDER_NAME="s1-mcps-builder"
if ! docker buildx inspect "$BUILDER_NAME" >/dev/null 2>&1; then
  docker buildx create --name "$BUILDER_NAME" \
    --driver docker-container --driver-opt network=host --use >/dev/null
else
  docker buildx use "$BUILDER_NAME" >/dev/null
fi

ARGS=(
  --build-arg "IMAGE_VERSION=${IMAGE_VERSION}"
  --build-arg "S1_MCP_VERSION=${S1_MCP_VERSION}"
  --build-arg "VT_MCP_REPO=${VT_MCP_REPO}"
  --build-arg "VT_MCP_REF=${VT_MCP_REF}"
  --build-arg "PURPLE_MCP_REPO=${PURPLE_MCP_REPO}"
  --build-arg "PURPLE_MCP_REF=${PURPLE_MCP_REF}"
  --build-arg "SHODAN_MCP_REPO=${SHODAN_MCP_REPO}"
  --build-arg "SHODAN_MCP_REF=${SHODAN_MCP_REF}"
  --build-arg "NODE_IMAGE=${NODE_IMAGE}"
  --build-arg "BUILD_DATE=${BUILD_DATE}"
  --build-arg "VCS_REF=${VCS_REF}"
  --tag "${REGISTRY}/${IMAGE_NAME}:${TAG}"
  --file docker/Dockerfile
  # Build attestations (1.5.5): SLSA provenance and an SPDX SBOM, attached to
  # the pushed index as one attestation manifest per platform (Docker Hub lists
  # it as "unknown/unknown"; pulls ignore it). mode=max records every
  # --build-arg above in the provenance, which is public: never pass a secret
  # as a build-arg, use --secret instead.
  --provenance=mode=max
  --sbom=true
)

if [ "${PUSH}" = "true" ]; then
  echo "Building multi-arch (${PLATFORMS}) and pushing..."
  # Attach build provenance and an SBOM to the published index so consumers can
  # verify what source and builder produced the image. Not supported with --load,
  # so this applies to pushes only. The SBOM is generated by BuildKit's default
  # scanner image; pin it with --sbom=generator=<image>@sha256:... if you need
  # that to be fixed as well.
  docker buildx build "${ARGS[@]}" --platform "${PLATFORMS}" \
    --provenance=mode=max --sbom=true --push .
else
  echo "Building local single-arch image (set PUSH=true for multi-arch + push)..."
  docker buildx build "${ARGS[@]}" --load .
  echo
  echo "Smoke test:"
  echo "  docker run -i --rm ${REGISTRY}/${IMAGE_NAME}:${TAG} help"
  echo "  docker run -i --rm ${REGISTRY}/${IMAGE_NAME}:${TAG} versions"
fi
