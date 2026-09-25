#!/usr/bin/env bash
#
# Build (and optionally push) the SentinelOne Claude Skills MCP Stack image.
#
# Usage:
#   docker/build.sh                   # local single-arch build, tag secops-skills:<version>
#   PUSH=true docker/build.sh         # multi-arch build + push to Docker Hub
#   TAG=dev docker/build.sh           # override tag
#   VT_MCP_REF=<sha> docker/build.sh  # override a pin
#
# All pins live in the "Pinned MCP sources" block below. Bump them there and
# in the GHA workflow at .github/workflows/docker-publish.yml, then re-run.
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
S1_MCP_VERSION="${S1_MCP_VERSION:-1.3.9}"

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
VT_MCP_REF="${VT_MCP_REF:-b3d847443f08c0a3fb1d5f34dc29770f6cec4d25}"

# purple-mcp: our fork of Sentinel-One/purple-mcp at the v0.7.0 release commit,
# plus one change. Upstream requires pandas, but imports it in exactly one place
# for SDLTableResultData.to_df(), which no MCP tool calls: the SDL tools render
# results straight from `values`. That made every install carry pandas and numpy
# (~141 MB) for a code path the server never executes. The fork makes pandas an
# optional `dataframe` extra, changing no behaviour. Upstream PR pending; repin
# to Sentinel-One once it merges.
PURPLE_MCP_REPO="${PURPLE_MCP_REPO:-https://github.com/pmoses-s1/purple-mcp.git}"
PURPLE_MCP_REF="${PURPLE_MCP_REF:-b8a200d3ad3e52df9c349f427faa344cdc3a8470}"

# Fail before a 4-minute build rather than after it.
if ! echo "${VT_MCP_REF}" | grep -qE '^[0-9a-f]{40}$'; then
  echo "error: VT_MCP_REF must be a full 40-char commit SHA, got '${VT_MCP_REF}'." >&2
  echo "Fork w0h1v/mcp-virustotal, run scripts/vendor-vt-fork.sh against it," >&2
  echo "push, then set VT_MCP_REF here and in .github/workflows/docker-publish.yml." >&2
  exit 1
fi

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
IMAGE_VERSION="${IMAGE_VERSION:-1.4.8}"

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
  --build-arg "BUILD_DATE=${BUILD_DATE}"
  --build-arg "VCS_REF=${VCS_REF}"
  --tag "${REGISTRY}/${IMAGE_NAME}:${TAG}"
  --file docker/Dockerfile
)

if [ "${PUSH}" = "true" ]; then
  echo "Building multi-arch (${PLATFORMS}) and pushing..."
  docker buildx build "${ARGS[@]}" --platform "${PLATFORMS}" --push .
else
  echo "Building local single-arch image (set PUSH=true for multi-arch + push)..."
  docker buildx build "${ARGS[@]}" --load .
  echo
  echo "Smoke test:"
  echo "  docker run -i --rm ${IMAGE_NAME}:${TAG} help"
  echo "  docker run -i --rm ${IMAGE_NAME}:${TAG} versions"
fi
