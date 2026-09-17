#!/usr/bin/env bash
#
# Build (and optionally push) the SentinelOne Claude Skills MCP Stack image.
#
# Usage:
#   docker/build.sh                   # local single-arch build, tag s1-mcps:<version>
#   PUSH=true docker/build.sh         # multi-arch build + push to ghcr.io
#   TAG=dev docker/build.sh           # override tag
#   S1_MCP_VERSION=1.2.3 docker/build.sh   # override a pin
#
# All version pins live in the "Pinned versions" block below. Bump them
# there and the GHA workflow at .github/workflows/docker-publish.yml,
# then re-run.
#
set -euo pipefail

# ── Pinned MCP versions ──────────────────────────────────────────────────────
S1_MCP_VERSION="${S1_MCP_VERSION:-1.3.9}"
VT_MCP_PACKAGE="${VT_MCP_PACKAGE:-@burtthecoder/mcp-virustotal}"
VT_MCP_VERSION="${VT_MCP_VERSION:-1.0.21}"
# purple-mcp v0.7.0 (2026-06-26). Pinned to the release commit, not a floating
# branch, per upstream's security guidance. Bump this to the newest release tag's
# commit when refreshing; keep it in sync with the GHA workflow env block.
PURPLE_MCP_REF="${PURPLE_MCP_REF:-07d4992089b10affff6163f296b1f6cb5734539f}"

# ── Image version ────────────────────────────────────────────────────────────
# The version of THIS image. Its own counter, independent of the MCP pins above:
# bump it when anything that changes the image bytes changes, which is the
# Dockerfile, the dispatcher, the bundled CLAUDE.md, or any pin above.
#
# TWO RULES, both now enforced in CI:
#   1. It must STRICTLY INCREASE. It once moved backwards, 1.3.7 to 1.3.3.
#   2. A published value is never reused. s1-mcps:1.3.3 shipped npm 1.3.3, then
#      1.3.7, then 1.3.8. With `--pull=missing` against an unchanged tag string
#      there is nothing for Docker to notice, so whoever pulled it first keeps
#      those bytes indefinitely while the tag still reads as current. Deleting a
#      tag from the registry does not make it reusable; someone already has it.
#
# Because the number does not encode what is inside, verify rather than infer:
#   docker run --rm --entrypoint npm <image> ls -g --depth=0
IMAGE_VERSION="${IMAGE_VERSION:-1.3.5}"

# ── Image identity ───────────────────────────────────────────────────────────
REGISTRY="${REGISTRY:-ghcr.io/pmoses-s1}"
IMAGE_NAME="${IMAGE_NAME:-s1-mcps}"
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
echo "MCP pins:"
echo "  s1-secops-mcp:   ${S1_MCP_VERSION}"
echo "  ${VT_MCP_PACKAGE}: ${VT_MCP_VERSION}"
echo "  purple-mcp ref:    ${PURPLE_MCP_REF}"
echo "Build date: ${BUILD_DATE}"
echo "VCS ref:    ${VCS_REF}"
echo

# Ensure the buildx builder exists (idempotent)
BUILDER_NAME="s1-mcps-builder"
if ! docker buildx inspect "$BUILDER_NAME" >/dev/null 2>&1; then
  docker buildx create --name "$BUILDER_NAME" --use >/dev/null
else
  docker buildx use "$BUILDER_NAME" >/dev/null
fi

ARGS=(
  --build-arg "S1_MCP_VERSION=${S1_MCP_VERSION}"
  --build-arg "VT_MCP_PACKAGE=${VT_MCP_PACKAGE}"
  --build-arg "VT_MCP_VERSION=${VT_MCP_VERSION}"
  --build-arg "PURPLE_MCP_REF=${PURPLE_MCP_REF}"
  --build-arg "BUILD_DATE=${BUILD_DATE}"
  --build-arg "VCS_REF=${VCS_REF}"
  --tag "${REGISTRY}/${IMAGE_NAME}:${TAG}"
  --tag "${REGISTRY}/${IMAGE_NAME}:latest"
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
fi
