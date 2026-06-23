#!/usr/bin/env bash
#
# Build (and optionally push) the SentinelOne Claude Skills MCP Stack image.
#
# Usage:
#   docker/build.sh                   # local single-arch build, tag s1-mcps:<version>
#   PUSH=true docker/build.sh         # multi-arch build + push to ghcr.io
#   TAG=dev docker/build.sh           # override tag
#   S1_MCP_VERSION=1.2.2 docker/build.sh   # override a pin
#
# All version pins live in the "Pinned versions" block below. Bump them
# there and the GHA workflow at .github/workflows/docker-publish.yml,
# then re-run.
#
set -euo pipefail

# ── Image version ────────────────────────────────────────────────────────────
# The version of THIS image. Independent of the underlying MCP versions
# below, bump this when the image content (Dockerfile, dispatcher, bundled
# CLAUDE.md) changes, even if all three MCP pins stay the same.
IMAGE_VERSION="${IMAGE_VERSION:-1.2.2}"

# ── Pinned MCP versions ──────────────────────────────────────────────────────
S1_MCP_VERSION="${S1_MCP_VERSION:-1.2.2}"
VT_MCP_PACKAGE="${VT_MCP_PACKAGE:-@burtthecoder/mcp-virustotal}"
VT_MCP_VERSION="${VT_MCP_VERSION:-1.0.21}"
PURPLE_MCP_REF="${PURPLE_MCP_REF:-1582c0945101d0da2a158e66d8c329f66f251f27}"

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
echo "  sentinelone-mcp:   ${S1_MCP_VERSION}"
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
