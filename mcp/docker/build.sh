#!/usr/bin/env bash
#
# Build (and optionally push) the SentinelOne SecOps MCP image.
#
# Usage:
#   docker/build.sh                   # local single-arch build, tag secops-mcps:<version>
#   PUSH=true docker/build.sh         # multi-arch build + push to Docker Hub
#   TAG=dev docker/build.sh           # override tag
#   BASE_IMAGE=<ref@digest> docker/build.sh  # override the base image pin
#
# From 1.6.0 the image carries one server, s1-secops-mcp, COPYed from this working
# tree, on a distroless Node 24 base. Purple AI, VirusTotal and Shodan are built-in
# tools of that server; there are no third-party MCP sources to pin. The image has
# no shell, no package manager and no npm.
#
set -euo pipefail

# s1-secops-mcp is COPY'd from this working tree, so its "pin" is whatever
# commit you are building. S1_MCP_VERSION below is therefore a LABEL, not an
# install target: keep it equal to the version in s1-secops-mcp/package.json so
# the image label does not lie about what it carries.
S1_MCP_VERSION="${S1_MCP_VERSION:-1.6.3}"

# ── Base image ───────────────────────────────────────────────────────────────
# Distroless Node 24 (Debian 13), pinned by index digest so a rebuild cannot
# silently pick up different bytes. Chosen in 1.6.0 for the smallest attack
# surface. With the four base packages Node never loads removed at build time
# (see the Dockerfile), the 1.6.0 image scanned at 12 packages, 0 critical,
# 0 high, 0 medium and 7 low (disputed glibc entries with no fix) in Docker Scout
# on 2026-11-05, against 397 packages and 4 high / 3 medium / 23 low for the
# 1.5.7 image on node:24-trixie-slim. The image's setup step asserts Node 24.
# To move to a newer build: `docker buildx imagetools inspect
# gcr.io/distroless/nodejs24-debian13:latest`, copy the index digest here and
# into any release pipeline that keeps its own copy.
# Resolved 2026-11-05: Node v24.22.2.
BASE_IMAGE="${BASE_IMAGE:-gcr.io/distroless/nodejs24-debian13@sha256:03980f6fd2a3245fa06e371c36fd33528ebbc676a1d0f84e3e21d95cd291b807}"

case "${BASE_IMAGE}" in
  gcr.io/distroless/nodejs24-*@sha256:*) ;;
  *) echo "error: BASE_IMAGE must be gcr.io/distroless/nodejs24-* pinned by digest, got '${BASE_IMAGE}'." >&2; exit 1 ;;
esac

# ── Image version ────────────────────────────────────────────────────────────
# The version of THIS image. Its own counter: bump it when anything that changes
# the image bytes changes, which is the server source, the Dockerfile, the
# dispatcher, the bundled CLAUDE.md, or the base image pin.
#
# TWO RULES, both enforced in CI: it must strictly increase, and a published
# value is never reused. Rationale and the incident behind it: docker/README.md.
#
# Because the number does not encode what is inside, verify rather than infer:
#   docker run --rm <image> versions
# (That replaces the old `--entrypoint npm <image> ls -g --depth=0`. There is
# no npm in the image any more, so that command now fails with "not found".)
IMAGE_VERSION="${IMAGE_VERSION:-1.6.3}"

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
echo "Server:        s1-secops-mcp, local source @ ${VCS_REF} (labelled ${S1_MCP_VERSION}); no npm registry"
echo "Base image:    ${BASE_IMAGE}"
echo "Build date: ${BUILD_DATE}"
echo "VCS ref:    ${VCS_REF}"
echo

# Ensure the buildx builder exists (idempotent).
#
# `--driver-opt network=host` is required, not cosmetic. The docker-container
# driver runs BuildKit in its own network namespace with its own resolver, and
# on a machine behind a split-horizon or proxied DNS (a corporate VPN, for
# instance) that resolver cannot see the names the host can. The failure is
# well disguised: pulling the base image or its metadata fails with a resolver
# error that reads as a broken image reference or registry outage rather
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
  --build-arg "BASE_IMAGE=${BASE_IMAGE}"
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
