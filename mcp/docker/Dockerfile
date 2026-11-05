# syntax=docker/dockerfile:1.7
#
# SentinelOne SecOps MCP
# ─────────────────────────────────────────────────────────────────────────────
# One image, one MCP server: s1-secops-mcp, on a distroless Node 24 base.
#
# 1.6.0 removed everything that was not our own code:
#   - No third-party MCP server. Purple AI, VirusTotal and Shodan are built-in
#     tools of s1-secops-mcp (Node's fetch, the operator's own keys). Other MCP
#     servers are installed by the user from their official sources
#     (docs/connect-optional-tools.md).
#   - No shell, no package manager, no npm, no init, no Python. The base is
#     gcr.io/distroless/nodejs24-debian13 (Node, glibc, libstdc++, CA certificates,
#     tzdata), minus the system OpenSSL, zlib, zstd and libgomp that Node never
#     loads (it compiles in its own OpenSSL and zlib).
#     The former sh entrypoint is now docker/container-entry.mjs, and the stdin
#     secrets preamble is read by the server itself (lib/stdio-transport.js).
#   - s1-secops-mcp has no runtime dependencies (its one optional dependency, the
#     Windows keychain binding, is not used in a container), so the COPYed source
#     IS the install: nothing is resolved from any registry.
#
# Layout inside the image:
#   /opt/s1-secops-mcp/                    (Node, from this repo)
#   /usr/local/lib/s1-secops/entry.mjs     (dispatcher: s1-secops-mcp | versions | notices | help)
#   /etc/sentinelone/CLAUDE.md             (default SOC analyst persona)
#   /etc/sentinelone/versions.json         (what is actually inside this image)
#   /usr/share/doc/secops-mcps/THIRD_PARTY_NOTICES.md
#
# RUN steps use the exec form: there is no /bin/sh to run a shell form.

# Base image pinned by digest (docker/build.sh owns the value and passes it in;
# this default only matters for a bare `docker build`). The root-user variant is
# used so the build steps can set file modes; the image runs as `nonroot` (USER below).
ARG BASE_IMAGE=gcr.io/distroless/nodejs24-debian13@sha256:03980f6fd2a3245fa06e371c36fd33528ebbc676a1d0f84e3e21d95cd291b807

FROM ${BASE_IMAGE}

# IMAGE_VERSION is the version of THIS IMAGE. S1_MCP_VERSION is the version of
# the bundled MCP server. They are separate counters, so the manifest and the OCI
# label each report the right one. Both reach the setup step as environment.
ARG IMAGE_VERSION
ARG S1_MCP_VERSION
ARG BUILD_DATE
ARG VCS_REF

LABEL org.opencontainers.image.title="SentinelOne SecOps MCP" \
      org.opencontainers.image.description="s1-secops-mcp with built-in Purple AI, VirusTotal and Shodan tools; distroless, one server, no shell, no npm" \
      org.opencontainers.image.source="https://github.com/Sentinel-One/ai-siem" \
      org.opencontainers.image.documentation="https://github.com/Sentinel-One/ai-siem/blob/main/plugins/s1-secops-skills/docs/docker.md" \
      org.opencontainers.image.licenses="AGPL-3.0" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.version="${IMAGE_VERSION}" \
      org.opencontainers.image.base.name="gcr.io/distroless/nodejs24-debian13"

# ─── s1-secops-mcp: straight from this repo, no resolution step ──────────────
# Mirrors the "files" allowlist in s1-secops-mcp/package.json exactly. Listed
# path by path rather than as a directory copy: the package directory also holds
# a `data/` tree that is not in the allowlist and must never reach the image.
COPY s1-secops-mcp/package.json  /opt/s1-secops-mcp/package.json
COPY s1-secops-mcp/index.js      /opt/s1-secops-mcp/index.js
COPY s1-secops-mcp/lib/          /opt/s1-secops-mcp/lib/
COPY s1-secops-mcp/tools/        /opt/s1-secops-mcp/tools/
COPY s1-secops-mcp/scripts/      /opt/s1-secops-mcp/scripts/
# License and third-party notices. The AGPL-3.0 text travels with the server it
# covers; the notices list the components and the services the built-in tools call.
COPY LICENSE                     /opt/s1-secops-mcp/LICENSE
COPY THIRD_PARTY_NOTICES.md      /usr/share/doc/secops-mcps/THIRD_PARTY_NOTICES.md
# Default SOC analyst persona. Override at runtime by mounting a project folder
# read-only (e.g. -v "$PROJECT:/workspace:ro") and setting S1_CLAUDE_MD_PATH=/workspace/CLAUDE.md.
COPY CLAUDE.md                   /etc/sentinelone/CLAUDE.md
COPY docker/container-entry.mjs  /usr/local/lib/s1-secops/entry.mjs

# Normalise file modes and write the version manifest. COPY keeps the source
# mode, and a checkout can carry 0600 files, which the nonroot user could not
# read (Node >=24 must read the nearest package.json to decide the module type).
# The same step asserts Node 24 and that S1_MCP_VERSION matches package.json.
# It also removes four base packages Node never loads (libssl3t64, zlib1g, libzstd1,
# libgomp1: Node compiles in its own OpenSSL and zlib), which carry the only scanner
# findings, files and dpkg records both. See UNUSED_PACKAGES in container-entry.mjs.
RUN ["/nodejs/bin/node", "/usr/local/lib/s1-secops/entry.mjs", "__image_setup"]
# Self-tests: crypto, TLS and zlib work without those packages, and the server loads.
RUN ["/nodejs/bin/node", "/usr/local/lib/s1-secops/entry.mjs", "__image_verify"]
RUN ["/nodejs/bin/node", "/opt/s1-secops-mcp/index.js", "--version"]

# A container has no OS keychain. Credentials arrive from the host launcher over
# stdin (S1_SECRETS_STDIN=1) or as environment variables.
ENV S1_KEYCHAIN=off
# Marks "running in this image" for lib/output.js: with no shared folder (the
# launcher's `install --output-dir`) outputFile is refused with advice that works
# under Docker, instead of reporting success for a file lost with the container.
ENV S1_IN_CONTAINER=1
ENV S1_CLAUDE_MD_PATH=/etc/sentinelone/CLAUDE.md

# ─── Run as a non-root user ──────────────────────────────────────────────────
# distroless ships `nonroot` (uid/gid 65532, home /home/nonroot). Nothing here
# writes: the server reads its code from /opt and speaks JSON-RPC over stdio.
# Node handles SIGINT/SIGTERM itself (lib/stdio-transport.js), so no init is needed.
USER 65532:65532
ENV HOME=/home/nonroot

ENTRYPOINT ["/nodejs/bin/node", "/usr/local/lib/s1-secops/entry.mjs"]
CMD ["help"]
