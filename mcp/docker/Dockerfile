# syntax=docker/dockerfile:1.7
#
# SentinelOne Claude Skills MCP Stack
# ─────────────────────────────────────────────────────────────────────────────
# One image, four MCPs (s1-secops-mcp, purple-mcp, virustotal-mcp, and the
# optional shodan-mcp).
#
# NO NPM. Nothing in this build resolves a package from the npm registry, and
# the npm and npx binaries are deleted from the final image so a future edit
# cannot quietly reintroduce one. Each MCP arrives from source:
#
#   s1-secops-mcp    COPY from this repo's build context. It has no required
#                    dependencies (its one optional dependency, the Windows
#                    keychain binding, is not used in a container), so there
#                    is nothing to resolve: the source IS the install.
#   virustotal-mcp   git clone of a pinned commit in our fork, which commits
#                    its own build/ and production node_modules/ (see
#                    scripts/vendor-node-fork.sh). Clone, symlink, done.
#   shodan-mcp       Same pattern as virustotal-mcp: pinned commit of our fork
#                    of w0h1v/mcp-shodan with vendored build/ and node_modules/.
#                    Optional: only started when the client config asks for it.
#   purple-mcp      pip install from a pinned git commit, isolated venv.
#                    Python deps still resolve from PyPI; see docker/README.md.
#
# Pins are passed as build args by docker/build.sh and the GHA workflow at
# .github/workflows/docker-publish.yml. Bumping a pin = one edit in build.sh
# and one in the workflow env block, then re-run.
#
# Layout inside the final image:
#   /opt/s1-secops-mcp/                  (Node, from local source)
#   /opt/mcp-virustotal/                 (Node, from the pinned fork)
#   /opt/mcp-shodan/                     (Node, from the pinned fork)
#   /opt/purple-mcp/                     (Python venv)
#   /usr/local/bin/s1-secops-mcp         (symlink)
#   /usr/local/bin/mcp-virustotal        (symlink)
#   /usr/local/bin/mcp-shodan            (symlink)
#   /usr/local/bin/purple-mcp-bin        (symlink)
#   /usr/local/bin/entrypoint.sh         (dispatcher; selects which MCP to run)
#   /etc/sentinelone/CLAUDE.md           (default SOC analyst persona)
#   /etc/sentinelone/versions.json       (what is actually inside this image)
#

# ═══════════════════════════════════════════════════════════════════════════
# Stage 1: fetch. Everything that needs network or git lives here, so neither
# git nor any clone metadata reaches the runtime image.
# ═══════════════════════════════════════════════════════════════════════════
# Base image: Node 24 LTS pinned by digest (docker/build.sh owns the value and
# passes it in; this default only matters for a bare `docker build`). Both
# stages use the same bytes. The runtime stage asserts the major version.
ARG NODE_IMAGE=node:24-trixie-slim@sha256:173f125896c3b47ddf056734c7ea789d04595a6a08769a8f78e0df642781fb66

FROM ${NODE_IMAGE} AS fetch

ARG VT_MCP_REPO
ARG VT_MCP_REF
ARG SHODAN_MCP_REPO
ARG SHODAN_MCP_REF
ARG PURPLE_MCP_REPO
ARG PURPLE_MCP_REF

RUN apt-get update && apt-get install -y --no-install-recommends \
      python3 python3-venv python3-pip \
      git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# ─── virustotal-mcp: pinned commit of our fork, deps already vendored ────────
#
# `git clone --depth 1` cannot target a bare SHA, so init + fetch the exact
# commit. GitHub serves reachable SHAs to fetch-by-object-id, which is what
# makes the pin exact rather than "whatever that branch points at today".
RUN mkdir -p /opt/mcp-virustotal \
    && cd /opt/mcp-virustotal \
    && git init -q . \
    && git remote add origin "${VT_MCP_REPO}" \
    && git fetch -q --depth 1 origin "${VT_MCP_REF}" \
    && git checkout -q FETCH_HEAD \
    && rm -rf .git

# Fail the build loudly rather than shipping a container that dies on first
# JSON-RPC call. The fork MUST commit its compiled output and its production
# dependency tree; that is the whole point of the no-registry design, and it
# is the one thing about the fork this build cannot fix for itself.
RUN set -eu; \
    cd /opt/mcp-virustotal; \
    if [ ! -f build/index.js ]; then \
      echo "ERROR: ${VT_MCP_REPO}@${VT_MCP_REF} has no build/index.js." >&2; \
      echo "The fork must commit its compiled output. Run scripts/vendor-vt-fork.sh" >&2; \
      echo "against the fork and push the result, then repin VT_MCP_REF." >&2; \
      exit 1; \
    fi; \
    if [ ! -d node_modules ]; then \
      echo "ERROR: ${VT_MCP_REPO}@${VT_MCP_REF} has no vendored node_modules/." >&2; \
      echo "Without it the server cannot start and this image would need npm." >&2; \
      echo "Run scripts/vendor-vt-fork.sh against the fork and push the result." >&2; \
      exit 1; \
    fi; \
    chmod +x build/index.js

# ─── shodan-mcp: pinned commit of our fork, deps already vendored ────────────
# Same fetch-by-SHA and same "fail loudly" checks as virustotal-mcp above. The
# fork also must not carry a .env file: the server would not read it (the fork
# removes dotenv), but a stray one in the image is a credential-shaped file
# that a scanner, or a person, would rightly flag.
RUN mkdir -p /opt/mcp-shodan \
    && cd /opt/mcp-shodan \
    && git init -q . \
    && git remote add origin "${SHODAN_MCP_REPO}" \
    && git fetch -q --depth 1 origin "${SHODAN_MCP_REF}" \
    && git checkout -q FETCH_HEAD \
    && rm -rf .git
RUN set -eu; \
    cd /opt/mcp-shodan; \
    for f in build/index.js FORK_NOTES.md; do \
      [ -f "$f" ] || { echo "ERROR: ${SHODAN_MCP_REPO}@${SHODAN_MCP_REF} has no $f. Run scripts/vendor-node-fork.sh against the fork, push, repin SHODAN_MCP_REF." >&2; exit 1; }; \
    done; \
    [ -d node_modules ] || { echo "ERROR: ${SHODAN_MCP_REPO}@${SHODAN_MCP_REF} has no vendored node_modules/." >&2; exit 1; }; \
    [ ! -d node_modules/dotenv ] || { echo "ERROR: dotenv is vendored; the S1 fork removes it." >&2; exit 1; }; \
    find . -name '.env' -o -name '.env.*' ! -name '.env.example' | grep -q . && { echo "ERROR: .env file in the fork" >&2; exit 1; } || true; \
    rm -rf src tests docs .github Dockerfile .dockerignore smithery.yaml mkdocs.yml mkdocs_hooks.py .env.example; \
    chmod +x build/index.js

# ─── purple-mcp: pinned git commit, isolated venv ────────────────────────────
# Built here and copied wholesale. The venv is created at the same absolute
# path it will occupy at runtime, so its baked-in paths stay valid.
RUN python3 -m venv /opt/purple-mcp \
    && /opt/purple-mcp/bin/pip install --no-cache-dir --upgrade pip \
    && /opt/purple-mcp/bin/pip install --no-cache-dir \
        "purple-mcp @ git+${PURPLE_MCP_REPO}@${PURPLE_MCP_REF}" \
    && /opt/purple-mcp/bin/pip install --no-cache-dir --upgrade \
        "setuptools>=78" "msgpack>=1.1.3" \
    && rm -rf /opt/purple-mcp/lib/python*/site-packages/pip \
              /opt/purple-mcp/lib/python*/site-packages/pip-*.dist-info \
              /opt/purple-mcp/bin/pip /opt/purple-mcp/bin/pip3 /opt/purple-mcp/bin/pip3.* \
    && find /opt/purple-mcp/lib/python*/site-packages \
         -type d \( -name tests -o -name testing \) -prune -exec rm -rf {} + \
    && find /opt/purple-mcp/lib/python*/site-packages \
         -type f -name "*.pyi" -delete

# setuptools and msgpack carry the only fixable HIGH CVEs that are not Debian's.
# They are transitive deps of purple-mcp, resolved from PyPI into OUR venv, so we
# upgrade them here rather than forking upstream: a fork would mean maintaining a
# divergent copy of someone else's server to change two pins we already control.
# Upstream is still pinned by commit; only these two are floated forward.
#
# Test suites bundled inside site-packages are stripped (~53 MB). They are dead
# weight in a runtime image.
#
# __pycache__ is deliberately NOT stripped, though it is the single biggest
# directory at ~95 MB. Those .pyc files ARE the compiled cache. The container
# runs as an unprivileged user against a root-owned site-packages, so Python
# cannot rewrite them: deleting them does not save the cost once, it pays
# recompilation on EVERY container start, forever, and purple-mcp imports
# pandas. Disk is cheaper than per-session latency here.
#
# The venv is ~288 MB mostly because purple-mcp hard-requires pandas
# (Requires-Dist: pandas>=2.2, imported by purple_mcp/libs/sdl/models.py), and
# pandas + numpy are ~141 MB of that. Removing them means patching upstream,
# which is the one change that would actually justify forking purple-mcp.
#
# pip is then DELETED from the venv. It is a build-time tool that nothing
# imports at runtime, and it ships its own vendored copies of the very packages
# we just upgraded: pip 26.2.1 bundles setuptools 70.3.0 and msgpack 1.1.2 under
# pip/_vendor/. Upgrading site-packages does not touch those, so a scanner
# correctly keeps reporting the old versions even though nothing can import
# them. Removing pip is what actually clears them, and it makes the venv
# immutable at runtime as a side effect.

# ═══════════════════════════════════════════════════════════════════════════
# Stage 2: runtime.
# ═══════════════════════════════════════════════════════════════════════════
FROM ${NODE_IMAGE}

# Node 24 is the supported runtime for all three JS servers. A digest bump that
# moved the major would change behaviour (and Node >=24 package.json handling
# already bit us once, see the chmod note below), so refuse it here.
RUN case "$(node -v)" in v24.*) ;; *) echo "ERROR: base image runs $(node -v), expected Node 24" >&2; exit 1 ;; esac

# IMAGE_VERSION is the version of THIS IMAGE. S1_MCP_VERSION is the version of
# the bundled MCP server. They are different counters and must not be conflated:
# image 1.4.3 bundles MCP 1.3.9. Both are needed here, because the version
# manifest and the OCI label below each report a different one.
ARG IMAGE_VERSION
ARG S1_MCP_VERSION
ARG VT_MCP_REPO
ARG VT_MCP_REF
ARG SHODAN_MCP_REPO
ARG SHODAN_MCP_REF
ARG PURPLE_MCP_REPO
ARG PURPLE_MCP_REF
ARG BUILD_DATE
ARG VCS_REF

# `org.opencontainers.image.version` is the version OF THE IMAGE, so it takes
# IMAGE_VERSION. It previously took S1_MCP_VERSION, which made every published
# image label itself with the MCP's number instead of its own.
LABEL org.opencontainers.image.title="SentinelOne Claude Skills MCP Stack" \
      org.opencontainers.image.description="s1-secops-mcp + purple-mcp + virustotal MCP + optional shodan MCP, single image, no npm" \
      org.opencontainers.image.source="https://github.com/Sentinel-One/ai-siem" \
      org.opencontainers.image.documentation="https://github.com/Sentinel-One/ai-siem/blob/main/plugins/s1-secops-skills/docs/docker.md" \
      org.opencontainers.image.licenses="AGPL-3.0" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.version="${IMAGE_VERSION}"

# Runtime system deps only.
#   python3         : the purple-mcp venv symlinks to it (no venv/pip needed here)
#   tini            : forwards SIGTERM cleanly to the MCP child process
#   ca-certificates : TLS for outbound calls to *.sentinelone.net etc.
# Deliberately absent: git (fetch-stage only), python3-pip, python3-venv.
# `apt-get upgrade` applies Debian security fixes published after the base image
# was built. The base tag lags: on 2026-10-05 node:24-trixie-slim still carried
# libpcre2-8-0 10.46-1~deb13u2 (CVE-2026-103111, HIGH) when u3 was available,
# which fails the Trivy fixable-HIGH gate on an otherwise clean build.
RUN apt-get update && apt-get upgrade -y --no-install-recommends \
    && apt-get install -y --no-install-recommends \
      python3 ca-certificates tini \
    && rm -rf /var/lib/apt/lists/*

# ─── libexpat1 from Debian forky (temporary) ─────────────────────────────────
# Trixie's expat 2.8.3-1~deb13u1 carries CVE-2026-77214 (heap over-read) and
# CVE-2026-93990 (unpaired UTF-16 surrogates), both HIGH, with no trixie fix
# yet (security-tracker, 2026-10-13). Forky ships 2.9.0-1, which fixes both.
# Only python3.13 links libexpat1 here (pyexpat).
#
# The forky source is added for this ONE package at an exact version, pinned
# above trixie only for libexpat1 (every other forky package stays at priority
# 100, below trixie's 500), then removed again so no later RUN can pull from
# testing. The install fails if apt would bring in anything else from forky.
# Drop this block once trixie-security publishes a fixed expat: `apt-get
# upgrade` above will then supply it.
ARG EXPAT_FORKY_VERSION=2.9.0-1
RUN set -eu; \
    echo 'deb http://deb.debian.org/debian forky main' > /etc/apt/sources.list.d/forky-expat.list; \
    printf 'Package: *\nPin: release n=forky\nPin-Priority: 100\n\nPackage: libexpat1\nPin: release n=forky\nPin-Priority: 990\n' > /etc/apt/preferences.d/forky-expat; \
    apt-get update; \
    extra="$(apt-get -s install -y --no-install-recommends "libexpat1=${EXPAT_FORKY_VERSION}" | awk '/^Inst / && $2 != "libexpat1" {print $2}')"; \
    [ -z "$extra" ] || { echo "ERROR: libexpat1 ${EXPAT_FORKY_VERSION} would also pull: $extra" >&2; exit 1; }; \
    apt-get install -y --no-install-recommends "libexpat1=${EXPAT_FORKY_VERSION}"; \
    rm -f /etc/apt/sources.list.d/forky-expat.list /etc/apt/preferences.d/forky-expat; \
    rm -rf /var/lib/apt/lists/*; \
    [ "$(dpkg-query -W -f='${Version}' libexpat1)" = "${EXPAT_FORKY_VERSION}" ]; \
    python3 -c 'import pyexpat, xml.etree.ElementTree as E; assert E.fromstring("<a>ok</a>").text == "ok"; print("pyexpat", pyexpat.EXPAT_VERSION)'

# ─── Delete npm and npx ──────────────────────────────────────────────────────
# The node base image ships them. Removing them turns "we do not use the npm
# registry" from a convention into a property of the image: a later RUN that
# tries `npm install` fails at build time instead of silently reintroducing a
# registry dependency. Node itself is untouched and is what actually runs the
# two JS servers.
#
# corepack goes with it. It is the yarn/pnpm shim, and together with npm it is
# the entire difference between node:24-trixie-slim and plain debian:trixie-slim.
# Nothing here uses an alternative package manager, and leaving a second
# registry-fetching tool behind after deleting the first would be pointless.
RUN rm -rf /usr/local/lib/node_modules/npm \
           /usr/local/lib/node_modules/corepack \
           /usr/local/bin/npm \
           /usr/local/bin/npx \
           /usr/local/bin/corepack \
    && ! command -v npm >/dev/null 2>&1 \
    && ! command -v corepack >/dev/null 2>&1

# ─── s1-secops-mcp: straight from this repo, no resolution step ──────────────
# Mirrors the "files" allowlist in s1-secops-mcp/package.json exactly. Listed
# path by path rather than as a `COPY s1-secops-mcp/ ...` directory copy, which
# would be both wrong and dangerous here: the package directory also holds a
# 17 MB `data/` tree containing `data/credentials.json`, which is not in the
# allowlist, is not referenced by any code, and must never reach the image.
COPY s1-secops-mcp/package.json  /opt/s1-secops-mcp/package.json
COPY s1-secops-mcp/index.js      /opt/s1-secops-mcp/index.js
COPY s1-secops-mcp/lib/          /opt/s1-secops-mcp/lib/
COPY s1-secops-mcp/tools/        /opt/s1-secops-mcp/tools/
COPY s1-secops-mcp/scripts/      /opt/s1-secops-mcp/scripts/
# A container has no OS keychain. Credentials arrive from the host launcher over
# stdin (S1_SECRETS_STDIN=1, see entrypoint.sh) or as environment variables.
# The optional @napi-rs/keyring dependency is deliberately not installed here.
ENV S1_KEYCHAIN=off
# Marks "running in this image" for lib/output.js. The container's home and
# temp folders vanish with the container, so with no shared folder (the
# launcher's `install --output-dir`) outputFile is refused with advice that
# works under Docker, instead of reporting success for a file that is then lost.
ENV S1_IN_CONTAINER=1
# Normalise permissions. COPY preserves the mode of the source file, and a
# repo checkout can easily carry 0600 files (this one does: package.json comes
# through as -rw-------). Under USER node that is unreadable, and Node >=24
# MUST read the nearest package.json to decide the module type, so the server
# dies at startup with "Cannot read package config ... permission denied".
# Node 22 tolerates it, which is why this stayed hidden until the base image
# moved. a+rX gives read to all and execute only where it already applied, so
# directories stay traversable without making data files executable.
RUN chmod -R a+rX /opt/s1-secops-mcp \
    && chmod +x /opt/s1-secops-mcp/index.js \
    && ln -s /opt/s1-secops-mcp/index.js /usr/local/bin/s1-secops-mcp

# ─── virustotal-mcp + shodan-mcp + purple-mcp: from the fetch stage ──────────
COPY --from=fetch /opt/mcp-virustotal /opt/mcp-virustotal
COPY --from=fetch /opt/mcp-shodan     /opt/mcp-shodan
COPY --from=fetch /opt/purple-mcp     /opt/purple-mcp
RUN chmod -R a+rX /opt/mcp-virustotal /opt/mcp-shodan /opt/purple-mcp \
    && ln -s /opt/mcp-virustotal/build/index.js /usr/local/bin/mcp-virustotal \
    && ln -s /opt/mcp-shodan/build/index.js     /usr/local/bin/mcp-shodan \
    && ln -s /opt/purple-mcp/bin/purple-mcp  /usr/local/bin/purple-mcp-bin

# ─── Version manifest ────────────────────────────────────────────────────────
# Replaces `npm ls -g`, which no longer exists here. The image tag does not
# encode what is inside it, so bake the answer in and expose it through the
# dispatcher's `versions` command.
#
# `image_version` must come from IMAGE_VERSION. It previously came from
# S1_MCP_VERSION, so the one command that exists to answer "which image is
# this?" reported the bundled MCP's version instead: a build tagged 1.4.2
# answered "1.3.9". That is precisely the confusion the manifest was added to
# prevent, so the MCP version now has its own clearly-named field.
RUN test -n "${IMAGE_VERSION}" || (echo "ERROR: IMAGE_VERSION build-arg is required" >&2; exit 1); \
    NODE_V="$(node -v)"; \
    SHODAN_V="$(node -p 'require("/opt/mcp-shodan/package.json").version')"; \
    mkdir -p /etc/sentinelone && printf '%s\n' \
  '{' \
  '  "image_version": "'"${IMAGE_VERSION}"'",' \
  '  "build_date": "'"${BUILD_DATE}"'",' \
  '  "vcs_ref": "'"${VCS_REF}"'",' \
  '  "node": "'"${NODE_V}"'",' \
  '  "servers": {' \
  '    "s1-secops-mcp": { "source": "git", "repo": "https://github.com/Sentinel-One/ai-siem", "ref": "'"${VCS_REF}"'", "path": "mcp/s1-secops-mcp", "version": "'"${S1_MCP_VERSION}"'" },' \
  '    "virustotal-mcp": { "source": "git", "repo": "'"${VT_MCP_REPO}"'", "ref": "'"${VT_MCP_REF}"'" },' \
  '    "shodan-mcp": { "source": "git", "repo": "'"${SHODAN_MCP_REPO}"'", "ref": "'"${SHODAN_MCP_REF}"'", "version": "'"${SHODAN_V}"'", "optional": true },' \
  '    "purple-mcp": { "source": "git", "repo": "'"${PURPLE_MCP_REPO}"'", "ref": "'"${PURPLE_MCP_REF}"'" }' \
  '  },' \
  '  "npm": false' \
  '}' > /etc/sentinelone/versions.json

# ─── Default SOC analyst persona ──────────────────────────────────────────────
# Bundled at build time. Override at runtime by mounting a project folder
# read-only (e.g. -v "$PROJECT:/workspace:ro") and setting S1_CLAUDE_MD_PATH=/workspace/CLAUDE.md.
COPY CLAUDE.md /etc/sentinelone/CLAUDE.md
ENV S1_CLAUDE_MD_PATH=/etc/sentinelone/CLAUDE.md

# ─── Dispatcher ───────────────────────────────────────────────────────────────
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
# 755, not +x: sh must READ the script, and +x on a 0700/0711 checkout copy leaves
# it unreadable to USER node ("cannot open /usr/local/bin/entrypoint.sh:
# Permission denied", every command fails). Seen 2026-10-03 on a local 1.4.9 build.
RUN chmod 755 /usr/local/bin/entrypoint.sh

# ─── Remove Debian packages nothing here uses (1.5.4) ────────────────────────
# Each package below carries a HIGH CVE with no trixie fix, and none of them is
# loaded by anything this image runs. That was established from the shared
# library closure of node, python3.13, every extension module in the purple-mcp
# venv and the stdlib, tini, dash, cat, env and sed, mapped back to packages
# with dpkg -S:
#   util-linux family (login, mount, util-linux, bsdutils, libmount1,
#     libblkid1, libsmartcols1, liblastlog2-2): CVE-2026-76642, -78408, -78409,
#     -78410. Mount, nsenter and login tooling; a container that never mounts
#     or logs in has no use for it.
#   perl-base: CVE-2026-9538. No perl script ships or runs here.
#   libsystemd0, libudev1: CVE-2026-16742 (systemd-homed). Only apt,
#     libapt-pkg and unused PAM/coreutils helpers link them.
#   apt, libapt-pkg7.0: no CVE, but removing libsystemd0/libudev1 breaks them,
#     and the image is immutable at runtime anyway (npm is deleted the same way).
# Kept on purpose: libacl1 (coreutils, sed), libtinfo6 (bash; Python readline,
# imported by websockets and cyclopts), libuuid1 (Python _uuid), libexpat1
# (pyexpat, now 2.9.0), python3.13 (purple-mcp).
#
# dpkg itself and its status database stay, so scanners still see an accurate
# package list. Essential, Protected (login) and dependency checks are forced
# because Debian marks these as base-system packages; this image does not need them.
# The checks after the removal fail the build if any runtime lost something.
RUN set -eu; \
    PKGS="apt libapt-pkg7.0 login mount util-linux bsdutils libmount1 libblkid1 libsmartcols1 liblastlog2-2 perl-base libsystemd0 libudev1"; \
    present=""; for p in $PKGS; do dpkg-query -W -f='${Status}' "$p" 2>/dev/null | grep -q 'install ok installed' && present="$present $p"; done; \
    echo "removing:$present"; \
    dpkg --purge --force-remove-essential --force-remove-protected --force-depends $present; \
    rm -rf /var/cache/apt /var/lib/apt /etc/apt /var/cache/debconf/*-old; \
    for p in $PKGS; do ! dpkg-query -W -f='${Status}' "$p" 2>/dev/null | grep -q 'install ok installed' || { echo "ERROR: $p still installed" >&2; exit 1; }; done; \
    node -e 'require("node:https"); require("node:crypto").randomUUID(); console.log("node ok", process.version)'; \
    /opt/purple-mcp/bin/python -c 'import ssl, uuid, readline, pyexpat, purple_mcp, httpx, pydantic, fastmcp; uuid.uuid4(); ssl.create_default_context(); print("python ok", pyexpat.EXPAT_VERSION)'; \
    sh -c 'echo x | sed s/x/y/ | cat >/dev/null && env >/dev/null' && echo "shell tools ok"; \
    bash -c 'echo bash ok'; \
    /usr/bin/tini --version

# ─── Run as a non-root user ──────────────────────────────────────────────────
# The node base image already ships an unprivileged `node` user (uid 1000), so
# use it rather than inventing another. Nothing here needs to write: the three
# servers read their code from /opt, read CLAUDE.md and versions.json from
# /etc/sentinelone, and speak JSON-RPC over stdio. Credentials arrive over stdin
# from the host launcher (docker/s1-secops-mcp-launch.sh), which keeps them out
# of `docker inspect`; plain environment variables still work but are visible
# there. The container never reads or writes a credentials file.
#
# HOME is set because a bare `USER node` leaves HOME=/root, which the user
# cannot read. Python and Node both fall back to HOME for caches, and the
# failure is obscure: a server that starts, then errors on first use.
USER node
ENV HOME=/home/node

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/entrypoint.sh"]
CMD ["help"]
