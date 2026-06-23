# syntax=docker/dockerfile:1.7
#
# SentinelOne Claude Skills MCP Stack
# ─────────────────────────────────────────────────────────────────────────────
# One image, three MCPs (sentinelone-mcp, purple-mcp, virustotal-mcp).
# Pinned versions are passed as build args by docker/build.sh and the GHA
# workflow at .github/workflows/docker-publish.yml. Bumping a pin = one edit
# in build.sh, then re-run.
#
# Layout inside the image:
#   /usr/local/bin/sentinelone-mcp       (Node, from @pmoses-s1/sentinelone-mcp)
#   /usr/local/bin/mcp-virustotal        (Node, from @burtthecoder/mcp-virustotal)
#   /usr/local/bin/purple-mcp-bin        (Python venv at /opt/purple-mcp)
#   /usr/local/bin/entrypoint.sh         (dispatcher; selects which MCP to run)
#   /etc/sentinelone/CLAUDE.md           (default SOC analyst persona)
#

FROM node:20-bookworm-slim

ARG S1_MCP_VERSION
ARG VT_MCP_PACKAGE
ARG VT_MCP_VERSION
ARG PURPLE_MCP_REF
ARG BUILD_DATE
ARG VCS_REF

LABEL org.opencontainers.image.title="SentinelOne Claude Skills MCP Stack" \
      org.opencontainers.image.description="sentinelone-mcp + purple-mcp + virustotal MCP, single image" \
      org.opencontainers.image.source="https://github.com/Sentinel-One/ai-siem" \
      org.opencontainers.image.documentation="https://github.com/Sentinel-One/ai-siem/blob/main/plugins/s1-secops-skills/docs/docker.md" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.version="${S1_MCP_VERSION}"

# System deps:
#   python3 + venv  : purple-mcp runtime
#   git             : pip needs it for git+ URLs
#   tini            : forwards SIGTERM cleanly to the MCP child process
#   ca-certificates : TLS for outbound calls to *.sentinelone.net etc.
RUN apt-get update && apt-get install -y --no-install-recommends \
      python3 python3-venv python3-pip \
      git ca-certificates tini \
    && rm -rf /var/lib/apt/lists/*

# ─── Node-based MCPs (pinned to exact npm versions) ───────────────────────────
RUN npm install -g \
      "@pmoses-s1/sentinelone-mcp@${S1_MCP_VERSION}" \
      "${VT_MCP_PACKAGE}@${VT_MCP_VERSION}" \
    && npm cache clean --force

# ─── Python-based MCP (pinned to a git ref, isolated venv) ────────────────────
RUN python3 -m venv /opt/purple-mcp \
    && /opt/purple-mcp/bin/pip install --no-cache-dir --upgrade pip \
    && /opt/purple-mcp/bin/pip install --no-cache-dir \
        "purple-mcp @ git+https://github.com/Sentinel-One/purple-mcp.git@${PURPLE_MCP_REF}" \
    && ln -s /opt/purple-mcp/bin/purple-mcp /usr/local/bin/purple-mcp-bin

# ─── Default SOC analyst persona ──────────────────────────────────────────────
# Bundled at build time. Override at runtime by mounting a project folder
# read-only (e.g. -v "$PROJECT:/workspace:ro") and setting S1_CLAUDE_MD_PATH=/workspace/CLAUDE.md.
COPY CLAUDE.md /etc/sentinelone/CLAUDE.md
ENV S1_CLAUDE_MD_PATH=/etc/sentinelone/CLAUDE.md

# ─── Dispatcher ───────────────────────────────────────────────────────────────
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/entrypoint.sh"]
CMD ["help"]
