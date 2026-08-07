#!/bin/sh
# Dispatcher for the SentinelOne Claude Skills MCP Stack image.
# Routes the first argument to the right MCP server. All servers speak
# JSON-RPC over stdio per the MCP spec.
set -e

# Canonical credential names, shared by every bundled server.
#
# purple-mcp and mcp-virustotal each expect their own variable names for the
# same values. Rather than make the operator set the console URL and token
# twice, map the canonical S1_* names onto them here. A server-specific name
# that is already set always wins, so existing configurations are unaffected.
#
#   S1_CONSOLE_URL       -> PURPLEMCP_CONSOLE_BASE_URL
#   S1_CONSOLE_API_TOKEN -> PURPLEMCP_CONSOLE_TOKEN
#   VT_API_KEY           -> VIRUSTOTAL_API_KEY   (and the reverse)
if [ -z "${PURPLEMCP_CONSOLE_BASE_URL:-}" ] && [ -n "${S1_CONSOLE_URL:-}" ]; then
  PURPLEMCP_CONSOLE_BASE_URL="${S1_CONSOLE_URL%/}"
  export PURPLEMCP_CONSOLE_BASE_URL
fi
if [ -z "${PURPLEMCP_CONSOLE_TOKEN:-}" ] && [ -n "${S1_CONSOLE_API_TOKEN:-}" ]; then
  PURPLEMCP_CONSOLE_TOKEN="${S1_CONSOLE_API_TOKEN}"
  export PURPLEMCP_CONSOLE_TOKEN
fi
if [ -z "${VIRUSTOTAL_API_KEY:-}" ] && [ -n "${VT_API_KEY:-}" ]; then
  VIRUSTOTAL_API_KEY="${VT_API_KEY}"
  export VIRUSTOTAL_API_KEY
fi
if [ -z "${VT_API_KEY:-}" ] && [ -n "${VIRUSTOTAL_API_KEY:-}" ]; then
  VT_API_KEY="${VIRUSTOTAL_API_KEY}"
  export VT_API_KEY
fi

# Extra arguments after the server name are passed through to the server
# binary (e.g. `s1-secops-mcp --transport http --port 8765`).
case "${1:-help}" in
  s1-secops-mcp | s1)
    shift
    exec s1-secops-mcp "$@"
    ;;
  purple-mcp | purple)
    shift
    exec purple-mcp-bin --mode stdio "$@"
    ;;
  virustotal-mcp | virustotal | vt)
    shift
    exec mcp-virustotal "$@"
    ;;
  help | --help | -h | "")
    cat <<'EOF'
SentinelOne Claude Skills MCP Stack

Bundled servers (select one per `docker run`):
  s1-secops-mcp   PowerQuery, SDL, Mgmt Console REST, UAM, Hyperautomation
  purple-mcp        Alert triage, Purple AI NLQ, Deep Visibility, assets, vulnerabilities
  virustotal-mcp    External IOC enrichment

Usage:
  docker run -i --rm -e S1_CONSOLE_URL -e S1_CONSOLE_API_TOKEN ... \
    ghcr.io/pmoses-s1/s1-mcps:latest s1-secops-mcp

Reference:
  https://github.com/pmoses-s1/claude-skills/blob/main/docs/docker.md
EOF
    ;;
  *)
    echo "entrypoint: unknown command '$1'" >&2
    echo "valid: s1-secops-mcp, purple-mcp, virustotal-mcp, help" >&2
    exit 64
    ;;
esac
