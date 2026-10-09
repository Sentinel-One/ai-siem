#!/bin/sh
# Dispatcher for the SentinelOne Claude Skills MCP Stack image.
# Routes the first argument to the right MCP server. All servers speak
# JSON-RPC over stdio per the MCP spec.
set -e

# ─── Secrets over stdin (S1_SECRETS_STDIN=1) ─────────────────────────────────
# The host launcher (docker/s1-secops-mcp-launch.sh / .ps1) reads the OS keychain
# and writes NAME=value lines, then one empty line, BEFORE relaying the MCP
# client's JSON-RPC stream. Reading them here keeps every secret out of
# `docker inspect` (Config.Env) and out of every command line. POSIX `read` on a
# pipe consumes exactly one line at a time, so the JSON-RPC stream that follows
# reaches the server untouched. Only known names are accepted.
if [ "${S1_SECRETS_STDIN:-}" = "1" ]; then
  BOM=$(printf '\357\273\277')
  while IFS= read -r line; do
    # A Windows host may prepend a UTF-8 BOM to the first line.
    line=${line#"$BOM"}
    [ -z "$line" ] && break
    case "$line" in
      "{"*) echo "entrypoint: S1_SECRETS_STDIN=1 but stdin starts with JSON-RPC; send NAME=value lines and an empty line first (use docker/s1-secops-mcp-launch.sh)" >&2; exit 64 ;;
    esac
    name=${line%%=*}
    value=${line#*=}
    case "$name" in
      S1_CONSOLE_URL|S1_CONSOLE_API_TOKEN|S1_HEC_INGEST_URL|S1_HEC_TOKEN|S1_SCOPE|VIRUSTOTAL_API_KEY|VT_API_KEY|PURPLEMCP_CONSOLE_BASE_URL|PURPLEMCP_CONSOLE_TOKEN|PURPLEMCP_VT_API_KEY)
        export "$name=$value" ;;
      *)
        echo "entrypoint: ignoring unknown name on the secrets channel" >&2 ;;
    esac
  done
  unset line name value BOM S1_SECRETS_STDIN
fi

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
# Only for the server that reads them: a second copy of the token in another
# server's environment is one more place for it to leak from.
case "${1:-}" in
  purple-mcp|purple)
    if [ -z "${PURPLEMCP_CONSOLE_BASE_URL:-}" ] && [ -n "${S1_CONSOLE_URL:-}" ]; then
      PURPLEMCP_CONSOLE_BASE_URL="${S1_CONSOLE_URL%/}"
      export PURPLEMCP_CONSOLE_BASE_URL
    fi
    if [ -z "${PURPLEMCP_CONSOLE_TOKEN:-}" ] && [ -n "${S1_CONSOLE_API_TOKEN:-}" ]; then
      PURPLEMCP_CONSOLE_TOKEN="${S1_CONSOLE_API_TOKEN}"
      export PURPLEMCP_CONSOLE_TOKEN
    fi
    # purple-mcp's threat_intel_* and VT Intelligence search read PURPLEMCP_VT_API_KEY.
    if [ -z "${PURPLEMCP_VT_API_KEY:-}" ]; then
      if [ -n "${VIRUSTOTAL_API_KEY:-}" ]; then PURPLEMCP_VT_API_KEY="${VIRUSTOTAL_API_KEY}"; export PURPLEMCP_VT_API_KEY
      elif [ -n "${VT_API_KEY:-}" ]; then PURPLEMCP_VT_API_KEY="${VT_API_KEY}"; export PURPLEMCP_VT_API_KEY; fi
    fi
    unset VIRUSTOTAL_API_KEY VT_API_KEY ;;
esac
if [ -z "${VIRUSTOTAL_API_KEY:-}" ] && [ -n "${VT_API_KEY:-}" ]; then
  VIRUSTOTAL_API_KEY="${VT_API_KEY}"
  export VIRUSTOTAL_API_KEY
fi
if [ -z "${VT_API_KEY:-}" ] && [ -n "${VIRUSTOTAL_API_KEY:-}" ]; then
  VT_API_KEY="${VIRUSTOTAL_API_KEY}"
  export VT_API_KEY
fi

# Extra arguments after the server name are passed through to the server
# binary (e.g. `s1-secops-mcp --version`).
# The two JS servers are invoked through `node <path>` rather than through their
# /usr/local/bin symlinks. The symlinks exist for anyone who shells into the
# container, but dispatching via node means a missing or mangled shebang in a
# built artefact cannot turn into an "exec format error" at first JSON-RPC call.
case "${1:-help}" in
  s1-secops-mcp | s1)
    shift
    exec node /opt/s1-secops-mcp/index.js "$@"
    ;;
  purple-mcp | purple)
    shift
    exec purple-mcp-bin --mode stdio "$@"
    ;;
  virustotal-mcp | virustotal | vt)
    shift
    exec node /opt/mcp-virustotal/build/index.js "$@"
    ;;
  versions | version)
    # Replaces `npm ls -g`, which this image no longer has. The image tag does
    # not encode what is inside it, so read the manifest rather than infer.
    exec cat /etc/sentinelone/versions.json
    ;;
  help | --help | -h | "")
    cat <<'EOF'
SentinelOne Claude Skills MCP Stack

Bundled servers (select one per `docker run`):
  s1-secops-mcp     PowerQuery, SDL, Mgmt Console REST, UAM, Hyperautomation
  purple-mcp        Alert triage, Purple AI NLQ, Deep Visibility, assets, vulnerabilities
  virustotal-mcp    External IOC enrichment

Other commands:
  versions          Print the pinned source of every bundled server as JSON

Usage (recommended): run through the host launcher, which reads the OS
keychain and passes secrets over stdin so they never appear in
`docker inspect`:
  s1-secops-mcp-launch.sh setup            # once: store values in the keychain
  s1-secops-mcp-launch.sh s1-secops-mcp    # what the MCP client runs

Manual equivalent (secrets as the first stdin lines, then an empty line):
  docker run -i --rm -e S1_SECRETS_STDIN=1 sentinelone/secops-mcps:1.5.3 s1-secops-mcp

Environment variables (-e S1_CONSOLE_URL -e S1_CONSOLE_API_TOKEN ...) still
work but are readable by anyone who can run `docker inspect`.

Every server is built from a pinned git source. This image contains no npm.

Reference:
  https://github.com/Sentinel-One/ai-siem/blob/main/plugins/s1-secops-skills/docs/docker.md
EOF
    ;;
  *)
    echo "entrypoint: unknown command '$1'" >&2
    echo "valid: s1-secops-mcp, purple-mcp, virustotal-mcp, versions, help" >&2
    exit 64
    ;;
esac
