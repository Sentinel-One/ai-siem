#!/bin/sh
# Dispatcher for the SentinelOne Claude Skills MCP Stack image.
# Routes the first argument to the right MCP server. All servers speak
# JSON-RPC over stdio per the MCP spec.
set -e

case "${1:-help}" in
  s1-secops-mcp|sentinelone-mcp|s1)
    exec sentinelone-mcp
    ;;
  purple-mcp|purple)
    exec purple-mcp-bin --mode stdio
    ;;
  virustotal-mcp|virustotal|vt)
    exec mcp-virustotal
    ;;
  help|--help|-h|"")
    cat <<'EOF'
SentinelOne Claude Skills MCP Stack

Bundled servers (select one per `docker run`):
  s1-secops-mcp    PowerQuery, SDL, Mgmt Console REST, UAM, Hyperautomation
  purple-mcp        Alert triage, Purple AI NLQ, Deep Visibility, assets, vulnerabilities
  virustotal-mcp    External IOC enrichment

Usage:
  docker run -i --rm -e S1_CONSOLE_URL -e S1_CONSOLE_API_TOKEN ... \
    ghcr.io/pmoses-s1/s1-mcps:latest s1-secops-mcp

Reference:
  https://github.com/Sentinel-One/ai-siem/blob/main/plugins/s1-secops-skills/docs/docker.md
EOF
    ;;
  *)
    echo "entrypoint: unknown command '$1'" >&2
    echo "valid: s1-secops-mcp, purple-mcp, virustotal-mcp, help" >&2
    exit 64
    ;;
esac
