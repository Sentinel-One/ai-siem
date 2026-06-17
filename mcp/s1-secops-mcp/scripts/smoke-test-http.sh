#!/usr/bin/env bash
#
# smoke-test-http.sh -- generic HTTP smoke test for s1-secops-mcp.
#
# Exercises the public contract end-to-end:
#   1. healthz returns 200 (no auth)
#   2. initialize returns the expected protocol version and server info
#   3. tools/list returns 26 tools
#   4. tools/call s1_api_get works (uses /agents/count as a cheap probe)
#   5. bad bearer returns HTTP 401
#   6. unknown method returns JSON-RPC error -32601 inside a 200 envelope
#
# Useful for new team members verifying their setup, or for re-checking the
# deployment after a config change, a cert rotation, or an MCP version bump.
#
# Run as:
#   MCP_HOST=mcp.s1.internal:8764 \
#   MCP_BEARER=your-bearer-token \
#     bash s1-secops-mcp/scripts/smoke-test-http.sh
#
# Or set defaults at the top of the script and run with no args.

set -uo pipefail

HOST="${MCP_HOST:-}"
TOKEN="${MCP_BEARER:-}"

if [[ -z "$HOST" || -z "$TOKEN" ]]; then
  cat >&2 <<EOF
Usage:
  MCP_HOST=<host:port> MCP_BEARER=<token> bash $0

Both env vars are required.
EOF
  exit 2
fi

for tool in curl jq; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "Missing dependency: $tool" >&2
    exit 3
  fi
done

URL="https://$HOST/mcp"
AUTH="Authorization: Bearer $TOKEN"
JSON="Content-Type: application/json"

FAILED=0
fail() { echo "  FAIL: $*" >&2; FAILED=$((FAILED+1)); }
pass() { echo "  PASS: $*"; }

echo "=== 1. healthz (no auth) ==="
HEALTHZ_CODE=$(curl -s -o /dev/null -w "%{http_code}" "https://$HOST/healthz")
[[ "$HEALTHZ_CODE" == "200" ]] && pass "healthz returned 200" || fail "healthz returned $HEALTHZ_CODE (expected 200)"

echo
echo "=== 2. initialize ==="
INIT_BODY=$(curl -s -X POST "$URL" -H "$AUTH" -H "$JSON" -d '{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "initialize",
  "params": {
    "protocolVersion": "2024-11-05",
    "capabilities": {},
    "clientInfo": { "name": "smoke-test", "version": "1" }
  }
}')
PROTO=$(echo "$INIT_BODY" | jq -r '.result.protocolVersion // "missing"')
NAME=$( echo "$INIT_BODY" | jq -r '.result.serverInfo.name    // "missing"')
VER=$(  echo "$INIT_BODY" | jq -r '.result.serverInfo.version // "missing"')
[[ "$PROTO" == "2024-11-05" ]] && pass "protocolVersion=$PROTO" || fail "protocolVersion=$PROTO"
[[ "$NAME"  == "s1-secops-mcp-server" ]] && pass "serverInfo.name=$NAME" || fail "serverInfo.name=$NAME"
[[ "$VER" != "missing" ]] && pass "serverInfo.version=$VER" || fail "serverInfo.version missing"

echo
echo "=== 3. tools/list count ==="
TOOLS_COUNT=$(curl -s -X POST "$URL" -H "$AUTH" -H "$JSON" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
  | jq '.result.tools | length')
[[ "$TOOLS_COUNT" == "26" ]] && pass "tools/list returned 26 tools" || fail "tools/list returned $TOOLS_COUNT"

echo
echo "=== 4. tools/call s1_api_get on /agents/count ==="
AGENTS_TOTAL=$(curl -s -X POST "$URL" -H "$AUTH" -H "$JSON" -d '{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "tools/call",
  "params": {
    "name": "s1_api_get",
    "arguments": { "path": "/web/api/v2.1/agents/count" }
  }
}' | jq -r '.result.content[0].text' | jq -r '.data.total // "missing"')
if [[ "$AGENTS_TOTAL" =~ ^[0-9]+$ ]]; then
  pass "s1_api_get returned $AGENTS_TOTAL agents"
else
  fail "s1_api_get returned data.total=$AGENTS_TOTAL"
fi

echo
echo "=== 5. bad bearer (expect HTTP 401) ==="
BAD_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$URL" \
  -H "Authorization: Bearer wrong-token-of-sufficient-length-1234567890" -H "$JSON" \
  -d '{"jsonrpc":"2.0","id":99,"method":"tools/list"}')
[[ "$BAD_CODE" == "401" ]] && pass "bad bearer rejected with 401" || fail "bad bearer returned $BAD_CODE (expected 401)"

echo
echo "=== 6. method not found (expect -32601) ==="
ERR_CODE=$(curl -s -X POST "$URL" -H "$AUTH" -H "$JSON" \
  -d '{"jsonrpc":"2.0","id":4,"method":"does/not/exist"}' \
  | jq -r '.error.code // "missing"')
[[ "$ERR_CODE" == "-32601" ]] && pass "unknown method returned -32601" || fail "unknown method returned code=$ERR_CODE"

echo
echo "=== Summary ==="
if [[ "$FAILED" -eq 0 ]]; then
  echo "All checks passed."
  exit 0
else
  echo "$FAILED check(s) failed."
  exit 1
fi
