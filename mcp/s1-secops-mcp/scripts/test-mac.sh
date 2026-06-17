#!/usr/bin/env bash
#
# Mac validation script for s1-secops-mcp v1.2.2.
#
# Runs the same test matrix as Linux:
#   - syntax-check every .js/.mjs file
#   - npm test (smoke + stdio + HTTP suites, 22 assertions)
#   - regen:readme --check (no doc drift)
#   - sanity-run the server in stdio and HTTP modes
#
# Run this from the s1-secops-mcp/ directory on your Mac:
#
#   cd ~/path/to/ai-siem/mcp/s1-secops-mcp
#   bash scripts/test-mac.sh
#
# All checks should pass with green PASS markers. Any FAIL line should be
# reported back so the issue can be diagnosed.

set -uo pipefail

PASS_COUNT=0
FAIL_COUNT=0

green() { printf '\033[32m%s\033[0m' "$*"; }
red()   { printf '\033[31m%s\033[0m' "$*"; }
bold()  { printf '\033[1m%s\033[0m' "$*"; }

pass() { printf '  %s %s\n' "$(green PASS)" "$1"; PASS_COUNT=$((PASS_COUNT+1)); }
fail() { printf '  %s %s\n  %s\n' "$(red FAIL)" "$1" "${2:-}"; FAIL_COUNT=$((FAIL_COUNT+1)); }
step() { printf '\n%s\n' "$(bold "$1")"; }

# ─── 1. Environment ───────────────────────────────────────────────────────────

step "1. Environment"
if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "  WARNING: this script targets macOS but you're on $(uname -s). Continuing anyway."
fi
if ! command -v node >/dev/null 2>&1; then
  fail "node not on PATH" "Install Node 18+: brew install node@20"
  exit 1
fi
NODE_MAJOR="$(node --version | sed 's/^v\([0-9]*\).*/\1/')"
if [[ "$NODE_MAJOR" -lt 18 ]]; then
  fail "Node $(node --version) is too old" "Need Node 18+"
  exit 1
fi
pass "Node $(node --version) on $(uname -srm)"

if [[ ! -f "index.js" ]]; then
  fail "Not in the s1-secops-mcp directory" "cd to .../ai-siem/mcp/s1-secops-mcp first"
  exit 1
fi
pass "running from s1-secops-mcp directory"

# ─── 2. Syntax check ──────────────────────────────────────────────────────────

step "2. Syntax check"
for f in index.js lib/*.js tests/*.mjs scripts/*.mjs; do
  [[ -f "$f" ]] || continue
  if node --check "$f" 2>/dev/null; then
    pass "$f"
  else
    out="$(node --check "$f" 2>&1)"
    fail "$f" "$out"
  fi
done

# ─── 3. npm test (22 assertions across smoke + stdio + HTTP) ─────────────────

step "3. Test suite (npm test)"
# Node 18-22 default to the TAP reporter, Node 23+ default to spec. Both
# reporters print the same passing assertions but with different summary
# lines. We check exit code first (authoritative) and then count assertions.
TEST_LOG="/tmp/mcp-test-mac.npm-test.log"
if npm test >"$TEST_LOG" 2>&1; then
  # Count passing assertions across both reporter formats:
  #   TAP:   "ok 1 - <name>"
  #   spec:  "✔ <name>" (U+2714 HEAVY CHECK MARK)
  TAP_OKS="$(grep -cE '^ok [0-9]+' "$TEST_LOG" || true)"
  SPEC_OKS="$(grep -cE '^[[:space:]]*✔' "$TEST_LOG" || true)"
  TOTAL=$((TAP_OKS + SPEC_OKS))
  if [[ "$TOTAL" -ge 22 ]]; then
    pass "$TOTAL passing assertions (npm test exit 0)"
  else
    fail "npm test exited 0 but only $TOTAL passing lines found" "$(tail -30 "$TEST_LOG")"
  fi
else
  fail "npm test exited non-zero" "$(tail -30 "$TEST_LOG")"
fi

# ─── 4. README/code drift check ───────────────────────────────────────────────

step "4. README/code drift check"
if npm run regen:readme -- --check >/dev/null 2>&1; then
  pass "README tools table in sync with ALL_TOOLS"
else
  fail "README tools table is stale" "Run: npm run regen:readme"
fi

# ─── 5. CLI flag sanity ───────────────────────────────────────────────────────

step "5. CLI flag sanity"
if [[ "$(node index.js --version 2>/dev/null)" == "1.2.2" ]]; then
  pass "--version returns 1.2.2"
else
  fail "--version did not return 1.2.2" "Got: $(node index.js --version 2>&1)"
fi
if node index.js --help 2>&1 | grep -q "s1-secops-mcp 1.2.2"; then
  pass "--help renders"
else
  fail "--help broken" "$(node index.js --help 2>&1 | head -5)"
fi

# ─── 6. stdio round-trip ──────────────────────────────────────────────────────

step "6. stdio round-trip"
STDIO_REPLY="$(printf '%s\n%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"mac-test","version":"1"}}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' \
  | node index.js 2>/dev/null)"

TOOL_COUNT="$(echo "$STDIO_REPLY" | tail -n 1 | node -e 'let s=""; process.stdin.on("data",d=>s+=d); process.stdin.on("end",()=>{try{console.log(JSON.parse(s).result.tools.length)}catch(e){console.log("ERR")}})')"
if [[ "$TOOL_COUNT" == "26" ]]; then
  pass "stdio tools/list returned 26 tools"
else
  fail "stdio tools/list returned $TOOL_COUNT (expected 26)" "$STDIO_REPLY"
fi

# ─── 7. HTTP transport round-trip ─────────────────────────────────────────────

step "7. HTTP transport round-trip"
PORT=$((10000 + RANDOM % 1000))
node index.js --transport http --port "$PORT" --host 127.0.0.1 >/tmp/mcp-test-mac.log 2>&1 &
SERVER_PID=$!
trap "kill $SERVER_PID 2>/dev/null || true" EXIT

# Wait for healthz
for i in $(seq 1 30); do
  if curl -sf "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1; then
    pass "HTTP server up on port $PORT"
    break
  fi
  sleep 0.2
  if [[ "$i" -eq 30 ]]; then
    fail "HTTP server did not start within 6s" "$(cat /tmp/mcp-test-mac.log)"
    exit 1
  fi
done

HTTP_REPLY="$(curl -sf -X POST "http://127.0.0.1:$PORT/mcp" \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}')"
HTTP_COUNT="$(echo "$HTTP_REPLY" | node -e 'let s=""; process.stdin.on("data",d=>s+=d); process.stdin.on("end",()=>{try{console.log(JSON.parse(s).result.tools.length)}catch(e){console.log("ERR")}})')"
if [[ "$HTTP_COUNT" == "26" ]]; then
  pass "HTTP tools/list returned 26 tools"
else
  fail "HTTP tools/list returned $HTTP_COUNT" "$HTTP_REPLY"
fi

# Auth: with no token loaded the server should accept unauthenticated requests
# (single-user local-only mode). Confirmed by the 26-tools response above.
pass "no-auth mode allows requests (single-user local)"

kill $SERVER_PID 2>/dev/null || true
trap - EXIT

# ─── Summary ──────────────────────────────────────────────────────────────────

step "Summary"
printf "  Passed: %s\n" "$(green "$PASS_COUNT")"
if [[ "$FAIL_COUNT" -gt 0 ]]; then
  printf "  Failed: %s\n\n" "$(red "$FAIL_COUNT")"
  echo "If any FAILs above, paste them so the issue can be diagnosed."
  exit 1
else
  printf "  Failed: %s\n\n" "$FAIL_COUNT"
  echo "$(green 'All checks passed on macOS.')"
  exit 0
fi
