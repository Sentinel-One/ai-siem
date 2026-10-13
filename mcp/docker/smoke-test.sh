#!/usr/bin/env bash
#
# smoke-test.sh -- validate a SentinelOne SecOps Skills MCP image.
#
# Usage:
#   docker/smoke-test.sh <image-ref> [--expect-version X.Y.Z] [--platform P]
#
# Examples:
#   docker/smoke-test.sh secops-mcps:local-rc1
#   docker/smoke-test.sh sentinelone/secops-mcps:1.5.4 --expect-version 1.5.4
#   docker/smoke-test.sh sentinelone/secops-mcps:1.5.4 --platform linux/amd64
#
# Exit code is the number of failed tests, so `if docker/smoke-test.sh IMG` works
# as a gate in CI or a release checklist.
#
# ── Why these tests exist ────────────────────────────────────────────────────
#
# Every assertion here corresponds to something that actually broke, or that the
# image makes a claim about. This is not a generic container test suite:
#
#   T04/T05  npm and npx are deleted on purpose. The whole point of the git-only
#            build is that they cannot come back; assert it rather than trust it.
#   T06      git belongs to the fetch stage only. If it appears in the runtime
#            image, the two-stage split has silently collapsed.
#   T07      versions.json once reported the MCP's version in the field named
#            `image_version`, so the one command that answers "which image is
#            this?" was lying. Check the value, not just that the file parses.
#   T09      s1-secops-mcp/data/ is git-ignored and holds only untracked local
#            exports. It is never copied into the image and must never reach a
#            published layer.
#   T10      The image must run unprivileged.
#   T12-T14  initialize alone proves very little. A server can start and still
#            fail to enumerate tools, so drive a real tools/list and count.
#   T15      Nothing may phone home at runtime. The provenance URL in
#            versions.json is metadata, not a dependency, and --network none is
#            the only way to prove that.
#   T16      A manifest list whose children 404 still returns 200 on the tag.
#            That exact failure shipped a "restored" image nobody could pull.
#   T22-T27  shodan-mcp (1.5.4, optional): tool count, stdio forced even when
#            MCP_TRANSPORT=httpStream is passed, a clear exit without a key,
#            no .git/.env/src or stripped tunnel code in /opt/mcp-shodan, the
#            Shodan key never reaches another server, and versions.json records
#            the pin and Node 24.
#   T28-T29  Unused Debian packages with unfixed HIGH CVEs stay removed, and
#            libexpat1 stays on the fixed 2.9.0-1.
#   T30-T31  outputFile: with no shared folder it is refused with the
#            `install --output-dir` advice (no silent loss in /tmp); with a
#            shared folder the path is accepted.
#
set -uo pipefail

IMAGE="${1:-}"
shift || true
EXPECT_VERSION=""
PLATFORM=""
while [ $# -gt 0 ]; do
  case "$1" in
    --expect-version) EXPECT_VERSION="${2:-}"; shift 2 ;;
    --platform)       PLATFORM="${2:-}"; shift 2 ;;
    *) echo "unknown option: $1" >&2; exit 64 ;;
  esac
done

if [ -z "$IMAGE" ]; then
  sed -n '3,12p' "$0" | sed 's/^# \{0,1\}//'
  exit 64
fi

PLAT_ARGS=()
[ -n "$PLATFORM" ] && PLAT_ARGS=(--platform "$PLATFORM")
# Expand safely on bash 3.2 (macOS default) where an empty array under
# `set -u` is an unbound-variable error. Use $PLAT as the expansion point.
PLAT() { printf '%s\n' ${PLAT_ARGS[@]+${PLAT_ARGS[@]+"${PLAT_ARGS[@]}"}}; }

# Expected tool counts. A server that starts but registers zero tools is broken
# in a way that "it started fine" will never surface.
EXPECT_S1_TOOLS=35
EXPECT_VT_TOOLS=11
EXPECT_PURPLE_TOOLS=33
EXPECT_SHODAN_TOOLS=11

PASS=0; FAIL=0; SKIP=0
if [ -t 1 ]; then G=$'\033[32m'; R=$'\033[31m'; Y=$'\033[33m'; Z=$'\033[0m'
else G=""; R=""; Y=""; Z=""; fi

ok()   { PASS=$((PASS+1)); printf "  ${G}PASS${Z} %-42s %s\n" "$1" "${2:-}"; }
bad()  { FAIL=$((FAIL+1)); printf "  ${R}FAIL${Z} %-42s %s\n" "$1" "${2:-}"; }
skip() { SKIP=$((SKIP+1)); printf "  ${Y}SKIP${Z} %-42s %s\n" "$1" "${2:-}"; }

# Run a command inside the image with a shell, capturing stdout.
inimg() { docker run --rm ${PLAT_ARGS[@]+"${PLAT_ARGS[@]}"} --entrypoint sh "$IMAGE" -c "$1" 2>/dev/null; }

# Drive a full MCP handshake and return the tool count on stdout.
# initialize -> notifications/initialized -> tools/list. The sleeps matter:
# purple-mcp imports a large dependency tree before it answers.
mcp_tool_count() {
  local server="$1"; shift
  { printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"smoke","version":"0.1"}}}'
    sleep 6
    printf '%s\n' '{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}'
    sleep 1
    printf '%s\n' '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'
    sleep 14
  } | docker run -i --rm ${PLAT_ARGS[@]+"${PLAT_ARGS[@]}"} "$@" \
        -e VT_API_KEY=dummy -e VIRUSTOTAL_API_KEY=dummy -e SHODAN_API_KEY=dummy \
        -e S1_CONSOLE_URL=https://example.invalid -e S1_CONSOLE_API_TOKEN=dummy \
        "$IMAGE" "$server" 2>/dev/null \
  | python3 -c '
import sys,json
n=""
for line in sys.stdin:
    line=line.strip()
    if not line.startswith("{"): continue
    try: m=json.loads(line)
    except Exception: continue
    if m.get("id")==2 and "result" in m:
        n=len(m["result"].get("tools",[]))
print(n)'
}

echo "SecOps Skills image smoke test"
echo "  image:    $IMAGE"
echo "  platform: ${PLATFORM:-<host default>}"
[ -n "$EXPECT_VERSION" ] && echo "  expecting image_version = $EXPECT_VERSION"
echo

# ── Availability ─────────────────────────────────────────────────────────────
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "  pulling $IMAGE ..."
  docker pull -q ${PLAT_ARGS[@]+"${PLAT_ARGS[@]}"} "$IMAGE" >/dev/null 2>&1 \
    || { bad "T01 image available" "cannot inspect or pull"; echo; echo "aborting"; exit 1; }
fi
ok "T01 image available"

# ── Dispatcher ───────────────────────────────────────────────────────────────
HELP="$(docker run --rm ${PLAT_ARGS[@]+"${PLAT_ARGS[@]}"} "$IMAGE" help 2>/dev/null)"
case "$HELP" in
  *s1-secops-mcp*purple-mcp*virustotal-mcp*shodan-mcp*) ok "T02 help lists all four servers" ;;
  *) bad "T02 help lists all four servers" "unexpected help output" ;;
esac

docker run --rm ${PLAT_ARGS[@]+"${PLAT_ARGS[@]}"} "$IMAGE" not-a-server >/dev/null 2>&1
[ $? -eq 64 ] && ok "T03 unknown command exits 64" || bad "T03 unknown command exits 64"

# ── The no-npm guarantee ─────────────────────────────────────────────────────
[ -z "$(inimg 'command -v npm')" ] && ok "T04 npm absent" || bad "T04 npm absent" "npm is present"
[ -z "$(inimg 'command -v npx')" ] && ok "T05 npx absent" || bad "T05 npx absent" "npx is present"
[ -z "$(inimg 'command -v git')" ] && ok "T06 git absent from runtime" || bad "T06 git absent from runtime" "git leaked from the fetch stage"
[ -z "$(inimg 'command -v corepack')" ] && ok "T06b corepack absent" || bad "T06b corepack absent" "corepack is present"

# ── Version manifest ─────────────────────────────────────────────────────────
VJSON="$(docker run --rm ${PLAT_ARGS[@]+"${PLAT_ARGS[@]}"} "$IMAGE" versions 2>/dev/null)"
VER="$(printf '%s' "$VJSON" | python3 -c 'import sys,json; print(json.load(sys.stdin)["image_version"])' 2>/dev/null)"
if [ -n "$VER" ]; then
  if [ -n "$EXPECT_VERSION" ] && [ "$VER" != "$EXPECT_VERSION" ]; then
    bad "T07 versions.json image_version" "got $VER, expected $EXPECT_VERSION"
  else
    ok "T07 versions.json image_version" "$VER"
  fi
else
  bad "T07 versions.json image_version" "missing or not valid JSON"
fi

NPMFLAG="$(printf '%s' "$VJSON" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("npm"))' 2>/dev/null)"
[ "$NPMFLAG" = "False" ] && ok "T08 versions.json declares npm:false" || bad "T08 versions.json declares npm:false" "got ${NPMFLAG:-<none>}"

# ── Secret hygiene ───────────────────────────────────────────────────────────
[ -z "$(inimg 'ls /opt/s1-secops-mcp/data 2>/dev/null')" ] \
  && ok "T09 no data/ dir (local exports)" \
  || bad "T09 no data/ dir (local exports)" "data/ reached the image"

# ── Runs unprivileged ────────────────────────────────────────────────────────
UID_OUT="$(inimg 'id -u')"
if [ "$UID_OUT" = "0" ]; then bad "T10 runs as non-root" "uid 0"
elif [ -n "$UID_OUT" ]; then ok "T10 runs as non-root" "uid $UID_OUT"
else bad "T10 runs as non-root" "could not read uid"; fi

HOME_OUT="$(inimg 'echo $HOME')"
if [ -n "$HOME_OUT" ] && [ -n "$(inimg "test -w '$HOME_OUT' && echo w")" ]; then
  ok "T11 HOME is writable" "$HOME_OUT"
else
  bad "T11 HOME is writable" "HOME=${HOME_OUT:-<unset>} not writable; caches will fail"
fi

# ── Every shipped file is readable by the runtime user ───────────────────────
# COPY preserves the source file mode, so a 0600 file in the repo becomes a
# 0600 file in the image. package.json shipped that way and Node >=24 refuses
# to start without reading it. Node 22 tolerated it, so this hid behind a base
# image for a while. Assert it directly instead of waiting for T12 to fail.
UNREADABLE="$(inimg 'find /opt/s1-secops-mcp /opt/mcp-virustotal /opt/mcp-shodan /opt/purple-mcp /etc/sentinelone /usr/local/bin/entrypoint.sh ! -readable 2>/dev/null | head -5')"
if [ -z "$UNREADABLE" ]; then
  ok "T11b all shipped files readable by runtime user"
else
  bad "T11b all shipped files readable by runtime user" "$(printf '%s' "$UNREADABLE" | tr '\n' ' ')"
fi

# ── The servers actually work ────────────────────────────────────────────────
TOOLS="$(mcp_tool_count s1-secops-mcp)"
[ "$TOOLS" = "$EXPECT_S1_TOOLS" ] && ok "T12 s1-secops-mcp tools/list" "$TOOLS tools" \
  || bad "T12 s1-secops-mcp tools/list" "got ${TOOLS:-none}, expected $EXPECT_S1_TOOLS"

TOOLS="$(mcp_tool_count virustotal-mcp)"
[ "$TOOLS" = "$EXPECT_VT_TOOLS" ] && ok "T13 virustotal-mcp tools/list" "$TOOLS tools" \
  || bad "T13 virustotal-mcp tools/list" "got ${TOOLS:-none}, expected $EXPECT_VT_TOOLS"

TOOLS="$(mcp_tool_count purple-mcp)"
[ "$TOOLS" = "$EXPECT_PURPLE_TOOLS" ] && ok "T14 purple-mcp tools/list" "$TOOLS tools" \
  || bad "T14 purple-mcp tools/list" "got ${TOOLS:-none}, expected $EXPECT_PURPLE_TOOLS"

# ── No runtime dependency on the source repo ─────────────────────────────────
TOOLS="$(mcp_tool_count s1-secops-mcp --network none)"
[ "$TOOLS" = "$EXPECT_S1_TOOLS" ] && ok "T15 works offline (--network none)" "$TOOLS tools" \
  || bad "T15 works offline (--network none)" "got ${TOOLS:-none}; something fetches at runtime"

# ── Persona file, readable BY THE UNPRIVILEGED USER ──────────────────────────
# `test -s` is not enough. Under USER node the file must be world-readable, and
# a root-owned 0600 file would pass a size check and then fail at runtime. Read
# it the way the server does and require real bytes back.
CLAUDE_PATH="$(inimg 'echo ${S1_CLAUDE_MD_PATH:-/etc/sentinelone/CLAUDE.md}')"
CLAUDE_BYTES="$(inimg "cat '$CLAUDE_PATH' 2>/dev/null | wc -c" | tr -d ' ')"
CLAUDE_PERMS="$(inimg "stat -c '%U:%G %a' '$CLAUDE_PATH' 2>/dev/null")"
if [ -n "$CLAUDE_BYTES" ] && [ "$CLAUDE_BYTES" -gt 100 ] 2>/dev/null; then
  ok "T16 CLAUDE.md readable as $(inimg 'id -un')" "${CLAUDE_BYTES} bytes, ${CLAUDE_PERMS}"
else
  bad "T16 CLAUDE.md readable as $(inimg 'id -un')" "read ${CLAUDE_BYTES:-0} bytes from $CLAUDE_PATH (${CLAUDE_PERMS:-no stat})"
fi

# End-to-end: the server exposes CLAUDE.md as an MCP resource. This is the check
# that matters, because it exercises the same read path a real client uses
# rather than a shell reading a file that happens to sit at that path.
RES_LEN="$( { printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"smoke","version":"0.1"}}}'
    sleep 5
    printf '%s\n' '{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}'
    sleep 1
    printf '%s\n' '{"jsonrpc":"2.0","id":3,"method":"resources/read","params":{"uri":"sentinelone://soc-context"}}'
    sleep 10
  } | docker run -i --rm ${PLAT_ARGS[@]+"${PLAT_ARGS[@]}"} \
        -e S1_CONSOLE_URL=https://example.invalid -e S1_CONSOLE_API_TOKEN=dummy \
        "$IMAGE" s1-secops-mcp 2>/dev/null \
  | python3 -c '
import sys,json
out=0
for line in sys.stdin:
    line=line.strip()
    if not line.startswith("{"): continue
    try: m=json.loads(line)
    except Exception: continue
    if m.get("id")==3 and "result" in m:
        for c in m["result"].get("contents",[]):
            out=max(out,len(c.get("text","") or ""))
print(out)')"
if [ -n "$RES_LEN" ] && [ "$RES_LEN" -gt 100 ] 2>/dev/null; then
  ok "T16b CLAUDE.md served as MCP resource" "${RES_LEN} chars via sentinelone://soc-context"
else
  bad "T16b CLAUDE.md served as MCP resource" "got ${RES_LEN:-0} chars; the persona would be silently empty"
fi

# ── Secrets over stdin (1.5.0): configured, and absent from docker inspect ───
# The launcher sends NAME=value lines then an empty line before the JSON-RPC
# stream. The server must see the values; `docker inspect` must not.
STDIN_TOKEN="FAKEsmoke$(date +%s)abcdef0123456789"
CNAME="s1smoke-stdin-$$"
STATUS_OUT="$( { printf 'S1_CONSOLE_URL=https://example.invalid\nS1_CONSOLE_API_TOKEN=%s\nBOGUS=1\n\n' "$STDIN_TOKEN"
    printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"smoke","version":"0.1"}}}'
    printf '%s\n' '{"jsonrpc":"2.0","id":4,"method":"resources/read","params":{"uri":"sentinelone://credentials-status"}}'
    sleep 4
  } | docker run -i --rm --name "$CNAME" ${PLAT_ARGS[@]+"${PLAT_ARGS[@]}"} -e S1_SECRETS_STDIN=1 "$IMAGE" s1-secops-mcp 2>/dev/null &
  sleep 2
  docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$CNAME" 2>/dev/null | grep -c "$STDIN_TOKEN" > "/tmp/s1smoke-inspect-$$" || true
  wait )"
INSPECT_HITS="$(cat "/tmp/s1smoke-inspect-$$" 2>/dev/null || echo err)"; rm -f "/tmp/s1smoke-inspect-$$"
if printf '%s' "$STATUS_OUT" | grep -q '\\"configured\\": true'; then
  ok "T18 S1_SECRETS_STDIN configures the server"
else
  bad "T18 S1_SECRETS_STDIN configures the server" "credentials-status did not report configured"
fi
[ "$INSPECT_HITS" = "0" ] && ok "T19 stdin secrets absent from docker inspect" \
  || bad "T19 stdin secrets absent from docker inspect" "inspect hits: $INSPECT_HITS"
printf '%s' "$STATUS_OUT" | grep -q "$STDIN_TOKEN" \
  && bad "T19b token never echoed on stdout" "token found in server output" \
  || ok "T19b token never echoed on stdout"

# ── stdio only (1.5.0): the HTTP transport must refuse to start ─────────────
HTTP_RC=0
docker run --rm ${PLAT_ARGS[@]+"${PLAT_ARGS[@]}"} "$IMAGE" s1-secops-mcp --transport http >/dev/null 2>&1 || HTTP_RC=$?
[ "$HTTP_RC" = "2" ] && ok "T20 --transport http refused" "exit 2" || bad "T20 --transport http refused" "exit $HTTP_RC"

# ── shodan-mcp (1.5.4, optional) ─────────────────────────────────────────────
TOOLS="$(mcp_tool_count shodan-mcp)"
[ "$TOOLS" = "$EXPECT_SHODAN_TOOLS" ] && ok "T22 shodan-mcp tools/list" "$TOOLS tools" \
  || bad "T22 shodan-mcp tools/list" "got ${TOOLS:-none}, expected $EXPECT_SHODAN_TOOLS"

# Upstream starts an unauthenticated HTTP listener on MCP_TRANSPORT=httpStream
# (its own Dockerfile binds 0.0.0.0). The entrypoint must drop those knobs, so
# the same server still answers tools/list on stdio.
TOOLS="$(mcp_tool_count shodan-mcp -e MCP_TRANSPORT=httpStream -e MCP_HOST=0.0.0.0 -e MCP_PORT=3000)"
[ "$TOOLS" = "$EXPECT_SHODAN_TOOLS" ] && ok "T23 shodan-mcp ignores MCP_TRANSPORT=httpStream" "stdio, $TOOLS tools" \
  || bad "T23 shodan-mcp ignores MCP_TRANSPORT=httpStream" "got ${TOOLS:-none} tools on stdio"

# Optional server: no key means one clear line and exit 78, not a stack trace.
NOKEY_ERR="$(docker run --rm ${PLAT_ARGS[@]+"${PLAT_ARGS[@]}"} "$IMAGE" shodan-mcp 2>&1 </dev/null)"; NOKEY_RC=$?
if [ "$NOKEY_RC" = "78" ] && printf '%s' "$NOKEY_ERR" | grep -q 'SHODAN_API_KEY is not set'; then
  ok "T24 shodan-mcp without a key exits 78 with a hint"
else
  bad "T24 shodan-mcp without a key exits 78 with a hint" "rc $NOKEY_RC: $(printf '%s' "$NOKEY_ERR" | head -1)"
fi

SHODAN_JUNK="$(inimg 'cd /opt/mcp-shodan && for p in .git .env src tests node_modules/dotenv node_modules/pipenet node_modules/koa node_modules/mcp-proxy/dist/bin; do [ -e "$p" ] && echo "$p"; done; [ -f FORK_NOTES.md ] || echo "missing:FORK_NOTES.md"; [ -f build/index.js ] || echo "missing:build/index.js"')"
[ -z "$SHODAN_JUNK" ] && ok "T25 /opt/mcp-shodan clean (no .git/.env/src, tunnel code stripped)" \
  || bad "T25 /opt/mcp-shodan clean" "$(printf '%s' "$SHODAN_JUNK" | tr '\n' ' ')"

# The Shodan key must reach shodan-mcp only. Run the real dispatcher with its
# final exec swapped for `env`, for a server that must NOT see the key.
LEAKS=0
for srv in s1-secops-mcp virustotal-mcp purple-mcp; do
  n="$(docker run --rm ${PLAT_ARGS[@]+"${PLAT_ARGS[@]}"} -e SHODAN_API_KEY=smokeleakcheck0123456789 --entrypoint /bin/sh "$IMAGE" \
        -c 'sed -e "s#^\( *\)exec node .*#\1exec env#" -e "s#^\( *\)exec purple-mcp-bin.*#\1exec env#" /usr/local/bin/entrypoint.sh > /tmp/e.sh && sh /tmp/e.sh '"$srv" 2>/dev/null \
        | grep -c '^SHODAN_API_KEY=')"
  [ "${n:-0}" = "0" ] || LEAKS=$((LEAKS+1))
done
SEEN="$(docker run --rm ${PLAT_ARGS[@]+"${PLAT_ARGS[@]}"} -e SHODAN_API_KEY=smokeleakcheck0123456789 -e VT_API_KEY=vtsmoke --entrypoint /bin/sh "$IMAGE" \
        -c 'sed -e "s#^\( *\)exec node .*#\1exec env#" /usr/local/bin/entrypoint.sh > /tmp/e.sh && sh /tmp/e.sh shodan-mcp' 2>/dev/null)"
if [ "$LEAKS" = "0" ] && printf '%s' "$SEEN" | grep -q '^SHODAN_API_KEY=' && ! printf '%s' "$SEEN" | grep -q '^VT_API_KEY='; then
  ok "T26 Shodan key reaches shodan-mcp only (and shodan-mcp gets no VT key)"
else
  bad "T26 Shodan key isolation" "leaks into $LEAKS other server(s), or shodan-mcp env wrong"
fi

VCHK="$(printf '%s' "$VJSON" | python3 -c '
import sys, json, re
d = json.load(sys.stdin); s = d.get("servers", {}).get("shodan-mcp", {})
ok = re.fullmatch(r"[0-9a-f]{40}", s.get("ref", "")) and str(d.get("node", "")).startswith("v24.")
print("ok" if ok else "ref=%s node=%s" % (s.get("ref"), d.get("node")))' 2>/dev/null)"
[ "$VCHK" = "ok" ] && ok "T27 versions.json: shodan-mcp pinned by SHA, node v24" \
  || bad "T27 versions.json: shodan-mcp pin and node" "${VCHK:-unparseable}"

# ── Unused Debian packages removed (1.5.4) ───────────────────────────────────
# Each carried a HIGH CVE with no trixie fix and nothing here loads it. A base
# image bump that brings one back would silently re-add the findings.
LEFT="$(inimg 'for p in apt libapt-pkg7.0 login mount util-linux bsdutils libmount1 libblkid1 libsmartcols1 liblastlog2-2 perl-base libsystemd0 libudev1; do dpkg-query -W -f="\${Status}" "$p" 2>/dev/null | grep -q "install ok installed" && echo "$p"; done')"
[ -z "$LEFT" ] && ok "T28 unused vulnerable packages removed" \
  || bad "T28 unused vulnerable packages removed" "still installed: $(printf '%s' "$LEFT" | tr '\n' ' ')"
# ── outputFile under Docker (1.5.4) ──────────────────────────────────────────
# T3/T4 of output-dir-changes.md: with no shared folder a write to the
# container's /tmp reported success and vanished with the container, and a
# host path got "Set S1_OUTPUT_DIRS", which does nothing under Docker. Drive
# s1_api_get over stdio: path validation runs before any network call, so an
# unreachable console is fine. T31: with a shared folder the write lands.
of_call() { # $1 outputFile, rest: extra docker args. Prints the tools/call reply line.
  of="$1"; shift
  { printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"smoke","version":"0.1"}}}'
    sleep 3
    printf '%s\n' '{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}'
    printf '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"s1_api_get","arguments":{"path":"/web/api/v2.1/system/status","outputFile":"%s"}}}\n' "$of"
    sleep 6
  } | docker run -i --rm ${PLAT_ARGS[@]+"${PLAT_ARGS[@]}"} -e S1_CONSOLE_URL=https://example.invalid -e S1_CONSOLE_API_TOKEN=dummy "$@" "$IMAGE" s1-secops-mcp 2>/dev/null \
  | grep '"id":5'
}
R30="$(of_call /tmp/inside-container.json)"
if printf '%s' "$R30" | grep -q '"isError":true' && printf '%s' "$R30" | grep -q 'install --output-dir' \
   && ! printf '%s' "$R30" | grep -q 'Set S1_OUTPUT_DIRS to allow'; then
  ok "T30 no shared folder: outputFile refused with install --output-dir advice"
else
  bad "T30 no shared folder: outputFile refused with install --output-dir advice" "$(printf '%s' "$R30" | cut -c1-200)"
fi
SHARED="$(mktemp -d "${TMPDIR:-/tmp}/s1smoke-out.XXXXXX")"; chmod 777 "$SHARED"
R31="$(of_call "$SHARED/r.json" -v "$SHARED:$SHARED" -e "S1_OUTPUT_DIRS=$SHARED")"
# example.invalid cannot answer, so the API call fails AFTER validation; the
# point is that the path is accepted (no refusal text), not that bytes land.
if printf '%s' "$R31" | grep -q 'id":5' && ! printf '%s' "$R31" | grep -q -E 'no output folder is shared|outside the folder shared'; then
  ok "T31 shared folder: outputFile path accepted"
else
  bad "T31 shared folder: outputFile path accepted" "$(printf '%s' "$R31" | cut -c1-200)"
fi
rm -rf "$SHARED"

EXPAT_V="$(inimg "dpkg-query -W -f='\${Version}' libexpat1")"
[ "$EXPAT_V" = "2.9.0-1" ] && ok "T29 libexpat1 2.9.0-1 (fixes 5 HIGH)" \
  || bad "T29 libexpat1 version" "got ${EXPAT_V:-none}"

# ── No keychain inside the container; no file discovery either ──────────────
KC="$(inimg 'echo ${S1_KEYCHAIN:-unset}')"
[ "$KC" = "off" ] && ok "T21 S1_KEYCHAIN=off baked in" || bad "T21 S1_KEYCHAIN=off baked in" "got $KC"

# ── Registry health: children must resolve, not just the tag ─────────────────
# A manifest list can return 200 while every platform manifest under it 404s.
# That shipped once and looked healthy from the tag alone.
case "$IMAGE" in
  *:*/*|*/*:*)
    if command -v skopeo >/dev/null 2>&1; then
      RAW="$(skopeo inspect --raw "docker://$IMAGE" 2>/dev/null)"
      # No f-strings here, deliberately. This block used escaped quotes inside an
      # f-string, which is a SyntaxError on Python < 3.12. Combined with the
      # 2>/dev/null below it failed silently and reported as a benign SKIP, so the
      # one test that exists to catch "manifest list 200 but children 404" was
      # skipping on the release machine (python 3.9). Keep it backslash-free.
      ARCHES="$(printf '%s' "$RAW" | python3 -c '
import sys, json
try:
    d = json.load(sys.stdin)
except Exception:
    raise SystemExit
ms = d.get("manifests")
if not ms:
    print("single")
else:
    out = []
    for m in ms:
        pl = m.get("platform", {})
        if pl.get("architecture") != "unknown":
            out.append(str(pl.get("os")) + "/" + str(pl.get("architecture")))
    print(",".join(out))' 2>/dev/null)"
      # A registry ref we cannot verify is a failure, not a skip. Skipping here
      # is indistinguishable from passing, which is how the bug above hid.
      if [ -n "$ARCHES" ]; then ok "T17 registry manifest readable" "$ARCHES"
      else bad "T17 registry manifest readable" "skopeo returned nothing or output unparseable"; fi
    else
      skip "T17 registry manifest readable" "skopeo not installed"
    fi ;;
  *) skip "T17 registry manifest readable" "local image reference" ;;
esac

echo
printf "  %s%d passed%s, %s%d failed%s, %d skipped\n" "$G" "$PASS" "$Z" "$R" "$FAIL" "$Z" "$SKIP"
[ "$FAIL" -eq 0 ] && echo "  ${G}image looks good${Z}" || echo "  ${R}image is NOT releasable${Z}"
exit "$FAIL"
