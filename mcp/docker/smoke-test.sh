#!/usr/bin/env bash
#
# smoke-test.sh -- validate a SentinelOne SecOps MCP image.
#
# Usage:
#   docker/smoke-test.sh <image-ref> [--expect-version X.Y.Z] [--platform P]
#
# Examples:
#   docker/smoke-test.sh sentinelone/secops-mcps:1.6.0 --expect-version 1.6.0
#   docker/smoke-test.sh sentinelone/secops-mcps:1.6.0 --platform linux/amd64
#
# Exit code is the number of failed tests, so `if docker/smoke-test.sh IMG` works
# as a gate in CI or a release checklist.
#
# ── What these tests assert ──────────────────────────────────────────────────
#
# The 1.6.0 image is distroless: no shell. In-image checks therefore run Node
# (`--entrypoint /nodejs/bin/node`), never sh.
#
#   T02-T03  help and the unknown-command exit code.
#   T04-T06  The image claims no shell, no npm/npx/corepack and no package
#            manager; assert it rather than trust it.
#   T07-T08  versions.json: image_version (it once reported the MCP version),
#            one server only, shell:false, npm:false, Node 24.
#   T09      s1-secops-mcp/data/ (local exports) and removed servers never ship.
#   T10-T11  Runs unprivileged; every shipped file is readable by that user.
#   T12-T13  tools/list: 36 tools with no threat-intel keys, 40 with both keys.
#   T14      Nothing phones home at runtime (--network none).
#   T15-T16  CLAUDE.md ships and is served as an MCP resource.
#   T18-T19  The stdin secrets preamble configures the server, never appears in
#            `docker inspect` or on stdout; a stream that starts with JSON-RPC
#            is refused (exit 64).
#   T20      --transport http is refused.
#   T21      S1_KEYCHAIN=off is baked in.
#   T22      Removed server names (purple-mcp, virustotal-mcp, shodan-mcp) exit
#            78 with the update instruction.
#   T23      SIGTERM stops the container promptly (no init in the image).
#   T30-T31  outputFile: refused with `install --output-dir` advice when no folder
#            is shared; accepted when one is.
#   T32-T34  Read-only by default: a write tool and a savelookup query are
#            refused with no network; S1_READ_ONLY=false lifts it.
#   T35-T36  Third-party notices and the AGPL LICENSE ship in the image.
#   T37      An s1_api_post path with a fragment is refused in read-only mode.
#   T17      Registry manifest readable (remote references only).
#
# No pipefail: checks use `printf "$OUT" | grep -q`, and grep -q exits at the first
# match, so a large capture (tools/list is ~80 KB) would SIGPIPE printf and fail
# the pipeline even though the pattern was found.
set -u

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
  sed -n '3,11p' "$0" | sed 's/^# \{0,1\}//'
  exit 64
fi

PLAT_ARGS=()
[ -n "$PLATFORM" ] && PLAT_ARGS=(--platform "$PLATFORM")

EXPECT_TOOLS_NOKEYS=36
EXPECT_TOOLS_KEYS=40

PASS=0; FAIL=0; SKIP=0
if [ -t 1 ]; then G=$'\033[32m'; R=$'\033[31m'; Y=$'\033[33m'; Z=$'\033[0m'
else G=""; R=""; Y=""; Z=""; fi

ok()   { PASS=$((PASS+1)); printf "  ${G}PASS${Z} %-46s %s\n" "$1" "${2:-}"; }
bad()  { FAIL=$((FAIL+1)); printf "  ${R}FAIL${Z} %-46s %s\n" "$1" "${2:-}"; }
skip() { SKIP=$((SKIP+1)); printf "  ${Y}SKIP${Z} %-46s %s\n" "$1" "${2:-}"; }

drun() { docker run --rm ${PLAT_ARGS[@]+"${PLAT_ARGS[@]}"} "$@"; }
# Run JavaScript inside the image as its runtime user (there is no shell).
innode() { drun --entrypoint /nodejs/bin/node "$IMAGE" -e "$1" 2>/dev/null; }
# JSON field from stdin, with python3 on the host.
jget() { python3 -c 'import sys,json
d=json.load(sys.stdin)
for k in sys.argv[1].split("."): d=d.get(k) if isinstance(d,dict) else None
print(json.dumps(d) if isinstance(d,(dict,list,bool)) or d is None else d)' "$1" 2>/dev/null; }

INIT='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"smoke","version":"0.1"}}}'
INITED='{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}'

# initialize -> initialized -> tools/list, return the tool count. Extra args go to docker run.
mcp_tool_count() {
  { printf '%s\n' "$INIT"; sleep 2; printf '%s\n' "$INITED"
    printf '%s\n' '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'; sleep 3
  } | drun -i "$@" -e S1_CONSOLE_URL=https://example.invalid -e S1_CONSOLE_API_TOKEN=dummy "$IMAGE" s1-secops-mcp 2>/dev/null \
  | python3 -c '
import sys,json
n=""
for line in sys.stdin:
    line=line.strip()
    if not line.startswith("{"): continue
    try: m=json.loads(line)
    except Exception: continue
    if m.get("id")==2 and "result" in m: n=len(m["result"].get("tools",[]))
print(n)'
}

echo "SecOps MCP image smoke test"
echo "  image:    $IMAGE"
echo "  platform: ${PLATFORM:-<host default>}"
[ -n "$EXPECT_VERSION" ] && echo "  expecting image_version = $EXPECT_VERSION"
echo

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "  pulling $IMAGE ..."
  docker pull -q ${PLAT_ARGS[@]+"${PLAT_ARGS[@]}"} "$IMAGE" >/dev/null 2>&1 \
    || { bad "T01 image available" "cannot inspect or pull"; echo; echo "aborting"; exit 1; }
fi
ok "T01 image available"

HELP="$(drun "$IMAGE" help 2>/dev/null)"
case "$HELP" in
  *s1-secops-mcp*purple_ai_query*ti_vt_*ti_shodan_*) ok "T02 help describes the server and built-in tools" ;;
  *) bad "T02 help describes the server and built-in tools" "unexpected help output" ;;
esac

drun "$IMAGE" not-a-server >/dev/null 2>&1
[ $? -eq 64 ] && ok "T03 unknown command exits 64" || bad "T03 unknown command exits 64"

SHELLS="$(innode 'const fs=require("fs");console.log(["/bin/sh","/bin/bash","/bin/dash","/bin/busybox","/usr/bin/sh"].filter(p=>fs.existsSync(p)).join(" "))')"
[ -z "$SHELLS" ] && ok "T04 no shell in the image" || bad "T04 no shell in the image" "found: $SHELLS"
NPM="$(innode 'const fs=require("fs");console.log(["/nodejs/bin/npm","/nodejs/bin/npx","/nodejs/bin/corepack","/usr/local/bin/npm","/usr/local/bin/npx","/nodejs/lib/node_modules/npm"].filter(p=>fs.existsSync(p)).join(" "))')"
[ -z "$NPM" ] && ok "T05 no npm, npx or corepack" || bad "T05 no npm, npx or corepack" "found: $NPM"
PKGM="$(innode 'const fs=require("fs");console.log(["/usr/bin/apt","/usr/bin/apt-get","/usr/bin/dpkg","/sbin/apk","/usr/bin/python3","/usr/bin/git"].filter(p=>fs.existsSync(p)).join(" "))')"
[ -z "$PKGM" ] && ok "T06 no package manager, Python or git" || bad "T06 no package manager, Python or git" "found: $PKGM"

VJSON="$(drun "$IMAGE" versions 2>/dev/null)"
VER="$(printf '%s' "$VJSON" | jget image_version)"
if [ -n "$VER" ] && [ "$VER" != "None" ]; then
  if [ -n "$EXPECT_VERSION" ] && [ "$VER" != "$EXPECT_VERSION" ]; then
    bad "T07 versions.json image_version" "got $VER, expected $EXPECT_VERSION"
  else ok "T07 versions.json image_version" "$VER"; fi
else bad "T07 versions.json image_version" "missing or not valid JSON"; fi
VCHK="$(printf '%s' "$VJSON" | python3 -c '
import sys,json
d=json.load(sys.stdin)
probs=[]
if list(d.get("servers",{}))!=["s1-secops-mcp"]: probs.append("servers=%s"%list(d.get("servers",{})))
if d.get("shell") is not False: probs.append("shell")
if d.get("npm") is not False: probs.append("npm")
if not str(d.get("node","")).startswith("v24."): probs.append("node=%s"%d.get("node"))
print("ok" if not probs else " ".join(probs))' 2>/dev/null)"
[ "$VCHK" = "ok" ] && ok "T08 versions.json: one server, no shell/npm, Node 24" || bad "T08 versions.json contents" "${VCHK:-unparseable}"

GONE="$(innode 'const fs=require("fs");console.log(["/opt/s1-secops-mcp/data","/opt/mcp-virustotal","/opt/mcp-shodan","/opt/purple-mcp","/usr/local/bin/entrypoint.sh"].filter(p=>fs.existsSync(p)).join(" "))')"
[ -z "$GONE" ] && ok "T09 no data/ dir, no removed servers" || bad "T09 no data/ dir, no removed servers" "present: $GONE"

UIDS="$(innode 'console.log(process.getuid()+":"+process.getgid())')"
case "$UIDS" in 0:*|"") bad "T10 runs as non-root" "uid:gid ${UIDS:-unknown}" ;; *) ok "T10 runs as non-root" "uid:gid $UIDS" ;; esac
UNREAD="$(innode 'const fs=require("fs"),p=require("path");const bad=[];
function w(x){let s;try{s=fs.statSync(x)}catch{return}
 try{fs.accessSync(x,fs.constants.R_OK)}catch{bad.push(x)}
 if(s.isDirectory())for(const e of fs.readdirSync(x))w(p.join(x,e))}
for(const r of ["/opt/s1-secops-mcp","/etc/sentinelone","/usr/local/lib/s1-secops","/usr/share/doc/secops-mcps"])w(r);
console.log(bad.slice(0,5).join(" "))')"
[ -z "$UNREAD" ] && ok "T11 all shipped files readable by runtime user" || bad "T11 all shipped files readable" "$UNREAD"

TOOLS="$(mcp_tool_count)"
[ "$TOOLS" = "$EXPECT_TOOLS_NOKEYS" ] && ok "T12 tools/list without threat-intel keys" "$TOOLS tools" \
  || bad "T12 tools/list without threat-intel keys" "got ${TOOLS:-none}, expected $EXPECT_TOOLS_NOKEYS"
TOOLS="$(mcp_tool_count -e VIRUSTOTAL_API_KEY=dummy-vt-key-0123456789 -e SHODAN_API_KEY=dummy-shodan-0123456789)"
[ "$TOOLS" = "$EXPECT_TOOLS_KEYS" ] && ok "T13 tools/list with VirusTotal and Shodan keys" "$TOOLS tools" \
  || bad "T13 tools/list with VirusTotal and Shodan keys" "got ${TOOLS:-none}, expected $EXPECT_TOOLS_KEYS"
TOOLS="$(mcp_tool_count --network none)"
[ "$TOOLS" = "$EXPECT_TOOLS_NOKEYS" ] && ok "T14 works offline (--network none)" "$TOOLS tools" \
  || bad "T14 works offline (--network none)" "got ${TOOLS:-none}; something fetches at runtime"

CLAUDE_BYTES="$(innode 'console.log(require("fs").readFileSync(process.env.S1_CLAUDE_MD_PATH||"/etc/sentinelone/CLAUDE.md").length)')"
[ "${CLAUDE_BYTES:-0}" -gt 100 ] 2>/dev/null && ok "T15 CLAUDE.md readable" "${CLAUDE_BYTES} bytes" \
  || bad "T15 CLAUDE.md readable" "read ${CLAUDE_BYTES:-0} bytes"
RES_LEN="$( { printf '%s\n' "$INIT"; sleep 2; printf '%s\n' "$INITED"
    printf '%s\n' '{"jsonrpc":"2.0","id":3,"method":"resources/read","params":{"uri":"sentinelone://soc-context"}}'; sleep 3
  } | drun -i -e S1_CONSOLE_URL=https://example.invalid -e S1_CONSOLE_API_TOKEN=dummy "$IMAGE" s1-secops-mcp 2>/dev/null \
  | python3 -c '
import sys,json
out=0
for line in sys.stdin:
    line=line.strip()
    if not line.startswith("{"): continue
    try: m=json.loads(line)
    except Exception: continue
    if m.get("id")==3 and "result" in m:
        for c in m["result"].get("contents",[]): out=max(out,len(c.get("text","") or ""))
print(out)')"
[ "${RES_LEN:-0}" -gt 100 ] 2>/dev/null && ok "T16 CLAUDE.md served as MCP resource" "${RES_LEN} chars" \
  || bad "T16 CLAUDE.md served as MCP resource" "got ${RES_LEN:-0} chars"

# Secrets over stdin, exactly as the host launcher sends them.
STDIN_TOKEN="FAKEsmoke$(date +%s)abcdef0123456789"
VT_FAKE="vtsmoke$(date +%s)0123456789abcdef"
CNAME="s1smoke-stdin-$$"
STATUS_OUT="$( { printf 'S1_CONSOLE_URL=https://example.invalid\nS1_CONSOLE_API_TOKEN=%s\nVIRUSTOTAL_API_KEY=%s\nBOGUS=1\n\n' "$STDIN_TOKEN" "$VT_FAKE"
    printf '%s\n' "$INIT"
    printf '%s\n' '{"jsonrpc":"2.0","id":4,"method":"resources/read","params":{"uri":"sentinelone://credentials-status"}}'
    printf '%s\n' '{"jsonrpc":"2.0","id":6,"method":"tools/list","params":{}}'
    sleep 4
  } | docker run -i --rm --name "$CNAME" ${PLAT_ARGS[@]+"${PLAT_ARGS[@]}"} -e S1_SECRETS_STDIN=1 "$IMAGE" s1-secops-mcp 2>/dev/null &
  sleep 2
  docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$CNAME" 2>/dev/null | grep -c -e "$STDIN_TOKEN" -e "$VT_FAKE" > "/tmp/s1smoke-inspect-$$" || true
  wait )"
INSPECT_HITS="$(cat "/tmp/s1smoke-inspect-$$" 2>/dev/null || echo err)"; rm -f "/tmp/s1smoke-inspect-$$"
if printf '%s' "$STATUS_OUT" | grep -q '\\"configured\\": true' && printf '%s' "$STATUS_OUT" | grep -q '"ti_vt_lookup"'; then
  ok "T18 stdin preamble configures the server (incl. VT tools)"
else
  bad "T18 stdin preamble configures the server" "credentials-status/tools/list did not reflect the preamble"
fi
[ "$INSPECT_HITS" = "0" ] && ok "T19 stdin secrets absent from docker inspect" || bad "T19 stdin secrets absent from docker inspect" "inspect hits: $INSPECT_HITS"
if printf '%s' "$STATUS_OUT" | grep -q -e "$STDIN_TOKEN" -e "$VT_FAKE"; then bad "T19b secrets never echoed on stdout" "found in server output"
else ok "T19b secrets never echoed on stdout"; fi
JRC=0; printf '%s\n' "$INIT" | drun -i -e S1_SECRETS_STDIN=1 "$IMAGE" s1-secops-mcp >/dev/null 2>&1 || JRC=$?
[ "$JRC" = "64" ] && ok "T19c preamble expected but JSON-RPC first: exit 64" || bad "T19c preamble expected but JSON-RPC first" "exit $JRC"

HTTP_RC=0; drun "$IMAGE" s1-secops-mcp --transport http >/dev/null 2>&1 || HTTP_RC=$?
[ "$HTTP_RC" = "2" ] && ok "T20 --transport http refused" "exit 2" || bad "T20 --transport http refused" "exit $HTTP_RC"

KC="$(innode 'console.log(process.env.S1_KEYCHAIN||"unset")')"
[ "$KC" = "off" ] && ok "T21 S1_KEYCHAIN=off baked in" || bad "T21 S1_KEYCHAIN=off baked in" "got $KC"

LEG_FAIL=""
for srv in purple-mcp virustotal-mcp shodan-mcp; do
  out="$(drun "$IMAGE" "$srv" 2>&1 </dev/null)"; rc=$?
  { [ "$rc" = "78" ] && printf '%s' "$out" | grep -q 'removed from this image in 1.6.0'; } || LEG_FAIL="$LEG_FAIL $srv:rc$rc"
done
[ -z "$LEG_FAIL" ] && ok "T22 removed server names exit 78 with instructions" || bad "T22 removed server names" "$LEG_FAIL"

SNAME="s1smoke-sig-$$"
docker run -d -i --rm --name "$SNAME" ${PLAT_ARGS[@]+"${PLAT_ARGS[@]}"} "$IMAGE" s1-secops-mcp >/dev/null 2>&1
sleep 2
T0=$(date +%s); docker stop -t 10 "$SNAME" >/dev/null 2>&1; T1=$(date +%s)
[ $((T1 - T0)) -lt 5 ] && ok "T23 SIGTERM stops the server promptly" "$((T1 - T0)) s" || bad "T23 SIGTERM stops the server promptly" "$((T1 - T0)) s (signal ignored?)"

of_call() { # $1 outputFile, rest: extra docker args. Prints the tools/call reply line.
  of="$1"; shift
  { printf '%s\n' "$INIT"; sleep 2; printf '%s\n' "$INITED"
    printf '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"s1_api_get","arguments":{"path":"/web/api/v2.1/system/status","outputFile":"%s"}}}\n' "$of"
    sleep 5
  } | drun -i -e S1_CONSOLE_URL=https://example.invalid -e S1_CONSOLE_API_TOKEN=dummy "$@" "$IMAGE" s1-secops-mcp 2>/dev/null \
  | grep '"id":5'
}
R30="$(of_call /tmp/inside-container.json)"
if printf '%s' "$R30" | grep -q '"isError":true' && printf '%s' "$R30" | grep -q 'install --output-dir'; then
  ok "T30 no shared folder: outputFile refused with advice"
else bad "T30 no shared folder: outputFile refused with advice" "$(printf '%s' "$R30" | cut -c1-200)"; fi
SHARED="$(mktemp -d "${TMPDIR:-/tmp}/s1smoke-out.XXXXXX")"; chmod 777 "$SHARED"
R31="$(of_call "$SHARED/r.json" -v "$SHARED:$SHARED" -e "S1_OUTPUT_DIRS=$SHARED")"
if printf '%s' "$R31" | grep -q 'id":5' && ! printf '%s' "$R31" | grep -q -E 'no output folder is shared|outside the folder shared'; then
  ok "T31 shared folder: outputFile path accepted"
else bad "T31 shared folder: outputFile path accepted" "$(printf '%s' "$R31" | cut -c1-200)"; fi
rm -rf "$SHARED"

mcp_call() { # $1 tool, $2 arguments JSON, rest: extra docker args. Prints the id 5 reply.
  t="$1"; a="$2"; shift 2
  { printf '%s\n' "$INIT"; sleep 2; printf '%s\n' "$INITED"
    printf '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"%s","arguments":%s}}\n' "$t" "$a"
    sleep 4
  } | drun -i --network none -e S1_CONSOLE_URL=https://example.invalid -e S1_CONSOLE_API_TOKEN=dummy "$@" "$IMAGE" s1-secops-mcp 2>/dev/null \
  | grep '"id":5'
}
R32="$(mcp_call sdl_delete_dashboard '{"id":"smoke-1"}')"
if printf '%s' "$R32" | grep -q '"isError":true' && printf '%s' "$R32" | grep -q 'read-only mode (S1_READ_ONLY)' && printf '%s' "$R32" | grep -q 'install --read-write'; then
  ok "T32 default: write tool refused, with how-to"
else bad "T32 default: write tool refused, with how-to" "$(printf '%s' "$R32" | cut -c1-200)"; fi
R33="$(mcp_call sdl_delete_dashboard '{"id":"smoke-1"}' -e S1_READ_ONLY=false)"
if printf '%s' "$R33" | grep -q 'id":5' && ! printf '%s' "$R33" | grep -q 'read-only mode'; then
  ok "T33 S1_READ_ONLY=false: write tool reaches its handler"
else bad "T33 S1_READ_ONLY=false: write tool reaches its handler" "$(printf '%s' "$R33" | cut -c1-200)"; fi
R34="$(mcp_call powerquery_run '{"query":"dataSource.name=* | savelookup \"smoke\""}')"
if printf '%s' "$R34" | grep -q '"isError":true' && printf '%s' "$R34" | grep -q 'read-only mode'; then
  ok "T34 default: PowerQuery savelookup refused"
else bad "T34 default: PowerQuery savelookup refused" "$(printf '%s' "$R34" | cut -c1-200)"; fi

NOTICES="$(drun "$IMAGE" notices 2>/dev/null)"
if printf '%s' "$NOTICES" | grep -q 'Third-Party Notices' && printf '%s' "$NOTICES" | grep -q 'VirusTotal' && printf '%s' "$NOTICES" | grep -q 'Shodan'; then
  ok "T35 notices command prints the third-party notices"
else bad "T35 notices command prints the third-party notices" "$(printf '%s' "$NOTICES" | head -3)"; fi
LIC="$(innode 'const fs=require("fs");const l=fs.readFileSync("/opt/s1-secops-mcp/LICENSE","utf8");console.log(l.includes("GNU AFFERO")?"":"not AGPL")')"
[ -z "$LIC" ] && ok "T36 AGPL LICENSE present and readable" || bad "T36 AGPL LICENSE present and readable" "$LIC"

R37="$(mcp_call s1_api_post '{"path":"/web/api/v2.1/agents/actions/disconnect#/dv/init-query","body":{}}')"
if printf '%s' "$R37" | grep -q '"isError":true' && printf '%s' "$R37" | grep -q 'read-only mode'; then
  ok "T37 s1_api_post path with a fragment refused"
else bad "T37 s1_api_post path with a fragment refused" "$(printf '%s' "$R37" | cut -c1-200)"; fi

case "$IMAGE" in
  *:*/*|*/*:*)
    if docker buildx imagetools inspect "$IMAGE" >/dev/null 2>&1; then
      ARCHES="$(docker buildx imagetools inspect "$IMAGE" 2>/dev/null | awk '/Platform:/ && $2 !~ /unknown/ {printf "%s ", $2}')"
      ok "T17 registry manifest readable" "${ARCHES:-single}"
    else skip "T17 registry manifest readable" "local image reference"; fi ;;
  *) skip "T17 registry manifest readable" "local image reference" ;;
esac

echo
echo "  passed: $PASS  failed: $FAIL  skipped: $SKIP"
exit "$FAIL"
