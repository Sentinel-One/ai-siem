#!/bin/sh
# launcher-test.sh: hermetic tests for `s1-secops-mcp-launch.sh install` and
# `config`. No network, no Docker, no keychain writes: HOME points at a temp
# directory and a fake `docker` that reports "not running" is first on PATH.
#
# Usage: docker/launcher-test.sh            (from the repo root, macOS or Linux)
# Runs every case under each POSIX shell found (sh, dash, bash).
set -u

HERE=$(cd "$(dirname "$0")" && pwd -P)
LAUNCHER="$HERE/s1-secops-mcp-launch.sh"
[ -f "$LAUNCHER" ] || { echo "launcher not found: $LAUNCHER" >&2; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "python3 is needed to check the JSON" >&2; exit 2; }

PASS=0; FAIL=0
ok()  { PASS=$((PASS + 1)); echo "  ok   $1"; }
bad() { FAIL=$((FAIL + 1)); echo "  FAIL $1"; [ -z "${2:-}" ] || sed 's/^/       /' "$2"; }
# py <json-file> <python expression over j>: exit 0 when the expression is true.
py() { python3 -I -c 'import json,sys; j=json.load(open(sys.argv[1])); sys.exit(0 if eval(sys.argv[2]) else 1)' "$1" "$2" 2>/dev/null; }

# Physical path: macOS /tmp and $TMPDIR are symlinks, and the launcher resolves them.
ROOT=$(cd "$(mktemp -d "${TMPDIR:-/tmp}/s1launch.XXXXXX")" && pwd -P)
trap 'rm -rf "$ROOT"' EXIT
mkdir -p "$ROOT/fakebin"
printf '#!/bin/sh\nexit 1\n' > "$ROOT/fakebin/docker"; chmod 755 "$ROOT/fakebin/docker"

if [ "$(uname -s)" = Darwin ]; then CFG_REL="Library/Application Support/Claude/claude_desktop_config.json"
else CFG_REL=".config/Claude/claude_desktop_config.json"; fi

for SHELL_BIN in /bin/sh /usr/bin/dash /bin/dash /bin/bash; do
  [ -x "$SHELL_BIN" ] || continue
  echo "== $SHELL_BIN"
  T="$ROOT/run-$(basename "$SHELL_BIN")"
  H="$T/home with space"; mkdir -p "$H" "$T/clone"
  cp "$LAUNCHER" "$T/clone/s1-secops-mcp-launch.sh"
  SRC="$T/clone/s1-secops-mcp-launch.sh"
  CFG="$H/$CFG_REL"
  DEST="$H/.local/bin/s1-secops-mcp-launch.sh"
  # S1_PROFILE is a profile nobody has, so a real SHODAN_API_KEY in the
  # developer's keychain cannot change which entries are written.
  run() { (cd "$T" && HOME="$H" XDG_CONFIG_HOME= S1_PROFILE=s1lt-nokey PATH="$ROOT/fakebin:$PATH" "$SHELL_BIN" "$@" </dev/null); }

  # config prints valid JSON whose command is the launcher's absolute path.
  # Shodan is optional: no key stored for the profile, so no shodan entry.
  run "$SRC" config > "$T/c.json" 2> "$T/c.err"
  if py "$T/c.json" "sorted(j['mcpServers'])==['purple-mcp','s1-secops-mcp','virustotal'] and {v['command'] for v in j['mcpServers'].values()}=={'$SRC'} and j['mcpServers']['virustotal']['args'][-1]=='virustotal-mcp'"; then
    ok "config: three entries without a Shodan key, absolute path"; else bad "config" "$T/c.err"; fi

  # --with-shodan adds the optional fourth entry, same launcher and image
  run "$SRC" config --with-shodan > "$T/c4.json" 2> "$T/c4.err"
  if py "$T/c4.json" "sorted(j['mcpServers'])==['purple-mcp','s1-secops-mcp','shodan','virustotal'] and j['mcpServers']['shodan']['command']=='$SRC' and j['mcpServers']['shodan']['args'][-1]=='shodan-mcp' and j['mcpServers']['shodan']['args'][:2]==j['mcpServers']['virustotal']['args'][:2]"; then
    ok "config: --with-shodan adds the shodan entry"; else bad "config --with-shodan" "$T/c4.err"; fi

  # Read-only is the default (no S1_READ_ONLY written); --read-write writes the
  # opt-out on the s1-secops-mcp entry only.
  run "$SRC" config --read-write > "$T/rw.json" 2> "$T/rw.err"
  if py "$T/c.json" "'env' not in j['mcpServers']['s1-secops-mcp']" && py "$T/rw.json" "j['mcpServers']['s1-secops-mcp']['env']=={'S1_READ_ONLY':'false'} and 'env' not in j['mcpServers']['purple-mcp'] and 'env' not in j['mcpServers']['virustotal']"; then
    ok "config: read-only by default, --read-write sets S1_READ_ONLY=false on s1-secops-mcp only"; else bad "config --read-write" "$T/rw.err"; fi

  # Runtime: S1_READ_ONLY from the client env is forwarded to docker run; unset
  # forwards nothing (the container default, read-only, applies).
  mkdir -p "$T/recbin"
  printf '#!/bin/sh\nprintf "%%s\\n" "$@" > "%s/argv"\ncat >/dev/null\nexit 0\n' "$T" > "$T/recbin/docker"; chmod 755 "$T/recbin/docker"
  (cd "$T" && HOME="$H" S1_PROFILE=s1lt-nokey S1_KEYCHAIN_TIMEOUT=3 S1_READ_ONLY=false PATH="$T/recbin:$PATH" "$SHELL_BIN" "$SRC" s1-secops-mcp </dev/null) >/dev/null 2>&1
  fwd_rw=$(grep -c '^S1_READ_ONLY=false$' "$T/argv" 2>/dev/null)
  (cd "$T" && env -u S1_READ_ONLY HOME="$H" S1_PROFILE=s1lt-nokey S1_KEYCHAIN_TIMEOUT=3 PATH="$T/recbin:$PATH" "$SHELL_BIN" "$SRC" s1-secops-mcp </dev/null) >/dev/null 2>&1
  fwd_def=$(grep -c '^S1_READ_ONLY' "$T/argv" 2>/dev/null)
  if [ "$fwd_rw" = 1 ] && [ "$fwd_def" = 0 ]; then
    ok "runtime: S1_READ_ONLY forwarded only when the client sets it"; else bad "runtime S1_READ_ONLY forwarding (set=$fwd_rw unset=$fwd_def)"; fi

  # a relative invocation still resolves to an absolute path
  (cd "$T/clone" && HOME="$H" "$SHELL_BIN" ./s1-secops-mcp-launch.sh config </dev/null) > "$T/c0.json" 2>/dev/null
  if py "$T/c0.json" "j['mcpServers']['purple-mcp']['command']=='$SRC'"; then ok "config: relative call gives absolute path"; else bad "config relative"; fi

  # config options: profile, output dir (created, absolute), CLAUDE.md, image
  mkdir -p "$T/md dir"; echo "# x" > "$T/md dir/CLAUDE.md"
  run "$SRC" config --profile prod --output-dir "out dir" --claude-md "md dir/CLAUDE.md" --image sentinelone/secops-mcps:9.9.9 > "$T/o.json" 2> "$T/o.err"
  if py "$T/o.json" "j['mcpServers']['s1-secops-mcp']['env']=={'S1_OUTPUT_DIR':'$T/out dir','S1_CLAUDE_MD_PATH':'$T/md dir/CLAUDE.md'} and j['mcpServers']['purple-mcp']['args']==['--image','sentinelone/secops-mcps:9.9.9','--profile','prod','purple-mcp'] and 'env' not in j['mcpServers']['virustotal']" && [ -d "$T/out dir" ]; then
    ok "config: --profile --output-dir --claude-md --image"; else bad "config options" "$T/o.err"; fi

  # option errors
  if ! run "$SRC" config --bogus x >/dev/null 2>&1 && ! run "$SRC" config --config-path x >/dev/null 2>&1 && ! run "$SRC" config --claude-md /nonexistent >/dev/null 2>&1; then
    ok "config: rejects unknown option, --config-path, missing CLAUDE.md"; else bad "config option errors"; fi

  # install, no existing config: copies itself, writes config, no backup
  run "$SRC" install > "$T/i1.out" 2> "$T/i1.err"; rc=$?
  if [ "$rc" = 0 ] && [ -x "$DEST" ] && cmp -s "$SRC" "$DEST" && py "$CFG" "{v['command'] for v in j['mcpServers'].values()}=={'$DEST'}" && ! ls "$CFG".bak-* >/dev/null 2>&1; then
    ok "install: fresh config"; else bad "install fresh (rc=$rc)" "$T/i1.err"; fi
  if grep -q "Docker is not running" "$T/i1.err" && grep -q "Quit Claude Desktop completely" "$T/i1.err" && grep -q "configured read-only (the default)" "$T/i1.err"; then
    ok "install: Docker warning, read-only notice and restart instruction"; else bad "install messages" "$T/i1.err"; fi

  # install merges: keeps other servers and settings, replaces ours, drops an
  # old launcher entry under another name, keeps a backup
  cat > "$CFG" <<'J'
{"globalShortcut": "Alt+Space",
 "mcpServers": {
   "other": {"command": "node", "args": ["x.js"]},
   "virustotal-mcp": {"command": "/Users/old/Documents/s1-secops-skills/docker/s1-secops-mcp-launch.sh", "args": ["virustotal-mcp"]},
   "s1-secops-mcp": {"command": "docker", "args": ["run", "-i", "--rm", "sentinelone/secops-mcps:1.4.0"]}},
 "preferences": {"a": 1}}
J
  cp "$CFG" "$T/orig.json"
  run "$SRC" install > /dev/null 2> "$T/i2.err"
  if py "$CFG" "j['globalShortcut']=='Alt+Space' and j['preferences']=={'a':1} and j['mcpServers']['other']=={'command':'node','args':['x.js']} and 'virustotal-mcp' not in j['mcpServers'] and sorted(j['mcpServers'])==['other','purple-mcp','s1-secops-mcp','virustotal'] and j['mcpServers']['s1-secops-mcp']['command']=='$DEST'"; then
    ok "install: merge keeps others, replaces ours, drops old entry"; else bad "install merge" "$T/i2.err"; fi
  BAK=$(ls "$CFG".bak-* 2>/dev/null | head -n 1)
  if [ -n "$BAK" ] && cmp -s "$BAK" "$T/orig.json" && grep -q "removed old entry virustotal-mcp" "$T/i2.err"; then
    ok "install: backup identical to previous config"; else bad "install backup" "$T/i2.err"; fi
  rm -f "$CFG".bak-*

  # re-running from the installed copy changes nothing
  cp "$CFG" "$T/before.json"
  run "$DEST" install > /dev/null 2>&1
  if cmp -s "$T/before.json" "$CFG" && cmp -s "$SRC" "$DEST"; then ok "install: idempotent from the installed copy"; else bad "install idempotent"; fi
  rm -f "$CFG".bak-*

  # invalid JSON: refuse, leave the file alone
  echo '{ "mcpServers": ' > "$CFG"; cp "$CFG" "$T/broken.json"
  run "$SRC" install > /dev/null 2> "$T/i3.err"; rc=$?
  if [ "$rc" != 0 ] && cmp -s "$T/broken.json" "$CFG" && grep -q "config not changed" "$T/i3.err" && ! ls "$CFG".bak-* >/dev/null 2>&1; then
    ok "install: invalid JSON left untouched (rc=$rc)"; else bad "install invalid JSON" "$T/i3.err"; fi

  # --config-path writes elsewhere
  run "$SRC" install --config-path "$T/alt/c.json" > /dev/null 2>&1
  if py "$T/alt/c.json" "len(j['mcpServers'])==3"; then ok "install: --config-path"; else bad "install --config-path"; fi

  # --read-write: writes the opt-out and prints the write NOTICE
  run "$SRC" install --read-write --config-path "$T/rwi/c.json" > /dev/null 2> "$T/i6.err"
  if py "$T/rwi/c.json" "j['mcpServers']['s1-secops-mcp']['env']=={'S1_READ_ONLY':'false'}" && grep -q "NOTICE: s1-secops-mcp is configured with write enabled" "$T/i6.err"; then
    ok "install: --read-write writes S1_READ_ONLY=false and the NOTICE"; else bad "install --read-write" "$T/i6.err"; fi

  # piped into the shell ($0 is the shell): refuse, never copy the shell binary
  rm -f "$DEST"
  (cd "$T" && HOME="$H" PATH="$ROOT/fakebin:$PATH" "$SHELL_BIN" -s install < "$SRC") > /dev/null 2> "$T/i4.err"; rc=$?
  if [ "$rc" = 2 ] && [ ! -e "$DEST" ] && grep -q "Download it to a file first" "$T/i4.err"; then
    ok "install: piped script refused, nothing copied"; else bad "install piped (rc=$rc)" "$T/i4.err"; fi

  # Linux without python3: print the entries, do not write
  if [ "$(uname -s)" != Darwin ]; then
    mkdir -p "$T/nopy"
    for t in cat sed dirname basename mkdir cp mv chmod date mktemp rm uname grep head; do
      p=$(command -v "$t") && ln -sf "$p" "$T/nopy/$t"
    done
    cp "$ROOT/fakebin/docker" "$T/nopy/docker"
    rm -f "$CFG"
    (cd "$T" && HOME="$H" PATH="$T/nopy" "$SHELL_BIN" "$SRC" install </dev/null) > "$T/i5.out" 2> "$T/i5.err"; rc=$?
    if [ "$rc" = 0 ] && [ ! -e "$CFG" ] && py "$T/i5.out" "len(j['mcpServers'])==3" && grep -q "No JSON tool found" "$T/i5.err"; then
      ok "install: no JSON tool prints the entries instead"; else bad "install without python3 (rc=$rc)" "$T/i5.err"; fi
  fi
done

# Live stdio check (Docker running and the image present): an MCP client keeps
# stdin open, so the initialize reply must arrive before stdin closes. Piping
# one line and closing stdin would hide a relay that buffers input.
IMAGE=${S1_MCP_IMAGE:-sentinelone/secops-mcps:1.5.7}
if command -v docker >/dev/null 2>&1 && docker image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "== live stdio"
  L="$ROOT/live"; mkdir -p "$L"; mkfifo "$L/in"
  sh "$LAUNCHER" --image "$IMAGE" s1-secops-mcp < "$L/in" > "$L/out" 2> "$L/err" &
  LPID=$!
  exec 4> "$L/in"   # hold stdin open
  printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"launcher-test","version":"0"}}}' >&4
  i=0; while [ $i -lt 450 ] && ! grep -q '"serverInfo"' "$L/out" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
  if grep -q '"serverInfo"' "$L/out"; then ok "stdio: initialize answered in about $((i / 10)) s with stdin still open"; else bad "stdio: no initialize reply within 45 s while stdin was open" "$L/err"; fi
  exec 4>&-
  w=0; while kill -0 "$LPID" 2>/dev/null && [ $w -lt 200 ]; do sleep 0.1; w=$((w + 1)); done
  kill "$LPID" 2>/dev/null || true
  # Claude Code connects stdio servers over a Unix socketpair, not pipes. Some
  # coreutils (uutils cat) never forward socket input, so test that path too.
  if command -v python3 >/dev/null 2>&1; then
    if python3 - "$LAUNCHER" "$IMAGE" > "$L/sock" 2>&1 <<'PY'
import json, socket, subprocess, sys, time
launcher, image = sys.argv[1:3]
init = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "launcher-test", "version": "0"}}}) + "\n"
a, b = socket.socketpair()
p = subprocess.Popen(["sh", launcher, "--image", image, "s1-secops-mcp"], stdin=b, stdout=b, stderr=subprocess.DEVNULL)
b.close(); a.sendall(init.encode()); a.settimeout(45)
t0 = time.time(); buf = b""
try:
    while b"\n" not in buf:
        c = a.recv(65536)
        if not c:
            break
        buf += c
except socket.timeout:
    pass
print("%.1f" % (time.time() - t0))
a.shutdown(socket.SHUT_WR)
try:
    p.wait(20)
except subprocess.TimeoutExpired:
    p.kill()
sys.exit(0 if b'"serverInfo"' in buf else 1)
PY
    then ok "stdio over a Unix socket (how Claude Code connects): initialize answered in about $(tail -1 "$L/sock") s"
    else bad "stdio over a Unix socket: no initialize reply within 45 s" "$L/sock"; fi
  else
    echo "  skip socket stdio: needs python3"
  fi
else
  echo "  skip stdio: needs Docker running and $IMAGE pulled"
fi

echo
echo "launcher-test: $PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
