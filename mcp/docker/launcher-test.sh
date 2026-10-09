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
  run() { (cd "$T" && HOME="$H" XDG_CONFIG_HOME= PATH="$ROOT/fakebin:$PATH" "$SHELL_BIN" "$@" </dev/null); }

  # config prints valid JSON whose command is the launcher's absolute path
  run "$SRC" config > "$T/c.json" 2> "$T/c.err"
  if py "$T/c.json" "sorted(j['mcpServers'])==['purple-mcp','s1-secops-mcp','virustotal'] and {v['command'] for v in j['mcpServers'].values()}=={'$SRC'} and j['mcpServers']['virustotal']['args'][-1]=='virustotal-mcp'"; then
    ok "config: three entries, absolute path"; else bad "config" "$T/c.err"; fi

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
  if grep -q "Docker is not running" "$T/i1.err" && grep -q "Quit Claude Desktop completely" "$T/i1.err"; then
    ok "install: Docker warning and restart instruction"; else bad "install messages" "$T/i1.err"; fi

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

echo
echo "launcher-test: $PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
