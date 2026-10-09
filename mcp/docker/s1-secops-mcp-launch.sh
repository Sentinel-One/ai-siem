#!/bin/sh
# s1-secops-mcp-launch.sh: run a bundled MCP server from the
# sentinelone/secops-mcps image with credentials from the OS keychain.
#
# Secrets are read from the macOS login keychain (/usr/bin/security) or the
# Linux Secret Service (secret-tool) and handed to the container over stdin
# (entrypoint S1_SECRETS_STDIN=1). They never appear on a command line, in the
# MCP client config, or in `docker inspect`.
#
# Usage
#   s1-secops-mcp-launch.sh [--image IMG] [--profile P] <server> [server args...]
#       server: s1-secops-mcp | purple-mcp | virustotal-mcp
#   s1-secops-mcp-launch.sh setup  [--profile P]   store values (prompts, no echo)
#   s1-secops-mcp-launch.sh status [--profile P]   show which values are stored
#   s1-secops-mcp-launch.sh versions | help        image versions / entrypoint help
#   s1-secops-mcp-launch.sh install [options]      copy to ~/.local/bin, pull the image,
#                                                  add the three servers to the Claude
#                                                  Desktop config (backup kept), then
#                                                  run setup if no token is stored
#   s1-secops-mcp-launch.sh config  [options]      print the mcpServers JSON with this
#                                                  launcher's absolute path (other clients)
#     options: --image IMG  --profile P  --output-dir DIR  --claude-md FILE
#              --config-path FILE (install only; default is Claude Desktop's config)
#
# MCP client config (Claude Desktop example; no secrets in it). JSON does not
# expand ~ or $HOME, which is why `install` and `config` write the real path:
#   "s1-secops-mcp": { "command": "/abs/path/s1-secops-mcp-launch.sh", "args": ["s1-secops-mcp"] }
#
# Environment
#   S1_MCP_IMAGE   image (default sentinelone/secops-mcps:1.5.3)
#   S1_PROFILE     keychain profile (default "default")
#   S1_OUTPUT_DIR  host directory mounted at the same path so outputFile works
#   S1_CLAUDE_MD_PATH  host CLAUDE.md, mounted read-only into the container
#   S1_KEYCHAIN_TIMEOUT  keychain call timeout in SECONDS (default 15); the
#                  Node and Python clients read S1_KEYCHAIN_TIMEOUT_MS instead
#
# Keychain items: service "sentinelone-mcp", account "<profile>:<NAME>" (the
# same items `s1-secops-mcp setup` writes). S1_SCOPE is <accountId> or
# <accountId>:<siteId>.
set -eu

SERVICE=sentinelone-mcp
IMAGE=${S1_MCP_IMAGE:-sentinelone/secops-mcps:1.5.3}
PROFILE=${S1_PROFILE:-default}

die() { echo "s1-secops-mcp-launch: $*" >&2; exit 2; }

while [ $# -gt 0 ]; do
  case "$1" in
    --image) [ $# -ge 2 ] || die "--image needs a value"; IMAGE=$2; shift 2 ;;
    --profile) [ $# -ge 2 ] || die "--profile needs a value"; PROFILE=$2; shift 2 ;;
    -h|--help) sed -n '2,39p' "$0"; exit 0 ;;
    *) break ;;
  esac
done
[ $# -ge 1 ] || die "missing server name (s1-secops-mcp | purple-mcp | virustotal-mcp | setup | status | install | config)"
CMD=$1; shift
OUTPUT_DIR=""; CLAUDE_MD=""; CONFIG_PATH=""
# setup, status, install and config take their options after the command too
# (`setup --profile P`); servers pass everything after the name through.
case "$CMD" in
  setup|status)
    while [ $# -gt 0 ]; do
      case "$1" in
        --profile) [ $# -ge 2 ] || die "--profile needs a value"; PROFILE=$2; shift 2 ;;
        *) die "unknown option for $CMD: $1" ;;
      esac
    done ;;
  install|config)
    while [ $# -gt 0 ]; do
      [ $# -ge 2 ] || die "$1 needs a value"
      case "$1" in
        --image) IMAGE=$2 ;;
        --profile) PROFILE=$2 ;;
        --output-dir) OUTPUT_DIR=$2 ;;
        --claude-md) CLAUDE_MD=$2 ;;
        --config-path) [ "$CMD" = install ] || die "--config-path is for install only"; CONFIG_PATH=$2 ;;
        *) die "unknown option for $CMD: $1" ;;
      esac
      shift 2
    done ;;
  s1-secops-mcp|s1|purple-mcp|purple|virustotal-mcp|virustotal|vt)
    case "${1:-}" in --image|--profile) die "put $1 before the server name: $0 $1 <value> $CMD" ;; esac ;;
esac

case "$PROFILE" in
  *[!A-Za-z0-9_.-]*|"") die "invalid profile name: $PROFILE" ;;
esac

OS=$(uname -s)

# Bounded keychain calls: a locked keyring waiting on an unlock prompt must not
# hang the MCP client. Portable (macOS has no `timeout`): run in the background
# with a watchdog. Exit 143 means the watchdog fired. Only the direct child is
# killed: security and secret-tool are single processes, but a wrapper script
# whose own children keep the output pipe open would delay the return.
KC_TIMEOUT=${S1_KEYCHAIN_TIMEOUT:-15}
case "$KC_TIMEOUT" in *[!0-9]*|"") KC_TIMEOUT=15 ;; esac
kc_run() {
  "$@" &
  _kp=$!
  # The watchdog kills its own sleep when it is cancelled, so no orphan sleeps remain.
  ( trap 'kill "$_ks" 2>/dev/null; exit 0' TERM
    sleep "$KC_TIMEOUT" & _ks=$!; wait "$_ks"; kill "$_kp" 2>/dev/null ) >/dev/null 2>&1 &
  _kw=$!
  # `|| ...` keeps set -e from aborting here: a killed watchdog makes wait
  # return 143, which must not be mistaken for the command's own status.
  _krc=0; wait "$_kp" || _krc=$?
  kill "$_kw" 2>/dev/null || true; wait "$_kw" 2>/dev/null || true
  return "$_krc"
}

# One up-front health check so a missing tool, a missing D-Bus session or a
# locked keyring is reported as such, instead of every value reading as unset.
KC_ERR=""
kc_check() {
  case "$OS" in
    Darwin)
      [ -x /usr/bin/security ] || { KC_ERR="/usr/bin/security not found"; return; }
      _probe=$(kc_run /usr/bin/security find-generic-password -s "$SERVICE" -a "$PROFILE:__probe__" -w 2>&1) && return
      _rc=$?
      if [ "$_rc" = 143 ]; then KC_ERR="macOS keychain timed out after ${KC_TIMEOUT} s (locked, or waiting on a prompt?)"
      elif [ "$_rc" != 44 ]; then KC_ERR="macOS keychain unavailable: $_probe"; fi ;;
    Linux)
      command -v secret-tool >/dev/null 2>&1 || { KC_ERR="secret-tool not found (install libsecret-tools), or use: s1-secops-mcp setup / environment variables"; return; }
      _rc=0
      _probe=$(kc_run secret-tool search --all service "$SERVICE" 2>&1 >/dev/null) || _rc=$?
      [ "$_rc" = 143 ] && { KC_ERR="Linux keyring timed out after ${KC_TIMEOUT} s (locked, or waiting on an unlock prompt?)"; return; }
      case "$_probe" in
        *locked*) KC_ERR="Linux keyring is locked; unlock it (log in to the desktop session or gnome-keyring-daemon --unlock)" ;;
        *D-Bus*|*DBUS*|*autolaunch*|*org.freedesktop.secrets*) KC_ERR="Linux keyring unavailable: $_probe" ;;
      esac ;;
    *) KC_ERR="unsupported OS $OS (use s1-secops-mcp-launch.ps1 on Windows)" ;;
  esac
}
# `config` only prints JSON: it must not wait on a locked keychain.
[ "$CMD" = config ] || kc_check

kc_get() {
  [ -z "$KC_ERR" ] || return 0   # the health check already failed or timed out: do not wait again per name
  case "$OS" in
    Darwin) kc_run /usr/bin/security find-generic-password -s "$SERVICE" -a "$PROFILE:$1" -w 2>/dev/null || true ;;
    Linux)
      command -v secret-tool >/dev/null 2>&1 || return 0
      kc_run secret-tool lookup service "$SERVICE" username "$PROFILE:$1" 2>/dev/null || true ;;
    *) return 0 ;;
  esac
}

kc_set() { # name value(from stdin-safe variable)
  case "$OS" in
    Darwin)
      # shellcheck disable=SC1003
      case "$2" in *'"'*|*'\'*) die "$1 contains a quote or backslash, which the macOS keychain CLI cannot take safely" ;; esac
      # printf is a shell builtin: the value goes to security's stdin, never argv.
      printf 'add-generic-password -U -s "%s" -a "%s" -l "SentinelOne MCP %s %s" -w "%s"\n' \
        "$SERVICE" "$PROFILE:$1" "$PROFILE" "$1" "$2" | /usr/bin/security -i >/dev/null ;;
    Linux)
      command -v secret-tool >/dev/null 2>&1 || die "secret-tool not found (install libsecret-tools)"
      printf '%s' "$2" | secret-tool store --label "SentinelOne MCP $PROFILE $1" service "$SERVICE" username "$PROFILE:$1" ;;
    *) die "unsupported OS $OS (use s1-secops-mcp-launch.ps1 on Windows)" ;;
  esac
  [ "$(kc_get "$1")" = "$2" ] || die "write for $1 did not read back"
}

ALL_NAMES="S1_CONSOLE_URL S1_CONSOLE_API_TOKEN S1_HEC_INGEST_URL S1_HEC_TOKEN S1_SCOPE VIRUSTOTAL_API_KEY"
is_secret() { case "$1" in *TOKEN*|*KEY*) return 0 ;; *) return 1 ;; esac; }

# ---- install / config ------------------------------------------------------
# Absolute path of a file whose directory exists, resolved from the caller's cwd.
abs_path() { _ad=$(cd "$(dirname "$1")" 2>/dev/null && pwd -P) || return 1; printf '%s/%s\n' "$_ad" "$(basename "$1")"; }
json_str() { printf '"%s"' "$(printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g')"; }
# macOS privacy protection stops Claude Desktop's /bin/sh running a script there.
tcc_blocked() {
  [ "$OS" = Darwin ] || return 1
  case "$1" in "$HOME"/Documents/*|"$HOME"/Desktop/*|"$HOME"/Downloads/*) return 0 ;; esac
  return 1
}
# The three Claude Desktop entries for launcher $1. No secrets: paths and names only.
mcp_json() {
  _l=$(json_str "$1"); _i=$(json_str "$IMAGE"); _p=""; _e=""
  [ "$PROFILE" = default ] || _p=", \"--profile\", $(json_str "$PROFILE")"
  [ -z "$OUTPUT_DIR" ] || _e="\"S1_OUTPUT_DIR\": $(json_str "$OUTPUT_DIR")"
  [ -z "$CLAUDE_MD" ] || _e="${_e:+$_e, }\"S1_CLAUDE_MD_PATH\": $(json_str "$CLAUDE_MD")"
  printf '{\n  "mcpServers": {\n'
  printf '    "s1-secops-mcp": {\n      "command": %s,\n      "args": ["--image", %s%s, "s1-secops-mcp"]' "$_l" "$_i" "$_p"
  [ -z "$_e" ] || printf ',\n      "env": {%s}' "$_e"
  printf '\n    },\n'
  printf '    "purple-mcp": {\n      "command": %s,\n      "args": ["--image", %s%s, "purple-mcp"]\n    },\n' "$_l" "$_i" "$_p"
  printf '    "virustotal": {\n      "command": %s,\n      "args": ["--image", %s%s, "virustotal-mcp"]\n    }\n' "$_l" "$_i" "$_p"
  printf '  }\n}\n'
}
# Merge: keep every other server and setting, replace our three entries, and drop
# older entries that ran this launcher under another name (e.g. "virustotal-mcp").
MERGE_JS='function run(argv) {
  ObjC.import("Foundation");
  function rd(p) { var s = $.NSString.stringWithContentsOfFileEncodingError(p, $.NSUTF8StringEncoding, null); return s.isNil() ? null : ObjC.unwrap(s); }
  var add = JSON.parse(rd(argv[1])).mcpServers, raw = rd(argv[0]), cfg = {};
  if (raw !== null && raw.trim() !== "") {
    try { cfg = JSON.parse(raw); } catch (e) { throw new Error("invalid JSON in " + argv[0] + ": " + e.message); }
  }
  if (cfg === null || typeof cfg !== "object" || Array.isArray(cfg)) throw new Error(argv[0] + " is not a JSON object");
  var s = (cfg.mcpServers && typeof cfg.mcpServers === "object" && !Array.isArray(cfg.mcpServers)) ? cfg.mcpServers : {};
  Object.keys(s).forEach(function (k) {
    if (!(k in add) && JSON.stringify(s[k]).indexOf("s1-secops-mcp-launch") >= 0) { delete s[k]; console.log("removed old entry " + k); }
  });
  Object.keys(add).forEach(function (k) { s[k] = add[k]; });
  cfg.mcpServers = s;
  return JSON.stringify(cfg, null, 2);
}'
MERGE_PY='import json, sys
cfg_path, new_path = sys.argv[1:3]
add = json.load(open(new_path, encoding="utf-8"))["mcpServers"]
try:
    raw = open(cfg_path, encoding="utf-8").read()
except FileNotFoundError:
    raw = ""
cfg = {}
if raw.strip():
    try:
        cfg = json.loads(raw)
    except ValueError as e:
        sys.exit("invalid JSON in %s: %s" % (cfg_path, e))
if not isinstance(cfg, dict):
    sys.exit("%s is not a JSON object" % cfg_path)
s = cfg.get("mcpServers") if isinstance(cfg.get("mcpServers"), dict) else {}
for k in list(s):
    if k not in add and "s1-secops-mcp-launch" in json.dumps(s[k]):
        del s[k]
        print("removed old entry " + k, file=sys.stderr)
s.update(add)
cfg["mcpServers"] = s
print(json.dumps(cfg, indent=2))'

case "$CMD" in
  install|config)
    if [ -n "$OUTPUT_DIR" ]; then
      mkdir -p "$OUTPUT_DIR" || die "cannot create --output-dir $OUTPUT_DIR"
      OUTPUT_DIR=$(cd "$OUTPUT_DIR" && pwd -P)
    fi
    if [ -n "$CLAUDE_MD" ]; then
      [ -f "$CLAUDE_MD" ] || die "--claude-md $CLAUDE_MD is not a file"
      CLAUDE_MD=$(abs_path "$CLAUDE_MD")
    fi
    # $0 is the shell itself when the script arrives on a pipe (curl ... | sh):
    # check the file really is this launcher before copying or pointing at it.
    SELF=$(abs_path "$0" 2>/dev/null || true)
    { [ -n "$SELF" ] && [ -f "$SELF" ] && sed -n 2p "$SELF" 2>/dev/null | grep -q '^# s1-secops-mcp-launch.sh: run a bundled MCP server'; } ||
      die "cannot find this script on disk ($0). Download it to a file first, then run: sh <file> $CMD"
    ;;
esac

case "$CMD" in
  config)
    tcc_blocked "$SELF" && echo "s1-secops-mcp-launch: warning: $SELF is under ~/Documents, ~/Desktop or ~/Downloads, where macOS blocks Claude Desktop from running it. Run '$0 install' instead, which copies it to ~/.local/bin." >&2
    mcp_json "$SELF"
    exit 0 ;;
  install)
    BIN_DIR="$HOME/.local/bin"
    DEST="$BIN_DIR/s1-secops-mcp-launch.sh"
    mkdir -p "$BIN_DIR"
    if [ "$SELF" != "$(abs_path "$DEST")" ]; then
      cp "$SELF" "$DEST.tmp.$$" && mv -f "$DEST.tmp.$$" "$DEST"
    fi
    chmod 755 "$DEST"
    # Drop the download quarantine flag and other extended attributes.
    [ "$OS" != Darwin ] || xattr -c "$DEST" 2>/dev/null || true
    echo "Launcher installed: $DEST" >&2

    if [ -z "$CONFIG_PATH" ]; then
      case "$OS" in
        Darwin) CONFIG_PATH="$HOME/Library/Application Support/Claude/claude_desktop_config.json" ;;
        *) CONFIG_PATH="${XDG_CONFIG_HOME:-$HOME/.config}/Claude/claude_desktop_config.json" ;;
      esac
    fi
    TMPD=$(mktemp -d "${TMPDIR:-/tmp}/s1mcp.XXXXXX")
    trap 'rm -rf "$TMPD"' EXIT
    mcp_json "$DEST" > "$TMPD/new.json"
    MERGED=""
    if [ "$OS" = Darwin ] && [ -x /usr/bin/osascript ]; then
      printf '%s\n' "$MERGE_JS" > "$TMPD/merge.js"
      MERGED=$(/usr/bin/osascript -l JavaScript "$TMPD/merge.js" "$CONFIG_PATH" "$TMPD/new.json") || die "config not changed: $CONFIG_PATH could not be merged (see the error above)"
    elif command -v python3 >/dev/null 2>&1; then
      MERGED=$(python3 -I -c "$MERGE_PY" "$CONFIG_PATH" "$TMPD/new.json") || die "config not changed: $CONFIG_PATH could not be merged (see the error above)"
    fi
    if [ -n "$MERGED" ]; then
      mkdir -p "$(dirname "$CONFIG_PATH")"
      if [ -f "$CONFIG_PATH" ]; then
        BAK="$CONFIG_PATH.bak-$(date +%Y%m%d-%H%M%S)"
        cp -p "$CONFIG_PATH" "$BAK"
        echo "Backup of your previous config: $BAK" >&2
      fi
      printf '%s\n' "$MERGED" > "$CONFIG_PATH.tmp.$$" && mv -f "$CONFIG_PATH.tmp.$$" "$CONFIG_PATH"
      echo "Claude Desktop config updated: $CONFIG_PATH" >&2
    else
      echo "No JSON tool found (osascript or python3), so the config was not edited. Add these entries to your MCP client config:" >&2
      cat "$TMPD/new.json"
    fi

    if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
      echo "Pulling $IMAGE ..." >&2
      docker pull "$IMAGE" >&2 || echo "s1-secops-mcp-launch: warning: pull failed; the first start will retry it" >&2
    else
      echo "s1-secops-mcp-launch: warning: Docker is not running. Start Docker Desktop (or the Docker service) before you open Claude Desktop." >&2
    fi

    if [ -n "$KC_ERR" ]; then
      echo "s1-secops-mcp-launch: warning: $KC_ERR" >&2
    elif [ -z "$(kc_get S1_CONSOLE_API_TOKEN)" ]; then
      if [ -t 0 ]; then
        echo "S1_CONSOLE_API_TOKEN is not stored for profile $PROFILE. Starting setup: press Enter to keep any value already stored." >&2
        "$DEST" --profile "$PROFILE" setup || true
        [ -n "$(kc_get S1_CONSOLE_API_TOKEN)" ] || echo "s1-secops-mcp-launch: warning: S1_CONSOLE_API_TOKEN is still not stored. Run: $DEST setup" >&2
      else
        echo "Next: store your credentials with: $DEST setup" >&2
      fi
    fi
    echo "Done. Quit Claude Desktop completely and open it again: it starts the three MCPs itself. Nothing needs starting in Docker Desktop." >&2
    exit 0 ;;
esac

case "$CMD" in
  setup)
    [ -t 0 ] || die "setup must run in a terminal (or use: s1-secops-mcp setup, which also reads NAME=value lines on stdin)"
    [ -z "$KC_ERR" ] || die "$KC_ERR"
    # Restore echo whatever happens (Ctrl-C mid-prompt must not leave the TTY silent).
    trap 'stty echo 2>/dev/null' EXIT
    trap 'stty echo 2>/dev/null; echo >&2; echo "setup cancelled" >&2; exit 130' INT TERM HUP
    echo "Profile: $PROFILE. Press Enter to keep a value. Secrets are not echoed." >&2
    for n in $ALL_NAMES; do
      cur=$(kc_get "$n")
      if [ -n "$cur" ]; then
        if is_secret "$n"; then hint="set, ${#cur} chars"; else hint=$cur; fi
      else hint="not set"; fi
      # Echo off BEFORE the prompt, so a secret typed ahead is not echoed.
      if is_secret "$n"; then stty -echo; fi
      printf '%s [%s]: ' "$n" "$hint" >&2
      IFS= read -r v || v=""
      if is_secret "$n"; then stty echo; echo >&2; fi
      [ -n "$v" ] || continue
      case "$n" in *URL) while [ "${v%/}" != "$v" ]; do v=${v%/}; done ;; esac
      # Same validation as `s1-secops-mcp setup`.
      case "$n" in
        S1_CONSOLE_URL|S1_HEC_INGEST_URL) printf '%s' "$v" | grep -Eq '^https://[A-Za-z0-9.-]+(:[0-9]+)?$' || { echo "  skip $n: must be an https:// origin" >&2; continue; } ;;
        S1_SCOPE) printf '%s' "$v" | grep -Eq '^[0-9]+(:[0-9]+)?$' || { echo "  skip $n: must be <accountId> or <accountId>:<siteId>" >&2; continue; } ;;
        *) case "$v" in *[[:space:]]*) echo "  skip $n: contains whitespace" >&2; continue ;; esac
           [ ${#v} -ge 16 ] || { echo "  skip $n: too short to be a real token" >&2; continue; } ;;
      esac
      kc_set "$n" "$v" && echo "  stored $n" >&2
    done
    exit 0 ;;
  status)
    [ -z "$KC_ERR" ] || { echo "keychain: $KC_ERR" >&2; exit 1; }
    for n in $ALL_NAMES; do
      v=$(kc_get "$n")
      if [ -z "$v" ]; then s="-"; elif is_secret "$n"; then s="set (${#v} chars)"; else s=$v; fi
      printf '%-34s %s\n' "$n" "$s"
    done
    exit 0 ;;
  s1-secops-mcp|s1) NAMES="S1_CONSOLE_URL S1_CONSOLE_API_TOKEN S1_HEC_INGEST_URL S1_HEC_TOKEN S1_SCOPE" ;;
  purple-mcp|purple) NAMES="S1_CONSOLE_URL S1_CONSOLE_API_TOKEN VIRUSTOTAL_API_KEY" ;;  # VT key -> PURPLEMCP_VT_API_KEY (threat_intel_*)
  virustotal-mcp|virustotal|vt) NAMES="VIRUSTOTAL_API_KEY" ;;
  versions|help) exec docker run --rm "$IMAGE" "$CMD" ;;
  *) die "unknown server '$CMD'" ;;
esac

# Build the secrets payload in memory (shell variables are not exported, so
# they never reach the environment of docker or any other child).
PAYLOAD=""
NL='
'
missing=""
[ -z "$KC_ERR" ] || echo "s1-secops-mcp-launch: warning: $KC_ERR. Starting without keychain values." >&2
for n in $NAMES; do
  v=$(kc_get "$n")
  if [ -n "$v" ]; then PAYLOAD="$PAYLOAD$n=$v$NL"; else missing="$missing $n"; fi
done
[ -n "$KC_ERR" ] || case "$CMD" in
  s1-secops-mcp|s1|purple-mcp|purple)
    case "$missing" in *S1_CONSOLE_API_TOKEN\ *|*S1_CONSOLE_API_TOKEN) echo "s1-secops-mcp-launch: warning: S1_CONSOLE_API_TOKEN not in the keychain for profile $PROFILE (run: $0 setup)" >&2 ;; esac ;;
  *) [ -z "$missing" ] || echo "s1-secops-mcp-launch: warning: not in the keychain:$missing" >&2 ;;
esac

# Final argv: docker run <docker opts> IMAGE CMD <server args>. "$@" holds the
# server args; prepend everything else (POSIX sh has no arrays).
CNAME="s1mcp-$$-$(date +%s)"
set -- "$IMAGE" "$CMD" "$@"
if [ -n "${S1_CLAUDE_MD_PATH:-}" ] && [ -f "$S1_CLAUDE_MD_PATH" ]; then
  set -- -v "$S1_CLAUDE_MD_PATH:/workspace/CLAUDE.md:ro" -e "S1_CLAUDE_MD_PATH=/workspace/CLAUDE.md" "$@"
fi
if [ -n "${S1_OUTPUT_DIR:-}" ]; then
  [ -d "$S1_OUTPUT_DIR" ] || die "S1_OUTPUT_DIR $S1_OUTPUT_DIR is not a directory"
  set -- -v "$S1_OUTPUT_DIR:$S1_OUTPUT_DIR" -e "S1_OUTPUT_DIRS=$S1_OUTPUT_DIR" "$@"
fi
set -- run -i --rm --name "$CNAME" -e S1_SECRETS_STDIN=1 "$@"

# Relay: secrets first, then the client's stdin. Run in the background and wait,
# so a TERM from the MCP client is handled (a foreground pipeline would defer
# the trap) and the container is removed rather than orphaned.
exec 3<&0
(
  { printf '%s\n' "$PAYLOAD"; exec cat <&3; } | docker "$@"
) &
PID=$!
trap 'docker kill "$CNAME" >/dev/null 2>&1 || true; kill "$PID" 2>/dev/null || true' INT TERM HUP
set +e
wait "$PID"; RC=$?
# A trapped signal interrupts wait with >128; wait again for the pipeline to finish.
while kill -0 "$PID" 2>/dev/null; do wait "$PID"; RC=$?; done
exit $RC
