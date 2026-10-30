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
#       server: s1-secops-mcp | purple-mcp | virustotal-mcp | shodan-mcp
#   s1-secops-mcp-launch.sh setup  [--profile P]   store values (prompts, no echo)
#   s1-secops-mcp-launch.sh status [--profile P]   show which values are stored
#   s1-secops-mcp-launch.sh versions | help        image versions / entrypoint help
#   s1-secops-mcp-launch.sh notices                third-party notices and licenses
#   s1-secops-mcp-launch.sh install [options]      copy to ~/.local/bin, pull the image,
#                                                  add the servers to the Claude
#                                                  Desktop config (backup kept), then
#                                                  run setup if no token is stored
#   s1-secops-mcp-launch.sh config  [options]      print the mcpServers JSON with this
#                                                  launcher's absolute path (other clients)
#     options: --image IMG  --profile P  --output-dir DIR  --claude-md FILE
#              --with-shodan (add the optional shodan entry even with no key stored)
#              --read-write (allow s1-secops-mcp tools that change the tenant;
#                            read-only is the default, see docs/read-only.md)
#              --config-path FILE (install only; default is Claude Desktop's config)
#              --claude-code (install only; register the servers with
#                             `claude mcp add-json --scope user` instead; automatic
#                             when install runs inside Claude Code)
#
# Credentials live in the macOS keychain, the Linux Secret Service, or, under
# WSL without a Secret Service, Windows Credential Manager via powershell.exe.
#
# Shodan is optional: install/config write the "shodan" entry only when
# SHODAN_API_KEY is stored for the profile, or with --with-shodan. To add it
# later: setup (enter the key), then install again, then restart the client.
#
# MCP client config (Claude Desktop example; no secrets in it). JSON does not
# expand ~ or $HOME, which is why `install` and `config` write the real path:
#   "s1-secops-mcp": { "command": "/abs/path/s1-secops-mcp-launch.sh", "args": ["s1-secops-mcp"] }
#
# Environment
#   S1_MCP_IMAGE   image (default sentinelone/secops-mcps:1.5.7)
#   S1_PROFILE     keychain profile (default "default")
#   S1_OUTPUT_DIR  host directory mounted at the same path so outputFile works
#   S1_CLAUDE_MD_PATH  host CLAUDE.md, mounted read-only into the container
#   S1_READ_ONLY   passed to s1-secops-mcp when set (default inside: true)
#   S1_KEYCHAIN_TIMEOUT  keychain call timeout in SECONDS (default 15); the
#                  Node and Python clients read S1_KEYCHAIN_TIMEOUT_MS instead
#
# Keychain items: service "sentinelone-mcp", account "<profile>:<NAME>" (the
# same items `s1-secops-mcp setup` writes). S1_SCOPE is <accountId> or
# <accountId>:<siteId>.
set -eu

SERVICE=sentinelone-mcp
IMAGE=${S1_MCP_IMAGE:-sentinelone/secops-mcps:1.5.7}
PROFILE=${S1_PROFILE:-default}

die() { trace "die: $*"; echo "s1-secops-mcp-launch: $*" >&2; exit 2; }
# Opt-in timing trace for diagnosing slow starts: S1_LAUNCH_TRACE=/path/file.
# Stage names and durations only, never values.
trace() { [ -z "${S1_LAUNCH_TRACE:-}" ] || printf '%s pid=%s %s\n' "$(date +%H:%M:%S.%N 2>/dev/null || date +%H:%M:%S)" "$$" "$*" >>"$S1_LAUNCH_TRACE" 2>/dev/null || true; }
trace "start args: $*"

while [ $# -gt 0 ]; do
  case "$1" in
    --image) [ $# -ge 2 ] || die "--image needs a value"; IMAGE=$2; shift 2 ;;
    --profile) [ $# -ge 2 ] || die "--profile needs a value"; PROFILE=$2; shift 2 ;;
    -h|--help) sed -n '2,53p' "$0"; exit 0 ;;
    *) break ;;
  esac
done
[ $# -ge 1 ] || die "missing server name (s1-secops-mcp | purple-mcp | virustotal-mcp | shodan-mcp | setup | status | install | config)"
CMD=$1; shift
OUTPUT_DIR=""; CLAUDE_MD=""; CONFIG_PATH=""; WITH_SHODAN=""; READ_WRITE=""; CLAUDE_CODE=""
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
      # The flags without a value.
      if [ "$1" = --with-shodan ]; then WITH_SHODAN=1; shift; continue; fi
      if [ "$1" = --read-write ]; then READ_WRITE=1; shift; continue; fi
      if [ "$1" = --claude-code ]; then [ "$CMD" = install ] || die "--claude-code is for install only"; CLAUDE_CODE=1; shift; continue; fi
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
  s1-secops-mcp|s1|purple-mcp|purple|virustotal-mcp|virustotal|vt|shodan-mcp|shodan)
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

ALL_NAMES="S1_CONSOLE_URL S1_CONSOLE_API_TOKEN S1_HEC_INGEST_URL S1_HEC_TOKEN S1_SCOPE VIRUSTOTAL_API_KEY SHODAN_API_KEY"
# A terminal reachable as /dev/tty even when stdin is a pipe (curl ... | sh).
# Never inside Claude Code or another agent's shell: secrets must not be typed
# where they could land in a transcript.
# (A subshell: a failed redirection on the special builtin `:` would end a POSIX shell.)
tty_usable() { [ -z "${CLAUDECODE:-}" ] && (true </dev/tty) 2>/dev/null; }

# WSL: Linux distributions under WSL rarely run a Secret Service. When none is
# available, use Windows Credential Manager through powershell.exe instead: the
# same items s1-secops-mcp-launch.ps1 and Cowork on Windows read and write
# ("<profile>:<NAME>.sentinelone-mcp", generic, UTF-16 blob).
IS_WSL=""
# S1_OSRELEASE_FILE overrides the kernel release file (tests only).
if [ "$OS" = Linux ] && grep -qi microsoft "${S1_OSRELEASE_FILE:-/proc/sys/kernel/osrelease}" 2>/dev/null && command -v powershell.exe >/dev/null 2>&1; then
  IS_WSL=1
fi
WC_CS='using System;
using System.Runtime.InteropServices;
public static class S1Cred {
  [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
  public struct CREDENTIAL {
    public int Flags; public int Type; public string TargetName; public string Comment;
    public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
    public int CredentialBlobSize; public IntPtr CredentialBlob; public int Persist;
    public int AttributeCount; public IntPtr Attributes; public string TargetAlias; public string UserName;
  }
  [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  static extern bool CredReadW(string target, int type, int flags, out IntPtr cred);
  [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  static extern bool CredWriteW(ref CREDENTIAL cred, int flags);
  [DllImport("advapi32.dll")] static extern void CredFree(IntPtr p);
  public static string Read(string target) {
    IntPtr p;
    if (!CredReadW(target, 1, 0, out p)) {
      int e = Marshal.GetLastWin32Error();
      if (e == 1168) return null;
      throw new System.ComponentModel.Win32Exception(e);
    }
    try {
      var c = (CREDENTIAL)Marshal.PtrToStructure(p, typeof(CREDENTIAL));
      if (c.CredentialBlobSize == 0) return "";
      return Marshal.PtrToStringUni(c.CredentialBlob, c.CredentialBlobSize / 2);
    } finally { CredFree(p); }
  }
  public static void Write(string target, string user, string value) {
    byte[] b = System.Text.Encoding.Unicode.GetBytes(value);
    var c = new CREDENTIAL();
    c.Type = 1; c.TargetName = target; c.UserName = user; c.Persist = 3;
    c.CredentialBlobSize = b.Length;
    c.CredentialBlob = Marshal.AllocHGlobal(b.Length);
    try {
      Marshal.Copy(b, 0, c.CredentialBlob, b.Length);
      if (!CredWriteW(ref c, 0)) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
    } finally { Marshal.FreeHGlobal(c.CredentialBlob); }
  }
}'
# Encode a PowerShell body (plus the S1Cred type) for -EncodedCommand. Only
# names and the validated profile go in the script; secret values travel on
# stdin (write) or stdout (read), never argv.
wc_encode() {
  printf "\$ErrorActionPreference = 'Stop'\nAdd-Type -TypeDefinition @'\n%s\n'@\n%s\n" "$WC_CS" "$1" |
    iconv -f UTF-8 -t UTF-16LE | base64 | tr -d '\n'
}
WC_CACHE=""; WC_LOADED=""
# One powershell.exe call reads every name; the result is cached in this shell
# (call it in the main shell, not in $( ), so subshells inherit the cache).
wc_load() {
  [ -z "$WC_LOADED" ] || return 0
  _wcmd=$(wc_encode "foreach (\$n in '$ALL_NAMES'.Split(' ')) { \$v = [S1Cred]::Read('$PROFILE:' + \$n + '.$SERVICE'); if (\$v) { [Console]::Out.Write(\$n + '=' + \$v + [char]10) } }")
  # Output goes to a private temp file, not a pipe: if powershell.exe hangs and
  # the watchdog kills it, a Windows-side child can keep a pipe open forever,
  # while a file needs no EOF. Calls from servers started together run in
  # parallel (serialising them multiplied the start-up time past the client's
  # connect timeout).
  _wdir=$(mktemp -d "${TMPDIR:-/tmp}/s1wc.XXXXXX") || return 1
  _wrc=0
  _wt0=$(date +%s)
  powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand "$_wcmd" </dev/null >"$_wdir/out" 2>/dev/null &
  _wp=$!
  # The deadline is wall-clock time, so the limit holds whether or not this
  # system's sleep accepts fractions.
  while kill -0 "$_wp" 2>/dev/null; do
    if [ $(( $(date +%s) - _wt0 )) -ge "$KC_TIMEOUT" ]; then kill "$_wp" 2>/dev/null; _wrc=143; break; fi
    sleep 0.1 2>/dev/null || sleep 1
  done
  [ "$_wrc" = 143 ] || wait "$_wp" || _wrc=$?
  WC_CACHE=$(tr -d '\r' <"$_wdir/out" 2>/dev/null)
  rm -rf "$_wdir"
  # Visible in the MCP client's server log, so slow credential reads are easy to spot.
  _wsec=$(( $(date +%s) - _wt0 ))
  trace "wincred read rc=$_wrc secs=$_wsec names=$(printf '%s\n' "$WC_CACHE" | grep -c '=')"
  [ "$_wsec" -lt 3 ] || echo "s1-secops-mcp-launch: Windows Credential Manager read took ${_wsec}s" >&2
  [ "$_wrc" = 0 ] || { WC_CACHE=""; return "$_wrc"; }
  WC_LOADED=1
}

# One up-front health check so a missing tool, a missing D-Bus session or a
# locked keyring is reported as such, instead of every value reading as unset.
KC_ERR=""; KC_BACKEND=""
kc_check() {
  case "$OS" in
    Darwin)
      KC_BACKEND=macos
      [ -x /usr/bin/security ] || { KC_ERR="/usr/bin/security not found"; return; }
      _probe=$(kc_run /usr/bin/security find-generic-password -s "$SERVICE" -a "$PROFILE:__probe__" -w 2>&1) && return
      _rc=$?
      if [ "$_rc" = 143 ]; then KC_ERR="macOS keychain timed out after ${KC_TIMEOUT} s (locked, or waiting on a prompt?)"
      elif [ "$_rc" != 44 ]; then KC_ERR="macOS keychain unavailable: $_probe"; fi ;;
    Linux)
      _serr=""
      if command -v secret-tool >/dev/null 2>&1; then
        _rc=0
        _probe=$(kc_run secret-tool search --all service "$SERVICE" 2>&1 >/dev/null) || _rc=$?
        if [ "$_rc" = 143 ]; then _serr="Linux keyring timed out after ${KC_TIMEOUT} s (locked, or waiting on an unlock prompt?)"
        else
          case "$_probe" in
            *locked*) _serr="Linux keyring is locked; unlock it (log in to the desktop session or gnome-keyring-daemon --unlock)" ;;
            *D-Bus*|*DBUS*|*autolaunch*|*org.freedesktop.secrets*) _serr="Linux keyring unavailable: $_probe" ;;
          esac
        fi
      else
        _serr="no Linux keyring: secret-tool not found (install libsecret-tools and a Secret Service such as gnome-keyring)"
      fi
      [ -n "$_serr" ] || { KC_BACKEND=secret; return; }
      if [ -n "$IS_WSL" ]; then
        KC_BACKEND=wincred
        wc_load || KC_ERR="Windows Credential Manager unreachable through powershell.exe (WSL interop off?); Linux keyring: $_serr"
        return
      fi
      KC_ERR=$_serr ;;
    *) KC_ERR="unsupported OS $OS (use s1-secops-mcp-launch.ps1 on Windows)" ;;
  esac
}
# `config` only prints JSON: it must not wait on a locked keychain.
if [ "$CMD" != config ]; then
  trace "kc_check begin (os=$OS wsl=${IS_WSL:-0})"
  kc_check
  trace "kc_check end backend=${KC_BACKEND:-none} err=${KC_ERR:+yes}"
fi

kc_get() {
  [ -z "$KC_ERR" ] || return 0   # the health check already failed or timed out: do not wait again per name
  case "$KC_BACKEND" in
    macos) kc_run /usr/bin/security find-generic-password -s "$SERVICE" -a "$PROFILE:$1" -w 2>/dev/null || true ;;
    secret) kc_run secret-tool lookup service "$SERVICE" username "$PROFILE:$1" 2>/dev/null || true ;;
    wincred) printf '%s\n' "$WC_CACHE" | sed -n "s/^$1=//p" | head -n 1 ;;
    *) return 0 ;;
  esac
}

kc_set() { # name value(from stdin-safe variable)
  case "$KC_BACKEND" in
    wincred)
      # The value goes to powershell.exe on stdin; the script holds only names.
      printf '%s' "$2" | powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand \
        "$(wc_encode "\$v = [Console]::In.ReadToEnd(); [S1Cred]::Write('$PROFILE:$1.$SERVICE', '$PROFILE:$1', \$v)")" >/dev/null ||
        die "could not write $1 to Windows Credential Manager"
      WC_LOADED=""; wc_load || true ;;
    macos)
      # shellcheck disable=SC1003
      case "$2" in *'"'*|*'\'*) die "$1 contains a quote or backslash, which the macOS keychain CLI cannot take safely" ;; esac
      # printf is a shell builtin: the value goes to security's stdin, never argv.
      printf 'add-generic-password -U -s "%s" -a "%s" -l "SentinelOne MCP %s %s" -w "%s"\n' \
        "$SERVICE" "$PROFILE:$1" "$PROFILE" "$1" "$2" | /usr/bin/security -i >/dev/null ;;
    secret)
      printf '%s' "$2" | secret-tool store --label "SentinelOne MCP $PROFILE $1" service "$SERVICE" username "$PROFILE:$1" ;;
    *) die "${KC_ERR:-no credential store available}" ;;
  esac
  [ "$(kc_get "$1")" = "$2" ] || die "write for $1 did not read back"
}
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
# Shodan is optional: its entry is written only when a key is stored for this
# profile or --with-shodan was given. Without a key the server refuses to start,
# which a client shows as a failed server.
want_shodan() { [ -n "$WITH_SHODAN" ] || [ -n "$(kc_get SHODAN_API_KEY)" ]; }
# The Claude Desktop entries for launcher $1. No secrets: paths and names only.
mcp_json() {
  _l=$(json_str "$1"); _i=$(json_str "$IMAGE"); _p=""; _e=""
  [ "$PROFILE" = default ] || _p=", \"--profile\", $(json_str "$PROFILE")"
  [ -z "$OUTPUT_DIR" ] || _e="\"S1_OUTPUT_DIR\": $(json_str "$OUTPUT_DIR")"
  [ -z "$CLAUDE_MD" ] || _e="${_e:+$_e, }\"S1_CLAUDE_MD_PATH\": $(json_str "$CLAUDE_MD")"
  # Read-only is the default; only --read-write writes the opt-out.
  [ -z "$READ_WRITE" ] || _e="${_e:+$_e, }\"S1_READ_ONLY\": \"false\""
  printf '{\n  "mcpServers": {\n'
  printf '    "s1-secops-mcp": {\n      "command": %s,\n      "args": ["--image", %s%s, "s1-secops-mcp"]' "$_l" "$_i" "$_p"
  [ -z "$_e" ] || printf ',\n      "env": {%s}' "$_e"
  printf '\n    },\n'
  printf '    "purple-mcp": {\n      "command": %s,\n      "args": ["--image", %s%s, "purple-mcp"]\n    },\n' "$_l" "$_i" "$_p"
  printf '    "virustotal": {\n      "command": %s,\n      "args": ["--image", %s%s, "virustotal-mcp"]\n    }' "$_l" "$_i" "$_p"
  if want_shodan; then
    printf ',\n    "shodan": {\n      "command": %s,\n      "args": ["--image", %s%s, "shodan-mcp"]\n    }' "$_l" "$_i" "$_p"
  fi
  printf '\n  }\n}\n'
}
# Merge: keep every other server and setting, replace our entries, and drop
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

    # Claude Code: register the servers with `claude mcp add-json` (user scope)
    # instead of editing Claude Desktop's file. Chosen with --claude-code, or
    # automatically when install runs inside Claude Code (CLAUDECODE is set).
    if [ -z "$CONFIG_PATH" ] && [ -z "$CLAUDE_CODE" ] && [ -n "${CLAUDECODE:-}" ]; then
      CLAUDE_CODE=1
      echo "Running inside Claude Code: registering the servers with Claude Code. The Claude Desktop config is not changed; to configure Claude Desktop too, run install again from a terminal without --claude-code." >&2
    fi
    if [ -n "$CLAUDE_CODE" ]; then
      TMPD=$(mktemp -d "${TMPDIR:-/tmp}/s1mcp.XXXXXX")
      trap 'rm -rf "$TMPD"' EXIT
      mcp_json "$DEST" > "$TMPD/new.json"
      if command -v python3 >/dev/null 2>&1; then
        python3 -I -c 'import json,sys
for k,v in json.load(open(sys.argv[1]))["mcpServers"].items():
    v["type"]="stdio"; print(k+"\t"+json.dumps(v))' "$TMPD/new.json" > "$TMPD/servers.tsv" ||
          die "could not read the generated server entries"
      else
        die "python3 is needed to register servers with Claude Code"
      fi
      if command -v claude >/dev/null 2>&1; then
        # Older names are removed only when they run this launcher, so a user's
        # own server with one of those names is left alone. Our own names are
        # replaced, as the Claude Desktop merge does.
        for _old in virustotal-mcp sentinelone-mcp; do
          if claude mcp get "$_old" 2>/dev/null | grep -q 's1-secops-mcp-launch'; then
            claude mcp remove --scope user "$_old" >/dev/null 2>&1 && echo "Claude Code: removed old entry $_old" >&2
          fi
        done
        while IFS="$(printf '\t')" read -r _name _json; do
          claude mcp remove --scope user "$_name" >/dev/null 2>&1 || true
          claude mcp add-json --scope user "$_name" "$_json" >/dev/null || die "claude mcp add-json $_name failed"
          echo "Claude Code: registered $_name (user scope)" >&2
        done < "$TMPD/servers.tsv"
      else
        echo "The claude CLI is not on PATH. Register the servers with:" >&2
        while IFS="$(printf '\t')" read -r _name _json; do
          printf "claude mcp add-json --scope user %s '%s'\n" "$_name" "$_json"
        done < "$TMPD/servers.tsv"
      fi
      # Claude Code allows 30 s for a server to connect. A cold Docker start plus a
      # credential read (powershell.exe under WSL can take several seconds) can
      # exceed that, so raise MCP_TIMEOUT to 120 s in ~/.claude/settings.json
      # unless the user already set a larger value. MCP_TIMEOUT applies to every
      # MCP server in Claude Code. A symlinked settings file is updated in place.
      CC_SETTINGS="$HOME/.claude/settings.json"
      mkdir -p "$HOME/.claude"
      if python3 -I -c 'import json,os,sys
p=os.path.realpath(sys.argv[1])
try:
    raw=open(p,encoding="utf-8").read()
except FileNotFoundError:
    raw=""
cfg=json.loads(raw) if raw.strip() else {}
if not isinstance(cfg,dict): sys.exit("not a JSON object")
env=cfg.get("env") if isinstance(cfg.get("env"),dict) else {}
try: cur=int(env.get("MCP_TIMEOUT","0"))
except ValueError: cur=0
if cur>=120000: sys.exit(0)
env["MCP_TIMEOUT"]="120000"; cfg["env"]=env
tmp=p+".tmp"
open(tmp,"w",encoding="utf-8").write(json.dumps(cfg,indent=2)+"\n"); os.replace(tmp,p)' "$CC_SETTINGS"; then
        echo "Claude Code: MCP connect timeout is at least 120 s ($CC_SETTINGS, env.MCP_TIMEOUT; applies to all MCP servers)" >&2
      else
        echo "s1-secops-mcp-launch: warning: could not update $CC_SETTINGS; start Claude Code with MCP_TIMEOUT=120000 claude" >&2
      fi
      if [ -n "$READ_WRITE" ]; then
        echo "NOTICE: s1-secops-mcp is configured with write enabled (S1_READ_ONLY=false). Its tools can change your SentinelOne tenant; every change runs as the user that owns the API token and is written to the server audit log." >&2
      else
        echo "s1-secops-mcp is configured read-only (the default). To allow tenant changes, run install again with --read-write." >&2
      fi
    fi

    if [ -z "$CLAUDE_CODE" ]; then
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
      if [ -n "$READ_WRITE" ]; then
        echo "NOTICE: s1-secops-mcp is configured with write enabled (S1_READ_ONLY=false). Its tools can change your SentinelOne tenant; every change runs as the user that owns the API token and is written to the server audit log. Use a least-privilege service user. See docs/read-only.md." >&2
      else
        echo "s1-secops-mcp is configured read-only (the default): tools that change the tenant are refused. To allow them, run install again with --read-write." >&2
      fi
    else
      echo "No JSON tool found (osascript or python3), so the config was not edited. Add these entries to your MCP client config:" >&2
      cat "$TMPD/new.json"
    fi
    fi
    if [ -n "$CLAUDE_CODE" ]; then CLIENT="Claude Code"; else CLIENT="Claude Desktop"; fi

    if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
      echo "Pulling $IMAGE ..." >&2
      if ! docker pull "$IMAGE" >&2; then
        # A locally built tag (e.g. a release candidate) is not on the registry; that is fine.
        if docker image inspect "$IMAGE" >/dev/null 2>&1; then
          echo "s1-secops-mcp-launch: $IMAGE is not on the registry; using the local image." >&2
        else
          echo "s1-secops-mcp-launch: warning: pull failed; the first start will retry it" >&2
        fi
      fi
    elif [ -n "$IS_WSL" ] && ! command -v docker >/dev/null 2>&1; then
      echo "s1-secops-mcp-launch: warning: docker is not available in this WSL distro. In Docker Desktop on Windows: Settings > Resources > WSL integration, switch on this distro, Apply & restart, then open a new WSL terminal." >&2
    else
      echo "s1-secops-mcp-launch: warning: Docker is not running. Start Docker Desktop (or the Docker service) before you open $CLIENT." >&2
    fi

    [ "$KC_BACKEND" != wincred ] || echo "Credentials: Windows Credential Manager (WSL), shared with the Windows launcher and Cowork." >&2
    if [ -n "$KC_ERR" ]; then
      echo "s1-secops-mcp-launch: warning: $KC_ERR" >&2
    elif [ -z "$(kc_get S1_CONSOLE_API_TOKEN)" ]; then
      if [ -t 0 ] || tty_usable; then
        echo "S1_CONSOLE_API_TOKEN is not stored for profile $PROFILE. Starting setup: press Enter to keep any value already stored." >&2
        if [ -t 0 ]; then "$DEST" --profile "$PROFILE" setup || true
        else "$DEST" --profile "$PROFILE" setup </dev/tty || true; fi
        [ -n "$(kc_get S1_CONSOLE_API_TOKEN)" ] || echo "s1-secops-mcp-launch: warning: S1_CONSOLE_API_TOKEN is still not stored. Run: $DEST setup" >&2
      else
        echo "Credentials are not stored yet, and this shell has no terminal to prompt in (for example a ! command in Claude Code)." >&2
        echo "Secrets are never typed into a chat or passed on a command line. In your own terminal, run once:  $DEST setup" >&2
      fi
    fi
    if want_shodan; then
      echo "Shodan: entry added (optional server)." >&2
    else
      echo "Shodan: skipped (optional). To add it: $DEST setup (enter SHODAN_API_KEY), then $DEST install again." >&2
    fi
    if [ -n "$CLAUDE_CODE" ]; then
      echo "Done. Exit Claude Code and start it again; /mcp lists the servers. Nothing needs starting in Docker Desktop." >&2
    else
      echo "Done. Quit Claude Desktop completely and open it again: it starts the MCPs itself. Nothing needs starting in Docker Desktop." >&2
    fi
    exit 0 ;;
esac

case "$CMD" in
  setup)
    if [ ! -t 0 ] && tty_usable; then exec </dev/tty; fi
    [ -t 0 ] || die "setup prompts for secrets, so it needs a terminal. Run it in your own terminal, not through a ! command in Claude Code or another tool: $0 setup"
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
    printf '%-34s %s\n' "S1_READ_ONLY" "set in the MCP client config, not the keychain (default: read-only)"
    exit 0 ;;
  s1-secops-mcp|s1) NAMES="S1_CONSOLE_URL S1_CONSOLE_API_TOKEN S1_HEC_INGEST_URL S1_HEC_TOKEN S1_SCOPE" ;;
  purple-mcp|purple) NAMES="S1_CONSOLE_URL S1_CONSOLE_API_TOKEN VIRUSTOTAL_API_KEY" ;;  # VT key -> PURPLEMCP_VT_API_KEY (threat_intel_*)
  virustotal-mcp|virustotal|vt) NAMES="VIRUSTOTAL_API_KEY" ;;
  shodan-mcp|shodan) NAMES="SHODAN_API_KEY" ;;
  versions|help|notices) exec docker run --rm "$IMAGE" "$CMD" ;;
  *) die "unknown server '$CMD'" ;;
esac

if ! command -v docker >/dev/null 2>&1; then
  if [ -n "$IS_WSL" ]; then
    die "docker not found in this WSL distro. In Docker Desktop on Windows: Settings > Resources > WSL integration, switch on this distro, Apply & restart."
  fi
  die "docker not found. Install Docker Desktop (or Docker Engine) and make sure docker is on PATH."
fi

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
# Read-only mode is decided inside the container (default true); forward the
# client's setting only when it set one.
if [ -n "${S1_READ_ONLY+x}" ]; then
  set -- -e "S1_READ_ONLY=$S1_READ_ONLY" "$@"
fi
set -- run -i --rm --name "$CNAME" -e S1_SECRETS_STDIN=1 "$@"
trace "docker run begin image=$IMAGE server=$CMD missing=${missing:-none}"

# Relay: secrets first, then the client's stdin. Run in the background and wait,
# so a TERM from the MCP client is handled (a foreground pipeline would defer
# the trap) and the container is removed rather than orphaned.
exec 3<&0
# dd, not cat, forwards the client's stdin: Claude Code connects stdio servers
# over a Unix socket, and the uutils (Rust) cat that recent Ubuntu ships never
# forwards data arriving on a socket, so the server never saw initialize.
# dd copies each read as it arrives on pipes and sockets alike; its transfer
# summary on exit goes to /dev/null (macOS dd has no status=none).
trace "relay begin"
(
  { printf '%s\n' "$PAYLOAD"; exec dd bs=65536 2>/dev/null <&3; } | docker "$@"
) &
PID=$!
trap 'docker kill "$CNAME" >/dev/null 2>&1 || true; kill "$PID" 2>/dev/null || true' INT TERM HUP
set +e
wait "$PID"; RC=$?
# A trapped signal interrupts wait with >128; wait again for the pipeline to finish.
while kill -0 "$PID" 2>/dev/null; do wait "$PID"; RC=$?; done
trace "exit rc=$RC"
exit $RC
