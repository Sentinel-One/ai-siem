#!/usr/bin/env bash
#
# s1-secops-mcp installer for macOS and Linux.
#
# Modes:
#   --user      (default) Install for the current user only.
#                Writes credentials to ~/.config/sentinelone/credentials.json,
#                installs the npm package globally via the current Node toolchain.
#
#   --server    Linux VM deployment. Creates a system `mcp` user, installs the
#                npm package globally, writes credentials and bearer tokens to
#                /etc/s1-secops-mcp/, drops the systemd unit, enables and
#                starts the service.
#
# Idempotent: rerunning is safe; it skips steps already completed.
#
# Exit codes: 0 ok, 1 generic failure, 2 unsupported platform, 3 missing prereq.

set -euo pipefail

# ─── helpers ─────────────────────────────────────────────────────────────────

c_red()    { printf '\033[31m%s\033[0m\n' "$*"; }
c_green()  { printf '\033[32m%s\033[0m\n' "$*"; }
c_yellow() { printf '\033[33m%s\033[0m\n' "$*"; }
c_bold()   { printf '\033[1m%s\033[0m\n' "$*"; }

step() { c_bold ">> $*"; }
ok()   { c_green   "   ok: $*"; }
warn() { c_yellow  "   warn: $*"; }
die()  { c_red     "   error: $*"; exit 1; }

PKG="@pmoses-s1/s1-secops-mcp"
MODE="user"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --user)   MODE="user"; shift ;;
    --server) MODE="server"; shift ;;
    -h|--help)
      cat <<EOF
Usage: $0 [--user|--server]

  --user      Install for current user (default).
              Default install path on macOS: ~/.config/sentinelone/
              Default install path on Linux: ~/.config/sentinelone/

  --server    Install on a Linux VM as a shared service.
              System path: /etc/s1-secops-mcp/
              systemd unit: s1-secops-mcp.service
              Requires sudo.

EOF
      exit 0 ;;
    *) die "Unknown flag: $1 (try --help)" ;;
  esac
done

OS="$(uname -s)"
case "$OS" in
  Darwin) PLATFORM="mac" ;;
  Linux)  PLATFORM="linux" ;;
  *) c_red "Unsupported platform: $OS"; exit 2 ;;
esac

if [[ "$MODE" == "server" && "$PLATFORM" != "linux" ]]; then
  die "--server mode is Linux only (got $PLATFORM)"
fi

# ─── prereqs ─────────────────────────────────────────────────────────────────

step "Checking prerequisites"

if ! command -v node >/dev/null 2>&1; then
  c_red   "Node.js is required but not found on PATH."
  c_red   "Install Node 18+:"
  c_red   "  macOS:  brew install node@20"
  c_red   "  Linux:  curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash - && sudo apt install -y nodejs"
  exit 3
fi
NODE_MAJOR="$(node --version | sed 's/^v\([0-9]*\).*/\1/')"
if [[ "$NODE_MAJOR" -lt 18 ]]; then
  die "Node $(node --version) is too old. Need Node 18+."
fi
ok "node $(node --version)"

if ! command -v npm >/dev/null 2>&1; then
  die "npm not found alongside node; please install Node 18+ from nodejs.org or your package manager."
fi
ok "npm $(npm --version)"

if [[ "$MODE" == "server" ]]; then
  if [[ "$EUID" -ne 0 ]]; then
    die "--server mode must be run with sudo (need to create /etc/s1-secops-mcp/, system user, and systemd unit)."
  fi
  command -v systemctl >/dev/null 2>&1 || die "systemctl not found; this script targets systemd-based Linux."
  ok "running as root, systemd present"
fi

# ─── install package ─────────────────────────────────────────────────────────

step "Installing $PKG globally"
if [[ "$MODE" == "server" ]]; then
  npm install -g "$PKG" >/dev/null
else
  # Avoid sudo on Mac/personal Linux: use a per-user npm prefix if not already.
  if ! npm config get prefix --location=user 2>/dev/null | grep -qE '^/'; then
    npm config set prefix "$HOME/.npm-global"
    case ":$PATH:" in
      *":$HOME/.npm-global/bin:"*) ;;
      *) warn "Add $HOME/.npm-global/bin to your PATH (currently missing)." ;;
    esac
  fi
  npm install -g "$PKG" >/dev/null
fi
ok "$(npm ls -g --depth=0 "$PKG" 2>/dev/null | grep "$PKG" | head -1 | sed 's/.*-> //' || echo installed)"

# ─── credentials skeleton ────────────────────────────────────────────────────

if [[ "$MODE" == "server" ]]; then
  CONF_DIR="/etc/s1-secops-mcp"
  CRED_PATH="$CONF_DIR/credentials.json"
  TOKEN_PATH="$CONF_DIR/bearer-tokens.json"
  ENV_PATH="$CONF_DIR/server.env"
  OWNER="mcp"
else
  CONF_DIR="$HOME/.config/sentinelone"
  CRED_PATH="$CONF_DIR/credentials.json"
  TOKEN_PATH=""
  ENV_PATH=""
  OWNER="$USER"
fi

step "Setting up $CONF_DIR"
mkdir -p "$CONF_DIR"
if [[ ! -f "$CRED_PATH" ]]; then
  cat > "$CRED_PATH" <<'EOF'
{
  "S1_CONSOLE_URL":       "https://usea1-acme.sentinelone.net",
  "S1_CONSOLE_API_TOKEN": "REPLACE_WITH_API_TOKEN",
  "S1_HEC_INGEST_URL":    "https://ingest.us1.sentinelone.net",
  "SDL_XDR_URL":          "https://xdr.us1.sentinelone.net",
  "SDL_LOG_READ_KEY":     "",
  "SDL_CONFIG_READ_KEY":  "",
  "SDL_CONFIG_WRITE_KEY": ""
}
EOF
  chmod 600 "$CRED_PATH"
  ok "wrote $CRED_PATH (placeholder, edit before starting)"
else
  ok "$CRED_PATH already exists, leaving untouched"
fi

if [[ "$MODE" == "server" ]]; then
  if ! id "$OWNER" >/dev/null 2>&1; then
    step "Creating system user '$OWNER'"
    useradd --system --no-create-home --shell /usr/sbin/nologin "$OWNER"
    ok "created"
  else
    ok "user '$OWNER' already exists"
  fi
  chown -R "$OWNER":"$OWNER" "$CONF_DIR"
  chmod 600 "$CRED_PATH"

  if [[ ! -f "$TOKEN_PATH" ]]; then
    step "Generating initial bearer token"
    if command -v openssl >/dev/null 2>&1; then
      TOKEN_ADMIN="$(openssl rand -hex 32)"
    else
      TOKEN_ADMIN="$(node -e 'console.log(require("crypto").randomBytes(32).toString("hex"))')"
    fi
    cat > "$TOKEN_PATH" <<EOF
{
  "admin": "$TOKEN_ADMIN"
}
EOF
    chmod 600 "$TOKEN_PATH"
    chown "$OWNER":"$OWNER" "$TOKEN_PATH"
    ok "wrote $TOKEN_PATH (one initial admin token)"
    c_yellow "   INITIAL ADMIN BEARER TOKEN:"
    c_yellow "   $TOKEN_ADMIN"
    c_yellow "   Save this value now; it is also stored in $TOKEN_PATH."
  else
    ok "$TOKEN_PATH already exists"
  fi

  if [[ ! -f "$ENV_PATH" ]]; then
    cat > "$ENV_PATH" <<EOF
# Environment file for s1-secops-mcp.service.
# Adjust LOG_LEVEL or override anything here; reload with: systemctl reload s1-secops-mcp
EOF
    chmod 600 "$ENV_PATH"
    chown "$OWNER":"$OWNER" "$ENV_PATH"
    ok "wrote $ENV_PATH"
  else
    ok "$ENV_PATH already exists"
  fi

  step "Installing systemd unit"
  SVC_PATH="/etc/systemd/system/s1-secops-mcp.service"
  GLOBAL_NODE_MODULES="$(npm root -g)"
  SCRIPT_DIR="$GLOBAL_NODE_MODULES/$PKG"
  # Rewrite the ExecStart path to point at the resolved global install,
  # since the bundled unit uses %h which assumes per-user install.
  sed "s|%h/.npm-global/lib/node_modules/@pmoses-s1/s1-secops-mcp|$SCRIPT_DIR|g" \
    "$SCRIPT_DIR/deploy/systemd/s1-secops-mcp.service" > "$SVC_PATH"
  systemctl daemon-reload
  systemctl enable s1-secops-mcp >/dev/null 2>&1
  ok "wrote $SVC_PATH and enabled the service"

  step "Starting the service"
  if systemctl is-active s1-secops-mcp >/dev/null 2>&1; then
    systemctl restart s1-secops-mcp
    ok "restarted"
  else
    systemctl start s1-secops-mcp
    ok "started"
  fi
  sleep 1
  if systemctl is-active --quiet s1-secops-mcp; then
    ok "service is active"
  else
    c_red "service failed to start. Recent log lines:"
    journalctl -u s1-secops-mcp -n 30 --no-pager | sed 's/^/   /'
    exit 1
  fi
fi

# ─── final notes ─────────────────────────────────────────────────────────────

step "Next steps"
if [[ "$MODE" == "user" ]]; then
  cat <<EOF

   1. Edit $CRED_PATH with your real SentinelOne values.
   2. Try the server:
        s1-secops-mcp --version
        s1-secops-mcp --help
   3. Wire it into Claude Cowork / Claude Desktop / Claude Code via stdio
      (no HTTP needed for single-user local). See deploy/README.md for the
      exact config block.

EOF
elif [[ "$MODE" == "server" ]]; then
  cat <<EOF

   1. Edit $CRED_PATH with your real SentinelOne values, then reload:
        sudo systemctl reload s1-secops-mcp
   2. Verify the server is up:
        curl -s http://127.0.0.1:8765/healthz
   3. Put TLS in front (Caddy template at $SCRIPT_DIR/deploy/caddy/Caddyfile.example).
   4. Add team members by editing $TOKEN_PATH and reloading:
        echo '{"admin":"...", "alice":"...", "bob":"..."}' > $TOKEN_PATH
        sudo systemctl reload s1-secops-mcp
      (Reload sends SIGHUP; no connection drops.)
   5. Tail the audit log:
        sudo journalctl -u s1-secops-mcp -f | grep '\[audit\]'

   See deploy/README.md for the full Linux VM walkthrough.

EOF
fi

c_green "Done."
