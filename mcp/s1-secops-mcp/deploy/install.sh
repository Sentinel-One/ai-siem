#!/usr/bin/env bash
#
# s1-secops-mcp installer for macOS and Linux.
#
# The server runs from the published Docker image, so the only host runtime
# requirement is Docker.
#
# Modes:
#   --user      (default) Install for the current user only.
#                Pulls the image and writes credentials to
#                ~/.config/sentinelone/credentials.json.
#
#   --server    Linux VM deployment. Pulls the image, creates a system `mcp`
#                user, writes credentials and bearer tokens to
#                /etc/s1-secops-mcp/, drops the systemd unit, enables and
#                starts the service.
#
# Idempotent: rerunning is safe; it skips steps already completed.
#
# Exit codes: 0 ok, 1 generic failure, 2 unsupported platform, 3 missing prereq.

set -euo pipefail

# Token and credential files must never be world-readable, even for the
# instant between creation and the explicit chmod 600 below.
umask 077

# ─── helpers ─────────────────────────────────────────────────────────────────

c_red() { printf '\033[31m%s\033[0m\n' "$*"; }
c_green() { printf '\033[32m%s\033[0m\n' "$*"; }
c_yellow() { printf '\033[33m%s\033[0m\n' "$*"; }
c_bold() { printf '\033[1m%s\033[0m\n' "$*"; }

step() { c_bold ">> $*"; }
ok() { c_green "   ok: $*"; }
warn() { c_yellow "   warn: $*"; }
die() {
  c_red "   error: $*"
  exit 1
}

# Pinned image. Single source of truth for this script; the systemd unit at
# deploy/systemd/s1-secops-mcp.service states the same pin in its
# Environment=S1_MCP_IMAGE line and the two are kept in sync (the server-mode
# install re-reads the installed unit and pulls whatever it pins).
IMAGE_REF="sentinelone/secops-skills:1.4.6"
CONTAINER_NAME="s1-secops-mcp"
MODE="user"

# Directory this script was run from, empty when piped in from curl.
SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || true)"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --user)
      MODE="user"
      shift
      ;;
    --server)
      MODE="server"
      shift
      ;;
    -h | --help)
      cat <<EOF
Usage: $0 [--user|--server]

  --user      Install for current user (default).
              Default install path on macOS: ~/.config/sentinelone/
              Default install path on Linux: ~/.config/sentinelone/

  --server    Install on a Linux VM as a shared service.
              System path: /etc/s1-secops-mcp/
              systemd unit: s1-secops-mcp.service
              Requires sudo.

  Image:      $IMAGE_REF

EOF
      exit 0
      ;;
    *) die "Unknown flag: $1 (try --help)" ;;
  esac
done

OS="$(uname -s)"
case "$OS" in
  Darwin) PLATFORM="mac" ;;
  Linux) PLATFORM="linux" ;;
  *)
    c_red "Unsupported platform: $OS"
    exit 2
    ;;
esac

if [[ "$MODE" == "server" && "$PLATFORM" != "linux" ]]; then
  die "--server mode is Linux only (got $PLATFORM)"
fi

# ─── prereqs ─────────────────────────────────────────────────────────────────

step "Checking prerequisites"

if ! command -v docker >/dev/null 2>&1; then
  c_red "Docker is required but not found on PATH."
  c_red "Install it:"
  c_red "  macOS:  https://www.docker.com/get-started/ (Docker Desktop)"
  c_red "  Linux:  curl -fsSL https://get.docker.com | sudo sh"
  exit 3
fi
ok "$(docker --version)"

if ! docker info >/dev/null 2>&1; then
  c_red "The Docker daemon is not reachable."
  c_red "  macOS:  start Docker Desktop and wait for the whale icon to settle."
  c_red "  Linux:  sudo systemctl start docker"
  c_red "If you are not root, your user must be in the 'docker' group."
  exit 3
fi
ok "docker daemon reachable"

if [[ "$MODE" == "server" ]]; then
  if [[ "$EUID" -ne 0 ]]; then
    die "--server mode must be run with sudo (need to create /etc/s1-secops-mcp/, system user, and systemd unit)."
  fi
  command -v systemctl >/dev/null 2>&1 || die "systemctl not found; this script targets systemd-based Linux."
  ok "running as root, systemd present"
fi

# ─── pull image ──────────────────────────────────────────────────────────────

step "Pulling $IMAGE_REF"
docker pull "$IMAGE_REF" >/dev/null || die "docker pull $IMAGE_REF failed. The image is public on Docker Hub and needs no login, so check network access to docker.io and the tag spelling."
ok "$(docker image inspect --format '{{index .RepoDigests 0}}' "$IMAGE_REF" 2>/dev/null || echo "$IMAGE_REF")"

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
  cat >"$CRED_PATH" <<'EOF'
{
  "S1_CONSOLE_URL":       "https://usea1-acme.sentinelone.net",
  "S1_CONSOLE_API_TOKEN": "REPLACE_WITH_API_TOKEN",
  "S1_HEC_INGEST_URL":    "https://ingest.us1.sentinelone.net"
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
      # No openssl on the box: same 32 bytes of kernel entropy, hex-encoded
      # with coreutils only.
      TOKEN_ADMIN="$(head -c 32 /dev/urandom | od -An -v -tx1 | tr -d ' \n')"
    fi
    [[ ${#TOKEN_ADMIN} -eq 64 ]] || die "bearer token generation produced ${#TOKEN_ADMIN} chars, expected 64."
    cat >"$TOKEN_PATH" <<EOF
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
    cat >"$ENV_PATH" <<EOF
# Environment file for s1-secops-mcp.service, read by systemd.
# Set S1_MCP_IMAGE here to override the image tag pinned in the unit, e.g.
#   S1_MCP_IMAGE=sentinelone/secops-skills:1.4.6
# Apply any change here with: systemctl restart s1-secops-mcp
# (systemd only re-reads EnvironmentFile on restart; reload/SIGHUP re-reads
#  bearer tokens only.)
EOF
    chmod 600 "$ENV_PATH"
    chown "$OWNER":"$OWNER" "$ENV_PATH"
    ok "wrote $ENV_PATH"
  else
    ok "$ENV_PATH already exists"
  fi

  step "Installing systemd unit"
  SVC_PATH="/etc/systemd/system/$CONTAINER_NAME.service"
  UNIT_SRC="$SELF_DIR/systemd/$CONTAINER_NAME.service"
  if [[ -n "$SELF_DIR" && -f "$UNIT_SRC" ]]; then
    # Running from a checkout: the repo copy wins.
    install -m 0644 "$UNIT_SRC" "$SVC_PATH"
    ok "installed $SVC_PATH from $UNIT_SRC"
  else
    # Piped in from curl: write the equivalent unit inline. Keep this in sync
    # with deploy/systemd/s1-secops-mcp.service.
    cat >"$SVC_PATH" <<EOF
[Unit]
Description=SentinelOne MCP server (Streamable HTTP, team-shared)
Documentation=https://github.com/pmoses-s1/s1-secops-skills/tree/main/s1-secops-mcp
After=network-online.target docker.service
Wants=network-online.target
Requires=docker.service

[Service]
Type=simple

# Pinned image. Override S1_MCP_IMAGE in server.env to move versions without
# editing this unit.
Environment=S1_MCP_IMAGE=$IMAGE_REF

# Credentials and bearer tokens live in /etc/s1-secops-mcp, bind mounted
# read-only into the container. Bearer tokens rotate via \`systemctl reload\`
# (SIGHUP, no dropped connections); credentials.json is read once at startup
# so changes to it require \`systemctl restart\`.
EnvironmentFile=/etc/s1-secops-mcp/server.env

# A container left behind by an unclean shutdown would make \`--name\` collide.
ExecStartPre=-/usr/bin/docker rm -f $CONTAINER_NAME

# The server binds 0.0.0.0 inside the container's own network namespace, and
# the port is published only to host loopback.
ExecStart=/usr/bin/docker run --rm --name $CONTAINER_NAME \\
  --cap-drop ALL \\
  --security-opt no-new-privileges \\
  -v /etc/s1-secops-mcp:/etc/s1-secops-mcp:ro \\
  -e MCP_BEARER_TOKENS_FILE=/etc/s1-secops-mcp/bearer-tokens.json \\
  -e S1_CREDS_FILE=/etc/s1-secops-mcp/credentials.json \\
  -p 127.0.0.1:8765:8765 \\
  \${S1_MCP_IMAGE} \\
  s1-secops-mcp \\
  --transport http \\
  --host 0.0.0.0 \\
  --port 8765 \\
  --path /mcp

# Signal the container, not \$MAINPID: the unit's main process is the docker
# client and the server is PID 1 inside the container.
ExecReload=/usr/bin/docker kill --signal=HUP $CONTAINER_NAME
ExecStop=-/usr/bin/docker stop --time=10 $CONTAINER_NAME

Restart=on-failure
RestartSec=5

# Hardening for the docker client process. The workload is confined by the
# container flags above. ProtectSystem and ProtectHome are deliberately absent:
# both can cut the client off from /run/docker.sock and /root/.docker.
NoNewPrivileges=true
PrivateTmp=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
SystemCallArchitectures=native

LimitNOFILE=4096
TasksMax=64

StandardOutput=journal
StandardError=journal
SyslogIdentifier=s1-secops-mcp

[Install]
WantedBy=multi-user.target
EOF
    chmod 644 "$SVC_PATH"
    ok "wrote $SVC_PATH"
  fi

  # The unit is what actually runs, so make sure the image it pins is present.
  UNIT_IMAGE="$(sed -n 's/^Environment=S1_MCP_IMAGE=//p' "$SVC_PATH" | tail -n1)"
  if [[ -n "$UNIT_IMAGE" && "$UNIT_IMAGE" != "$IMAGE_REF" ]]; then
    warn "unit pins $UNIT_IMAGE, installer pins $IMAGE_REF; pulling the unit's image as well"
    docker pull "$UNIT_IMAGE" >/dev/null || die "docker pull $UNIT_IMAGE failed."
  fi

  systemctl daemon-reload
  systemctl enable "$CONTAINER_NAME" >/dev/null 2>&1
  ok "enabled the service"

  step "Starting the service"
  if systemctl is-active "$CONTAINER_NAME" >/dev/null 2>&1; then
    systemctl restart "$CONTAINER_NAME"
    ok "restarted"
  else
    systemctl start "$CONTAINER_NAME"
    ok "started"
  fi
  sleep 2
  if systemctl is-active --quiet "$CONTAINER_NAME"; then
    ok "service is active"
  else
    c_red "service failed to start. Recent log lines:"
    journalctl -u "$CONTAINER_NAME" -n 30 --no-pager | sed 's/^/   /'
    exit 1
  fi
fi

# ─── final notes ─────────────────────────────────────────────────────────────

step "Next steps"
if [[ "$MODE" == "user" ]]; then
  cat <<EOF

   1. Edit $CRED_PATH with your real SentinelOne values.
   2. Try the server:
        docker run --rm $IMAGE_REF versions
        docker run -i --rm \\
          -v $CONF_DIR:/etc/s1-secops-mcp:ro \\
          -e S1_CREDS_FILE=/etc/s1-secops-mcp/credentials.json \\
          $IMAGE_REF s1-secops-mcp <<< \\
          '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"smoke","version":"0.1"}}}'
   3. Wire it into Claude Cowork / Claude Desktop / Claude Code over stdio
      (no HTTP needed for single-user local). See deploy/README.md for the
      exact config block.

EOF
elif [[ "$MODE" == "server" ]]; then
  cat <<EOF

   1. Edit $CRED_PATH with your real SentinelOne values, then restart:
        sudo systemctl restart s1-secops-mcp
      (credentials.json is read once at startup; reload/SIGHUP only re-reads
       bearer tokens, so credential changes need a full restart.)
   2. Verify the server is up:
        curl -s http://127.0.0.1:8765/healthz
   3. Put TLS in front:
        sudo curl -fsSL -o /etc/caddy/Caddyfile \\
          https://raw.githubusercontent.com/pmoses-s1/s1-secops-skills/main/s1-secops-mcp/deploy/caddy/Caddyfile.example
        sudo vim /etc/caddy/Caddyfile   # set your DNS name
        sudo systemctl reload caddy
   4. Add team members by editing $TOKEN_PATH and reloading:
        echo '{"admin":"...", "alice":"...", "bob":"..."}' > $TOKEN_PATH
        sudo systemctl reload s1-secops-mcp
      (Reload sends SIGHUP into the container; no connection drops.)
   5. Tail the audit log:
        sudo journalctl -u s1-secops-mcp -f | grep '\[audit\]'

   See deploy/README.md for the full Linux VM walkthrough.

EOF
fi

c_green "Done."
