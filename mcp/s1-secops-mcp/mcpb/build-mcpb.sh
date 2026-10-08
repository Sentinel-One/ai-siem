#!/usr/bin/env bash
# Build the optional Claude Desktop Extension (.mcpb) for s1-secops-mcp.
#
# Output: s1-secops-mcp/dist/s1-secops-mcp-<version>.mcpb
#
# Layout inside the archive:
#   manifest.json        from mcpb/manifest.json
#   CLAUDE.md            repo-root SOC analyst persona (default for the soc_analyst prompt)
#   LICENSE
#   server/index.js, server/lib/, server/tools/, server/package.json,
#   server/README.md, server/CHANGELOG.md
# Never staged: tests/, data/, scripts/, node_modules/, any credential file.
#
# Packing (MCPB_PACKER):
#   auto    (default) local `mcpb` CLI if on PATH, else the official CLI in a
#           Node container via Docker, else a plain zip (with a warning).
#   local   `mcpb` from PATH (npm install -g @anthropic-ai/mcpb).
#   docker  `npx @anthropic-ai/mcpb@$MCPB_CLI_VERSION` inside $MCPB_NODE_IMAGE.
#   zip     plain zip, no official validation. Validate separately.
#
# Environment:
#   MCPB_CLI_VERSION   official CLI version for the docker packer (default 2.1.2)
#   MCPB_NODE_IMAGE    container image for the docker packer (default node:24-trixie-slim)
#   MCPB_NPM_REGISTRY  npm registry for the docker packer when registry.npmjs.org is
#                      blocked, e.g. https://registry.yarnpkg.com/
#   KEEP_STAGE=1       keep dist/.stage after the build for inspection
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MCP_DIR="$(cd "$HERE/.." && pwd)"
REPO_DIR="$(cd "$MCP_DIR/.." && pwd)"
DIST="$MCP_DIR/dist"
STAGE="$DIST/.stage"
PACKER="${MCPB_PACKER:-auto}"
MCPB_CLI_VERSION="${MCPB_CLI_VERSION:-2.1.2}"
NODE_IMAGE="${MCPB_NODE_IMAGE:-node:24-trixie-slim}"

die() { echo "build-mcpb: $*" >&2; exit 1; }
command -v node >/dev/null || die "node is required (for the version and tool-list checks)"

cleanup() { [ "${KEEP_STAGE:-0}" = "1" ] || rm -rf "$STAGE"; }
trap cleanup EXIT

# ---- 1. Consistency checks -------------------------------------------------
PKG_VERSION="$(node -p "require('$MCP_DIR/package.json').version")"
MAN_VERSION="$(node -p "require('$HERE/manifest.json').version")"
[ "$PKG_VERSION" = "$MAN_VERSION" ] || die "manifest version $MAN_VERSION != package.json version $PKG_VERSION"
VERSION="$PKG_VERSION"

# The manifest's tools array must match what the server registers, name for name.
( cd "$MCP_DIR" && S1_KEYCHAIN=off node --input-type=module -e "
  const { TOOL_DEFS } = await import('./lib/server-core.js');
  const { readFileSync } = await import('fs');
  const man = JSON.parse(readFileSync('$HERE/manifest.json', 'utf-8'));
  const a = TOOL_DEFS.map(t => t.name).sort();
  const b = man.tools.map(t => t.name).sort();
  const missing = a.filter(n => !b.includes(n));
  const extra = b.filter(n => !a.includes(n));
  if (missing.length || extra.length) {
    console.error('manifest tools out of sync. missing: ' + missing.join(', ') + ' extra: ' + extra.join(', '));
    process.exit(1);
  }
  console.log('tools: ' + a.length + ' in manifest match the server registry');
" ) || die "fix mcpb/manifest.json tools[]"

# ---- 2. Stage ----------------------------------------------------------------
rm -rf "$STAGE"
mkdir -p "$STAGE/server"
cp "$HERE/manifest.json" "$STAGE/manifest.json"
cp "$REPO_DIR/CLAUDE.md" "$STAGE/CLAUDE.md"
cp "$REPO_DIR/LICENSE" "$STAGE/LICENSE"
cp "$MCP_DIR/index.js" "$MCP_DIR/package.json" "$MCP_DIR/README.md" "$MCP_DIR/CHANGELOG.md" "$STAGE/server/"
mkdir -p "$STAGE/server/lib" "$STAGE/server/tools"
cp "$MCP_DIR"/lib/*.js "$STAGE/server/lib/"
cp "$MCP_DIR"/tools/*.js "$STAGE/server/tools/"

# Normalise modes: the archive keeps file modes, and a 0600 file breaks a
# different-user install. Directories 755, files 644, entry point 755.
find "$STAGE" -type d -exec chmod 755 {} +
find "$STAGE" -type f -exec chmod 644 {} +
chmod 755 "$STAGE/server/index.js"

# Refuse to pack anything that looks like a credential or tenant data.
BAD="$(cd "$STAGE" && find . \( -name 'credentials.json*' -o -name '*.env' -o -name '.env*' \
        -o -name '*.pem' -o -name '*.key' -o -name '*.bak*' -o -name '*.log' \
        -o -path './server/tests*' -o -path './server/data*' -o -name node_modules \) -print)"
[ -z "$BAD" ] || die "refusing to pack sensitive or test files: $BAD"

# ---- 3. Pack -----------------------------------------------------------------
OUT="$DIST/s1-secops-mcp-$VERSION.mcpb"
rm -f "$OUT"

pack_local() {
  mcpb validate "$STAGE/manifest.json"
  mcpb pack "$STAGE" "$OUT"
  mcpb info "$OUT"
}

pack_docker() {
  local reg=()
  [ -n "${MCPB_NPM_REGISTRY:-}" ] && reg=(-e "npm_config_registry=$MCPB_NPM_REGISTRY")
  docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp -e npm_config_update_notifier=false \
    ${reg[@]+"${reg[@]}"} -v "$DIST:/w" -w /w "$NODE_IMAGE" sh -ec "
      npx -y @anthropic-ai/mcpb@$MCPB_CLI_VERSION --version
      npx -y @anthropic-ai/mcpb@$MCPB_CLI_VERSION validate /w/.stage/manifest.json
      npx -y @anthropic-ai/mcpb@$MCPB_CLI_VERSION pack /w/.stage /w/$(basename "$OUT")
      npx -y @anthropic-ai/mcpb@$MCPB_CLI_VERSION info /w/$(basename "$OUT")
    "
}

pack_zip() {
  command -v zip >/dev/null || die "zip not found"
  echo "build-mcpb: WARNING plain zip, the manifest was NOT checked by the official mcpb CLI" >&2
  ( cd "$STAGE" && zip -X -q -r "$OUT" . )
}

case "$PACKER" in
  local)  pack_local ;;
  docker) pack_docker ;;
  zip)    pack_zip ;;
  auto)
    if command -v mcpb >/dev/null; then pack_local
    elif command -v docker >/dev/null && docker info >/dev/null 2>&1; then pack_docker
    else pack_zip
    fi ;;
  *) die "unknown MCPB_PACKER=$PACKER (auto|local|docker|zip)" ;;
esac

[ -s "$OUT" ] || die "no archive produced"
echo
echo "Built $OUT"
if command -v shasum >/dev/null; then shasum -a 256 "$OUT"; elif command -v sha256sum >/dev/null; then sha256sum "$OUT"; fi
