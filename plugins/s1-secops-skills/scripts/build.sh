#!/usr/bin/env bash
# build.sh -- build individual .skill files and the combined .plugin for s1-secops-skills
#
# Usage (run from anywhere inside the plugin):
#   ./scripts/build.sh            # build everything into dist/
#   ./scripts/build.sh --clean    # remove old artifacts from dist/ first, then build
#
# Layout (all 7 skills live under <plugin>/skills/, single source of truth):
#   plugins/s1-secops-skills/
#     .claude-plugin/plugin.json
#     skills/<skill>/SKILL.md ...
#     hooks/  scripts/build.sh  dist/
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLUGIN_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
SKILLS_DIR="$PLUGIN_DIR/skills"
DIST_DIR="$PLUGIN_DIR/dist"

SOURCE_SKILLS=(
    mgmt-console-api
    powerquery
    sdl-api
    sdl-dashboard
    sdl-log-parser
    sdl-solutions
    hyperautomation
)

PLUGIN_JSON="$PLUGIN_DIR/.claude-plugin/plugin.json"
[ -f "$PLUGIN_JSON" ] || { echo "ERROR: $PLUGIN_JSON not found" >&2; exit 1; }
VERSION="$(python3 -c "import json; print(json.load(open('$PLUGIN_JSON'))['version'])")"
echo "Building s1-secops-skills v$VERSION  (skills dir: $SKILLS_DIR)"

# Sync the one shared reference: lrq-api.md lives in powerquery and is
# referenced by mgmt-console-api and sdl-api. Copy it so each skill stays
# self-contained inside its .skill bundle.
LRQ_SRC="$SKILLS_DIR/powerquery/references/lrq-api.md"
for s in mgmt-console-api sdl-api; do
    [ -f "$LRQ_SRC" ] && cp "$LRQ_SRC" "$SKILLS_DIR/$s/references/lrq-api.md"
done

strip_tree() {
    find "$1" \( -type d -name baselines -o -type d -name __pycache__ \
                 -o -type d -name reports -o -type d -name charts \) \
        -prune -exec rm -rf {} + 2>/dev/null || true
    find "$1" \( -name '*.pyc' -o -name '.DS_Store' -o -name '*.tmp' \
                 -o -name '*.log' -o -name '*.bak' -o -name '*.orig' \) \
        -delete 2>/dev/null || true
}

TMP_DIST="$(mktemp -d)"
TMP_PLUGIN="$(mktemp -d)"
trap 'rm -rf "$TMP_DIST" "$TMP_PLUGIN"' EXIT

echo "Building individual .skill files..."
for s in "${SOURCE_SKILLS[@]}"; do
    [ -d "$SKILLS_DIR/$s" ] || { echo "  ERROR: $SKILLS_DIR/$s not found" >&2; exit 1; }
    tmp="$(mktemp -d)"
    cp -rL "$SKILLS_DIR/$s" "$tmp/$s"
    strip_tree "$tmp/$s"
    (cd "$tmp" && zip -qr "$TMP_DIST/$s.skill" "$s/")
    rm -rf "$tmp"
    echo "  $s.skill"
done

echo "Building combined plugin..."
PLUGIN_FILENAME="s1-secops-skills-v${VERSION}.plugin"
cp -r "$PLUGIN_DIR/.claude-plugin" "$TMP_PLUGIN/"
[ -d "$PLUGIN_DIR/hooks" ] && cp -r "$PLUGIN_DIR/hooks" "$TMP_PLUGIN/"
mkdir -p "$TMP_PLUGIN/skills"
for s in "${SOURCE_SKILLS[@]}"; do
    cp -rL "$SKILLS_DIR/$s" "$TMP_PLUGIN/skills/"
done
strip_tree "$TMP_PLUGIN"
(cd "$TMP_PLUGIN" && zip -qr "$TMP_DIST/$PLUGIN_FILENAME" . \
    -x ".git/*" "*.orig" "*.bak" ".DS_Store" "*/__pycache__/*" "*.pyc" \
       "*/baselines/*" "*/reports/*" "*/charts/*")

[[ "${1:-}" == "--clean" ]] && rm -f "$DIST_DIR"/*.skill "$DIST_DIR"/*.plugin
mkdir -p "$DIST_DIR"
cp "$TMP_DIST"/*.skill "$TMP_DIST"/*.plugin "$DIST_DIR/"

echo "Done. Contents of dist/:"
ls -lh "$DIST_DIR"
