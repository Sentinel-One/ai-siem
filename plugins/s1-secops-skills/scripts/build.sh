#!/usr/bin/env bash
# build.sh -- build individual .skill files and the combined .plugin for s1-secops-skills
#
# Usage (run from anywhere inside the plugin):
#   ./scripts/build.sh            # build everything into dist/
#   ./scripts/build.sh --clean    # remove old artifacts from dist/ first, then build
#
# Layout (all 8 skills live under <plugin>/skills/, single source of truth):
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
    soc-investigator
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

# tests/ and evals/ are maintainer tooling (CI invariants, eval fixtures). They
# stay in the repo but do not ship, EXCEPT files the skill's own top-level .md
# files (SKILL.md, README.md) or references/ name as user tools (e.g. mgmt-console-api's
# reversible lifecycle tests, powerquery's tests/live/pq_live_cases.json). The keep-list
# is derived from those docs on every build, so citing a test in SKILL.md is what ships it.
prune_dev_files() {
    local d="$1" keep rel f
    # `|| true`: a skill that cites no test file makes grep exit 1, which set -e would turn into a failed build.
    keep="$( { grep -rhoE '(tests|evals)/[A-Za-z0-9_./-]*[A-Za-z0-9_]' "$d"/*.md "$d/references" 2>/dev/null || true; } | sort -u)"
    for sub in tests evals; do
        [ -d "$d/$sub" ] || continue
        while IFS= read -r -d '' f; do
            rel="${f#"$d"/}"
            printf '%s\n' "$keep" | grep -qxF "$rel" || rm -f "$f"
        done < <(find "$d/$sub" -type f -print0)
        find "$d/$sub" -depth -type d -empty -delete 2>/dev/null || true
    done
}

TMP_DIST="$(mktemp -d)"
TMP_PLUGIN="$(mktemp -d)"
trap 'rm -rf "$TMP_DIST" "$TMP_PLUGIN"' EXIT

echo "Building individual .skill files..."
for s in "${SOURCE_SKILLS[@]}"; do
    [ -d "$SKILLS_DIR/$s" ] || { echo "  ERROR: $SKILLS_DIR/$s not found" >&2; exit 1; }
    tmp="$(mktemp -d)"
    cp -rL "$SKILLS_DIR/$s" "$tmp/$s"
    prune_dev_files "$tmp/$s"
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
    prune_dev_files "$TMP_PLUGIN/skills/$s"
done
strip_tree "$TMP_PLUGIN"
(cd "$TMP_PLUGIN" && zip -qr "$TMP_DIST/$PLUGIN_FILENAME" . \
    -x ".git/*" "*.orig" "*.bak" ".DS_Store" "*/__pycache__/*" "*.pyc" \
       "*/baselines/*" "*/reports/*" "*/charts/*")

[[ "${1:-}" == "--clean" ]] && rm -f "$DIST_DIR"/*.skill "$DIST_DIR"/*.plugin
mkdir -p "$DIST_DIR"
cp "$TMP_DIST"/*.skill "$TMP_DIST"/*.plugin "$DIST_DIR/"

# Always drop superseded versioned plugin files so dist/ carries exactly one
# .plugin (the current version). Rebuilding the SAME version overwrites in
# place; a version bump would otherwise leave the old file sitting next to
# the new one until someone remembered --clean.
for old_plugin in "$DIST_DIR"/s1-secops-skills-v*.plugin; do
    [ -e "$old_plugin" ] || continue
    if [[ "$(basename "$old_plugin")" != "$PLUGIN_FILENAME" ]]; then
        echo "  Removing superseded $(basename "$old_plugin")"
        rm -f "$old_plugin"
    fi
done

echo "Done. Contents of dist/:"
ls -lh "$DIST_DIR"
