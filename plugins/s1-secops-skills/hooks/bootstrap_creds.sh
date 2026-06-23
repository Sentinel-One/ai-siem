#!/usr/bin/env bash
# SentinelOne plugin SessionStart hook.
# Runs automatically at the start of every Claude session so SentinelOne
# skills find credentials without prompting the user.
#
# Source (priority order):
#   1. $COWORK_WORKSPACE/credentials.json                    (recommended)
#   2. $HOME/mnt/<folder>/credentials.json                   (any Cowork-accessible folder)
#   3. $COWORK_WORKSPACE/.sentinelone/credentials.json       (legacy)
#   4. $COWORK_WORKSPACE/.claude/sentinelone/credentials.json (legacy)
#   5. $HOME/mnt/<folder>/.sentinelone/credentials.json       (legacy)
#   6. $HOME/mnt/<folder>/.claude/sentinelone/credentials.json (legacy)
#   7. $HOME/.config/sentinelone/credentials.json             (host terminal fallback)
#
# Destination: $HOME/.claude/sentinelone/credentials.json
#   In the Cowork bash sandbox this resolves to
#   /sessions/<id>/.claude/sentinelone/credentials.json — sandbox-local,
#   ephemeral per session, readable by every S1 skill script and CLI.
#
# Idempotent. Silent on success unless DEBUG=1. Never fails the session.

set -u

DEST="$HOME/.claude/sentinelone/credentials.json"
DEST_DIR="$(dirname "$DEST")"

log() { [ "${DEBUG:-0}" = "1" ] && echo "[s1-bootstrap] $*" >&2 || true; }

# Already populated this session — skip.
if [ -s "$DEST" ]; then
    log "creds already present at $DEST"
    exit 0
fi

mkdir -p "$DEST_DIR" 2>/dev/null || true
chmod 700 "$DEST_DIR" 2>/dev/null || true

shopt -s nullglob 2>/dev/null || true

candidates=()
# New (recommended) — credentials.json directly in the project folder.
if [ -n "${COWORK_WORKSPACE:-}" ]; then
    candidates+=("$COWORK_WORKSPACE/credentials.json")
fi
for mnt in "$HOME"/mnt/*/; do
    base="$(basename "$mnt")"
    case "$base" in
        .claude|.auto-memory|.remote-plugins|outputs|uploads) continue ;;
    esac
    candidates+=("${mnt}credentials.json")
done
# Legacy layouts — kept for backwards compatibility.
if [ -n "${COWORK_WORKSPACE:-}" ]; then
    candidates+=("$COWORK_WORKSPACE/.sentinelone/credentials.json")
    candidates+=("$COWORK_WORKSPACE/.claude/sentinelone/credentials.json")
fi
for mnt in "$HOME"/mnt/*/; do
    base="$(basename "$mnt")"
    case "$base" in
        .claude|.auto-memory|.remote-plugins|outputs|uploads) continue ;;
    esac
    candidates+=("$mnt.sentinelone/credentials.json")
    candidates+=("$mnt.claude/sentinelone/credentials.json")
done
# Host terminal fallback (Claude Code CLI without Cowork).
candidates+=("$HOME/.config/sentinelone/credentials.json")

for src in "${candidates[@]}"; do
    if [ -f "$src" ]; then
        cp "$src" "$DEST" 2>/dev/null && {
            chmod 600 "$DEST" 2>/dev/null || true
            log "copied $src -> $DEST"
            exit 0
        }
    fi
done

log "no credentials.json found in workspace, mounts, or host config"
# Do not fail the session — skills can still prompt for creds interactively.
exit 0
