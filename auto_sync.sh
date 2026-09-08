#!/bin/bash

REPO_DIR="/home/ws/Desktop/RetroScope"
LOG_FILE="/home/ws/Desktop/RetroScope/sync.log"
DEBOUNCE_SECONDS=3

cd "$REPO_DIR" || exit 1

echo "[$(date)] Auto-sync started, watching $REPO_DIR" >> "$LOG_FILE"

sync_now() {
    cd "$REPO_DIR" || return 1
    git add -A -- ':!polytracker/' ':!polytracker.tdag' ':!results/' ':!{output}' ':!out.mp3' 2>/dev/null
    CHANGES=$(git status --porcelain 2>/dev/null)
    if [ -n "$CHANGES" ]; then
        TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
        git commit -m "Auto-sync: $TIMESTAMP" 2>> "$LOG_FILE"
        git push origin main 2>> "$LOG_FILE"
        echo "[$(date)] Changes pushed successfully" >> "$LOG_FILE"
    fi
}

LAST_SYNC=0

inotifywait -m -r -e modify,create,delete,move \
    --exclude '(\.git/|__pycache__/|\.pyc$|\.so$|polytracker/|results/|\.tdag$)' \
    "$REPO_DIR" 2>/dev/null |
while read -r directory event filename; do
    NOW=$(date +%s)
    DIFF=$((NOW - LAST_SYNC))
    if [ "$DIFF" -ge "$DEBOUNCE_SECONDS" ]; then
        sleep "$DEBOUNCE_SECONDS"
        sync_now
        LAST_SYNC=$(date +%s)
    fi
done
