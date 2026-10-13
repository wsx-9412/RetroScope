#!/bin/bash

REPO_DIR="/home/ws/Desktop/RetroScope"
LOG_FILE="/home/ws/Desktop/RetroScope/sync.log"
PROXY_PY="/home/ws/Desktop/RetroScope/build/github_proxy.py"
PROXY_LOG="/tmp/retroscope_ghproxy.log"
DEBOUNCE_SECONDS=3
PROXY_ADDR="http://127.0.0.1:8888"

cd "$REPO_DIR" || exit 1
echo "[$(date)] Auto-sync started, watching $REPO_DIR" >> "$LOG_FILE"

# git is told to use the local CONNECT proxy (github.com DNS resolves to a
# blocked IP on this host; the proxy tunnels to a reachable GitHub IP)
git config http.proxy "$PROXY_ADDR"
git config http.postBuffer 524288000

ensure_proxy() {
    if ! pgrep -f "github_proxy.py" >/dev/null 2>&1; then
        echo "[$(date)] (re)starting github proxy" >> "$LOG_FILE"
        nohup python3 "$PROXY_PY" >"$PROXY_LOG" 2>&1 &
        sleep 1
    fi
}

sync_now() {
    ensure_proxy
    cd "$REPO_DIR" || return 1
    # .gitignore excludes the big *-versions/ trees and build artifacts, so this
    # only stages the small, valuable content (PoCs, scripts, docs, configs).
    git add -A 2>/dev/null
    CHANGES=$(git status --porcelain 2>/dev/null)
    if [ -n "$CHANGES" ]; then
        TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
        if git commit -q -m "Auto-sync: $TIMESTAMP" >> "$LOG_FILE" 2>&1; then
            # retry the push a few times: the tunnel to GitHub can be flaky
            for attempt in 1 2 3 4 5; do
                if git push origin main >> "$LOG_FILE" 2>&1; then
                    echo "[$(date)] push OK (attempt $attempt)" >> "$LOG_FILE"
                    return 0
                fi
                ensure_proxy
                sleep 5
            done
            echo "[$(date)] ERROR: push failed after 5 attempts" >> "$LOG_FILE"
        else
            echo "[$(date)] ERROR: commit failed" >> "$LOG_FILE"
        fi
    fi
}

LAST_SYNC=0

inotifywait -m -r -e modify,create,delete,move \
    --exclude '(\.git/|__pycache__/|\.pyc$|\.so$|polytracker/|results/|\.tdag$|binutils-versions/|giflib-versions/|libxml2-versions/|freetype-versions/|third_party/)' \
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
