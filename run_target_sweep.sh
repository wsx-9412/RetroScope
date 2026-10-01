#!/bin/bash
# run_target_sweep.sh
# Sweep every libtiff version OLDER than the reference through run_analysis.sh.
#
# For each target version (descending: the version immediately below the
# reference first, then older ones), the script:
#   1. rewrites TARGET_VERSION_PATH (and pins REFERENCE_VERSION_PATH) in
#      run_analysis.sh,
#   2. runs ./run_analysis.sh config_libtiff.py,
#   3. writes the log to results/version_sweep/<target>.log and a .done marker
#      when the run reaches "Analysis completed".
#
# Failed runs get no marker and are reported at the end (re-running the script
# retries them).  At the end the target is restored to the initial version.
#
# Usage:  ./run_target_sweep.sh
#         (optionally: CONFIG=config_libtiff.py ./run_target_sweep.sh)

set -u
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$BASE_DIR"

CONFIG="${CONFIG:-config_libtiff.py}"
REF_NAME="${REF_NAME:-tiff-4.0.9}"
REF_DIR="tiff-versions/$REF_NAME"
INITIAL_TARGET="${INITIAL_TARGET:-tiff-4.0.8}"
SWEEP_DIR="$BASE_DIR/results/version_sweep"
mkdir -p "$SWEEP_DIR"

if [ ! -d "$REF_DIR" ]; then
    echo "reference dir not found: $REF_DIR"; exit 1
fi

# all versions strictly older than the reference, newest first
mapfile -t TARGETS < <(
    printf '%s\n' tiff-versions/tiff-* \
    | sed 's|.*/||' | sort -V \
    | awk -v ref="$REF_NAME" 'BEGIN{f=1}{if($0==ref){f=0;next} if(f) print}' \
    | tac
)
if [ "${#TARGETS[@]}" -eq 0 ]; then
    echo "no target versions older than $REF_NAME"; exit 1
fi

echo "[*] reference : $REF_NAME"
echo "[*] config    : $CONFIG"
echo "[*] targets   : ${TARGETS[*]}"
echo "[*] logs      : $SWEEP_DIR"
echo

for T in "${TARGETS[@]}"; do
    TDIR="tiff-versions/$T"
    [ -d "$TDIR" ] || { echo "[skip] $T (dir missing)"; continue; }
    MARK="$SWEEP_DIR/${T}.done"
    LOG="$SWEEP_DIR/${T}.log"
    if [ -f "$MARK" ]; then
        echo "[skip] $T (already completed: $MARK)"
        continue
    fi
    echo "=============================================================="
    echo "[run ] target=$T  reference=$REF_NAME  $(date '+%F %T')"
    echo "=============================================================="

    # rewrite the version parameters in run_analysis.sh for this iteration
    sed -i "s|TARGET_VERSION_PATH=\"\$BASE_DIR/tiff-versions/[^\"]*\"|TARGET_VERSION_PATH=\"\$BASE_DIR/tiff-versions/$T\"|" run_analysis.sh
    sed -i "s|REFERENCE_VERSION_PATH=\"\$BASE_DIR/tiff-versions/[^\"]*\"|REFERENCE_VERSION_PATH=\"\$BASE_DIR/tiff-versions/$REF_NAME\"|" run_analysis.sh

    ./run_analysis.sh "$CONFIG" > "$LOG" 2>&1
    rc=$?
    echo "exit_code=$rc" >> "$LOG"

    if grep -q 'Analysis completed' "$LOG"; then
        touch "$MARK"
        echo "[done] $T (rc=$rc, $(grep -m1 'total time' "$LOG" | sed 's/^ *//'))"
    else
        echo "[FAIL] $T (rc=$rc) — last log line:"
        tail -n 1 "$LOG" | sed 's/^/       /'
    fi
done

# restore the initial target in run_analysis.sh
sed -i "s|TARGET_VERSION_PATH=\"\$BASE_DIR/tiff-versions/[^\"]*\"|TARGET_VERSION_PATH=\"\$BASE_DIR/tiff-versions/$INITIAL_TARGET\"|" run_analysis.sh
sed -i "s|REFERENCE_VERSION_PATH=\"\$BASE_DIR/tiff-versions/[^\"]*\"|REFERENCE_VERSION_PATH=\"\$BASE_DIR/tiff-versions/$REF_NAME\"|" run_analysis.sh

# per-target summary
SUMMARY="$SWEEP_DIR/summary.txt"
{
    echo "reference: $REF_NAME"
    printf '%-24s %-8s %-10s %-34s %s\n' TARGET STATUS OFFSETS "ROOT-CAUSE" "MUTATION(note)"
    for T in "${TARGETS[@]}"; do
        LOG="$SWEEP_DIR/${T}.log"
        [ -f "$LOG" ] || continue
        if [ -f "$SWEEP_DIR/${T}.done" ]; then STATUS=ok; else STATUS=FAIL; fi
        RC_FN=$(grep -m1 'Root cause function:' "$LOG" \
                | sed 's/^ *Root cause function: *//')
        RC_LOC=$(grep -m1 'Root cause location:' "$LOG" \
                | sed 's/^ *Root cause location: *//')
        DYN=$(grep -m1 'Dynamic origin trace input offsets:' "$LOG" \
                | sed 's/.*: *//')
        MUT=$(grep -m1 'dynamic-offset mutation matches:' "$LOG" \
                | sed 's/.*matches: *//; s/ .*//')
        LEG=$(grep -c 'MATCH SUMMARY' "$LOG")
        printf '%-24s %-8s %-10s %-34s %s\n' \
            "$T" "$STATUS" "${DYN:-?}" "${RC_FN:-?} ${RC_LOC:-?}" \
            "dyn-matches=${MUT:-?} legacy-match-summary=${LEG}"
    done
} > "$SUMMARY"

echo
echo "[*] sweep finished $(date '+%F %T')"
echo "[*] summary: $SUMMARY"
cat "$SUMMARY"
