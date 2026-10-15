#!/bin/bash
# run_analysis.sh
# Integrated fork-point analysis: compile two versions, read the config's
# execution command, then run lcs_trace.py to locate the fork statement.
#
# Usage:
#   ./run_analysis.sh config_libtiff.py              # GDB only (default)
#   ./run_analysis.sh config_libtiff.py -pt          # polytracker only
#   ./run_analysis.sh config_libtiff.py -full        # GDB + polytracker
#   ./run_analysis.sh config_lame.py
#   ./run_analysis.sh config_audiofile.py
#   ./run_analysis.sh config_jasper.py
#   ./run_analysis.sh config_libxml2.py
#   ./run_analysis.sh config_giflib.py
#   ./run_analysis.sh config_binutils.py
#   ./run_analysis.sh config_freetype.py

PROJECT_CONFIG="${1:-config_libtiff.py}"
GDB_MODE=true      # Default: GDB mode (full pipeline)
POLYTRACKER_MODE=false
FULL_MODE=false
DEPRECATED_GDB=false
shift
while [ $# -gt 0 ]; do
    case "$1" in
        -gdb) 
            DEPRECATED_GDB=true
            GDB_MODE=true
            ;;
        -gdb-only) 
            DEPRECATED_GDB=true
            GDB_MODE=true
            ;;
        -pt) 
            POLYTRACKER_MODE=true
            GDB_MODE=false
            ;;
        -full) 
            FULL_MODE=true
            GDB_MODE=true
            ;;
    esac
    shift
done

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$BASE_DIR"

PROJECT_NAME=$(basename "$PROJECT_CONFIG" .py | sed 's/config_//')
INPUT_FILE_DIR="$BASE_DIR/in"
CONFIG_MODULE="$PROJECT_CONFIG"

# Per-project: reference/target version paths + default input file
case "$PROJECT_NAME" in
    "libtiff")
        REFERENCE_VERSION_PATH="$BASE_DIR/tiff-versions/tiff-4.0.9"
        TARGET_VERSION_PATH="$BASE_DIR/tiff-versions/tiff-4.0.7"
        DEFAULT_INPUT="$INPUT_FILE_DIR/CVE-2022-0891"
        EXTRA_ARGS=(--include-exits --refactor-detect)
        ;;
"lame")
        REFERENCE_VERSION_PATH="$BASE_DIR/lame-versions/lame-3.99.5"
        TARGET_VERSION_PATH="$BASE_DIR/lame-versions/lame-3.98.2"
        DEFAULT_INPUT="$INPUT_FILE_DIR/CVE-2017-15045"
        # lame 3.98 -> 3.99 restructured the frontend (main -> c_main ->
        # lame_main); full call-path matching never aligns, so match by
        # function name instead.
        EXTRA_ARGS=(--match-level name)
        ;;
    "audiofile")
        REFERENCE_VERSION_PATH="$BASE_DIR/audiofile-versions/audiofile-0.3.6"
        TARGET_VERSION_PATH="$BASE_DIR/audiofile-versions/audiofile-0.2.7"
        DEFAULT_INPUT="$INPUT_FILE_DIR/CVE-2017-6831"
        EXTRA_ARGS=(--include-exits)
        ;;
    "jasper")
        REFERENCE_VERSION_PATH="$BASE_DIR/jasper-versions/jasper-version-2.0.33"
        TARGET_VERSION_PATH="$BASE_DIR/jasper-versions/jasper-version-2.0.32"
        DEFAULT_INPUT="$INPUT_FILE_DIR/CVE-2021-26926"
        EXTRA_ARGS=(--include-exits)
        ;;
    # Convention (see lcs_trace/divergence_analyzer): REFERENCE = the version
    # that CRASHES on the CVE's PoC (vulnerable); TARGET = the version where
    # the crash is unreachable (fixed).  The fork is located in the target.
    # For another CVE, update both paths so one version crashes and the other
    # does not, and pick the matching tool in the config's EXECUTION_CONFIG.
    "libxml2")
        REFERENCE_VERSION_PATH="$BASE_DIR/libxml2-versions/libxml2-2.9.4"
        TARGET_VERSION_PATH="$BASE_DIR/libxml2-versions/libxml2-2.9.5"
        DEFAULT_INPUT="$INPUT_FILE_DIR/CVE-2017-9049"
        EXTRA_ARGS=(--include-exits)
        ;;
    "giflib")
        REFERENCE_VERSION_PATH="$BASE_DIR/giflib-versions/giflib-5.2.1"
        TARGET_VERSION_PATH="$BASE_DIR/giflib-versions/giflib-5.2.2"
        DEFAULT_INPUT="$INPUT_FILE_DIR/CVE-2022-28506"
        EXTRA_ARGS=(--include-exits)
        ;;
    "binutils")
        REFERENCE_VERSION_PATH="$BASE_DIR/binutils-versions/binutils-2.26"
        TARGET_VERSION_PATH="$BASE_DIR/binutils-versions/binutils-2.25"
        DEFAULT_INPUT="$INPUT_FILE_DIR/CVE-2018-18605"
        EXTRA_ARGS=(--include-exits)
        ;;
    "freetype")
        REFERENCE_VERSION_PATH="$BASE_DIR/freetype-versions/freetype-2.11.1"
        TARGET_VERSION_PATH="$BASE_DIR/freetype-versions/freetype-2.12.1"
        DEFAULT_INPUT="$INPUT_FILE_DIR/CVE-2022-27404"
        EXTRA_ARGS=(--include-exits)
        ;;
    *)
        echo "Error: unknown project '$PROJECT_NAME'"
        echo "Available: libtiff, lame, audiofile, jasper, libxml2, giflib, binutils, freetype"
        exit 1
        ;;
esac

# Read CVE config from the config file (override defaults if present)
CVE_ID=$(python3 -c "import importlib.util; s=importlib.util.spec_from_file_location('c','$CONFIG_MODULE'); m=importlib.util.module_from_spec(s); s.loader.exec_module(m); print(getattr(m,'CVE_ID','unknown'))")
INPUT_FILE_REL=$(python3 -c "import importlib.util; s=importlib.util.spec_from_file_location('c','$CONFIG_MODULE'); m=importlib.util.module_from_spec(s); s.loader.exec_module(m); print(getattr(m,'INPUT_FILE',''))")
OUTPUT_FILE=$(python3 -c "import importlib.util; s=importlib.util.spec_from_file_location('c','$CONFIG_MODULE'); m=importlib.util.module_from_spec(s); s.loader.exec_module(m); print(getattr(m,'OUTPUT_FILE','/tmp/foo'))")
COMMAND_FORMAT=$(python3 -c "import importlib.util; s=importlib.util.spec_from_file_location('c','$CONFIG_MODULE'); m=importlib.util.module_from_spec(s); s.loader.exec_module(m); print(getattr(m,'COMMAND_FORMAT',''))")

# Resolve input file path (fall back to per-project default if config has none)
if [ -n "$INPUT_FILE_REL" ]; then
    if [[ "$INPUT_FILE_REL" = /* ]]; then
        INPUT_FILE="$INPUT_FILE_REL"
    else
        INPUT_FILE="$BASE_DIR/$INPUT_FILE_REL"
    fi
else
    INPUT_FILE="$DEFAULT_INPUT"
fi

RESULT_FILE="results/${PROJECT_NAME}_fork_result.json"
mkdir -p results
export RETRO_TIMINGS="results/${CVE_ID}_timings.json"

echo "=== ${PROJECT_NAME} fork-point analysis ==="
echo "CVE:           $CVE_ID"
echo "Config:        $CONFIG_MODULE"
echo "Reference:     $REFERENCE_VERSION_PATH"
echo "Target:        $TARGET_VERSION_PATH"
echo "Input:         $INPUT_FILE"
echo "Output:        $OUTPUT_FILE"
if [ "$DEPRECATED_GDB" = true ]; then
    echo "Warning: -gdb/-gdb-only flags are deprecated. GDB is now the default."
    echo "         Use -pt for polytracker only, -full for both GDB and polytracker."
fi
echo "Analysis mode: $([ "$POLYTRACKER_MODE" = true ] && echo "Polytracker" || ([ "$FULL_MODE" = true ] && echo "Full (GDB + Polytracker)" || echo "GDB"))"
echo "Result:        $RESULT_FILE"

if [ ! -f "$CONFIG_MODULE" ]; then
    echo "Error: config file $CONFIG_MODULE does not exist"; exit 1
fi
if [ ! -d "$REFERENCE_VERSION_PATH" ]; then
    echo "Error: reference version dir $REFERENCE_VERSION_PATH does not exist"; exit 1
fi
if [ ! -d "$TARGET_VERSION_PATH" ]; then
    echo "Error: target version dir $TARGET_VERSION_PATH does not exist"; exit 1
fi
if [ ! -f "$INPUT_FILE" ]; then
    echo "Error: input file $INPUT_FILE does not exist"; exit 1
fi

# ============================================================================
# Step 1: Compile + LCS trace + Divergence analysis
# ============================================================================
DIVERGE_JSON="results/${CVE_ID}.diverge.json"

# Always regenerate - delete old diverge JSON
rm -f "$DIVERGE_JSON"
# The dynamic stage's single-byte results are only meaningful for THIS
# target run; delete any stale copy (written by the previous target) so
# the legacy stage below never consumes another version's classification.
rm -f "results/${CVE_ID}_origin_mutation.json"

mkdir -p results
POLYTRACKER_OUTPUT="results/${CVE_ID}.json"

# Build extra arguments
EXTRA_ARGS_STEP1=("${EXTRA_ARGS[@]}")

# Always skip polytracker inside divergence_analyzer: the PolyTracker offset
# localization is handled separately in Step 3 (and GDB offsets in Step 2).
# Running it here too would build/run the instrumented binary twice.
EXTRA_ARGS_STEP1+=(--no-polytracker)

python3 -u run_fork_analysis.py \
    --config "$CONFIG_MODULE" \
    --ref "$REFERENCE_VERSION_PATH" \
    --target "$TARGET_VERSION_PATH" \
    --input "$INPUT_FILE" \
    --output "$POLYTRACKER_OUTPUT" \
    --gdb-timeout 300 \
        "${EXTRA_ARGS_STEP1[@]}"

    if [ $? -ne 0 ]; then
        echo "Fork-point analysis failed!"
        exit 1
    fi

# ============================================================================
# Step 2: GDB dynamic trace - map fork variables to input file offsets
# ============================================================================
if [ "$POLYTRACKER_MODE" = false ]; then
    echo ""
    echo "=== GDB dynamic origin trace (record/replay, fork variables -> input offsets) ==="
    DIVERGE_JSON="results/${CVE_ID}.diverge.json"
    ORIGIN_JSON="results/${CVE_ID}_origin.json"
    if [ ! -f "$DIVERGE_JSON" ]; then
        echo "Error: $DIVERGE_JSON not found"
        exit 1
    fi
    echo "Using divergence result: $DIVERGE_JSON"
    echo "Origin trace result:       $ORIGIN_JSON"
    # Direct dynamic backward tracing of the fork variables.  The tracer
    # records the target execution with GDB, stops at the fork, and walks
    # backwards to the input read/mmap that produced each value.  If the
    # pipeline binary is ASan-instrumented (record-full cannot replay the
    # sanitizer runtime) the tracer builds a -O0 no-ASan trace binary itself.
    python3 -u dynamic_origin_trace.py \
        --diverge-json "$DIVERGE_JSON" \
        --config "$CONFIG_MODULE" \
        --source-dir "$TARGET_VERSION_PATH" \
        --output "$ORIGIN_JSON" \
        --timeout 900 || true

    DYN_OFFSETS=$(python3 -c "import json;d=json.load(open('$ORIGIN_JSON'));print(len(d.get('offsets') or []))" 2>/dev/null || echo 0)
    echo "Dynamic origin trace input offsets: ${DYN_OFFSETS}"

    SKIP_LEGACY=0
    if [ "${DYN_OFFSETS:-0}" != "0" ]; then
        # Validate the dynamically derived offsets by mutating them and
        # checking whether the target reproduces the reference crash.  If it
        # does, the legacy offset+search stage is not needed.
        echo ""
        echo "=== mutation testing on dynamic origin-trace offsets ==="
        python3 -u - "$DIVERGE_JSON" "$ORIGIN_JSON" "results/${CVE_ID}_origin_mutation.json" <<'DYN_MUT_PY'
import json, sys
sys.path.insert(0, '.')
from trace_fork_offsets import test_byte_mutations_compare

diverge_json, origin_json, out_json = sys.argv[1], sys.argv[2], sys.argv[3]
div = json.load(open(diverge_json))
org = json.load(open(origin_json))
offs = set()
for o in (org.get('offsets') or []):
    off, ln = o.get('offset'), o.get('length') or 1
    if off is None:
        continue
    for k in range(off, off + ln):
        offs.add(k)
offs = sorted(offs)[:64]
print('dynamic offsets under test: %s' % ' '.join('0x%x' % o for o in offs),
      flush=True)
if not offs:
    sys.exit(3)
res = test_byte_mutations_compare(
    div.get('binary_b'), div.get('binary_a'), div.get('input_file'),
    div.get('args_b') or [], offs, timeout=60, version=div.get('version_b'))
n = sum(len(i.get('matches') or {})
        for i in res.values() if isinstance(i, dict))
json.dump(res, open(out_json, 'w'), indent=1, default=str)
print('dynamic-offset mutation matches: %d (details: %s)' % (n, out_json),
      flush=True)
sys.exit(0 if n else 3)
DYN_MUT_PY
        if [ $? -eq 0 ]; then
            echo "[*] dynamic origin trace + mutation reproduced the reference crash; legacy stage skipped."
            SKIP_LEGACY=1
        else
            echo "[*] dynamic offsets did not reproduce the crash; falling back to legacy."
        fi
    fi

    if [ "${SKIP_LEGACY:-0}" != "1" ]; then
        echo ""
        echo "=== Legacy GDB offset trace (fallback) ==="
        # Feed the dynamic stage's single-byte classification (when this
        # run produced one) into the legacy tracer: its active/inert
        # offsets extend the two-offset mutation pool and define the
        # interaction pairs.
        ORIGIN_MUT_ARGS=()
        if [ -f "results/${CVE_ID}_origin_mutation.json" ]; then
            ORIGIN_MUT_ARGS=(--origin-mutation "results/${CVE_ID}_origin_mutation.json")
        fi
        python3 -u trace_fork_offsets.py \
            --trace-json "$DIVERGE_JSON" \
            ${ORIGIN_MUT_ARGS[@]+"${ORIGIN_MUT_ARGS[@]}"} \
            --timeout 60
        if [ $? -eq 0 ]; then
            echo -e "\n=== GDB trace completed ==="
        else
            echo "GDB trace failed!"
            exit 1
        fi
    fi
fi

# ============================================================================
# Step 3: Polytracker analysis (only in -pt or -full mode)
# ============================================================================
if [ "$POLYTRACKER_MODE" = true ] || [ "$FULL_MODE" = true ]; then
    echo ""
    echo "=== PolyTracker taint analysis ==="
    DIVERGE_JSON="results/${CVE_ID}.diverge.json"
    if [ ! -f "$DIVERGE_JSON" ]; then
        echo "Error: $DIVERGE_JSON not found"
        exit 1
    fi

    # Pt-only mode (-pt) skips the GDB step, so tell the inline analysis to
    # reset the mutation output folder itself (in -full mode the GDB step
    # already did it, and Step 3 must append to its results).
    if [ "$POLYTRACKER_MODE" = true ]; then
        export RETRO_PT_ONLY=1
    fi

    python3 -u -c "
import sys, time
sys.path.insert(0, '.')
from polytracker_offsets import locate_offsets
import json, os
from pathlib import Path

with open('$DIVERGE_JSON') as f:
    div = json.load(f)

# Pt-only mode skips the GDB 2nd step, which normally resets the mutation
# output folder; reset it here so only this run's mutated inputs are kept.
if os.environ.get('RETRO_PT_ONLY') == '1':
    from trace_fork_offsets import _reset_mutation_out_dir
    _rd = _reset_mutation_out_dir(div.get('input_file'), div.get('version_b'))
    print(f'[*] Mutation output dir (reset): {_rd}')

# For semantic forks, poly_track_* fields point to the target's variable-read
# site (correct for PolyTracker instrumentation); root_cause_* may point to the
# guard or fork-call-site instead.
pt_file = div.get('poly_track_file') or div.get('root_cause_file_b', div.get('root_cause_file'))
pt_line = div.get('poly_track_line') or div.get('root_cause_line_b', div.get('root_cause_line'))
pt_stmt = div.get('poly_track_statement') or div.get('root_cause_statement_b', '')

_t_loc = time.time()
result = locate_offsets(
    source_dir=div.get('source_dir', '$TARGET_VERSION_PATH'),
    program_name=div.get('program_name', 'tiffcrop'),
    input_file=div.get('input_file', '$INPUT_FILE'),
    fork_function=div.get('root_cause_function', ''),
    fork_source_file=pt_file,
    fork_line=pt_line,
    variables=div.get('variables', []),
    fork_statement=pt_stmt,
    full_args=div.get('args_b', div.get('args_a')),
)
_t_loc = time.time() - _t_loc
try:
    import stage_timing
    stage_timing.record('locate input-file offsets for variables at the fork statement (PolyTracker)', _t_loc)
except Exception:
    print(f'[time] locate input-file offsets for variables at the fork statement (PolyTracker): took {_t_loc:.3f}s')

output_path = 'results/${CVE_ID}_polytracker_offsets.json'

# Save the PolyTracker result first (before the slow mutation test), so the
# offsets are persisted even if the mutation test is interrupted.
with open(output_path, 'w') as f:
    json.dump(result, f, indent=2)

# --- Byte mutation crash testing on the located offsets ---
# Pointer variables (e.g. TIFF* tif) taint the whole struct, producing noisy
# offsets; value variables (e.g. td_nstrips) yield a small, precise offset set.
# Only test precise variables (<= 16 offsets) to keep the mutation meaningful.
offsets = set()
precise = []
for vname, offs in (result.get('variable_offsets') or {}).items():
    if offs and len(offs) <= 16:
        precise.append((vname, offs))
        for off, length in offs:
            offsets.add(off)
offsets = sorted(offsets)

mutation_results = None
target_bin = div.get('binary_b')
ref_bin = div.get('binary_a')
input_file = div.get('input_file')
if offsets and target_bin and ref_bin and os.path.isfile(target_bin) and os.path.isfile(ref_bin) and input_file:
    print(f'\n=== Byte mutation crash testing ({len(offsets)} offsets '
          f'from {len(precise)} precise variable(s)) ===')
    try:
        from trace_fork_offsets import test_byte_mutations_compare
        mutation_results = test_byte_mutations_compare(
            target_bin, ref_bin, input_file, div.get('args_b') or [],
            offsets, timeout=60, version=div.get('version_b'))
        result['mutation_results'] = mutation_results
    except Exception as e:
        print(f'  [!] Byte mutation testing failed: {e}')
        result['mutation_results'] = {'status': 'error', 'error': str(e)}

    # Persist the mutation results as well.
    with open(output_path, 'w') as f:
        json.dump(result, f, indent=2)

print(f'PolyTracker results saved to: {output_path}')
"
    if [ $? -eq 0 ]; then
        echo -e "\n=== PolyTracker analysis completed ==="
    else
        echo "PolyTracker analysis failed!"
    fi
fi

# ============================================================================
# Final step: post-hoc fork-path verification of the generated PoCs.
# Runs after all mutation stages have finished and audits every produced input
# file independently: does the target binary actually execute the fork
# statement, does the fork condition now evaluate to the reference side, and
# does the reference-compatible crash occur after the fork?
# ============================================================================
FINAL_DIVERGE_JSON="results/${CVE_ID}.diverge.json"
if [ -f "$FINAL_DIVERGE_JSON" ]; then
    echo ""
    echo "=== Fork-path verification of generated PoCs (post-hoc) ==="
    python3 -u verify_fork_path.py \
        --trace-json "$FINAL_DIVERGE_JSON" \
        --output "results/${CVE_ID}_fork_path_verification.json" \
        --limit 32 --timeout 60 || true
fi

echo -e "\n=== Analysis completed ==="
echo ""
echo "=== Timing summary (since compilation finished) ==="
python3 -c "
import json, time
try:
    d = json.load(open('$RETRO_TIMINGS'))
    print(f'total time (after compilation): {time.time() - d[\"t0\"]:.3f}s')
    print('stages:')
    for s in d['stages']:
        extra = f' (took {s[\"duration\"]:.3f}s)' if 'duration' in s else ''
        print(f'  {s[\"stage\"]}: cumulative {s[\"elapsed\"]:.3f}s{extra}')
    print(f'details saved to: $RETRO_TIMINGS')
except Exception as e:
    print(f'failed to read the timing file $RETRO_TIMINGS: {e}')
"
