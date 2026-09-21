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
        REFERENCE_VERSION_PATH="$BASE_DIR/tiff-versions/tiff-4.3.0"
        TARGET_VERSION_PATH="$BASE_DIR/tiff-versions/tiff-4.0.8"
        DEFAULT_INPUT="$INPUT_FILE_DIR/CVE-2022-1354"
        EXTRA_ARGS=(--include-exits --refactor-detect)
        ;;
"lame")
        REFERENCE_VERSION_PATH="$BASE_DIR/lame-versions/lame-3.99.5"
        TARGET_VERSION_PATH="$BASE_DIR/lame-versions/lame-3.98.4"
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
    *)
        echo "Error: unknown project '$PROJECT_NAME'"
        echo "Available: libtiff, lame, audiofile, jasper"
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
    echo "=== GDB dynamic trace ==="
    DIVERGE_JSON="results/${CVE_ID}.diverge.json"
    if [ ! -f "$DIVERGE_JSON" ]; then
        echo "Error: $DIVERGE_JSON not found"
        exit 1
    fi
    echo "Using divergence result: $DIVERGE_JSON"
    python3 -u trace_fork_offsets.py \
        --trace-json "$DIVERGE_JSON" \
        --timeout 60
    if [ $? -eq 0 ]; then
        echo -e "\n=== GDB trace completed ==="
    else
        echo "GDB trace failed!"
        exit 1
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

    python3 -u -c "
import sys, time
sys.path.insert(0, '.')
from polytracker_offsets import locate_offsets
import json, os
from pathlib import Path

with open('$DIVERGE_JSON') as f:
    div = json.load(f)

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
    stage_timing.record('确定分叉语句处变量对应输入文件偏移位置(PolyTracker)', _t_loc)
except Exception:
    print(f'[时间] 确定分叉语句处变量对应输入文件偏移位置(PolyTracker): 用时 {_t_loc:.3f}s')

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
            offsets, timeout=60)
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

echo -e "\n=== Analysis completed ==="
echo ""
echo "=== Timing summary (since compilation finished) ==="
python3 -c "
import json, time
try:
    d = json.load(open('$RETRO_TIMINGS'))
    print(f'总用时(编译后): {time.time() - d[\"t0\"]:.3f}s')
    print('各阶段:')
    for s in d['stages']:
        extra = f' (用时 {s[\"duration\"]:.3f}s)' if 'duration' in s else ''
        print(f'  {s[\"stage\"]}: 累计 {s[\"elapsed\"]:.3f}s{extra}')
    print(f'明细保存在: $RETRO_TIMINGS')
except Exception as e:
    print(f'无法读取计时文件 $RETRO_TIMINGS: {e}')
"
