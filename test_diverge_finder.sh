#!/bin/bash
# test_diverge_finder.sh - script to test diverge_finder.py
#
# Usage:
#   ./test_diverge_finder.sh CVE-2022-3597

set -e

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CVE="${1:-CVE-2022-3597}"

# Configuration
BINARY="$BASE_DIR/tiff-versions/tiff-4.0.8/tools/tiffcrop"
INPUT_A="$BASE_DIR/in/$CVE"
INPUT_B="$BASE_DIR/new-in/${CVE}-4-0-8"
ARGS="-Z 1:4,3:3 -R 90 -H 300 -i {input} /tmp/foo"
OUTPUT="$BASE_DIR/results/${CVE}_diverge.json"

# Check whether the files exist
if [ ! -f "$BINARY" ]; then
    echo "error: binary does not exist: $BINARY"
    exit 1
fi
if [ ! -f "$INPUT_A" ]; then
    echo "error: input file A does not exist: $INPUT_A"
    exit 1
fi
if [ ! -f "$INPUT_B" ]; then
    echo "error: input file B does not exist: $INPUT_B"
    exit 1
fi

mkdir -p "$BASE_DIR/results"

echo "=== Testing diverge_finder.py ==="
echo "CVE: $CVE"
echo "Binary: $BINARY"
echo "Input A: $INPUT_A"
echo "Input B: $INPUT_B"
echo "Args: $ARGS"
echo "Output: $OUTPUT"
echo ""

python3 "$BASE_DIR/diverge_finder.py" \
    --binary "$BINARY" \
    --input-a "$INPUT_A" \
    --input-b "$INPUT_B" \
    --args "$ARGS" \
    --timeout 300 \
    --gdb-timeout 120 \
    --output "$OUTPUT"

echo ""
echo "=== Test finished ==="
