#!/bin/bash
# test_diverge_finder.sh - 测试 diverge_finder.py 的脚本
#
# 用法：
#   ./test_diverge_finder.sh CVE-2022-3597

set -e

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CVE="${1:-CVE-2022-3597}"

# 配置
BINARY="$BASE_DIR/tiff-versions/tiff-4.0.8/tools/tiffcrop"
INPUT_A="$BASE_DIR/in/$CVE"
INPUT_B="$BASE_DIR/new-in/${CVE}-4-0-8"
ARGS="-Z 1:4,3:3 -R 90 -H 300 -i {input} /tmp/foo"
OUTPUT="$BASE_DIR/results/${CVE}_diverge.json"

# 检查文件是否存在
if [ ! -f "$BINARY" ]; then
    echo "错误: 二进制文件不存在: $BINARY"
    exit 1
fi
if [ ! -f "$INPUT_A" ]; then
    echo "错误: 输入文件 A 不存在: $INPUT_A"
    exit 1
fi
if [ ! -f "$INPUT_B" ]; then
    echo "错误: 输入文件 B 不存在: $INPUT_B"
    exit 1
fi

mkdir -p "$BASE_DIR/results"

echo "=== 测试 diverge_finder.py ==="
echo "CVE: $CVE"
echo "二进制: $BINARY"
echo "输入 A: $INPUT_A"
echo "输入 B: $INPUT_B"
echo "参数: $ARGS"
echo "输出: $OUTPUT"
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
echo "=== 测试完成 ==="
