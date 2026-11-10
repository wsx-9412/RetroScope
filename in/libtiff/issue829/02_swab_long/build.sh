#!/bin/bash
# Build against unmodified libtiff.a at commit f324415f50cb
# Prerequisites: build libtiff with ASan from commit f324415f50cb
LIBTIFF_DIR="${LIBTIFF_DIR:-/path/to/libtiff}"
LIBTIFF_A="$LIBTIFF_DIR/libtiff/.libs/libtiff.a"

clang -fsanitize=address -fno-omit-frame-pointer -g -O0 -w \
    -I"$LIBTIFF_DIR/libtiff" -I"$LIBTIFF_DIR" \
    reproducer.c smart_stubs.c wrapper.c "$LIBTIFF_A" \
    -lzstd -llzma -lz -lm -lpthread \
    -o reproducer_bin

ASAN_OPTIONS='detect_leaks=0:halt_on_error=1:abort_on_error=1:print_stacktrace=1:log_path=asan' ./reproducer_bin
cat asan.* 2>/dev/null
