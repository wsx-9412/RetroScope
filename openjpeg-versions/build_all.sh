#!/bin/bash
set -e
for ver in v2.3.0 v2.3.1 v2.4.0 v2.5.0 v2.5.1 v2.5.2 v2.5.3; do
  src="$ver"
  build="build-asan-$ver"
  [ -d "$build" ] && echo "$ver already built" && continue
  echo "=== Building $ver ==="
  mkdir -p "$build"
  cd "$build"
  cmake "../$src" \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_C_FLAGS="-g -O0 -fsanitize=address -fno-omit-frame-pointer -fno-common" \
    -DCMAKE_CXX_FLAGS="-g -O0 -fsanitize=address -fno-omit-frame-pointer -fcommon" \
    -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address" \
    -DCMAKE_SHARED_LINKER_FLAGS="-fsanitize=address" \
    -DBUILD_SHARED_LIBS=ON \
    -DBUILD_CODEC=ON \
    2>&1 | tail -3
  make -j$(nproc) opj_decompress 2>&1 | tail -5
  cd ..
  echo "=== $ver DONE ==="
done
