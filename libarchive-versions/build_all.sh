#!/bin/bash
for ver in v3.4.0 v3.4.3 v3.5.0 v3.5.3 v3.6.0 v3.6.2 v3.7.0 v3.7.7 v3.7.9 v3.8.0; do
  [ -x "build-asan-$ver/bsdtar" ] && echo "$ver done" && continue
  echo "=== Building $ver ==="
  mkdir -p "build-asan-$ver"
  cd "build-asan-$ver"
  cmake "../$ver" \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_C_FLAGS="-g -O0 -fsanitize=address -fno-omit-frame-pointer" \
    -DCMAKE_CXX_FLAGS="-g -O0 -fsanitize=address -fno-omit-frame-pointer" \
    -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address" \
    -DCMAKE_SHARED_LINKER_FLAGS="-fsanitize=address" \
    -DENABLE_TEST=OFF -DENABLE_TAR=ON 2>&1 | tail -2
  make -j$(nproc) bsdtar 2>&1 | tail -3
  cd ..
done
