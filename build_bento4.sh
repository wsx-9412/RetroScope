#!/bin/bash
cd "$(dirname "$0")/bento4-versions"
for d in Bento4-1.5.0-612 Bento4-1.5.1-630; do
  echo "[BUILD] $d"
  (
    cd "$d" || exit 1
    mkdir -p build
    cd build
    cmake .. -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS='-g -O0 -fsanitize=address -fno-omit-frame-pointer' -DCMAKE_CXX_FLAGS='-g -O0 -fsanitize=address -fno-omit-frame-pointer' -DCMAKE_EXE_LINKER_FLAGS='-fsanitize=address' > /tmp/bento4_build.log 2>&1 || { echo "[CMAKE-FAIL] $d"; tail -5 /tmp/bento4_build.log; exit 0; }
    make -j4 >> /tmp/bento4_build.log 2>&1 || { echo "[MAKE-FAIL] $d"; tail -5 /tmp/bento4_build.log; exit 0; }
    echo "[OK] $d"
  )
done
echo "[ALL-DONE]"
