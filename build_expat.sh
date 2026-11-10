#!/bin/bash
cd "$(dirname "$0")/expat-versions"
for d in libexpat-R_2_3_0 libexpat-R_2_4_0 libexpat-R_2_4_1 libexpat-R_2_4_5 libexpat-R_2_5_0 libexpat-R_2_6_0; do
  v=${d#libexpat-R_}; v=${v//_/.}
  if [ -x "$d/expat/build/xmlwf/xmlwf" ]; then echo "[SKIP] $v"; continue; fi
  echo "[BUILD] $v"
  (
    cd "$d/expat" || exit 1
    mkdir -p build && cd build
    cmake .. -DEXPAT_BUILD_TOOLS=ON -DEXPAT_BUILD_EXAMPLES=OFF -DEXPAT_BUILD_TESTS=OFF -DEXPAT_BUILD_DOCS=OFF -DEXPAT_BUILD_PKGCONFIG=OFF -DEXPAT_SHARED_LIBS=OFF -DCMAKE_C_FLAGS='-g -O0 -fsanitize=address -fno-omit-frame-pointer' -DCMAKE_EXE_LINKER_FLAGS='-fsanitize=address' > /tmp/expat_build.log 2>&1 || { echo "[CMAKE-FAIL] $v"; tail -5 /tmp/expat_build.log; exit 0; }
    make xmlwf -j4 >> /tmp/expat_build.log 2>&1 || { echo "[MAKE-FAIL] $v"; tail -5 /tmp/expat_build.log; exit 0; }
    echo "[OK] $v"
  )
done
echo '[ALL-DONE]'
