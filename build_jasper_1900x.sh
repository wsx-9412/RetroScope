#!/bin/bash
# Build all jasper 1.900.x versions with ASan (autotools)
cd "$(dirname "$0")/jasper-versions"
for d in jasper-version-1.900.*; do
  v="${d#jasper-version-}"
  if [ -x "$d/src/appl/imginfo" ]; then
    echo "[SKIP] $v already built"
    continue
  fi
  echo "[BUILD] $v"
  (
    cd "$d" || exit 1
    autoreconf -fi > /tmp/jasper1_build_$v.log 2>&1 || { echo "[AUTORECONF-FAIL] $v"; tail -5 /tmp/jasper1_build_$v.log; exit 0; }
    ./configure --disable-shared --enable-static CFLAGS='-g -O0 -fsanitize=address -fno-omit-frame-pointer -Wno-error' LDFLAGS='-fsanitize=address' >> /tmp/jasper1_build_$v.log 2>&1 || { echo "[CONFIGURE-FAIL] $v"; tail -5 /tmp/jasper1_build_$v.log; exit 0; }
    make -j4 >> /tmp/jasper1_build_$v.log 2>&1 || { echo "[MAKE-FAIL] $v"; tail -5 /tmp/jasper1_build_$v.log; exit 0; }
    echo "[OK] $v"
  )
done
echo "[ALL-DONE-1.900]"
