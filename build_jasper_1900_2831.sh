#!/bin/bash
cd "$(dirname "$0")/jasper-versions"
for v in 1.900.28 1.900.29 1.900.30 1.900.31; do
  d=jasper-version-$v
  if [ -x "$d/src/appl/imginfo" ]; then echo "[SKIP] $v"; continue; fi
  echo "[BUILD] $v"
  (
    cd "$d" || exit 1
    make distclean >/dev/null 2>&1
    ./configure --disable-shared --enable-static CFLAGS='-g -O0 -fsanitize=address -fno-omit-frame-pointer -Wno-error' LDFLAGS='-fsanitize=address' > /tmp/jasper1b_build_$v.log 2>&1 || { echo "[CONFIGURE-FAIL] $v"; tail -5 /tmp/jasper1b_build_$v.log; exit 0; }
    make -j4 >> /tmp/jasper1b_build_$v.log 2>&1 || { echo "[MAKE-FAIL] $v"; tail -5 /tmp/jasper1b_build_$v.log; exit 0; }
    echo "[OK] $v"
  )
done
echo "[ALL-DONE-1.900.28-31]"
