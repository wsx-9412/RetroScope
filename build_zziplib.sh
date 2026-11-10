#!/bin/bash
cd "$(dirname "$0")/zziplib-versions"
for d in zziplib-0.13.56 zziplib-0.13.60 zziplib-0.13.62 zziplib-0.13.66; do
  echo "[BUILD] $d"
  (
    cd "$d" || exit 1
    make distclean >/dev/null 2>&1 || true
    ./configure --disable-shared CFLAGS='-g -O0 -fsanitize=address -fno-omit-frame-pointer' LDFLAGS='-fsanitize=address' > /tmp/zzip_build.log 2>&1 || { echo "[CONFIGURE-FAIL] $d"; tail -5 /tmp/zzip_build.log; exit 0; }
    make -j4 >> /tmp/zzip_build.log 2>&1 || { echo "[MAKE-FAIL] $d"; tail -8 /tmp/zzip_build.log; exit 0; }
    echo "[OK] $d"
  )
done
echo "[ALL-DONE]"
