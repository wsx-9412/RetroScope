#!/bin/bash
cd "$(dirname "$0")/libpng-versions"
for tgz in v1.6.*.tar.gz; do
  tag=$(basename "$tgz" .tar.gz)
  v=${tag#v}
  [ -x "$tag/pngtest" ] && { echo "[SKIP] $v"; continue; }
  echo "[BUILD] $v"
  tar xzf "$tgz" 2>/dev/null
  dir=$(ls -d libpng-*/ 2>/dev/null | grep -E "libpng-$v" | head -1)
  [ -z "$dir" ] && { echo "[NO-DIR] $v"; continue; }
  (
    cd "$dir" || exit 1
    ./configure --disable-shared CFLAGS='-g -O0 -fsanitize=address -fno-omit-frame-pointer' LDFLAGS='-fsanitize=address' > /tmp/png_build.log 2>&1 || { echo "[CONFIGURE-FAIL] $v"; tail -3 /tmp/png_build.log; exit 0; }
    make -j4 >> /tmp/png_build.log 2>&1 || { echo "[MAKE-FAIL] $v"; tail -3 /tmp/png_build.log; exit 0; }
    echo "[OK] $v"
  )
done
echo '[ALL-DONE]'
