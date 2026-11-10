#!/bin/bash
cd "$(dirname "$0")/libxml2-versions"
for d in libxml2-2.15.0 libxml2-2.15.3 libxml2-2.15.4; do
  v=${d#libxml2-}
  if [ -x "$d/xmllint" ]; then echo "[SKIP] $v"; continue; fi
  echo "[BUILD] $v"
  (
    cd "$d" || exit 1
    ./autogen.sh --without-python --without-zlib --without-lzma --without-iconv > /tmp/lxml_build_$v.log 2>&1 || true
    CFLAGS='-g -O0 -fsanitize=address -fno-omit-frame-pointer' LDFLAGS='-fsanitize=address' ./configure --without-python --without-zlib --without-lzma --without-iconv --without-threads >> /tmp/lxml_build_$v.log 2>&1 || { echo "[CONF-FAIL] $v"; tail -5 /tmp/lxml_build_$v.log; exit 0; }
    make xmllint -j4 >> /tmp/lxml_build_$v.log 2>&1 || { echo "[MAKE-FAIL] $v"; tail -8 /tmp/lxml_build_$v.log; exit 0; }
    echo "[OK] $v"
  )
done
echo '[ALL-DONE]'
