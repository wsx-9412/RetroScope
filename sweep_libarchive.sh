#!/bin/bash
cd "$(dirname "$0")"
OUT=/tmp/libarchive_sweep.tsv
echo -e 'poc\tversion\tresult\tsig' > "$OUT"
export ASAN_OPTIONS=detect_leaks=0:allocator_may_return_null=1
mkdir -p /tmp/la_extract
for poc in in/libarchive/asarubbo/*; do
  [ -f "$poc" ] || continue
  pname=$(basename "$poc")
  for v in 3.4.0 3.4.3 3.5.0 3.5.3 3.6.0 3.6.2 3.7.0 3.7.7 3.7.9 3.8.0; do
    bin="./libarchive-versions/build-asan-v$v/bin/bsdtar"
    [ -x "$bin" ] || continue
    rm -rf /tmp/la_extract/* 2>/dev/null
    log=$(timeout 15 "$bin" -xf "$poc" -C /tmp/la_extract 2>&1); rc=$?
    if echo "$log" | grep -q 'ERROR: AddressSanitizer'; then
      t=$(echo "$log" | grep -oE 'ERROR: AddressSanitizer: [a-z-]+' | head -1)
      echo -e "$pname\t$v\tasan\t$t" >> "$OUT"
    elif echo "$log" | grep -qE 'runtime error:'; then
      echo -e "$pname\t$v\tubsan\tubsan" >> "$OUT"
    elif [ $rc -ge 128 ] && [ $rc -ne 253 ]; then
      echo -e "$pname\t$v\tsignal\t$rc" >> "$OUT"
    elif [ $rc -eq 253 ]; then
      echo -e "$pname\t$v\tnone\t253" >> "$OUT"
    else
      echo -e "$pname\t$v\tnone\t$rc" >> "$OUT"
    fi
  done
done
echo "[SWEEP-DONE]"
