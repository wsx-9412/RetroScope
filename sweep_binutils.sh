#!/bin/bash
cd "$(dirname "$0")"
OUT=/tmp/binutils_sweep.tsv
echo -e 'poc\tversion\tresult\tsig' > "$OUT"
export ASAN_OPTIONS=detect_leaks=0:allocator_may_return_null=1
for poc in in/binutils/asarubbo/*; do
  [ -f "$poc" ] || continue
  pname=$(basename "$poc")
  for d in binutils-versions/binutils-*; do
    v=$(basename "$d")
    readelf="$d/build-asan/binutils/readelf"
    [ -x "$readelf" ] || continue
    found=0
    for flag in '-a' '-w' '-x' '-g' '-D'; do
      log=$(timeout 15 "$readelf" $flag "$poc" 2>&1); rc=$?
      if echo "$log" | grep -q 'ERROR: AddressSanitizer'; then
        t=$(echo "$log" | grep -oE 'ERROR: AddressSanitizer: [a-z-]+' | head -1)
        echo -e "$pname\t$v\tasan\t$flag|$t" >> "$OUT"; found=1; break
      elif [ $rc -ge 128 ] && [ $rc -ne 253 ]; then
        echo -e "$pname\t$v\tsignal\t$flag|$rc" >> "$OUT"; found=1; break
      fi
    done
    [ $found -eq 0 ] && echo -e "$pname\t$v\tnone\t" >> "$OUT"
  done
done
echo "[SWEEP-DONE]"
