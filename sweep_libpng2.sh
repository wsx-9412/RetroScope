#!/bin/bash
cd "$(dirname "$0")/libpng-versions"
OUT=/tmp/libpng_harness_sweep.tsv
echo -e 'poc\tversion\tresult\tsig' > "$OUT"
export ASAN_OPTIONS=detect_leaks=0:allocator_may_return_null=1
CRASH=libpng-1.6.43/contrib/testpngs/crashers
for poc in "$CRASH"/*.png; do
  pname=$(basename "$poc")
  for v in 1.6.12 1.6.18 1.6.27 1.6.34 1.6.36 1.6.38 1.6.40 1.6.43; do
    bin="/tmp/pngdec-$v"
    log=$(timeout 15 "$bin" "$poc" 2>&1); rc=$?
    if echo "$log" | grep -q 'ERROR: AddressSanitizer'; then
      tt=$(echo "$log" | grep -oE 'ERROR: AddressSanitizer: [a-z-]+' | head -1)
      echo -e "$pname\t$v\tasan\t$tt" >> "$OUT"
    elif [ $rc -ge 128 ] && [ $rc -ne 253 ]; then
      echo -e "$pname\t$v\tsignal\t$rc" >> "$OUT"
    else
      echo -e "$pname\t$v\tnone\t" >> "$OUT"
    fi
  done
done
echo '[DONE]'
