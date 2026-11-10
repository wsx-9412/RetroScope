#!/bin/bash
cd "$(dirname "$0")"
OUT=/tmp/openjpeg_sweep.tsv
echo -e 'poc\tversion\tresult\tsig' > "$OUT"
export ASAN_OPTIONS=detect_leaks=0:allocator_may_return_null=1
for poc in in/openjpeg/asarubbo/*; do
  [ -f "$poc" ] || continue
  pname=$(basename "$poc")
  for d in openjpeg-versions/*/; do
    bin="$d/bin/opj_decompress"
    [ -x "$bin" ] || continue
    v=$(basename "$d")
    log=$(timeout 15 "$bin" -i "$poc" -o /tmp/oj_out.ppm 2>&1); rc=$?
    if echo "$log" | grep -q 'ERROR: AddressSanitizer'; then
      t=$(echo "$log" | grep -oE 'ERROR: AddressSanitizer: [a-z-]+' | head -1)
      echo -e "$pname\t$v\tasan\t$t" >> "$OUT"
    elif [ $rc -ge 128 ] && [ $rc -ne 253 ]; then
      echo -e "$pname\t$v\tsignal\t$rc" >> "$OUT"
    else
      echo -e "$pname\t$v\tnone\t" >> "$OUT"
    fi
  done
done
echo "[SWEEP-DONE]"
