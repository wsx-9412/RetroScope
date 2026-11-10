#!/bin/bash
# Sweep: run each PoC against each jasper version, record crash classification.
cd "$(dirname "$0")"
VMAP=/tmp/jasper_versions.txt
POCDIR=in/jasper/asarubbo
OUT=/tmp/jasper_sweep.tsv
echo -e 'poc\tversion\tresult\tsig' > "$OUT"
export ASAN_OPTIONS=detect_leaks=0:allocator_may_return_null=1
for poc in "$POCDIR"/*; do
  [ -f "$poc" ] || continue
  pname=$(basename "$poc")
  while IFS='|' read -r v bin; do
    log=$(timeout 20 "$bin" -f "$poc" 2>&1)
    rc=$?
    if echo "$log" | grep -q 'ERROR: AddressSanitizer'; then
      t=$(echo "$log" | grep -oE 'ERROR: AddressSanitizer: [a-z-]+' | head -1)
      echo -e "$pname\t$v\tasan\t$t" >> "$OUT"
    elif echo "$log" | grep -qE 'runtime error:'; then
      t=$(echo "$log" | grep -oE 'runtime error: [a-z -]+' | head -1)
      echo -e "$pname\t$v\tubsan\t$t" >> "$OUT"
    elif echo "$log" | grep -qiE 'assertion|assert '; then
      echo -e "$pname\t$v\tassert\t$(echo "$log" | grep -iE 'assert' | head -1 | cut -c1-80)" >> "$OUT"
    elif [ $rc -ge 128 ] || echo "$log" | grep -qE 'Segmentation fault|Aborted|core dumped'; then
      echo -e "$pname\t$v\tsignal\t$rc" >> "$OUT"
    else
      echo -e "$pname\t$v\tnone\t" >> "$OUT"
    fi
  done < "$VMAP"
done
echo "[SWEEP-DONE]"
