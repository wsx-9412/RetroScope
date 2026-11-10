#!/bin/bash
# Sweep libtiff asarubbo PoCs with tiffcp across all versions
cd "$(dirname "$0")"
VMAP=/tmp/tiff_versions.txt
POCDIR=in/libtiff/asarubbo
OUT=/tmp/libtiff_sweep.tsv
echo -e 'poc\tversion\tresult\tsig' > "$OUT"
export ASAN_OPTIONS=detect_leaks=0:allocator_may_return_null=1
for poc in "$POCDIR"/*; do
  [ -f "$poc" ] || continue
  pname=$(basename "$poc")
  while IFS='|' read -r v bin; do
    log=$(timeout 15 "$bin" -i "$poc" /tmp/lt_out.tif 2>&1)
    rc=$?
    if echo "$log" | grep -q 'ERROR: AddressSanitizer'; then
      t=$(echo "$log" | grep -oE 'ERROR: AddressSanitizer: [a-z-]+' | head -1)
      echo -e "$pname\t$v\tasan\t$t" >> "$OUT"
    elif echo "$log" | grep -qE 'runtime error:'; then
      echo -e "$pname\t$v\tubsan\t$(echo "$log" | grep -oE 'runtime error: [a-z -]+' | head -1)" >> "$OUT"
    elif echo "$log" | grep -qiE 'assertion|Assertion'; then
      echo -e "$pname\t$v\tassert\tassert" >> "$OUT"
    elif [ $rc -ge 128 ] || echo "$log" | grep -qE 'Segmentation fault|Aborted|core dumped|Floating point'; then
      echo -e "$pname\t$v\tsignal\t$rc" >> "$OUT"
    else
      echo -e "$pname\t$v\tnone\t" >> "$OUT"
    fi
  done < "$VMAP"
done
echo "[SWEEP-DONE]"
