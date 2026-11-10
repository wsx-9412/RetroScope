#!/bin/bash
cd "$(dirname "$0")"
VMAP=/tmp/audiofile_versions.txt
POCDIR=in/audiofile/asarubbo
OUT=/tmp/audiofile_sweep.tsv
echo -e 'poc\tversion\tresult\tsig' > "$OUT"
export ASAN_OPTIONS=detect_leaks=0:allocator_may_return_null=1
for poc in "$POCDIR"/*; do
  [ -f "$poc" ] || continue
  pname=$(basename "$poc")
  while IFS='|' read -r v bin; do
    log=$(timeout 20 "$bin" "$poc" /tmp/af_out.aiff format aiff 2>&1)
    rc=$?
    if echo "$log" | grep -q 'ERROR: AddressSanitizer'; then
      t=$(echo "$log" | grep -oE 'ERROR: AddressSanitizer: [a-z-]+' | head -1)
      echo -e "$pname\t$v\tasan\t$t" >> "$OUT"
    elif echo "$log" | grep -qE 'runtime error:'; then
      echo -e "$pname\t$v\tubsan\tubsan" >> "$OUT"
    elif echo "$log" | grep -qiE 'assertion|assert '; then
      echo -e "$pname\t$v\tassert\tassert" >> "$OUT"
    elif [ $rc -ge 128 ] && [ $rc -ne 253 ]; then
      echo -e "$pname\t$v\tsignal\t$rc" >> "$OUT"
    elif [ $rc -eq 253 ]; then
      echo -e "$pname\t$v\tnone\t253" >> "$OUT"
    else
      echo -e "$pname\t$v\tnone\t" >> "$OUT"
    fi
  done < "$VMAP"
done
echo "[SWEEP-DONE]"
