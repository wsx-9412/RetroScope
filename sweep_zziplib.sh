#!/bin/bash
cd "$(dirname "$0")"
OUT=/tmp/zziplib_sweep.tsv
echo -e 'poc\tversion\tresult\tsig' > "$OUT"
export ASAN_OPTIONS=detect_leaks=0:allocator_may_return_null=1
TOOLS='zzcat unzzipcat unzzipdir unzip-mem unzzipcat-seeko'
for poc in in/zziplib/asarubbo/*; do
  [ -f "$poc" ] || continue
  pname=$(basename "$poc")
  for d in zziplib-versions/zziplib-*; do
    v=$(basename "$d" | sed 's/zziplib-//')
    dd=$(ls -d "$d"/Linux_*.d 2>/dev/null | head -1)
    [ -n "$dd" ] || continue
    found=0
    for t in $TOOLS; do
      bin="$dd/bins/$t"
      [ -x "$bin" ] || continue
      log=$(timeout 15 "$bin" "$poc" 2>&1); rc=$?
      if echo "$log" | grep -q 'ERROR: AddressSanitizer'; then
        tt=$(echo "$log" | grep -oE 'ERROR: AddressSanitizer: [a-z-]+' | head -1)
        echo -e "$pname\t$v\tasan\t$t|$tt" >> "$OUT"; found=1; break
      elif [ $rc -ge 128 ] && [ $rc -ne 253 ] && [ $rc -ne 1 ]; then
        echo -e "$pname\t$v\tsignal\t$t|$rc" >> "$OUT"; found=1; break
      fi
    done
    [ $found -eq 0 ] && echo -e "$pname\t$v\tnone\t" >> "$OUT"
  done
done
echo "[SWEEP-DONE]"
