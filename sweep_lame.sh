#!/bin/bash
cd "$(dirname "$0")"
OUT=/tmp/lame_sweep.tsv
echo -e 'poc\tversion\tresult\tsig' > "$OUT"
export ASAN_OPTIONS=detect_leaks=0:allocator_may_return_null=1
for poc in in/lame/asarubbo/*; do
  [ -f "$poc" ] || continue
  pname=$(basename "$poc")
  for v in 3.98.2 3.98.4 3.99.5; do
    bin="./lame-versions/lame-$v/frontend/lame"
    # try default (wav input), then mp3input
    for mode in 'default' 'mp3input'; do
      if [ "$mode" = default ]; then cmd="$bin -f -V 9 $poc /dev/null"; else cmd="$bin --mp3input -f -V 9 $poc /dev/null"; fi
      log=$(timeout 20 $cmd 2>&1); rc=$?
      if echo "$log" | grep -q 'ERROR: AddressSanitizer'; then
        t=$(echo "$log" | grep -oE 'ERROR: AddressSanitizer: [a-z-]+' | head -1)
        echo -e "$pname\t$v\tasan\t$mode|$t" >> "$OUT"; break
      elif echo "$log" | grep -qE 'runtime error:'; then
        echo -e "$pname\t$v\tubsan\t$mode" >> "$OUT"; break
      elif [ $rc -ge 128 ] && [ $rc -ne 253 ]; then
        echo -e "$pname\t$v\tsignal\t$mode|$rc" >> "$OUT"; break
      fi
    done
    # if no crash with either mode, record none (from default mode)
    grep -qP "^$pname\t$v\t" "$OUT" || echo -e "$pname\t$v\tnone\t" >> "$OUT"
  done
done
echo "[SWEEP-DONE]"
