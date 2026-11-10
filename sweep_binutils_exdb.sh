#!/bin/bash
cd "$(dirname "$0")"
OUT=/tmp/binutils_exdb_sweep.tsv
echo -e 'poc\tversion\tresult\tsig' > "$OUT"
export ASAN_OPTIONS=detect_leaks=0:allocator_may_return_null=1
for poc in in/binutils/exploitdb/*.min; do
  pname=$(basename "$poc")
  for d in binutils-versions/binutils-*; do
    v=$(basename "$d")
    objdump="$d/build-asan/binutils/objdump"
    [ -x "$objdump" ] || continue
    found=0
    for flag in '-D' '-d' '-x' '-g'; do
      log=$(timeout 15 "$objdump" $flag "$poc" 2>&1); rc=$?
      if echo "$log" | grep -q 'ERROR: AddressSanitizer'; then
        tt=$(echo "$log" | grep -oE 'ERROR: AddressSanitizer: [a-z-]+' | head -1)
        echo -e "$pname\t$v\tasan\t$flag|$tt" >> "$OUT"; found=1; break
      elif [ $rc -ge 128 ] && [ $rc -ne 253 ] && [ $rc -ne 1 ]; then
        echo -e "$pname\t$v\tsignal\t$flag|$rc" >> "$OUT"; found=1; break
      fi
    done
    [ $found -eq 0 ] && echo -e "$pname\t$v\tnone\t" >> "$OUT"
  done
done
echo "[SWEEP-DONE]"
