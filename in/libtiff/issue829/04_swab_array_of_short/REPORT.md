# libtiff disclosure package: 04_swab_array_of_short

**Crash:** heap-buffer-overflow /media/shafi/ssd2/disclosure_builds/libtiff/libtiff/tif_swab.c:90:11 in TIFFSwabArrayOfShort

**Verification:**
- Compiled against unmodified libtiff.a at commit `f324415f50cb`.
- Reproducer + smart_stubs (with conflicting symbols stripped) + auto-generated wrapper.
- No sliced source from the analysis pipeline is compiled — only the upstream library archive provides the vulnerable function.

**Files in this package:**
- `reproducer.c` — concrete-input driver
- `smart_stubs.c` — stub functions for non-libtiff helpers (libtiff symbols removed)
- `wrapper.c` — bridges the reproducer's harness entry to the real upstream symbol
- `harness_types.h` — type declarations shared with reproducer
- `build.sh` — clean build instructions (sets `LIBTIFF_DIR` to your libtiff source root)
- `asan_output.txt` — captured ASan stack trace for this crash

**Reproduction:**
```bash
# 1. Build libtiff with ASan at commit f324415f50cb:
git clone https://gitlab.com/libtiff/libtiff.git && cd libtiff
git checkout f324415f50cb
./autogen.sh && CC=clang CFLAGS='-fsanitize=address -g -O0' ./configure && make

# 2. Build and run this package:
LIBTIFF_DIR=/path/to/libtiff bash build.sh
```

ASan reports the heap-buffer-overflow inside upstream libtiff at `tif_swab.c:90`.
