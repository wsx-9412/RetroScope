# RetroScope PoC run commands (giflib / libxml2 / binutils / freetype)

All target versions were built from source with AddressSanitizer
(`-fsanitize=address`), in-tree, **without installing**.
Run everything from `/home/ws/Desktop/RetroScope`.
`ASAN_OPTIONS=detect_leaks=0` is used so only memory-corruption crashes are
reported (leak reports at exit are ignored).

Every PoC is stored in `in/<CVE-ID>` and was **verified to crash** the tested
vulnerable version. All PoCs are files obtained from public sources (the
discoverer's repository, the discoverer's Full-Disclosure advisory, a public
bug-tracker attachment, or a public PoC repository) — none are hand-written
from a CVE text description.

The "affected" range in each row is the result of testing **all built
versions** of that project.

------------------------------------------------------------------------

## Summary table (CVE | affected versions | trigger command)

### binutils (55 PoCs)

Tool dirs (run from repo root):
```bash
B27=binutils-versions/binutils-2.27/build-asan/binutils
B28=binutils-versions/binutils-2.28/build-asan/binutils
B30=binutils-versions/binutils-2.30/build-asan/binutils
B32=binutils-versions/binutils-2.32/build-asan/binutils
B35=binutils-versions/binutils-2.35/build-asan/binutils
B351=binutils-versions/binutils-2.35.1/build-asan/binutils
B36=binutils-versions/binutils-2.36/build-asan/binutils
B38=binutils-versions/binutils-2.38/build-asan/binutils
```

IMPORTANT — binutils is an out-of-tree build, so the executables are NOT in
`binutils-versions/binutils-<ver>/binutils/` but one level deeper:
`binutils-versions/binutils-<ver>/build-asan/binutils/<tool>`.
Example (binutils 2.25 is built too):
```bash
ASAN_OPTIONS=detect_leaks=0 \
  ./binutils-versions/binutils-2.25/build-asan/binutils/readelf -w in/CVE-2017-6965
```
(nm is `nm-new`, strip is `strip-new`; readelf/objdump/size/objcopy/addr2line
keep their names.)

```
CVE-2017-6965    2.24-2.28                 readelf -w  in/CVE-2017-6965
CVE-2017-8392    2.24,2.26-2.28            objdump -S  in/CVE-2017-8392
CVE-2017-8396    2.26-2.28                 objdump -g  in/CVE-2017-8396
CVE-2017-12448   2.24,2.26-2.29            objdump -x  in/CVE-2017-12448
CVE-2017-12449   2.24,2.29                 objdump -x  in/CVE-2017-12449
CVE-2017-12450   2.24,2.26-2.29            objdump -x  in/CVE-2017-12450
CVE-2017-12451   2.24,2.26-2.29            objdump -x  in/CVE-2017-12451
CVE-2017-12452   2.24,2.26-2.29            objdump -x  in/CVE-2017-12452
CVE-2017-12453   2.24,2.26-2.29            objdump -x  in/CVE-2017-12453
CVE-2017-12454   2.24,2.26-2.29            objdump -x  in/CVE-2017-12454
CVE-2017-12455   2.24,2.26-2.29            objdump -x  in/CVE-2017-12455
CVE-2017-12456   2.24,2.26-2.29            objdump -x -g  in/CVE-2017-12456
CVE-2017-12457   2.24,2.29                 objdump -x  in/CVE-2017-12457
CVE-2017-12458   2.24,2.26-2.29            objdump -x  in/CVE-2017-12458
CVE-2017-12459   2.24,2.26-2.29            objdump -x  in/CVE-2017-12459
CVE-2017-14130   2.24,2.26-2.29            objdump -x  in/CVE-2017-14130
CVE-2017-14529   2.24,2.26-2.29            objdump -x  in/CVE-2017-14529
CVE-2017-14729   2.24,2.26-2.29            objdump -x  in/CVE-2017-14729
CVE-2017-15225   2.24,2.26-2.29            readelf -w  in/CVE-2017-15225
CVE-2017-15996   2.24,2.26-2.29            readelf -w  in/CVE-2017-15996
CVE-2017-16826   2.24,2.26-2.29            objdump -r  in/CVE-2017-16826
CVE-2017-16832   2.24,2.26-2.29            objdump -x  in/CVE-2017-16832
CVE-2017-17080   2.24,2.26-2.29            objdump -x  in/CVE-2017-17080
CVE-2017-17121   2.24,2.26-2.29            objdump -g  in/CVE-2017-17121
CVE-2017-17122   2.24,2.26-2.29,2.34-2.36   objdump -r  in/CVE-2017-17122
CVE-2017-17123   2.24,2.26-2.29,2.35-2.36   objdump -g  in/CVE-2017-17123
CVE-2018-6323    2.24-2.31.1               objdump -x  in/CVE-2018-6323
CVE-2018-1000876 2.24-2.34                 objdump -d  in/CVE-2018-1000876
CVE-2018-10372   2.24-2.30                 readelf -w  in/CVE-2018-10372
CVE-2019-9077    2.24-2.32                 readelf -a  in/CVE-2019-9077
CVE-2021-20284   2.24,2.26,2.35-2.35.1     objdump -D  in/CVE-2021-20284
CVE-2021-20294   2.24,2.35-2.35.1          readelf --dyn-syms  in/CVE-2021-20294
CVE-2021-45078   2.24-2.36                 objdump -g  in/CVE-2021-45078
CVE-2022-44840   2.38                      readelf -w  in/CVE-2022-44840
CVE-2022-47695   2.28-2.38                 objdump -d  in/CVE-2022-47695
CVE-2022-47696   2.24,2.34-2.38            objdump -d  in/CVE-2022-47696
CVE-2023-1579    2.24-2.35.1               objdump -S  in/CVE-2023-1579
```

Additional binutils PoCs (2018–2023 batch, all sourceware Bugzilla attachments).
Several of these are **version-specific** — the PoC triggers only on some
versions, not on others (marked *.):
```
CVE-2018-18605   2.27-2.29                 readelf -w  in/CVE-2018-18605
CVE-2018-18606   2.27-2.29                 readelf -w  in/CVE-2018-18606
CVE-2018-18607   2.27-2.29                 readelf -w  in/CVE-2018-18607
CVE-2018-19931   2.27-2.31.1               objdump -x  in/CVE-2018-19931
CVE-2018-20002   2.27-2.32                 objdump -s  in/CVE-2018-20002
CVE-2019-9073    2.27-2.32                 objdump -x  in/CVE-2019-9073
CVE-2019-9074    2.27-2.32                 objdump -x  in/CVE-2019-9074
CVE-2019-9075    2.27-2.32                 objdump -x  in/CVE-2019-9075
CVE-2019-9076    2.27-2.34                 objdump -x  in/CVE-2019-9076
CVE-2019-17450 * 2.30,2.31,2.31.1,2.34-2.38  objdump -g  in/CVE-2019-17450   (NOT 2.27-2.29)
CVE-2019-17451   2.27-2.31.1,2.34-2.38      objdump -g  in/CVE-2019-17451
CVE-2020-16592 * 2.34                     objdump -x  in/CVE-2020-16592   (only 2.34)
CVE-2020-16599   2.27-2.32                 objdump -s  in/CVE-2020-16599
CVE-2020-35448 * 2.35,2.35.1               objdump -d  in/CVE-2020-35448   (only 2.35.x)
CVE-2021-46174   2.27-2.36                 objdump -g  in/CVE-2021-46174
CVE-2022-48063 * 2.34-2.38                 objdump -g  in/CVE-2022-48063   (NOT <=2.32)
CVE-2022-48064   2.27-2.32                 objdump -s  in/CVE-2022-48064
CVE-2023-1972  * 2.27-2.32,2.40            objdump -x  in/CVE-2023-1972   (gap 2.34-2.38)
```

Note: binutils 2.24 crashes on many malformed inputs (generic robustness
issue), so a "2.24 CRASH" may reflect a different defect than the named CVE.
The binutils 2.27–2.29 entries are the ones that match the CVE's reported
function (see crash-function column below).

### libxml2 (5 PoCs)

```
CVE-2017-9047    2.9.0-2.9.4    xmllint --valid in/CVE-2017-9047
CVE-2017-9049    2.9.4          xmllint --memory --oldxml10 in/CVE-2017-9049
CVE-2016-3627    2.9.0-2.9.2    xmllint --valid --recover in/CVE-2016-3627
CVE-2017-7376    2.9.0-2.9.4    xmllint --xinclude in/CVE-2017-7376   (needs redirect server)
CVE-2015-8710    2.9.0-2.9.2    ./build/h8710_2.9.1 in/CVE-2015-8710
```

### giflib (2 PoCs)

```
CVE-2022-28506   5.1.1-5.2.1    gif2rgb in/CVE-2022-28506
CVE-2015-7555    4.1.6-5.1.1    giffix in/CVE-2015-7555
```

### freetype (1 PoC)

```
CVE-2020-15999   2.5.5-2.9.1    ./build/tf_2.9.1 in/CVE-2020-15999
```

------------------------------------------------------------------------

## binutils details

Built versions: 2.24, 2.26, 2.27, 2.28, 2.29, 2.30, 2.31, 2.31.1, 2.32, 2.34,
2.35, 2.35.1, 2.36, 2.38, 2.40 (`--enable-targets=all`, `-fcommon`).

All PoCs are the **test-case attachments of the public sourceware Bugzilla
reports** for the CVE (NVD marks those references "Exploit"). CVE↔bug and
reported crash function:

```
CVE                 bug    att    trigger              crash function
CVE-2017-6965       21137  9804   readelf -w           byte_put_little_endian (elfcomm.c)
CVE-2017-8392       21409  10006  objdump -S           bfd_getl32 (objdump show_line)
CVE-2017-8396       21432  10019  objdump -g           bfd_getl64
CVE-2017-12448      21787  10272  objdump -x           bfd_cache_close
CVE-2017-12449      21840  10285  objdump -x           _bfd_vms_save_sized_string
CVE-2017-12450      21813  10281  objdump -x           alpha_vms_object_p
CVE-2017-12451      21786  10269  objdump -x           _bfd_xcoff_read_ar_hdr
CVE-2017-12452      21813  10281  objdump -x           bfd_mach_o_i386_canonicalize_one_reloc
CVE-2017-12453      21813  10281  objdump -x           _bfd_vms_slurp_eeom
CVE-2017-12454      21813  10281  objdump -x           _bfd_vms_slurp_egsd
CVE-2017-12455      21840  10285  objdump -x           evax_bfd_print_emh
CVE-2017-12456      21813  10281  objdump -x -g        read_symbol_stabs_debugging_info
CVE-2017-12457      21840  10285  objdump -x           bfd_make_section_with_flags
CVE-2017-12458      21840  10285  objdump -x           nlm_swap_auxiliary_headers_in
CVE-2017-12459      21840  10285  objdump -x           bfd_mach_o_read_symtab_strtab
CVE-2017-14130      22058  10383  objdump -x           display_object_bfd
CVE-2017-14529      22113  10404  objdump -x           dump_bfd_private_header
CVE-2017-14729      22113  10404  objdump -x           dump_bfd_private_header
CVE-2017-15225      22212  10486  readelf -w           get_line_filename_and_dirname (dwarf.c)
CVE-2017-15996      22361  10559  readelf -w           readelf
CVE-2017-16826      22376  10562  objdump -r           dump_relocs_in_section
CVE-2017-16832      22373  10560  objdump -x           display_object_bfd
CVE-2017-17080      22421  10581  objdump -x           display_object_bfd
CVE-2017-17121      22506  10642  objdump -g           perform_reloc
CVE-2017-17122      22508  10644  objdump -r           dump_relocs_in_section
CVE-2017-17123      22509  10645  objdump -g           load_specific_debug_section
CVE-2018-6323       22746  10760  objdump -x           elf_object_p
CVE-2018-1000876    23994  11464  objdump -d           bfd_get_dynamic_reloc_upper_bound
CVE-2018-10372      23064  10951  readelf -w           process_cu_tu_index
CVE-2019-9077       24243  11623  readelf -a           process_mips_specific
CVE-2021-20284      26931  12993  objdump -D           _bfd_elf_slurp_secondary_reloc_section
CVE-2021-20294      26929  12991  readelf --dyn-syms   get_num_dynamic_syms
CVE-2021-45078      28694  13851  objdump -g           finish_stab (stabs.c)
CVE-2022-44840      29732  14421  readelf -w           find_section_in_set
CVE-2022-47695      29846  14478  objdump -d           compare_symbols
CVE-2022-47696      29677  14396  objdump -d           bfd_get_flavour
CVE-2023-1579       29988  14574  objdump -S           coff_slurp_reloc_table
```

Example run:
```bash
ASAN_OPTIONS=detect_leaks=0 $B28/objdump -x in/CVE-2017-12452
ASAN_OPTIONS=detect_leaks=0 $B28/readelf -w in/CVE-2017-15225
ASAN_OPTIONS=detect_leaks=0 $B32/objdump -S in/CVE-2023-1579
```

------------------------------------------------------------------------

## libxml2 details

Built versions: 2.9.0, 2.9.1, 2.9.2, 2.9.4, 2.9.5, 2.9.7, 2.9.8, 2.9.9,
2.9.10, 2.9.11, 2.9.12, 2.9.14.

```bash
X2=libxml2-versions/libxml2-2.9.4/xmllint

# CVE-2017-9047  stack-buffer-overflow in xmlSnprintfElementContent (valid.c)
# source: discoverer full-disclosure reproducer (openwall.com/lists/oss-security/2017/05/15/1)
ASAN_OPTIONS=detect_leaks=0 $X2 --valid in/CVE-2017-9047

# CVE-2017-9049  heap-buffer-overflow in xmlDictComputeFastKey (dict.c:448)
ASAN_OPTIONS=detect_leaks=0 $X2 --memory --oldxml10 in/CVE-2017-9049

# CVE-2016-3627  heap-buffer-overflow (parser.c)
# source: github.com/Oneton429/CVE-2016-3627 (PoC XML file)
ASAN_OPTIONS=detect_leaks=0 libxml2-versions/libxml2-2.9.1/xmllint --valid --recover in/CVE-2016-3627

# CVE-2017-7376  heap-buffer-overflow in nanohttp.c (HTTP redirect port overflow)
# source: github.com/brahmstaedt/libxml2-exploit
python3 build/redir_server.py &                # serves 301 -> http://127.0.0.1:2147426192
ASAN_OPTIONS=detect_leaks=0 $X2 --xinclude in/CVE-2017-7376

# CVE-2015-8710  heap-buffer-overflow in htmlCurrentChar (HTMLparser.c:441)
# source: github.com/Karm/CVE-2015-8710 (reproducer program + payload)
ASAN_OPTIONS=detect_leaks=0 ./build/h8710_2.9.1 in/CVE-2015-8710
# harness: build/cve_2015_8710.c (htmlReadMemory with RECOVER|NOERROR|NOWARNING|NONET)
```

------------------------------------------------------------------------

## giflib details

Built versions: 4.1.6, 5.1.1, 5.1.2, 5.1.4, 5.1.7, 5.1.8, 5.1.9, 5.2.1, 5.2.2.

```bash
# CVE-2022-28506  heap-buffer-overflow in DumpScreen2RGB (gif2rgb.c:298)
# source: github.com/verf1sh/Poc
ASAN_OPTIONS=detect_leaks=0 ./giflib-versions/giflib-5.2.1/gif2rgb in/CVE-2022-28506

# CVE-2015-7555   heap-buffer-overflow in giffix (giffix.c:149, WRITE)
# source: discoverer Full-Disclosure (seclists.org/fulldisclosure/2015/Dec/83)
ASAN_OPTIONS=detect_leaks=0 ./giflib-versions/giflib-5.1.1/util/giffix in/CVE-2015-7555
```

------------------------------------------------------------------------

## freetype details

Built versions: 2.4.11, 2.5.5, 2.6.5, 2.7.1, 2.8.1, 2.9.1, 2.10.4, 2.11.1,
2.12.1, 2.13.0 (2.5.5–2.9.1 rebuilt with PNG support).

```bash
# CVE-2020-15999  heap-buffer-overflow in Load_SBit_Png (pngshim.c) via sbix
# source: github.com/oxfemale/CVE-2020-15999 (arialnew.ttf.sbix.ttf)
ASAN_OPTIONS=detect_leaks=0 ./build/tf_2.9.1 in/CVE-2020-15999
# harness: build/test_face.c
```

------------------------------------------------------------------------

## Not reproducible with the builds available

Public PoCs downloaded but not triggered here (exact vulnerable revision not
built, or exploit-style PoC):

- CVE-2018-20623 (readelf UAF, `process_archive`) — sourceware bug 24049, att 11503.
- CVE-2022-45703 (readelf, `display_debug_section`) — sourceware bug 29799, att 14460 (2.39/2.40-dev window only).
- CVE-2018-18309 / CVE-2018-17360 / CVE-2018-20671 / CVE-2017-7209 — attachments obtained, vulnerable path not reachable with a 64-bit ASAN build of the target versions.
- CVE-2017-8393 / CVE-2017-8394 / CVE-2017-8395 (objcopy) — attachments obtained, not triggered.
- CVE-2017-9954 / CVE-2017-9955 — PoC is a RAR archive (no unrar available).
- CVE-2017-12450/12452/... tar-group members outside the mapped set.
- CVE-2025-27363 (freetype) — github.com/zhuowei/... (`rf2.ttf`), not triggered on 2.11.1/2.12.1/2.13.0 here.
- CVE-2026-18220 (binutils objdump DLX OOB write → RCE) — needs `--target=dlx-elf` build; exploit-style, no clean ASAN crash.

------------------------------------------------------------------------

## 近年新增 (2023–2026, 全部为 sourceware Bugzilla 公开附件)

Newer toolchains built for this batch: binutils 2.41–2.45, 2.47
(`build-asan/` for objdump/readelf; `build-asan-ld/ld/ld-new` for the ld CVEs),
libxml2 2.10.4–2.14.5, freetype 2.13.1–2.14.1, giflib 6.1.3.

### objdump / readelf 类

```
CVE-2023-25588   objdump -d                      2.34 2.35 2.35.1 2.36 2.38
CVE-2025-0840    objdump --insn-width 64 -d      2.27–2.43            (fixed 2.44+)
CVE-2025-11081 * objdump -S -D -x -s -Z -g -e -G -T -t -L -R --disassemble-zeroes --insn-width=32 --disassembler-color=extended   仅 2.45
CVE-2025-11839 * objdump 同上参数                2.42–2.45 (SIGABRT)
CVE-2025-69645 * objdump --source-comment        2.42–2.45 (SIGABRT, assert)
CVE-2025-69652 * readelf -w abbrev              2.42 (ASAN) / 2.45 (SIGABRT)
```

### ld 类 (ld-new 位于 binutils-<ver>/build-asan-ld/ld/ld-new)

```
CVE-2025-5244    ld --no-undefined --orphan-handling discard --gc-sections --no-print-gc-sections -w -r -d   2.44
CVE-2025-11412   ld --gc-sections --no-print-gc-sections -w        2.44–2.45
CVE-2025-11413   ld --gc-sections --no-print-gc-sections -w        2.44–2.45
CVE-2025-11414   ld --gc-sections --no-print-gc-sections -w        2.44–2.45
CVE-2025-11082   ld --gc-sections --no-print-gc-sections -w        2.44–2.45
CVE-2025-11495   ld --gc-sections --no-print-gc-sections -w        2.45
CVE-2025-11083   ld --version-exports-section symbol --shared       2.44–2.45
CVE-2025-11840   ld --version-exports-section symbol --shared       2.44–2.45
CVE-2025-11494   ld --version-exports-section symbol --shared       2.44–2.45
CVE-2026-6846    ld -o /dev/null                                    2.44–2.45
CVE-2026-15003   ld --gc-sections -o /dev/null                      2.44–2.45
CVE-2026-90801   ld --gc-sections -w                                2.44–2.47
CVE-2026-90802   ld -o /dev/null                                    2.44–2.47
CVE-2026-90803   ld -o /dev/null                                    2.45, 2.47
CVE-2026-90828   ld -r -o /dev/null                                 2.44–2.47
CVE-2026-90829   ld -r -o /dev/null                                 2.44–2.47
CVE-2026-90830   ld --shared -z now -o /dev/null                    2.44–2.47
CVE-2026-90831   ld --version-exports-section symbol --shared -o /dev/null   2.45, 2.47
CVE-2026-91779   ld -r -o /dev/null                                 2.44–2.47
CVE-2026-91780   ld -o /dev/null                                    2.44–2.47
CVE-2026-91781   ld -r -o /dev/null                                 2.44–2.47
CVE-2026-91782   ld -o /dev/null                                    2.44
```

(2025 的 ld 批次在 2.47 已修复；2026 的 ld 批次 2.47 仍触发。`*` = 仅部分版本触发。)

### 未能复现的近年 CVE（附件已下载，但需特定 HEAD 版本或精确参数）
CVE-2024-57360, CVE-2025-1147–1152, CVE-2025-1176–1182, CVE-2025-3198,
CVE-2025-69644/69646/69647–69651（需 2.46(HEAD) 构建）, CVE-2025-7545/7546,
CVE-2025-8224, CVE-2026-4647, CVE-2026-90804。附件保留于 /tmp/bu_recent/poc/。
