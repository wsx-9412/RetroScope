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

------------------------------------------------------------------------

## 最新补充 (2026-10-13 第二轮): giflib / libxml2 / freetype 近年 CVE

### giflib (新增 2)

```
CVE-2024-45993   gif2rgb -o /tmp/o in/CVE-2024-45993   5.1.9, 5.2.1, 5.2.2 (DumpScreen2RGB 堆溢出)
                 source: gitlab.com/mthandazo/project-pov (crashes.zip/sample)
CVE-2026-26740   giftool -d 1 < in/CVE-2026-26740      5.2.1, 5.2.2 (EGifGCBToExtension 堆写越界)
                 source: github.com/zakkanijia/POC/giflib/giftool (poc.gif)
                 giftool 需单独构建: make CFLAGS="-O1 -g -fsanitize=address ..." giftool
```

### libxml2 (新增 7, 来源均为 gitlab.gnome.org/GNOME/libxml2 官方 issue 附件)

```
CVE-2024-56171   xmllint --noout --schema <版本自带 test/schemas/bug322411_1.xsd> in/CVE-2024-56171
                 触发: 2.10.4, 2.11.5   (2.12.10 起修复)
CVE-2024-34459   xmllint --htmlout in/CVE-2024-34459
                 触发: 2.11.5           (2.12.7 起修复; 仅 2.11.5)
CVE-2025-27113   xmllint --walker --pattern '/child::info/.' in/CVE-2025-27113
                 触发: 2.9.14, 2.10.4, 2.11.5   (2.12.10 起修复)
CVE-2024-25062   见 harness: build/fuzz_main.c + build/schema_cve25062.c + 版本 fuzz/fuzz.c
                 输入 in/CVE-2024-25062 (repro.bin); 触发: 2.11.5 (xmlValidatePopElement UAF)
CVE-2025-49794   编译 in/CVE-2025-49794.c 链接 libxml2 后直接运行 (payload 内嵌)
                 触发: 2.9.14, 2.11.5, 2.13.6 (xmlSchematronFormatReport UAF)
CVE-2025-49795   编译 in/CVE-2025-49795.c 直接运行
                 触发: 2.11.5, 2.13.6 (xmlSchematronFormatReport NULL 解引用)
CVE-2025-49796   编译 in/CVE-2025-49796.c 直接运行
                 触发: 2.9.14, 2.11.5, 2.13.6 (type confusion)
```

编译 .c PoC 示例:
```bash
gcc -O1 -g -fsanitize=address -Ilibxml2-versions/libxml2-2.13.6/include \
  in/CVE-2025-49795.c libxml2-versions/libxml2-2.13.6/.libs/libxml2.a \
  -lz -lm -fsanitize=address -o /tmp/t && ASAN_OPTIONS=detect_leaks=0 /tmp/t
```

### freetype (新增 4)

```
CVE-2022-27404   harness build/test_face_idx.c (FT_New_Face + 非法 face index -4939615758108852224)
                 触发: 2.11.1 (sfnt_init_face 堆读越界)   (2.12.1 起修复)
                 source: gitlab.freedesktop.org/freetype/freetype/-/issues/1138 (testface)
CVE-2026-23865   harness build/test_var.c (FT_New_Face + FT_Get_MM_Var + 变体坐标)
                 触发: 2.13.1, 2.13.2, 2.13.3, 2.14.0, 2.14.1 (tt_var_get_item_delta 堆读越界)
                 source: gitlab issue 1382 (tests/poc_itemvar_store/poc_itemvar.ttf)
CVE-2026-50811   harness build/ft_get_design_dump.c <font> 64
                 触发: 2.14.0, 2.14.1 (TT_Get_Var_Design OOB 读)   (2.13.3 不触发)
                 source: gitlab issue 1436 (PoC.zip, crash_reproducer_rep01.font)
CVE-2026-95512   harness build/test_face_all.c
                 2.14.1: FT_New_Face 时内存峰值 ~1.1GB (CID subr 重叠资源耗尽, 非崩溃)
                 source: gitlab issue 1457 (example.ps)
```

### 未能复现（附件已下载, 需特定 HEAD 版本）
CVE-2025-32415 (libxml2, 需 2.13.7/2.14.0 精确版本), CVE-2025-67812 (libxml2),
CVE-2025-6170/0990/0992/0989 (libxml2, 无文件型 PoC), CVE-2023-39742 (giflib getarg,
本环境 ASAN 不报), CVE-2023-48161/2025-31344 (giflib, sourceforge 不可达)。

### 全版本扫描结果 (2026-10-15)

CVE-2025-32415 (libxml2): 附件含 bug322411_1.xsd + bug322411_0.xml,
`xmllint --noout --schema` 触发**另一个** UAF (xmlSchemaIDCFillNodeTables):
- 2.9.0, 2.9.14, 2.10.4, 2.11.5: heap-use-after-free
- 2.12.10+ 不触发 (此 UAF 已在 2.12 修复)

但 **CVE-2025-32415 本体** 是 heap-buffer-overflow (nbNodes=0 时 nodeTable[-1] 越界读),
需 fuzzer 输入 (xmlSchemaIDCFillNodeTables-hbo), GitLab upload 需登录无法下载。
**舍弃**: 已下载附件不触发 CVE-2025-32415 本体。

CVE-2025-67812 (libxml2): 4096 字节模糊 XML 文本, 未找到 CVE 详情,
各版本 xmllint 常见参数 (--noout/--html/--push/--stream/--reader/--relaxng/--schema)
均无 ASan 崩溃。**舍弃**。

------------------------------------------------------------------------

## 同漏洞跨版本验证 (2026-10-14, verify_poc_versions.py)

对以上全部已下载 PoC (103 个 CVE, binutils 2.24–2.47 / ld-new 2.44–2.47 /
libxml2 2.9.0–2.14.5 / giflib 4.1.6–6.1.3 / freetype harness) 逐一跨版本
复测。判定复用管线同款标准 (`trace_fork_offsets.py::compare_crash_signatures`):

- **同漏洞** = ASan 崩溃类型一致 + 最内层用户帧函数一致 (same_site/same_func);
- **同类型异点** (类型同、函数/语句不同) 判为**不同漏洞**;
- 无 ASan 报告的 SIGABRT (assert) 单独按信号记录;
- "报告函数不一致!" 多为 ASan 最内层帧停在 memcpy/fread/bfd_getl32 等
  公共辅助函数、而 Bugzilla 报告的是调用方 —— 不影响同漏洞判定
  (判定基于 ref 崩溃签名跨版本对比, 非与报告函数比对)。

原始数据: `results/poc_samevuln/results.json`; 复跑: `python3 verify_poc_versions.py`。

### 本轮修正的两处记录

- **CVE-2026-91782**: 触发为 `ld -o /dev/null in/CVE-2026-91782`
  (**不带 -r**; 带 -r 各版本均不崩溃, 旧记录中的 `-r` 为笔误, 上表已按
  实测更正)。实测仅 2.44 触发 (SEGV elf_x86_allocate_dynrelocs),
  2.45/2.47 已修复。
- **CVE-2017-17122**: 2.29 上 objdump 输出 "File truncated" 正常退出、
  **不崩溃**; 实际同漏洞版本为 2.25–2.28 与 2.34–2.36 (ASan OOM in
  _objalloc_alloc), 2.24 为异类型通用崩溃。上表 "2.26-2.29" 应去掉 2.29。
- CVE-2017-14529 / CVE-2017-14729: 2.24–2.28 首轮 15s 超时, 60s 复跑后
  2.25–2.28 判定为同漏洞 (2.24 异类型)。
- **CVE-2018-18605**: 早期"2.25/2.27 打不开 PoC"的记录系误用 `ld -w` 所致;
  官方命令为 **`readelf -w`**。实测全版本扫描: 2.24–2.29 均触发 ASan
  heap-buffer-overflow (2.26–2.29 same_func `get_line_filename_and_dirname`,
  2.24/2.25 异函数 `display_debug_lines_raw`), **2.30 起不触发**。
  回归配置定为 REF=2.29 / TGT=2.30。


## 同漏洞跨版本验证 (2026-10-14)

判定标准与代码一致 (`trace_fork_offsets.py::compare_crash_signatures`): **同漏洞** = ASan 崩溃类型一致 + 最内层用户帧函数一致 (same_site/same_func); same_type (类型同、函数/语句不同) 判为**不同漏洞**; 无 ASan 报告的信号崩溃单独按信号记录。
每个 CVE 以文档记录的受影响版本为参考基准 (ref), 其余版本逐一运行同命令并对比崩溃签名。

### binutils (objdump/readelf)

```
CVE-2017-12448  ref=2.29  ref_crash=heap-use-after-free bfd_cache_close  reported=bfd_cache_close [报告函数一致]
    同漏洞: 2.24, 2.25, 2.26, 2.27, 2.28
    不触发: 2.30, 2.31, 2.31.1, 2.32, 2.34, 2.35, 2.35.1, 2.36, 2.38, 2.40, 2.41, 2.42, 2.43, 2.44, 2.45, 2.47
CVE-2017-12449  ref=2.29  ref_crash=heap-buffer-overflow memcpy  reported=_bfd_vms_save_sized_string [报告函数不一致!]
    同漏洞: 2.25
    异类型崩溃: 2.24
    不触发: 2.26, 2.27, 2.28, 2.30, 2.31, 2.31.1, 2.32, 2.34, 2.35, 2.35.1, 2.36, 2.38, 2.40, 2.41, 2.42, 2.43, 2.44, 2.45, 2.47
CVE-2017-12450  ref=2.29  ref_crash=heap-buffer-overflow fread  reported=alpha_vms_object_p [报告函数不一致!]
    同漏洞: 2.24, 2.25, 2.26, 2.27, 2.28
    不触发: 2.30, 2.31, 2.31.1, 2.32, 2.34, 2.35, 2.35.1, 2.36, 2.38, 2.40, 2.41, 2.42, 2.43, 2.44, 2.45, 2.47
CVE-2017-12451  ref=2.29  ref_crash=stack-buffer-overflow _bfd_xcoff_read_ar_hdr  reported=_bfd_xcoff_read_ar_hdr [报告函数一致]
    同漏洞: 2.24, 2.25, 2.26, 2.27, 2.28
    不触发: 2.30, 2.31, 2.31.1, 2.32, 2.34, 2.35, 2.35.1, 2.36, 2.38, 2.40, 2.41, 2.42, 2.43, 2.44, 2.45, 2.47
CVE-2017-12452  ref=2.29  ref_crash=heap-buffer-overflow bfd_mach_o_i386_canonicalize_one_reloc  reported=bfd_mach_o_i386_canonicalize_one_reloc [报告函数一致]
    同漏洞: 2.27, 2.28
    同类型异点(不同漏洞): 2.25, 2.26
    异类型崩溃: 2.24
    不触发: 2.30, 2.31, 2.31.1, 2.32, 2.34, 2.35, 2.35.1, 2.36, 2.38, 2.40, 2.41, 2.42, 2.43, 2.44, 2.45, 2.47
CVE-2017-12453  ref=2.29  ref_crash=heap-buffer-overflow bfd_getl32  reported=_bfd_vms_slurp_eeom [报告函数不一致!]
    同漏洞: 2.24, 2.25, 2.26, 2.27, 2.28
    不触发: 2.30, 2.31, 2.31.1, 2.32, 2.34, 2.35, 2.35.1, 2.36, 2.38, 2.40, 2.41, 2.42, 2.43, 2.44, 2.45, 2.47
CVE-2017-12454  ref=2.29  ref_crash=SEGV _bfd_vms_slurp_egsd  reported=_bfd_vms_slurp_egsd [报告函数一致]
    同漏洞: 2.25, 2.26, 2.27, 2.28
    同类型异点(不同漏洞): 2.24
    不触发: 2.30, 2.31, 2.31.1, 2.32, 2.34, 2.35, 2.35.1, 2.36, 2.38, 2.40, 2.41, 2.42, 2.43, 2.44, 2.45, 2.47
CVE-2017-12455  ref=2.29  ref_crash=heap-buffer-overflow evax_bfd_print_emh  reported=evax_bfd_print_emh [报告函数一致]
    同漏洞: 2.25, 2.26, 2.27, 2.28
    异类型崩溃: 2.24
    不触发: 2.30, 2.31, 2.31.1, 2.32, 2.34, 2.35, 2.35.1, 2.36, 2.38, 2.40, 2.41, 2.42, 2.43, 2.44, 2.45, 2.47
CVE-2017-12456  ref=2.29  ref_crash=heap-buffer-overflow read_symbol_stabs_debugging_info  reported=read_symbol_stabs_debugging_info [报告函数一致]
    同漏洞: 2.25, 2.26, 2.27, 2.28
    异类型崩溃: 2.24
    不触发: 2.30, 2.31, 2.31.1, 2.32, 2.34, 2.35, 2.35.1, 2.36, 2.38, 2.40, 2.41, 2.42, 2.43, 2.44, 2.45, 2.47
CVE-2017-12457  ref=2.29  ref_crash=SEGV bfd_make_section_with_flags  reported=bfd_make_section_with_flags [报告函数一致]
    同漏洞: -
    同类型异点(不同漏洞): 2.24
    不触发: 2.25, 2.26, 2.27, 2.28, 2.30, 2.31, 2.31.1, 2.32, 2.34, 2.35, 2.35.1, 2.36, 2.38, 2.40, 2.41, 2.42, 2.43, 2.44, 2.45, 2.47
CVE-2017-12458  ref=2.29  ref_crash=heap-buffer-overflow nlm_swap_auxiliary_headers_in  reported=nlm_swap_auxiliary_headers_in [报告函数一致]
    同漏洞: 2.24, 2.25, 2.26, 2.27, 2.28
    不触发: 2.30, 2.31, 2.31.1, 2.32, 2.34, 2.35, 2.35.1, 2.36, 2.38, 2.40, 2.41, 2.42, 2.43, 2.44, 2.45, 2.47
CVE-2017-12459  ref=2.29  ref_crash=heap-buffer-overflow fread  reported=bfd_mach_o_read_symtab_strtab [报告函数不一致!]
    同漏洞: 2.26, 2.27, 2.28
    异类型崩溃: 2.24
    不触发: 2.25, 2.30, 2.31, 2.31.1, 2.32, 2.34, 2.35, 2.35.1, 2.36, 2.38, 2.40, 2.41, 2.42, 2.43, 2.44, 2.45, 2.47
CVE-2017-14130  ref=2.29  ref_crash=heap-buffer-overflow _bfd_elf_attr_strdup  reported=display_object_bfd [报告函数不一致!]
    同漏洞: 2.24, 2.25, 2.26, 2.27, 2.28
    不触发: 2.30, 2.31, 2.31.1, 2.32, 2.34, 2.35, 2.35.1, 2.36, 2.38, 2.40, 2.41, 2.42, 2.43, 2.44, 2.45, 2.47
CVE-2017-14529  ref=2.29  ref_crash=heap-buffer-overflow bfd_getl16  reported=dump_bfd_private_header [报告函数不一致!]
    同漏洞: 2.25, 2.26, 2.27, 2.28
    异类型崩溃: 2.24
    不触发: 2.30, 2.31, 2.31.1, 2.32, 2.34, 2.35, 2.35.1, 2.36, 2.38, 2.40, 2.41, 2.42, 2.43, 2.44, 2.45, 2.47
CVE-2017-14729  ref=2.29  ref_crash=heap-buffer-overflow bfd_getl16  reported=dump_bfd_private_header [报告函数不一致!]
    同漏洞: 2.25, 2.26, 2.27, 2.28
    异类型崩溃: 2.24
    不触发: 2.30, 2.31, 2.31.1, 2.32, 2.34, 2.35, 2.35.1, 2.36, 2.38, 2.40, 2.41, 2.42, 2.43, 2.44, 2.45, 2.47
CVE-2017-15225  ref=2.29  ref_crash=heap-buffer-overflow get_line_filename_and_dirname  reported=get_line_filename_and_dirname [报告函数一致]
    同漏洞: 2.26, 2.27, 2.28
    同类型异点(不同漏洞): 2.25
    异类型崩溃: 2.24
    不触发: 2.30, 2.31, 2.31.1, 2.32, 2.34, 2.35, 2.35.1, 2.36, 2.38, 2.40, 2.41, 2.42, 2.43, 2.44, 2.45, 2.47
CVE-2017-15996  ref=2.29  ref_crash=allocator setup_archive  reported=?
    同漏洞: 2.24, 2.25, 2.26, 2.28
    异类型崩溃: 2.27
    不触发: 2.30, 2.31, 2.31.1, 2.32, 2.34, 2.35, 2.35.1, 2.36, 2.38, 2.40, 2.41, 2.42, 2.43, 2.44, 2.45, 2.47
CVE-2017-16826  ref=2.29  ref_crash=allocator _objalloc_alloc  reported=dump_relocs_in_section [报告函数不一致!]
    同漏洞: 2.25, 2.26, 2.27, 2.28
    异类型崩溃: 2.24
    不触发: 2.30, 2.31, 2.31.1, 2.32, 2.34, 2.35, 2.35.1, 2.36, 2.38, 2.40, 2.41, 2.42, 2.43, 2.44, 2.45, 2.47
CVE-2017-16832  ref=2.29  ref_crash=heap-buffer-overflow bfd_getl32  reported=display_object_bfd [报告函数不一致!]
    同漏洞: 2.26, 2.27, 2.28
    同类型异点(不同漏洞): 2.25
    异类型崩溃: 2.24
    不触发: 2.30, 2.31, 2.31.1, 2.32, 2.34, 2.35, 2.35.1, 2.36, 2.38, 2.40, 2.41, 2.42, 2.43, 2.44, 2.45, 2.47
CVE-2017-17080  ref=2.29  ref_crash=heap-buffer-overflow bfd_getl32  reported=display_object_bfd [报告函数不一致!]
    同漏洞: 2.25, 2.26, 2.27, 2.28
    异类型崩溃: 2.24
    不触发: 2.30, 2.31, 2.31.1, 2.32, 2.34, 2.35, 2.35.1, 2.36, 2.38, 2.40, 2.41, 2.42, 2.43, 2.44, 2.45, 2.47
CVE-2017-17121  ref=2.29  ref_crash=SEGV bfd_getl32  reported=perform_reloc [报告函数不一致!]
    同漏洞: 2.25, 2.26, 2.27, 2.28
    同类型异点(不同漏洞): 2.24
    不触发: 2.30, 2.31, 2.31.1, 2.32, 2.34, 2.35, 2.35.1, 2.36, 2.38, 2.40, 2.41, 2.42, 2.43, 2.44, 2.45, 2.47
CVE-2017-17122  ref=2.28  ref_crash=allocator _objalloc_alloc  reported=dump_relocs_in_section [报告函数不一致!]
    同漏洞: 2.25, 2.26, 2.27, 2.34, 2.35, 2.35.1, 2.36
    异类型崩溃: 2.24
    不触发: 2.29, 2.30, 2.31, 2.31.1, 2.32, 2.38, 2.40, 2.41, 2.42, 2.43, 2.44, 2.45, 2.47
CVE-2017-17123  ref=2.29  ref_crash=SEGV coff_slurp_reloc_table  reported=load_specific_debug_section [报告函数不一致!]
    同漏洞: 2.26, 2.27, 2.28
    同类型异点(不同漏洞): 2.24, 2.35, 2.35.1, 2.36
    不触发: 2.25, 2.30, 2.31, 2.31.1, 2.32, 2.34, 2.38, 2.40, 2.41, 2.42, 2.43, 2.44, 2.45, 2.47
CVE-2017-6965  ref=2.28  ref_crash=heap-buffer-overflow byte_put_little_endian  reported=byte_put_little_endian [报告函数一致]
    同漏洞: 2.24, 2.25, 2.26, 2.27
    不触发: 2.29, 2.30, 2.31, 2.31.1, 2.32, 2.34, 2.35, 2.35.1, 2.36, 2.38, 2.40, 2.41, 2.42, 2.43, 2.44, 2.45, 2.47
CVE-2017-8392  ref=2.28  ref_crash=heap-buffer-overflow bfd_getl32  reported=bfd_getl32 [报告函数一致]
    同漏洞: 2.25, 2.26, 2.27
    异类型崩溃: 2.24
    不触发: 2.29, 2.30, 2.31, 2.31.1, 2.32, 2.34, 2.35, 2.35.1, 2.36, 2.38, 2.40, 2.41, 2.42, 2.43, 2.44, 2.45, 2.47
CVE-2017-8396  ref=2.28  ref_crash=heap-buffer-overflow bfd_getl64  reported=bfd_getl64 [报告函数一致]
    同漏洞: 2.26, 2.27
    不触发: 2.24, 2.25, 2.29, 2.30, 2.31, 2.31.1, 2.32, 2.34, 2.35, 2.35.1, 2.36, 2.38, 2.40, 2.41, 2.42, 2.43, 2.44, 2.45, 2.47
CVE-2018-1000876  ref=2.34  ref_crash=allocator bfd_malloc  reported=bfd_get_dynamic_reloc_upper_bound [报告函数不一致!]
    同漏洞: 2.29, 2.30, 2.31, 2.31.1, 2.32
    异类型崩溃: 2.24, 2.25, 2.26, 2.27, 2.28
    不触发: 2.35, 2.35.1, 2.36, 2.38, 2.40, 2.41, 2.42, 2.43, 2.44, 2.45, 2.47
CVE-2018-10372  ref=2.30  ref_crash=heap-buffer-overflow printf  reported=process_cu_tu_index [报告函数不一致!]
    同漏洞: 2.26, 2.27, 2.28, 2.29
    同类型异点(不同漏洞): 2.24, 2.25
    不触发: 2.31, 2.31.1, 2.32, 2.34, 2.35, 2.35.1, 2.36, 2.38, 2.40, 2.41, 2.42, 2.43, 2.44, 2.45, 2.47
CVE-2018-18605  ref=2.29  ref_crash=heap-buffer-overflow get_line_filename_and_dirname  reported=byte_get_little_endian [报告函数不一致!]
    同漏洞: 2.26, 2.27, 2.28
    同类型异点(不同漏洞): 2.24, 2.25
    不触发: 2.30, 2.31, 2.31.1, 2.32, 2.34, 2.35, 2.35.1, 2.36, 2.38, 2.40, 2.41, 2.42, 2.43, 2.44, 2.45, 2.47
CVE-2018-18606  ref=2.29  ref_crash=heap-buffer-overflow get_line_filename_and_dirname  reported=?
    同漏洞: 2.26, 2.27, 2.28
    同类型异点(不同漏洞): 2.25
    异类型崩溃: 2.24
    不触发: 2.30, 2.31, 2.31.1, 2.32, 2.34, 2.35, 2.35.1, 2.36, 2.38, 2.40, 2.41, 2.42, 2.43, 2.44, 2.45, 2.47
CVE-2018-18607  ref=2.29  ref_crash=heap-buffer-overflow get_line_filename_and_dirname  reported=?
    同漏洞: 2.26, 2.27, 2.28
    同类型异点(不同漏洞): 2.24, 2.25
    不触发: 2.30, 2.31, 2.31.1, 2.32, 2.34, 2.35, 2.35.1, 2.36, 2.38, 2.40, 2.41, 2.42, 2.43, 2.44, 2.45, 2.47
CVE-2018-19931  ref=2.31.1  ref_crash=allocator _objalloc_alloc  reported=?
    同漏洞: 2.24, 2.25, 2.26, 2.27, 2.28, 2.29, 2.30, 2.31
    不触发: 2.32, 2.34, 2.35, 2.35.1, 2.36, 2.38, 2.40, 2.41, 2.42, 2.43, 2.44, 2.45, 2.47
CVE-2018-20002  ref=2.32  ref_crash=requested bfd_malloc  reported=?
    同漏洞: 2.25, 2.26, 2.27, 2.28, 2.29, 2.30, 2.31, 2.31.1
    异类型崩溃: 2.24
    不触发: 2.34, 2.35, 2.35.1, 2.36, 2.38, 2.40, 2.41, 2.42, 2.43, 2.44, 2.45, 2.47
CVE-2018-6323  ref=2.31.1  ref_crash=allocator _objalloc_alloc  reported=elf_object_p [报告函数不一致!]
    同漏洞: 2.24, 2.25, 2.26, 2.27, 2.28, 2.29, 2.30, 2.31
    不触发: 2.32, 2.34, 2.35, 2.35.1, 2.36, 2.38, 2.40, 2.41, 2.42, 2.43, 2.44, 2.45, 2.47
CVE-2019-17450  ref=2.34  ref_crash=requested load_specific_debug_section  reported=?
    同漏洞: 2.30, 2.31, 2.31.1, 2.35, 2.35.1, 2.36
    同类型异点(不同漏洞): 2.24, 2.25, 2.38
    不触发: 2.26, 2.27, 2.28, 2.29, 2.32, 2.40, 2.41, 2.42, 2.43, 2.44, 2.45, 2.47
CVE-2019-17451  ref=2.34  ref_crash=requested load_specific_debug_section  reported=?
    同漏洞: 2.30, 2.31, 2.31.1, 2.35, 2.35.1, 2.36
    同类型异点(不同漏洞): 2.25, 2.26, 2.27, 2.28, 2.29, 2.38
    异类型崩溃: 2.24
    不触发: 2.32, 2.40, 2.41, 2.42, 2.43, 2.44, 2.45, 2.47
CVE-2019-9073  ref=2.32  ref_crash=allocator bfd_malloc  reported=?
    同漏洞: 2.25, 2.26, 2.27, 2.28, 2.29, 2.30, 2.31, 2.31.1
    异类型崩溃: 2.24
    不触发: 2.34, 2.35, 2.35.1, 2.36, 2.38, 2.40, 2.41, 2.42, 2.43, 2.44, 2.45, 2.47
CVE-2019-9074  ref=2.32  ref_crash=SEGV bfd_getl32  reported=?
    同漏洞: 2.26, 2.27, 2.28, 2.29, 2.30, 2.31, 2.31.1
    同类型异点(不同漏洞): 2.24
    不触发: 2.25, 2.34, 2.35, 2.35.1, 2.36, 2.38, 2.40, 2.41, 2.42, 2.43, 2.44, 2.45, 2.47
CVE-2019-9075  ref=2.32  ref_crash=heap-buffer-overflow _bfd_archive_64_bit_slurp_armap  reported=?
    同漏洞: 2.27, 2.28, 2.29, 2.30, 2.31, 2.31.1
    同类型异点(不同漏洞): 2.24, 2.25, 2.26
    不触发: 2.34, 2.35, 2.35.1, 2.36, 2.38, 2.40, 2.41, 2.42, 2.43, 2.44, 2.45, 2.47
CVE-2019-9076  ref=2.34  ref_crash=allocator bfd_malloc  reported=?
    同漏洞: 2.25, 2.26, 2.27, 2.28, 2.29, 2.30, 2.31, 2.31.1, 2.32
    异类型崩溃: 2.24
    不触发: 2.35, 2.35.1, 2.36, 2.38, 2.40, 2.41, 2.42, 2.43, 2.44, 2.45, 2.47
CVE-2019-9077  ref=2.32  ref_crash=heap-buffer-overflow process_mips_specific  reported=process_mips_specific [报告函数一致]
    同漏洞: 2.24, 2.25, 2.26, 2.27, 2.28, 2.29, 2.30, 2.31, 2.31.1
    不触发: 2.34, 2.35, 2.35.1, 2.36, 2.38, 2.40, 2.41, 2.42, 2.43, 2.44, 2.45, 2.47
CVE-2020-16592  ref=2.34  ref_crash=heap-use-after-free bfd_hash_lookup  reported=?
    同漏洞: -
    异类型崩溃: 2.24
    不触发: 2.25, 2.26, 2.27, 2.28, 2.29, 2.30, 2.31, 2.31.1, 2.32, 2.35, 2.35.1, 2.36, 2.38, 2.40, 2.41, 2.42, 2.43, 2.44, 2.45, 2.47
CVE-2020-16599  ref=2.32  ref_crash=allocator bfd_malloc  reported=?
    同漏洞: 2.24, 2.25, 2.26, 2.27, 2.28, 2.29, 2.30, 2.31, 2.31.1
    不触发: 2.34, 2.35, 2.35.1, 2.36, 2.38, 2.40, 2.41, 2.42, 2.43, 2.44, 2.45, 2.47
CVE-2020-35448  ref=2.35.1  ref_crash=heap-buffer-overflow bfd_getl_signed_32  reported=?
    同漏洞: 2.35
    异类型崩溃: 2.24
    不触发: 2.25, 2.26, 2.27, 2.28, 2.29, 2.30, 2.31, 2.31.1, 2.32, 2.34, 2.36, 2.38, 2.40, 2.41, 2.42, 2.43, 2.44, 2.45, 2.47
CVE-2021-20284  ref=2.35.1  ref_crash=heap-buffer-overflow _bfd_elf_slurp_secondary_reloc_section  reported=_bfd_elf_slurp_secondary_reloc_section [报告函数一致]
    同漏洞: 2.35
    同类型异点(不同漏洞): 2.26
    异类型崩溃: 2.24
    不触发: 2.25, 2.27, 2.28, 2.29, 2.30, 2.31, 2.31.1, 2.32, 2.34, 2.36, 2.38, 2.40, 2.41, 2.42, 2.43, 2.44, 2.45, 2.47
CVE-2021-20294  ref=2.35.1  ref_crash=stack-buffer-overflow sprintf  reported=get_num_dynamic_syms [报告函数不一致!]
    同漏洞: 2.35
    异类型崩溃: 2.24
    不触发: 2.25, 2.26, 2.27, 2.28, 2.29, 2.30, 2.31, 2.31.1, 2.32, 2.34, 2.36, 2.38, 2.40, 2.41, 2.42, 2.43, 2.44, 2.45, 2.47
CVE-2021-45078  ref=2.36  ref_crash=heap-buffer-overflow finish_stab  reported=finish_stab [报告函数一致]
    同漏洞: 2.24, 2.25, 2.26, 2.27, 2.28, 2.29, 2.30, 2.31, 2.31.1, 2.32, 2.34, 2.35, 2.35.1
    不触发: 2.38, 2.40, 2.41, 2.42, 2.43, 2.44, 2.45, 2.47
CVE-2021-46174  ref=2.36  ref_crash=heap-buffer-overflow bfd_getl32  reported=?
    同漏洞: 2.25, 2.26, 2.27, 2.28, 2.29, 2.30, 2.31, 2.31.1, 2.32, 2.34, 2.35, 2.35.1
    异类型崩溃: 2.24
    不触发: 2.38, 2.40, 2.41, 2.42, 2.43, 2.44, 2.45, 2.47
CVE-2022-44840  ref=2.38  ref_crash=heap-buffer-overflow find_section_in_set  reported=find_section_in_set [报告函数一致]
    同漏洞: -
    不触发: 2.24, 2.25, 2.26, 2.27, 2.28, 2.29, 2.30, 2.31, 2.31.1, 2.32, 2.34, 2.35, 2.35.1, 2.36, 2.40, 2.41, 2.42, 2.43, 2.44, 2.45, 2.47
CVE-2022-47695  ref=2.38  ref_crash=SEGV bfd_get_flavour  reported=compare_symbols [报告函数不一致!]
    同漏洞: 2.34, 2.35, 2.35.1, 2.36
    同类型异点(不同漏洞): 2.24, 2.28, 2.29, 2.30, 2.31, 2.31.1, 2.32
    不触发: 2.25, 2.26, 2.27, 2.40, 2.41, 2.42, 2.43, 2.44, 2.45, 2.47
CVE-2022-47696  ref=2.38  ref_crash=SEGV bfd_get_flavour  reported=bfd_get_flavour [报告函数一致]
    同漏洞: 2.34, 2.35, 2.35.1, 2.36
    同类型异点(不同漏洞): 2.24, 2.25
    不触发: 2.26, 2.27, 2.28, 2.29, 2.30, 2.31, 2.31.1, 2.32, 2.40, 2.41, 2.42, 2.43, 2.44, 2.45, 2.47
CVE-2022-48063  ref=2.38  ref_crash=allocator xmalloc  reported=?
    同漏洞: -
    同类型异点(不同漏洞): 2.34, 2.35, 2.35.1, 2.36
    异类型崩溃: 2.24, 2.25
    不触发: 2.26, 2.27, 2.28, 2.29, 2.30, 2.31, 2.31.1, 2.32, 2.40, 2.41, 2.42, 2.43, 2.44, 2.45, 2.47
CVE-2022-48064  ref=2.32  ref_crash=requested bfd_malloc  reported=?
    同漏洞: 2.25, 2.26, 2.27, 2.28, 2.29, 2.30, 2.31, 2.31.1
    异类型崩溃: 2.24
    不触发: 2.34, 2.35, 2.35.1, 2.36, 2.38, 2.40, 2.41, 2.42, 2.43, 2.44, 2.45, 2.47
CVE-2023-1579  ref=2.35.1  ref_crash=requested xmalloc  reported=coff_slurp_reloc_table [报告函数不一致!]
    同漏洞: 2.26, 2.27, 2.28, 2.29, 2.30, 2.31, 2.31.1, 2.32, 2.34, 2.35
    同类型异点(不同漏洞): 2.24, 2.25
    不触发: 2.36, 2.38, 2.40, 2.41, 2.42, 2.43, 2.44, 2.45, 2.47
CVE-2023-1972  ref=2.32  ref_crash=requested xmalloc  reported=?
    同漏洞: 2.25, 2.26, 2.27, 2.28, 2.29, 2.30, 2.31, 2.31.1
    异类型崩溃: 2.24, 2.40
    不触发: 2.34, 2.35, 2.35.1, 2.36, 2.38, 2.41, 2.42, 2.43, 2.44, 2.45, 2.47
CVE-2023-25588  ref=2.38  ref_crash=SEGV bfd_get_flavour  reported=?
    同漏洞: 2.34, 2.35, 2.35.1, 2.36
    同类型异点(不同漏洞): 2.24, 2.25
    不触发: 2.26, 2.27, 2.28, 2.29, 2.30, 2.31, 2.31.1, 2.32, 2.40, 2.41, 2.42, 2.43, 2.44, 2.45, 2.47
CVE-2025-0840  ref=2.43  ref_crash=stack-buffer-overflow disassemble_bytes  reported=?
    同漏洞: 2.25, 2.26, 2.27, 2.28, 2.29, 2.30, 2.31, 2.31.1, 2.32, 2.34, 2.35, 2.35.1, 2.36, 2.38, 2.40, 2.41, 2.42
    异类型崩溃: 2.24
    不触发: 2.44, 2.45, 2.47
CVE-2025-11081  ref=2.45  ref_crash=SEGV dump_dwarf_section  reported=?
    同漏洞: -
    不触发: 2.24, 2.25, 2.26, 2.27, 2.28, 2.29, 2.30, 2.31, 2.31.1, 2.32, 2.34, 2.35, 2.35.1, 2.36, 2.38, 2.40, 2.41, 2.42, 2.43, 2.44, 2.47
CVE-2025-11839  ref=2.45  ref_crash=no-ASAN SIGABRT  reported=?
    同漏洞: -
    signal:SIGABRT (无ASAN报告): 2.42, 2.43, 2.44
    不触发: 2.24, 2.25, 2.26, 2.27, 2.28, 2.29, 2.30, 2.31, 2.31.1, 2.32, 2.34, 2.35, 2.35.1, 2.36, 2.38, 2.40, 2.41, 2.47
CVE-2025-69645  ref=2.45  ref_crash=no-ASAN SIGABRT  reported=?
    同漏洞: -
    signal:SIGABRT (无ASAN报告): 2.42, 2.43, 2.44
    不触发: 2.24, 2.25, 2.26, 2.27, 2.28, 2.29, 2.30, 2.31, 2.31.1, 2.32, 2.34, 2.35, 2.35.1, 2.36, 2.38, 2.40, 2.41, 2.47
CVE-2025-69652  ref=2.42  ref_crash=SEGV read_bases  reported=?
    同漏洞: -
    signal:SIGABRT (无ASAN报告): 2.45
    不触发: 2.24, 2.25, 2.26, 2.27, 2.28, 2.29, 2.30, 2.31, 2.31.1, 2.32, 2.34, 2.35, 2.35.1, 2.36, 2.38, 2.40, 2.41, 2.43, 2.44, 2.47
```

### binutils ld-new

```
CVE-2025-11082  ref=2.45  ref_crash=heap-buffer-overflow _bfd_elf_parse_eh_frame  reported=?
    同漏洞: 2.44
    不触发: 2.47
CVE-2025-11083  ref=2.45  ref_crash=heap-buffer-overflow cache_bwrite  reported=?
    同漏洞: 2.44
    不触发: 2.47
CVE-2025-11412  ref=2.45  ref_crash=SEGV bfd_elf_gc_record_vtentry  reported=?
    同漏洞: 2.44
    不触发: 2.47
CVE-2025-11413  ref=2.45  ref_crash=SEGV bfd_elf_gc_record_vtentry  reported=?
    同漏洞: 2.44
    不触发: 2.47
CVE-2025-11414  ref=2.45  ref_crash=SEGV get_link_hash_entry  reported=?
    同漏洞: -
    同类型异点(不同漏洞): 2.44
    不触发: 2.47
CVE-2025-11494  ref=2.45  ref_crash=SEGV _bfd_elf_write_section_eh_frame  reported=?
    同漏洞: 2.44
    不触发: 2.47
CVE-2025-11495  ref=2.45  ref_crash=heap-buffer-overflow elf_x86_64_relocate_section  reported=?
    同漏洞: -
    不触发: 2.44, 2.47
CVE-2025-11840  ref=2.45  ref_crash=SEGV fprintf  reported=?
    同漏洞: 2.44
    不触发: 2.47
CVE-2025-5244  ref=2.44  ref_crash=SEGV __GI__IO_default_xsputn  reported=?
    同漏洞: -
    不触发: 2.45, 2.47
CVE-2026-15003  ref=2.45  ref_crash=heap-buffer-overflow bfd_getb32  reported=?
    同漏洞: 2.44
    不触发: 2.47
CVE-2026-6846  ref=2.45  ref_crash=heap-buffer-overflow xcoff_link_add_symbols  reported=?
    同漏洞: 2.44
    不触发: 2.47
CVE-2026-90801  ref=2.47  ref_crash=heap-buffer-overflow cache_bwrite  reported=?
    同漏洞: 2.45
    同类型异点(不同漏洞): 2.44
CVE-2026-90802  ref=2.47  ref_crash=SEGV bfd_putl64  reported=?
    同漏洞: 2.44, 2.45
CVE-2026-90803  ref=2.47  ref_crash=heap-buffer-overflow elf_x86_64_relocate_section  reported=?
    同漏洞: 2.45
    不触发: 2.44
CVE-2026-90828  ref=2.47  ref_crash=SEGV elf_orphan_compatible  reported=?
    同漏洞: 2.44, 2.45
CVE-2026-90829  ref=2.47  ref_crash=SEGV bfd_elf_set_group_contents  reported=?
    同漏洞: 2.44, 2.45
CVE-2026-90830  ref=2.47  ref_crash=SEGV _bfd_write_merged_section  reported=?
    同漏洞: -
    同类型异点(不同漏洞): 2.44, 2.45
CVE-2026-90831  ref=2.47  ref_crash=SEGV _bfd_elf_strtab_delref  reported=?
    同漏洞: 2.45
    不触发: 2.44
CVE-2026-91779  ref=2.47  ref_crash=SEGV _bfd_elf_eh_frame_section_offset  reported=?
    同漏洞: 2.44, 2.45
CVE-2026-91780  ref=2.47  ref_crash=SEGV elf_link_add_object_symbols  reported=?
    同漏洞: 2.44, 2.45
CVE-2026-91781  ref=2.47  ref_crash=SEGV elf_x86_64_common_section_index  reported=?
    同漏洞: 2.44, 2.45
CVE-2026-91782  ref=2.44  ref_crash=SEGV elf_x86_allocate_dynrelocs  reported=?
    同漏洞: -
    不触发: 2.45, 2.47
```

### libxml2

```
CVE-2015-8710  ref=2.9.1  ref_crash=heap-buffer-overflow htmlCurrentChar  reported=htmlCurrentChar [报告函数一致]
    同漏洞: 2.9.0, 2.9.2
    不触发: 2.9.4
CVE-2016-3627  ref=2.9.2  ref_crash=stack-overflow xmlStrndup  reported=?
    同漏洞: 2.9.0
    同类型异点(不同漏洞): 2.9.1
    不触发: 2.9.4, 2.9.5, 2.9.7, 2.9.8, 2.9.9, 2.9.10, 2.9.11, 2.9.12, 2.9.14, 2.10.4, 2.11.5, 2.12.10, 2.13.6, 2.14.5
CVE-2017-7376  ref=2.9.4  ref_crash=heap-buffer-overflow snprintf  reported=?
    同漏洞: 2.9.0, 2.9.1, 2.9.2
    不触发: 2.9.5, 2.9.7, 2.9.8, 2.9.9, 2.9.10, 2.9.11, 2.9.12, 2.9.14, 2.10.4, 2.11.5, 2.12.10, 2.13.6, 2.14.5
CVE-2017-9047  ref=2.9.4  ref_crash=stack-buffer-overflow strcat  reported=xmlSnprintfElementContent [报告函数不一致!]
    同漏洞: 2.9.0, 2.9.1, 2.9.2
    不触发: 2.9.5, 2.9.7, 2.9.8, 2.9.9, 2.9.10, 2.9.11, 2.9.12, 2.9.14, 2.10.4, 2.11.5, 2.12.10, 2.13.6, 2.14.5
CVE-2017-9049  ref=2.9.4  ref_crash=heap-buffer-overflow xmlDictComputeFastKey  reported=xmlDictComputeFastKey [报告函数一致]
    同漏洞: -
    不触发: 2.9.0, 2.9.1, 2.9.2, 2.9.5, 2.9.7, 2.9.8, 2.9.9, 2.9.10, 2.9.11, 2.9.12, 2.9.14, 2.10.4, 2.11.5, 2.12.10, 2.13.6, 2.14.5
CVE-2024-25062  ref=2.11.5  ref_crash=heap-use-after-free xmlValidatePopElement  reported=xmlValidatePopElement [报告函数一致]
    同漏洞: -
    不触发: 2.12.10
CVE-2024-34459  ref=2.11.5  ref_crash=heap-buffer-overflow xmlHTMLPrintFileContext  reported=?
    同漏洞: 2.9.5, 2.9.7, 2.9.8, 2.9.9, 2.9.10
    不触发: 2.9.0, 2.9.1, 2.9.2, 2.9.4, 2.9.11, 2.9.12, 2.9.14, 2.10.4, 2.12.10, 2.13.6, 2.14.5
CVE-2025-27113  ref=2.11.5  ref_crash=SEGV xmlPatMatch  reported=?
    同漏洞: 2.9.0, 2.9.1, 2.9.2, 2.9.4, 2.9.5, 2.9.7, 2.9.8, 2.9.9, 2.9.10, 2.9.11, 2.9.12, 2.9.14, 2.10.4
    不触发: 2.12.10, 2.13.6, 2.14.5
CVE-2025-49794  ref=2.11.5  ref_crash=SEGV xmlSchematronFormatReport  reported=xmlSchematronFormatReport [报告函数一致]
    同漏洞: 2.9.14, 2.13.6
CVE-2025-49795  ref=2.11.5  ref_crash=SEGV xmlSchematronFormatReport  reported=xmlSchematronFormatReport [报告函数一致]
    同漏洞: 2.13.6
    不触发: 2.9.14
CVE-2025-49796  ref=2.11.5  ref_crash=SEGV xmlSchematronFormatReport  reported=?
    同漏洞: 2.9.14, 2.13.6
```

### giflib

```
CVE-2015-7555  ref=5.1.1  ref_crash=heap-buffer-overflow main  reported=?
    同漏洞: 4.1.6
    不触发: 5.1.2, 5.1.4, 5.1.7, 5.1.8, 5.1.9, 5.2.1, 5.2.2, 6.1.3
CVE-2022-28506  ref=5.2.1  ref_crash=heap-buffer-overflow DumpScreen2RGB  reported=DumpScreen2RGB [报告函数一致]
    同漏洞: 5.1.1, 5.1.2, 5.1.4, 5.1.7, 5.1.8, 5.1.9
    不触发: 4.1.6, 5.2.2, 6.1.3
CVE-2024-45993  ref=5.2.1  ref_crash=heap-buffer-overflow DumpScreen2RGB  reported=?
    同漏洞: 4.1.6, 5.1.1, 5.1.2, 5.1.4, 5.1.7, 5.1.8, 5.1.9, 5.2.2
    不触发: 6.1.3
CVE-2026-26740  ref=5.2.1  ref_crash=heap-buffer-overflow EGifGCBToExtension  reported=?
    同漏洞: 5.1.1, 5.1.2, 5.1.4, 5.2.2
```

### freetype

```
CVE-2020-15999  ref=2.9.1  ref_crash=heap-buffer-overflow png_combine_row  reported=Load_SBit_Png [报告函数不一致!]
    同漏洞: 2.5.5, 2.6.5, 2.7.1
    同类型异点(不同漏洞): 2.8.1
CVE-2022-27404  ref=2.11.1  ref_crash=heap-buffer-overflow sfnt_init_face  reported=sfnt_init_face [报告函数一致]
    同漏洞: -
CVE-2026-23865  ref=2.14.1  ref_crash=SEGV tt_var_get_item_delta  reported=tt_var_get_item_delta [报告函数一致]
    同漏洞: 2.13.1, 2.13.2, 2.13.3, 2.14.0
CVE-2026-50811  ref=2.14.1  ref_crash=heap-buffer-overflow TT_Get_Var_Design  reported=TT_Get_Var_Design [报告函数一致]
    同漏洞: 2.14.0
    不触发: 2.13.3
CVE-2026-95512  ref=2.14.1  ref_crash=no crash  reported=?
    同漏洞: -
```

