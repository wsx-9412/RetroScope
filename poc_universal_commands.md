# PoC 老版本同触发清单（非版本敏感）

本表收录：PoC 在**发现漏洞的版本**触发，且**更老版本也触发相同漏洞**（或整段受影响区间通用触发）的 CVE。
这些 PoC 不满足跨版本 fork 分析的"老版本不触发"条件，从 `poc_run_commands.md` 主表剔除，单独备查。

判定标准与主表一致：同漏洞 = ASan 崩溃类型一致 + 最内层用户帧函数一致
（same_site/same_func）；同类型异点（函数不同）判为不同漏洞。
数据来源：`results/poc_samevuln/results.json`（103-CVE 同漏洞跨版本验证）。

环境: `ASAN_OPTIONS=detect_leaks=0:allocator_may_return_null=1`
工作目录: `/home/ws/Desktop/RetroScope`

---

## binutils

工具: `binutils-versions/binutils-<ver>/build-asan/binutils/<tool>`
ld 类: `binutils-versions/binutils-<ver>/build-asan-ld/ld/ld-new`

### objdump/readelf — 老版本同漏洞触发（真实内存安全崩溃）

| CVE | 同漏洞版本 | 修复版本 | 命令 | 崩溃 |
|-----|-----------|----------|------|------|
| CVE-2017-6965 | 2.24-2.27 | 2.29+ | `readelf -w in/CVE-2017-6965` | heap-buffer-overflow byte_put_little_endian |
| CVE-2017-8392 | 2.25-2.27 (2.24 异类型) | 2.29+ | `objdump -S in/CVE-2017-8392` | heap-buffer-overflow bfd_getl32 |
| CVE-2017-12448 | 2.24-2.28 | 2.30+ | `objdump -x in/CVE-2017-12448` | heap-use-after-free bfd_cache_close |
| CVE-2017-12450 | 2.24-2.28 | 2.30+ | `objdump -x in/CVE-2017-12450` | heap-buffer-overflow alpha_vms_object_p |
| CVE-2017-12451 | 2.24-2.28 | 2.30+ | `objdump -x in/CVE-2017-12451` | stack-buffer-overflow _bfd_xcoff_read_ar_hdr |
| CVE-2017-12453 | 2.24-2.28 | 2.30+ | `objdump -x in/CVE-2017-12453` | heap-buffer-overflow _bfd_vms_slurp_eeom |
| CVE-2017-12454 | 2.25-2.28 (2.24 同类型异点) | 2.30+ | `objdump -x in/CVE-2017-12454` | SEGV _bfd_vms_slurp_egsd |
| CVE-2017-12455 | 2.25-2.28 (2.24 异类型) | 2.30+ | `objdump -x in/CVE-2017-12455` | heap-buffer-overflow evax_bfd_print_emh |
| CVE-2017-12456 | 2.25-2.28 (2.24 异类型) | 2.30+ | `objdump -x -g in/CVE-2017-12456` | heap-buffer-overflow read_symbol_stabs_debugging_info |
| CVE-2017-12458 | 2.24-2.28 | 2.30+ | `objdump -x in/CVE-2017-12458` | heap-buffer-overflow nlm_swap_auxiliary_headers_in |
| CVE-2017-14130 | 2.24-2.28 | 2.30+ | `objdump -x in/CVE-2017-14130` | heap-buffer-overflow _bfd_elf_attr_strdup |
| CVE-2017-14529 | 2.25-2.28 (2.24 异类型) | 2.30+ | `objdump -x in/CVE-2017-14529` | heap-buffer-overflow bfd_getl16 |
| CVE-2017-14729 | 2.25-2.28 (2.24 异类型) | 2.30+ | `objdump -x in/CVE-2017-14729` | heap-buffer-overflow bfd_getl16 |
| CVE-2017-15225 | 2.26-2.28 (2.25 同类型异点, 2.24 异类型) | 2.30+ | `readelf -w in/CVE-2017-15225` | heap-buffer-overflow get_line_filename_and_dirname |
| CVE-2017-16832 | 2.26-2.28 (2.25 同类型异点, 2.24 异类型) | 2.30+ | `objdump -x in/CVE-2017-16832` | heap-buffer-overflow bfd_getl32 |
| CVE-2017-17080 | 2.25-2.28 (2.24 异类型) | 2.30+ | `objdump -x in/CVE-2017-17080` | heap-buffer-overflow bfd_getl32 |
| CVE-2017-17121 | 2.25-2.28 (2.24 同类型异点) | 2.30+ | `objdump -g in/CVE-2017-17121` | SEGV bfd_getl32 |
| CVE-2018-10372 | 2.26-2.30 (2.24-2.25 同类型异点) | 2.31+ | `readelf -w in/CVE-2018-10372` | heap-buffer-overflow process_cu_tu_index |
| CVE-2018-18605 | 2.26-2.29 (2.24-2.25 同类型异点) | 2.30+ | `readelf -w in/CVE-2018-18605` | heap-buffer-overflow get_line_filename_and_dirname |
| CVE-2018-18606 | 2.26-2.29 (2.25 同类型异点, 2.24 异类型) | 2.30+ | `readelf -w in/CVE-2018-18606` | heap-buffer-overflow get_line_filename_and_dirname |
| CVE-2018-18607 | 2.26-2.29 (2.24-2.25 同类型异点) | 2.30+ | `readelf -w in/CVE-2018-18607` | heap-buffer-overflow get_line_filename_and_dirname |
| CVE-2019-9075 | 2.27-2.32 (2.24-2.26 同类型异点) | 2.34+ | `objdump -x in/CVE-2019-9075` | heap-buffer-overflow _bfd_archive_64_bit_slurp_armap |
| CVE-2019-9077 | 2.24-2.31.1 | 2.34+ | `readelf -a in/CVE-2019-9077` | heap-buffer-overflow process_mips_specific |
| CVE-2021-45078 | 2.24-2.35.1 | 2.38+ | `objdump -g in/CVE-2021-45078` | heap-buffer-overflow finish_stab |
| CVE-2021-46174 | 2.25-2.35.1 (2.24 异类型) | 2.38+ | `objdump -g in/CVE-2021-46174` | heap-buffer-overflow bfd_getl32 |
| CVE-2025-0840 | 2.25-2.42 (2.24 异类型) | 2.44+ | `objdump --insn-width 64 -d in/CVE-2025-0840` | stack-buffer-overflow disassemble_bytes |

### objdump/readelf — 仅 ASan OOM（分配失败，非内存安全崩溃）

| CVE | 触发版本 | 命令 |
|-----|----------|------|
| CVE-2017-15996 | 2.24-2.28 | `readelf -w in/CVE-2017-15996` |
| CVE-2017-16826 | 2.25-2.28 (2.24 异类型) | `objdump -r in/CVE-2017-16826` |
| CVE-2017-17122 | 2.25-2.27, 2.34-2.36 (2.24 异类型) | `objdump -r in/CVE-2017-17122` |
| CVE-2018-6323 | 2.24-2.31 | `objdump -x in/CVE-2018-6323` |
| CVE-2018-1000876 | 2.29-2.32 (2.24-2.28 异类型) | `objdump -d in/CVE-2018-1000876` |
| CVE-2018-19931 | 2.24-2.31 | `objdump -x in/CVE-2018-19931` |
| CVE-2018-20002 | 2.25-2.31.1 (2.24 异类型) | `objdump -s in/CVE-2018-20002` |
| CVE-2019-9073 | 2.25-2.31.1 (2.24 异类型) | `objdump -x in/CVE-2019-9073` |
| CVE-2019-9076 | 2.25-2.32 (2.24 异类型) | `objdump -x in/CVE-2019-9076` |
| CVE-2019-17450 | 2.30-2.31.1, 2.35-2.36 | `objdump -g in/CVE-2019-17450` |
| CVE-2019-17451 | 2.30-2.31.1, 2.35-2.36 | `objdump -g in/CVE-2019-17451` |
| CVE-2020-16599 | 2.24-2.31.1 | `objdump -s in/CVE-2020-16599` |
| CVE-2022-48063 | 2.34-2.38 (2.24-2.25 异类型) | `objdump -g in/CVE-2022-48063` |
| CVE-2022-48064 | 2.25-2.31.1 (2.24 异类型) | `objdump -s in/CVE-2022-48064` |
| CVE-2023-1972 | 2.25-2.31.1 (2.24/2.40 异类型) | `objdump -x in/CVE-2023-1972` |

### objdump/readelf — 仅最老 2.24 触发（2.25-2.47 不触发）

| CVE | 触发版本 | 命令 | 崩溃 |
|-----|----------|------|------|
| CVE-2018-17360 | 仅 2.24 | `objdump -x in/CVE-2018-17360` | stack-buffer-overflow bfd_getb32 |
| CVE-2018-18309 | 仅 2.24 | `objdump -x in/CVE-2018-18309` | stack-buffer-overflow bfd_getb32 |
| CVE-2018-20671 | 仅 2.24 | `objdump -x in/CVE-2018-20671` | stack-buffer-overflow bfd_getb32 |

### objdump/readelf — 2025-2026（部分版本 / SIGABRT，无 ASAN 报告）

| CVE | 触发版本 | 命令 | 表现 |
|-----|----------|------|------|
| CVE-2025-11081 | 仅 2.45 | `objdump -S -D -x -s -Z -g -e -G -T -t -L -R --disassemble-zeroes --insn-width=32 --disassembler-color=extended in/CVE-2025-11081` | SEGV dump_dwarf_section |
| CVE-2025-11839 | 2.42-2.45 | `objdump (同上多参数) in/CVE-2025-11839` | SIGABRT |
| CVE-2025-69645 | 2.42-2.45 | `objdump --source-comment in/CVE-2025-69645` | SIGABRT |
| CVE-2025-69652 | 2.42 (ASAN) / 2.45 (SIGABRT) | `readelf -w abbrev in/CVE-2025-69652` | SEGV read_bases |

### ld 类 2025-2026（ld-new）

| CVE | 触发版本 | 命令 |
|-----|----------|------|
| CVE-2025-5244 | 2.44 | `ld --no-undefined --orphan-handling discard --gc-sections --no-print-gc-sections -w -r -d in/<poc>` |
| CVE-2025-11412 | 2.44-2.45 | `ld --gc-sections --no-print-gc-sections -w in/<poc>` |
| CVE-2025-11413 | 2.44-2.45 | `ld --gc-sections --no-print-gc-sections -w in/<poc>` |
| CVE-2025-11414 | 2.44-2.45 | `ld --gc-sections --no-print-gc-sections -w in/<poc>` |
| CVE-2025-11082 | 2.44-2.45 | `ld --gc-sections --no-print-gc-sections -w in/<poc>` |
| CVE-2025-11495 | 2.45 | `ld --gc-sections --no-print-gc-sections -w in/<poc>` |
| CVE-2025-11083 | 2.44-2.45 | `ld --version-exports-section symbol --shared in/<poc>` |
| CVE-2025-11840 | 2.44-2.45 | `ld --version-exports-section symbol --shared in/<poc>` |
| CVE-2025-11494 | 2.44-2.45 | `ld --version-exports-section symbol --shared in/<poc>` |
| CVE-2026-6846 | 2.44-2.45 | `ld -o /dev/null in/<poc>` |
| CVE-2026-15003 | 2.44-2.45 | `ld --gc-sections -o /dev/null in/<poc>` |
| CVE-2026-90801 | 2.44-2.47 | `ld --gc-sections -w in/<poc>` |
| CVE-2026-90802 | 2.44-2.47 | `ld -o /dev/null in/<poc>` |
| CVE-2026-90803 | 2.45, 2.47 | `ld -o /dev/null in/<poc>` |
| CVE-2026-90828 | 2.44-2.47 | `ld -r -o /dev/null in/<poc>` |
| CVE-2026-90829 | 2.44-2.47 | `ld -r -o /dev/null in/<poc>` |
| CVE-2026-90830 | 2.44-2.47 | `ld --shared -z now -o /dev/null in/<poc>` |
| CVE-2026-90831 | 2.45, 2.47 | `ld --version-exports-section symbol --shared -o /dev/null in/<poc>` |
| CVE-2026-91779 | 2.44-2.47 | `ld -r -o /dev/null in/<poc>` |
| CVE-2026-91780 | 2.44-2.47 | `ld -o /dev/null in/<poc>` |
| CVE-2026-91781 | 2.44-2.47 | `ld -r -o /dev/null in/<poc>` |
| CVE-2026-91782 | 2.44 | `ld -o /dev/null in/CVE-2026-91782`（不带 -r） |

---

## libxml2

工具: `libxml2-versions/libxml2-<ver>/xmllint`

| CVE | 同漏洞版本 | 不触发版本 | 命令 | 崩溃 |
|-----|-----------|-----------|------|------|
| CVE-2015-8710 | 2.9.0-2.9.2 | 2.9.4+ | `./build/h8710_2.9.1 in/CVE-2015-8710` | heap-buffer-overflow htmlCurrentChar |
| CVE-2016-3627 | 2.9.0, 2.9.2 (2.9.1 同类型异点) | 2.9.4+ | `xmllint --valid --recover in/CVE-2016-3627` | stack-overflow xmlStrndup |
| CVE-2017-9047 | 2.9.0-2.9.4 | 2.9.5+ | `xmllint --valid in/CVE-2017-9047` | stack-buffer-overflow xmlSnprintfElementContent |
| CVE-2017-9049 | 仅 2.9.4 | 其余全部 | `xmllint --memory --oldxml10 in/CVE-2017-9049` | heap-buffer-overflow xmlDictComputeFastKey |
| CVE-2017-7376 | 2.9.0-2.9.4 | 2.9.5+ | `xmllint --xinclude in/CVE-2017-7376`（需先启动 `build/redir_server.py`） | heap-buffer-overflow snprintf (nanohttp) |
| CVE-2024-56171 | 2.9.0-2.11.5 | 2.12.10+ | `xmllint --noout --schema <版本自带 test/schemas/bug322411_1.xsd> in/CVE-2024-56171` | heap-use-after-free xmlSchemaIDCFillNodeTables |
| CVE-2025-27113 | 2.9.0-2.10.4 | 2.12.10+ | `xmllint --walker --pattern '/child::info/.' in/CVE-2025-27113` | SEGV xmlPatMatch |
| CVE-2025-49794 | 2.9.14, 2.11.5, 2.13.6（全部） | — | `gcc -O1 -g -fsanitize=address -I<libxml2>/include in/CVE-2025-49794.c <libxml2>/.libs/libxml2.a -lz -lm -fsanitize=address -o /tmp/t && /tmp/t` | SEGV xmlSchematronFormatReport |
| CVE-2025-49796 | 2.9.14, 2.11.5, 2.13.6（全部） | — | 同上，`in/CVE-2025-49796.c` | SEGV xmlSchematronFormatReport |
| CVE-2024-25062 | 仅 2.11.5 | 2.12.10 | fuzz harness: `build/fuzz_main.c` + `build/schema_cve25062.c` + 版本 fuzz/fuzz.c，输入 `in/CVE-2024-25062` | heap-use-after-free xmlValidatePopElement |

---

## giflib

工具: `giflib-versions/giflib-<ver>/util/<tool>`（5.1.8+ 在版本根目录）

| CVE | 同漏洞版本 | 不触发版本 | 命令 | 崩溃 |
|-----|-----------|-----------|------|------|
| CVE-2015-7555 | 4.1.6, 5.1.1 | 5.1.2+ | `giffix in/CVE-2015-7555` | heap-buffer-overflow (WRITE) |
| CVE-2024-45993 | 4.1.6-5.2.2 | 6.1.3 | `gif2rgb -o /tmp/o in/CVE-2024-45993` | heap-buffer-overflow DumpScreen2RGB |
| CVE-2026-26740 | 5.1.1-5.2.2 | — | `giftool -d 1 < in/CVE-2026-26740` | heap-buffer-overflow EGifGCBToExtension |

---

## freetype

工具: harness 编译产物 `build/tf_<ver>` / `build/tv_<ver>`

| CVE | 同漏洞版本 | 命令 | 崩溃 |
|-----|-----------|------|------|
| CVE-2020-15999 | 2.5.5-2.9.1 (2.8.1 同类型异点) | `./build/tf_2.9.1 in/CVE-2020-15999` | heap-buffer-overflow Load_SBit_Png (png_combine_row) |

构建 harness:
```bash
gcc -g -O0 -fsanitize=address -fno-omit-frame-pointer \
  -I<freetype-dir>/include build/test_face.c \
  <freetype-dir>/build/libfreetyped.a -o build/tf_<ver> -lm
```

---

## openjpeg

工具: `openjpeg-versions/<ver>/bin/opj_decompress`

| CVE/Issue | 触发版本 | 不触发版本 | 命令 | 崩溃 |
|-----------|----------|-----------|------|------|
| issue879 | version.2.0-2.1（全部） | v2.3.0+ | `opj_decompress -i in/openjpeg/issue879/poc1.j2k -o /tmp/out.pgm`（zip 密码 `infected`） | SEGV opj_read_bytes_LE (cio.c:87) |
| issue1221 | 2.0 (j2k.c:7451) / 2.3.0-2.3.1 (color.c:201) — 两个不同漏洞 | 2.0.1-2.1, v2.4.0+ | `opj_decompress -i in/openjpeg/issue1221/poc.j2k -o /tmp/out.bmp` | 2.0: heap-buffer-overflow opj_j2k_update_image_data；2.3.x: SEGV sycc422_to_rgb |

---

## libtiff

工具: `tiff-versions/tiff-<ver>/tools/<tool>`（thumbnail 需手动构建，见主文档）

| CVE | 触发版本 | 不触发版本 | 命令 | 崩溃 |
|-----|----------|-----------|------|------|
| CVE-2025-8177 | 4.0.0-4.0.9, 4.2.0-4.5.1, 4.7.0 | 3.9.3-3.9.5, 4.0.10, 4.1.0 | `thumbnail in/libtiff/CVE-2025-8177.tif /tmp/out.tif` | global-buffer-overflow setrow (thumbnail.c:623) |

注: 长期存在 bug，绝大部分版本触发，仅个别版本因代码路径差异不触发。

---

## libarchive

无。已下载 PoC 中：CVE-2025-5915 为版本敏感（3.4.0-3.5.3 不触发，已入主表）；
issue1276 (crash_file_1)、issue759 (62.crashes) 全版本不触发。

---

## libming

工具: `libming-versions/v<ver>/util/swftophp`

| CVE | 触发版本 | 不触发版本 | 命令 | 崩溃 |
|-----|----------|-----------|------|------|
| CVE-2018-8807 | 0.4.5-0.4.8 | 无（全部） | `libming-versions/v0.4.8/util/swftophp in/libming/CVE-2018-8807.swf >/dev/null` | heap-use-after-free decompileCALLFUNCTION (decompile.c:2864) |
| CVE-2017-11733 | 0.4.5-0.4.8 | 无（全部） | `libming-versions/v0.4.8/util/swftophp in/libming/CVE-2017-11733.swf >/dev/null` | SEGV stackswap (decompile.c:629) |

注: 0.4.5-0.4.8 均触发同一函数/同一崩溃类型；0.4.8 为最后发布版。

---

## swftools

工具: `swftools-versions/v<ver>/src/<tool>`

| CVE | 触发版本 | 不触发版本 | 命令 | 崩溃 |
|-----|----------|-----------|------|------|
| CVE-2021-42195 | 0.8.1, 0.9.0, 0.9.2 | 无（全部） | `swftools-versions/v0.9.2/src/swfdump in/swftools/CVE-2021-42195.swf >/dev/null` | heap-buffer-overflow handleEditText/printf_common |
| CVE-2021-42200 | 0.8.1, 0.9.0, 0.9.2 | 无（全部） | `swftools-versions/v0.9.2/src/swfdump in/swftools/CVE-2021-42200.swf >/dev/null` | SEGV main (swfdump.c) |
| CVE-2021-42199 | 0.8.1, 0.9.0, 0.9.2 | 无（全部） | `swftools-versions/v0.9.2/src/swfstrings in/swftools/CVE-2021-42199.swf >/dev/null` | heap-buffer-overflow swf_FontExtract_DefineTextCallback (swftext.c:508) |
| CVE-2021-42203 | 0.8.1, 0.9.0, 0.9.2 | 无（全部） | `swftools-versions/v0.9.2/src/swfstrings in/swftools/CVE-2021-42203.swf >/dev/null` | heap-buffer-overflow swf_FontExtract_DefineTextCallback (swftext.c:508) |
| CVE-2021-42204 | 0.8.1, 0.9.0, 0.9.2 | 无（全部） | `swftools-versions/v0.9.2/src/swfstrings in/swftools/CVE-2021-42204.swf >/dev/null` | heap-buffer-overflow swf_GetBits (rfxswf.c:213) |
| CVE-2021-42198 | 0.8.1, 0.9.0, 0.9.2 | 无（全部） | `swftools-versions/v0.9.2/src/swfdump in/swftools/CVE-2021-42198.swf >/dev/null` | SEGV swf_GetBits (rfxswf.c:213) |

注: CVE-2021-42203 公开描述为 heap-use-after-free；本地 ASan 在 0.8.1/0.9.0/0.9.2 均先报告同函数 heap-buffer-overflow (swftext.c:508)。
CVE-2021-42201 (`swf_GetD64`) 仅在 0.8.1/0.9.0 触发，0.9.2 不触发，未计入本表。

---

## 汇总

| 项目 | 老版本同触发 CVE 数 |
|------|---------------------|
| binutils objdump/readelf（真实崩溃） | 26 |
| binutils objdump/readelf（仅 OOM） | 15 |
| binutils objdump/readelf（仅 2.24） | 3 |
| binutils objdump/readelf（2025-2026） | 4 |
| binutils ld（2025-2026） | 22 |
| libxml2 | 10 |
| giflib | 3 |
| freetype | 1 |
| openjpeg | 2 |
| libtiff | 1 |
| libarchive | 0 |
| libming | 2 |
| swftools | 6 |
