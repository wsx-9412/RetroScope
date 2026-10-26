# RetroScope PoC Run Commands — 版本敏感 CVE

筛选标准: 原始 PoC 在**发现漏洞的版本**触发，但**该版本之前的更老版本**不触发（no crash）。
全版本通用触发、或"老版本触发新版本修复"的已剔除。

环境: `ASAN_OPTIONS=detect_leaks=0:allocator_may_return_null=1`
工作目录: `/home/ws/Desktop/RetroScope`

---

## binutils (14 个)

工具路径: `binutils-versions/binutils-<ver>/build-asan/binutils/<tool>`

| CVE | 发现版本触发 | 更老版本不触发 | 命令 |
|-----|-------------|---------------|------|
| CVE-2017-8396 | 2.26 | 2.24-2.25 | `objdump -g in/CVE-2017-8396` |
| CVE-2017-12449 | 2.29 | 2.26-2.28 | `objdump -x in/CVE-2017-12449` |
| CVE-2017-12457 | 2.29 | 2.25-2.28 | `objdump -x in/CVE-2017-12457` |
| CVE-2017-12459 | 2.26 | 2.25 | `objdump -x in/CVE-2017-12459` |
| CVE-2017-17123 | 2.26 | 2.25 | `objdump -g in/CVE-2017-17123` |
| CVE-2019-9074 | 2.26 | 2.25 | `objdump -x in/CVE-2019-9074` |
| CVE-2020-16592 | 2.34 | 2.25-2.32 | `objdump -d in/CVE-2020-16592` |
| CVE-2020-35448 | 2.35 | 2.25-2.34 | `objdump -d in/CVE-2020-35448` |
| CVE-2021-20284 | 2.26 | 2.25 | `objdump -D in/CVE-2021-20284` |
| CVE-2021-20294 | 2.35 | 2.25-2.34 | `readelf --dyn-syms in/CVE-2021-20294` |
| CVE-2022-44840 | 2.38 | 2.24-2.36 | `readelf -w in/CVE-2022-44840` |
| CVE-2022-47695 | 2.28 | 2.25-2.27 | `objdump -d in/CVE-2022-47695` |
| CVE-2022-47696 | 2.34 | 2.26-2.32 | `objdump -d in/CVE-2022-47696` |
| CVE-2023-1972 | 2.40 | 2.25-2.38 | `objdump -x in/CVE-2023-1972` |

示例:
```bash
ASAN_OPTIONS=detect_leaks=0:allocator_may_return_null=1 \
  ./binutils-versions/binutils-2.26/build-asan/binutils/objdump -g in/CVE-2017-8396
```

### 变异测试结论（14 个）

判定标准: `trace_fork_offsets.py::compare_crash_signatures`，同漏洞 = ASan 崩溃类型一致 + 最内层用户帧函数一致（same_site/same_func）；仅 same_type（类型同、函数/语句不同）记为不同漏洞。

| CVE | 参考→target | 命令 | 结果 | 原因 |
|---|---|---|---|---|
| CVE-2017-8396 | 2.26→2.25 | `objdump -g` | no-match | 2.25 没有 2.26 引入的 `bfd_getl64` 越界路径（无逐行源码证明） |
| CVE-2017-12449 | 2.29→2.28 | `objdump -x` | no-match | 2.28 用 `end = PRIV(recrd.buf)+buf_size`；2.29 改成 `vms_rec+size`，同一输入不再越界 |
| CVE-2017-12457 | 2.29→2.28 | `objdump -x` | no-match | 2.29 的 `_bfd_vms_save_counted_string(ptr,maxlen)` 可返回 NULL，随后 `strcmp(NULL)`；2.28 没有这条路径 |
| CVE-2017-12459 | 2.26→2.25 | `objdump -x` | no-match | 2.26 `strsize+1` 无符号回绕（SIZE_MAX→0）导致 `bfd_bread` 溢出；2.25 分配 `strsize` 并干净失败 |
| CVE-2017-17123 | 2.26→2.25 | `objdump -g` | no-match | 2.26 才引入 `load_specific_debug_section` 的 reloc 处理；2.25 的 `dwarf.h` 没有 `reloc_info` 字段 |
| **CVE-2019-9074** | 2.26→2.25 | `objdump -x` | **可变异** | target 2.25 复现 `bfd_getl32` heap-buffer-overflow（`bfd/libbfd.c:619`），ref 2.26 是 `bfd_getl32` SEGV（`libbfd.c:548`） |
| CVE-2020-16592 | 2.34→2.32 | `objdump -d` | no-match | 2.32 没有 2.34 的 UAF 路径（无逐行源码证明） |
| CVE-2020-35448 | 2.35→2.34 | `objdump -d` | no-match | 2.34 没有 2.35 的 `bfd_getl_signed_32` 路径（无逐行源码证明） |
| CVE-2021-20284 | 2.26→2.25 | `objdump -D` | no-match | 2.25 缺少 `_bfd_elf_get_symbol_version_string` / `_bfd_elf_slurp_secondary_reloc_section` |
| CVE-2021-20294 | 2.35→2.34 | `readelf --dyn-syms` | no-match | `get_num_dynamic_syms` 只在 2.35 存在 |
| CVE-2022-44840 | 2.38→2.36 | `readelf -w` | no-match | 2.36 有 “Section is too small for 208 slots” 检查；2.38 的 `process_cu_tu_index` 用 `_mul_overflow(nslots,12,&total)` 回归 |
| CVE-2022-47695 | 2.28→2.27 | `objdump -d` | no-match | 2.27 的 `compare_symbols` 缺少 2.28 加入的 ELF `st_size` 分支 |
| CVE-2022-47696 | 2.34→2.32 | `objdump -d` | no-match | 2.32 没有 2.34 的 `bfd_get_flavour` 路径（无逐行源码证明） |
| CVE-2023-1972 | 2.40→2.38 | `objdump -x` | no-match | 2.38 仍拒绝 `hdr->sh_info==0`，并保留 `bfd_alloc/amt` 检查；2.40 改成 `bfd_zalloc` |

结论: **14 个里只有 CVE-2019-9074 能通过变异复现参考版本的同一漏洞；其余 13 个为 no-match。** 每个 no-match 都有 `out/<CVE>-<target>/NO_CRASH_MATCH.txt`；2019-9074 的匹配样本在 `out/CVE-2019-9074-2-25/`。

说明:
- 2017-8396、2020-16592、2020-35448、2022-47696 当时只有“变异 no-match + 老版本不触发”的记录，没有逐行源码证明；其余 9 个 no-match 有源码级原因。
- `poc_run_commands.md` 原表中 **CVE-2022-44840** 的 `objdump -d` 不对，实际应使用 `readelf -w`。
- 原表中 **CVE-2023-1972** 的 `objdump -d` 不对，实际应使用 `objdump -x`。
- `results/poc_samevuln/summary.md` 中 CVE-2021-20284 的版本/崩溃函数（2.35.1，`_bfd_elf_slurp_secondary_reloc_section`）与本文档的 2.26 表项不一致，二者不是同一组测试。

---

## libxml2 (2 个)

工具路径: `libxml2-versions/libxml2-<ver>/xmllint`

| CVE | 发现版本触发 | 更老版本不触发 | 命令 |
|-----|-------------|---------------|------|
| CVE-2024-34459 | 2.9.5-2.9.10 | 2.9.0-2.9.4 | `xmllint --htmlout in/CVE-2024-34459` |
| CVE-2025-49795 | 2.11.5, 2.13.6 | 2.9.14 | `build/CVE_2025_49795_<ver>` |

---

## giflib (1 个)

工具路径: `giflib-versions/giflib-<ver>/util/<tool>`

| CVE | 发现版本触发 | 更老版本不触发 | 命令 |
|-----|-------------|---------------|------|
| CVE-2022-28506 | 5.1.1-5.2.1 | 4.1.6 | `gif2rgb in/CVE-2022-28506` |

---

## freetype (3 个)

工具: 需编译 harness (build/test_face.c, build/ft_get_design_dump.c)

| CVE | 发现版本触发 | 更老版本不触发 | 命令 |
|-----|-------------|---------------|------|
| CVE-2022-27404 | 2.11.1 | 2.5.5-2.9.1 | `test_face_idx <poc> -4939615758108852224` |
| CVE-2026-23865 | 2.13.1-2.14.1 | 2.11.1-2.13.0 | `test_var <poc.ttf>` (FT_Get_MM_Var + 变体坐标) |
| CVE-2026-50811 | 2.14.0-2.14.1 | 2.11.1-2.13.3 | `ft_get_design_dump <poc> 64` |

构建 harness:
```bash
gcc -g -O0 -fsanitize=address -fno-omit-frame-pointer \
  -I<freetype-dir>/include build/test_face.c \
  <freetype-dir>/build/libfreetyped.a -o build/tf_<ver> -lm
```

---

## openjpeg (5 个)

工具路径: `openjpeg-versions/<ver>/bin/opj_decompress`（源码目录内 cmake 编译）

| CVE | 发现版本触发 | 更老版本不触发 | 命令 |
|-----|-------------|---------------|------|
| CVE-2016-9572 | 2.0.1-2.1, v2.1.1-v2.1.2 | 2.0 | `opj_decompress -i in/openjpeg/CVE-2016-9572/PoC2 -o /tmp/out.ppm` |
| issue908 | 2.0.1-2.1, v2.1.1-v2.1.2 | 2.0 | `opj_decompress -i in/openjpeg/issue908_poc.jp2 -o /tmp/out.pgm` |
| CVE-2018-18088 | 2.3.0 (仅) | 2.0-v2.2.0 | `opj_decompress -i in/openjpeg/CVE-2018-18088/291554_FlipDeter -o /tmp/out.ppm` |
| CVE-2021-3575 | 2.3.1-2.5.0 | 2.3.0 | `opj_decompress -i in/openjpeg/CVE-2021-3575.j2k -o /tmp/out.pgm` |
| issue1620 | 2.5.3-2.5.4 | 2.0-2.5.2 | `opj_decompress -i in/openjpeg/issue1620_poc.jp2 -o /tmp/out.pgm` |

崩溃位置:
- CVE-2016-9572: SEGV in color conversion
- issue908: SEGV in imagetopnm (convert.c:2167)
- CVE-2018-18088: SEGV in imagetopnm (convert.c:2243)
- CVE-2021-3575: heap-buffer-overflow in sycc420_to_rgb (color.c:379)
- issue1620: heap-buffer-overflow in opj_j2k_read_sod (j2k.c:5086)

编译命令（源码目录内）:
```bash
cd openjpeg-versions/<ver>
cmake -S . -B . -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_C_FLAGS="-g -O0 -fsanitize=address -fno-omit-frame-pointer -fno-common" \
  -DCMAKE_CXX_FLAGS="-g -O0 -fsanitize=address -fno-omit-frame-pointer -fcommon" \
  -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address" \
  -DCMAKE_SHARED_LINKER_FLAGS="-fsanitize=address" \
  -DBUILD_SHARED_LIBS=ON -DBUILD_CODEC=ON && make -j opj_decompress
```

---

## libarchive (1 个)

工具路径: `libarchive-versions/build-asan-<ver>/bin/bsdtar`

| CVE | 发现版本触发 | 更老版本不触发 | 命令 |
|-----|-------------|---------------|------|
| CVE-2025-5915 | 3.6.0-3.7.9 | 3.4.0-3.5.3 | `bsdtar -xf in/libarchive/CVE-2025-5915/official_2565.rar -C /tmp/extract` |

崩溃位置: heap-buffer-overflow in copy_from_lzss_window (archive_read_support_format_rar.c:3069)

---

## libtiff (10 个)

工具路径: `tiff-versions/tiff-<ver>/tools/<tool>`

逐版本结果见 `results/libtiff_version_matrix.tsv`。

| CVE | 发现版本触发 | 更老版本不触发 | 命令 |
|-----|-------------|---------------|------|
| CVE-2016-10268 | 4.0.7 | 4.0.6 | `tiffcp -i in/libtiff/CVE-2016-10268 /tmp/foo` |
| CVE-2016-10269 | 4.0.7 | 4.0.6 | `tiffcp -i in/libtiff/CVE-2016-10269 /tmp/foo` |
| CVE-2018-17795 | 4.0.9 | 4.0.8 | `tiff2pdf in/libtiff/CVE-2018-17795 -o /tmp/foo.pdf` |
| CVE-2020-19144 | 4.0.10 | 4.0.8 | `tiffcp -i in/libtiff/CVE-2020-19144 /tmp/foo` |
| CVE-2022-3626 | 4.4.0 | 4.0.7 | `tiffcrop -X 1 -Y 2 -R 180 -H 300 -V 300 -i in/libtiff/CVE-2022-3626 /tmp/foo` |
| CVE-2022-48281 | 4.4.0 | 4.0.7 | `tiffcrop -Z 1:3,2:4 -e divided in/libtiff/CVE-2022-48281 /dev/null` |
| CVE-2023-26966 | 4.5.0 | 4.0.7 | `tiffcp -i -B in/libtiff/CVE-2023-26966 /tmp/foo` |
| CVE-2023-30775 | 4.4.0 | 4.0.7 | `tiffcrop -i in/libtiff/CVE-2023-30775 /tmp/foo` |
| CVE-2025-8176 | 4.7.0 | 4.1.0-4.5.1 | `tiffmedian -C 256 -c lzw:2 -f in/libtiff/CVE-2025-8176.tif /tmp/out.tif` |
| CVE-2025-8177 | 4.7.0 | 4.1.0-4.5.1 | `thumbnail in/libtiff/CVE-2025-8177.tif /tmp/out.tif` |

崩溃位置:
- CVE-2016-10268: heap-buffer-overflow in `TIFFReverseBits` (`libtiff/tif_swab.c:289`)，调用链 `TIFFWriteEncodedStrip` → `cpDecodedStrips`；4.0.6 同函数在 `tif_swab.c:286`，参考 PoC rc=0 不崩溃。
- CVE-2016-10269: heap-buffer-overflow in `_TIFFmemcpy` (`libtiff/tif_unix.c:340`)，由 `TIFFWriteDirectoryTagTransferfunction` (`tif_dirwrite.c:1842`) 调用；4.0.6 含同函数，参考 PoC rc=1 报 PixarLog 不支持 1-bit，无 ASan。
- CVE-2018-17795: heap-use-after-free，`t2p_writeproc` (`tools/tiff2pdf.c:405`) → `t2p_write_pdf_stream` (`tiff2pdf.c:3989`)；4.0.8 含 `t2p_write_pdf`，参考 PoC rc=1 被 StripOffsets 校验拒绝，无 ASan。
- CVE-2020-19144: heap-buffer-overflow in `_TIFFmemcpy` (`libtiff/tif_unix.c:346`)，由 `TIFFWriteDirectoryTagColormap` (`tif_dirwrite.c:1863`) 调用；4.0.8 含同函数，rc=253 无 ASan；4.0.9 也可触发，故取 4.0.8 作更老不触发版本。
- CVE-2022-3626: heap-buffer-overflow in `_TIFFmemset` (`libtiff/tif_unix.c:340`)，由 `processCropSelections` (`tools/tiffcrop.c:7612`) 调用；4.0.7 含同函数，rc=253 无 ASan。
- CVE-2022-48281: heap-buffer-overflow in `_TIFFmemset`，由 `processCropSelections` (`tools/tiffcrop.c:7715`) 调用；4.0.7 含同函数，rc=253 无 ASan。
- CVE-2023-26966: SEGV in `uv_encode` (`libtiff/tif_luv.c:961`)，调用链 `LogLuv24fromXYZ` → `LogLuvEncode24`；4.0.7 含同函数，`tiffcp -i -B` rc=253 无 ASan。
- CVE-2023-30775: heap-buffer-overflow in `extractContigSamples32bits` (`tools/tiffcrop.c:3196`)；4.0.7 含同函数 (`tiffcrop.c:3040`)，rc=253 无 ASan。
- CVE-2025-8176: heap-use-after-free in quant_fsdither (tiffmedian.c:952)
- CVE-2025-8177: global-buffer-overflow in setrow (thumbnail.c:623), 目标 4.1.0 同函数 (thumbnail.c:541)；变异 offset 254 (`0x08 -> 0x25`) 可在 4.1.0 复现

PoC 说明:
- CVE-2016-10268 / CVE-2016-10269: 来自 Agostino Sarubbo 公开 PoC（`00066-libtiff-heapoverflow-TIFFReverseBits`、`00071-libtiff-heapoverflow-_TIFFmemcpy`），未变异收录。
- CVE-2018-17795、CVE-2020-19144、CVE-2022-3626、CVE-2022-48281、CVE-2023-26966、CVE-2023-30775: 从现有 `in/CVE-*` 语料复制为 `in/libtiff/CVE-*`，未变异；对应公开 issue 命令见上表。

注: thumbnail 需手动构建:
```bash
gcc -g -O0 -fsanitize=address -fno-omit-frame-pointer \
  -I<tiff-dir>/libtiff -I<tiff-dir>/port \
  <tiff-dir>/tools/thumbnail.c -o <tiff-dir>/tools/thumbnail \
  -L<tiff-dir>/libtiff/.libs -ltiff -L<tiff-dir>/port/.libs -lport -lm
```

---

## libredwg (8 个)

工具路径: 参考版本 `libredwg-versions/libredwg-0.13.4/programs/{dwgread,dwgbmp,dwggrep,dwg2dxf,dwg2SVG}`（ASan 构建）；CVE-2026-9500/9504 的参考版本为 `libredwg-versions/libredwg-6d6a339/programs/{dwgread,dwggrep}`（2026-04-10 快照）；发布版 0.12–0.14 及 0.14.8625 快照已全部构建：`libredwg-versions/libredwg-{0.12,0.12.1,0.12.2,0.12.3,0.12.4,0.12.5,0.13,0.13.1,0.13.2,0.13.3,0.13.4,0.14,0.14.8625}/programs/`（ASan 构建）。CVE-2022-33034 另用快照 `/home/ws/Desktop/libredwg-pilot/snap/programs/dwg2dxf`。

| CVE | 触发版本 / 范围 | 更老版本不触发 | 命令 |
|-----|----------------|---------------|------|
| CVE-2022-33034 | 0.12.5, 2022-05 快照 | 0.12–0.12.4 | `dwg2dxf -b -m -y -o /dev/null in/libredwg/CVE-2022-33034-copy_bytes_sof` |
| CVE-2026-9500 | 6d6a339 (2026-04-10) | 0.13.4, 0.12.5 | `dwgread in/libredwg/CVE-2026-9500.dwg` |
| CVE-2026-9502 | 0.13.4 | 0.13.3, 0.12.5 | `dwgread in/libredwg/CVE-2026-9502.dwg` |
| CVE-2026-9503 | 0.13–0.13.4 | 0.12.5 及更早 | `dwg2SVG in/libredwg/CVE-2026-9503.dwg` |
| CVE-2026-9504 | 6d6a339 (2026-04-10) | 0.13.3, 0.12.5（同函数） | `dwggrep '.*' in/libredwg/CVE-2026-9504.dwg` |
| CVE-2026-9605 | 0.13.4 | 0.13.3, 0.12.5 | `dwgbmp in/libredwg/CVE-2026-9605.dwg` |
| CVE-2026-15184 | 0.13–0.13.4 | 0.12.5 及更早 | `dwggrep '.*' in/libredwg/CVE-2026-15184.dwg` |
| CVE-2026-15520 | 0.13.4 | 0.13.3, 0.12.5 | `dwg2dxf --binary in/libredwg/CVE-2026-15520.dwg` |

崩溃位置: stack-buffer-overflow in `copy_bytes` (`src/decode_r2007.c:228`)，调用链 `decompress_r2007` (`decode_r2007.c:563`) → `read_file_header` → `read_r2007_meta_data`。

版本扫描（同一 PoC）:

| 版本 | 结果 |
|---|---|
| 0.12–0.12.4 | 不崩溃；已包含 `copy_bytes`/`decompress_r2007`，0.12.3/0.12.4 已确认执行到 `copy_bytes`，在 `length overflow` 检查返回 0x400 |
| 2022-05 快照 `f2dea29` | stack-buffer-overflow in `copy_bytes` |
| 0.12.5 | stack-buffer-overflow in `copy_bytes` |
| 0.13–0.14.8625 | 不崩溃（已修复） |

与 libwebp 的区别: 0.12.3/0.12.4 **已经包含** `copy_bytes` 和 `decompress_r2007`，同一 PoC 也已执行到 `copy_bytes`（日志可见 `copy_bytes (dst, 19, 1)` 等调用），只是在越界检查处返回。0.12.4→0.12.5 的关键差异不是新增函数，而是 `decompress_r2007` 的输出缓冲区长度参数：
- `read_system_page`/section 解压调用从 `size_uncomp` 改为 `size_uncomp + 1`；
- 文件头解压从 `0x110` 改为 `sizeof (r2007_file_header) + 1`。

`copy_bytes` 函数体在两个版本中完全一致；老版本因少这 1 字节会在 `dst + length > dst_end` 处拒绝，新版本多出的 1 字节让同一 LZ77 复制越过栈缓冲区。这是同一段代码的边界回归，不是“漏洞代码未引入”。

PoC 来源: `https://gitee.com/cxlzff/fuzz-poc/raw/master/libredwg/copy_bytes_sof`（LibreDWG issue #494）。

编译命令（快照/0.12.5）:
```bash
git submodule update --init --recursive   # jsmn
sh autogen.sh
./configure --disable-shared --enable-static \
  CFLAGS="-g -O0 -fsanitize=address -fno-omit-frame-pointer" \
  LDFLAGS="-fsanitize=address"
make -j
```

### 2026 系列 (CVE-2026-9500 / 9502 / 9503 / 9504 / 9605 / 15184 / 15520)

崩溃位置:
- CVE-2026-9500: SEGV（WRITE，`memcpy`）in `read_2004_compressed_section` (`src/decode.c:2181`)，调用链 `read_2004_section_summary` (`:2624`) → `decode_R2004`；工具 `dwgread`；修复 commit `8f03865`。
- CVE-2026-9502: heap-buffer-overflow in `decompress_R2004_section` (`src/decode.c:1313`)，调用链 `read_2004_compressed_section` (`:2166`) → `read_2004_section_template` (`:3230`) → `decode_R2004`；工具 `dwgread`。
- CVE-2026-9503: SEGV（NULL read at `0x30`）in `dwg_next_entity` (`src/dwg.c:1233`)，调用 `get_next_owned_entity` (`:1274`) → `output_BLOCK_HEADER`；工具 `dwg2SVG`；修复 commit `8f03865`。
- CVE-2026-9504: heap-buffer-overflow（READ）in `bit_convert_TU` (`src/bits.c:2830`)，调用 `match_LTYPE` (`programs/dwggrep.c:520`) → `match_OBJECTS`；工具 `dwggrep`；修复 commit `be996bf`。
- CVE-2026-9605: heap-buffer-overflow in `bit_read_RC` (`src/bits.c:282`)，调用链 `copy_bytes` (`src/decode.c:1149`) → `decompress_R2004_section` (`:1328`)；工具 `dwgbmp`。
- CVE-2026-15184: SEGV（NULL read at `0x30`）in `dwg_next_entity` (`src/dwg.c:1233`)，调用 `get_next_owned_entity` (`:1274`)；工具 `dwggrep`。
- CVE-2026-15520: heap-buffer-overflow in `decompress_R2004_section` (`src/decode.c:1313`)，调用链同上；工具 `dwg2dxf --binary`。

版本扫描（ASan；`-` = 无 ASan 报告）:

| 版本 | 2022-33034 | 9500 | 9502 | 9503 | 9504 | 9605 | 15184 | 15520 |
|---|---|---|---|---|---|---|---|---|
| 0.12–0.12.4 | - | - | - | - | - | - | - | - |
| 0.12.5 | 崩溃 | - | - | - | - | - | - | - |
| 0.13–0.13.3 | - | - | - | 崩溃 | - | - | 崩溃 | - |
| 0.13.4 | - | - | 崩溃 | 崩溃 | 其他崩溃* | 崩溃 | 崩溃 | 崩溃 |
| 6d6a339 | - | 崩溃 | 崩溃 | 崩溃 | 崩溃 | 崩溃 | 崩溃 | 崩溃 |
| 0.14 | - | - | - | - | - | - | - | - |
| 0.14.8625 | - | - | - | - | - | - | - | - |

0.14.8625 为 0.14 之后的开发快照。原始逐版本结果见 `results/libredwg_version_matrix.tsv`。

\* CVE-2026-9504 的样本在 0.13.4 触发的是 `decompress_R2004_section` 的 heap-buffer-overflow，不是 `bit_convert_TU`；同一样本直到 6d6a339 才在 `bit_convert_TU` 触发。因此 9504 以 6d6a339/`bit_convert_TU` 为参考，0.13.3/0.12.5 不触发该函数。

版本差异: 0.13–0.13.3 已触发 9503/15184，说明这两个洞的引入早于 0.13.4；0.13.4 触发 9502/9503/9605/15184/15520，并在 9504 的样本上触发另一处 `decompress_R2004_section` 崩溃；6d6a339 触发 9500/9504。0.12–0.12.5 均不触发 2026 系列。0.14/0.14.8625 对 9502/9503/9605/15184/15520 均不再触发，9500/9504 也不再触发。0.12.5 对 R2018 样本报 `ERROR 0x441` 拒绝解析，对 R2004/R2000 样本解析后在边界检查处返回（`ERROR: Failed to read compressed AcDbObjects section` 或 `bit_read_* buffer overflow`），不越界；9500 样本在 0.12.5 中正常解析（仅警告/`Invalid .props`）；9503 样本正常输出 SVG；9504 样本在 LTYPE 前被 `error: 0x475` 拒绝，但 0.12.5 的 `dwggrep` 对有效 DWG 仍会执行到 `bit_convert_TU`。0.13.4/6d6a339 在同一读取路径上越过边界。

PoC 来源: `https://github.com/HackC0der/CVE-Repos/tree/main/libredwg`（6d6a339 / 0b57303 的 fuzz 崩溃样本），原样收录为 `in/libredwg/CVE-2026-*.dwg`，无需变异。NVD 将 CVE-2026-9500/9502/9503/9504/9605/15184/15520 的引用指向同一仓库；其中 9605 的通用引用样本不触发，仓库内按函数命名的 `libredwg_6d6a339_heap_overflow_bit_read_RC.dwg` 才在 `bit_read_RC` 触发，故采用后者。CVE-2026-9530 与 9605 同指 issue #1248（`bit_read_RC`），属重复记录，未单列；CVE-2026-9529（`match_BLOCK_HEADER`）的公开样本不触发，issue 中的 fuzz 输入未公开，未收录。CVE-2026-15182 在 0.13.4 触发，但本轮在 0.12–0.12.4 也复现了同一 `get_bmp`/`fwrite` 越界（0.12.5 因未识别缩略图不触发），不满足“更老版本不触发”，已从主表移除；PoC 仍保留在 `in/libredwg/CVE-2026-15182.dwg`。

编译命令（0.13.4 参考版本）:
```bash
curl -L -o r.tar.gz https://codeload.github.com/LibreDWG/libredwg/tar.gz/refs/tags/0.13.4
tar xzf r.tar.gz && cd libredwg-0.13.4
# jsmn 子模块；无 .git 时 autogen.sh 会跳过子模块，需手动放入
curl -L -o /tmp/jsmn.tar.gz https://codeload.github.com/zserge/jsmn/tar.gz/refs/heads/master
tar xzf /tmp/jsmn.tar.gz -C jsmn --strip-components=1
sh autogen.sh || true    # configure 已生成；末尾 git submodule 会失败
CFLAGS="-O0 -g -fno-omit-frame-pointer -fsanitize=address -Wno-error" \
LDFLAGS="-fsanitize=address" \
./configure --enable-debug --enable-trace --disable-shared --disable-bindings --disable-docs
make -j8
```

新增稳定版（0.12–0.14.8625）使用同一源码流程，但为快速复现只构建 ASan、未加 `-finstrument-functions`：
```bash
for v in 0.12 0.12.1 0.12.2 0.12.3 0.12.4 0.13 0.13.1 0.13.2 0.13.3 0.14 0.14.8625; do
  curl -fsSL -o /tmp/$v.tar.gz https://codeload.github.com/LibreDWG/libredwg/tar.gz/refs/tags/$v
  tar xzf /tmp/$v.tar.gz -C libredwg-versions
  cd libredwg-versions/libredwg-$v
  cp -r ../libredwg-0.13.4/jsmn/. jsmn/
  sh autogen.sh || true
  CC=clang CFLAGS='-g -O0 -fsanitize=address -fno-omit-frame-pointer -Wno-error' \
    LDFLAGS='-fsanitize=address -no-pie' \
    ./configure --enable-debug --enable-trace --disable-shared --disable-bindings
  make -C src -j4
  make -C programs -j4 dwgread dwgbmp dwggrep dwg2dxf dwg2SVG
  cd ../..
done
```

6d6a339 参考版本（CVE-2026-9500/9504）编译方式相同，仅源码换成：
```bash
curl -L -o r.tar.gz https://codeload.github.com/LibreDWG/libredwg/tar.gz/6d6a33987a1a97095b069c799c3d8a793320f812
tar xzf r.tar.gz && cd libredwg-6d6a33987a1a97095b069c799c3d8a793320f812
# jsmn 处理同 0.13.4；然后 make -C src -j4 && make -C programs -j4 dwgread dwggrep dwg2SVG
```

---

## audiofile (1 个)

工具路径: `audiofile-versions/audiofile-<ver>/sfcommands/sfconvert`（ASan 构建；0.3.5/0.3.6 已重新编译 `sfconvert`）

逐版本结果见 `results/audiofile_version_matrix.tsv`。

| CVE | 发现版本触发 | 更老版本不触发 | 命令 |
|-----|-------------|---------------|------|
| CVE-2019-13147 | 0.3.5-0.3.6 | 0.3.0-0.3.4 | `./audiofile-versions/audiofile-0.3.6/sfcommands/sfconvert in/audiofile/CVE-2019-13147 /tmp/out.aiff format aiff` |

构建备注: 0.3.5/0.3.6 原树只构建了 `sfinfo`；需 `make distclean` 后以 `-g -O1 -fsanitize=address -fno-omit-frame-pointer` 重新 configure，并分别执行 `make -C libaudiofile`、`make -C sfcommands`。

### CVE-2019-13147

崩溃位置: SEGV（WRITE of size 2，空指针写）in `ulaw2linear_buf` (`libaudiofile/modules/G711.cpp:42`)，调用链 `G711::runPull` (`G711.cpp:206`) → `afReadFrames` (`data.cpp:222`) → `copyaudiodata` (`sfconvert.c:340`)。0.3.6 先报 `AddressSanitizer failed to allocate 0xffffffffc2c00000 bytes`，随后在 `ulaw2linear_buf` 写空 `linear`。

PoC 来源: `https://github.com/mpruett/audiofile/issues/54`，附件 `https://github.com/mpruett/audiofile/files/3341808/poc.zip`。压缩包内为 24 字节公开 PoC；原报告使用 `format voc`，为兼容 0.3.0 的输出格式支持，本表统一改用 `format aiff`。收录为 `in/audiofile/CVE-2019-13147`，未变异。

版本差异: 0.3.0-0.3.4 均包含同一 `ulaw2linear_buf`（`G711.cpp:42`），`format aiff` 下 rc=0，不崩溃；0.3.5/0.3.6 稳定在 `ulaw2linear_buf` 触发 SEGV。0.3.0 不支持 `format voc`，因此不采用原命令作为版本判定命令。

候选剔除: `2017-6827/6828/6829/6830/6837` 在 0.2.7 也触发；`2017-6833/6838` 的老版本缺少对应 `BlockCodec` 路径；`2018-13440` 与 `2025-50950` 指向同一 `ModuleState::setup` 空指针问题，且 0.3.6 上会在 `ModuleState::setup` SEGV 与 `RebufferModule` OOM 之间不稳定切换，未收录。

---

## libsndfile (4 个)

工具路径: `libsndfile-versions/libsndfile-<ver>/programs/{sndfile-convert,sndfile-info}`（ASan 构建；1.0.29+ 为 CMake 构建）

逐版本原始结果见 `results/libsndfile_version_matrix.tsv`。

| CVE | 发现版本触发 | 更老版本不触发 | 命令 |
|-----|-------------|---------------|------|
| CVE-2017-7741 | 1.0.26-1.0.27 | 1.0.25 | `sndfile-info in/libsndfile/CVE-2017-7741` |
| CVE-2017-12562 | 1.0.28 | 1.0.25-1.0.27 | 编译 `in/libsndfile/CVE-2017-12562.c` 后运行生成的程序 |
| CVE-2018-19661 | 1.0.26-1.0.28 | 1.0.25 | `sndfile-convert -ulaw in/libsndfile/CVE-2018-19661 /tmp/out.raw` |
| CVE-2024-50612 | 1.0.27-1.0.31, 1.2.0-1.2.2 | 1.0.25-1.0.26 | `sndfile-convert -vorbis in/libsndfile/CVE-2024-50612 /tmp/out.ogg` |

构建备注: 1.0.25-1.0.28 使用 autotools；1.0.29+ 使用 CMake（`ENABLE_EXTERNAL_LIBS=ON`，静态 FLAC/Vorbis/Opus）。CMake 构建前需删除 autotools 生成的 `src/config.h`，否则源码目录的 `HAVE_EXTERNAL_XIPH_LIBS 0` 会覆盖 CMake 生成头，导致 FLAC/Vorbis 实际未启用。

### CVE-2017-12562

崩溃位置: heap-buffer-overflow（WRITE of size 458）in `psf_binheader_writef` (`src/common.c:687`)，调用链 `wavlike_write_strings` (`wavlike.c:1095`) → `wav_write_header` (`wav.c:1062`) → `sf_writef_short`。

PoC 来源: `https://github.com/erikd/libsndfile/issues/292` 中的公开测试代码 `bug1.c`（CVE-2017-12562，原报告针对 openmpt123 写入超长 `SF_STR_COMMENT`）。代码原样收录为 `in/libsndfile/CVE-2017-12562.c`；无需变异。

版本差异: 1.0.28 引入 `psf_bump_header_allocation`，`psf_binheader_writef` 对大小写 `'s'` 只预留 16 字节而不是 `size` 字节，超长字符串元数据在 `memcpy` 时越过 512 字节堆块。1.0.25-1.0.27 的 header 缓冲扩容逻辑不同，不产生越界；但三个版本都包含 `psf_binheader_writef`。1.0.28 在 `test(SF_FORMAT_WAV, 456, 190, 0)` 处直接崩溃；1.0.29+ 不再触发。

编译命令（以参考版本为例）:
```bash
gcc -std=c99 -g -O1 -fsanitize=address -fno-omit-frame-pointer \
  -Ilibsndfile-versions/libsndfile-1.0.28/src -Ilibsndfile-versions/libsndfile-1.0.28 \
  in/libsndfile/CVE-2017-12562.c -o /tmp/bug1 \
  -Wl,--start-group libsndfile-versions/libsndfile-1.0.28/src/.libs/libsndfile.a \
  /tmp/flacdev/root/usr/lib/x86_64-linux-gnu/libFLAC.a \
  /tmp/flacdev/root/usr/lib/x86_64-linux-gnu/libvorbisenc.a \
  /tmp/flacdev/root/usr/lib/x86_64-linux-gnu/libvorbis.a \
  /tmp/flacdev/root/usr/lib/x86_64-linux-gnu/libogg.a \
  -Wl,--end-group -lm
cd /tmp && ./bug1
```

### CVE-2017-7741

崩溃位置: stack-buffer-overflow（WRITE of size 8）in `flac_buffer_copy` (`src/flac.c:282`)，调用链 `psf_calc_signal_max` (`command.c:302`) → `sf_read_double` → `flac_read_flac2d` → `flac_read_loop` → `flac_buffer_copy`。

PoC 来源: `https://github.com/asarubbo/poc/blob/master/00261-libsndfile-invalidwrite-flac_buffer_copy`（CVE-2017-7741，Gentoo/Agostino Sarubbo）。原始 PoC 直接触发，无需变异。

版本差异: 1.0.26 将 `psf_calc_signal_max` 的读缓冲从 `SF_PRIVATE` 内部的 `psf->u.dbuf` 改为局部 `BUF_UNION ubuf`，并把长度按声道数对齐（3 声道时为 1023 个 double）。该畸形 FLAC 的帧声道/剩余计数使 `flac_buffer_copy` 在 `offset+j` 处写到 1026 个 double，越过 8192 字节栈缓冲 32 字节。1.0.25 仍使用内部缓冲，该路径不会调用 `flac_buffer_copy`，ASan 无报告；1.0.28 由 commit `60b2343` 修复，不再崩溃。

注意: 1.0.26 构建时需让 `flac.pc` 指向 `/tmp/flacdev/root`（否则 configure 报 `link failed` 并编译成无 FLAC 支持）。PoC 含 3 声道、8323094 帧，仅 `sndfile-info` 的 signal-max 扫描路径触发。

### CVE-2018-19661

崩溃位置: global-buffer-overflow in `i2ulaw_array` (`src/ulaw.c:833`)，调用链 `sf_writef_int` → `ulaw_write_i2ulaw`。

PoC 来源: 公开 PoC 为 `https://github.com/erikd/libsndfile/files/2619018/poc.tar.gz`（issue #429）。`in/libsndfile/CVE-2018-19661` 已恢复为原始文件（data 区 offset 66 为 `0x60`）。原始文件在 1.0.26/1.0.28 的 GSM 解码输出中出现 `INT_MIN`，1.0.25 不会；将 offset 66 改为 `0x9F`（XOR 0xFF）可让 1.0.25 也产生 `INT_MIN` 并触发同一处越界读，但该变异仅用于确认底层代码路径，不作为版本敏感判定依据。

版本差异: 1.0.26 起 `src/GSM610/decode.c` 使用 `int16_t` 中间类型，`src/gsm610.c` 改用 `arith_shift_left`，同一 GSM 帧可解出 `-32768`，再左移 16 位得到 `INT_MIN`；1.0.25 的旧解码路径对该帧不产生 `-32768`。1.0.26/1.0.28 在 stock ASan 下直接复现；1.0.27 的 `ulaw.c` 与 1.0.26/1.0.28 相同，但 stock ASan 全局布局未报，用 `asan_pad` + `-fno-toplevel-reorder` 可复现同一 `i2ulaw_array` 越界。1.0.29+ 不再触发；相关版本的 `i2ulaw_array` 代码相同，均缺少 `INT_MIN` 处理。

ASan 布局说明: 越界下标固定为 `-8192`（`-INT_MIN >> 18`）。原始 PoC 在 1.0.26/1.0.28 的 stock ASan 布局中可报错；1.0.27 的全局布局把 `ulaw_encode - 8192` 放进可寻址邻区，需在 `src/ulaw.c` 的 `ulaw_decode` 前加入 7584 字节全局 `asan_pad`，并用 `-fno-toplevel-reorder` 编译，才能稳定复现同一越界（不改变逻辑）。对 1.0.25 使用 offset 66 变异样本时，该下标同样落在红区而报错；原始样本因不产生 `INT_MIN` 不触发。

CVE-2018-19662 是同一修复 PR 的 alaw 分支；本次 1.0.26/1.0.28 用原始 PoC 加 `-alaw` 也能复现 `i2alaw_array` 越界（1.0.25 不触发），但未纳入本轮 4 个已收录 CVE 的复核范围。

编译命令（参考版本）:
```bash
cd libsndfile-versions/libsndfile-1.0.26
sed -i 's|^prefix=/usr|prefix=/tmp/flacdev/root/usr|' /tmp/flacdev/root/usr/lib/x86_64-linux-gnu/pkgconfig/*.pc
sed -i '16s/^/#/' configure.ac    # 去掉重复的 AC_CONFIG_MACRO_DIR
autoreconf -fi
./configure --disable-shared --disable-sqlite CC=gcc \
  CFLAGS="-g -O1 -fsanitize=address -fno-omit-frame-pointer" \
  LDFLAGS="-fsanitize=address"
make -C src -j
cd programs && gcc -g -O1 -fsanitize=address -fno-omit-frame-pointer \
  -o sndfile-convert sndfile-convert.o common.o \
  -Wl,--start-group ../src/.libs/libsndfile.a \
  /tmp/flacdev/root/usr/lib/x86_64-linux-gnu/libFLAC.a \
  /tmp/flacdev/root/usr/lib/x86_64-linux-gnu/libvorbisenc.a \
  /tmp/flacdev/root/usr/lib/x86_64-linux-gnu/libvorbis.a \
  /tmp/flacdev/root/usr/lib/x86_64-linux-gnu/libogg.a \
  -Wl,--end-group -lm
```

布局辅助补丁（参考构建，仅用于 ASan 红区，不改变逻辑）:
```c
/* src/ulaw.c: 放在 static short ulaw_decode [256] 之前 */
__attribute__((used)) unsigned char asan_pad [7584] = { 1 } ;
```
编译 `ulaw.c` 时额外加 `-fno-toplevel-reorder`。

### CVE-2024-50612

崩溃位置: 1.0.27 为 SEGV in `vorbis_analysis_buffer`，调用链 `vorbis_write_d` (`src/ogg_vorbis.c:851`) → `sf_writef_double`；1.0.28-1.0.31、1.2.0-1.2.2 为 SEGV in `vorbis_analysis_wrote`，调用链 `sf_close` → `psf_close` → `vorbis_close` (`src/ogg_vorbis.c:450`) → `vorbis_analysis_wrote`。1.2.2 中 `vorbis_close` 位于 `src/ogg_vorbis.c:417`。

PoC 来源: `https://github.com/4n0nym4u5/CVE/raw/main/libsndfile/segmentation_fault/poc`（issue #1035，284 字节 RF64/WAV）。原始 PoC 直接触发，无需变异；收录为 `in/libsndfile/CVE-2024-50612`。

版本差异: 1.0.26 及更早版本已包含 `vorbis_close` 与 `vorbis_analysis_wrote`（`ogg_vorbis.c:435/450`），但其 WAV 解析器不识别该 RF64 文件，报 `No 'data' chunk marker`；1.0.27 起可解析并在写 OGG 时崩溃。1.0.27-1.0.31 与 1.2.0-1.2.2 均复现；1.1.0 的 `sf_open` 对该文件返回 `Internal error : SF_INFO struct incomplete`，未能进入写入路径。1.0.27/1.0.28 需显式 `-vorbis`，1.2.x 对 `.ogg` 输出默认选择 Vorbis。逐版本见 `results/libsndfile_version_matrix.tsv`。

---

## lame (2 个)

工具路径: `lame-versions/lame-<ver>/frontend/lame`（ASan 构建；3.98.2、3.98.4、3.99.5 已构建）

逐版本结果见 `results/lame_version_matrix.tsv`。

| CVE | 发现版本触发 | 更老版本不触发 | 命令 |
|-----|-------------|---------------|------|
| CVE-2015-9101 | 3.99.5 | 3.98.2、3.98.4 | `./lame-versions/lame-3.99.5/frontend/lame -f -V 9 in/lame/CVE-2015-9101 /dev/null` |
| CVE-2017-15045 | 3.99.5 | 3.98.4 | `./lame-versions/lame-3.99.5/frontend/lame -f -V 9 in/lame/CVE-2017-15045 /dev/null` |

### CVE-2015-9101

崩溃位置: SEGV in `fill_buffer_resample` (`libmp3lame/util.c:606`)，调用链 `lame_encode_flush` → `lame_encode_buffer_sample_t` → `fill_buffer_resample`。报告中的 `inbuf_old[BLACKSIZE + j2]` 越界读位于同一行。

PoC 来源: Debian bug #777161 附件 `test09.wav`（`https://bugs.debian.org/cgi-bin/bugreport.cgi?att=2;bug=777161;filename=test09.wav;msg=5`）。68 字节 RIFF/WAVE；SHA-256 `d489f9144810aae6774574c65cd2af0ea5258b9b2a0fafa27c74d6aaba3fbf1f`。收录为 `in/lame/CVE-2015-9101`，未变异。

版本差异: 3.99.5 在 `fill_buffer_resample` 稳定触发 ASan SEGV；3.98.2/3.98.4 对该参考 PoC 在进入重采样前返回 rc=1，报 `Only 8, 16, 24 and 32 bit input files supported`，不崩溃。两版仍包含同一 `fill_buffer_resample`（3.98.2 `util.c:625`、3.98.4 `util.c:631`、3.99.5 `util.c:606`）；Hack-Me 的按版本公开 PoC（`CVE-2015-9101_3.98.2` / `CVE-2015-9101_3.98.4`）可在同版同函数触发，说明老版本代码路径存在，但本 CVE 的参考 PoC 不触发。

### CVE-2017-15045

崩溃位置: heap-buffer-overflow in `fill_buffer_resample` (`libmp3lame/util.c:606`)，调用链 `lame_encode_flush` → `lame_encode_buffer_sample_t` → `fill_buffer` → `fill_buffer_resample`；与 CVE-2015-9101 同函数，但本 PoC 报 heap-buffer-overflow 而非 SEGV。

PoC 来源: Hack-Me `Pocs_for_Multi_Versions` 的 3.99–3.99.4 版本文件（该目录未提供原 SourceForge 参考 PoC，本文件与 `CVE-2017-15045_3.99`/`_3.99.4` 同 SHA-256）。162 字节；SHA-256 `bdaf4f301868d4718212c76819721f8fd6aa8a6c09403b4edf482d3bad738b85`。收录为 `in/lame/CVE-2017-15045`，未变异。

版本差异: 3.99.5 在 `fill_buffer_resample` 稳定触发 ASan heap-buffer-overflow；3.98.4 对该 PoC rc=1，报 `Error reading input file`，无 ASan；3.98.2 触发 glibc `*** buffer overflow detected ***` 后 abort，故采用 3.98.4 作为更老不触发版本。3.98.4 仍包含同一 `fill_buffer_resample`（`util.c:551`），代码路径存在。

---

## 汇总

| 项目 | 版本敏感 CVE 数 |
|------|-----------------|
| binutils | 14 |
| libxml2 | 2 |
| giflib | 1 |
| freetype | 3 |
| openjpeg | 5 |
| libarchive | 1 |
| libtiff | 10 |
| libredwg | 8 |
| audiofile | 1 |
| libsndfile | 4 |
| lame | 2 |
| **总计** | **52** |
