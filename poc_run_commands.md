# RetroScope PoC Run Commands — 版本敏感 CVE

筛选标准: 原始 PoC 在**发现漏洞的版本**触发，但**该版本之前的更老版本**不触发（no crash）。
全版本通用触发、或"老版本触发新版本修复"的已剔除。

环境: `ASAN_OPTIONS=detect_leaks=0:allocator_may_return_null=1`
工作目录: `/home/ws/Desktop/RetroScope`

---

## binutils (5 个)

工具路径: `binutils-versions/binutils-<ver>/build-asan/binutils/<tool>`

| CVE | 发现版本触发 | 更老版本不触发 | 命令 |
|-----|-------------|---------------|------|
| CVE-2019-9074 | 2.26 | 2.25 | `objdump -x in/CVE-2019-9074` |
| CVE-2022-44840 | 2.38 | 2.24-2.36 | `readelf -w in/CVE-2022-44840` |
| CVE-2023-1972 | 2.40 | 2.25-2.38 | `objdump -x in/CVE-2023-1972` |
| CVE-2017-9750 | 2.28 | 2.25 | `objdump -D in/CVE-2017-9750` |
| CVE-2017-14939 | 2.29 | 2.26 | `nm-new -A -a -l -S -s --special-syms --synthetic --with-symbol-versions -D in/CVE-2017-14939` |

示例:
```bash
ASAN_OPTIONS=detect_leaks=0:allocator_may_return_null=1 \
  ./binutils-versions/binutils-2.26/build-asan/binutils/objdump -x in/CVE-2019-9074
```

新增 PoC 来源:
- CVE-2017-9750: Exploit-DB 42198；global-buffer-overflow in `rx_disp` / `rx_decode_opcode`（2.26 `opcodes/rx-decode.opc:230`）；SHA-256 `6dce426f802ceae8ef3da57ffde287e32e15408cf1f044ddc3d957d2d8589b90`
- CVE-2017-14939: Exploit-DB 42970；heap-buffer-overflow in `read_1_byte`（2.29 `bfd/dwarf2.c:593`）；2.26 不触发 ASan，函数仍在 `bfd/dwarf2.c:562`；SHA-256 `4c454b52d5f8b3d3562909ec38e8d2fc5692f284afce6c4690e448784f513a30`

### 变异测试结论（保留路径存在的 3 个）

判定标准: `trace_fork_offsets.py::compare_crash_signatures`，同漏洞 = ASan 崩溃类型一致 + 最内层用户帧函数一致（same_site/same_func）；仅 same_type（类型同、函数/语句不同）记为不同漏洞。

| CVE | 参考→target | 命令 | 结果 | 原因 |
|---|---|---|---|---|
| **CVE-2019-9074** | 2.26→2.25 | `objdump -x` | **可变异** | target 2.25 复现 `bfd_getl32` heap-buffer-overflow（`bfd/libbfd.c:619`），ref 2.26 是 `bfd_getl32` SEGV（`libbfd.c:548`） |
| CVE-2022-44840 | 2.38→2.36 | `readelf -w` | no-match | 2.36 有 “Section is too small for 208 slots” 检查；2.38 的 `process_cu_tu_index` 用 `_mul_overflow(nslots,12,&total)` 回归；路径存在但条件不同 |
| CVE-2023-1972 | 2.40→2.38 | `objdump -x` | no-match | 2.38 仍拒绝 `hdr->sh_info==0`，并保留 `bfd_alloc/amt` 检查；2.40 改成 `bfd_zalloc`；路径存在但条件不同 |

结论: **保留的 3 个里只有 CVE-2019-9074 能通过变异复现参考版本的同一漏洞；2022-44840/2023-1972 为 no-match。** 原 14 个中其余 11 个因目标版本缺少崩溃路径/函数，已按“老版本路径不存在”移除。保留的 no-match 有 `out/<CVE>-<target>/NO_CRASH_MATCH.txt`；2019-9074 的匹配样本在 `out/CVE-2019-9074-2-25/`。

说明:
- 2022-44840/2023-1972 的崩溃函数/路径在 target 中存在，但检查条件不同，属“路径存在但条件不满足”，保留并归入 no-match。
- `poc_run_commands.md` 原表中 **CVE-2022-44840** 的 `objdump -d` 不对，实际应使用 `readelf -w`。
- 原表中 **CVE-2023-1972** 的 `objdump -d` 不对，实际应使用 `objdump -x`。

---

## libxml2 (1 个)

工具路径: `libxml2-versions/libxml2-<ver>/xmllint`

| CVE | 发现版本触发 | 更老版本不触发 | 命令 |
|-----|-------------|---------------|------|
| CVE-2024-34459 | 2.9.5-2.9.10 | 2.9.0-2.9.4 | `xmllint --htmlout in/CVE-2024-34459` |


---

## giflib (1 个)

工具路径: `giflib-versions/giflib-<ver>/util/<tool>`

| CVE | 发现版本触发 | 更老版本不触发 | 命令 |
|-----|-------------|---------------|------|
| CVE-2022-28506 | 5.1.1-5.2.1 | 4.1.6 | `gif2rgb in/CVE-2022-28506` |

---

## freetype (2 个)

工具: 需编译 harness (build/test_face.c, build/ft_get_design_dump.c)

| CVE | 发现版本触发 | 更老版本不触发 | 命令 |
|-----|-------------|---------------|------|
| CVE-2026-23865 | 2.13.1-2.14.1 | 2.11.1-2.13.0 | `test_var <poc.ttf>` (FT_Get_MM_Var + 变体坐标) |
| CVE-2026-50811 | 2.14.0-2.14.1 | 2.11.1-2.13.3 | `ft_get_design_dump <poc> 64` |

构建 harness:
```bash
gcc -g -O0 -fsanitize=address -fno-omit-frame-pointer \
  -I<freetype-dir>/include build/test_face.c \
  <freetype-dir>/build/libfreetyped.a -o build/tf_<ver> -lm
```

---

## openjpeg (9 个)

工具路径: `openjpeg-versions/<ver>/bin/opj_decompress`（源码目录内 cmake 编译）；编码器 PoC 使用 `openjpeg-versions/version.2.2.0/build-release-asan/bin/opj_compress`

| CVE | 发现版本触发 | 更老版本不触发 | 命令 |
|-----|-------------|---------------|------|
| CVE-2016-9572 | 2.0.1-2.1, v2.1.1-v2.1.2 | 2.0 | `opj_decompress -i in/openjpeg/CVE-2016-9572/PoC2 -o /tmp/out.ppm` |
| issue908 | 2.0.1-2.1, v2.1.1-v2.1.2 | 2.0 | `opj_decompress -i in/openjpeg/issue908_poc.jp2 -o /tmp/out.pgm` |
| CVE-2018-18088 | 2.3.0 (仅) | 2.0-v2.2.0 | `opj_decompress -i in/openjpeg/CVE-2018-18088/291554_FlipDeter -o /tmp/out.ppm` |
| CVE-2021-3575 | 2.3.1-2.5.0 | 2.3.0 | `opj_decompress -i in/openjpeg/CVE-2021-3575.j2k -o /tmp/out.pgm` |
| issue1620 | 2.5.3-2.5.4 | 2.0-2.5.2 | `opj_decompress -i in/openjpeg/issue1620_poc.jp2 -o /tmp/out.pgm` |
| CVE-2017-14151 | 2.2.0 | 2.0-2.1 | `openjpeg-versions/version.2.2.0/build-release-asan/bin/opj_compress -n 1 -i in/openjpeg/CVE-2017-14151.bmp -o /tmp/null.j2c` |
| CVE-2017-14152 | 2.2.0 | 2.1 | `openjpeg-versions/version.2.2.0/build-release-asan/bin/opj_compress -I -cinema4K -n 1 -i in/openjpeg/CVE-2017-14152.tga -o /tmp/null.jp2` |
| CVE-2017-14164 | 2.2.0 | 2.1 | `openjpeg-versions/version.2.2.0/build-release-asan/bin/opj_compress -r 20,10,1 -jpip -EPH -SOP -cinema2K 24 -n 1 -i in/openjpeg/CVE-2017-14164.tif -o /tmp/null.j2k` |
| CVE-2017-14039 | 2.1.1-2.2.0 | 2.0-2.1.0（TIFF 加载失败，未到编码器） | `openjpeg-versions/version.2.2.0/build-release-asan/bin/opj_compress -r 20,10,1 -jpip -EPH -SOP -cinema2K 24 -n 1 -i in/openjpeg/CVE-2017-14039.tif -o /tmp/null.j2k` |

崩溃位置:
- CVE-2016-9572: SEGV in color conversion
- issue908: SEGV in imagetopnm (convert.c:2167)
- CVE-2018-18088: SEGV in imagetopnm (convert.c:2243)
- CVE-2021-3575: heap-buffer-overflow in sycc420_to_rgb (color.c:379)
- issue1620: heap-buffer-overflow in opj_j2k_read_sod (j2k.c:5086)
- CVE-2017-14151: heap-buffer-overflow in `opj_mqc_byteout` (2.2.0 `mqc.c:198`)，调用链 `opj_mqc_flush` → `opj_t1_encode_cblk`；2.0/2.1 不含 `opj_tcd_code_block_enc_allocate_data`，`opj_mqc_byteout` 仍在（2.1 `mqc.c:205`）。PoC 为 asarubbo 00314（BMP），2.0/2.1 报 `unknown BMP header size 124` 后退出；SHA-256 `aad9f17144535e923450f13c1120710b1bc5ea53267e8406551a51ce67a61ae3`
- CVE-2017-14152: heap-buffer-overflow in `opj_write_bytes_LE` (2.2.0 `cio.c:67`)，调用链 `opj_j2k_write_sot`；2.1 不触发 ASan，`opj_write_bytes_LE` 仍在（2.1 `cio.c:56`）；PoC 为 asarubbo 00317（TGA）；SHA-256 `81ab278fab2bd9a227a6aac3e747af03793dd8646e9204144d939b68c7771c4c`
- CVE-2017-14164: heap-buffer-overflow in `opj_write_bytes_LE` (2.2.0 `cio.c:67`)，调用链 `opj_j2k_write_sot`（`j2k.c:4225`）；2.1 不触发 ASan，函数仍在（2.1 `cio.c:56`）；PoC 为 asarubbo 00321（TIFF）；SHA-256 `cda98689351b94b59cb27374e8a8a84c06b5be6e568cfa920323c12007567091`
- CVE-2017-14039: heap-buffer-overflow in `opj_bio_byteout`（2.2.0 `bio.c:88`），由 `opj_t2_encode_packet`（`t2.c:796`）调用，上层 `opj_t2_encode_packets` → `opj_tcd_rateallocate`；2.1 不触发 ASan，`opj_t2_encode_packet` 仍在（2.1 `t2.c:71`）；PoC 为 asarubbo 00322（TIFF）；SHA-256 `220e941bce350722fc639d4469d1ef2fa55c53f39268ebc338e6d2d60237ce97`

编译命令（源码目录内）:
```bash
cd openjpeg-versions/<ver>
cmake -S . -B . -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_C_FLAGS="-g -O0 -fsanitize=address -fno-omit-frame-pointer -fno-common" \
  -DCMAKE_CXX_FLAGS="-g -O0 -fsanitize=address -fno-omit-frame-pointer -fcommon" \
  -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address" \
  -DCMAKE_SHARED_LINKER_FLAGS="-fsanitize=address" \
  -DBUILD_SHARED_LIBS=ON -DBUILD_CODEC=ON && make -j opj_decompress opj_compress
```

编码器 PoC 需在 2.2.0 上使用 `build-release-asan`（`RelWithDebInfo`/`-DNDEBUG` + ASan + libtiff）：
```bash
cmake -S . -B build-release-asan -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DCMAKE_C_FLAGS="-g -O1 -DNDEBUG -fsanitize=address -fno-omit-frame-pointer -fno-common" \
  -DCMAKE_CXX_FLAGS="-g -O1 -DNDEBUG -fsanitize=address -fno-omit-frame-pointer -fcommon" \
  -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address" \
  -DCMAKE_SHARED_LINKER_FLAGS="-fsanitize=address" \
  -DBUILD_SHARED_LIBS=ON -DBUILD_CODEC=ON \
  -DTIFF_INCLUDE_DIR=/tmp/tiffdev/usr/include/x86_64-linux-gnu \
  -DTIFF_LIBRARY=/usr/lib/x86_64-linux-gnu/libtiff.so.5 && \
  make -C build-release-asan -j opj_compress
```
调试构建会在 `j2k.c:7193` 的 `assert(res_spec > 0)` 提前中止，无法到达这些编码器漏洞。

### CVE-2017-14039 老版本补充验证（2026-10-30）

原表把「更老版本不触发」记为 2.1；实际下载/验证后：

- **2.1.1 / 2.1.2**（uclouvain/openjpeg 官方 tag，本次下载）：`opj_bio_byteout` 存在，**原始 PoC 直接触发同一漏洞** —— `heap-buffer-overflow` in `opj_bio_byteout`（2.1.1/2.1.2 `bio.c:87`，2.2.0 `bio.c:88`），调用链 `opj_bio_flush` → `opj_t2_encode_packet`。即漏洞实际存在于 **2.1.1-2.2.0**，2.2.0 只是公开披露版本。
- **2.1.0**：有 `opj_bio_byteout`，原始 PoC 在 TIFF 读取阶段失败（`imagetotif: Bits=0, Only 8 and 16 bits implemented` → `Unable to load tiff file`），但变异可成功（见下）。
- **2.0 / 2.0.1**：有函数，但原始 PoC 在 TIFF 读取阶段即失败，未进入编码器；目标崩溃路径不存在，相关 FAIL 行已移除。
- 变异分析（参考 2.2.0，`run_analysis.sh config_openjpeg.py`）：
  - 目标 2.1.0：**SUCCESS**，1 matching（offset `0x2c←0x10`，`same_func opj_bio_byteout`，mutant `out/CVE-2017-14039.tif-2-1/0x2c:-0x10:time:7`）

结论：CVE-2017-14039 的 PoC 触发范围为 **2.1.1-2.2.0**；2.0/2.0.1 因 TIFF 加载器拒绝 `Bits=0`（路径不存在）已从结果表移除；2.1.0 路径存在，变异可成功。

---

## libarchive (1 个)

工具路径: `libarchive-versions/build-asan-<ver>/bin/bsdtar`

| CVE | 发现版本触发 | 更老版本不触发 | 命令 |
|-----|-------------|---------------|------|
| CVE-2025-5915 | 3.6.0-3.7.9 | 3.4.0-3.5.3 | `bsdtar -xf in/libarchive/CVE-2025-5915/official_2565.rar -C /tmp/extract` |

崩溃位置: heap-buffer-overflow in copy_from_lzss_window (archive_read_support_format_rar.c:3069)

---

## libtiff (9 个)

工具路径: `tiff-versions/tiff-<ver>/tools/<tool>`

| CVE | 发现版本触发 | 更老版本不触发 | 命令 |
|-----|-------------|---------------|------|
| CVE-2025-8176 | 4.7.0 | 4.1.0-4.5.1 | `tiffmedian -C 256 -c lzw:2 -f in/libtiff/CVE-2025-8176.tif /tmp/out.tif` |
| CVE-2025-8177 | 4.0.0-4.0.9、4.2.0-4.7.0（长存 bug，非单调） | 3.9.3-3.9.5、4.0.10、4.1.0 | `thumbnail in/libtiff/CVE-2025-8177.tif /tmp/out.tif` |
| CVE-2016-10268 | 4.0.7 (仅) | 3.9.3-4.0.6、4.0.8-4.1.0 | `tiffcp -i in/libtiff/CVE-2016-10268.tif /tmp/out.tif` |
| CVE-2016-10269 | 4.0.7 | 3.9.3-4.0.6 | `tiffcp -i in/libtiff/asarubbo/00071-libtiff-heapoverflow-_TIFFmemcpy /tmp/out.tif` |
| CVE-2016-10270 | 4.0.7 | 3.9.3-3.9.6 | `tiffcp -i in/libtiff/asarubbo/00074-libtiff-heapoverflow-TIFFFillStrip /tmp/out.tif` |
| CVE-2017-7597 | 4.0.7 | 3.9.3-4.0.6 | `tiffcp -i in/libtiff/asarubbo/00114-libtiff-outside-float-tif_dirread /tmp/out.tif` |
| CVE-2022-0891 | 4.0.4-4.3.0 | 3.9.6、4.0.0-4.0.3 | `tiffcrop -i -E l -H 10 -V 10 -S 8:4 -R 270 in/libtiff/CVE-2022-0891-poc.tif /tmp/out.tif` |

崩溃位置:
- CVE-2025-8176: heap-use-after-free in quant_fsdither (tiffmedian.c:952)
- CVE-2022-0891: heap-buffer-overflow in extractImageSection (tiffcrop.c:6843)，`bytebuff2 = src_buff[offset2]` 越界读；函数 extractImageSection 3.9.6 即存在，4.0.4 引入 bug，4.4.0 修复
- CVE-2025-8177: global-buffer-overflow in setrow (thumbnail.c:623)；原始 PoC 在 4.0.0-4.0.9、4.2.0-4.7.0 触发，在 3.9.3-3.9.5、4.0.10、4.1.0 不触发；目标 4.1.0 同函数 (thumbnail.c:541)，手工变异 offset 0x8 (`0x08 -> 0x25`) 的样本来自 4.0.8（本身已触发），仅能在 4.1.0/4.0.10 上作事后验证，不能算从无崩溃目标生成的变异成功。4.5.1 原始 PoC 已触发，不能作为 P0 目标。
- CVE-2016-10268: heap-buffer-overflow in `_tiffWriteProc` (4.0.7 `tif_unix.c:115`)，调用链 `TIFFAppendToStrip` → `TIFFWriteEncodedStrip` → `cpDecodedStrips`；3.9.3-4.0.6 与 4.0.8-4.1.0 均不触发 ASan，`_tiffWriteProc` 仍在 (4.0.6 `tif_unix.c:97`)
- CVE-2016-10269: heap-buffer-overflow（READ of size 512）in `_TIFFmemcpy` (4.0.7 `tif_unix.c:340`)，调用链 `TIFFReadEncodedStrip`；重建前 3.9.3-4.0.6 返回 rc=1、不触发 ASan（缺 PixarLog）；重建后 4.0.0-4.0.6 原 PoC 或变异可触发，`_TIFFmemcpy` 仍在 (3.9.6 `tif_unix.c:311`)
- CVE-2016-10270: heap-buffer-overflow（READ of size 8）in `TIFFFillStrip` (4.0.7 `tif_read.c:523`)，调用链 `TIFFSeek`；3.9.3-3.9.6 报 `MissingRequired: TileOffsets` 后干净退出，不触发 ASan，`TIFFFillStrip` 仍在 (3.9.6 `tif_read.c:230`)
- CVE-2017-7597: UBSan `tif_dirread.c:2409 value outside float`；ASan 构建下触发 `TIFFReverseBits` heap-buffer-overflow (`tif_swab.c:296`)；3.9.3-4.0.6 不触发

PoC 来源:
- CVE-2016-10268: asarubbo 00068（`https://github.com/asarubbo/poc/blob/master/00068-libtiff-heapoverflow-_tiffWriteProc`），236 字节 TIFF；SHA-256 `f9f4099082cc8d1545d5978282e470c4f0a68f8b270b0821eb18d0c2d0f2c7b2`
- CVE-2016-10269/10270、CVE-2017-7597: 均为 asarubbo 公开 PoC，原样收录为 `in/libtiff/asarubbo/`（未变异）。CVE-2016-10269 = 00071、10270 = 00074、7597 = 00114，来源见 `https://github.com/asarubbo/poc/blob/master/<编号>-libtiff-*`；SHA-256 见 `results/libtiff_version_matrix.tsv`（如 00071 = `a14c0a5c...`）

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

变异结果: 8 个全部 no-match。2026 系列 7 个已用 P0 扩展变异复测（9500 813、9502 1128、9503 628、9504 220、9605 299、15184 717、15520 650 candidates，均 matched=False；明细 `results/p0_sweep/CVE-2026-*.json`，marker `out/CVE-2026-*.dwg-*/NO_CRASH_MATCH.txt`）；CVE-2022-33034 未跑 P0，首轮 0 matching / NO_CRASH_MATCH（42s）。

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

## audiofile (2 个)

工具路径: `audiofile-versions/audiofile-<ver>/sfcommands/sfconvert`（ASan 构建；0.3.5/0.3.6 已重新编译 `sfconvert`）

逐版本结果见 `results/audiofile_version_matrix.tsv`。

| CVE | 发现版本触发 | 更老版本不触发 | 命令 |
|-----|-------------|---------------|------|
| CVE-2019-13147 | 0.3.5-0.3.6 | 0.3.0-0.3.4 | `./audiofile-versions/audiofile-0.3.6/sfcommands/sfconvert in/audiofile/CVE-2019-13147 /tmp/out.aiff format aiff` |

构建备注: 0.3.5/0.3.6 原树只构建了 `sfinfo`；需 `make distclean` 后以 `-g -O1 -fsanitize=address -fno-omit-frame-pointer` 重新 configure，并分别执行 `make -C libaudiofile`、`make -C sfcommands`。



## libsndfile (3 个)

工具路径: `libsndfile-versions/libsndfile-<ver>/programs/{sndfile-convert,sndfile-info}`（ASan 构建；1.0.29+ 为 CMake 构建）

逐版本原始结果见 `results/libsndfile_version_matrix.tsv`。

| CVE | 发现版本触发 | 更老版本不触发 | 命令 |
|-----|-------------|---------------|------|
| CVE-2017-7741 | 1.0.26-1.0.27 | 1.0.25 | `sndfile-info in/libsndfile/CVE-2017-7741` |
| CVE-2024-50612 | 1.0.27-1.0.31, 1.2.0-1.2.2 | 1.0.25-1.0.26 | `sndfile-convert -vorbis in/libsndfile/CVE-2024-50612 /tmp/out.ogg` |

构建备注: 1.0.25-1.0.28 使用 autotools；1.0.29+ 使用 CMake（`ENABLE_EXTERNAL_LIBS=ON`，静态 FLAC/Vorbis/Opus）。CMake 构建前需删除 autotools 生成的 `src/config.h`，否则源码目录的 `HAVE_EXTERNAL_XIPH_LIBS 0` 会覆盖 CMake 生成头，导致 FLAC/Vorbis 实际未启用。


### CVE-2017-7741

崩溃位置: stack-buffer-overflow（WRITE of size 8）in `flac_buffer_copy` (`src/flac.c:282`)，调用链 `psf_calc_signal_max` (`command.c:302`) → `sf_read_double` → `flac_read_flac2d` → `flac_read_loop` → `flac_buffer_copy`。

PoC 来源: `https://github.com/asarubbo/poc/blob/master/00261-libsndfile-invalidwrite-flac_buffer_copy`（CVE-2017-7741，Gentoo/Agostino Sarubbo）。原始 PoC 直接触发，无需变异。

版本差异: 1.0.26 将 `psf_calc_signal_max` 的读缓冲从 `SF_PRIVATE` 内部的 `psf->u.dbuf` 改为局部 `BUF_UNION ubuf`，并把长度按声道数对齐（3 声道时为 1023 个 double）。该畸形 FLAC 的帧声道/剩余计数使 `flac_buffer_copy` 在 `offset+j` 处写到 1026 个 double，越过 8192 字节栈缓冲 32 字节。1.0.25 仍使用内部缓冲，该路径不会调用 `flac_buffer_copy`，ASan 无报告；1.0.28 由 commit `60b2343` 修复，不再崩溃。

注意: 1.0.26 构建时需让 `flac.pc` 指向 `/tmp/flacdev/root`（否则 configure 报 `link failed` 并编译成无 FLAC 支持）。PoC 含 3 声道、8323094 帧，仅 `sndfile-info` 的 signal-max 扫描路径触发。


### CVE-2024-50612

崩溃位置: 1.0.27 为 SEGV in `vorbis_analysis_buffer`，调用链 `vorbis_write_d` (`src/ogg_vorbis.c:851`) → `sf_writef_double`；1.0.28-1.0.31、1.2.0-1.2.2 为 SEGV in `vorbis_analysis_wrote`，调用链 `sf_close` → `psf_close` → `vorbis_close` (`src/ogg_vorbis.c:450`) → `vorbis_analysis_wrote`。1.2.2 中 `vorbis_close` 位于 `src/ogg_vorbis.c:417`。

PoC 来源: `https://github.com/4n0nym4u5/CVE/raw/main/libsndfile/segmentation_fault/poc`（issue #1035，284 字节 RF64/WAV）。原始 PoC 直接触发，无需变异；收录为 `in/libsndfile/CVE-2024-50612`。

版本差异: 1.0.26 及更早版本已包含 `vorbis_close` 与 `vorbis_analysis_wrote`（`ogg_vorbis.c:435/450`），但其 WAV 解析器不识别该 RF64 文件，报 `No 'data' chunk marker`；1.0.27 起可解析并在写 OGG 时崩溃。1.0.27-1.0.31 与 1.2.0-1.2.2 均复现；1.1.0 的 `sf_open` 对该文件返回 `Internal error : SF_INFO struct incomplete`，未能进入写入路径。1.0.27/1.0.28 需显式 `-vorbis`，1.2.x 对 `.ogg` 输出默认选择 Vorbis。逐版本见 `results/libsndfile_version_matrix.tsv`。

---

## lame (2 个)

工具路径: `lame-versions/lame-<ver>/frontend/lame`（ASan 构建；3.98.2、3.98.4、3.99.5 已构建）

CVE-2015-9101 逐版本结果见 `results/lame_version_matrix.tsv`。

| CVE | 发现版本触发 | 更老版本不触发 | 命令 |
|-----|-------------|---------------|------|
| CVE-2015-9101 | 3.99.5 | 3.98.2、3.98.4 | `./lame-versions/lame-3.99.5/frontend/lame -f -V 9 in/lame/CVE-2015-9101 /dev/null` |
| CVE-2017-9872 | 3.99.5 | 3.98.2、3.98.4 | `./lame-versions/lame-3.99.5/frontend/lame --mp3input -f -V 9 in/lame/CVE-2017-9872 /dev/null` |

### CVE-2015-9101

崩溃位置: SEGV in `fill_buffer_resample` (`libmp3lame/util.c:606`)，调用链 `lame_encode_flush` → `lame_encode_buffer_sample_t` → `fill_buffer_resample`。报告中的 `inbuf_old[BLACKSIZE + j2]` 越界读位于同一行。

PoC 来源: Debian bug #777161 附件 `test09.wav`（`https://bugs.debian.org/cgi-bin/bugreport.cgi?att=2;bug=777161;filename=test09.wav;msg=5`）。68 字节 RIFF/WAVE；SHA-256 `d489f9144810aae6774574c65cd2af0ea5258b9b2a0fafa27c74d6aaba3fbf1f`。收录为 `in/lame/CVE-2015-9101`，未变异。

版本差异: 3.99.5 在 `fill_buffer_resample` 稳定触发 ASan SEGV；3.98.2/3.98.4 对该参考 PoC 在进入重采样前返回 rc=1，报 `Only 8, 16, 24 and 32 bit input files supported`，不崩溃。两版仍包含同一 `fill_buffer_resample`（3.98.2 `util.c:625`、3.98.4 `util.c:631`、3.99.5 `util.c:606`）；Hack-Me 的按版本公开 PoC（`CVE-2015-9101_3.98.2` / `CVE-2015-9101_3.98.4`）可在同版同函数触发，说明老版本代码路径存在，但本 CVE 的参考 PoC 不触发。


### CVE-2017-9872

崩溃位置: stack-buffer-overflow in `III_dequantize_sample` (`mpglib/layer3.c:912`)，调用链 `decode_layer3_frame → decodeMP3_clipchoice → decodeMP3 → decode1_headersB_clipchoice → hip_decode1_headersB → lame_decode_fromfile`。3.98.2/3.98.4 对该 PoC 返回 rc=0、不触发 ASan，且仍包含 `III_dequantize_sample`（3.98.2 `layer3.c:667`、3.98.4 `layer3.c:685`、3.99.5 `layer3.c:710`）。

PoC 来源: Exploit-DB 42259 / asarubbo 00294 (`https://gitlab.com/exploit-database/exploitdb-bin-sploits/-/raw/main/bin-sploits/42259.zip`)，11,130 字节 MP3；SHA-256 `57216dc488eaec7bff64ca01c7bcb5d39d3623387adf3b05c47113952473b6e7`。需用 `--mp3input` 让 LAME 走 mpglib 解码路径。

---

## jasper (2 个)

工具路径: 1.900.x `jasper-versions/jasper-version-<ver>/src/appl/imginfo`；2.0.x `jasper-versions/jasper-version-<ver>/build/src/appl/imginfo`（均为 ASan 构建）。逐版本结果见 `results/jasper_version_matrix.tsv`。

| CVE | 发现版本触发 | 更老版本不触发 | 命令 |
|-----|-------------|---------------|------|
| CVE-2017-5505 | 1.900.27 | 1.900.8-1.900.24 | `imginfo -f in/jasper/asarubbo/00053-jasper-invalidread-jas_matrix_asl` |
| CVE-2017-6851 | 2.0.10 | 1.900.8-1.900.24 | `imginfo -f in/jasper/asarubbo/00125-jasper-invalidread-jas_matrix_bindsub` |

### CVE-2017-5505

崩溃位置: SEGV（invalid read）in `jas_matrix_asl` (`src/libjasper/base/jas_seq.c:376`)，调用链 `jpc_dec_tiledecode` → `jpc_dec_process_sod`。NVD 描述为“JasPer 1.900.27 中 `jas_matrix_asl` 的无效内存读”。实际引入版本为 1.900.25。

版本扫描（同一 PoC）:

| 版本范围 | 结果 |
|---|---|
| 1.900.8 - 1.900.24 | 不崩溃（rc=0，`warning: forcing negative ROI shift to zero` 后 `cannot load image`） |
| 1.900.25 - 2.0.14 | SEGV in `jas_matrix_asl` |
| 2.0.15 及以后 | 不崩溃（已修复） |

PoC 来源: `https://github.com/asarubbo/poc/blob/master/00053-jasper-invalidread-jas_matrix_asl`（asarubbo 00053），3630 字节；SHA-256 `5a4a695b483fe4e68280b498d60cc1f3368baf274b197fbcfeca77093b78bd5d`。原样收录为 `in/jasper/asarubbo/00053-jasper-invalidread-jas_matrix_asl`，未变异。

### CVE-2017-6851

崩溃位置: SEGV（invalid read）in `jas_matrix_bindsub` (`src/libjasper/base/jas_seq.c:254`)，调用链 `jpc_dec_tileinit` → `jas_seq2d_bindsub`。NVD 描述为“JasPer 2.0.10 中 `jas_matrix_bindsub` 的无效读”。实际引入版本为 1.900.25。

版本扫描（同一 PoC）:

| 版本范围 | 结果 |
|---|---|
| 1.900.8 - 1.900.24 | 不崩溃 |
| 1.900.25 - 2.0.16 | SEGV in `jas_matrix_bindsub` |
| 2.0.17 及以后 | 不崩溃（已修复） |

PoC 来源: `https://github.com/asarubbo/poc/blob/master/00125-jasper-invalidread-jas_matrix_bindsub`（asarubbo 00125），725 字节；SHA-256 `98b56c05f9424fdf4e79a81f897f483169a1c8dc4ee160a1a6830a47c5e7e1ef`。原样收录为 `in/jasper/asarubbo/00125-jasper-invalidread-jas_matrix_bindsub`，未变异。


## openexr (1 个)

工具路径: `/home/ws/Desktop/openexr-versions/openexr-<ver>/build/bin/exrcheck`（ASan 构建，依赖 `/home/ws/Desktop/imath-versions` 的 Imath 与 `/home/ws/Desktop/libdeflate`）。PoC 为 EXR 文件，经 `exrcheck <poc.exr>` 执行。

| CVE | 发现版本触发 | 更老版本不触发 | 命令 |
|-----|-------------|---------------|------|
| CVE-2025-48071 | 3.3.0-3.3.2 | 3.2.12 | `./openexr-3.3.2/build/bin/exrcheck in/openexr/CVE-2025-48071-heap_overflow.exr` |

### CVE-2025-48071

崩溃位置: heap-buffer-overflow（WRITE）in `interleave` (`src/lib/OpenEXRCore/internal_zip.c:166`，`_mm_storeu_si128`)，调用链 `undo_zip_impl` → `internal_zip_reconstruct_bytes` → `interleave`。NVD 描述为“ZIP 数据解压导致的缓冲区覆写”，修复于 3.3.3（commit `916cc729e24aa16b86d82813f6e136`）。

引入原因（真回归）: 3.2.12 的 `undo_zip_impl` 用严格检查 `actual_out_bytes == uncompressed_size`（解压大小必须与声明完全一致）；3.3.0 集成 libdeflate 时放宽为 `comp_buf_size > actual_out_bytes`，漏掉“解压结果大于声明大小”的情况，导致 `interleave` 写入越界。3.3.3 补回 `actual_out_bytes > uncompressed_size` 检查。

版本扫描（同一 PoC）:

| 版本 | 结果 |
|---|---|
| 3.2.12 | 不崩溃（`file heap_overflow.exr bad`，严格检查拒绝） |
| 3.3.0 / 3.3.1 / 3.3.2 | heap-buffer-overflow in `interleave` |
| 3.3.3 | 不崩溃（已修复） |

函数存在性: `undo_zip_impl` / `internal_zip_reconstruct_bytes` / `interleave` 在 3.2.12 的 `internal_zip.c` 中均存在（第 148/234/276 行），即老版本拥有漏洞触发函数，仅因 3.3.0 的 libdeflate 集成放宽检查才引入越界写。

PoC 来源: `https://github.com/ShielderSec/poc/tree/main/CVE-2025-48071`（`heap_overflow.exr`），1,613,377 字节；SHA-256 `f87b9af36ac45f5cd4004923d3a9d82342fedcc123051f2f277a5f5440581be9`。原样收录为 `in/openexr/CVE-2025-48071-heap_overflow.exr`，未变异。

## exiv2 (1 个)

工具路径: `/home/ws/Desktop/exiv2-versions/exiv2-<ver>/build/bin/exiv2`（ASan 构建，`-DEXIV2_ENABLE_BROTLI=OFF -DEXIV2_ENABLE_XMP=OFF -DEXIV2_ENABLE_INIH=OFF`）。PoC 为 TIFF 文件，经 `exiv2 -q fi <poc.tiff>`（fixiso 写元数据动作）触发。

| CVE | 发现版本触发 | 更老版本不触发 | 命令 |
|-----|-------------|---------------|------|
| CVE-2025-26623 | 0.28.0-0.28.4 | 0.27.7（0.28.0 之前） | `exiv2 -q fi in/exiv2/CVE-2025-26623-poc.tiff` |

### CVE-2025-26623

崩溃位置: heap-use-after-free in `Exiv2::Internal::TiffComponent::accept` (`src/tiffcomposite_int.cpp:622`)，调用链 `TiffSubIfd::doAccept` (line 661) → `TiffComponent::accept`；被释放对象为 `TiffDirectory`（析构于 line 92）。NVD 描述为「写元数据时触发的堆缓冲区溢出（UAF）」，修复于 0.28.5（GHSA-38h4-fx85-qcx7，vulnerable range `>= 0.28.0, < 0.28.5`）。

引入原因（真回归）: 0.28.0 大版本重写 TIFF composite 代码时引入该 UAF。NVD 原文明确「Versions prior to v0.28.0, such as v0.27.7, are **not** affected」。

版本扫描（同一 PoC，真实 `exiv2` 二进制，ASan）:

| 版本 | 结果 |
|---|---|
| 0.27.7（0.28.0 之前） | 不触发（已实证：`Exiv2 exception in fixiso action` 干净报错，rc=1；函数 `TiffSubIfd` 已存在） |
| 0.28.4（发现范围） | heap-use-after-free in `TiffComponent::accept` |
| 0.28.5（修复后） | 不触发（`Exiv2 exception in fixiso action ... ImageWriteFailed`，rc=1） |

函数存在性: `TiffSubIfd` / `TiffComponent::accept` / `doAccept` 在 0.27.7 的 `src/tiffcomposite_int.cpp` 中均存在（`TiffSubIfd` 31 处、`doAccept` 20 处），即老版本拥有漏洞触发函数，仅因 0.28.0 重写引入 UAF。

PoC 来源: exiv2 官方回归测试 `test/data/issue_ghsa_38h4_fx85_qcx7_poc.tiff`（fix commit 630487ffc5fe）。603 字节 TIFF；SHA-256 `e300f4f4c802dbf247d435da12b1f62e9f4a266d1fcaa1e6c8b470ca058a7b8b`。原样收录为 `in/exiv2/CVE-2025-26623-poc.tiff`，未变异。

---
## pcre2 (1 个)

工具路径: `/home/ws/Desktop/pcre2-versions/pcre2-pcre2-<ver>/pcre2test`（ASan 构建）。PoC 为 pcre2test 输入文本（正则 + subject + `\=dfa` 修饰），经 `pcre2test <poc.txt>` 执行。

| CVE | 发现版本触发 | 更老版本不触发 | 命令 |
|-----|-------------|---------------|------|
| CVE-2026-86145 | 10.32-10.47 | 10.30 | `pcre2test in/pcre2/CVE-2026-86145.txt` |

### CVE-2026-86145

崩溃位置: heap-buffer-overflow（WRITE）in `internal_dfa_match`（`src/pcre2_dfa_match.c:686`）。NVD 描述为「复用递归 DFA 匹配的缓存 workspace 块时缺少大小检查导致越界写」，修复于 10.48（GHSA-3r4p-g7gg-ppmf，fix commit c932e70451ea）。

版本扫描（同一 PoC，真实 `pcre2test` 二进制，ASan）:

| 版本 | 结果 |
|---|---|
| 10.30（更老） | 不触发（`error -52: nested recursion at the same subject position`，干净拒绝） |
| 10.34 / 10.47（发现范围） | heap-buffer-overflow in `internal_dfa_match` |
| 10.48（修复后） | 不触发（`error -63: heap limit exceeded`） |

函数存在性: `pcre2_dfa_match` / `internal_dfa_match` 在 10.30 的 `src/pcre2_dfa_match.c` 中存在（3 处），即老版本拥有漏洞触发函数；10.32 的改动移除了递归位置的限制检查，才让递归 DFA 匹配进入 workspace 复用的越界写路径。

PoC 来源: pcre2 官方回归测试 `testdata/testinput6` 末尾用例（fix commit c932e70451ea 加入）。正则 `/(*LIMIT_HEAP=4)(?=(?=(?=(?=(?=(?=(?=(?=a))(?R)))))))./` + subject `a` + `\=dfa`。原样收录为 `in/pcre2/CVE-2026-86145.txt`（未变异）；SHA-256 `452da70df75463346cdb1d2417d0536cdee3367c04dfe2c1a585034cb69f094b`。

---
## 汇总

| 项目 | 版本敏感 CVE 数 |
|------|-----------------|
| binutils | 5 |
| libxml2 | 2 |
| giflib | 1 |
| freetype | 2 |
| openjpeg | 9 |
| libarchive | 1 |
| libtiff | 9 |
| libredwg | 8 |
| audiofile | 2 |
| libsndfile | 3 |
| lame | 2 |
| jasper | 2 |
| openexr | 1 |
| exiv2 | 1 |
| pcre2 | 1 |
| **总计** | **49** |

---
## 变异分析结果（run_analysis.sh 管道，2026-10-28 ~ 10-30）

判定标准与 `results/version_sweep/sweep_20261028.md` 一致:
- **SUCCESS** = 变异样本在目标版本复现参考崩溃（matching combo/value > 0）
- **FAIL** = 变异未复现（0 matching / NO_CRASH_MATCH / fork_not_reached / 超时）
- **SKIP** = 无法通过输入变异管道处理（无输入文件、harness PoC、版本树缺失等）

| 项目 | CVE | 参考版本(触发) | 目标版本(不触发) | 结果 | 说明 |
|------|-----|---------------|-----------------|------|------|
| libxml2 | CVE-2024-34459 | 2.9.5 | 2.9.4 | FAIL | 0 matching combos |
| giflib | CVE-2022-28506 | 5.1.1 | 4.1.6 | FAIL | 0 matching；target 仅同类型异点崩溃（main:gif2rgb.c:145），非 DumpScreen2RGB:305 |
| freetype | CVE-2026-23865 | 2.13.1 | 2.13.0 | FAIL | 0 matching；ref crash tt_var_get_item_delta（ttgxvar.c:1053） |
| freetype | CVE-2026-50811 | 2.14.0 | 2.13.3 | FAIL | fork_not_reached（ttgxvar.c:2161/3488） |
| openjpeg | CVE-2016-9572 | 2.0.1 | 2.0 | FAIL | NO_CRASH_MATCH（26s；ref crash imagetopnm convert.c:2075；2026-10-30 重跑） |
| openjpeg | issue908 | 2.0.1 | 2.0 | FAIL | NO_CRASH_MATCH（26s；2026-10-30 重跑） |
| openjpeg | CVE-2018-18088 | 2.3.0 | 2.2.0 | FAIL | fork_not_reached（86s；ref crash imagetopnm convert.c:2243；重跑） |
| openjpeg | CVE-2021-3575 | 2.3.1 | 2.3.0 | FAIL | 0 matching value(s)（2040 变异；ref crash sycc420_to_rgb color.c:379；59s；重跑） |
| openjpeg | issue1620 | 2.5.3 | 2.5.2 | FAIL | 0 matching value(s)（1020 变异；ref crash opj_j2k_read_sod j2k.c:5086；252s；重跑） |
| openjpeg | CVE-2017-14151 | 2.2.0 | 2.1 | FAIL | NO_CRASH_MATCH（275s；ref crash opj_mqc_byteout mqc.c:198；重跑） |
| openjpeg | CVE-2017-14152 | 2.2.0 | 2.1 | FAIL | fork_not_reached（204s；重跑） |
| openjpeg | CVE-2017-14164 | 2.2.0 | 2.1 | FAIL | fork_not_reached（201s；重跑） |
| openjpeg | CVE-2017-14039 | 2.2.0 | 2.1 | SUCCESS | 1 matching：offset 0x2c←0x10，same_func opj_bio_byteout（ref bio.c:88 vs target bio.c:87）；mutant `out/CVE-2017-14039.tif-2-1/0x2c:-0x10:time:N`（N 为首次命中耗时秒数，两次运行为 time:6 / time:7）（421s；重跑） |
| openjpeg | CVE-2017-14039 | 2.2.0 | 2.1.1 | 已验证触发 | 原始 PoC 在 2.1.1 直接触发同一 opj_bio_byteout 堆溢出（bio.c:87），无需变异（2026-10-30 下载验证） |
| openjpeg | CVE-2017-14039 | 2.2.0 | 2.1.2 | 已验证触发 | 同上（bio.c:87） |
| openjpeg | CVE-2017-14039 | 2.2.0 | 2.1.0 | SUCCESS | 1 matching：0x2c←0x10（复核；mutant time:7） |
| libarchive | CVE-2025-5915 | 3.6.0 | 3.5.3 | FAIL | No matches；ref crash copy_from_lzss_window rar.c:3069 |
| libtiff | CVE-2025-8176 | 4.7.0 | 4.5.1 | FAIL | timeout(1800s) |
| libtiff | CVE-2025-8177 | 4.7.0 | 4.5.1 | INVALID | P0 4.5.1 结果作废：原始 PoC 在 4.5.1 已触发 `setrow`（thumbnail.c:623），变异非必要；4.1.0/4.0.10 上仅能用来自 4.0.8 的 offset 0x8 样本作事后验证，不能算目标生成成功 |
| libtiff | CVE-2016-10268 | 4.0.7 | 4.0.6 | FAIL | timeout(1800s) |
| libtiff | CVE-2016-10269 | 4.0.7 | 4.0.6 | FAIL | fork_not_reached |
| libtiff | CVE-2016-10270 | 4.0.7 | 3.9.6 | FAIL | no mutation reproduced ref crash |
| libtiff | CVE-2017-7597 | 4.0.7 | 4.0.6 | FAIL | no mutation reproduced ref crash |
| libredwg | CVE-2022-33034 | 0.12.5 | 0.12.4 | FAIL | 0 matching / NO_CRASH_MATCH（42s） |
| libredwg | CVE-2026-9500 | 6d6a339 | 0.13.4 | FAIL | 0 matching / NO_CRASH_MATCH（263s） |
| libredwg | CVE-2026-9502 | 0.13.4 | 0.13.3 | FAIL | 0 matching / NO_CRASH_MATCH（235s） |
| libredwg | CVE-2026-9503 | 0.13.4 | 0.12.5 | FAIL | 0 matching / NO_CRASH_MATCH（734s） |
| libredwg | CVE-2026-9504 | 6d6a339 | 0.13.3 | FAIL | fork_not_reached（432s）；P0 220 candidates 0 matching / NO_CRASH_MATCH |
| libredwg | CVE-2026-9605 | 0.13.4 | 0.13.3 | FAIL | 0 matching / NO_CRASH_MATCH（216s） |
| libredwg | CVE-2026-15184 | 0.13.4 | 0.12.5 | FAIL | 0 matching / NO_CRASH_MATCH（396s） |
| libredwg | CVE-2026-15520 | 0.13.4 | 0.13.3 | FAIL | 0 matching / NO_CRASH_MATCH（338s） |
| audiofile | CVE-2019-13147 | 0.3.5-0.3.6 | 0.3.0-0.3.4 | SUCCESS | 
| libsndfile | CVE-2024-50612 | 1.0.27 | 1.0.26 | FAIL | 0 matching / NO_CRASH_MATCH（60s） |
| lame | CVE-2015-9101 | 3.99.5 | 3.98.4 | SUCCESS | 3043 matching；ref crash fill_buffer_resample util.c:606 |
| lame | CVE-2017-9872 | 3.99.5 | 3.98.4 | FAIL | trace 202441 事件，分析超时(>15min) |
| jasper | CVE-2017-5505 | 1.900.27 | 1.900.24 | FAIL | 0 matching / NO_CRASH_MATCH（63s） |
| jasper | CVE-2017-6851 | 2.0.10 | 1.900.24 | FAIL | 0 matching / NO_CRASH_MATCH（29s；首次 COMPILE_FAIL 修复后重跑） |
| openexr | CVE-2025-48071 | 3.3.2 | 3.2.12 | FAIL | 0 matching / NO_CRASH_MATCH（1126s，11 万+变异；fork ImfCompressor.cpp:55 代码变更型） |
| exiv2 | CVE-2025-26623 | 0.28.4 | 0.27.7 | FAIL | 0 matching / NO_CRASH_MATCH（1795s） |
| pcre2 | CVE-2026-86145 | 10.34 | 10.30 | FAIL | 0 matching / NO_CRASH_MATCH（584s） |

说明:
- openjpeg 9 个 CVE 于 2026-10-30 用修复后的 `config_openjpeg.py`（`-DPKG_CONFIG_EXECUTABLE=/bin/false` 修 `-lwebp` 链接 + `PROGRAM_NAME` 单变量切换）全部重跑，结果与 2026-10-28 首次记录一致：仅 **CVE-2017-14039** 可变异复现，mutant 在目标 2.1 触发 `opj_bio_byteout`（bio.c:87）堆溢出。明细见 `results/version_sweep/openjpeg_all_results.txt`，日志在 `results/version_sweep/openjpeg_all/`。
- binutils 5 个 CVE：CVE-2019-9074 可变异；CVE-2022-44840/2023-1972/2017-9750/2017-14939 路径存在但 no-match。原 14 个中其余 11 个因目标版本缺少崩溃路径/函数已移除，详见上文「保留路径存在的 3 个」。
- freetype 表已移除 1 个误判项（目标旧版本原始 PoC 已崩溃于同一函数，原 SUCCESS 是 same_func 误判）；freetype 计数 3→2。
- CVE-2017-14039 的 2.0/2.0.1 目标因 TIFF 加载失败（路径不存在），相关 FAIL 行已移除；CVE 保留（2.1/2.1.0 成功）。
- 2026-11-02 补跑 CVE-2017-9750（2.28→2.25）与 CVE-2017-14939（2.29→2.26）：前者 P0 987 candidates 无匹配（static 阶段手动停止于 offset 0xb4）；后者 P0 777 + 1,734,510 pairwise 无匹配（NO_CRASH_MATCH）。日志：`results/version_sweep/binutils_CVE-2017-*.out`。
- 2026-11-01 P0 复测：对表中可进入 Step 6f 的 FAIL CVE 重跑（首轮 800 candidates/120s，复核 1200 candidates/300s）；CVE-2025-8177 的 4.5.1 P0 结果作废（目标原始 PoC 已触发，见下），无有效 P0 新匹配；其余仍无匹配；`CVE-2026-23865/2017-9872` 缺 diverge 产物。明细：`results/p0_sweep/`（复核）、`results/p0_sweep_pass1/`（首轮）。
- CVE-2025-8177 的 P0 4.5.1 结果无效：原始 PoC 在 4.5.1 已触发 `setrow`（thumbnail.c:623），`ins1@0x18e` 不是从无崩溃目标得到的新复现。4.1.0/4.0.10 原始不触发，但 offset 0x8 (`0x08 -> 0x25`) 的样本来自 4.0.8（本身已触发），只能作事后验证（4.1.0 thumbnail.c:541），不能算从 4.1.0/4.0.10 目标生成的 P0 结果。
- 完整原始记录（含参考崩溃位置、失败阶段、耗时）：`results/version_sweep/sweep_20261028.md`。

---

## no-match 原因分类（按主因）

统计口径: 主表 49 个 CVE；已删除的误判项不计；`INVALID`、`SKIP/未跑` 单列。分类按**主因**归类，可多因，但同一 CVE 只计一次主因。

| 主因 | 数量 | CVE |
|---|---:|---|
| 1. 格式/解析门禁卡死（`G_early_reject`/`unknown_early` 主导，format-aware 变异仍进不去） | 4 | issue908、CVE-2016-10270、CVE-2017-7597、CVE-2017-14151 |
| 2. 过了格式门但到不了漏洞分支（`unknown`/`unknown_decode` 主导，深入 parse 但 0 fork） | 8 | CVE-2024-34459、CVE-2016-9572、CVE-2021-3575、issue1620、CVE-2017-5505、CVE-2025-26623、CVE-2025-5915、CVE-2017-6851 |
| 3. 参考→目标 offset/branch 不一致 | 9 | CVE-2026-50811、CVE-2018-18088、CVE-2017-14152、CVE-2017-14164、CVE-2016-10269、CVE-2026-9504、CVE-2025-48071、CVE-2022-44840、CVE-2023-1972 |
| 4. 多字段/状态语义（压缩、结构、语法） | 9 | CVE-2026-23865、CVE-2022-33034、CVE-2026-9500、CVE-2026-9502、CVE-2026-9503、CVE-2026-9605、CVE-2026-15184、CVE-2026-15520、CVE-2026-86145 |
| 5. 搜索预算/反馈/超时 | 5 | CVE-2025-8176、CVE-2016-10268、CVE-2017-9872、CVE-2017-9750、CVE-2017-14939 |
| 6. 匹配/验证边界 | 1 | CVE-2022-28506（target 只在 `main:gif2rgb.c:145` 同类型异点崩溃，非 `DumpScreen2RGB:305`） |
| 阻塞未测（libsndfile 版本树缺失，原列格式类但无任何 pair 数据） | 2 | CVE-2017-7741、CVE-2024-50612 |
| 成功 | 5 | CVE-2019-9074、CVE-2017-14039、CVE-2015-9101、CVE-2019-13147  CVE-2022-0891|
| INVALID | 1 | CVE-2025-8177（目标 4.5.1 原始 PoC 已触发） |
| **合计** | **44** | |

备注:
- **原「1. 格式/解析约束（14 个）」已废除**。format-aware+coordinated 深挖（`results/cat1_fmt_retest/`，60 NO_MATCH pair / 26,834 候选 / **0 MATCH**）证明该类不是单一机制，须拆为两类：
  - **类1 门禁卡死（4）**：`G_early_reject`/`unknown_early` ≥50%。908/10270/7597 深挖后 early 仍 ~99%——format profile 过不了真门禁（门禁比静态格式更细：版本相关校验/状态）；14151 为 allver 死亡模式推断（early 50%，无 BMP profile 未深挖）。
  - **类2 过门不到 fork（8）**：`G_early≈0`、`unknown`/`unknown_decode` ≥50%、深入 decode 但 0 fork（仅 1620 有 8 条 near_miss/fork_yes）。格式已不是约束；卡在到不了漏洞分支/状态，与原类3（多字段/状态）同源。5915/6851 为 allver 死亡模式推断（deep 89%/100%，未做 fmt 深挖）。
  - 证据分级：908/10270/7597/34459/9572/3575/1620/5505/26623 = 深挖证实；14151/5915/6851 = allver death_mode 推断；7741/50612 = 阻塞无数据。
- 类3 是 `fork_not_reached`、目标检查条件或代码变更；类4 虽然进入了目标路径，但单字节/通用变异无法组合出所需状态。
- 分类是“主因”：例如 libredwg 也受搜索预算限制，`fork_not_reached` 也受 trace/offset 限制；CVE-2022-28506 不是完全没崩，而是崩在非目标点，被匹配规则拒绝。
- 真正成功复现的只有 3 个 CVE；要提升 no-match 转化率：类1 需结构保持型/版本感知门禁穿越算子，类2 需状态引导+动态算子（smoke 证实 9572 的 fork 命中来自 havoc 而非纯 fmt/coord），类3 需更准 fork-offset 映射。
- 已删除 1 个 freetype 误判项，不在上表；它不是 no-match，而是目标原始 PoC 已崩溃的 `same_func` 误判。

---

## 18 CVE 变异复测根因总结（A/B/C/D 四类，2026-11-08）

> 本节是上表「no-match 原因分类」中第 3 类（offset/branch，9 个）与第 4 类（多字段/状态，9 个）共 **18 个 CVE** 的证据级深挖。18 个全部经过 `run_extended_mutation_stage` 归因复测，逐候选数据在 `results/cat23_retest/`（基线）、`results/cat23_retest_forkfix2/`（fork 修正后）各 CVE 的 `attribution_summary`。

### 0. 硬数据

| 指标 | 值 |
|---|---|
| 累计变异候选 | **16,784**（类2 6,962 + 类3 9,822） |
| 同 match（same_func） | **0** |
| 产生 ASan 崩溃 | **226**（全部 CVE-2022-33034，全部 `crash_relation=elsewhere`） |
| 在 ref 路径/fork 站点崩溃 | **0**（`pastF_wrong_crash` / `pastF_onpath_nomatch` 全为 0） |
| 探针证实到达 fork 但不崩 | 50811 / 23865 / 15184 / 9503 各 3 条 `pastF_no_crash`；14152 / 1972 / 9500 各 3 条 `pastF_other` |

fork 修复（原①归因）已证明对 match 无效 → no-match 根因不在 fork 选择，而在下面四类。

### A 类：编译期边界差异 → 溢出数学上不可能【已证明，1 个】

**机制**：ref 崩溃依赖新版本特有的编译期常量/参数；目标版本同位置守卫更严，任何输入都过不了守卫。

**CVE-2022-33034**（libredwg 0.12.5 ← 0.12.4，`src/decode_r2007.c`）：
- ref `read_file_header:1247` 传 `dst_size = sizeof(r2007_file_header)+1 = 273`；栈对象 `file_header` 仅 272 字节（ASan `[48,320)`）→ 守卫 `dst+length > dst_end` 放行越界 1 字节 → `copy_bytes:228` 写穿；
- 目标 `read_file_header:1217` 传 `0x110 = 272` = 对象大小 → `dst_end` 恰等于对象末尾 → 守卫**必然**在 `copy_bytes` 之前拒绝；
- GDB 实测目标版：`copy_bytes` 调用 9 次全部有界，第 10 次被 `decode_r2007.c:539` 拦下（`ERROR: Decompression error: length overflow`）；
- 两版 `copy_bytes` 函数体与守卫逐字相同（定义 `:223`、守卫 `:539/:544`）；另两个 `decompress_r2007` 调用点均为堆缓冲（system page 余量 ≥255 字节；data page 理论可溢出但 `heap-buffer-overflow ≠ stack-buffer-overflow`，`_crash_types_compatible()` 返回 False）。

**结论**：MATCH 需要改代码（`dst_size` 由 `0x110` 改 `sizeof+1`），输入变异无解。

### B 类：结构门禁 → 解析被拒，到不了漏洞点【11 个】

**机制**：变异破坏魔数/目录/编码结构 → 格式校验直接拒绝（`G_early_reject` / `parse_error` / `reported_error`）。libredwg R2007 的 RS 编码还会纠正/拒收随机字节，进一步压缩可达空间。

| 子类 | 证据（stage） | CVE 与数据 |
|---|---|---|
| B1 目录级拒绝 | directory / header | 10269（1164/1200 directory）、14164（1119/1200）、44840（158 header） |
| B2 解码级解析失败 | decode | 9502（1200/1200）、15520（1200/1200）、33034（861，偏移 0/1 打烂 `AC1021` 魔数）、18088（772/1134）、9500（614）、14152（436/436 全 parse_error） |
| B3 报错无阶段 | unknown | 9504（1010/1010）、9605（586 parse_error + 533 reported_error）、86145（517/666 reported_error，pcre2test 拒 pattern） |

### C 类：状态门 → 跑得完但漏洞分支状态产生不了【6 个】

**机制**：漏洞需要多字段/多长度/标志位的特定组合同时成立；14 类算子以单字节/单字段/局部邻域为主，产生不了该组合；破坏组合的变异又先被 B 类门禁拦掉。

| 证据形态 | CVE | 数据 |
|---|---|---|
| clean 占多数（走完不崩） | 9503 | 826/1128 clean（73%） |
| | 15184 | 648/1200 clean |
| | 23865 | 540/1022 clean |
| | 50811 | 535/1022 clean，探针 3 条 `pastF_no_crash`（到 fork 不崩） |
| other（异常退出不崩） | 1972 | 352/393 other，3 条 `pastF_other` |
| | 48071 | 236/236 other，0 崩溃 |

### D 类：打偏 → 触发目标上的另一个 bug【33034 的 226 条】

- 全部崩在 `SEGV dxfb_header_write @ header_variables_dxf.spec:26`（`_obj->HANDSEED->handleref.value` 空指针解引用）；
- 16 种 distinct behavior；主算子 `gram-ins-dwg@0x6+41433130`（79 次）、`ins@0x6` / `ins@0x3e`——插入保住版本魔数但整体移位文件布局；
- `SEGV` 经 `_SEGV_ASAN_FAMILY` 桥接到 ref 的 `stack-buffer-overflow` → `same_type`，但函数不同且 33034 无 CVE 专属等价配置 → 永远升不到 `same_func`。

### 归类总表（11 B + 6 C + 1 A = 18）

| 类 | CVE | 主导死法 |
|---|---|---|
| A | 33034 | 守卫拦截（GDB 证明） |
| B1 | 10269 / 14164 / 44840 | directory / header 拒绝 |
| B2 | 9502 / 15520 / 18088 / 9500 / 14152 / 33034(861) | decode parse_error |
| B3 | 9504 / 9605 / 86145 | reported_error / parse_error（stage unknown） |
| C | 9503 / 15184 / 23865 / 50811 / 1972 / 48071 | clean / other 不崩 |
| D | 33034（226 条） | SEGV @ dxfb_header_write:26 |

### 备注

- 与上文分类的关系：本节只覆盖第 3、4 类共 18 个 CVE；原「格式/解析约束」已拆为上表类1（门禁卡死）与类2（过门不到 fork）——类1 与本节 B 类机制同源（结构门禁拒绝），类2 与本节 C 类同源（状态门，到不了漏洞分支），证据见 `results/cat1_fmt_retest/`（0/60 MATCH）。
- 证据分级：**A = 代码级 + GDB 证明**；**B/C = 16,784 条候选的经验否定**（`unknown_*` 含探针采样局限，每 CVE 仅采 3–12 条，但「0 条 on-path 崩溃」是硬事实）；**D = 已精确复现**。
- 可救性：D 不用救；B 需结构保持型算子（只改字段值、不改长度/不碰目录），受 RS 编码与校验和限制；C 需跨字段状态引导变异（如 R2004 section 尺寸三元组联动），成本高；A 无解。
- 产物：逐候选数据 `results/cat23_retest*/CVE-*.json` 的 `attribution_summary`；33034 全量 1088 条记录 `results/nearmiss_33034/records_1088_20261108.json`；复测/核验脚本 `retest_cat23.py`、`validate_fork_cat2.py`、`run_33034_records.py`（会话脚本，位于 `/tmp/opencode`，未入库）。

## 38 no-match CVE 全版本变异复测（任务2，2026-11-09）

- 脚本：`/tmp/opencode/retest_allver.py`（SPECS 内固化 38 CVE 的 ref/input/args/fork 参数）
- 口径：ref = 原 PoC 崩溃版本；target = 所有**严格早于** ref 的已下载版本；每 pair 先跑原 PoC baseline，再跑 extended-mutation stage（`max_candidates=1200, budget=300s`）。
- 判定：`MATCH` = 变异体与 ref same_func/same_site；`BASELINE_TRIGGERS` = 原 PoC 在 target 上已 same_func/same_site（跳过变异）；`NO_MATCH` = 预算内未命中。
- 结果文件：`results/allver_mut/{cve}__{ver}.json`；汇总 `_summary_cat1.json`、`_summary_cat2-3-4-5.json`。

### 总览

| 状态 | 数量 |
|---|---|
| MATCH | 6 |
| BASELINE_TRIGGERS | 43 |
| NO_MATCH | 216 |
| **合计** | **265** |

> 第二轮（帧过滤 + PixarLog 重建 + 单字节算子）后：10269 从 N=12 → M=2 B=6 N=4；10270 从 M=3 B=4 → M=4 B=3。详见文末「CVE-2016-10269 新旧结果矛盾：根因与修复」。

阻塞/缺失（不计入 265）：

| CVE | 版本 | 原因 |
|---|---|---|
| CVE-2017-7741 | 全部 | libsndfile 版本树缺失（BLOCKED） |
| CVE-2024-50612 | 全部 | libsndfile 版本树缺失（BLOCKED） |
| CVE-2025-8176 | 4.6.0 | 树内无 tiffmedian 源码（MISSING_BIN），其余 22 个版本已跑 |

### 逐 CVE × 版本结果

#### cat1 CVE-2024-34459 — ref=`2.9.5` — n=4 · M=0 · B=0 · N=4

| 版本 | 状态 | tested | death_mode（主导） | elapsed |
|---|---|---|---|---|
| 2.9.0 | · | 988 | unknown:883, G_early_reject:83, near_miss_same_type:22 | 7.6s |
| 2.9.1 | · | 989 | unknown:881, G_early_reject:83, near_miss_same_type:22 | 7.5s |
| 2.9.2 | · | 988 | unknown:880, G_early_reject:83, near_miss_same_type:22 | 23.7s |
| 2.9.4 | · | 988 | unknown:897, G_early_reject:88, pastF_other:3 | 22.4s |

#### cat1 CVE-2016-9572 — ref=`2.0.1` — n=1 · M=0 · B=0 · N=1

| 版本 | 状态 | tested | death_mode（主导） | elapsed |
|---|---|---|---|---|
| 2.0 | · | 1126 | unknown_decode:642, unknown:422, pastF_onpath_nomatch:56 | 60.2s |

#### cat1 issue908 — ref=`2.0.1` — n=1 · M=0 · B=0 · N=1

| 版本 | 状态 | tested | death_mode（主导） | elapsed |
|---|---|---|---|---|
| 2.0 | · | 1155 | G_early_reject:1005, unknown:88, unknown_decode:53 | 73.6s |

#### cat1 CVE-2021-3575 — ref=`2.3.1` — n=7 · M=0 · B=0 · N=7

| 版本 | 状态 | tested | death_mode（主导） | elapsed |
|---|---|---|---|---|
| 2.0 | · | 990 | unknown_decode:632, unknown:335, pastF_onpath_nomatch:16 | 42.8s |
| 2.0.1 | · | 1152 | unknown_decode:555, unknown:375, unknown_clean:211 | 144.9s |
| 2.1 | · | 1150 | unknown_decode:552, unknown:375, unknown_clean:212 | 138.7s |
| 2.1.1 | · | 1147 | unknown_decode:767, unknown:374, G_parse_error:3 | 44.4s |
| 2.1.2 | · | 1150 | unknown_decode:770, unknown:374, G_parse_error:3 | 46.1s |
| 2.2.0 | · | 1150 | unknown_decode:770, unknown:374, G_parse_error:3 | 16.4s |
| 2.3.0 | · | 1146 | unknown_decode:766, unknown:374, G_parse_error:3 | 20.0s |

#### cat1 issue1620 — ref=`2.5.3` — n=12 · M=0 · B=0 · N=12

| 版本 | 状态 | tested | death_mode（主导） | elapsed |
|---|---|---|---|---|
| 2.0 | · | 1200 | unknown_decode:683, unknown:329, unknown_clean:106 | 204.8s |
| 2.0.1 | · | 1200 | unknown_decode:777, unknown:307, unknown_clean:106 | 125.2s |
| 2.1 | · | 1200 | unknown_decode:786, unknown:298, unknown_clean:107 | 64.4s |
| 2.1.1 | · | 1200 | unknown_decode:786, unknown:298, unknown_clean:107 | 102.3s |
| 2.1.2 | · | 1200 | unknown_decode:785, unknown:298, unknown_clean:107 | 104.3s |
| 2.2.0 | · | 1200 | unknown_decode:757, unknown:327, unknown_clean:104 | 51.8s |
| 2.3.0 | · | 1200 | unknown_decode:760, unknown:324, unknown_clean:104 | 68.5s |
| 2.3.1 | · | 1200 | unknown_decode:760, unknown:324, unknown_clean:104 | 84.2s |
| 2.4.0 | · | 1200 | unknown_decode:760, unknown:324, unknown_clean:104 | 70.1s |
| 2.5.0 | · | 1200 | unknown_decode:760, unknown:324, unknown_clean:104 | 77.8s |
| 2.5.1 | · | 1200 | unknown_decode:760, unknown:324, unknown_clean:104 | 76.9s |
| 2.5.2 | · | 1200 | unknown_decode:760, unknown:324, unknown_clean:104 | 61.8s |

#### cat1 CVE-2017-14151 — ref=`2.2.0` — n=5 · M=0 · B=2 · N=3

| 版本 | 状态 | tested | death_mode（主导） | elapsed |
|---|---|---|---|---|
| 2.0 | · | 315 | G_early_reject:156, unknown:156, G_parse_error:3 | 19.9s |
| 2.0.1 | · | 315 | G_early_reject:156, unknown:156, G_parse_error:3 | 13.4s |
| 2.1 | · | 315 | G_early_reject:156, unknown:156, pastF_other:3 | 2.8s |
| 2.1.1 | 🔁 BASE | 0 | baseline same_func | 0.1s |
| 2.1.2 | 🔁 BASE | 0 | baseline same_func | 0.1s |

#### cat1 CVE-2025-5915 — ref=`3.6.0` — n=4 · M=0 · B=0 · N=4

| 版本 | 状态 | tested | death_mode（主导） | elapsed |
|---|---|---|---|---|
| 3.4.0 | · | 899 | unknown:802, G_early_reject:93, G_parse_error:4 | 23.7s |
| 3.4.3 | · | 899 | unknown:802, G_early_reject:93, G_parse_error:4 | 23.8s |
| 3.5.0 | · | 899 | unknown:802, G_early_reject:93, G_parse_error:4 | 20.1s |
| 3.5.3 | · | 400 | unknown:345, G_early_reject:52, G_parse_error:3 | 20.5s |

#### cat1 CVE-2016-10270 — ref=`4.0.7` — n=12 · M=4 · B=3 · N=5

| 版本 | 状态 | tested | death_mode（主导） | elapsed |
|---|---|---|---|---|
| 3.9.3 | · | 1200 | G_early_reject:1184, unknown:15, unknown_early:1 | 81.5s |
| 3.9.4 | · | 1200 | G_early_reject:1168, unknown:30, unknown_early:2 | 70.2s |
| 3.9.5 | · | 1200 | G_early_reject:1193, unknown:3, unknown_early:2, unknown_decode:2 | 7.4s |
| 3.9.6 | · | 1200 | G_early_reject:1193, unknown:3, unknown_early:2, unknown_decode:2 | 7.4s |
| 4.0.0 | 🔁 BASE (same_func) | 0 | baseline same_func | 0.3s |
| 4.0.1 | ✅ MATCH | 167 | G_early_reject:137, unknown_early:29, matched:1 | 16.6s |
| 4.0.2 | ✅ MATCH | 167 | G_early_reject:139, unknown_early:27, matched:1 | 16.6s |
| 4.0.3 | · | 768 | G_early_reject:759, near_miss_same_type:7, unknown:2 | 305.7s |
| 4.0.4 | ✅ MATCH | 167 | G_early_reject:134, unknown_early:32, matched:1 | 15.5s |
| 4.0.4beta | 🔁 BASE (same_func) | 0 | baseline same_func | 0.4s |
| 4.0.5 | 🔁 BASE (same_func) | 0 | baseline same_func | 0.3s |
| 4.0.6 | ✅ MATCH | 167 | G_early_reject:141, unknown_early:25, matched:1 | 5.9s |

MATCH 明细：4.0.1/4.0.2 `mb2@0xac=0x4`；4.0.4/4.0.6 `mb2@0xac=0x1` → `TIFFFillStrip` same_func。

#### cat1 CVE-2017-7597 — ref=`4.0.7` — n=12 · M=0 · B=0 · N=12

| 版本 | 状态 | tested | death_mode（主导） | elapsed |
|---|---|---|---|---|
| 3.9.3 | · | 1200 | G_early_reject:420, near_miss_same_type:323, unknown_early:311 | 156.9s |
| 3.9.4 | · | 1200 | G_early_reject:419, near_miss_same_type:319, unknown_early:314 | 146.7s |
| 3.9.5 | · | 1179 | G_early_reject:744, unknown_early:385, unknown:40 | 108.8s |
| 3.9.6 | · | 1179 | G_early_reject:749, unknown_early:384, unknown:36 | 94.2s |
| 4.0.0 | · | 1200 | G_early_reject:703, unknown_early:468, unknown:25 | 45.1s |
| 4.0.1 | · | 1200 | G_early_reject:703, unknown_early:468, unknown:25 | 54.4s |
| 4.0.2 | · | 1200 | G_early_reject:682, unknown_early:494, unknown:20 | 64.0s |
| 4.0.3 | · | 1200 | G_early_reject:703, unknown_early:468, unknown:25 | 56.5s |
| 4.0.4 | · | 1200 | G_early_reject:798, unknown_early:320, unknown:77 | 69.6s |
| 4.0.4beta | · | 1200 | G_early_reject:798, unknown_early:319, unknown:77 | 93.0s |
| 4.0.5 | · | 1200 | G_early_reject:798, unknown_early:319, unknown:77 | 102.9s |
| 4.0.6 | · | 1200 | G_early_reject:798, unknown_early:320, unknown:77 | 86.1s |

#### cat1 CVE-2017-7741 — ref=`1.0.26` — 0 runnable（BLOCKED）

#### cat1 CVE-2024-50612 — ref=`1.0.27` — 0 runnable（BLOCKED）

#### cat1 CVE-2017-5505 — ref=`1.900.27` — n=19 · M=0 · B=2 · N=17

| 版本 | 状态 | tested | death_mode（主导） | elapsed |
|---|---|---|---|---|
| 1.900.8 | · | 1200 | unknown:1078, unknown_decode:116, G_parse_error:6 | 26.1s |
| 1.900.9 | · | 1200 | unknown:1077, unknown_decode:117, G_parse_error:6 | 28.5s |
| 1.900.10 | · | 1200 | unknown:1078, unknown_decode:116, G_parse_error:6 | 17.7s |
| 1.900.11 | · | 1200 | unknown:1077, unknown_decode:117, G_parse_error:6 | 20.8s |
| 1.900.12 | · | 1200 | unknown:1078, unknown_decode:116, G_parse_error:3 | 22.6s |
| 1.900.13 | · | 1200 | unknown:1078, unknown_decode:116, G_parse_error:3 | 11.7s |
| 1.900.14 | · | 1200 | unknown:992, unknown_decode:202, G_parse_error:3 | 12.2s |
| 1.900.15 | · | 1200 | unknown:992, unknown_decode:202, G_parse_error:3 | 7.9s |
| 1.900.16 | · | 1200 | unknown:992, unknown_decode:202, G_parse_error:3 | 8.0s |
| 1.900.17 | · | 1040 | unknown:900, unknown_decode:134, G_parse_error:3 | 18.8s |
| 1.900.18 | · | 1039 | unknown:900, unknown_decode:133, G_parse_error:3 | 19.5s |
| 1.900.19 | · | 1040 | unknown:900, unknown_decode:134, G_parse_error:3 | 6.6s |
| 1.900.20 | · | 1040 | unknown:900, unknown_decode:134, G_parse_error:3 | 19.0s |
| 1.900.21 | · | 1040 | unknown:900, unknown_decode:134, G_parse_error:3 | 24.6s |
| 1.900.22 | · | 1039 | unknown:900, unknown_decode:133, G_parse_error:3 | 11.8s |
| 1.900.23 | · | 1040 | unknown:900, unknown_decode:134, G_parse_error:3 | 32.6s |
| 1.900.24 | · | 1040 | unknown:900, unknown_decode:134, G_parse_error:3 | 30.3s |
| 1.900.25 | 🔁 BASE | 0 | baseline same_site | 0.2s |
| 1.900.26 | 🔁 BASE | 0 | baseline same_site | 0.3s |

#### cat1 CVE-2017-6851 — ref=`2.0.10` — n=34 · M=0 · B=17 · N=17

| 版本 | 状态 | tested | death_mode（主导） | elapsed |
|---|---|---|---|---|
| 1.900.8 | · | 1200 | unknown_decode:1093, unknown:101, G_parse_error:6 | 12.3s |
| 1.900.9 | · | 1200 | unknown_decode:1093, unknown:101, G_parse_error:6 | 12.0s |
| 1.900.10 | · | 1200 | unknown_decode:1093, unknown:101, G_parse_error:6 | 18.2s |
| 1.900.11 | · | 1200 | unknown_decode:1093, unknown:101, G_parse_error:6 | 18.2s |
| 1.900.12 | · | 1200 | unknown_decode:1093, unknown:101, G_parse_error:6 | 5.9s |
| 1.900.13 | · | 1200 | unknown_decode:1093, unknown:101, G_parse_error:6 | 5.9s |
| 1.900.14 | · | 1200 | unknown_decode:1093, unknown:101, G_parse_error:6 | 6.1s |
| 1.900.15 | · | 1200 | unknown_decode:1093, unknown:101, G_parse_error:6 | 6.1s |
| 1.900.16 | · | 1200 | unknown_decode:1093, unknown:101, G_parse_error:6 | 13.9s |
| 1.900.17 | · | 1200 | unknown_decode:1093, unknown:101, G_parse_error:6 | 13.7s |
| 1.900.18 | · | 1200 | unknown_decode:1093, unknown:101, G_parse_error:6 | 5.9s |
| 1.900.19 | · | 1200 | unknown_decode:1093, unknown:101, G_parse_error:6 | 5.8s |
| 1.900.20 | · | 1200 | unknown_decode:1093, unknown:101, G_parse_error:6 | 22.0s |
| 1.900.21 | · | 1200 | unknown_decode:1093, unknown:101, G_parse_error:6 | 22.0s |
| 1.900.22 | · | 1200 | unknown_decode:1093, unknown:101, G_parse_error:6 | 5.8s |
| 1.900.23 | · | 1200 | unknown_decode:1097, unknown:97, G_parse_error:3 | 6.3s |
| 1.900.24 | · | 1200 | unknown_decode:1097, unknown:97, G_parse_error:3 | 18.9s |
| 1.900.25 | 🔁 BASE | 0 | baseline same_site | 0.1s |
| 1.900.26 | 🔁 BASE | 0 | baseline same_site | 0.1s |
| 1.900.27 | 🔁 BASE | 0 | baseline same_site | 0.1s |
| 1.900.28 | 🔁 BASE | 0 | baseline same_site | 0.1s |
| 1.900.29 | 🔁 BASE | 0 | baseline same_site | 0.1s |
| 1.900.30 | 🔁 BASE | 0 | baseline same_site | 0.1s |
| 1.900.31 | 🔁 BASE | 0 | baseline same_site | 0.1s |
| 2.0.0 | 🔁 BASE | 0 | baseline same_site | 0.1s |
| 2.0.1 | 🔁 BASE | 0 | baseline same_site | 0.1s |
| 2.0.2 | 🔁 BASE | 0 | baseline same_site | 0.1s |
| 2.0.3 | 🔁 BASE | 0 | baseline same_site | 0.1s |
| 2.0.4 | 🔁 BASE | 0 | baseline same_site | 0.1s |
| 2.0.5 | 🔁 BASE | 0 | baseline same_site | 0.1s |
| 2.0.6 | 🔁 BASE | 0 | baseline same_site | 0.1s |
| 2.0.7 | 🔁 BASE | 0 | baseline same_site | 0.1s |
| 2.0.8 | 🔁 BASE | 0 | baseline same_site | 0.1s |
| 2.0.9 | 🔁 BASE | 0 | baseline same_site | 0.1s |

#### cat1 CVE-2025-26623 — ref=`0.28.4` — n=1 · M=0 · B=0 · N=1

| 版本 | 状态 | tested | death_mode（主导） | elapsed |
|---|---|---|---|---|
| 0.27.7 | · | 1200 | unknown:956, unknown_clean:235, pastF_other:6 | 39.8s |

#### cat2 CVE-2026-50811 — ref=`2.14.0` — n=1 · M=0 · B=0 · N=1

| 版本 | 状态 | tested | death_mode（主导） | elapsed |
|---|---|---|---|---|
| 2.13.3 | · | 1021 | unknown_clean:532, unknown:483, prefork_other:3 | 23.5s |

#### cat2 CVE-2018-18088 — ref=`2.3.0` — n=6 · M=0 · B=0 · N=6

| 版本 | 状态 | tested | death_mode（主导） | elapsed |
|---|---|---|---|---|
| 2.0 | · | 1133 | unknown_decode:671, unknown:357, pastF_onpath_nomatch:47 | 101.7s |
| 2.0.1 | · | 1134 | unknown_decode:584, unknown:361, unknown_clean:179 | 140.8s |
| 2.1 | · | 1135 | unknown_decode:585, unknown:361, unknown_clean:180 | 150.6s |
| 2.1.1 | · | 1134 | unknown_decode:768, unknown:359, G_parse_error:6 | 44.0s |
| 2.1.2 | · | 1132 | unknown_decode:767, unknown:359, G_parse_error:6 | 59.7s |
| 2.2.0 | · | 1134 | unknown_decode:769, unknown:359, G_parse_error:6 | 19.6s |

#### cat2 CVE-2017-14152 — ref=`2.2.0` — n=5 · M=0 · B=2 · N=3

| 版本 | 状态 | tested | death_mode（主导） | elapsed |
|---|---|---|---|---|
| 2.0 | · | 436 | unknown:299, unknown_decode:131, G_parse_error:6 | 4.5s |
| 2.0.1 | · | 436 | unknown:299, unknown_decode:131, G_parse_error:6 | 17.7s |
| 2.1 | · | 436 | unknown:299, unknown_decode:131, G_parse_error:6 | 17.2s |
| 2.1.1 | 🔁 BASE | 0 | baseline same_func | 0.1s |
| 2.1.2 | 🔁 BASE | 0 | baseline same_func | 0.1s |

#### cat2 CVE-2017-14164 — ref=`2.2.0` — n=5 · M=0 · B=2 · N=3

| 版本 | 状态 | tested | death_mode（主导） | elapsed |
|---|---|---|---|---|
| 2.0 | · | 1200 | G_early_reject:1192, unknown:5, G_parse_error:3 | 21.8s |
| 2.0.1 | · | 1200 | G_early_reject:1192, unknown:5, G_parse_error:3 | 22.1s |
| 2.1 | · | 1200 | G_early_reject:1192, unknown:5, G_parse_error:3 | 32.8s |
| 2.1.1 | 🔁 BASE | 0 | baseline same_func | 0.1s |
| 2.1.2 | 🔁 BASE | 0 | baseline same_func | 0.1s |

#### cat2 CVE-2016-10269 — ref=`4.0.7` — n=12 · M=2 · B=6 · N=4

| 版本 | 状态 | tested | death_mode（主导） | elapsed |
|---|---|---|---|---|
| 3.9.3 | · | 1200 | G_early_reject:866, unknown:295, unknown_early:18, G_parse_error:6 | 26.8s |
| 3.9.4 | · | 1200 | G_early_reject:866, unknown:292, unknown_early:18, near_miss_same_type:9 | 27.0s |
| 3.9.5 | · | 1200 | G_early_reject:960, unknown:202, unknown_early:23, unknown_decode:7 | 13.7s |
| 3.9.6 | · | 1200 | G_early_reject:945, unknown:202, unknown_early:26, near_miss_same_type:12 | 27.4s |
| 4.0.0 | 🔁 BASE (same_func) | 0 | baseline `_TIFFmemcpy` tif_unix.c:280 | 0.2s |
| 4.0.1 | 🔁 BASE (same_func) | 0 | baseline `_TIFFmemcpy` tif_unix.c:280 | 0.1s |
| 4.0.2 | 🔁 BASE (same_func) | 0 | baseline `_TIFFmemcpy` tif_unix.c:284 | 0.1s |
| 4.0.3 | ✅ MATCH | 28 | G_early_reject:22, G_parse_error:4, unknown:1, matched:1 | 13.6s |
| 4.0.4 | ✅ MATCH | 9 | G_parse_error:6, unknown_decode:1, G_early_reject:1, matched:1 | 9.3s |
| 4.0.4beta | 🔁 BASE (same_func) | 0 | baseline `_TIFFmemcpy` tif_unix.c:287 | 0.1s |
| 4.0.5 | 🔁 BASE (same_site) | 0 | baseline `_TIFFmemcpy` tif_unix.c:340 | 0.1s |
| 4.0.6 | 🔁 BASE (same_site) | 0 | baseline `_TIFFmemcpy` tif_unix.c:340 | 0.1s |

MATCH 明细：4.0.3 `b@0xe=0x15`（单字节）→ `_TIFFmemcpy` tif_unix.c:284 same_func；4.0.4 `mb4@0xc=0x10` → `_TIFFmemcpy` tif_unix.c:307 same_func。与旧 `version_sweep` 日志中 0xe 成功变异一致。

#### cat2 CVE-2026-9504 — ref=`6d6a339` — n=5 · M=0 · B=0 · N=5

| 版本 | 状态 | tested | death_mode（主导） | elapsed |
|---|---|---|---|---|
| 0.12.4 | · | 1010 | unknown:1007, G_parse_error:3 | 34.5s |
| 0.12.5 | · | 1010 | unknown:1007, G_parse_error:3 | 58.0s |
| 0.13 | · | 1010 | unknown:1007, G_parse_error:3 | 53.7s |
| 0.13.3 | · | 1010 | unknown:1007, G_parse_error:3 | 43.0s |
| 0.13.4 | · | 1120 | near_miss_same_type:587, unknown:528, G_parse_error:3 | 115.4s |

#### cat2 CVE-2025-48071 — ref=`3.3.2` — n=3 · M=0 · B=2 · N=1

| 版本 | 状态 | tested | death_mode（主导） | elapsed |
|---|---|---|---|---|
| 3.2.12 | · | 236 | unknown:233, prefork_other:3 | 73.8s |
| 3.3.0 | 🔁 BASE | 0 | baseline same_site | 0.2s |
| 3.3.1 | 🔁 BASE | 0 | baseline same_site | 0.2s |

#### cat2 CVE-2022-44840 — ref=`2.38` — n=14 · M=0 · B=0 · N=14

| 版本 | 状态 | tested | death_mode（主导） | elapsed |
|---|---|---|---|---|
| 2.24 | · | 388 | G_early_reject:224, unknown:159, prefork_other:3 | 6.0s |
| 2.25 | · | 319 | G_early_reject:158, unknown:157, prefork_other:3 | 13.9s |
| 2.26 | · | 320 | G_early_reject:158, unknown:158, prefork_other:3 | 14.1s |
| 2.27 | · | 330 | unknown:167, G_early_reject:158, prefork_other:3 | 3.2s |
| 2.28 | · | 330 | unknown:167, G_early_reject:158, prefork_other:3 | 3.0s |
| 2.29 | · | 331 | unknown:167, G_early_reject:158, G_parse_error:3 | 3.2s |
| 2.30 | · | 331 | unknown:167, G_early_reject:158, G_parse_error:3 | 3.4s |
| 2.31 | · | 330 | unknown:166, G_early_reject:158, G_parse_error:3 | 20.5s |
| 2.31.1 | · | 331 | unknown:167, G_early_reject:158, G_parse_error:3 | 20.1s |
| 2.32 | · | 331 | unknown:167, G_early_reject:158, G_parse_error:3 | 3.5s |
| 2.34 | · | 331 | unknown:167, G_early_reject:158, G_parse_error:3 | 3.3s |
| 2.35 | · | 331 | unknown:167, G_early_reject:158, G_parse_error:3 | 3.7s |
| 2.35.1 | · | 330 | unknown:166, G_early_reject:158, G_parse_error:3 | 3.4s |
| 2.36 | · | 331 | unknown:167, G_early_reject:158, pastF_other:3 | 11.6s |

#### cat2 CVE-2023-1972 — ref=`2.40` — n=15 · M=0 · B=0 · N=15

| 版本 | 状态 | tested | death_mode（主导） | elapsed |
|---|---|---|---|---|
| 2.24 | · | 315 | pastF_onpath_nomatch:225, unknown_decode:87, prefork_other:3 | 57.8s |
| 2.25 | · | 440 | unknown:320, pastF_onpath_nomatch:50, unknown_decode:47 | 68.6s |
| 2.26 | · | 369 | unknown:274, unknown_decode:46, pastF_onpath_nomatch:40 | 43.6s |
| 2.27 | · | 369 | unknown:274, unknown_decode:46, pastF_onpath_nomatch:40 | 38.6s |
| 2.28 | · | 369 | unknown:274, unknown_decode:46, pastF_onpath_nomatch:40 | 51.1s |
| 2.29 | · | 369 | unknown:274, unknown_decode:46, pastF_onpath_nomatch:40 | 43.0s |
| 2.30 | · | 394 | unknown:297, unknown_decode:46, pastF_onpath_nomatch:42 | 47.5s |
| 2.31 | · | 315 | unknown:265, unknown_decode:41, prefork_other:6 | 38.7s |
| 2.31.1 | · | 315 | unknown:265, unknown_decode:41, prefork_other:6 | 21.0s |
| 2.32 | · | 474 | unknown:353, unknown_decode:109, prefork_other:6 | 34.8s |
| 2.34 | · | 474 | unknown:468, prefork_other:3, G_parse_error:3 | 38.1s |
| 2.35 | · | 474 | unknown:468, prefork_other:3, G_parse_error:3 | 31.4s |
| 2.35.1 | · | 474 | unknown:468, prefork_other:3, G_parse_error:3 | 25.7s |
| 2.36 | · | 474 | unknown:423, unknown_decode:44, prefork_other:3 | 49.9s |
| 2.38 | · | 393 | unknown:349, unknown_decode:38, prefork_other:3 | 57.3s |

#### cat3 CVE-2026-23865 — ref=`2.13.1` — n=6 · M=0 · B=0 · N=6

| 版本 | 状态 | tested | death_mode（主导） | elapsed |
|---|---|---|---|---|
| 2.8.1 | · | 1022 | unknown_clean:537, unknown:479, prefork_other:6 | 129.1s |
| 2.9.1 | · | 1021 | unknown_clean:537, unknown:478, prefork_other:3 | 121.5s |
| 2.10.4 | · | 1022 | unknown_clean:537, unknown:479, prefork_other:3 | 121.1s |
| 2.11.1 | · | 1022 | unknown_clean:537, unknown:479, prefork_other:3 | 135.6s |
| 2.12.1 | · | 1022 | unknown_clean:537, unknown:479, prefork_other:3 | 139.7s |
| 2.13.0 | · | 1022 | unknown_clean:537, unknown:479, prefork_other:3 | 106.8s |

#### cat3 CVE-2022-33034 — ref=`0.12.5` — n=1 · M=0 · B=0 · N=1

| 版本 | 状态 | tested | death_mode（主导） | elapsed |
|---|---|---|---|---|
| 0.12.4 | · | 1087 | unknown_decode:858, near_miss_same_type:226, G_parse_error:3 | 69.9s |

#### cat3 CVE-2026-9500 — ref=`6d6a339` — n=5 · M=0 · B=0 · N=5

| 版本 | 状态 | tested | death_mode（主导） | elapsed |
|---|---|---|---|---|
| 0.12.4 | · | 1200 | unknown_decode:1197, pastF_other:3 | 60.8s |
| 0.12.5 | · | 1200 | unknown_decode:608, unknown:586, pastF_other:3 | 58.7s |
| 0.13 | · | 1200 | unknown_decode:611, unknown:586, G_parse_error:3 | 58.2s |
| 0.13.3 | · | 1200 | unknown_decode:611, unknown:586, G_parse_error:3 | 83.9s |
| 0.13.4 | · | 1200 | unknown_decode:611, unknown:583, pastF_other:3 | 96.1s |

#### cat3 CVE-2026-9502 — ref=`0.13.4` — n=4 · M=0 · B=0 · N=4

| 版本 | 状态 | tested | death_mode（主导） | elapsed |
|---|---|---|---|---|
| 0.12.4 | · | 1200 | unknown_decode:1197, pastF_other:3 | 52.8s |
| 0.12.5 | · | 1200 | unknown_decode:1197, pastF_other:3 | 45.6s |
| 0.13 | · | 1200 | unknown_decode:1198, G_parse_error:2 | 45.7s |
| 0.13.3 | · | 1200 | unknown_decode:1198, G_parse_error:2 | 47.2s |

#### cat3 CVE-2026-9503 — ref=`0.13.4` — n=4 · M=0 · B=2 · N=2

| 版本 | 状态 | tested | death_mode（主导） | elapsed |
|---|---|---|---|---|
| 0.12.4 | · | 1128 | unknown_clean:802, unknown:320, pastF_no_crash:3 | 53.1s |
| 0.12.5 | · | 1128 | unknown_clean:823, unknown:299, pastF_no_crash:3 | 22.3s |
| 0.13 | 🔁 BASE | 0 | baseline same_func | 0.3s |
| 0.13.3 | 🔁 BASE | 0 | baseline same_func | 0.3s |

#### cat3 CVE-2026-9605 — ref=`0.13.4` — n=4 · M=0 · B=0 · N=4

| 版本 | 状态 | tested | death_mode（主导） | elapsed |
|---|---|---|---|---|
| 0.12.4 | · | 1119 | unknown:1113, pastF_other:6 | 18.4s |
| 0.12.5 | · | 1119 | unknown:1113, pastF_other:6 | 25.4s |
| 0.13 | · | 1119 | unknown:1113, G_parse_error:3, prefork_other:3 | 20.3s |
| 0.13.3 | · | 1119 | unknown:1113, G_parse_error:3, prefork_other:3 | 27.3s |

#### cat3 CVE-2026-15184 — ref=`0.13.4` — n=4 · M=0 · B=2 · N=2

| 版本 | 状态 | tested | death_mode（主导） | elapsed |
|---|---|---|---|---|
| 0.12.4 | · | 1200 | unknown:1070, unknown_clean:120, prefork_other:7 | 59.5s |
| 0.12.5 | · | 1200 | unknown_clean:642, unknown:546, prefork_other:6 | 61.6s |
| 0.13 | 🔁 BASE | 0 | baseline same_func | 0.3s |
| 0.13.3 | 🔁 BASE | 0 | baseline same_func | 0.3s |

#### cat3 CVE-2026-15520 — ref=`0.13.4` — n=4 · M=0 · B=0 · N=4

| 版本 | 状态 | tested | death_mode（主导） | elapsed |
|---|---|---|---|---|
| 0.12.4 | · | 1200 | unknown_decode:1197, pastF_other:3 | 29.6s |
| 0.12.5 | · | 1200 | unknown_decode:1197, pastF_other:3 | 12.0s |
| 0.13 | · | 1200 | unknown_decode:1200 | 20.4s |
| 0.13.3 | · | 1200 | unknown_decode:1200 | 20.2s |

#### cat3 CVE-2026-86145 — ref=`10.34` — n=3 · M=0 · B=0 · N=3

| 版本 | 状态 | tested | death_mode（主导） | elapsed |
|---|---|---|---|---|
| 10.00 | · | 584 | unknown:581, prefork_other:3 | 61.3s |
| 10.20 | · | 584 | unknown:581, prefork_other:3 | 73.4s |
| 10.30 | · | 666 | unknown:613, unknown_clean:44, prefork_other:9 | 4.1s |

#### cat4 CVE-2025-8176 — ref=`4.7.0` — n=22 · M=0 · B=0 · N=22

| 版本 | 状态 | tested | death_mode（主导） | elapsed |
|---|---|---|---|---|
| 3.9.3 | · | 1200 | G_early_reject:1037, unknown:109, unknown_decode:41 | 19.0s |
| 3.9.4 | · | 1200 | G_early_reject:1037, unknown:109, unknown_decode:41 | 18.9s |
| 3.9.5 | · | 1200 | G_early_reject:909, unknown_early:214, unknown:56 | 18.9s |
| 3.9.6 | · | 1200 | G_early_reject:911, unknown_early:215, unknown:55 | 24.2s |
| 4.0.0 | · | 1200 | G_early_reject:863, unknown_early:171, unknown:163 | 22.8s |
| 4.0.1 | · | 1200 | G_early_reject:863, unknown_early:171, unknown:163 | 15.7s |
| 4.0.2 | · | 1200 | G_early_reject:863, unknown_early:171, unknown:163 | 15.1s |
| 4.0.3 | · | 1200 | G_early_reject:863, unknown_early:171, unknown:163 | 14.6s |
| 4.0.4 | · | 1200 | G_early_reject:993, unknown_early:178, unknown:26 | 99.2s |
| 4.0.4beta | · | 1200 | G_early_reject:922, unknown_early:245, unknown:29 | 18.5s |
| 4.0.5 | · | 1200 | G_early_reject:922, unknown_early:245, unknown:29 | 105.8s |
| 4.0.6 | · | 1200 | G_early_reject:993, unknown_early:178, unknown:26 | 92.3s |
| 4.0.7 | · | 1200 | G_early_reject:997, unknown_early:177, unknown:23 | 104.2s |
| 4.0.8 | · | 1200 | G_early_reject:997, unknown_early:177, unknown:23 | 87.0s |
| 4.0.9 | · | 1200 | G_early_reject:856, unknown_early:175, unknown:166 | 102.5s |
| 4.0.10 | · | 1200 | G_early_reject:856, unknown_early:175, unknown:166 | 105.2s |
| 4.1.0 | · | 1200 | G_early_reject:997, unknown_early:177, unknown:23 | 76.3s |
| 4.2.0 | · | 1200 | G_early_reject:856, unknown_early:175, unknown:166 | 80.4s |
| 4.3.0 | · | 1200 | G_early_reject:856, unknown_early:175, unknown:166 | 81.5s |
| 4.4.0 | · | 1200 | G_early_reject:1002, unknown_early:174, unknown:21 | 98.1s |
| 4.5.0 | · | 1200 | G_early_reject:997, unknown_early:171, unknown:26 | 98.1s |
| 4.5.1 | · | 1200 | G_early_reject:997, unknown_early:171, unknown:26 | 88.3s |

#### cat4 CVE-2016-10268 — ref=`4.0.7` — n=12 · M=0 · B=0 · N=12

| 版本 | 状态 | tested | death_mode（主导） | elapsed |
|---|---|---|---|---|
| 3.9.3 | · | 577 | unknown:276, unknown_early:116, G_early_reject:101 | 397.0s |
| 3.9.4 | · | 613 | unknown:367, unknown_early:123, G_early_reject:105 | 398.9s |
| 3.9.5 | · | 1104 | unknown_early:518, unknown:351, G_early_reject:208 | 353.6s |
| 3.9.6 | · | 1104 | unknown_early:520, unknown:351, G_early_reject:207 | 335.5s |
| 4.0.0 | · | 1128 | unknown_early:493, G_early_reject:328, unknown:213 | 378.0s |
| 4.0.1 | · | 1200 | unknown_early:549, G_early_reject:344, unknown:213 | 359.8s |
| 4.0.2 | · | 1118 | unknown_early:491, G_early_reject:320, unknown:213 | 330.8s |
| 4.0.3 | · | 1118 | unknown_early:491, G_early_reject:320, unknown:213 | 353.4s |
| 4.0.4 | · | 1200 | unknown_early:546, G_early_reject:350, unknown:213 | 326.0s |
| 4.0.4beta | · | 1200 | unknown_early:545, G_early_reject:349, unknown:213 | 309.6s |
| 4.0.5 | · | 1181 | unknown_early:541, G_early_reject:334, unknown:213 | 335.5s |
| 4.0.6 | · | 1128 | unknown_early:491, G_early_reject:330, unknown:213 | 333.0s |

#### cat4 CVE-2017-9872 — ref=`3.99.5` — n=8 · M=0 · B=0 · N=8

| 版本 | 状态 | tested | death_mode（主导） | elapsed |
|---|---|---|---|---|
| 3.97 | · | 397 | unknown_clean:297, unknown:99, pastF_onpath_nomatch:1 | 18.7s |
| 3.98.2 | · | 318 | unknown_clean:219, unknown:98, pastF_onpath_nomatch:1 | 2.4s |
| 3.98.4 | · | 318 | unknown_clean:219, unknown:98, pastF_onpath_nomatch:1 | 3.5s |
| 3.99 | · | 408 | unknown:213, pastF_onpath_nomatch:188, unknown_clean:7 | 28.1s |
| 3.99.1 | · | 408 | unknown:213, pastF_onpath_nomatch:188, unknown_clean:7 | 28.0s |
| 3.99.2 | · | 408 | unknown:213, pastF_onpath_nomatch:188, unknown_clean:7 | 37.1s |
| 3.99.3 | · | 408 | unknown:213, pastF_onpath_nomatch:188, unknown_clean:7 | 36.9s |
| 3.99.4 | · | 408 | unknown:213, pastF_onpath_nomatch:188, unknown_clean:7 | 22.8s |

#### cat4 CVE-2017-9750 — ref=`2.28` — n=4 · M=0 · B=2 · N=2

| 版本 | 状态 | tested | death_mode（主导） | elapsed |
|---|---|---|---|---|
| 2.24 | · | 314 | pastF_onpath_nomatch:215, unknown_decode:78, unknown:14 | 35.2s |
| 2.25 | · | 416 | unknown:282, pastF_onpath_nomatch:54, unknown_clean:35 | 91.4s |
| 2.26 | 🔁 BASE | 0 | baseline same_site | 1.4s |
| 2.27 | 🔁 BASE | 0 | baseline same_site | 1.4s |

#### cat4 CVE-2017-14939 — ref=`2.29` — n=5 · M=0 · B=1 · N=4

| 版本 | 状态 | tested | death_mode（主导） | elapsed |
|---|---|---|---|---|
| 2.24 | · | 236 | unknown_decode:233, prefork_other:3 | 17.4s |
| 2.25 | · | 236 | unknown_decode:233, prefork_other:3 | 11.3s |
| 2.26 | · | 236 | unknown_decode:233, pastF_other:3 | 3.2s |
| 2.27 | · | 236 | unknown_decode:233, prefork_other:3 | 15.6s |
| 2.28 | 🔁 BASE | 0 | baseline same_func | 0.5s |

#### cat5 CVE-2022-28506 — ref=`5.1.1` — n=1 · M=0 · B=0 · N=1

| 版本 | 状态 | tested | death_mode（主导） | elapsed |
|---|---|---|---|---|
| 4.1.6 | · | 994 | unknown:918, near_miss_same_type:64, pastF_other:6 | 84.8s |

### 亮点

**MATCH（6 条）**

- `CVE-2016-10270` @ 4.0.1, 4.0.2, 4.0.4, 4.0.6（`mb2@0xac`）
- `CVE-2016-10269` @ 4.0.3 (`b@0xe=0x15`), 4.0.4 (`mb4@0xc=0x10`) — 第二轮修复后新增
- 10270 另有 BASELINE @ 4.0.0, 4.0.4beta, 4.0.5 → **4.0.x 全系实际都带此 bug**（ref=4.0.7）。
- 10269 另有 BASELINE @ 4.0.0-4.0.2, 4.0.4beta-4.0.6 → **4.0.x 全系原 PoC/变异均可触发**。

**BASELINE_TRIGGERS 集中区（43 条）**

| CVE | BASE 版本数 / 总数 | 版本 |
|---|---|---|
| CVE-2017-6851 | 17 / 34 | 1.900.25, 1.900.26, 1.900.27, 1.900.28, 1.900.29, 1.900.30, 1.900.31, 2.0.0, 2.0.1, 2.0.2, 2.0.3, 2.0.4, 2.0.5, 2.0.6, 2.0.7, 2.0.8, 2.0.9 … |
| CVE-2016-10269 | 6 / 12 | 4.0.0, 4.0.1, 4.0.2, 4.0.4beta, 4.0.5, 4.0.6 |
| CVE-2016-10270 | 3 / 12 | 4.0.0, 4.0.4beta, 4.0.5 |
| CVE-2017-14151 | 2 / 5 | 2.1.1, 2.1.2 |
| CVE-2017-14152 | 2 / 5 | 2.1.1, 2.1.2 |
| CVE-2017-14164 | 2 / 5 | 2.1.1, 2.1.2 |
| CVE-2017-5505 | 2 / 19 | 1.900.25, 1.900.26 |
| CVE-2017-9750 | 2 / 4 | 2.26, 2.27 |
| CVE-2025-48071 | 2 / 3 | 3.3.0, 3.3.1 |
| CVE-2026-15184 | 2 / 4 | 0.13, 0.13.3 |
| CVE-2026-9503 | 2 / 4 | 0.13, 0.13.3 |
| CVE-2017-14939 | 1 / 5 | 2.28 |

- **CVE-2017-6851**：34 个老版本中 17 个原 PoC 直接同点崩溃（1.900.25–2.0.9 几乎全中）→ bug 引入极早，ref=2.0.10 之前长期存在。
- **CVE-2016-10269/10270**：4.0.0–4.0.6 全部 baseline/match → 两个 bug 在 4.0 分支普遍存在（第二轮 PixarLog 重建 + 帧过滤修复后确认）。

**全 NO_MATCH 的大版本组（预算内 1200 候选未命中）**

| CVE | NO_MATCH / 总版本 | 备注 |
|---|---|---|
| CVE-2025-8176 | 22 / 22 | tiffmedian；4.6.0 缺失 |
| CVE-2017-6851 | 17 / 34 | 其余 17 个（1.900.24 及 2.0.10 之前部分） |
| CVE-2017-5505 | 17 / 19 | 其余 17 个 |
| CVE-2023-1972 | 15 / 15 | readelf/objdump header 门禁 |
| CVE-2022-44840 | 14 / 14 | readelf directory 门禁 |
| issue1620 | 12 / 12 | openjpeg SOD；ref=2.5.3 |
| CVE-2017-7597 | 12 / 12 | tiffcp TIFFReverseBits |
| CVE-2016-10268 | 12 / 12 | tiffcp write interceptor；候选多 timeout |

（CVE-2016-10269 已脱离全 NO_MATCH：见下「根因与修复」，现 M=2 B=6 N=4。）

### 本轮修复（跑通过程中发现并验证）

1. `_run_poc` 增加 `build_run_env(binary)` → tiff `.libs` 二进制加载版本内 `libtiff/.libs` 而非系统库。
2. `locate(tiff)` 优先 `tools/{tool}`（libtool wrapper 自带 LD_LIBRARY_PATH），fallback `.libs`。
3. `_uniq_tmp_args` 对目录型 `/tmp/extract` 改写时自动 `makedirs` → CVE-2025-5915 stage 恢复（此前 4 pair 全 `empty_results`）。
4. `ref_signature` 不再缓存 `null`；重算 5 个失效 ref sig（10268/10269/10270/7597/5915）全部成功。
5. 修复后 10270 的 baseline 才能正确报出 `BASELINE_TRIGGERS`（此前 ref sig 为 null，baseline 恒为 "no crash signature"）。

### CVE-2016-10269 新旧结果矛盾：根因与修复（第二轮）

**现象**：旧 `version_sweep` 日志（代码改动前）显示 4.0.0–4.0.6 全部 `mutation succeeded`（含 0xe 偏移），新代码重跑却 12/12 NO_MATCH，且明明变异了 0xe 仍判 no-match。

**根因分两层（均已修复并验证）**：

1. **帧过滤缺陷（`trace_fork_offsets._is_sanitizer_frame`）**
   - 预构建 target 栈为 `#0 __interceptor_memcpy` → `#1 memcpy /usr/include/.../bits/string_fortified.h:29` → `#2 _TIFFmemcpy tif_unix.c:280`。
   - 旧过滤只滤 `__interceptor_|__asan_|...`，不滤 fortified `memcpy` → `crash_frames[0]=memcpy` vs ref `_TIFFmemcpy` → 只判 `same_type` → NO_MATCH。
   - 修复：额外过滤 `string_fortified`/`bits/fortify`/`chk_fail` 及 `/usr/include`、`/usr/lib` 路径下的 libc wrapper 帧。
   - 验证：4.0.0 ORIG 与 0xe 变异均 → `same_func`；`test_crash_equivalence` 23 passed。

2. **4.0.1–4.0.6 预构建二进制缺 PixarLog（配置时无 zlib）**
   - 多数 `tif_config.h` 为 `/* #undef PIXARLOG_SUPPORT */` 且无 `libtiff.so.5` → 原 PoC/变异完全不崩（rc=1 无 ASan），"PixarLog compression support is not configured"。
   - 修复：系统已有 zlib 后对 4.0.1–4.0.6 重新 `./configure`（启用 PixarLog）并 `make clean && make` 重建 libtiff + 全部 tools。
   - 重建后验证：4.0.1/4.0.2/4.0.3 的 `b@0xe=0x15` → same_func；4.0.5/4.0.6 原 PoC 或变异 → same_site。

3. **单字节变异算子缺失（`extended_mutation`）**
   - 4.0.3 上仅「单字节写 `0xe=0x15`」可 same_func；原 mb/arith 算子只有 2/4/8 字节写入，`mb2@0xe=0x15` 会连带改掉相邻字节导致不崩。
   - 修复：新增 `_byte_candidates` + `dynamic-bytes` 阶段（优先值全偏移交错，cap=240 内覆盖 `b@0xe=0x15`，index=20）。
   - 验证：4.0.3 → MATCH `b@0xe=0x15` same_func `_TIFFmemcpy:284`。

**重跑结果（5 个 tiff CVE × 70 pair）**：

| CVE | 修复前 | 修复后 |
|---|---|---|
| CVE-2016-10269 | N=12 | **M=2 B=6 N=4** |
| CVE-2016-10270 | M=3 B=4 N=5 | **M=4 B=3 N=5** |
| CVE-2017-7597 | N=12 | N=12（near_miss 仍在，非帧/PixarLog 问题） |
| CVE-2016-10268 | N=12 | N=12（候选多 timeout） |
| CVE-2025-8176 | N=22 | N=22 |

3.9.x 仍 NO_MATCH，与旧日志一致（3.9.6 无 mutation success）。

### 环境与并发

- 双进程 sweep：`--cat 1 --workers 2` + `--cat 2,3,4,5 --workers 2`；stage 内部再各开 `RETROSCOPE_MUTATION_WORKERS=2` 的候选批池。
- `ASAN_OPTIONS=detect_leaks=0:halt_on_error=1:allocator_may_return_null=1:hard_rss_limit_mb=512`。
- 累计 recorded elapsed ≈ 4.0 h（不含 baseline/启动开销）。

