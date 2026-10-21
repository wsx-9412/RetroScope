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

## libtiff (1 个)

工具路径: `tiff-versions/tiff-<ver>/tools/<tool>`

| CVE | 发现版本触发 | 更老版本不触发 | 命令 |
|-----|-------------|---------------|------|
| CVE-2025-8176 | 4.7.0 | 4.1.0-4.5.1 | `tiffmedian -C 256 -c lzw:2 -f in/libtiff/CVE-2025-8176.tif /tmp/out.tif` |

崩溃位置: heap-use-after-free in quant_fsdither (tiffmedian.c:952)

注: thumbnail 需手动构建:
```bash
gcc -g -O0 -fsanitize=address -fno-omit-frame-pointer \
  -I<tiff-dir>/libtiff -I<tiff-dir>/port \
  <tiff-dir>/tools/thumbnail.c -o <tiff-dir>/tools/thumbnail \
  -L<tiff-dir>/libtiff/.libs -ltiff -L<tiff-dir>/port/.libs -lport -lm
```

---

## libwebp (1 个)

工具路径: `/home/ws/Desktop/webp-pilot/<ver>/build-asan/dwebp`（0.5.0 及更早为 `examples/dwebp`）

| CVE | 发现版本触发 | 更老版本不触发 | 命令 |
|-----|-------------|---------------|------|
| CVE-2023-4863 | 0.5.0-1.3.1 | 0.3.0-0.4.4 | `dwebp in/libwebp/CVE-2023-4863/bad.webp -o /tmp/out.ppm` |

崩溃位置: heap-buffer-overflow in `ReplicateValue`（0.6.0+ 为 `src/utils/huffman_utils.c:59`，0.5.x 为 `src/utils/huffman.c:59`），调用链 `BuildHuffmanTable` → `VP8LBuildHuffmanTable` → `ReadHuffmanCode` (`src/dec/vp8l_dec.c:348`)。

版本扫描（同一 `bad.webp`，25 个 tag）:

| 版本区间 | bad.webp | nso.webp |
|---|---|---|
| 0.3.0, 0.3.1, 0.4.0-0.4.4 | 不崩溃（BITSTREAM_ERROR） | 不崩溃 |
| 0.5.0, 0.5.1, 0.5.2 | heap-buffer-overflow in ReplicateValue | heap-buffer-overflow |
| 0.6.0, 0.6.1, 1.0.0-1.0.3, 1.1.0, 1.2.0-1.2.4, 1.3.0, 1.3.1 | heap-buffer-overflow in ReplicateValue | heap-buffer-overflow |
| 1.3.2 | 不崩溃（BITSTREAM_ERROR） | 不崩溃 |

结论: 漏洞路径随 0.5.0 的 Huffman 表重写引入，1.3.2 修复（提交 `2af26267`，重写 `VP8LBuildHuffmanTable` 分段分配）。0.3.0-0.4.4 源码中不存在 `BuildHuffmanTable`/`ReplicateValue`；1.3.2 虽保留函数名，但新增分段边界检查后不再越界。

编译命令（0.5.1+，CMake；0.5.1-1.0.0 需额外加 `-DWEBP_BUILD_DWEBP=ON`）:
```bash
cmake -S . -B build-asan -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_C_FLAGS="-g -O0 -fsanitize=address -fno-omit-frame-pointer" \
  -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address" -DBUILD_SHARED_LIBS=OFF \
  -DWEBP_BUILD_ANIM_UTILS=OFF -DWEBP_BUILD_CWEBP=OFF -DWEBP_BUILD_GIF2WEBP=OFF \
  -DWEBP_BUILD_IMG2WEBP=OFF -DWEBP_BUILD_VWEBP=OFF -DWEBP_BUILD_WEBPINFO=OFF \
  -DWEBP_BUILD_WEBPMUX=OFF -DWEBP_BUILD_EXTRAS=OFF
cmake --build build-asan --target dwebp -j
```

编译命令（0.3.0-0.5.0，autotools）:
```bash
sh autogen.sh && ./configure --disable-shared --enable-static \
  CFLAGS="-g -O0 -fsanitize=address -fno-omit-frame-pointer" \
  LDFLAGS="-fsanitize=address" && make -j
```

### 变异测试结论

`1.3.1→0.4.4`: **no-match**。0.4.4 不含 `BuildHuffmanTable`/`ReplicateValue`，无同一漏洞路径；而 0.5.0 是首个受影响版本，不存在“有相同代码但更老且不触发”的版本可用作变异目标。`1.3.2→1.3.1` 的 fork 定位落在 `vp8l_dec.c:303`（`VP8LSetBitPos`），变量 `ok`/`dec->status_`/`tables` 未映射到 PoC 输入字节，无法通过字节变异复现。

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
| libtiff | 1 |
| libwebp | 1 |
| **总计** | **28** |
