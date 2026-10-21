# RetroScope PoC Run Commands — 版本敏感 CVE

筛选标准: 原始 PoC 在**发现漏洞的版本**触发，但**该版本之前的更老版本**不触发（no crash）。
全版本通用触发、或"老版本触发新版本修复"的已剔除。

环境: `ASAN_OPTIONS=detect_leaks=0:allocator_may_return_null=1`
工作目录: `/home/ws/Desktop/RetroScope`

---

## binutils (21 个)

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
| CVE-2017-6966 | 2.28 | 2.23.2 | `readelf -w in/CVE-2017-6966` |
| CVE-2017-9750 | 2.28 | 2.25 | `objdump -D in/CVE-2017-9750` |
| CVE-2017-14745 | 2.29 | 2.25-2.28 | `objdump -d in/CVE-2017-14745` |
| CVE-2017-14974 | 2.29 | 2.25-2.28 | `objdump -d in/CVE-2017-14974` |
| CVE-2022-35206 | 2.38 | 2.23.2-2.36 | `readelf -w in/CVE-2022-35206` |
| CVE-2025-11081 | 2.45 | 2.43-2.44 | `objdump -S -D -x -s -Z -g -e -G -T -t -L -R --disassemble-zeroes --insn-width=32 --disassembler-color=extended in/CVE-2025-11081` |
| CVE-2025-69652 | 2.42 | 2.40-2.41 | `readelf -w abbrev in/CVE-2025-69652` |

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

## libxml2 (3 个)

工具路径: `libxml2-versions/libxml2-<ver>/xmllint`

| CVE | 发现版本触发 | 更老版本不触发 | 命令 |
|-----|-------------|---------------|------|
| CVE-2024-34459 | 2.9.5-2.9.10 | 2.9.0-2.9.4 | `xmllint --htmlout in/CVE-2024-34459` |
| CVE-2017-9049 | 2.9.4 | 2.9.0-2.9.2 | `xmllint --memory --oldxml10 in/CVE-2017-9049` |
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

## openjpeg (7 个)

工具路径: `openjpeg-versions/<ver>/bin/opj_decompress`（源码目录内 cmake 编译）

| CVE | 发现版本触发 | 更老版本不触发 | 命令 |
|-----|-------------|---------------|------|
| CVE-2016-9572 | 2.0.1-2.1, v2.1.1-v2.1.2 | 2.0 | `opj_decompress -i in/openjpeg/CVE-2016-9572/PoC2 -o /tmp/out.ppm` |
| issue908 | 2.0.1-2.1, v2.1.1-v2.1.2 | 2.0 | `opj_decompress -i in/openjpeg/issue908_poc.jp2 -o /tmp/out.pgm` |
| CVE-2018-18088 | 2.3.0 (仅) | 2.0-v2.2.0 | `opj_decompress -i in/openjpeg/CVE-2018-18088/291554_FlipDeter -o /tmp/out.ppm` |
| CVE-2021-3575 | 2.3.1-2.5.0 | 2.3.0 | `opj_decompress -i in/openjpeg/CVE-2021-3575.j2k -o /tmp/out.pgm` |
| issue1620 | 2.5.3-2.5.4 | 2.0-2.5.2 | `opj_decompress -i in/openjpeg/issue1620_poc.jp2 -o /tmp/out.pgm` |
| CVE-2016-10504 | v2.1.1-v2.1.2 | version.2.0-version.2.1 | `opj_compress -i in/openjpeg/CVE-2016-10504/poc.bmp -o /tmp/out.j2k` |
| issue1221 | v2.3.0-v2.3.1 | version.2.0-v2.2.0 | `opj_decompress -i in/openjpeg/issue1221/poc.j2k -o /tmp/out.ppm` |

崩溃位置:
- CVE-2016-9572: SEGV in color conversion
- issue908: SEGV in imagetopnm (convert.c:2167)
- CVE-2018-18088: SEGV in imagetopnm (convert.c:2243)
- CVE-2021-3575: heap-buffer-overflow in sycc420_to_rgb (color.c:379)
- issue1620: heap-buffer-overflow in opj_j2k_read_sod (j2k.c:5086)
- CVE-2016-10504: heap-buffer-overflow in opj_mqc_byteout (mqc.c:221)
- issue1221: SEGV in sycc422_to_rgb (color.c:201)

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

## libredwg (1 个)

工具路径: `/home/ws/Desktop/libredwg-pilot/v0.12.5/programs/dwg2dxf`；快照为 `/home/ws/Desktop/libredwg-pilot/snap/programs/dwg2dxf`

| CVE | 发现版本触发 | 更老版本不触发 | 命令 |
|-----|-------------|---------------|------|
| CVE-2022-33034 | 0.12.5, 2022-05 快照 | 0.12.3-0.12.4 | `dwg2dxf -b -m -y -o /dev/null in/libredwg/CVE-2022-33034-copy_bytes_sof` |

崩溃位置: stack-buffer-overflow in `copy_bytes` (`src/decode_r2007.c:228`)，调用链 `decompress_r2007` (`decode_r2007.c:563`) → `read_file_header` → `read_r2007_meta_data`。

版本扫描（同一 PoC）:

| 版本 | 结果 |
|---|---|
| 0.12.3 | 不崩溃，`copy_bytes` 执行到 `length overflow` 检查后返回 0x400 |
| 0.12.4 | 不崩溃，同样在 `length overflow` 检查返回 |
| 2022-05 快照 `f2dea29` | stack-buffer-overflow in `copy_bytes` |
| 0.12.5 | stack-buffer-overflow in `copy_bytes` |

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

---

## 汇总

| 项目 | 版本敏感 CVE 数 |
|------|-----------------|
| binutils | 21 |
| libxml2 | 3 |
| giflib | 1 |
| freetype | 3 |
| openjpeg | 7 |
| libarchive | 1 |
| libtiff | 1 |
| libredwg | 1 |
| **总计** | **38** |
