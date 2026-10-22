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

## libtiff (2 个)

工具路径: `tiff-versions/tiff-<ver>/tools/<tool>`

| CVE | 发现版本触发 | 更老版本不触发 | 命令 |
|-----|-------------|---------------|------|
| CVE-2025-8176 | 4.7.0 | 4.1.0-4.5.1 | `tiffmedian -C 256 -c lzw:2 -f in/libtiff/CVE-2025-8176.tif /tmp/out.tif` |
| CVE-2025-8177 | 4.7.0 | 4.1.0-4.5.1 | `thumbnail in/libtiff/CVE-2025-8177.tif /tmp/out.tif` |

崩溃位置:
- CVE-2025-8176: heap-use-after-free in quant_fsdither (tiffmedian.c:952)
- CVE-2025-8177: global-buffer-overflow in setrow (thumbnail.c:623), 目标 4.1.0 同函数 (thumbnail.c:541)；变异 offset 254 (`0x08 -> 0x25`) 可在 4.1.0 复现

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

## libsndfile (3 个)

工具路径: `/tmp/libsndfile-<ver>/programs/{sndfile-convert,sndfile-info}`（ASan 构建）

| CVE | 发现版本触发 | 更老版本不触发 | 命令 |
|-----|-------------|---------------|------|
| CVE-2017-7741 | 1.0.26-1.0.27 | 1.0.25 | `sndfile-info in/libsndfile/CVE-2017-7741` |
| CVE-2017-12562 | 1.0.28 | 1.0.25-1.0.27 | 编译 `in/libsndfile/CVE-2017-12562.c` 后运行生成的程序 |
| CVE-2018-19661 | 1.0.26-1.0.28 | 1.0.25 | `sndfile-convert -ulaw in/libsndfile/CVE-2018-19661 /tmp/out.raw` |

### CVE-2017-12562

崩溃位置: heap-buffer-overflow（WRITE of size 458）in `psf_binheader_writef` (`src/common.c:687`)，调用链 `wavlike_write_strings` (`wavlike.c:1095`) → `wav_write_header` (`wav.c:1062`) → `sf_writef_short`。

PoC 来源: `https://github.com/erikd/libsndfile/issues/292` 中的公开测试代码 `bug1.c`（CVE-2017-12562，原报告针对 openmpt123 写入超长 `SF_STR_COMMENT`）。代码原样收录为 `in/libsndfile/CVE-2017-12562.c`；无需变异。

版本差异: 1.0.28 引入 `psf_bump_header_allocation`，`psf_binheader_writef` 对大小写 `'s'` 只预留 16 字节而不是 `size` 字节，超长字符串元数据在 `memcpy` 时越过 512 字节堆块。1.0.25-1.0.27 的 header 缓冲扩容逻辑不同，不产生越界；但三个版本都包含 `psf_binheader_writef`。1.0.28 在 `test(SF_FORMAT_WAV, 456, 190, 0)` 处直接崩溃。

编译命令（以参考版本为例）:
```bash
gcc -std=c99 -g -O1 -fsanitize=address -fno-omit-frame-pointer \
  -I/tmp/libsndfile-1.0.28/src -I/tmp/libsndfile-1.0.28 \
  in/libsndfile/CVE-2017-12562.c -o /tmp/bug1 \
  -Wl,--start-group /tmp/libsndfile-1.0.28/src/.libs/libsndfile.a \
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

PoC 来源与变异: 公开 PoC 为 `https://github.com/erikd/libsndfile/files/2619018/poc.tar.gz`（issue #429）。原始文件在 1.0.26/1.0.27/1.0.28 的 GSM 解码输出中出现 `INT_MIN`，1.0.25 不会；将 data 区 offset 66 的字节 `0x60` 改为 `0x9F`（XOR 0xFF）后，1.0.25 也产生 `INT_MIN`，并触发同一处越界读。

版本差异: 1.0.26 起 `src/GSM610/decode.c` 使用 `int16_t` 中间类型，`src/gsm610.c` 改用 `arith_shift_left`，同一 GSM 帧可解出 `-32768`，再左移 16 位得到 `INT_MIN`；1.0.25 的旧解码路径对该帧不产生 `-32768`。两个版本的 `i2ulaw_array` 代码相同，均缺少 `INT_MIN` 处理。

ASan 布局说明: 越界下标固定为 `-8192`（`-INT_MIN >> 18`）。1.0.25 中 `ulaw_encode - 8192` 正好落在 ASan 全局红区，可直接报错；1.0.26 原始布局落在可寻址的相邻全局，ASan 静默。参考版本构建时在 `src/ulaw.c` 的 `ulaw_decode` 前加入 7584 字节全局 `asan_pad`，并用 `-fno-toplevel-reorder` 编译，使 `ulaw_encode - 8192` 落入该全局之前的红区（不改变被测代码），从而稳定复现参考崩溃。

CVE-2018-19662 是同一修复 PR 的 alaw 分支；其下标 `-2048` 在 1.0.25 和 1.0.26 的原始布局中都落在可寻址区，未单独收录。

编译命令（参考版本）:
```bash
cd /tmp/libsndfile-1.0.26
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
| libtiff | 2 |
| libredwg | 1 |
| libsndfile | 3 |
| **总计** | **32** |
