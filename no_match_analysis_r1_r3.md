# RetroScope 两轮 no-match CVE 分析（r1 + r3）

生成时间：2026-11-25 09:28  
状态快照：`status_r3.json` 最后更新 2026-11-25 08:36（后台批次仍在运行，部分 CVE 仍有版本未跑完）

## 0. 范围与口径

- 两轮：r1（单版本轮，结果已归档）与 r3（全版本轮，当前结果）。
- 纳入：两轮都没有任何 MATCH、且 r3 至少有一个 NO_MATCH 的 CVE；排除 TIMEOUT、ERROR、MATCH_PARTIAL 以及尚未开始的 pair。
- 快照统计：r3 记录 375 条，其中 NO_MATCH 265、MATCH 99、MATCH_PARTIAL 1、TIMEOUT 9、ERROR 1。
- 本文件分析 36 个 CVE；每个 CVE 的代表日志取“阶段最完整、候选最多”的 no-match 版本，版本间差异在备注中说明。
- 归类采用你给的 1 / 2a / 2b / 3，并额外把“GDB 回退导致流程没真正跑完”归到 1（方法/流程限制）。
- 初版主要是日志推断并沿用 poc_run_commands.md 的既有结论；本版补充逐 CVE 的源码函数体/守卫 diff，并在每节增加“源码核对”。源码核对目前是函数级，不是完整符号执行/调用图证明，2b/1 类结论仍可能随更深验证变化。

## 1. 结论总览

| CVE | no-match 版本数 | 代表版本 | 参考崩溃 | 主要归类 | 次要 | 一句话原因 |
|---|---:|---|---|---|---|---|
| CVE-2016-10270 | 4 | 3.9.5 | ASAN:heap-buffer-overflow TIFFFillStrip (tif_read.c:523) | **1** | 3 | 目标 3.9.x 在 `TIFFFillStrip` 之前报 `MissingRequired: TileOffsets |
| CVE-2016-9572 | 1 | 2.0 | ASAN:SEGV imagetopnm (convert.c:2075) | **1** | 3 | GDB fork 追踪失败（fork_not_reached），流程回退到仅格式字段变异（Step 6h），0 个动态候 |
| CVE-2017-14939 | 4 | 2.25 | ASAN:heap-buffer-overflow read_1_byte (dwarf2.c:593) | **1** | 2b | 文档将其归为搜索预算/反馈类；完整阶段约 5.2 万候选，目标 2.24-2.27 均含 `read_1_byte`，但 |
| CVE-2017-7597 | 11 | 4.0.4beta | ASAN:heap-buffer-overflow TIFFReverseBits (tif_swab.c:296) | **1** | 2b | 文档将其归为格式/解析门禁卡死（G_early_reject 主导）；本轮完整阶段约 11.3 万候选仍无 same_f |
| CVE-2025-8177 | 6 | 4.0.10 | ASAN:global-buffer-overflow setrow (thumbnail.c:623) | **1** | 2b | GDB fork 追踪失败，流程回退到仅格式字段（0 候选）；`setrow` 在 4.1.0 存在，目标基线不崩，但本 |
| CVE-2026-9504 | 4 | 0.12.5 | ASAN:heap-buffer-overflow bit_convert_TU (bits.c:2830) | **1** | 3 | 源码核对：目标 0.13.3 的 `bit_convert_TU` 与参考 6d6a339 仅差 2 行（基本相同），0 |
| issue1620 | 12 | 2.3.0 | ASAN:heap-buffer-overflow opj_j2k_read_sod (j2k.c:5086) | **1** | 2b | 仅执行到 Step 6f/6h，约 1.1 千候选；目标 2.0-2.5.2 的 `opj_j2k_read_sod`  |
| issue908 | 1 | 2.0 | ASAN:SEGV imagetopnm (convert.c:2167) | **1** | 3 | GDB fork 追踪失败，回退到仅格式字段（0 候选）；目标 2.0 的 `imagetopnm` 存在，但本轮没有真 |
| CVE-2017-14152 | 3 | 2.0.1 | ASAN:heap-buffer-overflow opj_write_bytes_LE (cio.c:67) | **2a** | 1 | 目标 2.0/2.0.1/2.1 的 `opj_start_compress`/`opj_write_bytes_LE` |
| CVE-2017-14164 | 3 | 2.0.1 | ASAN:heap-buffer-overflow opj_write_bytes_LE (cio.c:67) | **2a** | 2b | 完整阶段约 3.2 万候选，fork 在 `opj_start_compress`，目标 2.0/2.0.1/2.1 的 |
| CVE-2022-33034 | 1 | 0.12.4 | ASAN:stack-buffer-overflow copy_bytes (decode_r2007.c:228) | **2a** | 3 | 文档已证明：参考 0.12.5 `read_file_header` 传入 `sizeof+1`，目标 0.12.4 传 |
| CVE-2022-44840 | 14 | 2.29 | ASAN:heap-buffer-overflow find_section_in_set (readelf.c:1001) | **2a** | 1 | 目标 2.36 有 "Section is too small for 208 slots" 检查；参考 2.38 的  |
| CVE-2023-1972 | 14 | 2.32 | ASAN:heap-buffer-overflow _bfd_elf_print_private_bfd_data (elf.c:1844) | **2a** | 1 | 目标 2.38 仍拒绝 `hdr->sh_info==0` 并保留 `bfd_alloc/amt` 检查；参考 2.40 |
| CVE-2023-3618 | 11 | 3.9.5 | ASAN:SEGV _TIFFmemcpy (tif_unix.c:345) | **2a** | 2b | `Fax3Encode` 在 3.9.5/4.1.0 等目标存在；完整阶段约 2.3 万候选，只有 no_crash/f |
| CVE-2025-48071 | 1 | 3.2.12 | ASAN:heap-buffer-overflow interleave (internal_zip.c:166) | **2a** | 1 | 源码层面：3.2.12 要求 `actual_out_bytes == uncompressed_size`，3.3.0 |
| CVE-2026-15520 | 4 | 0.12.5 | ASAN:heap-buffer-overflow decompress_R2004_section (decode.c:1313) | **2a** | 3 | 目标 0.12.x/0.13.3：0.12.5 在 `decompress_R2004_section` 前拒绝/边界返 |
| CVE-2026-86145 | 3 | 10.30 | ASAN:heap-buffer-overflow internal_dfa_match (pcre2_dfa_match.c:677) | **2a** | 3 | 目标 10.30 对递归 DFA 报 `error -52: nested recursion...`，在到达 `int |
| CVE-2026-9500 | 4 | 0.13 | ASAN:SEGV read_2004_compressed_section (decode.c:2181) | **2a** | 3 | 参考崩溃只在 6d6a339；目标 0.12.4-0.13.4 的 `read_2004_compressed_sect |
| CVE-2026-9502 | 4 | 0.12.5 | ASAN:heap-buffer-overflow decompress_R2004_section (decode.c:1313) | **2a** | 3 | 目标 0.12.4/0.12.5/0.13/0.13.3：0.12.5 更早拒绝，`decompress_R2004_s |
| CVE-2018-18088 | 6 | 2.1.1 | ASAN:SEGV imagetopnm (convert.c:2243) | **2b** | 1 | 源码核对：最近目标 2.2.0 的 `imagetopnm` 与参考 2.3.0 完全相同（diff 0），2.0 才相 |
| CVE-2021-3575 | 7 | 2.3.0 | ASAN:heap-buffer-overflow sycc420_to_rgb (color.c:379) | **2b** | 1 | 完整阶段约 8 千候选，`sycc420_to_rgb` 在目标存在；fork 在 `opj_j2k_exec`，得到  |
| CVE-2023-30775 | 11 | 4.0.4beta | ASAN:heap-buffer-overflow extractContigSamples32bits (tiffcrop.c:3196) | **2b** | 2a | `extractContigSamples32bits` 在目标 4.0.6 存在；完整阶段约 5.5 万候选，出现 s |
| CVE-2024-34459 | 4 | 2.9.4 | ASAN:heap-buffer-overflow xmlHTMLPrintFileContext (xmllint.c:614) | **2b** | 1 | 源码核对：`xmlHTMLPrintFileContext` 在 2.9.4/2.9.0 与参考 2.9.5 完全相同（ |
| CVE-2025-5915 | 4 | 3.4.3 | ASAN:heap-buffer-overflow copy_from_lzss_window (archive_read_support_format_rar.c:3069) | **2b** | 3 | 目标 3.5.3 的 `copy_from_lzss_window` 签名/实现与 3.6.0 不同（`const vo |
| CVE-2026-23865 | 6 | 2.8.1 | ASAN:SEGV tt_var_get_item_delta (ttgxvar.c:1053) | **2b** | 3 | 源码核对：`tt_var_get_item_delta` 在目标 2.8.1 未找到（该版本路径不存在），2.13.0  |
| CVE-2026-50811 | 8 | 2.13.3 | ASAN:heap-buffer-overflow TT_Get_Var_Design (ttgxvar.c:3502) | **2b** | 2a | 完整阶段约 16 万候选，目标 2.8.1-2.13.3 均无 same_func；freetype 设计空间/状态组合 |
| CVE-2026-9605 | 4 | 0.12.4 | ASAN:heap-buffer-overflow bit_read_RC (bits.c:282) | **2b** | 1 | 源码核对：目标 0.13.3 的 `bit_read_RC` 与参考 0.13.4 完全相同（diff 0），0.12. |
| CVE-2016-10268 | 4 | 4.0.3 | ASAN:heap-buffer-overflow _tiffWriteProc (tif_unix.c:115) | **3** | 1 | 源码核对：目标 3.9.3/4.0.3/4.0.4/4.0.4beta 的 `_tiffWriteProc` 是单次 w |
| CVE-2016-10269 | 4 | 3.9.6 | ASAN:heap-buffer-overflow _TIFFmemcpy (tif_unix.c:340) | **3** | 2b | 目标 3.9.3-3.9.6 缺少 PixarLog 解码→写路径（文档记录：缺 PixarLog 时原 PoC 返回  |
| CVE-2017-14151 | 3 | 2.0.1 | ASAN:heap-buffer-overflow opj_mqc_byteout (mqc.c:198) | **3** | 1 | 目标 2.0/2.0.1/2.1 不含 `opj_tcd_code_block_enc_allocate_data`，参 |
| CVE-2017-5505 | 12 | 1.900.8 | ASAN:SEGV jas_matrix_asl (jas_seq.c:376) | **3** | 2a | `jas_matrix_asl` 在 1.900.24 已存在，但负 ROI shift 的漏洞行为实际在 1.900. |
| CVE-2017-6851 | 12 | 1.900.13 | ASAN:SEGV jas_matrix_bindsub (jas_seq.c:254) | **3** | 2a | `jas_matrix_bindsub` 在目标 1.900.8-1.900.24 已存在，但漏洞行为在 1.900.2 |
| CVE-2025-26623 | 1 | 0.27.7 | ASAN:heap-use-after-free Exiv2::Internal::TiffComponent::accept (tiffcomposite_int.cpp:622) | **3** | 2a | 0.27.7 早于 0.28 的 TIFF composite 重写；NVD 明确 <0.28.0 不受影响，目标缺少  |
| CVE-2025-8176 | 16 | 3.9.3 | ASAN:heap-use-after-free quant_fsdither (tiffmedian.c:952) | **3** | 2b | 源码对比：4.7.0 在 `quant_fsdither`/`create_colorcell` 增加了 `_TIFFf |
| CVE-2026-15184 | 2 | 0.12.5 | ASAN:SEGV dwg_next_entity (dwg.c:1233) | **3** | 2b | 目标 0.12.5 早于 0.13 的 `dwg_next_entity` 崩溃路径/行为；完整阶段约 4 千候选无 s |
| CVE-2026-9503 | 1 | 0.12.5 | ASAN:SEGV dwg_next_entity (dwg.c:1233) | **3** | 2b | 目标 0.12.4/0.12.5 早于 0.13 的 `dwg_next_entity` 崩溃行为；完整阶段仅约 2.6 |

### 归类统计

- **1**（8）：CVE-2016-10270、CVE-2016-9572、CVE-2017-14939、CVE-2017-7597、CVE-2025-8177、CVE-2026-9504、issue1620、issue908
- **2a**（11）：CVE-2017-14152、CVE-2017-14164、CVE-2022-33034、CVE-2022-44840、CVE-2023-1972、CVE-2023-3618、CVE-2025-48071、CVE-2026-15520、CVE-2026-86145、CVE-2026-9500、CVE-2026-9502
- **2b**（8）：CVE-2018-18088、CVE-2021-3575、CVE-2023-30775、CVE-2024-34459、CVE-2025-5915、CVE-2026-23865、CVE-2026-50811、CVE-2026-9605
- **3**（9）：CVE-2016-10268、CVE-2016-10269、CVE-2017-14151、CVE-2017-5505、CVE-2017-6851、CVE-2025-26623、CVE-2025-8176、CVE-2026-15184、CVE-2026-9503

> 1 = 方法/流程/搜索能力不足（含 GDB 回退、候选未覆盖、预算不足）；2a = 能到崩溃行但目标守卫/条件冲突；2b = 到崩溃行但偏移/状态组合不足；3 = 目标版本缺少完整漏洞路径（旧实现、函数/分支缺失、早期拒绝、bug 未引入）。

## 2. 逐 CVE 分析

### CVE-2016-10270

- **目标版本（no-match）**：3.9.3, 3.9.4, 3.9.5, 3.9.6
- **参考崩溃**：Reference CRASH: ASAN:heap-buffer-overflow in TIFFFillStrip at /home/ws/Desktop/RetroScope/tiff-versions/tiff-4.0.7/libtiff/tif_read.c:523
- **目标基线**：Target:    no crash
- **定位到的 fork**：[*] Fork: /home/ws/Desktop/RetroScope/tiff-versions/tiff-3.9.5/libtiff/tif_dirread.c:1646
- **fork 变量**：[*] Variables: ['fii', 'dp->tdir_count']
- **根因函数**：Root cause function: TIFFFetchNormalTag
- **变异证据（代表版本 3.9.5）**：阶段 {'a': 1, 'f': 3, 'h': 4}，候选约 3443；no_crash=2243、fork_flip=0、same_type=0、different_type=0；gdb_fail=0、fallback=0、not_reached=0、code_change=0
- **最后位置**：[*] Testing offset 0xe2 (original=0x02)...
- **归类：1（次要 3）**
- **源码核对**：`TIFFFillStrip` 目标 3.9.x 与参考 diff 109 行；目标更早的 required-tag/TileOffsets 门禁使输入到不了该函数。
- **原因**：目标 3.9.x 在 `TIFFFillStrip` 之前报 `MissingRequired: TileOffsets` 并干净退出；崩溃函数存在，但格式门禁使变异输入无法到达崩溃行（文档将该 CVE 归为格式门禁类）。
- **备注/置信度**：不是代码路径缺失，而是结构保持/门禁穿越能力不足。

### CVE-2016-9572

- **目标版本（no-match）**：2.0
- **参考崩溃**：Reference CRASH: ASAN:SEGV in imagetopnm at /home/ws/Desktop/RetroScope/openjpeg-versions/version.2.0.1/src/bin/jp2/convert.c:2075
- **目标基线**：Target:    no crash
- **定位到的 fork**：[*] Fork: /home/ws/Desktop/RetroScope/openjpeg-versions/version.2.0/src/bin/jp2/convert.c:1943
- **fork 变量**：[*] Variables: ['has_alpha']
- **根因函数**：Root cause function: imagetopnm
- **变异证据（代表版本 2.0）**：阶段 {'h': 2}，候选约 0；no_crash=0、fork_flip=0、same_type=0、different_type=0；gdb_fail=2、fallback=1、not_reached=1、code_change=0
- **归类：1（次要 3）**
- **源码核对**：`imagetopnm` 2.0 与 2.0.1 相差 592 行；本轮 GDB 回退，未完成搜索。
- **原因**：GDB fork 追踪失败（fork_not_reached），流程回退到仅格式字段变异（Step 6h），0 个动态候选；no-match 不具结论性。
- **备注/置信度**：需要修复/手工指定 fork 后复测；目标 2.0 的 `imagetopnm` 仍存在。

### CVE-2017-14939

- **目标版本（no-match）**：2.24, 2.25, 2.26, 2.27
- **参考崩溃**：Reference CRASH: ASAN:heap-buffer-overflow in read_1_byte at ../../bfd/dwarf2.c:593
- **目标基线**：Target:    no crash
- **定位到的 fork**：[*] Fork: ../../binutils/nm.c:1667
- **fork 变量**：[*] Variables: ['stderr', 'aABCDef', 'gHhlnopPrSst', 'uvVvX']
- **根因函数**：Root cause function: main
- **变异证据（代表版本 2.25）**：阶段 {'b': 1, 'e': 1, 'g': 1, 'f': 3, 'c': 1, 'd': 1, 'h': 4}，候选约 51764；no_crash=50564、fork_flip=0、same_type=0、different_type=0；gdb_fail=0、fallback=0、not_reached=0、code_change=0
- **最后位置**：[*] Testing pair 0x7480+0x7488 (original=f8,08)...
- **归类：1（次要 2b）**
- **源码核对**：`read_1_byte` 在 2.27 与参考 2.29 完全相同（diff 0）；2.24 少一个上界检查。路径存在，no-match 来自搜索/状态。
- **原因**：文档将其归为搜索预算/反馈类；完整阶段约 5.2 万候选，目标 2.24-2.27 均含 `read_1_byte`，但没有 same_func。
- **备注/置信度**：不是路径缺失，而是搜索/偏移覆盖不足。

### CVE-2017-7597

- **目标版本（no-match）**：3.9.3, 3.9.4, 3.9.5, 4.0.0, 4.0.1, 4.0.2, 4.0.3, 4.0.4, 4.0.4beta, 4.0.5, 4.0.6
- **参考崩溃**：Reference CRASH: ASAN:heap-buffer-overflow in TIFFReverseBits at /home/ws/Desktop/RetroScope/tiff-versions/tiff-4.0.7/libtiff/tif_swab.c:296
- **目标基线**：Target:    no crash
- **定位到的 fork**：[*] Fork: /home/ws/Desktop/RetroScope/tiff-versions/tiff-4.0.4beta/libtiff/tif_swab.c:289
- **fork 变量**：[*] Variables: ['cp[0]', 'TIFFBitRevTable', 'image.width', 'image.length', 'image.bps', 'image.spp', 'image.compression', 'image.photometric', 'image.orientation', 'image.planar', 'image.res_unit', 'crop.combined_width', 'crop.combined_length', 'crop.bufftotal', 'crop.zones', 'crop.selections', 'crop.edge_ref', 'crop.crop_mode']
- **根因函数**：Root cause function: TIFFReverseBits
- **变异证据（代表版本 4.0.4beta）**：阶段 {'f': 3, 'c': 1, 'd': 1, 'h': 4}，候选约 112862；no_crash=28952、fork_flip=82715、same_type=5、different_type=0；gdb_fail=0、fallback=0、not_reached=0、code_change=0
- **最后位置**：[*] Testing pair 0xdc+0xe0 (original=06,f8)...
- **归类：1（次要 2b）**
- **源码核对**：`TIFFReverseBits` 在 4.0.6/3.9.3 与参考仅 brace/loop 格式差异；路径存在，no-match 是门禁/搜索。
- **原因**：文档将其归为格式/解析门禁卡死（G_early_reject 主导）；本轮完整阶段约 11.3 万候选仍无 same_func，说明结构保持/门禁穿越算子不足。
- **备注/置信度**：目标 `TIFFReverseBits` 存在；主因是门禁与搜索方法。

### CVE-2025-8177

- **目标版本（no-match）**：3.9.3, 3.9.4, 3.9.5, 3.9.6, 4.0.10, 4.1.0
- **参考崩溃**：Reference CRASH: ASAN:global-buffer-overflow in setrow at /home/ws/Desktop/RetroScope/tiff-versions/tiff-4.7.0/tools/thumbnail.c:623
- **目标基线**：Target:    no crash
- **定位到的 fork**：[*] Fork: /home/ws/Desktop/RetroScope/tiff-versions/tiff-4.0.10/tools/thumbnail.c:526
- **fork 变量**：[*] Variables: ['i', 'fw', 'acc', 'bits', 'src', 'image.width', 'image.length', 'image.bps', 'image.spp', 'image.compression', 'image.photometric', 'image.orientation', 'image.planar', 'image.res_unit', 'crop.combined_width', 'crop.combined_length', 'crop.bufftotal', 'crop.zones', 'crop.selections', 'crop.edge_ref', 'crop.crop_mode']
- **根因函数**：Root cause function: setrow
- **变异证据（代表版本 4.0.10）**：阶段 {'h': 2}，候选约 0；no_crash=0、fork_flip=0、same_type=0、different_type=0；gdb_fail=2、fallback=1、not_reached=1、code_change=0
- **归类：1（次要 2b）**
- **源码核对**：`setrow` 在 4.1.0/3.9.3 存在，函数体差 74 行；本轮 GDB 回退，未真正搜索。
- **原因**：GDB fork 追踪失败，流程回退到仅格式字段（0 候选）；`setrow` 在 4.1.0 存在，目标基线不崩，但本轮没有真正搜索到偏移。
- **备注/置信度**：no-match 不具结论性，需要修复 fork 后复测。

### CVE-2026-9504

- **目标版本（no-match）**：0.12.4, 0.12.5, 0.13, 0.13.3
- **参考崩溃**：Reference CRASH: ASAN:heap-buffer-overflow in bit_convert_TU at /home/ws/Desktop/libredwg-versions/libredwg-6d6a339/src/bits.c:2830
- **目标基线**：Target:    no crash
- **根因函数**：Root cause function: bit_read_RC
- **变异证据（代表版本 0.12.5）**：阶段 {'h': 2}，候选约 0；no_crash=0、fork_flip=0、same_type=0、different_type=0；gdb_fail=1、fallback=1、not_reached=0、code_change=0
- **归类：1（次要 3）**
- **源码核对**：`bit_convert_TU` 在 0.13.3 与参考差 2 行（基本相同），0.12.4 差 103 行；0.13.3 的 no-match 不能用函数缺失解释，本轮还 GDB 回退。
- **原因**：源码核对：目标 0.13.3 的 `bit_convert_TU` 与参考 6d6a339 仅差 2 行（基本相同），0.12.4 才差 103 行；0.13.3 的 no-match 不能用“函数缺失”解释，更可能是本轮 GDB 回退/搜索未执行。0.12.x 另有路径差异。
- **备注/置信度**：版本相关；首要问题是流程回退（1），不是已证明的路径缺失。

### issue1620

- **目标版本（no-match）**：2.0, 2.0.1, 2.1, 2.1.1, 2.1.2, 2.2.0, 2.3.0, 2.3.1, 2.4.0, 2.5.0, 2.5.1, 2.5.2
- **参考崩溃**：Reference CRASH: ASAN:heap-buffer-overflow in opj_j2k_read_sod at /home/ws/Desktop/RetroScope/openjpeg-versions/v2.5.3/src/lib/openjp2/j2k.c:5086
- **目标基线**：Target:    no crash
- **定位到的 fork**：[*] Fork: /home/ws/Desktop/RetroScope/openjpeg-versions/v2.3.0/src/lib/openjp2/cio.c:586
- **fork 变量**：[*] Variables: ['p_stream->m_byte_offset']
- **根因函数**：Root cause function: opj_j2k_read_tile_header
- **变异证据（代表版本 2.3.0）**：阶段 {'f': 3, 'h': 4}，候选约 1137；no_crash=0、fork_flip=0、same_type=0、different_type=0；gdb_fail=0、fallback=0、not_reached=0、code_change=0
- **归类：1（次要 2b）**
- **源码核对**：`opj_j2k_read_sod` 在 2.5.2 与参考差 7 行；2.0 未找到该函数。
- **原因**：仅执行到 Step 6f/6h，约 1.1 千候选；目标 2.0-2.5.2 的 `opj_j2k_read_sod` 路径存在但大量输入被解析门禁拒绝，搜索未展开。
- **备注/置信度**：方法/预算为主。

### issue908

- **目标版本（no-match）**：2.0
- **参考崩溃**：Reference CRASH: ASAN:SEGV in imagetopnm at /home/ws/Desktop/RetroScope/openjpeg-versions/version.2.0.1/src/bin/jp2/convert.c:2167
- **目标基线**：Target:    no crash
- **定位到的 fork**：[*] Fork: /home/ws/Desktop/RetroScope/openjpeg-versions/version.2.0/src/bin/jp2/convert.c:1969
- **fork 变量**：[*] Variables: ['i', 'wr', 'hr']
- **根因函数**：Root cause function: imagetopnm
- **变异证据（代表版本 2.0）**：阶段 {'h': 2}，候选约 0；no_crash=0、fork_flip=0、same_type=0、different_type=0；gdb_fail=2、fallback=1、not_reached=1、code_change=0
- **归类：1（次要 3）**
- **源码核对**：`imagetopnm` 2.0 与 2.0.1 差 592 行；本轮 GDB 回退。
- **原因**：GDB fork 追踪失败，回退到仅格式字段（0 候选）；目标 2.0 的 `imagetopnm` 存在，但本轮没有真正搜索。
- **备注/置信度**：no-match 不具结论性，需要修复 fork 后复测。

### CVE-2017-14152

- **目标版本（no-match）**：2.0, 2.0.1, 2.1
- **参考崩溃**：Reference CRASH: ASAN:heap-buffer-overflow in opj_write_bytes_LE at /home/ws/Desktop/RetroScope/openjpeg-versions/version.2.2.0/src/lib/openjp2/cio.c:67
- **目标基线**：Target:    no crash
- **定位到的 fork**：[*] Fork: /home/ws/Desktop/RetroScope/openjpeg-versions/version.2.0.1/src/lib/openjp2/openjpeg.c:723
- **fork 变量**：[*] Variables: ['l_codec->is_decompressor']
- **根因函数**：Root cause function: opj_start_compress
- **变异证据（代表版本 2.0.1）**：阶段 {'f': 3, 'h': 4}，候选约 436；no_crash=0、fork_flip=0、same_type=0、different_type=0；gdb_fail=0、fallback=0、not_reached=0、code_change=0
- **归类：2a（次要 1）**
- **源码核对**：`opj_write_bytes_LE` 在 2.0/2.1 存在；源码/调用链与 2.2.0 有差异，需条件/偏移对齐。
- **原因**：目标 2.0/2.0.1/2.1 的 `opj_start_compress`/`opj_write_bytes_LE` 路径存在，但参考→目标的编码器分支/条件不一致；只有约 436 候选，未覆盖到同型崩溃。
- **备注/置信度**：文档归类为参考→目标 offset/branch 不一致。

### CVE-2017-14164

- **目标版本（no-match）**：2.0, 2.0.1, 2.1
- **参考崩溃**：Reference CRASH: ASAN:heap-buffer-overflow in opj_write_bytes_LE at /home/ws/Desktop/RetroScope/openjpeg-versions/version.2.2.0/src/lib/openjp2/cio.c:67
- **目标基线**：Target:    no crash
- **定位到的 fork**：[*] Fork: /home/ws/Desktop/RetroScope/openjpeg-versions/version.2.0.1/src/lib/openjp2/openjpeg.c:723
- **fork 变量**：[*] Variables: ['l_codec->is_decompressor']
- **根因函数**：Root cause function: opj_start_compress
- **变异证据（代表版本 2.0.1）**：阶段 {'f': 3, 'c': 1, 'd': 1, 'h': 4}，候选约 32164；no_crash=30968、fork_flip=0、same_type=0、different_type=0；gdb_fail=0、fallback=0、not_reached=0、code_change=0
- **最后位置**：[*] Testing pair 0xdc+0xe0 (original=3b,3b)...
- **归类：2a（次要 2b）**
- **源码核对**：`opj_write_bytes_LE` 在 2.0/2.1 存在；源码/调用链与 2.2.0 有差异，需条件/偏移对齐。
- **原因**：完整阶段约 3.2 万候选，fork 在 `opj_start_compress`，目标 2.0/2.0.1/2.1 的编码路径存在但条件/分支不同；没有 same_func。
- **备注/置信度**：偏移/条件不一致。

### CVE-2022-33034

- **目标版本（no-match）**：0.12.4
- **参考崩溃**：Reference CRASH: ASAN:stack-buffer-overflow in copy_bytes at /home/ws/Desktop/libredwg-versions/libredwg-0.12.5/src/decode_r2007.c:228
- **目标基线**：Target:    no crash
- **定位到的 fork**：[*] Fork: /home/ws/Desktop/RetroScope/libredwg-versions/libredwg-0.12.4/src/decode_r2007.c:228
- **fork 变量**：[*] Variables: ['dst', 'src']
- **根因函数**：Root cause function: copy_bytes
- **变异证据（代表版本 0.12.4）**：阶段 {'f': 3, 'h': 4}，候选约 851；no_crash=0、fork_flip=0、same_type=0、different_type=0；gdb_fail=0、fallback=0、not_reached=1、code_change=0
- **归类：2a（次要 3）**
- **源码核对**：`copy_bytes` 函数体与守卫逐字相同；差异在调用者 dst_size（272 vs 273），守卫必然拒绝。
- **原因**：文档已证明：参考 0.12.5 `read_file_header` 传入 `sizeof+1`，目标 0.12.4 传入 272，`dst_end` 恰等于对象末尾，`copy_bytes` 的越界守卫必然拒绝；输入变异无解。
- **备注/置信度**：条件冲突的代码级证据最充分。

### CVE-2022-44840

- **目标版本（no-match）**：2.24, 2.25, 2.26, 2.27, 2.28, 2.29, 2.30, 2.31, 2.31.1, 2.32, 2.34, 2.35, 2.35.1, 2.36
- **参考崩溃**：Reference CRASH: ASAN:heap-buffer-overflow in find_section_in_set at ../../binutils/readelf.c:1001
- **目标基线**：Target:    no crash
- **定位到的 fork**：[*] Fork: /tmp/retro_CVE-2022-44840_r3_2633577_1795141015/fork_analysis_u_w3rmjo/target/binutils/readelf.c:18397
- **fork 变量**：[*] Variables: ['dump_sects', 'cmdline.dump_sects']
- **根因函数**：Root cause function: process_object
- **变异证据（代表版本 2.29）**：阶段 {'b': 1, 'e': 1, 'g': 1, 'f': 2, 'c': 1, 'd': 1, 'h': 4}，候选约 56539；no_crash=17933、fork_flip=37406、same_type=0、different_type=0；gdb_fail=1、fallback=0、not_reached=1、code_change=0
- **最后位置**：[*] Testing pair 0x12c+0x130 (original=8c,17)...
- **归类：2a（次要 1）**
- **源码核对**：`find_section_in_set`/readelf.c 目标 2.36 与参考 2.38 差 5 行，目标含 Section too small 检查。
- **原因**：目标 2.36 有 "Section is too small for 208 slots" 检查；参考 2.38 的 `_mul_overflow` 路径存在但条件不同。14 个目标版本全部 no-match。
- **备注/置信度**：文档：路径存在但条件不同。

### CVE-2023-1972

- **目标版本（no-match）**：2.25, 2.26, 2.27, 2.28, 2.29, 2.30, 2.31, 2.31.1, 2.32, 2.34, 2.35, 2.35.1, 2.36, 2.38
- **参考崩溃**：Reference CRASH: ASAN:heap-buffer-overflow in _bfd_elf_print_private_bfd_data at ../../bfd/elf.c:1844
- **目标基线**：Target:    no crash
- **定位到的 fork**：[*] Fork: ../../binutils/objdump.c:696
- **fork 变量**：[*] Variables: ['storage', 'failed', 'to', 'read', 'symbol', 'table', 'from', 'abfd']
- **根因函数**：Root cause function: slurp_symtab
- **变异证据（代表版本 2.32）**：阶段 {'b': 2, 'e': 2, 'g': 2, 'f': 4, 'c': 2, 'd': 2, 'h': 4}，候选约 180726；no_crash=77691、fork_flip=101835、same_type=0、different_type=0；gdb_fail=0、fallback=0、not_reached=0、code_change=0
- **最后位置**：[*] Testing pair 0x3e+0x4d98 (original=25,30)...
- **归类：2a（次要 1）**
- **源码核对**：`elf.c` 目标 2.38 增加 `if (s->size < extdynsize) goto error_return` 等检查（与 2.40 差 13 行）；2.25 差 44 行。
- **原因**：目标 2.38 仍拒绝 `hdr->sh_info==0` 并保留 `bfd_alloc/amt` 检查；参考 2.40 改为 `bfd_zalloc`。14 个目标版本 no-match。
- **备注/置信度**：文档：路径存在但条件不同。

### CVE-2023-3618

- **目标版本（no-match）**：3.9.3, 3.9.4, 3.9.5, 3.9.6, 4.0.0, 4.0.1, 4.0.2, 4.0.3, 4.0.4, 4.0.4beta, 4.0.5
- **参考崩溃**：Reference CRASH: ASAN:SEGV in _TIFFmemcpy at /home/ws/Desktop/RetroScope/tiff-versions/tiff-4.5.0/libtiff/tif_unix.c:345
- **目标基线**：Target:    no crash
- **定位到的 fork**：[*] Fork: /home/ws/Desktop/RetroScope/tiff-versions/tiff-3.9.5/tools/tiffcrop.c:2020
- **fork 变量**：[*] Variables: ['opt_ptr', 'i', 'opt_offset']
- **根因函数**：Root cause function: N/A
- **变异证据（代表版本 3.9.5）**：阶段 {'b': 1, 'e': 1, 'g': 1, 'f': 2, 'c': 1, 'd': 1, 'h': 4}，候选约 22595；no_crash=21357、fork_flip=38、same_type=0、different_type=0；gdb_fail=0、fallback=0、not_reached=0、code_change=0
- **最后位置**：[*] Testing pair 0x338+0x33c (original=01,30)...
- **归类：2a（次要 2b）**
- **源码核对**：`_TIFFmemcpy` 在 4.0.5/3.9.3 与参考仅格式差异；`Fax3Encode` 存在，崩溃依赖 tile/refline 状态。
- **原因**：`Fax3Encode` 在 3.9.5/4.1.0 等目标存在；完整阶段约 2.3 万候选，只有 no_crash/fork_flip；崩溃需要输出/瓦片写入的特定状态（原 issue 用 `/dev/null`），目标条件未满足。
- **备注/置信度**：函数存在，条件/状态不满足为主。

### CVE-2025-48071

- **目标版本（no-match）**：3.2.12
- **参考崩溃**：Reference CRASH: ASAN:heap-buffer-overflow in interleave at /home/ws/Desktop/openexr-versions/openexr-3.3.2/src/lib/OpenEXRCore/internal_zip.c:166
- **目标基线**：Target:    no crash
- **定位到的 fork**：[*] Fork: /home/ws/Desktop/RetroScope/openexr-versions/openexr-3.2.12/src/lib/OpenEXRCore/internal_zip.c:158
- **fork 变量**：[*] Variables: ['i', 'vOutSize']
- **根因函数**：Root cause function: interleave
- **变异证据（代表版本 3.2.12）**：阶段 {'h': 2}，候选约 0；no_crash=0、fork_flip=0、same_type=0、different_type=0；gdb_fail=2、fallback=1、not_reached=1、code_change=0
- **归类：2a（次要 1）**
- **源码核对**：`interleave` 在 3.2.12 与参考 3.3.2 完全相同（diff 0）；条件在 `undo_zip_impl` 的严格/宽松大小检查。
- **原因**：源码层面：3.2.12 要求 `actual_out_bytes == uncompressed_size`，3.3.0 放宽为 `comp_buf_size > actual_out_bytes`，目标严格检查会拒绝；本轮 GDB 回退、仅格式字段，未完成全搜索。
- **备注/置信度**：条件冲突明确，但流水线未完整执行。

### CVE-2026-15520

- **目标版本（no-match）**：0.12.4, 0.12.5, 0.13, 0.13.3
- **参考崩溃**：Reference CRASH: ASAN:heap-buffer-overflow in decompress_R2004_section at /home/ws/Desktop/libredwg-versions/libredwg-0.13.4/src/decode.c:1313
- **目标基线**：Target:    no crash
- **定位到的 fork**：[*] Fork: /home/ws/Desktop/RetroScope/libredwg-versions/libredwg-0.12.5/src/decode.c:1717
- **fork 变量**：[*] Variables: ['comp_data_size', 'dat->size', 'start_byte']
- **根因函数**：Root cause function: decompress_R2004_section
- **变异证据（代表版本 0.12.5）**：阶段 {'b': 10, 'e': 10, 'g': 10, 'f': 21, 'h': 4}，候选约 113196；no_crash=86091、fork_flip=15105、same_type=0、different_type=0；gdb_fail=0、fallback=0、not_reached=10、code_change=0
- **最后位置**：[*] Testing pair 0x4c8a+0x4c8b (original=00,00)...
- **归类：2a（次要 3）**
- **源码核对**：`decompress_R2004_section` 在 0.13.3/0.12.4 与参考差 225-227 行；函数存在，条件/路径不同。
- **原因**：目标 0.12.x/0.13.3：0.12.5 在 `decompress_R2004_section` 前拒绝/边界返回，0.13.3 的条件也不同；完整阶段约 11 万候选无 same_func。
- **备注/置信度**：路径存在但条件/状态不满足；0.12.5 更接近路径不完整。

### CVE-2026-86145

- **目标版本（no-match）**：10.00, 10.20, 10.30
- **参考崩溃**：Reference CRASH: ASAN:heap-buffer-overflow in internal_dfa_match at src/pcre2_dfa_match.c:677
- **目标基线**：Target:    no crash
- **定位到的 fork**：[*] Fork: /home/ws/Desktop/RetroScope/pcre2-versions/pcre2-pcre2-10.30/src/pcre2_dfa_match.c:519
- **fork 变量**：[*] Variables: ['end_code']
- **根因函数**：Root cause function: internal_dfa_match
- **变异证据（代表版本 10.30）**：阶段 {'f': 3, 'h': 4}，候选约 666；no_crash=0、fork_flip=0、same_type=0、different_type=0；gdb_fail=0、fallback=0、not_reached=0、code_change=0
- **归类：2a（次要 3）**
- **源码核对**：`internal_dfa_match` 在 10.30 与参考差 485 行；目标 10.30 的递归位置检查在崩溃前拒绝。
- **原因**：目标 10.30 对递归 DFA 报 `error -52: nested recursion...`，在到达 `internal_dfa_match` 越界写之前就拒绝；函数存在但条件冲突。日志只有 f/h 阶段、666 候选。
- **备注/置信度**：条件冲突/路径被门禁挡住。

### CVE-2026-9500

- **目标版本（no-match）**：0.12.5, 0.13, 0.13.3, 0.13.4
- **参考崩溃**：Reference CRASH: ASAN:SEGV in read_2004_compressed_section at /home/ws/Desktop/libredwg-versions/libredwg-6d6a339/src/decode.c:2181
- **目标基线**：Target:    no crash
- **定位到的 fork**：[*] Fork: decode.c:2181
- **fork 变量**：[*] Variables: ['max_num', 'c', 'sec_dat']
- **根因函数**：Root cause function: read_2004_compressed_section
- **变异证据（代表版本 0.13）**：阶段 {'b': 10, 'e': 10, 'g': 10, 'f': 21, 'h': 4}，候选约 151846；no_crash=86272、fork_flip=53574、same_type=0、different_type=0；gdb_fail=0、fallback=0、not_reached=0、code_change=0
- **最后位置**：[*] Testing pair 0x2db54+0x2db55 (original=00,00)...
- **归类：2a（次要 3）**
- **源码核对**：`read_2004_compressed_section` 在 0.13.4/0.12.5 存在，差 47-160 行；目标路径/条件不同。
- **原因**：参考崩溃只在 6d6a339；目标 0.12.4-0.13.4 的 `read_2004_compressed_section` 路径/条件不同。完整阶段约 15 万候选无 same_func。
- **备注/置信度**：偏向条件差异/旧版本路径不完整。

### CVE-2026-9502

- **目标版本（no-match）**：0.12.4, 0.12.5, 0.13, 0.13.3
- **参考崩溃**：Reference CRASH: ASAN:heap-buffer-overflow in decompress_R2004_section at /home/ws/Desktop/libredwg-versions/libredwg-0.13.4/src/decode.c:1313
- **目标基线**：Target:    no crash
- **定位到的 fork**：[*] Fork: /home/ws/Desktop/RetroScope/libredwg-versions/libredwg-0.12.5/src/decode.c:1717
- **fork 变量**：[*] Variables: ['comp_data_size', 'dat->size', 'start_byte']
- **根因函数**：Root cause function: decompress_R2004_section
- **变异证据（代表版本 0.12.5）**：阶段 {'b': 10, 'e': 10, 'g': 10, 'f': 21, 'h': 4}，候选约 109291；no_crash=97290、fork_flip=1、same_type=0、different_type=0；gdb_fail=0、fallback=0、not_reached=10、code_change=0
- **最后位置**：[*] Testing pair 0x2dcaa+0x2dcab (original=00,00)...
- **归类：2a（次要 3）**
- **源码核对**：`decompress_R2004_section` 在 0.13.3/0.12.4 差 225-227 行；函数存在，条件/路径不同。
- **原因**：目标 0.12.4/0.12.5/0.13/0.13.3：0.12.5 更早拒绝，`decompress_R2004_section` 存在但边界条件不同；完整阶段约 11 万候选无 same_func。
- **备注/置信度**：条件冲突/旧版本路径差异。

### CVE-2018-18088

- **目标版本（no-match）**：2.0, 2.0.1, 2.1, 2.1.1, 2.1.2, 2.2.0
- **参考崩溃**：Reference CRASH: ASAN:SEGV in imagetopnm at /home/ws/Desktop/RetroScope/openjpeg-versions/v2.3.0/src/bin/jp2/convert.c:2243
- **目标基线**：Target:    no crash
- **定位到的 fork**：[*] Fork: /home/ws/Desktop/RetroScope/openjpeg-versions/version.2.1.1/src/bin/jp2/opj_decompress.c:1322
- **fork 变量**：[*] Variables: ['l_codec', 'image', 'parameters.DA_x0', 'parameters.DA_y0', 'parameters.DA_x1', 'parameters.DA_y1']
- **根因函数**：Root cause function: main
- **变异证据（代表版本 2.1.1）**：阶段 {'f': 3, 'h': 4}，候选约 1021；no_crash=0、fork_flip=0、same_type=0、different_type=0；gdb_fail=0、fallback=0、not_reached=0、code_change=3
- **归类：2b（次要 1）**
- **源码核对**：`imagetopnm` 在 2.2.0 与参考 2.3.0 完全相同（diff 0），2.0 才差 630 行；最近目标的 no-match 更可能是搜索/偏移。
- **原因**：源码核对：最近目标 2.2.0 的 `imagetopnm` 与参考 2.3.0 完全相同（diff 0），2.0 才相差 630 行；因此 2.2.0 的 no-match 不是代码条件冲突，更可能是搜索/偏移未覆盖；2.0 另有路径差异。
- **备注/置信度**：版本相关；日志的 code_change 不能代表 2.2.0 的代码差异。

### CVE-2021-3575

- **目标版本（no-match）**：2.0, 2.0.1, 2.1, 2.1.1, 2.1.2, 2.2.0, 2.3.0
- **参考崩溃**：Reference CRASH: ASAN:heap-buffer-overflow in sycc420_to_rgb at /home/ws/Desktop/RetroScope/openjpeg-versions/v2.3.1/src/bin/common/color.c:379
- **目标基线**：Target:    no crash
- **定位到的 fork**：[*] Fork: /home/ws/Desktop/RetroScope/openjpeg-versions/v2.3.0/src/lib/openjp2/function_list.c:105
- **fork 变量**：[*] Variables: ['p_validation_list->m_nb_procedures']
- **根因函数**：Root cause function: opj_j2k_exec
- **变异证据（代表版本 2.3.0）**：阶段 {'b': 1, 'e': 1, 'g': 1, 'f': 3, 'h': 4}，候选约 7956；no_crash=6756、fork_flip=0、same_type=0、different_type=0；gdb_fail=0、fallback=0、not_reached=1、code_change=0
- **最后位置**：[*] Testing pair 0x38c+0x38d (original=00,02)...
- **归类：2b（次要 1）**
- **源码核对**：`sycc420_to_rgb` 在 2.3.0 与参考 2.3.1 完全相同（diff 0），2.0 差 179 行；最近目标 no-match 是搜索/状态。
- **原因**：完整阶段约 8 千候选，`sycc420_to_rgb` 在目标存在；fork 在 `opj_j2k_exec`，得到 no_crash/fork_flip，没有 same_func；需要更精确的组件/采样状态。
- **备注/置信度**：偏移/状态覆盖不足。

### CVE-2023-30775

- **目标版本（no-match）**：3.9.3, 3.9.4, 3.9.5, 3.9.6, 4.0.0, 4.0.1, 4.0.2, 4.0.3, 4.0.4, 4.0.4beta, 4.0.5
- **参考崩溃**：Reference CRASH: ASAN:heap-buffer-overflow in extractContigSamples32bits at /home/ws/Desktop/RetroScope/tiff-versions/tiff-4.4.0/tools/tiffcrop.c:3196
- **目标基线**：Target:    no crash
- **定位到的 fork**：[*] Fork: /home/ws/Desktop/RetroScope/tiff-versions/tiff-4.0.4beta/libtiff/tif_dirread.c:3423
- **fork 变量**：[*] Variables: ['tif', 'image.width', 'image.length', 'image.bps', 'image.spp', 'image.compression', 'image.photometric', 'image.orientation', 'image.planar', 'image.res_unit', 'crop.combined_width', 'crop.combined_length', 'crop.bufftotal', 'crop.zones', 'crop.selections', 'crop.edge_ref', 'crop.crop_mode']
- **根因函数**：Root cause function: TIFFReadDirectory
- **变异证据（代表版本 4.0.4beta）**：阶段 {'b': 2, 'e': 2, 'g': 2, 'f': 4, 'c': 2, 'd': 2, 'h': 4}，候选约 54958；no_crash=41168、fork_flip=816、same_type=385、different_type=11389；gdb_fail=0、fallback=0、not_reached=0、code_change=3
- **最后位置**：[*] Testing pair 0x158+0x15a (original=2a,a0)...
- **归类：2b（次要 2a）**
- **源码核对**：`extractContigSamples32bits` 在 4.0.5/3.9.3 存在，函数体差 35-39 行；路径存在，偏移/状态覆盖不足。
- **原因**：`extractContigSamples32bits` 在目标 4.0.6 存在；完整阶段约 5.5 万候选，出现 same_type/different_type 但没有 same_func；目标路径存在，偏移/状态组合不足。
- **备注/置信度**：TBD CVE，尚无更细文档结论。

### CVE-2024-34459

- **目标版本（no-match）**：2.9.0, 2.9.1, 2.9.2, 2.9.4
- **参考崩溃**：Reference CRASH: ASAN:heap-buffer-overflow in xmlHTMLPrintFileContext at /home/ws/Desktop/RetroScope/libxml2-versions/libxml2-2.9.5/xmllint.c:614
- **目标基线**：Target:    no crash
- **定位到的 fork**：[*] Fork: xmllint.c:614
- **fork 变量**：[*] Variables: ['cur', 'n']
- **根因函数**：Root cause function: xmlHTMLPrintFileContext
- **变异证据（代表版本 2.9.4）**：阶段 {'f': 3, 'c': 1, 'd': 1, 'h': 4}，候选约 20331；no_crash=19346、fork_flip=0、same_type=0、different_type=0；gdb_fail=0、fallback=0、not_reached=0、code_change=0
- **最后位置**：[*] Testing pair 0x11f+0x128 (original=3e,3c)...
- **归类：2b（次要 1）**
- **源码核对**：`xmlHTMLPrintFileContext` 在 2.9.4/2.9.0 与参考 2.9.5 完全相同（diff 0）；no-match 是搜索/状态，不是代码条件差异。
- **原因**：源码核对：`xmlHTMLPrintFileContext` 在 2.9.4/2.9.0 与参考 2.9.5 完全相同（diff 0）；no-match 不是函数/条件差异，而是搜索/状态未覆盖。
- **备注/置信度**：路径与崩溃函数相同，优先归 2b/1。

### CVE-2025-5915

- **目标版本（no-match）**：3.4.0, 3.4.3, 3.5.0, 3.5.3
- **参考崩溃**：Reference CRASH: ASAN:heap-buffer-overflow in copy_from_lzss_window at /home/ws/Desktop/RetroScope/libarchive-versions/v3.6.0/libarchive/archive_read_support_format_rar.c:3069
- **目标基线**：Target:    no crash
- **定位到的 fork**：[*] Fork: /home/ws/Desktop/RetroScope/libarchive-versions/v3.4.3/libarchive/archive_read.c:1115
- **fork 变量**：[*] Variables: ['a->bidders[i].free', 'a->bidders[i]', 'i']
- **根因函数**：Root cause function: _archive_read_free
- **变异证据（代表版本 3.4.3）**：阶段 {'b': 1, 'e': 1, 'g': 1, 'f': 4, 'h': 4}，候选约 14577；no_crash=13456、fork_flip=0、same_type=0、different_type=0；gdb_fail=0、fallback=0、not_reached=0、code_change=0
- **最后位置**：[*] Testing pair 0x24+0xd1 (original=00,40)...
- **归类：2b（次要 3）**
- **源码核对**：`copy_from_lzss_window` 在 3.5.3 与参考 3.6.0 差 53 行（签名从 const void** 到 void*，实现变化）。
- **原因**：目标 3.5.3 的 `copy_from_lzss_window` 签名/实现与 3.6.0 不同（`const void **` vs `void *`），RAR 解码路径已变化；完整阶段约 1.5 万候选无 same_func。
- **备注/置信度**：旧实现的路径/条件不同；偏移/状态覆盖不足为主，路径差异为辅。

### CVE-2026-23865

- **目标版本（no-match）**：2.8.1, 2.9.1, 2.10.4, 2.11.1, 2.12.1, 2.13.0
- **参考崩溃**：Reference CRASH: ASAN:SEGV in tt_var_get_item_delta at /tmp/retro_CVE-2026-23865_r3_2249401_1795164524/fork_analysis_9vvwaf6j/ref/src/truetype/ttgxvar.c:1053
- **目标基线**：Target:    no crash
- **定位到的 fork**：[*] Fork: /tmp/retro_CVE-2026-23865_r3_2249401_1795164524/fork_analysis_9vvwaf6j/target/src/truetype/ttgxvar.c:2277
- **fork 变量**：[*] Variables: ['n', 'mmvar->num_axis', 'num_axes']
- **根因函数**：Root cause function: ft_var_load_mvar
- **变异证据（代表版本 2.8.1）**：阶段 {'b': 1, 'e': 1, 'g': 1, 'f': 3, 'c': 1, 'd': 1, 'h': 4}，候选约 100226；no_crash=35286、fork_flip=63740、same_type=0、different_type=0；gdb_fail=0、fallback=0、not_reached=0、code_change=0
- **最后位置**：[*] Testing pair 0x154+0x158 (original=00,00)...
- **归类：2b（次要 3）**
- **源码核对**：`tt_var_get_item_delta` 在 2.8.1 未找到（路径缺失），2.13.0 存在且差 77 行；2.13.0 更像多字段状态/搜索。
- **原因**：源码核对：`tt_var_get_item_delta` 在目标 2.8.1 未找到（该版本路径不存在），2.13.0 存在且与参考差 77 行；2.13.0 的 no-match 更像多字段状态/搜索，2.8.1 偏路径缺失。
- **备注/置信度**：版本相关；完整阶段约 10 万候选。

### CVE-2026-50811

- **目标版本（no-match）**：2.9.1, 2.10.4, 2.11.1, 2.12.1, 2.13.0, 2.13.1, 2.13.2, 2.13.3
- **ERROR/排除**：2.8.1
- **参考崩溃**：Reference CRASH: ASAN:heap-buffer-overflow in TT_Get_Var_Design at /tmp/retro_CVE-2026-50811_r3_3956668_1795473105/fork_analysis_zurpfg91/ref/src/truetype/ttgxvar.c:3502
- **目标基线**：Target:    no crash
- **定位到的 fork**：[*] Fork: /tmp/retro_CVE-2026-50811_r3_3956668_1795473105/fork_analysis_s0hjzxug/target/src/truetype/ttobjs.c:1081
- **fork 变量**：[*] Variables: ['size', 'TT_Size', 'ftsize', 'memory', 'size->root.face']
- **根因函数**：Root cause function: tt_size_done_bytecode
- **变异证据（代表版本 2.13.3）**：阶段 {'b': 2, 'e': 2, 'g': 2, 'f': 4, 'c': 2, 'd': 2, 'h': 4}，候选约 160885；no_crash=46306、fork_flip=113379、same_type=0、different_type=0；gdb_fail=0、fallback=0、not_reached=0、code_change=0
- **最后位置**：[*] Testing pair 0x144+0x148 (original=00,00)...
- **归类：2b（次要 2a）**
- **源码核对**：`TT_Get_Var_Design` 在 2.9.1/2.13.3 存在，差 24-33 行；状态/偏移覆盖不足。
- **原因**：完整阶段约 16 万候选，目标 2.8.1-2.13.3 均无 same_func；freetype 设计空间/状态组合未覆盖，2.8.1 还有单独 ERROR。
- **备注/置信度**：多字段状态/偏移覆盖不足。

### CVE-2026-9605

- **目标版本（no-match）**：0.12.4, 0.12.5, 0.13, 0.13.3
- **参考崩溃**：Reference CRASH: ASAN:heap-buffer-overflow in bit_read_RC at /home/ws/Desktop/libredwg-versions/libredwg-0.13.4/src/bits.c:282
- **目标基线**：Target:    no crash
- **定位到的 fork**：[*] Fork: /home/ws/Desktop/RetroScope/libredwg-versions/libredwg-0.12.4/src/bits.c:316
- **fork 变量**：[*] Variables: ['byte', 'dat->chain', 'dat->byte', 'dat->chain[dat->byte]', 'dat']
- **根因函数**：Root cause function: dwg_version_hdr_type
- **变异证据（代表版本 0.12.4）**：阶段 {'b': 1, 'e': 1, 'g': 1, 'f': 2, 'h': 4}，候选约 51376；no_crash=12013、fork_flip=38265、same_type=0、different_type=0；gdb_fail=0、fallback=0、not_reached=1、code_change=0
- **最后位置**：[*] Testing pair 0x3d26+0x3d27 (original=00,00)...
- **归类：2b（次要 1）**
- **源码核对**：`bit_read_RC` 在 0.13.3 与参考完全相同（diff 0），0.12.4 差 23 行；0.13.3 的 no-match 是搜索/状态。
- **原因**：源码核对：目标 0.13.3 的 `bit_read_RC` 与参考 0.13.4 完全相同（diff 0），0.12.4 才差 23 行；因此 0.13.3 的 no-match 是搜索/状态（2b），不是代码条件差异。
- **备注/置信度**：版本相关。

### CVE-2016-10268

- **目标版本（no-match）**：3.9.3, 4.0.3, 4.0.4, 4.0.4beta
- **参考崩溃**：Reference CRASH: ASAN:heap-buffer-overflow in _tiffWriteProc at /home/ws/Desktop/RetroScope/tiff-versions/tiff-4.0.7/libtiff/tif_unix.c:115
- **目标基线**：Target:    no crash
- **定位到的 fork**：[*] Fork: tif_unix.c:115
- **fork 变量**：[*] Variables: ['count', 'fdh.fd', 'buf_offset', 'TIFFIOSize_t', 'io_size', 'image.width', 'image.length', 'image.bps', 'image.spp', 'image.compression', 'image.photometric', 'image.orientation', 'image.planar', 'image.res_unit', 'crop.combined_width', 'crop.combined_length', 'crop.bufftotal', 'crop.zones', 'crop.selections', 'crop.edge_ref', 'crop.crop_mode']
- **根因函数**：Root cause function: _tiffWriteProc
- **变异证据（代表版本 4.0.3）**：阶段 {'f': 3, 'c': 1, 'd': 1, 'h': 4}，候选约 107080；no_crash=33627、fork_flip=72257、same_type=9、different_type=0；gdb_fail=0、fallback=0、not_reached=0、code_change=0
- **最后位置**：[*] Testing pair 0xde+0xe2 (original=77,61)...
- **归类：3（次要 1）**
- **源码核对**：目标 3.9.3/4.0.3/4.0.4/4.0.4beta 的 `_tiffWriteProc` 为单次 write（无循环）；参考 4.0.7 为循环 write，崩溃行 115 在循环内。4.0.6 已有循环但本轮超时。
- **原因**：源码核对：目标 3.9.3/4.0.3/4.0.4/4.0.4beta 的 `_tiffWriteProc` 是单次 write，没有参考 4.0.7 的 `for (bytes_written...)` 循环写入；参考崩溃行 115 位于该循环内。no-match 的这几个目标缺少该循环（3）；4.0.6 已有循环但本轮超时，未计入 no-match。
- **备注/置信度**：版本相关：不能把 10268 统一归为“搜索问题”。

### CVE-2016-10269

- **目标版本（no-match）**：3.9.3, 3.9.4, 3.9.5, 3.9.6
- **参考崩溃**：Reference CRASH: ASAN:heap-buffer-overflow in _TIFFmemcpy at /home/ws/Desktop/RetroScope/tiff-versions/tiff-4.0.7/libtiff/tif_unix.c:340
- **目标基线**：Target:    no crash
- **定位到的 fork**：[*] Fork: /home/ws/Desktop/RetroScope/tiff-versions/tiff-3.9.6/libtiff/tif_close.c:116
- **fork 变量**：[*] Variables: ['tif', 'image.width', 'image.length', 'image.bps', 'image.spp', 'image.compression', 'image.photometric', 'image.orientation', 'image.planar', 'image.res_unit', 'crop.combined_width', 'crop.combined_length', 'crop.bufftotal', 'crop.zones', 'crop.selections', 'crop.edge_ref', 'crop.crop_mode']
- **根因函数**：Root cause function: N/A
- **变异证据（代表版本 3.9.6）**：阶段 {'b': 1, 'e': 1, 'g': 1, 'f': 2, 'c': 1, 'd': 1, 'h': 4}，候选约 167055；no_crash=51458、fork_flip=114395、same_type=2、different_type=0；gdb_fail=0、fallback=0、not_reached=0、code_change=0
- **最后位置**：[*] Testing pair 0xde+0xe2 (original=00,00)...
- **归类：3（次要 2b）**
- **源码核对**：`_TIFFmemcpy` 在 3.9.6/3.9.3 与参考基本一致（diff 2 行）；问题在 PixarLog/压缩解码路径，不在 memcpy 实现。
- **原因**：目标 3.9.3-3.9.6 缺少 PixarLog 解码→写路径（文档记录：缺 PixarLog 时原 PoC 返回 rc=1），`_TIFFmemcpy` 虽存在但完整漏洞路径不完整；4.0.0-4.0.6 会 baseline 触发，未作为 no-match 目标。
- **备注/置信度**：路径不完整为主，变异搜索为辅。

### CVE-2017-14151

- **目标版本（no-match）**：2.0, 2.0.1, 2.1
- **参考崩溃**：Reference CRASH: ASAN:heap-buffer-overflow in opj_mqc_byteout at /home/ws/Desktop/RetroScope/openjpeg-versions/version.2.2.0/src/lib/openjp2/mqc.c:198
- **目标基线**：Target:    no crash
- **定位到的 fork**：[*] Fork: /home/ws/Desktop/RetroScope/openjpeg-versions/version.2.0.1/src/bin/jp2/opj_compress.c:1554
- **fork 变量**：[*] Variables: ['version']
- **根因函数**：Root cause function: main
- **变异证据（代表版本 2.0.1）**：阶段 {'f': 3, 'h': 4}，候选约 315；no_crash=0、fork_flip=0、same_type=0、different_type=0；gdb_fail=0、fallback=0、not_reached=0、code_change=3
- **归类：3（次要 1）**
- **源码核对**：`opj_mqc_byteout` 在 2.0/2.1 存在（grep 确认），但目标缺 `opj_tcd_code_block_enc_allocate_data`，完整调用链不成立。
- **原因**：目标 2.0/2.0.1/2.1 不含 `opj_tcd_code_block_enc_allocate_data`，参考 2.2.0 的 `opj_mqc_byteout` 溢出调用链在目标不完整；日志只有 315 候选、code_change fork。
- **备注/置信度**：文档归为格式门禁，但源码显示完整漏洞链在目标不成立；原 PoC 在 2.0/2.1 更早失败。

### CVE-2017-5505

- **目标版本（no-match）**：1.900.8, 1.900.9, 1.900.10, 1.900.11, 1.900.12, 1.900.13, 1.900.14, 1.900.15, 1.900.16, 1.900.17, 1.900.18, 1.900.19
- **参考崩溃**：Reference CRASH: ASAN:SEGV in jas_matrix_asl at /home/ws/Desktop/RetroScope/jasper-versions/jasper-version-1.900.27/src/libjasper/base/jas_seq.c:376
- **目标基线**：Target:    no crash
- **定位到的 fork**：[*] Fork: jas_seq.c:352
- **fork 变量**：[*] Variables: ['j', 'matrix->numcols_', 'rowstart', 'data']
- **根因函数**：Root cause function: jas_matrix_asl
- **变异证据（代表版本 1.900.8）**：阶段 {'b': 1, 'e': 1, 'g': 1, 'f': 3, 'h': 4}，候选约 12303；no_crash=11103、fork_flip=0、same_type=0、different_type=0；gdb_fail=0、fallback=0、not_reached=0、code_change=0
- **最后位置**：[*] Testing pair 0x605+0xdbf (original=14,14)...
- **归类：3（次要 2a）**
- **源码核对**：`jas_matrix_asl` 在 1.900.8/1.900.19 与参考差 6-9 行；文档确认漏洞行为 1.900.25 才引入，函数存在≠漏洞路径存在。
- **原因**：`jas_matrix_asl` 在 1.900.24 已存在，但负 ROI shift 的漏洞行为实际在 1.900.25 才引入；目标 1.900.8-1.900.24 的完整触发路径不存在。
- **备注/置信度**：文档：引入版本 1.900.25。

### CVE-2017-6851

- **目标版本（no-match）**：1.900.8, 1.900.9, 1.900.10, 1.900.11, 1.900.12, 1.900.13, 1.900.14, 1.900.15, 1.900.16, 1.900.17, 1.900.18, 1.900.19
- **参考崩溃**：Reference CRASH: ASAN:SEGV in jas_matrix_bindsub at /home/ws/Desktop/RetroScope/jasper-versions/jasper-version-2.0.10/src/libjasper/base/jas_seq.c:254
- **目标基线**：Target:    no crash
- **定位到的 fork**：[*] Fork: jpc_dec.c:401
- **fork 变量**：[*] Variables: ['ret']
- **根因函数**：Root cause function: jpc_dec_decode
- **变异证据（代表版本 1.900.13）**：阶段 {'b': 1, 'e': 1, 'g': 1, 'f': 3, 'h': 4}，候选约 9195；no_crash=7995、fork_flip=0、same_type=0、different_type=0；gdb_fail=0、fallback=0、not_reached=0、code_change=0
- **最后位置**：[*] Testing pair 0x141+0x142 (original=ff,ff)...
- **归类：3（次要 2a）**
- **源码核对**：`jas_matrix_bindsub` 在 1.900.8/1.900.19 与参考差 6 行；文档确认漏洞行为 1.900.25 才引入。
- **原因**：`jas_matrix_bindsub` 在目标 1.900.8-1.900.24 已存在，但漏洞行为在 1.900.25 才引入；目标版本完整路径不存在。
- **备注/置信度**：文档：引入版本 1.900.25。

### CVE-2025-26623

- **目标版本（no-match）**：0.27.7
- **参考崩溃**：Reference CRASH: ASAN:heap-use-after-free in Exiv2::Internal::TiffComponent::accept at /home/ws/Desktop/RetroScope/exiv2-versions/exiv2-0.28.4/src/tiffcomposite_int.cpp:622
- **目标基线**：Target:    no crash
- **定位到的 fork**：[*] Fork: /home/ws/Desktop/RetroScope/exiv2-versions/exiv2-0.27.7/src/exiv2.cpp:144
- **fork 变量**：[*] Variables: ['params.version_']
- **根因函数**：Root cause function: main
- **变异证据（代表版本 0.27.7）**：阶段 {'f': 3, 'c': 1, 'd': 1, 'h': 4}，候选约 136723；no_crash=74443、fork_flip=61128、same_type=0、different_type=0；gdb_fail=0、fallback=0、not_reached=0、code_change=0
- **最后位置**：[*] Testing pair 0x1f4+0x1f8 (original=3c,6f)...
- **归类：3（次要 2a）**
- **源码核对**：`TiffComponent::accept` 在 0.27.7 与 0.28.4 仅格式差异；UAF 来自 0.28 的 composite/TiffSubIfd 重写，需查 doAccept/析构路径；NVD 明确 <0.28 不受影响。
- **原因**：0.27.7 早于 0.28 的 TIFF composite 重写；NVD 明确 <0.28.0 不受影响，目标缺少 UAF 的完整实现路径。
- **备注/置信度**：文档：0.28.0 引入，0.27.7 不触发。

### CVE-2025-8176

- **目标版本（no-match）**：3.9.3, 3.9.4, 3.9.5, 3.9.6, 4.0.0, 4.0.1, 4.0.2, 4.0.3, 4.0.4, 4.0.4beta, 4.0.5, 4.0.6, 4.0.7, 4.0.8, 4.0.9, 4.0.10
- **参考崩溃**：Reference CRASH: ASAN:heap-use-after-free in quant_fsdither at /home/ws/Desktop/RetroScope/tiff-versions/tiff-4.7.0/tools/tiffmedian.c:952
- **目标基线**：Target:    no crash
- **定位到的 fork**：[*] Fork: /home/ws/Desktop/RetroScope/tiff-versions/tiff-3.9.3/libtiff/tif_dir.c:952
- **fork 变量**：[*] Variables: ['image.width', 'image.length', 'image.bps', 'image.spp', 'image.compression', 'image.photometric', 'image.orientation', 'image.planar', 'image.res_unit', 'crop.combined_width', 'crop.combined_length', 'crop.bufftotal', 'crop.zones', 'crop.selections', 'crop.edge_ref', 'crop.crop_mode']
- **根因函数**：Root cause function: TIFFGetField
- **变异证据（代表版本 3.9.3）**：阶段 {'b': 1, 'e': 1, 'g': 1, 'f': 4, 'c': 2, 'd': 2, 'h': 4}，候选约 93117；no_crash=40387、fork_flip=51469、same_type=0、different_type=61；gdb_fail=0、fallback=0、not_reached=0、code_change=0
- **最后位置**：[*] Testing pair 0x170+0x172 (original=03,0c)...
- **归类：3（次要 2b）**
- **源码核对**：4.7.0 在 `create_colorcell`/`quant_fsdither` 新增 `_TIFFfree(cell)`（4.7.0:831）及 ColorCells 释放（274/326），4.5.1 没有；UAF 路径未引入。
- **原因**：源码对比：4.7.0 在 `quant_fsdither`/`create_colorcell` 增加了 `_TIFFfree(cell)` 和 `ColorCells` 释放（4.5.1 没有），UAF 的完整路径在目标 4.5.1 及更早不存在；崩溃行虽在，释放/复用生命周期缺失。
- **备注/置信度**：14 个目标版本全部 no-match，符合“漏洞未引入”。

### CVE-2026-15184

- **目标版本（no-match）**：0.12.4, 0.12.5
- **参考崩溃**：Reference CRASH: ASAN:SEGV in dwg_next_entity at /home/ws/Desktop/libredwg-versions/libredwg-0.13.4/src/dwg.c:1233
- **目标基线**：Target:    no crash
- **定位到的 fork**：[*] Fork: /home/ws/Desktop/RetroScope/libredwg-versions/libredwg-0.12.5/src/dwg.c:1097
- **fork 变量**：[*] Variables: ['next', 'next->absolute_ref']
- **根因函数**：Root cause function: dwg_next_entity
- **变异证据（代表版本 0.12.5）**：阶段 {'b': 1, 'e': 1, 'g': 1, 'f': 3, 'h': 4}，候选约 4232；no_crash=3049、fork_flip=0、same_type=0、different_type=0；gdb_fail=0、fallback=0、not_reached=1、code_change=0
- **最后位置**：[*] Testing pair 0x15e+0xa8c9 (original=00,2f)...
- **归类：3（次要 2b）**
- **源码核对**：`dwg_next_entity` 在 0.12.5 与参考 0.13.4 差 15 行；0.13 才引入相关崩溃行为。
- **原因**：目标 0.12.5 早于 0.13 的 `dwg_next_entity` 崩溃路径/行为；完整阶段约 4 千候选无 same_func。
- **备注/置信度**：文档：0.13-0.13.4 触发，0.12.x 完整路径不存在。

### CVE-2026-9503

- **目标版本（no-match）**：0.12.5
- **参考崩溃**：Reference CRASH: ASAN:SEGV in dwg_next_entity at /home/ws/Desktop/libredwg-versions/libredwg-0.13.4/src/dwg.c:1233
- **目标基线**：Target:    no crash
- **定位到的 fork**：[*] Fork: /home/ws/Desktop/RetroScope/libredwg-versions/libredwg-0.12.5/src/dwg.c:1097
- **fork 变量**：[*] Variables: ['next', 'next->absolute_ref']
- **根因函数**：Root cause function: dwg_next_entity
- **变异证据（代表版本 0.12.5）**：阶段 {'b': 1, 'e': 1, 'g': 1, 'f': 3, 'h': 4}，候选约 2605；no_crash=1496、fork_flip=0、same_type=0、different_type=0；gdb_fail=0、fallback=0、not_reached=1、code_change=0
- **最后位置**：[*] Testing pair 0x617f0+0x617f1 (original=8c,01)...
- **归类：3（次要 2b）**
- **源码核对**：`dwg_next_entity` 0.12.5 与参考差 15 行；0.13 才引入崩溃行为。
- **原因**：目标 0.12.4/0.12.5 早于 0.13 的 `dwg_next_entity` 崩溃行为；完整阶段仅约 2.6 千候选，无 same_func。
- **备注/置信度**：文档：0.13-0.13.4 触发。

## 3. 关键源码/文档证据

- **CVE-2022-33034**：文档已给出代码级证明：参考 0.12.5 的 `read_file_header` 向 `copy_bytes` 传入 `sizeof(r2007_file_header)+1`（273 字节），目标 0.12.4 传 `0x110`（272 字节，恰为对象大小），`dst + length > dst_end` 守卫必然拒绝；两版 `copy_bytes` 函数体与守卫完全相同。因此目标 0.12.4 的 no-match 不是搜索问题，而是条件冲突（2a）。
- **CVE-2022-44840**：文档记录目标 2.36 有 "Section is too small for 208 slots" 检查；参考 2.38 的 `process_cu_tu_index` 改用 `_mul_overflow(nslots,12,&total)` 回归。路径存在但检查条件不同（2a）。
- **CVE-2023-1972**：文档记录目标 2.38 仍拒绝 `hdr->sh_info==0` 并保留 `bfd_alloc/amt` 检查；2.40 改成 `bfd_zalloc`（2a）。
- **CVE-2025-48071**：源码对比：3.2.12 的 `undo_zip_impl` 要求 `actual_out_bytes == uncompressed_size`；3.3.0 放宽为 `comp_buf_size > actual_out_bytes`；3.3.3 补回 `actual_out_bytes > uncompressed_size`。目标 3.2.12 的严格检查会拒绝原 PoC（2a）。
- **CVE-2025-8176**：源码对比：4.7.0 的 `tiffmedian.c` 在 `quant_fsdither`/`create_colorcell` 增加了 `_TIFFfree(cell)`（4.7.0 第 831 行）以及 `ColorCells`/`cell` 的释放（第 274/326 行），4.5.1 没有这些释放。目标 3.9.3-4.5.1 虽然保留 `quant_fsdither` 崩溃行，但 UAF 所需的“释放后再次使用”生命周期不存在（3）。
- **CVE-2017-5505 / CVE-2017-6851**：文档记录两个漏洞实际在 JasPer 1.900.25 才引入；目标 1.900.8-1.900.24 中 `jas_matrix_asl`/`jas_matrix_bindsub` 函数本身存在，但触发漏洞的行为/路径不存在（3）。
- **CVE-2025-26623**：NVD 明确 `<0.28.0`（如 0.27.7）不受影响；0.28.0 的 TIFF composite 重写引入 UAF，目标 0.27.7 缺少该实现路径（3）。
- **CVE-2016-10269 / CVE-2016-10270**：文档记录 3.9.x 缺 PixarLog 时原 PoC 返回 rc=1；3.9.x 在 `TIFFFillStrip` 前报 `MissingRequired: TileOffsets`。目标函数存在但完整解码/写路径不完整（10269→3，10270 更偏门禁→1/3）。
- **CVE-2026-15184 / CVE-2026-9503**：文档版本扫描显示 0.13-0.13.4 触发，0.12.x 不触发；`dwg_next_entity` 在 0.12.5 存在但崩溃行为/路径未引入（3）。
- **CVE-2026-9504**：文档记录 9504 样本直到 6d6a339 才在 `bit_convert_TU` 触发；0.13.3/0.12.x 不触发该函数路径（3），且本轮 GDB 回退（1）。

## 4. 日志判读说明

- `no_crash(unchanged)`：目标行为与基线一致，变异没有改变目标执行结果。
- `fork_flip(behavior changed)`：变异改变了目标行为，但没有造成与参考同函数/同类型的崩溃；说明变异能影响 fork/状态，但还差最后的触发条件。
- `same_type`：目标在**其他位置**崩了，类型与参考相同但函数/语句不同；不计为 same_func，因此仍是 no-match（典型如 CVE-2022-33034 的 226 条 SEGV @ dxfb_header_write）。
- `gdb_fail/fallback`：GDB fork 未定位，流程只跑 Step 6h 格式字段；这类 no-match 不是“搜索过但失败”，而是“流程没完整跑完”，应优先复测。
- `code_change`：参考与目标的 fork 位置是代码变更点（函数/分支/语句不同），此时输入变异很难对齐，优先按条件/路径差异分析。

## 5. 重点结论与后续建议

- **条件冲突（2a）证据最硬**：CVE-2022-33034（守卫数学）、CVE-2022-44840（Section slots 检查）、CVE-2023-1972（sh_info/bfd_alloc）、CVE-2025-48071（严格解压大小检查）、CVE-2026-86145（递归 DFA 门禁）。这些不是“没搜到”，而是目标版本在到达崩溃点前/处必然拒绝。
- **路径不完整/代码路径差异（3）**：CVE-2016-10268（目标 <=4.0.4beta 缺参考的循环 write）、CVE-2016-10269（PixarLog）、CVE-2017-5505/6851（1.900.25 才引入）、CVE-2017-14151（缺 allocate_data）、CVE-2025-26623（0.28 重写才引入）、CVE-2025-8176（4.7.0 才加入 free/UAF 路径）、CVE-2026-9503/15184（0.13 才引入）；CVE-2016-10270 更偏门禁（1/3）。
- **搜索/覆盖不足（1/2b）**：CVE-2016-10270、CVE-2017-7597、CVE-2017-14939、CVE-2018-18088（最近目标函数与 ref 相同）、CVE-2021-3575（2.3.0 函数与 ref 相同）、CVE-2023-30775、CVE-2024-34459（函数与 ref 完全相同）、CVE-2025-5915、CVE-2026-23865（2.13.0 函数存在）、CVE-2026-50811、CVE-2026-9605（0.13.3 函数与 ref 相同）等；这些目标路径存在，但候选数很大仍无 same_func，需要更强的字段级/状态引导变异，而不是继续盲目加随机候选。
- **流程回退导致 no-match 不具结论性**：CVE-2016-9572、issue908、CVE-2025-48071、CVE-2025-8177、CVE-2026-9504 的 GDB fork 未定位，只跑了 Step 6h；这些应优先修复/手工指定 fork 后复测，再判断 2a/2b/3。
- **下一步**：对 2a 类不再投入无结构变异；对 2b 类优先做字段级/跨字段状态变异并限制预算；对 3 类换更老/更接近引入点的目标版本或明确标记“不可变异”；对回退类先修 GDB/rr 再跑。
- 注意：本快照仍有 113 个 pair 未完成；后续若有版本转 MATCH，本文件对应条目的结论需要更新。
