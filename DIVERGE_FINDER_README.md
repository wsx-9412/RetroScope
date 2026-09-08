# Diverge Finder - 独立的分叉点查找程序

## 功能

这个程序可以找到导致两个版本程序执行路径不同的语句（分叉点）。

### 主要功能：
1. 分别用两个不同的输入文件运行同一个程序，获取函数调用轨迹
2. 对比两个轨迹找到函数调用分叉点
3. 用 GDB 逐步执行分叉函数（如果可能），或者分析源代码找到分叉点
4. 输出分叉点的详细信息

## 用法

```bash
python3 diverge_finder.py \
    --binary /path/to/binary \
    --input-a /path/to/input_a \
    --input-b /path/to/input_b \
    --args "-arg1 value1 -i {input} output_file" \
    --timeout 300 \
    --gdb-timeout 120 \
    --output /path/to/result.json
```

### 参数说明：

- `--binary`: 要测试的二进制文件路径
- `--input-a`: 第一个输入文件路径（参考版本）
- `--input-b`: 第二个输入文件路径（目标版本）
- `--args`: 程序参数模板，`{input}` 会被替换为输入文件路径
- `--timeout`: 程序执行超时时间（秒，默认300）
- `--gdb-timeout`: GDB 执行超时时间（秒，默认120）
- `-o, --output`: 输出 JSON 文件路径

## 示例

### 测试 libtiff 的 CVE-2022-3597

```bash
cd /home/ws/Desktop/RetroScope

python3 diverge_finder.py \
    --binary tiff-versions/tiff-4.0.8/tools/tiffcrop \
    --input-a in/CVE-2022-3597 \
    --input-b new-in/CVE-2022-3597-4-0-8 \
    --args "-Z 1:4,3:3 -R 90 -H 300 -i {input} /tmp/foo" \
    --timeout 60 \
    --gdb-timeout 60 \
    --output /tmp/result.json
```

### 输出示例

```
======================================================================
分析摘要
======================================================================
  最后一个匹配的函数: _TIFFfree
  分叉后第一个不同的函数: TIFFFetchStripThing
  实际分析的函数: TIFFFetchStripThing
  分叉文件: libtiff/tif_dirread.c
  分叉行号: 3749
  分叉描述: 在 TIFFReadDirectory 函数中，输入 A 处理 TIFFTAG_STRIPOFFSETS 标签，输入 B 处理其他标签
  根本原因: 两个输入文件的 TIFF 标签顺序或内容不同，导致处理路径分叉
  输出文件: /tmp/result.json
```

## 输出格式

输出的 JSON 文件包含以下信息：

```json
{
  "binary": "二进制文件路径",
  "input_a": "输入文件 A 路径",
  "input_b": "输入文件 B 路径",
  "args": "程序参数",
  "trace_a_length": 816,
  "trace_b_length": 1441,
  "trace_a": ["轨迹 A 的函数调用序列"],
  "trace_b": ["轨迹 B 的函数调用序列"],
  "divergence_function": "最后一个匹配的函数",
  "next_divergent_function": "分叉后第一个不同的函数",
  "analyzed_function": "实际分析的函数",
  "divergence_index_a": 788,
  "divergence_index_b": 788,
  "divergence_result": {
    "diverging_file": "分叉文件路径",
    "diverging_line": 3749,
    "line_text": "分叉行的内容",
    "description": "分叉描述",
    "root_cause": "根本原因"
  }
}
```

## 工作原理

1. **轨迹捕获**: 使用 `-finstrument-functions` 编译选项和 `functracer.so` 预加载库来捕获函数调用轨迹
2. **分叉点查找**: 比较两个轨迹，找到第一个不同的函数调用
3. **分叉分析**: 
   - 如果 GDB 能正常工作，逐步执行分叉函数找到导致分叉的语句
   - 如果 GDB 失败（程序崩溃），分析源代码找到分叉点

## 注意事项

1. 程序需要使用 `-finstrument-functions` 编译选项编译
2. 如果程序使用 ASan，GDB 可能会因为 LeakSanitizer 而失败
3. 对于崩溃的输入文件，GDB 可能无法到达断点，程序会回退到源代码分析

## 测试的 CVE

程序已经测试过以下 CVE：
- CVE-2022-3597
- CVE-2022-3627
- CVE-2022-3598
- 等等
