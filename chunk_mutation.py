#!/usr/bin/env python3
"""chunk_mutation.py - 分块变异法定位分叉变量对应的输入文件偏移

原理：大文件先按块翻转，找到有影响的块后再逐字节细化。
对 10,000 字节文件只需 ~200 次 GDB 运行（而非 10,000 次）。

用法:
    python3 chunk_mutation.py \
        --binary tiff-versions/tiff-4.0.8/tools/.libs/tiffcrop \
        --fork-file tools/tiffcrop.c --fork-line 3369 \
        --variables 'src[0]' 'src[1]' 'src[2]' 'src[3]' buff1 \
        --input in/CVE-2022-3570 \
        --args -Z 1:4,3:3 -R 90 -H 300 -i {input_file} /tmp/foo
"""

import subprocess
import tempfile
import os
import sys
import argparse
import time
from multiprocessing import Pool, cpu_count


def resolve_binary(binary):
    if not os.path.isfile(binary):
        return binary
    with open(binary, 'rb') as f:
        first = f.readline()
    if first.startswith(b'#!'):
        d = os.path.dirname(binary)
        candidate = os.path.join(d, '.libs', os.path.basename(binary))
        if os.path.isfile(candidate):
            return candidate
    return binary


def get_variable_values(binary, fork_spec, variables, input_file,
                        run_args_list, timeout=15):
    """运行一次程序，返回分叉语句处各变量的值。"""
    resolved_args = []
    for a in run_args_list:
        resolved_args.append(
            a.replace('{input_file}', input_file)
             .replace('{input}', input_file))
    run_args_str = ' '.join(resolved_args)

    fd, log_file = tempfile.mkstemp(suffix='.log', prefix='mut_')
    os.close(fd)

    var_printfs = []
    for v in variables:
        var_printfs.append(f'  printf "VAR {v}=%d\\n", (unsigned long){v}')

    script = f"""set pagination off
set confirm off
set print finish off
set logging file {log_file}
set logging overwrite on
set logging enabled on
break {fork_spec}
commands
  silent
  printf "FORK_HIT\\n"
{chr(10).join("  " + p for p in var_printfs)}
  set logging enabled off
  quit
end
set disable-randomization off
run {run_args_str}
"""
    fd2, script_file = tempfile.mkstemp(suffix='.gdb', prefix='mut_')
    os.close(fd2)
    with open(script_file, 'w') as f:
        f.write(script)

    try:
        subprocess.run(
            ['gdb', '-batch', '-nx', '-q', '-x', script_file, '--', binary],
            capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        os.unlink(script_file)
        os.unlink(log_file)
        return None
    finally:
        os.unlink(script_file)

    if not os.path.isfile(log_file):
        return None
    with open(log_file) as f:
        log_text = f.read()
    os.unlink(log_file)

    if 'FORK_HIT' not in log_text:
        return None

    values = {}
    for line in log_text.split('\n'):
        line = line.strip()
        if line.startswith('VAR '):
            parts = line.split('=', 1)
            if len(parts) == 2:
                try:
                    values[parts[0].replace('VAR ', '')] = int(parts[1])
                except ValueError:
                    pass
    return values


def _test_chunk(args):
    """并行工作函数：翻转一个块并检测变量变化。"""
    (start, end, original_data, tmp_path,
     binary, fork_spec, variables, program_args, timeout) = args

    mutated = bytearray(original_data)
    for i in range(start, min(end, len(mutated))):
        mutated[i] ^= 0xFF

    with open(tmp_path, 'wb') as f:
        f.write(mutated)

    run_parts = [a.replace('{input_file}', tmp_path).replace('{input}', tmp_path)
                 for a in program_args]

    values = get_variable_values(binary, fork_spec, variables, tmp_path,
                                 run_parts, timeout)
    os.unlink(tmp_path)
    return start, end, values


def _test_byte(args):
    """并行工作函数：翻转单个字节。"""
    (i, original_data, tmp_path,
     binary, fork_spec, variables, program_args, timeout) = args

    mutated = bytearray(original_data)
    mutated[i] ^= 0xFF

    with open(tmp_path, 'wb') as f:
        f.write(mutated)

    run_parts = [a.replace('{input_file}', tmp_path).replace('{input}', tmp_path)
                 for a in program_args]

    values = get_variable_values(binary, fork_spec, variables, tmp_path,
                                 run_parts, timeout)
    os.unlink(tmp_path)
    return i, values


def run_analysis(binary, fork_file, fork_line, variables, input_file,
                 program_args=None, timeout=15, workers=None, chunk_size=None):
    """
    分块变异法：先按块测试，再对有影响的块逐字节细化。

    参数:
        chunk_size: 块大小（None=自动，根据文件大小调整）
    """
    from multiprocessing import cpu_count

    program_args = program_args or []
    real_binary = resolve_binary(binary)
    fork_spec = f'{fork_file}:{fork_line}'
    n_workers = workers or min(cpu_count(), 8)

    with open(input_file, 'rb') as f:
        original = bytearray(f.read())
    file_size = len(original)
    print(f'[*] 输入文件: {input_file} ({file_size} 字节)')

    # 自动确定块大小
    if chunk_size is None:
        if file_size <= 500:
            chunk_size = 1     # 小文件逐字节
        elif file_size <= 5000:
            chunk_size = 10    # 中等文件 10 字节一块
        else:
            chunk_size = 50    # 大文件 50 字节一块
    print(f'[*] 块大小: {chunk_size}, 并行数: {n_workers}')

    # 获取基线
    print(f'[*] 获取基线变量值...')
    baseline = get_variable_values(real_binary, fork_spec, variables,
                                   input_file, program_args, timeout)
    if baseline is None:
        print('[!] 程序未到达分叉语句', file=sys.stderr)
        return {'error': 'baseline failed'}
    print(f'[*] 基线值: {baseline}')

    influenced = {v: [] for v in variables}
    total_runs = 0

    # ===== 第零轮：识别崩溃区域 =====
    print(f'\n[*] ===== 识别崩溃区域 =====')
    crash_blocks = set()
    test_blocks = [(i, min(i + chunk_size, file_size))
                   for i in range(0, file_size, chunk_size)]

    crash_tasks = []
    for start, end in test_blocks:
        fd, tmp = tempfile.mkstemp(suffix='.tif', prefix='crash_')
        os.close(fd)
        crash_tasks.append((start, end, bytes(original), tmp,
                            real_binary, fork_spec, variables,
                            list(program_args), timeout))

    crash_results = [None] * len(crash_tasks)
    crash_completed = [0]

    def crash_callback(result):
        start, end, values = result
        crash_completed[0] += 1
        idx = start // chunk_size
        crash_results[idx] = values

    pool_crash = Pool(processes=n_workers)
    try:
        for i, task in enumerate(crash_tasks):
            pool_crash.apply_async(_test_chunk, (task,),
                                   callback=crash_callback)
        pool_crash.close()
        pool_crash.join()
    finally:
        pool_crash.terminate()

    for i, vals in enumerate(crash_results):
        if vals is None:
            crash_blocks.add(i)
            start, end = test_blocks[i]
            print(f'    块 [{start:03d}-{end:03d}): 崩溃/超时', flush=True)

    print(f'[*] 崩溃块: {len(crash_blocks)}/{len(test_blocks)}')
    total_runs += len(test_blocks)

    # ===== 第一轮：分块测试（排除崩溃块） =====
    print(f'\n[*] ===== 第一轮：分块测试 =====')
    active_blocks = []
    live_blocks = [(s, e) for i, (s, e) in enumerate(test_blocks)
                   if i not in crash_blocks]
    print(f'[*] 可测试块: {len(live_blocks)}')

    live_tasks = []
    for start, end in live_blocks:
        fd, tmp = tempfile.mkstemp(suffix='.tif', prefix='chunk_')
        os.close(fd)
        live_tasks.append((start, end, bytes(original), tmp,
                           real_binary, fork_spec, variables,
                           list(program_args), timeout))

    live_results = [None] * len(live_tasks)
    live_completed = [0]

    def live_callback(result):
        start, end, values = result
        live_completed[0] += 1
        if live_completed[0] % 10 == 0:
            print(f'[*] 块进度: {live_completed[0]}/{len(live_tasks)}', flush=True)
        # 找到对应的块索引
        for idx, (s, e) in enumerate(live_blocks):
            if s == start and e == end:
                live_results[idx] = values
                break

    pool_live = Pool(processes=n_workers)
    try:
        for task in live_tasks:
            pool_live.apply_async(_test_chunk, (task,), callback=live_callback)
        pool_live.close()
        pool_live.join()
    finally:
        pool_live.terminate()

    for idx, vals in enumerate(live_results):
        if vals is None:
            continue
        start, end = live_blocks[idx]
        for v in variables:
            if v in vals and v in baseline and vals[v] != baseline[v]:
                active_blocks.append((start, end))
                print(f'    块 [{start:03d}-{end:03d}]: 影响 {v}', flush=True)
                break

    total_runs += len(live_tasks)
    print(f'[*] 发现 {len(active_blocks)} 个有影响的块')

    # ===== 第二轮：逐字节细化（排除崩溃字节） =====
    print(f'\n[*] ===== 第二轮：逐字节细化 =====')
    refine_bytes = []
    for start, end in active_blocks:
        refine_bytes.extend(range(start, end))
    print(f'[*] 需细化 {len(refine_bytes)} 个字节')

    tasks2 = []
    for i in refine_bytes:
        fd, tmp = tempfile.mkstemp(suffix='.tif', prefix='byte_')
        os.close(fd)
        tasks2.append((i, bytes(original), tmp,
                        real_binary, fork_spec, variables,
                        list(program_args), timeout))

    byte_results = [None] * len(tasks2)
    completed2 = [0]

    def byte_callback(result):
        i, values = result
        completed2[0] += 1
        if completed2[0] % 20 == 0:
            print(f'[*] 字节进度: {completed2[0]}/{len(refine_bytes)}', flush=True)
        # 找到对应的字节索引
        for idx, byte_i in enumerate(refine_bytes):
            if byte_i == i:
                byte_results[idx] = values
                break

    pool2 = Pool(processes=n_workers)
    try:
        for task in tasks2:
            pool2.apply_async(_test_byte, (task,), callback=byte_callback)
        pool2.close()
        pool2.join()
    finally:
        pool2.terminate()

    for idx, vals in enumerate(byte_results):
        if vals is None:
            continue  # 崩溃字节，跳过
        i = refine_bytes[idx]
        for v in variables:
            if v in vals and v in baseline and vals[v] != baseline[v]:
                influenced[v].append(i)
                break

    total_runs += len(refine_bytes)

    # 去重排序
    for v in influenced:
        influenced[v] = sorted(set(influenced[v]))

    return {
        'influential_offsets': influenced,
        'total_runs': total_runs,
        'baseline': baseline,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description='分块变异法：动态定位分叉变量对应的输入文件偏移')
    ap.add_argument('--binary',    required=True)
    ap.add_argument('--fork-file', required=True)
    ap.add_argument('--fork-line', required=True, type=int)
    ap.add_argument('--variables', required=True, nargs='+')
    ap.add_argument('--input',     required=True, help='输入文件路径')
    ap.add_argument('--timeout',   type=int, default=15)
    ap.add_argument('--workers',   type=int, default=None)
    ap.add_argument('--chunk-size', type=int, default=None,
                    help='块大小（默认自动）')
    ap.add_argument('--args',      nargs=argparse.REMAINDER, default=[],
                    help='程序参数（必须放最后，用 {input_file} 占位）')
    a = ap.parse_args()

    t0 = time.time()
    result = run_analysis(
        binary=a.binary, fork_file=a.fork_file, fork_line=a.fork_line,
        variables=a.variables, input_file=a.input,
        program_args=a.args, timeout=a.timeout,
        workers=a.workers, chunk_size=a.chunk_size)
    elapsed = time.time() - t0

    print(f'\n{"=" * 60}')
    if 'error' in result:
        print(f'  ERROR: {result["error"]}')
    else:
        all_offsets = set()
        for v, offs in result['influential_offsets'].items():
            hex_offsets = [f'0x{o:02x}' for o in offs]
            print(f'  {v}: {", ".join(hex_offsets) if hex_offsets else "(none)"}')
            all_offsets.update(offs)
        if all_offsets:
            sorted_all = sorted(all_offsets)
            print(f'\n  汇总: {", ".join(f"0x{o:02x}" for o in sorted_all)}')
        print(f'  总运行次数: {result["total_runs"]}')
        print(f'  耗时: {elapsed:.1f}s')
    print('=' * 60)


if __name__ == '__main__':
    main()
