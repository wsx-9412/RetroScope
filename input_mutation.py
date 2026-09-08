#!/usr/bin/env python3
"""input_mutation.py - 通过输入变异动态定位分叉变量对应的文件偏移

方法：逐字节修改输入文件，运行程序到分叉语句，比较变量值。
若变量值变化，则该字节影响分叉变量。

用法:
    python3 input_mutation.py \
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
import json
import shutil


def resolve_binary(binary):
    """跳过 libtool 包装脚本，找到真正的 ELF。"""
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


def make_gdb_script(fork_spec, variables, input_file, run_args, log_file):
    """生成 GDB 脚本：运行到分叉语句，记录所有变量值。"""
    var_printfs = []
    for v in variables:
        var_printfs.append(
            f'  printf "VAR {v}=%d\\n", (unsigned long){v}')

    return f"""set pagination off
set confirm off
set print finish off
set logging file {log_file}
set logging overwrite on
set logging enabled on

break {fork_spec}
commands
  silent
  printf "FORK_HIT\\n"
{chr(10).join('  ' + p for p in var_printfs)}
  set logging enabled off
  quit
end

set disable-randomization off
run {run_args}
"""


def get_variable_values(binary, fork_spec, variables, input_file, run_args_list,
                        timeout=30):
    """运行一次程序，返回分叉语句处各变量的值。"""
    # 替换占位符
    resolved_args = []
    for a in run_args_list:
        resolved_args.append(
            a.replace('{input_file}', input_file)
             .replace('{input}', input_file))
    run_args_str = ' '.join(resolved_args)

    fd, log_file = tempfile.mkstemp(suffix='.log', prefix='mut_')
    os.close(fd)

    script = make_gdb_script(fork_spec, variables, input_file, run_args_str, log_file)
    fd2, script_file = tempfile.mkstemp(suffix='.gdb', prefix='mut_')
    os.close(fd2)
    with open(script_file, 'w') as f:
        f.write(script)

    try:
        proc = subprocess.run(
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
                var_name = parts[0].replace('VAR ', '').strip()
                try:
                    values[var_name] = int(parts[1])
                except ValueError:
                    values[var_name] = parts[1]
    return values


def _test_single_byte(args):
    """并行工作函数：测试单个字节翻转的影响。"""
    (i, original_byte, tmp_path, original_data,
     binary, fork_spec, variables, program_args, timeout) = args

    mutated = bytearray(original_data)
    mutated[i] ^= 0xFF
    with open(tmp_path, 'wb') as f:
        f.write(mutated)

    run_parts = []
    for a in program_args:
        run_parts.append(a.replace('{input_file}', tmp_path)
                         .replace('{input}', tmp_path))

    values = get_variable_values(
        binary, fork_spec, variables, tmp_path, run_parts, timeout)
    return i, values


def _test_single_byte_worker(args):
    """并行工作函数：创建自己的临时文件。"""
    (i, original_data, binary, fork_spec, variables,
     program_args, timeout) = args

    fd, tmp_path = tempfile.mkstemp(suffix='.tif', prefix='mut_')
    os.close(fd)
    try:
        mutated = bytearray(original_data)
        mutated[i] ^= 0xFF
        with open(tmp_path, 'wb') as f:
            f.write(mutated)

        run_parts = []
        for a in program_args:
            run_parts.append(a.replace('{input_file}', tmp_path)
                             .replace('{input}', tmp_path))

        values = get_variable_values(
            binary, fork_spec, variables, tmp_path, run_parts, timeout)
        return i, values
    finally:
        os.unlink(tmp_path) if os.path.exists(tmp_path) else None


def run_analysis(binary, fork_file, fork_line, variables, input_file,
                 program_args=None, timeout=30, workers=None):
    """
    通过输入变异找到影响分叉变量的输入字节偏移。
    使用多进程并行加速。

    参数:
        binary:       ELF 二进制路径
        fork_file:    分叉语句所在源文件
        fork_line:    分叉语句行号
        variables:    要追踪的变量列表
        input_file:   输入文件路径
        program_args: 程序参数（用 {input_file} 占位）
        timeout:      每次运行超时（秒）
        workers:      并行进程数（默认 CPU 核数）

    返回:
        dict: {var: [offset1, offset2, ...]} 影响该变量的输入偏移
    """
    from multiprocessing import Pool, cpu_count

    program_args = program_args or []
    real_binary = resolve_binary(binary)
    fork_spec = f'{fork_file}:{fork_line}'

    # 读取原始输入
    with open(input_file, 'rb') as f:
        original = bytearray(f.read())
    file_size = len(original)
    print(f'[*] 输入文件: {input_file} ({file_size} 字节)')

    # 获取原始变量值（基线）
    print(f'[*] 获取基线变量值...')
    baseline = get_variable_values(
        real_binary, fork_spec, variables, input_file, program_args, timeout)
    if baseline is None:
        print('[!] 无法获取基线值（程序未到达分叉语句）', file=sys.stderr)
        return {'error': 'baseline failed'}

    print(f'[*] 基线值: {baseline}')

    # 跳过头部字节（通常导致崩溃）和末尾 padding
    skip_start = 0
    for i in range(min(16, file_size)):
        test_mut = bytearray(original)
        test_mut[i] ^= 0xFF
        fd, test_path = tempfile.mkstemp(suffix='.tif', prefix='mut_')
        os.close(fd)
        with open(test_path, 'wb') as f:
            f.write(test_mut)
        test_args = [a.replace('{input_file}', test_path) for a in program_args]
        val = get_variable_values(real_binary, fork_spec, variables, test_path, test_args, timeout=5)
        os.unlink(test_path)
        if val is not None:
            skip_start = i
            break
        skip_start = i + 1

    test_range = list(range(skip_start, file_size))
    print(f'[*] 需测试 {len(test_range)} 个偏移 (跳过头部 {skip_start} 字节)')

    # 创建临时文件用于并行测试
    # 每个进程需要自己的临时文件
    n_workers = workers or min(cpu_count(), 8)
    print(f'[*] 并行进程数: {n_workers}')

    influenced = {v: [] for v in variables}
    tested = [0]

    def _callback(result):
        i, values = result
        tested[0] += 1
        if tested[0] % 20 == 0 or tested[0] == len(test_range):
            print(f'[*] 已测试 {tested[0]}/{len(test_range)} 字节...', flush=True)
        if values is None:
            return
        for v in variables:
            if v in values and v in baseline:
                if values[v] != baseline[v]:
                    influenced[v].append(i)

    # 构建任务参数（每个任务用自己的临时文件）
    import atexit
    tasks = []
    tmp_files = []
    for i in test_range:
        fd, tmp_path = tempfile.mkstemp(suffix='.tif', prefix='mut_')
        os.close(fd)
        tmp_files.append(tmp_path)
        tasks.append((
            i, original[i], tmp_path, bytes(original),
            real_binary, fork_spec, variables, list(program_args), timeout
        ))

    # 并行执行
    pool = Pool(processes=n_workers)
    try:
        for task in tasks:
            pool.apply_async(_test_single_byte, (task,), callback=_callback)
        pool.close()
        pool.join()
    finally:
        pool.terminate()
        # 清理临时文件
        for f in tmp_files:
            os.unlink(f) if os.path.exists(f) else None

    return influenced


def main():
    ap = argparse.ArgumentParser(
        description='通过输入变异动态定位分叉变量对应的输入文件偏移')
    ap.add_argument('--binary',    required=True)
    ap.add_argument('--fork-file', required=True)
    ap.add_argument('--fork-line', required=True, type=int)
    ap.add_argument('--variables', required=True, nargs='+')
    ap.add_argument('--input',     required=True, help='输入文件路径')
    ap.add_argument('--args',      nargs=argparse.REMAINDER, default=[],
                    help='程序参数（用 {input_file} 占位）')
    ap.add_argument('--timeout',   type=int, default=30,
                    help='每次运行超时秒数')
    a = ap.parse_args()

    result = run_analysis(
        binary=a.binary, fork_file=a.fork_file, fork_line=a.fork_line,
        variables=a.variables, input_file=a.input,
        program_args=a.args, timeout=a.timeout)

    print('\n' + '=' * 60)
    if 'error' in result:
        print(f'  ERROR: {result["error"]}')
    else:
        for var, offsets in result.items():
            hex_offsets = [f'0x{o:02x}' for o in offsets]
            print(f'  {var}: {", ".join(hex_offsets) if hex_offsets else "(none)"}')
    print('=' * 60)


if __name__ == '__main__':
    main()
