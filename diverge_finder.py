#!/usr/bin/env python3
"""
diverge_finder.py - 独立的分叉点查找程序

功能：
1. 分别用两个不同的输入文件运行同一个程序，获取函数调用轨迹
2. 对比两个轨迹找到函数调用分叉点
3. 进入分叉函数用 GDB 逐步执行找到导致路径不同的分叉语句

用法：
    python3 diverge_finder.py \
        --binary /path/to/tiffcrop \
        --input-a /path/to/in/CVE-2022-3597 \
        --input-b /path/to/new-in/CVE-2022-3597-4-0-8 \
        --args "-Z 1:4,3:3 -R 90 -H 300 -i {input} /tmp/foo" \
        --output /tmp/result.json
"""

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import List, Dict, Tuple, Optional, Set

BASE_DIR = Path(__file__).resolve().parent
FUNCTRACER_SO = BASE_DIR / "functracer.so"
NOISE_PREFIX = ('__', 'asan', '_ZN', '_ZSt')


class TraceNode:
    """函数调用节点"""
    __slots__ = ("name", "depth", "path", "is_enter", "count")

    def __init__(self, name: str, depth: int, path: tuple, is_enter: bool = True, count: int = 1):
        self.name = name
        self.depth = depth
        self.path = path
        self.is_enter = is_enter
        self.count = count

    def __repr__(self):
        prefix = ">" if self.is_enter else "<"
        if self.count > 1:
            return f"{prefix}{self.name}*{self.count}"
        return f"{prefix}{self.name}"


# ===========================================================================
# 轨迹捕获
# ===========================================================================

def resolve_real_binary(binpath: str) -> str:
    """解析 libtool 包装脚本到实际的 ELF 二进制文件"""
    binpath = Path(binpath).resolve()
    try:
        with open(binpath, 'rb') as f:
            head = f.read(64)
        if head.startswith(b'#!') or head.startswith(b'# '):
            real = binpath.parent / '.libs' / binpath.name
            if real.exists() and open(real, 'rb').read(4) == b'\x7fELF':
                return str(real)
    except Exception:
        pass
    return str(binpath)


def find_version_root(binary: str) -> Path:
    """从二进制文件向上查找版本根目录"""
    d = Path(binary).resolve().parent
    fallback = None
    for _ in range(5):
        if (d / ".build_ok").exists() or (d / "configure").exists():
            return d
        if fallback is None and (d / "CMakeLists.txt").exists():
            fallback = d
        if d.parent == d:
            break
        d = d.parent
    return fallback or Path(binary).resolve().parent.parent.parent


def collect_lib_dirs(binary: str) -> List[str]:
    """收集 .libs 目录用于 LD_LIBRARY_PATH"""
    root = find_version_root(binary)
    dirs = []
    seen = set()
    for d in sorted(root.rglob('.libs')):
        s = str(d)
        if s not in seen:
            seen.add(s)
            dirs.append(s)
    for p in Path(binary).resolve().parents:
        d = p / '.libs'
        if d.exists() and str(d) not in seen:
            seen.add(str(d))
            dirs.append(str(d))
    return dirs


def capture_function_trace(cmd: List[str], timeout: int = 300) -> List[TraceNode]:
    """运行程序并捕获函数调用轨迹"""
    out_file = tempfile.mktemp(prefix="diverge_", suffix=".log")
    env = os.environ.copy()

    preloads = []
    try:
        r = subprocess.run(["gcc", "-print-file-name=libasan.so"],
                           capture_output=True, text=True)
        if "libasan" in r.stdout.strip():
            preloads.append(r.stdout.strip())
    except Exception:
        pass
    preloads.append(str(FUNCTRACER_SO))

    libs = collect_lib_dirs(cmd[0])
    env.update({
        "LD_PRELOAD": ":".join(preloads),
        "FUNC_TRACE_OUT": out_file,
        "ASAN_OPTIONS": "detect_leaks=0:abort_on_error=1"
    })
    if libs:
        old_ld = env.get("LD_LIBRARY_PATH", "")
        env["LD_LIBRARY_PATH"] = ":".join(libs + ([old_ld] if old_ld else []))

    try:
        subprocess.run([str(c) for c in cmd], capture_output=True,
                       text=True, timeout=timeout, env=env)
    except subprocess.TimeoutExpired:
        pass
    except Exception as e:
        print(f"  [!] 执行失败: {e}", file=sys.stderr)

    # 解析轨迹文件
    base_map = {}
    last_module = None
    events = []

    try:
        for line in open(out_file):
            parts = line.split()
            if len(parts) >= 3 and parts[0] == 'M':
                try:
                    mpath = parts[2]
                    base_addr = int(parts[1], 16)
                    base_map[base_addr] = mpath
                    last_module = mpath
                except (IndexError, ValueError):
                    pass
            elif len(parts) == 2 and parts[0] in ('>', '<'):
                tok = parts[1]
                if tok.startswith('@') and last_module:
                    try:
                        offset = int(tok[1:], 16)
                        events.append((parts[0], ('local', last_module, offset)))
                        continue
                    except ValueError:
                        pass
                events.append((parts[0], tok))
    except FileNotFoundError:
        return []
    finally:
        try:
            os.unlink(out_file)
        except Exception:
            pass

    # 构建轨迹
    seq = []
    stack = []
    for d, tok in events:
        if isinstance(tok, tuple):
            name = resolve_local(tok[1], tok[2])
            if not name:
                continue
        else:
            name = tok
        if name.startswith(NOISE_PREFIX) or 'asan' in name.lower():
            continue
        if d == '>':
            node = TraceNode(name, len(stack), tuple(stack) + (name,), is_enter=True)
            # 循环折叠：检测 >A <A >A 模式
            if (len(seq) >= 2
                and not seq[-1].is_enter
                and seq[-2].is_enter
                and seq[-2].path == node.path
                and seq[-1].path == node.path):
                seq[-2].count += 1
                seq.pop()
            elif not seq or seq[-1].path != node.path or not seq[-1].is_enter:
                seq.append(node)
            stack.append(name)
        else:  # '<'
            if stack:
                stack.pop()
    return seq


_symcache = {}


def resolve_local(binpath: str, offset: int) -> Optional[str]:
    """从偏移量解析本地（静态）符号"""
    if binpath not in _symcache:
        syms = []
        try:
            r = subprocess.run(["nm", "--defined-only", "-n", str(binpath)],
                               capture_output=True, text=True)
            for line in r.stdout.split('\n'):
                parts = line.split(maxsplit=2)
                if len(parts) == 3 and all(c in '0123456789abcdef' for c in parts[0]):
                    syms.append((int(parts[0], 16), parts[2]))
        except Exception:
            pass
        _symcache[binpath] = syms
    syms = _symcache[binpath]
    if not syms:
        return None
    import bisect
    i = bisect.bisect_right([s[0] for s in syms], offset) - 1
    if i >= 0 and offset - syms[i][0] < 65536:
        return syms[i][1].split('(')[0]
    return None


# ===========================================================================
# LCS 分析（简化版）
# ===========================================================================

def longest_common_subsequence(a: list, b: list) -> list:
    """计算两个序列的最长公共子序列"""
    n, m = len(a), len(b)
    dp = [[0] * (m + 1) for _ in range(n + 1)]
    
    for i in range(1, n + 1):
        for j in range(1, m + 1):
            if a[i-1] == b[j-1]:
                dp[i][j] = dp[i-1][j-1] + 1
            else:
                dp[i][j] = max(dp[i-1][j], dp[i][j-1])
    
    # 回溯找到 LCS
    result = []
    i, j = n, m
    while i > 0 and j > 0:
        if a[i-1] == b[j-1]:
            result.append((i-1, j-1))
            i -= 1
            j -= 1
        elif dp[i-1][j] > dp[i][j-1]:
            i -= 1
        else:
            j -= 1
    
    result.reverse()
    return result


def find_divergence_point(trace_a: List[TraceNode], trace_b: List[TraceNode]) -> Tuple[int, int, str]:
    """
    找到两个轨迹的分叉点
    
    返回：(index_a, index_b, divergence_function)
    index_a, index_b 是最后一个能对齐的函数在各自轨迹中的位置
    divergence_function 是导致分叉的函数名
    """
    # 提取函数名序列
    names_a = [n.name for n in trace_a]
    names_b = [n.name for n in trace_b]
    
    # 使用 LCS 找到最长公共子序列
    lcs = longest_common_subsequence(names_a, names_b)
    
    if not lcs:
        return 0, 0, None
    
    # 找到 LCS 中最后一个匹配点
    last_match_idx_a, last_match_idx_b = lcs[-1]
    
    # 从最后一个匹配点开始，找到第一个分叉
    idx_a = last_match_idx_a + 1
    idx_b = last_match_idx_b + 1
    
    # 如果两个序列都还有剩余，找到分叉函数
    if idx_a < len(names_a) and idx_b < len(names_b):
        # 分叉函数是最后一个匹配的函数
        divergence_func = names_a[last_match_idx_a]
        return last_match_idx_a, last_match_idx_b, divergence_func
    elif idx_a < len(names_a):
        # A 还有剩余，B 已经结束
        divergence_func = names_a[last_match_idx_a]
        return last_match_idx_a, last_match_idx_b, divergence_func
    elif idx_b < len(names_b):
        # B 还有剩余，A 已经结束
        divergence_func = names_a[last_match_idx_a]
        return last_match_idx_a, last_match_idx_b, divergence_func
    else:
        # 两个序列完全相同，没有分叉
        return last_match_idx_a, last_match_idx_b, None


def find_divergence_point_simple(trace_a: List[TraceNode], trace_b: List[TraceNode]) -> Tuple[int, int, str, str]:
    """
    简化版分叉点查找：直接比较两个轨迹，找到第一个不同的函数调用
    
    返回：(index_a, index_b, divergence_func, analyze_func)
    - index_a, index_b: 最后一个匹配的函数在各自轨迹中的位置
    - divergence_func: 导致分叉的函数（最后一个匹配的函数）
    - analyze_func: 应该分析的函数（分叉发生的函数）
    
    逻辑说明：
    - 如果分叉后 A 和 B 调用不同的函数，那么分叉发生在 divergence_func 内部
    - 应该分析 divergence_func，而不是分叉后的函数
    """
    names_a = [n.name for n in trace_a]
    names_b = [n.name for n in trace_b]
    
    # 找到第一个不同的位置
    min_len = min(len(names_a), len(names_b))
    
    for i in range(min_len):
        if names_a[i] != names_b[i]:
            # 找到分叉点，返回分叉前最后一个相同的函数
            divergence_func = names_a[i - 1] if i > 0 else None
            # 分叉发生在 divergence_func 内部，应该分析这个函数
            analyze_func = divergence_func
            return i - 1, i - 1, divergence_func, analyze_func
    
    # 如果一个轨迹是另一个的前缀
    if len(names_a) != len(names_b):
        shorter_len = min(len(names_a), len(names_b))
        if shorter_len > 0:
            divergence_func = names_a[shorter_len - 1]
            # 分叉发生在 divergence_func 内部，应该分析这个函数
            analyze_func = divergence_func
            return shorter_len - 1, shorter_len - 1, divergence_func, analyze_func
    
    # 两个轨迹完全相同
    return len(names_a) - 1, len(names_b) - 1, None, None


# ===========================================================================
# GDB 逐步执行分析
# ===========================================================================

def find_source_dirs(binary: str) -> List[str]:
    """查找二进制文件的源代码目录"""
    root = find_version_root(binary)
    dirs = []
    for subdir in [root, root / "libtiff", root / "tools"]:
        if subdir.exists():
            dirs.append(str(subdir))
    return dirs


def run_gdb_step_through(binary: str, func_name: str, args: List[str],
                         source_dirs: List[str], timeout: int = 120) -> Dict:
    """
    用 GDB 逐步执行函数，找到导致分叉的语句
    
    返回：{
        'diverging_line': int,
        'diverging_file': str,
        'line_text': str,
        'variables': dict,  # 变量名 -> 值
        'trace': list  # 执行轨迹
    }
    """
    args_str = " ".join(str(a) for a in args)
    libs = collect_lib_dirs(binary)
    
    script = f"""set pagination off
set confirm off
set disable-randomization off
set environment ASAN_OPTIONS=detect_leaks=0:abort_on_error=1
set environment LSAN_OPTIONS=verbosity=0
run {args_str}
break {func_name}
continue
python
import gdb
import re

try:
    frame = gdb.selected_frame()
    pc = frame.pc()
    print("REACHED_FUNC:" + frame.name())
    
    # 获取函数源代码范围
    try:
        disasm = gdb.execute("disassemble {func_name}", to_string=True)
        addrs = re.findall(r'(0x[0-9a-f]+)', disasm)
        if addrs:
            func_start = int(addrs[0], 16)
            func_end = int(addrs[-1], 16) + 16
        else:
            func_start = 0
            func_end = 0xFFFFFFFFFFFFFFFF
    except:
        func_start = 0
        func_end = 0xFFFFFFFFFFFFFFFF
    
    # 记录执行的行和变量值
    lines_seen = []
    last_line = None
    step_count = 0
    max_steps = 5000
    
    while step_count < max_steps:
        try:
            frame = gdb.selected_frame()
            pc = frame.pc()
            if func_start > 0 and (pc < func_start or pc > func_end):
                break
            
            sal = gdb.find_pc_line(pc)
            if sal.line and sal.symtab:
                fname = sal.symtab.filename
                line_num = sal.line
                key = f"{{fname}}:{{line_num}}"
                
                if key != last_line:
                    # 获取当前行的变量值
                    vars_info = {{}}
                    try:
                        block = frame.block()
                        for sym in block:
                            name = sym.name or ''
                            if name.startswith('$') or name in ('__PRETTY_FUNCTION__',):
                                continue
                            try:
                                val = frame.read_var(name)
                                vars_info[name] = str(val)
                            except:
                                pass
                    except:
                        pass
                    
                    lines_seen.append({{
                        'file': fname,
                        'line': line_num,
                        'vars': vars_info
                    }})
                    last_line = key
        except gdb.error:
            pass
        
        try:
            gdb.execute("next", to_string=True)
        except gdb.error:
            try:
                gdb.execute("finish", to_string=True)
            except gdb.error:
                break
        step_count += 1
    
    print("EXEC_TRACE_START")
    for ln in lines_seen:
        vars_str = "|".join(f"{{k}}={{v}}" for k, v in ln['vars'].items())
        print(f"{{ln['file']}}:{{ln['line']}}:{{vars_str}}")
    print("EXEC_TRACE_END")
    print(f"STEP_COUNT:{{step_count}}")
    
except Exception as e:
    print(f"ERROR:{{e}}")
end
quit
"""
    
    # 写入 GDB 脚本
    fd, script_file = tempfile.mkstemp(suffix='.gdb', prefix='diverge_gdb_')
    os.close(fd)
    with open(script_file, 'w') as f:
        f.write(script)
    
    env = os.environ.copy()
    if libs:
        old_ld = env.get("LD_LIBRARY_PATH", "")
        env["LD_LIBRARY_PATH"] = ":".join(libs + ([old_ld] if old_ld else []))
    
    try:
        result = subprocess.run(
            ['gdb', '-batch', '-nx', '-q', '-x', script_file, '--', binary],
            capture_output=True, text=True, timeout=timeout, env=env
        )
        output = result.stdout + result.stderr
        
        # 调试：输出 GDB 的原始输出（只在失败时）
        if 'REACHED_FUNC' not in output:
            print(f"  [DEBUG] GDB 未到达目标函数")
    except subprocess.TimeoutExpired:
        return {'error': 'timeout'}
    finally:
        try:
            os.unlink(script_file)
        except:
            pass
    
    # 解析输出
    trace = []
    in_trace = False
    step_count = 0
    
    for line in output.split('\n'):
        if line.strip() == 'EXEC_TRACE_START':
            in_trace = True
            continue
        if line.strip() == 'EXEC_TRACE_END':
            in_trace = False
            continue
        if line.startswith('STEP_COUNT:'):
            try:
                step_count = int(line.split(':')[1])
            except:
                pass
            continue
        if in_trace:
            parts = line.split(':', 2)
            if len(parts) >= 2:
                try:
                    file_name = parts[0]
                    line_num = int(parts[1])
                    vars_str = parts[2] if len(parts) > 2 else ''
                    vars_dict = {}
                    if vars_str:
                        for var_pair in vars_str.split('|'):
                            if '=' in var_pair:
                                k, v = var_pair.split('=', 1)
                                vars_dict[k.strip()] = v.strip()
                    trace.append({
                        'file': file_name,
                        'line': line_num,
                        'vars': vars_dict
                    })
                except:
                    pass
    
    return {
        'trace': trace,
        'step_count': step_count,
        'binary': binary,
        'function': func_name
    }


def compare_execution_traces(trace_a: List[Dict], trace_b: List[Dict]) -> Optional[Dict]:
    """
    比较两个执行轨迹，找到第一个导致分叉的语句
    
    返回：{
        'diverging_line_a': int,
        'diverging_line_b': int,
        'diverging_file': str,
        'description': str
    }
    """
    if not trace_a or not trace_b:
        return None
    
    # 找到第一个不同的行
    min_len = min(len(trace_a), len(trace_b))
    
    for i in range(min_len):
        if trace_a[i]['line'] != trace_b[i]['line']:
            return {
                'diverging_line_a': trace_a[i]['line'],
                'diverging_line_b': trace_b[i]['line'],
                'diverging_file': trace_a[i]['file'],
                'description': f"第一个不同的行：A={trace_a[i]['line']}, B={trace_b[i]['line']}"
            }
    
    # 如果一个轨迹更长
    if len(trace_a) != len(trace_b):
        shorter_len = min(len(trace_a), len(trace_b))
        if shorter_len > 0:
            last_common = trace_a[shorter_len - 1]
            next_line_a = trace_a[shorter_len] if len(trace_a) > shorter_len else None
            next_line_b = trace_b[shorter_len] if len(trace_b) > shorter_len else None
            
            return {
                'diverging_line_a': last_common['line'],
                'diverging_line_b': last_common['line'],
                'diverging_file': last_common['file'],
                'description': f"轨迹长度不同：A有{len(trace_a)}行, B有{len(trace_b)}行"
            }
    
    return None


# ===========================================================================
# 主程序
# ===========================================================================

def main():
    ap = argparse.ArgumentParser(
        description="独立的分叉点查找程序：找到导致两个版本程序执行路径不同的语句"
    )
    
    ap.add_argument("--binary", required=True,
                    help="要测试的二进制文件路径")
    ap.add_argument("--input-a", required=True,
                    help="第一个输入文件路径（参考版本）")
    ap.add_argument("--input-b", required=True,
                    help="第二个输入文件路径（目标版本）")
    ap.add_argument("--args", required=True,
                    help="程序参数模板，{input} 会被替换为输入文件路径")
    ap.add_argument("--timeout", type=int, default=300,
                    help="程序执行超时时间（秒，默认300）")
    ap.add_argument("--gdb-timeout", type=int, default=120,
                    help="GDB 执行超时时间（秒，默认120）")
    ap.add_argument("-o", "--output", default=None,
                    help="输出 JSON 文件路径")
    
    args = ap.parse_args()
    
    # 解析二进制文件
    real_binary = resolve_real_binary(args.binary)
    print(f"[*] 二进制文件: {real_binary}")
    
    # 构建命令
    def build_cmd(input_file):
        cmd_args = args.args.replace(
            "{input}", str(Path(input_file).resolve())
        ).split()
        return [real_binary] + cmd_args
    
    cmd_a = build_cmd(args.input_a)
    cmd_b = build_cmd(args.input_b)
    
    print(f"[*] 输入文件 A: {args.input_a}")
    print(f"[*] 输入文件 B: {args.input_b}")
    print(f"[*] 命令 A: {' '.join(cmd_a)}")
    print(f"[*] 命令 B: {' '.join(cmd_b)}")
    
    # Step 1: 捕获函数调用轨迹
    print("\n" + "=" * 70)
    print("Step 1: 捕获函数调用轨迹")
    print("=" * 70)
    
    print("[*] 捕获轨迹 A...")
    trace_a = capture_function_trace(cmd_a, timeout=args.timeout)
    print(f"  轨迹 A 长度: {len(trace_a)}")
    
    print("[*] 捕获轨迹 B...")
    trace_b = capture_function_trace(cmd_b, timeout=args.timeout)
    print(f"  轨迹 B 长度: {len(trace_b)}")
    
    if not trace_a or not trace_b:
        print("[!] 无法捕获轨迹", file=sys.stderr)
        sys.exit(1)
    
    # Step 2: 找到分叉点
    print("\n" + "=" * 70)
    print("Step 2: 找到函数调用分叉点")
    print("=" * 70)
    
    idx_a, idx_b, divergence_func, analyze_func = find_divergence_point_simple(trace_a, trace_b)
    
    # 显示分叉后第一个不同的函数
    next_func_a = trace_a[idx_a + 1].name if idx_a + 1 < len(trace_a) else None
    next_func_b = trace_b[idx_b + 1].name if idx_b + 1 < len(trace_b) else None
    
    print(f"  分叉函数（最后一个匹配的函数）: {divergence_func}")
    print(f"  应该分析的函数（分叉发生的函数）: {analyze_func}")
    if next_func_a or next_func_b:
        print(f"  分叉后第一个不同的函数: A={next_func_a}, B={next_func_b}")
    print(f"  分叉位置: A[{idx_a}], B[{idx_b}]")
    
    # 显示分叉前的轨迹
    print(f"\n  分叉前的轨迹 (最后5个函数):")
    start_a = max(0, idx_a - 4)
    start_b = max(0, idx_b - 4)
    for i in range(start_a, idx_a + 1):
        print(f"    A[{i}]: {trace_a[i]}")
    for i in range(start_b, idx_b + 1):
        print(f"    B[{i}]: {trace_b[i]}")
    
    # 显示分叉后的轨迹
    if idx_a + 1 < len(trace_a) or idx_b + 1 < len(trace_b):
        print(f"\n  分叉后的轨迹:")
        if idx_a + 1 < len(trace_a):
            print(f"    A[{idx_a+1}]: {trace_a[idx_a+1]}")
        if idx_b + 1 < len(trace_b):
            print(f"    B[{idx_b+1}]: {trace_b[idx_b+1]}")
    
    if not divergence_func:
        print("[!] 两个轨迹完全相同，没有分叉", file=sys.stderr)
        sys.exit(0)
    
    # Step 3: 用 GDB 逐步执行分叉函数
    print("\n" + "=" * 70)
    print(f"Step 3: 用 GDB 逐步执行函数 {analyze_func}")
    print("=" * 70)
    
    source_dirs = find_source_dirs(real_binary)
    print(f"  源代码目录: {source_dirs}")
    
    # 对于输入 A
    print(f"\n[*] 执行轨迹 A ({args.input_a})...")
    exec_trace_a = run_gdb_step_through(
        real_binary, analyze_func, cmd_a[1:],
        source_dirs, timeout=args.gdb_timeout
    )
    
    # 对于输入 B
    print(f"[*] 执行轨迹 B ({args.input_b})...")
    exec_trace_b = run_gdb_step_through(
        real_binary, analyze_func, cmd_b[1:],
        source_dirs, timeout=args.gdb_timeout
    )
    
    if 'error' in exec_trace_a or 'error' in exec_trace_b:
        print(f"[!] GDB 执行失败: A={exec_trace_a.get('error')}, B={exec_trace_b.get('error')}", 
              file=sys.stderr)
        sys.exit(1)
    
    print(f"  轨迹 A 执行了 {exec_trace_a.get('step_count', 0)} 步")
    print(f"  轨迹 B 执行了 {exec_trace_b.get('step_count', 0)} 步")
    print(f"  轨迹 A 有 {len(exec_trace_a.get('trace', []))} 个不同的行")
    print(f"  轨迹 B 有 {len(exec_trace_b.get('trace', []))} 个不同的行")
    
    # Step 4: 比较执行轨迹，找到分叉语句
    print("\n" + "=" * 70)
    print("Step 4: 比较执行轨迹，找到分叉语句")
    print("=" * 70)
    
    divergence_result = compare_execution_traces(
        exec_trace_a.get('trace', []),
        exec_trace_b.get('trace', [])
    )
    
    if divergence_result:
        print(f"\n  分叉语句:")
        print(f"    文件: {divergence_result['diverging_file']}")
        print(f"    行号 (A): {divergence_result['diverging_line_a']}")
        print(f"    行号 (B): {divergence_result['diverging_line_b']}")
        print(f"    描述: {divergence_result['description']}")
    else:
        print("  未找到明显的分叉语句")
    
    # Step 5: 源代码分析（如果 GDB 失败）
    print("\n" + "=" * 70)
    print("Step 5: 源代码分析")
    print("=" * 70)
    
    # 查找分叉函数的源代码
    source_dirs = find_source_dirs(real_binary)
    divergence_result = None
    
    # 分叉发生在 analyze_func 内部
    # analyze_func 返回后，A 调用 next_func_a，B 调用 next_func_b
    # 所以要搜索 analyze_func 源码中调用 next_func_a 和 next_func_b 的位置
    # 如果 analyze_func 内部没有找到，就搜索其调用者
    if analyze_func:
        targets = [f for f in [next_func_a, next_func_b] if f]
        print(f"  分析函数: {analyze_func}")
        print(f"  分叉后调用: A={next_func_a}, B={next_func_b}")
        
        # 构建候选分析函数列表：analyze_func + 它的调用者
        candidates = [analyze_func]
        # 找调用 analyze_func 的父函数
        if idx_a > 0:
            for i in range(idx_a - 1, max(0, idx_a - 30), -1):
                if trace_a[i].is_enter and trace_a[i].name not in candidates:
                    candidates.append(trace_a[i].name)
                    if len(candidates) >= 5:
                        break
        # 特殊情况：如果分析的是简单函数，优先搜索调用它的大函数
        if analyze_func in ('TIFFReadDirectoryFindFieldInfo', '_TIFFfree', '_TIFFmalloc', '_TIFFmemcpy'):
            if 'TIFFReadDirectory' not in candidates:
                candidates.insert(1, 'TIFFReadDirectory')
        
        print(f"  候选分析函数: {candidates}")
        
        for candidate in candidates:
            if divergence_result:
                break
            for src_dir in source_dirs:
                if divergence_result:
                    break
                for root, dirs, files in os.walk(src_dir):
                    if divergence_result:
                        break
                    for f in files:
                        if divergence_result:
                            break
                        if f.endswith('.c') or f.endswith('.cpp'):
                            filepath = os.path.join(root, f)
                            try:
                                with open(filepath, 'r', errors='ignore') as sf:
                                    content = sf.read()
                                lines = content.split('\n')
                                
                                # 找到候选函数的函数体
                                func_start = None
                                func_end = None
                                for i, line in enumerate(lines):
                                    stripped = line.strip()
                                    if stripped.startswith('static') or stripped.endswith(';'):
                                        continue
                                    if re.search(rf'\b{re.escape(candidate)}\s*\(', line):
                                        brace_line = i
                                        while brace_line < len(lines) and '{' not in lines[brace_line]:
                                            brace_line += 1
                                        if brace_line < len(lines):
                                            func_start = brace_line
                                            depth = 0
                                            for j in range(brace_line, len(lines)):
                                                depth += lines[j].count('{') - lines[j].count('}')
                                                if depth == 0:
                                                    func_end = j
                                                    break
                                        break
                                
                                if func_start is not None and func_end is not None:
                                    # 在函数体内搜索目标函数调用
                                    all_findings = []
                                    for target in targets:
                                        for i in range(func_start, func_end + 1):
                                            if re.search(rf'\b{re.escape(target)}\s*\(', lines[i]):
                                                stripped = lines[i].strip()
                                                if stripped.startswith('static') or stripped.endswith(';'):
                                                    continue
                                                print(f"  在 {candidate}() 中找到调用 {target} (行 {i+1}): {stripped}")
                                                
                                                # 搜索附近的条件判断
                                                start_line = max(func_start, i - 20)
                                                end_line = min(func_end, i + 5)
                                                conditions = []
                                                for j in range(start_line, end_line):
                                                    near_line = lines[j].strip()
                                                    if re.match(r'\b(if|switch|else\s*if|case)\b', near_line):
                                                        conditions.append(f"行 {j+1}: {near_line}")
                                                        print(f"      条件判断: {near_line}")
                                                
                                                all_findings.append({
                                                    'target': target,
                                                    'line': i+1,
                                                    'text': stripped,
                                                    'conditions': conditions
                                                })
                                    
                                    if all_findings:
                                        # 使用最后一个找到的目标作为结果
                                        last = all_findings[-1]
                                        divergence_result = {
                                            'diverging_file': filepath,
                                            'diverging_line': last['line'],
                                            'line_text': last['text'],
                                            'all_findings': all_findings,
                                            'conditions': last['conditions'],
                                            'description': f'在 {candidate}() 中，分叉后 A 调用 {next_func_a}，B 调用 {next_func_b}'
                                        }
                            except:
                                pass
        
    if not divergence_result:
        print("  未找到源代码中的分叉点")
    
    # Step 6: 输出结果
    print("\n" + "=" * 70)
    print("Step 6: 输出结果")
    print("=" * 70)
    
    result = {
        'binary': args.binary,
        'input_a': args.input_a,
        'input_b': args.input_b,
        'args': args.args,
        'trace_a_length': len(trace_a),
        'trace_b_length': len(trace_b),
        'trace_a': [str(n) for n in trace_a],
        'trace_b': [str(n) for n in trace_b],
        'divergence_function': divergence_func,
        'analyzed_function': analyze_func,
        'divergence_index_a': idx_a,
        'divergence_index_b': idx_b,
        'next_func_a': next_func_a,
        'next_func_b': next_func_b,
        'exec_trace_a': exec_trace_a,
        'exec_trace_b': exec_trace_b,
        'divergence_result': divergence_result,
    }
    
    output_path = args.output or "/tmp/diverge_result.json"
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=2, ensure_ascii=False, default=str)
    
    print(f"\n  结果已保存到: {output_path}")
    
    # 打印摘要
    print("\n" + "=" * 70)
    print("分析摘要")
    print("=" * 70)
    print(f"  最后一个匹配的函数（分叉发生的函数）: {divergence_func}")
    print(f"  实际分析的函数: {analyze_func}")
    if next_func_a or next_func_b:
        print(f"  分叉后第一个不同的函数: A={next_func_a}, B={next_func_b}")
    if divergence_result:
        print(f"  分叉文件: {divergence_result.get('diverging_file')}")
        # 显示所有找到的调用位置
        all_findings = divergence_result.get('all_findings', [])
        if all_findings:
            print(f"  在源代码中找到的调用位置:")
            for finding in all_findings:
                print(f"    {finding['target']} 在行 {finding['line']}: {finding['text'][:80]}")
        print(f"  分叉描述: {divergence_result.get('description')}")
    print(f"  输出文件: {output_path}")


if __name__ == "__main__":
    main()
