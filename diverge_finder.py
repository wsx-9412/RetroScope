#!/usr/bin/env python3
"""
diverge_finder.py - standalone fork-point finder

Features:
1. Run the same program with two different input files and capture the function-call traces
2. Compare the two traces to find the function-call fork point
3. Enter the fork function and single-step with GDB to find the fork statement that diverges the paths

Usage:
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
    """Function-call node"""
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
# Trace capture
# ===========================================================================

def resolve_real_binary(binpath: str) -> str:
    """Resolve the libtool wrapper script to the real ELF binary"""
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
    """Walk up from the binary to find the version root directory"""
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
    """Collect .libs directories for LD_LIBRARY_PATH"""
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
    """Run the program and capture the function-call trace"""
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
        "ASAN_OPTIONS": "detect_leaks=0:abort_on_error=1:allocator_may_return_null=1"
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
        print(f"  [!] execution failed: {e}", file=sys.stderr)

    # Parse the trace file
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

    # Build the trace
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
            # Loop folding: detect the >A <A >A pattern
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
    """Resolve local (static) symbols from offsets"""
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
# LCS analysis (simplified)
# ===========================================================================

def longest_common_subsequence(a: list, b: list) -> list:
    """Compute the longest common subsequence of two sequences"""
    n, m = len(a), len(b)
    dp = [[0] * (m + 1) for _ in range(n + 1)]
    
    for i in range(1, n + 1):
        for j in range(1, m + 1):
            if a[i-1] == b[j-1]:
                dp[i][j] = dp[i-1][j-1] + 1
            else:
                dp[i][j] = max(dp[i-1][j], dp[i][j-1])
    
    # Backtrack to find the LCS
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
    Find the fork point of two traces
    
    Returns: (index_a, index_b, divergence_function)
    index_a, index_b are the positions of the last aligned function in each trace
    divergence_function is the name of the function that diverges
    """
    # Extract the function-name sequence
    names_a = [n.name for n in trace_a]
    names_b = [n.name for n in trace_b]
    
    # Find the longest common subsequence with LCS
    lcs = longest_common_subsequence(names_a, names_b)
    
    if not lcs:
        return 0, 0, None
    
    # Find the last matching point in the LCS
    last_match_idx_a, last_match_idx_b = lcs[-1]
    
    # Starting from the last matching point, find the first divergence
    idx_a = last_match_idx_a + 1
    idx_b = last_match_idx_b + 1
    
    # If both sequences have leftovers, find the divergence function
    if idx_a < len(names_a) and idx_b < len(names_b):
        # The divergence function is the last matched function
        divergence_func = names_a[last_match_idx_a]
        return last_match_idx_a, last_match_idx_b, divergence_func
    elif idx_a < len(names_a):
        # A has leftovers, B has ended
        divergence_func = names_a[last_match_idx_a]
        return last_match_idx_a, last_match_idx_b, divergence_func
    elif idx_b < len(names_b):
        # B has leftovers, A has ended
        divergence_func = names_a[last_match_idx_a]
        return last_match_idx_a, last_match_idx_b, divergence_func
    else:
        # The two sequences are identical, no divergence
        return last_match_idx_a, last_match_idx_b, None


def find_divergence_point_simple(trace_a: List[TraceNode], trace_b: List[TraceNode]) -> Tuple[int, int, str, str]:
    """
    Simplified fork-point search: compare the two traces directly and find the first differing function call
    
    Returns: (index_a, index_b, divergence_func, analyze_func)
    - index_a, index_b: positions of the last matched function in each trace
    - divergence_func: the function that diverges (the last matched function)
    - analyze_func: the function to analyze (where the divergence happens)
    
    Logic:
    - If A and B call different functions after the fork, the divergence happens inside divergence_func
    - Analyze divergence_func, not the functions called after the fork
    """
    names_a = [n.name for n in trace_a]
    names_b = [n.name for n in trace_b]
    
    # Find the first differing position
    min_len = min(len(names_a), len(names_b))
    
    for i in range(min_len):
        if names_a[i] != names_b[i]:
            # Found the fork point: return the last identical function before it
            divergence_func = names_a[i - 1] if i > 0 else None
            # The divergence happens inside divergence_func; analyze that function
            analyze_func = divergence_func
            return i - 1, i - 1, divergence_func, analyze_func
    
    # If one trace is a prefix of the other
    if len(names_a) != len(names_b):
        shorter_len = min(len(names_a), len(names_b))
        if shorter_len > 0:
            divergence_func = names_a[shorter_len - 1]
            # The divergence happens inside divergence_func; analyze that function
            analyze_func = divergence_func
            return shorter_len - 1, shorter_len - 1, divergence_func, analyze_func
    
    # The two traces are identical
    return len(names_a) - 1, len(names_b) - 1, None, None


# ===========================================================================
# GDB single-step analysis
# ===========================================================================

def find_source_dirs(binary: str) -> List[str]:
    """Find the source directory of the binary"""
    root = find_version_root(binary)
    dirs = []
    for subdir in [root, root / "libtiff", root / "tools"]:
        if subdir.exists():
            dirs.append(str(subdir))
    return dirs


def run_gdb_step_through(binary: str, func_name: str, args: List[str],
                         source_dirs: List[str], timeout: int = 120) -> Dict:
    """
    Single-step the function with GDB to find the statement causing the divergence
    
    Returns: {
        'diverging_line': int,
        'diverging_file': str,
        'line_text': str,
        'variables': dict,  # variable name -> value
        'trace': list  # execution trace
    }
    """
    args_str = " ".join(str(a) for a in args)
    libs = collect_lib_dirs(binary)
    
    script = f"""set pagination off
set confirm off
set disable-randomization off
set environment ASAN_OPTIONS=detect_leaks=0:abort_on_error=1:allocator_may_return_null=1
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
    
    # Get the function's source range
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
    
    # Record executed lines and variable values
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
                    # Get variable values at the current line
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
    
    # Write the GDB script
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
        
        # Debug: dump raw GDB output (only on failure)
        if 'REACHED_FUNC' not in output:
            print(f"  [DEBUG] GDB did not reach the target function")
    except subprocess.TimeoutExpired:
        return {'error': 'timeout'}
    finally:
        try:
            os.unlink(script_file)
        except:
            pass
    
    # Parse the output
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
    Compare two execution traces and find the first statement causing the divergence
    
    Returns: {
        'diverging_line_a': int,
        'diverging_line_b': int,
        'diverging_file': str,
        'description': str
    }
    """
    if not trace_a or not trace_b:
        return None
    
    # Find the first differing line
    min_len = min(len(trace_a), len(trace_b))
    
    for i in range(min_len):
        if trace_a[i]['line'] != trace_b[i]['line']:
            return {
                'diverging_line_a': trace_a[i]['line'],
                'diverging_line_b': trace_b[i]['line'],
                'diverging_file': trace_a[i]['file'],
                'description': f"first differing line: A={trace_a[i]['line']}, B={trace_b[i]['line']}"
            }
    
    # If one trace is longer
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
                'description': f"trace lengths differ: A has {len(trace_a)} lines, B has {len(trace_b)} lines"
            }
    
    return None


# ===========================================================================
# Main program
# ===========================================================================

def main():
    ap = argparse.ArgumentParser(
        description="Standalone fork-point finder: find the statement that makes the two program versions diverge"
    )
    
    ap.add_argument("--binary", required=True,
                    help="path to the binary under test")
    ap.add_argument("--input-a", required=True,
                    help="path to the first input file (reference version)")
    ap.add_argument("--input-b", required=True,
                    help="path to the second input file (target version)")
    ap.add_argument("--args", required=True,
                    help="program argument template; {input} is replaced by the input file path")
    ap.add_argument("--timeout", type=int, default=300,
                    help="program execution timeout in seconds (default 300)")
    ap.add_argument("--gdb-timeout", type=int, default=120,
                    help="GDB execution timeout in seconds (default 120)")
    ap.add_argument("-o", "--output", default=None,
                    help="output JSON file path")
    
    args = ap.parse_args()
    
    # Resolve the binary
    real_binary = resolve_real_binary(args.binary)
    print(f"[*] Binary: {real_binary}")
    
    # Build the commands
    def build_cmd(input_file):
        cmd_args = args.args.replace(
            "{input}", str(Path(input_file).resolve())
        ).split()
        return [real_binary] + cmd_args
    
    cmd_a = build_cmd(args.input_a)
    cmd_b = build_cmd(args.input_b)
    
    print(f"[*] Input file A: {args.input_a}")
    print(f"[*] Input file B: {args.input_b}")
    print(f"[*] Command A: {' '.join(cmd_a)}")
    print(f"[*] Command B: {' '.join(cmd_b)}")
    
    # Step 1: capture the function-call traces
    print("\n" + "=" * 70)
    print("Step 1: capture the function-call traces")
    print("=" * 70)
    
    print("[*] Capturing trace A...")
    trace_a = capture_function_trace(cmd_a, timeout=args.timeout)
    print(f"  trace A length: {len(trace_a)}")
    
    print("[*] Capturing trace B...")
    trace_b = capture_function_trace(cmd_b, timeout=args.timeout)
    print(f"  trace B length: {len(trace_b)}")
    
    if not trace_a or not trace_b:
        print("[!] failed to capture traces", file=sys.stderr)
        sys.exit(1)
    
    # Step 2: find the fork point
    print("\n" + "=" * 70)
    print("Step 2: find the function-call fork point")
    print("=" * 70)
    
    idx_a, idx_b, divergence_func, analyze_func = find_divergence_point_simple(trace_a, trace_b)
    
    # Show the first differing function after the fork
    next_func_a = trace_a[idx_a + 1].name if idx_a + 1 < len(trace_a) else None
    next_func_b = trace_b[idx_b + 1].name if idx_b + 1 < len(trace_b) else None
    
    print(f"  fork function (last matched function): {divergence_func}")
    print(f"  function to analyze (where the fork happens): {analyze_func}")
    if next_func_a or next_func_b:
        print(f"  first differing function after the fork: A={next_func_a}, B={next_func_b}")
    print(f"  fork position: A[{idx_a}], B[{idx_b}]")
    
    # Show the trace before the fork
    print(f"\n  trace before the fork (last 5 functions):")
    start_a = max(0, idx_a - 4)
    start_b = max(0, idx_b - 4)
    for i in range(start_a, idx_a + 1):
        print(f"    A[{i}]: {trace_a[i]}")
    for i in range(start_b, idx_b + 1):
        print(f"    B[{i}]: {trace_b[i]}")
    
    # Show the trace after the fork
    if idx_a + 1 < len(trace_a) or idx_b + 1 < len(trace_b):
        print(f"\n  trace after the fork:")
        if idx_a + 1 < len(trace_a):
            print(f"    A[{idx_a+1}]: {trace_a[idx_a+1]}")
        if idx_b + 1 < len(trace_b):
            print(f"    B[{idx_b+1}]: {trace_b[idx_b+1]}")
    
    if not divergence_func:
        print("[!] the two traces are identical, no fork", file=sys.stderr)
        sys.exit(0)
    
    # Step 3: single-step the fork function with GDB
    print("\n" + "=" * 70)
    print(f"Step 3: single-step function {analyze_func} with GDB")
    print("=" * 70)
    
    source_dirs = find_source_dirs(real_binary)
    print(f"  source dirs: {source_dirs}")
    
    # For input A
    print(f"\n[*] execution trace A ({args.input_a})...")
    exec_trace_a = run_gdb_step_through(
        real_binary, analyze_func, cmd_a[1:],
        source_dirs, timeout=args.gdb_timeout
    )
    
    # For input B
    print(f"[*] execution trace B ({args.input_b})...")
    exec_trace_b = run_gdb_step_through(
        real_binary, analyze_func, cmd_b[1:],
        source_dirs, timeout=args.gdb_timeout
    )
    
    if 'error' in exec_trace_a or 'error' in exec_trace_b:
        print(f"[!] GDB execution failed: A={exec_trace_a.get('error')}, B={exec_trace_b.get('error')}", 
              file=sys.stderr)
        sys.exit(1)
    
    print(f"  trace A executed {exec_trace_a.get('step_count', 0)} steps")
    print(f"  trace B executed {exec_trace_b.get('step_count', 0)} steps")
    print(f"  trace A has {len(exec_trace_a.get('trace', []))} distinct lines")
    print(f"  trace B has {len(exec_trace_b.get('trace', []))} distinct lines")
    
    # Step 4: compare execution traces and find the fork statement
    print("\n" + "=" * 70)
    print("Step 4: compare execution traces and find the fork statement")
    print("=" * 70)
    
    divergence_result = compare_execution_traces(
        exec_trace_a.get('trace', []),
        exec_trace_b.get('trace', [])
    )
    
    if divergence_result:
        print(f"\n  fork statement:")
        print(f"    file: {divergence_result['diverging_file']}")
        print(f"    line (A): {divergence_result['diverging_line_a']}")
        print(f"    line (B): {divergence_result['diverging_line_b']}")
        print(f"    description: {divergence_result['description']}")
    else:
        print("  no obvious fork statement found")
    
    # Step 5: source analysis (if GDB failed)
    print("\n" + "=" * 70)
    print("Step 5: source analysis")
    print("=" * 70)
    
    # Locate the fork function's source
    source_dirs = find_source_dirs(real_binary)
    divergence_result = None
    
    # The divergence happens inside analyze_func
    # After analyze_func returns, A calls next_func_a and B calls next_func_b
    # So search analyze_func's source for calls to next_func_a and next_func_b
    # If not found inside analyze_func, search its callers
    if analyze_func:
        targets = [f for f in [next_func_a, next_func_b] if f]
        print(f"  analyze function: {analyze_func}")
        print(f"  calls after the fork: A={next_func_a}, B={next_func_b}")
        
        # Build the candidate list: analyze_func + its callers
        candidates = [analyze_func]
        # Find the parent function calling analyze_func
        if idx_a > 0:
            for i in range(idx_a - 1, max(0, idx_a - 30), -1):
                if trace_a[i].is_enter and trace_a[i].name not in candidates:
                    candidates.append(trace_a[i].name)
                    if len(candidates) >= 5:
                        break
        # Special case: for simple functions, prefer searching the larger caller
        if analyze_func in ('TIFFReadDirectoryFindFieldInfo', '_TIFFfree', '_TIFFmalloc', '_TIFFmemcpy'):
            if 'TIFFReadDirectory' not in candidates:
                candidates.insert(1, 'TIFFReadDirectory')
        
        print(f"  candidate functions: {candidates}")
        
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
                                
                                # Find the candidate function's body
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
                                    # Search the function body for target calls
                                    all_findings = []
                                    for target in targets:
                                        for i in range(func_start, func_end + 1):
                                            if re.search(rf'\b{re.escape(target)}\s*\(', lines[i]):
                                                stripped = lines[i].strip()
                                                if stripped.startswith('static') or stripped.endswith(';'):
                                                    continue
                                                print(f"  found call to {target} in {candidate}() (line {i+1}): {stripped}")
                                                
                                                # Search for nearby conditions
                                                start_line = max(func_start, i - 20)
                                                end_line = min(func_end, i + 5)
                                                conditions = []
                                                for j in range(start_line, end_line):
                                                    near_line = lines[j].strip()
                                                    if re.match(r'\b(if|switch|else\s*if|case)\b', near_line):
                                                        conditions.append(f"line {j+1}: {near_line}")
                                                        print(f"      condition: {near_line}")
                                                
                                                all_findings.append({
                                                    'target': target,
                                                    'line': i+1,
                                                    'text': stripped,
                                                    'conditions': conditions
                                                })
                                    
                                    if all_findings:
                                        # Use the last target found as the result
                                        last = all_findings[-1]
                                        divergence_result = {
                                            'diverging_file': filepath,
                                            'diverging_line': last['line'],
                                            'line_text': last['text'],
                                            'all_findings': all_findings,
                                            'conditions': last['conditions'],
                                            'description': f'in {candidate}(), after the fork A calls {next_func_a} and B calls {next_func_b}'
                                        }
                            except:
                                pass
        
    if not divergence_result:
        print("  no fork point found in the source")
    
    # Step 6: output results
    print("\n" + "=" * 70)
    print("Step 6: output results")
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
    
    print(f"\n  results saved to: {output_path}")
    
    # Print the summary
    print("\n" + "=" * 70)
    print("Analysis summary")
    print("=" * 70)
    print(f"  last matched function (where the fork happens): {divergence_func}")
    print(f"  function actually analyzed: {analyze_func}")
    if next_func_a or next_func_b:
        print(f"  first differing function after the fork: A={next_func_a}, B={next_func_b}")
    if divergence_result:
        print(f"  fork file: {divergence_result.get('diverging_file')}")
        # Show all found call sites
        all_findings = divergence_result.get('all_findings', [])
        if all_findings:
            print(f"  call sites found in the source:")
            for finding in all_findings:
                print(f"    {finding['target']} at line {finding['line']}: {finding['text'][:80]}")
        print(f"  fork description: {divergence_result.get('description')}")
    print(f"  output file: {output_path}")


if __name__ == "__main__":
    main()
