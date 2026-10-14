#!/usr/bin/env python3
"""
lcs_trace.py - recursively extract the longest common substrings (LCS) from two
function-call traces.

Two modes are supported:
  mode 1: same binary, two different inputs  (--binary --input-a --input-b)
  mode 2a: two binaries, one shared input     (--binary-a --binary-b --input)
  mode 2b: two binaries, two different inputs (--binary-a --binary-b --input-a --input-b)

Algorithm
---------
Given trace A and trace B (each a sequence of function calls; every call keeps
its call depth and full call path, reconstructed from the enter/exit events):

  1. Find the longest common substring (contiguous sequence) of A and B.
  2. Remove that substring from both traces. This splits trace A into a left
     part (before the match) and a right part (after the match); the same for B.
  3. Recursively find the LCS of the left parts (A1 vs B1) and of the right
     parts (A2 vs B2).
  4. Only keep LCS whose length is at least `--min-length` (default 3) function
     calls. A shorter match is discarded and the recursion stops there, leaving
     the whole segment as an unmatched gap.

Two calls are considered equal only when they match at the configured hierarchy
level (`--match-level`): by function name, by (depth, name), or by full call
path (default). With the default, calls at different depths -- or under
different callers -- are never aligned.

The output is a hierarchical decomposition of the two traces into matched
(common) blocks and unmatched (divergent) gaps, together with the positions of
every matched block in both traces.

By default, only function enter events are compared. Use --include-exits to
include function exit events in the comparison (significantly slower for large
traces).
"""

import argparse
import bisect
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import stage_timing

BASE = Path(__file__).resolve().parent
FUNCTRACER_SO = BASE / "functracer.so"
NOISE_PREFIX = ('__', 'asan', '_ZN', '_ZSt')


class TraceNode:
    """A single function call together with its reconstructed call-stack position."""
    __slots__ = ("name", "depth", "path", "is_enter", "count", "original_name")

    def __init__(self, name, depth, path, is_enter=True, count=1, original_name=None):
        self.name = name
        self.depth = depth
        self.path = path          # tuple of ancestor names + self
        self.is_enter = is_enter  # True for '>', False for '<'
        self.count = count        # loop iteration count (1 = no loop)
        self.original_name = original_name  # pre-rename name (set by refactor mapper)

    def key(self, level):
        """Return the comparison key for the given hierarchy level."""
        direction = self.is_enter
        count = self.count
        if level == "name":
            return (self.name, direction, count)
        if level == "depth":
            return (self.depth, self.name, direction, count)
        return (self.path, direction, count)  # "path"

    def __repr__(self):
        prefix = ">" if self.is_enter else "<"
        if self.count > 1:
            return f"{prefix}{self.name}*{self.count}"
        return f"{prefix}{self.name}"


def _json_default(o):
    """Serialize TraceNode and tuples for JSON output."""
    if isinstance(o, TraceNode) or hasattr(o, 'name') and hasattr(o, 'depth') and hasattr(o, 'path'):
        d = {"name": o.name, "depth": o.depth, "path": list(o.path),
             "is_enter": o.is_enter, "count": o.count}
        if getattr(o, 'original_name', None) is not None:
            d["original_name"] = o.original_name
        return d
    if isinstance(o, tuple):
        return list(o)
    if isinstance(o, set):
        return sorted(list(o))
    raise TypeError(f"object of type {type(o).__name__} is not JSON serializable")


# --------------------------------------------------------------------------- #
# Trace capture (reuses the -finstrument-functions + functracer.so approach)
# --------------------------------------------------------------------------- #

def resolve_real_binary(binpath):
    """Resolve a libtool wrapper script to the real ELF binary in .libs."""
    binpath = Path(binpath).resolve()
    try:
        with open(binpath, 'rb') as f:
            head = f.read(64)
        if head.startswith(b'#!') or head.startswith(b'# '):
            real = binpath.parent / '.libs' / binpath.name
            if real.exists() and open(real, 'rb').read(4) == b'\x7fELF':
                return real
    except Exception:
        pass
    return binpath


def find_version_root(binary):
    """Walk up from the binary to find the version root directory.

    Prefer directories with ``configure`` or ``.build_ok`` over plain
    ``CMakeLists.txt`` (a subdirectory like ``tools/`` may also have a
    ``CMakeLists.txt`` but is not the project root).
    """
    d = binary.parent
    fallback = None
    for _ in range(5):
        if (d / ".build_ok").exists() or (d / "configure").exists():
            return d
        if fallback is None and (d / "CMakeLists.txt").exists():
            fallback = d
        if d.parent == d:
            break
        d = d.parent
    return fallback or binary.parent.parent.parent


def collect_lib_dirs(binary):
    """Collect .libs directories so shared libraries (e.g. libaudiofile.so) resolve."""
    root = find_version_root(binary)
    dirs = []
    seen = set()
    for d in sorted(root.rglob('.libs')):
        s = str(d)
        if s not in seen:
            seen.add(s)
            dirs.append(s)
    for p in binary.parents:
        d = p / '.libs'
        if d.exists() and str(d) not in seen:
            seen.add(str(d))
            dirs.append(str(d))
    return dirs


_symcache = {}


def resolve_local(binpath, offset):
    """Resolve a local (static) symbol from an offset using nm output."""
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
    i = bisect.bisect_right([s[0] for s in syms], offset) - 1
    if i >= 0 and offset - syms[i][0] < 65536:
        return syms[i][1].split('(')[0]
    return None


def capture_function_trace(cmd, timeout=900, include_exits=False):
    """Run `cmd` under functracer.so and return the list of function calls (TraceNode).
    
    If include_exits is True, exit events are also recorded in the trace.
    """
    out_file = tempfile.mktemp(prefix="lcs_", suffix=".log")
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
    libs = collect_lib_dirs(Path(cmd[0]))
    env.update({"LD_PRELOAD": ":".join(preloads),
                "FUNC_TRACE_OUT": out_file,
                "ASAN_OPTIONS": "detect_leaks=0:abort_on_error=1"})
    if libs:
        old_ld = env.get("LD_LIBRARY_PATH", "")
        env["LD_LIBRARY_PATH"] = ":".join(libs + ([old_ld] if old_ld else []))

    try:
        # Bytes mode: the traced binary's stdout/stderr may contain raw
        # binary garbage (e.g. objdump -g on a corrupted DWARF file).
        subprocess.run([str(c) for c in cmd], capture_output=True,
                       timeout=timeout, env=env)
    except subprocess.TimeoutExpired:
        pass

    base_map, last_module, last_base, events = {}, None, 0, []
    try:
        for line in open(out_file):
            parts = line.split()
            if len(parts) >= 3 and parts[0] == 'M':
                try:
                    mpath = parts[2]
                    base_addr = int(parts[1], 16)
                    base_map[base_addr] = mpath
                    last_module = mpath
                    last_base = base_addr
                except (IndexError, ValueError):
                    pass
            elif len(parts) == 3 and parts[0] in ('>', '<') and parts[1].startswith('@'):
                try:
                    offset = int(parts[1][1:], 16)
                    events.append((parts[0], ('local',
                                              last_module,
                                              offset)))
                except ValueError:
                    continue
            elif len(parts) == 2 and parts[0] in ('>', '<'):
                tok = parts[1]
                if tok.startswith('@') and last_module:
                    try:
                        offset = int(tok[1:], 16)
                        events.append((parts[0], ('local', last_module,
                                                  offset)))
                        continue
                    except ValueError:
                        pass
                events.append((parts[0], tok))
    finally:
        try:
            os.unlink(out_file)
        except Exception:
            pass

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
            # Loop collapsing: detect >A <A >A pattern
            if (include_exits and len(seq) >= 2
                and not seq[-1].is_enter      # previous is exit
                and seq[-2].is_enter           # before that is enter
                and seq[-2].path == node.path  # same path as current
                and seq[-1].path == node.path): # exit also same path
                # Loop iteration detected, increment count on the enter node
                seq[-2].count += 1
                # Remove the previous exit node
                seq.pop()
            elif not seq or seq[-1].path != node.path or not seq[-1].is_enter:
                seq.append(node)
            stack.append(name)
        else:  # '<'
            if stack:
                if include_exits:
                    # Record exit event BEFORE popping
                    node = TraceNode(name, len(stack) - 1, tuple(stack), is_enter=False)
                    if not seq or seq[-1].path != node.path or seq[-1].is_enter:
                        seq.append(node)
                stack.pop()
    return seq


# --------------------------------------------------------------------------- #
# Longest common substring (contiguous)
# --------------------------------------------------------------------------- #

def longest_common_substring(a, b):
    """
    Return (a_start, b_start, length) of the longest contiguous common substring
    of sequences a and b (each a sequence of comparable keys), or None if no
    common element exists.

    Uses O(len(a) * len(b)) dynamic programming with two rolling rows.
    Optimized: early termination when full match found.
    """
    n, m = len(a), len(b)
    if n == 0 or m == 0:
        return None

    # Early exit: check if entire sequences match
    if n == m and a == b:
        return (0, 0, n)

    prev = [0] * (m + 1)
    best_len = 0
    best_end_i = -1
    best_end_j = -1

    # Track if any match exists
    found_any = False

    for i in range(1, n + 1):
        cur = [0] * (m + 1)
        ai = a[i - 1]
        for j in range(1, m + 1):
            if ai == b[j - 1]:
                cur[j] = prev[j - 1] + 1
                found_any = True
                if cur[j] > best_len:
                    best_len = cur[j]
                    best_end_i = i
                    best_end_j = j
                    # Early termination: found match covering rest of a
                    if best_len == n - (i - best_len + 1) + 1:
                        return best_end_i - best_len, best_end_j - best_len, best_len
        prev = cur

    if not found_any:
        return None
    return best_end_i - best_len, best_end_j - best_len, best_len


# --------------------------------------------------------------------------- #
# Recursive decomposition
# --------------------------------------------------------------------------- #

def decompose(a, b, ka, kb, a_base, b_base, depth, min_length, matches, gaps):
    """
    Recursively split traces a/b at their longest common substring.

    `a`/`b` are the lists of TraceNode; `ka`/`kb` are the parallel lists of
    comparison keys (one per call). `a_base`/`b_base` are the starting offsets
    of these segments in the original traces, used to report global positions.
    Uses indices instead of slicing for better performance.
    """
    lcs = longest_common_substring(ka, kb)
    if lcs is None:
        if a or b:
            gaps.append({"level": depth, "a": list(a), "b": list(b),
                         "a_range": (a_base, a_base + len(a)),
                         "b_range": (b_base, b_base + len(b))})
        return

    a_start, b_start, length = lcs
    if length < min_length:
        # LCS too short to be meaningful: discard it and leave the whole
        # segment as an unmatched gap, stopping the recursion here.
        if a or b:
            gaps.append({"level": depth, "a": list(a), "b": list(b),
                         "a_range": (a_base, a_base + len(a)),
                         "b_range": (b_base, b_base + len(b))})
        return

    match_a = list(a[a_start:a_start + length])

    matches.append({
        "level": depth,
        "functions": match_a,
        "length": length,
        "a_range": (a_base + a_start, a_base + a_start + length),
        "b_range": (b_base + b_start, b_base + b_start + length),
    })

    # Process left part
    if a_start > 0 or b_start > 0:
        decompose(a[:a_start], b[:b_start], ka[:a_start], kb[:b_start],
                  a_base, b_base, depth + 1, min_length, matches, gaps)
    # Process right part
    a_end = a_start + length
    b_end = b_start + length
    if a_end < len(a) or b_end < len(b):
        decompose(a[a_end:], b[b_end:], ka[a_end:], kb[b_end:],
                  a_base + a_end, b_base + b_end,
                  depth + 1, min_length, matches, gaps)


def format_range(rng):
    return f"[{rng[0]}:{rng[1]})"


def node_name(n):
    """Return the display label of a trace element, annotated with call depth."""
    if isinstance(n, TraceNode):
        prefix = ">" if n.is_enter else "<"
        count_str = f"*{n.count}" if n.count > 1 else ""
        return f"{prefix}{n.name}@d{n.depth}{count_str}"
    return str(n)


def join_names(names, head=6, tail=6):
    """Show the first `head` and last `tail` function names, eliding the middle."""
    names = [node_name(n) for n in names]
    if len(names) <= head + tail:
        return " -> ".join(names)
    return (" -> ".join(names[:head])
            + f" -> ... ({len(names) - head - tail} more) -> "
            + " -> ".join(names[-tail:]))


def main():
    ap = argparse.ArgumentParser(
        description="Recursively extract longest common substrings from two "
                    "function-call traces.")
    ap.add_argument("--binary", default=None,
                    help="[mode 1] program path (same binary, two different inputs)")
    ap.add_argument("--input-a", default=None, help="[mode 1/2b] input file A")
    ap.add_argument("--input-b", default=None, help="[mode 1/2b] input file B")
    ap.add_argument("--binary-a", default=None,
                    help="[mode 2] program path A (two binaries, one shared or two different inputs)")
    ap.add_argument("--binary-b", default=None,
                    help="[mode 2] program path B")
    ap.add_argument("--input", default=None,
                    help="[mode 2a] input file fed to both binaries")
    ap.add_argument("--args", default="{input} out.mp3 format aiff",
                    help="argument template; {input} is replaced by the input file path")
    ap.add_argument("--min-length", type=int, default=3,
                    help="minimum length of a valid LCS match (default 3); shorter matches are discarded")
    ap.add_argument("--match-level", choices=["name", "depth", "path"], default="path",
                    help="hierarchy level used to consider two calls equal: "
                         "'name' = function name only, 'depth' = (depth, name), "
                         "'path' = full call path (default)")
    ap.add_argument("--include-exits", action="store_true", default=False,
                    help="include function exit events in LCS comparison (slower for large traces)")
    ap.add_argument("--max-trace-size", type=int, default=0,
                    help="limit trace size for --include-exits (0 = no limit); "
                         "large traces with exits are very slow due to O(n*m) LCS")
    ap.add_argument("-o", "--output", default=None,
                    help="optional JSON output path")
    ap.add_argument("--refactor-detect", action="store_true", default=False,
                    help="enable cross-version refactoring detection to align "
                         "traces when function names changed between versions")
    ap.add_argument("--ref-a-dir", default=None,
                    help="source directory of version A for refactoring detection "
                         "(auto-detected from binary if not given)")
    ap.add_argument("--ref-b-dir", default=None,
                    help="source directory of version B for refactoring detection "
                         "(auto-detected from binary if not given)")
    ap.add_argument("--rename-threshold", type=float, default=0.7,
                     help="similarity threshold for rename detection (default 0.7)")
    ap.add_argument("--trace-diverge", action="store_true", default=False,
                     help="use GDB to automatically trace the root cause of "
                          "execution divergence at the LCS divergence point")
    ap.add_argument("--no-polytracker", action="store_true", default=False,
                     help="skip polytracker inside divergence analysis (GDB-only mode)")
    ap.add_argument("--config", default=None,
                    help="Path to config module for PolyTracker analysis")
    ap.add_argument("--gdb-timeout", type=int, default=120,
                     help="timeout for GDB operations in seconds (default 120)")
    ap.add_argument("--ref-label", default=None,
                    help="display label for the reference version "
                         "(e.g. tiff-4.0.6)")
    ap.add_argument("--target-label", default=None,
                    help="display label for the target version "
                         "(e.g. tiff-3.9.5)")
    args = ap.parse_args()

    cross = bool(args.binary_a and args.binary_b)
    if cross:
        if args.input:
            # mode 2a: two binaries, one shared input
            real_a = resolve_real_binary(args.binary_a)
            real_b = resolve_real_binary(args.binary_b)
            input_a = input_b = args.input
        elif args.input_a and args.input_b:
            # mode 2b: two binaries, two different inputs
            real_a = resolve_real_binary(args.binary_a)
            real_b = resolve_real_binary(args.binary_b)
            input_a, input_b = args.input_a, args.input_b
        else:
            sys.exit("mode 2 requires --input (shared) or --input-a --input-b (different)")
    else:
        if not (args.binary and args.input_a and args.input_b):
            sys.exit("mode 1 requires --binary --input-a --input-b "
                     "(or mode 2a: --binary-a --binary-b --input "
                     "or mode 2b: --binary-a --binary-b --input-a --input-b)")
        real_a = real_b = resolve_real_binary(args.binary)
        input_a, input_b = args.input_a, args.input_b

    def mk_a(input_file):
        return [str(real_a)] + args.args.replace(
            "{input}", str(Path(input_file).resolve())).split()

    def mk_b(input_file):
        return [str(real_b)] + args.args.replace(
            "{input}", str(Path(input_file).resolve())).split()

    print(f"binary A: {real_a}")
    print(f"binary B: {real_b}")
    print("capturing trace A ...")
    seq_a = capture_function_trace(mk_a(input_a), include_exits=args.include_exits)
    print("capturing trace B ...")
    seq_b = capture_function_trace(mk_b(input_b), include_exits=args.include_exits)
    print(f"trace A length: {len(seq_a)}")
    print(f"trace B length: {len(seq_b)}")
    print(f"match level: {args.match_level}")
    print(f"include exits: {args.include_exits}")
    
    # Start timing after traces are captured
    start_time = time.time()
    
    # Warn about performance with exits and apply default limit
    if args.include_exits:
        if args.max_trace_size == 0:
            # Auto-limit to prevent extremely slow LCS
            max_size = 5000
            if len(seq_a) > max_size or len(seq_b) > max_size:
                print(f"Warning: --include-exits with large traces is very slow (O(n*m) LCS)")
                print(f"  Auto-limiting traces to {max_size} elements (use --max-trace-size to change)")
                seq_a = seq_a[:max_size]
                seq_b = seq_b[:max_size]
        else:
            seq_a = seq_a[:args.max_trace_size]
            seq_b = seq_b[:args.max_trace_size]
    elif args.max_trace_size > 0:
        seq_a = seq_a[:args.max_trace_size]
        seq_b = seq_b[:args.max_trace_size]

    # ---- Cross-version refactoring detection ----
    rename_map = {}
    refactor_mappings = None
    if args.refactor_detect and cross:
        from refactor_detector import RefactorDetector, TraceRefactorMapper

        ref_a_dir = args.ref_a_dir or str(find_version_root(real_a))
        ref_b_dir = args.ref_b_dir or str(find_version_root(real_b))

        print(f"\n{'=' * 70}")
        print("Cross-version refactoring detection")
        print(f"{'=' * 70}")
        print(f"  source dir A: {ref_a_dir}")
        print(f"  source dir B: {ref_b_dir}")

        detector = RefactorDetector(
            ref_a_dir, ref_b_dir,
            ref_trace_funcs=[n.name for n in seq_a],
            tgt_trace_funcs=[n.name for n in seq_b],
            threshold=args.rename_threshold,
        )
        _t_ref_start = time.time()
        refactor_mappings = detector.detect()
        stage_timing.record("detect function refactor/rename", time.time() - _t_ref_start)
        rename_map = refactor_mappings.all_renames()

        if rename_map:
            non_id = {k: v for k, v in rename_map.items() if k != v}
            print(f"\n  rename mappings (non-identity): {len(non_id)}")
            if non_id and len(non_id) <= 30:
                print(TraceRefactorMapper.format_mapping_for_display(non_id))
            elif non_id:
                print(TraceRefactorMapper.format_mapping_for_display(non_id, max_entries=10))

            print(f"\n  applying mappings to trace B ...")
            seq_b = TraceRefactorMapper.apply_rename_mapping(seq_b, rename_map)
            print(f"  trace B unique names after alignment: "
                  f"{len(set(n.name for n in seq_b))}")
        else:
            print("\n  no rename mappings found; traces unchanged.")

    # Build refactor_info dict for stats and JSON output
    refactor_info = {}
    if refactor_mappings:
        refactor_info = {
            "renames": refactor_mappings.renames,
            "moves": refactor_mappings.moves,
            "split": refactor_mappings.split,
            "merge": refactor_mappings.merge,
            "semantic_renames": refactor_mappings.semantic_renames,
            "source_dir_a": args.ref_a_dir or (str(find_version_root(real_a)) if cross else None),
            "source_dir_b": args.ref_b_dir or (str(find_version_root(real_b)) if cross else None),
        }

    keyfn = lambda n: n.key(args.match_level)
    # Pre-compute keys once for better performance
    ka = [keyfn(n) for n in seq_a]
    kb = [keyfn(n) for n in seq_b]

    matches = []
    gaps = []
    decompose(seq_a, seq_b, ka, kb, 0, 0, 0, args.min_length, matches, gaps)

    print("\n" + "=" * 70)
    print("Hierarchical decomposition (pre-order)")
    print("  [level N] = recursion depth of the LCS splitting; "
          "functions shown as name@d<call-depth>")
    print("=" * 70)
    for m in matches:
        indent = "  " * m["level"]
        print(f"{indent}[level {m['level']}] LCS length={m['length']} "
              f"A{format_range(m['a_range'])} B{format_range(m['b_range'])}:")
        print(f"{indent}    {join_names(m['functions'])}")
    for g in gaps:
        indent = "  " * g["level"]
        desc_a = join_names(g["a"]) if g["a"] else "(empty)"
        desc_b = join_names(g["b"]) if g["b"] else "(empty)"
        print(f"{indent}[gap  level {g['level']}] A{format_range(g['a_range'])} "
              f"B{format_range(g['b_range'])}")
        print(f"{indent}    A: {desc_a}")
        print(f"{indent}    B: {desc_b}")

    # Ordered view (sorted by position in trace A)
    ordered = []
    for m in matches:
        ordered.append((m["a_range"][0], "match", m))
    for g in gaps:
        ordered.append((g["a_range"][0], "gap", g))
    ordered.sort(key=lambda x: x[0])

    print("\n" + "=" * 70)
    print("Ordered decomposition (by position in trace A)")
    print("=" * 70)
    for _, kind, item in ordered:
        if kind == "match":
            print(f"MATCH  len={item['length']:<4} "
                  f"A{format_range(item['a_range']):<12} B{format_range(item['b_range']):<12} "
                  f"{join_names(item['functions'])}")
        else:
            print(f"GAP          "
                  f"A{format_range(item['a_range']):<12} B{format_range(item['b_range']):<12} "
                  f"A: {join_names(item['a']) if item['a'] else '(empty)'}")
            if item["b"]:
                print(f"{' ' * 50}B: {join_names(item['b'])}")

    n_match = len(matches)
    n_gap = len(gaps)
    matched_a = sum(m["length"] for m in matches)
    print("\n" + "-" * 70)
    if refactor_info:
        n_ren = len(refactor_info.get("renames", {}))
        n_mov = len(refactor_info.get("moves", {}))
        n_spl = len(refactor_info.get("split", {}))
        n_mrg = len(refactor_info.get("merge", {}))
        print(f"refactoring: {n_ren} renames, {n_mov} moves, "
              f"{n_spl} splits, {n_mrg} merges applied")
    print(f"matches: {n_match}, gaps: {n_gap}")
    print(f"matched function names in A: {matched_a}/{len(seq_a)} "
          f"({100.0 * matched_a / len(seq_a):.1f}%)" if seq_a else
          "matched function names in A: 0")
    print(f"matched function names in B: {matched_a}/{len(seq_b)} "
          f"({100.0 * matched_a / len(seq_b):.1f}%)" if seq_b else
          "matched function names in B: 0")

    # Find and output the LCS and gap closest to the end of traces
    if ordered:
        print("\n" + "=" * 70)
        print("Tail analysis (closest to trace end)")
        print("=" * 70)

        # Find the last match and last gap by position in trace A
        last_match = None
        last_gap = None
        for _, kind, item in ordered:
            if kind == "match":
                last_match = item
            elif kind == "gap":
                last_gap = item

        if last_match:
            print(f"\nLast MATCH (len={last_match['length']}):")
            print(f"  A{format_range(last_match['a_range'])} B{format_range(last_match['b_range'])}")
            print(f"  {join_names(last_match['functions'])}")

        if last_gap:
            print(f"\nLast GAP:")
            print(f"  A{format_range(last_gap['a_range'])} B{format_range(last_gap['b_range'])}")
            if last_gap['a']:
                print(f"  A: {join_names(last_gap['a'])}")
            else:
                print(f"  A: (empty)")
            if last_gap['b']:
                print(f"  B: {join_names(last_gap['b'])}")
            else:
                print(f"  B: (empty)")

    # Save intermediate result for divergence analysis
    result_path = args.output or "/tmp/lcs_result.json"
    out_dir = Path(result_path).parent
    out_dir.mkdir(parents=True, exist_ok=True)
    with open(result_path, 'w', encoding='utf-8') as fp:
        json.dump({"trace_A": seq_a, "trace_B": seq_b,
                   "min_length": args.min_length,
                   "match_level": args.match_level,
                   "refactoring": refactor_info,
                   "matches": matches, "gaps": gaps},
                  fp, indent=2, ensure_ascii=False, default=_json_default)
    if args.output:
        print(f"result saved to: {result_path}")

    # --- Divergence analysis via GDB ---
    if args.trace_diverge:
        print("\n" + "=" * 70)
        print("Divergence Analysis (--trace-diverge)")
        print("=" * 70)

        from divergence_analyzer import analyze_lcs_result
        import divergence_analyzer as _div_mod

        diverge_args_a = args.args.replace(
            "{input}", str(Path(input_a).resolve())).split()
        diverge_args_b = args.args.replace(
            "{input}", str(Path(input_b).resolve())).split()

        # Load config module if provided
        config_module = None
        if args.config:
            import importlib.util
            cfg_path = Path(args.config).resolve()
            spec = importlib.util.spec_from_file_location("config_mod", str(cfg_path))
            config_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(config_module)

        _t_div_start = time.time()
        div_result = analyze_lcs_result(
            str(result_path),
            binary_a=str(real_a) if cross else str(real_a),
            binary_b=str(real_b) if cross else str(real_b),
            args_a=diverge_args_a,
            args_b=diverge_args_b,
            input_file=str(Path(input_a).resolve()) if input_a else None,
            gdb_timeout=args.gdb_timeout,
            refactoring_map=rename_map if rename_map else None,
            config=config_module,
            skip_polytracker=args.no_polytracker,
            ref_label=args.ref_label,
            target_label=args.target_label,
        )
        _div_secs = time.time() - _t_div_start
        try:
            import stage_timing as _st
            _gdb_count = _st.gdb_runs()
        except Exception:
            _gdb_count = 0
        print(f"  [GDB] launched {_gdb_count} GDB process(es) while searching for the fork statement"
              f" (average {_div_secs / max(_gdb_count, 1):.2f}s each)")
        stage_timing.record("find fork statement", _div_secs)

        # Ensure the divergence result carries the info trace_fork_offsets.py
        # needs: binary/args for the target and the input file.
        if isinstance(div_result, dict) and 'error' not in div_result:
            div_result.setdefault('binary_a', str(real_a))
            div_result.setdefault('binary_b', str(real_b))
            div_result.setdefault('args_a', diverge_args_a)
            div_result.setdefault('args_b', diverge_args_b)
            div_result.setdefault('input_file', str(input_a) if input_a else None)
            div_result.setdefault('version_a', _div_mod._LABEL_A)
            div_result.setdefault('version_b', _div_mod._LABEL_B)
            # The program name comes from the config's EXECUTION_CONFIG (e.g.
            # tiffcp, sfconvert, lame) — downstream steps must not fall back
            # to a hardcoded default (e.g. tiffcrop) when the project uses a
            # different program.
            if config_module is not None:
                _exec_cfg = getattr(config_module, 'EXECUTION_CONFIG', {})
                _prog = _exec_cfg.get('program_name', '')
                if _prog:
                    div_result.setdefault('program_name', _prog)
            _annotate_divergence_confidence(div_result)

        print(f"\n  Divergence function: {div_result.get('divergence_function', 'N/A')}")
        print(f"  Root cause function: {div_result.get('root_cause_function', 'N/A')}")
        print(f"  Root cause location: {div_result.get('root_cause_file', 'N/A')}:{div_result.get('root_cause_line', 'N/A')}")
        stmt_a = div_result.get('root_cause_statement_a', 'N/A')
        stmt_b = div_result.get('root_cause_statement_b', 'N/A')
        a_file = div_result.get('root_cause_file_a', div_result.get('root_cause_file', 'N/A'))
        a_line = div_result.get('root_cause_line_a', div_result.get('root_cause_line', 'N/A'))
        b_file = div_result.get('root_cause_file_b', div_result.get('root_cause_file', 'N/A'))
        b_line = div_result.get('root_cause_line_b', div_result.get('root_cause_line', 'N/A'))
        print(f"  {_div_mod._LABEL_A}: {stmt_a}  ({a_file}:{a_line})")
        print(f"  {_div_mod._LABEL_B}: {stmt_b}  ({b_file}:{b_line})")

        # Save divergence result
        div_out = Path(result_path).with_suffix(".diverge.json")
        with open(div_out, 'w') as fp:
            json.dump(div_result, fp, indent=2, ensure_ascii=False)
        print(f"\n  divergence result saved to: {div_out}")

        # Merge divergence result into main JSON
        with open(result_path, 'r') as fp:
            main_data = json.load(fp)
        main_data["divergence"] = div_result
        with open(result_path, 'w') as fp:
            json.dump(main_data, fp, indent=2, ensure_ascii=False, default=_json_default)

    # End timing and print elapsed time
    end_time = time.time()
    elapsed = end_time - start_time
    print(f"\ntime: {elapsed:.3f}s")


_SYNTHETIC_STMT_RE = re.compile(r'^v?\d+(\.\d+)*\s+calls\s+', re.I)


def _annotate_divergence_confidence(div):
    """Attach analysis-path / confidence / degradation markers to a divergence
    result (best-effort, generic — no project-specific keywords).

    The divergence JSON is produced by a chain of increasingly heuristic
    analyses (backward tracer -> crash cases -> step-into -> semantic diff ->
    gap walk).  Downstream consumers (PolyTracker/GDB offset localization,
    mutation testing) treat every location as equally trustworthy, which is
    why a "synthetic" reference statement or a failed step silently yields
    plausible-looking but wrong offsets.  These markers make the reliability
    of each claim explicit.
    """
    if not isinstance(div, dict):
        return
    notes = []
    stmt_a = str(div.get('root_cause_statement_a') or '').strip()
    stmt_b = str(div.get('root_cause_statement_b') or '').strip()
    a_synth = bool(_SYNTHETIC_STMT_RE.match(stmt_a)) or (
        div.get('crash_based') and not stmt_a)
    b_synth = bool(_SYNTHETIC_STMT_RE.match(stmt_b))
    if a_synth:
        notes.append('reference-side statement is a synthetic call '
                     'description, not real C source — variable extraction '
                     'and line mapping on the reference side are unreliable')
    if b_synth:
        notes.append('target-side statement is a synthetic call description, '
                     'not real C source')

    if div.get('enclosing_decision_fork'):
        path = 'crash_enclosing_decision'
        notes.append('fork located as the nearest enclosing decision of the '
                     'reference crash point; both versions execute it with '
                     'different operand values (the crash statement itself is '
                     'unreachable in the target)')
    elif div.get('crash_based'):
        path = 'crash_based'
        if div.get('crash_signal_b'):
            # Case C: the target crashes on its own (different site) — its
            # crash point is treated as the fork.  Mutating it must also keep
            # the target from re-triggering its own crash while it walks
            # toward the reference's crash.
            notes.append('target crashed on its own at the fork site; the '
                         'mutation must BOTH dodge the target crash AND reach '
                         'the reference crash point')
    elif div.get('dynamic_fork'):
        path = 'dynamic_fork'
        dyn = div.get('dynamic_fork') or {}
        if dyn.get('status') == 'decision_fork' and not dyn.get('weak'):
            pass  # strong dynamic evidence — high confidence
        else:
            notes.append('fork located with weak dynamic evidence '
                         '(value/text divergence or value fork)')
    elif div.get('semantic_fork'):
        path = 'semantic_static_diff'
        notes.append('fork located by static source diff (guard added in one '
                     'version); NOT execution-path aware — verify the guard '
                     'is actually reached by the input')
    elif div.get('backward_chain') or div.get('assign_diff'):
        path = 'backward_tracer_gdb'
        notes.append('fork located by GDB return-value probing; chain is '
                     'reconstructed heuristically (rename/assign matching)')
    elif div.get('_fork_is_condition'):
        path = 'gap_condition'
    elif div.get('fork_chain'):
        path = 'crash_anchor'
    elif div.get('step_trace_split'):
        path = 'step_trace_split'
        notes.append('fork located inside the last common function at the '
                     'permanent-split point (source-level step traces, GDB)')
    else:
        path = 'gap_or_step'

    level = 'high'
    if a_synth or b_synth or not div.get('root_cause_line'):
        level = 'low'
    elif path == 'semantic_static_diff':
        level = 'medium'
    elif path == 'backward_tracer_gdb':
        level = 'medium'
    elif path == 'crash_enclosing_decision':
        level = 'medium'
    elif path == 'crash_based':
        level = 'medium'
    elif path == 'dynamic_fork' and notes:
        level = 'medium'

    if not div.get('variables') and not div.get('step_trace_split'):
        # step_trace_split results carry no pre-resolved variable list; the
        # offset stage extracts fork variables from the source statement.
        notes.append('no fork variables reported — offset localization has '
                     'nothing to trace')
    if not div.get('root_cause_line'):
        notes.append('no root-cause source line was located')

    po = div.get('polytracker_offsets') or {}
    if isinstance(po, dict) and po.get('status') == 'error':
        notes.append('polyTracker offset localization failed inside the '
                     'divergence analysis (offset stage must be re-run '
                     'separately)')

    div['analysis_path'] = path
    div['statement_a_synthetic'] = a_synth
    div['statement_b_synthetic'] = b_synth
    div['analysis_confidence'] = level
    if notes:
        div['analysis_notes'] = notes
    else:
        div.pop('analysis_notes', None)
    print(f"  [confidence] path={path} level={level}"
          + (f" — {'; '.join(notes)}" if notes else ""))


if __name__ == "__main__":
    main()
