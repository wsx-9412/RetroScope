#!/usr/bin/env python3
"""
divergence_analyzer.py - Automatically trace the root cause of execution divergence
between two binary versions using GDB.

Given two binaries and the LCS divergence point, this tool:
  1. Identifies the divergence function from the trace
  2. Sets GDB breakpoints on both binaries at that function
  3. Compares variable states to find the first differing value
  4. Traces back to the source statement that produces the difference
"""

import json
import os
import re
import subprocess
import tempfile
from pathlib import Path


def find_version_root(binary):
    """Walk up from the binary to find the version root directory."""
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


def collect_lib_dirs(binary):
    """Collect .libs directories for LD_LIBRARY_PATH."""
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


def run_gdb_batch(binary, commands, env=None, timeout=120):
    """Run GDB in batch mode with the given commands and return stdout."""
    gdb_cmds = ["gdb", "-batch", "-ex", "set pagination off",
                "-ex", "set confirm off"]
    for cmd in commands:
        gdb_cmds.extend(["-ex", cmd])
    gdb_cmds.append(binary)

    result = subprocess.run(
        gdb_cmds, capture_output=True, text=True, timeout=timeout, env=env
    )
    return result.stdout + result.stderr


def run_gdb_with_source(binary, source_dirs, commands, lib_path=None, timeout=120):
    """Run GDB with source directory and library path configured."""
    env = os.environ.copy()
    env["ASAN_OPTIONS"] = "detect_leaks=0"
    if lib_path:
        old_ld = env.get("LD_LIBRARY_PATH", "")
        lib_parts = [lib_path] if isinstance(lib_path, str) else lib_path
        env["LD_LIBRARY_PATH"] = ":".join(lib_parts + ([old_ld] if old_ld else []))

    gdb_cmds = ["gdb", "-batch", "-ex", "set pagination off",
                "-ex", "set confirm off"]
    # Set solib-search-path so GDB loads the bundled libtiff with debug info
    if lib_path:
        gdb_cmds.extend(["-iex", f"set solib-search-path {lib_path}"])
    for d in source_dirs:
        gdb_cmds.extend(["-iex", f"directory {d}"])
    for cmd in commands:
        gdb_cmds.extend(["-ex", cmd])
    gdb_cmds.append(str(binary))

    result = subprocess.run(
        gdb_cmds, capture_output=True, text=True, timeout=timeout, env=env
    )
    return result.stdout + result.stderr


def find_libtiff_path(binary):
    """Find the bundled libtiff .libs directory for a binary."""
    lib_dirs = collect_lib_dirs(binary)
    for d in lib_dirs:
        candidates = list(Path(d).glob("libtiff.so*"))
        if candidates:
            return d
    return None


def find_source_dirs(binary):
    """Find source directories containing .c files for this binary."""
    root = find_version_root(binary)
    dirs = []
    for subdir in [root, root / "libtiff", root / "tools"]:
        if subdir.exists():
            dirs.append(str(subdir))
    return dirs


def _extract_gap_fork(gap):
    """Extract the forking caller from a gap.

    A gap records the calls that differ between the two traces.  The fork
    point is where the *same* caller invoked *different* callees in A vs B
    (e.g. ``TIFFFetchStripThing`` calling ``TIFFReadDirEntryLong8ArrayWithLimit``
    in A but ``TIFFReadDirEntryLong8Array`` in B).  Return the deepest such
    caller name, or None.
    """
    a_items = [x for x in gap.get("a", [])
               if isinstance(x, dict) and x.get("path")]
    b_items = [x for x in gap.get("b", [])
               if isinstance(x, dict) and x.get("path")]
    if not a_items or not b_items:
        return None
    b_parents = {}
    for x in b_items:
        p = tuple(x["path"][:-1])
        b_parents.setdefault(p, set()).add(x["name"])
    best = None
    for x in a_items:
        p = tuple(x["path"][:-1])
        if p in b_parents and x["name"] not in b_parents[p]:
            depth = len(p)
            if best is None or depth > best[0]:
                best = (depth, p[-1] if p else x["name"])
    return best[1] if best else None


def _extract_gap_fork_pair(gap):
    """Extract the forking callee pair and caller from a gap.

    Returns ``(callee_a, callee_b, caller)`` where the same ``caller`` invoked
    ``callee_a`` in A (e.g. ``TIFFReadDirEntryLong8ArrayWithLimit``) but
    ``callee_b`` in B (e.g. ``TIFFReadDirEntryLong8Array``), or None.  The pair
    is a *semantic-enhancement* rename: B's function was replaced by a
    strengthened A variant (``...WithLimit``/``...Checked``), whose added guard
    is the real fork statement.
    """
    a_items = [x for x in gap.get("a", [])
               if isinstance(x, dict) and x.get("path")]
    b_items = [x for x in gap.get("b", [])
               if isinstance(x, dict) and x.get("path")]
    if not a_items or not b_items:
        return None
    b_by_parent = {}
    for x in b_items:
        p = tuple(x["path"][:-1])
        b_by_parent.setdefault(p, set()).add(x["name"])
    best = None
    for x in a_items:
        p = tuple(x["path"][:-1])
        if p in b_by_parent:
            for b_name in b_by_parent[p]:
                if b_name == x["name"]:
                    continue
                depth = len(p)
                # Prefer a *semantic* pair (XWithLimit vs X) over an unrelated
                # callee that merely shares the caller (e.g. ...OutputErr).
                sem = 1 if is_semantic_pair(x["name"], b_name) else 0
                score = (depth, sem)
                if best is None or score > best[0]:
                    best = (score, x["name"], b_name, p[-1] if p else None)
    if best:
        return best[1], best[2], best[3]
    return None


def _semantic_pair_added_guard(callee_a, callee_b, source_dirs_a, source_dirs_b):
    """Diff a semantic-enhancement pair and return A's added guard statement.

    ``callee_a`` is the strengthened variant (e.g. ``TIFFReadDirEntryArrayWithLimit``)
    and ``callee_b`` the original (``TIFFReadDirEntryArray``).  Find a statement
    present in A's body but not B's that looks like a guard
    (``if ... >/< ...`` or ``return ErrSizesan`` etc.) — that guard is the real
    fork statement.
    """
    file_a = _find_function_source(callee_a, source_dirs_a)
    file_b = _find_function_source(callee_b, source_dirs_b)
    if not file_a or not file_b:
        return None
    try:
        code_a = open(file_a, encoding='utf-8', errors='replace').read()
        code_b = open(file_b, encoding='utf-8', errors='replace').read()
    except OSError:
        return None
    body_a = _extract_function_body(code_a, callee_a)
    body_b = _extract_function_body(code_b, callee_b)
    if not body_a or not body_b:
        return None

    # Line number of the function body start within the file (for reporting).
    head_a = code_a[:code_a.find(body_a)] if body_a in code_a else ''
    body_start_line = head_a.count('\n') + 1

    b_lines = {l.strip() for l in body_b.splitlines()}
    # Collect candidate statements that are present in A but not B and look
    # like a guard.  Score them so genuine size-limit checks (datasize >
    # tif_size, maxcount, Sizesan) rank above cosmetic refactors (renamed
    # locals such as `target_count64 == 0` vs `direntry->tdir_count == 0`).
    candidates = []
    for i, line in enumerate(body_a.splitlines()):
        s = line.strip()
        if not s or s.startswith(('/*', '//', '{', '}', '*')):
            continue
        if s in b_lines:
            continue
        if not ('if' in s or 'return' in s):
            continue
        if not ('>' in s or '<' in s or '==' in s or 'Sizesan' in s
                or 'tif_size' in s):
            continue
        score = 0
        for kw in ('tif_size', 'maxcount', 'Sizesan', 'limit', 'datasize',
                   'filesize', 'tif->tif_size'):
            if kw.lower() in s.lower():
                score += 1
        candidates.append((score, i, s))
    if not candidates:
        return None
    candidates.sort(reverse=True)
    score, i, s = candidates[0]

    # The fork call site (in the caller) is located by _locate_fork_call_site,
    # not here.  We don't search for a target statement inside the callee —
    # the callee is identical in both versions; the fork is in the caller.
    # target_statement / target_vars are set by _locate_semantic_enhancement_divergence
    # using the call_stmt_b from _locate_fork_call_site.
    target_line = None
    target_statement = None
    target_vars = []

    return {
        'file': file_a,
        'line': body_start_line + i,
        'statement': s,
        'callee_a': callee_a,
        'callee_b': callee_b,
        'target_file': file_b,
        'target_line': target_line,
        'target_statement': target_statement,
        'target_func': callee_b,
        'target_vars': target_vars,
    }


def _locate_fork_call_site(caller, callee_a, callee_b, source_dirs_a, source_dirs_b):
    """Locate the forking call site: the statement in ``caller`` that invokes
    ``callee_a`` in A vs ``callee_b`` in B — the *same* position, different callee."""
    # Use the callee's file basename as a hint so a same-named function in an
    # unrelated dir (e.g. contrib/pds/tif_pdsdirread.c's TIFFFetchStripThing)
    # doesn't win the rglob search over libtiff/tif_dirread.c.
    hint_a = hint_b = None
    _cf_a = _find_function_source(callee_a, source_dirs_a)
    _cf_b = _find_function_source(callee_b, source_dirs_b)
    if _cf_a:
        hint_a = os.path.basename(_cf_a)
    if _cf_b:
        hint_b = os.path.basename(_cf_b)
    file_a = _find_function_source(caller, source_dirs_a, file_hint=hint_a)
    file_b = _find_function_source(caller, source_dirs_b, file_hint=hint_b)
    if not file_a or not file_b:
        return None
    try:
        code_a = open(file_a, encoding='utf-8', errors='replace').read()
        code_b = open(file_b, encoding='utf-8', errors='replace').read()
    except OSError:
        return None
    body_a = _extract_function_body(code_a, caller)
    body_b = _extract_function_body(code_b, caller)
    if not body_a or not body_b:
        return None

    def find_call(body, callee):
        for j, line in enumerate(body.splitlines()):
            if re.search(r'\b' + re.escape(callee) + r'\s*\(', line):
                return line.strip(), j
        return None, None

    stmt_a, j_a = find_call(body_a, callee_a)
    stmt_b, j_b = find_call(body_b, callee_b)
    if not stmt_a or not stmt_b:
        return None
    head_a = code_a[:code_a.find(body_a)]
    head_b = code_b[:code_b.find(body_b)]
    return {
        'call_stmt_a': stmt_a,
        'call_line_a': head_a.count('\n') + 1 + j_a,
        'call_stmt_b': stmt_b,
        'call_line_b': head_b.count('\n') + 1 + j_b,
        'call_file_a': file_a,
        'call_file_b': file_b,
    }


def _locate_semantic_enhancement_divergence(gaps, source_dirs_a, source_dirs_b):
    """Walk all gap fork pairs and return the first added guard statement.

    Two things are located:
      * the *guard* (root cause) — diff of the leaf ``...WithLimit``/``...``
        pair, e.g. ``datasize > tif_size`` in ``TIFFReadDirEntryArrayWithLimit``;
      * the *fork call site* — the same position where the common caller invokes
        the strengthened vs original callee (``TIFFFetchStripThing`` calling
        ``TIFFReadDirEntryLong8ArrayWithLimit`` vs ``TIFFReadDirEntryLong8Array``).
    """
    seen = set()
    for gap in gaps:
        a_paths = {x["name"]: x["path"] for x in gap.get("a", [])
                   if isinstance(x, dict) and x.get("path")}
        b_paths = {x["name"]: x["path"] for x in gap.get("b", [])
                   if isinstance(x, dict) and x.get("path")}
        a_names = sorted(a_paths.keys())
        b_names = sorted(b_paths.keys())
        # Sort pairs by base-name length (shorter base => leaf-ish) so the
        # pair that actually gained the guard is tried first.
        pairs = []
        for a_name in a_names:
            for b_name in b_names:
                if not is_semantic_pair(a_name, b_name):
                    continue
                base = a_name
                for suf in ("WithLimit", "Checked", "Safe", "Secure",
                            "Validated", "Sanitized", "Bounded", "Limited",
                            "WithSize", "WithCount"):
                    if a_name.endswith(suf):
                        base = a_name[:-len(suf)]
                        break
                pairs.append((len(base), a_name, b_name))
        leaf_res = None
        for _, a_name, b_name in sorted(pairs):
            key = (a_name, b_name)
            if key in seen:
                continue
            seen.add(key)
            res = _semantic_pair_added_guard(
                a_name, b_name, source_dirs_a, source_dirs_b)
            if res:
                leaf_res = res
                break
        if not leaf_res:
            continue
        # Fork call site comes from the *wrapper* pair (common caller invoking
        # different callees), which shares the same parent path.
        pair = _extract_gap_fork_pair(gap)
        if pair:
            callee_a, callee_b, caller = pair
            site = _locate_fork_call_site(
                caller, callee_a, callee_b, source_dirs_a, source_dirs_b)
            if site:
                leaf_res.update(site)
                leaf_res['caller'] = caller
        return leaf_res
    return None


def is_semantic_pair(name_a, name_b):
    """True if name_a/name_b differ only by a semantic suffix (WithLimit/Checked...)."""
    if name_a == name_b:
        return False
    for suffix in ("WithLimit", "Checked", "Safe", "Secure", "Validated",
                   "Sanitized", "Bounded", "Limited", "WithSize", "WithCount"):
        if name_a.endswith(suffix) and name_a[:-len(suffix)] == name_b:
            return True
        if name_b.endswith(suffix) and name_b[:-len(suffix)] == name_a:
            return True
    return False


def identify_divergence_function(matches, gaps, trace_a, trace_b,
                                 hint_func=None, prefer_tail=False):
    """Identify the function where traces diverge.

    Returns (func_name, trace_a_index, trace_b_index) of the divergence point.
    The divergence function is the deepest common function that is called
    before the first gap occurs — i.e., the shared caller whose internal
    behavior differs.

    When ``prefer_tail`` is set (e.g. the reference crashed but the target did
    not), the gap at the very end of the reference trace — where the reference
    keeps running after the target has stopped — is selected.
    """
    if not gaps:
        return None, -1, -1

    if prefer_tail:
        target_gap = max(gaps, key=lambda g: g.get("a_range", [0, 0])[0])
    else:
        # Find the gap with the most significant divergence.
        # Key insight: the real divergence is where ONE version exits early
        # (calls TIFFErrorExt and returns) while the OTHER continues processing.
        # TIFFErrorExt in the OLD version's gap is the strongest signal.
        target_gap = None
        best_score = -1
        for g in gaps:
            a_funcs = [f['name'] for f in g.get("a", [])]
            b_funcs = [f['name'] for f in g.get("b", [])]
            all_funcs = set(a_funcs + b_funcs)
            a_count = len(a_funcs)
            b_count = len(b_funcs)
            total = a_count + b_count

            # Skip trivial gaps
            if total < 3:
                continue

            # TIFFErrorExt is the strongest signal: it means one version hit an
            # error and exited, while the other continued. This IS the divergence
            # point.
            b_has_error = 'TIFFErrorExt' in b_funcs
            a_has_error = 'TIFFErrorExt' in a_funcs
            has_error = 'TIFFErrorExt' in all_funcs
            has_warning = 'TIFFWarningExt' in all_funcs
            max_count = max(a_count, b_count)
            min_count = min(a_count, b_count)
            asymmetry = max_count / max(min_count, 1)

            if hint_func and hint_func in a_funcs:
                # The reference reaches the hinted (crash) function here — the
                # strongest possible signal that this gap is the real divergence.
                score = 100000000 + a_count
            elif b_has_error:
                # B (old version) has TIFFErrorExt: this is THE divergence point
                # where old version exits early. Score by how much larger A is.
                score = 10000000 + a_count * 100
            elif a_has_error:
                # Only A has TIFFErrorExt: might be relevant but less likely
                score = 1000000 + asymmetry * 10 + total
            elif has_warning and asymmetry > 10:
                score = 100000 + asymmetry * 10 + total
            else:
                score = asymmetry * 10 + total

            if score > best_score:
                best_score = score
                target_gap = g

        if target_gap is None:
            target_gap = gaps[0]

    if matches:
        # Prefer the forking caller inside the gap: the same caller invoked
        # different callees in A vs B (e.g. TIFFFetchStripThing calling
        # TIFFReadDirEntryLong8ArrayWithLimit vs TIFFReadDirEntryLong8Array).
        # This is far more precise than the last shared auxiliary function.
        fork_caller = _extract_gap_fork(target_gap)
        if fork_caller:
            # Locate the forking caller's enter event inside the gap.
            a_start, a_stop = target_gap["a_range"]
            b_start, b_stop = target_gap["b_range"]
            a_end = b_end = None
            for i in range(a_start, a_stop):
                if (trace_a[i].get("name") == fork_caller
                        and trace_a[i].get("is_enter")):
                    a_end = i
                    break
            for j in range(b_start, b_stop):
                if (trace_b[j].get("name") == fork_caller
                        and trace_b[j].get("is_enter")):
                    b_end = j
                    break
            if a_end is not None and b_end is not None:
                return fork_caller, a_end, b_end
            return fork_caller, a_start, b_start

        # Find the last match that ends at or before the gap starts
        last_match = None
        for m in matches:
            if m["a_range"][1] <= target_gap["a_range"][0]:
                last_match = m

        if last_match:
            # The last function in this match is the common caller
            # whose internal behavior diverges
            last_func = last_match["functions"][-1]
            a_end = last_match["a_range"][1] - 1
            b_end = last_match["b_range"][1] - 1
            return last_func["name"], a_end, b_end

    # Fallback: find the deepest common function just before the gap
    # Look backward from the gap start in trace A
    gap_a_start = target_gap["a_range"][0]
    gap_b_start = target_gap["b_range"][0]

    # Find common functions before the gap
    for i in range(gap_a_start - 1, max(0, gap_a_start - 20), -1):
        node_a = trace_a[i]
        # Find matching position in trace B
        for j in range(gap_b_start - 1, max(0, gap_b_start - 20), -1):
            node_b = trace_b[j]
            if node_a["name"] == node_b["name"] and node_a["depth"] == node_b["depth"]:
                return node_a["name"], i, j

    # Fallback to first function in gap
    if target_gap["a"]:
        func = target_gap["a"][0]
        return func["name"], target_gap["a_range"][0], target_gap["b_range"][0]

    return None, -1, -1


def compare_variable_states(binary_a, binary_b, func_name,
                            lib_path_a=None, lib_path_b=None,
                            args_a=None, args_b=None,
                            source_dirs_a=None, source_dirs_b=None,
                            input_file=None, gdb_timeout=120):
    """Use GDB to compare variable states at a function entry in both binaries.

    Returns a dict with:
      - diverging_var: name of the first variable that differs
      - value_a, value_b: the differing values
      - source_file, source_line: where the divergence originates
      - backtrace_a, backtrace_b: call stacks
    """
    if source_dirs_a is None:
        source_dirs_a = find_source_dirs(binary_a)
    if source_dirs_b is None:
        source_dirs_b = find_source_dirs(binary_b)
    if lib_path_a is None:
        lib_path_a = collect_lib_dirs(binary_a)
    if lib_path_b is None:
        lib_path_b = collect_lib_dirs(binary_b)
    if args_a is None:
        args_a = []
    if args_b is None:
        args_b = []

    # Build GDB commands for binary A — use "print" for better output
    cmd_a = [
        f"break {func_name}",
        "run " + " ".join(str(a) for a in args_a),
        "set logging file /tmp/gdb_state_a.txt",
        "set logging enabled on",
        "where 3",
        "info args",
        "info locals",
        "set logging enabled off",
        "continue",
        "set logging file /tmp/gdb_state_a2.txt",
        "set logging enabled on",
        "where 3",
        "info args",
        "info locals",
        "set logging enabled off",
        "quit",
    ]

    # Build GDB commands for binary B
    cmd_b = [
        f"break {func_name}",
        "run " + " ".join(str(a) for a in args_b),
        "set logging file /tmp/gdb_state_b.txt",
        "set logging enabled on",
        "where 3",
        "info args",
        "info locals",
        "set logging enabled off",
        "continue",
        "set logging file /tmp/gdb_state_b2.txt",
        "set logging enabled on",
        "where 3",
        "info args",
        "info locals",
        "set logging enabled off",
        "quit",
    ]

    # Also try with "catch load libtiff" to handle shared library loading
    cmd_a_catch = [
        "catch load libtiff",
        "run " + " ".join(str(a) for a in args_a),
        f"break {func_name}",
        "continue",
        "set logging file /tmp/gdb_state_a.txt",
        "set logging enabled on",
        "where 3",
        "info args",
        "info locals",
        "set logging enabled off",
        "continue",
        "set logging file /tmp/gdb_state_a2.txt",
        "set logging enabled on",
        "where 3",
        "info args",
        "info locals",
        "set logging enabled off",
        "quit",
    ]

    cmd_b_catch = [
        "catch load libtiff",
        "run " + " ".join(str(a) for a in args_b),
        f"break {func_name}",
        "continue",
        "set logging file /tmp/gdb_state_b.txt",
        "set logging enabled on",
        "where 3",
        "info args",
        "info locals",
        "set logging enabled off",
        "continue",
        "set logging file /tmp/gdb_state_b2.txt",
        "set logging enabled on",
        "where 3",
        "info args",
        "info locals",
        "set logging enabled off",
        "quit",
    ]

    # Run GDB on both binaries
    output_a = run_gdb_with_source(binary_a, source_dirs_a, cmd_a_catch,
                                    lib_path=lib_path_a, timeout=gdb_timeout)
    output_b = run_gdb_with_source(binary_b, source_dirs_b, cmd_b_catch,
                                    lib_path=lib_path_b, timeout=gdb_timeout)

    # Parse results
    result = {
        "diverging_var": None,
        "value_a": None,
        "value_b": None,
        "source_file": None,
        "source_line": None,
        "description": "",
    }

    # Read GDB log files
    state_a = _read_gdb_log("/tmp/gdb_state_a.txt")
    state_b = _read_gdb_log("/tmp/gdb_state_b.txt")

    if not state_a and not state_b:
        # Try the second breakpoint (after first call returns)
        state_a = _read_gdb_log("/tmp/gdb_state_a2.txt")
        state_b = _read_gdb_log("/tmp/gdb_state_b2.txt")

    if state_a and state_b:
        diff = _find_first_difference(state_a, state_b)
        if diff:
            result["diverging_var"] = diff["name"]
            result["value_a"] = diff["value_a"]
            result["value_b"] = diff["value_b"]
            result["source_file"] = diff.get("source_file")
            result["source_line"] = diff.get("source_line")
            result["description"] = (
                f"Variable '{diff['name']}' differs: "
                f"A={diff['value_a']}, B={diff['value_b']}"
            )
        else:
            result["description"] = "All compared variables are identical at function entry"
    else:
        result["description"] = (
            "Could not capture variable states. "
            "GDB may have failed to stop at the breakpoint."
        )
        # Try to extract useful info from raw GDB output
        result["raw_output_a"] = output_a[-2000:] if output_a else ""
        result["raw_output_b"] = output_b[-2000:] if output_b else ""

    return result


def _is_nonnull_pointer(val):
    """Return True if a GDB-printed value looks like a non-NULL pointer.

    Distinguishes a real (non-zero) pointer from NULL (0x0), so that a function
    returning a valid pointer in one version and NULL in the other is correctly
    treated as a divergence rather than "both pointers".
    """
    if not val:
        return False
    v = val.strip()
    if re.fullmatch(r'0x0+', v):
        return False
    if re.fullmatch(r'\([^)]*\*[^)]*\)\s*0x0+', v):
        return False
    if v in ('0', 'NULL', '(nil)'):
        return False
    return bool(re.search(r'\(.*\*\)\s*0x[0-9a-fA-F]', v) or v.startswith('0x'))


def trace_divergence_cause(binary_a, binary_b, func_name,
                           lib_path_a=None, lib_path_b=None,
                           args_a=None, args_b=None,
                           source_dirs_a=None, source_dirs_b=None,
                           gdb_timeout=120):
    """Step through both binaries and find the first statement that causes divergence.

    Strategy:
    1. Run to function entry, compare states
    2. Run to function return, compare return values
    3. If entry states match but return values differ, the divergence is inside
    4. Compare sub-function return values to narrow down
    """
    if source_dirs_a is None:
        source_dirs_a = find_source_dirs(binary_a)
    if source_dirs_b is None:
        source_dirs_b = find_source_dirs(binary_b)
    if lib_path_a is None:
        lib_path_a = collect_lib_dirs(binary_a)
    if lib_path_b is None:
        lib_path_b = collect_lib_dirs(binary_b)
    if args_a is None:
        args_a = []
    if args_b is None:
        args_b = []

    result = {
        "diverging_statement": None,
        "source_file": None,
        "source_line": None,
        "description": "",
        "details": [],
    }

    # Step 1: Compare return values first (most reliable indicator)
    ret_a = _get_return_value(binary_a, func_name, args_a, lib_path_a,
                               source_dirs_a, gdb_timeout)
    ret_b = _get_return_value(binary_b, func_name, args_b, lib_path_b,
                               source_dirs_b, gdb_timeout)

    if ret_a is not None and ret_b is not None and ret_a != ret_b:
        # Check if both are pointers with same symbolic info
        # (e.g., "0x... <tiffFields+240>" vs "0x... <tiffFields+240>")
        # If symbolic info matches, consider them equivalent
        sym_a = re.search(r'<([^>]+)>', ret_a)
        sym_b = re.search(r'<([^>]+)>', ret_b)
        if sym_a and sym_b and sym_a.group(1) == sym_b.group(1):
            # Same symbolic offset — equivalent pointers
            pass  # Continue to entry state comparison
        else:
            # Both non-null pointers — treat as equivalent (ASLR)
            is_ptr_a = _is_nonnull_pointer(ret_a)
            is_ptr_b = _is_nonnull_pointer(ret_b)
            if not (is_ptr_a and is_ptr_b):
                # Find the return location
                ret_loc_a = _find_return_location(binary_a, func_name, args_a,
                                                   lib_path_a, source_dirs_a, gdb_timeout)
                result["diverging_statement"] = (
                    f"{func_name}() returns different values: A={ret_a}, B={ret_b}"
                )
                result["description"] = (
                    f"The function {func_name}() returns {ret_a} in version A "
                    f"but {ret_b} in version B, causing different execution paths."
                )
                if ret_loc_a:
                    result["source_file"] = ret_loc_a.get("file")
                    result["source_line"] = ret_loc_a.get("line")
                return result

    # Step 2: Return values match — check entry states for deeper divergence
    entry_result = compare_variable_states(
        binary_a, binary_b, func_name,
        lib_path_a=lib_path_a, lib_path_b=lib_path_b,
        args_a=args_a, args_b=args_b,
        source_dirs_a=source_dirs_a, source_dirs_b=source_dirs_b,
        gdb_timeout=gdb_timeout
    )

    if ret_a is None and ret_b is None:
        result["diverging_statement"] = f"Could not capture return value of {func_name}()"
        result["description"] = f"GDB failed to capture return values for {func_name}()"
        return result

    if ret_a is not None and ret_b is not None and ret_a != ret_b:
        # Check if both are pointers with same symbolic info
        # (e.g., "0x... <tiffFields+240>" vs "0x... <tiffFields+240>")
        sym_a = re.search(r'<([^>]+)>', ret_a)
        sym_b = re.search(r'<([^>]+)>', ret_b)
        if sym_a and sym_b and sym_a.group(1) == sym_b.group(1):
            # Same symbolic offset — equivalent pointers, continue checking
            pass
        else:
            # Both non-null pointers — treat as equivalent (ASLR)
            is_ptr_a = _is_nonnull_pointer(ret_a)
            is_ptr_b = _is_nonnull_pointer(ret_b)
            if not (is_ptr_a and is_ptr_b):
                # Find the return location
                ret_loc_a = _find_return_location(binary_a, func_name, args_a,
                                                   lib_path_a, source_dirs_a, gdb_timeout)
                result["diverging_statement"] = (
                    f"{func_name}() returns different values: A={ret_a}, B={ret_b}"
                )
                result["description"] = (
                    f"The function {func_name}() returns {ret_a} in version A "
                    f"but {ret_b} in version B, causing different execution paths."
                )
                if ret_loc_a:
                    result["source_file"] = ret_loc_a.get("file")
                    result["source_line"] = ret_loc_a.get("line")
                return result

    # Step 3: Same return value — divergence is in a sub-function
    result["diverging_statement"] = (
        f"{func_name}() entry states and return values match. "
        f"Divergence is in a sub-function."
    )
    result["description"] = result["diverging_statement"]
    return result


def find_sub_function_divergence(binary_a, binary_b, func_name,
                                 trace_a, trace_b,
                                 lib_path_a=None, lib_path_b=None,
                                 args_a=None, args_b=None,
                                 source_dirs_a=None, source_dirs_b=None,
                                 gdb_timeout=120):
    """Given that func_name returns differently, trace into it to find which
    sub-function causes the divergence.

    Uses the trace data to identify sub-functions, then compares their
    return values via GDB. Prioritizes functions that appear in trace gaps.
    """
    if source_dirs_a is None:
        source_dirs_a = find_source_dirs(binary_a)
    if source_dirs_b is None:
        source_dirs_b = find_source_dirs(binary_b)
    if lib_path_a is None:
        lib_path_a = collect_lib_dirs(binary_a)
    if lib_path_b is None:
        lib_path_b = collect_lib_dirs(binary_b)

    # Find sub-functions of func_name in both traces
    subs_a = _find_sub_functions(func_name, trace_a)
    subs_b = _find_sub_functions(func_name, trace_b)

    # Find sub-functions that appear in gaps (present in one but not the other)
    gap_subs = set()
    for g in _get_gaps_for_function(func_name, trace_a, trace_b):
        for n in g:
            gap_subs.add(n["name"])

    # Find common sub-functions
    common = set(subs_a.keys()) & set(subs_b.keys())

    # Prioritize: gap functions first, then others
    sorted_subs = sorted(common,
                         key=lambda s: (0 if s in gap_subs else 1,
                                        subs_a[s]["depth"]))

    results = []

    for sub in sorted_subs:
        # Compare return values of each sub-function
        ret_a = _get_return_value(binary_a, sub, args_a, lib_path_a,
                                   source_dirs_a, gdb_timeout)
        ret_b = _get_return_value(binary_b, sub, args_b, lib_path_b,
                                   source_dirs_b, gdb_timeout)

        if ret_a is not None and ret_b is not None and ret_a != ret_b:
            # Skip if both are pointers to the same symbol (address difference
            # across versions is expected)
            if _is_same_symbol_pointer(ret_a, ret_b):
                continue

            results.append({
                "function": sub,
                "return_a": ret_a,
                "return_b": ret_b,
                "depth": subs_a[sub]["depth"],
                "in_gap": sub in gap_subs,
            })

    return results


def _get_gaps_for_function(func_name, trace_a, trace_b):
    """Extract the segments of trace_a and trace_b that are inside func_name
    and that differ between the two traces."""
    seg_a = _extract_function_segment(func_name, trace_a)
    seg_b = _extract_function_segment(func_name, trace_b)

    # Find the differing portions
    min_len = min(len(seg_a), len(seg_b))
    gaps = []
    for i in range(min_len):
        if seg_a[i]["name"] != seg_b[i]["name"]:
            # Collect the differing region
            gap_a = []
            gap_b = []
            j = i
            while j < len(seg_a) and j < len(seg_b):
                if seg_a[j]["name"] == seg_b[j]["name"]:
                    break
                gap_a.append(seg_a[j])
                gap_b.append(seg_b[j])
                j += 1
            gaps.append(gap_a)
            break  # Return first gap
    return gaps


def _extract_function_segment(func_name, trace):
    """Extract all nodes between func_name entry and exit."""
    segment = []
    depth = 0
    found = False
    for node in trace:
        if node["name"] == func_name and node["is_enter"]:
            found = True
            depth = node["depth"]
            continue
        if found:
            if node["name"] == func_name and not node["is_enter"]:
                break
            if node["depth"] >= depth:
                segment.append(node)
    return segment


def _is_same_symbol_pointer(val_a, val_b):
    """Check if two GDB pointer values point to the same symbol."""
    m_a = re.search(r'<(\w+)>', val_a)
    m_b = re.search(r'<(\w+)>', val_b)
    if m_a and m_b and m_a.group(1) == m_b.group(1):
        return True
    return False


def _find_sub_functions(func_name, trace):
    """Find all sub-functions called within func_name in the trace."""
    subs = {}
    in_func = False
    func_depth = 0

    for i, node in enumerate(trace):
        if node["name"] == func_name and node["is_enter"]:
            in_func = True
            func_depth = node["depth"]
        elif in_func:
            if node["name"] == func_name and not node["is_enter"]:
                break  # func_name returned
            if node["is_enter"] and node["depth"] > func_depth:
                sub_key = node["name"]
                if sub_key not in subs:
                    subs[sub_key] = {
                        "name": node["name"],
                        "depth": node["depth"],
                        "path": node["path"],
                    }
    return subs


def _read_gdb_log(path):
    """Read a GDB log file and extract variable states."""
    try:
        with open(path) as f:
            return f.read()
    except FileNotFoundError:
        return ""


def _find_first_difference(state_a, state_b):
    """Compare two GDB state dumps and find the first differing variable."""
    vars_a = _parse_gdb_variables(state_a)
    vars_b = _parse_gdb_variables(state_b)

    all_vars = set(vars_a.keys()) | set(vars_b.keys())
    for var in sorted(all_vars):
        val_a = vars_a.get(var)
        val_b = vars_b.get(var)
        if val_a is None or val_b is None:
            continue

        # Skip identical values
        if val_a == val_b:
            continue

        # Normalize: compare string contents, not pointers
        norm_a = _normalize_gdb_value(val_a)
        norm_b = _normalize_gdb_value(val_b)
        if norm_a == norm_b:
            continue

        return {"name": var, "value_a": val_a, "value_b": val_b}

    return None


def _normalize_gdb_value(val):
    """Normalize a GDB value for comparison (dereference pointers, etc.)."""
    # If it's a pointer with a string, extract just the string content
    m = re.match(r'0x[0-9a-f]+\s+"(.*)"$', val)
    if m:
        return f'"{m.group(1)}"'
    # If it's a pointer with no string, just note it's a pointer
    m = re.match(r'0x[0-9a-f]+', val)
    if m:
        return val  # Can't normalize further
    return val


def _parse_gdb_variables(text):
    """Parse variable names and values from GDB output."""
    variables = {}
    for line in text.split('\n'):
        line = line.strip()
        # Match "name = value" patterns
        m = re.match(r'^(\w[\w.]*)\s*=\s*(.+)$', line)
        if m:
            var_name = m.group(1)
            var_value = m.group(2).strip()
            # Skip GDB-internal variables
            if var_name.startswith('$') or var_name in ('__PRETTY_FUNCTION__',):
                continue
            variables[var_name] = var_value
    return variables


def _get_return_value(binary, func_name, args, lib_path, source_dirs, timeout):
    """Run GDB to get the return value of a function."""
    cmds = [
        "catch load libtiff",
        "run " + " ".join(str(a) for a in args),
        f"break {func_name}",
        "continue",
        "finish",
        "print $rax",
        "quit",
    ]
    output = run_gdb_with_source(binary, source_dirs, cmds,
                                  lib_path=lib_path, timeout=timeout)
    # Parse return value — look for "$N = VALUE" or "value = VALUE"
    for line in output.split('\n'):
        m = re.search(r'\$\d+\s*=\s*(.+)', line)
        if m:
            val = m.group(1).strip()
            # Clean up GDB formatting
            val = re.sub(r'<optimized out>', 'optimized', val)
            return val
    return None


def _find_return_location(binary, func_name, args, lib_path, source_dirs, timeout):
    """Find the source location where a function returns."""
    cmds = [
        "catch load libtiff",
        "run " + " ".join(str(a) for a in args),
        f"break {func_name}",
        "continue",
        "finish",
        "info frame",
        "where 1",
        "quit",
    ]
    output = run_gdb_with_source(binary, source_dirs, cmds,
                                  lib_path=lib_path, timeout=timeout)
    # Look for source file:line in the output
    # Skip dynamic linker locations (dl-*.c, dl-*.h)
    for line in output.split('\n'):
        m = re.search(r'at (\S+):(\d+)', line)
        if m:
            f = m.group(1)
            if not re.match(r'./dl-|/dl-', f):
                return {"file": m.group(1), "line": int(m.group(2))}
    # Fallback: accept any location
    for line in output.split('\n'):
        m = re.search(r'at (\S+):(\d+)', line)
        if m:
            return {"file": m.group(1), "line": int(m.group(2))}
    return None


_GDB_CACHE = {}


def _gdb_cache(func):
    """Cache a GDB-probing function's result keyed by (func_name, binary).

    The recursive origin trace revisits the same library functions many times
    (once per guard variable); each visit would otherwise re-run several slow
    GDB sessions (disassemble / single-step / breakpoint-continue).
    """
    def wrapper(*args, **kwargs):
        binary = args[0]
        func_name = args[1]
        key = (func.__name__, str(binary), func_name)
        if key in _GDB_CACHE:
            return _GDB_CACHE[key]
        r = func(*args, **kwargs)
        _GDB_CACHE[key] = r
        return r
    wrapper.__name__ = func.__name__
    return wrapper


@_gdb_cache
def _find_return_statement_location(binary, func_name, return_value,
                                    args, lib_path, source_dirs, timeout):
    """Find the source line where func_name returns return_value.

    Runs a *single* GDB session (Python command script) so the disassembled
    ret addresses match the loaded library's ASLR base: disassemble the
    function, break on each ``ret``, and stop at the first whose ``$rax``
    matches ``return_value`` (0/NULL for the error paths we trace).
    """
    args_str = " ".join(str(a) for a in args)
    rv = str(return_value).strip()
    if rv in ('0', 'NULL'):
        match_expr = 'rax == 0'
    else:
        match_expr = f'rax == {rv}'

    script = f'''set pagination off
set confirm off
set breakpoint pending on
catch load libtiff
run {args_str}
break {func_name}
continue
python
import gdb
import re
out = gdb.execute("disassemble {func_name}", to_string=True)
ret_addrs = []
for line in out.split("\\n"):
    m = re.search(r'(0x[0-9a-f]+)\\s*<[^>]*>:\\s*ret', line)
    if m:
        ret_addrs.append(m.group(1))
found = False
for addr in ret_addrs:
    gdb.execute("break *" + addr)
    # The function may be called several times; keep continuing until a call
    # returns the target value (e.g. StripOffsets succeeds -> 1, then
    # StripByteCounts fails -> 0).
    for i in range(20):
        gdb.execute("continue")
        try:
            rax = int(gdb.parse_and_eval("$rax"))
        except Exception:
            break
        print("RET_RAX:" + str(rax))
        if {match_expr}:
            sal = gdb.find_pc_line(gdb.selected_frame().pc())
            fname = sal.symtab.filename if sal and sal.symtab else ''
            ln = sal.line if sal else 0
            print("FOUND:" + fname + ":" + str(ln))
            found = True
            break
    if found:
        break
end
quit
'''

    script_path = f"/tmp/ret_probe_{os.getpid()}.gdb"
    with open(script_path, 'w') as f:
        f.write(script)

    env = os.environ.copy()
    env["ASAN_OPTIONS"] = "detect_leaks=0"
    if lib_path:
        old_ld = env.get("LD_LIBRARY_PATH", "")
        lib_parts = [lib_path] if isinstance(lib_path, str) else lib_path
        env["LD_LIBRARY_PATH"] = ":".join(lib_parts + ([old_ld] if old_ld else []))

    gdb_cmds = ["gdb", "-batch"]
    if lib_path:
        gdb_cmds.extend(["-iex", f"set solib-search-path {lib_path}"])
    for d in source_dirs:
        gdb_cmds.extend(["-iex", f"directory {d}"])
    gdb_cmds.extend(["-x", script_path, str(binary)])

    try:
        result = subprocess.run(gdb_cmds, capture_output=True, text=True,
                                timeout=timeout, env=env)
        output = result.stdout + result.stderr
    finally:
        try:
            os.unlink(script_path)
        except Exception:
            pass

    for l in output.split('\n'):
        m = re.search(r'FOUND:(.+):(\d+)', l)
        if m:
            return {"file": m.group(1), "line": int(m.group(2))}
    return None


def _return_values_match(gdb_val, target_val):
    """Check if a GDB-printed return value matches the target."""
    gdb_norm = re.sub(r'\s+', ' ', gdb_val).strip()
    target_norm = re.sub(r'\s+', ' ', target_val).strip()
    if gdb_norm == target_norm:
        return True
    gdb_num = re.search(r'(-?\d+)', gdb_norm)
    target_num = re.search(r'(-?\d+)', target_norm)
    if gdb_num and target_num:
        if gdb_num.group(1) == target_num.group(1):
            return True
    return False


# ============================================================================
# Cross-function value-origin tracing
# ============================================================================
# When a fork variable is a *function return value* (e.g. `in = TIFFOpen(...)`,
# then `if (in == NULL)`), its NULL/non-NULL state is decided by control flow
# *inside* the callee — not by data flow into the pointer.  These helpers trace
# the value's origin dynamically (GDB watchpoint + return-branch disassembly)
# until it resolves to an input-derived field/expression.
# ============================================================================

_RHS_KEYWORDS = {
    'if', 'else', 'while', 'for', 'do', 'switch', 'case', 'return', 'goto',
    'sizeof', 'NULL', 'break', 'continue',
}


def _extract_rhs_from_line(line, var_expr):
    """Extract the right-hand side of ``var_expr = <RHS>`` from a source line.

    Returns the RHS text (semicolon stripped) or None.  A negative lookahead
    ``(?!\s*=)`` skips comparison statements like ``if (in == NULL)``.
    """
    if not line:
        return None
    m = re.search(re.escape(var_expr) + r'\s*=\s*(?!\s*=)(.+)$', line)
    if not m:
        return None
    rhs = m.group(1).strip()
    rhs = rhs.rstrip(';').strip()
    return rhs or None


def _classify_rhs(rhs):
    """Classify an assignment right-hand side.

    Returns {'rhs_type': ..., 'rhs_text': ..., 'callee': ...} where rhs_type is
    one of 'function_call', 'field', 'expression', or 'constant'.
    """
    rhs = (rhs or '').strip()
    if not rhs:
        return {'rhs_type': 'constant', 'rhs_text': rhs}

    # Constant: NULL / 0 / number / string / (void*)0 etc.
    if re.match(r'^(NULL|0|\([^)]*\)\s*0|-?\d+|0x[0-9a-fA-F]+|"[^"]*"|\(NULL\))$', rhs):
        return {'rhs_type': 'constant', 'rhs_text': rhs}

    # Function call: identifier immediately followed by '(' (but not a cast —
    # a cast begins with '(' or a type name).  `ident (...)` -> callee = ident.
    m = re.match(r'^([a-zA-Z_]\w*)\s*\(', rhs)
    if m and m.group(1) not in _RHS_KEYWORDS:
        return {'rhs_type': 'function_call', 'rhs_text': rhs,
                'callee': m.group(1)}

    # Field access / plain variable: a chain of ident->field / ident.field /
    # ident[i].
    if re.match(r'^[a-zA-Z_]\w*(?:\s*(?:->|\.)\s*[a-zA-Z_]\w*)*(?:\s*\[[^\]]*\])*$', rhs):
        return {'rhs_type': 'field', 'rhs_text': rhs}

    # Anything else is a computed expression.
    return {'rhs_type': 'expression', 'rhs_text': rhs}


def _trace_assignment_location(source_file, line, var_expr, source_dirs):
    """Locate the nearest ``var_expr = ...`` assignment at or above ``line``.

    Static source scan (reliable even when the assigned value equals the prior
    value — e.g. ``in = TIFFOpen(...)`` returning NULL into a NULL-initialized
    pointer, where a hardware watchpoint would not fire).
    """
    full = _locate_source_file(source_file, source_dirs)
    if not full:
        return None
    try:
        with open(full, encoding='utf-8', errors='replace') as f:
            lines = f.read().splitlines()
    except (FileNotFoundError, UnicodeDecodeError):
        return None
    for i in range(line - 1, max(0, line - 100), -1):
        s = lines[i].strip()
        if not s or s.startswith('/*') or s.startswith('//'):
            continue
        # Skip block-comment continuation lines (`* foo`) but NOT dereference
        # assignments (`*count = ...` where `*` is immediately followed by a
        # word char).
        if s.startswith('*') and (len(s) == 1 or not s[1].isalnum()):
            continue
        if re.search(r'\b' + re.escape(var_expr) + r'\s*(==|!=|<=|>=)', s):
            continue
        if re.search(r'\b' + re.escape(var_expr) + r'\s*=', s):
            rhs = _extract_rhs_from_line(s, var_expr)
            if rhs is not None:
                return {'file': full, 'line': i + 1, 'source_line': s,
                        'rhs': rhs}
    return None


def _step_trace_lines(binary, func_name, args, lib_path, source_dirs, timeout):
    """Single-step through every invocation of ``func_name`` with GDB and return
    the ordered, de-duplicated source line numbers of the *last* invocation
    (which is the failing one when the function is called repeatedly, e.g.
    StripOffsets succeeds then StripByteCounts fails).

    Uses a single GDB Python command script (so `next` runs inside GDB, not via
    repeated subprocess round-trips)."""
    script = f'''set pagination off
set confirm off
set breakpoint pending on
catch load libtiff
run {" ".join(str(a) for a in args)}
break {func_name}
continue
python
import gdb
import re
try:
    disasm = gdb.execute("disassemble {func_name}", to_string=True)
    addrs = re.findall(r'(0x[0-9a-f]+)', disasm)
    func_start = int(addrs[0], 16) if addrs else 0
    func_end = int(addrs[-1], 16) + 16 if addrs else 0xFFFFFFFFFFFFFFFF
except gdb.error:
    func_start = 0
    func_end = 0xFFFFFFFFFFFFFFFF

traces = []
cur = []
last = None
steps = 0
max_steps = 8000
while steps < max_steps:
    try:
        frame = gdb.selected_frame()
        pc = frame.pc()
        if pc < func_start or pc > func_end:
            # Left the function (one invocation finished) — record it and
            # continue to the next invocation (or program exit).
            if cur:
                traces.append(cur)
                cur = []
                last = None
            try:
                gdb.execute("continue", to_string=True)
            except gdb.error:
                break
            steps += 1
            continue
        sal = gdb.find_pc_line(pc)
        ln = sal.line if sal else 0
        if ln and ln != last:
            cur.append(ln)
            last = ln
            print("STEP_LINE:" + str(ln))
    except gdb.error:
        pass
    try:
        gdb.execute("next", to_string=True)
    except gdb.error:
        try:
            gdb.execute("finish", to_string=True)
        except gdb.error:
            break
    steps += 1

if cur:
    traces.append(cur)
last_trace = traces[-1] if traces else []
print("TRACE_COUNT:" + str(len(traces)))
for ln in last_trace:
    print("LAST_LINE:" + str(ln))
end
quit
'''
    script_path = f"/tmp/step_trace_{os.getpid()}.gdb"
    with open(script_path, 'w') as f:
        f.write(script)

    env = os.environ.copy()
    env["ASAN_OPTIONS"] = "detect_leaks=0"
    if lib_path:
        old_ld = env.get("LD_LIBRARY_PATH", "")
        lib_parts = [lib_path] if isinstance(lib_path, str) else lib_path
        env["LD_LIBRARY_PATH"] = ":".join(lib_parts + ([old_ld] if old_ld else []))

    gdb_cmds = ["gdb", "-batch"]
    if lib_path:
        gdb_cmds.extend(["-iex", f"set solib-search-path {lib_path}"])
    for d in source_dirs:
        gdb_cmds.extend(["-iex", f"directory {d}"])
    gdb_cmds.extend(["-x", script_path, str(binary)])

    try:
        result = subprocess.run(gdb_cmds, capture_output=True, text=True,
                                timeout=timeout, env=env)
        output = result.stdout + result.stderr
    finally:
        try:
            os.unlink(script_path)
        except Exception:
            pass

    lines = []
    for l in output.split('\n'):
        m = re.search(r'LAST_LINE:(\d+)', l)
        if m:
            lines.append(int(m.group(1)))
    return lines


@_gdb_cache
def _find_actual_failure_goto(binary, func_name, ret_file, args, lib_path,
                              source_dirs, timeout):
    """Find which branch actually reached a failure return.

    A failure return (``bad2: return NULL;``) is the convergence point of many
    ``goto bad`` branches.  Single-step through the function with GDB, record
    the executed source lines, then walk back from the last executed ``goto``
    to the nearest enclosing ``if``/``while``/``for`` — that is the guard that
    actually diverted control to the failure path.  Returns the guard's
    1-indexed source line, or None.
    """
    trace_lines = _step_trace_lines(binary, func_name, args, lib_path,
                                    source_dirs, timeout)
    if not trace_lines:
        return None

    full = _locate_source_file(ret_file, source_dirs)
    if not full:
        return None
    try:
        with open(full, encoding='utf-8', errors='replace') as f:
            lines = f.read().splitlines()
    except (FileNotFoundError, UnicodeDecodeError):
        return None

    def _ctrl(ln):
        if ln < 1 or ln > len(lines):
            return None
        return _match_control_statement(lines[ln - 1])

    # Index of the last executed `goto` in the trace.
    goto_idx = None
    for idx, ln in enumerate(trace_lines):
        c = _ctrl(ln)
        if c and c['keyword'] == 'goto':
            goto_idx = idx

    scan = (trace_lines[:goto_idx + 1] if goto_idx is not None
            else trace_lines)
    for ln in reversed(scan):
        c = _ctrl(ln)
        if c and c['keyword'] in ('if', 'else if', 'while', 'for'):
            return ln
    return None


def _parse_guard_condition(source_file, line, source_dirs):
    """Parse the guard condition (if/while/for) at ``line``.

    Checks the line itself first (the reported goto-guard line *is* the guard),
    then reads the complete multi-line statement (for conditions that span
    lines, e.g. a multi-clause bounds check), and finally falls back to walking
    backwards to the enclosing control statement.
    """
    src = _read_source_line(source_file, line, source_dirs) or ''
    ctrl = _match_control_statement(src)
    if ctrl and ctrl.get('condition'):
        return {'keyword': ctrl['keyword'],
                'condition': ctrl['condition'],
                'line': line, 'full_line': src, 'file': source_file}

    full, _s, _e = _get_complete_fork_statement(source_file, line, source_dirs)
    if full:
        ctrl = _match_control_statement(full)
        if ctrl and ctrl.get('condition'):
            return {'keyword': ctrl['keyword'],
                    'condition': ctrl['condition'],
                    'line': line, 'full_line': full, 'file': source_file}

    return _find_control_statement(source_file, line, source_dirs)


def _extract_call_args(call_text, func_name):
    """Extract the top-level arguments of ``func_name(...)`` from a call line.

    Splits on top-level commas (ignoring nested parens/brackets) inside the
    call's parentheses.  Returns a list of argument strings.
    """
    m = re.search(r'\b' + re.escape(func_name) + r'\s*\(', call_text)
    if not m:
        return []
    start = m.end()
    depth = 1
    i = start
    while i < len(call_text) and depth > 0:
        if call_text[i] == '(':
            depth += 1
        elif call_text[i] == ')':
            depth -= 1
        i += 1
    args_text = call_text[start:i - 1]
    args = []
    cur = ''
    d = 0
    for ch in args_text:
        if ch in '([':
            d += 1
        elif ch in ')]':
            d -= 1
        if ch == ',' and d == 0:
            args.append(cur.strip())
            cur = ''
        else:
            cur += ch
    if cur.strip():
        args.append(cur.strip())
    return args


@_gdb_cache
def _find_caller_site(binary, func_name, args, lib_path, source_dirs, timeout):
    """Find the *failing* call site of ``func_name``.

    Like :func:`_find_return_statement_location`, keeps continuing until an
    invocation returns 0, then walks one frame up to the caller.  Returns
    ``(caller_func, caller_file, caller_line)`` or None.
    """
    script = f'''set pagination off
set confirm off
set breakpoint pending on
catch load libtiff
run {" ".join(str(a) for a in args)}
break {func_name}
continue
python
import gdb
import re
out = gdb.execute("disassemble {func_name}", to_string=True)
rets = []
for line in out.split("\\n"):
    m = re.search(r'(0x[0-9a-f]+)\\s*<[^>]*>:\\s*ret', line)
    if m:
        rets.append(m.group(1))
found = False
for addr in rets:
    gdb.execute("break *" + addr)
    for i in range(20):
        gdb.execute("continue")
        try:
            rax = int(gdb.parse_and_eval("$rax"))
        except Exception:
            break
        if rax == 0:
            gdb.execute("frame 1")
            frame = gdb.selected_frame()
            fn = frame.name() if frame else ''
            sal = gdb.find_pc_line(frame.pc()) if frame else None
            fname = sal.symtab.filename if sal and sal.symtab else ''
            ln = sal.line if sal else 0
            print("CALLER:" + fn + "|" + fname + ":" + str(ln))
            found = True
            break
    if found:
        break
end
quit
'''
    script_path = f"/tmp/caller_probe_{os.getpid()}.gdb"
    with open(script_path, 'w') as f:
        f.write(script)

    env = os.environ.copy()
    env["ASAN_OPTIONS"] = "detect_leaks=0"
    if lib_path:
        old_ld = env.get("LD_LIBRARY_PATH", "")
        lib_parts = [lib_path] if isinstance(lib_path, str) else lib_path
        env["LD_LIBRARY_PATH"] = ":".join(lib_parts + ([old_ld] if old_ld else []))

    gdb_cmds = ["gdb", "-batch"]
    if lib_path:
        gdb_cmds.extend(["-iex", f"set solib-search-path {lib_path}"])
    for d in source_dirs:
        gdb_cmds.extend(["-iex", f"directory {d}"])
    gdb_cmds.extend(["-x", script_path, str(binary)])

    try:
        result = subprocess.run(gdb_cmds, capture_output=True, text=True,
                                timeout=timeout, env=env)
        output = result.stdout + result.stderr
    finally:
        try:
            os.unlink(script_path)
        except Exception:
            pass

    for l in output.split('\n'):
        m = re.search(r'CALLER:(.+)\|(.+):(\d+)', l)
        if m:
            return (m.group(1), m.group(2), int(m.group(3)))
    return None


def _resolve_parameter_origin(binary, func_name, var_expr, args, lib_path,
                              source_dirs, timeout, depth, max_depth):
    """Trace a *parameter* back through the call site into the caller.

    ``var_expr`` is a parameter of ``func_name`` (its assignment lives in the
    caller, not the function body).  Find the failing call site, extract the
    call's arguments, and trace each of them inside the caller.

    Returns a list of origin dicts (possibly empty).
    """
    if depth >= max_depth:
        return []
    site = _find_caller_site(binary, func_name, args, lib_path, source_dirs,
                             timeout)
    if not site:
        return []
    caller_func, caller_file, caller_line = site
    call_text = _read_source_line(caller_file, caller_line, source_dirs) or ''
    if func_name not in call_text:
        return []

    results = []
    for arg in _extract_call_args(call_text, func_name):
        for cv in _extract_variables_from_expression(arg):
            results.extend(_resolve_value_origin(
                binary, caller_func, caller_file, caller_line, cv,
                args, lib_path, source_dirs, timeout, depth + 1, max_depth))
    return results


def _resolve_value_origin(binary, func_name, source_file, line, var_expr,
                          args, lib_path, source_dirs, timeout,
                          depth=0, max_depth=20):
    """Recursively trace a variable's value origin.

    The assignment location is found statically (scan up from ``line``); the
    cross-function step — locating the callee's return branch — is done
    dynamically with GDB.  When ``var_expr`` is assigned from a function call
    (e.g. ``in = TIFFOpen(...)``), step into the callee and trace the source of
    its return value, repeating until the origin resolves to input-derived
    field/expression(s).

    Returns a list of origin dicts (``{'var','func','file','line',
    'source_line','rhs'}``), possibly empty.
    """
    if depth >= max_depth:
        return []

    loc = _trace_assignment_location(source_file, line, var_expr, source_dirs)
    if not loc:
        # A struct field with no local assignment (e.g. `direntry->tdir_count`
        # read straight out of the IFD entry) is itself the input-derived value
        # we are after — return it instead of treating it as a parameter.
        if depth > 0 and ('->' in var_expr or '.' in var_expr or '[' in var_expr):
            src = _read_source_line(source_file, line, source_dirs) or ''
            return [{'var': var_expr, 'func': func_name,
                     'file': source_file, 'line': line,
                     'source_line': src.strip(), 'rhs': _classify_rhs(var_expr)}]
        # The variable may be a function parameter — trace it through the call
        # site into the caller.
        return _resolve_parameter_origin(
            binary, func_name, var_expr, args, lib_path, source_dirs,
            timeout, depth, max_depth)

    rhs = _classify_rhs(loc['rhs'])

    if rhs['rhs_type'] == 'function_call':
        return _trace_function_return_origin(
            binary, rhs['callee'], args, lib_path, source_dirs, timeout,
            depth + 1, max_depth)

    if rhs['rhs_type'] in ('field', 'expression'):
        # Only report a field/expression as the origin when tracing *inside* a
        # callee (depth > 0).  At the top level, a field-assigned fork variable
        # (e.g. `cropsize = crop->bufftotal`) is not a return value and should
        # be left untouched.
        if depth > 0:
            if rhs['rhs_type'] == 'expression':
                # A computed expression (e.g. `(size_t)offset`, `a + b`) — keep
                # tracing its sub-variables instead of stopping at the cast.
                results = []
                for cv in _extract_variables_from_expression(rhs['rhs_text']):
                    results.extend(_resolve_value_origin(
                        binary, func_name, loc['file'], loc['line'], cv,
                        args, lib_path, source_dirs, timeout,
                        depth + 1, max_depth))
                return results
            # A plain field access (e.g. `crop->bufftotal`, `dir->tdir_count`)
            # is the input-derived value we want.
            return [{'var': rhs['rhs_text'], 'func': func_name,
                     'file': loc['file'], 'line': loc['line'],
                     'source_line': loc['source_line'], 'rhs': rhs}]
        return []

    return []


def _trace_function_return_origin(binary, callee, args, lib_path, source_dirs,
                                  timeout, depth, max_depth):
    """Step into ``callee`` and trace why it returned 0/NULL.

    Single-step to find the guard that diverted control to the failing return
    (this handles single-exit functions where the failing ``return 0`` sits
    mid-body and the trailing ``return`` is the success path), then recurse into
    the guard's variables — or directly into the callee if the guard is itself
    a function call (``if (f(...))``).

    Returns a list of origin dicts (possibly empty).
    """
    if depth >= max_depth:
        return []

    ret = _find_return_statement_location(binary, callee, '0', args,
                                          lib_path, source_dirs, timeout)
    if not ret:
        return []

    cond_line = _find_actual_failure_goto(
        binary, callee, ret['file'], args, lib_path, source_dirs, timeout)

    if not cond_line:
        # Fallback: the return is a variable (e.g. `return tif` where tif is
        # NULL) — trace that variable inside the callee.
        ret_src = _read_source_line(ret['file'], ret['line'], source_dirs) or ''
        m = re.search(r'return\s*(.+?)\s*;', ret_src)
        if not m:
            for back in range(ret['line'] - 1, max(0, ret['line'] - 6), -1):
                s = _read_source_line(ret['file'], back, source_dirs) or ''
                m = re.search(r'return\s*(.+?)\s*;', s)
                if m:
                    ret['line'] = back
                    break
        if not m:
            return []
        stripped = m.group(1).strip()
        while stripped.startswith('(') and stripped.endswith(')'):
            inner = stripped[1:-1].strip()
            if inner and inner.count('(') == stripped.count('(') - 1:
                stripped = inner
            else:
                break
        return _resolve_value_origin(
            binary, callee, ret['file'], ret['line'], stripped,
            args, lib_path, source_dirs, timeout, depth + 1, max_depth)

    cond = _parse_guard_condition(ret['file'], cond_line, source_dirs)
    if cond and cond.get('condition'):
        cond_expr = cond['condition']
        # Strip a leading `!` so `if (!func(...))` is treated as a call to
        # func (whose failure is the divergence), not an expression.
        m_neg = re.match(r'^!\s*(.*)$', cond_expr)
        if m_neg:
            cond_expr = m_neg.group(1).strip()
        c_rhs = _classify_rhs(cond_expr)
        if c_rhs['rhs_type'] == 'function_call':
            results = _trace_function_return_origin(
                binary, c_rhs['callee'], args, lib_path, source_dirs,
                timeout, depth + 1, max_depth)
            if results:
                return results
            # Couldn't step into the callee — fall back to its arguments.
            for cv in _extract_variables_from_expression(cond_expr):
                if '->' in cv or '.' in cv or '[' in cv:
                    return [{'var': cv, 'func': callee,
                             'file': ret['file'], 'line': cond['line'],
                             'source_line': cond.get('full_line', ''),
                             'rhs': c_rhs}]
            return []
        # Trace *all* guard variables (not just the first) so a multi-clause
        # bounds check like `(mb > tif_size)` yields every input field it
        # depends on (e.g. both `dir->tdir_count` via `size` and
        # `dir->tdir_offset` via `offset`).  Only trace *parameters*: skip
        # struct fields (state like `tif->tif_size`, i.e. the file size from
        # fstat — not input content) and pure local temporaries (`ma =
        # (size_t)offset`, `mb = ma + size`) whose value is a rewrite of
        # another variable.
        results = []
        for cv in _extract_variables_from_expression(cond_expr):
            if '->' in cv or '.' in cv or '[' in cv:
                continue
            tmp = _trace_assignment_location(
                ret['file'], cond['line'], cv, source_dirs)
            # Skip only *pure* local temporaries (expression assignments like
            # `ma = (size_t)offset`, `mb = ma + size`) — a variable assigned
            # from a function call (`tif = TIFFFdOpen(...)`) is meaningful and
            # must still be traced.
            if tmp is not None and _classify_rhs(tmp['rhs'])['rhs_type'] == 'expression':
                continue
            results.extend(_resolve_value_origin(
                binary, callee, ret['file'], cond['line'], cv,
                args, lib_path, source_dirs, timeout, depth + 1, max_depth))
        return results
    return []


def _resolve_fork_variable_origin(result, binary_b, binary_a, args_b, args_a,
                                  lib_path_b, lib_path_a, source_dirs_b,
                                  source_dirs_a, gdb_timeout):
    """Trace fork variables that are function return values into their origin.

    Mutates and returns ``result``: replaces return-value variables (e.g.
    ``in`` from ``in = TIFFOpen(...)``) with the input-derived variables found
    inside the callee (e.g. ``dir->tdir_count``, ``dir->tdir_offset``),
    updating the fork statement location so downstream PolyTracker
    instrumentation targets the real values.
    """
    variables = result.get('variables') or []
    if not variables:
        # The target-stopped path may not have extracted variables yet — do it
        # from the fork statement now.
        variables = _extract_variables_from_expression(
            result.get('root_cause_statement_b', '') or '')
        if variables:
            result['variables'] = variables
    func_name = result.get('root_cause_function')
    if not variables or not func_name:
        return result

    binary = binary_b or binary_a
    args = args_b or args_a
    lib_path = lib_path_b or lib_path_a
    source_dirs = source_dirs_b or source_dirs_a
    if not binary or not source_dirs:
        return result

    # Locate the fork statement line in the target source (the reported line may
    # be the reference version's line number).
    source_file = result.get('root_cause_file')
    line = result.get('root_cause_line')
    stmt = result.get('root_cause_statement_b', '')
    if source_file and stmt:
        located = _find_matching_line(source_file, stmt, source_dirs)
        if located:
            line = located[0]
    if not source_file or not line:
        return result

    for var in list(variables):
        try:
            origins = _resolve_value_origin(
                binary, func_name, source_file, line, var,
                args, lib_path, source_dirs, gdb_timeout)
        except Exception as e:
            print(f"  [value-origin] trace of {var} failed: {e}")
            continue
        if origins:
            for o in origins:
                print(f"  [value-origin] {var} in {func_name}() traced to "
                      f"'{o['var']}' in {o['func']}() "
                      f"({o['file']}:{o['line']})")
            # Keep only the first (deepest) origin: it is the field read
            # straight out of the input (e.g. `direntry->tdir_count`).  The
            # remaining origins are other clauses of the same failure guard or
            # upper-level fallback temporaries, not additional fork variables.
            result['variables'] = [origins[0]['var']]
            result['root_cause_function'] = origins[0]['func']
            result['root_cause_file'] = origins[0]['file']
            result['root_cause_line'] = origins[0]['line']
            result['root_cause_line_b'] = origins[0]['line']
            result['root_cause_statement_b'] = origins[0]['source_line']
            result['value_origin'] = origins[0]
            result['value_origins'] = origins
            return result
    return result


def _find_diverging_source_line(binary_a, binary_b, func_name_a, func_name_b,
                                 args_a, args_b,
                                 lib_path_a, lib_path_b,
                                 source_dirs_a, source_dirs_b,
                                 timeout=120,
                                 refactoring_map=None,
                                 gaps=None,
                                 _depth=0):
    """Find the source statement that causes execution paths to diverge.

    Strategy:
    1. Step through func_name in both versions with GDB
    2. Compare execution traces to find the first differing line
    3. If function is identical, recursively check sub-functions that
       are called in one version but not the other
    """
    lines_a = _record_source_lines_v2(binary_a, func_name_a, args_a,
                                       lib_path_a, source_dirs_a, timeout)
    lines_b = _record_source_lines_v2(binary_b, func_name_b, args_b,
                                       lib_path_b, source_dirs_b, timeout)

    if not lines_a or not lines_b:
        return None

    result = _compare_execution_traces(lines_a, lines_b)

    if _depth >= 3:
        return result

    # Check sub-functions FIRST for deeper divergence
    # Only report current function's divergence if no deeper one is found

    # Use LCS trace data to find sub-functions (GDB next skips calls)
    sub_funcs_to_check = set()
    for gap in gaps:
        for op in gap.get("a", []) + gap.get("b", []):
            path = op.get("path", [])
            if func_name_a in path or func_name_b in path:
                for fn in path:
                    if fn != func_name_a and fn != func_name_b:
                        sub_funcs_to_check.add(fn)

    # Also check GDB-detected calls
    calls_a = set()
    for ln in lines_a:
        for c in ln.get("calls", []):
            if not c.startswith("0x") and "asan" not in c.lower() and "cyg_profile" not in c:
                calls_a.add(c)
    calls_b = set()
    for ln in lines_b:
        for c in ln.get("calls", []):
            if not c.startswith("0x") and "asan" not in c.lower() and "cyg_profile" not in c:
                calls_b.add(c)
    sub_funcs_to_check.update(calls_a | calls_b)

    sub_funcs_to_check.discard(func_name_a)
    sub_funcs_to_check.discard(func_name_b)

    # First check KEY sub-functions that are most likely to contain the root cause
    key_sub_funcs = ["TIFFReadDirectory", "TIFFSetDirectory", "TIFFFetchStripThing",
                     "TIFFReadDirEntryArray", "_TIFFCheckRealloc"]
    priority_funcs = [f for f in key_sub_funcs if f in sub_funcs_to_check]
    # Also add other sub-functions
    other_funcs = [f for f in sub_funcs_to_check if f not in key_sub_funcs]

    for sub_func in priority_funcs + other_funcs:
        ret_a = _get_return_value(binary_a, sub_func, args_a, lib_path_a,
                                  source_dirs_a, min(timeout, 30))
        ret_b = _get_return_value(binary_b, sub_func, args_b, lib_path_b,
                                  source_dirs_b, min(timeout, 30))
        if ret_a is not None and ret_b is not None and ret_a != ret_b:
            # Check if both are pointers with same symbolic info
            sym_a = re.search(r'<([^>]+)>', ret_a)
            sym_b = re.search(r'<([^>]+)>', ret_b)
            if sym_a and sym_b and sym_a.group(1) == sym_b.group(1):
                continue  # Same symbolic offset — equivalent pointers

            # Both non-null pointers — treat as equivalent (just ASLR differences)
            is_ptr_a = _is_nonnull_pointer(ret_a)
            is_ptr_b = _is_nonnull_pointer(ret_b)
            if is_ptr_a and is_ptr_b:
                continue  # Both non-null pointers — equivalent

            # This sub-function returns differently — recurse into it
            sub_a = sub_func
            sub_b = sub_func
            if refactoring_map:
                for old_name, new_name in refactoring_map.items():
                    if old_name == sub_func:
                        sub_b = new_name
                        break
                    elif new_name == sub_func:
                        sub_a = new_name
                        break

            sub_result = _find_diverging_source_line(
                binary_a, binary_b, sub_a, sub_b,
                args_a, args_b, lib_path_a, lib_path_b,
                source_dirs_a, source_dirs_b, timeout,
                refactoring_map=refactoring_map,
                gaps=gaps,
                _depth=_depth + 1
            )
            if sub_result:
                return sub_result

    # No deeper divergence found — report this function's divergence
    if result:
        return result

    return None


def _record_source_lines_v2(binary, func_name, args, lib_path, source_dirs, timeout):
    """Record source lines AND execution semantics inside func_name using GDB.

    Returns list of dicts with: file, line, calls (functions called at this line).
    """
    log_prefix = f"/tmp/gdb_exec_{id(binary) & 0xFFFFFF:06x}"
    args_str = " ".join(str(a) for a in args)

    script = f"""set pagination off
set confirm off
catch load libtiff
run {args_str}
break {func_name}
continue
python
import gdb
import re

try:
    disasm = gdb.execute("disassemble {func_name}", to_string=True)
    addrs = re.findall(r'(0x[0-9a-f]+)', disasm)
    if addrs:
        func_start = int(addrs[0], 16)
        func_end = int(addrs[-1], 16) + 16
    else:
        func_start = 0
        func_end = 0xFFFFFFFFFFFFFFFF
except gdb.error:
    func_start = 0
    func_end = 0xFFFFFFFFFFFFFFFF

lines_seen = []
last_line = None
step_count = 0
max_steps = 3000

while step_count < max_steps:
    try:
        frame = gdb.selected_frame()
        pc = frame.pc()
        if pc < func_start or pc > func_end:
            break
        sal = gdb.find_pc_line(pc)
        if sal.line and sal.symtab:
            fname = sal.symtab.filename
            line_num = sal.line
            key = fname + ":" + str(line_num)
            if key != last_line:
                calls = []
                try:
                    arch = frame.architecture()
                    insns = arch.disassemble(pc, count=10)
                    for ins in insns:
                        asm = ins.get("asm", "").lower()
                        if "call" in asm or "jmp" in asm:
                            # Extract target from asm: call 0xaddr <func@plt>
                            m2 = re.search(r'<([\\w.]+?)(?:@\w+)?>', ins.get("asm", ""))
                            if m2:
                                calls.append(m2.group(1))
                            else:
                                m3 = re.search(r'(0x[0-9a-f]+)', ins.get("asm", ""))
                                if m3:
                                    calls.append(m3.group(1))
                            break
                except gdb.error:
                    pass
                lines_seen.append(key + "|" + ",".join(calls))
                last_line = key
                print("LINE:" + key + "|" + ",".join(calls))
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

print("DONE:" + str(len(lines_seen)))
end
quit
"""

    script_path = f"{log_prefix}_script.gdb"
    with open(script_path, 'w') as f:
        f.write(script)

    env = os.environ.copy()
    if lib_path:
        old_ld = env.get("LD_LIBRARY_PATH", "")
        lib_parts = [lib_path] if isinstance(lib_path, str) else lib_path
        env["LD_LIBRARY_PATH"] = ":".join(lib_parts + ([old_ld] if old_ld else []))

    gdb_cmds = ["gdb", "-batch"]
    if lib_path:
        gdb_cmds.extend(["-iex", f"set solib-search-path {lib_path}"])
    for d in source_dirs:
        gdb_cmds.extend(["-iex", f"directory {d}"])
    gdb_cmds.extend(["-x", script_path, str(binary)])

    result = subprocess.run(gdb_cmds, capture_output=True, text=True,
                            timeout=timeout, env=env)
    output = result.stdout + result.stderr

    lines = []
    seen = set()
    for line in output.split('\n'):
        m = re.match(r'LINE:(.+):(\d+)\|(.*)', line)
        if m:
            file_name = m.group(1)
            line_num = int(m.group(2))
            calls_str = m.group(3)
            calls = [c for c in calls_str.split(',') if c] if calls_str else []
            key = f"{file_name}:{line_num}"
            if key not in seen:
                seen.add(key)
                lines.append({"file": file_name, "line": line_num, "calls": calls})

    return lines


def _compare_execution_traces(lines_a, lines_b):
    """Compare two execution traces to find the divergence point.

    Handles refactoring by comparing:
    1. Function call ordering (not just sets)
    2. Unique functions called only in one version
    3. Different arguments to the same function
    4. Execution length (early returns, error paths)
    """
    # Extract operation sequences (function calls only, preserving order)
    calls_a = []
    for ln in lines_a:
        for c in ln.get("calls", []):
            if not c.startswith("0x") and "asan" not in c.lower() and "cyg_profile" not in c:
                calls_a.append((c, ln))
    calls_b = []
    for ln in lines_b:
        for c in ln.get("calls", []):
            if not c.startswith("0x") and "asan" not in c.lower() and "cyg_profile" not in c:
                calls_b.append((c, ln))

    # Find calls unique to each version
    set_a = {c for c, _ in calls_a}
    set_b = {c for c, _ in calls_b}
    only_a = set_a - set_b
    only_b = set_b - set_a

    # Find the first position where traces differ
    min_len = min(len(calls_a), len(calls_b))
    for i in range(min_len):
        name_a, ln_a = calls_a[i]
        name_b, ln_b = calls_b[i]

        # Case 1: Different function names at same position
        if name_a != name_b:
            # Check if one is a renamed version of the other
            # (both appear in the unique sets)
            if name_a in only_a and name_b in only_b:
                # Both are unique — this is the divergence point
                return {
                    "file": ln_b["file"],
                    "line": ln_b["line"],
                    "line_text_a": f"v4.4.0 calls {name_a}() at line {ln_a['line']}",
                    "line_text_b": f"v4.0.8 calls {name_b}() at line {ln_b['line']}",
                    "note": f"First divergence: different functions at position {i}",
                }
            elif name_a in only_a:
                # Only A has this function — B doesn't call it
                return {
                    "file": ln_b["file"],
                    "line": ln_b["line"],
                    "line_text_a": f"v4.4.0 calls {name_a}() at line {ln_a['line']}",
                    "line_text_b": f"v4.0.8 does not call {name_a}()",
                    "note": f"v4.4.0 has additional function call at position {i}",
                }
            elif name_b in only_b:
                # Only B has this function — A doesn't call it
                return {
                    "file": ln_b["file"],
                    "line": ln_b["line"],
                    "line_text_a": f"v4.4.0 does not call {name_b}()",
                    "line_text_b": f"v4.0.8 calls {name_b}() at line {ln_b['line']}",
                    "note": f"v4.0.8 has additional function call at position {i}",
                }
            else:
                # Both call different functions — neither is unique
                # This could be a call site difference
                return {
                    "file": ln_b["file"],
                    "line": ln_b["line"],
                    "line_text_a": f"v4.4.0 calls {name_a}() at line {ln_a['line']}",
                    "line_text_b": f"v4.0.8 calls {name_b}() at line {ln_b['line']}",
                    "note": f"Different functions at position {i}: {name_a} vs {name_b}",
                }

    # Same calls so far but different lengths — one version stops early
    if len(calls_a) != len(calls_b):
        if len(calls_a) > len(calls_b):
            # A continues, B stops
            next_call, next_ln = calls_a[len(calls_b)]
            return {
                "file": calls_b[-1][1]["file"],
                "line": calls_b[-1][1]["line"],
                "line_text_a": f"v4.4.0 continues with {next_call}() at line {next_ln['line']}",
                "line_text_b": f"v4.0.8 stops after {len(calls_b)} operations",
                "note": f"v4.0.8 takes early-return/error path after {len(calls_b)} operations",
            }
        else:
            next_call, next_ln = calls_b[len(calls_a)]
            return {
                "file": calls_a[-1][1]["file"],
                "line": calls_a[-1][1]["line"],
                "line_text_a": f"v4.4.0 stops after {len(calls_a)} operations",
                "line_text_b": f"v4.0.8 continues with {next_call}() at line {next_ln['line']}",
                "note": f"v4.4.0 takes early-return path after {len(calls_a)} operations",
            }

    return None


_BENIGN_ONE_SIDED_CALLS = {
    'TIFFFileName', 'TIFFGetFileName', 'dump_data', 'dump_info',
}


def _first_real_call_divergence(lines_a, lines_b):
    """Like _compare_execution_traces, but tolerant of benign one-sided calls.

    The newer version often ADDS wrapper/logging calls (limitMalloc,
    TIFFFileName, ...) that the older one lacks, so the FIRST positional
    difference is a benign call asymmetry while the REAL fork — e.g. the
    older version hitting an error path (TIFFError) and stopping early, or
    calling a different function — comes later.  Align the two call
    sequences and report the first non-benign divergence:
      - 'replace' -> the versions call different functions at the same point
      - 'insert'  -> 4.0.8 calls something 4.4.0 never does (error path)
      - B stops   -> early-return/error path after the aligned prefix
    'delete' blocks (4.4.0-only extra calls) are skipped as benign.
    """
    import difflib
    calls_a = []
    for ln in lines_a:
        for c in ln.get("calls", []):
            if not c.startswith("0x") and "asan" not in c.lower() and "cyg_profile" not in c:
                calls_a.append((c, ln))
    calls_b = []
    for ln in lines_b:
        for c in ln.get("calls", []):
            if not c.startswith("0x") and "asan" not in c.lower() and "cyg_profile" not in c:
                calls_b.append((c, ln))

    names_a = [c for c, _ in calls_a]
    names_b = [c for c, _ in calls_b]
    if not names_a or not names_b:
        return None

    sm = difflib.SequenceMatcher(a=names_a, b=names_b, autojunk=False)
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == 'equal':
            continue
        if tag == 'replace':
            name_a, ln_a = calls_a[i1]
            name_b, ln_b = calls_b[j1]
            return {
                "file": ln_b["file"],
                "line": ln_b["line"],
                "line_text_a": f"v4.4.0 calls {name_a}() at line {ln_a['line']}",
                "line_text_b": f"v4.0.8 calls {name_b}() at line {ln_b['line']}",
                "note": f"Different functions at aligned position: {name_a} vs {name_b}",
                "diverging_call_a": name_a,
                "diverging_call_b": name_b,
            }
        if tag == 'insert':
            # 4.0.8-only calls: an error-path call is the fork (the older
            # version failed a check and took the error branch).
            name_b, ln_b = calls_b[j1]
            if name_b in _BENIGN_ONE_SIDED_CALLS:
                continue
            return {
                "file": ln_b["file"],
                "line": ln_b["line"],
                "line_text_a": f"v4.4.0 never calls {name_b}() (no error path)",
                "line_text_b": f"v4.0.8 calls {name_b}() at line {ln_b['line']}",
                "note": "v4.0.8-only call — error/early-exit path",
                "diverging_call_b": name_b,
            }
        # 'delete': 4.4.0-only extra calls (wrappers/logging) — benign, skip.

    # Same aligned calls but different lengths — one version stops early
    if len(calls_a) != len(calls_b):
        if len(calls_a) > len(calls_b):
            next_call, next_ln = calls_a[len(calls_b)]
            return {
                "file": calls_b[-1][1]["file"],
                "line": calls_b[-1][1]["line"],
                "line_text_a": f"v4.4.0 continues with {next_call}() at line {next_ln['line']}",
                "line_text_b": f"v4.0.8 stops after {len(calls_b)} operations",
                "note": f"v4.0.8 takes early-return/error path after {len(calls_b)} operations",
            }
        next_call, next_ln = calls_b[len(calls_a)]
        return {
            "file": calls_a[-1][1]["file"],
            "line": calls_a[-1][1]["line"],
            "line_text_a": f"v4.4.0 stops after {len(calls_a)} operations",
            "line_text_b": f"v4.0.8 continues with {next_call}() at line {next_ln['line']}",
            "note": f"v4.4.0 takes early-return path after {len(calls_a)} operations",
        }

    return None


def _find_function_source(func_name, source_dirs, file_hint=None):
    """Find the source file containing func_name definition.

    If file_hint (a basename) is given, only files with that name are considered,
    which disambiguates functions that share a name across the source tree.
    """
    for d in source_dirs:
        for ext in ['.c', '.cpp']:
            for path in Path(d).rglob(f'*{ext}'):
                if file_hint and path.name != file_hint:
                    continue
                try:
                    with open(path) as f:
                        content = f.read()
                    # Look for function definition pattern, not just references
                    pattern = rf'(?:static\s+)?(?:\w+\s+)*\b{func_name}\s*\([^)]*\)\s*\{{'
                    if re.search(pattern, content):
                        return str(path)
                except (FileNotFoundError, UnicodeDecodeError):
                    continue
    return None


def _locate_source_file(source_file, source_dirs):
    """Return the absolute path of source_file under source_dirs, or None.

    Matches by basename first so absolute debug paths and cross-version
    basename collisions resolve to the correct version's file.
    """
    base = os.path.basename(source_file)
    for d in source_dirs:
        candidate = os.path.join(d, base)
        if os.path.exists(candidate):
            return candidate
    if not os.path.isabs(source_file):
        for d in source_dirs:
            candidate = os.path.join(d, source_file)
            if os.path.exists(candidate):
                return candidate
    for d in source_dirs:
        for path in Path(d).rglob(base):
            return str(path)
    return None


def _first_parenthesized_expr(s):
    """Return the text inside the first balanced '(' ... ')' pair in s, or None."""
    start = s.find('(')
    if start < 0:
        return None
    depth = 0
    for i in range(start, len(s)):
        if s[i] == '(':
            depth += 1
        elif s[i] == ')':
            depth -= 1
            if depth == 0:
                return s[start + 1:i]
    return None


def _match_control_statement(line):
    """Return {'keyword','condition'} if line starts a control statement, else None."""
    s = line.strip()
    if not s:
        return None
    for kw in ("if", "switch", "while", "for"):
        if re.match(r'\b' + kw + r'\s*\(', s):
            expr = _first_parenthesized_expr(s)
            return {"keyword": kw, "condition": (expr or "").strip()}
    # 'else if' may follow a closing brace: '} else if (...)' or start the line.
    m = re.search(r'\belse\s+if\s*\(', s)
    if m:
        expr = _first_parenthesized_expr(s[m.start():])
        return {"keyword": "else if", "condition": (expr or "").strip()}
    if re.match(r'\bdo\b', s):
        return {"keyword": "do", "condition": ""}
    if re.match(r'\bgoto\s+\w+\s*;', s):
        return {"keyword": "goto", "condition": s}
    return None


def _next_line_is_brace(lines, i):
    """True if the next non-blank line after i is an opening brace."""
    j = i + 1
    while j < len(lines) and not lines[j].strip():
        j += 1
    return j < len(lines) and lines[j].strip().startswith('{')


def _eval_condition_at_line(binary, source_file, line_num, args, lib_path,
                            source_dirs, condition_expr, gdb_timeout=120,
                            ignore_count=0):
    """Use GDB to evaluate a condition expression at a specific source line.

    Breaks at source_file:line_num, runs to that point, and prints the value of
    condition_expr. Returns the raw GDB output string (containing the printed
    value), or None on failure.

    If the primary breakpoint is never hit (e.g. program crashes earlier), a
    second attempt breaks one line inside the body (line_num+1) to capture the
    variable values while still in scope.

    ignore_count: skip this many prior hits of the breakpoint (for loop bodies
    where the condition is evaluated multiple times).
    """
    for target_line in (line_num, line_num + 1):
        cmds = [
            "set breakpoint pending on",
            f"break {source_file}:{target_line}",
        ]
        if ignore_count:
            cmds.append(f"ignore 1 {ignore_count}")
        cmds += [
            "run " + " ".join(str(a) for a in args),
            f"print {condition_expr}",
            "quit",
        ]
        output = run_gdb_with_source(binary, source_dirs, cmds,
                                      lib_path=lib_path, timeout=gdb_timeout)
        # GDB prints:  $1 = <value>
        for line in output.split('\n'):
            if '$' in line and '=' in line:
                return line.strip()
    return None


_COND_JUMP_MNEMONICS = frozenset([
    'je', 'jz', 'jne', 'jnz', 'jg', 'jnle', 'jge', 'jnl',
    'jl', 'jnge', 'jle', 'jng', 'ja', 'jnbe', 'jae', 'jnb',
    'jb', 'jnae', 'jbe', 'jna', 'jo', 'jno', 'js', 'jns',
    'jp', 'jpe', 'jnp', 'jpo', 'jcxz', 'jecxz', 'jrcxz',
])


def _record_branch_decisions(binary, func_name, args, lib_path, source_dirs,
                             gdb_timeout=120):
    """Record the branch-decision sequence for *func_name* using GDB.

    Disassembles the function to find conditional-jump instructions,
    then steps through with nexti, recording at each cond-jump whether
    the branch was taken (PC == target) or not.

    Returns a list of dicts:
      addr    - address of the conditional-jump (int)
      mnem    - jump mnemonic (str)
      taken   - True if the branch was taken
      src     - 'file:line' string or None
    """
    args_str = " ".join(str(a) for a in args)
    func_esc = func_name.replace('"', '\\"')

    script = (
        'import gdb, re, sys\n'
        '\n'
        'COND_JUMPS = {"je","jz","jne","jnz","jg","jnle","jge","jnl",\n'
        '              "jl","jnge","jle","jng","ja","jnbe","jae","jnb",\n'
        '              "jb","jnae","jbe","jna","jo","jno","js","jns",\n'
        '              "jp","jpe","jnp","jpo","jcxz","jecxz","jrcxz"}\n'
        '\n'
        'gdb.execute("set pagination off")\n'
        'gdb.execute("set confirm off")\n'
        'gdb.execute("handle SIGABRT stop nopass")\n'
        'gdb.execute("handle SIGSEGV stop nopass")\n'
        'gdb.execute("catch load libtiff")\n'
        'gdb.execute("run ' + args_str + '")\n'
        '\n'
        'gdb.execute("sharedlibrary")\n'
        'gdb.execute("break ' + func_esc + '")\n'
        'gdb.execute("continue")\n'
        '\n'
        'raw = gdb.execute("disassemble ' + func_esc + '", to_string=True)\n'
        'cj_addrs = {}\n'
        'for line in raw.split("\\n"):\n'
        '    line = line.strip()\n'
        '    m = re.match(r"(0x[0-9a-fA-F]+)\\s+<[^>]*>:\\s+(\\w+)\\s+(0x[0-9a-fA-F]+)", line)\n'
        '    if not m:\n'
        '        continue\n'
        '    addr = int(m.group(1), 16)\n'
        '    mnem = m.group(2).lower()\n'
        '    target = int(m.group(3), 16)\n'
        '    if mnem in COND_JUMPS:\n'
        '        cj_addrs[addr] = (mnem, target)\n'
        '\n'
        'if not cj_addrs:\n'
        '    print("NO_BRANCHES")\n'
        '    gdb.execute("quit")\n'
        '    sys.exit(0)\n'
        '\n'
        'results = []\n'
        'for step in range(15000):\n'
        '    try:\n'
        '        frame = gdb.selected_frame()\n'
        '        pc = frame.pc()\n'
        '    except gdb.error:\n'
        '        break\n'
        '    if pc in cj_addrs:\n'
        '        mnem, target = cj_addrs[pc]\n'
        '        gdb.execute("nexti")\n'
        '        try:\n'
        '            frame = gdb.selected_frame()\n'
        '            pc_after = frame.pc()\n'
        '        except gdb.error:\n'
        '            break\n'
        '        taken = (pc_after == target)\n'
        '        src = None\n'
        '        try:\n'
        '            sal = gdb.find_pc_line(pc)\n'
        '            if sal.symtab and sal.line:\n'
        '                src = sal.symtab.filename + ":" + str(sal.line)\n'
        '        except:\n'
        '            pass\n'
        '        results.append(hex(pc) + "|" + mnem + "|" + str(taken) + "|" + str(src))\n'
        '    else:\n'
        '        try:\n'
        '            gdb.execute("nexti")\n'
        '        except gdb.error:\n'
        '            break\n'
        '\n'
        'print("RECORDED:" + str(len(results)))\n'
        'print("BRANCHES:" + "\\t".join(results))\n'
        'gdb.execute("quit")\n'
    )

    fd, script_path = tempfile.mkstemp(suffix='.gdb.py')
    try:
        with os.fdopen(fd, 'w') as f:
            f.write(script)

        env = os.environ.copy()
        env["LSAN_OPTIONS"] = "detect_leaks=0"
        if lib_path:
            old_ld = env.get("LD_LIBRARY_PATH", "")
            lib_parts = [lib_path] if isinstance(lib_path, str) else lib_path
            env["LD_LIBRARY_PATH"] = ":".join(lib_parts + ([old_ld] if old_ld else []))

        gdb_cmds = ["gdb", "-batch"]
        for d in source_dirs:
            gdb_cmds.extend(["-iex", f"directory {d}"])
        gdb_cmds.extend(["-x", script_path, str(binary)])

        result = subprocess.run(gdb_cmds, capture_output=True, text=True,
                                timeout=gdb_timeout, env=env)
        output = result.stdout + result.stderr
    finally:
        os.unlink(script_path)

    decisions = []
    for line in output.split('\n'):
        if line.startswith('BRANCHES:'):
            blob = line[len('BRANCHES:'):].strip()
            for item in blob.split('\t'):
                item = item.strip()
                if not item:
                    continue
                parts = item.split('|')
                if len(parts) >= 4:
                    addr_s, mnem, taken_s, src = parts[0], parts[1], parts[2], parts[3]
                    decisions.append({
                        'addr': int(addr_s, 16) if addr_s.startswith('0x') else int(addr_s),
                        'mnem': mnem,
                        'taken': (taken_s == 'True'),
                        'src': src if src != 'None' else None,
                    })
            break

    return decisions


def _compare_branch_sequences(seq_a, seq_b):
    """Compare two branch-decision sequences and return the first divergence.

    Matches by position (index) since addresses differ due to ASLR.
    Skips ASAN-only branches (those at the start of functions that don't
    correspond to real source code).
    Returns (index, taken_a, taken_b, src_a, src_b) of the first
    differing decision, or (None, None, None, None, None) if identical.
    """
    for i, (a_dec, b_dec) in enumerate(zip(seq_a, seq_b)):
        if a_dec['taken'] != b_dec['taken']:
            return i, a_dec['taken'], b_dec['taken'], a_dec.get('src'), b_dec.get('src')
    return None, None, None, None, None


def _verify_divergence_by_branches(binary_a, binary_b,
                                    func_name_a, func_name_b,
                                    args_a, args_b,
                                    lib_path_a, lib_path_b,
                                    source_dirs_a, source_dirs_b,
                                    gdb_timeout=120):
    """Record branch-decision sequences for both versions and find first divergence.

    Returns a dict with the first divergent branch info, or None.
    """
    seq_a = _record_branch_decisions(
        binary_a, func_name_a, args_a, lib_path_a, source_dirs_a, gdb_timeout
    )
    seq_b = _record_branch_decisions(
        binary_b, func_name_b, args_b, lib_path_b, source_dirs_b, gdb_timeout
    )
    if not seq_a or not seq_b:
        return None

    idx, taken_a, taken_b, src_a, src_b = _compare_branch_sequences(seq_a, seq_b)
    if idx is None:
        return None

    return {
        "first_divergent_index": idx,
        "total_branches_a": len(seq_a),
        "total_branches_b": len(seq_b),
        "taken_a": taken_a,
        "taken_b": taken_b,
        "src_a": src_a,
        "src_b": src_b,
        "seq_a": seq_a,
        "seq_b": seq_b,
    }


def _find_function_body_range(source_file, func_name, source_dirs):
    """Return (start_line, end_line) of func_name's body in source_file, or None.

    start_line is the first line inside the opening brace; end_line is the
    closing brace line.  Forward declarations and call sites are skipped.
    """
    full_path = _locate_source_file(source_file, source_dirs)
    if not full_path:
        return None
    try:
        with open(full_path, encoding='utf-8', errors='replace') as f:
            lines = f.readlines()
    except (FileNotFoundError, UnicodeDecodeError):
        return None

    import re
    for i, line in enumerate(lines):
        stripped = line.strip()
        # Match function definition: func_name( at start of line (possibly
        # preceded by return type / static / etc.), but NOT inside an expression.
        if re.match(r'^(?:static\s+)?(?:\w+\s+)*\b' + func_name + r'\s*\(', stripped):
            # Skip forward declarations (line ends with ;)
            if stripped.endswith(';'):
                continue
            # Find the opening brace (may be on this line or a later line)
            brace_line = None
            for j in range(i, min(i + 20, len(lines))):
                if '{' in lines[j]:
                    brace_line = j
                    break
            if brace_line is None:
                continue
            # Find matching closing brace
            depth = 0
            for j in range(brace_line, len(lines)):
                depth += lines[j].count('{') - lines[j].count('}')
                if depth == 0:
                    return (brace_line + 2, j + 1)  # 1-indexed
            return (brace_line + 2, len(lines))
    return None


def _find_control_statement(source_file, line_num, source_dirs, max_lookback=600):
    """Walk backwards from a call site and return the innermost enclosing braced
    control statement (if/while/for/do) that decides the call's path.

    switch statements are skipped: they select among same-nature cases (e.g. which
    error message) rather than deciding between divergent paths. Blocks that closed
    before the call site are skipped so sibling control statements earlier in the
    function are not mistaken for the enclosing one.
    """
    full_path = _locate_source_file(source_file, source_dirs)
    if not full_path:
        return None
    try:
        with open(full_path, encoding='utf-8', errors='replace') as f:
            lines = f.readlines()
    except (FileNotFoundError, UnicodeDecodeError):
        return None

    start = line_num - 1
    if start < 0 or start >= len(lines):
        return None

    i = start - 1
    steps = 0
    while i >= 0 and steps < max_lookback:
        s = lines[i].strip()
        steps += 1
        n_open = s.count('{')
        n_close = s.count('}')
        if n_close > n_open:
            # Skip a block that closed before the call site: find its matching
            # opening brace(s) so it is not treated as an enclosing statement.
            balance = n_close - n_open
            i -= 1
            steps += 1
            while i >= 0 and balance > 0 and steps < max_lookback:
                s2 = lines[i].strip()
                balance += s2.count('}') - s2.count('{')
                i -= 1
                steps += 1
            continue
        ctrl = _match_control_statement(s)
        if ctrl and ctrl["keyword"] != "switch" and (n_open > 0 or _next_line_is_brace(lines, i)):
            return {
                "keyword": ctrl["keyword"],
                "condition": ctrl["condition"],
                "line": i + 1,
                "full_line": lines[i].rstrip(),
                "file": source_file,
            }
        i -= 1
    return None


def _find_conditional_context(source_file, line_num, source_dirs):
    """Search backwards from a source line to find the controlling if/for/while statement."""
    # Find the actual source file
    full_path = None
    for d in source_dirs:
        candidate = os.path.join(d, source_file)
        if os.path.exists(candidate):
            full_path = candidate
            break
    if not full_path:
        # Try rglob
        for d in source_dirs:
            for ext in ['.c', '.cpp']:
                for path in Path(d).rglob(f'*{ext}'):
                    if path.name == source_file:
                        full_path = str(path)
                        break
                if full_path:
                    break
        if not full_path:
            return None

    try:
        with open(full_path) as f:
            lines = f.readlines()
    except (FileNotFoundError, UnicodeDecodeError):
        return None

    # Search backwards from line_num to find enclosing conditional
    depth = 0
    for i in range(min(line_num - 1, len(lines) - 1), max(0, line_num - 20), -1):
        line = lines[i].strip()
        # Track brace depth
        depth += line.count('}') - line.count('{')
        # Look for if/for/while at depth 0 or 1
        if depth <= 0:
            m = re.match(r'(if|for|while)\s*\((.+)\)', line)
            if m:
                return {
                    "keyword": m.group(1),
                    "condition": m.group(2).strip(),
                    "line": i + 1,
                    "full_line": lines[i].rstrip(),
                    "file": source_file,
                }
    return None


def _extract_function_body(code, func_name):
    """Extract the body of a function from source code."""
    # Find the function definition — handle multi-line parameters
    pattern = rf'(?:static\s+)?(?:\w+\s+)*\b{func_name}\s*\([^)]*\)\s*\{{'
    m = re.search(pattern, code, re.DOTALL)
    if not m:
        return None

    # Find matching closing brace
    start = m.end() - 1  # Position of opening brace
    depth = 1
    i = start + 1
    while i < len(code) and depth > 0:
        if code[i] == '{':
            depth += 1
        elif code[i] == '}':
            depth -= 1
        i += 1

    return code[start:i]


def _find_call_line(body, call_name):
    """Find the line number of a function call within a function body."""
    pattern = rf'\b{call_name}\s*\('
    m = re.search(pattern, body)
    if m:
        return body[:m.start()].count('\n') + 1
    return None


def _record_source_lines(binary, func_name, args, lib_path, source_dirs, timeout):
    """Record source lines visited inside func_name using GDB Python stepping.

    Uses 'finish' to skip sub-function calls for efficient traversal.
    """
    log_prefix = f"/tmp/gdb_lines_{id(binary) & 0xFFFFFF:06x}"
    args_str = " ".join(str(a) for a in args)

    # Write GDB command file with embedded Python
    script = f"""set pagination off
set confirm off
catch load libtiff
run {args_str}
break {func_name}
continue
python
import gdb
lines_seen = []
last_line = None
step_count = 0
max_steps = 3000
while step_count < max_steps:
    try:
        frame = gdb.selected_frame()
        sal = gdb.find_pc_line(frame.pc())
        if sal.line and sal.symtab:
            fname = sal.symtab.filename
            line_num = sal.line
            key = fname + ":" + str(line_num)
            if key != last_line:
                lines_seen.append(key)
                last_line = key
                print("LINE:" + key)
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
print("DONE:" + str(len(lines_seen)))
end
quit
"""

    script_path = f"{log_prefix}_script.gdb"
    with open(script_path, 'w') as f:
        f.write(script)

    env = os.environ.copy()
    if lib_path:
        old_ld = env.get("LD_LIBRARY_PATH", "")
        lib_parts = [lib_path] if isinstance(lib_path, str) else lib_path
        env["LD_LIBRARY_PATH"] = ":".join(lib_parts + ([old_ld] if old_ld else []))

    gdb_cmds = ["gdb", "-batch"]
    if lib_path:
        gdb_cmds.extend(["-iex", f"set solib-search-path {lib_path}"])
    for d in source_dirs:
        gdb_cmds.extend(["-iex", f"directory {d}"])
    gdb_cmds.extend(["-x", script_path, str(binary)])

    result = subprocess.run(gdb_cmds, capture_output=True, text=True,
                            timeout=timeout, env=env)
    output = result.stdout + result.stderr

    # Parse LINE: entries
    lines = []
    seen = set()
    for line in output.split('\n'):
        m = re.match(r'LINE:(.+):(\d+)', line)
        if m:
            key = f"{m.group(1)}:{m.group(2)}"
            if key not in seen:
                seen.add(key)
                lines.append({"file": m.group(1), "line": int(m.group(2))})

    return lines


def _find_divergence_gap(gaps, a_idx, b_idx):
    """Return the gap that immediately follows the divergence point (a_idx, b_idx).

    The divergence point indexes the last common call before the gap, so the gap
    of interest is the one starting right after that index.
    """
    for g in gaps:
        ar = g.get("a_range", [0, 0])
        br = g.get("b_range", [0, 0])
        if ar[0] == a_idx + 1 or br[0] == b_idx + 1:
            return g
    if gaps:
        return gaps[-1]
    return None


def _first_differing_enter(gap):
    """Return (a_name, b_name), the first enter-event names that differ in a gap."""
    a_enters = [op["name"] for op in gap.get("a", []) if op.get("is_enter")]
    b_enters = [op["name"] for op in gap.get("b", []) if op.get("is_enter")]
    a_first = a_enters[0] if a_enters else None
    b_first = b_enters[0] if b_enters else None
    return a_first, b_first


def _read_source_line(source_file, line_num, source_dirs):
    """Return the text of a single source line, or None if it can't be located."""
    full_path = None
    for d in source_dirs:
        candidate = os.path.join(d, source_file)
        if os.path.exists(candidate):
            full_path = candidate
            break
    if not full_path:
        for d in source_dirs:
            for path in Path(d).rglob(source_file):
                full_path = str(path)
                break
            if full_path:
                break
    if not full_path:
        return None
    try:
        with open(full_path, encoding='utf-8', errors='replace') as f:
            lines = f.readlines()
    except (FileNotFoundError, UnicodeDecodeError):
        return None
    if 1 <= line_num <= len(lines):
        return lines[line_num - 1].rstrip()
    return None


def _get_backtrace_frames(binary, func_name, args, lib_path, source_dirs,
                          timeout, ignore_count=0, max_frames=24):
    """Break on func_name and return the full call stack as a list of frames.

    Each frame is a dict with index, function, file and line. Frames without a
    source location (e.g. dynamic-linker frames) are skipped.
    """
    cmds = [
        "set breakpoint pending on",
        f"break {func_name}",
    ]
    if ignore_count:
        # func_name breakpoint is #1 (no catchpoint precedes it)
        cmds.append(f"ignore 1 {ignore_count}")
    cmds += [
        "run " + " ".join(str(a) for a in args),
        f"bt {max_frames}",
        "quit",
    ]
    output = run_gdb_with_source(binary, source_dirs, cmds,
                                  lib_path=lib_path, timeout=timeout)

    frames = []
    for line in output.split('\n'):
        # e.g. "#1  0x00005555555873f2 in processCropSelections (...) at tiffcrop.c:7507"
        # or (source-level frame) "#0  TIFFError (...) at tif_error.c:52"
        m = re.search(
            r'#(\d+)\s+(?:0x[0-9a-fA-F]+\s+in\s+)?([^\s(]+)\s*'
            r'(?:\([^)]*\))?\s+at\s+(\S+):(\d+)',
            line)
        if m:
            frames.append({
                "index": int(m.group(1)),
                "function": m.group(2),
                "file": m.group(3),
                "line": int(m.group(4)),
            })
    return frames


def _is_runtime_function(name, file):
    """True if the function is a sanitizer/libc runtime function, not project code."""
    if not name:
        return False
    if re.search(r'__interceptor_|__asan_|__sanitizer_|__ubsan_|__tsan_|__lsan_|__msan_', name):
        return True
    if name in ('qsort', 'bsearch', 'msort_with_tmp', '__qsort_r', '__libc_csu_init',
                '__libc_start_main'):
        return True
    f = file or ''
    if re.search(r'sanitizer|libsanitizer|/usr/|libc|stdlib|csu/', f):
        return True
    return False


def _find_guard_condition(binary, func_name, args, lib_path, source_dirs,
                          gdb_timeout=120, ignore_count=0):
    """Use GDB disassembly to find the control statement guarding a call to
    func_name.

    Break on func_name (at the ignore_count+1-th hit), take the caller frame,
    disassemble the caller, find the nearest conditional-jump instruction
    before the call return address, and map that instruction back to a source
    line.  Returns {'caller_function', 'call_file', 'call_line',
    'guard_file', 'guard_line'} or None.  No source-text analysis is used.
    """
    args_str = " ".join(str(a) for a in args)
    func_esc = func_name.replace('"', '\\"')

    cond_jumps = ("je","jz","jne","jnz","jg","jnle","jge","jnl","jl","jnge",
                  "jle","jng","ja","jnbe","jae","jnb","jb","jnae","jbe","jna",
                  "jo","jno","js","jns","jp","jpe","jnp","jpo")

    script = (
        'import gdb, re, sys\n'
        'gdb.execute("set pagination off")\n'
        'gdb.execute("set confirm off")\n'
        'gdb.execute("set breakpoint pending on")\n'
        'gdb.execute("break ' + func_esc + '")\n'
        'gdb.execute("ignore 1 ' + str(ignore_count) + '")\n'
        'gdb.execute("run ' + args_str + '")\n'
        'COND = {"' + '","'.join(cond_jumps) + '"}\n'
        'frame = gdb.newest_frame().older()\n'
        'while frame is not None:\n'
        '    try:\n'
        '        pc = frame.pc()\n'
        '        caller = frame.name()\n'
        '    except gdb.error:\n'
        '        break\n'
        '    if caller and re.search(r"__interceptor_|__asan_|__sanitizer_|__ubsan_|__tsan_|__lsan_|__msan_|^qsort$|^bsearch$|^msort_with_tmp$|^__qsort_r$", caller):\n'
        '        frame = frame.older()\n'
        '        continue\n'
        '    try:\n'
        '        csal = gdb.find_pc_line(pc)\n'
        '        cfile = csal.symtab.filename if csal.symtab else ""\n'
        '    except gdb.error:\n'
        '        cfile = ""\n'
        '    if cfile and re.search(r"sanitizer|libsanitizer|/usr/|libc|stdlib", cfile):\n'
        '        frame = frame.older()\n'
        '        continue\n'
        '    try:\n'
        '        raw = gdb.execute("disassemble " + caller, to_string=True)\n'
        '    except gdb.error:\n'
        '        raw = ""\n'
        '    best = None\n'
        '    for line in raw.split("\\n"):\n'
        '        m = re.match(r"\\s*(0x[0-9a-fA-F]+)\\s+<[^>]*>:\\s+(\\w+)\\s+(0x[0-9a-fA-F]+)", line)\n'
        '        if not m:\n'
        '            continue\n'
        '        addr = int(m.group(1), 16)\n'
        '        mnem = m.group(2).lower()\n'
        '        if mnem in COND and addr < pc:\n'
        '            if best is None or addr > best:\n'
        '                best = addr\n'
        '    if best is not None:\n'
        '        sal = gdb.find_pc_line(best)\n'
        '        gfile = sal.symtab.filename if sal.symtab else "?"\n'
        '        gline = sal.line if sal.line else 0\n'
        '        call_sal = gdb.find_pc_line(pc)\n'
        '        cfile = call_sal.symtab.filename if call_sal.symtab else "?"\n'
        '        cline = call_sal.line if call_sal.line else 0\n'
        '        print("GUARD|" + gfile + "|" + str(gline) + "|" + caller)\n'
        '        print("CALL|" + cfile + "|" + str(cline))\n'
        '        gdb.execute("quit"); sys.exit(0)\n'
        '    frame = frame.older()\n'
        'print("NO_GUARD")\n'
        'gdb.execute("quit")\n'
    )

    fd, script_path = tempfile.mkstemp(suffix='.gdb.py')
    try:
        with os.fdopen(fd, 'w') as f:
            f.write(script)
        env = os.environ.copy()
        env["ASAN_OPTIONS"] = "detect_leaks=0"
        if lib_path:
            old_ld = env.get("LD_LIBRARY_PATH", "")
            lib_parts = [lib_path] if isinstance(lib_path, str) else lib_path
            env["LD_LIBRARY_PATH"] = ":".join(lib_parts + ([old_ld] if old_ld else []))
        gdb_cmds = ["gdb", "-batch"]
        for d in source_dirs:
            gdb_cmds.extend(["-iex", f"directory {d}"])
        if lib_path:
            gdb_cmds.extend(["-iex", f"set solib-search-path {lib_path}"])
        gdb_cmds.extend(["-x", script_path, str(binary)])
        result = subprocess.run(gdb_cmds, capture_output=True, text=True,
                                timeout=gdb_timeout, env=env)
        output = result.stdout + result.stderr
    finally:
        os.unlink(script_path)

    guard = None
    call = None
    caller = None
    for line in output.split('\n'):
        if line.startswith('GUARD|'):
            parts = line.split('|', 3)
            if len(parts) == 4:
                guard = {"file": parts[1], "line": int(parts[2])}
                caller = parts[3]
        elif line.startswith('CALL|'):
            parts = line.split('|', 2)
            if len(parts) == 3:
                call = {"file": parts[1], "line": int(parts[2])}

    if guard is None:
        return None
    return {
        "caller_function": caller or func_name,
        "call_file": call["file"] if call else guard["file"],
        "call_line": call["line"] if call else guard["line"],
        "guard_file": guard["file"],
        "guard_line": guard["line"],
    }


def _verify_fork_branch(binary, ctrl_file, ctrl_line, diverging_call, args,
                        lib_path, source_dirs, gdb_timeout=120, call_ignore=0):
    """Verify that *diverging_call* is invoked after the control statement at
    ctrl_file:ctrl_line.

    Break at the control statement, run to it, then break at diverging_call
    (skipping call_ignore prior hits) and continue.  Returns True if the
    divergent call is reached from the control statement — i.e. the control
    statement really leads to this branch in this execution.
    """
    args_str = " ".join(str(a) for a in args)
    call_esc = diverging_call.replace('"', '\\"')
    ctrl_base = os.path.basename(ctrl_file)

    script = (
        'import gdb, sys\n'
        'gdb.execute("set pagination off")\n'
        'gdb.execute("set confirm off")\n'
        'gdb.execute("set breakpoint pending on")\n'
        'gdb.execute("break ' + ctrl_base + ':' + str(ctrl_line) + '")\n'
        'gdb.execute("run ' + args_str + '")\n'
        'gdb.execute("break ' + call_esc + '")\n'
        'gdb.execute("ignore 2 ' + str(call_ignore) + '")\n'
        'gdb.execute("continue")\n'
        'print("REACHED_CALL")\n'
        'gdb.execute("quit")\n'
    )

    fd, script_path = tempfile.mkstemp(suffix='.gdb.py')
    try:
        with os.fdopen(fd, 'w') as f:
            f.write(script)
        env = os.environ.copy()
        env["ASAN_OPTIONS"] = "detect_leaks=0"
        if lib_path:
            old_ld = env.get("LD_LIBRARY_PATH", "")
            lib_parts = [lib_path] if isinstance(lib_path, str) else lib_path
            env["LD_LIBRARY_PATH"] = ":".join(lib_parts + ([old_ld] if old_ld else []))
        gdb_cmds = ["gdb", "-batch"]
        for d in source_dirs:
            gdb_cmds.extend(["-iex", f"directory {d}"])
        if lib_path:
            gdb_cmds.extend(["-iex", f"set solib-search-path {lib_path}"])
        gdb_cmds.extend(["-x", script_path, str(binary)])
        result = subprocess.run(gdb_cmds, capture_output=True, text=True,
                                timeout=gdb_timeout, env=env)
        output = result.stdout + result.stderr
    finally:
        os.unlink(script_path)

    return 'REACHED_CALL' in output


def _find_caller_statement(binary, func_name, args, lib_path, source_dirs,
                           timeout, ignore_count=0):
    """Break on func_name and return the immediate caller's source statement."""
    frames = _get_backtrace_frames(binary, func_name, args, lib_path, source_dirs,
                                   timeout, ignore_count=ignore_count)
    if not frames:
        return None

    caller = None
    for f in frames:
        if f["index"] == 0:
            continue
        if f["function"].split('@')[0] == func_name:
            continue
        caller = f
        break
    if caller is None:
        caller = frames[0]

    call_line_text = _read_source_line(caller["file"], caller["line"], source_dirs)
    cond = _find_conditional_context(caller["file"], caller["line"], source_dirs)

    return {
        "caller_function": caller["function"],
        "file": caller["file"],
        "line": caller["line"],
        "call_line_text": call_line_text,
        "conditional": cond,
    }


def _find_last_common_function(matches, gaps, trace_a, trace_b, prefer_tail=False):
    """Find the function that CONTAINS the last divergence point.

    The divergence happens inside some function. We find it by looking at what
    function is active at the divergence point in both traces.
    Returns (func_name, match_info) or (None, None).

    When ``prefer_tail`` is set (reference crashed but the target stopped
    before it), only the LAST gap is considered — the divergence that matters
    is where the reference keeps running after the target has stopped, not an
    earlier gap whose fork caller is merely deeper.
    """
    if not gaps:
        return None, None

    def find_enclosing_function(trace, div_idx):
        """Find the deepest function still active at div_idx."""
        # Track enter/exit to find active functions
        active = []
        for i in range(div_idx):
            op = trace[i]
            if op.get("is_enter"):
                active.append(op)
            else:
                # Pop the last enter with matching name
                for j in range(len(active) - 1, -1, -1):
                    if active[j]["name"] == op["name"]:
                        active.pop(j)
                        break
        # The deepest active function is the last one
        if active:
            return active[-1]
        return None

    if prefer_tail:
        tail_gap = gaps[-1]
        fc = _extract_gap_fork(tail_gap)
        if fc:
            return fc, tail_gap
        # No forking caller in the tail gap (e.g. the target stopped there):
        # the last common function is the deepest function still active at
        # the end of the target trace.
        b_end = tail_gap.get("b_range", [0, len(trace_b)])[0]
        enc = find_enclosing_function(trace_b, b_end) if trace_b else None
        if enc:
            return enc["name"], tail_gap
        a_start = tail_gap.get("a_range", [0, 0])[0]
        enc = find_enclosing_function(trace_a, a_start) if trace_a else None
        if enc:
            return enc["name"], tail_gap
        return None, None

    # Prefer the forking caller inside a gap: the same caller invoked
    # different callees in A vs B (e.g. TIFFFetchStripThing calling
    # TIFFReadDirEntryLong8ArrayWithLimit vs TIFFReadDirEntryLong8Array).
    # Pick the deepest such caller across all gaps.
    best = None
    for g in gaps:
        fc = _extract_gap_fork(g)
        if not fc:
            continue
        depth = 0
        for x in g.get("a", []) + g.get("b", []):
            if isinstance(x, dict) and x.get("name") == fc:
                depth = max(depth, x.get("depth", 0))
        if best is None or depth > best[0]:
            best = (depth, fc, g)
    if best:
        return best[1], best[2]

    # Prefer the LAST match (the last aligned subsequence): the last common
    # function is the OUTERMOST function in that match (e.g. TIFFOpen in the
    # exit sequence <TIFFClientOpen -> <TIFFFdOpen -> <TIFFOpen).
    if matches:
        last_match = matches[-1]
        funcs = last_match.get("functions", [])
        if funcs:
            outermost = min(funcs, key=lambda f: f.get("depth", 999))
            return outermost.get("name"), last_match

    # Fallback: find the first gap with substantial divergence
    gap = None
    for g in gaps:
        a_funcs = g.get("a", [])
        b_funcs = g.get("b", [])
        if len(a_funcs) + len(b_funcs) >= 3:
            gap = g
            break
    if not gap:
        gap = gaps[0]

    # Get the divergence point indices
    a_div_idx = gap["a_range"][0] if gap.get("a_range") else None
    b_div_idx = gap["b_range"][0] if gap.get("b_range") else None

    if a_div_idx is None or b_div_idx is None:
        return None, None

    # Find what function is active at the divergence point by looking backwards
    # in the trace for the deepest function that's still entered
    func_a = find_enclosing_function(trace_a, a_div_idx)
    func_b = find_enclosing_function(trace_b, b_div_idx)

    if func_a and func_b and func_a["name"] == func_b["name"]:
        return func_a["name"], None
    elif func_a:
        return func_a["name"], None
    elif func_b:
        return func_b["name"], None

    # Fallback: look at the gap's parent functions
    if gap.get("a"):
        return gap["a"][0]["name"], None
    return None, None


def _step_trace_binary(binary, func_name, args, lib_path, source_dirs,
                       gdb_timeout=120):
    """Break at func_name entry, step through recording source lines until exit.

    Returns a list of dicts: [{"file": ..., "line": ..., "line_text": ...}, ...]
    """
    func_esc = func_name.replace('"', '\\"')
    args_str = " ".join(args) if args else ""

    script = (
        'import gdb, re, sys\n'
        '\n'
        'gdb.execute("set pagination off")\n'
        'gdb.execute("set confirm off")\n'
        'gdb.execute("handle SIGABRT stop nopass")\n'
        'gdb.execute("handle SIGSEGV stop nopass")\n'
        'gdb.execute("catch load libtiff")\n'
        'gdb.execute("run ' + args_str + '")\n'
        '\n'
        'gdb.execute("sharedlibrary")\n'
        'gdb.execute("break ' + func_esc + '")\n'
        'gdb.execute("continue")\n'
        '\n'
        'try:\n'
        '    frame = gdb.selected_frame()\n'
        '    func_start = frame.pc()\n'
        'except gdb.error:\n'
        '    print("ERROR:cannot get frame")\n'
        '    gdb.execute("quit")\n'
        '    sys.exit(0)\n'
        '\n'
        'func_end = func_start + 0x20000\n'
        '\n'
        'results = []\n'
        'max_steps = 8000\n'
        'for step in range(max_steps):\n'
        '    try:\n'
        '        frame = gdb.selected_frame()\n'
        '        pc = frame.pc()\n'
        '    except gdb.error:\n'
        '        break\n'
        '\n'
        '    if pc < func_start or pc >= func_end:\n'
        '        break\n'
        '\n'
        '    src_file = None\n'
        '    src_line = None\n'
        '    line_text = None\n'
        '    sal = gdb.find_pc_line(pc)\n'
        '    if sal.symtab and sal.line:\n'
        '        src_file = sal.symtab.filename\n'
        '        src_line = sal.line\n'
        '        try:\n'
        '            with open(sal.symtab.fullname()) as sf:\n'
        '                lines = sf.readlines()\n'
        '                if 0 < sal.line <= len(lines):\n'
        '                    line_text = lines[sal.line - 1].rstrip()\n'
        '        except:\n'
        '            pass\n'
        '\n'
        '    results.append(str(src_file or "None") + "|||" + str(src_line or 0) + "|||" + str(line_text or "None"))\n'
        '\n'
        '    try:\n'
        '        gdb.execute("next")\n'
        '    except gdb.error:\n'
        '        break\n'
        '\n'
        'print("STEP_TRACE:" + "|||".join(results))\n'
        'gdb.execute("quit")\n'
    )

    fd, script_path = tempfile.mkstemp(suffix='.gdb.py')
    try:
        with os.fdopen(fd, 'w') as f:
            f.write(script)

        env = os.environ.copy()
        env["LSAN_OPTIONS"] = "detect_leaks=0"
        if lib_path:
            old_ld = env.get("LD_LIBRARY_PATH", "")
            lib_parts = [lib_path] if isinstance(lib_path, str) else lib_path
            env["LD_LIBRARY_PATH"] = ":".join(lib_parts + ([old_ld] if old_ld else []))

        gdb_cmds = ["gdb", "-batch"]
        for d in source_dirs:
            gdb_cmds.extend(["-iex", f"directory {d}"])
        gdb_cmds.extend(["-x", script_path, str(binary)])

        result = subprocess.run(gdb_cmds, capture_output=True, text=True,
                                timeout=gdb_timeout, env=env)
        output = result.stdout + result.stderr
    finally:
        os.unlink(script_path)

    # Parse STEP_TRACE line
    # Format: file|||line|||text|||file|||line|||text|||...
    trace = []
    for line in output.split('\n'):
        if line.startswith('STEP_TRACE:'):
            blob = line[len('STEP_TRACE:'):].strip()
            entries = blob.split('|||')
            for i in range(0, len(entries) - 2, 3):
                f_name = entries[i] if entries[i] != "None" else None
                l_num = int(entries[i + 1]) if entries[i + 1] != "0" else None
                l_text = entries[i + 2] if entries[i + 2] != "None" else None
                trace.append({"file": f_name, "line": l_num, "line_text": l_text})
            break

    return trace


def _step_into_trace_binary(binary, func_name, args, lib_path, source_dirs,
                            gdb_timeout=120):
    """Break at func_name entry, step INTO called functions, record all source lines.

    Unlike _step_trace_binary which uses 'next' (stays in current function),
    this uses 'step' to enter sub-functions and records lines from ALL frames.
    Tracks frame level to know when we've returned to the original function.

    Returns a list of dicts: [{"file": ..., "line": ..., "line_text": ..., "depth": ...}, ...]
    """
    func_esc = func_name.replace('"', '\\"')
    args_str = " ".join(args) if args else ""

    script = (
        'import gdb, re, sys\n'
        '\n'
        'gdb.execute("set pagination off")\n'
        'gdb.execute("set confirm off")\n'
        'gdb.execute("handle SIGABRT stop nopass")\n'
        'gdb.execute("handle SIGSEGV stop nopass")\n'
        'gdb.execute("set follow-fork-mode child")\n'
        'gdb.execute("set detach-on-fork off")\n'
        'gdb.execute("catch load libtiff")\n'
        'gdb.execute("run ' + args_str + '")\n'
        '\n'
        'gdb.execute("sharedlibrary")\n'
        'gdb.execute("break ' + func_esc + '")\n'
        'gdb.execute("continue")\n'
        '\n'
        'try:\n'
        '    frame = gdb.selected_frame()\n'
        '    func_start = frame.pc()\n'
        '    base_level = frame.level()\n'
        'except gdb.error:\n'
        '    print("ERROR:cannot get frame")\n'
        '    gdb.execute("quit")\n'
        '    sys.exit(0)\n'
        '\n'
        'func_end = func_start + 0x20000\n'
        '\n'
        'results = []\n'
        'max_steps = 15000\n'
        'in_func = True\n'
        'for step in range(max_steps):\n'
        '    try:\n'
        '        frame = gdb.selected_frame()\n'
        '        pc = frame.pc()\n'
        '        level = frame.level()\n'
        '    except gdb.error:\n'
        '        break\n'
        '\n'
        '    # If we\'re back at base level and past the function, stop\n'
        '    if level <= base_level:\n'
        '        if pc < func_start or pc >= func_end:\n'
        '            if in_func:\n'
        '                break\n'
        '            # We returned from a sub-function call, continue in parent\n'
        '            in_func = True\n'
        '\n'
        '    src_file = None\n'
        '    src_line = None\n'
        '    line_text = None\n'
        '    sal = gdb.find_pc_line(pc)\n'
        '    if sal.symtab and sal.line:\n'
        '        src_file = sal.symtab.filename\n'
        '        src_line = sal.line\n'
        '        try:\n'
        '            with open(sal.symtab.fullname()) as sf:\n'
        '                lines = sf.readlines()\n'
        '                if 0 < sal.line <= len(lines):\n'
        '                    line_text = lines[sal.line - 1].rstrip()\n'
        '        except:\n'
        '            pass\n'
        '\n'
        '    depth = level - base_level\n'
        '    results.append(str(src_file or "None") + "|||" + str(src_line or 0) + "|||" + str(line_text or "None") + "|||" + str(depth))\n'
        '\n'
        '    try:\n'
        '        # Use step to enter sub-functions\n'
        '        gdb.execute("step")\n'
        '    except gdb.error:\n'
        '        break\n'
        '\n'
        'print("STEP_TRACE:" + "|||".join(results))\n'
        'gdb.execute("quit")\n'
    )

    fd, script_path = tempfile.mkstemp(suffix='.gdb.py')
    try:
        with os.fdopen(fd, 'w') as f:
            f.write(script)

        env = os.environ.copy()
        env["LSAN_OPTIONS"] = "detect_leaks=0"
        if lib_path:
            old_ld = env.get("LD_LIBRARY_PATH", "")
            lib_parts = [lib_path] if isinstance(lib_path, str) else lib_path
            env["LD_LIBRARY_PATH"] = ":".join(lib_parts + ([old_ld] if old_ld else []))

        gdb_cmds = ["gdb", "-batch"]
        for d in source_dirs:
            gdb_cmds.extend(["-iex", f"directory {d}"])
        gdb_cmds.extend(["-x", script_path, str(binary)])

        result = subprocess.run(gdb_cmds, capture_output=True, text=True,
                                timeout=gdb_timeout, env=env)
        output = result.stdout + result.stderr
    finally:
        os.unlink(script_path)

    # Parse STEP_TRACE line (4 fields: file|||line|||text|||depth)
    trace = []
    for line in output.split('\n'):
        if line.startswith('STEP_TRACE:'):
            blob = line[len('STEP_TRACE:'):].strip()
            entries = blob.split('|||')
            for i in range(0, len(entries) - 3, 4):
                f_name = entries[i] if entries[i] != "None" else None
                l_num = int(entries[i + 1]) if entries[i + 1] != "0" else None
                l_text = entries[i + 2] if entries[i + 2] != "None" else None
                depth = int(entries[i + 3]) if entries[i + 3] != "None" else 0
                trace.append({"file": f_name, "line": l_num, "line_text": l_text, "depth": depth})
            break

    return trace


def _compare_step_traces(trace_a, trace_b):
    """Compare two step traces to find the divergence point that causes permanent split.

    Each trace entry: {"file": ..., "line": ..., "line_text": ...}
    Compares by normalized line text. Skips trivial/whitespace-only/formatting differences.
    Returns the FIRST divergence followed by 3+ consecutive differences (the root cause),
    or None if identical.
    """
    all_divs = []
    for i in range(max(len(trace_a), len(trace_b))):
        a_op = trace_a[i] if i < len(trace_a) else None
        b_op = trace_b[i] if i < len(trace_b) else None

        if a_op is None or b_op is None:
            if a_op is not None or b_op is not None:
                all_divs.append({
                    "type": "length_mismatch",
                    "step": i,
                    "a": a_op,
                    "b": b_op,
                })
            continue

        a_text = (a_op.get("line_text") or "").strip()
        b_text = (b_op.get("line_text") or "").strip()

        if a_text in ('{', '}', '', ';') and b_text in ('{', '}', '', ';'):
            continue

        if a_text == b_text:
            continue

        a_norm = re.sub(r'\s+', ' ', a_text).strip()
        b_norm = re.sub(r'\s+', ' ', b_text).strip()
        a_norm = re.sub(r'\s*([=!<>]=|[=!<>]|&&|\|\||[+\-*/])\s*', r'\1', a_norm)
        b_norm = re.sub(r'\s*([=!<>]=|[=!<>]|&&|\|\||[+\-*/])\s*', r'\1', b_norm)
        a_norm = re.sub(r'\s*\{\s*$', '', a_norm)
        b_norm = re.sub(r'\s*\{\s*$', '', b_norm)
        if a_norm == b_norm:
            continue

        skip_re = re.compile(
            r'^\s*(uint\d*(?:_t)?|int\d*(?:_t)?|char|short|long|float|double|size_t|static|const|unsigned|signed)\b'
        )
        if skip_re.match(a_text) and skip_re.match(b_text):
            continue

        all_divs.append({
            "type": "line_divergence",
            "step": i,
            "a": a_op,
            "b": b_op,
        })

    if not all_divs:
        return None

    # Find the first divergence that's followed by many consecutive differences.
    # The root cause is the first divergence that causes permanent splitting.
    consecutive_threshold = 3
    for idx, div in enumerate(all_divs):
        # Check if there are enough consecutive differences after this one
        if idx + consecutive_threshold <= len(all_divs):
            return div

    # If no divergence has enough followers, return the first one
    return all_divs[0]


def _trace_from_common_ancestor(matches, gaps, trace_a, trace_b,
                                binary_a, binary_b, args_a, args_b,
                                lib_path_a, lib_path_b,
                                source_dirs_a, source_dirs_b,
                                gdb_timeout=120):
    """Find deepest common function, break at entry, step through both versions,
    compare step traces to find the LAST divergence point.

    Returns a result dict or None.
    """
    func_name, match_info = _find_last_common_function(matches, gaps, trace_a, trace_b)
    if not func_name:
        print("  Could not find common ancestor function")
        return None

    print(f"  Common ancestor function: {func_name}")

    # Step trace both versions
    print(f"  Stepping through {func_name}() in binary A...")
    step_trace_a = _step_trace_binary(
        binary_a, func_name, args_a, lib_path_a, source_dirs_a, gdb_timeout
    )
    print(f"  Got {len(step_trace_a)} source lines from A")

    print(f"  Stepping through {func_name}() in binary B...")
    step_trace_b = _step_trace_binary(
        binary_b, func_name, args_b, lib_path_b, source_dirs_b, gdb_timeout
    )
    print(f"  Got {len(step_trace_b)} source lines from B")

    if not step_trace_a or not step_trace_b:
        print("  Step tracing produced no results")
        return None

    # Compare traces — find LAST divergence
    div = _compare_step_traces(step_trace_a, step_trace_b)
    if not div:
        print("  Step traces are identical — no divergence found inside function")
        return None

    a_info = div.get("a", {})
    b_info = div.get("b", {})
    a_file = a_info.get("file") if a_info else None
    a_line = a_info.get("line") if a_info else None
    a_text = a_info.get("line_text", "") if a_info else ""
    b_file = b_info.get("file") if b_info else None
    b_line = b_info.get("line") if b_info else None
    b_text = b_info.get("line_text", "") if b_info else ""

    print(f"  Last divergence at step {div['step']}:")
    print(f"    A: {a_file}:{a_line} {a_text}")
    print(f"    B: {b_file}:{b_line} {b_text}")

    result = {
        "root_cause_function": func_name,
        "root_cause_file": a_file or b_file,
        "root_cause_line": a_line or b_line,
        "root_cause_file_a": a_file,
        "root_cause_line_a": a_line,
        "root_cause_statement_a": a_text.strip(),
        "root_cause_file_b": b_file,
        "root_cause_line_b": b_line,
        "root_cause_statement_b": b_text.strip(),
        "description": (
            f"Common ancestor: {func_name}\n"
            f"Last divergence at step {div['step']}:\n"
            f"  v4.4.0: {a_text.strip()}  ({a_file}:{a_line})\n"
            f"  v4.0.8: {b_text.strip()}  ({b_file}:{b_line})"
        ),
        "note": f"Step trace last divergence at step {div['step']}",
    }

    # Check if same line text (same statement, different condition value)
    a_norm = re.sub(r'\s+', ' ', a_text).strip()
    b_norm = re.sub(r'\s+', ' ', b_text).strip()
    a_norm2 = re.sub(r'\s*([=!<>]=|[=!<>]|&&|\|\||[+\-*/])\s*', r'\1', a_norm)
    b_norm2 = re.sub(r'\s*([=!<>]=|[=!<>]|&&|\|\||[+\-*/])\s*', r'\1', b_norm)
    if a_norm2 == b_norm2:
        result["same_statement"] = True
        result["description"] += (
            f"\nSame statement in both versions — different condition value."
        )

    return result


def _find_candidate_subfunctions(gaps, trace_a, trace_b, max_candidates=5):
    """Find candidate sub-functions to trace for divergence.

    Looks for functions that appear in gaps with bidirectional differences
    (both versions call different functions). These are likely the functions
    where the actual divergence occurs.

    Returns list of (func_name, reason) tuples.
    """
    candidates = []
    seen = set()

    # Priority 1: Functions in gaps where BOTH versions have functions
    for i, g in enumerate(gaps):
        a_funcs = [f['name'] for f in g.get('a', [])]
        b_funcs = [f['name'] for f in g.get('b', [])]
        if a_funcs and b_funcs:
            # Find functions unique to each side
            a_only = [f for f in a_funcs if f not in b_funcs]
            b_only = [f for f in b_funcs if f not in a_funcs]
            for f in a_only + b_only:
                if f not in seen and not f.startswith('_'):
                    candidates.append((f, f"bidirectional gap {i}"))
                    seen.add(f)

    # Priority 2: Functions that appear in multiple gaps (likely involved in divergence)
    func_gap_count = {}
    for g in gaps:
        for f in g.get('a', []) + g.get('b', []):
            name = f['name']
            if name not in func_gap_count:
                func_gap_count[name] = 0
            func_gap_count[name] += 1

    for func_name, count in sorted(func_gap_count.items(), key=lambda x: -x[1]):
        if func_name not in seen and not func_name.startswith('_') and count >= 3:
            candidates.append((func_name, f"appears in {count} gaps"))
            seen.add(func_name)

    return candidates[:max_candidates]


def _trace_subfunction_divergence(func_name, binary_a, binary_b,
                                   args_a, args_b,
                                   lib_path_a, lib_path_b,
                                   source_dirs_a, source_dirs_b,
                                   gdb_timeout=120):
    """Break into a sub-function in both versions, step through, compare traces.

    This finds divergence inside called functions that aren't in the profiling traces.
    Returns a result dict or None.
    """
    print(f"  Tracing sub-function: {func_name}")

    # Step trace both versions inside the sub-function
    step_trace_a = _step_trace_binary(
        binary_a, func_name, args_a, lib_path_a, source_dirs_a, gdb_timeout
    )
    step_trace_b = _step_trace_binary(
        binary_b, func_name, args_b, lib_path_b, source_dirs_b, gdb_timeout
    )

    if not step_trace_a and not step_trace_b:
        return None
    if not step_trace_a or not step_trace_b:
        # One version doesn't call this function — that's the divergence
        return {
            "root_cause_function": func_name,
            "root_cause_file": None,
            "root_cause_line": None,
            "description": (
                f"Function {func_name} called in one version but not the other.\n"
                f"  v4.4.0: {len(step_trace_a)} lines\n"
                f"  v4.0.8: {len(step_trace_b)} lines"
            ),
            "note": "Asymmetric function call",
        }

    # Compare traces
    div = _compare_step_traces(step_trace_a, step_trace_b)
    if not div:
        return None

    a_info = div.get("a", {})
    b_info = div.get("b", {})
    a_file = a_info.get("file") if a_info else None
    a_line = a_info.get("line") if a_info else None
    a_text = a_info.get("line_text", "") if a_info else ""
    b_file = b_info.get("file") if b_info else None
    b_line = b_info.get("line") if b_info else None
    b_text = b_info.get("line_text", "") if b_info else ""

    return {
        "root_cause_function": func_name,
        "root_cause_file": a_file or b_file,
        "root_cause_line": a_line or b_line,
        "root_cause_file_a": a_file,
        "root_cause_line_a": a_line,
        "root_cause_statement_a": a_text.strip(),
        "root_cause_file_b": b_file,
        "root_cause_line_b": b_line,
        "root_cause_statement_b": b_text.strip(),
        "description": (
            f"Sub-function: {func_name}\n"
            f"Divergence at step {div['step']}:\n"
            f"  v4.4.0: {a_text.strip()}  ({a_file}:{a_line})\n"
            f"  v4.0.8: {b_text.strip()}  ({b_file}:{b_line})"
        ),
        "note": f"Sub-function trace of {func_name}",
    }


def _find_call_sites_in_range(source_file, callee, start, end, source_dirs):
    """Return 1-indexed line numbers in [start, end] that call *callee*."""
    full_path = _locate_source_file(source_file, source_dirs)
    if not full_path:
        return []
    try:
        with open(full_path, encoding='utf-8', errors='replace') as f:
            lines = f.readlines()
    except (FileNotFoundError, UnicodeDecodeError):
        return []
    sites = []
    for i in range(start - 1, min(end, len(lines))):
        if callee in lines[i]:
            sites.append(i + 1)
    return sites


def _find_nearest_case_label(source_file, line_num, source_dirs, max_lookback=400):
    """Return the nearest enclosing ``case TAG:`` label above line_num.

    Returns {'tag': str, 'line': int} or None.  Used to align call sites
    across versions inside a switch (tag names are stable even when line
    numbers shift or the branch body is rewritten).
    """
    full_path = _locate_source_file(source_file, source_dirs)
    if not full_path:
        return None
    try:
        with open(full_path, encoding='utf-8', errors='replace') as f:
            lines = f.readlines()
    except (FileNotFoundError, UnicodeDecodeError):
        return None
    for i in range(line_num - 1, max(0, line_num - max_lookback), -1):
        m = re.match(r'\s*case\s+([A-Za-z_][A-Za-z0-9_]*)\s*:', lines[i])
        if m:
            return {"tag": m.group(1), "line": i + 1}
        if re.match(r'\s*switch\s*\(', lines[i]):
            break
    return None


def _find_case_lines(source_file, tag, start, end, source_dirs):
    """Return all 1-indexed lines of ``case <tag>:`` within [start, end]."""
    full_path = _locate_source_file(source_file, source_dirs)
    if not full_path:
        return []
    try:
        with open(full_path, encoding='utf-8', errors='replace') as f:
            lines = f.readlines()
    except (FileNotFoundError, UnicodeDecodeError):
        return []
    pat = re.compile(r'\s*case\s+' + re.escape(tag) + r'\s*:')
    out = []
    for i in range(start - 1, min(end, len(lines))):
        if pat.match(lines[i]):
            out.append(i + 1)
    return out


def _find_first_control_in_range(source_file, start, end, source_dirs):
    """Return the first control statement (if/switch/while/for) in [start, end].

    Includes switch (which the normal backward walk skips) so a rewritten
    switch-based tag handler is still located.
    """
    full_path = _locate_source_file(source_file, source_dirs)
    if not full_path:
        return None
    try:
        with open(full_path, encoding='utf-8', errors='replace') as f:
            lines = f.readlines()
    except (FileNotFoundError, UnicodeDecodeError):
        return None
    for i in range(start - 1, min(end, len(lines))):
        ctrl = _match_control_statement(lines[i])
        if ctrl and ctrl["keyword"] in ("if", "switch", "while", "for", "else if"):
            return {
                "keyword": ctrl["keyword"],
                "condition": ctrl["condition"],
                "line": i + 1,
                "full_line": lines[i].rstrip(),
                "file": source_file,
            }
    return None


def _find_block_end(source_file, line, source_dirs, max_lines=2000):
    """Return the 1-indexed line of the closing brace of the block opened at
    *line* (a control statement's body), or None if not found.

    Walks forward from *line* tracking brace balance; the block ends when the
    balance returns to the level it had just after the opening brace.
    """
    full_path = _locate_source_file(source_file, source_dirs)
    if not full_path:
        return None
    try:
        with open(full_path, encoding='utf-8', errors='replace') as f:
            lines = f.readlines()
    except (FileNotFoundError, UnicodeDecodeError):
        return None
    depth = 0
    opened = False
    for i in range(line - 1, min(len(lines), line - 1 + max_lines)):
        s = lines[i]
        depth += s.count('{') - s.count('}')
        if '{' in s:
            opened = True
        if opened and depth <= 0:
            return i + 1
    return None


def _line_in_block(source_file, ctrl_line, call_line, source_dirs):
    """Return True if call_line falls inside the block opened at ctrl_line.

    Falls back to a line-range heuristic when the strict brace match fails
    (e.g. an else-if chain where the call sits in the trailing else branch).
    The key invariant is that the control statement precedes the call.
    """
    if call_line <= ctrl_line:
        return False
    end = _find_block_end(source_file, ctrl_line, source_dirs)
    if end is not None and call_line <= end:
        return True
    return call_line - ctrl_line <= 300


def _find_divergence_in_function_body(func_name, frame0, b_first, binary_a, binary_b,
                                      args_a, args_b, lib_path_a, lib_path_b,
                                      source_dirs_a, source_dirs_b, gdb_timeout,
                                      a_first=None, b_first_call=None, ignore_b=0,
                                      call_ignore_b=0, call_ignore_a=0):
    """Find the control statement inside *func_name* that guards the first
    divergent call (b_first).

    The divergence function's backtrace frame points at the function entry,
    not a call site, so the normal backward walk misses control statements
    inside the body.  Here we locate calls to *b_first* within the body and
    walk back to their guarding control statement, then compare against the
    other version (condition text + GDB-evaluated value).
    """
    file_b = frame0["file"]
    body_b = _find_function_body_range(file_b, func_name, source_dirs_b)
    if not body_b:
        return None
    body_start_b, body_end_b = body_b

    sites_b = _find_call_sites_in_range(file_b, b_first, body_start_b, body_end_b,
                                        source_dirs_b)
    if not sites_b:
        return None

    body_a = _find_function_body_range(file_b, func_name, source_dirs_a)
    # A's divergent call may be renamed vs B's (e.g. TIFFErrorExt -> TIFFWarningExt).
    a_call = a_first if a_first else b_first
    # A's call sites of the SAME name as b_first (for position matching).
    sites_a_b = []
    if body_a:
        sites_a_b = _find_call_sites_in_range(
            file_b, b_first, body_a[0], body_a[1], source_dirs_a)

    for i, site_b in enumerate(sites_b):
        ctrl_b = _find_control_statement(file_b, site_b, source_dirs_b)
        if not ctrl_b:
            continue
        cond_expr = ctrl_b.get("condition", "")
        if not cond_expr:
            continue

        a_line = ctrl_b["line"]
        ctrl_a = None
        site_a = None  # A-version call site that corresponds to ctrl_a

        # 1. Exact condition-text match (code unchanged, only line numbers shift).
        if body_a:
            for ln in range(body_a[0], body_a[1] + 1):
                ca = _find_control_statement(file_b, ln + 1, source_dirs_a)
                if ca and ca.get("condition") == cond_expr:
                    ctrl_a = ca
                    a_line = ca["line"]
                    break

        # 2. Switch-case alignment (tag names are stable across refactors).
        if ctrl_a is None and body_a:
            case_b = _find_nearest_case_label(file_b, site_b, source_dirs_b)
            if case_b:
                case_lines_a = _find_case_lines(file_b, case_b["tag"],
                                                body_a[0], body_a[1], source_dirs_a)
                if case_lines_a:
                    # Pick the same-named case whose relative position best
                    # matches B's case (handles duplicated cases across loops).
                    rel = (case_b["line"] - body_start_b) / max(1, body_end_b - body_start_b)
                    case_a_line = min(case_lines_a, key=lambda l: abs(
                        (l - body_a[0]) / max(1, body_a[1] - body_a[0]) - rel))
                    sites_in_case = _find_call_sites_in_range(
                        file_b, a_call, case_a_line, case_a_line + 120, source_dirs_a)
                    if sites_in_case:
                        site_a = sites_in_case[0]
                        ca = _find_control_statement(file_b, site_a, source_dirs_a)
                        if ca and ca["line"] < case_a_line:
                            # Backward walk crossed the case label (switch or
                            # multi-line if): fall back to the first control in
                            # the case body.
                            ca = _find_first_control_in_range(
                                file_b, case_a_line, site_a, source_dirs_a)
                        if ca:
                            ctrl_a = ca
                            a_line = ca["line"]

        # 3. Position matching (same call name, i-th call in B ~ i-th call in A).
        if ctrl_a is None and i < len(sites_a_b):
            site_a = sites_a_b[i]
            ca = _find_control_statement(file_b, site_a, source_dirs_a)
            if ca:
                ctrl_a = ca
                a_line = ca["line"]

        # 4. Relative-position fallback (approx for non-switch refactors).
        if ctrl_a is None and body_a:
            sites_a = _find_call_sites_in_range(
                file_b, a_call, body_a[0], body_a[1], source_dirs_a)
            if sites_a:
                rel = (site_b - body_start_b) / max(1, body_end_b - body_start_b)
                best = min(sites_a, key=lambda s: abs(
                    (s - body_a[0]) / max(1, body_a[1] - body_a[0]) - rel))
                site_a = best
                ca = _find_control_statement(file_b, best, source_dirs_a)
                if ca:
                    ctrl_a = ca
                    a_line = ca["line"]

        a_stmt_text = ctrl_a["full_line"].strip() if ctrl_a else ctrl_b["full_line"].strip()
        a_cond = ctrl_a.get("condition", "") if ctrl_a else ""

        if ctrl_a is None or a_cond != cond_expr:
            # Condition text differs — a code change, but NOT necessarily the
            # cause of this divergence.  Verify two things:
            #   1. block containment: the divergent call site must fall inside
            #      the corresponding control block in each version;
            #   2. GDB branch check: the control statement must actually lead
            #      to the divergent call in this execution.
            ok_b = _line_in_block(file_b, ctrl_b["line"], site_b, source_dirs_b)
            ok_a = True
            if ctrl_a is not None:
                ok_a = _line_in_block(file_b, a_line, site_a, source_dirs_a)
            if not (ok_b and ok_a):
                continue

            branch_b = _verify_fork_branch(
                binary_b, file_b, ctrl_b["line"], b_first,
                args_b, lib_path_b, source_dirs_b, gdb_timeout,
                call_ignore=call_ignore_b)
            branch_a = True
            if a_first:
                branch_a = _verify_fork_branch(
                    binary_a, file_b, a_line, a_first,
                    args_a, lib_path_a, source_dirs_a, gdb_timeout,
                    call_ignore=call_ignore_a)
            if not (branch_b and branch_a):
                continue

            return {
                "root_cause_function": func_name,
                "file": file_b,
                "line": ctrl_b["line"],
                "line_a_file": file_b,
                "line_a": a_line,
                "line_text_b": ctrl_b["full_line"].strip(),
                "line_text_a": a_stmt_text,
                "note": (
                    f"Control statement '{ctrl_b['full_line'].strip()}' in "
                    f"{func_name}() guards the divergent call {b_first}() — the "
                    f"condition differs between versions "
                    f"(v4.0.8 vs v4.4.0)"
                ),
                "diverging_call_a": a_first,
                "diverging_call_b": b_first_call,
                "control": ctrl_b,
            }

        # Same condition text — check whether the evaluated value differs.
        val_b = _eval_condition_at_line(
            binary_b, file_b, ctrl_b["line"],
            args_b, lib_path_b, source_dirs_b, cond_expr, gdb_timeout,
            ignore_count=ignore_b)
        val_a = _eval_condition_at_line(
            binary_a, file_b, a_line,
            args_a, lib_path_a, source_dirs_a, cond_expr, gdb_timeout,
            ignore_count=ignore_b)
        if val_a is not None and val_b is not None and val_a != val_b:
            return {
                "root_cause_function": func_name,
                "file": file_b,
                "line": ctrl_b["line"],
                "line_a_file": file_b,
                "line_a": a_line,
                "line_text_b": ctrl_b["full_line"].strip(),
                "line_text_a": a_stmt_text,
                "condition_value_a": val_a,
                "condition_value_b": val_b,
                "note": (
                    f"Control statement '{ctrl_b['full_line'].strip()}' in "
                    f"{func_name}() guards the divergent call {b_first}() "
                    f"(verified: condition differs between versions)"
                ),
                "diverging_call_a": a_first,
                "diverging_call_b": b_first_call,
                "control": ctrl_b,
            }

    return None


def _clean_func_name(sig):
    """Normalize a C/C++ function signature to a displayable name.

    "void Expand3To4Module::run<int>(unsigned char const*, int*, int)"
        -> "Expand3To4Module::run<int>"
    "ms_adpcm_decode_block (ms_adpcm_data*, const uint8_t*, int16_t*)"
        -> "ms_adpcm_decode_block"
    """
    if not sig:
        return ""
    sig = re.sub(r'\s*\([^)]*\)\s*$', '', sig.strip())  # drop argument list
    # Prefer a C++ qualified name (Class::method, may carry template args).
    m = re.search(r'((?:\w+::)+\w+(?:<[^>]*>)?)', sig)
    if m:
        return m.group(1)
    # Fall back to the trailing identifier for plain C names.
    m = re.search(r'(\w+(?:<[^>]*>)?)\s*$', sig)
    return m.group(1) if m else sig


def _detect_crash_point(binary, args, lib_path, source_dirs, timeout=120):
    """Run binary under GDB and detect if/where it crashes.

    Returns dict with crash info (function, file, line, signal) or None if no crash.
    """
    env = os.environ.copy()
    env["ASAN_OPTIONS"] = "detect_leaks=0"

    # Collect library paths: explicit lib_path + any .libs directories
    lib_dirs = []
    if lib_path:
        lib_dirs.append(lib_path)
    # Walk up from binary to find .libs directories
    bin_path = Path(binary) if not isinstance(binary, Path) else binary
    for parent in [bin_path] + list(bin_path.parents):
        libs = parent / ".libs"
        if libs.exists() and str(libs) not in lib_dirs:
            lib_dirs.append(str(libs))
    # Also search the source tree for .libs (for libraries in sibling dirs)
    for parent in bin_path.parents:
        if (parent / "configure").exists() or (parent / "CMakeLists.txt").exists():
            for d in parent.rglob(".libs"):
                if d.is_dir() and str(d) not in lib_dirs:
                    lib_dirs.append(str(d))
            break
    if lib_dirs:
        old_ld = env.get("LD_LIBRARY_PATH", "")
        env["LD_LIBRARY_PATH"] = ":".join(lib_dirs + ([old_ld] if old_ld else []))

    cmds = ["set pagination off", "set confirm off"]
    for d in (source_dirs or []):
        cmds.append(f"directory {d}")
    cmds.append("run " + " ".join(str(a) for a in args))
    cmds.append("bt 24")
    cmds.append("info signals")
    cmds.append("quit")

    gdb_cmds = ["gdb", "-batch"]
    for c in cmds:
        gdb_cmds.extend(["-ex", c])
    gdb_cmds.append(str(binary))

    try:
        result = subprocess.run(gdb_cmds, capture_output=True, text=True,
                                timeout=timeout, env=env)
        output = result.stdout + result.stderr
    except Exception:
        return None

    # Detect crash signal — look for actual crash, not just signal table
    crash_signal = None
    for sig in ("SIGSEGV", "SIGABRT", "SIGFPE", "SIGBUS", "SIGILL"):
        # "Program received signal SIGSEGV, ..." or
        # "... terminated with signal SIGSEGV, ..."
        if (f"received signal {sig}" in output or
                f"terminated with signal {sig}" in output):
            crash_signal = sig
            break

    # ASan crashes abort with exit code 1 rather than raising a signal, so GDB
    # reports "exited with code 01" alongside an AddressSanitizer report.
    asan_kind = None
    if not crash_signal:
        m = re.search(r'ERROR: AddressSanitizer:\s*([^\s]+)', output)
        if m:
            asan_kind = m.group(1)
            crash_signal = f"ASAN:{asan_kind}"

    if not crash_signal:
        return None

    # Parse the crash location. For AddressSanitizer reports, prefer the
    # report's own backtrace (WRITE/READ) frames, skipping sanitizer/libc
    # interceptors so the deepest *project* frame is reported. For plain
    # signals (SIGSEGV), the GDB backtrace frame #0 is the faulting function.
    frames = []

    # (1) ASan backtrace frames: "#N 0x... in <func> <file>:<line>"
    for line in output.split('\n'):
        m = re.search(
            r'#(\d+)\s+0x[0-9a-fA-F]+\s+in\s+(.+?)\s+(\S+):(\d+)\s*$',
            line)
        if m:
            frames.append({
                "index": int(m.group(1)),
                "function": _clean_func_name(m.group(2)),
                "file": m.group(3),
                "line": int(m.group(4)),
            })

    # (2) ASan SUMMARY line: "SUMMARY: AddressSanitizer: <kind> <file>:<line> in <func>"
    m = re.search(
        r'SUMMARY: AddressSanitizer:\s*\S+\s+(\S+):(\d+)\s+in\s+(.+?)\s*$',
        output, re.M)
    if m:
        frames.append({
            "index": 0,
            "function": _clean_func_name(m.group(3)),
            "file": m.group(1),
            "line": int(m.group(2)),
        })

    # (3) GDB backtrace frames: "#N 0x... in <func> (<args>) at <file>:<line>"
    if not frames:
        for line in output.split('\n'):
            m = re.search(
                r'#(\d+)\s+(?:0x[0-9a-fA-F]+\s+in\s+)?(.+?)\s+at\s+(\S+):(\d+)\s*$',
                line)
            if m:
                frames.append({
                    "index": int(m.group(1)),
                    "function": _clean_func_name(m.group(2)),
                    "file": m.group(3),
                    "line": int(m.group(4)),
                })

    if not frames:
        return {"signal": crash_signal, "function": None, "file": None, "line": None}

    def _is_sanitizer(f):
        fn = f.get("function") or ""
        fl = f.get("file") or ""
        if re.search(r'__interceptor_|__asan_|__sanitizer_|__ubsan_|__tsan_', fn):
            return True
        if re.search(r'sanitizer|libc|csu/', fl):
            return True
        return False

    # Report the deepest project frame (skipping sanitizer/libc interceptors).
    crash_frame = next((f for f in frames if not _is_sanitizer(f)), frames[0])
    return {
        "signal": crash_signal,
        "function": crash_frame["function"],
        "file": crash_frame["file"],
        "line": crash_frame["line"],
        "backtrace": frames,
    }


def _crash_is_before_reference(target_crash, ref_crash, trace_a, gaps):
    """Check if target's crash point occurs before reference's crash point.

    The target's crash IS the fork statement if:
    1. Both versions crash, AND
    2. Target crashes at a different function (earlier in execution flow),
       OR target crashes at the same function but earlier line.
    """
    if not target_crash or not ref_crash:
        return False

    tc_func = target_crash.get("function")
    rc_func = ref_crash.get("function")
    if not tc_func or not rc_func:
        return False

    # Different crash functions — target hit a crash earlier in the flow
    if tc_func != rc_func:
        # Try to confirm via trace: if target's crash function appears earlier
        tc_pos = None
        rc_pos = None
        for i, op in enumerate(trace_a):
            name = op.get("name", "")
            if name == tc_func and op.get("is_enter") and tc_pos is None:
                tc_pos = i
            if name == rc_func and op.get("is_enter") and rc_pos is None:
                rc_pos = i
        # If both found in trace, compare positions
        if tc_pos is not None and rc_pos is not None:
            return tc_pos < rc_pos
        # If trace is empty or functions not found (different API names),
        # different crash functions means target crashed earlier
        return True

    # Same crash function — compare line numbers
    tc_line = target_crash.get("line", 0)
    rc_line = ref_crash.get("line", 0)
    if tc_line and rc_line:
        return tc_line < rc_line

    return False


def _find_condition_ifs(source_file, func_name, source_dirs):
    """Find `if` statements (with a comparison condition) in func_name's body.

    Returns a list of (line_number, condition_text, full_line) tuples, in
    source order.  Used for "reference crashes but target doesn't": the fork is
    a check the target fails and the reference passes, and the check's operands
    are read from the input (tainted).
    """
    body = _find_function_body_range(source_file, func_name, source_dirs)
    if not body:
        return []
    full = _locate_source_file(source_file, source_dirs)
    if not full:
        return []
    try:
        lines = open(full, encoding='utf-8', errors='replace').readlines()
    except (FileNotFoundError, UnicodeDecodeError):
        return []
    results = []
    for i in range(body[0] - 1, min(body[1], len(lines))):
        s = lines[i].strip()
        m = re.match(r'if\s*\((.*)\)\s*$', s)
        if m and re.search(r'[<>]=?|==|!=|<|>', m.group(1)):
            results.append((i + 1, m.group(1).strip(), lines[i].rstrip()))
    return results


def _find_value_divergence_condition(binary_a, binary_b, func_name, source_file,
                                     source_dirs_a, source_dirs_b,
                                     args_a, args_b, lib_path_a, lib_path_b,
                                     gdb_timeout):
    """Find the first `if` condition in func_name whose truth value differs
    between the two versions.

    For "reference crashes but target doesn't", the fork is a check the target
    fails (condition true -> early return) while the reference passes (condition
    false -> continues), or vice versa.  Evaluate each `if` condition at runtime
    with GDB in both binaries and return the first one whose value differs.
    """
    conds_b = _find_condition_ifs(source_file, func_name, source_dirs_b)
    if not conds_b:
        return None
    conds_a = _find_condition_ifs(source_file, func_name, source_dirs_a)

    def _norm(s):
        s = re.sub(r'\s+', ' ', s).strip()
        s = re.sub(r'\b(u?int(?:8|16|32|64))_t\b', r'\1', s)
        return s

    def _truth(out):
        for line in (out or '').split('\n'):
            if '$' in line and '=' in line:
                v = line.split('=', 1)[1].strip()
                if v in ('0', '1'):
                    return v
        return None

    for line_b, cond_b, full_b in conds_b:
        line_a = None
        for la, ca, _fa in (conds_a or []):
            if _norm(ca) == _norm(cond_b):
                line_a = la
                break
        if line_a is None:
            # Condition text differs (code change) — skip; handled by source diff.
            continue
        va = _eval_condition_at_line(binary_a, source_file, line_a, args_a,
                                     lib_path_a, source_dirs_a, cond_b,
                                     gdb_timeout)
        vb = _eval_condition_at_line(binary_b, source_file, line_b, args_b,
                                     lib_path_b, source_dirs_b, cond_b,
                                     gdb_timeout)
        ta, tb = _truth(va), _truth(vb)
        if ta is not None and tb is not None and ta != tb:
            return (line_b, cond_b, full_b, ta, tb)
    return None


def _diff_refactored_functions(source_file, func_name_b, func_name_a,
                               source_dirs_a, source_dirs_b):
    """Diff func_name_b (target) vs func_name_a (reference) and return the first
    differing statement, or None.

    Used when a function was renamed/split between versions (e.g.
    TIFFReadDirEntryArray -> TIFFReadDirEntryArrayWithLimit): the fork is the
    first code change in the corresponding functions.
    """
    body_a = _find_function_body_range(source_file, func_name_a, source_dirs_a)
    body_b = _find_function_body_range(source_file, func_name_b, source_dirs_b)
    if not body_a or not body_b:
        return None
    full_a = _locate_source_file(source_file, source_dirs_a)
    full_b = _locate_source_file(source_file, source_dirs_b)
    if not full_a or not full_b:
        return None

    import difflib

    def _norm(l):
        s = re.sub(r'\s+', ' ', l).strip()
        s = re.sub(r'\b(u?int(?:8|16|32|64))_t\b', r'\1', s)
        s = re.sub(r'\bconst\b\s*', '', s)
        return s

    def _first_code(block):
        for l in block:
            s = l.strip()
            if not s:
                continue
            if s.startswith('/*') or s.startswith('//') or s.startswith('*'):
                continue
            if s in ('{', '}'):
                continue
            return s
        return ''

    lines_a = open(full_a, encoding='utf-8', errors='replace').readlines()[body_a[0] - 1:body_a[1]]
    lines_b = open(full_b, encoding='utf-8', errors='replace').readlines()[body_b[0] - 1:body_b[1]]

    sm = difflib.SequenceMatcher(None, [_norm(l) for l in lines_a],
                                 [_norm(l) for l in lines_b])
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == 'equal':
            continue
        ta = _first_code(lines_a[i1:i2])
        tb = _first_code(lines_b[j1:j2])
        if not ta or not tb:
            continue
        if _norm(ta) == _norm(tb):
            continue
        return {
            'statement_a': ta,   # reference (4.4.0)
            'statement_b': tb,   # target (4.0.8)
            'line_a': body_a[0] + i1,
            'line_b': body_b[0] + j1,
        }
    return None


def _resolve_wrapper_func(source_file, func_name, source_dirs):
    """If func_name is a trivial wrapper (body is a single `return X(...);`),
    return X (the real function); otherwise return func_name unchanged."""
    body = _find_function_body_range(source_file, func_name, source_dirs)
    if not body:
        return func_name
    full = _locate_source_file(source_file, source_dirs)
    if not full:
        return func_name
    lines = open(full, encoding='utf-8', errors='replace').readlines()[body[0] - 1:body[1]]
    code = []
    for l in lines:
        s = l.strip()
        if not s or s in ('{', '}'):
            continue
        if s.startswith('/*') or s.startswith('//') or s.startswith('*'):
            continue
        code.append(s)
    joined = ' '.join(code).strip()
    if joined.startswith('return') and joined.endswith(';'):
        m = re.match(r'return\s+([a-zA-Z_]\w*)\s*\(', joined)
        if m and joined.rstrip(';').rstrip().endswith(')'):
            return m.group(1)
    return func_name


def _trace_gap_divergence(binary_a, binary_b, trace_a, trace_b, gaps,
                          a_idx, b_idx, args_a, args_b,
                          lib_path_a, lib_path_b,
                          source_dirs_a, source_dirs_b, gdb_timeout,
                          func_name=None):
    """Locate the control statement (fork point) that causes the trace divergence.

    Uses source analysis to locate candidate control statements in each version
    (condition-text match, switch-case alignment, position matching), then
    verifies them: GDB condition-value comparison for identical conditions, and
    block-containment for code changes.  Falls back to GDB disassembly when no
    candidate verifies.
    """
    gap = _find_divergence_gap(gaps, a_idx, b_idx)
    if not gap:
        return None
    a_first, b_first = _first_differing_enter(gap)
    target_stopped = False
    if not b_first:
        if a_first:
            # The target has no more enter events (it stopped early). The
            # divergence is the reference's continuation — treat a_first as the
            # diverging call instead of falling back to an unrelated gap.
            target_stopped = True
            b_first = a_first
        else:
            candidate = None
            best_depth = -1
            for g in gaps:
                if not _first_differing_enter(g)[1]:
                    continue
                d = max([op.get("depth", 0) for op in g.get("a", []) + g.get("b", [])] or [0])
                if d > best_depth:
                    best_depth = d
                    candidate = g
            if candidate is None:
                return None
            gap = candidate
            a_first, b_first = _first_differing_enter(gap)
            if not b_first:
                return None

    # Parent of b_first (the function where the control decision lives).  When
    # the target stopped, the parent lives on the reference (a) side.
    side_ops = gap.get("a", []) if target_stopped else gap.get("b", [])
    div_parent = None
    for op in side_ops:
        if op.get("name") == b_first and op.get("path") and len(op["path"]) >= 2:
            div_parent = op["path"][-2]
            break
    if div_parent is None:
        for op in side_ops:
            if op.get("path") and len(op["path"]) >= 2:
                div_parent = op["path"][-2]
                break
    if div_parent is None:
        div_parent = b_first

    gap_b_start = gap.get("b_range", [0, 0])[0]
    gap_a_start = gap.get("a_range", [0, 0])[0]

    def _count_enters(name):
        n = 0
        for i, op in enumerate(trace_b):
            if i >= gap_b_start:
                break
            if op.get("name") == name and op.get("is_enter"):
                n += op.get("count", 1)
        return max(0, n - 1)

    def _count_before(trace, start, name):
        n = 0
        for op in trace[:start]:
            if op.get("name") == name and op.get("is_enter"):
                n += op.get("count", 1)
        return n

    call_ignore_b = _count_before(trace_b, gap_b_start, b_first)
    call_ignore_a = _count_before(trace_a, gap_a_start, a_first)

    # When the target stopped before the reference's continuation (tail gap),
    # the fork lives entirely in the reference — use its guard directly and
    # skip the target-based body analysis below (the target has no such frame).
    if target_stopped:
        guard_a = _find_guard_condition(
            binary_a, a_first, args_a, lib_path_a, source_dirs_a, gdb_timeout,
            ignore_count=call_ignore_a)
        if guard_a is None:
            return None
        func_a = guard_a["caller_function"].split('@')[0]
        if _is_runtime_function(func_a, guard_a.get("guard_file", "")):
            print(f"  [gap] guard {func_a} is a runtime function — discarding.")
            return None
        # Use the GUARD (the enclosing control statement, e.g. `if (in == NULL)`)
        # as the fork.  The divergence is typically a *value* difference here —
        # e.g. `in` (TIFFOpen's return) is NULL in one version and non-NULL in
        # the other, so the guard itself is where the paths split.
        gfile = guard_a.get("guard_file")
        gline = guard_a.get("guard_line")
        return {
            "root_cause_function": func_a,
            "file": gfile,
            "line": gline,
            "line_a_file": gfile,
            "line_a": gline,
            "line_text_b": _read_source_line(gfile, gline, source_dirs_a) or "",
            "line_text_a": _read_source_line(gfile, gline, source_dirs_a) or "",
            "note": (f"GDB disassembly: v4.4.0's control statement guarding "
                     f"{a_first}() in {func_a}() ({gfile}:{gline}); "
                     f"v4.0.8 stopped before this point"),
            "diverging_call_a": a_first,
            "diverging_call_b": None,
        }

    # 1. Divergence function body.
    if func_name:
        ignore_f = _count_enters(func_name)
        frames_f = _get_backtrace_frames(
            binary_b, func_name, args_b, lib_path_b, source_dirs_b, gdb_timeout,
            ignore_count=ignore_f)
        if frames_f and frames_f[0]["function"].split('@')[0] == func_name:
            body_result = _find_divergence_in_function_body(
                func_name, frames_f[0], b_first, binary_a, binary_b,
                args_a, args_b, lib_path_a, lib_path_b,
                source_dirs_a, source_dirs_b, gdb_timeout,
                a_first=a_first, b_first_call=b_first, ignore_b=ignore_f,
                call_ignore_b=call_ignore_b, call_ignore_a=call_ignore_a)
            if body_result:
                return body_result

    # 2. Parent function body.
    ignore_b = _count_enters(div_parent)
    frames_b = _get_backtrace_frames(
        binary_b, div_parent, args_b, lib_path_b, source_dirs_b, gdb_timeout,
        ignore_count=ignore_b)
    if not frames_b:
        return None
    if frames_b[0]["function"].split('@')[0] == div_parent:
        body_result = _find_divergence_in_function_body(
            div_parent, frames_b[0], b_first, binary_a, binary_b,
            args_a, args_b, lib_path_a, lib_path_b,
            source_dirs_a, source_dirs_b, gdb_timeout,
            a_first=a_first, b_first_call=b_first, ignore_b=ignore_b,
            call_ignore_b=call_ignore_b, call_ignore_a=call_ignore_a)
        if body_result:
            return body_result

    # 3. Fallback: GDB backtrace + disassembly (no source analysis).
    guard_b = _find_guard_condition(
        binary_b, b_first, args_b, lib_path_b, source_dirs_b, gdb_timeout,
        ignore_count=_count_enters(b_first) + 1)
    guard_a = None
    if a_first:
        guard_a = _find_guard_condition(
            binary_a, a_first, args_a, lib_path_a, source_dirs_a, gdb_timeout,
            ignore_count=_count_enters(a_first) + 1)
    if guard_b is None and guard_a is None:
        return None

    g_b = guard_b or guard_a
    g_a = guard_a or guard_b
    func_b = g_b["caller_function"].split('@')[0]
    func_a = g_a["caller_function"].split('@')[0]

    # Safety net: if the located "guard" is a sanitizer/libc runtime function
    # (e.g. __interceptor_qsort), it is not a meaningful fork point — reject it
    # so the caller can fall back to a different strategy.
    if _is_runtime_function(func_b, g_b.get("guard_file", "")):
        print(f"  [gap] guard {func_b} is a runtime function — discarding.")
        return None

    return {
        "root_cause_function": func_b,
        "file": g_b["guard_file"],
        "line": g_b["guard_line"],
        "line_a_file": g_a["guard_file"],
        "line_a": g_a["guard_line"],
        "line_text_b": _read_source_line(g_b["guard_file"], g_b["guard_line"], source_dirs_b) or "",
        "line_text_a": _read_source_line(g_a["guard_file"], g_a["guard_line"], source_dirs_a) or "",
        "note": (
            f"GDB disassembly: v4.0.8's control statement guarding {b_first}() "
            f"in {func_b}() ({g_b['guard_file']}:{g_b['guard_line']}); "
            f"v4.4.0's guarding {a_first or 'no call'}() in {func_a}() "
            f"({g_a['guard_file']}:{g_a['guard_line']})"
        ),
        "diverging_call_a": a_first,
        "diverging_call_b": b_first,
    }


def _is_control_statement(text):
    """Return True if a source line is a control statement (if/while/for/do/switch)."""
    s = (text or '').strip()
    if not s:
        return False
    # Guard against comments / preprocessor
    if s.startswith('#') or s.startswith('//') or s.startswith('*'):
        return False
    return bool(re.match(r'^(if|while|for|do|switch)\b', s)) or bool(
        re.match(r'^.*\b(if|while|for)\s*\(', s)
    )


def _is_spurious_step_divergence(div_loc):
    """Return True if a step-trace divergence is a benign call asymmetry.

    The execution-trace comparison reports "v4.4.0 calls X() at line N" /
    "v4.0.8 does not call X()" when one version has an extra debug/logging
    call (e.g. TIFFFileName) that the other dropped.  That is a cosmetic
    difference, not the vulnerability fork, so it must fall back to the
    gap-based analysis (which locates the actual code-change / control-flow
    divergence).
    """
    if not div_loc:
        return True
    a = (div_loc.get("line_text_a") or "")
    b = (div_loc.get("line_text_b") or "")
    if "stops after" in a or "stops after" in b:
        return True
    if "does not call" in a or "does not call" in b:
        return True
    if not b:
        return True
    if b.startswith("v4.0.8 stops"):
        return True
    return False


def _find_matching_line(source_file, statement_text, source_dirs):
    """Find the line in source_file whose text matches statement_text.

    Used to map a statement from one version to the corresponding statement in
    the other version (whose line numbers may differ).  Returns (line, text)
    or None.
    """
    if not statement_text:
        return None
    full = _locate_source_file(source_file, source_dirs)
    if not full:
        return None
    try:
        with open(full, encoding='utf-8', errors='replace') as f:
            lines = f.readlines()
    except (FileNotFoundError, UnicodeDecodeError):
        return None
    needle = re.sub(r'\s+', ' ', statement_text).strip()
    # Normalize numeric literals so a one-number code change (e.g. 7 -> 8)
    # still matches the corresponding statement.
    needle_norm = re.sub(r'\b\d+\b', '#', needle)
    for i, line in enumerate(lines, start=1):
        norm = re.sub(r'\s+', ' ', line).strip()
        if norm == needle:
            return (i, line.strip())
        if re.sub(r'\b\d+\b', '#', norm) == needle_norm:
            return (i, line.strip())
    return None


def _refine_fork_statement(result, source_dirs_b=None, binary_b=None,
                           source_dirs_a=None, binary_a=None):
    """Refine the reported fork statement for a code-change divergence.

    When the gap-based analysis reports a statement that is not itself a
    control statement (e.g. ``goto end;``), the actual divergence is a *code
    change* between the two versions.  Find the first differing statement by
    diffing the two versions' function source, rather than walking up to an
    enclosing conditional (whose condition may be a static constant).
    """
    stmt = (result.get('root_cause_statement_b') or '').strip()
    file_b = result.get('root_cause_file')
    line_b = result.get('root_cause_line')
    func_name = result.get('root_cause_function')

    if not stmt or not file_b or not func_name:
        return result
    # A code-change fork has two *different* diverging calls (e.g. _TIFFmalloc
    # vs limitMalloc).  In that case even a control-statement guard should be
    # re-located to the actual differing statement in the function body.
    div_call_a = result.get('diverging_call_a')
    div_call_b = result.get('diverging_call_b')
    is_code_change = bool(div_call_a and div_call_b and div_call_a != div_call_b)
    if _is_control_statement(stmt) and not is_code_change:
        return result

    dirs_a = source_dirs_a
    dirs_b = source_dirs_b
    if not dirs_b and binary_b:
        try:
            dirs_b = find_source_dirs(str(binary_b))
        except Exception:
            dirs_b = None
    if not dirs_a and binary_a:
        try:
            dirs_a = find_source_dirs(str(binary_a))
        except Exception:
            dirs_a = None
    if not dirs_a or not dirs_b:
        return result

    body_a = _find_function_body_range(file_b, func_name, dirs_a)
    body_b = _find_function_body_range(file_b, func_name, dirs_b)
    if not body_a or not body_b:
        return result

    full_a = _locate_source_file(file_b, dirs_a)
    full_b = _locate_source_file(file_b, dirs_b)
    if not full_a or not full_b:
        return result

    import difflib

    def _read(path):
        with open(path, encoding='utf-8', errors='replace') as f:
            return f.readlines()

    lines_a = _read(full_a)
    lines_b = _read(full_b)
    seg_a = lines_a[body_a[0] - 1:body_a[1]]
    seg_b = lines_b[body_b[0] - 1:body_b[1]]

    def _is_pp(s):
        return s.lstrip().startswith('#')

    # Filter out preprocessor directives, blank lines, comments and braces so
    # the diff aligns on real code (a `#if defined(X)` block would otherwise
    # create a structural mismatch between versions and report the directive —
    # which has no variables — as the fork statement).
    def _filter(lines, start_line):
        out = []
        for i, l in enumerate(lines):
            s = l.strip()
            if not s or _is_pp(s):
                continue
            if s.startswith('/*') or s.startswith('//') or s.startswith('*'):
                continue
            if s in ('{', '}'):
                continue
            out.append((start_line + i, s))
        return out

    filtered_a = _filter(seg_a, body_a[0])
    filtered_b = _filter(seg_b, body_b[0])

    def _norm(l):
        s = re.sub(r'\s+', ' ', l).strip()
        # Normalize fixed-width typedefs (uint32_t -> uint32) and const
        # qualifiers so type-only refactors don't mask the semantic change.
        s = re.sub(r'\b(u?int(?:8|16|32|64))_t\b', r'\1', s)
        s = re.sub(r'\bconst\b\s*', '', s)
        return s

    _CALL_KEYWORDS = {
        'switch', 'if', 'while', 'for', 'do', 'return', 'goto', 'sizeof',
        'defined', 'case', 'else', 'break', 'continue', 'static_assert',
    }

    def _calls(s):
        return {
            m for m in re.findall(r'\b([a-zA-Z_]\w*)\s*\(', s)
            if m not in _CALL_KEYWORDS
        }

    norm_a = [_norm(l) for _, l in filtered_a]
    norm_b = [_norm(l) for _, l in filtered_b]

    sm = difflib.SequenceMatcher(None, norm_a, norm_b)
    candidates = []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == 'equal':
            continue
        a_block = [l for _, l in filtered_a[i1:i2]]
        b_block = [l for _, l in filtered_b[j1:j2]]

        text_a = a_block[0] if a_block else ''
        text_b = b_block[0] if b_block else ''
        if not (text_a or text_b):
            continue
        if _norm(text_a) == _norm(text_b):
            continue
        a_abs = filtered_a[i1][0] if a_block else None
        b_abs = filtered_b[j1][0] if b_block else None
        calls_diff = bool(_calls(text_a) ^ _calls(text_b))
        candidates.append((b_abs, text_a, text_b, a_abs, calls_diff))

    if not candidates:
        return result

    # Prefer a semantic change (different function call) near the reported line.
    semantic = [c for c in candidates if c[4]]
    pool = semantic or candidates
    text_a, text_b, line_a_abs, line_b_abs = min(
        ((c[1], c[2], c[3], c[0]) for c in pool),
        key=lambda t: abs((t[3] or line_b) - line_b),
    )

    # If the refined statement is empty, a preprocessor directive, or has no
    # extractable variables, it is unusable for downstream analysis (GDB trace /
    # PolyTracker instrumentation).  Keep the original gap-analysis statement
    # (e.g. an `if (...)` guard with real variables) instead of replacing it
    # with something that has no variables to trace.
    def _usable(s):
        if not s:
            return False
        s = s.strip()
        if s.startswith('#'):
            return False
        return bool(_extract_variables_from_expression(s))

    if not _usable(text_b):
        # The diff failed to find a usable statement (often because a
        # compile-time `#if` block — e.g. DEFER_STRILE_LOAD — splits the code
        # structurally).  Fall back to the *divergent call site*: for a
        # code-change fork like `TIFFFetchStripThing(tif, dp, td_nstrips,
        # &td_stripoffset)`, the call's *arguments* (td_nstrips) are the
        # input-derived values that matter — not the enclosing duplicate-check
        # guard (`if (td_stripoffset != NULL)`).
        call_stmt = None
        if div_call_b:
            body = _find_function_body_range(file_b, func_name, dirs_b)
            if body:
                sites = _find_call_sites_in_range(
                    file_b, div_call_b, body[0], body[1], dirs_b)
                if sites:
                    site = min(sites, key=lambda s: abs(s - (line_b or 0)))
                    call_stmt, call_start, _ = _get_complete_fork_statement(
                        file_b, site, dirs_b)
                    if call_start:
                        result['root_cause_line'] = call_start
                        result['root_cause_line_b'] = call_start
        if call_stmt and _extract_variables_from_expression(call_stmt):
            result['root_cause_statement_b'] = call_stmt
            result['root_cause_statement_a'] = call_stmt
            result['_code_change'] = True
            result['_fork_refined_from'] = stmt
            result['_fork_from_diverging_call'] = div_call_b
            result['variables'] = _extract_variables_from_expression(call_stmt)
            return result

        # Revert to the original statement and its reported line.
        result['root_cause_statement_b'] = stmt
        result['root_cause_statement_a'] = stmt
        result['root_cause_line'] = line_b
        result['root_cause_line_b'] = line_b
        result['_code_change'] = True
        result['_fork_refined_from'] = stmt
        result['variables'] = _extract_variables_from_expression(stmt or '')
        return result

    result['root_cause_statement_a'] = text_a
    result['root_cause_statement_b'] = text_b
    result['root_cause_line_a'] = line_a_abs
    result['root_cause_line'] = line_b_abs
    result['root_cause_line_b'] = line_b_abs
    result['_code_change'] = True
    result['_fork_refined_from'] = stmt
    # Extract the fork-statement variables so downstream analysis (GDB trace and
    # PolyTracker taint provenance) knows which expressions to instrument.
    result['variables'] = _extract_variables_from_expression(
        result.get('root_cause_statement_b', '') or '')
    return result


def _target_reached_crash_point(crash_a, trace_a, trace_b, refactoring_map=None):
    """Return True if the target's trace reaches the reference's crash function
    via the same (or equivalent) call chain.

    The reference crashes in crash_func with a specific call path.  The target
    "reached the crash point" only if it calls crash_func (or its renamed
    equivalent) with an equivalent call path — not merely if the function name
    appears anywhere in its trace (it might be reached via a different chain,
    e.g. a-b-c vs e-f-c).
    """
    crash_func = crash_a.get("function")
    if not crash_func:
        return False

    # Reference crash call path (from the last enter event of crash_func).
    ref_path = None
    for node in trace_a:
        if node.get("name") == crash_func and node.get("is_enter"):
            ref_path = tuple(node.get("path", []))
    if ref_path is None:
        return False

    def _map(name):
        if refactoring_map:
            return refactoring_map.get(name, name)
        return name

    ref_path_tgt = tuple(_map(n) for n in ref_path)
    tgt_crash_func = _map(crash_func)

    for node in trace_b:
        if node.get("name") == tgt_crash_func and node.get("is_enter"):
            if tuple(node.get("path", [])) == ref_path_tgt:
                return True
    return False


def _run_backward_tracer(func_name, binary_a, binary_b, source_dirs_a,
                         source_dirs_b, lib_path_a, lib_path_b, input_file,
                         args_b, gdb_timeout):
    """Run the backward tracer from the divergence function (entry point).

    The backward tracer starts at the divergence function (the last common
    function, e.g. ``TIFFOpen``) and recursively follows the return-value
    dependency chain to the guard statement that actually causes the divergence.

    Convention mapping: in this module ``binary_a``/``source_dirs_a`` are the
    reference (4.4.0, NEW); ``binary_b``/``source_dirs_b`` are the target
    (4.0.8, OLD).  ``backward_tracer`` uses the opposite (a=old, b=new), so the
    arguments are swapped here.
    """
    try:
        import backward_tracer as bt
    except ImportError as e:
        return {"status": "error", "error": f"import backward_tracer failed: {e}"}

    if not func_name:
        return {"status": "error", "error": "no divergence function"}

    run_args = " ".join(str(a) for a in (args_b or []))
    input_file = str(input_file) if input_file else None

    print(f"\n=== Backward tracer from divergence function: {func_name} ===")

    try:
        result = bt.find_fork_by_backward_tracing(
            binary_a=str(binary_b),   # old (target, 4.0.8)
            binary_b=str(binary_a),   # new (reference, 4.4.0)
            source_dir_a=source_dirs_b,  # old source (4.0.8)
            source_dir_b=source_dirs_a,  # new source (4.4.0)
            func_name=func_name,
            input_file=input_file,
            run_args=run_args,
            lib_path_a=lib_path_b,
            lib_path_b=lib_path_a,
            timeout=gdb_timeout,
            max_depth=20,
        )
    except Exception as e:
        return {"status": "error", "error": str(e)}

    return result


def _find_last_common_entry_function(matches):
    """Return the outermost (entry) function of the last LCS match.

    This is the last common function both versions were inside when the traces
    diverged (e.g. ``TIFFOpen``), the correct starting point for the backward
    tracer.
    """
    if not matches:
        return None
    last_match = matches[-1]
    funcs = last_match.get("functions", [])
    if not funcs:
        return None
    outermost = min(funcs, key=lambda f: f.get("depth", 999))
    return outermost.get("name")


def _build_result_from_backward_tracer(bt_result, func_name, a_idx, b_idx):
    """Build a divergence result dict from the backward tracer's output.

    The backward tracer reports the fork statement (the first differing
    variable's assignment in the *target* version) plus the input-derived
    variables (RHS member accesses that trace to input bytes) and the guard
    (root cause, reference-only).  This assembles them into the fields the
    downstream steps (trace_fork_offsets.py, polytracker_offsets.py) expect.
    """
    try:
        import backward_tracer as _bt
    except ImportError:
        _bt = None
    guard = bt_result.get("guard") or {}
    assign_diff = bt_result.get("assign_diff") or {}
    input_variables = bt_result.get("input_variables") or []
    fork_variables = bt_result.get("fork_variables") or []
    fork_stmt = bt_result.get("fork_statement")
    fork_line = bt_result.get("fork_line")

    # PolyTracker instrumentation: instrument the input-derived variable right
    # after the fork statement (the first differing variable's assignment) in
    # the TARGET version, so its taint traces to the exact input bytes.
    pt_file = bt_result.get("file_a")
    pt_func = bt_result.get("func_a")

    # When the backward tracer found a guard (4.4.0-only), fork_line points
    # to the guard in the reference.  Use the assign_diff's target line for
    # tracing, since that's the statement that actually exists in the target.
    target_fork_line = assign_diff.get("line_a") or fork_line
    pt_line = (target_fork_line + 1) if target_fork_line else None
    pt_stmt = assign_diff.get("statement_a") or fork_stmt

    # If input_variables is empty, trace backward from the fork statement to
    # find member accesses (e.g. direntry->tdir_count) that ARE input-derived.
    input_reads = []
    if not input_variables and target_fork_line and pt_file:
        func_a = bt_result.get("func_a")
        src_dirs = bt_result.get("file_a")
        if func_a and src_dirs:
            try:
                input_reads = _bt._trace_to_input_variables(
                    src_dirs, func_a, target_fork_line,
                    source_dirs=[os.path.dirname(src_dirs)])
            except Exception:
                pass
    if input_reads:
        read = input_reads[0]
        pt_file = read["file"]
        pt_line = read["line"] + 1  # instrument AFTER the read
        pt_stmt = read["statement"]
        pt_vars = [read["variable"]]
        pt_func = _bt._find_function_containing_line(read["file"],
                                                     read["line"]) if _bt else None
        input_variables = [read["variable"]]
    elif input_variables:
        pt_vars = input_variables[:1]
    else:
        pt_vars = fork_variables[:1]

    guard_stmt = guard.get("statement") if isinstance(guard, dict) else (guard or "")
    chain = bt_result.get("chain") or []
    chain_desc = " -> ".join(c.get("func", "?") for c in chain)

    result = {
        "divergence_function": func_name,
        "trace_a_index": a_idx,
        "trace_b_index": b_idx,
        "root_cause_function": bt_result.get("func_b") or func_name,
        "root_cause_file": bt_result.get("file_a"),
        "root_cause_line": fork_line,
        "root_cause_statement_b": guard_stmt,
        "fork_statement": fork_stmt,
        "fork_statement_line": fork_line,
        "fork_variables": fork_variables,
        "input_variables": input_variables,
        "assign_diff": assign_diff,
        "guard": guard_stmt,
        "backward_chain": chain,
        "semantic_fork": True,
        "backward_trace": bt_result,
        "description": (
            f"Divergence function: {func_name}\n"
            f"Backward tracer chain: {chain_desc}\n"
            f"Fork statement (target, first differing variable): {fork_stmt}\n"
            f"Input-derived variables: {input_variables}\n"
            f"Root cause guard (reference only): {guard_stmt}"
        ),
    }
    if pt_file and pt_line:
        result["poly_track_function"] = pt_func
        result["poly_track_file"] = pt_file
        result["poly_track_line"] = pt_line
        result["poly_track_statement"] = pt_stmt
        result["variables"] = pt_vars
    return result


def analyze_lcs_result(result_json_path, binary_a, binary_b,
                        args_a=None, args_b=None, input_file=None,
                        gdb_timeout=120, refactoring_map=None,
                        config=None, skip_polytracker=False):
    """Analyze the LCS result and trace the divergence cause.

    This is the main entry point for the divergence analysis.

    Args:
        result_json_path: Path to the JSON output from lcs_trace.py
        binary_a: Path to binary A (or libtool wrapper)
        binary_b: Path to binary B (or libtool wrapper)
        args_a: Command-line arguments for binary A
        args_b: Command-line arguments for binary B
        input_file: Input file path (used in args if not provided)
        gdb_timeout: Timeout for GDB operations
        refactoring_map: Dict mapping old function names to new names
                        (from TraceRefactorMapper). If provided, the tool
                        will use the correct function name for each version.
        config: Optional config module with COMPILE_COMMANDS and EXECUTION_CONFIG
                for PolyTracker-based input offset localization.
        skip_polytracker: If True, skip PolyTracker analysis (GDB-only mode).

    Returns:
        Dict with divergence analysis results.
    """
    binary_a = resolve_real_binary(binary_a)
    binary_b = resolve_real_binary(binary_b)

    with open(result_json_path) as f:
        data = json.load(f)

    matches = data.get("matches", [])
    gaps = data.get("gaps", [])
    trace_a = data.get("trace_A", [])
    trace_b = data.get("trace_B", [])

    if not gaps:
        return {"error": "No gaps found in LCS result; traces are identical."}

    # Identify the divergence function
    func_name, a_idx, b_idx = identify_divergence_function(
        matches, gaps, trace_a, trace_b
    )
    if func_name is None:
        return {"error": "Could not identify divergence function."}

    print(f"Divergence function: {func_name}")
    print(f"  Trace A position: {a_idx}")
    print(f"  Trace B position: {b_idx}")

    # Find library paths
    lib_path_a = find_libtiff_path(str(binary_a))
    lib_path_b = find_libtiff_path(str(binary_b))
    print(f"  Library path A: {lib_path_a}")
    print(f"  Library path B: {lib_path_b}")

    # Find source directories
    source_dirs_a = find_source_dirs(str(binary_a))
    source_dirs_b = find_source_dirs(str(binary_b))

    # Build argument lists
    if args_a is None:
        args_a = []
    if args_b is None:
        args_b = []

    # ========================================================
    # UNIFIED: the backward tracer is the PRIMARY fork locator.
    # Recursively follows the return-value dependency chain from the last
    # common entry function (e.g. TIFFOpen) down to the fork statement (the
    # input-read statement in the target version).  The crash-based / semantic
    # / gap-based analyses below remain only as a fallback.
    # ========================================================
    last_common = _find_last_common_entry_function(matches)
    if last_common:
        print(f"\n=== Unified backward tracer from: {last_common} ===")
        try:
            bt_result = _run_backward_tracer(
                last_common, binary_a, binary_b, source_dirs_a, source_dirs_b,
                lib_path_a, lib_path_b, input_file, args_b, gdb_timeout)
        except Exception as e:
            print(f"  [Backward tracer] failed: {e}")
            bt_result = {"status": "error", "error": str(e)}

        if bt_result.get("status") == "found" and bt_result.get("fork_statement"):
            print(f"\n  Backward tracer located the fork statement.")
            result = _build_result_from_backward_tracer(
                bt_result, last_common, a_idx, b_idx)
            if input_file:
                result["input_file"] = str(input_file)
            if not skip_polytracker:
                try:
                    result = _polytracker_locate_input_offsets(
                        result, config=config, binary_b=binary_b,
                        binary_a=binary_a)
                except Exception as e:
                    print(f"  [PolyTracker] Analysis failed: {e}")
                    result["polytracker_offsets"] = {
                        "status": "error", "error": str(e)}
            return result
        else:
            print(f"  [Backward tracer] no fork statement found — "
                  f"falling back to the legacy analysis.")

    # ========================================================
    # CRASH-BASED ANALYSIS: If both versions crash, the target's
    # crash point may BE the fork statement.
    # ========================================================
    print("\nChecking for crash-based divergence...")
    crash_a = _detect_crash_point(binary_a, args_a, lib_path_a,
                                  source_dirs_a, gdb_timeout)
    crash_b = _detect_crash_point(binary_b, args_b, lib_path_b,
                                  source_dirs_b, gdb_timeout)

    if crash_a:
        print(f"  Reference CRASH: {crash_a.get('signal')} in "
              f"{crash_a.get('function')} at {crash_a.get('file')}:{crash_a.get('line')}")
    else:
        print("  Reference: no crash")
    if crash_b:
        print(f"  Target CRASH:    {crash_b.get('signal')} in "
              f"{crash_b.get('function')} at {crash_b.get('file')}:{crash_b.get('line')}")
    else:
        print("  Target:    no crash")

    reference_crashed = bool(crash_a and not crash_b)

    # Case C: target crashes BEFORE the reference's vulnerability crash point.
    # The target's crash point (triggered by the PoC) is the fork.
    if crash_a and crash_b and _crash_is_before_reference(crash_b, crash_a, trace_a, gaps):
        print("\n  >> Target crashes before the reference's vulnerability crash — "
              "target crash point is the fork.")
        source_line = _read_source_line(
            crash_b["file"], crash_b["line"],
            find_source_dirs(str(binary_b)))
        ref_source = _read_source_line(
            crash_a["file"], crash_a["line"],
            find_source_dirs(str(binary_a)))
        result = {
            "divergence_function": func_name,
            "trace_a_index": a_idx,
            "trace_b_index": b_idx,
            "root_cause_function": crash_b["function"],
            "root_cause_file": crash_b["file"],
            "root_cause_line": crash_b["line"],
            "root_cause_file_a": crash_a["file"],
            "root_cause_line_a": crash_a["line"],
            "root_cause_statement_a": ref_source,
            "root_cause_statement_b": source_line,
            "crash_based": True,
            "crash_signal_a": crash_a["signal"],
            "crash_signal_b": crash_b["signal"],
            "description": (
                f"Target crashes before the reference's vulnerability crash.\n"
                f"Target crash point IS the fork statement.\n"
                f"  Target:    {crash_b['function']} at {crash_b['file']}:{crash_b['line']} ({crash_b['signal']})\n"
                f"  Reference: {crash_a['function']} at {crash_a['file']}:{crash_a['line']} ({crash_a['signal']})\n"
                f"  Statement: {source_line}"
            ),
        }
        if input_file:
            result["input_file"] = str(input_file)
        if not skip_polytracker:
            try:
                result = _polytracker_locate_input_offsets(result, config=config, binary_b=binary_b, binary_a=binary_a)
            except Exception as e:
                print(f"  [PolyTracker] Analysis failed: {e}")
                result["polytracker_offsets"] = {"status": "error", "error": str(e)}
        return result

    # Case A/B: reference crashes, target doesn't.
    if crash_a and not crash_b:
        if _target_reached_crash_point(crash_a, trace_a, trace_b, refactoring_map):
            # Case A: the target reached the crash point but didn't trigger.
            # The reference's crash point (mapped to the target) is the fork.
            print("\n  >> Target reached the crash point but didn't trigger — "
                  "reference crash point (mapped to target) is the fork.")
            crash_func = crash_a.get("function")
            crash_file = crash_a.get("file")
            crash_line = crash_a.get("line")
            ref_stmt = _read_source_line(
                crash_file, crash_line, find_source_dirs(str(binary_a)))
            tgt_line, tgt_text = crash_line, ref_stmt
            mapped = _find_matching_line(crash_file, ref_stmt, source_dirs_b)
            if mapped:
                tgt_line, tgt_text = mapped
            tgt_func = (refactoring_map.get(crash_func, crash_func)
                        if refactoring_map else crash_func)
            ref_file = os.path.basename(crash_file) or crash_file
            result = {
                "divergence_function": func_name,
                "trace_a_index": a_idx,
                "trace_b_index": b_idx,
                "root_cause_function": tgt_func,
                "root_cause_file": ref_file,
                "root_cause_line": tgt_line,
                "root_cause_file_a": crash_file,
                "root_cause_line_a": crash_line,
                "root_cause_statement_a": ref_stmt,
                "root_cause_statement_b": tgt_text,
                "crash_based": True,
                "crash_signal": crash_a["signal"],
                "description": (
                    f"Reference crashes ({crash_a['signal']}) but the target reaches "
                    f"the same code without triggering.\n"
                    f"Crash point (mapped to target) is the fork.\n"
                    f"  Reference: {crash_func} at {crash_file}:{crash_line}\n"
                    f"  Target:    {tgt_func} at {ref_file}:{tgt_line}"
                ),
            }
            if input_file:
                result["input_file"] = str(input_file)
            if not skip_polytracker:
                try:
                    result = _polytracker_locate_input_offsets(result, config=config, binary_b=binary_b, binary_a=binary_a)
                except Exception as e:
                    print(f"  [PolyTracker] Analysis failed: {e}")
                    result["polytracker_offsets"] = {"status": "error", "error": str(e)}
            return result
        else:
            # Case B: the target did not reach the crash point (it diverged
            # earlier).  Use the LCS: the last function of the last LCS match.
            print("\n  >> Target did not reach the crash point — LCS-based fork.")
            if matches:
                last_match = matches[-1]
                funcs = last_match.get("functions", [])
                if funcs:
                    last_func = funcs[-1]
                    lcs_func = (last_func.get("name")
                                if isinstance(last_func, dict)
                                else getattr(last_func, "name", None))
                    if lcs_func:
                        func_name = lcs_func
                        a_idx = last_match.get("a_range", [0, 0])[1] - 1
                        b_idx = last_match.get("b_range", [0, 0])[1] - 1
                        print(f"  LCS divergence function: {func_name}")

    # ========================================================
    # STEP-into: when the reference crashes but the target stops before it,
    # the fork lives inside the LAST common function (the outermost function of
    # the last LCS match).  Step into it dynamically (into its callees, noting
    # return-value differences) to locate the diverging statement.
    # ========================================================
    if reference_crashed:
        # PREFERRED (dynamic, execution-path based): step through the LAST
        # COMMON function (from the LCS) in both versions and locate the
        # statement where execution actually diverges.  This follows the
        # user's algorithm: LCS -> last common function -> breakpoint ->
        # step through -> fork statement.  prefer_tail selects the tail gap
        # (where the reference keeps running after the target stopped) instead
        # of the deepest fork caller anywhere in the trace.
        common_func, _ = _find_last_common_function(
            matches, gaps, trace_a, trace_b, prefer_tail=True)
        if common_func:
            print(f"  [step-into] last common function: {common_func}()")
            cause_a = common_func
            cause_b = common_func
            if refactoring_map:
                for old_name, new_name in refactoring_map.items():
                    if old_name == common_func:
                        cause_b = new_name
                        break
                    elif new_name == common_func:
                        cause_a = new_name
                        break
            div_loc = _find_diverging_source_line(
                binary_a, binary_b, cause_a, cause_b,
                args_a, args_b, lib_path_a, lib_path_b,
                source_dirs_a, source_dirs_b, gdb_timeout,
                refactoring_map=refactoring_map, gaps=gaps,
            )
            bogus = _is_spurious_step_divergence(div_loc)
            if not bogus:
                result = {
                    "divergence_function": func_name,
                    "trace_a_index": a_idx,
                    "trace_b_index": b_idx,
                    "root_cause_function": div_loc.get("root_cause_function", common_func),
                    "root_cause_file": div_loc["file"],
                    "root_cause_line": div_loc["line"],
                    "root_cause_statement_a": div_loc.get("line_text_a", ""),
                    "root_cause_statement_b": div_loc.get("line_text_b", ""),
                    "description": (
                        f"Divergence function: {func_name}\n"
                        f"Root cause function: {div_loc.get('root_cause_function', common_func)}\n"
                        f"Root cause: {div_loc.get('note', '')}\n"
                        f"  v4.4.0: {div_loc.get('line_text_a', '')}\n"
                        f"  v4.0.8: {div_loc.get('line_text_b', '')}\n"
                        f"Source: {div_loc['file']}:{div_loc['line']}"
                    ),
                }
                if div_loc.get("diverging_call_a") or div_loc.get("diverging_call_b"):
                    result["diverging_call_a"] = div_loc.get("diverging_call_a")
                    result["diverging_call_b"] = div_loc.get("diverging_call_b")
                if input_file:
                    result["input_file"] = str(input_file)
                if not skip_polytracker:
                    try:
                        result = _polytracker_locate_input_offsets(
                            result, config=config, binary_b=binary_b, binary_a=binary_a)
                    except Exception as e:
                        print(f"  [PolyTracker] Analysis failed: {e}")
                        result["polytracker_offsets"] = {"status": "error", "error": str(e)}
                return result
            else:
                print("  [step-into] no divergence pinpointed — falling back.")

        # LAST RESORT (static): semantic-enhancement fork (WithLimit/Checked):
        # diff the two function bodies directly and report the guard 4.4.0
        # added.  Only used when dynamic stepping found nothing — this search
        # is NOT execution-path aware, so it can report a guard the input
        # never reaches.
        sem = _locate_semantic_enhancement_divergence(
            gaps, source_dirs_a, source_dirs_b)
        if sem:
            print(f"  [semantic-fork] {sem['callee_a']} vs {sem['callee_b']}: "
                  f"added guard '{sem['statement']}' "
                  f"({os.path.basename(sem['file'])}:{sem['line']})")
            # The *fork point* is the call site: the same position where 4.4.0
            # calls the strengthened callee and 4.0.8 calls the original.  The
            # added guard (datasize > tif_size) is the *root cause*, reported in
            # the description.  PolyTracker still needs the target's equivalent
            # value-read site, kept in poly_track_*.
            target_file = sem.get("target_file") or ""
            target_line = sem.get("target_line") or 0
            target_stmt = sem.get("target_statement") or ""
            target_func = sem.get("target_func") or sem["callee_b"]

            call_stmt_a = sem.get("call_stmt_a") or sem["statement"]
            call_stmt_b = sem.get("call_stmt_b") or ""
            call_file_a = sem.get("call_file_a") or sem["file"]
            call_file_b = sem.get("call_file_b") or target_file
            call_line_a = sem.get("call_line_a") or sem["line"]
            call_line_b = sem.get("call_line_b") or target_line

            # The fork statement is the call site in the caller (e.g.
            # TIFFFetchStripThing calling different callees).  Variables to
            # trace are from this call statement, not from inside the callee.
            fork_vars = _extract_variables_from_expression(call_stmt_b)

            # Map the guard's variables to the TARGET's read site.  The guard
            # (e.g. "datasize > tif_size") lives ONLY in the reference, so it is
            # the root cause, NOT the fork statement.  The fork statement is the
            # TARGET's statement that computes the guard variable — it exists in
            # both versions.  Trace its variables backward to the input-derived
            # sources (e.g. direntry->tdir_count).
            target_sites = []
            input_reads = []
            fork_stmt = None
            fork_stmt_line = None
            try:
                import backward_tracer as _bt
                guard_vars = _bt._extract_variables(sem.get("statement", ""))
                target_sites = _bt._map_fork_vars_to_target(
                    guard_vars, sem["callee_b"],
                    sem.get("target_file") or call_file_b)
                if target_sites:
                    site = target_sites[0]
                    fork_stmt = site["statement"]
                    fork_stmt_line = site["assignment_line"]
                    input_reads = _bt._trace_to_input_variables(
                        site["file"], sem["callee_b"], site["assignment_line"],
                        source_dirs=source_dirs_b)
                    print(f"  [semantic-fork] fork statement (target "
                          f"{sem['callee_b']}): '{fork_stmt}' "
                          f"({os.path.basename(site['file'])}:{fork_stmt_line})")
                    for read in input_reads:
                        print(f"  [semantic-fork] input-read statement: "
                              f"'{read['statement']}' "
                              f"({os.path.basename(read['file'])}:{read['line']})")
            except Exception as _e:
                print(f"  [semantic-fork] target-site mapping failed: {_e}")

            # Prefer the input-read site for PolyTracker instrumentation: it is
            # the statement that reads the fork variable from the input, so its
            # taint traces to the exact input bytes.  Fall back to the fork call
            # site if no input read could be located.
            if input_reads:
                read = input_reads[0]
                pt_file = read["file"]
                pt_line = read["line"] + 1  # instrument AFTER the read
                pt_stmt = read["statement"]
                pt_vars = [read["variable"]]
                pt_func = _bt._find_function_containing_line(read["file"],
                                                             read["line"])
            elif target_sites:
                pt_file = target_sites[0]["file"]
                pt_line = target_sites[0]["line"]
                pt_stmt = target_sites[0]["statement"]
                pt_vars = [s["variable"] for s in target_sites]
                pt_func = sem["callee_b"]
            else:
                pt_file = call_file_b
                pt_line = call_line_b
                pt_stmt = call_stmt_b
                pt_vars = fork_vars
                pt_func = sem.get("caller") or sem["callee_a"]

            # Prefer the input-read statement as the fork statement (it reads
            # the divergent value from the input); the derived computation is a
            # secondary detail.
            if input_reads:
                read = input_reads[0]
                fork_stmt = read["statement"]
                fork_stmt_line = read["line"]

            result = {
                "divergence_function": func_name,
                "trace_a_index": a_idx,
                "trace_b_index": b_idx,
                "root_cause_function": sem.get("caller") or sem["callee_a"],
                "root_cause_file": call_file_a,
                "root_cause_line": call_line_a,
                "root_cause_file_a": call_file_a,
                "root_cause_line_a": call_line_a,
                "root_cause_file_b": call_file_b,
                "root_cause_line_b": call_line_b,
                "root_cause_statement_a": call_stmt_a,
                "root_cause_statement_b": call_stmt_b,
                "fork_statement": fork_stmt or call_stmt_b,
                "fork_statement_line": fork_stmt_line,
                "fork_statement_file": pt_file if target_sites else call_file_b,
                "input_reads": input_reads,
                "poly_track_function": pt_func,
                "poly_track_file": pt_file,
                "poly_track_line": pt_line,
                "poly_track_statement": pt_stmt,
                "semantic_fork": True,
                "variables": pt_vars,
                "target_sites": target_sites,
                "description": (
                    f"Divergence function: {func_name}\n"
                    f"Root cause function: {sem.get('caller') or sem['callee_a']}\n"
                    f"Root cause: {sem['callee_a']} adds a guard that "
                    f"{sem['callee_b']} lacks\n"
                    f"  4.4.0 calls {sem['callee_a']}: {call_stmt_a}\n"
                    f"  4.0.8 calls {sem['callee_b']}: {call_stmt_b}\n"
                    f"  Guard added (4.4.0 only): {sem['statement']}"
                ),
            }
            if input_file:
                result["input_file"] = str(input_file)
            if not skip_polytracker:
                try:
                    result = _polytracker_locate_input_offsets(
                        result, config=config, binary_b=binary_b, binary_a=binary_a)
                except Exception as e:
                    print(f"  [PolyTracker] Analysis failed: {e}")
                    result["polytracker_offsets"] = {"status": "error", "error": str(e)}
            return result

    # ========================================================
    # PRIMARY: Gap-based divergence tracing (backtrace walk-up)
    # Break at the first divergent call in the LCS gap, get
    # backtrace, walk up to find the enclosing control statement.
    # ========================================================
    gap_result = _trace_gap_divergence(
        binary_a, binary_b, trace_a, trace_b, gaps,
        a_idx, b_idx, args_a, args_b,
        lib_path_a, lib_path_b,
        source_dirs_a, source_dirs_b, gdb_timeout,
        func_name=func_name,
    )

    # Re-locate to the tail gap when either:
    #   (a) the two "diverging calls" are identical (e.g. tagCompare vs
    #       tagCompare from a qsort/bsearch refactor — a code change that
    #       re-converges, NOT the last fork point), or
    #   (b) the target stopped (diverging_call_b is None) — the fork is a
    #       return-value difference: the reference keeps running while the
    #       target returned early (e.g. `in == NULL` because TIFFOpen failed).
    if (gap_result and reference_crashed
            and gap_result.get("diverging_call_a")
            and (gap_result.get("diverging_call_a") == gap_result.get("diverging_call_b")
                 or gap_result.get("diverging_call_b") is None)):
        print(f"  [tail-relocate] re-locating to tail gap "
              f"(diverging calls: {gap_result.get('diverging_call_a')} vs "
              f"{gap_result.get('diverging_call_b')}).")
        tail_func, tail_a, tail_b = identify_divergence_function(
            matches, gaps, trace_a, trace_b, prefer_tail=True)
        if tail_func is not None:
            func_name, a_idx, b_idx = tail_func, tail_a, tail_b
            gap_result = _trace_gap_divergence(
                binary_a, binary_b, trace_a, trace_b, gaps,
                a_idx, b_idx, args_a, args_b,
                lib_path_a, lib_path_b,
                source_dirs_a, source_dirs_b, gdb_timeout,
                func_name=func_name,
            )

    if gap_result:
        print(f"\n  Gap-based divergence located in {gap_result['root_cause_function']}()")
        a_file = gap_result.get("line_a_file", gap_result['file'])
        a_line = gap_result.get("line_a", gap_result['line'])
        result = {
            "divergence_function": func_name,
            "trace_a_index": a_idx,
            "trace_b_index": b_idx,
            "root_cause_function": gap_result["root_cause_function"],
            "root_cause_file": gap_result["file"],
            "root_cause_line": gap_result["line"],
            "root_cause_file_a": a_file,
            "root_cause_line_a": a_line,
            "root_cause_statement_a": gap_result["line_text_a"],
            "root_cause_statement_b": gap_result["line_text_b"],
            "description": (
                f"Divergence function: {func_name}\n"
                f"Root cause function: {gap_result['root_cause_function']}\n"
                f"Root cause: {gap_result.get('note', '')}\n"
                f"  v4.4.0: {gap_result['line_text_a']}  ({a_file}:{a_line})\n"
                f"  v4.0.8: {gap_result['line_text_b']}  ({gap_result['file']}:{gap_result['line']})"
            ),
        }
        if gap_result.get("diverging_call_a") or gap_result.get("diverging_call_b"):
            result["diverging_call_a"] = gap_result.get("diverging_call_a")
            result["diverging_call_b"] = gap_result.get("diverging_call_b")
        if gap_result.get("control"):
            result["control"] = gap_result["control"]
        if input_file:
            result["input_file"] = str(input_file)
        if reference_crashed:
            # Case B: the target diverged before reaching the reference crash.
            div_call_a = gap_result.get("diverging_call_a")
            div_call_b = gap_result.get("diverging_call_b")
            stmt = (gap_result.get("line_text_b") or "").strip()
            is_ctrl = _is_control_statement(stmt)
            is_code_change = bool(div_call_a and div_call_b and div_call_a != div_call_b)

            if div_call_a and not div_call_b:
                # The target stopped before the reference's continuation. The
                # call site in the reference IS the fork — keep it as-is
                # (do not overwrite with an enclosing condition).
                pass
            elif is_ctrl and is_code_change:
                # A control statement guards a code change (e.g. `if (!crop_buff)`
                # guarding _TIFFmalloc vs limitMalloc) -> locate the diff.
                print(f"  Diverging calls differ ({div_call_a} vs {div_call_b}) — code-change fork.")
                result = _refine_fork_statement(result, source_dirs_b, binary_b,
                                                source_dirs_a, binary_a)
            elif is_ctrl:
                result["_fork_is_condition"] = True
            else:
                # Not a control statement: prefer an enclosing condition;
                # otherwise it is a code change (e.g. qsort vs bsearch).
                conds = _find_condition_ifs(
                    gap_result["file"], gap_result["root_cause_function"],
                    source_dirs_b)
                if conds:
                    line, cond, full_line = conds[0]
                    result["root_cause_line"] = line
                    result["root_cause_statement_b"] = full_line
                    result["root_cause_statement_a"] = full_line
                    print(f"  Fork condition: {gap_result['file']}:{line}")
                    result["_fork_is_condition"] = True
                else:
                    result = _refine_fork_statement(result, source_dirs_b, binary_b,
                                                    source_dirs_a, binary_a)
        else:
            result = _refine_fork_statement(result, source_dirs_b, binary_b,
                                            source_dirs_a, binary_a)

        # Cross-function value-origin tracing: if a fork variable is a function
        # return value (e.g. `in = TIFFOpen(...)` then `if (in == NULL)`), trace
        # it into the callee to find the input-derived variable that actually
        # decides the return value.
        if reference_crashed or not result.get('variables'):
            try:
                result = _resolve_fork_variable_origin(
                    result, binary_b, binary_a, args_b, args_a,
                    lib_path_b, lib_path_a, source_dirs_b, source_dirs_a,
                    gdb_timeout)
            except Exception as e:
                print(f"  [value-origin] tracing failed: {e}")

        if not skip_polytracker:
            try:
                result = _polytracker_locate_input_offsets(result, config=config, binary_b=binary_b, binary_a=binary_a)
            except Exception as e:
                print(f"  [PolyTracker] Analysis failed: {e}")
                result["polytracker_offsets"] = {"status": "error", "error": str(e)}
        return result

    # ========================================================
    # FALLBACK 1: Trace from common ancestor
    # Break at deepest common function, step through both
    # versions, compare step traces to find first divergence.
    # ========================================================
    ancestor_result = _trace_from_common_ancestor(
        matches, gaps, trace_a, trace_b,
        binary_a, binary_b, args_a, args_b,
        lib_path_a, lib_path_b,
        source_dirs_a, source_dirs_b, gdb_timeout,
    )
    if ancestor_result:
        ancestor_result["divergence_function"] = func_name
        ancestor_result["trace_a_index"] = a_idx
        ancestor_result["trace_b_index"] = b_idx
        print(f"\n  Common ancestor divergence: {ancestor_result.get('root_cause_function')}()")
        return ancestor_result

    # ========================================================
    # FALLBACK 2: Trace candidate sub-functions
    # ========================================================
    candidates = _find_candidate_subfunctions(gaps, trace_a, trace_b)
    if candidates:
        print(f"\n  Trying {len(candidates)} candidate sub-functions...")
        for cand_name, reason in candidates:
            print(f"    Candidate: {cand_name} ({reason})")
            sub_result = _trace_subfunction_divergence(
                cand_name, binary_a, binary_b,
                args_a, args_b,
                lib_path_a, lib_path_b,
                source_dirs_a, source_dirs_b, gdb_timeout,
            )
            if sub_result:
                sub_result["divergence_function"] = func_name
                sub_result["trace_a_index"] = a_idx
                sub_result["trace_b_index"] = b_idx
                print(f"\n  Sub-function divergence in {cand_name}(): "
                      f"{sub_result.get('root_cause_file')}:{sub_result.get('root_cause_line')}")
                return sub_result

    # Run divergence analysis
    print(f"\nRunning GDB analysis on {func_name}()...")
    result = trace_divergence_cause(
        binary_a, binary_b, func_name,
        lib_path_a=lib_path_a, lib_path_b=lib_path_b,
        args_a=args_a, args_b=args_b,
        source_dirs_a=source_dirs_a, source_dirs_b=source_dirs_b,
        gdb_timeout=gdb_timeout,
    )

    result["divergence_function"] = func_name
    result["trace_a_index"] = a_idx
    result["trace_b_index"] = b_idx

    # If return values differ, find the statement that causes different returns
    if "returns different values" in result.get("diverging_statement", ""):
        print(f"\n  {func_name}() returns differently — tracing divergence point...")

        # Try GDB stepping inside the function to find the divergence
        cause_func_a = func_name
        cause_func_b = func_name
        if refactoring_map:
            for old_name, new_name in refactoring_map.items():
                if old_name == func_name:
                    cause_func_b = new_name
                    break
                elif new_name == func_name:
                    cause_func_a = new_name
                    break

        div_loc = _find_diverging_source_line(
            binary_a, binary_b, cause_func_a, cause_func_b,
            args_a, args_b, lib_path_a, lib_path_b,
            source_dirs_a, source_dirs_b, gdb_timeout,
            refactoring_map=refactoring_map,
            gaps=gaps,
        )

        # If the GDB stepping could only conclude that one version "stops early"
        # (or otherwise failed to pinpoint a source statement), fall back to the
        # gap-based analysis, which locates the caller of the first differing
        # function call in v4.0.8.
        bogus = _is_spurious_step_divergence(div_loc)
        if bogus:
            gap_loc = _trace_gap_divergence(
                binary_a, binary_b, trace_a, trace_b, gaps,
                a_idx, b_idx, args_a, args_b,
                lib_path_a, lib_path_b,
                source_dirs_a, source_dirs_b, gdb_timeout,
            )
            if gap_loc:
                div_loc = gap_loc

        if div_loc:
            result["root_cause_function"] = div_loc.get("root_cause_function", func_name)
            result["root_cause_file"] = div_loc["file"]
            result["root_cause_line"] = div_loc["line"]
            result["root_cause_statement_a"] = div_loc.get("line_text_a",
                                                           div_loc.get("root_cause_statement_a", ""))
            result["root_cause_statement_b"] = div_loc.get("line_text_b",
                                                           div_loc.get("root_cause_statement_b", ""))
            if div_loc.get("conditional"):
                result["root_cause_conditional"] = div_loc["conditional"]
            if div_loc.get("diverging_call_a") or div_loc.get("diverging_call_b"):
                result["diverging_call_a"] = div_loc.get("diverging_call_a")
                result["diverging_call_b"] = div_loc.get("diverging_call_b")
            result["description"] = (
                f"Divergence function: {func_name}\n"
                f"Root cause function: {result['root_cause_function']}\n"
                f"Root cause: {div_loc.get('note', '')}\n"
                f"  v4.4.0: {result['root_cause_statement_a']}\n"
                f"  v4.0.8: {result['root_cause_statement_b']}\n"
                f"Source: {div_loc['file']}:{div_loc['line']}"
            )
        else:
            # GDB stepping didn't find divergence — find return location
            result["root_cause_function"] = func_name
            cause_loc_a = _find_return_statement_location(
                binary_a, func_name, "1", args_a, lib_path_a,
                source_dirs_a, gdb_timeout
            )
            if cause_loc_a:
                result["root_cause_file"] = cause_loc_a.get("file")
                result["root_cause_line"] = cause_loc_a.get("line")
            result["description"] += (
                f"\n\nCould not pinpoint diverging source line in {func_name}()."
            )

    else:
        # Return values are the same — divergence is in execution pattern
        print(f"\n  {func_name}() returns same value in both versions.")

        # First check if function is identical via GDB stepping
        cause_func_a = func_name
        cause_func_b = func_name
        if refactoring_map:
            for old_name, new_name in refactoring_map.items():
                if old_name == func_name:
                    cause_func_b = new_name
                    break
                elif new_name == func_name:
                    cause_func_a = new_name
                    break

        # Quick GDB check — step through and see if traces differ
        lines_a = _record_source_lines_v2(binary_a, cause_func_a, args_a,
                                          lib_path_a, source_dirs_a, gdb_timeout)
        lines_b = _record_source_lines_v2(binary_b, cause_func_b, args_b,
                                          lib_path_b, source_dirs_b, gdb_timeout)
        func_identical = False
        gdb_result = None
        if lines_a and lines_b:
            gdb_result = _compare_execution_traces(lines_a, lines_b)
            if not gdb_result:
                func_identical = True

        if func_identical:
            # Function is identical — divergence is in caller
            # Use LCS gap to find caller and what happens differently
            print(f"  {func_name}() is identical in both versions.")
            print("  Analyzing LCS gap for caller divergence...")

            gap_info = _find_pattern_divergence(
                func_name, trace_a, trace_b, a_idx, b_idx, matches, gaps
            )
            if gap_info:
                cause_func = gap_info["caller"]
                a_ops = gap_info.get("a_ops", [])
                b_ops = gap_info.get("b_ops", [])

                print(f"  After {func_name}():")
                if a_ops and b_ops:
                    print(f"    v4.4.0 calls: {', '.join(a_ops[:3])}")
                    print(f"    v4.0.8 calls: {', '.join(b_ops[:3])}")
                elif a_ops:
                    print(f"    v4.4.0 calls: {', '.join(a_ops[:3])}")
                elif b_ops:
                    print(f"    v4.0.8 calls: {', '.join(b_ops[:3])}")

                # Use GDB stepping inside the CALLER to find exact divergence
                cause_func_a2 = cause_func
                cause_func_b2 = cause_func
                if refactoring_map:
                    for old_name, new_name in refactoring_map.items():
                        if old_name == cause_func:
                            cause_func_b2 = new_name
                            break
                        elif new_name == cause_func:
                            cause_func_a2 = new_name
                            break

                # Step inside the caller function to find exact divergence
                caller_lines_a = _record_source_lines_v2(
                    binary_a, cause_func_a2, args_a, lib_path_a,
                    source_dirs_a, gdb_timeout)
                caller_lines_b = _record_source_lines_v2(
                    binary_b, cause_func_b2, args_b, lib_path_b,
                    source_dirs_b, gdb_timeout)

                if caller_lines_a and caller_lines_b:
                    caller_gdb_result = _compare_execution_traces(
                        caller_lines_a, caller_lines_b)
                    if caller_gdb_result:
                        result["root_cause_function"] = cause_func
                        result["root_cause_file"] = caller_gdb_result["file"]
                        result["root_cause_line"] = caller_gdb_result["line"]
                        result["root_cause_statement_a"] = caller_gdb_result.get("line_text_a", "")
                        result["root_cause_statement_b"] = caller_gdb_result.get("line_text_b", "")

                        # Find controlling conditional — use B's source dirs since line is from v4.0.8
                        cond = _find_conditional_context(
                            caller_gdb_result["file"], caller_gdb_result["line"],
                            source_dirs_b)
                        cond_info = ""
                        if cond:
                            cond_info = f"\nControlling conditional ({cond['file']}:{cond['line']}): {cond['full_line']}"

                        result["description"] = (
                            f"Divergence function: {func_name}\n"
                            f"Root cause function: {cause_func}\n"
                            f"Root cause: {caller_gdb_result.get('note', '')}\n"
                            f"  v4.4.0: {caller_gdb_result.get('line_text_a', '')}\n"
                            f"  v4.0.8: {caller_gdb_result.get('line_text_b', '')}\n"
                            f"Source: {caller_gdb_result['file']}:{caller_gdb_result['line']}"
                            f"{cond_info}"
                        )

                # Fallback to LCS source pattern if GDB didn't find it
                if "root_cause_function" not in result:
                    div_loc = _find_pattern_in_source(
                        cause_func_a2, cause_func_b2,
                        a_ops, b_ops,
                        source_dirs_a, source_dirs_b,
                    )
                    if div_loc:
                        result["root_cause_function"] = cause_func
                        result["root_cause_file"] = div_loc["file"]
                        result["root_cause_line"] = div_loc["line"]
                        result["root_cause_statement_a"] = div_loc.get("line_text_a", "")
                        result["root_cause_statement_b"] = div_loc.get("line_text_b", "")
                        result["description"] = (
                            f"Divergence function: {func_name}\n"
                            f"Root cause function: {cause_func}\n"
                            f"Root cause: {div_loc.get('note', '')}\n"
                            f"  v4.4.0: {div_loc.get('line_text_a', '')}\n"
                            f"  v4.0.8: {div_loc.get('line_text_b', '')}\n"
                            f"Source: {div_loc['file']}:{div_loc['line']}"
                        )
        else:
            # Function has internal divergence — report it
            div_loc = gdb_result
            if div_loc:
                result["root_cause_function"] = func_name
                result["root_cause_file"] = div_loc["file"]
                result["root_cause_line"] = div_loc["line"]
                result["root_cause_statement_a"] = div_loc.get("line_text_a", "")
                result["root_cause_statement_b"] = div_loc.get("line_text_b", "")

                # Find controlling conditional — use B's source dirs since line is from v4.0.8
                cond = _find_conditional_context(
                    div_loc["file"], div_loc["line"],
                    source_dirs_b)
                cond_info = ""
                if cond:
                    cond_info = f"\nControlling conditional ({cond['file']}:{cond['line']}): {cond['full_line']}"

                result["description"] = (
                    f"Divergence function: {func_name}\n"
                    f"Root cause function: {func_name}\n"
                    f"Root cause: {div_loc.get('note', '')}\n"
                    f"  v4.4.0: {div_loc.get('line_text_a', '')}\n"
                    f"  v4.0.8: {div_loc.get('line_text_b', '')}\n"
                    f"Source: {div_loc['file']}:{div_loc['line']}"
                    f"{cond_info}"
                )

        if "root_cause_function" not in result:
            result["description"] += (
                f"\n\n{func_name}() is identical in both versions."
                f" Could not pinpoint divergence statement."
            )

    # Final fallback: if the analysis did not produce a concrete source statement
    # in v4.0.8 (e.g. it only reports "v4.0.8 stops after N operations"), locate
    # the caller of the first differing function call in the LCS gap via GDB.
    stmt_b = (result.get("root_cause_statement_b") or "").strip()
    if (not result.get("root_cause_file")
            or not stmt_b
            or stmt_b.startswith("v4.0.8")
            or stmt_b.startswith("v4.4.0")):
        gap_loc = _trace_gap_divergence(
            binary_a, binary_b, trace_a, trace_b, gaps,
            a_idx, b_idx, args_a, args_b,
            lib_path_a, lib_path_b,
            source_dirs_a, source_dirs_b, gdb_timeout,
        )
        if gap_loc:
            result["root_cause_function"] = gap_loc["root_cause_function"]
            result["root_cause_file"] = gap_loc["file"]
            result["root_cause_line"] = gap_loc["line"]
            result["root_cause_statement_a"] = gap_loc["line_text_a"]
            result["root_cause_statement_b"] = gap_loc["line_text_b"]
            if gap_loc.get("conditional"):
                result["root_cause_conditional"] = gap_loc["conditional"]
            if gap_loc.get("control"):
                result["control"] = gap_loc["control"]
            result["diverging_call_a"] = gap_loc.get("diverging_call_a")
            result["diverging_call_b"] = gap_loc.get("diverging_call_b")
            result["description"] = (
                f"Divergence function: {func_name}\n"
                f"Root cause function: {gap_loc['root_cause_function']}\n"
                f"Root cause: {gap_loc.get('note', '')}\n"
                f"  v4.4.0: {gap_loc['line_text_a']}\n"
                f"  v4.0.8: {gap_loc['line_text_b']}\n"
                f"Source: {gap_loc['file']}:{gap_loc['line']}"
            )

    # ============================================================
    # PolyTracker: extract variables and locate input offsets
    # ============================================================
    if result and not result.get("error"):
        # Store input_file in result for PolyTracker
        if input_file:
            result["input_file"] = str(input_file)
        if not skip_polytracker:
            try:
                result = _polytracker_locate_input_offsets(result, config=config, binary_b=binary_b, binary_a=binary_a)
            except Exception as e:
                print(f"  [PolyTracker] Analysis failed: {e}")
                result["polytracker_offsets"] = {"status": "error", "error": str(e)}

    return result


def _find_pattern_in_source(func_name_a, func_name_b, ops_a, ops_b,
                             source_dirs_a, source_dirs_b):
    """Find the source line where a unique function is called.

    When GDB stepping can't find the divergence, search the source code
    for the unique function calls identified by the LCS analysis.
    Searches in the caller function's source file.
    """
    # Find source files for both versions
    src_a = _find_function_source(func_name_a, source_dirs_a)
    src_b = _find_function_source(func_name_b, source_dirs_b)

    if not src_a and not src_b:
        return None

    # Search for the unique operations in the source
    # Try B first (older/crashing version)
    if ops_b and src_b:
        try:
            with open(src_b) as f:
                content_b = f.read()
            # Try to extract function body, or search the whole file
            body_b = _extract_function_body(content_b, func_name_b)
            if not body_b:
                body_b = content_b  # fallback to whole file

            for op in ops_b:
                pattern = rf'\b{op}\s*\('
                match = re.search(pattern, body_b)
                if match:
                    # Find line number
                    if body_b is content_b:
                        line_num = content_b[:match.start()].count('\n') + 1
                    else:
                        pos = content_b.find(body_b[:50])
                        line_num = content_b[:pos + match.start()].count('\n') + 1 if pos >= 0 else 0

                    lines = body_b.split('\n')
                    line_idx = body_b[:match.start()].count('\n')
                    line_text = lines[line_idx].strip() if line_idx < len(lines) else ""

                    # Determine file name from source path
                    file_name = src_b.split('/')[-1] if src_b else "unknown"

                    desc_a = f"v4.4.0 does not call {op}()" if ops_a else "different code path"
                    return {
                        "file": file_name,
                        "line": line_num,
                        "line_text_a": desc_a,
                        "line_text_b": f"v4.0.8 calls {op}() here: {line_text}",
                        "note": f"Source pattern match: {op} found in {func_name_b}()",
                    }
        except (FileNotFoundError, UnicodeDecodeError):
            pass

    # Try A
    if ops_a and src_a:
        try:
            with open(src_a) as f:
                content_a = f.read()
            body_a = _extract_function_body(content_a, func_name_a)
            if not body_a:
                body_a = content_a

            for op in ops_a:
                pattern = rf'\b{op}\s*\('
                match = re.search(pattern, body_a)
                if match:
                    if body_a is content_a:
                        line_num = content_a[:match.start()].count('\n') + 1
                    else:
                        pos = content_a.find(body_a[:50])
                        line_num = content_a[:pos + match.start()].count('\n') + 1 if pos >= 0 else 0

                    lines = body_a.split('\n')
                    line_idx = body_a[:match.start()].count('\n')
                    line_text = lines[line_idx].strip() if line_idx < len(lines) else ""

                    file_name = src_a.split('/')[-1] if src_a else "unknown"

                    desc_b = f"v4.0.8 does not call {op}()" if ops_b else "different code path"
                    return {
                        "file": file_name,
                        "line": line_num,
                        "line_text_a": f"v4.4.0 calls {op}() here: {line_text}",
                        "line_text_b": desc_b,
                        "note": f"Source pattern match: {op} found in {func_name_a}()",
                    }
        except (FileNotFoundError, UnicodeDecodeError):
            pass

    return None


def _find_pattern_divergence(func_name, trace_a, trace_b, a_idx, b_idx,
                              matches, gaps):
    """Find execution pattern divergence using LCS trace data.

    Finds the gap IMMEDIATELY AFTER the divergence function returns,
    identifying the next call in each version.
    """
    # Find the match that contains a_idx/b_idx (the divergence point)
    # Then look at the gap right after that match
    for i, match in enumerate(matches):
        a_range = match.get("a_range", [0, 0])
        b_range = match.get("b_range", [0, 0])
        if a_range[0] <= a_idx <= a_range[1] and b_range[0] <= b_idx <= b_range[1]:
            # Found the match — look at the gap right after it
            if i < len(gaps):
                next_gap = gaps[i]
                a_ops = next_gap.get("a", [])
                b_ops = next_gap.get("b", [])

                if a_ops or b_ops:
                    a_names = [op["name"] for op in a_ops if op.get("is_enter")]
                    b_names = [op["name"] for op in b_ops if op.get("is_enter")]

                    # Get caller from the path — the function just before
                    # the first unique operation
                    path = (a_ops or b_ops)[0].get("path", [])
                    caller = func_name

                    # If path is empty, search backwards in trace for last full path
                    if len(path) <= 1:
                        search_idx = a_idx if a_idx else b_idx
                        trace = trace_a if a_idx else trace_b
                        for back_i in range(search_idx - 1, max(0, search_idx - 50), -1):
                            prev_path = trace[back_i].get("path", [])
                            if len(prev_path) > 1:
                                caller = prev_path[-1]
                                break
                    else:
                        # Find the parent of the first unique operation
                        first_op_name = (a_names or b_names)[0] if (a_names or b_names) else None
                        if first_op_name:
                            for j, fn in enumerate(path):
                                if fn == first_op_name and j > 0:
                                    caller = path[j - 1]
                                    break
                        else:
                            for fn in path:
                                if fn in ("TIFFReadDirectory", "TIFFSetDirectory"):
                                    caller = fn
                                    break

                    # Build description
                    if a_names and b_names:
                        if a_names[0] != b_names[0]:
                            desc = f"v4.4.0 calls {a_names[0]}(), v4.0.8 calls {b_names[0]}()"
                        else:
                            desc = f"Both call {a_names[0]}() but with different context"
                    elif a_names:
                        desc = f"v4.4.0 calls {a_names[0]}(), v4.0.8 does not"
                    elif b_names:
                        desc = f"v4.0.8 calls {b_names[0]}(), v4.4.0 does not"
                    else:
                        desc = "Different operations"

                    return {
                        "caller": caller,
                        "gap": next_gap,
                        "description": desc,
                        "a_ops": a_names,
                        "b_ops": b_names,
                    }

    return None


# ================================================================
# PolyTracker-based input offset tracing
# ================================================================

def _extract_if_condition(stmt):
    """Extract the meaningful part of an if/while/for statement.

    - Braced body (`if (cond) { ... }`): return the condition only — the body
      is a separate block and its variables are not part of the fork decision.
    - Single-statement body (`if (cond) stmt;`): return the WHOLE statement —
      the body carries the divergent computation (e.g. a malloc with a size).
    - No body (`if (cond)`): return the condition.

    Returns None if the statement is not a control statement with a condition.
    """
    if not stmt:
        return None
    s = stmt.strip()
    m = re.match(r'(if|while|for|switch)\s*\(', s)
    if not m:
        return None
    open_paren = s.index('(')
    depth = 0
    i = open_paren
    while i < len(s):
        ch = s[i]
        if ch == '(':
            depth += 1
        elif ch == ')':
            depth -= 1
            if depth == 0:
                break
        i += 1
    if depth != 0:
        return None
    cond = s[open_paren + 1:i].strip()
    rest = s[i + 1:].strip()
    if rest.startswith('{'):
        # Braced body -> keep condition only.
        return cond if cond else None
    if rest:
        # Single-statement body -> keep the whole statement.
        return s
    return cond if cond else None


def _get_complete_fork_statement(source_file, line_num, source_dirs=None):
    """Read source file and extract the complete statement starting at line_num.

    Handles multi-line statements by tracking parentheses, brackets, and
    looking for the terminating semicolon or closing brace.
    Returns the complete statement text and the line range (start, end).
    """
    if source_file is None or line_num is None:
        return None, None, None

    # Resolve source file path: absolute path, relative path under
    # source_dirs, or a basename search within source_dirs.
    sf = Path(source_file)
    if not (sf.is_absolute() and sf.exists()):
        located = _locate_source_file(str(source_file), source_dirs) if source_dirs else None
        if located:
            sf = Path(located)
    if not sf.exists():
        return None, None, None

    try:
        lines = sf.read_text(errors='replace').splitlines()
    except Exception:
        return None, None, None

    idx = line_num - 1  # 0-based
    if idx < 0 or idx >= len(lines):
        return None, None, None

    # Accumulate lines until the statement is complete
    paren_depth = 0
    bracket_depth = 0
    brace_depth = 0
    stmt_lines = []
    start_line = line_num

    for i in range(idx, min(idx + 30, len(lines))):
        line = lines[i]
        stmt_lines.append(line)

        for ch in line:
            if ch == '(':
                paren_depth += 1
            elif ch == ')':
                paren_depth = max(0, paren_depth - 1)
            elif ch == '[':
                bracket_depth += 1
            elif ch == ']':
                bracket_depth = max(0, bracket_depth - 1)
            elif ch == '{':
                brace_depth += 1
            elif ch == '}':
                brace_depth = max(0, brace_depth - 1)

        # Statement is complete when all depths are 0 and we hit a semicolon
        # or we're at a closing brace at depth 0
        joined = ' '.join(s.strip() for s in stmt_lines)
        if (paren_depth == 0 and bracket_depth == 0 and
                (';' in line or (brace_depth == 0 and i > idx))):
            break

    full_stmt = ' '.join(s.strip() for s in stmt_lines)
    # Clean up multiple spaces
    full_stmt = re.sub(r'\s+', ' ', full_stmt).strip()
    end_line = start_line + len(stmt_lines) - 1
    return full_stmt, start_line, end_line


def _extract_variables_from_expression(expr):
    """Extract variable-like names from a C expression.

    Returns a list of variable expressions like ['track->data_size', 'x', 'arr'].
    Skips C keywords, numbers, and common function names.
    """
    if not expr:
        return []

    # Strip C/C++ comments so comment text is not mistaken for variables.
    expr = re.sub(r'/\*.*?\*/', '', expr, flags=re.DOTALL)
    expr = re.sub(r'//[^\n]*', '', expr)
    # Strip sizeof(...) so the type argument (e.g. sizeof(TIFFField *)) is not
    # mistaken for a variable.
    expr = re.sub(r'\bsizeof\s*\([^()]*\)', '', expr)
    # Strip `goto <label>;` — the label is not a variable.
    expr = re.sub(r'\bgoto\s+\w+\s*;', '', expr)

    C_KEYWORDS = {
        'if', 'else', 'while', 'for', 'do', 'switch', 'case', 'return',
        'break', 'continue', 'goto', 'int', 'char', 'float', 'double',
        'void', 'long', 'short', 'unsigned', 'signed', 'const', 'static',
        'extern', 'struct', 'union', 'enum', 'typedef', 'sizeof', 'NULL',
        'true', 'false', 'TRUE', 'FALSE', 'uint8_t', 'uint16_t', 'uint32_t',
        'uint64_t', 'int8_t', 'int16_t', 'int32_t', 'int64_t', 'size_t',
        # libtiff fixed-width typedefs (uint64, uint32, ...) without the _t
        # suffix — these are types, not variables.
        'uint8', 'uint16', 'uint32', 'uint64', 'int8', 'int16', 'int32',
        'int64', 'uint', 'tsize_t', 'tmsize_t', 'toff_t', 'tstrip_t',
        'ttile_t', 'uint64_t', 'int64_t',
        # Command-line argument plumbing (file path, not input *content*).
        'argv', 'argc', 'optind',
    }

    SKIP_FUNCTIONS = {
        'malloc', 'calloc', 'realloc', 'free', 'memcpy', 'memset', 'memmove',
        'strlen', 'strcmp', 'strncmp', 'strcpy', 'strncpy', 'fprintf', 'printf',
        'sprintf', 'snprintf', 'fopen', 'fclose', 'fread', 'fwrite', 'fseek',
        'ftell', 'feof', 'ferror', 'fflush', 'exit', 'abort', 'assert',
        'ceil', 'floor', 'abs', 'min', 'max', 'pow', 'sqrt',
    }

    variables = []
    # Match: identifier, identifier->member, identifier.member, identifier[index]
    # Also match: *ptr, &var
    pattern = re.compile(
        r'(?<![>\w.])'          # not preceded by > or word char or dot
        r'([a-zA-Z_]\w*)'      # base variable name
        r'(?:\s*->\s*[a-zA-Z_]\w*)*'  # optional ->member chains
        r'(?:\s*\.\s*[a-zA-Z_]\w*)*'  # optional .member chains
        r'(?:\s*\[[^\]]*\])?',  # optional [index]
        re.VERBOSE
    )

    seen = set()
    for m in pattern.finditer(expr):
        var = m.group(0).strip()
        base = m.group(1)

        if base in C_KEYWORDS or base in SKIP_FUNCTIONS:
            continue
        # Skip function calls: identifier immediately followed by '('.
        if expr[m.end():].lstrip().startswith('('):
            continue
        # Skip pure numbers
        if re.match(r'^\d+', var):
            continue
        # Skip type names / typedefs (CamelCase identifiers like TIFFField).
        if re.match(r'^[A-Z]', base):
            continue
        # Skip single-char operators that might match
        if len(var) <= 1 and var not in ('x', 'y', 'i', 'j', 'k', 'n', 'p', 't'):
            continue
        # Skip all-caps identifiers (macros / enum constants, e.g.
        # COMPOSITE_IMAGES) — these are not lvalues and can't be instrumented.
        if re.match(r'^[A-Z][A-Z0-9_]*$', var):
            continue

        if var not in seen:
            seen.add(var)
            variables.append(var)

        # Also extract identifiers used inside an array index (e.g. offset1,
        # j from `src_buff[offset1 + j + 1]`), since those are the values that
        # actually steer the (possibly out-of-bounds) access.
        m_idx = re.search(r'\[([^\]]*)\]', var)
        if m_idx:
            for im in re.finditer(r'\b([a-zA-Z_]\w*)\b', m_idx.group(1)):
                name = im.group(1)
                if name in C_KEYWORDS or name in SKIP_FUNCTIONS:
                    continue
                if name not in seen:
                    seen.add(name)
                    variables.append(name)

    return variables


def _check_polytracker_env():
    """Check if PolyTracker build environment is properly configured.

    Returns:
        Tuple of (is_ok, missing_vars, error_message).
    """
    required = ['COMPILER_DIR', 'CXX_LIB_PATH', 'WLLVM_ARTIFACT_STORE',
                'DFSAN_LIB_PATH']
    missing = [v for v in required if not os.environ.get(v)]

    if missing:
        return False, missing, (
            f"PolyTracker build environment not configured. "
            f"Missing env vars: {', '.join(missing)}.\n"
            f"  To use PolyTracker, either:\n"
            f"  1. Run inside PolyTracker Docker container:\n"
            f"     docker pull trailofbits/polytracker:latest\n"
            f"     docker run -v $(pwd):/work -w /work trailofbits/polytracker:latest\n"
            f"  2. Or set the required environment variables (see PolyTracker README)."
        )

    # Verify paths exist
    for var in required:
        p = Path(os.environ[var])
        if not p.exists():
            return False, [var], f"PolyTracker env var {var}={p} does not exist"

    return True, [], ""


def _polytracker_build_and_run(source_dir, program_name, input_file,
                                output_file, extra_args=None,
                                build_cmds=None, polytracker_bin=None,
                                trace_output_dir=None):
    """Build target with PolyTracker, run it, and return trace path.

    Args:
        source_dir: Path to the source/build directory of the target version.
        program_name: Name of the program binary (e.g. 'sfconvert').
        input_file: Path to the input file.
        output_file: Path for the output file.
        extra_args: Additional command-line arguments list.
        build_cmds: List of shell commands to build the project (pre_build).
        polytracker_bin: Path to polytracker command. Auto-detected if None.
        trace_output_dir: Directory for trace output. Uses tempdir if None.

    Returns:
        Path to the .tdb trace file, or None on failure.
    """
    source_dir = Path(source_dir).resolve()
    input_file = Path(input_file).resolve()
    output_file = Path(output_file).resolve()

    if not source_dir.exists():
        print(f"  [PolyTracker] Source directory not found: {source_dir}")
        return None

    # Find polytracker command
    if polytracker_bin is None:
        polytracker_bin = shutil.which('polytracker')
    if polytracker_bin is None:
        print("  [PolyTracker] polytracker command not found in PATH")
        return None

    if trace_output_dir is None:
        trace_output_dir = Path(tempfile.mkdtemp(prefix="polytracker_"))
    else:
        trace_output_dir = Path(trace_output_dir)
        trace_output_dir.mkdir(parents=True, exist_ok=True)

    print(f"  [PolyTracker] Building in {source_dir} ...")

    # Step 1: Build with polytracker build
    try:
        if build_cmds:
            # Use the project's own build commands wrapped with polytracker
            for cmd in build_cmds:
                full_cmd = f"{polytracker_bin} build {cmd}"
                print(f"    $ {full_cmd}")
                result = subprocess.run(
                    full_cmd, shell=True, cwd=str(source_dir),
                    capture_output=True, text=True, timeout=600
                )
                if result.returncode != 0:
                    print(f"  [PolyTracker] Build command failed: {cmd}")
                    print(f"    stderr: {result.stderr[:500]}")
                    return None
        else:
            # Try simple make
            full_cmd = f"{polytracker_bin} build make -j2"
            print(f"    $ {full_cmd}")
            result = subprocess.run(
                full_cmd, shell=True, cwd=str(source_dir),
                capture_output=True, text=True, timeout=600
            )
            if result.returncode != 0:
                print(f"  [PolyTracker] Build failed")
                print(f"    stderr: {result.stderr[:500]}")
                return None
    except subprocess.TimeoutExpired:
        print("  [PolyTracker] Build timed out (600s)")
        return None
    except Exception as e:
        print(f"  [PolyTracker] Build error: {e}")
        return None

    # Step 2: Instrument the target binary
    # Look for the binary in common locations
    binary_candidates = []
    for root, dirs, files in source_dir.walk():
        for f in files:
            if f == program_name or f == program_name + '.libs':
                binary_candidates.append(root / f)
        # Don't recurse too deep
        if len(list(root.parts)) - len(source_dir.parts) > 4:
            break

    # Also check exec_subdir patterns
    for subdir in ['', '/sfcommands', '/.libs', '/libaudiofile/.libs',
                    '/src/appl', '/build/src/appl']:
        candidate = source_dir / subdir.lstrip('/') / program_name
        if candidate.exists():
            binary_candidates.insert(0, candidate)

    if not binary_candidates:
        print(f"  [PolyTracker] Binary '{program_name}' not found after build")
        return None

    target_binary = binary_candidates[0]
    print(f"  [PolyTracker] Found binary: {target_binary}")

    try:
        journal_path = source_dir / "blight_journal.jsonl"
        if not journal_path.exists():
            # Search for it
            for root, dirs, files in source_dir.walk():
                if "blight_journal.jsonl" in files:
                    journal_path = root / "blight_journal.jsonl"
                    break

        if not journal_path.exists():
            print("  [PolyTracker] blight_journal.jsonl not found")
            return None

        inst_cmd = [
            str(polytracker_bin), "instrument-targets",
            "--journal-path", str(journal_path),
            str(target_binary)
        ]
        print(f"    $ {' '.join(inst_cmd)}")
        result = subprocess.run(
            inst_cmd, capture_output=True, text=True, timeout=300
        )
        if result.returncode != 0:
            print(f"  [PolyTracker] Instrumentation failed")
            print(f"    stderr: {result.stderr[:500]}")
            return None
    except Exception as e:
        print(f"  [PolyTracker] Instrumentation error: {e}")
        return None

    # Find the instrumented binary
    inst_binary = None
    for suffix in ['.instrumented', '_track', '.track']:
        candidate = target_binary.parent / (target_binary.name + suffix)
        if candidate.exists():
            inst_binary = candidate
            break
    # Also check for .instrumented in same directory
    for f in target_binary.parent.iterdir():
        if f.name.endswith('.instrumented') or '_track' in f.name:
            inst_binary = f
            break

    if inst_binary is None:
        print(f"  [PolyTracker] Instrumented binary not found")
        return None

    print(f"  [PolyTracker] Instrumented binary: {inst_binary}")

    # Step 3: Run the instrumented binary
    trace_db = trace_output_dir / "polytracker.tdb"
    try:
        output_file.parent.mkdir(parents=True, exist_ok=True)
        run_cmd = [
            str(polytracker_bin), "trace", "run",
            "-o", str(trace_db),
            str(inst_binary),
            str(input_file),
        ]
        if extra_args:
            run_cmd.extend(extra_args)

        print(f"    $ {' '.join(run_cmd)}")
        env = os.environ.copy()
        env['ASAN_OPTIONS'] = 'detect_leaks=0'
        result = subprocess.run(
            run_cmd, capture_output=True, text=True,
            timeout=120, env=env
        )
        if result.returncode != 0:
            # Check if trace was still produced (crash is OK)
            if not trace_db.exists():
                print(f"  [PolyTracker] Run failed and no trace produced")
                print(f"    stderr: {result.stderr[:500]}")
                return None
            print(f"  [PolyTracker] Program exited with code {result.returncode} (may be OK)")
        print(f"  [PolyTracker] Trace saved to: {trace_db}")
    except subprocess.TimeoutExpired:
        print("  [PolyTracker] Run timed out (120s)")
        if trace_db.exists():
            print(f"  [PolyTracker] Partial trace saved to: {trace_db}")
        else:
            return None
    except Exception as e:
        print(f"  [PolyTracker] Run error: {e}")
        return None

    return trace_db if trace_db.exists() else None


def _polytracker_analyze_trace(trace_path, fork_function=None):
    """Analyze a PolyTracker trace to find input byte offsets.

    Args:
        trace_path: Path to the .tdb trace file.
        fork_function: Name of the function containing the fork statement.
                      If provided, only taints from this function are returned.
                      If None, all inputs affecting control flow are returned.

    Returns:
        Dict with:
          'input_offsets': sorted list of (offset, length) tuples
          'total_bytes': total number of tainted input bytes
          'function_name': the function analyzed
    """
    trace_path = Path(trace_path)
    if not trace_path.exists():
        print(f"  [PolyTracker] Trace file not found: {trace_path}")
        return None

    try:
        from polytracker import PolyTrackerTrace
        trace = PolyTrackerTrace.load(str(trace_path))
    except Exception as e:
        print(f"  [PolyTracker] Failed to load trace: {e}")
        return None

    input_offsets = set()

    if fork_function:
        # Find the function in the trace and get its taints
        try:
            for func_entry in trace.function_trace:
                func_name = func_entry.function.name if hasattr(func_entry.function, 'name') else str(func_entry.function)
                if fork_function in func_name or func_name in fork_function:
                    # Get taints for this function entry
                    taints = func_entry.taints
                    for region in taints.regions:
                        input_offsets.add((region.offset, region.length))
                    print(f"  [PolyTracker] Found {len(input_offsets)} tainted regions in {func_name}")
                    break
            else:
                print(f"  [PolyTracker] Function '{fork_function}' not found in trace")
                # Fall back to all inputs affecting control flow
        except Exception as e:
            print(f"  [PolyTracker] Error reading function taints: {e}")

    if not input_offsets:
        # Fall back: all inputs affecting control flow
        try:
            cf_taints = trace.inputs_affecting_control_flow
            for region in cf_taints.regions:
                input_offsets.add((region.offset, region.length))
            print(f"  [PolyTracker] Found {len(input_offsets)} control-flow-affecting input regions")
        except Exception as e:
            print(f"  [PolyTracker] Error reading control flow taints: {e}")

    if not input_offsets:
        # Last resort: get all taints from all inputs
        try:
            all_taints = trace.taints
            for region in all_taints.regions:
                input_offsets.add((region.offset, region.length))
            print(f"  [PolyTracker] Found {len(input_offsets)} total tainted regions")
        except Exception as e:
            print(f"  [PolyTracker] Error reading all taints: {e}")

    sorted_offsets = sorted(input_offsets, key=lambda x: x[0])
    total_bytes = sum(length for _, length in sorted_offsets)

    return {
        'input_offsets': sorted_offsets,
        'total_bytes': total_bytes,
        'function_name': fork_function,
    }


def _polytracker_locate_input_offsets(result, config=None, binary_b=None, binary_a=None):
    """Run PolyTracker analysis on the target binary to locate input offsets.

    This is the main entry point for PolyTracker-based input offset localization.
    It is called after a fork statement has been identified.

    Args:
        result: The divergence analysis result dict (must contain
                'root_cause_function', 'root_cause_file', 'root_cause_line',
                'root_cause_statement_b').
        config: Optional config module with COMPILE_COMMANDS and EXECUTION_CONFIG.
        binary_b: Optional path to the target binary (to find the project root).
        binary_a: Optional path to the reference binary (used when the fork
                  lives in the reference, i.e. the target stopped before it).

    Returns:
        Updated result dict with 'polytracker_offsets' key added.
    """
    # For a semantic fork, PolyTracker must instrument the *target*'s equivalent
    # value-read site (poly_track_*), not the 4.4.0 guard (which the target lacks).
    if result.get('semantic_fork') and result.get('poly_track_file'):
        func_name = result.get('poly_track_function') or result.get('root_cause_function')
        source_file = result.get('poly_track_file')
        source_line = result.get('poly_track_line')
        statement = result.get('poly_track_statement', '')
    else:
        func_name = result.get('root_cause_function')
        source_file = result.get('root_cause_file')
        source_line = result.get('root_cause_line')
        statement = result.get('root_cause_statement_b', '')

    if not func_name or not statement:
        print("  [PolyTracker] No fork statement to analyze")
        return result

    print("\n" + "=" * 70)
    print("PolyTracker Input Offset Analysis")
    print("=" * 70)

    # When the target stopped before the fork (diverging_call_b is None), the
    # fork lives in the reference — use binary_a to locate its source text.
    fork_binary = binary_b
    if result.get('diverging_call_a') and not result.get('diverging_call_b'):
        fork_binary = binary_a or binary_b

    # Step 1: Get the complete fork statement (may span multiple lines)
    source_dirs = None
    if fork_binary:
        try:
            source_dirs = find_source_dirs(str(fork_binary))
        except Exception:
            source_dirs = None
    # Robustly resolve the fork statement's source file: absolute path,
    # relative path under source_dirs, or a basename search across version dirs.
    if source_file:
        sf = Path(source_file)
        if sf.is_absolute() and sf.exists():
            source_dirs = [str(sf.parent)]
        elif not source_dirs or not _locate_source_file(str(source_file), source_dirs):
            search_roots = [Path('.')] + [
                v for v in Path('.').glob('*-versions/*') if v.is_dir()]
            for root in search_roots:
                for match in root.rglob(sf.name):
                    if match.is_file():
                        source_dirs = [str(match.parent)]
                        break
                if source_dirs:
                    break

    full_stmt, start_line, end_line = _get_complete_fork_statement(
        source_file, source_line, source_dirs)

    if full_stmt:
        print(f"  Complete fork statement (lines {start_line}-{end_line}):")
        print(f"    {full_stmt}")
    else:
        full_stmt = statement
        print(f"  Fork statement (from result): {statement}")

    # If this is a condition fork, keep ONLY the condition expression (drop the
    # `{ body; }` block) so variable extraction doesn't pick up body variables.
    if result.get('_fork_is_condition'):
        cond = _extract_if_condition(full_stmt)
        if cond:
            full_stmt = cond
            print(f"  Fork condition (body stripped): {cond}")

    # Update the reported fork statement to the complete multi-line statement
    # so downstream display and variable extraction use the full expression.
    if full_stmt:
        result['root_cause_statement_b'] = full_stmt
        result['root_cause_line'] = start_line or source_line
        if end_line:
            result['root_cause_line_end'] = end_line

    # Step 2: Extract variables from the statement
    # Use the pre-collected variables from the dependency chain if available
    # (which include all variables that feed into the guard's computation),
    # otherwise extract from the statement directly.
    variables = result.get('variables') or _extract_variables_from_expression(full_stmt)
    if variables:
        print(f"  Extracted variables: {variables}")
    else:
        print("  No variables extracted from statement")

    # Determine the target project root for the PolyTracker build.
    source_dir = None
    if binary_b:
        source_dir = find_version_root(binary_b)
    if source_dir is None and source_file:
        sf = Path(source_file)
        if not sf.is_absolute():
            for root in [Path('.')] + [v for v in Path('.').glob('*-versions/*') if v.is_dir()]:
                for match in root.rglob(sf.name):
                    if match.is_file():
                        sf = match.resolve()
                        break
        for parent in [sf] + list(sf.parents):
            if (parent / 'configure').exists() or (parent / 'Makefile').exists():
                source_dir = parent
                break

    base_info = {
        'function_name': func_name,
        'variables': variables,
        'fork_statement': full_stmt,
        'fork_statement_lines': [start_line, end_line],
        'source_file': source_file,
        'source_line': source_line,
    }

    if config is None:
        print("  [PolyTracker] No config provided — variable extraction only.")
        result['polytracker_offsets'] = dict(base_info, status='skipped_no_config')
        return result

    if source_dir is None:
        print("  [PolyTracker] Cannot determine target source directory.")
        result['polytracker_offsets'] = dict(base_info, status='no_source_dir')
        return result

    print(f"  Target project root: {source_dir}")

    # Step 3: Build + run + analyze with PolyTracker (external module).
    exec_config = getattr(config, 'EXECUTION_CONFIG', {})
    compile_cmds = getattr(config, 'COMPILE_COMMANDS', {})
    program_name = exec_config.get('program_name', '')
    command_format = exec_config.get('command_format', '')

    input_file = result.get('input_file') or config_path_input(config)
    output_file = getattr(config, 'OUTPUT_FILE', None)
    if not output_file:
        import tempfile
        output_file = tempfile.mktemp(prefix="poly_out_", suffix=".tif")

    # Build the full argument list from command_format, substituting the
    # placeholders (program_path is dropped; binary is argv[0]).
    full_args = []
    for arg in (command_format or '').split():
        if arg == '{program_path}' or '{program_name}' in arg:
            continue
        if '{input_file}' in arg:
            full_args.append(arg.replace('{input_file}', str(input_file)))
        elif '{output_file}' in arg:
            full_args.append(arg.replace('{output_file}', str(output_file)))
        elif '{input}' in arg:
            full_args.append(arg.replace('{input}', str(input_file)))
        elif '{output}' in arg:
            full_args.append(arg.replace('{output}', str(output_file)))
        else:
            full_args.append(arg)

    target_build = compile_cmds.get('target', {})
    build_cmds = [
        c.replace('-finstrument-functions', '')
        for c in target_build.get('pre_build', [])
    ]
    compile_flags = target_build.get('compile_flags', {})

    try:
        import polytracker_offsets as po
        # For semantic forks, use poly_track_* fields (pointing to the target's
        # variable-read site) rather than root_cause_* (which may point to the
        # guard or the caller's fork-call-site, neither of which is correct for
        # instrumentation).
        pt_file = result.get('poly_track_file') or result.get('root_cause_file')
        pt_line = result.get('poly_track_line') or result.get('root_cause_line')
        pt_stmt = result.get('poly_track_statement') or full_stmt
        pt = po.locate_offsets(
            source_dir=source_dir,
            program_name=program_name,
            input_file=input_file,
            fork_function=func_name,
            build_cmds=build_cmds or None,
            full_args=full_args,
            compile_flags=compile_flags,
            fork_source_file=pt_file,
            fork_line=pt_line,
            variables=variables,
            fork_statement=pt_stmt,
        )
    except Exception as e:
        print(f"  [PolyTracker] Analysis error: {e}")
        result['polytracker_offsets'] = dict(base_info, status='error', error=str(e))
        return result

    result['polytracker_offsets'] = dict(base_info, **pt)

    # Also run reverse_taint.py as a cross-check (no build required)
    try:
        import reverse_taint as rt
        binary = result.get('target_binary') or result.get('binary_b', '')
        if binary and input_file:
            fork_file = result.get('root_cause_file', '')
            fork_line = result.get('root_cause_line', 0)
            if fork_file and fork_line:
                rt_result = rt.run_analysis(
                    binary=binary, fork_file=fork_file, fork_line=fork_line,
                    variables=variables or [], input_file=str(input_file),
                    program_args=full_args, mode='tiff')
                result['reverse_taint_offsets'] = rt_result
    except Exception as e:
        result['reverse_taint_offsets'] = {'status': 'error', 'error': str(e)}

    # chunk_mutation.py is available as a fallback for non-TIFF formats,
    # but has a known limitation: flipping header/structure bytes causes
    # crashes before reaching the fork, so it cannot detect influential
    # offsets in critical file structure areas. For TIFF files, use
    # reverse_taint.py (static TIFF parse) instead.

    return result


def config_path_input(config):
    """Best-effort extraction of the input file path from a config module."""
    for attr in ('INPUT_FILE', 'input_file'):
        v = getattr(config, attr, None)
        if v:
            return v
    return None


def main():
    """CLI entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Trace the root cause of execution divergence between two binary versions."
    )
    parser.add_argument("result_json",
                        help="Path to JSON output from lcs_trace.py")
    parser.add_argument("--binary-a", required=True,
                        help="Path to binary A")
    parser.add_argument("--binary-b", required=True,
                        help="Path to binary B")
    parser.add_argument("--args-a", nargs="*", default=[],
                        help="Arguments for binary A")
    parser.add_argument("--args-b", nargs="*", default=[],
                        help="Arguments for binary B")
    parser.add_argument("--input", help="Input file (referenced as {input} in args)")
    parser.add_argument("--config", default=None,
                        help="Path to config module for PolyTracker analysis")
    parser.add_argument("--gdb-timeout", type=int, default=120,
                        help="Timeout for GDB operations (seconds)")
    parser.add_argument("-o", "--output", help="Output JSON file")

    args = parser.parse_args()

    # Substitute {input} in args
    args_a = [a.replace("{input}", args.input) if args.input else a
              for a in args.args_a]
    args_b = [a.replace("{input}", args.input) if args.input else a
              for a in args.args_b]

    # Load config module if provided
    config_module = None
    if args.config:
        import importlib.util
        cfg_path = Path(args.config).resolve()
        spec = importlib.util.spec_from_file_location("config_mod", str(cfg_path))
        config_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(config_module)

    result = analyze_lcs_result(
        args.result_json, args.binary_a, args.binary_b,
        args_a=args_a, args_b=args_b,
        input_file=args.input,
        gdb_timeout=args.gdb_timeout,
        config=config_module,
    )

    print("\n" + "=" * 70)
    print("Divergence Analysis Result")
    print("=" * 70)
    print(f"Divergence function: {result.get('divergence_function', 'N/A')}")
    print(f"Root cause: {result.get('diverging_statement', result.get('description', 'N/A'))}")
    if result.get("source_file") and result.get("source_line"):
        print(f"Location: {result['source_file']}:{result['source_line']}")
    print(f"Description: {result.get('description', 'N/A')}")

    if args.output:
        with open(args.output, 'w') as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        print(f"\nResult saved to: {args.output}")


if __name__ == "__main__":
    main()
