"""Backward tracer: find the fork statement by tracing from function exit backward.

Given two versions of a program, find the last common function from the trace,
then trace backward from its return statement to find the first variable whose
value differs between versions. That variable's assignment/condition is the fork
statement.

Usage:
    from backward_tracer import find_fork_by_backward_tracing
    result = find_fork_by_backward_tracing(
        binary_a, binary_b, source_a, source_b,
        func_name, input_file, args
    )
"""

import os
import re
import subprocess
import tempfile
from pathlib import Path


# ---------------------------------------------------------------------------
# Source-code analysis helpers
# ---------------------------------------------------------------------------

def find_return_statements(source_file, func_name):
    """Find all return statements in func_name's body.

    Returns list of dicts:
        [{"line": int, "statement": str, "condition": str or None}, ...]

    The condition is the enclosing if-condition (if any) that guards the return.
    """
    try:
        code = open(source_file, encoding='utf-8', errors='replace').read()
    except OSError:
        return []

    # Extract function body
    body = _extract_function_body(code, func_name)
    if not body:
        return []

    # Compute the line offset of the function body within the file
    head = code[:code.find(body)] if body in code else ''
    body_offset = head.count('\n') + 1  # 1-indexed

    results = []
    lines = body.splitlines()
    cond_stack = []  # (condition_text, active_from_depth)
    brace_depth = 0
    pending_single_line = None

    for i, line in enumerate(lines):
        stripped = line.strip()
        depth_at_start = brace_depth

        # Detect if-statements
        if_m = re.match(r'if\s*\((.+?)\)\s*\{?\s*$', stripped)
        if if_m:
            if stripped.endswith('{'):
                cond_stack.append((if_m.group(1).strip(), brace_depth + 1))
                pending_single_line = None
            else:
                pending_single_line = if_m.group(1).strip()

        # Detect return statements (BEFORE brace update)
        ret_m = re.match(r'return\s+(.+?)\s*;', stripped)
        if ret_m:
            cond = None
            if pending_single_line:
                cond = pending_single_line
                pending_single_line = None
            elif cond_stack:
                for c, d in reversed(cond_stack):
                    if d <= depth_at_start:
                        cond = c
                        break
            results.append({
                'line': body_offset + i,
                'statement': stripped,
                'return_expr': ret_m.group(1).strip(),
                'condition': cond,
                'brace_depth': depth_at_start,
            })
        elif pending_single_line and not stripped.startswith(('if', 'else')):
            pending_single_line = None

        # Update depth AFTER processing content
        open_count = stripped.count('{')
        close_count = stripped.count('}')
        brace_depth = depth_at_start + open_count - close_count

        # Pop conditions whose scope is above the new depth
        while cond_stack and cond_stack[-1][1] > brace_depth:
            cond_stack.pop()

    return results


def trace_dependenciesbackward(source_file, func_name, return_line):
    """Trace backward from a return statement to find variables that affect it.

    Returns a list of dependency entries in reverse order (closest to return first):
        [{"line": int, "statement": str, "variables": [str, ...],
          "kind": "assignment"|"condition"|"call"|"return"}, ...]
    """
    try:
        code = open(source_file, encoding='utf-8', errors='replace').read()
    except OSError:
        return []

    body = _extract_function_body(code, func_name)
    if not body:
        return []

    head = code[:code.find(body)] if body in code else ''
    body_offset = head.count('\n') + 1

    lines = body.splitlines()
    # Convert return_line to body-local index
    local_idx = return_line - body_offset
    if local_idx < 0 or local_idx >= len(lines):
        return []

    deps = []
    # Scan backward from the return statement
    brace_depth = 0
    # Pre-compute brace depths
    depths = []
    d = 0
    for line in lines:
        d += line.count('{') - line.count('}')
        depths.append(d)

    seen_vars = set()
    for i in range(local_idx, -1, -1):
        stripped = lines[i].strip()
        if not stripped or stripped.startswith(('/*', '//', '*')):
            continue

        kind = None
        variables = []

        # Return statement
        if re.match(r'return\b', stripped):
            kind = 'return'
            variables = _extract_variables(stripped)

        # Assignment: var = expr  or  var op= expr
        elif re.match(r'\w[\w.\[\]>-]*\s*=\s*.+', stripped) and not stripped.startswith(('if', 'else', 'while', 'for')):
            kind = 'assignment'
            m = re.match(r'([\w.\[\]>-]+)\s*=', stripped)
            if m:
                variables = [m.group(1)] + _extract_variables(stripped[m.end():])

        # Condition in if/while
        elif re.match(r'(if|while)\s*\(', stripped):
            kind = 'condition'
            m = re.match(r'(?:if|while)\s*\((.+?)\)\s*\{?\s*$', stripped)
            if m:
                variables = _extract_variables(m.group(1))

        # Function call: might be an assignment  ret = func(...)
        elif re.match(r'\w[\w.\[\]>-]*\s*=\s*\w+\s*\(', stripped):
            kind = 'call'
            m = re.match(r'([\w.\[\]>-]+)\s*=\s*(\w+)\s*\(([^)]*)\)', stripped)
            if m:
                variables = [m.group(1)]  # LHS variable
            else:
                variables = _extract_variables(stripped)

        # Standalone function call (side effect)
        elif re.match(r'\w+\s*\(', stripped):
            kind = 'call'
            variables = _extract_variables(stripped)

        # Declaration with initialization: type var = expr
        elif re.match(r'(?:static\s+)?(?:const\s+)?\w[\w\s*]*\s+\w+\s*=\s*.+', stripped):
            kind = 'assignment'
            m = re.match(r'(?:static\s+)?(?:const\s+)?\w[\w\s*]*\s+(\w+)\s*=\s*(.+)', stripped)
            if m:
                variables = [m.group(1)] + _extract_variables(m.group(2))

        if kind and variables:
            # Filter out constants, numbers, macros
            variables = [v for v in variables
                         if not re.match(r'^\d', v) and v.islower() or '->' in v or '.' in v]
            # Only keep variables we haven't seen yet (most recent assignment)
            new_vars = [v for v in variables if v not in seen_vars]
            if new_vars:
                seen_vars.update(new_vars)
                deps.append({
                    'line': body_offset + i,
                    'statement': stripped,
                    'variables': variables,
                    'kind': kind,
                })

        # Stop at function entry
        if re.match(rf'(?:static\s+)?(?:\w+\s+)*\b{re.escape(func_name)}\s*\(', stripped):
            break

    return deps


def _extract_variables(expr):
    """Extract variable names from a C expression."""
    if not expr:
        return []
    # Remove string literals
    expr = re.sub(r'"[^"]*"', '', expr)
    # Remove character literals
    expr = re.sub(r"'[^']*'", '', expr)
    # Remove numbers
    expr = re.sub(r'\b\d+\b', '', expr)
    # Remove common keywords/operators
    expr = re.sub(r'\b(sizeof|sizeof|NULL|TRUE|FALSE|true|false)\b', '', expr)
    # Find identifiers (including a->b, a.b, a[i] patterns)
    # First, find member access chains like direntry->tdir_count
    chains = re.findall(r'[\w]+(?:->|\.|\[[\w]+\])[\w]+(?:->|\.|\[[\w]+\])*[\w]*', expr)
    # Then find bare identifiers
    bare = re.findall(r'\b([a-zA-Z_]\w*)\b', expr)
    # Combine: chains first, then bare (minus keywords)
    keywords = {'if', 'else', 'while', 'for', 'do', 'return', 'sizeof', 'NULL',
                'TRUE', 'FALSE', 'true', 'false', 'static', 'const', 'void',
                'int', 'uint8', 'uint16', 'uint32', 'uint64', 'char', 'unsigned',
                'signed', 'long', 'short', 'float', 'double', 'struct', 'enum'}
    result = list(chains) + [v for v in bare if v not in keywords]
    return result


def _extract_function_body(code, func_name):
    """Extract the body of a function from source code.

    Brace-matching skips braces inside comments, strings, char literals, and
    preprocessor conditionals (``#if``/``#else``/``#endif``): for a conditional
    only the *then* branch's braces are counted, so an ``{`` duplicated across
    ``#if``/``#else`` branches (common in libtiff) does not corrupt scope
    tracking.
    """
    pattern = rf'(?:static\s+)?(?:\w+\s+)*\b{re.escape(func_name)}\s*\([^)]*\)\s*\{{'
    m = re.search(pattern, code, re.DOTALL)
    if not m:
        return None

    start = m.end() - 1  # position of the opening brace
    lines = code.split('\n')
    start_line = code[:start].count('\n')  # 0-indexed line holding '{'

    # Preprocessor state: for each nested conditional, are we in the
    # "then" branch (count braces) or "skip" branch (ignore braces)?
    pp_stack = []  # values: 'then' or 'skip'

    depth = 0
    i = start_line
    while i < len(lines):
        line = lines[i]
        stripped = line.lstrip()

        if stripped.startswith('#'):
            directive = stripped[1:].strip()
            if directive.startswith('if'):
                pp_stack.append('then')
            elif directive.startswith(('else', 'elif')):
                if pp_stack:
                    pp_stack[-1] = 'skip'
            elif directive.startswith('endif'):
                if pp_stack:
                    pp_stack.pop()
            i += 1
            continue

        if pp_stack and pp_stack[-1] == 'skip':
            i += 1
            continue

        # For the opening-brace line, only count braces AFTER the '{'.
        seg = line
        if i == start_line:
            col = start - code[:start].rfind('\n') - 1
            seg = line[col:]

        depth += _count_braces_in_segment(seg)

        if depth == 0 and i != start_line:
            return '\n'.join(lines[start_line:i + 1])

        i += 1

    return None


def _count_braces_in_segment(seg):
    """Count ``{`` (as +1) and ``}`` (as -1) in a code segment, skipping
    comments, strings, and char literals."""
    delta = 0
    i = 0
    n = len(seg)
    while i < n:
        c = seg[i]
        nxt = seg[i + 1] if i + 1 < n else ''
        if c == '/' and nxt == '/':
            i += 2
            while i < n and seg[i] != '\n':
                i += 1
            continue
        if c == '/' and nxt == '*':
            i += 2
            while i < n and not (seg[i] == '*' and i + 1 < n and seg[i + 1] == '/'):
                i += 1
            i += 2
            continue
        if c == '"':
            i += 1
            while i < n:
                if seg[i] == '\\':
                    i += 2
                    continue
                if seg[i] == '"':
                    i += 1
                    break
                i += 1
            continue
        if c == "'":
            i += 1
            while i < n:
                if seg[i] == '\\':
                    i += 2
                    continue
                if seg[i] == "'":
                    i += 1
                    break
                i += 1
            continue
        if c == '{':
            delta += 1
        elif c == '}':
            delta -= 1
        i += 1
    return delta


def _find_function_source(func_name, source_dirs):
    """Find the source file containing func_name's definition.

    ``source_dirs`` is a single dir or a list of dirs to search (rglob .c/.cpp).
    Returns the file path as a string, or None.

    When a function is defined in both a platform-specific file (e.g.
    ``tif_win32.c``) and a generic one (``tif_unix.c``), prefer the file that
    matches the current OS (on Linux, avoid ``*win32*`` files).
    """
    if isinstance(source_dirs, (str, os.PathLike)):
        source_dirs = [source_dirs]
    matches = []
    for d in source_dirs:
        for ext in ('.c', '.cpp'):
            for path in Path(d).rglob(f'*{ext}'):
                try:
                    content = path.read_text(encoding='utf-8', errors='replace')
                except OSError:
                    continue
                pattern = rf'(?:static\s+)?(?:\w+\s+)*\b{re.escape(func_name)}\s*\([^)]*\)\s*\{{'
                if re.search(pattern, content):
                    matches.append(str(path))
    if not matches:
        return None
    # Prefer non-win32 files on Linux (they are the compiled variant)
    if os.name != 'nt':
        preferred = [p for p in matches if 'win32' not in p.lower()]
        if preferred:
            return preferred[0]
    return matches[0]


def _extract_callee(statement):
    """Extract the called function name from an assignment statement.

    Handles ``var = Callee(...)``, ``var = Callee(...)`` with casts, and
    multi-line calls. Returns the callee name or None.  Skips C keywords
    (``sizeof``, ``if``, ``while``, ``for``, ``switch``, ``return``) which are
    operators/control-flow, not function calls.
    """
    if not statement:
        return None
    m = re.search(r'=\s*(?:\([^)]*\)\s*)?(\w+)\s*\(', statement)
    if m:
        name = m.group(1)
        if name in _C_KEYWORDS:
            return None
        return name
    return None


_C_KEYWORDS = {
    'sizeof', 'if', 'else', 'while', 'for', 'switch', 'case', 'return',
    'goto', 'break', 'continue', 'static', 'const', 'do',
}

_SEMANTIC_SUFFIXES = (
    'WithLimit', 'Checked', 'Safe', 'Secure', 'Validated', 'Sanitized',
    'Bounded', 'Limited', 'WithSize', 'WithCount',
)


def _resolve_callee_pair(callee, src_dir_a, src_dir_b):
    """Resolve a callee name to its (possibly renamed) definitions in both versions.

    Returns (callee_a, callee_b, src_a, src_b).  If ``callee`` exists directly in
    both versions, returns it as-is.  If it exists only in A, looks for a
    *semantic variant* in B (e.g. ``TIFFReadDirEntryLong8Array`` in A vs
    ``TIFFReadDirEntryLong8ArrayWithLimit`` in B) and vice-versa.
    """
    src_a = _find_function_source(callee, src_dir_a)
    src_b = _find_function_source(callee, src_dir_b)

    if src_a and src_b:
        return callee, callee, src_a, src_b

    if src_a and not src_b:
        for suf in _SEMANTIC_SUFFIXES:
            variant = callee + suf
            src_b2 = _find_function_source(variant, src_dir_b)
            if src_b2:
                return callee, variant, src_a, src_b2

    if src_b and not src_a:
        for suf in _SEMANTIC_SUFFIXES:
            variant = callee + suf
            src_a2 = _find_function_source(variant, src_dir_a)
            if src_a2:
                return variant, callee, src_a2, src_b

    return callee, callee, src_a, src_b


def _extract_calls_from_expression(expr):
    """Extract function-call names from a C expression string.

    Returns a list of callee names (in order of appearance), skipping keywords.
    """
    if not expr:
        return []
    # Find identifiers followed by '('
    calls = re.findall(r'\b([A-Za-z_]\w*)\s*\(', expr)
    return [c for c in calls if c not in _C_KEYWORDS]


def _extract_checked_calls(source_file, func_name):
    """Extract all *checked* function calls in func_name's body.

    A "checked" call is one whose return value is tested in an ``if``/``while``
    condition (e.g. ``if (!TIFFFetchStripThing(...))``).  These calls can change
    control flow and thus the function's return value, so they are fork
    candidates even when far from the return statement (e.g. behind a ``goto``).

    Returns a list of (callee, line, statement) tuples in source order.
    """
    try:
        code = open(source_file, encoding='utf-8', errors='replace').read()
    except OSError:
        return []
    body = _extract_function_body(code, func_name)
    if not body:
        return []
    head = code[:code.find(body)] if body in code else ''
    body_offset = head.count('\n') + 1

    results = []
    for i, line in enumerate(body.splitlines()):
        stripped = line.strip()
        m = re.match(r'(?:if|while|for)\s*\((.+)', stripped)
        if not m:
            m = re.match(r'(?:if|while|for)\s*\(([^)]*)$', stripped)
        cond = m.group(1) if m else ''
        if not cond:
            continue
        for callee in _extract_calls_from_expression(cond):
            results.append((callee, body_offset + i, stripped))
    return results


def _extract_assign_calls(source_file, func_name):
    """Extract all assignment-of-function-call statements in func_name's body.

    Covers ``x = Callee(...)`` and ``x = (Type)Callee(...)`` patterns.  Returns a
    list of (callee, line, statement) tuples in source order.
    """
    try:
        code = open(source_file, encoding='utf-8', errors='replace').read()
    except OSError:
        return []
    body = _extract_function_body(code, func_name)
    if not body:
        return []
    head = code[:code.find(body)] if body in code else ''
    body_offset = head.count('\n') + 1

    results = []
    for i, line in enumerate(body.splitlines()):
        stripped = line.strip()
        callee = _extract_callee(stripped)
        if callee:
            results.append((callee, body_offset + i, stripped))
    return results


# ---------------------------------------------------------------------------
# GDB-based comparison
# ---------------------------------------------------------------------------

def run_gdb_batch(binary, commands, env=None, timeout=120):
    """Run GDB in batch mode and return stdout."""
    gdb_cmds = ["gdb", "-batch", "-ex", "set pagination off",
                "-ex", "set confirm off",
                "-ex", "set breakpoint pending on"]
    for cmd in commands:
        gdb_cmds.extend(["-ex", cmd])
    gdb_cmds.append(binary)
    result = subprocess.run(
        gdb_cmds, capture_output=True, text=True, timeout=timeout, env=env
    )
    return result.stdout + result.stderr


def probe_returns(binary, func_name, input_file, run_args, lib_path=None,
                  timeout=120, max_calls=30):
    """Record every return of ``func_name`` during execution.

    Uses a GDB Python script: break at function entry, disassemble to find all
    ``ret`` instructions, break on each, and continue, recording ``(value, line)``
    for every return hit.  Handles functions called multiple times.

    Returns a list of ``{"value": int, "line": int, "file": str}`` dicts.
    """
    script = f'''set pagination off
set confirm off
set breakpoint pending on
set env ASAN_OPTIONS=detect_leaks=0
catch load libtiff
run {run_args}
tbreak {func_name}
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
if not ret_addrs:
    print("NO_RET_FOUND")
for addr in ret_addrs:
    gdb.execute("break *" + addr)
for i in range({max_calls}):
    gdb.execute("continue")
    try:
        rax = int(gdb.parse_and_eval("$rax"))
    except Exception:
        break
    sal = gdb.find_pc_line(gdb.selected_frame().pc())
    fname = sal.symtab.filename if sal and sal.symtab else ''
    ln = sal.line if sal else 0
    print("RET_HIT:" + str(rax) + ":" + fname + ":" + str(ln))
end
quit
'''

    script_path = f"/tmp/ret_probe_{os.getpid()}.gdb"
    with open(script_path, 'w') as f:
        f.write(script)

    env = _make_env(lib_path)
    gdb_cmds = ["gdb", "-batch", "-x", script_path, str(binary)]
    try:
        result = subprocess.run(gdb_cmds, capture_output=True, text=True,
                                timeout=timeout, env=env)
        output = result.stdout + result.stderr
    finally:
        try:
            os.unlink(script_path)
        except Exception:
            pass

    returns = []
    for line in output.split('\n'):
        m = re.search(r'RET_HIT:(-?\d+):(.+):(\d+)', line)
        if m:
            returns.append({
                'value': int(m.group(1)),
                'file': m.group(2).strip(),
                'line': int(m.group(3)),
            })
    return returns


def compare_return_values(binary_a, binary_b, func_name_a, func_name_b,
                          source_a, source_b, input_file, run_args,
                          lib_path_a=None, lib_path_b=None,
                          timeout=120):
    """Compare return values of func_name_a (in A) vs func_name_b (in B).

    Records every return (value + source line) of each function, then finds the
    first return whose value differs.  Handles functions called multiple times
    and semantic renames (e.g. ``...Array`` vs ``...ArrayWithLimit``).

    Returns a dict with the differing return's value/line/kind, or None.
    """
    rets_a = probe_returns(binary_a, func_name_a, input_file, run_args,
                           lib_path_a, timeout)
    rets_b = probe_returns(binary_b, func_name_b, input_file, run_args,
                           lib_path_b, timeout)

    if not rets_a or not rets_b:
        return None

    n = len(rets_a)
    m = len(rets_b)

    # Classify the difference:
    #  - same length, some value differs -> a genuine fork candidate
    #  - different length              -> early-abort consequence (secondary)
    if n == m:
        diff_a = diff_b = None
        for i in range(n):
            if rets_a[i]['value'] != rets_b[i]['value']:
                diff_a, diff_b = rets_a[i], rets_b[i]
                break
        if diff_a is None:
            return None
        diff_kind = 'same_len_diff_value'
    else:
        # Different lengths: report the first differing value (if any)
        k = min(n, m)
        diff_a = diff_b = None
        for i in range(k):
            if rets_a[i]['value'] != rets_b[i]['value']:
                diff_a, diff_b = rets_a[i], rets_b[i]
                break
        if diff_a is None:
            # The extra return(s) is the difference
            if n > m:
                diff_a, diff_b = rets_a[k], rets_b[-1]
            else:
                diff_a, diff_b = rets_a[-1], rets_b[k]
        diff_kind = 'diff_len'

    # Map the source line back to the local source file for condition lookup.
    returns_a = find_return_statements(source_a, func_name)
    returns_b = find_return_statements(source_b, func_name)

    return {
        'return_line_a': diff_a['line'],
        'return_line_b': diff_b['line'],
        'return_expr_a': _return_expr_at(returns_a, diff_a['line']),
        'return_expr_b': _return_expr_at(returns_b, diff_b['line']),
        'val_a': diff_a['value'],
        'val_b': diff_b['value'],
        'condition_a': _condition_at(returns_a, diff_a['line']),
        'condition_b': _condition_at(returns_b, diff_b['line']),
        'count_a': n,
        'count_b': m,
        'diff_kind': diff_kind,
    }


def _return_expr_at(returns, line):
    """Find the return expression for a given source line."""
    for r in returns:
        if r['line'] == line:
            return r['return_expr']
    return None


def _condition_at(returns, line):
    """Find the enclosing condition for a given source line."""
    for r in returns:
        if r['line'] == line:
            return r['condition']
    return None


def _make_env(lib_path=None):
    """Create environment with ASAN_OPTIONS and optional LD_LIBRARY_PATH."""
    env = os.environ.copy()
    env["ASAN_OPTIONS"] = "detect_leaks=0"
    if lib_path:
        old_ld = env.get("LD_LIBRARY_PATH", "")
        env["LD_LIBRARY_PATH"] = f"{lib_path}:{old_ld}" if old_ld else lib_path
    return env


def _find_main_return(returns, value):
    """Find the return statement that produced ``value``.

    Prefer the return whose expression is a variable (the "real" result) over
    early error returns that return a constant (0/NULL).  This matters because
    a function may return NULL both via ``return NULL`` (early error) and via
    ``return tif`` where ``tif`` happens to be NULL (the value we care about).
    """
    # First pass: return statements whose expression is a variable
    for ret in returns:
        expr = ret['return_expr'].strip()
        if re.match(r'^\w[\w.]*$', expr) and '0' not in expr:
            return ret
    # Second pass: match by value
    for ret in returns:
        expr = ret['return_expr'].strip()
        if value == 0 and '0' in expr:
            return ret
    # Fallback: last return
    return returns[-1] if returns else None


def _parse_rax(gdb_output):
    """Parse $rax value from GDB output."""
    for line in gdb_output.splitlines():
        # Look for "Value returned is $N = ..." pattern first
        m = re.search(r'Value returned is \$\d+\s*=\s*(.+)', line)
        if m:
            val_str = m.group(1).strip()
            return _parse_value(val_str)
        # Look for "$N = <value>" pattern (print $rax result)
        m = re.search(r'\$\d+\s*=\s*(.+)', line)
        if m:
            val_str = m.group(1).strip()
            return _parse_value(val_str)
    return None


def _parse_value(val_str):
    """Parse a GDB value string to int."""
    # Strip type casts like "(TIFF *) 0x0" -> "0x0"
    m = re.search(r'0x[0-9a-fA-F]+', val_str)
    if m:
        return int(m.group(0), 16)
    if val_str in ('0', 'NULL'):
        return 0
    try:
        return int(val_str)
    except ValueError:
        return val_str


def compare_variable_at_line(binary, source_file, line_no, variables,
                              input_file, lib_path=None, timeout=60):
    """Compare variable values at a specific source line between two runs.

    Returns: {var_name: value} or None if breakpoint not hit.
    """
    env = os.environ.copy()
    env["ASAN_OPTIONS"] = "detect_leaks=0"
    if lib_path:
        old_ld = env.get("LD_LIBRARY_PATH", "")
        env["LD_LIBRARY_PATH"] = f"{lib_path}:{old_ld}" if old_ld else lib_path

    cmds = [f"break {source_file}:{line_no}", f"run {input_file}"]
    for var in variables:
        cmds.append(f"print {var}")
    # Continue to next breakpoint hit if first hit is at entry
    cmds.append("continue")

    out = run_gdb_batch(binary, cmds, env=env, timeout=timeout)
    return _parse_variables(out, variables)


def _parse_variables(gdb_output, variables):
    """Parse variable values from GDB output."""
    results = {}
    values = []
    for line in gdb_output.splitlines():
        m = re.search(r'\$\d+\s*=\s*(.+)', line)
        if m:
            values.append(m.group(1).strip())

    for i, var in enumerate(variables):
        if i < len(values):
            val_str = values[i]
            try:
                if val_str.startswith('0x'):
                    results[var] = int(val_str, 16)
                elif val_str in ('0', 'NULL'):
                    results[var] = 0
                else:
                    results[var] = int(val_str)
            except ValueError:
                results[var] = val_str
        else:
            results[var] = None

    return results


def compare_dependency_variables(binary_a, binary_b, deps_a, deps_b,
                                 source_a, source_b, input_file,
                                 lib_path=None, timeout=60):
    """Compare variable values along dependency chains of two versions.

    For each dependency entry, set a breakpoint at that line and compare
    the values of the listed variables.

    Returns: (dep, var_name, val_a, val_b) for the first differing variable,
             or None if all match.
    """
    env = os.environ.copy()
    env["ASAN_OPTIONS"] = "detect_leaks=0"
    if lib_path:
        old_ld = env.get("LD_LIBRARY_PATH", "")
        env["LD_LIBRARY_PATH"] = f"{lib_path}:{old_ld}" if old_ld else lib_path

    # Align dependencies by line number ratio (since code may be at different lines)
    # For each dep in A, find the most likely corresponding dep in B
    for dep_a in deps_a:
        vars_a = dep_a['variables']
        if not vars_a:
            continue

        # Find matching dep in B (same kind, similar position in function)
        best_dep_b = None
        for dep_b in deps_b:
            if dep_b['kind'] == dep_a['kind']:
                # Check if the statement structure is similar
                if _statements_similar(dep_a['statement'], dep_b['statement']):
                    best_dep_b = dep_b
                    break

        if not best_dep_b:
            # Fallback: compare at the same line ratio
            continue

        # Run GDB to compare variable values
        cmds_a = [f"break {source_a}:{dep_a['line']}", f"run {input_file}"]
        for v in vars_a:
            cmds_a.append(f"print {v}")
        out_a = run_gdb_batch(binary_a, cmds_a, env=env, timeout=timeout)
        vals_a = _parse_variables(out_a, vars_a)

        vars_b = best_dep_b['variables']
        cmds_b = [f"break {source_b}:{best_dep_b['line']}", f"run {input_file}"]
        for v in vars_b:
            cmds_b.append(f"print {v}")
        out_b = run_gdb_batch(binary_b, cmds_b, env=env, timeout=timeout)
        vals_b = _parse_variables(out_b, vars_b)

        # Compare common variables
        common_vars = set(vars_a) & set(vars_b)
        for v in common_vars:
            if v in vals_a and v in vals_b:
                if vals_a[v] != vals_b[v]:
                    return {
                        'dep_a': dep_a,
                        'dep_b': best_dep_b,
                        'variable': v,
                        'val_a': vals_a[v],
                        'val_b': vals_b[v],
                    }

    return None


def _statements_similar(stmt_a, stmt_b):
    """Check if two statements have similar structure (for alignment)."""
    # Normalize: remove whitespace, lowercase
    norm_a = re.sub(r'\s+', '', stmt_a).lower()
    norm_b = re.sub(r'\s+', '', stmt_b).lower()
    if norm_a == norm_b:
        return True
    # Check if the LHS variable or operator structure is similar
    # Simple heuristic: same assignment variable
    lhs_a = re.match(r'(\w[\w>.\[\]]*)\s*=', norm_a)
    lhs_b = re.match(r'(\w[\w>.\[\]]*)\s*=', norm_b)
    if lhs_a and lhs_b and lhs_a.group(1) == lhs_b.group(1):
        return True
    # Same condition variable
    cond_a = re.match(r'if\s*\((\w)', norm_a)
    cond_b = re.match(r'if\s*\((\w)', norm_b)
    if cond_a and cond_b and cond_a.group(1) == cond_b.group(1):
        return True
    return False


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def find_fork_by_backward_tracing(binary_a, binary_b, source_dir_a, source_dir_b,
                                   func_name, input_file, run_args,
                                   lib_path_a=None, lib_path_b=None,
                                   timeout=120, max_depth=15):
    """Find the fork statement by backward tracing from function exit.

    Recursively follows the return-value dependency chain: at each function, if
    its return value differs between versions, trace backward to find what
    determines that value.  If it comes from a callee, recurse into the callee;
    otherwise the differing condition/assignment IS the fork statement.

    Args:
        binary_a: Path to version A binary (target/old, e.g. 4.0.8)
        binary_b: Path to version B binary (reference/new, e.g. 4.4.0)
        source_dir_a: Source directory for version A (e.g. .../tiff-4.0.8/libtiff)
        source_dir_b: Source directory for version B
        func_name: The last common function (e.g. "TIFFOpen")
        input_file: Input file to run with
        run_args: Full argument string after the program name
        lib_path_a: Library path for version A
        lib_path_b: Library path for version B
        timeout: GDB timeout in seconds
        max_depth: Max recursion depth into callees

    Returns:
        dict with fork_statement, fork_variable, values, chain, etc.
    """
    chain = []
    result = _find_fork_recursive(
        func_name, binary_a, binary_b, source_dir_a, source_dir_b,
        input_file, run_args, lib_path_a, lib_path_b, timeout,
        depth=0, max_depth=max_depth, chain=chain
    )
    result['chain'] = chain
    return result


def _find_fork_recursive(func_name, binary_a, binary_b, src_dir_a, src_dir_b,
                         input_file, run_args, lib_path_a, lib_path_b, timeout,
                         depth, max_depth, chain):
    """One level of the backward tracing recursion."""
    indent = "  " * depth
    print(f"\n{indent}[depth {depth}] Analyzing function: {func_name}")

    # 1. Find source files
    src_a = _find_function_source(func_name, src_dir_a)
    src_b = _find_function_source(func_name, src_dir_b)
    if not src_a or not src_b:
        print(f"{indent}  Source not found for {func_name}")
        return {'status': 'source_not_found', 'func': func_name}

    # 2. Compare return values
    ret = compare_return_values(
        binary_a, binary_b, func_name, src_a, src_b,
        input_file, run_args, lib_path_a, lib_path_b, timeout
    )
    if not ret:
        print(f"{indent}  Return values equal — not the fork")
        return {'status': 'no_return_difference', 'func': func_name}

    print(f"{indent}  Return values DIFFER:")
    print(f"{indent}    A (old): line {ret['return_line_a']}, val={ret['val_a']:#x}")
    print(f"{indent}    B (new): line {ret['return_line_b']}, val={ret['val_b']:#x}")

    chain.append({
        'func': func_name,
        'val_a': ret['val_a'],
        'val_b': ret['val_b'],
        'return_line_a': ret['return_line_a'],
        'return_line_b': ret['return_line_b'],
    })

    # 3. Collect candidate callees that may determine the return value:
    #    (a) function calls inside return conditions,
    #    (b) function calls that assign to the returned variable, and
    #    (c) all *checked* function calls (if/while conditions) in the body,
    #        which can divert control flow via goto/early-return.
    candidates = []
    returns_a = find_return_statements(src_a, func_name)
    for r in returns_a:
        if r.get('condition'):
            candidates.extend(_extract_calls_from_expression(r['condition']))

    deps_a = trace_dependenciesbackward(src_a, func_name, ret['return_line_a'])
    for dep in deps_a:
        if dep['kind'] in ('call', 'assignment'):
            c = _extract_callee(dep['statement'])
            if c:
                candidates.append(c)

    for callee, line, stmt in _extract_checked_calls(src_a, func_name):
        candidates.append(callee)

    for callee, line, stmt in _extract_assign_calls(src_a, func_name):
        candidates.append(callee)

    seen = set()
    unique_candidates = []
    for c in candidates:
        if c and c != func_name and c not in seen:
            seen.add(c)
            unique_candidates.append(c)

    print(f"{indent}  Candidate callees ({len(unique_candidates)}): "
          f"{unique_candidates[:15]}{'...' if len(unique_candidates) > 15 else ''}")

    # 4. For each candidate, check if its return value also differs.
    #    Prefer "same length, different value" (a genuine fork) over
    #    "different length" (an early-abort consequence of another fork).
    if depth < max_depth:
        primary = []   # same-length value differences
        secondary = []  # length differences
        for callee in unique_candidates:
            callee_src_a = _find_function_source(callee, src_dir_a)
            callee_src_b = _find_function_source(callee, src_dir_b)
            if not callee_src_a or not callee_src_b:
                continue
            sub_ret = compare_return_values(
                binary_a, binary_b, callee, callee_src_a, callee_src_b,
                input_file, run_args, lib_path_a, lib_path_b, timeout
            )
            if sub_ret:
                if sub_ret.get('diff_kind') == 'same_len_diff_value':
                    primary.append((callee, sub_ret))
                else:
                    secondary.append((callee, sub_ret))

        chosen = None
        if primary:
            chosen = primary[0]
        elif secondary:
            chosen = secondary[0]

        if chosen:
            callee, sub_ret = chosen
            print(f"{indent}  -> {callee} return differs ({sub_ret.get('diff_kind')}); "
                  f"recursing")
            return _find_fork_recursive(
                callee, binary_a, binary_b, src_dir_a, src_dir_b,
                input_file, run_args, lib_path_a, lib_path_b, timeout,
                depth + 1, max_depth, chain
            )

    # 5. No callee with a differing return value: the fork is a
    #    variable comparison/assignment in this function.
    fork_dep = None
    for dep in deps_a:
        if dep['kind'] == 'condition':
            fork_dep = dep
            break
    if not fork_dep and deps_a:
        fork_dep = deps_a[0]

    print(f"{indent}  FORK at {func_name}: "
          f"{fork_dep['statement'].strip() if fork_dep else '?'}")
    return {
        'status': 'found',
        'func': func_name,
        'fork_statement': fork_dep['statement'] if fork_dep else None,
        'fork_line': fork_dep['line'] if fork_dep else None,
        'fork_variables': fork_dep['variables'] if fork_dep else [],
        'return_diff': ret,
        'deps_a': deps_a,
    }
