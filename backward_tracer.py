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
    brace_depth = 0
    # Stack of (condition_text, depth_of_opening_brace, is_braced)
    cond_stack = []
    pending_single_line = None

    for i, line in enumerate(lines):
        stripped = line.strip()

        # Detect if-statements
        if_m = re.match(r'if\s*\((.+?)\)\s*\{?\s*$', stripped)
        if if_m:
            if stripped.endswith('{'):
                # Braced if: condition valid inside the block (brace_depth+1)
                cond_stack.append((if_m.group(1).strip(), brace_depth + 1, True))
                pending_single_line = None
            else:
                # Single-line if: condition valid only for the NEXT statement
                pending_single_line = if_m.group(1).strip()

        # Detect return statements
        ret_m = re.match(r'return\s+(.+?)\s*;', stripped)
        if ret_m:
            cond = None
            if pending_single_line:
                cond = pending_single_line
                pending_single_line = None
            elif cond_stack:
                # Find innermost condition whose scope covers current depth
                for c, d, braced in reversed(cond_stack):
                    if d <= brace_depth:
                        cond = c
                        break
            results.append({
                'line': body_offset + i,
                'statement': stripped,
                'return_expr': ret_m.group(1).strip(),
                'condition': cond,
                'brace_depth': brace_depth,
            })
        elif pending_single_line and not stripped.startswith(('if', 'else')):
            pending_single_line = None

        # Count braces
        open_count = stripped.count('{')
        close_count = stripped.count('}')

        # Check for "} else {" — closing one block, opening another
        is_else_brace = bool(re.match(r'\}\s*else\s*\{', stripped))

        if is_else_brace:
            # } else { : the } closes the if-block, but the else continues
            # Pop only conditions whose opening brace depth == current depth
            # (the if-block being closed), NOT conditions at shallower depths
            new_depth = brace_depth + 1 - 1  # net 0 change
            while cond_stack and cond_stack[-1][1] == brace_depth + 1:
                cond_stack.pop()
            brace_depth = new_depth
        else:
            new_depth = brace_depth + open_count - close_count
            # Pop conditions whose scope is above the new depth
            while cond_stack and cond_stack[-1][1] > new_depth:
                cond_stack.pop()
            brace_depth = new_depth

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
        elif re.match(r'\w[\w->.\[\]]*\s*=\s*.+', stripped) and not stripped.startswith(('if', 'else', 'while', 'for')):
            kind = 'assignment'
            m = re.match(r'([\w->.\[\]]+)\s*=', stripped)
            if m:
                variables = [m.group(1)] + _extract_variables(stripped[m.end():])

        # Condition in if/while
        elif re.match(r'(if|while)\s*\(', stripped):
            kind = 'condition'
            m = re.match(r'(?:if|while)\s*\((.+?)\)\s*\{?\s*$', stripped)
            if m:
                variables = _extract_variables(m.group(1))

        # Function call: might be an assignment  ret = func(...)
        elif re.match(r'\w[\w->.\[\]]*\s*=\s*\w+\s*\(', stripped):
            kind = 'call'
            m = re.match(r'([\w->.\[\]]+)\s*=\s*(\w+)\s*\(([^)]*)\)', stripped)
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
    """Extract the body of a function from source code."""
    pattern = rf'(?:static\s+)?(?:\w+\s+)*\b{re.escape(func_name)}\s*\([^)]*\)\s*\{{'
    m = re.search(pattern, code, re.DOTALL)
    if not m:
        return None
    start = m.end() - 1
    depth = 1
    i = start + 1
    while i < len(code) and depth > 0:
        if code[i] == '{':
            depth += 1
        elif code[i] == '}':
            depth -= 1
        i += 1
    return code[start:i]


# ---------------------------------------------------------------------------
# GDB-based comparison
# ---------------------------------------------------------------------------

def run_gdb_batch(binary, commands, env=None, timeout=120):
    """Run GDB in batch mode and return stdout."""
    gdb_cmds = ["gdb", "-batch", "-ex", "set pagination off",
                "-ex", "set confirm off"]
    for cmd in commands:
        gdb_cmds.extend(["-ex", cmd])
    gdb_cmds.append(binary)
    result = subprocess.run(
        gdb_cmds, capture_output=True, text=True, timeout=timeout, env=env
    )
    return result.stdout + result.stderr


def compare_return_values(binary_a, binary_b, func_name,
                          source_a, source_b, input_file,
                          lib_path=None, timeout=120):
    """Compare return values of func_name between two versions.

    Sets a breakpoint at each return statement and compares the return value
    (via $rax register for x86-64).

    Returns: (return_line_a, return_line_b, val_a, val_b) or None
    """
    returns_a = find_return_statements(source_a, func_name)
    returns_b = find_return_statements(source_b, func_name)

    if not returns_a or not returns_b:
        return None

    env = os.environ.copy()
    env["ASAN_OPTIONS"] = "detect_leaks=0"
    if lib_path:
        old_ld = env.get("LD_LIBRARY_PATH", "")
        env["LD_LIBRARY_PATH"] = f"{lib_path}:{old_ld}" if old_ld else lib_path

    # Try each return statement in version A
    for ret_a in returns_a:
        # GDB: break at return line, run, print $rax
        cmds_a = [
            f"break {source_a}:{ret_a['line']}",
            f"run {input_file}",
            "print $rax",
        ]
        out_a = run_gdb_batch(binary_a, cmds_a, env=env, timeout=timeout)
        val_a = _parse_rax(out_a)

        # Try matching return statements in version B
        for ret_b in returns_b:
            cmds_b = [
                f"break {source_b}:{ret_b['line']}",
                f"run {input_file}",
                "print $rax",
            ]
            out_b = run_gdb_batch(binary_b, cmds_b, env=env, timeout=timeout)
            val_b = _parse_rax(out_b)

            if val_a is not None and val_b is not None and val_a != val_b:
                return {
                    'return_line_a': ret_a['line'],
                    'return_line_b': ret_b['line'],
                    'return_expr_a': ret_a['return_expr'],
                    'return_expr_b': ret_b['return_expr'],
                    'val_a': val_a,
                    'val_b': val_b,
                    'condition_a': ret_a['condition'],
                    'condition_b': ret_b['condition'],
                }

    return None


def _parse_rax(gdb_output):
    """Parse $rax value from GDB output."""
    for line in gdb_output.splitlines():
        # Look for "$1 = <value>" pattern (print $rax result)
        m = re.search(r'\$\d+\s*=\s*(.+)', line)
        if m:
            val_str = m.group(1).strip()
            # Parse hex or decimal
            try:
                if val_str.startswith('0x'):
                    return int(val_str, 16)
                elif val_str in ('0', 'NULL'):
                    return 0
                else:
                    return int(val_str)
            except ValueError:
                return val_str
    return None


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

def find_fork_by_backward_tracing(binary_a, binary_b, source_a, source_b,
                                   func_name, input_file,
                                   lib_path_a=None, lib_path_b=None,
                                   timeout=120):
    """Find the fork statement by backward tracing from function exit.

    Args:
        binary_a: Path to version A binary (target/old, e.g. 4.0.8)
        binary_b: Path to version B binary (reference/new, e.g. 4.4.0)
        source_a: Source file for version A
        source_b: Source file for version B
        func_name: The last common function (e.g. "TIFFOpen")
        input_file: Input file to run with
        lib_path_a: Library path for version A
        lib_path_b: Library path for version B
        timeout: GDB timeout in seconds

    Returns:
        dict with fork_statement, fork_variable, values, etc.
    """
    print(f"\n{'='*60}")
    print(f"Backward Tracing: {func_name}")
    print(f"{'='*60}")

    # Step 1: Compare return values
    print(f"\n[1] Comparing return values of {func_name}...")
    ret_result = compare_return_values(
        binary_a, binary_b, func_name,
        source_a, source_b, input_file,
        lib_path=lib_path_a, timeout=timeout
    )

    if ret_result:
        print(f"  Return values DIFFER:")
        print(f"    4.0.8 (A): line {ret_result['return_line_a']}, "
              f"val={ret_result['val_a']}, expr={ret_result['return_expr_a']}")
        print(f"    4.4.0 (B): line {ret_result['return_line_b']}, "
              f"val={ret_result['val_b']}, expr={ret_result['return_expr_b']}")
    else:
        print(f"  Return values MATCH or no return found")
        return {'status': 'no_return_difference'}

    # Step 2: Trace backward from return in both versions
    print(f"\n[2] Tracing dependencies backward...")
    deps_a = trace_dependenciesbackward(source_a, func_name, ret_result['return_line_a'])
    deps_b = trace_dependenciesbackward(source_b, func_name, ret_result['return_line_b'])

    print(f"  Version A: {len(deps_a)} dependencies found")
    print(f"  Version B: {len(deps_b)} dependencies found")

    # Step 3: Compare variables along dependency chain
    print(f"\n[3] Comparing dependency variables...")
    diff = compare_dependency_variables(
        binary_a, binary_b, deps_a, deps_b,
        source_a, source_b, input_file,
        lib_path=lib_path_a, timeout=timeout
    )

    if diff:
        print(f"  FIRST DIFFERENCE FOUND:")
        print(f"    Variable: {diff['variable']}")
        print(f"    4.0.8 (A): line {diff['dep_a']['line']}, "
              f"val={diff['val_a']}, stmt={diff['dep_a']['statement']}")
        print(f"    4.4.0 (B): line {diff['dep_b']['line']}, "
              f"val={diff['val_b']}, stmt={diff['dep_b']['statement']}")
        return {
            'status': 'found',
            'fork_variable': diff['variable'],
            'fork_statement_a': diff['dep_a'],
            'fork_statement_b': diff['dep_b'],
            'val_a': diff['val_a'],
            'val_b': diff['val_b'],
            'return_diff': ret_result,
        }
    else:
        print(f"  No variable difference found in dependency chain")
        return {
            'status': 'no_variable_difference',
            'return_diff': ret_result,
            'deps_a': deps_a,
            'deps_b': deps_b,
        }
