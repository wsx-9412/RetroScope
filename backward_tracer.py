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
    """Extract variable names from a C expression.

    Returns member-access chains (``tif->tif_size``) and bare identifiers,
    dropping keywords, type names, and function names (an identifier followed by
    ``(`` such as ``isMapped`` or ``TIFFReadDirEntryArray``).
    """
    if not expr:
        return []
    # Remove string/char literals and numbers
    expr = re.sub(r'"[^"]*"', '', expr)
    expr = re.sub(r"'[^']*'", '', expr)
    expr = re.sub(r'\b\d+\b', '', expr)
    # Remove function calls (identifiers followed by '(') so we keep variables
    expr = re.sub(r'\b[A-Za-z_]\w*\s*\(', '', expr)
    # Find member access chains like direntry->tdir_count / tif->tif_size
    chains = re.findall(r'\b\w+(?:->|\.)\w+\b', expr)
    # Find bare identifiers (lowercase or _-prefixed, excluding type names)
    bare = re.findall(r'\b([a-z_]\w*)\b', expr)
    keywords = {'if', 'else', 'while', 'for', 'do', 'return', 'sizeof', 'null',
                'true', 'false', 'static', 'const', 'void', 'int', 'uint8',
                'uint16', 'uint32', 'uint64', 'char', 'unsigned', 'signed',
                'long', 'short', 'float', 'double', 'struct', 'enum'}
    # Filter out type names ending in _t (uint64_t, uint32_t, size_t, ...)
    bare = [v for v in bare
            if v not in keywords and not v.endswith('_t')]
    # Drop bare identifiers already captured inside a chain
    chained = set()
    for c in chains:
        for part in re.split(r'->|\.', c):
            chained.add(part)
    bare = [v for v in bare if v not in chained]
    result = list(chains) + bare
    return result


def _find_variable_assignment(source_file, func_name, var_name):
    """Find where ``var_name`` is assigned in ``func_name``'s body.

    Returns a dict ``{line, statement}`` of the LAST assignment to the variable
    (the site whose value is the one the guard reads), or None.  A bare variable
    (``datasize``) is matched as a whole word; a member chain (``tif->tif_size``)
    is matched literally.
    """
    try:
        code = open(source_file, encoding='utf-8', errors='replace').read()
    except OSError:
        return None
    body = _extract_function_body(code, func_name)
    if not body:
        return None
    head = code[:code.find(body)] if body in code else ''
    body_offset = head.count('\n') + 1

    last = None
    for i, line in enumerate(body.splitlines()):
        stripped = line.strip()
        if not stripped or stripped.startswith(('/*', '//', '*')):
            continue
        if re.search(r'\b' + re.escape(var_name) + r'\b\s*=', stripped):
            last = {
                'line': body_offset + i,
                'statement': stripped,
            }
    return last


def _map_fork_vars_to_target(fork_variables, func_name_a, src_a):
    """Map the fork (guard) variables to the target version's read site.

    The guard lives in the *reference* (new) version, but PolyTracker must
    instrument the *target* (old) version.  For each fork variable, find where it
    is assigned in the target function (``func_name_a``) and return the
    instrumentation info.

    ``line`` is the source line *after* the assignment (the instrumentation
    helper inserts the taint-log call before that line, so the logged value is
    the freshly-computed one, not a stale pre-assignment value).

    Returns a list of ``{variable, file, line, statement}`` dicts.
    """
    sites = []
    for var in fork_variables:
        # A member chain like tif->tif_size is a struct field, not a local;
        # its taint is fixed at open time and does not map to an input byte
        # offset in a useful way, so only trace bare local variables.
        if '->' in var or '.' in var:
            continue
        site = _find_variable_assignment(src_a, func_name_a, var)
        if site:
            sites.append({
                'variable': var,
                'file': src_a,
                'line': site['line'] + 1,  # instrument AFTER the assignment
                'statement': site['statement'],
                'assignment_line': site['line'],
            })
    return sites


def _trace_to_input_variables(src_a, func_name_a, fork_line, source_dirs=None):
    """Trace the fork statement's variables backward to input-derived sources.

    Starting at the fork statement line in the target version, follow the
    dependency chain backward and collect the *member accesses* (``direntry->
    tdir_count``, ``direntry->tdir_type``, ...).  Then, for each member field,
    find the statement that actually READS it from the input file (across all
    source files), so the reported fork statement is the input-read site, not a
    derived local computation.

    Returns a list of dicts ``{field, file, line, statement}``.
    """
    if source_dirs is None:
        source_dirs = [src_a]

    deps = trace_dependenciesbackward(src_a, func_name_a, fork_line)
    member_fields = []
    seen = set()
    for dep in deps:
        for v in dep['variables']:
            if ('->' in v or '.' in v) and v not in seen:
                seen.add(v)
                # Keep just the field name (direntry->tdir_count -> tdir_count)
                field = re.split(r'->|\.', v)[-1]
                member_fields.append(field)

    results = []
    for field in member_fields:
        for file_path, line, stmt in _find_member_field_assignments(
                source_dirs, field):
            lhs = re.split(r'\s*=', stmt)[0].strip()
            results.append({
                'field': field,
                'variable': lhs,
                'file': file_path,
                'line': line,
                'statement': stmt,
            })
            break  # first (or primary) assignment is the input read
    return results


def _find_function_containing_line(source_file, line):
    """Return the name of the function whose body contains ``line``."""
    try:
        code = open(source_file, encoding='utf-8', errors='replace').read()
    except OSError:
        return None
    lines = code.split('\n')
    n = len(lines)
    _CTRL = {'if', 'while', 'for', 'switch', 'return', 'else', 'do', 'sizeof'}

    # Find function definitions: a column-0 line naming a function whose opening
    # brace follows on this or a later line.  Track brace depth to find each
    # function's extent.
    funcs = []
    i = 0
    while i < n:
        l = lines[i]
        if not l or l[0] in ' \t':  # functions are declared at column 0
            i += 1
            continue
        if '#' in l or l.rstrip().endswith(';'):
            i += 1
            continue
        # The function name is the last identifier before '(' on this line.
        m = re.search(r'(\w+)\s*\(', l)
        if not m:
            i += 1
            continue
        name = m.group(1)
        if name in _CTRL:
            i += 1
            continue
        # Find the opening brace
        j = i
        while j < n and '{' not in lines[j] and ';' not in lines[j]:
            j += 1
        if j >= n or '{' not in lines[j]:
            i += 1
            continue
        depth = 0
        k = j
        while k < n:
            depth += _count_braces_in_segment(lines[k])
            k += 1
            if depth <= 0:
                break
        funcs.append((i + 1, k, name))
        i = k
    for start, end, name in funcs:
        if start <= line <= end:
            return name
    return None


def _find_member_field_assignments(source_dirs, field_name):
    """Find statements that assign to ``->field_name`` (or ``.field_name``).

    Searches all source files and returns a list of (file, line, statement).
    The most likely *input read* is an assignment whose RHS dereferences a raw
    byte pointer (e.g. ``*(uint32*)ma``, ``TIFFReadUInt64(ma)``); those are
    ranked first.
    """
    if isinstance(source_dirs, (str, os.PathLike)):
        source_dirs = [source_dirs]
    pattern = re.compile(r'->\s*' + re.escape(field_name) + r'\s*=')

    raw = []   # reads from a raw byte pointer (the input)
    other = []  # other assignments (trimming, defaults, ...)
    for d in source_dirs:
        for ext in ('.c', '.cpp'):
            for path in Path(d).rglob(f'*{ext}'):
                try:
                    code = path.read_text(encoding='utf-8', errors='replace')
                except OSError:
                    continue
                for i, line in enumerate(code.splitlines(), 1):
                    if pattern.search(line):
                        s = line.strip()
                        entry = (str(path), i, s)
                        if re.search(r'\*\s*\(\s*\w+\s*\*\)\s*\w+|'
                                     r'TIFFReadUInt\d+|Getc|ReadOK|'
                                     r'\*\s*\w+\s*\+\+|TIFFReadShort|'
                                     r'TIFFReadLong', s):
                            raw.append(entry)
                        else:
                            other.append(entry)
    return raw + other


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

    # Prefer the main library directory over auxiliary trees.  libtiff keeps
    # duplicate function definitions under contrib/ (e.g. TIFFFetchStripThing
    # in contrib/pds/tif_pdsdirread.c) that are NOT the compiled variant, so a
    # naive rglob can pick the wrong file.
    def _rank(p):
        pl = p.lower()
        if 'contrib' in pl or 'tools' in pl or 'test' in pl or 'utils' in pl:
            return 2
        if 'libtiff' in pl:
            return 0
        return 1

    # Prefer non-win32 files on Linux (they are the compiled variant)
    if os.name != 'nt':
        matches = [p for p in matches if 'win32' not in p.lower()] or matches

    matches.sort(key=_rank)
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


def _find_added_guard(src_a, func_name_a, src_b, func_name_b):
    """Diff two function bodies and find the guard statement added in B.

    When ``func_name_a`` and ``func_name_b`` form a semantic-enhancement pair
    (e.g. ``TIFFReadDirEntryArray`` vs ``TIFFReadDirEntryArrayWithLimit``), the
    fork is the guard added in the strengthened variant.  Returns a dict with
    ``statement``, ``line`` (in B), and ``variables``, or None.
    """
    try:
        code_a = open(src_a, encoding='utf-8', errors='replace').read()
        code_b = open(src_b, encoding='utf-8', errors='replace').read()
    except OSError:
        return None
    body_a = _extract_function_body(code_a, func_name_a)
    body_b = _extract_function_body(code_b, func_name_b)
    if not body_a or not body_b:
        return None

    head_b = code_b[:code_b.find(body_b)] if body_b in code_b else ''
    body_b_offset = head_b.count('\n') + 1

    a_lines = {l.strip() for l in body_a.splitlines()}

    candidates = []
    for i, line in enumerate(body_b.splitlines()):
        s = line.strip()
        if not s or s.startswith(('/*', '//', '{', '}', '*')):
            continue
        if s in a_lines:
            continue
        if not ('if' in s or 'return' in s):
            continue
        if not ('>' in s or '<' in s or '==' in s or 'Sizesan' in s
                or 'tif_size' in s or 'datasize' in s or 'maxcount' in s
                or 'limit' in s):
            continue
        score = 0
        for kw in ('tif_size', 'maxcount', 'Sizesan', 'limit', 'datasize',
                   'filesize', 'tif->tif_size', 'nstrips'):
            if kw.lower() in s.lower():
                score += 1
        candidates.append((score, body_b_offset + i, s))

    if not candidates:
        return None
    candidates.sort(reverse=True)
    score, line, stmt = candidates[0]
    return {
        'statement': stmt,
        'line': line,
        'variables': _extract_variables(stmt),
        'score': score,
    }


def _find_assign_diff(src_a, func_name_a, src_b, func_name_b):
    """Diff two function bodies and find the first variable whose value differs.

    The "first variable whose value differs" is a variable assigned in BOTH
    versions (same LHS) but from a different source (different RHS), e.g. 4.0.8
    ``*count = (uint32)direntry->tdir_count`` vs 4.4.0
    ``*count = (uint32_t)target_count64`` (clamped).  Its assignment in the
    target (old) version is the fork statement.

    Returns a dict ``{var, line_a, statement_a, line_b, statement_b}`` or None.
    """
    try:
        code_a = open(src_a, encoding='utf-8', errors='replace').read()
        code_b = open(src_b, encoding='utf-8', errors='replace').read()
    except OSError:
        return None
    body_a = _extract_function_body(code_a, func_name_a)
    body_b = _extract_function_body(code_b, func_name_b)
    if not body_a or not body_b:
        return None

    head_a = code_a[:code_a.find(body_a)] if body_a in code_a else ''
    head_b = code_b[:code_b.find(body_b)] if body_b in code_b else ''
    offset_a = head_a.count('\n') + 1
    offset_b = head_b.count('\n') + 1

    assigns_a = {}
    assigns_b = {}
    for i, line in enumerate(body_a.splitlines()):
        m = re.match(r'(\*?\w[\w.\[\]>-]*)\s*=\s*.+', line.strip())
        if m:
            assigns_a.setdefault(m.group(1), (offset_a + i, line.strip()))
    for i, line in enumerate(body_b.splitlines()):
        m = re.match(r'(\*?\w[\w.\[\]>-]*)\s*=\s*.+', line.strip())
        if m:
            assigns_b.setdefault(m.group(1), (offset_b + i, line.strip()))

    # The first LHS (in the target's source order) whose RHS differs.
    for lhs in assigns_a:
        if lhs in assigns_b and assigns_a[lhs][1] != assigns_b[lhs][1]:
            return {
                'var': lhs,
                'line_a': assigns_a[lhs][0],
                'statement_a': assigns_a[lhs][1],
                'line_b': assigns_b[lhs][0],
                'statement_b': assigns_b[lhs][1],
            }
    return None


def _probe_callee_pair(callee, binary_a, binary_b, src_dir_a, src_dir_b,
                       input_file, run_args, lib_path_a, lib_path_b, timeout):
    """Probe ``callee`` in A and its (possibly semantic-variant) counterpart in B.

    Returns ``(callee_a, callee_b, sub_ret)`` if their return values differ, else
    None.  Handles the case where ``callee`` is defined in both versions but only
    *called* in one (a wrapper that is never invoked), by probing semantic
    variants (``...WithLimit``, ``...Checked``) in B for one that is actually
    called.
    """
    rets_a = probe_returns(binary_a, callee, input_file, run_args,
                           lib_path_a, timeout)
    if not rets_a:
        return None

    src_a = _find_function_source(callee, src_dir_a)

    # Try the direct name first, then semantic variants, in B.
    for cb in [callee] + [callee + s for s in _SEMANTIC_SUFFIXES]:
        src_b = _find_function_source(cb, src_dir_b)
        if not src_b:
            continue
        rets_b = probe_returns(binary_b, cb, input_file, run_args,
                               lib_path_b, timeout)
        if not rets_b:
            continue
        sub_ret = _diff_return_sequences(rets_a, rets_b, src_a, src_b,
                                         callee, cb)
        if sub_ret:
            return callee, cb, sub_ret
        # Return values identical — not a fork.
        return None
    return None


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
break {func_name}
run {run_args}
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

    return _diff_return_sequences(rets_a, rets_b, source_a, source_b,
                                  func_name_a, func_name_b)


def _diff_return_sequences(rets_a, rets_b, source_a, source_b,
                           func_name_a, func_name_b):
    """Compare two return-value sequences and return the first differing return.

    Returns None if the sequences are identical (in value, position by position
    up to the shorter length).
    """
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
    returns_a = find_return_statements(source_a, func_name_a)
    returns_b = find_return_statements(source_b, func_name_b)

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
    _visited = set()
    result = _find_fork_recursive(
        func_name, func_name, binary_a, binary_b, source_dir_a, source_dir_b,
        input_file, run_args, lib_path_a, lib_path_b, timeout,
        depth=0, max_depth=max_depth, chain=chain, _visited=_visited
    )
    result['chain'] = chain
    return result


def _find_fork_recursive(func_name_a, func_name_b, binary_a, binary_b,
                         src_dir_a, src_dir_b, input_file, run_args,
                         lib_path_a, lib_path_b, timeout,
                         depth, max_depth, chain, _visited=None):
    """One level of the backward tracing recursion.

    ``func_name_a`` and ``func_name_b`` may differ (a semantic rename such as
    ``TIFFReadDirEntryLong8Array`` vs ``TIFFReadDirEntryLong8ArrayWithLimit``).
    """
    indent = "  " * depth
    label = func_name_a if func_name_a == func_name_b else f"{func_name_a} vs {func_name_b}"
    print(f"\n{indent}[depth {depth}] Analyzing function: {label}")

    # 1. Find source files
    src_a = _find_function_source(func_name_a, src_dir_a)
    src_b = _find_function_source(func_name_b, src_dir_b)
    if not src_a or not src_b:
        print(f"{indent}  Source not found for {label} "
              f"(a={src_a}, b={src_b})")
        return {'status': 'source_not_found', 'func': label}

    # 2. Compare return values
    ret = compare_return_values(
        binary_a, binary_b, func_name_a, func_name_b, src_a, src_b,
        input_file, run_args, lib_path_a, lib_path_b, timeout
    )
    if not ret:
        print(f"{indent}  Return values equal — scanning libtiff sources for divergence")
        # Entry function returns the same value, but a deeper function may
        # have been renamed (semantic pair) with different behavior.
        import re as _re
        all_defs_a = set()
        all_defs_b = set()
        for sub in ['libtiff', '']:
            for d, out_set in [(src_dir_a, all_defs_a), (src_dir_b, all_defs_b)]:
                if not d:
                    continue
                search_dir = Path(d) / sub if sub else Path(d)
                if not search_dir.is_dir():
                    continue
                for p in search_dir.glob('*.c'):
                    try:
                        txt = p.read_text(encoding='utf-8', errors='replace')
                    except OSError:
                        continue
                    out_set.update(_re.findall(r'\b(\w+)\s*\(', txt))
        # Find semantic pairs: functions in B that are A + suffix.
        # Skip pairs we've already visited to avoid infinite loops.
        _visited.add(func_name_a)
        _visited.add(func_name_b)
        for name_b in sorted(all_defs_b):
            for suf in _SEMANTIC_SUFFIXES:
                if name_b.endswith(suf):
                    base = name_b[:-len(suf)]
                    if base in all_defs_a and base not in _visited and name_b not in _visited:
                        src_base = _find_function_source(base, src_dir_a)
                        src_variant = _find_function_source(name_b, src_dir_b)
                        if src_base and src_variant:
                            print(f"{indent}  Found semantic pair: "
                                  f"{base} vs {name_b}; recursing")
                            return _find_fork_recursive(
                                base, name_b, binary_a, binary_b,
                                src_dir_a, src_dir_b,
                                input_file, run_args,
                                lib_path_a, lib_path_b,
                                timeout, depth + 1, max_depth, chain,
                                _visited=_visited
                            )
        print(f"{indent}  No divergence found at this level")
        return {'status': 'no_return_difference', 'func': label}

    print(f"{indent}  Return values DIFFER:")
    print(f"{indent}    A (old): line {ret['return_line_a']}, val={ret['val_a']:#x}")
    print(f"{indent}    B (new): line {ret['return_line_b']}, val={ret['val_b']:#x}")

    chain.append({
        'func': label,
        'val_a': ret['val_a'],
        'val_b': ret['val_b'],
        'return_line_a': ret['return_line_a'],
        'return_line_b': ret['return_line_b'],
    })

    # 3. Collect candidate callees that may determine the return value.
    candidates = []
    returns_a = find_return_statements(src_a, func_name_a)
    for r in returns_a:
        if r.get('condition'):
            candidates.extend(_extract_calls_from_expression(r['condition']))

    deps_a = trace_dependenciesbackward(src_a, func_name_a, ret['return_line_a'])
    for dep in deps_a:
        if dep['kind'] in ('call', 'assignment'):
            c = _extract_callee(dep['statement'])
            if c:
                candidates.append(c)

    for callee, line, stmt in _extract_checked_calls(src_a, func_name_a):
        candidates.append(callee)

    for callee, line, stmt in _extract_assign_calls(src_a, func_name_a):
        candidates.append(callee)

    # 3b. If this is a semantic pair (different names), diff the bodies:
    #     (a) if the added statement is a call to a semantic variant, recurse
    #         into that pair (the guard is one level deeper);
    #     (b) find an added guard — the statement that directly causes the
    #         behavioral divergence (prioritized over upstream variable diffs);
    #     (c) find the FIRST variable whose value differs (same LHS, different
    #         RHS) — its assignment in the target is the fork statement.
    if func_name_a != func_name_b:
        diff = _find_assign_diff(src_a, func_name_a, src_b, func_name_b)
        if diff:
            # If the differing assignment is just a call to a *semantic variant*
            # (X(...) vs XWithLimit(...)), the real fork is one level deeper —
            # recurse into that pair instead of reporting the call itself.
            callee_a = _extract_callee(diff['statement_a'])
            callee_b = _extract_callee(diff['statement_b'])
            recurse_pair = None
            if callee_a and callee_b:
                for suf in _SEMANTIC_SUFFIXES:
                    if callee_b.endswith(suf) and callee_b[:-len(suf)] == callee_a:
                        recurse_pair = (callee_a, callee_b)
                        break
                    if callee_a.endswith(suf) and callee_a[:-len(suf)] == callee_b:
                        recurse_pair = (callee_b, callee_a)
                        break
            if recurse_pair:
                base, variant = recurse_pair
                if _find_function_source(variant, src_dir_b) or \
                        _find_function_source(variant, src_dir_a):
                    print(f"{indent}  Assignment differs by semantic variant "
                          f"call {base} vs {variant}; recursing")
                    return _find_fork_recursive(
                        base, variant, binary_a, binary_b, src_dir_a, src_dir_b,
                        input_file, run_args, lib_path_a, lib_path_b,
                        timeout, depth + 1, max_depth, chain
                    )

        # Check for added guard — it indicates behavioral divergence.
        guard = _find_added_guard(src_a, func_name_a, src_b, func_name_b)
        if guard:
            stmt = guard['statement']
            calls = _extract_calls_from_expression(stmt)
            for c in calls:
                # Is this call itself a semantic variant of a function in A?
                for suf in _SEMANTIC_SUFFIXES:
                    if c.endswith(suf):
                        base = c[:-len(suf)]
                        if _find_function_source(base, src_dir_a):
                            print(f"{indent}  Added statement calls semantic "
                                  f"variant {c}; recursing into pair")
                            return _find_fork_recursive(
                                base, c, binary_a, binary_b, src_dir_a, src_dir_b,
                                input_file, run_args, lib_path_a, lib_path_b,
                                timeout, depth + 1, max_depth, chain
                            )
            print(f"{indent}  Added guard in B: '{stmt}' "
                  f"(line {guard['line']})")

        # The fork statement is the one that exists in BOTH versions but
        # produces different values (the assign_diff).  The guard is the
        # *consequence* of that difference, not the root cause.
        if diff:
            fork_statement = diff['statement_a']
            fork_line = diff['line_a']
            fork_variables = _extract_variables(fork_statement)
            input_variables = [v for v in fork_variables if '->' in v or '.' in v]
            print(f"{indent}  First differing variable: '{diff['var']}' "
                  f"(A: '{diff['statement_a']}' vs B: '{diff['statement_b']}')")
            print(f"{indent}  Fork statement (target {func_name_a}): "
                  f"'{fork_statement}' (line {fork_line})")
            print(f"{indent}  Input-derived variables: {input_variables}")
            return {
                'status': 'found',
                'func': label,
                'func_a': func_name_a,
                'func_b': func_name_b,
                'file_a': src_a,
                'file_b': src_b,
                'fork_statement': fork_statement,
                'fork_line': fork_line,
                'fork_variables': fork_variables,
                'input_variables': input_variables,
                'assign_diff': diff,
                'guard': guard,
                'return_diff': ret,
            }

        # No assign_diff found but guard exists — the guard itself is the
        # only source-level difference; report it as fork statement.
        if guard:
            return {
                'status': 'found',
                'func': label,
                'func_a': func_name_a,
                'func_b': func_name_b,
                'file_a': src_a,
                'file_b': src_b,
                'fork_statement': guard['statement'],
                'fork_line': guard['line'],
                'fork_variables': guard['variables'],
                'guard': guard,
                'return_diff': ret,
            }

    # 3c. Same-name functions: check if B is a wrapper calling a semantic
    #     variant of A (e.g. TIFFReadDirEntryArray -> TIFFReadDirEntryArrayWithLimit).
    if func_name_a == func_name_b and src_b:
        try:
            code_b = open(src_b, encoding='utf-8', errors='replace').read()
        except OSError:
            code_b = None
        if code_b:
            body_b = _extract_function_body(code_b, func_name_b)
            if body_b:
                for c in _extract_calls_from_expression(body_b):
                    for suf in _SEMANTIC_SUFFIXES:
                        if c.endswith(suf):
                            base = c[:-len(suf)]
                            if base == func_name_a:
                                variant_src = _find_function_source(c, src_dir_b)
                                if variant_src:
                                    print(f"{indent}  Same-name wrapper: B calls "
                                          f"semantic variant {c}; recursing")
                                    return _find_fork_recursive(
                                        func_name_a, c, binary_a, binary_b,
                                        src_dir_a, src_dir_b,
                                        input_file, run_args, lib_path_a, lib_path_b,
                                        timeout, depth + 1, max_depth, chain
                                    )

    _UTILITY_CALLEES = {
        '_TIFFmalloc', '_TIFFrealloc', '_TIFFfree', '_TIFFmemcpy',
        '_TIFFmemset', '_TIFFCheckMalloc', '_TIFFCheckRealloc',
        'malloc', 'realloc', 'free', 'memcpy', 'memset', 'memmove',
        'strerror', 'strlcpy', 'strncpy', 'strlen',
    }
    seen = set()
    unique_candidates = []
    for c in candidates:
        if c and c != func_name_a and c not in seen and c not in _UTILITY_CALLEES:
            seen.add(c)
            unique_candidates.append(c)

    print(f"{indent}  Candidate callees ({len(unique_candidates)}): "
          f"{unique_candidates[:15]}{'...' if len(unique_candidates) > 15 else ''}")

    # 4. For each candidate, check if its return value also differs.
    if depth < max_depth:
        primary = []    # same-length value differences (genuine fork)
        secondary = []  # length differences (early-abort consequence)
        for callee in unique_candidates:
            probed = _probe_callee_pair(
                callee, binary_a, binary_b, src_dir_a, src_dir_b,
                input_file, run_args, lib_path_a, lib_path_b, timeout
            )
            if not probed:
                continue
            ca, cb, sub_ret = probed
            if sub_ret.get('diff_kind') == 'same_len_diff_value':
                primary.append((ca, cb, sub_ret))
            else:
                secondary.append((ca, cb, sub_ret))

        # Among primaries, prefer callees that have a semantic variant in the
        # other version (e.g. TIFFReadDirEntryArray vs WithLimit) — these are
        # more likely to contain the actual guard.
        def _has_semantic_variant(callee_name):
            for suf in _SEMANTIC_SUFFIXES:
                variant = callee_name + suf
                if _find_function_source(variant, src_dir_b):
                    return True
                if callee_name.endswith(suf):
                    base = callee_name[:-len(suf)]
                    if _find_function_source(base, src_dir_b):
                        return True
            return False

        def _calls_semantic_variant(callee_name):
            """Check if callee transitively calls a function with a semantic variant."""
            callee_src = _find_function_source(callee_name, src_dir_a)
            if not callee_src:
                return False
            try:
                code = open(callee_src, encoding='utf-8', errors='replace').read()
            except OSError:
                return False
            body = _extract_function_body(code, callee_name)
            if not body:
                return False
            for c in _extract_calls_from_expression(body):
                if _has_semantic_variant(c):
                    return True
            return False

        if primary and len(primary) > 1:
            primary.sort(key=lambda x: (
                0 if _has_semantic_variant(x[0]) else
                1 if _calls_semantic_variant(x[0]) else 2
            ))

        chosen = None
        if primary:
            chosen = primary[0]
        elif secondary:
            chosen = secondary[0]

        if chosen:
            ca, cb, sub_ret = chosen
            # Before recursing into a callee, check if there's an added guard
            # between this function pair.  If both a guard and an assign_diff
            # exist, the assign_diff (the common statement that differs) is
            # the fork statement; the guard is the consequence.
            if func_name_a != func_name_b:
                guard_here = _find_added_guard(
                    src_a, func_name_a, src_b, func_name_b)
                diff_here = _find_assign_diff(
                    src_a, func_name_a, src_b, func_name_b)
                if guard_here:
                    stmt = guard_here['statement']
                    calls_in_guard = _extract_calls_from_expression(stmt)
                    for gc in calls_in_guard:
                        for suf in _SEMANTIC_SUFFIXES:
                            if gc.endswith(suf):
                                gbase = gc[:-len(suf)]
                                if _find_function_source(gbase, src_dir_a):
                                    return _find_fork_recursive(
                                        gbase, gc, binary_a, binary_b,
                                        src_dir_a, src_dir_b,
                                        input_file, run_args,
                                        lib_path_a, lib_path_b,
                                        timeout, depth + 1, max_depth, chain
                                    )
                    print(f"{indent}  Added guard (before callee recurse): "
                          f"'{stmt}' (line {guard_here['line']})")
                    if diff_here:
                        # Report the assign_diff as fork (exists in both
                        # versions); keep the guard as context.
                        fork_statement = diff_here['statement_a']
                        fork_line = diff_here['line_a']
                        fork_variables = _extract_variables(fork_statement)
                        input_variables = [
                            v for v in fork_variables
                            if '->' in v or '.' in v]
                        print(f"{indent}  Fork statement (assign_diff): "
                              f"'{fork_statement}' (line {fork_line})")
                        return {
                            'status': 'found',
                            'func': label,
                            'func_a': func_name_a,
                            'func_b': func_name_b,
                            'file_a': src_a,
                            'file_b': src_b,
                            'fork_statement': fork_statement,
                            'fork_line': fork_line,
                            'fork_variables': fork_variables,
                            'input_variables': input_variables,
                            'assign_diff': diff_here,
                            'guard': guard_here,
                            'return_diff': ret,
                        }
                    return {
                        'status': 'found',
                        'func': label,
                        'func_a': func_name_a,
                        'func_b': func_name_b,
                        'file_a': src_a,
                        'file_b': src_b,
                        'fork_statement': stmt,
                        'fork_line': guard_here['line'],
                        'fork_variables': guard_here['variables'],
                        'guard': guard_here,
                        'return_diff': ret,
                    }
            print(f"{indent}  -> {ca} return differs ({sub_ret.get('diff_kind')}); "
                  f"recursing")
            return _find_fork_recursive(
                ca, cb, binary_a, binary_b, src_dir_a, src_dir_b,
                input_file, run_args, lib_path_a, lib_path_b, timeout,
                depth + 1, max_depth, chain
            )

    # 5. No callee with a differing return value: the fork is here.
    fork_dep = None
    for dep in deps_a:
        if dep['kind'] == 'condition':
            fork_dep = dep
            break
    if not fork_dep and deps_a:
        fork_dep = deps_a[0]

    print(f"{indent}  FORK at {label}: "
          f"{fork_dep['statement'].strip() if fork_dep else '?'}")
    return {
        'status': 'found',
        'func': label,
        'fork_statement': fork_dep['statement'] if fork_dep else None,
        'fork_line': fork_dep['line'] if fork_dep else None,
        'fork_variables': fork_dep['variables'] if fork_dep else [],
        'return_diff': ret,
        'deps_a': deps_a,
    }
