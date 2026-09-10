#!/usr/bin/env python3
"""decision_trace.py — M1: dynamic decision-event recorder (generic).

For ONE binary and ONE source function, this runs the program under GDB and
records every *decision event* inside that function:

    * which conditional (if/else-if/while/for/switch/do-while) was evaluated,
    * the condition text,
    * the runtime values of the condition's comparison operands (the guard's
      inputs), and the computed outcome where the operands are side-effect-free
      scalars.

Only decision events are recorded — plain statements, assignments and ordinary
calls are ignored.  This is the key property that makes the trace robust to
statement-level drift between two versions: extra/missing/renumbered statements
never produce events, while added guards (e.g. a sanity check present in one
version only) produce *unmatched* events that downstream alignment (M2) treats
as a code-change fork.

Modes of operation
------------------
* Breakpoint mode (default): one breakpoint per decision line; the gdb python
  stub evaluates the clauses at each hit.  Fast — O(events).
* The function body and its decision lines are located statically in the
  version's own source tree (``find_function_line`` /
  ``find_function_body_range``); conditions spanning several lines are handled
  by paren-balance scanning.

No project-specific knowledge is used.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from trace_fork_offsets import (find_function_body_range, find_function_line,
                                is_function_definition, resolve_binary)

# --------------------------------------------------------------------------
# Condition parsing (static, generic)
# --------------------------------------------------------------------------

_SIMPLE_OPS = re.compile(r'(?<![=!<>-])\s*(==|!=|<=|>=|<|>)\s*(?!=)')
_RISKY_TOKENS = re.compile(r'[+]{2}|--|(?<![=!<>])=[^=]|\?|\(\)|\([^)]*\)')
_DECISION_START = re.compile(
    r'^\s*(?:}\s*else\s+if|else\s+if|if|else\s+while|while|for|switch|do)\s*\(')
_DECISION_START2 = re.compile(r'^\s*}\s*(?:while|else\s+if|else)\b')


def _balanced_parens(text, start):
    """Find the index just past the matching ')' for the '(' at text[start]."""
    depth = 0
    for i in range(start, len(text)):
        c = text[i]
        if c == '(':
            depth += 1
        elif c == ')':
            depth -= 1
            if depth == 0:
                return i + 1
    return None


def _extract_condition(text, start):
    """Extract the condition between the '(' at ``start`` and its match."""
    end = _balanced_parens(text, start)
    if end is None:
        return None
    return text[start + 1:end - 1].strip()


def _locate_function_source(func, source_root, binary=None):
    """Find the source file defining ``func`` under ``source_root``.

    When several files define the same name (e.g. libtiff's TIFFFetchStripThing
    and contrib/pds' copy), prefer the file under the project's main library
    directory (heuristically: a path containing ``libtiff``/``lib``), then the
    shortest path.
    """
    if not source_root:
        return None
    candidates = []
    for f in Path(source_root).rglob('*.c'):
        if is_function_definition(str(f), func):
            candidates.append(f)
    if not candidates:
        return None
    if len(candidates) == 1:
        return str(candidates[0])
    lib = [c for c in candidates if '/libtiff/' in c.as_posix()]
    if lib:
        return str(lib[0])
    return str(min(candidates, key=lambda c: len(c.parts)))


def _normalize_operand(expr):
    """Strip leading type casts / outer parens so an operand can be evaluated.

    ``(uint64_t)tif->tif_size`` -> ``tif->tif_size``; ``(x)`` -> ``x``.
    """
    e = (expr or '').strip()
    while True:
        m = re.match(r'^\(\s*(?:const\s+)?(?:unsigned\s+|signed\s+|long\s+|short\s+|int\s+|char\s+|float\s+|double\s+|size_t\s+|int64_t\s+|uint64_t\s+|int32_t\s+|uint32_t\s+|int16_t\s+|uint16_t\s+|int8_t\s+|uint8_t\s+|void\s+)*[\w\s_*]*\)\s*(.*)$', e, re.S)
        if m and m.group(1) != e:
            e = m.group(1).strip()
            continue
        if e.startswith('(') and e.endswith(')') and '(' not in e[1:-1]:
            e = e[1:-1].strip()
            continue
        break
    return e


def parse_condition_clauses(cond):
    """Split a C condition into top-level comparison clauses.

    ``(a < b) && !(c >= d)`` -> [("a","<","b"), ("c",">=","d")] with negation
    propagated into the clause.  Returns a list of dicts:
    ``{lhs, op, rhs, negated}``.  Expressions that are not simple scalar
    comparisons (e.g. containing function calls) are still returned with
    ``op=None`` so the recorder can log their text without evaluating them.
    """
    clauses = []
    text = cond.strip()
    negate = False
    # Split top-level && / || (| is rare in conditions; keep || only).
    parts = re.split(r'\s*(\|\||&&)\s*', text)
    for part in parts:
        if part in ('&&', '||'):
            continue
        part = part.strip()
        if not part:
            continue
        neg = negate
        negate = False
        # Unary ! on the whole clause.
        while part.startswith('!'):
            neg = not neg
            part = part[1:].strip()
        if part.startswith('(') and part.endswith(')'):
            inner = part[1:-1].strip()
            if '(' not in inner and ')' not in inner:
                part = inner
        m = _SIMPLE_OPS.search(part)
        if m:
            lhs = _normalize_operand(part[:m.start()])
            rhs = _normalize_operand(part[m.end():])
            if _RISKY_TOKENS.search(lhs) or _RISKY_TOKENS.search(rhs):
                op = None
            else:
                op = m.group(1)
            clauses.append({'lhs': lhs, 'op': op, 'rhs': rhs, 'negated': neg})
        else:
            # No comparison operator: bare boolean / function call.
            clauses.append({'lhs': part, 'op': None, 'rhs': '', 'negated': neg})
    return clauses


def _function_body(source_file, func_name):
    """Return (start, end, lines) of func_name's body, or None.

    Robust variant of find_function_body_range: ALL definition-like lines are
    brace-matched, and the LONGEST valid span is chosen.  The backward
    signature scan fails for ``main`` (the previous function's signature is
    found instead), yielding a tiny/empty body — the longest-span rule fixes
    that without any project-specific knowledge.
    """
    try:
        lines = Path(source_file).read_text(errors='replace').splitlines()
    except Exception:
        return None
    n = len(lines)
    pat = re.compile(
        r'^(?:(?:static|inline|extern)\s+)?(?:[\w\s\*]+?\s+)?'
        + re.escape(func_name) + r'\s*\(')
    candidates = []
    for i, raw in enumerate(lines):
        stripped = raw.strip()
        if not stripped or stripped.startswith(('#', '//', '/*', '*')):
            continue
        if stripped.endswith(';'):
            continue  # forward declaration
        if pat.match(stripped):
            candidates.append(i)
    best = None
    for i in candidates:
        brace = None
        for j in range(i, min(i + 30, n)):
            if '{' in lines[j]:
                brace = j
                break
        if brace is None:
            continue
        depth = 0
        end = None
        for j in range(brace, n):
            depth += lines[j].count('{') - lines[j].count('}')
            if depth == 0:
                end = j
                break
        if end is None:
            continue
        span = end - i
        if best is None or span > best[0]:
            best = (span, brace + 1, end + 1)
    if best is None:
        return None
    return best[1], best[2], lines


_SKIP_CALL_TOKENS = {
    'if', 'for', 'while', 'switch', 'sizeof', 'return', 'goto', 'do',
    'assert', 'min', 'max', 'abs', 'static_cast', 'reinterpret_cast',
    'dynamic_cast', 'const_cast', 'defined', 'typeof', '__typeof__',
    'NULL', 'true', 'false', 'malloc', 'free', 'realloc', 'calloc',
    'memset', 'memcpy', 'memmove', 'strlen', 'strcmp', 'printf',
    'fprintf', 'sprintf', 'snprintf', 'exit', 'abort',
}


def find_call_sites(source_file, func_name):
    """Map function-body lines to the callee names they call (static, best-effort).

    Returns ``{line: [callee, ...]}``.  Used to (a) confirm which callees a
    divergent invocation actually executed and (b) drive the recursive descent
    into callees whose behavior diverges.
    """
    fb = _function_body(source_file, func_name)
    if not fb:
        return {}
    start, end, lines = fb
    call_lines = {}
    for i in range(start - 1, end):
        raw = lines[i]
        stripped = raw.strip()
        if not stripped or stripped.startswith(('#', '//', '/*', '*')):
            continue
        names = []
        for m in re.finditer(r'\b([A-Za-z_]\w*)\s*\(', stripped):
            name = m.group(1)
            if name in _SKIP_CALL_TOKENS:
                continue
            # Skip obvious macros / type names used in casts: the token must
            # be followed by something that is not a type keyword pattern.
            prev = stripped[max(0, m.start() - 8):m.start()]
            if re.search(r'(typedef|#define|\b(?:int|char|void|long|short|float|double|unsigned|signed|struct|union|enum|const|static|inline|uint\d+_t|int\d+_t|size_t)\s*$)', prev):
                continue
            names.append(name)
        if names:
            call_lines[i + 1] = list(dict.fromkeys(names))
    return call_lines


def find_return_lines(source_file, func_name):
    """Lines of func_name's body containing a return statement."""
    fb = _function_body(source_file, func_name)
    if not fb:
        return set()
    start, end, lines = fb
    ret = set()
    for i in range(start - 1, end):
        stripped = lines[i].strip()
        if stripped.startswith('return') or re.search(r'\breturn\s*;', stripped):
            ret.add(i + 1)
    return ret


def find_function_decisions(source_file, func_name):
    """Locate all decision lines inside ``func_name`` in ``source_file``.

    Returns a list of ``{line, text, clauses}``.  Conditions spanning several
    lines are folded into the start line's text via paren balancing.
    """
    fb = _function_body(source_file, func_name)
    if not fb:
        return []
    start, end, lines = fb
    decisions = []
    seen = set()
    for i in range(start - 1, end):
        raw = lines[i]
        stripped = raw.strip()
        if not stripped:
            continue
        if stripped.startswith(('#', '//', '/*', '*')):
            continue
        m = _DECISION_START.match(stripped) or _DECISION_START2.match(stripped)
        if not m:
            continue
        if stripped.endswith(';'):
            # e.g. `} while (...);` — still a decision; keep it.
            pass
        # Locate the first '(' of the condition.
        open_idx = stripped.find('(')
        if open_idx < 0:
            continue
        # Fold in continuation lines until the parens balance.
        text = stripped
        line_no = i + 1
        idx = line_no - 1
        bal = text.count('(') - text.count(')')
        while bal > 0 and idx + 1 < end:
            idx += 1
            nxt = lines[idx]
            text += ' ' + nxt.strip()
            bal += nxt.count('(') - nxt.count(')')
        cond = _extract_condition(text, text.find('('))
        if cond is None:
            continue
        clauses = parse_condition_clauses(cond)
        key = (line_no, cond)
        if key in seen:
            continue
        seen.add(key)
        decisions.append({'line': line_no, 'text': cond, 'clauses': clauses})
    return decisions


# --------------------------------------------------------------------------
# GDB embedded script
# --------------------------------------------------------------------------

_GDB_TEMPLATE = r'''
import json
import re

config = json.loads("""__CONFIG__""")
gdb.execute("set pagination off")
gdb.execute("set confirm off")
gdb.execute("set breakpoint pending on")
for d in config["dirs"]:
    try:
        gdb.execute(f"directory {d}")
    except Exception:
        pass

MAX_EVENTS = config.get("max_events", 100000)
MODE = config.get("mode", "bp")          # "bp" (breakpoint, fast) or "step"
decision_lines = set(d["line"] for d in config["decisions"])
clauses_by_line = config["clauses_by_line"]
call_lines = config.get("call_lines", {})       # str(line) -> [callee...]
return_lines = set(config.get("return_lines", []))
RET_RE = re.compile(r'Value returned is \$(\d+)\s*=\s*(.+)')
S = {"order": 0, "inv": 0, "created": False}

def eval_clauses(line):
    clauses = {}
    for ci, cl in enumerate(clauses_by_line.get(str(line), [])):
        vals = {}
        for side in ("lhs", "rhs"):
            expr = cl.get(side, "")
            if not expr or cl.get("op") is None:
                continue
            try:
                v = gdb.parse_and_eval(expr)
                vals[side] = int(v)
            except Exception:
                vals[side] = None
        if vals:
            clauses[str(ci)] = vals
    return clauses

def in_func():
    try:
        return gdb.newest_frame().name() == config["func"]
    except Exception:
        return False

class LineBP(gdb.Breakpoint):
    def __init__(self, spec, line):
        super(LineBP, self).__init__(spec, internal=False)
        self.line = line
    def stop(self):
        if not in_func():
            return False
        if S["order"] >= MAX_EVENTS:
            return False
        if self.line in decision_lines:
            S["order"] += 1
            clauses = eval_clauses(self.line)
            gdb.write("##EVT %d %d %d %s\n"
                      % (S["order"], S["inv"], self.line, json.dumps(clauses)))
        callees = call_lines.get(str(self.line))
        if callees:
            gdb.write("##CALL %d %d %s\n"
                      % (S["inv"], self.line, json.dumps(callees)))
        return False

class EntryBP(gdb.Breakpoint):
    def __init__(self, spec):
        super(EntryBP, self).__init__(spec, internal=False)
    def stop(self):
        if not in_func():
            return False
        S["inv"] += 1
        gdb.write("##ENTER %d\n" % S["inv"])
        if not S["created"]:
            S["created"] = True
            # Line breakpoints can only resolve now (the shared library is
            # loaded and its symtab is in scope); absolute paths avoid the
            # basename matching problem of pending file:line breakpoints.
            for ln in sorted(set(decision_lines) |
                             {int(k) for k in call_lines}):
                try:
                    LineBP("%s:%d" % (config["file"], ln), ln)
                except Exception as e:
                    gdb.write("##BPFAIL %d %s\n" % (ln, str(e)))
        return False

gdb.write("##READY\n")
try:
    EntryBP(config["func"])
except Exception as e:
    gdb.write("##BPFAIL 0 %s\n" % str(e))
gdb.execute("run " + config["runargs"])
gdb.write("##TOTAL %d\n" % S["order"])
gdb.write("##INVTOTAL %d\n" % S["inv"])
'''


_STEP_TEMPLATE = r'''
import json
import re

config = json.loads("""__CONFIG__""")
gdb.execute("set pagination off")
gdb.execute("set confirm off")
gdb.execute("set breakpoint pending on")
for d in config["dirs"]:
    try:
        gdb.execute(f"directory {d}")
    except Exception:
        pass

MAX_STEPS = config.get("max_steps", 200000)
MAX_EVENTS = config.get("max_events", 100000)
decision_lines = set(d["line"] for d in config["decisions"])
clauses_by_line = config["clauses_by_line"]
call_lines = config.get("call_lines", {})       # str(line) -> [callee...]
return_lines = set(config.get("return_lines", []))
RET_RE = re.compile(r'Value returned is \$(\d+)\s*=\s*(.+)')

# NOTE: stepping happens at TOP-LEVEL python (run -> continue -> next loop).
# Running gdb.execute("next") inside a Breakpoint.stop() callback raises
# "Cannot execute this command while the selected thread is running" on
# gdb 12, so no stop() callback is used here.

def eval_clauses(line):
    clauses = {}
    for ci, cl in enumerate(clauses_by_line.get(str(line), [])):
        vals = {}
        for side in ("lhs", "rhs"):
            expr = cl.get(side, "")
            if not expr or cl.get("op") is None:
                continue
            try:
                v = gdb.parse_and_eval(expr)
                vals[side] = int(v)
            except Exception:
                vals[side] = None
        if vals:
            clauses[str(ci)] = vals
    return clauses

gdb.write("##READY\n")
try:
    gdb.Breakpoint(config["func"], internal=False)
except Exception as e:
    gdb.write("##BPFAIL %s\n" % str(e))

order = 0
inv = 0
first = True
while True:
    try:
        if first:
            gdb.execute("run " + config["runargs"])
            first = False
        else:
            gdb.execute("continue")
    except gdb.error as e:
        gdb.write("##END %s\n" % str(e))
        break
    try:
        frame = gdb.newest_frame()
        fn = frame.name()
    except gdb.error:
        gdb.write("##END noframe\n")
        break
    if fn != config["func"]:
        gdb.write("##STOPOTHER %s\n" % str(fn))
        continue
    inv += 1
    gdb.write("##ENTER %d\n" % inv)
    steps = 0
    while steps < MAX_STEPS:
        try:
            frame = gdb.newest_frame()
            fn = frame.name()
        except gdb.error:
            break
        if fn != config["func"]:
            try:
                rv = gdb.parse_and_eval("$rax")
                gdb.write("##RET %d %s\n" % (inv, str(rv)))
            except Exception:
                gdb.write("##RET %d ?\n" % inv)
            break
        try:
            line = frame.find_sal().line
        except Exception:
            line = 0
        if line in decision_lines and order < MAX_EVENTS:
            order += 1
            clauses = eval_clauses(line)
            gdb.write("##EVT %d %d %d %s\n" % (order, inv, line, json.dumps(clauses)))
        callees = call_lines.get(str(line))
        if callees:
            gdb.write("##CALL %d %d %s\n"
                      % (inv, line, json.dumps(callees)))
        if line in return_lines:
            try:
                text = gdb.execute("finish", to_string=True)
                m = RET_RE.search(text)
                if m:
                    gdb.write("##RET %d %s\n" % (inv, m.group(2).strip()))
                else:
                    gdb.write("##RET %d ?\n" % inv)
            except gdb.error as e:
                gdb.write("##RET %d ?\n" % inv)
            break
        try:
            gdb.execute("next", to_string=True)
        except gdb.error:
            break
        steps += 1
    gdb.write("##STEPOUT %d %d\n" % (steps, order))
gdb.write("##TOTAL %d\n" % order)
gdb.write("##INVTOTAL %d\n" % inv)
'''


def _build_gdb_script(config):
    # The JSON is a valid Python literal; splice it directly into the template
    # (avoids argv quoting problems — gdb does not shell-parse -ex arguments).
    # Backslashes must be doubled: inside the triple-quoted python literal the
    # string parser consumes one level of escaping, which would corrupt the
    # JSON (e.g. \" inside condition texts).
    template = _STEP_TEMPLATE if config.get("mode") == "step" else _GDB_TEMPLATE
    return template.replace('__CONFIG__', json.dumps(config).replace('\\', '\\\\'))


# --------------------------------------------------------------------------
# Runner
# --------------------------------------------------------------------------

def _collect_lib_paths(binary):
    """Collect every ``.libs`` directory near the version root so the run
    resolves the *version's own* shared libraries (a naive parent-only walk
    silently falls back to system libraries — with completely different
    behavior)."""
    dirs = []
    seen = set()
    bin_path = Path(binary).resolve()
    for parent in [bin_path.parent] + list(bin_path.parents[:6]):
        libs = parent / ".libs"
        if libs.is_dir() and str(libs) not in seen:
            seen.add(str(libs))
            dirs.append(str(libs))
        # Found the version root: sweep ALL of its .libs dirs (a library may
        # live in libtiff/.libs, src/.libs, ... — not just the binary's own).
        if (parent / "configure").exists():
            for d in parent.rglob(".libs"):
                if d.is_dir() and str(d) not in seen:
                    seen.add(str(d))
                    dirs.append(str(d))
            break
    return dirs


def _gdb_main_source(binary, source_root):
    """Ask GDB which source file contains the *executed* ``main``.

    ``main`` is defined in many files of a source tree (e.g. tiffcrop.c vs
    libtiff/mkg3states.c); the static search may pick the wrong one.  Running
    ``gdb start`` stops at the real entry point and ``info source`` reports
    its file — precise and generic.
    """
    try:
        cmd = ['gdb', '-batch', '-q', '-ex', 'start', '-ex', 'info source',
               '--args', str(resolve_binary(binary))]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    except Exception:
        return None
    m = re.search(r'Current source file is (.+)', r.stdout + r.stderr)
    if not m:
        return None
    path = m.group(1).strip()
    if os.path.isabs(path) and Path(path).exists():
        return path
    candidate = Path(source_root or '.') / path
    if candidate.exists():
        return str(candidate)
    for f in Path(source_root or '.').rglob(Path(path).name):
        return str(f)
    return None


def record_decisions(binary, func, args, source_root=None, timeout=180,
                     out_path=None, limit=100000, mode='bp'):
    """Run ``binary args`` under GDB and record the decision events of ``func``.

    ``mode``: 'bp' (breakpoints on decision/call lines — fast, default) or
    'step' (top-level stepping — slower but captures return values).

    Returns a dict: ``{func, file, binary, run_args, decision_lines,
    events, invocations, stats}`` or None when the function could not be
    located in the sources.
    """
    real_bin = resolve_binary(binary)
    fsrc = _locate_function_source(func, source_root or str(Path(real_bin).parent),
                                   binary=real_bin)
    if not fsrc:
        print(f'  [!] source for {func} not found under {source_root or real_bin}')
        return None
    if func == 'main':
        msrc = _gdb_main_source(real_bin, source_root)
        if msrc:
            fsrc = msrc
    decisions = find_function_decisions(fsrc, func)
    if not decisions:
        print(f'  [!] no decision lines found for {func} in {fsrc}')
        return None

    clauses_by_line = {}
    for d in decisions:
        clauses_by_line[str(d["line"])] = d["clauses"]

    config = {
        "func": func,
        "file": str(fsrc),  # absolute path: gdb resolves file:line against
                            # the debug info's full path; basename-only specs
                            # stay pending forever when sources are relocated.
        "dirs": [str(Path(fsrc).parent), source_root or ""],
        "runargs": " ".join(str(a) for a in args),
        "decisions": decisions,
        "clauses_by_line": clauses_by_line,
        "call_lines": {str(k): v for k, v in find_call_sites(fsrc, func).items()},
        "return_lines": sorted(find_return_lines(fsrc, func)),
        "mode": mode,
        "max_steps": 200000,
        "max_events": 100000,
    }

    with tempfile.NamedTemporaryFile('w', suffix='.py', delete=False) as tf:
        tf.write(_build_gdb_script(config))
        script = tf.name

    env = os.environ.copy()
    env.setdefault('ASAN_OPTIONS', 'detect_leaks=0')
    libs = _collect_lib_paths(real_bin)
    if libs:
        env['LD_LIBRARY_PATH'] = ':'.join(libs + [env.get('LD_LIBRARY_PATH', '')])

    cmd = ['gdb', '-batch', '-q',
           '-ex', f"python exec(open({script!r}).read())",
           str(real_bin)]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           env=env)
    except subprocess.TimeoutExpired:
        print(f'  [!] gdb timeout after {timeout}s for {func}')
        return {'error': 'timeout'}
    finally:
        try:
            os.unlink(script)
        except Exception:
            pass

    out = r.stdout or ''
    err = r.stderr or ''

    # Parse events.
    events = {}
    for m in re.finditer(r'##EVT (\d+) (\d+) (\d+) (\{.*\})', out):
        n, inv, line, j = int(m.group(1)), int(m.group(2)), int(m.group(3)), m.group(4)
        try:
            clauses = json.loads(j)
        except Exception:
            clauses = {}
        events[n] = {'n': n, 'inv': inv, 'line': line, 'clauses': clauses}
    # Invocation markers: ENTER <inv> / CALL <inv> <line> <json> / RET <inv> <val>
    enters = [int(m) for m in re.findall(r'##ENTER (\d+)', out)]
    totals = re.findall(r'##TOTAL (\d+)', out)
    total = int(totals[-1]) if totals else len(events)
    inv_total = int((re.findall(r'##INVTOTAL (\d+)', out) or [0])[-1])
    if inv_total < len(enters):
        inv_total = len(enters)
    bp_fail = bool(re.search(r'##BPFAIL', out))

    calls = []
    for m in re.finditer(r'##CALL (\d+) (\d+) (\[.*\])', out):
        try:
            calls.append({'inv': int(m.group(1)), 'line': int(m.group(2)),
                          'callees': json.loads(m.group(3))})
        except Exception:
            pass
    rets = {}
    for m in re.finditer(r'##RET (\d+) (.+)', out):
        rets[int(m.group(1))] = m.group(2).strip()

    # Attach the invocation index and the executed source-line text to events.
    src_lines = Path(fsrc).read_text(errors='replace').splitlines()
    for n in events:
        ln = events[n]['line']
        events[n]['text'] = src_lines[ln - 1].strip() if 0 < ln <= len(src_lines) else ''

    # Compute outcomes client-side from the numeric clause values.
    dline_map = {d['line']: d for d in decisions}
    for n, ev in events.items():
        d = dline_map.get(ev['line'])
        if not d:
            continue
        results = []
        unknown = False
        for i, cl in enumerate(d['clauses']):
            vals = ev['clauses'].get(str(i), {})
            lhs, rhs = vals.get('lhs'), vals.get('rhs')
            op = cl.get('op')
            # gdb cannot parse the NULL macro; a NULL operand is 0 by
            # definition, which makes comparisons like `in == NULL`
            # computable (and the fork STRONG when the pointer differs).
            if lhs is None and cl.get('lhs') in ('NULL', 'nullptr'):
                lhs = 0
            if rhs is None and cl.get('rhs') in ('NULL', 'nullptr'):
                rhs = 0
            if op is None or lhs is None or rhs is None:
                unknown = True
                results.append(None)
                continue
            try:
                if op == '==':
                    res = bool(lhs == rhs)
                elif op == '!=':
                    res = bool(lhs != rhs)
                elif op == '<':
                    res = bool(lhs < rhs)
                elif op == '<=':
                    res = bool(lhs <= rhs)
                elif op == '>':
                    res = bool(lhs > rhs)
                elif op == '>=':
                    res = bool(lhs >= rhs)
                else:
                    unknown = True
                    results.append(None)
                    continue
                if cl.get('negated'):
                    res = not res
                results.append(res)
            except Exception:
                unknown = True
                results.append(None)
        ev['clause_results'] = results
        ev['outcome'] = None if unknown else (all(results) if results else None)
        ev['exprs'] = [[cl.get('lhs', ''), cl.get('rhs', '')]
                       for cl in d['clauses']]

    event_list = [events[n] for n in sorted(events)]

    # Group events/calls/returns per invocation (in execution order).
    invocations = []
    for i in range(1, inv_total + 1):
        invocations.append({
            'inv': i,
            'events': [e for e in event_list if e.get('inv') == i],
            'calls': [c for c in calls if c['inv'] == i],
            'return': rets.get(i),
        })

    result = {
        'func': func,
        'file': str(fsrc),
        'binary': str(real_bin),
        'run_args': args,
        'decision_lines': decisions,
        'events': event_list,
        'invocations': invocations,
        'invocations_total': inv_total,
        'bp_fail': bp_fail,
        'returns': rets,
        'total_events': total,
        'stats': {
            'decision_lines': len(decisions),
            'events': len(event_list),
            'invocations': inv_total,
            'lines_hit': len({e['line'] for e in event_list}),
            'outcome_known': sum(1 for e in event_list if e.get('outcome') is not None),
        },
    }
    if r.returncode != 0 and '##EVT' not in out:
        result['gdb_rc'] = r.returncode
        result['gdb_tail'] = (out + err)[-1500:]
    if out_path:
        Path(out_path).write_text(json.dumps(result, indent=2))
    return result


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--binary', required=True)
    ap.add_argument('--func', required=True)
    ap.add_argument('--source-root', help='version source root (searched for the function)')
    ap.add_argument('--out', help='output JSON path')
    ap.add_argument('--timeout', type=int, default=180)
    ap.add_argument('--mode', choices=['bp', 'step'], default='bp')
    ap.add_argument('--args', nargs=argparse.REMAINDER, default=[],
                    help='program args; use -- before them')
    a = ap.parse_args()

    r = record_decisions(a.binary, a.func, a.args, source_root=a.source_root,
                         timeout=a.timeout, out_path=a.out, mode=a.mode)
    if r is None or 'error' in r:
        sys.exit(1)
    print(json.dumps(r['stats'], indent=2))
    print(f'\nDecision events for {a.func} '
          f'({r["total_events"]} events in {r["invocations_total"]} invocation(s)):')
    for inv in r['invocations']:
        print(f'  [inv #{inv["inv"]}] return={inv["return"]}')
        for e in inv['events'][:40]:
            print(f'    L{e["line"]}: outcome={e.get("outcome")} '
                  f'clauses={e["clauses"]}')
        if len(inv['events']) > 40:
            print(f'    ... ({len(inv["events"]) - 40} more)')


if __name__ == '__main__':
    main()