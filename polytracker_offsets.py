#!/usr/bin/env python3
"""PolyTracker-based input-offset localization for fork-statement variables.

Given a fork statement (e.g. ``track->data_size / track->bytespersample``) and
the function it lives in, this module:

  1. Builds the target program with PolyTracker instrumentation
     (``clang-14 -fsanitize=dataflow -fpass-plugin=libPolytrackerPass.so``).
  2. Runs it on the PoC input, producing a ``.tdag`` taint trace.
  3. Loads the trace and reports the input-file byte offsets that reach the
     fork function (and, transitively, the fork-statement variables).

The PolyTracker Python analysis code lives in ``polytracker/`` (source tree).
Because that package's ``__init__.py`` eagerly imports every submodule (which
runs ``setup.py`` and other side-effectful code), we load the analysis modules
directly via :mod:`importlib` instead of importing the package.
"""

import importlib.util
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

POLYTRACKER_ROOT = Path("/home/ws/Desktop/RetroScope/polytracker")
PASS_PLUGIN = POLYTRACKER_ROOT / "build/src/passes/libPolytrackerPass.so"
POLY_LIB = POLYTRACKER_ROOT / "build/src/libPolytracker.a"
DFSAN_RT = POLYTRACKER_ROOT / "build/src/compiler-rt/lib/linux/libclang_rt.dfsan-x86_64.a"
DFSAN_ABILIST = POLYTRACKER_ROOT / "custom_abi/dfsan_abilist.txt"
POLY_ABILIST = POLYTRACKER_ROOT / "custom_abi/polytracker_abilist.txt"
CLANG = "clang-14"
CLANGXX = "clang++-14"
OPT = POLYTRACKER_ROOT / "bin/opt"
WLLVM = "/home/ws/.local/bin/wllvm"
WLLVMXX = "/home/ws/.local/bin/wllvm++"
EXTRACT_BC = "/home/ws/.local/bin/extract-bc"
LLVM_COMPILER_PATH = "/usr/lib/llvm-14/bin"

_PT_TRACE = None


def _load_trace_module():
    """Load the source tree's tracing/taint_dag modules without triggering the
    problematic package __init__."""
    global _PT_TRACE
    if _PT_TRACE is not None:
        return _PT_TRACE

    pkg = {}
    # graphs.py in the source tree uses an absolute `from polytracker.cache`
    # import that triggers the package's side-effectful __init__; use the
    # pre-patched copy instead.
    fixed_graphs = Path("/home/ws/Desktop/RetroScope/pt_analyze/graphs.py")
    mod_names = [
        "cache", "inputs", "plugins", "graphs", "taint_forest",
        "tracing", "repl", "polytracker", "taint_dag",
    ]
    for name in mod_names:
        if name == "graphs" and fixed_graphs.exists():
            path = fixed_graphs
        else:
            path = POLYTRACKER_ROOT / f"{name}.py"
        if not path.exists():
            continue
        spec = importlib.util.spec_from_file_location(f"pt_analyze.{name}", str(path))
        mod = importlib.util.module_from_spec(spec)
        mod.__package__ = "pt_analyze"
        pkg[name] = mod
        # Register as a pseudo-submodule so relative imports resolve
        sys.modules[f"pt_analyze.{name}"] = mod
        spec.loader.exec_module(mod)

    _PT_TRACE = pkg["taint_dag"]
    return _PT_TRACE


def load_trace(tdpath):
    td = _load_trace_module()
    return td.TDProgramTrace(open(tdpath, "rb"))


def analyze_trace_offsets(tdpath, function_name=None):
    """Extract input byte offsets from a .tdag trace.

    Returns dict with:
      inputs: list of (fd, path, size)
      offsets: sorted list of (offset, length) affecting control flow
      source_offsets: sorted list of (offset, length) for ALL tainted input bytes
      function_taints: dict {function_name: [(offset, length), ...]}
    """
    trace = load_trace(tdpath)

    result = {
        "inputs": [],
        "offsets": [],
        "source_offsets": [],
        "function_taints": {},
    }

    # Inputs
    try:
        result["inputs"] = [
            {"uid": getattr(i, "uid", None),
             "path": str(getattr(i, "path", i)),
             "size": getattr(i, "size", None),
             "track_start": getattr(i, "track_start", 0),
             "track_end": getattr(i, "track_end", None)}
            for i in trace.inputs
        ]
    except Exception as e:
        print(f"    [PolyTracker] inputs(): {e}")

    # Input bytes affecting control flow
    try:
        cf = trace.inputs_affecting_control_flow()
        offsets = set()
        for bo in cf:
            offsets.add((bo.offset, bo.length))
        result["offsets"] = sorted(offsets)
    except Exception as e:
        print(f"    [PolyTracker] inputs_affecting_control_flow(): {e}")

    # ALL tainted input bytes (source taints), regardless of control flow.
    # This is the useful set for crash/data-flow forks (e.g. division by zero)
    # where the tainted operands never reach a branch.
    try:
        tdfile = trace.tdfile
        src_offsets = set()
        for label in tdfile.input_labels():
            node = tdfile.decode_node(label)
            # TDSourceNode carries (source_index, offset); source_taint nodes
            # are decoded into TDSourceNode by decode_node.
            if node.__class__.__name__ == "TDSourceNode":
                src_offsets.add((node.offset, 1))
        result["source_offsets"] = sorted(src_offsets)
    except Exception as e:
        print(f"    [PolyTracker] source taints: {e}")

    return result


def decode_label_offsets(trace, label, max_depth=64):
    """Recursively decode a taint label to the set of input byte offsets it
    derives from (the provenance of a specific variable's taint)."""
    offsets = set()
    seen = set()

    def _walk(lbl, depth):
        if lbl == 0 or depth > max_depth or lbl in seen:
            return
        seen.add(lbl)
        node = trace.tdfile.decode_node(lbl)
        name = node.__class__.__name__
        if name == "TDSourceNode":
            offsets.add((node.offset, 1))
        elif name == "TDUnionNode":
            _walk(node.left, depth + 1)
            _walk(node.right, depth + 1)
        elif name == "TDRangeNode":
            # A contiguous range of labels.
            for i in range(node.first, node.last + 1):
                _walk(i, depth + 1)
                if len(seen) > 100000:
                    break

    _walk(label, 0)
    return sorted(offsets)


def analyze_var_taints(tdpath, var_labels):
    """Map variable names to input byte offsets using their recorded labels.

    ``var_labels`` maps a variable name to a single label or a list of labels
    (a variable inside a loop is logged once per iteration); the offsets of all
    labels are unioned.
    """
    if not var_labels:
        return {}
    trace = load_trace(tdpath)
    result = {}
    for name, labels in var_labels.items():
        if not isinstance(labels, (list, tuple)):
            labels = [labels]
        offsets = set()
        for label in labels:
            try:
                offsets.update(decode_label_offsets(trace, label))
            except Exception as e:
                print(f"    [PolyTracker] decode {name} (label {label}): {e}")
        result[name] = sorted(offsets)
    return result


def _resolve_pointer_vars(source_dir, variables):
    """Return the subset of ``variables`` that are pointer expressions.

    For a chain ``a->b->...->z`` the last field ``z``'s declaration is looked up
    in the source tree; for a bare identifier its declaration is looked up in the
    enclosing source.  A declaration containing ``*`` (e.g. ``uint64* z;``) marks
    the expression as a pointer.

    Pointers are special for taint tracking: their *address* is untainted (it
    comes from malloc), but the *memory they point to* is what was read from the
    input.  So pointer variables are dereferenced when instrumented.
    """
    source_dir = Path(source_dir)
    pointers = set()
    decl_cache = {}
    _C_KEYWORDS = {
        "if", "else", "while", "for", "do", "switch", "case", "return",
        "goto", "break", "continue", "static", "const", "sizeof",
    }

    def _find_decl(name):
        if name in decl_cache:
            return decl_cache[name]
        # Prefer headers (struct field declarations are unambiguous); fall back
        # to .c files (local variables) only if not found in headers.
        for suffix in (".h", ".c"):
            for p in source_dir.rglob("*"):
                if p.suffix != suffix:
                    continue
                try:
                    text = p.read_text(errors="replace")
                except Exception:
                    continue
                # "<type> name;" / "<type> name[..."; capture the full type
                # prefix (which may contain '*' for pointers, e.g.
                # "unsigned char *crop_buff").  Anchor to line start and reject
                # keyword/empty prefixes (assignment/condition contexts).
                for m in re.finditer(
                        r"(?:^|\n)\s*([^\n;{}]*?)\b"
                        + re.escape(name) + r"\b\s*(\[|;|=)", text):
                    decl = m.group(1).strip()
                    if not decl or decl in _C_KEYWORDS:
                        continue
                    if "*" in decl:
                        decl_cache[name] = decl
                        return decl
                    decl_cache[name] = decl
                    return decl
        decl_cache[name] = None
        return None

    for expr in variables:
        expr = (expr or "").strip()
        if not expr:
            continue
        fields = re.findall(r"(?:->|\.)\s*([a-zA-Z_]\w*)", expr)
        target_name = fields[-1] if fields else expr
        decl = _find_decl(target_name)
        if decl and "*" in decl:
            pointers.add(expr)
    return pointers


def _partition_vars(stripped_stmt, vars_):
    """Split fork variables into read-only (log BEFORE the statement) and
    assigned (log AFTER the statement) ones.

    A variable whose value is produced by the fork statement itself
    (e.g. ``err = TIFFReadDirEntryLong8Array(...)``) must be read after the
    statement executes — reading it beforehand yields the stale value of a
    previous assignment, whose taint points at unrelated input bytes.
    """
    before, after = [], []
    for v in vars_:
        assigned = False
        # Whole-expression LHS: `err = ...` at a statement boundary.
        if re.search(r'(?:^|[;{}])\s*' + re.escape(v) + r'\s*=(?!=)',
                     stripped_stmt):
            assigned = True
        else:
            # Member LHS: `tif->tif_dir.td_nstrips = ...` — the variable name
            # is the trailing field of the assignment target.
            base = re.split(r'->|\.', v)[-1]
            if base != v and re.search(r'[.>]\s*' + re.escape(base) + r'\s*=(?!=)',
                                       stripped_stmt):
                assigned = True
        (after if assigned else before).append(v)
    return before, after


def _parse_if_line(stripped):
    """Split a one-line ``if (...)`` header into ``(condition, rest)``.

    ``rest`` is everything after the condition's closing parenthesis (the
    inline body, if any).  A naive greedy regex ``if\s*\((.+)\)`` swallows
    every ``)`` up to the last one, so ``if (cond) x = f(1, 2);`` would be
    mis-split with ``f(1, 2`` inside the condition.  Scanning with a paren
    balance instead stops exactly at the condition's closing parenthesis.
    Returns None when the line does not start an ``if``.
    """
    m = re.match(r'if\s*\(', stripped)
    if not m:
        return None
    depth = 0
    for i in range(m.end() - 1, len(stripped)):
        ch = stripped[i]
        if ch == '(':
            depth += 1
        elif ch == ')':
            depth -= 1
            if depth == 0:
                cond = stripped[m.end():i].strip()
                return cond, stripped[i + 1:].strip()
    return None


def _find_pointer_assignment(source_dir, src_name, var_name, fork_line):
    """Find the assignment statement for a pointer variable before the fork line.
    
    Returns (line_number, assigned_expr) or (None, None).
    For example, for `crop_buff`, returns (line, "TIFFReadEncodedStrip(...)")
    """
    target = None
    for p in source_dir.rglob(src_name):
        if p.is_file():
            target = p
            break
    if target is None:
        return None, None
    
    lines = target.read_text(errors="replace").splitlines()
    
    # Search backwards from fork_line to find the assignment
    for i in range(min(fork_line - 1, len(lines) - 1), -1, -1):
        line = lines[i]
        # Look for `var_name = ...` pattern
        m = re.search(r'\b' + re.escape(var_name) + r'\s*=\s*(.+?)(?:;|$)', line)
        if m:
            return i + 1, m.group(1).strip()
    
    return None, None


def _extract_function_calls(expr):
    """Extract function calls from an expression.
    
    For example, `TIFFReadEncodedStrip(tif, strip, buf, size)` returns
    `['TIFFReadEncodedStrip']`.
    """
    if not expr:
        return []
    # Match function_name(...) pattern
    calls = re.findall(r'\b([a-zA-Z_]\w*)\s*\(', expr)
    # Filter out keywords and common non-function identifiers
    keywords = {'if', 'else', 'while', 'for', 'do', 'switch', 'case', 'return',
                'sizeof', 'typeof', 'alignof', 'static_cast', 'dynamic_cast'}
    return [c for c in calls if c not in keywords]


def _instrument_source(source_dir, instrument):
    """Insert taint-logging calls for each fork-statement variable.

    Modifies the fork statement's source file in ``source_dir`` so that, right
    before the fork statement, each variable's taint label is logged to stderr
    as ``POLY_VAR_TAINT <name> <label>``.
    """
    src_name = Path(instrument.get("source_file", "")).name
    line = instrument.get("line")
    variables = instrument.get("variables", [])
    if not src_name or not line:
        return

    # Locate the source file in the build tree.
    target = None
    for p in source_dir.rglob(src_name):
        if p.is_file():
            target = p
            break
    if target is None:
        return

    vars_ = []
    for v in variables:
        if not v:
            continue
        # Skip function names (identifiers followed by `(` in the statement).
        stmt = instrument.get("statement", "")
        if re.search(re.escape(v) + r"\s*\(", stmt):
            continue
        # Skip all-caps macros / enum constants (e.g. COMPOSITE_IMAGES) — they
        # are not lvalues, so &(macro) fails to compile.
        if re.match(r'^[A-Z][A-Z0-9_]*$', v):
            continue
        # Skip expressions that would not compile as an lvalue (e.g. LHS
        # assignment targets are fine, but casts/function results are not).
        vars_.append(v)
    if not vars_:
        return

    lines = target.read_text(errors="replace").splitlines()
    if line < 1 or line > len(lines):
        return

    header = [
        '#ifdef __cplusplus',
        'extern "C" {',
        '#endif',
        'void __polytracker_log_var_taint(const char*, unsigned);',
        # NOTE: The Polytracker runtime uses 32-bit dfsan labels, but the
        # system <sanitizer/dfsan_interface.h> (LLVM's stock DFSan) declares
        # dfsan_label as uint8_t.  Declare the function directly so the 32-bit
        # label is not truncated to 8 bits at the call site.
        'unsigned dfsan_read_label(const void*, unsigned long);',
        '#ifdef __cplusplus',
        '}',
        '#endif',
    ]
    # Insert header after the last existing #include line.
    last_inc = -1
    for i, l in enumerate(lines):
        if l.lstrip().startswith("#include"):
            last_inc = i
    if last_inc >= 0:
        lines = lines[:last_inc + 1] + header + lines[last_inc + 1:]
        line += len(header)
    else:
        lines = header + lines
        line += len(header)

    pointer_vars = _resolve_pointer_vars(source_dir, vars_)

    idx = line - 1  # fork statement is now `line`
    fork_line = lines[idx]
    indent = fork_line[:len(fork_line) - len(fork_line.lstrip())]
    stripped = fork_line.strip()

    def _log_calls(candidate_vars):
        """Build the taint-log statements for a variable subset."""
        calls = []
        for v in candidate_vars:
            if v in pointer_vars:
                # Pointer: the address is untainted (from malloc); trace the
                # taint of the memory it points to (read from the input).
                # For NULL checks like `if (!ptr)`, we need to trace why the
                # pointer is NULL - log a special marker when ptr is NULL.
                # Also log the pointer's own taint (which tracks where the
                # pointer value came from, e.g., function return values).
                calls.append(
                    f'if ({v}) {{ __polytracker_log_var_taint("{v}", '
                    f'dfsan_read_label({v}, sizeof(*({v})))); '
                    f'__polytracker_log_var_taint("{v}_ptr", '
                    f'dfsan_read_label(&({v}), sizeof({v}))); }} '
                    f'else {{ __polytracker_log_var_taint("{v}_NULL", '
                    f'dfsan_read_label(&({v}), sizeof({v}))); }}')
            else:
                calls.append(
                    f'__polytracker_log_var_taint("{v}", '
                    f'dfsan_read_label(&({v}), sizeof({v})));')
        return calls

    # Variables *assigned* by the fork statement must be logged AFTER the
    # statement: a log inserted before the assignment reads the variable's
    # stale pre-statement value (its taint belongs to an earlier assignment),
    # so the reported input offsets do not steer the fork at all.
    before_vars, after_vars = _partition_vars(stripped, vars_)
    before_calls = _log_calls(before_vars)
    after_calls = _log_calls(after_vars)

    def _shifted(calls, extra):
        return [f'{indent}{extra}{c}' for c in calls]

    # For `if` forks, instrument *inside* the body so the taint is logged only
    # on the diverging iteration (condition true), not every loop iteration.
    if_parts = _parse_if_line(stripped)
    if if_parts:
        cond, rest = if_parts
        if rest and not rest.startswith('{'):
            # Single-line: `if (cond) stmt;`
            body = rest
            if re.match(r'(goto|return|break|continue)\b', body):
                # Early-exit body (error handling): instrument BEFORE the `if`
                # so the taint is logged regardless of whether the error path
                # is taken (e.g. `if (!load(...)) goto bad;`).
                indented_calls = [f'{indent}  {c}' for c in before_calls]
                lines = lines[:idx] + indented_calls + lines[idx:]
            else:
                new_lines = [f'{indent}if ({cond}) {{']
                new_lines += [f'{indent}  {c}' for c in before_calls]
                new_lines += [f'{indent}  {body}']
                # After-log an assignment that lives inside the `if` body.
                new_lines += [f'{indent}  {c}' for c in after_calls]
                new_lines.append(f'{indent}}}')
                lines = lines[:idx] + new_lines + lines[idx + 1:]
        elif not rest and idx + 1 < len(lines):
            # Body on the next line: `if (cond)\n    stmt;`
            body = lines[idx + 1].strip()
            if body and not body.startswith('{'):
                if re.match(r'(goto|return|break|continue)\b', body):
                    indented_calls = [f'{indent}  {c}' for c in before_calls]
                    lines = lines[:idx] + indented_calls + lines[idx:]
                else:
                    new_lines = [f'{indent}if ({cond}) {{']
                    new_lines += [f'{indent}  {c}' for c in before_calls]
                    new_lines += [f'{indent}  {body}']
                    new_lines += [f'{indent}  {c}' for c in after_calls]
                    new_lines.append(f'{indent}}}')
                    lines = lines[:idx] + new_lines + lines[idx + 2:]
            else:
                # Block body on the following lines: keep the current
                # before-`if` placement (after-logs would need brace
                # matching, and a block body is rarely a single assignment).
                indented_calls = [f'{indent}  {c}' for c in before_calls]
                lines = lines[:idx] + indented_calls + lines[idx:]
        else:
            indented_calls = [f'{indent}  {c}' for c in before_calls]
            lines = lines[:idx] + indented_calls + lines[idx:]
    else:
        # The fork is not an `if` itself.  It may be a single-statement body of
        # a control statement (if/else/for/while/do) on the previous line —
        # inserting log calls before it would break the control structure, so
        # wrap it in a block.
        prev = ''
        for j in range(idx - 1, -1, -1):
            p = lines[j].strip()
            if p and not p.startswith('/*') and not p.startswith('*') and not p.startswith('//'):
                prev = p
                break
        is_ctrl_body = (bool(re.match(r'^(if|else|for|while|do)\b', prev))
                        and not prev.endswith('{'))
        if is_ctrl_body:
            # Wrap `{ before-logs; stmt; after-logs }`: the before-logs run in
            # the same execution context the original single statement had,
            # and the after-logs run right after the assignment.  Wrapping a
            # single-statement body of if/else/for/while/do in a block does
            # not change the semantics.
            new_lines = [f'{indent}{{']
            new_lines += [f'{indent}  {c}' for c in before_calls]
            new_lines += [f'{indent}  {stripped}']
            new_lines += [f'{indent}  {c}' for c in after_calls]
            new_lines.append(f'{indent}}}')
            lines = lines[:idx] + new_lines + lines[idx + 1:]
        else:
            # Plain statement: logs that read pre-statement state go before,
            # logs of variables assigned by the statement go after it.
            new_lines = _shifted(before_calls, '')
            new_lines += [fork_line]
            new_lines += _shifted(after_calls, '')
            lines = lines[:idx] + new_lines + lines[idx + 1:]

    target.write_text("\n".join(lines) + "\n")
    print(f"    [PolyTracker] instrumented {target.name}:{line} "
          f"vars={vars_}")


def build_instrumented(source_dir, program_name, build_cmds=None,
                       compile_flags=None, instrument=None):
    """Build the target program with PolyTracker instrumentation.

    Uses whole-program instrumentation: build the project normally with wllvm
    (which embeds LLVM bitcode in each binary), extract the whole-program
    bitcode, run the pt-taint/pt-dfsan passes, and lower back to an executable.
    This avoids the DFSan library/executable ABI mismatch that occurs when
    instrumenting each translation unit separately.

    ``instrument`` optionally gives ``{source_file, line, variables}`` to log
    each fork-statement variable's taint label at runtime.

    Returns the path to the instrumented binary, or None.
    """
    source_dir = Path(source_dir).resolve()

    if not PASS_PLUGIN.exists() or not OPT.exists():
        print(f"    [PolyTracker] pass plugin or opt missing")
        return None
    if not POLY_LIB.exists() or not DFSAN_RT.exists():
        print(f"    [PolyTracker] PolyTracker runtime libs missing")
        return None

    # Optionally instrument the fork-statement source so each variable's taint
    # label is logged at runtime (used for targeted provenance analysis).
    if instrument:
        _instrument_source(source_dir, instrument)
        # Touch the instrumented file to ensure make sees it as newer than any
        # cached object files.
        _src_name = Path(instrument.get("source_file", "")).name
        for _p in source_dir.rglob(_src_name):
            if _p.is_file():
                _p.touch()
                break
        # Verify instrumentation survived before the build starts
        _src_name = Path(instrument.get("source_file", "")).name
        _line = instrument.get("line", 0)
        for _p in source_dir.rglob(_src_name):
            if _p.is_file():
                _txt = _p.read_text(errors="replace")
                _ok = "__polytracker_log_var_taint" in _txt
                print(f"    [PolyTracker] pre-build check: {_p.name} has instrumentation: {_ok}")
                break

    def _clean_flags(flags):
        if not flags:
            return ""
        out = []
        for tok in flags.split():
            if tok in ("-fsanitize=address", "-finstrument-functions",
                       "-rdynamic", "-ldl", "-lm"):
                continue
            out.append(tok)
        return " ".join(out)

    # Runtime libraries to link so instrumented-source symbols (dfsan_get_label,
    # __polytracker_log_var_taint) resolve during the wllvm build.  Use -u to
    # force the linker to pull these symbols from the runtime libs regardless of
    # link order (the project libs referencing them appear later on the line).
    runtime_ld = (
        f"-Wl,-u,dfsan_get_label -Wl,-u,__polytracker_log_var_taint "
        f"{POLY_LIB} {DFSAN_RT} "
        f"-L/usr/lib/llvm-14/lib -lc++ -lc++abi -lstdc++ "
        "-Wl,--allow-multiple-definition -lpthread -ldl -lm -ltinfo"
    )

    # wllvm environment: builds normal binaries with embedded bitcode.
    llvm_bin = str(POLYTRACKER_ROOT / "bin")
    env = os.environ.copy()
    env["PATH"] = f"{llvm_bin}:{env.get('PATH', '')}"
    env["CC"] = WLLVM
    env["CXX"] = WLLVMXX
    env["LLVM_COMPILER"] = "clang"
    env["LLVM_COMPILER_PATH"] = LLVM_COMPILER_PATH
    env["CFLAGS"] = "-g -O0 " + _clean_flags((compile_flags or {}).get("CFLAGS", ""))
    env["CXXFLAGS"] = "-g -O0 " + _clean_flags((compile_flags or {}).get("CXXFLAGS", ""))
    env["LDFLAGS"] = _clean_flags((compile_flags or {}).get("LDFLAGS", "")) + " " + runtime_ld

    # Plain environment for configure (probe programs must run).
    plain_env = os.environ.copy()
    plain_env["CC"] = CLANG
    plain_env["CXX"] = CLANGXX
    plain_env["CFLAGS"] = "-g -O0"
    plain_env["CXXFLAGS"] = "-g -O0"
    plain_env["LDFLAGS"] = ""

    nproc = str(os.cpu_count() or 2)

    def run(cmd, use_env=None, timeout=1800):
        e = env if use_env is None else use_env
        print(f"    [PolyTracker] $ {cmd}")
        r = subprocess.run(cmd, shell=True, cwd=str(source_dir), env=e,
                           capture_output=True, text=True, timeout=timeout)
        if r.returncode != 0:
            print(f"    [PolyTracker] build step failed: {r.stderr[-800:]}")
            return False
        return True

    def _strip_configure(cmd):
        # Reduce `bash -c 'CFLAGS=... LDFLAGS=... ./configure'` to a plain
        # `./configure --disable-shared --enable-static` so configure runs with
        # the plain compiler and the library is built statically (so its object
        # files are linked into the executable and captured by whole-program
        # bitcode extraction).
        m = re.search(r"\./configure", cmd)
        if m:
            return "./configure --disable-shared --enable-static"
        return None

    def _make_cmd(cmd):
        cmd = cmd.strip()
        if not cmd.startswith("make"):
            cmd = "make " + cmd
        cmd = re.sub(r"\s+CC=\S+", "", cmd)
        cmd = re.sub(r"\s+CXX=\S+", "", cmd)
        cmd = re.sub(r"\s+CFLAGS=\S+", "", cmd)
        cmd = re.sub(r"\s+CXXFLAGS=\S+", "", cmd)
        cmd = re.sub(r"\s+LDFLAGS=\S+", "", cmd)
        return (f"{cmd} CC={WLLVM} CXX={WLLVMXX} "
                f"CFLAGS='-g -O0' CXXFLAGS='-g -O0' LDFLAGS='{runtime_ld}' "
                f"LLVM_COMPILER=clang LLVM_COMPILER_PATH={LLVM_COMPILER_PATH}")

    configured = False
    did_build = False
    # 1) Project-provided pre_build commands.
    for cmd in (build_cmds or []):
        cmd = cmd.replace("-finstrument-functions", "")
        if "distclean" in cmd or "make clean" in cmd:
            if not run(cmd, plain_env):
                # make clean failed — likely stale artifacts blocking it.
                # Force-remove common stale files, then retry.
                import shutil
                for pat in ['*.o', '*.lo', '*.la', '*.a', '*.Plo']:
                    for f in source_dir.rglob(pat):
                        try: f.unlink()
                        except OSError: pass
                for d in source_dir.rglob('.deps'):
                    try: shutil.rmtree(d)
                    except OSError: pass
                for d in source_dir.rglob('.libs'):
                    try: shutil.rmtree(d)
                    except OSError: pass
                # Retry make clean
                run(cmd, plain_env)
                # Don't fail — continue with configure/build
        elif "configure" in cmd:
            cfg = _strip_configure(cmd)
            if cfg and not configured:
                if not run(cfg, plain_env):
                    return None
                configured = True
        elif "cmake" in cmd:
            if not run(cmd, plain_env):
                return None
            configured = True
        elif "make" in cmd:
            if not run(_make_cmd(cmd), env):
                return None
            did_build = True
        else:
            if not run(cmd, plain_env):
                return None

    # 2) Autotools / CMake build with wllvm.  Only run when pre_build did not
    #    already compile (a full `make` here would also build docs/man pages
    #    that often lack the required tools, e.g. audiofile's afReadMisc.3).
    if not did_build:
        # Remove stale build artifacts copied from the source tree.  The copy
        # keeps *.lo (libtool wrappers) but drops *.o, so a `make` would see the
        # .lo files as up-to-date and skip recompiling, then fail to link the
        # missing .o files (e.g. `ar: tif_aux.o: No such file or directory`).
        if (source_dir / "Makefile").exists():
            r = run("make clean", plain_env)
            if not r:
                # make clean may fail on a dirty copy; force-remove artifacts.
                for pattern in ("*.o", "*.lo", "*.la", "*.a", "*.Plo"):
                    for p in source_dir.rglob(pattern):
                        p.unlink(missing_ok=True)
                for d in list(source_dir.rglob(".deps")) + list(source_dir.rglob(".libs")):
                    if d.is_dir():
                        shutil.rmtree(d, ignore_errors=True)
        if (source_dir / "configure").exists():
            if not run("./configure --disable-shared --enable-static", plain_env):
                return None
            configured = True
        if (source_dir / "Makefile").exists():
            if not run(_make_cmd(f"make -j{nproc}"), env):
                return None
        elif (source_dir / "CMakeLists.txt").exists():
            bld = source_dir / "poly_build"
            bld.mkdir(exist_ok=True)
            if not run("cmake .. -DCMAKE_BUILD_TYPE=Debug", plain_env):
                return None
            if not run(_make_cmd(f"make -j{nproc}"), env):
                return None

    # Locate the produced (uninstrumented) binary.
    candidates = []
    for root, dirs, files in os.walk(str(source_dir)):
        depth = root[len(str(source_dir)):].count(os.sep)
        if depth > 5:
            continue
        for f in files:
            if f == program_name:
                candidates.append(Path(root) / f)
    # Prefer a real ELF binary over a libtool wrapper script.
    def _is_elf(p):
        try:
            return p.read_bytes()[:4] == b"\x7fELF"
        except Exception:
            return False
    real = [p for p in candidates if _is_elf(p)]
    binary = (real or candidates)[0] if (real or candidates) else None
    if binary is None:
        print(f"    [PolyTracker] binary '{program_name}' not found after build")
        return None
    print(f"    [PolyTracker] built binary: {binary}")

    # Extract whole-program bitcode.
    bc = binary.with_suffix(".bc")
    print(f"    [PolyTracker] $ extract-bc -o {bc} {binary}")
    r = subprocess.run([EXTRACT_BC, "-o", str(bc), str(binary)],
                       capture_output=True, text=True, timeout=300, env=env)
    if r.returncode != 0 or not bc.exists():
        print(f"    [PolyTracker] bitcode extraction failed: {r.stderr[-500:]}")
        return None

    # Instrument the whole-program bitcode.
    inst_bc = binary.with_name(binary.name + ".inst.bc")
    # System-library abilists (zlib, freetype, ...) mark those functions as
    # discard so uninstrumented library calls resolve to the plain symbols
    # rather than dfs$ wrappers.
    extra_abilists = []
    for name in ("libz", "freetype", "fontconfig", "gmp", "ssl", "xml2"):
        p = POLYTRACKER_ROOT / "custom_abi" / name
        if p.exists():
            extra_abilists.append(f"-pt-dfsan-abilist={p}")
    opt_cmd = [
        str(OPT),
        "-load", str(PASS_PLUGIN),
        "-load-pass-plugin", str(PASS_PLUGIN),
        "-passes=pt-taint,pt-dfsan,pt-rm-fn-attr",
        f"-pt-taint-ignore-list={POLY_ABILIST}",
        f"-pt-dfsan-abilist={DFSAN_ABILIST}",
        *extra_abilists,
        str(bc), "-o", str(inst_bc),
    ]
    print(f"    [PolyTracker] $ opt -passes=pt-taint,pt-dfsan,pt-rm-fn-attr ...")
    r = subprocess.run(opt_cmd, capture_output=True, text=True, timeout=600)
    if r.returncode != 0 or not inst_bc.exists():
        print(f"    [PolyTracker] instrumentation failed: {r.stderr[-600:]}")
        return None

    # Lower to an executable.  Link common system libraries the target may
    # depend on (zlib, jpeg) so their uninstrumented symbols resolve.
    inst_bin = binary.with_name(binary.name + ".track")
    lower_cmd = [
        CLANG, str(inst_bc), "-o", str(inst_bin),
        f"-Wl,--whole-archive", str(POLY_LIB), "-Wl,--no-whole-archive",
        str(DFSAN_RT), "-L/usr/lib/llvm-14/lib", "-lc++", "-lc++abi", "-lstdc++",
        "-Wl,--allow-multiple-definition", "-lpthread", "-ldl", "-lm",
        "-ltinfo", "-lz",
    ]
    print(f"    [PolyTracker] $ {CLANG} ... -o {inst_bin.name}")
    r = subprocess.run(lower_cmd, capture_output=True, text=True, timeout=600)
    if r.returncode != 0 or not inst_bin.exists():
        print(f"    [PolyTracker] lowering failed: {r.stderr[-600:]}")
        return None

    print(f"    [PolyTracker] instrumented binary: {inst_bin}")
    return inst_bin


def run_trace(binary, full_args, output_dir):
    """Run an instrumented binary.

    Returns ``(trace_path, var_labels)`` where ``var_labels`` is a dict mapping
    variable name -> taint label parsed from the ``POLY_VAR_TAINT`` stderr lines.
    """
    binary = Path(binary).resolve()
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    env = os.environ.copy()
    env["ASAN_OPTIONS"] = "detect_leaks=0"
    env["POLYDB"] = str(output_dir / "polytracker.tdag")

    cmd = [str(binary)] + list(full_args)

    print(f"    [PolyTracker] $ {' '.join(cmd)}")
    r = subprocess.run(cmd, cwd=str(output_dir), env=env,
                       capture_output=True, text=True, timeout=300)

    var_labels = {}
    for m in re.finditer(r"POLY_VAR_TAINT\s+(\S+)\s+(\d+)", r.stderr or ""):
        var_labels.setdefault(m.group(1), []).append(int(m.group(2)))

    # The runtime may ignore POLYDB and always write polytracker.tdag in cwd.
    trace_path = output_dir / "polytracker.tdag"
    if not trace_path.exists():
        trace_path = Path.cwd() / "polytracker.tdag"

    if trace_path.exists():
        print(f"    [PolyTracker] trace: {trace_path} (returncode={r.returncode})")
        return trace_path, var_labels
    print(f"    [PolyTracker] no trace produced (returncode={r.returncode})")
    if r.stderr:
        print(f"    [PolyTracker] stderr: {r.stderr[-500:]}")
    return None, var_labels


def locate_offsets(source_dir, program_name, input_file, fork_function,
                   output_file="/tmp/poly_out", build_cmds=None,
                   full_args=None, compile_flags=None,
                   fork_source_file=None, fork_line=None, variables=None,
                   fork_statement=None):
    """End-to-end: build, run, and analyze to locate input offsets.

    Builds in a throwaway copy of ``source_dir`` so the original version tree
    is never modified.  ``full_args`` is the argument list after the program
    name, with ``{input_file}``/``{output_file}`` already substituted.

    When ``fork_source_file``/``fork_line``/``variables`` are given, the fork
    statement's variables are instrumented and their specific input byte
    offsets (taint provenance) are reported.
    """
    import tempfile

    print("\n" + "=" * 70)
    print("PolyTracker Input-Offset Localization")
    print("=" * 70)

    source_dir = Path(source_dir).resolve()
    input_file = Path(input_file).resolve() if input_file else None
    if input_file is None or not input_file.exists():
        print(f"    [PolyTracker] input file not found: {input_file}")
        return {"status": "no_input"}

    work = Path(tempfile.mkdtemp(prefix="poly_build_"))
    print(f"    [PolyTracker] build workspace: {work}")
    shutil.copytree(source_dir, work, dirs_exist_ok=True,
                    ignore=shutil.ignore_patterns(".git", "*.o", "*.so"))

    # Remove any stale build artifacts that survived the copy (object files,
    # libtool archives, .deps, .libs from a previous build).  These can cause
    # `make` to skip recompilation of source files we later instrument.
    # NOTE: Do NOT delete Makefiles — ./configure needs them or will regenerate.
    for pattern in ("*.o", "*.lo", "*.la", "*.a", "*.Plo"):
        for p in work.rglob(pattern):
            p.unlink(missing_ok=True)
    for d in list(work.rglob(".deps")) + list(work.rglob(".libs")):
        if d.is_dir():
            shutil.rmtree(d, ignore_errors=True)

    instrument = None
    if fork_source_file and fork_line and variables:
        instrument = {
            "source_file": fork_source_file,
            "line": fork_line,
            "variables": variables,
            "statement": fork_statement or "",
        }

    try:
        return _locate_offsets_in_work(work, input_file, program_name,
                                       build_cmds, compile_flags, instrument,
                                       full_args, fork_function)
    finally:
        # The build workspace is pure intermediate data (wllvm bitcode + -g
        # -O0 objects can reach tens of GB); a fresh copy is made on every
        # run, so remove it as soon as the offsets are extracted.
        print(f"    [PolyTracker] cleaning build workspace: {work}")
        shutil.rmtree(work, ignore_errors=True)


def _locate_offsets_in_work(work, input_file, program_name, build_cmds,
                            compile_flags, instrument, full_args,
                            fork_function):
    binary = build_instrumented(work, program_name, build_cmds,
                                compile_flags=compile_flags, instrument=instrument)
    if binary is None:
        return {"status": "build_failed"}

    if full_args is None:
        full_args = [str(input_file)]

    outdir = Path(tempfile.mkdtemp(prefix="poly_trace_"))
    trace_path, var_labels = run_trace(binary, full_args, outdir)
    if trace_path is None:
        return {"status": "no_trace", "binary": str(binary)}

    result = analyze_trace_offsets(trace_path, fork_function)
    result["status"] = "success"
    result["binary"] = str(binary)
    result["trace_path"] = str(trace_path)

    # Targeted provenance: which input bytes each fork variable derives from.
    result["variable_offsets"] = analyze_var_taints(trace_path, var_labels)

    # Keep only variables with a non-empty provenance for the primary result.
    result["variable_offsets"] = {
        k: v for k, v in result["variable_offsets"].items() if v
    }

    print("\n  PolyTracker results:")
    if result["variable_offsets"]:
        print("    Fork statement variables -> input file offsets:")
        for name, offs in result["variable_offsets"].items():
            offs_str = ", ".join(f"0x{o:x}" for o, _ in offs)
            print(f"      {name}: {offs_str}")
    else:
        print("    Fork statement variables -> input file offsets: (none)")
    return result


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--source-dir", required=True)
    ap.add_argument("--program", required=True)
    ap.add_argument("--input", required=True)
    ap.add_argument("--function", required=True)
    ap.add_argument("--extra-args", nargs="*", default=[])
    args = ap.parse_args()
    print(locate_offsets(args.source_dir, args.program, args.input,
                         args.function, extra_args=args.extra_args))
