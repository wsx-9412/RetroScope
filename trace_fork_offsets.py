#!/usr/bin/env python3
"""trace_fork_offsets.py - GDB dynamic tracing: fork-statement variables → input file offsets

Combines GDB dynamic tracing with minimal file-format parsing:
  1. GDB: hit fork breakpoint, collect variable addresses/values, memory mappings
  2. File parsing: extract TIFF IFD tags (StripOffsets, ImageWidth, SamplesPerPixel, etc.)
  3. Cross-reference: map heap buffer offsets to file offsets using tag metadata

For TIFF:
  - Reads the IFD to find tag entry file offsets
  - Uses StripOffsets tag value to map strip data buffer → file
  - Reports which IFD entry bytes influence the vulnerable computation

For the non-TIFF targets (binutils/ELF, giflib/GIF, libxml2/XML,
freetype/sfnt+WOFF) the on-disk structure is parsed statically
(static_structure_region) and its field positions feed the Step 6c/6d
static fallback sweep — the same role _static_ifd_region plays for TIFF
when no dynamic fork context exists.
"""

import subprocess
import tempfile
import os
import re
import sys
import json
import struct
import itertools
import argparse
import difflib
import time
import shutil
from pathlib import Path


def resolve_binary(binary):
    if os.path.isfile(binary):
        with open(binary, 'rb') as f:
            first = f.readline()
        if first.startswith(b'#!'):
            d = os.path.dirname(binary)
            candidate = os.path.join(d, '.libs', os.path.basename(binary))
            if os.path.isfile(candidate):
                return candidate
        return binary
    name = os.path.basename(binary)
    d = os.path.dirname(binary)
    candidates = [os.path.join(d, name),
                  os.path.join(d, '.libs', name)]
    parent = os.path.dirname(d)
    if parent and parent != d:
        candidates.append(os.path.join(parent, name))
        candidates.append(os.path.join(parent, '.libs', name))
    for c in candidates:
        if os.path.isfile(c):
            return c
    return binary


def build_run_env(binary):
    """Build an environment that loads the version's freshly built library.

    The real ELF binary lives in <subdir>/.libs and carries no RPATH; the
    libtool wrapper normally exports LD_LIBRARY_PATH.  When invoking the
    .libs binary directly, point LD_LIBRARY_PATH at the project's library
    build dir (libtiff/.libs, libaudiofile/.libs, ...) so the built library
    (with its debug info) is loaded instead of a system one.
    """
    env = os.environ.copy()
    # ASan-instrumented binaries (especially statically-linked ones like lame)
    # abort under GDB's ptrace because LeakSanitizer cannot run; disable it so
    # the fork breakpoint is actually reachable during GDB tracing.
    _asan = env.get("ASAN_OPTIONS", "")
    if "detect_leaks=0" not in _asan:
        env["ASAN_OPTIONS"] = ("detect_leaks=0" +
                               (":" + _asan if _asan else ""))
    # Return NULL on OOM instead of ASan aborting: a huge allocation
    # (e.g. CVE-2018-19931) then hits the program's own error path
    # ("memory exhausted") rather than a fake ASan crash.
    _asan = env.get("ASAN_OPTIONS", "")
    if "allocator_may_return_null" not in _asan:
        env["ASAN_OPTIONS"] = _asan + ":allocator_may_return_null=1"
    d = os.path.dirname(os.path.abspath(binary))
    for _ in range(6):
        lib_dirs = []
        try:
            for entry in sorted(os.listdir(d)):
                cand = os.path.join(d, entry, '.libs')
                if entry.startswith('lib') and os.path.isdir(cand):
                    lib_dirs.append(cand)
        except OSError:
            pass
        if lib_dirs:
            prev = env.get('LD_LIBRARY_PATH', '')
            env['LD_LIBRARY_PATH'] = ':'.join(lib_dirs) + (
                ':' + prev if prev else '')
            break
        parent = os.path.dirname(d)
        if parent == d:
            break
        d = parent
    return env


def _mutation_env(binary):
    """Environment for a single mutation run.

    Same as ``build_run_env`` plus an ASan RSS cap so a runaway mutant
    (huge allocation, no crash) cannot exhaust the host.  GDB-trace runs
    deliberately do NOT get the cap: a legitimately large target run must
    be able to reach its fork breakpoint.
    """
    env = build_run_env(binary)
    _asan = env.get("ASAN_OPTIONS", "")
    if "hard_rss_limit_mb" not in _asan:
        _asan += ":hard_rss_limit_mb=" + os.environ.get(
            "RETROSCOPE_ASAN_RSS_MB", "512")
    env["ASAN_OPTIONS"] = _asan
    return env


def _strip_c_comments(text):
    """Remove C block/line comments and string/char literals from source text.

    ``{'/'}`` inside comments or strings must not corrupt the token scan.
    """
    out = []
    i, n = 0, len(text)
    in_block = in_str = in_char = False
    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ''
        if in_block:
            if c == '*' and nxt == '/':
                in_block = False
                i += 2
                continue
            i += 1
            continue
        if in_str:
            if c == '\\':
                i += 2
                continue
            if c == '"':
                in_str = False
            i += 1
            continue
        if in_char:
            if c == '\\':
                i += 2
                continue
            if c == "'":
                in_char = False
            i += 1
            continue
        if c == '/' and nxt == '/':
            while i < n and text[i] != '\n':
                i += 1
            continue
        if c == '/' and nxt == '*':
            in_block = True
            i += 2
            continue
        if c == '"':
            in_str = True
            i += 1
            continue
        if c == "'":
            in_char = True
            i += 1
            continue
        out.append(c)
        i += 1
    return ''.join(out)


def extract_variables_from_statement(stmt):
    """Extract C variable expressions from a fork statement.

    Returns expressions evaluable in GDB (e.g., 'tif->tif_dir.td_stripoffset').
    """
    if not stmt:
        return []

    # Strip comments FIRST: the fork-statement span may include function
    # header comments (e.g. tif_strip.c's "YCbCr data contain one Cb+Cr for
    # every ... roundup width and height"), whose words must never become
    # "variables" (they then fail GDB evaluation and report no file mapping).
    cleaned = _strip_c_comments(stmt)
    cleaned = re.sub(r'"[^"]*"', '', cleaned)
    cleaned = re.sub(r"'[^']*'", '', cleaned)
    cleaned = re.sub(r'\bsizeof\s*\([^()]*\)', '', cleaned)
    # Remove preprocessor directives
    cleaned = re.sub(r'#\w+[^\n]*', '', cleaned)

    _EXPR_RE = re.compile(r'(?<!\w)((?:[a-zA-Z_]\w*)(?:\s*->\s*[a-zA-Z_]\w*|\s*\.\s*[a-zA-Z_]\w*|\s*\[\s*\w+\s*\])*)(?!\w)')
    _KEYWORDS = {
        'if', 'else', 'while', 'for', 'do', 'switch', 'case', 'break',
        'continue', 'return', 'int', 'char', 'long', 'short', 'unsigned',
        'signed', 'float', 'double', 'void', 'const', 'static', 'extern',
        'struct', 'union', 'enum', 'typedef', 'sizeof', 'NULL', 'true',
        'false', 'uint8_t', 'uint16_t', 'uint32_t', 'uint64_t',
        'int8_t', 'int16_t', 'int32_t', 'int64_t', 'size_t',
        'uint8', 'uint16', 'uint32', 'uint64', 'int8', 'int16', 'int32',
        'int64', 'toff_t', 'tsize_t', 'tdata_t', 'uint', 'ushort', 'uchar',
        # Preprocessor and control flow
        'goto', 'defined', 'endif', 'elif', 'ifdef', 'ifndef',
        # Common C identifiers that are not variables
        'bad', 'module', 'err', 'data', 'm', 'TIFFTAG',
    }

    seen = set()
    result = []
    for m in _EXPR_RE.finditer(cleaned):
        expr = m.group(1).strip()
        root = expr.split('->')[0].split('.')[0].split('[')[0]
        if root in _KEYWORDS or expr in seen or root.isdigit():
            continue
        # Skip type names / typedefs (CamelCase identifiers like TIFFField),
        # but only in type context — followed by a declarator, '(' or '*',
        # or at the end of the statement.  In expression position (an
        # operator or punctuation follows) an uppercase identifier is a real
        # variable: e.g. '*BufferP++ = ColorMapEntry->Red;' must yield
        # BufferP and ColorMapEntry->Red, while 'TIFFField field;' must not
        # yield TIFFField.
        if re.match(r'^[A-Z]', root):
            _after = cleaned[m.end():].lstrip()
            if not _after or _after[0] in '(*' or re.match(r'^[A-Za-z_]', _after):
                continue
            # Expression position: keep CamelCase variables (BufferP,
            # ColorMapEntry->Red) but still skip ALL-CAPS macro constants
            # (TIFF_SHORT, TIFFTAG_STRIPOFFSETS).
            if expr.isupper():
                continue
        # Skip function calls: identifier immediately followed by '('.
        if cleaned[m.end():].lstrip().startswith('('):
            continue
        seen.add(expr)
        result.append(expr)

    return result


def read_source_fork_statement(source_file, target_line, target_binary=None,
                               search_range=30, expected_statement=None):
    """Read source file around target_line and extract the full fork statement.

    Handles preprocessor conditionals (#if/#else/#endif) by extracting
    variables from ALL branches, so that GDB can try each one.

    Args:
        source_file: Source file path (relative or absolute)
        target_line: Line number of the fork statement
        target_binary: Path to the target binary (used to find the correct version)
        search_range: Lines to search around target_line

    Returns (full_statement, variables_list).
    """
    if not source_file or not target_line:
        return None

    # Try to locate the source file
    p = Path(source_file)
    _resolved_in_version_root = False
    if not p.is_absolute():
        # First, try to find in the target binary's version directory
        if target_binary:
            binary_path = Path(target_binary)
            # Walk up from binary to find version root
            for parent in [binary_path] + list(binary_path.parents):
                # Check libtiff subdir first (common for libtiff)
                candidate = parent / 'libtiff' / p.name
                if candidate.is_file():
                    p = candidate
                    _resolved_in_version_root = True
                    break
                # Also check tools subdir (for tiffcrop)
                candidate = parent / 'tools' / p.name
                if candidate.is_file():
                    p = candidate
                    _resolved_in_version_root = True
                    break
                # Check if this is the version root
                if (parent / 'configure').exists() or (parent / '.build_ok').exists():
                    candidate = parent / 'libtiff' / p.name
                    if candidate.is_file():
                        p = candidate
                        _resolved_in_version_root = True
                        break
                    candidate = parent / 'tools' / p.name
                    if candidate.is_file():
                        p = candidate
                        _resolved_in_version_root = True
                        break
                    # Any project layout (e.g. audiofile's libaudiofile/):
                    # resolve inside THIS version's tree only, so another
                    # version's same-named file can never be picked.
                    _hit = None
                    try:
                        _hit = next((m for m in parent.rglob(p.name)
                                     if m.is_file()), None)
                    except Exception:
                        _hit = None
                    if _hit is not None:
                        p = _hit
                        _resolved_in_version_root = True
                        break

        # If not found, search in version directories (prefer target binary's version)
        if not p.is_file():
            # Extract version from target binary path if possible
            if target_binary:
                tb = Path(target_binary).resolve()
                # Look for version directory pattern in the path
                for part in tb.parts:
                    if re.match(r'tiff-\d+\.\d+\.\d+', part):
                        # Found version dir, search there first
                        ver_dir = tb.parent
                        while ver_dir.name != part and ver_dir != ver_dir.parent:
                            ver_dir = ver_dir.parent
                        if ver_dir.name == part:
                            candidate = ver_dir / 'tools' / p.name
                            if candidate.is_file():
                                p = candidate
                            else:
                                candidate = ver_dir / 'libtiff' / p.name
                                if candidate.is_file():
                                    p = candidate
                        break
            
            if not p.is_file():
                for ver_dir in Path('.').glob('*-versions'):
                    for match in ver_dir.rglob(p.name):
                        if match.is_file():
                            p = match
                            break
                    if p.is_file():
                        break
    if not p.is_file():
        return None

    try:
        lines = p.read_text(errors='replace').splitlines()
    except Exception:
        return None

    # Guard: when the caller knows the analysis' expected statement text,
    # make sure the resolved file really contains it at the requested line.
    # A wrong-version same-named file (relative-name resolution) would
    # otherwise silently yield the wrong variables.
    if expected_statement and not _resolved_in_version_root:
        _exp = ' '.join(str(expected_statement).split())[:40]
        if _exp:
            _lo = max(0, target_line - 3)
            _hi = min(len(lines), target_line + 2)
            _window = ' '.join(' '.join(lines[_lo:_hi]).split())
            if _exp not in _window:
                return None

    n = len(lines)

    # Fallback: if target_line is outside file range or doesn't contain a fork,
    # search for common fork patterns like "if (in == NULL)"
    if target_line < 1 or target_line > n:
        target_line = None

    # If the target line doesn't contain a fork pattern, keep it as-is
    # Don't override with a different fork — use the divergence analyzer's result
    if target_line:
        stripped = lines[target_line - 1].strip()
        # If it's not an if/switch/case, still use it (it may be the body of a fork)

    if not target_line:
        return None

    # Find the start of the statement
    # If target line is an if/switch/case, search backward for full block
    # If target line is a regular statement (assignment, function call), use just that line
    target_stripped = lines[target_line - 1].strip()
    is_if_like = re.match(r'if\s*\(|switch\s*\(|case\s+', target_stripped)

    if is_if_like:
        if target_stripped.startswith('case ') or target_stripped.startswith('default:'):
            # Search backward for case/preprocessor/if
            start = target_line - 1
            for i in range(target_line - 1, max(0, target_line - search_range) - 1, -1):
                stripped = lines[i].strip()
                if stripped.startswith('case ') or stripped.startswith('default:'):
                    start = i + 1
                    break
                if stripped.startswith('break;') or stripped.startswith('goto ') or stripped.startswith('return'):
                    start = i + 1
                    break
                if re.match(r'^[a-zA-Z_]\w*\s*\(', stripped) and not stripped.startswith('if'):
                    start = i
                    break
                if stripped.startswith('#') and not stripped.startswith('#if') and not stripped.startswith('#else') and not stripped.startswith('#endif'):
                    start = i + 1
                    break
                # A comment block above the fork line ends the enclosing
                # statement — never start the span inside one.
                if stripped.startswith('/*') or stripped.startswith('//') \
                        or '*/' in stripped:
                    start = i + 1
                    break
                start = i
        else:
            # Plain ``if (...)`` fork: the fork IS the condition at the fork
            # line.  Do NOT expand backward — preceding statements (e.g. an
            # adjacent ``if (!(tif->tif_flags&TIFF_BIGTIFF))`` two lines
            # above) are unrelated and would corrupt the fork statement and
            # its variables.
            start = target_line - 1
    else:
        # Regular statement — use just this line (don't expand backward)
        start = target_line - 1

    # Find the end of the statement (look forward for break/return/next case)
    end = target_line
    depth = 0
    # Find the end of the statement
    if is_if_like:
        # Look forward for break/return/next case.  The statement ends at
        # the first depth-0 line that terminates it: a comment block (the
        # fork span must never swallow comment words), a `;`/`{` terminator
        # (the if's body opens), or the pre-existing break/goto/return/case
        # stops.  Paren balance is NOT tracked here (matching the original
        # behavior), so multi-line conditions still scan past continuation
        # lines.
        end = target_line
        depth = 0
        for i in range(target_line - 1, min(n, target_line + search_range)):
            stripped = lines[i].strip()
            if stripped.startswith('#if'):
                depth += 1
            elif stripped.startswith('#endif'):
                depth -= 1
            if depth == 0:
                if stripped.startswith('/*') or stripped.startswith('//') \
                        or '*/' in stripped:
                    end = i
                    break
                if stripped.endswith(';') or stripped.endswith('{'):
                    end = i + 1
                    break
                if stripped.startswith('break;') or stripped.startswith('goto ') or stripped.startswith('return'):
                    end = i + 1
                    break
                if stripped.startswith('case ') or stripped.startswith('default:'):
                    end = i
                    break
                if i > target_line - 1 and re.match(r'^[a-zA-Z_]\w*\s*\(', stripped) and not stripped.startswith('if'):
                    end = i
                    break
            end = i + 1
    else:
        # Regular statement — just this line (handle multi-line statements)
        end = target_line
        depth = 0
        for i in range(target_line - 1, min(n, target_line + 5)):
            stripped = lines[i].strip()
            depth += stripped.count('(') - stripped.count(')')
            if depth <= 0 and (stripped.endswith(';') or stripped.endswith('{')):
                end = i + 1
                break
            end = i + 1

    # Extract the full statement text
    full_stmt = '\n'.join(lines[start:end])

    # Extract variables from ALL branches (including #else)
    variables = extract_variables_from_statement(full_stmt)

    return full_stmt, variables, target_line


def read_trace_json(json_path):
    """Read lcs_trace.py JSON output (with divergence) and extract fork info.

    Handles two formats:
    1. Main JSON with 'divergence' key (merged by lcs_trace.py)
    2. Standalone .diverge.json file
    """
    with open(json_path) as f:
        data = json.load(f)

    div = data.get('divergence', data)

    if not div or not isinstance(div, dict):
        return None

    root_cause_file = div.get('root_cause_file_b') or div.get('root_cause_file')
    root_cause_line = div.get('root_cause_line_b') or div.get('root_cause_line')
    root_cause_stmt = div.get('root_cause_statement_b', '')

    if not root_cause_file or not root_cause_line:
        return None

    input_file = div.get('input_file', '')
    binary = div.get('binary_b', '')
    binary_a = div.get('binary_a', '')
    args = div.get('args_b', [])

    variables = []
    full_fork_stmt = root_cause_stmt

    is_code_change = div.get('_code_change', False)
    orig_is_code_change = is_code_change  # preserve for later

    # Save the original fork line from divergence JSON
    original_fork_line = root_cause_line

    source_file = root_cause_file
    if 'polytracker_offsets' in div:
        pt = div['polytracker_offsets']
        source_file = pt.get('source_file', root_cause_file)
        root_cause_line = pt.get('source_line', root_cause_line)

    if is_code_change:
        # Code-change fork: extract variables directly from the fork statement
        # Don't search for other forks — use the divergence analyzer's result
        if root_cause_stmt:
            variables = extract_variables_from_statement(root_cause_stmt)
            full_fork_stmt = root_cause_stmt
        # Also try reading the source line for a more complete statement
        if source_file and root_cause_line:
            result = read_source_fork_statement(
                source_file, root_cause_line, target_binary=binary, search_range=5)
            if result:
                full_fork_stmt, vars_from_src, actual_line = result
                if vars_from_src:
                    variables = vars_from_src
                    root_cause_line = actual_line
        # Set reference line from divergence JSON
        ref_line = div.get('root_cause_line_a')
        if ref_line:
            original_fork_line = ref_line
        print(f'  [*] Code-change fork: v4.4.0: {div.get("root_cause_statement_a", "N/A")}')
        print(f'  [*] Code-change fork: v4.0.8: {div.get("root_cause_statement_b", "N/A")}')
        if variables:
            print(f'  [*] Extracted {len(variables)} variables from code-change fork statement')
    elif source_file and root_cause_line:
        # Data-dependent fork: read source for the full fork statement.
        # Pass the analysis' statement (when non-synthetic) so a wrong
        # same-named source file from another version is rejected.
        _exp_stmt = None
        if root_cause_stmt and not div.get('statement_b_synthetic'):
            _exp_stmt = root_cause_stmt
        result = read_source_fork_statement(
            source_file, root_cause_line, target_binary=binary,
            search_range=100, expected_statement=_exp_stmt)
        if result:
            full_fork_stmt, variables, actual_line = result
            root_cause_line = actual_line
            print(f'  [*] Read full fork statement from source: {source_file}:{root_cause_line}')
            print(f'  [*] Extracted {len(variables)} variables from all branches')

    # Fallback: extract from the JSON's fork statement
    if not variables:
        # The divergence analyzer may already have resolved the fork
        # variables (e.g. the one-hop producer fallback supplies the RHS
        # variables of the assignment that produced a status-code operand
        # like ``err``).  Prefer those over re-extracting, which filters
        # exactly the operands that fallback supplied.
        div_vars = div.get('variables') or []
        for v in div_vars:
            if v and v not in variables:
                variables.append(v)

        if not variables and 'polytracker_offsets' in div:
            pt = div['polytracker_offsets']
            fork_stmt = pt.get('fork_statement', root_cause_stmt)
            if fork_stmt:
                variables = extract_variables_from_statement(fork_stmt)
                full_fork_stmt = fork_stmt

        if not variables and root_cause_stmt:
            variables = extract_variables_from_statement(root_cause_stmt)
            full_fork_stmt = root_cause_stmt

    # Reference-side line/file (dynamic-locator forks carry both sides).
    ref_line = div.get('root_cause_line_a')
    if ref_line:
        original_fork_line = ref_line

    return {
        'binary_b': binary,
        'binary_a': div.get('binary_a', ''),
        'target_binary': div.get('binary_b', ''),
        'target_args': div.get('args_b', []),
        'input_file': input_file,
        'fork_file': root_cause_file,
        'fork_line': root_cause_line,
        'original_fork_line': original_fork_line,
        'ref_fork_file': div.get('root_cause_file_a', ''),
        'fork_stmt': full_fork_stmt,
        'program_args': args,
        'variables': variables,
        'root_cause_function': div.get('root_cause_function', ''),
        'poly_track_function': div.get('poly_track_function', ''),
        '_code_change': orig_is_code_change,
        'dynamic_fork': div.get('dynamic_fork'),
        'root_cause_statement_a': div.get('root_cause_statement_a', ''),
        'root_cause_statement_b': div.get('root_cause_statement_b', ''),
        'version_a': div.get('version_a', ''),
        'version_b': div.get('version_b', ''),
    }


# ---------------------------------------------------------------------------
# TIFF IFD parser
# ---------------------------------------------------------------------------

_TIFF_TYPE_SIZES = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 1, 7: 1, 8: 2, 9: 4, 10: 8, 11: 4, 12: 8}
_TIFF_TYPE_FORMATS = {1: 'B', 2: 'c', 3: 'H', 4: 'I', 5: 'II', 6: 'b', 7: 'B', 8: 'h', 9: 'i', 10: 'd', 11: 'f', 12: 'd'}
_TIFF_TAG_NAMES = {
    256: 'ImageWidth', 257: 'ImageLength', 258: 'BitsPerSample',
    259: 'Compression', 262: 'PhotometricInterpretation',
    273: 'StripOffsets', 274: 'Orientation', 277: 'SamplesPerPixel',
    278: 'RowsPerStrip', 279: 'StripByteCounts',
    282: 'XResolution', 283: 'YResolution', 284: 'PlanarConfiguration',
    296: 'ResolutionUnit', 297: 'PageNumber',
    317: 'Predictor', 330: 'SubIFDs', 339: 'SampleFormat',
}

# A value encoding that appears more than this many times in the program's
# read regions is not distinctive (e.g. 1 -> "01 00 00 00" matches zero
# padding everywhere) and would only produce noisy offsets.
MAX_PATTERN_OCCURRENCES = 6


def _slot_width(file_data, off, val, endian, min_w, size_hint=None, max_slot=8):
    """Widest plausible integer slot at ``off`` whose bytes still encode ``val``.

    A value parsed from a file field may occupy a wider on-disk slot than its
    minimal encoding — e.g. the 4-byte TIFF header IFD-offset field holding
    value 2 is ``02 00 00 00``, so the minimal 2-byte match would report only
    half of the field.  The variable's own in-memory width (``size_hint`` from
    GDB) is preferred, then the standard integer widths 8/4/2; each candidate
    is only accepted when the surrounding file bytes actually verify it (the
    wider slot must decode to the same value: zero/sign extension).
    """
    def _enc_ok(w):
        if w < min_w or w > max_slot or off + w > len(file_data):
            return False
        if val >= 0:
            if val >= (1 << (8 * w)):
                return False
        elif val < -(1 << (8 * w - 1)):
            return False
        return (int.from_bytes(file_data[off:off + w], endian)
                == (val & ((1 << (8 * w)) - 1)))

    order = []
    if size_hint in (1, 2, 4, 8) and size_hint >= min_w:
        order.append(size_hint)
    for w in (8, 4, 2):
        if w not in order:
            order.append(w)
    for w in order:
        if _enc_ok(w):
            return w
    return min_w


def map_fork_variables_to_offsets(variables, reads, file_data, max_hits=16):
    """Dynamic fork-variable -> input file offset mapping (generic).

    For every fork variable captured at the breakpoint (name/value/size):

      * pointer values — if the VALUE points inside a recorded read buffer
        (``buf_addr .. buf_addr+size``), the variable points straight into
        bytes read from the input; file offset =
        ``read_offset + (value - buf_addr)``;
      * scalar values — search the input bytes that the program actually
        read for the value's byte encoding (4/2/8-byte, little/big
        endian): the variable's value was parsed from those bytes.

    Small values (e.g. 1, 2) encode as zero-heavy patterns ("01 00 00 00")
    that occur in many places of any real file, so a rarity filter rejects
    patterns whose total occurrence count in the read regions exceeds
    ``MAX_PATTERN_OCCURRENCES`` — only distinctive values (real field
    contents like a sample rate or data size) produce candidate offsets.

    Each hit carries a ``tier`` describing how strongly it is tied to the
    fork statement, so precision can be measured per layer:

      * ``A_direct_pointer`` — the value IS an address inside a recorded
        read buffer (exact provenance, no pattern guessing);
      * ``B_value_field``   — a single (unambiguous) multi-byte field whose
        full slot was verified in the read regions;
      * ``C_value_pattern`` — a narrow or ambiguous value-pattern match
        (several candidate locations for the same value = likely noise).

    No file-format knowledge is used.  Returns
    ``{var: [{'offset', 'width', 'match_width', 'method', 'tier'}, ...]}``.
    """
    out = {}
    if not variables:
        return out
    # Normalize the read regions into non-overlapping intervals: the same
    # file region is often read repeatedly, so raw read records inflate the
    # pattern-occurrence counts and the match list.
    _raw = sorted((r['offset'], r['offset'] + r['size'])
                  for r in reads
                  if r.get('offset') is not None and r['offset'] >= 0
                  and r.get('size'))
    ranges = []
    for s, e in _raw:
        if not ranges or s > ranges[-1][1]:
            ranges.append([s, e])
        else:
            ranges[-1][1] = max(ranges[-1][1], e)
    if not ranges:
        return out

    # Pattern occurrence counts (per encoding), used by the rarity filter.
    occ_cache = {}

    def _pattern_occurrences(pat):
        if pat in occ_cache:
            return occ_cache[pat]
        occ = 0
        for (rs, re_) in ranges:
            if rs >= len(file_data):
                continue
            occ += file_data[rs:min(re_, len(file_data))].count(pat)
        occ_cache[pat] = occ
        return occ

    for var in variables:
        name = var.get('name')
        val = var.get('val')
        if name is None or val is None:
            continue
        hits = []

        # 1) Pointer value inside a recorded read buffer.
        for r in reads:
            b = r.get('buf_addr')
            if (b is None or not r.get('size') or r.get('offset') is None
                    or r['offset'] < 0):
                continue
            if b <= val < b + r['size']:
                hits.append({'offset': r['offset'] + (val - b),
                             'width': 0,
                             'method': 'points_into_read_buffer'})

        # 2) Scalar value byte pattern inside the actually-read regions.
        #    4-byte little-endian first (C ints dominate), then wider
        #    widths; 1-byte last (noisy for small values).  Negative ints
        #    (e.g. a corrupt -21692 Hz sample-rate field) are matched by
        #    their two's-complement encoding.  Multi-byte hits are expanded
        #    to the FULL value span (e.g. a 4-byte sample rate at 0x18 maps
        #    0x18..0x1b) so byte-mutation sweeps the whole field, including
        #    the sign byte.
        match_starts = []
        if not hits and file_data:
            # Try the value's MINIMAL encoding width first (a 4-byte "01 00
            # 00 00" pattern for value 1 matches zero padding everywhere; the
            # natural width is far more specific), then one byte wider as a
            # fallback for fields stored in a larger slot.
            if val >= 0:
                min_w = max(1, (val.bit_length() + 7) // 8)
            else:
                min_w = 2
                while min_w <= 8 and val < -(1 << (8 * min_w - 1)):
                    min_w += 1
            size_hint = var.get('size')
            for width, endian in (
                    (min_w, 'little'), (min_w, 'big'),
                    (min_w + 1, 'little'), (min_w + 1, 'big'),
                    (min_w + 2, 'little'), (min_w + 2, 'big')):
                if width > 8:
                    continue
                if val >= 0 and val >= (1 << (8 * width)):
                    continue
                if val < 0 and val < -(1 << (8 * width - 1)):
                    continue
                enc = val & ((1 << (8 * width)) - 1)
                if enc == 0:
                    continue  # a zero value matches every zero byte — no signal
                if width == 1 and enc < 16:
                    continue  # a byte 0x00-0x0f matches everywhere
                try:
                    pat = enc.to_bytes(width, endian)
                except OverflowError:
                    continue
                if _pattern_occurrences(pat) > MAX_PATTERN_OCCURRENCES:
                    continue  # too common in the read regions — no signal
                for (rs, re_) in ranges:
                    seg = file_data[rs:re_]
                    pos = seg.find(pat)
                    while pos != -1:
                        off = rs + pos
                        # Extend the minimal match to the full on-disk slot
                        # (GDB type width preferred, byte-verified) so the
                        # whole field is reported, not half of it.  The lower
                        # bound is the value's minimal encoding width, so a
                        # fallback match found at a non-standard search width
                        # (e.g. min_w+2 for negative values) still snaps to a
                        # standard slot when the bytes verify it.
                        slot_w = _slot_width(file_data, off, val, endian, min_w,
                                             size_hint=size_hint)
                        if off not in match_starts:
                            match_starts.append(off)
                        # A byte-verified wider slot marks a real field-shaped
                        # encoding even when the same value also appears at
                        # other (noisy) locations; a bare minimal-width match
                        # is only promoted when it is the single match.
                        _mt = 'B_value_field' if slot_w > width else None
                        for span_off in range(off, off + slot_w):
                            if all(h['offset'] != span_off for h in hits):
                                hits.append({'offset': span_off, 'width': slot_w,
                                             'match_width': width,
                                             'method': f'value_bytes_{endian}',
                                             'tier': _mt})
                        if len(hits) >= max_hits:
                            break
                        pos = seg.find(pat, pos + 1)
                    if len(hits) >= max_hits:
                        break
                if hits:
                    # Positive values: the minimal-width match is the precise
                    # field — stop.  Negative values: keep going until the
                    # full field width (min_w+2, e.g. the 4-byte slot holding
                    # a negative sample rate) so the sign bytes are covered.
                    if val >= 0 or width >= min_w + 2:
                        break
        if hits:
            if any(h.get('method') == 'points_into_read_buffer' for h in hits):
                _tier = 'A_direct_pointer'
            else:
                _tier = ('B_value_field' if len(match_starts) == 1
                         else 'C_value_pattern')
            for h in hits:
                if h.get('tier') is None:
                    h['tier'] = _tier
            out[name] = hits
    return out


# Fork variables that are the return value of a file-reading function
# (e.g. ``in = TIFFOpen(argv[optind], "r")``).  When the function fails it
# returns NULL and the fork ``if (in == NULL)`` is taken; the file regions
# the function actually read (the positioned pread64/read calls captured
# during the GDB run) are exactly what determined that NULL return.
_FILE_FUNC_RETURN_VARS = {
    'in': 'TIFFOpen', 'out': 'TIFFOpen', 'tif': 'TIFFOpen',
}


def map_file_read_return_offsets(variables, reads, fork_vars=None, max_hits=32,
                                 deep_reads=None, file_size=None):
    """Map a fork variable that is the NULL return value of a file-reading
    function (TIFFOpen) to the positioned file reads captured during the run.

    This is the fully-dynamic counterpart of the removed ``analyze_offsets``
    Case 5: a variable whose captured value is 0 (NULL) and whose name is a
    known file-handle return (in/out/tif) has no byte-pattern signal (a zero
    matches every zero byte) and no read-buffer pointer — but the positioned
    reads that happened before the fork are the input bytes that determined
    the NULL.

    ``deep_reads`` are the reads observed INSIDE the file-open function
    (Step 3.5 deep trace): those are the specific reads that decided the
    return value, so they take priority over the broader pre-fork read set.
    Reads that go BEYOND the file boundary (``offset + size > file_size``)
    are flagged as the actual failure cause (an IO error inside TIFFOpen
    makes it return NULL).

    Tiers: ``A_deep_open_critical`` (beyond-file read = actual failure
    cause) > ``A_deep_open_read`` (a read inside the open function) >
    ``C_open_read_fallback`` (whole-run read set, used only when the deep
    trace produced nothing).  Returns
    ``{var: [{'offset','width','method','tier'}, ...]}``.
    """
    out = {}
    if not reads:
        return out
    captured = {v.get('name'): v.get('val') for v in variables if v.get('name')}
    names = list(fork_vars) if fork_vars else list(captured)

    def _collect(read_list):
        positioned = sorted({r['offset'] for r in read_list
                             if r.get('offset') is not None and r['offset'] >= 0
                             and r.get('size')})
        critical = []
        normal = []
        for off in positioned:
            sz = next((r.get('size') for r in read_list
                       if r.get('offset') == off), 0)
            if file_size and off + sz > file_size:
                critical.append(off)
            else:
                normal.append(off)
        return critical, normal

    for name in names:
        if name not in _FILE_FUNC_RETURN_VARS:
            continue
        # A variable is NULL either when captured as 0 or when it is a fork
        # variable the dump could not evaluate (NULL handle) — in both cases
        # the guard ``if (in == NULL)`` is decided by the open-time reads.
        if name in captured and captured[name] != 0:
            continue
        hits = []
        if deep_reads:
            critical, normal = _collect(deep_reads)
        else:
            critical, normal = [], []
        for off in critical:  # beyond-file reads = the actual failure cause
            if len(hits) >= max_hits:
                break
            hits.append({'offset': off, 'width': 0,
                         'tier': 'A_deep_open_critical',
                         'method': f'return_of_{_FILE_FUNC_RETURN_VARS[name]}_critical_read'})
        for off in normal:
            if len(hits) >= max_hits:
                break
            hits.append({'offset': off, 'width': 0,
                         'tier': 'A_deep_open_read',
                         'method': f'return_of_{_FILE_FUNC_RETURN_VARS[name]}'})
        if not hits:
            # Fall back to the pre-fork reads when no deep-trace reads exist.
            positioned = sorted({r['offset'] for r in reads
                                 if r.get('offset') is not None and r['offset'] >= 0
                                 and r.get('fd', -1) >= 3 and r.get('size')})
            for off in positioned:
                if len(hits) >= max_hits:
                    break
                hits.append({'offset': off, 'width': 0,
                             'tier': 'C_open_read_fallback',
                             'method': f'return_of_{_FILE_FUNC_RETURN_VARS[name]}'})
        if hits:
            out[name] = hits
    return out


def parse_tiff_ifd(filepath):
    """Parse TIFF IFD and return tag info with file offsets.

    Returns dict: tag_id -> {name, value, entry_offset, type, count}
    """
    with open(filepath, 'rb') as f:
        data = f.read()

    if len(data) < 8:
        return None

    byte_order = data[0:2]
    if byte_order not in (b'II', b'MM'):
        return None

    little = byte_order == b'II'
    fmt = '<' if little else '>'

    magic = struct.unpack_from(fmt + 'H', data, 2)[0]
    if magic not in (42, 43):
        return None

    ifd_offset = struct.unpack_from(fmt + 'I', data, 4)[0]

    tags = {}
    num_entries = struct.unpack_from(fmt + 'H', data, ifd_offset)[0]

    for i in range(num_entries):
        entry_offset = ifd_offset + 2 + i * 12
        tag = struct.unpack_from(fmt + 'H', data, entry_offset)[0]
        typ = struct.unpack_from(fmt + 'H', data, entry_offset + 2)[0]
        count = struct.unpack_from(fmt + 'I', data, entry_offset + 4)[0]
        value_raw = struct.unpack_from(fmt + 'I', data, entry_offset + 8)[0]

        type_size = _TIFF_TYPE_SIZES.get(typ, 0)
        total_bytes = type_size * count
        value_offset_in_file = entry_offset + 8

        if total_bytes <= 4:
            value = value_raw
        elif total_bytes > len(data) or count > 10000:
            value = value_raw
        else:
            val_fmt = fmt + _TIFF_TYPE_FORMATS.get(typ, 'B') * count
            try:
                value = struct.unpack_from(val_fmt, data, value_raw)
            except:
                value = value_raw

        name = _TIFF_TAG_NAMES.get(tag, f'Tag_{tag}')
        if tag not in tags:
            tags[tag] = {
                'name': name,
                'value': value,
                'entry_offset': entry_offset,
                'value_offset_in_file': value_offset_in_file if total_bytes <= 4 else value_raw,
                'type': typ,
                'count': count,
            }
        else:
            # Duplicate tag in same IFD — keep first occurrence (what the TIFF library reads).
            pass

    return tags


def parse_tiff_entries(filepath):
    """Parse ALL TIFF IFD entries (including duplicates) as a list.

    Each entry: {'tag', 'name', 'type', 'count', 'value', 'entry_offset'}.
    """
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
    except Exception:
        return []
    if len(data) < 8 or data[0:2] not in (b'II', b'MM'):
        return []
    fmt = '<' if data[0:2] == b'II' else '>'
    magic = struct.unpack_from(fmt + 'H', data, 2)[0]
    if magic not in (42, 43):
        return []
    ifd_offset = struct.unpack_from(fmt + 'I', data, 4)[0]
    if ifd_offset + 2 > len(data):
        return []
    num_entries = struct.unpack_from(fmt + 'H', data, ifd_offset)[0]
    entries = []
    for i in range(num_entries):
        eo = ifd_offset + 2 + i * 12
        if eo + 12 > len(data):
            break
        tag = struct.unpack_from(fmt + 'H', data, eo)[0]
        typ = struct.unpack_from(fmt + 'H', data, eo + 2)[0]
        count = struct.unpack_from(fmt + 'I', data, eo + 4)[0]
        value_raw = struct.unpack_from(fmt + 'I', data, eo + 8)[0]
        entries.append({
            'tag': tag,
            'name': _TIFF_TAG_NAMES.get(tag, f'Tag_{tag}'),
            'type': typ,
            'count': count,
            'value': value_raw,
            'entry_offset': eo,
        })
    return entries


def analyze_tiff_tags(tags):
    """Extract key TIFF metadata from parsed tags."""
    result = {}
    for tag_id in (256, 257, 259, 273, 277, 278, 279):
        if tag_id in tags:
            t = tags[tag_id]
            result[t['name']] = {
                'tag_id': tag_id,
                'value': t['value'],
                'entry_offset': t['entry_offset'],
            }
    return result


def analyze_tiff_tags_all(tags):
    """Return ALL parsed TIFF tags (for corruption analysis)."""
    result = {}
    for tag_id, t in tags.items():
        name = t['name']
        result[name] = {
            'tag_id': tag_id,
            'value': t['value'],
            'entry_offset': t['entry_offset'],
            'type': t.get('type', 0),
            'count': t.get('count', 0),
        }
    return result


def parse_tiff_error_tag(stderr_text):
    """Parse a TIFF error message to find the failing tag name.

    Handles patterns like:
      TIFFFetchStripThing: IO error during reading of "StripByteCounts".
      TIFFReadDirectory: Unknown field with tag 279 (0x117) encountered.
    Returns the tag NAME (e.g. 'StripByteCounts') or None.
    """
    if not stderr_text:
        return None
    # Look for all "IO error during reading of" matches - return the last one
    # (the last one is usually the critical error causing failure)
    io_errors = list(re.finditer(r'IO error during reading of\s*"([^"]+)"', stderr_text))
    if io_errors:
        return io_errors[-1].group(1)
    # Then look for "reading of" (other read errors) - return last match
    read_errors = list(re.finditer(r'reading of\s*"([^"]+)"', stderr_text))
    if read_errors:
        return read_errors[-1].group(1)
    # Finally, unknown fields - return last match
    unknown_fields = list(re.finditer(r'Unknown field with tag\s+(\d+)', stderr_text))
    if unknown_fields:
        tag_id = int(unknown_fields[-1].group(1))
        return _TIFF_TAG_NAMES.get(tag_id, f'Tag_{tag_id}')
    return None


def map_tag_name_to_corruption(tag_name, entries, file_size):
    """Given a failing tag name, return (offset ranges, description) for its
    corrupted entry fields (e.g. a count that overruns the file).

    `entries` is the list from parse_tiff_entries (includes duplicates).
    """
    if not tag_name or not entries:
        return [], None
    infos = [e for e in entries if e.get('name') == tag_name]
    if not infos:
        return [], None
    for info in infos:
        entry = info['entry_offset']
        typ = info.get('type', 0)
        cnt = info.get('count', 0)
        type_size = _TIFF_TYPE_SIZES.get(typ, 1)
        total = cnt * type_size
        if total > file_size:
            # The count overruns the file — that's the corruption.
            offs = list(range(entry + 4, entry + 8))  # count field (4 bytes)
            desc = (f'{tag_name}({info["tag"]}) count={cnt} -> reads '
                    f'{total} bytes but file is {file_size} bytes')
            return offs, desc
    # No overrun found: report the value field of the (first) entry.
    info = infos[0]
    entry = info['entry_offset']
    offs = list(range(entry, entry + 12))
    desc = f'{tag_name}({info["tag"]}) entry'
    return offs, desc


def detect_suspicious_tiff_tags(input_file):
    """Detect suspicious/corrupted TIFF tags in the input file.

    Returns list of (tag_name, entry_offset, description) for suspicious tags.
    """
    if not input_file or not os.path.isfile(input_file):
        return []

    try:
        entries = parse_tiff_entries(input_file)
    except Exception:
        return []

    if not entries:
        return []

    fsize = os.path.getsize(input_file)
    suspicious = []

    # Known tags with expected value ranges
    VALUE_LIMITS = {
        256: (1, 0x100000),     # ImageWidth
        257: (1, 0x100000),     # ImageLength
        277: (1, 100),          # SamplesPerPixel
        278: (1, 0x100000),     # RowsPerStrip
        259: (1, 100),          # Compression
        262: (0, 30),           # PhotometricInterpretation
    }

    for info in entries:
        tag = info['tag']
        name = info['name']
        typ = info.get('type', 0)
        cnt = info.get('count', 0)
        val = info.get('value', 0)
        entry = info['entry_offset']

        # Check 1: Unknown tag (not in known tags list)
        KNOWN_TAGS = {
            256, 257, 258, 259, 262, 266, 273, 274, 277, 278, 279, 282, 283,
            296, 320, 321, 322, 323, 324, 325, 327, 328, 329, 330, 332, 333,
            338, 339, 347, 512, 513, 514, 515, 516, 517, 518, 519, 520, 521,
            529, 530, 531, 532, 559, 562, 2048, 2049, 2050, 2051, 2052,
            33723, 34377, 34665, 34675, 34853, 37385, 37386, 37387, 37388,
            37389, 37390, 37392, 37393, 42112, 42113,
        }
        if tag not in KNOWN_TAGS and tag != 0:
            suspicious.append((name, entry, f'Unknown tag {tag} (0x{tag:x})'))
            continue

        # Check 2: Tag 0 (invalid)
        if tag == 0:
            suspicious.append((name, entry, f'Invalid tag 0'))
            continue

        # Check 3: Value out of expected range
        if tag in VALUE_LIMITS:
            lo, hi = VALUE_LIMITS[tag]
            if isinstance(val, int) and (val < lo or val > hi):
                suspicious.append((name, entry,
                    f'{name}={val} out of range [{lo}, {hi}]'))
                continue

        # Check 4: Count too large (potential buffer overrun)
        if cnt > 10000:
            type_size = _TIFF_TYPE_SIZES.get(typ, 1)
            total = cnt * type_size
            if total > fsize:
                suspicious.append((name, entry,
                    f'{name} count={cnt} -> reads {total} bytes but file is {fsize} bytes'))
                continue

        # Check 5: StripByteCounts = 0 (common in crafted exploits)
        if tag == 279 and isinstance(val, int) and val == 0:
            suspicious.append((name, entry,
                f'StripByteCounts=0 (will cause read of 0 bytes)'))
            continue

    return suspicious


# ---------------------------------------------------------------------------
# GDB script: dynamic tracing + variable collection
# ---------------------------------------------------------------------------

GDB_SCRIPT = r"""set pagination off
set confirm off
set print finish off
set disable-randomization off
set breakpoint pending on

catch syscall read
catch syscall pread64

commands 2
  silent
  if $rdi >= 3 && $rdx > 0 && $rdx < 100000
    printf "PREAD64 fd=%d offset=%ld size=%ld buf=0x%lx\n", $rdi, $r10, $rdx, $rsi
  end
  continue
end

commands 1
  silent
  if $rdi >= 3 && $rdx > 0 && $rdx < 100000
    python
import gdb
try:
    pid = gdb.selected_inferior().pid
    fd = int(gdb.parse_and_eval("$rdi"))
    sz = int(gdb.parse_and_eval("$rdx"))
    buf = int(gdb.parse_and_eval("$rsi"))
    pos = -1
    try:
        # At the syscall-entry catchpoint the fd position has not advanced
        # yet — /proc/<pid>/fdinfo/<fd> reports where this read() starts.
        with open("/proc/%d/fdinfo/%d" % (pid, fd)) as f:
            for ln in f:
                if ln.startswith("pos:"):
                    pos = int(ln.split()[1])
                    break
    except Exception:
        pass
    print("IO fd=%d offset=%d size=%d buf=0x%x" % (fd, pos, sz, buf))
except Exception:
    pass
end
  end
  continue
end

break {fork_spec}
commands
  silent
  printf "FORK_REACHED\n"
  printf "FRAME_0_ARGS\n"
  info args
  printf "ARGS_END\n"
{var_dump}
  printf "STRIP_OFFSET_START\n"
{strip_offset}
  printf "STRIP_OFFSET_END\n"
  printf "BACKTRACE_START\n"
  backtrace full 10
  printf "BACKTRACE_END\n"
  printf "HEAP_SCAN_START\n"
{heap_scan}
  printf "HEAP_SCAN_END\n"
  info proc mappings
  printf "MAPPINGS_END\n"
  printf "FORK_DONE\n"
  quit
end

run {run_args}
"""


def build_var_dump_block(variables):
    """Build GDB commands to dump variable values with error handling.

    Uses GDB Python to safely evaluate each variable. If a variable doesn't
    exist in the current binary (e.g., a struct member from a different
    version), the error is caught and the variable is skipped.

    Struct/union variables (e.g. ``track->f`` — the format struct that feeds
    the divisor of a division-by-zero) are expanded into their scalar fields
    (``track->f.channelCount``, ``track->f.sampleWidth``, ...) so the exact
    input-derived bytes are traced instead of dropping the whole struct.

    Pointer variables are dereferenced one level, but ONLY into fields that
    the fork variables reference (e.g. ``tif`` is only expanded to
    ``tif->tif_dir`` when the fork variables include ``tif->tif_dir``) —
    otherwise the whole handle's internal state (``tif->tif_header``,
    ``tif->tif_row``, ...) would produce value matches at structurally
    unrelated file offsets.  Pointers with no referenced fields (e.g. lame's
    ``gf``) are expanded fully.
    """
    if not variables:
        return ''
    # Build a Python list of variable expressions for GDB Python
    var_list = ', '.join(f'"{v.replace(chr(34), chr(92)+chr(34))}"' for v in variables)
    return f"""  python
import gdb
_vars = [{var_list}]
_roots = set(_vars)
def _eval_var(_v):
    # Evaluate in the current (fork) frame first; context expressions such as
    # image->length live in an ancestor frame when the fork statement only
    # uses callee locals (start/end/cols), so walk up a few frames.
    try:
        return gdb.parse_and_eval(_v)
    except Exception:
        pass
    try:
        _sel = gdb.selected_frame()
    except Exception:
        return None
    _f = _sel.older() if _sel is not None else None
    _n = 0
    _val = None
    while _f is not None and _n < 4:
        try:
            _f.select()
            _val = gdb.parse_and_eval(_v)
            break
        except Exception:
            _val = None
            _f = _f.older()
            _n += 1
    try:
        if _sel is not None:
            _sel.select()
    except Exception:
        pass
    return _val

def _dump_var(_v, _depth=0):
    _val = _eval_var(_v)
    if _val is None:
        return
    _t = _val.type
    # Resolve typedefs (e.g. AFframecount -> unsigned long, or a typedef'd
    # struct) so code checks see the underlying type.
    try:
        _t = _t.strip_typedefs()
    except Exception:
        pass
    if _t.code in (gdb.TYPE_CODE_STRUCT, gdb.TYPE_CODE_UNION):
        if _depth >= 2:
            return
        for _fld in _t.fields():
            if getattr(_fld, 'is_static', False) or getattr(_fld, 'artificial', False):
                continue
            try:
                _dump_var(_v + '.' + _fld.name, _depth + 1)
            except Exception:
                continue
        return
    if _t.code in (gdb.TYPE_CODE_PTR,):
        # Handle pointers (e.g. lame_encoder's gf -> gf->in_samplerate):
        # dereference one level and expand the pointee's scalar fields.
        if _depth >= 2:
            return
        try:
            _pv = int(_val)
        except Exception:
            return
        if _pv == 0:
            # NULL pointer (e.g. `in` when TIFFOpen fails): dereference()
            # still reports the pointee's type (a pure type op) but every
            # field read would fail, so no scalar is ever printed.  Capture
            # the pointer VALUE itself (0) — the fork operand ``if (in ==
            # NULL)`` is exactly that value, and it must be recorded to map
            # the NULL return back to the input file bytes.
            try:
                _addr = int(_val.address) if _val.address else 0
            except Exception:
                _addr = 0
            print("VAR_NAME %s" % _v)
            print("VAR_ADDR 0x%x" % _addr)
            print("VAR_VAL %d" % _pv)
            print("VAR_SIZE %d" % _val.type.sizeof)
            return
        try:
            _dt = _val.dereference().type.strip_typedefs()
        except Exception:
            _dt = None
        if _dt is not None and _dt.code in (gdb.TYPE_CODE_STRUCT, gdb.TYPE_CODE_UNION):
            _referenced = [_r for _r in _roots if _r.startswith(_v + '->')]
            _nf = 0
            for _fld in _dt.fields():
                if _nf >= 32:  # cap per pointee to limit noise
                    break
                if getattr(_fld, 'is_static', False) or getattr(_fld, 'artificial', False):
                    continue
                _fname = _v + '->' + _fld.name
                if _referenced and not any(_r == _fname or _r.startswith(_fname + '->')
                                           or _r.startswith(_fname + '.')
                                           for _r in _referenced):
                    continue  # not on the fork's data path
                try:
                    _dump_var(_fname, _depth + 1)
                except Exception:
                    continue
                _nf += 1
            return
        # Pointer to a scalar: capture the pointer VALUE itself.
        try:
            _addr = int(_val.address) if _val.address else 0
            _iv = int(_val)
        except Exception:
            return
        print("VAR_NAME %s" % _v)
        print("VAR_ADDR 0x%x" % _addr)
        print("VAR_VAL %d" % _iv)
        print("VAR_SIZE %d" % _val.type.sizeof)
        return
    _scalar_codes = {{getattr(gdb, 'TYPE_CODE_INT', None),
                     getattr(gdb, 'TYPE_CODE_ENUM', None),
                     getattr(gdb, 'TYPE_CODE_FLOAT', None),
                     getattr(gdb, 'TYPE_CODE_FLT', None),
                     getattr(gdb, 'TYPE_CODE_BOOL', None)}}
    if _t.code not in _scalar_codes:
        return
    try:
        _addr = int(_val.address) if _val.address else 0
        _iv = int(_val)
    except Exception:
        return
    print("VAR_NAME %s" % _v)
    print("VAR_ADDR 0x%x" % _addr)
    print("VAR_VAL %d" % _iv)
    print("VAR_SIZE %d" % _val.type.sizeof)
for _v in _vars:
    try:
        _dump_var(_v)
    except Exception:
        pass
    print("VAR_END")
end
"""



def build_strip_offset_block():
    """Capture the program's ACTUAL strip offset (td_stripoffset[0]) via GDB.

    Walks the call stack to find the TIFF handle (a pointer whose type has a
    tif_dir sub-struct), then reads td_stripoffset[0].  This avoids trusting a
    StripOffsets value re-parsed from a possibly-corrupted input file.
    """
    return r"""
  python
import gdb
try:
    frame = gdb.newest_frame()
    found = False
    while frame is not None and not found:
        try:
            block = frame.block()
            for sym in block:
                name = sym.name or ''
                if name not in ('tif', 'in', 'out', 'image'):
                    continue
                try:
                    val = frame.read_var(name)
                    if '*' not in str(val.type):
                        continue
                    try:
                        soff = int(val['tif_dir']['td_stripoffset'][0])
                        print("STRIP_OFFSET %d" % soff)
                        found = True
                        break
                    except Exception:
                        continue
                except Exception:
                    continue
        except Exception:
            pass
        try:
            frame = frame.older()
        except Exception:
            break
except Exception:
    pass
end
"""


def build_heap_scan_block():
    """Scan frames for pointer variables pointing to heap region."""
    return r"""
  python
import gdb

try:
    frame = gdb.newest_frame()
    for depth in range(8):
        if frame is None:
            break
        try:
            block = frame.block()
            for sym in block:
                name = sym.name or ''
                if not name:
                    continue
                try:
                    val = frame.read_var(name)
                    val_str = str(val.type)
                    if '*' not in val_str:
                        continue
                    ptr = int(val)
                except:
                    continue
                if 0x500000000000 <= ptr < 0x600000000000:
                    print(f"HEAP_PTR 0x{ptr:x} {name} depth={depth}")
                elif 0x7fff00000000 <= ptr < 0x800000000000:
                    print(f"STACK_PTR 0x{ptr:x} {name} depth={depth}")
        except:
            pass
        try:
            frame = frame.older()
        except:
            break
except:
    pass
end
"""

# Deep trace GDB script for TIFFOpen internals
TIFFOPEN_DEEP_TRACE = r"""
set pagination off
set confirm off
set width 0
set height 0

# Function breakpoints
break TIFFOpen
break TIFFClientOpen
break TIFFReadDirectory
break TIFFFetchDirectory
break TIFFFetchNormalTag
break TIFFFetchStripThing
break TIFFFetchPerSampleShorts
break TIFFReadDirectoryFindEntry
break TIFFFetchShort
break TIFFFetchLong
break TIFFFetchDouble
break TIFFFetchRational
break TIFFFetchShortArray
break TIFFFetchLongArray
break TIFFFetchFloatArray
break TIFFFetchDoubleArray
break TIFFFetchAnyArray
break TIFFFetchByte
break TIFFFetchSByte
break TIFFFetchShortPair
break TIFFCheckDirOffset
break TIFFFetchStripThing

# Run the program
run {input_file}
quit
"""


# Input-controlling TIFF context expressions tried on every trace in
# addition to the fork statement's own variables.  The crashed value often
# lives in the caller context (e.g. image->length) while the fork statement
# itself only uses callee locals (start/end/cols); without these the
# value-pattern mapping cannot find the input bytes steering the crash.
# Undefined expressions are skipped silently by the dumper.
_TIFF_CONTEXT_VARS = (
    'image->width', 'image->length', 'image->bps', 'image->spp',
    'image->compression', 'image->photometric',
    'crop->bufftotal', 'crop->combined_width', 'crop->combined_length',
)


def run_gdb_trace(binary, fork_spec, variables, input_file, program_args, timeout=30):
    real_binary = resolve_binary(binary)
    run_parts = [a.replace('{input_file}', input_file).replace('{input}', input_file)
                 for a in program_args]

    # The absolute fork path comes from the binary's debug info.  If it no
    # longer matches (e.g. the build dir was removed), fall back to the source
    # basename, which GDB matches against any loaded symtab.
    specs = [fork_spec]
    path, _, line = fork_spec.rpartition(':')
    if path and os.sep in path:
        base_spec = f'{os.path.basename(path)}:{line}'
        if base_spec != fork_spec:
            specs.append(base_spec)

    env = build_run_env(real_binary)
    output = ''
    for spec in specs:
        _vars_for_dump = list(variables or [])
        for _cv in _TIFF_CONTEXT_VARS:
            if _cv not in _vars_for_dump:
                _vars_for_dump.append(_cv)
        script = GDB_SCRIPT.format(
            fork_spec=spec,
            var_dump=build_var_dump_block(_vars_for_dump),
            strip_offset=build_strip_offset_block(),
            heap_scan=build_heap_scan_block(),
            run_args=' '.join(run_parts),
        )

        fd2, script_file = tempfile.mkstemp(suffix='.gdb', prefix='gdb_trace_')
        os.close(fd2)
        with open(script_file, 'w') as f:
            f.write(script)

        try:
            proc = subprocess.run(
                ['gdb', '-batch', '-nx', '-q', '-x', script_file, '--', real_binary],
                capture_output=True, text=True, errors="replace", timeout=timeout, env=env)
        except subprocess.TimeoutExpired:
            return None, 'timeout'
        finally:
            try: os.unlink(script_file)
            except: pass

        output = proc.stdout + proc.stderr
        if 'FORK_REACHED' in output:
            return output, None

    return None, 'fork_not_reached'


def run_deep_tiffopen_trace(binary, input_file, program_args, timeout=30):
    """Run GDB to trace TIFFOpen internals using raw breakpoint/catchpoint output.

    Sets breakpoints at the key TIFF library functions and catches pread64
    calls, then walks the actual open-time call path.  This is how the
    ``in``/``out``/``tif`` (TIFFOpen return) fork variables are traced: once
    the fork guard (e.g. ``if (in == NULL)``) is located, the NULL return is
    traced INWARD to the specific file reads that determined it — which
    directory/strip read failed — instead of just attributing the value to
    "TIFFOpen".  The raw GDB output is returned for parsing.
    """
    real_binary = resolve_binary(binary)
    run_parts = [a.replace('{input_file}', input_file).replace('{input}', input_file)
                 for a in program_args]

    run_args = ' '.join(run_parts)

    # Build GDB commands as a series of -ex arguments
    cmds = [
        'set pagination off',
        'set confirm off',
        'set breakpoint pending on',
        'break TIFFOpen',
        'break TIFFFetchStripThing',
        'catch syscall pread64',
        f'run {run_args}',
    ]
    # Add enough continues to get through all breakpoints/catchpoints
    for _ in range(30):
        cmds.append('continue')
    cmds.append('quit')

    # Build the full command line
    gdb_args = ['gdb', '-batch', '-nx', '-q']
    for cmd in cmds:
        gdb_args.extend(['-ex', cmd])
    gdb_args.extend(['--', real_binary])

    try:
        proc = subprocess.run(
            gdb_args,
            capture_output=True, text=True, errors="replace", timeout=timeout,
            env=build_run_env(real_binary))
    except subprocess.TimeoutExpired:
        return None, 'timeout'

    output = proc.stdout + proc.stderr
    return output, None


def run_gdb_chain_trace(binary, fork_spec, variables, input_file, program_args, timeout=120):
    """Use GDB watchpoints to chain-trace variables back to file offsets.

    For each variable:
    1. At the fork point, get the variable's address and value
    2. Set a watchpoint on that address
    3. Re-run and catch when the value is written
    4. Analyze the call stack to find the data source
    5. If from file I/O, record the file offset

    Returns a dict: {var_name: {'address': hex, 'value': int, 'file_offsets': [...], 'trace': [...]}}
    """
    real_binary = resolve_binary(binary)
    run_parts = [a.replace('{input_file}', input_file).replace('{input}', input_file)
                 for a in program_args]
    env = build_run_env(real_binary)

    # Build GDB script for chain tracing
    # Phase 1: At fork point, capture variable addresses and values
    # Phase 2: Set watchpoints and re-run to trace writes
    var_list = ', '.join(f'"{v}"' for v in variables)

    script = f"""set pagination off
set confirm off
set breakpoint pending on
set print pretty on

# Phase 1: Hit fork point and capture variable info
break {fork_spec}
commands
  silent
  printf "FORK_HIT\\n"
  python
import gdb

_vars = [{var_list}]
_results = {{}}

for var_expr in _vars:
    try:
        val = gdb.parse_and_eval(var_expr)
        addr = int(val.address) if val.address else 0
        _results[var_expr] = {{
            'address': f'0x{{addr:x}}' if addr else '0x0',
            'value': int(val),
            'size': val.type.sizeof,
        }}
        print(f"VAR {{var_expr}} addr=0x{{addr:x}} val={{int(val)}} size={{val.type.sizeof}}")
    except Exception as e:
        print(f"VAR_ERR {{var_expr}}: {{e}}")

# Also capture tif pointer and tif_fields array base
try:
    tif_ptr = int(gdb.parse_and_eval('tif'))
    tif_fields_ptr = int(gdb.parse_and_eval('tif->tif_fields'))
    tif_nfields = int(gdb.parse_and_eval('tif->tif_nfields'))
    print(f"TIF_INFO tif=0x{{tif_ptr:x}} tif_fields=0x{{tif_fields_ptr:x}} nfields={{tif_nfields}}")
except Exception as e:
    print(f"TIF_ERR: {{e}}")

# Capture mb index if available
try:
    mb_val = int(gdb.parse_and_eval('mb'))
    print(f"MB_VAL {{mb_val}}")
except:
    pass

print("PHASE1_END")
end
  quit
end

run {' '.join(run_parts)}
"""

    fd, script_file = tempfile.mkstemp(suffix='.gdb', prefix='gdb_chain_')
    os.close(fd)
    with open(script_file, 'w') as f:
        f.write(script)

    try:
        proc = subprocess.run(
            ['gdb', '-batch', '-nx', '-q', '-x', script_file, '--', real_binary],
            capture_output=True, text=True, errors="replace", timeout=timeout, env=env)
    except subprocess.TimeoutExpired:
        return None, 'timeout'
    finally:
        try: os.unlink(script_file)
        except: pass

    output = proc.stdout + proc.stderr
    if 'FORK_HIT' not in output:
        return None, 'fork_not_reached'

    # Parse phase 1 results
    results = {}
    tif_info = {}
    mb_val = None

    for line in output.splitlines():
        line = line.strip()
        m = re.match(r'VAR (\S+) addr=(0x[0-9a-f]+) val=(-?\d+) size=(\d+)', line)
        if m:
            results[m.group(1)] = {
                'address': m.group(2),
                'value': int(m.group(3)),
                'size': int(m.group(4)),
                'file_offsets': [],
                'trace': [],
            }
            continue
        m = re.match(r'TIF_INFO tif=(0x[0-9a-f]+) tif_fields=(0x[0-9a-f]+) nfields=(\d+)', line)
        if m:
            tif_info = {'tif': m.group(1), 'tif_fields': m.group(2), 'nfields': int(m.group(3))}
            continue
        m = re.match(r'MB_VAL (\d+)', line)
        if m:
            mb_val = int(m.group(1))

    if not results:
        return None, 'no_variables'

    # Phase 2: For each variable with an address, set watchpoint and trace
    # We do this in a second GDB run for each variable
    for var_name, var_info in results.items():
        addr = var_info['address']
        if addr == '0x0':
            continue

        trace_result = _trace_write_location(real_binary, fork_spec, var_name, addr,
                                              var_info['value'], input_file, run_parts, env, timeout)
        if trace_result:
            var_info['file_offsets'] = trace_result.get('file_offsets', [])
            var_info['trace'] = trace_result.get('trace', [])

    return results, None


def _trace_write_location(binary, fork_spec, var_name, addr, expected_val, input_file,
                          run_parts, env, timeout):
    """Set a watchpoint on addr and trace when it's written.

    Returns {'file_offsets': [...], 'trace': [...]} or None.
    """
    # Build script that:
    # 1. Sets watchpoint on the address
    # 2. Runs until watchpoint triggers
    # 3. Captures backtrace and assignment info
    script = f"""set pagination off
set confirm off
set breakpoint pending on
set print pretty on

# Set watchpoint on the target address
watch *{addr}
commands
  silent
  printf "WATCH_HIT\\n"
  printf "BACKTRACE_START\\n"
  backtrace 20
  printf "BACKTRACE_END\\n"
  printf "FRAME_INFO_START\\n"
  info frame
  printf "FRAME_INFO_END\\n"
  printf "WATCH_DONE\\n"
  quit
end

run {' '.join(run_parts)}
"""

    fd, script_file = tempfile.mkstemp(suffix='.gdb', prefix='gdb_watch_')
    os.close(fd)
    with open(script_file, 'w') as f:
        f.write(script)

    try:
        proc = subprocess.run(
            ['gdb', '-batch', '-nx', '-q', '-x', script_file, '--', binary],
            capture_output=True, text=True, errors="replace", timeout=timeout, env=env)
    except subprocess.TimeoutExpired:
        return None
    finally:
        try: os.unlink(script_file)
        except: pass

    output = proc.stdout + proc.stderr
    if 'WATCH_HIT' not in output:
        return None

    # Parse backtrace to find TIFF-related functions
    trace = []
    in_backtrace = False
    for line in output.splitlines():
        line = line.strip()
        if line == 'BACKTRACE_START':
            in_backtrace = True
            continue
        if line == 'BACKTRACE_END':
            break
        if in_backtrace:
            trace.append(line)

    # Look for TIFF functions in the trace that read from file
    tiff_funcs = ['TIFFReadDirectory', 'TIFFFetchNormalTag', 'TIFFFetchStripThing',
                  'TIFFFetchDirectory', '_TIFFReadDirEntryArray', 'TIFFReadCustomDirectory']

    result = {'file_offsets': [], 'trace': trace}

    # If we found a TIFF function, try to extract tag info
    for tline in trace:
        for func in tiff_funcs:
            if func in tline:
                result['trace'].append(f'FOUND_FUNC: {func}')
                break

    return result


def run_gdb_function_chain_trace(binary, fork_spec, input_file, program_args, timeout=120):
    """Function-based chain trace: track data flow through libtiff functions.

    Algorithm:
    1. Set breakpoints on key libtiff functions that read/process file data
    2. At each breakpoint, capture arguments and relevant state
    3. Build a call chain showing how data flows from file to fork variables
    
    This is more practical than watchpoint tracing for library code because:
    - Data is often written before the fork point
    - Library functions have well-defined interfaces
    - We can correlate function arguments with file offsets
    """
    real_binary = resolve_binary(binary)
    run_parts = [a.replace('{input_file}', input_file).replace('{input}', input_file)
                 for a in program_args]
    env = build_run_env(real_binary)

    # Key libtiff functions to trace, in order of data flow
    script = f"""set pagination off
set confirm off
set breakpoint pending on
set print pretty on

# Break on fork point to get context
break {fork_spec}
commands
  silent
  printf "FORK_CONTEXT\\n"
  python
import gdb
# Capture the state at fork point
try:
    mb = int(gdb.parse_and_eval('mb'))
    tagid = int(gdb.parse_and_eval('tagid'))
    field_tag = int(gdb.parse_and_eval('tif->tif_fields[mb]->field_tag'))
    nfields = int(gdb.parse_and_eval('tif->tif_nfields'))
    tif_ptr = int(gdb.parse_and_eval('tif'))
    
    # Enumerate tif_fields to find which index has tagid
    for i in range(min(nfields, 200)):
        try:
            t = int(gdb.parse_and_eval(f'tif->tif_fields[{{i}}]->field_tag'))
            if t == tagid:
                print(f"TAGID_INDEX {{i}}")
                break
        except:
            pass
    
    print(f"FORK_MB {{mb}}")
    print(f"FORK_TAGID {{tagid}}")
    print(f"FORK_FIELD_TAG {{field_tag}}")
    print(f"FORK_NFIELDS {{nfields}}")
    print(f"FORK_TIF_PTR 0x{{tif_ptr:x}}")
except Exception as e:
    print(f"FORK_ERR {{e}}")
end
  continue
end

# Break on TIFFReadDirectory - where IFD is parsed
break TIFFReadDirectory
commands
  silent
  printf "FUNC_TIFFReadDirectory\\n"
  info args
  continue
end

# Break on TIFFFetchNormalTag - where individual tags are fetched
break TIFFFetchNormalTag
commands
  silent
  printf "FUNC_TIFFFetchNormalTag\\n"
  python
import gdb
try:
    tag = int(gdb.parse_and_eval('tag'))
    print(f"FETCH_TAG {{tag}}")
except:
    pass
end
  continue
end

# Break on _TIFFReadDirEntryArray - where IFD entries are read from file
break _TIFFReadDirEntryArray
commands
  silent
  printf "FUNC_TIFFReadDirEntryArray\\n"
  info args
  continue
end

# Catch pread64 to see actual file reads
catch syscall pread64
commands
  silent
  if $rdi >= 3 && $rdx > 0 && $rdx < 100000
    printf "PREAD64 fd=%d offset=%ld size=%ld\\n", $rdi, $r10, $rdx
  end
  continue
end

run {' '.join(run_parts)}
"""

    fd, script_file = tempfile.mkstemp(suffix='.gdb', prefix='gdb_func_chain_')
    os.close(fd)
    with open(script_file, 'w') as f:
        f.write(script)

    try:
        proc = subprocess.run(
            ['gdb', '-batch', '-nx', '-q', '-x', script_file, '--', real_binary],
            capture_output=True, text=True, errors="replace", timeout=timeout, env=env)
    except subprocess.TimeoutExpired:
        return None, 'timeout'
    finally:
        try: os.unlink(script_file)
        except: pass

    output = proc.stdout + proc.stderr
    if 'FORK_CONTEXT' not in output:
        return None, 'fork_not_reached'

    # Parse results
    result = {
        'fork_context': {},
        'functions_called': [],
        'pread64_calls': [],
        'tag_fetches': [],
    }

    for line in output.splitlines():
        line = line.strip()
        
        # Fork context
        m = re.match(r'FORK_MB (\d+)', line)
        if m: result['fork_context']['mb'] = int(m.group(1))
        m = re.match(r'FORK_TAGID (\d+)', line)
        if m: result['fork_context']['tagid'] = int(m.group(1))
        m = re.match(r'FORK_FIELD_TAG (\d+)', line)
        if m: result['fork_context']['field_tag'] = int(m.group(1))
        m = re.match(r'FORK_NFIELDS (\d+)', line)
        if m: result['fork_context']['nfields'] = int(m.group(1))
        m = re.match(r'TAGID_INDEX (\d+)', line)
        if m: result['fork_context']['tagid_index'] = int(m.group(1))
        
        # Function calls
        if line.startswith('FUNC_'):
            func_name = line[5:]
            if func_name not in result['functions_called']:
                result['functions_called'].append(func_name)
        
        # Tag fetches
        m = re.match(r'FETCH_TAG (\d+)', line)
        if m:
            result['tag_fetches'].append(int(m.group(1)))
        
        # pread64 calls
        m = re.match(r'PREAD64 fd=(\d+) offset=(\d+) size=(\d+)', line)
        if m:
            result['pread64_calls'].append({
                'fd': int(m.group(1)),
                'offset': int(m.group(2)),
                'size': int(m.group(3)),
            })

    return result, None


def run_gdb_call_site_trace(binary, fork_spec, fork_func, variables, input_file,
                            program_args, timeout=120, clauses=None):
    """Fully dynamic call-site / fork-context back-tracing (no static analysis).

    Dispatches on the fork function:

    * case A -- fork_func == ``TIFFReadDirectoryFindFieldInfo`` (the classic
      path, unchanged): the fork variable ``tagid`` is a function parameter
      whose source is the call-site actual argument ``dp->tdir_tag``.  Phase A
      records every fork-point execution (tagid/mb/field_tag); Phase B runs
      once per distinct tagid with ``break <fork_func> if tagid == N``,
      reads ``dp``/``dir`` from the caller frames and maps
      ``file offset = tif_diroff + count_size + (dp - dir)/entry_size*disk_esz``.

    * case B -- any other fork function: Phase A records every fork-point
      execution (invocation counter + ALL fork variables + IFD context:
      ``tif->tif_diroff``, ``dp``/``dir``/``direntry`` if in scope).  The
      mapping is computed directly from the fork-point context: a variable
      whose value is the IFD buffer base (``dir``) maps to
      ``tif_diroff + count_size``; an entry pointer (``direntry``/``dp``)
      maps to ``tif_diroff + count_size + index*disk_esz``.

    Returns
      {'tag_mappings': {tagid: {...}},   (case A)
       'var_mappings': {var: {...}},     (case B)
       'fork_points': [...], 'pread64': [...]} or (None, error).
    """
    real_binary = resolve_binary(binary)
    run_parts = [a.replace('{input_file}', input_file).replace('{input}', input_file)
                 for a in program_args]
    run_args = ' '.join(run_parts)
    env = build_run_env(real_binary)
    var_reprs = ', '.join(json.dumps(str(v)) for v in variables)

    # ------------------------------------------------------------------
    # Phase A: record every fork-point execution (all variables + context)
    # ------------------------------------------------------------------
    phase_a = f"""set pagination off
set confirm off
set breakpoint pending on

set $inv = 0
break {fork_spec}
commands
  silent
  set $inv = $inv + 1
  printf "FORK_POINT inv=%d\\n", $inv
  python
import gdb
_vars = [{var_reprs}]
for _v in _vars:
    try:
        _val = int(gdb.parse_and_eval(_v))
        print("VARVAL " + _v + " " + str(_val))
    except Exception:
        pass
try:
    print("DIROFF %d" % int(gdb.parse_and_eval('tif->tif_diroff')))
except Exception:
    pass
try:
    print("CUR_DP 0x%x" % int(gdb.parse_and_eval('dp')))
except Exception:
    pass
try:
    print("CUR_DIR 0x%x" % int(gdb.parse_and_eval('dir')))
except Exception:
    pass
try:
    print("CUR_ENTRY 0x%x" % int(gdb.parse_and_eval('direntry')))
except Exception:
    pass
try:
    f = gdb.newest_frame().older()
    while f is not None:
        try:
            d = int(f.read_var('dir'))
            print("FRAME_DIR 0x%x " % d + (f.name() or ''))
            break
        except Exception:
            pass
        try:
            f = f.older()
        except Exception:
            break
except Exception:
    pass
try:
    print("ENTSIZE %d" % int(gdb.parse_and_eval('sizeof(TIFFDirEntry)')))
except Exception:
    pass
try:
    print("FLAGS %d" % int(gdb.parse_and_eval('tif->tif_flags')))
except Exception:
    pass
try:
    f = gdb.newest_frame().older()
    while f is not None:
        try:
            dc = int(f.read_var('dircount'))
            print("IFD_DIRCOUNT %d" % dc)
            break
        except Exception:
            pass
        try:
            f = f.older()
        except Exception:
            break
except Exception:
    pass
end
  continue
end

break {fork_func}
commands
  silent
  set $inv = $inv + 1
  continue
end

run {run_args}
"""
    fd, script_file = tempfile.mkstemp(suffix='.gdb', prefix='gdb_callsite_a_')
    os.close(fd)
    with open(script_file, 'w') as f:
        f.write(phase_a)
    try:
        proc = subprocess.run(
            ['gdb', '-batch', '-nx', '-q', '-x', script_file, '--', real_binary],
            capture_output=True, text=True, errors="replace", timeout=timeout, env=env)
    except subprocess.TimeoutExpired:
        return None, 'timeout_phase_a'
    finally:
        try: os.unlink(script_file)
        except: pass

    out_a = proc.stdout + proc.stderr
    if 'FORK_POINT' not in out_a:
        return None, 'fork_not_reached'

    fork_points = []
    cur = None
    for line in out_a.splitlines():
        line = line.strip()
        m = re.match(r'FORK_POINT inv=(\d+)', line)
        if m:
            cur = {'inv': int(m.group(1)), 'varvals': {},
                   'diroff': None, 'dp': None, 'dir': None, 'entry': None,
                   'frame_dir': None, 'entsize': None, 'flags': None,
                   'dircount': None}
            fork_points.append(cur)
            continue
        if cur is None:
            continue
        m = re.match(r'VARVAL (.+?) (-?\d+)$', line)
        if m:
            cur['varvals'][m.group(1)] = int(m.group(2))
            continue
        m = re.match(r'DIROFF (\d+)', line)
        if m: cur['diroff'] = int(m.group(1)); continue
        m = re.match(r'CUR_DP (0x[0-9a-f]+)', line)
        if m: cur['dp'] = int(m.group(1), 16); continue
        m = re.match(r'CUR_DIR (0x[0-9a-f]+)', line)
        if m: cur['dir'] = int(m.group(1), 16); continue
        m = re.match(r'CUR_ENTRY (0x[0-9a-f]+)', line)
        if m: cur['entry'] = int(m.group(1), 16); continue
        m = re.match(r'FRAME_DIR (0x[0-9a-f]+) (\S+)', line)
        if m: cur['frame_dir'] = int(m.group(1), 16); continue
        m = re.match(r'ENTSIZE (\d+)', line)
        if m: cur['entsize'] = int(m.group(1)); continue
        m = re.match(r'FLAGS (\d+)', line)
        if m: cur['flags'] = int(m.group(1)); continue
        m = re.match(r'IFD_DIRCOUNT (\d+)', line)
        if m: cur['dircount'] = int(m.group(1)); continue

    if not fork_points:
        return None, 'no_invocations'

    # ------------------------------------------------------------------
    # Phase B / mapping dispatch
    # ------------------------------------------------------------------
    if fork_func == 'TIFFReadDirectoryFindFieldInfo':
        return _call_site_trace_case_a(
            real_binary, fork_spec, fork_func, run_args, env,
            fork_points, timeout), None
    return _call_site_trace_case_b(fork_points, variables, clauses,
                                   input_file), None


def _call_site_trace_case_a(real_binary, fork_spec, fork_func, run_args, env,
                            fork_points, timeout):
    """Classic path: per-tagid conditional breakpoint at the fork-function
    entry; maps dp->tdir_tag to the file offset of the IFD entry."""
    distinct_tagids = list(dict.fromkeys(
        fp['varvals'].get('tagid') for fp in fork_points
        if fp['varvals'].get('tagid') is not None))
    pread64_all = []
    tag_mappings = {}

    for tagid in distinct_tagids:
        phase_b = f"""set pagination off
set confirm off
set breakpoint pending on

catch syscall pread64
commands
  silent
  if $rdi >= 3 && $rdx > 0 && $rdx < 1000000
    printf "PREAD64 fd=%d offset=%ld size=%ld buf=0x%lx\\n", $rdi, $r10, $rdx, $rsi
  end
  continue
end

break {fork_func} if tagid == {tagid}
commands
  silent
  printf "CALL_HIT tagid={tagid}\\n"
  python
import gdb
frame = gdb.newest_frame()
f = frame.older()
while f is not None:
    try:
        fname = f.name() or ''
    except Exception:
        fname = ''
    try:
        dp = int(f.read_var('dp'))
        print(f"CALLER_DP 0x{{dp:x}} " + fname)
    except Exception:
        pass
    try:
        d = int(f.read_var('dir'))
        print(f"CALLER_DIR 0x{{d:x}} " + fname)
    except Exception:
        pass
    try:
        f = f.older()
    except Exception:
        break
try:
    print("DIROFF %d" % int(gdb.parse_and_eval('tif->tif_diroff')))
except Exception:
    pass
try:
    print("ENTSIZE %d" % int(gdb.parse_and_eval('sizeof(TIFFDirEntry)')))
except Exception:
    pass
try:
    print("FLAGS %d" % int(gdb.parse_and_eval('tif->tif_flags')))
except Exception:
    pass
end
  quit
end

run {run_args}
"""
        fd, script_file = tempfile.mkstemp(suffix='.gdb', prefix='gdb_callsite_b_')
        os.close(fd)
        with open(script_file, 'w') as f:
            f.write(phase_b)
        try:
            proc = subprocess.run(
                ['gdb', '-batch', '-nx', '-q', '-x', script_file, '--', real_binary],
                capture_output=True, text=True, errors="replace", timeout=timeout, env=env)
        except subprocess.TimeoutExpired:
            continue
        finally:
            try: os.unlink(script_file)
            except: pass

        out_b = proc.stdout + proc.stderr
        if 'CALL_HIT' not in out_b:
            continue

        preads = []
        dp_addr = None
        dir_addr = None
        diroff = None
        entry_size = None
        tif_flags = None
        for line in out_b.splitlines():
            line = line.strip()
            m = re.match(r'PREAD64 fd=(\d+) offset=(-?\d+) size=(-?\d+) buf=(0x[0-9a-f]+)', line)
            if m:
                preads.append({
                    'fd': int(m.group(1)),
                    'offset': int(m.group(2)),
                    'size': int(m.group(3)),
                    'buf': int(m.group(4), 16),
                })
                continue
            m = re.match(r'CALLER_DP (0x[0-9a-f]+) (\S+)', line)
            if m:
                dp_addr = int(m.group(1), 16)
                continue
            m = re.match(r'CALLER_DIR (0x[0-9a-f]+) (\S+)', line)
            if m:
                dir_addr = int(m.group(1), 16)
                continue
            m = re.match(r'DIROFF (\d+)', line)
            if m:
                diroff = int(m.group(1))
                continue
            m = re.match(r'ENTSIZE (\d+)', line)
            if m:
                entry_size = int(m.group(1))
                continue
            m = re.match(r'FLAGS (\d+)', line)
            if m:
                tif_flags = int(m.group(1))

        # File offset of the IFD entry.  tif->tif_diroff points at the
        # directory count (2 bytes for classic TIFF, 8 for BigTIFF); the
        # entry array starts right after it.  dp - dir is the entry's offset
        # in the *in-memory* buffer (TIFFDirEntry is 24 bytes), while the
        # on-disk entry is 12 bytes (classic) or 20 bytes (BigTIFF).
        entry_off = None
        entry_index = None
        if (diroff is not None and dp_addr is not None and dir_addr is not None
                and dp_addr >= dir_addr):
            delta = dp_addr - dir_addr
            esz = entry_size if entry_size else 12
            entry_index = delta // esz
            disk_esz = 20 if (tif_flags is not None and tif_flags & 0x80000) else 12  # TIFF_BIGTIFF
            count_size = 8 if (tif_flags is not None and tif_flags & 0x80000) else 2
            entry_off = diroff + count_size + entry_index * disk_esz

        tag_mappings[tagid] = {
            'file_offset': entry_off,
            'entry_index': entry_index,
            'dp': f'0x{dp_addr:x}' if dp_addr else None,
            'dir': f'0x{dir_addr:x}' if dir_addr else None,
            'ifd_offset': diroff,
            'entry_size': entry_size,
            'tag_name': _TIFF_TAG_NAMES.get(tagid, f'tag_{tagid}'),
        }
        pread64_all.extend(preads)

    return {
        'tag_mappings': tag_mappings,
        'fork_points': fork_points,
        'pread64': pread64_all,
    }


def _call_site_trace_case_b(fork_points, variables, clauses=None,
                            input_file=None):
    """Generic path: map fork variables from the fork-point context.

    The diverging fork point is selected by matching the divergence
    clauses' lhs/rhs operand values against the recorded variable values
    (fallback: the LAST recorded fork point).  Variables are then mapped:

      * a variable equal to the IFD buffer base (``dir``) or an entry
        pointer (``dp``/``direntry``) -> the buffer/entry file offset;
      * a variable that is an IFD entry field (e.g. ``dp->tdir_tag``) or a
        scalar derived from the current entry (e.g. ``fii``, driven by
        ``dp->tdir_tag``) -> the current entry's file offset, computed from
        the fork-point context (``dp``-``dir`` + ``tif_diroff``).
    """
    var_mappings = {}
    for v in variables:
        var_mappings[v] = {
            'file_offset': None,
            'kind': None,
            'values': [],
        }

    # Select the diverging fork point via the clauses' operand values.
    fp = None
    if clauses:
        target_vals = [v for v in (clauses.get('lhs'), clauses.get('rhs'))
                       if isinstance(v, int)]
        for cand in fork_points:
            vals = cand.get('varvals') or {}
            if any(val in target_vals for val in vals.values()):
                fp = cand
                break
    if fp is None:
        fp = fork_points[-1]

    diroff = fp.get('diroff')
    flags = fp.get('flags')
    bigtiff = flags is not None and bool(flags & 0x80000)
    count_size = 8 if bigtiff else 2
    disk_esz = 20 if bigtiff else 12
    esz = fp.get('entsize') or 12
    dp = fp.get('dp')
    dir_base = fp.get('dir')

    def _entry_offset(entry_ptr, base=None):
        base = base if base is not None else dir_base
        if diroff is None or base is None or entry_ptr is None \
                or entry_ptr < base:
            return None, None
        idx = (entry_ptr - base) // esz
        return diroff + count_size + idx * disk_esz, idx

    # Entry pointer of the current iteration: prefer dp (in scope at the
    # fork point inside TIFFReadDirectory's loop).
    entry_ptr = dp

    for v in variables:
        val = fp['varvals'].get(v)
        mapping = var_mappings[v]
        if val is not None:
            mapping['values'] = [val]
        low = v.lower()

        if (diroff is not None and dir_base is not None
                and (low == 'dir' or (isinstance(val, int) and val == dir_base))):
            # 'dir' may be the IFD buffer base (TIFFReadDirectory) or an
            # entry pointer (TIFFFetchStripThing's parameter).  When the
            # caller frame's dir (FRAME_DIR) differs and lies below it, the
            # fork-point 'dir' is an ENTRY pointer -> map to the entry offset.
            base = fp.get('frame_dir')
            if (base is not None and dir_base is not None
                    and dir_base > base and low == 'dir'):
                off, idx = _entry_offset(dir_base, base)
                if off is not None:
                    mapping['file_offset'] = off
                    mapping['kind'] = 'ifd_entry'
                    mapping['entry_index'] = idx
                    continue
            mapping['file_offset'] = diroff + count_size
            mapping['kind'] = 'ifd_entries_base'
            continue
        if low in ('dp', 'direntry') or (isinstance(val, int)
                                         and val == entry_ptr):
            off, idx = _entry_offset(val if isinstance(val, int) else entry_ptr)
            if off is not None:
                mapping['file_offset'] = off
                mapping['kind'] = 'ifd_entry'
            continue
        # IFD entry field expression (e.g. dp->tdir_tag) or a scalar whose
        # value is driven by the current entry (fii, tdir_*): map to the
        # current entry's file offset.
        if ('tdir_' in v or 'tdir' in low or low in ('fii', 'err', 'tagid')) \
                and entry_ptr is not None:
            off, idx = _entry_offset(entry_ptr)
            if off is not None:
                mapping['file_offset'] = off
                mapping['kind'] = 'ifd_entry'
                mapping['entry_index'] = idx

    # ------------------------------------------------------------------
    # IFD region: the fork decision runs inside TIFFReadDirectory's loop
    # over the IFD entries, so EVERY entry of the same IFD is a structural
    # input to the decision (not just the current entry's value fields).
    # From the fork-point context (diroff + dircount + entry size) the whole
    # on-disk IFD region is computed dynamically: entry offsets for all four
    # fields (tag/type/count/offset) of every entry in the directory the
    # fork point belongs to.  Nothing here is a static parse of the input —
    # without a fork-point execution there is no diroff/dircount to map.
    # ------------------------------------------------------------------
    ifd_region = {
        'ifd_offset': None,
        'entry_size': None,
        'entries_base': None,
        'count': None,
        'entry_offsets': [],
        'field_offsets': [],
    }
    for fp in fork_points:
        diroff = fp.get('diroff')
        dircount = fp.get('dircount')
        if diroff is None or dircount is None or dircount <= 0 \
                or dircount > 10000:
            continue
        flags = fp.get('flags')
        bigtiff = flags is not None and bool(flags & 0x80000)
        count_size = 8 if bigtiff else 2
        disk_esz = 20 if bigtiff else 12
        ifd_region['ifd_offset'] = diroff
        ifd_region['entry_size'] = disk_esz
        ifd_region['entries_base'] = diroff + count_size
        ifd_region['count'] = dircount
        base = diroff + count_size
        ifd_region['entry_offsets'] = [
            base + i * disk_esz for i in range(dircount)]
        ifd_region['field_offsets'] = []
        for eo in ifd_region['entry_offsets']:
            ifd_region['field_offsets'].extend(
                [eo, eo + 2, eo + 4, eo + 8])  # tag, type, count, offset
        break

    return {
        'var_mappings': var_mappings,
        'fork_points': fork_points,
        'pread64': [],
        'ifd_region': ifd_region,
    }


def _frame_symbols_snapshot():
    """GDB Python code body (no python/end wrappers): dump all in-scope
    variables (locals + args) of the innermost frames with their values.
    Used by the watchpoint chain to find value-matching data sources at a
    write site."""
    return r"""
_frame = gdb.newest_frame()
for _i in range(6):
    if _frame is None:
        break
    try:
        _fname = _frame.name() or '?'
    except Exception:
        _fname = '?'
    try:
        _block = _frame.block()
    except Exception:
        _block = None
    _seen = set()
    if _block is not None:
        try:
            _iter = _block
            while _iter is not None:
                for _sym in _iter:
                    _n = _sym.name or ''
                    if not _n or _n in _seen:
                        continue
                    _seen.add(_n)
                    try:
                        _v = int(_frame.read_var(_n))
                        print("SYM %s %d 0x%x" % (_n, _v, _v))
                    except Exception:
                        pass
                try:
                    _iter = _iter.superblock
                except Exception:
                    _iter = None
        except Exception:
            pass
    try:
        _args = _frame.arguments()
        for _a in _args:
            _n = _a.name or ''
            if _n in _seen:
                continue
            _seen.add(_n)
            try:
                _v = int(_a.value(_frame))
                print("SYM %s %d 0x%x" % (_n, _v, _v))
            except Exception:
                pass
    except Exception:
        pass
    print("FRAME_END %s" % _fname)
    try:
        _frame = _frame.older()
    except Exception:
        break
"""


def run_gdb_watchpoint_chain(binary, fork_spec, fork_func, var_expr, input_file,
                             program_args, timeout=120, max_depth=5):
    """Fully dynamic watchpoint-chain data-flow tracing.

    Starting from a fork variable (e.g. ``crop_buff``), repeatedly:
      1. break at the enclosing function's entry, read the variable's ADDRESS,
         set a hardware watchpoint on it, and continue;
      2. when the watchpoint fires (the variable is written), record the
         write site (function:line), the written value, and snapshot every
         in-scope variable whose value equals the written value -- those are
         the data-flow candidates;
      3. recurse into the candidates (the next layer runs in the writer's
         function), until the chain reaches an input-file leaf (a variable
         whose value matches an IFD tag value / entry) or a dead end.

    No source text is read: both the write sites and the candidate sources
    are discovered dynamically via watchpoints and value matching.
    """
    real_binary = resolve_binary(binary)
    run_parts = [a.replace('{input_file}', input_file).replace('{input}', input_file)
                 for a in program_args]
    run_args = ' '.join(run_parts)
    env = build_run_env(real_binary)
    snapshot = _frame_symbols_snapshot()

    chain = []
    current_var = var_expr
    current_func = fork_func

    for depth in range(max_depth):
        script = f"""set pagination off
set confirm off
set breakpoint pending on

break {current_func}
commands 1
  silent
  python
import gdb
_g_state = {{'hits': 0, 'var': '{current_var}', 'depth': {depth}}}
def _on_stop(ev):
    _g_state['hits'] += 1
    try:
        _f = gdb.newest_frame()
        _sal = _f.find_sal()
        _line = _sal.line if _sal else -1
        _name = _f.name() or '?'
        _v = int(gdb.parse_and_eval('{current_var}'))
        print("CB_HIT depth=%d hit=%d frame=%s line=%d val=%d" % (
            _g_state['depth'], _g_state['hits'], _name, _line, _v))
    except Exception as e:
        print("CB_ERR %s" % e)
        return
    # First hit is usually the declaration init (e.g. `crop_buff = NULL`);
    # skip it and keep watching for the real assignment.
    if _g_state['hits'] == 1:
        return
    # Real write: snapshot in-scope variables for value matching, then quit.
{_frame_symbols_snapshot()}
    gdb.execute('quit')
gdb.events.stop.connect(_on_stop)
try:
    _a = int(gdb.parse_and_eval('&({current_var})'))
    print("VAR_ADDR 0x%x" % _a)
    gdb.execute('watch *0x%x' % _a)
    print("WATCH_ISSUED")
except Exception as e:
    print("VAR_ERR %s" % e)
end
  continue
end

run {run_args}
"""
        fd, script_file = tempfile.mkstemp(suffix='.gdb', prefix='gdb_wchain_')
        os.close(fd)
        with open(script_file, 'w') as f:
            f.write(script)
        try:
            proc = subprocess.run(
                ['gdb', '-batch', '-nx', '-q', '-x', script_file, '--', real_binary],
                capture_output=True, text=True, errors="replace", timeout=timeout, env=env)
        except subprocess.TimeoutExpired:
            return {'chain': chain, 'error': 'timeout'}, None
        finally:
            try: os.unlink(script_file)
            except: pass

        out = proc.stdout + proc.stderr
        hit_line = None
        hit_frame = None
        write_val = None
        syms = []
        got_hit = False
        for line in out.splitlines():
            line = line.strip()
            m = re.match(r'CB_HIT depth=\d+ hit=\d+ frame=(\S+) line=(\d+) val=(-?\d+)', line)
            if m:
                got_hit = True
                hit_frame = m.group(1)
                hit_line = int(m.group(2))
                write_val = int(m.group(4))
                continue
            m = re.match(r'SYM (\S+) (-?\d+) (0x[0-9a-f]+)', line)
            if m:
                syms.append({'name': m.group(1), 'val': int(m.group(2))})
                continue

        if not got_hit:
            chain.append({'var': current_var, 'func': current_func,
                          'hit': False})
            break

        # Candidates: in-scope variables whose value equals the written value
        # (excluding the watched variable itself and loop counters).
        candidates = []
        for s in syms:
            if s['name'] == current_var:
                continue
            if s['val'] != write_val:
                continue
            if s['name'] in ('i', 'j', 'k', 'n', 'idx'):
                continue
            candidates.append(s['name'])

        chain.append({'var': current_var, 'func': current_func,
                      'write_line': hit_line, 'value': write_val,
                      'candidates': candidates})

        # Next layer: recurse into the first plausible candidate.  A heap
        # pointer (>= 0x500000000000) usually comes from malloc — dead end
        # for file mapping; a small integer is a computed/loop scalar — try
        # to follow it.
        next_var = None
        for c in candidates:
            cv = next((s['val'] for s in syms if s['name'] == c), 0)
            if cv >= 0x500000000000:
                continue  # heap pointer: allocation result, not file data
            next_var = c
            break
        if next_var is None:
            break
        # The candidate lives in the current write frame; the next layer
        # breaks at that frame's function to re-watch it.
        current_var = next_var
        current_func = hit_frame or current_func
        if current_func == '?':
            break

    return {'chain': chain}, None


def run_gdb_watchpoint_chain_trace(binary, fork_spec, var_expr, input_file, program_args,
                                    max_depth=5, timeout=300):
    """True GDB watchpoint-based chain tracing.

    Algorithm:
    1. At fork point, get variable's address and value
    2. Set watchpoint on that address
    3. Re-run, when watchpoint triggers: capture backtrace (find writer)
    4. In the writer function, find what data it reads (parameters, file I/O)
    5. Recursively trace those sources up to max_depth
    6. If we hit a file I/O function (pread64, read), record the file offset

    Returns: {'chain': [...], 'file_offsets': [...], 'trace_tree': {...}}
    """
    real_binary = resolve_binary(binary)
    run_parts = [a.replace('{input_file}', input_file).replace('{input}', input_file)
                 for a in program_args]
    env = build_run_env(real_binary)

    # Phase 1: Get variable address at fork point
    addr_script = f"""set pagination off
set confirm off
set breakpoint pending on

break {fork_spec}
commands
  silent
  printf "FORK_HIT\\n"
  python
import gdb
try:
    val = gdb.parse_and_eval('{var_expr}')
    addr = int(val.address) if val.address else 0
    print(f"VAR_ADDR 0x{{addr:x}}")
    print(f"VAR_VAL {{int(val)}}")
    print(f"VAR_SIZE {{val.type.sizeof}}")
except Exception as e:
    print(f"VAR_ERR {{e}}")
end
  quit
end

run {' '.join(run_parts)}
"""

    fd, script_file = tempfile.mkstemp(suffix='.gdb', prefix='gdb_addr_')
    os.close(fd)
    with open(script_file, 'w') as f:
        f.write(addr_script)

    try:
        proc = subprocess.run(
            ['gdb', '-batch', '-nx', '-q', '-x', script_file, '--', real_binary],
            capture_output=True, text=True, errors="replace", timeout=30, env=env)
    except subprocess.TimeoutExpired:
        return None, 'timeout_phase1'
    finally:
        try: os.unlink(script_file)
        except: pass

    output = proc.stdout + proc.stderr
    if 'FORK_HIT' not in output:
        return None, 'fork_not_reached'

    # Parse variable info
    var_addr = None
    var_val = None
    var_size = None
    for line in output.splitlines():
        m = re.match(r'VAR_ADDR (0x[0-9a-f]+)', line.strip())
        if m: var_addr = int(m.group(1), 16)
        m = re.match(r'VAR_VAL (-?\d+)', line.strip())
        if m: var_val = int(m.group(1))
        m = re.match(r'VAR_SIZE (\d+)', line.strip())
        if m: var_size = int(m.group(1))

    if var_addr is None or var_addr == 0:
        return None, 'no_address'

    # Phase 2: Set watchpoint and trace write chain
    chain = []
    file_offsets = []
    trace_tree = {
        'var': var_expr,
        'addr': f'0x{var_addr:x}',
        'value': var_val,
        'writers': [],
    }

    current_addr = var_addr
    for depth in range(max_depth):
        # Set watchpoint on current address
        watch_script = f"""set pagination off
set confirm off
set breakpoint pending on

# Set watchpoint on the address
watch *{current_addr}
commands
  silent
  printf "WATCH_HIT depth={depth}\\n"
  printf "BACKTRACE_START\\n"
  backtrace 30
  printf "BACKTRACE_END\\n"
  # Capture frame info to find the writer function
  printf "FRAME_INFO_START\\n"
  info frame
  printf "FRAME_INFO_END\\n"
  # Capture local variables in the writer
  printf "LOCALS_START\\n"
  info locals
  printf "LOCALS_END\\n"
  # Capture function arguments
  printf "ARGS_START\\n"
  info args
  printf "ARGS_END\\n"
  quit
end

run {' '.join(run_parts)}
"""

        fd, script_file = tempfile.mkstemp(suffix='.gdb', prefix='gdb_watch_')
        os.close(fd)
        with open(script_file, 'w') as f:
            f.write(watch_script)

        try:
            proc = subprocess.run(
                ['gdb', '-batch', '-nx', '-q', '-x', script_file, '--', real_binary],
                capture_output=True, text=True, errors="replace", timeout=60, env=env)
        except subprocess.TimeoutExpired:
            try: os.unlink(script_file)
            except: pass
            break
        finally:
            try: os.unlink(script_file)
            except: pass

        output = proc.stdout + proc.stderr
        if 'WATCH_HIT' not in output:
            break

        # Parse backtrace
        writer_info = _parse_watchpoint_hit(output, depth)
        if not writer_info:
            break

        chain.append(writer_info)
        trace_tree['writers'].append(writer_info)

        # Check if we hit a file I/O function
        func_name = writer_info.get('function', '')
        if func_name in ('pread64', 'read', '_tiffReadProc', '_TIFFmemcpy'):
            # Extract file offset from arguments
            offset = writer_info.get('offset')
            if offset is not None:
                file_offsets.append(offset)
            break

        # Check if we hit a TIFF read function
        if func_name in ('TIFFReadDirectory', 'TIFFFetchNormalTag', 'TIFFFetchStripThing',
                         '_TIFFReadDirEntryArray', 'TIFFReadCustomDirectory'):
            # These functions read from file - the data comes from pread64
            # We've traced far enough
            break

        # Try to find the next address to trace (the source of the data)
        # Look for pointer arguments or source variables
        source_addr = _find_source_address(writer_info)
        if source_addr is None or source_addr == current_addr:
            break
        current_addr = source_addr

    result = {
        'chain': chain,
        'file_offsets': file_offsets,
        'trace_tree': trace_tree,
        'depth_reached': len(chain),
    }
    return result, None


def _parse_watchpoint_hit(output, depth):
    """Parse GDB output from a watchpoint hit."""
    info = {
        'depth': depth,
        'function': None,
        'file': None,
        'line': None,
        'backtrace': [],
        'locals': {},
        'args': {},
        'offset': None,
    }

    in_backtrace = False
    in_frame = False
    in_locals = False
    in_args = False

    for line in output.splitlines():
        line = line.strip()

        if line == 'BACKTRACE_START':
            in_backtrace = True
            continue
        if line == 'BACKTRACE_END':
            in_backtrace = False
            continue
        if in_backtrace:
            info['backtrace'].append(line)
            # Extract top frame function
            if info['function'] is None:
                m = re.match(r'#\d+\s+(\w+)\s*\(', line)
                if m:
                    info['function'] = m.group(1)
                    # Extract file:line if present
                    m2 = re.search(r'at\s+([^:]+):(\d+)', line)
                    if m2:
                        info['file'] = m2.group(1)
                        info['line'] = int(m2.group(2))
            continue

        if line == 'FRAME_INFO_START':
            in_frame = True
            continue
        if line == 'FRAME_INFO_END':
            in_frame = False
            continue

        if line == 'LOCALS_START':
            in_locals = True
            continue
        if line == 'LOCALS_END':
            in_locals = False
            continue
        if in_locals:
            m = re.match(r'(\w+)\s*=\s*(.+)', line)
            if m:
                info['locals'][m.group(1)] = m.group(2)
            continue

        if line == 'ARGS_START':
            in_args = True
            continue
        if line == 'ARGS_END':
            in_args = False
            continue
        if in_args:
            m = re.match(r'(\w+)\s*=\s*(.+)', line)
            if m:
                info['args'][m.group(1)] = m.group(2)
                # Extract offset from pread64 arguments
                if m.group(1) == 'offset':
                    try:
                        info['offset'] = int(m.group(2))
                    except:
                        pass
            continue

    return info


def _find_source_address(writer_info):
    """Try to find the source address that the writer read from."""
    # Look for pointer arguments that might be the data source
    args = writer_info.get('args', {})
    locals_dict = writer_info.get('locals', {})

    # Common patterns: buf, data, src, in, dir
    source_names = ['buf', 'data', 'src', 'in', 'dir', 'tdir', 'value', 'v']

    for name in source_names:
        if name in args:
            val_str = args[name]
            m = re.match(r'0x([0-9a-f]+)', val_str)
            if m:
                return int(m.group(1), 16)
        if name in locals_dict:
            val_str = locals_dict[name]
            m = re.match(r'0x([0-9a-f]+)', val_str)
            if m:
                return int(m.group(1), 16)

    return None


def run_gdb_libtiff_tag_trace(binary, fork_spec, input_file, program_args, timeout=60):
    """Trace libtiff tag accesses at the fork point to file offsets.

    For variables like `tif->tif_fields[mb]->field_tag`:
    1. At fork point, get mb (index) and field_tag (tag ID)
    2. Get tif->tif_fields[mb] pointer (TIFFField*)
    3. Parse IFD to find which entry has this tag ID
    4. Return the file offset of that IFD entry

    Returns dict with variable -> file_offset mapping.
    """
    real_binary = resolve_binary(binary)
    run_parts = [a.replace('{input_file}', input_file).replace('{input}', input_file)
                 for a in program_args]
    env = build_run_env(real_binary)

    script = f"""set pagination off
set confirm off
set breakpoint pending on

break {fork_spec}
commands
  silent
  printf "FORK_HIT\\n"
  python
import gdb

result = {{}}

# Get mb index
try:
    mb = int(gdb.parse_and_eval('mb'))
    result['mb'] = mb
    print(f"MB {{mb}}")
except Exception as e:
    print(f"MB_ERR {{e}}")

# Get tagid (function parameter)
try:
    tagid = int(gdb.parse_and_eval('tagid'))
    result['tagid'] = tagid
    print(f"TAGID {{tagid}}")
except Exception as e:
    print(f"TAGID_ERR {{e}}")

# Get tif->tif_fields[mb]->field_tag
try:
    field_tag = int(gdb.parse_and_eval('tif->tif_fields[mb]->field_tag'))
    result['field_tag'] = field_tag
    print(f"FIELD_TAG {{field_tag}}")
except Exception as e:
    print(f"FIELD_TAG_ERR {{e}}")

# Get tif->tif_fields[mb] pointer
try:
    field_ptr = int(gdb.parse_and_eval('tif->tif_fields[mb]'))
    result['field_ptr'] = field_ptr
    print(f"FIELD_PTR 0x{{field_ptr:x}}")
except Exception as e:
    print(f"FIELD_PTR_ERR {{e}}")

# Get tif->tif_fields array base
try:
    fields_base = int(gdb.parse_and_eval('tif->tif_fields'))
    result['fields_base'] = fields_base
    print(f"FIELDS_BASE 0x{{fields_base:x}}")
except Exception as e:
    print(f"FIELDS_BASE_ERR {{e}}")

# Get tif->tif_nfields
try:
    nfields = int(gdb.parse_and_eval('tif->tif_nfields'))
    result['nfields'] = nfields
    print(f"NFIELDS {{nfields}}")
except Exception as e:
    print(f"NFIELDS_ERR {{e}}")

# Enumerate all tif_fields to find tag IDs
try:
    nfields = int(gdb.parse_and_eval('tif->tif_nfields'))
    print("FIELDS_ENUM_START")
    for i in range(min(nfields, 200)):  # Limit to 200 entries
        try:
            tag = int(gdb.parse_and_eval(f'tif->tif_fields[{{i}}]->field_tag'))
            print(f"FIELD_{{i}} tag={{tag}}")
        except:
            pass
    print("FIELDS_ENUM_END")
except Exception as e:
    print(f"FIELDS_ENUM_ERR {{e}}")

print("TRACE_END")
end
  quit
end

run {' '.join(run_parts)}
"""

    fd, script_file = tempfile.mkstemp(suffix='.gdb', prefix='gdb_tag_')
    os.close(fd)
    with open(script_file, 'w') as f:
        f.write(script)

    try:
        proc = subprocess.run(
            ['gdb', '-batch', '-nx', '-q', '-x', script_file, '--', real_binary],
            capture_output=True, text=True, errors="replace", timeout=timeout, env=env)
    except subprocess.TimeoutExpired:
        return None, 'timeout'
    finally:
        try: os.unlink(script_file)
        except: pass

    output = proc.stdout + proc.stderr
    if 'FORK_HIT' not in output:
        return None, 'fork_not_reached'

    # Parse results
    result = {
        'mb': None,
        'tagid': None,
        'field_tag': None,
        'field_ptr': None,
        'fields_base': None,
        'nfields': None,
        'all_tags': {},  # index -> tag_id
    }

    in_enum = False
    for line in output.splitlines():
        line = line.strip()
        m = re.match(r'MB (\d+)', line)
        if m: result['mb'] = int(m.group(1))
        m = re.match(r'TAGID (\d+)', line)
        if m: result['tagid'] = int(m.group(1))
        m = re.match(r'FIELD_TAG (\d+)', line)
        if m: result['field_tag'] = int(m.group(1))
        m = re.match(r'FIELD_PTR (0x[0-9a-f]+)', line)
        if m: result['field_ptr'] = int(m.group(1), 16)
        m = re.match(r'FIELDS_BASE (0x[0-9a-f]+)', line)
        if m: result['fields_base'] = int(m.group(1), 16)
        m = re.match(r'NFIELDS (\d+)', line)
        if m: result['nfields'] = int(m.group(1))
        if line == 'FIELDS_ENUM_START':
            in_enum = True
            continue
        if line == 'FIELDS_ENUM_END':
            in_enum = False
            continue
        if in_enum:
            m = re.match(r'FIELD_(\d+) tag=(\d+)', line)
            if m:
                result['all_tags'][int(m.group(1))] = int(m.group(2))

    return result, None


def map_libtiff_tag_to_file_offset(tag_id, input_file):
    """Map a libtiff tag ID to its IFD entry file offset.

    Parses the TIFF IFD and returns the file offset of the entry with the given tag ID.
    Returns (entry_offset, value_offset, tag_name) or (None, None, None).
    """
    if not input_file or not os.path.isfile(input_file):
        return None, None, None

    try:
        tags = parse_tiff_ifd(input_file)
        if not tags:
            return None, None, None

        for tid, tinfo in tags.items():
            if tid == tag_id:
                entry_off = tinfo.get('entry_offset', 0)
                val_off = tinfo.get('value_offset_in_file', entry_off + 8)
                name = tinfo.get('name', f'tag_{tid}')
                return entry_off, val_off, name
    except Exception:
        pass

    return None, None, None


def parse_deep_trace(output):
    """Parse raw GDB output from the TIFFOpen-internals deep trace.

    Extracts:
    - Function breakpoints (which TIFF functions were actually called)
    - pread64 calls (offset and size) — the file reads that happened during
      TIFFOpen, i.e. the specific reads that determine the handle's value
    - Error messages (IO errors, etc.) that explain a NULL return
    """
    result = {
        'functions_called': [],
        'pread64_calls': [],
        'errors': [],
        'tif_ptr': None,
    }

    if not output:
        return result

    for line in output.splitlines():
        line = line.strip()

        # Capture function breakpoints
        m = re.match(r'Breakpoint \d+, (\w+) \(', line)
        if m:
            func_name = m.group(1)
            if func_name not in result['functions_called']:
                result['functions_called'].append(func_name)
            # Capture TIFF pointer
            if func_name in ('TIFFReadDirectory', 'TIFFFetchDirectory', 'TIFFFetchStripThing'):
                mp = re.search(r'tif=(0x[0-9a-f]+)', line)
                if mp:
                    result['tif_ptr'] = mp.group(1)

        # Capture pread64 call to syscall
        if 'call to syscall pread64' in line:
            m = re.search(r'count=count@entry=(\d+),\s*offset=(\d+)', line)
            if m:
                result['pread64_calls'].append({
                    'offset': int(m.group(2)),
                    'size': int(m.group(1)),
                })

        # Capture error messages from TIFF library
        if 'Warning' in line and ('IO error' in line or 'Bogus' in line or 'error' in line.lower()):
            result['errors'].append(line)
        if 'TIFFFetchStripThing' in line and 'error' in line.lower():
            result['errors'].append(line)

    return result


def _parse_value_str(val_str):
    """Parse a GDB value string into an int (hex or decimal) or return the string."""
    val_str = val_str.strip()
    m = re.match(r'(0x[0-9a-fA-F]+)', val_str)
    if m:
        return int(m.group(1), 16)
    if val_str.isdigit() or (val_str.startswith('-') and val_str[1:].isdigit()):
        return int(val_str)
    return val_str


def parse_gdb_log(log_text):
    variables = []
    func_args = []
    mappings = []
    heap_ptrs = []
    frames = []
    strip_offset = None
    current_var = None
    in_args = False
    in_mappings = False
    in_backtrace = False
    cur_frame = None
    file_reads = []
    ifd_found = []  # list of {'addr': int, 'tags': {tag_id: {'name', 'value', 'val_addr'}}}

    for line in log_text.split('\n'):
        line = line.strip()

        # Parse PREAD64 with buffer address (new format from dynamic trace)
        # Format: "PREAD64 fd=3 offset=64 size=784 buf=0x7ffff7dc5000"
        if line.startswith('PREAD64 fd='):
            m = re.match(r'PREAD64 fd=(\d+) offset=(-?\d+) size=(-?\d+) buf=(0x[0-9a-f]+)', line)
            if m:
                fd = int(m.group(1))
                offset = int(m.group(2))
                size = int(m.group(3))
                buf = int(m.group(4), 16)
                file_reads.append({'fd': fd, 'offset': offset, 'size': size,
                                   'buf_addr': buf})
            continue

        # Parse PREAD64_DATA: hex bytes dumped after pread64 returns
        # Format: "PREAD64_DATA fd=3 offset=64 buf=0x... size=784 bytes=0a1b2c..."
        if line.startswith('PREAD64_DATA'):
            m = re.match(r'PREAD64_DATA fd=(\d+) offset=(-?\d+) buf=(0x[0-9a-f]+) size=(-?\d+) bytes=([0-9a-f]*)', line)
            if m:
                fd = int(m.group(1))
                offset = int(m.group(2))
                buf = int(m.group(3), 16)
                size = int(m.group(4))
                hex_str = m.group(5)
                data = bytes.fromhex(hex_str) if hex_str else b''
                # Update the last file_reads entry with buffer data
                for fr in reversed(file_reads):
                    if fr.get('fd') == fd and fr.get('offset') == offset and fr.get('buf_addr') == buf:
                        fr['buf_data'] = data
                        break
            continue

        # Parse I/O operations (legacy catch syscall output)
        # Format: "IO fd=3 offset=-1 size=832" (read) or "IO fd=3 offset=64 size=784" (pread64)
        if line.startswith('IO fd='):
            m = re.match(r'IO fd=(\d+) offset=(-?\d+) size=(\d+)'
                         r'(?: buf=(0x[0-9a-f]+))?', line)
            if m:
                fd = int(m.group(1))
                offset = int(m.group(2))
                size = int(m.group(3))
                rec = {'fd': fd, 'offset': offset, 'size': size}
                if m.group(4):
                    rec['buf_addr'] = int(m.group(4), 16)
                file_reads.append(rec)
            continue

        # Legacy format (backward compat)
        if line.startswith('FILE_READ fd='):
            m = re.match(r'FILE_READ fd=(\d+) offset=(\d+) size=(\d+)', line)
            if m:
                fd = int(m.group(1))
                offset = int(m.group(2))
                size = int(m.group(3))
                file_reads.append({'fd': fd, 'offset': offset, 'size': size})
            continue

        if line.startswith('STRIP_OFFSET '):
            parts = line.split()
            if len(parts) >= 2:
                try:
                    strip_offset = int(parts[1])
                except ValueError:
                    pass
            continue

        # Parse IFD_FOUND / IFD_TAG from dynamic memory scan
        if line.startswith('IFD_FOUND '):
            m = re.search(r'buf=(0x[0-9a-f]+)', line)
            if m:
                ifd_found.append({'addr': int(m.group(1), 16), 'tags': {}})
            continue
        if line.startswith('IFD_TAG '):
            m = re.match(r'IFD_TAG tag=(\d+) name=(\S+) value=(0x[0-9a-f]+) val_addr=(0x[0-9a-f]+)', line)
            if m and ifd_found:
                tag_id = int(m.group(1))
                tag_name = m.group(2)
                tag_val = int(m.group(3), 16)
                val_addr = int(m.group(4), 16)
                ifd_found[-1]['tags'][tag_id] = {
                    'name': tag_name, 'value': tag_val, 'val_addr': val_addr}
            continue

        if line == 'ARGS_END':
            in_args = False
            continue

        if in_args:
            m = re.match(r'(\w+)\s*=\s*(.*)', line)
            if m:
                name = m.group(1)
                val = _parse_value_str(m.group(2))
                func_args.append({'name': name, 'val': val})
                continue

        if in_backtrace:
            if line == 'BACKTRACE_END':
                in_backtrace = False
                continue
            # Frame header: #N 0xADDR in FUNC (args) at file:line
            fm = re.match(r'#(\d+)\s+(?:0x[0-9a-fA-F]+\s+in\s+)?(\w+)\s*\((.*)\)\s+at\s+(\S+):(\d+)', line)
            if fm:
                if cur_frame:
                    frames.append(cur_frame)
                cur_frame = {
                    'index': int(fm.group(1)),
                    'func': fm.group(2),
                    'args': {},
                    'locals': {},
                }
                args_text = fm.group(3)
                for part in _split_c_arguments(args_text):
                    am = re.match(r'(\w+)\s*=\s*(.*)', part)
                    if am:
                        cur_frame['args'][am.group(1)] = _parse_value_str(am.group(2))
                continue
            # Local variable line:  name = value
            if cur_frame is not None:
                lm = re.match(r'(\w+)\s*=\s*(.*)', line)
                if lm:
                    name = lm.group(1)
                    if name not in ('__PRETTY_FUNCTION__',):
                        cur_frame['locals'][name] = _parse_value_str(lm.group(2))
                continue

        if line == 'HEAP_SCAN_START':
            continue
        if line == 'HEAP_SCAN_END':
            continue
        if line.startswith('HEAP_PTR ') or line.startswith('STACK_PTR '):
            parts = line.split()
            if len(parts) >= 3:
                heap_ptrs.append({
                    'ptr': int(parts[1], 16),
                    'name': parts[2],
                    'type': 'heap' if 'HEAP_PTR' in line else 'stack',
                })
            continue

        if line == 'MAPPINGS_END':
            in_mappings = False
            continue
        if in_mappings:
            m = re.match(r'(0x[0-9a-f]+)\s+(0x[0-9a-f]+)\s+(\S+)', line)
            if m:
                mappings.append({
                    'start': int(m.group(1), 16),
                    'end': int(m.group(2), 16),
                    'path': m.group(3),
                })
            continue

        m = re.match(r'VAR_NAME (.+)', line)
        if m:
            current_var = {'name': m.group(1)}
            continue
        m = re.match(r'VAR_ADDR 0x([0-9a-f]+)', line)
        if m and current_var:
            current_var['addr'] = int(m.group(1), 16)
            continue
        m = re.match(r'VAR_VAL (-?\d+)', line)
        if m and current_var:
            current_var['val'] = int(m.group(1))
            continue
        m = re.match(r'VAR_SIZE (\d+)', line)
        if m and current_var:
            current_var['size'] = int(m.group(1))
            variables.append(current_var)
            current_var = None
            continue

        if line == 'FRAME_0_ARGS':
            in_args = True
            in_backtrace = False
            continue
        if line == 'BACKTRACE_START':
            in_backtrace = True
            in_args = False
            continue
        if line.startswith('Start Addr') or line.startswith('start_addr'):
            in_mappings = True
            in_backtrace = False
            continue

    if cur_frame:
        frames.append(cur_frame)

    return {
        'variables': variables,
        'func_args': func_args,
        'mappings': mappings,
        'heap_ptrs': heap_ptrs,
        'frames': frames,
        'strip_offset': strip_offset,
        'file_reads': file_reads,
        'ifd_found': ifd_found,
    }


def _split_c_arguments(args_text):
    """Split a C argument list string on commas, respecting nested parens/angle brackets."""
    parts = []
    depth = 0
    cur = ''
    for ch in args_text:
        if ch in '(<[{':
            depth += 1
        elif ch in ')>]}':
            depth -= 1
        if ch == ',' and depth == 0:
            parts.append(cur.strip())
            cur = ''
        else:
            cur += ch
    if cur.strip():
        parts.append(cur.strip())
    return parts


# ---------------------------------------------------------------------------
# Analysis: combine GDB + file parsing
# ---------------------------------------------------------------------------

def _is_corrupted_tiff_tag(tiff_tags, tag_id, info):
    """Check if a TIFF tag entry looks corrupted (unknown tag, bad values)."""
    KNOWN_TAGS = {
        256, 257, 258, 259, 262, 266, 273, 274, 277, 278, 279, 282, 283,
        296, 320, 321, 322, 323, 324, 325, 327, 328, 329, 330, 332, 333,
        338, 339, 347, 512, 513, 514, 515, 516, 517, 518, 519, 520, 521,
        529, 530, 531, 532, 559, 562, 2048, 2049, 2050, 2051, 2052,
        33723, 34377, 34665, 34675, 34853, 37385, 37386, 37387, 37388,
        37389, 37390, 37392, 37393, 42112, 42113,
    }
    # Unknown tag → corrupted
    if tag_id not in KNOWN_TAGS:
        return True
    val = info.get('value', 0)
    if isinstance(val, tuple):
        val = max(val) if val else 0
    typ = info.get('type', 0)
    count = info.get('count', 0)
    # Invalid type
    if typ == 0:
        return True
    # Huge count
    if count > 10000:
        return True
    # Known tag with clearly wrong value
    VALUE_LIMITS = {
        256: 0x100000,     # ImageWidth: max ~1M
        257: 0x100000,     # ImageLength
        277: 100,          # SamplesPerPixel: max ~100
        278: 0x100000,     # RowsPerStrip
        259: 100,          # Compression: max ~100
        262: 30,           # PhotometricInterpretation
    }
    if tag_id in VALUE_LIMITS and val > VALUE_LIMITS[tag_id]:
        return True
    return False


# TIFFDirEntry in-memory layout (libtiff/tif_dir.h)
#   uint16 tdir_tag;    // offset 0
#   uint16 tdir_type;   // offset 2
#   uint64 tdir_count;  // offset 8 (4 bytes padding after tdir_type)
#   union  tdir_offset; // offset 16
TIFF_DIRENTRY_SIZE = 24

# TIFFDirEntry field -> byte offset within the 12-byte file IFD entry
# (file entry = tag[2] type[2] count[4] value/offset[4])
TIFF_DIRENTRY_FILE_FIELD = {
    'tdir_tag': 0,
    'tdir_type': 2,
    'tdir_count': 4,
    'tdir_offset': 8,
}

# TIFFDirEntry field -> byte size within the file IFD entry
TIFF_DIRENTRY_FILE_FIELD_SIZE = {
    'tdir_tag': 2,
    'tdir_type': 2,
    'tdir_count': 4,
    'tdir_offset': 4,
}

# image_data (tiffcrop) / TIFF directory field -> TIFF tag id.
# These struct fields are populated directly from TIFFGetField(tag, ...).
IMAGE_FIELD_TO_TAG = {
    'width': 256,         # ImageWidth
    'length': 257,        # ImageLength
    'bps': 258,           # BitsPerSample
    'spp': 277,           # SamplesPerPixel
    'photometric': 262,   # PhotometricInterpretation
    'planar': 284,        # PlanarConfiguration
    'compression': 259,   # Compression
    'orientation': 274,   # Orientation
    'res_unit': 296,      # ResolutionUnit
    'xres': 282,          # XResolution
    'yres': 283,          # YResolution
    'rowsperstrip': 278,  # RowsPerStrip
    'stripbytecounts': 279,  # StripByteCounts
}


def parse_var_expr(expr):
    """Split a C variable expression into (root, fields, array_index).

    'direntry->tdir_count' -> ('direntry', ['tdir_count'], None)
    'src[0]'               -> ('src', [], 0)
    'tif->tif_dir.td_x'    -> ('tif', ['tif_dir', 'td_x'], None)
    'typesize'             -> ('typesize', [], None)
    """
    expr = expr.strip()
    idx = None
    m = re.search(r'\[(\d+)\]', expr)
    if m:
        idx = int(m.group(1))
    m = re.match(r'^([a-zA-Z_]\w*)', expr)
    root = m.group(1) if m else None
    fields = re.findall(r'(?:->|\.)\s*([a-zA-Z_]\w*)', expr)
    return root, fields, idx


def get_tiff_ifd_offset(filepath):
    """Read the TIFF header and return the IFD offset (byte 4-7)."""
    try:
        with open(filepath, 'rb') as f:
            data = f.read(8)
        if len(data) < 8 or data[0:2] not in (b'II', b'MM'):
            return None
        fmt = '<' if data[0:2] == b'II' else '>'
        return struct.unpack_from(fmt + 'I', data, 4)[0]
    except Exception:
        return None


def find_version_root(binary):
    """Walk up from the binary to find the version root directory."""
    d = Path(binary).resolve().parent
    for _ in range(6):
        if (d / "configure").exists() or (d / ".build_ok").exists():
            return str(d)
        if d.parent == d:
            break
        d = d.parent
    return None


def locate_source_file(filename, binary=None):
    """Resolve a source file path, preferring the binary's version root."""
    if not filename:
        return None
    p = Path(filename)
    if p.is_absolute() and p.exists():
        return str(p)
    if p.exists():
        return str(p)
    base = p.name
    # Prefer the target binary's version root so we pick the right version.
    if binary:
        root = find_version_root(binary)
        if root:
            for match in Path(root).rglob(base):
                if match.is_file():
                    return str(match)
    for ver_dir in Path('.').glob('*-versions'):
        for match in ver_dir.rglob(base):
            if match.is_file():
                return str(match)
    return None


def map_tiff_direntry_field(symbols, dir_base, ifd_offset, root, fields):
    """Map root->field (root is a TIFFDirEntry*) to file offsets.

    Returns (offsets, idx) or ([], None).
    """
    if dir_base is None or ifd_offset is None or root not in symbols:
        return [], None
    rv = symbols[root]
    if not isinstance(rv, int):
        return [], None
    delta = rv - dir_base
    if delta < 0 or delta % TIFF_DIRENTRY_SIZE != 0:
        return [], None
    idx = delta // TIFF_DIRENTRY_SIZE
    entry_off = ifd_offset + 2 + idx * 12
    offs = []
    for f in fields:
        fo = TIFF_DIRENTRY_FILE_FIELD.get(f)
        if fo is None:
            continue
        fsize = TIFF_DIRENTRY_FILE_FIELD_SIZE.get(f, 1)
        offs.extend(range(entry_off + fo, entry_off + fo + fsize))
    return offs, idx


def find_assignments(source_file, var_expr, search_range=None):
    """Find all assignments to var_expr in the source file.

    Handles `=`, `+=`, `-=`, `*=`, `/=`, `%=` and multi-line RHS.  Returns a
    list of (op, rhs, line_number) tuples (in file order).  The `(?<![\w.>])`
    guard keeps `a.buffsize = ...` from matching a bare `buffsize = ...`.
    If search_range=(lo,hi) is given, only lines in [lo,hi] are considered.
    """
    if not source_file or not var_expr:
        return []
    try:
        lines = Path(source_file).read_text(errors='replace').splitlines()
    except Exception:
        return []
    esc = re.escape(var_expr)
    # (?!=) after the operator rejects `==`/`!=`/`<=`/`>=` comparisons so that
    # only true assignments (=, +=, -=, *=, /=, %=, ...) are matched.
    pat = re.compile(r'(?<![\w.>])' + esc + r'\s*([+\-*/%&|^]?=)(?!=)\s*')
    out = []
    n = len(lines)
    lo = search_range[0] if search_range else 1
    hi = search_range[1] if search_range else n
    for ln, line in enumerate(lines, start=1):
        if ln < lo or ln > hi:
            continue
        m = pat.search(line)
        if not m:
            continue
        rhs = line[m.end():].strip()
        # If the RHS does not terminate on this line, join continuation lines
        # until a ';' is reached.
        j = ln  # index of the next line (0-based)
        while ';' not in rhs and j < n:
            rhs += ' ' + lines[j].strip()
            j += 1
        rhs = rhs.split(';', 1)[0].strip()
        out.append((m.group(1), rhs, ln))
    return out


def find_function_body_range(source_file, line):
    """Return (start_line, end_line) of the enclosing function body for `line`.

    Locates the function *signature* (a column-0 line containing an opening
    '(' that is not a forward declaration), then brace-matches its body.
    Returns None on failure.
    """
    if not source_file or not line:
        return None
    try:
        lines = Path(source_file).read_text(errors='replace').splitlines()
    except Exception:
        return None
    n = len(lines)
    sig = None
    for i in range(line - 1, max(0, line - 500) - 1, -1):
        raw = lines[i]
        if raw[:1] in (' ', '\t'):
            continue
        stripped = raw.strip()
        if not stripped:
            continue
        if stripped.startswith(('#', '//', '/*', '*')):
            continue
        if stripped.endswith(';'):
            continue  # forward declaration
        if '(' in stripped:
            sig = i
            break
    if sig is None:
        return None
    brace = None
    for j in range(sig, min(sig + 30, n)):
        if '{' in lines[j]:
            brace = j
            break
    if brace is None:
        return None
    depth = 0
    for j in range(brace, n):
        depth += lines[j].count('{') - lines[j].count('}')
        if depth == 0:
            return (brace + 1, j + 1)
    return None


def _is_trivial_rhs(rhs):
    """True if the RHS is a trivial init/constant (0, NULL, etc.)."""
    s = (rhs or '').strip()
    if s in ('0', 'NULL', 'nullptr', '0x0', '0U', '0L'):
        return True
    return False


def is_function_definition(source_file, name):
    """True if `name` is defined as a function in the source (not a variable).

    Matches `static int name(...)` / `name(...)` definitions (with a body),
    skipping forward declarations (which end with ';').
    """
    if not source_file or not name:
        return False
    try:
        lines = Path(source_file).read_text(errors='replace').splitlines()
    except Exception:
        return False
    pat = re.compile(
        r'^(?:(?:static|inline|extern)\s+)?(?:[\w\s\*]+?\s+)?'
        + re.escape(name) + r'\s*\(')
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith(('#', '//', '/*', '*')):
            continue
        if stripped.endswith(';'):
            continue
        if pat.match(stripped):
            return True
    return False


def find_function_line(source_file, func_name):
    """Return the line number of func_name's definition, or None."""
    if not source_file or not func_name:
        return None
    try:
        lines = Path(source_file).read_text(errors='replace').splitlines()
    except Exception:
        return None
    pat = re.compile(
        r'^(?:(?:static|inline|extern)\s+)?(?:[\w\s\*]+?\s+)?'
        + re.escape(func_name) + r'\s*\(')
    for i, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith(('#', '//', '/*', '*')):
            continue
        if stripped.endswith(';'):
            continue
        if pat.match(stripped):
            return i
    return None


def locate_function_source(func_name, src_path=None):
    """Find the source file that defines func_name (search version dirs)."""
    if not func_name:
        return None
    roots = []
    if src_path:
        p = Path(src_path)
        for parent in [p] + list(p.parents):
            if (parent / 'configure').exists() or (parent / 'Makefile').exists():
                roots.append(parent)
                break
    for d in Path('.').glob('*-versions'):
        roots.append(d)
    seen = set()
    for root in roots:
        for f in root.rglob('*.c'):
            s = str(f)
            if s in seen:
                continue
            seen.add(s)
            if is_function_definition(s, func_name):
                return s
    return None


def extract_function_calls(expr):
    """Extract function-call names from an expression."""
    if not expr:
        return []
    calls = re.findall(r'\b([a-zA-Z_]\w*)\s*\(', expr)
    skip = {'if', 'while', 'for', 'switch', 'sizeof', 'return', 'assert',
            'min', 'max', 'abs'}
    return [c for c in calls if c not in skip]


def trace_function_return(func_name, src_path, symbols, dir_base, ifd_offset,
                          tag_id_to_entry, depth=0, visited=None):
    """Trace a function's return value to file offsets.

    Finds the function's definition, extracts the struct-field accesses in its
    body (which feed the return value), and maps them to file offsets.  This is
    a heuristic: it over-approximates the return value's dependencies, but it is
    format-independent (relies only on the field -> offset mapping tables).
    Returns (offsets, sources).
    """
    if visited is None:
        visited = set()
    if depth > 4 or not func_name:
        return [], []
    if func_name in visited:
        return [], []
    visited.add(func_name)

    fsrc = locate_function_source(func_name, src_path)
    if not fsrc:
        return [], []
    fn_line = find_function_line(fsrc, func_name)
    if fn_line is None:
        return [], []
    rng = find_function_body_range(fsrc, fn_line)
    if rng is None:
        return [], []

    try:
        lines = Path(fsrc).read_text(errors='replace').splitlines()
    except Exception:
        return [], []
    body = ' '.join(lines[rng[0] - 1:rng[1]])

    offsets = []
    sources = []
    for ref in extract_variables_from_statement(body):
        if '->' not in ref and '.' not in ref:
            continue
        so, ss = resolve_value_source(
            ref, fsrc, symbols, dir_base, ifd_offset,
            tag_id_to_entry, context_line=fn_line, depth=depth + 1, visited=visited)
        if so:
            offsets.extend(so)
            sources.extend(f'{func_name}() -> {s}' for s in ss)
    return offsets, sources


def resolve_value_source(var_expr, src_path, symbols, dir_base, ifd_offset,
                         tag_id_to_entry, context_line=None, depth=0, visited=None):
    """Recursively resolve a variable expression to input-file byte offsets.

    The value of a fork-statement variable is ultimately determined by the
    variables that participate in its computation.  This walks the assignment
    chain (including function-call return values) until it reaches a leaf that
    maps to a file byte:

      - struct field `image->bps`/`image->spp`/...  -> TIFF tag value field
      - struct field `tif_header...tiff_diroff`     -> file header field
      - struct field `direntry->tdir_count`         -> IFD entry field
      - local `cropsize = crop->bufftotal`          -> recurse into RHS
      - local `n = TIFFNumberOfDirectories(tif)`    -> trace the function

    Local variables are searched within the function body containing the
    current context line (their scope); struct fields are searched file-wide
    (they can be assigned in a different function).  Returns
    (offsets: list[int], sources: list[str]).
    """
    MAX_DEPTH = 8
    if visited is None:
        visited = set()
    if depth > MAX_DEPTH or not var_expr:
        return [], []
    key = var_expr.strip()
    if key in visited:
        return [], []
    visited.add(key)

    root, fields, idx = parse_var_expr(key)
    offsets = []
    sources = []

    if fields:
        field = fields[-1]
        # A1: known struct field -> TIFF tag value field.
        tag_id = IMAGE_FIELD_TO_TAG.get(field)
        if tag_id is not None:
            entry = tag_id_to_entry.get(tag_id) if tag_id_to_entry else None
            if entry is not None:
                offsets.append(entry + 8)
                tag_name = _TIFF_TAG_NAMES.get(tag_id, f'tag {tag_id}')
                sources.append(f'{key} <- {tag_name}({tag_id})')
                return offsets, sources
        # A2: TIFFDirEntry field.
        offs, eidx = map_tiff_direntry_field(symbols, dir_base, ifd_offset, root, fields)
        if offs:
            offsets.extend(offs)
            sources.append(f'{key} <- IFD entry[{eidx}] field {".".join(fields)}')
            return offsets, sources
        # A3: other struct field (e.g. crop->bufftotal) -> its assignment
        #     (file-wide, because the struct may be filled in another function).
        for op, rhs, ln in find_assignments(src_path, key):
            if _is_trivial_rhs(rhs):
                continue
            for func_name in extract_function_calls(rhs):
                so, ss = trace_function_return(
                    func_name, src_path, symbols, dir_base, ifd_offset,
                    tag_id_to_entry, depth=depth + 1, visited=visited)
                if so:
                    offsets.extend(so)
                    sources.extend(ss)
            for ref in extract_variables_from_statement(rhs):
                so, ss = resolve_value_source(
                    ref, src_path, symbols, dir_base, ifd_offset,
                    tag_id_to_entry, context_line=ln, depth=depth + 1, visited=visited)
                if so:
                    offsets.extend(so)
                    sources.extend(ss)
        return offsets, sources

    # Plain local variable -> its assignment, scoped to the enclosing function.
    rng = find_function_body_range(src_path, context_line) if context_line else None
    for op, rhs, ln in find_assignments(src_path, root, search_range=rng):
        if _is_trivial_rhs(rhs):
            continue
        # Trace function-call return values (e.g. n = TIFFNumberOfDirectories(tif)).
        for func_name in extract_function_calls(rhs):
            so, ss = trace_function_return(
                func_name, src_path, symbols, dir_base, ifd_offset,
                tag_id_to_entry, depth=depth + 1, visited=visited)
            if so:
                offsets.extend(so)
                sources.extend(ss)
        for ref in extract_variables_from_statement(rhs):
            so, ss = resolve_value_source(
                ref, src_path, symbols, dir_base, ifd_offset,
                tag_id_to_entry, context_line=ln, depth=depth + 1, visited=visited)
            if so:
                offsets.extend(so)
                sources.extend(ss)
    return offsets, sources


def format_offsets(offsets):
    """Collapse a sorted list of int offsets into compact ranges like '0x2c-0x2f'."""
    if not offsets:
        return ''
    offsets = sorted(set(offsets))
    parts = []
    start = prev = offsets[0]
    for o in offsets[1:]:
        if o == prev + 1:
            prev = o
            continue
        parts.append(f'0x{start:x}-0x{prev:x}' if prev > start else f'0x{start:x}')
        start = prev = o
    parts.append(f'0x{start:x}-0x{prev:x}' if prev > start else f'0x{start:x}')
    return ', '.join(parts)


def dynamic_data_flow_analysis(parsed, variables, input_file, tiff_tags=None):
    """Dynamic data flow analysis using GDB runtime observation.

    At the fork point, the TIFF library has already read the file and populated
    the image_data struct.  We observe the ACTUAL values the program computed
    (from GDB) and map them back to input file bytes via TIFF IFD parsing.

    Data flow:
      file bytes (IFD entry) → TIFF library reads → tif_dir struct →
      loadImage() copies to image_data → getCropOffsets() computes → cropsize

    We trace this chain by:
    1. Parsing the TIFF file to get tag_id → (value, file_offset_in_ifd) mapping
    2. Reading runtime variable values from GDB (image.width, image.length, etc.)
    3. Matching GDB values to tag values to find which file bytes were used
    4. Following the computation chain to map cropsize → image.* → file offsets
    """
    fork_vars = parsed.get('variables', [])
    if not fork_vars:
        return {}

    file_size = os.path.getsize(input_file) if input_file and os.path.isfile(input_file) else 0

    # --- Step 1: Parse TIFF file to get tag → file_offset mapping ---
    tag_to_file_offset = {}  # tag_id → {file_offset, value, name}
    if tiff_tags:
        # tiff_tags may be from analyze_tiff_tags ({tag_name: {tag_id, value, entry_offset}})
        # or from parse_tiff_ifd ({tag_id: {name, value, entry_offset, ...}})
        for key, t in tiff_tags.items():
            if isinstance(key, str):
                # analyze_tiff_tags format: key=tag_name, t={tag_id, value, entry_offset}
                tag_name = key
                tag_id = t.get('tag_id', 0)
                val = t.get('value', 0)
                entry_off = t.get('entry_offset', 0)
                # entry_offset is the IFD entry offset; value field is at entry+8
                val_off = t.get('value_offset_in_file', entry_off + 8)
                tag_to_file_offset[tag_id] = {
                    'file_offset': val_off,
                    'value': val,
                    'name': tag_name,
                }
            else:
                # parse_tiff_ifd format: key=tag_id, t={name, value, entry_offset, ...}
                tag_id = key
                val_off = t.get('value_offset_in_file', t.get('entry_offset', 0) + 8)
                tag_to_file_offset[tag_id] = {
                    'file_offset': val_off,
                    'value': t['value'],
                    'name': t['name'],
                }
    elif input_file and os.path.isfile(input_file):
        tags_from_file = parse_tiff_ifd(input_file)
        if tags_from_file:
            for tag_id, t in tags_from_file.items():
                val_off = t.get('value_offset_in_file', t.get('entry_offset', 0) + 8)
                tag_to_file_offset[tag_id] = {
                    'file_offset': val_off,
                    'value': t['value'],
                    'name': t['name'],
                }

    # --- Step 2: Build runtime value map from GDB variables ---
    # Map GDB variable names to their runtime values
    runtime = {}  # var_name → value
    for v in fork_vars:
        runtime[v['name']] = v.get('val', 0)

    # Also extract image.* fields if present (from GDB frame info)
    image_fields = {}  # 'width' → value
    for v in fork_vars:
        if v['name'].startswith('image.'):
            field = v['name'].split('.', 1)[1]
            image_fields[field] = v.get('val', 0)

    # --- Step 3: Map runtime values to file offsets ---
    # For each tag in the file, check if its value matches a runtime variable
    tag_value_to_offset = {}  # (tag_name, value) → file_offset
    for tag_id, tag_info in tag_to_file_offset.items():
        key = (tag_info['name'], tag_info['value'])
        tag_value_to_offset[key] = tag_info['file_offset']

    # --- Step 4: Trace data flow chain ---
    # Known data flow chains in tiffcrop:
    #   cropsize = crop.bufftotal
    #   crop.bufftotal depends on: crop.combined_width, crop.combined_length,
    #                               image.bps, image.spp
    #   crop.combined_width depends on: image.width, crop.zonelist[*], crop.edge_ref
    #   crop.combined_length depends on: image.length, crop.zonelist[*], crop.edge_ref
    #
    # So cropsize ultimately depends on: image.width, image.length, image.bps, image.spp
    # (and zone parameters from command line, which are not file-dependent)

    # Define the computation dependency chain
    # variable → set of variables it depends on
    COMPUTE_DEPS = {
        'cropsize': {'crop.bufftotal'},
        'crop_buff': {'cropsize'},
        'crop.bufftotal': {'crop.combined_width', 'crop.combined_length',
                           'image.bps', 'image.spp'},
        'crop.combined_width': {'image.width'},
        'crop.combined_length': {'image.length'},
    }

    # TIFF tag name → image_data field mapping
    TAG_TO_IMAGE_FIELD = {
        'ImageWidth': 'width',
        'ImageLength': 'length',
        'BitsPerSample': 'bps',
        'SamplesPerPixel': 'spp',
        'Compression': 'compression',
        'PhotometricInterpretation': 'photometric',
        'Orientation': 'orientation',
        'RowsPerStrip': 'rowsperstrip',
        'StripOffsets': 'stripoffset',
        'StripByteCounts': 'stripbytecount',
        'FillOrder': 'fillorder',
        'PlanarConfiguration': 'planar',
        'ResolutionUnit': 'res_unit',
        'XResolution': 'xres',
        'YResolution': 'yres',
    }

    def resolve_deps(var_name, visited=None):
        """Recursively resolve variable dependencies to file offsets."""
        if visited is None:
            visited = set()
        if var_name in visited:
            return [], []
        visited.add(var_name)

        offsets = []
        sources = []

        # Check if this variable is an image.* field
        if var_name.startswith('image.'):
            field = var_name.split('.', 1)[1]
            if field in image_fields:
                val = image_fields[field]
                # Find which TIFF tag corresponds to this field
                for tag_name, img_field in TAG_TO_IMAGE_FIELD.items():
                    if img_field == field and (tag_name, val) in tag_value_to_offset:
                        fo = tag_value_to_offset[(tag_name, val)]
                        offsets.append(fo)
                        sources.append(
                            f'DYN: {var_name}={val} read from {tag_name} '
                            f'at file@0x{fo:x}')
                        break
            return offsets, sources

        # Check if this variable's runtime value matches a TIFF tag
        if var_name in runtime:
            val = runtime[var_name]
            for (tname, tval), fo in tag_value_to_offset.items():
                if tval == val and isinstance(val, int) and val != 0:
                    offsets.append(fo)
                    sources.append(
                        f'DYN: {var_name}={val} matches {tname} '
                        f'at file@0x{fo:x}')

        # Recursively resolve dependencies
        if var_name in COMPUTE_DEPS:
            for dep in COMPUTE_DEPS[var_name]:
                dep_offsets, dep_sources = resolve_deps(dep, visited)
                offsets.extend(dep_offsets)
                sources.extend(dep_sources)

        return offsets, sources

    # --- Step 5: Analyze each fork variable ---
    result = {}
    for v in fork_vars:
        name = v['name']
        val = v.get('val', 0)

        offsets, sources = resolve_deps(name)

        # Deduplicate while preserving order
        unique_offsets = sorted(set(offsets))
        source_str = ' ; '.join(dict.fromkeys(sources)) if sources else 'not traced dynamically'
        result[name] = {
            'offsets': unique_offsets,
            'source': source_str,
        }

    return result


def analyze_offsets(parsed, input_file, variables, tiff_tags, tiff_tags_all=None,
                    fork_file=None, fork_line=None, binary=None, file_reads=None):
    """Map each fork-statement variable to the input file bytes that determine
    its VALUE (not indirect influence).

    TIFF mapping cases:
      1. Struct field access via a TIFFDirEntry* (e.g. direntry->tdir_count):
         the value lives in the IFD entry's count/type/tag field in the file.
      2. Strip-data buffer element (e.g. src[0]): value is the pixel byte read
         from the strip data, located via StripOffsets + heap offset.
      3. TIFF directory field (e.g. td_stripoffset): value is a tag value field.
      4. Local derived from a struct field (e.g. typesize = TIFFDataWidth(...)):
         traced via the source line's assignment to the underlying field.
    """
    fork_vars = parsed['variables']
    func_args = parsed.get('func_args', [])
    heap_ptrs = parsed.get('heap_ptrs', [])
    frames = parsed.get('frames', [])

    file_size = 0
    if input_file and os.path.isfile(input_file):
        file_size = os.path.getsize(input_file)

    # Flat symbol table from backtrace frames (innermost frame wins).
    symbols = {}
    for frame in frames:
        for k, v in frame.get('args', {}).items():
            symbols.setdefault(k, v)
        for k, v in frame.get('locals', {}).items():
            symbols.setdefault(k, v)
    for a in func_args:
        symbols.setdefault(a['name'], a['val'])

    ifd_offset = get_tiff_ifd_offset(input_file) if input_file else None
    dir_base = symbols.get('dir')
    dir_base = dir_base if isinstance(dir_base, int) else None

    strip_offsets_val = None
    strip_offsets_entry = None
    if tiff_tags and 'StripOffsets' in tiff_tags:
        strip_offsets_val = tiff_tags['StripOffsets']['value']
        strip_offsets_entry = tiff_tags['StripOffsets']['entry_offset']
        if isinstance(strip_offsets_val, tuple):
            strip_offsets_val = strip_offsets_val[0]
    # Prefer the program's ACTUAL strip offset (td_stripoffset[0]) captured via
    # GDB over a value re-parsed from a possibly-corrupted PoC file.
    gdb_strip = parsed.get('strip_offset')
    if isinstance(gdb_strip, int) and gdb_strip >= 0:
        strip_offsets_val = gdb_strip

    all_ptrs = set()
    for arg in func_args:
        if isinstance(arg['val'], int) and arg['val'] > 0x1000:
            all_ptrs.add(arg['val'])
    for p in heap_ptrs:
        if p['type'] == 'heap':
            all_ptrs.add(p['ptr'])
    heap_ptrs_sorted = sorted([p for p in all_ptrs if 0x500000000000 <= p < 0x600000000000])
    base_ptr = heap_ptrs_sorted[0] if heap_ptrs_sorted else None

    src_path = locate_source_file(fork_file, binary=binary) if fork_file else None

    # tag_id -> IFD entry offset, for mapping struct fields (bps/spp/width/...)
    tag_id_to_entry = {}
    if tiff_tags_all:
        for tname, tinfo in tiff_tags_all.items():
            tag_id_to_entry[tinfo['tag_id']] = tinfo['entry_offset']

    result = {}

    # Try dynamic data flow analysis first (using pread64 buffer observations)
    dyn_result = dynamic_data_flow_analysis(parsed, fork_vars, input_file, tiff_tags=tiff_tags)

    for v in fork_vars:
        name = v['name']
        addr = v.get('addr', 0)
        val = v.get('val', 0)
        size = v.get('size', 0)

        direct_offsets = []
        indirect_offsets = []
        source = 'not from input file'
        source_chain = []

        # Dynamic data flow analysis result
        dyn = dyn_result.get(name, {})
        dyn_offsets = dyn.get('offsets', [])
        dyn_source = dyn.get('source', '')
        if dyn_offsets:
            direct_offsets.extend(dyn_offsets)
            source = f'DYNAMIC: {dyn_source}'
            source_chain = [source]

        root, fields, arr_idx = parse_var_expr(name)

        # Case 1: struct field access via TIFFDirEntry*
        if not direct_offsets and dir_base is not None and root and fields:
            offs, idx = map_tiff_direntry_field(symbols, dir_base, ifd_offset, root, fields)
            if offs:
                direct_offsets.extend(offs)
                source = f'IFD entry[{idx}] field {".".join(fields)}'
                source_chain = [source]

        # Case 2: strip-data buffer element (value = pixel byte)
        if not direct_offsets and base_ptr is not None and addr >= base_ptr:
            heap_offset = addr - base_ptr
            if strip_offsets_val is not None:
                file_pos = strip_offsets_val + heap_offset
                if file_size == 0 or file_pos < file_size:
                    direct_offsets.append(file_pos)
                    source = f'strip_off({strip_offsets_val})+heap_off({heap_offset})'
                    source_chain = [source]
            else:
                direct_offsets.append(heap_offset)
                source = f'heap_off({heap_offset})'
                source_chain = [source]

        # Case 3: TIFF directory field (td_stripoffset value = StripOffsets tag value)
        if not direct_offsets and 'td_stripoffset' in name:
            if strip_offsets_entry is not None:
                direct_offsets.append(strip_offsets_entry + 8)
                source = f'StripOffsets tag value field (IFD entry@0x{strip_offsets_entry:x})'
                source_chain = [source]

        # Case 4: recursive value-source resolution (multi-level data flow).
        if not direct_offsets:
            offs, chain = resolve_value_source(
                name, src_path, symbols, dir_base, ifd_offset, tag_id_to_entry,
                context_line=fork_line)
            if offs:
                direct_offsets.extend(offs)
                source_chain = list(dict.fromkeys(chain))
                source = ' ; '.join(source_chain) if source_chain else 'resolved'
            else:
                # Distinguish a function name (e.g. tagCompare passed as a
                # comparison callback) from a value with no file data-flow.
                root, fields, _ = parse_var_expr(name)
                if not fields and is_function_definition(src_path, root):
                    source = 'function (not a variable)'

        # Case 5: Variable is a return value from a function that reads the input file.
        # E.g., `in = TIFFOpen(argv[optind], "r")` — TIFFOpen reads the TIFF header
        # and returns NULL when the file is corrupted. The file reads captured during
        # TIFFOpen execution are what determine this variable's value.
        if not direct_offsets and file_reads:
            # Known patterns: variables assigned from file-reading functions
            file_func_patterns = {
                'in': 'TIFFOpen', 'out': 'TIFFOpen',
                'tif': 'TIFFOpen',
            }
            for pat, func_name in file_func_patterns.items():
                if name == pat:
                    # Only use pread64 calls (offset >= 0) — these have explicit file offsets
                    seen_offsets = set()
                    for fr in file_reads:
                        fd = fr.get('fd', -1)
                        off = fr.get('offset', 0)
                        sz = fr.get('size', 0)
                        if fd >= 3 and off >= 0 and sz > 0 and off not in seen_offsets:
                            direct_offsets.append(off)
                            seen_offsets.add(off)
                    if direct_offsets:
                        source = f'return value of {func_name}() — determined by pread64 at these offsets'
                        source_chain = [source]
                        break

        all_offsets = sorted(set(direct_offsets + indirect_offsets))

        result[name] = {
            'address': f'0x{addr:x}' if addr else '?',
            'value': val,
            'size': size,
            'source': source,
            'source_chain': source_chain,
            'direct_offsets': sorted(set(direct_offsets)),
            'indirect_offsets': sorted(set(indirect_offsets)),
            'input_offsets': all_offsets,
        }

    tag_offsets = {}
    if tiff_tags:
        for tag_id_or_name, info in tiff_tags.items():
            if isinstance(info, dict):
                tag_name = info.get('name', str(tag_id_or_name))
                tag_offsets[tag_name] = {
                    'tag_id': info.get('tag_id', tag_id_or_name),
                    'value': info.get('value'),
                    'ifd_entry_offset': f'0x{info["entry_offset"]:04x}' if 'entry_offset' in info else None,
                }

    return {
        'base_ptr': f'0x{base_ptr:x}' if base_ptr else None,
        'strip_offsets': strip_offsets_val,
        'format': 'TIFF' if tiff_tags else None,
        'tag_offsets': tag_offsets,
        'heap_ptrs_count': len(heap_ptrs_sorted),
        'variables': result,
    }


# ---------------------------------------------------------------------------
# Arithmetic backtrace: allocator summary + def-use chain → input offsets
# ---------------------------------------------------------------------------

_ALLOC_RE = re.compile(
    r'\b(?:_TIFF|TIFF)?(?:malloc|calloc|realloc|limitMalloc)\s*\(')

_CLI_LEAF_MARKERS = ('zonelist', 'edge_ref', 'crop_mode', 'exp_mode',
                     'img_mode', 'selections', 'zones', 'regions')


def _alloc_size_expr(rhs):
    """Return the first argument expression of an allocator call in rhs.

    e.g. '(unsigned char *)_TIFFmalloc(cropsize)' -> 'cropsize'.
    """
    m = _ALLOC_RE.search(rhs or '')
    if not m:
        return None
    start = m.end()   # match includes the opening '('
    depth = 1
    end = -1
    for i in range(start, len(rhs)):
        ch = rhs[i]
        if ch == '(':
            depth += 1
        elif ch == ')':
            depth -= 1
            if depth == 0:
                end = i
                break
    if end < 0:
        return None
    args, cur, d = [], '', 0
    for ch in rhs[start:end]:
        if ch == '(':
            d += 1
        elif ch == ')':
            d -= 1
        if ch == ',' and d == 0:
            args.append(cur.strip())
            cur = ''
        else:
            cur += ch
    if cur.strip():
        args.append(cur.strip())
    if not args:
        return None
    # realloc(p, size): size is the LAST argument; others: first argument.
    if m.group(0).rstrip('(').endswith('realloc'):
        return args[-1].strip()
    return args[0].strip()


def arithmetic_backtrace(binary, fork_file, fork_line, variables, fork_vals,
                         input_file, program_args, timeout=60):
    """Backward def-use trace with allocator summaries.

    Fork variables that are allocator returns
    (``crop_buff = _TIFFmalloc(cropsize)``) are traced through their *size*
    argument; plain variables are traced through their assignment chain
    (``find_assignments`` + ``extract_variables_from_statement``).  Leaves:

      * ``image.<field>``                  -> TIFF tag value field (file offset)
      * ``crop->zonelist/edge_ref/...``    -> command-line option (no offset)
      * constants / no assignment found    -> dead end

    Runtime values of every chain expression are captured from the target
    binary at the fork point (GDB) and used to validate tag matches.
    """
    src = fork_file
    if not src or not os.path.isfile(src):
        vroot = find_version_root(binary) if binary else None
        if vroot:
            cand = os.path.join(vroot, 'tools',
                                os.path.basename(fork_file or 'tiffcrop.c'))
            if os.path.isfile(cand):
                src = cand
    if not src or not os.path.isfile(src):
        return None

    tags = {}
    if input_file and os.path.isfile(input_file):
        tags = parse_tiff_ifd(input_file) or {}

    nodes = {}   # expr -> {'kind','deps':[(expr,line,edge)],'line','rhs'}
    _MAX_DEPTH = 12
    _MAX_NODES = 90

    def _add_node(key, kind, deps, line=None, rhs=None):
        if key in nodes:
            existing = {d for d, _, _ in nodes[key]['deps']}
            for d, ln, edge in deps:
                if d not in existing:
                    nodes[key]['deps'].append((d, ln, edge))
                    existing.add(d)
            return
        nodes[key] = {'kind': kind, 'deps': list(deps), 'line': line,
                      'rhs': rhs}

    def _walk(expr, context_line, depth):
        key = (expr or '').strip()
        if depth > _MAX_DEPTH or len(nodes) > _MAX_NODES or not key:
            return
        if key in nodes:
            return
        root, fields, _idx = parse_var_expr(key)

        # TIFF-tag leaf: image.<field>
        if root == 'image' and fields and fields[-1] in IMAGE_FIELD_TO_TAG:
            _add_node(key, 'tag', [], context_line)
            return
        # command-line leaf
        if root == 'crop' and any(m in key for m in _CLI_LEAF_MARKERS):
            _add_node(key, 'cli', [], context_line)
            return
        if _is_trivial_rhs(key):
            _add_node(key, 'const', [], context_line)
            return

        rng = find_function_body_range(src, context_line) if context_line else None
        assigns = find_assignments(src, key, search_range=rng)
        if not assigns and fields:
            assigns = find_assignments(src, key)  # struct fields: file-wide

        deps, kept = [], []
        alloc_size = None
        for op, rhs, ln in assigns:
            if _is_trivial_rhs(rhs):
                continue
            kept.append((op, rhs, ln))
            sz = _alloc_size_expr(rhs)
            if sz:
                deps.append((sz, ln, 'alloc'))
                if alloc_size is None:
                    alloc_size = sz
            for ref in extract_variables_from_statement(rhs):
                if ref == key:
                    continue
                deps.append((ref, ln, 'assign'))
        if not kept:
            _add_node(key, 'unknown', [], context_line)
            return
        seen_d, uniq = set(), []
        for d, ln, edge in deps:
            if d not in seen_d:
                seen_d.add(d)
                uniq.append((d, ln, edge))
        _add_node(key, 'assign', uniq, kept[-1][2], kept[-1][1])
        if alloc_size is not None:
            nodes[key]['alloc_size'] = alloc_size
        for d, ln, edge in uniq:
            _walk(d, ln, depth + 1)

    for v in (variables or []):
        _walk(v, fork_line, 0)

    # ---- Runtime value pass: evaluate every chain expr at the fork point ----
    exprs = list(nodes.keys())
    for v in (variables or []):
        if v not in exprs:
            exprs.append(v)
    rvals = dict(fork_vals or {})
    if exprs and binary and os.path.isfile(resolve_binary(binary)):
        run_parts = [a.replace('{input_file}', input_file)
                     .replace('{input}', input_file)
                     for a in (program_args or [])]
        run_args = ' '.join(run_parts)
        script = (
            'set pagination off\nset confirm off\nset breakpoint pending on\n'
            f'break {src}:{fork_line}\n'
            'commands\n  silent\n  python\n'
            'import gdb\n'
            f'_exprs = {json.dumps(exprs)}\n'
            'for _e in _exprs:\n'
            '    try:\n'
            '        _v = int(gdb.parse_and_eval(_e))\n'
            '        print("BACKVAL " + _e + " " + str(_v))\n'
            '    except Exception:\n'
            '        pass\n'
            '  end\n  continue\nend\n'
            f'run {run_args}\n')
        fd, script_file = tempfile.mkstemp(suffix='.gdb', prefix='gdb_backtrace_')
        os.close(fd)
        with open(script_file, 'w') as f:
            f.write(script)
        try:
            proc = subprocess.run(
                ['gdb', '-batch', '-nx', '-q', '-x', script_file, '--',
                 resolve_binary(binary)],
                capture_output=True, text=True, errors="replace", timeout=timeout,
                env=build_run_env(binary))
        except subprocess.TimeoutExpired:
            proc = None
        finally:
            try:
                os.unlink(script_file)
            except Exception:
                pass
        if proc:
            for line in (proc.stdout + proc.stderr).splitlines():
                m = re.match(r'BACKVAL (.+?) (-?\d+)$', line.strip())
                if m:
                    rvals[m.group(1)] = int(m.group(2))

    # ---- Tag leaves → input file offsets ----
    tag_info = {}
    for e, node in nodes.items():
        if node['kind'] != 'tag':
            continue
        root, fields, _ = parse_var_expr(e)
        tag_id = IMAGE_FIELD_TO_TAG[fields[-1]]
        t = tags.get(tag_id)
        if not t:
            continue
        off = t.get('value_offset_in_file')
        if off is None:
            continue
        tv = t.get('value')
        if isinstance(tv, tuple):
            tv = tv[0] if tv else 0
        rv = rvals.get(e)
        tag_info[e] = {
            'file_offset': off,
            'tag_name': t.get('name'),
            'tag_id': tag_id,
            'tag_value': tv,
            'runtime': rv,
            'confirmed': (rv is not None and tv is not None and rv == tv),
        }

    # ---- Per-fork-variable reachable tag/CLI leaves ----
    chains = {}
    for v in (variables or []):
        if v not in nodes:
            continue
        reach, stack = set(), [v]
        while stack:
            n = stack.pop()
            node = nodes.get(n)
            if not node:
                continue
            for d, _ln, _edge in node['deps']:
                if d not in reach:
                    reach.add(d)
                    stack.append(d)
        if v in tag_info:
            reach.add(v)
        chains[v] = {
            'kind': nodes[v]['kind'],
            'tag_offsets': [tag_info[e] for e in sorted(reach) if e in tag_info],
            'cli_leaves': sorted(e for e in reach
                                 if nodes.get(e, {}).get('kind') == 'cli'),
            'node_count': len(reach) + 1,
        }
        if nodes[v].get('alloc_size'):
            chains[v]['allocator'] = nodes[v]['alloc_size']

    # ---- Explanation tree ----
    def _explain(e, depth, buf, seen):
        node = nodes.get(e)
        if not node or e in seen or depth > 8:
            return
        seen.add(e)
        pad = '  ' * depth
        rv = rvals.get(e)
        rv_s = f' [GDB: {rv}]' if rv is not None else ''
        if node['kind'] == 'tag':
            ti = tag_info.get(e)
            if ti:
                conf = ('GDB-confirmed' if ti['confirmed']
                        else f'tag-value={ti["tag_value"]}')
                buf.append(f'{pad}{e}{rv_s} -> {ti["tag_name"]}({ti["tag_id"]}) '
                           f'@ file 0x{ti["file_offset"]:x} [{conf}]')
            else:
                buf.append(f'{pad}{e}{rv_s} -> TIFF tag (no IFD entry found)')
            return
        if node['kind'] == 'cli':
            buf.append(f'{pad}{e}{rv_s} -> command-line option '
                       f'(not file-derived)')
            return
        if node['kind'] in ('const', 'unknown'):
            buf.append(f'{pad}{e}{rv_s} -> {node["kind"]}')
            return
        rhs_short = (node.get('rhs') or '')[:90]
        buf.append(f'{pad}{e}{rv_s} <- {rhs_short}  (line {node["line"]})')
        for d, _ln, _edge in node['deps']:
            _explain(d, depth + 1, buf, seen)

    def _build_explanation(start):
        buf, seen = [], set()
        node = nodes.get(start)
        if not node:
            return buf
        rv = rvals.get(start)
        rv_s = f' [GDB: {rv}]' if rv is not None else ''
        if node.get('alloc_size'):
            buf.append(f'{start} = {node.get("rhs", "")}  '
                       f'[allocator {node["alloc_size"]}: '
                       f'NULL <=> size==0 / OOM]')
        elif node['kind'] == 'assign':
            buf.append(f'{start}{rv_s} <- {node.get("rhs", "")}  '
                       f'(line {node.get("line")})')
        else:
            buf.append(f'{start}{rv_s}')
        for d, _ln, _edge in node['deps']:
            _explain(d, 1, buf, seen)
        return buf

    return {
        'source': src,
        'fork_line': fork_line,
        'nodes': {e: {'kind': n['kind'], 'line': n['line'], 'rhs': n['rhs']}
                  for e, n in nodes.items()},
        'runtime_values': rvals,
        'tag_mappings': tag_info,
        'chains': chains,
        'explanation': {v: _build_explanation(v) for v in chains},
    }


def fork_flip_probe(binary, input_file, program_args, offsets, fork_marker,
                    timeout=30, values=None, deadline=None):
    """Cheap fork-outcome validation: mutate each mapped offset with a few
    byte values and check whether the target's fork outcome changes.

    ``fork_marker`` is a substring that appears in the target's output exactly
    when the fork condition is taken (e.g. the 'Unable to allocate' message).

    ``values`` overrides the default trial bytes; ``deadline`` (epoch seconds)
    stops the probe early so a caller can enforce a phase budget.
    """
    results = {}
    if not (binary and input_file and os.path.isfile(input_file)):
        return results
    trial_values = tuple(values) if values else (0x01, 0x32, 0x63, 0x64, 0xFF)
    with open(input_file, 'rb') as f:
        orig = bytearray(f.read())
    run_parts = [a.replace('{input_file}', '{IN}').replace('{input}', '{IN}')
                 for a in (program_args or [])]
    _suffix = os.path.splitext(input_file)[1] or '.bin'

    def _run(data):
        fd, tmp = tempfile.mkstemp(suffix=_suffix, prefix='probe_')
        os.close(fd)
        with open(tmp, 'wb') as f:
            f.write(data)
        try:
            cmd = [resolve_binary(binary)]
            for a in run_parts:
                if '{IN}' in a:
                    cmd.append(a.replace('{IN}', tmp))
                elif a == input_file:
                    cmd.append(tmp)
                else:
                    cmd.append(a)
            proc = subprocess.run(cmd, capture_output=True, text=True, errors="replace",
                                  timeout=timeout, env=build_run_env(binary))
            return proc.stdout + proc.stderr
        except Exception:
            return ''
        finally:
            try:
                os.unlink(tmp)
            except Exception:
                pass

    base_out = _run(orig)
    base_flip = fork_marker in base_out
    for off in sorted(offsets):
        if deadline and time.time() > deadline:
            break
        if off >= len(orig):
            continue
        trials = {}
        for v in trial_values:
            if deadline and time.time() > deadline:
                break
            if v == orig[off]:
                continue
            m = bytearray(orig)
            m[off] = v
            out = _run(m)
            trials[v] = fork_marker in out
        if not trials:
            continue
        results[off] = {
            'original_byte': orig[off],
            'original_fork_taken': base_flip,
            'trials': trials,
        }
    return results


# ---------------------------------------------------------------------------
# Byte mutation crash testing
# ---------------------------------------------------------------------------

_ASAN_ERR_RE = re.compile(r'ERROR:\s*AddressSanitizer:\s*([A-Za-z0-9-]+)')
# ASan backtrace frames: "#N 0x... in <func> <file>:<line>"
_ASAN_FRAME_RE = re.compile(
    r'#(\d+)\s+0x[0-9a-fA-F]+\s+in\s+(.+?)\s+(\S+?):(\d+)\s*$')
# ASan SUMMARY: "SUMMARY: AddressSanitizer: <kind> <file>:<line> in <func>"
_ASAN_SUMMARY_RE = re.compile(
    r'SUMMARY:\s*AddressSanitizer:\s*\S+\s+(\S+?):(\d+)\s+in\s+(.+?)\s*$', re.M)
_SANITIZER_FRAME_RE = re.compile(
    r'__interceptor_|__asan_|__sanitizer_|__ubsan_|__tsan_|^libc|sanitizer|/csu/')

# ASan error types that are all memory-access violations reported as a bare
# SEGV when ASan cannot classify the access (e.g. a wild dereference that is
# really an out-of-bounds read).  A crash reported as ``SEGV`` matches any of
# these concrete types; two distinct concrete types are NOT interchangeable.
_SEGV_ASAN_FAMILY = {
    'SEGV',
    'heap-buffer-overflow',
    'stack-buffer-overflow',
    'global-buffer-overflow',
    'buffer-overflow',
    'heap-use-after-free',
    'stack-use-after-free',
    'use-after-free',
    'use-after-poison',
    'use-after-scope',
    'container-overflow',
    'dynamic-stack-buffer-overflow',
    'intra-object-overflow',
    'string-overflow',
    'unknown-crash',
}


def _crash_types_compatible(ref_type, tgt_type):
    """True when two crash types denote the same failure class.

    Types are compatible when equal, or when exactly ONE side is the coarse
    ``SEGV`` report while the other is a concrete memory-access error under
    the SEGV umbrella (ASan falls back to ``SEGV`` when it cannot classify
    the access).  Two distinct concrete types (e.g. heap-buffer-overflow vs
    use-after-free) remain different crashes.
    """
    if ref_type == tgt_type:
        return True
    if ref_type not in _SEGV_ASAN_FAMILY or tgt_type not in _SEGV_ASAN_FAMILY:
        return False
    return 'SEGV' in (ref_type, tgt_type)


def _path_basename(p):
    """Basename of a frame file path (``/build/tiffcrop.c`` -> ``tiffcrop.c``)."""
    if not p:
        return None
    return os.path.basename(str(p)) or str(p)


def _is_sanitizer_frame(frame):
    fn = (frame.get("function") or "")
    fl = (frame.get("file") or "")
    if _SANITIZER_FRAME_RE.search(fn) or _SANITIZER_FRAME_RE.search(fl):
        return True
    # glibc fortify wrappers (memcpy/memset inlined via <bits/string_fortified.h>)
    # sit between the ASan interceptor and the real project frame; without
    # filtering them crash_frames[0] becomes the wrapper and same_func
    # comparison fails against stacks built without fortify (e.g. -O0 ref).
    if "string_fortified" in fl or "bits/fortify" in fl or "chk_fail" in fl:
        return True
    if fn in ("memcpy", "memmove", "memset", "memcmp", "mempcpy",
              "__memcpy_chk", "__memmove_chk", "__memset_chk") and (
            fl.startswith("/usr/include") or fl.startswith("/usr/lib")
            or "libc" in fl or fl.startswith("../")):
        return True
    return False


def extract_crash_signature(output):
    """Parse a full crash signature out of an ASan report.

    Returns a dict with the ASan error type, the parsed backtrace frames
    (sanitizer/libc interceptors kept, but flagged) and the SUMMARY location,
    or None when the output contains no ASan error.

    ``crash_frames`` lists the project frames (interceptors removed) in stack
    order, so ``crash_frames[0]`` is the innermost user frame that actually
    faulted — not the ``memcpy``/``free`` interceptor.
    """
    if not output:
        return None
    m = _ASAN_ERR_RE.search(output)
    if not m:
        return None
    asan_type = m.group(1)
    # ASan OOM ("allocator is out of memory trying to allocate ...") is
    # resource exhaustion, not a memory-safety violation; do not treat it
    # as a crash (CVE-2018-19931-style huge allocations).
    _err_line = output[m.start():output.find('\n', m.start())]
    if asan_type == 'allocator' or 'out of memory' in _err_line:
        return None

    frames = []
    for ln in output.split('\n'):
        m2 = _ASAN_FRAME_RE.search(ln)
        if m2:
            frames.append({
                "no": int(m2.group(1)),
                "function": m2.group(2).strip(),
                "file": m2.group(3),
                "line": int(m2.group(4)),
            })

    summary = None
    m3 = _ASAN_SUMMARY_RE.search(output)
    if m3:
        summary = {
            "file": m3.group(1),
            "line": int(m3.group(2)),
            "function": m3.group(3).strip(),
        }

    crash_frames = [f for f in frames if not _is_sanitizer_frame(f)]
    return {
        "type": asan_type,
        "frames": frames,
        "crash_frames": crash_frames or frames,
        "summary": summary,
    }


def _extract_crash_type(output):
    """Legacy tuple signature ``(asan_type, crash_func)``; kept for callers
    that only need the coarse (type, top-frame-function) comparison.

    The crash function is the innermost *user* frame (interceptors skipped) —
    e.g. ``('heap-buffer-overflow', '_TIFFmemcpy')``.
    """
    sig = extract_crash_signature(output)
    if sig is None:
        return None
    crash = sig["crash_frames"][0] if sig["crash_frames"] else {}
    return (sig["type"], crash.get("function"))


# Cross-version equivalent crash functions: a refactor can rename the
# function a vulnerability crashes in while keeping the same faulty write.
# Keys are reference-side names; values are target-side equivalents.  The
# comparator matches these at stack level (not only frame[0]) so old
# versions still count as reproducing the reference crash.
_CRASH_FUNC_EQUIV = {
    # libtiff < 4.0 writes the ColorMap via TIFFWriteShortTable; 4.0 split
    # the per-tag writers and renamed the path TIFFWriteDirectoryTagColormap.
    'TIFFWriteDirectoryTagColormap': ('TIFFWriteShortTable',),
}


def _fault_stack_frames(sig):
    """Frames of the FAULTING stack only (the first stack of the report).

    ASan follows the fault stack with ``allocated by`` / ``freed by``
    stacks whose frame numbers restart at #0; those must not take part in
    the crash comparison (``crash_frames`` spans every stack and would
    otherwise intersect on the allocation path, e.g. ``loadImage``).
    """
    frames = sig.get('frames') or []
    out = []
    prev_no = -1
    for f in frames:
        no = f.get('no')
        if not isinstance(no, int):
            continue
        if out and no <= prev_no:
            break
        out.append(f)
        prev_no = no
    return out


# Frames that appear in (nearly) every stack: process entry points and
# generic memory wrappers.  A shared generic frame alone does not identify
# the vulnerability — the CALLER does — so such frames never justify a
# same_func verdict on their own.
_CRASH_STACK_NOISE = frozenset({
    'main', '_start', 'exit', 'abort',
    '__libc_start_call_main', '__libc_start_main', '__libc_start_main_impl',
    'memcpy', 'memmove', 'memset', 'memcmp',
    '_TIFFmemcpy', '_TIFFmemset', '_TIFFmalloc', '_TIFFrealloc', '_TIFFfree',
    'malloc', 'free', 'realloc', 'calloc',
    '_Znwm', '_Znam', '_ZdlPv', '_ZdaPv',
})


def _is_noise_stack_frame(func):
    if not func or func in _CRASH_STACK_NOISE:
        return True
    return func.startswith('__libc_') or func.startswith('__cxa_')


# ---------------------------------------------------------------------------
# CVE-specific crash-equivalence profiles
#
# The generic comparator below requires the same crash POINT (function +
# statement).  A few CVEs involve a source-level REWRITE (not a rename), where
# the same defect is re-implemented in a differently named function, so no
# similarity/rename mapper can link the two names.  For those CVEs only, the
# profile identifies the defect by what is version-invariant:
#   * the memory OBJECT  -> allocation stack of the overflowed buffer;
#   * the offending ACCESS -> fault function reached through a shared caller.
# The manifestation (access width, region size, overflow side) is deliberately
# NOT gated: the same defect can be a 2-byte write in one version and a 4-byte
# write in the other, or overflow the same buffer by a different amount.
# Input dependence is implicit: mutations are applied to offsets derived from
# the located fork variables.
# ---------------------------------------------------------------------------

_CVE_CRASH_PROFILES = {
    'CVE-2017-6831': {
        # IMA ADPCM decode body: the C function _af_adpcm_decoder (adpcm.c,
        # 0.3.0) was rewritten as the C++ member IMA::decodeBlockWAVE
        # (IMA.cpp:188, 0.3.6); both are called by IMA::decodeBlock.
        'ref_fault_functions': ('IMA::decodeBlockWAVE',),
        'tgt_fault_functions': ('_af_adpcm_decoder',),
        'common_caller': 'IMA::decodeBlock',
        'alloc_frames': ('Chunk::allocate', 'ModuleState::setup',
                         'afGetFrameCount'),
        'alloc_jaccard': 0.5,
    },
}

_ACTIVE_CVE_ID = None


def _cve_id_from_input(input_file):
    """Extract 'CVE-YYYY-NNNN' from the input file name (e.g. in/CVE-...)."""
    if not input_file:
        return None
    m = re.search(r'(CVE-\d{4}-\d+)', os.path.basename(str(input_file)), re.I)
    return m.group(1).upper() if m else None


def _set_active_cve(input_file):
    global _ACTIVE_CVE_ID
    _ACTIVE_CVE_ID = _cve_id_from_input(input_file)


def _func_basename(name):
    """Strip the parameter list: 'IMA::f(int)' -> 'IMA::f'."""
    return (name or '').split('(', 1)[0].strip()


def _stack_groups(sig):
    """Split parsed frames into stacks at ASan's frame-number resets.

    ASan prints the faulting stack (#0..#N), then 'allocated by' (#0..#M),
    then optionally 'freed by' (#0..#K); every stack restarts at #0.
    """
    groups, cur, prev = [], [], None
    for f in (sig or {}).get('frames') or []:
        no = f.get('no')
        if not isinstance(no, int):
            continue
        if cur and prev is not None and no <= prev:
            groups.append(cur)
            cur = []
        cur.append(f)
        prev = no
    if cur:
        groups.append(cur)
    return groups


def _allocation_stack(sig):
    groups = _stack_groups(sig)
    return groups[1] if len(groups) > 1 else []


def _alloc_frame_names(sig):
    names = []
    for f in _allocation_stack(sig):
        n = _func_basename(f.get('function'))
        if not n or _is_noise_stack_frame(n):
            continue
        if n in ('operator new', 'operator new[]',
                 'operator delete', 'operator delete[]'):
            continue
        names.append(n)
    return names


def _cve_crash_match(cve_id, ref_sig, tgt_sig):
    """CVE-specific same-defect check (does not gate on manifestation)."""
    profile = _CVE_CRASH_PROFILES.get((cve_id or '').upper())
    if not profile or not ref_sig or not tgt_sig:
        return False, ''
    if not _crash_types_compatible(ref_sig.get('type'), tgt_sig.get('type')):
        return False, ''

    rframes = ref_sig.get('crash_frames') or []
    tframes = tgt_sig.get('crash_frames') or []
    if len(rframes) < 2 or len(tframes) < 2:
        return False, ''
    rfunc = _func_basename(rframes[0].get('function'))
    tfunc = _func_basename(tframes[0].get('function'))
    if rfunc not in profile['ref_fault_functions']:
        return False, ''
    if tfunc not in profile['tgt_fault_functions']:
        return False, ''
    if _func_basename(rframes[1].get('function')) != profile['common_caller']:
        return False, ''
    if _func_basename(tframes[1].get('function')) != profile['common_caller']:
        return False, ''

    ralloc = set(_alloc_frame_names(ref_sig))
    talloc = set(_alloc_frame_names(tgt_sig))
    keys = set(profile['alloc_frames'])
    if not keys <= ralloc or not keys <= talloc:
        return False, ''
    union = ralloc | talloc
    jac = (len(ralloc & talloc) / len(union)) if union else 0.0
    if jac < profile['alloc_jaccard']:
        return False, ''
    return True, (
        f"CVE-specific equivalence ({cve_id}): same allocation object "
        f"({'/'.join(profile['alloc_frames'])}, jaccard={jac:.2f}); "
        f"fault {rfunc} vs {tfunc} both reached via "
        f"{profile['common_caller']} (access width/size not gated)")


def _resolve_source_file(file_field, binary):
    """Resolve an ASan frame's ``file`` field to a readable source path.

    Frame files are either absolute (harness temp dirs) or build-relative
    such as ``../../binutils/dwarf.c``; relative paths are resolved by
    walking up from the binary's directory until a hit is found.
    """
    if not file_field:
        return None
    if os.path.isabs(file_field):
        return file_field if os.path.isfile(file_field) else None
    if not binary:
        return None
    d = os.path.dirname(os.path.abspath(binary))
    for _ in range(8):
        cand = os.path.normpath(os.path.join(d, file_field))
        if os.path.isfile(cand):
            return cand
        parent = os.path.dirname(d)
        if parent == d:
            break
        d = parent
    return None


def _attach_crash_statement(sig, binary):
    """Fill ``sig['crash_frames'][0]['statement']`` in place (best effort).

    Stores the trimmed source line at the crash frame's file:line so
    ``compare_crash_signatures`` can apply the statement-similarity half
    of the same-vulnerability criterion.  Unresolvable source simply
    leaves the key absent; the check is then skipped (function match alone
    decides).
    """
    if not sig or not binary:
        return sig
    frames = sig.get('crash_frames') or []
    if not frames:
        return sig
    f = frames[0]
    src = _resolve_source_file(f.get('file'), binary)
    if not src:
        return sig
    try:
        with open(src, 'r', encoding='utf-8', errors='replace') as fh:
            lines = fh.readlines()
        ln = f.get('line')
        if isinstance(ln, int) and 1 <= ln <= len(lines):
            stmt = lines[ln - 1].strip()
            if stmt and not stmt.startswith('//'):
                f['statement'] = stmt
    except OSError:
        pass
    return sig


def _statements_similar(a, b):
    """Whether two crash-point statements denote the same failure point
    modulo version drift (whitespace, added guards, renames).

    Fails open when a statement is unavailable on either side (source not
    resolvable): the function match alone then decides, as before.  Two
    resolved but clearly different statements inside the same function
    mean the crash points are NOT the same vulnerability.
    """
    a = re.sub(r'\s+', ' ', a or '').strip()
    b = re.sub(r'\s+', ' ', b or '').strip()
    if not a or not b:
        return True
    if a == b:
        return True
    if len(a) >= 8 and len(b) >= 8 and (a in b or b in a):
        return True
    return difflib.SequenceMatcher(None, a, b).ratio() >= 0.5


def compare_crash_signatures(ref_sig, tgt_sig, cve_id=None):
    """Classify how close a target crash is to the reference crash.

    Returns one of:
      * 'same_site' — type, function, file AND line all match (identical
                      crash point; requires identical/mapped code lines),
      * 'same_func' — type + crash-point function match (line/file may differ
                      between versions) AND the statements at both crash
                      points are similar (or unresolvable); this is the
                      level used as "success".
                      The crash point is the innermost user frame of the fault
                      stack (sanitizer/libc interceptors filtered out), so a
                      fault one wrapper deeper on the same path still matches,
      * 'same_type' — only the ASan error type matches,
      * None        — different types (a genuinely different crash).
    Also returns a human-readable diff line for reporting.

    ``cve_id`` (or the module-level active id set from the input file name)
    enables the CVE-specific equivalence profiles defined above; those are
    opt-in per CVE and never affect other CVEs.
    """
    if ref_sig is None or tgt_sig is None:
        return None, "no crash signature to compare"
    if not _crash_types_compatible(ref_sig["type"], tgt_sig["type"]):
        return None, (f"type differs: ref={ref_sig['type']} "
                      f"target={tgt_sig['type']}")
    _cve = (cve_id or _ACTIVE_CVE_ID or '').upper()
    if _cve:
        _ok, _why = _cve_crash_match(_cve, ref_sig, tgt_sig)
        if _ok:
            return "same_func", _why
    if ref_sig["type"] != tgt_sig["type"]:
        # SEGV umbrella match (e.g. ref=heap-buffer-overflow, target=SEGV):
        # ASan reports some memory-access failures as a bare SEGV; the crash
        # SITE comparison below still decides the verdict.
        pass
    rf = ref_sig["crash_frames"][0] if ref_sig["crash_frames"] else {}
    tf = tgt_sig["crash_frames"][0] if tgt_sig["crash_frames"] else {}
    rfunc, tfunc = rf.get("function"), tf.get("function")
    if not rfunc or not tfunc:
        return "same_type", "type matches; no function info to compare"
    if rfunc != tfunc:
        _ref_funcs = {f.get("function")
                      for f in (ref_sig.get("crash_frames") or [])}
        _tgt_funcs = {f.get("function")
                      for f in (tgt_sig.get("crash_frames") or [])}
        for _f in _ref_funcs:
            for _eq in _CRASH_FUNC_EQUIV.get(_f, ()):
                if _eq in _tgt_funcs:
                    return "same_func", (
                        f"equivalent crash function: {_f} ~ {_eq} "
                        f"(ref={rfunc} target={tfunc})")
        # The two top frames differ, so the crash points are different.
        #
        # NOTE: there used to be a "shared fault-stack frame" fallback here
        # (any common non-generic project frame => same_func).  That is far
        # too permissive for tools with deep generic dispatch stacks, e.g.
        # binutils readelf/objdump: every DWARF-parsing crash shares
        # display_debug_section -> process_section_contents -> process_object
        # -> process_file, so two COMPLETELY different crash sites (e.g.
        # get_line_filename_and_dirname vs display_debug_lines_raw) were
        # wrongly classified as the same vulnerability.  The equivalence
        # standard is: same ASan type AND same crash point (innermost user
        # frame).  A fault one wrapper deeper on the same path is already
        # covered by the top-frame match after sanitizer/noise frames
        # (memcpy/malloc/etc.) are filtered out.
        return "same_type", (f"type matches but crash function differs: "
                             f"ref={rfunc} target={tfunc}")
    # Same crash function: line numbers differ across versions, so compare
    # the statements at both crash points (best effort — skipped when a
    # source line is unresolvable).  Same function but unrelated statements
    # means the two crashes are at different points of the same function
    # and must NOT count as the same vulnerability.
    if not _statements_similar(rf.get("statement"), tf.get("statement")):
        return "same_type", (
            f"same crash function {rfunc} but statements differ: "
            f"ref={rf.get('statement')!r} target={tf.get('statement')!r}")
    rfile = _path_basename(rf.get("file"))
    tfile = _path_basename(tf.get("file"))
    if rfile == tfile and rf.get("line") == tf.get("line"):
        return "same_site", (f"identical crash site: {rfunc} at "
                             f"{rfile}:{rf.get('line')}")
    return "same_func", (f"same crash function {rfunc} "
                         f"(ref {rfile}:{rf.get('line')} vs "
                         f"target {tfile}:{tf.get('line')})")


def _ifd_field_probe_values(offset, entry_size, entries_base=None):
    """Directed byte values for an IFD entry field offset.

    Structural IFD fields are semantic, not value-driven: the full 255-value
    sweep per field would explode (N entries x 4 fields x 255 runs).  Each
    field type gets a small set of meaning-bearing byte values instead:

      * tag field  — values that turn the tag into a nearby / common TIFF
        tag (a tag rewrite like RowsPerStrip 278 -> StripByteCounts 279 is
        exactly the 0xDC case: low byte 0x16 -> 0x17);
      * type field — the common TIFF field types (BYTE..DOUBLE, LONG8...);
      * count field — boundary counts (0, 1, huge);
      * offset field — in-file offsets / 0 / 8.

    Returns a sorted list of byte values (the original value is skipped by
    the caller), or None when the offset is not a valid field position.
    """
    if not entry_size or entry_size <= 0:
        return None
    # The entry starts at ``entries_base + i*entry_size``; the on-disk entry
    # start is NOT a multiple of ``entry_size`` (IFD count bytes precede it),
    # so the field position must be relative to the entries base.
    rel = (offset - (entries_base or 0)) % entry_size
    if rel in (0, 1):  # tag field (2-byte LE at entry start)
        return [0x00, 0x01, 0x02, 0x03, 0x10, 0x11, 0x12, 0x13,
                0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1c,
                0x1f, 0x20, 0x28, 0x40, 0x7f, 0xff]
    if rel in (2, 3):  # type field (2-byte LE at entry+2)
        return [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x10, 0x11, 0x12, 0xff]
    if rel in (4, 5, 6, 7):  # count field (4-byte LE at entry+4)
        return [0x00, 0x01, 0x02, 0x03, 0x10, 0x7f, 0xff, 0x00,
                0x00, 0x01, 0x02, 0xff, 0x7f, 0xff, 0xff]
    if rel in (8, 9, 10, 11):  # offset/value field (4-byte LE at entry+8)
        return [0x00, 0x01, 0x02, 0x08, 0x10, 0x40, 0x7f, 0xff,
                0x00, 0x01, 0x02, 0x10, 0xff, 0x7f, 0xff, 0xff]
    return None


def _static_ifd_region(input_file):
    """Parse the TIFF header/IFD of the input file (endian-aware).

    Dynamic fork-point context is unavailable on some target versions
    (record-full never reaches the fork breakpoint, read-offset mapping
    fails), which leaves the structural IFD candidates empty.  The IFD is
    plain on-disk structure, so it can be parsed without any runtime
    information: returns {ifd_offset, count, entry_size, entries_base,
    field_offsets} with the tag/type/count/value field start of every entry,
    or {} when the file is not a parseable TIFF.
    """
    try:
        with open(input_file, 'rb') as f:
            data = f.read()
        if len(data) < 8:
            return {}
        if data[:2] == b'II':
            e = '<'
        elif data[:2] == b'MM':
            e = '>'
        else:
            return {}
        if struct.unpack(e + 'H', data[2:4])[0] != 42:
            return {}
        ifd_off = struct.unpack(e + 'I', data[4:8])[0]
        if ifd_off + 2 > len(data):
            return {}
        count = struct.unpack(e + 'H', data[ifd_off:ifd_off + 2])[0]
        entries_base = ifd_off + 2
        max_entries = max(0, (len(data) - entries_base) // 12)
        count = min(count, max_entries)
        if count <= 0:
            return {}
        field_offsets = [entries_base + i * 12 + j
                         for i in range(count) for j in (0, 2, 4, 8)]
        return {
            'ifd_offset': ifd_off,
            'count': count,
            'entry_size': 12,
            'entries_base': entries_base,
            'field_offsets': field_offsets,
            'source': 'static',
        }
    except Exception:
        return {}


# ---------------------------------------------------------------------------
# Static input-format structure analysis for the non-TIFF targets:
# binutils (ELF), giflib (GIF), libxml2 (XML), freetype (sfnt/TTF/OTF/TTC
# and WOFF).  Same role as _static_ifd_region: when the dynamic fork-point
# context produced no structural region, parse the plain on-disk structure
# and hand the field positions to the Step 6c/6d static fallback sweep.
# ---------------------------------------------------------------------------

# Cap on structural field positions per format: every position is swept
# with all 255 values in Step 6c, so unbounded structures (a
# 256-entry colour table, a 1000-section ELF) must not explode the run
# count.  Fields are sorted by offset, so the header/marker positions —
# the semantically critical ones — are kept first.
_STATIC_FIELD_CAP = 100

# Directed probe bytes per field kind — the non-TIFF counterpart of
# _ifd_field_probe_values (meaning-bearing bytes, not the 255 sweep).
_FORMAT_PROBE_KINDS = {
    'magic':  [0x00, 0x01, 0x02, 0x03, 0x7f],
    'index':  [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x40, 0x80, 0xff],
    'enum':   [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
               0x0b, 0x0e, 0x11, 0x64, 0x65, 0x66, 0x67, 0x68, 0x6b,
               0x71, 0x80, 0x81, 0xff],
    'offset': [0x00, 0x01, 0x02, 0x3f, 0x40, 0x7f, 0x80, 0xff],
    'size':   [0x00, 0x01, 0x02, 0x7f, 0x80, 0xff],
    'count':  [0x00, 0x01, 0x02, 0x03, 0x08, 0x7f, 0x80, 0xff],
    'tag':    [0x00, 0x01, 0x20, 0x41, 0x61, 0x63, 0x66, 0x67, 0x68,
               0x6c, 0x6d, 0x70, 0xfe, 0xff],
    'markup': [0x00, 0x20, 0x21, 0x22, 0x23, 0x27, 0x2d, 0x2f, 0x3c,
               0x3d, 0x3e, 0x3f, 0xff],
    'name':   [0x00, 0x20, 0x2d, 0x2e, 0x2f, 0x3a, 0x5f, 0x61, 0xff],
    'attr':   [0x00, 0x22, 0x27, 0x26, 0x2f, 0x3c, 0x3e, 0xff],
    'desc':   [0x00, 0x01, 0x40, 0x7f, 0x80, 0xff],
}
_FORMAT_PROBE_DEFAULT = [0x00, 0x01, 0x7f, 0x80, 0xff]


def _pack_static_region(fmt, label, region_offset, count, entry_size,
                        entries_base, fields):
    """Build the region dict shared by all static format parsers.

    Same keys the Step 5.1/6a flow already consumes (field_offsets,
    entry_size, entries_base, count) plus ``format``/``label``/``fields``
    for the non-TIFF probes and prints.  Returns None when nothing usable
    was parsed.
    """
    seen = set()
    positions = []
    for f in sorted(fields, key=lambda x: x['offset']):
        if f['offset'] in seen:
            continue
        seen.add(f['offset'])
        positions.append(f['offset'])
    if not positions:
        return None
    return {
        'format': fmt,
        'label': label,
        'region_offset': region_offset,
        'count': count,
        'entry_size': entry_size,
        'entries_base': entries_base,
        'field_offsets': positions[:_STATIC_FIELD_CAP],
        'fields': fields,
        'source': 'static',
    }


def _static_elf_region(data):
    """ELF header + section-header field positions (32/64-bit, LE/BE).

    The fields readelf/objdump do their bound checks on: e_type/e_machine,
    e_phoff/e_shoff, e_phnum/e_shnum/e_shstrndx, and per section
    sh_name/sh_type/sh_offset/sh_size.
    """
    if len(data) < 52 or data[:4] != b'\x7fELF':
        return None
    cls, enc = data[4], data[5]
    if cls not in (1, 2) or enc not in (1, 2):
        return None
    e = '<' if enc == 1 else '>'
    is64 = cls == 2

    def u16(o):
        return struct.unpack_from(e + 'H', data, o)[0] \
            if o + 2 <= len(data) else 0

    def u32(o):
        return struct.unpack_from(e + 'I', data, o)[0] \
            if o + 4 <= len(data) else 0

    def u64(o):
        return struct.unpack_from(e + 'Q', data, o)[0] \
            if o + 8 <= len(data) else 0

    fields = []

    def add(off, size, kind, name):
        if 0 <= off and off + size <= len(data):
            fields.append({'offset': off, 'size': size, 'kind': kind,
                           'name': name})

    add(4, 1, 'magic', 'EI_CLASS')
    add(5, 1, 'magic', 'EI_DATA')
    add(0x10, 2, 'enum', 'e_type')
    add(0x12, 2, 'enum', 'e_machine')
    if is64:
        add(0x20, 8, 'offset', 'e_phoff')
        add(0x28, 8, 'offset', 'e_shoff')
        add(0x36, 2, 'count', 'e_phentsize')
        add(0x38, 2, 'count', 'e_phnum')
        add(0x3a, 2, 'count', 'e_shentsize')
        add(0x3c, 2, 'count', 'e_shnum')
        add(0x3e, 2, 'index', 'e_shstrndx')
        shoff, shentsize, shnum = u64(0x28), u16(0x3a), u16(0x3c)
        min_shdr, sz_w = 64, 8
        rel = {'name': 0, 'type': 4, 'offset': 24, 'size': 32}
    else:
        add(0x1c, 4, 'offset', 'e_phoff')
        add(0x20, 4, 'offset', 'e_shoff')
        add(0x2a, 2, 'count', 'e_phentsize')
        add(0x2c, 2, 'count', 'e_phnum')
        add(0x2e, 2, 'count', 'e_shentsize')
        add(0x30, 2, 'count', 'e_shnum')
        add(0x32, 2, 'index', 'e_shstrndx')
        shoff, shentsize, shnum = u32(0x20), u16(0x2e), u16(0x30)
        min_shdr, sz_w = 40, 4
        rel = {'name': 0, 'type': 4, 'offset': 16, 'size': 20}
    if shoff and shentsize >= min_shdr and shoff < len(data):
        n = min(shnum, (len(data) - shoff) // shentsize)
        n = min(n, max(0, (_STATIC_FIELD_CAP - len(fields)) // 4))
        for i in range(n):
            base = shoff + i * shentsize
            add(base + rel['name'], 4, 'index', f'shdr[{i}].sh_name')
            add(base + rel['type'], 4, 'enum', f'shdr[{i}].sh_type')
            add(base + rel['offset'], sz_w, 'offset', f'shdr[{i}].sh_offset')
            add(base + rel['size'], sz_w, 'size', f'shdr[{i}].sh_size')
    return _pack_static_region(
        'elf', f'ELF{64 if is64 else 32}-bit header/section headers',
        shoff, shnum, shentsize, shoff, fields)


def _static_gif_region(data):
    """GIF87a/89a: logical screen descriptor, colour tables, image blocks.

    Field positions of the LSD (width/height/packed/bg), the first colour
    table entries, and every image descriptor (separator/left/top/width/
    height/packed/LZW-min) up to a bounded block count.
    """
    if len(data) < 13 or data[:6] not in (b'GIF87a', b'GIF89a'):
        return None
    fields = []

    def add(off, size, kind, name):
        if 0 <= off and off + size <= len(data):
            fields.append({'offset': off, 'size': size, 'kind': kind,
                           'name': name})

    add(0, 6, 'magic', 'signature')
    add(6, 2, 'size', 'screen_width')
    add(8, 2, 'size', 'screen_height')
    packed = data[10]
    add(10, 1, 'desc', 'packed')
    add(11, 1, 'index', 'bg_color')
    pos = 13
    if packed & 0x80:
        gct_len = 3 * (2 ** ((packed & 7) + 1))
        for i in range(min(8, gct_len // 3)):
            add(13 + i * 3, 3, 'desc', f'gct[{i}]')
        pos = 13 + gct_len
    images = 0
    while 0 <= pos < len(data) and len(fields) < _STATIC_FIELD_CAP:
        b = data[pos]
        if b == 0x3b:                      # trailer
            add(pos, 1, 'desc', 'trailer')
            break
        if b == 0x21:                      # extension
            add(pos, 2, 'desc', 'extension')
            pos += 2
            while pos < len(data):
                sz = data[pos]
                if sz == 0:
                    pos += 1
                    break
                pos += 1 + sz
            continue
        if b == 0x2c:                      # image descriptor
            add(pos, 1, 'desc', 'image_separator')
            add(pos + 1, 2, 'size', 'image_left')
            add(pos + 3, 2, 'size', 'image_top')
            add(pos + 5, 2, 'size', 'image_width')
            add(pos + 7, 2, 'size', 'image_height')
            add(pos + 9, 1, 'desc', 'image_packed')
            lct = 0
            if pos + 10 <= len(data) and data[pos + 9] & 0x80:
                lct = 3 * (2 ** ((data[pos + 9] & 7) + 1))
            add(pos + 10 + lct, 1, 'count', 'lzw_min_code')
            pos = pos + 11 + lct
            while pos < len(data):
                sz = data[pos]
                if sz == 0:
                    pos += 1
                    break
                pos += 1 + sz
            images += 1
            if images >= 16:
                break
            continue
        break                             # not a block start (corrupt data)
    return _pack_static_region('gif', 'GIF screen/image descriptors',
                               6, images, None, 6, fields)


def _static_xml_region(data):
    """XML markup positions (element/attribute/entity bytes).

    Tolerant linear scan instead of a validating parser: crash PoCs are
    deliberately malformed, so a real parser would reject them.  Records the
    '<' of each construct, element/attribute name starts, attribute value
    starts — the structural bytes of the file.
    """
    if not data:
        return None
    head = data[:512].lstrip(b'\xef\xbb\xbf \t\r\n')
    if not head.startswith(b'<'):
        return None
    fields = []
    seen = set()

    def add(off, kind, name):
        if off in seen or not (0 <= off < len(data)):
            return
        seen.add(off)
        fields.append({'offset': off, 'size': 1, 'kind': kind, 'name': name})

    n = len(data)
    i = 0
    while i < n and len(fields) < _STATIC_FIELD_CAP:
        lt = data.find(b'<', i)
        if lt < 0:
            break
        if data.startswith(b'<!--', lt):
            add(lt, 'markup', 'comment')
            end = data.find(b'-->', lt)
            i = end + 3 if end >= 0 else n
        elif data.startswith(b'<![CDATA[', lt):
            add(lt, 'markup', 'cdata')
            end = data.find(b']]', lt)
            i = end + 2 if end >= 0 else n
        elif data.startswith(b'<?', lt):
            add(lt, 'markup', 'pi')
            end = data.find(b'?>', lt)
            i = end + 2 if end >= 0 else n
        elif data.startswith(b'<!', lt):
            add(lt, 'markup', 'decl')
            # DOCTYPE may carry an internal subset '[ ... ]' whose nested
            # <!ENTITY/<!ELEMENT decls are structure too — continue scanning
            # right after the '[' instead of after the first '>'.
            if data[lt:lt + 9].upper() == b'<!DOCTYPE':
                lb = data.find(b'[', lt)
                gt = data.find(b'>', lt)
                if lb != -1 and (gt == -1 or lb < gt):
                    i = lb + 1
                else:
                    i = gt + 1 if gt >= 0 else n
            else:
                # Quote-aware '>' scan: ENTITY values may contain '>'.
                # Resync at an unquoted '<' (the decl ended abnormally) or
                # after the '<!' (no '>' at all) instead of aborting the
                # whole scan at end of file.
                end = -1
                resync = lt + 2
                j = lt + 1
                while j < n:
                    c = data[j]
                    if c in (0x22, 0x27):
                        q = c
                        j += 1
                        while j < n and data[j] != q:
                            j += 1
                    elif c == 0x3e:
                        end = j
                        break
                    elif c == 0x3c:
                        resync = j
                        break
                    j += 1
                i = end + 1 if end >= 0 else resync
        else:
            add(lt, 'markup', 'open')
            k = lt + 1
            if k < n and data[k] == 0x2f:   # '/'
                k += 1
            name_start = k
            while k < n and data[k] not in b' \t\r\n/>':
                k += 1
            if k > name_start:
                add(name_start, 'name', 'element')
            end = lt + 1
            while end < n and data[end] != 0x3e:   # '>'
                if data[end] in (0x22, 0x27):      # '"' "'"
                    quote = data[end]
                    end += 1
                    while end < n and data[end] != quote:
                        end += 1
                end += 1
            if end < n:
                add(end, 'markup', 'close')
            i = end + 1 if end < n else n
    for m in re.finditer(
            rb'([A-Za-z_][\w.:-]*)\s*=\s*(?:"([^"]*)"|\'([^\']*)\')', data):
        if len(fields) >= _STATIC_FIELD_CAP:
            break
        add(m.start(1), 'name', 'attribute')
        if m.group(2):
            add(m.start(2), 'attr', 'value')
        elif m.group(3):
            add(m.start(3), 'attr', 'value')
    return _pack_static_region('xml', 'XML element/attribute marks',
                               None, None, None, None, fields)


def _static_font_region(data):
    """sfnt (TTF/OTF/TTC) and WOFF table-directory field positions.

    Offset table (numTables), then per table tag/offset/length — the fields
    freetype's file-format loaders do their range checks on.
    """
    if len(data) < 12:
        return None
    sig = data[:4]
    fields = []

    def add(off, size, kind, name):
        if 0 <= off and off + size <= len(data):
            fields.append({'offset': off, 'size': size, 'kind': kind,
                           'name': name})

    def u16be(o):
        return struct.unpack_from('>H', data, o)[0] \
            if o + 2 <= len(data) else 0

    def u32be(o):
        return struct.unpack_from('>I', data, o)[0] \
            if o + 4 <= len(data) else 0

    if sig in (b'\x00\x01\x00\x00', b'OTTO', b'true', b'typ1'):
        base, fmt_name = 0, 'sfnt'
    elif sig == b'ttcf':
        num_fonts = u32be(8)
        if num_fonts < 1:
            return None
        base, fmt_name = u32be(12), 'ttc'
        add(8, 4, 'count', 'numFonts')
        add(12, 4, 'offset', 'font[0]')
    elif sig == b'wOFF':
        add(4, 4, 'magic', 'flavor')
        add(8, 4, 'size', 'length')
        add(12, 2, 'count', 'numTables')
        num = u16be(12)
        for i in range(min(num, 32)):
            rec = 44 + i * 20
            add(rec, 4, 'tag', 'table.tag')
            add(rec + 4, 4, 'offset', 'table.offset')
            add(rec + 8, 4, 'size', 'compLength')
            add(rec + 12, 4, 'size', 'origLength')
        return _pack_static_region('woff', 'WOFF table directory',
                                   44, num, 20, 44, fields)
    else:
        return None
    if base == 0:
        add(0, 4, 'magic', 'sfnt_version')
    num = u16be(base + 4)
    add(base + 4, 2, 'count', 'numTables')
    add(base + 6, 2, 'count', 'searchRange')
    add(base + 10, 2, 'count', 'rangeShift')
    for i in range(min(num, 32)):
        rec = base + 12 + i * 16
        add(rec, 4, 'tag', 'table.tag')
        add(rec + 8, 4, 'offset', 'table.offset')
        add(rec + 12, 4, 'size', 'table.length')
    return _pack_static_region(fmt_name, f'{fmt_name} table directory',
                               base + 12, num, 16, base + 12, fields)


def _static_j2k_region(data):
    """JPEG2000 codestream marker fields.

    Lenient scan for marker-like patterns (``FF xx``, xx in 01..FE, not
    preceded by another FF — ``FF FF`` is stuffing): fuzzed J2K files are
    full of junk between markers, so a strict size-driven walk breaks.
    Records each marker's two ID bytes as structural fields.  The marker
    family is the natural unit for the multi-offset combination stage:
    guards like "only one COD per tile" are flipped by rewriting several
    equal marker bytes at once, so the region is flagged ``combo_only`` —
    the full 255-value single-byte sweep (Step 6c) and pairwise (6d) are
    skipped for it.
    """
    if len(data) < 4 or data[:2] != b'\xff\x4f':
        return None
    fields = []
    i = 2
    n = len(data)
    while i + 1 < n:
        if data[i] != 0xFF or data[i + 1] in (0x00, 0xFF):
            i += 1
            continue
        fields.append({'offset': i, 'size': 1, 'kind': 'marker',
                       'name': 'marker_id_hi'})
        fields.append({'offset': i + 1, 'size': 1, 'kind': 'marker',
                       'name': 'marker_id_lo'})
        i += 2
    region = _pack_static_region('j2k', 'J2K codestream marker IDs',
                                 0, len(fields), 1, 0, fields)
    if region:
        region['combo_only'] = True
    return region


def static_structure_region(input_file):
    """Static structure analysis for the non-TIFF input formats.

    Detects the format by magic (ELF, GIF, XML, sfnt/TTC/WOFF, J2K) and
    returns the structural field positions of the on-disk file — same
    contract as _static_ifd_region plus format/label/fields — or None when
    the format has no parser here (then only the format-agnostic value
    search applies).
    """
    try:
        with open(input_file, 'rb') as f:
            data = f.read()
    except Exception:
        return None
    for parser in (_static_elf_region, _static_gif_region,
                   _static_xml_region, _static_font_region,
                   _static_j2k_region):
        try:
            region = parser(data)
        except Exception:
            region = None
        if region:
            return region
    return None


def _structure_probe_values(region, offset):
    """Directed probe values for one structural field offset.

    TIFF keeps the original IFD semantics (_ifd_field_probe_values); the
    other formats look up the field kind recorded by their static parser.
    """
    if not region:
        return None
    if (region.get('format') or 'tiff') == 'tiff':
        if not region.get('entry_size'):
            return None
        return _ifd_field_probe_values(offset, region['entry_size'],
                                       region.get('entries_base'))
    for f in region.get('fields') or []:
        if f.get('offset') == offset:
            return _FORMAT_PROBE_KINDS.get(f.get('kind'),
                                           _FORMAT_PROBE_DEFAULT)
    return _FORMAT_PROBE_DEFAULT


def _replace_input_arg(arg, tmp_path, input_file):
    """Map a program argument to the mutated temp file.

    The arg may reference the input via ``{input_file}``/``{input}``
    placeholders, the exact input path, a relative spelling of it, or the
    path embedded inside a larger token (e.g. sqlite3 ``.read /path``) —
    all must be rewritten or the mutation silently runs the ORIGINAL file.
    """
    if '{' in arg:
        return arg.replace('{input_file}', tmp_path).replace('{input}', tmp_path)
    if arg == input_file or os.path.abspath(arg) == os.path.abspath(input_file):
        return tmp_path
    if input_file:
        if input_file in arg:
            return arg.replace(input_file, tmp_path)
        absv = os.path.abspath(input_file)
        if absv in arg:
            return arg.replace(absv, tmp_path)
    return arg


def _fork_condition_expr(stmt_text):
    """Turn a recorded fork statement into a GDB-evaluable boolean condition.

    ``if (nrows == (uint32) -1)`` -> ``((nrows == (uint32) -1))``.
    Falls back to None when no condition can be extracted.
    """
    s = (stmt_text or '').strip()
    m = re.match(r'^\s*if\s*\((.*)\)\s*$', s, re.S)
    if m:
        cond = m.group(1).strip()
        if cond:
            return f'(({cond}))'
    return None


def _mutation_out_dir(input_file, version, out_root=None):
    """Directory for successfully mutated inputs: ``out/<name>-<version>/``.

    One folder per input file (CVE) + target version, e.g.
    ``out/CVE-2022-3627-4-0-8/`` for ``in/CVE-2022-3627`` against tiff-4.0.8.
    The directory is created lazily by ``_save_mutation_artifact`` (only when
    a mutation actually succeeds).
    """
    base = os.path.basename(input_file) if input_file else 'unknown'
    ver = 'target'
    if version:
        m = re.search(r'(\d+\.\d+(?:\.\d+)*[A-Za-z]*)', str(version))
        if m:
            ver = m.group(1).replace('.', '-')
    root = out_root or os.path.join(
        os.path.dirname(os.path.abspath(__file__)), 'out')
    return os.path.join(root, f'{base}-{ver}')


def _save_mutation_artifact(out_dir, name, original_data, changes):
    """Persist a successfully mutated input file; returns its path or None.

    ``changes`` = [(offset, new_byte), ...] applied to ``original_data``.
    ``name`` is used verbatim (e.g. ``0xe8:-0x00:time:1``); ':' and '-' are
    legal in POSIX file names and keep offset/value/time readable.
    """
    if not out_dir or not changes:
        return None
    data = bytearray(original_data)
    for off, val in changes:
        if 0 <= off < len(data):
            data[off] = val
    path = os.path.join(out_dir, name)
    try:
        os.makedirs(out_dir, exist_ok=True)
        with open(path, 'wb') as f:
            f.write(bytes(data))
    except Exception:
        return None
    return path


def _reset_mutation_out_dir(input_file, version, out_root=None):
    """Clear previous mutation artifacts for this input + target version.

    Every run keeps only its own results: the ``out/<name>-<version>/`` folder
    for the same CVE + target version is removed before new mutations are
    archived (called once per analysis run, before any mutation stage).
    Returns the (now empty / non-existent) folder path.
    """
    path = _mutation_out_dir(input_file, version, out_root=out_root)
    try:
        if os.path.isdir(path):
            shutil.rmtree(path)
    except Exception:
        pass
    return path


def run_byte_mutation_stage(binary, binary_ref, input_file, program_args,
                            offsets, timeout, title='Byte mutation crash testing',
                            version=None):
    """Run the exhaustive 255-value mutation sweep for the given input
    offsets and print the match summary.

    Every offset is mutated with ALL 255 byte values (except the original)
    — no probe screening: the fork-variable offsets are already the precise
    positions of interest, so each one gets the full sweep.

    Returns ``(crash_results, any_match)``.
    """
    if not offsets or not input_file or not os.path.isfile(input_file) \
            or not binary:
        return {}, False
    offsets = sorted(set(offsets))
    print(f'\n{"="*60}')
    print(f'  {title}')
    print(f'{"="*60}')
    print(f'  Input file: {input_file}')
    print(f'  Target binary: {resolve_binary(binary)}')
    print(f'  Reference binary: {resolve_binary(binary_ref)}')
    print(f'  Offsets to test: {", ".join(f"0x{o:x}" for o in offsets)}')

    crash_results = test_byte_mutations_compare(
        binary, binary_ref, input_file, program_args,
        offsets, timeout=timeout, version=version)

    any_match = False
    for offset, info in sorted((k, v) for k, v in crash_results.items()
                               if isinstance(k, int)):
        if info.get('matches'):
            if not any_match:
                print(f'\n  {"="*60}')
                print(f'  MATCH SUMMARY (target reproduces '
                      f'reference crash)')
                print(f'  {"="*60}')
                any_match = True
            print(f'\n  Offset 0x{offset:x} '
                  f'(original=0x{info["original"]:02x}):')
            for byte_val, m in sorted(info['matches'].items()):
                print(f'    0x{byte_val:02x} -> {m}')
    if not any_match:
        print(f'\n  No byte value reproduces the reference crash')
    return crash_results, any_match


def test_value_level_mutations(binary_target, binary_ref, input_file,
                               program_args, var_origins, fork_spec,
                               fork_cond, timeout=60, fork_variables=None,
                               version=None):
    """Value-level mutation of fork-variable origin offsets (generic).

    The single-byte sweep proves which *byte* steers the crash; this tests
    the whole *value* at the variable's origin (e.g. the 4-byte RowsPerStrip
    value at 0x76): for a set of replacement values it re-runs the target
    under GDB, evaluates the fork guard's outcome AND the fork variables'
    values AT the fork statement, and records:

      * outcome flips — the guard evaluates differently than baseline;
      * variable value changes — the fork variables read different values
        (the guard may be normalized upstream, e.g. rowsperstrip==-1 is
        substituted with imagelength before the guard is reached);
      * crash reproduction — the reference ASan crash signature appears.

    ``var_origins`` = {var: [{'offset','width','method'}, ...]} (the output
    of map_fork_variables_to_offsets).  Returns
    ``{offset: {'width', 'original', 'baseline_outcome', 'baseline_vals',
    'trials': {value: {'outcome', 'outcome_flip', 'val_changed',
    'crash'}}}}``.

    Values that reproduce the reference crash are archived under
    ``out/<input-name>-<target-version>/`` named
    ``<offset>:-<value>:time:<seconds>``.
    """
    _set_active_cve(input_file)
    real_target = resolve_binary(binary_target)
    real_ref = resolve_binary(binary_ref)
    cond = _fork_condition_expr(fork_cond)
    if not cond or not real_target or not real_ref:
        return {}
    fork_variables = list(fork_variables or [])

    with open(input_file, 'rb') as f:
        original_data = bytearray(f.read())

    out_dir = _mutation_out_dir(input_file, version)

    def _archive(off, width, v, t_mut):
        """Save a crash-reproducing value mutation to the out folder."""
        _changes = []
        for i in range(width):
            _changes.append((off + i, (int(v) >> (8 * i)) & 0xff))
        _saved = _save_mutation_artifact(
            out_dir, f'0x{off:x}:-0x{int(v):x}:time:{int(round(t_mut))}',
            original_data, _changes)
        if _saved:
            print(f'      saved: {_saved}')

    def _run_outcome(binary, data):
        fd, tmp_path = tempfile.mkstemp(suffix='.tif', prefix='valmut_')
        os.close(fd)
        try:
            with open(tmp_path, 'wb') as f:
                f.write(data)
            cmd_args = [_replace_input_arg(a, tmp_path, input_file)
                        for a in program_args]
            var_code = ('\n'.join(
                f'i = {i}\n'
                f'try:\n'
                f'    v = gdb.parse_and_eval("{v}")\n'
                f'    print("FORK_VAL %d %s" % (i, str(v)))\n'
                f'except Exception:\n'
                f'    pass'
                for i, v in enumerate(fork_variables))) + '\n'
            script = (
                'set pagination off\n'
                'set confirm off\n'
                'set breakpoint pending on\n'
                f'break {fork_spec}\n'
                'commands\n'
                '  silent\n'
                '  python\n'
                'import gdb\n'
                'try:\n'
                f'    print("FORK_OUTCOME %d" % (1 if gdb.parse_and_eval('
                f'"{cond}") else 0))\n'
                'except Exception as e:\n'
                '    print("FORK_OUTCOME_ERR %s" % e)\n'
                + var_code +
                'end\n'
                '  continue\n'
                'end\n'
                f'run {" ".join(str(c) for c in cmd_args)}\n')
            fd2, script_file = tempfile.mkstemp(suffix='.gdb')
            os.close(fd2)
            with open(script_file, 'w') as f:
                f.write(script)
            try:
                env = _mutation_env(binary)
                proc = subprocess.run(
                    ['gdb', '-batch', '-nx', '-q', '-x', script_file,
                     '--', binary],
                    capture_output=True, text=True, errors="replace", timeout=timeout, env=env)
                out = proc.stdout + proc.stderr
                rc = proc.returncode
            finally:
                try:
                    os.unlink(script_file)
                except Exception:
                    pass
            outcome = None
            vals = {}
            for ln in out.splitlines():
                m = re.match(r'FORK_OUTCOME (\d+)', ln.strip())
                if m:
                    outcome = bool(int(m.group(1)))
                    continue
                m = re.match(r'FORK_VAL (\d+) (.+)', ln.strip())
                if m:
                    vals[int(m.group(1))] = m.group(2)
            sig = extract_crash_signature(out)
            return outcome, vals, sig, rc
        finally:
            try:
                os.unlink(tmp_path)
            except Exception:
                pass

    base_out, base_vals, _, _ = _run_outcome(real_target, original_data)
    ref_out, ref_vals, ref_sig, _ = _run_outcome(real_ref, original_data)
    _attach_crash_statement(ref_sig, real_ref)

    # Candidate replacement values: corner values, value-range flips, and
    # the values that matter for size guards (-1 / 0 / 1 / huge).
    trial_values = [0, 1, 2, 0x100, 0x7ff, 0x800, 0x801, 0xfff, 0x1000,
                    0x7fff, 0xffff, 0x10000, 0x7fffffff, 0x80000000,
                    0xfffffffe, 0xffffffff]

    results = {}
    for var, hits in var_origins.items():
        for hit in hits:
            off = hit['offset']
            width = hit['width']
            if not width or width not in (2, 4, 8):
                continue
            if off + width > len(original_data):
                continue
            key = off
            if key in results:
                continue
            orig_val = int.from_bytes(
                original_data[off:off + width], 'little')
            trials = {}
            for v in trial_values:
                if v == orig_val:
                    continue
                data = bytearray(original_data)
                data[off:off + width] = int(v).to_bytes(width, 'little')
                _t_trial = time.time()
                outcome, vals, sig, _ = _run_outcome(real_target, data)
                _t_mut = time.time() - _t_trial
                verdict = None
                if sig is not None and ref_sig is not None:
                    _attach_crash_statement(sig, real_target)
                    verdict, _ = compare_crash_signatures(ref_sig, sig)
                if verdict in ('same_func', 'same_site'):
                    _archive(off, width, v, _t_mut)
                val_changed = bool(
                    vals and base_vals
                    and any(vals.get(i) != base_vals.get(i)
                            for i in set(vals) | set(base_vals)))
                trials[v] = {
                    'outcome': outcome,
                    'outcome_flip': (outcome is not None
                                     and base_out is not None
                                     and outcome != base_out),
                    'val_changed': val_changed,
                    'crash': verdict,
                }
            results[key] = {
                'width': width,
                'original': orig_val,
                'baseline_outcome': base_out,
                'baseline_vals': base_vals,
                'ref_outcome': ref_out,
                'ref_vals': ref_vals,
                'var': var,
                'trials': trials,
            }
    return results
    if '{' in arg:
        return arg.replace('{input_file}', tmp_path).replace('{input}', tmp_path)
    if arg == input_file or os.path.abspath(arg) == os.path.abspath(input_file):
        return tmp_path
    return arg


def _run_mutation_worker(task):
    """Run one byte-mutation through ``binary`` in a subprocess (worker for the
    parallel mutation sweep).  ``task`` = (binary, data, program_args,
    input_file, timeout).

    Returns ``(stdout+stderr, returncode, elapsed_seconds)`` where the
    elapsed time is THIS mutation's own execution time (temp-file write +
    subprocess run) — not the pool queue wait, which would otherwise inflate
    the reported time for tasks queued behind other workers.
    """
    binary, data, program_args, input_file, timeout = task
    _ext = os.path.splitext(input_file)[1] if input_file else '.bin'
    fd, tmp_path = tempfile.mkstemp(suffix=_ext, prefix='mutate_')
    os.close(fd)
    _t0 = time.time()
    try:
        with open(tmp_path, 'wb') as f:
            f.write(data)
        cmd = [binary] + [_replace_input_arg(a, tmp_path, input_file)
                          for a in program_args]
        env = _mutation_env(binary)
        proc = subprocess.run(cmd, capture_output=True, text=True, errors="replace",
                              timeout=timeout, env=env)
        return proc.stdout + proc.stderr, proc.returncode, time.time() - _t0
    except subprocess.TimeoutExpired:
        return '', -1, time.time() - _t0
    except Exception:
        return '', -2, time.time() - _t0
    finally:
        try:
            os.unlink(tmp_path)
        except Exception:
            pass


def _target_defines_function(func, ref_crash, source_dirs):
    """Return True when ``func`` is defined in the target source tree.

    A same-named definition means no cross-version rename mapping is needed.
    Checking this first prevents a same-named function from being replaced by
    an unrelated function that merely has a similar source body.
    """
    try:
        import divergence_analyzer as da
    except Exception:
        return False

    file_hint = (ref_crash or {}).get('file')
    if file_hint:
        try:
            if da._find_function_body_range(file_hint, func, source_dirs):
                return True
        except Exception:
            pass

    # Fallback when no usable file hint exists: scan the target sources.
    for d in (source_dirs or []):
        try:
            paths = list(Path(d).rglob('*.c')) + list(Path(d).rglob('*.cpp'))
        except Exception:
            continue
        for p in paths:
            try:
                if da._find_function_body_range(str(p), func,
                                                [str(p.parent)]):
                    return True
            except Exception:
                continue
    return False


def _map_ref_crash_function(binary_target, binary_ref, ref_crash):
    """Map the reference's crash function to its target-side equivalent.

    When the two versions rewrote the code (e.g. audiofile's C++ -> C
    rewrite: ``WAVEFile::readInit`` -> ``_af_wave_read_init``), the same
    vulnerability crashes in differently-named functions.  ``same_func``
    comparison would never match, so the reference crash function is mapped
    to the target function whose source body most closely resembles it.

    Returns the target-side function name, or None when no mapping exists.
    """
    func = (ref_crash or {}).get('function')
    if not func:
        return None
    try:
        import divergence_analyzer as da
        ref_dirs = da.find_source_dirs(str(binary_ref))
        tgt_dirs = da.find_source_dirs(str(binary_target))
        if _target_defines_function(func, ref_crash, tgt_dirs):
            return None
        mapped = da._map_function_to_target(func, ref_dirs, tgt_dirs)
        if mapped and mapped[0] and mapped[0] != func:
            return mapped[0]
    except Exception:
        pass
    return None


# Time-to-success is measured from the FIRST mutation attempt of the process
# (across all mutation stages), not from the start of each individual run.
_MUTATION_T0 = None


def _mutation_clock_start():
    global _MUTATION_T0
    if _MUTATION_T0 is None:
        _MUTATION_T0 = time.time()


def _mutation_elapsed():
    return (time.time() - _MUTATION_T0) if _MUTATION_T0 else 0.0


def test_byte_mutations_compare(binary_target, binary_ref, input_file,
                                program_args, offsets, timeout=10,
                                probe_values=None, version=None):
    """Mutate each byte at each offset and check whether the *target* binary
    (e.g. 4.0.8) reproduces the *reference* binary's (4.4.0) crash type.

    For every byte value at every offset:
      1. write the mutated file,
      2. run it through the target binary,
      3. extract its ASan crash signature,
      4. record it only if it matches the reference's crash signature.

    A value that makes the target crash *the same way* the reference does is
    evidence that this byte steers the divergence.  A mere exit-code change
    (e.g. the target's TIFFOpen returning NULL) is NOT counted as a match.

    Every successful mutation is also archived as a standalone input file
    under ``out/<input-name>-<target-version>/`` named
    ``<offset>:-<new-value>:time:<seconds>`` (per-offset mutation time,
    rounded to whole seconds).
    """
    _set_active_cve(input_file)
    real_target = resolve_binary(binary_target)
    real_ref = resolve_binary(binary_ref)
    if not (real_target and real_ref
            and os.path.isfile(real_target) and os.path.isfile(real_ref)):
        print(f'  [!] Binary not found: target={binary_target} ref={binary_ref}')
        return {}

    with open(input_file, 'rb') as f:
        original_data = bytearray(f.read())

    out_dir = _mutation_out_dir(input_file, version)

    def _archive(offset, byte_val, t_success):
        """Save a successful mutation to the out folder and report it.

        The ``time:`` component is the elapsed time from the FIRST mutation
        attempt of the run to this successful one (integer seconds),
        matching the reported time-to-success metric."""
        _saved = _save_mutation_artifact(
            out_dir,
            f'0x{offset:x}:-0x{byte_val:02x}:time:{int(round(t_success))}',
            original_data, [(offset, byte_val)])
        if _saved:
            print(f'      saved: {_saved}')

    def _run(binary, data):
        _ext = os.path.splitext(input_file)[1] if input_file else '.bin'
        fd, tmp_path = tempfile.mkstemp(suffix=_ext, prefix='mutate_')
        os.close(fd)
        try:
            with open(tmp_path, 'wb') as f:
                f.write(data)
            cmd = [binary] + [_replace_input_arg(a, tmp_path, input_file)
                              for a in program_args]
            env = _mutation_env(binary)
            proc = subprocess.run(cmd, capture_output=True, text=True, errors="replace",
                                  timeout=timeout, env=env)
            return proc.stdout + proc.stderr, proc.returncode
        except subprocess.TimeoutExpired:
            return '', -1
        except Exception:
            return '', -2
        finally:
            try:
                os.unlink(tmp_path)
            except Exception:
                pass

    # Reference crash signature (original file through the reference binary).
    ref_out, ref_rc = _run(real_ref, original_data)
    ref_sig = extract_crash_signature(ref_out)
    if ref_sig is None:
        print(f'  [!] Reference binary did not produce an ASan crash '
              f'(rc={ref_rc}); cannot compare.')
        return {}
    _attach_crash_statement(ref_sig, real_ref)
    ref_crash = ref_sig["crash_frames"][0] if ref_sig["crash_frames"] else {}
    print(f'  Reference crash: {ref_sig["type"]} in '
          f'{ref_crash.get("function")} '
          f'({_path_basename(ref_crash.get("file"))}:'
          f'{ref_crash.get("line")}, rc={ref_rc})')

    # Cross-version rewrite (e.g. audiofile C++ -> C): map the reference's
    # crash function to its target-side equivalent so the same underlying bug
    # counts as a same_func match.
    _mapped_ref_func = _map_ref_crash_function(real_target, real_ref, ref_crash)
    _comp_ref_sig = ref_sig
    if _mapped_ref_func:
        print(f'  [*] Reference crash function mapped to target-side '
              f'{_mapped_ref_func}() for cross-version comparison')
        import copy as _copy
        _comp_ref_sig = _copy.deepcopy(ref_sig)
        _comp_ref_sig['crash_frames'][0]['function'] = _mapped_ref_func

    # Baseline target outcome on the ORIGINAL file.  A mutation with no crash
    # signature is only "unchanged" if its exit code matches the baseline;
    # a different exit code means the mutation FLIPPED the fork outcome
    # (e.g. the target's fatal init error -> normal encoding).  Without this,
    # fork-flipping mutations are indistinguishable from no-op mutations.
    base_tgt_out, base_tgt_rc = _run(real_target, original_data)
    base_tgt_sig = extract_crash_signature(base_tgt_out)
    print(f'  Target baseline (original file): rc={base_tgt_rc}'
          + (f', crash={base_tgt_sig["type"]}'
             if base_tgt_sig else ', no crash (unchanged if rc matches)'))

    results = {
        'ref_signature': {
            'type': ref_sig['type'],
            'crash_frame': {k: ref_crash.get(k)
                            for k in ('function', 'file', 'line')},
            'summary': ref_sig['summary'],
        },
        'baseline_target': {
            'rc': base_tgt_rc,
            'crash': base_tgt_sig['type'] if base_tgt_sig else None,
        },
    }
    observed = {}      # verdict -> count across all mutations
    total_tests = 0
    try:
        n_workers = int(os.environ.get("RETROSCOPE_MUTATION_WORKERS", "2"))
    except ValueError:
        n_workers = 2
    n_workers = max(1, min(n_workers, 8))

    from concurrent.futures import ProcessPoolExecutor, as_completed

    for offset in sorted(offsets):
        if offset >= len(original_data):
            print(f'  [!] Offset 0x{offset:x} beyond file size, skipping')
            continue
        orig_byte = original_data[offset]
        results[offset] = {'original': orig_byte, 'matches': {},
                           'no_crash': [], 'fork_flip': [],
                           'same_type': {}, 'different_type': []}
        print(f'\n  [*] Testing offset 0x{offset:x} (original=0x{orig_byte:02x})...')

        # All 255 byte values are independent subprocess runs: sweep them in
        # parallel (one process pool per offset).  With ``probe_values`` only
        # that subset is tested (a cheap screening pass that filters which
        # offsets deserve the full 255-value sweep).
        tasks = []
        for byte_val in range(256):
            if byte_val == orig_byte:
                continue
            if probe_values is not None and byte_val not in probe_values:
                continue
            modified = bytearray(original_data)
            modified[offset] = byte_val
            tasks.append((byte_val, bytes(modified)))

        if tasks:
            _mutation_clock_start()

        if len(tasks) <= 1:
            for byte_val, data in tasks:
                out, rc, _t_mut = _run_mutation_worker(
                    (real_target, data, program_args, input_file, timeout))
                total_tests += 1
                sig = extract_crash_signature(out)
                _attach_crash_statement(sig, real_target)
                if sig is None:
                    if base_tgt_rc is not None and rc != base_tgt_rc:
                        results[offset]['fork_flip'].append(byte_val)
                    else:
                        results[offset]['no_crash'].append(byte_val)
                    continue
                verdict, diff = compare_crash_signatures(_comp_ref_sig, sig)
                crash = sig["crash_frames"][0] if sig["crash_frames"] else {}
                if verdict in ('same_func', 'same_site'):
                    results[offset]['matches'][byte_val] = {
                        'verdict': verdict,
                        'type': sig['type'],
                        'function': crash.get('function'),
                        'file': _path_basename(crash.get('file')),
                        'line': crash.get('line'),
                        'rc': rc,
                    }
                    _tot = _mutation_elapsed()
                    results[offset]['matches'][byte_val]['time_to_success'] = round(_tot, 3)
                    results[offset]['matches'][byte_val]['time_this_mutation'] = round(_t_mut, 3)
                    try:
                        import stage_timing
                        stage_timing.record(
                            f"mutation succeeded offset=0x{offset:x} byte=0x{byte_val:02x}",
                            _tot)
                    except Exception:
                        pass
                    print(f'    0x{byte_val:02x} -> MATCHES ref crash '
                          f'({verdict}: {diff})  [since first mutation {_tot:.3f}s, '
                          f'this run {_t_mut:.3f}s]')
                    _archive(offset, byte_val, _tot)
                else:
                    observed.setdefault(verdict or 'no_crash', 0)
                    observed[verdict or 'no_crash'] += 1
                    if verdict == 'same_type':
                        _site = (crash.get('function'),
                                 _path_basename(crash.get('file')),
                                 crash.get('line'))
                        key = f"{_site[0]}:{_site[1]}:{_site[2]}"
                        # Near-miss: same ASan type at some other site —
                        # not a match unless the crash POINT (function +
                        # statement) equals the reference's, which
                        # compare_crash_signatures already decided above.
                        observed.setdefault('same_type_sites', {})
                        sites = observed['same_type_sites']
                        sites.setdefault(key, 0)
                        sites[key] += 1
                        results[offset]['same_type'].setdefault(key, [])
                        results[offset]['same_type'][key].append(byte_val)
                    else:
                        results[offset]['different_type'].append(
                            (byte_val, sig['type']))
        else:
            with ProcessPoolExecutor(max_workers=n_workers) as ex:
                futures = {}
                for byte_val, data in tasks:
                    fut = ex.submit(_run_mutation_worker,
                                    (real_target, data, program_args,
                                     input_file, timeout))
                    futures[fut] = byte_val
                for fut in as_completed(futures):
                    byte_val = futures[fut]
                    out, rc, _t_mut = fut.result()
                    total_tests += 1
                    sig = extract_crash_signature(out)
                    _attach_crash_statement(sig, real_target)
                    if sig is None:
                        if base_tgt_rc is not None and rc != base_tgt_rc:
                            results[offset]['fork_flip'].append(byte_val)
                        else:
                            results[offset]['no_crash'].append(byte_val)
                        continue
                    verdict, diff = compare_crash_signatures(_comp_ref_sig, sig)
                    crash = sig["crash_frames"][0] if sig["crash_frames"] else {}
                    # ``same_func`` or better = the target reproduces the
                    # reference crash; ``same_type`` only = a same-kind crash
                    # at another site.
                    if verdict in ('same_func', 'same_site'):
                        results[offset]['matches'][byte_val] = {
                            'verdict': verdict,
                            'type': sig['type'],
                            'function': crash.get('function'),
                            'file': _path_basename(crash.get('file')),
                            'line': crash.get('line'),
                            'rc': rc,
                        }
                        _tot = _mutation_elapsed()
                        results[offset]['matches'][byte_val]['time_to_success'] = round(_tot, 3)
                        results[offset]['matches'][byte_val]['time_this_mutation'] = round(_t_mut, 3)
                        try:
                            import stage_timing
                            stage_timing.record(
                                f"mutation succeeded offset=0x{offset:x} byte=0x{byte_val:02x}",
                                _tot)
                        except Exception:
                            pass
                        print(f'    0x{byte_val:02x} -> MATCHES ref crash '
                              f'({verdict}: {diff})  [since first mutation {_tot:.3f}s, '
                              f'this run {_t_mut:.3f}s]')
                        _archive(offset, byte_val, _tot)
                    else:
                        observed.setdefault(verdict or 'no_crash', 0)
                        observed[verdict or 'no_crash'] += 1
                        if verdict == 'same_type':
                            _site = (crash.get('function'),
                                     _path_basename(crash.get('file')),
                                     crash.get('line'))
                            key = f"{_site[0]}:{_site[1]}:{_site[2]}"
                            # Near-miss: same ASan type at some other site —
                            # not a match unless the crash POINT (function +
                            # statement) equals the reference's, which
                            # compare_crash_signatures already decided above.
                            observed.setdefault('same_type_sites', {})
                            sites = observed['same_type_sites']
                            sites.setdefault(key, 0)
                            sites[key] += 1
                            results[offset]['same_type'].setdefault(key, [])
                            results[offset]['same_type'][key].append(byte_val)
                        else:
                            results[offset]['different_type'].append(
                                (byte_val, sig['type']))

        n = len(results[offset]['matches'])
        verdicts = {}
        for v in results[offset]['matches'].values():
            verdicts[v['verdict']] = verdicts.get(v['verdict'], 0) + 1
        _nc = len(results[offset]['no_crash'])
        _ff = len(results[offset]['fork_flip'])
        _st = sum(len(v) for v in results[offset]['same_type'].values())
        _dt = len(results[offset]['different_type'])
        print(f'    => {n} matching value(s) (target reproduces ref crash) '
              f'{verdicts}; no_crash(unchanged)={_nc}, fork_flip(behavior changed)={_ff}, '
              f'same_type(other crash site)={_st}, different_type={_dt}')
        if _ff:
            print(f'       fork-flipping values (target outcome changed): '
                  f'{[f"0x{v:02x}" for v in results[offset]["fork_flip"][:40]]}')
        if _nc:
            print(f'       unchanged (same as baseline) values: '
                  f'{[f"0x{v:02x}" for v in results[offset]["no_crash"][:40]]}')
        if _st:
            _sites = ', '.join(f'{k}:{len(v)}' for k, v in
                               results[offset]['same_type'].items())
            print(f'       same-type crash sites: {_sites}')

    results['target_crash_summary'] = observed
    print(f'\n  [*] Total mutations tested: {total_tests}')
    if observed:
        near = observed.get('same_type_sites', {})
        other = {k: v for k, v in observed.items() if k != 'same_type_sites'}
        if other:
            print(f'  [*] Target crashed differently {sum(other.values())} '
                  f'time(s): {other}')
        if near:
            print(f'  [*] Same ASan type at OTHER sites: {near}')
    return results


# Pairwise (two-offset) probe values.  A full 255x255 sweep per pair is
# usually prohibitive, so each side is mutated with a small fuzzing-style
# operator set derived from its ORIGINAL byte: integer extremes, +/-1
# arithmetic, and single-bit flips.  The two per-offset sets are then
# combined as a Cartesian product.  This is deliberately not a dictionary
# of fixed "magic" bytes: the candidates depend on the byte actually found
# at that position, which is what makes a two-byte interaction meaningful.
PAIRWISE_LIMITS = (0x00, 0x01, 0x7f, 0x80, 0xfe, 0xff)
PAIRWISE_BIT_FLIPS = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80)

# Backwards-compatible name for callers that still import the old constant.
PAIRWISE_PROBE = PAIRWISE_LIMITS


def _pairwise_probe_cap():
    """Per-offset probe-set size for the two-offset mutation (env-tunable)."""
    try:
        return max(6, min(64,
                          int(os.environ.get('RETROSCOPE_PAIR_PROBE_MAX',
                                             '20'))))
    except ValueError:
        return 20


def _pairwise_probe_values(orig, hints=None, cap=None):
    """Fuzzing-style byte values for ONE side of a two-offset mutation.

    Operators, in priority order (truncated to ``cap``):
      1. integer extremes (0x00, 0x01, 0x7f, 0x80, 0xfe, 0xff);
      2. +/-1 arithmetic on the original byte (mod 256, so 0x00-1 wraps);
      3. every single-bit flip of the original byte;
      4. observed fork-flipping / crash-changing values from the single-byte
         sweep at this same offset (high-signal fuzz hints);
      5. bitwise inversion and +/-2 neighbours when budget remains.

    The same generator is used for both offsets in a pair, and the two sets
    are combined pairwise.  Values never equal the original byte and are
    deduplicated, so ``cap*cap`` is an upper bound on one pair's runs.
    """
    if cap is None:
        cap = _pairwise_probe_cap()
    vals = []

    def _add(v):
        if isinstance(v, int):
            v &= 0xff
            if v != orig and v not in vals:
                vals.append(v)

    for v in PAIRWISE_LIMITS:
        if len(vals) >= cap:
            break
        _add(v)
    for d in (1, -1):
        if len(vals) >= cap:
            break
        _add(orig + d)
    for bit in PAIRWISE_BIT_FLIPS:
        if len(vals) >= cap:
            break
        _add(orig ^ bit)
    for h in (hints or ()):
        if len(vals) >= cap:
            break
        _add(h)
    for v in (orig ^ 0xff, orig + 2, orig - 2):
        if len(vals) >= cap:
            break
        _add(v)
    return vals or [orig]


def _mutation_offset_effects(info):
    """``(matched, changed)`` counters of a single-offset sweep record.

    ``matched`` = single-byte values reproducing the reference crash;
    ``changed`` = values that changed the target's outcome (fork flips,
    same-type crashes, different-type crashes).
    """
    if not isinstance(info, dict):
        return 0, 0
    matched = len(info.get('matches') or ())
    changed = (len(info.get('fork_flip') or ())
               + sum(len(v) for v in (info.get('same_type') or {}).values())
               + len(info.get('different_type') or ()))
    return matched, changed


# Minimum number of behavior-changing single-byte runs for an offset to be
# treated as a pairwise GATE ("active").  Offsets below the threshold (but
# with SOME effect) are "weak" — they still get coverage pairs, they just
# do not multiply into every interaction pair.
_ACTIVE_MIN_EFFECTS = 4


def _classify_sweep_results(*result_maps):
    """Classify offsets across single-byte sweep result dicts.

    Accepts any number of result maps keyed by offset (in-memory
    ``crash_results`` with int keys, and/or a JSON
    ``*_origin_mutation.json`` with digit-string keys).

    Returns ``(active, inert, weak, hints)``:
      * ``active`` — {offset: strength}: matched the reference or changed
        the target's behavior in >= _ACTIVE_MIN_EFFECTS runs.  These are
        the gates a two-offset combination must turn "on";
      * ``inert``  — offsets swept with NO effect at all (uniform
        no-crash): the pool the gates must be combined with — a single-byte
        sweep can never discover what one of these bytes does TOGETHER
        with a gate;
      * ``weak``   — some effect, but below the gate threshold;
      * ``hints``  — {offset: sorted values}: observed fork-flipping /
        crash-changing byte values, used to enrich the probe sets.
    """
    stats = {}   # offset -> [matched, changed, no_crash]
    hints = {}
    for results in result_maps:
        if not isinstance(results, dict):
            continue
        for k, info in results.items():
            if isinstance(k, str):
                if not k.isdigit():
                    continue
                k = int(k)
            if not isinstance(k, int) or not isinstance(info, dict) \
                    or 'no_crash' not in info:
                continue
            matched, changed = _mutation_offset_effects(info)
            st = stats.setdefault(k, [0, 0, 0])
            st[0] += matched
            st[1] += changed
            st[2] += len(info.get('no_crash') or ())
            if matched or changed:
                hv = hints.setdefault(k, [])
                for v in (info.get('fork_flip') or ()):
                    if isinstance(v, int) and v not in hv:
                        hv.append(v)
                for v in (info.get('different_type') or ()):
                    if isinstance(v, int):
                        if v not in hv:
                            hv.append(v)
                    elif isinstance(v, (list, tuple)) and v \
                            and isinstance(v[0], int) and v[0] not in hv:
                        hv.append(v[0])
                for mkey in (info.get('matches') or {}):
                    try:
                        mv = int(str(mkey), 16)
                    except ValueError:
                        continue
                    if mv not in hv:
                        hv.append(mv)
    active, inert, weak = {}, set(), set()
    for o, (matched, changed, no_crash) in stats.items():
        if matched or matched + changed >= _ACTIVE_MIN_EFFECTS:
            active[o] = matched + changed
        elif matched + changed > 0:
            weak.add(o)
        elif no_crash:
            inert.add(o)
    for hv in hints.values():
        hv.sort()
    return active, inert, weak, hints


def _build_interaction_pairs(active, partners, cap=None):
    """Gate x partner pairs for the two-offset mutation.

    ``active`` = {offset: strength} behaviour-changing gates, ``partners``
    = the offsets each gate should be combined with (inert/weak offsets —
    and the other gates, so gate x gate is covered too).

    Partners are visited nearest-to-any-gate first and every partner is
    paired with every gate (strongest first) before moving on, so a total
    cap (``RETROSCOPE_INTERACTION_MAX``, default 200) keeps the local
    combinations and spreads the budget across gates instead of letting
    the strongest gate consume it.
    """
    if not active:
        return []
    if cap is None:
        try:
            cap = max(0, int(os.environ.get('RETROSCOPE_INTERACTION_MAX',
                                            '200')))
        except ValueError:
            cap = 200
    gates = sorted(active, key=lambda o: (-active[o], o))
    pool = set(partners) | set(active)
    partners_ordered = sorted(pool,
                              key=lambda x: (min(abs(x - a) for a in gates),
                                             x))
    pairs, seen = [], set()
    for b in partners_ordered:
        for a in gates:
            if a == b:
                continue
            key = (min(a, b), max(a, b))
            if key in seen:
                continue
            seen.add(key)
            pairs.append(key)
            if cap and len(pairs) >= cap:
                return pairs
    return pairs


def _build_mutation_pairs(offsets, var_spans, max_pairs=60,
                          interaction_pairs=None):
    """Build (offA, offB) pairs for the combined two-offset mutation.

    Three passes, in priority order:

      1) INTERACTION pairs supplied by the caller — a behaviour-changing
         gate combined with an inert offset is exactly the class of
         combination no single-byte sweep can discover;
      2) COVERAGE: every candidate offset participates in at least one
         pair (same fork-variable span first, then the nearest other
         offset).  This pass may push the list past ``max_pairs`` so that
         no candidate is ever silently untested;
      3) the HISTORICAL pairs (within-span multi-byte manipulation,
         neighbouring cross-variable pairs, generic pairs for small offset
         sets), bounded by ``max_pairs`` ADDITIONS — the same budget the
         historical code applied to the whole list.

    ``RETROSCOPE_MAX_PAIR_TOTAL`` (default 400) is a hard ceiling over the
    finished list; it only ever truncates the low-priority tail.
    """
    def _norm(o):
        try:
            return int(o)
        except (TypeError, ValueError):
            return None

    offsets = sorted({o for o in map(_norm, offsets) if o is not None})
    off_set = set(offsets)
    pairs = []
    seen = set()

    def _add(a, b):
        if a == b or a not in off_set or b not in off_set:
            return False
        key = (min(a, b), max(a, b))
        if key in seen:
            return False
        seen.add(key)
        pairs.append(key)
        return True

    # 1) caller-provided interaction pairs (strongest signal first).
    for a, b in (interaction_pairs or ()):
        _add(_norm(a), _norm(b))

    # 2) coverage: every offset in >= one pair.
    span_of = {}
    for offs in (var_spans or {}).values():
        offs = sorted({o for o in map(_norm, offs) if o in off_set}
                      if offs else set())
        for o in offs:
            span_of.setdefault(o, set()).update(offs)
    covered = {x for p in pairs for x in p}
    for o in offsets:
        if o in covered:
            continue
        cand = [x for x in sorted(span_of.get(o, ()))
                if x != o and x not in covered]
        if cand:
            partner = cand[0]
        else:
            others = [x for x in offsets if x != o and x not in covered]
            if not others:
                others = [x for x in offsets if x != o]
            partner = min(others, key=lambda x: (abs(x - o), x)) \
                if others else None
        if partner is not None:
            _add(o, partner)
            covered.update((o, partner))

    # 3) historical passes, bounded by max_pairs ADDITIONS.
    _base = len(pairs)

    # 3a) within-span pairs (each variable's multi-byte value bytes).
    for offs in (var_spans or {}).values():
        offs = sorted({o for o in map(_norm, offs) if o in off_set}
                      if offs else set())
        if len(offs) > 8:
            offs = offs[:8]
        for i in range(len(offs)):
            for j in range(i + 1, len(offs)):
                _add(offs[i], offs[j])
        if len(pairs) - _base >= max_pairs:
            break

    # 3b) neighbouring cross-variable pairs.
    if len(pairs) - _base < max_pairs:
        for i in range(len(offsets)):
            for j in range(i + 1, len(offsets)):
                if offsets[j] - offsets[i] <= 2:
                    _add(offsets[i], offsets[j])
            if len(pairs) - _base >= max_pairs:
                break

    # 3c) generic pairs (only when the total offset set is small).
    if len(pairs) - _base < max_pairs and len(offsets) <= 16:
        for i in range(len(offsets)):
            for j in range(i + 1, len(offsets)):
                _add(offsets[i], offsets[j])
                if len(pairs) - _base >= max_pairs:
                    break
            if len(pairs) - _base >= max_pairs:
                break

    # hard ceiling (env-overridable) — truncates the tail only.
    try:
        _total_cap = max(0, int(os.environ.get('RETROSCOPE_MAX_PAIR_TOTAL',
                                               '400')))
    except ValueError:
        _total_cap = 400
    if _total_cap and len(pairs) > _total_cap:
        pairs = pairs[:_total_cap]
    return pairs


def test_pairwise_mutations_compare(binary_target, binary_ref, input_file,
                                    program_args, pairs, timeout=10,
                                    probe_values=None, version=None,
                                    value_hints=None):
    """Two-offset combined byte mutation.

    For every (offA, offB) pair, mutate BOTH bytes simultaneously (each
    side sweeping its own fuzz-style set derived from that offset's
    original byte — integer extremes, +/-1, single-bit flips, then any
    observed fork-flipping values; ``probe_values`` overrides both sides)
    and check whether the combined mutation makes the target reproduce the
    reference's crash — or produces a new outcome that neither single-byte
    mutation alone achieves.

    Successful combinations are archived under
    ``out/<input-name>-<target-version>/`` named
    ``<offA>+<offB>:-<va>-<vb>:time:<seconds>``.
    """
    _set_active_cve(input_file)
    real_target = resolve_binary(binary_target)
    real_ref = resolve_binary(binary_ref)
    if not (real_target and real_ref
            and os.path.isfile(real_target) and os.path.isfile(real_ref)):
        print(f'  [!] Binary not found: target={binary_target} ref={binary_ref}')
        return {}

    with open(input_file, 'rb') as f:
        original_data = bytearray(f.read())

    out_dir = _mutation_out_dir(input_file, version)

    def _archive(offA, offB, va, vb, t_success):
        """Save a successful two-offset mutation to the out folder.

        The ``time:`` component is the elapsed time from the first mutation
        attempt of the run to this successful one (integer seconds)."""
        _saved = _save_mutation_artifact(
            out_dir,
            f'0x{offA:x}+0x{offB:x}:-0x{va:02x}-0x{vb:02x}:time:{int(round(t_success))}',
            original_data, [(offA, va), (offB, vb)])
        if _saved:
            print(f'      saved: {_saved}')

    ref_out, ref_rc, _ = _run_mutation_worker(
        (real_ref, bytes(original_data), program_args, input_file, timeout))
    ref_sig = extract_crash_signature(ref_out)
    if ref_sig is None:
        print(f'  [!] Reference binary did not produce an ASan crash '
              f'(rc={ref_rc}); cannot compare.')
        return {}
    _attach_crash_statement(ref_sig, real_ref)
    ref_crash = ref_sig["crash_frames"][0] if ref_sig["crash_frames"] else {}
    print(f'  Reference crash: {ref_sig["type"]} in '
          f'{ref_crash.get("function")} '
          f'({_path_basename(ref_crash.get("file"))}:'
          f'{ref_crash.get("line")}, rc={ref_rc})')

    # Cross-version rewrite (e.g. audiofile C++ -> C): map the reference's
    # crash function to its target-side equivalent so the same underlying bug
    # counts as a same_func match.
    _mapped_ref_func = _map_ref_crash_function(real_target, real_ref, ref_crash)
    _comp_ref_sig = ref_sig
    if _mapped_ref_func:
        print(f'  [*] Reference crash function mapped to target-side '
              f'{_mapped_ref_func}() for cross-version comparison')
        import copy as _copy
        _comp_ref_sig = _copy.deepcopy(ref_sig)
        _comp_ref_sig['crash_frames'][0]['function'] = _mapped_ref_func

    # Baseline target outcome on the ORIGINAL file (for fork-flip detection).
    base_tgt_out, base_tgt_rc, _ = _run_mutation_worker(
        (real_target, bytes(original_data), program_args, input_file, timeout))
    base_tgt_sig = extract_crash_signature(base_tgt_out)
    print(f'  Target baseline (original file): rc={base_tgt_rc}'
          + (f', crash={base_tgt_sig["type"]}'
             if base_tgt_sig else ', no crash (unchanged if rc matches)'))

    probe = probe_values  # explicit override; None -> per-offset derivation
    results = {
        'ref_signature': {
            'type': ref_sig['type'],
            'crash_frame': {k: ref_crash.get(k)
                            for k in ('function', 'file', 'line')},
            'summary': ref_sig['summary'],
        },
        'baseline_target': {
            'rc': base_tgt_rc,
            'crash': base_tgt_sig['type'] if base_tgt_sig else None,
        },
    }
    observed = {}
    total_tests = 0
    try:
        n_workers = int(os.environ.get("RETROSCOPE_MUTATION_WORKERS", "2"))
    except ValueError:
        n_workers = 2
    n_workers = max(1, min(n_workers, 8))

    from concurrent.futures import ProcessPoolExecutor, as_completed

    for offA, offB in sorted(pairs):
        if offA >= len(original_data) or offB >= len(original_data):
            print(f'  [!] Pair 0x{offA:x}/0x{offB:x} beyond file size, skipping')
            continue
        oa, ob = original_data[offA], original_data[offB]
        key = f'0x{offA:x}+0x{offB:x}'
        results[key] = {'original': [oa, ob], 'matches': {},
                        'no_crash': [], 'fork_flip': [],
                        'same_type': {}, 'different_type': []}
        print(f'\n  [*] Testing pair {key} '
              f'(original={oa:02x},{ob:02x})...')

        if probe is not None:
            probe_a = probe_b = list(probe)
        else:
            probe_a = _pairwise_probe_values(
                oa, (value_hints or {}).get(offA))
            probe_b = _pairwise_probe_values(
                ob, (value_hints or {}).get(offB))
        tasks = []
        for va in probe_a:
            for vb in probe_b:
                modified = bytearray(original_data)
                modified[offA] = va
                modified[offB] = vb
                if bytes(modified) == bytes(original_data):
                    continue
                tasks.append(((va, vb), bytes(modified)))

        if tasks:
            _mutation_clock_start()

        with ProcessPoolExecutor(max_workers=n_workers) as ex:
            futures = {}
            for combo, data in tasks:
                fut = ex.submit(_run_mutation_worker,
                                (real_target, data, program_args,
                                 input_file, timeout))
                futures[fut] = combo
                for fut in as_completed(futures):
                    va, vb = futures[fut]
                    out, rc, _t_mut = fut.result()
                    total_tests += 1
                    sig = extract_crash_signature(out)
                    _attach_crash_statement(sig, real_target)
                if sig is None:
                    if base_tgt_rc is not None and rc != base_tgt_rc:
                        results[key]['fork_flip'].append((va, vb))
                    else:
                        results[key]['no_crash'].append((va, vb))
                    continue
                verdict, diff = compare_crash_signatures(_comp_ref_sig, sig)
                crash = sig["crash_frames"][0] if sig["crash_frames"] else {}
                if verdict in ('same_func', 'same_site'):
                    results[key]['matches'][f'{va:02x},{vb:02x}'] = {
                        'verdict': verdict,
                        'type': sig['type'],
                        'function': crash.get('function'),
                        'file': _path_basename(crash.get('file')),
                        'line': crash.get('line'),
                        'rc': rc,
                    }
                    _tot = _mutation_elapsed()
                    results[key]['matches'][f'{va:02x},{vb:02x}']['time_to_success'] = round(_tot, 3)
                    results[key]['matches'][f'{va:02x},{vb:02x}']['time_this_mutation'] = round(_t_mut, 3)
                    print(f'    ({va:02x},{vb:02x}) -> MATCHES ref crash '
                          f'({verdict}: {diff})  [since first mutation {_tot:.3f}s, '
                          f'this run {_t_mut:.3f}s]')
                    _archive(offA, offB, va, vb, _tot)
                else:
                    observed.setdefault(verdict or 'no_crash', 0)
                    observed[verdict or 'no_crash'] += 1
                    if verdict == 'same_type':
                        _site = (crash.get('function'),
                                 _path_basename(crash.get('file')),
                                 crash.get('line'))
                        skey = f"{_site[0]}:{_site[1]}:{_site[2]}"
                        # Near-miss: same ASan type at some other site —
                        # not a match unless the crash POINT (function +
                        # statement) equals the reference's, which
                        # compare_crash_signatures already decided above.
                        observed.setdefault('same_type_sites', {})
                        sites = observed['same_type_sites']
                        sites.setdefault(skey, 0)
                        sites[skey] += 1
                        results[key]['same_type'].setdefault(skey, [])
                        results[key]['same_type'][skey].append((va, vb))
                    else:
                        results[key]['different_type'].append(
                            (va, vb, sig['type']))

        n = len(results[key]['matches'])
        _nc = len(results[key]['no_crash'])
        _ff = len(results[key]['fork_flip'])
        _st = sum(len(v) for v in results[key]['same_type'].values())
        _dt = len(results[key]['different_type'])
        print(f'    => {n} matching combo(s) (target reproduces ref crash); '
              f'no_crash(unchanged)={_nc}, fork_flip(behavior changed)={_ff}, '
              f'same_type={_st}, different_type={_dt}')
        if _ff and _ff <= 60:
            print(f'       fork-flipping combos (target outcome changed): '
                  f'{[(f"0x{a:02x}", f"0x{b:02x}") for a, b in results[key]["fork_flip"]]}')

    results['pairwise_target_crash_summary'] = observed
    print(f'\n  [*] Total pairwise mutations tested: {total_tests}')
    if observed:
        near = observed.get('same_type_sites', {})
        other = {k: v for k, v in observed.items() if k != 'same_type_sites'}
        if other:
            print(f'  [*] Target crashed differently {sum(other.values())} '
                  f'time(s): {other}')
        if near:
            print(f'  [*] Same ASan type at OTHER sites: {near}')
    return results


def run_pairwise_mutation_stage(binary, binary_ref, input_file, program_args,
                                offsets, var_spans, timeout,
                                title='Pairwise mutation', version=None,
                                interaction_pairs=None, value_hints=None,
                                max_pairs=None):
    """Combined two-offset mutation over the fork-variable offsets.

    ``interaction_pairs`` (see _build_interaction_pairs) are added to the
    pair list ahead of the historical pairs; ``value_hints`` (see
    _classify_sweep_results) enrich the per-offset probe sets.
    """
    if not offsets or len(offsets) < 2 or not input_file \
            or not os.path.isfile(input_file) or not binary:
        return {}
    if max_pairs is None:
        try:
            max_pairs = max(0, int(os.environ.get('RETROSCOPE_PAIR_BUDGET',
                                                  '60')))
        except ValueError:
            max_pairs = 60
    pairs = _build_mutation_pairs(offsets, var_spans,
                                  max_pairs=max_pairs,
                                  interaction_pairs=interaction_pairs)
    if not pairs:
        return {}
    _ix = {p for p in map(lambda ab: (min(ab), max(ab)),
                          interaction_pairs or ())}
    n_ix = sum(1 for p in pairs if p in _ix)
    print(f'\n{"="*60}')
    print(f'  {title}')
    print(f'{"="*60}')
    print(f'  Input file: {input_file}')
    print(f'  Target binary: {resolve_binary(binary)}')
    print(f'  Reference binary: {resolve_binary(binary_ref)}')
    print(f'  Pairs to test: {len(pairs)} '
          f'(interaction: {n_ix}, historical/coverage: {len(pairs) - n_ix}; '
          f'probe: per-offset fuzz set '
          f'[extremes -> +-1 -> bit-flips -> hints -> invert/+-2], '
          f'caps {_pairwise_probe_cap()}x{_pairwise_probe_cap()}/pair)')
    return test_pairwise_mutations_compare(
        binary, binary_ref, input_file, program_args, pairs, timeout=timeout,
        version=version, value_hints=value_hints)


def _combo_probe_values():
    """Uniform values for the k-offset combination stage (k >= 3).

    Per combo the stage first tests the UNIFORM mutation (every offset in
    the combo set to the same byte value): this catches marker/flag families
    where several equal bytes must all change together.  The set covers
    low/high boundary values (the common rewrite targets) plus the classic
    boundaries; per-offset refined grids would explode combinatorially.
    """
    return [0x00, 0x01, 0x02, 0x03, 0x04, 0x7f, 0x80, 0xfe, 0xff]


def _combo_budget(kind, default):
    try:
        return max(0, int(os.environ.get(kind, str(default))))
    except ValueError:
        return default


def run_multi_offset_combination_stage(binary, binary_ref, input_file,
                                       program_args, pool, timeout,
                                       version=None, single_results=None,
                                       value_hints=None, max_k=None):
    """Step 6e: automatic k-offset combination mutation (k = 3, 4, ...).

    Runs AFTER the single-byte and two-offset stages found nothing.  It
    combines the dynamically discovered offset pool (fork-variable offsets,
    active/inert/weak single-byte offsets)
    into 3-, then 4-, ... offset combos.  Each combo is first tested with the
    UNIFORM value set (all offsets take the same byte value); a matching
    combo is greedily minimized (drop one offset at a time) and archived.

    Ordering: offsets are scored by their single-byte effect (matches /
    fork-flips / same-type crashes); combos of more "interesting" offsets
    are tried first.

    Budgets (env): RETROSCOPE_COMBO_K_MAX combos per k (default 500),
    RETROSCOPE_COMBO_TOTAL total target runs (default 8000),
    RETROSCOPE_COMBO_K largest k tried (default min(len(pool), 6)).

    Returns ``(results, any_match)``.
    """
    _set_active_cve(input_file)
    results = {}
    if not pool or len(pool) < 3 or not input_file \
            or not os.path.isfile(input_file):
        return results, False
    real_target = resolve_binary(binary)
    real_ref = resolve_binary(binary_ref)
    if not (real_target and real_ref and os.path.isfile(real_target)
            and os.path.isfile(real_ref)):
        print('  [!] Binary not found; combination stage skipped')
        return results, False

    with open(input_file, 'rb') as f:
        original_data = bytearray(f.read())

    def _run(binary, data):
        _ext = os.path.splitext(input_file)[1] if input_file else '.bin'
        fd, tmp_path = tempfile.mkstemp(suffix=_ext, prefix='combo_')
        os.close(fd)
        try:
            with open(tmp_path, 'wb') as f:
                f.write(data)
            cmd = [binary] + [_replace_input_arg(a, tmp_path, input_file)
                              for a in program_args]
            env = _mutation_env(binary)
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  errors="replace", timeout=timeout, env=env)
            return proc.stdout + proc.stderr, proc.returncode
        except subprocess.TimeoutExpired:
            return '', -1
        except Exception:
            return '', -2
        finally:
            try:
                os.unlink(tmp_path)
            except Exception:
                pass

    ref_out, _ = _run(real_ref, original_data)
    ref_sig = extract_crash_signature(ref_out)
    if ref_sig is None:
        print('  [!] Reference binary produced no ASan crash on the '
              'original input; combination stage skipped.')
        return results, False
    ref_crash = ref_sig['crash_frames'][0] if ref_sig['crash_frames'] else {}
    print(f'  Reference crash: {ref_sig["type"]} in '
          f'{ref_crash.get("function")} '
          f'({_path_basename(ref_crash.get("file"))}:'
          f'{ref_crash.get("line")})')

    pool = sorted(set(int(o) for o in pool))
    if max_k is None:
        try:
            max_k = max(0, int(os.environ.get('RETROSCOPE_COMBO_K',
                                             str(min(len(pool), 6)))))
        except ValueError:
            max_k = min(len(pool), 6)
    max_k = max(3, min(max_k, len(pool)))
    combo_k_cap = _combo_budget('RETROSCOPE_COMBO_K_MAX', 500)
    total_budget = _combo_budget('RETROSCOPE_COMBO_TOTAL', 8000)
    probes = _combo_probe_values()

    def _score(o):
        info = (single_results or {}).get(o) or {}
        if not isinstance(info, dict):
            return 0
        return (2 * len(info.get('matches') or {})
                + len(info.get('fork_flip') or ())
                + sum(len(v) for v in (info.get('same_type') or {}).values())
                + len(info.get('different_type') or ()))

    ordered = sorted(pool, key=lambda o: (-_score(o), o))
    hints = {o: v for o, v in (value_hints or {}).items()}

    out_dir = _mutation_out_dir(input_file, version)
    total_runs = 0
    any_match = False
    _t0 = time.time()

    # Same-value grouping: a marker/flag FAMILY is a set of offsets holding
    # the same original byte.  Combos within one family are tried first —
    # that is exactly the shape of "several equal marker bytes must all be
    # rewritten together" (e.g. the COD markers of CVE-2021-3575).
    _groups = {}
    for o in pool:
        if 0 <= o < len(original_data):
            _groups.setdefault(original_data[o], []).append(o)
    _family_order = sorted(
        (v for v in _groups if len(_groups[v]) >= 3),
        key=lambda v: (len(_groups[v]), v))

    def _iter_combos(k):
        seen = set()
        for v in _family_order:
            for combo in itertools.combinations(sorted(_groups[v]), k):
                key = frozenset(combo)
                if key not in seen:
                    seen.add(key)
                    yield list(combo)
        for combo in itertools.combinations(ordered, k):
            key = frozenset(combo)
            if key not in seen:
                seen.add(key)
                yield list(combo)

    def _write_manifest(name, changes, verdict, elapsed):
        try:
            lines = [
                f'mutated file : {name}',
                f'input        : {input_file}',
                f'target ver   : {version}',
                f'reference    : {binary_ref}',
                f'verdict      : {verdict}',
                f'time (s)     : {elapsed} (since first mutation attempt)',
                f'total runs   : {total_runs}',
                'changes:',
            ]
            for off, val in changes:
                if 0 <= off < len(original_data):
                    lines.append(f'  0x{off:04x}  0x{original_data[off]:02x} '
                                 f'-> 0x{val:02x}')
            with open(os.path.join(out_dir, name + '.changes.txt'),
                      'w') as f:
                f.write('\n'.join(lines) + '\n')
        except Exception:
            pass

    for k in range(3, max_k + 1):
        if total_runs >= total_budget:
            break
        n_combos = min(combo_k_cap,
                       _combinations_count(len(pool), k))
        print(f'\n  [combo k={k}] pool={len(pool)} combos={n_combos} '
              f'uniform values={len(probes)} '
              f'(same-value families: {len(_family_order)})')
        tested = 0
        for combo in _iter_combos(k):
            if tested >= combo_k_cap or total_runs >= total_budget:
                break
            # Uniform-value test: every offset in the combo takes the same
            # value.  Offsets whose original byte equals the value are no-ops.
            for val in probes:
                if total_runs >= total_budget:
                    break
                mut = bytearray(original_data)
                for off in combo:
                    if 0 <= off < len(mut) and mut[off] != val:
                        mut[off] = val
                tgt_out, tgt_rc = _run(real_target, mut)
                total_runs += 1
                tested += 1
                tgt_sig = extract_crash_signature(tgt_out)
                verdict, diff = compare_crash_signatures(ref_sig, tgt_sig)
                if verdict in ('same_site', 'same_func'):
                    # Greedy offset minimization (keep the uniform value).
                    minimal = list(combo)
                    reduced = True
                    while reduced and len(minimal) > 1:
                        reduced = False
                        for drop_i in range(len(minimal)):
                            trial = minimal[:drop_i] + minimal[drop_i + 1:]
                            tmut = bytearray(original_data)
                            for off in trial:
                                if 0 <= off < len(tmut) \
                                        and tmut[off] != val:
                                    tmut[off] = val
                            t_out, _ = _run(real_target, tmut)
                            total_runs += 1
                            t_sig = extract_crash_signature(t_out)
                            tv, _ = compare_crash_signatures(ref_sig, t_sig)
                            if tv in ('same_site', 'same_func'):
                                minimal = trial
                                print(f'    [min] drop one offset -> '
                                      f'{len(minimal)} offset(s) still match')
                                reduced = True
                                break
                    _elapsed = int(round(time.time() - _t0))
                    results['match'] = {
                        'combo': [[o, val] for o in minimal],
                        'uniform_value': val,
                        'verdict': verdict,
                        'matched': True,
                        'total_runs': total_runs,
                        'elapsed_seconds': _elapsed,
                    }
                    print(f'  => MATCH (k={k} -> minimal {len(minimal)} '
                          f'offset(s), uniform value 0x{val:02x}, '
                          f'{verdict}): {diff}')
                    _name = (f'combo-k{k}-{len(minimal)}offsets-'
                             f'val0x{val:02x}:time:{_elapsed}')
                    _saved = _save_mutation_artifact(
                        out_dir, _name, original_data,
                        [[o, val] for o in minimal])
                    if _saved:
                        print(f'      saved: {_saved}')
                    _write_manifest(_name, [[o, val] for o in minimal],
                                    verdict, _elapsed)
                    any_match = True
                    return results, any_match
        print(f'    [combo k={k}] {tested} combos tested, no match')

    print(f'  [combo] no k-offset combination reproduced the reference '
          f'crash ({total_runs} runs)')
    return results, any_match


def _combinations_count(n, k):
    import math
    if k > n:
        return 0
    return math.comb(n, k)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description='GDB dynamic tracing: fork-statement variables → input file offsets')

    ap.add_argument('--trace-json', help='lcs_trace.py JSON output (with divergence)')
    ap.add_argument('--binary', help='target binary path (tiff-4.0.8)')
    ap.add_argument('--binary-ref', help='reference binary path (tiff-4.4.0)')
    ap.add_argument('--input', help='input file path')
    ap.add_argument('--fork-file', help='fork-statement source file')
    ap.add_argument('--fork-line', type=int, help='fork-statement line number')
    ap.add_argument('--variables', nargs='+', help='variable names')
    ap.add_argument('--timeout', type=int, default=30, help='GDB timeout seconds')
    ap.add_argument('--no-extended-mutation', dest='extended_mutation',
                    action='store_false',
                    help='disable Step 6f generic extended mutation')
    ap.add_argument('--extended-max-candidates', type=int,
                    default=int(os.environ.get('RETROSCOPE_EXTENDED_MAX',
                                               '1200')),
                    help='Step 6f candidate budget (default 1200)')
    ap.add_argument('--extended-budget', type=float,
                    default=float(os.environ.get(
                        'RETROSCOPE_EXTENDED_BUDGET', '600')),
                    help='Step 6f wall-clock budget seconds (default 600)')
    ap.add_argument('--extended-timeout', type=int,
                    default=int(os.environ.get(
                        'RETROSCOPE_EXTENDED_TIMEOUT', '0')),
                    help='Step 6f per-candidate timeout (0 = use --timeout)')
    ap.set_defaults(extended_mutation=True)
    ap.add_argument('--origin-mutation',
                    help='results/<CVE>_origin_mutation.json from the '
                         'dynamic stage: its active/inert single-byte '
                         'results extend the two-offset pool, supply the '
                         'interaction pairs and the per-offset value hints')
    ap.add_argument('--args', nargs=argparse.REMAINDER, default=[],
                    help='program args (must be last)')

    a = ap.parse_args()

    import stage_timing
    _t_main_start = time.time()

    config = {}
    if a.trace_json:
        config = read_trace_json(a.trace_json) or {}
        if not config:
            print(f'[!] No fork info found in JSON', file=sys.stderr)
            sys.exit(1)

    if a.binary:    config['binary_b'] = a.binary
    if a.binary_ref: config['binary_a'] = a.binary_ref
    if a.input:     config['input_file'] = a.input
    if a.args:      config['program_args'] = a.args
    if a.fork_file: config['fork_file'] = a.fork_file
    if a.fork_line: config['fork_line'] = a.fork_line
    if a.variables: config['variables'] = a.variables

    # Single-byte results of the dynamic stage (if supplied): they classify
    # the offsets into gates/inert for the two-offset stage below and add
    # the dynamically found offsets to its pool.
    origin_results = {}
    if a.origin_mutation:
        if os.path.isfile(a.origin_mutation):
            try:
                with open(a.origin_mutation) as _f:
                    origin_results = json.load(_f) or {}
                _n_off = sum(1 for k in origin_results if str(k).isdigit())
                print(f'[*] origin mutation results: {a.origin_mutation} '
                      f'({_n_off} offsets)')
            except Exception as _e:
                print(f'[!] origin mutation results unreadable: {_e}')
        else:
            print(f'[!] --origin-mutation file not found: '
                  f'{a.origin_mutation}')
    is_code_change = config.get('_code_change', False)

    if not config.get('variables') and config.get('fork_stmt'):
        config['variables'] = extract_variables_from_statement(config['fork_stmt'])

    binary = config.get('binary_b', '')
    binary_ref = config.get('binary_a', '')
    fork_file = config.get('fork_file')
    fork_line = config.get('fork_line')
    original_fork_line = config.get('original_fork_line', fork_line)
    variables = config.get('variables', [])
    input_file = config.get('input_file', '')
    program_args = config.get('program_args', [])

    # Legacy TIFF convenience: for forks produced WITHOUT the unified dynamic
    # locator, additionally probe the image/crop geometry fields (they feed
    # the TIFF tag-value matching).  Dynamic-locator forks already carry the
    # precise guard operands (e.g. ['in']) and must NOT be polluted.
    # Only apply to TIFF projects — for other targets these fields do not
    # exist and their GDB evaluation just fails.
    _is_tiff = 'tiff' in (fork_file or '').lower() or 'tiff' in binary.lower()
    # a "crash_point_hits" dynamic_fork only carries the invocation anchor
    # (no fork variables); the TIFF image-field extension still applies.
    _dynfork = config.get('dynamic_fork') or {}
    if (not _dynfork or _dynfork.get('status') == 'crash_point_hits') \
            and _is_tiff:
        _image_fields = ['image.width', 'image.length', 'image.bps', 'image.spp',
                         'image.compression', 'image.photometric', 'image.orientation',
                         'image.planar', 'image.res_unit']
        for _f in _image_fields:
            if _f not in variables:
                variables.append(_f)
        _crop_fields = ['crop.combined_width', 'crop.combined_length',
                        'crop.bufftotal', 'crop.zones', 'crop.selections',
                        'crop.edge_ref', 'crop.crop_mode']
        for _f in _crop_fields:
            if _f not in variables:
                variables.append(_f)

    if not binary:
        print('Error: --binary required (not found in JSON)', file=sys.stderr)
        print('Usage: python3 trace_fork_offsets.py --trace-json FILE --binary BINARY [--args ...]', file=sys.stderr)
        sys.exit(1)
    if not fork_file or not fork_line:
        print('Error: --fork-file/--fork-line or valid JSON required', file=sys.stderr); sys.exit(1)

    # Note code-change forks but continue tracing
    is_code_change = config.get('_code_change', False)
    if is_code_change:
        stmt_a = config.get('_code_change_info', {}).get('stmt_a', config.get('root_cause_statement_a', 'N/A'))
        stmt_b = config.get('_code_change_info', {}).get('stmt_b', config.get('root_cause_statement_b', 'N/A'))
        print(f'\n  [*] NOTE: Code-change fork detected — tracing target version variables anyway')
        print(f'  [*] v4.4.0: {stmt_a}')
        print(f'  [*] v4.0.8: {stmt_b}')

    if not variables:
        print('Error: --variables or JSON with fork_stmt required', file=sys.stderr); sys.exit(1)

    fork_spec = f'{fork_file}:{fork_line}'
    print(f'[*] Target binary: {resolve_binary(binary)}')
    if binary_ref:
        print(f'[*] Reference binary: {resolve_binary(binary_ref)}')
    print(f'[*] Fork: {fork_spec}')
    print(f'[*] Variables: {variables}')
    print(f'[*] Input: {input_file}')

    # Find the correct fork line for each version
    fork_spec_b = fork_spec  # Target version (tiff-4.0.8) - uses line from read_source_fork_statement
    ref_fork_file = config.get('ref_fork_file') or fork_file
    fork_spec_a = f'{ref_fork_file}:{original_fork_line}'  # Reference version - its own file & line

    print(f'[*] Target fork spec: {fork_spec_b}')
    if binary_ref:
        print(f'[*] Reference fork spec: {fork_spec_a}')

    # Each run keeps only its own mutation artifacts: clear the
    # out/<input-name>-<target-version>/ folder for this CVE + version
    # before any mutation stage archives new results.
    _reset_dir = _reset_mutation_out_dir(input_file, config.get('version_b'))
    print(f'[*] Mutation output dir (reset): {_reset_dir}')
    print('[*] Next mutation stages: Step 6b pairwise -> Step 6a directed '
          '-> Step 6e combo -> Step 6f P0 -> Steps 6c/6d static last')

    # ================================================================
    # Step 1: Run GDB on TARGET binary (tiff-4.0.8)
    # ================================================================
    print(f'\n{"="*60}')
    print(f'  Step 1: GDB trace on TARGET binary')
    print(f'{"="*60}')
    log_text_b, error_b = run_gdb_trace(
        binary, fork_spec_b, variables, input_file, program_args, timeout=a.timeout)

    if error_b:
        print(f'[!] Target GDB trace failed: {error_b}', file=sys.stderr)
        sys.exit(1)

    parsed_b = parse_gdb_log(log_text_b)
    print(f'  [*] Captured {len(parsed_b["variables"])} variables')

    # ================================================================
    # Step 2: Run GDB on REFERENCE binary (tiff-4.4.0) if available
    # ================================================================
    parsed_a = None
    if binary_ref and os.path.isfile(resolve_binary(binary_ref)):
        print(f'\n{"="*60}')
        print(f'  Step 2: GDB trace on REFERENCE binary')
        print(f'{"="*60}')
        log_text_a, error_a = run_gdb_trace(
            binary_ref, fork_spec_a, variables, input_file, program_args, timeout=a.timeout)

        if error_a:
            print(f'  [!] Reference GDB trace failed: {error_a}')
            print(f'  [*] Continuing with target-only analysis')
        else:
            parsed_a = parse_gdb_log(log_text_a)
            print(f'  [*] Captured {len(parsed_a["variables"])} variables')

    # ================================================================
    # Step 3: Compare variable values between two versions
    # ================================================================
    print(f'\n{"="*60}')
    print(f'  Step 3: Compare variable values')
    print(f'{"="*60}')

    differing_vars = []
    for vname in variables:
        val_b = None
        val_a = None
        for v in parsed_b['variables']:
            if v['name'] == vname:
                val_b = v['val']
                break
        if parsed_a:
            for v in parsed_a['variables']:
                if v['name'] == vname:
                    val_a = v['val']
                    break

        if val_a is not None and val_b is not None:
            same = 'SAME' if val_a == val_b else 'DIFFER'
            print(f'  {vname}: target=0x{val_b:x} ref=0x{val_a:x} [{same}]')
            if val_a != val_b:
                differing_vars.append(vname)
        elif val_b is not None:
            print(f'  {vname}: target=0x{val_b:x} ref=N/A')
        else:
            print(f'  {vname}: target=N/A ref=N/A')

    if not differing_vars:
        print(f'\n  [*] No differing variables found between versions')
        print(f'  [*] All fork variables have the same value in both versions')
        # Fall back to single-version analysis
        differing_vars = variables

    # ================================================================
    # Step 3.5: Deep trace into TIFFOpen internals for differing vars
    # ================================================================
    # A fork guard like ``if (in == NULL)`` tests a variable that is the
    # RETURN value of TIFFOpen().  Rather than stopping at "in = TIFFOpen()
    # returns NULL", trace INWARD through the open-time call path: which TIFF
    # functions were reached, which pread64 reads were performed, and which
    # read/error actually decided the NULL return.  This pinpoints the input
    # file bytes that made the handle NULL.
    deep_results = {}
    _file_return_vars = [v for v in differing_vars if v in _FILE_FUNC_RETURN_VARS]
    if _file_return_vars:
        print(f'\n{"="*60}')
        print(f'  Step 3.5: Deep trace into {", ".join(sorted(set(_FILE_FUNC_RETURN_VARS[v] for v in _file_return_vars)))} internals')
        print(f'{"="*60}')

        file_size = 0
        if input_file and os.path.isfile(input_file):
            file_size = os.path.getsize(input_file)

        for ver_name, ver_binary in [('target', binary), ('reference', binary_ref)]:
            if not ver_binary or not os.path.isfile(resolve_binary(ver_binary)):
                continue
            print(f'\n  [*] Tracing {ver_name}: {resolve_binary(ver_binary)}')
            trace_out, err = run_deep_tiffopen_trace(
                ver_binary, input_file, program_args, timeout=a.timeout)
            if err:
                print(f'  [!] {ver_name} deep trace failed: {err}')
                continue
            result = parse_deep_trace(trace_out)
            deep_results[ver_name] = result

            # Print call chain results
            print(f'    Functions called: {", ".join(result["functions_called"]) if result["functions_called"] else "none"}')
            print(f'    TIFF pointer: {result["tif_ptr"] or "N/A"}')
            print(f'    pread64 calls: {len(result["pread64_calls"])}')
            for p in result['pread64_calls']:
                within = 'within file' if p['offset'] + p['size'] <= file_size else 'BEYOND FILE'
                print(f'      offset=0x{p["offset"]:04x} size={p["size"]} [{within}]')
            if result['errors']:
                print(f'    Errors ({len(result["errors"])}):')
                for e in result['errors'][:3]:
                    print(f'      {e[:120]}')

        # Compare deep trace results
        if 'target' in deep_results and 'reference' in deep_results:
            t = deep_results['target']
            r = deep_results['reference']
            print(f'\n  [*] Deep trace comparison:')
            t_funcs = set(t['functions_called'])
            r_funcs = set(r['functions_called'])
            print(f'    Functions: target={t["functions_called"]} ref={r["functions_called"]}')

            # Find differing pread64 calls
            t_offs = set((p['offset'], p['size']) for p in t['pread64_calls'])
            r_offs = set((p['offset'], p['size']) for p in r['pread64_calls'])
            only_t = t_offs - r_offs
            only_r = r_offs - t_offs
            if only_t or only_r:
                print(f'    pread64 DIFFERS:')
                if only_t:
                    for off, sz in sorted(only_t):
                        print(f'      only target: offset=0x{off:x} size={sz}')
                if only_r:
                    for off, sz in sorted(only_r):
                        print(f'      only ref: offset=0x{off:x} size={sz}')
            else:
                print(f'    pread64 calls IDENTICAL between versions')

            # Map pread64 calls to input file offsets
            print(f'\n  [*] Mapping pread64 calls to input file:')
            for p in t['pread64_calls']:
                off = p['offset']
                sz = p['size']
                if off < file_size:
                    end = min(off + sz, file_size)
                    print(f'    pread64 offset=0x{off:x} size={sz} => input file bytes [0x{off:x}-0x{end:x})')
                else:
                    print(f'    pread64 offset=0x{off:x} size={sz} => BEYOND file (size={file_size})')
                    print(f'      ^^^ This read accesses invalid data beyond file boundary')

    # ================================================================
    # Step 4: Trace file I/O and map to input file
    # ================================================================
    print(f'\n{"="*60}')
    print(f'  Step 4: Trace file I/O → input file offsets')
    print(f'{"="*60}')

    # Collect pread64 calls from both versions
    file_reads_b = parsed_b.get('file_reads', [])
    file_reads_a = parsed_a.get('file_reads', []) if parsed_a else []

    # Filter to positioned reads (pread64 with explicit offsets)
    positioned_b = [r for r in file_reads_b if r['offset'] >= 0]
    positioned_a = [r for r in file_reads_a if r['offset'] >= 0]

    # Deduplicate
    def dedup(reads):
        seen = set()
        result = []
        for r in reads:
            key = (r['offset'], r['size'])
            if key not in seen:
                seen.add(key)
                result.append(r)
        return sorted(result, key=lambda r: r['offset'])

    positioned_b = dedup(positioned_b)
    positioned_a = dedup(positioned_a)

    if input_file and os.path.isfile(input_file):
        file_size = os.path.getsize(input_file)
        print(f'\n  Input file: {input_file} ({file_size} bytes)')

        # Show target version I/O
        print(f'\n  Target version ({config.get("version_b", "target")}) pread64 calls:')
        if positioned_b:
            for r in positioned_b:
                beyond = ' ** BEYOND FILE **' if r['offset'] >= file_size else ''
                print(f'    offset=0x{r["offset"]:04x} ({r["offset"]})  size={r["size"]}  [{r["offset"]:04x}-{r["offset"]+r["size"]:04x}){beyond}')
        else:
            print(f'    (no pread64 calls captured)')

        # Show reference version I/O
        if positioned_a:
            print(f'\n  Reference version ({config.get("version_a", "reference")}) pread64 calls:')
            for r in positioned_a:
                beyond = ' ** BEYOND FILE **' if r['offset'] >= file_size else ''
                print(f'    offset=0x{r["offset"]:04x} ({r["offset"]})  size={r["size"]}  [{r["offset"]:04x}-{r["offset"]+r["size"]:04x}){beyond}')

        # Find reads that differ between versions
        if positioned_a:
            target_offsets = set((r['offset'], r['size']) for r in positioned_b)
            ref_offsets = set((r['offset'], r['size']) for r in positioned_a)
            only_target = target_offsets - ref_offsets
            only_ref = ref_offsets - target_offsets

            if only_target or only_ref:
                print(f'\n  I/O differences between versions:')
                if only_target:
                    print(f'    Only in target ({config.get("version_b", "target")}):')
                    for off, sz in sorted(only_target):
                        print(f'      offset=0x{off:04x} size={sz}')
                if only_ref:
                    print(f'    Only in reference ({config.get("version_a", "reference")}):')
                    for off, sz in sorted(only_ref):
                        print(f'      offset=0x{off:04x} size={sz}')
            else:
                print(f'\n  I/O patterns are identical between versions')

        # Identify critical reads
        print(f'\n  Critical file reads (determining fork variable values):')
        for r in positioned_b:
            offset = r['offset']
            size = r['size']
            if offset >= file_size:
                print(f'    offset=0x{offset:04x} size={size} -- BEYOND FILE BOUNDARY')
                print(f'      This read accesses invalid data beyond the file '
                      f'end (short read / IO error)')
            else:
                print(f'    offset=0x{offset:04x} size={size} -- within file boundary')

    # ================================================================
    # Step 4.5: GDB call-site / fork-context trace (fully dynamic)
    # ================================================================
    chain_trace_results = {}
    if binary and fork_spec and input_file:
        print(f'\n{"="*60}')
        print(f'  Step 4.5: GDB call-site / fork-context trace (fully dynamic)')
        print(f'{"="*60}')

        # Fork function comes from the divergence result; variables are the
        # fork-statement operands captured by the divergence analysis.
        df = config.get('dynamic_fork') or {}
        fork_func_name = (df.get('function_b')
                          or config.get('root_cause_function')
                          or config.get('poly_track_function')
                          or '')
        if not fork_func_name:
            # Last resort: derive the enclosing function of the fork line
            # from the fork source file.
            try:
                from backward_tracer import _find_function_containing_line
                _src = Path(fork_file)
                if not _src.is_absolute():
                    _root = Path(resolve_binary(binary)).resolve()
                    for _par in [_root] + list(_root.parents):
                        _cand = _par / _src.name
                        if _cand.is_file():
                            _src = _cand
                            break
                fork_func_name = _find_function_containing_line(
                    str(_src), fork_line) or ''
            except Exception:
                fork_func_name = ''
        if not fork_func_name:
            print('  [!] No fork function available — skipping call-site '
                  'trace (the fork statement location is used directly).')
            chain_trace_results = {}
            cs_result, err = None, None
        else:
            print(f'  [*] Fork function: {fork_func_name}')

            _diff_b = ((df.get('diff') or {}).get('b') or {})
            _b_clauses = _diff_b.get('clauses') or {}
            _clause = None
            if _b_clauses:
                _first_key = sorted(_b_clauses, key=lambda k: int(k))[0]
                _clause = _b_clauses[_first_key]

            cs_result, err = run_gdb_call_site_trace(
                binary, fork_spec, fork_func_name, variables, input_file,
                program_args, timeout=a.timeout * 2, clauses=_clause)

            if err:
                print(f'  [!] Call-site trace failed: {err}')
            elif cs_result:
                chain_trace_results = cs_result
                fork_points = cs_result.get('fork_points', [])
                mappings = cs_result.get('tag_mappings', {})
                var_mappings = cs_result.get('var_mappings', {})

                if fork_points:
                    print(f'  [*] Fork-point executions ({len(fork_points)}):')
                    for fp in fork_points[:3]:
                        vals = ' '.join(f'{k}={v}' for k, v in fp['varvals'].items())
                        print(f'      inv={fp["inv"]}: {vals}')
                    if len(fork_points) > 3:
                        print(f'      ... (+{len(fork_points)-3} more)')

                if mappings:
                    print(f'\n  [*] Call-site actual arguments (dp->tdir_tag) -> file offsets:')
                    for tagid, info in mappings.items():
                        name = info.get('tag_name', f'tag_{tagid}')
                        if info.get('file_offset') is not None:
                            print(f'      tagid={tagid} ({name}):')
                            print(f'        dp={info["dp"]}  dir={info["dir"]}')
                            print(f'        IFD at file offset '
                                  f'0x{info["ifd_offset"]:x} (tif->tif_diroff)')
                            print(f'        entry index {info["entry_index"]} '
                                  f'-> tdir_tag at file offset '
                                  f'0x{info["file_offset"]:x}')
                        else:
                            print(f'      tagid={tagid} ({name}): no IFD buffer match')
                elif var_mappings:
                    print(f'\n  [*] Fork-variable sources (fork-point context):')
                    fp = fork_points[-1] if fork_points else {}
                    diroff = fp.get('diroff')
                    for vname, info in var_mappings.items():
                        if info.get('file_offset') is not None:
                            print(f'      {vname}:')
                            print(f'        kind={info["kind"]} -> file offset '
                                  f'0x{info["file_offset"]:x} '
                                  f'(tif->tif_diroff=0x{diroff:x})')
                        else:
                            print(f'      {vname}: no IFD mapping')

    # ================================================================
    # Step 4.6: Arithmetic backtrace (allocator summary + def-use chain)
    # ================================================================
    arith_result = None
    _fork_points = (chain_trace_results or {}).get('fork_points') or []
    if _fork_points and fork_file and fork_line:
        fork_vals = _fork_points[-1].get('varvals') or {}
        print(f'\n{"="*60}')
        print(f'  Step 4.6: Arithmetic backtrace (allocator summary)')
        print(f'{"="*60}')
        try:
            arith_result = arithmetic_backtrace(
                binary, fork_file, fork_line, list(fork_vals.keys()),
                fork_vals, input_file, program_args, timeout=a.timeout * 2)
        except Exception as exc:
            print(f'  [!] Arithmetic backtrace failed: {exc}')
            arith_result = None
        if arith_result:
            chains = arith_result.get('chains') or {}
            expl = arith_result.get('explanation') or {}
            for v in list(fork_vals.keys()):
                ch = chains.get(v)
                lines = expl.get(v)
                if not ch or not lines:
                    continue
                head = f'  [*] {v}'
                if ch.get('allocator'):
                    head += (f'  (allocator {ch["allocator"]}: '
                             f'NULL <=> size==0 / OOM)')
                print(head)
                for ln in lines:
                    print(f'      {ln}')
                if ch['tag_offsets']:
                    tos = ', '.join(f'0x{t["file_offset"]:x}({t["tag_name"]})'
                                    for t in ch['tag_offsets'])
                    print(f'      -> input file offsets: {tos}')
                if ch['cli_leaves']:
                    print(f'      -> command-line contributors: '
                          f'{", ".join(ch["cli_leaves"])}')
            probe_offsets = sorted({
                t['file_offset']
                for ch in chains.values()
                for t in ch.get('tag_offsets', [])})
            if probe_offsets:
                print(f'\n  [*] Fork-flip probe (mutate mapped offsets, '
                      f'check if the fork outcome changes):')
                probe = fork_flip_probe(
                    binary, input_file, program_args, probe_offsets,
                    'Unable to allocate/reallocate crop buffer',
                    timeout=a.timeout)
                for off in sorted(probe):
                    info = probe[off]
                    flips = [
                        f'0x{v:02x}:{"FLIP" if not flipped else "no-flip"}'
                        for v, flipped in sorted(info['trials'].items())]
                    print(f'      offset 0x{off:x} (orig=0x{info["original_byte"]:02x}): '
                          f'fork-taken={info["original_fork_taken"]}; '
                          + ', '.join(flips))

    # ================================================================
    # Step 5: Fork-variable → file offset mapping (fully dynamic)
    # ================================================================
    print(f'\n{"="*60}')
    print(f'  Step 5: Fork-variable → input file offset mapping')
    print(f'{"="*60}')

    # Identify the DIVERGING invocation's tagid from the divergence result:
    # the fork statement's comparison clauses record the runtime operand
    # values (e.g. `field_tag < tagid` with lhs=270, rhs=269), so the
    # diverging call-site argument is the rhs of the first clause.
    fork_tagid = None
    df = config.get('dynamic_fork') or {}
    diff_b = ((df.get('diff') or {}).get('b') or {})
    b_clauses = diff_b.get('clauses') or {}
    if b_clauses:
        for _k in sorted(b_clauses, key=lambda k: int(k)):
            _c = b_clauses[_k]
            if _c.get('rhs') is not None:
                fork_tagid = int(_c.get('rhs'))
                break

    # Identify the DIVERGING invocation's tagid from the divergence result:
    # the fork statement's comparison clauses record the runtime operand
    # values (e.g. `field_tag < tagid` with lhs=270, rhs=269), so the
    # diverging call-site argument is the rhs of the first clause.
    fork_tagid = None
    df = config.get('dynamic_fork') or {}
    diff_b = ((df.get('diff') or {}).get('b') or {})
    b_clauses = diff_b.get('clauses') or {}
    if b_clauses:
        for _k in sorted(b_clauses, key=lambda k: int(k)):
            _c = b_clauses[_k]
            if _c.get('rhs') is not None:
                fork_tagid = int(_c.get('rhs'))
                break

    print(f'\n  GDB call-site trace summary (fully dynamic):')
    if chain_trace_results and chain_trace_results.get('tag_mappings'):
        # Case A (classic): dp->tdir_tag argument mapping, filtered to the
        # diverging invocation's tagid.
        all_mappings = chain_trace_results['tag_mappings']
        if fork_tagid is not None:
            key = fork_tagid
            selected = {key: all_mappings[key]} if key in all_mappings else {}
        else:
            selected = dict(all_mappings)

        if fork_tagid is not None:
            print(f'  [*] Diverging invocation: tagid={fork_tagid} '
                  f'(from divergence clauses rhs)')
        if not selected:
            print(f'    (no mapping for the diverging call-site argument)')
        for tagid, info in selected.items():
            name = info.get('tag_name', f'tag_{tagid}')
            if info.get('file_offset') is not None:
                print(f'    tagid={tagid} ({name})')
                print(f'      ← dp->tdir_tag (IFD entry '
                      f'#{info["entry_index"]}) at file offset '
                      f'0x{info["file_offset"]:x}')
                print(f'      ← IFD at file offset '
                      f'0x{info["ifd_offset"]:x} (tif->tif_diroff)')
            else:
                print(f'    tagid={tagid} ({name}): no file mapping')

        # Keep only the diverging mapping in the saved result.
        chain_trace_results['tag_mappings'] = selected
    elif chain_trace_results and chain_trace_results.get('var_mappings'):
        # Case B (generic): fork-variable sources from the fork-point context.
        fp = chain_trace_results.get('fork_points') or []
        fp = fp[-1] if fp else {}
        for vname, info in chain_trace_results['var_mappings'].items():
            if info.get('file_offset') is not None:
                print(f'    {vname} ({info["kind"]})')
                print(f'      ← at file offset 0x{info["file_offset"]:x}')
                if fp.get('diroff') is not None:
                    print(f'      ← IFD at file offset '
                          f'0x{fp["diroff"]:x} (tif->tif_diroff)')
            else:
                print(f'    {vname}: no file mapping')

    # ================================================================
    # Summary — dynamic, based on analysis results
    # ================================================================
    print(f'\n{"="*60}')
    print(f'  SUMMARY')
    print(f'{"="*60}')

    fork_stmt_text = config.get('fork_stmt', fork_spec)

    # 1. Fork point
    # Truncate multi-line fork statement to the key line (e.g., "if (in == NULL)")
    short_fork = fork_stmt_text.strip()
    for line in short_fork.splitlines():
        stripped = line.strip()
        if 'if (' in stripped or 'else if (' in stripped:
            short_fork = stripped
            break

    print(f'  1. Fork point: {short_fork}')

    # 3. Deep trace comparison (errors and function calls) — the INWARD
    # trace into the file-open function whose return value the guard tests.
    if deep_results:
        target_errors = deep_results.get('target', {}).get('errors', [])
        ref_errors = deep_results.get('reference', {}).get('errors', [])
        target_funcs = deep_results.get('target', {}).get('functions_called', [])
        ref_funcs = deep_results.get('reference', {}).get('functions_called', [])

        print(f'  3. Deep trace comparison:')
        if target_errors:
            for e in target_errors:
                print(f'     Target error: {e}')
        if ref_errors:
            for e in ref_errors:
                print(f'     Reference error: {e}')
        if target_funcs:
            print(f'     Target functions called: {", ".join(target_funcs)}')
        if ref_funcs:
            print(f'     Reference functions called: {", ".join(ref_funcs)}')

        # Critical reads beyond file boundary
        target_reads = deep_results.get('target', {}).get('pread64_calls', [])
        file_size = 0
        if input_file and os.path.isfile(input_file):
            with open(input_file, 'rb') as f:
                file_size = len(f.read())
        critical_reads = [r for r in target_reads if r['offset'] + r['size'] > file_size] if file_size else []
        if critical_reads:
            print(f'  4. Critical file reads (beyond file boundary, size={file_size}):')
            for r in critical_reads:
                print(f'     pread64 offset=0x{r["offset"]:x} size={r["size"]} — BEYOND FILE')
            print(f'     These reads cause IO errors, leading to TIFFOpen returning NULL')
    else:
        print(f'  3. Root cause: see detailed analysis above')

    # 5. Input file offsets to modify (from the dynamic call-site trace)
    mapped_offsets = set()
    if chain_trace_results and chain_trace_results.get('tag_mappings'):
        for _tagid, _info in chain_trace_results['tag_mappings'].items():
            if _info.get('file_offset') is not None:
                mapped_offsets.add(_info['file_offset'])
    if chain_trace_results and chain_trace_results.get('var_mappings'):
        for _vname, _info in chain_trace_results['var_mappings'].items():
            if _info.get('file_offset') is not None:
                mapped_offsets.add(_info['file_offset'])

    # 5. Fork-variable -> input file offset mapping (dynamic, generic).
    # Every fork variable captured at the breakpoint (value/address) is
    # traced back to the input bytes: pointer values that land inside a
    # recorded read buffer map exactly; scalar values are located by their
    # byte encoding within the regions the program actually read.
    var_offsets = {}
    if parsed_b and input_file and os.path.isfile(input_file):
        try:
            with open(input_file, 'rb') as _f:
                _fdata = _f.read()
            var_offsets = map_fork_variables_to_offsets(
                parsed_b.get('variables', []), file_reads_b, _fdata)
        except Exception as _e:
            print(f'  [!] variable->offset mapping failed: {_e}')

    # A fork variable that is the NULL return of a file-reading function
    # (``in = TIFFOpen(...)`` returning NULL — the ``if (in == NULL)`` guard)
    # has no byte-pattern signal (value 0 matches every zero byte) and its
    # pointer value 0 lies in no read buffer.  The positioned reads captured
    # before the fork ARE the input bytes that made the open fail, so they
    # are the variable's file offsets.
    if not var_offsets and file_reads_b:
        try:
            _deep_reads = None
            _file_size = None
            if deep_results.get('target'):
                _deep_reads = deep_results['target'].get('pread64_calls') or []
            if input_file and os.path.isfile(input_file):
                _file_size = os.path.getsize(input_file)
            _open_offsets = map_file_read_return_offsets(
                parsed_b.get('variables', []), file_reads_b,
                fork_vars=config.get('variables'),
                deep_reads=_deep_reads, file_size=_file_size)
            if _open_offsets:
                var_offsets.update(_open_offsets)
        except Exception as _e:
            print(f'  [!] file-open return-value mapping failed: {_e}')

    mapped_offsets = set()
    # Candidate confidence tiers: how each offset was tied to the fork
    # statement.  Kept separately so per-tier precision can be measured
    # (e.g. in experiments) instead of mixing exact provenance with
    # value-pattern guesses and structural expansion.
    candidate_tiers = {}

    def _add_tier(_tier, _off):
        candidate_tiers.setdefault(_tier, [])
        if _off not in candidate_tiers[_tier]:
            candidate_tiers[_tier].append(_off)

    if var_offsets:
        print(f'\n  5. Fork variables -> input file offsets (dynamic):')
        for _vname, _hits in var_offsets.items():
            _hstr = ', '.join(
                f'0x{h["offset"]:x} ({h["method"]}'
                f'{", w"+str(h["width"]) if h["width"] else ""}'
                f'{", " + h["tier"] if h.get("tier") else ""})'
                for h in _hits[:8])
            print(f'     {_vname} -> {_hstr}')
        for _hits in var_offsets.values():
            for _h in _hits:
                mapped_offsets.add(_h['offset'])
                _add_tier(_h.get('tier') or 'C_value_pattern', _h['offset'])

    if chain_trace_results and chain_trace_results.get('tag_mappings'):
        for _tagid, _info in chain_trace_results['tag_mappings'].items():
            if _info.get('file_offset') is not None:
                mapped_offsets.add(_info['file_offset'])
                _add_tier('A_dynamic_callsite', _info['file_offset'])
    if chain_trace_results and chain_trace_results.get('var_mappings'):
        for _vname, _info in chain_trace_results['var_mappings'].items():
            if _info.get('file_offset') is not None:
                mapped_offsets.add(_info['file_offset'])
                _add_tier('A_dynamic_callsite', _info['file_offset'])

    # 5.1. IFD region offsets (dynamic): the fork decision executes inside
    # TIFFReadDirectory's IFD-entry loop, so the whole directory that the
    # fork point belongs to is a structural input.  All four fields
    # (tag/type/count/offset) of EVERY entry in that IFD are computed from
    # the fork-point runtime context (tif->tif_diroff + dircount) — nothing
    # static, nothing without a fork-point execution.  These structural
    # fields are NOT merged into the full-sweep set (72 fields x 255 values
    # would explode); they get a directed-value mutation in Step 6a when
    # the region comes from the dynamic fork-point context, or the full
    # Steps 6c/6d fallback sweep when it comes from a static format parse.
    _ifd_region = (chain_trace_results or {}).get('ifd_region') or {}
    _ifd_from_dynamic = bool(_ifd_region.get('field_offsets'))
    if (not _ifd_region.get('field_offsets')) and input_file \
            and os.path.isfile(input_file):
        _ifd_region = _static_ifd_region(input_file) or {}
        if _ifd_region:
            print(f'  [*] IFD region from static TIFF parse (dynamic '
                  f'fork-point context unavailable)')
        else:
            _ifd_region = static_structure_region(input_file) or {}
            if _ifd_region:
                print(f"  [*] {_ifd_region.get('label')} from static "
                      f"{_ifd_region.get('format')} parse (dynamic "
                      f"fork-point context unavailable)")
    _ifd_fields = _ifd_region.get('field_offsets') or []
    if _ifd_fields:
        if (_ifd_region.get('format') or 'tiff') == 'tiff':
            print(f'\n  5.1. IFD region offsets (dynamic, from fork-point context):')
            print(f'      IFD at file offset 0x{_ifd_region.get("ifd_offset"):x}, '
                  f'{_ifd_region.get("count")} entries x '
                  f'{_ifd_region.get("entry_size")} bytes')
            _fo = ', '.join(f'0x{o:x}' for o in sorted(_ifd_fields))
            print(f'      all entry fields (tag/type/count/offset): {_fo}')
            _s_tier = 'S_structural_ifd_region'
        else:
            _lab = _ifd_region.get('label') or 'structure region'
            _base = _ifd_region.get('region_offset')
            _base_s = (f' at file offset 0x{_base:x}'
                       if isinstance(_base, int) else '')
            print(f'\n  5.1. {_lab} offsets (static format parse):')
            if _ifd_region.get('count') and _ifd_region.get('entry_size'):
                print(f'      {_lab}{_base_s}, {_ifd_region.get("count")} '
                      f'records x {_ifd_region.get("entry_size")} bytes')
            else:
                print(f'      {_lab}{_base_s}, {len(_ifd_fields)} '
                      f'field position(s)')
            _fo = ', '.join(f'0x{o:x}' for o in sorted(_ifd_fields))
            print(f'      structure fields: {_fo}')
            _s_tier = 'S_structural_format'
        for _off in _ifd_fields:
            _add_tier(_s_tier, _off)

    # Validation candidates = exactly the offsets derived from the fork
    # variables (no read-region expansion).
    if mapped_offsets:
        offset_strs = ', '.join(f'0x{o:x}' for o in sorted(mapped_offsets))
        print(f'  Validation candidates (from fork variables) at input file '
              f'offsets: {offset_strs}')

    # 5.2. Confidence-tiered view of the candidates (for precision
    #      measurement per association method).
    if arith_result:
        for _ch in (arith_result.get('chains') or {}).values():
            for _t in _ch.get('tag_offsets', []):
                _add_tier('B_arithmetic_tag', _t['file_offset'])
    if candidate_tiers:
        print(f'\n  5.2. Candidate offsets by confidence tier:')
        _TIER_ORDER = (
            'A_direct_pointer', 'A_dynamic_callsite', 'A_deep_open_critical',
            'A_deep_open_read', 'B_value_field', 'B_arithmetic_tag',
            'C_value_pattern', 'C_open_read_fallback',
            'S_structural_ifd_region', 'S_structural_format',
        )
        _TIER_DESC = {
            'A_direct_pointer': 'pointer value inside a recorded read buffer (exact)',
            'A_dynamic_callsite': 'IFD entry/dir/dp arithmetic at the fork point (exact)',
            'A_deep_open_critical': 'beyond-file read inside the open function (failure cause)',
            'A_deep_open_read': 'read performed inside the open function',
            'B_value_field': 'unique multi-byte value field verified in read regions',
            'B_arithmetic_tag': 'def-use chain TIFF tag value (runtime-matched)',
            'C_value_pattern': 'ambiguous/narrow value-pattern match (likely noise)',
            'C_open_read_fallback': 'whole-run read set (deep trace produced nothing)',
            'S_structural_ifd_region': 'directory region from fork context (not swept)',
            'S_structural_format': 'input-format structure fields (static parse, directed probes only)',
        }
        for _tier in _TIER_ORDER:
            _offs = sorted(candidate_tiers.get(_tier) or [])
            if not _offs:
                continue
            _sample = ', '.join(f'0x{o:x}' for o in _offs[:8])
            _more = f' ... (+{len(_offs)-8} more)' if len(_offs) > 8 else ''
            print(f'     {_tier} [{_TIER_DESC.get(_tier, "")}]: '
                  f'{len(_offs)} offset(s): {_sample}{_more}')

    # 5c. Value-level mutation of the fork-variable origins: rewrite the
    #     whole value at each origin (e.g. the 4-byte ImageLength value at
    #     0x22) and check at the fork statement whether the guard's outcome
    #     flips — "change the value, not the byte".
    value_level_results = None
    if var_offsets and binary and fork_spec_b and input_file:
        _df = config.get('dynamic_fork') or {}
        _cond_text = (((_df.get('diff') or {}).get('b') or {}).get('text')
                      or config.get('root_cause_statement_b', ''))
        if _fork_condition_expr(_cond_text):
            print(f'\n  Step 5c: Value-level mutation of fork-variable origins')
            try:
                value_level_results = test_value_level_mutations(
                    binary, binary_ref, input_file, program_args,
                    var_offsets, fork_spec_b, _cond_text,
                    timeout=a.timeout, fork_variables=variables,
                    version=config.get('version_b'))
            except Exception as _e:
                print(f'  [!] value-level mutation failed: {_e}')
            if value_level_results:
                _NUM = re.compile(r'^-?\d+$')
                for _off, _r in sorted(value_level_results.items()):
                    _flips = [v for v, t in _r['trials'].items()
                              if t.get('outcome_flip')]
                    _vchg = [v for v, t in _r['trials'].items()
                             if t.get('val_changed')]
                    _crashes = [v for v, t in _r['trials'].items()
                                if t.get('crash') in ('same_func', 'same_site')]
                    # Display only numeric-valued fork variables (skip
                    # pointer/struct dumps).
                    def _fmt(vals):
                        return ', '.join(
                            f'{variables[i]}={v}' for i, v in
                            sorted((vals or {}).items())
                            if _NUM.match(str(v)))
                    _bvals = _fmt(_r.get('baseline_vals'))
                    _rvals = _fmt(_r.get('ref_vals'))
                    print(f'\n  Offset 0x{_off:x} ({_r["var"]}, '
                          f'{_r["width"]}B, original=0x{_r["original"]:x}):')
                    print(f'    baseline target: outcome='
                          f'{_r["baseline_outcome"]}, {_bvals}')
                    if _r.get('ref_outcome') is not None or _rvals:
                        print(f'    reference:       outcome='
                              f'{_r["ref_outcome"]}, {_rvals}')
                    if _flips:
                        print(f'    fork-outcome-flipping values: '
                              + ', '.join(f'0x{v:x}' for v in _flips[:12]))
                    if _vchg:
                        print(f'    fork-variable-value-changing values: '
                              + ', '.join(f'0x{v:x}' for v in _vchg[:12]))
                    if _crashes:
                        print(f'    crash-reproducing values: '
                              + ', '.join(f'0x{v:x}' for v in _crashes[:12]))
                    if not _flips and not _vchg and not _crashes:
                        print('    no tested value changes the fork '
                              'variables or reproduces the reference crash')
            else:
                print('  (no value-level results)')

    # 5b. Offsets found by the arithmetic backtrace (already probe-validated).
    arith_offsets = set()
    if arith_result:
        for _ch in (arith_result.get('chains') or {}).values():
            for _t in _ch.get('tag_offsets', []):
                arith_offsets.add(_t['file_offset'])
                _add_tier('B_arithmetic_tag', _t['file_offset'])
    if arith_offsets:
        arith_strs = ', '.join(f'0x{o:x}' for o in sorted(arith_offsets))
        print(f'  5b. Arithmetic-backtrace offsets (fork-controlling bytes): '
              f'{arith_strs}')
        print(f'      (validated by the Step 4.6 fork-flip probe; the full '
              f'255-value crash-reproduction sweep runs below)')

    # 6. Byte mutation crash testing — STAGE 1: the fork-variable-derived
    # offsets (and arithmetic-backtrace offsets).  Collect them now.
    stage1_offsets = set(mapped_offsets) | arith_offsets

    # IFD region offsets are mutated with DIRECTED values only: they are
    # structural (tag/type/count/offset) rather than value-driven, so the
    # full 255-value sweep per field would explode (N entries x 4 fields x
    # 255 runs).  Each field type gets the small meaning-bearing value set
    # from _ifd_field_probe_values (tag rewrites like 278->279, common
    # types, boundary counts, in-file offsets); the non-TIFF formats get
    # their kind-based set from _structure_probe_values.  Offsets already
    # covered by the fork-variable sweep (stage1) are skipped here.
    _ifd_field_offsets = [
        o for o in _ifd_fields
        if _structure_probe_values(_ifd_region, o) is not None]
    _ifd_probe_offsets = sorted(set(_ifd_field_offsets) - stage1_offsets)

    # End of the offset-localization phase (GDB tracing / mapping above);
    # what follows is the byte-mutation crash testing.
    stage_timing.record("locate input-file offsets for variables at the fork statement",
                        time.time() - _t_main_start)

    crash_results = {}
    any_match = False
    if stage1_offsets:
        crash_results, any_match = run_byte_mutation_stage(
            binary, binary_ref, input_file, program_args,
            sorted(stage1_offsets), a.timeout,
            title='Step 6: Byte mutation crash testing '
                  '(fork-variable offsets)',
            version=config.get('version_b'))

    # Mutation ordering (dynamic first, static last):
    #   Step 6   — single-byte sweep over the GDB-discovered fork-variable
    #              offsets (dynamic);
    #   Step 6b  — pairwise (two-offset) mutation over the dynamic offset
    #              pool only;
    #   Step 6a  — directed-value mutation of structure fields derived from
    #              the DYNAMIC fork-point context (e.g. the TIFF IFD region
    #              traced at the fork statement);
    #   Step 6e  — k-offset uniform combinations over the dynamic pool;
    #   Step 6f  — generic P0 extended mutation (dynamic offsets first);
    #   Step 6c  — full 255-value single-byte sweep over the STATIC
    #              format-parse offsets (ELF/GIF/XML/font headers, or the
    #              TIFF IFD when no dynamic fork context exists);
    #   Step 6d  — pairwise over the static offsets (last fallback).
    def _directed_structural_stage(_probe_offsets, _step_label):
        """Directed-meaning-value mutation of structural fields.

        Each field is tested only with its meaning-bearing value set (e.g.
        a tag rewrite like RowsPerStrip 278 -> StripByteCounts 279 at 0xDC)
        rather than a full 255-value sweep.  Returns (results, matched)."""
        _results = {}
        _matched = False
        if not (_probe_offsets and binary and binary_ref and input_file
                and os.path.isfile(input_file)):
            return _results, _matched
        _probe_map = {o: _structure_probe_values(_ifd_region, o)
                      for o in _probe_offsets}
        _probe_map = {o: v for o, v in _probe_map.items() if v}
        if not _probe_map:
            return _results, _matched
        _all_probes = sorted({v for vals in _probe_map.values()
                              for v in vals})
        _offs = sorted(_probe_map)
        _is_tiff_region = (_ifd_region.get('format') or 'tiff') == 'tiff'
        _struct_title = ('IFD-region' if _is_tiff_region
                         else (_ifd_region.get('label') or 'structure'))
        _struct_field = 'IFD-field' if _is_tiff_region else 'structure-field'
        print(f'\n{"="*60}')
        print(f'  {_step_label}: Directed {_struct_title} mutation '
              f'({len(_offs)} structural fields, '
              f'{len(_all_probes)} directed values)')
        print(f'{"="*60}')
        try:
            _results = test_byte_mutations_compare(
                binary, binary_ref, input_file, program_args,
                _offs, timeout=a.timeout,
                probe_values=_all_probes,
                version=config.get('version_b'))
            for offset, info in sorted(
                    (k, v) for k, v in _results.items()
                    if isinstance(k, int)):
                if info.get('matches'):
                    _matched = True
                    print(f'\n  Offset 0x{offset:x} '
                          f'(original=0x{info["original"]:02x}):')
                    for byte_val, m in sorted(info['matches'].items()):
                        print(f'    0x{byte_val:02x} -> {m}')
            if not _matched:
                print(f'\n  No directed {_struct_field} value reproduces the '
                      f'reference crash')
        except Exception as _e:
            print(f'  [!] {_step_label} mutation failed: {_e}')
        return _results, _matched

    print("\n" + "=" * 60)
    print("  Mutation order (dynamic first, static last)")
    print("=" * 60)
    print("  1. single-byte over dynamic origin/fork offsets (above)")
    print("  2. pairwise over the dynamic offset pool (Step 6b)")
    print("  3. directed structural fields from dynamic context (Step 6a)")
    print("  4. k-offset uniform combinations, dynamic pool (Step 6e)")
    print("  5. P0 generic extended mutation, dynamic offsets first (Step 6f)")
    print("  6. static-analysis offsets, single then pairwise (Steps 6c/6d)")
    # Step 6b: two-offset combined mutation — single-byte sweeps miss
    # interactions that need TWO bytes changed (e.g. the sign byte AND the
    # low byte of a corrupt sample-rate field).  The pool covers every
    # single-byte DYNAMIC candidate: the fork-variable stage-1 offsets
    # PLUS the dynamically traced offsets and their gate/inert
    # classification from --origin-mutation, so a gate discovered by one
    # sweep is always combinable with an inert byte discovered by another.
    # Static-format offsets are deliberately excluded — they belong to the
    # Steps 6c/6d fallback.
    pairwise_results = {}
    _active_offs, _inert_offs, _weak_offs, _value_hints = \
        _classify_sweep_results(crash_results, origin_results)
    _pair_pool = sorted(set(stage1_offsets) | set(_active_offs)
                        | _inert_offs | _weak_offs)
    _interaction_pairs = _build_interaction_pairs(
        _active_offs, _inert_offs | _weak_offs | set(_active_offs))
    if _active_offs:
        print(f'\n  Pairwise gates (behavior-changing single-byte offsets): '
              f'{", ".join(f"0x{o:x}" for o in sorted(_active_offs))}')
        print(f'  Pairwise inert pool: {len(_inert_offs)} offset(s); '
              f'interaction pairs: {len(_interaction_pairs)}')
    if len(_pair_pool) >= 2:
        _var_spans = {v: [h['offset'] for h in hits]
                      for v, hits in (var_offsets or {}).items()}
        pairwise_results = run_pairwise_mutation_stage(
            binary, binary_ref, input_file, program_args,
            _pair_pool, _var_spans, a.timeout,
            title='Step 6b: Two-offset combined byte mutation '
                  '(pairwise)',
            version=config.get('version_b'),
            interaction_pairs=_interaction_pairs,
            value_hints=_value_hints)
        for _pk, _pv in pairwise_results.items():
            if isinstance(_pv, dict) and _pv.get('matches'):
                any_match = True
                break

    ifd_crash_results = {}
    # Step 6a: dynamic-context structure fields (still "GDB-discovered").
    _dyn_probe_offsets = list(_ifd_probe_offsets) if _ifd_from_dynamic \
        else []
    ifd_crash_results, ifd_any_match = _directed_structural_stage(
        _dyn_probe_offsets, 'Step 6a')
    if ifd_any_match:
        any_match = True

    # Step 6c/6d: STATIC-analysis offsets — the on-disk structure fields
    # from the static format parse (ELF/GIF/XML/font headers, or the TIFF
    # IFD when no dynamic fork-point context exists).  Same treatment as
    # the dynamic phase — full 255-value single sweep, then pairwise — but
    # run only when every dynamic phase above failed to reproduce the
    # reference crash.
    static_crash_results = {}
    static_pairwise_results = {}
    _stat_offsets = [] if _ifd_from_dynamic \
        else sorted(set(_ifd_fields) - stage1_offsets)
    _combo_only = bool(_ifd_region.get('combo_only'))
    # Step 6e: automatic k-offset combination mutation (k = 3, 4, ...) over
    # the DYNAMICALLY discovered offset pool — runs only when the single-byte
    # and two-offset stages found nothing.  Combos are tested with a uniform
    # byte value across all offsets (marker/flag families), greedy-minimized
    # on a hit and archived.  The pool is DYNAMIC-only: STATIC structure
    # offsets are the last fallback and run in Steps 6c/6d after P0.
    multi_combo_results = {}
    _combo_pool = set(_pair_pool)
    if not any_match and len(_combo_pool) >= 3:
        print(f'\n{"="*60}')
        print(f'  Step 6e: Multi-offset combination mutation '
              f'(pool={len(_combo_pool)} offsets)')
        print(f'{"="*60}')
        multi_combo_results, _combo_match = \
            run_multi_offset_combination_stage(
                binary, binary_ref, input_file, program_args,
                _combo_pool, a.timeout, version=config.get('version_b'),
                single_results=crash_results, value_hints=_value_hints)
        if _combo_match:
            any_match = True

    # Step 6f: generic extended mutation (P0).  Runs only when every
    # existing stage failed to reproduce the reference crash.  The exact
    # dynamic offsets (fork variables / origin trace) are mutated first,
    # then their neighbourhood, the dynamic structure region, the static
    # offsets and finally global/havoc candidates.
    extended_results = {}
    if not any_match and a.extended_mutation:
        # Path A: fold in dynamic-origin offsets (incl. section fallback)
        # from the sibling *_origin.json when present.
        _origin_offs = set()
        if a.trace_json:
            _op = os.path.splitext(str(a.trace_json))[0] + '_origin.json'
            if not os.path.isfile(_op) and str(a.trace_json).endswith(
                    '.diverge.json'):
                _op = str(a.trace_json)[:-len('.diverge.json')] + \
                    '_origin.json'
            if os.path.isfile(_op):
                try:
                    with open(_op) as _of:
                        _od = json.load(_of) or {}
                    for _o in (_od.get('offsets') or []):
                        _off = _o.get('offset')
                        if _off is None:
                            continue
                        _ln = int(_o.get('length') or 1)
                        for _k in range(int(_off),
                                        int(_off) + max(1, _ln)):
                            _origin_offs.add(_k)
                    if _origin_offs and not any_match:
                        print('[*] origin offsets folded into Step 6f: %d '
                              'bytes (from %s)' % (len(_origin_offs),
                                                   os.path.basename(_op)))
                except Exception as _oe:
                    print('[!] origin offsets unreadable: %s' % _oe)
        _ext_primary = sorted(
            set(stage1_offsets)
            | {k for k in origin_results if isinstance(k, int)}
            | {int(k) for k in origin_results
               if isinstance(k, str) and k.isdigit()}
            | set(_active_offs)
            | _origin_offs)
        _t_ext = time.time()
        try:
            from extended_mutation import run_extended_mutation_stage
            extended_results, _ext_match = run_extended_mutation_stage(
                binary, binary_ref, input_file, program_args,
                _ext_primary,
                static_offsets=_stat_offsets,
                structure=_ifd_region,
                timeout=a.timeout,
                version=config.get('version_b'),
                max_candidates=a.extended_max_candidates,
                budget_seconds=a.extended_budget,
                per_candidate_timeout=a.extended_timeout or None,
                fork_file=fork_file,
                fork_line=fork_line,
                fork_func=(config.get('root_cause_function')
                           or config.get('poly_track_function')
                           or (config.get('dynamic_fork') or {}).get('function_b')
                           or None),
            )
            if _ext_match:
                any_match = True
            stage_timing.record('Step 6f extended mutation',
                                time.time() - _t_ext)
        except Exception as _e:
            print(f'  [!] Step 6f extended mutation failed: {_e}')

    # Static offsets are the last fallback: run only after every
    # dynamic stage (single, pairwise, combo, P0) failed.
    if not any_match and _stat_offsets and not _combo_only:
        static_crash_results, _stat_match = run_byte_mutation_stage(
            binary, binary_ref, input_file, program_args,
            _stat_offsets, a.timeout,
            title='Step 6c: Byte mutation crash testing '
                  '(static structure offsets)',
            version=config.get('version_b'))
        if _stat_match:
            any_match = True
    elif _stat_offsets and _combo_only:
        print(f'\n  Steps 6c/6d skipped: '
              f'{_ifd_region.get("label")} is combo-only '
              f'({len(_stat_offsets)} static field offsets are not '
              f'swept separately)')
    elif _stat_offsets:
        print(f'\n  Steps 6c/6d skipped: a dynamic offset already reproduces '
              f'the reference crash (static structure offsets not mutated)')
    elif not any_match:
        print('\n  Steps 6c/6d: no static-analysis offsets to mutate '
              '(static fallback empty)')
    if not any_match and len(_stat_offsets) >= 2 and not _combo_only:
        _s_active, _s_inert, _s_weak, _s_hints = \
            _classify_sweep_results(static_crash_results)
        _s_pool = sorted(set(_stat_offsets) | set(_s_active) | _s_inert | _s_weak)
        _s_pairs = _build_interaction_pairs(
            _s_active, _s_inert | _s_weak | set(_s_active))
        static_pairwise_results = run_pairwise_mutation_stage(
            binary, binary_ref, input_file, program_args,
            _s_pool, {}, a.timeout,
            title='Step 6d: Two-offset combined byte mutation '
                  '(static structure offsets)',
            version=config.get('version_b'),
            interaction_pairs=_s_pairs,
            value_hints=_s_hints)
        for _pk, _pv in static_pairwise_results.items():
            if isinstance(_pv, dict) and _pv.get('matches'):
                any_match = True
                break

    print(f'{"="*60}')

    # Save results
    output = {
        'binary_target': binary,
        'binary_ref': binary_ref,
        'fork_spec': fork_spec,
        'variables': variables,
        'differing_variables': differing_vars,
        'target_file_reads': positioned_b,
        'ref_file_reads': positioned_a,
        'chain_trace': chain_trace_results,
        'deep_trace': deep_results,
        'arithmetic_backtrace': arith_result,
        'variable_offsets': var_offsets,
        'candidate_tiers': candidate_tiers,
        'ifd_region': _ifd_region,
        'ifd_region_from_dynamic': _ifd_from_dynamic,
        'ifd_region_mutation': ifd_crash_results,
        'static_mutation_offsets': _stat_offsets,
        'static_crash_results': static_crash_results,
        'static_pairwise_results': static_pairwise_results,
        'mutation_offsets': sorted(stage1_offsets),
        'crash_results': crash_results,
        'pairwise_results': pairwise_results,
        'multi_combo_results': multi_combo_results,
        'extended_mutation_results': extended_results,
        'mutation_any_match': any_match,
    }
    out_path = os.path.join(os.path.dirname(input_file) if input_file else '.', 'fork_trace_result.json')
    with open(out_path, 'w') as f:
        json.dump(output, f, indent=2, default=str)
    print(f'\n  Results saved to: {out_path}')

    debug_log = '/tmp/trace_fork_debug.log'
    with open(debug_log, 'w') as f:
        f.write(log_text_b)
    print(f'[*] Raw GDB log: {debug_log}')

    # Every target version keeps a trace in out/: on success the directory
    # holds the crashing mutants; on zero matches an explicit marker is
    # written so the sweep can tell "processed, nothing found" apart from
    # "never ran".
    try:
        out_dir = _mutation_out_dir(input_file, config.get('version_b'))
        real_files = ([n for n in os.listdir(out_dir)
                       if not n.startswith('.')
                       and not n.startswith('NO_CRASH_MATCH')]
                      if os.path.isdir(out_dir) else [])
        if not any_match and not real_files:
            os.makedirs(out_dir, exist_ok=True)
            with open(os.path.join(out_dir, 'NO_CRASH_MATCH.txt'), 'w') as f:
                f.write('No mutation reproduced the reference crash.\n')
                f.write(f'input            : {input_file}\n')
                f.write(f'target version   : '
                        f'{config.get("version_b", "?")}\n')
                f.write(f'reference version: '
                        f'{config.get("version_a", "?")}\n')
                f.write(f'timestamp        : '
                        f'{time.strftime("%Y-%m-%d %H:%M:%S")}\n')
            print(f'[*] No matches; marker written: '
                  f'{os.path.join(out_dir, "NO_CRASH_MATCH.txt")}')
    except Exception as _e:
        print(f'[!] could not write no-match marker: {_e}')


if __name__ == '__main__':
    main()
