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
"""

import subprocess
import tempfile
import os
import re
import sys
import json
import struct
import argparse
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
    """Build an environment that loads the version's freshly built libtiff.

    The real ELF binary lives in tools/.libs and carries no RPATH; the libtool
    wrapper (tools/tiffcrop) normally exports LD_LIBRARY_PATH.  When invoking
    .libs/tiffcrop directly, point LD_LIBRARY_PATH at <root>/libtiff/.libs so
    the built libtiff (with its debug info) is loaded instead of the system
    one -- otherwise both versions silently run the system libtiff.
    """
    env = os.environ.copy()
    d = os.path.dirname(os.path.abspath(binary))
    for _ in range(6):
        cand = os.path.join(d, 'libtiff', '.libs')
        if os.path.isdir(cand):
            prev = env.get('LD_LIBRARY_PATH', '')
            env['LD_LIBRARY_PATH'] = cand + (':' + prev if prev else '')
            break
        parent = os.path.dirname(d)
        if parent == d:
            break
        d = parent
    return env


def extract_variables_from_statement(stmt):
    """Extract C variable expressions from a fork statement.

    Returns expressions evaluable in GDB (e.g., 'tif->tif_dir.td_stripoffset').
    """
    if not stmt:
        return []

    cleaned = re.sub(r'"[^"]*"', '', stmt)
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
        # Skip type names / typedefs (CamelCase identifiers like TIFFField).
        if re.match(r'^[A-Z]', root):
            continue
        # Skip function calls: identifier immediately followed by '('.
        if cleaned[m.end():].lstrip().startswith('('):
            continue
        seen.add(expr)
        result.append(expr)

    return result


def read_source_fork_statement(source_file, target_line, target_binary=None, search_range=30):
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
                    break
                # Also check tools subdir (for tiffcrop)
                candidate = parent / 'tools' / p.name
                if candidate.is_file():
                    p = candidate
                    break
                # Check if this is the version root
                if (parent / 'configure').exists() or (parent / '.build_ok').exists():
                    candidate = parent / 'libtiff' / p.name
                    if candidate.is_file():
                        p = candidate
                        break
                    candidate = parent / 'tools' / p.name
                    if candidate.is_file():
                        p = candidate
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
            start = i
    else:
        # Regular statement — use just this line (don't expand backward)
        start = target_line - 1

    # Find the end of the statement (look forward for break/return/next case)
    end = target_line
    depth = 0
    # Find the end of the statement
    if is_if_like:
        # Look forward for break/return/next case
        end = target_line
        depth = 0
        for i in range(target_line - 1, min(n, target_line + search_range)):
            stripped = lines[i].strip()
            if stripped.startswith('#if'):
                depth += 1
            elif stripped.startswith('#endif'):
                depth -= 1
            if depth == 0:
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
        # Data-dependent fork: read source for the full fork statement
        result = read_source_fork_statement(
            source_file, root_cause_line, target_binary=binary, search_range=100)
        if result:
            full_fork_stmt, variables, actual_line = result
            root_cause_line = actual_line
            print(f'  [*] Read full fork statement from source: {source_file}:{root_cause_line}')
            print(f'  [*] Extracted {len(variables)} variables from all branches')

    # Fallback: extract from the JSON's fork statement
    if not variables:
        if 'polytracker_offsets' in div:
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
        '_code_change': orig_is_code_change,
        'dynamic_fork': div.get('dynamic_fork'),
        'root_cause_statement_a': div.get('root_cause_statement_a', ''),
        'root_cause_statement_b': div.get('root_cause_statement_b', ''),
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
    printf "IO fd=%d offset=-1 size=%d\n", $rdi, $rdx
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
    """
    if not variables:
        return ''
    # Build a Python list of variable expressions for GDB Python
    var_list = ', '.join(f'"{v.replace(chr(34), chr(92)+chr(34))}"' for v in variables)
    return f"""  python
import gdb
_vars = [{var_list}]
for _v in _vars:
    try:
        _val = gdb.parse_and_eval(_v)
        _addr = int(_val.address) if _val.address else 0
        print("VAR_NAME %s" % _v)
        print("VAR_ADDR 0x%x" % _addr)
        print("VAR_VAL %d" % int(_val))
        print("VAR_SIZE %d" % _val.type.sizeof)
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
        script = GDB_SCRIPT.format(
            fork_spec=spec,
            var_dump=build_var_dump_block(variables),
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
                capture_output=True, text=True, timeout=timeout, env=env)
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

    Sets breakpoints at key functions and catches pread64 calls.
    The raw GDB output is returned for parsing.
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
            capture_output=True, text=True, timeout=timeout,
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
            capture_output=True, text=True, timeout=timeout, env=env)
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
            capture_output=True, text=True, timeout=timeout, env=env)
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
            capture_output=True, text=True, timeout=timeout, env=env)
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


def run_gdb_call_site_trace(binary, fork_spec, fork_func, input_file, program_args,
                            timeout=120):
    """Fully dynamic call-site argument back-tracing (no static analysis).

    For a fork variable that is a function parameter (e.g. ``tagid`` in
    ``TIFFReadDirectoryFindFieldInfo``), the value's true source is the
    *call-site actual argument*: ``dp->tdir_tag`` inside ``TIFFReadDirectory``,
    where ``dp`` iterates over the IFD buffer ``dir`` that was read from the
    file by a single ``pread64``.

    Chain (all resolved dynamically, no source parsing):

      pread64(buf=dir, offset=IFD_off)   <- IFD buffer read from the file
        -> dir                           <- buffer base (caller local)
        -> dp                            <- current IFD entry (caller local)
        -> dp->tdir_tag == tagid         <- actual argument at the call site
        -> file offset = IFD_off + (dp - dir)

    Two GDB runs:
      Phase A: hit the fork point on every invocation, record (tagid, mb,
               field_tag) for each; the program runs to completion.
      Phase B: for each distinct tagid, run again with a conditional breakpoint
               ``break <fork_func> if tagid == N`` plus ``catch syscall
               pread64``; on hit, read ``dp``/``dir`` from the caller frames
               and quit.

    Returns
      {'tag_mappings': {tagid: {file_offset, entry_index, dp, dir, ifd_offset,
                                tag_name}},
       'invocations': [...], 'pread64': [...]} or (None, error).
    """
    real_binary = resolve_binary(binary)
    run_parts = [a.replace('{input_file}', input_file).replace('{input}', input_file)
                 for a in program_args]
    run_args = ' '.join(run_parts)
    env = build_run_env(real_binary)

    # ------------------------------------------------------------------
    # Phase A: record every fork-point invocation
    # ------------------------------------------------------------------
    phase_a = f"""set pagination off
set confirm off
set breakpoint pending on

break {fork_spec}
commands
  silent
  printf "FORK_INV tagid=%u mb=%d field_tag=%u\\n", tagid, mb, tif->tif_fields[mb]->field_tag
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
            capture_output=True, text=True, timeout=timeout, env=env)
    except subprocess.TimeoutExpired:
        return None, 'timeout_phase_a'
    finally:
        try: os.unlink(script_file)
        except: pass

    out_a = proc.stdout + proc.stderr
    if 'FORK_INV' not in out_a:
        return None, 'fork_not_reached'

    invocations = []
    for line in out_a.splitlines():
        m = re.match(r'FORK_INV tagid=(\d+) mb=(-?\d+) field_tag=(-?\d+)', line.strip())
        if m:
            invocations.append({
                'tagid': int(m.group(1)),
                'mb': int(m.group(2)),
                'field_tag': int(m.group(3)),
            })
    if not invocations:
        return None, 'no_invocations'

    distinct_tagids = list(dict.fromkeys(v['tagid'] for v in invocations))

    # ------------------------------------------------------------------
    # Phase B: per-tagid conditional breakpoint at the fork-function entry
    # ------------------------------------------------------------------
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
                capture_output=True, text=True, timeout=timeout, env=env)
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

        # File offset of the IFD entry.  tif->tif_diroff points at the
        # directory count (2 bytes for classic TIFF); the entry array starts
        # 2 bytes later.  dp - dir is the byte offset of the entry in the
        # buffer; tdir_tag is the entry's first field.
        entry_off = None
        entry_index = None
        if (diroff is not None and dp_addr is not None and dir_addr is not None
                and dp_addr >= dir_addr):
            delta = dp_addr - dir_addr
            esz = entry_size if entry_size else 12
            entry_index = delta // esz
            entry_off = diroff + 2 + delta

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

    # Tag name lookup for the diverging invocation (last invocation's tagid)
    for tagid in tag_mappings:
        pass

    return {
        'tag_mappings': tag_mappings,
        'invocations': invocations,
        'pread64': pread64_all,
    }, None


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
            capture_output=True, text=True, timeout=30, env=env)
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
                capture_output=True, text=True, timeout=60, env=env)
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
            capture_output=True, text=True, timeout=timeout, env=env)
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
    """Parse raw GDB output from deep trace.

    Extracts:
    - Function breakpoints (which functions were called)
    - pread64 calls (offset and size)
    - Error messages (IO errors, etc.)
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


# ---------------------------------------------------------------------------
# Parse GDB output
# ---------------------------------------------------------------------------

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
            m = re.match(r'IO fd=(\d+) offset=(-?\d+) size=(\d+)', line)
            if m:
                fd = int(m.group(1))
                offset = int(m.group(2))
                size = int(m.group(3))
                file_reads.append({'fd': fd, 'offset': offset, 'size': size})
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
# Byte mutation crash testing
# ---------------------------------------------------------------------------

_ASAN_ERR_RE = re.compile(r'ERROR:\s*AddressSanitizer:\s*([a-z-]+)')
# ASan backtrace frames: "#N 0x... in <func> <file>:<line>"
_ASAN_FRAME_RE = re.compile(
    r'#(\d+)\s+0x[0-9a-fA-F]+\s+in\s+(.+?)\s+(\S+?):(\d+)\s*$')
# ASan SUMMARY: "SUMMARY: AddressSanitizer: <kind> <file>:<line> in <func>"
_ASAN_SUMMARY_RE = re.compile(
    r'SUMMARY:\s*AddressSanitizer:\s*\S+\s+(\S+?):(\d+)\s+in\s+(.+?)\s*$', re.M)
_SANITIZER_FRAME_RE = re.compile(
    r'__interceptor_|__asan_|__sanitizer_|__ubsan_|__tsan_|^libc|sanitizer|/csu/')


def _path_basename(p):
    """Basename of a frame file path (``/build/tiffcrop.c`` -> ``tiffcrop.c``)."""
    if not p:
        return None
    return os.path.basename(str(p)) or str(p)


def _is_sanitizer_frame(frame):
    fn = (frame.get("function") or "")
    fl = (frame.get("file") or "")
    return bool(_SANITIZER_FRAME_RE.search(fn)) or \
        bool(_SANITIZER_FRAME_RE.search(fl))


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


def compare_crash_signatures(ref_sig, tgt_sig):
    """Classify how close a target crash is to the reference crash.

    Returns one of:
      * 'same_site' — type, function, file AND line all match (identical
                      crash point; requires identical/mapped code lines),
      * 'same_func' — type + crash function match (line/file may differ
                      between versions), this is the level used as "success",
      * 'same_type' — only the ASan error type matches,
      * None        — different types (a genuinely different crash).
    Also returns a human-readable diff line for reporting.
    """
    if ref_sig is None or tgt_sig is None:
        return None, "no crash signature to compare"
    if ref_sig["type"] != tgt_sig["type"]:
        return None, (f"type differs: ref={ref_sig['type']} "
                      f"target={tgt_sig['type']}")
    rf = ref_sig["crash_frames"][0] if ref_sig["crash_frames"] else {}
    tf = tgt_sig["crash_frames"][0] if tgt_sig["crash_frames"] else {}
    rfunc, tfunc = rf.get("function"), tf.get("function")
    if not rfunc or not tfunc:
        return "same_type", "type matches; no function info to compare"
    if rfunc != tfunc:
        return "same_type", (f"type matches but crash function differs: "
                             f"ref={rfunc} target={tfunc}")
    rfile = _path_basename(rf.get("file"))
    tfile = _path_basename(tf.get("file"))
    if rfile == tfile and rf.get("line") == tf.get("line"):
        return "same_site", (f"identical crash site: {rfunc} at "
                             f"{rfile}:{rf.get('line')}")
    return "same_func", (f"same crash function {rfunc} "
                         f"(ref {rfile}:{rf.get('line')} vs "
                         f"target {tfile}:{tf.get('line')})")


def test_byte_mutations_compare(binary_target, binary_ref, input_file,
                                program_args, offsets, timeout=10):
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
    """
    real_target = resolve_binary(binary_target)
    real_ref = resolve_binary(binary_ref)
    if not (real_target and real_ref
            and os.path.isfile(real_target) and os.path.isfile(real_ref)):
        print(f'  [!] Binary not found: target={binary_target} ref={binary_ref}')
        return {}

    with open(input_file, 'rb') as f:
        original_data = bytearray(f.read())

    def _run(binary, data):
        fd, tmp_path = tempfile.mkstemp(suffix='.tif', prefix='mutate_')
        os.close(fd)
        try:
            with open(tmp_path, 'wb') as f:
                f.write(data)
            cmd = [binary] + [a.replace('{input_file}', tmp_path).replace('{input}', tmp_path)
                              if '{' in a else (tmp_path if a == input_file else a)
                              for a in program_args]
            env = build_run_env(binary)
            proc = subprocess.run(cmd, capture_output=True, text=True,
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
    ref_crash = ref_sig["crash_frames"][0] if ref_sig["crash_frames"] else {}
    print(f'  Reference crash: {ref_sig["type"]} in '
          f'{ref_crash.get("function")} '
          f'({_path_basename(ref_crash.get("file"))}:'
          f'{ref_crash.get("line")}, rc={ref_rc})')

    results = {
        'ref_signature': {
            'type': ref_sig['type'],
            'crash_frame': {k: ref_crash.get(k)
                            for k in ('function', 'file', 'line')},
            'summary': ref_sig['summary'],
        },
    }
    observed = {}      # verdict -> count across all mutations
    total_tests = 0
    for offset in sorted(offsets):
        if offset >= len(original_data):
            print(f'  [!] Offset 0x{offset:x} beyond file size, skipping')
            continue
        orig_byte = original_data[offset]
        results[offset] = {'original': orig_byte, 'matches': {}}
        print(f'\n  [*] Testing offset 0x{offset:x} (original=0x{orig_byte:02x})...')

        for byte_val in range(256):
            if byte_val == orig_byte:
                continue
            modified = bytearray(original_data)
            modified[offset] = byte_val
            out, rc = _run(real_target, modified)
            total_tests += 1
            sig = extract_crash_signature(out)
            if sig is None:
                continue
            verdict, diff = compare_crash_signatures(ref_sig, sig)
            crash = sig["crash_frames"][0] if sig["crash_frames"] else {}
            # ``same_func`` or better = the target reproduces the reference
            # crash; ``same_type`` only = a same-kind crash at another site.
            if verdict in ('same_func', 'same_site'):
                results[offset]['matches'][byte_val] = {
                    'verdict': verdict,
                    'type': sig['type'],
                    'function': crash.get('function'),
                    'file': _path_basename(crash.get('file')),
                    'line': crash.get('line'),
                    'rc': rc,
                }
                print(f'    0x{byte_val:02x} -> MATCHES ref crash '
                      f'({verdict}: {diff})')
            else:
                observed.setdefault(verdict or 'no_crash', 0)
                observed[verdict or 'no_crash'] += 1
                if verdict == 'same_type':
                    # Near-miss: same ASan kind but a different crash site —
                    # valuable signal that the mutation steers the path but
                    # not (yet) to the reference's site.
                    observed.setdefault('same_type_sites', {})
                    sites = observed['same_type_sites']
                    key = f"{crash.get('function')}:{_path_basename(crash.get('file'))}:{crash.get('line')}"
                    sites.setdefault(key, 0)
                    sites[key] += 1

        n = len(results[offset]['matches'])
        verdicts = {}
        for v in results[offset]['matches'].values():
            verdicts[v['verdict']] = verdicts.get(v['verdict'], 0) + 1
        print(f'    => {n} matching value(s) (target reproduces ref crash) '
              f'{verdicts}')

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
    ap.add_argument('--test-offsets', nargs='*', help='additional hex offsets for byte mutation testing (e.g. 0xe8 0xec 0xf0)')
    ap.add_argument('--args', nargs=argparse.REMAINDER, default=[],
                    help='program args (must be last)')

    a = ap.parse_args()

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
    if not config.get('dynamic_fork'):
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

    tiff_tags = None
    tiff_tags_all = None
    if input_file and os.path.isfile(input_file):
        try:
            tags = parse_tiff_ifd(input_file)
            if tags:
                tiff_tags = analyze_tiff_tags(tags)
                tiff_tags_all = analyze_tiff_tags_all(tags)
                print(f'[*] TIFF tags found: {list(tiff_tags.keys())}')
        except Exception as e:
            print(f'[*] File parse skipped: {e}')

    # Find the correct fork line for each version
    fork_spec_b = fork_spec  # Target version (tiff-4.0.8) - uses line from read_source_fork_statement
    ref_fork_file = config.get('ref_fork_file') or fork_file
    fork_spec_a = f'{ref_fork_file}:{original_fork_line}'  # Reference version - its own file & line

    print(f'[*] Target fork spec: {fork_spec_b}')
    if binary_ref:
        print(f'[*] Reference fork spec: {fork_spec_a}')

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
    deep_results = {}
    if differing_vars:
        print(f'\n{"="*60}')
        print(f'  Step 3.5: Deep trace into TIFFOpen internals')
        print(f'{"="*60}')

        file_size = os.path.getsize(input_file) if input_file and os.path.isfile(input_file) else 0

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

            # Parse the IFD to find the corrupted tag that causes the divergence
            if input_file and os.path.isfile(input_file):
                with open(input_file, 'rb') as f:
                    file_data = f.read()
                # TIFF header: bytes 4-7 = IFD offset
                if len(file_data) >= 8:
                    ifd_off = int.from_bytes(file_data[4:8], 'little')
                    if ifd_off + 2 <= len(file_data):
                        n_entries = int.from_bytes(file_data[ifd_off:ifd_off+2], 'little')
                        pos = ifd_off + 2
                        tag_names = {279: 'StripByteCounts', 273: 'StripOffsets',
                                     256: 'ImageWidth', 257: 'ImageLength',
                                     258: 'BitsPerSample', 262: 'PhotometricInterpretation'}
                        for i in range(n_entries):
                            if pos + 12 > len(file_data):
                                break
                            tag = int.from_bytes(file_data[pos:pos+2], 'little')
                            typ = int.from_bytes(file_data[pos+2:pos+4], 'little')
                            cnt = int.from_bytes(file_data[pos+4:pos+8], 'little')
                            val = int.from_bytes(file_data[pos+8:pos+12], 'little')
                            tname = tag_names.get(tag, f'Tag_{tag}')

                            # Check if this tag has suspicious values
                            if tag == 279:  # StripByteCounts
                                print(f'\n  [*] Divergence-causing IFD entry at file offset 0x{pos:x}:')
                                print(f'      tag=279 ({tname}) type={typ} count={cnt} value/offset={val}')
                                print(f'      bytes: {file_data[pos:pos+12].hex()}')
                                if cnt > 100:
                                    print(f'      ^^^ count={cnt} is suspiciously large for a single-strip image')
                                    print(f'      This causes tiff-4.0.8 to attempt reading {cnt}*{4}={cnt*4} bytes')
                                    print(f'      resulting in IO error → TIFFOpen returns NULL')
                                    print(f'      tiff-4.4.0 detects bogus count, ignores it → TIFFOpen returns valid pointer')
                            pos += 12

    # ================================================================
    # Step 4: Trace file I/O and map to input file
    # ================================================================
    print(f'\n{"="*60}')
    print(f'  Step 4: Trace file I/O → input file offsets')
    print(f'{"="*60}')

    result = analyze_offsets(parsed_b, input_file, variables, tiff_tags, tiff_tags_all,
                             fork_file=fork_file, fork_line=fork_line, binary=binary,
                             file_reads=parsed_b.get('file_reads', []))

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
        print(f'\n  Target version (tiff-4.0.8) pread64 calls:')
        if positioned_b:
            for r in positioned_b:
                beyond = ' ** BEYOND FILE **' if r['offset'] >= file_size else ''
                print(f'    offset=0x{r["offset"]:04x} ({r["offset"]})  size={r["size"]}  [{r["offset"]:04x}-{r["offset"]+r["size"]:04x}){beyond}')
        else:
            print(f'    (no pread64 calls captured)')

        # Show reference version I/O
        if positioned_a:
            print(f'\n  Reference version (tiff-4.4.0) pread64 calls:')
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
                    print(f'    Only in target (tiff-4.0.8):')
                    for off, sz in sorted(only_target):
                        print(f'      offset=0x{off:04x} size={sz}')
                if only_ref:
                    print(f'    Only in reference (tiff-4.4.0):')
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
                print(f'      This read accesses invalid data, causing TIFFOpen to return NULL')
            else:
                print(f'    offset=0x{offset:04x} size={size} -- within file boundary')

    # ================================================================
    # Step 4.5: GDB call-site argument trace (fully dynamic)
    # ================================================================
    chain_trace_results = {}
    if binary and fork_spec and input_file:
        print(f'\n{"="*60}')
        print(f'  Step 4.5: GDB call-site argument trace (fully dynamic)')
        print(f'{"="*60}')

        # Fully dynamic: chain pread64(IFD buffer) -> dir -> dp -> dp->tdir_tag
        fork_func_name = 'TIFFReadDirectoryFindFieldInfo'
        cs_result, err = run_gdb_call_site_trace(
            binary, fork_spec, fork_func_name, input_file, program_args,
            timeout=a.timeout * 2)

        if err:
            print(f'  [!] Call-site trace failed: {err}')
        elif cs_result:
            chain_trace_results = cs_result
            mappings = cs_result.get('tag_mappings', {})
            invocations = cs_result.get('invocations', [])

            if invocations:
                print(f'  [*] Fork-point invocations ({len(invocations)}):')
                shown = invocations[:3]
                for inv in shown:
                    print(f'      tagid={inv["tagid"]} mb={inv["mb"]} '
                          f'field_tag={inv["field_tag"]}')
                if len(invocations) > 3:
                    print(f'      ... (+{len(invocations)-3} more)')

            print(f'\n  [*] Call-site actual arguments (dp->tdir_tag) -> file offsets:')
            if not mappings:
                print(f'      (no call-site mapping captured)')
            for tagid, info in mappings.items():
                name = info.get('tag_name', f'tag_{tagid}')
                if info.get('file_offset') is not None:
                    print(f'      tagid={tagid} ({name}):')
                    print(f'        dp={info["dp"]}  dir={info["dir"]}')
                    print(f'        IFD buffer read at file offset '
                          f'0x{info["ifd_offset"]:x}')
                    print(f'        entry index {info["entry_index"]} '
                          f'-> tdir_tag at file offset '
                          f'0x{info["file_offset"]:x}')
                else:
                    print(f'      tagid={tagid} ({name}): no IFD buffer match')

    # ================================================================
    # Step 5: Variable → file offset mapping
    # ================================================================
    print(f'\n{"="*60}')
    print(f'  Step 5: Variable → input file offset mapping')
    print(f'{"="*60}')

    print(f'\n  Variable → file offset mapping:')
    for name, info in result.get('variables', {}).items():
        direct = info.get('direct_offsets', [])
        src = info['source']
        print(f'    {name}:')
        print(f'      address={info["address"]}  value={info["value"]}  size={info["size"]}')
        print(f'      value source: {src}')
        if direct:
            print(f'      file offsets (modify to change value): {format_offsets(direct)}')
        else:
            print(f'      file offsets: (not from input file)')

    # Show call-site trace results if available (fully dynamic mapping)
    if chain_trace_results and chain_trace_results.get('tag_mappings'):
        print(f'\n  GDB call-site trace summary (dynamic):')
        invocations = chain_trace_results.get('invocations', [])
        for tagid, info in chain_trace_results['tag_mappings'].items():
            name = info.get('tag_name', f'tag_{tagid}')
            if info.get('file_offset') is not None:
                print(f'    tagid={tagid} ({name})')
                print(f'      ← dp->tdir_tag (IFD entry '
                      f'#{info["entry_index"]}) at file offset '
                      f'0x{info["file_offset"]:x}')
                print(f'      ← IFD buffer read by pread64 at '
                      f'0x{info["ifd_offset"]:x} (buf={info["dir"]})')
            else:
                print(f'    tagid={tagid} ({name}): no file mapping')

    # ================================================================
    # Summary — dynamic, based on analysis results
    # ================================================================
    print(f'\n{"="*60}')
    print(f'  SUMMARY')
    print(f'{"="*60}')

    fork_stmt_text = config.get('fork_stmt', fork_spec)
    in_val_target = result.get('variables', {}).get('in', {}).get('value', None)
    in_val_ref = deep_results.get('variables', {}).get('in', {}).get('value', None) if deep_results else None
    target_returns_null = (in_val_target == 0)

    # 1. Fork point
    # Truncate multi-line fork statement to the key line (e.g., "if (in == NULL)")
    short_fork = fork_stmt_text.strip()
    for line in short_fork.splitlines():
        stripped = line.strip()
        if 'if (' in stripped or 'else if (' in stripped:
            short_fork = stripped
            break

    if target_returns_null:
        print(f'  1. Fork point: {short_fork} — where execution diverges')
        print(f'  2. in = TIFFOpen(argv[optind], "r") — returns NULL in target, valid ptr in reference')
    else:
        print(f'  1. Fork point: {short_fork}')
        if in_val_target is not None and in_val_ref is not None:
            print(f'  2. in: target=0x{in_val_target:x} ref=0x{in_val_ref:x}')
        elif in_val_target is not None:
            print(f'  2. in: target=0x{in_val_target:x} ref=N/A')

    # 3. Deep trace comparison (errors and function calls)
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

    # 5. Input file offsets to modify
    in_offsets = result.get('variables', {}).get('in', {}).get('direct_offsets', [])
    if in_offsets and target_returns_null:
        offset_strs = [f'0x{o:x}' for o in in_offsets]
        print(f'  5. To eliminate the fork, modify bytes at input file offsets: {", ".join(offset_strs)}')
        print(f'     These offsets determine the return value of TIFFOpen()')

    # 6. Byte mutation crash testing
    # Collect offsets from variable mapping
    all_offsets = set()
    for vname, vinfo in result.get('variables', {}).items():
        for off in vinfo.get('direct_offsets', []):
            all_offsets.add(off)

    # Also include user-specified offsets
    if a.test_offsets:
        for h in a.test_offsets:
            all_offsets.add(int(h, 16))

    if all_offsets and input_file and os.path.isfile(input_file) and binary:
        print(f'\n{"="*60}')
        print(f'  Step 6: Byte mutation crash testing')
        print(f'{"="*60}')
        print(f'  Input file: {input_file}')
        print(f'  Target binary: {resolve_binary(binary)}')
        print(f'  Reference binary: {resolve_binary(binary_ref)}')
        print(f'  Offsets to test: {", ".join(f"0x{o:x}" for o in sorted(all_offsets))}')
        print(f'  Total mutations per offset: 255 (all byte values except original)')

        crash_results = test_byte_mutations_compare(
            binary, binary_ref, input_file, program_args,
            sorted(all_offsets), timeout=a.timeout)

        # Print match summary
        any_match = False
        for offset, info in sorted(crash_results.items()):
            if info['matches']:
                if not any_match:
                    print(f'\n  {"="*60}')
                    print(f'  MATCH SUMMARY (target reproduces reference crash)')
                    print(f'  {"="*60}')
                    any_match = True
                print(f'\n  Offset 0x{offset:x} (original=0x{info["original"]:02x}):')
                for byte_val, m in sorted(info['matches'].items()):
                    print(f'    0x{byte_val:02x} -> {m}')

        if not any_match:
            print(f'\n  No byte value reproduces the reference crash')

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
        'variable_mapping': result.get('variables', {}),
        'chain_trace': chain_trace_results,
    }
    out_path = os.path.join(os.path.dirname(input_file) if input_file else '.', 'fork_trace_result.json')
    with open(out_path, 'w') as f:
        json.dump(output, f, indent=2, default=str)
    print(f'\n  Results saved to: {out_path}')

    debug_log = '/tmp/trace_fork_debug.log'
    with open(debug_log, 'w') as f:
        f.write(log_text_b)
    print(f'[*] Raw GDB log: {debug_log}')


if __name__ == '__main__':
    main()
