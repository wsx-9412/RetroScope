#!/usr/bin/env python3
"""extended_mutation.py - generic P0 extended mutation stage (Step 6f).

This stage runs only after every existing mutation stage (Step 6 / 6a-6e)
failed to make the target reproduce the reference crash.  Its operators are
format-agnostic: they need byte offsets plus (optionally) the record layout
metadata already produced by the dynamic/static structure parsers.

Operators
---------
* multi-byte integer overwrite (2/4/8 bytes, endian-aware, boundary values)
* arithmetic mutation (+/- deltas) on 2/4-byte integers
* block insert / delete / duplicate / move / truncate / append
* dictionary/token insertion
* record insert / delete / duplicate (when a record layout is available)
* havoc (random combinations of the above) and crossover
* feedback search: a candidate that changes the target's behaviour (new
  error message / exit code / crash) becomes a seed for the next round

Offset priority
---------------
1. dynamic offsets from the fork-variable / origin trace (exact bytes)
2. their neighbourhood (the containing record and nearby fields)
3. the dynamically derived structure region
4. static structure offsets
5. global / havoc

The module reuses the worker, crash-signature extractor/comparator and
artifact helpers from trace_fork_offsets.py through a lazy import, so it can
be imported by that module without a circular import at load time.
"""

import hashlib
import os
import random
import re
import subprocess
import tempfile
import time
from concurrent.futures import ProcessPoolExecutor, as_completed

# Boundary values for multi-byte overwrites.  Small integers come first so
# that a tight candidate budget still covers tag/type/count-like fields.
_MB_VALUES = {
    2: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
        20, 24, 32, 48, 64, 96, 128, 192, 256, 384, 512, 768, 1024,
        2048, 4096, 0x7fff, 0x8000, 0xffff],
    4: [0, 1, 2, 3, 4, 5, 8, 16, 32, 64, 128, 256, 512, 1024, 2048,
        4096, 0x1000, 0x10000, 0x100000, 0x7fffffff, 0x80000000,
        0xffffffff],
    8: [0, 1, 0xffffffff, 0x7fffffff, 0xffffffffffffffff,
        0x7fffffffffffffff],
}

_ARITH_DELTAS = {
    2: [1, 2, 3, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048,
        0x7fff, 0x8000, 0xffff],
    4: [1, 2, 3, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 0x1000,
        0x10000, 0x7fffffff],
}

_TOKENS = [
    b'\x00', b'\xff', b'\x7f', b'\x80',
    b'II*\x00', b'MM\x00*', b'\x7fELF', b'GIF89a', b'PK\x03\x04',
    b'%PDF-', b'<', b'\n', b'\x00\x01\x00\x00', b'\xff\xff\xff\xff',
]

_BLOCK_SIZES = [1, 2, 4, 8, 12, 16, 24, 32, 64]


def _cand(op, detail, data, offsets, desc=''):
    return {'op': op, 'detail': detail, 'data': data,
            'offsets': list(offsets or []), 'desc': desc}


def _guess_endian(data):
    if len(data) >= 6:
        if data[:2] == b'II':
            return '<'
        if data[:2] == b'MM':
            return '>'
        if data[:4] == b'\x7fELF':
            return '<' if data[5] == 1 else '>'
    return '<'


def _as_offset(value):
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return value if isinstance(value, int) else None


def _dedupe(offsets, limit=None):
    seen = set()
    out = []
    for raw in offsets or []:
        off = _as_offset(raw)
        if off is None or off < 0 or off in seen:
            continue
        seen.add(off)
        out.append(off)
        if limit is not None and len(out) >= limit:
            break
    return out


def _mb_values(size, file_size):
    vals = list(_MB_VALUES.get(size) or [])
    for v in (file_size, file_size - 1, file_size + 1):
        if 0 <= v < (1 << (8 * size)) and v not in vals:
            vals.append(v)
    return vals


# Prioritised single-byte values: common sentinel/boundary bytes first so a
# tight phase cap still reaches high-value pokes (e.g. 0x15) at early offsets.
_BYTE_PRIORITY = (
    0x00, 0x01, 0x15, 0xff, 0x10, 0x20, 0x40, 0x80, 0x7f, 0xfe,
    0x02, 0x03, 0x04, 0x08, 0x0f, 0x30, 0x60, 0xc0, 0xaa, 0x55,
)


def _byte_candidates(data, offsets, values=None):
    """Single-byte overwrite sweep at ``offsets``.

    Multi-byte mb/arith operators miss pokes that only change one byte of a
    wider field (e.g. low byte of a 2-byte tag).  Priority values are tried
    at every offset first so a tight phase cap still reaches high-value
    bytes (e.g. 0x15) across the whole offset set; remaining values follow.
    """
    n = len(data)
    offs = _dedupe(offsets)
    if values is None:
        pri = list(_BYTE_PRIORITY)
        rest = [v for v in range(256) if v not in set(pri)]
        blocks = [pri, rest]
    else:
        blocks = [list(values)]
    for block in blocks:
        for v in block:
            for off in offs:
                if off < 0 or off >= n:
                    continue
                if v == data[off]:
                    continue
                new = bytearray(data)
                new[off] = v & 0xff
                yield _cand('byte', f'b@{off:#x}={v:#x}',
                            bytes(new), [off])


def _field_size(structure, offset):
    """Best-effort field width for an offset.

    The static parsers already attach ``size`` to their fields; the record
    fallback handles the common 12-byte (tag2/type2/count4/value4) layout
    used by TIFF IFDs and similar record arrays.
    """
    for f in (structure or {}).get('fields') or []:
        if f.get('offset') == offset and f.get('size'):
            try:
                return int(f['size'])
            except (TypeError, ValueError):
                pass
    es = (structure or {}).get('entry_size')
    base = (structure or {}).get('entries_base')
    if es == 12 and base is not None:
        rel = (offset - base) % 12
        return 2 if rel in (0, 1, 2, 3) else 4
    return 4


def _record_index(structure, offset):
    es = int((structure or {}).get('entry_size') or 0)
    base = (structure or {}).get('entries_base')
    count = (structure or {}).get('count')
    if not es or base is None or count is None:
        return None
    if offset < base:
        return None
    idx = (offset - base) // es
    return idx if 0 <= idx < int(count) else None


def _neighbourhood(primary, structure, radius=64):
    """Priority-ordered offsets around the dynamic offsets.

    Order: field starts of the containing record (tag/type/count/value),
    the primary offsets and small deltas, the remaining bytes of the
    record, then nearby structure fields.  Kept as a list (not a set) so
    the candidate budget reaches the semantic fields first.
    """
    ordered = []
    seen = set()

    def _add(offset):
        if offset is not None and offset >= 0 and offset not in seen:
            seen.add(offset)
            ordered.append(offset)

    primary = _dedupe(primary)
    field_offsets = _dedupe((structure or {}).get('field_offsets'))
    for off in primary:
        idx = _record_index(structure, off)
        if idx is None:
            continue
        es = int(structure['entry_size'])
        base = int(structure['entries_base'])
        start, end = base + idx * es, base + (idx + 1) * es
        for f in field_offsets:
            if start <= f < end:
                _add(f)
    for off in primary:
        _add(off)
    for delta in (1, 2, 3, 4, 8, 12, 16, 32, 64):
        for off in primary:
            _add(off - delta)
            _add(off + delta)
    for off in primary:
        idx = _record_index(structure, off)
        if idx is None:
            continue
        es = int(structure['entry_size'])
        base = int(structure['entries_base'])
        for k in range(base + idx * es, base + (idx + 1) * es):
            _add(k)
    for field_off in field_offsets:
        if any(abs(field_off - off) <= radius for off in primary):
            _add(field_off)
    return ordered


def _mb_candidates(data, offsets, endian, structure, sizes=None):
    """Multi-byte overwrite + arithmetic candidates.

    ``sizes='native'`` uses only the inferred field width (best for a tight
    budget: tag/type are 2 bytes, count/value 4 bytes); ``sizes=None``
    tries every width at every offset.
    """
    n = len(data)
    for off in offsets:
        if off < 0 or off >= n:
            continue
        native = _field_size(structure, off)
        if sizes == 'native':
            value_sizes = [native]
        elif sizes is None:
            value_sizes = [native] + [s for s in (4, 2, 8) if s != native]
        else:
            value_sizes = [s for s in sizes if s in (2, 4, 8)]
        for size in value_sizes:
            if off + size > n:
                continue
            for value in _mb_values(size, n):
                if value < 0 or value >= (1 << (8 * size)):
                    continue
                raw = value.to_bytes(
                    size, 'little' if endian == '<' else 'big')
                if data[off:off + size] == raw:
                    continue
                new = bytearray(data)
                new[off:off + size] = raw
                yield _cand('mb', f'mb{size}@{off:#x}={value:#x}',
                            bytes(new), [off])
        for size in [s for s in value_sizes if s in (2, 4)]:
            if off + size > n:
                continue
            cur = int.from_bytes(
                data[off:off + size], 'little' if endian == '<' else 'big')
            for delta in _ARITH_DELTAS.get(size, []):
                for sign in (1, -1):
                    value = (cur + sign * delta) & ((1 << (8 * size)) - 1)
                    if value == cur:
                        continue
                    raw = value.to_bytes(
                        size, 'little' if endian == '<' else 'big')
                    new = bytearray(data)
                    new[off:off + size] = raw
                    yield _cand(
                        'arith',
                        f'ar{size}@{off:#x}{"+" if sign > 0 else "-"}'
                        f'{delta:#x}', bytes(new), [off])


def _block_candidates(data, offsets, anchors, max_span=8 * 1024 * 1024):
    n = len(data)
    positions = _dedupe(list(offsets) + list(anchors))
    for pos in positions[:24]:
        if not (0 <= pos <= n):
            continue
        for size in _BLOCK_SIZES:
            for pattern in (0x00, 0xff, 0x41, 0x80):
                if len(data) + size > max_span:
                    continue
                block = bytes([pattern]) * size
                new = data[:pos] + block + data[pos:]
                yield _cand('ins', f'ins{size}@{pos:#x}', new, [pos])
    for pos in positions[:24]:
        for size in _BLOCK_SIZES:
            if not (0 <= pos and pos + size <= n):
                continue
            new = data[:pos] + data[pos + size:]
            yield _cand('del', f'del{size}@{pos:#x}', new, [pos])
    for pos in positions[:16]:
        for size in (4, 8, 12, 16, 32, 64):
            if not (0 <= pos and pos + size <= n):
                continue
            block = data[pos:pos + size]
            new = data[:pos] + block + data[pos:]
            yield _cand('dup', f'dup{size}@{pos:#x}', new, [pos])
    for pos in positions[:8]:
        for size in (4, 8, 12, 16):
            if not (0 <= pos and pos + size <= n):
                continue
            block = data[pos:pos + size]
            rest = data[:pos] + data[pos + size:]
            for dst in positions[:8]:
                if not (0 <= dst <= len(rest)):
                    continue
                if dst == pos:
                    continue
                new = rest[:dst] + block + rest[dst:]
                yield _cand('mov', f'mov{size}@{pos:#x}->{dst:#x}',
                            new, [pos, dst])
    for pos in sorted({n - 1, n // 2, n // 4, n // 8} | set(positions[:8])):
        if 0 < pos < n:
            yield _cand('trunc', f'trunc@{pos:#x}', data[:pos], [pos])
    for token in _TOKENS:
        for pos in (n, 0, n // 2):
            if len(data) + len(token) > max_span:
                continue
            new = data[:pos] + token + data[pos:]
            yield _cand('app', f'app{len(token)}@{pos:#x}', new, [pos])


def _record_candidates(data, structure, primary, endian):
    structure = structure or {}
    es = int(structure.get('entry_size') or 0)
    base = structure.get('entries_base')
    count = structure.get('count')
    count_off = structure.get('count_offset', structure.get('ifd_offset'))
    count_size = int(structure.get('count_size') or 2)
    if not es or base is None or count is None or count_off is None:
        return
    base = int(base)
    count = int(count)
    count_off = int(count_off)
    end = base + count * es
    if base < 0 or count <= 0 or count_off < 0 \
            or count_off + count_size > len(data) or end > len(data):
        return
    byteorder = 'little' if endian == '<' else 'big'

    def _set_count(buf, value):
        buf[count_off:count_off + count_size] = value.to_bytes(
            count_size, byteorder)

    templates = [('zero', b'\x00' * es), ('ff', b'\xff' * es)]
    for idx in (0, 1, count - 2, count - 1):
        if 0 <= idx < count and base + (idx + 1) * es <= len(data):
            templates.append(
                (f'copy{idx}', data[base + idx * es:base + (idx + 1) * es]))
    for name, template in templates:
        new = bytearray(data[:end] + template + data[end:])
        _set_count(new, count + 1)
        yield _cand('rec+', f'rec+{name}@{end:#x}', bytes(new),
                    [end, count_off])
    seen = set()
    for offset in _dedupe(primary):
        idx = _record_index(structure, offset)
        if idx is None or idx in seen:
            continue
        seen.add(idx)
        start = base + idx * es
        if start + es > len(data):
            continue
        template = data[start:start + es]
        new = bytearray(data[:end] + template + data[end:])
        _set_count(new, count + 1)
        yield _cand('rec+', f'rec+copy{idx}@{end:#x}', bytes(new),
                    [end, count_off])
        new = bytearray(data[:start] + data[start + es:])
        _set_count(new, count - 1)
        yield _cand('rec-', f'rec-del{idx}@{start:#x}', bytes(new),
                    [start, count_off])


_HINT_COUNT_RE = re.compile(
    r'incorrect count for (?:field )?"([^"]+)"\s*'
    r'\((\d+),\s*expecting\s*(\d+)\)', re.I)
_HINT_VALUE_RE = re.compile(r'Bad value (\d+) for "([^"]+)"', re.I)
_HINT_TYPE_RE = re.compile(r'wrong data type (\d+) for "([^"]+)"', re.I)


def _parse_error_hints(output):
    """Numeric repair hints from the target's own diagnostics.

    No tag-name table is needed: the count/value/type numbers in the message
    are matched against the record fields read from the input.
    """
    hints = []
    for m in _HINT_COUNT_RE.finditer(output or ''):
        hints.append({'kind': 'count', 'name': m.group(1),
                      'match': int(m.group(2)), 'new': int(m.group(3))})
    for m in _HINT_VALUE_RE.finditer(output or ''):
        hints.append({'kind': 'value', 'name': m.group(2),
                      'match': int(m.group(1)), 'new': 1})
    for m in _HINT_TYPE_RE.finditer(output or ''):
        hints.append({'kind': 'type', 'name': m.group(2),
                      'match': int(m.group(1)), 'new': 4})
    seen = set()
    out = []
    for hint in hints:
        key = (hint['kind'], hint['name'], hint['match'], hint['new'])
        if key not in seen:
            seen.add(key)
            out.append(hint)
    return out


def _record_fields(data, structure, endian):
    es = int((structure or {}).get('entry_size') or 0)
    base = (structure or {}).get('entries_base')
    count = (structure or {}).get('count')
    if not es or base is None or count is None:
        return []
    base, count = int(base), int(count)
    byteorder = 'little' if endian == '<' else 'big'
    out = []
    for idx in range(count):
        start = base + idx * es
        if start < 0 or start + es > len(data):
            break
        out.append({
            'index': idx, 'start': start,
            'tag': int.from_bytes(data[start:start + 2], byteorder),
            'type': int.from_bytes(data[start + 2:start + 4], byteorder),
            'count': int.from_bytes(data[start + 4:start + 8], byteorder),
            'value': int.from_bytes(data[start + 8:start + 12], byteorder),
        })
    return out


def _patched_candidate(data, fixes, label, endian, op='hint'):
    byteorder = 'little' if endian == '<' else 'big'
    new = bytearray(data)
    for off, size, value in fixes:
        if off < 0 or off + size > len(new) or value < 0:
            return None
        try:
            new[off:off + size] = value.to_bytes(size, byteorder)
        except OverflowError:
            return None
    return _cand(op, label, bytes(new), [off for off, _s, _v in fixes])


def _error_hint_candidates(data, structure, endian, output):
    """Directed repairs from the target's numeric diagnostics.

    The coordinated "combined" repair is emitted first because one error
    class usually needs several fields fixed together.
    """
    hints = _parse_error_hints(output)
    if not hints:
        return
    records = _record_fields(data, structure, endian)
    if not records:
        return
    combined = []
    per_field = []
    for hint in hints:
        for rec in records:
            field = hint['kind']
            if rec[field] != hint['match']:
                continue
            off = rec['start'] + {'type': 2, 'count': 4, 'value': 8}[field]
            size = 2 if field == 'type' else 4
            if field == 'value':
                values = [1, 0, 2, 3, hint['new']]
            elif field == 'type':
                values = [4, 3, 1, hint['new']]
            else:
                values = [hint['new'], 1, 8, 16]
            for value in values:
                cand = _patched_candidate(
                    data, [(off, size, value)],
                    f'hint-{field}{rec["index"]}@{off:#x}={value}', endian)
                if cand:
                    per_field.append(cand)
            combined.append((off, size, hint['new']))
    if combined:
        cand = _patched_candidate(data, combined, 'hint-combined', endian)
        if cand:
            yield cand
    for cand in per_field[:120]:
        yield cand


def _uniform_field_candidates(data, structure, endian, focus_offsets=None):
    """Set a whole field class to one value (globally, then per record).

    One candidate can fix the type/count/value of every entry at once, which
    is the cheap coordinated counterpart of the single-field sweep.
    """
    records = _record_fields(data, structure, endian)
    if not records:
        return
    focus = set(_dedupe(focus_offsets))
    if focus:
        es = int(structure['entry_size'])
        records = sorted(
            records,
            key=lambda r: 0 if any(r['start'] <= o < r['start'] + es
                                   for o in focus) else 1)
    for field, delta, size, values in (
            ('type', 2, 2, (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12)),
            ('count', 4, 4, (0, 1, 2, 3, 4, 8, 16, 256)),
            ('value', 8, 4, (0, 1, 2, 4, 8, 16, 256))):
        for value in values:
            fixes = [(rec['start'] + delta, size, value)
                     for rec in records]
            cand = _patched_candidate(
                data, fixes, f'uni-all-{field}={value}', endian,
                op='uniform')
            if cand:
                yield cand
    for rec in records:
        for field, delta, size, values in (
                ('type', 2, 2, (1, 2, 3, 4, 5, 6, 7, 8)),
                ('count', 4, 4, (0, 1, 2, 3, 4, 8, 16)),
                ('value', 8, 4, (0, 1, 2, 4, 8, 16, 256))):
            off = rec['start'] + delta
            for value in values:
                cand = _patched_candidate(
                    data, [(off, size, value)],
                    f'uni-{field}{rec["index"]}@{off:#x}={value}',
                    endian, op='uniform')
                if cand:
                    yield cand


def _havoc_one(data, rng, offsets, structure, endian, max_span):
    new = bytearray(data)
    touched = []
    endianness = 'little' if endian == '<' else 'big'
    focus = _dedupe(offsets)
    for _ in range(rng.randint(2, 6)):
        n = len(new)
        if n == 0:
            break
        op = rng.choice(('byte', 'mb', 'arith', 'ins', 'del', 'dup',
                         'app', 'trunc'))
        if op == 'byte':
            off = (rng.choice(focus) if focus and rng.random() < 0.5
                   else rng.randrange(n))
            if off < n:
                new[off] = rng.randrange(256)
                touched.append(off)
        elif op == 'mb':
            size = rng.choice((2, 4))
            if n >= size:
                off = (rng.choice(focus) if focus and rng.random() < 0.5
                       else rng.randrange(n - size + 1))
                if off + size <= n:
                    value = rng.choice(_mb_values(size, n))
                    new[off:off + size] = value.to_bytes(size, endianness)
                    touched.append(off)
        elif op == 'arith':
            size = rng.choice((2, 4))
            if n >= size:
                off = (rng.choice(focus) if focus and rng.random() < 0.5
                       else rng.randrange(n - size + 1))
                if off + size <= n:
                    cur = int.from_bytes(new[off:off + size], endianness)
                    delta = rng.choice(_ARITH_DELTAS[size])
                    value = (cur + rng.choice((1, -1)) * delta) \
                        & ((1 << (8 * size)) - 1)
                    new[off:off + size] = value.to_bytes(size, endianness)
                    touched.append(off)
        elif op == 'ins':
            if len(new) < max_span:
                pos = rng.randrange(n + 1)
                size = rng.choice((1, 2, 4, 8, 12, 16, 32))
                block = bytes([rng.choice((0, 0xff, 0x41, 0x80))]) * size
                new[pos:pos] = block
                touched.append(pos)
        elif op == 'del':
            size = rng.choice((1, 2, 4, 8, 12, 16, 32))
            if n > size:
                pos = rng.randrange(n - size + 1)
                del new[pos:pos + size]
                touched.append(pos)
        elif op == 'dup':
            size = rng.choice((4, 8, 12, 16))
            if n > size and len(new) < max_span:
                pos = rng.randrange(n - size + 1)
                block = bytes(new[pos:pos + size])
                new[pos:pos] = block
                touched.append(pos)
        elif op == 'app':
            if len(new) < max_span:
                token = rng.choice(_TOKENS)
                pos = rng.choice((n, 0, n // 2))
                new[pos:pos] = token
                touched.append(pos)
        elif op == 'trunc':
            if n > 1:
                pos = rng.randrange(1, n)
                del new[pos:]
                touched.append(pos)
    return bytes(new), touched


_PARSE_STAGE_RES = (
    ('header', re.compile(
        r'(?i)(bad (magic|header)|not a \w+|unknown (file )?format|'
        r'missing (magic|header)|invalid (magic|header)|'
        r'wrong (magic|header))')),
    ('directory', re.compile(
        r'(?i)(\bIFD\b|directory|entry|tag|count|offset).{0,60}'
        r'(invalid|bad|corrupt|out of|beyond|exceed|too (large|many))')),
    ('decode', re.compile(
        r'(?i)(decode|decompress|uncompress|corrupt data|truncated|'
        r'strip|tile|scanline|unexpected end)')),
)


def _behavior_signature(output, rc, input_file, sig=None, fork_func=None,
                        fork_file=None, ref_stack_funcs=None):
    """Structured behaviour record for the A1 attribution probe.

    ``key`` is byte-identical to the historical ``_behavior_key`` hash so the
    feedback-corpus dedup is unchanged; the extra fields only feed the
    no-match attribution report (error class, parse stage, whether the
    candidate reached the fork region).

    ``fork_func`` is the root-cause / fork-statement function (not merely
    the reference crash top frame).  ``fork_file`` is the source file that
    contains the fork statement.  ``ref_stack_funcs`` are every project
    frame on the reference crash stack — a candidate crash that shares a
    non-generic frame with them (or lands in ``fork_file``) proves
    execution entered the vulnerable region.  Generic process frames
    (``main``, ``__libc_start_*``, sanitizer/runtime stubs) are ignored
    for that intersection: every crash shares them, so they cannot prove
    the fork was reached.

    Returns::

        {'key', 'error_class', 'parse_stage', 'crash_func',
         'crash_relation', 'reached_fork'}
    """
    lines = []
    for line in (output or '').splitlines():
        if re.search(r'(?i)(error|warning|missing|invalid|assert|sanitizer|'
                     r'abort|fail|unable|cannot|unsupported|not supported)',
                     line):
            lines.append(line)
    text = '\n'.join(lines[-24:])
    text = re.sub(r'0x[0-9a-fA-F]+', '0xADDR', text)
    text = re.sub(r'\b\d+\b', 'N', text)
    text = re.sub(r'mutate_[A-Za-z0-9_]+', 'MUT', text)
    text = re.sub(r'/tmp/[^\s:]+', 'TMP', text)
    if input_file:
        text = text.replace(os.path.basename(input_file), 'INPUT')
    key = hashlib.sha1(
        (str(rc) + '\n' + text).encode('utf-8', 'replace')).hexdigest()

    # --- structured fields (attribution only; never affect dedup) ---
    raw = output or ''
    if rc == -1:
        error_class = 'timeout'
    elif rc == -2:
        error_class = 'exec_error'
    elif sig is not None:
        error_class = 'asan_crash'
    elif re.search(r'(?i)(segmentation fault|sigsegv|sigabrt|bus error|'
                   r'illegal instruction|killed)', raw):
        error_class = 'signal'
    elif re.search(r'(?i)(error|invalid|corrupt|unable|cannot|failed|'
                   r'unsupported|not supported|missing)', raw):
        error_class = 'parse_error' if rc != 0 else 'reported_error'
    elif rc == 0:
        error_class = 'clean'
    else:
        error_class = 'other'

    parse_stage = 'unknown'
    if rc != -1:
        for stage, pat in _PARSE_STAGE_RES:
            if pat.search(raw):
                parse_stage = stage
                break

    # Early structural rejection often lacks the error keywords above
    # ("bad magic header", "not a TIFF") — classify by stage so the
    # reached_fork=False branch can fire.
    if (parse_stage in ('header', 'directory')
            and rc not in (0, -1, -2)
            and error_class in ('other', 'reported_error')):
        error_class = 'parse_error'

    crash_func = None
    crash_funcs = set()
    crash_files = set()
    if sig and sig.get('crash_frames'):
        crash_func = sig['crash_frames'][0].get('function')
        for fr in sig['crash_frames']:
            if fr.get('function'):
                crash_funcs.add(fr['function'])
            if fr.get('file'):
                crash_files.add(os.path.basename(str(fr['file'])))

    ref_funcs = set(ref_stack_funcs or ())
    if fork_func:
        ref_funcs.add(fork_func)

    # on_ref_path must intersect on *project* frames only.  Sharing
    # main / __libc_start_* / sanitizer stubs is universal and does not
    # prove the candidate entered the reference vulnerable call chain
    # (e.g. a DXF-output crash still has main + libc on its stack).
    def _project_funcs(names):
        out = set()
        for n in names:
            if not n:
                continue
            if n in ('main', '_start', 'clone', 'clone3', 'fork',
                     '__libc_start_call_main', '__libc_start_main'):
                continue
            if n.startswith('__libc') or n.startswith('__sanitizer'):
                continue
            if n.startswith('__asan') or n.startswith('__interceptor'):
                continue
            out.add(n)
        return out

    crash_relation = None
    if sig is not None:
        if fork_func and crash_func and crash_func == fork_func:
            crash_relation = 'at_fork'
        elif _project_funcs(crash_funcs) & _project_funcs(ref_funcs):
            # Innermost frame differs but the fault sits on the reference
            # vulnerable call chain — still "in the fork region".
            crash_relation = 'on_ref_path'
        elif fork_file and os.path.basename(str(fork_file)) in crash_files:
            crash_relation = 'in_fork_file'
        else:
            crash_relation = 'elsewhere'

    # reached_fork: True  = proof execution entered the vulnerable region
    #               False = proof it died before the fork (early reject)
    #               'unknown' = clean / timeout / decode-stage / off-path
    if crash_relation in ('at_fork', 'on_ref_path', 'in_fork_file'):
        reached_fork = True
    elif crash_relation == 'elsewhere':
        # ASan fired past the header, but not on the known path/file —
        # cannot claim the fork was hit.
        reached_fork = 'unknown'
    elif rc == -2:
        reached_fork = False
    elif (parse_stage in ('header', 'directory')
          and rc not in (0, -1, -2)):
        reached_fork = False
    else:
        # clean, timeout, decode-stage parse_error, reported_error, other
        reached_fork = 'unknown'

    return {
        'key': key,
        'error_class': error_class,
        'parse_stage': parse_stage,
        'crash_func': crash_func,
        'crash_relation': crash_relation,
        'reached_fork': reached_fork,
    }


def _behavior_key(output, rc, input_file):
    """Coarse behaviour fingerprint for feedback search.

    Only diagnostic lines are kept; ASan addresses, temp file names and the
    input path are normalised so identical behaviour yields the same key.
    Thin wrapper over :func:`_behavior_signature` (same hash as before).
    """
    return _behavior_signature(output, rc, input_file)['key']


def _fork_coverage_hint(fork_file, fork_line):
    """Minimal verify_one hint from explicit fork file:line.

    Deliberately does NOT use verify_fork_path.build_hint: that helper
    defaults to root_cause_line_b when fork_line is None, which is wrong
    for targets whose real fork line differs (e.g. CVE-2022-33034: 539
    vs 541).  Callers that reach this helper already hold the correct line.
    """
    if not fork_file or fork_line in (None, '', 0, '0'):
        return None
    try:
        line = int(fork_line)
    except (TypeError, ValueError):
        return None
    if line <= 0:
        return None
    return {
        'fork_spec': '%s:%d' % (fork_file, line),
        'cond_expr': None,
        'expected_outcome': None,
        'invocation': None,
        'var_exprs': [],
    }


def _fork_coverage_probe(real_target, fork_file, fork_line, data,
                         program_args, input_file, timeout=15):
    """GDB line-breakpoint probe: did this candidate reach the fork?

    Returns True (fork hit), False (ran to completion / died without
    hitting the line), or None (probe could not run: missing binary,
    gdb error, timeout, disabled).
    """
    if os.environ.get('RETROSCOPE_FORK_PROBE', '1') in ('0', 'false', 'no'):
        return None
    hint = _fork_coverage_hint(fork_file, fork_line)
    if hint is None or data is None or not real_target:
        return None
    try:
        from verify_fork_path import verify_one
    except Exception:
        return None
    ext = os.path.splitext(input_file)[1] if input_file else '.bin'
    fd, tmp_path = tempfile.mkstemp(suffix=ext, prefix='fcov_')
    os.close(fd)
    try:
        with open(tmp_path, 'wb') as f:
            f.write(data)
        res = verify_one(real_target, hint, tmp_path,
                         list(program_args or []), input_file,
                         timeout=timeout)
        if not isinstance(res, dict) or res.get('status') != 'ok':
            return None
        if res.get('bp_unresolved'):
            return None
        return bool(res.get('reached'))
    except Exception:
        return None
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


def _classify_death_mode(rec):
    """Map one attribution record onto the unified death-mode taxonomy.

    Modes (see near-miss analysis / coverage plan):
      matched              - same_func / same_site (success)
      near_miss_same_type  - same_type only (boundary)
      G_early_reject       - mode 0: died at header/directory before F
      G_parse_error        - mode 0: parse_error (often decode) before F
      prefork_other        - mode 0/1: proven pre-F, other class
      pastF_wrong_crash    - mode 2a/2b: reached F, crash off the ref path
      pastF_no_crash       - mode 4: reached F, clean exit (data state)
      pastF_onpath_nomatch - reached F + on-path crash, still no match
      pastF_other          - reached F, other outcome
      unknown_*            - fork reach not proven (probe missing/failed)
    """
    v = rec.get('verdict')
    if v in ('same_func', 'same_site'):
        return 'matched'
    if v == 'same_type':
        return 'near_miss_same_type'
    fh = rec.get('fork_hit')
    rf = rec.get('reached_fork')
    ec = rec.get('error_class') or 'unknown'
    ps = rec.get('parse_stage') or 'unknown'
    cr = rec.get('crash_relation')
    if fh is True or rf == 'yes':
        reached = True
    elif fh is False or rf == 'no':
        reached = False
    else:
        reached = None
    if reached is False:
        if ps in ('header', 'directory'):
            return 'G_early_reject'
        if ec == 'parse_error':
            return 'G_parse_error'
        if ec == 'exec_error':
            return 'infra_error'
        return 'prefork_other'
    if reached is True:
        if cr == 'elsewhere':
            return 'pastF_wrong_crash'
        if ec == 'clean':
            return 'pastF_no_crash'
        if ec == 'timeout':
            return 'pastF_timeout'
        if cr in ('at_fork', 'on_ref_path', 'in_fork_file'):
            return 'pastF_onpath_nomatch'
        if ec == 'asan_crash':
            return 'pastF_other_crash'
        return 'pastF_other'
    if ec == 'clean':
        return 'unknown_clean'
    if ec == 'timeout':
        return 'unknown_timeout'
    if ec == 'exec_error':
        return 'infra_error'
    if ps == 'decode':
        return 'unknown_decode'
    if ps in ('header', 'directory'):
        return 'unknown_early'
    return 'unknown'


def _run_once(real_binary, data, program_args, input_file, timeout,
              mutation_env, replace_input_arg):
    ext = os.path.splitext(input_file)[1] if input_file else '.bin'
    fd, tmp_path = tempfile.mkstemp(suffix=ext, prefix='p0_')
    os.close(fd)
    try:
        with open(tmp_path, 'wb') as f:
            f.write(data)
        cmd = [real_binary] + [
            replace_input_arg(a, tmp_path, input_file)
            for a in program_args]
        proc = subprocess.run(
            cmd, capture_output=True, text=True, errors='replace',
            timeout=timeout, env=mutation_env(real_binary))
        return proc.stdout + proc.stderr, proc.returncode
    except subprocess.TimeoutExpired:
        return '', -1
    except Exception:
        return '', -2
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


def _save_full_artifact(out_dir, name, data):
    safe = re.sub(r'[/\\\s]+', '_', name)[:180]
    try:
        os.makedirs(out_dir, exist_ok=True)
        path = os.path.join(out_dir, safe)
        with open(path, 'wb') as f:
            f.write(data)
        return path
    except Exception:
        return None


def _batched(iterable, size):
    batch = []
    for item in iterable:
        batch.append(item)
        if len(batch) >= size:
            yield batch
            batch = []
    if batch:
        yield batch


# ---------------------------------------------------------------------------
# A3: fork-flip gate (prove an offset can steer the target fork before the
# budget is spent crash-matching candidates that cannot cross the divergence).
# ---------------------------------------------------------------------------

_C_STR_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')
_FMT_SPEC_RE = re.compile(
    r'%[-+ #0]*(?:\d+|\*)?(?:\.(?:\d+|\*))?[hlL]*[diouxXeEfgGaAcsp]')


def _decode_c_string(s):
    out = []
    i = 0
    while i < len(s):
        if s[i] == '\\' and i + 1 < len(s):
            n = s[i + 1]
            mapping = {'n': '\n', 't': '\t', 'r': '\r', '"': '"',
                       "'": "'", '\\': '\\', '0': '\0'}
            out.append(mapping.get(n, n))
            i += 2
        else:
            out.append(s[i])
            i += 1
    return ''.join(out)


def _marker_from_c_string(raw, min_len=10):
    """Turn a C string literal into a substring that appears in run output.

    Format conversions (``%d`` …) are stripped and the longest remaining
    literal chunk is used, because the runtime output contains substituted
    values, not the format string itself.
    """
    s = _decode_c_string(raw)
    parts = _FMT_SPEC_RE.split(s)
    parts = [p.replace('%%', '%') for p in parts]
    best = max(parts, key=len) if parts else ''
    best = best.strip().strip('\n\t\r')
    # Drop chunks that are still mostly punctuation/whitespace.
    if len(best) < min_len or not re.search(r'[A-Za-z]', best):
        return None
    if not re.search(r'[A-Za-z]{3}', best):
        return None
    return best


def _score_marker(s):
    if not s or len(s) < 10:
        return -1
    score = len(s)
    if ' ' in s:
        score += 100
    if re.search(r'(error|invalid|unable|cannot|failed|not supported|bad '
                 r'|unsupported|overflow|corrupt)', s, re.I):
        score += 200
    return score


def _derive_fork_marker(fork_file, fork_line, binary=None, min_len=10):
    """Best-effort output marker for the fork's taken-branch body.

    Reads the source at ``fork_file:fork_line``, collects string literals
    from the branch body (brace-matched, or the single statement), and
    returns the highest-scoring literal that will appear in the target's
    output when the fork is taken.  Returns ``None`` when nothing suitable
    is found — callers must then skip the gate (pass-through).
    """
    if not fork_file or not fork_line:
        return None
    try:
        import trace_fork_offsets as tfo
        path = tfo.locate_source_file(os.path.basename(str(fork_file)),
                                      binary=binary)
        if not path and os.path.isfile(str(fork_file)):
            path = str(fork_file)
    except Exception:
        path = fork_file if os.path.isfile(str(fork_file)) else None
    if not path:
        return None
    try:
        with open(path, errors='replace') as fh:
            lines = fh.read().splitlines()
    except OSError:
        return None
    try:
        idx = int(fork_line) - 1
    except (TypeError, ValueError):
        return None
    if idx < 0 or idx >= len(lines):
        return None

    depth = 0
    seen_open = False
    region = []
    for i in range(idx, min(len(lines), idx + 40)):
        line = lines[i]
        region.append(line)
        stripped = _C_STR_RE.sub('', line)
        stripped = re.sub(r"'(?:[^'\\]|\\.)'", '', stripped)
        stripped = re.sub(r'//.*', '', stripped)
        for ch in stripped:
            if ch == '{':
                depth += 1
                seen_open = True
            elif ch == '}':
                depth -= 1
        if seen_open and depth <= 0:
            break
        if not seen_open and ';' in stripped and i > idx:
            break
        if not seen_open and i == idx and ';' in stripped and '{' not in stripped:
            break

    text = '\n'.join(region)
    text = re.sub(r'/\*.*?\*/', '', text, flags=re.S)
    text = re.sub(r'//.*', '', text)
    cands = []
    for raw in _C_STR_RE.findall(text):
        s = _marker_from_c_string(raw, min_len=min_len)
        if s:
            cands.append((_score_marker(s), s))
    if not cands:
        return None
    cands.sort(reverse=True)
    return cands[0][1]


def _fork_flip_gate(real_target, input_file, program_args, offsets,
                    marker, per_timeout, deadline, max_offsets=12,
                    verbose=True):
    """Probe whether each offset can flip the target fork (A3).

    Returns ``(flip_offsets, noflip_offsets, gate_info)``.  The gate is
    conclusive only when at least one offset flips — zero flips means the
    marker is insensitive (or nothing here steers the fork) and the caller
    must pass through unchanged.
    """
    import trace_fork_offsets as tfo

    gate_info = {
        'marker': marker,
        'probed': [],
        'flip': [],
        'noflip': [],
        'conclusive': False,
        'error': None,
    }
    probe_offs = _dedupe(offsets, limit=max_offsets)
    if not marker or not probe_offs:
        gate_info['error'] = 'no-marker-or-no-offsets'
        return list(offsets or []), [], gate_info
    # Keep the probe inside a small slice of the stage budget.
    probe_deadline = min(deadline or float('inf'),
                         time.time() + 45.0)
    try:
        probe = tfo.fork_flip_probe(
            real_target, input_file, program_args, probe_offs, marker,
            timeout=max(1, int(per_timeout or 10)),
            values=(0x00, 0xFF),
            deadline=probe_deadline)
    except Exception as exc:
        gate_info['error'] = f'probe-failed: {exc}'
        return list(offsets or []), [], gate_info

    flip, noflip = [], []
    for off in probe_offs:
        info = probe.get(off)
        if not info:
            continue
        gate_info['probed'].append(off)
        base = info.get('original_fork_taken')
        trials = info.get('trials') or {}
        flipped = any(present != base for present in trials.values())
        (flip if flipped else noflip).append(off)
    gate_info['flip'] = flip
    gate_info['noflip'] = noflip
    gate_info['conclusive'] = bool(flip)
    if verbose:
        print(f'  [*] A3 fork-flip gate: marker={marker[:60]!r}')
        print(f'      probed={len(gate_info["probed"])} '
              f'flip={len(flip)} noflip={len(noflip)} '
              f'conclusive={gate_info["conclusive"]}')
    if not gate_info['conclusive']:
        return list(offsets or []), [], gate_info
    flip_set = set(flip)
    noflip_set = set(noflip)
    # Flip-proven offsets first; unprobed offsets (budget/cap) stay in the
    # main pool; proven-non-flipping offsets are deferred to a late phase.
    kept = ([o for o in (offsets or []) if o in flip_set]
            + [o for o in (offsets or [])
               if o not in flip_set and o not in noflip_set])
    deferred = [o for o in (offsets or []) if o in noflip_set]
    return kept, deferred, gate_info


def _format_candidates(data, structure, focus_offsets=None):
    """Format-aware candidates from the independent format_profiles package.

    Detects the on-disk format by magic, then yields directed repairs for
    structural issues followed by per-field meaning-bearing mutations.
    Returns an empty iterator when the package is unavailable or the
    format is unknown — the phase is strictly additive.
    """
    try:
        from format_profiles import detect_profile, profile_candidates
    except ImportError:
        return
    try:
        profile = detect_profile(data)
    except Exception:
        return
    if not profile:
        return
    # Reuse the pipeline structure only when it already carries typed
    # fields; otherwise reparse via the profile for full field metadata
    # (kinds/names/values) that value_domain/repair need.
    use_struct = structure if (structure or {}).get('fields') else None
    # Deep-dive env: raise the generator's internal caps (default 8/60/100).
    def _env_int(key, default):
        try:
            return int(os.environ.get(key, default))
        except ValueError:
            return default
    try:
        yield from profile_candidates(
            data, structure=use_struct, focus=focus_offsets,
            per_field_cap=_env_int('RETROSCOPE_FMT_PER_FIELD', 8),
            issue_cap=_env_int('RETROSCOPE_FMT_ISSUE_CAP', 60),
            field_cap=_env_int('RETROSCOPE_FMT_FIELD_CAP', 100))
    except Exception:
        return


# ---------------------------------------------------------------------------
# Plan C1: coordinated multi-field mutation via format dependency groups
# ---------------------------------------------------------------------------

def _coordinated_candidates(data, structure, endian, focus_offsets=None,
                            per_group_cap=None):
    """Mutate DEPENDENT fields together (one candidate = one group rewrite).

    Single-field sweeps miss constraints that need several bytes changed at
    once — the classic case is a TIFF IFD entry whose type AND count AND
    value-offset must agree, or a GIF screen size that must match the image
    descriptor.  Each candidate rewrites every field of one dependency
    group with a consistent value assignment.

    Yields ``_cand`` dicts; empty when format_profiles/deps is unavailable
    or the structure carries no dependency groups.
    """
    try:
        from format_profiles import (
            detect_profile, dependency_groups, focus_groups,
        )
    except ImportError:
        return
    if not data:
        return
    try:
        profile = detect_profile(data)
    except Exception:
        profile = None
    use_struct = structure if (structure or {}).get('fields') else None
    if use_struct is None and profile is not None:
        try:
            use_struct = profile.parse(data)
        except Exception:
            use_struct = None
    if not use_struct:
        return
    try:
        groups = dependency_groups(use_struct)
    except Exception:
        return
    if not groups:
        return
    try:
        groups = focus_groups(groups, focus_offsets)
    except Exception:
        pass

    def _read(field):
        off = field.get('offset')
        size = int(field.get('size') or 1)
        little = bool(field.get('little', endian != '>'))
        if not isinstance(off, int) or off < 0 or off + size > len(data):
            return None
        return int.from_bytes(data[off:off + size],
                              'little' if little else 'big')

    def _write_into(buf, field, value):
        off = field.get('offset')
        size = int(field.get('size') or 1)
        little = bool(field.get('little', endian != '>'))
        if not isinstance(off, int) or off < 0 or off + size > len(buf):
            return False
        if value < 0 or value >= (1 << (8 * size)):
            return False
        buf[off:off + size] = int(value).to_bytes(
            size, 'little' if little else 'big')
        return True

    def _domain(field):
        if profile is not None:
            try:
                vals = profile.value_domain(field)
                if vals:
                    return vals
            except Exception:
                pass
        size = int(field.get('size') or 1)
        from format_profiles.base import MB_VALUES, PROBE_DEFAULT
        return list(PROBE_DEFAULT) + MB_VALUES.get(size, MB_VALUES[4])[:8]

    emitted = 0
    if per_group_cap is None:
        try:
            per_group_cap = int(os.environ.get(
                'RETROSCOPE_COORD_PER_GROUP', '6'))
        except ValueError:
            per_group_cap = 6
    try:
        max_total = int(os.environ.get('RETROSCOPE_COORD_MAX', '100'))
    except ValueError:
        max_total = 100
    for label, fields in groups:
        if emitted >= max_total:
            break
        if not fields:
            continue
        # Pick one field as the "driver" (first with a non-trivial domain),
        # assign it a value, then make the peers consistent.
        driver = None
        driver_vals = None
        for f in fields:
            vals = _domain(f)
            if vals:
                driver, driver_vals = f, vals
                break
        if driver is None:
            continue
        n = 0
        for value in driver_vals:
            if n >= per_group_cap or emitted >= max_total:
                break
            orig = _read(driver)
            if orig is not None and value == orig:
                continue
            buf = bytearray(data)
            if not _write_into(buf, driver, value):
                continue
            # Consistency pass: for size-typed peers that are clearly
            # "length of the same object", set them to a file-bounded
            # value derived from the driver change (0 / 1 / small).
            touched = [int(driver.get('offset'))]
            for f in fields:
                if f is driver:
                    continue
                kind = f.get('kind')
                peer_off = f.get('offset')
                if not isinstance(peer_off, int):
                    continue
                if kind in ('count', 'size', 'offset'):
                    # Conservative peer: clamp into a few safe values.
                    peer_vals = _domain(f)[:4]
                    chosen = None
                    for pv in peer_vals:
                        if _write_into(buf, f, pv):
                            chosen = pv
                            break
                    if chosen is not None:
                        touched.append(peer_off)
                elif kind in ('tag', 'enum', 'desc', 'marker', 'magic',
                              'flag', 'name', 'attr'):
                    # Leave peers alone unless the driver was also this
                    # kind (uniform group rewrite).
                    if f.get('kind') == driver.get('kind'):
                        for pv in _domain(f)[:4]:
                            if pv != _read(f) and _write_into(buf, f, pv):
                                touched.append(peer_off)
                                break
            if bytes(buf) == data:
                continue
            yield _cand(
                'coord',
                f'coord-{label}@{driver.get("offset", 0):#x}={value}',
                bytes(buf), touched,
                desc=f'coordinated group {label}')
            emitted += 1
            n += 1


# ---------------------------------------------------------------------------
# Plan C2: grammar + compression operators
# ---------------------------------------------------------------------------

_XML_TOKENS = (
    b'<a/>', b'</a>', b'<a></a>', b'<!DOCTYPE a>', b'<?xml version="1.0"?>',
    b'<!--x-->', b'<![CDATA[x]]>', b'<a b="c"/>', b'&amp;', b'&lt;',
    b'&#0;', b'&#x0;', b'"', b"'", b'<', b'>', b'/',
)

_GIF_TOKENS = (
    b'\x2c', b'\x21\xf9', b'\x3b', b'\x00', b'\xff', b'\x80',
)

_J2K_TOKENS = (
    b'\xff\x4f', b'\xff\xd9', b'\xff\x51', b'\xff\x52', b'\xff\x5c',
    b'\xff\x90', b'\xff\x93', b'\xff\x92',
)


def _grammar_tokens(fmt):
    if fmt == 'xml':
        return _XML_TOKENS
    if fmt == 'gif':
        return _GIF_TOKENS
    if fmt == 'j2k':
        return _J2K_TOKENS
    if fmt == 'tiff':
        return (b'II*\x00', b'MM\x00*', b'\x00\x2a', b'\x2a\x00')
    if fmt in ('dwg',):
        return (b'AC1015', b'AC1018', b'AC1032', b'\x00\x00')
    return (b'\x00', b'\xff', b'<', b'>')


def _grammar_candidates(data, structure, endian, focus_offsets=None,
                        cap=80):
    """Format-grammar token insert/replace at structural positions.

    Crash PoCs are malformed on purpose; inserting a *valid* construct
    (closing tag, EOC marker, GIF trailer) at a structural position can
    push the parser past the guard that the single-byte sweep never
    crosses.  Positions come from the structure's field offsets (focus
    first), not from a blind scan.
    """
    try:
        from format_profiles import detect_profile
    except ImportError:
        return
    try:
        profile = detect_profile(data)
    except Exception:
        profile = None
    fmt = (structure or {}).get('format') or (profile.name if profile
                                              else None)
    if not fmt and profile is not None:
        try:
            st = profile.parse(data)
            fmt = (st or {}).get('format')
        except Exception:
            fmt = None
    if not fmt:
        # Fall back to magic sniff without a full parse.
        if data[:6] in (b'GIF87a', b'GIF89a'):
            fmt = 'gif'
        elif data[:2] in (b'II', b'MM'):
            fmt = 'tiff'
        elif data[:2] == b'\xff\x4f':
            fmt = 'j2k'
        elif data[:1] == b'<' or data[:5] == b'<?xml':
            fmt = 'xml'
        elif data[:2] == b'AC':
            fmt = 'dwg'
        else:
            return
    tokens = _grammar_tokens(fmt)

    # Structural positions: field offsets (focus first), plus header
    # anchors and EOF for append-style repairs.
    positions = []
    seen = set()

    def _pos(off):
        if isinstance(off, int) and 0 <= off <= len(data) and off not in seen:
            seen.add(off)
            positions.append(off)

    for off in _dedupe(focus_offsets):
        _pos(off)
    for f in (structure or {}).get('fields') or []:
        _pos(f.get('offset'))
    # Header anchors + EOF.
    for off in (0, 1, 2, 4, 6, 8, 12, 16, len(data)):
        _pos(off)
    if not positions:
        positions = [0, len(data)]

    emitted = 0
    for off in positions:
        if emitted >= cap:
            break
        for tok in tokens:
            if emitted >= cap:
                break
            # insert
            if len(data) + len(tok) <= 8 * 1024 * 1024:
                new = data[:off] + tok + data[off:]
                yield _cand('grammar',
                            f'gram-ins-{fmt}@{off:#x}+{tok[:4].hex()}',
                            new, [off],
                            desc=f'insert {fmt} grammar token')
                emitted += 1
            # replace 1..len(tok) bytes when in range
            end = min(len(data), off + len(tok))
            if end > off:
                new = data[:off] + tok[:end - off] + data[end:]
                if new != data:
                    yield _cand(
                        'grammar',
                        f'gram-rep-{fmt}@{off:#x}={tok[:4].hex()}',
                        new, [off],
                        desc=f'replace with {fmt} grammar token')
                    emitted += 1


def _compression_candidates(data, structure, endian, focus_offsets=None,
                            cap=60):
    """Recompress / stream-mutate candidates for compressible inputs.

    Two families:
      1. whole-file zlib/gzip/bz2 recompress at different levels (the
         decoder's length/checksum guards are the usual divergence point);
      2. raw-deflate window mutations — flip bytes inside an existing
         zlib stream, then recompress, so the decompressed output shifts
         without changing the container.

    Only emits when the input actually compresses (ratio < 0.98), so
    already-raw formats (TIFF strips, GIF LZW blocks) are untouched.
    """
    import bz2
    import zlib

    if not data or len(data) < 16:
        return

    # Skip obvious non-compressible containers.
    if data[:2] in (b'II', b'MM') or data[:6] in (b'GIF87a', b'GIF89a') \
            or data[:2] == b'\xff\x4f':
        # Still try a tiny raw-deflate poke at focus offsets for these.
        raw_ok = True
    else:
        raw_ok = False

    def _try_compress(blob, wbits, level):
        try:
            out = zlib.compress(blob, level) if wbits == 15 else \
                zlib.compress(blob, level, wbits)
        except Exception:
            return None
        if not out or out == blob:
            return None
        if len(out) >= len(blob):
            return None
        return out

    # 1) whole-file recompress at several levels / wrappers
    emitted = 0
    for level in (1, 6, 9):
        if emitted >= cap // 2:
            break
        packed = _try_compress(data, 15, level)
        if packed is None:
            continue
        # zlib wrapper (wbits=15) is already the default; also emit a
        # raw-deflate and a gzip-wrapped variant.
        yield _cand('compress',
                    f'zlib-l{level}({len(data)}->{len(packed)})',
                    packed, [0],
                    desc=f'zlib recompress level {level}')
        emitted += 1
        try:
            gz = gzip_bytes(data, level)
            if gz and gz != data:
                yield _cand('compress',
                            f'gzip-l{level}({len(data)}->{len(gz)})',
                            gz, [0],
                            desc=f'gzip recompress level {level}')
                emitted += 1
        except Exception:
            pass
        if emitted >= cap // 2:
            break

    # 2) raw-deflate poke: mutate focus bytes, recompress, check ratio
    focus = _dedupe(focus_offsets) or [0, len(data) // 2, max(0, len(data) - 1)]
    for off in focus[:8]:
        if emitted >= cap:
            break
        if off >= len(data):
            continue
        for delta in (1, 0xFF, 0x80):
            if emitted >= cap:
                break
            buf = bytearray(data)
            buf[off] = (buf[off] + delta) & 0xFF
            packed = _try_compress(bytes(buf), 15, 6)
            if packed is None:
                continue
            yield _cand('compress',
                        f'raw-poke@{off:#x}+{delta:#x}({len(packed)})',
                        packed, [off],
                        desc='mutate then recompress')
            emitted += 1

    # 3) bz2 whole-file (different checksum/length guard family)
    if emitted < cap:
        try:
            bpacked = bz2.compress(data, 9)
            if bpacked and bpacked != data and len(bpacked) < 2 * len(data):
                yield _cand('compress',
                            f'bz2({len(data)}->{len(bpacked)})',
                            bpacked, [0],
                            desc='bz2 recompress')
                emitted += 1
        except Exception:
            pass


def gzip_bytes(data, level=6):
    """Minimal gzip container (no optional fields) around ``data``."""
    import zlib
    body = zlib.compress(data, level)[2:-4]  # raw deflate
    crc = zlib.crc32(data) & 0xffffffff
    isize = len(data) & 0xffffffff
    header = b'\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff'
    trailer = crc.to_bytes(4, 'little') + isize.to_bytes(4, 'little')
    return header + body + trailer


# ---------------------------------------------------------------------------
# Plan C3: parse-depth feedback (attribution -> focus reordering)
# ---------------------------------------------------------------------------

def _parse_depth_focus(attribution, structure, base_focus=None):
    """Reorder/extend focus offsets using A1 parse-stage attribution.

    When the corpus keeps failing at a *shallow* parse stage (header /
    directory), the interesting bytes are the structural ones the parser
    rejects early — prioritise structure field offsets.  When failures are
    deep (decode / unknown / reached_fork), prioritise the dynamic primary
    offsets and their neighbourhood instead.

    Returns a list of offsets (focus order); never raises.
    """
    try:
        records = attribution or []
        if not records:
            return list(base_focus or [])
        stages = {}
        for r in records:
            st = r.get('parse_stage') or 'unknown'
            stages[st] = stages.get(st, 0) + 1
        shallow = stages.get('header', 0) + stages.get('directory', 0)
        deep = stages.get('decode', 0) + stages.get('unknown', 0)
        struct_offs = _dedupe((structure or {}).get('field_offsets'))
        base = _dedupe(base_focus)
        if shallow > deep and struct_offs:
            # Early-reject failures: structure first, then base.
            return _dedupe(struct_offs + base)
        # Deep / unknown: keep dynamic focus, append structure as tail.
        return _dedupe(base + struct_offs)
    except Exception:
        return list(base_focus or [])


def _feedback_offsets(seed, structure, radius=64):
    offsets = set(_dedupe(seed.get('offsets')))
    for off in list(offsets):
        for delta in (1, 2, 3, 4, 8, 12, 16, 32, 64):
            for sign in (-1, 1):
                if off + sign * delta >= 0:
                    offsets.add(off + sign * delta)
        idx = _record_index(structure, off)
        if idx is not None:
            es = int(structure['entry_size'])
            base = int(structure['entries_base'])
            for k in range(base + idx * es, base + (idx + 1) * es):
                offsets.add(k)
    for field_off in (structure or {}).get('field_offsets') or []:
        if any(abs(field_off - off) <= radius for off in offsets):
            offsets.add(field_off)
    return sorted(o for o in offsets if o >= 0)


def run_extended_mutation_stage(
        binary, binary_ref, input_file, program_args,
        dynamic_offsets, static_offsets=None, structure=None,
        timeout=60, version=None, max_candidates=1200,
        budget_seconds=600.0, per_candidate_timeout=None,
        seed=0xC0FFEE, verbose=True,
        fork_file=None, fork_line=None, fork_marker=None,
        fork_func=None):
    """Step 6f: generic extended mutation.

    ``dynamic_offsets`` are the exact offsets obtained from dynamic
    execution (fork-variable / origin trace); they are always mutated first.
    ``structure`` is the region dict already produced by the pipeline
    (``field_offsets``/``fields``/``entry_size``/``entries_base``/``count``/
    ``ifd_offset``); ``static_offsets`` are the static fallback offsets.
    ``fork_file``/``fork_line``/``fork_marker`` enable the A3 fork-flip
    gate (optional; absent metadata ⇒ gate skipped, behaviour unchanged).
    ``fork_func`` is the root-cause function that contains the fork
    statement (A1 attribution); when omitted the reference crash top
    frame is used as a fallback.

    Returns ``(results, matched)``; results is a JSON-friendly dict.
    """
    import trace_fork_offsets as tfo

    if not (binary and binary_ref and input_file
            and os.path.isfile(input_file)):
        return {}, False

    real_target = tfo.resolve_binary(binary)
    real_ref = tfo.resolve_binary(binary_ref)
    if not (os.path.isfile(real_target) and os.path.isfile(real_ref)):
        if verbose:
            print(f'  [!] Step 6f: binary not found '
                  f'(target={real_target}, ref={real_ref})')
        return {}, False

    try:
        with open(input_file, 'rb') as f:
            original = f.read()
    except OSError:
        return {}, False

    endian = _guess_endian(original)
    structure = structure or {}
    primary = _dedupe(dynamic_offsets)
    neigh = _neighbourhood(primary, structure)
    struct_offsets = _dedupe(structure.get('field_offsets'))
    static = _dedupe(static_offsets)
    # B: detect on-disk format once (format_profiles package).
    fmt_profile = None
    try:
        from format_profiles import detect_profile as _detect_fp
        fmt_profile = _detect_fp(original)
    except Exception:
        fmt_profile = None
    fmt_name = fmt_profile.name if fmt_profile else None
    anchors = [0, len(original), len(original) // 2,
               structure.get('ifd_offset'),
               structure.get('entries_base')]
    if structure.get('entries_base') is not None \
            and structure.get('entry_size') and structure.get('count'):
        anchors.append(int(structure['entries_base'])
                       + int(structure['entry_size'])
                       * int(structure['count']))
    anchors = _dedupe(anchors)

    per_timeout = int(per_candidate_timeout or timeout or 60)
    p0_start = time.time()
    deadline = p0_start + float(budget_seconds or 0)

    if verbose:
        print(f'\n{"="*60}')
        print('  Step 6f: Generic extended mutation (P0)')
        print(f'{"="*60}')
        print(f'  Input file: {input_file} ({len(original)} bytes)')
        print(f'  Target binary: {real_target}')
        print(f'  Reference binary: {real_ref}')
        print('  Primary dynamic offsets: '
              + (', '.join(f'0x{o:x}' for o in primary) or '(none)'))
        print(f'  Dynamic neighbourhood: {len(neigh)} offset(s)')
        print(f'  Dynamic structure offsets: {len(struct_offsets)}')
        print(f'  Static offsets: {len(static)}')
        print(f'  Format profile: {fmt_name or "(none detected)"}')
        print(f'  Budget: {max_candidates} candidates / '
              f'{budget_seconds:.0f}s')

    ref_out, ref_rc = _run_once(
        real_ref, original, program_args, input_file, per_timeout,
        tfo._mutation_env, tfo._replace_input_arg)
    ref_sig = tfo.extract_crash_signature(ref_out)
    if ref_sig is None:
        if verbose:
            print(f'  [!] Reference binary did not produce an ASan crash '
                  f'(rc={ref_rc}); Step 6f skipped.')
        return {}, False
    tfo._attach_crash_statement(ref_sig, real_ref)
    ref_crash = ref_sig['crash_frames'][0] if ref_sig['crash_frames'] else {}
    comp_ref_sig = ref_sig
    mapped = tfo._map_ref_crash_function(real_target, real_ref, ref_crash)
    if mapped:
        import copy as _copy
        comp_ref_sig = _copy.deepcopy(ref_sig)
        comp_ref_sig['crash_frames'][0]['function'] = mapped
        if verbose:
            print(f'  [*] Reference crash function mapped to target-side '
                  f'{mapped}()')
    if verbose:
        print(f'  Reference crash: {ref_sig["type"]} in '
              f'{ref_crash.get("function")} '
              f'({tfo._path_basename(ref_crash.get("file"))}:'
              f'{ref_crash.get("line")}, rc={ref_rc})')

    base_out, base_rc = _run_once(
        real_target, original, program_args, input_file, per_timeout,
        tfo._mutation_env, tfo._replace_input_arg)
    base_sig = tfo.extract_crash_signature(base_out)
    base_key = _behavior_key(base_out, base_rc, input_file)
    if verbose:
        print(f'  Target baseline: rc={base_rc}'
              + (f', crash={base_sig["type"]}'
                 if base_sig else ', no crash'))

    # A3: fork-flip gate — only offsets that can steer the target fork
    # enter the early crash-matching phases.  Inconclusive probe (no
    # marker / zero flips) leaves `primary` untouched (pass-through).
    gate_info = None
    primary_deferred = []
    if primary and (fork_marker or (fork_file and fork_line)):
        marker = fork_marker or _derive_fork_marker(
            fork_file, fork_line, binary=binary)
        if marker:
            _kept, _deferred, gate_info = _fork_flip_gate(
                real_target, input_file, program_args, primary, marker,
                per_timeout, deadline, verbose=verbose)
            if gate_info.get('conclusive'):
                primary = _dedupe(_kept)
                primary_deferred = _dedupe(_deferred)
                neigh = _neighbourhood(primary, structure)
                if verbose:
                    print(f'  [*] A3 gate applied: primary={len(primary)}, '
                          f'deferred={len(primary_deferred)}')
        elif verbose:
            print('  [*] A3 fork-flip gate skipped (no marker derivable)')
    gate_info = gate_info or {'skipped': True}

    out_dir = tfo._mutation_out_dir(input_file, version)
    tfo._mutation_clock_start()
    try:
        n_workers = int(os.environ.get('RETROSCOPE_MUTATION_WORKERS', '2'))
    except ValueError:
        n_workers = 2
    n_workers = max(1, min(n_workers, 4))

    seen_keys = {base_key}
    corpus = []
    tested = 0
    op_counts = {}
    matches = []
    matched = False
    budget_exhausted = False
    max_span = max(4096, min(8 * 1024 * 1024, 4 * len(original)))
    rng = random.Random(seed)
    seen_hashes = set()

    # A1 attribution probe: structured per-candidate record so a no-match run
    # can be explained (parse stage reached, error class, whether the fork
    # region was hit, which phase/offset tier produced the candidate).
    # Bounded so a large budget cannot grow the result JSON without limit.
    # Prefer the explicit root-cause function; fall back to the reference
    # crash top frame (legacy behaviour when fork_func was not supplied).
    attr_fork_func = (
        (fork_func or '').strip()
        or ((comp_ref_sig.get('crash_frames') or [{}])[0]
            .get('function') or ''))
    # Every project frame on the reference crash stack (generic process
    # frames filtered at comparison time in _behavior_signature): a
    # candidate crash sharing any of them proves the vulnerable call chain.
    attr_ref_stack = sorted({
        f.get('function')
        for f in (ref_sig.get('crash_frames') or [])
        if f.get('function')
    })
    attr_fork_file = fork_file or ''
    attr_fork_line = fork_line
    attribution = []
    _ATTR_CAP = 4000
    current_phase = {'name': 'init'}

    # Coverage-probe sampling: GDB line-breakpoint runs are expensive
    # (1-8s each), so only `reached_fork=unknown` candidates are eligible
    # (yes/no already have crash/parse evidence).  Bucket by behaviour so
    # a single loud class cannot exhaust the sample.
    _probe_jobs = []          # (record_index, candidate_bytes)
    _probe_bucket = {}
    _PROBE_PER_BUCKET = int(os.environ.get('RETROSCOPE_FORK_PROBE_BUCKET', '3'))
    _PROBE_MAX = int(os.environ.get('RETROSCOPE_FORK_PROBE_MAX', '48'))
    _PROBE_TIMEOUT = float(os.environ.get('RETROSCOPE_FORK_PROBE_TIMEOUT', '15'))
    _PROBE_BUDGET_S = float(os.environ.get('RETROSCOPE_FORK_PROBE_BUDGET', '90'))
    _probe_enabled = bool(attr_fork_file and attr_fork_line
                          and os.environ.get('RETROSCOPE_FORK_PROBE', '1')
                          not in ('0', 'false', 'no'))

    def _attribute(candidate, output, rc, sig, verdict=None):
        if len(attribution) >= _ATTR_CAP:
            return
        beh = _behavior_signature(
            output, rc, input_file,
            sig=sig,
            fork_func=attr_fork_func or None,
            fork_file=attr_fork_file or None,
            ref_stack_funcs=attr_ref_stack)
        rec = {
            'phase': current_phase['name'],
            'op': candidate.get('op'),
            'detail': candidate.get('detail'),
            'offsets': list(candidate.get('offsets') or [])[:8],
            'error_class': beh['error_class'],
            'parse_stage': beh['parse_stage'],
            'crash_func': beh['crash_func'],
            'crash_relation': beh['crash_relation'],
            'reached_fork': ('yes' if beh['reached_fork'] is True
                             else 'no' if beh['reached_fork'] is False
                             else 'unknown'),
            'fork_hit': None,
            'verdict': verdict,
            'key': beh['key'],
        }
        attribution.append(rec)
        # Schedule a coverage probe only when the heuristic cannot decide.
        if (_probe_enabled and rec['reached_fork'] == 'unknown'
                and len(_probe_jobs) < _PROBE_MAX):
            bucket = (beh['error_class'], beh['parse_stage'],
                      beh['crash_relation'])
            n = _probe_bucket.get(bucket, 0)
            if n < _PROBE_PER_BUCKET:
                _probe_bucket[bucket] = n + 1
                data = candidate.get('data')
                if data is not None:
                    _probe_jobs.append((len(attribution) - 1, data))

    def _summarize_attribution(records):
        def _count(field):
            out = {}
            for r in records:
                k = str(r.get(field))
                out[k] = out.get(k, 0) + 1
            return dict(sorted(out.items(), key=lambda kv: -kv[1]))

        def _fmt_fh(v):
            if v is True:
                return 'true'
            if v is False:
                return 'false'
            return 'null'

        def _cross(a, b):
            out = {}
            for r in records:
                ka = str(r.get(a))
                kb = _fmt_fh(r.get(b)) if b == 'fork_hit' else str(r.get(b))
                key = '%s|%s' % (ka, kb)
                out[key] = out.get(key, 0) + 1
            return dict(sorted(out.items(), key=lambda kv: -kv[1]))

        fh_counts = {'true': 0, 'false': 0, 'null': 0}
        for r in records:
            v = r.get('fork_hit')
            fh_counts['true' if v is True else
                      'false' if v is False else 'null'] += 1
        return {
            'total': len(records),
            'reached_fork': _count('reached_fork'),
            'error_class': _count('error_class'),
            'parse_stage': _count('parse_stage'),
            'crash_relation': _count('crash_relation'),
            'phase': _count('phase'),
            'verdict': _count('verdict'),
            'fork_hit': fh_counts,
            'death_mode': _count('death_mode'),
            'error_class_x_fork_hit': _cross('error_class', 'fork_hit'),
            'capped': len(attribution) >= _ATTR_CAP,
        }

    def _remember(candidate, output, rc, sig):
        key = _behavior_key(output, rc, input_file)
        if key in seen_keys:
            return
        seen_keys.add(key)
        if len(corpus) >= 24:
            drop = next((i for i, c in enumerate(corpus)
                         if not c.get('crash')), 0)
            corpus.pop(drop)
        corpus.append({
            'data': candidate['data'],
            'offsets': candidate['offsets'],
            'op': candidate['op'],
            'key': key,
            'crash': sig is not None,
            'output': output,
        })

    def _test_batch(batch):
        nonlocal tested, matched
        todo = []
        for candidate in batch:
            digest = hashlib.sha1(candidate['data']).digest()
            if digest in seen_hashes:
                continue
            seen_hashes.add(digest)
            todo.append(candidate)
        if not todo:
            return
        with ProcessPoolExecutor(max_workers=n_workers) as ex:
            futures = {}
            for candidate in todo:
                task = (real_target, candidate['data'], program_args,
                        input_file, per_timeout)
                futures[ex.submit(tfo._run_mutation_worker, task)] = candidate
            for future in as_completed(futures):
                candidate = futures[future]
                output, rc, _t_mut = future.result()
                tested += 1
                op_counts[candidate['op']] = op_counts.get(candidate['op'], 0) + 1
                sig = tfo.extract_crash_signature(output)
                _verdict = None
                if sig is not None:
                    tfo._attach_crash_statement(sig, real_target)
                    verdict, diff = tfo.compare_crash_signatures(
                        comp_ref_sig, sig)
                    _verdict = verdict
                    if verdict in ('same_func', 'same_site'):
                        elapsed = time.time() - p0_start
                        crash = sig['crash_frames'][0] \
                            if sig['crash_frames'] else {}
                        saved = _save_full_artifact(
                            out_dir,
                            f'p0:{candidate["detail"]}:'
                            f'time:{int(round(elapsed))}',
                            candidate['data'])
                        match = {
                            'operator': candidate['op'],
                            'detail': candidate['detail'],
                            'verdict': verdict,
                            'type': sig['type'],
                            'function': crash.get('function'),
                            'file': tfo._path_basename(crash.get('file')),
                            'line': crash.get('line'),
                            'rc': rc,
                            'time_to_success': round(elapsed, 3),
                            'saved': saved,
                        }
                        matches.append(match)
                        matched = True
                        _attribute(candidate, output, rc, sig, verdict)
                        if verbose:
                            print(f'    MATCH: {candidate["detail"]} '
                                  f'({verdict}: {diff})')
                            if saved:
                                print(f'      saved: {saved}')
                        return
                _attribute(candidate, output, rc, sig, _verdict)
                _remember(candidate, output, rc, sig)
        if verbose and tested and tested % 100 < len(todo):
            print(f'    tested {tested} candidate(s), '
                  f'novel behaviours: {len(seen_keys) - 1}, '
                  f'corpus: {len(corpus)}')

    def _run_phase(name, generator, cap, phase_seconds=None):
        """Run one mutation phase up to ``cap`` candidates.

        ``phase_seconds`` (optional) is a phase-local wall-clock budget —
        independent of the global ``budget_seconds`` deadline — used by
        the format-aware phase (300 cand / 120s contract).

        Env overrides (deep-dive / ablation):
          RETROSCOPE_PHASES=a,b,...     run only these phases (name or
                                        trailing component after '/').
          RETROSCOPE_PHASE_CAP_<NAME>   raise/lower this phase's cap.
          RETROSCOPE_PHASE_SECONDS_<NAME>  override phase_seconds.
        """
        nonlocal tested, budget_exhausted
        if matched:
            return
        only = os.environ.get('RETROSCOPE_PHASES', '').strip()
        if only:
            allowed = {p.strip() for p in only.split(',') if p.strip()}
            base = name.split('/')[-1]
            if name not in allowed and base not in allowed:
                return
        env_key = name.upper().replace('-', '_').replace('/', '_')
        cap_ov = os.environ.get(f'RETROSCOPE_PHASE_CAP_{env_key}')
        if cap_ov:
            try:
                cap = int(cap_ov)
            except ValueError:
                pass
        secs_ov = os.environ.get(f'RETROSCOPE_PHASE_SECONDS_{env_key}')
        if secs_ov:
            try:
                phase_seconds = float(secs_ov)
            except ValueError:
                pass
        cap = min(cap, max_candidates - tested)
        if cap <= 0:
            budget_exhausted = True
            return
        current_phase['name'] = name
        phase_deadline = (time.time() + float(phase_seconds)
                          if phase_seconds else None)
        if verbose:
            extra = (f' / {phase_seconds:.0f}s' if phase_seconds else '')
            print(f'\n  [phase {name}] cap={cap}{extra}')
        count = 0
        for batch in _batched(generator, 32):
            if matched or count >= cap:
                break
            if budget_seconds and time.time() > deadline:
                budget_exhausted = True
                break
            if phase_deadline and time.time() > phase_deadline:
                break
            batch = batch[:cap - count]
            if not batch:
                break
            _test_batch(batch)
            count += len(batch)
        if verbose:
            print(f'    phase {name}: {count} candidate(s) tested')

    def _feedback_round(round_no):
        nonlocal tested, budget_exhausted
        if matched or not corpus:
            return
        crash_seeds = [c for c in corpus if c.get('crash')]
        seeds = crash_seeds[-1:] + corpus[-4:]
        uniq = []
        for seed in seeds:
            if all(seed is not other for other in uniq):
                uniq.append(seed)
        seeds = uniq[:3]
        if verbose:
            print(f'\n  [feedback round {round_no}] '
                  f'{len(seeds)} seed(s)')
        generated = 0
        cap = min(220, max_candidates - tested)
        for seed_entry in seeds:
            if matched or generated >= cap:
                break
            if budget_seconds and time.time() > deadline:
                budget_exhausted = True
                break
            data = seed_entry['data']
            offsets = _feedback_offsets(seed_entry, structure)
            # C3: parse-depth feedback — if attribution says candidates
            # keep dying at a shallow stage, put structure fields first.
            offsets = _parse_depth_focus(attribution, structure, offsets)
            plans = [
                ('hints', _error_hint_candidates(
                    data, structure, endian,
                    seed_entry.get('output') or ''), 60),
                ('uniform', _uniform_field_candidates(
                    data, structure, endian, seed_entry['offsets']), 70),
                ('record', _record_candidates(
                    data, structure, offsets, endian), 40),
                ('neighbour', _mb_candidates(
                    data, offsets, endian, structure, sizes='native'), 40),
                ('coord', _coordinated_candidates(
                    data, structure, endian, offsets), 30),
                ('blocks', _block_candidates(
                    data, seed_entry['offsets'], anchors, max_span), 20),
            ]
            # Deep-dive phase filter also applies to feedback sub-phases
            # (they bypass _run_phase by setting current_phase directly).
            only_fb = os.environ.get('RETROSCOPE_PHASES', '').strip()
            if only_fb:
                allowed_fb = {p.strip() for p in only_fb.split(',')
                              if p.strip()}
                plans = [pl for pl in plans
                         if pl[0] in allowed_fb
                         or f'fb{round_no}/{pl[0]}' in allowed_fb]
            for label, gen, sub_cap in plans:
                if matched or generated >= cap:
                    break
                current_phase['name'] = f'fb{round_no}/{label}'
                sub_cap = min(sub_cap, cap - generated)
                count = 0
                for batch in _batched(gen, 32):
                    if matched or count >= sub_cap:
                        break
                    batch = batch[:sub_cap - count]
                    if not batch:
                        break
                    _test_batch(batch)
                    count += len(batch)
                generated += count
                if verbose and count:
                    print(f'    fb{round_no}/{label}: {count} tested')
            # havoc sub-phase only when explicitly allowed
            if not only_fb or 'havoc' in {
                    p.strip() for p in only_fb.split(',') if p.strip()} \
                    or any(p.strip().endswith('/havoc')
                           for p in only_fb.split(',') if p.strip()):
                current_phase['name'] = f'fb{round_no}/havoc'
                for _ in range(min(10, cap - generated)):
                    if matched:
                        break
                    new_data, touched = _havoc_one(
                        data, rng, offsets, structure, endian, max_span)
                    _test_batch([_cand('havoc', f'havoc-fb{round_no}',
                                       new_data, touched)])
                    generated += 1
        if verbose:
            print(f'    feedback round {round_no}: '
                  f'{generated} candidate(s) tested')

    _run_phase('dynamic-bytes',
               _byte_candidates(original, primary), 240)
    if not matched:
        _run_phase('dynamic-exact',
                   _mb_candidates(original, primary, endian, structure,
                                  sizes='native'), 120)
    if not matched:
        _run_phase('dynamic-neighbourhood',
                   _mb_candidates(original, neigh, endian, structure,
                                  sizes='native'), 300)
    if not matched:
        _feedback_round(1)
    if not matched:
        _run_phase('dynamic-blocks',
                   _block_candidates(original, primary + neigh, anchors,
                                     max_span), 120)
    if not matched:
        _run_phase('record-layout',
                   _record_candidates(original, structure, primary, endian),
                   80)
    if not matched:
        _run_phase('structure-uniform',
                   _uniform_field_candidates(original, structure, endian,
                                             primary), 100)
    # B: format-aware phase — independent format_profiles package
    # (parse/validate/repair/value_domain/mutate_field).  Budget contract:
    # 300 candidates / 120s, strictly additive; unknown format => no-op.
    if not matched:
        _run_phase('format-aware',
                   _format_candidates(original, structure, primary),
                   300, phase_seconds=120.0)
    # C1: coordinated multi-field rewrites from format dependency groups
    # (one candidate = one consistent group rewrite).  300 / 120s.
    if not matched:
        _run_phase('coordinated',
                   _coordinated_candidates(original, structure, endian,
                                           primary),
                   300, phase_seconds=120.0)
    # C2: grammar-token insert/replace + recompress operators.  300 / 120s.
    if not matched:
        _run_phase('grammar-compress',
                   _grammar_candidates(original, structure, endian,
                                       primary, cap=150),
                   150, phase_seconds=60.0)
    if not matched:
        _run_phase('compress',
                   _compression_candidates(original, structure, endian,
                                           primary, cap=150),
                   150, phase_seconds=60.0)
    if not matched:
        _feedback_round(2)
    if not matched:
        _run_phase('dynamic-structure',
                   _mb_candidates(original, struct_offsets, endian,
                                  structure, sizes='native'), 160)
    if not matched:
        _feedback_round(3)
    # A3 deferred pool: offsets that failed the flip gate still get a
    # small late chance (the marker can be imperfect) before static.
    if not matched and primary_deferred:
        _run_phase('dynamic-deferred',
                   _mb_candidates(original, primary_deferred, endian,
                                  structure, sizes='native'), 60)
    if not matched:
        _run_phase('static-offsets',
                   _mb_candidates(original, static, endian, structure,
                                  sizes='native'), 120)
    if not matched:
        _run_phase('static-blocks',
                   _block_candidates(original, static, anchors, max_span),
                   80)
    if not matched:
        havoc_gen = (_havoc_one(original, rng, primary + neigh, structure,
                                endian, max_span)
                     for _ in range(100))
        _run_phase(
            'havoc',
            (_cand('havoc', f'havoc{i}', data, touched)
             for i, (data, touched) in enumerate(havoc_gen)),
            100)
    if not matched and corpus:
        splices = []
        for i, entry in enumerate(corpus[:20]):
            other = entry['data']
            if len(other) < 2:
                continue
            cut = rng.randrange(1, min(len(original), len(other)))
            splices.append(_cand('splice', f'splice{i}@{cut:#x}',
                                 original[:cut] + other[cut:], [cut]))
        if splices:
            _run_phase('splice', iter(splices), len(splices))

    # Coverage probes: resolve remaining `unknown` reached_fork via GDB
    # line breakpoint (verify_fork_path.verify_one).  Sampled during
    # _attribute; run post-phase so mutation throughput is unaffected.
    probe_stats = {
        'scheduled': len(_probe_jobs),
        'ran': 0, 'hit': 0, 'miss': 0, 'failed': 0,
        'enabled': _probe_enabled,
        'budget_seconds': _PROBE_BUDGET_S,
    }
    if _probe_jobs:
        probe_deadline = time.time() + _PROBE_BUDGET_S
        for idx, data in _probe_jobs:
            if idx >= len(attribution):
                continue
            if time.time() > probe_deadline:
                break
            hit = _fork_coverage_probe(
                real_target, attr_fork_file, attr_fork_line, data,
                program_args, input_file, timeout=int(_PROBE_TIMEOUT) or 15)
            probe_stats['ran'] += 1
            if hit is True:
                probe_stats['hit'] += 1
                attribution[idx]['fork_hit'] = True
            elif hit is False:
                probe_stats['miss'] += 1
                attribution[idx]['fork_hit'] = False
            else:
                probe_stats['failed'] += 1

    # Death-mode taxonomy on every record (uses fork_hit when the
    # coverage probe ran, else falls back to the A1 heuristic).
    for rec in attribution:
        rec['death_mode'] = _classify_death_mode(rec)

    elapsed = time.time() - p0_start
    attr_summary = _summarize_attribution(attribution)
    attr_summary['coverage_probe'] = probe_stats
    if verbose:
        print(f'\n  Step 6f summary: tested={tested}, matched={matched}, '
              f'novel_behaviours={len(seen_keys) - 1}, '
              f'corpus={len(corpus)}, elapsed={elapsed:.1f}s'
              + (', budget exhausted' if budget_exhausted else ''))
        # A1 attribution: why the candidates did (not) reach the fork.
        rf = attr_summary.get('reached_fork') or {}
        ec = attr_summary.get('error_class') or {}
        print('  Attribution (A1): reached_fork='
              + ', '.join(f'{k}:{v}' for k, v in rf.items())
              + ' | error='
              + ', '.join(f'{k}:{v}' for k, v in
                          list(ec.items())[:6]))
        cr = attr_summary.get('crash_relation') or {}
        if cr:
            print('  Attribution (A1): crash_relation='
                  + ', '.join(f'{k}:{v}' for k, v in cr.items()))
        ps = attr_summary.get('parse_stage') or {}
        if ps:
            print('  Attribution (A1): parse_stage='
                  + ', '.join(f'{k}:{v}' for k, v in ps.items()))
        fh = attr_summary.get('fork_hit') or {}
        if any(fh.get(k) for k in ('true', 'false')):
            print('  Attribution (coverage): fork_hit='
                  + ', '.join(f'{k}:{v}' for k, v in fh.items())
                  + f" (probe ran={probe_stats['ran']}/"
                  f"{probe_stats['scheduled']})")
        dm = attr_summary.get('death_mode') or {}
        if dm:
            print('  Attribution (death modes): '
                  + ', '.join(f'{k}:{v}' for k, v in dm.items()))

    results = {
        'enabled': True,
        'format_profile': fmt_name,
        'primary_offsets': primary,
        'primary_deferred_offsets': primary_deferred,
        'fork_flip_gate': gate_info,
        'dynamic_neighbourhood': neigh,
        'dynamic_structure_offsets': struct_offsets,
        'static_offsets': static,
        'candidates_tested': tested,
        'matched': matched,
        'matches': matches,
        'novel_behaviours': len(seen_keys) - 1,
        'corpus_seeds': len(corpus),
        'operators': op_counts,
        'budget_exhausted': budget_exhausted,
        'elapsed_seconds': round(elapsed, 3),
        'attribution_summary': attr_summary,
        'attribution_records': attribution,
        'coverage_probe': probe_stats,
    }
    return results, matched
