"""AutoCAD DWG profile (R13+ magic headers).

DWG's on-disk layout is version-specific and heavily compressed in recent
releases; this profile targets the stable prefix every version shares —
the 6-byte ``AC10xx`` version string plus the fixed header fields that
libredwg's header reader bounds-checks (version, maintenance, codepage,
and for R2004+ the section-page-map related header words).
"""

from __future__ import annotations

import struct
from typing import Any, Dict, Iterable, List, Optional, Sequence

from .base import (
    FIELD_CAP, FormatProfile, MB_VALUES, cand, mutate_bytes, mutate_int,
    pack_region, read_int,
)

# Known version strings (R13 -> R2018).
_VERSIONS = [
    b'AC1012', b'AC1014', b'AC1015', b'AC1018', b'AC1021', b'AC1024',
    b'AC1027', b'AC1032',
]

# Header field offsets shared by R2000 (AC1015) and later.  Values are
# best-effort from libredwg's header read order; fields the reader
# bounds-checks are preferred.
#
# layout (post-version, all little-endian unless noted):
#   +0x06  5B  unknown (usually 0)
#   +0x0B  1B  maintenance / zero byte
#   +0x0C  2B  codepage (AC1015+)
#   ... version-specific; we expose a conservative fixed grid so the
#   directed sweep has stable positions even when the exact semantic
#   differs across releases.
_HEADER_FIELDS_AC1015 = [
    (0x00, 6, 'magic', 'version'),
    (0x06, 5, 'desc', 'unknown'),
    (0x0B, 1, 'flag', 'maintenance'),
    (0x0C, 2, 'enum', 'codepage'),
    (0x0E, 4, 'size', 'header_words_a'),
    (0x12, 4, 'offset', 'header_words_b'),
    (0x16, 4, 'count', 'header_count'),
    (0x1A, 4, 'offset', 'header_offset'),
    (0x1E, 4, 'size', 'header_size'),
    (0x22, 4, 'flag', 'header_flags'),
    (0x26, 4, 'offset', 'section_map_off'),
    (0x2A, 4, 'size', 'section_map_size'),
    (0x2E, 4, 'count', 'section_count'),
    (0x32, 4, 'offset', 'section_array_off'),
    (0x36, 4, 'size', 'section_array_size'),
    (0x3A, 4, 'flag', 'section_flags'),
    (0x3E, 4, 'offset', 'object_map_off'),
    (0x42, 4, 'size', 'object_map_size'),
    (0x46, 4, 'count', 'object_count'),
    (0x4A, 4, 'offset', 'object_array_off'),
    (0x4E, 4, 'size', 'object_array_size'),
    (0x52, 4, 'flag', 'object_flags'),
    (0x56, 4, 'offset', 'second_header_off'),
    (0x5A, 4, 'size', 'second_header_size'),
    (0x5E, 4, 'count', 'handle_count'),
    (0x62, 4, 'offset', 'handle_map_off'),
    (0x66, 4, 'size', 'handle_map_size'),
    (0x6A, 4, 'flag', 'handle_flags'),
    (0x6E, 4, 'offset', 'aux_header_off'),
    (0x72, 4, 'size', 'aux_header_size'),
    (0x76, 4, 'count', 'aux_count'),
    (0x7A, 4, 'offset', 'aux_array_off'),
    (0x7E, 4, 'size', 'aux_array_size'),
]


class DwgProfile(FormatProfile):
    name = 'dwg'

    @classmethod
    def detect(cls, data: bytes) -> bool:
        return len(data) >= 6 and data[:2] == b'AC' and data[2:6].isdigit()

    def parse(self, data: bytes) -> Optional[Dict[str, Any]]:
        if not self.detect(data):
            return None
        version = data[:6]
        little = True
        fields: List[Dict[str, Any]] = []
        # Version string as a magic field (6 bytes).
        fields.append({'offset': 0, 'size': 6, 'kind': 'magic',
                       'name': 'version', 'little': little,
                       'value': int.from_bytes(version, 'big')})
        # Fixed header grid.  R13/R14 (AC1012/AC1014) share the AC1015
        # layout closely enough for directed mutation; cap to file size.
        for off, size, kind, name in _HEADER_FIELDS_AC1015[1:]:
            if off + size > len(data):
                break
            val = read_int(data, off, size, little)
            fields.append({'offset': off, 'size': size, 'kind': kind,
                           'name': name, 'little': little, 'value': val})
        # For R2004+ (AC1018+) the header is longer — add a second grid
        # of u32 words the section-page reader inspects.
        if version in (b'AC1018', b'AC1021', b'AC1024', b'AC1027',
                       b'AC1032'):
            for off in range(0x80, min(0x100, len(data) - 4), 4):
                val = read_int(data, off, 4, little)
                fields.append({'offset': off, 'size': 4, 'kind': 'offset',
                               'name': f'hdr32_{off:#x}', 'little': little,
                               'value': val})
                if len(fields) >= FIELD_CAP:
                    break
        return pack_region(
            'dwg', 'DWG version/header fields', 0, len(fields), None, 0,
            fields, extra={'little': little, 'version': version.decode(
                'ascii', 'replace')})

    def validate(self, data: bytes,
                 structure: Dict[str, Any]) -> List[Dict[str, Any]]:
        issues: List[Dict[str, Any]] = []
        if len(data) < 6 or data[:2] != b'AC':
            issues.append({'kind': 'bad_magic', 'offset': 0, 'size': 6,
                           'msg': 'missing AC10xx version string'})
            return issues
        ver = data[:6]
        if ver not in _VERSIONS:
            issues.append({'kind': 'unknown_version', 'offset': 0, 'size': 6,
                           'msg': f'unknown DWG version {ver!r}'})
        # Offset/size pairs that must land inside the file.
        little = bool(structure.get('little', True))
        for f in structure.get('fields') or []:
            kind = f.get('kind')
            name = f.get('name') or ''
            off = f.get('offset')
            size = int(f.get('size') or 0)
            if not isinstance(off, int) or kind not in (
                    'offset', 'size', 'count'):
                continue
            val = read_int(data, off, size, little)
            if val is None:
                continue
            # Only flag obviously-out-of-file offsets (high words that
            # exceed the file by a wide margin) — small values are often
            # relative or version-specific.
            if kind == 'offset' and val > len(data) and val > 0x1000:
                issues.append({'kind': 'offset_oob', 'offset': off,
                               'size': size, 'field': name,
                               'msg': f'{name}={val:#x} outside file '
                                      f'({len(data)} bytes)'})
            if kind == 'size' and val > len(data) and val > 0x1000:
                issues.append({'kind': 'size_oob', 'offset': off,
                               'size': size, 'field': name,
                               'msg': f'{name}={val:#x} larger than file'})
        return issues

    def repair(self, data: bytes, structure: Dict[str, Any],
               issues: Sequence[Dict[str, Any]]) -> Iterable[Dict[str, Any]]:
        for issue in issues:
            kind = issue.get('kind')
            off = issue.get('offset')
            if not isinstance(off, int):
                continue
            if kind == 'bad_magic':
                for ver in _VERSIONS:
                    new = mutate_bytes(data, 0, ver)
                    if new:
                        yield cand('fmt-repair',
                                   f'fmt-dwg-ver={ver.decode()}', new, [0],
                                   desc='rewrite DWG version string')
            elif kind == 'unknown_version':
                # Snap to nearest known version by shared prefix.
                cur = data[:6]
                best = min(_VERSIONS,
                           key=lambda v: sum(a != b for a, b in zip(v, cur)))
                new = mutate_bytes(data, 0, best)
                if new:
                    yield cand('fmt-repair',
                               f'fmt-dwg-ver={best.decode()}', new, [0],
                               desc='snap DWG version to known release')
            elif kind in ('offset_oob', 'size_oob'):
                fsize = len(data)
                for v in (0, 8, 16, fsize // 2, max(0, fsize - 4)):
                    size = int(issue.get('size') or 4)
                    new = mutate_int(data, off, size, v, True)
                    if new:
                        yield cand('fmt-repair',
                                   f'fmt-dwg-oob@{off:#x}={v}', new, [off],
                                   desc='clamp DWG header offset/size')

    def value_domain(self, field: Dict[str, Any]) -> List[int]:
        kind = field.get('kind')
        name = field.get('name') or ''
        size = int(field.get('size') or 1)
        if kind == 'magic' or name == 'version':
            # Whole-version rewrites are emitted by repair(); here only
            # single-byte probes of the version string.
            return [0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x38, 0x39,
                    0x41, 0x43, 0x00, 0xff]
        if kind == 'enum' and name == 'codepage':
            return [0, 30, 1252, 1250, 1251, 932, 936, 949, 950, 0xffff]
        if kind == 'flag':
            return [0, 1, 2, 4, 8, 0x10, 0x20, 0x40, 0x80, 0xff,
                    0xffff, 0xffffffff][:max(1, min(12, 1 << (8 * min(size, 2))))]
        if kind in ('offset', 'size', 'count'):
            vals = [0, 1, 2, 4, 8, 16, 32, 64, 128, 256, 1024, 4096]
            fsize_hint = MB_VALUES.get(size, [])
            for v in fsize_hint:
                if v not in vals:
                    vals.append(v)
            return vals[:20]
        return super().value_domain(field)
