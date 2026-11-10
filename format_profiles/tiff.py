"""TIFF / BigTIFF IFD profile."""

from __future__ import annotations

import struct
from typing import Any, Dict, Iterable, List, Optional, Sequence

from .base import (
    FIELD_CAP, FormatProfile, MB_VALUES, cand, mutate_int, pack_region,
    read_int,
)

# Classic TIFF tag -> meaning-bearing low-byte rewrites (tag field is
# little-endian u16; the classic RowsPerStrip 278 -> StripByteCounts 279
# case is the archetype).
_TAG_LOW_BYTES = [
    0x00, 0x01, 0x02, 0x03, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
    0x17, 0x18, 0x19, 0x1a, 0x1c, 0x1f, 0x20, 0x28, 0x40, 0x7f, 0xff,
]
_TYPE_BYTES = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
               0x0a, 0x0b, 0x0c, 0x0d, 0x10, 0x11, 0x12, 0xff]
_COUNT_BYTES = [0x00, 0x01, 0x02, 0x03, 0x10, 0x7f, 0xff]
_VALUE_BYTES = [0x00, 0x01, 0x02, 0x08, 0x10, 0x40, 0x7f, 0xff]


class TiffProfile(FormatProfile):
    name = 'tiff'

    @classmethod
    def detect(cls, data: bytes) -> bool:
        if len(data) < 8:
            return False
        if data[:2] not in (b'II', b'MM'):
            return False
        little = data[:2] == b'II'
        magic = read_int(data, 2, 2, little)
        return magic in (42, 43)  # classic or BigTIFF

    def parse(self, data: bytes) -> Optional[Dict[str, Any]]:
        if len(data) < 8 or data[:2] not in (b'II', b'MM'):
            return None
        little = data[:2] == b'II'
        magic = read_int(data, 2, 2, little)
        if magic == 43:  # BigTIFF
            return self._parse_bigtiff(data, little)
        if magic != 42:
            return None
        ifd_off = read_int(data, 4, 4, little)
        if ifd_off is None or ifd_off + 2 > len(data):
            return None
        count = read_int(data, ifd_off, 2, little)
        if not count:
            return None
        entries_base = ifd_off + 2
        max_entries = max(0, (len(data) - entries_base) // 12)
        count = min(count, max_entries)
        if count <= 0:
            return None
        fields: List[Dict[str, Any]] = []
        for i in range(min(count, FIELD_CAP // 4)):
            base = entries_base + i * 12
            if base + 12 > len(data):
                break
            tag = read_int(data, base, 2, little) or 0
            typ = read_int(data, base + 2, 2, little) or 0
            cnt = read_int(data, base + 4, 4, little) or 0
            val = read_int(data, base + 8, 4, little) or 0
            for rel, size, kind, fname, fval in (
                    (0, 2, 'tag', 'tag', tag),
                    (2, 2, 'enum', 'type', typ),
                    (4, 4, 'count', 'count', cnt),
                    (8, 4, 'offset', 'value', val)):
                fields.append({
                    'offset': base + rel, 'size': size, 'kind': kind,
                    'name': f'{fname}[{i}]', 'value': fval, 'little': little,
                    'entry_index': i, 'field': fname,
                })
        return pack_region(
            'tiff', 'TIFF IFD entries', ifd_off, count, 12, entries_base,
            fields, extra={'ifd_offset': ifd_off, 'little': little,
                           'bigendian': not little})

    def _parse_bigtiff(self, data: bytes, little: bool) -> Optional[Dict[str, Any]]:
        # offset/size (8), count (8), entries 20 bytes each
        if len(data) < 16:
            return None
        ifd_off = read_int(data, 8, 8, little)
        if ifd_off is None or ifd_off + 8 > len(data):
            return None
        count = read_int(data, ifd_off, 8, little)
        if not count:
            return None
        entries_base = ifd_off + 8
        max_entries = max(0, (len(data) - entries_base) // 20)
        count = min(count, max_entries, FIELD_CAP // 5)
        if count <= 0:
            return None
        fields: List[Dict[str, Any]] = []
        for i in range(count):
            base = entries_base + i * 20
            if base + 20 > len(data):
                break
            tag = read_int(data, base, 2, little) or 0
            typ = read_int(data, base + 2, 2, little) or 0
            cnt = read_int(data, base + 4, 8, little) or 0
            val = read_int(data, base + 12, 8, little) or 0
            for rel, size, kind, fname, fval in (
                    (0, 2, 'tag', 'tag', tag),
                    (2, 2, 'enum', 'type', typ),
                    (4, 8, 'count', 'count', cnt),
                    (12, 8, 'offset', 'value', val)):
                fields.append({
                    'offset': base + rel, 'size': size, 'kind': kind,
                    'name': f'{fname}[{i}]', 'value': fval, 'little': little,
                    'entry_index': i, 'field': fname,
                })
        return pack_region(
            'tiff', 'BigTIFF IFD entries', ifd_off, count, 20, entries_base,
            fields, extra={'ifd_offset': ifd_off, 'little': little,
                           'bigendian': not little, 'bigtiff': True})

    def validate(self, data: bytes,
                 structure: Dict[str, Any]) -> List[Dict[str, Any]]:
        issues: List[Dict[str, Any]] = []
        ifd_off = structure.get('ifd_offset')
        count = structure.get('count')
        es = int(structure.get('entry_size') or 12)
        base = structure.get('entries_base')
        if not isinstance(ifd_off, int) or ifd_off < 0 \
                or ifd_off + 2 > len(data):
            issues.append({'kind': 'ifd_oob', 'offset': 0, 'size': 4,
                           'msg': 'IFD offset outside file'})
            return issues
        if isinstance(count, int) and isinstance(base, int):
            end = base + count * es
            if end > len(data):
                issues.append({'kind': 'ifd_truncated', 'offset': base,
                               'size': 4,
                               'msg': f'IFD entries extend past EOF '
                                      f'({end} > {len(data)})'})
        # Per-entry: type size * count must fit either inline (<=4/8) or
        # via the value/offset field pointing inside the file.
        little = bool(structure.get('little', True))
        type_sizes = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 1, 7: 1, 8: 2,
                      9: 4, 10: 8, 11: 4, 12: 8, 13: 4, 16: 8, 17: 8}
        inline = 4 if es == 12 else 8
        n = int(count or 0)
        for i in range(n):
            start = (base or 0) + i * es
            if start + es > len(data):
                break
            typ = read_int(data, start + 2, 2, little) or 0
            cnt = read_int(data, start + 4, 4 if es == 12 else 8, little) or 0
            val = read_int(data, start + 8 if es == 12 else start + 12,
                           4 if es == 12 else 8, little) or 0
            tsz = type_sizes.get(typ)
            if tsz is None or typ == 0:
                issues.append({'kind': 'bad_type', 'offset': start + 2,
                               'size': 2, 'entry': i,
                               'msg': f'entry {i}: invalid type {typ}'})
                continue
            nbytes = tsz * cnt
            if nbytes > inline:
                # value is an offset — must land inside the file
                if val < 0 or val + min(nbytes, 1) > len(data):
                    issues.append({'kind': 'value_oob', 'offset': start + 8,
                                   'size': 4, 'entry': i,
                                   'msg': f'entry {i}: data offset {val} '
                                          f'outside file'})
            elif nbytes < 0:
                issues.append({'kind': 'bad_count', 'offset': start + 4,
                               'size': 4, 'entry': i,
                               'msg': f'entry {i}: negative count'})
        return issues

    def repair(self, data: bytes, structure: Dict[str, Any],
               issues: Sequence[Dict[str, Any]]) -> Iterable[Dict[str, Any]]:
        little = bool(structure.get('little', True))
        es = int(structure.get('entry_size') or 12)
        base = int(structure.get('entries_base') or 0)
        count = int(structure.get('count') or 0)
        for issue in issues:
            kind = issue.get('kind')
            off = issue.get('offset')
            if not isinstance(off, int):
                continue
            if kind == 'ifd_oob':
                # Point IFD at offset 8 (first byte after header) — a
                # plausible in-file directory location.
                new = mutate_int(data, 4, 4, 8, little)
                if new:
                    yield cand('fmt-repair', 'fmt-tiff-ifd@8', new, [4],
                              desc='reset IFD offset to 8')
            elif kind == 'ifd_truncated' and isinstance(base, int):
                # Clamp entry count so the directory fits.
                max_n = max(0, (len(data) - base) // es)
                if max_n < count and max_n >= 0:
                    csize = 2 if es == 12 else 8
                    c_off = int(structure.get('ifd_offset') or 0)
                    new = mutate_int(data, c_off, csize, max_n, little)
                    if new:
                        yield cand('fmt-repair',
                                   f'fmt-tiff-count={max_n}', new, [c_off],
                                   desc='clamp IFD entry count to EOF')
            elif kind == 'bad_type':
                entry = issue.get('entry')
                if isinstance(entry, int):
                    start = base + entry * es
                    for t in (4, 3, 1, 2):
                        new = mutate_int(data, start + 2, 2, t, little)
                        if new:
                            yield cand('fmt-repair',
                                       f'fmt-tiff-type[{entry}]={t}', new,
                                       [start + 2],
                                       desc='rewrite invalid IFD type')
            elif kind == 'value_oob':
                entry = issue.get('entry')
                if isinstance(entry, int):
                    start = base + entry * es
                    voff = start + (8 if es == 12 else 12)
                    vsize = 4 if es == 12 else 8
                    for v in (0, 8, 16, len(data) // 2):
                        new = mutate_int(data, voff, vsize, v, little)
                        if new:
                            yield cand('fmt-repair',
                                       f'fmt-tiff-val[{entry}]={v}', new,
                                       [voff],
                                       desc='clamp IFD value offset')

    def value_domain(self, field: Dict[str, Any]) -> List[int]:
        fname = field.get('field')
        size = int(field.get('size') or 1)
        if fname == 'tag':
            # Prefer full u16 tag rewrites built from the low-byte set.
            out = list(_TAG_LOW_BYTES)
            for hi in (0x00, 0x01, 0x02, 0x03, 0x80, 0x81, 0xff):
                for lo in _TAG_LOW_BYTES:
                    v = (hi << 8) | lo
                    if v not in out:
                        out.append(v)
            return out[:48]
        if fname == 'type':
            return list(_TYPE_BYTES)
        if fname == 'count':
            return list(_COUNT_BYTES) + [0, 1, 2, 3, 4, 8, 16, 256,
                                         0x7fffffff, 0xffffffff][:6]
        if fname == 'value':
            return list(_VALUE_BYTES) + MB_VALUES[size][:12]
        return super().value_domain(field)
