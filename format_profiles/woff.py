"""sfnt (TTF/OTF/TTC) and WOFF table-directory profile."""

from __future__ import annotations

import struct
from typing import Any, Dict, Iterable, List, Optional, Sequence

from .base import (
    FIELD_CAP, FormatProfile, MB_VALUES, cand, mutate_int, pack_region,
    read_int,
)

_SFNT_SIGS = (b'\x00\x01\x00\x00', b'OTTO', b'true', b'typ1')


class FontProfile(FormatProfile):
    name = 'font'

    @classmethod
    def detect(cls, data: bytes) -> bool:
        if len(data) < 4:
            return False
        return data[:4] in _SFNT_SIGS or data[:4] == b'ttcf' \
            or data[:4] == b'wOFF' or data[:4] == b'wOF2'

    def parse(self, data: bytes) -> Optional[Dict[str, Any]]:
        if not self.detect(data):
            return None
        sig = data[:4]
        fields: List[Dict[str, Any]] = []

        def add(off: int, size: int, kind: str, name: str, value=None,
                little: bool = False):
            if 0 <= off and off + size <= len(data):
                fields.append({'offset': off, 'size': size, 'kind': kind,
                               'name': name, 'value': value, 'little': little})

        def u16be(o: int) -> Optional[int]:
            return read_int(data, o, 2, little=False)

        def u32be(o: int) -> Optional[int]:
            return read_int(data, o, 4, little=False)

        if sig == b'wOFF':
            add(0, 4, 'magic', 'signature')
            add(4, 4, 'magic', 'flavor')
            add(8, 4, 'size', 'length', u32be(8))
            add(12, 2, 'count', 'numTables', u16be(12))
            add(14, 2, 'enum', 'reserved')
            add(16, 4, 'size', 'totalSfntSize', u32be(16))
            add(20, 2, 'enum', 'majorVersion')
            add(22, 2, 'enum', 'minorVersion')
            num = u16be(12) or 0
            for i in range(min(num, 32)):
                rec = 44 + i * 20
                if rec + 16 > len(data):
                    break
                add(rec, 4, 'tag', f'table[{i}].tag')
                add(rec + 4, 4, 'offset', f'table[{i}].offset',
                    u32be(rec + 4))
                add(rec + 8, 4, 'size', f'table[{i}].compLength',
                    u32be(rec + 8))
                add(rec + 12, 4, 'size', f'table[{i}].origLength',
                    u32be(rec + 12))
                add(rec + 16, 4, 'size', f'table[{i}].origChecksum',
                    u32be(rec + 16))
            return pack_region('woff', 'WOFF table directory', 44, num, 20,
                               44, fields,
                               extra={'little': False, 'woff': True})
        if sig == b'wOF2':
            # WOFF2: compressed — expose only the fixed prefix.
            add(0, 4, 'magic', 'signature')
            add(4, 4, 'magic', 'flavor')
            add(8, 4, 'size', 'length', u32be(8))
            add(12, 4, 'count', 'numTables', u32be(12))
            add(16, 2, 'enum', 'reserved')
            add(18, 4, 'size', 'totalSfntSize', u32be(18) if False else
                read_int(data, 18, 4, False))
            add(22, 4, 'size', 'totalCompressedSize',
                read_int(data, 22, 4, False))
            return pack_region('woff2', 'WOFF2 header', 0, 1, None, 0,
                               fields, extra={'little': False, 'woff2': True})
        if sig == b'ttcf':
            num_fonts = u32be(8) or 0
            add(0, 4, 'magic', 'ttcf')
            add(4, 4, 'enum', 'version')
            add(8, 4, 'count', 'numFonts', num_fonts)
            add(12, 4, 'offset', 'font[0]', u32be(12))
            if num_fonts < 1:
                return None
            base = u32be(12) or 0
            # Fall through to sfnt parse at ``base`` — only expose the
            # first font's directory to stay within FIELD_CAP.
            sig = data[base:base + 4] if base + 4 <= len(data) else b''
        if sig in _SFNT_SIGS:
            base = 0 if sig != b'ttcf' else (u32be(12) or 0)
            # When called after ttcf fall-through, base is already set;
            # for plain sfnt base=0.
            if sig in _SFNT_SIGS and data[:4] in _SFNT_SIGS:
                base = 0
            add(base, 4, 'magic', 'sfnt_version')
            num = u16be(base + 4) or 0
            add(base + 4, 2, 'count', 'numTables', num)
            add(base + 6, 2, 'count', 'searchRange', u16be(base + 6))
            add(base + 8, 2, 'count', 'entrySelector', u16be(base + 8))
            add(base + 10, 2, 'count', 'rangeShift', u16be(base + 10))
            for i in range(min(num, 32)):
                rec = base + 12 + i * 16
                if rec + 16 > len(data):
                    break
                add(rec, 4, 'tag', f'table[{i}].tag')
                add(rec + 4, 4, 'size', f'table[{i}].checksum',
                    u32be(rec + 4))
                add(rec + 8, 4, 'offset', f'table[{i}].offset',
                    u32be(rec + 8))
                add(rec + 12, 4, 'size', f'table[{i}].length',
                    u32be(rec + 12))
            fmt = 'ttc' if data[:4] == b'ttcf' else 'sfnt'
            return pack_region(fmt, f'{fmt} table directory',
                               base + 12, num, 16, base + 12, fields,
                               extra={'little': False, 'sfnt_base': base})
        return None

    def validate(self, data: bytes,
                 structure: Dict[str, Any]) -> List[Dict[str, Any]]:
        issues: List[Dict[str, Any]] = []
        if not self.detect(data):
            issues.append({'kind': 'bad_magic', 'offset': 0, 'size': 4,
                           'msg': 'missing sfnt/WOFF signature'})
            return issues
        little = bool(structure.get('little', False))
        fmt = structure.get('format')
        num = int(structure.get('count') or 0)
        base = int(structure.get('entries_base') or 0)
        es = int(structure.get('entry_size') or 16)
        # numTables must be consistent with the directory size.
        if num and base + num * es > len(data):
            issues.append({'kind': 'dir_truncated', 'offset': base,
                           'size': 4,
                           'msg': f'table directory ({num} x {es}) past EOF'})
        # Per-table offset/length must land inside the file.
        for i in range(min(num, 32)):
            rec = base + i * es
            if rec + es > len(data):
                break
            if fmt == 'woff':
                off = read_int(data, rec + 4, 4, little=False)
                comp = read_int(data, rec + 8, 4, little=False)
                orig = read_int(data, rec + 12, 4, little=False)
                length = comp or 0
            else:
                off = read_int(data, rec + 8, 4, little=False)
                length = read_int(data, rec + 12, 4, little=False) or 0
                orig = length
            if off is None:
                continue
            if off > len(data) or (length and off + length > len(data)):
                issues.append({'kind': 'table_oob', 'offset': rec + (
                    4 if fmt == 'woff' else 8), 'size': 4, 'table': i,
                    'msg': f'table {i} [{off:#x}+{length}] outside file'})
            if orig and length and fmt == 'woff' and orig < length:
                issues.append({'kind': 'woff_len_inconsistent',
                               'offset': rec + 12, 'size': 4, 'table': i,
                               'msg': f'table {i} origLength {orig} < '
                                      f'compLength {length}'})
        # sfnt searchRange/entrySelector/rangeShift consistency (soft).
        if fmt in ('sfnt', 'ttc') and num:
            import math
            esz = structure.get('sfnt_base', 0) or 0
            expect_sr = (1 << int(math.floor(math.log2(max(num, 1))))) * 16
            sr = read_int(data, esz + 6, 2, little=False)
            if sr is not None and num <= 0x4000 and sr != expect_sr:
                issues.append({'kind': 'bad_search_range',
                               'offset': esz + 6, 'size': 2,
                               'msg': f'searchRange {sr} != expected '
                                      f'{expect_sr}'})
        return issues

    def repair(self, data: bytes, structure: Dict[str, Any],
               issues: Sequence[Dict[str, Any]]) -> Iterable[Dict[str, Any]]:
        little = bool(structure.get('little', False))
        fmt = structure.get('format')
        base = int(structure.get('entries_base') or 0)
        es = int(structure.get('entry_size') or 16)
        fsize = len(data)
        for issue in issues:
            kind = issue.get('kind')
            off = issue.get('offset')
            if not isinstance(off, int):
                continue
            if kind == 'bad_magic':
                for sig in _SFNT_SIGS + (b'wOFF', b'ttcf'):
                    new = bytearray(data)
                    new[:4] = sig
                    yield cand('fmt-repair',
                               f'fmt-font-sig={sig.hex()}', bytes(new),
                               [0], desc='rewrite font signature')
            elif kind == 'dir_truncated':
                # Clamp numTables so the directory fits.
                max_n = max(0, (fsize - base) // es) if es else 0
                # numTables sits at base-8+4 for sfnt (base=entries_base
                # = 12 for plain sfnt) — recover from structure.
                n_off = None
                if fmt in ('sfnt', 'ttc'):
                    sbase = int(structure.get('sfnt_base') or 0)
                    n_off = sbase + 4
                elif fmt == 'woff':
                    n_off = 12
                if n_off is not None and max_n < (structure.get('count') or 0):
                    new = mutate_int(data, n_off, 2, max(1, max_n),
                                     little=False)
                    if new:
                        yield cand('fmt-repair',
                                   f'fmt-font-numtables={max_n}', new,
                                   [n_off],
                                   desc='clamp numTables to file size')
            elif kind == 'table_oob':
                table = issue.get('table')
                if isinstance(table, int):
                    rec = base + table * es
                    if fmt == 'woff':
                        o_off, l_off = rec + 4, rec + 8
                    else:
                        o_off, l_off = rec + 8, rec + 12
                    for v in (0, 12, 16, fsize // 2, max(0, fsize - 4)):
                        new = mutate_int(data, o_off, 4, v, little=False)
                        if new:
                            yield cand('fmt-repair',
                                       f'fmt-font-toff[{table}]={v}', new,
                                       [o_off],
                                       desc='clamp table offset inside file')
                    for v in (0, 1, 4, 16, max(0, fsize)):
                        new = mutate_int(data, l_off, 4, v, little=False)
                        if new:
                            yield cand('fmt-repair',
                                       f'fmt-font-tlen[{table}]={v}', new,
                                       [l_off],
                                       desc='clamp table length inside file')
            elif kind == 'woff_len_inconsistent':
                table = issue.get('table')
                if isinstance(table, int):
                    rec = base + table * es
                    # Set origLength = compLength.
                    comp = read_int(data, rec + 8, 4, False) or 0
                    new = mutate_int(data, rec + 12, 4, comp, False)
                    if new:
                        yield cand('fmt-repair',
                                   f'fmt-font-orig={comp}', new, [rec + 12],
                                   desc='set origLength = compLength')
            elif kind == 'bad_search_range':
                sbase = int(structure.get('sfnt_base') or 0)
                num = int(structure.get('count') or 1)
                import math
                expect = (1 << int(math.floor(math.log2(max(num, 1))))) * 16
                new = mutate_int(data, off, 2, expect, False)
                if new:
                    yield cand('fmt-repair',
                               f'fmt-font-sr={expect}', new, [off],
                               desc='fix sfnt searchRange')

    def value_domain(self, field: Dict[str, Any]) -> List[int]:
        kind = field.get('kind')
        name = field.get('name') or ''
        size = int(field.get('size') or 1)
        if kind == 'tag' or name.endswith('.tag'):
            # ASCII-ish table tag bytes (first byte probes).
            return [0x00, 0x20, 0x41, 0x43, 0x46, 0x47, 0x48, 0x4c,
                    0x4d, 0x4e, 0x4f, 0x50, 0x54, 0x63, 0x6d, 0x61,
                    0xfe, 0xff]
        if name in ('numTables', 'numFonts'):
            return [0, 1, 2, 3, 4, 5, 8, 16, 32, 64, 128, 255, 256,
                    0x7fff, 0xffff]
        if kind in ('offset', 'size'):
            return [0, 1, 4, 8, 12, 16, 32, 64, 128, 256, 1024, 4096,
                    0x10000] + MB_VALUES[size][:8]
        if kind == 'count':
            return [0, 1, 2, 3, 4, 8, 16, 32, 64, 128, 255, 256]
        if kind == 'magic':
            return [0x00, 0x01, 0x4f, 0x54, 0x74, 0x77, 0xff]
        return super().value_domain(field)
