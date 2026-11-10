"""GIF87a/89a profile."""

from __future__ import annotations

import struct
from typing import Any, Dict, Iterable, List, Optional, Sequence

from .base import (
    FIELD_CAP, FormatProfile, cand, mutate_int, pack_region, read_int,
)


class GifProfile(FormatProfile):
    name = 'gif'

    @classmethod
    def detect(cls, data: bytes) -> bool:
        return len(data) >= 6 and data[:6] in (b'GIF87a', b'GIF89a')

    def parse(self, data: bytes) -> Optional[Dict[str, Any]]:
        if not self.detect(data):
            return None
        fields: List[Dict[str, Any]] = []

        def add(off: int, size: int, kind: str, name: str, value=None):
            if 0 <= off and off + size <= len(data):
                fields.append({'offset': off, 'size': size, 'kind': kind,
                               'name': name, 'value': value, 'little': True})

        add(0, 6, 'magic', 'signature')
        add(6, 2, 'size', 'screen_width',
            read_int(data, 6, 2, True))
        add(8, 2, 'size', 'screen_height',
            read_int(data, 8, 2, True))
        packed = data[10] if len(data) > 10 else 0
        add(10, 1, 'desc', 'packed', packed)
        add(11, 1, 'index', 'bg_color',
            data[11] if len(data) > 11 else None)
        pos = 13
        if packed & 0x80:
            gct_len = 3 * (2 ** ((packed & 7) + 1))
            for i in range(min(8, gct_len // 3)):
                add(13 + i * 3, 3, 'desc', f'gct[{i}]')
            pos = 13 + gct_len
        images = 0
        while 0 <= pos < len(data) and len(fields) < FIELD_CAP:
            b = data[pos]
            if b == 0x3b:
                add(pos, 1, 'desc', 'trailer')
                break
            if b == 0x21:
                add(pos, 2, 'desc', 'extension')
                pos += 2
                while pos < len(data):
                    sz = data[pos]
                    if sz == 0:
                        pos += 1
                        break
                    pos += 1 + sz
                continue
            if b == 0x2c:
                add(pos, 1, 'desc', 'image_separator')
                add(pos + 1, 2, 'size', 'image_left',
                    read_int(data, pos + 1, 2, True))
                add(pos + 3, 2, 'size', 'image_top',
                    read_int(data, pos + 3, 2, True))
                add(pos + 5, 2, 'size', 'image_width',
                    read_int(data, pos + 5, 2, True))
                add(pos + 7, 2, 'size', 'image_height',
                    read_int(data, pos + 7, 2, True))
                lct = 0
                if pos + 10 <= len(data):
                    ipacked = data[pos + 9]
                    add(pos + 9, 1, 'desc', 'image_packed', ipacked)
                    if ipacked & 0x80:
                        lct = 3 * (2 ** ((ipacked & 7) + 1))
                add(pos + 10 + lct, 1, 'count', 'lzw_min_code',
                    data[pos + 10 + lct] if pos + 10 + lct < len(data)
                    else None)
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
            break
        return pack_region('gif', 'GIF screen/image descriptors',
                           6, images, None, 6, fields)

    def validate(self, data: bytes,
                 structure: Dict[str, Any]) -> List[Dict[str, Any]]:
        issues: List[Dict[str, Any]] = []
        if not self.detect(data):
            issues.append({'kind': 'bad_magic', 'offset': 0, 'size': 6,
                           'msg': 'missing GIF87a/89a signature'})
            return issues
        if len(data) < 13:
            issues.append({'kind': 'truncated_lsd', 'offset': 0, 'size': 13,
                           'msg': 'file shorter than logical screen '
                                  'descriptor'})
            return issues
        w = read_int(data, 6, 2, True) or 0
        h = read_int(data, 8, 2, True) or 0
        packed = data[10]
        if w == 0 or h == 0:
            issues.append({'kind': 'zero_dimension', 'offset': 6, 'size': 4,
                           'msg': f'screen {w}x{h} has a zero side'})
        gct_flag = bool(packed & 0x80)
        gct_size = 3 * (2 ** ((packed & 7) + 1)) if gct_flag else 0
        if gct_flag and 13 + gct_size > len(data):
            issues.append({'kind': 'gct_oob', 'offset': 10, 'size': 1,
                           'msg': f'GCT ({gct_size} bytes) past EOF'})
        # Image descriptor dimensions vs screen (soft warning → repair).
        pos = 13 + gct_size
        if 0 <= pos < len(data) and data[pos] == 0x2c and pos + 10 <= len(data):
            iw = read_int(data, pos + 5, 2, True) or 0
            ih = read_int(data, pos + 7, 2, True) or 0
            if iw == 0 or ih == 0:
                issues.append({'kind': 'zero_image_dim', 'offset': pos + 5,
                               'size': 4,
                               'msg': f'image {iw}x{ih} has a zero side'})
        # LZW minimum code size must be 2..8 for GIF.
        # Find first image block's LZW byte.
        scan = data.find(b'\x2c', 13)
        if scan >= 0 and scan + 11 <= len(data):
            ipacked = data[scan + 9]
            lct = 0
            if ipacked & 0x80:
                lct = 3 * (2 ** ((ipacked & 7) + 1))
            lzw_off = scan + 10 + lct
            if lzw_off < len(data):
                lzw = data[lzw_off]
                if not (2 <= lzw <= 8):
                    issues.append({'kind': 'bad_lzw_min', 'offset': lzw_off,
                                   'size': 1,
                                   'msg': f'LZW min code size {lzw} '
                                          f'outside 2..8'})
        # Missing trailer.
        if data and data[-1] != 0x3b:
            issues.append({'kind': 'missing_trailer', 'offset': len(data) - 1,
                           'size': 1, 'msg': 'missing GIF trailer 0x3B'})
        return issues

    def repair(self, data: bytes, structure: Dict[str, Any],
               issues: Sequence[Dict[str, Any]]) -> Iterable[Dict[str, Any]]:
        for issue in issues:
            kind = issue.get('kind')
            off = issue.get('offset')
            if not isinstance(off, int):
                continue
            if kind == 'bad_magic':
                for sig in (b'GIF89a', b'GIF87a'):
                    new = bytearray(data)
                    new[:6] = sig
                    yield cand('fmt-repair', f'fmt-gif-sig={sig.decode()}',
                               bytes(new), [0], desc='rewrite GIF signature')
            elif kind == 'zero_dimension':
                for w, h in ((1, 1), (2, 2), (8, 8), (0xFFFF, 1),
                             (1, 0xFFFF)):
                    new = bytearray(data)
                    new[6:8] = w.to_bytes(2, 'little')
                    new[8:10] = h.to_bytes(2, 'little')
                    yield cand('fmt-repair',
                               f'fmt-gif-dim={w}x{h}', bytes(new),
                               [6, 8], desc='set non-zero screen size')
            elif kind == 'zero_image_dim':
                for v in (1, 2, 8, 0xFFFF):
                    new = mutate_int(data, off, 2, v, True)
                    if new:
                        yield cand('fmt-repair',
                                   f'fmt-gif-imgdim@{off:#x}={v}', new,
                                   [off], desc='set non-zero image size')
            elif kind == 'bad_lzw_min':
                for v in (2, 3, 4, 7, 8):
                    new = mutate_int(data, off, 1, v, True)
                    if new:
                        yield cand('fmt-repair',
                                   f'fmt-gif-lzw@{off:#x}={v}', new, [off],
                                   desc='clamp LZW min code size to 2..8')
            elif kind == 'gct_oob':
                # Clear the GCT flag (keep global color table size bits 0).
                if off < len(data):
                    new = bytearray(data)
                    new[off] = new[off] & 0x7F
                    yield cand('fmt-repair', 'fmt-gif-clear-gct',
                               bytes(new), [off],
                               desc='clear GCT flag when table past EOF')
            elif kind == 'missing_trailer':
                yield cand('fmt-repair', 'fmt-gif-trailer',
                           data + b'\x3b', [len(data)],
                           desc='append GIF trailer')
            elif kind == 'truncated_lsd':
                # Pad a minimal LSD + trailer.
                yield cand('fmt-repair', 'fmt-gif-pad-lsd',
                           data.ljust(13, b'\x00') + b'\x3b', [0],
                           desc='pad to minimal GIF')

    def value_domain(self, field: Dict[str, Any]) -> List[int]:
        kind = field.get('kind')
        name = field.get('name') or ''
        if name in ('screen_width', 'screen_height', 'image_left',
                    'image_top', 'image_width', 'image_height'):
            return [0, 1, 2, 3, 4, 8, 16, 32, 64, 128, 255, 256, 512,
                    1024, 2048, 4096, 0x7fff, 0xffff]
        if name == 'packed' or name == 'image_packed':
            # Bit 7 = GCT/LCT present, bits 0-2 = size, bit 3 = sort,
            # bits 4-6 = colour resolution.
            return [0x00, 0x01, 0x02, 0x03, 0x04, 0x07, 0x08, 0x10,
                    0x20, 0x40, 0x70, 0x77, 0x80, 0x87, 0x88, 0xF0,
                    0xFF]
        if name == 'lzw_min_code':
            return [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0xFF]
        if name == 'bg_color':
            return [0, 1, 2, 3, 4, 7, 8, 15, 16, 31, 32, 63, 64, 127,
                    128, 255]
        if kind == 'magic':
            # Signature bytes: flip version digits / trailer-like values.
            return [0x37, 0x38, 0x39, 0x61, 0x00, 0xFF]
        return super().value_domain(field)
