"""PNG profile: fixed IHDR fields (libpng inputs)."""

from __future__ import annotations

from typing import Any, Dict, Optional

from .base import FormatProfile, read_int


class PngProfile(FormatProfile):
    name = 'png'

    COMBO_DOMAINS: Dict[str, Any] = {
        'width': [1, 2, 4, 8, 16, 0x7fff, 0x8000, 0xffffffff],
        'height': [1, 2, 4, 8, 16, 0x7fff, 0x8000, 0xffffffff],
        'bit_depth': [1, 2, 4, 8, 16],
        'color_type': [0, 2, 3, 4, 6],
        'compression': [0, 1],
        'filter': [0, 1],
        'interlace': [0, 1],
    }

    @classmethod
    def detect(cls, data: bytes) -> bool:
        return len(data) >= 24 and data[:8] == b'\x89PNG\r\n\x1a\n'

    def parse(self, data: bytes) -> Optional[Dict[str, Any]]:
        if not self.detect(data):
            return None
        if data[12:16] != b'IHDR':
            return None
        fields = []
        def add(off, size, kind, name):
            if off + size <= len(data):
                fields.append({'offset': off, 'size': size, 'kind': kind,
                               'name': name,
                               'value': read_int(data, off, size, little=False),
                               'little': False})
        add(16, 4, 'size', 'width')
        add(20, 4, 'size', 'height')
        add(24, 1, 'enum', 'bit_depth')
        add(25, 1, 'enum', 'color_type')
        add(26, 1, 'enum', 'compression')
        add(27, 1, 'enum', 'filter')
        add(28, 1, 'enum', 'interlace')
        return {'format': self.name, 'label': 'png-ihdr',
                'field_offsets': [f['offset'] for f in fields],
                'fields': fields, 'source': 'format_profile'}
