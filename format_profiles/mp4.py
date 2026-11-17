"""MP4/ISO-BMFF profile: fixed ftyp box fields (bento4 inputs)."""

from __future__ import annotations

from typing import Any, Dict, Optional

from .base import FormatProfile, read_int


class Mp4Profile(FormatProfile):
    name = 'mp4'

    COMBO_DOMAINS: Dict[str, Any] = {
        'major_brand': [0x69736f6d, 0x61766331, 0x6d703431, 0x6d703432,
                        0x4d344120, 0x71742020],
        'minor_version': [0, 1, 512],
        'compatible_brand0': [0x69736f6d, 0x61766331, 0x6d703431],
    }

    @classmethod
    def detect(cls, data: bytes) -> bool:
        return len(data) >= 12 and data[4:8] == b'ftyp'

    def parse(self, data: bytes) -> Optional[Dict[str, Any]]:
        if not self.detect(data):
            return None
        fields = []
        def add(off, size, kind, name):
            if off + size <= len(data):
                fields.append({'offset': off, 'size': size, 'kind': kind,
                               'name': name,
                               'value': read_int(data, off, size, little=False),
                               'little': False})
        add(0, 4, 'size', 'box_size')
        add(8, 4, 'magic', 'major_brand')
        add(12, 4, 'enum', 'minor_version')
        add(16, 4, 'magic', 'compatible_brand0')
        return {'format': self.name, 'label': 'mp4-ftyp',
                'field_offsets': [f['offset'] for f in fields],
                'fields': fields, 'source': 'format_profile'}
