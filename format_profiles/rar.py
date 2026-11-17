"""RAR profile: fixed block-header fields (libarchive inputs)."""

from __future__ import annotations

from typing import Any, Dict, Optional

from .base import FormatProfile, read_int


class RarProfile(FormatProfile):
    name = 'rar'

    COMBO_DOMAINS: Dict[str, Any] = {
        'head_flags': [0x9000, 0x8000, 0x0000],
        'head_size': [0, 1, 7, 0x7fff],
    }

    @classmethod
    def detect(cls, data: bytes) -> bool:
        return len(data) >= 7 and data[:7] == b'Rar!\x1a\x07\x00'

    def parse(self, data: bytes) -> Optional[Dict[str, Any]]:
        if not self.detect(data):
            return None
        fields = []
        def add(off, size, kind, name):
            if off + size <= len(data):
                fields.append({'offset': off, 'size': size, 'kind': kind,
                               'name': name, 'value': read_int(data, off, size),
                               'little': True})
        add(3, 2, 'flag', 'head_flags')   # header flags
        add(5, 2, 'size', 'head_size')    # header size
        add(7, 4, 'size', 'pack_size')    # (present in many block types)
        return {'format': self.name, 'label': 'rar-block-header',
                'field_offsets': [f['offset'] for f in fields],
                'fields': fields, 'source': 'format_profile'}
