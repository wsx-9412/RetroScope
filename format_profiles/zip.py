"""ZIP profile: fixed local-file-header fields (zziplib inputs)."""

from __future__ import annotations

from typing import Any, Dict, Optional

from .base import FormatProfile, read_int


class ZipProfile(FormatProfile):
    name = 'zip'

    COMBO_DOMAINS: Dict[str, Any] = {
        'version_needed': [10, 20, 45],
        'flags': [0, 1, 8, 0x800],
        'method': [0, 8, 12],
        'comp_size': [0, 1, 0x7fffffff, 0xffffffff],
        'uncomp_size': [0, 1, 0x7fffffff, 0xffffffff],
        'name_len': [0, 1, 4, 0xffff],
        'extra_len': [0, 1, 4, 0xffff],
    }

    @classmethod
    def detect(cls, data: bytes) -> bool:
        return len(data) >= 4 and data[:4] in (b'PK\x03\x04', b'PK\x05\x06')

    def parse(self, data: bytes) -> Optional[Dict[str, Any]]:
        if not self.detect(data):
            return None
        fields = []
        def add(off, size, kind, name):
            if off + size <= len(data):
                fields.append({'offset': off, 'size': size, 'kind': kind,
                               'name': name, 'value': read_int(data, off, size),
                               'little': True})
        # Local file header (offset 0 when the archive starts there) — the
        # fields other entries' headers share the same layout.
        if data[:4] == b'PK\x03\x04':
            add(4, 2, 'enum', 'version_needed')
            add(6, 2, 'flag', 'flags')
            add(8, 2, 'enum', 'method')
            add(14, 4, 'size', 'crc32')
            add(18, 4, 'size', 'comp_size')
            add(22, 4, 'size', 'uncomp_size')
            add(26, 2, 'size', 'name_len')
            add(28, 2, 'size', 'extra_len')
        else:  # EOCD record
            add(8, 2, 'count', 'disk_num')
            add(10, 2, 'count', 'cd_disk')
            add(12, 2, 'count', 'disk_entries')
            add(14, 2, 'count', 'total_entries')
            add(16, 4, 'size', 'cd_size')
            add(20, 4, 'size', 'cd_offset')
        return {'format': self.name, 'label': 'zip-header',
                'field_offsets': [f['offset'] for f in fields],
                'fields': fields, 'source': 'format_profile'}
