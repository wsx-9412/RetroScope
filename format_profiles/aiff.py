"""AIFF/AIFF-C profile: fixed COMM-chunk header fields."""

from __future__ import annotations

from typing import Any, Dict, Optional

from .base import FormatProfile, read_int


class AiffProfile(FormatProfile):
    name = 'aiff'

    COMBO_DOMAINS: Dict[str, Any] = {
        'channels': [1, 2],
        'sample_size': [8, 16, 24, 32],
        'num_sample_frames': [0, 1, 2, 0x7fffffff],
    }

    @classmethod
    def detect(cls, data: bytes) -> bool:
        return (len(data) >= 12 and data[0:4] == b'FORM'
                and data[8:12] in (b'AIFF', b'AIFC'))

    def parse(self, data: bytes) -> Optional[Dict[str, Any]]:
        if not self.detect(data):
            return None
        # Walk top-level chunks to find COMM (its position varies: AIFC
        # files may carry FVER before COMM, and PoCs often corrupt the
        # chunk order).
        pos = 12
        base = None
        for _ in range(24):
            if pos + 8 > len(data):
                break
            chunk_id = data[pos:pos + 4]
            size = read_int(data, pos + 4, 4, little=False)
            if size is None:
                break
            if chunk_id == b'COMM' and size >= 18:
                base = pos + 8
                break
            pos = pos + 8 + size + (size & 1)
        if base is None or base + 18 > len(data):
            return None
        fields = [
            {'offset': base, 'size': 2, 'kind': 'count', 'name': 'channels',
             'value': read_int(data, base, 2, little=False), 'little': False},
            {'offset': base + 2, 'size': 4, 'kind': 'count',
             'name': 'num_sample_frames',
             'value': read_int(data, base + 2, 4, little=False),
             'little': False},
            {'offset': base + 6, 'size': 2, 'kind': 'enum',
             'name': 'sample_size',
             'value': read_int(data, base + 6, 2, little=False),
             'little': False},
            # sample_rate at base+8 is an 80-bit extended float — skipped.
        ]
        fields = [f for f in fields if f['offset'] + f['size'] <= len(data)]
        return {'format': self.name, 'label': 'aiff-comm-header',
                'field_offsets': [f['offset'] for f in fields],
                'fields': fields, 'source': 'format_profile'}
