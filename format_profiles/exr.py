"""OpenEXR profile: fixed header fields (openexr inputs)."""

from __future__ import annotations

from typing import Any, Dict, Optional

from .base import FormatProfile, read_int


class ExrProfile(FormatProfile):
    name = 'exr'

    COMBO_DOMAINS: Dict[str, Any] = {
        'version': [0, 2, 1, 0xff],
        'flags': [0, 1, 2, 4, 8],
    }

    @classmethod
    def detect(cls, data: bytes) -> bool:
        return len(data) >= 8 and data[:4] == b'\x76\x2f\x31\x01'

    def parse(self, data: bytes) -> Optional[Dict[str, Any]]:
        if not self.detect(data):
            return None
        fields = [
            {'offset': 4, 'size': 4, 'kind': 'enum', 'name': 'version',
             'value': read_int(data, 4, 4, little=True), 'little': True},
            {'offset': 4, 'size': 1, 'kind': 'flag', 'name': 'flags',
             'value': data[4] if len(data) > 4 else None, 'little': True},
        ]
        return {'format': self.name, 'label': 'exr-header',
                'field_offsets': [f['offset'] for f in fields],
                'fields': fields, 'source': 'format_profile'}
