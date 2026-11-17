"""WAV (RIFF PCM) profile: fixed fmt-chunk header fields."""

from __future__ import annotations

from typing import Any, Dict, Optional

from .base import FormatProfile, read_int


class WavProfile(FormatProfile):
    name = 'wav'

    # Meaning-bearing values for the cross-field combo mutation stage.
    COMBO_DOMAINS: Dict[str, Any] = {
        'channels': [1, 2],
        'block_align': [1, 2, 4],
        'bits_per_sample': [8, 16, 24, 32],
    }

    @classmethod
    def detect(cls, data: bytes) -> bool:
        return (len(data) >= 12 and data[0:4] == b'RIFF'
                and data[8:12] == b'WAVE')

    def parse(self, data: bytes) -> Optional[Dict[str, Any]]:
        if not self.detect(data):
            return None
        # fmt-chunk header fields at fixed offsets (RIFF size at 4,
        # WAVE at 8, 'fmt ' at 12, chunk size at 16).
        fields = []
        if len(data) < 20:
            return None
        if data[12:16] != b'fmt ':
            return None
        base = 20
        fields.append({'offset': base, 'size': 2, 'kind': 'enum',
                       'name': 'format_tag', 'value': read_int(data, base, 2),
                       'little': True})
        fields.append({'offset': base + 2, 'size': 2, 'kind': 'count',
                       'name': 'channels',
                       'value': read_int(data, base + 2, 2), 'little': True})
        fields.append({'offset': base + 4, 'size': 4, 'kind': 'size',
                       'name': 'sample_rate',
                       'value': read_int(data, base + 4, 4), 'little': True})
        fields.append({'offset': base + 8, 'size': 4, 'kind': 'size',
                       'name': 'byte_rate',
                       'value': read_int(data, base + 8, 4), 'little': True})
        fields.append({'offset': base + 12, 'size': 2, 'kind': 'size',
                       'name': 'block_align',
                       'value': read_int(data, base + 12, 2), 'little': True})
        fields.append({'offset': base + 14, 'size': 2, 'kind': 'enum',
                       'name': 'bits_per_sample',
                       'value': read_int(data, base + 14, 2), 'little': True})
        # 16-bit LE fields read as such; PNG-style big-endian not relevant.
        fields = [f for f in fields
                  if f['offset'] + f['size'] <= len(data)]
        return {'format': self.name, 'label': 'wav-fmt-header',
                'field_offsets': [f['offset'] for f in fields],
                'fields': fields, 'source': 'format_profile',
                'little': True}
