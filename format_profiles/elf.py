"""ELF profile: fixed ehdr fields (binutils inputs)."""

from __future__ import annotations

from typing import Any, Dict, Optional

from .base import FormatProfile, read_int


class ElfProfile(FormatProfile):
    name = 'elf'

    COMBO_DOMAINS: Dict[str, Any] = {
        'class': [1, 2],
        'e_type': [1, 2, 3, 4],
        'e_machine': [3, 8, 40, 62, 183],
        'e_version': [0, 1],
        'e_ehsize': [52, 64],
        'e_phnum': [0, 1, 2, 0xffff],
        'e_shnum': [0, 1, 2, 0xffff],
        'e_phentsize': [32, 56],
        'e_shentsize': [40, 64],
    }

    @classmethod
    def detect(cls, data: bytes) -> bool:
        return len(data) >= 16 and data[:4] == b'\x7fELF'

    def parse(self, data: bytes) -> Optional[Dict[str, Any]]:
        if not self.detect(data):
            return None
        fields = []
        def add(off, size, kind, name):
            if off + size <= len(data):
                fields.append({'offset': off, 'size': size, 'kind': kind,
                               'name': name, 'value': read_int(data, off, size),
                               'little': True})
        add(4, 1, 'enum', 'class')       # EI_CLASS
        add(5, 1, 'enum', 'data_enc')    # EI_DATA
        add(16, 2, 'enum', 'e_type')
        add(18, 2, 'enum', 'e_machine')
        add(20, 4, 'enum', 'e_version')
        add(40, 2, 'size', 'e_ehsize')
        add(42, 2, 'size', 'e_phentsize')
        add(44, 2, 'size', 'e_phnum')
        add(46, 2, 'size', 'e_shentsize')
        add(48, 2, 'size', 'e_shnum')
        add(50, 2, 'size', 'e_shstrndx')
        return {'format': self.name, 'label': 'elf-ehdr',
                'field_offsets': [f['offset'] for f in fields],
                'fields': fields, 'source': 'format_profile'}
