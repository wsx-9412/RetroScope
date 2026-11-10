"""Shared types and helpers for format_profiles.

Every profile implements the same five-method contract::

    parse(data)                  -> structure dict (field positions + kinds)
    validate(data, structure)    -> [issue, ...]
    repair(data, structure, issues) -> iterator of candidate dicts
    value_domain(field)          -> [value, ...]   meaning-bearing values
    mutate_field(data, field, value) -> bytes | None

A *structure* dict is intentionally compatible with the region dicts the
pipeline already consumes (``field_offsets`` / ``fields`` / ``entry_size``
/ ``entries_base`` / ``count``) so a profile result can be dropped straight
into Step 6a-6f without translation.

A *candidate* dict matches ``extended_mutation._cand``::

    {'op': str, 'detail': str, 'data': bytes, 'offsets': [int, ...],
     'desc': str}
"""

from __future__ import annotations

import struct
from typing import Any, Dict, Iterable, List, Optional, Sequence

# Cap on structural field positions per parse: every position may be swept,
# so unbounded structures must not explode the candidate budget.
FIELD_CAP = 100

# Directed probe bytes per field kind — the shared value vocabulary.
# Profiles may narrow this per-field via ``value_domain``.
PROBE_KINDS: Dict[str, List[int]] = {
    'magic':  [0x00, 0x01, 0x02, 0x03, 0x7f],
    'index':  [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x40, 0x80, 0xff],
    'enum':   [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
               0x0b, 0x0e, 0x11, 0x64, 0x65, 0x66, 0x67, 0x68, 0x6b,
               0x71, 0x80, 0x81, 0xff],
    'offset': [0x00, 0x01, 0x02, 0x3f, 0x40, 0x7f, 0x80, 0xff],
    'size':   [0x00, 0x01, 0x02, 0x7f, 0x80, 0xff],
    'count':  [0x00, 0x01, 0x02, 0x03, 0x08, 0x7f, 0x80, 0xff],
    'tag':    [0x00, 0x01, 0x20, 0x41, 0x61, 0x63, 0x66, 0x67, 0x68,
               0x6c, 0x6d, 0x70, 0xfe, 0xff],
    'markup': [0x00, 0x20, 0x21, 0x22, 0x23, 0x27, 0x2d, 0x2f, 0x3c,
               0x3d, 0x3e, 0x3f, 0xff],
    'name':   [0x00, 0x20, 0x2d, 0x2e, 0x2f, 0x3a, 0x5f, 0x61, 0xff],
    'attr':   [0x00, 0x22, 0x27, 0x26, 0x2f, 0x3c, 0x3e, 0xff],
    'desc':   [0x00, 0x01, 0x40, 0x7f, 0x80, 0xff],
    'marker': [0x00, 0x01, 0x20, 0x40, 0x4f, 0x51, 0x52, 0x53, 0x5c,
               0x64, 0x65, 0x90, 0x91, 0x92, 0x93, 0xd9, 0xff],
    'flag':   [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
               0xff],
}
PROBE_DEFAULT = [0x00, 0x01, 0x7f, 0x80, 0xff]

# Multi-byte boundary values by width (shared with extended_mutation's
# _MB_VALUES; duplicated here so the package stays dependency-free).
MB_VALUES: Dict[int, List[int]] = {
    1: [0, 1, 2, 3, 4, 7, 8, 15, 16, 31, 32, 63, 64, 127, 128, 255],
    2: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
        20, 24, 32, 48, 64, 96, 128, 192, 256, 384, 512, 768, 1024,
        2048, 4096, 0x7fff, 0x8000, 0xffff],
    4: [0, 1, 2, 3, 4, 5, 8, 16, 32, 64, 128, 256, 512, 1024, 2048,
        4096, 0x1000, 0x10000, 0x100000, 0x7fffffff, 0x80000000,
        0xffffffff],
    8: [0, 1, 0xffffffff, 0x7fffffff, 0xffffffffffffffff,
        0x7fffffffffffffff],
}


def pack_region(
        fmt: str, label: str, region_offset, count, entry_size,
        entries_base, fields: Sequence[Dict[str, Any]],
        extra: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
    """Build the structure dict shared by all profiles.

    Same keys the pipeline already consumes plus ``format``/``label``/
    ``fields``.  Returns None when nothing usable was parsed.
    """
    seen = set()
    positions: List[int] = []
    kept: List[Dict[str, Any]] = []
    for f in sorted(fields, key=lambda x: int(x.get('offset', -1))):
        off = f.get('offset')
        if not isinstance(off, int) or off < 0 or off in seen:
            continue
        seen.add(off)
        positions.append(off)
        kept.append(f)
        if len(positions) >= FIELD_CAP:
            break
    if not positions:
        return None
    region = {
        'format': fmt,
        'label': label,
        'region_offset': region_offset,
        'count': count,
        'entry_size': entry_size,
        'entries_base': entries_base,
        'field_offsets': positions,
        'fields': kept,
        'source': 'format_profile',
    }
    if extra:
        region.update(extra)
    return region


def read_int(data: bytes, offset: int, size: int, little: bool = True) -> Optional[int]:
    """Endian-aware unsigned integer read; None when out of bounds."""
    if offset < 0 or size <= 0 or offset + size > len(data):
        return None
    return int.from_bytes(data[offset:offset + size],
                          'little' if little else 'big')


def write_int(data: bytearray, offset: int, size: int, value: int,
              little: bool = True) -> bool:
    """Endian-aware unsigned integer write; False when out of bounds/overflow."""
    if offset < 0 or size <= 0 or offset + size > len(data) or value < 0:
        return False
    try:
        data[offset:offset + size] = int(value).to_bytes(
            size, 'little' if little else 'big')
        return True
    except OverflowError:
        return False


def cand(op: str, detail: str, data: bytes, offsets: Iterable[int],
         desc: str = '') -> Dict[str, Any]:
    """Candidate dict compatible with extended_mutation._cand."""
    return {'op': op, 'detail': detail, 'data': bytes(data),
            'offsets': [o for o in offsets if isinstance(o, int) and o >= 0],
            'desc': desc}


def mutate_bytes(data: bytes, offset: int, payload: bytes) -> Optional[bytes]:
    """Overwrite ``payload`` at ``offset``; None when out of bounds."""
    if offset < 0 or offset + len(payload) > len(data):
        return None
    buf = bytearray(data)
    buf[offset:offset + len(payload)] = payload
    return bytes(buf)


def mutate_int(data: bytes, offset: int, size: int, value: int,
               little: bool = True) -> Optional[bytes]:
    """Overwrite a ``size``-byte integer at ``offset``; None on failure."""
    buf = bytearray(data)
    if not write_int(buf, offset, size, value, little):
        return None
    return bytes(buf)


class FormatProfile:
    """Abstract format profile.  Subclasses implement the five methods."""

    #: short id used in structure['format'] and candidate labels
    name: str = 'base'

    @classmethod
    def detect(cls, data: bytes) -> bool:
        """True when ``data`` looks like this format (magic sniff)."""
        raise NotImplementedError

    def parse(self, data: bytes) -> Optional[Dict[str, Any]]:
        """Parse on-disk structure; None when the file is not this format."""
        raise NotImplementedError

    def validate(self, data: bytes,
                 structure: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Return structural issues as [{'kind','offset','size','msg',...}]."""
        raise NotImplementedError

    def repair(self, data: bytes, structure: Dict[str, Any],
               issues: Sequence[Dict[str, Any]]) -> Iterable[Dict[str, Any]]:
        """Yield directed repair candidates for the given issues."""
        return iter(())

    def value_domain(self, field: Dict[str, Any]) -> List[int]:
        """Meaning-bearing values for one parsed field.

        Default: the shared per-kind probe set, widened with multi-byte
        boundary values when the field is wider than one byte.
        """
        kind = field.get('kind') or 'desc'
        size = int(field.get('size') or 1)
        vals = list(PROBE_KINDS.get(kind, PROBE_DEFAULT))
        if size > 1:
            for v in MB_VALUES.get(size, MB_VALUES[4]):
                if 0 <= v < (1 << (8 * size)) and v not in vals:
                    vals.append(v)
        return vals

    def mutate_field(self, data: bytes, field: Dict[str, Any],
                     value: int) -> Optional[bytes]:
        """Write ``value`` into ``field``; None when out of bounds.

        Default: endian-aware integer write using the field's offset/size.
        """
        off = field.get('offset')
        size = int(field.get('size') or 1)
        if not isinstance(off, int):
            return None
        little = field.get('little')
        if little is None:
            little = True
        return mutate_int(data, off, size, value, bool(little))

    # ------------------------------------------------------------------
    # Shared candidate generators (profiles override as needed)
    # ------------------------------------------------------------------

    def field_candidates(self, data: bytes, structure: Dict[str, Any],
                         focus: Optional[Sequence[int]] = None,
                         per_field_cap: int = 8) -> Iterable[Dict[str, Any]]:
        """Directed single-field mutations, focus offsets first."""
        fields = list(structure.get('fields') or [])
        if not fields:
            return
        focus_set = set(focus or ())
        if focus_set:
            fields.sort(key=lambda f: 0 if f.get('offset') in focus_set else 1)
        emitted = 0
        for field in fields:
            if emitted >= FIELD_CAP:
                break
            off = field.get('offset')
            original = read_int(data, off, int(field.get('size') or 1),
                                bool(field.get('little', True))) \
                if isinstance(off, int) else None
            n = 0
            for value in self.value_domain(field):
                if n >= per_field_cap or emitted >= FIELD_CAP:
                    break
                if original is not None and value == original:
                    continue
                mutated = self.mutate_field(data, field, value)
                if mutated is None or mutated == data:
                    continue
                name = field.get('name') or 'field'
                yield cand(
                    'fmt', f'fmt-{self.name}-{name}@{off:#x}={value}',
                    mutated, [off],
                    desc=f'{self.name} field {name}')
                emitted += 1
                n += 1

    def issue_candidates(self, data: bytes, structure: Dict[str, Any],
                         issues: Sequence[Dict[str, Any]],
                         cap: int = 60) -> Iterable[Dict[str, Any]]:
        """Repair candidates for structural issues, then field candidates."""
        yielded = 0
        for fix in self.repair(data, structure, issues):
            if yielded >= cap:
                return
            yield fix
            yielded += 1
        yield from self.field_candidates(data, structure)


def sniff(data: bytes, profiles: Sequence[type]) -> Optional[FormatProfile]:
    """Return the first profile whose ``detect`` accepts ``data``."""
    for cls in profiles:
        try:
            if cls.detect(data):
                return cls()
        except Exception:
            continue
    return None
