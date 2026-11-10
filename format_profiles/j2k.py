"""JPEG 2000 codestream (J2K/JP2) profile."""

from __future__ import annotations

import struct
from typing import Any, Dict, Iterable, List, Optional, Sequence

from .base import (
    FIELD_CAP, FormatProfile, cand, mutate_bytes, pack_region, read_int,
)

# Marker IDs that carry a 2-byte length (SOC/SOD/EOC do not).
_LEN_MARKERS = {
    0xFF51, 0xFF52, 0xFF53, 0xFF5C, 0xFF5D, 0xFF5E, 0xFF5F, 0xFF60,
    0xFF61, 0xFF63, 0xFF64, 0xFF66, 0xFF90, 0xFF91, 0xFF92, 0xFF93,
    0xFF94, 0xFF95, 0xFF96, 0xFF97, 0xFF98, 0xFF99, 0xFF9A, 0xFF9B,
    0xFF9C, 0xFF9D, 0xFF9E, 0xFF9F, 0xFFA0, 0xFFA1, 0xFFA2, 0xFFA3,
    0xFFA4, 0xFFA5, 0xFFA6, 0xFFA7, 0xFFA8, 0xFFA9, 0xFFAA, 0xFFAB,
    0xFFAC, 0xFFAD, 0xFFAE, 0xFFAF, 0xFFB0, 0xFFB1, 0xFFB2, 0xFFB3,
    0xFFB4, 0xFFB5, 0xFFB6, 0xFFB7, 0xFFB8, 0xFFB9, 0xFFBA, 0xFFBB,
    0xFFBC, 0xFFBD, 0xFFBE, 0xFFBF, 0xFFC0, 0xFFC1, 0xFFC2, 0xFFC3,
    0xFFC4, 0xFFC5, 0xFFC6, 0xFFC7, 0xFFC8, 0xFFC9, 0xFFCA, 0xFFCB,
    0xFFCC, 0xFFCD, 0xFFCE, 0xFFCF, 0xFFD0, 0xFFD1, 0xFFD2, 0xFFD3,
    0xFFD4, 0xFFD5, 0xFFD6, 0xFFD7, 0xFFD8, 0xFFD9, 0xFFDA, 0xFFDB,
    0xFFDC, 0xFFDD, 0xFFDE, 0xFFDF, 0xFFE0, 0xFFE1, 0xFFE2, 0xFFE3,
    0xFFE4, 0xFFE5, 0xFFE6, 0xFFE7, 0xFFE8, 0xFFE9, 0xFFEA, 0xFFEB,
    0xFFEC, 0xFFED, 0xFFEE, 0xFFEF, 0xFFF0, 0xFFF1, 0xFFF2, 0xFFF3,
    0xFFF4, 0xFFF5, 0xFFF6, 0xFFF7, 0xFFF8, 0xFFF9, 0xFFFA, 0xFFFB,
    0xFFFC, 0xFFFD, 0xFFFE, 0xFFFF,
}
_NO_LEN = {0xFF4F, 0xFF93, 0xFFD9}  # SOC, SOD, EOC

# Meaning-bearing marker rewrites: families that guards like "only one COD
# per tile" are sensitive to.
_MARKER_LO = [0x4F, 0x51, 0x52, 0x53, 0x5C, 0x64, 0x65, 0x90, 0x91,
              0x92, 0x93, 0xD9, 0x00, 0x01, 0xFF]


class J2kProfile(FormatProfile):
    name = 'j2k'

    @classmethod
    def detect(cls, data: bytes) -> bool:
        # SOC marker, or JP2 signature box
        if data[:2] == b'\xff\x4f':
            return True
        if data[:4] == b'\x00\x00\x00\x0c' and data[4:8] == b'jP  ':
            return True
        if len(data) >= 8 and data[4:8] in (b'jP  ', b'jP\x1a\x1a'):
            return True
        return False

    def parse(self, data: bytes) -> Optional[Dict[str, Any]]:
        if len(data) < 4:
            return None
        # Skip JP2 box wrapper if present — find SOC inside.
        soc = data.find(b'\xff\x4f')
        if soc < 0:
            # JP2 signature but no SOC: still expose the box header.
            if data[:2] == b'\x00\x00' or data[4:8] in (b'jP  ', b'jP\x1a\x1a'):
                fields = [{'offset': 0, 'size': 4, 'kind': 'size',
                           'name': 'box_length'},
                          {'offset': 4, 'size': 4, 'kind': 'magic',
                           'name': 'box_type'}]
                return pack_region('j2k', 'JP2 signature box', 0, 1, None,
                                   None, fields)
            return None
        fields: List[Dict[str, Any]] = []
        i = soc
        n = len(data)
        markers = 0
        while i + 1 < n and markers < FIELD_CAP // 2:
            if data[i] != 0xFF or data[i + 1] in (0x00, 0xFF):
                i += 1
                continue
            mid = (data[i] << 8) | data[i + 1]
            fields.append({'offset': i, 'size': 1, 'kind': 'marker',
                           'name': 'marker_hi', 'value': data[i],
                           'marker': mid})
            fields.append({'offset': i + 1, 'size': 1, 'kind': 'marker',
                           'name': 'marker_lo', 'value': data[i + 1],
                           'marker': mid})
            markers += 1
            i += 2
            if mid in _NO_LEN:
                if mid == 0xFFD9:  # EOC — stop
                    break
                continue
            if i + 2 <= n:
                ln = read_int(data, i, 2, little=False)
                if ln is not None and ln >= 2:
                    fields.append({'offset': i, 'size': 2, 'kind': 'size',
                                   'name': 'marker_length', 'value': ln,
                                   'marker': mid, 'little': False})
                    i += ln  # length includes the 2 length bytes
                else:
                    i += 2
            else:
                break
        region = pack_region('j2k', 'J2K codestream marker IDs', soc,
                             markers, 1, soc, fields)
        if region:
            # Full 255 sweep / pairwise explode on marker families — the
            # combo stage is the right unit (same contract as before).
            region['combo_only'] = True
            region['little'] = False
        return region

    def validate(self, data: bytes,
                 structure: Dict[str, Any]) -> List[Dict[str, Any]]:
        issues: List[Dict[str, Any]] = []
        if data[:2] != b'\xff\x4f':
            # JP2 wrapper without SOC is OK; raw codestream must start SOC.
            if data[:4] != b'\x00\x00\x00\x0c' and data[4:8] not in (
                    b'jP  ', b'jP\x1a\x1a'):
                issues.append({'kind': 'missing_soc', 'offset': 0, 'size': 2,
                               'msg': 'missing SOC marker'})
        # Walk markers and check length fields stay in-bounds.
        soc = data.find(b'\xff\x4f')
        i = max(soc, 0)
        n = len(data)
        saw_eoc = False
        while i + 1 < n:
            if data[i] != 0xFF or data[i + 1] in (0x00, 0xFF):
                i += 1
                continue
            mid = (data[i] << 8) | data[i + 1]
            if mid == 0xFFD9:
                saw_eoc = True
                break
            i += 2
            if mid in _NO_LEN:
                continue
            if i + 2 > n:
                issues.append({'kind': 'marker_trunc', 'offset': i,
                               'size': 2,
                               'msg': f'marker {mid:#06x} length past EOF'})
                break
            ln = read_int(data, i, 2, little=False) or 0
            if ln < 2:
                issues.append({'kind': 'bad_marker_len', 'offset': i,
                               'size': 2,
                               'msg': f'marker {mid:#06x} length {ln} < 2'})
                i += 2
                continue
            if i + ln > n:
                issues.append({'kind': 'marker_len_oob', 'offset': i,
                               'size': 2,
                               'msg': f'marker {mid:#06x} length {ln} '
                                      f'past EOF'})
                break
            i += ln
        if soc >= 0 and not saw_eoc and len(data) > soc + 4:
            issues.append({'kind': 'missing_eoc', 'offset': max(n - 2, 0),
                           'size': 2, 'msg': 'missing EOC marker'})
        return issues

    def repair(self, data: bytes, structure: Dict[str, Any],
               issues: Sequence[Dict[str, Any]]) -> Iterable[Dict[str, Any]]:
        n = len(data)
        for issue in issues:
            kind = issue.get('kind')
            off = issue.get('offset')
            if not isinstance(off, int):
                continue
            if kind in ('marker_len_oob', 'marker_trunc'):
                # Clamp length to remaining bytes (min 2).
                remain = max(2, n - off)
                if remain > 0xFFFF:
                    remain = 0xFFFF
                new = mutate_bytes(data, off, int(remain).to_bytes(2, 'big'))
                if new:
                    yield cand('fmt-repair',
                               f'fmt-j2k-len@{off:#x}={remain}', new, [off],
                               desc='clamp J2K marker length to EOF')
            elif kind == 'bad_marker_len':
                new = mutate_bytes(data, off, b'\x00\x02')
                if new:
                    yield cand('fmt-repair', f'fmt-j2k-len2@{off:#x}', new,
                              [off], desc='set J2K marker length to 2')
            elif kind == 'missing_eoc':
                # Append EOC.
                yield cand('fmt-repair', 'fmt-j2k-append-eoc',
                           data + b'\xff\xd9', [n],
                           desc='append missing EOC')
            elif kind == 'missing_soc':
                yield cand('fmt-repair', 'fmt-j2k-prepend-soc',
                           b'\xff\x4f' + data, [0],
                           desc='prepend missing SOC')

    def value_domain(self, field: Dict[str, Any]) -> List[int]:
        kind = field.get('kind')
        if kind == 'marker':
            # Marker ID bytes: prefer family-meaning values.
            return list(_MARKER_LO)
        if kind == 'size':
            return [0, 1, 2, 3, 4, 8, 16, 32, 64, 128, 255, 256, 512,
                    1024, 0x7fff, 0xffff]
        return super().value_domain(field)

    def field_candidates(self, data: bytes, structure: Dict[str, Any],
                         focus: Optional[Sequence[int]] = None,
                         per_field_cap: int = 8) -> Iterable[Dict[str, Any]]:
        # Marker IDs are rewritten as a FAMILY (combo): flipping one COD
        # byte alone rarely passes the "only one per tile" guard.  Emit
        # both per-byte and whole-family candidates.
        fields = [f for f in (structure.get('fields') or [])
                  if f.get('kind') == 'marker']
        if not fields:
            yield from super().field_candidates(data, structure, focus,
                                                per_field_cap)
            return
        focus_set = set(focus or ())
        # Group marker positions by marker id (hi+lo pair).
        pairs: Dict[int, List[int]] = {}
        for f in fields:
            mid = f.get('marker')
            if isinstance(mid, int):
                pairs.setdefault(mid, []).append(int(f['offset']))
        # Family rewrites: replace every occurrence of one marker id with
        # another (uniform across the codestream).
        import os as _os
        try:
            family_cap = int(_os.environ.get('RETROSCOPE_J2K_FAMILY_CAP',
                                             '40'))
        except ValueError:
            family_cap = 40
        emitted = 0
        for old_mid, offs in sorted(pairs.items(),
                                    key=lambda kv: 0 if any(
                                        o in focus_set for o in kv[1])
                                    else 1):
            if emitted >= family_cap:
                break
            for new_lo in _MARKER_LO:
                if emitted >= family_cap:
                    break
                new_mid = (old_mid & 0xFF00) | new_lo
                if new_mid == old_mid:
                    continue
                buf = bytearray(data)
                ok = True
                for o in offs:
                    if o + 1 >= len(buf):
                        ok = False
                        break
                    buf[o + 1] = new_lo
                if not ok or bytes(buf) == data:
                    continue
                yield cand('fmt',
                           f'fmt-j2k-mark{old_mid:#06x}->{new_mid:#06x}',
                           bytes(buf), offs,
                           desc='rewrite J2K marker family')
                emitted += 1
        # Also single-byte marker tweaks (budget residual).
        yield from super().field_candidates(data, structure, focus,
                                            per_field_cap=max(
                                                0, 12 - emitted))
