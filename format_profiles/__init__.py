"""format_profiles — independent on-disk format structure profiles.

Each profile implements the five-method contract::

    parse(data)                     -> structure dict
    validate(data, structure)       -> [issue, ...]
    repair(data, structure, issues) -> iterator of candidate dicts
    value_domain(field)             -> [value, ...]
    mutate_field(data, field, value)-> bytes | None

First batch: TIFF IFD, J2K, DWG, XML, GIF, WOFF/sfnt font.

Usage::

    from format_profiles import detect_profile, profile_candidates

    profile = detect_profile(data)
    if profile:
        structure = profile.parse(data)
        issues = profile.validate(data, structure)
        for cand in profile_candidates(data, structure, issues,
                                       focus=primary_offsets):
            ...
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Sequence

from .base import (
    FIELD_CAP, FormatProfile, MB_VALUES, PROBE_DEFAULT, PROBE_KINDS,
    cand, mutate_bytes, mutate_int, pack_region, read_int, sniff,
    write_int,
)
from .dwg import DwgProfile
from .gif import GifProfile
from .j2k import J2kProfile
from .tiff import TiffProfile
from .woff import FontProfile
from .xml import XmlProfile

# Detection order: magic-strict formats first, tolerant scanners last.
PROFILES = (
    TiffProfile,   # II*/MM*
    GifProfile,    # GIF87a/89a
    FontProfile,   # sfnt/ttcf/wOFF/wOF2
    J2kProfile,    # FF4F / JP2 box
    DwgProfile,    # AC10xx
    XmlProfile,    # leading '<' (tolerant — keep last)
)


def detect_profile(data: bytes) -> Optional[FormatProfile]:
    """Return the first profile that recognises ``data``, or None."""
    return sniff(data, PROFILES)


def detect_profile_by_name(name: str) -> Optional[FormatProfile]:
    """Look up a profile by its short name (``tiff``, ``j2k``, ...)."""
    for cls in PROFILES:
        if cls.name == name:
            return cls()
    return None


def parse_bytes(data: bytes) -> Optional[Dict[str, Any]]:
    """Convenience: detect + parse in one call."""
    profile = detect_profile(data)
    if not profile:
        return None
    return profile.parse(data)


def profile_candidates(
        data: bytes,
        structure: Optional[Dict[str, Any]] = None,
        issues: Optional[Sequence[Dict[str, Any]]] = None,
        focus: Optional[Sequence[int]] = None,
        per_field_cap: int = 8,
        issue_cap: int = 60,
        field_cap: int = FIELD_CAP) -> Iterable[Dict[str, Any]]:
    """Generate format-aware candidates for ``data``.

    Order: directed repairs for known structural issues first, then
    per-field meaning-bearing mutations (focus offsets first).  When
    ``structure`` is omitted it is parsed fresh from ``data``; when
    ``issues`` is omitted they are computed via ``validate``.

    Yields candidate dicts compatible with ``extended_mutation._cand``.
    """
    profile = detect_profile(data)
    if not profile:
        return
    if structure is None:
        structure = profile.parse(data)
    if not structure:
        return
    if issues is None:
        try:
            issues = profile.validate(data, structure)
        except Exception:
            issues = []
    yielded = 0
    for fix in profile.repair(data, structure, issues or ()):
        if yielded >= issue_cap:
            break
        yield fix
        yielded += 1
    for cand_dict in profile.field_candidates(data, structure, focus,
                                              per_field_cap=per_field_cap):
        if yielded >= field_cap:
            break
        yield cand_dict
        yielded += 1


def structure_only(data: bytes) -> Optional[Dict[str, Any]]:
    """Parse structure without generating candidates (cheap sniff)."""
    return parse_bytes(data)


__all__ = [
    'FIELD_CAP', 'FormatProfile', 'MB_VALUES', 'PROBE_DEFAULT',
    'PROBE_KINDS', 'PROFILES',
    'DwgProfile', 'FontProfile', 'GifProfile', 'J2kProfile',
    'TiffProfile', 'XmlProfile',
    'cand', 'detect_profile', 'detect_profile_by_name', 'mutate_bytes',
    'mutate_int', 'pack_region', 'parse_bytes', 'profile_candidates',
    'read_int', 'sniff', 'structure_only', 'write_int',
]

# Plan C1: field dependency groups for coordinated mutation.
from .deps import (  # noqa: E402
    dependency_groups, focus_groups, group_offsets,
)

__all__.extend([
    'dependency_groups', 'focus_groups', 'group_offsets',
])
