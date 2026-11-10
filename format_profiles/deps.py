"""Field dependency groups for coordinated mutation (Plan C1).

A *dependency group* is a set of on-disk fields that must stay consistent
with each other — mutating one without its peers usually yields a file the
parser rejects before the interesting code.  Examples:

* TIFF IFD entry  — tag/type/count/value of ONE entry (type size x count
  decides whether value is inline or an offset);
* GIF screen vs first image descriptor — dimensions must agree;
* WOFF table record — offset + compLength + origLength must land in-file;
* J2K marker pair — marker ID + its 2-byte length field;
* DWG version + header layout — version string selects the header grid.

The graph is derived from the structure dict a profile already parses;
it never needs runtime information.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

# A group is (label, [field, ...]) where each field is the dict from
# structure['fields'] (must carry 'offset' and ideally 'name'/'kind').
Group = Tuple[str, List[Dict[str, Any]]]


def _fields_by_name(structure: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    out = {}
    for f in structure.get('fields') or []:
        name = f.get('name')
        if isinstance(name, str) and name not in out:
            out[name] = f
    return out


def _fields_by_kind(structure: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    out: Dict[str, List[Dict[str, Any]]] = {}
    for f in structure.get('fields') or []:
        out.setdefault(f.get('kind') or 'desc', []).append(f)
    return out


def tiff_dependency_groups(structure: Dict[str, Any]) -> List[Group]:
    """Group the four fields of each IFD/BigTIFF entry."""
    groups: List[Group] = []
    by_entry: Dict[int, Dict[str, Dict[str, Any]]] = {}
    for f in structure.get('fields') or []:
        idx = f.get('entry_index')
        field = f.get('field')
        if isinstance(idx, int) and field:
            by_entry.setdefault(idx, {})[field] = f
    for idx, parts in sorted(by_entry.items()):
        need = ('tag', 'type', 'count', 'value')
        if all(k in parts for k in need):
            groups.append(
                (f'tiff-entry[{idx}]', [parts[k] for k in need]))
    return groups


def gif_dependency_groups(structure: Dict[str, Any]) -> List[Group]:
    """Screen descriptor fields + first image descriptor dimensions."""
    by_name = _fields_by_name(structure)
    groups: List[Group] = []
    screen = [by_name[n] for n in
              ('screen_width', 'screen_height', 'packed', 'bg_color')
              if n in by_name]
    if len(screen) >= 2:
        groups.append(('gif-screen', screen))
    img = [by_name[n] for n in
           ('image_left', 'image_top', 'image_width', 'image_height',
            'image_packed', 'lzw_min_code')
           if n in by_name]
    if len(img) >= 2:
        groups.append(('gif-image', img))
    # GCT flag (bit 7 of packed) is tied to the gct[] colour entries.
    if 'packed' in by_name:
        gct = [f for f in structure.get('fields') or []
               if str(f.get('name', '')).startswith('gct[')]
        if gct:
            groups.append(('gif-gct', [by_name['packed']] + gct[:4]))
    return groups


def j2k_dependency_groups(structure: Dict[str, Any]) -> List[Group]:
    """Pair each marker ID (hi+lo) with its length field when adjacent."""
    fields = sorted(structure.get('fields') or [],
                    key=lambda f: int(f.get('offset', 0)))
    groups: List[Group] = []
    i = 0
    while i < len(fields):
        f = fields[i]
        if f.get('kind') == 'marker' and str(f.get('name', '')).endswith(
                '_lo'):
            pair = [f]
            # hi byte is usually the previous field
            if i > 0 and fields[i - 1].get('kind') == 'marker' \
                    and fields[i - 1].get('marker') == f.get('marker'):
                pair.insert(0, fields[i - 1])
            # length field immediately after (offset == lo.offset + 1 + 1?
            # actually length sits at lo.offset + 1)
            lo_off = int(f.get('offset', -1))
            for g in fields[i + 1:i + 3]:
                if g.get('kind') == 'size' and int(g.get('offset', -1)) \
                        == lo_off + 1:
                    pair.append(g)
                    break
            if len(pair) >= 2:
                mid = f.get('marker')
                groups.append((f'j2k-marker-{mid:#06x}', pair))
        i += 1
    return groups


def woff_dependency_groups(structure: Dict[str, Any]) -> List[Group]:
    """Each table record: tag + offset + compLength + origLength."""
    groups: List[Group] = []
    by_table: Dict[int, Dict[str, Dict[str, Any]]] = {}
    for f in structure.get('fields') or []:
        name = str(f.get('name') or '')
        if not name.startswith('table['):
            continue
        # table[<i>].<part>
        try:
            rest = name.split('.', 1)[1]
            idx = int(name[name.index('[') + 1:name.index(']')])
        except (ValueError, IndexError):
            continue
        by_table.setdefault(idx, {})[rest] = f
    for idx, parts in sorted(by_table.items()):
        need = ('tag', 'offset')
        if all(k in parts for k in need):
            group = [parts[k] for k in need]
            for extra in ('compLength', 'origLength', 'length'):
                if extra in parts:
                    group.append(parts[extra])
            groups.append((f'woff-table[{idx}]', group))
    # numTables is tied to the directory extent.
    by_name = _fields_by_name(structure)
    if 'numTables' in by_name:
        tables = [f for f in structure.get('fields') or []
                  if str(f.get('name', '')).startswith('table[')]
        if tables:
            groups.append(('woff-numtables',
                           [by_name['numTables']] + tables[:3]))
    return groups


def dwg_dependency_groups(structure: Dict[str, Any]) -> List[Group]:
    """Version string + the header words it selects."""
    by_name = _fields_by_name(structure)
    groups: List[Group] = []
    if 'version' in by_name:
        header = [by_name[n] for n in
                  ('maintenance', 'codepage', 'header_words_a',
                   'header_words_b', 'section_map_off', 'section_map_size')
                  if n in by_name]
        if header:
            groups.append(('dwg-version-header',
                           [by_name['version']] + header))
    # Offset/size pairs that must both land in-file.
    offs = [f for f in structure.get('fields') or []
            if f.get('kind') == 'offset']
    sizes = [f for f in structure.get('fields') or []
             if f.get('kind') == 'size']
    # Pair by proximity (same record region).
    for o in offs[:8]:
        o_off = int(o.get('offset', -1))
        for s in sizes:
            s_off = int(s.get('offset', -1))
            if 0 <= s_off - o_off <= 8:
                groups.append((f'dwg-off-size@{o_off:#x}', [o, s]))
                break
    return groups


def xml_dependency_groups(structure: Dict[str, Any]) -> List[Group]:
    """Open tag + its close markup (name element and matching '>')."""
    fields = sorted(structure.get('fields') or [],
                    key=lambda f: int(f.get('offset', 0)))
    groups: List[Group] = []
    pending_open: Optional[Dict[str, Any]] = None
    pending_name: Optional[Dict[str, Any]] = None
    for f in fields:
        kind = f.get('kind')
        name = f.get('name')
        if name == 'open':
            pending_open, pending_name = f, None
        elif name == 'element' and pending_open is not None:
            pending_name = f
        elif name == 'close' and pending_open is not None:
            group = [pending_open]
            if pending_name is not None:
                group.append(pending_name)
            group.append(f)
            groups.append((f'xml-tag@{int(pending_open.get("offset", 0)):#x}',
                           group))
            pending_open, pending_name = None, None
    # Attribute: name + value travel together.
    by_name = _fields_by_name(structure)
    if 'attribute' in by_name and 'value' in by_name:
        groups.append(('xml-attr',
                       [by_name['attribute'], by_name['value']]))
    return groups


def elf_dependency_groups(structure: Dict[str, Any]) -> List[Group]:
    """e_shoff + e_shnum + e_shentsize (section table extent)."""
    by_name = _fields_by_name(structure)
    group = [by_name[n] for n in
             ('e_shoff', 'e_shnum', 'e_shentsize') if n in by_name]
    if len(group) >= 2:
        return [('elf-shtable', group)]
    return []


_DISPATCH = {
    'tiff': tiff_dependency_groups,
    'gif': gif_dependency_groups,
    'j2k': j2k_dependency_groups,
    'woff': woff_dependency_groups,
    'woff2': woff_dependency_groups,
    'sfnt': woff_dependency_groups,
    'ttc': woff_dependency_groups,
    'dwg': dwg_dependency_groups,
    'xml': xml_dependency_groups,
    'elf': elf_dependency_groups,
}


def dependency_groups(structure: Dict[str, Any]) -> List[Group]:
    """Return dependency groups for a structure dict (format-dispatched).

    Unknown formats get an empty list — coordinated mutation then falls
    back to single-field candidates (behaviour unchanged).
    """
    if not structure:
        return []
    fmt = structure.get('format') or 'tiff'
    fn = _DISPATCH.get(fmt)
    if fn is None:
        return []
    try:
        return fn(structure)
    except Exception:
        return []


def group_offsets(group: Group) -> List[int]:
    """File offsets covered by a dependency group."""
    _label, fields = group
    out = []
    for f in fields:
        off = f.get('offset')
        if isinstance(off, int) and off >= 0:
            out.append(off)
    return out


def focus_groups(groups: Sequence[Group],
                 focus: Optional[Sequence[int]]) -> List[Group]:
    """Reorder groups: ones touching ``focus`` offsets come first."""
    if not focus:
        return list(groups)
    focus_set = set(focus)
    def _score(g: Group) -> int:
        return 0 if any(o in focus_set for o in group_offsets(g)) else 1
    return sorted(groups, key=_score)


__all__ = [
    'Group', 'dependency_groups', 'focus_groups', 'group_offsets',
    'tiff_dependency_groups', 'gif_dependency_groups',
    'j2k_dependency_groups', 'woff_dependency_groups',
    'dwg_dependency_groups', 'xml_dependency_groups',
    'elf_dependency_groups',
]
