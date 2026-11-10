"""Section-targeted fallback when dynamic origin tracing yields no offsets.

For formats where the fork variable is produced by decompression/parsing
(libredwg R2004 sections), the backward value chain dies before reaching a
read()/mmap buffer.  Instead of leaving ``offsets`` empty we map the fork
function to the on-disk section(s) it reads and emit those page/header
candidates as ``via=section_fallback`` origin offsets.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional

# fork/root-cause function → short DWG section names (AcDb:<name>)
# Longer names first when matching (prefix).
_FUNC_SECTIONS = [
    ("read_2004_section_header", ["Header"]),
    ("read_2004_section_classes", ["Classes"]),
    ("read_2004_section_summary", ["SummaryInfo"]),
    ("read_2004_section_handles", ["Handles"]),
    ("read_2004_section_template", ["Template"]),
    ("read_2004_section_auxheader", ["AuxHeader"]),
    ("read_2004_section_appinfo", ["AppInfo"]),
    ("read_2004_section_revhistory", ["RevHistory"]),
    ("read_2004_section_objfreespace", ["ObjFreeSpace"]),
    ("read_2004_section_objects", ["AcDbObjects"]),
    ("read_2004_section_preview", ["Preview"]),
    ("read_2004_section_filedeplist", ["FileDepList"]),
    ("read_2004_section_security", ["Security"]),
    # generic compressed-section reader: caller context unknown → priority set
    ("read_2004_compressed_section", [
        "Header", "SummaryInfo", "Classes", "Handles", "AcDbObjects",
    ]),
    # section map / decompress of the map itself
    ("read_R2004_section_map", []),  # control fields only
    ("decompress_R2004_section", []),
]

# functions that walk arbitrary section bytes (bits.c): sample all priority
_BITS_FUNC_MARKERS = ("bit_read", "bit_advance", "bit_search", "bit_write",
                      "bit_", "decompress_r2007", "decode_preR13")

_PRIORITY_ALL = [
    "Header", "SummaryInfo", "AuxHeader", "Classes", "Handles",
    "Template", "ObjFreeSpace", "AcDbObjects", "Preview", "RevHistory",
    "AppInfo", "AppInfoHistory",
]


def _is_dwg(path: str) -> bool:
    try:
        with open(path, "rb") as f:
            head = f.read(6)
        return head[:2] == b"AC" and head[2:6].isdigit()
    except OSError:
        return False


def _sections_for_func(fork_func: str) -> List[str]:
    f = (fork_func or "").strip()
    if not f:
        return list(_PRIORITY_ALL)
    # strip +offset / namespaces
    f = f.split(" +")[0].split("(")[0].strip()
    for key, names in _FUNC_SECTIONS:
        if key == f:
            return list(names)
        if f.startswith(key):
            return list(names)
    low = f.lower()
    if any(m in low for m in _BITS_FUNC_MARKERS):
        return list(_PRIORITY_ALL)
    # unknown but still libredwg decode path
    if "decode" in low or "dwg" in low or "section" in low:
        return list(_PRIORITY_ALL)
    return list(_PRIORITY_ALL)


def section_fallback_offsets(
    input_file: str,
    fork_func: Optional[str] = None,
    max_offsets: int = 48,
) -> List[Dict[str, Any]]:
    """Return origin-style offset dicts for a DWG input (empty if not DWG)."""
    if not input_file or not os.path.isfile(input_file) or not _is_dwg(input_file):
        return []
    try:
        from dwg_sections import extract_dwg_sections, sample_offsets
        from dwg_sections import section_control_offsets
    except Exception:
        return []
    try:
        with open(input_file, "rb") as f:
            data = f.read()
    except OSError:
        return []

    out: List[Dict[str, Any]] = []
    seen = set()

    def _add(off, ln, via, note=""):
        if off is None or ln is None or ln <= 0:
            return
        if off < 0 or off >= len(data):
            return
        ln = min(int(ln), len(data) - off)
        key = int(off)
        if key in seen:
            return
        seen.add(key)
        out.append({
            "offset": int(off),
            "length": int(ln),
            "via": via,
            "file": os.path.realpath(input_file),
            "path": ["section_fallback"],
            "note": note,
        })

    # 1) section map / encrypted header control fields (always useful:
    #    they steer which pages are decoded for ANY fork in decode path)
    for off, ln, note in section_control_offsets(data):
        _add(off, ln, "section_map_control", note)

    # 2) named section pages for the fork function
    wanted = _sections_for_func(fork_func)
    regs = extract_dwg_sections(data, max_pages=120)
    named = [r for r in regs if r.get("kind") == "section_page"]
    by_short = {}
    for r in named:
        short = (r.get("section") or "").split(":")[-1]
        by_short.setdefault(short, []).append(r)

    # priority sections first, then any remaining named sections
    order = list(wanted) + [s for s in by_short if s not in wanted]
    for short in order:
        rs = by_short.get(short) or []
        if not rs:
            continue
        # smaller structural sections: denser sampling
        per = 4 if short in ("Header", "SummaryInfo", "AuxHeader",
                             "Classes", "Handles", "Template") else 2
        if short not in wanted and len(out) > max_offsets // 2:
            continue
        for off, ln, lab in sample_offsets(rs, per_region=per, value_size=4):
            _add(off, ln, "section_page",
                 f"{short}:{lab}" if short not in str(lab) else str(lab))
            if len(out) >= max_offsets:
                break
        if len(out) >= max_offsets:
            break

    # 3) generic page map samples as last resort (already listed as kind=page)
    if len(out) < 8:
        pages = [r for r in regs if r.get("kind") != "section_page"]
        for off, ln, lab in sample_offsets(pages, per_region=2, value_size=4):
            _add(off, ln, "section_page", str(lab))
            if len(out) >= max_offsets:
                break

    return out[:max_offsets]


def enrich_origin_result(
    res: Dict[str, Any],
    input_file: Optional[str] = None,
    fork_func: Optional[str] = None,
    max_offsets: int = 48,
) -> int:
    """If ``res['offsets']`` is empty, append section-fallback offsets.

    Returns the number of fallback offsets added (0 when dynamic already
    succeeded or the input is not a supported DWG).
    """
    if not isinstance(res, dict):
        return 0
    if res.get("offsets"):
        return 0
    if res.get("status") not in (None, "ok"):
        return 0
    path = input_file or res.get("input_file")
    if not path:
        # origin JSON stores no top-level input; derive from first matching read
        for r in res.get("reads") or []:
            f = r.get("file")
            if f and os.path.isfile(f):
                path = f
                break
    if not path or not os.path.isfile(path):
        return 0
    if not fork_func:
        fork_func = res.get("fork_func") or ""
    adds = section_fallback_offsets(path, fork_func, max_offsets=max_offsets)
    if not adds:
        return 0
    res.setdefault("offsets", []).extend(adds)
    res["section_fallback"] = {
        "count": len(adds),
        "fork_func": fork_func or "",
        "input": os.path.realpath(path),
    }
    return len(adds)


def enrich_origin_file(
    origin_path: str,
    diverge_path: Optional[str] = None,
    fork_func: Optional[str] = None,
    input_file: Optional[str] = None,
    max_offsets: int = 48,
    rewrite: bool = True,
) -> Dict[str, Any]:
    """Load an existing origin JSON, fill empty offsets, optionally rewrite."""
    with open(origin_path) as f:
        res = json.load(f)
    if not fork_func and diverge_path and os.path.isfile(diverge_path):
        try:
            with open(diverge_path) as f:
                raw = json.load(f)
            div = raw.get("divergence", raw)
            fork_func = (div.get("root_cause_function")
                         or div.get("divergence_function")
                         or div.get("fork_func") or "")
        except Exception:
            pass
    if not input_file:
        input_file = res.get("input_file")
        if not input_file:
            for r in res.get("reads") or []:
                if r.get("file") and os.path.isfile(r["file"]):
                    input_file = r["file"]
                    break
    n = enrich_origin_result(
        res, input_file=input_file, fork_func=fork_func,
        max_offsets=max_offsets)
    if n and rewrite:
        tmp = origin_path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(res, f, indent=1, default=str)
        os.replace(tmp, origin_path)
    return {"added": n, "offsets": len(res.get("offsets") or []),
            "fork_func": fork_func or "", "result": res}


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("usage: origin_fallback.py ORIGIN.json [DIVERGE.json]")
        sys.exit(2)
    info = enrich_origin_file(sys.argv[1],
                              sys.argv[2] if len(sys.argv) > 2 else None)
    print("added=%d total=%d func=%s" % (
        info["added"], info["offsets"], info["fork_func"]))
    for o in (info["result"].get("offsets") or [])[:12]:
        print("  0x%x len=%s via=%s" % (
            o["offset"], o.get("length"), o.get("via")))
