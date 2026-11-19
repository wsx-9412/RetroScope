#!/usr/bin/env python3
"""census_crash_reach.py - corrected Case A/B/C census for match/no-match pairs.

Ground truth priority:
  1. version_sweep log Case A/B/C markers (pipeline's own verdict on original PoC)
  2. GDB probe of the *mapped reference crash line* (never the fork line)

Match status priority:
  1. allver_mut status (MATCH / NO_MATCH / BASELINE_TRIGGERS)
  2. SUCCESS_CVES from poc_run_commands.md
  3. explicit "reproduced the reference crash on the target: YES/no"

Usage:
  python3 census_crash_reach.py
  python3 census_crash_reach.py --probe-missing -j 6 --timeout 40
  python3 census_crash_reach.py --force-probe -j 6
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

BASE = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE))

from trace_fork_offsets import (  # noqa: E402
    resolve_binary,
    build_run_env,
    extract_crash_signature,
    _replace_input_arg,
    _attach_crash_statement,
)

VS_DIR = BASE / "results" / "version_sweep"
ALLVER_DIR = BASE / "results" / "allver_mut"
OUT_DIR = BASE / "results" / "crash_line_reach"
PAIR_CACHE = OUT_DIR / "pairs_census"

SUCCESS_CVES = {
    "CVE-2019-9074", "CVE-2017-14039", "CVE-2015-9101",
    "CVE-2019-13147", "CVE-2022-0891",
}

PROJ_PREFIX = (
    "tiff-", "lame-", "binutils-", "giflib-", "audiofile-", "exiv2-",
    "freetype-", "jasper-version-", "libredwg-", "openjpeg-", "libxml2-",
    "pcre2-", "libpng-", "expat-", "openexr-", "libarchive-", "libxml-",
    "libsndfile-", "sqlite-",
)


def norm_ver(ver: str) -> str:
    ver = str(ver or "")
    if ver.endswith(".first_pass"):
        ver = ver[: -len(".first_pass")]
    if ver.endswith(".driver"):
        ver = ver[: -len(".driver")]
    for p in PROJ_PREFIX:
        if ver.startswith(p):
            ver = ver[len(p):]
            break
    return ver


def load_allver():
    out = {}
    if not ALLVER_DIR.is_dir():
        return out
    for f in sorted(ALLVER_DIR.glob("*.json")):
        if f.name.startswith("_"):
            continue
        try:
            d = json.load(open(f))
        except Exception:
            continue
        cve, ver = d.get("cve"), str(d.get("ver") or "")
        if not cve or not ver:
            continue
        out[(cve, ver)] = d
        out.setdefault((cve, norm_ver(ver)), d)
    return out


def parse_vsweep_log(path: Path) -> dict:
    t = open(path, errors="replace").read()
    has_A = "Target reached the crash point but didn't trigger" in t
    has_B = "Target did not reach the crash point" in t
    has_C = "Target crashes before" in t
    has_line_no = (
        "Target calls the crash function but never executes" in t
    )

    # Match pipeline control flow: A and B are exclusive in one analysis
    # pass; multi-pass logs may contain both — take the first occurrence.
    if has_A and has_B:
        ia = t.find("Target reached the crash point")
        ib = t.find("Target did not reach the crash point")
        case = "A" if 0 <= ia < ib else "B"
    elif has_A:
        case = "A"
    elif has_B:
        case = "B"
    elif has_C:
        case = "C"
    else:
        case = None

    ref_crash = None
    for pat in (
        r"Reference CRASH:\s*(.+)",
        r"^\s*Reference crash:\s*(.+)",
        r"^\s*\[\*\] reference crash:\s*(.+)",
        r"Reference CRASH:\s*(.+)",
    ):
        m = re.search(pat, t, re.M)
        if m:
            ref_crash = m.group(1).strip()
            break
    # Fallback: first ASAN/SIG line with "in <func> at <file>:<line>"
    if not ref_crash:
        m = re.search(
            r"(ASAN:[\w:-]+\s+in\s+\S+\s+at\s+\S+:\d+"
            r"|SIG\w+\s+in\s+\S+\s+at\s+\S+:\d+"
            r"|heap-buffer-overflow in \S+ \([^)]+:\d+"
            r"|SEGV in \S+ \([^)]+:\d+)",
            t,
        )
        if m:
            ref_crash = m.group(1).strip()

    ref_no_crash = bool(
        re.search(r"Reference:\s*no crash", t)
        or re.search(r"Reference binary did not produce an ASan crash", t)
    )

    # Recover runtime metadata from log header when allver is missing
    def _log_field(*pats):
        for p in pats:
            m = re.search(p, t, re.M)
            if m:
                return m.group(1).strip()
        return None

    log_input = _log_field(
        r"^Input:\s+(.+)$",
        r"^\[\*\]\s+input\s*:\s*(\S+)",
        r"^Input file:\s*(\S+)",
    )
    log_args = _log_field(
        r"^Arguments template:\s*(.+)$",
        r"^\[\*\]\s+args\s*:\s*(.+)$",
    )
    log_bin_t = _log_field(
        r"^Target binary:\s*(.+)$",
        r"^\[\*\]\s+Target binary:\s*(.+)$",
        r"^binary B:\s*(.+)$",
    )
    log_bin_r = _log_field(
        r"^Reference binary:\s*(.+)$",
        r"^\[\*\]\s+Reference binary:\s*(.+)$",
        r"^binary A:\s*(.+)$",
    )
    log_args = _log_field(
        r"^Arguments template:\s*(.+)$",
        r"^\[\*\]\s+args\s*:\s*(.+)$",
    )
    # Prefer fully-resolved args line over template with {input}
    m = re.search(r"^\[\*\]\s+args\s*:\s*(.+)$", t, re.M)
    if m:
        log_args = m.group(1).strip()
    else:
        m = re.search(r"^Arguments template:\s*(.+)$", t, re.M)
        if m:
            log_args = m.group(1).strip()

    m = re.search(
        r"reproduced the reference crash on the target:\s*(YES|no)",
        t, re.I,
    )
    vs_match = m.group(1).upper() if m else None
    if vs_match is None:
        if "MATCH SUMMARY (target reproduces reference crash)" in t:
            vs_match = "MUT_YES"
        elif "No byte value reproduces the reference crash" in t:
            vs_match = "MUT_NO"

    tgt = re.search(r"Target:\s*(.+)", t)
    tgt_line = tgt.group(1).strip() if tgt else None

    # Infer project/version from header paths
    log_proj = None
    m = re.search(r"^Reference:\s+(.+)$", t, re.M)
    ref_path = m.group(1).strip() if m else None

    return {
        "case": case,
        "has_A": has_A,
        "has_B": has_B,
        "has_C": has_C,
        "line_no_msg": has_line_no,
        "ref_crash": ref_crash,
        "ref_no_crash": ref_no_crash,
        "vs_match": vs_match,
        "tgt_line": tgt_line,
        "log_input": log_input,
        "log_args": log_args,
        "log_bin_t": log_bin_t,
        "log_bin_r": log_bin_r,
        "ref_path": ref_path,
        "backward_found": (
            "Backward tracer located the fork statement" in t
        ),
    }


def parse_ref_crash_str(s: str) -> dict | None:
    """Parse several ref-crash string formats from logs."""
    if not s:
        return None
    s = s.strip()
    # Strip trailing ", rc=1)" style noise: "heap-buffer-overflow in foo (bar.c:12, rc=1)"
    # Formats:
    #   ASAN:SEGV in foo at /path/file.c:123
    #   SIGSEGV in foo at file.c:123
    #   SEGV in foo (file.c:123, rc=1)
    #   heap-buffer-overflow in foo (file.c:123, rc=1)
    m = re.search(
        r"(?:ASAN:)?([\w:-]+)\s+in\s+(\S+)\s+at\s+(.+?):(\d+)\s*$", s
    )
    if m and "/" in m.group(3) or (m and "." in os.path.basename(m.group(3))):
        return {
            "signal": m.group(1),
            "function": m.group(2),
            "file": m.group(3),
            "line": int(m.group(4)),
        }
    m = re.search(
        r"([\w:-]+)\s+in\s+(\S+)\s+\((.+?):(\d+)(?:,[^)]*)?\)", s
    )
    if m:
        return {
            "signal": m.group(1),
            "function": m.group(2),
            "file": m.group(3),
            "line": int(m.group(4)),
        }
    m = re.search(r"in\s+(\S+)\s+at\s+(.+?):(\d+)", s)
    if m:
        return {
            "signal": None,
            "function": m.group(1),
            "file": m.group(2),
            "line": int(m.group(3)),
        }
    m = re.search(r"in\s+(\S+)\s+\((.+?):(\d+)", s)
    if m:
        return {
            "signal": None,
            "function": m.group(1),
            "file": m.group(2),
            "line": int(m.group(3)),
        }
    return None


def infer_proj_from_text(*texts):
    blob = " ".join(str(x or "") for x in texts).lower()
    rules = [
        ("tiff", "tiff"), ("libtiff", "tiff"),
        ("lame", "lame"),
        ("binutils", "binutils"), ("objdump", "binutils"),
        ("readelf", "binutils"), ("nm-new", "binutils"),
        ("giflib", "giflib"), ("gif2rgb", "giflib"),
        ("audiofile", "audiofile"),
        ("jasper", "jasper"),
        ("libredwg", "libredwg"), ("dwg2dxf", "libredwg"),
        ("openjpeg", "openjpeg"), ("opj_compress", "openjpeg"),
        ("openjp2", "openjpeg"),
        ("libxml", "libxml2"), ("xmllint", "libxml2"),
        ("pcre", "pcre2"), ("pcre2test", "pcre2"),
        ("exiv2", "exiv2"),
        ("freetype", "freetype"),
        ("libsndfile", "libsndfile"), ("sndfile-convert", "libsndfile"),
        ("libarchive", "libarchive"), ("bsdtar", "libarchive"),
        ("openexr", "openexr"), ("exrcheck", "openexr"),
        ("expat", "expat"), ("xmlwf", "expat"),
        ("libpng", "libpng"), ("pngfix", "libpng"),
        ("sqlite", "sqlite"),
    ]
    for needle, proj in rules:
        if needle in blob:
            return proj
    return None


def resolve_bin_from_log(path_or_none, proj, ver, prefer_prog=None):
    """Resolve a binary path; try log path first, then version tree."""
    if path_or_none and os.path.isfile(path_or_none):
        # skip /tmp/fork_analysis_* which is gone
        p = path_or_none
        if not p.startswith("/tmp/fork_analysis"):
            return p
    if not proj or not ver:
        return None
    try:
        from audit_crash_line_reach import (
            resolve_version_dir, locate_binary, PROJECTS,
        )
    except Exception:
        return None
    vdir = resolve_version_dir(proj, ver)
    if not vdir:
        return None
    if prefer_prog:
        b = locate_binary(vdir, prefer_prog)
        if b:
            return b
    # walk for common program names
    want = {
        "tiff": ["tiffcp", "tiffcrop", "tiff2rgba", "tiffinfo", "tiffset"],
        "lame": ["lame"],
        "binutils": ["objdump", "readelf", "nm", "nm-new", "objcopy", "ld"],
        "giflib": ["gif2rgb", "giftext"],
        "openjpeg": ["opj_compress", "opj_decompress", "opj_dump"],
        "libxml2": ["xmllint"],
        "pcre2": ["pcre2test"],
        "exiv2": ["exiv2"],
        "jasper": ["imginfo", "jasper"],
        "libredwg": ["dwg2dxf", "dwgread"],
        "audiofile": ["sfconvert", "sfedit"],
        "libsndfile": ["sndfile-convert"],
        "libarchive": ["bsdtar"],
        "openexr": ["exrcheck"],
        "freetype": ["fttest"],
        "expat": ["xmlwf"],
        "libpng": ["pngfix"],
    }.get(proj, [])
    for prog in want:
        b = locate_binary(vdir, prog)
        if b:
            return b
    return locate_binary(vdir, prefer_prog) if prefer_prog else None


def collect_pairs():
    """Build unified pair list from version_sweep + allver_mut."""
    allver = load_allver()
    pairs = {}  # key: (cve, norm_ver)

    def key_of(cve, ver):
        return (cve, norm_ver(ver))

    # version_sweep first (has Case markers)
    if VS_DIR.is_dir():
        for cve_dir in sorted(VS_DIR.iterdir()):
            if not cve_dir.is_dir():
                continue
            cve = cve_dir.name
            if cve.endswith(".bak") or ".bak_" in cve:
                continue
            for lg in sorted(cve_dir.glob("*.log")):
                fn = lg.name
                ver_raw = fn[:-4] if fn.endswith(".log") else fn
                info = parse_vsweep_log(lg)
                k = key_of(cve, ver_raw)
                av = allver.get(k) or allver.get((cve, ver_raw))
                rec = {
                    "pair_id": "%s__%s" % (cve, norm_ver(ver_raw)),
                    "cve": cve,
                    "ver_raw": ver_raw,
                    "ver": norm_ver(ver_raw),
                    "source": "version_sweep",
                    "log": str(lg.relative_to(BASE)),
                    "case": info["case"],
                    "ref_crash_str": info["ref_crash"],
                    "ref_no_crash": info.get("ref_no_crash"),
                    "vs_match": info["vs_match"],
                    "backward_found": info["backward_found"],
                    "line_no_msg": info["line_no_msg"],
                    "log_input": info.get("log_input"),
                    "log_args": info.get("log_args"),
                    "log_bin_t": info.get("log_bin_t"),
                    "log_bin_r": info.get("log_bin_r"),
                    "allver_status": (av or {}).get("status"),
                    "allver_matched": (av or {}).get("matched"),
                    "allver_baseline_triggers": (av or {}).get(
                        "baseline_triggers"
                    ),
                    "bin_t": (av or {}).get("bin_t") or info.get("log_bin_t"),
                    "bin_r": (av or {}).get("bin_r") or info.get("log_bin_r"),
                    "input": (av or {}).get("input") or info.get("log_input"),
                    "args": (av or {}).get("args_resolved")
                    or (av or {}).get("args")
                    or info.get("log_args"),
                    "fork_file": (av or {}).get("fork_file"),
                    "fork_line": (av or {}).get("fork_line"),
                    "ref": (av or {}).get("ref"),
                    "proj": (av or {}).get("proj") or infer_proj_from_text(
                        info.get("log_bin_t"), info.get("log_bin_r"),
                        info.get("ref_path"), ver_raw, cve, lg.name,
                    ),
                }
                # Prefer existing record; keep first Case marker if re-run
                if k in pairs:
                    if pairs[k]["case"] is None and rec["case"]:
                        pairs[k].update(
                            case=rec["case"],
                            ref_crash_str=rec["ref_crash_str"]
                            or pairs[k]["ref_crash_str"],
                        )
                    if not pairs[k].get("allver_status") and rec["allver_status"]:
                        pairs[k].update(
                            allver_status=rec["allver_status"],
                            allver_matched=rec["allver_matched"],
                            bin_t=rec["bin_t"] or pairs[k]["bin_t"],
                            input=rec["input"] or pairs[k]["input"],
                            args=rec["args"] or pairs[k]["args"],
                        )
                    continue
                pairs[k] = rec

    # allver-only pairs (match experiment without vsweep Case log)
    for (cve, ver), av in allver.items():
        if not re.match(r"CVE-|issue|official|unknown", cve or "", re.I):
            continue
        # skip duplicate norm key already present with same ver
        k = key_of(cve, ver)
        if k in pairs:
            continue
        # only add if this ver is the "raw" form not already covered
        if str(av.get("ver")) != ver and norm_ver(str(av.get("ver"))) == ver:
            # prefer raw ver key
            pass
        pairs[k] = {
            "pair_id": "%s__%s" % (cve, norm_ver(ver)),
            "cve": cve,
            "ver_raw": str(av.get("ver")),
            "ver": norm_ver(ver),
            "source": "allver_only",
            "log": None,
            "case": None,
            "ref_crash_str": None,
            "vs_match": None,
            "backward_found": False,
            "line_no_msg": False,
            "allver_status": av.get("status"),
            "allver_matched": av.get("matched"),
            "allver_baseline_triggers": av.get("baseline_triggers"),
            "bin_t": av.get("bin_t"),
            "input": av.get("input"),
            "args": av.get("args_resolved") or av.get("args"),
            "fork_file": av.get("fork_file"),
            "fork_line": av.get("fork_line"),
            "ref": av.get("ref"),
            "proj": av.get("proj"),
        }

    return list(pairs.values())


def classify_match(rec) -> str:
    st = (rec.get("allver_status") or "").upper()
    if st == "MATCH":
        return "MATCH"
    if st == "NO_MATCH":
        return "NO_MATCH"
    if st == "BASELINE_TRIGGERS":
        return "BASELINE_TRIGGERS"
    vm = rec.get("vs_match")
    if vm == "YES":
        return "MATCH"
    if vm == "NO":
        return "NO_MATCH"
    if rec.get("cve") in SUCCESS_CVES:
        return "SUCCESS_LEGACY"
    if vm == "MUT_YES":
        return "MATCH"
    if vm == "MUT_NO":
        return "NO_MATCH"
    return "UNKNOWN"


def reach_from_case(case: str | None) -> str | None:
    if case == "A":
        return "reached_no_crash"
    if case == "B":
        return "not_reached"
    if case == "C":
        return "not_reached_early_crash"
    return None


# --- GDB probe on mapped crash line (pipeline style) -----------------

GDB_SCRIPT = r"""
import gdb, json, os
CFG = json.load(open(os.environ["CENSUS_CFG"]))
gdb.execute("set pagination off")
gdb.execute("set confirm off")
gdb.execute("set breakpoint pending on")
try:
    gdb.execute("set disable-randomization on")
except Exception:
    pass

class HitBP(gdb.Breakpoint):
    def __init__(self, spec):
        super(HitBP, self).__init__(spec)
        self.n = 0
    def stop(self):
        self.n += 1
        print("REACH_HIT " + json.dumps({"hit": self.n}))
        return False

bps = []
for spec in CFG.get("specs", []):
    try:
        bps.append(HitBP(spec))
    except Exception:
        pass
if not bps:
    print("REACH_BP_UNRESOLVED")
gdb.execute("run")
gdb.execute("quit")
"""


def map_ref_crash_to_target(ref: dict, bin_t: str) -> dict | None:
    """Map ref crash file:line onto target using pipeline _find_matching_line."""
    from divergence_analyzer import (
        find_source_dirs,
        _read_source_line,
        _find_matching_line,
        _locate_source_file,
        find_version_root,
    )
    ref_file, ref_line = ref.get("file"), ref.get("line")
    if not ref_file or not ref_line:
        return None
    source_dirs = list(find_source_dirs(bin_t) or [])
    vroot = find_version_root(bin_t)
    if vroot and str(vroot) not in source_dirs:
        source_dirs = [str(vroot)] + source_dirs
    # Read ref statement from ref tree if path exists, else same basename
    ref_stmt = None
    if os.path.isfile(ref_file):
        try:
            ref_stmt = open(ref_file, encoding="utf-8", errors="replace").readlines()[
                int(ref_line) - 1
            ].strip()
        except Exception:
            ref_stmt = None
    mapped = _find_matching_line(ref_file, ref_stmt or "", source_dirs)
    if mapped:
        tgt_line, tgt_text = mapped
        full = _locate_source_file(ref_file, source_dirs)
        if full:
            return {
                "file": full,
                "line": int(tgt_line),
                "stmt": tgt_text,
                "how": "pipeline_find_matching_line",
            }
    # Fallback: locate same basename in target, try statement elsewhere
    base = os.path.basename(ref_file)
    full = _locate_source_file(ref_file, source_dirs)
    if not full:
        # search
        if vroot:
            for p in Path(vroot).rglob(base):
                if p.is_file():
                    full = str(p)
                    break
    if full and ref_stmt:
        mapped = _find_matching_line(full, ref_stmt, [os.path.dirname(full)])
        if mapped:
            return {
                "file": full,
                "line": int(mapped[0]),
                "stmt": mapped[1],
                "how": "basename_stmt_match",
            }
    if full and ref_line:
        # last resort: same line number in target file (weak)
        return {
            "file": full,
            "line": int(ref_line),
            "stmt": ref_stmt,
            "how": "same_line_number_weak",
        }
    return None


def run_ref_crash(job, timeout) -> dict | None:
    from divergence_analyzer import _detect_crash_point, find_source_dirs
    bin_r = job.get("bin_r")
    # resolve via version tree if missing
    if not bin_r or not os.path.isfile(bin_r):
        bin_r = resolve_ref_binary(job)
    if not bin_r or not os.path.isfile(bin_r):
        return None
    inp = job.get("input")
    args = job.get("args") or []
    if isinstance(args, str):
        args = args.split()
    resolved = []
    for a in args:
        a = str(a)
        if a in ("INPUT", "{input_file}", "{input}"):
            resolved.append(inp)
        else:
            resolved.append(_replace_input_arg(a, inp or a, inp or a))
    if not any(str(a) == inp for a in resolved) and inp:
        # try input as first arg if not present
        if not any(os.path.basename(str(a)) == os.path.basename(inp or "")
                   for a in resolved):
            resolved = [inp] + resolved
    try:
        sig = _detect_crash_point(
            bin_r, resolved, build_run_env(bin_r),
            find_source_dirs(bin_r), timeout=timeout,
        )
        return sig
    except Exception:
        return None


def resolve_ref_binary(job) -> str | None:
    from trace_fork_offsets import resolve_binary as rb
    for key in ("bin_r", "ref_bin", "log_bin_r"):
        v = job.get(key)
        if v and os.path.isfile(v) and not str(v).startswith("/tmp/fork_analysis"):
            return rb(v)
    prog = None
    bt = job.get("bin_t") or job.get("log_bin_t") or ""
    if bt:
        prog = os.path.basename(bt)
    # version tree
    try:
        from audit_crash_line_reach import resolve_version_dir, locate_binary
    except Exception:
        return None
    proj = job.get("proj")
    ref = job.get("ref")
    if not proj or not ref:
        return None
    vdir = resolve_version_dir(proj, ref)
    if not vdir:
        return None
    if prog:
        b = locate_binary(vdir, prog)
        if b:
            return b
    return resolve_bin_from_log(None, proj, ref, prefer_prog=prog)


def probe_pair(job, timeout) -> dict:
    # Resolve target binary: log path -> version tree
    bin_t = job.get("bin_t")
    if bin_t and not os.path.isfile(bin_t):
        bin_t = None
    if not bin_t:
        bin_t = resolve_bin_from_log(
            job.get("log_bin_t"), job.get("proj"), job.get("ver")
        )
    if not bin_t:
        try:
            from audit_crash_line_reach import resolve_pair_binaries
            resolved = resolve_pair_binaries(job)
            bin_t = resolved.get("bin_t")
            if resolved.get("bin_r"):
                job["bin_r"] = resolved["bin_r"]
        except Exception:
            pass
    if not bin_t or not os.path.isfile(bin_t):
        return {"reach": None, "status": "skip_no_binary"}
    job["bin_t"] = bin_t
    real = resolve_binary(bin_t)
    if not real or not os.path.isfile(real):
        return {"reach": None, "status": "skip_no_binary"}

    # If pipeline recorded that ref does not crash on original PoC, there is
    # no reference crash line to reach — mark explicitly (not a probe miss).
    if job.get("ref_no_crash"):
        return {
            "reach": None,
            "status": "skip_ref_no_crash",
            "note": "reference did not crash on original PoC in analysis log",
        }

    ref = parse_ref_crash_str(job.get("ref_crash_str") or "")
    site = None
    how = None
    if ref:
        site = map_ref_crash_to_target(ref, real)
        if site:
            how = "ref_crash_mapped"
    if site is None:
        # run ref crash detection
        sig = run_ref_crash(job, timeout)
        if sig:
            fr = (sig.get("crash_frames") or [{}])[0]
            summ = sig.get("summary") or {}
            ref2 = {
                "file": fr.get("file") or summ.get("file"),
                "line": fr.get("line") or summ.get("line"),
                "function": fr.get("function") or summ.get("function"),
            }
            if ref2["file"] and "sanitizer" not in str(ref2["file"]):
                site = map_ref_crash_to_target(ref2, real)
                if site:
                    how = "ref_run_then_map"
                    job["ref_crash_str"] = (
                        "%s in %s at %s:%s"
                        % (sig.get("type") or "", ref2.get("function") or "",
                           ref2.get("file"), ref2.get("line"))
                    )
    if site is None:
        # NEVER fall back to fork line — that was the bug
        return {
            "reach": None,
            "status": "skip_no_crash_site",
            "ref_crash_str": job.get("ref_crash_str"),
            "ref": ref,
        }

    inp = job.get("input")
    if not inp or not os.path.isfile(inp):
        # try common in/ locations
        cve = job.get("cve") or ""
        for cand in (
            BASE / "in" / cve,
            BASE / "in" / "libtiff" / cve,
            BASE / "in" / "lame" / cve,
            BASE / "in" / "openjpeg" / (cve + ".tif"),
            BASE / "in" / "binutils" / cve,
            BASE / "in" / "libredwg" / (cve + ".dwg"),
            BASE / "in" / "libsndfile" / cve,
            BASE / "in" / "jasper" / cve,
        ):
            if cand.is_file():
                inp = str(cand)
                job["input"] = inp
                break
    if not inp or not os.path.isfile(inp):
        return {"reach": None, "status": "skip_no_input", "site": site}

    args = job.get("args") or []
    if isinstance(args, str):
        args = args.split()
    run_args = []
    for a in args:
        a = str(a)
        if a in ("INPUT", "{input_file}", "{input}"):
            run_args.append(inp)
        else:
            run_args.append(_replace_input_arg(a, inp, inp))
    if not run_args:
        run_args = [inp]
    # If args already contain resolved input path, keep as-is
    if not any(
        str(a) == inp or (
            os.path.isabs(str(a)) and os.path.abspath(str(a)) == os.path.abspath(inp)
        )
        for a in run_args
    ):
        # template may have been resolved already with a different path — if any
        # arg looks like a file that exists under in/, leave it; else append inp
        if not any(os.path.isfile(str(a)) for a in run_args):
            run_args = run_args + [inp]

    specs = [
        "%s:%d" % (site["file"], site["line"]),
        "%s:%d" % (os.path.basename(site["file"]), site["line"]),
    ]
    specs = list(dict.fromkeys(specs))

    tmpdir = tempfile.mkdtemp(prefix="census_reach_")
    cfg_path = os.path.join(tmpdir, "cfg.json")
    script_path = os.path.join(tmpdir, "probe.py")
    with open(cfg_path, "w") as fh:
        json.dump({"specs": specs}, fh)
    with open(script_path, "w") as fh:
        fh.write(GDB_SCRIPT)

    env = build_run_env(real)
    env["ASAN_OPTIONS"] = (
        "detect_leaks=0:abort_on_error=0:allocator_may_return_null=1:"
        "halt_on_error=0"
    )
    env["CENSUS_CFG"] = cfg_path

    t0 = time.time()
    try:
        proc = subprocess.run(
            ["gdb", "-batch", "-nx", "-q", "-x", script_path,
             "--args", str(real)] + [str(a) for a in run_args],
            env=env, capture_output=True, text=True, errors="replace",
            timeout=timeout,
        )
        out = (proc.stdout or "") + "\n" + (proc.stderr or "")
    except subprocess.TimeoutExpired:
        return {"reach": None, "status": "error_timeout", "site": site}
    except Exception as e:
        return {"reach": None, "status": "error_gdb", "error": str(e)[:200],
                "site": site}

    hits = len(re.findall(r"REACH_HIT \{", out))
    bp_unresolved = "REACH_BP_UNRESOLVED" in out
    sig = extract_crash_signature(out)
    if sig:
        _attach_crash_statement(sig, real)
    signaled = None
    m = re.search(r"(?:terminated|received) signal (\w+)", out)
    if m:
        signaled = m.group(1)
    exited = None
    m = re.search(r"exited with code\s+0*(\d+)", out)
    if m:
        exited = int(m.group(1), 10)
    elif re.search(r"exited normally", out):
        exited = 0

    reached = hits > 0
    if reached:
        cls = "A_reached_then_crash" if (sig or signaled) else "A_reached_no_crash"
    else:
        if sig or signaled:
            cls = "C_not_reached_crash"
        elif exited is not None:
            cls = "B_not_reached_exit"
        elif bp_unresolved:
            cls = "error_bp_unresolved"
        else:
            cls = "B_not_reached_other"

    return {
        "reach": reached,
        "status": "ok",
        "classification": cls,
        "hit_count": hits,
        "site": site,
        "how": how,
        "bp_unresolved": bp_unresolved,
        "signal": signaled,
        "exit_code": exited,
        "target_crash_type": (sig or {}).get("type"),
        "elapsed": round(time.time() - t0, 2),
    }


def ensure_ref_bin(job):
    if job.get("bin_r") and os.path.isfile(job["bin_r"]):
        return
    try:
        from audit_crash_line_reach import resolve_pair_binaries
        resolved = resolve_pair_binaries(job)
        if resolved.get("bin_r"):
            job["bin_r"] = resolved["bin_r"]
        if resolved.get("bin_t") and not job.get("bin_t"):
            job["bin_t"] = resolved["bin_t"]
    except Exception:
        pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--probe-missing", action="store_true",
                    help="probe pairs without Case A/B/C markers")
    ap.add_argument("--force-probe", action="store_true")
    ap.add_argument("-j", "--workers", type=int, default=4)
    ap.add_argument("--timeout", type=int, default=40)
    ap.add_argument("--limit", type=int, default=0)
    a = ap.parse_args()

    pairs = collect_pairs()
    if a.limit:
        pairs = pairs[: a.limit]
    print("[*] pairs collected: %d" % len(pairs))
    print("    case:", Counter(p.get("case") or "None" for p in pairs))
    print("    source:", Counter(p.get("source") for p in pairs))

    # Ensure ref binaries for probes
    need_probe = []
    for p in pairs:
        p["match"] = classify_match(p)
        p["reach"] = reach_from_case(p.get("case"))
        p["reach_source"] = "case_marker" if p["reach"] else None
        if p["reach"] is None:
            need_probe.append(p)

    print("[*] without case marker (need probe): %d" % len(need_probe))
    print("    match among need_probe:", Counter(p["match"] for p in need_probe))

    if a.probe_missing or a.force_probe:
        targets = need_probe if not a.force_probe else pairs
        # force-probe only re-probes if no case? force all without case too
        if a.force_probe:
            targets = [p for p in pairs if p.get("case") is None] or targets
        print("[*] probing %d pairs ..." % len(targets))
        PAIR_CACHE.mkdir(parents=True, exist_ok=True)
        t0 = time.time()
        with ThreadPoolExecutor(max_workers=max(1, a.workers)) as ex:
            futs = {}
            for p in targets:
                cache = PAIR_CACHE / (
                    re.sub(r"[^\w.\-]+", "_", p["pair_id"]) + ".json"
                )
                if cache.is_file() and not a.force_probe:
                    try:
                        cached = json.load(open(cache))
                        p.update(
                            reach=cached.get("reach"),
                            reach_source="probe",
                            probe=cached,
                        )
                        continue
                    except Exception:
                        pass
                futs[ex.submit(probe_pair, p, a.timeout)] = (p, cache)
            done = 0
            for fut in as_completed(futs):
                p, cache = futs[fut]
                done += 1
                try:
                    res = fut.result()
                except Exception as e:
                    res = {"reach": None, "status": "error", "error": str(e)[:200]}
                p["reach"] = res.get("reach")
                p["reach_source"] = "probe" if res.get("reach") is not None else "probe_failed"
                p["probe"] = res
                try:
                    with open(cache, "w") as fh:
                        json.dump(
                            {
                                "pair_id": p["pair_id"],
                                "reach": res.get("reach"),
                                "status": res.get("status"),
                                "classification": res.get("classification"),
                                "site": res.get("site"),
                                "how": res.get("how"),
                                "ref_crash_str": p.get("ref_crash_str"),
                                "match": p.get("match"),
                                "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
                            },
                            fh, indent=1, default=str,
                        )
                except Exception:
                    pass
                if done % 15 == 0 or done == len(futs):
                    print("  [%d/%d] %.0fs last=%s reach=%s" % (
                        done, len(futs), time.time() - t0,
                        p["pair_id"], res.get("reach")), flush=True)

    # Final tallies
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    def bucket(p):
        r = p.get("reach")
        if r is True or r == "reached_no_crash":
            return "reached"
        if r is False or r in ("not_reached", "not_reached_early_crash"):
            if r == "not_reached_early_crash" or p.get("case") == "C":
                return "not_reached_early_crash"
            cls = (p.get("probe") or {}).get("classification") or ""
            if cls.startswith("C_"):
                return "not_reached_early_crash"
            return "not_reached"
        if r is None:
            return "unknown"
        # unexpected string
        return "unknown"

    for p in pairs:
        p["reach_bucket"] = bucket(p)

    # Pair-level cross: match x reach
    cross = defaultdict(Counter)
    for p in pairs:
        cross[p["match"]][p["reach_bucket"]] += 1

    # CVE-level: a CVE is "reached" if ANY of its pairs reached without crash?
    # User asked: among match/no-match, how many CVEs ...
    # Use: for each CVE, classify by majority / any-A / pure
    cve_info = defaultdict(lambda: {
        "matches": set(), "reaches": set(), "cases": set(), "pairs": 0,
        "reached_pairs": 0, "not_reached_pairs": 0, "unknown_pairs": 0,
    })
    for p in pairs:
        c = cve_info[p["cve"]]
        c["pairs"] += 1
        c["matches"].add(p["match"])
        c["reaches"].add(p["reach_bucket"])
        if p.get("case"):
            c["cases"].add(p["case"])
        if p["reach_bucket"] == "reached":
            c["reached_pairs"] += 1
        elif p["reach_bucket"].startswith("not_reached"):
            c["not_reached_pairs"] += 1
        else:
            c["unknown_pairs"] += 1

    # CVE match label: prefer definitive
    def cve_match(ms):
        if "MATCH" in ms:
            return "MATCH"
        if "SUCCESS_LEGACY" in ms:
            return "SUCCESS_LEGACY"
        if "NO_MATCH" in ms and "MATCH" not in ms:
            # if only NO_MATCH and UNKNOWN
            if ms <= {"NO_MATCH", "UNKNOWN"}:
                return "NO_MATCH"
        if "BASELINE_TRIGGERS" in ms and ms <= {
            "BASELINE_TRIGGERS", "UNKNOWN"
        }:
            return "BASELINE_TRIGGERS"
        if ms == {"UNKNOWN"}:
            return "UNKNOWN"
        if "NO_MATCH" in ms:
            return "NO_MATCH"
        return "MIXED"

    cve_cross = defaultdict(Counter)
    for cve, info in cve_info.items():
        m = cve_match(info["matches"])
        # CVE reach: any reached_no_crash counts as reached for that CVE
        if info["reached_pairs"] > 0:
            r = "reached"
        elif info["not_reached_pairs"] > 0:
            r = "not_reached"
        else:
            r = "unknown"
        cve_cross[m][r] += 1
        cve_cross[m]["n_pairs"] += info["pairs"]

    # Case-only tallies (ground truth subset)
    case_pairs = [p for p in pairs if p.get("case")]
    case_cves = defaultdict(set)
    for p in case_pairs:
        case_cves[p["case"]].add(p["cve"])
    case_cve_all = set()
    for s in case_cves.values():
        case_cve_all |= s
    mixed_cves = [
        cve for cve, info in cve_info.items()
        if len(info["cases"]) > 1
    ]

    summary = {
        "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "total_pairs": len(pairs),
        "total_cves": len(cve_info),
        "case_pair_counts": dict(Counter(
            p.get("case") or "None" for p in pairs
        )),
        "case_cve_counts": {
            k: len(v) for k, v in case_cves.items()
        },
        "case_cves_any_marker": len(case_cve_all),
        "mixed_case_cves": sorted(mixed_cves),
        "reach_pair_counts": dict(Counter(p["reach_bucket"] for p in pairs)),
        "match_pair_counts": dict(Counter(p["match"] for p in pairs)),
        "cross_match_x_reach_pairs": {
            m: dict(c) for m, c in sorted(cross.items())
        },
        "cross_match_x_reach_cves": {
            m: {k: v for k, v in c.items() if k != "n_pairs"}
            for m, c in sorted(cve_cross.items())
        },
        "cve_match_counts": dict(Counter(
            cve_match(i["matches"]) for i in cve_info.values()
        )),
        "reach_source_counts": dict(Counter(
            p.get("reach_source") or "none" for p in pairs
        )),
        "probe_status_counts": dict(Counter(
            (p.get("probe") or {}).get("status") or "n/a"
            for p in pairs
            if p.get("probe")
        )),
    }

    with open(OUT_DIR / "_census_summary.json", "w") as fh:
        json.dump(summary, fh, indent=2, default=str)

    # CSV
    fields = [
        "pair_id", "cve", "ver", "source", "match", "case",
        "reach", "reach_bucket", "reach_source", "ref_crash_str",
        "allver_status", "probe_status", "probe_class", "probe_how",
        "probe_file", "probe_line", "hit_count",
    ]
    with open(OUT_DIR / "_census_pairs.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for p in sorted(pairs, key=lambda x: (x.get("cve") or "",
                                              str(x.get("ver") or ""))):
            pr = p.get("probe") or {}
            site = pr.get("site") or {}
            w.writerow({
                "pair_id": p.get("pair_id"),
                "cve": p.get("cve"),
                "ver": p.get("ver"),
                "source": p.get("source"),
                "match": p.get("match"),
                "case": p.get("case"),
                "reach": p.get("reach"),
                "reach_bucket": p.get("reach_bucket"),
                "reach_source": p.get("reach_source"),
                "ref_crash_str": p.get("ref_crash_str"),
                "allver_status": p.get("allver_status"),
                "probe_status": pr.get("status"),
                "probe_class": pr.get("classification"),
                "probe_how": pr.get("how") or site.get("how"),
                "probe_file": site.get("file"),
                "probe_line": site.get("line"),
                "hit_count": pr.get("hit_count"),
            })

    with open(OUT_DIR / "_census_pairs.json", "w") as fh:
        json.dump(pairs, fh, indent=1, default=str)

    # Print report
    print("\n========== CORRECTED CENSUS ==========")
    print("pairs=%d  cves=%d" % (len(pairs), len(cve_info)))
    print("\nCase markers (ground truth, original PoC):")
    print("  pair-level:", summary["case_pair_counts"])
    print("  CVE-level  :", summary["case_cve_counts"])
    print("  CVEs with any Case marker: %d" % summary["case_cves_any_marker"])
    print("  mixed-case CVEs: %d" % len(mixed_cves))
    print("\nReach buckets (all pairs):", summary["reach_pair_counts"])
    print("Match labels (pairs):", summary["match_pair_counts"])
    print("\nPAIR-level  match x reach:")
    for m, row in sorted(cross.items()):
        print("  %-20s %s" % (m, dict(row)))
    print("\nCVE-level   match x reach (any pair reached => reached):")
    for m, row in sorted(cve_cross.items()):
        print("  %-20s %s" % (m, {
            k: v for k, v in row.items() if k != "n_pairs"
        }))
    print("\nreach_source:", summary["reach_source_counts"])
    if summary["probe_status_counts"]:
        print("probe_status:", summary["probe_status_counts"])
    print("\noutputs:")
    for n in ("_census_summary.json", "_census_pairs.csv",
              "_census_pairs.json"):
        print("  %s" % (OUT_DIR / n))


if __name__ == "__main__":
    main()
