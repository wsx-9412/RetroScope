#!/usr/bin/env python3
"""audit_crash_line_reach.py - batch original-PoC crash-line reachability audit.

For every match / no-match pair under results/, run the ORIGINAL PoC on the
target binary under GDB and classify whether it reaches the statement that
corresponds to the reference crash line:

  A_reached_no_crash    hit the line, did not die
  A_reached_then_crash  hit the line, then crashed
  B_not_reached_exit    never hit; process exited (other branch / early return)
  B_not_reached_other   never hit; neither clean exit nor crash
  C_not_reached_crash   never hit; target crashed earlier
  skipped / error_*     could not probe

Probe site:
  auto       - map ref ASan crash statement onto target, else known site
  ref_crash  - force ref-run + statement map
  known_site - diverge root_cause_*_b / allver fork_file:line (faster)

Usage:
  python3 audit_crash_line_reach.py
  python3 audit_crash_line_reach.py --limit 3 --force -v
  python3 audit_crash_line_reach.py --status NO_MATCH -j 8 --timeout 45
  python3 audit_crash_line_reach.py --probe known_site
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
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

BASE = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE))

from trace_fork_offsets import (
    resolve_binary,
    build_run_env,
    extract_crash_signature,
    _replace_input_arg,
    _attach_crash_statement,
    _path_basename,
)

ALLVER_DIR = BASE / "results" / "allver_mut"
DIVERGE_DIR = BASE / "results"
OUT_DIR = BASE / "results" / "crash_line_reach"
PAIR_DIR = OUT_DIR / "pairs"

PROJECTS = {
    "binutils":   ("config_binutils.py",  "binutils-versions", "binutils-"),
    "exiv2":      ("config_exiv2.py",     "exiv2-versions",    "exiv2-"),
    "freetype":   ("config_freetype.py",  "freetype-versions", "freetype-"),
    "giflib":     ("config_giflib.py",    "giflib-versions",   "giflib-"),
    "jasper":     ("config_jasper.py",    "jasper-versions",   "jasper-version-"),
    "lame":       ("config_lame.py",      "lame-versions",     "lame-"),
    "libarchive": ("config_libarchive.py", "libarchive-versions", "v"),
    "libredwg":   ("config_libredwg.py",  "libredwg-versions", "libredwg-"),
    "pcre2":      ("config_pcre2.py",     "pcre2-versions",    "pcre2-pcre2-"),
    "tiff":       ("config_libtiff.py",   "tiff-versions",     "tiff-"),
    "openjpeg":   ("config_openjpeg.py",  "openjpeg-versions", ""),
    "audiofile":  ("config_audiofile.py", "audiofile-versions", "audiofile-"),
    "libxml2":    ("config_libxml2.py",   "libxml2-versions",  "libxml2-"),
    "libpng":     ("config_libpng.py",    "libpng-versions",   "libpng-"),
    "openexr":    ("config_openexr.py",   "openexr-versions",  "openexr-"),
    "expat":      ("config_expat.py",     "expat-versions",    "libexpat-"),
}

PROG_TO_PROJ = {
    "tiffcp": "tiff", "tiffcrop": "tiff", "tiff2rgba": "tiff",
    "tiffinfo": "tiff", "tiffset": "tiff",
    "opj_compress": "openjpeg", "opj_decompress": "openjpeg",
    "opj_dump": "openjpeg",
    "lame": "lame",
    "xmllint": "libxml2",
    "readelf": "binutils", "objdump": "binutils", "nm": "binutils",
    "objcopy": "binutils", "ld": "binutils", "addr2line": "binutils",
    "gif2rgb": "giflib", "giftext": "giflib",
    "dwg2dxf": "libredwg", "dwgread": "libredwg",
    "bsdtar": "libarchive",
    "exrcheck": "openexr",
    "fttest": "freetype",
    "sfconvert": "audiofile", "sfedit": "audiofile",
    "sndfile-convert": "libsndfile",
    "pcre2test": "pcre2",
    "imginfo": "jasper",
    "exiv2": "exiv2",
    "pngfix": "libpng",
    "xmlwf": "expat",
}

PATH_TO_PROJ = [
    ("tiff", "tiff"), ("libtiff", "tiff"),
    ("openjpeg", "openjpeg"), ("openjp2", "openjpeg"),
    ("lame", "lame"), ("libxml", "libxml2"),
    ("binutils", "binutils"), ("giflib", "giflib"),
    ("redwg", "libredwg"), ("libarchive", "libarchive"),
    ("openexr", "openexr"), ("freetype", "freetype"),
    ("libpng", "libpng"), ("pcre", "pcre2"),
    ("jasper", "jasper"), ("audiofile", "audiofile"),
    ("expat", "expat"), ("sndfile", "libsndfile"),
]

SKIP_DIVERGE = re.compile(r"(flip|diverge_test|\.bak|copy)", re.I)
SUCCESS_CVES = {
    "CVE-2019-9074", "CVE-2017-14039", "CVE-2015-9101",
    "CVE-2019-13147", "CVE-2022-0891",
}


def resolve_version_dir(proj, ver):
    if not proj or proj not in PROJECTS or not ver:
        return None
    _, vroot, prefix = PROJECTS[proj]
    root = BASE / vroot
    if not root.is_dir():
        return None
    candidates = []
    if prefix:
        candidates.append(prefix + ver)
    candidates.append(ver)
    if prefix and ver.startswith(prefix):
        candidates.append(ver)
    for name in candidates:
        p = root / name
        if p.is_dir():
            return str(p)
    best = None
    for d in sorted(root.iterdir()):
        if not d.is_dir():
            continue
        if d.name.endswith(ver) or d.name.endswith("-" + ver):
            if best is None or len(d.name) > len(best.name):
                best = d
    return str(best) if best else None


def locate_binary(version_dir, program):
    if not version_dir or not os.path.isdir(version_dir) or not program:
        return None
    prefer = []
    asan = []
    skip = {".git", "autom4te.cache", "test", "tests", "doc", "docs",
            "html", "po", "m4", "cmake", "man", "config", "examples",
            "testdata", "devel", "bindings", "python"}
    for root, dirs, files in os.walk(version_dir):
        rel = os.path.relpath(root, version_dir)
        depth = 0 if rel == "." else rel.count(os.sep) + 1
        if depth > 6:
            dirs.clear()
            continue
        dirs[:] = [d for d in dirs if d not in skip]
        if program not in files:
            continue
        p = os.path.join(root, program)
        if not (os.path.isfile(p) and os.access(p, os.X_OK)):
            continue
        libs = os.path.join(root, ".libs", program)
        if os.path.isfile(libs) and os.access(libs, os.X_OK):
            prefer.append(libs)
        else:
            prefer.append(p)
        if "asan" in p.lower():
            asan.append(p)
    if asan:
        return asan[0]
    if prefer:
        for p in prefer:
            if any(s in p for s in ("/bin/", "/.libs/", "/tools/", "/frontend/",
                                    "/util/", "/programs/", "/sfcommands/")):
                return p
        return prefer[0]
    return None


def infer_proj(obj):
    if not isinstance(obj, dict):
        return None
    prog = obj.get("program_name") or ""
    if prog in PROG_TO_PROJ:
        return PROG_TO_PROJ[prog]
    for key in ("binary_b", "binary_a", "bin_t", "input", "input_file"):
        val = str(obj.get(key) or "").lower()
        if not val:
            continue
        for needle, proj in PATH_TO_PROJ:
            if needle in val:
                return proj
    proj = obj.get("proj")
    if proj in PROJECTS:
        return proj
    for key in ("version_a", "version_b", "ref", "ver"):
        v = str(obj.get(key) or "")
        if "openjpeg" in v or v.startswith("version.") or v.startswith("v2."):
            return "openjpeg"
    return None


def program_of(div, pair=None):
    for src in (pair, div):
        if src and src.get("program_name"):
            return src["program_name"]
    for src in (pair, div):
        if not src:
            continue
        b = src.get("binary_b") or src.get("bin_t")
        if b:
            return os.path.basename(str(b))
    return None


def load_pairs(only_status=None):
    by_key = {}
    if ALLVER_DIR.is_dir():
        for f in sorted(ALLVER_DIR.glob("CVE-*.json")):
            try:
                j = json.load(open(f))
            except Exception:
                continue
            cve, ver = j.get("cve"), j.get("ver")
            if not cve or ver is None:
                continue
            by_key[(cve, str(ver))] = {
                "pair_id": "%s__%s" % (cve, ver),
                "source": "allver",
                "cve": cve,
                "ver": str(ver),
                "ref": j.get("ref"),
                "proj": j.get("proj"),
                "status": j.get("status"),
                "bin_t": j.get("bin_t"),
                "input": j.get("input"),
                "args": j.get("args"),
                "args_resolved": j.get("args_resolved"),
                "fork_file": j.get("fork_file"),
                "fork_line": j.get("fork_line"),
                "fork_func": j.get("fork_func"),
            }
    for f in sorted(DIVERGE_DIR.glob("*.diverge.json")):
        name = f.name
        if SKIP_DIVERGE.search(name):
            continue
        if not name.startswith(("CVE-", "issue", "official", "unknown")):
            continue
        try:
            raw = json.load(open(f))
        except Exception:
            continue
        div = raw.get("divergence", raw)
        m = re.match(r"(CVE-\d{4}-\d+)", name)
        cve = m.group(1) if m else name.replace(".diverge.json", "")
        vb = div.get("version_b") or "default"
        key = (cve, str(vb))
        if key in by_key:
            job = by_key[key]
            if not job.get("fork_file"):
                job["fork_file"] = div.get("root_cause_file_b") or div.get("root_cause_file")
                job["fork_line"] = div.get("root_cause_line_b") or div.get("root_cause_line")
            if not job.get("bin_t"):
                job["bin_t"] = div.get("binary_b")
            if not job.get("input"):
                job["input"] = div.get("input_file")
            if not job.get("args"):
                job["args"] = div.get("args_b") or div.get("args_a")
            if not job.get("proj"):
                job["proj"] = infer_proj(div)
            if not job.get("ref"):
                job["ref"] = div.get("version_a")
            job.setdefault("diverge_path", str(f))
            job["div"] = div
            continue
        by_key[key] = {
            "pair_id": "%s__%s" % (cve, vb),
            "source": "diverge",
            "cve": cve,
            "ver": str(vb),
            "ref": div.get("version_a"),
            "proj": infer_proj(div),
            "status": None,
            "bin_t": div.get("binary_b"),
            "input": div.get("input_file"),
            "args": div.get("args_b") or div.get("args_a"),
            "args_resolved": None,
            "fork_file": div.get("root_cause_file_b") or div.get("root_cause_file"),
            "fork_line": div.get("root_cause_line_b") or div.get("root_cause_line"),
            "fork_func": div.get("root_cause_function"),
            "diverge_path": str(f),
            "div": div,
        }
    jobs = list(by_key.values())
    if only_status and only_status.upper() not in ("ANY", ""):
        want = only_status.upper()
        if want == "NONE":
            jobs = [j for j in jobs if not j.get("status")]
        else:
            jobs = [j for j in jobs if (j.get("status") or "").upper() == want]
    return jobs


def resolve_pair_binaries(job):
    notes = []
    div = job.get("div") or {}
    prog = program_of(div, job)
    proj = job.get("proj") or infer_proj(div) or infer_proj(job)

    bin_t = job.get("bin_t")
    real_t = None
    if bin_t:
        real_t = resolve_binary(str(bin_t))
        if not (real_t and os.path.isfile(real_t)):
            real_t = None
            notes.append("bin_t path missing: %s" % bin_t)
    if real_t is None:
        ver = job.get("ver")
        vdir = resolve_version_dir(proj, ver) if proj else None
        if vdir:
            real_t = locate_binary(vdir, prog)
            notes.append("bin_t via %s -> %s" % (vdir, real_t))
        else:
            notes.append("no version dir proj=%s ver=%s" % (proj, ver))

    bin_r = None
    raw_r = div.get("binary_a")
    if raw_r:
        cand = resolve_binary(str(raw_r))
        if cand and os.path.isfile(cand):
            bin_r = cand
    if bin_r is None:
        ref = job.get("ref") or div.get("version_a")
        if ref and proj:
            vdir_r = resolve_version_dir(proj, ref)
            if vdir_r:
                bin_r = locate_binary(vdir_r, prog)
                notes.append("bin_r via %s -> %s" % (vdir_r, bin_r))
            else:
                notes.append("no ref dir proj=%s ref=%s" % (proj, ref))
    return {"bin_t": real_t, "bin_r": bin_r, "prog": prog, "proj": proj,
            "notes": notes}


def _stmt_keys(stmt):
    s = re.sub(r"\s+", " ", (stmt or "").strip())
    if not s:
        return []
    return re.findall(
        r"[A-Za-z_][A-Za-z0-9_]*|\d+|==|!=|<=|>=|&&|\|\||"
        r"[+\-*/%<>=!&|^~]", s)


def map_statement_to_target(stmt, target_file_base, target_binary):
    if not stmt or not target_binary:
        return None, None, "no_stmt"
    try:
        from divergence_analyzer import find_source_dirs, find_version_root
        vroot = find_version_root(target_binary)
        source_dirs = list(find_source_dirs(target_binary) or [])
        if vroot and str(vroot) not in source_dirs:
            source_dirs = [str(vroot)] + source_dirs
    except Exception:
        p = Path(target_binary).resolve().parent
        source_dirs = []
        for _ in range(5):
            source_dirs.append(str(p))
            p = p.parent
    base = os.path.basename(target_file_base or "")
    candidates = []
    seen = set()
    for d in source_dirs:
        if not d or not os.path.isdir(d):
            continue
        for sub in (base, os.path.join("src", base), os.path.join("libtiff", base),
                    os.path.join("tools", base), os.path.join("frontend", base),
                    os.path.join("programs", base), os.path.join("sfcommands", base),
                    os.path.join("src", "bin", "jp2", base),
                    os.path.join("src", "lib", base)):
            pth = os.path.join(d, sub)
            if os.path.isfile(pth) and pth not in seen:
                seen.add(pth)
                candidates.append(pth)
        try:
            for path in Path(d).rglob(base):
                if path.is_file() and str(path) not in seen:
                    seen.add(str(path))
                    candidates.append(str(path))
                    if len(candidates) > 8:
                        break
        except OSError:
            pass
    if not candidates:
        return None, None, "file_not_found"
    keys = _stmt_keys(stmt)
    if not keys:
        return candidates[0], None, "file_only"
    best = None
    for path in candidates:
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                lines = fh.readlines()
        except OSError:
            continue
        for i, line in enumerate(lines, 1):
            lkeys = _stmt_keys(line)
            if not lkeys:
                continue
            n = min(len(keys), len(lkeys))
            if n >= 3 and keys[:n] == lkeys[:n]:
                score = n
            elif keys[0] and keys[0] in lkeys:
                score = 1
            else:
                continue
            if best is None or score > best[0]:
                best = (score, path, i)
            if score >= 4 and score >= min(len(keys), 6):
                break
        if best and best[0] >= 4:
            break
    if best:
        return best[1], best[2], "stmt_match"
    return candidates[0], None, "file_only"


def resolve_known_file(job, binaries, known_file, known_stmt):
    f = str(known_file)
    if os.path.isabs(f) and os.path.isfile(f):
        return f
    base = os.path.basename(f)
    try:
        from divergence_analyzer import find_version_root
        vroot = find_version_root(binaries.get("bin_t") or "")
        if vroot:
            cand = os.path.join(str(vroot), f)
            if os.path.isfile(cand):
                return cand
            cand = os.path.join(str(vroot), base)
            if os.path.isfile(cand):
                return cand
    except Exception:
        pass
    if binaries.get("bin_t"):
        p = Path(binaries["bin_t"]).resolve()
        for _ in range(6):
            hits = list(p.rglob(base)) if p.is_dir() else []
            if hits:
                return str(hits[0])
            p = p.parent
    return f


def run_reference_crash(job, bin_r, timeout):
    inp = job.get("input")
    if not inp or not os.path.isfile(inp):
        return None
    args = job.get("args") or []
    if isinstance(args, str):
        args = args.split()
    resolved = []
    for a in args:
        a = str(a)
        if a in ("INPUT", "{input_file}", "{input}"):
            resolved.append(inp)
        else:
            resolved.append(_replace_input_arg(a, inp, inp))
    real = resolve_binary(bin_r)
    if not real or not os.path.isfile(real):
        return None
    env = build_run_env(real)
    env["ASAN_OPTIONS"] = (
        "detect_leaks=0:abort_on_error=0:allocator_may_return_null=1:"
        "halt_on_error=0")
    try:
        proc = subprocess.run(
            [real] + resolved, env=env, capture_output=True,
            text=True, errors="replace", timeout=timeout)
        out = (proc.stdout or "") + "\n" + (proc.stderr or "")
    except Exception:
        return None
    sig = extract_crash_signature(out)
    if sig:
        _attach_crash_statement(sig, real)
    return sig


def decide_probe_site(job, binaries, timeout, probe_mode):
    div = job.get("div") or {}
    known_file = (job.get("fork_file") or div.get("root_cause_file_b")
                  or div.get("root_cause_file"))
    known_line = (job.get("fork_line") or div.get("root_cause_line_b")
                  or div.get("root_cause_line"))
    known_stmt = div.get("root_cause_statement_b") or ""
    known_func = job.get("fork_func") or div.get("root_cause_function")

    site = {"mode": None, "file": None, "line": None, "stmt": known_stmt,
            "func": known_func, "ref_crash": None, "how": None}

    ref_sig = None
    if probe_mode in ("auto", "ref_crash") and binaries.get("bin_r") and job.get("input"):
        ref_sig = run_reference_crash(job, binaries["bin_r"], timeout)
        if ref_sig:
            fr0 = (ref_sig.get("crash_frames") or [{}])[0]
            summ = ref_sig.get("summary") or {}
            site["ref_crash"] = {
                "type": ref_sig.get("type"),
                "file": summ.get("file") or fr0.get("file"),
                "line": summ.get("line") or fr0.get("line"),
                "function": summ.get("function") or fr0.get("function"),
                "statement": fr0.get("statement"),
            }

    if ref_sig and probe_mode in ("auto", "ref_crash"):
        fr = (ref_sig.get("crash_frames") or [{}])[0]
        stmt = fr.get("statement") or ""
        rfile = fr.get("file") or (ref_sig.get("summary") or {}).get("file")
        if stmt and rfile and binaries.get("bin_t"):
            tfile, tline, how = map_statement_to_target(stmt, rfile, binaries["bin_t"])
            if tfile and tline:
                site.update(mode="ref_crash", file=tfile, line=tline,
                            stmt=stmt, how="ref_stmt_mapped")
                return site
            if tfile and known_line and os.path.basename(tfile) == \
                    os.path.basename(str(known_file or "")):
                site.update(mode="ref_crash", file=tfile, line=int(known_line),
                            stmt=stmt, how="ref_file_plus_known_line")
                return site
        elif rfile and known_file and os.path.basename(str(rfile)) == \
                os.path.basename(str(known_file)) and known_line:
            site.update(mode="ref_crash", file=known_file, line=int(known_line),
                        stmt=stmt or known_stmt, how="ref_same_basename_line")
            return site

    if known_file and known_line:
        f = resolve_known_file(job, binaries, known_file, known_stmt)
        site.update(mode="known_site", file=f, line=int(known_line),
                    stmt=known_stmt, how="diverge_or_allver_fork")
        return site

    site.update(mode="none", how="no_probe_site")
    return site


GDB_PROBE_SCRIPT = """
import gdb, json, os
CFG = json.load(open(os.environ["CRASH_REACH_CFG"]))
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
        rec = {"hit": self.n}
        try:
            rec["pc"] = int(gdb.parse_and_eval("$pc"))
        except Exception:
            pass
        print("REACH_HIT " + json.dumps(rec))
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


def _tail(text, n=400):
    lines = [l for l in (text or "").strip().splitlines() if l.strip()]
    if not lines:
        return None
    return "\n".join(lines[-6:])[:n]


def probe_target(job, binaries, site, timeout):
    bin_t = binaries.get("bin_t")
    inp = job.get("input")
    if not bin_t or not os.path.isfile(bin_t):
        return {"status": "error_binary_missing", "reach": None}
    if not inp or not os.path.isfile(inp):
        return {"status": "error_input_missing", "reach": None}
    if not site.get("file") or not site.get("line"):
        return {"status": "error_no_site", "reach": None}
    real = resolve_binary(bin_t)
    if not real or not os.path.isfile(real) or not os.access(real, os.X_OK):
        return {"status": "error_binary_missing", "reach": None}

    f = str(site["file"])
    line = int(site["line"])
    specs = ["%s:%d" % (f, line), "%s:%d" % (os.path.basename(f), line)]
    if site.get("func"):
        specs.append("%s:%d" % (site["func"], line))
    specs = list(dict.fromkeys(specs))

    args = job.get("args_resolved") or job.get("args") or []
    if isinstance(args, str):
        args = args.split()
    run_args = []
    for a in args:
        a = str(a)
        if a in ("INPUT", "{input_file}", "{input}"):
            run_args.append(inp)
        else:
            run_args.append(_replace_input_arg(a, inp, inp))
    if not any(str(a) == inp or (os.path.isabs(str(a)) and
               os.path.abspath(str(a)) == os.path.abspath(inp))
               for a in run_args):
        if not run_args:
            run_args = [inp]

    tmpdir = tempfile.mkdtemp(prefix="crash_reach_")
    cfg_path = os.path.join(tmpdir, "cfg.json")
    script_path = os.path.join(tmpdir, "probe.py")
    with open(cfg_path, "w") as fh:
        json.dump({"specs": specs}, fh)
    with open(script_path, "w") as fh:
        fh.write(GDB_PROBE_SCRIPT)

    env = build_run_env(real)
    env["ASAN_OPTIONS"] = (
        "detect_leaks=0:abort_on_error=0:allocator_may_return_null=1:"
        "halt_on_error=0")
    env["CRASH_REACH_CFG"] = cfg_path

    t0 = time.time()
    try:
        proc = subprocess.run(
            ["gdb", "-batch", "-nx", "-q", "-x", script_path,
             "--args", str(real)] + [str(a) for a in run_args],
            env=env, capture_output=True, text=True, errors="replace",
            timeout=timeout)
        out = (proc.stdout or "") + "\n" + (proc.stderr or "")
        elapsed = time.time() - t0
    except subprocess.TimeoutExpired:
        return {"status": "error_timeout", "reach": None,
                "elapsed": round(time.time() - t0, 2)}
    except Exception as e:
        return {"status": "error_gdb", "reach": None, "error": str(e)[:200]}

    if ("not in executable format" in out or "Cannot exec" in out) and \
            "REACH_HIT" not in out:
        return {"status": "error_gdb", "reach": None,
                "error": _tail(out) or "exec failed"}

    hits = len(re.findall(r"REACH_HIT \{", out))
    bp_unresolved = "REACH_BP_UNRESOLVED" in out

    sig = extract_crash_signature(out)
    if sig:
        _attach_crash_statement(sig, real)
    crash = None
    if sig:
        fr = (sig.get("crash_frames") or [{}])[0]
        crash = {"type": sig.get("type"), "function": fr.get("function"),
                 "file": _path_basename(fr.get("file")), "line": fr.get("line")}

    exited = None
    m = re.search(r"Program exited(?: normally)? with code (\d+)", out)
    if m:
        exited = int(m.group(1))
    elif re.search(r"Program exited normally", out):
        exited = 0
    signaled = None
    m = re.search(r"Program terminated with signal (\w+)", out)
    if m:
        signaled = m.group(1)

    reached = hits > 0
    if reached:
        cls = "A_reached_then_crash" if sig else "A_reached_no_crash"
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
        "status": "ok",
        "reach": reached,
        "hit_count": hits,
        "bp_unresolved": bp_unresolved,
        "classification": cls,
        "crash": crash,
        "exit_code": exited,
        "signal": signaled,
        "specs": specs,
        "elapsed": round(elapsed, 2),
        "error_excerpt": None if (reached or sig or exited is not None)
        else _tail(out),
    }


def enrich_status(job):
    if job.get("status"):
        return
    cve = job.get("cve") or ""
    if cve in SUCCESS_CVES:
        job["status"] = "SUCCESS"
        job["status_source"] = "poc_run_commands"


def _write(path, rec):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    with open(tmp, "w") as fh:
        json.dump(rec, fh, indent=1, default=str)
    os.replace(tmp, path)


def audit_one(job, timeout, probe_mode, force=False, verbose=False):
    pair_id = job["pair_id"]
    out_path = PAIR_DIR / (re.sub(r"[^\w.\-]+", "_", pair_id) + ".json")
    if out_path.is_file() and not force:
        try:
            return json.load(open(out_path))
        except Exception:
            pass

    rec = {
        "pair_id": pair_id,
        "cve": job.get("cve"),
        "ver": job.get("ver"),
        "ref": job.get("ref"),
        "proj": job.get("proj"),
        "match_status": job.get("status"),
        "source": job.get("source"),
        "input": job.get("input"),
        "fork_file": job.get("fork_file"),
        "fork_line": job.get("fork_line"),
        "fork_func": job.get("fork_func"),
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }
    t0 = time.time()
    try:
        enrich_status(job)
        rec["match_status"] = job.get("status")

        inp = job.get("input")
        if not inp or not os.path.isfile(inp):
            rec.update(probe_status="skipped", classification="skipped",
                       skip_reason="input_missing", input=inp)
            _write(out_path, rec)
            return rec

        binaries = resolve_pair_binaries(job)
        rec["bin_t"] = binaries.get("bin_t")
        rec["bin_r"] = binaries.get("bin_r")
        rec["resolve_notes"] = binaries.get("notes")
        rec["proj"] = binaries.get("proj") or rec.get("proj")
        if not binaries.get("bin_t"):
            rec.update(probe_status="skipped", classification="skipped",
                       skip_reason="binary_missing")
            _write(out_path, rec)
            return rec

        site = decide_probe_site(job, binaries, timeout, probe_mode)
        rec["probe_mode"] = site.get("mode")
        rec["probe_how"] = site.get("how")
        rec["probe_file"] = site.get("file")
        rec["probe_line"] = site.get("line")
        rec["probe_stmt"] = (site.get("stmt") or "")[:200]
        rec["ref_crash"] = site.get("ref_crash")

        if site.get("mode") == "none" or not site.get("line"):
            rec.update(probe_status="skipped", classification="skipped",
                       skip_reason="no_probe_site")
            _write(out_path, rec)
            return rec

        result = probe_target(job, binaries, site, timeout)
        rec["probe_status"] = result.get("status")
        if result.get("classification"):
            rec["classification"] = result["classification"]
        elif str(result.get("status", "")).startswith("error"):
            rec["classification"] = "skipped"
            rec["skip_reason"] = result.get("status")
            rec["error"] = result.get("error") or result.get("error_excerpt")
        else:
            rec["classification"] = "unknown"
        if result.get("status") != "ok" and "skip_reason" not in rec:
            rec["skip_reason"] = result.get("status")
            rec["error"] = result.get("error") or result.get("error_excerpt")
        rec["reach"] = result.get("reach")
        rec["hit_count"] = result.get("hit_count")
        rec["target_crash"] = result.get("crash")
        rec["exit_code"] = result.get("exit_code")
        rec["signal"] = result.get("signal")
        rec["probe_elapsed"] = result.get("elapsed")
        rec["bp_unresolved"] = result.get("bp_unresolved")
        if verbose:
            print("[%s] %s  reach=%s  mode=%s" % (
                pair_id, rec.get("classification"), rec.get("reach"),
                rec.get("probe_mode")), flush=True)
    except Exception as e:
        rec.update(probe_status="error", classification="error",
                   skip_reason="exception", error=str(e)[:300],
                   traceback=traceback.format_exc()[-800:])
    rec["wall_seconds"] = round(time.time() - t0, 2)
    _write(out_path, rec)
    return rec


def _count_by(records, key):
    out = {}
    for r in records:
        k = r.get(key)
        k = "?" if k is None or k == "" else str(k)
        out[k] = out.get(k, 0) + 1
    return dict(sorted(out.items()))


def write_summary(records):
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    cross = {}
    cls_counts = {}
    reach_counts = {"reached": 0, "not_reached": 0, "unknown": 0}
    for r in records:
        cls = r.get("classification") or "unknown"
        cls_counts[cls] = cls_counts.get(cls, 0) + 1
        st = r.get("match_status") or "?"
        cross.setdefault(cls, {})
        cross[cls][st] = cross[cls].get(st, 0) + 1
        if r.get("reach") is True:
            reach_counts["reached"] += 1
        elif r.get("reach") is False:
            reach_counts["not_reached"] += 1
        else:
            reach_counts["unknown"] += 1

    collapsed = {
        "A_reached": sum(v for k, v in cls_counts.items() if k.startswith("A_reached")),
        "B_not_reached": sum(v for k, v in cls_counts.items() if k.startswith("B_not")),
        "C_not_reached_early_crash": cls_counts.get("C_not_reached_crash", 0),
        "skipped_or_error": sum(
            v for k, v in cls_counts.items()
            if k in ("skipped", "unknown", "error") or k.startswith("error")),
    }
    summary = {
        "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "total": len(records),
        "reach_counts": reach_counts,
        "classification_counts": dict(sorted(cls_counts.items())),
        "collapsed": collapsed,
        "cross_classification_x_match": cross,
        "probe_mode_counts": _count_by(records, "probe_mode"),
        "match_status_counts": _count_by(records, "match_status"),
        "by_source": _count_by(records, "source"),
        "by_proj": _count_by(records, "proj"),
    }
    with open(OUT_DIR / "_summary.json", "w") as fh:
        json.dump(summary, fh, indent=2, default=str)

    fields = [
        "pair_id", "cve", "ver", "ref", "proj", "match_status", "source",
        "classification", "reach", "probe_mode", "probe_how",
        "probe_file", "probe_line", "hit_count",
        "target_crash_type", "target_crash_func", "target_crash_line",
        "exit_code", "signal", "probe_status", "skip_reason",
        "bin_t", "bin_r", "input", "wall_seconds", "error",
    ]
    with open(OUT_DIR / "_summary.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for r in sorted(records, key=lambda x: (x.get("cve") or "",
                                                str(x.get("ver") or ""))):
            row = dict(r)
            tc = r.get("target_crash") or {}
            row["target_crash_type"] = tc.get("type")
            row["target_crash_func"] = tc.get("function")
            row["target_crash_line"] = tc.get("line")
            w.writerow(row)
    with open(OUT_DIR / "_records.json", "w") as fh:
        json.dump(records, fh, indent=1, default=str)
    return summary


def print_summary(summary):
    print("\n=== crash-line reachability audit ===")
    print("total jobs          : %d" % summary["total"])
    print("reach               : %s" % summary["reach_counts"])
    print("collapsed           : %s" % summary["collapsed"])
    print("\nby classification:")
    for k, v in summary["classification_counts"].items():
        print("  %-28s %d" % (k, v))
    print("\nclassification x match_status:")
    for cls, row in sorted(summary["cross_classification_x_match"].items()):
        parts = ", ".join("%s=%d" % (k, v) for k, v in sorted(row.items()))
        print("  %-28s %s" % (cls, parts))
    print("\nprobe_mode  : %s" % summary["probe_mode_counts"])
    print("match_status: %s" % summary["match_status_counts"])
    print("source      : %s" % summary["by_source"])
    print("\noutputs:")
    for p in (OUT_DIR / "_summary.json", OUT_DIR / "_summary.csv",
              OUT_DIR / "_records.json"):
        print("  %s" % p)


def main():
    ap = argparse.ArgumentParser(
        description="Batch-audit original-PoC reachability of the "
                    "reference crash line on target versions.")
    ap.add_argument("--status", default=None,
                    help="MATCH | NO_MATCH | BASELINE_TRIGGERS | SUCCESS | NONE | ANY")
    ap.add_argument("--cve", action="append", default=[],
                    help="only these CVEs (repeatable)")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("-j", "--workers", type=int, default=4)
    ap.add_argument("--timeout", type=int, default=60,
                    help="per-probe timeout seconds (default 60)")
    ap.add_argument("--probe", choices=["auto", "ref_crash", "known_site"],
                    default="auto",
                    help="auto: ref map then known site; known_site: skip ref run")
    ap.add_argument("--force", action="store_true",
                    help="re-probe even if cached pair JSON exists")
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("--dry-run", action="store_true",
                    help="list jobs only, do not probe")
    a = ap.parse_args()

    jobs = load_pairs(a.status)
    if a.cve:
        want = {c.upper() for c in a.cve}
        jobs = [j for j in jobs if (j.get("cve") or "").upper() in want]
    jobs.sort(key=lambda j: (j.get("cve") or "", str(j.get("ver") or "")))
    if a.limit and len(jobs) > a.limit:
        jobs = jobs[: a.limit]

    print("[*] audit jobs: %d  (status=%s probe=%s workers=%d timeout=%d)" % (
        len(jobs), a.status or "ALL", a.probe, a.workers, a.timeout))
    if a.dry_run:
        for j in jobs:
            print("  %s  status=%s  bin_t=%s  fork=%s:%s  input=%s" % (
                j["pair_id"], j.get("status"), j.get("bin_t"),
                j.get("fork_file"), j.get("fork_line"), j.get("input")))
        return 0

    PAIR_DIR.mkdir(parents=True, exist_ok=True)
    records = []
    t0 = time.time()
    with ThreadPoolExecutor(max_workers=max(1, a.workers)) as ex:
        futs = {
            ex.submit(audit_one, j, a.timeout, a.probe, a.force, a.verbose): j
            for j in jobs
        }
        done = 0
        for fut in as_completed(futs):
            job = futs[fut]
            done += 1
            try:
                rec = fut.result()
            except Exception as e:
                rec = {"pair_id": job.get("pair_id"),
                       "cve": job.get("cve"), "ver": job.get("ver"),
                       "classification": "error", "error": str(e)[:200]}
            records.append(rec)
            if done % 10 == 0 or done == len(jobs):
                print("  [%d/%d] %.0fs  last=%s" % (
                    done, len(jobs), time.time() - t0,
                    rec.get("pair_id")), flush=True)

    summary = write_summary(records)
    print_summary(summary)
    return 0


if __name__ == "__main__":
    sys.exit(main())
