#!/usr/bin/env python3
"""Driver: run non-libtiff CVEs (jasper/openexr/exiv2/pcre2/libredwg/...)
through run_analysis.sh and append results to sweep_20261028.md."""
import subprocess, os, sys, re, time

BASE = str(__import__("pathlib").Path(__file__).resolve().parent)
LOG = os.path.join(BASE, "results/version_sweep/sweep_20261028.md")

# (project, cve, ref_path, tgt_path, config, ref_label, tgt_label, input_file,
#  cmd_fmt, prog_name)  -- prog_name "" => keep config's, None => skip (record only)
JOBS = [
    ("jasper", "CVE-2017-5505",
     f"{BASE}/jasper-versions/jasper-version-1.900.27",
     f"{BASE}/jasper-versions/jasper-version-1.900.24",
     "config_jasper.py", "1.900.27", "1.900.24",
     "in/jasper/asarubbo/00053-jasper-invalidread-jas_matrix_asl",
     "{program_path} -f {input_file}", ""),
    ("jasper", "CVE-2017-6851",
     f"{BASE}/jasper-versions/jasper-version-2.0.10",
     f"{BASE}/jasper-versions/jasper-version-1.900.24",
     "config_jasper.py", "2.0.10", "1.900.24",
     "in/jasper/asarubbo/00125-jasper-invalidread-jas_matrix_bindsub",
     "{program_path} -f {input_file}", ""),
    ("openexr", "CVE-2025-48071",
     str(BASE / "openexr-versions/openexr-3.3.2"),
     str(BASE / "openexr-versions/openexr-3.2.12"),
     "config_openexr.py", "3.3.2", "3.2.12",
     "in/openexr/CVE-2025-48071-heap_overflow.exr",
     "{program_path} {input_file}", ""),
    ("exiv2", "CVE-2025-26623",
     str(BASE / "exiv2-versions/exiv2-0.28.4"),
     str(BASE / "exiv2-versions/exiv2-0.27.7"),
     "config_exiv2.py", "0.28.4", "0.27.7",
     "in/exiv2/CVE-2025-26623-poc.tiff",
     "{program_path} -q fi {input_file}", ""),
    ("pcre2", "CVE-2026-86145",
     str(BASE / "pcre2-versions/pcre2-pcre2-10.34"),
     str(BASE / "pcre2-versions/pcre2-pcre2-10.30"),
     "config_pcre2.py", "10.34", "10.30",
     "in/pcre2/CVE-2026-86145.txt",
     "{program_path} {input_file}", ""),
    ("libsndfile", "CVE-2017-7741",
     str(BASE / "libsndfile-versions/libsndfile-1.0.26"),
     str(BASE / "libsndfile-versions/libsndfile-1.0.25"),
     "config_libsndfile.py", "1.0.26", "1.0.25",
     "in/libsndfile/CVE-2017-7741",
     "{program_path} {input_file}", "sndfile-info"),
    ("libsndfile", "CVE-2017-12562",
     str(BASE / "libsndfile-versions/libsndfile-1.0.28"),
     str(BASE / "libsndfile-versions/libsndfile-1.0.25"),
     "config_libsndfile.py", "1.0.28", "1.0.25",
     "in/libsndfile/CVE-2017-12562.c", "", None),
    ("libsndfile", "CVE-2018-19661",
     str(BASE / "libsndfile-versions/libsndfile-1.0.26"),
     str(BASE / "libsndfile-versions/libsndfile-1.0.25"),
     "config_libsndfile.py", "1.0.26", "1.0.25",
     "in/libsndfile/CVE-2018-19661",
     "{program_path} -ulaw {input_file} {output_file}", "sndfile-convert"),
    ("libsndfile", "CVE-2024-50612",
     str(BASE / "libsndfile-versions/libsndfile-1.0.27"),
     str(BASE / "libsndfile-versions/libsndfile-1.0.26"),
     "config_libsndfile.py", "1.0.27", "1.0.26",
     "in/libsndfile/CVE-2024-50612",
     "{program_path} -vorbis {input_file} {output_file}", "sndfile-convert"),
    ("libredwg", "CVE-2022-33034",
     str(BASE / "libredwg-versions/libredwg-0.12.5"),
     str(BASE / "libredwg-versions/libredwg-0.12.4"),
     "config_libredwg.py", "0.12.5", "0.12.4",
     "in/libredwg/CVE-2022-33034-copy_bytes_sof",
     "{program_path} -b -m -y -o /dev/null {input_file}", "dwg2dxf"),
    ("libredwg", "CVE-2026-9500",
     str(BASE / "libredwg-versions/libredwg-6d6a339"),
     str(BASE / "libredwg-versions/libredwg-0.13.4"),
     "config_libredwg.py", "6d6a339", "0.13.4",
     "in/libredwg/CVE-2026-9500.dwg",
     "{program_path} {input_file}", "dwgread"),
    ("libredwg", "CVE-2026-9502",
     str(BASE / "libredwg-versions/libredwg-0.13.4"),
     str(BASE / "libredwg-versions/libredwg-0.13.3"),
     "config_libredwg.py", "0.13.4", "0.13.3",
     "in/libredwg/CVE-2026-9502.dwg",
     "{program_path} {input_file}", "dwgread"),
    ("libredwg", "CVE-2026-9503",
     str(BASE / "libredwg-versions/libredwg-0.13.4"),
     str(BASE / "libredwg-versions/libredwg-0.12.5"),
     "config_libredwg.py", "0.13.4", "0.12.5",
     "in/libredwg/CVE-2026-9503.dwg",
     "{program_path} {input_file}", "dwg2SVG"),
    ("libredwg", "CVE-2026-9504",
     str(BASE / "libredwg-versions/libredwg-6d6a339"),
     str(BASE / "libredwg-versions/libredwg-0.13.3"),
     "config_libredwg.py", "6d6a339", "0.13.3",
     "in/libredwg/CVE-2026-9504.dwg",
     "{program_path} .* {input_file}", "dwggrep"),
    ("libredwg", "CVE-2026-9605",
     str(BASE / "libredwg-versions/libredwg-0.13.4"),
     str(BASE / "libredwg-versions/libredwg-0.13.3"),
     "config_libredwg.py", "0.13.4", "0.13.3",
     "in/libredwg/CVE-2026-9605.dwg",
     "{program_path} {input_file}", "dwgbmp"),
    ("libredwg", "CVE-2026-15184",
     str(BASE / "libredwg-versions/libredwg-0.13.4"),
     str(BASE / "libredwg-versions/libredwg-0.12.5"),
     "config_libredwg.py", "0.13.4", "0.12.5",
     "in/libredwg/CVE-2026-15184.dwg",
     "{program_path} .* {input_file}", "dwggrep"),
    ("libredwg", "CVE-2026-15520",
     str(BASE / "libredwg-versions/libredwg-0.13.4"),
     str(BASE / "libredwg-versions/libredwg-0.13.3"),
     "config_libredwg.py", "0.13.4", "0.13.3",
     "in/libredwg/CVE-2026-15520.dwg",
     "{program_path} --binary {input_file}", "dwg2dxf"),
]

def patch_config(cfg_path, cve, input_file, cmd_fmt, prog_name=""):
    """Rewrite only the CVE section at the top of the config file."""
    p = os.path.join(BASE, cfg_path)
    with open(p) as f:
        text = f.read()
    text = re.sub(r'^CVE_ID\s*=\s*".*?"', f'CVE_ID = "{cve}"', text, count=1, flags=re.M)
    text = re.sub(r'^INPUT_FILE\s*=\s*".*?"', f'INPUT_FILE = "{input_file}"', text, count=1, flags=re.M)
    text = re.sub(r'^COMMAND_FORMAT\s*=\s*".*"',
                  'COMMAND_FORMAT = "' + cmd_fmt.replace('\\', '\\\\').replace('"', '\\"') + '"',
                  text, count=1, flags=re.M)
    if prog_name:
        text = re.sub(r'"program_name"\s*:\s*".*?"',
                      f'"program_name": "{prog_name}"', text, count=1)
    with open(p, "w") as f:
        f.write(text)

def classify(text):
    m = re.search(r"=>\s*(\d+)\s+matching combo", text)
    if m and int(m.group(1)) > 0:
        mm = re.search(r"=>\s*\d+\s+matching combo\(s\).*", text)
        return "SUCCESS", (mm.group(0) if mm else "matching combos > 0")
    if "fork_not_reached" in text or "fork not reached" in text:
        return "FAIL", "fork_not_reached"
    if "Traceback" in text and "Error" in text:
        return "FAIL", "pipeline error (see log)"
    if "Fork-point analysis failed" in text or "GDB trace failed" in text:
        # compile or earlier failure
        if "pre_build FAILED" in text or "configure failed" in text or "make failed" in text:
            return "COMPILE_FAIL", "编译失败"
        return "FAIL", "fork-point/GDB 失败"
    if re.search(r"no k-offset combination reproduced", text) or \
       re.search(r"0 matching", text) or "NO_CRASH_MATCH" in text:
        return "FAIL", "0 matching / NO_CRASH_MATCH"
    if "Analysis completed" in text:
        return "FAIL", "完成但未复现 (see log)"
    return "FAIL", "see log"

def append_row(row):
    with open(LOG, "a") as f:
        f.write(row + "\n")

def main():
    only = sys.argv[1:] if len(sys.argv) > 1 else None
    for proj, cve, ref, tgt, cfg, refl, tgtl, inp, cmd, prog in JOBS:
        if only and cve not in only and proj not in only:
            continue
        print(f"\n########## {proj} {cve}: {refl} -> {tgtl} ##########", flush=True)
        if prog is None:
            row = f"| {proj} | {cve} | {refl} | {tgtl} | SKIP | C harness / no mutable input |"
            print(row, flush=True)
            append_row(row)
            continue
        patch_config(cfg, cve, inp, cmd, prog)
        env = os.environ.copy()
        env["RETRO_REF"] = ref
        env["RETRO_TGT"] = tgt
        env["ASAN_OPTIONS"] = "detect_leaks=0:allocator_may_return_null=1"
        t0 = time.time()
        try:
            r = subprocess.run(
                ["./run_analysis.sh", cfg],
                cwd=BASE, env=env, capture_output=True, text=True,
                errors="replace", timeout=5400)
            out = (r.stdout or "") + "\n" + (r.stderr or "")
        except subprocess.TimeoutExpired as e:
            out = ((e.stdout or b"").decode("utf-8", "replace") if isinstance(e.stdout, bytes) else (e.stdout or ""))
            out += "\n[DRIVER TIMEOUT 5400s]\n"
        dt = time.time() - t0
        # keep a per-CVE log
        logdir = os.path.join(BASE, "results/version_sweep", cve)
        os.makedirs(logdir, exist_ok=True)
        with open(os.path.join(logdir, f"{tgtl}.driver.log"), "w") as f:
            f.write(out)
        status, why = classify(out)
        why = why.replace("|", "/")
        row = f"| {proj} | {cve} | {refl} | {tgtl} | {status} | {why} ({dt:.0f}s) |"
        print(row, flush=True)
        append_row(row)
    print("\n[DRIVER DONE]", flush=True)

if __name__ == "__main__":
    main()
