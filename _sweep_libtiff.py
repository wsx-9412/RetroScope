#!/usr/bin/env python3
"""Driver: run libtiff CVEs through run_analysis.sh and log results."""
import subprocess, os, sys, re

BASE = str(__import__("pathlib").Path(__file__).resolve().parent)
LOG = os.path.join(BASE, "results/version_sweep/sweep_20261028.md")

# (cve, input_rel, ref_ver, tgt_ver, tool, command_format)
CVES = [
    ("CVE-2025-8176", "in/libtiff/CVE-2025-8176.tif", "tiff-4.7.0", "tiff-4.5.1",
     "tiffmedian", "{program_path} -C 256 -c lzw:2 -f {input_file} {output_file}"),
    ("CVE-2025-8177", "in/libtiff/CVE-2025-8177.tif", "tiff-4.7.0", "tiff-4.5.1",
     "thumbnail", "{program_path} {input_file} {output_file}"),
    ("CVE-2016-10268", "in/libtiff/CVE-2016-10268.tif", "tiff-4.0.7", "tiff-4.0.6",
     "tiffcp", "{program_path} -i {input_file} {output_file}"),
    ("CVE-2016-10269", "in/libtiff/asarubbo/00071-libtiff-heapoverflow-_TIFFmemcpy", "tiff-4.0.7", "tiff-4.0.6",
     "tiffcp", "{program_path} -i {input_file} {output_file}"),
    ("CVE-2016-10270", "in/libtiff/asarubbo/00074-libtiff-heapoverflow-TIFFFillStrip", "tiff-4.0.7", "tiff-3.9.6",
     "tiffcp", "{program_path} -i {input_file} {output_file}"),
    ("CVE-2017-7596", "in/libtiff/asarubbo/00113-libtiff-outside-float", "tiff-4.0.7", "tiff-3.9.6",
     "tiffcp", "{program_path} -i {input_file} {output_file}"),
    ("CVE-2017-7597", "in/libtiff/asarubbo/00114-libtiff-outside-float-tif_dirread", "tiff-4.0.7", "tiff-4.0.6",
     "tiffcp", "{program_path} -i {input_file} {output_file}"),
    ("CVE-2017-7598", "in/libtiff/asarubbo/00115-libtiff-fpe-tif_dirread", "tiff-4.0.7", "tiff-3.9.6",
     "tiffcp", "{program_path} -i {input_file} {output_file}"),
    ("CVE-2017-7599", "in/libtiff/asarubbo/00117-libtiff-outside-short-tif_dirwrite", "tiff-4.0.7", "tiff-3.9.6",
     "tiffcp", "{program_path} -i {input_file} {output_file}"),
    ("CVE-2017-7601", "in/libtiff/asarubbo/00119-libtiff-shift-long-tif_jpeg", "tiff-4.0.7", "tiff-3.9.6",
     "tiffcp", "{program_path} -i {input_file} {output_file}"),
    ("CVE-2017-7602", "in/libtiff/asarubbo/00121-libtiff-signintoverflow-tif_read", "tiff-4.0.7", "tiff-3.9.6",
     "tiffcp", "{program_path} -i {input_file} {output_file}"),
]

def make_config(cve, inp, tool, cmd):
    return f'''# config_libtiff.py
CVE_ID = "{cve}"
INPUT_FILE = "{inp}"
OUTPUT_FILE = "/tmp/foo"
COMMAND_FORMAT = "{cmd}"

COMPILE_COMMANDS = {{
    "reference": {{
        "pre_build": [
            "make clean",
            "sh ./configure CFLAGS='-finstrument-functions -g -O0 -fsanitize=address -fno-omit-frame-pointer' LDFLAGS='-fsanitize=address -ldl'",
            "make -j4 CFLAGS='-finstrument-functions -g -O0 -fsanitize=address -fno-omit-frame-pointer' LDFLAGS='-fsanitize=address -ldl'",
            "make -C tools -j4 thumbnail CFLAGS='-finstrument-functions -g -O0 -fsanitize=address -fno-omit-frame-pointer' LDFLAGS='-fsanitize=address -ldl'",
        ],
        "compile_flags": {{
            "CFLAGS": "-finstrument-functions -g  -ldl -fsanitize=address -fno-omit-frame-pointer",
            "CXXFLAGS": "-g -fno-omit-frame-pointer -finstrument-functions -Wno-error -fpermissive -rdynamic",
            "LDFLAGS": "-ldl -fsanitize=address"
        }}
    }},
    "target": {{
        "pre_build": [
            "make clean",
            "sh ./configure CFLAGS='-finstrument-functions -g -O0 -fsanitize=address -fno-omit-frame-pointer' LDFLAGS='-fsanitize=address -ldl'",
            "make -j4 CFLAGS='-finstrument-functions -g -O0 -fsanitize=address -fno-omit-frame-pointer' LDFLAGS='-fsanitize=address -ldl'",
            "make -C tools -j4 thumbnail CFLAGS='-finstrument-functions -g -O0 -fsanitize=address -fno-omit-frame-pointer' LDFLAGS='-fsanitize=address -ldl'",
        ],
        "compile_flags": {{
            "CFLAGS": "-finstrument-functions -g  -ldl -fsanitize=address -fno-omit-frame-pointer",
            "CXXFLAGS": "-g -fno-omit-frame-pointer -finstrument-functions -Wno-error -fpermissive -rdynamic",
            "LDFLAGS": "-ldl -fsanitize=address"
        }}
    }}
}}

EXECUTION_CONFIG = {{
    "program_name": "{tool}",
    "timeout": 120,
    "exec_subdir": "/tools",
    "command_format": COMMAND_FORMAT,
    "build_dir_pattern": "/tools/"
}}

ANALYSIS_CONFIG = {{
    "max_test_bytes": 64,
    "crash_detection_keywords": [
        "division by zero", "heap-buffer-overflow", "stack-buffer-overflow",
        "SEGV", "use-after-free", "libtiff", "buffer overflow", "tiff",
        "Assertion failure", "AddressSanitizer", "ERROR", "Aborted"
    ],
    "separate_build_and_run": True
}}
'''

def parse(out):
    if "mutation reproduced the reference crash" in out:
        return "SUCCESS", "dynamic mutation reproduced ref crash"
    m = re.findall(r'(\d+) matching value\(s\) \(target reproduces ref crash\)', out)
    if m and int(m[-1]) > 0:
        return "SUCCESS", f"{m[-1]} matching value(s)"
    mm = re.findall(r'MATCHES ref crash \(same_func: same crash function ([^)]+)\)', out)
    if mm:
        return "SUCCESS", "same_func: " + mm[0]
    if "No matches" in out or "NO_CRASH_MATCH" in out:
        return "FAIL", "no mutation reproduced ref crash"
    if "fork_not_reached" in out:
        return "FAIL", "fork_not_reached"
    if "GDB trace failed" in out:
        return "FAIL", "GDB trace failed"
    if "traces are identical" in out or "No gaps found" in out:
        return "FAIL", "traces identical / no gaps"
    ref = re.search(r'Reference crash: ([^\n]+)', out)
    return "FAIL", ("ref crash: " + ref.group(1).strip()[:60]) if ref else "unknown"

results = []
for cve, inp, refv, tgtv, tool, cmd in CVES:
    cfg = make_config(cve, inp, tool, cmd)
    with open(os.path.join(BASE, "config_libtiff.py"), "w") as f:
        f.write(cfg)
    env = os.environ.copy()
    env["RETRO_REF"] = f"{BASE}/tiff-versions/{refv}"
    env["RETRO_TGT"] = f"{BASE}/tiff-versions/{tgtv}"
    print(f"=== {cve} ref={refv} tgt={tgtv} tool={tool} ===", flush=True)
    try:
        r = subprocess.run(["./run_analysis.sh", "config_libtiff.py"],
                           cwd=BASE, env=env, capture_output=True, text=True,
                           timeout=1800)
        out = r.stdout + r.stderr
        status, detail = parse(out)
    except subprocess.TimeoutExpired:
        status, detail = "FAIL", "timeout(1800s)"
    results.append((cve, refv, tgtv, tool, status, detail))
    line = f"| libtiff | {cve} | {refv} | {tgtv} | {status} | {detail} |"
    with open(LOG, "a") as f:
        f.write(line + "\n")
    print(line, flush=True)

print("\n==== DONE ====", flush=True)
for r in results:
    print(" | ".join(r), flush=True)
