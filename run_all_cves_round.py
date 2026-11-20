#!/usr/bin/env python3
"""Run one round of every CVE listed in poc_run_commands.md.

For each CVE the driver generates a per-run config (so concurrent runs never
share a config), copies the PoC into an isolated input directory (the
pipeline writes fork_trace_result.json next to the input), and invokes
./run_analysis.sh with RETRO_REF / RETRO_TGT overrides.

Output layout (one round):

  results/<CVE>/<target-version>.log   terminal output of that run (only logs)
  out/<input>-<target-version><tag>/   mutation artifacts, tag defaults to -r1
  .retro_work/...                      configs, isolated inputs, intermediate
                                       JSONs, per-run status (never results/)

Usage:
  python3 run_all_cves_round.py --round-tag r1 --workers 2
  python3 run_all_cves_round.py --only CVE-2022-28506 --dry-run
  python3 run_all_cves_round.py --clear-results --round-tag r1
"""

import argparse
import concurrent.futures
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

BASE = Path(__file__).resolve().parent
WORK = BASE / ".retro_work"
RESULTS = BASE / "results"

# ---------------------------------------------------------------------------
# Specs: (cve, project, ref version dir, target version dir, target label,
#         input path, tool, args template, output file, optional extras)
# The ref/target dirs are relative to BASE for in-repo trees.
# ---------------------------------------------------------------------------
S = dict


def spec(cve, project, ref, tgt, label, inp, tool, args,
         output="/tmp/foo", harness=None, blocked=None):
    return S(cve=cve, project=project, ref=ref, tgt=tgt, label=label,
             input=inp, tool=tool, args=args, output=output,
             harness=harness, blocked=blocked)


SPECS = [
    # ---------------- binutils ----------------
    spec("CVE-2019-9074", "binutils", "binutils-versions/binutils-2.26",
         "binutils-versions/binutils-2.25", "2.25", "in/CVE-2019-9074",
         "objdump", ["-x", "{input_file}"]),
    spec("CVE-2022-44840", "binutils", "binutils-versions/binutils-2.38",
         "binutils-versions/binutils-2.36", "2.36", "in/CVE-2022-44840",
         "readelf", ["-w", "{input_file}"]),
    spec("CVE-2023-1972", "binutils", "binutils-versions/binutils-2.40",
         "binutils-versions/binutils-2.38", "2.38", "in/CVE-2023-1972",
         "objdump", ["-x", "{input_file}"]),
    spec("CVE-2017-9750", "binutils", "binutils-versions/binutils-2.28",
         "binutils-versions/binutils-2.25", "2.25", "in/CVE-2017-9750",
         "objdump", ["-D", "{input_file}"]),
    spec("CVE-2017-14939", "binutils", "binutils-versions/binutils-2.29",
         "binutils-versions/binutils-2.26", "2.26", "in/CVE-2017-14939",
         "nm-new", ["-A", "-a", "-l", "-S", "-s", "--special-syms",
                    "--synthetic", "--with-symbol-versions", "-D",
                    "{input_file}"]),
    # ---------------- libxml2 ----------------
    spec("CVE-2024-34459", "libxml2", "libxml2-versions/libxml2-2.9.5",
         "libxml2-versions/libxml2-2.9.4", "2.9.4", "in/CVE-2024-34459",
         "xmllint", ["--htmlout", "{input_file}"]),
    # ---------------- giflib ----------------
    spec("CVE-2022-28506", "giflib", "giflib-versions/giflib-5.1.1",
         "giflib-versions/giflib-4.1.6", "4.1.6", "in/CVE-2022-28506",
         "gif2rgb", ["{input_file}"]),
    # ---------------- freetype ----------------
    spec("CVE-2026-23865", "freetype", "freetype-versions/freetype-2.13.1",
         "freetype-versions/freetype-2.13.0", "2.13.0",
         "in/CVE-2026-23865", "fttest", ["{input_file}"],
         harness="build/test_var.c"),
    spec("CVE-2026-50811", "freetype", "freetype-versions/freetype-2.14.0",
         "freetype-versions/freetype-2.13.3", "2.13.3",
         "in/CVE-2026-50811", "fttest", ["{input_file}", "64"],
         harness="build/ft_get_design_dump.c"),
    # ---------------- openjpeg ----------------
    spec("CVE-2016-9572", "openjpeg", "openjpeg-versions/version.2.0.1",
         "openjpeg-versions/version.2.0", "2.0",
         "in/openjpeg/CVE-2016-9572/PoC2", "opj_decompress",
         ["-i", "{input_file}", "-o", "/tmp/out.ppm"]),
    spec("issue908", "openjpeg", "openjpeg-versions/version.2.0.1",
         "openjpeg-versions/version.2.0", "2.0",
         "in/openjpeg/issue908_poc.jp2", "opj_decompress",
         ["-i", "{input_file}", "-o", "/tmp/out.pgm"]),
    spec("CVE-2018-18088", "openjpeg", "openjpeg-versions/v2.3.0",
         "openjpeg-versions/version.2.2.0", "2.2.0",
         "in/openjpeg/CVE-2018-18088/291554_FlipDeter", "opj_decompress",
         ["-i", "{input_file}", "-o", "/tmp/out.ppm"]),
    spec("CVE-2021-3575", "openjpeg", "openjpeg-versions/v2.3.1",
         "openjpeg-versions/v2.3.0", "2.3.0",
         "in/openjpeg/CVE-2021-3575.j2k", "opj_decompress",
         ["-i", "{input_file}", "-o", "/tmp/out.pgm"]),
    spec("issue1620", "openjpeg", "openjpeg-versions/v2.5.3",
         "openjpeg-versions/v2.5.2", "2.5.2",
         "in/openjpeg/issue1620_poc.jp2", "opj_decompress",
         ["-i", "{input_file}", "-o", "/tmp/out.pgm"]),
    spec("CVE-2017-14151", "openjpeg", "openjpeg-versions/version.2.2.0",
         "openjpeg-versions/version.2.1", "2.1",
         "in/openjpeg/CVE-2017-14151.bmp", "opj_compress",
         ["-n", "1", "-i", "{input_file}", "-o", "/tmp/null.j2c"]),
    spec("CVE-2017-14152", "openjpeg", "openjpeg-versions/version.2.2.0",
         "openjpeg-versions/version.2.1", "2.1",
         "in/openjpeg/CVE-2017-14152.tga", "opj_compress",
         ["-I", "-cinema4K", "-n", "1", "-i", "{input_file}",
          "-o", "/tmp/null.jp2"]),
    spec("CVE-2017-14164", "openjpeg", "openjpeg-versions/version.2.2.0",
         "openjpeg-versions/version.2.1", "2.1",
         "in/openjpeg/CVE-2017-14164.tif", "opj_compress",
         ["-r", "20,10,1", "-jpip", "-EPH", "-SOP", "-cinema2K", "24",
          "-n", "1", "-i", "{input_file}", "-o", "/tmp/null.j2k"]),
    spec("CVE-2017-14039", "openjpeg", "openjpeg-versions/version.2.2.0",
         "openjpeg-versions/version.2.1", "2.1",
         "in/openjpeg/CVE-2017-14039.tif", "opj_compress",
         ["-r", "20,10,1", "-jpip", "-EPH", "-SOP", "-cinema2K", "24",
          "-n", "1", "-i", "{input_file}", "-o", "/tmp/null.j2k"]),
    # ---------------- libarchive ----------------
    spec("CVE-2025-5915", "libarchive", "libarchive-versions/v3.6.0",
         "libarchive-versions/v3.5.3", "3.5.3",
         "in/libarchive/CVE-2025-5915/official_2565.rar", "bsdtar",
         ["-xf", "{input_file}", "-C", "/tmp/extract"]),
    # ---------------- libtiff (main table) ----------------
    spec("CVE-2025-8176", "libtiff", "tiff-versions/tiff-4.7.0",
         "tiff-versions/tiff-4.5.1", "4.5.1", "in/libtiff/CVE-2025-8176.tif",
         "tiffmedian", ["-C", "256", "-c", "lzw:2", "-f", "{input_file}",
                        "{output_file}"]),
    spec("CVE-2025-8177", "libtiff", "tiff-versions/tiff-4.7.0",
         "tiff-versions/tiff-4.1.0", "4.1.0", "in/libtiff/CVE-2025-8177.tif",
         "thumbnail", ["{input_file}", "{output_file}"]),
    spec("CVE-2016-10268", "libtiff", "tiff-versions/tiff-4.0.7",
         "tiff-versions/tiff-4.0.6", "4.0.6",
         "in/libtiff/CVE-2016-10268.tif", "tiffcp",
         ["-i", "{input_file}", "{output_file}"]),
    spec("CVE-2016-10269", "libtiff", "tiff-versions/tiff-4.0.7",
         "tiff-versions/tiff-4.0.6", "4.0.6",
         "in/libtiff/asarubbo/00071-libtiff-heapoverflow-_TIFFmemcpy",
         "tiffcp", ["-i", "{input_file}", "{output_file}"]),
    spec("CVE-2016-10270", "libtiff", "tiff-versions/tiff-4.0.7",
         "tiff-versions/tiff-3.9.6", "3.9.6",
         "in/libtiff/asarubbo/00074-libtiff-heapoverflow-TIFFFillStrip",
         "tiffcp", ["-i", "{input_file}", "{output_file}"]),
    spec("CVE-2017-7597", "libtiff", "tiff-versions/tiff-4.0.7",
         "tiff-versions/tiff-4.0.6", "4.0.6",
         "in/libtiff/asarubbo/00114-libtiff-outside-float-tif_dirread",
         "tiffcp", ["-i", "{input_file}", "{output_file}"]),
    spec("CVE-2022-0891", "libtiff", "tiff-versions/tiff-4.0.4",
         "tiff-versions/tiff-3.9.3", "3.9.3", "in/CVE-2022-0891",
         "tiffcrop", ["-i", "-E", "l", "-H", "10", "-V", "10", "-S", "8:4",
                      "-R", "270", "{input_file}", "{output_file}"]),
    # ---------------- libredwg ----------------
    spec("CVE-2022-33034", "libredwg", "libredwg-versions/libredwg-0.12.5",
         "libredwg-versions/libredwg-0.12.4", "0.12.4",
         "in/libredwg/CVE-2022-33034-copy_bytes_sof", "dwg2dxf",
         ["-b", "-m", "-y", "-o", "{output_file}", "{input_file}"],
         output="/dev/null"),
    spec("CVE-2026-9500", "libredwg", "libredwg-versions/libredwg-6d6a339",
         "libredwg-versions/libredwg-0.13.4", "0.13.4",
         "in/libredwg/CVE-2026-9500.dwg", "dwgread", ["{input_file}"]),
    spec("CVE-2026-9502", "libredwg", "libredwg-versions/libredwg-0.13.4",
         "libredwg-versions/libredwg-0.13.3", "0.13.3",
         "in/libredwg/CVE-2026-9502.dwg", "dwgread", ["{input_file}"]),
    spec("CVE-2026-9503", "libredwg", "libredwg-versions/libredwg-0.13.4",
         "libredwg-versions/libredwg-0.12.5", "0.12.5",
         "in/libredwg/CVE-2026-9503.dwg", "dwg2SVG", ["{input_file}"]),
    spec("CVE-2026-9504", "libredwg", "libredwg-versions/libredwg-6d6a339",
         "libredwg-versions/libredwg-0.13.3", "0.13.3",
         "in/libredwg/CVE-2026-9504.dwg", "dwggrep",
         [".*", "{input_file}"]),
    spec("CVE-2026-9605", "libredwg", "libredwg-versions/libredwg-0.13.4",
         "libredwg-versions/libredwg-0.13.3", "0.13.3",
         "in/libredwg/CVE-2026-9605.dwg", "dwgbmp", ["{input_file}"]),
    spec("CVE-2026-15184", "libredwg", "libredwg-versions/libredwg-0.13.4",
         "libredwg-versions/libredwg-0.12.5", "0.12.5",
         "in/libredwg/CVE-2026-15184.dwg", "dwggrep",
         [".*", "{input_file}"]),
    spec("CVE-2026-15520", "libredwg", "libredwg-versions/libredwg-0.13.4",
         "libredwg-versions/libredwg-0.13.3", "0.13.3",
         "in/libredwg/CVE-2026-15520.dwg", "dwg2dxf",
         ["--binary", "{input_file}"]),
    # ---------------- audiofile ----------------
    spec("CVE-2019-13147", "audiofile", "audiofile-versions/audiofile-0.3.6",
         "audiofile-versions/audiofile-0.3.4", "0.3.4",
         "in/audiofile/CVE-2019-13147", "sfconvert",
         ["{input_file}", "{output_file}", "format", "aiff"],
         output="/tmp/out.aiff"),
    # ---------------- libsndfile (blocked: version trees missing) ----------
    spec("CVE-2017-7741", "libsndfile", None,
         "libsndfile-versions/libsndfile-1.0.25", "1.0.25",
         "in/libsndfile/CVE-2017-7741", None, None,
         blocked="libsndfile version tree missing (libsndfile-versions/ empty)"),
    spec("CVE-2024-50612", "libsndfile", None,
         "libsndfile-versions/libsndfile-1.0.26", "1.0.26",
         "in/libsndfile/CVE-2024-50612", None, None,
         blocked="libsndfile version tree missing (libsndfile-versions/ empty)"),
    # ---------------- lame ----------------
    spec("CVE-2015-9101", "lame", "lame-versions/lame-3.99.5",
         "lame-versions/lame-3.98.4", "3.98.4", "in/lame/CVE-2015-9101",
         "lame", ["-f", "-V", "9", "{input_file}", "{output_file}"],
         output="/dev/null"),
    spec("CVE-2017-9872", "lame", "lame-versions/lame-3.99.5",
         "lame-versions/lame-3.98.4", "3.98.4", "in/lame/CVE-2017-9872",
         "lame", ["--mp3input", "-f", "-V", "9", "{input_file}",
                  "{output_file}"], output="/dev/null"),
    # ---------------- jasper ----------------
    spec("CVE-2017-5505", "jasper",
         "jasper-versions/jasper-version-1.900.27",
         "jasper-versions/jasper-version-1.900.24", "1.900.24",
         "in/jasper/asarubbo/00053-jasper-invalidread-jas_matrix_asl",
         "imginfo", ["-f", "{input_file}"]),
    spec("CVE-2017-6851", "jasper",
         "jasper-versions/jasper-version-2.0.10",
         "jasper-versions/jasper-version-1.900.24", "1.900.24",
         "in/jasper/asarubbo/00125-jasper-invalidread-jas_matrix_bindsub",
         "imginfo", ["-f", "{input_file}"]),
    # ---------------- openexr ----------------
    spec("CVE-2025-48071", "openexr", "openexr-versions/openexr-3.3.2",
         "openexr-versions/openexr-3.2.12", "3.2.12",
         "in/openexr/CVE-2025-48071-heap_overflow.exr", "exrcheck",
         ["{input_file}"]),
    # ---------------- exiv2 ----------------
    spec("CVE-2025-26623", "exiv2", "exiv2-versions/exiv2-0.28.4",
         "exiv2-versions/exiv2-0.27.7", "0.27.7",
         "in/exiv2/CVE-2025-26623-poc.tiff", "exiv2",
         ["-q", "fi", "{input_file}"]),
    # ---------------- pcre2 ----------------
    spec("CVE-2026-86145", "pcre2", "pcre2-versions/pcre2-pcre2-10.34",
         "pcre2-versions/pcre2-pcre2-10.30", "10.30",
         "in/pcre2/CVE-2026-86145.txt", "pcre2test", ["{input_file}"]),
    # ---------------- libtiff (tail: mutate success) ----------------
    spec("CVE-2016-10092", "libtiff", "tiff-versions/tiff-4.0.7",
         "tiff-versions/tiff-3.9.4", "3.9.4", "in/CVE-2016-10092",
         "tiffcrop", ["-i", "{input_file}", "{output_file}"]),
    spec("CVE-2022-2953", "libtiff", "tiff-versions/tiff-4.4.0",
         "tiff-versions/tiff-4.0.4beta", "4.0.4beta", "in/CVE-2022-2953",
         "tiffcrop", ["-Z", "1:4,3:3", "-R", "90", "-H", "300", "-S", "2:2",
                      "-i", "{input_file}", "{output_file}"]),
    spec("CVE-2022-3627", "libtiff", "tiff-versions/tiff-4.4.0",
         "tiff-versions/tiff-4.0.7", "4.0.7", "in/CVE-2022-3627",
         "tiffcrop", ["-Z", "1:4,3:3", "-R", "90", "-H", "300", "-i",
                      "{input_file}", "{output_file}"]),
    spec("CVE-2023-25435", "libtiff", "tiff-versions/tiff-4.5.0",
         "tiff-versions/tiff-4.3.0", "4.3.0", "in/CVE-2023-25435",
         "tiffcrop", ["-E", "l", "-Z", "12:50,12:99", "-e", "divided",
                      "-R", "270", "{input_file}", "{output_file}"]),
    spec("CVE-2022-3598", "libtiff", "tiff-versions/tiff-4.4.0",
         "tiff-versions/tiff-4.0.8", "4.0.8", "in/CVE-2022-3598",
         "tiffcrop", ["-Z", "1:4,3:3", "{input_file}", "{output_file}"]),
    spec("CVE-2022-3597", "libtiff", "tiff-versions/tiff-4.4.0",
         "tiff-versions/tiff-4.0.8", "4.0.8", "in/CVE-2022-3597",
         "tiffcrop", ["-Z", "1:4,3:3", "-R", "90", "-H", "300", "-i",
                      "{input_file}", "{output_file}"]),
    spec("CVE-2020-19144", "libtiff", "tiff-versions/tiff-4.0.10",
         "tiff-versions/tiff-4.0.8", "4.0.8", "in/CVE-2020-19144",
         "tiffcp", ["-i", "{input_file}", "{output_file}"]),
    spec("CVE-2023-0800", "libtiff", "tiff-versions/tiff-4.4.0",
         "tiff-versions/tiff-4.3.0", "4.3.0", "in/CVE-2023-0800",
         "tiffcrop", ["-E", "right", "-z",
                      "1,1,2048,2048:1,2049,2048,4097", "-i",
                      "{input_file}", "{output_file}"]),
    spec("CVE-2023-30775", "libtiff", "tiff-versions/tiff-4.4.0",
         "tiff-versions/tiff-4.0.8", "4.0.8", "in/CVE-2023-30775",
         "tiffcrop", ["-i", "{input_file}", "{output_file}"]),
    # ---------------- libtiff (tail: pending) ----------------
    spec("CVE-2022-1354", "libtiff", "tiff-versions/tiff-4.3.0",
         "tiff-versions/tiff-4.0.8", "4.0.8", "in/CVE-2022-1354",
         "tiffinfo", ["-D", "-i", "-r", "{input_file}"]),
    spec("CVE-2022-3570", "libtiff", "tiff-versions/tiff-4.4.0",
         "tiff-versions/tiff-3.9.6", "3.9.6", "in/CVE-2022-3570",
         "tiffcrop", ["-i", "-E", "l", "-H", "10", "-V", "10", "-S", "8:4",
                      "-R", "270", "{input_file}", "{output_file}"],
         blocked="no non-crashing old version: 3.9.3-4.4.0 all crash "
                 "(<=3.9.6 in reverseSamples24bits, 4.4.0 in "
                 "rotateContigSamples24bits)"),
    spec("CVE-2022-2519", "libtiff", "tiff-versions/tiff-4.4.0",
         "tiff-versions/tiff-4.0.8", "4.0.8", "in/CVE-2022-2519",
         "tiffcrop", ["-Z", "1:4,3:3", "-R", "90", "-H", "300", "-S", "2:2",
                      "-i", "{input_file}", "{output_file}"]),
    spec("CVE-2022-3626", "libtiff", "tiff-versions/tiff-4.4.0",
         "tiff-versions/tiff-4.0.8", "4.0.8", "in/CVE-2022-3626",
         "tiffcrop", ["-X", "1", "-Y", "2", "-R", "180", "-H", "300",
                      "-V", "300", "-i", "{input_file}",
                      "{output_file}"]),
    spec("CVE-2022-4645", "libtiff", "tiff-versions/tiff-4.4.0",
         "tiff-versions/tiff-4.0.8", "4.0.8", "in/CVE-2022-4645",
         "tiffcp", ["{input_file}", "{output_file}"]),
    spec("CVE-2022-48281", "libtiff", "tiff-versions/tiff-4.5.0",
         "tiff-versions/tiff-4.0.8", "4.0.8", "in/CVE-2022-48281",
         "tiffcrop", ["-Z", "1:3,2:4", "-e", "divided", "{input_file}",
                      "{output_file}"]),
    spec("CVE-2023-3618", "libtiff", "tiff-versions/tiff-4.5.0",
         "tiff-versions/tiff-4.1.0", "4.1.0", "in/CVE-2023-3618",
         "tiffcrop", ["-Z", "12:50,12:99", "-R", "270", "{input_file}",
                      "{output_file}"], output="/dev/null"),
]


# ---------------------------------------------------------------------------
# Full target-version sets per CVE ("all qualifying older versions").
# A base spec's single target is replaced by this list when its CVE appears
# here.  Lists are the documented non-crashing ranges, restricted to version
# trees that exist locally.  Ref versions and versions known to trigger the
# original PoC are excluded.
# ---------------------------------------------------------------------------
def _bu(*v):
    return [f"binutils-versions/binutils-{x}" for x in v]


def _lx(*v):
    return [f"libxml2-versions/libxml2-{x}" for x in v]


def _ft(*v):
    return [f"freetype-versions/freetype-{x}" for x in v]


def _oj(*v):
    return [f"openjpeg-versions/{x}" for x in v]


def _la(*v):
    return [f"libarchive-versions/v{x}" for x in v]


def _tf(*v):
    return [f"tiff-versions/tiff-{x}" for x in v]


def _lr(*v):
    return [f"libredwg-versions/libredwg-{x}" for x in v]


def _af(*v):
    return [f"audiofile-versions/audiofile-{x}" for x in v]


def _lm(*v):
    return [f"lame-versions/lame-{x}" for x in v]


def _js(*v):
    return [f"jasper-versions/jasper-version-{x}" for x in v]


def _pe(*v):
    return [f"pcre2-versions/pcre2-pcre2-{x}" for x in v]


_T39 = ["3.9.3", "3.9.4", "3.9.5", "3.9.6"]
_T40 = ["4.0.0", "4.0.1", "4.0.2", "4.0.3", "4.0.4", "4.0.4beta",
        "4.0.5", "4.0.6", "4.0.7", "4.0.8", "4.0.9", "4.0.10"]
_T40_06 = _T40[:8]
_T40_08 = _T40[:10]
_T40_09 = _T40[:11]
_T41_43 = ["4.1.0", "4.2.0", "4.3.0"]

ALL_TARGETS = {
    # binutils
    "CVE-2022-44840": _bu("2.24", "2.25", "2.26", "2.27", "2.28", "2.29",
                          "2.30", "2.31", "2.31.1", "2.32", "2.34", "2.35",
                          "2.35.1", "2.36"),
    "CVE-2023-1972": _bu("2.25", "2.26", "2.27", "2.28", "2.29", "2.30",
                         "2.31", "2.31.1", "2.32", "2.34", "2.35", "2.35.1",
                         "2.36", "2.38"),
    "CVE-2019-9074": _bu("2.25"),
    "CVE-2017-9750": _bu("2.25"),
    "CVE-2017-14939": _bu("2.26"),
    # libxml2
    "CVE-2024-34459": _lx("2.9.0", "2.9.1", "2.9.2", "2.9.4"),
    # freetype
    "CVE-2026-23865": _ft("2.11.1", "2.12.1", "2.13.0"),
    "CVE-2026-50811": _ft("2.11.1", "2.12.1", "2.13.0", "2.13.1",
                          "2.13.2", "2.13.3"),
    # openjpeg
    "CVE-2016-9572": _oj("version.2.0"),
    "issue908": _oj("version.2.0"),
    "CVE-2018-18088": _oj("version.2.0", "version.2.0.1", "version.2.1",
                          "version.2.1.1", "version.2.1.2", "version.2.2.0"),
    "CVE-2021-3575": _oj("v2.3.0"),
    "issue1620": _oj("version.2.0", "version.2.0.1", "version.2.1",
                     "version.2.1.1", "version.2.1.2", "version.2.2.0",
                     "v2.3.0", "v2.3.1", "v2.4.0", "v2.5.0", "v2.5.1",
                     "v2.5.2"),
    "CVE-2017-14151": _oj("version.2.0", "version.2.0.1", "version.2.1"),
    "CVE-2017-14152": _oj("version.2.0", "version.2.0.1", "version.2.1"),
    "CVE-2017-14164": _oj("version.2.0", "version.2.0.1", "version.2.1"),
    "CVE-2017-14039": _oj("version.2.1"),
    # libarchive
    "CVE-2025-5915": _la("3.4.0", "3.4.3", "3.5.0", "3.5.3"),
    # libtiff main table
    "CVE-2025-8176": _tf("4.1.0", "4.2.0", "4.3.0", "4.4.0", "4.5.0",
                         "4.5.1"),
    "CVE-2025-8177": _tf("3.9.3", "3.9.4", "3.9.5", "4.0.10", "4.1.0"),
    "CVE-2016-10268": _tf(*(_T39 + _T40_06 + ["4.0.8", "4.0.9", "4.0.10",
                                              "4.1.0"])),
    "CVE-2016-10269": _tf(*_T39),
    "CVE-2016-10270": _tf(*_T39),
    "CVE-2017-7597": _tf(*(_T39 + _T40_06)),
    "CVE-2022-0891": _tf(*(_T39 + ["4.0.0", "4.0.1", "4.0.2", "4.0.3",
                                    "4.0.4beta"])),
    # libredwg
    "CVE-2022-33034": _lr("0.12.4"),
    "CVE-2026-9500": _lr("0.12.4", "0.12.5", "0.13", "0.13.3", "0.13.4"),
    "CVE-2026-9502": _lr("0.12.4", "0.12.5", "0.13", "0.13.3"),
    "CVE-2026-9503": _lr("0.12.4", "0.12.5"),
    "CVE-2026-9504": _lr("0.12.4", "0.12.5", "0.13", "0.13.3"),
    "CVE-2026-9605": _lr("0.12.4", "0.12.5", "0.13", "0.13.3"),
    "CVE-2026-15184": _lr("0.12.4", "0.12.5"),
    "CVE-2026-15520": _lr("0.12.4", "0.12.5", "0.13", "0.13.3"),
    # audiofile
    "CVE-2019-13147": _af("0.3.0", "0.3.1", "0.3.2", "0.3.3", "0.3.4"),
    # lame
    "CVE-2015-9101": _lm("3.98.2", "3.98.4"),
    "CVE-2017-9872": _lm("3.98.2", "3.98.4"),
    # jasper
    "CVE-2017-5505": _js(*[f"1.900.{i}" for i in range(8, 25)]),
    "CVE-2017-6851": _js(*[f"1.900.{i}" for i in range(8, 25)]),
    # pcre2
    "CVE-2026-86145": _pe("10.00", "10.20", "10.30"),
    # libtiff tail (mutate-success list)
    "CVE-2016-10092": _tf(*_T39),
    "CVE-2022-2953": _tf(*(_T39 + _T40 + _T41_43)),
    "CVE-2022-3627": _tf(*(_T40_08)),
    "CVE-2023-25435": _tf(*(_T39[3:] + _T40 + _T41_43)),
    "CVE-2022-3598": _tf(*_T40_08),
    "CVE-2022-3597": _tf(*_T40_08),
    "CVE-2020-19144": _tf(*(_T39 + _T40_08)),
    "CVE-2023-0800": _tf(*(_T39 + _T40 + _T41_43)),
    "CVE-2023-30775": _tf("4.0.7", "4.0.8"),
    # libtiff tail (pending, verified non-crashing targets)
    "CVE-2022-1354": _tf(*(_T39 + _T40_08)),
    "CVE-2022-2519": _tf(*(_T39 + _T40_08)),
    "CVE-2022-3626": _tf(*(_T39 + _T40_08)),
    "CVE-2022-4645": _tf(*(_T39 + _T40_09)),
    "CVE-2022-48281": _tf(*(_T39 + _T40_08)),
    "CVE-2023-3618": _tf(*(_T39 + _T40 + ["4.1.0"])),
}


def _version_label(path):
    b = os.path.basename(str(path).rstrip("/"))
    return re.sub(
        r"^(libredwg-|libxml2-|libsndfile-|audiofile-|giflib-|binutils-|"
        r"jasper-version-|lame-|tiff-|freetype-|libarchive-v|exiv2-|"
        r"openexr-|pcre2-pcre2-|openjpeg-|version\.|v)", "", b)


_expanded = []
_missing_targets = []
for _sp in SPECS:
    _dirs = ALL_TARGETS.get(_sp["cve"])
    if not _dirs:
        _expanded.append(_sp)
        continue
    _seen = set()
    for _d in _dirs:
        if _d in _seen:
            continue
        _seen.add(_d)
        if not (BASE / _d).is_dir():
            _missing_targets.append(_d)
            continue
        _x = dict(_sp)
        _x["tgt"] = _d
        _x["label"] = _version_label(_d)
        _expanded.append(_x)
SPECS = _expanded

# Per-project EXECUTION_CONFIG values used by the generated configs.
EXEC = {
    "binutils":   ("/build-asan/binutils", 120),
    "libxml2":    ("", 120),
    "giflib":     ("/util", 120),
    "freetype":   ("/build", 120),
    "openjpeg":   (None, 120),   # computed from tool
    "libarchive": ("/build-asan/bin", 120),
    "libtiff":    ("/tools", 120),
    "libredwg":   ("/programs", 120),
    "audiofile":  ("/sfcommands", 60),
    "lame":       ("/frontend", 120),
    "jasper":     ("/build/src/appl", 120),
    "openexr":    ("/build/bin", 120),
    "exiv2":      ("/build/bin", 120),
    "pcre2":      ("", 120),
}


def cfg_template(project):
    return BASE / f"config_{project}.py"


def make_config(sp, cfg_path):
    text = cfg_template(sp["project"]).read_text()
    if sp["project"] == "openjpeg":
        text = re.sub(r'^PROGRAM_NAME\s*=\s*"[^"]*"',
                      f'PROGRAM_NAME = "{sp["tool"]}"', text, count=1,
                      flags=re.M)
    if sp["project"] == "freetype":
        harness = (BASE / sp["harness"]).resolve()
        lines = text.splitlines(keepends=True)
        start = next(i for i, l in enumerate(lines)
                     if l.startswith("HARNESS_SRC"))
        end = start
        while end < len(lines) and not lines[end].rstrip().endswith(")"):
            end += 1
        lines[start:end + 1] = [f"HARNESS_SRC = {str(harness)!r}\n"]
        text = "".join(lines)
    subdir, timeout = EXEC[sp["project"]]
    if subdir is None:
        subdir = ("/build-release-asan/bin"
                  if sp["tool"] == "opj_compress" else "/build/bin")
    cmd = "{program_path} " + " ".join(sp["args"])
    override = f'''

# ---- generated by run_all_cves_round.py ----
CVE_ID = {sp["cve"]!r}
INPUT_FILE = {str(sp["input_abs"])!r}
OUTPUT_FILE = {sp["output"]!r}
COMMAND_FORMAT = {cmd!r}
EXECUTION_CONFIG = {{
    "program_name": {sp["tool"]!r},
    "timeout": {timeout},
    "exec_subdir": {subdir!r},
    "command_format": COMMAND_FORMAT,
    "build_dir_pattern": {(subdir.rstrip('/') + '/')!r},
    "output_file": OUTPUT_FILE,
}}
'''
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    cfg_path.write_text(text + override)


def archive_and_clear_results():
    RESULTS.mkdir(exist_ok=True)
    ts = time.strftime("%Y%m%d_%H%M%S")
    arc = WORK / f"results_archive_{ts}"
    kept = 0
    for p in RESULTS.rglob("*"):
        if p.is_file() and p.suffix.lower() in (
                ".md", ".tsv", ".txt", ".log", ".out", ".stdout", ".csv"):
            rel = p.relative_to(RESULTS)
            dst = arc / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(p, dst)
            kept += 1
    shutil.rmtree(RESULTS)
    RESULTS.mkdir()
    print(f"[clear] results/ removed; archived {kept} text/log files -> {arc}")
    return arc


def prepare(sp, tag):
    inp = BASE / sp["input"]
    if not inp.is_file():
        return None, f"input missing: {inp}"
    ref = BASE / sp["ref"] if sp["ref"] else None
    tgt = BASE / sp["tgt"]
    if not ref or not ref.is_dir():
        return None, f"ref dir missing: {ref}"
    if not tgt.is_dir():
        return None, f"target dir missing: {tgt}"
    # isolated input copy (fork_trace_result.json lives next to the input).
    # Include the target label so two concurrent targets of the same CVE do
    # not share fork_trace_result.json.
    idir = WORK / "inputs" / sp["cve"] / sp["label"]
    idir.mkdir(parents=True, exist_ok=True)
    icopy = idir / inp.name
    shutil.copy2(inp, icopy)
    sp["input_abs"] = icopy.resolve()
    cfg = (WORK / "configs" / sp["cve"] / sp["label"] /
           f"config_{sp['project']}.py")
    make_config(sp, cfg)
    sp["cfg"] = cfg
    sp["ref_abs"] = ref.resolve()
    sp["tgt_abs"] = tgt.resolve()
    sp["artifact"] = (WORK / "artifacts" / sp["cve"] /
                      f"{sp['label']}-{tag}").resolve()
    sp["artifact"].mkdir(parents=True, exist_ok=True)
    return sp, None


def run_one(sp, tag, timeout, log_suffix=""):
    log = RESULTS / sp["cve"] / f"{sp['label']}.log"
    log.parent.mkdir(parents=True, exist_ok=True)
    spool = sp["artifact"] / "driver_stdout.tmp"
    # Per-pair TMPDIR: run_fork_analysis builds both version trees under it
    # and the rr/dynamic traces keep their workspaces there.  Removing it
    # after the run keeps /tmp from filling up over 57 pairs.
    tmpdir = Path("/tmp") / f"retro_{sp['cve']}_{tag}_{os.getpid()}_{int(time.time())}"
    tmpdir.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env.update({
        "RETRO_REF": str(sp["ref_abs"]),
        "RETRO_TGT": str(sp["tgt_abs"]),
        "RETRO_ARTIFACT_DIR": str(sp["artifact"]),
        "RETRO_OUT_SUFFIX": f"-{tag}",
        "RETRO_LOG_NAME": sp["label"],
        "RETRO_LOG_SUFFIX": log_suffix,
        "RETROSCOPE_MUTATION_WORKERS": "1",
        "ASAN_OPTIONS": ("detect_leaks=0:halt_on_error=1:"
                         "allocator_may_return_null=1:hard_rss_limit_mb=512"),
        "TMPDIR": str(tmpdir),
    })
    t0 = time.time()
    out_f = open(spool, "w", errors="replace")
    try:
        p = subprocess.Popen(
            ["./run_analysis.sh", str(sp["cfg"])], cwd=str(BASE), env=env,
            stdout=out_f, stderr=subprocess.STDOUT, start_new_session=True,
            text=True)
        try:
            rc = p.wait(timeout=timeout)
            timed_out = False
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(p.pid, signal.SIGTERM)
                time.sleep(10)
                os.killpg(p.pid, signal.SIGKILL)
            except Exception:
                pass
            rc = p.wait()
    finally:
        out_f.close()
        shutil.rmtree(tmpdir, ignore_errors=True)

    # run_analysis.sh tees its terminal output into the log itself.  If it
    # died before that (bad config/path), keep the captured stdout instead.
    if not log.is_file() or log.stat().st_size == 0:
        shutil.move(str(spool), str(log))
    else:
        try:
            spool.unlink()
        except OSError:
            pass
    if timed_out:
        with open(log, "a") as f:
            f.write(f"\n[driver] TIMEOUT after {timeout}s\n")
    elapsed = time.time() - t0
    text = log.read_text(errors="replace") if log.is_file() else ""
    completed = "Analysis completed" in text
    m = re.search(r"reproduced the reference crash on the target: (YES|no)", text)
    reproduced = bool(m and m.group(1) == "YES")
    partial_match = ("MATCHES ref crash" in text
                     or "mutation succeeded" in text
                     or "matching value(s)" in text and "1 matching" in text)
    if not completed:
        if partial_match and timed_out:
            status = "MATCH_PARTIAL"
        else:
            status = "TIMEOUT" if timed_out else "ERROR"
    elif reproduced:
        status = "MATCH"
    else:
        status = "NO_MATCH"
    return {"cve": sp["cve"], "label": sp["label"], "status": status,
            "rc": rc, "elapsed": round(elapsed, 1), "log": str(log)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--round-tag", default="r1",
                    help="suffix for out/ and artifact dirs (default: r1)")
    ap.add_argument("--workers", type=int, default=2)
    ap.add_argument("--log-suffix", default="",
                    help="suffix for results/<CVE>/<version><suffix>.log "
                         "(e.g. _run2 for a later round)")
    ap.add_argument("--timeout", type=int, default=6 * 3600,
                    help="per-pair timeout seconds (default 21600)")
    ap.add_argument("--clear-results", action="store_true",
                    help="archive text/log summaries and empty results/ first")
    ap.add_argument("--only", action="append", default=[],
                    help="run only these CVE ids (repeatable)")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    WORK.mkdir(parents=True, exist_ok=True)
    (WORK / "status").mkdir(exist_ok=True)
    if args.clear_results:
        archive_and_clear_results()
    RESULTS.mkdir(exist_ok=True)

    specs = [s for s in SPECS if not args.only or s["cve"] in args.only]
    # blocked entries: write a readable log into results/<CVE>/
    queue = []
    for sp in specs:
        if sp["blocked"]:
            log = RESULTS / sp["cve"] / f"{sp['label']}.log"
            log.parent.mkdir(parents=True, exist_ok=True)
            log.write_text(f"BLOCKED: {sp['blocked']}\n")
            print(f"[blocked] {sp['cve']} {sp['label']}: {sp['blocked']}")
            continue
        queue.append(sp)

    print(f"[*] round={args.round_tag} workers={args.workers} "
          f"runnable={len(queue)} blocked={len(specs) - len(queue)}")
    if args.dry_run:
        for sp in queue:
            print(f"  {sp['cve']:16s} {sp['project']:10s} "
                  f"{sp['ref']} -> {sp['tgt']}  {sp['input']}")
        return 0

    prepared = []
    for sp in queue:
        s, err = prepare(sp, args.round_tag)
        if err:
            log = RESULTS / sp["cve"] / f"{sp['label']}.log"
            log.parent.mkdir(parents=True, exist_ok=True)
            log.write_text(f"SETUP_ERROR: {err}\n")
            print(f"[setup-error] {sp['cve']}: {err}")
        else:
            prepared.append(s)
    print(f"[*] prepared {len(prepared)} pairs")

    statuses = []
    lock = __import__("threading").Lock()

    def _work(sp):
        t = time.strftime("%F %T")
        with lock:
            print(f"[{t}] START {sp['cve']} ({sp['label']})", flush=True)
        try:
            r = run_one(sp, args.round_tag, args.timeout, args.log_suffix)
        except Exception as e:
            r = {"cve": sp["cve"], "label": sp["label"],
                 "status": "DRIVER_ERROR", "error": repr(e),
                 "elapsed": 0, "log": ""}
        with lock:
            statuses.append(r)
            print(f"[{time.strftime('%F %T')}] DONE  {r['cve']} "
                  f"{r.get('status')} ({r.get('elapsed')}s)", flush=True)
            json.dump(statuses, open(WORK / "status" /
                                     f"status_{args.round_tag}.json", "w"),
                      indent=1)
        return r

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as ex:
        list(ex.map(_work, prepared))

    tsv = WORK / "status" / f"status_{args.round_tag}.tsv"
    with open(tsv, "w") as f:
        f.write("cve\tlabel\tstatus\trc\telapsed_s\tlog\n")
        for r in sorted(statuses, key=lambda x: x["cve"]):
            f.write("\t".join(str(r.get(k, "")) for k in
                              ("cve", "label", "status", "rc", "elapsed",
                               "log")) + "\n")
    counts = {}
    for r in statuses:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    print(f"[*] finished: {counts}")
    print(f"[*] status: {tsv}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
