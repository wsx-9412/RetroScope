# config_openjpeg.py
# OpenJPEG project compilation configuration file.
#
# Two build flavours exist:
#   - DECOMPRESS CVEs  -> debug build (build/) with opj_decompress
#   - ENCODER CVEs     -> build-release-asan (RelWithDebInfo + NDEBUG) with
#                         opj_compress (debug build asserts too early at
#                         j2k.c:7193 and never reaches the encoder vulns)
#
# Edit the CVE section (CVE_ID, INPUT_FILE, OUTPUT_FILE, COMMAND_FORMAT) and
# PROGRAM_NAME (under "Program (tool) selection") below, then run:
#     ./run_analysis.sh config_openjpeg.py          # GDB pipeline

# =====================================================
# CVE configuration: change this section for each CVE
# =====================================================
CVE_ID = "issue1620"       # CVE number
INPUT_FILE = "in/openjpeg/issue1620_poc.jp2"  # input file path (relative to RetroScope/)
OUTPUT_FILE = "tmp/out.pgm"   # program output file
# Program arguments template: {program_path}, {input_file}, {output_file}
COMMAND_FORMAT = "{program_path} -i {input_file} -o {output_file}"

# =====================================================
# Program (tool) selection: change PROGRAM_NAME only
# =====================================================
# The traced binary is:  <version-dir>/<BUILD_DIR>/bin/<PROGRAM_NAME>
#   "opj_compress"   -> encoder CVEs, build-release-asan/ (RelWithDebInfo+NDEBUG;
#                       the debug build asserts at j2k.c:7193 before the vuln)
#   "opj_decompress" -> decoder CVEs, build/
PROGRAM_NAME = "opj_decompress"
BUILD_TARGET = PROGRAM_NAME
BUILD_DIR = "build-release-asan" if PROGRAM_NAME == "opj_compress" else "build"

# =====================================================
# Compilation configuration
# =====================================================
# Encoder CVEs need RelWithDebInfo + NDEBUG (the debug build asserts at
# j2k.c:7193 before reaching the vuln); decoder CVEs use a debug build.
_BUILD_TYPE = "RelWithDebInfo" if PROGRAM_NAME == "opj_compress" else "Debug"
_OPT_FLAGS = "-O1 -DNDEBUG" if PROGRAM_NAME == "opj_compress" else "-O0"
_FSAN_FLAGS = "-finstrument-functions -g " + _OPT_FLAGS + " -fsanitize=address -fno-omit-frame-pointer"
_CMAKE_CMD = (
    "bash -c 'cmake -S . -B " + BUILD_DIR + " "
    "-DCMAKE_BUILD_TYPE=" + _BUILD_TYPE + " "
    "-DCMAKE_C_FLAGS=\"" + _FSAN_FLAGS + " -fno-common\" "
    "-DCMAKE_CXX_FLAGS=\"" + _FSAN_FLAGS + " -fcommon\" "
    "-DCMAKE_EXE_LINKER_FLAGS=\"-fsanitize=address\" "
    "-DCMAKE_SHARED_LINKER_FLAGS=\"-fsanitize=address\" "
    "-DBUILD_SHARED_LIBS=ON -DBUILD_CODEC=ON "
    "-DTIFF_INCLUDE_DIR=/tmp/tiffdev/usr/include/x86_64-linux-gnu "
    "-DTIFF_LIBRARY=/usr/lib/x86_64-linux-gnu/libtiff.so.5 "
    # OpenJPEG appends libtiff-4.pc's Libs.private (-lwebp -lzstd ...) to the
    # link line; this system lacks the libwebp.so dev symlink, so disable
    # pkg-config for the build (find_package(TIFF) still locates libtiff).
    "-DPKG_CONFIG_EXECUTABLE=/bin/false'"
)

_PRE_BUILD = [
    "rm -rf " + BUILD_DIR,
    _CMAKE_CMD,
    "make -C " + BUILD_DIR + " -j2 " + BUILD_TARGET,
]

COMPILE_COMMANDS = {
    "reference": {
        "pre_build": _PRE_BUILD,
        "compile_flags": {
            "CFLAGS": _FSAN_FLAGS + " -fno-common",
            "CXXFLAGS": _FSAN_FLAGS + " -fcommon",
            "LDFLAGS": "-fsanitize=address"
        }
    },
    "target": {
        "pre_build": _PRE_BUILD,
        "compile_flags": {
            "CFLAGS": _FSAN_FLAGS + " -fno-common",
            "CXXFLAGS": _FSAN_FLAGS + " -fcommon",
            "LDFLAGS": "-fsanitize=address"
        }
    }
}

# Program execution parameter configuration
# The traced binary resolves to: <version-dir>/<exec_subdir>/<program_name>
# e.g. .../version.2.2.0/build-release-asan/bin/opj_compress
EXECUTION_CONFIG = {
    "program_name": PROGRAM_NAME,
    "timeout": 120,
    "exec_subdir": "/" + BUILD_DIR + "/bin",
    "command_format": COMMAND_FORMAT,
    "build_dir_pattern": "/" + BUILD_DIR + "/bin/"
}

# Analysis parameter configuration
ANALYSIS_CONFIG = {
    "max_test_bytes": 64,
    "crash_detection_keywords": [
        "division by zero",
        "heap-buffer-overflow",
        "stack-buffer-overflow",
        "SEGV",
        "use-after-free",
        "heap-use-after-free",
        "opj_",
        "openjpeg",
        "buffer overflow",
        "Assertion failure",
        "AddressSanitizer",
        "ERROR",
        "Aborted"
    ],
    "separate_build_and_run": True
}
