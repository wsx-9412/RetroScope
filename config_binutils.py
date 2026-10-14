# config_binutils.py
# GNU binutils project compilation configuration file
#
# To test a different CVE, edit ONLY the CVE section below (CVE_ID, INPUT_FILE,
# OUTPUT_FILE, COMMAND_FORMAT), then run:
#     ./run_analysis.sh config_binutils.py          # GDB pipeline
#     ./run_analysis.sh config_binutils.py -full    # GDB + polytracker
#
# binutils is built out-of-tree (build-asan/); objdump/readelf live under
# build-asan/binutils/.  The first compilation is slow (~10-20 min/version).
#
# NOTE: -finstrument-functions is NOT passed to configure.  Exporting it in
# the configure environment breaks config.guess's link probes (undefined
# __cyg_profile_func_enter), which misdetects the host triple and makes the
# doc/makeinfo machinery fail.  It is injected only at make time, where a
# command-line CFLAGS override propagates to all sub-makes via MAKEFLAGS.

# =====================================================
# CVE configuration: change this section for each CVE
# =====================================================
CVE_ID = "CVE-2019-17450"          # CVE number
INPUT_FILE = "in/CVE-2019-17450"   # input file path (relative to RetroScope/)
OUTPUT_FILE = "/tmp/foo"          # program output file
# Program arguments template: {program_path}, {input_file}, {output_file}
# {program_path} already IS the tool binary selected by EXECUTION_CONFIG
# "program_name"; do NOT write the tool name into the format string.
COMMAND_FORMAT = "{program_path} -g {input_file}"

# =====================================================
# Compilation configuration (usually no need to change)
# =====================================================
# -fcommon is required so old crx/cr16 disassembler globals do not clash under
# GCC 10+; MAKEINFO=true / --disable-werror avoid doc and old-code build noise.
COMPILE_COMMANDS = {
    "reference": {
        "pre_build": [
            "rm -rf build-asan",
            "mkdir -p build-asan",
            "bash -c 'cd build-asan && MAKEINFO=true ../configure --disable-nls --disable-werror --disable-gdb --disable-gold --disable-ld --disable-gas --disable-sim --disable-gprof --disable-gprofng --enable-targets=all CFLAGS=\"-g -O0 -fsanitize=address -fno-omit-frame-pointer -fcommon\" LDFLAGS=\"-fsanitize=address\"'",
            "bash -c 'cd build-asan && mkdir -p bfd/doc binutils/doc && touch bfd/doc/bfd.info binutils/doc/binutils.info'",
            "bash -c 'cd build-asan && ASAN_OPTIONS=detect_leaks=0 make -j2 MAKEINFO=true CFLAGS=\"-finstrument-functions -g -O0 -fsanitize=address -fno-omit-frame-pointer -fcommon\" all-binutils'",
        ],
        "compile_flags": {
            "CFLAGS": "-g -O0 -fsanitize=address -fno-omit-frame-pointer -fcommon",
            "LDFLAGS": "-fsanitize=address"
        }
    },
    "target": {
        "pre_build": [
            "rm -rf build-asan",
            "mkdir -p build-asan",
            "bash -c 'cd build-asan && MAKEINFO=true ../configure --disable-nls --disable-werror --disable-gdb --disable-gold --disable-ld --disable-gas --disable-sim --disable-gprof --disable-gprofng --enable-targets=all CFLAGS=\"-g -O0 -fsanitize=address -fno-omit-frame-pointer -fcommon\" LDFLAGS=\"-fsanitize=address\"'",
            "bash -c 'cd build-asan && mkdir -p bfd/doc binutils/doc && touch bfd/doc/bfd.info binutils/doc/binutils.info'",
            "bash -c 'cd build-asan && ASAN_OPTIONS=detect_leaks=0 make -j2 MAKEINFO=true CFLAGS=\"-finstrument-functions -g -O0 -fsanitize=address -fno-omit-frame-pointer -fcommon\" all-binutils'",
        ],
        "compile_flags": {
            "CFLAGS": "-g -O0 -fsanitize=address -fno-omit-frame-pointer -fcommon",
            "LDFLAGS": "-fsanitize=address"
        }
    }
}

# Program execution parameter configuration
EXECUTION_CONFIG = {
    "program_name": "objdump",
    "timeout": 120,
    "exec_subdir": "/build-asan/binutils",
    "command_format": COMMAND_FORMAT,
    "build_dir_pattern": "/build-asan/binutils/"
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
        "binutils",
        "objdump",
        "bfd",
        "buffer overflow",
        "Assertion failure",
        "AddressSanitizer",
        "ERROR",
        "Aborted"
    ],
    "separate_build_and_run": True
}
