# config_libsndfile.py
# libsndfile project compilation configuration file
#
# To test a different CVE, edit ONLY the CVE section below (CVE_ID, INPUT_FILE,
# OUTPUT_FILE, COMMAND_FORMAT), then run:
#     ./run_analysis.sh config_libsndfile.py          # GDB only (default)
#     ./run_analysis.sh config_libsndfile.py -pt      # polytracker only
#     ./run_analysis.sh config_libsndfile.py -full    # GDB + polytracker

# =====================================================
# CVE configuration: change this section for each CVE
# =====================================================
CVE_ID = "CVE-2024-50612"                                  # CVE number
INPUT_FILE = "in/libsndfile/CVE-2024-50612"                # input file path (relative to RetroScope/)
OUTPUT_FILE = "/tmp/out.ogg"                               # program output file
# Program arguments template: {program_path}, {input_file}, {output_file}
COMMAND_FORMAT = "{program_path} -vorbis {input_file} {output_file}"

# =====================================================
# Compilation configuration (usually no need to change)
# =====================================================
# FLAC/Ogg/Vorbis/Opus are built out-of-tree:
#   /tmp/flacdev/root  -> FLAC 1.3.3, Ogg 1.3.5, Vorbis 1.3.7
#   /tmp/opusroot      -> Opus 1.4 (only needed by 1.2.x)
# The 1.0.x trees are already configured against those prefixes.  Re-running
# their configure is not possible without the `autogen` tool: configure ends
# with `(cd src && make genfiles)` / `(cd tests && make genfiles)`, which
# regenerates test_endswap.c / write_read_test.c via autogen.  Python-package
# `autogen` is a different program.  Build the library and two tools directly.
_CFLAGS = (
    "-finstrument-functions -g -O0 -fsanitize=address "
    "-fno-omit-frame-pointer -Wno-error"
)

_PRE_BUILD = [
    "make clean || true",
    "make -C src -j4 CFLAGS='" + _CFLAGS + "' LDFLAGS='-fsanitize=address'",
    "make -C programs -j4 CFLAGS='" + _CFLAGS + "' "
    "LDFLAGS='-fsanitize=address' sndfile-convert sndfile-info",
]

COMPILE_COMMANDS = {
    "reference": {
        "pre_build": _PRE_BUILD,
        "compile_flags": {
            "CFLAGS": "-finstrument-functions -g -O0 -fsanitize=address -fno-omit-frame-pointer -Wno-error",
            "CXXFLAGS": "-finstrument-functions -g -O0 -fsanitize=address -fno-omit-frame-pointer -Wno-error",
            "LDFLAGS": "-fsanitize=address"
        }
    },
    "target": {
        "pre_build": _PRE_BUILD,
        "compile_flags": {
            "CFLAGS": "-finstrument-functions -g -O0 -fsanitize=address -fno-omit-frame-pointer -Wno-error",
            "CXXFLAGS": "-finstrument-functions -g -O0 -fsanitize=address -fno-omit-frame-pointer -Wno-error",
            "LDFLAGS": "-fsanitize=address"
        }
    }
}

# Program execution parameter configuration
EXECUTION_CONFIG = {
    "program_name": "sndfile-convert",
    "timeout": 120,
    "exec_subdir": "/programs",
    "command_format": COMMAND_FORMAT,
    "build_dir_pattern": "/programs/",
    "output_file": OUTPUT_FILE
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
        "libsndfile",
        "sndfile",
        "vorbis",
        "buffer overflow",
        "Assertion failure",
        "AddressSanitizer",
        "ERROR",
        "Aborted",
        "core dumped",
        "Floating point exception"
    ],
    "separate_build_and_run": True
}
