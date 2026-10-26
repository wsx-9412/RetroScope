# config_libredwg.py
# GNU LibreDWG project compilation configuration file
#
# To test a different CVE, edit ONLY the CVE section below (CVE_ID, INPUT_FILE,
# OUTPUT_FILE, COMMAND_FORMAT), then run:
#     ./run_analysis.sh config_libredwg.py          # GDB only (default)
#     ./run_analysis.sh config_libredwg.py -pt      # polytracker only
#     ./run_analysis.sh config_libredwg.py -full    # GDB + polytracker

# =====================================================
# CVE configuration: change this section for each CVE
# =====================================================
CVE_ID = "CVE-2026-9503"                          # CVE number
INPUT_FILE = "in/libredwg/CVE-2026-9503.dwg"       # input file path (relative to RetroScope/)
OUTPUT_FILE = "/dev/null"                          # dwgread writes JSON to stdout
# Program arguments template: {program_path}, {input_file}, {output_file}
COMMAND_FORMAT = "{program_path} {input_file}"

# =====================================================
# Compilation configuration (usually no need to change)
# =====================================================
# Both 0.13.4 (reference, crashes) and 0.12.5 (target, rejects the sample) ship
# a generated configure script and the jsmn submodule, so neither autogen.sh
# nor a network fetch is needed here.
_PRE_BUILD = [
    "make clean || true",
    "./configure "
    "CFLAGS='-finstrument-functions -g -O0 -fsanitize=address -fno-omit-frame-pointer -Wno-error' "
    "LDFLAGS='-fsanitize=address' "
    "--enable-debug --enable-trace --disable-shared --disable-bindings",
    # Do not build the whole tree: doc/ needs makeinfo, which is often absent.
    "make -C src -j4",
    "make -C programs -j4 dwgread dwgbmp dwggrep dwg2dxf dwg2SVG",
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
    "program_name": "dwg2SVG",
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
        "libredwg",
        "dwg",
        "buffer overflow",
        "Assertion failure",
        "AddressSanitizer",
        "ERROR",
        "Aborted",
        "core dumped"
    ],
    "separate_build_and_run": True
}
