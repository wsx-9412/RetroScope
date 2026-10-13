# config_giflib.py
# giflib project compilation configuration file
#
# To test a different CVE, edit ONLY the CVE section below (CVE_ID, INPUT_FILE,
# OUTPUT_FILE, COMMAND_FORMAT), then run:
#     ./run_analysis.sh config_giflib.py          # GDB pipeline
#     ./run_analysis.sh config_giflib.py -full    # GDB + polytracker
#
# Note: the default reference/target pair (5.2.2 / 5.2.1) uses the plain
# Makefile build (giflib >= 5.1.7).  For autotools versions (<= 5.1.4, tools
# under util/) adjust the pre_build commands accordingly.

# =====================================================
# CVE configuration: change this section for each CVE
# =====================================================
CVE_ID = "CVE-2022-28506"        # CVE number
INPUT_FILE = "in/CVE-2022-28506" # input file path (relative to RetroScope/)
OUTPUT_FILE = "/tmp/foo"         # program output file
# Program arguments template: {program_path}, {input_file}, {output_file}
COMMAND_FORMAT = "{program_path} {input_file}"

# =====================================================
# Compilation configuration (usually no need to change)
# =====================================================
# giflib's Makefile assigns CFLAGS with '=', so the flags must be passed on
# the make command line (they are also exported via compile_flags below).
COMPILE_COMMANDS = {
    "reference": {
        "pre_build": [
            "make clean || true",
            "make -j2 CFLAGS='-finstrument-functions -g -O0 -fsanitize=address -fno-omit-frame-pointer' libgif.a gif2rgb",
        ],
        "compile_flags": {
            "CFLAGS": "-finstrument-functions -g -O0 -fsanitize=address -fno-omit-frame-pointer",
            "LDFLAGS": "-fsanitize=address"
        }
    },
    "target": {
        "pre_build": [
            "make clean || true",
            "make -j2 CFLAGS='-finstrument-functions -g -O0 -fsanitize=address -fno-omit-frame-pointer' libgif.a gif2rgb",
        ],
        "compile_flags": {
            "CFLAGS": "-finstrument-functions -g -O0 -fsanitize=address -fno-omit-frame-pointer",
            "LDFLAGS": "-fsanitize=address"
        }
    }
}

# Program execution parameter configuration
EXECUTION_CONFIG = {
    "program_name": "gif2rgb",
    "timeout": 120,
    "exec_subdir": "",
    "command_format": COMMAND_FORMAT,
    "build_dir_pattern": ""
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
        "giflib",
        "gif2rgb",
        "buffer overflow",
        "Assertion failure",
        "AddressSanitizer",
        "ERROR",
        "Aborted"
    ],
    "separate_build_and_run": True
}
