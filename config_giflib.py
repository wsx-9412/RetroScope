# config_giflib.py
# giflib project compilation configuration file
#
# To test a different CVE, edit ONLY the CVE section below (CVE_ID, INPUT_FILE,
# OUTPUT_FILE, COMMAND_FORMAT), then run:
#     ./run_analysis.sh config_giflib.py          # GDB pipeline
#     ./run_analysis.sh config_giflib.py -full    # GDB + polytracker
#
# The default reference/target pair (5.1.1 / 4.1.6, CVE-2022-28506) are BOTH
# autotools builds (configure + make), with gif2rgb produced under util/.

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
# giflib 4.1.6 and 5.1.1 are autotools trees: configure then make.  gif2rgb
# and libgif land in util/ and lib/ respectively.
_PRE_BUILD = [
    "make clean || true",
    "bash -c 'CFLAGS=\"-finstrument-functions -g -O0 -fsanitize=address -fno-omit-frame-pointer\" LDFLAGS=\"-fsanitize=address\" ./configure'",
    "make -j2",
]

COMPILE_COMMANDS = {
    "reference": {
        "pre_build": _PRE_BUILD,
        "compile_flags": {
            "CFLAGS": "-finstrument-functions -g -O0 -fsanitize=address -fno-omit-frame-pointer",
            "LDFLAGS": "-fsanitize=address"
        }
    },
    "target": {
        "pre_build": _PRE_BUILD,
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
    "exec_subdir": "/util",
    "command_format": COMMAND_FORMAT,
    "build_dir_pattern": "/util/"
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
