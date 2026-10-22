# config_libtiff.py
# LibTIFF project compilation configuration file
#
# To test a different CVE, edit ONLY the CVE section below (CVE_ID, INPUT_FILE,
# OUTPUT_FILE, COMMAND_FORMAT), then run:
#     ./run_analysis.sh config_libtiff.py          # polytracker only
#     ./run_analysis.sh config_libtiff.py -gdb     # polytracker + GDB trace

# =====================================================
# CVE configuration: change this section for each CVE
# =====================================================
CVE_ID = "CVE-2025-8177"          # CVE number
INPUT_FILE = "in/libtiff/CVE-2025-8177.tif"   # input file path (relative to RetroScope/)
OUTPUT_FILE = "/tmp/foo"          # program output file
# Program arguments template: {program_path}, {input_file}, {output_file}
COMMAND_FORMAT = "{program_path} {input_file} {output_file}"

# =====================================================
# Compilation configuration (usually no need to change)
# =====================================================
COMPILE_COMMANDS = {
    "reference": {
        "pre_build": [
            "make clean",
            "sh ./configure CFLAGS='-finstrument-functions -g -O0 -fsanitize=address -fno-omit-frame-pointer' LDFLAGS='-fsanitize=address -ldl'",
            "make -j4 CFLAGS='-finstrument-functions -g -O0 -fsanitize=address -fno-omit-frame-pointer' LDFLAGS='-fsanitize=address -ldl'",
            "make -C tools -j4 thumbnail CFLAGS='-finstrument-functions -g -O0 -fsanitize=address -fno-omit-frame-pointer' LDFLAGS='-fsanitize=address -ldl'",
        ],
        "compile_flags": {
            "CFLAGS": "-finstrument-functions -g  -ldl -fsanitize=address -fno-omit-frame-pointer",
            "CXXFLAGS": "-g -fno-omit-frame-pointer -finstrument-functions -Wno-error -fpermissive -rdynamic",
            "LDFLAGS": "-ldl -fsanitize=address"
        }
    },
    "target": {
        "pre_build": [
            "make clean",
            "sh ./configure CFLAGS='-finstrument-functions -g -O0 -fsanitize=address -fno-omit-frame-pointer' LDFLAGS='-fsanitize=address -ldl'",
            "make -j4 CFLAGS='-finstrument-functions -g -O0 -fsanitize=address -fno-omit-frame-pointer' LDFLAGS='-fsanitize=address -ldl'",
            "make -C tools -j4 thumbnail CFLAGS='-finstrument-functions -g -O0 -fsanitize=address -fno-omit-frame-pointer' LDFLAGS='-fsanitize=address -ldl'",
        ],
        "compile_flags": {
            "CFLAGS": "-finstrument-functions -g  -ldl -fsanitize=address -fno-omit-frame-pointer",
            "CXXFLAGS": "-g -fno-omit-frame-pointer -finstrument-functions -Wno-error -fpermissive -rdynamic",
            "LDFLAGS": "-ldl -fsanitize=address"
        }
    }
}

# Program execution parameter configuration
EXECUTION_CONFIG = {
    "program_name": "thumbnail",
    "timeout": 120,
    "exec_subdir": "/tools",
    "command_format": COMMAND_FORMAT,
    "build_dir_pattern": "/tools/"
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
        "libtiff",
        "buffer overflow",
        "tiff",
        "Assertion failure"
    ],
    "separate_build_and_run": True
}
