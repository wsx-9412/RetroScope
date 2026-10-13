# config_freetype.py
# FreeType project compilation configuration file
#
# To test a different CVE, edit ONLY the CVE section below (CVE_ID, INPUT_FILE,
# OUTPUT_FILE, COMMAND_FORMAT), then run:
#     ./run_analysis.sh config_freetype.py          # GDB pipeline
#     ./run_analysis.sh config_freetype.py -full    # GDB + polytracker
#
# FreeType ships no CLI tool; the library is built with cmake and a small
# harness (HARNESS_SRC) is compiled against it inside the version dir.
# The default harness (test_face_idx.c) is the one matching the default pair
# (2.12.1 / 2.11.1, CVE-2022-27404: FT_New_Face with an invalid face index).
# For other CVEs pick the matching harness in build/ (test_face.c,
# test_var.c, ft_get_design_dump.c, ...) and adapt COMMAND_FORMAT.

# =====================================================
# CVE configuration: change this section for each CVE
# =====================================================
CVE_ID = "CVE-2022-27404"        # CVE number
INPUT_FILE = "in/CVE-2022-27404" # input file path (relative to RetroScope/)
OUTPUT_FILE = "/tmp/foo"         # program output file
# Program arguments template: {program_path}, {input_file}, {output_file}
COMMAND_FORMAT = "{program_path} {input_file}"

HARNESS_SRC = "/home/ws/Desktop/RetroScope/build/test_face_idx.c"

# =====================================================
# Compilation configuration (usually no need to change)
# =====================================================
COMPILE_COMMANDS = {
    "reference": {
        "pre_build": [
            "rm -rf build",
            "bash -c 'cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS=\"-finstrument-functions -g -O0 -fsanitize=address -fno-omit-frame-pointer\" -DCMAKE_EXE_LINKER_FLAGS=\"-fsanitize=address\" -DCMAKE_SHARED_LINKER_FLAGS=\"-fsanitize=address\" -DFT_DISABLE_ZLIB=TRUE -DFT_DISABLE_BZIP2=TRUE -DFT_DISABLE_PNG=TRUE -DFT_DISABLE_HARFBUZZ=TRUE -DFT_DISABLE_BROTLI=TRUE'",
            "make -C build -j2",
            f"gcc -finstrument-functions -g -O0 -fsanitize=address -fno-omit-frame-pointer -I./include {HARNESS_SRC} build/libfreetyped.a -lz -lm -fsanitize=address -o build/fttest",
        ],
        "compile_flags": {
            "CFLAGS": "-finstrument-functions -g -O0 -fsanitize=address -fno-omit-frame-pointer",
            "LDFLAGS": "-fsanitize=address"
        }
    },
    "target": {
        "pre_build": [
            "rm -rf build",
            "bash -c 'cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS=\"-finstrument-functions -g -O0 -fsanitize=address -fno-omit-frame-pointer\" -DCMAKE_EXE_LINKER_FLAGS=\"-fsanitize=address\" -DCMAKE_SHARED_LINKER_FLAGS=\"-fsanitize=address\" -DFT_DISABLE_ZLIB=TRUE -DFT_DISABLE_BZIP2=TRUE -DFT_DISABLE_PNG=TRUE -DFT_DISABLE_HARFBUZZ=TRUE -DFT_DISABLE_BROTLI=TRUE'",
            "make -C build -j2",
            f"gcc -finstrument-functions -g -O0 -fsanitize=address -fno-omit-frame-pointer -I./include {HARNESS_SRC} build/libfreetyped.a -lz -lm -fsanitize=address -o build/fttest",
        ],
        "compile_flags": {
            "CFLAGS": "-finstrument-functions -g -O0 -fsanitize=address -fno-omit-frame-pointer",
            "LDFLAGS": "-fsanitize=address"
        }
    }
}

# Program execution parameter configuration
EXECUTION_CONFIG = {
    "program_name": "fttest",
    "timeout": 120,
    "exec_subdir": "/build",
    "command_format": COMMAND_FORMAT,
    "build_dir_pattern": "/build/"
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
        "freetype",
        "FreeType",
        "FT_",
        "buffer overflow",
        "Assertion failure",
        "AddressSanitizer",
        "ERROR",
        "Aborted"
    ],
    "separate_build_and_run": True
}
