# config_libxml2.py
# libxml2 project compilation configuration file
#
# To test a different CVE, edit ONLY the CVE section below (CVE_ID, INPUT_FILE,
# OUTPUT_FILE, COMMAND_FORMAT), then run:
#     ./run_analysis.sh config_libxml2.py          # GDB pipeline
#     ./run_analysis.sh config_libxml2.py -full    # GDB + polytracker

# =====================================================
# CVE configuration: change this section for each CVE
# =====================================================
CVE_ID = "CVE-2017-9049"          # CVE number
INPUT_FILE = "in/CVE-2017-9049"   # input file path (relative to RetroScope/)
OUTPUT_FILE = "/tmp/foo"          # program output file
# Program arguments template: {program_path}, {input_file}, {output_file}
COMMAND_FORMAT = "{program_path} --memory --oldxml10 {input_file}"

# =====================================================
# Compilation configuration (usually no need to change)
# =====================================================
# The pre_build commands run inside the version directory.  Autotools builds
# (2.9.x) put xmllint at the version root; cmake-only builds (2.10+) put it
# under build/, so both are handled.
COMPILE_COMMANDS = {
    "reference": {
        "pre_build": [
            "make distclean || true",
            "bash -c 'if [ -f configure ]; then CFLAGS=\"-finstrument-functions -g -O0 -fsanitize=address -fno-omit-frame-pointer\" LDFLAGS=\"-fsanitize=address\" ./configure --without-python --without-zlib --without-lzma --disable-shared && make -j2 xmllint; else cmake -S . -B build -DBUILD_SHARED_LIBS=OFF -DLIBXML2_WITH_PYTHON=OFF -DLIBXML2_WITH_ZLIB=OFF -DLIBXML2_WITH_LZMA=OFF -DCMAKE_C_FLAGS=\"-finstrument-functions -g -O0 -fsanitize=address -fno-omit-frame-pointer\" -DCMAKE_EXE_LINKER_FLAGS=\"-fsanitize=address\" && make -C build -j2 xmllint; fi'",
        ],
        "compile_flags": {
            "CFLAGS": "-finstrument-functions -g -O0 -fsanitize=address -fno-omit-frame-pointer",
            "LDFLAGS": "-fsanitize=address"
        }
    },
    "target": {
        "pre_build": [
            "make distclean || true",
            "bash -c 'if [ -f configure ]; then CFLAGS=\"-finstrument-functions -g -O0 -fsanitize=address -fno-omit-frame-pointer\" LDFLAGS=\"-fsanitize=address\" ./configure --without-python --without-zlib --without-lzma --disable-shared && make -j2 xmllint; else cmake -S . -B build -DBUILD_SHARED_LIBS=OFF -DLIBXML2_WITH_PYTHON=OFF -DLIBXML2_WITH_ZLIB=OFF -DLIBXML2_WITH_LZMA=OFF -DCMAKE_C_FLAGS=\"-finstrument-functions -g -O0 -fsanitize=address -fno-omit-frame-pointer\" -DCMAKE_EXE_LINKER_FLAGS=\"-fsanitize=address\" && make -C build -j2 xmllint; fi'",
        ],
        "compile_flags": {
            "CFLAGS": "-finstrument-functions -g -O0 -fsanitize=address -fno-omit-frame-pointer",
            "LDFLAGS": "-fsanitize=address"
        }
    }
}

# Program execution parameter configuration
EXECUTION_CONFIG = {
    "program_name": "xmllint",
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
        "heap-use-after-free",
        "libxml",
        "xmllint",
        "buffer overflow",
        "Assertion failure",
        "AddressSanitizer",
        "ERROR",
        "Aborted"
    ],
    "separate_build_and_run": True
}
