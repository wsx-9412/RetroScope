# config_exiv2.py
# Exiv2 project compilation configuration file
#
# To test a different CVE, edit ONLY the CVE section below (CVE_ID, INPUT_FILE,
# OUTPUT_FILE, COMMAND_FORMAT), then run:
#     ./run_analysis.sh config_exiv2.py

# =====================================================
# CVE configuration: change this section for each CVE
# =====================================================
CVE_ID = "CVE-2025-26623"
INPUT_FILE = "in/exiv2/CVE-2025-26623-poc.tiff"
OUTPUT_FILE = "/tmp/foo"
COMMAND_FORMAT = "{program_path} -q fi {input_file}"

# =====================================================
# Compilation configuration
# =====================================================
# Matches the flags of the existing ASan builds: brotli/XMP/inih off,
# static, no samples/tests/docs.  0.27.7 has no INIH option.
_PRE_BUILD = [
    "bash -c 'set -e; "
    "rm -rf build; mkdir -p build; cd build; "
    "cmake .. "
    "-DBUILD_SHARED_LIBS=OFF "
    "-DEXIV2_ENABLE_BROTLI=OFF -DEXIV2_ENABLE_XMP=OFF -DEXIV2_ENABLE_INIH=OFF "
    "-DEXIV2_BUILD_SAMPLES=OFF -DEXIV2_BUILD_UNIT_TESTS=OFF -DEXIV2_BUILD_DOC=OFF "
    "-DEXIV2_BUILD_FUZZ_TESTS=OFF "
    "-DCMAKE_C_FLAGS=\"-finstrument-functions -g -O0 -fsanitize=address -fno-omit-frame-pointer\" "
    "-DCMAKE_CXX_FLAGS=\"-finstrument-functions -g -O0 -fsanitize=address -fno-omit-frame-pointer\" "
    "-DCMAKE_EXE_LINKER_FLAGS=\"-fsanitize=address\" "
    "-DCMAKE_SHARED_LINKER_FLAGS=\"-fsanitize=address\" "
    ">/tmp/exiv2_cmake.log 2>&1; "
    "make exiv2 -j2 >>/tmp/exiv2_cmake.log 2>&1'"
]

COMPILE_COMMANDS = {
    "reference": {
        "pre_build": _PRE_BUILD,
        "compile_flags": {
            "CFLAGS": "-finstrument-functions -g -O0 -fsanitize=address -fno-omit-frame-pointer",
            "CXXFLAGS": "-finstrument-functions -g -O0 -fsanitize=address -fno-omit-frame-pointer",
            "LDFLAGS": "-fsanitize=address"
        }
    },
    "target": {
        "pre_build": _PRE_BUILD,
        "compile_flags": {
            "CFLAGS": "-finstrument-functions -g -O0 -fsanitize=address -fno-omit-frame-pointer",
            "CXXFLAGS": "-finstrument-functions -g -O0 -fsanitize=address -fno-omit-frame-pointer",
            "LDFLAGS": "-fsanitize=address"
        }
    }
}

EXECUTION_CONFIG = {
    "program_name": "exiv2",
    "timeout": 120,
    "exec_subdir": "/build/bin",
    "command_format": COMMAND_FORMAT,
    "build_dir_pattern": "/build/bin/"
}

ANALYSIS_CONFIG = {
    "max_test_bytes": 64,
    "crash_detection_keywords": [
        "heap-buffer-overflow",
        "stack-buffer-overflow",
        "SEGV",
        "use-after-free",
        "heap-use-after-free",
        "heap-use-after-free",
        "global-buffer-overflow",
        "AddressSanitizer",
        "Exiv2",
        "exiv2",
        "buffer overflow",
        "Assertion failure",
        "ERROR",
        "Aborted"
    ],
    "separate_build_and_run": True
}
