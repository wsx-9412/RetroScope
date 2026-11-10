# config_openexr.py
# OpenEXR project compilation configuration file
#
# To test a different CVE, edit ONLY the CVE section below (CVE_ID, INPUT_FILE,
# OUTPUT_FILE, COMMAND_FORMAT), then run:
#     ./run_analysis.sh config_openexr.py

# =====================================================
# CVE configuration: change this section for each CVE
# =====================================================
CVE_ID = "CVE-2025-48071"
INPUT_FILE = "in/openexr/CVE-2025-48071-heap_overflow.exr"
OUTPUT_FILE = "/tmp/foo"
COMMAND_FORMAT = "{program_path} {input_file}"

# =====================================================
# Compilation configuration
# =====================================================
# Imath is at /tmp/imath-install, libdeflate at /tmp/libdeflate-install
# (3.2.x needs libdeflate on the prefix path; 3.3.x ignores it).
_PRE_BUILD = [
    "bash -c 'set -e; "
    "mkdir -p website/src; echo \"# dummy\" > website/src/CMakeLists.txt; "
    "rm -rf build; mkdir -p build; cd build; "
    "cmake .. "
    "-DCMAKE_PREFIX_PATH=\"/tmp/imath-install;/tmp/libdeflate-install\" "
    "-DBUILD_SHARED_LIBS=OFF -DBUILD_TESTING=OFF "
    "-DOPENEXR_BUILD_TOOLS=ON -DOPENEXR_BUILD_EXAMPLES=OFF -DOPENEXR_BUILD_PYTHON=OFF "
    "-DCMAKE_C_FLAGS=\"-finstrument-functions -g -O0 -fsanitize=address -fno-omit-frame-pointer\" "
    "-DCMAKE_CXX_FLAGS=\"-finstrument-functions -g -O0 -fsanitize=address -fno-omit-frame-pointer\" "
    "-DCMAKE_EXE_LINKER_FLAGS=\"-fsanitize=address\" "
    "-DCMAKE_SHARED_LINKER_FLAGS=\"-fsanitize=address\" "
    ">/tmp/openexr_cmake.log 2>&1; "
    "make exrcheck -j2 >>/tmp/openexr_cmake.log 2>&1'"
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
    "program_name": "exrcheck",
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
        "global-buffer-overflow",
        "AddressSanitizer",
        "OpenEXR",
        "Imath",
        "buffer overflow",
        "Assertion failure",
        "ERROR",
        "Aborted"
    ],
    "separate_build_and_run": True
}
