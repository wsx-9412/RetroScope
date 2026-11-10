# config_libarchive.py
# libarchive project compilation configuration file.
#
# To test a different CVE, edit the CVE section (CVE_ID, INPUT_FILE,
# OUTPUT_FILE, COMMAND_FORMAT), then run:
#     ./run_analysis.sh config_libarchive.py        # GDB pipeline

# =====================================================
# CVE configuration: change this section for each CVE
# =====================================================
CVE_ID = "CVE-2025-5915"        # CVE number
INPUT_FILE = "in/libarchive/CVE-2025-5915/official_2565.rar"  # input file path (relative to RetroScope/)
OUTPUT_FILE = "/tmp/extract"    # extraction dir (created by pre_build)
# Program arguments template: {program_path}, {input_file}, {output_file}
COMMAND_FORMAT = "{program_path} -xf {input_file} -C /tmp/extract"

# =====================================================
# Compilation configuration
# =====================================================
_CMAKE_CMD = (
    "bash -c 'cmake -S . -B build-asan "
    "-DCMAKE_BUILD_TYPE=Debug "
    "-DCMAKE_C_FLAGS=\"-finstrument-functions -g -O0 -fsanitize=address -fno-omit-frame-pointer -Wno-deprecated-declarations -Wno-array-parameter\" "
    "-DCMAKE_EXE_LINKER_FLAGS=\"-fsanitize=address\" "
    "-DENABLE_WERROR=OFF -DENABLE_LZO=OFF -DENABLE_NETTLE=OFF -DENABLE_OPENSSL=OFF "
    "-DENABLE_BZip2=ON -DENABLE_EXPAT=ON -DENABLE_LIBXML2=ON -DENABLE_LZMA=ON -DENABLE_ZLIB=ON'"
)

_PRE_BUILD = [
    "rm -rf build-asan",
    _CMAKE_CMD,
    "make -C build-asan -j2 bsdtar",
    "mkdir -p /tmp/extract",
]

COMPILE_COMMANDS = {
    "reference": {
        "pre_build": _PRE_BUILD,
        "compile_flags": {
            "CFLAGS": "-finstrument-functions -g -O0 -fsanitize=address -fno-omit-frame-pointer -Wno-deprecated-declarations -Wno-array-parameter",
            "LDFLAGS": "-fsanitize=address"
        }
    },
    "target": {
        "pre_build": _PRE_BUILD,
        "compile_flags": {
            "CFLAGS": "-finstrument-functions -g -O0 -fsanitize=address -fno-omit-frame-pointer -Wno-deprecated-declarations -Wno-array-parameter",
            "LDFLAGS": "-fsanitize=address"
        }
    }
}

# Program execution parameter configuration
EXECUTION_CONFIG = {
    "program_name": "bsdtar",
    "timeout": 120,
    "exec_subdir": "/build-asan/bin",
    "command_format": COMMAND_FORMAT,
    "build_dir_pattern": "/build-asan/bin/"
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
        "libarchive",
        "bsdtar",
        "copy_from_lzss_window",
        "buffer overflow",
        "Assertion failure",
        "AddressSanitizer",
        "ERROR",
        "Aborted"
    ],
    "separate_build_and_run": True
}
