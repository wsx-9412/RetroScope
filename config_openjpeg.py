# config_openjpeg.py


# =====================================================
# CVE configuration: change this section for each CVE
# =====================================================
CVE_ID = "CVE-2018-18088"        # CVE number
INPUT_FILE = "in/openjpeg/CVE-2018-18088.j2k"  # input file path (relative to RetroScope/)
OUTPUT_FILE = "/tmp/foo.ppm"     # program output file 
# Program arguments template: {program_path}, {input_file}, {output_file}
COMMAND_FORMAT = "{program_path} -i {input_file} -o {output_file}"


# =====================================================
# Compilation configuration (usually no need to change)
# =====================================================
_CMAKE_CMD = (
    "bash -c 'cmake -S . -B build "
    "-DCMAKE_BUILD_TYPE=Debug "
    "-DCMAKE_C_FLAGS=\"-finstrument-functions -g -O0 -fsanitize=address -fno-omit-frame-pointer -fno-common\" "
    "-DCMAKE_CXX_FLAGS=\"-finstrument-functions -g -O0 -fsanitize=address -fno-omit-frame-pointer -fcommon\" "
    "-DCMAKE_EXE_LINKER_FLAGS=\"-fsanitize=address\" "
    "-DCMAKE_SHARED_LINKER_FLAGS=\"-fsanitize=address\" "
    "-DBUILD_SHARED_LIBS=ON -DBUILD_CODEC=ON'"
)

COMPILE_COMMANDS = {
    "reference": {
        "pre_build": [
            "rm -rf build",
            _CMAKE_CMD,
            "make -C build -j2 opj_decompress",
        ],
        "compile_flags": {
            "CFLAGS": "-finstrument-functions -g -O0 -fsanitize=address -fno-omit-frame-pointer",
            "CXXFLAGS": "-finstrument-functions -g -O0 -fsanitize=address -fno-omit-frame-pointer",
            "LDFLAGS": "-fsanitize=address"
        }
    },
    "target": {
        "pre_build": [
            "rm -rf build",
            _CMAKE_CMD,
            "make -C build -j2 opj_decompress",
        ],
        "compile_flags": {
            "CFLAGS": "-finstrument-functions -g -O0 -fsanitize=address -fno-omit-frame-pointer",
            "CXXFLAGS": "-finstrument-functions -g -O0 -fsanitize=address -fno-omit-frame-pointer",
            "LDFLAGS": "-fsanitize=address"
        }
    }
}

# Program execution parameter configuration
EXECUTION_CONFIG = {
    "program_name": "opj_decompress",
    "timeout": 120,
    "exec_subdir": "/build/bin",
    "command_format": COMMAND_FORMAT,
    "build_dir_pattern": "/build/bin/"
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
        "opj_",
        "openjpeg",
        "buffer overflow",
        "Assertion failure",
        "AddressSanitizer",
        "ERROR",
        "Aborted"
    ],
    "separate_build_and_run": True
}
