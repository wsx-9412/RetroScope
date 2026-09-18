# config_lame.py

# =====================================================
# CVE configuration: change this section for each CVE
# =====================================================
CVE_ID = "CVE-2017-15045"            # CVE number
INPUT_FILE = "in/CVE-2017-15045"     # input file path (relative to RetroScope/)
OUTPUT_FILE = "/dev/null"            # program output file
# Program arguments template: {program_path}, {input_file}, {output_file}
COMMAND_FORMAT = "{program_path} -f -V 9 {input_file} {output_file}"

COMPILE_COMMANDS = {
    "reference": {
        "pre_build": [
            "make clean || true",
            "bash -c 'CFLAGS=\"-finstrument-functions -g -fsanitize=address -fno-omit-frame-pointer -Wno-error -O0\" LDFLAGS=\"-fsanitize=address -ldl -lm\" ./configure --disable-shared --enable-static'",
            "make"
        ],
        "compile_flags": {
            "CFLAGS": "-finstrument-functions -g -fsanitize=address -fno-omit-frame-pointer -Wno-error -O0",
            "CXXFLAGS": "-finstrument-functions -g -fsanitize=address -fno-omit-frame-pointer -Wno-error -fpermissive -O0",
            "LDFLAGS": "-fsanitize=address -ldl -lm"
        }
    },
    "target": {
        "pre_build": [
            "make clean || true",
            "bash -c 'CFLAGS=\"-finstrument-functions -g -fsanitize=address -fno-omit-frame-pointer -Wno-error -O0\" LDFLAGS=\"-fsanitize=address -ldl -lm\" ./configure --disable-shared --enable-static'",
            "make"
        ],
        "compile_flags": {
            "CFLAGS": "-finstrument-functions -g -fsanitize=address -fno-omit-frame-pointer -Wno-error -O0",
            "CXXFLAGS": "-finstrument-functions -g -fsanitize=address -fno-omit-frame-pointer -Wno-error -fpermissive -O0",
            "LDFLAGS": "-fsanitize=address -ldl -lm"
        }
    }
}

EXECUTION_CONFIG = {
    "program_name": "lame",
    "timeout": 120,
    "exec_subdir": "/frontend",
    "command_format": "{program_path} -f -V 9 {input_file} /dev/null",
    "build_dir_pattern": "/frontend/"
}

ANALYSIS_CONFIG = {
    "max_test_bytes": 64,
    "crash_detection_keywords": [
        "division by zero",
        "heap-buffer-overflow",
        "stack-buffer-overflow",
        "SEGV",
        "use-after-free",
        "lame",
        "mp3",
        "buffer overflow",
        "Assertion failure",
        "segmentation fault",
        "core dumped",
        "Floating point exception",
        "Aborted",
        "AddressSanitizer",
        "ERROR"
    ],
    "separate_build_and_run": True
}
