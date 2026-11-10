# config_libtiff.py
CVE_ID = "CVE-2016-10269"
INPUT_FILE = "in/libtiff/asarubbo/00071-libtiff-heapoverflow-_TIFFmemcpy"
OUTPUT_FILE = "/tmp/foo"
COMMAND_FORMAT = "{program_path} -i {input_file} {output_file}"

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

EXECUTION_CONFIG = {
    "program_name": "tiffcp",
    "timeout": 120,
    "exec_subdir": "/tools",
    "command_format": COMMAND_FORMAT,
    "build_dir_pattern": "/tools/"
}

ANALYSIS_CONFIG = {
    "max_test_bytes": 64,
    "crash_detection_keywords": [
        "division by zero", "heap-buffer-overflow", "stack-buffer-overflow",
        "SEGV", "use-after-free", "libtiff", "buffer overflow", "tiff",
        "Assertion failure", "AddressSanitizer", "ERROR", "Aborted"
    ],
    "separate_build_and_run": True
}
