# config_audiofile.py

COMPILE_COMMANDS = {
    "reference": {
        "pre_build": [
            "make distclean || true",
            "bash -c 'CFLAGS=\"-finstrument-functions -g -O0 -fsanitize=address -fno-omit-frame-pointer -Wno-error\" LDFLAGS=\"-fsanitize=address -ldl -lm\" ./configure'",
            "make -C libaudiofile -j2",
            "make -C sfcommands -j2"
        ],
        "compile_flags": {
            "CFLAGS": "-finstrument-functions -g -O0 -fsanitize=address -fno-omit-frame-pointer -Wno-error",
            "CXXFLAGS": "-finstrument-functions -g -O0 -fsanitize=address -fno-omit-frame-pointer -Wno-error -fpermissive",
            "LDFLAGS": "-fsanitize=address -ldl -lm"
        }
    },
    "target": {
        "pre_build": [
            "make distclean || true",
            "bash -c 'CFLAGS=\"-finstrument-functions -g -O0 -fsanitize=address -fno-omit-frame-pointer -Wno-error\" LDFLAGS=\"-fsanitize=address -ldl -lm\" ./configure'",
            "make -C libaudiofile -j2",
            "make -C sfcommands -j2"
        ],
        "compile_flags": {
            "CFLAGS": "-finstrument-functions -g -O0 -fsanitize=address -fno-omit-frame-pointer -Wno-error",
            "CXXFLAGS": "-finstrument-functions -g -O0 -fsanitize=address -fno-omit-frame-pointer -Wno-error -fpermissive",
            "LDFLAGS": "-fsanitize=address -ldl -lm"
        }
    }
}

EXECUTION_CONFIG = {
    "program_name": "sfconvert",
    "timeout": 60,
    "exec_subdir": "/sfcommands",
    "command_format": "{program_path} {input_file} {output_file} format aiff",
    "build_dir_pattern": "/sfcommands/"
}

ANALYSIS_CONFIG = {
    "max_test_bytes": 64,
    "crash_detection_keywords": [
        "division by zero",
        "heap-buffer-overflow",
        "stack-buffer-overflow",
        "SEGV",
        "use-after-free",
        "audiofile",
        "sfconvert",
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
