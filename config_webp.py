# config_webp.py
# libwebp CVE-2023-4863: ref = fixed 1.3.2, target = vulnerable 1.3.1

CVE_ID = "CVE-2023-4863"
INPUT_FILE = "/home/ws/Desktop/webp-pilot/poc/bad.webp"
OUTPUT_FILE = "/tmp/webp_out.ppm"
COMMAND_FORMAT = "{program_path} {input_file} -o {output_file}"

COMPILE_COMMANDS = {
    "reference": {
        "pre_build": [],
        "compile_flags": {
            "CFLAGS": "-finstrument-functions -g -O0 -fsanitize=address -fno-omit-frame-pointer",
            "CXXFLAGS": "-finstrument-functions -g -O0 -fsanitize=address -fno-omit-frame-pointer",
            "LDFLAGS": "-fsanitize=address -rdynamic",
        },
    },
    "target": {
        "pre_build": [],
        "compile_flags": {
            "CFLAGS": "-finstrument-functions -g -O0 -fsanitize=address -fno-omit-frame-pointer",
            "CXXFLAGS": "-finstrument-functions -g -O0 -fsanitize=address -fno-omit-frame-pointer",
            "LDFLAGS": "-fsanitize=address -rdynamic",
        },
    },
}

EXECUTION_CONFIG = {
    "program_name": "dwebp",
    "timeout": 120,
    "exec_subdir": "",
    "command_format": COMMAND_FORMAT,
    "build_dir_pattern": "/bld/",
}

ANALYSIS_CONFIG = {
    "max_test_bytes": 64,
    "crash_detection_keywords": [
        "heap-buffer-overflow",
        "stack-buffer-overflow",
        "SEGV",
        "use-after-free",
        "AddressSanitizer",
    ],
    "separate_build_and_run": True,
}
