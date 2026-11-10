# config_pcre2.py
# PCRE2 project compilation configuration file
#
# Requires the run_analysis.sh "pcre2" case (reference pcre2-10.34,
# target pcre2-10.30 under pcre2-versions/).  Then run:
#     ./run_analysis.sh config_pcre2.py

# =====================================================
# CVE configuration: change this section for each CVE
# =====================================================
CVE_ID = "CVE-2026-86145"
INPUT_FILE = "in/pcre2/CVE-2026-86145.txt"
OUTPUT_FILE = "/tmp/foo"
COMMAND_FORMAT = "{program_path} {input_file}"

# =====================================================
# Compilation configuration
# =====================================================
# Autotools build of pcre2test only.  configure already exists in the
# extracted trees; re-run it so the instrumented flags take effect.
_PRE_BUILD = [
    "bash -c 'set -e; "
    "if [ ! -f configure ]; then autoreconf -fi; fi; "
    "./configure --disable-shared "
    "CFLAGS=\"-finstrument-functions -g -O0 -fsanitize=address -fno-omit-frame-pointer\" "
    "LDFLAGS=\"-fsanitize=address\" >/tmp/pcre2_cfg.log 2>&1; "
    "make -j2 pcre2test >/tmp/pcre2_make.log 2>&1'"
]

COMPILE_COMMANDS = {
    "reference": {
        "pre_build": _PRE_BUILD,
        "compile_flags": {
            "CFLAGS": "-finstrument-functions -g -O0 -fsanitize=address -fno-omit-frame-pointer",
            "LDFLAGS": "-fsanitize=address"
        }
    },
    "target": {
        "pre_build": _PRE_BUILD,
        "compile_flags": {
            "CFLAGS": "-finstrument-functions -g -O0 -fsanitize=address -fno-omit-frame-pointer",
            "LDFLAGS": "-fsanitize=address"
        }
    }
}

EXECUTION_CONFIG = {
    "program_name": "pcre2test",
    "timeout": 120,
    "exec_subdir": "",
    "command_format": COMMAND_FORMAT,
    "build_dir_pattern": ""
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
        "pcre2",
        "buffer overflow",
        "Assertion failure",
        "ERROR",
        "Aborted"
    ],
    "separate_build_and_run": True
}
