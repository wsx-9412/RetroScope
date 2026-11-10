# config_jasper.py

# =====================================================
# CVE configuration: change this section for each CVE
# =====================================================
CVE_ID = "CVE-2017-6851"
INPUT_FILE = "in/jasper/asarubbo/00125-jasper-invalidread-jas_matrix_bindsub"
OUTPUT_FILE = "/tmp/foo"
COMMAND_FORMAT = "{program_path} -f {input_file}"

# Both branches run in one bash -c so the same config works for
# 1.900.x (autotools, imginfo at src/appl/) and 2.0.x (cmake, imginfo
# at build/src/appl/).
_PRE_BUILD = [
    "bash -c 'set -e; "
    "if [ -f configure ]; then "
    "make distclean >/dev/null 2>&1 || true; "
    "./configure --disable-shared --enable-static "
    "CFLAGS=\"-finstrument-functions -g -O0 -fsanitize=address -fno-omit-frame-pointer -Wno-error\" "
    "LDFLAGS=\"-fsanitize=address\" >/tmp/jasper_cfg.log 2>&1; "
    "make -j2 >/tmp/jasper_make.log 2>&1; "
    "else "
    "rm -rf build; mkdir -p build/cmake/modules; "
    "echo \"# Dummy InSourceBuild\" > build/cmake/modules/InSourceBuild.cmake; "
    "echo \"# Dummy Sanitizers\" > build/cmake/modules/Sanitizers.cmake; "
    "echo \"# Dummy JasOpenGL\" > build/cmake/modules/JasOpenGL.cmake; "
    "echo \"# dummy\" > build/cmake/modules/EnableAssertions.cmake; "
    "printf \"prefix=@CMAKE_INSTALL_PREFIX@\\nexec_prefix=${prefix}\\nlibdir=${exec_prefix}/@CMAKE_INSTALL_LIBDIR@\\nincludedir=${prefix}/@CMAKE_INSTALL_INCLUDEDIR@\\n\\nName: jasper\\nDescription: JasPer\\nVersion: @PROJECT_VERSION@\\nLibs: -L${libdir} -ljasper\\nCflags: -I${includedir}\\n\" > build/jasper.pc.in; "
    "cd build && cmake .. -DJAS_ENABLE_LIBJPEG=OFF -DJAS_ENABLE_OPENGL=OFF -DJAS_ENABLE_DOC=OFF -DJAS_ENABLE_AUTOMATIC_DEPENDENCIES=ON "
    "-DCMAKE_C_FLAGS=\"-finstrument-functions -g -fsanitize=address -fno-omit-frame-pointer -Wno-error\" "
    "-DCMAKE_CXX_FLAGS=\"-finstrument-functions -g -fsanitize=address -fno-omit-frame-pointer -Wno-error -fpermissive\" "
    "-DCMAKE_EXE_LINKER_FLAGS=\"-fsanitize=address\" -DCMAKE_SHARED_LINKER_FLAGS=\"-fsanitize=address\" "
    ">/tmp/jasper_cmake.log 2>&1; "
    "make -j2 >>/tmp/jasper_cmake.log 2>&1; "
    "fi'"
]

COMPILE_COMMANDS = {
    "reference": {
        "pre_build": _PRE_BUILD,
        "compile_flags": {
            "CFLAGS": "-finstrument-functions -g -O0 -fsanitize=address -fno-omit-frame-pointer -Wno-error",
            "CXXFLAGS": "-finstrument-functions -g -O0 -fsanitize=address -fno-omit-frame-pointer -Wno-error -fpermissive",
            "LDFLAGS": "-fsanitize=address -ldl -lm"
        }
    },
    "target": {
        "pre_build": _PRE_BUILD,
        "compile_flags": {
            "CFLAGS": "-finstrument-functions -g -O0 -fsanitize=address -fno-omit-frame-pointer -Wno-error",
            "CXXFLAGS": "-finstrument-functions -g -O0 -fsanitize=address -fno-omit-frame-pointer -Wno-error -fpermissive",
            "LDFLAGS": "-fsanitize=address -ldl -lm"
        }
    }
}

EXECUTION_CONFIG = {
    "program_name": "imginfo",
    "timeout": 120,
    "exec_subdir": "/build/src/appl",
    "command_format": "{program_path} -f {input_file}",
    "build_dir_pattern": "/build/src/appl/"
}

ANALYSIS_CONFIG = {
    "max_test_bytes": 64,
    "crash_detection_keywords": [
        "division by zero",
        "heap-buffer-overflow",
        "stack-buffer-overflow",
        "SEGV",
        "use-after-free",
        "heap-use-after-free",
        "global-buffer-overflow",
        "AddressSanitizer",
        "exceeds maximum supported size",
        "integer overflow",
        "jasper",
        "buffer overflow",
        "assertion failed",
        "double free"
    ]
}
