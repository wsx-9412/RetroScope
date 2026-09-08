# config_jasper.py

COMPILE_COMMANDS = {
    "reference": {
        "pre_build": [
            "rm -rf build",
            "mkdir -p build/cmake/modules",
            "echo '# Dummy InSourceBuild' > build/cmake/modules/InSourceBuild.cmake",
            "echo '# Dummy Sanitizers' > build/cmake/modules/Sanitizers.cmake",
            "echo '# Dummy JasOpenGL' > build/cmake/modules/JasOpenGL.cmake",
            "printf 'prefix=@CMAKE_INSTALL_PREFIX@\\nexec_prefix=${prefix}\\nlibdir=${exec_prefix}/@CMAKE_INSTALL_LIBDIR@\\nincludedir=${prefix}/@CMAKE_INSTALL_INCLUDEDIR@\\n\\nName: jasper\\nDescription: JasPer\\nVersion: @PROJECT_VERSION@\\nLibs: -L${libdir} -ljasper\\nCflags: -I${includedir}\\n' > build/jasper.pc.in",
            "bash -c 'cd build && cmake .. -DJAS_ENABLE_LIBJPEG=OFF -DJAS_ENABLE_OPENGL=OFF -DJAS_ENABLE_DOC=OFF -DJAS_ENABLE_AUTOMATIC_DEPENDENCIES=OFF -DCMAKE_C_FLAGS=\"-finstrument-functions -g -fsanitize=address -fno-omit-frame-pointer -Wno-error\" -DCMAKE_CXX_FLAGS=\"-finstrument-functions -g -fsanitize=address -fno-omit-frame-pointer -Wno-error -fpermissive\" -DCMAKE_EXE_LINKER_FLAGS=\"-fsanitize=address\" -DCMAKE_SHARED_LINKER_FLAGS=\"-fsanitize=address\"'",
            "make -C build -j2"
        ],
        "compile_flags": {
            "CFLAGS": "-finstrument-functions -g -fsanitize=address -fno-omit-frame-pointer -Wno-error",
            "CXXFLAGS": "-finstrument-functions -g -fsanitize=address -fno-omit-frame-pointer -Wno-error -fpermissive",
            "LDFLAGS": "-fsanitize=address -ldl -lm"
        }
    },
    "target": {
        "pre_build": [
            "rm -rf build",
            "mkdir -p build/cmake/modules",
            "echo '# Dummy InSourceBuild' > build/cmake/modules/InSourceBuild.cmake",
            "echo '# Dummy Sanitizers' > build/cmake/modules/Sanitizers.cmake",
            "echo '# Dummy JasOpenGL' > build/cmake/modules/JasOpenGL.cmake",
            "printf 'prefix=@CMAKE_INSTALL_PREFIX@\\nexec_prefix=${prefix}\\nlibdir=${exec_prefix}/@CMAKE_INSTALL_LIBDIR@\\nincludedir=${prefix}/@CMAKE_INSTALL_INCLUDEDIR@\\n\\nName: jasper\\nDescription: JasPer\\nVersion: @PROJECT_VERSION@\\nLibs: -L${libdir} -ljasper\\nCflags: -I${includedir}\\n' > build/jasper.pc.in",
            "bash -c 'cd build && cmake .. -DJAS_ENABLE_LIBJPEG=OFF -DJAS_ENABLE_OPENGL=OFF -DJAS_ENABLE_DOC=OFF -DJAS_ENABLE_AUTOMATIC_DEPENDENCIES=OFF -DCMAKE_C_FLAGS=\"-finstrument-functions -g -fsanitize=address -fno-omit-frame-pointer -Wno-error\" -DCMAKE_CXX_FLAGS=\"-finstrument-functions -g -fsanitize=address -fno-omit-frame-pointer -Wno-error -fpermissive\" -DCMAKE_EXE_LINKER_FLAGS=\"-fsanitize=address\" -DCMAKE_SHARED_LINKER_FLAGS=\"-fsanitize=address\"'",
            "make -C build -j2"
        ],
        "compile_flags": {
            "CFLAGS": "-finstrument-functions -g -fsanitize=address -fno-omit-frame-pointer -Wno-error",
            "CXXFLAGS": "-finstrument-functions -g -fsanitize=address -fno-omit-frame-pointer -Wno-error -fpermissive",
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
