#!/bin/bash
cd "$(dirname "$0")/jasper-versions"
MODS=/tmp/jasper-modules
for d in jasper-version-4.2.*; do
  v="${d#jasper-version-}"
  if [ -x "/tmp/jb-$v/src/appl/imginfo" ]; then echo "[SKIP] $v"; continue; fi
  echo "[BUILD] $v"
  (
    cd "$d" || exit 1
    mkdir -p build/cmake/modules build/cmake/src build/pkgconfig
    cp $MODS/InSourceBuild.cmake $MODS/EnableAssertions.cmake $MODS/Sanitizers.cmake $MODS/JasCheckType.cmake $MODS/JasGetIncludes.cmake $MODS/JasGetStdcVersion.cmake build/cmake/modules/
    cp $MODS/print_stdc.c build/cmake/src/
    printf 'prefix=@CMAKE_INSTALL_PREFIX@\nexec_prefix=${prefix}\nlibdir=${exec_prefix}/@CMAKE_INSTALL_LIBDIR@\nincludedir=${prefix}/@CMAKE_INSTALL_INCLUDEDIR@\n\nName: jasper\nDescription: JasPer\nVersion: @PROJECT_VERSION@\nLibs: -L${libdir} -ljasper\nCflags: -I${includedir}\n' > build/pkgconfig/jasper.pc.in
    bdir="/tmp/jb-$v"
    rm -rf "$bdir" && mkdir -p "$bdir"
    cd "$bdir" || exit 1
    cmake "$OLDPWD" -DJAS_ENABLE_LIBJPEG=OFF -DJAS_ENABLE_OPENGL=OFF -DJAS_ENABLE_DOC=OFF -DJAS_ENABLE_AUTOMATIC_DEPENDENCIES=ON -DCMAKE_C_FLAGS='-g -fsanitize=address -fno-omit-frame-pointer -Wno-error' -DCMAKE_EXE_LINKER_FLAGS='-fsanitize=address' > /tmp/jasper_build_$v.log 2>&1 || { echo "[CMAKE-FAIL] $v"; tail -10 /tmp/jasper_build_$v.log; exit 0; }
    make -j4 >> /tmp/jasper_build_$v.log 2>&1 || { echo "[MAKE-FAIL] $v"; tail -10 /tmp/jasper_build_$v.log; exit 0; }
    echo "[OK] $v"
  )
done
echo "[ALL-DONE-4.2]"
