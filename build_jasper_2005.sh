#!/bin/bash
# Rebuild jasper 2.0.0-2.0.5 which need jasper.spec.in
cd "$(dirname "$0")/jasper-versions"
for d in jasper-version-2.0.0 jasper-version-2.0.1 jasper-version-2.0.2 jasper-version-2.0.3 jasper-version-2.0.4 jasper-version-2.0.5; do
  v="${d#jasper-version-}"
  if [ -x "$d/build/src/appl/imginfo" ]; then echo "[SKIP] $v"; continue; fi
  echo "[BUILD] $v"
  (
    cd "$d" || exit 1
    rm -rf build && mkdir -p build/cmake/modules
    for m in InSourceBuild Sanitizers EnableAssertions JasOpenGL; do echo '# dummy' > build/cmake/modules/$m.cmake; done
    printf 'prefix=@CMAKE_INSTALL_PREFIX@\nexec_prefix=${prefix}\nlibdir=${exec_prefix}/@CMAKE_INSTALL_LIBDIR@\nincludedir=${prefix}/@CMAKE_INSTALL_INCLUDEDIR@\n\nName: jasper\nDescription: JasPer\nVersion: @PROJECT_VERSION@\nLibs: -L${libdir} -ljasper\nCflags: -I${includedir}\n' > build/jasper.pc.in
    echo 'Summary: JasPer' > build/jasper.spec.in
    echo 'Name: jasper' >> build/jasper.spec.in
    echo 'Version: @PROJECT_VERSION@' >> build/jasper.spec.in
    echo 'Release: 1' >> build/jasper.spec.in
    echo 'License: JasPer' >> build/jasper.spec.in
    cd build || exit 1
    cmake .. -DJAS_ENABLE_LIBJPEG=OFF -DJAS_ENABLE_OPENGL=OFF -DJAS_ENABLE_DOC=OFF -DJAS_ENABLE_AUTOMATIC_DEPENDENCIES=ON -DCMAKE_C_FLAGS='-g -fsanitize=address -fno-omit-frame-pointer -Wno-error' -DCMAKE_EXE_LINKER_FLAGS='-fsanitize=address' > /tmp/jasper_build_$v.log 2>&1 || { echo "[CMAKE-FAIL] $v"; tail -8 /tmp/jasper_build_$v.log; exit 0; }
    make -j4 >> /tmp/jasper_build_$v.log 2>&1 || { echo "[MAKE-FAIL] $v"; tail -8 /tmp/jasper_build_$v.log; exit 0; }
    echo "[OK] $v"
  )
done
echo "[ALL-DONE-2.0.0-5]"
