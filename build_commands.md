# RetroScope build command documentation

Unified environment: Ubuntu 22.04, gcc 11.4.0. All builds enable ASAN (-fsanitize=address) so PoC crashes can be detected.
Compile only, do not install. The location of each program's executable is described in each section.


# tiff
## tiff-3.9.3

- Status: success
- Commands:
```bash
sh ./configure CFLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" LDFLAGS="-fsanitize=address" --disable-shared && make -j2
```
- Main programs: (see tools/, frontend/, test/ etc. in the source tree)

## tiff-3.9.4

- Status: success
- Commands:
```bash
sh ./configure CFLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" LDFLAGS="-fsanitize=address" --disable-shared && make -j2
```
- Main programs: (see tools/, frontend/, test/ etc. in the source tree)

## tiff-3.9.5

- Status: success
- Commands:
```bash
sh ./configure CFLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" LDFLAGS="-fsanitize=address" --disable-shared && make -j2
```
- Main programs: (see tools/, frontend/, test/ etc. in the source tree)

## tiff-4.0.0

- Status: success
- Commands:
```bash
sh ./configure CFLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" LDFLAGS="-fsanitize=address" --disable-shared && make -j2
```
- Main programs: (see tools/, frontend/, test/ etc. in the source tree)

## tiff-4.0.1

- Status: success
- Commands:
```bash
sh ./configure CFLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" LDFLAGS="-fsanitize=address" --disable-shared && make -j2
```
- Main programs: (see tools/, frontend/, test/ etc. in the source tree)

## tiff-4.0.10

- Status: success
- Commands:
```bash
sh ./configure CFLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" LDFLAGS="-fsanitize=address" --disable-shared && make -j2
```
- Main programs: (see tools/, frontend/, test/ etc. in the source tree)

## tiff-4.0.2

- Status: success
- Commands:
```bash
sh ./configure CFLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" LDFLAGS="-fsanitize=address" --disable-shared && make -j2
```
- Main programs: (see tools/, frontend/, test/ etc. in the source tree)

## tiff-4.0.3

- Status: success
- Commands:
```bash
sh ./configure CFLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" LDFLAGS="-fsanitize=address" --disable-shared && make -j2
```
- Main programs: (see tools/, frontend/, test/ etc. in the source tree)

## tiff-4.0.4

- Status: success
- Commands:
```bash
sh ./configure CFLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" LDFLAGS="-fsanitize=address" --disable-shared && make -j2
```
- Main programs: (see tools/, frontend/, test/ etc. in the source tree)

## tiff-4.0.4beta

- Status: success
- Commands:
```bash
sh ./configure CFLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" LDFLAGS="-fsanitize=address" --disable-shared && make -j2
```
- Main programs: (see tools/, frontend/, test/ etc. in the source tree)

## tiff-4.0.5

- Status: success
- Commands:
```bash
sh ./configure CFLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" LDFLAGS="-fsanitize=address" --disable-shared && make -j2
```
- Main programs: (see tools/, frontend/, test/ etc. in the source tree)

## tiff-4.0.6

- Status: success
- Commands:
```bash
sh ./configure CFLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" LDFLAGS="-fsanitize=address" --disable-shared && make -j2
```
- Main programs: (see tools/, frontend/, test/ etc. in the source tree)

## tiff-4.0.7

- Status: success
- Commands:
```bash
sh ./configure CFLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" LDFLAGS="-fsanitize=address" --disable-shared && make -j2
```
- Main programs: (see tools/, frontend/, test/ etc. in the source tree)

## tiff-4.0.8

- Status: success
- Commands:
```bash
sh ./configure CFLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" LDFLAGS="-fsanitize=address" --disable-shared && make -j2
```
- Main programs: (see tools/, frontend/, test/ etc. in the source tree)

## tiff-4.0.9

- Status: success
- Commands:
```bash
sh ./configure CFLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" LDFLAGS="-fsanitize=address" --disable-shared && make -j2
```
- Main programs: (see tools/, frontend/, test/ etc. in the source tree)

## tiff-4.1.0

- Status: success
- Commands:
```bash
sh ./configure CFLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" LDFLAGS="-fsanitize=address" --disable-shared && make -j2
```
- Main programs: (see tools/, frontend/, test/ etc. in the source tree)

## tiff-4.2.0

- Status: success
- Commands:
```bash
sh ./configure CFLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" LDFLAGS="-fsanitize=address" --disable-shared && make -j2
```
- Main programs: (see tools/, frontend/, test/ etc. in the source tree)

## tiff-4.3.0

- Status: success
- Commands:
```bash
sh ./configure CFLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" LDFLAGS="-fsanitize=address" --disable-shared && make -j2
```
- Main programs: (see tools/, frontend/, test/ etc. in the source tree)

## tiff-4.4.0

- Status: success
- Commands:
```bash
sh ./configure CFLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" LDFLAGS="-fsanitize=address" --disable-shared && make -j2
```
- Main programs: (see tools/, frontend/, test/ etc. in the source tree)

## tiff-4.5.0

- Status: success
- Commands:
```bash
sh ./configure CFLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" LDFLAGS="-fsanitize=address" --disable-shared && make -j2
```
- Main programs: (see tools/, frontend/, test/ etc. in the source tree)

## tiff-4.5.1

- Status: success
- Commands:
```bash
sh ./configure CFLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" LDFLAGS="-fsanitize=address" --disable-shared && make -j2
```
- Main programs: (see tools/, frontend/, test/ etc. in the source tree)

## tiff-4.6.0

- Status: success
- Commands:
```bash
sh ./configure CFLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" LDFLAGS="-fsanitize=address" --disable-shared && make -j2
```
- Main programs: (see tools/, frontend/, test/ etc. in the source tree)

## tiff-4.7.0

- Status: success
- Commands:
```bash
sh ./configure CFLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" LDFLAGS="-fsanitize=address" --disable-shared && make -j2
```
- Main programs: (see tools/, frontend/, test/ etc. in the source tree)


# jasper
## jasper-version-1.900.10

- Status: skipped: build system not found
- Commands:
```bash
-
```

## jasper-version-1.900.11

- Status: skipped: build system not found
- Commands:
```bash
-
```

## jasper-version-1.900.12

- Status: skipped: build system not found
- Commands:
```bash
-
```

## jasper-version-1.900.13

- Status: skipped: build system not found
- Commands:
```bash
-
```

## jasper-version-1.900.14

- Status: skipped: build system not found
- Commands:
```bash
-
```

## jasper-version-1.900.15

- Status: skipped: build system not found
- Commands:
```bash
-
```

## jasper-version-1.900.16

- Status: skipped: build system not found
- Commands:
```bash
-
```

## jasper-version-1.900.17

- Status: skipped: build system not found
- Commands:
```bash
-
```

## jasper-version-1.900.18

- Status: skipped: build system not found
- Commands:
```bash
-
```

## jasper-version-1.900.19

- Status: skipped: build system not found
- Commands:
```bash
-
```

## jasper-version-1.900.20

- Status: skipped: build system not found
- Commands:
```bash
-
```

## jasper-version-1.900.21

- Status: skipped: build system not found
- Commands:
```bash
-
```

## jasper-version-1.900.22

- Status: skipped: build system not found
- Commands:
```bash
-
```

## jasper-version-1.900.23

- Status: skipped: build system not found
- Commands:
```bash
-
```

## jasper-version-1.900.24

- Status: skipped: build system not found
- Commands:
```bash
-
```

## jasper-version-1.900.25

- Status: skipped: build system not found
- Commands:
```bash
-
```

## jasper-version-1.900.26

- Status: skipped: build system not found
- Commands:
```bash
-
```

## jasper-version-1.900.27

- Status: skipped: build system not found
- Commands:
```bash
-
```

## jasper-version-1.900.28

- Status: skipped: build system not found
- Commands:
```bash
-
```

## jasper-version-1.900.29

- Status: skipped: build system not found
- Commands:
```bash
-
```

## jasper-version-1.900.30

- Status: skipped: build system not found
- Commands:
```bash
-
```

## jasper-version-1.900.31

- Status: skipped: build system not found
- Commands:
```bash
-
```

## jasper-version-1.900.8

- Status: skipped: build system not found
- Commands:
```bash
-
```

## jasper-version-1.900.9

- Status: skipped: build system not found
- Commands:
```bash
-
```

## jasper-version-2.0.0

- Status: failed (see cmake.log/make.log in the directory)
- Commands:
```bash
mkdir -p build && cd build && cmake .. -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address" && make -j2
```

## jasper-version-2.0.1

- Status: failed (see cmake.log/make.log in the directory)
- Commands:
```bash
mkdir -p build && cd build && cmake .. -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address" && make -j2
```

## jasper-version-2.0.10

- Status: failed (see cmake.log/make.log in the directory)
- Commands:
```bash
mkdir -p build && cd build && cmake .. -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address" && make -j2
```

## jasper-version-2.0.11

- Status: failed (see cmake.log/make.log in the directory)
- Commands:
```bash
mkdir -p build && cd build && cmake .. -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address" && make -j2
```

## jasper-version-2.0.12

- Status: failed (see cmake.log/make.log in the directory)
- Commands:
```bash
mkdir -p build && cd build && cmake .. -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address" && make -j2
```

## jasper-version-2.0.13

- Status: failed (see cmake.log/make.log in the directory)
- Commands:
```bash
mkdir -p build && cd build && cmake .. -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address" && make -j2
```

## jasper-version-2.0.14

- Status: failed (see cmake.log/make.log in the directory)
- Commands:
```bash
mkdir -p build && cd build && cmake .. -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address" && make -j2
```

## jasper-version-2.0.15

- Status: failed (see cmake.log/make.log in the directory)
- Commands:
```bash
mkdir -p build && cd build && cmake .. -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address" && make -j2
```

## jasper-version-2.0.16

- Status: failed (see cmake.log/make.log in the directory)
- Commands:
```bash
mkdir -p build && cd build && cmake .. -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address" && make -j2
```

## jasper-version-2.0.17

- Status: failed (see cmake.log/make.log in the directory)
- Commands:
```bash
mkdir -p build && cd build && cmake .. -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address" && make -j2
```

## jasper-version-2.0.19

- Status: failed (see cmake.log/make.log in the directory)
- Commands:
```bash
mkdir -p build && cd build && cmake .. -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address" && make -j2
```

## jasper-version-2.0.2

- Status: failed (see cmake.log/make.log in the directory)
- Commands:
```bash
mkdir -p build && cd build && cmake .. -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address" && make -j2
```

## jasper-version-2.0.20

- Status: failed (see cmake.log/make.log in the directory)
- Commands:
```bash
mkdir -p build && cd build && cmake .. -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address" && make -j2
```

## jasper-version-2.0.21

- Status: failed (see cmake.log/make.log in the directory)
- Commands:
```bash
mkdir -p build && cd build && cmake .. -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address" && make -j2
```

## jasper-version-2.0.22

- Status: failed (see cmake.log/make.log in the directory)
- Commands:
```bash
mkdir -p build && cd build && cmake .. -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address" && make -j2
```

## jasper-version-2.0.23

- Status: failed (see cmake.log/make.log in the directory)
- Commands:
```bash
mkdir -p build && cd build && cmake .. -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address" && make -j2
```

## jasper-version-2.0.24

- Status: failed (see cmake.log/make.log in the directory)
- Commands:
```bash
mkdir -p build && cd build && cmake .. -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address" && make -j2
```

## jasper-version-2.0.25

- Status: failed (see cmake.log/make.log in the directory)
- Commands:
```bash
mkdir -p build && cd build && cmake .. -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address" && make -j2
```

## jasper-version-2.0.26

- Status: failed (see cmake.log/make.log in the directory)
- Commands:
```bash
mkdir -p build && cd build && cmake .. -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address" && make -j2
```

## jasper-version-2.0.27

- Status: failed (see cmake.log/make.log in the directory)
- Commands:
```bash
mkdir -p build && cd build && cmake .. -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address" && make -j2
```

## jasper-version-2.0.28

- Status: failed (see cmake.log/make.log in the directory)
- Commands:
```bash
mkdir -p build && cd build && cmake .. -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address" && make -j2
```

## jasper-version-2.0.29

- Status: failed (see cmake.log/make.log in the directory)
- Commands:
```bash
mkdir -p build && cd build && cmake .. -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address" && make -j2
```

## jasper-version-2.0.3

- Status: failed (see cmake.log/make.log in the directory)
- Commands:
```bash
mkdir -p build && cd build && cmake .. -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address" && make -j2
```

## jasper-version-2.0.31

- Status: failed (see cmake.log/make.log in the directory)
- Commands:
```bash
mkdir -p build && cd build && cmake .. -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address" && make -j2
```

## jasper-version-2.0.32

- Status: failed (see cmake.log/make.log in the directory)
- Commands:
```bash
mkdir -p build && cd build && cmake .. -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address" && make -j2
```

## jasper-version-2.0.33

- Status: failed (see cmake.log/make.log in the directory)
- Commands:
```bash
mkdir -p build && cd build && cmake .. -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address" && make -j2
```

## jasper-version-2.0.4

- Status: failed (see cmake.log/make.log in the directory)
- Commands:
```bash
mkdir -p build && cd build && cmake .. -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address" && make -j2
```

## jasper-version-2.0.5

- Status: failed (see cmake.log/make.log in the directory)
- Commands:
```bash
mkdir -p build && cd build && cmake .. -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address" && make -j2
```

## jasper-version-2.0.6

- Status: failed (see cmake.log/make.log in the directory)
- Commands:
```bash
mkdir -p build && cd build && cmake .. -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address" && make -j2
```

## jasper-version-2.0.7

- Status: failed (see cmake.log/make.log in the directory)
- Commands:
```bash
mkdir -p build && cd build && cmake .. -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address" && make -j2
```

## jasper-version-2.0.8

- Status: failed (see cmake.log/make.log in the directory)
- Commands:
```bash
mkdir -p build && cd build && cmake .. -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address" && make -j2
```

## jasper-version-2.0.9

- Status: failed (see cmake.log/make.log in the directory)
- Commands:
```bash
mkdir -p build && cd build && cmake .. -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address" && make -j2
```

## jasper-version-3.0.0

- Status: failed (see cmake.log/make.log in the directory)
- Commands:
```bash
mkdir -p build && cd build && cmake .. -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address" && make -j2
```

## jasper-version-3.0.1

- Status: failed (see cmake.log/make.log in the directory)
- Commands:
```bash
mkdir -p build && cd build && cmake .. -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address" && make -j2
```

## jasper-version-3.0.2

- Status: failed (see cmake.log/make.log in the directory)
- Commands:
```bash
mkdir -p build && cd build && cmake .. -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address" && make -j2
```

## jasper-version-3.0.3

- Status: failed (see cmake.log/make.log in the directory)
- Commands:
```bash
mkdir -p build && cd build && cmake .. -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address" && make -j2
```

## jasper-version-3.0.4

- Status: failed (see cmake.log/make.log in the directory)
- Commands:
```bash
mkdir -p build && cd build && cmake .. -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address" && make -j2
```

## jasper-version-3.0.5

- Status: failed (see cmake.log/make.log in the directory)
- Commands:
```bash
mkdir -p build && cd build && cmake .. -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address" && make -j2
```

## jasper-version-3.0.6

- Status: failed (see cmake.log/make.log in the directory)
- Commands:
```bash
mkdir -p build && cd build && cmake .. -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address" && make -j2
```

## jasper-version-4.0.0

- Status: failed (see cmake.log/make.log in the directory)
- Commands:
```bash
mkdir -p build && cd build && cmake .. -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address" && make -j2
```

## jasper-version-4.0.1

- Status: failed (see cmake.log/make.log in the directory)
- Commands:
```bash
mkdir -p build && cd build && cmake .. -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address" && make -j2
```

## jasper-version-4.1.0

- Status: failed (see cmake.log/make.log in the directory)
- Commands:
```bash
mkdir -p build && cd build && cmake .. -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address" && make -j2
```

## jasper-version-4.1.1

- Status: failed (see cmake.log/make.log in the directory)
- Commands:
```bash
mkdir -p build && cd build && cmake .. -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address" && make -j2
```

## jasper-version-4.1.2

- Status: failed (see cmake.log/make.log in the directory)
- Commands:
```bash
mkdir -p build && cd build && cmake .. -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address" && make -j2
```

## jasper-version-4.2.0

- Status: failed (see cmake.log/make.log in the directory)
- Commands:
```bash
mkdir -p build && cd build && cmake .. -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address" && make -j2
```

## jasper-version-4.2.1

- Status: failed (see cmake.log/make.log in the directory)
- Commands:
```bash
mkdir -p build && cd build && cmake .. -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address" && make -j2
```

## jasper-version-4.2.2

- Status: failed (see cmake.log/make.log in the directory)
- Commands:
```bash
mkdir -p build && cd build && cmake .. -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address" && make -j2
```

## jasper-version-4.2.3

- Status: failed (see cmake.log/make.log in the directory)
- Commands:
```bash
mkdir -p build && cd build && cmake .. -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address" && make -j2
```

## jasper-version-4.2.4

- Status: failed (see cmake.log/make.log in the directory)
- Commands:
```bash
mkdir -p build && cd build && cmake .. -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address" && make -j2
```

## jasper-version-4.2.5

- Status: failed (see cmake.log/make.log in the directory)
- Commands:
```bash
mkdir -p build && cd build && cmake .. -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address" && make -j2
```

## jasper-version-4.2.6

- Status: failed (see cmake.log/make.log in the directory)
- Commands:
```bash
mkdir -p build && cd build && cmake .. -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address" && make -j2
```

## jasper-version-4.2.7

- Status: failed (see cmake.log/make.log in the directory)
- Commands:
```bash
mkdir -p build && cd build && cmake .. -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address" && make -j2
```

## jasper-version-4.2.8

- Status: failed (see cmake.log/make.log in the directory)
- Commands:
```bash
mkdir -p build && cd build && cmake .. -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address" && make -j2
```

## jasper-version-4.2.9

- Status: failed (see cmake.log/make.log in the directory)
- Commands:
```bash
mkdir -p build && cd build && cmake .. -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address" && make -j2
```


# audiofile
## audiofile-0.2.7

- Status: success
- Commands:
```bash
sh ./configure CFLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" LDFLAGS="-fsanitize=address" --disable-shared && make -j2
```
- Main programs: (see tools/, frontend/, test/ etc. in the source tree)

## audiofile-0.3.0

- Status: failed (see configure.log/make.log in the directory)
- Commands:
```bash
sh ./configure CFLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" LDFLAGS="-fsanitize=address" --disable-shared && make -j2
```

## audiofile-0.3.1

- Status: failed (see configure.log/make.log in the directory)
- Commands:
```bash
sh ./configure CFLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" LDFLAGS="-fsanitize=address" --disable-shared && make -j2
```

## audiofile-0.3.2

- Status: failed (see configure.log/make.log in the directory)
- Commands:
```bash
sh ./configure CFLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" LDFLAGS="-fsanitize=address" --disable-shared && make -j2
```

## audiofile-0.3.3

- Status: failed (see configure.log/make.log in the directory)
- Commands:
```bash
sh ./configure CFLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" LDFLAGS="-fsanitize=address" --disable-shared && make -j2
```

## audiofile-0.3.4

- Status: failed (see configure.log/make.log in the directory)
- Commands:
```bash
sh ./configure CFLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" LDFLAGS="-fsanitize=address" --disable-shared && make -j2
```


# lame
## lame-3.97

- Status: success
- Commands:
```bash
sh ./configure CFLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" LDFLAGS="-fsanitize=address" --disable-shared --disable-frontend=no && make -j2
```
- Main programs: (see tools/, frontend/, test/ etc. in the source tree)

## lame-3.98.2

- Status: success
- Commands:
```bash
sh ./configure CFLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" LDFLAGS="-fsanitize=address" --disable-shared --disable-frontend=no && make -j2
```
- Main programs: (see tools/, frontend/, test/ etc. in the source tree)

## lame-3.98.4

- Status: success
- Commands:
```bash
sh ./configure CFLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" LDFLAGS="-fsanitize=address" --disable-shared --disable-frontend=no && make -j2
```
- Main programs: (see tools/, frontend/, test/ etc. in the source tree)


# Corrections (final commands for specially-handled versions)
## jasper-version-1.900.10

- Status: success (requires autoreconf first to generate configure)
- Commands:
```bash
autoreconf -fi
sh ./configure CFLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" LDFLAGS="-fsanitize=address" --disable-shared && make -j2
```
- Programs: src/appl/jasper, src/appl/imginfo

## jasper-version-1.900.11

- Status: success (requires autoreconf first to generate configure)
- Commands:
```bash
autoreconf -fi
sh ./configure CFLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" LDFLAGS="-fsanitize=address" --disable-shared && make -j2
```
- Programs: src/appl/jasper, src/appl/imginfo

## jasper-version-1.900.12

- Status: success (requires autoreconf first to generate configure)
- Commands:
```bash
autoreconf -fi
sh ./configure CFLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" LDFLAGS="-fsanitize=address" --disable-shared && make -j2
```
- Programs: src/appl/jasper, src/appl/imginfo

## jasper-version-1.900.13

- Status: success (requires autoreconf first to generate configure)
- Commands:
```bash
autoreconf -fi
sh ./configure CFLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" LDFLAGS="-fsanitize=address" --disable-shared && make -j2
```
- Programs: src/appl/jasper, src/appl/imginfo

## jasper-version-1.900.14

- Status: success (requires autoreconf first to generate configure)
- Commands:
```bash
autoreconf -fi
sh ./configure CFLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" LDFLAGS="-fsanitize=address" --disable-shared && make -j2
```
- Programs: src/appl/jasper, src/appl/imginfo

## jasper-version-1.900.15

- Status: success (requires autoreconf first to generate configure)
- Commands:
```bash
autoreconf -fi
sh ./configure CFLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" LDFLAGS="-fsanitize=address" --disable-shared && make -j2
```
- Programs: src/appl/jasper, src/appl/imginfo

