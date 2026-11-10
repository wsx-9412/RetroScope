Heap OOB Write in TIFFReadAndRealloc() -- Proof of Concept
===========================================================

Bug: TIFFReadAndRealloc() does not validate negative return values from the
     read callback, causing a heap-buffer-overflow when bytes_read == -1.

Location: libtiff/tif_read.c:133
Commit  : a94d1ded80b9b46327d3982a3c80043b29f23e2e (upstream master)


CONTENTS
--------
  natural_trigger_local_tcp.c   Self-contained PoC (single C file)
  asan_output.txt               Captured ASAN output from a confirmed run
  README.txt                    This file


HOW TO BUILD
------------
  BUILD=<path-to-libtiff-asan-build>/libtiff

  gcc -g -O0 -fsanitize=address,undefined -pthread \
      natural_trigger_local_tcp.c -o natural_trigger_local \
      -I/usr/include/x86_64-linux-gnu \
      -L$BUILD -ltiff -Wl,-rpath,$BUILD


HOW TO RUN
----------
  ASAN_OPTIONS=detect_leaks=0 \
  LD_LIBRARY_PATH=$BUILD \
  ./natural_trigger_local

  Expected: ASAN reports heap-buffer-overflow at TIFFReadAndRealloc tif_read.c:133


WHAT THE PoC DOES (no external server required)
-----------------------------------------------
  1. Spawns a background thread as a local TCP peer on 127.0.0.1:14759.
  2. Thread sends a valid 200-byte TIFF header (IFD with StripOffsets=200).
  3. Thread waits 300 ms, then closes the socket with SO_LINGER=0 --> TCP RST.
  4. Main thread connects and opens the TIFF stream via TIFFClientOpen() using
     a read callback built on the standard read() syscall.
  5. Forward seek from byte 122 to byte 200 succeeds (78 pad bytes in buffer).
  6. Next read() for strip data blocks until RST fires --> returns -1 (ECONNRESET).
  7. The -1 is passed directly into TIFFReadAndRealloc() --> OOB write.


TRIGGER CONDITION
-----------------
  The read() syscall is the natural trigger: it returns -1 on ECONNRESET.
  No LD_PRELOAD, no filesystem fault injection, no third-party tooling needed.
  This reproduces the exact code path used by stream-backed TIFF consumers
  (e.g. libvips openin_source_read) when a network connection is reset.


SUGGESTED FIX
-------------
  In TIFFReadAndRealloc() (tif_read.c), before line 133:

      bytes_read = (*tif->tif_readproc)(...);
  +   if (bytes_read < 0)
  +       bytes_read = 0;
      already_read += bytes_read;

  After the fix: clean TIFFFillStrip read error, no ASAN OOB write.
