/*
 * Standalone harness for taintflow / Frida instrumentation.
 * Auto-generated from the same STEP 1/2/3 sections as the afl-untracer harness.
 * Usage: ./standalone <input_file>
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <dlfcn.h>
#include <unistd.h>
#include <sys/stat.h>

/* AFL++ type compatibility */
typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int8_t   s8;
typedef int16_t  s16;
typedef int32_t  s32;
typedef int64_t  s64;

#define FATAL(fmt, ...) do { fprintf(stderr, "FATAL: " fmt "\n", ##__VA_ARGS__); exit(1); } while(0)
#define OKF(fmt, ...) do { fprintf(stderr, "OK: " fmt "\n", ##__VA_ARGS__); } while(0)
#define WARNF(fmt, ...) do { fprintf(stderr, "WARN: " fmt "\n", ##__VA_ARGS__); } while(0)
static int debug = 1;

// --- STEP 1: headers, typedefs, function pointers, helpers ---
// STEP 1 - START
#include <tiffio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

// Function pointer typedefs
typedef TIFF* (*pfn_TIFFClientOpen_t)(const char*, const char*, thandle_t,
    TIFFReadWriteProc, TIFFReadWriteProc, TIFFSeekProc, TIFFCloseProc,
    TIFFSizeProc, TIFFMapFileProc, TIFFUnmapFileProc);
typedef int (*pfn_TIFFSetField_t)(TIFF*, uint32_t, ...);
typedef void (*pfn_TIFFClose_t)(TIFF*);

// Resolved function pointers
static pfn_TIFFClientOpen_t o_TIFFClientOpen;
static pfn_TIFFSetField_t   o_TIFFSetField;
static pfn_TIFFClose_t      o_TIFFClose;

// Input configuration
static u32 use_stdin = 0;    // ALWAYS file-based input (@@)
static u8  buf[1048576];     // Max 1MB input

// --- Dummy I/O callbacks for write-mode TIFFClientOpen ---
// We write to /dev/null effectively; no real I/O needed.

typedef struct {
    uint8_t dummy_buf[4096];
    toff_t  pos;
    toff_t  size;
} MemBuf;

static MemBuf g_membuf;

static tmsize_t _tiff_dummy_read(thandle_t fd, void* buf_arg, tmsize_t size) {
    (void)fd; (void)buf_arg; (void)size;
    return 0;
}

static tmsize_t _tiff_dummy_write(thandle_t fd, void* buf_arg, tmsize_t size) {
    (void)fd; (void)buf_arg;
    /* Pretend write succeeded */
    MemBuf* mb = (MemBuf*)fd;
    mb->pos += size;
    if (mb->pos > mb->size) mb->size = mb->pos;
    return size;
}

static toff_t _tiff_dummy_seek(thandle_t fd, toff_t off, int whence) {
    MemBuf* mb = (MemBuf*)fd;
    switch (whence) {
        case SEEK_SET: mb->pos = off; break;
        case SEEK_CUR: mb->pos += off; break;
        case SEEK_END: mb->pos = mb->size + off; break;
    }
    return mb->pos;
}

static int _tiff_dummy_close(thandle_t fd) {
    (void)fd;
    return 0;
}

static toff_t _tiff_dummy_size(thandle_t fd) {
    MemBuf* mb = (MemBuf*)fd;
    return mb->size;
}
// STEP 1 - END

/* Framework globals */
static u32 len;
static const char *fn;
static u8 *inputfile;
static u8 *file;

static u8 *read_input_file(const char *path, u32 *out_len) {
    FILE *fp = fopen(path, "rb");
    if (!fp) { perror(path); return NULL; }
    struct stat st;
    if (fstat(fileno(fp), &st) != 0) { fclose(fp); return NULL; }
    u32 sz = (u32)st.st_size;
    u8 *data = (u8 *)malloc(sz);
    if (!data) { fclose(fp); return NULL; }
    if (fread(data, 1, sz, fp) != sz) { free(data); fclose(fp); return NULL; }
    fclose(fp);
    *out_len = sz;
    return data;
}

static void fuzz_body(void) {
    
    // STEP 3 - START
    // Need at least 6 bytes: 4 for tag + 2 minimum for value
    if (len < 6) return;

    // Reset dummy membuf state
    memset(&g_membuf, 0, sizeof(g_membuf));

    // Open TIFF in write mode with dummy I/O (no file I/O)
    TIFF *tif = o_TIFFClientOpen(
        "fuzz_mem", "w",
        (thandle_t)&g_membuf,
        _tiff_dummy_read,
        _tiff_dummy_write,
        _tiff_dummy_seek,
        _tiff_dummy_close,
        _tiff_dummy_size,
        NULL, NULL
    );
    if (!tif) return;

    // Parse fuzz input as a sequence of (tag_id, value) records.
    // Each record: 4 bytes tag_id (uint32_t) + 4 bytes value (uint32_t)
    // This allows the fuzzer to exercise many different tags per iteration.
    size_t offset = 0;

    while (offset + 8 <= (size_t)len) {
        uint32_t tag;
        uint32_t val;
        memcpy(&tag, buf + offset, 4);
        memcpy(&val, buf + offset + 4, 4);
        offset += 8;

        // Call TIFFSetField with the fuzz-derived tag and value.
        // TIFFSetField is variadic — for most tags, a single uint32_t
        // is promoted correctly on x86-64. Tags expecting uint16_t
        // receive the low 16 bits due to C integer promotion rules.
        // Tags expecting doubles/pointers will get garbage, which is
        // exactly the kind of edge case we want to fuzz.
        o_TIFFSetField(tif, tag, val);
    }

    // If there are remaining bytes (4-7), try one more tag with partial value
    if (offset + 4 <= (size_t)len) {
        uint32_t tag;
        memcpy(&tag, buf + offset, 4);
        uint32_t partial_val = 0;
        size_t remaining = (size_t)len - offset - 4;
        if (remaining > 4) remaining = 4;
        memcpy(&partial_val, buf + offset + 4, remaining);
        o_TIFFSetField(tif, tag, partial_val);
    }

    o_TIFFClose(tif);
    // STEP 3 - END

}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
        return 1;
    }

    fn = argv[1];
    inputfile = (u8 *)argv[1];
    file = (u8 *)argv[1];

    // --- STEP 2: dlopen/dlsym ---
    // STEP 2 - START
void *dl = dlopen("libtiff.so.6.2.0", RTLD_LAZY);

if (!dl) FATAL("could not load libtiff: %s", dlerror());

o_TIFFClientOpen = (pfn_TIFFClientOpen_t)dlsym(dl, "TIFFClientOpen");
if (!o_TIFFClientOpen) FATAL("could not resolve TIFFClientOpen: %s", dlerror());

o_TIFFSetField = (pfn_TIFFSetField_t)dlsym(dl, "TIFFSetField");
if (!o_TIFFSetField) FATAL("could not resolve TIFFSetField: %s", dlerror());

o_TIFFClose = (pfn_TIFFClose_t)dlsym(dl, "TIFFClose");
if (!o_TIFFClose) FATAL("could not resolve TIFFClose: %s", dlerror());

if (debug) fprintf(stderr, "[HARNESS] libtiff loaded. TIFFClientOpen=%p TIFFSetField=%p TIFFClose=%p\n",
    (void*)o_TIFFClientOpen, (void*)o_TIFFSetField, (void*)o_TIFFClose);
// STEP 2 - END

    u32 file_len = 0;
    u8 *file_data = read_input_file(argv[1], &file_len);
    if (!file_data) {
        fprintf(stderr, "[STANDALONE] Failed to read input file\n");
        return 1;
    }

    if (file_len > sizeof(buf))
        file_len = sizeof(buf);
    memcpy(buf, file_data, file_len);
    len = file_len;
    free(file_data);

    fprintf(stderr, "[STANDALONE] Running fuzz body with %u bytes\n", len);
    fuzz_body();
    fprintf(stderr, "[STANDALONE] Done\n");
    return 0;
}
