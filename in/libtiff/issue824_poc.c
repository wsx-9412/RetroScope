#include <stdio.h>
#include <stdlib.h>
#include <tiffio.h>

#define W 64
#define H 4

static int create(const char *fn) {
    TIFF *t = TIFFOpen(fn, "w"); if (!t) return 1;
    TIFFSetField(t, TIFFTAG_IMAGEWIDTH,      W);
    TIFFSetField(t, TIFFTAG_IMAGELENGTH,     H);
    TIFFSetField(t, TIFFTAG_SAMPLESPERPIXEL, 3);     /* stride = 3 */
    TIFFSetField(t, TIFFTAG_BITSPERSAMPLE,   8);
    TIFFSetField(t, TIFFTAG_COMPRESSION,     COMPRESSION_PIXARLOG);
    TIFFSetField(t, TIFFTAG_PHOTOMETRIC,     PHOTOMETRIC_RGB);
    TIFFSetField(t, TIFFTAG_PLANARCONFIG,    PLANARCONFIG_CONTIG);
    TIFFSetField(t, TIFFTAG_ROWSPERSTRIP,    H);
    unsigned char row[W * 3];
    for (int i = 0; i < W * 3; i++) row[i] = (unsigned char)i;
    for (int y = 0; y < H; y++) TIFFWriteScanline(t, row, y, 0);
    TIFFClose(t);
    return 0;
}

int main(void) {
    const char *fn = "/tmp/pixarlog_poc.tif";
    if (create(fn)) return 1;
    TIFF *t = TIFFOpen(fn, "r"); if (!t) return 1;
    TIFFSetField(t, TIFFTAG_PIXARLOGDATAFMT, PIXARLOGDATAFMT_8BITABGR);
    tmsize_t sz = TIFFScanlineSize(t);          /* = W * 3 = 192 */
    unsigned char *buf = malloc(sz);
    for (int y = 0; y < H; y++) TIFFReadScanline(t, buf, y, 0);
    free(buf);
    TIFFClose(t);
    return 0;
}