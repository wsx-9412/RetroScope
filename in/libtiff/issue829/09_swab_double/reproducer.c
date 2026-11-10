/*
 * Standalone reproducer — build with ASan.
 * Standalone reproducer for ASan validation.
 */
/* Standalone reproducer driver
 *
 * Compile with ASan: gcc -fsanitize=address -g -O0 replay_driver.c ... -o replay
 */
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "harness_types.h"

#include <stdlib.h>
#include <stdint.h>

int entry_func(double *dp);

int main() {
    // Allocate a too-small buffer to trigger OOB read at cp[7]
    const size_t sz = 4;  // concrete size < 8
    unsigned char *buf = (unsigned char *)malloc(sz);
    if (!buf) return 0;

    // Make content symbolic (not required for OOB, but fine)
    { /* replay: concrete values for "buf_bytes" (4 bytes) */
  static const unsigned char buf_bytes_data[] = {0x00, 0x00, 0x00, 0x00};
  memcpy(buf, buf_bytes_data, (sz) < 4 ? (sz) : 4);
};

    // Cast to double* as expected by entry_func/TIFFSwabDouble
    double *dp = (double *)buf;

    // Direct call to entry
    entry_func(dp);
    return 0;
}
