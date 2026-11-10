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

// Prototype from harness
void TIFFSwabArrayOfFloat(float *fp, tmsize_t n);

int main() {
    // Allocate a too-small buffer (3 bytes) so cp[3] is out-of-bounds
    size_t sz = 3;  // concrete size per instructions
    unsigned char *buf = (unsigned char *)malloc(sz);
    if (!buf) return 0;

    // Make buffer content symbolic (values don't matter for OOB trigger)
    { /* replay: concrete values for "buf3" (3 bytes) */
  static const unsigned char buf3_data[] = {0x00, 0x00, 0x00};
  memcpy(buf, buf3_data, (sz) < 3 ? (sz) : 3);
};

    // Call vulnerable function with n = 1 (process one float)
    TIFFSwabArrayOfFloat((float *)buf, (tmsize_t)1);

    return 0;
}
