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
#include <stdint.h>
#include <stdlib.h>

// entry from harness
int harness_entry(double *dp, tmsize_t n);

int main() {
    // Allocate an undersized buffer (< 8 bytes) so cp[7] is OOB
    size_t small = 4;  // concrete size as required
    unsigned char *raw = (unsigned char *)malloc(small);
    { /* replay: concrete values for "raw" (4 bytes) */
  static const unsigned char raw_data[] = {0x00, 0x00, 0x00, 0x00};
  memcpy(raw, raw_data, (small) < 4 ? (small) : 4);
};

    double *dp = (double *)raw;  // intentionally mis-sized
    tmsize_t n = 1;               // ensure loop runs once

    // Call entry (direct pass-through to vulnerable function)
    harness_entry(dp, n);
    return 0;
}
