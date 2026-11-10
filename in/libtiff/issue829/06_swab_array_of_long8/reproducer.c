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

int main() {
    // Allocate fewer than 8 bytes to trigger OOB read at cp[7]
    char *buf = (char *)malloc(7);
    if (!buf) return 0;
    { /* replay: concrete values for "buf" (7 bytes) */
  static const unsigned char buf_data[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  memcpy(buf, buf_data, (7) < 7 ? (7) : 7);
};

    // Cast to expected type; function immediately casts back to unsigned char*
    uint64_t *lp = (uint64_t *)buf;

    tmsize_t n = 1; // process exactly one element
    entry_func(lp, n);
    return 0;
}
