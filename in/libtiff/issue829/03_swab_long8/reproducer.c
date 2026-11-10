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

// entry is defined in harness/tif_swab.c
int entry(uint64_t *lp);

int main() {
    // Allocate fewer than 8 bytes so that cp[7] is out-of-bounds
    const size_t sz = 7;  // concrete size per instructions
    unsigned char *buf = (unsigned char *)malloc(sz);
    if (!buf) return 0;

    // Make buffer content symbolic
    { /* replay: concrete values for "buf" (7 bytes) */
  static const unsigned char buf_data[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  memcpy(buf, buf_data, (sz) < 7 ? (sz) : 7);
};

    // Call entry with the under-sized buffer
    entry((uint64_t *)buf);
    return 0;
}
