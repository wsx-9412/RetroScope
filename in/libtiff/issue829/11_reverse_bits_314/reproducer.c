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

// entry function from harness
int entry_func(uint8_t *cp, tmsize_t n);

int main() {
    // Concrete allocation as required
    size_t sz = 8;
    uint8_t *buf = (uint8_t*)malloc(sz);
    if (!buf) return 0;
    // Make buffer contents symbolic (not size)
    { /* replay: concrete values for "buf_bytes" (8 bytes) */
  static const unsigned char buf_bytes_data[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  memcpy(buf, buf_bytes_data, (sz) < 8 ? (sz) : 8);
};

    // Set cp to point just past the end to trigger OOB at cp[0]
    uint8_t *cp = buf + sz;  // 1-past-end
    tmsize_t n = 9;          // ensures the for-loop body with cp[0] executes

    // Direct pass-through call
    entry_func(cp, n);
    return 0;
}
