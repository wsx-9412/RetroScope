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
// NO_HARNESS_TYPES
#include <stdint.h>
#include <stdlib.h>

#ifndef tmsize_t
typedef long tmsize_t;
#endif

extern int harness_entry(uint16_t *wp, tmsize_t n);

int main() {
    // Allocate a 1-byte buffer so cp[1] is out-of-bounds when n > 0
    unsigned char *raw = (unsigned char *)malloc(1);
    if (!raw) return 0;
    { /* replay: concrete values for "raw_buf" (1 bytes) */
  static const unsigned char raw_buf_data[] = {0x00};
  memcpy(raw, raw_buf_data, (1) < 1 ? (1) : 1);
};

    uint16_t *wp = (uint16_t *)raw; // Intentionally mis-sized to trigger OOB on cp[1]
    tmsize_t n = 1;                 // Ensure the loop executes once

    harness_entry(wp, n);
    return 0;
}
