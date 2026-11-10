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

int entry_func(uint8_t *cp, tmsize_t n); // from harness

int main() {
    // Allocate a small concrete buffer so that accessing cp[4] goes OOB
    enum { BUF_SZ = 4 }; // only 4 bytes valid, index 0..3
    uint8_t *buf = (uint8_t *)malloc(BUF_SZ);
    if (!buf) return 0;
    { /* replay: concrete values for "buf" (4 bytes) */
  static const unsigned char buf_data[] = {0x00, 0x00, 0x00, 0x00};
  memcpy(buf, buf_data, (BUF_SZ) < 4 ? (BUF_SZ) : 4);
};

    // n controls the branch; make it symbolic but ensure we take n > 8 path
    tmsize_t n;
    { /* replay: concrete values for "n" (8 bytes) */
  static const unsigned char n_data[] = {0x5c, 0x74, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  memcpy(&n, n_data, (sizeof(n)) < 8 ? (sizeof(n)) : 8);
};
    /* klee_assume removed for replay */
    // Also keep n within a sane bound to avoid overflow semantics
    /* klee_assume removed for replay */

    // Direct call into entry (which directly calls TIFFReverseBits)
    entry_func(buf, n);
    return 0;
}
