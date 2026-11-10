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

// Match the harness entry function signature (tmsize_t == long in harness)
int entry_func(uint32_t *lp, long n);

int main() {
    // Allocate a too-small buffer (3 bytes) so cp[3] goes OOB
    size_t sz = 3; // concrete size per compilation model
    unsigned char *buf = (unsigned char *)malloc(sz);
    if (!buf) return 0;

    // Make the content symbolic (not strictly necessary, but good practice)
    { /* replay: concrete values for "buf_bytes" (3 bytes) */
  static const unsigned char buf_bytes_data[] = {0x00, 0x00, 0x00};
  memcpy(buf, buf_bytes_data, (sz) < 3 ? (sz) : 3);
};

    // Cast to uint32_t* and call entry; n can be any value, use 1
    uint32_t *lp = (uint32_t *)buf;
    long n = 1;
    entry_func(lp, n);
    return 0;
}
