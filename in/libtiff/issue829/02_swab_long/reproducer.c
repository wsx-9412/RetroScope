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

int swab_entry(uint32_t *lp);

int main() {
    const size_t sz = 3;  // less than 4 to trigger cp[3] OOB
    unsigned char *buf = (unsigned char *)malloc(sz);
    if (!buf) return 0;
    { /* replay: concrete values for "buf" (3 bytes) */
  static const unsigned char buf_data[] = {0x00, 0x00, 0x00};
  memcpy(buf, buf_data, (sz) < 3 ? (sz) : 3);
};

    uint32_t *lp = (uint32_t *)buf;
    return swab_entry(lp);
}
