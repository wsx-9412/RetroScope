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

int harness_entry(uint16_t *wp);

int main() {
    unsigned char *buf = (unsigned char *)malloc(1);
    if (!buf) return 0;
    { /* replay: concrete values for "buf" (1 bytes) */
  static const unsigned char buf_data[] = {0x00};
  memcpy(buf, buf_data, (1) < 1 ? (1) : 1);
};
    uint16_t *wp = (uint16_t *)buf;
    harness_entry(wp);
    return 0;
}
