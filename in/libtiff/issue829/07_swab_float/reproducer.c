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

#include <stdlib.h>
#include <stdint.h>

int entry_func(float *fp);

int main() {
    char *buf = (char*)malloc(3); // fewer than 4 bytes so cp[3] is OOB
    if (!buf) return 0;
    { /* replay: concrete values for "buf" (3 bytes) */
  static const unsigned char buf_data[] = {0x00, 0x00, 0x00};
  memcpy(buf, buf_data, (3) < 3 ? (3) : 3);
};

    entry_func((float*)buf);
    return 0;
}
