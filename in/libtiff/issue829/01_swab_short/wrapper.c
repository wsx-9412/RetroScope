#define HAS_HARNESS_TYPES 1
/* Wrapper: harness_entry(...) -> real upstream TIFFSwabShort(...) from libtiff.a */
#include <stdint.h>
#include <stddef.h>
#ifdef HAS_HARNESS_TYPES
#include "harness_types.h"
#endif

extern int TIFFSwabShort(uint16_t *wp);

int harness_entry(uint16_t *wp) {
    TIFFSwabShort(wp);
    return 0;
}
