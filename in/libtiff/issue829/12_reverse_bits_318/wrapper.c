#define HAS_HARNESS_TYPES 1
/* Wrapper: entry_func(...) -> real upstream TIFFReverseBits(...) from libtiff.a */
#include <stdint.h>
#include <stddef.h>
#ifdef HAS_HARNESS_TYPES
#include "harness_types.h"
#endif

extern int TIFFReverseBits(uint8_t *cp, tmsize_t n);

int entry_func(uint8_t *cp, tmsize_t n) {
    TIFFReverseBits(cp,n);
    return 0;
}
