#define HAS_HARNESS_TYPES 1
/* Wrapper: entry_func(...) -> real upstream TIFFSwabArrayOfLong8(...) from libtiff.a */
#include <stdint.h>
#include <stddef.h>
#ifdef HAS_HARNESS_TYPES
#include "harness_types.h"
#endif

extern int TIFFSwabArrayOfLong8(uint64_t *lp, tmsize_t n);

int entry_func(uint64_t *lp, tmsize_t n) {
    TIFFSwabArrayOfLong8(lp,n);
    return 0;
}
