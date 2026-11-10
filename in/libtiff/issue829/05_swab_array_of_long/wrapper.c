#define HAS_HARNESS_TYPES 1
/* Wrapper: entry_func(...) -> real upstream TIFFSwabArrayOfLong(...) from libtiff.a */
#include <stdint.h>
#include <stddef.h>
#ifdef HAS_HARNESS_TYPES
#include "harness_types.h"
#endif

extern int TIFFSwabArrayOfLong(uint32_t *lp, long n);

int entry_func(uint32_t *lp, long n) {
    TIFFSwabArrayOfLong(lp,n);
    return 0;
}
