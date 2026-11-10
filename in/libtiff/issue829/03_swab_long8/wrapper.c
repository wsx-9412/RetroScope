#define HAS_HARNESS_TYPES 1
/* Wrapper: entry(...) -> real upstream TIFFSwabLong8(...) from libtiff.a */
#include <stdint.h>
#include <stddef.h>
#ifdef HAS_HARNESS_TYPES
#include "harness_types.h"
#endif

extern int TIFFSwabLong8(uint64_t *lp);

int entry(uint64_t *lp) {
    TIFFSwabLong8(lp);
    return 0;
}
