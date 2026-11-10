#define HAS_HARNESS_TYPES 1
/* Wrapper: swab_entry(...) -> real upstream TIFFSwabLong(...) from libtiff.a */
#include <stdint.h>
#include <stddef.h>
#ifdef HAS_HARNESS_TYPES
#include "harness_types.h"
#endif

extern int TIFFSwabLong(uint32_t *lp);

int swab_entry(uint32_t *lp) {
    TIFFSwabLong(lp);
    return 0;
}
