#define HAS_HARNESS_TYPES 1
/* Wrapper: harness_entry(...) -> real upstream TIFFSwabArrayOfDouble(...) from libtiff.a */
#include <stdint.h>
#include <stddef.h>
#ifdef HAS_HARNESS_TYPES
#include "harness_types.h"
#endif

extern int TIFFSwabArrayOfDouble(double *dp, tmsize_t n);

int harness_entry(double *dp, tmsize_t n) {
    TIFFSwabArrayOfDouble(dp,n);
    return 0;
}
