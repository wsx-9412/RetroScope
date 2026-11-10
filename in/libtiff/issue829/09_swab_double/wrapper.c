#define HAS_HARNESS_TYPES 1
/* Wrapper: entry_func(...) -> real upstream TIFFSwabDouble(...) from libtiff.a */
#include <stdint.h>
#include <stddef.h>
#ifdef HAS_HARNESS_TYPES
#include "harness_types.h"
#endif

extern int TIFFSwabDouble(double *dp);

int entry_func(double *dp) {
    TIFFSwabDouble(dp);
    return 0;
}
