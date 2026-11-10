#define HAS_HARNESS_TYPES 1
/* Wrapper: entry_func(...) -> real upstream TIFFSwabFloat(...) from libtiff.a */
#include <stdint.h>
#include <stddef.h>
#ifdef HAS_HARNESS_TYPES
#include "harness_types.h"
#endif

extern int TIFFSwabFloat(float *fp);

int entry_func(float *fp) {
    TIFFSwabFloat(fp);
    return 0;
}
