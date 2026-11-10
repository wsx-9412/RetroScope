#define HAS_HARNESS_TYPES 1
/* Wrapper: entry_func(...) -> real upstream TIFFSwabArrayOfFloat(...) from libtiff.a */
#include <stdint.h>
#include <stddef.h>
#ifdef HAS_HARNESS_TYPES
#include "harness_types.h"
#endif

extern int TIFFSwabArrayOfFloat();

int entry_func() {
    TIFFSwabArrayOfFloat();
    return 0;
}
