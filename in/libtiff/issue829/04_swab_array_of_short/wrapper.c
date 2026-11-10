/* Wrapper: harness_entry(uint16_t *wp, tmsize_t n) -> real upstream TIFFSwabArrayOfShort */
#include <stdint.h>
#include <stddef.h>
#include "harness_types.h"

extern void TIFFSwabArrayOfShort(uint16_t *wp, tmsize_t n);

int harness_entry(uint16_t *wp, tmsize_t n) {
    TIFFSwabArrayOfShort(wp, n);
    return 0;
}
