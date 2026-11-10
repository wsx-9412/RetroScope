/* Type declarations shared with the reproducer */
#pragma once

#include <stdint.h>
#include <assert.h>

// Minimal local definition; libtiff typically defines tmsize_t as a signed size type
#ifndef TIF_TMSIZE_T_DEFINED
#define TIF_TMSIZE_T_DEFINED 1
typedef long tmsize_t;
#endif

