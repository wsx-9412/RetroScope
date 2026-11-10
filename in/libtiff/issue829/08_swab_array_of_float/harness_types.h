/* Type declarations shared with the reproducer */
#pragma once

#include <assert.h>
#include <stdint.h>
#include <stddef.h>

#ifndef TMSIZE_T_DEFINED
#define TMSIZE_T_DEFINED 1
typedef long tmsize_t;  // reasonable stand-in for libtiff's tmsize_t
#endif

// Minimal neutralized harness containing the vulnerable function verbatim
