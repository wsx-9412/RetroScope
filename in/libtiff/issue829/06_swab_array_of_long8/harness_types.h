/* Type declarations shared with the reproducer */
#pragma once

#include <stdint.h>
#include <assert.h>

#ifndef TMSIZE_T_DEFINED
#define TMSIZE_T_DEFINED
typedef long tmsize_t;  // reasonable stand-in for libtiff's tmsize_t
#endif

