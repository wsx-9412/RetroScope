/* Type declarations shared with the reproducer */
#pragma once

#include <stdint.h>
#include <stdlib.h>

#ifndef tmsize_t
typedef long tmsize_t;  // reasonable signed size type for libtiff
#endif

// Minimal tables to satisfy references. Contents don't matter for triggering OOB.
static const unsigned char TIFFBitRevTable[256] = {0};
static const unsigned char TIFFNoBitRevTable[256] = {0};

