/* Type declarations shared with the reproducer */
#pragma once

#include <assert.h>
#include <stdint.h>

#ifndef tmsize_t
typedef long tmsize_t;  // reasonable local stand-in
#endif

// Vulnerable function (keep signature and body, add sink assertion just after the vulnerable read)
