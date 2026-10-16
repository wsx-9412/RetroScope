/* */
#include <limits.h>
#include <stdint.h>
#include <inttypes.h>

int main(int argc, char** argv)
{
  (void)argv;
#ifndef SIZE_MAX
  return ((int*)(&SIZE_MAX))[argc];
#else
  (void)argc;
  return 0;
#endif
}
