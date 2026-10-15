/* */
#include <stdlib.h>

int main(int argc, char** argv)
{
  (void)argv;
#ifndef posix_memalign
  return ((int*)(&posix_memalign))[argc];
#else
  (void)argc;
  return 0;
#endif
}
