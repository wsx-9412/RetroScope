#ifdef __STDC__
#include <limits.h>
#else
#include <assert.h>
#endif

int
main()
{
#if defined __stub_sigaction || defined __stub___sigaction
  return 0;
#else
this system have stub
  return 0;
#endif
}
