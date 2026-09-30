/* confdefs.h */
#define PACKAGE_NAME "LibTIFF Software"
#define PACKAGE_TARNAME "tiff"
#define PACKAGE_VERSION "4.0.8"
#define PACKAGE_STRING "LibTIFF Software 4.0.8"
#define PACKAGE_BUGREPORT "tiff@lists.maptools.org"
#define PACKAGE_URL ""
#define PACKAGE "tiff"
#define VERSION "4.0.8"
/* end confdefs.h.  */
#include <stdarg.h>
#include <stdio.h>
struct stat;
/* Most of the following tests are stolen from RCS 5.7's src/conf.sh.  */
struct buf { int x; };
FILE * (*rcsopen) (struct buf *, struct stat *, int);
static char *e (p, i)
     char **p;
     int i;
{
  return p[i];
}
static char *f (char * (*g) (char **, int), char **p, ...)
{
  char *s;
  va_list v;
  va_start (v,p);
  s = g (p, va_arg (v,int));
  va_end (v);
  return s;
}

/* OSF 4.0 Compaq cc is some sort of almost-ANSI by default.  It has
   function prototypes and stuff, but not '\xHH' hex character constants.
   These don't provoke an error unfortunately, instead are silently treated
   as 'x'.  The following induces an error, until -std is added to get
   proper ANSI mode.  Curiously '\x00'!='x' always comes out true, for an
   array size at least.  It's necessary to write '\x00'==0 to get something
   that's true only with -std.  */
int osf4_cc_array ['\x00' == 0 ? 1 : -1];

/* IBM C 6 for AIX is almost-ANSI by default, but it replaces macro parameters
   inside strings and character constants.  */
#define FOO(x) 'x'
int xlc6_cc_array[FOO(a) == 'x' ? 1 : -1];

int test (int i, double x);
struct s1 {int (*f) (int a);};
struct s2 {int (*f) (double a);};
int pairnames (int, char **, FILE *(*)(struct buf *, struct stat *, int), int, int);
int argc;
char **argv;
int
main ()
{
return f (e, argv, 0) != argv[0]  ||  f (e, argv, 1) != argv[1];
  ;
  return 0;
}
