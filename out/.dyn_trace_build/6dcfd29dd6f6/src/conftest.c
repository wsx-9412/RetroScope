/* confdefs.h */
#define PACKAGE_NAME "LibTIFF Software"
#define PACKAGE_TARNAME "tiff"
#define PACKAGE_VERSION "4.0.6"
#define PACKAGE_STRING "LibTIFF Software 4.0.6"
#define PACKAGE_BUGREPORT "tiff@lists.maptools.org"
#define PACKAGE_URL ""
#define PACKAGE "tiff"
#define VERSION "4.0.6"
#define STDC_HEADERS 1
#define HAVE_SYS_TYPES_H 1
#define HAVE_SYS_STAT_H 1
#define HAVE_STDLIB_H 1
#define HAVE_STRING_H 1
#define HAVE_MEMORY_H 1
#define HAVE_STRINGS_H 1
#define HAVE_INTTYPES_H 1
#define HAVE_STDINT_H 1
#define HAVE_UNISTD_H 1
#define HAVE_DLFCN_H 1
#define LT_OBJDIR ".libs/"
#define HAVE_ASSERT_H 1
#define HAVE_FCNTL_H 1
#define HAVE_LIMITS_H 1
#define HAVE_MALLOC_H 1
#define HAVE_SEARCH_H 1
#define HAVE_SYS_TIME_H 1
#define HAVE_UNISTD_H 1
#define TIME_WITH_SYS_TIME 1
#define HAVE_FSEEKO 1
#define HAVE_DECL_OPTARG 1
#define SIZEOF_SIGNED_SHORT 2
#define SIZEOF_UNSIGNED_SHORT 2
#define SIZEOF_SIGNED_INT 4
#define SIZEOF_UNSIGNED_INT 4
#define SIZEOF_SIGNED_LONG 8
#define SIZEOF_UNSIGNED_LONG 8
#define SIZEOF_SIGNED_LONG_LONG 8
#define SIZEOF_UNSIGNED_LONG_LONG 8
#define SIZEOF_UNSIGNED_CHAR_P 8
#define SIZEOF_SIZE_T 8
#define TIFF_INT8_T signed char
#define TIFF_UINT8_T unsigned char
#define TIFF_INT16_T signed short
#define TIFF_UINT16_T unsigned short
#define TIFF_INT32_T signed int
#define TIFF_INT32_FORMAT "%d"
#define TIFF_UINT32_T unsigned int
#define TIFF_UINT32_FORMAT "%u"
#define TIFF_INT64_T signed long
#define TIFF_INT64_FORMAT "%ld"
#define TIFF_UINT64_T unsigned long
#define TIFF_UINT64_FORMAT "%lu"
#define TIFF_SIZE_T unsigned long
#define TIFF_SIZE_FORMAT "%lu"
#define TIFF_SSIZE_T signed long
#define TIFF_SSIZE_FORMAT "%ld"
#define TIFF_PTRDIFF_T ptrdiff_t
#define TIFF_PTRDIFF_FORMAT "%ld"
#define HAVE_FLOOR 1
#define HAVE_ISASCII 1
#define HAVE_MEMMOVE 1
#define HAVE_MEMSET 1
#define HAVE_MMAP 1
#define HAVE_POW 1
#define HAVE_SNPRINTF 1
#define HAVE_SQRT 1
#define HAVE_STRCHR 1
#define HAVE_STRRCHR 1
#define HAVE_STRSTR 1
#define HAVE_STRTOL 1
#define HAVE_STRTOUL 1
#define HAVE_STRTOULL 1
/* end confdefs.h.  */
/* Define getopt to an innocuous variant, in case <limits.h> declares getopt.
   For example, HP-UX 11i <limits.h> declares gettimeofday.  */
#define getopt innocuous_getopt

/* System header to define __stub macros and hopefully few prototypes,
    which can conflict with char getopt (); below.
    Prefer <limits.h> to <assert.h> if __STDC__ is defined, since
    <limits.h> exists even on freestanding compilers.  */

#ifdef __STDC__
# include <limits.h>
#else
# include <assert.h>
#endif

#undef getopt

/* Override any GCC internal prototype to avoid an error.
   Use char because int might match the return type of a GCC
   builtin and then its argument prototype would still apply.  */
#ifdef __cplusplus
extern "C"
#endif
char getopt ();
/* The GNU C library defines this for functions which it implements
    to always fail with ENOSYS.  Some functions are actually named
    something starting with __ and the normal name is an alias.  */
#if defined __stub_getopt || defined __stub___getopt
choke me
#endif

int
main ()
{
return getopt ();
  ;
  return 0;
}
