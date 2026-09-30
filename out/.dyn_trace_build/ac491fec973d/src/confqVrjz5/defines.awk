BEGIN {
D["PACKAGE_NAME"]=" \"LibTIFF Software\""
D["PACKAGE_TARNAME"]=" \"tiff\""
D["PACKAGE_VERSION"]=" \"4.0.8\""
D["PACKAGE_STRING"]=" \"LibTIFF Software 4.0.8\""
D["PACKAGE_BUGREPORT"]=" \"tiff@lists.maptools.org\""
D["PACKAGE_URL"]=" \"\""
D["PACKAGE"]=" \"tiff\""
D["VERSION"]=" \"4.0.8\""
D["STDC_HEADERS"]=" 1"
D["HAVE_SYS_TYPES_H"]=" 1"
D["HAVE_SYS_STAT_H"]=" 1"
D["HAVE_STDLIB_H"]=" 1"
D["HAVE_STRING_H"]=" 1"
D["HAVE_MEMORY_H"]=" 1"
D["HAVE_STRINGS_H"]=" 1"
D["HAVE_INTTYPES_H"]=" 1"
D["HAVE_STDINT_H"]=" 1"
D["HAVE_UNISTD_H"]=" 1"
D["HAVE_DLFCN_H"]=" 1"
D["LT_OBJDIR"]=" \".libs/\""
D["HAVE_ASSERT_H"]=" 1"
D["HAVE_FCNTL_H"]=" 1"
D["HAVE_LIMITS_H"]=" 1"
D["HAVE_MALLOC_H"]=" 1"
D["HAVE_SEARCH_H"]=" 1"
D["HAVE_SYS_TIME_H"]=" 1"
D["HAVE_UNISTD_H"]=" 1"
D["TIME_WITH_SYS_TIME"]=" 1"
D["HAVE_FSEEKO"]=" 1"
D["HAVE_DECL_OPTARG"]=" 1"
D["SIZEOF_SIGNED_SHORT"]=" 2"
D["SIZEOF_UNSIGNED_SHORT"]=" 2"
D["SIZEOF_SIGNED_INT"]=" 4"
D["SIZEOF_UNSIGNED_INT"]=" 4"
D["SIZEOF_SIGNED_LONG"]=" 8"
D["SIZEOF_UNSIGNED_LONG"]=" 8"
D["SIZEOF_SIGNED_LONG_LONG"]=" 8"
D["SIZEOF_UNSIGNED_LONG_LONG"]=" 8"
D["SIZEOF_UNSIGNED_CHAR_P"]=" 8"
D["SIZEOF_SIZE_T"]=" 8"
D["TIFF_INT8_T"]=" signed char"
D["TIFF_UINT8_T"]=" unsigned char"
D["TIFF_INT16_T"]=" signed short"
D["TIFF_UINT16_T"]=" unsigned short"
D["TIFF_INT32_T"]=" signed int"
D["TIFF_INT32_FORMAT"]=" \"%d\""
D["TIFF_UINT32_T"]=" unsigned int"
D["TIFF_UINT32_FORMAT"]=" \"%u\""
D["TIFF_INT64_T"]=" signed long"
D["TIFF_INT64_FORMAT"]=" \"%ld\""
D["TIFF_UINT64_T"]=" unsigned long"
D["TIFF_UINT64_FORMAT"]=" \"%lu\""
D["TIFF_SIZE_T"]=" unsigned long"
D["TIFF_SIZE_FORMAT"]=" \"%lu\""
D["TIFF_SSIZE_T"]=" signed long"
D["TIFF_SSIZE_FORMAT"]=" \"%ld\""
D["TIFF_PTRDIFF_T"]=" ptrdiff_t"
D["TIFF_PTRDIFF_FORMAT"]=" \"%ld\""
D["HAVE_FLOOR"]=" 1"
D["HAVE_ISASCII"]=" 1"
D["HAVE_MEMMOVE"]=" 1"
D["HAVE_MEMSET"]=" 1"
D["HAVE_MMAP"]=" 1"
D["HAVE_POW"]=" 1"
D["HAVE_SNPRINTF"]=" 1"
D["HAVE_SQRT"]=" 1"
D["HAVE_STRCHR"]=" 1"
D["HAVE_STRRCHR"]=" 1"
D["HAVE_STRSTR"]=" 1"
D["HAVE_STRTOL"]=" 1"
D["HAVE_STRTOUL"]=" 1"
D["HAVE_STRTOULL"]=" 1"
D["HAVE_GETOPT"]=" 1"
D["HAVE_SNPRINTF"]=" 1"
D["HAVE_STRCASECMP"]=" 1"
D["HAVE_STRTOUL"]=" 1"
D["HAVE_STRTOULL"]=" 1"
D["HAVE_LFIND"]=" 1"
D["HOST_FILLORDER"]=" FILLORDER_LSB2MSB"
D["HOST_BIGENDIAN"]=" 0"
D["HAVE_IEEEFP"]=" 1"
D["CCITT_SUPPORT"]=" 1"
D["PACKBITS_SUPPORT"]=" 1"
D["LZW_SUPPORT"]=" 1"
D["THUNDER_SUPPORT"]=" 1"
D["NEXT_SUPPORT"]=" 1"
D["LOGLUV_SUPPORT"]=" 1"
D["MDI_SUPPORT"]=" 1"
D["ZIP_SUPPORT"]=" 1"
D["PIXARLOG_SUPPORT"]=" 1"
D["CXX_SUPPORT"]=" 1"
D["X_DISPLAY_MISSING"]=" 1"
D["HAVE_PTHREAD"]=" 1"
D["STRIPCHOP_DEFAULT"]=" TIFF_STRIPCHOP"
D["STRIP_SIZE_DEFAULT"]=" 8192"
D["SUBIFD_SUPPORT"]=" 1"
D["DEFAULT_EXTRASAMPLE_AS_ALPHA"]=" 1"
D["CHECK_JPEG_YCBCR_SUBSAMPLING"]=" 1"
  for (key in D) D_is_set[key] = 1
  FS = ""
}
/^[\t ]*#[\t ]*(define|undef)[\t ]+[_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ][_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789]*([\t (]|$)/ {
  line = $ 0
  split(line, arg, " ")
  if (arg[1] == "#") {
    defundef = arg[2]
    mac1 = arg[3]
  } else {
    defundef = substr(arg[1], 2)
    mac1 = arg[2]
  }
  split(mac1, mac2, "(") #)
  macro = mac2[1]
  prefix = substr(line, 1, index(line, defundef) - 1)
  if (D_is_set[macro]) {
    # Preserve the white space surrounding the "#".
    print prefix "define", macro P[macro] D[macro]
    next
  } else {
    # Replace #undef with comments.  This is necessary, for example,
    # in the case of _POSIX_SOURCE, which is predefined and required
    # on some systems where configure will not decide to define it.
    if (defundef == "undef") {
      print "/*", prefix defundef, macro, "*/"
      next
    }
  }
}
{ print }
