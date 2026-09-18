BEGIN {
D["PACKAGE_NAME"]=" \"lame\""
D["PACKAGE_TARNAME"]=" \"lame\""
D["PACKAGE_VERSION"]=" \"3.99.5\""
D["PACKAGE_STRING"]=" \"lame 3.99.5\""
D["PACKAGE_BUGREPORT"]=" \"lame-dev@lists.sf.net\""
D["PACKAGE_URL"]=" \"\""
D["PACKAGE"]=" \"lame\""
D["VERSION"]=" \"3.99.5\""
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
D["__EXTENSIONS__"]=" 1"
D["_ALL_SOURCE"]=" 1"
D["_GNU_SOURCE"]=" 1"
D["_POSIX_PTHREAD_SEMANTICS"]=" 1"
D["_TANDEM_SOURCE"]=" 1"
D["HAVE_DLFCN_H"]=" 1"
D["LT_OBJDIR"]=" \".libs/\""
D["PROTOTYPES"]=" 1"
D["__PROTOTYPES"]=" 1"
D["HAVE_STRING_H"]=" 1"
D["STDC_HEADERS"]=" 1"
D["HAVE_ERRNO_H"]=" 1"
D["HAVE_FCNTL_H"]=" 1"
D["HAVE_LIMITS_H"]=" 1"
D["HAVE_STDINT_H"]=" 1"
D["HAVE_STRING_H"]=" 1"
D["HAVE_SYS_SOUNDCARD_H"]=" 1"
D["HAVE_SYS_TIME_H"]=" 1"
D["HAVE_UNISTD_H"]=" 1"
D["HAVE_XMMINTRIN_H"]=" 1"
D["HAVE_LINUX_SOUNDCARD_H"]=" 1"
D["SIZEOF_SHORT"]=" 2"
D["SIZEOF_UNSIGNED_SHORT"]=" 2"
D["SIZEOF_INT"]=" 4"
D["SIZEOF_UNSIGNED_INT"]=" 4"
D["SIZEOF_LONG"]=" 8"
D["SIZEOF_UNSIGNED_LONG"]=" 8"
D["SIZEOF_LONG_LONG"]=" 8"
D["SIZEOF_UNSIGNED_LONG_LONG"]=" 8"
D["SIZEOF_FLOAT"]=" 4"
D["SIZEOF_DOUBLE"]=" 8"
D["HAVE_LONG_DOUBLE_WIDER"]=" 1"
D["HAVE_LONG_DOUBLE"]=" 1"
D["HAVE_UINT8_T"]=" 1"
D["HAVE_INT8_T"]=" 1"
D["HAVE_UINT16_T"]=" 1"
D["HAVE_INT16_T"]=" 1"
D["HAVE_UINT32_T"]=" 1"
D["HAVE_INT32_T"]=" 1"
D["HAVE_UINT64_T"]=" 1"
D["HAVE_INT64_T"]=" 1"
D["A_UINT32_T"]=" unsigned int"
D["A_INT32_T"]=" int"
D["A_UINT64_T"]=" unsigned long"
D["A_INT64_T"]=" long"
D["HAVE_IEEE854_FLOAT80"]=" 1"
D["LAME_LIBRARY_BUILD"]=" 1"
D["TIME_WITH_SYS_TIME"]=" 1"
D["HAVE_ALLOCA_H"]=" 1"
D["HAVE_ALLOCA"]=" 1"
D["HAVE_GETTIMEOFDAY"]=" 1"
D["HAVE_STRTOL"]=" 1"
D["HAVE_SOCKET"]=" 1"
D["HAVE_TERMCAP_H"]=" 1"
D["ICONV_CONST"]=" "
D["HAVE_MPGLIB"]=" 1"
D["DECODE_ON_THE_FLY"]=" 1"
D["HAVE_TERMCAP"]=" 1"
D["TAKEHIRO_IEEE754_HACK"]=" 1"
D["USE_FAST_LOG"]=" 1"
D["NDEBUG"]=" 1"
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
