dnl Process this file with autoconf to produce a configure script.

dnl This is required at the start; the name is the name of a file
dnl it should be seeing, to verify it is in the same directory.

AC_INIT(configure.ac)

dnl Checks for programs.

AC_PROG_CC
AC_PROG_INSTALL

dnl Checks for header files.

AC_HEADER_STDC

dnl Checks for typedefs, structures, and compiler characteristics.

AC_C_CONST
AC_TYPE_SIZE_T

dnl Checks for library functions.

AC_CHECK_FUNCS(bcopy memmove strerror)

AC_SUBST(LFLAGS)

dnl This must be last; it determines what files are written
AC_OUTPUT(Makefile)
