dnl Process this file with autoconf to produce a configure script.

dnl This is required at the start; the name is the name of a file
dnl it should be seeing, to verify it is in the same directory.

AC_INIT(listtests)

dnl A safety precaution

AC_PREREQ(2.57)

dnl Checks for programs.

AC_PROG_CC

dnl Checks for header files.

AC_CHECK_HEADERS(sys/socket.h)
AC_CHECK_HEADERS(openssl/crypto.h,[CLIENT_SSL=bin/client-ssl])
AC_CHECK_HEADERS(gnutls/gnutls.h,[CLIENT_GNUTLS=bin/client-gnutls])
AC_CHECK_HEADERS(gnutls/gnutls.h,[B64_GNUTLS=bin/ed25519_privkey_pem_to_pubkey_raw_b64])

dnl The check on dynamically loaded modules requires the building of
dnl something to load. This seems to be something that varies between
dnl systems and compilers something awful. Therefore, we enable it only
dnl for those systems and compilers that we know about.

dnl I tried using AC_CANONICAL_HOST, but it insisted on looking for an
dnl "install" script for some weird reason.

host_os=`uname -s`

case $CC-$host_os in
  gcc-*linux* | gcc-*Linux* | gcc-*LINUX* | gcc-FreeBSD)
    LOADED=bin/loaded
    LOADED_OPT="-shared -fPIC"
    echo "Using gcc on $host_os: will compile dynamically loaded module"
    ;;
  *)
    LOADED=
    echo "Will not compile dynamically loaded module: not known OS/CC combination"
    ;;
esac

dnl At least one operating system needs BIND_8_COMPAT to be defined.

case $host_os in
  Darwin)
    BIND_8_COMPAT=-DBIND_8_COMPAT
    ;;
esac

dnl Solaris requires additional libraries for networking functions.

AC_SEARCH_LIBS([inet_addr], [nsl])
AC_SEARCH_LIBS([connect], [socket])
AC_SEARCH_LIBS([inet_pton], [nsl socket resolv])
AC_SEARCH_LIBS([inet_ntop], [nsl socket resolv])

dnl "Export" these variables

AC_SUBST(BIND_8_COMPAT)
AC_SUBST(CLIENT_SSL)
AC_SUBST(CLIENT_GNUTLS)
AC_SUBST(B64_GNUTLS)
AC_SUBST(LOADED)
AC_SUBST(LOADED_OPT)
AC_SUBST(LIBS)

dnl This must be last; it determines what files are written

AC_OUTPUT(Makefile)
