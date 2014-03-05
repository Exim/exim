/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2012 */
/* See the file NOTICE for conditions of use and distribution. */

/* This module provides TLS (aka SSL) support for Exim. The code for OpenSSL is
based on a patch that was originally contributed by Steve Haslam. It was
adapted from stunnel, a GPL program by Michal Trojnara. The code for GNU TLS is
based on a patch contributed by Nikos Mavroyanopoulos. Because these packages
are so very different, the functions for each are kept in separate files. The
relevant file is #included as required, after any any common functions.

No cryptographic code is included in Exim. All this module does is to call
functions from the OpenSSL or GNU TLS libraries. */


#include "exim.h"

/* This module is compiled only when it is specifically requested in the
build-time configuration. However, some compilers don't like compiling empty
modules, so keep them happy with a dummy when skipping the rest. Make it
reference itself to stop picky compilers complaining that it is unused, and put
in a dummy argument to stop even pickier compilers complaining about infinite
loops. */

#ifndef EXPERIMENTAL_DANE
static void dummy(int x) { dummy(x-1); }
#else

/* Enabling DANE without enabling TLS cannot work. Abort the compilation. */
#ifndef SUPPORT_TLS
#error DANE support requires that TLS support must be enabled. Abort build.
#endif

#ifdef USE_GNUTLS
#include "dane-gnu.c"
#else
#include "dane-openssl.c"
#endif


#endif  /* EXPERIMENTAL_DANE */

/* End of dane.c */
