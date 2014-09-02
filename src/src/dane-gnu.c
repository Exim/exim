/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2013 */
/* See the file NOTICE for conditions of use and distribution. */

/* This file (will) provide DANE support for Exim using the GnuTLS library,
but is not yet an available supported implementation.  This file is #included
into dane.c when USE_GNUTLS has been set.  */

/* As of March 2014, the reference implementation for DANE that we are
using was written by Viktor Dukhovny and it supports OpenSSL only.  At
some point we will add GnuTLS support, but for right now just abort the
build and explain why. */


#error No support for DANE using GnuTLS yet.


/* End of dane-gnu.c */
