/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) Jeremy Harris 2017 */
/* See the file NOTICE for conditions of use and distribution. */

/* Signing and hashing routine selection for PDKIM */

#include "../exim.h"
#include "../sha_ver.h"


#ifdef USE_GNUTLS
# include <gnutls/gnutls.h>

# if GNUTLS_VERSION_NUMBER >= 0x30000
#  define SIGN_GNUTLS
# else
#  define SIGN_GCRYPT
# endif

#else
# define SIGN_OPENSSL
#endif

