/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) Jeremy Harris 2016 */
/* See the file NOTICE for conditions of use and distribution. */

/* SHA routine selection */

#include "exim.h"

#ifdef SUPPORT_TLS

# define EXIM_HAVE_SHA2

# ifdef USE_GNUTLS
#  include <gnutls/gnutls.h>

#  if GNUTLS_VERSION_NUMBER >= 0x020a00
#   define SHA_GNUTLS
#  else
#   define SHA_GCRYPT
#  endif

# else
#  define SHA_OPENSSL
# endif

#else
# define SHA_NATIVE
#endif

