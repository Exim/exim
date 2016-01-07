/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) Jeremy Harris 2016 */
/* See the file NOTICE for conditions of use and distribution. */

/* RSA and SHA routine selection for PDKIM */

#include "../exim.h"


#ifdef USE_GNUTLS
# define RSA_GNUTLS

# include <gnutls/gnutls.h>
# if GNUTLS_VERSION_NUMBER >= 0x020a00
#  define SHA_GNUTLS

# else
#  define SHA_POLARSSL
# endif

#else
# define RSA_OPENSSL
# define SHA_OPENSSL
#endif

