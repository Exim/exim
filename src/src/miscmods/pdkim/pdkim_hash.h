/*
 *  PDKIM - a RFC4871 (DKIM) implementation
 *
 *  Copyright (C) 1995 - 2018  Exim maintainers
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *
 *  Hash interface functions
 */

#include "../exim.h"

#if !defined(HASH_H)	/* entire file */
#define HASH_H

#ifdef DISABLE_TLS
# error Must not DISABLE_TLS, for DKIM
#endif

#include "crypt_ver.h"
#include "../blob.h"
#include "../hash.h"

#ifdef SIGN_OPENSSL
# include <openssl/rsa.h>
# include <openssl/ssl.h>
# include <openssl/err.h>
#elif defined(SIGN_GNUTLS)
# include <gnutls/gnutls.h>
# include <gnutls/x509.h>
#endif

#if defined(SHA_OPENSSL)
# include "pdkim.h"
#elif defined(SHA_GCRYPT)
# include "pdkim.h"
#endif

#endif
/* End of File */
