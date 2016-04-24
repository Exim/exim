/*
 *  PDKIM - a RFC4871 (DKIM) implementation
 *
 *  Copyright (C) 2016  Exim maintainers
 *
 *  Hash interface functions
 */

#include "../exim.h"

#if !defined(DISABLE_DKIM) && !defined(PDKIM_HASH_H)	/* entire file */
#define PDKIM_HASH_H

#ifndef SUPPORT_TLS
# error Need SUPPORT_TLS for DKIM
#endif

#include "crypt_ver.h"
#include "blob.h"

#ifdef RSA_OPENSSL
# include <openssl/rsa.h>
# include <openssl/ssl.h>
# include <openssl/err.h>
#elif defined(RSA_GNUTLS)
# include <gnutls/gnutls.h>
# include <gnutls/x509.h>
#endif

#ifdef SHA_GNUTLS
# include <gnutls/crypto.h>
#elif defined(SHA_GCRYPT)
# include <gcrypt.h>
#elif defined(SHA_POLARSSL)
# include "pdkim.h"
# include "polarssl/sha1.h"
# include "polarssl/sha2.h"
#endif

/* Hash context */
typedef struct {
  int sha1;
  int hashlen;

#ifdef SHA_OPENSSL
  union {
    SHA_CTX      sha1;       /* SHA1 block                                */
    SHA256_CTX   sha2;       /* SHA256 block                              */
  } u;

#elif defined(SHA_GNUTLS)
  gnutls_hash_hd_t sha;      /* Either SHA1 or SHA256 block               */

#elif defined(SHA_GCRYPT)
  gcry_md_hd_t sha;          /* Either SHA1 or SHA256 block               */

#elif defined(SHA_POLARSSL)
  union {
    sha1_context sha1;       /* SHA1 block                                */
    sha2_context sha2;       /* SHA256 block                              */
  } u;
#endif

} hctx;

#if defined(SHA_OPENSSL)
# include "pdkim.h"
#elif defined(SHA_GCRYPT)
# include "pdkim.h"
#endif


extern void     exim_sha_init(hctx *, BOOL);
extern void     exim_sha_update(hctx *, const uschar *a, int);
extern void     exim_sha_finish(hctx *, blob *);
extern int      exim_sha_hashlen(hctx *);

#endif	/*DISABLE_DKIM*/
/* End of File */
