/*
 *  PDKIM - a RFC4871 (DKIM) implementation
 *
 *  Copyright (C) 2016  Exim maintainers
 *
 *  Hash interface functions
 */

#include "../exim.h"

#ifndef DISABLE_DKIM	/* entire file */

#ifndef SUPPORT_TLS
# error Need SUPPORT_TLS for DKIM
#endif

#include "crypt_ver.h"

#ifdef RSA_OPENSSL
# include <openssl/rsa.h>
# include <openssl/ssl.h>
# include <openssl/err.h>
#elif defined(RSA_GNUTLS)
# include <gnutls/gnutls.h>
# include <gnutls/x509.h>
# ifdef RSA_VERIFY_GNUTLS
#  include <gnutls/abstract.h>
# endif
#endif

#ifdef SHA_GNUTLS
# include <gnutls/crypto.h>
#endif

#include "hash.h"


/******************************************************************************/
#ifdef SHA_OPENSSL

void
exim_sha_init(hctx * h, BOOL sha1)
{
h->sha1 = sha1;
h->hashlen = sha1 ? 20 : 32;
if (h->sha1)
  SHA1_Init  (&h->u.sha1);
else
  SHA256_Init(&h->u.sha2);
}


void
exim_sha_update(hctx * h, const uschar * data, int len)
{
if (h->sha1)
  SHA1_Update  (&h->u.sha1, data, len);
else
  SHA256_Update(&h->u.sha2, data, len);
}


void
exim_sha_finish(hctx * h, blob * b)
{
b->data = store_get(b->len = h->hashlen);

if (h->sha1)
  SHA1_Final  (b->data, &h->u.sha1);
else
  SHA256_Final(b->data, &h->u.sha2);
}



#elif defined(SHA_GNUTLS)
/******************************************************************************/

void
exim_sha_init(hctx * h, BOOL sha1)
{
h->sha1 = sha1;
h->hashlen = sha1 ? 20 : 32;
gnutls_hash_init(&h->sha, sha1 ? GNUTLS_DIG_SHA1 : GNUTLS_DIG_SHA256);
}


void
exim_sha_update(hctx * h, const uschar * data, int len)
{
gnutls_hash(h->sha, data, len);
}


void
exim_sha_finish(hctx * h, blob * b)
{
b->data = store_get(b->len = h->hashlen);
gnutls_hash_output(h->sha, b->data);
}



#elif defined(SHA_GCRYPT)
/******************************************************************************/

void
exim_sha_init(hctx * h, BOOL sha1)
{
h->sha1 = sha1;
h->hashlen = sha1 ? 20 : 32;
gcry_md_open(&h->sha, sha1 ? GCRY_MD_SHA1 : GCRY_MD_SHA256, 0);
}


void
exim_sha_update(hctx * h, const uschar * data, int len)
{
gcry_md_write(h->sha, data, len);
}


void
exim_sha_finish(hctx * h, blob * b)
{
b->data = store_get(b->len = h->hashlen);
memcpy(b->data, gcry_md_read(h->sha, 0), h->hashlen);
}




#elif defined(SHA_POLARSSL)
/******************************************************************************/

void
exim_sha_init(hctx * h, BOOL sha1)
{
h->sha1 = sha1;
h->hashlen = sha1 ? 20 : 32;
if (h->sha1)
  sha1_starts(&h->u.sha1);
else
  sha2_starts(&h->u.sha2, 0);
}


void
exim_sha_update(hctx * h, const uschar * data, int len)
{
if (h->sha1)
  sha1_update(h->u.sha1, US data, len);
else
  sha2_update(h->u.sha2, US data, len);
}


void
exim_sha_finish(hctx * h, blob * b)
{
b->data = store_get(b->len = h->hashlen);

if (h->sha1)
  sha1_finish(h->u.sha1, b->data);
else
  sha2_finish(h->u.sha2, b->data);
}

#endif
/******************************************************************************/

/* Common to all library versions */
int
exim_sha_hashlen(hctx * h)
{
return h->sha1 ? 20 : 32;
}


#endif	/*DISABLE_DKIM*/
/* End of File */
