/*
 *  PDKIM - a RFC4871 (DKIM) implementation
 *
 *  Copyright (C) 2016  Exim maintainers
 *
 *  RSA signing/verification interface
 */

#include "../exim.h"

#ifndef DISABLE_DKIM	/* entire file */

#include "crypt_ver.h"

#ifdef RSA_OPENSSL
# include <openssl/rsa.h>
# include <openssl/ssl.h>
# include <openssl/err.h>
#elif defined(RSA_GNUTLS)
# include <gnutls/gnutls.h>
# include <gnutls/x509.h>
#  include <gnutls/abstract.h>
#elif defined(RSA_GCRYPT)
#  include <gcrypt.h>
#  include <libtasn1.h>
#endif

#include "../blob.h"


#ifdef RSA_OPENSSL

typedef struct {
  RSA * rsa;
} es_ctx;

typedef struct {
  RSA * rsa;
} ev_ctx;

#elif defined(RSA_GNUTLS)

typedef struct {
  gnutls_x509_privkey_t rsa;
} es_ctx;

typedef struct {
  gnutls_pubkey_t rsa;
} ev_ctx;

#elif defined(RSA_GCRYPT)

typedef struct {
  gcry_mpi_t n;
  gcry_mpi_t e;
  gcry_mpi_t d;
  gcry_mpi_t p;
  gcry_mpi_t q;
  gcry_mpi_t dp;
  gcry_mpi_t dq;
  gcry_mpi_t qp;
} es_ctx;

typedef struct {
  gcry_mpi_t n;
  gcry_mpi_t e;
} ev_ctx;

#endif


extern void exim_dkim_init(void);
extern blob * exim_dkim_data_append(blob *, int *, uschar *);

extern const uschar * exim_dkim_signing_init(uschar *, es_ctx *);
extern const uschar * exim_dkim_sign(es_ctx *, BOOL, blob *, blob *);
extern const uschar * exim_dkim_verify_init(blob *, ev_ctx *);
extern const uschar * exim_dkim_verify(ev_ctx *, BOOL, blob *, blob *);

#endif	/*DISABLE_DKIM*/
/* End of File */
