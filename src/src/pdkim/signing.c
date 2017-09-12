/*
 *  PDKIM - a RFC4871 (DKIM) implementation
 *
 *  Copyright (C) 2016  Exim maintainers
 *
 *  signing/verification interface
 */

#include "../exim.h"

#ifndef DISABLE_DKIM	/* entire file */

#ifndef SUPPORT_TLS
# error Need SUPPORT_TLS for DKIM
#endif

#include "crypt_ver.h"
#include "signing.h"


/******************************************************************************/
#ifdef SIGN_GNUTLS

void
exim_dkim_init(void)
{
}


/* accumulate data (gnutls-only).  String to be appended must be nul-terminated. */
blob *
exim_dkim_data_append(blob * b, int * alloc, uschar * s)
{
int len = b->len;
b->data = string_append(b->data, alloc, &len, 1, s);
b->len = len;
return b;
}



/* import private key from PEM string in memory.
Return: NULL for success, or an error string */

const uschar *
exim_dkim_signing_init(uschar * privkey_pem, es_ctx * sign_ctx)
{
gnutls_datum_t k;
int rc;

k.data = privkey_pem;
k.size = strlen(privkey_pem);

if (  (rc = gnutls_x509_privkey_init(&sign_ctx->key)) != GNUTLS_E_SUCCESS
   || (rc = gnutls_x509_privkey_import(sign_ctx->key, &k,
	  GNUTLS_X509_FMT_PEM)) != GNUTLS_E_SUCCESS
   )
  return gnutls_strerror(rc);

return NULL;
}



/* allocate mem for signature (when signing) */
/* sign data (gnutls_only)
OR
sign hash.

Return: NULL for success, or an error string */

const uschar *
exim_dkim_sign(es_ctx * sign_ctx, hashmethod hash, blob * data, blob * sig)
{
gnutls_digest_algorithm_t dig;
gnutls_datum_t k;
size_t sigsize = 0;
int rc;
const uschar * ret = NULL;

switch (hash)
  {
  case HASH_SHA1:	dig = GNUTLS_DIG_SHA1; break;
  case HASH_SHA2_256:	dig = GNUTLS_DIG_SHA256; break;
  case HASH_SHA2_512:	dig = GNUTLS_DIG_SHA512; break;
  default:		return US"nonhandled hash type";
  }

/* Allocate mem for signature */
k.data = data->data;
k.size = data->len;
(void) gnutls_x509_privkey_sign_data(sign_ctx->key, dig,
  0, &k, NULL, &sigsize);

sig->data = store_get(sigsize);
sig->len = sigsize;

/* Do signing */
if ((rc = gnutls_x509_privkey_sign_data(sign_ctx->key, dig,
	    0, &k, sig->data, &sigsize)) != GNUTLS_E_SUCCESS
   )
  ret = gnutls_strerror(rc);

gnutls_x509_privkey_deinit(sign_ctx->key);
return ret;
}



/* import public key (from DER in memory)
Return: NULL for success, or an error string */

const uschar *
exim_dkim_verify_init(blob * pubkey_der, ev_ctx * verify_ctx)
{
gnutls_datum_t k;
int rc;
const uschar * ret = NULL;

gnutls_pubkey_init(&verify_ctx->key);

k.data = pubkey_der->data;
k.size = pubkey_der->len;

if ((rc = gnutls_pubkey_import(verify_ctx->key, &k, GNUTLS_X509_FMT_DER))
       != GNUTLS_E_SUCCESS)
  ret = gnutls_strerror(rc);
return ret;
}


/* verify signature (of hash)  (given pubkey & alleged sig)
Return: NULL for success, or an error string */

const uschar *
exim_dkim_verify(ev_ctx * verify_ctx, hashmethod hash, blob * data_hash, blob * sig)
{
gnutls_sign_algorithm_t algo;
gnutls_datum_t k, s;
int rc;
const uschar * ret = NULL;

/*XXX needs extension for non-rsa */
switch (hash)
  {
  case HASH_SHA1:	algo = GNUTLS_SIGN_RSA_SHA1;   break;
  case HASH_SHA2_256:	algo = GNUTLS_SIGN_RSA_SHA256; break;
  case HASH_SHA2_512:	algo = GNUTLS_SIGN_RSA_SHA512; break;
  default:		return US"nonhandled hash type";
  }

k.data = data_hash->data;
k.size = data_hash->len;
s.data = sig->data;
s.size = sig->len;
if ((rc = gnutls_pubkey_verify_hash2(verify_ctx->key, algo, 0, &k, &s)) < 0)
  ret = gnutls_strerror(rc);

gnutls_pubkey_deinit(verify_ctx->key);
return ret;
}




#elif defined(SIGN_GCRYPT)
/******************************************************************************/
/* This variant is used under pre-3.0.0 GnuTLS.  Only rsa-sha1 and rsa-sha256 */


/* Internal service routine:
Read and move past an asn.1 header, checking class & tag,
optionally returning the data-length */

static int
as_tag(blob * der, uschar req_cls, long req_tag, long * alen)
{
int rc;
uschar tag_class;
int taglen;
long tag, len;

/* debug_printf_indent("as_tag: %02x %02x %02x %02x\n",
	der->data[0], der->data[1], der->data[2], der->data[3]); */

if ((rc = asn1_get_tag_der(der->data++, der->len--, &tag_class, &taglen, &tag))
    != ASN1_SUCCESS)
  return rc;

if (tag_class != req_cls || tag != req_tag) return ASN1_ELEMENT_NOT_FOUND;

if ((len = asn1_get_length_der(der->data, der->len, &taglen)) < 0)
  return ASN1_DER_ERROR;
if (alen) *alen = len;

/* debug_printf_indent("as_tag:  tlen %d dlen %d\n", taglen, (int)len); */

der->data += taglen;
der->len -= taglen;
return rc;
}

/* Internal service routine:
Read and move over an asn.1 integer, setting an MPI to the value
*/

static uschar *
as_mpi(blob * der, gcry_mpi_t * mpi)
{
long alen;
int rc;
gcry_error_t gerr;

/* integer; move past the header */
if ((rc = as_tag(der, 0, ASN1_TAG_INTEGER, &alen)) != ASN1_SUCCESS)
  return US asn1_strerror(rc);

/* read to an MPI */
if ((gerr = gcry_mpi_scan(mpi, GCRYMPI_FMT_STD, der->data, alen, NULL)))
  return US gcry_strerror(gerr);

/* move over the data */
der->data += alen; der->len -= alen;
return NULL;
}



void
exim_dkim_init(void)
{
/* Version check should be the very first call because it
makes sure that important subsystems are initialized. */
if (!gcry_check_version (GCRYPT_VERSION))
  {
  fputs ("libgcrypt version mismatch\n", stderr);
  exit (2);
  }

/* We don't want to see any warnings, e.g. because we have not yet
parsed program options which might be used to suppress such
warnings. */
gcry_control (GCRYCTL_SUSPEND_SECMEM_WARN);

/* ... If required, other initialization goes here.  Note that the
process might still be running with increased privileges and that
the secure memory has not been initialized.  */

/* Allocate a pool of 16k secure memory.  This make the secure memory
available and also drops privileges where needed.  */
gcry_control (GCRYCTL_INIT_SECMEM, 16384, 0);

/* It is now okay to let Libgcrypt complain when there was/is
a problem with the secure memory. */
gcry_control (GCRYCTL_RESUME_SECMEM_WARN);

/* ... If required, other initialization goes here.  */

/* Tell Libgcrypt that initialization has completed. */
gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);

return;
}




/* Accumulate data (gnutls-only).
String to be appended must be nul-terminated. */

blob *
exim_dkim_data_append(blob * b, int * alloc, uschar * s)
{
return b;	/*dummy*/
}



/* import private key from PEM string in memory.
Return: NULL for success, or an error string */

const uschar *
exim_dkim_signing_init(uschar * privkey_pem, es_ctx * sign_ctx)
{
uschar * s1, * s2;
blob der;
long alen;
int rc;

/*XXX will need extension to _spot_ as well as handle a
non-RSA key?  I think... */

/*
 *  RSAPrivateKey ::= SEQUENCE
 *      version           Version,
 *      modulus           INTEGER,  -- n
 *      publicExponent    INTEGER,  -- e
 *      privateExponent   INTEGER,  -- d
 *      prime1            INTEGER,  -- p
 *      prime2            INTEGER,  -- q
 *      exponent1         INTEGER,  -- d mod (p-1)
 *      exponent2         INTEGER,  -- d mod (q-1)
 *      coefficient       INTEGER,  -- (inverse of q) mod p
 *      otherPrimeInfos   OtherPrimeInfos OPTIONAL
 */
 
if (  !(s1 = Ustrstr(CS privkey_pem, "-----BEGIN RSA PRIVATE KEY-----"))
   || !(s2 = Ustrstr(CS (s1+=31),    "-----END RSA PRIVATE KEY-----" ))
   )
  return US"Bad PEM wrapper";

*s2 = '\0';

if ((der.len = b64decode(s1, &der.data)) < 0)
  return US"Bad PEM-DER b64 decode";

/* untangle asn.1 */

/* sequence; just move past the header */
if ((rc = as_tag(&der, ASN1_CLASS_STRUCTURED, ASN1_TAG_SEQUENCE, NULL))
   != ASN1_SUCCESS) goto asn_err;

/* integer version; move past the header, check is zero */
if ((rc = as_tag(&der, 0, ASN1_TAG_INTEGER, &alen)) != ASN1_SUCCESS)
  goto asn_err;
if (alen != 1 || *der.data != 0)
  return US"Bad version number";
der.data++; der.len--;

if (  (s1 = as_mpi(&der, &sign_ctx->n))
   || (s1 = as_mpi(&der, &sign_ctx->e))
   || (s1 = as_mpi(&der, &sign_ctx->d))
   || (s1 = as_mpi(&der, &sign_ctx->p))
   || (s1 = as_mpi(&der, &sign_ctx->q))
   || (s1 = as_mpi(&der, &sign_ctx->dp))
   || (s1 = as_mpi(&der, &sign_ctx->dq))
   || (s1 = as_mpi(&der, &sign_ctx->qp))
   )
  return s1;

DEBUG(D_acl) debug_printf_indent("rsa_signing_init:\n");
  {
  uschar * s;
  gcry_mpi_aprint (GCRYMPI_FMT_HEX, &s, NULL, sign_ctx->n);
  debug_printf_indent(" N : %s\n", s);
  gcry_mpi_aprint (GCRYMPI_FMT_HEX, &s, NULL, sign_ctx->e);
  debug_printf_indent(" E : %s\n", s);
  gcry_mpi_aprint (GCRYMPI_FMT_HEX, &s, NULL, sign_ctx->d);
  debug_printf_indent(" D : %s\n", s);
  gcry_mpi_aprint (GCRYMPI_FMT_HEX, &s, NULL, sign_ctx->p);
  debug_printf_indent(" P : %s\n", s);
  gcry_mpi_aprint (GCRYMPI_FMT_HEX, &s, NULL, sign_ctx->q);
  debug_printf_indent(" Q : %s\n", s);
  gcry_mpi_aprint (GCRYMPI_FMT_HEX, &s, NULL, sign_ctx->dp);
  debug_printf_indent(" DP: %s\n", s);
  gcry_mpi_aprint (GCRYMPI_FMT_HEX, &s, NULL, sign_ctx->dq);
  debug_printf_indent(" DQ: %s\n", s);
  gcry_mpi_aprint (GCRYMPI_FMT_HEX, &s, NULL, sign_ctx->qp);
  debug_printf_indent(" QP: %s\n", s);
  }
return NULL;

asn_err: return US asn1_strerror(rc);
}



/* allocate mem for signature (when signing) */
/* sign data (gnutls_only)
OR
sign hash.

Return: NULL for success, or an error string */

const uschar *
exim_dkim_sign(es_ctx * sign_ctx, hashmethod hash, blob * data, blob * sig)
{
BOOL is_sha1;
gcry_sexp_t s_hash = NULL, s_key = NULL, s_sig = NULL;
gcry_mpi_t m_sig;
uschar * errstr;
gcry_error_t gerr;

/*XXX will need extension for hash types (though, possibly, should
be re-specced to not rehash but take an already-hashed value? Actually
current impl looks WRONG - it _is_ given a hash so should not be
re-hashing.  Has this been tested?

Will need extension for non-RSA sugning algos. */

switch (hash)
  {
  case HASH_SHA1:	is_sha1 = TRUE; break;
  case HASH_SHA2_256:	is_sha1 = FALSE; break;
  default:		return US"nonhandled hash type";
  }

#define SIGSPACE 128
sig->data = store_get(SIGSPACE);

if (gcry_mpi_cmp (sign_ctx->p, sign_ctx->q) > 0)
  {
  gcry_mpi_swap (sign_ctx->p, sign_ctx->q);
  gcry_mpi_invm (sign_ctx->qp, sign_ctx->p, sign_ctx->q);
  }

if (  (gerr = gcry_sexp_build (&s_key, NULL,
		"(private-key (rsa (n%m)(e%m)(d%m)(p%m)(q%m)(u%m)))",
		sign_ctx->n, sign_ctx->e,
		sign_ctx->d, sign_ctx->p,
		sign_ctx->q, sign_ctx->qp))
   || (gerr = gcry_sexp_build (&s_hash, NULL,
		is_sha1
		? "(data(flags pkcs1)(hash sha1 %b))"
		: "(data(flags pkcs1)(hash sha256 %b))",
		(int) data->len, CS data->data))
   ||  (gerr = gcry_pk_sign (&s_sig, s_hash, s_key))
   )
  return US gcry_strerror(gerr);

/* gcry_sexp_dump(s_sig); */

if (  !(s_sig = gcry_sexp_find_token(s_sig, "s", 0))
   )
  return US"no sig result";

m_sig = gcry_sexp_nth_mpi(s_sig, 1, GCRYMPI_FMT_USG);

DEBUG(D_acl)
  {
  uschar * s;
  gcry_mpi_aprint (GCRYMPI_FMT_HEX, &s, NULL, m_sig);
  debug_printf_indent(" SG: %s\n", s);
  }

gerr = gcry_mpi_print(GCRYMPI_FMT_USG, sig->data, SIGSPACE, &sig->len, m_sig);
if (gerr)
  {
  debug_printf_indent("signature conversion from MPI to buffer failed\n");
  return US gcry_strerror(gerr);
  }
#undef SIGSPACE

return NULL;
}


/* import public key (from DER in memory)
Return: NULL for success, or an error string */

const uschar *
exim_dkim_verify_init(blob * pubkey_der, ev_ctx * verify_ctx)
{
/*
in code sequence per b81207d2bfa92 rsa_parse_public_key() and asn1_get_mpi()
*/
uschar tag_class;
int taglen;
long alen;
int rc;
uschar * errstr;
gcry_error_t gerr;
uschar * stage = US"S1";

/*
sequence
 sequence
  OBJECT:rsaEncryption
  NULL
 BIT STRING:RSAPublicKey
  sequence
   INTEGER:Public modulus
   INTEGER:Public exponent

openssl rsa -in aux-fixed/dkim/dkim.private -pubout -outform DER | od -t x1 | head;
openssl rsa -in aux-fixed/dkim/dkim.private -pubout | openssl asn1parse -dump;
openssl rsa -in aux-fixed/dkim/dkim.private -pubout | openssl asn1parse -dump -offset 22;
*/

/* sequence; just move past the header */
if ((rc = as_tag(pubkey_der, ASN1_CLASS_STRUCTURED, ASN1_TAG_SEQUENCE, NULL))
   != ASN1_SUCCESS) goto asn_err;

/* sequence; skip the entire thing */
DEBUG(D_acl) stage = US"S2";
if ((rc = as_tag(pubkey_der, ASN1_CLASS_STRUCTURED, ASN1_TAG_SEQUENCE, &alen))
   != ASN1_SUCCESS) goto asn_err;
pubkey_der->data += alen; pubkey_der->len -= alen;


/* bitstring: limit range to size of bitstring;
move over header + content wrapper */
DEBUG(D_acl) stage = US"BS";
if ((rc = as_tag(pubkey_der, 0, ASN1_TAG_BIT_STRING, &alen)) != ASN1_SUCCESS)
  goto asn_err;
pubkey_der->len = alen;
pubkey_der->data++; pubkey_der->len--;

/* sequence; just move past the header */
DEBUG(D_acl) stage = US"S3";
if ((rc = as_tag(pubkey_der, ASN1_CLASS_STRUCTURED, ASN1_TAG_SEQUENCE, NULL))
   != ASN1_SUCCESS) goto asn_err;

/* read two integers */
DEBUG(D_acl) stage = US"MPI";
if (  (errstr = as_mpi(pubkey_der, &verify_ctx->n))
   || (errstr = as_mpi(pubkey_der, &verify_ctx->e))
   )
  return errstr;

DEBUG(D_acl) debug_printf_indent("rsa_verify_init:\n");
	{
	uschar * s;
	gcry_mpi_aprint (GCRYMPI_FMT_HEX, &s, NULL, verify_ctx->n);
	debug_printf_indent(" N : %s\n", s);
	gcry_mpi_aprint (GCRYMPI_FMT_HEX, &s, NULL, verify_ctx->e);
	debug_printf_indent(" E : %s\n", s);
	}

return NULL;

asn_err:
DEBUG(D_acl) return string_sprintf("%s: %s", stage, asn1_strerror(rc));
	     return US asn1_strerror(rc);
}


/* verify signature (of hash)  (given pubkey & alleged sig)
Return: NULL for success, or an error string */

const uschar *
exim_dkim_verify(ev_ctx * verify_ctx, hashmethod hash, blob * data_hash, blob * sig)
{
/*
cf. libgnutls 2.8.5 _wrap_gcry_pk_verify()
*/
gcry_mpi_t m_sig;
gcry_sexp_t s_sig = NULL, s_hash = NULL, s_pkey = NULL;
gcry_error_t gerr;
uschar * stage;

switch (hash)
  {
  case HASH_SHA1:	is_sha1 = TRUE; break;
  case HASH_SHA2_256:	is_sha1 = FALSE; break;
  default:		return US"nonhandled hash type";
  }

if (  (stage = US"pkey sexp build",
       gerr = gcry_sexp_build (&s_pkey, NULL, "(public-key(rsa(n%m)(e%m)))",
		        verify_ctx->n, verify_ctx->e))
   || (stage = US"data sexp build",
       gerr = gcry_sexp_build (&s_hash, NULL,
/*XXX needs extension for SHA512 */
		is_sha1
		? "(data(flags pkcs1)(hash sha1 %b))"
		: "(data(flags pkcs1)(hash sha256 %b))",
		(int) data_hash->len, CS data_hash->data))
   || (stage = US"sig mpi scan",
       gerr = gcry_mpi_scan(&m_sig, GCRYMPI_FMT_USG, sig->data, sig->len, NULL))
   || (stage = US"sig sexp build",
       gerr = gcry_sexp_build (&s_sig, NULL, "(sig-val(rsa(s%m)))", m_sig))
   || (stage = US"verify",
       gerr = gcry_pk_verify (s_sig, s_hash, s_pkey))
   )
  {
  DEBUG(D_acl) debug_printf_indent("verify: error in stage '%s'\n", stage);
  return US gcry_strerror(gerr);
  }

if (s_sig) gcry_sexp_release (s_sig);
if (s_hash) gcry_sexp_release (s_hash);
if (s_pkey) gcry_sexp_release (s_pkey);
gcry_mpi_release (m_sig);
gcry_mpi_release (verify_ctx->n);
gcry_mpi_release (verify_ctx->e);

return NULL;
}




#elif defined(SIGN_OPENSSL)
/******************************************************************************/

void
exim_dkim_init(void)
{
}


/* accumulate data (gnutls-only) */
blob *
exim_dkim_data_append(blob * b, int * alloc, uschar * s)
{
return b;	/*dummy*/
}


/* import private key from PEM string in memory.
Return: NULL for success, or an error string */

const uschar *
exim_dkim_signing_init(uschar * privkey_pem, es_ctx * sign_ctx)
{
BIO * bp = BIO_new_mem_buf(privkey_pem, -1);

if (!(sign_ctx->key = PEM_read_bio_PrivateKey(bp, NULL, NULL, NULL)))
  return ERR_error_string(ERR_get_error(), NULL);
return NULL;
}



/* allocate mem for signature (when signing) */
/* sign data (gnutls_only)
OR
sign hash.

Return: NULL for success, or an error string */

const uschar *
exim_dkim_sign(es_ctx * sign_ctx, hashmethod hash, blob * data, blob * sig)
{
const EVP_MD * md;
EVP_PKEY_CTX * ctx;
size_t siglen;

switch (hash)
  {
  case HASH_SHA1:	md = EVP_sha1();   break;
  case HASH_SHA2_256:	md = EVP_sha256(); break;
  case HASH_SHA2_512:	md = EVP_sha512(); break;
  default:		return US"nonhandled hash type";
  }

if (  (ctx = EVP_PKEY_CTX_new(sign_ctx->key, NULL))
   && EVP_PKEY_sign_init(ctx) > 0
   && EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) > 0
   && EVP_PKEY_CTX_set_signature_md(ctx, md) > 0
   && EVP_PKEY_sign(ctx, NULL, &siglen, data->data, data->len) > 0
   )
  {
  /* Allocate mem for signature */
  sig->data = store_get(siglen);
  sig->len = siglen;

  if (EVP_PKEY_sign(ctx, sig->data, &siglen, data->data, data->len) > 0)
    { EVP_PKEY_CTX_free(ctx); return NULL; }
  }

if (ctx) EVP_PKEY_CTX_free(ctx);
return ERR_error_string(ERR_get_error(), NULL);
}



/* import public key (from DER in memory)
Return: NULL for success, or an error string */

const uschar *
exim_dkim_verify_init(blob * pubkey_der, ev_ctx * verify_ctx)
{
const uschar * s = pubkey_der->data;

/*XXX hmm, we never free this */

if ((verify_ctx->key = d2i_PUBKEY(NULL, &s, pubkey_der->len)))
  return NULL;
return ERR_error_string(ERR_get_error(), NULL);
}




/* verify signature (of hash)  (given pubkey & alleged sig)
Return: NULL for success, or an error string */

const uschar *
exim_dkim_verify(ev_ctx * verify_ctx, hashmethod hash, blob * data_hash, blob * sig)
{
const EVP_MD * md;
EVP_PKEY_CTX * ctx;

switch (hash)
  {
  case HASH_SHA1:	md = EVP_sha1();   break;
  case HASH_SHA2_256:	md = EVP_sha256(); break;
  case HASH_SHA2_512:	md = EVP_sha512(); break;
  default:		return US"nonhandled hash type";
  }

if (  (ctx = EVP_PKEY_CTX_new(verify_ctx->key, NULL))
   && EVP_PKEY_verify_init(ctx) > 0
   && EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) > 0
   && EVP_PKEY_CTX_set_signature_md(ctx, md) > 0
   && EVP_PKEY_verify(ctx, sig->data, sig->len,
	data_hash->data, data_hash->len) == 1
   )
  { EVP_PKEY_CTX_free(ctx); return NULL; }

if (ctx) EVP_PKEY_CTX_free(ctx);
return ERR_error_string(ERR_get_error(), NULL);
}



#endif
/******************************************************************************/

#endif	/*DISABLE_DKIM*/
/* End of File */
