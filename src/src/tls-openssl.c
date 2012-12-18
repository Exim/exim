/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2012 */
/* See the file NOTICE for conditions of use and distribution. */

/* This module provides the TLS (aka SSL) support for Exim using the OpenSSL
library. It is #included into the tls.c file when that library is used. The
code herein is based on a patch that was originally contributed by Steve
Haslam. It was adapted from stunnel, a GPL program by Michal Trojnara.

No cryptographic code is included in Exim. All this module does is to call
functions from the OpenSSL library. */


/* Heading stuff */

#include <openssl/lhash.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#ifdef EXPERIMENTAL_OCSP
#include <openssl/ocsp.h>
#endif

#ifdef EXPERIMENTAL_OCSP
#define EXIM_OCSP_SKEW_SECONDS (300L)
#define EXIM_OCSP_MAX_AGE (-1L)
#endif

#if OPENSSL_VERSION_NUMBER >= 0x0090806fL && !defined(OPENSSL_NO_TLSEXT)
#define EXIM_HAVE_OPENSSL_TLSEXT
#endif

/* Structure for collecting random data for seeding. */

typedef struct randstuff {
  struct timeval tv;
  pid_t          p;
} randstuff;

/* Local static variables */

static BOOL client_verify_callback_called = FALSE;
static BOOL server_verify_callback_called = FALSE;
static const uschar *sid_ctx = US"exim";

/* We have three different contexts to care about.

Simple case: client, `client_ctx`
 As a client, we can be doing a callout or cut-through delivery while receiving
 a message.  So we have a client context, which should have options initialised
 from the SMTP Transport.

Server:
 There are two cases: with and without ServerNameIndication from the client.
 Given TLS SNI, we can be using different keys, certs and various other
 configuration settings, because they're re-expanded with $tls_sni set.  This
 allows vhosting with TLS.  This SNI is sent in the handshake.
 A client might not send SNI, so we need a fallback, and an initial setup too.
 So as a server, we start out using `server_ctx`.
 If SNI is sent by the client, then we as server, mid-negotiation, try to clone
 `server_sni` from `server_ctx` and then initialise settings by re-expanding
 configuration.
*/

static SSL_CTX *client_ctx = NULL;
static SSL_CTX *server_ctx = NULL;
static SSL     *client_ssl = NULL;
static SSL     *server_ssl = NULL;

#ifdef EXIM_HAVE_OPENSSL_TLSEXT
static SSL_CTX *server_sni = NULL;
#endif

static char ssl_errstring[256];

static int  ssl_session_timeout = 200;
static BOOL client_verify_optional = FALSE;
static BOOL server_verify_optional = FALSE;

static BOOL    reexpand_tls_files_for_sni = FALSE;


typedef struct tls_ext_ctx_cb {
  uschar *certificate;
  uschar *privatekey;
#ifdef EXPERIMENTAL_OCSP
  uschar *ocsp_file;
  uschar *ocsp_file_expanded;
  OCSP_RESPONSE *ocsp_response;
#endif
  uschar *dhparam;
  /* these are cached from first expand */
  uschar *server_cipher_list;
  /* only passed down to tls_error: */
  host_item *host;
} tls_ext_ctx_cb;

/* should figure out a cleanup of API to handle state preserved per
implementation, for various reasons, which can be void * in the APIs.
For now, we hack around it. */
tls_ext_ctx_cb *client_static_cbinfo = NULL;
tls_ext_ctx_cb *server_static_cbinfo = NULL;

static int
setup_certs(SSL_CTX *sctx, uschar *certs, uschar *crl, host_item *host, BOOL optional, BOOL client);

/* Callbacks */
#ifdef EXIM_HAVE_OPENSSL_TLSEXT
static int tls_servername_cb(SSL *s, int *ad ARG_UNUSED, void *arg);
#endif
#ifdef EXPERIMENTAL_OCSP
static int tls_stapling_cb(SSL *s, void *arg);
#endif


/*************************************************
*               Handle TLS error                 *
*************************************************/

/* Called from lots of places when errors occur before actually starting to do
the TLS handshake, that is, while the session is still in clear. Always returns
DEFER for a server and FAIL for a client so that most calls can use "return
tls_error(...)" to do this processing and then give an appropriate return. A
single function is used for both server and client, because it is called from
some shared functions.

Argument:
  prefix    text to include in the logged error
  host      NULL if setting up a server;
            the connected host if setting up a client
  msg       error message or NULL if we should ask OpenSSL

Returns:    OK/DEFER/FAIL
*/

static int
tls_error(uschar *prefix, host_item *host, uschar *msg)
{
if (msg == NULL)
  {
  ERR_error_string(ERR_get_error(), ssl_errstring);
  msg = (uschar *)ssl_errstring;
  }

if (host == NULL)
  {
  uschar *conn_info = smtp_get_connection_info();
  if (Ustrncmp(conn_info, US"SMTP ", 5) == 0)
    conn_info += 5;
  log_write(0, LOG_MAIN, "TLS error on %s (%s): %s",
    conn_info, prefix, msg);
  return DEFER;
  }
else
  {
  log_write(0, LOG_MAIN, "TLS error on connection to %s [%s] (%s): %s",
    host->name, host->address, prefix, msg);
  return FAIL;
  }
}



/*************************************************
*        Callback to generate RSA key            *
*************************************************/

/*
Arguments:
  s          SSL connection
  export     not used
  keylength  keylength

Returns:     pointer to generated key
*/

static RSA *
rsa_callback(SSL *s, int export, int keylength)
{
RSA *rsa_key;
export = export;     /* Shut picky compilers up */
DEBUG(D_tls) debug_printf("Generating %d bit RSA key...\n", keylength);
rsa_key = RSA_generate_key(keylength, RSA_F4, NULL, NULL);
if (rsa_key == NULL)
  {
  ERR_error_string(ERR_get_error(), ssl_errstring);
  log_write(0, LOG_MAIN|LOG_PANIC, "TLS error (RSA_generate_key): %s",
    ssl_errstring);
  return NULL;
  }
return rsa_key;
}




/*************************************************
*        Callback for verification               *
*************************************************/

/* The SSL library does certificate verification if set up to do so. This
callback has the current yes/no state is in "state". If verification succeeded,
we set up the tls_peerdn string. If verification failed, what happens depends
on whether the client is required to present a verifiable certificate or not.

If verification is optional, we change the state to yes, but still log the
verification error. For some reason (it really would help to have proper
documentation of OpenSSL), this callback function then gets called again, this
time with state = 1. In fact, that's useful, because we can set up the peerdn
value, but we must take care not to set the private verified flag on the second
time through.

Note: this function is not called if the client fails to present a certificate
when asked. We get here only if a certificate has been received. Handling of
optional verification for this case is done when requesting SSL to verify, by
setting SSL_VERIFY_FAIL_IF_NO_PEER_CERT in the non-optional case.

Arguments:
  state      current yes/no state as 1/0
  x509ctx    certificate information.
  client     TRUE for client startup, FALSE for server startup

Returns:     1 if verified, 0 if not
*/

static int
verify_callback(int state, X509_STORE_CTX *x509ctx, BOOL client)
{
static uschar txt[256];
tls_support * tlsp;
BOOL * calledp;
BOOL * optionalp;

if (client)
  {
  tlsp= &tls_out;
  calledp= &client_verify_callback_called;
  optionalp= &client_verify_optional;
  }
else
  {
  tlsp= &tls_in;
  calledp= &server_verify_callback_called;
  optionalp= &server_verify_optional;
  }

X509_NAME_oneline(X509_get_subject_name(x509ctx->current_cert),
  CS txt, sizeof(txt));

if (state == 0)
  {
  log_write(0, LOG_MAIN, "SSL verify error: depth=%d error=%s cert=%s",
    x509ctx->error_depth,
    X509_verify_cert_error_string(x509ctx->error),
    txt);
  tlsp->certificate_verified = FALSE;
  *calledp = TRUE;
  if (!*optionalp) return 0;    /* reject */
  DEBUG(D_tls) debug_printf("SSL verify failure overridden (host in "
    "tls_try_verify_hosts)\n");
  return 1;                          /* accept */
  }

if (x509ctx->error_depth != 0)
  {
  DEBUG(D_tls) debug_printf("SSL verify ok: depth=%d cert=%s\n",
     x509ctx->error_depth, txt);
  }
else
  {
  DEBUG(D_tls) debug_printf("SSL%s peer: %s\n",
    *calledp ? "" : " authenticated", txt);
  tlsp->peerdn = txt;
  }

if (!*calledp) tlsp->certificate_verified = TRUE;
*calledp = TRUE;

return 1;   /* accept */
}

static int
verify_callback_client(int state, X509_STORE_CTX *x509ctx)
{
return verify_callback(state, x509ctx, TRUE);
}

static int
verify_callback_server(int state, X509_STORE_CTX *x509ctx)
{
return verify_callback(state, x509ctx, FALSE);
}



/*************************************************
*           Information callback                 *
*************************************************/

/* The SSL library functions call this from time to time to indicate what they
are doing. We copy the string to the debugging output when TLS debugging has
been requested.

Arguments:
  s         the SSL connection
  where
  ret

Returns:    nothing
*/

static void
info_callback(SSL *s, int where, int ret)
{
where = where;
ret = ret;
DEBUG(D_tls) debug_printf("SSL info: %s\n", SSL_state_string_long(s));
}



/*************************************************
*                Initialize for DH               *
*************************************************/

/* If dhparam is set, expand it, and load up the parameters for DH encryption.

Arguments:
  dhparam   DH parameter file or fixed parameter identity string
  host      connected host, if client; NULL if server

Returns:    TRUE if OK (nothing to set up, or setup worked)
*/

static BOOL
init_dh(SSL_CTX *sctx, uschar *dhparam, host_item *host)
{
BIO *bio;
DH *dh;
uschar *dhexpanded;
const char *pem;

if (!expand_check(dhparam, US"tls_dhparam", &dhexpanded))
  return FALSE;

if (dhexpanded == NULL || *dhexpanded == '\0')
  {
  bio = BIO_new_mem_buf(CS std_dh_prime_default(), -1);
  }
else if (dhexpanded[0] == '/')
  {
  bio = BIO_new_file(CS dhexpanded, "r");
  if (bio == NULL)
    {
    tls_error(string_sprintf("could not read dhparams file %s", dhexpanded),
          host, US strerror(errno));
    return FALSE;
    }
  }
else
  {
  if (Ustrcmp(dhexpanded, "none") == 0)
    {
    DEBUG(D_tls) debug_printf("Requested no DH parameters.\n");
    return TRUE;
    }

  pem = std_dh_prime_named(dhexpanded);
  if (!pem)
    {
    tls_error(string_sprintf("Unknown standard DH prime \"%s\"", dhexpanded),
        host, US strerror(errno));
    return FALSE;
    }
  bio = BIO_new_mem_buf(CS pem, -1);
  }

dh = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
if (dh == NULL)
  {
  BIO_free(bio);
  tls_error(string_sprintf("Could not read tls_dhparams \"%s\"", dhexpanded),
      host, NULL);
  return FALSE;
  }

/* Even if it is larger, we silently return success rather than cause things
 * to fail out, so that a too-large DH will not knock out all TLS; it's a
 * debatable choice. */
if ((8*DH_size(dh)) > tls_dh_max_bits)
  {
  DEBUG(D_tls)
    debug_printf("dhparams file %d bits, is > tls_dh_max_bits limit of %d",
        8*DH_size(dh), tls_dh_max_bits);
  }
else
  {
  SSL_CTX_set_tmp_dh(sctx, dh);
  DEBUG(D_tls)
    debug_printf("Diffie-Hellman initialized from %s with %d-bit prime\n",
      dhexpanded ? dhexpanded : US"default", 8*DH_size(dh));
  }

DH_free(dh);
BIO_free(bio);

return TRUE;
}




#ifdef EXPERIMENTAL_OCSP
/*************************************************
*       Load OCSP information into state         *
*************************************************/

/* Called to load the OCSP response from the given file into memory, once
caller has determined this is needed.  Checks validity.  Debugs a message
if invalid.

ASSUMES: single response, for single cert.

Arguments:
  sctx            the SSL_CTX* to update
  cbinfo          various parts of session state
  expanded        the filename putatively holding an OCSP response

*/

static void
ocsp_load_response(SSL_CTX *sctx,
    tls_ext_ctx_cb *cbinfo,
    const uschar *expanded)
{
BIO *bio;
OCSP_RESPONSE *resp;
OCSP_BASICRESP *basic_response;
OCSP_SINGLERESP *single_response;
ASN1_GENERALIZEDTIME *rev, *thisupd, *nextupd;
X509_STORE *store;
unsigned long verify_flags;
int status, reason, i;

cbinfo->ocsp_file_expanded = string_copy(expanded);
if (cbinfo->ocsp_response)
  {
  OCSP_RESPONSE_free(cbinfo->ocsp_response);
  cbinfo->ocsp_response = NULL;
  }

bio = BIO_new_file(CS cbinfo->ocsp_file_expanded, "rb");
if (!bio)
  {
  DEBUG(D_tls) debug_printf("Failed to open OCSP response file \"%s\"\n",
      cbinfo->ocsp_file_expanded);
  return;
  }

resp = d2i_OCSP_RESPONSE_bio(bio, NULL);
BIO_free(bio);
if (!resp)
  {
  DEBUG(D_tls) debug_printf("Error reading OCSP response.\n");
  return;
  }

status = OCSP_response_status(resp);
if (status != OCSP_RESPONSE_STATUS_SUCCESSFUL)
  {
  DEBUG(D_tls) debug_printf("OCSP response not valid: %s (%d)\n",
      OCSP_response_status_str(status), status);
  return;
  }

basic_response = OCSP_response_get1_basic(resp);
if (!basic_response)
  {
  DEBUG(D_tls)
    debug_printf("OCSP response parse error: unable to extract basic response.\n");
  return;
  }

store = SSL_CTX_get_cert_store(sctx);
verify_flags = OCSP_NOVERIFY; /* check sigs, but not purpose */

/* May need to expose ability to adjust those flags?
OCSP_NOSIGS OCSP_NOVERIFY OCSP_NOCHAIN OCSP_NOCHECKS OCSP_NOEXPLICIT
OCSP_TRUSTOTHER OCSP_NOINTERN */

i = OCSP_basic_verify(basic_response, NULL, store, verify_flags);
if (i <= 0)
  {
  DEBUG(D_tls) {
    ERR_error_string(ERR_get_error(), ssl_errstring);
    debug_printf("OCSP response verify failure: %s\n", US ssl_errstring);
  }
  return;
  }

/* Here's the simplifying assumption: there's only one response, for the
one certificate we use, and nothing for anything else in a chain.  If this
proves false, we need to extract a cert id from our issued cert
(tls_certificate) and use that for OCSP_resp_find_status() (which finds the
right cert in the stack and then calls OCSP_single_get0_status()).

I'm hoping to avoid reworking a bunch more of how we handle state here. */
single_response = OCSP_resp_get0(basic_response, 0);
if (!single_response)
  {
  DEBUG(D_tls)
    debug_printf("Unable to get first response from OCSP basic response.\n");
  return;
  }

status = OCSP_single_get0_status(single_response, &reason, &rev, &thisupd, &nextupd);
/* how does this status differ from the one above? */
if (status != OCSP_RESPONSE_STATUS_SUCCESSFUL)
  {
  DEBUG(D_tls) debug_printf("OCSP response not valid (take 2): %s (%d)\n",
      OCSP_response_status_str(status), status);
  return;
  }

if (!OCSP_check_validity(thisupd, nextupd, EXIM_OCSP_SKEW_SECONDS, EXIM_OCSP_MAX_AGE))
  {
  DEBUG(D_tls) debug_printf("OCSP status invalid times.\n");
  return;
  }

cbinfo->ocsp_response = resp;
}
#endif




/*************************************************
*        Expand key and cert file specs          *
*************************************************/

/* Called once during tls_init and possibly againt during TLS setup, for a
new context, if Server Name Indication was used and tls_sni was seen in
the certificate string.

Arguments:
  sctx            the SSL_CTX* to update
  cbinfo          various parts of session state

Returns:          OK/DEFER/FAIL
*/

static int
tls_expand_session_files(SSL_CTX *sctx, tls_ext_ctx_cb *cbinfo)
{
uschar *expanded;

if (cbinfo->certificate == NULL)
  return OK;

if (Ustrstr(cbinfo->certificate, US"tls_sni") ||
    Ustrstr(cbinfo->certificate, US"tls_in_sni") ||
    Ustrstr(cbinfo->certificate, US"tls_out_sni")
   )
  reexpand_tls_files_for_sni = TRUE;

if (!expand_check(cbinfo->certificate, US"tls_certificate", &expanded))
  return DEFER;

if (expanded != NULL)
  {
  DEBUG(D_tls) debug_printf("tls_certificate file %s\n", expanded);
  if (!SSL_CTX_use_certificate_chain_file(sctx, CS expanded))
    return tls_error(string_sprintf(
      "SSL_CTX_use_certificate_chain_file file=%s", expanded),
        cbinfo->host, NULL);
  }

if (cbinfo->privatekey != NULL &&
    !expand_check(cbinfo->privatekey, US"tls_privatekey", &expanded))
  return DEFER;

/* If expansion was forced to fail, key_expanded will be NULL. If the result
of the expansion is an empty string, ignore it also, and assume the private
key is in the same file as the certificate. */

if (expanded != NULL && *expanded != 0)
  {
  DEBUG(D_tls) debug_printf("tls_privatekey file %s\n", expanded);
  if (!SSL_CTX_use_PrivateKey_file(sctx, CS expanded, SSL_FILETYPE_PEM))
    return tls_error(string_sprintf(
      "SSL_CTX_use_PrivateKey_file file=%s", expanded), cbinfo->host, NULL);
  }

#ifdef EXPERIMENTAL_OCSP
if (cbinfo->ocsp_file != NULL)
  {
  if (!expand_check(cbinfo->ocsp_file, US"tls_ocsp_file", &expanded))
    return DEFER;

  if (expanded != NULL && *expanded != 0)
    {
    DEBUG(D_tls) debug_printf("tls_ocsp_file %s\n", expanded);
    if (cbinfo->ocsp_file_expanded &&
        (Ustrcmp(expanded, cbinfo->ocsp_file_expanded) == 0))
      {
      DEBUG(D_tls)
        debug_printf("tls_ocsp_file value unchanged, using existing values.\n");
      } else {
        ocsp_load_response(sctx, cbinfo, expanded);
      }
    }
  }
#endif

return OK;
}




/*************************************************
*            Callback to handle SNI              *
*************************************************/

/* Called when acting as server during the TLS session setup if a Server Name
Indication extension was sent by the client.

API documentation is OpenSSL s_server.c implementation.

Arguments:
  s               SSL* of the current session
  ad              unknown (part of OpenSSL API) (unused)
  arg             Callback of "our" registered data

Returns:          SSL_TLSEXT_ERR_{OK,ALERT_WARNING,ALERT_FATAL,NOACK}
*/

#ifdef EXIM_HAVE_OPENSSL_TLSEXT
static int
tls_servername_cb(SSL *s, int *ad ARG_UNUSED, void *arg)
{
const char *servername = SSL_get_servername(s, TLSEXT_NAMETYPE_host_name);
tls_ext_ctx_cb *cbinfo = (tls_ext_ctx_cb *) arg;
int rc;
int old_pool = store_pool;

if (!servername)
  return SSL_TLSEXT_ERR_OK;

DEBUG(D_tls) debug_printf("Received TLS SNI \"%s\"%s\n", servername,
    reexpand_tls_files_for_sni ? "" : " (unused for certificate selection)");

/* Make the extension value available for expansion */
store_pool = POOL_PERM;
tls_in.sni = string_copy(US servername);
store_pool = old_pool;

if (!reexpand_tls_files_for_sni)
  return SSL_TLSEXT_ERR_OK;

/* Can't find an SSL_CTX_clone() or equivalent, so we do it manually;
not confident that memcpy wouldn't break some internal reference counting.
Especially since there's a references struct member, which would be off. */

server_sni = SSL_CTX_new(SSLv23_server_method());
if (!server_sni)
  {
  ERR_error_string(ERR_get_error(), ssl_errstring);
  DEBUG(D_tls) debug_printf("SSL_CTX_new() failed: %s\n", ssl_errstring);
  return SSL_TLSEXT_ERR_NOACK;
  }

/* Not sure how many of these are actually needed, since SSL object
already exists.  Might even need this selfsame callback, for reneg? */

SSL_CTX_set_info_callback(server_sni, SSL_CTX_get_info_callback(server_ctx));
SSL_CTX_set_mode(server_sni, SSL_CTX_get_mode(server_ctx));
SSL_CTX_set_options(server_sni, SSL_CTX_get_options(server_ctx));
SSL_CTX_set_timeout(server_sni, SSL_CTX_get_timeout(server_ctx));
SSL_CTX_set_tlsext_servername_callback(server_sni, tls_servername_cb);
SSL_CTX_set_tlsext_servername_arg(server_sni, cbinfo);
if (cbinfo->server_cipher_list)
  SSL_CTX_set_cipher_list(server_sni, CS cbinfo->server_cipher_list);
#ifdef EXPERIMENTAL_OCSP
if (cbinfo->ocsp_file)
  {
  SSL_CTX_set_tlsext_status_cb(server_sni, tls_stapling_cb);
  SSL_CTX_set_tlsext_status_arg(server_sni, cbinfo);
  }
#endif

rc = setup_certs(server_sni, tls_verify_certificates, tls_crl, NULL, FALSE, FALSE);
if (rc != OK) return SSL_TLSEXT_ERR_NOACK;

/* do this after setup_certs, because this can require the certs for verifying
OCSP information. */
rc = tls_expand_session_files(server_sni, cbinfo);
if (rc != OK) return SSL_TLSEXT_ERR_NOACK;

rc = init_dh(server_sni, cbinfo->dhparam, NULL);
if (rc != OK) return SSL_TLSEXT_ERR_NOACK;

DEBUG(D_tls) debug_printf("Switching SSL context.\n");
SSL_set_SSL_CTX(s, server_sni);

return SSL_TLSEXT_ERR_OK;
}
#endif /* EXIM_HAVE_OPENSSL_TLSEXT */




#ifdef EXPERIMENTAL_OCSP
/*************************************************
*        Callback to handle OCSP Stapling        *
*************************************************/

/* Called when acting as server during the TLS session setup if the client
requests OCSP information with a Certificate Status Request.

Documentation via openssl s_server.c and the Apache patch from the OpenSSL
project.

*/

static int
tls_stapling_cb(SSL *s, void *arg)
{
const tls_ext_ctx_cb *cbinfo = (tls_ext_ctx_cb *) arg;
uschar *response_der;
int response_der_len;

DEBUG(D_tls) debug_printf("Received TLS status request (OCSP stapling); %s response.\n",
    cbinfo->ocsp_response ? "have" : "lack");
if (!cbinfo->ocsp_response)
  return SSL_TLSEXT_ERR_NOACK;

response_der = NULL;
response_der_len = i2d_OCSP_RESPONSE(cbinfo->ocsp_response, &response_der);
if (response_der_len <= 0)
  return SSL_TLSEXT_ERR_NOACK;

SSL_set_tlsext_status_ocsp_resp(server_ssl, response_der, response_der_len);
return SSL_TLSEXT_ERR_OK;
}

#endif /* EXPERIMENTAL_OCSP */




/*************************************************
*            Initialize for TLS                  *
*************************************************/

/* Called from both server and client code, to do preliminary initialization of
the library.

Arguments:
  host            connected host, if client; NULL if server
  dhparam         DH parameter file
  certificate     certificate file
  privatekey      private key
  addr            address if client; NULL if server (for some randomness)

Returns:          OK/DEFER/FAIL
*/

static int
tls_init(SSL_CTX **ctxp, host_item *host, uschar *dhparam, uschar *certificate,
  uschar *privatekey,
#ifdef EXPERIMENTAL_OCSP
  uschar *ocsp_file,
#endif
  address_item *addr, tls_ext_ctx_cb ** cbp)
{
long init_options;
int rc;
BOOL okay;
tls_ext_ctx_cb *cbinfo;

cbinfo = store_malloc(sizeof(tls_ext_ctx_cb));
cbinfo->certificate = certificate;
cbinfo->privatekey = privatekey;
#ifdef EXPERIMENTAL_OCSP
cbinfo->ocsp_file = ocsp_file;
cbinfo->ocsp_file_expanded = NULL;
cbinfo->ocsp_response = NULL;
#endif
cbinfo->dhparam = dhparam;
cbinfo->host = host;

SSL_load_error_strings();          /* basic set up */
OpenSSL_add_ssl_algorithms();

#if (OPENSSL_VERSION_NUMBER >= 0x0090800fL) && !defined(OPENSSL_NO_SHA256)
/* SHA256 is becoming ever more popular. This makes sure it gets added to the
list of available digests. */
EVP_add_digest(EVP_sha256());
#endif

/* Create a context.
The OpenSSL docs in 1.0.1b have not been updated to clarify TLS variant
negotiation in the different methods; as far as I can tell, the only
*_{server,client}_method which allows negotiation is SSLv23, which exists even
when OpenSSL is built without SSLv2 support.
By disabling with openssl_options, we can let admins re-enable with the
existing knob. */

*ctxp = SSL_CTX_new((host == NULL)?
  SSLv23_server_method() : SSLv23_client_method());

if (*ctxp == NULL) return tls_error(US"SSL_CTX_new", host, NULL);

/* It turns out that we need to seed the random number generator this early in
order to get the full complement of ciphers to work. It took me roughly a day
of work to discover this by experiment.

On systems that have /dev/urandom, SSL may automatically seed itself from
there. Otherwise, we have to make something up as best we can. Double check
afterwards. */

if (!RAND_status())
  {
  randstuff r;
  gettimeofday(&r.tv, NULL);
  r.p = getpid();

  RAND_seed((uschar *)(&r), sizeof(r));
  RAND_seed((uschar *)big_buffer, big_buffer_size);
  if (addr != NULL) RAND_seed((uschar *)addr, sizeof(addr));

  if (!RAND_status())
    return tls_error(US"RAND_status", host,
      US"unable to seed random number generator");
  }

/* Set up the information callback, which outputs if debugging is at a suitable
level. */

SSL_CTX_set_info_callback(*ctxp, (void (*)())info_callback);

/* Automatically re-try reads/writes after renegotiation. */
(void) SSL_CTX_set_mode(*ctxp, SSL_MODE_AUTO_RETRY);

/* Apply administrator-supplied work-arounds.
Historically we applied just one requested option,
SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS, but when bug 994 requested a second, we
moved to an administrator-controlled list of options to specify and
grandfathered in the first one as the default value for "openssl_options".

No OpenSSL version number checks: the options we accept depend upon the
availability of the option value macros from OpenSSL.  */

okay = tls_openssl_options_parse(openssl_options, &init_options);
if (!okay)
  return tls_error(US"openssl_options parsing failed", host, NULL);

if (init_options)
  {
  DEBUG(D_tls) debug_printf("setting SSL CTX options: %#lx\n", init_options);
  if (!(SSL_CTX_set_options(*ctxp, init_options)))
    return tls_error(string_sprintf(
          "SSL_CTX_set_option(%#lx)", init_options), host, NULL);
  }
else
  DEBUG(D_tls) debug_printf("no SSL CTX options to set\n");

/* Initialize with DH parameters if supplied */

if (!init_dh(*ctxp, dhparam, host)) return DEFER;

/* Set up certificate and key (and perhaps OCSP info) */

rc = tls_expand_session_files(*ctxp, cbinfo);
if (rc != OK) return rc;

/* If we need to handle SNI, do so */
#ifdef EXIM_HAVE_OPENSSL_TLSEXT
if (host == NULL)
  {
#ifdef EXPERIMENTAL_OCSP
  /* We check ocsp_file, not ocsp_response, because we care about if
  the option exists, not what the current expansion might be, as SNI might
  change the certificate and OCSP file in use between now and the time the
  callback is invoked. */
  if (cbinfo->ocsp_file)
    {
    SSL_CTX_set_tlsext_status_cb(server_ctx, tls_stapling_cb);
    SSL_CTX_set_tlsext_status_arg(server_ctx, cbinfo);
    }
#endif
  /* We always do this, so that $tls_sni is available even if not used in
  tls_certificate */
  SSL_CTX_set_tlsext_servername_callback(*ctxp, tls_servername_cb);
  SSL_CTX_set_tlsext_servername_arg(*ctxp, cbinfo);
  }
#endif

/* Set up the RSA callback */

SSL_CTX_set_tmp_rsa_callback(*ctxp, rsa_callback);

/* Finally, set the timeout, and we are done */

SSL_CTX_set_timeout(*ctxp, ssl_session_timeout);
DEBUG(D_tls) debug_printf("Initialized TLS\n");

*cbp = cbinfo;

return OK;
}




/*************************************************
*           Get name of cipher in use            *
*************************************************/

/*
Argument:   pointer to an SSL structure for the connection
            buffer to use for answer
            size of buffer
	    pointer to number of bits for cipher
Returns:    nothing
*/

static void
construct_cipher_name(SSL *ssl, uschar *cipherbuf, int bsize, int *bits)
{
/* With OpenSSL 1.0.0a, this needs to be const but the documentation doesn't
yet reflect that.  It should be a safe change anyway, even 0.9.8 versions have
the accessor functions use const in the prototype. */
const SSL_CIPHER *c;
uschar *ver;

switch (ssl->session->ssl_version)
  {
  case SSL2_VERSION:
  ver = US"SSLv2";
  break;

  case SSL3_VERSION:
  ver = US"SSLv3";
  break;

  case TLS1_VERSION:
  ver = US"TLSv1";
  break;

#ifdef TLS1_1_VERSION
  case TLS1_1_VERSION:
  ver = US"TLSv1.1";
  break;
#endif

#ifdef TLS1_2_VERSION
  case TLS1_2_VERSION:
  ver = US"TLSv1.2";
  break;
#endif

  default:
  ver = US"UNKNOWN";
  }

c = (const SSL_CIPHER *) SSL_get_current_cipher(ssl);
SSL_CIPHER_get_bits(c, bits);

string_format(cipherbuf, bsize, "%s:%s:%u", ver,
  SSL_CIPHER_get_name(c), *bits);

DEBUG(D_tls) debug_printf("Cipher: %s\n", cipherbuf);
}





/*************************************************
*        Set up for verifying certificates       *
*************************************************/

/* Called by both client and server startup

Arguments:
  sctx          SSL_CTX* to initialise
  certs         certs file or NULL
  crl           CRL file or NULL
  host          NULL in a server; the remote host in a client
  optional      TRUE if called from a server for a host in tls_try_verify_hosts;
                otherwise passed as FALSE
  client        TRUE if called for client startup, FALSE for server startup

Returns:        OK/DEFER/FAIL
*/

static int
setup_certs(SSL_CTX *sctx, uschar *certs, uschar *crl, host_item *host, BOOL optional, BOOL client)
{
uschar *expcerts, *expcrl;

if (!expand_check(certs, US"tls_verify_certificates", &expcerts))
  return DEFER;

if (expcerts != NULL)
  {
  struct stat statbuf;
  if (!SSL_CTX_set_default_verify_paths(sctx))
    return tls_error(US"SSL_CTX_set_default_verify_paths", host, NULL);

  if (Ustat(expcerts, &statbuf) < 0)
    {
    log_write(0, LOG_MAIN|LOG_PANIC,
      "failed to stat %s for certificates", expcerts);
    return DEFER;
    }
  else
    {
    uschar *file, *dir;
    if ((statbuf.st_mode & S_IFMT) == S_IFDIR)
      { file = NULL; dir = expcerts; }
    else
      { file = expcerts; dir = NULL; }

    /* If a certificate file is empty, the next function fails with an
    unhelpful error message. If we skip it, we get the correct behaviour (no
    certificates are recognized, but the error message is still misleading (it
    says no certificate was supplied.) But this is better. */

    if ((file == NULL || statbuf.st_size > 0) &&
          !SSL_CTX_load_verify_locations(sctx, CS file, CS dir))
      return tls_error(US"SSL_CTX_load_verify_locations", host, NULL);

    if (file != NULL)
      {
      SSL_CTX_set_client_CA_list(sctx, SSL_load_client_CA_file(CS file));
      }
    }

  /* Handle a certificate revocation list. */

  #if OPENSSL_VERSION_NUMBER > 0x00907000L

  /* This bit of code is now the version supplied by Lars Mainka. (I have
   * merely reformatted it into the Exim code style.)

   * "From here I changed the code to add support for multiple crl's
   * in pem format in one file or to support hashed directory entries in
   * pem format instead of a file. This method now uses the library function
   * X509_STORE_load_locations to add the CRL location to the SSL context.
   * OpenSSL will then handle the verify against CA certs and CRLs by
   * itself in the verify callback." */

  if (!expand_check(crl, US"tls_crl", &expcrl)) return DEFER;
  if (expcrl != NULL && *expcrl != 0)
    {
    struct stat statbufcrl;
    if (Ustat(expcrl, &statbufcrl) < 0)
      {
      log_write(0, LOG_MAIN|LOG_PANIC,
        "failed to stat %s for certificates revocation lists", expcrl);
      return DEFER;
      }
    else
      {
      /* is it a file or directory? */
      uschar *file, *dir;
      X509_STORE *cvstore = SSL_CTX_get_cert_store(sctx);
      if ((statbufcrl.st_mode & S_IFMT) == S_IFDIR)
        {
        file = NULL;
        dir = expcrl;
        DEBUG(D_tls) debug_printf("SSL CRL value is a directory %s\n", dir);
        }
      else
        {
        file = expcrl;
        dir = NULL;
        DEBUG(D_tls) debug_printf("SSL CRL value is a file %s\n", file);
        }
      if (X509_STORE_load_locations(cvstore, CS file, CS dir) == 0)
        return tls_error(US"X509_STORE_load_locations", host, NULL);

      /* setting the flags to check against the complete crl chain */

      X509_STORE_set_flags(cvstore,
        X509_V_FLAG_CRL_CHECK|X509_V_FLAG_CRL_CHECK_ALL);
      }
    }

  #endif  /* OPENSSL_VERSION_NUMBER > 0x00907000L */

  /* If verification is optional, don't fail if no certificate */

  SSL_CTX_set_verify(sctx,
    SSL_VERIFY_PEER | (optional? 0 : SSL_VERIFY_FAIL_IF_NO_PEER_CERT),
    client ? verify_callback_client : verify_callback_server);
  }

return OK;
}



/*************************************************
*       Start a TLS session in a server          *
*************************************************/

/* This is called when Exim is running as a server, after having received
the STARTTLS command. It must respond to that command, and then negotiate
a TLS session.

Arguments:
  require_ciphers   allowed ciphers

Returns:            OK on success
                    DEFER for errors before the start of the negotiation
                    FAIL for errors during the negotation; the server can't
                      continue running.
*/

int
tls_server_start(const uschar *require_ciphers)
{
int rc;
uschar *expciphers;
tls_ext_ctx_cb *cbinfo;
static uschar cipherbuf[256];

/* Check for previous activation */

if (tls_in.active >= 0)
  {
  tls_error(US"STARTTLS received after TLS started", NULL, US"");
  smtp_printf("554 Already in TLS\r\n");
  return FAIL;
  }

/* Initialize the SSL library. If it fails, it will already have logged
the error. */

rc = tls_init(&server_ctx, NULL, tls_dhparam, tls_certificate, tls_privatekey,
#ifdef EXPERIMENTAL_OCSP
    tls_ocsp_file,
#endif
    NULL, &server_static_cbinfo);
if (rc != OK) return rc;
cbinfo = server_static_cbinfo;

if (!expand_check(require_ciphers, US"tls_require_ciphers", &expciphers))
  return FAIL;

/* In OpenSSL, cipher components are separated by hyphens. In GnuTLS, they
were historically separated by underscores. So that I can use either form in my
tests, and also for general convenience, we turn underscores into hyphens here.
*/

if (expciphers != NULL)
  {
  uschar *s = expciphers;
  while (*s != 0) { if (*s == '_') *s = '-'; s++; }
  DEBUG(D_tls) debug_printf("required ciphers: %s\n", expciphers);
  if (!SSL_CTX_set_cipher_list(server_ctx, CS expciphers))
    return tls_error(US"SSL_CTX_set_cipher_list", NULL, NULL);
  cbinfo->server_cipher_list = expciphers;
  }

/* If this is a host for which certificate verification is mandatory or
optional, set up appropriately. */

tls_in.certificate_verified = FALSE;
server_verify_callback_called = FALSE;

if (verify_check_host(&tls_verify_hosts) == OK)
  {
  rc = setup_certs(server_ctx, tls_verify_certificates, tls_crl, NULL, FALSE, FALSE);
  if (rc != OK) return rc;
  server_verify_optional = FALSE;
  }
else if (verify_check_host(&tls_try_verify_hosts) == OK)
  {
  rc = setup_certs(server_ctx, tls_verify_certificates, tls_crl, NULL, TRUE, FALSE);
  if (rc != OK) return rc;
  server_verify_optional = TRUE;
  }

/* Prepare for new connection */

if ((server_ssl = SSL_new(server_ctx)) == NULL) return tls_error(US"SSL_new", NULL, NULL);

/* Warning: we used to SSL_clear(ssl) here, it was removed.
 *
 * With the SSL_clear(), we get strange interoperability bugs with
 * OpenSSL 1.0.1b and TLS1.1/1.2.  It looks as though this may be a bug in
 * OpenSSL itself, as a clear should not lead to inability to follow protocols.
 *
 * The SSL_clear() call is to let an existing SSL* be reused, typically after
 * session shutdown.  In this case, we have a brand new object and there's no
 * obvious reason to immediately clear it.  I'm guessing that this was
 * originally added because of incomplete initialisation which the clear fixed,
 * in some historic release.
 */

/* Set context and tell client to go ahead, except in the case of TLS startup
on connection, where outputting anything now upsets the clients and tends to
make them disconnect. We need to have an explicit fflush() here, to force out
the response. Other smtp_printf() calls do not need it, because in non-TLS
mode, the fflush() happens when smtp_getc() is called. */

SSL_set_session_id_context(server_ssl, sid_ctx, Ustrlen(sid_ctx));
if (!tls_in.on_connect)
  {
  smtp_printf("220 TLS go ahead\r\n");
  fflush(smtp_out);
  }

/* Now negotiate the TLS session. We put our own timer on it, since it seems
that the OpenSSL library doesn't. */

SSL_set_wfd(server_ssl, fileno(smtp_out));
SSL_set_rfd(server_ssl, fileno(smtp_in));
SSL_set_accept_state(server_ssl);

DEBUG(D_tls) debug_printf("Calling SSL_accept\n");

sigalrm_seen = FALSE;
if (smtp_receive_timeout > 0) alarm(smtp_receive_timeout);
rc = SSL_accept(server_ssl);
alarm(0);

if (rc <= 0)
  {
  tls_error(US"SSL_accept", NULL, sigalrm_seen ? US"timed out" : NULL);
  if (ERR_get_error() == 0)
    log_write(0, LOG_MAIN,
        "TLS client disconnected cleanly (rejected our certificate?)");
  return FAIL;
  }

DEBUG(D_tls) debug_printf("SSL_accept was successful\n");

/* TLS has been set up. Adjust the input functions to read via TLS,
and initialize things. */

construct_cipher_name(server_ssl, cipherbuf, sizeof(cipherbuf), &tls_in.bits);
tls_in.cipher = cipherbuf;

DEBUG(D_tls)
  {
  uschar buf[2048];
  if (SSL_get_shared_ciphers(server_ssl, CS buf, sizeof(buf)) != NULL)
    debug_printf("Shared ciphers: %s\n", buf);
  }


/* Only used by the server-side tls (tls_in), including tls_getc.
   Client-side (tls_out) reads (seem to?) go via
   smtp_read_response()/ip_recv().
   Hence no need to duplicate for _in and _out.
 */
ssl_xfer_buffer = store_malloc(ssl_xfer_buffer_size);
ssl_xfer_buffer_lwm = ssl_xfer_buffer_hwm = 0;
ssl_xfer_eof = ssl_xfer_error = 0;

receive_getc = tls_getc;
receive_ungetc = tls_ungetc;
receive_feof = tls_feof;
receive_ferror = tls_ferror;
receive_smtp_buffered = tls_smtp_buffered;

tls_in.active = fileno(smtp_out);
return OK;
}





/*************************************************
*    Start a TLS session in a client             *
*************************************************/

/* Called from the smtp transport after STARTTLS has been accepted.

Argument:
  fd               the fd of the connection
  host             connected host (for messages)
  addr             the first address
  dhparam          DH parameter file
  certificate      certificate file
  privatekey       private key file
  sni              TLS SNI to send to remote host
  verify_certs     file for certificate verify
  crl              file containing CRL
  require_ciphers  list of allowed ciphers
  dh_min_bits      minimum number of bits acceptable in server's DH prime
                   (unused in OpenSSL)
  timeout          startup timeout

Returns:           OK on success
                   FAIL otherwise - note that tls_error() will not give DEFER
                     because this is not a server
*/

int
tls_client_start(int fd, host_item *host, address_item *addr, uschar *dhparam,
  uschar *certificate, uschar *privatekey, uschar *sni,
  uschar *verify_certs, uschar *crl,
  uschar *require_ciphers, int dh_min_bits ARG_UNUSED, int timeout)
{
static uschar txt[256];
uschar *expciphers;
X509* server_cert;
int rc;
static uschar cipherbuf[256];

rc = tls_init(&client_ctx, host, dhparam, certificate, privatekey,
#ifdef EXPERIMENTAL_OCSP
    NULL,
#endif
    addr, &client_static_cbinfo);
if (rc != OK) return rc;

tls_out.certificate_verified = FALSE;
client_verify_callback_called = FALSE;

if (!expand_check(require_ciphers, US"tls_require_ciphers", &expciphers))
  return FAIL;

/* In OpenSSL, cipher components are separated by hyphens. In GnuTLS, they
are separated by underscores. So that I can use either form in my tests, and
also for general convenience, we turn underscores into hyphens here. */

if (expciphers != NULL)
  {
  uschar *s = expciphers;
  while (*s != 0) { if (*s == '_') *s = '-'; s++; }
  DEBUG(D_tls) debug_printf("required ciphers: %s\n", expciphers);
  if (!SSL_CTX_set_cipher_list(client_ctx, CS expciphers))
    return tls_error(US"SSL_CTX_set_cipher_list", host, NULL);
  }

rc = setup_certs(client_ctx, verify_certs, crl, host, FALSE, TRUE);
if (rc != OK) return rc;

if ((client_ssl = SSL_new(client_ctx)) == NULL) return tls_error(US"SSL_new", host, NULL);
SSL_set_session_id_context(client_ssl, sid_ctx, Ustrlen(sid_ctx));
SSL_set_fd(client_ssl, fd);
SSL_set_connect_state(client_ssl);

if (sni)
  {
  if (!expand_check(sni, US"tls_sni", &tls_out.sni))
    return FAIL;
  if (tls_out.sni == NULL)
    {
    DEBUG(D_tls) debug_printf("Setting TLS SNI forced to fail, not sending\n");
    }
  else if (!Ustrlen(tls_out.sni))
    tls_out.sni = NULL;
  else
    {
#ifdef EXIM_HAVE_OPENSSL_TLSEXT
    DEBUG(D_tls) debug_printf("Setting TLS SNI \"%s\"\n", tls_out.sni);
    SSL_set_tlsext_host_name(client_ssl, tls_out.sni);
#else
    DEBUG(D_tls)
      debug_printf("OpenSSL at build-time lacked SNI support, ignoring \"%s\"\n",
          tls_sni);
#endif
    }
  }

/* There doesn't seem to be a built-in timeout on connection. */

DEBUG(D_tls) debug_printf("Calling SSL_connect\n");
sigalrm_seen = FALSE;
alarm(timeout);
rc = SSL_connect(client_ssl);
alarm(0);

if (rc <= 0)
  return tls_error(US"SSL_connect", host, sigalrm_seen ? US"timed out" : NULL);

DEBUG(D_tls) debug_printf("SSL_connect succeeded\n");

/* Beware anonymous ciphers which lead to server_cert being NULL */
server_cert = SSL_get_peer_certificate (client_ssl);
if (server_cert)
  {
  tls_out.peerdn = US X509_NAME_oneline(X509_get_subject_name(server_cert),
    CS txt, sizeof(txt));
  tls_out.peerdn = txt;
  }
else
  tls_out.peerdn = NULL;

construct_cipher_name(client_ssl, cipherbuf, sizeof(cipherbuf), &tls_out.bits);
tls_out.cipher = cipherbuf;

tls_out.active = fd;
return OK;
}





/*************************************************
*            TLS version of getc                 *
*************************************************/

/* This gets the next byte from the TLS input buffer. If the buffer is empty,
it refills the buffer via the SSL reading function.

Arguments:  none
Returns:    the next character or EOF

Only used by the server-side TLS.
*/

int
tls_getc(void)
{
if (ssl_xfer_buffer_lwm >= ssl_xfer_buffer_hwm)
  {
  int error;
  int inbytes;

  DEBUG(D_tls) debug_printf("Calling SSL_read(%p, %p, %u)\n", server_ssl,
    ssl_xfer_buffer, ssl_xfer_buffer_size);

  if (smtp_receive_timeout > 0) alarm(smtp_receive_timeout);
  inbytes = SSL_read(server_ssl, CS ssl_xfer_buffer, ssl_xfer_buffer_size);
  error = SSL_get_error(server_ssl, inbytes);
  alarm(0);

  /* SSL_ERROR_ZERO_RETURN appears to mean that the SSL session has been
  closed down, not that the socket itself has been closed down. Revert to
  non-SSL handling. */

  if (error == SSL_ERROR_ZERO_RETURN)
    {
    DEBUG(D_tls) debug_printf("Got SSL_ERROR_ZERO_RETURN\n");

    receive_getc = smtp_getc;
    receive_ungetc = smtp_ungetc;
    receive_feof = smtp_feof;
    receive_ferror = smtp_ferror;
    receive_smtp_buffered = smtp_buffered;

    SSL_free(server_ssl);
    server_ssl = NULL;
    tls_in.active = -1;
    tls_in.bits = 0;
    tls_in.cipher = NULL;
    tls_in.peerdn = NULL;
    tls_in.sni = NULL;

    return smtp_getc();
    }

  /* Handle genuine errors */

  else if (error == SSL_ERROR_SSL)
    {
    ERR_error_string(ERR_get_error(), ssl_errstring);
    log_write(0, LOG_MAIN, "TLS error (SSL_read): %s", ssl_errstring);
    ssl_xfer_error = 1;
    return EOF;
    }

  else if (error != SSL_ERROR_NONE)
    {
    DEBUG(D_tls) debug_printf("Got SSL error %d\n", error);
    ssl_xfer_error = 1;
    return EOF;
    }

#ifndef DISABLE_DKIM
  dkim_exim_verify_feed(ssl_xfer_buffer, inbytes);
#endif
  ssl_xfer_buffer_hwm = inbytes;
  ssl_xfer_buffer_lwm = 0;
  }

/* Something in the buffer; return next uschar */

return ssl_xfer_buffer[ssl_xfer_buffer_lwm++];
}



/*************************************************
*          Read bytes from TLS channel           *
*************************************************/

/*
Arguments:
  buff      buffer of data
  len       size of buffer

Returns:    the number of bytes read
            -1 after a failed read

Only used by the client-side TLS.
*/

int
tls_read(BOOL is_server, uschar *buff, size_t len)
{
SSL *ssl = is_server ? server_ssl : client_ssl;
int inbytes;
int error;

DEBUG(D_tls) debug_printf("Calling SSL_read(%p, %p, %u)\n", ssl,
  buff, (unsigned int)len);

inbytes = SSL_read(ssl, CS buff, len);
error = SSL_get_error(ssl, inbytes);

if (error == SSL_ERROR_ZERO_RETURN)
  {
  DEBUG(D_tls) debug_printf("Got SSL_ERROR_ZERO_RETURN\n");
  return -1;
  }
else if (error != SSL_ERROR_NONE)
  {
  return -1;
  }

return inbytes;
}





/*************************************************
*         Write bytes down TLS channel           *
*************************************************/

/*
Arguments:
  is_server channel specifier
  buff      buffer of data
  len       number of bytes

Returns:    the number of bytes after a successful write,
            -1 after a failed write

Used by both server-side and client-side TLS.
*/

int
tls_write(BOOL is_server, const uschar *buff, size_t len)
{
int outbytes;
int error;
int left = len;
SSL *ssl = is_server ? server_ssl : client_ssl;

DEBUG(D_tls) debug_printf("tls_do_write(%p, %d)\n", buff, left);
while (left > 0)
  {
  DEBUG(D_tls) debug_printf("SSL_write(SSL, %p, %d)\n", buff, left);
  outbytes = SSL_write(ssl, CS buff, left);
  error = SSL_get_error(ssl, outbytes);
  DEBUG(D_tls) debug_printf("outbytes=%d error=%d\n", outbytes, error);
  switch (error)
    {
    case SSL_ERROR_SSL:
    ERR_error_string(ERR_get_error(), ssl_errstring);
    log_write(0, LOG_MAIN, "TLS error (SSL_write): %s", ssl_errstring);
    return -1;

    case SSL_ERROR_NONE:
    left -= outbytes;
    buff += outbytes;
    break;

    case SSL_ERROR_ZERO_RETURN:
    log_write(0, LOG_MAIN, "SSL channel closed on write");
    return -1;

    case SSL_ERROR_SYSCALL:
    log_write(0, LOG_MAIN, "SSL_write: (from %s) syscall: %s",
      sender_fullhost ? sender_fullhost : US"<unknown>",
      strerror(errno));

    default:
    log_write(0, LOG_MAIN, "SSL_write error %d", error);
    return -1;
    }
  }
return len;
}



/*************************************************
*         Close down a TLS session               *
*************************************************/

/* This is also called from within a delivery subprocess forked from the
daemon, to shut down the TLS library, without actually doing a shutdown (which
would tamper with the SSL session in the parent process).

Arguments:   TRUE if SSL_shutdown is to be called
Returns:     nothing

Used by both server-side and client-side TLS.
*/

void
tls_close(BOOL is_server, BOOL shutdown)
{
SSL **sslp = is_server ? &server_ssl : &client_ssl;
int *fdp = is_server ? &tls_in.active : &tls_out.active;

if (*fdp < 0) return;  /* TLS was not active */

if (shutdown)
  {
  DEBUG(D_tls) debug_printf("tls_close(): shutting down SSL\n");
  SSL_shutdown(*sslp);
  }

SSL_free(*sslp);
*sslp = NULL;

*fdp = -1;
}




/*************************************************
*  Let tls_require_ciphers be checked at startup *
*************************************************/

/* The tls_require_ciphers option, if set, must be something which the
library can parse.

Returns:     NULL on success, or error message
*/

uschar *
tls_validate_require_cipher(void)
{
SSL_CTX *ctx;
uschar *s, *expciphers, *err;

/* this duplicates from tls_init(), we need a better "init just global
state, for no specific purpose" singleton function of our own */

SSL_load_error_strings();
OpenSSL_add_ssl_algorithms();
#if (OPENSSL_VERSION_NUMBER >= 0x0090800fL) && !defined(OPENSSL_NO_SHA256)
/* SHA256 is becoming ever more popular. This makes sure it gets added to the
list of available digests. */
EVP_add_digest(EVP_sha256());
#endif

if (!(tls_require_ciphers && *tls_require_ciphers))
  return NULL;

if (!expand_check(tls_require_ciphers, US"tls_require_ciphers", &expciphers))
  return US"failed to expand tls_require_ciphers";

if (!(expciphers && *expciphers))
  return NULL;

/* normalisation ripped from above */
s = expciphers;
while (*s != 0) { if (*s == '_') *s = '-'; s++; }

err = NULL;

ctx = SSL_CTX_new(SSLv23_server_method());
if (!ctx)
  {
  ERR_error_string(ERR_get_error(), ssl_errstring);
  return string_sprintf("SSL_CTX_new() failed: %s", ssl_errstring);
  }

DEBUG(D_tls)
  debug_printf("tls_require_ciphers expands to \"%s\"\n", expciphers);

if (!SSL_CTX_set_cipher_list(ctx, CS expciphers))
  {
  ERR_error_string(ERR_get_error(), ssl_errstring);
  err = string_sprintf("SSL_CTX_set_cipher_list(%s) failed", expciphers);
  }

SSL_CTX_free(ctx);

return err;
}




/*************************************************
*         Report the library versions.           *
*************************************************/

/* There have historically been some issues with binary compatibility in
OpenSSL libraries; if Exim (like many other applications) is built against
one version of OpenSSL but the run-time linker picks up another version,
it can result in serious failures, including crashing with a SIGSEGV.  So
report the version found by the compiler and the run-time version.

Arguments:   a FILE* to print the results to
Returns:     nothing
*/

void
tls_version_report(FILE *f)
{
fprintf(f, "Library version: OpenSSL: Compile: %s\n"
           "                          Runtime: %s\n",
           OPENSSL_VERSION_TEXT,
           SSLeay_version(SSLEAY_VERSION));
}




/*************************************************
*            Random number generation            *
*************************************************/

/* Pseudo-random number generation.  The result is not expected to be
cryptographically strong but not so weak that someone will shoot themselves
in the foot using it as a nonce in input in some email header scheme or
whatever weirdness they'll twist this into.  The result should handle fork()
and avoid repeating sequences.  OpenSSL handles that for us.

Arguments:
  max       range maximum
Returns     a random number in range [0, max-1]
*/

int
vaguely_random_number(int max)
{
unsigned int r;
int i, needed_len;
uschar *p;
uschar smallbuf[sizeof(r)];

if (max <= 1)
  return 0;

/* OpenSSL auto-seeds from /dev/random, etc, but this a double-check. */
if (!RAND_status())
  {
  randstuff r;
  gettimeofday(&r.tv, NULL);
  r.p = getpid();

  RAND_seed((uschar *)(&r), sizeof(r));
  }
/* We're after pseudo-random, not random; if we still don't have enough data
in the internal PRNG then our options are limited.  We could sleep and hope
for entropy to come along (prayer technique) but if the system is so depleted
in the first place then something is likely to just keep taking it.  Instead,
we'll just take whatever little bit of pseudo-random we can still manage to
get. */

needed_len = sizeof(r);
/* Don't take 8 times more entropy than needed if int is 8 octets and we were
asked for a number less than 10. */
for (r = max, i = 0; r; ++i)
  r >>= 1;
i = (i + 7) / 8;
if (i < needed_len)
  needed_len = i;

/* We do not care if crypto-strong */
i = RAND_pseudo_bytes(smallbuf, needed_len);
if (i < 0)
  {
  DEBUG(D_all)
    debug_printf("OpenSSL RAND_pseudo_bytes() not supported by RAND method, using fallback.\n");
  return vaguely_random_number_fallback(max);
  }

r = 0;
for (p = smallbuf; needed_len; --needed_len, ++p)
  {
  r *= 256;
  r += *p;
  }

/* We don't particularly care about weighted results; if someone wants
smooth distribution and cares enough then they should submit a patch then. */
return r % max;
}




/*************************************************
*        OpenSSL option parse                    *
*************************************************/

/* Parse one option for tls_openssl_options_parse below

Arguments:
  name    one option name
  value   place to store a value for it
Returns   success or failure in parsing
*/

struct exim_openssl_option {
  uschar *name;
  long    value;
};
/* We could use a macro to expand, but we need the ifdef and not all the
options document which version they were introduced in.  Policylet: include
all options unless explicitly for DTLS, let the administrator choose which
to apply.

This list is current as of:
  ==>  1.0.1b  <==  */
static struct exim_openssl_option exim_openssl_options[] = {
/* KEEP SORTED ALPHABETICALLY! */
#ifdef SSL_OP_ALL
  { US"all", SSL_OP_ALL },
#endif
#ifdef SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION
  { US"allow_unsafe_legacy_renegotiation", SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION },
#endif
#ifdef SSL_OP_CIPHER_SERVER_PREFERENCE
  { US"cipher_server_preference", SSL_OP_CIPHER_SERVER_PREFERENCE },
#endif
#ifdef SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS
  { US"dont_insert_empty_fragments", SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS },
#endif
#ifdef SSL_OP_EPHEMERAL_RSA
  { US"ephemeral_rsa", SSL_OP_EPHEMERAL_RSA },
#endif
#ifdef SSL_OP_LEGACY_SERVER_CONNECT
  { US"legacy_server_connect", SSL_OP_LEGACY_SERVER_CONNECT },
#endif
#ifdef SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER
  { US"microsoft_big_sslv3_buffer", SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER },
#endif
#ifdef SSL_OP_MICROSOFT_SESS_ID_BUG
  { US"microsoft_sess_id_bug", SSL_OP_MICROSOFT_SESS_ID_BUG },
#endif
#ifdef SSL_OP_MSIE_SSLV2_RSA_PADDING
  { US"msie_sslv2_rsa_padding", SSL_OP_MSIE_SSLV2_RSA_PADDING },
#endif
#ifdef SSL_OP_NETSCAPE_CHALLENGE_BUG
  { US"netscape_challenge_bug", SSL_OP_NETSCAPE_CHALLENGE_BUG },
#endif
#ifdef SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG
  { US"netscape_reuse_cipher_change_bug", SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG },
#endif
#ifdef SSL_OP_NO_COMPRESSION
  { US"no_compression", SSL_OP_NO_COMPRESSION },
#endif
#ifdef SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION
  { US"no_session_resumption_on_renegotiation", SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION },
#endif
#ifdef SSL_OP_NO_SSLv2
  { US"no_sslv2", SSL_OP_NO_SSLv2 },
#endif
#ifdef SSL_OP_NO_SSLv3
  { US"no_sslv3", SSL_OP_NO_SSLv3 },
#endif
#ifdef SSL_OP_NO_TICKET
  { US"no_ticket", SSL_OP_NO_TICKET },
#endif
#ifdef SSL_OP_NO_TLSv1
  { US"no_tlsv1", SSL_OP_NO_TLSv1 },
#endif
#ifdef SSL_OP_NO_TLSv1_1
#if SSL_OP_NO_TLSv1_1 == 0x00000400L
  /* Error in chosen value in 1.0.1a; see first item in CHANGES for 1.0.1b */
#warning OpenSSL 1.0.1a uses a bad value for SSL_OP_NO_TLSv1_1, ignoring
#else
  { US"no_tlsv1_1", SSL_OP_NO_TLSv1_1 },
#endif
#endif
#ifdef SSL_OP_NO_TLSv1_2
  { US"no_tlsv1_2", SSL_OP_NO_TLSv1_2 },
#endif
#ifdef SSL_OP_SINGLE_DH_USE
  { US"single_dh_use", SSL_OP_SINGLE_DH_USE },
#endif
#ifdef SSL_OP_SINGLE_ECDH_USE
  { US"single_ecdh_use", SSL_OP_SINGLE_ECDH_USE },
#endif
#ifdef SSL_OP_SSLEAY_080_CLIENT_DH_BUG
  { US"ssleay_080_client_dh_bug", SSL_OP_SSLEAY_080_CLIENT_DH_BUG },
#endif
#ifdef SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG
  { US"sslref2_reuse_cert_type_bug", SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG },
#endif
#ifdef SSL_OP_TLS_BLOCK_PADDING_BUG
  { US"tls_block_padding_bug", SSL_OP_TLS_BLOCK_PADDING_BUG },
#endif
#ifdef SSL_OP_TLS_D5_BUG
  { US"tls_d5_bug", SSL_OP_TLS_D5_BUG },
#endif
#ifdef SSL_OP_TLS_ROLLBACK_BUG
  { US"tls_rollback_bug", SSL_OP_TLS_ROLLBACK_BUG },
#endif
};
static int exim_openssl_options_size =
  sizeof(exim_openssl_options)/sizeof(struct exim_openssl_option);


static BOOL
tls_openssl_one_option_parse(uschar *name, long *value)
{
int first = 0;
int last = exim_openssl_options_size;
while (last > first)
  {
  int middle = (first + last)/2;
  int c = Ustrcmp(name, exim_openssl_options[middle].name);
  if (c == 0)
    {
    *value = exim_openssl_options[middle].value;
    return TRUE;
    }
  else if (c > 0)
    first = middle + 1;
  else
    last = middle;
  }
return FALSE;
}




/*************************************************
*        OpenSSL option parsing logic            *
*************************************************/

/* OpenSSL has a number of compatibility options which an administrator might
reasonably wish to set.  Interpret a list similarly to decode_bits(), so that
we look like log_selector.

Arguments:
  option_spec  the administrator-supplied string of options
  results      ptr to long storage for the options bitmap
Returns        success or failure
*/

BOOL
tls_openssl_options_parse(uschar *option_spec, long *results)
{
long result, item;
uschar *s, *end;
uschar keep_c;
BOOL adding, item_parsed;

result = 0L;
/* Prior to 4.80 we or'd in SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS; removed
 * from default because it increases BEAST susceptibility. */
#ifdef SSL_OP_NO_SSLv2
result |= SSL_OP_NO_SSLv2;
#endif

if (option_spec == NULL)
  {
  *results = result;
  return TRUE;
  }

for (s=option_spec; *s != '\0'; /**/)
  {
  while (isspace(*s)) ++s;
  if (*s == '\0')
    break;
  if (*s != '+' && *s != '-')
    {
    DEBUG(D_tls) debug_printf("malformed openssl option setting: "
        "+ or - expected but found \"%s\"\n", s);
    return FALSE;
    }
  adding = *s++ == '+';
  for (end = s; (*end != '\0') && !isspace(*end); ++end) /**/ ;
  keep_c = *end;
  *end = '\0';
  item_parsed = tls_openssl_one_option_parse(s, &item);
  if (!item_parsed)
    {
    DEBUG(D_tls) debug_printf("openssl option setting unrecognised: \"%s\"\n", s);
    return FALSE;
    }
  DEBUG(D_tls) debug_printf("openssl option, %s from %lx: %lx (%s)\n",
      adding ? "adding" : "removing", result, item, s);
  if (adding)
    result |= item;
  else
    result &= ~item;
  *end = keep_c;
  s = end;
  }

*results = result;
return TRUE;
}

/* End of tls-openssl.c */
