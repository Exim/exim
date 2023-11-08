/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) The Exim Maintainers 2020 - 2023 */
/* Copyright (c) University of Cambridge 1995 - 2019 */
/* See the file NOTICE for conditions of use and distribution. */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/* Portions Copyright (c) The OpenSSL Project 1999 */

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
#ifndef OPENSSL_NO_ECDH
# include <openssl/ec.h>
#endif
#ifndef DISABLE_OCSP
# include <openssl/ocsp.h>
#endif
#ifdef SUPPORT_DANE
# include "danessl.h"
#endif


#ifndef DISABLE_OCSP
# define EXIM_OCSP_SKEW_SECONDS (300L)
# define EXIM_OCSP_MAX_AGE (-1L)
#endif

#if OPENSSL_VERSION_NUMBER >= 0x0090806fL && !defined(OPENSSL_NO_TLSEXT)
# define EXIM_HAVE_OPENSSL_TLSEXT
#endif
#if OPENSSL_VERSION_NUMBER >= 0x00908000L
# define EXIM_HAVE_RSA_GENKEY_EX
#endif
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
# define EXIM_HAVE_OCSP_RESP_COUNT
# define OPENSSL_AUTO_SHA256
# define OPENSSL_MIN_PROTO_VERSION
#else
# define EXIM_HAVE_EPHEM_RSA_KEX
# define EXIM_HAVE_RAND_PSEUDO
#endif
#if (OPENSSL_VERSION_NUMBER >= 0x0090800fL) && !defined(OPENSSL_NO_SHA256)
# define EXIM_HAVE_SHA256
#endif

/* X509_check_host provides sane certificate hostname checking, but was added
to OpenSSL late, after other projects forked off the code-base.  So in
addition to guarding against the base version number, beware that LibreSSL
does not (at this time) support this function.

If LibreSSL gains a different API, perhaps via libtls, then we'll probably
opt to disentangle and ask a LibreSSL user to provide glue for a third
crypto provider for libtls instead of continuing to tie the OpenSSL glue
into even twistier knots.  If LibreSSL gains the same API, we can just
change this guard and punt the issue for a while longer. */

#ifndef LIBRESSL_VERSION_NUMBER
# if OPENSSL_VERSION_NUMBER >= 0x010100000L
#  define EXIM_HAVE_OPENSSL_CHECKHOST
#  define EXIM_HAVE_OPENSSL_DH_BITS
#  define EXIM_HAVE_OPENSSL_TLS_METHOD
#  define EXIM_HAVE_OPENSSL_KEYLOG
#  define EXIM_HAVE_OPENSSL_CIPHER_GET_ID
#  define EXIM_HAVE_SESSION_TICKET
#  define EXIM_HAVE_OPENSSL_TRACE
#  define EXIM_HAVE_OPENSSL_GET0_SERIAL
#  define EXIM_HAVE_OPENSSL_OCSP_RESP_GET0_CERTS
#  define EXIM_HAVE_SSL_GET0_VERIFIED_CHAIN
#  ifndef DISABLE_OCSP
#   define EXIM_HAVE_OCSP
#  endif
#  define EXIM_HAVE_ALPN /* fail ret from hshake-cb is ignored by LibreSSL */
# else
#  define EXIM_NEED_OPENSSL_INIT
# endif
# if OPENSSL_VERSION_NUMBER >= 0x010000000L \
    && (OPENSSL_VERSION_NUMBER & 0x0000ff000L) >= 0x000002000L
#  define EXIM_HAVE_OPENSSL_CHECKHOST
# endif
#endif

#if LIBRESSL_VERSION_NUMBER >= 0x3040000fL
# define EXIM_HAVE_OPENSSL_CIPHER_GET_ID
#endif

#if !defined(LIBRESSL_VERSION_NUMBER) && (OPENSSL_VERSION_NUMBER >= 0x030000000L)
# define EXIM_HAVE_EXPORT_CHNL_BNGNG
# define EXIM_HAVE_OPENSSL_X509_STORE_GET1_ALL_CERTS
#endif

#if !defined(LIBRESSL_VERSION_NUMBER) \
    || LIBRESSL_VERSION_NUMBER >= 0x20010000L
# if !defined(OPENSSL_NO_ECDH)
#  if OPENSSL_VERSION_NUMBER >= 0x0090800fL
#   define EXIM_HAVE_ECDH
#  endif
#  if OPENSSL_VERSION_NUMBER >= 0x10002000L
#   define EXIM_HAVE_OPENSSL_EC_NIST2NID
#  endif
# endif
#endif

#ifndef LIBRESSL_VERSION_NUMBER
# if OPENSSL_VERSION_NUMBER >= 0x010101000L
#  define OPENSSL_HAVE_KEYLOG_CB
#  define OPENSSL_HAVE_NUM_TICKETS
#  define EXIM_HAVE_OPENSSL_CIPHER_STD_NAME
#  define EXIM_HAVE_EXP_CHNL_BNGNG
#  define EXIM_HAVE_OPENSSL_OCSP_RESP_GET0_SIGNER
#  define EXIM_HAVE_OPENSSL_SET1_GROUPS
# else
#  define OPENSSL_BAD_SRVR_OURCERT
# endif
#endif

#if !defined(LIBRESSL_VERSION_NUMBER) && (OPENSSL_VERSION_NUMBER >= 0x010002000L)
# define EXIM_HAVE_EXPORT_CHNL_BNGNG
#endif

#if !defined(EXIM_HAVE_OPENSSL_TLSEXT) && !defined(DISABLE_OCSP)
# warning "OpenSSL library version too old; define DISABLE_OCSP in Makefile"
# define DISABLE_OCSP
#endif

#ifndef DISABLE_TLS_RESUME
# if OPENSSL_VERSION_NUMBER < 0x0101010L
#  error OpenSSL version too old for session-resumption
# endif
#endif

#ifdef EXIM_HAVE_OPENSSL_CHECKHOST
# include <openssl/x509v3.h>
#endif

#ifndef EXIM_HAVE_OPENSSL_CIPHER_STD_NAME
# ifndef EXIM_HAVE_OPENSSL_CIPHER_GET_ID
#  define SSL_CIPHER_get_id(c) (c->id)
# endif
# ifndef MACRO_PREDEF
#  include "tls-cipher-stdname.c"
# endif
#endif

#define TESTSUITE_TICKET_LIFE 10	/* seconds */
/*************************************************
*        OpenSSL option parse                    *
*************************************************/

typedef struct exim_openssl_option {
  uschar *name;
  long    value;
} exim_openssl_option;
/* We could use a macro to expand, but we need the ifdef and not all the
options document which version they were introduced in.  Policylet: include
all options unless explicitly for DTLS, let the administrator choose which
to apply.

This list is current as of:
  ==>  1.1.1c  <==

XXX could we autobuild this list, as with predefined-macros?
Seems just parsing ssl.h for SSL_OP_.* would be enough (except to exclude DTLS).
Also allow a numeric literal?
*/
static exim_openssl_option exim_openssl_options[] = {
/* KEEP SORTED ALPHABETICALLY! */
#ifdef SSL_OP_ALL
  { US"all", (long) SSL_OP_ALL },
#endif
#ifdef SSL_OP_ALLOW_NO_DHE_KEX
  { US"allow_no_dhe_kex", SSL_OP_ALLOW_NO_DHE_KEX },
#endif
#ifdef SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION
  { US"allow_unsafe_legacy_renegotiation", SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION },
#endif
#ifdef SSL_OP_CIPHER_SERVER_PREFERENCE
  { US"cipher_server_preference", SSL_OP_CIPHER_SERVER_PREFERENCE },
#endif
#ifdef SSL_OP_CRYPTOPRO_TLSEXT_BUG
  { US"cryptopro_tlsext_bug", SSL_OP_CRYPTOPRO_TLSEXT_BUG },
#endif
#ifdef SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS
  { US"dont_insert_empty_fragments", SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS },
#endif
#ifdef SSL_OP_ENABLE_MIDDLEBOX_COMPAT
  { US"enable_middlebox_compat", SSL_OP_ENABLE_MIDDLEBOX_COMPAT },
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
#ifdef SSL_OP_NO_ANTI_REPLAY
  { US"no_anti_replay", SSL_OP_NO_ANTI_REPLAY },
#endif
#ifdef SSL_OP_NO_COMPRESSION
  { US"no_compression", SSL_OP_NO_COMPRESSION },
#endif
#ifdef SSL_OP_NO_ENCRYPT_THEN_MAC
  { US"no_encrypt_then_mac", SSL_OP_NO_ENCRYPT_THEN_MAC },
#endif
#ifdef SSL_OP_NO_RENEGOTIATION
  { US"no_renegotiation", SSL_OP_NO_RENEGOTIATION },
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
# if OPENSSL_VERSION_NUMBER < 0x30000000L
#  if SSL_OP_NO_TLSv1_1 == 0x00000400L
  /* Error in chosen value in 1.0.1a; see first item in CHANGES for 1.0.1b */
#   warning OpenSSL 1.0.1a uses a bad value for SSL_OP_NO_TLSv1_1, ignoring
#   define NO_SSL_OP_NO_TLSv1_1
#  endif
# endif
# ifndef NO_SSL_OP_NO_TLSv1_1
  { US"no_tlsv1_1", SSL_OP_NO_TLSv1_1 },
# endif
#endif
#ifdef SSL_OP_NO_TLSv1_2
  { US"no_tlsv1_2", SSL_OP_NO_TLSv1_2 },
#endif
#ifdef SSL_OP_NO_TLSv1_3
  { US"no_tlsv1_3", SSL_OP_NO_TLSv1_3 },
#endif
#ifdef SSL_OP_PRIORITIZE_CHACHA
  { US"prioritize_chacha", SSL_OP_PRIORITIZE_CHACHA },
#endif
#ifdef SSL_OP_SAFARI_ECDHE_ECDSA_BUG
  { US"safari_ecdhe_ecdsa_bug", SSL_OP_SAFARI_ECDHE_ECDSA_BUG },
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
#ifdef SSL_OP_TLSEXT_PADDING
  { US"tlsext_padding", SSL_OP_TLSEXT_PADDING },
#endif
};

#ifndef MACRO_PREDEF
static int exim_openssl_options_size = nelem(exim_openssl_options);
static long init_options = 0;
#endif

#ifdef MACRO_PREDEF
void
options_tls(void)
{
uschar buf[64];

for (struct exim_openssl_option * o = exim_openssl_options;
     o < exim_openssl_options + nelem(exim_openssl_options); o++)
  {
  /* Trailing X is workaround for problem with _OPT_OPENSSL_NO_TLSV1
  being a ".ifdef _OPT_OPENSSL_NO_TLSV1_3" match */

  spf(buf, sizeof(buf), US"_OPT_OPENSSL_%T_X", o->name);
  builtin_macro_create(buf);
  }

# ifndef DISABLE_TLS_RESUME
builtin_macro_create_var(US"_RESUME_DECODE", RESUME_DECODE_STRING );
# endif
# ifdef SSL_OP_NO_TLSv1_3
builtin_macro_create(US"_HAVE_TLS1_3");
# endif
# ifdef OPENSSL_BAD_SRVR_OURCERT
builtin_macro_create(US"_TLS_BAD_MULTICERT_IN_OURCERT");
# endif
# ifdef EXIM_HAVE_OCSP
builtin_macro_create(US"_HAVE_TLS_OCSP");
builtin_macro_create(US"_HAVE_TLS_OCSP_LIST");
# endif
# ifdef EXIM_HAVE_ALPN
builtin_macro_create(US"_HAVE_TLS_ALPN");
# endif
}
#else

/******************************************************************************/

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
 from the SMTP Transport.  We may also concurrently want to make TLS connections
 to utility daemons, so client-contexts are allocated and passed around in call
 args rather than using a gobal.

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

typedef struct {
  SSL_CTX *	ctx;
  SSL *		ssl;
  gstring *	corked;
} exim_openssl_client_tls_ctx;


/* static SSL_CTX *server_ctx = NULL; */
/* static SSL     *server_ssl = NULL; */

#ifdef EXIM_HAVE_OPENSSL_TLSEXT
static SSL_CTX *server_sni = NULL;
#endif
#ifdef EXIM_HAVE_ALPN
static BOOL server_seen_alpn = FALSE;
#endif

static char ssl_errstring[256];

static int  ssl_session_timeout = 7200;		/* Two hours */
static BOOL client_verify_optional = FALSE;
static BOOL server_verify_optional = FALSE;

static BOOL reexpand_tls_files_for_sni = FALSE;


typedef struct ocsp_resp {
  struct ocsp_resp *	next;
  OCSP_RESPONSE *	resp;
} ocsp_resplist;

typedef struct exim_openssl_state {
  exim_tlslib_state	lib_state;
#define lib_ctx			libdata0
#define lib_ssl			libdata1

  tls_support *	tlsp;
  uschar *	certificate;
  uschar *	privatekey;
  BOOL		is_server;
#ifndef DISABLE_OCSP
  union {
    struct {
      uschar        *file;
      const uschar  *file_expanded;
      ocsp_resplist *olist;
      STACK_OF(X509) *verify_stack;	/* chain for verifying the proof */
    } server;
    struct {
      X509_STORE    *verify_store;	/* non-null if status requested */
      uschar	    *verify_errstr;	/* only if _required */
      BOOL	    verify_required;
    } client;
  } u_ocsp;
#endif
  uschar *	dhparam;
  /* these are cached from first expand */
  uschar *	server_cipher_list;
  /* only passed down to tls_error: */
  host_item *	host;
  const uschar * verify_cert_hostnames;
#ifndef DISABLE_EVENT
  uschar *	event_action;
#endif
} exim_openssl_state_st;

/* should figure out a cleanup of API to handle state preserved per
implementation, for various reasons, which can be void * in the APIs.
For now, we hack around it. */
exim_openssl_state_st *client_static_state = NULL;	/*XXX should not use static; multiple concurrent clients! */
exim_openssl_state_st state_server = {.is_server = TRUE};

static int
setup_certs(SSL_CTX * sctx, uschar ** certs, uschar * crl, host_item * host,
    uschar ** errstr);

/* Callbacks */
#ifndef DISABLE_OCSP
static int tls_server_stapling_cb(SSL *s, void *arg);
static void x509_stack_dump_cert_s_names(const STACK_OF(X509) * sk);
static void x509_store_dump_cert_s_names(X509_STORE * store);
#endif



/* Daemon-called, before every connection, key create/rotate */
#ifndef DISABLE_TLS_RESUME
static void tk_init(void);
static int tls_exdata_idx = -1;
#endif

static void
tls_per_lib_daemon_tick(void)
{
#ifndef DISABLE_TLS_RESUME
tk_init();
#endif
}

/* Called once at daemon startup */

static void
tls_per_lib_daemon_init(void)
{
tls_daemon_creds_reload();
}


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
  errstr    pointer to output error message

Returns:    OK/DEFER/FAIL
*/

static int
tls_error(uschar * prefix, const host_item * host, uschar * msg, uschar ** errstr)
{
if (!msg)
  {
  ERR_error_string_n(ERR_get_error(), ssl_errstring, sizeof(ssl_errstring));
  msg = US ssl_errstring;
  }

msg = string_sprintf("(%s): %s", prefix, msg);
DEBUG(D_tls) debug_printf("TLS error '%s'\n", msg);
if (errstr) *errstr = msg;
return host ? FAIL : DEFER;
}



/**************************************************
* General library initalisation                   *
**************************************************/

static BOOL
lib_rand_init(void * addr)
{
randstuff r;
if (!RAND_status()) return TRUE;

gettimeofday(&r.tv, NULL);
r.p = getpid();
RAND_seed(US (&r), sizeof(r));
RAND_seed(US big_buffer, big_buffer_size);
if (addr) RAND_seed(US addr, sizeof(addr));

return RAND_status();
}


static void
tls_openssl_init(void)
{
static BOOL once = FALSE;
if (once) return;
once = TRUE;

#ifdef EXIM_NEED_OPENSSL_INIT
SSL_load_error_strings();          /* basic set up */
OpenSSL_add_ssl_algorithms();
#endif

#if defined(EXIM_HAVE_SHA256) && !defined(OPENSSL_AUTO_SHA256)
/* SHA256 is becoming ever more popular. This makes sure it gets added to the
list of available digests. */
EVP_add_digest(EVP_sha256());
#endif

(void) lib_rand_init(NULL);
(void) tls_openssl_options_parse(openssl_options, &init_options);
}



/*************************************************
*                Initialize for DH               *
*************************************************/

/* If dhparam is set, expand it, and load up the parameters for DH encryption.
Server only.

Arguments:
  sctx      The current SSL CTX (inbound or outbound)
  dhparam   DH parameter file or fixed parameter identity string
  errstr    error string pointer

Returns:    TRUE if OK (nothing to set up, or setup worked)
*/

static BOOL
init_dh(SSL_CTX * sctx, uschar * dhparam, uschar ** errstr)
{
BIO * bio;
#if OPENSSL_VERSION_NUMBER < 0x30000000L
DH * dh;
#else
EVP_PKEY * pkey;
#endif
uschar * dhexpanded;
const char * pem;
int dh_bitsize;

if (!expand_check(dhparam, US"tls_dhparam", &dhexpanded, errstr))
  return FALSE;

if (!dhexpanded || !*dhexpanded)
  bio = BIO_new_mem_buf(CS std_dh_prime_default(), -1);
else if (dhexpanded[0] == '/')
  {
  if (!(bio = BIO_new_file(CS dhexpanded, "r")))
    {
    tls_error(string_sprintf("could not read dhparams file %s", dhexpanded),
          NULL, US strerror(errno), errstr);
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

  if (!(pem = std_dh_prime_named(dhexpanded)))
    {
    tls_error(string_sprintf("Unknown standard DH prime \"%s\"", dhexpanded),
        NULL, US strerror(errno), errstr);
    return FALSE;
    }
  bio = BIO_new_mem_buf(CS pem, -1);
  }

if (!(
#if OPENSSL_VERSION_NUMBER < 0x30000000L
      dh = PEM_read_bio_DHparams(bio, NULL, NULL, NULL)
#else
      pkey = PEM_read_bio_Parameters_ex(bio, NULL, NULL, NULL)
#endif
   ) )
  {
  BIO_free(bio);
  tls_error(string_sprintf("Could not read tls_dhparams \"%s\"", dhexpanded),
      NULL, NULL, errstr);
  return FALSE;
  }

/* note: our default limit of 2236 is not a multiple of 8; the limit comes from
an NSS limit, and the GnuTLS APIs handle bit-sizes fine, so we went with 2236.
But older OpenSSL can only report in bytes (octets), not bits.  If someone wants
to dance at the edge, then they can raise the limit or use current libraries. */

#if OPENSSL_VERSION_NUMBER < 0x30000000L
# ifdef EXIM_HAVE_OPENSSL_DH_BITS
/* Added in commit 26c79d5641d; `git describe --contains` says OpenSSL_1_1_0-pre1~1022
This predates OpenSSL_1_1_0 (before a, b, ...) so is in all 1.1.0 */
dh_bitsize = DH_bits(dh);
# else
dh_bitsize = 8 * DH_size(dh);
# endif
#else	/* 3.0.0 + */
dh_bitsize = EVP_PKEY_get_bits(pkey);
#endif

/* Even if it is larger, we silently return success rather than cause things to
fail out, so that a too-large DH will not knock out all TLS; it's a debatable
choice.  Likewise for a failing attempt to set one. */

if (dh_bitsize <= tls_dh_max_bits)
  {
  if (
#if OPENSSL_VERSION_NUMBER < 0x30000000L
      SSL_CTX_set_tmp_dh(sctx, dh)
#else
      SSL_CTX_set0_tmp_dh_pkey(sctx, pkey)
#endif
      == 0)
    {
    ERR_error_string_n(ERR_get_error(), ssl_errstring, sizeof(ssl_errstring));
    log_write(0, LOG_MAIN|LOG_PANIC, "TLS error (D-H param setting '%s'): %s",
	dhexpanded ? dhexpanded : US"default", ssl_errstring);
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    /* EVP_PKEY_free(pkey);  crashes */
#endif
    }
  else
    DEBUG(D_tls)
      debug_printf(" Diffie-Hellman initialized from %s with %d-bit prime\n",
	dhexpanded ? dhexpanded : US"default", dh_bitsize);
  }
else
  DEBUG(D_tls)
    debug_printf(" dhparams '%s' %d bits, is > tls_dh_max_bits limit of %d\n",
	dhexpanded ? dhexpanded : US"default", dh_bitsize, tls_dh_max_bits);

#if OPENSSL_VERSION_NUMBER < 0x30000000L
DH_free(dh);
#endif
/* The EVP_PKEY ownership stays with the ctx; do not free it */

BIO_free(bio);
return TRUE;
}




/*************************************************
*               Initialize for ECDH              *
*************************************************/

/* "auto" needs to be handled carefully.
OpenSSL <  1.0.2: we do not select anything, but fallback to prime256v1
OpenSSL <  1.1.0: we have to call SSL_CTX_set_ecdh_auto
                  (openssl/ssl.h defines SSL_CTRL_SET_ECDH_AUTO)
OpenSSL >= 1.1.0: we do not set anything, the libray does autoselection
                  https://github.com/openssl/openssl/commit/fe6ef2472db933f01b59cad82aa925736935984b

*/

static uschar *
init_ecdh_auto(SSL_CTX * sctx)
{
#if OPENSSL_VERSION_NUMBER < 0x10002000L
DEBUG(D_tls) debug_printf(
  " ECDH OpenSSL < 1.0.2: temp key parameter settings: overriding \"auto\" with \"prime256v1\"\n");
return US"prime256v1";

#else
# if defined SSL_CTRL_SET_ECDH_AUTO

DEBUG(D_tls) debug_printf(
  " ECDH OpenSSL 1.0.2+: temp key parameter settings: autoselection\n");
SSL_CTX_set_ecdh_auto(sctx, 1);
return NULL;

# else

DEBUG(D_tls) debug_printf(
  " ECDH OpenSSL 1.1.0+: temp key parameter settings: library default selection\n");
return NULL;

# endif
#endif
}

/* Load parameters for ECDH encryption.  Server only.

For now, we stick to NIST P-256 because: it's simple and easy to configure;
it avoids any patent issues that might bite redistributors; despite events in
the news and concerns over curve choices, we're not cryptographers, we're not
pretending to be, and this is "good enough" to be better than no support,
protecting against most adversaries.  Given another year or two, there might
be sufficient clarity about a "right" way forward to let us make an informed
decision, instead of a knee-jerk reaction.

Longer-term, we should look at supporting both various named curves and
external files generated with "openssl ecparam", much as we do for init_dh().
We should also support "none" as a value, to explicitly avoid initialisation.

Patches welcome.

Arguments:
  sctx      The current SSL CTX (inbound or outbound)
  errstr    error string pointer

Returns:    TRUE if OK (nothing to set up, or setup worked)
*/

static BOOL
init_ecdh(SSL_CTX * sctx, uschar ** errstr)
{
#ifdef OPENSSL_NO_ECDH
return TRUE;
#else

# ifndef EXIM_HAVE_ECDH
DEBUG(D_tls)
  debug_printf(" No OpenSSL API to define ECDH parameters, skipping\n");
return TRUE;
# else

uschar * exp_curve;
int ngroups, rc, sep;
const uschar * curves_list,  * curve;
#  ifdef EXIM_HAVE_OPENSSL_SET1_GROUPS
int nids[16];
#  else
int nids[1];
#  endif

if (!expand_check(tls_eccurve, US"tls_eccurve", &exp_curve, errstr))
  return FALSE;

/* Is the option deliberately empty? */

if (!exp_curve || !*exp_curve)
  return TRUE;

/* Limit the list to hardwired array size. Drop out if any element is "suto". */

curves_list = exp_curve;
sep = 0;
for (ngroups = 0;
       ngroups < nelem(nids)
    && (curve = string_nextinlist(&curves_list, &sep, NULL, 0));
    )
  if (Ustrcmp(curve, "auto") == 0)
    {
    DEBUG(D_tls) if (ngroups > 0)
      debug_printf(" tls_eccurve 'auto' item takes precedence\n");
    if ((exp_curve = init_ecdh_auto(sctx))) break; /* have a curve name to set */
    return TRUE;				   /* all done */
    }
  else
    ngroups++;

/* Translate to NIDs */

curves_list = exp_curve;
for (ngroups = 0; curve = string_nextinlist(&curves_list, &sep, NULL, 0);
     ngroups++)
  if (  (nids[ngroups] = OBJ_sn2nid       (CCS curve)) == NID_undef
#  ifdef EXIM_HAVE_OPENSSL_EC_NIST2NID
     && (nids[ngroups] = EC_curve_nist2nid(CCS curve)) == NID_undef
#  endif
     )
    {
    uschar * s = string_sprintf("Unknown curve name in tls_eccurve '%s'", curve);
    DEBUG(D_tls) debug_printf("TLS error: %s\n", s);
    if (errstr) *errstr = s;
    return FALSE;
    }

#  ifdef EXIM_HAVE_OPENSSL_SET1_GROUPS
/* Set the groups */

if ((rc = SSL_CTX_set1_groups(sctx, nids, ngroups)) == 0)
  tls_error(string_sprintf("Error enabling '%s' group(s)", exp_curve), NULL, NULL, errstr);
else
  DEBUG(D_tls) debug_printf(" ECDH: enabled '%s' group(s)\n", exp_curve);

#  else		/* Cannot handle a list; only 1 element nids array */
 {
  EC_KEY * ecdh;
  if (!(ecdh = EC_KEY_new_by_curve_name(nids[0])))
    {
    tls_error(US"Unable to create ec curve", NULL, NULL, errstr);
    return FALSE;
    }

  /* The "tmp" in the name here refers to setting a temporary key
  not to the stability of the interface. */

  if ((rc = SSL_CTX_set_tmp_ecdh(sctx, ecdh)) == 0)
    tls_error(string_sprintf("Error enabling '%s' curve", exp_curve), NULL, NULL, errstr);
  else
    DEBUG(D_tls) debug_printf(" ECDH: enabled '%s' curve\n", exp_curve);
  EC_KEY_free(ecdh);
 }
#  endif	/*!EXIM_HAVE_OPENSSL_SET1_GROUPS*/

return !!rc;

# endif	/*EXIM_HAVE_ECDH*/
#endif /*OPENSSL_NO_ECDH*/
}



/*************************************************
*        Expand key and cert file specs          *
*************************************************/

#if OPENSSL_VERSION_NUMBER < 0x30000000L
/*
Arguments:
  s          SSL connection (not used)
  export     not used
  keylength  keylength

Returns:     pointer to generated key
*/

static RSA *
rsa_callback(SSL *s, int export, int keylength)
{
RSA *rsa_key;
#ifdef EXIM_HAVE_RSA_GENKEY_EX
BIGNUM *bn = BN_new();
#endif

DEBUG(D_tls) debug_printf("Generating %d bit RSA key...\n", keylength);

# ifdef EXIM_HAVE_RSA_GENKEY_EX
if (  !BN_set_word(bn, (unsigned long)RSA_F4)
   || !(rsa_key = RSA_new())
   || !RSA_generate_key_ex(rsa_key, keylength, bn, NULL)
   )
# else
if (!(rsa_key = RSA_generate_key(keylength, RSA_F4, NULL, NULL)))
# endif

  {
  ERR_error_string_n(ERR_get_error(), ssl_errstring, sizeof(ssl_errstring));
  log_write(0, LOG_MAIN|LOG_PANIC, "TLS error (RSA_generate_key): %s",
    ssl_errstring);
  return NULL;
  }
return rsa_key;
}
#endif	/* pre-3.0.0 */



/* Create and install a selfsigned certificate, for use in server mode */
/*XXX we could arrange to call this during prelo for a null tls_certificate option.
The normal cache inval + relo will suffice.
Just need a timer for inval. */

static int
tls_install_selfsign(SSL_CTX * sctx, uschar ** errstr)
{
X509 * x509 = NULL;
EVP_PKEY * pkey;
X509_NAME * name;
uschar * where;

DEBUG(D_tls) debug_printf("TLS: generating selfsigned server cert\n");
where = US"allocating pkey";
if (!(pkey = EVP_PKEY_new()))
  goto err;

where = US"allocating cert";
if (!(x509 = X509_new()))
  goto err;

where = US"generating pkey";
#if OPENSSL_VERSION_NUMBER < 0x30000000L
 {
  RSA * rsa;
  if (!(rsa = rsa_callback(NULL, 0, 2048)))
    goto err;

  where = US"assigning pkey";
  if (!EVP_PKEY_assign_RSA(pkey, rsa))
    goto err;
 }
#else
pkey = EVP_RSA_gen(2048);
#endif

X509_set_version(x509, 2);				/* N+1 - version 3 */
ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
X509_gmtime_adj(X509_get_notBefore(x509), 0);
X509_gmtime_adj(X509_get_notAfter(x509), (long)2 * 60 * 60);	/* 2 hour */
X509_set_pubkey(x509, pkey);

name = X509_get_subject_name(x509);
X509_NAME_add_entry_by_txt(name, "C",
			  MBSTRING_ASC, CUS "UK", -1, -1, 0);
X509_NAME_add_entry_by_txt(name, "O",
			  MBSTRING_ASC, CUS "Exim Developers", -1, -1, 0);
X509_NAME_add_entry_by_txt(name, "CN",
			  MBSTRING_ASC, CUS smtp_active_hostname, -1, -1, 0);
X509_set_issuer_name(x509, name);

where = US"signing cert";
if (!X509_sign(x509, pkey, EVP_md5()))
  goto err;

where = US"installing selfsign cert";
if (!SSL_CTX_use_certificate(sctx, x509))
  goto err;

where = US"installing selfsign key";
if (!SSL_CTX_use_PrivateKey(sctx, pkey))
  goto err;

return OK;

err:
  (void) tls_error(where, NULL, NULL, errstr);
  if (x509) X509_free(x509);
  if (pkey) EVP_PKEY_free(pkey);
  return DEFER;
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
info_callback(const SSL * s, int where, int ret)
{
DEBUG(D_tls)
  {
  gstring * g = NULL;

  if (where & SSL_ST_CONNECT) g = string_append_listele(g, ',', US"SSL_connect");
  if (where & SSL_ST_ACCEPT)  g = string_append_listele(g, ',', US"SSL_accept");
  if (where & SSL_CB_LOOP)    g = string_append_listele(g, ',', US"state_chg");
  if (where & SSL_CB_EXIT)    g = string_append_listele(g, ',', US"hshake_exit");
  if (where & SSL_CB_READ)    g = string_append_listele(g, ',', US"read");
  if (where & SSL_CB_WRITE)   g = string_append_listele(g, ',', US"write");
  if (where & SSL_CB_ALERT)   g = string_append_listele(g, ',', US"alert");
  if (where & SSL_CB_HANDSHAKE_START) g = string_append_listele(g, ',', US"hshake_start");
  if (where & SSL_CB_HANDSHAKE_DONE)  g = string_append_listele(g, ',', US"hshake_done");

  if (where & SSL_CB_LOOP)
     debug_printf("SSL %s: %s\n", g->s, SSL_state_string_long(s));
  else if (where & SSL_CB_ALERT)
    debug_printf("SSL %s %s:%s\n", g->s,
	  SSL_alert_type_string_long(ret), SSL_alert_desc_string_long(ret));
  else if (where & SSL_CB_EXIT)
    {
    if (ret <= 0)
      debug_printf("SSL %s: %s in %s\n", g->s,
	ret == 0 ? "failed" : "error", SSL_state_string_long(s));
    }
  else if (where & (SSL_CB_HANDSHAKE_START | SSL_CB_HANDSHAKE_DONE))
     debug_printf("SSL %s: %s\n", g->s, SSL_state_string_long(s));
  }
}

#ifdef OPENSSL_HAVE_KEYLOG_CB
static void
keylog_callback(const SSL *ssl, const char *line)
{
char * filename;
FILE * fp;
DEBUG(D_tls) debug_printf("%.200s\n", line);
if (!(filename = getenv("SSLKEYLOGFILE"))) return;
if (!(fp = fopen(filename, "a"))) return;
fprintf(fp, "%s\n", line);
fclose(fp);
}
#endif





#ifndef DISABLE_EVENT
static int
verify_event(tls_support * tlsp, X509 * cert, int depth, const uschar * dn,
  BOOL *calledp, const BOOL *optionalp, const uschar * what)
{
uschar * ev;
uschar * yield;
X509 * old_cert;

ev = tlsp == &tls_out ? client_static_state->event_action : event_action;
if (ev)
  {
  DEBUG(D_tls) debug_printf("verify_event: %s %d\n", what, depth);
  old_cert = tlsp->peercert;
  tlsp->peercert = X509_dup(cert);
  /* NB we do not bother setting peerdn */
  if ((yield = event_raise(ev, US"tls:cert", string_sprintf("%d", depth), &errno)))
    {
    log_write(0, LOG_MAIN, "[%s] %s verify denied by event-action: "
		"depth=%d cert=%s: %s",
	      tlsp == &tls_out ? deliver_host_address : sender_host_address,
	      what, depth, dn, yield);
    *calledp = TRUE;
    if (!*optionalp)
      {
      if (old_cert) tlsp->peercert = old_cert;	/* restore 1st failing cert */
      return 1;			    /* reject (leaving peercert set) */
      }
    DEBUG(D_tls) debug_printf("Event-action verify failure overridden "
      "(host in tls_try_verify_hosts)\n");
    tlsp->verify_override = TRUE;
    }
  X509_free(tlsp->peercert);
  tlsp->peercert = old_cert;
  }
return 0;
}
#endif

/*************************************************
*        Callback for verification               *
*************************************************/

/* The SSL library does certificate verification if set up to do so. This
callback has the current yes/no state is in "state". If verification succeeded,
we set the certificate-verified flag. If verification failed, what happens
depends on whether the client is required to present a verifiable certificate
or not.

If verification is optional, we change the state to yes, but still log the
verification error. For some reason (it really would help to have proper
documentation of OpenSSL), this callback function then gets called again, this
time with state = 1.  We must take care not to set the private verified flag on
the second time through.

Note: this function is not called if the client fails to present a certificate
when asked. We get here only if a certificate has been received. Handling of
optional verification for this case is done when requesting SSL to verify, by
setting SSL_VERIFY_FAIL_IF_NO_PEER_CERT in the non-optional case.

May be called multiple times for different issues with a certificate, even
for a given "depth" in the certificate chain.

Arguments:
  preverify_ok current yes/no state as 1/0
  x509ctx      certificate information.
  tlsp         per-direction (client vs. server) support data
  calledp      has-been-called flag
  optionalp    verification-is-optional flag

Returns:     0 if verification should fail, otherwise 1
*/

static int
verify_callback(int preverify_ok, X509_STORE_CTX * x509ctx,
  tls_support * tlsp, BOOL * calledp, BOOL * optionalp)
{
X509 * cert = X509_STORE_CTX_get_current_cert(x509ctx);
int depth = X509_STORE_CTX_get_error_depth(x509ctx);
uschar dn[256];

if (!X509_NAME_oneline(X509_get_subject_name(cert), CS dn, sizeof(dn)))
  {
  DEBUG(D_tls) debug_printf("X509_NAME_oneline() error\n");
  log_write(0, LOG_MAIN, "[%s] SSL verify error: internal error",
    tlsp == &tls_out ? deliver_host_address : sender_host_address);
  return 0;
  }
dn[sizeof(dn)-1] = '\0';

tlsp->verify_override = FALSE;
if (preverify_ok == 0)
  {
  uschar * extra = verify_mode ? string_sprintf(" (during %c-verify for [%s])",
      *verify_mode, sender_host_address)
    : US"";
  log_write(0, LOG_MAIN, "[%s] SSL verify error%s: depth=%d error=%s cert=%s",
    tlsp == &tls_out ? deliver_host_address : sender_host_address,
    extra, depth,
    X509_verify_cert_error_string(X509_STORE_CTX_get_error(x509ctx)), dn);
  *calledp = TRUE;
  if (!*optionalp)
    {
    if (!tlsp->peercert)
      tlsp->peercert = X509_dup(cert);	/* record failing cert */
    return 0;				/* reject */
    }
  DEBUG(D_tls) debug_printf("SSL verify failure overridden (host in "
    "tls_try_verify_hosts)\n");
  tlsp->verify_override = TRUE;
  }

else if (depth != 0)
  {
  DEBUG(D_tls) debug_printf("SSL verify ok: depth=%d SN=%s\n", depth, dn);
#ifndef DISABLE_EVENT
    if (verify_event(tlsp, cert, depth, dn, calledp, optionalp, US"SSL"))
      return 0;				/* reject, with peercert set */
#endif
  }
else
  {
  const uschar * verify_cert_hostnames;

  if (  tlsp == &tls_out
     && ((verify_cert_hostnames = client_static_state->verify_cert_hostnames)))
	/* client, wanting hostname check */
    {

#ifdef EXIM_HAVE_OPENSSL_CHECKHOST
# ifndef X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS
#  define X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS 0
# endif
# ifndef X509_CHECK_FLAG_SINGLE_LABEL_SUBDOMAINS
#  define X509_CHECK_FLAG_SINGLE_LABEL_SUBDOMAINS 0
# endif
    int sep = 0;
    const uschar * list = verify_cert_hostnames;
    uschar * name;
    int rc;
    while ((name = string_nextinlist(&list, &sep, NULL, 0)))
      {
      DEBUG(D_tls|D_lookup) debug_printf_indent("%s suitable for cert, per OpenSSL?", name);
      if ((rc = X509_check_host(cert, CCS name, 0,
		  X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS
		  | X509_CHECK_FLAG_SINGLE_LABEL_SUBDOMAINS,
		  NULL)))
	{
	if (rc < 0)
	  {
	  log_write(0, LOG_MAIN, "[%s] SSL verify error: internal error",
	    tlsp == &tls_out ? deliver_host_address : sender_host_address);
	  name = NULL;
	  }
	DEBUG(D_tls|D_lookup) debug_printf_indent("  yes\n");
	break;
	}
      else DEBUG(D_tls|D_lookup) debug_printf_indent("  no\n");
      }
    if (!name)
#else
    if (!tls_is_name_for_cert(verify_cert_hostnames, cert))
#endif
      {
      uschar * extra = verify_mode
        ? string_sprintf(" (during %c-verify for [%s])",
	  *verify_mode, sender_host_address)
	: US"";
      log_write(0, LOG_MAIN,
	"[%s] SSL verify error%s: certificate name mismatch: DN=\"%s\" H=\"%s\"",
	tlsp == &tls_out ? deliver_host_address : sender_host_address,
	extra, dn, verify_cert_hostnames);
      *calledp = TRUE;
      if (!*optionalp)
	{
	if (!tlsp->peercert)
	  tlsp->peercert = X509_dup(cert);	/* record failing cert */
	return 0;				/* reject */
	}
      DEBUG(D_tls) debug_printf("SSL verify name failure overridden (host in "
	"tls_try_verify_hosts)\n");
      tlsp->verify_override = TRUE;
      }
    }

#ifndef DISABLE_EVENT
  if (verify_event(tlsp, cert, depth, dn, calledp, optionalp, US"SSL"))
    return 0;				/* reject, with peercert set */
#endif

  DEBUG(D_tls) debug_printf("SSL%s verify ok: depth=0 SN=%s\n",
    *calledp ? "" : " authenticated", dn);
  *calledp = TRUE;
  }

return 1;   /* accept, at least for this level */
}

static int
verify_callback_client(int preverify_ok, X509_STORE_CTX *x509ctx)
{
return verify_callback(preverify_ok, x509ctx, &tls_out,
  &client_verify_callback_called, &client_verify_optional);
}

static int
verify_callback_server(int preverify_ok, X509_STORE_CTX *x509ctx)
{
return verify_callback(preverify_ok, x509ctx, &tls_in,
  &server_verify_callback_called, &server_verify_optional);
}


#ifdef SUPPORT_DANE

/* This gets called *by* the dane library verify callback, which interposes
itself.
*/
static int
verify_callback_client_dane(int preverify_ok, X509_STORE_CTX * x509ctx)
{
X509 * cert = X509_STORE_CTX_get_current_cert(x509ctx);
uschar dn[256];
int depth = X509_STORE_CTX_get_error_depth(x509ctx);
#ifndef DISABLE_EVENT
BOOL dummy_called, optional = FALSE;
#endif

if (!X509_NAME_oneline(X509_get_subject_name(cert), CS dn, sizeof(dn)))
  {
  DEBUG(D_tls) debug_printf("X509_NAME_oneline() error\n");
  log_write(0, LOG_MAIN, "[%s] SSL verify error: internal error",
    deliver_host_address);
  return 0;
  }
dn[sizeof(dn)-1] = '\0';

DEBUG(D_tls) debug_printf("verify_callback_client_dane: %s depth %d %s\n",
  preverify_ok ? "ok":"BAD", depth, dn);

#ifndef DISABLE_EVENT
  if (verify_event(&tls_out, cert, depth, dn,
	  &dummy_called, &optional, US"DANE"))
    return 0;				/* reject, with peercert set */
#endif

if (preverify_ok == 1)
  tls_out.dane_verified = TRUE;
else
  {
  int err = X509_STORE_CTX_get_error(x509ctx);
  DEBUG(D_tls)
    debug_printf(" - err %d '%s'\n", err, X509_verify_cert_error_string(err));
  if (err == X509_V_ERR_APPLICATION_VERIFICATION)
    preverify_ok = 1;
  }
return preverify_ok;
}

#endif	/*SUPPORT_DANE*/


#ifndef DISABLE_OCSP
static void
time_print(BIO * bp, const char * str, ASN1_GENERALIZEDTIME * time)
{
BIO_printf(bp, "\t%s: ", str);
ASN1_GENERALIZEDTIME_print(bp, time);
BIO_puts(bp, "\n");
}

/*************************************************
*       Load OCSP information into state         *
*************************************************/
/* Called to load the server OCSP response from the given file into memory, once
caller has determined this is needed.  Checks validity.  Debugs a message
if invalid.

ASSUMES: single response, for single cert.

Arguments:
  state           various parts of session state
  filename        the filename putatively holding an OCSP response
  is_pem	  file is PEM format; otherwise is DER
*/

static void
ocsp_load_response(exim_openssl_state_st * state, const uschar * filename,
  BOOL is_pem)
{
BIO * bio;
OCSP_RESPONSE * resp;
OCSP_BASICRESP * basic_response;
OCSP_SINGLERESP * single_response;
ASN1_GENERALIZEDTIME * rev, * thisupd, * nextupd;
STACK_OF(X509) * sk;
int status, reason, i;

DEBUG(D_tls)
  debug_printf("tls_ocsp_file (%s)  '%s'\n", is_pem ? "PEM" : "DER", filename);

if (!filename || !*filename) return;

ERR_clear_error();
if (!(bio = BIO_new_file(CS filename, "rb")))
  {
  log_write(0, LOG_MAIN|LOG_PANIC,
    "Failed to open OCSP response file \"%s\": %.100s",
    filename, ERR_reason_error_string(ERR_get_error()));
  return;
  }

if (is_pem)
  {
  uschar * data, * freep;
  char * dummy;
  long len;
  if (!PEM_read_bio(bio, &dummy, &dummy, &data, &len))
    {
    log_write(0, LOG_MAIN|LOG_PANIC, "Failed to read PEM file \"%s\": %.100s",
      filename, ERR_reason_error_string(ERR_get_error()));
    return;
    }
  freep = data;
  resp = d2i_OCSP_RESPONSE(NULL, CUSS &data, len);
  OPENSSL_free(freep);
  }
else
  resp = d2i_OCSP_RESPONSE_bio(bio, NULL);
BIO_free(bio);

if (!resp)
  {
  log_write(0, LOG_MAIN|LOG_PANIC, "Error reading OCSP response from \"%s\": %s",
      filename, ERR_reason_error_string(ERR_get_error()));
  return;
  }

if ((status = OCSP_response_status(resp)) != OCSP_RESPONSE_STATUS_SUCCESSFUL)
  {
  DEBUG(D_tls) debug_printf("OCSP response not valid: %s (%d)\n",
      OCSP_response_status_str(status), status);
  goto bad;
  }

#ifdef notdef
  {
  BIO * bp = BIO_new_fp(debug_file, BIO_NOCLOSE);
  OCSP_RESPONSE_print(bp, resp, 0);  /* extreme debug: stapling content */
  BIO_free(bp);
  }
#endif

if (!(basic_response = OCSP_response_get1_basic(resp)))
  {
  DEBUG(D_tls)
    debug_printf("OCSP response parse error: unable to extract basic response.\n");
  goto bad;
  }

sk = state->u_ocsp.server.verify_stack;	/* set by setup_certs() / chain_from_pem_file() */

/* May need to expose ability to adjust those flags?
OCSP_NOSIGS OCSP_NOVERIFY OCSP_NOCHAIN OCSP_NOCHECKS OCSP_NOEXPLICIT
OCSP_TRUSTOTHER OCSP_NOINTERN */

/* This does a partial verify (only the signer link, not the whole chain-to-CA)
on the OCSP proof before we load it for serving up; possibly overkill -
just date-checks might be nice enough.

OCSP_basic_verify takes a "store" arg, but does not
use it for the chain verification, when OCSP_NOVERIFY is set.
The content from the wire "basic_response" and a cert-stack "sk" are all
that is used.

We have a stack, loaded in setup_certs() if tls_verify_certificates
was a file (not a directory, or "system").  It is unfortunate we
cannot used the connection context store, as that would neatly
handle the "system" case too, but there seems to be no library
function for getting a stack from a store.
[ In OpenSSL 1.1 - ?  X509_STORE_CTX_get0_chain(ctx) ? ]
[ 3.0.0 - sk = X509_STORE_get1_all_certs(store) ]
We do not free the stack since it could be needed a second time for
SNI handling.

Separately we might try to replace using OCSP_basic_verify() - which seems to not
be a public interface into the OpenSSL library (there's no manual entry) -
(in 3.0.0 + it is public)
But what with?  We also use OCSP_basic_verify in the client stapling callback.
And there we NEED it; we must verify that status... unless the
library does it for us anyway?  */

if ((i = OCSP_basic_verify(basic_response, sk, NULL, OCSP_NOVERIFY)) < 0)
  {
  DEBUG(D_tls)
    {
    ERR_error_string_n(ERR_get_error(), ssl_errstring, sizeof(ssl_errstring));
    debug_printf("OCSP response has bad signature: %s\n", US ssl_errstring);
    }
  goto bad;
  }

/* Here's the simplifying assumption: there's only one response, for the
one certificate we use, and nothing for anything else in a chain.  If this
proves false, we need to extract a cert id from our issued cert
(tls_certificate) and use that for OCSP_resp_find_status() (which finds the
right cert in the stack and then calls OCSP_single_get0_status()).

I'm hoping to avoid reworking a bunch more of how we handle state here.

XXX that will change when we add support for (TLS1.3) whole-chain stapling
*/

if (!(single_response = OCSP_resp_get0(basic_response, 0)))
  {
  DEBUG(D_tls)
    debug_printf("Unable to get first response from OCSP basic response.\n");
  goto bad;
  }

status = OCSP_single_get0_status(single_response, &reason, &rev, &thisupd, &nextupd);
if (status != V_OCSP_CERTSTATUS_GOOD)
  {
  DEBUG(D_tls) debug_printf("OCSP response bad cert status: %s (%d) %s (%d)\n",
      OCSP_cert_status_str(status), status,
      OCSP_crl_reason_str(reason), reason);
  goto bad;
  }

if (!OCSP_check_validity(thisupd, nextupd, EXIM_OCSP_SKEW_SECONDS, EXIM_OCSP_MAX_AGE))
  {
  DEBUG(D_tls)
    {
    BIO * bp = BIO_new(BIO_s_mem());
    uschar * s = NULL;
    int len;
    time_print(bp, "This OCSP Update", thisupd);
    if (nextupd) time_print(bp, "Next OCSP Update", nextupd);
    if ((len = (int) BIO_get_mem_data(bp, CSS &s)) > 0) debug_printf("%.*s", len, s);
    debug_printf("OCSP status invalid times.\n");
    }
  goto bad;
  }

supply_response:
  /* Add the resp to the list used by tls_server_stapling_cb() */
  {
  ocsp_resplist ** op = &state->u_ocsp.server.olist, * oentry;
  while (oentry = *op)
    op = &oentry->next;
  *op = oentry = store_get(sizeof(ocsp_resplist), GET_UNTAINTED);
  oentry->next = NULL;
  oentry->resp = resp;
  }
return;

bad:
  if (f.running_in_test_harness)
    {
    extern char ** environ;
    if (environ) for (uschar ** p = USS environ; *p; p++)
      if (Ustrncmp(*p, "EXIM_TESTHARNESS_DISABLE_OCSPVALIDITYCHECK", 42) == 0)
	{
	DEBUG(D_tls) debug_printf("Supplying known bad OCSP response\n");
	goto supply_response;
	}
    }
return;
}


static void
ocsp_free_response_list(exim_openssl_state_st * state)
{
for (ocsp_resplist * olist = state->u_ocsp.server.olist; olist;
     olist = olist->next)
  OCSP_RESPONSE_free(olist->resp);
state->u_ocsp.server.olist = NULL;
}
#endif	/*!DISABLE_OCSP*/





static int
tls_add_certfile(SSL_CTX * sctx, exim_openssl_state_st * cbinfo, uschar * file,
  uschar ** errstr)
{
DEBUG(D_tls) debug_printf("tls_certificate file '%s'\n", file);
if (!SSL_CTX_use_certificate_chain_file(sctx, CS file))
  return tls_error(string_sprintf(
    "SSL_CTX_use_certificate_chain_file file=%s", file),
      cbinfo->host, NULL, errstr);
return 0;
}

static int
tls_add_pkeyfile(SSL_CTX * sctx, exim_openssl_state_st * cbinfo, uschar * file,
  uschar ** errstr)
{
DEBUG(D_tls) debug_printf("tls_privatekey file  '%s'\n", file);
if (!SSL_CTX_use_PrivateKey_file(sctx, CS file, SSL_FILETYPE_PEM))
  return tls_error(string_sprintf(
    "SSL_CTX_use_PrivateKey_file file=%s", file), cbinfo->host, NULL, errstr);
return 0;
}




/* Called once during tls_init and possibly again during TLS setup, for a
new context, if Server Name Indication was used and tls_sni was seen in
the certificate string.

Arguments:
  sctx            the SSL_CTX* to update
  state           various parts of session state
  errstr	  error string pointer

Returns:          OK/DEFER/FAIL
*/

static int
tls_expand_session_files(SSL_CTX * sctx, exim_openssl_state_st * state,
  uschar ** errstr)
{
uschar * expanded;

if (!state->certificate)
  {
  if (!state->is_server)		/* client */
    return OK;
					/* server */
  if (tls_install_selfsign(sctx, errstr) != OK)
    return DEFER;
  }
else
  {
  int err;

  if ( !reexpand_tls_files_for_sni
     && (  Ustrstr(state->certificate, US"tls_sni")
	|| Ustrstr(state->certificate, US"tls_in_sni")
	|| Ustrstr(state->certificate, US"tls_out_sni")
     )  )
    reexpand_tls_files_for_sni = TRUE;

  if (  !expand_check(state->certificate, US"tls_certificate", &expanded, errstr)
     || f.expand_string_forcedfail)
    {
    if (f.expand_string_forcedfail)
      *errstr = US"expansion of tls_certificate failed";
    return DEFER;
    }

  if (expanded)
    if (state->is_server)
      {
      const uschar * file_list = expanded;
      int sep = 0;
      uschar * file;
#ifndef DISABLE_OCSP
      const uschar * olist = state->u_ocsp.server.file;
      int osep = 0;
      uschar * ofile;
      BOOL fmt_pem = FALSE;

      if (olist)
	if (!expand_check(olist, US"tls_ocsp_file", USS &olist, errstr))
	  return DEFER;
      if (olist && !*olist)
	olist = NULL;

      /* If doing a re-expand after SNI, avoid reloading the OCSP
      responses when the list of filenames has not changed.
      The creds-invali on content change wipes file_expanded, so that
      always reloads here. */

      if (  state->u_ocsp.server.file_expanded && olist
	 && (Ustrcmp(olist, state->u_ocsp.server.file_expanded) == 0))
	{
	DEBUG(D_tls) debug_printf(" - value unchanged, using existing values\n");
	olist = NULL;
	}
      else
	{
	ocsp_free_response_list(state);
	state->u_ocsp.server.file_expanded = olist;
	}
#endif

      while (file = string_nextinlist(&file_list, &sep, NULL, 0))
	{
	if ((err = tls_add_certfile(sctx, state, file, errstr)))
	  return err;

#ifndef DISABLE_OCSP
	if (olist)
	  if ((ofile = string_nextinlist(&olist, &osep, NULL, 0)))
	    {
	    if (Ustrncmp(ofile, US"PEM ", 4) == 0)
	      {
	      fmt_pem = TRUE;
	      ofile += 4;
	      }
	    else if (Ustrncmp(ofile, US"DER ", 4) == 0)
	      {
	      fmt_pem = FALSE;
	      ofile += 4;
	      }
	    ocsp_load_response(state, ofile, fmt_pem);
	    }
	  else
	    DEBUG(D_tls) debug_printf("ran out of ocsp file list\n");
#endif
	}
      }
    else	/* would there ever be a need for multiple client certs? */
      if ((err = tls_add_certfile(sctx, state, expanded, errstr)))
	return err;

  if (     state->privatekey
        && !expand_check(state->privatekey, US"tls_privatekey", &expanded, errstr)
     || f.expand_string_forcedfail)
    {
    if (f.expand_string_forcedfail)
      *errstr = US"expansion of tls_privatekey failed";
    return DEFER;
    }

  /* If expansion was forced to fail, key_expanded will be NULL. If the result
  of the expansion is an empty string, ignore it also, and assume the private
  key is in the same file as the certificate. */

  if (expanded && *expanded)
    if (state->is_server)
      {
      const uschar * file_list = expanded;
      int sep = 0;
      uschar * file;

      while (file = string_nextinlist(&file_list, &sep, NULL, 0))
	if ((err = tls_add_pkeyfile(sctx, state, file, errstr)))
	  return err;
      }
    else	/* would there ever be a need for multiple client certs? */
      if ((err = tls_add_pkeyfile(sctx, state, expanded, errstr)))
	return err;
  }

return OK;
}




/**************************************************
* One-time init credentials for server and client *
**************************************************/

static void
normalise_ciphers(uschar ** ciphers, const uschar * pre_expansion_ciphers)
{
uschar * s = *ciphers;

if (!s || !Ustrchr(s, '_')) return;	/* no change needed */

if (s == pre_expansion_ciphers)
  s = string_copy(s);			/* get writable copy */

for (uschar * t = s; *t; t++) if (*t == '_') *t = '-';
*ciphers = s;
}

static int
server_load_ciphers(SSL_CTX * ctx, exim_openssl_state_st * state,
  uschar * ciphers, uschar ** errstr)
{
DEBUG(D_tls) debug_printf("required ciphers: %s\n", ciphers);
if (!SSL_CTX_set_cipher_list(ctx, CS ciphers))
  return tls_error(US"SSL_CTX_set_cipher_list", NULL, NULL, errstr);
state->server_cipher_list = ciphers;
return OK;
}



static int
lib_ctx_new(SSL_CTX ** ctxp, host_item * host, uschar ** errstr)
{
SSL_CTX * ctx;
#ifdef EXIM_HAVE_OPENSSL_TLS_METHOD
if (!(ctx = SSL_CTX_new(host ? TLS_client_method() : TLS_server_method())))
#else
if (!(ctx = SSL_CTX_new(host ? SSLv23_client_method() : SSLv23_server_method())))
#endif
  return tls_error(US"SSL_CTX_new", host, NULL, errstr);

/* Set up the information callback, which outputs if debugging is at a suitable
level. */

DEBUG(D_tls)
  {
  SSL_CTX_set_info_callback(ctx, info_callback);
#if defined(EXIM_HAVE_OPENSSL_TRACE) && !defined(OPENSSL_NO_SSL_TRACE)
  /* this needs a debug build of OpenSSL */
  SSL_CTX_set_msg_callback(ctx, SSL_trace);
#endif
#ifdef OPENSSL_HAVE_KEYLOG_CB
  SSL_CTX_set_keylog_callback(ctx, keylog_callback);
#endif
  }

/* Automatically re-try reads/writes after renegotiation. */
(void) SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);
*ctxp = ctx;
return OK;
}


static unsigned
tls_server_creds_init(void)
{
SSL_CTX * ctx;
uschar * dummy_errstr;
unsigned lifetime = 0;

tls_openssl_init();

state_server.lib_state = null_tls_preload;

if (lib_ctx_new(&ctx, NULL, &dummy_errstr) != OK)
  return 0;
state_server.lib_state.lib_ctx = ctx;

/* Preload DH params and EC curve */

if (opt_unset_or_noexpand(tls_dhparam))
  {
  DEBUG(D_tls) debug_printf("TLS: preloading DH params '%s' for server\n", tls_dhparam);
  if (init_dh(ctx, tls_dhparam, &dummy_errstr))
    state_server.lib_state.dh = TRUE;
  }
else
  DEBUG(D_tls) debug_printf("TLS: not preloading DH params for server\n");
if (opt_unset_or_noexpand(tls_eccurve))
  {
  DEBUG(D_tls) debug_printf("TLS: preloading ECDH curve '%s' for server\n", tls_eccurve);
  if (init_ecdh(ctx, &dummy_errstr))
    state_server.lib_state.ecdh = TRUE;
  }
else
  DEBUG(D_tls) debug_printf("TLS: not preloading ECDH curve for server\n");

#if defined(EXIM_HAVE_INOTIFY) || defined(EXIM_HAVE_KEVENT)
/* If we can, preload the Authorities for checking client certs against.
Actual choice to do verify is made (tls_{,try_}verify_hosts)
at TLS conn startup.
Do this before the server ocsp so that its info can verify the ocsp. */

if (  opt_set_and_noexpand(tls_verify_certificates)
   && opt_unset_or_noexpand(tls_crl))
  {
  /* Watch the default dir also as they are always included */

  if (  tls_set_watch(CUS X509_get_default_cert_file(), FALSE)
     && tls_set_watch(tls_verify_certificates, FALSE)
     && tls_set_watch(tls_crl, FALSE))
    {
    uschar * v_certs = tls_verify_certificates;
    DEBUG(D_tls) debug_printf("TLS: preloading CA bundle for server\n");

    if (setup_certs(ctx, &v_certs, tls_crl, NULL, &dummy_errstr) == OK)
      state_server.lib_state.cabundle = TRUE;

    /* If we can, preload the server-side cert, key and ocsp */

    if (  opt_set_and_noexpand(tls_certificate)
# ifndef DISABLE_OCSP
       && opt_unset_or_noexpand(tls_ocsp_file)
# endif
       && opt_unset_or_noexpand(tls_privatekey))
      {
      /* Set watches on the filenames.  The implementation does de-duplication
      so we can just blindly do them all.  */

      if (  tls_set_watch(tls_certificate, TRUE)
# ifndef DISABLE_OCSP
	 && tls_set_watch(tls_ocsp_file, TRUE)
# endif
	 && tls_set_watch(tls_privatekey, TRUE))
	{
	state_server.certificate = tls_certificate;
	state_server.privatekey = tls_privatekey;
#ifndef DISABLE_OCSP
	state_server.u_ocsp.server.file = tls_ocsp_file;
# endif

	DEBUG(D_tls) debug_printf("TLS: preloading server certs\n");
	if (tls_expand_session_files(ctx, &state_server, &dummy_errstr) == OK)
	  state_server.lib_state.conn_certs = TRUE;
	}
      }
    else if (  !tls_certificate && !tls_privatekey
# ifndef DISABLE_OCSP
	    && !tls_ocsp_file
# endif
       )
      {		/* Generate & preload a selfsigned cert. No files to watch. */
      if (tls_expand_session_files(ctx, &state_server, &dummy_errstr) == OK)
	{
	state_server.lib_state.conn_certs = TRUE;
	lifetime = f.running_in_test_harness ? 2 : 60 * 60;		/* 1 hour */
	}
      }
    else
      DEBUG(D_tls) debug_printf("TLS: not preloading server certs\n");
	}
  }
else
  DEBUG(D_tls) debug_printf("TLS: not preloading CA bundle for server\n");


#endif	/* EXIM_HAVE_INOTIFY */


/* If we can, preload the ciphers control string */

if (opt_set_and_noexpand(tls_require_ciphers))
  {
  DEBUG(D_tls) debug_printf("TLS: preloading cipher list for server\n");
  normalise_ciphers(&tls_require_ciphers, tls_require_ciphers);
  if (server_load_ciphers(ctx, &state_server, tls_require_ciphers,
			  &dummy_errstr) == OK)
    state_server.lib_state.pri_string = TRUE;
  }
else
  DEBUG(D_tls) debug_printf("TLS: not preloading cipher list for server\n");
return lifetime;
}




/* Preload whatever creds are static, onto a transport.  The client can then
just copy the pointer as it starts up.
Called from the daemon after a cache-invalidate with watch set; called from
a queue-run startup with watch clear. */

static void
tls_client_creds_init(transport_instance * t, BOOL watch)
{
smtp_transport_options_block * ob = t->options_block;
exim_openssl_state_st tpt_dummy_state;
host_item * dummy_host = (host_item *)1;
uschar * dummy_errstr;
SSL_CTX * ctx;

tls_openssl_init();

ob->tls_preload = null_tls_preload;
if (lib_ctx_new(&ctx, dummy_host, &dummy_errstr) != OK)
  return;
ob->tls_preload.lib_ctx = ctx;

tpt_dummy_state.lib_state = ob->tls_preload;

#if defined(EXIM_HAVE_INOTIFY) || defined(EXIM_HAVE_KEVENT)
if (  opt_set_and_noexpand(ob->tls_certificate)
   && opt_unset_or_noexpand(ob->tls_privatekey))
  {
  if (  !watch
     || (  tls_set_watch(ob->tls_certificate, FALSE)
	&& tls_set_watch(ob->tls_privatekey, FALSE)
     )  )
    {
    uschar * pkey = ob->tls_privatekey;

    DEBUG(D_tls)
      debug_printf("TLS: preloading client certs for transport '%s'\n",t->name);

    if (  tls_add_certfile(ctx, &tpt_dummy_state, ob->tls_certificate,
				    &dummy_errstr) == 0
       && tls_add_pkeyfile(ctx, &tpt_dummy_state,
				    pkey ? pkey : ob->tls_certificate,
				    &dummy_errstr) == 0
       )
      ob->tls_preload.conn_certs = TRUE;
    }
  }
else
  DEBUG(D_tls)
    debug_printf("TLS: not preloading client certs, for transport '%s'\n", t->name);


if (  opt_set_and_noexpand(ob->tls_verify_certificates)
   && opt_unset_or_noexpand(ob->tls_crl))
  {
  if (  !watch
     ||    tls_set_watch(CUS X509_get_default_cert_file(), FALSE)
        && tls_set_watch(ob->tls_verify_certificates, FALSE)
	&& tls_set_watch(ob->tls_crl, FALSE)
     )
    {
    uschar * v_certs = ob->tls_verify_certificates;
    DEBUG(D_tls)
      debug_printf("TLS: preloading CA bundle for transport '%s'\n", t->name);

    if (setup_certs(ctx, &v_certs,
	  ob->tls_crl, dummy_host, &dummy_errstr) == OK)
      ob->tls_preload.cabundle = TRUE;
    }
  }
else
  DEBUG(D_tls)
      debug_printf("TLS: not preloading CA bundle, for transport '%s'\n", t->name);

#endif /*EXIM_HAVE_INOTIFY*/
}


#if defined(EXIM_HAVE_INOTIFY) || defined(EXIM_HAVE_KEVENT)
/* Invalidate the creds cached, by dropping the current ones.
Call when we notice one of the source files has changed. */

static void
tls_server_creds_invalidate(void)
{
SSL_CTX_free(state_server.lib_state.lib_ctx);
state_server.lib_state = null_tls_preload;
#ifndef DISABLE_OCSP
state_server.u_ocsp.server.file_expanded = NULL;
#endif
}


static void
tls_client_creds_invalidate(transport_instance * t)
{
smtp_transport_options_block * ob = t->options_block;
SSL_CTX_free(ob->tls_preload.lib_ctx);
ob->tls_preload = null_tls_preload;
}

#else

static void
tls_server_creds_invalidate(void)
{ return; }

static void
tls_client_creds_invalidate(transport_instance * t)
{ return; }

#endif	/*EXIM_HAVE_INOTIFY*/


/* Extreme debug
 * */
#ifndef DISABLE_OCSP
static void
debug_print_sn(const X509 * cert)
{
X509_NAME * sn = X509_get_subject_name((X509 *)cert);
static uschar name[256];
if (X509_NAME_oneline(sn, CS name, sizeof(name)))
  {
  name[sizeof(name)-1] = '\0';
  debug_printf(" %s\n", name);
  }
}

static void
x509_stack_dump_cert_s_names(const STACK_OF(X509) * sk)
{
if (!sk)
  debug_printf(" (null)\n");
else
  {
  int idx = sk_X509_num(sk);
  if (!idx)
    debug_printf(" (empty)\n");
  else
    while (--idx >= 0) debug_print_sn(sk_X509_value(sk, idx));
  }
}

static void
x509_store_dump_cert_s_names(X509_STORE * store)
{
# ifdef EXIM_HAVE_OPENSSL_X509_STORE_GET1_ALL_CERTS
if (!store)
  debug_printf(" (no store)\n");
else
  {
  STACK_OF(X509) * sk = X509_STORE_get1_all_certs(store);
  x509_stack_dump_cert_s_names(sk);
  sk_X509_pop_free(sk, X509_free);
  }
# endif
}
#endif	/*!DISABLE_OCSP*/
/*
*/


#ifndef DISABLE_TLS_RESUME
/* Manage the keysets used for encrypting the session tickets, on the server. */

typedef struct {			/* Session ticket encryption key */
  uschar 	name[16];

  const EVP_CIPHER *	aes_cipher;
  uschar		aes_key[32];	/* size needed depends on cipher. aes_128 implies 128/8 = 16? */
# if OPENSSL_VERSION_NUMBER < 0x30000000L
  const EVP_MD *	hmac_hash;
# else
  const uschar *	hmac_hashname;
# endif
  uschar		hmac_key[16];
  time_t		renew;
  time_t		expire;
} exim_stek;

static exim_stek exim_tk;	/* current key */
static exim_stek exim_tk_old;	/* previous key */

static void
tk_init(void)
{
time_t t = time(NULL);

if (exim_tk.name[0])
  {
  if (exim_tk.renew >= t) return;
  exim_tk_old = exim_tk;
  }

if (f.running_in_test_harness) ssl_session_timeout = TESTSUITE_TICKET_LIFE;

DEBUG(D_tls) debug_printf("OpenSSL: %s STEK\n", exim_tk.name[0] ? "rotating" : "creating");
if (RAND_bytes(exim_tk.aes_key, sizeof(exim_tk.aes_key)) <= 0) return;
if (RAND_bytes(exim_tk.hmac_key, sizeof(exim_tk.hmac_key)) <= 0) return;
if (RAND_bytes(exim_tk.name+1, sizeof(exim_tk.name)-1) <= 0) return;

exim_tk.name[0] = 'E';
exim_tk.aes_cipher = EVP_aes_256_cbc();
# if OPENSSL_VERSION_NUMBER < 0x30000000L
exim_tk.hmac_hash = EVP_sha256();
# else
exim_tk.hmac_hashname = US "sha256";
# endif
exim_tk.expire = t + ssl_session_timeout;
exim_tk.renew = t + ssl_session_timeout/2;
}

static exim_stek *
tk_current(void)
{
if (!exim_tk.name[0]) return NULL;
return &exim_tk;
}

static exim_stek *
tk_find(const uschar * name)
{
return memcmp(name, exim_tk.name, sizeof(exim_tk.name)) == 0 ? &exim_tk
  : memcmp(name, exim_tk_old.name, sizeof(exim_tk_old.name)) == 0 ? &exim_tk_old
  : NULL;
}


static int
tk_hmac_init(
# if OPENSSL_VERSION_NUMBER < 0x30000000L
  HMAC_CTX * hctx,
#else
  EVP_MAC_CTX * hctx,
#endif
  exim_stek * key
  )
{
/*XXX will want these dependent on the ssl session strength */
# if OPENSSL_VERSION_NUMBER < 0x30000000L
  HMAC_Init_ex(hctx, key->hmac_key, sizeof(key->hmac_key),
		key->hmac_hash, NULL);
#else
 {
  OSSL_PARAM params[3];
  uschar * hk = string_copy(key->hmac_hashname);	/* need nonconst */
  params[0] = OSSL_PARAM_construct_octet_string("key", key->hmac_key, sizeof(key->hmac_key));
  params[1] = OSSL_PARAM_construct_utf8_string("digest", CS hk, 0);
  params[2] = OSSL_PARAM_construct_end();
  if (EVP_MAC_CTX_set_params(hctx, params) == 0)
    {
    DEBUG(D_tls) debug_printf("EVP_MAC_CTX_set_params: %s\n",
      ERR_reason_error_string(ERR_get_error()));
    return 0; /* error in mac initialisation */
    }
}
#endif
return 1;
}

/* Callback for session tickets, on server */
static int
ticket_key_callback(SSL * ssl, uschar key_name[16],
  uschar * iv, EVP_CIPHER_CTX * c_ctx,
# if OPENSSL_VERSION_NUMBER < 0x30000000L
  HMAC_CTX * hctx,
#else
  EVP_MAC_CTX * hctx,
#endif
  int enc)
{
tls_support * tlsp = state_server.tlsp;
exim_stek * key;

if (enc)
  {
  DEBUG(D_tls) debug_printf("ticket_key_callback: create new session\n");
  tlsp->resumption |= RESUME_CLIENT_REQUESTED;

  if (RAND_bytes(iv, EVP_MAX_IV_LENGTH) <= 0)
    return -1; /* insufficient random */

  if (!(key = tk_current()))	/* current key doesn't exist or isn't valid */
     return 0;			/* key couldn't be created */
  memcpy(key_name, key->name, 16);
  DEBUG(D_tls) debug_printf("STEK expire " TIME_T_FMT "\n", key->expire - time(NULL));

  if (tk_hmac_init(hctx, key) == 0) return 0;
  EVP_EncryptInit_ex(c_ctx, key->aes_cipher, NULL, key->aes_key, iv);

  DEBUG(D_tls) debug_printf("ticket created\n");
  return 1;
  }
else
  {
  time_t now = time(NULL);

  DEBUG(D_tls) debug_printf("ticket_key_callback: retrieve session\n");
  tlsp->resumption |= RESUME_CLIENT_SUGGESTED;

  if (!(key = tk_find(key_name)) || key->expire < now)
    {
    DEBUG(D_tls)
      {
      debug_printf("ticket not usable (%s)\n", key ? "expired" : "not found");
      if (key) debug_printf("STEK expire " TIME_T_FMT "\n", key->expire - now);
      }
    return 0;
    }

  if (tk_hmac_init(hctx, key) == 0) return 0;
  EVP_DecryptInit_ex(c_ctx, key->aes_cipher, NULL, key->aes_key, iv);

  DEBUG(D_tls) debug_printf("ticket usable, STEK expire " TIME_T_FMT "\n", key->expire - now);

  /* The ticket lifetime and renewal are the same as the STEK lifetime and
  renewal, which is overenthusiastic.  A factor of, say, 3x longer STEK would
  be better.  To do that we'd have to encode ticket lifetime in the name as
  we don't yet see the restored session.  Could check posthandshake for TLS1.3
  and trigger a new ticket then, but cannot do that for TLS1.2 */
  return key->renew < now ? 2 : 1;
  }
}
#endif	/* !DISABLE_TLS_RESUME */



static void
setup_cert_verify(SSL_CTX * ctx, BOOL optional,
    int (*cert_vfy_cb)(int, X509_STORE_CTX *))
{
/* If verification is optional, don't fail if no certificate */

SSL_CTX_set_verify(ctx,
    SSL_VERIFY_PEER | (optional ? 0 : SSL_VERIFY_FAIL_IF_NO_PEER_CERT),
    cert_vfy_cb);
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

XXX might need to change to using ClientHello callback,
per https://www.openssl.org/docs/manmaster/man3/SSL_client_hello_cb_fn.html
*/

#ifdef EXIM_HAVE_OPENSSL_TLSEXT
static int
tls_servername_cb(SSL * s, int * ad ARG_UNUSED, void * arg)
{
const char * servername = SSL_get_servername(s, TLSEXT_NAMETYPE_host_name);
exim_openssl_state_st * state = (exim_openssl_state_st *) arg;
int rc;
int old_pool = store_pool;
uschar * errstr;

if (!servername)
  return SSL_TLSEXT_ERR_OK;

DEBUG(D_tls) debug_printf("Received TLS SNI \"%s\"%s\n", servername,
    reexpand_tls_files_for_sni ? "" : " (unused for certificate selection)");

/* Make the extension value available for expansion */
store_pool = POOL_PERM;
tls_in.sni = string_copy_taint(US servername, GET_TAINTED);
store_pool = old_pool;

if (!reexpand_tls_files_for_sni)
  return SSL_TLSEXT_ERR_OK;

/* Can't find an SSL_CTX_clone() or equivalent, so we do it manually;
not confident that memcpy wouldn't break some internal reference counting.
Especially since there's a references struct member, which would be off. */

if (lib_ctx_new(&server_sni, NULL, &errstr) != OK)
  goto bad;

/* Not sure how many of these are actually needed, since SSL object
already exists.  Might even need this selfsame callback, for reneg? */

 {
  SSL_CTX * ctx = state_server.lib_state.lib_ctx;
  SSL_CTX_set_info_callback(server_sni, SSL_CTX_get_info_callback(ctx));
  SSL_CTX_set_mode(server_sni, SSL_CTX_get_mode(ctx));
#ifdef OPENSSL_MIN_PROTO_VERSION
  SSL_CTX_set_min_proto_version(server_sni, SSL3_VERSION);
#endif
  SSL_CTX_set_options(server_sni, SSL_CTX_get_options(ctx));
  SSL_CTX_clear_options(server_sni, ~SSL_CTX_get_options(ctx));
  SSL_CTX_set_timeout(server_sni, SSL_CTX_get_timeout(ctx));
  SSL_CTX_set_tlsext_servername_callback(server_sni, tls_servername_cb);
  SSL_CTX_set_tlsext_servername_arg(server_sni, state);
 }

if (  !init_dh(server_sni, state->dhparam, &errstr)
   || !init_ecdh(server_sni, &errstr)
   )
  goto bad;

if (  state->server_cipher_list
   && !SSL_CTX_set_cipher_list(server_sni, CS state->server_cipher_list))
  goto bad;

#ifndef DISABLE_OCSP
if (state->u_ocsp.server.file)
  {
  SSL_CTX_set_tlsext_status_cb(server_sni, tls_server_stapling_cb);
  SSL_CTX_set_tlsext_status_arg(server_sni, state);
  }
#endif

  {
  uschar * v_certs = tls_verify_certificates;
  if ((rc = setup_certs(server_sni, &v_certs, tls_crl, NULL,
			&errstr)) != OK)
    goto bad;

  if (v_certs && *v_certs)
    setup_cert_verify(server_sni, FALSE, verify_callback_server);
  }

/* do this after setup_certs, because this can require the certs for verifying
OCSP information. */
if ((rc = tls_expand_session_files(server_sni, state, &errstr)) != OK)
  goto bad;

DEBUG(D_tls) debug_printf("Switching SSL context.\n");
SSL_set_SSL_CTX(s, server_sni);
return SSL_TLSEXT_ERR_OK;

bad:
  log_write(0, LOG_MAIN|LOG_PANIC, "%s", errstr);
  return SSL_TLSEXT_ERR_ALERT_FATAL;
}
#endif /* EXIM_HAVE_OPENSSL_TLSEXT */




#ifdef EXIM_HAVE_ALPN
/*************************************************
*        Callback to handle ALPN                 *
*************************************************/

/* Called on server if tls_alpn nonblank after expansion,
when client offers ALPN, after the SNI callback.
If set and not matching the list then we dump the connection */

static int
tls_server_alpn_cb(SSL *ssl, const uschar ** out, uschar * outlen,
  const uschar * in, unsigned int inlen, void * arg)
{
gstring * g = NULL;

server_seen_alpn = TRUE;
DEBUG(D_tls)
  {
  debug_printf("Received TLS ALPN offer:");
  for (int pos = 0, siz; pos < inlen; pos += siz+1)
    {
    siz = in[pos];
    if (pos + 1 + siz > inlen) siz = inlen - pos - 1;
    debug_printf(" '%.*s'", siz, in + pos + 1);
    }
  debug_printf(".  Our list: '%s'\n", tls_alpn);
  }

/* Look for an acceptable ALPN */

if (  inlen > 1		/* at least one name */
   && in[0]+1 == inlen	/* filling the vector, so exactly one name */
   )
  {
  const uschar * list = tls_alpn;
  int sep = 0;
  for (uschar * name; name = string_nextinlist(&list, &sep, NULL, 0); )
    if (Ustrncmp(in+1, name, in[0]) == 0)
      {
      *out = in+1;			/* we checked for exactly one, so can just point to it */
      *outlen = inlen;
      return SSL_TLSEXT_ERR_OK;		/* use ALPN */
      }
  }

/* More than one name from client, or name did not match our list. */

/* This will be fatal to the TLS conn; would be nice to kill TCP also.
Maybe as an option in future; for now leave control to the config (must-tls). */

for (int pos = 0, siz; pos < inlen; pos += siz+1)
  {
  siz = in[pos];
  if (pos + 1 + siz > inlen) siz = inlen - pos - 1;
  g = string_append_listele_n(g, ':', in + pos + 1, siz);
  }
log_write(0, LOG_MAIN, "TLS ALPN (%Y) rejected", g);
gstring_release_unused(g);
return SSL_TLSEXT_ERR_ALERT_FATAL;
}
#endif	/* EXIM_HAVE_ALPN */



#ifndef DISABLE_OCSP

/*************************************************
*        Callback to handle OCSP Stapling        *
*************************************************/

/* Called when acting as server during the TLS session setup if the client
requests OCSP information with a Certificate Status Request.

Documentation via openssl s_server.c and the Apache patch from the OpenSSL
project.

*/

static int
tls_server_stapling_cb(SSL *s, void *arg)
{
const exim_openssl_state_st * state = arg;
ocsp_resplist * olist = state->u_ocsp.server.olist;
uschar * response_der;	/*XXX blob */
int response_der_len;

DEBUG(D_tls)
  debug_printf("Received TLS status request (OCSP stapling); %s response list\n",
    olist ? "have" : "lack");

tls_in.ocsp = OCSP_NOT_RESP;
if (!olist)
  return SSL_TLSEXT_ERR_NOACK;

#ifdef EXIM_HAVE_OPENSSL_GET0_SERIAL
 {
  const X509 * cert_sent = SSL_get_certificate(s);
  const ASN1_INTEGER * cert_serial = X509_get0_serialNumber(cert_sent);
  const BIGNUM * cert_bn = ASN1_INTEGER_to_BN(cert_serial, NULL);

  for (; olist; olist = olist->next)
    {
    OCSP_BASICRESP * bs = OCSP_response_get1_basic(olist->resp);
    const OCSP_SINGLERESP * single = OCSP_resp_get0(bs, 0);
    const OCSP_CERTID * cid = OCSP_SINGLERESP_get0_id(single);
    ASN1_INTEGER * res_cert_serial;
    const BIGNUM * resp_bn;
    ASN1_OCTET_STRING * res_cert_iNameHash;


    (void) OCSP_id_get0_info(&res_cert_iNameHash, NULL, NULL, &res_cert_serial,
      (OCSP_CERTID *) cid);
    resp_bn = ASN1_INTEGER_to_BN(res_cert_serial, NULL);

    DEBUG(D_tls)
      {
      debug_printf("cert serial: %s\n", BN_bn2hex(cert_bn));
      debug_printf("resp serial: %s\n", BN_bn2hex(resp_bn));
      }

    if (BN_cmp(cert_bn, resp_bn) == 0)
      {
      DEBUG(D_tls) debug_printf("matched serial for ocsp\n");

      /*XXX TODO: check the rest of the list for duplicate matches.
      If any, need to also check the Issuer Name hash.
      Without this, we will provide the wrong status in the case of
      duplicate id. */

      break;
      }
    DEBUG(D_tls) debug_printf("not match serial for ocsp\n");
    }
  if (!olist)
    {
    DEBUG(D_tls) debug_printf("failed to find match for ocsp\n");
    return SSL_TLSEXT_ERR_NOACK;
    }
 }
#else
if (olist->next)
  {
  DEBUG(D_tls) debug_printf("OpenSSL version too early to support multi-leaf OCSP\n");
  return SSL_TLSEXT_ERR_NOACK;
  }
#endif

/*XXX could we do the i2d earlier, rather than during the callback? */
response_der = NULL;
response_der_len = i2d_OCSP_RESPONSE(olist->resp, &response_der);
if (response_der_len <= 0)
  return SSL_TLSEXT_ERR_NOACK;

SSL_set_tlsext_status_ocsp_resp(state_server.lib_state.lib_ssl,
				response_der, response_der_len);
tls_in.ocsp = OCSP_VFIED;
return SSL_TLSEXT_ERR_OK;
}


static void
add_chain_to_store(X509_STORE * store, STACK_OF(X509) * sk,
  const char * debug_text)
{
int idx;

DEBUG(D_tls)
  {
  debug_printf("chain for %s:\n", debug_text);
  x509_stack_dump_cert_s_names(sk);
  }
if (sk)
  if ((idx = sk_X509_num(sk)) > 0)
    while (--idx >= 0)
      X509_STORE_add_cert(store, sk_X509_value(sk, idx));

}

static int
tls_client_stapling_cb(SSL * ssl, void * arg)
{
exim_openssl_state_st * cbinfo = arg;
const unsigned char * p;
int len;
OCSP_RESPONSE * rsp;
OCSP_BASICRESP * bs;
int i;

DEBUG(D_tls) debug_printf("Received TLS status callback (OCSP stapling):\n");
len = SSL_get_tlsext_status_ocsp_resp(ssl, &p);
if(!p)
  {				/* Expect this when we requested ocsp but got none */
  if (SSL_session_reused(ssl) && tls_out.ocsp == OCSP_VFIED)
    {
    DEBUG(D_tls) debug_printf(" null, but resumed; ocsp vfy stored with session is good\n");
    return 1;
    }

  if (cbinfo->u_ocsp.client.verify_required && LOGGING(tls_cipher))
    log_write(0, LOG_MAIN, "Required TLS certificate status not received");
  else
    DEBUG(D_tls) debug_printf(" null\n");

  if (!cbinfo->u_ocsp.client.verify_required)
    return 1;
  cbinfo->u_ocsp.client.verify_errstr =
			US"(SSL_connect) Required TLS certificate status not received";
  return 0;
  }

if (!(rsp = d2i_OCSP_RESPONSE(NULL, &p, len)))
  {
  tls_out.ocsp = OCSP_FAILED;	/*XXX should use tlsp-> to permit concurrent outbound */
  if (LOGGING(tls_cipher))
    log_write(0, LOG_MAIN, "Received TLS cert status response, parse error");
  else
    DEBUG(D_tls) debug_printf(" parse error\n");
  return 0;
  }

if (!(bs = OCSP_response_get1_basic(rsp)))
  {
  tls_out.ocsp = OCSP_FAILED;
  if (LOGGING(tls_cipher))
    log_write(0, LOG_MAIN, "Received TLS cert status response, error parsing response");
  else
    DEBUG(D_tls) debug_printf(" error parsing response\n");
  OCSP_RESPONSE_free(rsp);
  return 0;
  }

/* We'd check the nonce here if we'd put one in the request. */
/* However that would defeat cacheability on the server so we don't. */

/* This section of code reworked from OpenSSL apps source;
   The OpenSSL Project retains copyright:
   Copyright (c) 1999 The OpenSSL Project.  All rights reserved.
*/
  {
    BIO * bp = NULL;
    X509_STORE * verify_store = NULL;
    BOOL have_verified_OCSP_signer = FALSE;
#ifndef EXIM_HAVE_OCSP_RESP_COUNT
    STACK_OF(OCSP_SINGLERESP) * sresp = bs->tbsResponseData->responses;
#endif

    DEBUG(D_tls) bp = BIO_new(BIO_s_mem());

    /* Use the CA & chain that verified the server cert to verify the stapled info */
    /*XXX could we do an event here, for observability of ocsp?  What reasonable data could we give access to? */
    /* Dates would be a start. Do we need another opaque variable type, as for certs, plus an extract expansion? */

   {
    /* If this routine is not available, we've avoided [in tls_client_start()]
    asking for certificate-status under DANE, so this callback won't run for
    that combination. It still will for non-DANE. */

#if defined(EXIM_HAVE_OPENSSL_OCSP_RESP_GET0_SIGNER) && defined(SUPPORT_DANE)
    X509 * signer;

    if (  tls_out.dane_verified
       && (have_verified_OCSP_signer =
	OCSP_resp_get0_signer(bs, &signer, SSL_get0_verified_chain(ssl)) == 1))
      {
      DEBUG(D_tls)
	debug_printf("signer for OCSP basicres is in the verified chain;"
		      " shortcut its verification\n");
      }
    else
#endif
      {
      STACK_OF(X509) * verified_chain;

      verify_store = X509_STORE_new();

      SSL_get0_chain_certs(ssl, &verified_chain);
      add_chain_to_store(verify_store, verified_chain,
			      "'current cert' per SSL_get0_chain_certs()");
#ifdef EXIM_HAVE_SSL_GET0_VERIFIED_CHAIN
      verified_chain = SSL_get0_verified_chain(ssl);
      add_chain_to_store(verify_store, verified_chain,
			      "SSL_get0_verified_chain()");
#endif
      }
   }

    DEBUG(D_tls)
      {
      debug_printf("Untrusted intermediate cert stack (from SSL_get_peer_cert_chain()):\n");
      x509_stack_dump_cert_s_names(SSL_get_peer_cert_chain(ssl));

      debug_printf("will use this CA store for verifying basicresp:\n");
      x509_store_dump_cert_s_names(verify_store);

      /* OCSP_RESPONSE_print(bp, rsp, 0);   extreme debug: stapling content */

      debug_printf("certs contained in basicresp:\n");
      x509_stack_dump_cert_s_names(
#ifdef EXIM_HAVE_OPENSSL_OCSP_RESP_GET0_CERTS
	OCSP_resp_get0_certs(bs)
#else
	bs->certs
#endif
	);

#ifdef EXIM_HAVE_OPENSSL_X509_STORE_GET1_ALL_CERTS
/* could do via X509_STORE_get0_objects(); not worth it just for debug info */
       {
	X509 * signer;
	if (OCSP_resp_get0_signer(bs, &signer, X509_STORE_get1_all_certs(verify_store)) == 1)
	  {
	  debug_printf("found signer for basicres:\n");
	  debug_print_sn(signer);
	  }
	else
	  {
	  debug_printf("failed to find signer for basicres:\n");
	  ERR_print_errors(bp);
	  }
       }
#endif

      }

    ERR_clear_error();

    /* Under DANE the trust-anchor (at least in TA mode) is indicated by the TLSA
    record in DNS, and probably is not the root of the chain of certificates. So
    accept a partial chain for that case (and hope that anchor is visible for
    verifying the OCSP stapling).
    XXX for EE mode it won't even be that.  Does that make OCSP useless for EE?

    Worse, for LetsEncrypt-mode (ocsp signer is leaf-signer) under DANE, the
    data used within OpenSSL for the signer has nil pointers for signing
    algorithms - and a crash results.  Avoid this by shortcutting verification,
    having determined that the OCSP signer is in the (DANE-)validated set.
    */

#ifndef OCSP_PARTIAL_CHAIN	/* defined for 3.0.0 onwards */
# define OCSP_PARTIAL_CHAIN 0
#endif

    if ((i = OCSP_basic_verify(bs, SSL_get_peer_cert_chain(ssl),
		verify_store,
#ifdef SUPPORT_DANE
		tls_out.dane_verified
		? have_verified_OCSP_signer
		  ? OCSP_NOVERIFY | OCSP_NOEXPLICIT
		  : OCSP_PARTIAL_CHAIN | OCSP_NOEXPLICIT
		:
#endif
		OCSP_NOEXPLICIT)) <= 0)
      {
      DEBUG(D_tls) debug_printf("OCSP_basic_verify() fail: returned %d\n", i);
      if (ERR_peek_error())
	{
	tls_out.ocsp = OCSP_FAILED;
	if (LOGGING(tls_cipher))
	  {
	  static uschar peerdn[256];
	  const uschar * errstr;;

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	  ERR_peek_error_all(NULL, NULL, NULL, CCSS &errstr, NULL);
	  if (!errstr)
#endif
	    errstr = CUS ERR_reason_error_string(ERR_peek_error());

	  X509_NAME_oneline(X509_get_subject_name(SSL_get_peer_certificate(ssl)),
						  CS peerdn, sizeof(peerdn));
	  log_write(0, LOG_MAIN,
		"[%s] %s Received TLS cert (DN: '%.*s') status response, "
		"itself unverifiable: %s",
		deliver_host_address, deliver_host,
		(int)sizeof(peerdn), peerdn, errstr);
	  }
	DEBUG(D_tls)
	  {
	  BIO_printf(bp, "OCSP response verify failure\n");
	  ERR_print_errors(bp);
  {
  uschar * s = NULL;
  int len = (int) BIO_get_mem_data(bp, CSS &s);
  if (len > 0) debug_printf("%.*s", len, s);
  BIO_reset(bp);
  }
	  OCSP_RESPONSE_print(bp, rsp, 0);
	  }
	goto failed;
	}
      else
	DEBUG(D_tls) debug_printf("no explicit trust for OCSP signing"
	  " in the root CA certificate; ignoring\n");
      }

    DEBUG(D_tls) debug_printf("OCSP response well-formed and signed OK\n");

    /*XXX So we have a good stapled OCSP status.  How do we know
    it is for the cert of interest?  OpenSSL 1.1.0 has a routine
    OCSP_resp_find_status() which matches on a cert id, which presumably
    we should use. Making an id needs OCSP_cert_id_new(), which takes
    issuerName, issuerKey, serialNumber.  Are they all in the cert?

    For now, carry on blindly accepting the resp. */

    for (int idx =
#ifdef EXIM_HAVE_OCSP_RESP_COUNT
	    OCSP_resp_count(bs) - 1;
#else
	    sk_OCSP_SINGLERESP_num(sresp) - 1;
#endif
	 idx >= 0; idx--)
      {
      OCSP_SINGLERESP * single = OCSP_resp_get0(bs, idx);
      int status, reason;
      ASN1_GENERALIZEDTIME * rev, * thisupd, * nextupd;

  /*XXX so I can see putting a loop in here to handle a rsp with >1 singleresp
  - but what happens with a GnuTLS-style input?

  we could do with a debug label for each singleresp
  - it has a certID with a serialNumber, but I see no API to get that
  */
      status = OCSP_single_get0_status(single, &reason, &rev,
		  &thisupd, &nextupd);

      DEBUG(D_tls)
	{
	time_print(bp, "This OCSP Update", thisupd);
	if (nextupd) time_print(bp, "Next OCSP Update", nextupd);
	}
      if (!OCSP_check_validity(thisupd, nextupd,
	    EXIM_OCSP_SKEW_SECONDS, EXIM_OCSP_MAX_AGE))
	{
	tls_out.ocsp = OCSP_FAILED;
	DEBUG(D_tls) ERR_print_errors(bp);
	cbinfo->u_ocsp.client.verify_errstr =
		    US"(SSL_connect) Server certificate status is out-of-date";
	log_write(0, LOG_MAIN, "OCSP dates invalid");
	goto failed;
	}

      DEBUG(D_tls) BIO_printf(bp, "Certificate status: %s\n",
		    OCSP_cert_status_str(status));
      switch(status)
	{
	case V_OCSP_CERTSTATUS_GOOD:
	  continue;	/* the idx loop */
	case V_OCSP_CERTSTATUS_REVOKED:
	  cbinfo->u_ocsp.client.verify_errstr =
			US"(SSL_connect) Server certificate revoked";
	  log_write(0, LOG_MAIN, "Server certificate revoked%s%s",
	      reason != -1 ? "; reason: " : "",
	      reason != -1 ? OCSP_crl_reason_str(reason) : "");
	  DEBUG(D_tls) time_print(bp, "Revocation Time", rev);
	  break;
	default:
	  cbinfo->u_ocsp.client.verify_errstr =
			US"(SSL_connect) Server certificate has unknown status";
	  log_write(0, LOG_MAIN,
	      "Server certificate status unknown, in OCSP stapling");
	  break;
	}

      goto failed;
      }

    i = 1;
    tls_out.ocsp = OCSP_VFIED;
    goto good;

  failed:
    tls_out.ocsp = OCSP_FAILED;
    i = cbinfo->u_ocsp.client.verify_required ? 0 : 1;
  good:
    {
    uschar * s = NULL;
    int len = (int) BIO_get_mem_data(bp, CSS &s);
    if (len > 0) debug_printf("%.*s", len, s);
    }
    BIO_free(bp);
  }

OCSP_RESPONSE_free(rsp);
return i;
}
#endif	/*!DISABLE_OCSP*/


/*************************************************
*            Initialize for TLS                  *
*************************************************/
/* Called from both server and client code, to do preliminary initialization
of the library.  We allocate and return a context structure.

Arguments:
  host            connected host, if client; NULL if server
  ob		  transport options block, if client; NULL if server
  ocsp_file       file of stapling info (server); flag for require ocsp (client)
  addr            address if client; NULL if server (for some randomness)
  caller_state    place to put pointer to allocated state-struct
  errstr	  error string pointer

Returns:          OK/DEFER/FAIL
*/

static int
tls_init(host_item * host, smtp_transport_options_block * ob,
#ifndef DISABLE_OCSP
  uschar *ocsp_file,
#endif
  address_item *addr, exim_openssl_state_st ** caller_state,
  tls_support * tlsp, uschar ** errstr)
{
SSL_CTX * ctx;
exim_openssl_state_st * state;
int rc;

if (host)			/* client */
  {
  state = store_malloc(sizeof(exim_openssl_state_st));
  memset(state, 0, sizeof(*state));
  state->certificate = ob->tls_certificate;
  state->privatekey =  ob->tls_privatekey;
  state->is_server = FALSE;
  state->dhparam = NULL;
  state->lib_state = ob->tls_preload;
  }
else				/* server */
  {
  state = &state_server;
  state->certificate = tls_certificate;
  state->privatekey =  tls_privatekey;
  state->is_server = TRUE;
  state->dhparam = tls_dhparam;
  state->lib_state = state_server.lib_state;
  }

state->tlsp = tlsp;
state->host = host;

if (!state->lib_state.pri_string)
  state->server_cipher_list = NULL;

#ifndef DISABLE_EVENT
state->event_action = NULL;
#endif

tls_openssl_init();

/* It turns out that we need to seed the random number generator this early in
order to get the full complement of ciphers to work. It took me roughly a day
of work to discover this by experiment.

On systems that have /dev/urandom, SSL may automatically seed itself from
there. Otherwise, we have to make something up as best we can. Double check
afterwards.

Although we likely called this before, at daemon startup, this is a chance
to mix in further variable info (time, pid) if needed. */

if (!lib_rand_init(addr))
  return tls_error(US"RAND_status", host,
    US"unable to seed random number generator", errstr);

/* Apply administrator-supplied work-arounds.
Historically we applied just one requested option,
SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS, but when bug 994 requested a second, we
moved to an administrator-controlled list of options to specify and
grandfathered in the first one as the default value for "openssl_options".

No OpenSSL version number checks: the options we accept depend upon the
availability of the option value macros from OpenSSL.  */

if (!init_options)
  if (!tls_openssl_options_parse(openssl_options, &init_options))
    return tls_error(US"openssl_options parsing failed", host, NULL, errstr);

/* Create a context.
The OpenSSL docs in 1.0.1b have not been updated to clarify TLS variant
negotiation in the different methods; as far as I can tell, the only
*_{server,client}_method which allows negotiation is SSLv23, which exists even
when OpenSSL is built without SSLv2 support.
By disabling with openssl_options, we can let admins re-enable with the
existing knob. */

if (!(ctx = state->lib_state.lib_ctx))
  {
  if ((rc = lib_ctx_new(&ctx, host, errstr)) != OK)
    return rc;
  state->lib_state.lib_ctx = ctx;
  }

#ifndef DISABLE_TLS_RESUME
tlsp->resumption = RESUME_SUPPORTED;
#endif
if (init_options)
  {
#ifndef DISABLE_TLS_RESUME
  /* Should the server offer session resumption? */
  if (!host && verify_check_host(&tls_resumption_hosts) == OK)
    {
    DEBUG(D_tls) debug_printf("tls_resumption_hosts overrides openssl_options\n");
    init_options &= ~SSL_OP_NO_TICKET;
    tlsp->resumption |= RESUME_SERVER_TICKET; /* server will give ticket on request */
    tlsp->host_resumable = TRUE;
    }
#endif

#ifdef OPENSSL_MIN_PROTO_VERSION
  SSL_CTX_set_min_proto_version(ctx, SSL3_VERSION);
#endif
  DEBUG(D_tls) debug_printf("setting  SSL CTX options: %016lx\n", init_options);
  SSL_CTX_set_options(ctx, init_options);
   {
    uint64_t readback = SSL_CTX_clear_options(ctx, ~init_options);
    if (readback != init_options)
      return tls_error(string_sprintf(
          "SSL_CTX_set_option(%#lx)", init_options), host, NULL, errstr);
   }
  }
else
  DEBUG(D_tls) debug_printf("no SSL CTX options to set\n");

/* We'd like to disable session cache unconditionally, but foolish Outlook
Express clients then give up the first TLS connection and make a second one
(which works).  Only when there is an IMAP service on the same machine.
Presumably OE is trying to use the cache for A on B.  Leave it enabled for
now, until we work out a decent way of presenting control to the config.  It
will never be used because we use a new context every time. */
#ifdef notdef
(void) SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
#endif

/* Initialize with DH parameters if supplied */
/* Initialize ECDH temp key parameter selection */

if (!host)
  {
  if (state->lib_state.dh)
    { DEBUG(D_tls) debug_printf("TLS: DH params were preloaded\n"); }
  else
    if (!init_dh(ctx, state->dhparam, errstr)) return DEFER;

  if (state->lib_state.ecdh)
    { DEBUG(D_tls) debug_printf("TLS: ECDH curve was preloaded\n"); }
  else
    if (!init_ecdh(ctx, errstr)) return DEFER;
  }

/* Set up certificate and key (and perhaps OCSP info) */

if (state->lib_state.conn_certs)
  {
  DEBUG(D_tls)
    debug_printf("TLS: %s certs were preloaded\n", host ? "client":"server");
  }
else
  {
#ifndef DISABLE_OCSP
  if (!host)					/* server */
    {
    state->u_ocsp.server.file = ocsp_file;
    state->u_ocsp.server.file_expanded = NULL;
    state->u_ocsp.server.olist = NULL;
    }
#endif
  if ((rc = tls_expand_session_files(ctx, state, errstr)) != OK) return rc;
  }

/* If we need to handle SNI or OCSP, do so */

#ifdef EXIM_HAVE_OPENSSL_TLSEXT
# ifndef DISABLE_OCSP
  if (!host && !(state->u_ocsp.server.verify_stack = sk_X509_new_null()))
    {
    DEBUG(D_tls) debug_printf("failed to create stack for stapling verify\n");
    return FAIL;
    }
# endif

if (!host)		/* server */
  {
# ifndef DISABLE_OCSP
  /* We check u_ocsp.server.file, not server.olist, because we care about if
  the option exists, not what the current expansion might be, as SNI might
  change the certificate and OCSP file in use between now and the time the
  callback is invoked. */
  if (state->u_ocsp.server.file)
    {
    SSL_CTX_set_tlsext_status_cb(ctx, tls_server_stapling_cb);
    SSL_CTX_set_tlsext_status_arg(ctx, state);
    }
# endif
  /* We always do this, so that $tls_sni is available even if not used in
  tls_certificate */
  SSL_CTX_set_tlsext_servername_callback(ctx, tls_servername_cb);
  SSL_CTX_set_tlsext_servername_arg(ctx, state);

# ifdef EXIM_HAVE_ALPN
  if (tls_alpn && *tls_alpn)
    {
    uschar * exp_alpn;
    if (  expand_check(tls_alpn, US"tls_alpn", &exp_alpn, errstr)
       && *exp_alpn && !isblank(*exp_alpn))
      {
      tls_alpn = exp_alpn;	/* subprocess so ok to overwrite */
      SSL_CTX_set_alpn_select_cb(ctx, tls_server_alpn_cb, state);
      }
    else
      tls_alpn = NULL;
    }
# endif
  }
# ifndef DISABLE_OCSP
else			/* client */
  if(ocsp_file)		/* wanting stapling */
    {
    if (!(state->u_ocsp.client.verify_store = X509_STORE_new()))
      {
      DEBUG(D_tls) debug_printf("failed to create store for stapling verify\n");
      return FAIL;
      }

    SSL_CTX_set_tlsext_status_cb(ctx, tls_client_stapling_cb);
    SSL_CTX_set_tlsext_status_arg(ctx, state);
    }
# endif
#endif	/*EXIM_HAVE_OPENSSL_TLSEXT*/

state->verify_cert_hostnames = NULL;

#ifdef EXIM_HAVE_EPHEM_RSA_KEX
/* Set up the RSA callback */
SSL_CTX_set_tmp_rsa_callback(ctx, rsa_callback);
#endif

/* Finally, set the session cache timeout, and we are done.
The period appears to be also used for (server-generated) session tickets */

SSL_CTX_set_timeout(ctx, ssl_session_timeout);
DEBUG(D_tls) debug_printf("Initialized TLS\n");

*caller_state = state;

return OK;
}




/*************************************************
*           Get name of cipher in use            *
*************************************************/

/*
Argument:   pointer to an SSL structure for the connection
	    pointer to number of bits for cipher
Returns:    pointer to allocated string in perm-pool
*/

static uschar *
construct_cipher_name(SSL * ssl, const uschar * ver, int * bits)
{
int pool = store_pool;
/* With OpenSSL 1.0.0a, 'c' needs to be const but the documentation doesn't
yet reflect that.  It should be a safe change anyway, even 0.9.8 versions have
the accessor functions use const in the prototype. */

const SSL_CIPHER * c = (const SSL_CIPHER *) SSL_get_current_cipher(ssl);
uschar * s;

SSL_CIPHER_get_bits(c, bits);

store_pool = POOL_PERM;
s = string_sprintf("%s:%s:%u", ver, SSL_CIPHER_get_name(c), *bits);
store_pool = pool;
DEBUG(D_tls) debug_printf("Cipher: %s\n", s);
return s;
}


/* Get IETF-standard name for ciphersuite.
Argument:   pointer to an SSL structure for the connection
Returns:    pointer to string
*/

static const uschar *
cipher_stdname_ssl(SSL * ssl)
{
#ifdef EXIM_HAVE_OPENSSL_CIPHER_STD_NAME
return CUS SSL_CIPHER_standard_name(SSL_get_current_cipher(ssl));
#else
ushort id = 0xffff & SSL_CIPHER_get_id(SSL_get_current_cipher(ssl));
return cipher_stdname(id >> 8, id & 0xff);
#endif
}


static const uschar *
tlsver_name(SSL * ssl)
{
uschar * s, * p;
int pool = store_pool;

store_pool = POOL_PERM;
s = string_copy(US SSL_get_version(ssl));
store_pool = pool;
if ((p = Ustrchr(s, 'v')))	/* TLSv1.2 -> TLS1.2 */
  for (;; p++) if (!(*p = p[1])) break;
return CUS s;
}


static void
peer_cert(SSL * ssl, tls_support * tlsp, uschar * peerdn, unsigned siz)
{
/*XXX we might consider a list-of-certs variable for the cert chain.
SSL_get_peer_cert_chain(SSL*).  We'd need a new variable type and support
in list-handling functions, also consider the difference between the entire
chain and the elements sent by the peer. */

tlsp->peerdn = NULL;

/* Will have already noted peercert on a verify fail; possibly not the leaf */
if (!tlsp->peercert)
  tlsp->peercert = SSL_get_peer_certificate(ssl);
/* Beware anonymous ciphers which lead to server_cert being NULL */
if (tlsp->peercert)
  if (!X509_NAME_oneline(X509_get_subject_name(tlsp->peercert), CS peerdn, siz))
    { DEBUG(D_tls) debug_printf("X509_NAME_oneline() error\n"); }
  else
    {
    int oldpool = store_pool;

    peerdn[siz-1] = '\0';		/* paranoia */
    store_pool = POOL_PERM;
    tlsp->peerdn = string_copy(peerdn);
    store_pool = oldpool;

    /* We used to set CV in the cert-verify callbacks (either plain or dane)
    but they don't get called on session-resumption.  So use the official
    interface, which uses the resumed value.  Unfortunately this claims verified
    when it actually failed but we're in try-verify mode, due to us wanting the
    knowlege that it failed so needing to have the callback and forcing a
    permissive return.  If we don't force it, the TLS startup is failed.
    The extra bit of information is set in verify_override in the cb, stashed
    for resumption next to the TLS session, and used here. */

    if (!tlsp->verify_override)
      tlsp->certificate_verified =
#ifdef SUPPORT_DANE
	tlsp->dane_verified ||
#endif
	SSL_get_verify_result(ssl) == X509_V_OK;
    }
}





/*************************************************
*        Set up for verifying certificates       *
*************************************************/

#ifndef DISABLE_OCSP
/* In the server, load certs from file, return TRUE on success */

static BOOL
chain_from_pem_file(const uschar * file, STACK_OF(X509) ** vp)
{
BIO * bp;
STACK_OF(X509) * verify_stack = *vp;

if (verify_stack)
  while (sk_X509_num(verify_stack) > 0)
    X509_free(sk_X509_pop(verify_stack));
else
  verify_stack = sk_X509_new_null();

if (!(bp = BIO_new_file(CS file, "r"))) return FALSE;
for (X509 * x; x = PEM_read_bio_X509(bp, NULL, 0, NULL); )
  sk_X509_push(verify_stack, x);
BIO_free(bp);
*vp = verify_stack;
return TRUE;
}
#endif



/* Called by both client and server startup; on the server possibly
repeated after a Server Name Indication.

Arguments:
  sctx          SSL_CTX* to initialise
  certsp        certs file, returned expanded
  crl           CRL file or NULL
  host          NULL in a server; the remote host in a client
  errstr	error string pointer

Returns:        OK/DEFER/FAIL
*/

static int
setup_certs(SSL_CTX * sctx, uschar ** certsp, uschar * crl, host_item * host,
    uschar ** errstr)
{
uschar * expcerts, * expcrl;

if (!expand_check(*certsp, US"tls_verify_certificates", &expcerts, errstr))
  return DEFER;
DEBUG(D_tls) debug_printf("tls_verify_certificates: %s\n", expcerts);

*certsp = expcerts;
if (expcerts && *expcerts)
  {
  /* Tell the library to use its compiled-in location for the system default
  CA bundle. Then add the ones specified in the config, if any. */

  if (!SSL_CTX_set_default_verify_paths(sctx))
    return tls_error(US"SSL_CTX_set_default_verify_paths", host, NULL, errstr);

  if (Ustrcmp(expcerts, "system") != 0 && Ustrncmp(expcerts, "system,", 7) != 0)
    {
    struct stat statbuf;

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
	{
	STACK_OF(X509) * verify_stack =
#ifndef DISABLE_OCSP
	  !host ? state_server.u_ocsp.server.verify_stack :
#endif
	  NULL;
	STACK_OF(X509) ** vp = &verify_stack;

	file = expcerts; dir = NULL;
#ifndef DISABLE_OCSP
	/* In the server if we will be offering an OCSP proof; load chain from
	file for verifying the OCSP proof at load time. */

/*XXX Glitch!   The file here is tls_verify_certs: the chain for verifying the client cert.
This is inconsistent with the need to verify the OCSP proof of the server cert.
*/
/* *debug_printf("file for checking server ocsp stapling is: %s\n", file); */
	if (  !host
	   && statbuf.st_size > 0
	   && state_server.u_ocsp.server.file
	   && !chain_from_pem_file(file, vp)
	   )
	  {
	  log_write(0, LOG_MAIN|LOG_PANIC,
	    "failed to load cert chain from %s", file);
	  return DEFER;
	  }
#endif
	}

      /* If a certificate file is empty, the load function fails with an
      unhelpful error message. If we skip it, we get the correct behaviour (no
      certificates are recognized, but the error message is still misleading (it
      says no certificate was supplied).  But this is better. */

      if (  (!file || statbuf.st_size > 0)
         && !SSL_CTX_load_verify_locations(sctx, CS file, CS dir))
	  return tls_error(US"SSL_CTX_load_verify_locations",
			    host, NULL, errstr);

      /* On the server load the list of CAs for which we will accept certs, for
      sending to the client.  This is only for the one-file
      tls_verify_certificates variant.
      If a list isn't loaded into the server, but some verify locations are set,
      the server end appears to make a wildcard request for client certs.
      Meanwhile, the client library as default behaviour *ignores* the list
      we send over the wire - see man SSL_CTX_set_client_cert_cb.
      Because of this, and that the dir variant is likely only used for
      the public-CA bundle (not for a private CA), not worth fixing.  */

      if (file)
	{
	STACK_OF(X509_NAME) * names = SSL_load_client_CA_file(CS file);
	int i = sk_X509_NAME_num(names);

	if (!host) SSL_CTX_set_client_CA_list(sctx, names);
	DEBUG(D_tls) debug_printf("Added %d additional certificate authorit%s\n",
				    i, i>1 ? "ies":"y");
	}
      else
	DEBUG(D_tls)
	  debug_printf("Added dir for additional certificate authorities\n");
      }
    }

  /* Handle a certificate revocation list. */

#if OPENSSL_VERSION_NUMBER > 0x00907000L

  /* This bit of code is now the version supplied by Lars Mainka. (I have
  merely reformatted it into the Exim code style.)

  "From here I changed the code to add support for multiple crl's
  in pem format in one file or to support hashed directory entries in
  pem format instead of a file. This method now uses the library function
  X509_STORE_load_locations to add the CRL location to the SSL context.
  OpenSSL will then handle the verify against CA certs and CRLs by
  itself in the verify callback." */

  if (!expand_check(crl, US"tls_crl", &expcrl, errstr)) return DEFER;
  if (expcrl && *expcrl)
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
        return tls_error(US"X509_STORE_load_locations", host, NULL, errstr);

      /* setting the flags to check against the complete crl chain */

      X509_STORE_set_flags(cvstore,
        X509_V_FLAG_CRL_CHECK|X509_V_FLAG_CRL_CHECK_ALL);
      }
    }

#endif  /* OPENSSL_VERSION_NUMBER > 0x00907000L */
  }

return OK;
}



static void
tls_dump_keylog(SSL * ssl)
{
#ifdef EXIM_HAVE_OPENSSL_KEYLOG
  BIO * bp = BIO_new(BIO_s_mem());
  uschar * s = NULL;
  int len;
  SSL_SESSION_print_keylog(bp, SSL_get_session(ssl));
  len = (int) BIO_get_mem_data(bp, CSS &s);
  if (len > 0) debug_printf("%.*s", len, s);
  BIO_free(bp);
#endif
}


/* Channel-binding info for authenticators
See description in https://paquier.xyz/postgresql-2/channel-binding-openssl/
for pre-TLS1.3
*/

static void
tls_get_channel_binding(SSL * ssl, tls_support * tlsp, const void * taintval)
{
uschar c, * s;
size_t len;

#ifdef EXIM_HAVE_EXPORT_CHNL_BNGNG
if (SSL_version(ssl) > TLS1_2_VERSION)
  {
  /* It's not documented by OpenSSL how big the output buffer must be.
  The OpenSSL testcases use 80 bytes but don't say why. The GnuTLS impl only
  serves out 32B.  RFC 9266 says it is 32B.
  Interop fails unless we use the same each end. */
  len = 32;

  tlsp->channelbind_exporter = TRUE;
  taintval = GET_UNTAINTED;
  if (SSL_export_keying_material(ssl,
	s = store_get((int)len, taintval), len,
	"EXPORTER-Channel-Binding", (size_t) 24,
	NULL, 0, 0) != 1)
    len = 0;
  }
else
#endif
  {
  len = SSL_get_peer_finished(ssl, &c, 0);
  len = SSL_get_peer_finished(ssl, s = store_get((int)len, taintval), len);
  }

if (len > 0)
  {
  int old_pool = store_pool;
  store_pool = POOL_PERM;
    tlsp->channelbinding = b64encode_taint(CUS s, (int)len, taintval);
  store_pool = old_pool;
  DEBUG(D_tls) debug_printf("Have channel bindings cached for possible auth usage %p %p\n", tlsp->channelbinding, tlsp);
  }
}


/*************************************************
*       Start a TLS session in a server          *
*************************************************/
/* This is called when Exim is running as a server, after having received
the STARTTLS command. It must respond to that command, and then negotiate
a TLS session.

Arguments:
  errstr	    pointer to error message

Returns:            OK on success
                    DEFER for errors before the start of the negotiation
                    FAIL for errors during the negotiation; the server can't
                      continue running.
*/

int
tls_server_start(uschar ** errstr)
{
int rc;
uschar * expciphers;
exim_openssl_state_st * dummy_statep;
SSL_CTX * ctx;
SSL * ssl;
static uschar peerdn[256];

/* Check for previous activation */

if (tls_in.active.sock >= 0)
  {
  tls_error(US"STARTTLS received after TLS started", NULL, US"", errstr);
  smtp_printf("554 Already in TLS\r\n", SP_NO_MORE);
  return FAIL;
  }

/* Initialize the SSL library. If it fails, it will already have logged
the error. */

rc = tls_init(NULL, NULL,
#ifndef DISABLE_OCSP
    tls_ocsp_file,
#endif
    NULL, &dummy_statep, &tls_in, errstr);
if (rc != OK) return rc;
ctx = state_server.lib_state.lib_ctx;

/* In OpenSSL, cipher components are separated by hyphens. In GnuTLS, they
were historically separated by underscores. So that I can use either form in my
tests, and also for general convenience, we turn underscores into hyphens here.

XXX SSL_CTX_set_cipher_list() is replaced by SSL_CTX_set_ciphersuites()
for TLS 1.3 .  Since we do not call it at present we get the default list:
TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256
*/

if (state_server.lib_state.pri_string)
  { DEBUG(D_tls) debug_printf("TLS: cipher list was preloaded\n"); }
else
  {
  if (!expand_check(tls_require_ciphers, US"tls_require_ciphers", &expciphers, errstr))
    return FAIL;

  if (expciphers)
    {
    normalise_ciphers(&expciphers, tls_require_ciphers);
    if ((rc = server_load_ciphers(ctx, &state_server, expciphers, errstr)) != OK)
      return rc;
    }
  }

/* If this is a host for which certificate verification is mandatory or
optional, set up appropriately. */

tls_in.certificate_verified = FALSE;
#ifdef SUPPORT_DANE
tls_in.dane_verified = FALSE;
#endif
server_verify_callback_called = FALSE;

if (verify_check_host(&tls_verify_hosts) == OK)
  server_verify_optional = FALSE;
else if (verify_check_host(&tls_try_verify_hosts) == OK)
  server_verify_optional = TRUE;
else
  goto skip_certs;

 {
  uschar * v_certs = tls_verify_certificates;

  if (state_server.lib_state.cabundle)
    {
    DEBUG(D_tls) debug_printf("TLS: CA bundle for server was preloaded\n");
    setup_cert_verify(ctx, server_verify_optional, verify_callback_server);
    }
  else
    {
    if ((rc = setup_certs(ctx, &v_certs, tls_crl, NULL, errstr)) != OK)
      return rc;
    if (v_certs && *v_certs)
      setup_cert_verify(ctx, server_verify_optional, verify_callback_server);
    }
 }
skip_certs: ;

#ifndef DISABLE_TLS_RESUME
# if OPENSSL_VERSION_NUMBER < 0x30000000L
SSL_CTX_set_tlsext_ticket_key_cb(ctx, ticket_key_callback);
/* despite working, appears to always return failure, so ignoring */
# else
SSL_CTX_set_tlsext_ticket_key_evp_cb(ctx, ticket_key_callback);
/* despite working, appears to always return failure, so ignoring */
# endif
#endif

#ifdef OPENSSL_HAVE_NUM_TICKETS
# ifndef DISABLE_TLS_RESUME
SSL_CTX_set_num_tickets(ctx, tls_in.host_resumable ? 1 : 0);
# else
SSL_CTX_set_num_tickets(ctx, 0);	/* send no TLS1.3 stateful-tickets */
# endif
#endif


/* Prepare for new connection */

if (!(ssl = SSL_new(ctx)))
  return tls_error(US"SSL_new", NULL, NULL, errstr);
state_server.lib_state.lib_ssl = ssl;

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

SSL_set_session_id_context(ssl, sid_ctx, Ustrlen(sid_ctx));
if (!tls_in.on_connect)
  {
  smtp_printf("220 TLS go ahead\r\n", SP_NO_MORE);
  fflush(smtp_out);
  }

/* Now negotiate the TLS session. We put our own timer on it, since it seems
that the OpenSSL library doesn't. */

SSL_set_wfd(ssl, fileno(smtp_out));
SSL_set_rfd(ssl, fileno(smtp_in));
SSL_set_accept_state(ssl);

DEBUG(D_tls) debug_printf("Calling SSL_accept\n");

ERR_clear_error();
sigalrm_seen = FALSE;
if (smtp_receive_timeout > 0) ALARM(smtp_receive_timeout);
rc = SSL_accept(ssl);
ALARM_CLR(0);

if (rc <= 0)
  {
  int error = SSL_get_error(ssl, rc);
  switch(error)
    {
    case SSL_ERROR_NONE:
      break;

    case SSL_ERROR_ZERO_RETURN:
      DEBUG(D_tls) debug_printf("Got SSL_ERROR_ZERO_RETURN\n");
      (void) tls_error(US"SSL_accept", NULL, sigalrm_seen ? US"timed out" : NULL, errstr);
#ifndef DISABLE_EVENT
      (void) event_raise(event_action, US"tls:fail:connect", *errstr, NULL);
#endif
      if (SSL_get_shutdown(ssl) == SSL_RECEIVED_SHUTDOWN)
	SSL_shutdown(ssl);

      tls_close(NULL, TLS_NO_SHUTDOWN);
      return FAIL;

    /* Handle genuine errors */
    case SSL_ERROR_SSL:
      {
      uschar * s = NULL;
      int r = ERR_GET_REASON(ERR_peek_error());
      if (  r == SSL_R_WRONG_VERSION_NUMBER
#ifdef SSL_R_VERSION_TOO_LOW
         || r == SSL_R_VERSION_TOO_LOW
#endif
         || r == SSL_R_UNKNOWN_PROTOCOL || r == SSL_R_UNSUPPORTED_PROTOCOL)
	s = string_sprintf("(%s)", SSL_get_version(ssl));
      (void) tls_error(US"SSL_accept", NULL, sigalrm_seen ? US"timed out" : s, errstr);
#ifndef DISABLE_EVENT
      (void) event_raise(event_action, US"tls:fail:connect", *errstr, NULL);
#endif
      return FAIL;
      }

    default:
      DEBUG(D_tls) debug_printf("Got SSL error %d\n", error);
      if (error == SSL_ERROR_SYSCALL)
	{
	if (!errno)
	  {
	  *errstr = US"SSL_accept: TCP connection closed by peer";
#ifndef DISABLE_EVENT
	  (void) event_raise(event_action, US"tls:fail:connect", *errstr, NULL);
#endif
	  return FAIL;
	  }
	DEBUG(D_tls) debug_printf(" - syscall %s\n", strerror(errno));
	}
      (void) tls_error(US"SSL_accept", NULL,
		      sigalrm_seen ? US"timed out"
		      : ERR_peek_error() ? NULL : string_sprintf("ret %d", error),
		      errstr);
#ifndef DISABLE_EVENT
      (void) event_raise(event_action, US"tls:fail:connect", *errstr, NULL);
#endif
      return FAIL;
    }
  }

DEBUG(D_tls) debug_printf("SSL_accept was successful\n");
ERR_clear_error();	/* Even success can leave errors in the stack. Seen with
			anon-authentication ciphersuite negotiated. */

#ifndef DISABLE_TLS_RESUME
if (SSL_session_reused(ssl))
  {
  tls_in.resumption |= RESUME_USED;
  DEBUG(D_tls) debug_printf("Session reused\n");
  }
#endif

#ifdef EXIM_HAVE_ALPN
/* If require-alpn, check server_seen_alpn here.  Else abort TLS */
if (!tls_alpn || !*tls_alpn)
  { DEBUG(D_tls) debug_printf("TLS: was not watching for ALPN\n"); }
else if (!server_seen_alpn)
  if (verify_check_host(&hosts_require_alpn) == OK)
    {
    /* We'd like to send a definitive Alert but OpenSSL provides no facility */
    SSL_shutdown(ssl);
    tls_error(US"handshake", NULL, US"ALPN required but not negotiated", errstr);
    return FAIL;
    }
  else
    { DEBUG(D_tls) debug_printf("TLS: no ALPN presented in handshake\n"); }
else DEBUG(D_tls)
  {
  const uschar * name;
  unsigned len;
  SSL_get0_alpn_selected(ssl, &name, &len);
  if (len && name)
    debug_printf("ALPN negotiated: '%.*s'\n", (int)*name, name+1);
  else
    debug_printf("ALPN: no protocol negotiated\n");
  }
#endif


/* TLS has been set up. Record data for the connection,
adjust the input functions to read via TLS, and initialize things. */

#ifdef SSL_get_extms_support
/*XXX what does this return for tls1.3 ? */
tls_in.ext_master_secret = SSL_get_extms_support(ssl) == 1;
#endif
peer_cert(ssl, &tls_in, peerdn, sizeof(peerdn));

tls_in.ver = tlsver_name(ssl);
tls_in.cipher = construct_cipher_name(ssl, tls_in.ver, &tls_in.bits);
tls_in.cipher_stdname = cipher_stdname_ssl(ssl);

DEBUG(D_tls)
  {
  uschar buf[2048];
  if (SSL_get_shared_ciphers(ssl, CS buf, sizeof(buf)))
    debug_printf("Shared ciphers: %s\n", buf);

  tls_dump_keylog(ssl);

#ifdef EXIM_HAVE_SESSION_TICKET
  {
  SSL_SESSION * ss = SSL_get_session(ssl);
  if (SSL_SESSION_has_ticket(ss))	/* 1.1.0 */
    debug_printf("The session has a ticket, life %lu seconds\n",
      SSL_SESSION_get_ticket_lifetime_hint(ss));
  }
#endif
  }

/* Record the certificate we presented */
  {
  X509 * crt = SSL_get_certificate(ssl);
  tls_in.ourcert = crt ? X509_dup(crt) : NULL;
  }

tls_get_channel_binding(ssl, &tls_in, GET_UNTAINTED);

/* Only used by the server-side tls (tls_in), including tls_getc.
   Client-side (tls_out) reads (seem to?) go via
   smtp_read_response()/ip_recv().
   Hence no need to duplicate for _in and _out.
 */
if (!ssl_xfer_buffer) ssl_xfer_buffer = store_malloc(ssl_xfer_buffer_size);
ssl_xfer_buffer_lwm = ssl_xfer_buffer_hwm = 0;
ssl_xfer_eof = ssl_xfer_error = FALSE;

receive_getc = tls_getc;
receive_getbuf = tls_getbuf;
receive_get_cache = tls_get_cache;
receive_hasc = tls_hasc;
receive_ungetc = tls_ungetc;
receive_feof = tls_feof;
receive_ferror = tls_ferror;

tls_in.active.sock = fileno(smtp_out);
tls_in.active.tls_ctx = NULL;	/* not using explicit ctx for server-side */
return OK;
}




static int
tls_client_basic_ctx_init(SSL_CTX * ctx,
    host_item * host, smtp_transport_options_block * ob, exim_openssl_state_st * state,
    uschar ** errstr)
{
int rc;

/* Back-compatible old behaviour if tls_verify_certificates is set but both
tls_verify_hosts and tls_try_verify_hosts are not set. Check only the specified
host patterns if one of them is set with content. */

if (  (  (  !ob->tls_verify_hosts || !ob->tls_verify_hosts
	 || Ustrcmp(ob->tls_try_verify_hosts, ":") == 0
	 )
      && (  !ob->tls_try_verify_hosts || !*ob->tls_try_verify_hosts
	 || Ustrcmp(ob->tls_try_verify_hosts, ":") == 0
         )
      )
   || verify_check_given_host(CUSS &ob->tls_verify_hosts, host) == OK
   )
  client_verify_optional = FALSE;
else if (verify_check_given_host(CUSS &ob->tls_try_verify_hosts, host) == OK)
  client_verify_optional = TRUE;
else
  return OK;

 {
  uschar * v_certs = ob->tls_verify_certificates;

  if (state->lib_state.cabundle)
    {
    DEBUG(D_tls) debug_printf("TLS: CA bundle for tpt was preloaded\n");
    setup_cert_verify(ctx, client_verify_optional, verify_callback_client);
    }
  else
    {
    if ((rc = setup_certs(ctx, &v_certs, ob->tls_crl, host, errstr)) != OK)
      return rc;
    if (v_certs && *v_certs)
      setup_cert_verify(ctx, client_verify_optional, verify_callback_client);
    }
 }

if (verify_check_given_host(CUSS &ob->tls_verify_cert_hostnames, host) == OK)
  {
  state->verify_cert_hostnames =
#ifdef SUPPORT_I18N
    string_domain_utf8_to_alabel(host->certname, NULL);
#else
    host->certname;
#endif
  DEBUG(D_tls) debug_printf("Cert hostname to check: \"%s\"\n",
		    state->verify_cert_hostnames);
  }
return OK;
}


#ifdef SUPPORT_DANE
static int
dane_tlsa_load(SSL * ssl, host_item * host, dns_answer * dnsa, uschar ** errstr)
{
dns_scan dnss;
const char * hostnames[2] = { CS host->name, NULL };
int found = 0;

if (DANESSL_init(ssl, NULL, hostnames) != 1)
  return tls_error(US"hostnames load", host, NULL, errstr);

for (dns_record * rr = dns_next_rr(dnsa, &dnss, RESET_ANSWERS); rr;
     rr = dns_next_rr(dnsa, &dnss, RESET_NEXT)
    ) if (rr->type == T_TLSA && rr->size > 3)
  {
  const uschar * p = rr->data;
  uint8_t usage, selector, mtype;
  const char * mdname;

  usage = *p++;

  /* Only DANE-TA(2) and DANE-EE(3) are supported */
  if (usage != 2 && usage != 3) continue;

  selector = *p++;
  mtype = *p++;

  switch (mtype)
    {
    default: continue;	/* Only match-types 0, 1, 2 are supported */
    case 0:  mdname = NULL; break;
    case 1:  mdname = "sha256"; break;
    case 2:  mdname = "sha512"; break;
    }

  found++;
  switch (DANESSL_add_tlsa(ssl, usage, selector, mdname, p, rr->size - 3))
    {
    default:
      return tls_error(US"tlsa load", host, NULL, errstr);
    case 0:	/* action not taken */
    case 1:	break;
    }

  tls_out.tlsa_usage |= 1<<usage;
  }

if (found)
  return OK;

log_write(0, LOG_MAIN, "DANE error: No usable TLSA records");
return DEFER;
}
#endif	/*SUPPORT_DANE*/



#ifndef DISABLE_TLS_RESUME
/* On the client, get any stashed session for the given IP from hints db
and apply it to the ssl-connection for attempted resumption. */

static void
tls_retrieve_session(tls_support * tlsp, SSL * ssl)
{
if (tlsp->host_resumable)
  {
  dbdata_tls_session * dt;
  int len;
  open_db dbblock, * dbm_file;

  tlsp->resumption |= RESUME_CLIENT_REQUESTED;
  DEBUG(D_tls)
    debug_printf("checking for resumable session for %s\n", tlsp->resume_index);
  if ((dbm_file = dbfn_open(US"tls", O_RDWR, &dbblock, FALSE, FALSE)))
    {
    if ((dt = dbfn_read_with_length(dbm_file, tlsp->resume_index, &len)))
      {
      SSL_SESSION * ss = NULL;
      const uschar * sess_asn1 = dt->session;

      len -= sizeof(dbdata_tls_session);
      if (!(d2i_SSL_SESSION(&ss, &sess_asn1, (long)len)))
	{
	DEBUG(D_tls)
	  {
	  ERR_error_string_n(ERR_get_error(),
	    ssl_errstring, sizeof(ssl_errstring));
	  debug_printf("decoding session: %s\n", ssl_errstring);
	  }
	}
      else
	{
	unsigned long lifetime =
#ifdef EXIM_HAVE_SESSION_TICKET
	  SSL_SESSION_get_ticket_lifetime_hint(ss);
#else			/* Use, fairly arbitrilarily, what we as server would */
	  f.running_in_test_harness ? TESTSUITE_TICKET_LIFE : ssl_session_timeout;
#endif
	time_t now = time(NULL), expires = lifetime + dt->time_stamp;
	if (expires < now)
	  {
	  DEBUG(D_tls) debug_printf("session expired (by " TIME_T_FMT "s from %lus)\n", now - expires, lifetime);
	  dbfn_delete(dbm_file, tlsp->resume_index);
	  }
	else if (SSL_set_session(ssl, ss))
	  {
	  DEBUG(D_tls) debug_printf("good session (" TIME_T_FMT "s left of %lus)\n", expires - now, lifetime);
	  tlsp->resumption |= RESUME_CLIENT_SUGGESTED;
	  tlsp->verify_override = dt->verify_override;
	  tlsp->ocsp = dt->ocsp;
	  }
	else DEBUG(D_tls)
	  {
	  ERR_error_string_n(ERR_get_error(),
	    ssl_errstring, sizeof(ssl_errstring));
	  debug_printf("applying session to ssl: %s\n", ssl_errstring);
	  }
	}
      }
    else
      DEBUG(D_tls) debug_printf("no session record\n");
    dbfn_close(dbm_file);
    }
  }
}


/* On the client, save the session for later resumption */

static int
tls_save_session_cb(SSL * ssl, SSL_SESSION * ss)
{
exim_openssl_state_st * cbinfo = SSL_get_ex_data(ssl, tls_exdata_idx);
tls_support * tlsp;

DEBUG(D_tls) debug_printf("tls_save_session_cb\n");

if (!cbinfo || !(tlsp = cbinfo->tlsp)->host_resumable) return 0;

# ifdef OPENSSL_HAVE_NUM_TICKETS
if (SSL_SESSION_is_resumable(ss)) 	/* 1.1.1 */
# endif
  {
  int len = i2d_SSL_SESSION(ss, NULL);
  int dlen = sizeof(dbdata_tls_session) + len;
  dbdata_tls_session * dt = store_get(dlen, GET_TAINTED);
  uschar * s = dt->session;
  open_db dbblock, * dbm_file;

  DEBUG(D_tls) debug_printf("session is resumable\n");
  tlsp->resumption |= RESUME_SERVER_TICKET;	/* server gave us a ticket */

  dt->verify_override = tlsp->verify_override;
  dt->ocsp = tlsp->ocsp;
  (void) i2d_SSL_SESSION(ss, &s);		/* s gets bumped to end */

  if ((dbm_file = dbfn_open(US"tls", O_RDWR, &dbblock, FALSE, FALSE)))
    {
    dbfn_write(dbm_file, tlsp->resume_index, dt, dlen);
    dbfn_close(dbm_file);
    DEBUG(D_tls) debug_printf("wrote session (len %u) to db\n",
		  (unsigned)dlen);
    }
  }
return 1;
}


/* Construct a key for session DB lookup, and setup the SSL_CTX for resumption */

static void
tls_client_ctx_resume_prehandshake(
  exim_openssl_client_tls_ctx * exim_client_ctx, smtp_connect_args * conn_args,
  tls_support * tlsp, smtp_transport_options_block * ob)
{
tlsp->host_resumable = TRUE;
tls_client_resmption_key(tlsp, conn_args, ob);

SSL_CTX_set_session_cache_mode(exim_client_ctx->ctx,
      SSL_SESS_CACHE_CLIENT
      | SSL_SESS_CACHE_NO_INTERNAL | SSL_SESS_CACHE_NO_AUTO_CLEAR);
SSL_CTX_sess_set_new_cb(exim_client_ctx->ctx, tls_save_session_cb);
}

static BOOL
tls_client_ssl_resume_prehandshake(SSL * ssl, tls_support * tlsp,
  host_item * host, uschar ** errstr)
{
if (tlsp->host_resumable)
  {
  DEBUG(D_tls)
    debug_printf("tls_resumption_hosts overrides openssl_options, enabling tickets\n");
  SSL_clear_options(ssl, SSL_OP_NO_TICKET);

  tls_exdata_idx = SSL_get_ex_new_index(0, 0, 0, 0, 0);
  if (!SSL_set_ex_data(ssl, tls_exdata_idx, client_static_state))
    {
    tls_error(US"set ex_data", host, NULL, errstr);
    return FALSE;
    }
  /* debug_printf("tls_exdata_idx %d cbinfo %p\n", tls_exdata_idx, client_static_state); */
  }

tlsp->resumption = RESUME_SUPPORTED;
/* Pick up a previous session, saved on an old ticket */
tls_retrieve_session(tlsp, ssl);
return TRUE;
}

static void
tls_client_resume_posthandshake(exim_openssl_client_tls_ctx * exim_client_ctx,
  tls_support * tlsp)
{
if (SSL_session_reused(exim_client_ctx->ssl))
  {
  DEBUG(D_tls) debug_printf("The session was reused\n");
  tlsp->resumption |= RESUME_USED;
  }
}
#endif	/* !DISABLE_TLS_RESUME */


#ifdef EXIM_HAVE_ALPN
/* Expand and convert an Exim list to an ALPN list.  False return for fail.
NULL plist return for silent no-ALPN.

Overwite the passed-in list with the expanded version.
*/

static BOOL
tls_alpn_plist(uschar ** tls_alpn, const uschar ** plist, unsigned * plen,
  uschar ** errstr)
{
uschar * exp_alpn;

if (!expand_check(*tls_alpn, US"tls_alpn", &exp_alpn, errstr))
  return FALSE;
*tls_alpn = exp_alpn;

if (!exp_alpn)
  {
  DEBUG(D_tls) debug_printf("Setting TLS ALPN forced to fail, not sending\n");
  *plist = NULL;
  }
else
  {
  /* The server implementation only accepts exactly one protocol name
  but it's little extra code complexity in the client. */

  const uschar * list = exp_alpn;
  uschar * p = store_get(Ustrlen(exp_alpn), exp_alpn), * s, * t;
  int sep = 0;
  uschar len;

  for (t = p; s = string_nextinlist(&list, &sep, NULL, 0); t += len)
    {
    *t++ = len = (uschar) Ustrlen(s);
    memcpy(t, s, len);
    }
  *plist = (*plen = t - p) ? p : NULL;
  }
return TRUE;
}
#endif	/* EXIM_HAVE_ALPN */


/*************************************************
*    Start a TLS session in a client             *
*************************************************/

/* Called from the smtp transport after STARTTLS has been accepted.

Arguments:
  cctx		connection context
  conn_args	connection details
  cookie	datum for randomness; can be NULL
  tlsp		record details of TLS channel configuration here; must be non-NULL
  errstr	error string pointer

Returns:	TRUE for success with TLS session context set in connection context,
		FALSE on error
*/

BOOL
tls_client_start(client_conn_ctx * cctx, smtp_connect_args * conn_args,
  void * cookie, tls_support * tlsp, uschar ** errstr)
{
host_item * host = conn_args->host;		/* for msgs and option-tests */
transport_instance * tb = conn_args->tblock;	/* always smtp or NULL */
smtp_transport_options_block * ob = tb
  ? (smtp_transport_options_block *)tb->options_block
  : &smtp_transport_option_defaults;
exim_openssl_client_tls_ctx * exim_client_ctx;
uschar * expciphers;
int rc;
static uschar peerdn[256];

#ifndef DISABLE_OCSP
BOOL request_ocsp = FALSE;
BOOL require_ocsp = FALSE;
#endif

rc = store_pool;
store_pool = POOL_PERM;
exim_client_ctx = store_get(sizeof(exim_openssl_client_tls_ctx), GET_UNTAINTED);
exim_client_ctx->corked = NULL;
store_pool = rc;

#ifdef SUPPORT_DANE
tlsp->tlsa_usage = 0;
#endif

#ifndef DISABLE_OCSP
  {
# ifdef SUPPORT_DANE
  if (  conn_args->dane
     && ob->hosts_request_ocsp[0] == '*'
     && ob->hosts_request_ocsp[1] == '\0'
     )
    {
    /* Unchanged from default.  Use a safer one under DANE */
    request_ocsp = TRUE;
    ob->hosts_request_ocsp = US"${if or { {= {0}{$tls_out_tlsa_usage}} "
				      "   {= {4}{$tls_out_tlsa_usage}} } "
				 " {*}{}}";
    }
# endif

  if ((require_ocsp =
	verify_check_given_host(CUSS &ob->hosts_require_ocsp, host) == OK))
    request_ocsp = TRUE;
  else
# ifdef SUPPORT_DANE
    if (!request_ocsp)
# endif
      request_ocsp =
	verify_check_given_host(CUSS &ob->hosts_request_ocsp, host) == OK;

# if defined(SUPPORT_DANE) && !defined(EXIM_HAVE_OPENSSL_OCSP_RESP_GET0_SIGNER)
  if (conn_args->dane && (require_ocsp || request_ocsp))
    {
    DEBUG(D_tls) debug_printf("OpenSSL version to early to combine OCSP"
			      " and DANE; disabling OCSP\n");
    require_ocsp = request_ocsp = FALSE;
    }
# endif
  }
#endif

rc = tls_init(host, ob,
#ifndef DISABLE_OCSP
    (void *)(long)request_ocsp,
#endif
    cookie, &client_static_state, tlsp, errstr);
if (rc != OK) return FALSE;

exim_client_ctx->ctx = client_static_state->lib_state.lib_ctx;

tlsp->certificate_verified = FALSE;
client_verify_callback_called = FALSE;

expciphers = NULL;
#ifdef SUPPORT_DANE
if (conn_args->dane)
  {
  /* We fall back to tls_require_ciphers if unset, empty or forced failure, but
  other failures should be treated as problems. */
  if (ob->dane_require_tls_ciphers &&
      !expand_check(ob->dane_require_tls_ciphers, US"dane_require_tls_ciphers",
        &expciphers, errstr))
    return FALSE;
  if (expciphers && *expciphers == '\0')
    expciphers = NULL;

  normalise_ciphers(&expciphers, ob->dane_require_tls_ciphers);
  }
#endif
if (!expciphers)
  {
  if (!expand_check(ob->tls_require_ciphers, US"tls_require_ciphers",
      &expciphers, errstr))
    return FALSE;

  /* In OpenSSL, cipher components are separated by hyphens. In GnuTLS, they
  are separated by underscores. So that I can use either form in my tests, and
  also for general convenience, we turn underscores into hyphens here. */

  normalise_ciphers(&expciphers, ob->tls_require_ciphers);
  }

if (expciphers)
  {
  DEBUG(D_tls) debug_printf("required ciphers: %s\n", expciphers);
  if (!SSL_CTX_set_cipher_list(exim_client_ctx->ctx, CS expciphers))
    {
    tls_error(US"SSL_CTX_set_cipher_list", host, NULL, errstr);
    return FALSE;
    }
  }

#ifdef SUPPORT_DANE
if (conn_args->dane)
  {
  SSL_CTX_set_verify(exim_client_ctx->ctx,
    SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
    verify_callback_client_dane);

  if (!DANESSL_library_init())
    {
    tls_error(US"library init", host, NULL, errstr);
    return FALSE;
    }
  if (DANESSL_CTX_init(exim_client_ctx->ctx) <= 0)
    {
    tls_error(US"context init", host, NULL, errstr);
    return FALSE;
    }
  DEBUG(D_tls) debug_printf("since dane-mode conn, not loading the usual CA bundle\n");
  }
else

#endif

if (tls_client_basic_ctx_init(exim_client_ctx->ctx, host, ob,
      client_static_state, errstr) != OK)
  return FALSE;

if (ob->tls_sni)
  {
  if (!expand_check(ob->tls_sni, US"tls_sni", &tlsp->sni, errstr))
    return FALSE;
  if (!tlsp->sni)
    { DEBUG(D_tls) debug_printf("Setting TLS SNI forced to fail, not sending\n"); }
  else if (!Ustrlen(tlsp->sni))
    tlsp->sni = NULL;
  else
    {
#ifndef EXIM_HAVE_OPENSSL_TLSEXT
    log_write(0, LOG_MAIN, "SNI unusable with this OpenSSL library version; ignoring \"%s\"\n",
          tlsp->sni);
    tlsp->sni = NULL;
#endif
    }
  }

if (ob->tls_alpn)
#ifdef EXIM_HAVE_ALPN
  {
  const uschar * plist;
  unsigned plen;

  if (!tls_alpn_plist(&ob->tls_alpn, &plist, &plen, errstr))
    return FALSE;
  if (plist)
    if (SSL_CTX_set_alpn_protos(exim_client_ctx->ctx, plist, plen) != 0)
      {
      tls_error(US"alpn init", host, NULL, errstr);
      return FALSE;
      }
    else
      DEBUG(D_tls) debug_printf("Setting TLS ALPN '%s'\n", ob->tls_alpn);
  }
#else
  log_write(0, LOG_MAIN, "ALPN unusable with this OpenSSL library version; ignoring \"%s\"\n",
          ob->tls_alpn);
#endif

#ifndef DISABLE_TLS_RESUME
/*XXX have_lbserver: another cmdline arg possibly, for continued-conn, but use
will be very low. */

if (!conn_args->have_lbserver)	/* wanted for tls_client_resmption_key() */
  { DEBUG(D_tls) debug_printf("resumption not supported on continued-connection\n"); }
else if (verify_check_given_host(CUSS &ob->tls_resumption_hosts, host) == OK)
  tls_client_ctx_resume_prehandshake(exim_client_ctx, conn_args, tlsp, ob);
#endif


if (!(exim_client_ctx->ssl = SSL_new(exim_client_ctx->ctx)))
  {
  tls_error(US"SSL_new", host, NULL, errstr);
  return FALSE;
  }
SSL_set_session_id_context(exim_client_ctx->ssl, sid_ctx, Ustrlen(sid_ctx));
SSL_set_fd(exim_client_ctx->ssl, cctx->sock);
SSL_set_connect_state(exim_client_ctx->ssl);

#ifdef EXIM_HAVE_OPENSSL_TLSEXT
if (tlsp->sni)
  {
  DEBUG(D_tls) debug_printf("Setting TLS SNI \"%s\"\n", tlsp->sni);
  SSL_set_tlsext_host_name(exim_client_ctx->ssl, tlsp->sni);
  }
#endif

#ifdef SUPPORT_DANE
if (conn_args->dane)
  if (dane_tlsa_load(exim_client_ctx->ssl, host, &conn_args->tlsa_dnsa, errstr) != OK)
    return FALSE;
#endif

#ifndef DISABLE_OCSP
/* Request certificate status at connection-time.  If the server
does OCSP stapling we will get the callback (set in tls_init()) */
# ifdef SUPPORT_DANE
if (request_ocsp)
  {
  const uschar * s;
  if (  ((s = ob->hosts_require_ocsp) && Ustrstr(s, US"tls_out_tlsa_usage"))
     || ((s = ob->hosts_request_ocsp) && Ustrstr(s, US"tls_out_tlsa_usage"))
     )
    {	/* Re-eval now $tls_out_tlsa_usage is populated.  If
    	this means we avoid the OCSP request, we wasted the setup
	cost in tls_init(). */
    require_ocsp = verify_check_given_host(CUSS &ob->hosts_require_ocsp, host) == OK;
    request_ocsp = require_ocsp
      || verify_check_given_host(CUSS &ob->hosts_request_ocsp, host) == OK;
    }
  }
# endif

if (request_ocsp)
  {
  SSL_set_tlsext_status_type(exim_client_ctx->ssl, TLSEXT_STATUSTYPE_ocsp);
  client_static_state->u_ocsp.client.verify_required = require_ocsp;
  tlsp->ocsp = OCSP_NOT_RESP;
  }
#endif

#ifndef DISABLE_TLS_RESUME
if (!tls_client_ssl_resume_prehandshake(exim_client_ctx->ssl, tlsp, host,
      errstr))
  return FALSE;
#endif

#ifndef DISABLE_EVENT
client_static_state->event_action = tb ? tb->event_action : NULL;
#endif

/* There doesn't seem to be a built-in timeout on connection. */

DEBUG(D_tls) debug_printf("Calling SSL_connect\n");
sigalrm_seen = FALSE;
ALARM(ob->command_timeout);
rc = SSL_connect(exim_client_ctx->ssl);
ALARM_CLR(0);

#ifdef SUPPORT_DANE
if (conn_args->dane)
  DANESSL_cleanup(exim_client_ctx->ssl);
#endif

if (rc <= 0)
  {
#ifndef DISABLE_OCSP
  if (client_static_state->u_ocsp.client.verify_errstr)
    { if (errstr) *errstr = client_static_state->u_ocsp.client.verify_errstr; }
  else
#endif
    tls_error(US"SSL_connect", host, sigalrm_seen ? US"timed out" : NULL, errstr);
  return FALSE;
  }

DEBUG(D_tls)
  {
  debug_printf("SSL_connect succeeded\n");
  tls_dump_keylog(exim_client_ctx->ssl);
  }

#ifndef DISABLE_TLS_RESUME
tls_client_resume_posthandshake(exim_client_ctx, tlsp);
#endif

#ifdef EXIM_HAVE_ALPN
if (ob->tls_alpn)	/* We requested. See what was negotiated. */
  {
  const uschar * name;
  unsigned len;

  SSL_get0_alpn_selected(exim_client_ctx->ssl, &name, &len);
  if (len > 0)
    { DEBUG(D_tls) debug_printf("ALPN negotiated %u: '%.*s'\n", len, (int)*name, name+1); }
  else if (verify_check_given_host(CUSS &ob->hosts_require_alpn, host) == OK)
    {
    /* Would like to send a relevant fatal Alert, but OpenSSL has no API */
    tls_error(US"handshake", host, US"ALPN required but not negotiated", errstr);
    return FALSE;
    }
  }
#endif

#ifdef SSL_get_extms_support
tlsp->ext_master_secret = SSL_get_extms_support(exim_client_ctx->ssl) == 1;
#endif
peer_cert(exim_client_ctx->ssl, tlsp, peerdn, sizeof(peerdn));

tlsp->ver = tlsver_name(exim_client_ctx->ssl);
tlsp->cipher = construct_cipher_name(exim_client_ctx->ssl, tlsp->ver, &tlsp->bits);
tlsp->cipher_stdname = cipher_stdname_ssl(exim_client_ctx->ssl);

/* Record the certificate we presented */
  {
  X509 * crt = SSL_get_certificate(exim_client_ctx->ssl);
  tlsp->ourcert = crt ? X509_dup(crt) : NULL;
  }

/*XXX will this work with continued-TLS? */
tls_get_channel_binding(exim_client_ctx->ssl, tlsp, GET_TAINTED);

tlsp->active.sock = cctx->sock;
tlsp->active.tls_ctx = exim_client_ctx;
cctx->tls_ctx = exim_client_ctx;
return TRUE;
}





static BOOL
tls_refill(unsigned lim)
{
SSL * ssl = state_server.lib_state.lib_ssl;
int error;
int inbytes;

DEBUG(D_tls) debug_printf("Calling SSL_read(%p, %p, %u)\n", ssl,
  ssl_xfer_buffer, ssl_xfer_buffer_size);

ERR_clear_error();
if (smtp_receive_timeout > 0) ALARM(smtp_receive_timeout);
inbytes = SSL_read(ssl, CS ssl_xfer_buffer,
		  MIN(ssl_xfer_buffer_size, lim));
error = SSL_get_error(ssl, inbytes);
if (smtp_receive_timeout > 0) ALARM_CLR(0);

if (had_command_timeout)		/* set by signal handler */
  smtp_command_timeout_exit();		/* does not return */
if (had_command_sigterm)
  smtp_command_sigterm_exit();
if (had_data_timeout)
  smtp_data_timeout_exit();
if (had_data_sigint)
  smtp_data_sigint_exit();

/* SSL_ERROR_ZERO_RETURN appears to mean that the SSL session has been
closed down, not that the socket itself has been closed down. Revert to
non-SSL handling. */

switch(error)
  {
  case SSL_ERROR_NONE:
    break;

  case SSL_ERROR_ZERO_RETURN:
    DEBUG(D_tls) debug_printf("Got SSL_ERROR_ZERO_RETURN\n");

    if (SSL_get_shutdown(ssl) == SSL_RECEIVED_SHUTDOWN)
	  SSL_shutdown(ssl);

    tls_close(NULL, TLS_NO_SHUTDOWN);
    return FALSE;

  /* Handle genuine errors */
  case SSL_ERROR_SSL:
    {
    uschar * conn_info = smtp_get_connection_info();
    if (Ustrncmp(conn_info, US"SMTP ", 5) == 0) conn_info += 5;
    /* I'd like to get separated H= here, but too hard for now */
    ERR_error_string_n(ERR_get_error(), ssl_errstring, sizeof(ssl_errstring));
    log_write(0, LOG_MAIN, "TLS error (SSL_read): on %s %s", conn_info, ssl_errstring);
    ssl_xfer_error = TRUE;
    return FALSE;
    }

  default:
    DEBUG(D_tls) debug_printf("Got SSL error %d\n", error);
    DEBUG(D_tls) if (error == SSL_ERROR_SYSCALL)
      debug_printf(" - syscall %s\n", strerror(errno));
    ssl_xfer_error = TRUE;
    return FALSE;
  }

#ifndef DISABLE_DKIM
dkim_exim_verify_feed(ssl_xfer_buffer, inbytes);
#endif
ssl_xfer_buffer_hwm = inbytes;
ssl_xfer_buffer_lwm = 0;
return TRUE;
}


/*************************************************
*            TLS version of getc                 *
*************************************************/

/* This gets the next byte from the TLS input buffer. If the buffer is empty,
it refills the buffer via the SSL reading function.

Arguments:  lim		Maximum amount to read/buffer
Returns:    the next character or EOF

Only used by the server-side TLS.
*/

int
tls_getc(unsigned lim)
{
if (ssl_xfer_buffer_lwm >= ssl_xfer_buffer_hwm)
  if (!tls_refill(lim))
    return ssl_xfer_error ? EOF : smtp_getc(lim);

/* Something in the buffer; return next uschar */

return ssl_xfer_buffer[ssl_xfer_buffer_lwm++];
}

BOOL
tls_hasc(void)
{
return ssl_xfer_buffer_lwm < ssl_xfer_buffer_hwm;
}

uschar *
tls_getbuf(unsigned * len)
{
unsigned size;
uschar * buf;

if (ssl_xfer_buffer_lwm >= ssl_xfer_buffer_hwm)
  if (!tls_refill(*len))
    {
    if (!ssl_xfer_error) return smtp_getbuf(len);
    *len = 0;
    return NULL;
    }

if ((size = ssl_xfer_buffer_hwm - ssl_xfer_buffer_lwm) > *len)
  size = *len;
buf = &ssl_xfer_buffer[ssl_xfer_buffer_lwm];
ssl_xfer_buffer_lwm += size;
*len = size;
return buf;
}


void
tls_get_cache(unsigned lim)
{
#ifndef DISABLE_DKIM
int n = ssl_xfer_buffer_hwm - ssl_xfer_buffer_lwm;
if (n > lim)
  n = lim;
if (n > 0)
  dkim_exim_verify_feed(ssl_xfer_buffer+ssl_xfer_buffer_lwm, n);
#endif
}


BOOL
tls_could_getc(void)
{
return ssl_xfer_buffer_lwm < ssl_xfer_buffer_hwm
    || SSL_pending(state_server.lib_state.lib_ssl) > 0;
}


/*************************************************
*          Read bytes from TLS channel           *
*************************************************/

/*
Arguments:
  ct_ctx    client context pointer, or NULL for the one global server context
  buff      buffer of data
  len       size of buffer

Returns:    the number of bytes read
            -1 after a failed read, including EOF

Only used by the client-side TLS.
*/

int
tls_read(void * ct_ctx, uschar *buff, size_t len)
{
SSL * ssl = ct_ctx ? ((exim_openssl_client_tls_ctx *)ct_ctx)->ssl
		  : state_server.lib_state.lib_ssl;
int inbytes;
int error;

DEBUG(D_tls) debug_printf("Calling SSL_read(%p, %p, %u)\n", ssl,
  buff, (unsigned int)len);

ERR_clear_error();
inbytes = SSL_read(ssl, CS buff, len);
error = SSL_get_error(ssl, inbytes);

if (error == SSL_ERROR_ZERO_RETURN)
  {
  DEBUG(D_tls) debug_printf("Got SSL_ERROR_ZERO_RETURN\n");
  return -1;
  }
else if (error != SSL_ERROR_NONE)
  return -1;

return inbytes;
}





/*************************************************
*         Write bytes down TLS channel           *
*************************************************/

/*
Arguments:
  ct_ctx    client context pointer, or NULL for the one global server context
  buff      buffer of data
  len       number of bytes
  more	    further data expected soon

Returns:    the number of bytes after a successful write,
            -1 after a failed write

Used by both server-side and client-side TLS.  Calling with len zero and more unset
will flush buffered writes; buff can be null for this case.
*/

int
tls_write(void * ct_ctx, const uschar * buff, size_t len, BOOL more)
{
size_t olen = len;
int outbytes, error;
SSL * ssl = ct_ctx
  ? ((exim_openssl_client_tls_ctx *)ct_ctx)->ssl
  : state_server.lib_state.lib_ssl;
static gstring * server_corked = NULL;
gstring ** corkedp = ct_ctx
  ? &((exim_openssl_client_tls_ctx *)ct_ctx)->corked : &server_corked;
gstring * corked = *corkedp;

DEBUG(D_tls) debug_printf("%s(%p, %lu%s)\n", __FUNCTION__,
  buff, (unsigned long)len, more ? ", more" : "");

/* Lacking a CORK or MSG_MORE facility (such as GnuTLS has) we copy data when
"more" is notified.  This hack is only ok if small amounts are involved AND only
one stream does it, in one context (i.e. no store reset).  Currently it is used
for the responses to the received SMTP MAIL , RCPT, DATA sequence, only.
We support callouts done by the server process by using a separate client
context for the stashed information. */
/* + if PIPE_COMMAND, banner & ehlo-resp for smmtp-on-connect. Suspect there's
a store reset there, so use POOL_PERM. */
/* + if CHUNKING, cmds EHLO,MAIL,RCPT(s),BDAT */

if (more || corked)
  {
  if (!len) buff = US &error;	/* dummy just so that string_catn is ok */

  int save_pool = store_pool;
  store_pool = POOL_PERM;

  corked = string_catn(corked, buff, len);

  store_pool = save_pool;

  if (more)
    {
    *corkedp = corked;
    return len;
    }
  buff = CUS corked->s;
  len = corked->ptr;
  *corkedp = NULL;
  }

for (int left = len; left > 0;)
  {
  DEBUG(D_tls) debug_printf("SSL_write(%p, %p, %d)\n", ssl, buff, left);
  ERR_clear_error();
  outbytes = SSL_write(ssl, CS buff, left);
  error = SSL_get_error(ssl, outbytes);
  DEBUG(D_tls) debug_printf("outbytes=%d error=%d\n", outbytes, error);
  switch (error)
    {
    case SSL_ERROR_NONE:	/* the usual case */
      left -= outbytes;
      buff += outbytes;
      break;

    case SSL_ERROR_SSL:
      ERR_error_string_n(ERR_get_error(), ssl_errstring, sizeof(ssl_errstring));
      log_write(0, LOG_MAIN, "TLS error (SSL_write): %s", ssl_errstring);
      return -1;

    case SSL_ERROR_ZERO_RETURN:
      log_write(0, LOG_MAIN, "SSL channel closed on write");
      return -1;

    case SSL_ERROR_SYSCALL:
      if (ct_ctx || errno != ECONNRESET || !f.smtp_in_quit)
	log_write(0, LOG_MAIN, "SSL_write: (from %s) syscall: %s",
	  sender_fullhost ? sender_fullhost : US"<unknown>",
	  strerror(errno));
      else if (LOGGING(protocol_detail))
	log_write(0, LOG_MAIN, "[%s] after QUIT, client reset TCP before"
	  " SMTP response and TLS close\n", sender_host_address);
      else
	DEBUG(D_tls) debug_printf("[%s] SSL_write: after QUIT,"
	  " client reset TCP before TLS close\n", sender_host_address);
      return -1;

    default:
      log_write(0, LOG_MAIN, "SSL_write error %d", error);
      return -1;
    }
  }
return olen;
}



/*
Arguments:
  ct_ctx	client TLS context pointer, or NULL for the one global server context
*/

void
tls_shutdown_wr(void * ct_ctx)
{
exim_openssl_client_tls_ctx * o_ctx = ct_ctx;
SSL ** sslp = o_ctx ? &o_ctx->ssl : (SSL **) &state_server.lib_state.lib_ssl;
int * fdp = o_ctx ? &tls_out.active.sock : &tls_in.active.sock;
int rc;

if (*fdp < 0) return;  /* TLS was not active */

tls_write(ct_ctx, NULL, 0, FALSE);	/* flush write buffer */

HDEBUG(D_transport|D_tls|D_acl|D_v) debug_printf_indent("  SMTP(TLS shutdown)>>\n");
rc = SSL_shutdown(*sslp);
if (rc < 0) DEBUG(D_tls)
  {
  ERR_error_string_n(ERR_get_error(), ssl_errstring, sizeof(ssl_errstring));
  debug_printf("SSL_shutdown: %s\n", ssl_errstring);
  }
}

/*************************************************
*         Close down a TLS session               *
*************************************************/

/* This is also called from within a delivery subprocess forked from the
daemon, to shut down the TLS library, without actually doing a shutdown (which
would tamper with the SSL session in the parent process).

Arguments:
  ct_ctx	client TLS context pointer, or NULL for the one global server context
  do_shutdown	0 no data-flush or TLS close-alert
		1 if TLS close-alert is to be sent,
 		2 if also response to be waited for

Returns:     nothing

Used by both server-side and client-side TLS.
*/

void
tls_close(void * ct_ctx, int do_shutdown)
{
exim_openssl_client_tls_ctx * o_ctx = ct_ctx;
SSL ** sslp = o_ctx ? &o_ctx->ssl : (SSL **) &state_server.lib_state.lib_ssl;
int * fdp = o_ctx ? &tls_out.active.sock : &tls_in.active.sock;

if (*fdp < 0) return;  /* TLS was not active */

if (do_shutdown > TLS_NO_SHUTDOWN)
  {
  int rc;
  DEBUG(D_tls) debug_printf("tls_close(): shutting down TLS%s\n",
    do_shutdown > TLS_SHUTDOWN_NOWAIT ? " (with response-wait)" : "");

  tls_write(ct_ctx, NULL, 0, FALSE);	/* flush write buffer */

  if (  (  do_shutdown >= TLS_SHUTDOWN_WONLY
	|| (rc = SSL_shutdown(*sslp)) == 0	/* send "close notify" alert */
	)
     && do_shutdown > TLS_SHUTDOWN_NOWAIT
     )
    {
#ifdef EXIM_TCP_CORK
    (void) setsockopt(*fdp, IPPROTO_TCP, EXIM_TCP_CORK, US &off, sizeof(off));
#endif
    ALARM(2);
    rc = SSL_shutdown(*sslp);			/* wait for response */
    ALARM_CLR(0);
    }

  if (rc < 0) DEBUG(D_tls)
    {
    ERR_error_string_n(ERR_get_error(), ssl_errstring, sizeof(ssl_errstring));
    debug_printf("SSL_shutdown: %s\n", ssl_errstring);
    }
  }

if (!o_ctx)		/* server side */
  {
#ifndef DISABLE_OCSP
  sk_X509_pop_free(state_server.u_ocsp.server.verify_stack, X509_free);
  state_server.u_ocsp.server.verify_stack = NULL;
#endif

  receive_getc =	smtp_getc;
  receive_getbuf =	smtp_getbuf;
  receive_get_cache =	smtp_get_cache;
  receive_hasc =	smtp_hasc;
  receive_ungetc =	smtp_ungetc;
  receive_feof =	smtp_feof;
  receive_ferror =	smtp_ferror;
  tls_in.active.tls_ctx = NULL;
  tls_in.sni = NULL;
  /* Leave bits, peercert, cipher, peerdn, certificate_verified set, for logging */
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
SSL_CTX * ctx;
uschar * expciphers, * err;

tls_openssl_init();

if (!(tls_require_ciphers && *tls_require_ciphers))
  return NULL;

if (!expand_check(tls_require_ciphers, US"tls_require_ciphers", &expciphers,
		  &err))
  return US"failed to expand tls_require_ciphers";

if (!(expciphers && *expciphers))
  return NULL;

normalise_ciphers(&expciphers, tls_require_ciphers);

err = NULL;
if (lib_ctx_new(&ctx, NULL, &err) == OK)
  {
  DEBUG(D_tls)
    debug_printf("tls_require_ciphers expands to \"%s\"\n", expciphers);

  if (!SSL_CTX_set_cipher_list(ctx, CS expciphers))
    {
    ERR_error_string_n(ERR_get_error(), ssl_errstring, sizeof(ssl_errstring));
    err = string_sprintf("SSL_CTX_set_cipher_list(%s) failed: %s",
			expciphers, ssl_errstring);
    }

  SSL_CTX_free(ctx);
  }
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

Note: some OS vendors backport security fixes without changing the version
number/string, and the version date remains unchanged.  The _build_ date
will change, so we can more usefully assist with version diagnosis by also
reporting the build date.

Arguments:   string to append to
Returns:     string
*/

gstring *
tls_version_report(gstring * g)
{
return string_fmt_append(g,
    "Library version: OpenSSL: Compile: %s\n"
    "                          Runtime: %s\n"
    "                                 : %s\n",
	     OPENSSL_VERSION_TEXT,
	     SSLeay_version(SSLEAY_VERSION),
	     SSLeay_version(SSLEAY_BUILT_ON));
  /* third line is 38 characters for the %s and the line is 73 chars long;
  the OpenSSL output includes a "built on: " prefix already. */
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
static pid_t pidlast = 0;
pid_t pidnow;
uschar smallbuf[sizeof(r)];

if (max <= 1)
  return 0;

pidnow = getpid();
if (pidnow != pidlast)
  {
  /* Although OpenSSL documents that "OpenSSL makes sure that the PRNG state
  is unique for each thread", this doesn't apparently apply across processes,
  so our own warning from vaguely_random_number_fallback() applies here too.
  Fix per PostgreSQL. */
  if (pidlast != 0)
    RAND_cleanup();
  pidlast = pidnow;
  }

/* OpenSSL auto-seeds from /dev/random, etc, but this a double-check. */
if (!RAND_status())
  {
  randstuff r;
  gettimeofday(&r.tv, NULL);
  r.p = getpid();

  RAND_seed(US (&r), sizeof(r));
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

#ifdef EXIM_HAVE_RAND_PSEUDO
/* We do not care if crypto-strong */
i = RAND_pseudo_bytes(smallbuf, needed_len);
#else
i = RAND_bytes(smallbuf, needed_len);
#endif

if (i < 0)
  {
  DEBUG(D_all)
    debug_printf("OpenSSL RAND_pseudo_bytes() not supported by RAND method, using fallback.\n");
  return vaguely_random_number_fallback(max);
  }

r = 0;
for (uschar * p = smallbuf; needed_len; --needed_len, ++p)
  r = 256 * r + *p;

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
uschar * exp, * end;
BOOL adding, item_parsed;

/* Server: send no (<= TLS1.2) session tickets */
result = SSL_OP_NO_TICKET;

/* Prior to 4.80 we or'd in SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS; removed
from default because it increases BEAST susceptibility. */
#ifdef SSL_OP_NO_SSLv2
result |= SSL_OP_NO_SSLv2;
#endif
#ifdef SSL_OP_NO_SSLv3
result |= SSL_OP_NO_SSLv3;
#endif
#ifdef SSL_OP_SINGLE_DH_USE
result |= SSL_OP_SINGLE_DH_USE;
#endif
#ifdef SSL_OP_NO_RENEGOTIATION
result |= SSL_OP_NO_RENEGOTIATION;
#endif

if (!option_spec)
  {
  *results = result;
  return TRUE;
  }

if (!expand_check(option_spec, US"openssl_options", &exp, &end))
  return FALSE;

for (uschar * s = exp; *s; /**/)
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
  for (end = s; *end && !isspace(*end); ) end++;
  item_parsed = tls_openssl_one_option_parse(string_copyn(s, end-s), &item);
  if (!item_parsed)
    {
    DEBUG(D_tls) debug_printf("openssl option setting unrecognised: \"%s\"\n", s);
    return FALSE;
    }
  DEBUG(D_tls) debug_printf("openssl option, %s %08lx: %08lx (%s)\n",
      adding ? "adding to    " : "removing from", result, item, s);
  if (adding)
    result |= item;
  else
    result &= ~item;
  s = end;
  }

*results = result;
return TRUE;
}

#endif	/*!MACRO_PREDEF*/
/* vi: aw ai sw=2
*/
/* End of tls-openssl.c */
