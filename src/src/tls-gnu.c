/* $Cambridge: exim/src/src/tls-gnu.c,v 1.3 2004/12/21 09:26:31 ph10 Exp $ */

/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2004 */
/* See the file NOTICE for conditions of use and distribution. */

/* This module provides TLS (aka SSL) support for Exim using the GnuTLS
library. It is #included into tls.c when that library is used. The code herein
is based on a patch that was contributed by Nikos Mavroyanopoulos.

No cryptographic code is included in Exim. All this module does is to call
functions from the GnuTLS library. */


/* Heading stuff for GnuTLS */

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>


#define UNKNOWN_NAME "unknown"
#define DH_BITS      768
#define RSA_BITS     512

/* Values for verify_requirment and initialized */

enum { VERIFY_NONE, VERIFY_OPTIONAL, VERIFY_REQUIRED };
enum { INITIALIZED_NOT, INITIALIZED_SERVER, INITIALIZED_CLIENT };

/* Local static variables for GNUTLS */

static BOOL initialized = INITIALIZED_NOT;
static host_item *client_host;

static gnutls_rsa_params rsa_params = NULL;
static gnutls_dh_params dh_params = NULL;

static gnutls_certificate_server_credentials x509_cred = NULL;
static gnutls_session tls_session = NULL;

static char ssl_errstring[256];

static int  ssl_session_timeout = 200;
static int  verify_requirement;

/* Priorities for TLS algorithms to use. At present, only the cipher priority
vector can be altered. */

static const int protocol_priority[16] = { GNUTLS_TLS1, GNUTLS_SSL3, 0 };

static const int kx_priority[16] = {
  GNUTLS_KX_RSA,
  GNUTLS_KX_DHE_DSS,
  GNUTLS_KX_DHE_RSA,
  GNUTLS_KX_RSA_EXPORT,
  0 };

static int default_cipher_priority[16] = {
  GNUTLS_CIPHER_AES_256_CBC,
  GNUTLS_CIPHER_AES_128_CBC,
  GNUTLS_CIPHER_3DES_CBC,
  GNUTLS_CIPHER_ARCFOUR_128,
  0 };

static int cipher_priority[16];

static const int mac_priority[16] = {
  GNUTLS_MAC_SHA,
  GNUTLS_MAC_MD5,
  0 };

static const int comp_priority[16] = { GNUTLS_COMP_NULL, 0 };
static const int cert_type_priority[16] = { GNUTLS_CRT_X509, 0 };

/* Tables of cipher names and equivalent numbers */

typedef struct pri_item {
  uschar *name;
  int *values;
} pri_item;

static int arcfour_128_codes[] = { GNUTLS_CIPHER_ARCFOUR_128, 0 };
static int arcfour_40_codes[]  = { GNUTLS_CIPHER_ARCFOUR_40, 0 };
static int arcfour_codes[]     = { GNUTLS_CIPHER_ARCFOUR_128,
                                   GNUTLS_CIPHER_ARCFOUR_40, 0 };
static int aes_256_codes[]     = { GNUTLS_CIPHER_AES_256_CBC, 0 };
static int aes_128_codes[]     = { GNUTLS_CIPHER_AES_128_CBC, 0 };
static int aes_codes[]         = { GNUTLS_CIPHER_AES_256_CBC,
                                   GNUTLS_CIPHER_AES_128_CBC, 0 };
static int des3_codes[]        = { GNUTLS_CIPHER_3DES_CBC, 0 };

static pri_item cipher_index[] = {
  { US"ARCFOUR_128", arcfour_128_codes },
  { US"ARCFOUR_40", arcfour_40_codes },
  { US"ARCFOUR", arcfour_codes },
  { US"AES_256", aes_256_codes },
  { US"AES_128", aes_128_codes },
  { US"AES", aes_codes },
  { US"3DES", des3_codes }
};



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
  err       a GnuTLS error number, or 0 if local error

Returns:    OK/DEFER/FAIL
*/

static int
tls_error(uschar *prefix, host_item *host, int err)
{
uschar *errtext = US"";
if (err != 0) errtext = string_sprintf(": %s", gnutls_strerror(err));
if (host == NULL)
  {
  log_write(0, LOG_MAIN, "TLS error on connection from %s (%s)%s",
    (sender_fullhost != NULL)? sender_fullhost : US "local process",
    prefix, errtext);
  return DEFER;
  }
else
  {
  log_write(0, LOG_MAIN, "TLS error on connection to %s [%s] (%s)%s",
    host->name, host->address, prefix, errtext);
  return FAIL;
  }
}



/*************************************************
*             Verify certificate                 *
*************************************************/

/* Called after a successful handshake, when certificate verification is
required or optional, for both server and client.

Arguments:
  session    GNUTLS session
  error      where to put text giving a reason for failure

Returns:     TRUE/FALSE
*/

static BOOL
verify_certificate(gnutls_session session, uschar **error)
{
int verify;
uschar *dn_string = US"";
const gnutls_datum *cert;
unsigned int cert_size = 0;

*error = NULL;

/* Get the peer's certificate. If it sent one, extract it's DN, and then
attempt to verify the certificate. If no certificate is supplied, verification
is forced to fail. */

cert = gnutls_certificate_get_peers(session, &cert_size);
if (cert != NULL)
  {
  uschar buff[1024];
  gnutls_x509_crt gcert;

  gnutls_x509_crt_init(&gcert);
  dn_string = US"unknown";

  if (gnutls_x509_crt_import(gcert, cert, GNUTLS_X509_FMT_DER) == 0)
    {
    size_t bufsize = sizeof(buff);
    if (gnutls_x509_crt_get_dn(gcert, CS buff, &bufsize) >= 0)
      dn_string = string_copy_malloc(buff);
    }

  verify = gnutls_certificate_verify_peers(session);
  }
else
  {
  DEBUG(D_tls) debug_printf("no peer certificate supplied\n");
  verify = GNUTLS_CERT_INVALID;
  *error = US"not supplied";
  }

/* Handle the result of verification. INVALID seems to be set as well
as REVOKED, but leave the test for both. */

if ((verify & (GNUTLS_CERT_INVALID|GNUTLS_CERT_REVOKED)) != 0)
  {
  tls_certificate_verified = FALSE;
  if (*error == NULL) *error = ((verify & GNUTLS_CERT_REVOKED) != 0)?
    US"revoked" : US"invalid";
  if (verify_requirement == VERIFY_REQUIRED)
    {
    DEBUG(D_tls) debug_printf("TLS certificate verification failed (%s): "
      "peerdn=%s\n", *error, dn_string);
    gnutls_alert_send(session, GNUTLS_AL_FATAL, GNUTLS_A_BAD_CERTIFICATE);
    return FALSE;                       /* reject */
    }
  DEBUG(D_tls) debug_printf("TLS certificate verify failure (%s) overridden "
      "(host in tls_try_verify_hosts): peerdn=%s\n", *error, dn_string);
  }
else
  {
  tls_certificate_verified = TRUE;
  DEBUG(D_tls) debug_printf("TLS certificate verified: peerdn=%s\n",
    dn_string);
  }

tls_peerdn = dn_string;
return TRUE;                            /* accept */
}




/*************************************************
*        Write/read datum to/from file           *
*************************************************/

/* These functions are used for saving and restoring the RSA and D-H parameters
for use by all Exim processes. Data that is read is placed in malloc'd store
because that's what happens for newly generated data.

Arguments:
  fd          the file descriptor
  d           points to the datum

returns:      FALSE on error (errno set)
*/

static BOOL
write_datum(int fd, gnutls_datum *d)
{
if (write(fd, &(d->size), sizeof(d->size)) != sizeof(d->size)) return FALSE;
if (write(fd, d->data, d->size) != d->size) return FALSE;
return TRUE;
}


static BOOL
read_datum(int fd, gnutls_datum *d)
{
if (read(fd, &(d->size), sizeof(d->size)) != sizeof(d->size)) return FALSE;
d->data = malloc(d->size);
if (d->data == NULL) return FALSE;
if (read(fd, d->data, d->size) != d->size) return FALSE;
return TRUE;
}



/*************************************************
*          Setup up RSA and DH parameters        *
*************************************************/

/* Generating the RSA and D-H parameters takes a long time. They only need to
be re-generated every so often, depending on security policy. What we do is to
keep these parameters in a file in the spool directory. If the file does not
exist, we generate them. This means that it is easy to cause a regeneration.

The new file is written as a temporary file and renamed, so that an incomplete
file is never present. If two processes both compute some new parameters, you
waste a bit of effort, but it doesn't seem worth messing around with locking to
prevent this.

Argument:
  host       NULL for server, server for client (for error handling)

Returns:     OK/DEFER/FAIL
*/

static int
init_rsa_dh(host_item *host)
{
int fd, ret;
gnutls_datum m, e, d, p, q, u, prime, generator;
uschar filename[200];

/* Initialize the data structures for holding the parameters */

ret = gnutls_rsa_params_init(&rsa_params);
if (ret < 0) return tls_error(US"init rsa_params", host, ret);

ret = gnutls_dh_params_init(&dh_params);
if (ret < 0) return tls_error(US"init dh_params", host, ret);

/* Set up the name of the cache file */

if (!string_format(filename, sizeof(filename), "%s/gnutls-params",
      spool_directory))
  return tls_error(US"overlong filename", host, 0);

/* Open the cache file for reading. If this fails because of a non-existent
file, compute a new set of parameters, write them to a temporary file, and then
rename that file as the cache file. Other opening errors are bad. */

fd = Uopen(filename, O_RDONLY, 0);
if (fd < 0)
  {
  unsigned int rsa_bits = RSA_BITS;
  unsigned int dh_bits = DH_BITS;
  uschar tempfilename[sizeof(filename) + 10];

  if (errno != ENOENT)
    return tls_error(string_open_failed(errno, "%s for reading", filename),
      host, 0);

  DEBUG(D_tls) debug_printf("generating %d bit RSA key...\n", RSA_BITS);
  ret = gnutls_rsa_params_generate2(rsa_params, RSA_BITS);
  if (ret < 0) return tls_error(US"RSA key generation", host, ret);

  DEBUG(D_tls) debug_printf("generating %d bit Diffie-Hellman key...\n",
    DH_BITS);
  ret = gnutls_dh_params_generate2(dh_params, DH_BITS);
  if (ret < 0) return tls_error(US"D-H key generation", host, ret);

  /* Write the parameters to a file in the spool directory so that we
  can use them from other Exim processes. */

  sprintf(CS tempfilename, "%s-%d", filename, (int)getpid());
  fd = Uopen(tempfilename, O_WRONLY|O_CREAT, 0400);
  if (fd < 0)
    return tls_error(string_open_failed(errno, "%s for writing", filename),
      host, 0);
  (void)fchown(fd, exim_uid, exim_gid);   /* Probably not necessary */

  ret = gnutls_rsa_params_export_raw(rsa_params, &m, &e, &d, &p, &q, &u,
    &rsa_bits);
  if (ret < 0) return tls_error(US"RSA params export", host, ret);

  ret = gnutls_dh_params_export_raw(dh_params, &prime, &generator, &dh_bits);
  if (ret < 0) return tls_error(US"DH params export", host, ret);

  if (!write_datum(fd, &m) ||
      !write_datum(fd, &e) ||
      !write_datum(fd, &d) ||
      !write_datum(fd, &p) ||
      !write_datum(fd, &q) ||
      !write_datum(fd, &u) ||
      !write_datum(fd, &prime) ||
      !write_datum(fd, &generator))
    return tls_error(US"TLS cache write failed", host, 0);

  (void)close(fd);

  if (rename(CS tempfilename, CS filename) < 0)
    return tls_error(string_sprintf("failed to rename %s as %s: %s",
      tempfilename, filename, strerror(errno)), host, 0);

  DEBUG(D_tls) debug_printf("wrote RSA and D-H parameters to file\n");
  }

/* File opened for reading; get the data */

else
  {
  if (!read_datum(fd, &m) ||
      !read_datum(fd, &e) ||
      !read_datum(fd, &d) ||
      !read_datum(fd, &p) ||
      !read_datum(fd, &q) ||
      !read_datum(fd, &u) ||
      !read_datum(fd, &prime) ||
      !read_datum(fd, &generator))
    return tls_error(US"TLS cache read failed", host, 0);

  (void)close(fd);

  ret = gnutls_rsa_params_import_raw(rsa_params, &m, &e, &d, &p, &q, &u);
  if (ret < 0) return tls_error(US"RSA params import", host, ret);

  ret = gnutls_dh_params_import_raw(dh_params, &prime, &generator);
  if (ret < 0) return tls_error(US"DH params import", host, ret);

  DEBUG(D_tls) debug_printf("read RSA and D-H parameters from file\n");
  }

DEBUG(D_tls) debug_printf("initialized RSA and D-H parameters\n");
return OK;
}




/*************************************************
*            Initialize for GnuTLS               *
*************************************************/

/* Called from both server and client code. In the case of a server, errors
before actual TLS negotiation return DEFER.

Arguments:
  host            connected host, if client; NULL if server
  certificate     certificate file
  privatekey      private key file
  cas             CA certs file
  crl             CRL file

Returns:          OK/DEFER/FAIL
*/

static int
tls_init(host_item *host, uschar *certificate, uschar *privatekey, uschar *cas,
  uschar *crl)
{
int rc;
uschar *cert_expanded, *key_expanded, *cas_expanded, *crl_expanded;

initialized = (host == NULL)? INITIALIZED_SERVER : INITIALIZED_CLIENT;

rc = gnutls_global_init();
if (rc < 0) return tls_error(US"tls-init", host, rc);

/* Create RSA and D-H parameters, or read them from the cache file. This
function does its own SMTP error messaging. */

rc = init_rsa_dh(host);
if (rc != OK) return rc;

/* Create the credentials structure */

rc = gnutls_certificate_allocate_credentials(&x509_cred);
if (rc < 0) return tls_error(US"certificate_allocate_credentials", host, rc);

/* This stuff must be done for each session, because different certificates
may be required for different sessions. */

if (!expand_check(certificate, US"tls_certificate", &cert_expanded))
  return DEFER;

if (privatekey != NULL)
  {
  if (!expand_check(privatekey, US"tls_privatekey", &key_expanded))
    return DEFER;
  }
else key_expanded = cert_expanded;

/* Set the certificate and private keys */

if (cert_expanded != NULL)
  {
  DEBUG(D_tls) debug_printf("certificate file = %s\nkey file = %s\n",
    cert_expanded, key_expanded);
  rc = gnutls_certificate_set_x509_key_file(x509_cred, CS cert_expanded,
    CS key_expanded, GNUTLS_X509_FMT_PEM);
  if (rc < 0) 
    {
    uschar *msg = string_sprintf("cert/key setup: cert=%s key=%s",
      cert_expanded, key_expanded); 
    return tls_error(msg, host, rc);
    } 
  }

/* A certificate is mandatory in a server, but not in a client */

else
  {
  if (host == NULL)
    return tls_error(US"no TLS server certificate is specified", host, 0);
  DEBUG(D_tls) debug_printf("no TLS client certificate is specified\n");
  }

/* Set the trusted CAs file if one is provided, and then add the CRL if one is
provided. Experiment shows that, if the certificate file is empty, an unhelpful
error message is provided. However, if we just refrain from setting anything up
in that case, certificate verification fails, which seems to be the correct
behaviour. */

if (cas != NULL)
  {
  struct stat statbuf;

  if (!expand_check(cas, US"tls_verify_certificates", &cas_expanded))
    return DEFER;

  if (stat(CS cas_expanded, &statbuf) < 0)
    {
    log_write(0, LOG_MAIN|LOG_PANIC, "could not stat %s "
      "(tls_verify_certificates): %s", cas_expanded, strerror(errno));
    return DEFER;
    }

  DEBUG(D_tls) debug_printf("verify certificates = %s size=%d\n",
    cas_expanded, (int)statbuf.st_size);

  /* If the cert file is empty, there's no point in loading the CRL file. */

  if (statbuf.st_size > 0)
    {
    rc = gnutls_certificate_set_x509_trust_file(x509_cred, CS cas_expanded,
      GNUTLS_X509_FMT_PEM);
    if (rc < 0) return tls_error(US"setup_certs", host, rc);

    if (crl != NULL && *crl != 0)
      {
      if (!expand_check(crl, US"tls_crl", &crl_expanded))
        return DEFER;
      DEBUG(D_tls) debug_printf("loading CRL file = %s\n", crl_expanded);
      rc = gnutls_certificate_set_x509_crl_file(x509_cred, CS crl_expanded,
        GNUTLS_X509_FMT_PEM);
      if (rc < 0) return tls_error(US"CRL setup", host, rc);
      }
    }
  }

/* Associate the parameters with the x509 credentials structure. */

gnutls_certificate_set_dh_params(x509_cred, dh_params);
gnutls_certificate_set_rsa_params(x509_cred, rsa_params);

DEBUG(D_tls) debug_printf("initialized certificate stuff\n");
return OK;
}




/*************************************************
*        Remove ciphers from priority list       *
*************************************************/

/* Cautiously written so that it will remove duplicates if present.

Arguments:
  list         a zero-terminated list
  remove_list  a zero-terminated list to be removed

Returns:       nothing
*/

static void
remove_ciphers(int *list, int *remove_list)
{
for (; *remove_list != 0; remove_list++)
  {
  int *p = list;
  while (*p != 0)
    {
    if (*p == *remove_list)
      {
      int *pp = p;
      do { pp[0] = pp[1]; pp++; } while (*pp != 0);
      }
    else p++;
    }
  }
}



/*************************************************
*        Add ciphers to priority list            *
*************************************************/

/* Cautiously written to check the list size

Arguments:
  list         a zero-terminated list
  list_max     maximum offset in the list
  add_list     a zero-terminated list to be added

Returns:       TRUE if OK; FALSE if list overflows
*/

static BOOL
add_ciphers(int *list, int list_max, int *add_list)
{
int next = 0;
while (list[next] != 0) next++;
while (*add_list != 0)
  {
  if (next >= list_max) return FALSE;
  list[next++] = *add_list++;
  }
list[next] = 0;
return TRUE;
}



/*************************************************
*        Initialize a single GNUTLS session      *
*************************************************/

/* Set the algorithm, the db backend, whether to request certificates etc.

TLS in Exim was first implemented using OpenSSL. This has a function to which
you pass a list of cipher suites that are permitted/not permitted. GnuTLS works
differently. It operates using priority lists for the different components of
cipher suites.

For compatibility of configuration, we scan a list of cipher suites and set
priorities therefrom. However, at the moment, we pay attention only to the bulk
cipher.

Arguments:
  side         one of GNUTLS_SERVER, GNUTLS_CLIENT
  expciphers   expanded ciphers list

Returns:  a gnutls_session, or NULL if there is a problem
*/

static gnutls_session
tls_session_init(int side, uschar *expciphers)
{
gnutls_session session;

gnutls_init(&session, side);

/* Handle the list of permitted ciphers */

memcpy(cipher_priority, default_cipher_priority, sizeof(cipher_priority));

if (expciphers != NULL)
  {
  int sep = 0;
  BOOL first = TRUE;
  uschar *cipher;

  /* The names OpenSSL uses are of the form DES-CBC3-SHA, using hyphen
  separators. GnuTLS uses underscore separators. So that I can use either form
  in my tests, and also for general convenience, we turn hyphens into
  underscores before scanning the list. */

  uschar *s = expciphers;
  while (*s != 0) { if (*s == '-') *s = '_'; s++; }

  while ((cipher = string_nextinlist(&expciphers, &sep, big_buffer,
             big_buffer_size)) != NULL)
    {
    int i;
    BOOL exclude = cipher[0] == '!';
    if (first && !exclude) cipher_priority[0] = 0;
    first = FALSE;

    for (i = 0; i < sizeof(cipher_index)/sizeof(pri_item); i++)
      {
      uschar *ss = strstric(cipher, cipher_index[i].name, FALSE);
      if (ss != NULL)
        {
        uschar *endss = ss + Ustrlen(cipher_index[i].name);
        if ((ss == cipher || !isalnum(ss[-1])) && !isalnum(*endss))
          {
          if (exclude)
            remove_ciphers(cipher_priority, cipher_index[i].values);
          else
            {
            if (!add_ciphers(cipher_priority,
                             sizeof(cipher_priority)/sizeof(pri_item),
                             cipher_index[i].values))
              {
              log_write(0, LOG_MAIN|LOG_PANIC, "GnuTLS init failed: cipher "
                "priority table overflow");
              gnutls_deinit(session);
              return NULL;
              }
            }
          }
        }
      }
    }

  DEBUG(D_tls)
    {
    int *ptr = cipher_priority;
    debug_printf("adjusted cipher priorities:");
    while (*ptr != 0) debug_printf(" %d", *ptr++);
    debug_printf("\n");
    }
  }

/* Define the various priorities */

gnutls_cipher_set_priority(session, cipher_priority);
gnutls_compression_set_priority(session, comp_priority);
gnutls_kx_set_priority(session, kx_priority);
gnutls_protocol_set_priority(session, protocol_priority);
gnutls_mac_set_priority(session, mac_priority);

gnutls_cred_set(session, GNUTLS_CRD_CERTIFICATE, x509_cred);

gnutls_dh_set_prime_bits(session, DH_BITS);

/* Request or demand a certificate of the peer, as configured. This will
happen only in a server. */

if (verify_requirement != VERIFY_NONE)
  gnutls_certificate_server_set_request(session,
    (verify_requirement == VERIFY_OPTIONAL)?
      GNUTLS_CERT_REQUEST : GNUTLS_CERT_REQUIRE);

gnutls_db_set_cache_expiration(session, ssl_session_timeout);

DEBUG(D_tls) debug_printf("initialized GnuTLS session\n");
return session;
}



/*************************************************
*           Get name of cipher in use            *
*************************************************/

/* The answer is left in a static buffer, and tls_cipher is set to point
to it.

Argument:   pointer to a GnuTLS session
Returns:    nothing
*/

static void
construct_cipher_name(gnutls_session session)
{
static uschar cipherbuf[256];
uschar *ver;
int bits, c, kx, mac;

ver = string_copy(
  US gnutls_protocol_get_name(gnutls_protocol_get_version(session)));
if (Ustrncmp(ver, "TLS ", 4) == 0) ver[3] = '-';   /* Don't want space */

c = gnutls_cipher_get(session);
bits = gnutls_cipher_get_key_size(c);

mac = gnutls_mac_get(session);
kx = gnutls_kx_get(session);

string_format(cipherbuf, sizeof(cipherbuf), "%s:%s:%u", ver,
  gnutls_cipher_suite_get_name(kx, c, mac), bits);
tls_cipher = cipherbuf;

DEBUG(D_tls) debug_printf("cipher: %s\n", cipherbuf);
}



/*************************************************
*       Start a TLS session in a server          *
*************************************************/

/* This is called when Exim is running as a server, after having received
the STARTTLS command. It must respond to that command, and then negotiate
a TLS session.

Arguments:
  require_ciphers  list of allowed ciphers

Returns:           OK on success
                   DEFER for errors before the start of the negotiation
                   FAIL for errors during the negotation; the server can't
                     continue running.
*/

int
tls_server_start(uschar *require_ciphers)
{
int rc;
uschar *error;
uschar *expciphers = NULL;

/* Check for previous activation */

if (tls_active >= 0)
  {
  log_write(0, LOG_MAIN, "STARTTLS received in already encrypted "
    "connection from %s",
    (sender_fullhost != NULL)? sender_fullhost : US"local process");
  smtp_printf("554 Already in TLS\r\n");
  return FAIL;
  }

/* Initialize the library. If it fails, it will already have logged the error
and sent an SMTP response. */

DEBUG(D_tls) debug_printf("initializing GnuTLS as a server\n");

rc = tls_init(NULL, tls_certificate, tls_privatekey, tls_verify_certificates,
  tls_crl);
if (rc != OK) return rc;

if (!expand_check(require_ciphers, US"tls_require_ciphers", &expciphers))
  return FAIL;

/* If this is a host for which certificate verification is mandatory or
optional, set up appropriately. */

tls_certificate_verified = FALSE;
verify_requirement = VERIFY_NONE;

if (verify_check_host(&tls_verify_hosts) == OK)
  verify_requirement = VERIFY_REQUIRED;
else if (verify_check_host(&tls_try_verify_hosts) == OK)
  verify_requirement = VERIFY_OPTIONAL;

/* Prepare for new connection */

tls_session = tls_session_init(GNUTLS_SERVER, expciphers);
if (tls_session == NULL)
  return tls_error(US"tls_session_init", NULL, GNUTLS_E_MEMORY_ERROR);

/* Set context and tell client to go ahead, except in the case of TLS startup
on connection, where outputting anything now upsets the clients and tends to
make them disconnect. We need to have an explicit fflush() here, to force out
the response. Other smtp_printf() calls do not need it, because in non-TLS
mode, the fflush() happens when smtp_getc() is called. */

if (!tls_on_connect)
  {
  smtp_printf("220 TLS go ahead\r\n");
  fflush(smtp_out);
  }

/* Now negotiate the TLS session. We put our own timer on it, since it seems
that the GnuTLS library doesn't. */

gnutls_transport_set_ptr(tls_session, (gnutls_transport_ptr)fileno(smtp_out));

sigalrm_seen = FALSE;
if (smtp_receive_timeout > 0) alarm(smtp_receive_timeout);
rc = gnutls_handshake(tls_session);
alarm(0);

if (rc < 0)
  {
  if (sigalrm_seen)
    Ustrcpy(ssl_errstring, "timed out");
  else
    Ustrcpy(ssl_errstring, gnutls_strerror(rc));
  log_write(0, LOG_MAIN,
    "TLS error on connection from %s (gnutls_handshake): %s",
    (sender_fullhost != NULL)? sender_fullhost : US"local process",
    ssl_errstring);

  /* It seems that, except in the case of a timeout, we have to close the
  connection right here; otherwise if the other end is running OpenSSL it hangs
  until the server times out. */

  if (!sigalrm_seen)
    {
    fclose(smtp_out);
    fclose(smtp_in);
    }

  return FAIL;
  }

DEBUG(D_tls) debug_printf("gnutls_handshake was successful\n");

if (verify_requirement != VERIFY_NONE &&
     !verify_certificate(tls_session, &error))
  {
  log_write(0, LOG_MAIN,
    "TLS error on connection from %s: certificate verification failed (%s)",
    (sender_fullhost != NULL)? sender_fullhost : US"local process", error);
  return FAIL;
  }

construct_cipher_name(tls_session);

/* TLS has been set up. Adjust the input functions to read via TLS,
and initialize appropriately. */

ssl_xfer_buffer = store_malloc(ssl_xfer_buffer_size);
ssl_xfer_buffer_lwm = ssl_xfer_buffer_hwm = 0;
ssl_xfer_eof = ssl_xfer_error = 0;

receive_getc = tls_getc;
receive_ungetc = tls_ungetc;
receive_feof = tls_feof;
receive_ferror = tls_ferror;

tls_active = fileno(smtp_out);

return OK;
}




/*************************************************
*    Start a TLS session in a client             *
*************************************************/

/* Called from the smtp transport after STARTTLS has been accepted.

Arguments:
  fd                the fd of the connection
  host              connected host (for messages)
  addr
  dhparam           DH parameter file
  certificate       certificate file
  privatekey        private key file
  verify_certs      file for certificate verify
  verify_crl        CRL for verify
  require_ciphers   list of allowed ciphers
  timeout           startup timeout

Returns:            OK/DEFER/FAIL (because using common functions),
                    but for a client, DEFER and FAIL have the same meaning
*/

int
tls_client_start(int fd, host_item *host, address_item *addr, uschar *dhparam,
  uschar *certificate, uschar *privatekey, uschar *verify_certs,
  uschar *verify_crl, uschar *require_ciphers, int timeout)
{
const gnutls_datum *server_certs;
uschar *expciphers = NULL;
uschar *error;
unsigned int server_certs_size;
int rc;

DEBUG(D_tls) debug_printf("initializing GnuTLS as a client\n");

client_host = host;
verify_requirement = (verify_certs == NULL)? VERIFY_NONE : VERIFY_REQUIRED;
rc = tls_init(host, certificate, privatekey, verify_certs, verify_crl);
if (rc != OK) return rc;

if (!expand_check(require_ciphers, US"tls_require_ciphers", &expciphers))
  return FAIL;

tls_session = tls_session_init(GNUTLS_CLIENT, expciphers);
if (tls_session == NULL)
  return tls_error(US "tls_session_init", host, GNUTLS_E_MEMORY_ERROR);

gnutls_transport_set_ptr(tls_session, (gnutls_transport_ptr)fd);

/* There doesn't seem to be a built-in timeout on connection. */

sigalrm_seen = FALSE;
alarm(timeout);
rc = gnutls_handshake(tls_session);
alarm(0);

if (rc < 0)
  {
  if (sigalrm_seen)
    {
    log_write(0, LOG_MAIN, "TLS error on connection to %s [%s]: "
      "gnutls_handshake timed out", host->name, host->address);
    return FAIL;
    }
  else return tls_error(US "gnutls_handshake", host, rc);
  }

server_certs = gnutls_certificate_get_peers(tls_session, &server_certs_size);

if (server_certs != NULL)
  {
  uschar buff[1024];
  gnutls_x509_crt gcert;

  gnutls_x509_crt_init(&gcert);
  tls_peerdn = US"unknown";

  if (gnutls_x509_crt_import(gcert, server_certs, GNUTLS_X509_FMT_DER) == 0)
    {
    size_t bufsize = sizeof(buff);
    if (gnutls_x509_crt_get_dn(gcert, CS buff, &bufsize) >= 0)
      tls_peerdn = string_copy_malloc(buff);
    }
  }

/* Should we also verify the hostname here? */

if (verify_requirement != VERIFY_NONE &&
      !verify_certificate(tls_session, &error))
  {
  log_write(0, LOG_MAIN,
    "TLS error on connection to %s [%s]: certificate verification failed (%s)",
    host->name, host->address, error);
  return FAIL;
  }

construct_cipher_name(tls_session);    /* Sets tls_cipher */
tls_active = fd;
return OK;
}



/*************************************************
*    Deal with logging errors during I/O         *
*************************************************/

/* We have to get the identity of the peer from saved data.

Argument:
  ec       the GnuTLS error code, or 0 if it's a local error
  when     text identifying read or write
  text     local error text when ec is 0

Returns:   nothing
*/

static void
record_io_error(int ec, uschar *when, uschar *text)
{
uschar *additional = US"";

if (ec == GNUTLS_E_FATAL_ALERT_RECEIVED)
  additional = string_sprintf(": %s",
    gnutls_alert_get_name(gnutls_alert_get(tls_session)));

if (initialized == INITIALIZED_SERVER)
  log_write(0, LOG_MAIN, "TLS %s error on connection from %s: %s%s", when,
    (sender_fullhost != NULL)? sender_fullhost : US "local process",
    (ec == 0)? text : US gnutls_strerror(ec), additional);

else
  log_write(0, LOG_MAIN, "TLS %s error on connection to %s [%s]: %s%s", when,
    client_host->name, client_host->address,
    (ec == 0)? text : US gnutls_strerror(ec), additional);
}



/*************************************************
*            TLS version of getc                 *
*************************************************/

/* This gets the next byte from the TLS input buffer. If the buffer is empty,
it refills the buffer via the GnuTLS reading function.

Arguments:  none
Returns:    the next character or EOF
*/

int
tls_getc(void)
{
if (ssl_xfer_buffer_lwm >= ssl_xfer_buffer_hwm)
  {
  int inbytes;

  DEBUG(D_tls) debug_printf("Calling gnutls_record_recv(%lx, %lx, %u)\n",
    (long) tls_session, (long) ssl_xfer_buffer, ssl_xfer_buffer_size);

  if (smtp_receive_timeout > 0) alarm(smtp_receive_timeout);
  inbytes = gnutls_record_recv(tls_session, CS ssl_xfer_buffer,
    ssl_xfer_buffer_size);
  alarm(0);

  /* A zero-byte return appears to mean that the TLS session has been
     closed down, not that the socket itself has been closed down. Revert to
     non-TLS handling. */

  if (inbytes == 0)
    {
    DEBUG(D_tls) debug_printf("Got TLS_EOF\n");

    receive_getc = smtp_getc;
    receive_ungetc = smtp_ungetc;
    receive_feof = smtp_feof;
    receive_ferror = smtp_ferror;

    gnutls_deinit(tls_session);
    tls_session = NULL;
    tls_active = -1;
    tls_cipher = NULL;
    tls_peerdn = NULL;

    return smtp_getc();
    }

  /* Handle genuine errors */

  else if (inbytes < 0)
    {
    record_io_error(inbytes, US"recv", NULL);
    ssl_xfer_error = 1;
    return EOF;
    }

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
*/

int
tls_read(uschar *buff, size_t len)
{
int inbytes;

DEBUG(D_tls) debug_printf("Calling gnutls_record_recv(%lx, %lx, %u)\n",
  (long) tls_session, (long) buff, len);

inbytes = gnutls_record_recv(tls_session, CS buff, len);
if (inbytes > 0) return inbytes;
if (inbytes == 0)
  {
  DEBUG(D_tls) debug_printf("Got TLS_EOF\n");
  }
else record_io_error(inbytes, US"recv", NULL);

return -1;
}



/*************************************************
*         Write bytes down TLS channel           *
*************************************************/

/*
Arguments:
  buff      buffer of data
  len       number of bytes

Returns:    the number of bytes after a successful write,
            -1 after a failed write
*/

int
tls_write(const uschar *buff, size_t len)
{
int outbytes;
int left = len;

DEBUG(D_tls) debug_printf("tls_do_write(%lx, %d)\n", (long) buff, left);
while (left > 0)
  {
  DEBUG(D_tls) debug_printf("gnutls_record_send(SSL, %lx, %d)\n", (long)buff,
    left);
  outbytes = gnutls_record_send(tls_session, CS buff, left);

  DEBUG(D_tls) debug_printf("outbytes=%d\n", outbytes);
  if (outbytes < 0)
    {
    record_io_error(outbytes, US"send", NULL);
    return -1;
    }
  if (outbytes == 0)
    {
    record_io_error(0, US"send", US"TLS channel closed on write");
    return -1;
    }

  left -= outbytes;
  buff += outbytes;
  }

return len;
}



/*************************************************
*         Close down a TLS session               *
*************************************************/

/* This is also called from within a delivery subprocess forked from the
daemon, to shut down the TLS library, without actually doing a shutdown (which
would tamper with the TLS session in the parent process).

Arguments:   TRUE if gnutls_bye is to be called
Returns:     nothing
*/

void
tls_close(BOOL shutdown)
{
if (tls_active < 0) return;  /* TLS was not active */

if (shutdown)
  {
  DEBUG(D_tls) debug_printf("tls_close(): shutting down TLS\n");
  gnutls_bye(tls_session, GNUTLS_SHUT_WR);
  }

gnutls_deinit(tls_session);
tls_session = NULL;
gnutls_global_deinit();

tls_active = -1;
}

/* End of tls-gnu.c */
