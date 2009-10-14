/* $Cambridge: exim/src/src/tls-gnu.c,v 1.22 2009/10/14 13:52:48 nm4 Exp $ */

/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2007 */
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
#define DH_BITS      1024
#define PARAM_SIZE 2*1024


/* Values for verify_requirment */

enum { VERIFY_NONE, VERIFY_OPTIONAL, VERIFY_REQUIRED };

/* Local static variables for GNUTLS */

static host_item *client_host;

static gnutls_dh_params dh_params = NULL;

static gnutls_certificate_server_credentials x509_cred = NULL;
static gnutls_session tls_session = NULL;

static char ssl_errstring[256];

static int  ssl_session_timeout = 200;
static int  verify_requirement;

/* Priorities for TLS algorithms to use. In each case there's a default table,
and space into which it can be copied and altered. */

static const int default_proto_priority[16] = {
  GNUTLS_TLS1,
  GNUTLS_SSL3,
  0 };

static int proto_priority[16];

static const int default_kx_priority[16] = {
  GNUTLS_KX_RSA,
  GNUTLS_KX_DHE_DSS,
  GNUTLS_KX_DHE_RSA,
  0 };

static int kx_priority[16];

static int default_cipher_priority[16] = {
  GNUTLS_CIPHER_AES_256_CBC,
  GNUTLS_CIPHER_AES_128_CBC,
  GNUTLS_CIPHER_3DES_CBC,
  GNUTLS_CIPHER_ARCFOUR_128,
  0 };

static int cipher_priority[16];

static const int default_mac_priority[16] = {
  GNUTLS_MAC_SHA,
  GNUTLS_MAC_MD5,
  0 };

static int mac_priority[16];

/* These two are currently not changeable. */

static const int comp_priority[16] = { GNUTLS_COMP_NULL, 0 };
static const int cert_type_priority[16] = { GNUTLS_CRT_X509, 0 };

/* Tables of priority names and equivalent numbers */

typedef struct pri_item {
  uschar *name;
  int *values;
} pri_item;


static int tls1_codes[] = { GNUTLS_TLS1, 0 };
static int ssl3_codes[] = { GNUTLS_SSL3, 0 };

static pri_item proto_index[] = {
  { US"TLS1", tls1_codes },
  { US"SSL3", ssl3_codes }
};


static int kx_rsa_codes[]      = { GNUTLS_KX_RSA,
                                   GNUTLS_KX_DHE_RSA, 0 };
static int kx_dhe_codes[]      = { GNUTLS_KX_DHE_DSS,
                                   GNUTLS_KX_DHE_RSA, 0 };
static int kx_dhe_dss_codes[]  = { GNUTLS_KX_DHE_DSS, 0 };
static int kx_dhe_rsa_codes[]  = { GNUTLS_KX_DHE_RSA, 0 };

static pri_item kx_index[] = {
  { US"DHE_DSS", kx_dhe_dss_codes },
  { US"DHE_RSA", kx_dhe_rsa_codes },
  { US"RSA", kx_rsa_codes },
  { US"DHE", kx_dhe_codes }
};


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


static int mac_sha_codes[]     = { GNUTLS_MAC_SHA, 0 };
static int mac_md5_codes[]     = { GNUTLS_MAC_MD5, 0 };

static pri_item mac_index[] = {
  { US"SHA",  mac_sha_codes },
  { US"SHA1", mac_sha_codes },
  { US"MD5",  mac_md5_codes }
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
  msg       additional error string (may be NULL)
            usually obtained from gnutls_strerror()

Returns:    OK/DEFER/FAIL
*/

static int
tls_error(uschar *prefix, host_item *host, const char *msg)
{
if (host == NULL)
  {
  uschar *conn_info = smtp_get_connection_info();
  if (strncmp(conn_info, "SMTP ", 5) == 0)
    conn_info += 5;
  log_write(0, LOG_MAIN, "TLS error on %s (%s)%s%s",
    conn_info, prefix, msg ? ": " : "", msg ? msg : "");
  return DEFER;
  }
else
  {
  log_write(0, LOG_MAIN, "TLS error on connection to %s [%s] (%s)%s%s",
    host->name, host->address, prefix, msg ? ": " : "", msg ? msg : "");
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
verify_certificate(gnutls_session session, const char **error)
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
  *error = "not supplied";
  }

/* Handle the result of verification. INVALID seems to be set as well
as REVOKED, but leave the test for both. */

if ((verify & (GNUTLS_CERT_INVALID|GNUTLS_CERT_REVOKED)) != 0)
  {
  tls_certificate_verified = FALSE;
  if (*error == NULL) *error = ((verify & GNUTLS_CERT_REVOKED) != 0)?
    "revoked" : "invalid";
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
*            Setup up DH parameters              *
*************************************************/

/* Generating the D-H parameters may take a long time. They only need to
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
init_dh(host_item *host)
{
int fd;
int ret;
gnutls_datum m;
uschar filename[200];

/* Initialize the data structures for holding the parameters */

ret = gnutls_dh_params_init(&dh_params);
if (ret < 0) return tls_error(US"init dh_params", host, gnutls_strerror(ret));

/* Set up the name of the cache file */

if (!string_format(filename, sizeof(filename), "%s/gnutls-params",
      spool_directory))
  return tls_error(US"overlong filename", host, NULL);

/* Open the cache file for reading and if successful, read it and set up the
parameters. */

fd = Uopen(filename, O_RDONLY, 0);
if (fd >= 0)
  {
  struct stat statbuf;
  if (fstat(fd, &statbuf) < 0)
    {
    (void)close(fd);
    return tls_error(US"TLS cache stat failed", host, strerror(errno));
    }

  m.size = statbuf.st_size;
  m.data = malloc(m.size);
  if (m.data == NULL)
    return tls_error(US"memory allocation failed", host, strerror(errno));
  errno = 0;
  if (read(fd, m.data, m.size) != m.size)
    return tls_error(US"TLS cache read failed", host, strerror(errno));
  (void)close(fd);

  ret = gnutls_dh_params_import_pkcs3(dh_params, &m, GNUTLS_X509_FMT_PEM);
  if (ret < 0)
    return tls_error(US"DH params import", host, gnutls_strerror(ret));
  DEBUG(D_tls) debug_printf("read D-H parameters from file\n");

  free(m.data);
  }

/* If the file does not exist, fall through to compute new data and cache it.
If there was any other opening error, it is serious. */

else if (errno == ENOENT)
  {
  ret = -1;
  DEBUG(D_tls)
    debug_printf("parameter cache file %s does not exist\n", filename);
  }
else
  return tls_error(string_open_failed(errno, "%s for reading", filename),
    host, NULL);

/* If ret < 0, either the cache file does not exist, or the data it contains
is not useful. One particular case of this is when upgrading from an older
release of Exim in which the data was stored in a different format. We don't
try to be clever and support both formats; we just regenerate new data in this
case. */

if (ret < 0)
  {
  uschar tempfilename[sizeof(filename) + 10];

  DEBUG(D_tls) debug_printf("generating %d bit Diffie-Hellman key...\n",
    DH_BITS);
  ret = gnutls_dh_params_generate2(dh_params, DH_BITS);
  if (ret < 0) return tls_error(US"D-H key generation", host, gnutls_strerror(ret));

  /* Write the parameters to a file in the spool directory so that we
  can use them from other Exim processes. */

  sprintf(CS tempfilename, "%s-%d", filename, (int)getpid());
  fd = Uopen(tempfilename, O_WRONLY|O_CREAT, 0400);
  if (fd < 0)
    return tls_error(string_open_failed(errno, "%s for writing", filename),
      host, NULL);
  (void)fchown(fd, exim_uid, exim_gid);   /* Probably not necessary */

  /* export the parameters in a format that can be generated using GNUTLS'
   * certtool or other programs.
   *
   * The commands for certtool are:
   * $ certtool --generate-dh-params --bits 1024 > params
   */

  m.size = PARAM_SIZE;
  m.data = malloc(m.size);
  if (m.data == NULL)
    return tls_error(US"memory allocation failed", host, strerror(errno));

  m.size = PARAM_SIZE;
  ret = gnutls_dh_params_export_pkcs3(dh_params, GNUTLS_X509_FMT_PEM, m.data,
    &m.size);
  if (ret < 0)
    return tls_error(US"DH params export", host, gnutls_strerror(ret));

  m.size = Ustrlen(m.data);
  errno = 0;
  if (write(fd, m.data, m.size) != m.size || write(fd, "\n", 1) != 1)
    return tls_error(US"TLS cache write failed", host, strerror(errno));

  free(m.data);
  (void)close(fd);

  if (rename(CS tempfilename, CS filename) < 0)
    return tls_error(string_sprintf("failed to rename %s as %s",
      tempfilename, filename), host, strerror(errno));

  DEBUG(D_tls) debug_printf("wrote D-H parameters to file %s\n", filename);
  }

DEBUG(D_tls) debug_printf("initialized D-H parameters\n");
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

client_host = host;

rc = gnutls_global_init();
if (rc < 0) return tls_error(US"tls-init", host, gnutls_strerror(rc));

/* Create D-H parameters, or read them from the cache file. This function does
its own SMTP error messaging. */

rc = init_dh(host);
if (rc != OK) return rc;

/* Create the credentials structure */

rc = gnutls_certificate_allocate_credentials(&x509_cred);
if (rc < 0)
  return tls_error(US"certificate_allocate_credentials",
    host, gnutls_strerror(rc));

/* This stuff must be done for each session, because different certificates
may be required for different sessions. */

if (!expand_check(certificate, US"tls_certificate", &cert_expanded))
  return DEFER;

key_expanded = NULL;
if (privatekey != NULL)
  {
  if (!expand_check(privatekey, US"tls_privatekey", &key_expanded))
    return DEFER;
  }

/* If expansion was forced to fail, key_expanded will be NULL. If the result of
the expansion is an empty string, ignore it also, and assume that the private
key is in the same file as the certificate. */

if (key_expanded == NULL || *key_expanded == 0)
  key_expanded = cert_expanded;

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
    return tls_error(msg, host, gnutls_strerror(rc));
    }
  }

/* A certificate is mandatory in a server, but not in a client */

else
  {
  if (host == NULL)
    return tls_error(US"no TLS server certificate is specified", NULL, NULL);
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

  DEBUG(D_tls) debug_printf("verify certificates = %s size=" OFF_T_FMT "\n",
    cas_expanded, statbuf.st_size);

  /* If the cert file is empty, there's no point in loading the CRL file. */

  if (statbuf.st_size > 0)
    {
    rc = gnutls_certificate_set_x509_trust_file(x509_cred, CS cas_expanded,
      GNUTLS_X509_FMT_PEM);
    if (rc < 0) return tls_error(US"setup_certs", host, gnutls_strerror(rc));

    if (crl != NULL && *crl != 0)
      {
      if (!expand_check(crl, US"tls_crl", &crl_expanded))
        return DEFER;
      DEBUG(D_tls) debug_printf("loading CRL file = %s\n", crl_expanded);
      rc = gnutls_certificate_set_x509_crl_file(x509_cred, CS crl_expanded,
        GNUTLS_X509_FMT_PEM);
      if (rc < 0) return tls_error(US"CRL setup", host, gnutls_strerror(rc));
      }
    }
  }

/* Associate the parameters with the x509 credentials structure. */

gnutls_certificate_set_dh_params(x509_cred, dh_params);

DEBUG(D_tls) debug_printf("initialized certificate stuff\n");
return OK;
}




/*************************************************
*           Remove from a priority list          *
*************************************************/

/* Cautiously written so that it will remove duplicates if present.

Arguments:
  list         a zero-terminated list
  remove_list  a zero-terminated list to be removed

Returns:       nothing
*/

static void
remove_priority(int *list, int *remove_list)
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
*            Add to a priority list              *
*************************************************/

/* Cautiously written to check the list size

Arguments:
  list         a zero-terminated list
  list_max     maximum offset in the list
  add_list     a zero-terminated list to be added

Returns:       TRUE if OK; FALSE if list overflows
*/

static BOOL
add_priority(int *list, int list_max, int *add_list)
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
*          Adjust a priority list                *
*************************************************/

/* This function is called to adjust the lists of cipher algorithms, MAC
algorithms, key-exchange methods, and protocols.

Arguments:
  plist       the appropriate priority list
  psize       the length of the list
  s           the configuation string
  index       the index of recognized strings
  isize       the length of the index


  which       text for an error message

Returns:      FALSE if the table overflows, else TRUE
*/

static BOOL
set_priority(int *plist, int psize, uschar *s, pri_item *index, int isize,
   uschar *which)
{
int sep = 0;
BOOL first = TRUE;
uschar *t;

while ((t = string_nextinlist(&s, &sep, big_buffer, big_buffer_size)) != NULL)
  {
  int i;
  BOOL exclude = t[0] == '!';
  if (first && !exclude) plist[0] = 0;
  first = FALSE;
  for (i = 0; i < isize; i++)
    {
    uschar *ss = strstric(t, index[i].name, FALSE);
    if (ss != NULL)
      {
      uschar *endss = ss + Ustrlen(index[i].name);
      if ((ss == t || !isalnum(ss[-1])) && !isalnum(*endss))
        {
        if (exclude)
          remove_priority(plist, index[i].values);
        else
          {
          if (!add_priority(plist, psize, index[i].values))
            {
            log_write(0, LOG_MAIN|LOG_PANIC, "GnuTLS init failed: %s "
              "priority table overflow", which);
            return FALSE;
            }
          }
        }
      }
    }
  }

DEBUG(D_tls)
  {
  int *ptr = plist;
  debug_printf("adjusted %s priorities:", which);
  while (*ptr != 0) debug_printf(" %d", *ptr++);
  debug_printf("\n");
  }

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
  expciphers   expanded ciphers list or NULL
  expmac       expanded MAC list or NULL
  expkx        expanded key-exchange list or NULL
  expproto     expanded protocol list or NULL

Returns:  a gnutls_session, or NULL if there is a problem
*/

static gnutls_session
tls_session_init(int side, uschar *expciphers, uschar *expmac, uschar *expkx,
  uschar *expproto)
{
gnutls_session session;

gnutls_init(&session, side);

/* Initialize the lists of permitted protocols, key-exchange methods, ciphers,
and MACs. */

memcpy(cipher_priority, default_cipher_priority, sizeof(cipher_priority));
memcpy(mac_priority, default_mac_priority, sizeof(mac_priority));
memcpy(kx_priority, default_kx_priority, sizeof(kx_priority));
memcpy(proto_priority, default_proto_priority, sizeof(proto_priority));

/* The names OpenSSL uses in tls_require_ciphers are of the form DES-CBC3-SHA,
using hyphen separators. GnuTLS uses underscore separators. So that I can use
either form for tls_require_ciphers in my tests, and also for general
convenience, we turn hyphens into underscores before scanning the list. */

if (expciphers != NULL)
  {
  uschar *s = expciphers;
  while (*s != 0) { if (*s == '-') *s = '_'; s++; }
  }

if ((expciphers != NULL &&
      !set_priority(cipher_priority, sizeof(cipher_priority)/sizeof(int),
        expciphers, cipher_index, sizeof(cipher_index)/sizeof(pri_item),
        US"cipher")) ||
    (expmac != NULL &&
      !set_priority(mac_priority, sizeof(mac_priority)/sizeof(int),
        expmac, mac_index, sizeof(mac_index)/sizeof(pri_item),
        US"MAC")) ||
    (expkx != NULL &&
      !set_priority(kx_priority, sizeof(kx_priority)/sizeof(int),
        expkx, kx_index, sizeof(kx_index)/sizeof(pri_item),
        US"key-exchange")) ||
    (expproto != NULL &&
      !set_priority(proto_priority, sizeof(proto_priority)/sizeof(int),
        expproto, proto_index, sizeof(proto_index)/sizeof(pri_item),
        US"protocol")))
  {
  gnutls_deinit(session);
  return NULL;
  }

/* Define the various priorities */

gnutls_cipher_set_priority(session, cipher_priority);
gnutls_compression_set_priority(session, comp_priority);
gnutls_kx_set_priority(session, kx_priority);
gnutls_protocol_set_priority(session, proto_priority);
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
  require_ciphers  list of allowed ciphers or NULL
  require_mac      list of allowed MACs or NULL
  require_kx       list of allowed key_exchange methods or NULL
  require_proto    list of allowed protocols or NULL

Returns:           OK on success
                   DEFER for errors before the start of the negotiation
                   FAIL for errors during the negotation; the server can't
                     continue running.
*/

int
tls_server_start(uschar *require_ciphers, uschar *require_mac,
  uschar *require_kx, uschar *require_proto)
{
int rc;
const char *error;
uschar *expciphers = NULL;
uschar *expmac = NULL;
uschar *expkx = NULL;
uschar *expproto = NULL;

/* Check for previous activation */

if (tls_active >= 0)
  {
  tls_error("STARTTLS received after TLS started", NULL, "");
  smtp_printf("554 Already in TLS\r\n");
  return FAIL;
  }

/* Initialize the library. If it fails, it will already have logged the error
and sent an SMTP response. */

DEBUG(D_tls) debug_printf("initializing GnuTLS as a server\n");

rc = tls_init(NULL, tls_certificate, tls_privatekey, tls_verify_certificates,
  tls_crl);
if (rc != OK) return rc;

if (!expand_check(require_ciphers, US"tls_require_ciphers", &expciphers) ||
    !expand_check(require_mac, US"gnutls_require_mac", &expmac) ||
    !expand_check(require_kx, US"gnutls_require_kx", &expkx) ||
    !expand_check(require_proto, US"gnutls_require_proto", &expproto))
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

tls_session = tls_session_init(GNUTLS_SERVER, expciphers, expmac, expkx,
  expproto);
if (tls_session == NULL)
  return tls_error(US"tls_session_init", NULL,
    gnutls_strerror(GNUTLS_E_MEMORY_ERROR));

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

gnutls_transport_set_ptr2(tls_session, (gnutls_transport_ptr)fileno(smtp_in),
                                       (gnutls_transport_ptr)fileno(smtp_out));

sigalrm_seen = FALSE;
if (smtp_receive_timeout > 0) alarm(smtp_receive_timeout);
rc = gnutls_handshake(tls_session);
alarm(0);

if (rc < 0)
  {
  tls_error(US"gnutls_handshake", NULL,
    sigalrm_seen ? "timed out" : gnutls_strerror(rc));

  /* It seems that, except in the case of a timeout, we have to close the
  connection right here; otherwise if the other end is running OpenSSL it hangs
  until the server times out. */

  if (!sigalrm_seen)
    {
    (void)fclose(smtp_out);
    (void)fclose(smtp_in);
    }

  return FAIL;
  }

DEBUG(D_tls) debug_printf("gnutls_handshake was successful\n");

if (verify_requirement != VERIFY_NONE &&
     !verify_certificate(tls_session, &error))
  {
  tls_error(US"certificate verification failed", NULL, error);
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
receive_smtp_buffered = tls_smtp_buffered;

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
  addr              the first address (not used)
  dhparam           DH parameter file
  certificate       certificate file
  privatekey        private key file
  verify_certs      file for certificate verify
  verify_crl        CRL for verify
  require_ciphers   list of allowed ciphers or NULL
  require_mac       list of allowed MACs or NULL
  require_kx        list of allowed key_exchange methods or NULL
  require_proto     list of allowed protocols or NULL
  timeout           startup timeout

Returns:            OK/DEFER/FAIL (because using common functions),
                    but for a client, DEFER and FAIL have the same meaning
*/

int
tls_client_start(int fd, host_item *host, address_item *addr, uschar *dhparam,
  uschar *certificate, uschar *privatekey, uschar *verify_certs,
  uschar *verify_crl, uschar *require_ciphers, uschar *require_mac,
  uschar *require_kx, uschar *require_proto, int timeout)
{
const gnutls_datum *server_certs;
uschar *expciphers = NULL;
uschar *expmac = NULL;
uschar *expkx = NULL;
uschar *expproto = NULL;
const char *error;
unsigned int server_certs_size;
int rc;

DEBUG(D_tls) debug_printf("initializing GnuTLS as a client\n");

verify_requirement = (verify_certs == NULL)? VERIFY_NONE : VERIFY_REQUIRED;
rc = tls_init(host, certificate, privatekey, verify_certs, verify_crl);
if (rc != OK) return rc;

if (!expand_check(require_ciphers, US"tls_require_ciphers", &expciphers) ||
    !expand_check(require_mac, US"gnutls_require_mac", &expmac) ||
    !expand_check(require_kx, US"gnutls_require_kx", &expkx) ||
    !expand_check(require_proto, US"gnutls_require_proto", &expproto))
  return FAIL;

tls_session = tls_session_init(GNUTLS_CLIENT, expciphers, expmac, expkx,
  expproto);

if (tls_session == NULL)
  return tls_error(US "tls_session_init", host,
    gnutls_strerror(GNUTLS_E_MEMORY_ERROR));

gnutls_transport_set_ptr(tls_session, (gnutls_transport_ptr)fd);

/* There doesn't seem to be a built-in timeout on connection. */

sigalrm_seen = FALSE;
alarm(timeout);
rc = gnutls_handshake(tls_session);
alarm(0);

if (rc < 0)
  return tls_error(US "gnutls_handshake", host,
    sigalrm_seen ? "timed out" : gnutls_strerror(rc));

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
  return tls_error(US"certificate verification failed", host, error);

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
const char *msg;

if (ec == GNUTLS_E_FATAL_ALERT_RECEIVED)
  msg = string_sprintf("%s: %s", gnutls_strerror(ec),
    gnutls_alert_get_name(gnutls_alert_get(tls_session)));
else
  msg = gnutls_strerror(ec);

tls_error(when, client_host, msg);
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
    receive_smtp_buffered = smtp_buffered;

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




/*************************************************
*         Report the library versions.           *
*************************************************/

/* See a description in tls-openssl.c for an explanation of why this exists.

Arguments:   a FILE* to print the results to
Returns:     nothing
*/

void
tls_version_report(FILE *f)
{
fprintf(f, "GnuTLS compile-time version: %s\n", LIBGNUTLS_VERSION);
fprintf(f, "GnuTLS runtime version: %s\n", gnutls_check_version(NULL));
}

/* End of tls-gnu.c */
