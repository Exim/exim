/* A little hacked up program that makes a TCP/IP call and reads a script to
drive it, for testing Exim server code running as a daemon. It's got a bit
messy with the addition of support for either OpenSSL or GnuTLS. The code for
those was hacked out of Exim itself, then code for OCSP stapling was ripped
from the openssl ocsp and s_client utilities. */

/* ANSI C standard includes */

#include <ctype.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Unix includes */

#include <errno.h>
#include <dirent.h>
#include <sys/types.h>

#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>

#include <netdb.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <utime.h>

#ifdef AF_INET6
#define HAVE_IPV6 1
#endif

#ifndef S_ADDR_TYPE
#define S_ADDR_TYPE u_long
#endif

typedef unsigned char uschar;

#define CS   (char *)
#define US   (unsigned char *)

#define FALSE         0
#define TRUE          1



static int sigalrm_seen = 0;


/* TLS support can be optionally included, either for OpenSSL or GnuTLS. The
latter needs a whole pile of tables. */

#ifdef HAVE_OPENSSL
#define HAVE_TLS
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ocsp.h>

char * ocsp_stapling = NULL;
#endif


#ifdef HAVE_GNUTLS
#define HAVE_TLS
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

#define DH_BITS      768

/* Local static variables for GNUTLS */

static gnutls_dh_params dh_params = NULL;

static gnutls_certificate_credentials_t x509_cred = NULL;
static gnutls_session tls_session = NULL;

static int  ssl_session_timeout = 200;

/* Priorities for TLS algorithms to use. */

static const int protocol_priority[16] = { GNUTLS_TLS1, GNUTLS_SSL3, 0 };

static const int kx_priority[16] = {
  GNUTLS_KX_RSA,
  GNUTLS_KX_DHE_DSS,
  GNUTLS_KX_DHE_RSA,
  0 };

static int default_cipher_priority[16] = {
  GNUTLS_CIPHER_AES_256_CBC,
  GNUTLS_CIPHER_AES_128_CBC,
  GNUTLS_CIPHER_3DES_CBC,
  GNUTLS_CIPHER_ARCFOUR_128,
  0 };

static const int mac_priority[16] = {
  GNUTLS_MAC_SHA,
  GNUTLS_MAC_MD5,
  0 };

static const int comp_priority[16] = { GNUTLS_COMP_NULL, 0 };
static const int cert_type_priority[16] = { GNUTLS_CRT_X509, 0 };

#endif




/*************************************************
*            SIGALRM handler - crash out         *
*************************************************/

static void
sigalrm_handler_crash(int sig)
{
sig = sig;    /* Keep picky compilers happy */
printf("\nClient timed out\n");
exit(99);
}


/*************************************************
*            SIGALRM handler - set flag          *
*************************************************/

static void
sigalrm_handler_flag(int sig)
{
sig = sig;    /* Keep picky compilers happy */
sigalrm_seen = 1;
}



/****************************************************************************/
/****************************************************************************/

#ifdef HAVE_OPENSSL

X509_STORE *
setup_verify(BIO *bp, char *CAfile, char *CApath)
{
        X509_STORE *store;
        X509_LOOKUP *lookup;
        if(!(store = X509_STORE_new())) goto end;
        lookup=X509_STORE_add_lookup(store,X509_LOOKUP_file());
        if (lookup == NULL) goto end;
        if (CAfile) {
                if(!X509_LOOKUP_load_file(lookup,CAfile,X509_FILETYPE_PEM)) {
                        BIO_printf(bp, "Error loading file %s\n", CAfile);
                        goto end;
                }
        } else X509_LOOKUP_load_file(lookup,NULL,X509_FILETYPE_DEFAULT);

        lookup=X509_STORE_add_lookup(store,X509_LOOKUP_hash_dir());
        if (lookup == NULL) goto end;
        if (CApath) {
                if(!X509_LOOKUP_add_dir(lookup,CApath,X509_FILETYPE_PEM)) {
                        BIO_printf(bp, "Error loading directory %s\n", CApath);
                        goto end;
                }
        } else X509_LOOKUP_add_dir(lookup,NULL,X509_FILETYPE_DEFAULT);

        ERR_clear_error();
        return store;
        end:
        X509_STORE_free(store);
        return NULL;
}


static int
tls_client_stapling_cb(SSL *s, void *arg)
{
const unsigned char *p;
int len;
OCSP_RESPONSE *rsp;
OCSP_BASICRESP *bs;
char *CAfile = NULL;
X509_STORE *store = NULL;
int ret = 1;

len = SSL_get_tlsext_status_ocsp_resp(s, &p);
/*BIO_printf(arg, "OCSP response: ");*/
if (!p)
	{
	BIO_printf(arg, "no response received\n");
	return 1;
	}
if(!(rsp = d2i_OCSP_RESPONSE(NULL, &p, len)))
	{
	BIO_printf(arg, "response parse error\n");
	BIO_dump_indent(arg, (char *)p, len, 4);
	return 0;
	}
if(!(bs = OCSP_response_get1_basic(rsp)))
  {
  BIO_printf(arg, "error parsing response\n");
  return 0;
  }

CAfile = ocsp_stapling;
if(!(store = setup_verify(arg, CAfile, NULL)))
  {
  BIO_printf(arg, "error in cert setup\n");
  return 0;
  }

/* No file of alternate certs, no options */
if(OCSP_basic_verify(bs, NULL, store, 0) <= 0)
  {
  BIO_printf(arg, "Response Verify Failure\n");
  ERR_print_errors(arg);
  ret = 0;
  }
else
  BIO_printf(arg, "Response verify OK\n");

X509_STORE_free(store);
return ret;
}


/*************************************************
*         Start an OpenSSL TLS session           *
*************************************************/

int tls_start(int sock, SSL **ssl, SSL_CTX *ctx)
{
int rc;
static const char *sid_ctx = "exim";

RAND_load_file("client.c", -1);   /* Not *very* random! */

*ssl = SSL_new (ctx);
SSL_set_session_id_context(*ssl, sid_ctx, strlen(sid_ctx));
SSL_set_fd (*ssl, sock);
SSL_set_connect_state(*ssl);

if (ocsp_stapling)
  {
  SSL_CTX_set_tlsext_status_cb(ctx, tls_client_stapling_cb);
  SSL_CTX_set_tlsext_status_arg(ctx, BIO_new_fp(stdout, BIO_NOCLOSE));
  SSL_set_tlsext_status_type(*ssl, TLSEXT_STATUSTYPE_ocsp);
  }

signal(SIGALRM, sigalrm_handler_flag);
sigalrm_seen = 0;
alarm(5);
rc = SSL_connect (*ssl);
alarm(0);

if (sigalrm_seen)
  {
  printf("SSL_connect timed out\n");
  return 0;
  }

if (rc <= 0)
  {
  ERR_print_errors_fp(stdout);
  return 0;
  }

printf("SSL connection using %s\n", SSL_get_cipher (*ssl));
return 1;
}


/*************************************************
*           SSL Information callback             *
*************************************************/

static void
info_callback(SSL *s, int where, int ret)
{
where = where;
ret = ret;
printf("SSL info: %s\n", SSL_state_string_long(s));
}
#endif


/****************************************************************************/
/****************************************************************************/


#ifdef HAVE_GNUTLS
/*************************************************
*            Handle GnuTLS error                 *
*************************************************/

/* Called from lots of places when errors occur before actually starting to do
the TLS handshake, that is, while the session is still in clear.

Argument:
  prefix    prefix text
  err       a GnuTLS error number, or 0 if local error

Returns:    doesn't - it dies
*/

static void
gnutls_error(uschar *prefix, int err)
{
fprintf(stderr, "GnuTLS connection error: %s:", prefix);
if (err != 0) fprintf(stderr, " %s", gnutls_strerror(err));
fprintf(stderr, "\n");
exit(1);
}



/*************************************************
*             Setup up DH parameters             *
*************************************************/

/* For the test suite, the parameters should always be available in the spool
directory. */

static void
init_dh(void)
{
int fd;
int ret;
gnutls_datum m;
uschar filename[200];
struct stat statbuf;

/* Initialize the data structures for holding the parameters */

ret = gnutls_dh_params_init(&dh_params);
if (ret < 0) gnutls_error(US"init dh_params", ret);

/* Open the cache file for reading and if successful, read it and set up the
parameters. */

fd = open("aux-fixed/gnutls-params", O_RDONLY, 0);
if (fd < 0)
  {
  fprintf(stderr, "Failed to open spool/gnutls-params: %s\n", strerror(errno));
  exit(1);
  }

if (fstat(fd, &statbuf) < 0)
  {
  (void)close(fd);
  return gnutls_error(US"TLS cache stat failed", 0);
  }

m.size = statbuf.st_size;
m.data = malloc(m.size);
if (m.data == NULL)
  return gnutls_error(US"memory allocation failed", 0);
if (read(fd, m.data, m.size) != m.size)
  return gnutls_error(US"TLS cache read failed", 0);
(void)close(fd);

ret = gnutls_dh_params_import_pkcs3(dh_params, &m, GNUTLS_X509_FMT_PEM);
if (ret < 0) return gnutls_error(US"DH params import", ret);
free(m.data);
}




/*************************************************
*            Initialize for GnuTLS               *
*************************************************/

/*
Arguments:
  certificate     certificate file
  privatekey      private key file
*/

static void
tls_init(uschar *certificate, uschar *privatekey)
{
int rc;

rc = gnutls_global_init();
if (rc < 0) gnutls_error(US"gnutls_global_init", rc);

/* Read D-H parameters from the cache file. */

init_dh();

/* Create the credentials structure */

rc = gnutls_certificate_allocate_credentials(&x509_cred);
if (rc < 0) gnutls_error(US"certificate_allocate_credentials", rc);

/* Set the certificate and private keys */

if (certificate != NULL)
  {
  rc = gnutls_certificate_set_x509_key_file(x509_cred, CS certificate,
    CS privatekey, GNUTLS_X509_FMT_PEM);
  if (rc < 0) gnutls_error("gnutls_certificate", rc);
  }

/* Associate the parameters with the x509 credentials structure. */

gnutls_certificate_set_dh_params(x509_cred, dh_params);
}



/*************************************************
*        Initialize a single GNUTLS session      *
*************************************************/

static gnutls_session
tls_session_init(void)
{
gnutls_session session;

gnutls_init(&session, GNUTLS_CLIENT);

gnutls_cipher_set_priority(session, default_cipher_priority);
gnutls_compression_set_priority(session, comp_priority);
gnutls_kx_set_priority(session, kx_priority);
gnutls_protocol_set_priority(session, protocol_priority);
gnutls_mac_set_priority(session, mac_priority);

gnutls_cred_set(session, GNUTLS_CRD_CERTIFICATE, x509_cred);

gnutls_dh_set_prime_bits(session, DH_BITS);
gnutls_db_set_cache_expiration(session, ssl_session_timeout);

return session;
}
#endif


/****************************************************************************/
/****************************************************************************/




/*************************************************
*                 Main Program                   *
*************************************************/

const char * const HELP_MESSAGE = "\n\
Usage: client\n\
          <IP address>\n\
          <port>\n\
          [<outgoing interface>]\n\
          [<cert file>]\n\
          [<key file>]\n\
\n";

int main(int argc, char **argv)
{
struct sockaddr *s_ptr;
struct sockaddr_in s_in4;
char *interface = NULL;
char *address = NULL;
char *certfile = NULL;
char *keyfile = NULL;
char *end = NULL;
int argi = 1;
int host_af, port, s_len, rc, sock, save_errno;
int timeout = 1;
int tls_active = 0;
int sent_starttls = 0;
int tls_on_connect = 0;
long tmplong;

#if HAVE_IPV6
struct sockaddr_in6 s_in6;
#endif

#ifdef HAVE_OPENSSL
SSL_CTX* ctx;
SSL*     ssl;
#endif

unsigned char outbuffer[10240];
unsigned char inbuffer[10240];
unsigned char *inptr = inbuffer;

*inptr = 0;   /* Buffer empty */

/* Options */

while (argc >= argi + 1 && argv[argi][0] == '-')
  {
  if (strcmp(argv[argi], "-help") == 0 ||
      strcmp(argv[argi], "--help") == 0 ||
      strcmp(argv[argi], "-h") == 0)
    {
    printf(HELP_MESSAGE);
    exit(0);
    }
  if (strcmp(argv[argi], "-tls-on-connect") == 0)
    {
    tls_on_connect = 1;
    argi++;
    }
#ifdef HAVE_OPENSSL
  else if (strcmp(argv[argi], "-ocsp") == 0)
    {
    if (argc < ++argi + 1)
      {
      fprintf(stderr, "Missing required certificate file for ocsp option\n");
      exit(1);
      }
    ocsp_stapling = argv[argi++];
    }
#endif
  else if (argv[argi][1] == 't' && isdigit(argv[argi][2]))
    {
    tmplong = strtol(argv[argi]+2, &end, 10);
    if (end == argv[argi]+2 || *end)
      {
      fprintf(stderr, "Failed to parse seconds from option <%s>\n",
        argv[argi]);
      exit(1);
      }
    if (tmplong > 10000L)
      {
      fprintf(stderr, "Unreasonably long wait of %d seconds requested\n",
        tmplong);
      exit(1);
      }
    if (tmplong < 0L)
      {
      fprintf(stderr, "Timeout must not be negative (%d)\n", tmplong);
      exit(1);
      }
    timeout = (int) tmplong;
    argi++;
    }
  else
    {
    fprintf(stderr, "Unrecognized option %s\n", argv[argi]);
    exit(1);
    }
  }

/* Mandatory 1st arg is IP address */

if (argc < argi+1)
  {
  fprintf(stderr, "No IP address given\n");
  exit(1);
  }

address = argv[argi++];
host_af = (strchr(address, ':') != NULL)? AF_INET6 : AF_INET;

/* Mandatory 2nd arg is port */

if (argc < argi+1)
  {
  fprintf(stderr, "No port number given\n");
  exit(1);
  }

port = atoi(argv[argi++]);

/* Optional next arg is interface */

if (argc > argi &&
  (isdigit((unsigned char)argv[argi][0]) || argv[argi][0] == ':'))
    interface = argv[argi++];

/* Any more arguments are the name of a certificate file and key file */

if (argc > argi) certfile = argv[argi++];
if (argc > argi) keyfile = argv[argi++];


#if HAVE_IPV6
/* For an IPv6 address, use an IPv6 sockaddr structure. */

if (host_af == AF_INET6)
  {
  s_ptr = (struct sockaddr *)&s_in6;
  s_len = sizeof(s_in6);
  }
else
#endif

/* For an IPv4 address, use an IPv4 sockaddr structure,
even on an IPv6 system. */

  {
  s_ptr = (struct sockaddr *)&s_in4;
  s_len = sizeof(s_in4);
  }

printf("Connecting to %s port %d ... ", address, port);

sock = socket(host_af, SOCK_STREAM, 0);
if (sock < 0)
  {
  printf("socket creation failed: %s\n", strerror(errno));
  exit(1);
  }

/* Bind to a specific interface if requested. On an IPv6 system, this has
to be of the same family as the address we are calling. On an IPv4 system the
test is redundant, but it keeps the code tidier. */

if (interface != NULL)
  {
  int interface_af = (strchr(interface, ':') != NULL)? AF_INET6 : AF_INET;

  if (interface_af == host_af)
    {
    #if HAVE_IPV6

    /* Set up for IPv6 binding */

    if (host_af == AF_INET6)
      {
      memset(&s_in6, 0, sizeof(s_in6));
      s_in6.sin6_family = AF_INET6;
      s_in6.sin6_port = 0;
      if (inet_pton(AF_INET6, interface, &s_in6.sin6_addr) != 1)
        {
        printf("Unable to parse \"%s\"", interface);
        exit(1);
        }
      }
    else
    #endif

    /* Set up for IPv4 binding */

      {
      memset(&s_in4, 0, sizeof(s_in4));
      s_in4.sin_family = AF_INET;
      s_in4.sin_port = 0;
      s_in4.sin_addr.s_addr = (S_ADDR_TYPE)inet_addr(interface);
      }

    /* Bind */

    if (bind(sock, s_ptr, s_len) < 0)
      {
      printf("Unable to bind outgoing SMTP call to %s: %s",
        interface, strerror(errno));
      exit(1);
      }
    }
  }

/* Set up a remote IPv6 address */

#if HAVE_IPV6
if (host_af == AF_INET6)
  {
  memset(&s_in6, 0, sizeof(s_in6));
  s_in6.sin6_family = AF_INET6;
  s_in6.sin6_port = htons(port);
  if (inet_pton(host_af, address, &s_in6.sin6_addr) != 1)
    {
    printf("Unable to parse \"%s\"", address);
    exit(1);
    }
  }
else
#endif

/* Set up a remote IPv4 address */

  {
  memset(&s_in4, 0, sizeof(s_in4));
  s_in4.sin_family = AF_INET;
  s_in4.sin_port = htons(port);
  s_in4.sin_addr.s_addr = (S_ADDR_TYPE)inet_addr(address);
  }

/* SIGALRM handler crashes out */

signal(SIGALRM, sigalrm_handler_crash);
alarm(timeout);
rc = connect(sock, s_ptr, s_len);
save_errno = errno;
alarm(0);

/* A failure whose error code is "Interrupted system call" is in fact
an externally applied timeout if the signal handler has been run. */

if (rc < 0)
  {
  close(sock);
  printf("failed: %s\n", strerror(save_errno));
  exit(1);
  }

printf("connected\n");


/* --------------- Set up for OpenSSL --------------- */

#ifdef HAVE_OPENSSL
SSL_library_init();
SSL_load_error_strings();

ctx = SSL_CTX_new(SSLv23_method());
if (ctx == NULL)
  {
  printf ("SSL_CTX_new failed\n");
  exit(1);
  }

if (certfile != NULL)
  {
  if (!SSL_CTX_use_certificate_file(ctx, certfile, SSL_FILETYPE_PEM))
    {
    printf("SSL_CTX_use_certificate_file failed\n");
    exit(1);
    }
  printf("Certificate file = %s\n", certfile);
  }

if (keyfile != NULL)
  {
  if (!SSL_CTX_use_PrivateKey_file(ctx, keyfile, SSL_FILETYPE_PEM))
    {
    printf("SSL_CTX_use_PrivateKey_file failed\n");
    exit(1);
    }
  printf("Key file = %s\n", keyfile);
  }

SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_BOTH);
SSL_CTX_set_timeout(ctx, 200);
SSL_CTX_set_info_callback(ctx, (void (*)())info_callback);
#endif


/* --------------- Set up for GnuTLS --------------- */

#ifdef HAVE_GNUTLS
if (certfile != NULL) printf("Certificate file = %s\n", certfile);
if (keyfile != NULL) printf("Key file = %s\n", keyfile);
tls_init(certfile, keyfile);
tls_session = tls_session_init();
gnutls_transport_set_ptr(tls_session, (gnutls_transport_ptr)sock);

/* When the server asks for a certificate and the client does not have one,
there is a SIGPIPE error in the gnutls_handshake() function for some reason
that is not understood. As luck would have it, this has never hit Exim itself
because it ignores SIGPIPE errors. Doing the same here allows it all to work as
one wants. */

signal(SIGPIPE, SIG_IGN);
#endif

/* ---------------------------------------------- */


/* Start TLS session if configured to do so without STARTTLS */

#ifdef HAVE_TLS
if (tls_on_connect)
  {
  printf("Attempting to start TLS\n");

  #ifdef HAVE_OPENSSL
  tls_active = tls_start(sock, &ssl, ctx);
  #endif

  #ifdef HAVE_GNUTLS
  sigalrm_seen = FALSE;
  alarm(timeout);
  tls_active = gnutls_handshake(tls_session) >= 0;
  alarm(0);
  #endif

  if (!tls_active)
    printf("Failed to start TLS\n");
  else
    printf("Succeeded in starting TLS\n");
  }
#endif

while (fgets(outbuffer, sizeof(outbuffer), stdin) != NULL)
  {
  int n = (int)strlen(outbuffer);
  while (n > 0 && isspace(outbuffer[n-1])) n--;
  outbuffer[n] = 0;

  /* Expect incoming */

  if (strncmp(outbuffer, "??? ", 4) == 0)
    {
    unsigned char *lineptr;
    printf("%s\n", outbuffer);

    if (*inptr == 0)   /* Refill input buffer */
      {
      if (tls_active)
        {
        #ifdef HAVE_OPENSSL
        rc = SSL_read (ssl, inbuffer, sizeof(inbuffer) - 1);
        #endif
        #ifdef HAVE_GNUTLS
        rc = gnutls_record_recv(tls_session, CS inbuffer, sizeof(inbuffer) - 1);
        #endif
        }
      else
        {
        alarm(timeout);
        rc = read(sock, inbuffer, sizeof(inbuffer));
        alarm(0);
        }

      if (rc < 0)
        {
        printf("Read error %s\n", strerror(errno));
        exit(1)  ;
        }
      else if (rc == 0)
        {
        printf("Unexpected EOF read\n");
        close(sock);
        exit(1);
        }
      else
        {
        inbuffer[rc] = 0;
        inptr = inbuffer;
        }
      }

    lineptr = inptr;
    while (*inptr != 0 && *inptr != '\r' && *inptr != '\n') inptr++;
    if (*inptr != 0)
      {
      *inptr++ = 0;
      if (*inptr == '\n') inptr++;
      }

    printf("<<< %s\n", lineptr);
    if (strncmp(lineptr, outbuffer + 4, (int)strlen(outbuffer) - 4) != 0)
      {
      printf("\n******** Input mismatch ********\n");
      exit(1);
      }

    #ifdef HAVE_TLS
    if (sent_starttls)
      {
      if (lineptr[0] == '2')
        {
        printf("Attempting to start TLS\n");
        fflush(stdout);

        #ifdef HAVE_OPENSSL
        tls_active = tls_start(sock, &ssl, ctx);
        #endif

        #ifdef HAVE_GNUTLS
        sigalrm_seen = FALSE;
        alarm(timeout);
        tls_active = gnutls_handshake(tls_session) >= 0;
        alarm(0);
        #endif

        if (!tls_active)
          {
          printf("Failed to start TLS\n");
          fflush(stdout);
          }
        else
          printf("Succeeded in starting TLS\n");
        }
      else printf("Abandoning TLS start attempt\n");
      }
    sent_starttls = 0;
    #endif
    }

  /* Wait for a bit before proceeding */

  else if (strncmp(outbuffer, "+++ ", 4) == 0)
    {
    printf("%s\n", outbuffer);
    sleep(atoi(outbuffer + 4));
    }

  /* Send outgoing, but barf if unconsumed incoming */

  else
    {
    unsigned char *escape;

    if (*inptr != 0)
      {
      printf("Unconsumed input: %s", inptr);
      printf("   About to send: %s\n", outbuffer);
      exit(1);
      }

    #ifdef HAVE_TLS

    /* Shutdown TLS */

    if (strcmp(outbuffer, "stoptls") == 0 ||
        strcmp(outbuffer, "STOPTLS") == 0)
      {
      if (!tls_active)
        {
        printf("STOPTLS read when TLS not active\n");
        exit(1);
        }
      printf("Shutting down TLS encryption\n");

      #ifdef HAVE_OPENSSL
      SSL_shutdown(ssl);
      SSL_free(ssl);
      #endif

      #ifdef HAVE_GNUTLS
      gnutls_bye(tls_session, GNUTLS_SHUT_WR);
      gnutls_deinit(tls_session);
      tls_session = NULL;
      gnutls_global_deinit();
      #endif

      tls_active = 0;
      continue;
      }

    /* Remember that we sent STARTTLS */

    sent_starttls = (strcmp(outbuffer, "starttls") == 0 ||
                     strcmp(outbuffer, "STARTTLS") == 0);

    /* Fudge: if the command is "starttls_wait", we send the starttls bit,
    but we haven't set the flag, so that there is no negotiation. This is for
    testing the server's timeout. */

    if (strcmp(outbuffer, "starttls_wait") == 0)
      {
      outbuffer[8] = 0;
      n = 8;
      }
    #endif

    printf(">>> %s\n", outbuffer);
    strcpy(outbuffer + n, "\r\n");

    /* Turn "\n" and "\r" into the relevant characters. This is a hack. */

    while ((escape = strstr(outbuffer, "\\r")) != NULL)
      {
      *escape = '\r';
      memmove(escape + 1, escape + 2,  (n + 2) - (escape - outbuffer) - 2);
      n--;
      }

    while ((escape = strstr(outbuffer, "\\n")) != NULL)
      {
      *escape = '\n';
      memmove(escape + 1, escape + 2,  (n + 2) - (escape - outbuffer) - 2);
      n--;
      }

    /* OK, do it */

    alarm(timeout);
    if (tls_active)
      {
      #ifdef HAVE_OPENSSL
        rc = SSL_write (ssl, outbuffer, n + 2);
      #endif
      #ifdef HAVE_GNUTLS
        rc = gnutls_record_send(tls_session, CS outbuffer, n + 2);
        if (rc < 0)
          {
          printf("GnuTLS write error: %s\n", gnutls_strerror(rc));
          exit(1);
          }
      #endif
      }
    else
      {
      rc = write(sock, outbuffer, n + 2);
      }
    alarm(0);

    if (rc < 0)
      {
      printf("Write error: %s\n", strerror(errno));
      exit(1);
      }
    }
  }

printf("End of script\n");
close(sock);

exit(0);
}

/* End of client.c */
