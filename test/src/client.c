/* A little hacked up program that makes a TCP/IP call and reads a script to
drive it, for testing Exim server code running as a daemon. It's got a bit
messy with the addition of support for either OpenSSL or GnuTLS. The code for
those was hacked out of Exim itself, then code for OpenSSL OCSP stapling was
ripped from the openssl ocsp and s_client utilities. */

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
#include <netinet/tcp.h>

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
# define HAVE_TLS
# include <openssl/crypto.h>
# include <openssl/x509.h>
# include <openssl/pem.h>
# include <openssl/ssl.h>
# include <openssl/err.h>
# include <openssl/rand.h>

# if OPENSSL_VERSION_NUMBER < 0x0090806fL && !defined(DISABLE_OCSP) && !defined(OPENSSL_NO_TLSEXT)
#  warning "OpenSSL library version too old; define DISABLE_OCSP in Makefile"
#  define DISABLE_OCSP
# endif
# ifndef DISABLE_OCSP
#  include <openssl/ocsp.h>
# endif
#endif


#ifdef HAVE_GNUTLS
# define HAVE_TLS
# include <gnutls/gnutls.h>
# include <gnutls/x509.h>
# if GNUTLS_VERSION_NUMBER >= 0x030103
#  define HAVE_OCSP
#  include <gnutls/ocsp.h>
# endif
# ifndef GNUTLS_NO_EXTENSIONS
#  define GNUTLS_NO_EXTENSIONS 0
# endif

# define DH_BITS      768

/* Local static variables for GNUTLS */

static gnutls_dh_params_t dh_params = NULL;

static gnutls_certificate_credentials_t x509_cred = NULL;
static gnutls_session_t tls_session = NULL;

static int  ssl_session_timeout = 200;

/* Priorities for TLS algorithms to use. */

# if GNUTLS_VERSION_NUMBER < 0x030400
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
# endif

#endif	/*HAVE_GNUTLS*/



#ifdef HAVE_TLS
char * ocsp_stapling = NULL;
char * pri_string = NULL;
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
# ifndef DISABLE_OCSP

static STACK_OF(X509) *
chain_from_pem_file(const uschar * file)
{
BIO * bp;
X509 * x;
STACK_OF(X509) * sk;

if (!(sk = sk_X509_new_null())) return NULL;
if (!(bp = BIO_new_file(CS file, "r"))) return NULL;
while ((x = PEM_read_bio_X509(bp, NULL, 0, NULL)))
  sk_X509_push(sk, x);
BIO_free(bp);
return sk;
}



static void
cert_stack_free(STACK_OF(X509) * sk)
{
while (sk_X509_num(sk) > 0) (void) sk_X509_pop(sk);
sk_X509_free(sk);
}


static int
tls_client_stapling_cb(SSL *s, void *arg)
{
const unsigned char *p;
int len;
OCSP_RESPONSE *rsp;
OCSP_BASICRESP *bs;
STACK_OF(X509) * sk;
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


if (!(sk = chain_from_pem_file((const uschar *)ocsp_stapling)))
  {
  BIO_printf(arg, "error in cert setup\n");
  return 0;
  }

/* OCSP_basic_verify takes a "store" arg, but does not
use it for the chain verification, which is all we do
when OCSP_NOVERIFY is set.  The content from the wire
(in "bs") and a cert-stack "sk" are all that is used. */

if(OCSP_basic_verify(bs, sk, NULL, OCSP_NOVERIFY) <= 0)
  {
  BIO_printf(arg, "Response Verify Failure\n");
  ERR_print_errors(arg);
  ret = 0;
  }
else
  BIO_printf(arg, "Response verify OK\n");

cert_stack_free(sk);
return ret;
}
# endif	/*DISABLE_OCSP*/


/*************************************************
*         Start an OpenSSL TLS session           *
*************************************************/

int
tls_start(int sock, SSL **ssl, SSL_CTX *ctx)
{
int rc;
static const unsigned char *sid_ctx = US"exim";

RAND_load_file("client.c", -1);   /* Not *very* random! */

*ssl = SSL_new (ctx);
SSL_set_session_id_context(*ssl, sid_ctx, strlen(CS sid_ctx));
SSL_set_fd (*ssl, sock);
SSL_set_connect_state(*ssl);

#ifndef DISABLE_OCSP
if (ocsp_stapling)
  {
  SSL_CTX_set_tlsext_status_cb(ctx, tls_client_stapling_cb);
  SSL_CTX_set_tlsext_status_arg(ctx, BIO_new_fp(stdout, BIO_NOCLOSE));
  SSL_set_tlsext_status_type(*ssl, TLSEXT_STATUSTYPE_ocsp);
  }
#endif

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
exit(98);
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
gnutls_datum_t m;
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
  exit(97);
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

/* set the CA info for server-cert verify */
if (ocsp_stapling)
  gnutls_certificate_set_x509_trust_file(x509_cred, ocsp_stapling,
       	GNUTLS_X509_FMT_PEM);
}



/*************************************************
*        Initialize a single GNUTLS session      *
*************************************************/

static gnutls_session_t
tls_session_init(void)
{
gnutls_session_t session;

gnutls_init(&session, GNUTLS_CLIENT | GNUTLS_NO_EXTENSIONS);

# if GNUTLS_VERSION_NUMBER < 0x030400
gnutls_cipher_set_priority(session, default_cipher_priority);
gnutls_compression_set_priority(session, comp_priority);
gnutls_kx_set_priority(session, kx_priority);
gnutls_protocol_set_priority(session, protocol_priority);
gnutls_mac_set_priority(session, mac_priority);

gnutls_cred_set(session, GNUTLS_CRD_CERTIFICATE, x509_cred);
# else
if (pri_string)
  {
  gnutls_priority_t priority_cache;
  const char * errpos;

  gnutls_priority_init(&priority_cache, pri_string, &errpos);
  gnutls_priority_set(session, priority_cache);
  }
else
  gnutls_set_default_priority(session);
gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, x509_cred);
# endif

gnutls_dh_set_prime_bits(session, DH_BITS);
gnutls_db_set_cache_expiration(session, ssl_session_timeout);

return session;
}
#endif


/****************************************************************************/
/* Turn "\n" and "\r" into the relevant characters. This is a hack. */

static int
unescape_buf(unsigned char * buf, int len)
{
unsigned char * s;
unsigned char c, t;
unsigned shift;

for (s = buf; s < buf+len; s++) if (*s == '\\')
  {
  switch (s[1])
    {
    default:	c = s[1]; shift = 1; break;
    case 'n':	c = '\n'; shift = 1; break;
    case 'r':	c = '\r'; shift = 1; break;
    case 'x':
		t = s[2];
    		if (t >= 'A' && t <= 'F') t -= 'A'-'9'-1;
		else if (t >= 'a' && t <= 'f') t -= 'a'-'9'-1;
		t -= '0';
		c = (t<<4) & 0xf0;
		t = s[3];
    		if (t >= 'A' && t <= 'F') t -= 'A'-'9'-1;
		else if (t >= 'a' && t <= 'f') t -= 'a'-'9'-1;
		t -= '0';
		c |= t & 0xf;
		shift = 3;
		break;
    }
  *s = c;
  memmove(s+1, s+shift+1, len-shift);
  len -= shift;
  }
return len;
}


/****************************************************************************/
typedef struct {
  int	sock;
  int	tls_active;
#ifdef HAVE_OPENSSL
  SSL_CTX * ctx;
  SSL * ssl;
#endif
  int	sent_starttls;
} srv_ctx;

static void
do_file(srv_ctx * srv, FILE * f, int timeout,
  unsigned char * inbuffer, unsigned bsiz, unsigned char * inptr)
{
unsigned char outbuffer[1024 * 20];

while (fgets(CS outbuffer, sizeof(outbuffer), f) != NULL)
  {
  int n = (int)strlen(CS outbuffer);
  int crlf = 1;
  int rc;

  /* Strip trailing newline */
  if (outbuffer[n-1] == '\n') outbuffer[--n] = 0;

  /* Expect incoming */

  if (  strncmp(CS outbuffer, "???", 3) == 0
     && (outbuffer[3] == ' ' || outbuffer[3] == '*')
     )
    {
    unsigned char *lineptr;
    unsigned exp_eof = outbuffer[3] == '*';

    printf("%s\n", outbuffer);
    n = unescape_buf(outbuffer, n);

    if (*inptr == 0)   /* Refill input buffer */
      {
      if (srv->tls_active)
        {
        #ifdef HAVE_OPENSSL
        rc = SSL_read (srv->ssl, inbuffer, bsiz - 1);
        #endif
        #ifdef HAVE_GNUTLS
        rc = gnutls_record_recv(tls_session, CS inbuffer, bsiz - 1);
        #endif
        }
      else
        {
        alarm(timeout);
        rc = read(srv->sock, inbuffer, bsiz);
        alarm(0);
        }

      if (rc < 0)
	{
        printf("Read error %s\n", strerror(errno));
        exit(81);
	}
      else if (rc == 0)
	if (exp_eof)
	  {
          printf("Expected EOF read\n");
	  continue;
	  }
	else
	  {
	  printf("Unexpected EOF read\n");
	  close(srv->sock);
	  exit(80);
	  }
      else if (exp_eof)
        {
        printf("Expected EOF not read\n");
        close(srv->sock);
        exit(74);
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
    if (strncmp(CS lineptr, CS outbuffer + 4, n - 4) != 0)
      {
      printf("\n******** Input mismatch ********\n");
      exit(79);
      }

    #ifdef HAVE_TLS
    if (srv->sent_starttls)
      {
      if (lineptr[0] == '2')
        {
int rc;
	unsigned int verify;

        printf("Attempting to start TLS\n");
        fflush(stdout);

        #ifdef HAVE_OPENSSL
        srv->tls_active = tls_start(srv->sock, &srv->ssl, srv->ctx);
        #endif

        #ifdef HAVE_GNUTLS
	  {
	  int rc;
	  sigalrm_seen = FALSE;
	  alarm(timeout);
	  do {
	    rc = gnutls_handshake(tls_session);
	  } while (rc < 0 && gnutls_error_is_fatal(rc) == 0);
	  srv->tls_active = rc >= 0;
	  alarm(0);

	  if (!srv->tls_active) printf("%s\n", gnutls_strerror(rc));
	  }
        #endif

        if (!srv->tls_active)
          {
          printf("Failed to start TLS\n");
          fflush(stdout);
          }
	#ifdef HAVE_GNUTLS
	else if (ocsp_stapling)
	  {
	  if ((rc= gnutls_certificate_verify_peers2(tls_session, &verify)) < 0)
	    {
	    printf("Failed to verify certificate: %s\n", gnutls_strerror(rc));
	    fflush(stdout);
	    }
	  else if (verify & (GNUTLS_CERT_INVALID|GNUTLS_CERT_REVOKED))
	    {
	    printf("Bad certificate\n");
	    fflush(stdout);
	    }
	  #ifdef HAVE_OCSP
	  else if (gnutls_ocsp_status_request_is_checked(tls_session, 0) == 0)
	    {
	    printf("Failed to verify certificate status\n");
	      {
	      gnutls_datum_t stapling;
	      gnutls_ocsp_resp_t resp;
	      gnutls_datum_t printed;
	      if (  (rc= gnutls_ocsp_status_request_get(tls_session, &stapling)) == 0
		 && (rc= gnutls_ocsp_resp_init(&resp)) == 0
		 && (rc= gnutls_ocsp_resp_import(resp, &stapling)) == 0
		 && (rc= gnutls_ocsp_resp_print(resp, GNUTLS_OCSP_PRINT_FULL, &printed)) == 0
		 )
		{
		fprintf(stderr, "%.4096s", printed.data);
		gnutls_free(printed.data);
		}
	      else
		(void) fprintf(stderr,"ocsp decode: %s", gnutls_strerror(rc));
	      }
	    fflush(stdout);
	    }
	  #endif
	  }
	#endif
        else
          printf("Succeeded in starting TLS\n");
        }
      else printf("Abandoning TLS start attempt\n");
      }
    srv->sent_starttls = 0;
    #endif
    }

  /* Wait for a bit before proceeding */

  else if (strncmp(CS outbuffer, "+++ ", 4) == 0)
    {
    printf("%s\n", outbuffer);
    sleep(atoi(CS outbuffer + 4));
    }

  /* Stack new input file */

  else if (strncmp(CS outbuffer, "<<< ", 4) == 0)
    {
    FILE * new_f;
    if (!(new_f = fopen((const char *)outbuffer+4 , "r")))
      {
      printf("Unable to open '%s': %s", inptr, strerror(errno));
      exit(74);
      }
    do_file(srv, new_f, timeout, inbuffer, bsiz, inptr);
    }


  /* Send line outgoing, but barf if unconsumed incoming */

  else
    {
    unsigned char * out = outbuffer;

    if (strncmp(CS outbuffer, ">>> ", 4) == 0)
      {
      crlf = 0;
      out += 4;
      n -= 4;
      }

    if (*inptr != 0)
      {
      printf("Unconsumed input: %s", inptr);
      printf("   About to send: %s\n", out);
      exit(78);
      }

    #ifdef HAVE_TLS

    /* Shutdown TLS */

    if (strcmp(CS out, "stoptls") == 0 ||
        strcmp(CS out, "STOPTLS") == 0)
      {
      if (!srv->tls_active)
        {
        printf("STOPTLS read when TLS not active\n");
        exit(77);
        }
      printf("Shutting down TLS encryption\n");

      #ifdef HAVE_OPENSSL
      SSL_shutdown(srv->ssl);
      SSL_free(srv->ssl);
      #endif

      #ifdef HAVE_GNUTLS
      gnutls_bye(tls_session, GNUTLS_SHUT_WR);
      gnutls_deinit(tls_session);
      tls_session = NULL;
      gnutls_global_deinit();
      #endif

      srv->tls_active = 0;
      continue;
      }

    /* Remember that we sent STARTTLS */

    srv->sent_starttls = (strcmp(CS out, "starttls") == 0 ||
                     strcmp(CS out, "STARTTLS") == 0);

    /* Fudge: if the command is "starttls_wait", we send the starttls bit,
    but we haven't set the flag, so that there is no negotiation. This is for
    testing the server's timeout. */

    if (strcmp(CS out, "starttls_wait") == 0)
      {
      out[8] = 0;
      n = 8;
      }
    #endif

    printf(">>> %s\n", out);
    if (crlf)
      {
      strcpy(CS out + n, "\r\n");
      n += 2;
      }

    n = unescape_buf(out, n);

    /* OK, do it */

    alarm(timeout);
    if (srv->tls_active)
      {
      #ifdef HAVE_OPENSSL
        rc = SSL_write (srv->ssl, out, n);
      #endif
      #ifdef HAVE_GNUTLS
        if ((rc = gnutls_record_send(tls_session, CS out, n)) < 0)
          {
          printf("GnuTLS write error: %s\n", gnutls_strerror(rc));
          exit(76);
          }
      #endif
      }
    else
      rc = write(srv->sock, out, n);
    alarm(0);

    if (rc < 0)
      {
      printf("Write error: %s\n", strerror(errno));
      exit(75);
      }
    }
  }
}




/*************************************************
*                 Main Program                   *
*************************************************/

const char * const HELP_MESSAGE = "\n\
Usage: client\n"
#ifdef HAVE_TLS
"\
          [-tls-on-connect]\n\
          [-ocsp]\n"
# ifdef HAVE_GNUTLS
"\
          [-p priority-string]\n"
# endif
#endif
"\
          [-tn] n seconds timeout\n\
          <IP address>\n\
          <port>\n\
          [<outgoing interface>]\n\
          [<cert file>]\n\
          [<key file>]\n\
\n";

int
main(int argc, char **argv)
{
struct sockaddr *s_ptr;
struct sockaddr_in s_in4;
char *interface = NULL;
char *address = NULL;
char *certfile = NULL;
char *keyfile = NULL;
char *end = NULL;
int argi = 1;
int host_af, port, s_len, rc, save_errno;
int timeout = 5;
int tls_on_connect = 0;
long tmplong;

#if HAVE_IPV6
struct sockaddr_in6 s_in6;
#endif

srv_ctx srv;

unsigned char inbuffer[10240];
unsigned char *inptr = inbuffer;

*inptr = 0;   /* Buffer empty */
srv.tls_active = 0;
srv.sent_starttls = 0;

/* Options */

while (argc >= argi + 1 && argv[argi][0] == '-')
  {
  if (strcmp(argv[argi], "-help") == 0 ||
      strcmp(argv[argi], "--help") == 0 ||
      strcmp(argv[argi], "-h") == 0)
    {
    puts(HELP_MESSAGE);
    exit(0);
    }
  if (strcmp(argv[argi], "-tls-on-connect") == 0)
    {
    tls_on_connect = 1;
    argi++;
    }
#ifdef HAVE_TLS
  else if (strcmp(argv[argi], "-ocsp") == 0)
    {
    if (argc < ++argi + 1)
      {
      fprintf(stderr, "Missing required certificate file for ocsp option\n");
      exit(96);
      }
    ocsp_stapling = argv[argi++];
    }
# ifdef HAVE_GNUTLS
  else if (strcmp(argv[argi], "-p") == 0)
    {
    if (argc < ++argi + 1)
      {
      fprintf(stderr, "Missing priority string\n");
      exit(96);
      }
    pri_string = argv[argi++];
    }
#endif

#endif
  else if (argv[argi][1] == 't' && isdigit(argv[argi][2]))
    {
    tmplong = strtol(argv[argi]+2, &end, 10);
    if (end == argv[argi]+2 || *end)
      {
      fprintf(stderr, "Failed to parse seconds from option <%s>\n",
        argv[argi]);
      exit(95);
      }
    if (tmplong > 10000L)
      {
      fprintf(stderr, "Unreasonably long wait of %ld seconds requested\n",
        tmplong);
      exit(94);
      }
    if (tmplong < 0L)
      {
      fprintf(stderr, "Timeout must not be negative (%ld)\n", tmplong);
      exit(93);
      }
    timeout = (int) tmplong;
    argi++;
    }
  else
    {
    fprintf(stderr, "Unrecognized option %s\n", argv[argi]);
    exit(92);
    }
  }

/* Mandatory 1st arg is IP address */

if (argc < argi+1)
  {
  fprintf(stderr, "No IP address given\n");
  exit(91);
  }

address = argv[argi++];
host_af = (strchr(address, ':') != NULL)? AF_INET6 : AF_INET;

/* Mandatory 2nd arg is port */

if (argc < argi+1)
  {
  fprintf(stderr, "No port number given\n");
  exit(90);
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

srv.sock = socket(host_af, SOCK_STREAM, 0);
if (srv.sock < 0)
  {
  printf("socket creation failed: %s\n", strerror(errno));
  exit(89);
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
        exit(88);
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

    if (bind(srv.sock, s_ptr, s_len) < 0)
      {
      printf("Unable to bind outgoing SMTP call to %s: %s",
        interface, strerror(errno));
      exit(87);
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
    exit(86);
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
rc = connect(srv.sock, s_ptr, s_len);
save_errno = errno;
alarm(0);

/* A failure whose error code is "Interrupted system call" is in fact
an externally applied timeout if the signal handler has been run. */

if (rc < 0)
  {
  close(srv.sock);
  printf("connect failed: %s\n", strerror(save_errno));
  exit(85);
  }

printf("connected\n");


/* --------------- Set up for OpenSSL --------------- */

#ifdef HAVE_OPENSSL
SSL_library_init();
SSL_load_error_strings();

if (!(srv.ctx = SSL_CTX_new(SSLv23_method())))
  {
  printf ("SSL_CTX_new failed\n");
  exit(84);
  }

if (certfile)
  {
  if (!SSL_CTX_use_certificate_file(srv.ctx, certfile, SSL_FILETYPE_PEM))
    {
    printf("SSL_CTX_use_certificate_file failed\n");
    exit(83);
    }
  printf("Certificate file = %s\n", certfile);
  }

if (keyfile)
  {
  if (!SSL_CTX_use_PrivateKey_file(srv.ctx, keyfile, SSL_FILETYPE_PEM))
    {
    printf("SSL_CTX_use_PrivateKey_file failed\n");
    exit(82);
    }
  printf("Key file = %s\n", keyfile);
  }

SSL_CTX_set_session_cache_mode(srv.ctx, SSL_SESS_CACHE_BOTH);
SSL_CTX_set_timeout(srv.ctx, 200);
SSL_CTX_set_info_callback(srv.ctx, (void (*)())info_callback);
#endif


/* --------------- Set up for GnuTLS --------------- */

#ifdef HAVE_GNUTLS
if (certfile != NULL) printf("Certificate file = %s\n", certfile);
if (keyfile != NULL) printf("Key file = %s\n", keyfile);
tls_init(certfile, keyfile);
tls_session = tls_session_init();
#ifdef HAVE_OCSP
if (ocsp_stapling)
  gnutls_ocsp_status_request_enable_client(tls_session, NULL, 0, NULL);
#endif
gnutls_transport_set_ptr(tls_session, (gnutls_transport_ptr_t)(intptr_t)srv.sock);

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
  srv.tls_active = tls_start(srv.sock, &srv.ssl, srv.ctx);
#endif

#ifdef HAVE_GNUTLS
  {
  int rc;
  sigalrm_seen = FALSE;
  alarm(timeout);
  do {
    rc = gnutls_handshake(tls_session);
  } while (rc < 0 && gnutls_error_is_fatal(rc) == 0);
  srv.tls_active = rc >= 0;
  alarm(0);

  if (!srv.tls_active) printf("%s\n", gnutls_strerror(rc));
  }
#endif

  if (!srv.tls_active)
    printf("Failed to start TLS\n");
#if defined(HAVE_GNUTLS) && defined(HAVE_OCSP)
  else if (  ocsp_stapling
	  && gnutls_ocsp_status_request_is_checked(tls_session, 0) == 0)
    printf("Failed to verify certificate status\n");
#endif
  else
    printf("Succeeded in starting TLS\n");
  }
#endif

do_file(&srv, stdin, timeout, inbuffer, sizeof(inbuffer), inptr);

printf("End of script\n");
shutdown(srv.sock, SHUT_WR);
while (read(srv.sock, inbuffer, sizeof(inbuffer)) > 0) ;
close(srv.sock);

exit(0);
}

/* End of client.c */
