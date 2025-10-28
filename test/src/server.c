/* A little hacked up program that listens on a given port and allows a script
to play the part of a remote MTA for testing purposes. This scripted version is
hacked from my original interactive version. A further hack allows it to listen
on a Unix domain socket as an alternative to a TCP/IP port.

In an IPv6 world, listening happens on both an IPv6 and an IPv4 socket, always
on all interfaces, unless the option -noipv6 is given. */

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
#include <sys/param.h>

#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#ifdef HAVE_NETINET_IP_VAR_H
# include <netinet/ip_var.h>
#endif

#include <netdb.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <utime.h>

#ifdef AF_INET6
# define HAVE_IPV6 1
#endif

#if !defined(__SunOS_5_10) && !defined(__SunOS_5_11) && !defined(OpenBSD)
# define HAVE_FOPENCOOKIE

/* TLS support can be optionally included, either for OpenSSL or GnuTLS. The
latter needs a whole pile of tables.  However, due to the existing use of
stdio-buffering on the socket, the easiest way to add TLS support was
to use fopencookie() to layer stdio on top of the TLS library interface.
This API does not appear to be available in Solaris or OpenSBD. */

# ifdef HAVE_OPENSSL_CRYPTO_H		/* from "configure" */
#  define HAVE_OPENSSL
#  include <openssl/crypto.h>
#  include <openssl/x509.h>
#  include <openssl/pem.h>
#  include <openssl/ssl.h>
#  include <openssl/err.h>
#  include <openssl/rand.h>

#  if OPENSSL_VERSION_NUMBER < 0x0090806fL && !defined(DISABLE_OCSP) && !defined(OPENSSL_NO_TLSEXT)
#   warning "OpenSSL library version too old; define DISABLE_OCSP in Makefile"
#   define DISABLE_OCSP
#  endif
#  ifndef DISABLE_OCSP
#   include <openssl/ocsp.h>
#  endif

# else					/* use only one of them */

#  ifdef HAVE_GNUTLS_GNUTLS_H		/* from "configure" */
#   define HAVE_GNUTLS
#   include <gnutls/gnutls.h>
#   include <gnutls/x509.h>
#   if GNUTLS_VERSION_NUMBER >= 0x030103
#    define HAVE_GNUTLS_OCSP
#    include <gnutls/ocsp.h>
#   endif
#   ifndef GNUTLS_NO_EXTENSIONS
#    define GNUTLS_NO_EXTENSIONS 0
#   endif

#   define DH_BITS      768

#  endif	/*HAVE_GNUTLS*/
# endif		/*HAVE_OPENSSL*/
#endif		/*HAVE_FOPENCOOKIE*/



#ifndef S_ADDR_TYPE
# define S_ADDR_TYPE u_long
#endif

#ifndef CS
# define CS (char *)
# define CCS (const char *)
#endif


typedef struct line {
  struct line *next;
  unsigned len;
  char line[1];
} line;

typedef unsigned BOOL;
#define FALSE 0
#define TRUE  1

int debug = 0;
int accept_socket, dup_accept_socket;
FILE *in, *out;


/*************************************************
*            SIGALRM handler - crash out         *
*************************************************/
int tmo_noerror = 0;

static void
sigalrm_handler(int sig)
{
sig = sig;    /* Keep picky compilers happy */
printf("\nServer timed out\n");
exit(tmo_noerror ? 0 : 99);
}


/*************************************************
*          Get textual IP address                *
*************************************************/

/* This function is copied from Exim */

char *
host_ntoa(const void *arg, char *buffer)
{
char *yield;

/* The new world. It is annoying that we have to fish out the address from
different places in the block, depending on what kind of address it is. It
is also a pain that inet_ntop() returns a const char *, whereas the IPv4
function inet_ntoa() returns just char *, and some picky compilers insist
on warning if one assigns a const char * to a char *. Hence the casts. */

#if HAVE_IPV6
char addr_buffer[46];
int family = ((struct sockaddr *)arg)->sa_family;
if (family == AF_INET6)
  {
  struct sockaddr_in6 *sk = (struct sockaddr_in6 *)arg;
  yield = (char *)inet_ntop(family, &(sk->sin6_addr), addr_buffer,
    sizeof(addr_buffer));
  }
else
  {
  struct sockaddr_in *sk = (struct sockaddr_in *)arg;
  yield = (char *)inet_ntop(family, &(sk->sin_addr), addr_buffer,
    sizeof(addr_buffer));
  }

/* If the result is a mapped IPv4 address, show it in V4 format. */

if (strncmp(yield, "::ffff:", 7) == 0) yield += 7;

#else /* HAVE_IPV6 */

/* The old world */

yield = inet_ntoa(((struct sockaddr_in *)arg)->sin_addr);
#endif

strcpy(buffer, yield);
return buffer;
}



static void
printit(char * s, int n)
{
while(n--)
  {
  unsigned char c = *s++;
  if (c == '\\')
    printf("\\\\");
  else if (c >= ' ' && c <= '~')	/* assumes ascii */
    putchar(c);
  else
    printf("\\x%02x", c);
  }
putchar('\n');
}



#ifdef HAVE_FOPENCOOKIE
/*************************************************
*                 TLS startup                    *
*************************************************/

# ifdef HAVE_OPENSSL
ssize_t
tls_read(void * ssl, char * buf, size_t size)
{
int rc, error;

ERR_clear_error();
if ((rc = SSL_read(ssl, buf, (int)size)) > 0)
  return (ssize_t)rc;				/* data return */

error = SSL_get_error(ssl, rc);
if (error == SSL_ERROR_ZERO_RETURN		/* clean TLS close */
   || error == SSL_ERROR_SYSCALL && errno != 0)	/* err from syscall */
  return 0;					/* EOF return */

return -1;					/* error return */
}

ssize_t
tls_write(void * ssl, const char * buf, size_t size)
{
int rc = SSL_write(ssl, buf, (int)size);
return rc >= 0 ? rc : 0;
}

int
tls_close(void * cookie)
{
return shutdown(accept_socket, SHUT_WR) < 0 ? EOF : 0;
}

int
tls_start(int sock, char * certfile, char * keyfile)
{
int rc;
static const unsigned char *sid_ctx = "exim";
SSL_CTX * ctx;
SSL * ssl;
cookie_io_functions_t iofuncs = {
  .read = tls_read,
  .write = tls_write,
  .close = tls_close
  };

SSL_library_init();
SSL_load_error_strings();

if (!(ctx = SSL_CTX_new(SSLv23_method())))
  {
  printf("SSL_CTX_new failed\n");
  exit(84);
  }
if (!SSL_CTX_use_certificate_file(ctx, certfile, SSL_FILETYPE_PEM))
  {
  printf("SSL_CTX_use_certificate_file failed\n");
  exit(83);
  }
if (!SSL_CTX_use_PrivateKey_file(ctx, keyfile, SSL_FILETYPE_PEM))
  {
  printf("SSL_CTX_use_PrivateKey_file failed\n");
  exit(82);
  }
SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_BOTH);
SSL_CTX_set_timeout(ctx, 200);

RAND_load_file("server.c", -1);   /* Not *very* random! */

ssl = SSL_new(ctx);
SSL_set_session_id_context(ssl, sid_ctx, strlen(CS sid_ctx));
SSL_set_fd(ssl, sock);
SSL_set_accept_state(ssl);

rc = SSL_accept(ssl);		/* we are already running an alarm timer */
if (rc <= 0)
  {
  ERR_print_errors_fp(stdout);
  return 0;
  }

if (debug) printf("SSL connection using %s\n", SSL_get_cipher (ssl));

out = fopencookie(ssl, "w", iofuncs);	/* Replace stream */
iofuncs.close = NULL;
in =  fopencookie(ssl, "r", iofuncs);	/* Replace stream */
return 1;
}
# endif /*HAVE_OPENSSL*/

# ifdef HAVE_GNUTLS
/* For the test suite, the parameters should always be available in the spool
directory. */

static void
init_dh(gnutls_dh_params_t * dhp)
{
int fd;
int ret;
gnutls_datum_t m;
uschar filename[200];
struct stat statbuf;

/* Initialize the data structures for holding the parameters */

ret = gnutls_dh_params_init(dhp);
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

ret = gnutls_dh_params_import_pkcs3(*dhp, &m, GNUTLS_X509_FMT_PEM);
if (ret < 0) return gnutls_error(US"DH params import", ret);
free(m.data);
}


ssize_t
tls_read(void * cookie, char * buf, size_t size)
{
gnutls_session_t tls_session = cookie;
int rc = gnutls_record_recv(tls_session, buf, size);
return rc >= 0 ? rc : -1;
}

ssize_t
tls_write(void * cookie, const char * buf, size_t size)
{
gnutls_session_t tls_session = cookie;
int rc = gnutls_record_send(tls_session, buf, (int)size);
return rc >= 0 ? rc : 0;
}

int
tls_close(void * cookie)
{
return shutdown(accept_socket, SHUT_WR) < 0 ? EOF : 0;
}

int
tls_start(int sock, char * certfile, char * keyfile)
{
static gnutls_dh_params_t dh_params = NULL;
gnutls_certificate_credentials_t x509_cred = NULL;
gnutls_session_t tls_session = NULL;
cookie_io_functions_t iofuncs = {
  .read = tls_read,
  .write = tls_write,
  .close = tls_close
  };
int rc;

rc = gnutls_global_init();
if (rc < 0) gnutls_error(US"gnutls_global_init", rc);

/* Read D-H parameters from the cache file. */
init_dh(&dh_params);

/* Create the credentials structure */

rc = gnutls_certificate_allocate_credentials(&x509_cred);
if (rc < 0) gnutls_error(US"certificate_allocate_credentials", rc);

/* Set the certificate and private keys */
rc = gnutls_certificate_set_x509_key_file(x509_cred, CS certificate,
  CS privatekey, GNUTLS_X509_FMT_PEM);
if (rc < 0) gnutls_error(US"gnutls_certificate", rc);

/* Associate the parameters with the x509 credentials structure. */
gnutls_certificate_set_dh_params(x509_cred, dh_params);

tls_session = tls_session_init();
gnutls_transport_set_ptr(tls_session, (gnutls_transport_ptr_t)(intptr_t)sock);

do {
  rc = gnutls_handshake(tls_session);
} while (rc < 0 && gnutls_error_is_fatal(rc) == 0);

if (rc >= 0)
  {
  out = fopencookie(tls_session, "w", iofuncs);	/* Replace stream */
  iofuncs.close = NULL;
  in =  fopencookie(tls_session, "r", iofuncs);	/* Replace stream */
  return 1;
  }
return 0;
}
# endif /*HAVE_GNUTLS*/


/******************************************************************************/
# ifdef HAVE_OPENSSL
# endif
int tls_active = 0;

#endif	/*HAVE_FOPENCOOKIE*/


/*************************************************
*                 Main Program                   *
*************************************************/

#define v6n 0    /* IPv6 socket number */
#define v4n 1    /* IPv4 socket number */
#define udn 2    /* Unix domain socket number */
#define skn 2    /* Potential number of sockets */

int
main(int argc, char **argv)
{
int i;
int port = 0;
int listen_socket[3] = { -1, -1, -1 };
int connection_count = 1;
int count;
int on = 1;
int timeout = 5;
int initial_pause = 0, tfo = 0;
int use_ipv4 = 1;
int use_ipv6 = 1;
int na = 1;
line *script = NULL;
line *last = NULL;
line *s;
int linebuf = 1;
char *pidfile = NULL;
char *certfile = NULL, *keyfile = NULL;

char *sockname = NULL;
unsigned char buffer[10240];

struct sockaddr_un sockun;            /* don't use "sun" */
struct sockaddr_un sockun_accepted;
int sockun_len = sizeof(sockun_accepted);

#if HAVE_IPV6
struct sockaddr_in6 sin6;
struct sockaddr_in6 accepted;
struct in6_addr anyaddr6 =  IN6ADDR_ANY_INIT ;
#else
struct sockaddr_in accepted;
#endif

/* Always need an IPv4 structure */

struct sockaddr_in sin4;

int len = sizeof(accepted);


/* Sort out the arguments */
if (argc > 1 && (!strcmp(argv[1], "--help") || !strcmp(argv[1], "-h")))
  {
  printf("Usage: %s [options] port|socket [connection count]\n", argv[0]);
  puts("Options"
       "\n\t-d       debug"
       "\n\t-i n     n seconds initial delay"
       "\n\t-noipv4  disable ipv4"
       "\n\t-noipv6  disable ipv6"
       "\n\t-oP file write PID to file"
       "\n\t-t n     n seconds timeout"
       "\n\t-tfo     enable TCP Fast Open"
#ifdef HAVE_FOPENCOOKIE
       "\n\t-tls certfile keyfile	files for TLS"
#endif
      );
#ifndef HAVE_FOPENCOOKIE
  puts("The -tls option is not supported on this platform\n");
#endif
  exit(0);
  }

while (na < argc && argv[na][0] == '-')
  {
  if (strcmp(argv[na], "-d") == 0)
    { debug = 1; setvbuf(stdout, NULL, _IONBF, 0); }
  else if (strcmp(argv[na], "-tfo") == 0) tfo = 1;
#ifdef HAVE_FOPENCOOKIE
  else if (strcmp(argv[na], "-tls") == 0)
    { certfile = argv[++na]; keyfile = argv[++na]; }
#endif
  else if (strcmp(argv[na], "-t") == 0)
    {
    if ((tmo_noerror = ((timeout = atoi(argv[++na])) < 0))) timeout = -timeout;
    }
  else if (strcmp(argv[na], "-i") == 0) initial_pause = atoi(argv[++na]);
  else if (strcmp(argv[na], "-noipv4") == 0) use_ipv4 = 0;
  else if (strcmp(argv[na], "-noipv6") == 0) use_ipv6 = 0;
  else if (strcmp(argv[na], "-oP") == 0) pidfile = argv[++na];
  else
    {
    printf("server: unknown option %s, try -h or --help\n", argv[na]);
    exit(1);
    }
  na++;
  }

if (!use_ipv4 && !use_ipv6)
  {
  printf("server: -noipv4 and -noipv6 cannot both be given\n");
  exit(1);
  }

if (na >= argc)
  {
  printf("server: no port number or socket name given\n");
  exit(1);
  }

if (argv[na][0] == '/')
  {
  sockname = argv[na];
  unlink(sockname);       /* in case left lying around */
  }
else port = atoi(argv[na]);
na++;

if (na < argc) connection_count = atoi(argv[na]);


/* Initial pause (before creating listen sockets */
if (initial_pause > 0)
  {
  if (debug)
    printf("%ld: Inital pause of %d seconds\n", (long)time(NULL), initial_pause);
  else
    printf("Inital pause of %d seconds\n", initial_pause);
  while (initial_pause > 0)
    initial_pause = sleep(initial_pause);
  }

/* Create sockets */

if (port == 0)  /* Unix domain */
  {
  if (debug) printf("%ld: Creating Unix domain socket\n", (long) time(NULL));
  listen_socket[udn] = socket(PF_UNIX, SOCK_STREAM, 0);
  if (listen_socket[udn] < 0)
    {
    printf("Unix domain socket creation failed: %s\n", strerror(errno));
    exit(1);
    }
  }
else
  {
  #if HAVE_IPV6
  if (use_ipv6)
    {
    if (debug) printf("Creating IPv6 socket\n");
    listen_socket[v6n] = socket(AF_INET6, SOCK_STREAM, 0);
    if (listen_socket[v6n] < 0)
      {
      printf("IPv6 socket creation failed: %s\n", strerror(errno));
      exit(1);
      }
#if defined(TCP_FASTOPEN) && !defined(__APPLE__)
    if (tfo)
      {
      int backlog = 5;
      if (setsockopt(listen_socket[v6n], IPPROTO_TCP, TCP_FASTOPEN,
                    &backlog, sizeof(backlog)))
	if (debug) printf("setsockopt TCP_FASTOPEN: %s\n", strerror(errno));
      }
#endif
    /* If this is an IPv6 wildcard socket, set IPV6_V6ONLY if that option is
    available. */

    #ifdef IPV6_V6ONLY
    if (setsockopt(listen_socket[v6n], IPPROTO_IPV6, IPV6_V6ONLY, (char *)(&on),
          sizeof(on)) < 0)
      printf("Setting IPV6_V6ONLY on IPv6 wildcard "
        "socket failed (%s): carrying on without it\n", strerror(errno));
    #endif  /* IPV6_V6ONLY */
    }
  #endif  /* HAVE_IPV6 */

  /* Create an IPv4 socket if required */

  if (use_ipv4)
    {
    if (debug) printf("Creating IPv4 socket\n");
    listen_socket[v4n] = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_socket[v4n] < 0)
      {
      printf("IPv4 socket creation failed: %s\n", strerror(errno));
      exit(1);
      }
#if defined(TCP_FASTOPEN) && !defined(__APPLE__)
    if (tfo)
      {
      int backlog = 5;
      if (setsockopt(listen_socket[v4n], IPPROTO_TCP, TCP_FASTOPEN,
                    &backlog, sizeof(backlog)))
	if (debug) printf("setsockopt TCP_FASTOPEN: %s\n", strerror(errno));
      }
#endif
    }
  }


/* Set SO_REUSEADDR on the IP sockets so that the program can be restarted
while a connection is being handled - this can happen as old connections lie
around for a bit while crashed processes are tidied away.  Without this, a
connection will prevent reuse of the smtp port for listening. */

for (i = v6n; i <= v4n; i++)
  {
  if (listen_socket[i] >= 0 &&
      setsockopt(listen_socket[i], SOL_SOCKET, SO_REUSEADDR, (char *)(&on),
        sizeof(on)) < 0)
    {
    printf("setting SO_REUSEADDR on socket failed: %s\n", strerror(errno));
    exit(1);
    }
  }


/* Now bind the sockets to the required port or path. If a path, ensure
anyone can write to it. */

if (port == 0)
  {
  struct stat statbuf;
  sockun.sun_family = AF_UNIX;
  if (debug) printf("Binding Unix domain socket\n");
  sprintf(sockun.sun_path, "%.*s", (int)(sizeof(sockun.sun_path)-1), sockname);
  if (bind(listen_socket[udn], (struct sockaddr *)&sockun, sizeof(sockun)) < 0)
    {
    printf("Unix domain socket bind() failed: %s\n", strerror(errno));
    exit(1);
    }
  (void)stat(sockname, &statbuf);
  if (debug) printf("Setting Unix domain socket mode: %0x\n",
    statbuf.st_mode | 0777);
  if (chmod(sockname, statbuf.st_mode | 0777) < 0)
    {
    printf("Unix domain socket chmod() failed: %s\n", strerror(errno));
    exit(1);
    }
  }

else
  {
  for (i = 0; i < skn; i++)
    {
    if (listen_socket[i] < 0) continue;

    /* For an IPv6 listen, use an IPv6 socket */

    #if HAVE_IPV6
    if (i == v6n)
      {
      memset(&sin6, 0, sizeof(sin6));
      sin6.sin6_family = AF_INET6;
      sin6.sin6_port = htons(port);
      sin6.sin6_addr = anyaddr6;
      if (bind(listen_socket[i], (struct sockaddr *)&sin6, sizeof(sin6)) < 0)
        {
        printf("IPv6 socket bind(port %d) failed: %s\n", port, strerror(errno));
        exit(1);
        }
      }
    else
    #endif

    /* For an IPv4 bind, use an IPv4 socket, even in an IPv6 world. If an IPv4
    bind fails EADDRINUSE after IPv6 success, carry on, because it means the
    IPv6 socket will handle IPv4 connections. */

      {
      memset(&sin4, 0, sizeof(sin4));
      sin4.sin_family = AF_INET;
      sin4.sin_addr.s_addr = (S_ADDR_TYPE)INADDR_ANY;
      sin4.sin_port = htons(port);
      if (bind(listen_socket[i], (struct sockaddr *)&sin4, sizeof(sin4)) < 0)
        if (listen_socket[v6n] < 0 || errno != EADDRINUSE)
          {
          printf("IPv4 socket bind(port %d) failed: %s\n", port, strerror(errno));
          exit(1);
          }
        else
          {
          close(listen_socket[i]);
          listen_socket[i] = -1;
          }
      }
    }
  }


/* Start listening. If IPv4 fails EADDRINUSE after IPv6 succeeds, ignore the
error because it means that the IPv6 socket will handle IPv4 connections. Don't
output anything, because it will mess up the test output, which will be
different for systems that do this and those that don't. */

for (i = 0; i <= skn; i++) if (listen_socket[i] >= 0)
  {
  if (listen(listen_socket[i], 5) < 0)
    if (i != v4n || listen_socket[v6n] < 0 || errno != EADDRINUSE)
      {
      printf("listen() failed: %s\n", strerror(errno));
      exit(1);
      }

#if defined(TCP_FASTOPEN) && defined(__APPLE__)
  if (  tfo
     && setsockopt(listen_socket[v4n], IPPROTO_TCP, TCP_FASTOPEN, &on, sizeof(on))
     && debug)
      printf("setsockopt TCP_FASTOPEN: %s\n", strerror(errno));
#endif
  }


if (pidfile)
  {
  FILE * p;
  if (!(p = fopen(pidfile, "w")))
    {
    fprintf(stderr, "pidfile create failed: %s\n", strerror(errno));
    exit(1);
    }
  fprintf(p, "%ld\n", (long)getpid());
  fclose(p);
  }

/* This program handles only a fixed number of connections, in sequence. Before
waiting for the first connection, read the standard input, which contains the
script of things to do. A line containing "++++" is treated as end of file.
This is so that the Perl driving script doesn't have to close the pipe -
because that would cause it to wait for this process, which it doesn't yet want
to do. The driving script adds the "++++" automatically - it doesn't actually
appear in the test script. Within lines we interpret \xNN and \\ groups */

while (fgets(CS buffer, sizeof(buffer), stdin) != NULL)
  {
  line *next;
  char * d;
  int n = (int)strlen(CS buffer);

  if (n > 1 && buffer[0] == '>' && buffer[1] == '>')
    linebuf = 0;
  while (n > 0 && isspace(buffer[n-1])) n--;
  buffer[n] = 0;
  if (strcmp(CS buffer, "++++") == 0) break;
  next = malloc(sizeof(line) + n);
  next->next = NULL;
  d = next->line;
    {
    char * s = CS buffer;
    do
      {
      char ch;
      char cl = *s;
      if (cl == '\\' && (cl = *++s) == 'x')
	{
	if ((ch = *++s - '0') > 9 && (ch -= 'A'-'9'-1) > 15) ch -= 'a'-'A';
	if ((cl = *++s - '0') > 9 && (cl -= 'A'-'9'-1) > 15) cl -= 'a'-'A';
	cl |= ch << 4;
	}
      *d++ = cl;
      }
    while (*s++);
    }
  next->len = d - next->line - 1;
  if (last == NULL) script = last = next;
    else last->next = next;
  last = next;
  }

fclose(stdin);

/* SIGALRM handler crashes out */

signal(SIGALRM, sigalrm_handler);

/* s points to the current place in the script */

s = script;

for (count = 0; count < connection_count; count++)
  {
  struct {
    int left;
    BOOL in_use;
  } content_length = { 0, FALSE };

  alarm(timeout);
  if (port <= 0)
    {
    printf("Listening on %s ... ", sockname);
    fflush(stdout);
    accept_socket = accept(listen_socket[udn],
      (struct sockaddr *)&sockun_accepted, &sockun_len);
    }

  else
    {
    int lcount;
    int max_socket = 0;
    fd_set select_listen;

    printf("Listening on port %d ... ", port);
    fflush(stdout);

    FD_ZERO(&select_listen);
    for (i = 0; i < skn; i++)
      {
      if (listen_socket[i] >= 0) FD_SET(listen_socket[i], &select_listen);
      if (listen_socket[i] > max_socket) max_socket = listen_socket[i];
      }

    if ((lcount = select(max_socket + 1, &select_listen, NULL, NULL, NULL)) < 0)
      {
      printf("Select failed\n");
      fflush(stdout);
      continue;
      }

    accept_socket = -1;
    for (i = 0; i < skn; i++)
      if (listen_socket[i] > 0 && FD_ISSET(listen_socket[i], &select_listen))
        {
        accept_socket = accept(listen_socket[i],
          (struct sockaddr *)&accepted, &len);
        FD_CLR(listen_socket[i], &select_listen);
        break;
        }
    }
  alarm(0);

  if (accept_socket < 0)
    {
    printf("accept() failed: %s\n", strerror(errno));
    exit(1);
    }

  out = fdopen(accept_socket, "w");

  dup_accept_socket = dup(accept_socket);

  if (port > 0)
    printf("\nConnection request from [%s]\n", host_ntoa(&accepted, CS buffer));
  else
    {
    printf("\nConnection request\n");

    /* Linux supports a feature for acquiring the peer's credentials, but it
    appears to be Linux-specific. This code is untested and unused, just
    saved here for reference. */

    /**********--------------------
    struct ucred cr;
    int cl=sizeof(cr);

    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cr, &cl)==0) {
      printf("Peer's pid=%d, uid=%d, gid=%d\n",
              cr.pid, cr.uid, cr.gid);
    --------------*****************/
    }
  fflush(stdout);

  if (dup_accept_socket < 0)
    {
    printf("Couldn't dup socket descriptor\n");
    printf("421 Connection refused: %s\n", strerror(errno));
    fprintf(out, "421 Connection refused: %s\r\n", strerror(errno));
    fclose(out);
    exit(2);
    }

  in = fdopen(dup_accept_socket, "r");

  /* Loop for handling the conversation(s). For use in SMTP sessions, there are
  default rules for determining input and output lines: the latter start with
  digits. This means that the input looks like SMTP dialog. However, this
  doesn't work for other tests (e.g. ident tests) so we have explicit '<' and
  '>' flags for input and output as well as the defaults. */

  for (; s; s = s->next)
    {
    char *ss = s->line;

    /* Output lines either start with '>' or a digit. In the '>' case we can
    fudge the sending of \r\n as required. Default is \r\n, ">>" send nothing,
    ">CR>" sends \r only, and ">LF>" sends \n only. We can also force a
    connection closedown by ">*eof". */

    if (ss[0] == '>')
      {
      char *end = "\r\n";
      unsigned len = s->len;
      printit(ss++, len--);

      if (strncmp(ss, "*eof", 4) == 0)
        {
        s = s->next;
        goto END_OFF;
        }

      if (*ss == '>')
        { end = ""; ss++; len--; }
      else if (strncmp(ss, "CR>", 3) == 0)
        { end = "\r"; ss += 3; len -= 3; }
      else if (strncmp(ss, "LF>", 3) == 0)
        { end = "\n"; ss += 3; len -= 3; }

      fwrite(ss, 1, len, out);
      if (*end) fputs(end, out);
      }

    else if (isdigit((unsigned char)ss[0]))
      {
      printf("%s\n", ss);
      fprintf(out, "%s\r\n", ss);
      }

    /* If the script line starts with "*sleep" we just sleep for a while
    before continuing. */

    else if (strncmp(ss, "*sleep ", 7) == 0)
      {
      int sleepfor = atoi(ss+7);
      printf("%s\n", ss);
      fflush(out);
      sleep(sleepfor);
      }

    /* If the script line starts with "*data " we expect a numeric argument,
    and we expect to read (and discard) that many data bytes from the input. */

    else if (strncmp(ss, "*data ", 6) == 0)
      {
      int dlen = atoi(ss+6);
      int n;

      alarm(timeout);

      if (!linebuf)
	while (dlen > 0)
	  {
	  n = dlen < sizeof(buffer) ? dlen : sizeof(buffer);
	  if ((n = read(dup_accept_socket, CS buffer, n)) == 0)
	    {
	    printf("Unexpected EOF read from client\n");
	    s = s->next;
	    goto END_OFF;
	    }
	  dlen -= n;
	  }
      else
	while (dlen-- > 0)
	  if (fgetc(in) == EOF)
	    {
	    printf("Unexpected EOF read from client\n");
	    s = s->next;
	    goto END_OFF;
	    }
      }

#ifdef HAVE_FOPENCOOKIE
    /* If the script line starts with "*starttls" (presumably we either did
    a STARTTLS, 220 sequence or are doing tls-on-connect) we start TLS in
    accept mode, waiting for a TLS Client Hello.  */

    else if (strncmp(ss, "*starttls", 9) == 0)
      {
      fflush(out);
      alarm(timeout);
      tls_active = tls_start(accept_socket, certfile, keyfile);
      alarm(0);
      }
#endif


    /* Otherwise the script line is the start of an input line we are expecting
    from the client, or "*eof" indicating we expect the client to close the
    connection. Read command line or data lines; the latter are indicated
    by the expected line being just ".". If the line starts with '<', that
    doesn't form part of the expected input. (This allows for incoming data
    starting with a digit.) If the line starts with '<<' we operate in
    unbuffered rather than line mode and assume that a single read gets the
    entire message. */

    else
      {
      int offset;
      int data = strcmp(ss, ".") == 0;

      if (ss[0] != '<')
	offset = 0;
      else
        {
        buffer[0] = '<';
	if (ss[1] != '<')
	  offset = 1;
	else
	  {
	  buffer[1] = '<';
	  offset = 2;
	  }
        }

      fflush(out);

      if (!linebuf)
	{
	int n;
	char c;

	alarm(timeout);
	n = read(dup_accept_socket, CS buffer+offset, s->len - offset);
	if (content_length.in_use) content_length.left -= n;
	if (n == 0)
	  {
	  printf("%sxpected EOF read from client\n",
	    (strncmp(ss, "*eof", 4) == 0)? "E" : "Une");
	  s = s->next;
	  goto END_OFF;
	  }
	if (offset != 2)
	  while (read(dup_accept_socket, &c, 1) == 1 && c != '\n') ;
	alarm(0);
	n += offset;

	printit(CS buffer, n);

	if (data) do
	  {
	  n = (read(dup_accept_socket, &c, 1) == 1 && c == '.');
	  if (content_length.in_use) content_length.left--;
	  while (c != '\n' && read(dup_accept_socket, &c, 1) == 1)
            if (content_length.in_use) content_length.left--;
	  } while (!n);
	else if (memcmp(ss, buffer, n) != 0)
	  {
	  printf("Comparison failed - bailing out\nExpected: ");
	  printit(ss, n);
	  break;
	  }
	}
      else
	{
	for (;;)
	  {
	  int n;
	  alarm(timeout);
	  if (fgets(CS buffer+offset, sizeof(buffer)-offset, in) == NULL)
	    {
	    printf("%sxpected EOF read from client\n",
	      (strncmp(ss, "*eof", 4) == 0)? "E" : "Une");
	    s = s->next;
	    goto END_OFF;
	    }
	  alarm(0);
	  n = strlen(CS buffer);
	  if (content_length.in_use) content_length.left -= (n - offset);
	  while (n > 0 && isspace(buffer[n-1])) n--;
	  buffer[n] = 0;
	  printf("%s\n", buffer);
	  if (!data || strcmp(CS buffer, ".") == 0) break;
	  }

	if (strncmp(ss, CS buffer, (int)strlen(ss)) != 0)
	  {
	  printf("Comparison failed - bailing out\n");
	  printf("Expected: %s\n", ss);
	  break;
	  }
	}

	if (sscanf(CCS buffer, "<Content-length: %d", &content_length.left))
       	  content_length.in_use = TRUE;
	if (content_length.in_use && content_length.left <= 0)
	  shutdown(dup_accept_socket, SHUT_RD);
      }
    }

  END_OFF:
  fclose(in);
  fclose(out);
  }

if (s == NULL) printf("End of script\n");

if (sockname) unlink(sockname);
exit(0);
}

/* End of server.c */
