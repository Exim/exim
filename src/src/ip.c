/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2015 */
/* See the file NOTICE for conditions of use and distribution. */

/* Functions for doing things with sockets. With the advent of IPv6 this has
got messier, so that it's worth pulling out the code into separate functions
that other parts of Exim can call, expecially as there are now several
different places in the code where sockets are used. */


#include "exim.h"


/*************************************************
*             Create a socket                    *
*************************************************/

/* Socket creation happens in a number of places so it's packaged here for
convenience.

Arguments:
  type       SOCK_DGRAM or SOCK_STREAM
  af         AF_INET or AF_INET6

Returns:     socket number or -1 on failure
*/

int
ip_socket(int type, int af)
{
int sock = socket(af, type, 0);
if (sock < 0)
  log_write(0, LOG_MAIN, "IPv%c socket creation failed: %s",
    (af == AF_INET6)? '6':'4', strerror(errno));
return sock;
}




#if HAVE_IPV6
/*************************************************
*      Convert printing address to numeric       *
*************************************************/

/* This function converts the textual form of an IP address into a numeric form
in an appropriate structure in an IPv6 environment. The getaddrinfo() function
can (apparently) handle more complicated addresses (e.g. those containing
scopes) than inet_pton() in some environments. We use hints to tell it that the
input must be a numeric address.

However, apparently some operating systems (or libraries) don't support
getaddrinfo(), so there is a build-time option to revert to inet_pton() (which
does not support scopes).

Arguments:
  address     textual form of the address
  addr        where to copy back the answer

Returns:      nothing - failure provokes a panic-die
*/

static void
ip_addrinfo(const uschar *address, struct sockaddr_in6 *saddr)
{
#ifdef IPV6_USE_INET_PTON

  if (inet_pton(AF_INET6, CCS address, &saddr->sin6_addr) != 1)
    log_write(0, LOG_MAIN|LOG_PANIC_DIE, "unable to parse \"%s\" as an "
      "IP address", address);
  saddr->sin6_family = AF_INET6;

#else

  int rc;
  struct addrinfo hints, *res;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET6;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_NUMERICHOST;
  if ((rc = getaddrinfo(CCS address, NULL, &hints, &res)) != 0 || res == NULL)
    log_write(0, LOG_MAIN|LOG_PANIC_DIE, "unable to parse \"%s\" as an "
      "IP address: %s", address,
      (rc == 0)? "NULL result returned" : gai_strerror(rc));
  memcpy(saddr, res->ai_addr, res->ai_addrlen);
  freeaddrinfo(res);

#endif
}
#endif  /* HAVE_IPV6 */


/*************************************************
*         Bind socket to interface and port      *
*************************************************/

int
ip_addr(void * sin_, int af, const uschar * address, int port)
{
union sockaddr_46 * sin = sin_;
memset(sin, 0, sizeof(*sin));

/* Setup code when using an IPv6 socket. The wildcard address is ":", to
ensure an IPv6 socket is used. */

#if HAVE_IPV6
if (af == AF_INET6)
  {
  if (address[0] == ':' && address[1] == 0)
    {
    sin->v6.sin6_family = AF_INET6;
    sin->v6.sin6_addr = in6addr_any;
    }
  else
    ip_addrinfo(address, &sin->v6);  /* Panic-dies on error */
  sin->v6.sin6_port = htons(port);
  return sizeof(sin->v6);
  }
else
#else     /* HAVE_IPv6 */
af = af;  /* Avoid compiler warning */
#endif    /* HAVE_IPV6 */

/* Setup code when using IPv4 socket. The wildcard address is "". */

  {
  sin->v4.sin_family = AF_INET;
  sin->v4.sin_port = htons(port);
  sin->v4.sin_addr.s_addr = address[0] == 0
    ? (S_ADDR_TYPE)INADDR_ANY
    : (S_ADDR_TYPE)inet_addr(CS address);
  return sizeof(sin->v4);
  }
}



/* This function binds a socket to a local interface address and port. For a
wildcard IPv6 bind, the address is ":".

Arguments:
  sock           the socket
  af             AF_INET or AF_INET6 - the socket type
  address        the IP address, in text form
  port           the IP port (host order)

Returns:         the result of bind()
*/

int
ip_bind(int sock, int af, uschar *address, int port)
{
union sockaddr_46 sin;
int s_len = ip_addr(&sin, af, address, port);
return bind(sock, (struct sockaddr *)&sin, s_len);
}



/*************************************************
*        Connect socket to remote host           *
*************************************************/

/* This function connects a socket to a remote address and port. The socket may
or may not have previously been bound to a local interface. The socket is not
closed, even in cases of error. It is expected that the calling function, which
created the socket, will be the one that closes it.

Arguments:
  sock        the socket
  af          AF_INET6 or AF_INET for the socket type
  address     the remote address, in text form
  port        the remote port
  timeout     a timeout (zero for indefinite timeout)

Returns:      0 on success; -1 on failure, with errno set
*/

int
ip_connect(int sock, int af, const uschar *address, int port, int timeout)
{
struct sockaddr_in s_in4;
struct sockaddr *s_ptr;
int s_len, rc, save_errno;

/* For an IPv6 address, use an IPv6 sockaddr structure. */

#if HAVE_IPV6
struct sockaddr_in6 s_in6;
if (af == AF_INET6)
  {
  memset(&s_in6, 0, sizeof(s_in6));
  ip_addrinfo(address, &s_in6);   /* Panic-dies on error */
  s_in6.sin6_port = htons(port);
  s_ptr = (struct sockaddr *)&s_in6;
  s_len = sizeof(s_in6);
  }
else
#else     /* HAVE_IPV6 */
af = af;  /* Avoid compiler warning */
#endif    /* HAVE_IPV6 */

/* For an IPv4 address, use an IPv4 sockaddr structure, even on a system with
IPv6 support. */

  {
  memset(&s_in4, 0, sizeof(s_in4));
  s_in4.sin_family = AF_INET;
  s_in4.sin_port = htons(port);
  s_in4.sin_addr.s_addr = (S_ADDR_TYPE)inet_addr(CCS address);
  s_ptr = (struct sockaddr *)&s_in4;
  s_len = sizeof(s_in4);
  }

/* If no connection timeout is set, just call connect() without setting a
timer, thereby allowing the inbuilt OS timeout to operate. */

sigalrm_seen = FALSE;
if (timeout > 0) alarm(timeout);
rc = connect(sock, s_ptr, s_len);
save_errno = errno;
alarm(0);

/* There is a testing facility for simulating a connection timeout, as I
can't think of any other way of doing this. It converts a connection refused
into a timeout if the timeout is set to 999999. */

if (running_in_test_harness  && save_errno == ECONNREFUSED && timeout == 999999)
  {
  rc = -1;
  save_errno = EINTR;
  sigalrm_seen = TRUE;
  }

/* Success */

if (rc >= 0) return 0;

/* A failure whose error code is "Interrupted system call" is in fact
an externally applied timeout if the signal handler has been run. */

errno = save_errno == EINTR && sigalrm_seen ? ETIMEDOUT : save_errno;
return -1;
}



/*************************************************
*    Create connected socket to remote host      *
*************************************************/

/* Create a socket and connect to host (name or number, ipv6 ok)
   at one of port-range.

Arguments:
  type          SOCK_DGRAM or SOCK_STREAM
  af            AF_INET6 or AF_INET for the socket type
  address       the remote address, in text form
  portlo,porthi the remote port range
  timeout       a timeout
  connhost	if not NULL, host_item filled in with connection details
  errstr        pointer for allocated string on error

Return:
  socket fd, or -1 on failure (having allocated an error string)
*/
int
ip_connectedsocket(int type, const uschar * hostname, int portlo, int porthi,
	int timeout, host_item * connhost, uschar ** errstr)
{
int namelen, port;
host_item shost;
host_item *h;
int af = 0, fd, fd4 = -1, fd6 = -1;

shost.next = NULL;
shost.address = NULL;
shost.port = portlo;
shost.mx = -1;

namelen = Ustrlen(hostname);

/* Anything enclosed in [] must be an IP address. */

if (hostname[0] == '[' &&
    hostname[namelen - 1] == ']')
  {
  uschar * host = string_copy(hostname);
  host[namelen - 1] = 0;
  host++;
  if (string_is_ip_address(host, NULL) == 0)
    {
    *errstr = string_sprintf("malformed IP address \"%s\"", hostname);
    return -1;
    }
  shost.name = shost.address = host;
  }

/* Otherwise check for an unadorned IP address */

else if (string_is_ip_address(hostname, NULL) != 0)
  shost.name = shost.address = string_copy(hostname);

/* Otherwise lookup IP address(es) from the name */

else
  {
  shost.name = string_copy(hostname);
  if (host_find_byname(&shost, NULL, HOST_FIND_QUALIFY_SINGLE,
      NULL, FALSE) != HOST_FOUND)
    {
    *errstr = string_sprintf("no IP address found for host %s", shost.name);
    return -1;
    }
  }

/* Try to connect to the server - test each IP till one works */

for (h = &shost; h != NULL; h = h->next)
  {
  fd = (Ustrchr(h->address, ':') != 0)
    ? (fd6 < 0) ? (fd6 = ip_socket(type, af = AF_INET6)) : fd6
    : (fd4 < 0) ? (fd4 = ip_socket(type, af = AF_INET )) : fd4;

  if (fd < 0)
    {
    *errstr = string_sprintf("failed to create socket: %s", strerror(errno));
    goto bad;
    }

  for(port = portlo; port <= porthi; port++)
    if (ip_connect(fd, af, h->address, port, timeout) == 0)
      {
      if (fd != fd6) close(fd6);
      if (fd != fd4) close(fd4);
      if (connhost)
	{
	h->port = port;
	*connhost = *h;
	connhost->next = NULL;
	}
      return fd;
      }
  }

*errstr = string_sprintf("failed to connect to any address for %s: %s",
  hostname, strerror(errno));

bad:
  close(fd4); close(fd6); return -1;
}


int
ip_tcpsocket(const uschar * hostport, uschar ** errstr, int tmo)
{
int scan;
uschar hostname[256];
unsigned int portlow, porthigh;

/* extract host and port part */
scan = sscanf(CS hostport, "%255s %u-%u", hostname, &portlow, &porthigh);
if (scan != 3)
  {
  if (scan != 2)
    {
    *errstr = string_sprintf("invalid socket '%s'", hostport);
    return -1;
    }
  porthigh = portlow;
  }

return ip_connectedsocket(SOCK_STREAM, hostname, portlow, porthigh,
			  tmo, NULL, errstr);
}

int
ip_unixsocket(const uschar * path, uschar ** errstr)
{
int sock;
struct sockaddr_un server;

if ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
  {
  *errstr = US"can't open UNIX socket.";
  return -1;
  }

server.sun_family = AF_UNIX;
Ustrncpy(server.sun_path, path, sizeof(server.sun_path)-1);
server.sun_path[sizeof(server.sun_path)-1] = '\0';
if (connect(sock, (struct sockaddr *) &server, sizeof(server)) < 0)
  {
  int err = errno;
  (void)close(sock);
  *errstr = string_sprintf("unable to connect to UNIX socket (%s): %s",
		path, strerror(err));
  return -1;
  }
return sock;
}

int
ip_streamsocket(const uschar * spec, uschar ** errstr, int tmo)
{
return *spec == '/'
  ? ip_unixsocket(spec, errstr) : ip_tcpsocket(spec, errstr, tmo);
}

/*************************************************
*         Set keepalive on a socket              *
*************************************************/

/* Can be called for both incoming and outgoing sockets.

Arguments:
  sock       the socket
  address    the remote host address, for failure logging
  torf       true for outgoing connection, false for incoming

Returns:     nothing
*/

void
ip_keepalive(int sock, const uschar *address, BOOL torf)
{
int fodder = 1;
if (setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE,
    (uschar *)(&fodder), sizeof(fodder)) != 0)
  log_write(0, LOG_MAIN, "setsockopt(SO_KEEPALIVE) on connection %s %s "
    "failed: %s", torf? "to":"from", address, strerror(errno));
}



/*************************************************
*         Receive from a socket with timeout     *
*************************************************/

/*
Arguments:
  fd          the file descriptor
  timeout     the timeout, seconds
Returns:      TRUE => ready for i/o
              FALSE => timed out, or other error
*/
BOOL
fd_ready(int fd, int timeout)
{
fd_set select_inset;
struct timeval tv;
time_t start_recv = time(NULL);
int rc;

if (timeout <= 0)
  {
  errno = ETIMEDOUT;
  return FALSE;
  }
/* Wait until the socket is ready */

do
  {
  FD_ZERO (&select_inset);
  FD_SET (fd, &select_inset);
  tv.tv_sec = timeout;
  tv.tv_usec = 0;

  /*DEBUG(D_transport) debug_printf("waiting for data on fd\n");*/
  rc = select(fd + 1, (SELECT_ARG2_TYPE *)&select_inset, NULL, NULL, &tv);

  /* If some interrupt arrived, just retry. We presume this to be rare,
  but it can happen (e.g. the SIGUSR1 signal sent by exiwhat causes
  select() to exit).

  Aug 2004: Somebody set up a cron job that ran exiwhat every 2 minutes, making
  the interrupt not at all rare. Since the timeout is typically more than 2
  minutes, the effect was to block the timeout completely. To prevent this
  happening again, we do an explicit time test. */

  if (rc < 0 && errno == EINTR)
    {
    DEBUG(D_transport) debug_printf("EINTR while waiting for socket data\n");
    if (time(NULL) - start_recv < timeout) continue;
    DEBUG(D_transport) debug_printf("total wait time exceeds timeout\n");
    }

  /* Handle a timeout, and treat any other select error as a timeout, including
  an EINTR when we have been in this loop for longer than timeout. */

  if (rc <= 0)
    {
    errno = ETIMEDOUT;
    return FALSE;
    }

  /* If the socket is ready, break out of the loop. */
  }
while (!FD_ISSET(fd, &select_inset));
return TRUE;
}

/* The timeout is implemented using select(), and we loop to cover select()
getting interrupted, and the possibility of select() returning with a positive
result but no ready descriptor. Is this in fact possible?

Arguments:
  sock        the socket
  buffer      to read into
  bufsize     the buffer size
  timeout     the timeout

Returns:      > 0 => that much data read
              <= 0 on error or EOF; errno set - zero for EOF
*/

int
ip_recv(int sock, uschar *buffer, int buffsize, int timeout)
{
int rc;

if (!fd_ready(sock, timeout))
  return -1;

/* The socket is ready, read from it (via TLS if it's active). On EOF (i.e.
close down of the connection), set errno to zero; otherwise leave it alone. */

#ifdef SUPPORT_TLS
if (tls_out.active == sock)
  rc = tls_read(FALSE, buffer, buffsize);
else if (tls_in.active == sock)
  rc = tls_read(TRUE, buffer, buffsize);
else
#endif
  rc = recv(sock, buffer, buffsize, 0);

if (rc > 0) return rc;
if (rc == 0) errno = 0;
return -1;
}




/*************************************************
*    Lookup address family of potential socket   *
*************************************************/

/* Given a file-descriptor, check to see if it's a socket and, if so,
return the address family; detects IPv4 vs IPv6.  If not a socket then
return -1.

The value 0 is typically AF_UNSPEC, which should not be seen on a connected
fd.  If the return is -1, the errno will be from getsockname(); probably
ENOTSOCK or ECONNRESET.

Arguments:     socket-or-not fd
Returns:       address family or -1
*/

int
ip_get_address_family(int fd)
{
struct sockaddr_storage ss;
socklen_t sslen = sizeof(ss);

if (getsockname(fd, (struct sockaddr *) &ss, &sslen) < 0)
  return -1;

return (int) ss.ss_family;
}




/*************************************************
*       Lookup DSCP settings for a socket        *
*************************************************/

struct dscp_name_tableentry {
  const uschar *name;
  int value;
};
/* Keep both of these tables sorted! */
static struct dscp_name_tableentry dscp_table[] = {
#ifdef IPTOS_DSCP_AF11
    { CUS"af11", IPTOS_DSCP_AF11 },
    { CUS"af12", IPTOS_DSCP_AF12 },
    { CUS"af13", IPTOS_DSCP_AF13 },
    { CUS"af21", IPTOS_DSCP_AF21 },
    { CUS"af22", IPTOS_DSCP_AF22 },
    { CUS"af23", IPTOS_DSCP_AF23 },
    { CUS"af31", IPTOS_DSCP_AF31 },
    { CUS"af32", IPTOS_DSCP_AF32 },
    { CUS"af33", IPTOS_DSCP_AF33 },
    { CUS"af41", IPTOS_DSCP_AF41 },
    { CUS"af42", IPTOS_DSCP_AF42 },
    { CUS"af43", IPTOS_DSCP_AF43 },
    { CUS"ef", IPTOS_DSCP_EF },
#endif
#ifdef IPTOS_LOWCOST
    { CUS"lowcost", IPTOS_LOWCOST },
#endif
    { CUS"lowdelay", IPTOS_LOWDELAY },
#ifdef IPTOS_MINCOST
    { CUS"mincost", IPTOS_MINCOST },
#endif
    { CUS"reliability", IPTOS_RELIABILITY },
    { CUS"throughput", IPTOS_THROUGHPUT }
};
static int dscp_table_size =
  sizeof(dscp_table) / sizeof(struct dscp_name_tableentry);

/* DSCP values change by protocol family, and so do the options used for
setsockopt(); this utility does all the lookups.  It takes an unexpanded
option string, expands it, strips off affix whitespace, then checks if it's
a number.  If all of what's left is a number, then that's how the option will
be parsed and success/failure is a range check.  If it's not all a number,
then it must be a supported keyword.

Arguments:
  dscp_name   a string, so far unvalidated
  af          address_family in use
  level       setsockopt level to use
  optname     setsockopt name to use
  dscp_value  value for dscp_name

Returns: TRUE if okay to setsockopt(), else FALSE

*level and *optname may be set even if FALSE is returned
*/

BOOL
dscp_lookup(const uschar *dscp_name, int af,
    int *level, int *optname, int *dscp_value)
{
uschar *dscp_lookup, *p;
int first, last;
long rawlong;

if (af == AF_INET)
  {
  *level = IPPROTO_IP;
  *optname = IP_TOS;
  }
#if HAVE_IPV6 && defined(IPV6_TCLASS)
else if (af == AF_INET6)
  {
  *level = IPPROTO_IPV6;
  *optname = IPV6_TCLASS;
  }
#endif
else
  {
  DEBUG(D_transport)
    debug_printf("Unhandled address family %d in dscp_lookup()\n", af);
  return FALSE;
  }
if (!dscp_name)
  {
  DEBUG(D_transport)
    debug_printf("[empty DSCP]\n");
  return FALSE;
  }
dscp_lookup = expand_string(US dscp_name);
if (dscp_lookup == NULL || *dscp_lookup == '\0')
  return FALSE;

p = dscp_lookup + Ustrlen(dscp_lookup) - 1;
while (isspace(*p)) *p-- = '\0';
while (isspace(*dscp_lookup) && dscp_lookup < p) dscp_lookup++;
if (*dscp_lookup == '\0')
  return FALSE;

rawlong = Ustrtol(dscp_lookup, &p, 0);
if (p != dscp_lookup && *p == '\0')
  {
  /* We have six bits available, which will end up shifted to fit in 0xFC mask.
  RFC 2597 defines the values unshifted. */
  if (rawlong < 0 || rawlong > 0x3F)
    {
    DEBUG(D_transport)
      debug_printf("DSCP value %ld out of range, ignored.\n", rawlong);
    return FALSE;
    }
  *dscp_value = rawlong << 2;
  return TRUE;
  }

first = 0;
last = dscp_table_size;
while (last > first)
  {
  int middle = (first + last)/2;
  int c = Ustrcmp(dscp_lookup, dscp_table[middle].name);
  if (c == 0)
    {
    *dscp_value = dscp_table[middle].value;
    return TRUE;
    }
  else if (c > 0)
    first = middle + 1;
  else
    last = middle;
  }
return FALSE;
}

void
dscp_list_to_stream(FILE *stream)
{
int i;
for (i=0; i < dscp_table_size; ++i)
  fprintf(stream, "%s\n", dscp_table[i].name);
}


/* End of ip.c */
/* vi: aw ai sw=2
*/
